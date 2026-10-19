/**
 * inspect-net-confine — the kernel network confine for the inspect-mcp
 * server (docs/design/confidentiality/model-endpoints.md §1.8
 * item 5).
 *
 * inspect-mcp is spawned by the agent from the MCP config the launcher
 * writes, so it lives in the agent world and shares that world's TCP allow
 * set: the model proxy, the net-proxy, the U-LLM forwarder, the declared
 * local endpoints, and 443/22 unless strict. "A local-model datum's bytes go
 * only to the declared endpoint" was therefore enforced in inspect-mcp's code
 * (`assertNonProxyBaseUrl` / `assertDeclaredEndpointUrl`), not by the kernel.
 *
 * This module wraps the server command with the same committed applier the
 * whole-agent wrap uses (`mandu-landlock-apply --net-only`, landlock-net.ts),
 * so the inspect-mcp process tree may CONNECT only to:
 *   - the U-LLM forwarder's port when one runs, else 443 (the default U-LLM
 *     dials its vendor directly, api or `claude -p` / `codex exec`);
 *   - the port of the declared entry the helper dials, the `local: true`
 *     entry marked `helper: true`, else the first one (`helperEndpointPorts`);
 *     no other declared entry's port (least privilege, 2026-09-29).
 * Never the model proxy (the instrumented T-LLM path), never the net-proxy (a
 * forwarder to any host), never 22. Landlock stacks, so this ruleset inside
 * the whole-agent one only narrows; and the connect guard honors it on the
 * connects it performs (net-supervisor landlock_mirror "CONNECTS"), so it
 * holds in the default posture too. `--net-only` touches no filesystem rule
 * (the server still reads its package, node, HOME for `claude -p`), and
 * Landlock TCP rules do not govern Unix sockets (the arbiter socket).
 *
 * Degrade (the non-root principle: on by default where the kernel allows):
 * no applier bin, or a kernel without Landlock TCP rules (ABI < 4, < 6.7),
 * keeps today's command and prints one launch note. `--no-landlock-net` opts
 * out of this confine together with the whole-agent one. OpenClaw mounts the
 * inspect channel inside its gateway process (no separate command to wrap).
 * macOS: Linux only (no Landlock, and sandbox-exec does not nest inside the
 * whole-agent Seatbelt profile); one informational line, no applier lookup.
 *
 * Pure plan/render here; the bin resolution and the kernel probe are
 * injectable deps (mirrors landlock-net-setup.ts).
 *
 * Mandu-new (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { planLandlockNet } from "./landlock-net.js";
import { cachedProbe } from "./probe-cache.js";
import { helperEndpointEntry, helperEndpointPorts, isLoopbackHost, parseOrigin, type ModelEndpoint } from "./model-endpoints.js";
import { nativeBinBuildHint, resolveNativeBin, staleNativeBinNote, type NativeBinName } from "./services/native-bins.js";

/** The port a default U-LLM without the forwarder dials (its vendor's TLS). */
export const DIRECT_ULLM_PORT = 443;

export interface InspectNetPortInput {
  /** The live U-LLM forwarder's port, or null when none runs. */
  ullmForwarderPort: number | null;
  /** policy.yaml `models:` as the arbiter reported it; only `local: true`
   *  the helper's entry counts (model-endpoints.ts `helperEndpointPorts`
   *  says why). */
  modelEndpoints: readonly ModelEndpoint[];
}

/**
 * The CONNECT ports of the inspect-mcp tree: the forwarder's port (or 443
 * without one) plus every declared local endpoint's port, deduped + sorted.
 * The model-proxy, net-proxy and ssh ports are never inputs, so they can
 * never appear (unless a declared local endpoint shares one, which the
 * launch refuses first: model-endpoints.ts `assertLocalEndpoints`).
 */
export function computeInspectMcpPorts(input: InspectNetPortInput): number[] {
  const ports = new Set<number>();
  ports.add(input.ullmForwarderPort !== null && input.ullmForwarderPort > 0 ? input.ullmForwarderPort : DIRECT_ULLM_PORT);
  for (const p of helperEndpointPorts(input.modelEndpoints)) ports.add(p);
  return [...ports].sort((a, b) => a - b);
}

/** Prefix a server entry's command with the wrap argv (the applier, its
 *  flags, `--`); the env is unchanged. An empty wrap returns the entry as is. */
export function wrapServerCommand<T extends { command: string; args: string[] }>(server: T, wrapArgv: readonly string[] | undefined): T {
  if (!wrapArgv || wrapArgv.length === 0) return server;
  return { ...server, command: wrapArgv[0]!, args: [...wrapArgv.slice(1), server.command, ...server.args] };
}

/**
 * The inspect-mcp env's NO_PROXY when the confine is on and the session
 * routes HTTP through the net-proxy: the session's own list plus the
 * helper's entry when it is on a non-loopback host. Without it Node
 * (NODE_USE_ENV_PROXY, env-compose.ts) sends a request for a LAN model to
 * the net-proxy, whose port the confine denies. null = leave the inherited
 * value alone (no net-proxy, no helper entry, or a loopback one, which the
 * session list already names).
 */
export function inspectNoProxy(sessionNoProxy: string | null, endpoints: readonly ModelEndpoint[]): string | null {
  if (sessionNoProxy === null) return null;
  const helper = helperEndpointEntry(endpoints);
  const o = helper ? parseOrigin(helper.url) : null;
  if (o === null || isLoopbackHost(o.host)) return null;
  const extra = [o.host.includes(":") ? `[${o.host}]` : o.host];
  const have = sessionNoProxy.split(",").filter((h) => h !== "");
  return [...have, ...extra.filter((h) => !have.includes(h))].join(",");
}

export interface InspectNetConfineDeps {
  resolveBin?: (name: NativeBinName) => string | null;
  staleNote?: (name: NativeBinName, path: string) => string | null;
  /** Does the applier confine TCP on this kernel? Default: run it once
   *  WITHOUT `--skip-unsupported` on `true` (exit 0 = yes; it exits 71 with
   *  "TCP-net unavailable" below ABI 4), the probe the live tests use. The
   *  probe's argv leads with `--allow-tcp-port`, so an argv recorder (the
   *  launcher e2e's stand-in bins) can tell it from a real wrap, which leads
   *  with `--net-only`. */
  probeNet?: (applierPath: string) => boolean;
  log?: (msg: string) => void;
  /** The host platform. Default: this process's (`process.platform`): the
   *  service manager calls in without one. Landlock is Linux only, and on
   *  macOS a second Seatbelt profile cannot be applied inside the agent's
   *  (sandbox-exec does not nest), so there ONE informational line says so,
   *  never the "not built" degrade. */
  platform?: NodeJS.Platform;
}

/** The one line a macOS launch prints for this confine (informational). */
export const INSPECT_CONFINE_LINUX_ONLY_NOTE =
  "mandu: the inspect_symbol network confine is Linux only (a Seatbelt profile does not nest inside the agent's); " +
  "on macOS inspect-mcp keeps the agent's TCP allow set, and your own model's bytes are still sent only to it, by " +
  "inspect-mcp's own check";

/** The default kernel probe: the applier's own answer. */
/** The probe's argv after the applier. */
export const LANDLOCK_NET_PROBE_ARGV = ["--allow-tcp-port", "1", "--net-only", "--", "true"];

/** The kernel probe: the applier's own answer. */
export function probeLandlockNet(applierPath: string): boolean {
  try {
    const r = spawnSync(applierPath, LANDLOCK_NET_PROBE_ARGV, { stdio: "ignore", timeout: 5000 });
    return r.status === 0;
  } catch {
    return false;
  }
}

/** The launch's probe: a pass is kept for the boot, keyed by the applier's
 *  identity (probe-cache.ts). The wrap it enables is strict (no
 *  `--skip-unsupported`), so a wrong kept pass stops inspect-mcp at the
 *  applier (exit 71) instead of running it unconfined. */
export function launchProbeLandlockNet(applierPath: string): boolean {
  return cachedProbe("landlock-net", () => ({ bins: [applierPath], argv: LANDLOCK_NET_PROBE_ARGV }), () => probeLandlockNet(applierPath));
}

/**
 * Decide the inspect-mcp wrap for a launch. Returns the wrap argv and its
 * ports, or null when it is off or degraded (one note printed). The caller
 * stores the argv on the plan (`plan.inspectMcpWrap`); every writer of the
 * inspect server entry (services/mcp.ts, the Codex `-c mcp_servers` splice
 * built from it, the OpenCode config) applies it through
 * `inspectMcpConfigDoc`.
 */
export function planInspectNetConfine(
  plan: {
    landlockNet?: boolean;
    ullmForwarder?: { host: string; port: number };
    modelEndpoints?: ModelEndpoint[];
  },
  deps: InspectNetConfineDeps = {},
): { wrapArgv: string[]; ports: number[] } | null {
  if (plan.landlockNet === false) return null;
  const log = deps.log ?? ((m: string) => console.error(m));
  const platform = deps.platform ?? process.platform;
  if (platform !== "linux") {
    if (platform === "darwin") log(INSPECT_CONFINE_LINUX_ONLY_NOTE);
    return null;
  }
  const applierPath = (deps.resolveBin ?? resolveNativeBin)("mandu-landlock-apply");
  if (!applierPath) {
    log(
      "mandu: the inspect_symbol network confine is unavailable: the mandu-landlock-apply bin is not built; " +
      "inspect-mcp keeps the agent's TCP allow set (your own model's bytes are still sent only to it, " +
      `by inspect-mcp's own check). ${nativeBinBuildHint()}`,
    );
    return null;
  }
  const stale = (deps.staleNote ?? staleNativeBinNote)("mandu-landlock-apply", applierPath);
  if (stale) log(stale);
  if (!(deps.probeNet ?? launchProbeLandlockNet)(applierPath)) {
    log(
      "mandu: the inspect_symbol network confine is unavailable: this kernel has no Landlock TCP rules " +
      "(needs 6.7); inspect-mcp keeps the agent's TCP allow set (your own model's bytes are still sent " +
      "only to it, by inspect-mcp's own check)",
    );
    return null;
  }
  const ports = computeInspectMcpPorts({
    ullmForwarderPort: plan.ullmForwarder ? plan.ullmForwarder.port : null,
    modelEndpoints: plan.modelEndpoints ?? [],
  });
  // Strict: the probe said this kernel confines TCP, so the wrap does not
  // degrade. Were the probe's answer wrong (a kept answer, a changed host),
  // the applier exits 71 and inspect-mcp never runs unconfined.
  const { wrapArgv } = planLandlockNet({ applierPath, ports, failClosed: true });
  log(
    `mandu: inspect_symbol network confine LIVE: inspect-mcp may CONNECT only to TCP ports [${ports.join(", ")}] ` +
    `(${plan.ullmForwarder ? "the U-LLM forwarder" : "the U-LLM's direct :443"}` +
    `${helperEndpointPorts(plan.modelEndpoints ?? []).length > 0 ? " and your own model's endpoint" : ""}; ` +
    "not the model proxy, the net-proxy or ssh)",
  );
  return { wrapArgv, ports };
}
