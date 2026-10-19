/**
 * wire-release — the launch's two steps for serving npm the `.npmrc` twin
 * (confidentiality plan 10 §11.13.1).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 *
 * npm needs no raw registry token when the session's egress proxy terminates
 * TLS: npm sends the token's symbol, and the proxy puts the real value back
 * at the registry the token's own key names (its field symbol is bound
 * there). Two things make that true for a launch:
 *
 * 1. The arbiter must know this session's proxy inspects TLS
 *    (`registerWireRelease {sessionKey, inspecting, pid}`, a HUMAN-PLANE op:
 *    it decides whether npm reads the credential raw, so only the launcher,
 *    which started the proxy, may say it). Without it npm keeps today's raw
 *    read. Best-effort: a failure logs one WARNING and never refuses the
 *    launch. The pid lets the arbiter keep the word across its own restart
 *    while this launcher runs; the session's end withdraws it
 *    (`endLaunchWireRelease`).
 * 2. Every program that reads the twin must send through the proxy. Claude
 *    Code passes its environment to stdio MCP servers and to its shell; Codex
 *    0.159 passes the CA variables to a stdio MCP server but drops
 *    `HTTPS_PROXY`, `NO_PROXY` and `NODE_USE_ENV_PROXY` (measured 2026-10-02,
 *    §11.13.1), so an `npx`-launched server would send the symbol straight to
 *    the registry. The launch forwards them with Codex's own per-server
 *    `env_vars` list (`-c mcp_servers.<name>.env_vars=[…]`), keeping the
 *    entry's own names, for every stdio server in the Codex config the
 *    launcher reads. An entry whose `env_vars` it cannot read, or whose name
 *    is not a bare TOML key, is left alone.
 */
import type { ConfiguredMcpServer } from "./mcp-server-config.js";
import type { LaunchPlan } from "./types.js";
import { sessionNoProxy } from "./services/net-proxy.js";

/** The proxy variables Codex drops for a stdio MCP server (measured on
 *  0.159.1; the CA variables already pass). */
export const CODEX_MCP_PROXY_VARS: readonly string[] = [
  "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "NODE_USE_ENV_PROXY",
];

const BARE_KEY = /^[A-Za-z0-9_-]+$/;

/**
 * The `-c` overrides that make Codex forward the proxy variables to each
 * configured stdio MCP server: its own `env_vars` first, then the missing
 * proxy names. Pure; [] when there is nothing to forward to.
 */
export function codexMcpProxyEnvOverrides(
  servers: readonly ConfiguredMcpServer[],
  vars: readonly string[] = CODEX_MCP_PROXY_VARS,
): string[] {
  const out: string[] = [];
  const done = new Set<string>();
  for (const s of servers) {
    if (done.has(s.name) || !BARE_KEY.test(s.name) || s.envVarsUnreadable) continue;
    done.add(s.name);
    const names = [...(s.envVars ?? [])];
    for (const v of vars) if (!names.includes(v)) names.push(v);
    out.push("-c", `mcp_servers.${s.name}.env_vars=[${names.map((n) => JSON.stringify(n)).join(",")}]`);
  }
  return out;
}

export interface WireReleaseDeps {
  /** One request on a socket (secret-setup.ts `ndjsonCall`). */
  call: (sock: string, op: string, args: Record<string, unknown>) => Promise<unknown>;
  log: (m: string) => void;
  /** This launcher's pid: with it the arbiter keeps the session's word
   *  across its own restart while this launcher runs, and the end of the
   *  session drops only this launcher's word. */
  pid?: number;
}

export type WireReleasePlan = Pick<LaunchPlan, "scopeId" | "arbiterHumanSock" | "effectiveAxes" | "confidentiality" | "netProxy" | "mitmCaCert" | "noProxyExtra"> & Partial<Pick<LaunchPlan, "modelHostDeny">>;

/** Does this launch's egress proxy terminate TLS with a session CA the
 *  agent's environment trusts? Pure. */
export function launchInspectsTls(plan: WireReleasePlan): boolean {
  return plan.netProxy !== undefined && typeof plan.mitmCaCert === "string" && plan.mitmCaCert !== "";
}

/**
 * Tell the arbiter (human plane) that this session's proxy inspects TLS, with
 * the session's NO_PROXY hosts (npm reaches those around the proxy, so a
 * token bound to one stays a raw read). Confidentiality axis on and TLS
 * inspection on only, and not opted out (`MANDU_WIRE_TWIN=0` in the
 * launcher's environment, the human's: npm then reads `.npmrc` raw as
 * before); otherwise nothing is sent. Never throws; returns what happened.
 */
export async function registerLaunchWireRelease(
  plan: WireReleasePlan,
  env: Record<string, string | undefined>,
  deps: WireReleaseDeps,
): Promise<"registered" | "off" | "opted-out" | "skipped" | "failed"> {
  if ((plan.effectiveAxes?.confidentiality ?? plan.confidentiality) !== true) return "off";
  if (!launchInspectsTls(plan)) return "off";
  if (env["MANDU_WIRE_TWIN"] === "0") return "opted-out";
  const tail = "npm reads ~/.npmrc raw this session (its token held by npm, its output masked)";
  if (!plan.arbiterHumanSock) {
    deps.log(`WARNING: mandu: the protection service reported no human-plane socket; ${tail}`);
    return "skipped";
  }
  const direct = (sessionNoProxy(plan) ?? "").split(",").filter((h) => h !== "");
  try {
    const r = (await deps.call(plan.arbiterHumanSock, "registerWireRelease", { sessionKey: plan.scopeId, inspecting: true, direct, ...(deps.pid !== undefined ? { pid: deps.pid } : {}) })) as { inspecting?: unknown } | null;
    if (r === null || typeof r !== "object" || r.inspecting !== true) {
      deps.log(`WARNING: mandu: the protection service did not record the session's TLS inspection; ${tail}`);
      return "failed";
    }
    return "registered";
  } catch (e) {
    deps.log(`WARNING: mandu: could not record the session's TLS inspection (${e instanceof Error ? e.message : String(e)}); ${tail}`);
    return "failed";
  }
}

/**
 * The session ended: tell the arbiter (human plane) to forget its word, so a
 * restart after the launch cannot take it back and a later launch under the
 * same session key starts without it. Only for a launch whose word was
 * registered; with `deps.pid`, only this launcher's word. Best-effort and
 * quiet: the arbiter also drops the persisted word of a launcher that is
 * gone. Never throws.
 */
export async function endLaunchWireRelease(
  plan: Pick<WireReleasePlan, "scopeId" | "arbiterHumanSock">,
  registered: "registered" | "off" | "opted-out" | "skipped" | "failed" | null,
  deps: Pick<WireReleaseDeps, "call" | "pid">,
): Promise<boolean> {
  if (registered !== "registered" || !plan.arbiterHumanSock) return false;
  try {
    await deps.call(plan.arbiterHumanSock, "registerWireRelease", { sessionKey: plan.scopeId, inspecting: false, ...(deps.pid !== undefined ? { pid: deps.pid } : {}) });
    return true;
  } catch {
    return false;
  }
}
