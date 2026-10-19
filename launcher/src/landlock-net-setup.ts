/**
 * landlock-net-setup — establish the whole-agent TCP port-allow wrap for a
 * launch (docs/design/integrity/exec-routing.md §7).
 *
 * Mirrors applySecretTwins's deps + degrade shape (secret-setup.ts): resolve the
 * committed applier bin, compute the allowed port set from the live plan, and —
 * when the bin is present — PREPEND `mandu-landlock-apply --net-only …` to
 * `mut.launchPrefix` so it is the OUTERMOST sandbox wrap (inside only the
 * reply-filter). Unlike the secret twin this is a UTILITY-CLASS hardening add,
 * ON BY DEFAULT (the non-root principle): if the applier bin is not built we
 * WARN and proceed WITHOUT the wrap rather than fail the launch (the netns /
 * net-proxy stay whatever boundary they were), and `--skip-unsupported` degrades
 * in-place on a pre-6.7 kernel.
 *
 * macOS has no Landlock: there the same port set is planned for the
 * whole-agent Seatbelt profile (`planSeatbeltNet`; seatbelt-profile.ts
 * component 4) and no applier is looked for, so a Mac launch never prints
 * the Linux "not built" note (exec-routing.md §7.1 "macOS").
 *
 * Mandu-new (no reference origin).
 */
import { computeLandlockNetPorts, planLandlockNet, WORKFLOW_PORTS } from "./landlock-net.js";
import { helperEndpointPorts } from "./model-endpoints.js";
import type { SeatbeltNet } from "./seatbelt-profile.js";
import { nativeBinBuildHint, resolveNativeBin, staleNativeBinNote, type NativeBinName } from "./services/native-bins.js";
import { wireOf, type LaunchMutation, type LaunchPlan } from "./types.js";

export interface LandlockNetDeps {
  /** Resolve a committed Rust bin (defaults to the real resolver). */
  resolveBin?: (name: NativeBinName) => string | null;
  /** The stale-bin WARNING for a resolved bin (services/native-bins
   *  `staleNativeBinNote`; null = fresh or unjudgeable). Injectable. */
  staleNote?: (name: NativeBinName, path: string) => string | null;
  log?: (msg: string) => void;
  /** The host platform (run.ts passes `platform.id`). "darwin": no Landlock;
   *  the same port set is enforced by the whole-agent Seatbelt profile
   *  (seatbelt-profile.ts component 4), so no applier bin is resolved and no
   *  wrap is prepended; the result's `seatbelt` carries the rules. Absent:
   *  the Linux path. */
  platform?: "linux" | "darwin" | "win32";
  /** darwin: is `sandbox-exec` there to enforce the profile? Default true. */
  seatbeltAvailable?: boolean;
}

/** The result: the wrap argv prepended (empty on macOS, where the Seatbelt
 *  profile enforces the set), the CONNECT ports and the BIND ports, and on
 *  macOS the Seatbelt rules. */
export interface LandlockNetResult {
  wrapArgv: string[];
  ports: number[];
  bindPorts: number[];
  seatbelt?: SeatbeltNet;
}

/** The inputs of the port set, from the live plan (shared by both
 *  platforms so they cannot drift). */
function portInputs(plan: LaunchPlan): { targetProxyPort: number; netProxyPort: number | null; ullmForwarderPort: number | null; cdpRelayPort: number | null; modelEndpointPorts: number[]; strict: boolean } {
  return {
    targetProxyPort: wireOf(plan.target) === "anthropic" ? plan.proxy.port : plan.openaiProxy.port,
    netProxyPort: plan.netProxy ? plan.netProxy.port : null,
    ullmForwarderPort: plan.ullmForwarder ? plan.ullmForwarder.port : null,
    // The DevTools relay (browser-cdp.ts): its port, never Chrome's.
    cdpRelayPort: plan.cdpRelay ? plan.cdpRelay.port : null,
    // policy.yaml `models:` (confidentiality-plan-11 D5): the port of the
    // entry the helper dials, read from the arbiter by run.ts.
    modelEndpointPorts: helperEndpointPorts(plan.modelEndpoints ?? []),
    strict: plan.landlockNetStrict === true,
  };
}

/**
 * The macOS rules for the landlock-net port set (exec-routing.md §7.1
 * "macOS"). The SAME ports as `computeLandlockNetPorts` (a parity test pins
 * it); Seatbelt can name `localhost`, so Mandu's own loopback services (the
 * model proxy, the net-proxy, the U-LLM forwarder) are allowed on loopback
 * only, and the rest keep Linux's any-host-on-the-port meaning. An explicit
 * `--landlock-net=<ports>` set replaces the computed one, any host. Pure.
 */
export function planSeatbeltNet(plan: LaunchPlan): SeatbeltNet {
  const inp = portInputs(plan);
  const bind = [...new Set(plan.landlockNetBind ?? [])].sort((a, b) => a - b);
  if (plan.landlockNetPorts !== undefined) {
    return { connect: plan.landlockNetPorts.map((port) => ({ host: "*" as const, port })), bind };
  }
  const connect: SeatbeltNet["connect"] = [];
  if (inp.targetProxyPort > 0) connect.push({ host: "localhost", port: inp.targetProxyPort });
  if (inp.netProxyPort !== null) connect.push({ host: "localhost", port: inp.netProxyPort });
  if (inp.ullmForwarderPort !== null) connect.push({ host: "localhost", port: inp.ullmForwarderPort });
  if (inp.cdpRelayPort !== null) connect.push({ host: "localhost", port: inp.cdpRelayPort });
  for (const port of inp.modelEndpointPorts) connect.push({ host: "*", port });
  if (!inp.strict) for (const port of WORKFLOW_PORTS) connect.push({ host: "*", port });
  return { connect, bind };
}

/**
 * Prepend the whole-agent net-confine wrap. No-ops when `plan.landlockNet` is
 * false (explicit opt-out); undefined = default-on. Returns the wrap argv it
 * prepended (or null when it degraded / was off) for the caller's banner + the
 * tests. On macOS (`deps.platform === "darwin"`) it plans the same set for the
 * Seatbelt profile instead (the result's `seatbelt`).
 */
export function applyLandlockNet(
  plan: LaunchPlan,
  mut: LaunchMutation,
  deps: LandlockNetDeps = {},
): LandlockNetResult | null {
  if (plan.landlockNet === false) return null;
  const log = deps.log ?? ((m: string) => console.error(m));
  const resolveBin = deps.resolveBin ?? resolveNativeBin;
  // Explicit request (--landlock-net) vs the default-on posture: both degrade
  // identically (this wrap is additive hardening, never a gate), but the
  // message must not claim the user "asked" for what a default provided.
  const asked = plan.landlockNet === true ? "--landlock-net asked for" : "the default-on";
  if (deps.platform === "win32") return null;
  if (deps.platform === "darwin") return seatbeltNet(plan, asked, deps.seatbeltAvailable !== false, log);

  const applierPath = resolveBin("mandu-landlock-apply");
  if (!applierPath) {
    log(
      `mandu: ${asked} whole-agent TCP confine is unavailable — the ` +
      "mandu-landlock-apply bin is not built; proceeding WITHOUT it (all TCP " +
      `stays reachable). ${nativeBinBuildHint()}`,
    );
    return null;
  }
  const applierStale = (deps.staleNote ?? staleNativeBinNote)("mandu-landlock-apply", applierPath);
  if (applierStale) log(applierStale);

  const { strict, targetProxyPort, netProxyPort, ullmForwarderPort, cdpRelayPort, modelEndpointPorts } = portInputs(plan);
  const ports = computeLandlockNetPorts({
    targetProxyPort,
    netProxyPort,
    ullmForwarderPort,
    cdpRelayPort,
    modelEndpointPorts,
    explicitPorts: plan.landlockNetPorts,
    strict,
  });
  // The bind allowance (exec-routing.md §7.1): ports the agent may LISTEN on.
  // Each is also connectable (the applier grants BIND|CONNECT), so it joins the
  // reported CONNECT set — and counts as "allowed" for the proxy-port warning.
  const bindPorts = [...new Set(plan.landlockNetBind ?? [])].sort((a, b) => a - b);
  const { wrapArgv } = planLandlockNet({ applierPath, ports, bindPorts });

  // OUTERMOST sandbox wrap: prepend so it wraps the secret-twins bwrap and every
  // shell/child the agent spawns; the reply-filter (prepended later) stays outside.
  mut.launchPrefix = [...wrapArgv, ...mut.launchPrefix];

  // Banner + the honest residuals (exec-routing.md §7).
  const sorted = [...new Set([...ports, ...bindPorts])].sort((a, b) => a - b);
  log(
    `mandu: landlock-net LIVE — whole-agent TCP confined to CONNECT ports ` +
    `[${sorted.join(", ")}]` +
    (bindPorts.length > 0 ? ` + BIND (listen) ports [${bindPorts.join(", ")}]` : "") +
    " (deny all other TCP; --skip-unsupported degrades on kernel < 6.7)",
  );
  residualNotes("landlock-net", plan, sorted, log);
  return { wrapArgv, ports: sorted, bindPorts };
}

/** The honest residual lines after the LIVE banner, shared by both
 *  platforms (`name` is how the line names the rung). Linux wording is
 *  unchanged ("landlock-net"). */
function residualNotes(name: string, plan: LaunchPlan, sorted: number[], log: (m: string) => void): void {
  const { strict, targetProxyPort, ullmForwarderPort, modelEndpointPorts } = portInputs(plan);
  if (strict) {
    log(
      `mandu: ${name} STRICT — the workflow ports 443 + 22 are DENIED ` +
      "(closes the direct-TLS and ssh exfil channels). " +
      (ullmForwarderPort !== null
        ? `The U-LLM rides the loopback forwarder (:${ullmForwarderPort}); `
        : "WARNING: the loopback U-LLM forwarder is NOT running, so a cli/api " +
          "U-LLM's direct api.anthropic.com:443 dial WILL fail; ") +
      "any other direct :443/:22 client in the agent tree (git-ssh remotes, " +
      "proxy-unaware fetchers, CC-internal calls) also breaks — use " +
      "--landlock-net=<ports> to curate exceptions.",
    );
  } else if (sorted.includes(443) || sorted.includes(22)) {
    log(
      `mandu: ${name} — the workflow ports 443 + 22 stay allowed (direct ` +
      "TLS + git-ssh keep working" +
      (ullmForwarderPort !== null
        ? "; the U-LLM already rides the loopback forwarder"
        : "; the U-LLM dials :443 directly") +
      "). The honest trade-off: a 443/22-based exfil stays possible — " +
      "--landlock-net-strict denies both.",
    );
  }
  if (modelEndpointPorts.length > 0) {
    const missing = modelEndpointPorts.filter((p) => !sorted.includes(p));
    log(
      missing.length === 0
        ? `mandu: ${name}: your own model endpoint port(s) [${modelEndpointPorts.join(", ")}] are allowed ` +
          "(policy.yaml models: with local: true)"
        : `mandu: ${name} WARNING: your own model endpoint port(s) [${missing.join(", ")}] (policy.yaml models:) ` +
          `are NOT in the allowed set [${sorted.join(", ")}]; inspect_symbol cannot reach that model. ` +
          "Add them to --landlock-net=… or drop the override.",
    );
  }
  if (!sorted.includes(targetProxyPort)) {
    log(
      `mandu: ${name} WARNING — the ${plan.target} model-proxy port ${targetProxyPort} is NOT in ` +
      `the allowed set [${sorted.join(", ")}]; the agent's model calls will fail. ` +
      "Add it to --landlock-net=… or drop the override.",
    );
  }
}

/** macOS (exec-routing.md §7.1 "macOS"): the same port set, planned for the
 *  whole-agent Seatbelt profile (seatbelt-setup.ts renders and applies it;
 *  no applier bin, no wrap here). Without `sandbox-exec` nothing can enforce
 *  it: one degrade line, as for a missing Linux applier. */
function seatbeltNet(plan: LaunchPlan, asked: string, available: boolean, log: (m: string) => void): LandlockNetResult | null {
  if (!available) {
    log(
      `mandu: ${asked} whole-agent TCP confine is unavailable — \`sandbox-exec\` is missing on this Mac; ` +
      "proceeding WITHOUT it (all TCP stays reachable).",
    );
    return null;
  }
  const rules = planSeatbeltNet(plan);
  const bindPorts = [...rules.bind];
  const sorted = [...new Set([...rules.connect.map((r) => r.port), ...bindPorts])].sort((a, b) => a - b);
  const loopback = rules.connect.filter((r) => r.host === "localhost").map((r) => r.port);
  log(
    `mandu: network-confine LIVE (Seatbelt, the macOS landlock-net) — whole-agent TCP confined to CONNECT ports ` +
    `[${sorted.join(", ")}]` +
    (loopback.length > 0 ? ` (Mandu's own services [${[...new Set(loopback)].sort((a, b) => a - b).join(", ")}] on loopback only)` : "") +
    (bindPorts.length > 0 ? ` + BIND (listen) ports [${bindPorts.join(", ")}]` : "") +
    " (deny all other TCP connects and binds; UDP and name lookups untouched)",
  );
  residualNotes("network-confine", plan, sorted, log);
  return { wrapArgv: [], ports: sorted, bindPorts, seatbelt: rules };
}
