/**
 * net-guard-setup — establish the whole-agent IP/domain-aware connect-guard for a
 * launch (docs/design/integrity/exec-routing.md §7.5).
 *
 * Mirrors applyLandlockNet's deps + degrade shape (landlock-net-setup.ts): resolve
 * the committed `mandu-net-guard` bin, compute the allow-spec set from the live
 * plan, and — when the bin is present — PREPEND the guard wrap to
 * `mut.launchPrefix` so it is the OUTERMOST net wrap, wrapping the landlock-net
 * port wrap and every child. That ordering is LOAD-BEARING: the guard SUPERVISOR
 * (the wrap's own long-lived process) must sit OUTSIDE the Landlock port wrap so
 * its supervisor-side connect (to an allowed destination) is not itself
 * port-restricted — which is what lets an allowed :443 destination stay reachable
 * even under `--landlock-net-strict`.
 *
 * UTILITY-CLASS hardening, ON BY DEFAULT (the non-root principle): if the bin is
 * not built we WARN and proceed WITHOUT the guard (the landlock-net port wrap /
 * netns stay whatever boundary they were) rather than fail the launch, and the
 * bin's own `--skip-unsupported` degrades in-place where seccomp NEW_LISTENER is
 * unavailable.
 *
 * Mandu-new (no reference origin).
 */
import { execFileSync } from "node:child_process";
import { rmSync } from "node:fs";
import { hardenedGitArgs, hardenedGitEnv } from "./hardened-git.js";
import { countGitCall } from "./launch-timings.js";
import { resolve } from "node:path";
import {
  computeNetGuardSpecs,
  gitRemoteSpecs,
  NET_GUARD_PROXY_PORTS_ENV,
  planNetGuard,
  sessionProxyPorts,
  specsAdmitAnyHttps,
} from "./net-guard.js";
import { NET_GUARD_STATUS_ENV } from "./guard-death.js";
import { cleanHostGuardArgs } from "./clean-host.js";
import { helperEndpointGuardSpecs } from "./model-endpoints.js";
import { uploadDenyGuardSpecs } from "./upload-deny.js";
import { modelHostGuardDenySpecs } from "./model-host-deny.js";
import { buildHintFor, resolveNativeBin, staleNativeBinNote, type NativeBinName } from "./services/native-bins.js";
import { wireOf, type LaunchMutation, type LaunchPlan } from "./types.js";

export interface NetGuardDeps {
  /** Resolve a committed Rust bin (defaults to the real resolver). */
  resolveBin?: (name: NativeBinName) => string | null;
  /** The stale-bin WARNING for a resolved bin (services/native-bins
   *  `staleNativeBinNote`; null = fresh or unjudgeable). Injectable. */
  staleNote?: (name: NativeBinName, path: string) => string | null;
  /** Enumerate the workspace's git remote URLs (defaults to `git -C <cwd> …`;
   *  called with the user's workspace, plan.humanCwd, not the AgentView).
   *  Injected so the allow-set derivation is unit-testable with no git repo. */
  gitRemotes?: (cwd: string) => string[];
  /** The law's connect allowances (policy.yaml `destinations:` → arbiter op
   *  `netConnectAllow`, read by run.ts via net-guard-law.ts). Appended to the
   *  guard set as fallback-preserving EXTRA allows (net-guard.ts). */
  lawAllow?: string[];
  log?: (msg: string) => void;
  /** The host platform (run.ts passes `platform.id`). The guard is seccomp
   *  user notification, Linux only: elsewhere no bin is looked for and ONE
   *  informational line says so (never the "not built" degrade; on macOS the
   *  Seatbelt profile confines TCP by port, exec-routing.md §7.5). Absent:
   *  the Linux path. */
  platform?: "linux" | "darwin" | "win32";
}

/** The one line a non-Linux launch prints for the guard (an informational
 *  note: shown under --verbose, never an attention note). */
export const NET_GUARD_LINUX_ONLY_NOTE =
  "mandu: net-guard (the connect guard that pins :443 to named hosts) is Linux only; on macOS the whole-agent " +
  "Seatbelt profile confines TCP by port instead (the network-confine line)";

/** Read the workspace's git remote URLs via `git config --get-regexp`. Returns []
 *  on any failure (not a repo / git absent) — the guard just skips the auto-add.
 *  Hardened (hardened-git.ts): the workspace's config is the agent's to write. */
export function readGitRemotes(cwd: string): string[] {
  try {
    countGitCall(false); // the launch's costs (launch-timings.ts)
    const out = execFileSync("git", hardenedGitArgs(["-C", cwd, "config", "--get-regexp", "^remote\\..*\\.url$"]), {
      encoding: "utf8",
      env: hardenedGitEnv(),
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 3000,
    });
    // Lines are "remote.<name>.url <URL>" — take the last whitespace-delimited field.
    return out
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => l.slice(l.indexOf(" ") + 1).trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

/** The model API host the guard admits on :443, per target. */
function apiHostFor(plan: LaunchPlan): string {
  return plan.target === "codex" ? "api.openai.com" : "api.anthropic.com";
}

/** Tells the guard to serve the command box's socket allow-list, and the box
 *  that it does (exec-routing.md §4.2; read by mandu-net-guard and
 *  mandu-exec-box). */
export const NET_GUARD_BOX_SOCKETS_ENV = "MANDU_NET_GUARD_BOX_SOCKETS";

/** The variable naming the agent's executable for the guard's private-server
 *  allowance (`net_supervisor::own_server::OWN_SERVER_ENV`). */
export const NET_GUARD_OWN_SERVER_ENV = "MANDU_NET_GUARD_OWN_SERVER";

/** The variable naming the session the guard files its events under
 *  (`net_supervisor::events::guard_session_id`; exec-routing.md §7.5,
 *  "Whose session"). */
export const NET_GUARD_SESSION_ENV = "MANDU_SESSION_ID";

/** The launch's guard status file, in the session's scope-run dir. */
export function netGuardStatusFile(plan: Pick<LaunchPlan, "eventDir">): string {
  return resolve(plan.eventDir, "..", "net-guard.status");
}

/**
 * Prepend the whole-agent connect-guard wrap. No-ops when `plan.netGuard` is
 * false (explicit opt-out); undefined = default-on. Returns the wrap argv it
 * prepended (or null when it degraded / was off) for the caller's banner + tests.
 */
export function applyNetGuard(
  plan: LaunchPlan,
  mut: LaunchMutation,
  deps: NetGuardDeps = {},
): { wrapArgv: string[]; specs: string[] } | null {
  if (plan.netGuard === false) return null;
  const log = deps.log ?? ((m: string) => console.error(m));
  if (deps.platform !== undefined && deps.platform !== "linux") {
    if (deps.platform === "darwin") log(NET_GUARD_LINUX_ONLY_NOTE);
    return null;
  }
  const resolveBin = deps.resolveBin ?? resolveNativeBin;
  // Explicit request (--net-guard) vs the default-on posture: both degrade
  // identically (additive hardening, never a gate), but the message must not
  // claim the user "asked" for what a default provided.
  const asked = plan.netGuard === true ? "--net-guard asked for" : "the default-on";

  const binPath = resolveBin("mandu-net-guard");
  if (!binPath) {
    log(
      `mandu: ${asked} whole-agent connect-guard is unavailable — the ` +
      "mandu-net-guard bin is not built; proceeding WITHOUT it (the landlock-net " +
      `port wrap / netns stay the boundary). ${buildHintFor("mandu-net-guard")}`,
    );
    return null;
  }
  const guardStale = (deps.staleNote ?? staleNativeBinNote)("mandu-net-guard", binPath);
  if (guardStale) log(guardStale);

  const strict = plan.landlockNetStrict === true;
  const targetProxyPort = wireOf(plan.target) === "anthropic" ? plan.proxy.port : plan.openaiProxy.port;
  const netProxyPort = plan.netProxy ? plan.netProxy.port : null;
  const ullmForwarderPort = plan.ullmForwarder ? plan.ullmForwarder.port : null;

  // Git-remote auto-allow: only when the set is NARROWED (strict/curated) — the
  // `*:443/*:22` fallback already covers remotes in the permissive default, so
  // enumerating there would be a pointless `git` call. Opt out with
  // --no-net-guard-git / MANDU_NET_GUARD_GIT=0. The reader is injectable.
  // The remotes are the USER's workspace's (plan.humanCwd), never plan.cwd:
  // with fs-sync on, plan.cwd is the AgentView worktree of the shadow repo
  // (fs-sync.md §3), which carries no remotes, so reading it silently
  // auto-allowed nothing from 2026-07-19 until 2026-09-28.
  const narrowed = strict || plan.netGuardAllow !== undefined;
  let gitSpecs: string[] | undefined;
  if (narrowed && plan.netGuardGitRemotes !== false) {
    const readRemotes = deps.gitRemotes ?? readGitRemotes;
    gitSpecs = gitRemoteSpecs(readRemotes(plan.humanCwd || plan.cwd));
  }

  // policy.yaml `models:` (confidentiality-plan-11 D5): the entry the helper
  // dials, pinned to its host; read from the arbiter by run.ts.
  const modelEndpointSpecs = helperEndpointGuardSpecs(plan.modelEndpoints ?? []);
  const specs = computeNetGuardSpecs({
    targetProxyPort,
    netProxyPort,
    ullmForwarderPort,
    cdpRelayPort: plan.cdpRelay ? plan.cdpRelay.port : null,
    // The model-host deny (model-host-deny.ts): no direct :443 allowance
    // for the API host; it is denied below instead.
    apiHost: plan.modelHostDeny === true ? null : apiHostFor(plan),
    explicitAllow: plan.netGuardAllow,
    gitRemoteSpecs: gitSpecs,
    strict,
    extraAllow: deps.lawAllow,
    modelEndpointSpecs,
  });
  // exec-routing.md §8.5.3: the guard hosts the clean box (clean-host.ts)
  // and serves the command box's sockets (below), so the hosted box is told
  // so too.
  const clean = plan.cleanHost
    ? cleanHostGuardArgs(
      { ...plan.cleanHost, env: [...plan.cleanHost.env, [NET_GUARD_BOX_SOCKETS_ENV, "1"]] },
      plan.scopeId,
    )
    : [];
  // The agent's upload hosts (upload-deny.ts; supported-agents.md §5.3.4
  // rule 1), refused before any allow rule, so they beat the `*:443` fallback.
  const uploadDeny = uploadDenyGuardSpecs(plan.uploadDenyHosts ?? []);
  // The model-host deny (model-host-deny.ts; agent-sdks.md §4): every model
  // vendor's host, refused before any allow rule, so a program that dials
  // one around the egress proxy (its proxy variables unset or ignored) is
  // refused at connect. Only when the egress proxy carries the deny.
  const modelDeny = plan.modelHostDeny === true ? modelHostGuardDenySpecs().filter((s) => !uploadDeny.includes(s)) : [];
  const deny = [...uploadDeny, ...modelDeny];
  // OpenCode 2 with confidentiality ON depends on the guard
  // (opencode2-confidentiality.ts): no in-place degrade for it.
  const { wrapArgv } = planNetGuard({ binPath, specs, deny, extra: clean, required: plan.netGuardRequired === true });
  if (uploadDeny.length > 0) {
    log(`mandu: net-guard — ${uploadDeny.length} upload destination(s) of this agent denied in-kernel [${uploadDeny.join(", ")}]`);
  }
  if (modelDeny.length > 0) {
    log(`mandu: net-guard — the model hosts are denied to the agent's programs in-kernel [${modelDeny.join(", ")}]; they reach them only through the egress proxy, for the account and sign-in calls it lists`);
  }

  // OUTERMOST net wrap: prepend so it wraps the landlock-net port wrap, the
  // secret-twins bwrap, and every child; the reply-filter (prepended later)
  // stays outside. Called AFTER applyLandlockNet so it lands ahead of it.
  mut.launchPrefix = [...wrapArgv, ...mut.launchPrefix];
  // The command box's socket allow-list (exec-routing.md §4.2): the kernel
  // allows ONE seccomp listener per filter chain and the guard holds it for the
  // whole agent, so a box under it cannot install its own. The guard serves the
  // box instead (it also traps bind, and applies the box's allow-list to a
  // boxed process's connects); the box reads the same variable to know it.
  // Without it a box under the guard refuses every connect (fail-closed).
  mut.env[NET_GUARD_BOX_SOCKETS_ENV] = "1";
  // exec-routing.md §7.5 (2026-10-01): the only loopback ports a process
  // holding a secret reaches without a binding (sessionProxyPorts).
  mut.env[NET_GUARD_PROXY_PORTS_ENV] = sessionProxyPorts({ netProxyPort }).join(",");
  // supported-agents.md §2.3.1: an OpenCode 2 launch names its executable,
  // so the guard performs its private server's ephemeral loopback bind and
  // admits the client's connect to it (net-supervisor own_server.rs). A
  // value already in the environment is the user's own (or a test's) and
  // is left as it is; nothing is set for any other launch.
  if (plan.ownServerExe) {
    mut.env[NET_GUARD_OWN_SERVER_ENV] = plan.ownServerExe;
    log(`mandu: net-guard — the agent's private server (${plan.ownServerExe}): its ephemeral loopback port is reachable from the agent's own process only`);
  }
  // exec-routing.md §7.5 "Whose session": the guard files its events (a
  // refused connect, a twin served) under this launch's session, the id the
  // model proxy files the session's turns under (env-compose.ts, the
  // x-mandu-session-id header). Set unconditionally: a value inherited from
  // an outer launch names that launch, not this one.
  mut.env[NET_GUARD_SESSION_ENV] = plan.scopeId;
  // §12.2: the guard records itself here; a file left at `supervising`
  // after the launch means it died first (guard-death.ts).
  const statusFile = netGuardStatusFile(plan);
  // A reused --id's scope dir may hold the last launch's record.
  try { rmSync(statusFile, { force: true }); } catch { /* best-effort */ }
  mut.env[NET_GUARD_STATUS_ENV] = statusFile;

  // Banner + the honest residuals (exec-routing.md §7.5).
  const curated = plan.netGuardAllow !== undefined;
  log(
    `mandu: net-guard LIVE — whole-agent connect(2) confined by DESTINATION ` +
    `(IP/CIDR/host × port); ${specs.length} allow rule(s) (deny all other TCP/UDP ` +
    `connects in-kernel; ${plan.netGuardRequired === true
      ? "REQUIRED for this launch: where seccomp is unavailable the launch fails instead of running unguarded"
      : "--skip-unsupported degrades where seccomp is unavailable"})`,
  );
  if (specsAdmitAnyHttps(specs)) {
    log(
      "mandu: net-guard — the permissive fallback tcp:*:443 + tcp:*:22 stays in " +
      "the non-strict default (arbitrary HTTPS + git-ssh keep working). The honest " +
      "trade-off: an any-host-:443/:22 exfil is still possible — --landlock-net-strict " +
      "OR --net-allow=<host:port,...> drops the fallback and pins :443 to the API host " +
      "+ your curated set (still reachable via the guard's supervisor-connect).",
    );
  } else {
    log(
      `mandu: net-guard ${curated ? "CURATED" : "STRICT"} — :443 is admitted ONLY to ` +
      `${plan.modelHostDeny === true ? "no model host (the egress proxy carries them)" : apiHostFor(plan)}${curated ? " + your --net-allow set" : ""} (+ loopback services + DNS` +
      `${gitSpecs && gitSpecs.length ? " + git remotes" : ""}); ` +
      "every other destination is denied in-kernel. Direct TLS to unlisted hosts " +
      "(npm/pip/git-https to arbitrary registries) will fail — add them with --net-allow.",
    );
    if (gitSpecs && gitSpecs.length) {
      log(
        `mandu: net-guard — auto-allowed ${gitSpecs.length} git-remote destination(s) ` +
        `[${gitSpecs.join(", ")}] so push/fetch survive the narrowed guard ` +
        "(--no-net-guard-git / MANDU_NET_GUARD_GIT=0 to disable).",
      );
    }
  }

  if (deps.lawAllow && deps.lawAllow.length) {
    log(
      `mandu: net-guard — policy.yaml allows ${deps.lawAllow.length} extra destination(s) ` +
      `[${deps.lawAllow.join(", ")}] (destinations: connect: allow; additive — the fallback and ` +
      "your --net-allow set are unchanged).",
    );
  }

  if (modelEndpointSpecs.length > 0) {
    log(
      `mandu: net-guard: your own model endpoint(s) allowed [${modelEndpointSpecs.join(", ")}] ` +
      "(policy.yaml models: with local: true; additive).",
    );
  }

  return { wrapArgv, specs };
}
