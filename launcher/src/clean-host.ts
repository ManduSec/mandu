/**
 * clean-host — the launcher's half of the guard-hosted clean box
 * (docs/design/integrity/exec-routing.md §8.5.3, sandbox-security-review-2026-09-28
 * finding 4). Mandu-new, no reference origin.
 *
 * A clean verdict un-masks a Bash result, so it may come only from outside
 * the agent's process tree. The session's guard (`mandu-net-guard`) is: this
 * launcher starts it before the agent, and the agent can neither signal nor
 * read it. So:
 *   1. the launcher's FIRST `setSessionUpstream` for the session asks for a
 *      reporter (`cleanReporter: true`); only that fresh, bind-once call can
 *      make the session's reporter claimable (arbiter/policy/clean-reporters.ts);
 *   2. the exec-box shims learn the guard's socket (`MANDU_EXEC_CLEAN_SOCK`)
 *      and the clean box goes ON by default, since it now buys the upgrade;
 *   3. the guard gets `--clean-socket/--clean-session/--clean-box/--clean-env`:
 *      it claims the token before the agent starts and runs each clean
 *      attempt itself, with the box binary and the environment named HERE
 *      (never the agent's), then reports with its token.
 * Where any piece is missing (integrity axis off, no exec box, no guard, an
 * arbiter that does not offer the reporter) nothing is hosted and no verdict
 * counts: the fail-closed default.
 */

import { join } from "node:path";
import { resolveNativeBin } from "./services/native-bins.js";
import type { LaunchPlan } from "./types.js";

/** What the guard is told to host. */
export interface CleanHostPlan {
  /** The guard's clean-run socket (in the session run dir). */
  socket: string;
  /** The `mandu-exec-box` the guard runs (`--clean-only`). */
  boxBin: string;
  /** The hosted box's whole environment. */
  env: Array<[string, string]>;
}

/** Should this launch ask the arbiter for a clean reporter? Only where a
 *  clean verdict can matter (integrity axis ON: Bash results are masked) and
 *  the pieces can exist (Linux, the exec box and the guard not turned off,
 *  the clean box not refused). Codex boxes its own commands (exec-box is off
 *  for it unless forced). */
export function cleanReporterWanted(
  plan: LaunchPlan,
  platformId: string,
  guardBuilt: () => boolean = () => resolveNativeBin("mandu-net-guard") !== null,
): boolean {
  if (platformId !== "linux") return false;
  if (plan.effectiveAxes?.integrity !== true) return false;
  if (plan.execBox === false || plan.execCleanBox === false || plan.netGuard === false) return false;
  if (plan.target === "codex" && plan.execBox !== true) return false;
  return guardBuilt();
}

/** The guard's clean-run socket for a session run dir. */
export function cleanHostSocket(scopeRunDir: string): string {
  return join(scopeRunDir, "clean.sock");
}

/** Variables the hosted box inherits from the launch's own environment:
 *  what a command needs to run the same way (PATH, HOME, locale, time zone,
 *  the user's names), what the box's host hiding reads (HOME,
 *  XDG_RUNTIME_DIR) and the tenant stamp. */
export const CLEAN_HOST_PASS_ENV = [
  "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TZ", "XDG_RUNTIME_DIR", "MANDU_TENANT",
] as const;

/** The hosted box's environment: the box's own configuration (what the
 *  shims bake) plus {@link CLEAN_HOST_PASS_ENV} from the launch. */
export function cleanHostEnv(opts: {
  arbiterSock: string;
  hostEnv: Record<string, string | undefined>;
  view?: { agentViewRoot: string; workspace: string };
  projectRoot?: string;
  landlockApply?: string;
  /** Mandu's own bubblewrap (bwrap-grant.ts), first on PATH as it is on the
   *  agent's: where `mandu setup` replaced the system bwrap's AppArmor grant,
   *  the system one cannot set up the box's namespaces. */
  bwrapDir?: string;
}): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const k of CLEAN_HOST_PASS_ENV) {
    let v = opts.hostEnv[k];
    if (k === "PATH" && opts.bwrapDir) v = v ? `${opts.bwrapDir}:${v}` : opts.bwrapDir;
    if (typeof v === "string" && v !== "" && !v.includes("\0")) out.push([k, v]);
  }
  out.push(["MANDU_ARBITER_SOCK", opts.arbiterSock]);
  if (opts.view) {
    out.push(["MANDU_AGENTVIEW_ROOT", opts.view.agentViewRoot], ["MANDU_WORKSPACE", opts.view.workspace]);
  } else if (opts.projectRoot) {
    out.push(["MANDU_WORKSPACE", opts.projectRoot]);
  }
  if (opts.landlockApply) out.push(["MANDU_LANDLOCK_APPLY", opts.landlockApply]);
  return out;
}

/** The guard's arguments for a hosted clean box (before its `--`). */
export function cleanHostGuardArgs(host: CleanHostPlan, session: string): string[] {
  return [
    "--clean-socket", host.socket,
    "--clean-session", session,
    "--clean-box", host.boxBin,
    ...host.env.flatMap(([k, v]) => ["--clean-env", `${k}=${v}`]),
  ];
}
