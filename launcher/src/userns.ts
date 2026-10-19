/**
 * userns — can this host create an unprivileged user namespace, and if not,
 * WHY (docs/design/architecture/privilege-model.md "Host prerequisite: Ubuntu's AppArmor
 * userns restriction").
 *
 * Mandu's own bubblewrap (bwrap-grant.ts), when `mandu setup` installed it
 * and its grant is loaded, answers first: it is what the rungs run then.
 * Otherwise two probes, in the order the launcher's own rungs use them:
 *   1. `bwrap --unshare-user …` — bubblewrap is what the secret-twins wrap and
 *      the exec-box actually run. Ubuntu's AppArmor restriction grants
 *      `userns` PER BINARY, so a host whose profile covers bwrap alone must
 *      count as able even though a bare `unshare --user` is still denied.
 *      The bwrap is the distribution's (bwrap-path.ts: by absolute path,
 *      never one inside the current directory).
 *   2. `unshare --user --map-root-user --mount` — the historical probe, the
 *      fallback where there is no such bwrap.
 *
 * The hint reads the kernel knobs that gate unprivileged userns creation and
 * names the one that is shut, with the fix. Pure: every side effect is an
 * injectable dep so the decision logic is unit-tested with no privilege.
 *
 * Mandu-new (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { manduBwrapInForceHere } from "./bwrap-grant.js";
import { systemBwrapBin } from "./bwrap-path.js";
import { cachedProbe, type ProbeInputs } from "./probe-cache.js";

export interface UsernsProbeDeps {
  /** The distribution's bubblewrap by absolute path, or null (bwrap-path.ts
   *  systemBwrapBin: never one inside the current directory). */
  bwrapBin?: () => string | null;
  /** Run a command with its args; true iff it exited 0. */
  runOk?: (cmd: string, args: string[]) => boolean;
  /** Mandu's own bubblewrap is in force (bwrap-grant.ts): it is what the
   *  rungs run then, and its probe already passed. */
  manduBwrapInForce?: () => boolean;
}

const defaultRunOk = (cmd: string, args: string[]): boolean =>
  spawnSync(cmd, args, { stdio: "ignore" }).status === 0;

/** The bubblewrap probe: a user+pid namespace over a read-only root, running `true`. */
export const BWRAP_PROBE_ARGV = ["--unshare-user", "--unshare-pid", "--ro-bind", "/", "/", "--", "true"];
/** The util-linux probe: a user+mount namespace with the caller mapped to root. */
export const UNSHARE_PROBE_ARGV = ["--user", "--map-root-user", "--mount", "--", "true"];

/**
 * Can we create an unprivileged user (+ mount / pid) namespace here?
 * bwrap decides when it is on PATH (the binary the rungs actually exec);
 * otherwise `unshare` decides.
 */
export function probeUserns(deps: UsernsProbeDeps = {}): boolean {
  const runOk = deps.runOk ?? defaultRunOk;
  // A fixture that injects its own runner never reads the host's copy.
  if ((deps.manduBwrapInForce ?? (deps.runOk ? (): boolean => false : manduBwrapInForceHere))()) return true;
  // The functional probe, as Codex runs one: a bwrap that cannot make the
  // namespace is no bwrap for the rungs, whatever `--version` says.
  const bwrap = (deps.bwrapBin ?? systemBwrapBin)();
  if (bwrap !== null) return runOk(bwrap, BWRAP_PROBE_ARGV);
  return runOk("unshare", UNSHARE_PROBE_ARGV);
}

/** What the userns probe runs: its key's own inputs (probe-cache.ts). */
export const usernsProbeInputs = (): ProbeInputs => ({ bins: [systemBwrapBin() ?? "bwrap:none", "unshare"], argv: [...BWRAP_PROBE_ARGV, "|", ...UNSHARE_PROBE_ARGV] });

/**
 * The launch's userns answer: Mandu's own bubblewrap in force answers first
 * (as in probeUserns), else the probe, whose pass a launch keeps for the boot
 * (probe-cache.ts; outside a launch this is probeUserns). A kept pass is
 * enacted like a fresh one: the secret wrap and the exec box die when it was
 * wrong, so the step is never skipped.
 */
export function launchUsernsOk(): boolean {
  if (manduBwrapInForceHere()) return true;
  return cachedProbe("userns", usernsProbeInputs, () => probeUserns({ manduBwrapInForce: () => false }));
}

/** The kernel knobs consulted, in precedence order. */
export const APPARMOR_USERNS_SYSCTL = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
export const USERNS_CLONE_SYSCTL = "/proc/sys/kernel/unprivileged_userns_clone";
export const MAX_USER_NAMESPACES_SYSCTL = "/proc/sys/user/max_user_namespaces";

/** Mandu's own bubblewrap and its AppArmor grant (bwrap-grant.ts). */
export const APPARMOR_GRANT_HINT =
  "install Mandu's own bubblewrap with `mandu setup` (asks for sudo once)";

const defaultReadFile = (path: string): string | null => {
  try { return readFileSync(path, "utf8"); } catch { return null; }
};

/**
 * One cause+fix sentence for a failed userns probe. A knob whose file is
 * missing (older kernel, no AppArmor) is skipped, not treated as shut.
 */
export function usernsGapHint(readFile: (path: string) => string | null = defaultReadFile): string {
  const knob = (path: string): string | null => readFile(path)?.trim() ?? null;
  if (knob(APPARMOR_USERNS_SYSCTL) === "1") {
    return "kernel.apparmor_restrict_unprivileged_userns=1 (Ubuntu 24.04 AppArmor): only binaries whose " +
      `AppArmor profile grants \`userns\` may create one; ${APPARMOR_GRANT_HINT}`;
  }
  if (knob(USERNS_CLONE_SYSCTL) === "0") {
    return "kernel.unprivileged_userns_clone=0: unprivileged user namespaces are switched off; " +
      "set it to 1 (`sudo sysctl -w kernel.unprivileged_userns_clone=1`, persisted under /etc/sysctl.d/)";
  }
  if (knob(MAX_USER_NAMESPACES_SYSCTL) === "0") {
    return "user.max_user_namespaces=0: the user-namespace quota is zero; raise it " +
      "(`sudo sysctl -w user.max_user_namespaces=<n>`, persisted under /etc/sysctl.d/)";
  }
  return "the probe failed (a container / seccomp policy denies the namespace, or the kernel lacks CONFIG_USER_NS)";
}
