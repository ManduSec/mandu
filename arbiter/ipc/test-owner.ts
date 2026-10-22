/**
 * test-owner — a daemon a test started exits when that test's process is gone
 * (docs/design/architecture/runtime-instances.md §8a).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code, duplicated
 * verbatim in dashboard/src/test-owner.ts (the repo's narrow-module
 * convention: no cross-package src imports). Keep the copies in sync.
 *
 * The incident (2026-10-21): twelve arbiters and three dashboards started by
 * test suites in agent worktrees on 2026-10-17/18 were still serving four
 * days later. The resident stack a launch autostarts has no owner and no
 * lifeline on purpose (§8, §10: it outlives the launch), and the arbiter
 * suites that spawn the daemon pass no lifeline either, so a test process
 * killed before its `finally` (a runner timeout, an interrupted run, a
 * SIGKILL) left them running for good. They registered under the test's own
 * temp runtime dir, which `mandu reap` never scans.
 *
 * The rule, read once when the daemon starts:
 *   1. `MANDU_TEST_OWNER_PID=<pid>` names the owner explicitly (a harness that
 *      runs outside node's test runner); `0` or `none` turns the rule off;
 *   2. else, when `NODE_TEST_CONTEXT` is set (node's test runner sets it in
 *      the process of each test file, and every process that file spawns
 *      inherits it), the owner is the TOPMOST ancestor whose environment
 *      also carries it: the test file's process, not a launcher CLI or
 *      dashboard in between, which may exit long before the test does;
 *   3. else there is no owner (every production start).
 * The owner is written back into this process's environment as
 * MANDU_TEST_OWNER_PID, so what the daemon spawns (the dashboard's arbiter,
 * a self-restart's successor) inherits it even after the chain of parents
 * is broken. The daemon then checks once a second that the owner still runs
 * (on Linux, the same process: its start time unchanged, so a reused pid does
 * not count), and runs its graceful SIGTERM shutdown when it does not.
 *
 * Linux reads the ancestry from /proc; elsewhere only rule 1 applies.
 */
import { readFileSync } from "node:fs";

/** The process facts the rule needs (test-injectable). */
export interface TestOwnerDeps {
  selfPid: number;
  /** The parent pid of `pid`, or null when unreadable. */
  parentOf(pid: number): number | null;
  /** The environment `pid` was started with, or null when unreadable. */
  environOf(pid: number): string[] | null;
  /** An opaque start time of `pid` (Linux: field 22 of /proc/<pid>/stat), or null. */
  startTimeOf(pid: number): string | null;
  /** Whether `pid` exists (signal 0; EPERM counts as alive). */
  alive(pid: number): boolean;
}

/** Fields after the comm of /proc/<pid>/stat (comm may hold spaces and parens). */
function statFields(pid: number): string[] | null {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    return stat.slice(stat.lastIndexOf(")") + 2).split(" ");
  } catch {
    return null;
  }
}

export const realTestOwnerDeps: TestOwnerDeps = {
  selfPid: process.pid,
  parentOf: (pid) => {
    const f = statFields(pid);
    const ppid = f ? Number(f[1]) : NaN; // field 4 = index 1 after state
    return Number.isInteger(ppid) && ppid > 0 ? ppid : null;
  },
  environOf: (pid) => {
    try { return readFileSync(`/proc/${pid}/environ`, "latin1").split("\0"); } catch { return null; }
  },
  startTimeOf: (pid) => statFields(pid)?.[19] ?? null, // field 22 = index 19 after state
  alive: (pid) => {
    try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EPERM"; }
  },
};

const CONTEXT = "NODE_TEST_CONTEXT=";

/** The test process that owns this daemon (rules 1 to 3 above), or null. */
export function resolveTestOwner(
  env: Record<string, string | undefined> = process.env,
  deps: TestOwnerDeps = realTestOwnerDeps,
): number | null {
  const explicit = (env["MANDU_TEST_OWNER_PID"] ?? "").trim();
  if (explicit !== "") {
    if (explicit === "0" || explicit.toLowerCase() === "none") return null;
    const n = Number(explicit);
    return Number.isInteger(n) && n > 1 && n !== deps.selfPid ? n : null;
  }
  if ((env["NODE_TEST_CONTEXT"] ?? "") === "") return null;
  let top: number | null = null;
  let pid = deps.parentOf(deps.selfPid);
  for (let depth = 0; depth < 64 && pid !== null && pid > 1; depth++) {
    const environ = deps.environOf(pid);
    if (!environ || !environ.some((e) => e.startsWith(CONTEXT) && e.length > CONTEXT.length)) break;
    top = pid;
    pid = deps.parentOf(pid);
  }
  return top;
}

/** A started watch: the owner it follows; stop() ends the polling. */
export interface TestOwnerWatch {
  owner: number;
  stop(): void;
}

/**
 * Resolve the owner and, when there is one, poll it every `intervalMs` and
 * call `onGone` ONCE when it is gone (treat it like SIGTERM). Returns null
 * when there is no owner. The timer is unref'd: it never keeps a closing
 * daemon alive.
 */
export function armTestOwnerWatch(
  onGone: (owner: number) => void,
  env: Record<string, string | undefined> = process.env,
  deps: TestOwnerDeps = realTestOwnerDeps,
  intervalMs = 1_000,
): TestOwnerWatch | null {
  const owner = resolveTestOwner(env, deps);
  if (owner === null) return null;
  env["MANDU_TEST_OWNER_PID"] = String(owner);
  const born = deps.startTimeOf(owner);
  let fired = false;
  const gone = (): boolean => !deps.alive(owner) || (born !== null && deps.startTimeOf(owner) !== born);
  const timer = setInterval(() => {
    if (fired || !gone()) return;
    fired = true;
    clearInterval(timer);
    onGone(owner);
  }, intervalMs);
  timer.unref?.();
  return { owner, stop: () => clearInterval(timer) };
}
