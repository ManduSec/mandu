/**
 * scope-dir-cleanup — a launch removes its own scope run dir
 * (`<runtime base>/<epochSec>-<pid>/`) when it ends cleanly
 * (runtime-instances.md §10.1; os-test-matrix.md §10.16.2).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin:
 * the plugin realization ran inside its host and staged nothing per launch).
 *
 * The scope dir holds what the launch staged for its own agent and services:
 * exec shims, the MCP and agent configs, the secret twins, the guard policy,
 * the services' port files and logs, launch.log. Nothing reads it after the
 * launch: the services are stopped, the session's record is the arbiter's
 * event store (launch.log's lines are also its `launch_posture` event). Before
 * this, every launch left it behind for `mandu reap` or the next reboot.
 *
 * What is removed is deliberately narrow. The dir goes only when ALL hold:
 *   - the launch ended cleanly: the teardown ran to the end and the session's
 *     exit code is 0. A failed session keeps its logs for diagnosis; a
 *     launcher killed part-way (SIGTERM, SIGHUP, a crash) never gets here.
 *     `mandu reap` collects both (its pid is dead);
 *   - the launcher minted the scope id itself (`<epochSec>-<own pid>`). A
 *     scope named with `--id` / MANDU_SCOPE_ID is the caller's: harnesses read
 *     it after the launch, and two launches may share the name;
 *   - the path is `<runtime base>/<that id>`, a real directory (not a
 *     symlink) owned by this uid;
 *   - no arbiter this launch started lives off it: a per-launch (pinned)
 *     arbiter writes its events and log there and outlives the launcher, and
 *     a socket placed inside it would be cut off;
 *   - MANDU_KEEP_SCOPE_DIR is not set (forensics, and harnesses that read what
 *     the launch staged).
 * Removal is best-effort: a failure leaves the dir for `mandu reap`.
 *
 * Pure decision (`scopeDirCleanupDecision`) plus the removal over injectable
 * fs calls (`removeOwnScopeDir`).
 */
import { lstatSync, rmSync } from "node:fs";
import { join, relative, isAbsolute } from "node:path";

export interface ScopeDirCleanupInput {
  /** The launch's scope run dir (plan.eventDir/..). */
  scopeRunDir: string;
  /** The runtime base the scope dir sits in (plan.arbiterRuntimeBase). */
  runtimeBase: string;
  scopeId: string;
  /** True when parse minted the id (no --id / MANDU_SCOPE_ID). */
  scopeIdGenerated: boolean;
  /** This launcher's pid. */
  pid: number;
  /** The session's exit code, as the launcher returns it. */
  code: number;
  /** This launch started a per-launch (pinned) arbiter, which writes into the
   *  scope dir and outlives the launcher. */
  startedPinnedArbiter: boolean;
  arbiterSock: string;
  /** MANDU_KEEP_SCOPE_DIR is set. */
  keep: boolean;
}

export type ScopeDirVerdict = { remove: true } | { remove: false; reason: string };

/** Is `p` inside (or equal to) `dir`? Lexical, both absolute. */
function within(dir: string, p: string): boolean {
  const r = relative(dir, p);
  return r === "" || (!r.startsWith("..") && !isAbsolute(r));
}

/** Whether a clean end of this launch removes its scope dir, and if not, why. Pure. */
export function scopeDirCleanupDecision(i: ScopeDirCleanupInput): ScopeDirVerdict {
  if (i.keep) return { remove: false, reason: "MANDU_KEEP_SCOPE_DIR is set" };
  if (i.code !== 0) return { remove: false, reason: `the session exited ${i.code}; its scope dir is kept for diagnosis (mandu reap collects it)` };
  if (!i.scopeIdGenerated) return { remove: false, reason: "the scope was named (--id / MANDU_SCOPE_ID); a named scope dir is the caller's" };
  const m = i.scopeId.match(/^\d+-(\d+)$/);
  if (!m || Number(m[1]) !== i.pid) return { remove: false, reason: `scope id ${i.scopeId} is not this launcher's (pid ${i.pid})` };
  if (!isAbsolute(i.runtimeBase) || i.scopeRunDir !== join(i.runtimeBase, i.scopeId)) {
    return { remove: false, reason: `${i.scopeRunDir} is not <runtime base>/${i.scopeId}` };
  }
  if (i.startedPinnedArbiter) return { remove: false, reason: "the arbiter this launch started keeps its events and log there" };
  if (i.arbiterSock !== "" && within(i.scopeRunDir, i.arbiterSock)) return { remove: false, reason: "the arbiter's socket lives there" };
  return { remove: true };
}

export interface RemoveDeps {
  lstat?: (p: string) => { isDirectory(): boolean; isSymbolicLink(): boolean; uid: number };
  rm?: (p: string) => void;
  uid?: number | undefined;
}

/** Remove the scope dir the decision allowed. Never follows a symlink (the
 *  dir itself must be a real directory; rm -r unlinks links inside it) and
 *  never throws. */
export function removeOwnScopeDir(dir: string, deps: RemoveDeps = {}): { removed: boolean; error?: string } {
  const lstat = deps.lstat ?? ((p: string) => lstatSync(p));
  const rm = deps.rm ?? ((p: string) => rmSync(p, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 }));
  const uid = "uid" in deps ? deps.uid : process.getuid?.();
  try {
    const st = lstat(dir);
    if (st.isSymbolicLink() || !st.isDirectory()) return { removed: false, error: `${dir} is not a directory` };
    if (uid !== undefined && st.uid !== uid) return { removed: false, error: `${dir} is not owned by uid ${uid}` };
    rm(dir);
    return { removed: true };
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { removed: false };
    return { removed: false, error: e instanceof Error ? e.message : String(e) };
  }
}
