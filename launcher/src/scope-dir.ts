/**
 * scope-dir — a launch makes its own scope run dir (`<runtime base>/<scope
 * id>/`) before anything is written into it, and never adopts one someone
 * else prepared (runtime-instances.md §2 "planted paths", §10.2).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 *
 * Why: the runtime base stays writable to the agent (its own scope dir is
 * there; on macOS the Seatbelt profile write-denies only Mandu's registries,
 * and on Linux nothing stops a same-uid process). A minted scope id is
 * predictable (`<epochSec>-<pid>`), so an agent could make a FUTURE launch's
 * scope dir in advance with links planted inside (`launch.log`, a service
 * log, the profile's copy): the launcher and its services, which run outside
 * any confinement, would then write through them into the user's files. The
 * dir used to be made by whichever service came first, with `mkdir -p`,
 * which adopts whatever is there.
 *
 * So run.ts makes it before anything is written into it (in the per-launch
 * arbiter's start, which writes there, or right after the arbiter is up,
 * before any service):
 *   - the runtime base is made (`mkdir -p`, as before) after the fallback's
 *     private-dir rule ran (arbiter.ts `guardRuntimePath`);
 *   - a MINTED scope's dir is made non-recursively, mode 0700, and one that
 *     already exists REFUSES the launch (the id holds this process's pid and
 *     the current second, so no one else had a reason to make it). The one
 *     exception is a dir THIS process made: the per-launch arbiter's start
 *     made it a moment before (run.ts calls this again once the arbiter is
 *     up), or an in-process caller of run.ts main() (the e2e tests) launched
 *     twice in one second. Such a dir is checked again, as a named one is;
 *   - a NAMED scope's dir (`--id`, MANDU_SCOPE_ID) may exist, since a caller
 *     may reuse the name, but only as a real directory (not a link) owned by
 *     this uid; a new one is made 0700.
 * What this does not close: once made, the dir is still writable to the agent
 * of ANOTHER session while this one runs (confidentiality.md §7.3 residuals).
 *
 * Pure decision over injectable fs calls; the default deps are the real fs.
 */
import { lstatSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export interface ScopeDirInput {
  /** The launch's scope run dir (plan.eventDir/..). */
  scopeRunDir: string;
  /** True when parse minted the id (no --id / MANDU_SCOPE_ID). */
  scopeIdGenerated: boolean;
}

export interface ScopeDirDeps {
  mkdir?: (p: string, opts: { recursive?: boolean; mode?: number }) => void;
  lstat?: (p: string) => { isDirectory(): boolean; isSymbolicLink(): boolean; uid: number };
  /** This process's uid; undefined where the platform has none. */
  uid?: number | undefined;
}

/** The scope dirs this process made (see the module doc). */
const madeHere = new Set<string>();

/** Make the launch's scope dir, or throw a refusal that says why. */
export function createScopeDir(i: ScopeDirInput, deps: ScopeDirDeps = {}): void {
  const mkdir = deps.mkdir ?? ((p: string, o: { recursive?: boolean; mode?: number }) => { mkdirSync(p, o); });
  const lstat = deps.lstat ?? ((p: string) => lstatSync(p));
  const uid = "uid" in deps ? deps.uid : process.getuid?.();
  const dir = i.scopeRunDir;
  mkdir(dirname(dir), { recursive: true });
  try {
    mkdir(dir, { mode: 0o700 });
    madeHere.add(dir);
    return;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
  }
  if (i.scopeIdGenerated && !madeHere.has(dir)) {
    throw new Error(
      `mandu: refusing to launch: the session folder ${dir} already exists, and this launch did not make it ` +
        "(its name holds this launch's process id and start time, so something prepared it in advance). " +
        "Nothing was written into it; remove it and launch again (runtime-instances.md §2).",
    );
  }
  const st = lstat(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new Error(
      `mandu: refusing to launch: the session folder ${dir} is not a real directory (a link or a file); ` +
        "remove it, or pick another --id (runtime-instances.md §2).",
    );
  }
  if (uid !== undefined && st.uid !== uid) {
    throw new Error(`mandu: refusing to launch: the session folder ${dir} is owned by uid ${st.uid}, not ${uid}; pick another --id.`);
  }
}
