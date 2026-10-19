/**
 * launch-cwd — the directory a launch is FOR (packaging.md §1, "The launch directory").
 *
 * The launch's project folder is the process's real working directory, the
 * kernel's view (`process.cwd()`). `$PWD` is only the shell's spelling of it:
 * a program that `chdir`s without exporting PWD (`subprocess.run(cwd=…)` in
 * Python keeps the parent's PWD, `env -i`, a non-shell parent) hands the
 * launcher a PWD that names ANOTHER directory, and a launch that believed it
 * would confine, twin, scan and run the agent for the wrong folder.
 *
 * `$PWD` is kept for one thing: the user's symlinked spelling of the SAME
 * directory (a shell's logical path, e.g. macOS `/tmp/x` for
 * `/private/tmp/x`, or a symlinked home), which is what the human typed and
 * what an agent keys its per-project state on. It is accepted only when it is
 * an absolute, already-normal path that names the same file (same device and
 * inode) as the real cwd; anything else is ignored, silently (a script's
 * stale PWD is not the user's mistake to be told about).
 */
import { statSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

export interface LaunchCwdDeps {
  /** The real working directory (`process.cwd()`); may throw when it was removed. */
  cwd(): string;
  /** The identity of a directory, or null when it cannot be stat'ed. */
  stat(p: string): { dev: number; ino: number } | null;
}

export const REAL_LAUNCH_CWD_DEPS: LaunchCwdDeps = {
  cwd: () => process.cwd(),
  stat: (p) => {
    try {
      const s = statSync(p);
      return s.isDirectory() ? { dev: s.dev, ino: s.ino } : null;
    } catch { return null; }
  },
};

/**
 * The launch directory: `pwd` when it is an absolute, normal spelling of the
 * real cwd, else the real cwd. Throws a plain message when the real cwd no
 * longer exists (there is no folder to launch for).
 */
export function resolveLaunchCwd(pwd: string | undefined, deps: LaunchCwdDeps = REAL_LAUNCH_CWD_DEPS): string {
  let real: string;
  try {
    real = deps.cwd();
  } catch (e) {
    throw new Error(
      `mandu: the current directory no longer exists (${(e as Error).message}); cd into the project folder and launch again`,
    );
  }
  if (pwd === undefined || pwd === "" || pwd === real) return real;
  // Only a canonical spelling: absolute, no `.`/`..` segment, no trailing or
  // doubled slash (path.resolve leaves such a path unchanged).
  if (!isAbsolute(pwd) || resolve(pwd) !== pwd) return real;
  const a = deps.stat(pwd);
  const b = deps.stat(real);
  if (a === null || b === null) return real;
  return a.dev === b.dev && a.ino === b.ino ? pwd : real;
}
