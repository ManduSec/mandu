/**
 * e2e-fs-root — the root the e2e suites keep their fsSync workspaces under,
 * `<tmpdir>/mandu-e2e-fs-<uid>/<batch>/<ws>/`, so the dashboard can read the
 * dual-view refs after the run (docker-e2e-rig.md §3).
 *
 * The dashboard's docker runner makes it on the host and hands it to the
 * container as MANDU_E2E_FS_ROOT (bind-mounted at the same path); a host run
 * computes the same name. Twin of the developer view's test-docker.ts
 * `resolveFsSyncDir` / `ensureFsSyncDir` (the packages install
 * independently).
 *
 * The root is in the shared TMPDIR, so it is per-uid and PRIVATE: created
 * 0700 when absent (non-recursively, so a dir someone else made first is
 * never adopted), otherwise a real directory of this uid with no group/other
 * bits, else the suite refuses to run. A fixed `/tmp/mandu-e2e-fs` (before
 * 2026-10-09) could be made first by another account, which could then read
 * the kept workspaces and plant a repository the dashboard reads.
 */
import { chmodSync, lstatSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const E2E_FS_ROOT_ENV = "MANDU_E2E_FS_ROOT";

/** The root's path: MANDU_E2E_FS_ROOT, else `<tmpdir>/mandu-e2e-fs-<uid>`. */
export function e2eFsRootPath(env: NodeJS.ProcessEnv = process.env): string {
  const uid = typeof process.getuid === "function" ? process.getuid() : 0;
  return env[E2E_FS_ROOT_ENV] || join(tmpdir(), `mandu-e2e-fs-${uid}`);
}

/** Why `dir` is not this uid's private directory, or null. */
export function e2eFsRootProblem(dir: string): string | null {
  let st;
  try { st = lstatSync(dir); } catch (e) { return `cannot be checked (${(e as Error).message})`; }
  const uid = typeof process.getuid === "function" ? process.getuid() : st.uid;
  if (st.isSymbolicLink()) return "is a symlink";
  if (!st.isDirectory()) return "is not a directory";
  if (st.uid !== uid) return `is owned by uid ${st.uid}, not by you (uid ${uid})`;
  if ((st.mode & 0o077) !== 0) return `is shared (mode ${(st.mode & 0o777).toString(8)})`;
  return null;
}

/** The root, created 0700 when absent; THROWS unless it is this uid's private dir. */
export function ensureE2eFsRoot(env: NodeJS.ProcessEnv = process.env): string {
  const dir = e2eFsRootPath(env);
  try {
    mkdirSync(dir, { mode: 0o700 });
    chmodSync(dir, 0o700);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
  }
  const problem = e2eFsRootProblem(dir);
  if (problem !== null) {
    throw new Error(`the e2e workspace root ${dir} ${problem}; the suite will not keep workspaces in a directory another user could control (remove it, or set ${E2E_FS_ROOT_ENV} to a private dir)`);
  }
  return dir;
}
