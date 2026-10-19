/**
 * store-links — Mandu's stores of originals stay inside Mandu's home
 * (confidentiality-plan-14 §11.2 residual (c); on-disk-layout.md §4).
 *
 * Every layer that keeps a confined agent out of Mandu's stores names the
 * HOME: the guard denies the home's real path, the wrap puts a tmpfs over
 * it, Seatbelt denies it by subpath. A store whose path inside the home
 * resolves OUTSIDE it is behind none of them. Anything that ran unconfined
 * (an `off` session, a `gated` launch with no wall, a program outside
 * Mandu) can make that so with one rename: swap `state/` for a symlink to a
 * directory of its own (a copy of the store, so nothing looks broken), or
 * hard-link `state/mandu.db` from a directory the agent can write. From then
 * on every original the arbiter stores lands where every later confined
 * agent reads (and writes) it.
 *
 * So the arbiter refuses to start, and the launcher refuses a protecting
 * launch, while a store directory resolves outside the home (a symlink
 * anywhere on its path within the home), is not a directory, or is not the
 * user's own; or the symbol DB (or a SQLite companion of it) is a symlink,
 * not a regular file, not the user's own, or has another hard link. The
 * home itself may be a symlink (a relocated home): the layers use its real
 * path. The config files (`policy.yaml`, `config.toml`, `secrets.json`,
 * `dashboard.env`) are not checked: a user may keep them in a dotfiles
 * repository, Mandu writes no original to them, and a relaxing edit of the
 * law is held (policy-surface.md §8.4.6).
 *
 * What it does not stop: a swap made while a launch runs (the next start
 * refuses) and a same-uid process outside Mandu (plan 14 §11.2 S3). Pure
 * but for the default filesystem seams. Mirrored in
 * launcher/src/store-links.ts (the standalone-package policy;
 * tests/stack/store-links-parity.test.ts keeps the two lists one).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { lstatSync, realpathSync, statSync } from "node:fs";
import { dirname } from "node:path";
import { manduPath, type ManduPathEnv, type ManduPathName } from "../src/generated/mandu-paths.js";

/** The directories that hold originals or what enforcement trusts. */
export const STORE_DIRS: readonly ManduPathName[] = ["state-root", "workspaces", "object-walks", "events", "events-test", "object-twins"];
/** The symbol DBs (each with its SQLite companions). */
export const STORE_FILES: readonly ManduPathName[] = ["symbol-db", "symbol-db-test"];
const COMPANIONS = ["", "-wal", "-shm", "-journal"] as const;

export interface StoreLinkFs {
  /** lstat, or null when the path does not exist. */
  lstat(p: string): { isSymbolicLink(): boolean; isDirectory(): boolean; isFile(): boolean; uid: number; nlink: number } | null;
  /** stat (following links), or null. */
  stat(p: string): { isDirectory(): boolean; uid: number } | null;
  /** realpath, or null when it cannot be resolved. */
  realpath(p: string): string | null;
  /** The user's uid, or null where there is none (no check of owners). */
  uid: number | null;
}

export const realStoreLinkFs: StoreLinkFs = {
  lstat: (p) => { try { return lstatSync(p); } catch { return null; } },
  stat: (p) => { try { return statSync(p); } catch { return null; } },
  realpath: (p) => { try { return realpathSync(p); } catch { return null; } },
  uid: typeof process.getuid === "function" ? process.getuid() : null,
};

const inside = (p: string, root: string): boolean => p === root || p.startsWith(root.endsWith("/") ? root : `${root}/`);

/**
 * The problems with Mandu's store layout under `home` (empty: none). A home
 * that does not exist yet has none (the arbiter and the launcher make it
 * owner-only).
 */
export function storeLinkProblems(env: ManduPathEnv, home: string, fs: StoreLinkFs = realStoreLinkFs): string[] {
  const homeDir = manduPath("mandu-home", env, home);
  const realHome = fs.realpath(homeDir);
  if (realHome === null) return [];
  const out: string[] = [];
  for (const name of STORE_DIRS) {
    const p = manduPath(name, env, home);
    if (fs.lstat(p) === null) continue;
    const real = fs.realpath(p);
    if (real === null) { out.push(`${p} cannot be resolved (a dangling symlink?)`); continue; }
    if (!inside(real, realHome)) { out.push(`${p} resolves to ${real}, outside Mandu's home ${realHome}`); continue; }
    const st = fs.stat(p);
    if (st === null || !st.isDirectory()) { out.push(`${p} is not a directory`); continue; }
    if (fs.uid !== null && st.uid !== fs.uid) out.push(`${p} is owned by uid ${st.uid}, not ${fs.uid}`);
  }
  for (const name of STORE_FILES) {
    const db = manduPath(name, env, home);
    for (const suffix of COMPANIONS) {
      const p = db + suffix;
      const st = fs.lstat(p);
      if (st === null) continue;
      if (st.isSymbolicLink()) { out.push(`${p} is a symlink`); continue; }
      if (!st.isFile()) { out.push(`${p} is not a regular file`); continue; }
      if (st.nlink > 1) out.push(`${p} has ${st.nlink} hard links (another name for it may lie outside Mandu's home)`);
      if (fs.uid !== null && st.uid !== fs.uid) out.push(`${p} is owned by uid ${st.uid}, not ${fs.uid}`);
      const dir = fs.realpath(dirname(p));
      if (dir !== null && !inside(dir, realHome)) out.push(`${p} lies in ${dir}, outside Mandu's home ${realHome}`);
    }
  }
  return out;
}

/** The refusal text for {@link storeLinkProblems}' answer. */
export function storeLinkRefusal(problems: readonly string[], who: string): string {
  return (
    `${who}: Mandu's stores must lie inside its home, where the layers that keep the agent out of them reach ` +
    `(on-disk-layout.md §4): ${problems.join("; ")}. Something that ran without confinement may have planted this. ` +
    "Move the store back into the home (or delete it: the state and caches are rebuilt, approvals and history are lost), then retry."
  );
}
