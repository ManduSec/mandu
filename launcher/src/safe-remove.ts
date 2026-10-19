/**
 * safe-remove — walk and delete in a directory someone else may write,
 * never through a link (runtime-instances.md §2 "planted paths", §10).
 *
 * `mandu reap` runs outside the agent's confinement and deletes in the
 * runtime base, whose names are predictable and which the agent may write.
 * A path-based walk (`readdirSync(<base>/instances)`, `rmSync(<dir>)`) goes
 * wherever a link planted on the way leads: through a linked `instances/`
 * every old subdirectory of the target reads as an abandoned instance and is
 * removed. Here:
 *
 *   - a directory is opened O_DIRECTORY|O_NOFOLLOW after an lstat, and the
 *     descriptor must be the same directory the lstat saw (device + inode)
 *     and, where asked, this user's; a link at the name fails the open;
 *   - every later step names its target RELATIVE to that descriptor
 *     (`/proc/self/fd/<fd>/<name>` on Linux: the kernel resolves the
 *     descriptor's directory itself, not its path, so a component swapped
 *     for a link after the check changes nothing; this is the openat(2)
 *     form Node has no call for);
 *   - a tree is removed bottom-up the same way: a link inside is unlinked
 *     (never followed), a directory is opened as above before its entries
 *     are, and rmdir(2) / unlink(2) never follow the last component;
 *   - the directory a removal starts from must be reached through no link
 *     but the system's own (an ancestor link that root owns, as macOS's
 *     `/tmp` → `/private/tmp`): a link this user (so the agent) could have
 *     made refuses it.
 *
 * Without /proc (macOS) the steps name paths, each checked by lstat just
 * before: a link swapped in between the check and the call is the residual
 * race there, where the agent's Seatbelt profile write-denies the registries
 * (`runtime-registry.ts`), so the agent cannot plant one.
 *
 * Mandu-new (no reference origin).
 */
import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readdirSync, readSync, rmdirSync, unlinkSync, type Stats } from "node:fs";
import { dirname, isAbsolute, join, normalize, basename } from "node:path";

const PROC_FD = process.platform === "linux" && existsSync("/proc/self/fd");

/** An open directory: the descriptor every step is relative to. */
export interface DirHandle {
  fd: number;
  /** Its path, for messages (and the steps themselves without /proc). */
  path: string;
}

export type EntryKind = "dir" | "file" | "link" | "socket" | "any";

/** The name `name` in `h`, as the kernel should resolve it. */
function at(h: DirHandle, name: string): string {
  if (name === "" || name === "." || name === ".." || name.includes("/")) throw new Error(`not one name: ${JSON.stringify(name)}`);
  return PROC_FD ? `/proc/self/fd/${h.fd}/${name}` : join(h.path, name);
}

/** The path that names `name` in the open directory `h` the way every step
 *  here does (resolved through the descriptor on Linux), for a caller that
 *  opens or lstats it itself, with O_NOFOLLOW (twin-writes.ts, which hashes
 *  a stale scope dir's twins for `mandu reap`). Throws unless `name` is one
 *  name. */
export function entryPathIn(h: DirHandle, name: string): string {
  return at(h, name);
}

function myUid(): number | null {
  return process.getuid?.() ?? null;
}

/** Is there a link on the way to `path` (its ancestors, not `path` itself)
 *  that someone other than root owns? Returns that ancestor, or null. */
export function userLinkOnTheWay(path: string): string | null {
  let p = "/";
  const parts = path.split("/").filter(Boolean);
  for (const part of parts.slice(0, -1)) {
    p = join(p, part);
    let st: Stats;
    try { st = lstatSync(p); } catch { return null; } // missing: the open below fails
    if (st.isSymbolicLink() && st.uid !== 0) return p;
  }
  return null;
}

function openDirFd(path: string): number {
  return openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
}

/**
 * Open the directory `path`: absolute and normalized, no link of this user's
 * on the way, not a link itself, and (with `uid`, default this process's;
 * null skips) owned by that user. Throws with the reason otherwise.
 */
export function openDir(path: string, opts: { uid?: number | null } = {}): DirHandle {
  if (!isAbsolute(path) || normalize(path) !== path) throw new Error(`${path} is not an absolute, normalized path`);
  const link = userLinkOnTheWay(path);
  if (link !== null) throw new Error(`${link} is a symbolic link on the way to ${path}`);
  const st = lstatSync(path);
  if (st.isSymbolicLink()) throw new Error(`${path} is a symbolic link, not a real directory`);
  if (!st.isDirectory()) throw new Error(`${path} is not a directory`);
  const fd = openDirFd(path);
  try {
    checkSame(fd, st, path, opts.uid === undefined ? myUid() : opts.uid);
  } catch (e) {
    closeSync(fd);
    throw e;
  }
  return { fd, path };
}

function checkSame(fd: number, seen: Stats, path: string, uid: number | null): void {
  const now = fstatSync(fd);
  if (!now.isDirectory() || now.dev !== seen.dev || now.ino !== seen.ino) throw new Error(`${path} changed while it was opened`);
  if (uid !== null && now.uid !== uid) throw new Error(`${path} is not yours (owner uid ${now.uid})`);
}

/** Open the directory `name` in `h` (a real directory, not a link; with
 *  `uid`, default this process's, owned by that user). */
export function openDirIn(h: DirHandle, name: string, opts: { uid?: number | null } = {}): DirHandle {
  const p = at(h, name);
  const st = lstatSync(p);
  if (st.isSymbolicLink()) throw new Error(`${join(h.path, name)} is a symbolic link, not a real directory`);
  if (!st.isDirectory()) throw new Error(`${join(h.path, name)} is not a directory`);
  const fd = openDirFd(p);
  try {
    checkSame(fd, st, join(h.path, name), opts.uid === undefined ? myUid() : opts.uid);
  } catch (e) {
    closeSync(fd);
    throw e;
  }
  return { fd, path: join(h.path, name) };
}

export function closeDir(h: DirHandle): void {
  try { closeSync(h.fd); } catch { /* already closed */ }
}

/** The names in `h`. */
export function listDir(h: DirHandle): string[] {
  return readdirSync(PROC_FD ? `/proc/self/fd/${h.fd}` : h.path);
}

/** lstat of `name` in `h`; null when it is gone. */
export function lstatIn(h: DirHandle, name: string): Stats | null {
  try { return lstatSync(at(h, name)); } catch { return null; }
}

/** The text of the regular file `name` of `h` (opened O_NOFOLLOW|O_NONBLOCK:
 *  a link or a FIFO planted there is never read), or null: missing, not a
 *  regular file, over `max` bytes, or unreadable. */
export function readTextIn(h: DirHandle, name: string, max = 1 << 20): string | null {
  let fd: number;
  try { fd = openSync(at(h, name), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch { return null; }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > max) return null;
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < buf.length) {
      const n = readSync(fd, buf, off, buf.length - off, off);
      if (n === 0) break;
      off += n;
    }
    return buf.subarray(0, off).toString("utf8");
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

/** The JSON in the regular file `name` of `h` (`readTextIn`), or null:
 *  missing, not a regular file, over `max` bytes, or not JSON. */
export function readJsonIn(h: DirHandle, name: string, max = 1 << 20): unknown {
  const text = readTextIn(h, name, max);
  if (text === null) return null;
  try { return JSON.parse(text); } catch { return null; }
}

function kindOf(st: Stats): Exclude<EntryKind, "any"> | "other" {
  if (st.isSymbolicLink()) return "link";
  if (st.isDirectory()) return "dir";
  if (st.isFile()) return "file";
  if (st.isSocket()) return "socket";
  return "other";
}

/**
 * Remove the entry `name` of `h`: the entry must be of `kind` ("any": a
 * directory, file, link or socket) and, with `uid` (default this process's;
 * null skips), owned by that user. A directory goes with everything below
 * it, never through a link; a link is removed itself. Throws with the
 * reason when it refuses or a step fails.
 */
export function removeIn(h: DirHandle, name: string, opts: { kind: EntryKind | readonly EntryKind[]; uid?: number | null }): void {
  const p = at(h, name);
  const st = lstatSync(p);
  const shown = join(h.path, name);
  const uid = opts.uid === undefined ? myUid() : opts.uid;
  if (uid !== null && st.uid !== uid) throw new Error(`${shown} is not yours (owner uid ${st.uid})`);
  const k = kindOf(st);
  const kinds: readonly EntryKind[] = typeof opts.kind === "string" ? [opts.kind] : opts.kind;
  if (!kinds.includes("any") && !kinds.includes(k as EntryKind)) {
    throw new Error(`${shown} is a ${k === "link" ? "symbolic link" : k}, not a ${kinds.map((x) => (x === "dir" ? "directory" : x)).join(" or ")}`);
  }
  if (k === "dir") removeTree(h, name, st, 0);
  else unlinkSync(p);
}

function removeTree(h: DirHandle, name: string, seen: Stats, depth: number): void {
  if (depth > 256) throw new Error(`${join(h.path, name)}: too deep`);
  const fd = openDirFd(at(h, name));
  const child: DirHandle = { fd, path: join(h.path, name) };
  try {
    checkSame(fd, seen, child.path, null);
    for (const n of listDir(child)) {
      const st = lstatSync(at(child, n));
      if (st.isDirectory()) removeTree(child, n, st, depth + 1);
      else unlinkSync(at(child, n));
    }
  } finally {
    closeDir(child);
  }
  rmdirSync(at(h, name));
}

/** Remove `path` (see `removeIn`) from its directory, opened with `openDir`
 *  and no owner requirement on it (`/tmp` is root's). */
export function removePath(path: string, opts: { kind: EntryKind | readonly EntryKind[]; uid?: number | null }): void {
  if (!isAbsolute(path) || normalize(path) !== path || path === "/") throw new Error(`${path} is not an absolute, normalized path`);
  const parent = openDir(dirname(path), { uid: null });
  try {
    removeIn(parent, basename(path), opts);
  } finally {
    closeDir(parent);
  }
}
