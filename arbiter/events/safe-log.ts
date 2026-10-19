/**
 * safe-log — open a log Mandu appends to, never through a link on the way
 * (runtime-instances.md §2, "planted paths").
 *
 * Mandu's logs live in the runtime base (`<base>/dashboard.log`,
 * `<base>/logs/`, a scope dir), which the agent may write, and the process
 * that opens them runs outside any confinement. Until 2026-10-17 only the
 * LAST component was checked (O_NOFOLLOW on the file): a `logs/` swapped for
 * a link to a folder got a new log created there, and the recursive mkdir
 * before the open made a dangling link's target folder. Here every
 * component is:
 *
 *   - the walk starts at `/` and opens each directory relative to the one
 *     before (`/proc/self/fd/<fd>/<name>` on Linux: the openat(2) form Node
 *     has no call for, so a component swapped for a link after its check
 *     changes nothing), O_DIRECTORY|O_NOFOLLOW, and the descriptor must be
 *     the directory the lstat saw (device + inode);
 *   - a link on the way is refused unless root owns it (the system's own,
 *     as macOS's `/tmp` → `/private/tmp`: one the agent could not have made;
 *     in a user namespace, the overflow uid an unmapped owner shows as);
 *   - each directory must be the system's (as above) or this user's, and no other account may
 *     write it unless it is sticky (`/tmp`): `dirProblem`. At and below
 *     `root` (the runtime base, when the caller knows it) a directory must
 *     be this user's, and one group or others could write is tightened on
 *     its descriptor (an older release's `mkdir -p` under umask 002);
 *   - a missing directory is made one at a time, mode 0700, in the
 *     directory opened before it (never `mkdir -p` by path);
 *   - the file is opened in the last directory's descriptor,
 *     O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_NONBLOCK (a link fails it, a
 *     FIFO with no reader fails it instead of hanging), and must be a
 *     regular file of this user's with one link (a FIFO, a device, a hard
 *     link to someone's file is refused); truncated only after the checks.
 *
 * Without /proc (macOS) the steps name paths, each checked by lstat just
 * before: a component swapped in between is the residual race there, where
 * the agent's Seatbelt profile write-denies the registries.
 *
 * Byte-identical copies: launcher/src/safe-log.ts,
 * dashboard/src/supervisor/safe-log.ts (the supervisor's service logs) and
 * arbiter/events/safe-log.ts (the event store's per-session files, appended
 * in the event dir's descriptor, `openSafeDir` + `openSafeLogIn`);
 * tests/stack/safe-log-parity.test.ts.
 *
 * Mandu-new (no reference origin).
 */
import { closeSync, constants, existsSync, fchmodSync, fstatSync, ftruncateSync, lstatSync, mkdirSync, openSync, readFileSync, type Stats } from "node:fs";
import { isAbsolute, join, normalize } from "node:path";

const PROC_FD = process.platform === "linux" && existsSync("/proc/self/fd");

/** The owners a directory or a link on the way may have besides this user:
 *  root, and the overflow uid a user namespace shows for an owner it does
 *  not map (the host's root under bubblewrap). Neither is the agent. */
const SYSTEM_UIDS: readonly number[] = [0, overflowUid()];

function overflowUid(): number {
  try {
    const n = Number.parseInt(readFileSync("/proc/sys/kernel/overflowuid", "utf8").trim(), 10);
    return Number.isInteger(n) && n > 0 ? n : 65534;
  } catch {
    return 65534;
  }
}

export interface SafeLogOptions {
  /** Empty the file after the checks (a fresh log per process). */
  truncate?: boolean;
  /** The runtime base the log lives under, when the caller knows it: it and
   *  every directory below it must be this user's (tightened when shared). */
  root?: string;
  /** The user (default this process's; null skips the owner checks). */
  uid?: number | null;
}

/** The facts of a directory the checks read. */
export interface DirFacts {
  uid: number;
  mode: number;
}

/** Why the directory `st` may not be on a log's way, or null. `own`: at or
 *  below the caller's root, where only this user's directories count. Pure. */
export function dirProblem(st: DirFacts, uid: number | null, own: boolean, system: readonly number[] = SYSTEM_UIDS): string | null {
  if (uid === null) return null;
  if (own) return st.uid === uid ? null : `is owned by uid ${st.uid}, not by you (uid ${uid})`;
  if (st.uid !== uid && !system.includes(st.uid)) return `is owned by uid ${st.uid}, not by you (uid ${uid}) or the system`;
  const sticky = (st.mode & 0o1000) !== 0;
  if ((st.mode & 0o002) !== 0 && !sticky) return `is writable by every account (mode ${(st.mode & 0o7777).toString(8)}) and not sticky`;
  return null;
}

/** The mode to tighten an own directory to, or null when it needs none:
 *  group and other write dropped. Pure. */
export function tightenedMode(mode: number): number | null {
  return (mode & 0o022) === 0 ? null : (mode & 0o7777) & ~0o022;
}

/** Is `dir` (absolute, normalized) `root` or below it? Pure. */
export function atOrBelow(dir: string, root: string | undefined): boolean {
  if (root === undefined) return false;
  const r = root.replace(/\/+$/, "") || "/";
  return dir === r || dir.startsWith(r === "/" ? "/" : `${r}/`);
}

function at(fd: number, path: string, name: string): string {
  return PROC_FD ? `/proc/self/fd/${fd}/${name}` : join(path, name);
}

function lstatOrNull(p: string): Stats | null {
  try { return lstatSync(p); } catch { return null; }
}

/** A directory opened with every component on its way checked: the
 *  descriptor the logs in it are opened in, and its path (messages, and the
 *  steps themselves without /proc). */
export interface SafeDir {
  fd: number;
  path: string;
}

/**
 * Open the directory `path` (absolute, normalized), every component on its
 * way checked and a missing one made (0700) as above. The caller closes it
 * (`closeSafeDir`). Throws a plain message naming what was refused.
 */
export function openSafeDir(path: string, opts: SafeLogOptions = {}): SafeDir {
  if (!isAbsolute(path) || normalize(path) !== path) throw new Error(`the log folder ${path} is not an absolute, normalized path`);
  const uid = opts.uid === undefined ? (process.getuid?.() ?? null) : opts.uid;
  const root = opts.root === undefined ? undefined : normalize(opts.root);
  let dirFd = openSync("/", constants.O_RDONLY | constants.O_DIRECTORY);
  let dirPath = "/";
  try {
    for (const part of path.split("/").filter(Boolean)) {
      const here = join(dirPath, part);
      const p = at(dirFd, dirPath, part);
      let st = lstatOrNull(p);
      if (st === null) {
        try { mkdirSync(p, 0o700); } catch (e) { if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e; }
        st = lstatSync(p);
      }
      let fd: number;
      if (st.isSymbolicLink()) {
        if (!SYSTEM_UIDS.includes(st.uid) || st.uid === uid || atOrBelow(here, root)) throw new Error(`${here} is a symbolic link on the way to the log folder ${path}; refusing to write through it (remove it)`);
        fd = openSync(p, constants.O_RDONLY | constants.O_DIRECTORY);
      } else {
        if (!st.isDirectory()) throw new Error(`${here} is not a directory, on the way to the log folder ${path}`);
        fd = openSync(p, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
        const now = fstatSync(fd);
        if (now.dev !== st.dev || now.ino !== st.ino) {
          closeSync(fd);
          throw new Error(`${here} changed while it was opened, on the way to the log folder ${path}`);
        }
      }
      try {
        const now = fstatSync(fd);
        const own = atOrBelow(here, root);
        const problem = dirProblem(now, uid, own);
        if (problem !== null) throw new Error(`${here} ${problem}; refusing to write logs there`);
        const tight = own ? tightenedMode(now.mode) : null;
        if (tight !== null) fchmodSync(fd, tight);
      } catch (e) {
        closeSync(fd);
        throw e;
      }
      closeSync(dirFd);
      dirFd = fd;
      dirPath = here;
    }
    return { fd: dirFd, path: dirPath };
  } catch (e) {
    closeSync(dirFd);
    throw e;
  }
}

export function closeSafeDir(d: SafeDir): void {
  try { closeSync(d.fd); } catch { /* already closed */ }
}

/**
 * Open the log `name` (one name) in the checked directory `d` for append
 * (mode `opts.mode`, default 0666 before the umask, when created): never a
 * link, a FIFO, a hard link to someone's file or another user's file.
 */
export function openSafeLogIn(d: SafeDir, name: string, opts: SafeLogOptions & { mode?: number } = {}): number {
  if (name === "" || name === "." || name === ".." || name.includes("/")) throw new Error(`not one name: ${JSON.stringify(name)}`);
  const uid = opts.uid === undefined ? (process.getuid?.() ?? null) : opts.uid;
  const path = join(d.path, name);
  let fd: number;
  try {
    fd = openSync(at(d.fd, d.path, name), constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, opts.mode ?? 0o666);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ELOOP" || code === "EMLINK") throw new Error(`the log ${path} is a symbolic link; refusing to write through it (remove it)`);
    if (code === "ENXIO") throw new Error(`the log ${path} is not a regular file (a FIFO); refusing to write to it (remove it)`);
    throw e;
  }
  const st = fstatSync(fd);
  const problem = !st.isFile() ? "not a file" : st.nlink > 1 ? `${st.nlink} links to it` : uid !== null && st.uid !== uid ? `owned by uid ${st.uid}` : null;
  if (problem !== null) {
    closeSync(fd);
    throw new Error(`the log ${path} is not a regular file of its own (${problem}); refusing to write to it (remove it)`);
  }
  if (opts.truncate) ftruncateSync(fd, 0);
  return fd;
}

/**
 * Open the log `path` for append (mode 0666 before the umask), every
 * component on its way checked (`openSafeDir`, then `openSafeLogIn`).
 * Returns the descriptor; throws a plain message naming what was refused.
 */
export function openSafeLog(path: string, opts: SafeLogOptions & { mode?: number } = {}): number {
  if (!isAbsolute(path) || normalize(path) !== path) throw new Error(`the log ${path} is not an absolute, normalized path`);
  const parts = path.split("/").filter(Boolean);
  const file = parts.pop();
  if (file === undefined) throw new Error(`the log ${path} names no file`);
  let d: SafeDir;
  try {
    d = openSafeDir(`/${parts.join("/")}`, opts);
  } catch (e) {
    throw new Error((e as Error).message.replace(/on the way to the log folder .*?;/, `on the way to the log ${path};`));
  }
  try {
    return openSafeLogIn(d, file, opts);
  } finally {
    closeSafeDir(d);
  }
}
