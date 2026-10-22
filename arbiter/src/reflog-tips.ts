/**
 * reflog-tips — the object names `git rev-list --reflog` starts from, read
 * straight from a files-backend repository's reflogs
 * (docs/design/confidentiality/confidentiality.md §7.2a "Cost on a relaunch").
 *
 * WHY: the history walk behind the git-object twins starts from every ref and
 * every reflog entry. `git rev-list --all --reflog --no-walk` answers that,
 * but git enumerates every reflog of the common directory once PER WORKTREE
 * (each worktree's ref store iterates its own logs and the shared ones): in a
 * repository with 163 worktrees and 1072 refs, 177k openat and 350k
 * read/fstat calls, 1.3 s bare and ~2.5 s in a launch, where `rev-list --all
 * --no-walk` alone takes 20 ms. Each reflog file is read here ONCE.
 *
 * WHAT git adds for `--reflog` (revision.c `add_reflogs_to_pending`): the old
 * and the new name of every entry (the all-zero name left out) of every
 * reflog of the current worktree's ref store and of every other worktree's.
 * In the files backend those are the files under `<common>/logs/` (the shared
 * refs and the main worktree's own: HEAD, refs/bisect, refs/worktree …) and
 * under `<common>/worktrees/<id>/logs/` (each linked worktree's own). This
 * module reads every regular file under both, so its answer is that set or a
 * SUPERSET of it (a log git would skip: an invalid ref name, a worktree git
 * no longer lists, a last line with no newline). git then keeps the names of
 * objects it has (`rev-list --no-walk --ignore-missing --stdin`, exactly as
 * `--reflog` skips a pruned entry with a warning) and peels each to its
 * commit, so the tips equal git's own answer.
 *
 * SECURITY: a tip left out could leave a protected version un-twinned (a
 * confidentiality regression), so the set must never shrink relative to
 * git's. Every doubt returns null and the caller asks git the slow way: a
 * reftable directory, any entry that is not a plain directory or a regular
 * file (a symlink, a FIFO, a device), a line that does not start with two
 * names of the repository's hash length, more bytes, files or depth than the
 * caps, any read error but an absent `logs` directory. The reads open each
 * file O_NOFOLLOW | O_NONBLOCK and check it is regular on the descriptor, so a
 * planted FIFO cannot stall the launch and a planted symlink cannot point the
 * read elsewhere; nothing read is ever run or passed to a program but as
 * object names on git's stdin (an unknown name is ignored there).
 *
 * USERS: the launcher's git-object twins (git-object-twins.ts
 * `reflogTipsOf`) and, in the arbiter, the background lock resolution and
 * the git-history secret scan (arbiter/policy/history-tips.ts), which hand
 * git the same names on its stdin in place of `--reflog`.
 *
 * ONE FILE, TWO COPIES: launcher/src and arbiter/src each ship this file
 * byte-identical (the packages ship standalone and do not import each
 * other); tests/stack/reflog-tips-parity.test.ts holds them equal.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readSync, type Dirent } from "node:fs";
import { join } from "node:path";

/** Caps past which the reader stops and the caller asks git (MiB of reflog
 *  text, files, directory depth). */
export const REFLOG_MAX_BYTES = 128 * 1024 * 1024;
export const REFLOG_MAX_FILES = 200_000;
export const REFLOG_MAX_DEPTH = 64;
/** The longest the reads hold the main thread at a time (Pacer). */
export const REFLOG_SLICE_MS = 4;

/**
 * The object names of one reflog's text: the old and the new name of every
 * entry, the all-zero name left out. `hexLen` is 40 (SHA-1) or 64 (SHA-256).
 * null when any line does not start `<name> <name> ` with names of that
 * length in lowercase hex (the caller falls back to git). A last line with no
 * newline counts (git skips it: a superset). Pure.
 */
export function parseReflog(text: string, hexLen: number): string[] | null {
  const out: string[] = [];
  if (text === "") return out;
  const lines = text.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  const zero = "0".repeat(hexLen);
  const hex = /^[0-9a-f]+$/;
  for (const line of lines) {
    if (line.length < 2 * hexLen + 2 || line[hexLen] !== " " || line[2 * hexLen + 1] !== " ") return null;
    const a = line.slice(0, hexLen);
    const b = line.slice(hexLen + 1, 2 * hexLen + 1);
    if (!hex.test(a) || !hex.test(b)) return null;
    if (a !== zero) out.push(a);
    if (b !== zero) out.push(b);
  }
  return out;
}

/** Why the reader gave up (a test and log aid), or the names it read. */
export type ReflogRead = { oids: string[] } | { fallback: string };

/**
 * Hands the event loop back between slices of synchronous work: `tick()`
 * after each file-system operation yields (setImmediate) once the slice
 * has run `sliceMs`. The reads stay synchronous system calls (each a few
 * microseconds; the promise API's thread-pool round trip made the same
 * reads five times slower), but none holds the main thread longer than a
 * slice. `yields` counts the hand-backs (a test aid).
 */
export class Pacer {
  yields = 0;
  private ops = 0;
  private since = performance.now();
  constructor(private readonly sliceMs: number = REFLOG_SLICE_MS) {}
  tick(): Promise<void> | null {
    // The clock read once every 16 operations.
    if ((++this.ops & 15) !== 0 || performance.now() - this.since < this.sliceMs) return null;
    this.yields++;
    return new Promise<void>((go) => setImmediate(() => { this.since = performance.now(); go(); }));
  }
}

interface Walk { hexLen: number; bytes: number; files: number; into: Set<string>; pace: Pacer }

function isMissing(e: unknown): boolean {
  return (e as NodeJS.ErrnoException)?.code === "ENOENT";
}

/** The kind of a directory entry, by its dirent type or, where the
 *  filesystem gives none, by lstat (never following a link). */
function kindOf(dir: string, d: Dirent): "dir" | "file" | "other" {
  if (d.isDirectory()) return "dir";
  if (d.isFile()) return "file";
  if (d.isSymbolicLink() || d.isFIFO() || d.isSocket() || d.isBlockDevice() || d.isCharacterDevice()) return "other";
  const s = lstatSync(join(dir, d.name));
  return s.isDirectory() ? "dir" : s.isFile() ? "file" : "other";
}

/** Read one reflog file without following a link or blocking on a FIFO:
 *  checked regular on the descriptor, then its bytes up to the size fstat
 *  gave (as readFileSync reads a regular file, without its second fstat). */
function readLog(path: string, w: Walk): string {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error(`${path} is not a regular file`);
    w.bytes += st.size;
    w.files++;
    if (w.bytes > REFLOG_MAX_BYTES) throw new Error(`the reflogs exceed ${REFLOG_MAX_BYTES} bytes`);
    if (w.files > REFLOG_MAX_FILES) throw new Error(`more than ${REFLOG_MAX_FILES} reflogs`);
    const buf = Buffer.allocUnsafe(st.size);
    let got = 0;
    while (got < buf.length) {
      const n = readSync(fd, buf, got, buf.length - got, got);
      if (n === 0) break;
      got += n;
    }
    return buf.toString("latin1", 0, got);
  } finally {
    closeSync(fd);
  }
}

/** Every reflog under `dir` (recursively), parsed into `w.into`. Throws on
 *  any doubt (the caller falls back). */
async function readTree(dir: string, depth: number, w: Walk): Promise<void> {
  if (depth > REFLOG_MAX_DEPTH) throw new Error(`the reflogs nest deeper than ${REFLOG_MAX_DEPTH}`);
  for (const d of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, d.name);
    const k = kindOf(dir, d);
    if (k === "dir") await readTree(p, depth + 1, w);
    else if (k === "file") {
      const oids = parseReflog(readLog(p, w), w.hexLen);
      if (oids === null) throw new Error(`${p}: a line that is not a reflog entry`);
      for (const o of oids) w.into.add(o);
    } else throw new Error(`${p} is not a plain directory or file`);
    const y = w.pace.tick();
    if (y !== null) await y;
  }
}

/** `p` is a plain directory (not a link): true; absent: false; anything
 *  else throws (a doubt). */
function plainDir(p: string): boolean {
  let s;
  try { s = lstatSync(p); } catch (e) { if (isMissing(e)) return false; throw e; }
  if (!s.isDirectory()) throw new Error(`${p} is not a plain directory`);
  return true;
}

/**
 * The object names in every reflog of the files-backend repository whose
 * common git directory is `commonDir` (absolute): `<common>/logs/**` and
 * `<common>/worktrees/<id>/logs/**`, sorted and unique. `{fallback}` (why)
 * on any doubt: the caller asks git (`rev-list --all --reflog`) instead.
 * The caller has already ruled out a reftable repository by its config;
 * a `reftable` directory is ruled out here too.
 *
 * PACED (2026-10-21): in a store with many worktrees and branches
 * (thousands of logs) the reads held the main thread 30-80 ms in one go;
 * now they hand it back every REFLOG_SLICE_MS (Pacer), so the launch's
 * other work (the services' start, the git calls' answers) runs between
 * slices. What is read, in what order, the doubts and the caps are
 * unchanged. `pace`: a test knob.
 */
export async function readReflogOids(commonDir: string, hexLen: number, pace: Pacer = new Pacer()): Promise<ReflogRead> {
  try {
    if (hexLen !== 40 && hexLen !== 64) return { fallback: `an object name length of ${hexLen}` };
    if (!plainDir(commonDir)) return { fallback: `${commonDir} is not a directory` };
    try { lstatSync(join(commonDir, "reftable")); return { fallback: "a reftable directory" }; } catch (e) { if (!isMissing(e)) throw e; }
    const w: Walk = { hexLen, bytes: 0, files: 0, into: new Set(), pace };
    const logs = join(commonDir, "logs");
    if (plainDir(logs)) await readTree(logs, 0, w);
    const wts = join(commonDir, "worktrees");
    if (plainDir(wts)) {
      for (const d of readdirSync(wts, { withFileTypes: true })) {
        const k = kindOf(wts, d);
        // git lists a worktree by `worktrees/<id>/gitdir`; a file or a link
        // here is a doubt, never skipped.
        if (k !== "dir") throw new Error(`${join(wts, d.name)} is not a plain directory`);
        const wl = join(wts, d.name, "logs");
        if (plainDir(wl)) await readTree(wl, 0, w);
        const y = pace.tick();
        if (y !== null) await y;
      }
    }
    return { oids: [...w.into].sort() };
  } catch (e) {
    return { fallback: (e as Error).message };
  }
}
