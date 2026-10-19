/**
 * twin-index-stat — a protected file git tracks looks CLEAN to git in the
 * agent's world (docs/design/confidentiality/confidentiality.md §7.2a "A
 * twinned file git tracks looks clean").
 *
 * Inside the agent's world a protected file is its twin (secret-twins.ts).
 * git there compares the work tree with the index by each entry's cached
 * stat (`ce_match_stat`: size, mtime, ctime, inode, owner): the twin is
 * another file, so the stat differs, git hashes what it reads, the twin's
 * bytes are not the committed blob, and the file is "modified". Every
 * command that needs a clean tree then refuses (`git filter-branch`, `git
 * rebase`, `git pull --rebase`, `git stash`, a `git checkout` that touches
 * the file), and `git commit -a` after any unrelated edit records the
 * placeholder (placeholder-commits.ts).
 *
 * The index's stat is a CACHE: git trusts it only to skip reading a file.
 * So the launcher writes, into the index entry of such a file, the stat of
 * its TWIN as the agent's git will see it (the blob id, mode, flags and
 * every other entry untouched). git in the agent's world then finds the
 * stat equal and does not read the file: clean. An edit of the twin changes
 * its mtime (and size), so git reads it again and the file shows modified,
 * as an edit of the real file would. No byte of any file reaches the index:
 * the real blob id was in it already; the cached size, the real file's
 * before, is now the twin's.
 *
 * Only where it is TRUE: the entry is the only one of its path (stage 0),
 * a plain file (100644, neither assume-unchanged nor skip-worktree), and
 * the real file's bytes hash to its blob (`git hash-object --no-filters`,
 * computed here, never by git). A file the user changed before the launch
 * keeps showing modified, as it is. The twin's mtime is set two seconds
 * back first, so the entry is never "racily clean" (an entry as new as the
 * index file is re-read whatever its stat says, and smudged on the next
 * index write). Not for a split index (the entries live in a shared file
 * named by its hash) nor an index extension git requires that this code
 * does not know; an index it cannot read, or a lock another git holds,
 * leaves the file showing modified, as before. Advisory: never refuses a
 * launch.
 *
 * THE TRADE-OFF: git keeps one stat per entry for both worlds. While the
 * session runs, git OUTSIDE it (the human's terminal, an editor) finds the
 * real file's size differ from the cached (twin's) size and, as git does
 * for a non-zero cached size, calls the file modified WITHOUT reading it:
 * ` M` with no content diff; its rebase and filter-branch refuse, and its
 * stash, `reset --hard`, `checkout -- .` or an editor's "Discard changes"
 * REWRITE the real file (same bytes, a new inode). Under the bind alone a
 * replaced file detaches the bind, so the caller patches only where the
 * guard serves the twins (its by-path open covers a replace;
 * secret-setup.ts). The patch lasts only as long as the session: at its end each
 * entry that still holds exactly the stat written here (same blob) gets its
 * launch stat back, and an entry git has changed since (a `git add`, the
 * agent's staging) is left as it is. The CRASH RECORD (`TwinIndexRecorder`,
 * in the Mandu home, written before the patched index lands) lets the next
 * launch, before its own patch, or `mandu reap` do the same for a session
 * whose launcher died. A second session on the same repository takes the
 * first's launch stat as its own (`inheritBefore`), so whichever ends last
 * puts the real one back.
 *
 * The write follows git's own lock protocol: `index.lock` created with
 * O_EXCL (a git holding it wins, nothing is written), the index re-read
 * under the lock, patched in place (fixed-width fields: no entry moves, so
 * the extensions' offsets stay right), its trailing checksum recomputed
 * (left all zero under `index.skipHash`), then renamed over `index`.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference
 * origin). The index layout is git's (Documentation/gitformat-index.txt).
 */
import { createHash } from "node:crypto";
import {
  closeSync, constants, fchmodSync, fstatSync, fsyncSync, lstatSync, openSync, readdirSync, readSync, renameSync, rmSync, unlinkSync, utimesSync, writeSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { defaultGitRunner, type GitRunner } from "./git-object-twins.js";
import {
  bootIdNow, ensureRecordDir, gitBlobId, processStartTicks, RECORD_NAME, recordDirSafe, recordOwnerLive,
  WATCH_GIT_TIMEOUT_MS, WATCH_MAX_PATHS, WATCH_MAX_REPOS, type WatchedRepo,
} from "./placeholder-commits.js";
import { dirProblem, publishFile } from "./safe-file.js";

/** The ten 32-bit stat words of an index entry, in their on-disk order. */
export interface IndexStat {
  ctimeSec: number; ctimeNsec: number;
  mtimeSec: number; mtimeNsec: number;
  dev: number; ino: number;
  mode: number;
  uid: number; gid: number;
  size: number;
}

/** The stat words occupy the first 40 bytes of every entry. */
export const STAT_BYTES = 40;
/** An index read here at most (a 3M-file repository's is about 300 MiB). */
export const INDEX_MAX_BYTES = 512 * 1024 * 1024;
/** A real file hashed here at most (a protected file larger is left as is). */
export const REAL_MAX_BYTES = 16 * 1024 * 1024;
/** How far back the twin's mtime is set (whole seconds: a git built with or
 *  without USE_NSEC finds the entry older than any index written after). */
export const TWIN_MTIME_BACK_S = 2;

const CE_VALID = 0x8000;
const CE_EXTENDED = 0x4000;
const CE_STAGEMASK = 0x3000;
const CE_NAMEMASK = 0x0fff;
const CE_SKIP_WORKTREE = 0x4000; // in the extended flags (v3+)

/** One entry of a parsed index. */
export interface IndexEntry {
  /** Byte offset of the entry (its stat words) in the file. */
  offset: number;
  path: string;
  oid: string;
  stage: number;
  mode: number;
  assumeValid: boolean;
  skipWorktree: boolean;
}

export interface ParsedIndex {
  version: number;
  hashBytes: number;
  entries: IndexEntry[];
  /** The 4-byte signatures of its extensions, in order. */
  extensions: string[];
  /** The trailing checksum is all zero (index.skipHash). */
  skipHash: boolean;
}

/** Why an index is not patched here (a thrown Error's message). */
export class IndexUnsupported extends Error {}

function u32(buf: Buffer, at: number): number {
  if (at + 4 > buf.length) throw new IndexUnsupported("truncated");
  return buf.readUInt32BE(at);
}

/**
 * Parse `buf` as a git index (versions 2, 3, 4) whose object names are
 * `hashBytes` long (20 SHA-1, 32 SHA-256). Verifies the trailing checksum
 * (unless it is all zero). Throws IndexUnsupported for anything it cannot
 * read exactly, a split index (`link`), or a required extension it does not
 * know (lowercase signature other than `sdir`). Pure.
 */
export function parseIndex(buf: Buffer, hashBytes: 20 | 32): ParsedIndex {
  if (buf.length < 12 + hashBytes) throw new IndexUnsupported("too short");
  if (buf.toString("latin1", 0, 4) !== "DIRC") throw new IndexUnsupported("not an index");
  const version = u32(buf, 4);
  if (version < 2 || version > 4) throw new IndexUnsupported(`index version ${version}`);
  const count = u32(buf, 8);
  const end = buf.length - hashBytes;
  const trailer = buf.subarray(end);
  const skipHash = trailer.every((b) => b === 0);
  if (!skipHash) {
    const sum = createHash(hashBytes === 20 ? "sha1" : "sha256").update(buf.subarray(0, end)).digest();
    if (!sum.equals(trailer)) throw new IndexUnsupported("checksum mismatch");
  }
  const entries: IndexEntry[] = [];
  let at = 12;
  let prev: Buffer = Buffer.alloc(0);
  for (let i = 0; i < count; i++) {
    const offset = at;
    const fixed = STAT_BYTES + hashBytes + 2;
    if (at + fixed > end) throw new IndexUnsupported("truncated entry");
    const mode = buf.readUInt32BE(at + 24);
    const oid = buf.toString("hex", at + STAT_BYTES, at + STAT_BYTES + hashBytes);
    const flags = buf.readUInt16BE(at + STAT_BYTES + hashBytes);
    at += fixed;
    let ext = 0;
    if ((flags & CE_EXTENDED) !== 0) {
      if (version < 3) throw new IndexUnsupported("extended flag in a version 2 index");
      if (at + 2 > end) throw new IndexUnsupported("truncated entry");
      ext = buf.readUInt16BE(at);
      at += 2;
    }
    let name: Buffer;
    if (version === 4) {
      // The prefix-compressed name: a varint (bytes to drop from the
      // previous name), then the NUL-terminated rest; no padding.
      let c = buf[at++];
      if (c === undefined) throw new IndexUnsupported("truncated entry");
      let strip = c & 127;
      while ((c & 128) !== 0) {
        strip += 1;
        c = buf[at++];
        if (c === undefined || strip > 0xffffff) throw new IndexUnsupported("bad name prefix");
        strip = strip * 128 + (c & 127);
      }
      if (strip > prev.length) throw new IndexUnsupported("bad name prefix");
      const nul = buf.indexOf(0, at);
      if (nul < 0 || nul >= end) throw new IndexUnsupported("truncated name");
      name = Buffer.concat([prev.subarray(0, prev.length - strip), buf.subarray(at, nul)]);
      at = nul + 1;
    } else {
      const nameStart = at;
      let nameLen = flags & CE_NAMEMASK;
      if (nameLen === CE_NAMEMASK) {
        const nul = buf.indexOf(0, nameStart);
        if (nul < 0 || nul >= end) throw new IndexUnsupported("truncated name");
        nameLen = nul - nameStart;
      }
      if (nameStart + nameLen >= end || buf[nameStart + nameLen] !== 0) throw new IndexUnsupported("bad name");
      name = buf.subarray(nameStart, nameStart + nameLen);
      // Entry length padded to a multiple of 8 with 1..8 NULs.
      const entryLen = (nameStart - offset + nameLen + 8) & ~7;
      at = offset + entryLen;
      if (at > end) throw new IndexUnsupported("truncated entry");
    }
    prev = name;
    entries.push({
      offset, path: name.toString("utf8"), oid, stage: (flags & CE_STAGEMASK) >> 12, mode,
      assumeValid: (flags & CE_VALID) !== 0, skipWorktree: (ext & CE_SKIP_WORKTREE) !== 0,
    });
  }
  const extensions: string[] = [];
  while (at < end) {
    if (at + 8 > end) throw new IndexUnsupported("truncated extension");
    const sig = buf.toString("latin1", at, at + 4);
    const size = buf.readUInt32BE(at + 4);
    if (at + 8 + size > end) throw new IndexUnsupported("truncated extension");
    if (sig === "link") throw new IndexUnsupported("split index");
    // git: an extension whose first byte is not A-Z is required ("we do not
    // understand"); of those only the sparse index is read here.
    const first = buf[at]!;
    if (!(first >= 0x41 && first <= 0x5a) && sig !== "sdir") throw new IndexUnsupported(`required extension ${JSON.stringify(sig)}`);
    extensions.push(sig);
    at += 8 + size;
  }
  return { version, hashBytes, entries, extensions, skipHash };
}

/** The stat words at `offset`. Pure. */
export function readStat(buf: Buffer, offset: number): IndexStat {
  const w = (i: number): number => buf.readUInt32BE(offset + 4 * i);
  return { ctimeSec: w(0), ctimeNsec: w(1), mtimeSec: w(2), mtimeNsec: w(3), dev: w(4), ino: w(5), mode: w(6), uid: w(7), gid: w(8), size: w(9) };
}

/** Write `st`'s words at `offset`, all but the mode (an entry's mode is
 *  git's, never a file's). Mutates `buf`. */
export function writeStat(buf: Buffer, offset: number, st: IndexStat): void {
  const words = [st.ctimeSec, st.ctimeNsec, st.mtimeSec, st.mtimeNsec, st.dev, st.ino, -1, st.uid, st.gid, st.size];
  words.forEach((v, i) => { if (i !== 6) buf.writeUInt32BE(v >>> 0, offset + 4 * i); });
}

/** Recompute the trailing checksum of a patched index (left zero when it
 *  was zero: index.skipHash). Mutates `buf`. */
export function resealIndex(buf: Buffer, parsed: Pick<ParsedIndex, "hashBytes" | "skipHash">): void {
  if (parsed.skipHash) return;
  const end = buf.length - parsed.hashBytes;
  createHash(parsed.hashBytes === 20 ? "sha1" : "sha256").update(buf.subarray(0, end)).digest().copy(buf, end);
}

/** A file's stat as git caches it: each field truncated to 32 bits, as
 *  git's `fill_stat_data` does. `st` from `lstatSync(p, { bigint: true })`. */
export function indexStatOf(st: { ctimeNs: bigint; mtimeNs: bigint; dev: bigint; ino: bigint; mode: bigint; uid: bigint; gid: bigint; size: bigint }): IndexStat {
  const lo = (v: bigint): number => Number(v & 0xffffffffn);
  const sec = (ns: bigint): number => lo(ns / 1_000_000_000n);
  const nsec = (ns: bigint): number => Number(ns % 1_000_000_000n);
  return {
    ctimeSec: sec(st.ctimeNs), ctimeNsec: nsec(st.ctimeNs), mtimeSec: sec(st.mtimeNs), mtimeNsec: nsec(st.mtimeNs),
    dev: lo(st.dev), ino: lo(st.ino), mode: lo(st.mode), uid: lo(st.uid), gid: lo(st.gid), size: lo(st.size),
  };
}

function sameStat(a: IndexStat, b: IndexStat): boolean {
  return a.ctimeSec === b.ctimeSec && a.ctimeNsec === b.ctimeNsec && a.mtimeSec === b.mtimeSec && a.mtimeNsec === b.mtimeNsec &&
    a.dev === b.dev && a.ino === b.ino && a.uid === b.uid && a.gid === b.gid && a.size === b.size;
}

/** One entry to patch: path (relative to the work tree), the blob it must
 *  still name, and the stat to write. */
export interface StatPatch { rel: string; oid: string; stat: IndexStat }

/** What a patch did to one entry: enough to put it back. */
export interface PatchedEntry { rel: string; oid: string; before: IndexStat; after: IndexStat }

/**
 * Patch `buf` in place: each patch's entry (stage 0, its path, the blob it
 * must name, mode 100644, neither assume-unchanged nor skip-worktree, and
 * the path's ONLY entry) gets the patch's stat; `onlyIf`, when given, must
 * equal the entry's current stat (the restore). Returns what changed and
 * reseals the checksum when anything did. Pure but for `buf`.
 */
export function patchIndexBuffer(
  buf: Buffer, hashBytes: 20 | 32, patches: readonly StatPatch[], onlyIf?: ReadonlyMap<string, IndexStat>, missing?: string[],
): PatchedEntry[] {
  const parsed = parseIndex(buf, hashBytes);
  const byPath = new Map<string, IndexEntry[]>();
  for (const e of parsed.entries) {
    const l = byPath.get(e.path) ?? [];
    l.push(e);
    byPath.set(e.path, l);
  }
  const done: PatchedEntry[] = [];
  for (const p of patches) {
    const es = byPath.get(p.rel);
    if (es === undefined) { missing?.push(p.rel); continue; }
    if (es.length !== 1) continue;
    const e = es[0]!;
    if (e.stage !== 0 || e.oid !== p.oid || e.mode !== 0o100644 || e.assumeValid || e.skipWorktree) continue;
    const before = readStat(buf, e.offset);
    const want = onlyIf?.get(p.rel);
    if (onlyIf !== undefined && (want === undefined || !sameStat(before, want))) continue;
    if (sameStat(before, p.stat)) continue;
    writeStat(buf, e.offset, p.stat);
    done.push({ rel: p.rel, oid: p.oid, before, after: readStat(buf, e.offset) });
  }
  if (done.length > 0) resealIndex(buf, parsed);
  return done;
}

function readWhole(fd: number, size: number): Buffer {
  const buf = Buffer.alloc(size);
  let off = 0;
  while (off < size) {
    const n = readSync(fd, buf, off, size - off, off);
    if (n === 0) throw new IndexUnsupported("index shrank while read");
    off += n;
  }
  return buf;
}

export interface IndexFs {
  uid?: number;
  /** Called under the lock with what is about to change, BEFORE the new
   *  index replaces the old one (the crash record is written here): its
   *  answer is what the call returns; null aborts, nothing written. */
  beforeCommit?: (done: PatchedEntry[]) => PatchedEntry[] | null;
  /** Filled with each patch's path the index no longer holds at all. */
  missing?: string[];
}

/**
 * Patch the index at `indexPath` under git's lock protocol. Returns what
 * changed ([] when nothing matched). Throws (with a message to log) when the
 * lock is held, the index or its directory is not a plain one of this user,
 * or the index cannot be read exactly. The patched bytes are parsed again
 * (same entries, a valid checksum) before they replace the index.
 */
export function patchIndexFile(
  indexPath: string, hashBytes: 20 | 32, patches: readonly StatPatch[], onlyIf?: ReadonlyMap<string, IndexStat>, fs: IndexFs = {},
): PatchedEntry[] {
  const dir = dirname(indexPath);
  const why = dirProblem(dir, fs.uid !== undefined ? { uid: fs.uid } : {});
  if (why !== null) throw new IndexUnsupported(why);
  const lock = `${indexPath}.lock`;
  let lockFd: number;
  try {
    lockFd = openSync(lock, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    throw new IndexUnsupported(code === "EEXIST" ? "another git holds the index lock" : `cannot lock the index (${code ?? "error"})`);
  }
  let renamed = false;
  try {
    const fd = openSync(indexPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    let buf: Buffer;
    let mode: number;
    try {
      const st = fstatSync(fd);
      const uid = fs.uid ?? process.getuid?.();
      if (!st.isFile()) throw new IndexUnsupported("the index is not a regular file");
      if (uid !== undefined && st.uid !== uid) throw new IndexUnsupported("the index is not yours");
      if (st.size > INDEX_MAX_BYTES) throw new IndexUnsupported("the index is too large");
      mode = st.mode & 0o777;
      buf = readWhole(fd, st.size);
    } finally {
      closeSync(fd);
    }
    const count = parseIndex(buf, hashBytes).entries.length;
    let done = patchIndexBuffer(buf, hashBytes, patches, onlyIf, fs.missing);
    if (done.length === 0) return [];
    // Never a wrong index: the patched bytes read back as an index of the
    // same entries (a field written out of place would fail here).
    if (parseIndex(buf, hashBytes).entries.length !== count) throw new IndexUnsupported("the patched index does not read back");
    if (fs.beforeCommit !== undefined) {
      const kept = fs.beforeCommit(done);
      if (kept === null) return [];
      done = kept;
    }
    let off = 0;
    while (off < buf.length) off += writeSync(lockFd, buf, off, buf.length - off);
    try { fsyncSync(lockFd); } catch { /* best effort, as git without core.fsync */ }
    // git creates the index 0666 & ~umask; keep what the user's was.
    try { fchmodSync(lockFd, mode); } catch { /* keep 0600 */ }
    closeSync(lockFd);
    lockFd = -1;
    renameSync(lock, indexPath);
    renamed = true;
    return done;
  } finally {
    if (lockFd >= 0) { try { closeSync(lockFd); } catch { /* closed */ } }
    if (!renamed) { try { unlinkSync(lock); } catch { /* gone */ } }
  }
}

// ── The launch side ─────────────────────────────────────────────────────────

/** One repository's patched entries, for the restore at the session's end. */
export interface CleanedIndex {
  root: string;
  indexPath: string;
  hashBytes: 20 | 32;
  entries: PatchedEntry[];
}

/**
 * The crash record: what one launch wrote into which index, written BEFORE
 * the patched index replaces the old one, in the Mandu home (where the agent
 * can neither read nor write), removed once the session's end has put every
 * entry back. A record whose launcher is gone (its pid, that process's start
 * time and the boot: placeholder-commits.ts `recordOwnerLive`) is restored
 * by the next launch before its own patch, and by `mandu reap`.
 */
export interface TwinIndexRecord {
  v: 1;
  pid: number;
  startTicks: string | null;
  bootId: string | null;
  scopeId: string;
  /** When it was written (ms). */
  at: number;
  indexes: CleanedIndex[];
}

/** The records' directory under the walk cache (the path table's
 *  `object-walks`). Pure. */
export function twinIndexRecordDir(walkCacheDir: string): string {
  return join(walkCacheDir, "twin-index");
}

/** A record at most (16 repositories of 256 paths fit many times over). */
export const TWIN_RECORD_MAX_BYTES = 4 * 1024 * 1024;
/** The names a recorder gives: `<ms>-<pid>-<scope>.json`. Only such a file
 *  in the folder is ever read or removed. */
export const TWIN_RECORD_NAME = RECORD_NAME;

const HEXOID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const STAT_KEYS: ReadonlyArray<keyof IndexStat> = ["ctimeSec", "ctimeNsec", "mtimeSec", "mtimeNsec", "dev", "ino", "mode", "uid", "gid", "size"];
const okU32 = (v: unknown): v is number => Number.isInteger(v) && (v as number) >= 0 && (v as number) <= 0xffffffff;
const okAbs = (p: unknown): p is string => typeof p === "string" && p.length > 1 && p.length <= 4096 && isAbsolute(p) && !p.includes("\0");
const okRel = (p: unknown): p is string =>
  typeof p === "string" && p.length > 0 && p.length <= 4096 && !isAbsolute(p) && !p.includes("\0") && !p.split("/").includes("..");

function parseStat(v: unknown): IndexStat | null {
  if (v === null || typeof v !== "object") return null;
  const o = v as Record<string, unknown>;
  const out: Partial<IndexStat> = {};
  for (const k of STAT_KEYS) {
    if (!okU32(o[k])) return null;
    out[k] = o[k] as number;
  }
  return out as IndexStat;
}

/** The record in `text`, or null when it is not one (an exact, bounded
 *  shape). Pure. */
export function parseTwinIndexRecord(text: string): TwinIndexRecord | null {
  if (text.length > TWIN_RECORD_MAX_BYTES) return null;
  let o: unknown;
  try { o = JSON.parse(text); } catch { return null; }
  const r = o as Partial<TwinIndexRecord> | null;
  if (r === null || typeof r !== "object" || r.v !== 1) return null;
  if (!Number.isInteger(r.pid) || (r.pid as number) <= 0 || typeof r.scopeId !== "string" || r.scopeId.length > 512 || !Number.isFinite(r.at)) return null;
  if (r.startTicks !== null && (typeof r.startTicks !== "string" || !/^\d+$/.test(r.startTicks))) return null;
  if (r.bootId !== null && (typeof r.bootId !== "string" || r.bootId.length > 128)) return null;
  if (!Array.isArray(r.indexes) || r.indexes.length > WATCH_MAX_REPOS) return null;
  const indexes: CleanedIndex[] = [];
  for (const x of r.indexes as unknown[]) {
    const c = x as Partial<CleanedIndex> | null;
    if (c === null || typeof c !== "object" || !okAbs(c.root) || !okAbs(c.indexPath) || (c.hashBytes !== 20 && c.hashBytes !== 32)) return null;
    if (!Array.isArray(c.entries) || c.entries.length === 0 || c.entries.length > WATCH_MAX_PATHS) return null;
    const entries: PatchedEntry[] = [];
    for (const y of c.entries as unknown[]) {
      const e = y as Partial<PatchedEntry> | null;
      if (e === null || typeof e !== "object" || !okRel(e.rel) || typeof e.oid !== "string" || !HEXOID.test(e.oid) || e.oid.length !== c.hashBytes * 2) return null;
      const before = parseStat(e.before);
      const after = parseStat(e.after);
      if (before === null || after === null) return null;
      entries.push({ rel: e.rel, oid: e.oid, before, after });
    }
    indexes.push({ root: c.root, indexPath: c.indexPath, hashBytes: c.hashBytes, entries });
  }
  return { v: 1, pid: r.pid as number, startTicks: r.startTicks ?? null, bootId: r.bootId ?? null, scopeId: r.scopeId, at: r.at as number, indexes };
}

/** What a file in the records' folder is (as placeholder-commits.ts reads
 *  its own): a record; `foreign` (JSON of another version: left alone);
 *  `bad` (dropped); `absent` (gone, or not a regular file). Never throws. */
type TwinRecordFile = { kind: "record"; rec: TwinIndexRecord } | { kind: "foreign" } | { kind: "bad" } | { kind: "absent" };

function readTwinRecordFile(file: string): TwinRecordFile {
  let fd: number;
  try { fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch { return { kind: "absent" }; }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { kind: "absent" };
    if (st.size > TWIN_RECORD_MAX_BYTES) return { kind: "foreign" };
    const text = readWhole(fd, st.size).toString("utf8");
    const rec = parseTwinIndexRecord(text);
    if (rec !== null) return { kind: "record", rec };
    let o: unknown;
    try { o = JSON.parse(text); } catch { return { kind: "bad" }; }
    return o !== null && typeof o === "object" && (o as { v?: unknown }).v !== 1 ? { kind: "foreign" } : { kind: "bad" };
  } catch {
    return { kind: "absent" };
  } finally {
    closeSync(fd);
  }
}

/** Remove a record: only a file named as one, in a folder that is a real
 *  directory inside the Mandu home (recordDirSafe). Never throws. */
export function removeTwinIndexRecord(file: string | null, home: string): void {
  if (file === null || !TWIN_RECORD_NAME.test(basename(file)) || !recordDirSafe(dirname(file), home)) return;
  try { rmSync(file, { force: true }); } catch { /* best effort */ }
}

/** The records in `dir` (a real directory inside the Mandu home), each with
 *  its file; `bad` ones are dropped on the way. Never throws. */
export function readTwinIndexRecords(dir: string, home: string): Array<{ file: string; rec: TwinIndexRecord }> {
  if (!recordDirSafe(dir, home)) return [];
  let names: string[];
  try { names = readdirSync(dir).filter((n) => TWIN_RECORD_NAME.test(n)); } catch { return []; }
  const out: Array<{ file: string; rec: TwinIndexRecord }> = [];
  for (const n of names) {
    const file = join(dir, n);
    const r = readTwinRecordFile(file);
    if (r.kind === "bad") removeTwinIndexRecord(file, home);
    else if (r.kind === "record") out.push({ file, rec: r.rec });
  }
  return out.sort((a, b) => a.rec.at - b.rec.at);
}

/**
 * One launch's record, kept on disk while the session runs. `save` writes
 * it whole (0600, temp-and-rename, the folder made one level at a time
 * inside the Mandu home: placeholder-commits.ts `ensureRecordDir`); a
 * record that cannot be written stops the patch it was to cover.
 */
export class TwinIndexRecorder {
  readonly rec: TwinIndexRecord;
  file: string | null = null;
  constructor(readonly dir: string, readonly home: string, scopeId: string, now = Date.now()) {
    this.rec = { v: 1, pid: process.pid, startTicks: processStartTicks(process.pid), bootId: bootIdNow(), scopeId, at: now, indexes: [] };
  }
  save(): boolean {
    const text = JSON.stringify(this.rec);
    if (text.length > TWIN_RECORD_MAX_BYTES) return false;
    const safeScope = this.rec.scopeId.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 64);
    const file = join(this.dir, `${this.rec.at}-${this.rec.pid}-${safeScope}.json`);
    try {
      if (!ensureRecordDir(this.dir, this.home)) return false;
      publishFile(file, text, { mode: 0o600 });
      this.file = file;
      // On disk before the patched index replaces the old one: a crash (a
      // power loss too) must not leave a patched index with no record.
      // A record that cannot be synced is not trusted to be there.
      for (const [p, flags] of [[file, constants.O_RDONLY | constants.O_NOFOLLOW], [this.dir, constants.O_RDONLY | constants.O_DIRECTORY]] as const) {
        const fd = openSync(p, flags);
        try { fsyncSync(fd); } finally { closeSync(fd); }
      }
      return true;
    } catch {
      return false;
    }
  }
  remove(): void {
    removeTwinIndexRecord(this.file, this.home);
    this.file = null;
  }
}

export interface CleanTwinsOpts {
  git?: GitRunner;
  log?: (m: string) => void;
  /** Now, in ms (tests). */
  now?: number;
  /** Each git call at most. */
  timeoutMs?: number;
  /** The real file's bytes (tests); default: read it, O_NOFOLLOW, capped. */
  readReal?: (path: string) => Buffer | null;
  uid?: number;
  /** The crash record (production: always). Without it nothing is recorded
   *  (unit tests of the patch itself). */
  recorder?: TwinIndexRecorder;
  /** The records of OTHER live sessions (a second session on the same
   *  repository): an entry that holds one's stat takes that one's launch
   *  stat as its own, so whichever session ends last puts the real one
   *  back. */
  peers?: () => readonly TwinIndexRecord[];
}

/** The real file's bytes, or null when it is not a plain file of at most
 *  REAL_MAX_BYTES (then it is left as is). */
export function readRealFile(path: string): Buffer | null {
  let fd: number;
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch { return null; }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > REAL_MAX_BYTES) return null;
    return readWhole(fd, st.size);
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

/** `e` with the launch stat of a peer session whose patch it holds. Pure. */
export function inheritBefore(e: PatchedEntry, indexPath: string, peers: readonly TwinIndexRecord[]): PatchedEntry {
  for (const r of peers) {
    for (const c of r.indexes) {
      if (c.indexPath !== indexPath) continue;
      const p = c.entries.find((x) => x.rel === e.rel && x.oid === e.oid && sameStat(x.after, e.before));
      if (p !== undefined) return { ...e, before: p.before };
    }
  }
  return e;
}

/**
 * For each watched repository (placeholder-commits.ts `preparePlaceholderWatch`
 * found its twinned files and their index blobs): each tracked twinned file
 * whose real bytes ARE its one index blob gets its twin's mtime set back
 * TWIN_MTIME_BACK_S seconds and its twin's stat written into its index
 * entry, the crash record saved first. Returns what was patched, per
 * repository, for `restoreTwinIndexes`. Never throws: a repository it
 * cannot do is logged and left as it was (its twinned files show modified,
 * as before).
 */
export async function cleanTwinsInIndex(repos: readonly WatchedRepo[], opts: CleanTwinsOpts = {}): Promise<CleanedIndex[]> {
  const git = opts.git ?? defaultGitRunner;
  const readReal = opts.readReal ?? readRealFile;
  const backSec = Math.floor((opts.now ?? Date.now()) / 1000) - TWIN_MTIME_BACK_S;
  const out: CleanedIndex[] = [];
  for (const repo of repos) {
    const patches: StatPatch[] = [];
    let hashBytes: 20 | 32 | null = null;
    for (const p of repo.paths) {
      const blobs = p.index ?? [];
      if (p.twin === undefined || blobs.length !== 1) continue;
      const oid = blobs[0]!;
      const hb = oid.length === 40 ? 20 : oid.length === 64 ? 32 : null;
      if (hb === null || (hashBytes !== null && hb !== hashBytes)) continue;
      const real = readReal(join(repo.root, p.rel));
      if (real === null || gitBlobId(real, hb === 20 ? "sha1" : "sha256") !== oid) continue;
      try {
        utimesSync(p.twin, backSec, backSec);
        const st = lstatSync(p.twin, { bigint: true });
        if (!st.isFile()) continue;
        patches.push({ rel: p.rel, oid, stat: indexStatOf(st) });
        hashBytes = hb;
      } catch {
        continue;
      }
    }
    if (patches.length === 0 || hashBytes === null) continue;
    const hb = hashBytes;
    try {
      const r = await git(["rev-parse", "--path-format=absolute", "--git-path", "index"], { cwd: repo.root, timeoutMs: opts.timeoutMs ?? WATCH_GIT_TIMEOUT_MS });
      const p = r.stdout.trim();
      if (r.code !== 0 || p === "" || p.includes("\n")) throw new Error(r.stderr.trim().split("\n").slice(-1)[0] || `exit ${r.code}`);
      const indexPath = isAbsolute(p) ? p : resolve(repo.root, p);
      let recordFailed = false;
      const entries = patchIndexFile(indexPath, hb, patches, undefined, {
        ...(opts.uid !== undefined ? { uid: opts.uid } : {}),
        beforeCommit: (done) => {
          const peers = opts.peers?.() ?? [];
          const kept = done.map((e) => inheritBefore(e, indexPath, peers));
          if (opts.recorder === undefined) return kept;
          opts.recorder.rec.indexes.push({ root: repo.root, indexPath, hashBytes: hb, entries: kept });
          if (opts.recorder.save()) return kept;
          opts.recorder.rec.indexes.pop();
          recordFailed = true;
          return null;
        },
      });
      if (recordFailed) throw new Error("its crash record could not be written in the Mandu home");
      if (entries.length > 0) out.push({ root: repo.root, indexPath, hashBytes: hb, entries });
    } catch (e) {
      opts.log?.(`mandu: ${repo.root}: git in this session sees the protected file${patches.length === 1 ? "" : "s"} it tracks as modified (the index was left as is: ${(e as Error).message})`);
    }
  }
  return out;
}

/** How long a restore waits for another git's index lock, at most. */
export const RESTORE_LOCK_WAIT_MS = 2_000;

function pause(ms: number): void {
  try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); } catch { /* no wait */ }
}

/**
 * Put the launch stat back into each entry that still holds exactly the
 * stat the launch wrote (same blob); an entry git has since changed (a
 * human's `git add`, the agent's staging, another session's patch) is left
 * as it is. Waits up to RESTORE_LOCK_WAIT_MS for a lock another git holds.
 * `complete` is false only when such a lock was held throughout (the one
 * TRANSIENT failure: the caller keeps the record for a later try). Every
 * other failure (an index that is gone, split since, symlinked, not the
 * user's, or does not read back) is final: said once, and the record goes,
 * since no later try would do better and the agent can cause most of them;
 * the user's `git add` of the file clears what is left. `untracked`: the
 * twinned paths the index no longer holds at all (the session untracked
 * them, e.g. a history rewrite). Never throws.
 */
export function restoreTwinIndexes(
  cleaned: readonly CleanedIndex[], opts: { log?: (m: string) => void; uid?: number; lockWaitMs?: number } = {},
): { back: string[]; complete: boolean; untracked: Array<{ root: string; rel: string }> } {
  const back: string[] = [];
  const untracked: Array<{ root: string; rel: string }> = [];
  let complete = true;
  for (const c of cleaned) {
    const onlyIf = new Map(c.entries.map((e) => [e.rel, e.after]));
    const patches = c.entries.map((e) => ({ rel: e.rel, oid: e.oid, stat: e.before }));
    const deadline = Date.now() + (opts.lockWaitMs ?? RESTORE_LOCK_WAIT_MS);
    // An index gone (the repository removed or moved) has nothing to put back.
    try { lstatSync(c.indexPath); } catch (e) { if ((e as NodeJS.ErrnoException).code === "ENOENT" || (e as NodeJS.ErrnoException).code === "ENOTDIR") continue; }
    for (;;) {
      const missing: string[] = [];
      try {
        for (const e of patchIndexFile(c.indexPath, c.hashBytes, patches, onlyIf, { ...(opts.uid !== undefined ? { uid: opts.uid } : {}), missing })) back.push(join(c.root, e.rel));
        for (const m of missing) untracked.push({ root: c.root, rel: m });
        break;
      } catch (e) {
        const locked = e instanceof IndexUnsupported && /holds the index lock/.test(e.message);
        if (locked && Date.now() < deadline) { pause(50); continue; }
        if ((e as NodeJS.ErrnoException).code === "ENOENT") break;
        if (locked) {
          complete = false;
          opts.log?.(`mandu: ${c.root}: another git held the index lock, so git outside the session may still show a protected file as modified; the next launch (or \`mandu reap\`) puts it back`);
        } else {
          opts.log?.(`mandu: ${c.root}: the index stat of a protected file was not put back (${(e as Error).message}); git there may show it modified until you \`git add\` it (that stores the same content)`);
        }
        break;
      }
    }
  }
  return { back, complete, untracked };
}

/** A crash record older than this is dropped after one more try, whatever
 *  that try found: a lock held for a month is not a git at work. */
export const TWIN_RECORD_MAX_AGE_MS = 30 * 24 * 3600 * 1000;

/**
 * The records in `dir` whose launcher is gone (a crash, a kill): each
 * restored now (restoreTwinIndexes) and removed once complete. Run by a
 * launch BEFORE its own patch (so its launch stat is never a dead session's
 * twin stat) and by `mandu reap`. Returns the work trees put back. Never
 * throws.
 */
export function restorePendingTwinIndexes(
  dir: string, home: string, opts: { live?: (rec: TwinIndexRecord) => boolean; log?: (m: string) => void; uid?: number; lockWaitMs?: number; now?: number } = {},
): string[] {
  const live = opts.live ?? ((r: TwinIndexRecord) => recordOwnerLive(r));
  const roots: string[] = [];
  for (const { file, rec } of readTwinIndexRecords(dir, home)) {
    if (live(rec)) continue;
    const r = restoreTwinIndexes(rec.indexes, opts);
    for (const p of r.back) {
      const root = rec.indexes.find((c) => p.startsWith(`${c.root}/`))?.root;
      if (root !== undefined && !roots.includes(root)) roots.push(root);
    }
    if (r.complete || (opts.now ?? Date.now()) - rec.at > TWIN_RECORD_MAX_AGE_MS) removeTwinIndexRecord(file, home);
  }
  return roots;
}

/** The records of OTHER sessions still running (peers for
 *  cleanTwinsInIndex). Never throws. */
export function livePeerRecords(dir: string, home: string, live: (rec: TwinIndexRecord) => boolean = (r) => recordOwnerLive(r)): TwinIndexRecord[] {
  return readTwinIndexRecords(dir, home).map((x) => x.rec).filter((r) => r.pid !== process.pid && live(r));
}

/**
 * The session's end: `cleaned` put back (restoreTwinIndexes), then its
 * crash record removed when that was complete (else it stays for the next
 * launch or `mandu reap`). Never throws.
 */
export function endTwinIndexSession(
  cleaned: readonly CleanedIndex[] | undefined, recorder: TwinIndexRecorder | undefined,
  opts: { log?: (m: string) => void; uid?: number; lockWaitMs?: number } = {},
): { back: string[]; complete: boolean; untracked: Array<{ root: string; rel: string }> } {
  const r = cleaned !== undefined ? restoreTwinIndexes(cleaned, opts) : { back: [], complete: true, untracked: [] };
  if (r.complete) recorder?.remove();
  return r;
}

/**
 * The exit notice for a protected file git tracked at launch and no longer
 * tracks (the session untracked it: `git rm --cached`, a history rewrite)
 * and that `.gitignore` does not name: a later `git add -A` or `git add .`
 * outside the session would commit the REAL file, key and all. One line per
 * file, asked of git (`check-ignore`, the hardened runner: it reads ignore
 * files, runs nothing a repository names); a path git cannot answer for is
 * said too. Never throws.
 */
export async function untrackedNotice(
  untracked: ReadonlyArray<{ root: string; rel: string }>, opts: { git?: GitRunner; timeoutMs?: number } = {},
): Promise<string[]> {
  const git = opts.git ?? defaultGitRunner;
  const out: string[] = [];
  for (const u of untracked.slice(0, 16)) {
    let ignored = false;
    try {
      const r = await git(["check-ignore", "-q", "--no-index", "--", u.rel], { cwd: u.root, timeoutMs: opts.timeoutMs ?? WATCH_GIT_TIMEOUT_MS });
      ignored = r.code === 0;
    } catch { /* unknown: said */ }
    if (ignored) continue;
    out.push(
      `mandu: ${join(u.root, u.rel)} is no longer tracked by git (the session untracked it) and .gitignore does not name it: ` +
      "a later `git add -A` or `git add .` would commit your real file. Add it to .gitignore if it should stay out of git.",
    );
  }
  return out;
}
