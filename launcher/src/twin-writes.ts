/**
 * twin-writes — say which registered secret files the agent changed, when
 * the session ends (confidentiality-plan-10-flow-taint.md §4.1, "A write
 * lands in the twin"; guarantees.md §3).
 *
 * A write that a program in the agent's tree makes to a registered secret
 * file lands in the session's placeholder copy (the twin, secret-twins.ts):
 * the mount layer binds the twin writable over the real path, and the guard
 * hands a write-intent open the twin by its own path. The program sees
 * success, the real file never changes, and the twin goes with the scope dir
 * at the session's end. Writing through instead would put placeholders over
 * the user's real credential (write-protection.md §2), so the write path
 * stays; what this module removes is the silence.
 *
 * At launch (`watchTwins`), right after the twins are written:
 *   - each twin's SHA-256, size, device and inode (`TwinSnapshot`), also
 *     written beside the twins (`TWIN_SNAPSHOT_FILE`, mode 0600) so that
 *     `mandu reap` can still name the changes of a session whose launcher
 *     died before it could (a signal it does not catch, a crash);
 *   - each REAL file's identity (device, inode, size, mtime and ctime in
 *     nanoseconds) and, up to `REAL_HASH_MAX` bytes, its SHA-256
 *     (`RealFileMark`), kept in the launcher's memory only, never written
 *     down: a hash or a size of the real bytes on disk would be a guessing
 *     oracle for a short secret (the runtime base is a directory the agent
 *     can read), while the twin's are of text the agent reads anyway.
 *
 * After the agent exits (`discardedWrites`), every registered file whose
 * twin changed, was removed, was replaced or cannot be read, each with what
 * became of the real file: unchanged (the same size and bytes; for a file
 * too big to have been hashed, the same identity), changed (an allow-listed reader the guard handed the real file
 * wrote it, a hard link made before the launch reached it under the bind, or
 * the user edited it meanwhile), or unknown (it could not be read). The
 * notice (`discardedWriteNotice`) words each line by that, so "the real file
 * is unchanged" is said only when it was checked. A size is compared before
 * any hash: a twin a program grew by gigabytes is judged by one lstat, and
 * nothing is read in full unless the sizes match.
 *
 * Only paths are ever printed or recorded: the twin's bytes are hashed,
 * never shown, and they may hold a fresh credential a program wrote there
 * (a token refresh, `npm login`). A path is printed with its control and
 * format characters (C0, DEL, C1, Unicode Cf such as the bidi overrides,
 * line and paragraph separators) as `?`, so a file name cannot forge a
 * terminal line, send an escape sequence or reorder the line on screen.
 *
 * A labelled file the launch did not register (confidentiality.md §6,
 * "Read by a program the launch did not see") has no twin from the launch:
 * the network guard makes one when a program other than the agent opens it,
 * in `derived-twins/` beside the launch's twins, and a write through that
 * open lands in it as a registered file's write lands in its twin. The
 * guard records each such twin as it makes it (`LABELLED_TWIN_RECORDS`, one
 * JSON line each: the twin's size, hash and identity, and the REAL file's
 * identity only, never its size or a hash of its bytes), so the session's
 * end names those files too, in the same notice (`labelledDiscardedWrites`),
 * and `mandu reap` names them for a launcher that died. Without the real
 * file's bytes, what became of it is judged by its identity (device, inode,
 * mtime and ctime), as a registered file too big to hash is.
 *
 * The snapshot file is advisory: a program in the agent's tree that can
 * write the runtime base could alter it, which changes only what `mandu
 * reap` says, never what reaches a model, and reap reads it through the
 * open scope dir, never through a link (safe-remove.ts).
 *
 * Mandu-new (no reference origin).
 */
import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, unlinkSync } from "node:fs";
import { basename, join } from "node:path";
import { publishFile } from "./safe-file.js";
import { closeDir, entryPathIn, openDir, openDirIn, readJsonIn, readTextIn, type DirHandle } from "./safe-remove.js";

/** Where the launch writes its twins' snapshots, in the twin directory
 *  (`<scope dir>/secret-twins/`). No twin is named like it (theirs start
 *  with a three-digit index, secret-twins.ts `twinName`). */
export const TWIN_SNAPSHOT_FILE = "twin-snapshots.json";

/** One twin as the launch wrote it. Holds nothing of the real file. */
export interface TwinSnapshot {
  /** The registered file the twin stands for (the bind target), as printed. */
  targetPath: string;
  /** The twin file in the scope dir (secret-twins/NNN-name). */
  twinPath: string;
  /** SHA-256 of the twin's bytes, hex. */
  sha256: string;
  /** The twin's size in bytes. */
  size: number;
  /** The twin file's device and inode right after it was written; absent
   *  when it could not be read back (then size and hash are compared). */
  dev?: string;
  ino?: string;
}

/** Up to this size the launch hashes a real file (a registered `.env`, a
 *  key, a config: kilobytes); a bigger labelled document is judged by its
 *  identity alone, so no launch reads more than this of one file. */
export const REAL_HASH_MAX = 16 * 1024 * 1024;

/** A real file as the launch found it: launcher memory only. */
export interface RealFileMark {
  size: number;
  dev: string;
  ino: string;
  mtimeNs: string;
  ctimeNs: string;
  /** Absent over `REAL_HASH_MAX`. */
  sha256?: string;
}

/** What `TwinLook.stat` reports of a path (not followed). */
export interface LookStat {
  regular: boolean;
  size: number;
  dev: string;
  ino: string;
  mtimeNs: string;
  ctimeNs: string;
}

/** What became of the real file over the session. */
export type RealFileState = "unchanged" | "changed" | "unknown";

/** One registered file whose twin the session changed. */
export interface DiscardedWrite {
  path: string;
  real: RealFileState;
}

/** The launch's watch over its twins. */
export interface TwinWatch {
  /** The twins as written (the same list is in `file`). */
  twins: TwinSnapshot[];
  /** Each real file as found, by target path (null: it could not be read). */
  real: ReadonlyMap<string, RealFileMark | null>;
  /** The snapshot file for `mandu reap`; null when it could not be written. */
  file: string | null;
}

/** What this module asks of the filesystem. A test knob; the default reads
 *  the real one, never following a link at the last component. */
export interface TwinLook {
  /** The path itself (not followed): null when it does not exist; throws
   *  when it cannot be looked at. */
  stat: (path: string) => LookStat | null;
  /** SHA-256 of the regular file at `path` (a link there is not followed);
   *  throws when it cannot be read, is not a regular file, or changed size
   *  while it was read. */
  hash: (path: string) => string;
}

/** SHA-256 of the regular file at `path`, opened O_NOFOLLOW|O_NONBLOCK (a
 *  link or a FIFO planted at the name is never read through or waited on). */
function hashRegularFile(path: string): string {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd);
    if (!before.isFile()) throw new Error(`${path} is not a regular file`);
    const h = createHash("sha256");
    const buf = Buffer.allocUnsafe(1 << 20);
    let size = 0;
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n <= 0) break;
      h.update(buf.subarray(0, n));
      size += n;
    }
    if (size !== fstatSync(fd).size || size !== before.size) throw new Error(`${path} changed while it was read`);
    return h.digest("hex");
  } finally {
    closeSync(fd);
  }
}

export const realTwinLook: TwinLook = {
  stat: (p) => {
    try {
      const st = lstatSync(p, { bigint: true });
      return {
        regular: st.isFile(), size: Number(st.size), dev: String(st.dev), ino: String(st.ino),
        mtimeNs: String(st.mtimeNs), ctimeNs: String(st.ctimeNs),
      };
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw e;
    }
  },
  hash: hashRegularFile,
};

/** SHA-256 of a twin's text as `publishFile` writes it (UTF-8). Pure. */
export function twinContentHash(content: string): string {
  return createHash("sha256").update(Buffer.from(content, "utf8")).digest("hex");
}

/**
 * The snapshot of a twin the launch has just written: the file read back
 * (size, hash and identity), or, when it cannot be read, the size and hash
 * of the text it was given with no identity. Never throws.
 */
export function snapshotTwin(file: { twinPath: string; targetPath: string; content: string }, look: TwinLook = realTwinLook): TwinSnapshot {
  const base = { targetPath: file.targetPath, twinPath: file.twinPath };
  try {
    const st = look.stat(file.twinPath);
    if (st !== null && st.regular) return { ...base, sha256: look.hash(file.twinPath), size: st.size, dev: st.dev, ino: st.ino };
  } catch { /* the text's own below */ }
  return { ...base, sha256: twinContentHash(file.content), size: Buffer.byteLength(file.content, "utf8") };
}

/** The real file at `path` as it is now (its identity, and its hash up to
 *  `REAL_HASH_MAX`), or null when it is not a regular file or cannot be
 *  read. Never throws. */
export function markRealFile(path: string, look: TwinLook = realTwinLook): RealFileMark | null {
  try {
    const st = look.stat(path);
    if (st === null || !st.regular) return null;
    const id = { size: st.size, dev: st.dev, ino: st.ino, mtimeNs: st.mtimeNs, ctimeNs: st.ctimeNs };
    return st.size <= REAL_HASH_MAX ? { ...id, sha256: look.hash(path) } : id;
  } catch {
    return null;
  }
}

/** What became of the real file `mark` describes: gone, no longer a
 *  regular file or another size is a change, decided by one lstat; where
 *  the launch hashed it, the bytes decide, whatever its times say (a
 *  same-size write in the same clock tick as the launch's mark leaves
 *  mtime and ctime as they were, seen in the CI guest, so the times alone
 *  never clear it); a file too big to have been hashed is judged by its
 *  identity (device, inode, mtime and ctime), and its times moving counts
 *  as a change. One that cannot be read now, or could not at launch, is
 *  unknown. Never throws. */
export function realFileState(path: string, mark: RealFileMark | null | undefined, look: TwinLook = realTwinLook): RealFileState {
  if (mark === null || mark === undefined) return "unknown";
  try {
    const st = look.stat(path);
    if (st === null || !st.regular || st.size !== mark.size) return "changed";
    if (mark.sha256 !== undefined) return look.hash(path) === mark.sha256 ? "unchanged" : "changed";
    return st.dev === mark.dev && st.ino === mark.ino && st.mtimeNs === mark.mtimeNs && st.ctimeNs === mark.ctimeNs ? "unchanged" : "changed";
  } catch {
    return "unknown";
  }
}

/** Is this twin still the one the launch wrote? Size and identity by one
 *  lstat; the bytes only when those match. Errs loud: anything it cannot
 *  judge is a change. */
function twinUnchanged(s: TwinSnapshot, look: TwinLook): boolean {
  try {
    const st = look.stat(s.twinPath);
    if (st === null || !st.regular || st.size !== s.size) return false;
    if (s.dev !== undefined && s.ino !== undefined && (st.dev !== s.dev || st.ino !== s.ino)) return false;
    return look.hash(s.twinPath) === s.sha256;
  } catch {
    return false;
  }
}

function sorted(paths: Iterable<string>): string[] {
  return [...new Set(paths)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/**
 * The registered files whose twin is no longer the one the launch wrote:
 * its size or bytes differ, it is gone, it is no longer a regular file (a
 * symlink or a directory in its place), it is another file than the one
 * written (another inode: replaced), or it cannot be read. Each target
 * once, sorted.
 */
export function changedTwins(snaps: readonly TwinSnapshot[], look: TwinLook = realTwinLook): string[] {
  return sorted(snaps.filter((s) => !twinUnchanged(s, look)).map((s) => s.targetPath));
}

/** Watch the twins the launch has just written: snapshot each, mark each
 *  real file (memory only), and leave the snapshots in the twin directory
 *  for `mandu reap` (best effort: a failure costs only reap's notice).
 *  Never throws. */
export function watchTwins(
  files: ReadonlyArray<{ twinPath: string; targetPath: string; content: string }>,
  twinDir: string,
  look: TwinLook = realTwinLook,
): TwinWatch {
  const twins = files.map((f) => snapshotTwin(f, look));
  const real = new Map<string, RealFileMark | null>();
  for (const f of files) if (!real.has(f.targetPath)) real.set(f.targetPath, markRealFile(f.targetPath, look));
  const file = join(twinDir, TWIN_SNAPSHOT_FILE);
  try {
    publishFile(file, JSON.stringify({ version: 1, twins }), { mode: 0o600 });
    return { twins, real, file };
  } catch {
    return { twins, real, file: null };
  }
}

/** After the agent exits: each registered file whose twin changed, with
 *  what became of its real file. Sorted by path. Never throws. */
export function discardedWrites(watch: TwinWatch, look: TwinLook = realTwinLook): DiscardedWrite[] {
  return changedTwins(watch.twins, look).map((path) => ({ path, real: realFileState(path, watch.real.get(path), look) }));
}

/** The end of the session has said what changed: remove the snapshot file
 *  so `mandu reap` does not say it again of a kept scope dir. Best effort;
 *  never follows a link (unlink(2) does not). */
export function forgetTwinWatch(watch: TwinWatch): void {
  if (watch.file === null) return;
  try { unlinkSync(watch.file); } catch { /* already gone */ }
}

/** A path made safe for one terminal line: control characters (C0, DEL,
 *  C1), format characters (Unicode Cf: the bidi embeddings, overrides and
 *  isolates, zero-width characters) and the line and paragraph separators
 *  become `?`, so a file name can neither move the cursor, forge a line nor
 *  reorder the line on screen. Pure. */
export function printablePath(p: string): string {
  return p.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\p{Cf}]/gu, "?");
}

/**
 * The notice after the session, one line per changed file (by path only,
 * never content), in the order given. `kept`: the scope dir stays (a
 * non-zero exit, a named scope, MANDU_KEEP_SCOPE_DIR), so the copy is not
 * gone yet. "The real file is unchanged" only when it was checked. Pure.
 */
export function discardedWriteNotice(writes: readonly DiscardedWrite[], opts: { kept?: boolean } = {}): string[] {
  return writes.map(({ path, real }) => {
    const fate = opts.kept === true
      ? "did not apply it (the copy stays in the session's scope dir until `mandu reap` removes it)"
      : "discarded it";
    const tail = real === "unchanged"
      ? ", and the real file is unchanged. Apply the change yourself if you want it."
      : real === "changed"
        ? ". The real file also changed during the session, so check it before you apply the change yourself."
        : ". Mandu could not check whether the real file changed, so check it before you apply the change yourself.";
    return `mandu: during this session the agent changed ${printablePath(path)}; Mandu kept the change in its placeholder copy and ${fate}${tail}`;
  });
}

/** `mandu reap`'s notice for a scope dir it is about to remove, whose
 *  launcher ended before it could say what the session changed. Pure. */
export function reapDiscardedWriteNotice(scope: string, paths: readonly string[]): string[] {
  return paths.map((p) =>
    `  the session ${printablePath(scope)} ended before Mandu could say so: its agent changed ${printablePath(p)}; ` +
    "the change went to the file's placeholder copy, which goes with the scope dir, never to the real file. Apply it yourself if you want it.");
}

/** The snapshot file's twins, checked; null when it is not one. Pure. */
export function parseTwinSnapshots(v: unknown): TwinSnapshot[] | null {
  const o = v as { version?: unknown; twins?: unknown } | null;
  if (o === null || typeof o !== "object" || o.version !== 1 || !Array.isArray(o.twins)) return null;
  const out: TwinSnapshot[] = [];
  for (const t of o.twins as unknown[]) {
    const s = t as Partial<TwinSnapshot> | null;
    if (s === null || typeof s !== "object") return null;
    if (typeof s.targetPath !== "string" || typeof s.twinPath !== "string") return null;
    if (typeof s.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(s.sha256)) return null;
    if (typeof s.size !== "number" || !Number.isSafeInteger(s.size) || s.size < 0) return null;
    if ((s.dev !== undefined && typeof s.dev !== "string") || (s.ino !== undefined && typeof s.ino !== "string")) return null;
    out.push({
      targetPath: s.targetPath, twinPath: s.twinPath, sha256: s.sha256, size: s.size,
      ...(s.dev !== undefined && s.ino !== undefined ? { dev: s.dev, ino: s.ino } : {}),
    });
  }
  return out;
}

/** The twin directory of the scope dir `scopeRunDir` (where the launch
 *  writes its twins and the guard's policy file, secret-setup.ts). Pure. */
export function scopeTwinDir(scopeRunDir: string): string {
  return `${scopeRunDir.replace(/\/$/, "")}/secret-twins`;
}

/** Where the network guard makes the twins of the files it gates on demand
 *  (a derived copy, a labelled file the launch did not register), in the
 *  twin directory (net-supervisor guard_kernel.rs `derived_twin`). */
export const DERIVED_TWIN_DIR = "derived-twins";

/** The guard's record of each labelled file's twin it made, in
 *  `DERIVED_TWIN_DIR` (net-supervisor label_index.rs `TWIN_RECORDS`). */
export const LABELLED_TWIN_RECORDS = "labelled-twins.ndjson";

/** The largest record file read (a line is some 400 bytes). */
const LABELLED_RECORDS_MAX = 16 * 1024 * 1024;

/** A real file's identity as the guard found it: no size, no hash. */
export interface RealFileIdentity {
  dev: string;
  ino: string;
  mtimeNs: string;
  ctimeNs: string;
  /** When the guard looked (ns since the epoch); absent: never cleared. */
  markedNs?: string;
}

/** How long before the guard's look the real file's times must lie for an
 *  unchanged identity to clear it (2026-10-17, CI pipeline 11426): a
 *  same-size or other in-place write within one timestamp tick of the look
 *  (a coarse clock tick on Linux; 1-2 s on some filesystems) keeps the
 *  inode, mtime and ctime as they were, and the record holds no size or
 *  hash of the real bytes to catch it. Within the slack the notice says
 *  Mandu could not check, never that the real file is unchanged. */
export const REAL_TIME_SLACK_NS = 2_000_000_000n;

/** One labelled file's twin as the guard recorded it. */
export interface LabelledTwinRecord {
  snap: TwinSnapshot;
  /** Null when the record names none (then what became of it is unknown). */
  real: RealFileIdentity | null;
}

const DECIMAL = /^[0-9]{1,40}$/;

/** The guard's records, one per well-formed line (a torn or altered line
 *  is skipped: the file is advisory). Pure. */
export function parseLabelledTwinRecords(text: string): LabelledTwinRecord[] {
  const out: LabelledTwinRecord[] = [];
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    let v: unknown;
    try { v = JSON.parse(line); } catch { continue; }
    const o = v as { v?: unknown; real?: unknown } | null;
    if (o === null || typeof o !== "object" || o.v !== 1) continue;
    const snaps = parseTwinSnapshots({ version: 1, twins: [o] });
    if (snaps === null || snaps.length !== 1) continue;
    const r = o.real as Partial<RealFileIdentity> | null | undefined;
    const real = r !== null && typeof r === "object" && [r.dev, r.ino, r.mtimeNs, r.ctimeNs].every((x) => typeof x === "string" && DECIMAL.test(x))
      ? { dev: r.dev!, ino: r.ino!, mtimeNs: r.mtimeNs!, ctimeNs: r.ctimeNs!, ...(typeof r.markedNs === "string" && DECIMAL.test(r.markedNs) ? { markedNs: r.markedNs } : {}) }
      : null;
    out.push({ snap: snaps[0]!, real });
  }
  return out;
}

/** What became of the real file the guard identified as `mark`: gone, not
 *  a regular file or another identity is a change; the same device, inode,
 *  mtime and ctime is unchanged only when those times lie more than
 *  `REAL_TIME_SLACK_NS` before the guard's look (else a write in the same
 *  tick cannot be ruled out: unknown); no mark, or a file that cannot be
 *  looked at, is unknown. Never throws. */
export function realIdentityState(path: string, mark: RealFileIdentity | null, look: TwinLook = realTwinLook): RealFileState {
  if (mark === null) return "unknown";
  try {
    const st = look.stat(path);
    if (st === null || !st.regular) return "changed";
    if (st.dev !== mark.dev || st.ino !== mark.ino || st.mtimeNs !== mark.mtimeNs || st.ctimeNs !== mark.ctimeNs) return "changed";
    if (mark.markedNs === undefined) return "unknown";
    const latest = BigInt(mark.mtimeNs) > BigInt(mark.ctimeNs) ? BigInt(mark.mtimeNs) : BigInt(mark.ctimeNs);
    return BigInt(mark.markedNs) - latest > REAL_TIME_SLACK_NS ? "unchanged" : "unknown";
  } catch {
    return "unknown";
  }
}

const STATE_RANK: Record<RealFileState, number> = { unchanged: 0, unknown: 1, changed: 2 };

/**
 * The labelled files whose twin the guard made in the twin directory `h`
 * and a program then changed, each with what became of its real file (the
 * most cautious word over its changed twins: a twin remade after the real
 * file changed is another record). Each twin is looked up by its own name
 * in `DERIVED_TWIN_DIR`, whatever path its record names. Sorted by path;
 * empty when there is no record. Never throws.
 */
export function labelledDiscardedWritesIn(h: DirHandle, look: TwinLook = realTwinLook): DiscardedWrite[] {
  let derived: DirHandle;
  try { derived = openDirIn(h, DERIVED_TWIN_DIR); } catch { return []; }
  try {
    const text = readTextIn(derived, LABELLED_TWIN_RECORDS, LABELLED_RECORDS_MAX);
    if (text === null) return [];
    const here: TwinLook = { stat: (n) => look.stat(entryPathIn(derived, n)), hash: (n) => look.hash(entryPathIn(derived, n)) };
    const byPath = new Map<string, RealFileState>();
    for (const { snap, real } of parseLabelledTwinRecords(text)) {
      const name = twinName(snap.twinPath);
      if (name === null || name === LABELLED_TWIN_RECORDS) continue;
      if (twinUnchanged({ ...snap, twinPath: name }, here)) continue;
      const state = realIdentityState(snap.targetPath, real, look);
      const was = byPath.get(snap.targetPath);
      if (was === undefined || STATE_RANK[state] > STATE_RANK[was]) byPath.set(snap.targetPath, state);
    }
    return sorted(byPath.keys()).map((path) => ({ path, real: byPath.get(path)! }));
  } catch {
    return [];
  } finally {
    closeDir(derived);
  }
}

/** `labelledDiscardedWritesIn` of the twin directory at `twinDir`. Never
 *  throws. */
export function labelledDiscardedWrites(twinDir: string, look: TwinLook = realTwinLook): DiscardedWrite[] {
  let h: DirHandle;
  try { h = openDir(twinDir); } catch { return []; }
  try { return labelledDiscardedWritesIn(h, look); } finally { closeDir(h); }
}

/** The end of the session has said what changed: remove the guard's
 *  records so `mandu reap` does not say it again of a kept scope dir. Best
 *  effort; never follows a link (unlink(2) does not). */
export function forgetLabelledTwinRecords(twinDir: string): void {
  try { unlinkSync(join(twinDir, DERIVED_TWIN_DIR, LABELLED_TWIN_RECORDS)); } catch { /* none, or already gone */ }
}

/** Two lists of discarded writes as one, each path once (the more
 *  cautious word on the real file), sorted. Pure. */
export function mergeDiscardedWrites(a: readonly DiscardedWrite[], b: readonly DiscardedWrite[]): DiscardedWrite[] {
  const byPath = new Map<string, RealFileState>();
  for (const { path, real } of [...a, ...b]) {
    const was = byPath.get(path);
    if (was === undefined || STATE_RANK[real] > STATE_RANK[was]) byPath.set(path, real);
  }
  return sorted(byPath.keys()).map((path) => ({ path, real: byPath.get(path)! }));
}

/** A twin's own name in the twin directory: one name, not the snapshot
 *  file. */
function twinName(twinPath: string): string | null {
  const n = basename(twinPath);
  return n === "" || n === "." || n === ".." || n.includes("/") || n === TWIN_SNAPSHOT_FILE ? null : n;
}

/**
 * For `mandu reap`, about to remove the stale scope dir `<base>/<scope>`:
 * the registered files whose twin that session changed, from the snapshot
 * file its launch left (absent when the launcher ended normally and said
 * so itself), and the labelled files whose guard-made twin it changed, from
 * the guard's records (`labelledDiscardedWritesIn`, removed likewise). Everything is reached through the open scope and twin
 * directories (real directories of this user's, never a link; a twin is
 * looked up by its own name there, whatever path the file names). Empty
 * when there is neither file or they cannot be read. Never throws.
 */
export function staleScopeDiscardedWrites(base: string, scope: string, look: TwinLook = realTwinLook): string[] {
  const opened: DirHandle[] = [];
  try {
    opened.push(openDir(base));
    opened.push(openDirIn(opened[0]!, scope));
    const twinsH = openDirIn(opened[1]!, "secret-twins");
    opened.push(twinsH);
    const snaps = parseTwinSnapshots(readJsonIn(twinsH, TWIN_SNAPSHOT_FILE));
    const here: TwinLook = { stat: (n) => look.stat(entryPathIn(twinsH, n)), hash: (n) => look.hash(entryPathIn(twinsH, n)) };
    const inDir: TwinSnapshot[] = [];
    for (const s of snaps ?? []) {
      const name = twinName(s.twinPath);
      if (name !== null) inDir.push({ ...s, twinPath: name });
    }
    // The labelled files' twins the guard made (2026-10-17), in the same
    // twin directory.
    return sorted([...changedTwins(inDir, here), ...labelledDiscardedWritesIn(twinsH, look).map((w) => w.path)]);
  } catch {
    return [];
  } finally {
    for (const h of opened) closeDir(h);
  }
}
