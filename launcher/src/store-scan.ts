/**
 * store-scan — every object an object store holds is checked once, whether
 * anything reaches it or not (security fix 2026-10-21; confidentiality.md
 * §7.2a "Every stored object is checked once").
 *
 * The history step (git-object-twins.ts) finds a protected file's versions
 * from what git can REACH (the refs, the reflogs, the index, the working
 * copy), and the locked memory (locked-memory.ts) keeps every version a
 * launch once found. A version NO launch ever found stayed readable by
 * object id through the object twins: history cut before Mandu first walked
 * the repository with that path protected (an orphaned branch, the reflogs
 * expired), a tree in no ref (`git write-tree`), a blob written by plumbing
 * and abandoned (`git hash-object -w`). So the step also reads the STORE:
 *
 *   - every object id the store's object directories hold (each pack's
 *     `.idx`, each loose fan-out directory; alternates included) that this
 *     store's scan has not seen before is asked its type, and every new
 *     tree, commit and tag is read;
 *   - each tree gets its paths from the trees and commits that name it: a
 *     commit's (or a tag's) tree is a root; a tree a new tree names is at
 *     that tree's path plus the entry's name, an OLD tree named at a path it
 *     was never seen at (a renamed folder) is read again there; a new tree
 *     nothing names (no commit, no tree: `git write-tree`, or a subtree whose
 *     parent is gone) is read as a root AND under every folder a protected
 *     path or a label names (`top`: its real place is unknown, so every
 *     place a protected path could be is assumed);
 *   - every (blob, path) a tree names is recorded, for EVERY path, so a path
 *     protected later (a new label, a new protected file) finds its versions
 *     among what was recorded, with no new scan; the versions at the paths
 *     protected now join the walk's, hidden like them;
 *   - a blob no tree names (no path to decide it by) is hidden when its
 *     content shares a credential-like token with a protected version (the
 *     current file or an earlier one), and only when no index of the store
 *     holds it (a staged file has its path there). It is then remembered as
 *     a version of that protected path, for good: a tree written later
 *     naming it (the agent can write one, `git mktree`, without reading it)
 *     does not bring it back.
 *
 * The cost is paid once per object: the scan keeps, per store, the ids it
 * has seen, the (object, path) pairs it recorded and the path table, under
 * `<walk cache>/store-scan/<key>/` (the Mandu home's state, which the agent
 * can neither read nor write), its `state.json` sealed with the arbiter like
 * the walk cache (cache-seals.ts; kind `store-scan`), the data files it
 * names checked by identity (device, inode, size, mtime, ctime). A launch
 * with nothing new stats each object directory, its `pack/` and its loose
 * fan-out directories (a fingerprint; an entry younger than two seconds is
 * never trusted, git's "racily clean"), reads nothing else and asks git
 * nothing. A new pack (a repack) costs reading its `.idx` and merging it
 * with the ids seen; only ids never seen are asked of git. Anything the scan
 * cannot vouch for (no seal of the current epoch, a data file changed, a
 * torn file, a new rule) scans the store anew: slower, never less.
 *
 * FAIL-CLOSED: a git call that fails, an index that cannot be read, fails
 * the store (the caller refuses the launch unless --best-effort). A store
 * over the object cap (MANDU_GIT_STORE_SCAN_MAX_OBJECTS) is not scanned and
 * the caller says so (the residual of confidentiality.md §7.2a).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { createHash, randomBytes } from "node:crypto";
import {
  closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync,
  type Stats,
} from "node:fs";
import { join } from "node:path";
import { constants as zlibConstants, inflateSync } from "node:zlib";
import type { SealSession } from "./cache-seals.js";
import type { GitRunner } from "./git-object-twins.js";
import { Pacer } from "./reflog-tips.js";

/** The rule the kept state was computed by; another rule scans anew. */
export const STORE_SCAN_RULE = "store-scan:v1 tops=root+prefixes pathless=tokens+index";
/** The seal kind of a store's `state.json` (cache-seals.ts). */
export const SEAL_KIND_STORE_SCAN = "store-scan";
/** An entry whose mtime or ctime is this recent is never trusted unchanged. */
export const RACY_MS = 2000;
/** A store holding more objects is not scanned (the caller warns). */
export const STORE_SCAN_MAX_OBJECTS = 4_000_000;
/** A pathless blob over this is not read for the token rule (said in
 *  confidentiality.md §7.2a: credential files are small). */
export const CANDIDATE_MAX_BYTES = 4 * 1024 * 1024;
/** A state file over this is not read (scanned anew). */
export const STATE_MAX_BYTES = 64 * 1024 * 1024;
/** How many predicate answers a state keeps (one per protected-path set:
 *  launches from different work trees of one store may differ). */
export const MAX_ANSWERS = 8;
/** The first scan of a store this large says it is slower this once. */
export const FIRST_SCAN_NOTICE_OBJECTS = 20_000;

/** MANDU_GIT_STORE_SCAN_MAX_OBJECTS → the cap (unset/invalid: default). Pure. */
export function storeScanMaxFromEnv(env: Record<string, string | undefined>): number {
  const n = Number(env["MANDU_GIT_STORE_SCAN_MAX_OBJECTS"]);
  return Number.isInteger(n) && n > 0 ? n : STORE_SCAN_MAX_OBJECTS;
}

// ── Pure: identities ────────────────────────────────────────────────────────

/** (device, inode, size, mtime ms, ctime ms) of a file or directory. */
export type Ident = [number, number, number, number, number];

export function identOf(st: Stats): Ident {
  return [st.dev, st.ino, st.size, st.mtimeMs, st.ctimeMs];
}

export function sameIdent(a: Ident | null | undefined, b: Ident | null | undefined): boolean {
  return a !== null && a !== undefined && b !== null && b !== undefined && a.length === 5 && b.length === 5 && a.every((v, i) => v === b[i]);
}

/** Too recent to be trusted unchanged at the next look (a change within the
 *  same timestamp granule would keep it). Pure. */
export function isRacy(id: Ident, now: number): boolean {
  return id[3] >= now - RACY_MS || id[4] >= now - RACY_MS;
}

// ── Pure: sorted object-id sets and pair records ────────────────────────────

/** Compare `n` bytes of `a` at `ai` with `b` at `bi`. Pure. */
export function cmpBytes(a: Buffer, ai: number, b: Buffer, bi: number, n: number): number {
  let i = 0;
  for (; i + 4 <= n; i += 4) {
    const x = a.readUInt32BE(ai + i);
    const y = b.readUInt32BE(bi + i);
    if (x !== y) return x < y ? -1 : 1;
  }
  for (; i < n; i++) {
    const x = a[ai + i]!;
    const y = b[bi + i]!;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** Index of the first record of `buf` (records of `width` bytes, sorted by
 *  their first `keyLen` bytes) not below `key` at `ko`. Pure. */
export function lowerBound(buf: Buffer, width: number, key: Buffer, ko: number, keyLen: number): number {
  let lo = 0;
  let hi = Math.floor(buf.length / width);
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (cmpBytes(buf, mid * width, key, ko, keyLen) < 0) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** Is the id at `key[ko..]` in the sorted id set `ids`? Pure. */
export function hasId(ids: Buffer, hashLen: number, key: Buffer, ko = 0): boolean {
  const i = lowerBound(ids, hashLen, key, ko, hashLen);
  return i * hashLen < ids.length && cmpBytes(ids, i * hashLen, key, ko, hashLen) === 0;
}

/** The ids of the sorted run `names` (`count` ids of `hashLen` bytes from
 *  `off`) that the sorted set `seen` lacks, by one merge. Pure. */
export function unseenOfSorted(names: Buffer, off: number, count: number, seen: Buffer, hashLen: number): Buffer[] {
  const out: Buffer[] = [];
  const total = Math.floor(seen.length / hashLen);
  let j = 0;
  for (let i = 0; i < count; i++) {
    const p = off + i * hashLen;
    while (j < total && cmpBytes(seen, j * hashLen, names, p, hashLen) < 0) j++;
    if (j < total && cmpBytes(seen, j * hashLen, names, p, hashLen) === 0) continue;
    out.push(names.subarray(p, p + hashLen));
  }
  return out;
}

/** `ids` (raw) sorted, duplicates out, as one buffer. Pure. */
export function sortedIdBuffer(ids: readonly Buffer[], hashLen: number): Buffer {
  const hex = [...new Set(ids.map((b) => b.toString("hex")))].sort();
  const out = Buffer.alloc(hex.length * hashLen);
  hex.forEach((h, i) => out.write(h, i * hashLen, "hex"));
  return out;
}

/** The union of two sorted, duplicate-free record buffers (`width` bytes
 *  each, whole-record order). Pure. */
export function mergeSorted(a: Buffer, b: Buffer, width: number): Buffer {
  const out = Buffer.alloc(a.length + b.length);
  let i = 0;
  let j = 0;
  let o = 0;
  while (i < a.length && j < b.length) {
    const c = cmpBytes(a, i, b, j, width);
    if (c <= 0) { a.copy(out, o, i, i + width); o += width; i += width; if (c === 0) j += width; }
    else { b.copy(out, o, j, j + width); o += width; j += width; }
  }
  if (i < a.length) { a.copy(out, o, i); o += a.length - i; }
  if (j < b.length) { b.copy(out, o, j); o += b.length - j; }
  return out.subarray(0, o);
}

/** A pair record's meta word: the path id, and whether the object is a tree
 *  and whether its path is relative to a tree nothing names (`top`). */
export const META_TOP = 0x80000000;
export const META_TREE = 0x40000000;
export const META_PATH = 0x3fffffff;
/** At most this many distinct paths (the in-run keys need it). */
export const MAX_PATHS = 1 << 20;

/** Records of (object id, meta u32 BE), `hashLen + 4` bytes each, sorted. */
export function recordWidth(hashLen: number): number {
  return hashLen + 4;
}

/** The metas the sorted records hold for the id at `key[ko..]`. Pure. */
export function metasOf(recs: Buffer, hashLen: number, key: Buffer, ko = 0): number[] {
  const w = recordWidth(hashLen);
  const out: number[] = [];
  for (let i = lowerBound(recs, w, key, ko, hashLen); i * w < recs.length; i++) {
    if (cmpBytes(recs, i * w, key, ko, hashLen) !== 0) break;
    out.push(recs.readUInt32BE(i * w + hashLen));
  }
  return out;
}

/** A buffer of `width`-byte records sorted, duplicates out (a new buffer).
 *  Pure. */
export function sortRecords(buf: Buffer, w: number): Buffer {
  const n = Math.floor(buf.length / w);
  const order = Array.from({ length: n }, (_, i) => i).sort((x, y) => cmpBytes(buf, x * w, buf, y * w, w));
  const out = Buffer.alloc(buf.length);
  let o = 0;
  for (const i of order) {
    if (o > 0 && cmpBytes(out, o - w, buf, i * w, w) === 0) continue;
    buf.copy(out, o, i * w, i * w + w);
    o += w;
  }
  return out.subarray(0, o);
}

// ── Pure: git's answers ─────────────────────────────────────────────────────

export interface ObjectInfo { oid: string; type: string; size: number }

/** `cat-file --batch-check='%(objectname) %(objecttype) %(objectsize)'`
 *  output: the objects git has, and the names it reported missing. Throws
 *  on a line of another shape (the caller fails closed). Pure. */
export function parseBatchCheck(out: string, hexLen: number): { found: ObjectInfo[]; missing: string[] } {
  const found: ObjectInfo[] = [];
  const missing: string[] = [];
  const re = new RegExp(`^([0-9a-f]{${hexLen}}) (blob|tree|commit|tag) (\\d+)$`);
  const miss = new RegExp(`^([0-9a-f]{${hexLen}}) missing$`);
  for (const line of out.split("\n")) {
    if (line === "") continue;
    const m = re.exec(line);
    if (m !== null) { found.push({ oid: m[1]!, type: m[2]!, size: Number(m[3]) }); continue; }
    const x = miss.exec(line);
    if (x !== null) { missing.push(x[1]!); continue; }
    throw new Error(`unexpected cat-file --batch-check line: ${line.slice(0, 120)}`);
  }
  return { found, missing };
}

/** Each object of `cat-file --batch` output (`<oid> <type> <size>\n<body>\n`
 *  or `<oid> missing\n`), its body a view of `buf`. Throws on a malformed
 *  answer (the caller fails closed). Pure. */
export function parseBatch(buf: Buffer, hexLen: number): { objects: Array<{ oid: string; type: string; body: Buffer }>; missing: string[] } {
  const objects: Array<{ oid: string; type: string; body: Buffer }> = [];
  const missing: string[] = [];
  let p = 0;
  while (p < buf.length) {
    const nl = buf.indexOf(10, p);
    if (nl < 0) throw new Error("cat-file --batch: a header without its end");
    const head = buf.toString("latin1", p, nl);
    const parts = head.split(" ");
    if (parts.length === 2 && parts[1] === "missing" && parts[0]!.length === hexLen) { missing.push(parts[0]!); p = nl + 1; continue; }
    if (parts.length !== 3 || parts[0]!.length !== hexLen || !/^\d+$/.test(parts[2]!)) throw new Error(`cat-file --batch: unexpected header ${head.slice(0, 120)}`);
    const size = Number(parts[2]);
    const start = nl + 1;
    if (start + size + 1 > buf.length || buf[start + size] !== 10) throw new Error("cat-file --batch: a body shorter than its size");
    objects.push({ oid: parts[0]!, type: parts[1]!, body: buf.subarray(start, start + size) });
    p = start + size + 1;
  }
  return { objects, missing };
}

export const ENTRY_BLOB = 0;
export const ENTRY_TREE = 1;
export const ENTRY_OTHER = 2;

/** The entries of a tree object's body: (kind, name, child id raw). A
 *  gitlink (a submodule's commit) is `ENTRY_OTHER`. Throws on a malformed
 *  tree. Pure. */
export function treeEntries(body: Buffer, hashLen: number): Array<{ kind: number; name: string; oid: Buffer }> {
  const out: Array<{ kind: number; name: string; oid: Buffer }> = [];
  forEachEntry(body, hashLen, (kind, nameStart, nameEnd, oidAt) => {
    out.push({ kind, name: body.toString("utf8", nameStart, nameEnd), oid: body.subarray(oidAt, oidAt + hashLen) });
  });
  return out;
}

/** Each entry of a tree object's body, without copying: its kind, where
 *  its name lies and where its child id starts. Throws on a malformed
 *  tree. Pure. */
export function forEachEntry(body: Buffer, hashLen: number, fn: (kind: number, nameStart: number, nameEnd: number, oidAt: number, entryStart: number) => void): void {
  let p = 0;
  while (p < body.length) {
    const sp = body.indexOf(32, p);
    const nul = sp < 0 ? -1 : body.indexOf(0, sp + 1);
    if (sp < 0 || nul < 0 || nul + 1 + hashLen > body.length || sp === p) throw new Error("a malformed tree object");
    // The mode: "40000" (a tree; "040000" from old writers), "160000" (a
    // gitlink), anything else a blob (100644, 100755, 120000, odd old modes).
    const m0 = body[p]!;
    const len = sp - p;
    const kind = (len === 5 && m0 === 0x34) || (len === 6 && m0 === 0x30 && body[p + 1] === 0x34)
      ? ENTRY_TREE
      : len === 6 && m0 === 0x31 && body[p + 1] === 0x36 ? ENTRY_OTHER : ENTRY_BLOB;
    fn(kind, sp + 1, nul, nul + 1, p);
    p = nul + 1 + hashLen;
  }
}

/** The tree a commit body names, or null. Pure. */
export function commitTree(body: Buffer, hexLen: number): string | null {
  const m = new RegExp(`^tree ([0-9a-f]{${hexLen}})\\n`).exec(body.toString("latin1", 0, Math.min(body.length, hexLen + 6)));
  return m === null ? null : m[1]!;
}

/** The object and type a tag body names, or null. Pure. */
export function tagTarget(body: Buffer, hexLen: number): { object: string; type: string } | null {
  const m = new RegExp(`^object ([0-9a-f]{${hexLen}})\\ntype (\\w+)\\n`).exec(body.toString("latin1", 0, Math.min(body.length, hexLen + 40)));
  return m === null ? null : { object: m[1]!, type: m[2]! };
}

// ── Pure: the token rule for pathless blobs ─────────────────────────────────

/**
 * The credential-like tokens of a text: every run of 12 or more of
 * `[A-Za-z0-9+/_.~-]` that holds a letter and a digit (a key, a token, a
 * digest, a PEM line), and every `KEY=value` / `KEY: value` line whose value
 * is 8 or more characters, as the whole trimmed line. A name alone
 * (`ANTHROPIC_API_KEY`, no digit) is not a token: code that only names a
 * variable shares nothing with the file that sets it. Pure.
 */
export function credentialTokens(text: string): Set<string> {
  const out = new Set<string>();
  for (const m of text.matchAll(/[A-Za-z0-9+/_.~-]{12,}/g)) {
    const t = m[0];
    if (/[A-Za-z]/.test(t) && /[0-9]/.test(t)) out.add(t);
  }
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const m = /^(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*[=:]\s*(.*)$/.exec(line);
    if (m !== null && m[1]!.trim().length >= 8) out.add(line.replace(/\s*([=:])\s*/, "$1"));
  }
  return out;
}

// ── Pure: what decides a path ───────────────────────────────────────────────

/** What the store's protected paths are this launch: `isProtected` decides
 *  a path relative to a work tree of the store; `prefixes` are the folders
 *  ("" first, the rest ending in "/") a tree nothing names is also read
 *  under; `key` names the set (equal keys, equal answers). */
export interface ScanPredicate {
  key: string;
  isProtected(rel: string): boolean;
  prefixes: readonly string[];
}

/** The folders a tree with no known place is also read under: every
 *  folder above a protected path, and every label pathspec (which may name
 *  a folder) with the folders above it, "" first. Pure. */
export function topPrefixes(paths: readonly string[], folders: readonly string[] = []): string[] {
  const out = new Set<string>([""]);
  for (const [l, self] of [...paths.map((x) => [x, false] as const), ...folders.map((x) => [x, true] as const)]) {
    const parts = l.split("/").filter((s) => s !== "");
    let acc = "";
    for (let i = 0; i < parts.length - (self ? 0 : 1); i++) {
      acc += `${parts[i]}/`;
      out.add(acc);
    }
  }
  return ["", ...[...out].filter((p) => p !== "").sort()];
}

/** Is `rel`, a path relative to a tree nothing names, protected at some
 *  place that tree could be: as a root, or under one of the prefixes. */
export function topProtected(rel: string, p: ScanPredicate): boolean {
  for (const x of p.prefixes) if (p.isProtected(x + rel)) return true;
  return false;
}

/** The place (`x + rel`) at which it is protected, or null. */
function topPlace(rel: string, p: ScanPredicate): string | null {
  for (const x of p.prefixes) if (p.isProtected(x + rel)) return x + rel;
  return null;
}

// ── The kept state ──────────────────────────────────────────────────────────

/** One object directory's fingerprint as the scan last listed it. */
export interface DirPrint {
  dir: string;
  /** The directory itself (null: too recent, listed again). */
  objects: Ident | null;
  pack: Ident | null;
  /** Each pack (by base name) whose ids were all taken: its .idx and .pack. */
  packs: Record<string, [Ident, Ident]>;
  /** Each loose fan-out directory whose ids were all taken (null: listed again). */
  loose: Record<string, Ident | null>;
}

/** A blob no tree names, as the token rule last left it. */
export interface Candidate {
  size: number;
  /** `u`: no token shared with the protected versions named by `d`; `m`:
   *  shares one with a version of `path` (hidden for good); `i`: shares one
   *  but an index holds it (`idx`: the index files then); `x`: over the
   *  size cap, not read. */
  s: "u" | "m" | "i" | "x";
  d?: string;
  path?: string;
  idx?: Array<[string, Ident]>;
}

export interface ScanState {
  v: 1;
  rule: string;
  commonDir: string;
  hashLen: number;
  /** Data files of this generation: seen ids, pair records, the path table. */
  gen: string;
  files: { seen: Ident; pairs: Ident; paths: Ident };
  dirs: DirPrint[];
  /** Predicate key → the protected (version, path) pairs among the records. */
  answers: Array<{ key: string; pairs: Array<[string, string]> }>;
  candidates: Record<string, Candidate>;
}

const HEX = /^[0-9a-f]+$/;

/** A state file's text, or null when it is not exactly one of `commonDir`
 *  of this rule (scanned anew). Pure. */
export function parseScanState(text: string, commonDir: string): ScanState | null {
  let j: unknown;
  try { j = JSON.parse(text); } catch { return null; }
  if (j === null || typeof j !== "object") return null;
  const s = j as ScanState;
  const isIdent = (x: unknown): x is Ident => Array.isArray(x) && x.length === 5 && x.every((n) => typeof n === "number" && Number.isFinite(n));
  if (s.v !== 1 || s.rule !== STORE_SCAN_RULE || s.commonDir !== commonDir || (s.hashLen !== 20 && s.hashLen !== 32)) return null;
  if (typeof s.gen !== "string" || !/^[0-9a-f]{16}$/.test(s.gen)) return null;
  if (s.files === null || typeof s.files !== "object" || !isIdent(s.files.seen) || !isIdent(s.files.pairs) || !isIdent(s.files.paths)) return null;
  if (!Array.isArray(s.dirs) || !s.dirs.every((d) =>
    d !== null && typeof d === "object" && typeof d.dir === "string" && (d.objects === null || isIdent(d.objects)) && (d.pack === null || isIdent(d.pack))
    && d.packs !== null && typeof d.packs === "object" && Object.values(d.packs).every((v) => Array.isArray(v) && v.length === 2 && isIdent(v[0]) && isIdent(v[1]))
    && d.loose !== null && typeof d.loose === "object" && Object.values(d.loose).every((v) => v === null || isIdent(v)))) return null;
  if (!Array.isArray(s.answers) || !s.answers.every((a) => a !== null && typeof a === "object" && typeof a.key === "string" && Array.isArray(a.pairs)
    && a.pairs.every((p) => Array.isArray(p) && p.length === 2 && typeof p[0] === "string" && HEX.test(p[0]) && typeof p[1] === "string"))) return null;
  if (s.candidates === null || typeof s.candidates !== "object" || Array.isArray(s.candidates)) return null;
  for (const [oid, c] of Object.entries(s.candidates)) {
    if (!HEX.test(oid) || oid.length !== s.hashLen * 2 || c === null || typeof c !== "object" || !["u", "m", "i", "x"].includes(c.s) || typeof c.size !== "number") return null;
    if (c.s === "m" && typeof c.path !== "string") return null;
    if (c.s === "i" && !(Array.isArray(c.idx) && c.idx.every((e) => Array.isArray(e) && typeof e[0] === "string" && isIdent(e[1])))) return null;
  }
  return s;
}

/** The scan state directory of the store whose real common dir is `commonDir`. */
export function storeScanDir(stateRoot: string, commonDir: string): string {
  return join(stateRoot, createHash("sha256").update(commonDir).digest("hex").slice(0, 32));
}

function readFileNoFollow(path: string, max: number): Buffer | null {
  let fd: number;
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch { return null; }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > max) return null;
    return readFileSync(fd);
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

/** A data file of the state, when it still is what the state recorded. */
function readKept(path: string, want: Ident): Buffer | null {
  let st: Stats;
  try { st = lstatSync(path); } catch { return null; }
  if (!st.isFile() || !sameIdent(identOf(st), want)) return null;
  const b = readFileNoFollow(path, STATE_MAX_BYTES * 16);
  return b !== null && b.length === want[2] ? b : null;
}

// ── Byte-keyed ids and the path table ───────────────────────────────────────

/**
 * Small integer ids for byte strings (object ids, entry names), looked up
 * straight from the bytes of a tree body: a tree's two million entries cost
 * no string each. Open addressing over a seeded FNV-1a hash (an object store
 * cannot steer it into long probes).
 */
export class ByteIds {
  private slots: Int32Array;
  private data: Buffer = Buffer.alloc(4096);
  private used = 0;
  private offs: Uint32Array = new Uint32Array(1024);
  private lens: Uint32Array = new Uint32Array(1024);
  private hashes: Uint32Array = new Uint32Array(1024);
  size = 0;
  /** `objectIds`: keys are object ids, already uniformly spread (hashed
   *  from their first eight bytes; steering two into one slot means finding
   *  a 64-bit prefix collision). */
  constructor(private readonly objectIds = false, private readonly seed: number = randomBytes(4).readUInt32LE(0)) {
    this.slots = new Int32Array(2048).fill(-1);
  }
  private hash(b: Buffer, s: number, e: number): number {
    if (this.objectIds && e - s >= 8) return (Math.imul(b.readUInt32LE(s) ^ this.seed, 0x9e3779b1) ^ b.readUInt32LE(s + 4)) >>> 0;
    let h = (0x811c9dc5 ^ this.seed) >>> 0;
    for (let i = s; i < e; i++) h = Math.imul(h ^ b[i]!, 16777619);
    return h >>> 0;
  }
  private same(id: number, b: Buffer, s: number, len: number): boolean {
    if (this.lens[id] !== len) return false;
    const d = this.data;
    const o = this.offs[id]!;
    for (let i = 0; i < len; i++) if (d[o + i] !== b[s + i]) return false;
    return true;
  }
  /** The id of `b[s..e)`, given one when new. */
  idOf(b: Buffer, s: number, e: number): number {
    const h = this.hash(b, s, e);
    const len = e - s;
    const mask = this.slots.length - 1;
    for (let i = h & mask; ; i = (i + 1) & mask) {
      const id = this.slots[i]!;
      if (id < 0) {
        const n = this.add(b, s, len, h);
        this.slots[i] = n;
        if (this.size * 2 > this.slots.length) this.grow();
        return n;
      }
      if (this.hashes[id] === h && this.same(id, b, s, len)) return id;
    }
  }
  private add(b: Buffer, s: number, len: number, h: number): number {
    if (this.used + len > this.data.length) {
      const g = Buffer.alloc(Math.max(this.data.length * 2, this.used + len));
      this.data.copy(g, 0, 0, this.used);
      this.data = g;
    }
    if (this.size === this.offs.length) {
      const grow = (a: Uint32Array): Uint32Array => { const g = new Uint32Array(a.length * 2); g.set(a); return g; };
      this.offs = grow(this.offs);
      this.lens = grow(this.lens);
      this.hashes = grow(this.hashes);
    }
    b.copy(this.data, this.used, s, s + len);
    const id = this.size++;
    this.offs[id] = this.used;
    this.lens[id] = len;
    this.hashes[id] = h;
    this.used += len;
    return id;
  }
  private grow(): void {
    const slots = new Int32Array(this.slots.length * 2).fill(-1);
    const mask = slots.length - 1;
    for (let id = 0; id < this.size; id++) {
      let i = this.hashes[id]! & mask;
      while (slots[i]! >= 0) i = (i + 1) & mask;
      slots[i] = id;
    }
    this.slots = slots;
  }
  /** Where the bytes of `id` lie: `buf()` from `offset(id)`. */
  buf(): Buffer { return this.data; }
  offset(id: number): number { return this.offs[id]!; }
  hex(id: number): string { return this.data.toString("hex", this.offs[id]!, this.offs[id]! + this.lens[id]!); }
}

/** The distinct paths, id 0 the root (""); a path's id never changes. Its
 *  lookup maps are built at the first `child` (a launch that only answers
 *  from the records never builds them). */
class PathTable {
  readonly paths: string[];
  private readonly byKey = new Map<number, number>();
  private readonly names = new ByteIds();
  private readonly byString = new Map<string, number>();
  private built = false;
  added = 0;
  constructor(paths: string[]) {
    this.paths = paths.length === 0 ? [""] : paths;
  }
  private build(): void {
    this.built = true;
    this.paths.forEach((p, i) => this.byString.set(p, i));
    for (let i = 1; i < this.paths.length; i++) {
      const p = this.paths[i]!;
      const slash = p.lastIndexOf("/");
      const parent = slash < 0 ? 0 : this.byString.get(p.slice(0, slash));
      const name = Buffer.from(p.slice(slash + 1), "utf8");
      if (parent !== undefined) this.byKey.set(parent * 2097152 + this.names.idOf(name, 0, name.length), i);
    }
  }
  /** The id of the path `parent`/(the name at `b[s..e)`). */
  child(parent: number, b: Buffer, s: number, e: number): number {
    if (!this.built) this.build();
    const n = this.names.idOf(b, s, e);
    if (n >= 2097152) throw new StoreScanOverCap("more than 2097152 distinct names");
    const k = parent * 2097152 + n;
    let id = this.byKey.get(k);
    if (id === undefined) {
      const name = b.toString("utf8", s, e);
      const p = parent === 0 ? name : `${this.paths[parent]}/${name}`;
      id = this.byString.get(p);
      if (id === undefined) {
        id = this.paths.length;
        if (id >= MAX_PATHS) throw new StoreScanOverCap(`more than ${MAX_PATHS} distinct paths`);
        this.paths.push(p);
        this.byString.set(p, id);
        this.added++;
      }
      this.byKey.set(k, id);
    }
    return id;
  }
}


/** The store is over a scan cap: not scanned (the caller warns). */
export class StoreScanOverCap extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StoreScanOverCap";
  }
}

// ── Loose objects ───────────────────────────────────────────────────────────

/** A loose object's body over this is asked of git instead. */
export const LOOSE_BODY_MAX = 8 * 1024 * 1024;

/** `<type> <size>\0` at the start of an inflated loose object: the type,
 *  the size and where the body starts, or null. Pure. */
export function parseLooseHeader(b: Buffer): { type: string; size: number; start: number } | null {
  const nul = b.indexOf(0);
  if (nul < 0 || nul > 32) return null;
  const m = /^(blob|tree|commit|tag) (0|[1-9][0-9]{0,15})$/.exec(b.toString("latin1", 0, nul));
  return m === null ? null : { type: m[1]!, size: Number(m[2]), start: nul + 1 };
}

/**
 * A loose object of `dir` read here, as git would read it: its type and
 * size, and its body when `wantBody(type)` (whole, checked against the
 * size its header declares). Null on anything this does not read with
 * certainty (a file that is not regular, a stream that does not inflate, a
 * body larger than LOOSE_BODY_MAX or than declared): the caller asks git.
 */
export function readLooseObject(dir: string, hexId: string, wantBody: (type: string) => boolean): { type: string; size: number; body: Buffer | null } | null {
  const z = readFileNoFollow(join(dir, hexId.slice(0, 2), hexId.slice(2)), 64 * 1024 * 1024);
  if (z === null || z.length === 0) return null;
  let head: Buffer;
  try { head = inflateSync(z.subarray(0, Math.min(z.length, 256)), { finishFlush: zlibConstants.Z_SYNC_FLUSH }); } catch { return null; }
  const h = parseLooseHeader(head);
  if (h === null) return null;
  if (!wantBody(h.type)) return { type: h.type, size: h.size, body: null };
  if (h.size > LOOSE_BODY_MAX) return null;
  let full: Buffer;
  try { full = inflateSync(z, { maxOutputLength: h.start + h.size }); } catch { return null; }
  if (full.length !== h.start + h.size) return null;
  return { type: h.type, size: h.size, body: full.subarray(h.start) };
}

// ── The scan ────────────────────────────────────────────────────────────────

/** How one store's scan went (a test and log aid). */
export interface StoreScanStats {
  /** Stores scanned from nothing, incrementally, unchanged. */
  first: number;
  incremental: number;
  unchanged: number;
  /** Object ids listed from new packs and changed loose directories. */
  listed: number;
  /** Objects asked of git (new ids), and bodies read (trees, commits,
   *  tags, renamed old trees, pathless blobs, protected versions). */
  asked: number;
  read: number;
  /** git calls the scan made. */
  gitCalls: number;
  /** Predicate answers computed over every record (a new protected set). */
  reevaluated: number;
  /** Stores over the cap (not scanned). */
  overCap: number;
  /** New loose objects read here (not asked of git). */
  loose: number;
  /** Where the time went (ms by phase), a log aid. */
  ms: Record<string, number>;
}

export function newStoreScanStats(): StoreScanStats {
  return { first: 0, incremental: 0, unchanged: 0, listed: 0, asked: 0, read: 0, gitCalls: 0, reevaluated: 0, overCap: 0, loose: 0, ms: {} };
}

/** `from` added into `into`. */
export function addStoreScanStats(into: StoreScanStats, from: StoreScanStats): void {
  for (const k of ["first", "incremental", "unchanged", "listed", "asked", "read", "gitCalls", "reevaluated", "overCap", "loose"] as const) into[k] += from[k];
  for (const [k, v] of Object.entries(from.ms)) into.ms[k] = (into.ms[k] ?? 0) + v;
}

export interface StoreScanOpts {
  git: GitRunner;
  /** A work tree of the store: the git calls run there. */
  cwd: string;
  /** The store's real common dir (its key). */
  commonDir: string;
  hashLen: number;
  /** Every object directory the store reads (alternates followed). */
  dirs: readonly string[];
  /** `<walk cache>/store-scan` (the agent can neither read nor write it);
   *  unset: nothing kept, every launch scans the whole store. */
  stateRoot?: string;
  sealing?: SealSession;
  maxObjects?: number;
  stats?: StoreScanStats;
  /** Wall clock (ms), a test knob. */
  now?: () => number;
  /** Said once before a first scan of a large store (the rebuild notice). */
  onFirstScan?: () => void;
}

/** What the first half of a store's scan found, and its second half. */
export interface StoreScan {
  /** Objects held, when the store is over the cap (not scanned), else null. */
  overCap: number | null;
  /** Every recorded (version, path) at a path protected now. */
  pairs: Array<[string, string]>;
  /**
   * The token rule for the blobs no tree names (needs the store's protected
   * versions: `known`, (version, path) pairs, and `workingFiles`, the
   * protected files as (absolute path, relative path)), then the state kept.
   * Returns the pathless blobs hidden, each as a version of its protected
   * path (only paths protected now). Throws on a failed git call.
   */
  finish(known: ReadonlyArray<readonly [string, string]>, workingFiles: ReadonlyArray<readonly [string, string]>): Promise<Array<[string, string]>>;
}

interface Listing {
  dirs: DirPrint[];
  /** Ids listed that the kept set lacks (hex, unique). */
  fresh: string[];
  changed: boolean;
  total: number;
}

/** Stat without throwing: null when absent. */
function statOrNull(p: string): Stats | null {
  try { return statSync(p); } catch { return null; }
}

/** Where a new id was listed: the pack (by base name) or the loose fan-out
 *  directory of the object directory `dir`. */
export interface FreshSource { dir: string; pack?: string; loose?: string }

/** The ids one object directory holds that `seen` lacks (each with where
 *  it was listed: a pack wins over a loose copy), and its new fingerprint;
 *  `old` (its last fingerprint) spares what did not change. */
export function listObjectDir(
  dir: string, old: DirPrint | undefined, hashLen: number, seen: () => Buffer, now: number, out: Map<string, FreshSource>, counts: { listed: number },
): { print: DirPrint; changed: boolean } {
  const hex = hashLen * 2;
  const keep = (st: Stats | null): Ident | null => (st === null ? null : isRacy(identOf(st), now) ? null : identOf(st));
  const objSt = statOrNull(dir);
  if (objSt === null) return { print: { dir, objects: null, pack: null, packs: {}, loose: {} }, changed: old !== undefined && (old.objects !== null || Object.keys(old.packs).length > 0) };
  let changed = false;
  // Packs: the pack directory unchanged (nothing added, removed or renamed)
  // keeps every pack the last listing took.
  const packDir = join(dir, "pack");
  const packSt = statOrNull(packDir);
  const packs: Record<string, [Ident, Ident]> = {};
  if (old !== undefined && packSt !== null && sameIdent(old.pack, identOf(packSt))) {
    Object.assign(packs, old.packs);
  } else if (packSt !== null) {
    changed = true;
    let names: string[] = [];
    try { names = readdirSync(packDir); } catch { names = []; }
    for (const n of names) {
      if (!/^pack-[0-9a-f]+\.idx$/.test(n)) continue;
      const base = n.slice(0, -4);
      const idxSt = statOrNull(join(packDir, n));
      const pSt = statOrNull(join(packDir, `${base}.pack`));
      if (idxSt === null || pSt === null || !idxSt.isFile() || !pSt.isFile()) continue;
      const prev = old?.packs[base];
      if (prev !== undefined && sameIdent(prev[0], identOf(idxSt)) && sameIdent(prev[1], identOf(pSt))) { packs[base] = prev; continue; }
      const idx = readFileSync(join(packDir, n));
      if (idx.length < 8 + 256 * 4 || idx.readUInt32BE(0) !== 0xff744f63 || idx.readUInt32BE(4) !== 2) throw new Error(`${join(packDir, n)} is not a version-2 pack index`);
      const count = idx.readUInt32BE(8 + 255 * 4);
      const start = 8 + 256 * 4;
      if (idx.length < start + count * hashLen) throw new Error(`${join(packDir, n)} is truncated`);
      counts.listed += count;
      for (const id of unseenOfSorted(idx, start, count, seen(), hashLen)) out.set(id.toString("hex"), { dir, pack: base });
      packs[base] = [identOf(idxSt), identOf(pSt)];
    }
  }
  // Loose: the directory unchanged keeps the set of fan-out directories;
  // each unchanged fan-out keeps its ids.
  const loose: Record<string, Ident | null> = {};
  let fans: string[];
  if (old !== undefined && sameIdent(old.objects, identOf(objSt))) fans = Object.keys(old.loose);
  else {
    changed = true;
    try { fans = readdirSync(dir).filter((n) => /^[0-9a-f]{2}$/.test(n)); } catch { fans = []; }
  }
  for (const f of fans) {
    const st = statOrNull(join(dir, f));
    if (st === null || !st.isDirectory()) { if (old?.loose[f] !== undefined) changed = true; continue; }
    const prev = old?.loose[f];
    if (prev !== undefined && prev !== null && sameIdent(prev, identOf(st))) { loose[f] = prev; continue; }
    changed = true;
    let names: string[] = [];
    try { names = readdirSync(join(dir, f)); } catch { names = []; }
    const key = Buffer.alloc(hashLen);
    for (const n of names) {
      if (n.length !== hex - 2 || !HEX.test(n)) continue;
      counts.listed++;
      key.write(f + n, 0, "hex");
      if (!hasId(seen(), hashLen, key) && !out.has(f + n)) out.set(f + n, { dir, loose: f });
    }
    loose[f] = keep(st);
  }
  return { print: { dir, objects: keep(objSt), pack: keep(packSt), packs, loose }, changed };
}

/** Is every directory of `prints` unchanged since it was listed (the
 *  steady state: a stat of each directory, its `pack/` and each fan-out
 *  directory, nothing read)? */
export function storeUnchanged(dirs: readonly string[], prints: readonly DirPrint[]): boolean {
  if (dirs.length !== prints.length) return false;
  for (let i = 0; i < dirs.length; i++) {
    const p = prints[i]!;
    if (p.dir !== dirs[i]) return false;
    if (p.objects === null || p.pack === null) return false;
    const o = statOrNull(p.dir);
    if (o === null || !sameIdent(p.objects, identOf(o))) return false;
    const k = statOrNull(join(p.dir, "pack"));
    if (k === null || !sameIdent(p.pack, identOf(k))) return false;
    for (const [f, id] of Object.entries(p.loose)) {
      if (id === null) return false;
      const s = statOrNull(join(p.dir, f));
      if (s === null || !sameIdent(id, identOf(s))) return false;
    }
  }
  return true;
}

/** Ask git in batches, at most `limit` calls at once. */
async function batched<T>(items: readonly T[], size: (t: T) => number, cap: number, limit: number, fn: (chunk: T[]) => Promise<void>): Promise<void> {
  const chunks: T[][] = [];
  let cur: T[] = [];
  let n = 0;
  for (const it of items) {
    const s = size(it);
    if (cur.length > 0 && n + s > cap) { chunks.push(cur); cur = []; n = 0; }
    cur.push(it);
    n += s;
  }
  if (cur.length > 0) chunks.push(cur);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < chunks.length) await fn(chunks[next++]!);
  };
  await Promise.all(Array.from({ length: Math.min(limit, chunks.length) }, worker));
}

const IDS_PER_CALL = 20_000;
const BYTES_PER_CALL = 8 * 1024 * 1024;
const CALLS_AT_ONCE = 4;

/** Every index file of the store (each work tree's `index`, a split index's
 *  `sharedindex.*`), with its identity. Fail-closed: a directory that cannot
 *  be listed throws. */
export function storeIndexFiles(commonDir: string): Array<[string, Ident]> {
  const out: Array<[string, Ident]> = [];
  const look = (dir: string): void => {
    let names: string[];
    try { names = readdirSync(dir); } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return;
      throw e;
    }
    for (const n of names.sort()) {
      if (n !== "index" && !n.startsWith("sharedindex.")) continue;
      const st = statOrNull(join(dir, n));
      if (st !== null && st.isFile()) out.push([join(dir, n), identOf(st)]);
    }
  };
  look(commonDir);
  let wts: string[] = [];
  try { wts = readdirSync(join(commonDir, "worktrees")); } catch { wts = []; }
  for (const w of wts.sort()) look(join(commonDir, "worktrees", w));
  return out;
}


/**
 * The first half of one store's scan (the module comment): list what is new,
 * ask git about it, record its pairs and answer the protected ones for
 * `pred`. Never more than the store holds; throws (fail closed) on a git or
 * filesystem failure; a store over the cap answers `overCap`.
 */
export async function scanStore(opts: StoreScanOpts, pred: ScanPredicate): Promise<StoreScan> {
  const { git, cwd, commonDir, hashLen } = opts;
  const hex = hashLen * 2;
  const w = recordWidth(hashLen);
  const stats = opts.stats ?? newStoreScanStats();
  const now = (opts.now ?? Date.now)();
  const dir = opts.stateRoot === undefined ? undefined : storeScanDir(opts.stateRoot, commonDir);
  const stateFile = dir === undefined ? undefined : join(dir, "state.json");
  const sealKey = dir === undefined ? "" : dir.slice(dir.lastIndexOf("/") + 1);
  const pace = new Pacer(16);
  let lapAt = performance.now();
  const lap = (name: string): void => { const t = performance.now(); stats.ms[name] = (stats.ms[name] ?? 0) + Math.round(t - lapAt); lapAt = t; };

  // The kept state, used only when sealed in the current epoch.
  let state: ScanState | null = null;
  if (stateFile !== undefined && opts.sealing !== undefined) {
    const raw = readFileNoFollow(stateFile, STATE_MAX_BYTES);
    const parsed = raw === null ? null : parseScanState(raw.toString("utf8"), commonDir);
    lap("read");
    if (parsed !== null && parsed.hashLen === hashLen && await opts.sealing.verifyBytes(SEAL_KIND_STORE_SCAN, sealKey, raw!)) state = parsed;
    lap("verify");
  }

  const call = async (args: string[], input: string, binary: boolean): Promise<string> => {
    stats.gitCalls++;
    const r = await git(args, { cwd, input, ...(binary ? { binary: true } : {}) });
    if (r.code !== 0) throw new Error(`git ${args.slice(0, 2).join(" ")} failed: ${r.stderr.trim().split("\n").slice(-1)[0] ?? `exit ${r.code}`}`);
    return r.stdout;
  };
  // Ids git could not answer (gone, or unreadable now): never taken as
  // seen, and where they were listed is listed again next time.
  const missing = new Set<string>();
  const typesOf = async (ids: readonly string[]): Promise<ObjectInfo[]> => {
    const found: ObjectInfo[] = [];
    await batched(ids, () => 1, IDS_PER_CALL, CALLS_AT_ONCE, async (chunk) => {
      const out = await call(["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"], `${chunk.join("\n")}\n`, false);
      const got = parseBatchCheck(out, hex);
      found.push(...got.found);
      for (const m of got.missing) missing.add(m);
    });
    return found;
  };
  const readBodies = async (items: ReadonlyArray<{ oid: string; size: number }>): Promise<Map<string, { type: string; body: Buffer }>> => {
    const got = new Map<string, { type: string; body: Buffer }>();
    await batched(items, (i) => i.size + 64, BYTES_PER_CALL, CALLS_AT_ONCE, async (chunk) => {
      const out = await call(["cat-file", "--batch"], `${chunk.map((c) => c.oid).join("\n")}\n`, true);
      const parsed = parseBatch(Buffer.from(out, "latin1"), hex);
      for (const o of parsed.objects) got.set(o.oid, { type: o.type, body: o.body });
      for (const c of chunk) if (!got.has(c.oid)) missing.add(c.oid);
    });
    stats.read += got.size;
    return got;
  };

  // The steady state: every directory unchanged, this set of protected
  // paths answered before. Nothing is read, git is asked nothing.
  const dirsNow = [...opts.dirs];
  if (state !== null && storeUnchanged(dirsNow, state.dirs)) {
    const answer = state.answers.find((a) => a.key === pred.key);
    if (answer !== undefined) {
      stats.unchanged++;
      lap("steady");
      const st = state;
      return { overCap: null, pairs: answer.pairs.map(([o, p]) => [o, p]), finish: (k, wf) => finishScan(st, st, null, k, wf) };
    }
  }

  // Something changed (or nothing is kept): the kept data, when it is what
  // the sealed state names; else a scan from nothing.
  let seenBuf: Buffer = Buffer.alloc(0);
  let pairs0: Buffer = Buffer.alloc(0);
  let paths0: string[] = [""];
  if (state !== null && dir !== undefined) {
    const seen = readKept(join(dir, `seen-${state.gen}.bin`), state.files.seen);
    const pairs = readKept(join(dir, `pairs-${state.gen}.bin`), state.files.pairs);
    const paths = readKept(join(dir, `paths-${state.gen}.bin`), state.files.paths);
    if (seen !== null && pairs !== null && paths !== null && seen.length % hashLen === 0 && pairs.length % w === 0) {
      seenBuf = seen;
      pairs0 = pairs;
      paths0 = paths.length === 0 ? [""] : paths.toString("utf8").split("\0");
    } else {
      state = null;
    }
  }
  const prior = state;
  const wasFirst = prior === null;
  const fresh = new Map<string, FreshSource>();
  const counts = { listed: 0 };
  const prints: DirPrint[] = [];
  let changed = false;
  for (const d of dirsNow) {
    const old = prior?.dirs.find((p) => p.dir === d);
    const r = listObjectDir(d, old, hashLen, () => seenBuf, now, fresh, counts);
    prints.push(r.print);
    if (r.changed) changed = true;
    const t = pace.tick();
    if (t !== null) await t;
  }
  stats.listed += counts.listed;
  lap("list");
  const seenCount = seenBuf.length / hashLen;
  if (seenCount + fresh.size > (opts.maxObjects ?? STORE_SCAN_MAX_OBJECTS)) {
    stats.overCap++;
    return { overCap: seenCount + fresh.size, pairs: [], finish: async () => [] };
  }
  if (wasFirst) stats.first++;
  else if (changed || fresh.size > 0) stats.incremental++;
  if (wasFirst && fresh.size >= FIRST_SCAN_NOTICE_OBJECTS) opts.onFirstScan?.();


  // 1. The new ids' types (an id git no longer has is not taken: listed
  // again, and asked again, next time). A loose object is read here (its
  // header, and its body unless a blob): a commit writes loose objects, so
  // a launch after one asks git nothing. Anything this cannot read is asked
  // of git, which answers as it would to the agent.
  const freshList = [...fresh.keys()].sort();
  const infos: ObjectInfo[] = [];
  const preloaded = new Map<string, Buffer>();
  const viaGit: string[] = [];
  for (const h of freshList) {
    const src = fresh.get(h);
    const lo = src?.loose === undefined ? null : readLooseObject(src.dir, h, (t) => t !== "blob");
    if (lo === null) { viaGit.push(h); continue; }
    infos.push({ oid: h, type: lo.type, size: lo.size });
    if (lo.body !== null) preloaded.set(h, lo.body);
    const t = pace.tick();
    if (t !== null) await t;
  }
  if (viaGit.length > 0) infos.push(...await typesOf(viaGit));
  stats.asked += viaGit.length;
  stats.loose += freshList.length - viaGit.length;
  const newBlobs: ObjectInfo[] = [];
  for (const i of infos) if (i.type === "blob") newBlobs.push(i);
  lap("types");
  // 2. The new commits and tags: the trees they name are roots. When the
  // new trees are few, they are read in the same call.
  const treeSize = new Map<string, number>();
  const newTrees = new Set<string>();
  const heads: ObjectInfo[] = [];
  let treeBytes = 0;
  for (const i of infos) {
    if (i.type === "tree") { newTrees.add(i.oid); treeSize.set(i.oid, i.size); if (!preloaded.has(i.oid)) treeBytes += i.size; }
    else if (i.type === "commit" || i.type === "tag") heads.push(i);
  }
  const ask = heads.filter((h) => !preloaded.has(h.oid));
  if (treeBytes <= BYTES_PER_CALL) for (const i of infos) if (i.type === "tree" && !preloaded.has(i.oid)) ask.push(i);
  if (ask.length > 0) for (const [oid, o] of await readBodies(ask)) preloaded.set(oid, o.body);
  const roots = new Set<string>();
  for (const h of heads) {
    const body = preloaded.get(h.oid);
    if (body === undefined) continue;
    if (h.type === "commit") { const t = commitTree(body, hex); if (t !== null) roots.add(t); }
    else { const t = tagTarget(body, hex); if (t !== null && t.type === "tree") roots.add(t.object); }
    preloaded.delete(h.oid);
  }

  lap("heads");
  // 3. Paths. Trees are read in rounds, one level at a time and a bounded
  // batch at a time (never the whole store in memory, the next batch read
  // while this one is walked): first from every root, then from every new
  // tree no root reached and no other such tree names (a top). Object ids,
  // names and places are small integers looked up from the bytes.
  const paths = new PathTable(paths0);
  const oids = new ByteIds(true);
  const P = 2097152; // > MAX_PATHS * 2
  const newTreeIds = new Set<number>();
  const sizeOf = new Map<number, number>();
  for (const t of newTrees) {
    const raw = Buffer.from(t, "hex");
    const id = oids.idOf(raw, 0, hashLen);
    newTreeIds.add(id);
    sizeOf.set(id, treeSize.get(t)!);
  }
  const visitedTree = new Set<number>();
  const blobSeen = new Set<number>();
  const reached = new Set<number>();
  let recs = Buffer.alloc(1024 * w);
  let nrecs = 0;
  const addRec = (src: Buffer, at: number, meta: number): void => {
    if ((nrecs + 1) * w > recs.length) { const g = Buffer.alloc(recs.length * 2); recs.copy(g, 0, 0, nrecs * w); recs = g; }
    src.copy(recs, nrecs * w, at, at + hashLen);
    recs.writeUInt32BE(meta >>> 0, nrecs * w + hashLen);
    nrecs++;
  };
  const metaOf = (place: number, tree: boolean, top: number): number => ((top !== 0 ? META_TOP : 0) | (tree ? META_TREE : 0) | place) >>> 0;
  const keptHas = (raw: Buffer, at: number, meta: number): boolean => {
    if (pairs0.length === 0) return false;
    for (let i = lowerBound(pairs0, w, raw, at, hashLen); i * w < pairs0.length; i++) {
      if (cmpBytes(pairs0, i * w, raw, at, hashLen) !== 0) return false;
      if (pairs0.readUInt32BE(i * w + hashLen) === meta) return true;
    }
    return false;
  };
  /** Bodies of `ids` (trees), in batches of about BYTES_PER_CALL *
   *  CALLS_AT_ONCE bytes, the next batch asked while `each` walks this one. */
  const eachBody = async (ids: readonly number[], each: (id: number, body: Buffer) => Promise<void>): Promise<void> => {
    const batches: number[][] = [];
    let cur: number[] = [];
    let bytes = 0;
    const rest: number[] = [];
    for (const id of ids) {
      const body = preloaded.get(oids.hex(id));
      if (body !== undefined) await each(id, body);
      else rest.push(id);
    }
    for (const id of rest) {
      const s = sizeOf.get(id) ?? 4096;
      if (cur.length > 0 && bytes + s > BYTES_PER_CALL * CALLS_AT_ONCE) { batches.push(cur); cur = []; bytes = 0; }
      cur.push(id);
      bytes += s;
    }
    if (cur.length > 0) batches.push(cur);
    const ask = (b: number[]): Promise<Map<string, { type: string; body: Buffer }>> =>
      readBodies(b.map((id) => ({ oid: oids.hex(id), size: sizeOf.get(id) ?? 4096 })));
    let pending = batches.length > 0 ? ask(batches[0]!) : null;
    for (let i = 0; i < batches.length; i++) {
      const got = await pending!;
      pending = i + 1 < batches.length ? ask(batches[i + 1]!) : null;
      pending?.catch(() => undefined);
      for (const id of batches[i]!) {
        const o = got.get(oids.hex(id));
        if (o !== undefined && o.type === "tree") await each(id, o.body);
      }
    }
  };
  /** Walk from `start` (triples: object id, place, top 0/1). */
  const walk = async (start: number[]): Promise<void> => {
    let items = start;
    for (let round = 0; items.length > 0; round++) {
      if (round > 4096) throw new Error("trees nested deeper than the scan follows");
      // The places to read this round, by tree.
      const need = new Map<number, number[]>();
      for (let j = 0; j < items.length; j += 3) {
        const oid = items[j]!;
        const place = items[j + 1]!;
        const top = items[j + 2]!;
        const k = oid * P + place * 2 + top;
        if (visitedTree.has(k)) continue;
        visitedTree.add(k);
        const meta = metaOf(place, true, top);
        const at = oids.offset(oid);
        const known = keptHas(oids.buf(), at, meta);
        if (newTreeIds.has(oid)) reached.add(oid);
        // An old tree is read again only at a place it was never seen at (a
        // folder renamed, a tree reused); one git does not have, never.
        else if (known || !hasId(seenBuf, hashLen, oids.buf(), at)) continue;
        if (!known) addRec(oids.buf(), oids.offset(oid), meta);
        let l = need.get(oid);
        if (l === undefined) { l = []; need.set(oid, l); }
        l.push(place * 2 + top);
      }
      if (need.size === 0) break;
      const next: number[] = [];
      // Old trees' sizes are unknown here: asked with their bodies.
      await eachBody([...need.keys()], async (id, body) => {
        for (const pt of need.get(id)!) {
          const place = pt >>> 1;
          const top = pt & 1;
          try {
            forEachEntry(body, hashLen, (kind, ns, ne, at) => {
              if (kind === ENTRY_OTHER) return;
              const child = paths.child(place, body, ns, ne);
              const cid = oids.idOf(body, at, at + hashLen);
              const k = cid * P + child * 2 + top;
              if (kind === ENTRY_TREE) { if (!visitedTree.has(k)) next.push(cid, child, top); return; }
              if (blobSeen.has(k)) return;
              blobSeen.add(k);
              const bm = metaOf(child, false, top);
              if (!keptHas(body, at, bm)) addRec(body, at, bm);
            });
          } catch (e) {
            if (e instanceof StoreScanOverCap) throw e;
            throw new Error(`tree ${oids.hex(id)}: ${(e as Error).message}`);
          }
          const t = pace.tick();
          if (t !== null) await t;
        }
      });
      items = next;
    }
  };
  const rootItems: number[] = [];
  for (const r of roots) rootItems.push(oids.idOf(Buffer.from(r, "hex"), 0, hashLen), 0, 0);
  await walk(rootItems);
  lap("roots");
  // The new trees no root reached: those none of them names are tops.
  const unreached = [...newTreeIds].filter((t) => !reached.has(t));
  if (unreached.length > 0) {
    const named = new Set<number>();
    await eachBody(unreached, async (id, body) => {
      try {
        forEachEntry(body, hashLen, (kind, _s, _e, at) => { if (kind === ENTRY_TREE) named.add(oids.idOf(body, at, at + hashLen)); });
      } catch (e) { throw new Error(`tree ${oids.hex(id)}: ${(e as Error).message}`); }
    });
    const tops: number[] = [];
    for (const t of unreached) if (!named.has(t)) tops.push(t, 0, 1);
    await walk(tops);
  }
  visitedTree.clear();
  blobSeen.clear();

  lap("tops");
  // 4. The new data.
  const newPairs = nrecs === 0 ? Buffer.alloc(0) : sortRecords(recs.subarray(0, nrecs * w), w);
  recs = Buffer.alloc(0);
  const allPairs = newPairs.length === 0 ? pairs0 : mergeSorted(pairs0, newPairs, w);
  // What git could not answer is not seen; where it was listed is not
  // trusted unchanged (its pack, its fan-out directory, its pack directory).
  for (const m of missing) {
    const src = fresh.get(m);
    const pr = src === undefined ? undefined : prints.find((x) => x.dir === src.dir);
    if (src === undefined || pr === undefined) continue;
    if (src.pack !== undefined) { delete pr.packs[src.pack]; pr.pack = null; }
    if (src.loose !== undefined) { pr.loose[src.loose] = null; pr.objects = null; }
  }
  fresh.clear();
  const answered = infos.filter((i) => !missing.has(i.oid)).map((i) => Buffer.from(i.oid, "hex"));
  const allSeen = answered.length === 0 ? seenBuf : mergeSorted(seenBuf, sortedIdBuffer(answered, hashLen), hashLen);
  // A blob some record names has a path (or a place in a top).
  const blobNamed = (oidHex: string): boolean => {
    const raw = Buffer.from(oidHex, "hex");
    for (let i = lowerBound(allPairs, w, raw, 0, hashLen); i * w < allPairs.length; i++) {
      if (cmpBytes(allPairs, i * w, raw, 0, hashLen) !== 0) return false;
      if ((allPairs.readUInt32BE(i * w + hashLen) & META_TREE) === 0) return true;
    }
    return false;
  };

  lap("merge");
  // 5. This predicate's answer: the old answer plus the new records' when
  // the set of protected paths is the same, else every record evaluated.
  const evalRecords = async (recs: Buffer): Promise<Array<[string, string]>> => {
    const memo = new Map<number, string | null>();
    const out = new Map<string, [string, string]>();
    for (let i = 0; i < recs.length; i += w) {
      const meta = recs.readUInt32BE(i + hashLen);
      if ((meta & META_TREE) !== 0) continue;
      let place = memo.get(meta);
      if (place === undefined) {
        const rel = paths.paths[meta & META_PATH];
        place = rel === undefined || rel === "" ? null : (meta & META_TOP) !== 0 ? topPlace(rel, pred) : pred.isProtected(rel) ? rel : null;
        memo.set(meta, place);
      }
      if (place !== null) {
        const oid = recs.toString("hex", i, i + hashLen);
        out.set(`${oid}\0${place}`, [oid, place]);
      }
      if ((i & 0x3fff) === 0) { const t = pace.tick(); if (t !== null) await t; }
    }
    return [...out.values()];
  };
  const before = prior?.answers.find((a) => a.key === pred.key);
  let answer: Array<[string, string]>;
  if (before !== undefined) {
    const m = new Map(before.pairs.map(([o, p]) => [`${o}\0${p}`, [o, p] as [string, string]]));
    for (const p of await evalRecords(newPairs)) m.set(`${p[0]}\0${p[1]}`, p);
    answer = [...m.values()];
  } else {
    stats.reevaluated++;
    answer = await evalRecords(allPairs);
  }
  lap("answer");
  answer.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  const answers = [{ key: pred.key, pairs: answer }];
  // Another set's answer stays right only while no record was added.
  if (newPairs.length === 0 && prior !== null) for (const a of prior.answers) if (a.key !== pred.key && answers.length < MAX_ANSWERS) answers.push(a);
  // The blobs no record names: new ones join the token rule's candidates;
  // a candidate a record now names has a path to be decided by (all but
  // `m`, hidden for good).
  const candidates: Record<string, Candidate> = { ...(prior?.candidates ?? {}) };
  for (const [oid, c] of Object.entries(candidates)) if (c.s !== "m" && blobNamed(oid)) delete candidates[oid];
  for (const b of newBlobs) if (candidates[b.oid] === undefined && !blobNamed(b.oid)) candidates[b.oid] = { size: b.size, s: "u", d: "" };
  const next: ScanState = {
    v: 1, rule: STORE_SCAN_RULE, commonDir, hashLen,
    gen: prior?.gen ?? "0000000000000000",
    files: prior?.files ?? { seen: [0, 0, 0, 0, 0], pairs: [0, 0, 0, 0, 0], paths: [0, 0, 0, 0, 0] },
    dirs: prints, answers, candidates,
  };
  const data = wasFirst || newPairs.length > 0 || answered.length > 0 || paths.added > 0
    ? { seen: allSeen, pairs: allPairs, paths: paths.paths }
    : null;
  return { overCap: null, pairs: answer, finish: (k, wf) => finishScan(next, prior, data, k, wf) };

  /** The token rule, then the state kept (when anything changed). */
  async function finishScan(
    st: ScanState, was: ScanState | null, newData: { seen: Buffer; pairs: Buffer; paths: string[] } | null,
    known: ReadonlyArray<readonly [string, string]>, workingFiles: ReadonlyArray<readonly [string, string]>,
  ): Promise<Array<[string, string]>> {
    const cands = st.candidates;
    // The protected versions the tokens come from: every known one but the
    // candidates themselves (a hidden candidate is remembered as a version
    // of its path; its own tokens add nothing, and leaving it out keeps the
    // digest the same from one launch to the next).
    const knownAll = new Set(known.map(([n]) => n));
    const knownPath = new Map<string, string>();
    for (const [n, p] of known) if (!knownPath.has(n) && cands[n] === undefined) knownPath.set(n, p);
    const digest = createHash("sha256").update(JSON.stringify([[...knownPath.keys()].sort(), workingFiles.map(([, r]) => r).sort()])).digest("hex").slice(0, 32);
    let indexFiles: Array<[string, Ident]> | null = null;
    const indexNow = (): Array<[string, Ident]> => (indexFiles ??= storeIndexFiles(commonDir));
    const sameIndexes = (a: Array<[string, Ident]> | undefined): boolean => {
      const b = indexNow();
      return a !== undefined && a.length === b.length && a.every(([p, id], i) => p === b[i]![0] && sameIdent(id, b[i]![1]));
    };
    const toCheck = Object.entries(cands).filter(([oid, c]) =>
      !knownAll.has(oid) && ((c.s === "u" && c.d !== digest) || (c.s === "i" && !sameIndexes(c.idx))));
    let dirty = newData !== null || st !== was;
    if (toCheck.length > 0) {
      dirty = true;
      for (const [oid, c] of toCheck) if (c.size > CANDIDATE_MAX_BYTES) cands[oid] = { size: c.size, s: "x" };
      const small = toCheck.filter(([, c]) => c.size <= CANDIDATE_MAX_BYTES);
      if (small.length > 0) {
        // The protected versions' tokens: each version's body, and each
        // protected file's working copy.
        const tokenPath = new Map<string, string>();
        const addTokens = (text: string, path: string): void => { for (const t of credentialTokens(text)) if (!tokenPath.has(t)) tokenPath.set(t, path); };
        const kv = (await (knownPath.size === 0 ? Promise.resolve([]) : typesOf([...knownPath.keys()])))
          .filter((i) => i.type === "blob" && i.size <= CANDIDATE_MAX_BYTES);
        for (const [oid, o] of await readBodies(kv)) addTokens(o.body.toString("latin1"), knownPath.get(oid)!);
        for (const [abs, rel] of workingFiles) {
          const b = readFileNoFollow(abs, CANDIDATE_MAX_BYTES);
          if (b !== null) addTokens(b.toString("latin1"), rel);
        }
        const cb = await readBodies(small.map(([oid, c]) => ({ oid, size: c.size })));
        for (const [oid, c] of small) {
          const o = cb.get(oid);
          if (o === undefined) { delete cands[oid]; continue; } // gone from the store
          let hit: string | null = null;
          for (const t of credentialTokens(o.body.toString("latin1"))) {
            const p = tokenPath.get(t);
            if (p !== undefined) { hit = p; break; }
          }
          if (hit === null) { cands[oid] = { size: c.size, s: "u", d: digest }; continue; }
          // A staged file has its path in an index: not pathless.
          const raw = Buffer.from(oid, "hex");
          let staged = false;
          for (const [p] of indexNow()) {
            const b = readFileNoFollow(p, 1024 * 1024 * 1024);
            if (b === null) throw new Error(`could not read the index ${p}`);
            if (b.indexOf(raw) >= 0) { staged = true; break; }
          }
          cands[oid] = staged ? { size: c.size, s: "i", idx: indexNow() } : { size: c.size, s: "m", path: hit };
        }
      }
    }
    if (dirty && dir !== undefined && stateFile !== undefined) persist(st, newData);
    const out: Array<[string, string]> = [];
    for (const [oid, c] of Object.entries(cands)) if (c.s === "m" && c.path !== undefined && pred.isProtected(c.path)) out.push([oid, c.path]);
    return out;
  }

  /** Write the data files (a new generation) and the state, sealed. Best
   *  effort: a state not written scans again next launch. */
  function persist(st: ScanState, newData: { seen: Buffer; pairs: Buffer; paths: string[] } | null): void {
    try {
      mkdirSync(dir!, { recursive: true, mode: 0o700 });
      const out: ScanState = { ...st };
      if (newData !== null) {
        const gen = randomBytes(8).toString("hex");
        const write = (name: string, bytes: Buffer): Ident => {
          const p = join(dir!, `${name}-${gen}.bin`);
          writeFileSync(p, bytes, { mode: 0o600, flag: "wx" });
          return identOf(lstatSync(p));
        };
        out.gen = gen;
        out.files = {
          seen: write("seen", newData.seen),
          pairs: write("pairs", newData.pairs),
          paths: write("paths", Buffer.from(newData.paths.join("\0"), "utf8")),
        };
      }
      const text = JSON.stringify(out);
      const tmp = `${stateFile!}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
      writeFileSync(tmp, text, { mode: 0o600, flag: "wx" });
      renameSync(tmp, stateFile!);
      opts.sealing?.sealBytes(SEAL_KIND_STORE_SCAN, sealKey, Buffer.from(text, "utf8"));
      // Older generations go once a minute old (a launch beside this one
      // may still be writing its own).
      for (const n of readdirSync(dir!)) {
        const m = /^(?:seen|pairs|paths)-([0-9a-f]{16})\.bin$/.exec(n);
        if (m === null || m[1] === out.gen) continue;
        const s = statOrNull(join(dir!, n));
        if (s !== null && s.mtimeMs < Date.now() - 60_000) rmSync(join(dir!, n), { force: true });
      }
    } catch { /* best effort */ }
  }
}
