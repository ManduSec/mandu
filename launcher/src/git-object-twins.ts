/**
 * git-object-twins — keep a protected file's COMMITTED bytes out of the
 * agent's world (docs/design/confidentiality/confidentiality.md §7.2a; the residue
 * confidentiality-plan-11 §8 row 1 left open).
 *
 * The twin (secret-twins.ts) replaces a protected file where the agent opens
 * it. A file that is committed to git also lives in `.git/objects`, and
 * `git show` / `git diff` / `git log -p` (or any program reading the object
 * store) get its bytes without ever opening the file. Git objects cannot be
 * rewritten in place: an object's name is the hash of its content. So the
 * launcher TWINS THE OBJECT STORE FILES instead:
 *
 *   - every pack that holds a protected blob gets a SANITIZED twin: the same
 *     objects minus the protected blobs, repacked by `git pack-objects`
 *     (self-contained, never thin), with its own `.idx` and `.rev`. The real
 *     `.pack` / `.idx` / `.rev` are masked by those twins, exactly as a
 *     credential file is masked by its twin (the bind where there is one, the
 *     guard's descriptor otherwise);
 *   - what indexes the real pack by position (its `.bitmap`, a cruft pack's
 *     `.mtimes`, the directory's `multi-pack-index` and its `.bitmap` /
 *     `.rev`) and each protected blob stored LOOSE are made unreadable (git
 *     treats an unreadable midx or bitmap as absent);
 *
 * so git sees a repository in which the protected blobs are missing: `git
 * show HEAD:secret` fails with "bad object", every other object reads as
 * before, and new commits work. A protected blob is found by its path: every
 * version the file had in any ref, the reflog, the stash or the index, and the
 * working copy's own content hashed as `git add` would.
 *
 * Two more sources name protected blobs (confidentiality-plan-14 §8.1, §8.2):
 *
 *   - a path a HUMAN LABEL puts above `public` that the history holds, whether
 *     or not it exists in the work tree now (the deploy key committed and
 *     deleted, C17). The labels come from the arbiter (`gitHistoryLocks`);
 *     each path the walk sees is decided by the arbiter's own precedence rule
 *     (history-labels.ts, a pinned mirror), so a `public` carve-out stays
 *     readable;
 *   - a BLOB LOCK (policy.yaml `blobs:`, `lock-blob`): an object id, hidden in
 *     every repository whose object format it names (`sha1:` ids in SHA-1
 *     repositories, `sha256:` in SHA-256 ones). The key once inline in a file
 *     that is public now: the old version goes, the current file stays.
 *
 * And what no ref reaches: every object a store holds is checked once
 * (store-scan.ts, confidentiality.md §7.2a "Every stored object is checked
 * once"), beside the walks, so a protected version in history cut before
 * Mandu first walked it, in a tree no ref names, or in a blob written by
 * plumbing is hidden too; a launch with nothing new stats the store's
 * directories and asks git nothing.
 *
 * Sanitized packs are cached by (pack, excluded blobs) under the state base,
 * so a relaunch rebuilds nothing. A pack that cannot be sanitized refuses the
 * launch unless --best-effort (secret-setup.ts); rebuilding is capped
 * (MANDU_GIT_TWIN_MAX_MB, default 1024 MiB of packs per launch).
 *
 * A relaunch is also cheap on a large history (confidentiality.md §7.2a
 * "Cost on a relaunch"): the history walk that finds the protected versions
 * is cached per (repository, protected paths) and keyed by the tips it
 * started from, so an unchanged repository is not walked again and a changed
 * one walks only the new commits; the tips are read without `git rev-list
 * --reflog` (reflog-tips.ts: the reflog files once, never fewer tips than
 * git's); work trees of one object store share the tips, the walks and one
 * pack plan (RepoReads), and stores that share an object directory through
 * `objects/info/alternates` share one plan of it, its exclusions the union
 * of theirs (objectStoreClosure, clusterObjectStores: the wrap binds one
 * twin per path); the small git calls are batched and run at once, all
 * in ONE git sandbox for the launch (git-session.ts `GitSession`, the
 * launch's or the step's own: one bubblewrap, not one per call; the same
 * confinement, arguments, environment and failures, a dead sandbox failing
 * every call in flight; an empty /proc and Yama ptrace_scope >= 1 keep the
 * calls apart, else one sandbox per call); and a pack index is searched for the protected
 * names (its fanout table and a binary search), never read whole.
 *
 * Both caches are SEALED (confidentiality-plan-14 §11.2, cache-seals.ts):
 * an entry is used only when its bytes match a seal of the arbiter's
 * current epoch, which voids every seal when an unconfined period ends;
 * anything else is rebuilt and reported. The existing `.idx` check stays.
 *
 * The parsers and the planner are PURE and unit-tested; the git runner and
 * the filesystem are injected.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { createHash } from "node:crypto";
import {
  closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, realpathSync,
  renameSync, rmSync, statSync, utimesSync, writeFileSync, mkdtempSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { SEAL_KIND_HISTORY_WALK, SEAL_KIND_OBJECT_TWIN, SealSession, historyRecheckNotice, type CacheSealClient } from "./cache-seals.js";
import { FileHashes } from "./file-hashes.js";
import { writeLaunchHint } from "./launch-hint.js";
import type { RunningChild } from "./child-run.js";
import {
  ALTERNATES_MAX_DEPTH, ALTERNATES_MAX_STORES, AlternatesError, defaultAlternatesIo, objectStoreClosure as sharedObjectStoreClosure,
  type AlternatesIo,
} from "./git-alternates.js";
import { readReflogOids } from "./reflog-tips.js";
import { lockedMemoryFile, readLockedMemory, rememberLocked } from "./locked-memory.js";
import { addStoreScanStats, newStoreScanStats, scanStore, storeScanMaxFromEnv, StoreScanOverCap, topPrefixes, type StoreScan, type StoreScanStats } from "./store-scan.js";
import { GIT_RUNNER_MAX_STDOUT, isProductionGitRunner, openGitSession, perCallGitRunner, type GitSession } from "./git-session.js";
import { launchGitSandbox } from "./probe-cache.js";
import {
  compileHistoryLabels, HISTORY_WALK_ARGS, historyPathspecs, labelFilterKey, labelledAbovePublic, labelWalkKey, realSpellingOf,
  resolutionKey, walkBaseKey, walkShallowRule, withRealSpellings, type CompiledHistoryLabels, type HistoryLabel, type ShallowRule,
} from "./history-labels.js";

// The walk's keys moved to history-labels.ts (shared with the arbiter's
// resolver, plan 14 §11.1 R2); re-exported for the callers that import them here.
export { labelWalkKey, walkBaseKey };

// ── Pure: the pack index (.idx v2) ──────────────────────────────────────────

/** The object names a version-2 pack index lists, in index (sorted) order.
 *  `hashLen` is 20 for SHA-1 repositories, 32 for SHA-256. Throws on a file
 *  that is not a v2 index (the caller fails closed). Pure. */
export function idxObjectNames(buf: Buffer, hashLen = 20): string[] {
  if (buf.length < 8 + 256 * 4) throw new Error("pack index too small");
  if (buf.readUInt32BE(0) !== 0xff744f63 || buf.readUInt32BE(4) !== 2) {
    throw new Error("not a version-2 pack index");
  }
  const count = buf.readUInt32BE(8 + 255 * 4);
  const start = 8 + 256 * 4;
  if (buf.length < start + count * hashLen) throw new Error("pack index truncated");
  const out: string[] = new Array(count);
  for (let i = 0; i < count; i++) {
    out[i] = buf.subarray(start + i * hashLen, start + (i + 1) * hashLen).toString("hex");
  }
  return out;
}

/** Reads `len` bytes at `offset` (short at the end of the file). */
export type ByteReader = (offset: number, len: number) => Buffer;

/** Which of `names` a version-2 pack index lists (sorted, unique), found
 *  through its fanout table and a binary search, reading only the header and
 *  the name entries the search visits: a relaunch over a pack of millions of
 *  objects never reads its whole index (confidentiality.md §7.2a). Throws on
 *  a file that is not a v2 index (the caller fails closed). Pure given
 *  `read`. */
export function idxLookup(read: ByteReader, names: readonly string[], hashLen = 20): string[] {
  const head = read(0, 8 + 256 * 4);
  if (head.length < 8 + 256 * 4) throw new Error("pack index too small");
  if (head.readUInt32BE(0) !== 0xff744f63 || head.readUInt32BE(4) !== 2) {
    throw new Error("not a version-2 pack index");
  }
  const fan = (b: number) => (b < 0 ? 0 : head.readUInt32BE(8 + b * 4));
  const start = 8 + 256 * 4;
  const count = fan(255);
  if (count > 0 && read(start + (count - 1) * hashLen, hashLen).length < hashLen) throw new Error("pack index truncated");
  const found = new Set<string>();
  for (const name of names) {
    if (name.length !== hashLen * 2 || !/^[0-9a-f]+$/.test(name)) continue;
    const want = Buffer.from(name, "hex");
    let lo = fan(want[0]! - 1);
    let hi = fan(want[0]!);
    if (hi < lo || hi > count) throw new Error("pack index fanout is not monotonic");
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      const got = read(start + mid * hashLen, hashLen);
      if (got.length < hashLen) throw new Error("pack index truncated");
      const c = Buffer.compare(got, want);
      if (c === 0) { found.add(name); break; }
      if (c < 0) lo = mid + 1;
      else hi = mid;
    }
  }
  return [...found].sort();
}

/** idxLookup over a file, by positioned reads. */
export function idxLookupFile(path: string, names: readonly string[], hashLen = 20): string[] {
  const fd = openSync(path, "r");
  try {
    return idxLookup((offset, len) => {
      const buf = Buffer.alloc(len);
      const n = readSync(fd, buf, 0, len, offset);
      return buf.subarray(0, n);
    }, names, hashLen);
  } finally {
    closeSync(fd);
  }
}

// ── Pure: git output ────────────────────────────────────────────────────────

const ZERO = /^0+$/;
const HEX = /^[0-9a-f]{40}([0-9a-f]{24})?$/;

/** Blob names in `git log --raw -z --no-abbrev --format=` output: both sides
 *  of every change record, gitlinks (mode 160000) and the all-zero name of a
 *  missing side left out. Pure. */
export function parseRawLogBlobs(out: string): string[] {
  const found = new Set<string>();
  for (const tok of out.split("\0")) {
    const t = tok.replace(/^\n+/, "");
    if (!t.startsWith(":")) continue;
    const [srcMode, dstMode, src, dst] = t.slice(1).split(" ");
    if (src !== undefined && HEX.test(src) && !ZERO.test(src) && srcMode !== "160000") found.add(src);
    if (dst !== undefined && HEX.test(dst) && !ZERO.test(dst) && dstMode !== "160000") found.add(dst);
  }
  return [...found].sort();
}

/** Every (blob, path) pair of `git log --raw -z --no-abbrev --format=` output:
 *  both sides of every change record, with the path the record names (one
 *  path: the walk runs `--no-renames`). Gitlinks and the all-zero name of a
 *  missing side are left out. Pure. */
export function parseRawLogBlobPaths(out: string): Array<[string, string]> {
  const found: Array<[string, string]> = [];
  const toks = out.split("\0");
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!.replace(/^\n+/, "");
    if (!t.startsWith(":")) continue;
    const path = toks[i + 1];
    if (path === undefined) break;
    i++;
    const [srcMode, dstMode, src, dst] = t.slice(1).split(" ");
    if (src !== undefined && HEX.test(src) && !ZERO.test(src) && srcMode !== "160000") found.push([src, path]);
    if (dst !== undefined && HEX.test(dst) && !ZERO.test(dst) && dstMode !== "160000") found.push([dst, path]);
  }
  return found;
}

/** Every (blob, path) of `git ls-files -s -z` output (every stage). Pure. */
export function parseLsFilesStagePaths(out: string): Array<[string, string]> {
  const found: Array<[string, string]> = [];
  for (const rec of out.split("\0")) {
    const m = /^(\d{6}) ([0-9a-f]+) \d\t(.*)$/s.exec(rec);
    if (m && m[1] !== "160000" && HEX.test(m[2]!)) found.push([m[2]!, m[3]!]);
  }
  return found;
}

/** The locked blob ids (`sha1:…` / `sha256:…`) that apply to a repository of
 *  this object format (hash length 20 or 32), as bare names. Pure. */
export function lockedNamesFor(blobLocks: readonly string[], hashLen: number): string[] {
  const prefix = hashLen === 32 ? "sha256:" : "sha1:";
  const want = hashLen * 2;
  return [...new Set(blobLocks
    .filter((b) => b.startsWith(prefix))
    .map((b) => b.slice(prefix.length))
    .filter((n) => n.length === want && /^[0-9a-f]+$/.test(n)))].sort();
}

/** Blob names in `git ls-files -s -z` output (every stage). Pure. */
export function parseLsFilesStage(out: string): string[] {
  const found = new Set<string>();
  for (const rec of out.split("\0")) {
    const m = /^(\d{6}) ([0-9a-f]+) \d\t/.exec(rec);
    if (m && m[1] !== "160000" && HEX.test(m[2]!)) found.add(m[2]!);
  }
  return [...found].sort();
}

/** Blob names in `git hash-object` output, one per line. Pure. */
export function parseHashLines(out: string): string[] {
  return out.split("\n").map((l) => l.trim()).filter((l) => HEX.test(l));
}

/** The work tree a file sits in: the nearest ancestor holding `.git` (a
 *  directory, or the file a linked worktree or submodule has). null when
 *  none, or when the file is itself inside a `.git` directory. Pure given
 *  `exists`. */
export function repoRootOf(realPath: string, exists: (p: string) => boolean): string | null {
  if (realPath.split("/").includes(".git")) return null;
  let dir = dirname(realPath);
  for (;;) {
    if (exists(join(dir, ".git"))) return dir;
    const up = dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}

/** The work tree `p` is (a directory holding `.git`) or lies in; null when
 *  none. `p` need not exist (a labelled path gone from the work tree): its
 *  nearest existing folder decides. Pure given `exists`. */
export function repoRootAt(p: string, exists: (p: string) => boolean): string | null {
  if (p.split("/").includes(".git")) return null;
  if (exists(join(p, ".git"))) return p;
  return repoRootOf(p, exists);
}

/** Group protected files by the work tree holding them: root → paths
 *  relative to it (sorted, unique). Pure given `exists`. */
export function groupByRepo(realPaths: readonly string[], exists: (p: string) => boolean): Map<string, string[]> {
  const out = new Map<string, Set<string>>();
  for (const p of realPaths) {
    const root = repoRootOf(p, exists);
    if (root === null) continue;
    const rel = relative(root, p);
    if (rel === "" || rel.startsWith("..")) continue;
    const s = out.get(root) ?? new Set<string>();
    s.add(rel);
    out.set(root, s);
  }
  return new Map([...out].map(([k, v]) => [k, [...v].sort()]));
}

// ── Pure: the plan ──────────────────────────────────────────────────────────

/** One pack in an object directory, as the inventory saw it. */
export interface PackInventory {
  /** `<objects>/pack/pack-<hash>` (no extension). */
  base: string;
  /** The protected names its `.idx` lists (idxLookup; the full list is read
   *  only to rebuild the pack). */
  held: readonly string[];
  /** Which companion files exist. */
  hasRev: boolean;
  hasBitmap: boolean;
  hasMtimes: boolean;
  size: number;
}

/** One object directory (the repository's own, or an alternate). */
export interface ObjectDirInventory {
  dir: string;
  packs: readonly PackInventory[];
  /** The protected blobs stored loose here, as their paths. */
  looseProtected: readonly string[];
  /** multi-pack-index files present in `<dir>/pack` (full paths). */
  midx: readonly string[];
  /** `<dir>/pack/multi-pack-index.d` exists (incremental midx: unsupported). */
  incrementalMidx: boolean;
}

export interface PackRebuild {
  pack: PackInventory;
  /** The protected blobs this pack holds (sorted). */
  exclude: string[];
  /** The cache key: sha256 of the pack's name and the excluded names. */
  key: string;
}

export interface ObjectTwinPlan {
  rebuild: PackRebuild[];
  /** Real paths to make unreadable. */
  deny: string[];
  /** Layouts the planner cannot sanitize (the caller fails closed). */
  unsupported: string[];
}

/** The cache key of a sanitized pack. Pure. */
export function rebuildKey(packBase: string, exclude: readonly string[]): string {
  const name = packBase.slice(packBase.lastIndexOf("/") + 1);
  return createHash("sha256").update(`${name}\n${[...exclude].sort().join("\n")}`).digest("hex").slice(0, 32);
}

/** Which packs to sanitize and which files to deny, for one repository's
 *  object directories and its protected blob names. Pure. */
export function planObjectTwins(dirs: readonly ObjectDirInventory[], protectedBlobs: readonly string[]): ObjectTwinPlan {
  const want = new Set(protectedBlobs);
  const rebuild: PackRebuild[] = [];
  const deny: string[] = [];
  const unsupported: string[] = [];
  if (want.size === 0) return { rebuild, deny, unsupported };
  for (const d of dirs) {
    let touched = false;
    for (const p of d.packs) {
      const exclude = p.held.filter((o) => want.has(o));
      if (exclude.length === 0) continue;
      touched = true;
      exclude.sort();
      rebuild.push({ pack: p, exclude, key: rebuildKey(p.base, exclude) });
      if (p.hasBitmap) deny.push(`${p.base}.bitmap`);
      if (p.hasMtimes) deny.push(`${p.base}.mtimes`);
    }
    for (const l of d.looseProtected) deny.push(l);
    if (touched) {
      for (const m of d.midx) deny.push(m);
      if (d.incrementalMidx) unsupported.push(`${d.dir}/pack/multi-pack-index.d (an incremental multi-pack-index)`);
    }
  }
  return { rebuild, deny: [...new Set(deny)].sort(), unsupported };
}

// ── The twins the secret setup consumes ─────────────────────────────────────

/** One object-store file masked for the agent. `object`: served the sanitized
 *  twin; `deny`: unreadable. */
export interface ObjectTwin {
  targetPath: string;
  twinPath: string;
  kind: "object" | "deny";
}

export interface GitObjectTwinResult {
  twins: ObjectTwin[];
  /** Repositories holding a protected file's committed bytes. */
  repos: number;
  /** Protected blob names found across them. */
  blobs: number;
  packsRebuilt: number;
  cacheHits: number;
  /** How the history walks were served. */
  walks: WalkStats;
  /** How the object stores were scanned (store-scan.ts). */
  scans?: StoreScanStats;
  /** With `resolved`: how many repositories' label walks the arbiter's
   *  resolution stood in for (an equal key). */
  fromArbiter?: number;
  /** Every protected version the walks resolved and every blob lock that
   *  applied, as locked ids (`sha1:<hex>` / `sha256:<hex>`, sorted): the
   *  guard's backstop looks them up in every other repository's packs
   *  (confidentiality-plan-14 §11.1 R4). A repository that turned out to
   *  need no twin still contributes its ids. */
  lockedIds?: string[];
  /** With `continueOnFailure`: the repositories whose history could not be
   *  hidden, each with why. Always empty otherwise (a failure throws). */
  failed?: Array<{ root: string; reason: string }>;
  /** Every repository this launch prepared itself (twinned or not): the
   *  prepared copies (preparedCopyTwins) leave them alone. */
  roots?: string[];
  /** Each work tree's index file, from the facts this step read at this
   *  launch (RepoFacts `index`); a work tree it did not read is absent. */
  indexPaths?: Record<string, string>;
}

/** A pack that could not be sanitized, a timeout, a cap: the caller refuses
 *  the launch unless --best-effort (the raw committed bytes would stay
 *  readable). */
export class GitObjectTwinError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GitObjectTwinError";
  }
}

export interface GitRun {
  code: number;
  stdout: string;
  stderr: string;
}

export type GitRunner = (
  args: string[],
  opts: {
    cwd: string; input?: string; timeoutMs?: number; env?: Record<string, string>;
    /** Directories the call writes (the pack cache): read-write in the git
     *  sandbox, which is read-only everywhere else. */
    writable?: readonly string[];
    /** stdout decoded byte for byte (latin1, one character per byte)
     *  instead of as UTF-8: an answer that is binary (`cat-file --batch` of
     *  trees, store-scan.ts). */
    binary?: boolean;
  },
) => Promise<GitRun>;

/** Collected stdout over this many characters fails a call of the
 *  production runner (never a silently truncated answer). */
export { GIT_RUNNER_MAX_STDOUT };

/** The production runner, one sandbox per call: `git` from PATH, HARDENED
 *  (hardened-git.ts, docs/design/architecture/write-protection.md §8). The
 *  agent can write a workspace's `.git/config` and attributes, so no program
 *  a repository names is started: the forced config, the scrubbed
 *  environment, and no command this module runs applies a filter, diff or
 *  merge driver (the working copies are hashed by `worktreeBlobNames`).
 *  Where one can be made (bubblewrap on Linux, Seatbelt on macOS), git runs
 *  in the git sandbox: no network, the filesystem read-only but for
 *  `writable` (on macOS in both spellings, and no program but git can
 *  start). Literal pathspecs, unquoted paths, no optional locks.
 *
 *  Run by `runChild` (child-run.ts, write-protection.md §8.5.1): the call is a
 *  process group of its own and its deadline kills the whole group, so a
 *  deadline landing in the sandbox's start-up leaves no sandbox child behind
 *  and the call always settles (a failure, code 1).
 *
 *  The launch's own reads (prepareGitObjectTwins, the prefetch, the
 *  placeholder watch) run in ONE sandbox instead (git-session.ts
 *  `GitSession`, write-protection.md §8.5.3): the same git, flags,
 *  arguments, environment and failures, one bubblewrap for all. */
export const defaultGitRunner: GitRunner = perCallGitRunner();

/** The production runner, its calls tracked in `children` while they run
 *  (so an owner can kill them: twin-prefetch.ts `close`). */
export function trackedGitRunner(children: Set<RunningChild>): GitRunner {
  return perCallGitRunner(children);
}

export interface GitObjectTwinOpts {
  /** Where sanitized packs are cached (the path table's `object-twins`). */
  cacheDir: string;
  /** The deny source: an empty mode-000 file the caller created. */
  denyFile: string;
  /** Cap on the bytes of packs rebuilt THIS launch (cache misses). */
  maxRebuildBytes?: number;
  /** Where each repository's history walk is cached (WalkCacheEntry). It
   *  must be a directory the agent cannot write: an entry with a version
   *  left out would leave that version readable on the next launch. The
   *  launcher uses the path table's `object-walks` (under `state-root`), which write-protect
   *  denies. Unset: every launch walks every history. */
  walkCacheDir?: string;
  git?: GitRunner;
  /** The git session the step's calls run in (git-session.ts; the launch
   *  opens it at its start and closes it after the step). Unset (and no
   *  `git`): the step opens its own and closes it when it ends. */
  gitSession?: GitSession;
  exists?: (p: string) => boolean;
  log?: (m: string) => void;
  /** Plan 14 §8.1: the human labels, every level (`gitHistoryLocks`). A
   *  path any repository's history holds that they put above `public` is
   *  protected, whether it exists in the work tree or not. */
  labels?: readonly HistoryLabel[];
  /** Plan 14 §8.2: the locked blob ids (`sha1:<hex>` / `sha256:<hex>`),
   *  hidden in every repository of the matching object format. */
  blobLocks?: readonly string[];
  /** Plan 14 §11.1 R2/R3: the GLOBAL LOCKED SET (`gitHistoryLocks`
   *  `lockedSet`, as the guard gets it: the empty blob out), hidden like a
   *  blob lock in every repository this launch prepares. So a sanitized
   *  pack excludes every id the guard's backstop refuses (a twin is served
   *  before the backstop runs), and its cache key is the one the arbiter's
   *  prepared copy of the same pack has. */
  globalLocked?: readonly string[];
  /** Directories whose repositories the labels and blob locks apply to even
   *  when no protected file lies in them (the workspace). A repository that
   *  holds a labelled path (it or its folder exists) is found by itself. */
  repoHints?: readonly string[];
  /** Real path of an existing path, or null (default: realpathSync). */
  realpath?: (p: string) => string | null;
  /** Keep going past a repository that cannot be sanitized: it is listed in
   *  `failed` and gets no twin, every other repository keeps its own (the
   *  caller's --best-effort). Default: the first failure throws. */
  continueOnFailure?: boolean;
  /** Plan 14 §11.2: the arbiter's seals (its human-plane `cacheSeals` and
   *  `sealCacheEntries`). A cached pack or walk is used only when its bytes
   *  match a seal of the current epoch. Unset: no cache is trusted (every
   *  launch walks and rebuilds). */
  seals?: CacheSealClient;
  /** Plan 14 §11.1 R2: the repositories the arbiter already resolved
   *  (`gitHistoryLocks` `repos`), by real work-tree root. A repository's
   *  label walk is skipped when its resolution key equals the one this
   *  launch computes; otherwise (stale, other labels, absent) it walks. */
  resolved?: ReadonlyMap<string, ArbiterResolution>;
  /** How `objects/info/alternates` files are read (default:
   *  defaultAlternatesIo). A test knob. */
  alternatesIo?: AlternatesIo;
  /** The launch's file hashes for the seal check (file-hashes.ts), shared
   *  with the caller, who closes them. Unset: this call's own (on worker
   *  threads), closed at its end. */
  hashes?: FileHashes;
  /** History states computed at launch start (twin-prefetch.ts), each
   *  used only for the same work trees and unchanged inputs. */
  statePrefetch?: StatePrefetch;
  /** A store holding more objects is not scanned (store-scan.ts; default
   *  MANDU_GIT_STORE_SCAN_MAX_OBJECTS, else STORE_SCAN_MAX_OBJECTS). */
  maxScanObjects?: number;
  /** Where to leave the hint the next launch's prefetch starts from
   *  (twin-prefetch.ts `writeLaunchHint`). Unset: none is written. */
  hintFile?: string;
}

/** A source of history states computed ahead (twin-prefetch.ts): the state
 *  of exactly these work trees (sorted), or null to compute it as usual.
 *  `reads` is the launch's own (its facts and config are the fresh ones the
 *  answer is checked against). Never throws. */
export interface StatePrefetch {
  take(roots: readonly string[], reads: RepoReads): Promise<HistoryState | null>;
}

const DEFAULT_MAX_REBUILD = 1024 * 1024 * 1024;

/** MANDU_GIT_TWIN_MAX_MB → bytes (unset/invalid: the default). */
export function maxRebuildBytesFromEnv(env: Record<string, string | undefined>): number {
  const n = Number(env["MANDU_GIT_TWIN_MAX_MB"]);
  return Number.isFinite(n) && n > 0 ? Math.floor(n * 1024 * 1024) : DEFAULT_MAX_REBUILD;
}

async function mustGit(git: GitRunner, args: string[], cwd: string, what: string, input?: string, timeoutMs?: number): Promise<string> {
  const r = await git(args, { cwd, ...(input !== undefined ? { input } : {}), ...(timeoutMs !== undefined ? { timeoutMs } : {}) });
  if (r.code !== 0) throw new GitObjectTwinError(`${what} failed in ${cwd}: ${r.stderr.trim().split("\n").slice(-1)[0] ?? `exit ${r.code}`}`);
  return r.stdout;
}

// ── The history walk and its cache ──────────────────────────────────────────

/** The walk's arguments after the revisions (history-labels.ts, shared with
 *  the arbiter's resolver). */
const WALK_ARGS = HISTORY_WALK_ARGS;

/** One repository's cached history walk (`<walkCacheDir>/<key>.json`): the
 *  protected blob names the walk from `tips` found. */
export interface WalkCacheEntry {
  v: 1;
  root: string;
  rels: string[];
  /** What else decides the walk's output (walkBaseKey). */
  base: string;
  /** The label walk (plan 14 §8.1): the key of the labels that decided which
   *  paths it kept. Absent on a walk by path. */
  filter?: string;
  /** The commits the walk started from: every ref, every reflog entry. */
  tips: string[];
  blobs: string[];
}

export type WalkPlan =
  | { kind: "hit" }
  | { kind: "incremental"; include: string[]; exclude: string[] }
  | { kind: "full" };

/** The file one repository's walk is cached in. Pure. `filter` names a
 *  label walk (its labels' key), which never shares a file with a walk by
 *  path. */
export function walkCacheFile(dir: string, root: string, rels: readonly string[], filter?: string): string {
  const key = createHash("sha256")
    .update(`${root}\0${[...rels].sort().join("\0")}${filter !== undefined ? `\0\0filter:${filter}` : ""}`)
    .digest("hex").slice(0, 32);
  return join(dir, `${key}.json`);
}

/** How to bring a cached walk up to date. The same repository, paths and
 *  base: no new tip is a hit (a tip gone away leaves the cached names a
 *  superset, which only hides more), new tips walk only what the old tips
 *  cannot reach (every older commit's changes are already in the cache).
 *  Anything else walks the whole history. Pure. */
export function planWalk(
  entry: WalkCacheEntry | null, root: string, rels: readonly string[], base: string, tips: readonly string[], filter?: string,
): WalkPlan {
  if (entry === null || entry.v !== 1 || entry.root !== root || entry.base !== base) return { kind: "full" };
  if (entry.filter !== filter) return { kind: "full" };
  const want = [...rels].sort();
  if (entry.rels.length !== want.length || entry.rels.some((r, i) => r !== want[i])) return { kind: "full" };
  const old = new Set(entry.tips);
  const include = tips.filter((t) => !old.has(t));
  if (include.length === 0) return { kind: "hit" };
  return { kind: "incremental", include, exclude: [...entry.tips] };
}

/** A cache file as read back, or null when absent or not a well-formed
 *  entry (the caller walks the whole history). Pure. */
export function parseWalkCache(text: string): WalkCacheEntry | null {
  let j: unknown;
  try { j = JSON.parse(text); } catch { return null; }
  if (typeof j !== "object" || j === null) return null;
  const e = j as Record<string, unknown>;
  const strs = (v: unknown, re?: RegExp): v is string[] =>
    Array.isArray(v) && v.every((x) => typeof x === "string" && (re === undefined || re.test(x)));
  if (e["v"] !== 1 || typeof e["root"] !== "string" || typeof e["base"] !== "string") return null;
  if (!strs(e["rels"]) || !strs(e["tips"], HEX) || !strs(e["blobs"], HEX)) return null;
  if (e["filter"] !== undefined && typeof e["filter"] !== "string") return null;
  return {
    v: 1, root: e["root"], rels: e["rels"], base: e["base"], tips: e["tips"], blobs: e["blobs"],
    ...(typeof e["filter"] === "string" ? { filter: e["filter"] } : {}),
  };
}

/** `git version`, asked once per runner (it is part of every repository's
 *  walk base key). The production runner takes it from the git sandbox's
 *  own probe (`git --version` in the same sandbox, hardened-git.ts
 *  `probeGitSandbox`: the same git, the same output) and asks no second
 *  time; when this launch's sandbox came from the per-boot probe cache
 *  (probe-cache.ts `launchGitSandbox`, no probe ran) it asks here, in the
 *  sandbox, and the version is never cached. A failure is not remembered. */
const gitVersions = new WeakMap<GitRunner, Promise<string>>();
function gitVersionOf(git: GitRunner, cwd: string): Promise<string> {
  let v = gitVersions.get(git);
  if (v === undefined) {
    const probed = isProductionGitRunner(git) ? launchGitSandbox()?.gitVersion : undefined;
    v = probed !== undefined ? Promise.resolve(probed) : mustGit(git, ["version"], cwd, "git version");
    v.catch(() => gitVersions.delete(git));
    gitVersions.set(git, v);
  }
  return v;
}

// ── One launch's reads, each asked once and shared ──────────────────────────

/** What one `git rev-parse` says about a work tree (repoFactsOf). Paths are
 *  absolute. */
export interface RepoFacts {
  hashLen: number;
  /** The common git directory (shared by every worktree of the repository). */
  commonDir: string;
  shallow: string;
  grafts: string;
  infoAttributes: string;
  /** The work tree's index file (`--git-path index`): read here, at the
   *  same point of the launch as the twin-index patch that follows, so the
   *  patch asks no rev-parse of its own for it (twin-index-stat.ts
   *  `cleanTwinsInIndex`). Absent from the old split (a git before 2.27). */
  index?: string;
}

/** The rev-parse arguments repoFactsOf asks in one call: six lines out, in
 *  order (the format, the common dir, then each `--git-path`). */
export const REPO_FACTS_ARGS: readonly string[] = [
  "rev-parse", "--show-object-format", "--git-common-dir", "--git-path", "shallow", "--git-path", "info/grafts", "--git-path", "info/attributes",
  "--git-path", "index",
];

/** RepoFacts of `rev-parse` REPO_FACTS_ARGS output, paths resolved against
 *  `root` (the call's cwd); null when its first five lines are not
 *  non-empty (the sixth, the index, is taken when present). Pure. */
export function parseRepoFacts(out: string, root: string): RepoFacts | null {
  const l = out.split("\n");
  if (l.length < 5 || l.slice(0, 5).some((x) => x.trim() === "")) return null;
  const fmt = l[0]!.trim();
  if (fmt !== "sha1" && fmt !== "sha256") return null;
  return {
    hashLen: fmt === "sha256" ? 32 : 20,
    commonDir: resolve(root, l[1]!.trim()),
    shallow: resolve(root, l[2]!.trim()),
    grafts: resolve(root, l[3]!.trim()),
    infoAttributes: resolve(root, l[4]!.trim()),
    ...((l[5] ?? "").trim() !== "" ? { index: resolve(root, l[5]!.trim()) } : {}),
  };
}

/** One work tree's facts in ONE rev-parse (it was four). A git that refuses
 *  `--show-object-format` (before 2.27) gets the old split: the paths by a
 *  rev-parse every git answers, the format by a call whose failure means
 *  SHA-1 (as objectDirsOf always read it). */
export async function repoFactsOf(git: GitRunner, root: string): Promise<RepoFacts> {
  const r = await git([...REPO_FACTS_ARGS], { cwd: root });
  const got = r.code === 0 ? parseRepoFacts(r.stdout, root) : null;
  if (got !== null) return got;
  const [paths, fmt] = await Promise.all([
    mustGit(git, ["rev-parse", "--git-common-dir", "--git-path", "shallow", "--git-path", "info/grafts", "--git-path", "info/attributes"], root, "git rev-parse"),
    git(["rev-parse", "--show-object-format"], { cwd: root }),
  ]);
  const p = paths.split("\n").map((x) => x.trim());
  if (p.length < 4 || p.slice(0, 4).some((x) => x === "")) throw new GitObjectTwinError(`git rev-parse in ${root}: an answer it cannot read`);
  return {
    hashLen: fmt.code === 0 && fmt.stdout.trim() === "sha256" ? 32 : 20,
    commonDir: resolve(root, p[0]!), shallow: resolve(root, p[1]!), grafts: resolve(root, p[2]!), infoAttributes: resolve(root, p[3]!),
  };
}

/** What one `git config` read says about a work tree (repoConfigOf). */
export interface RepoConfig {
  /** `-c` pairs of the effective core.autocrlf / core.eol (eolConfigArgs). */
  eol: string[];
  /** core.attributesFile as the user wrote it ("" when unset). */
  attributesFile: string;
  /** extensions.refStorage ("" when unset: the files backend), or null when
   *  the config could not be read (a doubt: the reflogs are asked of git). */
  refStorage: string | null;
}

/** The keys repoConfigOf reads in one `git config -z --get-regexp` (it was
 *  two calls, and the reflog reader needs the ref storage). */
export const REPO_CONFIG_REGEXP = "^(core\\.(autocrlf|eol|attributesfile)|extensions\\.refstorage)$";

/** RepoConfig of `git config -z --get-regexp` output (`<key>\n<value>\0`, a
 *  bare key `<key>\0`); the last value of a key wins, as in git. Pure. */
export function parseRepoConfig(out: string, ok: boolean): RepoConfig {
  const last = new Map<string, string | null>();
  for (const rec of out.split("\0")) {
    if (rec === "") continue;
    const nl = rec.indexOf("\n");
    last.set((nl < 0 ? rec : rec.slice(0, nl)).toLowerCase(), nl < 0 ? null : rec.slice(nl + 1));
  }
  const attr = last.get("core.attributesfile");
  return {
    eol: eolConfigArgs(out),
    attributesFile: typeof attr === "string" ? attr : "",
    refStorage: !ok ? null : last.has("extensions.refstorage") ? (last.get("extensions.refstorage") ?? "true") : "",
  };
}

/** One work tree's config in ONE read. Exit 1 is "none set". A
 *  core.attributesFile that git would expand (`~`, `%(prefix)`, `:(optional)`)
 *  is asked again with `--path`, as before. */
export async function repoConfigOf(git: GitRunner, root: string): Promise<RepoConfig> {
  const r = await git(["config", "-z", "--get-regexp", REPO_CONFIG_REGEXP], { cwd: root });
  const cfg = parseRepoConfig(r.code === 0 ? r.stdout : "", r.code === 0 || r.code === 1);
  if (/^(~|%\(|:\()/.test(cfg.attributesFile)) {
    cfg.attributesFile = (await git(["config", "--path", "--get", "core.attributesFile"], { cwd: root })).stdout.trim();
  }
  return cfg;
}

/** A promise memo whose rejection is handled where it is stored (a read
 *  started early and never awaited must not be an unhandled rejection). */
function memo<T>(m: Map<string, Promise<T>>, key: string, make: () => Promise<T>): Promise<T> {
  let p = m.get(key);
  if (p === undefined) {
    p = make();
    p.catch(() => undefined);
    m.set(key, p);
  }
  return p;
}

/**
 * One launch's reads of its repositories (confidentiality.md §7.2a "Cost on
 * a relaunch"): each work tree's facts and config asked once, and the
 * history state and the history walks asked once per OBJECT STORE, so two
 * work trees of one repository (a worktree and its main checkout) share
 * them. What is per work tree stays per work tree: its index, its working
 * copies, its HEAD and its own refs (each work tree's `rev-list --all` is
 * part of the shared tips).
 */
export class RepoReads {
  private readonly facts = new Map<string, Promise<RepoFacts>>();
  private readonly configs = new Map<string, Promise<RepoConfig>>();
  private readonly states = new Map<string, Promise<HistoryState>>();
  private readonly walks = new Map<string, Promise<string[]>>();
  /** How the reflogs were read, per common dir (a test and log aid). */
  readonly reflogFallbacks = new Map<string, string>();
  /** The work-tree sets whose history state was asked (each sorted). */
  readonly statesAsked: string[][] = [];
  /** How many states came from the prefetch (a test and log aid). */
  prefetchedStates = 0;
  constructor(readonly git: GitRunner, private readonly prefetch?: StatePrefetch) {}
  factsOf(root: string): Promise<RepoFacts> { return memo(this.facts, root, () => repoFactsOf(this.git, root)); }
  configOf(root: string): Promise<RepoConfig> { return memo(this.configs, root, () => repoConfigOf(this.git, root)); }
  /** The history state of the object store `roots` (work trees of one
   *  repository) share: the prefetch's when it has one for exactly these
   *  work trees and its inputs are unchanged (twin-prefetch.ts), else
   *  computed now. */
  stateOf(roots: readonly string[]): Promise<HistoryState> {
    const all = [...new Set(roots)].sort();
    return memo(this.states, all.join("\0"), async () => {
      this.statesAsked.push(all);
      const pre = this.prefetch !== undefined ? await this.prefetch.take(all, this).catch(() => null) : null;
      if (pre !== null) { this.prefetchedStates++; return pre; }
      return historyStateOfRoots(this.git, all, this);
    });
  }
  /** A walk shared by the work trees of one store (`key` names the store,
   *  the paths and the state it starts from). */
  walkOnce(key: string, make: () => Promise<string[]>): Promise<string[]> { return memo(this.walks, key, make); }
}

function readOptional(path: string): string {
  try { return readFileSync(path, "utf8"); } catch { return ""; }
}

function readOptionalBytes(path: string): Buffer | null {
  try { return readFileSync(path); } catch { return null; }
}

/** A label walk's path filter (plan 14 §8.1): `keep` decides a path the
 *  history holds; `key` names the labels it decides by (the cache key). */
interface WalkFilter {
  key: string;
  keep: (rel: string) => boolean;
}

/** The blob names in the history of `rels`, from the cache where it is
 *  current. The cache is only an accelerator: a file that is absent, torn,
 *  or from another base walks the whole history, and so does an incremental
 *  walk git refuses (an old tip pruned since). With `filter`, `rels` are the
 *  pathspecs that bound the walk ([] = the whole history) and only the
 *  blobs of the paths `filter.keep` accepts are kept. */
/** A repository's history state as a walk is keyed by: the tips it starts
 *  from (every ref, every reflog entry) and its base (walkBaseKey). */
export interface HistoryState {
  tips: string[];
  base: string;
  /** The global options the walk runs with (the shallow rule: [] or
   *  IGNORE_SHALLOW_ARGS). Decided with `base`, which names it. */
  walkArgs: string[];
  /** Why a walk that fails on a missing parent may have failed (said in
   *  the refusal, historyWalkFailure): a repository `info/grafts` file
   *  (ignored: grafts are off), or a shallow file the rule ignored. */
  rewrites?: { grafts: boolean; shallowIgnored: boolean };
}

/** The history state of the repository at `root` (the arbiter's resolver
 *  computes the same, plan 14 §11.1 R2). */
export async function historyStateOf(git: GitRunner, root: string, reads?: RepoReads): Promise<HistoryState> {
  return (reads ?? new RepoReads(git)).stateOf([root]);
}

function hexLines(out: string): string[] {
  return out.split("\n").map((l) => l.trim()).filter((l) => HEX.test(l));
}

/**
 * The commits the reflogs name, as `git rev-list --reflog` would add them
 * (reflog-tips.ts): read from the reflog files of a files-backend
 * repository, then kept by git when it has the object and peeled to a
 * commit (`rev-list --no-walk --ignore-missing --stdin`). On any doubt (a
 * ref storage other than files, a config git could not read, anything the
 * reader does not take) the old command answers: `rev-list --all --reflog
 * --no-walk`, never fewer tips.
 */
async function reflogTipsOf(git: GitRunner, root: string, reads: RepoReads): Promise<string[]> {
  const [facts, cfg] = await Promise.all([reads.factsOf(root), reads.configOf(root)]);
  let why: string;
  if (cfg.refStorage === null) why = "the config could not be read";
  else if (cfg.refStorage !== "" && cfg.refStorage.toLowerCase() !== "files") why = `extensions.refStorage is ${cfg.refStorage}`;
  else {
    const got = await readReflogOids(facts.commonDir, facts.hashLen * 2);
    if ("oids" in got) {
      if (got.oids.length === 0) return [];
      return hexLines(await mustGit(git, ["rev-list", "--no-walk", "--ignore-missing", "--stdin"], root, "git rev-list", `${got.oids.join("\n")}\n`));
    }
    why = got.fallback;
  }
  reads.reflogFallbacks.set(facts.commonDir, why);
  return hexLines(await mustGit(git, ["rev-list", "--all", "--reflog", "--no-walk"], root, "git rev-list"));
}

/**
 * The history state of the object store `roots` share (work trees of one
 * repository; one root alone is historyStateOf). The tips are every ref and
 * every reflog entry: each work tree's `rev-list --all --no-walk` (its HEAD
 * and its own refs; strict, as before: a ref naming a missing object fails
 * the call) and the reflogs' commits once for the store (reflogTipsOf). The
 * base is the store's: the git version and the shallow boundary the walk
 * honours (history-labels.ts walkShallowRule; grafts and replace refs are
 * off for every hardened call, and a replace ref is a tip like any ref).
 * Every git call here runs concurrently.
 */
export async function historyStateOfRoots(git: GitRunner, roots: readonly string[], reads: RepoReads = new RepoReads(git)): Promise<HistoryState> {
  const root = roots[0]!;
  const [alls, fromLogs, shallow, gitVersion] = await Promise.all([
    Promise.all(roots.map((r) => mustGit(git, ["rev-list", "--all", "--no-walk"], r, "git rev-list"))),
    reflogTipsOf(git, root, reads),
    reads.factsOf(root).then((facts) => shallowRuleOf(git, root, facts)),
    gitVersionOf(git, root),
  ]);
  const tips = [...new Set([...alls.flatMap(hexLines), ...fromLogs])].sort();
  const base = walkBaseKey({ gitVersion, shallow: shallow.honoured });
  const facts = await reads.factsOf(root);
  const grafts = readOptional(join(facts.commonDir, "info", "grafts")).trim() !== "";
  return { tips, base, walkArgs: shallow.args, rewrites: { grafts, shallowIgnored: shallow.args.length > 0 } };
}

/**
 * The refusal of a walk that failed, in plain words where a history rewrite
 * the walk does not honour explains it (confidentiality.md §7.2a "What the
 * walk does not let a repository hide"): history cut by a deprecated
 * `info/grafts` file over commits the repository does not have, or a shallow
 * file that names a commit whose parent the repository does have beside a
 * boundary past which it has nothing. Anything else: `e` as it is. Pure.
 */
export function historyWalkFailure(root: string, rewrites: HistoryState["rewrites"], e: unknown): unknown {
  if (!(e instanceof GitObjectTwinError) || rewrites === undefined) return e;
  if (rewrites.grafts) {
    return new GitObjectTwinError(
      `${root}: its history is cut by a .git/info/grafts file (a git feature git has deprecated), and the commits it cuts away are not in ` +
      "the repository. Mandu reads history without grafts, since a graft could hide a protected version, so it cannot read this history " +
      "to its end. To fix it, if the repository is a partial copy, turn the cut into a shallow boundary and remove the file: " +
      "`cut -d' ' -f1 .git/info/grafts >> .git/shallow && rm .git/info/grafts`; otherwise fetch the missing history, or remove the file. " +
      "(`git replace --convert-graft-file` does not help: Mandu reads history without replace refs too.)",
    );
  }
  if (rewrites.shallowIgnored) {
    return new GitObjectTwinError(
      `${root}: its .git/shallow file names a commit whose parent IS in the repository, beside a boundary past which history is missing. ` +
      "Mandu honours a shallow file only where it is true, since a false boundary could hide a protected version, and it cannot read past " +
      "the missing history either. If you did not edit .git/shallow, something did: restore it (`git fetch --depth=<n>` rewrites it) or " +
      "fetch the whole history (`git fetch --unshallow`).",
    );
  }
  return e;
}

/** The shallow rule (history-labels.ts walkShallowRule) for the store of
 *  `root`: its shallow file read as git would, the rule's two calls only
 *  when it names a commit. */
export function shallowRuleOf(git: GitRunner, root: string, facts: Pick<RepoFacts, "shallow" | "hashLen">): Promise<ShallowRule> {
  return walkShallowRule(
    (args, input) => git(args, { cwd: root, input }),
    readOptional(facts.shallow),
    facts.hashLen * 2,
  );
}

async function historyBlobsOf(
  git: GitRunner, root: string, rels: readonly string[], walkCacheDir: string | undefined, stats: WalkStats | undefined, filter: WalkFilter | undefined,
  state: HistoryState, sealing?: SealSession, found?: Array<[string, string]>,
): Promise<string[]> {
  // Each (version, path) a walk reads also goes to `found` (the store's
  // locked memory, locked-memory.ts).
  const parse = (out: string): string[] => {
    const pairs = parseRawLogBlobPaths(out).filter(([, p]) => filter === undefined || filter.keep(p));
    found?.push(...pairs);
    return [...new Set(pairs.map(([b]) => b))].sort();
  };
  // The whole history: from the tips (every ref and reflog entry of every
  // work tree of the store, historyStateOfRoots), the commits `git log --all
  // --reflog` starts from, without git enumerating the reflogs again. No tip
  // (an empty repository) is no history (`git log --stdin` with no input
  // would walk HEAD, which does not exist yet).
  const full = async (): Promise<string[]> => state.tips.length === 0
    ? []
    : parse(await mustGit(git, [...state.walkArgs, "log", "--stdin", ...WALK_ARGS, "--", ...rels], root, "git log", `${state.tips.join("\n")}\n`)
      .catch((e: unknown) => { throw historyWalkFailure(root, state.rewrites, e); }));
  if (walkCacheDir === undefined) {
    if (stats) stats.full++;
    return full();
  }
  const { tips, base } = state;
  const file = walkCacheFile(walkCacheDir, root, rels, filter?.key);
  const sealKey = basename(file, ".json");
  const raw = readOptionalBytes(file);
  let entry = raw === null ? null : parseWalkCache(raw.toString("utf8"));
  // Plan 14 §11.2: an entry is used only when a seal of the current epoch
  // vouches for its bytes (the same bytes parsed above). No seal session
  // trusts nothing.
  if (entry !== null && !(sealing !== undefined && await sealing.verifyBytes(SEAL_KIND_HISTORY_WALK, sealKey, raw!))) entry = null;
  // A sealed walk of the same paths, kept under another base key (a new
  // git, a new walk rule, a shallow boundary honoured or not), is walked
  // anew as a whole: said once, as an unsealed cache is (plan 14 §11.2.1
  // "The rebuild notice").
  if (entry !== null && entry.root === root && entry.base !== base && entry.filter === filter?.key) sealing?.noteWalkChanged();
  const plan = planWalk(entry, root, rels, base, tips, filter?.key);
  let blobs: string[];
  if (plan.kind === "hit") {
    if (stats) stats.hit++;
    blobs = entry!.blobs;
  } else if (plan.kind === "incremental") {
    const r = await git([...state.walkArgs, "log", "--stdin", ...WALK_ARGS, "--", ...rels], {
      cwd: root, input: `${plan.include.join("\n")}\n${plan.exclude.map((t) => `^${t}`).join("\n")}\n`,
    });
    if (r.code === 0) {
      if (stats) stats.incremental++;
      blobs = [...new Set([...entry!.blobs, ...parse(r.stdout)])].sort();
    } else {
      if (stats) stats.full++;
      blobs = await full();
    }
  } else {
    if (stats) stats.full++;
    blobs = await full();
  }
  if (plan.kind !== "hit" || entry!.tips.length !== tips.length) {
    const next: WalkCacheEntry = { v: 1, root, rels: [...rels].sort(), base, tips, blobs, ...(filter !== undefined ? { filter: filter.key } : {}) };
    try {
      mkdirSync(walkCacheDir, { recursive: true, mode: 0o700 });
      const tmp = `${file}.tmp-${process.pid}`;
      const text = JSON.stringify(next);
      writeFileSync(tmp, text, { mode: 0o600 });
      renameSync(tmp, file);
      sealing?.sealBytes(SEAL_KIND_HISTORY_WALK, sealKey, Buffer.from(text, "utf8"));
    } catch { /* best effort: the next launch walks again */ }
  }
  return blobs;
}

/** How each repository's history walk was served (a test and log aid). */
export interface WalkStats {
  hit: number;
  incremental: number;
  full: number;
}

/** `Promise.all`, but on a failure it still waits for every other promise
 *  before rejecting with the first failure: no read of a failed work tree
 *  (a history walk, which writes its cache entry when it ends) outlives the
 *  step that gave up on it. */
async function allSettledOrFirstError<T extends readonly unknown[]>(ps: { [K in keyof T]: Promise<T[K]> }): Promise<T> {
  const got = await Promise.allSettled(ps as readonly Promise<unknown>[]);
  const bad = got.find((r): r is PromiseRejectedResult => r.status === "rejected");
  if (bad !== undefined) throw bad.reason;
  return got.map((r) => (r as PromiseFulfilledResult<unknown>).value) as unknown as T;
}

/** The protected blob names of one repository: every version of the files in
 *  any ref, the reflog and the stash, the index's stages, and the working
 *  copies as `git add` would store them (`worktreeBlobNames`). With
 *  `walkCacheDir`, the history part comes from the walk cache where it is
 *  current. */
export async function protectedBlobsOf(
  git: GitRunner, root: string, rels: readonly string[], walkCacheDir?: string, stats?: WalkStats, sealing?: SealSession,
  store?: StoreReads,
): Promise<string[]> {
  const reads = store?.reads ?? new RepoReads(git);
  const roots = store?.roots ?? [root];
  const present = rels.filter((r) => existsSync(join(root, r)));
  // The walk is the store's (every work tree of it walks the same history
  // from the same tips): one walk per set of paths, shared; the index and
  // the working copies are this work tree's own. All three run at once.
  const sorted = [...rels].sort();
  const [history, idx, hashed] = await allSettledOrFirstError([
    reads.stateOf(roots).then((state) => reads.walkOnce(
      JSON.stringify(["paths", roots, sorted, walkCacheDir ?? null]),
      () => historyBlobsOf(git, root, rels, walkCacheDir, stats, undefined, state, sealing, store?.found),
    )),
    mustGit(git, ["ls-files", "-s", "-z", "--", ...rels], root, "git ls-files"),
    worktreeBlobNames(git, root, present, reads),
  ]);
  if (store?.found !== undefined) {
    store.found.push(...parseLsFilesStagePaths(idx));
    // The working copies' names: the raw hashes, then the converted ones,
    // each in `present`'s order.
    if (hashed.length === 2 * present.length) hashed.forEach((b, i) => store.found!.push([b, present[i % present.length]!]));
  }
  return [...new Set([...history, ...parseLsFilesStage(idx), ...hashed])].sort();
}

/** The reads a work tree shares with the other work trees of its object
 *  store this launch (RepoReads; `roots` are all of them, sorted). */
export interface StoreReads {
  reads: RepoReads;
  roots: readonly string[];
  /** Every (version, path) found protected in the store this launch (the
   *  history walked, the index, the working copies): the store's locked
   *  memory (locked-memory.ts) adds them. */
  found?: Array<[string, string]>;
}

/** The config file of an empty scratch git directory of `format`. Pure. */
export function scratchGitConfig(format: "sha1" | "sha256"): string {
  return format === "sha256"
    ? "[core]\n\trepositoryformatversion = 1\n\tbare = true\n[extensions]\n\tobjectFormat = sha256\n"
    : "[core]\n\trepositoryformatversion = 0\n\tbare = true\n";
}

/** `-c` pairs for the end-of-line settings of `git config -z --get-regexp`
 *  output (`<key>\n<value>\0`, a bare boolean key `<key>\0`); the last
 *  value of a key wins, as in git. Pure. */
export function eolConfigArgs(out: string): string[] {
  const last = new Map<string, string>();
  for (const rec of out.split("\0")) {
    if (rec === "") continue;
    const nl = rec.indexOf("\n");
    const key = (nl < 0 ? rec : rec.slice(0, nl)).toLowerCase();
    if (key !== "core.autocrlf" && key !== "core.eol") continue;
    last.set(key, nl < 0 ? "true" : rec.slice(nl + 1));
  }
  return [...last].flatMap(([k, v]) => ["-c", `${k}=${v}`]);
}

/**
 * The blob names the working copies of `rels` (relative to `root`, each
 * present) would get from `git add`, found WITHOUT starting a program the
 * repository names (docs/design/architecture/write-protection.md §8.4).
 *
 * `git add` (and a plain `git hash-object <file>`) passes a file through
 * its clean filter: a PROGRAM, `filter.<x>.clean` or `.process` in the
 * config, named for the path by an attribute. The agent writes both
 * `.git/config` and `.gitattributes`, and no `-c` switches off a driver
 * whose name the caller does not know. So each file gets two names, both
 * computed by git with no driver:
 *
 *   - its raw bytes (`hash-object --no-filters`), what `git add` stores when
 *     no conversion applies;
 *   - its bytes as git converts them WITHOUT a driver (end of line, `ident`,
 *     `working-tree-encoding`): hashed in a SCRATCH git directory whose
 *     config holds only the object format and the repository's effective
 *     `core.autocrlf` / `core.eol` / `core.attributesFile`, with the
 *     repository's `info/attributes` and the repository's work tree, so every
 *     attribute applies as it would for `git add` but no config names a
 *     driver for one (the user's global config is left out too:
 *     GIT_CONFIG_GLOBAL=/dev/null).
 *
 * What only a real driver could compute (a file a git-lfs, git-crypt or
 * nbstripout filter really cleans) is stored as the driver's output; that
 * version is hidden when a ref, the reflog or the index names it (the walk),
 * not as a dangling object. Inside a confined session the agent cannot make
 * such a blob of a protected file: it reads the twin, so what it could add
 * holds the symbol, not the secret.
 */
export async function worktreeBlobNames(git: GitRunner, root: string, rels: readonly string[], reads?: RepoReads): Promise<string[]> {
  if (rels.length === 0) return [];
  const r0 = reads ?? new RepoReads(git);
  // The raw hash needs nothing else; the converted hash needs the work
  // tree's facts (object format, info/attributes) and config (end of line,
  // core.attributesFile), each one read shared with the rest of the launch.
  const converted = async (): Promise<string[]> => {
    const [facts, cfg] = await Promise.all([r0.factsOf(root), r0.configOf(root)]);
    const infoAttributes = readOptional(facts.infoAttributes);
    const scratch = mkdtempSync(join(tmpdir(), "mandu-hash-"));
    try {
      for (const d of ["objects", "refs", "info"]) mkdirSync(join(scratch, d), { mode: 0o700 });
      writeFileSync(join(scratch, "HEAD"), "ref: refs/heads/main\n");
      writeFileSync(join(scratch, "config"), scratchGitConfig(facts.hashLen === 32 ? "sha256" : "sha1"));
      writeFileSync(join(scratch, "info", "attributes"), infoAttributes);
      const args = [...cfg.eol, ...(cfg.attributesFile ? ["-c", `core.attributesFile=${cfg.attributesFile}`] : []), "hash-object", "--", ...rels];
      const r = await git(args, { cwd: root, env: { GIT_DIR: scratch, GIT_WORK_TREE: root, GIT_CONFIG_GLOBAL: "/dev/null" } });
      if (r.code !== 0) throw new GitObjectTwinError(`git hash-object failed in ${root}: ${r.stderr.trim().split("\n").slice(-1)[0] ?? `exit ${r.code}`}`);
      return parseHashLines(r.stdout);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  };
  const [raw, conv] = await Promise.all([
    mustGit(git, ["hash-object", "--no-filters", "--", ...rels], root, "git hash-object").then(parseHashLines),
    converted(),
  ]);
  return [...raw, ...conv];
}

/** One repository as the arbiter resolved it (`gitHistoryLocks` `repos`,
 *  plan 14 §11.1 R2): the resolution key and the labelled versions, bare
 *  names of the repository's object format. */
export interface ArbiterResolution {
  key: string;
  blobs: readonly string[];
}

/**
 * The blob names of every path in the repository's history, reflog, stash
 * and index that a human label puts above `public` (plan 14 §8.1), whether
 * the path exists now or not. The walk is bounded by `historyPathspecs` (the
 * labels' literal prefixes inside the repository; the whole history when a
 * label covers the repository or a pattern may match anywhere in it) and
 * each path it sees is decided by `labelledAbovePublic`. Empty (no git call)
 * when no label above `public` reaches inside the repository.
 */
export async function labelledBlobsOf(
  git: GitRunner, root: string, labels: CompiledHistoryLabels, key: string, walkCacheDir?: string, stats?: WalkStats,
  resolved?: ArbiterResolution, used?: { arbiter: number }, sealing?: SealSession, store?: StoreReads,
): Promise<string[]> {
  const specs = historyPathspecs(root, labels);
  if (specs !== null && specs.length === 0) return [];
  const reads = store?.reads ?? new RepoReads(git);
  const memo = new Map<string, boolean>();
  const keep = (rel: string): boolean => {
    let v = memo.get(rel);
    if (v === undefined) { v = labelledAbovePublic(join(root, rel), labels); memo.set(rel, v); }
    return v;
  };
  const filter: WalkFilter = { key: labelFilterKey(key, specs), keep };
  // The index is this work tree's own; it is read while the history is.
  const idxP = mustGit(git, ["ls-files", "-s", "-z", "--", ...(specs ?? [])], root, "git ls-files")
    .then((out) => { const kept = parseLsFilesStagePaths(out).filter(([, p]) => keep(p)); store?.found?.push(...kept); return kept.map(([b]) => b); });
  idxP.catch(() => undefined);
  const state = await reads.stateOf(store?.roots ?? [root]);
  // Plan 14 §11.1 R2: the arbiter resolved this repository in the background.
  // Its blobs stand in for the walk ONLY when it resolved exactly what this
  // walk would read (the same root, labels, pathspecs, base and tips: an
  // equal key); anything else walks as before, so a stale or foreign answer
  // can only cost time, never a version.
  if (resolved !== undefined && resolutionKey(root, filter.key, state.base, state.tips) === resolved.key) {
    if (used) used.arbiter++;
    return [...new Set([...resolved.blobs, ...await idxP])].sort();
  }
  // A label walk is not shared between work trees: which paths it keeps
  // depends on where the work tree is.
  const history = await historyBlobsOf(git, root, specs ?? [], walkCacheDir, stats, filter, state, sealing, store?.found);
  return [...new Set([...history, ...await idxP])].sort();
}

// ── Alternates: every object directory a repository reads ──────────────────
//
// One implementation, shared with the arbiter's prepared copies
// (git-alternates.ts, a byte-identical copy in arbiter/src): a pack one of
// them reaches and the other does not would have no sanitized copy.

export {
  ALTERNATES_MAX_BYTES, ALTERNATES_MAX_DEPTH, ALTERNATES_MAX_STORES, defaultAlternatesIo, parseAlternates, type AlternatesIo,
} from "./git-alternates.js";

/** git-alternates.ts `objectStoreClosure`, its failure a GitObjectTwinError
 *  (the launch is refused unless --best-effort, never a shorter list). */
export function objectStoreClosure(
  own: string, io: AlternatesIo = defaultAlternatesIo, maxDepth = ALTERNATES_MAX_DEPTH, maxStores = ALTERNATES_MAX_STORES,
): string[] {
  try {
    return sharedObjectStoreClosure(own, io, maxDepth, maxStores);
  } catch (e) {
    if (e instanceof AlternatesError) throw new GitObjectTwinError(e.message);
    throw e;
  }
}

/** The object directories of a repository: its own and every alternate it
 *  reaches (objectStoreClosure). Throws GitObjectTwinError when they cannot
 *  be told. */
export async function objectDirsOf(
  git: GitRunner, root: string, reads?: RepoReads, io?: AlternatesIo,
): Promise<{ dirs: string[]; hashLen: number }> {
  const facts = await (reads ?? new RepoReads(git)).factsOf(root);
  return objectDirsOfFacts(facts, io);
}

/** objectDirsOf from facts already read (no git call). */
export function objectDirsOfFacts(facts: RepoFacts, io?: AlternatesIo): { dirs: string[]; hashLen: number } {
  return { dirs: objectStoreClosure(join(facts.commonDir, "objects"), io), hashLen: facts.hashLen };
}

// ── Pure: stores that share an object directory ─────────────────────────────

/** One object store's read half (prepareGitObjectTwins): the object
 *  directories it reads (objectStoreClosure) and the protected names it
 *  found. */
export interface StoreNeed {
  id: string;
  hashLen: number;
  dirs: readonly string[];
  found: readonly string[];
}

/** One object directory as a cluster plans it. */
export interface DirNeed {
  dir: string;
  hashLen: number;
  /** The union of the names of every store that reads it (sorted). */
  names: string[];
  /** The stores that read it, in input order. */
  by: string[];
}

/** Stores linked through the object directories they share. */
export interface StoreCluster {
  /** Its stores, in input order. */
  stores: string[];
  /** Each directory any of them reads, once (first reader's order). */
  dirs: DirNeed[];
  /** Directories the planner cannot sanitize (the caller fails closed). */
  unsupported: string[];
}

/**
 * Plan per REAL object directory (confidentiality.md §7.2a "Stores shared
 * through alternates"). The wrap binds one twin per path, so a pack two
 * stores reach (one borrows the other's objects through its alternates, or
 * both borrow a third's) must get ONE sanitized twin whose exclusions are
 * the union of the names of every store that reads it; planned per store,
 * it got one twin per store and the first bound left the other store's
 * versions readable. Stores that share a directory, directly or through a
 * chain, form one cluster: the unit that is twinned, or fails, as one. A
 * directory read by stores of two object formats is unsupported. Pure.
 */
export function clusterObjectStores(needs: readonly StoreNeed[]): StoreCluster[] {
  const parent = needs.map((_, i) => i);
  const find = (i: number): number => {
    while (parent[i] !== i) { parent[i] = parent[parent[i]!]!; i = parent[i]!; }
    return i;
  };
  const readers = new Map<string, number[]>();
  needs.forEach((n, i) => {
    for (const d of new Set(n.dirs)) {
      const r = readers.get(d) ?? [];
      r.push(i);
      readers.set(d, r);
    }
  });
  for (const r of readers.values()) {
    for (const j of r.slice(1)) {
      const a = find(r[0]!);
      const b = find(j);
      if (a !== b) parent[Math.max(a, b)] = Math.min(a, b);
    }
  }
  const byRoot = new Map<number, StoreCluster>();
  const placed = new Set<string>();
  needs.forEach((n, i) => {
    const k = find(i);
    let c = byRoot.get(k);
    if (c === undefined) { c = { stores: [], dirs: [], unsupported: [] }; byRoot.set(k, c); }
    c.stores.push(n.id);
    for (const d of n.dirs) {
      if (placed.has(d)) continue;
      placed.add(d);
      const rs = readers.get(d)!;
      const formats = new Set(rs.map((x) => needs[x]!.hashLen));
      if (formats.size > 1) c.unsupported.push(`${d} (read by repositories of two object formats)`);
      c.dirs.push({
        dir: d,
        hashLen: n.hashLen,
        names: [...new Set(rs.flatMap((x) => needs[x]!.found))].sort(),
        by: rs.map((x) => needs[x]!.id),
      });
    }
  });
  return [...byRoot.values()];
}

/** Inventory one object directory for the given protected names. */
export function inventoryObjectDir(dir: string, protectedBlobs: readonly string[], hashLen: number): ObjectDirInventory {
  const packDir = join(dir, "pack");
  let names: string[] = [];
  try { names = readdirSync(packDir); } catch { /* no packs */ }
  const packs: PackInventory[] = [];
  for (const n of names) {
    if (!/^pack-[0-9a-f]+\.idx$/.test(n)) continue;
    const base = join(packDir, n.slice(0, -4));
    if (!existsSync(`${base}.pack`)) continue;
    const held = idxLookupFile(`${base}.idx`, protectedBlobs, hashLen);
    packs.push({
      base, held,
      hasRev: existsSync(`${base}.rev`), hasBitmap: existsSync(`${base}.bitmap`), hasMtimes: existsSync(`${base}.mtimes`),
      size: statSync(`${base}.pack`).size,
    });
  }
  const looseProtected = protectedBlobs
    .map((b) => join(dir, b.slice(0, 2), b.slice(2)))
    .filter((p) => existsSync(p));
  const midx = names.filter((n) => n === "multi-pack-index" || /^multi-pack-index-[0-9a-f]+\.(bitmap|rev)$/.test(n)).map((n) => join(packDir, n)).sort();
  return { dir, packs, looseProtected, midx, incrementalMidx: names.includes("multi-pack-index.d") };
}

/** The files of a sanitized pack in the cache, or null when absent or not
 *  what the key promises (a pack whose index still lists an excluded blob is
 *  never served). This alone does not authenticate the pack: a pack holding
 *  the real bytes under a clean `.idx` passes it, so the caller also checks
 *  the seals (plan 14 §11.2). */
function cachedPack(cacheDir: string, r: PackRebuild, hashLen: number): { pack: string; idx: string; rev: string | null } | null {
  const dir = join(cacheDir, r.key);
  let names: string[];
  try { names = readdirSync(dir); } catch { return null; }
  const idxName = names.find((n) => n.endsWith(".idx"));
  if (!idxName) return null;
  const base = join(dir, idxName.slice(0, -4));
  if (!existsSync(`${base}.pack`)) return null;
  try {
    if (idxLookupFile(`${base}.idx`, r.exclude, hashLen).length > 0) return null;
  } catch {
    return null;
  }
  return { pack: `${base}.pack`, idx: `${base}.idx`, rev: existsSync(`${base}.rev`) ? `${base}.rev` : null };
}

/** The files of a cached sanitized pack the twin serves, each with its seal
 *  key (`<cache key>/<file name>`): the pack, its index, and its reverse
 *  index when the real pack has one. */
function packParts(r: PackRebuild, files: { pack: string; idx: string; rev: string | null }): Array<{ key: string; path: string }> {
  const parts = [files.pack, files.idx, ...(r.pack.hasRev && files.rev !== null ? [files.rev] : [])];
  return parts.map((p) => ({ key: `${r.key}/${basename(p)}`, path: p }));
}

/** Do two lists name the same objects (as sets)? A sanitized pack's index,
 *  rebuilt from its content, must name exactly the objects asked for. Pure. */
export function sameNames(got: readonly string[], want: readonly string[]): boolean {
  const a = [...new Set(got)].sort();
  const b = [...new Set(want)].sort();
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** `GIT_ALTERNATE_OBJECT_DIRECTORIES` for `dirs`: colon-separated, an entry
 *  holding a colon or starting with a quote C-quoted (git's own rule). */
export function alternateObjectDirsEnv(dirs: readonly string[]): string {
  return [...new Set(dirs)].map((d) => (d.includes(":") || d.startsWith("\"") ? JSON.stringify(d) : d)).join(":");
}

/**
 * Build one sanitized pack into the cache (atomic: a temp dir renamed).
 *
 * `git pack-objects` writes its temporary pack in the object directory it
 * runs against and then renames it to the base name given. Run against the
 * repository, that rename crosses filesystems whenever the view state (the
 * cache) is not on the repository's: EXDEV, and the launch refused
 * (2026-09-28, a view state under /tmp with repositories under /home). So
 * the command gets a private, empty object directory beside the cache
 * (`GIT_OBJECT_DIRECTORY`, where the temporary files land) and reads the
 * repository's objects through `GIT_ALTERNATE_OBJECT_DIRECTORIES`: the
 * pack's own object directory and the repository's (git follows their
 * alternates in turn). The same objects in, the same pack out.
 */
async function buildPack(git: GitRunner, root: string, cacheDir: string, r: PackRebuild, hashLen: number, commonDir: string): Promise<void> {
  const drop = new Set(r.exclude);
  const list = idxObjectNames(readFileSync(`${r.pack.base}.idx`), hashLen).filter((o) => !drop.has(o));
  const tmp = join(cacheDir, `.tmp-${r.key}-${process.pid}`);
  const odb = `${tmp}.odb`;
  rmSync(tmp, { recursive: true, force: true });
  rmSync(odb, { recursive: true, force: true });
  mkdirSync(tmp, { recursive: true, mode: 0o700 });
  mkdirSync(join(odb, "pack"), { recursive: true, mode: 0o700 });
  try {
    const env = {
      GIT_OBJECT_DIRECTORY: odb,
      GIT_ALTERNATE_OBJECT_DIRECTORIES: alternateObjectDirsEnv([dirname(dirname(r.pack.base)), join(commonDir, "objects")]),
    };
    const args = list.length > 0
      ? ["-c", "pack.writeReverseIndex=true", "-c", "pack.writeBitmapIndex=false", "pack-objects", "-q", "--no-write-bitmap-index", join(tmp, "p")]
      // Every object of the pack is protected: the twin is an empty pack.
      : ["-c", "pack.writeReverseIndex=true", "pack-objects", "-q", join(tmp, "p")];
    const res = await git(args, {
      cwd: root, input: list.length > 0 ? `${list.join("\n")}\n` : "", timeoutMs: list.length > 0 ? 30 * 60_000 : 60_000, env, writable: [cacheDir],
    });
    if (res.code !== 0) {
      throw new GitObjectTwinError(`git pack-objects failed in ${root}: ${res.stderr.trim().split("\n").slice(-1)[0] ?? `exit ${res.code}`}`);
    }
    // The names pack-objects writes into the index are the SOURCE's, not
    // their content's: a crafted pack in the repository (an index naming the
    // protected blob's bytes, or a delta on it, as another object; the agent
    // can write the object store) would carry the protected bytes under a
    // name nobody excludes. So the index is rebuilt FROM THE CONTENT
    // (`index-pack` hashes every object; the pack is never thin, and with an
    // empty object directory and no alternates it reads nothing else) and
    // must name exactly the objects asked for (confidentiality-plan-14
    // §11.1 R3, found while building the arbiter's copies).
    const packName = readdirSync(tmp).find((n) => n.endsWith(".pack"));
    if (packName === undefined) throw new GitObjectTwinError(`git pack-objects wrote no pack in ${root}`);
    const packBase = join(tmp, packName.slice(0, -5));
    rmSync(`${packBase}.idx`, { force: true });
    rmSync(`${packBase}.rev`, { force: true });
    const idx = await git(
      ["-c", "core.hooksPath=/dev/null", "-c", "pack.indexVersion=2", "-c", "pack.writeReverseIndex=true", "index-pack", "-o", `${packBase}.idx`, `${packBase}.pack`],
      // Writes the index and reverse index beside the pack (the temp dir in
      // the cache): read-write in the git sandbox, like pack-objects above.
      { cwd: root, timeoutMs: 30 * 60_000, env: { GIT_OBJECT_DIRECTORY: odb, GIT_ALTERNATE_OBJECT_DIRECTORIES: "" }, writable: [cacheDir] },
    );
    if (idx.code !== 0) {
      throw new GitObjectTwinError(`git index-pack failed in ${root}: ${idx.stderr.trim().split("\n").slice(-1)[0] ?? `exit ${idx.code}`}`);
    }
    if (!sameNames(idxObjectNames(readFileSync(`${packBase}.idx`), hashLen), list)) {
      throw new GitObjectTwinError(
        `${root}: the objects of ${basename(r.pack.base)}.pack do not hash to the names its index gives them (a crafted pack?); it cannot be sanitized`,
      );
    }
    const dest = join(cacheDir, r.key);
    rmSync(dest, { recursive: true, force: true });
    renameSync(tmp, dest);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
    rmSync(odb, { recursive: true, force: true });
  }
}

/** Drop cached packs nobody used for 30 days. Best effort. */
function pruneCache(cacheDir: string, keep: ReadonlySet<string>): void {
  const cutoff = Date.now() - 30 * 24 * 3600_000;
  let names: string[] = [];
  try { names = readdirSync(cacheDir); } catch { return; }
  for (const n of names) {
    if (keep.has(n)) continue;
    const p = join(cacheDir, n);
    try { if (statSync(p).mtimeMs < cutoff) rmSync(p, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

/** How many repositories prepareGitObjectTwins reads at once. */
const REPO_CONCURRENCY = 8;

/** What one object store's read half found (prepareGitObjectTwins). */
interface StoreRead {
  /** Every protected name: by path, by label, and the locked ids of its
   *  object format (sorted). */
  found: string[];
  /** The names found by path or label (the count). */
  byPath: string[];
  hashLen: number;
  /** Every object directory it reads, alternates followed. */
  dirs: string[];
}

/** Work trees of one object store, read as one (prepareGitObjectTwins). */
interface StoreGroup {
  /** Sorted. */
  roots: string[];
  /** The first work tree's facts (the store's common dir and format). */
  facts: RepoFacts;
}

/** `fn` over `items`, at most `limit` at once; results in input order. */
async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/**
 * The object-store twins for the protected files at `realPaths` (their real
 * paths: the bind targets secret-twins resolved). Throws GitObjectTwinError
 * when a repository holding a protected file's bytes cannot be sanitized.
 */
export async function prepareGitObjectTwins(realPaths: readonly string[], opts: GitObjectTwinOpts): Promise<GitObjectTwinResult> {
  // Every git call of the step in ONE git sandbox (git-session.ts): the
  // caller's session (the launch's, warmed at its start), else one of its own,
  // closed when the step ends.
  const ownSession = opts.git === undefined && opts.gitSession === undefined ? openGitSession() : null;
  const git = opts.git ?? (opts.gitSession ?? ownSession!).runner();
  const exists = opts.exists ?? existsSync;
  const maxBytes = opts.maxRebuildBytes ?? DEFAULT_MAX_REBUILD;
  const byRepo = groupByRepo(realPaths, exists);
  const realpath = opts.realpath ?? ((p: string): string | null => { try { return realpathSync(p); } catch { return null; } });
  // Plan 14 §8.1: the labels, each literal path (and a pattern's literal
  // prefix) also under its real spelling, as the repositories are found by
  // real path (a label written through a symlink still reaches them).
  const labels = opts.labels !== undefined && opts.labels.length > 0
    ? withRealSpellings(opts.labels, (p) => realSpellingOf(p, realpath))
    : [];
  const compiledLabels = compileHistoryLabels(labels);
  const labelKey = labelWalkKey(labels, null);
  const blobLocks = [...new Set([...(opts.blobLocks ?? []), ...(opts.globalLocked ?? [])])].sort();
  // The repositories the labels and blob locks apply to beyond the ones a
  // protected file lies in: the hints (the workspace), and each repository a
  // labelled path lies in, whether the path exists now or not.
  if (labels.length > 0 || blobLocks.length > 0) {
    const extra = [
      ...(opts.repoHints ?? []).map((h) => realpath(h)).filter((h): h is string => h !== null),
      ...(labels.length > 0 ? labels.filter((l) => !l.glob && l.level !== "public").map((l) => l.path) : []),
      ...(labels.length > 0 ? compiledLabels.labels.filter((l) => l.glob && l.level !== "public" && (l.compiled?.literalPrefix ?? "") !== "").map((l) => l.compiled!.literalPrefix) : []),
    ];
    for (const p of extra) {
      const root = repoRootAt(p, exists);
      if (root !== null && !byRepo.has(root)) byRepo.set(root, []);
    }
  }
  const twins: ObjectTwin[] = [];
  let repos = 0;
  let blobs = 0;
  let packsRebuilt = 0;
  let cacheHits = 0;
  let rebuiltBytes = 0;
  const used = new Set<string>();
  const failed: Array<{ root: string; reason: string }> = [];
  const walks: WalkStats = { hit: 0, incremental: 0, full: 0 };
  const scans: StoreScanStats = newStoreScanStats();
  const fromArbiter = { arbiter: 0 };
  const lockedIds = new Set<string>();
  // Plan 14 §11.2: one launch's use of the seals; what it sealed and what it
  // refused are reported once, at the end, whatever happened.
  // The packs' hashes run on worker threads, beside the git calls (D,
  // file-hashes.ts); the full hash, and every check still gates its pack.
  const hashes = opts.hashes ?? new FileHashes();
  if (opts.seals !== undefined) hashes.warm();
  const sealing = new SealSession(opts.seals, opts.log, hashes);
  // Plan 14 §11.2.1 "The rebuild notice": the first cache entry found with
  // no seal of the current epoch means this launch walks and rebuilds what
  // the caches held (seconds on a large checkout): say so ONCE, before that
  // work, naming why and how many repositories. Display only.
  let storeCount = 0;
  sealing.onRecheck = (cause) => opts.log?.(historyRecheckNotice(cause, storeCount));
  // Every git question this launch asks of its repositories, asked once.
  const reads = new RepoReads(git, opts.statePrefetch);
  try {
    // What each repository holds is READ concurrently (the walk or its cache,
    // the object store inventory, the plan: independent git reads); the packs
    // are then rebuilt and the twins assembled one object store at a time in
    // order, so the rebuild cap counts as before.
    //
    // Work trees that share an object store (a worktree and its main
    // checkout) are read as ONE store (confidentiality.md §7.2a "Cost on a
    // relaunch"): the tips, the base and each walk once, and one plan whose
    // exclusions are the union of every work tree's protected versions, so
    // one sanitized twin serves the store's packs. (Planned per work tree,
    // two twins of one pack with different exclusions would reach the wrap,
    // which binds one of them.) Each work tree's index and working copies
    // stay its own.
    //
    // Stores that share an object DIRECTORY (one borrows another's objects
    // through `objects/info/alternates`, `git clone --shared` or
    // `--reference`, or both borrow a third's) are planned per real object
    // directory (§7.2a "Stores shared through alternates"): each directory
    // once, its exclusions the union of every store that reads it, for the
    // same reason; stores linked so are twinned, or fail, as one cluster.
    const entries = [...byRepo];
    const needsState = (root: string, rels: readonly string[]): boolean => {
      if (rels.length > 0) return true;
      if (labels.length === 0) return false;
      const specs = historyPathspecs(root, compiledLabels);
      return specs === null || specs.length > 0;
    };
    // A work tree with nothing to look for costs no git call (as before).
    const active = entries.filter(([root, rels]) => blobLocks.length > 0 || needsState(root, rels));
    // Each work tree's facts (one rev-parse) and, where a walk or a working
    // copy needs it, its config (one read), all at once.
    const factsOf = await mapLimit(active, REPO_CONCURRENCY, ([root, rels]) => {
      if (needsState(root, rels)) void reads.configOf(root);
      return reads.factsOf(root).then((v) => ({ ok: true as const, v }), (e: unknown) => ({ ok: false as const, e }));
    });
    const rootErrors = new Map<string, unknown>();
    const stores = new Map<string, StoreGroup>();
    const storeOfRoot = new Map<string, StoreGroup>();
    for (let i = 0; i < active.length; i++) {
      const [root] = active[i]!;
      const f = factsOf[i]!;
      if (!f.ok) { rootErrors.set(root, f.e); continue; }
      const key = realpath(f.v.commonDir) ?? f.v.commonDir;
      let g = stores.get(key);
      if (g === undefined) { g = { roots: [], facts: f.v }; stores.set(key, g); }
      g.roots.push(root);
      storeOfRoot.set(root, g);
    }
    for (const g of stores.values()) g.roots.sort();
    storeCount = stores.size;
    const indexPaths: Record<string, string> = {};
    for (let i = 0; i < active.length; i++) {
      const f = factsOf[i]!;
      if (f.ok && f.v.index !== undefined) indexPaths[active[i]![0]] = f.v.index;
    }
    const groups = [...stores.values()];
    const readsOf = await mapLimit(groups, REPO_CONCURRENCY, (g) =>
      readStore(g).then((v) => ({ ok: true as const, v }), (e: unknown) => ({ ok: false as const, e })));
    const readOf = new Map(groups.map((g, i) => [g, readsOf[i]!]));
    // The stores with something to hide, clustered by the object
    // directories they share (clusterObjectStores).
    const groupOfId = new Map<string, StoreGroup>();
    const needs: StoreNeed[] = [];
    groups.forEach((g, i) => {
      const r = readOf.get(g)!;
      if (!r.ok || r.v.read === null) return;
      const id = String(i);
      groupOfId.set(id, g);
      needs.push({ id, hashLen: r.v.read.hashLen, dirs: r.v.read.dirs, found: r.v.read.found });
    });
    const clusters = clusterObjectStores(needs);
    const clusterOf = new Map<StoreGroup, StoreCluster>();
    for (const c of clusters) for (const id of c.stores) clusterOf.set(groupOfId.get(id)!, c);
    const fail = (root: string, e: unknown): void => {
      if (!opts.continueOnFailure) throw e;
      if (!failed.some((f) => f.root === root)) failed.push({ root, reason: (e as Error).message });
    };
    const done = new Set<StoreGroup>();
    const doneClusters = new Set<StoreCluster>();
    for (const [root] of entries) {
      const own = rootErrors.get(root);
      if (own !== undefined) { fail(root, own); continue; }
      const g = storeOfRoot.get(root);
      if (g === undefined || done.has(g)) continue;
      done.add(g);
      // Under continueOnFailure a store that cannot be sanitized loses only
      // its own twins (its cluster's: the stores sharing its directories),
      // never another's; a work tree whose own reads failed is named, and
      // the store is twinned from the others.
      const read = readOf.get(g)!;
      if (!read.ok) {
        if (!opts.continueOnFailure) throw read.e;
        for (const r of g.roots) fail(r, read.e);
        continue;
      }
      for (const [r, e] of read.v.rootErrors) fail(r, e);
      const c = clusterOf.get(g);
      if (c === undefined || doneClusters.has(c)) continue;
      doneClusters.add(c);
      const members = c.stores.map((id) => groupOfId.get(id)!);
      const mine: ObjectTwin[] = [];
      const bytesBefore = rebuiltBytes;
      try {
        const memberReads = members.flatMap((m) => {
          const r = readOf.get(m)!;
          return r.ok && r.v.read !== null ? [r.v.read] : [];
        });
        const got = await twinCluster(c, members, memberReads, mine);
        repos += got.repos;
        blobs += got.blobs;
        packsRebuilt += got.packsRebuilt;
        cacheHits += got.cacheHits;
        twins.push(...mine);
      } catch (e) {
        if (!opts.continueOnFailure) throw e;
        rebuiltBytes = bytesBefore;
        for (const m of members) for (const r of m.roots) fail(r, e);
      }
    }
    pruneCache(opts.cacheDir, used);
    // The next launch's prefetch (twin-prefetch.ts): the work trees whose
    // history state this launch read, and the packs it served. A hint only.
    if (opts.hintFile !== undefined) {
      writeLaunchHint(opts.hintFile, { stores: reads.statesAsked, packs: [...used].sort() });
    }
    return {
      twins, repos, blobs, packsRebuilt, cacheHits, walks, scans, lockedIds: [...lockedIds].sort(), roots: [...byRepo.keys()].sort(), indexPaths,
      ...(opts.resolved !== undefined ? { fromArbiter: fromArbiter.arbiter } : {}),
      ...(opts.continueOnFailure ? { failed } : {}),
    };
  } finally {
    ownSession?.close();
    await sealing.flush();
    if (opts.hashes === undefined) hashes.close();
  }

  /** The read half of one object store: every work tree's protected
   *  versions (each work tree's failure kept apart) and the object
   *  directories it reads, or a null read when it has nothing to hide. */
  async function readStore(g: StoreGroup): Promise<{ read: StoreRead | null; rootErrors: Array<[string, unknown]> }> {
    const store: StoreReads = { reads, roots: g.roots, found: [] };
    const commonDir = realpath(g.facts.commonDir) ?? g.facts.commonDir;
    const hashLen = g.facts.hashLen;
    // What the store protects this launch: a protected file of one of its
    // work trees, or a path a label above `public` decides.
    const isProtected = (rel: string): boolean => g.roots.some((r) =>
      (byRepo.get(r) ?? []).includes(rel) || (labels.length > 0 && labelledAbovePublic(join(r, rel), compiledLabels)));
    // Every object the store holds is checked once, reachable or not
    // (store-scan.ts, confidentiality.md §7.2a "Every stored object is
    // checked once"), beside the walks.
    const scanP = scanTheStore(g, commonDir, isProtected);
    scanP.catch(() => undefined);
    const per = await Promise.all(g.roots.map(async (root) => {
      const rels = byRepo.get(root) ?? [];
      try {
        const [fromFiles, fromLabels] = await allSettledOrFirstError([
          rels.length > 0 ? protectedBlobsOf(git, root, rels, opts.walkCacheDir, walks, sealing, store) : Promise.resolve([] as string[]),
          labels.length > 0
            ? labelledBlobsOf(git, root, compiledLabels, labelKey, opts.walkCacheDir, walks, opts.resolved?.get(root), fromArbiter, sealing, store)
            : Promise.resolve([] as string[]),
        ]);
        return { root, ok: true as const, v: [...fromFiles, ...fromLabels] };
      } catch (e) {
        return { root, ok: false as const, e };
      }
    }));
    const rootErrs: Array<[string, unknown]> = per.flatMap((p) => (p.ok ? [] : [[p.root, p.e] as [string, unknown]]));
    // The scan's failure fails the store (fail closed: what it would have
    // found could be readable).
    let scan: StoreScan | null;
    try {
      scan = await scanP;
    } catch (e) {
      if (e instanceof AlternatesError) throw e;
      throw new GitObjectTwinError(`${g.roots[0]}: could not check every object its repository stores (${(e as Error).message})`);
    }
    // Every work tree failed: the store has nothing it can be twinned from.
    if (rootErrs.length === per.length && per.length > 0) throw rootErrs[0]![1];
    // A version once found protected stays protected while its path is
    // (locked-memory.ts, confidentiality.md §7.2a "A version once locked
    // stays locked"): what the store's memory holds for a path protected now
    // joins what was found, reachable or not; what was found joins the
    // memory. Only ever added to, so it needs no seal.
    const memFile = opts.walkCacheDir === undefined ? undefined : lockedMemoryFile(opts.walkCacheDir, commonDir);
    const rememberedPairs: Array<[string, string]> = [];
    if (memFile !== undefined) {
      for (const [p, names] of readLockedMemory(memFile, commonDir)) if (isProtected(p)) for (const n of names) rememberedPairs.push([n, p]);
    }
    // The scan's versions at paths protected now, then the pathless blobs
    // the token rule hides (it reads every protected version known here).
    const scanned: Array<[string, string]> = [];
    if (scan !== null) {
      scanned.push(...scan.pairs);
      const working: Array<[string, string]> = [];
      for (const r of g.roots) for (const rel of byRepo.get(r) ?? []) working.push([join(r, rel), rel]);
      try {
        scanned.push(...await scan.finish([...store.found!, ...rememberedPairs, ...scanned], working));
      } catch (e) {
        throw new GitObjectTwinError(`${g.roots[0]}: could not check the blobs no tree names in its repository (${(e as Error).message})`);
      }
      store.found!.push(...scanned);
    }
    if (memFile !== undefined) rememberLocked(memFile, commonDir, store.found!);
    const remembered = [...new Set([...rememberedPairs.map(([n]) => n), ...scanned.map(([n]) => n)])].sort();
    // Counted as found only where the store still holds one (twinCluster).
    const byPath = [...new Set(per.flatMap((p) => (p.ok ? p.v : [])))].sort();
    if (byPath.length === 0 && remembered.length === 0 && blobLocks.length === 0) return { read: null, rootErrors: rootErrs };
    // Plan 14 §8.2: only the ids of this repository's object format apply.
    const locked = lockedNamesFor(blobLocks, hashLen);
    const found = [...new Set([...byPath, ...remembered, ...locked])].sort();
    if (found.length === 0) return { read: null, rootErrors: rootErrs };
    for (const n of found) lockedIds.add(`${hashLen === 32 ? "sha256" : "sha1"}:${n}`);
    // Every object directory the store reads, its alternates' alternates
    // too; one it cannot tell fails the store (objectStoreClosure).
    const { dirs } = objectDirsOfFacts(g.facts, opts.alternatesIo);
    return { read: { found, byPath, hashLen, dirs }, rootErrors: rootErrs };
  }

  /** The scan of one store (store-scan.ts) for what it protects this launch,
   *  or null when it protects no path (nothing a scan could find). */
  async function scanTheStore(g: StoreGroup, commonDir: string, isProtected: (rel: string) => boolean): Promise<StoreScan | null> {
    const rels = [...new Set(g.roots.flatMap((r) => byRepo.get(r) ?? []))].sort();
    const specs = labels.length > 0 ? g.roots.map((r) => [r, historyPathspecs(r, compiledLabels)] as const).filter(([, s]) => s === null || s.length > 0) : [];
    if (rels.length === 0 && specs.length === 0) return null;
    // Equal keys, equal answers: the protected files (relative), and where
    // a label reaches, the work tree, its pathspecs and the labels.
    const key = createHash("sha256").update(JSON.stringify([rels, specs, specs.length > 0 ? labelKey : null])).digest("hex").slice(0, 32);
    const prefixes = topPrefixes(rels, specs.flatMap(([, s]) => s ?? []));
    const { dirs } = objectDirsOfFacts(g.facts, opts.alternatesIo);
    const max = opts.maxScanObjects ?? storeScanMaxFromEnv(process.env);
    const overCap = (what: string): null => {
      opts.log?.(
        `WARNING: mandu: the git object store of ${g.roots[0]} is too large to check every object (${what}; MANDU_GIT_STORE_SCAN_MAX_OBJECTS): ` +
        "a protected file's version that no branch, tag or reflog reaches is not looked for there.",
      );
      return null;
    };
    let got: StoreScan;
    const mine = newStoreScanStats();
    const t0 = performance.now();
    try {
      got = await scanStore({
        git, cwd: g.roots[0]!, commonDir, hashLen: g.facts.hashLen, dirs,
        ...(opts.walkCacheDir !== undefined ? { stateRoot: join(opts.walkCacheDir, "store-scan") } : {}),
        sealing, stats: mine, maxObjects: max,
        onFirstScan: () => sealing.noteStoreScan(),
      }, { key, isProtected, prefixes });
    } catch (e) {
      if (e instanceof StoreScanOverCap) return overCap(e.message);
      throw e;
    } finally {
      addStoreScanStats(scans, mine);
    }
    // Kept for `mandu log` (never a value): what a scan that did read cost.
    if (mine.first + mine.incremental + mine.reevaluated > 0) {
      opts.log?.(
        `mandu: checked the git object store of ${g.roots[0]}: ${mine.asked + mine.loose} new object(s), ${mine.read} read, ` +
        `${mine.gitCalls} git call(s)${mine.first > 0 ? " (its first check)" : ""} in ${Math.round(performance.now() - t0)} ms`,
      );
    }
    if (got.overCap !== null) return overCap(`${got.overCap} objects, over ${max}`);
    return got;
  }

  /** The twin half of one cluster of stores (clusterObjectStores): each
   *  object directory inventoried once for the union of the names of the
   *  stores that read it, every pack holding one rebuilt (its build runs in
   *  the first store reading it), all or nothing. */
  async function twinCluster(
    c: StoreCluster, members: readonly StoreGroup[], storeReads: readonly StoreRead[], out: ObjectTwin[],
  ): Promise<{ repos: number; blobs: number; packsRebuilt: number; cacheHits: number }> {
    const label = members.flatMap((m) => m.roots).join(", ");
    if (c.unsupported.length > 0) throw new GitObjectTwinError(`${label}: ${c.unsupported.join("; ")} cannot be sanitized`);
    const groupOfIdHere = new Map(c.stores.map((id, i) => [id, members[i]!]));
    const inventories = new Map<string, ObjectDirInventory>();
    const rebuilds: Array<{ r: PackRebuild; hashLen: number; by: StoreGroup }> = [];
    const deny = new Set<string>();
    for (const d of c.dirs) {
      if (!exists(d.dir)) continue;
      const by = groupOfIdHere.get(d.by[0]!)!;
      let inv: ObjectDirInventory;
      try {
        inv = inventoryObjectDir(d.dir, d.names, d.hashLen);
      } catch (e) {
        throw new GitObjectTwinError(`could not read the object store ${d.dir} of ${by.roots[0]}: ${(e as Error).message}`);
      }
      inventories.set(d.dir, inv);
      const plan = planObjectTwins([inv], d.names);
      if (plan.unsupported.length > 0) throw new GitObjectTwinError(`${label}: ${plan.unsupported.join("; ")} cannot be sanitized`);
      for (const r of plan.rebuild) rebuilds.push({ r, hashLen: d.hashLen, by });
      for (const x of plan.deny) deny.add(x);
    }
    // What the count says, per store: every version found by path (as
    // before), and each locked blob it actually holds; a store counts as a
    // repository when a directory it reads holds one of its own names.
    let repos = 0;
    let blobs = 0;
    for (const s of storeReads) {
      const { found, byPath, hashLen, dirs } = s;
      const mine = new Set(found);
      const pathSet = new Set(byPath);
      let holds = false;
      const held = new Set<string>();
      for (const dir of dirs) {
        const inv = inventories.get(dir);
        if (inv === undefined) continue;
        for (const p of inv.packs) for (const n of p.held) if (mine.has(n)) { holds = true; if (!pathSet.has(n)) held.add(n); }
        for (const l of inv.looseProtected) {
          const n = l.slice(-(hashLen * 2 + 1)).replace("/", "");
          if (mine.has(n)) { holds = true; if (!pathSet.has(n)) held.add(n); }
        }
      }
      if (!holds) continue;
      repos++;
      blobs += byPath.length + held.size;
    }
    let packsRebuilt = 0;
    let cacheHits = 0;
    if (rebuilds.length > 0) mkdirSync(opts.cacheDir, { recursive: true, mode: 0o700 });
    // Every cached pack of the cluster starts hashing at once (on the
    // workers); each is still checked, in order, before it is served.
    const cached = rebuilds.map(({ r, hashLen }) => {
      const f = cachedPack(opts.cacheDir, r, hashLen);
      return f !== null && r.pack.hasRev && f.rev === null ? null : f;
    });
    sealing.prefetch(cached.flatMap((f, i) => (f === null ? [] : packParts(rebuilds[i]!.r, f).map((p) => p.path))));
    for (const [i, { r, hashLen, by }] of rebuilds.entries()) {
      const root = by.roots[0]!;
      const commonDir = by.facts.commonDir;
      used.add(r.key);
      let files: ReturnType<typeof cachedPack> = cached[i] ?? null;
      // Plan 14 §11.2: a cached pack is served only when a seal of the
      // current epoch vouches for every file of it the twin uses (the .idx
      // check in cachedPack does not see a pack holding the real bytes).
      if (files !== null && !(await sealing.verifyFiles(SEAL_KIND_OBJECT_TWIN, packParts(r, files)))) files = null;
      if (files === null) {
        rebuiltBytes += r.pack.size;
        if (rebuiltBytes > maxBytes) {
          throw new GitObjectTwinError(
            `${root}: sanitizing its git history needs ${Math.ceil(rebuiltBytes / 1048576)} MiB of packs rebuilt, over the ` +
              `${Math.floor(maxBytes / 1048576)} MiB cap (MANDU_GIT_TWIN_MAX_MB)`,
          );
        }
        opts.log?.(`mandu: sanitizing ${r.pack.base.slice(r.pack.base.lastIndexOf("/") + 1)}.pack (${Math.ceil(r.pack.size / 1048576)} MiB) of ${root}: it holds ${r.exclude.length} protected version(s)`);
        await buildPack(git, root, opts.cacheDir, r, hashLen, commonDir);
        files = cachedPack(opts.cacheDir, r, hashLen);
        if (files === null) throw new GitObjectTwinError(`${root}: the sanitized copy of ${r.pack.base}.pack was not produced`);
        await Promise.all(packParts(r, files).map((part) => sealing.sealFile(SEAL_KIND_OBJECT_TWIN, part.key, part.path)));
        packsRebuilt++;
      } else {
        cacheHits++;
        try { const now = new Date(); utimesSync(join(opts.cacheDir, r.key), now, now); } catch { /* best effort */ }
      }
      out.push({ targetPath: `${r.pack.base}.pack`, twinPath: files.pack, kind: "object" });
      out.push({ targetPath: `${r.pack.base}.idx`, twinPath: files.idx, kind: "object" });
      if (r.pack.hasRev) {
        if (files.rev === null) throw new GitObjectTwinError(`${root}: the sanitized copy of ${r.pack.base}.pack has no reverse index`);
        out.push({ targetPath: `${r.pack.base}.rev`, twinPath: files.rev, kind: "object" });
      }
    }
    for (const d of [...deny].sort()) out.push({ targetPath: d, twinPath: opts.denyFile, kind: "deny" });
    return { repos, blobs, packsRebuilt, cacheHits };
  }
}

// ── Copies prepared ahead of time (plan 14 §11.1 R3) ────────────────────────

/** How many repositories, packs and bytes of copies one launch binds from
 *  the arbiter's prepared copies: each pack is two or three mounts (or guard
 *  entries), and its copy is hashed at use. */
export const PREPARED_MAX_REPOS = 16;
export const PREPARED_MAX_PACKS = 64;
export const PREPARED_MAX_VERIFY_BYTES = 2048 * 1048576;

/** MANDU_GIT_PREPARED_REPOS → the repository cap (0: bind none). Pure. */
export function preparedMaxReposFromEnv(env: Record<string, string | undefined>): number {
  const v = env["MANDU_GIT_PREPARED_REPOS"];
  if (v === undefined || v.trim() === "") return PREPARED_MAX_REPOS;
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 ? n : PREPARED_MAX_REPOS;
}

export interface PreparedCopyOpts {
  /** The object-twin cache (the arbiter prepares into the same one). */
  cacheDir: string;
  denyFile: string;
  /** The locked set the guard gets (`sha1:<hex>` / `sha256:<hex>`, the
   *  empty blob out): a pack's copy must exclude exactly the ids of it the
   *  pack holds, or it is not the copy this launch needs. */
  lockedIds: readonly string[];
  /** Repositories this launch prepared itself (their twins win). */
  skipRoots?: ReadonlySet<string>;
  /** Object-store files already twinned (an alternate two repositories share). */
  skipTargets?: ReadonlySet<string>;
  seals?: CacheSealClient;
  git?: GitRunner;
  exists?: (p: string) => boolean;
  log?: (m: string) => void;
  maxRepos?: number;
  maxPacks?: number;
  maxVerifyBytes?: number;
  /** The launch's file hashes (GitObjectTwinOpts.hashes). */
  hashes?: FileHashes;
}

export interface PreparedCopyResult {
  twins: ObjectTwin[];
  /** Repositories whose every pack holding a locked id is served its copy. */
  bound: string[];
  /** Repositories left to the guard's backstop (R4), each with why. */
  notReady: Array<{ root: string; reason: string }>;
  /** Repositories past the launch's caps (also left to the backstop). */
  overCap: string[];
}

/**
 * The twins of the copies the arbiter prepared ahead of time (plan 14 §11.1
 * R3) for the repositories it lists (`gitHistoryLocks` `prepared`). The list
 * is only a hint: for each repository the launcher reads its object store
 * itself, finds each pack holding a locked id and the exclusion the guard's
 * set gives it (so the cache key), and binds a copy ONLY when it is present,
 * its index lists none of the excluded ids, and every file served matches a
 * seal of the arbiter's current epoch (hashed here, as a cached twin is). A
 * repository is all or nothing: one pack without a ready copy leaves the
 * whole repository to the guard's backstop, which refuses its object files
 * (R4). Never throws for a repository: a failure is a `notReady` entry.
 * The object directories are every one the repository reads, alternates
 * followed (objectDirsOf, the arbiter's closure too); a pack two listed
 * repositories reach (an object directory shared through alternates) is
 * verified and served once.
 */
export async function preparedCopyTwins(
  repos: ReadonlyArray<{ root: string; format: "sha1" | "sha256" }>, opts: PreparedCopyOpts,
): Promise<PreparedCopyResult> {
  const git = opts.git ?? defaultGitRunner;
  const exists = opts.exists ?? existsSync;
  const maxRepos = opts.maxRepos ?? PREPARED_MAX_REPOS;
  const maxPacks = opts.maxPacks ?? PREPARED_MAX_PACKS;
  const maxVerify = opts.maxVerifyBytes ?? PREPARED_MAX_VERIFY_BYTES;
  const out: PreparedCopyResult = { twins: [], bound: [], notReady: [], overCap: [] };
  if (opts.lockedIds.length === 0 || repos.length === 0) return out;
  const sealing = new SealSession(opts.seals, opts.log, opts.hashes);
  let packs = 0;
  let verified = 0;
  const seen = new Set<string>();
  /** The targets already served by a repository bound before. */
  const served = new Set<string>();
  try {
    for (const { root, format } of repos) {
      if (seen.has(root) || opts.skipRoots?.has(root)) continue;
      seen.add(root);
      if (out.bound.length >= maxRepos) { out.overCap.push(root); continue; }
      try {
        const { dirs, hashLen } = await objectDirsOf(git, root);
        if ((hashLen === 32 ? "sha256" : "sha1") !== format) {
          out.notReady.push({ root, reason: "its object format is not the one its copies were prepared for" });
          continue;
        }
        const names = lockedNamesFor(opts.lockedIds, hashLen);
        const plan = planObjectTwins(dirs.filter((d) => exists(d)).map((d) => inventoryObjectDir(d, names, hashLen)), names);
        if (plan.unsupported.length > 0) { out.notReady.push({ root, reason: `${plan.unsupported.join("; ")} cannot be sanitized` }); continue; }
        // Only loose locked objects (no pack holds one): no copy is needed,
        // the backstop refuses those objects alone and git keeps working.
        if (plan.rebuild.length === 0) continue;
        const fresh = plan.rebuild.filter((r) => !served.has(`${r.pack.base}.pack`));
        if (packs + fresh.length > maxPacks) { out.overCap.push(root); continue; }
        const mine: ObjectTwin[] = [];
        let bytes = 0;
        let why: string | null = null;
        let capped = false;
        for (const r of fresh) {
          if (opts.skipTargets?.has(`${r.pack.base}.pack`)) { why = "a pack of it is twinned by this launch already"; break; }
          const files = cachedPack(opts.cacheDir, r, hashLen);
          if (files === null || (r.pack.hasRev && files.rev === null)) { why = "its sanitized copies are not prepared yet"; break; }
          const parts = packParts(r, files);
          let size = 0;
          for (const p of parts) { try { size += statSync(p.path).size; } catch { /* verifyFiles refuses it */ } }
          if (verified + bytes + size > maxVerify) { capped = true; break; }
          bytes += size;
          if (!(await sealing.verifyFiles(SEAL_KIND_OBJECT_TWIN, parts))) { why = "its prepared copies are not sealed in the current epoch"; break; }
          mine.push({ targetPath: `${r.pack.base}.pack`, twinPath: files.pack, kind: "object" });
          mine.push({ targetPath: `${r.pack.base}.idx`, twinPath: files.idx, kind: "object" });
          if (r.pack.hasRev) mine.push({ targetPath: `${r.pack.base}.rev`, twinPath: files.rev!, kind: "object" });
        }
        if (capped) { out.overCap.push(root); continue; }
        if (why !== null) { out.notReady.push({ root, reason: why }); continue; }
        for (const d of plan.deny) if (!served.has(d)) mine.push({ targetPath: d, twinPath: opts.denyFile, kind: "deny" });
        // Used: the launcher's 30-day prune and the arbiter's keep it.
        for (const r of fresh) { try { const now = new Date(); utimesSync(join(opts.cacheDir, r.key), now, now); } catch { /* best effort */ } }
        packs += fresh.length;
        verified += bytes;
        for (const t of mine) served.add(t.targetPath);
        out.twins.push(...mine);
        out.bound.push(root);
      } catch (e) {
        out.notReady.push({ root, reason: (e as Error).message });
      }
    }
    return out;
  } finally {
    await sealing.flush();
  }
}

// ── The copies a session serves stay in use while it runs ───────────────────

/** How often a running launch marks the copies it serves used: well under the
 *  arbiter's prune grace (arbiter/policy/prepared-copies.ts `pruneGraceMs`,
 *  10 minutes). */
export const COPIES_IN_USE_INTERVAL_MS = 4 * 60_000;

/**
 * The cache entries a launch's object twins are served from: each sanitized
 * copy is one directory `<cacheDir>/<key>` holding its pack, index and
 * reverse index (`cachedPack`). Deny twins and anything outside the cache are
 * left out. Sorted, unique. Pure.
 */
export function servedCopyDirs(twins: readonly ObjectTwin[], cacheDir: string): string[] {
  const root = resolve(cacheDir);
  const out = new Set<string>();
  for (const t of twins) {
    if (t.kind !== "object") continue;
    const dir = dirname(resolve(t.twinPath));
    if (dir !== root && dirname(dir) === root) out.add(dir);
  }
  return [...out].sort();
}

export interface CopiesInUse {
  /** Stop marking (the session ended). Idempotent. */
  stop(): void;
}

/**
 * Plan 14 §11.1 R3 (a), 2026-10-17: keep the copies a session serves from
 * being pruned while it runs. The arbiter removes a copy no repository wants
 * any more (a lock added or lifted gives a pack a new key; a repository
 * capped or forgotten) unless a launch used it within its grace, and a
 * launch marked what it binds only once, at its start. Where the guard
 * serves the copies by path (the guard-only postures: no bind holds the
 * file), a session longer than the grace lost them, and git in that
 * repository failed for the rest of it (fail closed, never the real pack:
 * the guard refuses an open whose twin cannot be opened). Marking each
 * served entry every `COPIES_IN_USE_INTERVAL_MS` keeps them for the
 * session's life; the mark is the same `utimes` a launch's use makes, best
 * effort. The timer never holds the launcher open.
 */
export function keepCopiesInUse(
  dirs: readonly string[],
  opts: { intervalMs?: number; touch?: (dir: string) => void; every?: (fn: () => void, ms: number) => { unref?: () => void; clear: () => void } } = {},
): CopiesInUse {
  if (dirs.length === 0) return { stop: () => {} };
  const touch = opts.touch ?? ((dir: string) => { try { const now = new Date(); utimesSync(dir, now, now); } catch { /* best effort: gone */ } });
  const every = opts.every ?? ((fn: () => void, ms: number) => {
    const t = setInterval(fn, ms);
    return { unref: () => { t.unref(); }, clear: () => { clearInterval(t); } };
  });
  const list = [...dirs];
  const timer = every(() => { for (const d of list) touch(d); }, opts.intervalMs ?? COPIES_IN_USE_INTERVAL_MS);
  timer.unref?.();
  let stopped = false;
  return { stop: () => { if (!stopped) { stopped = true; timer.clear(); } } };
}
