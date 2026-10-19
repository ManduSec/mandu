/**
 * prepared-copies — sanitized copies of every known repository's packs that
 * hold a locked object, built AHEAD OF TIME in the arbiter's background
 * (docs/design/confidentiality/confidentiality-plan-14-policy-suggestions.md §11.1 R3).
 *
 * A lock holds in the repositories a launch prepares: the launcher builds
 * sanitized packs (the object twins) for its workspace and for the
 * repositories its confined files and labels lie in. Every other repository
 * holding a locked object is covered by the guard's backstop (R4), which
 * refuses its object files: git there stops working for the session. This
 * module prepares the copies those repositories need BEFORE any launch, so
 * a launch anywhere binds (or has the guard serve) them and git keeps
 * working with the locked versions missing:
 *
 *   - for each known repository (known-repos.ts, R1, in the registry's
 *     order), the packs whose `.idx` lists an id of the GLOBAL LOCKED SET
 *     (lock-resolution.ts, R2; the empty blob never counts), in EVERY object
 *     directory it reads: its own and every alternate it reaches, an
 *     alternate's alternates too (../src/git-alternates.ts, the launcher's
 *     closure, one file in both packages). Each real object directory is
 *     inventoried once and a pack two repositories reach is one copy
 *     (`inventoryStores`, confidentiality.md §7.2a "Stores shared through
 *     alternates"); an alternates file that cannot be read as git reads it
 *     fails the repository (no copy, the backstop stays), never a shorter
 *     list;
 *   - each such pack is rebuilt without those ids into the SAME cache the
 *     launcher reads (the path table's `object-twins`), under the SAME key
 *     (`rebuildKey`: the pack's name and the excluded ids), so a launch that
 *     computes that exclusion finds it as a cache hit;
 *   - every file the launcher serves (`.pack`, `.idx`, `.rev`) is SEALED in
 *     the current epoch through the seal store directly (cache-seals.ts, kind
 *     `object-twin`, key `<cache key>/<file name>`): the arbiter owns the
 *     store, so no socket is involved.
 *
 * NEVER DURING AN UNCONFINED PERIOD. No build starts while the store honours
 * no seal (an unconfined launch is live, or the confidentiality axis is off),
 * and a build is sealed only when the epoch it started in is still current
 * and honoured when it ends: a copy an unconfined writer could have touched
 * mid-build is discarded, never sealed. The cycle resumes when the period
 * ends (the rotation kicks it). What this process built itself it remembers
 * (sha256 and size, in memory only): after a rotation voids the seals, a
 * file whose bytes still match is sealed again without a rebuild. Nothing
 * persisted is trusted for that (a record on disk would survive the
 * rotation that is meant to void it).
 *
 * BUDGET, lowest priority. One repository at a time, one pack at a time,
 * `git pack-objects` at nice 19 (`prepGitCommand`: where the host has a
 * `nice` at a fixed system path). A per-cycle cap on the bytes of source
 * packs rebuilt (`cycleBytes`, MANDU_GIT_PREP_CYCLE_MB, default the
 * launcher's MANDU_GIT_TWIN_MAX_MB, 1024 MiB) and a total cap on what the
 * prepared copies may hold (`totalBytes`, MANDU_GIT_PREP_TOTAL_MB, default
 * 4096 MiB), both counted by source pack size (an upper bound of the copy).
 * A repository with a pack over the cycle cap, or that would take the total
 * past its cap, is CAPPED (never built, reported); one whose packs do not
 * all fit this cycle is PENDING and continues next cycle. Copies of packs
 * that no longer exist or no longer hold a locked id are pruned.
 *
 * EVERY git call runs HARDENED and SANDBOXED like the arbiter's other
 * runners (`prepGit`, docs/design/architecture/write-protection.md §8.2, §8.5): behind
 * secret-history-scan.ts HARDENED_GIT_ARGS (../src/hardened-git.ts: no
 * program a repository names, no transport, no lazy fetch) with the
 * scrubbed environment, and inside the git sandbox where one can be made
 * (bubblewrap on Linux, Seatbelt on macOS, where no program but git can
 * start: no network, the filesystem read-only), whose only writable bind
 * is the build's own work directory in the cache (the output, the empty object
 * directory and the private bare repository below). On top of that (defense
 * in depth, not a substitute), `pack-objects` and `index-pack` read NO
 * REPOSITORY CONFIG: they run against a private empty bare repository
 * (`--git-dir`, its own object format), read the repository's objects
 * through `GIT_ALTERNATE_OBJECT_DIRECTORIES`, with the user's and the
 * system's config off (`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`):
 * nothing the repository (which the agent may have written) configures is
 * read, not even a key no `-c` names.
 *
 * EVERY git call SETTLES (write-protection.md §8.5.1): the runner kills a call's
 * whole process group (a bubblewrap killed in its start-up otherwise left
 * its sandbox child holding the pipes forever, and the cycle, `stop()` and
 * the arbiter's close with it), and `call` gives up on one not settled by
 * its deadline plus `settleGraceMs`, or in flight at `stop()`. A call given
 * up on is a failure: the repository is failed for the cycle and stays with
 * the backstop (R4).
 *
 * WHERE IT RUNS, and why in the arbiter (decided 2026-09-30): the heavy part
 * is already a child process (`git pack-objects`); what stays on the event
 * loop is a directory listing, an index lookup bounded by the locked set
 * (a binary search per id, or one read of the name table for a large set:
 * `heldIn`), and hashing, which is streamed.
 * A separate worker would need its own access to the seal store, which the
 * arbiter owns and which must not be reachable from anything the agent can
 * reach (§11.2); in-process it is a method call.
 *
 * ONLY WHERE A LAUNCH USES IT (2026-09-30): the daemon prepares on Linux
 * only. The consumers (the launcher's object twins, the guard) are Linux
 * only, so on macOS every copy would cost `git pack-objects` over the
 * user's repositories for nothing (`preparedCopiesOff`).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code. The index readers
 * (`idxObjectNames`, `idxLookup`), the cache key (`rebuildKey`), the object
 * directory inventory, the cached-copy check (`cachedPack`, `packParts`) and
 * the build (`buildPack`, `alternateObjectDirsEnv`) are PORTED from
 * launcher/src/git-object-twins.ts (the arbiter never imports the
 * launcher); tests/stack/prepared-copies-parity.test.ts
 * builds with both and proves the launcher takes the arbiter's copy as its
 * own (the same key, the same seal). The alternates closure is not ported
 * but SHARED: ../src/git-alternates.ts is the launcher's file, byte for byte
 * (the same parity test holds the two copies equal).
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  accessSync, closeSync, constants as fsConstants, existsSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, realpathSync, renameSync, rmSync,
  statSync, utimesSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { CACHE_SEAL_KINDS, type CacheSeal, type CacheSealStatus } from "./cache-seals.js";
import { defaultAlternatesIo, objectStoreClosure, type AlternatesIo } from "../src/git-alternates.js";
import { gitCommand, gitSandbox, type GitSandbox } from "../src/hardened-git.js";
import { runChild, type RunningChild } from "../src/child-run.js";
import { HARDENED_GIT_ARGS, historyGitEnv } from "./secret-history-scan.js";

// ── Pure: the pack index (ported from launcher git-object-twins.ts) ─────────

/** The object names a version-2 pack index lists, in index order. Throws on
 *  a file that is not a v2 index. Pure. */
export function idxObjectNames(buf: Buffer, hashLen = 20): string[] {
  if (buf.length < 8 + 256 * 4) throw new Error("pack index too small");
  if (buf.readUInt32BE(0) !== 0xff744f63 || buf.readUInt32BE(4) !== 2) throw new Error("not a version-2 pack index");
  const count = buf.readUInt32BE(8 + 255 * 4);
  const start = 8 + 256 * 4;
  if (buf.length < start + count * hashLen) throw new Error("pack index truncated");
  const out: string[] = new Array(count);
  for (let i = 0; i < count; i++) out[i] = buf.subarray(start + i * hashLen, start + (i + 1) * hashLen).toString("hex");
  return out;
}

export type ByteReader = (offset: number, len: number) => Buffer;

/** Which of `names` a version-2 pack index lists (sorted, unique), by its
 *  fanout table and a binary search. Throws on a file that is not a v2
 *  index. Pure given `read`. */
export function idxLookup(read: ByteReader, names: readonly string[], hashLen = 20): string[] {
  const head = read(0, 8 + 256 * 4);
  if (head.length < 8 + 256 * 4) throw new Error("pack index too small");
  if (head.readUInt32BE(0) !== 0xff744f63 || head.readUInt32BE(4) !== 2) throw new Error("not a version-2 pack index");
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

/** Which of `names` an index lists: by binary search while the set is small
 *  next to the index (a few reads per name), by one read of its name table
 *  when the set is large (the global set can hold 200 000 ids: a search per
 *  id would hold the event loop for seconds). The same answer either way. */
export function heldIn(idxPath: string, names: readonly string[], hashLen = 20): string[] {
  const size = statSync(idxPath).size;
  const count = Math.max(0, Math.floor((size - 8 - 256 * 4) / (hashLen + 8)));
  if (names.length * 24 < count) return idxLookupFile(idxPath, names, hashLen);
  const listed = new Set(idxObjectNames(readFileSync(idxPath), hashLen));
  return [...new Set(names.filter((n) => listed.has(n)))].sort();
}

/** The cache key of a sanitized pack: sha256 of the pack's name and the
 *  excluded names (the launcher's `rebuildKey`, byte for byte). Pure. */
export function rebuildKey(packBase: string, exclude: readonly string[]): string {
  const name = packBase.slice(packBase.lastIndexOf("/") + 1);
  return createHash("sha256").update(`${name}\n${[...exclude].sort().join("\n")}`).digest("hex").slice(0, 32);
}

/** Do two lists name the same objects (as sets)? The check that a copy's
 *  index, rebuilt from its content, names exactly what was asked for (the
 *  launcher's `sameNames`). Pure. */
export function sameNames(got: readonly string[], want: readonly string[]): boolean {
  const a = [...new Set(got)].sort();
  const b = [...new Set(want)].sort();
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** `GIT_ALTERNATE_OBJECT_DIRECTORIES` for `dirs` (git's quoting rule). */
export function alternateObjectDirsEnv(dirs: readonly string[]): string {
  return [...new Set(dirs)].map((d) => (d.includes(":") || d.startsWith("\"") ? JSON.stringify(d) : d)).join(":");
}

/** The empty blob, in both formats: never locked (the launcher's
 *  git-lock-backstop.ts EMPTY_BLOB_IDS, bare). */
export const EMPTY_BLOBS: { readonly sha1: string; readonly sha256: string } = {
  sha1: "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
  sha256: "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813",
};

/** The ids a copy excludes, per object format: the locked set, well formed,
 *  the empty blob out (the set the launcher hands the guard). Pure. */
export function exclusionSet(set: { sha1: readonly string[]; sha256: readonly string[] }): { sha1: string[]; sha256: string[] } {
  const f = (xs: readonly string[], n: number, empty: string): string[] =>
    [...new Set(xs.filter((x) => x.length === n && /^[0-9a-f]+$/.test(x) && x !== empty))].sort();
  return { sha1: f(set.sha1, 40, EMPTY_BLOBS.sha1), sha256: f(set.sha256, 64, EMPTY_BLOBS.sha256) };
}

// ── Pure: the plan of one cycle ─────────────────────────────────────────────

/** One pack of a repository that holds a locked id. */
export interface PrepPack {
  /** `<objects>/pack/pack-<hash>` (no extension). */
  base: string;
  /** The locked ids it holds (sorted). */
  exclude: string[];
  key: string;
  /** The source pack's size: the unit both caps count in. */
  size: number;
  hasRev: boolean;
  /** Present in the cache and sealed in the current epoch. */
  ready: boolean;
}

/** One known repository, as a cycle found it. */
export interface PrepRepo {
  root: string;
  format: "sha1" | "sha256";
  packs: PrepPack[];
  /** Why it cannot be sanitized (an incremental multi-pack-index), if so. */
  unsupported?: string;
}

export interface PrepCaps {
  /** Bytes of source packs rebuilt in one cycle. */
  cycleBytes: number;
  /** Bytes the prepared copies may hold together. */
  totalBytes: number;
}

export type PrepState = "ready" | "pending" | "capped" | "failed";

export interface PrepPlan {
  /** The packs to build this cycle, in order. */
  build: Array<{ root: string; pack: PrepPack }>;
  state: Map<string, { state: PrepState; reason?: string }>;
  /** Every key a repository that is not capped wants (kept, never pruned). */
  wanted: Set<string>;
  /** Source bytes the wanted copies stand for. */
  wantedBytes: number;
}

/**
 * The plan of one cycle, over the repositories in the registry's order.
 * A repository with a pack over the cycle cap, or whose packs would take the
 * total past its cap, is CAPPED: nothing of it is built or kept. Otherwise
 * its missing packs are built while the cycle's budget lasts (one pack that
 * does not fit ends the cycle's building: lowest priority, one at a time);
 * a repository with a pack left is PENDING. A repository whose layout cannot
 * be sanitized is FAILED, whether or not a pack of it was found.
 *
 * A pack several repositories read (an object directory shared through
 * `objects/info/alternates`: `git clone --shared`, `--reference`, a chain
 * of them) is ONE copy (its key: the pack's name and the locked ids it
 * holds, the same whoever reaches it): its bytes count once against the
 * total, it is built once, and each repository reading it waits on that
 * one build. Pure.
 */
export function planPreparation(repos: readonly PrepRepo[], caps: PrepCaps): PrepPlan {
  const build: PrepPlan["build"] = [];
  const state: PrepPlan["state"] = new Map();
  const wanted = new Set<string>();
  const scheduled = new Set<string>();
  let total = 0;
  let cycleLeft = Math.max(0, caps.cycleBytes);
  let stopped = false;
  for (const r of repos) {
    if (r.unsupported !== undefined) { state.set(r.root, { state: "failed", reason: r.unsupported }); continue; }
    if (r.packs.length === 0) continue;
    const packs = [...new Map(r.packs.map((p) => [p.key, p])).values()];
    // Only the copies no repository before it counted add to the total.
    const bytes = packs.filter((p) => !wanted.has(p.key)).reduce((s, p) => s + p.size, 0);
    const missing = packs.filter((p) => !p.ready);
    const big = missing.find((p) => p.size > caps.cycleBytes);
    if (big !== undefined) {
      state.set(r.root, { state: "capped", reason: `a pack of ${mib(big.size)} MiB is over the ${mib(caps.cycleBytes)} MiB a cycle may rebuild` });
      continue;
    }
    if (total + bytes > caps.totalBytes) {
      state.set(r.root, { state: "capped", reason: `its ${mib(bytes)} MiB of packs would take the prepared copies past their ${mib(caps.totalBytes)} MiB cap` });
      continue;
    }
    total += bytes;
    for (const p of packs) wanted.add(p.key);
    if (missing.length === 0) { state.set(r.root, { state: "ready" }); continue; }
    for (const p of missing) {
      if (scheduled.has(p.key)) continue;
      if (stopped || p.size > cycleLeft) { stopped = true; break; }
      cycleLeft -= p.size;
      scheduled.add(p.key);
      build.push({ root: r.root, pack: p });
    }
    state.set(r.root, { state: "pending", reason: "its sanitized copies are being prepared" });
  }
  return { build, state, wanted, wantedBytes: total };
}

// ── The inventory: one per real object directory ────────────────────────────

/** One known repository, located: its object format and every object
 *  directory it reads, its own first (git-alternates.ts
 *  `objectStoreClosure`: an alternate's alternates followed, each once by
 *  its real path). */
export interface PrepStore {
  root: string;
  format: "sha1" | "sha256";
  dirs: readonly string[];
}

/** One object directory's packs holding a locked id (`inventoryPrepDir`). */
export interface PrepDir {
  packs: PrepPack[];
  /** Why its packs cannot be sanitized (an incremental multi-pack-index). */
  unsupported?: string;
}

/** The packs of one object directory whose `.idx` lists one of `names`
 *  (the launcher's `inventoryObjectDir`, for packs only: a loose locked
 *  object needs no copy, the guard refuses it alone and git keeps working).
 *  Throws when an index cannot be read. */
export function inventoryPrepDir(dir: string, names: readonly string[], hashLen: number): PrepDir {
  if (!existsSync(dir)) return { packs: [] };
  const packDir = join(dir, "pack");
  let entries: string[] = [];
  try { entries = readdirSync(packDir); } catch { /* no packs */ }
  const packs: PrepPack[] = [];
  for (const n of entries) {
    if (!/^pack-[0-9a-f]+\.idx$/.test(n)) continue;
    const base = join(packDir, n.slice(0, -4));
    if (!existsSync(`${base}.pack`)) continue;
    const held = heldIn(`${base}.idx`, names, hashLen);
    if (held.length === 0) continue;
    packs.push({ base, exclude: held, key: rebuildKey(base, held), size: statSync(`${base}.pack`).size, hasRev: existsSync(`${base}.rev`), ready: false });
  }
  if (packs.length > 0 && entries.includes("multi-pack-index.d")) {
    return { packs, unsupported: `${dir}/pack/multi-pack-index.d (an incremental multi-pack-index) cannot be sanitized` };
  }
  return { packs };
}

/**
 * The repositories of one cycle from their located stores, each object
 * directory inventoried ONCE (confidentiality.md §7.2a "Stores shared
 * through alternates"): every repository reading a directory gets the SAME
 * pack entries, so a pack two repositories reach is one copy, built once,
 * ready for both. The exclusions are the global locked set's (what the pack
 * holds of it), so the union of what every repository reaching it locks.
 * Fail closed: a directory read by repositories of two object formats, or
 * one whose index cannot be read, fails every repository reading it (no
 * copy; the guard's backstop keeps refusing its packs). A repository with
 * nothing locked in any directory it reads is left out. `yieldNow` runs
 * between directories (the event loop).
 */
export async function inventoryStores(
  stores: readonly PrepStore[], set: { sha1: readonly string[]; sha256: readonly string[] },
  opts: { inventoryDir?: typeof inventoryPrepDir; yieldNow?: () => Promise<void> } = {},
): Promise<{ repos: PrepRepo[]; failed: Map<string, string> }> {
  const inventoryDir = opts.inventoryDir ?? inventoryPrepDir;
  const formats = new Map<string, Set<"sha1" | "sha256">>();
  for (const s of stores) for (const d of s.dirs) formats.set(d, (formats.get(d) ?? new Set()).add(s.format));
  const byDir = new Map<string, PrepDir | { error: string }>();
  const repos: PrepRepo[] = [];
  const failed = new Map<string, string>();
  for (const s of stores) {
    const names = set[s.format];
    const packs: PrepPack[] = [];
    let unsupported: string | undefined;
    let error: string | undefined;
    for (const d of new Set(s.dirs)) {
      let got = byDir.get(d);
      if (got === undefined) {
        if ((formats.get(d)?.size ?? 0) > 1) got = { error: `${d} is read by repositories of two object formats and cannot be sanitized` };
        else {
          try {
            got = inventoryDir(d, names, s.format === "sha256" ? 32 : 20);
          } catch (e) {
            got = { error: `could not read the object store ${d}: ${(e as Error).message}` };
          }
          if (opts.yieldNow) await opts.yieldNow();
        }
        byDir.set(d, got);
      }
      if ("error" in got) { error ??= got.error; continue; }
      packs.push(...got.packs);
      if (got.unsupported !== undefined) unsupported ??= got.unsupported;
    }
    if (error !== undefined) { failed.set(s.root, error); continue; }
    if (packs.length === 0) continue;
    repos.push({ root: s.root, format: s.format, packs, ...(unsupported !== undefined ? { unsupported } : {}) });
  }
  return { repos, failed };
}

const mib = (n: number): number => Math.ceil(n / 1048576);

// ── Limits ──────────────────────────────────────────────────────────────────

export interface PrepLimits extends PrepCaps {
  /** One `pack-objects` run. */
  packTimeoutMs: number;
  /** One repository's inventory (`rev-parse`). */
  inventoryTimeoutMs: number;
  /** A copy this arbiter prepared and no longer wants is kept this long
   *  after its last use (a launch touches what it binds). */
  pruneGraceMs: number;
  /** How long past its own deadline a git call may take to settle before
   *  the preparer gives up on it (a runner that never answers costs the
   *  call, never the cycle: write-protection.md §8.5.1). */
  settleGraceMs: number;
}

export const DEFAULT_PREP_LIMITS: PrepLimits = {
  cycleBytes: 1024 * 1048576,
  totalBytes: 4096 * 1048576,
  packTimeoutMs: 30 * 60_000,
  inventoryTimeoutMs: 20_000,
  pruneGraceMs: 10 * 60_000,
  settleGraceMs: 5_000,
};

/** The caps from the environment: MANDU_GIT_PREP_CYCLE_MB (default
 *  MANDU_GIT_TWIN_MAX_MB, else 1024; 0 builds nothing) and
 *  MANDU_GIT_PREP_TOTAL_MB (default 4096; 0 keeps nothing). Pure. */
export function prepLimitsFromEnv(env: Readonly<Record<string, string | undefined>>): Partial<PrepLimits> {
  const mb = (v: string | undefined): number | null => {
    if (v === undefined || v.trim() === "") return null;
    const n = Number(v);
    return Number.isFinite(n) && n >= 0 ? Math.floor(n * 1048576) : null;
  };
  const twin = mb(env["MANDU_GIT_TWIN_MAX_MB"]);
  const cycle = mb(env["MANDU_GIT_PREP_CYCLE_MB"]) ?? (twin !== null && twin > 0 ? twin : null);
  const total = mb(env["MANDU_GIT_PREP_TOTAL_MB"]);
  return { ...(cycle !== null ? { cycleBytes: cycle } : {}), ...(total !== null ? { totalBytes: total } : {}) };
}

/**
 * Why the daemon prepares no copies on this host, or null when it does
 * (server-main.ts; 2026-09-30). Off with `MANDU_GIT_PREPARE=0`, and off on
 * every host but Linux: only a Linux launch consumes a prepared copy. The
 * launcher binds one (or has the file guard serve it) from `hideGitHistory`
 * (launcher/src/secret-setup.ts `preparedCopyTwins`), which runs only when
 * the platform is linux, beside the object twins and the guard's backstop
 * it completes (§11.1 R3, R4). A macOS launch confines by its Seatbelt
 * profile and has no counterpart of either yet (confidentiality.md §7.3):
 * every copy would be built, sealed and kept for nothing, each cycle
 * spending CPU on `git pack-objects` over the user's repositories and disk
 * in the cache. An embedder or a test that names a cache
 * (`ArbiterServer` `preparedCopies`) still gets one on any host. Pure.
 */
export function preparedCopiesOff(
  env: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform = process.platform,
): string | null {
  if (env["MANDU_GIT_PREPARE"] === "0") return "MANDU_GIT_PREPARE=0";
  if (platform !== "linux") {
    return `only a Linux launch uses them (the object twins and the file guard are Linux only); this host is ${platform}`;
  }
  return null;
}

// ── The seams ───────────────────────────────────────────────────────────────

/** The seal store as this module uses it (cache-seals.ts CacheSealStore). */
export interface PrepSealStore {
  status(): CacheSealStatus;
  seals(kind: string, keys: readonly string[]): CacheSealStatus & { seals: Array<{ key: string; sha256: string; size: number }> };
  record(entries: readonly CacheSeal[]): { epoch: string; recorded: number };
}

export interface PrepGitRun {
  code: number;
  stdout: string;
  stderr: string;
}

/** Runs one git command. `args` are the subcommand's (the runner puts the
 *  hardened global options in front); `env` is laid over the scrubbed
 *  environment; `writable` are the directories the call writes, the only
 *  read-write binds of the git sandbox; `lowPriority` runs it at nice 19
 *  (where the host has a `nice` in NICE_CANDIDATES). */
export type PrepGit = (
  args: string[],
  opts: {
    cwd: string; input?: string; timeoutMs: number; env?: Record<string, string>; lowPriority?: boolean;
    writable?: readonly string[];
  },
) => Promise<PrepGitRun>;

/** Where a low-priority call looks for `nice`: absolute paths in the base
 *  system's root-owned directories, in order (coreutils' on most Linux
 *  distributions and on macOS; busybox's on Alpine). Never a PATH lookup: a
 *  `nice` planted on PATH (a user's `~/.local/bin`, `/opt/homebrew/bin`)
 *  would run outside every sandbox with git's command line. */
export const NICE_CANDIDATES: readonly string[] = ["/usr/bin/nice", "/bin/nice"];

const executableFile = (p: string): boolean => {
  try {
    if (!statSync(p).isFile()) return false;
    accessSync(p, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
};

/** The first of NICE_CANDIDATES that is an executable file, or null (NixOS
 *  and Guix have neither). */
export function resolveNice(executable: (p: string) => boolean = executableFile): string | null {
  return NICE_CANDIDATES.find((p) => executable(p)) ?? null;
}

let niceResolved: string | null | undefined;
/** This process's `nice` (resolveNice, looked up once). */
export function niceBinary(): string | null {
  if (niceResolved === undefined) niceResolved = resolveNice();
  return niceResolved;
}

/**
 * The command for one call: `git` behind HARDENED_GIT_ARGS, in `sandbox`
 * (the arbiter's git sandbox: bubblewrap on Linux, Seatbelt on macOS; null
 * where neither can be made) with each of `writable` its only writable
 * path; under `<nice> -n 19` when `lowPriority` (nice wraps the sandbox, so
 * git and everything it starts inherit the priority from their first
 * instruction; renicing the child after the spawn would race bubblewrap's
 * own fork). `nice` is `niceBinary()` by default (NICE_CANDIDATES, never
 * PATH); where there is none the call runs without it, still hardened and
 * sandboxed: the low priority is a scheduling courtesy, not a security
 * property. Pure given `nice`, but for a Seatbelt sandbox's canonical
 * spelling of `writable` (hardened-git.ts `gitCommand`).
 */
export function prepGitCommand(
  args: readonly string[],
  opts: { writable?: readonly string[]; lowPriority?: boolean },
  sandbox: GitSandbox | null,
  nice: string | null = niceBinary(),
): { file: string; args: string[] } {
  const cmd = gitCommand([...HARDENED_GIT_ARGS, ...args], sandbox, opts.writable ?? []);
  return opts.lowPriority && nice !== null ? { file: nice, args: ["-n", "19", cmd.file, ...cmd.args] } : cmd;
}

/** The environment for one call: the arbiter's scrubbed git environment
 *  (secret-history-scan.ts `historyGitEnv`: no inherited `GIT_*`, so a
 *  stray GIT_DIR or GIT_OBJECT_DIRECTORY in the arbiter's own environment
 *  cannot redirect a build), then `extra`. */
export function prepGitEnv(extra: Readonly<Record<string, string>> = {}): NodeJS.ProcessEnv {
  return { ...historyGitEnv(), ...extra };
}

/** The production runner: hardened and sandboxed (`prepGitCommand`), run by
 *  ../src/child-run.ts `runChild` (its own process group, SIGKILL to the
 *  group at the deadline, and settled even when a sandbox child orphaned
 *  in its start-up holds the pipes: write-protection.md §8.5.1); `children`
 *  tracks what runs so `stop` can kill it. */
export function prepGit(children: Set<RunningChild>, sandbox: () => GitSandbox | null = gitSandbox): PrepGit {
  return async (args, opts) => {
    let cmd: { file: string; args: string[] };
    try {
      cmd = prepGitCommand(args, opts, sandbox());
    } catch (e) {
      return { code: 1, stdout: "", stderr: (e as Error).message };
    }
    const r = await runChild(cmd.file, cmd.args, {
      cwd: opts.cwd, env: prepGitEnv(opts.env), timeoutMs: opts.timeoutMs, maxStdout: 1 << 20,
      ...(opts.input !== undefined ? { input: opts.input } : {}),
    }, children);
    return { code: r.code, stdout: r.stdout, stderr: r.stderr };
  };
}

/** sha256 and size of a file, streamed (the event loop is never held). */
export function hashFileAsync(path: string): Promise<{ sha256: string; size: number }> {
  return new Promise((resolveHash, reject) => {
    const h = createHash("sha256");
    let size = 0;
    const s = createReadStream(path, { highWaterMark: 1 << 20 });
    s.on("data", (c) => { const b = c as Buffer; size += b.length; h.update(b); });
    s.on("error", reject);
    s.on("end", () => resolveHash({ sha256: h.digest("hex"), size }));
  });
}

// ── The cache ───────────────────────────────────────────────────────────────

/** The files of a cached copy, or null when absent or not what the key
 *  promises (an index still listing an excluded id). The launcher's
 *  `cachedPack`. */
export function cachedCopy(cacheDir: string, key: string, exclude: readonly string[], hashLen: number): { pack: string; idx: string; rev: string | null } | null {
  const dir = join(cacheDir, key);
  let names: string[];
  try { names = readdirSync(dir); } catch { return null; }
  const idxName = names.find((n) => n.endsWith(".idx"));
  if (!idxName) return null;
  const base = join(dir, idxName.slice(0, -4));
  if (!existsSync(`${base}.pack`)) return null;
  try {
    if (idxLookupFile(`${base}.idx`, exclude, hashLen).length > 0) return null;
  } catch {
    return null;
  }
  return { pack: `${base}.pack`, idx: `${base}.idx`, rev: existsSync(`${base}.rev`) ? `${base}.rev` : null };
}

/** The files the launcher serves of a copy, with their seal keys (the
 *  launcher's `packParts`): the pack, its index, and its reverse index when
 *  the real pack has one. Null when a needed `.rev` is missing. */
export function copyParts(key: string, hasRev: boolean, files: { pack: string; idx: string; rev: string | null }): Array<{ key: string; path: string }> | null {
  if (hasRev && files.rev === null) return null;
  const parts = [files.pack, files.idx, ...(hasRev && files.rev !== null ? [files.rev] : [])];
  return parts.map((p) => ({ key: `${key}/${basename(p)}`, path: p }));
}

// ── The preparer ────────────────────────────────────────────────────────────

export interface PreparedCopiesOptions {
  /** The object-twin cache the launcher reads (the path table's `object-twins`). */
  cacheDir: string;
  /** The known repositories, in the registry's order. */
  repos: () => string[];
  /** The global locked set (R2), bare hex per format. */
  lockedSet: () => { sha1: string[]; sha256: string[] };
  seals: PrepSealStore;
  limits?: Partial<PrepLimits>;
  git?: PrepGit;
  hashFile?: (path: string) => Promise<{ sha256: string; size: number }>;
  realpath?: (p: string) => string | null;
  /** How `objects/info/alternates` files are read (default:
   *  git-alternates.ts defaultAlternatesIo). A test knob. */
  alternatesIo?: AlternatesIo;
  log?: (m: string) => void;
  now?: () => number;
}

/** What the answer (`gitHistoryLocks`) and the doctor say. */
export interface PreparationSummary {
  /** Repositories whose every copy is present and sealed. */
  ready: Array<{ root: string; format: "sha1" | "sha256" }>;
  pending: string[];
  capped: Array<{ root: string; reason: string }>;
  failed: Array<{ root: string; reason: string }>;
  /** Set while nothing is built (an unconfined period, why). */
  paused?: string;
  /** Source bytes the kept copies stand for. */
  bytes: number;
  caps: PrepCaps;
  /** Cycles finished; the last one's end (ms since the epoch), or null. */
  cycles: number;
  at: number | null;
}

/** A copy this process built: its parts' hashes (memory only). */
type Built = Map<string, { sha256: string; size: number }>;

export class PreparedCopies {
  private readonly limits: PrepLimits;
  private readonly git: PrepGit;
  private readonly hashFile: (p: string) => Promise<{ sha256: string; size: number }>;
  private readonly realpath: (p: string) => string | null;
  private readonly alternatesIo: AlternatesIo;
  private readonly log: (m: string) => void;
  private readonly now: () => number;
  private readonly children = new Set<RunningChild>();
  /** The calls in flight, each settled (as a failure) by `stop`. */
  private readonly inFlight = new Set<() => void>();
  /** Seal key → hashes of what this process built. */
  private readonly built: Built = new Map();
  /** Cache keys this process built or kept (only these are ever pruned). */
  private readonly owned = new Set<string>();
  /** Keys a launcher reported as not matching their seal: rebuilt. */
  private readonly distrusted = new Set<string>();
  /** Each repository's copy keys at its last inventory. */
  private readonly rootKeys = new Map<string, Set<string>>();
  private readonly states = new Map<string, { state: PrepState; format: "sha1" | "sha256"; reason?: string }>();
  private running: Promise<void> | null = null;
  private again = false;
  private stopped = false;
  private paused: string | undefined;
  private bytes = 0;
  private lastAt: number | null = null;
  /** Cycles finished (a test aid). */
  cycles = 0;
  /** Packs built by the last cycle (a test and log aid). */
  lastBuilt = 0;
  /** Packs built since start (a test aid). */
  builtTotal = 0;

  constructor(private readonly opts: PreparedCopiesOptions) {
    this.limits = { ...DEFAULT_PREP_LIMITS, ...(opts.limits ?? {}) };
    this.git = opts.git ?? prepGit(this.children);
    this.hashFile = opts.hashFile ?? hashFileAsync;
    this.realpath = opts.realpath ?? ((p) => { try { return realpathSync(p); } catch { return null; } });
    this.alternatesIo = opts.alternatesIo ?? defaultAlternatesIo;
    this.log = opts.log ?? (() => {});
    this.now = opts.now ?? Date.now;
  }

  /** Prepare soon (after a resolution cycle, a rotation, a launch's end). */
  kick(): void {
    if (this.stopped) return;
    if (this.running !== null) { this.again = true; return; }
    const t = setTimeout(() => { void this.runCycle(); }, 0);
    t.unref();
  }

  /** The seals were voided (a rotation): nothing is ready until a cycle
   *  seals it again. */
  voided(): void {
    for (const s of this.states.values()) if (s.state === "ready") { s.state = "pending"; s.reason = "its seals were voided by an unconfined period; being sealed again"; }
    this.kick();
  }

  /** A launcher found these copies' bytes not matching their seals
   *  (`sealCacheEntries` `rejected`, reason `mismatch`): rebuild them. */
  distrust(keys: readonly string[]): void {
    let any = false;
    for (const k of keys) {
      const key = k.split("/")[0] ?? "";
      if (/^[0-9a-f]{32}$/.test(key) && this.owned.has(key)) { this.distrusted.add(key); any = true; }
    }
    if (any) this.kick();
  }

  /** One cycle, or join the running one. */
  runCycle(): Promise<void> {
    if (this.running !== null) { this.again = true; return this.running; }
    this.running = (async () => {
      try {
        do {
          this.again = false;
          await this.cycleOnce();
        } while (this.again && !this.stopped);
      } catch (e) {
        this.log(`prepared copies: a cycle failed: ${(e as Error).message}`);
      }
    })().finally(() => { this.running = null; });
    return this.running;
  }

  async idle(): Promise<void> {
    while (this.running !== null) await this.running;
  }

  async stop(): Promise<void> {
    this.stopped = true;
    for (const c of this.children) { try { c.kill("the preparer stopped"); } catch { /* gone */ } }
    for (const settle of [...this.inFlight]) settle();
    try { await this.running; } catch { /* reported */ }
  }

  /**
   * Every git call of a cycle. Refused once stopped; otherwise settled by
   * the call's deadline plus `settleGraceMs`, or at once by `stop`, whatever
   * the runner does (the production runner settles by its deadline plus
   * one second, ../src/child-run.ts). A call given up on is a FAILURE: the
   * repository is failed this cycle and left to the backstop (R4), never
   * waited for (write-protection.md §8.5.1).
   */
  private call(args: string[], opts: Parameters<PrepGit>[1]): Promise<PrepGitRun> {
    const failed = (stderr: string): PrepGitRun => ({ code: 1, stdout: "", stderr });
    if (this.stopped) return Promise.resolve(failed("the preparer stopped"));
    return new Promise((resolveCall) => {
      const finish = (r: PrepGitRun): void => {
        if (!this.inFlight.delete(stop)) return;
        clearTimeout(timer);
        resolveCall(r);
      };
      const stop = (): void => finish(failed("the preparer stopped"));
      const timer = setTimeout(() => {
        const what = args.find((a) => /^[a-z][a-z-]*$/.test(a)) ?? "call";
        this.log(`prepared copies: git ${what} did not settle within ${opts.timeoutMs + this.limits.settleGraceMs} ms; given up (the repository is left to the backstop)`);
        finish(failed(`git ${what} did not finish within its ${opts.timeoutMs} ms deadline`));
      }, Math.max(1, opts.timeoutMs) + this.limits.settleGraceMs);
      this.inFlight.add(stop);
      this.git(args, opts).then(finish, (e: unknown) => finish(failed(e instanceof Error ? e.message : String(e))));
    });
  }

  summary(): PreparationSummary {
    const ready: PreparationSummary["ready"] = [];
    const pending: string[] = [];
    const capped: PreparationSummary["capped"] = [];
    const failed: PreparationSummary["failed"] = [];
    for (const [root, s] of this.states) {
      if (s.state === "ready") ready.push({ root, format: s.format });
      else if (s.state === "pending") pending.push(root);
      else if (s.state === "capped") capped.push({ root, reason: s.reason ?? "over a cap" });
      else failed.push({ root, reason: s.reason ?? "failed" });
    }
    return {
      ready, pending, capped, failed, ...(this.paused !== undefined ? { paused: this.paused } : {}),
      bytes: this.bytes, caps: { cycleBytes: this.limits.cycleBytes, totalBytes: this.limits.totalBytes }, cycles: this.cycles, at: this.lastAt,
    };
  }

  /** Is building allowed now, in `epoch`? (An unconfined period: no.) */
  private allowed(epoch?: string): { ok: true; epoch: string } | { ok: false; reason: string } {
    let st: CacheSealStatus;
    try { st = this.opts.seals.status(); } catch (e) { return { ok: false, reason: `the seal store could not answer (${(e as Error).message})` }; }
    if (!st.honoured) return { ok: false, reason: st.reason ?? "no seal is honoured now" };
    if (epoch !== undefined && st.epoch !== epoch) return { ok: false, reason: "the epoch changed during the cycle" };
    return { ok: true, epoch: st.epoch };
  }

  private async cycleOnce(): Promise<void> {
    if (this.stopped) return;
    const gate = this.allowed();
    if (!gate.ok) {
      // Never build during an unconfined period: its seals would be void at
      // its end, and a copy it could touch mid-build must not be sealed.
      this.paused = gate.reason;
      for (const s of this.states.values()) if (s.state === "ready") { s.state = "pending"; s.reason = "waiting for the unconfined period to end"; }
      return;
    }
    this.paused = undefined;
    const epoch = gate.epoch;
    const t0 = this.now();
    const set = exclusionSet(this.opts.lockedSet());
    const stores: PrepStore[] = [];
    const failed = new Map<string, string>();
    const yieldNow = (): Promise<void> => new Promise((r) => setImmediate(r));
    for (const root of this.opts.repos()) {
      if (this.stopped) return;
      try {
        const s = await this.locate(root, set);
        if (s !== null) stores.push(s);
      } catch (e) {
        failed.set(root, (e as Error).message);
      }
      await yieldNow();
    }
    // Each object directory once, whichever repositories read it.
    const inv = await inventoryStores(stores, set, { yieldNow });
    if (this.stopped) return;
    const repos = inv.repos;
    for (const [root, reason] of inv.failed) failed.set(root, reason);
    // What is ready: present, what the key promises, and sealed now (a seal
    // of the current epoch whose size matches; the launcher hashes at use).
    // A copy this process built whose seal a rotation voided is sealed again
    // when its bytes still match what it built. A pack several repositories
    // read is one entry, checked once.
    const checked = new Set<PrepPack>();
    for (const r of repos) {
      const hashLen = r.format === "sha256" ? 32 : 20;
      for (const p of r.packs) {
        if (checked.has(p)) continue;
        checked.add(p);
        if (this.distrusted.has(p.key)) { p.ready = false; continue; }
        p.ready = await this.readyOrResealed(p, hashLen, epoch);
      }
    }
    const plan = planPreparation(repos, { cycleBytes: this.limits.cycleBytes, totalBytes: this.limits.totalBytes });
    const next = new Map<string, { state: PrepState; format: "sha1" | "sha256"; reason?: string }>();
    for (const r of repos) {
      const s = plan.state.get(r.root);
      if (s !== undefined) next.set(r.root, { ...s, format: r.format });
    }
    for (const [root, reason] of failed) next.set(root, { state: "failed", format: "sha1", reason });
    // Build, one pack at a time; each checked against the period before it
    // starts and before it is sealed.
    let builtNow = 0;
    const broken = new Set<string>();
    for (const b of plan.build) {
      if (this.stopped) return;
      if (broken.has(b.root)) continue;
      const g = this.allowed(epoch);
      if (!g.ok) { this.paused = g.reason; break; }
      const repo = repos.find((r) => r.root === b.root)!;
      try {
        await this.build(repo, b.pack, epoch);
        builtNow++;
        this.distrusted.delete(b.pack.key);
        // One copy per key: every repository whose pack has it is served it
        // (the same pack reached twice, or the same pack in two stores).
        for (const r of repos) for (const p of r.packs) if (p.key === b.pack.key) p.ready = true;
      } catch (e) {
        // Every repository reading the pack fails with it (an object
        // directory shared through alternates).
        for (const r of repos) {
          if (!r.packs.some((p) => p.key === b.pack.key)) continue;
          broken.add(r.root);
          next.set(r.root, { state: "failed", format: r.format, reason: (e as Error).message });
        }
        this.log(`prepared copies: ${b.root}: ${(e as Error).message}`);
      }
    }
    for (const r of repos) {
      if (next.get(r.root)?.state === "pending" && r.packs.every((p) => p.ready)) next.set(r.root, { state: "ready", format: r.format });
    }
    // A repository whose inventory failed this cycle keeps the copies it had
    // (a transient failure must not cost them); the rest are what the plan
    // wants.
    const keep = new Set(plan.wanted);
    for (const root of failed.keys()) for (const k of this.rootKeys.get(root) ?? []) keep.add(k);
    for (const r of repos) this.rootKeys.set(r.root, new Set(r.packs.map((p) => p.key)));
    for (const root of [...this.rootKeys.keys()]) if (!failed.has(root) && !repos.some((r) => r.root === root)) this.rootKeys.delete(root);
    this.states.clear();
    for (const [k, v] of next) this.states.set(k, v);
    this.bytes = plan.wantedBytes;
    this.prune(keep);
    this.cycles++;
    this.lastBuilt = builtNow;
    this.builtTotal += builtNow;
    this.lastAt = this.now();
    if (builtNow > 0 || failed.size > 0) {
      const s = this.summary();
      this.log(`prepared copies: ${builtNow} pack(s) sanitized in ${this.now() - t0} ms; ${s.ready.length} repositor${s.ready.length === 1 ? "y" : "ies"} ready, ${s.pending.length} pending, ${s.capped.length} capped, ${s.failed.length} failed`);
    }
  }

  /** One known repository, located: its object format and every object
   *  directory it reads (the launcher's `objectDirsOf`: the same
   *  git-alternates.ts closure), or null when nothing of its format is
   *  locked. Throws, so the repository fails this cycle and keeps no new
   *  copy, when its alternates cannot be told (an odd or unreadable
   *  `info/alternates`, a chain past the bounds): never a shorter list. */
  private async locate(root: string, set: { sha1: string[]; sha256: string[] }): Promise<PrepStore | null> {
    if (set.sha1.length === 0 && set.sha256.length === 0) return null;
    const r = await this.call(["rev-parse", "--show-toplevel", "--git-common-dir", "--show-object-format"], {
      cwd: root, timeoutMs: this.limits.inventoryTimeoutMs,
    });
    if (r.code !== 0) throw new Error(`git rev-parse failed: ${r.stderr.trim().split("\n").slice(-1)[0] || `exit ${r.code}`}`);
    const [top, common, fmt] = r.stdout.split("\n").map((l) => l.trim());
    if (this.realpath(top ?? "") !== root) throw new Error(`${root} is not a work tree's top`);
    const format: "sha1" | "sha256" = fmt === "sha256" ? "sha256" : "sha1";
    if (set[format].length === 0) return null;
    const dirs = objectStoreClosure(resolve(root, common ?? ".git", "objects"), this.alternatesIo);
    return { root, format, dirs };
  }

  /** Present, promised and sealed now; or re-sealed from what this process
   *  built (after a rotation). */
  private async readyOrResealed(p: PrepPack, hashLen: number, epoch: string): Promise<boolean> {
    const files = cachedCopy(this.opts.cacheDir, p.key, p.exclude, hashLen);
    if (files === null) return false;
    const parts = copyParts(p.key, p.hasRev, files);
    if (parts === null) return false;
    let sizes: number[];
    try { sizes = parts.map((x) => statSync(x.path).size); } catch { return false; }
    const got = this.opts.seals.seals(CACHE_SEAL_KINDS.objectTwin, parts.map((x) => x.key));
    if (!got.honoured || got.epoch !== epoch) return false;
    const sealedNow = parts.every((x, i) => got.seals.some((s) => s.key === x.key && s.size === sizes[i]));
    if (sealedNow) {
      this.owned.add(p.key);
      touch(join(this.opts.cacheDir, p.key));
      return true;
    }
    // Sealed again only from this process's own memory of what it built.
    if (!parts.every((x) => this.built.has(x.key))) return false;
    const entries: CacheSeal[] = [];
    for (const x of parts) {
      let h: { sha256: string; size: number };
      try { h = await this.hashFile(x.path); } catch { return false; }
      const want = this.built.get(x.key)!;
      if (h.sha256 !== want.sha256 || h.size !== want.size) return false;
      entries.push({ kind: CACHE_SEAL_KINDS.objectTwin, key: x.key, sha256: h.sha256, size: h.size });
    }
    if (!this.allowed(epoch).ok) return false;
    this.opts.seals.record(entries);
    touch(join(this.opts.cacheDir, p.key));
    return true;
  }

  /**
   * Build one copy (the launcher's `buildPack`, with no repository config)
   * and seal it, only if the epoch it started in is still current and
   * honoured. Marks `p.ready`.
   */
  private async build(repo: PrepRepo, p: PrepPack, epoch: string): Promise<void> {
    const hashLen = repo.format === "sha256" ? 32 : 20;
    const cacheDir = this.opts.cacheDir;
    mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
    const drop = new Set(p.exclude);
    const list = idxObjectNames(readFileSync(`${p.base}.idx`), hashLen).filter((o) => !drop.has(o));
    // The build's own work directory, the git sandbox's ONLY writable bind:
    // the output (`out`, renamed into place once verified), the empty object
    // directory pack-objects writes its temporary pack in (`odb`) and the
    // private bare repository (`git`). One bind, so pack-objects' rename of
    // its temporary pack into `out` stays on one mount (across two binds it
    // would fail, EXDEV), and no other copy in the cache is writable.
    const work = join(cacheDir, `.tmp-${p.key}-${process.pid}-prep`);
    const tmp = join(work, "out");
    const odb = join(work, "odb");
    const gitDir = join(work, "git");
    const writable = [work];
    rmSync(work, { recursive: true, force: true });
    mkdirSync(tmp, { recursive: true, mode: 0o700 });
    mkdirSync(join(odb, "pack"), { recursive: true, mode: 0o700 });
    const noConfig = { GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
    try {
      const init = await this.call(["init", "-q", "--bare", "--template=", `--object-format=${repo.format}`, gitDir], {
        cwd: cacheDir, timeoutMs: 20_000, env: noConfig, writable,
      });
      if (init.code !== 0) throw new Error(`git init failed: ${init.stderr.trim().split("\n").slice(-1)[0] || `exit ${init.code}`}`);
      const own = dirname(dirname(p.base));
      const common = (await this.call(["rev-parse", "--git-common-dir"], { cwd: repo.root, timeoutMs: this.limits.inventoryTimeoutMs })).stdout.trim();
      const env = {
        ...noConfig,
        GIT_OBJECT_DIRECTORY: odb,
        GIT_ALTERNATE_OBJECT_DIRECTORIES: alternateObjectDirsEnv([own, ...(common !== "" ? [resolve(repo.root, common, "objects")] : [])]),
      };
      const args = [
        `--git-dir=${gitDir}`, "-c", "pack.writeReverseIndex=true", "-c", "pack.writeBitmapIndex=false",
        "pack-objects", "-q", ...(list.length > 0 ? ["--no-write-bitmap-index"] : []), join(tmp, "p"),
      ];
      const res = await this.call(args, {
        cwd: cacheDir, input: list.length > 0 ? `${list.join("\n")}\n` : "", timeoutMs: this.limits.packTimeoutMs, env, lowPriority: true, writable,
      });
      if (res.code !== 0) throw new Error(`git pack-objects failed: ${res.stderr.trim().split("\n").slice(-1)[0] || `exit ${res.code}`}`);
      // The names the copy's index gives its objects are the source's, not
      // their content's: a crafted source pack (an index naming the locked
      // blob's bytes, or a delta on it, as another object) would carry the
      // key under a name nobody excludes. So the index is rebuilt FROM THE
      // CONTENT (`index-pack` hashes every object; the copy is never thin, so
      // it reads nothing else) and must name exactly the objects asked for.
      const packName = readdirSync(tmp).find((n) => n.endsWith(".pack"));
      if (packName === undefined) throw new Error("git pack-objects wrote no pack");
      const base = join(tmp, packName.slice(0, -5));
      rmSync(`${base}.idx`, { force: true });
      rmSync(`${base}.rev`, { force: true });
      const idx = await this.call([
        `--git-dir=${gitDir}`, "-c", "pack.indexVersion=2", "-c", "pack.writeReverseIndex=true",
        "index-pack", "-o", `${base}.idx`, `${base}.pack`,
      ], { cwd: cacheDir, timeoutMs: this.limits.packTimeoutMs, env: noConfig, lowPriority: true, writable });
      if (idx.code !== 0) throw new Error(`git index-pack failed: ${idx.stderr.trim().split("\n").slice(-1)[0] || `exit ${idx.code}`}`);
      if (!sameNames(idxObjectNames(readFileSync(`${base}.idx`), hashLen), list)) {
        throw new Error(`the objects of ${basename(p.base)}.pack do not hash to the names its index gives them (a crafted pack?): not prepared`);
      }
      const dest = join(cacheDir, p.key);
      rmSync(dest, { recursive: true, force: true });
      renameSync(tmp, dest);
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
    this.owned.add(p.key);
    const files = cachedCopy(cacheDir, p.key, p.exclude, hashLen);
    const parts = files === null ? null : copyParts(p.key, p.hasRev, files);
    if (parts === null) throw new Error(`the sanitized copy of ${basename(p.base)}.pack was not produced`);
    const entries: CacheSeal[] = [];
    for (const x of parts) {
      const h = await this.hashFile(x.path);
      entries.push({ kind: CACHE_SEAL_KINDS.objectTwin, key: x.key, sha256: h.sha256, size: h.size });
    }
    // The period check that decides the seal: the epoch the build started
    // in, still current and honoured now. Otherwise the copy is dropped.
    const g = this.allowed(epoch);
    if (!g.ok) {
      rmSync(join(cacheDir, p.key), { recursive: true, force: true });
      throw new Error(`not sealed: ${g.reason}`);
    }
    this.opts.seals.record(entries);
    for (const e of entries) this.built.set(e.key, { sha256: e.sha256, size: e.size });
    p.ready = true;
  }

  /** Remove the copies this process owns that no repository wants any more
   *  (a pack gone, a lock lifted, a repository capped or forgotten), unless
   *  a launch used them within the grace. */
  private prune(wanted: ReadonlySet<string>): void {
    const cutoff = this.now() - this.limits.pruneGraceMs;
    for (const key of [...this.owned]) {
      // Wanted (a distrusted one is rebuilt in place, this cycle or the next).
      if (wanted.has(key)) continue;
      const dir = join(this.opts.cacheDir, key);
      let mtime = 0;
      try { mtime = statSync(dir).mtimeMs; } catch { this.owned.delete(key); continue; }
      if (mtime > cutoff) continue;
      rmSync(dir, { recursive: true, force: true });
      this.owned.delete(key);
      for (const k of [...this.built.keys()]) if (k.startsWith(`${key}/`)) this.built.delete(k);
    }
  }
}

/** Mark a cache entry used (the launcher's 30-day prune keeps it). */
function touch(dir: string): void {
  try { const now = new Date(); utimesSync(dir, now, now); } catch { /* best effort */ }
}
