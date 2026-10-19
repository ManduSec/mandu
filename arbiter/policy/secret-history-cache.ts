/**
 * secret-history-cache — the git-history scan's cache (secret-discovery.md §3
 * §2 item 8; confidentiality-plan-14 §3, §5.5).
 *
 * Every secrets-mode launch asks the arbiter for `suggestPolicy`, which runs
 * the history scan. Uncached, that reads every reachable blob again each
 * time (on a large repository: tens of seconds and the byte cap). This
 * module remembers, per repository, what a scan already knows, so an
 * unchanged repository is not read again and a changed one reads only its
 * new objects:
 *
 *   - the KEY: the repository, a base (the detector's fingerprint, the
 *     object format, the git version, the replace refs) and the tips every
 *     reachable object hangs from (every ref, every reflog entry, the stash;
 *     the index is listed on every call, it is one cheap command);
 *   - the reachable blobs (name, size, the path `rev-list` reached it by);
 *   - the blobs whose content was READ (clean or not, text or binary) and
 *     the hits among them. A blob's name is its content, so a verdict on a
 *     name holds for as long as the detector does;
 *   - the traces (first and last commit) of the findings.
 *
 * What it never holds: a blob's content, a value, a character of a value's
 * body, a length or a hash of one. A hit is a {@link ShapeHit}: the shape,
 * the line and the scan's fixed mask, exactly as the reply carries it.
 *
 * What is NOT cached, because it moves without history moving: whether a
 * path exists in the work tree, the catalog and the labels (the
 * `catalog-path` detector and coverage), HEAD's tree and the index. The scan
 * recomputes those on every call against the law in force.
 *
 * A capped scan is never recorded as complete: only the blobs actually read
 * are in `scanned`, so what a cap left unread is read by the next call.
 *
 * Where: `<object-walks>/history-scan/<sha256(repoRoot)[:32]>.json` (the path
 * table's `object-walks`, under `state-root`: owner-only, not readable or
 * writable by the agent), files 0600 in a 0700 directory, written atomically
 * (a temp file renamed). Bounded: an entry larger than 64 MiB is not stored,
 * at most 64 repositories are kept (least recently used first out), and an
 * entry nobody used for 30 days is dropped. The cache is only an
 * accelerator: a missing, torn or foreign file scans as if there were none.
 *
 * SEALED (confidentiality-plan-14 §11.2): an entry that marks a blob as
 * scanned hides a finding, so a file this arbiter did not write must not be
 * read as one. Every save records a seal (sha256 and size, kind
 * `history-scan`, key = the file's name) in the current epoch
 * (cache-seals.ts); a load uses the file only when its bytes match a seal of
 * the current epoch, and otherwise scans as if there were none (the gate is
 * told, for an event naming the key).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code. The tips-keyed plan
 * mirrors launcher/src/git-object-twins.ts `planWalk` (the packages ship
 * standalone and do not import each other).
 */
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { manduPath, type ManduPathEnv } from "../src/generated/mandu-paths.js";
import { CACHE_SEAL_KINDS, type CacheSealGate } from "./cache-seals.js";
import type { ShapeHit } from "./secret-history-scan.js";

/** The cache's directory: `history-scan` in the path table's `object-walks`
 *  (the launcher's history-walk cache, under `state-root`), resolved from
 *  MANDU_HOME like every store of the arbiter. */
export function defaultHistoryCacheDir(env: ManduPathEnv, home: string): string {
  return join(manduPath("object-walks", env, home), "history-scan");
}

/** The format of a cache file; a bump drops every entry. */
export const HISTORY_CACHE_FORMAT = 1;

/** One finding's trace, as the scan found it at the entry's tips. */
export interface HistoryScanTrace {
  first: string | null;
  last: string | null;
  /** Every path the trace saw the blob at, repo-relative, sorted. */
  paths: string[];
}

/** One repository's cache file. */
export interface HistoryScanCacheEntry {
  v: typeof HISTORY_CACHE_FORMAT;
  repoRoot: string;
  /** What besides the tips decides the result (`historyCacheBase`). */
  base: string;
  /** Every ref, reflog entry and stash entry the reachable set hangs from,
   *  sorted, unique. */
  tips: string[];
  /** Every blob reachable from `tips`: [name, size, the path it was reached
   *  by or null]. */
  blobs: Array<[string, number, string | null]>;
  /** Blobs read and matched as text. */
  scanned: string[];
  /** Blobs read and skipped as binary. */
  binary: string[];
  /** The hits among `scanned`: masks only. */
  hits: Record<string, ShapeHit[]>;
  /** The traces of the findings at `tips`. */
  traces: Record<string, HistoryScanTrace>;
}

/** How to bring a repository's scan up to date. */
export type HistoryScanPlan =
  /** No usable entry: list and read everything. */
  | { kind: "fresh" }
  /** The same base and tips: nothing to list; read only what a cap left. */
  | { kind: "hit" }
  /** Only new tips: list what the old tips cannot reach. */
  | { kind: "incremental"; include: string[]; exclude: string[] }
  /** A tip went away (a rewrite, a reset, an expired reflog): list the whole
   *  history again, but read only what was never read. */
  | { kind: "relist" };

/** What besides the tips decides a scan's result: the detector's
 *  fingerprint, the object format, the git version and the replace refs.
 *  Pure. */
export function historyCacheBase(parts: { detector: string; objectFormat: string; gitVersion: string; replaceRefs: string }): string {
  return createHash("sha256")
    .update(JSON.stringify([HISTORY_CACHE_FORMAT, parts.detector, parts.objectFormat.trim(), parts.gitVersion.trim(), parts.replaceRefs]))
    .digest("hex");
}

/** The plan for one repository. Pure. */
export function planHistoryScan(entry: HistoryScanCacheEntry | null, repoRoot: string, base: string, tips: readonly string[]): HistoryScanPlan {
  if (entry === null || entry.v !== HISTORY_CACHE_FORMAT || entry.repoRoot !== repoRoot || entry.base !== base) return { kind: "fresh" };
  const now = new Set(tips);
  if (entry.tips.some((t) => !now.has(t))) return { kind: "relist" };
  const old = new Set(entry.tips);
  const include = tips.filter((t) => !old.has(t));
  if (include.length === 0) return { kind: "hit" };
  return { kind: "incremental", include, exclude: [...entry.tips] };
}

/** The file a repository's entry lives in. Pure. */
export function historyCacheFile(dir: string, repoRoot: string): string {
  return join(dir, `${createHash("sha256").update(repoRoot).digest("hex").slice(0, 32)}.json`);
}

const HEX = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const SHAPE = /^[a-z][a-z0-9-]{0,40}$/;
/** A mask is short; anything longer is not one this scan wrote. */
const PREVIEW_MAX = 300;

/** A cache file as read back, or null when it is not a well-formed entry
 *  (the scan then starts fresh). Pure. */
export function parseHistoryCache(text: string): HistoryScanCacheEntry | null {
  let j: unknown;
  try { j = JSON.parse(text); } catch { return null; }
  if (typeof j !== "object" || j === null) return null;
  const e = j as Record<string, unknown>;
  const hexes = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string" && HEX.test(x));
  const obj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
  if (e["v"] !== HISTORY_CACHE_FORMAT || typeof e["repoRoot"] !== "string" || typeof e["base"] !== "string") return null;
  if (!hexes(e["tips"]) || !hexes(e["scanned"]) || !hexes(e["binary"])) return null;
  const blobs = e["blobs"];
  if (!Array.isArray(blobs) || !blobs.every((b) => Array.isArray(b) && b.length === 3 && typeof b[0] === "string" && HEX.test(b[0])
    && Number.isSafeInteger(b[1]) && (b[1] as number) >= 0 && (b[2] === null || typeof b[2] === "string"))) return null;
  const hits = e["hits"];
  if (!obj(hits)) return null;
  for (const [k, v] of Object.entries(hits)) {
    if (!HEX.test(k) || !Array.isArray(v)) return null;
    for (const h of v) {
      if (!obj(h) || typeof h["shape"] !== "string" || !SHAPE.test(h["shape"]) || !Number.isSafeInteger(h["line"]) || (h["line"] as number) < 1
        || typeof h["preview"] !== "string" || h["preview"].length > PREVIEW_MAX) return null;
    }
  }
  const traces = e["traces"];
  if (!obj(traces)) return null;
  for (const [k, v] of Object.entries(traces)) {
    if (!HEX.test(k) || !obj(v)) return null;
    const c = (x: unknown): boolean => x === null || (typeof x === "string" && HEX.test(x));
    if (!c(v["first"]) || !c(v["last"]) || !Array.isArray(v["paths"]) || !v["paths"].every((p) => typeof p === "string")) return null;
  }
  return {
    v: HISTORY_CACHE_FORMAT,
    repoRoot: e["repoRoot"],
    base: e["base"],
    tips: e["tips"],
    blobs: blobs as Array<[string, number, string | null]>,
    scanned: e["scanned"],
    binary: e["binary"],
    hits: hits as Record<string, ShapeHit[]>,
    traces: traces as Record<string, HistoryScanTrace>,
  };
}

/** Where a scan keeps what it knows. */
export interface HistoryScanCache {
  /** The repository's entry, or null (none, torn, foreign). Never throws. */
  load(repoRoot: string): HistoryScanCacheEntry | null;
  /** Store an entry; false when it was not (too large, a filesystem
   *  error). Never throws. */
  save(entry: HistoryScanCacheEntry): boolean;
  /** Mark an unchanged entry used (it is kept by recency). Never throws. */
  touch(repoRoot: string): void;
}

export interface FileHistoryCacheOpts {
  /** An entry larger than this is not stored (default 64 MiB). */
  maxEntryBytes?: number;
  /** Repositories kept (default 64); the least recently used go first. */
  maxEntries?: number;
  /** An entry unused this long is dropped (default 30 days). */
  maxAgeMs?: number;
  now?: () => number;
  /** The seals (cache-seals.ts). The server always passes them; unset (a
   *  unit test of the file format) trusts every well-formed file. */
  seals?: CacheSealGate;
}

export const HISTORY_CACHE_MAX_ENTRY_BYTES = 64 * 1024 * 1024;
export const HISTORY_CACHE_MAX_ENTRIES = 64;
export const HISTORY_CACHE_MAX_AGE_MS = 30 * 24 * 3600_000;

/** The production cache: one owner-only JSON file per repository in `dir`. */
export function fileHistoryScanCache(dir: string, o: FileHistoryCacheOpts = {}): HistoryScanCache {
  const maxEntryBytes = o.maxEntryBytes ?? HISTORY_CACHE_MAX_ENTRY_BYTES;
  const maxEntries = o.maxEntries ?? HISTORY_CACHE_MAX_ENTRIES;
  const maxAgeMs = o.maxAgeMs ?? HISTORY_CACHE_MAX_AGE_MS;
  const now = o.now ?? Date.now;
  const seals = o.seals;
  const keyOf = (file: string): string => file.slice(file.lastIndexOf("/") + 1).replace(/\.json$/, "");
  const prune = (keep: string): void => {
    let names: string[];
    try { names = readdirSync(dir); } catch { return; }
    const files: Array<{ p: string; t: number }> = [];
    for (const n of names) {
      const p = join(dir, n);
      let t: number;
      try { t = statSync(p).mtimeMs; } catch { continue; }
      if (n.includes(".tmp-")) {
        if (now() - t > 3600_000) { try { rmSync(p, { force: true }); } catch { /* best effort */ } }
        continue;
      }
      if (!n.endsWith(".json")) continue;
      if (p !== keep && now() - t > maxAgeMs) { try { rmSync(p, { force: true }); } catch { /* best effort */ } continue; }
      files.push({ p, t });
    }
    files.sort((a, b) => b.t - a.t);
    for (const f of files.slice(maxEntries)) {
      if (f.p === keep) continue;
      try { rmSync(f.p, { force: true }); } catch { /* best effort */ }
    }
  };
  return {
    load(repoRoot) {
      const file = historyCacheFile(dir, repoRoot);
      let bytes: Buffer;
      try { bytes = readFileSync(file); } catch { return null; }
      if (seals) {
        const verdict = seals.check(CACHE_SEAL_KINDS.historyScan, keyOf(file), bytes);
        if (verdict !== "ok") {
          if (verdict !== "not-honoured") seals.rejected?.({ kind: CACHE_SEAL_KINDS.historyScan, key: keyOf(file), reason: verdict });
          return null;
        }
      }
      const e = parseHistoryCache(bytes.toString("utf8"));
      return e !== null && e.repoRoot === repoRoot ? e : null;
    },
    save(entry) {
      const file = historyCacheFile(dir, entry.repoRoot);
      try {
        const text = JSON.stringify(entry);
        if (Buffer.byteLength(text) > maxEntryBytes) {
          try { rmSync(file, { force: true }); } catch { /* best effort */ }
          return false;
        }
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        chmodSync(dir, 0o700);
        const tmp = `${file}.tmp-${process.pid}`;
        writeFileSync(tmp, text, { mode: 0o600 });
        renameSync(tmp, file);
        seals?.seal(CACHE_SEAL_KINDS.historyScan, keyOf(file), Buffer.from(text, "utf8"));
      } catch {
        return false;
      }
      prune(file);
      return true;
    },
    touch(repoRoot) {
      const t = new Date(now());
      try { utimesSync(historyCacheFile(dir, repoRoot), t, t); } catch { /* best effort */ }
    },
  };
}
