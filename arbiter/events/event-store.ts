/**
 * event-store — append-only, per-session NDJSON event store for the arbiter's
 * observability event stream (Mandu-new, no reference origin).
 *
 * The arbiter owns the symbol table + policy engine; it ALSO acts as the single
 * fan-out point for the observability event feed the dashboard renders. The
 * anthropic-proxy, the inspect-MCP server, and (later) the OS interceptors emit
 * events via the `emit` op; the dashboard subscribes via the `subscribe` op.
 *
 * Design (mirrors docs/design/ui/dashboard.md §2 — the ManduEvent record):
 *   - One append-only NDJSON file per session at
 *     `<event dir>/<sessionId>.ndjson`. Each line is one JSON object:
 *     the caller's opaque `event` with a arbiter-assigned monotonic `seq` merged
 *     in (the `seq` field the dashboard's event-model.ts expects).
 *   - `seq` is a per-session monotonic integer starting at 1, recovered on
 *     startup by scanning the existing file (so a restart keeps counting).
 *   - Append-atomic per line: each event is written with a single
 *     `write` of one complete `JSON.stringify(...) + "\n"` string, so a
 *     concurrent reader never sees a half-written record at the tail.
 *   - Reads tolerate partial/concurrent writes: a trailing line without its
 *     terminating "\n", or any unparseable line, is skipped rather than thrown.
 *
 * The arbiter treats `event` as OPAQUE JSON. We keep a LOCAL minimal type
 * (ArbiterEvent) describing only the fields the arbiter itself requires
 * (`sessionId`, `id`) and the field it assigns (`seq`); we do NOT import the
 * dashboard package. The dashboard's richer `ManduEvent` is structurally a
 * superset, so persisted lines validate against its `isManduEvent`.
 *
 * SECURITY / SEMANTICS: the event feed is OBSERVABILITY ONLY. Emission is
 * best-effort / fire-and-forget — it is never on the security path. A failed
 * emit is reported to the caller as an error response, but callers must not gate
 * any ingress/egress decision on emit success (see protocol.ts `emit`).
 */

import {
  chmodSync,
  closeSync,
  existsSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { closeSafeDir, openSafeDir, openSafeLogIn, type SafeDir } from "./safe-log.js";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { manduPath } from "../src/generated/mandu-paths.js";

/**
 * The arbiter's LOCAL minimal event type. The arbiter only requires the two
 * identity fields below; everything else is opaque caller-supplied JSON. The
 * arbiter assigns `seq`. This is intentionally NOT the dashboard's ManduEvent —
 * the arbiter must not depend on the dashboard package — but it is a structural
 * subset, so any value the arbiter accepts and persists is a valid ManduEvent
 * once the emitter supplies the remaining fields.
 */
export interface ArbiterEvent {
  /** Stable, globally-unique event id (e.g. a ULID). Required. */
  id: string;
  /** Mandu scope id this event belongs to. Required; selects the NDJSON file. */
  sessionId: string;
  /** Arbiter-assigned per-session monotonic counter (>= 1). Filled in by emit. */
  seq?: number;
  /** ISO 8601 wall clock, if the emitter set one. Used by `sessions` summaries. */
  ts?: string;
  /** Any further opaque fields the emitter supplied. */
  [k: string]: unknown;
}

/** A persisted event always has its arbiter-assigned seq. */
export type StoredEvent = ArbiterEvent & { seq: number; chain?: string };

/**
 * The session log's hash chain (comparisons.md §3.9): each stored line
 * carries `chain = sha256(previous chain + "\n" + the line's JSON without
 * `chain`)`, the first chained line hashing against "". Editing, dropping or
 * reordering a line breaks every later link; `verifyChain` names the first
 * break. It is tamper-EVIDENT, not tamper-proof: whoever can rewrite the file
 * as the user can recompute the chain, which is why the SIEM exporter
 * forwards each line (and so each chain head) off the machine. Lines written
 * before the chain existed are an unchained prefix, skipped by the verifier.
 */
export function chainLink(prev: string, lineWithoutChain: string): string {
  return createHash("sha256").update(prev).update("\n").update(lineWithoutChain).digest("hex");
}

export interface ChainVerdict {
  /** True when every chained line links to the one before it. */
  ok: boolean;
  /** Lines checked (chained), and lines before the chain started. */
  chained: number;
  unchained: number;
  /** The seq of the first line that does not link, when !ok. */
  brokenAt?: number;
  /** The last good chain value (the head), for anchoring elsewhere. */
  head: string | null;
}

/** Verify one session log's chain from its raw NDJSON text. Pure. */
export function verifyChainText(raw: string): ChainVerdict {
  let prev = "";
  let chained = 0;
  let unchained = 0;
  let started = false;
  let head: string | null = null;
  for (const line of raw.split("\n")) {
    if (line.trim() === "") continue;
    let obj: Record<string, unknown>;
    try { obj = JSON.parse(line) as Record<string, unknown>; } catch { return { ok: false, chained, unchained, brokenAt: undefined, head }; }
    const seq = typeof obj["seq"] === "number" ? (obj["seq"] as number) : undefined;
    const link = obj["chain"];
    if (typeof link !== "string") {
      if (started) return { ok: false, chained, unchained, ...(seq !== undefined ? { brokenAt: seq } : {}), head };
      unchained += 1;
      continue;
    }
    started = true;
    const { chain: _drop, ...rest } = obj;
    if (chainLink(prev, JSON.stringify(rest)) !== link) {
      return { ok: false, chained, unchained, ...(seq !== undefined ? { brokenAt: seq } : {}), head };
    }
    prev = link;
    head = link;
    chained += 1;
  }
  return { ok: true, chained, unchained, head };
}

/**
 * TENANT (policy-surface.md §2.7): every session belongs to exactly
 * one of two tenants — `live` (a human's real agent run) or `test` (an e2e
 * suite, a harness, a dev rig). Whoever mints the session stamps its events
 * (`event.tenant`); an explicitly tenanted arbiter refuses the other tenant's
 * events and labels unstamped ones as its own, so the dashboard never has to
 * guess from a session-id prefix again. An arbiter with no tenant configured
 * is UNTENANTED (legacy): it accepts everything and labels nothing.
 */
export type Tenant = "live" | "test";

export function isTenant(v: unknown): v is Tenant {
  return v === "live" || v === "test";
}

/** `MANDU_TENANT` → Tenant; unset/empty → undefined (untenanted); anything
 *  else is a configuration error and throws (never a silent fallback). */
export function tenantFromEnv(env: NodeJS.ProcessEnv = process.env): Tenant | undefined {
  const raw = env.MANDU_TENANT;
  if (raw === undefined || raw === "") return undefined;
  if (isTenant(raw)) return raw;
  throw new Error(`MANDU_TENANT must be "live" or "test" (got ${JSON.stringify(raw)})`);
}

/**
 * Per-session incremental summary state (sessions() cache). All offsets are in
 * BYTES, not JS string characters — events carry multi-byte UTF-8 (emoji in
 * labels), and the resume offset must land exactly after a real newline byte.
 */
interface SummaryCacheEntry {
  /** File identity at the last reconcile; any mismatch → resync. */
  ino: number;
  size: number;
  mtimeMs: number;
  /** Byte offset just past the last CONSUMED newline (torn tails stay unconsumed). */
  parsedBytes: number;
  /** Running summary over the consumed prefix. */
  count: number;
  firstTs: string | null;
  lastTs: string | null;
  /** The first stamped `tenant` seen (null until one is). */
  tenant: Tenant | null;
}

/** Summary row returned by the `sessions` op. */
export interface SessionSummary {
  sessionId: string;
  /** Number of persisted events in the session. */
  count: number;
  /** `ts` of the first event (or null if no event carried a ts). */
  firstTs: string | null;
  /** `ts` of the last event (or null if no event carried a ts). */
  lastTs: string | null;
  /** The session's tenant, from the first stamped event; absent when no event
   *  in the session carries a stamp (pre-tenancy traffic). */
  tenant?: Tenant;
}

/**
 * Return the default event directory, the path table's `events` entry
 * (on-disk-layout.md §3, §5):
 *
 *   ${MANDU_HOME:-~/.mandu}/events   on disk, owner-only
 *
 * No environment variable moves it; the daemon's `--event-dir` flag
 * (ipc/server-args.ts) names another directory for the store it opens.
 *
 * The log holds originals (`DualRepr.original`), so it lives in the one home
 * the agent may not read. History: until 2026-09-05 the default was the
 * per-boot runtime dir, and three reboots on 2026-09-04 wiped every session
 * trace; until the one-home flip it was `${XDG_STATE_HOME:-~/.local/state}/
 * mandu/events` (runtime-instances.md §12).
 *
 * The same rule resolves in dashboard/src/event-dir.ts and (host side, with
 * the passwd home — see the comment there) scripts/ci/docker-run.sh, so the
 * host arbiter, the dashboard's docker mode, and CI's --publish-events agree
 * on one directory with no config. A change belongs in the table
 * (scripts/paths/mandu-paths.mjs), never here;
 * tests/stack/mandu-paths-parity.test.ts checks the owners.
 */
export function getEventDir(env: NodeJS.ProcessEnv = process.env): string {
  // `env.HOME` is consulted before os.homedir() so a caller-supplied env
  // (tests, the launcher's composed env) is honored the way a spawned
  // process would.
  return manduPath("events", env, env.HOME || homedir());
}

/**
 * Mandu's own directories to tighten for an event store at `dir`: the
 * table's `events` and `events-test` (with the home and, for the test tenant,
 * `events` above them). Empty for any other directory (one an
 * `--event-dir` flag names outside the home keeps its mode). Pure.
 */
export function ownEventDirs(dir: string, env: NodeJS.ProcessEnv = process.env): string[] {
  const home = env.HOME || homedir();
  const d = resolve(dir);
  const mh = manduPath("mandu-home", env, home);
  const ev = manduPath("events", env, home);
  const evt = manduPath("events-test", env, home);
  if (d === resolve(evt)) return [evt, ev, mh];
  if (d === resolve(ev)) return [ev, mh];
  return [];
}

/** Retention window for the event store, in days, from
 *  $MANDU_EVENT_RETENTION_DAYS (server-main → ArbiterServerOptions.
 *  eventRetentionMs): unset/blank/unparseable/negative → 90 — deliberately
 *  generous, the sweep exists to bound disk growth, not to expire evidence
 *  anyone still wants; `0` → never prune. Pure. */
export const DEFAULT_EVENT_RETENTION_DAYS = 90;
export function eventRetentionDaysFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = (env.MANDU_EVENT_RETENTION_DAYS ?? "").trim();
  if (raw === "") return DEFAULT_EVENT_RETENTION_DAYS;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : DEFAULT_EVENT_RETENTION_DAYS;
}

/** A sessionId is used directly as a filename component; reject path-traversal
 * and separators so a malicious emitter cannot escape the event dir. */
function isSafeSessionId(sessionId: unknown): sessionId is string {
  return (
    typeof sessionId === "string" &&
    sessionId.length > 0 &&
    sessionId.length <= 256 &&
    !sessionId.includes("/") &&
    !sessionId.includes("\\") &&
    !sessionId.includes("\0") &&
    sessionId !== "." &&
    sessionId !== ".."
  );
}

/**
 * Append-only, per-session NDJSON event store + per-session seq counter.
 *
 * In-process state is just the next-seq map; the NDJSON files are the source of
 * truth. Node's JS is single-threaded so `emit` (read-modify-write of the seq
 * counter + a single appendFileSync) is atomic with respect to other arbiter
 * requests on the same process. The append itself is a single syscall of a
 * newline-terminated string, so even a *second* writer process appending to the
 * same file interleaves only at line boundaries (O_APPEND semantics), never
 * mid-line.
 */
export class EventStore {
  private readonly dir: string;
  /** sessionId → next seq to assign (>= 1). Lazily seeded from disk. */
  private readonly nextSeq = new Map<string, number>();
  /** Whether we've reconciled a session's nextSeq against its NDJSON file. */
  private readonly seeded = new Set<string>();
  /** sessionId → the chain value of its last stored line ("" before any). */
  private readonly lastChain = new Map<string, string>();
  /**
   * sessionId → incrementally-maintained summary (see sessions()). Keyed by the
   * file's (ino, size, mtimeMs) identity so `sessions()` costs one stat per file
   * when nothing changed, and parses only the APPENDED suffix when it did —
   * the log is append-only, so bytes before `parsedBytes` never change. Without
   * this, every `sessions` op re-parsed every line of every session file; at
   * ~1000 sessions / 220MB (2026-07-18 shared stack) that blew the dashboard's
   * per-op IPC deadline on every poll and blanked the session rail.
   */
  private readonly summaryCache = new Map<string, SummaryCacheEntry>();

  /** `env` resolves the table's paths for the ownership rule (ensureDir). */
  constructor(dir?: string, private readonly env: NodeJS.ProcessEnv = process.env) {
    this.dir = dir ?? getEventDir(env);
  }

  private dirReady = false;
  /** The event directory, opened once with every component on its way
   *  checked (safe-log.ts): each record is appended in this descriptor. */
  private safeDir: SafeDir | null = null;

  /** Create the directory owner-only (0700), and tighten Mandu's own event
   *  dirs (ownEventDirs) when an older version left them group- or
   *  world-readable: the records carry originals (on-disk-layout.md §1, §3).
   *  A directory outside the home (an `--event-dir`) keeps its mode. Once per store;
   *  a chmod that fails leaves the mode as it was. */
  private ensureDir(): void {
    if (this.dirReady && this.safeDir !== null && existsSync(this.dir)) return;
    // Made one directory at a time (0700) and opened through no link of
    // this user's on the way (runtime-instances.md §2, "planted paths",
    // 2026-10-17): a per-launch arbiter's event dir is in the session's scope
    // dir, which the agent may write while it runs, and `appendFileSync` by
    // path followed a link planted at `<session>.ndjson` (or at the dir) into
    // whatever file it named, appending records the agent can steer.
    if (this.safeDir !== null) closeSafeDir(this.safeDir);
    this.safeDir = openSafeDir(resolve(this.dir));
    for (const d of ownEventDirs(this.dir, this.env)) {
      try {
        if ((statSync(d).mode & 0o077) !== 0) chmodSync(d, 0o700);
      } catch { /* absent, or not ours */ }
    }
    this.dirReady = true;
  }

  /** The resolved event directory. */
  get directory(): string {
    return this.dir;
  }

  private filePathFor(sessionId: string): string {
    return join(this.dir, `${sessionId}.ndjson`);
  }

  /** Parse one session's NDJSON file, tolerating partial/concurrent writes.
   * A trailing line lacking its newline, or any unparseable line, is skipped. */
  private readAll(sessionId: string): StoredEvent[] {
    const path = this.filePathFor(sessionId);
    let raw: string;
    try {
      raw = readFileSync(path, "utf8");
    } catch {
      return []; // no file yet → no events
    }
    const out: StoredEvent[] = [];
    let start = 0;
    const len = raw.length;
    while (start < len) {
      const nl = raw.indexOf("\n", start);
      if (nl < 0) {
        // Trailing bytes with no terminating newline: a record still being
        // written by a concurrent appender. Skip it — it'll be complete on the
        // next read once the appender's single write syscall lands.
        break;
      }
      const line = raw.slice(start, nl);
      start = nl + 1;
      if (line.trim() === "") continue;
      try {
        const obj = JSON.parse(line) as StoredEvent;
        if (obj && typeof obj === "object" && typeof obj.seq === "number") {
          out.push(obj);
        }
      } catch {
        // Unparseable line (torn write / corruption) — skip, never throw.
      }
    }
    return out;
  }

  /** Ensure nextSeq[sessionId] reflects the max seq already persisted, so a
   * arbiter restart keeps the per-session counter monotonic. */
  private seed(sessionId: string): void {
    if (this.seeded.has(sessionId)) return;
    let max = 0;
    let chain = "";
    for (const e of this.readAll(sessionId)) {
      if (e.seq > max) max = e.seq;
      if (typeof e.chain === "string") chain = e.chain;
    }
    if (!this.nextSeq.has(sessionId)) this.nextSeq.set(sessionId, max + 1);
    if (!this.lastChain.has(sessionId)) this.lastChain.set(sessionId, chain);
    this.seeded.add(sessionId);
  }

  /**
   * Assign the next per-session seq, persist `{...event, seq}` as one atomic
   * NDJSON line, and return the stored event (with seq). Throws on a missing/
   * invalid `id` or `sessionId`, or on a filesystem write failure.
   */
  append(event: ArbiterEvent): StoredEvent {
    if (!isSafeSessionId(event.sessionId)) {
      throw new Error("event.sessionId is required and must be a safe non-empty string");
    }
    if (typeof event.id !== "string" || event.id.length === 0) {
      throw new Error("event.id is required and must be a non-empty string");
    }
    const sessionId = event.sessionId;
    this.seed(sessionId);

    const seq = this.nextSeq.get(sessionId)!;
    // A caller-supplied `chain` is not the store's to trust: dropped, then
    // the store's own link is appended as the LAST key (verifyChainText
    // re-serializes the line without it, key order preserved).
    const { chain: _callerChain, ...body } = event as ArbiterEvent & { chain?: unknown };
    const unchained = { ...body, seq } as StoredEvent;
    const chain = chainLink(this.lastChain.get(sessionId) ?? "", JSON.stringify(unchained));
    const stored: StoredEvent = { ...unchained, chain };

    this.ensureDir();
    // Single write syscall of a complete newline-terminated line ⇒ append-atomic
    // per record; a reader never observes a half-written line at the tail.
    // Owner-only: a record carries originals (DualRepr.original).
    // Never through a link, a FIFO or a hard link at the name (safe-log.ts).
    const fd = openSafeLogIn(this.safeDir!, `${sessionId}.ndjson`, { mode: 0o600 });
    try {
      writeSync(fd, JSON.stringify(stored) + "\n");
    } finally {
      closeSync(fd);
    }

    // Only advance the counter AFTER a successful write, so a failed emit does
    // not burn a seq (and a retry reuses it).
    this.nextSeq.set(sessionId, seq + 1);
    this.lastChain.set(sessionId, chain);
    return stored;
  }

  /** Verify one session log's hash chain (see verifyChainText). */
  verifyChain(sessionId: string): ChainVerdict {
    if (!isSafeSessionId(sessionId)) throw new Error("invalid sessionId");
    let raw = "";
    try { raw = readFileSync(this.filePathFor(sessionId), "utf8"); } catch { /* no log: vacuously ok */ }
    return verifyChainText(raw);
  }

  /**
   * Delete one session's event log + its in-memory counters. OBSERVABILITY
   * ONLY: this is the store behind the dashboard's sidebar delete (any
   * session, live or test) — it touches nothing on the security path. Returns
   * false when the session has no NDJSON file (unknown session), so the
   * caller can answer gracefully instead of pretending success. The store is
   * a policy-free storage primitive, like append/since; the safe-session-id
   * guard (a traversal-shaped id throws) is its only refusal.
   */
  delete(sessionId: string): boolean {
    if (!isSafeSessionId(sessionId)) {
      throw new Error("sessionId is required and must be a safe non-empty string");
    }
    const path = this.filePathFor(sessionId);
    if (!existsSync(path)) return false;
    unlinkSync(path);
    // Drop the per-session seq state so a later reuse of the id re-seeds from
    // the (now absent) file and starts back at seq 1 — a stale counter would
    // otherwise leave a phantom gap in a brand-new log.
    this.nextSeq.delete(sessionId);
    this.seeded.delete(sessionId);
    this.lastChain.delete(sessionId);
    this.summaryCache.delete(sessionId);
    return true;
  }

  /** Persisted events for a session with `seq > sinceSeq` (default 0), in seq
   * order. Tolerates partial/concurrent writes (see readAll). */
  since(sessionId: string, sinceSeq = 0): StoredEvent[] {
    if (!isSafeSessionId(sessionId)) {
      throw new Error("sessionId is required and must be a safe non-empty string");
    }
    const all = this.readAll(sessionId);
    all.sort((a, b) => a.seq - b.seq);
    return sinceSeq > 0 ? all.filter((e) => e.seq > sinceSeq) : all;
  }

  /**
   * List every session that has an NDJSON file, with counts + ts bounds.
   *
   * Incremental (see summaryCache): one stat per file; an unchanged
   * (ino, size, mtime) reuses the cached summary, a grown same-inode file
   * parses only the appended suffix, and anything else (new file, replaced
   * inode, shrink) falls back to a full re-parse of that one file. The
   * append-only / O_APPEND writer contract is what makes the suffix merge
   * sound; an out-of-contract in-place rewrite that keeps inode AND
   * monotonically-grown size is the one shape the identity check cannot see.
   */
  sessions(): SessionSummary[] {
    if (!existsSync(this.dir)) return [];
    let names: string[];
    try {
      names = readdirSync(this.dir);
    } catch {
      return [];
    }
    const seen = new Set<string>();
    const out: SessionSummary[] = [];
    for (const name of names) {
      if (!name.endsWith(".ndjson")) continue;
      const sessionId = name.slice(0, -".ndjson".length);
      seen.add(sessionId);
      const entry = this.reconcile(sessionId);
      // A file holding no valid event yet (empty / only a torn tail) is not a
      // session — same behavior as the pre-cache full scan.
      if (!entry || entry.count === 0) continue;
      out.push({
        sessionId,
        count: entry.count,
        firstTs: entry.firstTs,
        lastTs: entry.lastTs,
        ...(entry.tenant ? { tenant: entry.tenant } : {}),
      });
    }
    // Evict entries whose file vanished outside delete() (external rm/rotation).
    for (const id of this.summaryCache.keys()) {
      if (!seen.has(id)) this.summaryCache.delete(id);
    }
    out.sort((a, b) => a.sessionId.localeCompare(b.sessionId));
    return out;
  }

  /**
   * Session ids whose NDJSON file was last appended more than `maxAgeMs` ago,
   * judged by file mtime — under the append-only writer contract mtime IS the
   * session's last-activity time, so a session that is still being written
   * to can never qualify. `exempt` ids are never returned (the server passes
   * the reserved `arbiter-admin` audit stream). A pure listing: the caller
   * removes each id through the deleteSession path so live subscribe streams
   * are ended with the file (ArbiterServer.pruneStaleSessions).
   */
  staleSessions(
    maxAgeMs: number,
    now: number = Date.now(),
    exempt: ReadonlySet<string> = new Set(),
  ): string[] {
    if (!(maxAgeMs > 0)) return [];
    let names: string[];
    try {
      names = readdirSync(this.dir);
    } catch {
      return [];
    }
    const out: string[] = [];
    for (const name of names) {
      if (!name.endsWith(".ndjson")) continue;
      const sessionId = name.slice(0, -".ndjson".length);
      if (exempt.has(sessionId) || !isSafeSessionId(sessionId)) continue;
      let st: ReturnType<typeof statSync>;
      try {
        st = statSync(join(this.dir, name));
      } catch {
        continue; // raced delete — not ours to prune
      }
      if (now - st.mtimeMs > maxAgeMs) out.push(sessionId);
    }
    out.sort();
    return out;
  }

  /** Sync sessionId's cache entry with its file. Returns null when the file is
   * unreadable (raced delete) — the entry is dropped so a later same-id file
   * starts clean. */
  private reconcile(sessionId: string): SummaryCacheEntry | null {
    const path = this.filePathFor(sessionId);
    let st: ReturnType<typeof statSync>;
    try {
      st = statSync(path);
    } catch {
      this.summaryCache.delete(sessionId);
      return null;
    }
    const cached = this.summaryCache.get(sessionId);
    if (cached && cached.ino === st.ino && cached.size === st.size && cached.mtimeMs === st.mtimeMs) {
      return cached;
    }
    // Same inode, never shrunk → append-only growth: resume at parsedBytes.
    const grown = cached !== undefined && cached.ino === st.ino && st.size >= cached.size;
    const entry: SummaryCacheEntry = grown
      ? { ...cached, size: st.size, mtimeMs: st.mtimeMs }
      : {
          ino: st.ino,
          size: st.size,
          mtimeMs: st.mtimeMs,
          parsedBytes: 0,
          count: 0,
          firstTs: null,
          lastTs: null,
          tenant: null,
        };
    this.consumeSuffix(path, entry);
    this.summaryCache.set(sessionId, entry);
    return entry;
  }

  /** Parse the unconsumed byte window [parsedBytes, size) of `path` into
   * `entry`, consuming only complete lines (a torn tail stays unconsumed and is
   * re-attempted once its terminating newline lands). Byte-domain throughout so
   * multi-byte UTF-8 never skews the resume offset. */
  private consumeSuffix(path: string, entry: SummaryCacheEntry): void {
    const want = entry.size - entry.parsedBytes;
    if (want <= 0) return;
    let buf: Buffer;
    try {
      const fd = openSync(path, "r");
      try {
        buf = Buffer.alloc(want);
        let got = 0;
        while (got < want) {
          const n = readSync(fd, buf, got, want - got, entry.parsedBytes + got);
          if (n <= 0) break;
          got += n;
        }
        if (got < want) buf = buf.subarray(0, got); // shrank mid-read; next stat resyncs
      } finally {
        closeSync(fd);
      }
    } catch {
      return; // raced delete/rotation — next sessions() re-stats and resyncs
    }
    let start = 0;
    for (;;) {
      const nl = buf.indexOf(0x0a, start);
      if (nl < 0) break;
      const line = buf.subarray(start, nl).toString("utf8");
      start = nl + 1;
      if (line.trim() === "") continue;
      try {
        const obj = JSON.parse(line) as StoredEvent;
        if (obj && typeof obj === "object" && typeof obj.seq === "number") {
          entry.count += 1;
          if (typeof obj.ts === "string") {
            if (entry.firstTs === null) entry.firstTs = obj.ts;
            entry.lastTs = obj.ts;
          }
          if (entry.tenant === null && isTenant(obj.tenant)) entry.tenant = obj.tenant;
        }
      } catch {
        // Unparseable line — skipped but consumed, matching readAll().
      }
    }
    entry.parsedBytes += start;
  }
}

/** Convenience: a temp event dir helper for tests/callers (not used at runtime). */
export function tmpEventDirName(prefix = "mandu-events-"): string {
  return join(tmpdir(), prefix + Math.random().toString(36).slice(2));
}
