/**
 * transcript-stores — where OpenCode, Goose and OpenClaw keep their
 * sessions, and how the past-sessions scan reads them without touching them
 * (docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md
 * §3 items 3 and 8, §4).
 *
 * Three of the stores are SQLite databases a running agent may be writing
 * at the same moment (OpenCode's `opencode.db`, Goose's
 * `sessions/sessions.db`, OpenClaw 9.x's per-agent
 * `agents/<id>/agent/openclaw-agent.sqlite`). The arbiter is the single
 * writer of its own database (db/sqlite.ts); an agent's is the agent's, so
 * the scan opens it READ-ONLY and in a way that can neither change it nor
 * hold the agent up ({@link openAgentStore}):
 *
 *   - When the database has no write-ahead log in use (no `-wal` file, or an
 *     empty one: the agent is not running, or the database is in rollback
 *     mode), it is opened `immutable=1`: SQLite then takes no lock at all
 *     and creates no file, so a writer that starts meanwhile is never
 *     blocked. Everything committed is in the main file.
 *   - When a `-wal` with content and its `-shm` exist (the agent is running,
 *     or stopped without a checkpoint), the newest messages are only in the
 *     WAL, which `immutable` would not read. It is then opened `mode=ro`, a
 *     WAL reader: readers and the writer never block each other in WAL mode,
 *     the connection never writes the database or the WAL and creates no
 *     file; the one thing it touches is its read-mark in the `-shm`
 *     wal-index, as every reader of a WAL database does. If that open fails
 *     (a `-shm` it may not map, a recovery a reader may not run), it falls
 *     back to `immutable` and reads what is checkpointed.
 *
 * Opening `mode=ro` when no `-wal`/`-shm` exists would CREATE them (probed:
 * SQLite makes both for a WAL database), which is why that case is
 * immutable. An immutable read of a file the agent is checkpointing into can
 * meet a torn page; a session whose read fails is counted as unreadable,
 * never thrown.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { DatabaseSync } from "node:sqlite";
import { createReadStream, existsSync, mkdtempSync, readdirSync, rmSync, statSync, type Stats } from "node:fs";
import { tmpdir } from "node:os";
import { createInterface } from "node:readline";
import { basename, dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import zlib from "node:zlib";
import type { SentText, SessionMeta, TranscriptAgent } from "./transcript-scan.js";
import type { SessionActs } from "./transcript-acts.js";
import {
  gooseActs, gooseRequestLogTexts, gooseSentTexts, isoTime, opencodeV1Acts, providerOf, opencodeV1SentTexts, opencodeV2Acts,
  opencodeV2SentTexts, openclawActs, openclawSentTexts, type GooseMessage, type OpencodeV1Message, type OpencodeV2Row,
} from "./transcript-readers.js";

/** How a source's files are laid out and read. */
export type StoreKind =
  /** OpenCode's `opencode.db` (1.x `message`/`part`, 2.x `session_message`). */
  | "opencode-db"
  /** Goose's `sessions/sessions.db`. */
  | "goose-db"
  /** Goose's older `sessions/<id>.jsonl`. */
  | "goose-jsonl"
  /** Goose's request log, `logs/llm_request.*.jsonl`. */
  | "goose-request-log"
  /** OpenClaw's `agents/<id>/sessions/<session>.jsonl` (before 9.x). */
  | "openclaw-jsonl"
  /** OpenClaw 9.x's `agents/<id>/agent/openclaw-agent.sqlite`. */
  | "openclaw-db";

/** What one session gave the scan. */
export interface ReadSession {
  texts: Iterable<SentText>;
  meta: SessionMeta;
  acts?: SessionActs;
}

/** One unit of the scan: a file, or a session of a database. */
export interface StoreItem {
  agent: TranscriptAgent;
  /** The file it is in. */
  path: string;
  /** Its last write (ms), newest read first. */
  mtimeMs: number;
  /** Bytes it holds (a file's size, a session's rows). */
  size: number;
  /** The session it belongs to (a child session's is its parent's). */
  session: string;
  read: () => Promise<ReadSession>;
}

type Row = Record<string, unknown>;

/** How a database was opened (see the module comment). */
export type StoreOpenMode = "wal-reader" | "immutable";

const fileSize = (p: string): number => { try { return statSync(p).size; } catch { return -1; } };

/** A `file:` URI for `path` with `query` (`?mode=ro`), as a string: Node
 *  22.13's `DatabaseSync` takes a string only, never a URL object. */
function uriOf(path: string, query: string): string {
  const u = pathToFileURL(path);
  u.search = query;
  return u.href;
}

let uriProbe: boolean | undefined;

/**
 * Does this Node's `node:sqlite` open SQLite URI filenames (`file:…?mode=ro`)?
 * Node 22.15 and later do (probed on 22.15.0, 22.16.0, 22.22.1); 22.13.0, the
 * floor, does not: it takes the string as a plain file name, and a read-only
 * open of one that does not exist fails without creating anything. Probed
 * once, on a database of its own in a fresh temporary folder, removed after.
 */
export function sqliteUriFilenames(): boolean {
  if (uriProbe !== undefined) return uriProbe;
  const dir = mkdtempSync(join(tmpdir(), "mdu-sqlite-uri-"));
  try {
    const p = join(dir, "probe.db");
    new DatabaseSync(p).close();
    try {
      new DatabaseSync(uriOf(p, "?mode=ro"), { readOnly: true }).close();
      uriProbe = true;
    } catch {
      uriProbe = false;
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  return uriProbe;
}

/**
 * Open an agent's SQLite store read-only, never blocking or changing it
 * (the module comment says how). Without URI filenames (a Node before
 * 22.15, {@link sqliteUriFilenames}) there is no `immutable` open, and a
 * plain read-only open of a database with no WAL in use would create its
 * `-wal` and `-shm` (probed): then only a database whose WAL is in use is
 * read (a plain read-only path is then a WAL reader that creates nothing),
 * and any other throws, so the scan counts it as unreadable. Throws when it
 * cannot be opened at all. `uri` overrides the probe (tests).
 */
export function openAgentStore(path: string, opts: { uri?: boolean } = {}): { db: DatabaseSync; mode: StoreOpenMode } {
  const uri = opts.uri ?? sqliteUriFilenames();
  if (fileSize(`${path}-wal`) > 0 && fileSize(`${path}-shm`) >= 0) {
    let db: DatabaseSync | undefined;
    try {
      db = new DatabaseSync(uri ? uriOf(path, "?mode=ro") : path, { readOnly: true });
      db.prepare("SELECT count(*) FROM sqlite_master").get();
      return { db, mode: "wal-reader" };
    } catch {
      try { db?.close(); } catch { /* not open */ }
    }
  }
  if (!uri) throw new Error("this Node cannot open a stopped agent's database without touching it: Node 22.15 or later reads it");
  const db = new DatabaseSync(uriOf(path, "?immutable=1"), { readOnly: true });
  db.prepare("SELECT count(*) FROM sqlite_master").get();
  return { db, mode: "immutable" };
}

function tablesOf(db: DatabaseSync): Set<string> {
  return new Set((db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Row[]).map((r) => String(r["name"])));
}

function columnsOf(db: DatabaseSync, table: string): Set<string> {
  // `table` is one of this module's constant names, never input.
  return new Set((db.prepare(`SELECT name FROM pragma_table_info('${table}')`).all() as Row[]).map((r) => String(r["name"])));
}

/** `cols` of `table` that exist, as a select list (a missing one as NULL). */
function pick(have: ReadonlySet<string>, cols: readonly string[]): string {
  return cols.map((c) => (have.has(c) ? `"${c}"` : `NULL AS "${c}"`)).join(", ");
}

function parse(v: unknown): unknown {
  if (typeof v !== "string") return v ?? undefined;
  try { return JSON.parse(v) as unknown; } catch { return undefined; }
}

const num = (v: unknown): number | undefined => (typeof v === "number" ? v : typeof v === "bigint" ? Number(v) : undefined);
const ms = (v: unknown): number => { const t = isoTime(num(v) ?? v); return t === undefined ? 0 : Date.parse(t); };

/** The root of `id` in a parent map (cycle-safe). */
function rootOf(id: string, parent: ReadonlyMap<string, string>): string {
  let cur = id;
  const seen = new Set<string>();
  while (parent.has(cur) && !seen.has(cur)) { seen.add(cur); cur = parent.get(cur)!; }
  return cur;
}

/** A session of a database, before it is read. */
interface DbSession {
  id: string;
  updatedMs: number;
  bytes: number;
  read: () => ReadSession;
}

// ── OpenCode ────────────────────────────────────────────────────────────────

/** The sessions of an OpenCode database, either generation. A session with
 *  2.x `session_message` rows is read from them (a 2.x database migrated
 *  from 1.x keeps the 1.x rows too, and the migration copied them); any
 *  other from the 1.x `message` and `part` tables. A child session (a
 *  subagent's, `parent_id`) counts with its parent. */
function opencodeSessions(db: DatabaseSync): Array<DbSession & { root: string }> {
  const T = tablesOf(db);
  const info = new Map<string, Row>();
  for (const t of ["session", "session_v2"]) {
    if (!T.has(t)) continue;
    const have = columnsOf(db, t);
    for (const r of db.prepare(`SELECT ${pick(have, ["id", "parent_id", "directory", "permission", "time_updated"])} FROM "${t}"`).all() as Row[]) {
      info.set(String(r["id"]), { ...info.get(String(r["id"])), ...Object.fromEntries(Object.entries(r).filter(([, v]) => v !== null)) });
    }
  }
  const agg = new Map<string, { v2: number; v1: number; bytes: number; updated: number }>();
  const add = (sql: string, which: "v1" | "v2" | "parts"): void => {
    for (const r of db.prepare(sql).all() as Row[]) {
      const id = String(r["sid"]);
      const a = agg.get(id) ?? { v2: 0, v1: 0, bytes: 0, updated: 0 };
      if (which !== "parts") a[which] += num(r["n"]) ?? 0;
      a.bytes += num(r["b"]) ?? 0;
      a.updated = Math.max(a.updated, ms(r["u"]));
      agg.set(id, a);
    }
  };
  const v2 = T.has("session_message") ? columnsOf(db, "session_message") : new Set<string>();
  if (v2.has("session_id") && v2.has("data")) add(`SELECT session_id AS sid, count(*) AS n, sum(length(data)) AS b, max(${v2.has("time_updated") ? "time_updated" : "time_created"}) AS u FROM session_message GROUP BY session_id`, "v2");
  const v1m = T.has("message") ? columnsOf(db, "message") : new Set<string>();
  const v1p = T.has("part") ? columnsOf(db, "part") : new Set<string>();
  if (v1m.has("session_id") && v1m.has("data")) add(`SELECT session_id AS sid, count(*) AS n, sum(length(data)) AS b, max(${v1m.has("time_updated") ? "time_updated" : "time_created"}) AS u FROM message GROUP BY session_id`, "v1");
  if (v1p.has("session_id") && v1p.has("data")) add("SELECT session_id AS sid, sum(length(data)) AS b, 0 AS u FROM part GROUP BY session_id", "parts");
  const parent = new Map<string, string>();
  for (const [id, r] of info) if (typeof r["parent_id"] === "string" && r["parent_id"] !== "") parent.set(id, r["parent_id"]);
  const out: Array<DbSession & { root: string }> = [];
  for (const [id, a] of agg) {
    if (a.v1 + a.v2 === 0) continue;
    const r = info.get(id) ?? {};
    const root = rootOf(id, parent);
    const dir = (info.get(root) ?? r)["directory"];
    const cwd = typeof dir === "string" ? dir : undefined;
    const permission = parse(r["permission"]);
    const useV2 = a.v2 > 0;
    out.push({
      id, root, bytes: a.bytes, updatedMs: Math.max(a.updated, ms(r["time_updated"])),
      read: () => {
        const meta: SessionMeta = cwd !== undefined ? { cwd } : {};
        if (useV2) {
          const order = v2.has("seq") ? "seq, id" : "time_created, id";
          const rows: OpencodeV2Row[] = (db.prepare(`SELECT ${pick(v2, ["type", "seq", "time_created", "data"])} FROM session_message WHERE session_id = ? ORDER BY ${order}`).all(id) as Row[])
            .map((x) => ({ type: String(x["type"] ?? ""), ...(num(x["seq"]) !== undefined ? { seq: num(x["seq"])! } : {}), ...(num(x["time_created"]) !== undefined ? { time_created: num(x["time_created"])! } : {}), data: parse(x["data"]) }));
          return { texts: [...opencodeV2SentTexts(rows, meta, id)], meta, acts: opencodeV2Acts(rows, permission) };
        }
        const msgs = (db.prepare(`SELECT ${pick(v1m, ["id", "time_created", "data"])} FROM message WHERE session_id = ? ORDER BY time_created, id`).all(id) as Row[]);
        const parts = new Map<string, unknown[]>();
        const partSql = v1p.has("session_id")
          ? "SELECT message_id, data FROM part WHERE session_id = ? ORDER BY message_id, id"
          : "SELECT message_id, data FROM part WHERE message_id IN (SELECT id FROM message WHERE session_id = ?) ORDER BY message_id, id";
        if (v1p.has("message_id")) {
          for (const p of db.prepare(partSql).all(id) as Row[]) {
            const k = String(p["message_id"]);
            const l = parts.get(k) ?? [];
            l.push(parse(p["data"]));
            parts.set(k, l);
          }
        }
        const messages: OpencodeV1Message[] = msgs.map((m) => ({
          id: String(m["id"]), ...(num(m["time_created"]) !== undefined ? { time_created: num(m["time_created"])! } : {}), data: parse(m["data"]), parts: parts.get(String(m["id"])) ?? [],
        }));
        return { texts: [...opencodeV1SentTexts(messages, meta, id)], meta, acts: opencodeV1Acts(messages, permission) };
      },
    });
  }
  return out;
}

// ── Goose ───────────────────────────────────────────────────────────────────

/** The sessions of Goose's `sessions.db`; a sub-agent's session
 *  (`parent_session_id`) counts with its parent. */
function gooseSessions(db: DatabaseSync): Array<DbSession & { root: string }> {
  const T = tablesOf(db);
  if (!T.has("messages")) return [];
  const sc = T.has("sessions") ? columnsOf(db, "sessions") : new Set<string>();
  const mc = columnsOf(db, "messages");
  if (!mc.has("session_id") || !mc.has("content_json")) return [];
  const info = new Map<string, Row>();
  if (sc.has("id")) for (const r of db.prepare(`SELECT ${pick(sc, ["id", "working_dir", "goose_mode", "parent_session_id", "updated_at", "provider_name"])} FROM sessions`).all() as Row[]) info.set(String(r["id"]), r);
  const parent = new Map<string, string>();
  for (const [id, r] of info) if (typeof r["parent_session_id"] === "string" && r["parent_session_id"] !== "") parent.set(id, r["parent_session_id"]);
  const out: Array<DbSession & { root: string }> = [];
  const tcol = mc.has("created_timestamp") ? "created_timestamp" : "NULL";
  for (const a of db.prepare(`SELECT session_id AS sid, count(*) AS n, sum(length(content_json)) AS b, max(${tcol}) AS u FROM messages GROUP BY session_id`).all() as Row[]) {
    const id = String(a["sid"]);
    const r = info.get(id) ?? {};
    const root = rootOf(id, parent);
    const wd = (info.get(root) ?? r)["working_dir"];
    const cwd = typeof wd === "string" ? wd : undefined;
    out.push({
      id, root, bytes: num(a["b"]) ?? 0, updatedMs: Math.max(ms(a["u"]), ms(r["updated_at"])),
      read: () => {
        const provider = providerOf(r["provider_name"]);
        const meta: SessionMeta = { ...(cwd !== undefined ? { cwd } : {}), ...(provider !== undefined ? { provider } : {}) };
        const rows = db.prepare(`SELECT ${pick(mc, ["message_id", "role", "content_json", "metadata_json", "created_timestamp"])} FROM messages WHERE session_id = ? ORDER BY id`).all(id) as Row[];
        const messages: GooseMessage[] = rows.map((x) => ({ id: x["message_id"], role: x["role"], content: parse(x["content_json"]), metadata: parse(x["metadata_json"]), created: num(x["created_timestamp"]) }));
        return { texts: [...gooseSentTexts(messages, meta)], meta, acts: gooseActs(messages, r["goose_mode"]) };
      },
    });
  }
  return out;
}

// ── OpenClaw ────────────────────────────────────────────────────────────────

const unzstd = (zlib as unknown as { zstdDecompressSync?: (b: Uint8Array) => Buffer }).zstdDecompressSync;

/** The sessions of an OpenClaw 9.x agent database: each `session_id` of
 *  `transcript_events`, its events the records a `.jsonl` line held. An
 *  event OpenClaw stored compressed (`event_zstd`) is read where this Node
 *  has zstd (22.15 and later) and skipped otherwise. */
function openclawSessions(db: DatabaseSync): DbSession[] {
  const T = tablesOf(db);
  if (!T.has("transcript_events")) return [];
  const c = columnsOf(db, "transcript_events");
  if (!c.has("session_id") || !c.has("event_json")) return [];
  const size = c.has("event_utf8_bytes") ? "coalesce(length(event_json), event_utf8_bytes, 0)" : "coalesce(length(event_json), 0)";
  const out: DbSession[] = [];
  for (const a of db.prepare(`SELECT session_id AS sid, sum(${size}) AS b, max(${c.has("created_at") ? "created_at" : "NULL"}) AS u FROM transcript_events GROUP BY session_id`).all() as Row[]) {
    const id = String(a["sid"]);
    out.push({
      id, bytes: num(a["b"]) ?? 0, updatedMs: ms(a["u"]),
      read: () => {
        const recs: unknown[] = [];
        for (const row of db.prepare(`SELECT ${pick(c, ["event_json", "event_zstd"])} FROM transcript_events WHERE session_id = ? ORDER BY seq`).all(id) as Row[]) {
          if (typeof row["event_json"] === "string") recs.push(parse(row["event_json"]));
          else if (row["event_zstd"] instanceof Uint8Array && unzstd !== undefined) {
            try { recs.push(parse(unzstd(row["event_zstd"]).toString("utf8"))); } catch { /* a torn row */ }
          }
        }
        const meta: SessionMeta = {};
        return { texts: [...openclawSentTexts(recs, meta)], meta, acts: openclawActs(recs) };
      },
    });
  }
  return out;
}

// ── The files ───────────────────────────────────────────────────────────────

/** One JSONL file's records, parsed; a line that is not JSON is skipped. */
export async function readJsonlRecords(file: string): Promise<unknown[]> {
  const out: unknown[] = [];
  const rl = createInterface({ input: createReadStream(file), crlfDelay: Infinity });
  for await (const line of rl) {
    if (line === "") continue;
    try { out.push(JSON.parse(line)); } catch { /* a torn or foreign line */ }
  }
  return out;
}

/** Is `path` one of the transcript files of a source of `kind` rooted at
 *  `root`? The layouts: Goose's `<root>/<id>.jsonl` and
 *  `<root>/llm_request.<n>.jsonl`; OpenClaw's
 *  `<root>/<agent>/sessions/<session>.jsonl` and
 *  `<root>/<agent>/agent/openclaw-agent.sqlite`; a database source's root is
 *  the database itself. Pure. */
export function isStoreFile(kind: StoreKind, root: string, path: string): boolean {
  switch (kind) {
    case "opencode-db":
    case "goose-db":
      return path === root;
    case "goose-jsonl":
      return dirname(path) === root && path.endsWith(".jsonl");
    case "goose-request-log":
      return dirname(path) === root && /^llm_request\.[^/]+\.jsonl$/.test(basename(path));
    case "openclaw-jsonl":
      return dirname(dirname(dirname(path))) === root && basename(dirname(path)) === "sessions" && path.endsWith(".jsonl");
    case "openclaw-db":
      return dirname(dirname(dirname(path))) === root && basename(dirname(path)) === "agent" && basename(path) === "openclaw-agent.sqlite";
  }
}

/** Is `path` OpenClaw's run trace, `<session>.trajectory.jsonl`, beside the
 *  session it traces (written by 2026.7 and later, found by driving the real
 *  agent: plan 17 §6)? It is a store file (it holds the same text, so a known
 *  value is never taken from it) but not a session: its records are the
 *  compiled context of each run (`context.compiled`, `prompt.submitted`,
 *  `model.completed`, the system prompt and tool list among them, hundreds
 *  of kB), not the session's entries, so the scan does not read it, and a
 *  session is not counted twice. Pure. */
export function isRunTrace(kind: StoreKind, path: string): boolean {
  return kind === "openclaw-jsonl" && path.endsWith(".trajectory.jsonl");
}

/** The files of a source, at most `max` (`overflow` counts the rest). */
function storeFiles(kind: StoreKind, root: string, max: number, overflow: { n: number }): Array<{ path: string; st: Stats }> {
  const cands: string[] = [];
  const ls = (d: string): string[] => { try { return readdirSync(d); } catch { return []; } };
  if (kind === "opencode-db" || kind === "goose-db") { if (existsSync(root)) cands.push(root); }
  else if (kind === "goose-jsonl" || kind === "goose-request-log") for (const n of ls(root)) cands.push(join(root, n));
  else for (const a of ls(root)) {
    const sub = kind === "openclaw-jsonl" ? join(root, a, "sessions") : join(root, a, "agent");
    for (const n of ls(sub)) cands.push(join(sub, n));
  }
  const out: Array<{ path: string; st: Stats }> = [];
  for (const p of cands) {
    if (!isStoreFile(kind, root, p) || isRunTrace(kind, p)) continue;
    let st: Stats;
    try { st = statSync(p); } catch { continue; }
    if (!st.isFile()) continue;
    if (out.length >= max) { overflow.n++; continue; }
    out.push({ path: p, st });
  }
  return out;
}

/** The newest write of a database: its file or its WAL. */
function dbMtime(path: string, st: Stats): number {
  try { return Math.max(st.mtimeMs, statSync(`${path}-wal`).mtimeMs); } catch { return st.mtimeMs; }
}

/** Open databases, closed by {@link closeStores} when the scan ends. */
export type OpenStores = Map<string, DatabaseSync>;

export function closeStores(open: OpenStores): void {
  for (const db of open.values()) { try { db.close(); } catch { /* closed */ } }
  open.clear();
}

/**
 * The scan's units for one source of the new agents: a JSONL file per
 * session, or a database's sessions (each its own unit, sized by its rows,
 * timed by its newest message). A database is opened here
 * ({@link openAgentStore}) and kept in `open` until the scan ends; one that
 * cannot be opened counts in `failed`. At most `max` units per source.
 */
export function storeItems(src: { agent: TranscriptAgent; kind: StoreKind; root: string }, max: number, overflow: { n: number }, open: OpenStores, failed: { n: number }): StoreItem[] {
  const out: StoreItem[] = [];
  for (const f of storeFiles(src.kind, src.root, max, overflow)) {
    if (src.kind === "goose-jsonl" || src.kind === "openclaw-jsonl" || src.kind === "goose-request-log") {
      const kind = src.kind;
      // Goose's request log is one record of many sessions' requests, not a
      // session: its findings count it as one, the sessions read do not.
      const session = kind === "goose-request-log" ? join(src.root, "llm_request") : f.path;
      out.push({
        agent: src.agent, path: f.path, mtimeMs: f.st.mtimeMs, size: f.st.size, session,
        read: async () => {
          const recs = await readJsonlRecords(f.path);
          if (kind === "goose-request-log") {
            const logMeta: SessionMeta = { uncounted: true };
            return { texts: [...gooseRequestLogTexts(recs, new Date(f.st.mtimeMs).toISOString(), logMeta)], meta: logMeta };
          }
          const meta: SessionMeta = {};
          if (kind === "goose-jsonl") {
            const msgs = recs.filter((r): r is GooseMessage => typeof r === "object" && r !== null) as GooseMessage[];
            return { texts: [...gooseSentTexts(msgs, meta)], meta, acts: gooseActs(msgs) };
          }
          return { texts: [...openclawSentTexts(recs, meta)], meta, acts: openclawActs(recs) };
        },
      });
      continue;
    }
    let db = open.get(f.path);
    if (db === undefined) {
      try { db = openAgentStore(f.path).db; } catch { failed.n++; continue; }
      open.set(f.path, db);
    }
    let sessions: Array<DbSession & { root?: string }>;
    try {
      sessions = src.kind === "opencode-db" ? opencodeSessions(db) : src.kind === "goose-db" ? gooseSessions(db) : openclawSessions(db);
    } catch {
      failed.n++;
      continue;
    }
    const fallback = dbMtime(f.path, f.st);
    for (const s of sessions) {
      if (out.length >= max) { overflow.n++; continue; }
      out.push({
        agent: src.agent, path: f.path, mtimeMs: s.updatedMs > 0 ? s.updatedMs : fallback, size: s.bytes,
        session: `${f.path}#${s.root ?? s.id}`,
        read: async () => s.read(),
      });
    }
  }
  return out;
}
