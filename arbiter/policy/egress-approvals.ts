/**
 * egress-approvals — arbiter-side egress-approval queue, SQLite-backed so the
 * queue survives a arbiter restart (Mandu-new, no reference origin).
 *
 * The data-usage / egress gate (`decideDesymbolization`, policy-interface.ts)
 * returns `{ allow:false, requiresApproval:true }` for a NETWORK egress of an
 * untrusted symbol to an untrusted destination (and symbol-as-command). This
 * module turns that fire-and-forget verdict into a queue a human can act on: it
 * records each such denied attempt as a PENDING entry, and lets a later human
 * decision (approve / deny) be consulted on the NEXT attempt for the same
 * {symbol, destination} pair so the gate can resolve to a stable verdict.
 *
 * PLACEMENT (why here and not in decideDesymbolization):
 *   `decideDesymbolization` is a PURE function (request + lookups → decision) and
 *   stays that way — it is unit-tested as a pure oracle. The STATEFUL part (the
 *   queue + its mutation) lives here and is driven by the arbiter server handler
 *   (ipc/server.ts, `desymbolizationDecision` op), which is the single stateful
 *   hub. The handler:
 *     1. consults this store for a prior human decision (approvalLookup), and if
 *        found, short-circuits the gate to allow (approved) / deny (denied);
 *     2. otherwise calls the pure gate, and when the gate says
 *        requiresApproval for a NETWORK egress, UPSERTs a pending entry here.
 *
 * PERSISTENCE (why SQLite, and which connection):
 *   The queue is the one piece of human-decision state the arbiter holds, so a
 *   restart that dropped it would silently re-prompt for already-decided pairs
 *   (a usability and trust regression). It is now backed by an `egress_approvals`
 *   table in the arbiter's symbol DB (the daemon's `--symbol-db`, else the
 *   home's `state/mandu.db`; tests pass a temp path). The store keeps the SAME in-memory model as before for O(1) reads and
 *   writes THROUGH to the table on every mutation; on construction it hydrates
 *   the in-memory maps from the table (load-all on init — the queue is low-volume
 *   human-paced state, so a single SELECT is trivial and simpler/cheaper than a
 *   per-call query).
 *
 *   Connection choice: the lifted symbol-table module does NOT keep a long-lived
 *   shared connection — its functions open + close a connection per call and the
 *   arbiter only holds the in-memory SymbolMap. There is therefore no existing
 *   handle for this store to join. The store opens its OWN long-lived connection
 *   to the SAME file in WAL mode (the mode symbol-table also uses), which is the
 *   standard SQLite way to share a file across connections in one process
 *   (synchronous, single-threaded JS → no locking surprises).
 *
 * Entries are keyed by `${symbol} ${destination}` (NUL-joined so neither
 * field can spoof the separator), enforced at the DB layer by a UNIQUE index on
 * (symbol, destination). UPSERT is idempotent: a repeat of the same
 * {symbol, destination} increments `count` and bumps `lastSeen` — it never
 * duplicates and never resets a LIVE human `status` (the one exception is a
 * SPENT once-scoped verdict, below, which by definition no longer applies).
 *
 * VERDICT SCOPE (dashboard.md §4.18's "Allow once / Always allow" split): a
 * human verdict carries `scope` — "always" (the default: standing, checked
 * before every rule, never expires) or "once" (satisfies exactly ONE gated
 * decision, then no longer applies). Consumption is enacted by the gate
 * handlers (ipc/server.ts `consultPriorVerdict`): the first short-circuit off
 * a once-scoped verdict stamps `consumedAt` via {@link consumeOnce}; a spent
 * verdict reads as "no prior", so the next attempt falls through to the pure
 * gate and — if it still requires approval — {@link recordPending} resets the
 * SAME row to a fresh pending cycle (status/resolvedAt/scope/consumedAt reset;
 * id, count history, firstSeen and session attribution are kept). Re-resolving
 * any row re-arms it (`consumedAt` cleared).
 *
 * IDS ARE NEVER REUSED: a row can leave the table (`forget`, an answered
 * row the human removes; `withdraw`, a pending question no answer can make
 * take effect), so the id counter's high-water mark is persisted beside the
 * rows (`egress_approvals_seq`) and hydrate seeds past both. Otherwise the
 * next row after a restart could take a removed row's id, and an answer
 * from a stale page about the removed question would land on a different
 * one (an approval the human never gave).
 *
 * SEND WITHOUT IT (confidentiality.md §4, "Send without it", 2026-10-17): a
 * fourth answer beside Allow once / Always allow / Block, for a card about a
 * secret's SYMBOL in a network request only (the arbiter decides which rows
 * take it: send-without.ts `sendWithoutRefusal`). It is stored as a ONCE
 * DENIAL with `strip: true`: the value is never released (a reader that does
 * not know the flag reads a denial, fail-closed), and the net-proxy, told
 * by the gate's decision, forwards that one request with a neutral marker
 * where the symbol was. One-shot like *Allow once*: spent by its one
 * decision, then the pair asks again. Persisted in the `strip` column, added
 * to an older table in place (a nullable column; an absent cell reads as no
 * strip, the stricter reading).
 *
 * SESSION ATTRIBUTION: each entry carries `sessions` — the distinct session
 * keys that created/bumped it (most-recent-LAST, capped at 8, oldest evicted),
 * threaded from the gate requests' optional `sessionKey`. Attribution ONLY:
 * no decision reads it; it exists so a pending row can NAME the sessions
 * waiting on it. Persisted as a JSON-encoded TEXT column, parsed fail-safe on
 * hydrate (bad JSON or a pre-column NULL → []).
 */

import { existsSync, mkdirSync } from "fs";
import { join } from "path";
import Database from "../db/sqlite.js";
import { getSymbolDbPath } from "../symbol-table/symbol-table.js";

/** A single queued egress-approval entry. The dashboard renders these. */
export interface EgressApproval {
  /** The symbol's origin HOST (from its URL origin), attached at READ time by
   *  the server from the symbol table — never persisted here. Lets the Inbox
   *  offer "anything from <origin> → <destination>" as a rule to mint
   *  (policy-surface.md §2.5). Null when the origin is not a URL. */
  originHost?: string | null;
  /** Where the gated symbol's value came from — the symbol table's `tool` and
   *  `origin` columns (a file path, a URL, a command), attached at READ time
   *  like `originHost`, never persisted here. Provenance, never the value:
   *  lets the Rules page say WHICH data an answer covers (dashboard.md
   *  §4.25e). Null when the subject is not a known symbol (a file or exec
   *  key, or a symbol the table no longer holds). */
  source?: { tool: string; origin: string | null } | null;
  /** A waiting prompt hold under a LOCKED administrator's `ask` row (plan 15
   *  §12, 2026-10-04): it takes an answer for this message only, and an
   *  Always is refused. Attached at READ time like `originHost`, never
   *  persisted here. */
  onceOnly?: true;
  /** An ANSWERED verdict about a program that applies to nothing any more
   *  (flow-taint.ts `verdictNoLongerApplies`): attached at READ time like
   *  `originHost`, never persisted here, so the dashboard can say so
   *  (dashboard.md §4.34 "Answers that no longer apply"). */
  noLongerApplies?: "name-only" | "printer" | "interpreter" | "unvetted";
  /** A HIGH session's ask (`session-net:` / `session-exec:` subjects,
   *  confidentiality.md §4, 2026-10-11): what that session read into
   *  context, as symbols with their origins (a file path, `env:NAME`, a URL,
   *  or null), at most a few; `sessionReadsMore` counts the rest. Attached
   *  at READ time like `originHost`, never persisted here. Provenance,
   *  never a value. */
  sessionReads?: Array<{ symbol: string; origin: string | null }>;
  sessionReadsMore?: number;
  /** A HIGH session's command ask: whether the session's kernel guard holds
   *  an allowed run (its hosts limited to `sessionBindings`, its files
   *  labeled), attached at READ time (confidentiality.md §4). */
  sessionConfined?: boolean;
  sessionBindings?: string[];
  /** A HIGH session's network ask whose latest request was a HELD command's
   *  connection (`session-approvals.ts` SESSION_HELD_REASON_PREFIX): the card
   *  says the command's request was stopped, that the command holds data
   *  from what the session read, and that Allow once lets the next try
   *  through. Attached at READ time (confidentiality.md §4). */
  sessionHeld?: true;
  /** A holder's send question (`holder-send:` subjects, confidentiality
   *  plan 13 §5.4, 2026-10-11): every file the holder holds as it stands
   *  now, with where it may go, whether it blocks the destination and
   *  whether an *Always* can add the destination to its rule
   *  (holder-send-ask.ts `holderSources`). Attached at READ time to a
   *  pending row, never persisted here. Paths and hosts, never a value. */
  holderSources?: Array<{ path: string; via?: string; rule?: true; level: string; bindings: string[]; blocks: boolean; always: boolean; noAlways?: string }>;
  /** Stable id for this {symbol, destination} pair (monotonic counter). */
  id: string;
  /** The symbol whose desymbolization was gated. */
  symbol: string;
  /** The network destination/host from the request. */
  destination: string;
  /** Lifecycle: pending until a human resolves it to approved/denied. */
  status: "pending" | "approved" | "denied";
  /** The policy reason that triggered the approval requirement. */
  reason: string;
  /** How many times this {symbol, destination} was attempted. */
  count: number;
  /** Epoch millis of the first attempt. */
  firstSeen: number;
  /** Epoch millis of the most recent attempt. */
  lastSeen: number;
  /** Epoch millis of the human resolution (approve/deny), or null while
   * pending. The audit half of policy-surface.md §9.6: dating a verdict no
   * longer takes lastSeen inference. Survives restarts like everything else. */
  resolvedAt: number | null;
  /** Distinct session keys that created/bumped this entry, most-recent-LAST,
   * capped at MAX_SESSIONS (oldest evicted). Attribution ONLY — no decision
   * reads it. [] for rows predating the column. */
  sessions: string[];
  /** Verdict scope (module header): "always" = standing, never expires (the
   * default, and the only pre-scope behavior); "once" = satisfies exactly one
   * gated decision, then no longer applies. Meaningful once resolved; pending
   * rows carry "always". */
  scope: ApprovalScope;
  /** Epoch millis when a once-scoped verdict was spent by its one satisfying
   * decision, or null (not consumed / not once-scoped). A spent verdict reads
   * as "no prior" at the gates; re-resolving clears it. */
  consumedAt: number | null;
  /** "Send without it" (module header): a once-scoped DENIAL whose one use
   * forwards the request with a marker in the symbol's place. Present
   * (true) only on such a verdict; absent on every other row. */
  strip?: true;
  /** Whether this row takes "Send without it" (send-without.ts), attached
   * at READ time by the server to a PENDING row, never persisted here: the
   * dashboard offers the button only where it is set, and the arbiter
   * refuses the answer anywhere else. */
  stripOffered?: true;
  /** A FILE's card (egress-hold.md "One card per file", 2026-10-19): the
   * subject is a registered file's base symbol whose registration holds
   * this many protected values (its active field rows), so the card says
   * the answer covers them all. Attached at READ time, never persisted;
   * present only when it is two or more. */
  fileValues?: number;
}

/** The human decision a prior approval encodes, as the gate consults it. */
export type ApprovalStatus = EgressApproval["status"];

/** How long a human verdict stands: forever ("always") or for one use ("once"). */
export type ApprovalScope = "once" | "always";

/** NUL-join the key fields so neither can spoof the separator. */
function keyOf(symbol: string, destination: string): string {
  return `${symbol} ${destination}`;
}

/** Cap on per-entry session attribution: keep the 8 most recent distinct keys. */
const MAX_SESSIONS = 8;

/** Append/refresh `sessionKey` in `sessions` (most-recent-LAST): a key already
 * present moves to the end rather than duplicating; overflow evicts the oldest.
 * Mutates in place. */
function touchSession(sessions: string[], sessionKey: string): void {
  const i = sessions.indexOf(sessionKey);
  if (i !== -1) sessions.splice(i, 1);
  sessions.push(sessionKey);
  while (sessions.length > MAX_SESSIONS) sessions.shift();
}

/**
 * Schema for the egress-approval queue. The UNIQUE index on (symbol, destination)
 * mirrors the in-memory `byKey` map's key so the DB enforces idempotency: an
 * ON CONFLICT(symbol, destination) upsert can never create a duplicate row.
 */
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS egress_approvals (
  id          TEXT PRIMARY KEY,
  symbol      TEXT NOT NULL,
  destination TEXT NOT NULL,
  status      TEXT NOT NULL,
  reason      TEXT NOT NULL,
  count       INTEGER NOT NULL,
  firstSeen   INTEGER NOT NULL,
  lastSeen    INTEGER NOT NULL,
  resolvedAt  INTEGER,
  sessions    TEXT,
  scope       TEXT NOT NULL,
  consumedAt  INTEGER,
  strip       INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_egress_approvals_key
  ON egress_approvals(symbol, destination);
CREATE TABLE IF NOT EXISTS egress_approvals_seq (
  one INTEGER PRIMARY KEY CHECK (one = 0),
  seq INTEGER NOT NULL
);
`;

type Row = {
  id: string;
  symbol: string;
  destination: string;
  status: ApprovalStatus;
  reason: string;
  count: number;
  firstSeen: number;
  lastSeen: number;
  resolvedAt: number | null;
  sessions: string | null;
  scope: ApprovalScope;
  consumedAt: number | null;
  strip: number | null;
};

/** Fail-safe parse of the JSON-encoded `sessions` column: bad JSON, a
 * non-array, or a pre-column NULL all hydrate as [] — a corrupt cell must
 * never take down hydrate. Non-string members are dropped. */
function parseSessions(raw: string | null): string[] {
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((s): s is string => typeof s === "string");
  } catch {
    return [];
  }
}

/** Optional persistence backing. When omitted the store is pure in-memory
 * (unit fixtures), keeping the legacy zero-DB behavior for callers that don't
 * pass a path. */
export interface EgressApprovalStoreOptions {
  /** Injectable clock for offline tests (defaults to Date.now). */
  now?: () => number;
  /** SQLite DB path to persist to. When set, the store hydrates from this file
   * on construction and writes through on every mutation. When omitted, the
   * store is in-memory only (no DB touched). Pass the literal string to opt into
   * the arbiter default ({@link getSymbolDbPath}); a temp path in tests. */
  dbPath?: string;
}

/**
 * Store of egress-approval entries, keyed by {symbol, destination}.
 *
 * In-memory maps are the fast read path; when a `dbPath` is configured the store
 * hydrates them from the `egress_approvals` table on construction and writes
 * through to it on every mutation, so the queue survives a arbiter restart.
 * Single-threaded access (Node event loop), so no locking is needed.
 */
export class EgressApprovalStore {
  /** key → entry. */
  private readonly byKey = new Map<string, EgressApproval>();
  /** id → entry (for O(1) resolve-by-id). */
  private readonly byId = new Map<string, EgressApproval>();
  /** Monotonic id counter (seeded past the max persisted id on hydrate). */
  private seq = 0;
  /** Injectable clock for offline tests (defaults to Date.now). */
  private readonly now: () => number;
  /** Long-lived connection to the arbiter DB file, or undefined for in-memory. */
  private readonly db?: InstanceType<typeof Database>;

  constructor(opts: EgressApprovalStoreOptions = {}) {
    this.now = opts.now ?? (() => Date.now());
    if (opts.dbPath !== undefined) {
      this.db = this.openDb(opts.dbPath);
      // Fail-safe: a read error at startup must not crash the arbiter — log and
      // start with an empty in-memory view (the table, if present, is still
      // intact; only this process's cache is empty).
      try {
        this.hydrate();
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(
          `[egress-approvals] hydrate failed, starting empty: ${(err as Error).message}`,
        );
      }
    }
  }

  /** Open (or create) the DB file in WAL mode and ensure the schema exists.
   * Mirrors symbol-table.openSymbolDb: same directory-create + WAL + create-if-
   * not-exists pattern, against the SAME file. No column migrations: mandu.db
   * carries NO schema back-compat by decision (2026-07-18) — the data is test
   * state, and a pre-current file is simply not supported (delete it and
   * re-run; the fresh CREATE TABLE is the whole contract). */
  private openDb(dbPath: string): InstanceType<typeof Database> {
    const dir = join(dbPath, "..");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.exec(SCHEMA_SQL);
    // 2026-10-17 ("Send without it"): a table created before the column
    // gains it in place (nullable; an absent cell is no strip).
    const cols = db.prepare("PRAGMA table_info(egress_approvals)").all() as Array<{ name: string }>;
    if (!cols.some((c) => c.name === "strip")) db.exec("ALTER TABLE egress_approvals ADD COLUMN strip INTEGER");
    return db;
  }

  /** Load all persisted rows into the in-memory maps and seed `seq` past the
   * highest persisted id so freshly-allocated ids never collide with old ones. */
  private hydrate(): void {
    if (!this.db) return;
    const rows = this.db
      .prepare(
        "SELECT id, symbol, destination, status, reason, count, firstSeen, lastSeen, resolvedAt, sessions, scope, consumedAt, strip FROM egress_approvals",
      )
      .all() as Row[];
    let maxSeq = 0;
    for (const row of rows) {
      const entry: EgressApproval = {
        id: row.id,
        symbol: row.symbol,
        destination: row.destination,
        status: row.status,
        reason: row.reason,
        count: row.count,
        firstSeen: row.firstSeen,
        lastSeen: row.lastSeen,
        resolvedAt: row.resolvedAt ?? null,
        sessions: parseSessions(row.sessions),
        scope: row.scope === "once" ? "once" : "always",
        consumedAt: row.consumedAt ?? null,
        // Only a once DENIAL carries it (resolve): a cell on any other row
        // is ignored, never read as a release.
        ...(row.strip === 1 && row.status === "denied" && row.scope === "once" ? { strip: true as const } : {}),
      };
      this.byKey.set(keyOf(entry.symbol, entry.destination), entry);
      this.byId.set(entry.id, entry);
      const n = parseInt(row.id.replace(/^egr-/, ""), 10);
      if (Number.isFinite(n) && n > maxSeq) maxSeq = n;
    }
    // The persisted high-water mark (module header, IDS ARE NEVER REUSED):
    // a removed row's id stays spent across restarts.
    const mark = this.db.prepare("SELECT seq FROM egress_approvals_seq WHERE one = 0").get() as { seq: number } | undefined;
    if (mark && Number.isFinite(mark.seq) && mark.seq > maxSeq) maxSeq = mark.seq;
    this.seq = maxSeq;
  }

  /** Allocate the next id and persist the high-water mark before it is used. */
  private nextId(): string {
    const n = ++this.seq;
    this.db
      ?.prepare("INSERT INTO egress_approvals_seq (one, seq) VALUES (0, @n) ON CONFLICT(one) DO UPDATE SET seq = MAX(seq, excluded.seq)")
      .run({ n });
    return `egr-${n}`;
  }

  /** Write-through INSERT-or-UPDATE for one entry. A write error surfaces to the
   * caller (so a corrupt/unwritable DB is loud) but never corrupts the already-
   * mutated in-memory state — the in-memory maps are the authoritative view and
   * are updated before this is called. */
  private persist(entry: EgressApproval): void {
    if (!this.db) return;
    this.db
      .prepare(
        `INSERT INTO egress_approvals (id, symbol, destination, status, reason, count, firstSeen, lastSeen, resolvedAt, sessions, scope, consumedAt, strip)
         VALUES (@id, @symbol, @destination, @status, @reason, @count, @firstSeen, @lastSeen, @resolvedAt, @sessions, @scope, @consumedAt, @strip)
         ON CONFLICT(symbol, destination) DO UPDATE SET
           status     = excluded.status,
           reason     = excluded.reason,
           count      = excluded.count,
           lastSeen   = excluded.lastSeen,
           resolvedAt = excluded.resolvedAt,
           sessions   = excluded.sessions,
           scope      = excluded.scope,
           consumedAt = excluded.consumedAt,
           strip      = excluded.strip`,
      )
      // Arrays are not bindable — the sessions column stores the JSON encoding.
      // Only the persisted fields are bound (a read-time field never is).
      .run({
        id: entry.id, symbol: entry.symbol, destination: entry.destination, status: entry.status,
        reason: entry.reason, count: entry.count, firstSeen: entry.firstSeen, lastSeen: entry.lastSeen,
        resolvedAt: entry.resolvedAt, sessions: JSON.stringify(entry.sessions), scope: entry.scope,
        consumedAt: entry.consumedAt, strip: entry.strip === true ? 1 : null,
      });
  }

  /** The human decision recorded for {symbol, destination}, or undefined if no
   * entry exists yet. The gate handler consults this BEFORE the pure decision. */
  lookup(symbol: string, destination: string): ApprovalStatus | undefined {
    return this.byKey.get(keyOf(symbol, destination))?.status;
  }

  /** The full entry for {symbol, destination}, or undefined. The gate wraps use
   * this to stamp `verdict:<id>` provenance (rule-ref.ts) on short-circuited
   * decisions. Copied (sessions array included), same as list(). */
  lookupEntry(symbol: string, destination: string): EgressApproval | undefined {
    const e = this.byKey.get(keyOf(symbol, destination));
    return e ? { ...e, sessions: [...e.sessions] } : undefined;
  }

  /**
   * Record a denied (requires-approval) NETWORK egress attempt. Idempotent by
   * {symbol, destination}: a first attempt inserts a PENDING entry; a repeat
   * increments `count` and bumps `lastSeen` (never duplicating, never resetting
   * a LIVE human-set status). The one status reset: a SPENT once-scoped verdict
   * (consumedAt set) no longer applies by definition, so the row returns to a
   * fresh pending cycle — the human is asked again, keeping the pair's id,
   * count history, firstSeen and session attribution. A non-empty `sessionKey`
   * is appended/refreshed in `sessions` (attribution only — module header).
   * Returns the (new or updated) entry. Writes through to the DB when
   * persistence is configured.
   */
  recordPending(
    symbol: string,
    destination: string,
    reason: string,
    sessionKey?: string,
  ): EgressApproval {
    const key = keyOf(symbol, destination);
    const t = this.now();
    const existing = this.byKey.get(key);
    if (existing) {
      existing.count += 1;
      existing.lastSeen = t;
      // Keep the latest reason text (it may carry the live destination), but do
      // NOT touch a human-set status — only the gate-default reason field.
      existing.reason = reason;
      if (existing.consumedAt !== null) {
        // Spent once-verdict → fresh pending cycle (module header).
        existing.status = "pending";
        existing.resolvedAt = null;
        existing.scope = "always";
        existing.consumedAt = null;
        delete existing.strip;
      }
      if (sessionKey) touchSession(existing.sessions, sessionKey);
      this.persist(existing);
      return existing;
    }
    const entry: EgressApproval = {
      id: this.nextId(),
      symbol,
      destination,
      status: "pending",
      reason,
      count: 1,
      firstSeen: t,
      lastSeen: t,
      resolvedAt: null,
      sessions: sessionKey ? [sessionKey] : [],
      scope: "always",
      consumedAt: null,
    };
    this.byKey.set(key, entry);
    this.byId.set(entry.id, entry);
    this.persist(entry);
    return entry;
  }

  /**
   * Set a human verdict on the entry with `id`. `approve:true` → "approved",
   * `false` → "denied". `scope` defaults to "always" (standing — the only
   * pre-scope behavior); "once" arms a single-use verdict (module header).
   * Re-resolving always clears `consumedAt`, re-arming a spent row.
   * `opts.strip` ("Send without it", module header) stores a ONCE DENIAL
   * that carries the flag, whatever `approve` and `scope` say (the server
   * refuses it with `approve: true` and on a row that does not take it,
   * before it reaches here). Any other answer clears the flag. Returns the
   * updated entry, or undefined if `id` is unknown (the handler turns that
   * into a structured error). Writes through.
   */
  resolve(id: string, approve: boolean, scope: ApprovalScope = "always", opts: { strip?: boolean } = {}): EgressApproval | undefined {
    const entry = this.byId.get(id);
    if (!entry) return undefined;
    const strip = opts.strip === true;
    entry.status = approve && !strip ? "approved" : "denied";
    entry.scope = strip ? "once" : scope;
    if (strip) entry.strip = true;
    else delete entry.strip;
    entry.consumedAt = null;
    entry.lastSeen = this.now();
    entry.resolvedAt = entry.lastSeen;
    this.persist(entry);
    return entry;
  }

  /**
   * FORGET a human verdict (dashboard.md §4.25 Rules page, "Remove" on a past
   * answer): delete the entry so the pair's next gated attempt starts a fresh
   * PENDING cycle and the human is asked again. Only a RESOLVED entry can be
   * forgotten; a pending one is still waiting for its answer, so forgetting it
   * would only hide the question. Never loosens anything: an approved verdict
   * becomes "ask", a denied one becomes "ask" (the gate still requires a human
   * before any release). Returns the removed entry, or undefined if `id` is
   * unknown or still pending. Writes through.
   */
  forget(id: string): EgressApproval | undefined {
    const entry = this.byId.get(id);
    if (!entry || entry.status === "pending") return undefined;
    this.byId.delete(id);
    this.byKey.delete(keyOf(entry.symbol, entry.destination));
    this.db?.prepare("DELETE FROM egress_approvals WHERE id = ?").run(id);
    return { ...entry, sessions: [...entry.sessions] };
  }

  /**
   * WITHDRAW a pending question that no answer can make take effect (the
   * !437 leftover (4), confidentiality plan 13 §3 D8: the arbiter's
   * `retireMootQuestions` decides which). The counterpart of {@link forget},
   * which removes only an ANSWERED row: this removes only a PENDING one, so
   * it never touches a human verdict. Removing a pending row grants nothing:
   * `lookup` then finds no prior answer and the gate decides by the law, the
   * same as before the row existed (fail-closed: what a non-reader gets, or
   * a fresh question). The id stays spent (IDS ARE NEVER REUSED). Returns the
   * removed entry, or undefined if `id` is unknown or answered. Writes through.
   */
  withdraw(id: string): EgressApproval | undefined {
    const entry = this.byId.get(id);
    if (!entry || entry.status !== "pending") return undefined;
    this.byId.delete(id);
    this.byKey.delete(keyOf(entry.symbol, entry.destination));
    this.db?.prepare("DELETE FROM egress_approvals WHERE id = ? AND status = 'pending'").run(id);
    return { ...entry, sessions: [...entry.sessions] };
  }

  /**
   * Spend a once-scoped verdict: stamp `consumedAt` so it no longer applies.
   * Called by the gate handlers' prior-verdict consultation (ipc/server.ts) at
   * the moment the verdict short-circuits its one decision. Guarded no-op
   * (returns undefined) for unknown ids, unresolved rows, always-scoped rows,
   * and already-spent rows — consumption is single by construction. Returns
   * the updated entry (a live reference, same as resolve). Writes through.
   */
  consumeOnce(id: string): EgressApproval | undefined {
    const entry = this.byId.get(id);
    if (!entry || entry.status === "pending") return undefined;
    if (entry.scope !== "once" || entry.consumedAt !== null) return undefined;
    entry.consumedAt = this.now();
    this.persist(entry);
    return entry;
  }

  /**
   * List entries, optionally filtered by status, newest-resolved first (by
   * lastSeen descending). Returns shallow copies so callers can't mutate the
   * store.
   */
  list(filter?: { status?: ApprovalStatus }): EgressApproval[] {
    const out: EgressApproval[] = [];
    for (const e of this.byId.values()) {
      if (filter?.status && e.status !== filter.status) continue;
      out.push({ ...e, sessions: [...e.sessions] });
    }
    out.sort((a, b) => b.lastSeen - a.lastSeen);
    return out;
  }

  /** Close the backing DB connection, if any. Idempotent. Exposed for the
   * arbiter's shutdown path and tests; in-memory stores are no-ops. */
  close(): void {
    this.db?.close();
  }
}

/** Re-export so callers can resolve the arbiter default path without importing
 * the symbol-table module directly. */
export { getSymbolDbPath };
