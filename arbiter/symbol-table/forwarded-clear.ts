/**
 * forwarded-clear — the tool-call ids whose result body a model proxy
 * forwarded to the model in clear (confidentiality.md §7.1, "Masked after the
 * fact", *Across a resume*).
 *
 * The proxies' `masked after the fact` note goes on a result that is masked
 * now but whose body an earlier request carried in clear. The proxy keeps
 * those ids in memory (after-the-fact.ts `ClearResultLedger`); before
 * 2026-10-09 that was the only copy, so a conversation resumed under a new
 * launch (`claude --resume`, `--continue`, `codex resume`) re-sent the
 * history to a proxy that had never seen it, and the earlier results came
 * back masked with no note. This store keeps the ids in mandu.db, which the
 * arbiter owns, so the next launch's proxy finds them again.
 *
 * The key is the tool-call id ALONE (`toolu_…` on the Anthropic wire,
 * `call_…` on the OpenAI one): the provider mints it, the agent stores it in
 * its transcript, and a resume re-sends it byte for byte, while no other
 * identity is promised to stay (the Mandu session key is per launch, and
 * Claude Code's own session id is new under `--fork-session`). A
 * random provider id names one call in one conversation, so no session
 * scope is needed; a collision could only add a note, never lift a mask.
 *
 * Ids only, never content: no result byte, no tool name, no path, no
 * session. A whole table of its own (`forwarded_clear`), so a file of the
 * previous schema is adopted (symbol-table.ts `ADDITIVE_FROM`). Bounded: past
 * {@link MAX_ROWS} the oldest rows go first, which only drops a note.
 *
 * Mandu-new (no reference origin).
 */
import Database from "../db/sqlite.js";
import { getSymbolDbPath } from "./symbol-table.js";

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS forwarded_clear (
  call_id     TEXT PRIMARY KEY,
  recorded_at INTEGER NOT NULL
);
`;

/** Rows kept (a long history of tool calls across many conversations). */
export const MAX_ROWS = 500_000;

/** Ids per request, either op (a resumed history's whole set fits). */
export const MAX_IDS_PER_REQUEST = 10_000;

/** Ids one `since` answer lists at most; past it the answer says it is not
 *  complete and the proxy asks again about every id it holds as unknown. */
export const MAX_RECENT_IDS = 10_000;

/** A tool-call id the store accepts: 1..256 printable ASCII, no space. Pure. */
export function isCallId(id: unknown): id is string {
  return typeof id === "string" && id.length > 0 && id.length <= 256 && /^[\x21-\x7e]+$/.test(id);
}

export class ForwardedClearStore {
  private readonly db: InstanceType<typeof Database>;
  private readonly maxRows: number;
  private rows: number;

  constructor(opts: { dbPath?: string; maxRows?: number } = {}) {
    this.db = new Database(opts.dbPath ?? getSymbolDbPath());
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA_SQL);
    this.maxRows = opts.maxRows ?? MAX_ROWS;
    this.rows = Number((this.db.prepare("SELECT COUNT(*) AS n FROM forwarded_clear").get() as { n: number | bigint }).n);
  }

  /** Record ids (idempotent). Returns how many were new. */
  record(ids: readonly string[], now: number = Date.now()): number {
    const insert = this.db.prepare("INSERT OR IGNORE INTO forwarded_clear (call_id, recorded_at) VALUES (?, ?)");
    let added = 0;
    const tx = this.db.transaction((list: readonly string[]) => {
      for (const id of list) added += insert.run(id, now).changes;
    });
    tx(ids);
    this.rows += added;
    if (this.rows > this.maxRows) {
      const drop = this.rows - this.maxRows;
      this.db.prepare("DELETE FROM forwarded_clear WHERE rowid IN (SELECT rowid FROM forwarded_clear ORDER BY rowid LIMIT ?)").run(drop);
      this.rows -= drop;
    }
    return added;
  }

  /** The subset of `ids` recorded, in the order asked. */
  known(ids: readonly string[]): string[] {
    const get = this.db.prepare("SELECT 1 AS one FROM forwarded_clear WHERE call_id = ?");
    return ids.filter((id) => get.get(id) !== undefined);
  }

  /**
   * "Two launches at once" (confidentiality.md §7.1, 2026-10-17): the store's
   * generation, the rowid of its latest row (0 when empty). A row's rowid is
   * assigned under SQLite's single writer, larger than every committed one,
   * so the rows recorded after a generation are exactly those above it, from
   * any process sharing mandu.db (another launch's arbiter included). The
   * oldest rows are trimmed first, so the latest row stays; a generation
   * that went DOWN (an emptied or rebuilt file) is the proxy's cue to forget
   * what it holds as unknown.
   */
  generation(): number {
    const row = this.db.prepare("SELECT MAX(rowid) AS g FROM forwarded_clear").get() as { g: number | bigint | null };
    return row.g === null ? 0 : Number(row.g);
  }

  /** The ids recorded after generation `since`, oldest first, at most
   *  `limit`; `complete` false when more were. */
  since(since: number, limit: number = MAX_RECENT_IDS): { ids: string[]; complete: boolean } {
    const rows = this.db.prepare("SELECT call_id FROM forwarded_clear WHERE rowid > ? ORDER BY rowid LIMIT ?")
      .all(since, limit + 1) as Array<{ call_id: string }>;
    return { ids: rows.slice(0, limit).map((r) => r.call_id), complete: rows.length <= limit };
  }

  close(): void {
    try { this.db.close(); } catch { /* double-close must not throw */ }
  }
}
