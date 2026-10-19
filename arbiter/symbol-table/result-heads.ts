/**
 * result-heads — the durable mark that a registered row's value is an
 * agent's whole tool result led by its runtime's own head
 * (confidentiality-plan-10-flow-taint.md §11.14; agent-result-head.ts).
 *
 * Before 2026-10-09 the mark lived in the arbiter's memory only, so after a
 * restart every head line of every masked Codex result was a registered line
 * again until the proxy re-sent that result: fail-closed, but each later
 * result repeating a head line was masked whole. The mark is now stored with
 * the row, in mandu.db.
 *
 * Bound to the row's VALUE: each mark keeps the SHA-256 of the value it was
 * learned on, and a mark whose row is gone or holds another value is not
 * loaded. Loading a mark only lets the value index re-match that kind's exact
 * grammar at offset 0 of the row's own value (agent-result-head.ts): the
 * whole value and every line after the head stay registered.
 *
 * A separate table (`result_heads`), not a column: the `symbols` table is
 * unchanged, so a file of the previous schema is adopted (symbol-table.ts
 * `ADDITIVE_FROM`).
 *
 * Mandu-new (no reference origin).
 */
import { createHash } from "node:crypto";

import Database from "../db/sqlite.js";
import { parseResultHead, type ResultHeadKind } from "../policy/agent-result-head.js";
import { getSymbolDbPath, type SymbolMap } from "./symbol-table.js";

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS result_heads (
  sym_name     TEXT PRIMARY KEY,
  kind         TEXT NOT NULL,
  value_sha256 TEXT NOT NULL
);
`;

/** The SHA-256 (hex) a mark is bound to. Pure. */
export function resultHeadValueHash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export class ResultHeadStore {
  private readonly db: InstanceType<typeof Database>;

  constructor(opts: { dbPath?: string } = {}) {
    this.db = new Database(opts.dbPath ?? getSymbolDbPath());
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA_SQL);
  }

  /**
   * The stored marks whose row still holds the value each was learned on, by
   * row name. A mark of an unknown kind, of a row that is gone, or of a row
   * whose value differs is skipped (that row keeps every line).
   */
  load(map: SymbolMap): Map<string, ResultHeadKind> {
    const out = new Map<string, ResultHeadKind>();
    const rows = this.db.prepare("SELECT sym_name, kind, value_sha256 FROM result_heads").all() as Array<{ sym_name: string; kind: string; value_sha256: string }>;
    for (const r of rows) {
      const kind = parseResultHead(r.kind);
      const e = map.symbols.get(r.sym_name);
      if (kind === null || !e || resultHeadValueHash(e.value) !== r.value_sha256) continue;
      out.set(r.sym_name, kind);
    }
    return out;
  }

  /** Store `name`'s mark, bound to `value`. Idempotent; a later mark of the
   *  same row replaces it. */
  record(name: string, kind: ResultHeadKind, value: string): void {
    this.db
      .prepare("INSERT OR REPLACE INTO result_heads (sym_name, kind, value_sha256) VALUES (?, ?, ?)")
      .run(name, kind, resultHeadValueHash(value));
  }

  close(): void {
    try { this.db.close(); } catch { /* double-close must not throw */ }
  }
}
