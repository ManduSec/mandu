/**
 * symbol-sources — the source symbols a multi-input derived row was joined
 * from (symbol-quality.md §7, confidentiality.md §2.1).
 *
 * `symbolizeDerived` (an `inspect_symbol` result over several inputs) mints a
 * row whose level and bindings are the join of every source's
 * (source-label.ts). The row itself records one parent (`derived_from`, the
 * first input) and its origin, so before 2026-10-05 a binding removed from
 * any OTHER source never reached the result: the sync of bindings to the law
 * in force (current-bindings.ts rule 2) had nothing to read. This store keeps
 * the whole list, so the sync intersects the row with the join of its
 * sources' CURRENT bindings.
 *
 * A separate table (`symbol_sources`), not a column: mandu.db's `symbols`
 * table is unchanged, so a file of the previous schema is adopted
 * (symbol-table.ts `ADDITIVE_FROM`). A row minted before the table existed
 * has no entry and keeps its mint-time join (narrowed still by its origin
 * and parent).
 *
 * Mandu-new (no reference origin).
 */
import Database from "../db/sqlite.js";
import { getSymbolDbPath } from "./symbol-table.js";

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS symbol_sources (
  sym_name TEXT NOT NULL,
  source   TEXT NOT NULL,
  PRIMARY KEY (sym_name, source)
);
`;

export class SymbolSourceStore {
  private readonly db: InstanceType<typeof Database>;
  private readonly bySymbol = new Map<string, string[]>();

  constructor(opts: { dbPath?: string } = {}) {
    this.db = new Database(opts.dbPath ?? getSymbolDbPath());
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA_SQL);
    const rows = this.db.prepare("SELECT sym_name, source FROM symbol_sources").all() as Array<{ sym_name: string; source: string }>;
    for (const r of rows) {
      const list = this.bySymbol.get(r.sym_name) ?? [];
      list.push(r.source);
      this.bySymbol.set(r.sym_name, list);
    }
  }

  /** Record the sources `symbol` was joined from (idempotent, additive). */
  record(symbol: string, sources: readonly string[]): void {
    const list = this.bySymbol.get(symbol) ?? [];
    const insert = this.db.prepare("INSERT OR IGNORE INTO symbol_sources (sym_name, source) VALUES (?, ?)");
    for (const s of sources) {
      if (list.includes(s)) continue;
      insert.run(symbol, s);
      list.push(s);
    }
    if (list.length > 0) this.bySymbol.set(symbol, list);
  }

  /** The recorded sources of `symbol`, or undefined when none were. */
  get(symbol: string): readonly string[] | undefined {
    return this.bySymbol.get(symbol);
  }

  close(): void {
    try { this.db.close(); } catch { /* double-close must not throw */ }
  }
}
