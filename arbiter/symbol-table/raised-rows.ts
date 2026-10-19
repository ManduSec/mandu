/**
 * raised-rows — the durable mark that a registered row is secret only
 * because the value backstop found a registered secret in it, and which of
 * its lines held one (confidentiality-plan-15-prompt-filter.md §4.1, "What a
 * raised row registers"; prompt-filter/registered-values.ts
 * `raisedRowPieces`).
 *
 * The value index then keeps, of that row's long lines, only the kept ones
 * (and any line with a credential-shaped span); the whole value and every
 * credential-shaped span stay pieces. Without the mark every line of the
 * raised result was a piece, and a later unrelated result that shared an
 * ordinary line (a heading, `}`, a log line) was masked whole.
 *
 * Bound to the row's VALUE, like result-heads.ts: each mark keeps the
 * SHA-256 of the value it was learned on, and a mark whose row is gone or
 * holds another value, or whose line list does not parse, is not loaded
 * (that row keeps every line, fail-closed). A separate table, not a column:
 * the `symbols` table is unchanged, so a file of the previous schema is
 * adopted (symbol-table.ts `ADDITIVE_FROM`).
 *
 * A second table, `path_rows` (plan 15 §13.12, "What a path row
 * registers", 2026-10-17), holds the same mark for a row masked whole only
 * by the path rule (the command names a registered secret file the guard
 * served as its twin): there an EMPTY line list is the usual case (no
 * registered secret was found in the output) and is stored as such. A
 * `raised_rows` mark with no line is not loaded, as before.
 *
 * Mandu-new (no reference origin).
 */
import Database from "../db/sqlite.js";
import { resultHeadValueHash } from "./result-heads.js";
import { getSymbolDbPath, type SymbolMap } from "./symbol-table.js";

/** The two kinds of mark, each its own table of the same shape. */
export type NarrowedRowKind = "raised" | "path";

const TABLE: Readonly<Record<NarrowedRowKind, string>> = { raised: "raised_rows", path: "path_rows" };

const schemaSql = (table: string): string => `
CREATE TABLE IF NOT EXISTS ${table} (
  sym_name     TEXT PRIMARY KEY,
  value_sha256 TEXT NOT NULL,
  keep_lines   TEXT NOT NULL
);
`;

/** The stored line list, or null when it is not a list of line indices
 *  (an empty list only where `allowEmpty`, the path rows). */
function parseKeepLines(raw: string, allowEmpty: boolean): Set<number> | null {
  let v: unknown;
  try { v = JSON.parse(raw); } catch { return null; }
  if (!Array.isArray(v) || (v.length === 0 && !allowEmpty)) return null;
  const out = new Set<number>();
  for (const n of v) {
    if (typeof n !== "number" || !Number.isInteger(n) || n < 0) return null;
    out.add(n);
  }
  return out;
}

export class RaisedRowStore {
  private readonly db: InstanceType<typeof Database>;
  private readonly table: string;
  private readonly allowEmpty: boolean;

  /** `kind`: `raised` (plan 15 §13.11, the default) or `path` (§13.12). */
  constructor(opts: { dbPath?: string; kind?: NarrowedRowKind } = {}) {
    const kind = opts.kind ?? "raised";
    this.table = TABLE[kind];
    this.allowEmpty = kind === "path";
    this.db = new Database(opts.dbPath ?? getSymbolDbPath());
    this.db.pragma("journal_mode = WAL");
    this.db.exec(schemaSql(this.table));
  }

  /** The stored marks whose row still holds the value each was learned on,
   *  by row name: the row's kept line indices. */
  load(map: SymbolMap): Map<string, ReadonlySet<number>> {
    const out = new Map<string, ReadonlySet<number>>();
    const rows = this.db.prepare(`SELECT sym_name, value_sha256, keep_lines FROM ${this.table}`).all() as Array<{ sym_name: string; value_sha256: string; keep_lines: string }>;
    for (const r of rows) {
      const e = map.symbols.get(r.sym_name);
      const keep = parseKeepLines(r.keep_lines, this.allowEmpty);
      if (!e || keep === null || resultHeadValueHash(e.value) !== r.value_sha256) continue;
      out.set(r.sym_name, keep);
    }
    return out;
  }

  /** Store `name`'s mark, bound to `value`. A later mark replaces it. */
  record(name: string, value: string, keep: ReadonlySet<number>): void {
    this.db
      .prepare(`INSERT OR REPLACE INTO ${this.table} (sym_name, value_sha256, keep_lines) VALUES (?, ?, ?)`)
      .run(name, resultHeadValueHash(value), JSON.stringify([...keep].sort((a, b) => a - b)));
  }

  close(): void {
    try { this.db.close(); } catch { /* double-close must not throw */ }
  }
}
