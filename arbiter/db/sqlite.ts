/**
 * db/sqlite — a `better-sqlite3`-shaped façade over Node's built-in
 * `node:sqlite` (`DatabaseSync`), so the arbiter ships with ZERO native addons
 * (packaging.md §4). `better-sqlite3` was the repo's only native dependency and
 * the #1 npm first-run failure class (node-gyp fallback on any platform a
 * prebuild misses). `node:sqlite` is pure-Node, so `npm install` can no longer
 * fail on compilation — at the cost of a Node ≥ 22 floor (`DatabaseSync`
 * unflagged since 22.13; enforced via `engines` + a launch-time check).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. This is a THIN adapter, not a reimplementation: it exposes
 *   exactly the `better-sqlite3` surface the three arbiter consumers use
 *   (symbol-table, provenance-store, egress-approvals) — `new Database(path)`,
 *   `.exec`, `.prepare().{run,get,all}`, `.pragma`, `.transaction`, `.close` —
 *   so those security-sensitive modules change by ONE import line and their
 *   existing unit tests remain the behavioral oracle.
 *
 * Semantic notes where `node:sqlite` differs from `better-sqlite3`:
 *   - `.pragma(src)`: `node:sqlite` has no `.pragma()`. We run `PRAGMA <src>`
 *     via `prepare().all()`, which returns rows for query pragmas
 *     (`table_info(...)`) and an ignorable one-row result for setters
 *     (`journal_mode = WAL`). Callers pass CONSTANT pragma strings only — never
 *     interpolate untrusted input here.
 *   - `.transaction(fn)`: `node:sqlite` has no transaction helper. We wrap in an
 *     explicit `BEGIN`/`COMMIT`, rolling back on throw. This covers the single,
 *     NON-NESTED top-level transaction the arbiter uses (saveSymbolMap); it is
 *     not a savepoint-aware nested-transaction emulation.
 *   - `run().changes`: coerced to `number` (row counts never exceed the safe
 *     integer range) so `result.changes === 1` keeps working; `node:sqlite`
 *     may otherwise hand back a bigint.
 *   - Rows from `.get()/.all()` are null-prototype objects (property reads work
 *     identically; do not rely on `Object.prototype` methods on them).
 */

import { DatabaseSync, type StatementSync } from "node:sqlite";

/** Result of a mutating statement — mirrors better-sqlite3's RunResult. */
export interface RunResult {
  changes: number;
  lastInsertRowid: number | bigint;
}

/**
 * A prepared statement — the `better-sqlite3` Statement surface the arbiter
 * uses. Bind params are typed `any[]` to match better-sqlite3's own `.d.ts`:
 * each param is either a positional value (string/number/bigint/null/Uint8Array)
 * or, as a single argument, an object of named binds (`{ id, … }` → `@id`;
 * `node:sqlite` binds bare object keys).
 */
export interface Statement {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  run(...params: any[]): RunResult;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  get(...params: any[]): unknown;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  all(...params: any[]): unknown[];
}

function wrapStatement(stmt: StatementSync): Statement {
  return {
    run(...params): RunResult {
      const r = stmt.run(...params);
      return { changes: Number(r.changes), lastInsertRowid: r.lastInsertRowid };
    },
    get(...params): unknown {
      return stmt.get(...params);
    },
    all(...params): unknown[] {
      return stmt.all(...params);
    },
  };
}

/**
 * Drop-in stand-in for `better-sqlite3`'s default export. Construct with a file
 * path; synchronous like better-sqlite3.
 */
export default class Database {
  private readonly db: DatabaseSync;

  /** `readOnly` opens with SQLITE_OPEN_READONLY (no write, no create):
   *  store-seed.ts reads another arbiter's store this way. */
  constructor(path: string, opts: { readOnly?: boolean } = {}) {
    this.db = opts.readOnly === true ? new DatabaseSync(path, { readOnly: true }) : new DatabaseSync(path);
  }

  /** Execute one or more statements with no result (schema DDL, PRAGMA setters). */
  exec(sql: string): void {
    this.db.exec(sql);
  }

  /** Prepare a statement. */
  prepare(sql: string): Statement {
    return wrapStatement(this.db.prepare(sql));
  }

  /**
   * Run a PRAGMA and return its rows. `source` is a CONSTANT like
   * `"journal_mode = WAL"` or `"table_info(symbols)"` — never untrusted input.
   */
  pragma(source: string): unknown {
    return this.db.prepare(`PRAGMA ${source}`).all();
  }

  /**
   * Wrap `fn` in a single (non-nested) transaction. Returns a callable that
   * runs `fn` inside `BEGIN`…`COMMIT`, rolling back and rethrowing on error —
   * matching how better-sqlite3's `.transaction()` is invoked at the call site.
   */
  transaction<A extends unknown[], R>(fn: (...args: A) => R): (...args: A) => R {
    return (...args: A): R => {
      this.db.exec("BEGIN");
      try {
        const result = fn(...args);
        this.db.exec("COMMIT");
        return result;
      } catch (err) {
        try {
          this.db.exec("ROLLBACK");
        } catch {
          /* best-effort rollback: the original error is what matters */
        }
        throw err;
      }
    };
  }

  /** Close the underlying connection. */
  close(): void {
    this.db.close();
  }
}
