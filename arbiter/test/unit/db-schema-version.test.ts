/**
 * db-schema-version.test — mandu.db's schema stamp (runtime-instances.md
 * §9a, 2026-09-25). The no-back-compat decision (2026-07-18) stands; what this
 * pins is that "not supported" is a CLEAN REFUSAL naming the file and the
 * remedy, decided before any table is read. Since v3 (the DualView symbol
 * prefix, 2026-09-27) nothing older is adopted, and v4 (the `$MDU:` prefix,
 * the same day) retired v3's prefix the same way, and v5 (the level names
 * any-model / no-model and their markers) retired v4's level spellings: the
 * unstamped v1 shape and stamped v1–v4 files all hold retired spellings.
 *
 * Pure symbol-table logic: no protection axis is involved (no arbiter policy).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "../../db/sqlite.js";
import {
  MANDU_DB_SCHEMA_VERSION,
  ManduDbSchemaError,
  loadSymbolMap,
  openSymbolDb,
} from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4); none is exercised

function withDir<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dbver-"));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const userVersion = (path: string): number => {
  const db = new Database(path);
  try {
    return Number((db.pragma("user_version") as Array<{ user_version: number }>)[0]!.user_version);
  } finally {
    db.close();
  }
};

test("a fresh file is stamped with the current schema version", () => {
  withDir((dir) => {
    const path = join(dir, "mandu.db");
    openSymbolDb(path).close();
    assert.equal(userVersion(path), MANDU_DB_SCHEMA_VERSION);
    // and reopening is a no-op
    openSymbolDb(path).close();
    assert.equal(userVersion(path), MANDU_DB_SCHEMA_VERSION);
  });
});

test("v6 (the cache seal tables, plan 14 §11.2), v7 (the prompt hold state, plan 15 §13.6), v8 (the bindings sync's source tables, confidentiality.md §2.1), v9 (the proxies' forwarded-in-clear ids, confidentiality.md §7.1), v10 (result_heads, plan 10 §11.14), v11 (call_polls, plan 13 D7), v12 (suggest_scans, plan 14 §5.5), v13 (forwarded_placeholders, confidentiality.md §6), v14 (raised_rows, plan 15 §4.1), v15 (path_rows, plan 15 §13.12), v16 (wire_grants, confidentiality.md §2.1) and v17 (wire_release_sessions, plan 10 §11.13.1) only ADDED tables: v5 to v16 files are adopted and re-stamped; v4 stays refused", () => {
  assert.equal(MANDU_DB_SCHEMA_VERSION, 17);
  withDir((dir) => {
    const path = join(dir, "mandu.db");
    openSymbolDb(path).close();
    for (const v of [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]) {
      const raw = new Database(path);
      raw.exec(`PRAGMA user_version = ${v}`);
      raw.close();
      openSymbolDb(path).close();
      assert.equal(userVersion(path), 17, `a v${v} file is re-stamped, not refused`);
    }
    const old = new Database(path);
    old.exec("PRAGMA user_version = 4");
    old.close();
    assert.throws(() => openSymbolDb(path), (e: unknown) => e instanceof ManduDbSchemaError && e.found === 4);
  });
});

test("an unstamped file with the v1 symbols shape is REFUSED since v3 (its tokens spell the retired $-MDU prefix)", () => {
  withDir((dir) => {
    const path = join(dir, "mandu.db");
    openSymbolDb(path).close();
    // The shape every pre-2026-09-25 lab DB has: current tables, user_version 0.
    // v1 and v2 adopted it; v3 and later cannot, its stored tokens are dead.
    const raw = new Database(path);
    raw.exec("PRAGMA user_version = 0");
    raw.close();
    assert.throws(
      () => openSymbolDb(path),
      (e: unknown) => e instanceof ManduDbSchemaError && e.found === "unstamped",
    );
    assert.equal(userVersion(path), 0, "a refused file is left untouched");
  });
});

test("an unstamped file with a DIFFERENT symbols shape is refused, naming file + remedy, before any read", () => {
  withDir((dir) => {
    const path = join(dir, "mandu.db");
    const raw = new Database(path);
    // An older schema: the pre-confidentiality column set.
    raw.exec(`CREATE TABLE symbols (
      sym_name TEXT PRIMARY KEY, value TEXT NOT NULL, tool TEXT NOT NULL, field TEXT,
      origin TEXT, session_key TEXT, call_id TEXT, created_at INTEGER NOT NULL
    )`);
    raw.close();
    assert.throws(
      () => openSymbolDb(path),
      (e: unknown) =>
        e instanceof ManduDbSchemaError &&
        e.found === "unstamped" &&
        e.expected === MANDU_DB_SCHEMA_VERSION &&
        e.message.includes(path) &&
        /delete .*mandu\.db/.test(e.message) &&
        /mandu stop --all/.test(e.message),
    );
    assert.equal(userVersion(path), 0, "a refused file is left untouched");
    // Every consumer goes through openSymbolDb, so loadSymbolMap refuses the same way.
    assert.throws(() => loadSymbolMap(path), ManduDbSchemaError);
  });
});

test("a file stamped with a NEWER version is refused (a downgrade never mis-reads a future schema)", () => {
  withDir((dir) => {
    const path = join(dir, "mandu.db");
    openSymbolDb(path).close();
    const raw = new Database(path);
    raw.exec(`PRAGMA user_version = ${MANDU_DB_SCHEMA_VERSION + 7}`);
    raw.close();
    assert.throws(
      () => openSymbolDb(path),
      (e: unknown) =>
        e instanceof ManduDbSchemaError &&
        e.found === MANDU_DB_SCHEMA_VERSION + 7 &&
        new RegExp(`schema v${MANDU_DB_SCHEMA_VERSION + 7}; this build needs v${MANDU_DB_SCHEMA_VERSION}`).test(e.message),
    );
  });
});

for (const old of [1, 2, 3, 4]) {
  test(`a v${old} file is REFUSED by v16 (v3 and v4 renamed the token prefix, v5 the level names; stored tokens are not adoptable; v16 adopts only v5 to v15)`, () => {
    withDir((dir) => {
      const path = join(dir, "mandu.db");
      openSymbolDb(path).close();
      const raw = new Database(path);
      raw.exec(`PRAGMA user_version = ${old}`);
      raw.close();
      assert.throws(
        () => openSymbolDb(path),
        (e: unknown) =>
          e instanceof ManduDbSchemaError && e.found === old && e.expected === MANDU_DB_SCHEMA_VERSION,
      );
      assert.equal(userVersion(path), old, "a refused file is left untouched");
      assert.equal(MANDU_DB_SCHEMA_VERSION, 17, "update the refusal list when the version moves again");
    });
  });
}
