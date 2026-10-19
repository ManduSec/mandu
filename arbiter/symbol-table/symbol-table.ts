/**
 * symbol-table — Mandu persistent symbol table (SQLite-backed).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/dualview-symbol-table.ts
 *   Purpose: maps `$MDU:*` placeholders to their original untrusted values
 *   with provenance metadata; SQLite-backed; the heart of the dual-view defense.
 *
 *   Adaptation for Mandu M0 (the ONLY change from the reference):
 *     - Removed the OpenClaw plugin coupling: the reference imported
 *       `dualviewSymbolDbPath()` from `./adfi-dualview.js`, which pulled in the
 *       whole plugin's workspace-identity machinery. That single import is
 *       replaced by a self-contained `getSymbolDbPath()` below
 *       (the path table's `symbol-db`: `${MANDU_HOME:-~/.mandu}/state/mandu.db`;
 *       the daemon's `--symbol-db` flag names another; renamed from
 *       the reference's `symbols.db` 2026-07-17 — see getSymbolDbPath —
 *       with the schema kept compatible). Nothing else changed: the schema,
 *       migrations, allocation/race-safety, resolution, and human-edit support
 *       are preserved byte-for-byte so the evaluated behavior carries over.
 *
 *   Canonical-field repair (2026-09-11): reuse skips scanner-incomplete legacy
 *   names while exposing matching rows for restriction-preserving replacement.
 *   Existing persisted identifiers are never renamed.
 *
 *   Promotion note (plan §3, §8): in Mandu this module is owned by the arbiter
 *   daemon (one writer) and reached by every interceptor over IPC, rather than
 *   being an in-process singleton. The race-safe INSERT-OR-IGNORE allocation
 *   path is retained because multiple arbiter-adjacent tools may still allocate.
 */

import { randomBytes } from "crypto";
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, statSync } from "fs";
import { homedir } from "os";
import { join, resolve } from "path";
import Database from "../db/sqlite.js";
import { manduPath, type ManduPathEnv } from "../src/generated/mandu-paths.js";
import { findByCandidates, getActiveFormat } from "./symbol-format.js";
import {
  type ConfidentialityLevel,
  type IntegrityLabel,
  isSecret,
  maxConfidentiality,
  parseConfidentialityLevel,
  parseIntegrityLabel,
} from "./confidentiality.js";

// ─────────────────────────────────────────────────────────────────────────────
// Mandu persistent symbol table (SQLite-backed)
//
// Maps symbol placeholders to their original untrusted values with
// provenance metadata. Symbol format is defined in symbol-format.ts.
// ─────────────────────────────────────────────────────────────────────────────

export interface SymbolEntry {
  value: string;
  tool: string;
  field: string | null;
  origin: string | null;
  session_key: string | null;
  call_id: string | null;
  created_at: number;
  /** Timestamp when this symbol was obsoleted (human edit, etc.). null = active. */
  obsoleted_at: number | null;
  /** What obsoleted this symbol: 'human' or a commit hash. null = active. */
  obsoleted_by: string | null;
  /** Parent symbol name if this is a derived symbol (from symbol splitting). */
  derived_from: string | null;
  /** Line range within parent value, e.g. "0:29". null if not derived. */
  line_range: string | null;
  /** Confidentiality level (docs/design/confidentiality/confidentiality.md §2). The table
   * row is authoritative — never trust the name's wire marker. */
  confidentiality: ConfidentialityLevel;
  /** Per-datum bound destinations (§2): host suffixes this datum may be
   * released to at egress. null = none. Stored as a JSON array. */
  bindings: string[] | null;
  /** Integrity half of the 2×3 label (§2). Only the exact stored string
   * "trusted" counts; everything else parses untrusted (fail-closed). */
  integrity: IntegrityLabel;
}

export interface SymbolMap {
  symbols: Map<string, SymbolEntry>;
  /** The wire grants the registration gave (plan 10 §11.13.1,
   *  confidentiality.md §2.1 "The wire grant is recorded"): a field row of
   *  the launch HOME's `.npmrc` / pip.conf → the host its own text names,
   *  and a pip index variable's row (`env:PIP_INDEX_URL`, registered on the
   *  human plane) → its index host. Persisted in `wire_grants`. Absent =
   *  none recorded. */
  wireGrants?: Map<string, string>;
}

/** A per-map mutation counter (confidentiality-plan-15 §4.1): the value
 *  index (prompt-filter/registered-values.ts) rebuilds its matcher when it
 *  moves. Every function of this module that adds a row or changes one in
 *  place bumps it; the index also compares the map's size, so a row added
 *  elsewhere still invalidates it. */
const mapGenerations = new WeakMap<SymbolMap, number>();

/** The map's mutation counter (0 = never touched). */
export function symbolMapGeneration(map: SymbolMap): number {
  return mapGenerations.get(map) ?? 0;
}

/** Record a mutation of `map` (a row added, obsoleted or relabelled). */
export function touchSymbolMap(map: SymbolMap): void {
  mapGenerations.set(map, symbolMapGeneration(map) + 1);
}

/** Regex to detect symbol references in text. Delegates to active format. */
export function getSymbolPattern(): RegExp {
  return getActiveFormat().pattern;
}

/**
 * @deprecated Use getSymbolPattern() for format-independent code.
 * Kept for backward compatibility with existing imports.
 */
export const SYMBOL_PATTERN = /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*|\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/g;

/**
 * Check if a string contains any symbol references.
 */
export function hasSymbols(text: string): boolean {
  const fmt = getActiveFormat();
  if (!text.includes(fmt.prefix)) return false;
  const pat = fmt.pattern;
  pat.lastIndex = 0;
  return pat.test(text);
}

// ─────────────────────────────────────────────────────────────────────────────
// SQLite helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The FULL current schema. mandu.db carries NO schema back-compat by
 * decision (2026-07-18): every column lives here in the CREATE TABLE, there
 * are no guarded ALTERs, and a file created by older code is simply not
 * supported — delete the file and re-run.
 *
 * What changed for the product (2026-09-25, runtime-instances.md §9a): the
 * decision stands, but "not supported" is now a CLEAN REFUSAL instead of a
 * raw SQLite column error deep in a boot. The file carries a schema version
 * (`PRAGMA user_version`, {@link MANDU_DB_SCHEMA_VERSION}); openSymbolDb
 * compares it before touching any table and throws {@link ManduDbSchemaError}
 * — naming the file, both versions and the remedy — on a mismatch. BUMP THE
 * CONSTANT WITH EVERY SCHEMA CHANGE, in this file or in any of the stores
 * that share the file (egress_approvals, path_labels, session_labels,
 * session_label_sources, symbol_sources, forwarded_clear, forwarded_placeholders, result_heads, raised_rows, path_rows, derived_labels, rule_hits, policy_proposals, policy_changes, known_repos, lock_resolutions, cache_seals and
 * its state and launch tables, the provenance
 * tables): the number is the whole
 * contract, and a change that lands without the bump is a file the next boot
 * mis-reads instead of refusing. (The one exception: policy_proposals adds
 * NULLABLE columns in place, NULL reading as the old meaning;
 * runtime-instances.md §9a.)
 */
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS symbols (
  sym_name    TEXT PRIMARY KEY,
  value       TEXT NOT NULL,
  tool        TEXT NOT NULL,
  field       TEXT,
  origin      TEXT,
  session_key TEXT,
  call_id     TEXT,
  created_at  INTEGER NOT NULL,
  obsoleted_at INTEGER,
  obsoleted_by TEXT,
  derived_from TEXT,
  line_range  TEXT,
  confidentiality TEXT NOT NULL DEFAULT 'public',
  bindings    TEXT,
  integrity   TEXT NOT NULL DEFAULT 'untrusted'
);
CREATE INDEX IF NOT EXISTS idx_symbols_value ON symbols(value);
CREATE INDEX IF NOT EXISTS idx_symbols_call_id ON symbols(call_id);
CREATE TABLE IF NOT EXISTS wire_grants (
  sym_name TEXT PRIMARY KEY,
  host     TEXT NOT NULL
);
`;

/**
 * The schema version stamped into mandu.db (`PRAGMA user_version`). 1 =
 * the schema as of 2026-09-25 (the first stamped one); 2 = v1 plus the
 * `policy_proposals` and `policy_changes` tables (policy-surface.md §8
 * §4.5); 3 = the DualView symbol token prefix (2026-09-27): every stored
 * `sym_name` (and every token inside a stored value, binding or twin) of a v1/v2
 * file spells the retired agentOS-era prefix; 4 = the `$MDU:` prefix (the same
 * day, confidentiality.md), which retired the v3 prefix the
 * same way; 5 = the confidentiality level names `any-model` / `no-model` and
 * their markers (the same day, confidentiality.md), which
 * every level column, `sym_name` and stored token of a v4 file spells the old
 * way. Nothing resolves a retired prefix or marker, so a v1-v4 file is
 * REFUSED, never adopted; 6 = v5 plus the enforcement caches' seal tables
 * (`cache_seals`, `cache_seal_state`, `unconfined_launches`;
 * confidentiality-plan-14 §11.2; the §11.1 registry's `known_repos` and
 * `lock_resolutions` came the same day without a bump), whole tables only,
 * so a v5 file is adopted (ADDITIVE_FROM); 7 = v6 plus the prompt filter's
 * hold state (`prompt_hold_state`: the key its span references are keyed
 * with, confidentiality-plan-15 §13.6), a whole table only, so v5 and v6
 * files are adopted; 8 = v7 plus the sources the bindings sync reads
 * (`session_label_sources`: the symbols each session read into context;
 * `symbol_sources`: a multi-input derived row's sources; confidentiality.md
 * §2.1, 2026-10-05), whole tables only, so v5, v6 and v7 files are adopted;
 * 9 = v8 plus the model proxies' forwarded-in-clear call ids
 * (`forwarded_clear`: the after-the-fact note across a resume,
 * confidentiality.md §7.1, 2026-10-09), a whole table only, so v5 to v8
 * files are adopted; 10 = v9 plus `result_heads` (the durable mark that a
 * row is an agent's whole result led by its runtime's head, plan 10
 * §11.14, 2026-10-09), a whole table only, so v5 to v9 files are adopted
 * (an adopted file's rows have no mark: their head lines count,
 * fail-closed); 11 = v10 plus the provenance table `call_polls` (a
 * background poll tied to the call that started its task, plan 13 D7,
 * 2026-10-09), a whole table only, so v5 to v10 files are adopted (an
 * adopted file's polls are untied: their rows count as before); 12 =
 * v11 plus the policy proposals' `suggest_scans` (when a scan of every
 * source last finished over each root, plan 14 §5.5, 2026-10-09), a whole
 * table only, so v5 to v11 files are adopted (an adopted file has no
 * finished scan: its next launch waits once, as after a restart did); 13 =
 * v12 plus the model proxies' `forwarded_placeholders` (where Mandu's
 * placeholders sat in an OpenClaw result forwarded in clear, and its
 * digest: OpenClaw's history redaction undone across a relaunch,
 * confidentiality.md §6, 2026-10-11), a whole table only, so v5 to v12
 * files are adopted (an adopted file has no record: a relaunch masks a
 * redacted result whole, as before); 14 = v13 plus `raised_rows` (the
 * durable mark that a row is secret only because the value backstop found
 * a registered secret in it, and which of its lines held one: plan 15 §4.1,
 * 2026-10-12), a whole table only, so v5 to v13 files are adopted (an
 * adopted file's rows have no mark: every line of a raised row counts, as
 * before); 15 = v14 plus `path_rows` (the same mark for a row masked whole
 * only by the path rule, whose call's tree read no secret raw and whose
 * named files are registered as they are: plan 15 §13.12, 2026-10-17), a
 * whole table only, so v5 to v14 files are adopted (an adopted file's path
 * rows have no mark: every line counts, as before); 16 = v15 plus
 * `wire_grants` (the field rows a registration gave their own wire host,
 * so the bindings sync keeps exactly those and never infers one:
 * confidentiality.md §2.1, 2026-10-17), a whole table only, so v5 to v15
 * files are adopted (an adopted file has no record: a field's wire grant is
 * dropped until the next launch registers the file again, fail-closed);
 * 17 = v16 plus `wire_release_sessions` (the sessions whose egress proxy
 * inspects TLS, kept across a restart while their launcher runs: plan 10
 * §11.13.1, 2026-10-17), a whole table only, so v5 to v16 files are adopted
 * (an adopted file has no record: npm reads `.npmrc` raw until the next
 * launch, as after a restart did, fail-closed).
 * Bump on ANY change to any table in the file (see the
 * SCHEMA_SQL note).
 */
export const MANDU_DB_SCHEMA_VERSION = 17;

/**
 * Stamped versions this build ADOPTS by re-stamping instead of refusing,
 * because the step from each of them to the current version only ADDED whole
 * tables (created IF NOT EXISTS by their stores on open) and changed nothing
 * that exists. This is not a migration: no existing table or column is read
 * differently, so the no-back-compat decision (2026-07-18) is untouched. A
 * version whose step changed an existing table must never be listed here.
 */
const ADDITIVE_FROM: ReadonlySet<number> = new Set<number>([5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

/** Does this build read a mandu.db stamped `found` as it is (this version,
 *  or one it adopts)? An unstamped file (0) is not: its shape is checked
 *  only by an open that may stamp it. Pure (db/store-seed.ts reads a store
 *  read-only and must refuse what a start would refuse). */
export function schemaVersionReadable(found: number): boolean {
  return found === MANDU_DB_SCHEMA_VERSION || ADDITIVE_FROM.has(found);
}

/**
 * The `symbols` columns of schema version 1, in CREATE order. Used ONLY to
 * adopt an unstamped file: every mandu.db written before 2026-09-25 has
 * `user_version = 0`, and the one shape worth adopting silently is the file
 * whose `symbols` table is exactly this — the current schema, written by code
 * that simply predates the stamp. Any other unstamped shape is refused.
 * Pinned to SCHEMA_SQL by test/unit/db-schema-version.test.ts.
 */
const SCHEMA_V1_SYMBOLS_COLUMNS = [
  "sym_name", "value", "tool", "field", "origin", "session_key", "call_id", "created_at",
  "obsoleted_at", "obsoleted_by", "derived_from", "line_range", "confidentiality", "bindings", "integrity",
];

/** mandu.db was written by a different Mandu (schema version mismatch). */
export class ManduDbSchemaError extends Error {
  constructor(
    readonly dbPath: string,
    readonly found: number | "unstamped",
    readonly expected: number,
  ) {
    super(
      `mandu.db at ${dbPath} was written by a different Mandu version ` +
        `(schema ${found === "unstamped" ? "unstamped, pre-2026-09-25 shape" : `v${found}`}; this build needs v${expected}). ` +
        `mandu.db carries no schema back-compat: stop every Mandu session (mandu stop --all), ` +
        `delete ${dbPath} (and ${dbPath}-wal, ${dbPath}-shm if present), and relaunch. ` +
        `Secret-file labels declared under policy.yaml \`paths:\` survive; labels that live only in the DB and past approvals do not.`,
    );
    this.name = "ManduDbSchemaError";
  }
}

/**
 * Compare the file's stamp with this build's, BEFORE any table is touched.
 * Fresh file (no `symbols` table) → stamp it. Unstamped file with the exact
 * v1 `symbols` shape → adopt (stamp) it. Anything else → ManduDbSchemaError.
 */
function checkSchemaVersion(db: InstanceType<typeof Database>, dbPath: string): void {
  const rows = db.pragma("user_version") as Array<{ user_version: number | bigint }>;
  const found = Number(rows[0]?.user_version ?? 0);
  if (found === MANDU_DB_SCHEMA_VERSION) return;
  if (ADDITIVE_FROM.has(found)) {
    db.exec(`PRAGMA user_version = ${MANDU_DB_SCHEMA_VERSION}`);
    return;
  }
  if (found === 0) {
    const hasSymbols = db
      .prepare("SELECT 1 AS one FROM sqlite_master WHERE type = 'table' AND name = 'symbols'")
      .get();
    if (!hasSymbols) {
      db.exec(`PRAGMA user_version = ${MANDU_DB_SCHEMA_VERSION}`);
      return;
    }
    const cols = (db.pragma("table_info(symbols)") as Array<{ name: string }>).map((c) => c.name);
    const same =
      cols.length === SCHEMA_V1_SYMBOLS_COLUMNS.length &&
      SCHEMA_V1_SYMBOLS_COLUMNS.every((c) => cols.includes(c));
    if (same && ((MANDU_DB_SCHEMA_VERSION as number) === 1 || ADDITIVE_FROM.has(1))) {
      db.exec(`PRAGMA user_version = ${MANDU_DB_SCHEMA_VERSION}`);
      return;
    }
    throw new ManduDbSchemaError(dbPath, "unstamped", MANDU_DB_SCHEMA_VERSION);
  }
  throw new ManduDbSchemaError(dbPath, found, MANDU_DB_SCHEMA_VERSION);
}

/**
 * Return the default arbiter DB path.
 *
 * Mandu adaptation: standalone replacement for the reference's
 * `dualviewSymbolDbPath()` (which lived in the OpenClaw plugin's
 * adfi-dualview.ts). The path table's `symbol-db`:
 * `${MANDU_HOME:-~/.mandu}/state/mandu.db` (on-disk-layout.md §3, §5). No
 * environment variable moves it; the daemon's `--symbol-db` flag
 * (ipc/server-args.ts) names another path for the stores it opens.
 *
 * RENAME (2026-07-17): the default file was `~/.mandu/symbols.db` (the
 * reference's location), but the name had become a lie — the file holds the
 * symbol table AND every durable policy table (egress_approvals, path_labels,
 * session_labels, derived_labels, file_taint, process_taint, process_lineage;
 * all Mandu-new). It is named for its OWNER now: everything durable the one
 * arbiter writes. A leftover `symbols.db` is IGNORED (no rename migration —
 * mandu.db carries no back-compat by decision, 2026-07-18).
 */
export function getSymbolDbPath(env: ManduPathEnv = process.env, home: string = homedir()): string {
  return manduPath("symbol-db", env, home);
}

/**
 * Mandu's own directories to tighten for a DB in `dir`: the table's `state/`
 * and the home above it (`~/.mandu/state`, `~/.mandu`). Empty for any other
 * directory: one a `--symbol-db` flag names outside the home keeps its mode.
 * Pure.
 */
export function ownDbDirs(dir: string, env: ManduPathEnv = process.env, home: string = env["HOME"] || homedir()): string[] {
  const d = resolve(dir);
  const state = manduPath("state-root", env, home);
  if (d === resolve(state)) return [state, manduPath("mandu-home", env, home)];
  return [];
}

/**
 * The DB holds every original behind a `$MDU:` placeholder (`symbols.value`),
 * so only its owner may read it (on-disk-layout.md §1, §3). SQLite creates the
 * file with the umask's mode (0644 typically) and gives `-wal`, `-shm` and
 * `-journal` the main file's mode, so the file is created 0600 before SQLite
 * opens it and an existing one (with its companions) is tightened. Mandu's
 * own directories (ownDbDirs) are tightened to 0700 too. Best-effort: a chmod
 * that fails (not the owner) leaves the mode as it was.
 */
function ownerOnly(dir: string, dbPath: string, env: ManduPathEnv): void {
  const tighten = (p: string, mode: number): void => {
    try {
      if ((statSync(p).mode & 0o077) !== 0) chmodSync(p, mode);
    } catch { /* absent, or not ours */ }
  };
  for (const d of ownDbDirs(dir, env)) tighten(d, 0o700);
  if (!existsSync(dbPath)) {
    try { closeSync(openSync(dbPath, "a", 0o600)); } catch { /* SQLite reports it */ }
  }
  for (const suffix of ["", "-wal", "-shm", "-journal"]) tighten(dbPath + suffix, 0o600);
}

/**
 * Open (or create) the arbiter database.
 * Defaults to getSymbolDbPath(). `env` resolves the table's paths for the
 * ownership rule (ownDbDirs).
 * Applies WAL mode, checks the schema stamp (throws ManduDbSchemaError on a
 * mismatch, before any table is read), and creates the schema if needed.
 */
export function openSymbolDb(dbPath?: string, env: ManduPathEnv = process.env): InstanceType<typeof Database> {
  const resolvedPath = dbPath ?? getSymbolDbPath();
  const dir = join(resolvedPath, "..");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  ownerOnly(dir, resolvedPath, env);

  const db = new Database(resolvedPath);
  db.pragma("journal_mode = WAL");
  try {
    checkSchemaVersion(db, resolvedPath);
  } catch (e) {
    db.close();
    throw e;
  }
  db.exec(SCHEMA_SQL);
  return db;
}

/**
 * Parse the JSON `bindings` cell. A corrupt cell must not kill the load —
 * losing a binding only RESTRICTS (the datum loses its release destinations),
 * so degrading to null is the fail-closed direction.
 */
function parseBindings(raw: string | null): string[] | null {
  if (raw === null || raw === "") return null;
  try {
    const v = JSON.parse(raw);
    if (Array.isArray(v) && v.every((x) => typeof x === "string")) return v;
    return null;
  } catch {
    return null;
  }
}

/**
 * Load the symbol table from the SQLite database into a SymbolMap.
 */
export function loadSymbolMap(dbPath?: string): SymbolMap {
  const db = openSymbolDb(dbPath);
  try {
    const rows = db.prepare(
      "SELECT sym_name, value, tool, field, origin, session_key, call_id, created_at, obsoleted_at, obsoleted_by, derived_from, line_range, confidentiality, bindings, integrity FROM symbols",
    ).all() as Array<{
      sym_name: string; value: string; tool: string; field: string | null;
      origin: string | null; session_key: string | null; call_id: string | null; created_at: number;
      obsoleted_at: number | null; obsoleted_by: string | null;
      derived_from: string | null; line_range: string | null;
      confidentiality: string | null; bindings: string | null;
      integrity: string | null;
    }>;
    const symbols = new Map<string, SymbolEntry>();
    for (const row of rows) {
      symbols.set(row.sym_name, {
        value: row.value,
        tool: row.tool,
        field: row.field,
        origin: row.origin,
        session_key: row.session_key,
        call_id: row.call_id,
        created_at: row.created_at,
        obsoleted_at: row.obsoleted_at ?? null,
        obsoleted_by: row.obsoleted_by ?? null,
        derived_from: row.derived_from ?? null,
        line_range: row.line_range ?? null,
        // Unknown stored levels (a newer build's value) parse fail-closed to
        // no-model; legacy rows read the column default 'public'.
        confidentiality: parseConfidentialityLevel(row.confidentiality),
        bindings: parseBindings(row.bindings),
        integrity: parseIntegrityLabel(row.integrity),
      });
    }
    const wireGrants = new Map<string, string>();
    for (const g of db.prepare("SELECT sym_name, host FROM wire_grants").all() as Array<{ sym_name: string; host: string }>) {
      wireGrants.set(g.sym_name, g.host);
    }
    return { symbols, wireGrants };
  } finally {
    db.close();
  }
}

/**
 * Record that the registration gave row `symName` its own wire host (plan
 * 10 §11.13.1: the launch HOME's `.npmrc` token, a pip.conf index password,
 * a pip index variable's password). The bindings sync keeps that host on
 * that row and on no other (current-bindings.ts rules 1 and 3), whatever
 * the label or `env.sources` binds: a grant is never inferred from the
 * row's bindings (confidentiality.md §2.1, 2026-10-17). One host per row: a
 * later grant replaces it. Persisted when `dbPath` is given; idempotent.
 * Dropped when the row is obsoleted ({@link obsoleteSymbol}).
 */
export function recordWireGrant(symbolMap: SymbolMap, symName: string, host: string, dbPath?: string): void {
  const h = host.toLowerCase();
  const grants = symbolMap.wireGrants ?? (symbolMap.wireGrants = new Map());
  if (grants.get(symName) === h) return;
  grants.set(symName, h);
  if (dbPath === undefined) return;
  const db = openSymbolDb(dbPath);
  try {
    db.prepare("INSERT INTO wire_grants (sym_name, host) VALUES (?, ?) ON CONFLICT(sym_name) DO UPDATE SET host = excluded.host").run(symName, h);
  } finally {
    db.close();
  }
}

/** The wire host the registration recorded for `symName`, if any. */
export function wireGrantOf(symbolMap: SymbolMap, symName: string): string | undefined {
  return symbolMap.wireGrants?.get(symName);
}
/**
 * Save the symbol table to the SQLite database (upsert all entries).
 */
export function saveSymbolMap(symbolMap: SymbolMap, dbPath?: string): void {
  const db = openSymbolDb(dbPath);
  try {
    const upsert = db.prepare(`
      INSERT INTO symbols (sym_name, value, tool, field, origin, session_key, call_id, created_at,
                           obsoleted_at, obsoleted_by, derived_from, line_range, confidentiality, bindings, integrity)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(sym_name) DO UPDATE SET
        value = excluded.value,
        tool = excluded.tool,
        field = excluded.field,
        origin = excluded.origin,
        session_key = excluded.session_key,
        call_id = excluded.call_id,
        created_at = excluded.created_at,
        obsoleted_at = excluded.obsoleted_at,
        obsoleted_by = excluded.obsoleted_by,
        derived_from = excluded.derived_from,
        line_range = excluded.line_range,
        confidentiality = excluded.confidentiality,
        bindings = excluded.bindings,
        integrity = excluded.integrity
    `);

    const saveAll = db.transaction(() => {
      for (const [symName, entry] of symbolMap.symbols) {
        upsert.run(
          symName, entry.value, entry.tool, entry.field,
          entry.origin, entry.session_key, entry.call_id, entry.created_at,
          entry.obsoleted_at, entry.obsoleted_by, entry.derived_from, entry.line_range,
          entry.confidentiality, entry.bindings === null ? null : JSON.stringify(entry.bindings),
          entry.integrity,
        );
      }
      const grant = db.prepare("INSERT INTO wire_grants (sym_name, host) VALUES (?, ?) ON CONFLICT(sym_name) DO UPDATE SET host = excluded.host");
      for (const [symName, host] of symbolMap.wireGrants ?? []) grant.run(symName, host);
    });

    saveAll();
  } finally {
    db.close();
  }
}

/**
 * Persist a single symbol to the database (incremental write).
 */
export function persistSymbol(symName: string, entry: SymbolEntry, dbPath?: string): void {
  const db = openSymbolDb(dbPath);
  try {
    db.prepare(`
      INSERT INTO symbols (sym_name, value, tool, field, origin, session_key, call_id, created_at,
                           obsoleted_at, obsoleted_by, derived_from, line_range, confidentiality, bindings, integrity)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(sym_name) DO UPDATE SET
        value = excluded.value,
        tool = excluded.tool,
        field = excluded.field,
        origin = excluded.origin,
        session_key = excluded.session_key,
        call_id = excluded.call_id,
        created_at = excluded.created_at,
        obsoleted_at = excluded.obsoleted_at,
        obsoleted_by = excluded.obsoleted_by,
        derived_from = excluded.derived_from,
        line_range = excluded.line_range,
        confidentiality = excluded.confidentiality,
        bindings = excluded.bindings,
        integrity = excluded.integrity
    `).run(
      symName, entry.value, entry.tool, entry.field,
      entry.origin, entry.session_key, entry.call_id, entry.created_at,
      entry.obsoleted_at, entry.obsoleted_by, entry.derived_from, entry.line_range,
      entry.confidentiality, entry.bindings === null ? null : JSON.stringify(entry.bindings),
      entry.integrity,
    );
  } finally {
    db.close();
  }
}

/**
 * Atomically insert a symbol row only if sym_name is not already present.
 * Returns true if the insert succeeded, false on primary-key collision.
 *
 * Used to close cross-process symbol allocation races (issue #213 R3):
 * two concurrent allocators may pick the same hash at the in-memory level;
 * whoever reaches the DB first wins, the loser retries with a fresh hash.
 */
export function persistSymbolIfNew(symName: string, entry: SymbolEntry, dbPath?: string): boolean {
  const db = openSymbolDb(dbPath);
  try {
    const result = db.prepare(`
      INSERT OR IGNORE INTO symbols (sym_name, value, tool, field, origin, session_key, call_id, created_at,
                                     obsoleted_at, obsoleted_by, derived_from, line_range, confidentiality, bindings, integrity)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      symName, entry.value, entry.tool, entry.field,
      entry.origin, entry.session_key, entry.call_id, entry.created_at,
      entry.obsoleted_at, entry.obsoleted_by, entry.derived_from, entry.line_range,
      entry.confidentiality, entry.bindings === null ? null : JSON.stringify(entry.bindings),
      entry.integrity,
    );
    return result.changes === 1;
  } finally {
    db.close();
  }
}

/**
 * Deterministic counter for integration tests.
 * When MANDU_DETERMINISTIC_SYMBOLS=1, symbol hashes are sequential
 * (0001, 0002, ...) instead of random, making them predictable in test YAML.
 */
let _deterministicCounter = 0;

export function resetDeterministicCounter(): void {
  _deterministicCounter = 0;
}

/**
 * Generate a random 4-char hex string that doesn't collide with
 * any existing symbol in the map for the given tool+field combination.
 *
 * In deterministic mode (MANDU_DETERMINISTIC_SYMBOLS=1), returns sequential
 * hex counters (0001, 0002, ...) for predictable integration tests.
 */
export function randomHash4(
  symbolMap: SymbolMap,
  tool: string,
  field?: string,
  level?: ConfidentialityLevel,
): string {
  const fmt = getActiveFormat();

  // MANDU_DETERMINISTIC_SYMBOLS is the current name; ADFI_DETERMINISTIC_SYMBOLS
  // is read as a back-compat fallback for callers still on the old env name.
  if (process.env.MANDU_DETERMINISTIC_SYMBOLS ?? process.env.ADFI_DETERMINISTIC_SYMBOLS) {
    for (;;) {
      const h = (++_deterministicCounter).toString(16).padStart(4, "0");
      const candidate = fmt.generate({ tool, hash: h, field, level });
      if (!symbolMap.symbols.has(candidate)) return h;
    }
  }

  for (let attempt = 0; attempt < 100; attempt++) {
    const h = randomBytes(2).toString("hex"); // 2 bytes = 4 hex chars
    const candidate = fmt.generate({ tool, hash: h, field, level });
    if (!symbolMap.symbols.has(candidate)) return h;
  }
  // Fallback: 8-char hex (effectively no collision)
  return randomBytes(4).toString("hex").slice(0, 4);
}

export interface AllocateSymbolOpts {
  tool: string;
  field?: string;
  value: string;
  origin?: string;
  sessionKey?: string;
  callId?: string;
  hash?: string;
  /** Confidentiality level to store (default "public"). Wire-name marker
   * follows automatically (symbol-format.ts). */
  confidentiality?: ConfidentialityLevel;
  /** Per-datum bound destinations to store (confidentiality.md §2). */
  bindings?: string[];
  /** Integrity half of the label (default "untrusted" — fail-closed). */
  integrity?: IntegrityLabel;
  /** Parent symbol name when the value derives from another symbol
   * (symbol-lineage.md G2 — the U-LLM re-symbolization path). Stored in
   * derived_from; NOT part of the reuse key (findReusableSymbol), so a
   * reuse hit keeps the first mint's lineage. */
  derivedFrom?: string;
  /** Line span within the parent value, end-exclusive `start:end` (the
   * allocateDerivedSymbol format). Stored in line_range. */
  lineRange?: string;
}

/**
 * Find a LIVE (non-obsoleted) symbol already minted for the identical
 * allocation key — (session_key, call_id, tool, field, origin, value), all
 * compared null-normalized.
 *
 * WHY (Mandu vs the stateful reference): OpenClaw stores the transformed
 * transcript, so a tool result is symbolized ONCE. The Anthropic Messages API
 * is stateless — the ingress proxy re-processes the WHOLE history and calls
 * `symbolize` again for the same tool_result on every later model call, which
 * without reuse minted a FRESH name each turn (e.g. $MDU:Read[1a9f] →
 * [4026] → [a124] for the same bytes). That breaks context coherence for
 * T-LLM (the same content changes its opaque token under the model between
 * turns, invalidating its own earlier references) and grows the symbol table
 * per turn. Returning the FIRST scanner-complete name keeps the symbol stable.
 * Legacy names that scan only as a prefix are retained for exact lookup but
 * cannot be reused; the caller allocates a canonical replacement without
 * rewriting the old row (mandu.md §9).
 *
 * The key deliberately includes call_id and origin: only the literal re-send
 * of the SAME tool call's result reuses. Identical bytes from a different
 * call, origin, or session still get their own symbol (provenance and
 * cross-session unlinkability preserved).
 *
 * The confidentiality level is deliberately NOT part of the key: a reuse hit
 * that arrives with a HIGHER level escalates the stored row in place
 * (escalateSymbolConfidentiality — monotone, fail-closed) so one datum keeps
 * one stable symbol. The name keeps its original marker; presentation only.
 */
export function findReusableSymbol(
  symbolMap: SymbolMap,
  { tool, field, value, origin, sessionKey, callId }: Omit<AllocateSymbolOpts, "hash">,
): string | null {
  const pattern = getActiveFormat().pattern;
  for (const [name] of findAllocationMatches(symbolMap, { tool, field, value, origin, sessionKey, callId })) {
    pattern.lastIndex = 0;
    const match = pattern.exec(name);
    pattern.lastIndex = 0;
    if (match?.index === 0 && match[0] === name) return name;
  }
  return null;
}

/** Original rows for an allocation key, including legacy noncanonical names.
 * The server uses their restrictions when a request needs a canonical new row;
 * these are metadata sources, not permission to reuse their wire identifiers. */
export function* findAllocationMatches(
  symbolMap: SymbolMap,
  { tool, field, value, origin, sessionKey, callId }: Omit<AllocateSymbolOpts, "hash">,
): Generator<[string, SymbolEntry]> {
  for (const [name, e] of symbolMap.symbols) {
    if (e.obsoleted_at === null && e.tool === tool && e.value === value &&
      (e.field ?? null) === (field ?? null) &&
      (e.origin ?? null) === (origin ?? null) &&
      (e.session_key ?? null) === (sessionKey ?? null) &&
      (e.call_id ?? null) === (callId ?? null)) yield [name, e];
  }
}

/** Max attempts when retrying on DB-level symbol name collisions. */
const ALLOC_MAX_ATTEMPTS = 16;

/**
 * Allocate a new symbol for an untrusted value.
 *
 * When `dbPath` is passed and `hash` is not pre-specified, allocation is
 * race-safe across concurrent processes (issue #213 R3): each attempt
 * performs an atomic INSERT OR IGNORE at the DB layer, retrying with a
 * fresh hash on primary-key collision. The in-memory `symbolMap` is only
 * updated after the DB insert succeeds so the map never lists a sym_name
 * that belongs to another allocator.
 *
 * Without `dbPath` the allocator stays in-memory only (legacy behaviour for
 * unit fixtures). Callers that preallocate `hash` upstream skip the retry
 * loop — those paths remain vulnerable to cross-process collisions at the
 * upstream hash-selection step and should migrate to the atomic helpers
 * once the upstream sites are refactored.
 */
export function allocateSymbol(
  symbolMap: SymbolMap,
  { tool, field, value, origin, sessionKey, callId, hash, confidentiality, bindings, integrity, derivedFrom, lineRange }: AllocateSymbolOpts,
  dbPath?: string,
): string {
  const fmt = getActiveFormat();
  const level: ConfidentialityLevel = confidentiality ?? "public";

  const buildEntry = (): SymbolEntry => ({
    value,
    tool,
    field: field ?? null,
    origin: origin ?? null,
    session_key: sessionKey ?? null,
    call_id: callId ?? null,
    created_at: Math.floor(Date.now() / 1000),
    obsoleted_at: null,
    obsoleted_by: null,
    derived_from: derivedFrom ?? null,
    line_range: lineRange ?? null,
    confidentiality: level,
    bindings: bindings ?? null,
    integrity: integrity ?? "untrusted",
  });

  // Caller-provided hash: honor it. Non-atomic (caller owns the hash
  // collision domain upstream).
  if (hash !== undefined) {
    const symName = fmt.generate({ tool, hash, field, level });
    const entry = buildEntry();
    symbolMap.symbols.set(symName, entry);
    touchSymbolMap(symbolMap);
    if (dbPath !== undefined) persistSymbol(symName, entry, dbPath);
    return symName;
  }

  // No dbPath: legacy in-memory-only allocation for test fixtures.
  if (dbPath === undefined) {
    const h = randomHash4(symbolMap, tool, field, level);
    const symName = fmt.generate({ tool, hash: h, field, level });
    symbolMap.symbols.set(symName, buildEntry());
    touchSymbolMap(symbolMap);
    return symName;
  }

  // Persistent allocation: retry loop with atomic DB insert.
  for (let attempt = 0; attempt < ALLOC_MAX_ATTEMPTS; attempt++) {
    const h = randomHash4(symbolMap, tool, field, level);
    const symName = fmt.generate({ tool, hash: h, field, level });
    const entry = buildEntry();
    if (persistSymbolIfNew(symName, entry, dbPath)) {
      symbolMap.symbols.set(symName, entry);
      touchSymbolMap(symbolMap);
      return symName;
    }
    // Collision: another process owns this symName. Seed the in-memory map
    // with a sentinel so randomHash4's prefilter avoids it next round.
    if (!symbolMap.symbols.has(symName)) {
      symbolMap.symbols.set(symName, entry);
      touchSymbolMap(symbolMap);
    }
  }
  throw new Error(
    `allocateSymbol: exhausted ${ALLOC_MAX_ATTEMPTS} attempts for tool=${tool} field=${field ?? ""}`,
  );
}

/**
 * The one name→entry lookup walk (symbol-format symbolNameCandidates): exact
 * name first, then the token minus trailing-dot punctuation, then
 * progressively shorter field paths down to the `$MDU:tool[hash]` base. This
 * replaces the historical ONE-LEVEL base fallback, which only recovered
 * mutations of field-LESS names — an invented suffix on a field-ful name
 * (`…inspect[h].result` + `.x`) and sentence-dot glue both fell through.
 * After every shortening candidate misses, the ALIAS TIER runs the REVERSE
 * direction (symbol-format uniqueFieldExtension): a stranded token that
 * extends to exactly one allocated name at a `.` field boundary — the
 * base↔field SSE-seam shape that showed the human a raw `$MDU:inspect[…]`
 * token (third live hit 2026-07-19) — resolves as that name.
 *
 * EVERY lookup (the data-usage gate's symbolLookup, resolve, the resolveAll*
 * scanners, the exec policy's argv resolution) routes through this walk so
 * decision and resolution can never disagree about whether a token is known.
 */
export function findSymbolByName(
  symbolMap: SymbolMap,
  token: string,
): { name: string; entry: SymbolEntry } | null {
  const r = findByCandidates(
    token,
    (n) => symbolMap.symbols.get(n),
    () => symbolMap.symbols.keys(),
  );
  if (!r) return null;
  // A registered secret with FIELD rows (plan 10 §2.4, `$MDU:nomodel_Read[h].KEY`)
  // never resolves an unknown field down to its base: the base row's value is
  // the WHOLE file, and a token the model invented (`…[h].bogus`) must not
  // release the file where one value was meant. A genuine field hits exactly;
  // trailing punctuation still trims to the base as before.
  if (r.name !== token && token.startsWith(r.name + ".") && token.length > r.name.length + 1
      && isStructuredSecretBase(symbolMap, r.name, r.hit)) {
    return null;
  }
  return { name: r.name, entry: r.hit };
}

/** A base row of a registered secret that has field rows beneath it. */
function isStructuredSecretBase(symbolMap: SymbolMap, name: string, e: SymbolEntry): boolean {
  if (e.field !== null || e.integrity !== "trusted") return false;
  if (!isSecret(parseConfidentialityLevel(e.confidentiality))) return false;
  if (!e.origin || !e.origin.startsWith("/")) return false;
  const prefix = name + ".";
  for (const [n, row] of symbolMap.symbols) {
    if (row.field !== null && row.obsoleted_at === null && n.startsWith(prefix)) return true;
  }
  return false;
}

/** The nearest KNOWN name behind a (possibly mutated) token, for messaging
 *  ("did you mean …") — null when nothing in the walk exists. */
export function nearestSymbolName(symbolMap: SymbolMap, token: string): string | null {
  return findSymbolByName(symbolMap, token)?.name ?? null;
}

/**
 * Resolve a symbol name to its raw value (candidate walk — a model-mutated
 * token resolves like the real name it mutates; genuinely unknown → null).
 */
export function resolveSymbol(symbolMap: SymbolMap, symName: string): string | null {
  return findSymbolByName(symbolMap, symName)?.entry.value ?? null;
}

/**
 * The symbol-table ENTRY behind a symbol name (candidate walk, see
 * findSymbolByName). Read-only provenance surface for the symbolProvenance
 * IPC op (symbol-quality.md §4.1 v2) and the resolveAllSymbols skip callback.
 */
export function getSymbolEntry(symbolMap: SymbolMap, symName: string): SymbolEntry | null {
  return findSymbolByName(symbolMap, symName)?.entry ?? null;
}

/** A placeholder's BASE: `$MDU:kind[code]`, no field path. */
export const PLACEHOLDER_BASE_RE = /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]$/;

/**
 * Whether a placeholder's BASE (`$MDU:kind[code]`) names a row: its own, or a
 * field's beneath it (`base.FIELD`). The DevTools relay asks it on the key
 * that closes a typed placeholder's code (devtools-relay.md §3.3, the
 * `placeholderKnown` op): false means no name the agent could go on to type
 * after it resolves, so the relay refuses that key.
 *
 * SOUND for that use: every name `findSymbolByName` can answer for a token
 * whose base is `base` is `base` or `base.<…>` (the candidate walk shortens
 * at `.` field boundaries down to the base, the alias tier extends at a `.`
 * boundary), and the walk reads every row, obsoleted ones too, as this does.
 * So false here means `resolve` of any such token answers null. Names only,
 * no value; a code is drawn at random (`randomHash4`; a counter in the
 * deterministic test mode), never from the value, so whether one is
 * allocated says nothing about any value.
 */
export function placeholderBaseKnown(symbolMap: SymbolMap, base: string): boolean {
  if (!PLACEHOLDER_BASE_RE.test(base)) return false;
  if (symbolMap.symbols.has(base)) return true;
  const prefix = `${base}.`;
  for (const name of symbolMap.symbols.keys()) if (name.startsWith(prefix)) return true;
  return false;
}

/**
 * Find all symbol names that map to a given raw value.
 */
export function findSymbolsByValue(symbolMap: SymbolMap, rawValue: string): string[] {
  const matches: string[] = [];
  for (const [symName, entry] of symbolMap.symbols) {
    if (entry.value === rawValue) matches.push(symName);
  }
  return matches;
}

/**
 * Find all symbols associated with a given callId.
 * Returns an array of [symName, SymbolEntry] pairs.
 */
export function findSymbolsByCallId(symbolMap: SymbolMap, callId: string): Array<[string, SymbolEntry]> {
  const matches: Array<[string, SymbolEntry]> = [];
  for (const [symName, entry] of symbolMap.symbols) {
    if (entry.call_id === callId) matches.push([symName, entry]);
  }
  return matches;
}

/**
 * Replace all symbol references in a string with their raw values.
 *
 * SINGLE-PASS: a resolved value that itself contains symbol references is NOT
 * re-expanded. This is the right primitive for the per-symbol-GATED egress
 * paths (net-proxy/net-supervisor egress, exec resolution): there every symbol
 * is individually approved by `desymbolizationDecision` before resolution, so
 * a nested symbol must stay opaque rather than ride out under the OUTER
 * symbol's approval. For unguarded full-fidelity surfaces (HumanView writes,
 * the quarantined U-LLM) use `resolveAllSymbolsDeep`.
 */
export function resolveAllSymbols(
  text: string,
  symbolMap: SymbolMap,
  skip?: (entry: SymbolEntry) => boolean,
): string {
  const pat = getActiveFormat().pattern;
  pat.lastIndex = 0;
  return text.replace(pat, (match) => {
    const hit = findSymbolByName(symbolMap, match);
    if (!hit) return match;
    // A skipped entry's token stays verbatim (opaque). Used by the U-LLM
    // resolve path to keep secret-labeled nested symbols out of the
    // quarantine payload (confidentiality.md §3.2 — the U-LLM call is also
    // an egress to the provider). Same candidate walk as resolution, so
    // field-path tails and mutated tokens are covered.
    if (skip && skip(hit.entry)) return match;
    // The scanner grammar swallows sentence punctuation (field segments may
    // contain dots), so a match can extend past the resolved name. Candidates
    // are prefixes of the match: re-attach a trailing dot-run the name did
    // not consume ("… $MDU:x[ab].result." keeps its period); an invented
    // field suffix between the two is the model's fiction and is dropped.
    const leftover = match.slice(hit.name.length);
    const dots = /\.+$/.exec(leftover)?.[0] ?? "";
    return hit.entry.value + dots;
  });
}

/** Max fixpoint iterations for resolveAllSymbolsDeep. Nesting arises when a
 *  symbolized representation is itself symbolized (e.g. the fs-sync AgentView
 *  twin — already a `$MDU:Read[..].<file>` on disk — is Read by the
 *  agent and the proxy re-symbolizes the tool_result: 2 levels). Real chains
 *  are short; 8 is comfortably above anything legitimate while terminating
 *  self-referential cycles. */
export const MAX_DEEP_RESOLVE_DEPTH = 8;

/** Output-size guard for resolveAllSymbolsDeep (bytes). A crafted chain whose
 *  values fan out multiple references per level could blow up exponentially
 *  (billion-laughs shape); stop expanding once past this and return as-is —
 *  fail-closed TOWARD SYMBOLIC (leftover symbols stay opaque, never leak). */
const MAX_DEEP_RESOLVE_LENGTH = 16 * 1024 * 1024;

/**
 * Replace all symbol references with their raw values, RECURSIVELY, until no
 * known symbol remains (fixpoint) or a safety cap trips.
 *
 * This is the full-fidelity dual of `resolveAllSymbols` for surfaces that are
 * supposed to see ORIGINAL data with no per-symbol gate in between:
 *   - the `desymbolize` IPC op (fs-sync syncToHuman → HumanView files), and
 *   - the quarantined U-LLM's `resolve` (inspect_symbol with `deep`) — without
 *     it, a nested chain hands the U-LLM a literal symbol string and every
 *     "summarize this file" degrades to describing the placeholder.
 *
 * Termination: each iteration either reaches a fixpoint (returned), exceeds
 * the size guard (returned, symbols left opaque), or consumes one of maxDepth
 * rounds — cycles (a symbol whose value transitively contains itself) and
 * unknown symbols (left literal by resolveAllSymbols) both hit a fixpoint or
 * the depth cap. Never throws.
 */
export function resolveAllSymbolsDeep(
  text: string,
  symbolMap: SymbolMap,
  maxDepth: number = MAX_DEEP_RESOLVE_DEPTH,
  skip?: (entry: SymbolEntry) => boolean,
): string {
  let current = text;
  for (let i = 0; i < maxDepth; i++) {
    const next = resolveAllSymbols(current, symbolMap, skip);
    if (next === current) return next; // fixpoint: nothing left resolvable
    if (next.length > MAX_DEEP_RESOLVE_LENGTH) return next; // size guard
    current = next;
  }
  return current;
}

// ─────────────────────────────────────────────────────────────────────────────
// Human-edit support: symbol obsolescence and derived symbols
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Mark a symbol as obsoleted (e.g., by a human edit).
 * Updates both the in-memory map and the persistent DB.
 */
export function obsoleteSymbol(
  symbolMap: SymbolMap,
  symName: string,
  obsoletedBy: string,
  dbPath?: string,
): void {
  const entry = symbolMap.symbols.get(symName);
  if (!entry) return;

  entry.obsoleted_at = Math.floor(Date.now() / 1000);
  entry.obsoleted_by = obsoletedBy;
  touchSymbolMap(symbolMap);

  const db = openSymbolDb(dbPath);
  try {
    db.prepare(
      "UPDATE symbols SET obsoleted_at = ?, obsoleted_by = ? WHERE sym_name = ?",
    ).run(entry.obsoleted_at, obsoletedBy, symName);
    // The row's wire grant goes with it (confidentiality.md §2.1).
    if (symbolMap.wireGrants?.delete(symName)) db.prepare("DELETE FROM wire_grants WHERE sym_name = ?").run(symName);
  } finally {
    db.close();
  }
}

export interface AllocateDerivedSymbolOpts {
  /** Parent symbol name. */
  parentSymName: string;
  /** Value for the derived symbol (subset of parent's value). */
  value: string;
  /** 0-indexed start line within parent value. */
  lineStart: number;
  /** 0-indexed end line (exclusive) within parent value. */
  lineEnd: number;
  /** 0-indexed derived piece ordinal within the current split operation. */
  splitIndex: number;
}

const SPLIT_FIELD_SEGMENT = "__mdu_split";

function appendSplitFieldSegment(field: string | null, splitIndex: number): string {
  const suffix = `${SPLIT_FIELD_SEGMENT}[${splitIndex}]`;
  return field ? `${field}.${suffix}` : suffix;
}

/**
 * Allocate a derived symbol from a parent symbol (for symbol splitting).
 * Inherits tool, call_id, origin, session_key from the parent. The field path
 * appends .__mdu_split[n] so nested split provenance is visible in the name.
 * Persists to both the in-memory map and the DB.
 *
 * Race-safe across concurrent processes (issue #213 R3): each attempt
 * performs an atomic INSERT OR IGNORE on the symbol DB and retries with a
 * fresh hash on primary-key collision, so two allocators can never land on
 * the same sym_name even when they share a stale in-memory view.
 */
export function allocateDerivedSymbol(
  symbolMap: SymbolMap,
  { parentSymName, value, lineStart, lineEnd, splitIndex }: AllocateDerivedSymbolOpts,
  dbPath?: string,
): string {
  const parent = symbolMap.symbols.get(parentSymName);
  if (!parent) {
    throw new Error(`Cannot derive from unknown symbol: ${parentSymName}`);
  }

  const fmt = getActiveFormat();
  const derivedField = appendSplitFieldSegment(parent.field, splitIndex);

  const buildEntry = (): SymbolEntry => ({
    value,
    tool: parent.tool,
    field: derivedField,
    origin: parent.origin,
    session_key: parent.session_key,
    call_id: parent.call_id,
    created_at: Math.floor(Date.now() / 1000),
    obsoleted_at: null,
    obsoleted_by: null,
    derived_from: parentSymName,
    line_range: `${lineStart}:${lineEnd}`,
    // Derived data inherits the source's confidentiality (§8) — a subset of
    // a secret is a secret, and its release destinations are the parent's.
    confidentiality: parent.confidentiality,
    bindings: parent.bindings,
    integrity: parent.integrity,
  });

  // Fixture path: no DB. Legacy in-memory-only allocation.
  if (dbPath === undefined) {
    const h = randomHash4(symbolMap, parent.tool, derivedField, parent.confidentiality);
    const symName = fmt.generate({
      tool: parent.tool,
      hash: h,
      field: derivedField,
      level: parent.confidentiality,
    });
    symbolMap.symbols.set(symName, buildEntry());
    touchSymbolMap(symbolMap);
    return symName;
  }

  for (let attempt = 0; attempt < ALLOC_MAX_ATTEMPTS; attempt++) {
    const h = randomHash4(symbolMap, parent.tool, derivedField, parent.confidentiality);
    const symName = fmt.generate({
      tool: parent.tool,
      hash: h,
      field: derivedField,
      level: parent.confidentiality,
    });
    const entry = buildEntry();
    if (persistSymbolIfNew(symName, entry, dbPath)) {
      symbolMap.symbols.set(symName, entry);
      touchSymbolMap(symbolMap);
      return symName;
    }
    // Collision: seed the in-memory map so randomHash4's prefilter avoids
    // this sym_name on the next attempt.
    if (!symbolMap.symbols.has(symName)) {
      symbolMap.symbols.set(symName, entry);
      touchSymbolMap(symbolMap);
    }
  }
  throw new Error(
    `allocateDerivedSymbol: exhausted ${ALLOC_MAX_ATTEMPTS} attempts for parent=${parentSymName}`,
  );
}

/**
 * Check if a symbol is active (not obsoleted).
 */
export function isSymbolActive(symbolMap: SymbolMap, symName: string): boolean {
  const entry = symbolMap.symbols.get(symName);
  return entry != null && entry.obsoleted_at == null;
}

/**
 * Monotone label escalation (fail-closed: labels only rise). Used when a
 * symbolize reuse hit arrives with a higher confidentiality level than the
 * stored row (findReusableSymbol deliberately excludes the level from its
 * key). The symbol NAME keeps its original marker — presentation only, the
 * table is authoritative (confidentiality.md §2).
 */
export function escalateSymbolConfidentiality(
  symbolMap: SymbolMap,
  symName: string,
  level: ConfidentialityLevel,
  dbPath?: string,
): void {
  const entry = symbolMap.symbols.get(symName);
  if (!entry) return;
  const next = maxConfidentiality(entry.confidentiality, level);
  if (next === entry.confidentiality) return;
  entry.confidentiality = next;
  touchSymbolMap(symbolMap);
  if (dbPath !== undefined) persistSymbol(symName, entry, dbPath);
}
