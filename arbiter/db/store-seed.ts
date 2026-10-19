/**
 * store-seed — a temporary arbiter's store, seeded READ-ONLY from the one the
 * resident arbiter keeps (`mandu why` with no Mandu running; comparisons.md
 * §3.2, runtime-instances.md §9b).
 *
 * `mandu why` asks an arbiter. With none running it starts a temporary one
 * (launcher/src/doctor-secrets.ts `throwawayArbiter`) on a store of its own,
 * which held none of what the resident one keeps: the human's remembered
 * answers, the changes waiting in Approvals and the content in force while a
 * hand edit of `policy.yaml` waits, the labels set on the dashboard, the
 * files a secret-holding session wrote, the registered files' placeholders.
 * So `--to` never found a remembered answer and a waiting change read as if
 * it were in force (the CLI said so). Seeded with those tables, the
 * temporary arbiter answers with the arbiter's own code what the resident
 * one would answer once started.
 *
 * The resident store is only ever READ, and never by a second writer:
 *   - it is opened on a connection of its own with SQLITE_OPEN_READONLY
 *     (`readOnly`: SQLite refuses every write, and creates no database);
 *   - by a URI where this Node's SQLite takes one (`readOnlyUri`): with no
 *     `-wal` beside the store (no connection open: the last one to close
 *     checkpoints and deletes it) `immutable=1`, so the read creates no
 *     `-wal` or `-shm` next to it. Node 22.13 (the floor, CI's) takes no URI
 *     filename; there the store is opened by its path, read-only, and SQLite
 *     creates the empty `-wal` and the `-shm` index any reader of a WAL
 *     database creates, with the store's own mode, and leaves them (an
 *     arbiter started later uses them as its own); the store's bytes are not
 *     written either way. With a `-wal` beside it (an arbiter is running, or
 *     died unclean) the read goes through the WAL, so the newest commit is
 *     read;
 *   - the file opened is checked to be the store asked for, and its schema
 *     stamp to be one this build reads (`schemaVersionReadable`): a store of
 *     another Mandu version is refused, not mis-read;
 *   - a missing store is no store (the copy is never created then either).
 * The single-writer lock (runtime-instances.md §9) names writers; readers
 * were always allowed.
 *
 * What is copied, into a fresh file that must not exist (created 0600):
 * only the tables {@link SEED_TABLES} names, with their own DDL. `symbols`
 * keeps only the registered files' rows (what `registeredFileSymbols` and
 * `listSecretRegistry` read), and their VALUE is replaced by the
 * placeholder's own name: no original is copied anywhere, and the temporary
 * arbiter holds none of the resident store's. `policy_enforced` keeps only
 * the row of the policy file the resident arbiter read, re-keyed to the copy
 * of it the temporary arbiter reads (so a held change stays held, and a
 * declined one is never written back over the person's file).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { closeSync, existsSync, mkdirSync, openSync, realpathSync, statSync, unlinkSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import Database from "./sqlite.js";
import { schemaVersionReadable } from "../symbol-table/symbol-table.js";

/** The tables a seeded store carries: what `whyPath`, `whyHost` and
 *  `testFlow` read beyond the law in the file. */
export const SEED_TABLES = [
  "symbols", // registered files' rows only, values replaced
  "egress_approvals", // the human's remembered answers (and the open/change ones)
  "egress_approvals_seq",
  "policy_proposals", // the changes waiting in Approvals, held disk edits
  "policy_enforced", // the content in force while a disk edit waits
  "policy_changes",
  "path_labels", // labels set on the dashboard
  "derived_labels", // files a secret-holding session wrote
] as const;

/** The registered files' rows (registry.ts: tool `Read`, trusted, an origin),
 *  active ones only. */
const REGISTRY_ROWS = "tool = 'Read' AND integrity = 'trusted' AND origin IS NOT NULL AND obsoleted_at IS NULL";

/** `uri`: the store was read through an immutable/read-only URI (nothing
 *  created beside it); `path`: by its path, read-only (this SQLite takes no
 *  URI filename). */
export type SeedResult = { ok: true; rows: Record<string, number>; via: "uri" | "path" } | { ok: false; why: string };

export interface SeedOptions {
  /** The resident arbiter's store (read only). */
  from: string;
  /** The new store: must not exist. */
  to: string;
  /** The policy file whose content in force is carried over (`from`, as
   *  the resident arbiter read it) and the path it is keyed by in the copy
   *  (`to`). Absent: no content in force is carried (the file is the law). */
  policy?: { from: string; to: string };
}

/** One DDL statement of the store's own schema, or null. */
function safeDdl(sql: unknown): string | null {
  if (typeof sql !== "string") return null;
  if (!/^CREATE (UNIQUE )?(TABLE|INDEX) /i.test(sql) || sql.includes(";")) return null;
  return sql;
}

/** The SQLite URI that opens `path` read-only (immutable when no WAL is
 *  beside it). Pure but for the `-wal` check. */
export function readOnlyUri(path: string, walExists: (p: string) => boolean = existsSync): string {
  return pathToFileURL(path).href + (walExists(`${path}-wal`) ? "?mode=ro" : "?mode=ro&immutable=1");
}

type Db = InstanceType<typeof Database>;

/** The store, opened read-only: by its URI where this SQLite takes one, else
 *  by its path. Throws when it cannot be opened. */
function openReadOnly(from: string): { db: Db; via: "uri" | "path" } {
  try {
    return { db: new Database(readOnlyUri(from), { readOnly: true }), via: "uri" };
  } catch {
    // No URI filenames here (Node 22.13): read-only by the path.
    return { db: new Database(from, { readOnly: true }), via: "path" };
  }
}

/**
 * Copy {@link SEED_TABLES} from the store at `from`, read only, into a new
 * store at `to`. On any failure nothing is left at `to` and the reason is
 * returned (the caller answers as before). Never writes `from`.
 */
export function seedStoreFrom(opts: SeedOptions): SeedResult {
  const from = resolve(opts.from);
  const to = resolve(opts.to);
  const fail = (why: string): SeedResult => ({ ok: false, why });
  if (from === to) return fail("the store and its copy are one file");
  try {
    if (!statSync(from).isFile()) return fail(`${from} is not a file`);
  } catch {
    return fail(`no store at ${from}`);
  }
  if ([to, `${to}-wal`, `${to}-shm`, `${to}-journal`].some((p) => existsSync(p))) return fail(`${to} exists already`);
  let fromReal: string;
  try {
    fromReal = realpathSync(from);
  } catch (err) {
    return fail(`cannot read ${from}: ${(err as Error).message}`);
  }
  let src: Db | null = null;
  let dst: Db | null = null;
  let created = false;
  let done = false;
  try {
    const opened = openReadOnly(from);
    src = opened.db;
    const file = (src.prepare("SELECT file FROM pragma_database_list WHERE name = 'main'").get() as { file?: unknown } | undefined)?.file;
    if (typeof file !== "string" || file === "" || realpathSync(file) !== fromReal) return fail(`opened ${String(file)}, not ${from}`);
    const version = Number((src.prepare("PRAGMA user_version").get() as { user_version?: number | bigint } | undefined)?.user_version ?? 0);
    if (!schemaVersionReadable(version)) return fail(`${from} was written by another Mandu version (schema v${version})`);

    mkdirSync(dirname(to), { recursive: true, mode: 0o700 });
    closeSync(openSync(to, "wx", 0o600));
    created = true;
    dst = new Database(to);
    const rows: Record<string, number> = {};
    dst.exec("BEGIN");
    for (const table of SEED_TABLES) {
      if (table === "policy_enforced" && opts.policy === undefined) continue;
      const ddl = src.prepare(
        "SELECT type, sql FROM sqlite_master WHERE tbl_name = ? AND type IN ('table', 'index') AND sql IS NOT NULL ORDER BY type = 'index', name",
      ).all(table) as Array<{ type: string; sql: unknown }>;
      if (!ddl.some((d) => d.type === "table")) continue; // an older store without it
      for (const d of ddl) {
        const sql = safeDdl(d.sql);
        if (sql === null) throw new Error(`unexpected schema for ${table}`);
        dst.exec(sql);
      }
      const cols = (src.prepare(`PRAGMA table_info("${table}")`).all() as Array<{ name: string }>).map((c) => c.name);
      const quoted = cols.map((c) => `"${c.replace(/"/g, "\"\"")}"`);
      const where = table === "symbols" ? ` WHERE ${REGISTRY_ROWS}` : table === "policy_enforced" ? " WHERE path = ?" : "";
      const select = src.prepare(`SELECT ${quoted.join(", ")} FROM "${table}"${where}`);
      const found = (table === "policy_enforced" ? select.all(opts.policy!.from) : select.all()) as Array<Record<string, unknown>>;
      const insert = dst.prepare(`INSERT INTO "${table}" (${quoted.join(", ")}) VALUES (${cols.map(() => "?").join(", ")})`);
      for (const row of found) {
        insert.run(...cols.map((c) => {
          // No original leaves the store: a registered row's value is its own name.
          if (table === "symbols" && c === "value") return row["sym_name"];
          // The content in force, keyed by the copy of the policy file.
          if (table === "policy_enforced" && c === "path") return opts.policy!.to;
          return row[c];
        }));
      }
      rows[table] = found.length;
    }
    dst.exec(`PRAGMA user_version = ${version}`);
    dst.exec("COMMIT");
    done = true;
    return { ok: true, rows, via: opened.via };
  } catch (err) {
    return fail((err as Error).message);
  } finally {
    try { src?.close(); } catch { /* closing the read */ }
    try { dst?.close(); } catch { /* closing a failed copy */ }
    if (created && !done) for (const p of [to, `${to}-journal`]) try { unlinkSync(p); } catch { /* not created */ }
  }
}
