/**
 * agent-store-fixtures — the past-sessions scan's agent-store fixtures
 * (test/fixtures/transcripts) turned back into stores
 * (docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md
 * §6): a database fixture is one `{table, ...columns}` record per row, a JSONL
 * one the store's own lines. The real ones (test/fixtures/transcripts/real,
 * written by the agents themselves: tests/transcript-fixtures/generate.ts)
 * are listed in their `manifest.json`.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import type { StoreKind } from "../../policy/transcript-stores.js";

export const FIXTURES = join(import.meta.dirname, "..", "fixtures", "transcripts");
export const REAL_FIXTURES = join(FIXTURES, "real");

/** A fixture's records, one per line. */
export function fixtureRecords(path: string): Array<Record<string, unknown>> {
  return readFileSync(path, "utf8").split("\n").filter((l) => l !== "").map((l) => JSON.parse(l) as Record<string, unknown>);
}

/** A column's value as SQLite keeps it: an object as JSON, `{$base64}` as a
 *  blob, a boolean as 0 or 1. */
function cell(v: unknown): string | number | null | Uint8Array {
  if (v !== null && typeof v === "object") {
    const b = (v as Record<string, unknown>)["$base64"];
    if (typeof b === "string" && Object.keys(v).length === 1) return new Uint8Array(Buffer.from(b, "base64"));
    return JSON.stringify(v);
  }
  if (typeof v === "boolean") return Number(v);
  return v as string | number | null;
}

/** A SQLite file holding `rows` (`{table, ...columns}`), objects as JSON,
 *  left as a running agent keeps its store: in WAL mode with the writer
 *  open and the rows in the WAL, which every Node the scan supports reads
 *  (transcript-stores.ts `openAgentStore`). Close it after the read. */
export function rowsToDb(path: string, rows: Array<Record<string, unknown>>): DatabaseSync {
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;");
  const cols = new Map<string, Set<string>>();
  for (const r of rows) {
    const t = String(r["table"]);
    const s = cols.get(t) ?? new Set<string>();
    for (const k of Object.keys(r)) if (k !== "table") s.add(k);
    cols.set(t, s);
  }
  for (const [t, s] of cols) db.exec(`CREATE TABLE "${t}" (${[...s].map((c) => `"${c}"`).join(", ")}${t === "messages" && !s.has("id") ? ", id INTEGER PRIMARY KEY" : ""})`);
  for (const r of rows) {
    const t = String(r["table"]);
    const entries = Object.entries(r).filter(([k]) => k !== "table");
    db.prepare(`INSERT INTO "${t}" (${entries.map(([k]) => `"${k}"`).join(", ")}) VALUES (${entries.map(() => "?").join(", ")})`).run(...entries.map(([, v]) => cell(v)));
  }
  return db;
}

/** Lay `records` out as a store of `kind` under `dir`, where the store
 *  layer's root for that kind finds it; returns the root and the writer to
 *  close (a database's). */
export function layOut(kind: StoreKind, dir: string, records: Array<Record<string, unknown>>, name = "s"): { root: string; writer?: DatabaseSync } {
  if (kind === "opencode-db" || kind === "goose-db") { const root = join(dir, "store.db"); return { root, writer: rowsToDb(root, records) }; }
  if (kind === "openclaw-db") { mkdirSync(join(dir, "main", "agent"), { recursive: true }); return { root: dir, writer: rowsToDb(join(dir, "main", "agent", "openclaw-agent.sqlite"), records) }; }
  const lines = records.map((r) => JSON.stringify(r)).join("\n");
  if (kind === "openclaw-jsonl") { mkdirSync(join(dir, "main", "sessions"), { recursive: true }); writeFileSync(join(dir, "main", "sessions", `${name}.jsonl`), lines); return { root: dir }; }
  writeFileSync(join(dir, kind === "goose-request-log" ? `llm_request.${name === "s" ? "0" : name}.jsonl` : `${name}.jsonl`), lines);
  return { root: dir };
}

/** One real fixture, as its manifest lists it. */
export interface RealFixture {
  /** The generator's id of the run: opencode, opencode2, goose, openclaw, openclaw9. */
  id: string;
  version: string;
  fixture: string;
  kind: StoreKind;
  /** The store's place under the agent's home. */
  store: string;
}

/** The real fixtures the manifest lists. */
export function realFixtures(): RealFixture[] {
  const m = JSON.parse(readFileSync(join(REAL_FIXTURES, "manifest.json"), "utf8")) as { agents: Array<{ id: string; version?: string; stores?: Array<{ fixture?: string; kind: StoreKind | "trace"; store: string }> }> };
  // A `trace` (OpenClaw's run trace) is listed, not copied.
  return m.agents.flatMap((a) => (a.stores ?? []).flatMap((s) => (s.fixture !== undefined && s.kind !== "trace" ? [{ id: a.id, version: a.version ?? "", fixture: s.fixture, kind: s.kind, store: s.store }] : [])));
}
