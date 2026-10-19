/**
 * rule-hits — how often each rule decided (docs/design/ui/policy-surface.md
 * §2.4, stage 4). Mandu-new (no reference origin).
 *
 * Every egress decision the arbiter takes carries a `RuleRef`; this store
 * counts, per rule id, how many decisions it made and when it last did —
 * the firewall-table "states" column, and the signal behind "this
 * relaxation has not fired in 60 days". Audit-mode user rules count
 * separately (`auditHits`): they were evaluated and would have decided, but
 * did not. MACHINE state, so it lives in the arbiter's SQLite beside the
 * symbol table (a DB reset loses counts, never law). Best-effort: a write
 * failure is logged by the caller and never reaches a decision.
 */
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import Database from "../db/sqlite.js";

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS rule_hits (
  rule_id    TEXT PRIMARY KEY,
  hits       INTEGER NOT NULL DEFAULT 0,
  audit_hits INTEGER NOT NULL DEFAULT 0,
  last_hit   INTEGER
);
`;

export interface RuleHitRow {
  hits: number;
  auditHits: number;
  /** Epoch millis of the last decision (either kind), or null. */
  lastHit: number | null;
}

export interface RuleHitStoreOptions {
  /** Omit for an in-memory store (tests). */
  dbPath?: string;
  now?: () => number;
}

export class RuleHitStore {
  private readonly rows = new Map<string, RuleHitRow>();
  private readonly db?: InstanceType<typeof Database>;
  private readonly now: () => number;

  constructor(opts: RuleHitStoreOptions = {}) {
    this.now = opts.now ?? (() => Date.now());
    if (opts.dbPath !== undefined) {
      const dir = join(opts.dbPath, "..");
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      this.db = new Database(opts.dbPath);
      this.db.pragma("journal_mode = WAL");
      this.db.exec(SCHEMA_SQL);
      const rows = this.db.prepare("SELECT rule_id, hits, audit_hits, last_hit FROM rule_hits").all() as Array<{
        rule_id: string; hits: number; audit_hits: number; last_hit: number | null;
      }>;
      for (const r of rows) this.rows.set(r.rule_id, { hits: r.hits, auditHits: r.audit_hits, lastHit: r.last_hit });
    }
  }

  /** A rule decided. */
  hit(ruleId: string): void {
    this.bump(ruleId, "hits");
  }

  /** An audit-mode rule matched and WOULD have decided. */
  auditHit(ruleId: string): void {
    this.bump(ruleId, "auditHits");
  }

  private bump(ruleId: string, field: "hits" | "auditHits"): void {
    const row = this.rows.get(ruleId) ?? { hits: 0, auditHits: 0, lastHit: null };
    row[field] += 1;
    row.lastHit = this.now();
    this.rows.set(ruleId, row);
    this.db
      ?.prepare(
        `INSERT INTO rule_hits (rule_id, hits, audit_hits, last_hit) VALUES (?, ?, ?, ?)
         ON CONFLICT(rule_id) DO UPDATE SET hits = excluded.hits, audit_hits = excluded.audit_hits, last_hit = excluded.last_hit`,
      )
      .run(ruleId, row.hits, row.auditHits, row.lastHit);
  }

  get(ruleId: string): RuleHitRow | undefined {
    const r = this.rows.get(ruleId);
    return r ? { ...r } : undefined;
  }

  all(): Record<string, RuleHitRow> {
    const out: Record<string, RuleHitRow> = {};
    for (const [id, r] of this.rows) out[id] = { ...r };
    return out;
  }

  close(): void {
    this.db?.close();
  }
}
