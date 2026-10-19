/**
 * session-labels — the SESSION HIGH-WATERMARK (confidentiality.md §4, Plan 8).
 *
 * Mandu-new (no reference origin). The classic Bell-LaPadula floating label
 * (Weissman's high-watermark, Fenton's data-mark machine) with the model
 * CONVERSATION as the subject:
 *
 *     sessionLabel = max(sessionLabel, confidentiality of every in-context read)
 *
 * WHY IT MUST EXIST AT ALL. Once the model has read secret content into its
 * context, "not readable by the outside world" cannot be enforced on the SYMBOL
 * any more — the model can paraphrase, re-encode, or summarize the content into
 * anything it emits, and **a paraphrase carries no symbol for the egress gate to
 * catch**. `desymbolizationDecision` is per-symbol and therefore structurally
 * blind to it. The only enforceable meaning of `any-model` AFTER an
 * in-context read is session confinement. §4 is blunt about the alternative: a
 * design that grants the read but skips the watermark "is theater".
 *
 * ── TWO pieces of state, and the second one is the surprise ─────────────────
 *
 * `confidentiality` is the floating label. `untrustedTainted` is §9 rule 2's
 * other half — the rule suspends `model-ok`'s standing model clearance for
 * in-context reads when "the session is untrusted-tainted", and THAT CONDITION
 * HAD NO REPRESENTATION IN THE ARBITER. ProvenanceStore tracks *process* and
 * *file* taint; nothing tracked *session* taint. Rule 2 was unimplementable
 * until this column existed.
 *
 * ── The cost, stated honestly (§7 of the plan doc) ──────────────────────────
 *
 * Under the real Claude Code inbound policy a `Read` tool_result is
 * UNTRUSTED-by-integrity, so `untrustedTainted` goes true almost immediately in
 * any real session — and by rule 2 every in-context read then requires human
 * approval. That is CORRECT (it is the danger cell, and §9 means it), and it
 * means rung 3 in practice is an approval per read. Over-taint is the predicted
 * failure mode, and it is a reason to expect rung 2 (the quarantined read) to be
 * the path anyone actually uses. Do not soften this before measuring it — the
 * softening knobs are exactly where a confidentiality design gets quietly gutted.
 *
 * ── The bindings follow the law in force (confidentiality.md §2.1, §4) ──────
 *
 * The LEVEL is a fact about the past (the session read the secret) and never
 * falls. The BINDINGS are a standing release rule, and the human's label
 * decides them now, not at the moment of the read: before 2026-10-05 `raise`
 * copied the read symbol's bindings into the row and nothing re-derived them,
 * so a binding removed from policy.yaml (or by a dashboard label act, or while
 * the arbiter was down) kept releasing the session's paraphrases to the old
 * host. The store now records WHICH symbols each session read into context
 * (`session_label_sources`), and {@link SessionLabelStore.rederive} sets every
 * high session's bindings to the intersection of those symbols' CURRENT
 * bindings (the rows themselves follow the law, current-bindings.ts). A
 * source it cannot read (an unknown or obsoleted row, a read recorded before
 * the sources were, a `raise` that named none) binds the session nowhere, and
 * its egress asks.
 */

import Database from "../db/sqlite.js";
import {
  type ConfidentialityLevel,
  maxConfidentiality,
  parseConfidentialityLevel,
} from "../symbol-table/confidentiality.js";
import { getSymbolDbPath } from "../symbol-table/symbol-table.js";
import { intersectBindings } from "./flow-taint.js";

/** A session's floating label. */
export interface SessionLabel {
  sessionKey: string;
  /** The high-watermark: the max level ever READ INTO CONTEXT in this session. */
  confidentiality: ConfidentialityLevel;
  /** Has this session ingested UNTRUSTED data? (§9 rule 2.) */
  untrustedTainted: boolean;
  /** The INTERSECTION of the bound destinations of every secret datum read
   *  into context here (confidentiality plan 13 D1 / §9 R3: before 2026-10-02
   *  the union, which let a session holding two secrets deliver either to the
   *  other's sink). A high session's egress is allowed to these sinks without
   *  a fresh human decision — every datum it read may go there (§2/§4) — and
   *  nowhere else. */
  bindings: string[];
  updatedAt: number;
}

/** A session with no record yet — public and clean. Never invent a level. */
const CLEAN: Omit<SessionLabel, "sessionKey" | "updatedAt"> = {
  confidentiality: "public",
  untrustedTainted: false,
  bindings: [],
};

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS session_labels (
  session_key       TEXT PRIMARY KEY,
  confidentiality   TEXT    NOT NULL DEFAULT 'public',
  untrusted_tainted INTEGER NOT NULL DEFAULT 0,
  bindings          TEXT,
  updated_at        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS session_label_sources (
  session_key TEXT NOT NULL,
  symbol      TEXT NOT NULL,
  PRIMARY KEY (session_key, symbol)
);
`;

/** The source of a secret read the store cannot name: a `raise` without a
 *  symbol, or a high session recorded before the sources table existed. Never
 *  a symbol name, so it resolves to nothing and binds the session nowhere. */
export const UNKNOWN_SOURCE = "?";

/** A symbol's bindings under the law in force, or null when the row cannot
 *  be read (unknown, obsoleted). */
export type CurrentBindingsOf = (symbol: string) => readonly string[] | null;

export interface SessionLabelStoreOptions {
  dbPath?: string;
}

export class SessionLabelStore {
  private readonly db: InstanceType<typeof Database>;
  private readonly sessions = new Map<string, SessionLabel>();
  /** The symbols each session read into context above `public`. */
  private readonly sources = new Map<string, Set<string>>();

  constructor(opts: SessionLabelStoreOptions = {}) {
    const dbPath = opts.dbPath ?? getSymbolDbPath();
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA_SQL);
    this.hydrate();
  }

  private hydrate(): void {
    const rows = this.db
      .prepare("SELECT session_key, confidentiality, untrusted_tainted, bindings, updated_at FROM session_labels")
      .all() as Array<{
        session_key: string; confidentiality: string;
        untrusted_tainted: number; bindings: string | null; updated_at: number;
      }>;
    for (const r of rows) {
      this.sessions.set(r.session_key, {
        sessionKey: r.session_key,
        // Fail-closed on a corrupt row: unknown → no-model, never public.
        confidentiality: parseConfidentialityLevel(r.confidentiality),
        untrustedTainted: r.untrusted_tainted !== 0,
        bindings: parseBindings(r.bindings),
        updatedAt: r.updated_at,
      });
    }
    const src = this.db.prepare("SELECT session_key, symbol FROM session_label_sources").all() as Array<{ session_key: string; symbol: string }>;
    for (const r of src) this.sourceSet(r.session_key).add(r.symbol);
    // A high session with no recorded source (written before the table
    // existed): what it read is unknown, so the next re-derivation binds it
    // nowhere. Recorded, so a later read cannot hide the unknown one.
    for (const [key, row] of this.sessions) {
      if (row.confidentiality !== "public" && !this.sources.has(key)) this.addSource(key, UNKNOWN_SOURCE);
    }
  }

  private sourceSet(sessionKey: string): Set<string> {
    let set = this.sources.get(sessionKey);
    if (!set) this.sources.set(sessionKey, (set = new Set()));
    return set;
  }

  private addSource(sessionKey: string, symbol: string): void {
    const set = this.sourceSet(sessionKey);
    if (set.has(symbol)) return;
    this.db.prepare("INSERT OR IGNORE INTO session_label_sources (session_key, symbol) VALUES (?, ?)").run(sessionKey, symbol);
    set.add(symbol);
  }

  /** The symbols this session read into context above `public` (§4). */
  sourcesOf(sessionKey: string): string[] {
    return [...(this.sources.get(sessionKey) ?? [])];
  }

  /** The session's current state. Absent ⇒ public + clean. */
  get(sessionKey: string | undefined): SessionLabel {
    if (!sessionKey) {
      // No session key ⇒ we cannot attribute a watermark to anything. Report
      // clean; the CALLER decides what an unattributable egress means (the
      // egress gate treats it as ungated-by-watermark, which is today's
      // behavior — the watermark can only ever ADD restriction).
      return { sessionKey: "", ...CLEAN, updatedAt: 0 };
    }
    return this.sessions.get(sessionKey) ?? { sessionKey, ...CLEAN, updatedAt: 0 };
  }

  /** Is this session HIGH — i.e. has it read secret content into context? */
  isHigh(sessionKey: string | undefined): boolean {
    return this.get(sessionKey).confidentiality !== "public";
  }

  /**
   * Raise the watermark. MONOTONE — it never falls, which is the whole point of
   * a high-watermark: a session that has read a secret cannot un-read it, and
   * "the task moved on" is not a declassification.
   *
   * `source` names the symbol read (`bindings` are that row's current ones),
   * so {@link rederive} can follow the law later; a secret read with no
   * source is recorded as {@link UNKNOWN_SOURCE}.
   */
  raise(sessionKey: string, level: ConfidentialityLevel, bindings: string[] = [], source?: string): SessionLabel {
    if (level !== "public") this.addSource(sessionKey, source ?? UNKNOWN_SOURCE);
    const cur = this.get(sessionKey);
    const next = maxConfidentiality(cur.confidentiality, level);
    // The session's release surface is where EVERY secret it read may go
    // (plan 13 D1, §9 R3): the first secret read sets it, each later one
    // intersects it; a public read leaves it alone. Disjoint bindings leave
    // nothing: the session's egress then asks.
    const merged = level === "public"
      ? cur.bindings
      : cur.confidentiality === "public"
        ? [...new Set(bindings)]
        : intersectBindings([cur.bindings, bindings]);
    const unchanged = next === cur.confidentiality
      && merged.length === cur.bindings.length
      && merged.every((b) => cur.bindings.includes(b))
      && this.sessions.has(sessionKey);
    if (unchanged) return cur;
    return this.write({ ...cur, sessionKey, confidentiality: next, bindings: merged });
  }

  /**
   * Bring every high session's bindings to the law in force (§2.1, §4): the
   * intersection of the CURRENT bindings of every symbol it read into
   * context. Both directions: a binding removed from any source leaves the
   * session at once; one added to every source reaches it (each datum it
   * read may go there now, the rule a registered file's own rows follow). A
   * source `current` cannot read binds the session nowhere (fail-closed).
   * Returns the session keys it changed (persisted).
   */
  rederive(current: CurrentBindingsOf): string[] {
    const changed: string[] = [];
    for (const [key, row] of [...this.sessions]) {
      if (row.confidentiality === "public") continue;
      const want = deriveSessionBindings(this.sourcesOf(key), current);
      if (sameSet(want, row.bindings)) continue;
      this.write({ ...row, bindings: want });
      changed.push(key);
    }
    return changed;
  }

  /** Mark the session as having ingested untrusted data (§9 rule 2). Sticky. */
  taint(sessionKey: string): SessionLabel {
    const cur = this.get(sessionKey);
    if (cur.untrustedTainted && this.sessions.has(sessionKey)) return cur;
    return this.write({ ...cur, sessionKey, untrustedTainted: true });
  }

  private write(row: Omit<SessionLabel, "updatedAt">): SessionLabel {
    const full: SessionLabel = { ...row, updatedAt: Date.now() };
    this.db.prepare(
      `INSERT INTO session_labels (session_key, confidentiality, untrusted_tainted, bindings, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(session_key) DO UPDATE SET
         confidentiality   = excluded.confidentiality,
         untrusted_tainted = excluded.untrusted_tainted,
         bindings          = excluded.bindings,
         updated_at        = excluded.updated_at`,
    ).run(
      full.sessionKey, full.confidentiality, full.untrustedTainted ? 1 : 0,
      JSON.stringify(full.bindings), full.updatedAt,
    );
    this.sessions.set(full.sessionKey, full);
    return full;
  }

  /** Every session with a label — the dashboard's watermark surface. */
  list(): SessionLabel[] {
    return [...this.sessions.values()].sort((a, b) => b.updatedAt - a.updatedAt);
  }

  close(): void {
    try { this.db.close(); } catch { /* double-close must not throw */ }
  }
}

/**
 * A high session's bindings from the symbols it read: where EVERY one of
 * them may go under the law in force. No source, or one that cannot be read
 * ({@link UNKNOWN_SOURCE}, a row gone or obsoleted): nowhere. Pure.
 */
export function deriveSessionBindings(sources: readonly string[], current: CurrentBindingsOf): string[] {
  if (sources.length === 0) return [];
  const each: string[][] = [];
  for (const s of sources) {
    const b = s === UNKNOWN_SOURCE ? null : current(s);
    if (b === null) return [];
    each.push([...b]);
  }
  return [...new Set(intersectBindings(each))].sort();
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const s = new Set(a);
  return b.every((x) => s.has(x));
}

function parseBindings(raw: string | null): string[] {
  if (!raw) return [];
  try {
    const v = JSON.parse(raw) as unknown;
    return Array.isArray(v) ? v.filter((b): b is string => typeof b === "string") : [];
  } catch {
    return [];
  }
}
