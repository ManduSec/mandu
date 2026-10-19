/**
 * derived-labels — the ON-DISK label a HIGH session's write leaves behind
 * (confidentiality.md §4 bullet 2, §8; Plan 9).
 *
 * Mandu-new (no reference origin). This is what makes the session watermark
 * survive the session.
 *
 * ── THE HOLE THIS CLOSES ────────────────────────────────────────────────────
 *
 * Plan 8's watermark is SESSION state. A high session writes a file derived from
 * the secret it read; the session ends; the watermark is gone; the next session
 * reads that file, the catalog finds no match, and it classifies PUBLIC — raw
 * into T-LLM, free to egress anywhere. Everything the watermark confined walks
 * out of the NEXT conversation. §8 names the fix precisely: *"derived files still
 * need on-disk labels so future sessions classify them correctly. Cross-session
 * persistence is a labeling act, not a runtime taint."*
 *
 * ── WHY ITS OWN TABLE, AND NOT A `source:'derived'` ROW IN path_labels ──────
 *
 * 1. SECURITY. `path_labels` is `PRIMARY KEY(path)`, so a machine-minted row
 *    would CLOBBER a human one on the same path — including a RECURSIVE
 *    directory label, silently un-labeling a whole subtree. A store whose rows a
 *    machine can overwrite is not a record of human decisions.
 * 2. LEGIBILITY. §6's surface is exactly that record: every row is a standing
 *    release rule a human is accountable for. A machine taint shown in that list
 *    is a lie in the UI, and §6's argument is that the surface must be legible.
 *
 * ── RAISE-ONLY: a machine may TAINT, never DECLASSIFY ───────────────────────
 *
 * The resolver composes `max(derived, base)` and the mint refuses to record
 * below the path's current verdict. Without that rule this feature would open a
 * hole bigger than the one it closes: a `model-ok` session writing
 * `~/.ssh/id_ed25519` would mint a `model-ok` label on a path the catalog
 * calls `no-model` — a machine-authored declassification of a key. The
 * check lives in the RESOLVER, not only at mint time, so a human label that
 * arrives LATER (raising a directory to `strict` next week) still wins over a row
 * minted under the old verdict.
 *
 * ── …EXCEPT an EXACT human label, which wins in EITHER direction ────────────
 *
 * §8: "Declassification must be first-class … without a low-friction 'release
 * this derived artifact', utility dies by over-taint." The release act is a human
 * labeling THAT ARTIFACT — an exact-path label beats the derived row, `public`
 * included. An ANCESTOR label does not: `~/notes = public` must not silently
 * release every secret-derived file a high session ever drops into `~/notes`. A
 * bulk default is not a decision about the artifact.
 */

import { randomUUID } from "node:crypto";
import { homedir } from "os";

import Database from "../db/sqlite.js";
import {
  type ConfidentialityLevel,
  maxConfidentiality,
  parseConfidentialityLevel,
} from "../symbol-table/confidentiality.js";
import { getSymbolDbPath } from "../symbol-table/symbol-table.js";
import {
  type LabelDecision,
  type PathLabel,
  normalizeLabelPath,
  resolvePathLabel,
} from "./path-labels.js";

/** One machine-minted taint record: a file a HIGH session wrote. */
export interface DerivedLabel {
  /** Absolute, normalized. HumanView spelling — the same world the catalog and
   *  the user labels are keyed in. */
  path: string;
  /** The watermark of the session that wrote it. */
  confidentiality: ConfidentialityLevel;
  /** ALWAYS EMPTY, and that is the decision (§2/§6).
   *
   *  A binding is a STANDING RELEASE RULE — "this datum may leave, to here, with
   *  no human in the loop". The obvious move is to let the derived file inherit
   *  the writing session's bindings (the union of the sinks its read data was
   *  bound for). That would be a MACHINE MINTING A RELEASE SURFACE: a future
   *  session reading the file would egress to those sinks with no approval, where
   *  before the write it needed one. §8 says derived data inherits the source's
   *  LEVEL; it never says it inherits the source's releases, and §6 is emphatic
   *  that every standing grant is a human act the dashboard must show.
   *
   *  So the taint carries the level and nothing else. A human who wants the
   *  derived artifact released to a sink labels it — one act, visible, theirs.
   *  The field stays on the row so the wire/UI shape matches a user label (it
   *  renders as "—": bound NOWHERE, which is exactly true).
   *
   *  Confidentiality plan 13 §4.6 keeps the refusal of the union and gives
   *  the copy a label BY REFERENCE to its sources (built 2026-10-02): the
   *  intersection of the sources' bindings as they stand, computed at each
   *  lookup from the human's labels (`composedLabel`, label-lookup.ts) and
   *  never stored here, so this field stays empty and a revoked source
   *  binding reaches every copy. A row with unknown `sources` stays bound
   *  nowhere. Since 2026-10-02 (plan 13 D4) the guard also gates a derived
   *  path at the open (`derivedLabelsSince`), discovery lists it, and the
   *  row follows a rename or hard link (`followDerivedLabel`). */
  bindings: string[];
  /** WHICH session wrote it — §8 requires the declassification UI show what fed
   *  the artifact, and this is the handle to that provenance. */
  sessionKey: string;
  /** The tool that wrote it (`Write`, `Edit`, …), for the same reason. */
  tool: string | null;
  /** Confidentiality plan 13 D4 (§4.6, the part built): the secret FILES the
   *  writers held, the union over every write (a file written twice may hold
   *  either's bytes). `null` = unknown (a high session wrote it, Plan 9, or a
   *  row from before 2026-10-02): no holder shortcut. A process that already
   *  holds every one of them gains nothing by reading this file raw, so the
   *  program gate lets it (`decideSecretOpen`); everyone else gets the twin. */
  sources: string[] | null;
  createdAt: number;
  updatedAt: number;
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS derived_labels (
  path            TEXT PRIMARY KEY,
  confidentiality TEXT    NOT NULL,
  bindings        TEXT,
  session_key     TEXT    NOT NULL DEFAULT '',
  tool            TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);
`;

/**
 * The derived verdict for one path. EXACT MATCH ONLY — no inheritance, in either
 * direction. A derived row is a statement about the bytes in ONE file: it must
 * not taint that file's siblings (a directory is never the target of a write
 * tool), and a derived row on a directory must not exist to taint what is under
 * it. Human labels inherit (they are policy); machine taint does not (it is a
 * fact about one artifact).
 */
export function resolveDerivedLabel(
  rawPath: string | null | undefined,
  derived: ReadonlyMap<string, DerivedLabel>,
  home: string = homedir(),
): DerivedLabel | null {
  if (!rawPath) return null;
  const p = normalizeLabelPath(rawPath, home);
  if (p === null) return null;
  return derived.get(p) ?? null;
}

/**
 * The PURE composition (the module header's two rules, stated as code). Returns
 * the verdict `pathConfidentiality` should apply — or null for "no label at all",
 * which keeps the catalog fall-through byte-identical to the pre-Plan-9 system.
 *
 * The `origin`/`overridesCatalog` fields on the result are how the caller knows
 * whether the CATALOG still gets a say: a human label overrides it in either
 * direction (§6), a derived label only raises it.
 */
export function resolveWithDerived(
  rawPath: string | null | undefined,
  humanLabels: ReadonlyMap<string, PathLabel>,
  derivedLabels: ReadonlyMap<string, DerivedLabel>,
  home: string = homedir(),
): LabelDecision | null {
  const human = resolvePathLabel(rawPath, humanLabels, home);
  const derived = resolveDerivedLabel(rawPath, derivedLabels, home);

  // No taint ⇒ exactly today's answer, whatever it is.
  if (derived === null) return human;

  const asDecision = (overridesCatalog: boolean): LabelDecision => ({
    level: derived.confidentiality,
    bindings: derived.bindings,
    via: derived.path,
    origin: "derived",
    overridesCatalog,
  });

  // No human label covers the path ⇒ the derived row stands, and the CATALOG
  // still composes with it (raise-only) in pathConfidentiality.
  if (human === null) return asDecision(false);

  // An EXACT human label is a decision about THIS artifact — the §8 release act.
  // It wins in either direction, `public` included, and it suppresses the catalog
  // as any human label does. (An ANCESTOR label does not: see the header.)
  // A PATTERN is never that act, even one whose text equals the path: it is a
  // statement about a class of files, written before this artifact existed.
  if (human.via === derived.path && !human.glob) return human;

  // An ancestor human label: the catalog is already overridden, so only the two
  // labels compete — and the derived row may only RAISE.
  if (maxConfidentiality(human.level, derived.confidentiality) === human.level) return human;
  return asDecision(true);
}

export interface DerivedLabelStoreOptions {
  dbPath?: string;
}

/**
 * The store. Same shape and rationale as PathLabelStore: an in-memory map (the
 * resolver runs on every classify) written THROUGH to SQLite on every mutation,
 * hydrated on construction, on its own long-lived WAL connection.
 */
export class DerivedLabelStore {
  private readonly db: InstanceType<typeof Database>;
  private readonly labels = new Map<string, DerivedLabel>();
  /** Confidentiality plan 13 D4: every row's change number, and the last one
   *  handed out. The guard asks for what changed after the number it saw
   *  (`since`), within one `epoch`; in memory only, so a restarted arbiter
   *  is a new epoch and the guard re-reads every row. */
  private readonly rowGen = new Map<string, number>();
  private gen = 0;
  /** This store instance (a fresh id per arbiter start). */
  readonly epoch: string = randomUUID();

  constructor(opts: DerivedLabelStoreOptions = {}) {
    const dbPath = opts.dbPath ?? getSymbolDbPath();
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA_SQL);
    // 2026-10-02 (plan 13 D4): the writers' source files.
    const cols = this.db.prepare("PRAGMA table_info(derived_labels)").all() as Array<{ name: string }>;
    if (!cols.some((c) => c.name === "sources")) this.db.exec("ALTER TABLE derived_labels ADD COLUMN sources TEXT");
    this.hydrate();
  }

  private hydrate(): void {
    const rows = this.db
      .prepare(
        "SELECT path, confidentiality, bindings, session_key, tool, sources, created_at, updated_at FROM derived_labels",
      )
      .all() as Array<{
        path: string; confidentiality: string; bindings: string | null;
        session_key: string; tool: string | null; sources: string | null;
        created_at: number; updated_at: number;
      }>;
    for (const r of rows) {
      this.rowGen.set(r.path, ++this.gen);
      this.labels.set(r.path, {
        path: r.path,
        // Fail-closed on a corrupt row: unknown → no-model, never public.
        confidentiality: parseConfidentialityLevel(r.confidentiality),
        bindings: parseBindings(r.bindings),
        sessionKey: r.session_key ?? "",
        tool: r.tool,
        sources: parseSources(r.sources),
        createdAt: r.created_at,
        updatedAt: r.updated_at,
      });
    }
  }

  /**
   * Record (or raise) the taint on a written path. MONOTONE, like the session
   * watermark itself: a later write at a LOWER level never lowers the row.
   *
   * We cannot tell an overwrite from an append (`Edit` is a partial modification),
   * so a public session writing a tainted file leaves the taint standing. That is
   * over-restriction by construction, and the human clears it (`remove`) or
   * overrides it with an exact label — both are one act, and both are visible.
   *
   * Returns null when the path has no stable identity (relative — the same rule
   * PathLabelStore applies, and for the same reason).
   */
  raise(
    rawPath: string,
    level: ConfidentialityLevel,
    meta: { sessionKey: string; tool?: string | null; sources?: readonly string[] | null },
    home: string = homedir(),
  ): DerivedLabel | null {
    const p = normalizeLabelPath(rawPath, home);
    if (p === null) return null;

    const prev = this.labels.get(p);
    const next = prev ? maxConfidentiality(prev.confidentiality, level) : level;
    // NO BINDINGS, ever — see the field's doc. A machine may taint; it may not
    // grant a release.
    const bindings: string[] = [];
    // The writers' sources: the union over every write; unknown (null) once
    // any write's sources were unknown, and for a fresh row without them.
    // 2026-10-16: NO sources (`[]`) is as absorbing as unknown. A row's
    // destinations are the INTERSECTION of its sources' (label-lookup.ts
    // `byReference`), and a row with none, or unknown ones, is bound
    // nowhere; so adding a source to a non-empty list can only narrow, but
    // `[]` → `[A]` would move a row from nowhere to A's hosts. A raise never
    // adds a destination: nowhere stays nowhere, from either side.
    const given = meta.sources === undefined || meta.sources === null ? null : [...meta.sources];
    const sources = prev === undefined
      ? (given === null ? null : [...new Set(given)].sort())
      : prev.sources === null || given === null
        ? null
        : prev.sources.length === 0 || given.length === 0
          ? []
          : [...new Set([...prev.sources, ...given])].sort();
    const now = Date.now();
    const row: DerivedLabel = {
      path: p,
      confidentiality: next,
      bindings,
      // The MOST RECENT writer owns the provenance line — it is the one whose
      // read data the newest bytes came from.
      sessionKey: meta.sessionKey,
      tool: meta.tool ?? null,
      sources,
      createdAt: prev?.createdAt ?? now,
      updatedAt: now,
    };
    this.db.prepare(
      `INSERT INTO derived_labels (path, confidentiality, bindings, session_key, tool, sources, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(path) DO UPDATE SET
         confidentiality = excluded.confidentiality,
         bindings        = excluded.bindings,
         session_key     = excluded.session_key,
         tool            = excluded.tool,
         sources         = excluded.sources,
         updated_at      = excluded.updated_at`,
    ).run(
      row.path, row.confidentiality, JSON.stringify(row.bindings),
      row.sessionKey, row.tool, row.sources === null ? null : JSON.stringify(row.sources),
      row.createdAt, row.updatedAt,
    );
    this.labels.set(row.path, row);
    this.rowGen.set(row.path, ++this.gen);
    return row;
  }

  /** The last change number handed out (0: no row was ever written in this
   *  epoch). */
  generation(): number {
    return this.gen;
  }

  /** A change number for a row another store lists in this store's sequence
   *  (session-path-labels.ts: the guard reads both through one cursor,
   *  `derivedLabelsSince`). */
  nextGen(): number {
    return ++this.gen;
  }

  /** The rows raised after change number `gen` (every row for 0), oldest
   *  change first. A removed row is not reported: whoever keeps a copy of
   *  the list keeps it labelled until it reads the list afresh, which errs
   *  toward the label. */
  since(gen: number): DerivedLabel[] {
    const out: Array<[number, DerivedLabel]> = [];
    for (const [path, g] of this.rowGen) {
      const row = this.labels.get(path);
      if (row && g > gen) out.push([g, row]);
    }
    return out.sort((a, b) => a[0] - b[0]).map(([, r]) => r);
  }

  /** The human's CLEAR act (§8's first-class declassification, the blunt form).
   *  The other form is an exact-path user label, which OVERRIDES this row without
   *  destroying the record. */
  remove(rawPath: string, home: string = homedir()): boolean {
    const p = normalizeLabelPath(rawPath, home);
    if (p === null) return false;
    const had = this.labels.delete(p);
    this.rowGen.delete(p);
    if (had) this.gen++;
    this.db.prepare("DELETE FROM derived_labels WHERE path = ?").run(p);
    return had;
  }

  /** Every taint record, newest first — the dashboard's derived surface. */
  list(): DerivedLabel[] {
    return [...this.labels.values()].sort((a, b) => b.updatedAt - a.updatedAt);
  }

  /** The live map, for the pure resolver. */
  map(): ReadonlyMap<string, DerivedLabel> {
    return this.labels;
  }

  close(): void {
    try { this.db.close(); } catch { /* double-close must not throw */ }
  }
}

/** A row's `sources`: a JSON list of paths, else null (unknown). */
function parseSources(raw: string | null): string[] | null {
  if (!raw) return null;
  try {
    const v = JSON.parse(raw) as unknown;
    return Array.isArray(v) && v.every((b) => typeof b === "string") ? (v as string[]) : null;
  } catch {
    return null;
  }
}

/**
 * Plan 13 D4: may a process that holds raw bytes of `held` (its secret taint's
 * files, its ancestors' included) read the derived file `row` raw? Only when
 * the row's sources are known, non-empty, and every one is held: the file can
 * carry nothing the process does not already hold. Pure.
 */
export function holderMayReadDerived(row: Pick<DerivedLabel, "sources">, held: ReadonlySet<string>): boolean {
  return row.sources !== null && row.sources.length > 0 && row.sources.every((s) => held.has(s));
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
