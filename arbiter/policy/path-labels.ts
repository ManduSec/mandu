/**
 * path-labels — the USER labeling store (confidentiality.md §6 item 2, Plan 6).
 *
 * Mandu-new (no reference origin). This is the module that makes
 * `any-model` EXIST. Before it, the level was fully plumbed — the type,
 * the `anymodel_` wire marker, the egress-gate branches, the event model — and
 * nothing in the system could mint it: the default-secret catalog
 * (secret-catalog.ts) yields only `public` or `no-model`, deliberately,
 * because §6 defines `model-ok` as "a deliberate labeling act". This store is
 * that act.
 *
 * ── THE OVERRIDE RULE (the decision this module encodes) ────────────────────
 * A user label is AUTHORITATIVE for its path; the catalog is a DEFAULT.
 *
 * The fail-closed reflex is `max(catalog, user)` — the user may only RAISE.
 * That is wrong here, and the plan doc argues it at length: a default that
 * cannot be overridden is not a default, and `max()` cannot express the single
 * most necessary correction ("this `test/fixtures/.env` is a FIXTURE — it is
 * public"). Fail-closed governs what we do when we DON'T KNOW — absent a label,
 * the catalog and its no-model default still decide, and an unparseable
 * level still fails closed to strict. It does not mean overriding what a human
 * explicitly decided about their own data.
 *
 * The guardrail is visibility, not refusal: a label BELOW the catalog's verdict
 * is a DECLASSIFICATION, and §6 requires the standing-release surface show it.
 * `isDowngrade` is how the caller learns to say so.
 *
 * ── INHERITANCE: longest segment-prefix wins, in BOTH directions ────────────
 * `~/docs` = model-ok with `~/docs/keys.txt` = strict ⇒ the file is strict.
 * `~/private` = strict with `~/private/public-notes` = public ⇒ those are public.
 * Specificity decides, never restrictiveness — otherwise you cannot carve a
 * public subtree out of a secret one, which is the second thing anyone needs.
 *
 * The segment-awareness is LOAD-BEARING, not hygiene: a raw string prefix would
 * make `~/docs-public` inherit from `~/docs`. That is a silent mislabeling, and
 * §6 names silent mislabeling as the risk that kills DLP deployments.
 *
 * ── PATTERNS (gitignore-style, path-glob.ts; confidentiality.md §6.1) ───────
 * A `policy.yaml paths:` entry with an unescaped `*`, `?` or `[` is a PATTERN
 * (`glob: true`), never a literal. Precedence, most to least specific:
 *   1. a LITERAL label on exactly this path;
 *   2. among recursive literal ancestors and matching patterns, the longest
 *      LITERAL PREFIX (a literal's whole path; a pattern's leading wildcard-free
 *      segments) — the same "specificity decides" rule, extended;
 *   3. on a tie, a pattern beats a literal ancestor (it names more of the path),
 *      and between two patterns the STRICTER level wins, then the pattern text
 *      (deterministic). Restrictiveness breaks ties only: where specificity
 *      cannot decide we do not know which the human meant, and not knowing is
 *      where fail-closed applies.
 * Consequence to state, not to discover: a pattern that leads with `**` has an
 * EMPTY literal prefix, so any directory label closer to the file beats it.
 * A pattern is never an EXACT label: only a literal can be the §8 release act
 * on one derived artifact (derived-labels.ts reads `glob` for this).
 */

import { homedir } from "os";
import path from "path";

import Database from "../db/sqlite.js";
import {
  type ConfidentialityLevel,
  isConfidentialityLevel,
  maxConfidentiality,
  parseConfidentialityLevel,
} from "../symbol-table/confidentiality.js";
import { getSymbolDbPath } from "../symbol-table/symbol-table.js";
import { compilePathGlob, pathGlobMatches, type CompiledPathGlob } from "./path-glob.js";
import { wholeFileBindings, type ValueRule } from "./value-bindings.js";

/** One human labeling act. */
export interface PathLabel {
  /** Absolute, normalized, no trailing slash. */
  path: string;
  confidentiality: ConfidentialityLevel;
  /** Bound destinations — the standing release rules (§2). */
  bindings: string[];
  /** Does this label cover descendants? (Directories: yes. A single file: the
   *  flag is irrelevant — nothing is below it.) */
  recursive: boolean;
  /** Where the label came from. `import` is reserved for Phase C (Purview/MIP);
   *  `policy-file` = declared in policy.yaml `paths:` (policy-surface.md
   *  §2.1) — law on disk, not a DB row. */
  source: "user" | "import" | "policy-file";
  updatedAt: number;
  /** `path` is a gitignore-style PATTERN (path-glob.ts), not a literal. Only
   *  `policy.yaml paths:` mints these; a dashboard act labels a real path. */
  glob?: true;
  /** Plan 10 §2.4: the file's secret spans are group 1 of this regex, not the
   *  catalog shape. Only `policy.yaml paths:` carries it (expert-only). */
  extract?: string;
  /** Plan 10 §2.1: the programs that may open the raw file. */
  readers?: Array<string | { app: string; path?: string; sha256?: string; from?: string; output?: "secret" | "clear" | "mask"; mask?: string[]; script?: string; scriptSha256?: string; prints?: "nothing" }>;
  others?: "deny" | "twin";
  /** Plan 13 §5.2: per-value bindings of a structured file (`values:`),
   *  in document order. Only `policy.yaml paths:` carries them. */
  values?: ValueRule[];
}

/** The resolved verdict for a queried path. */
export interface LabelDecision {
  level: ConfidentialityLevel;
  /** Where the file, taken WHOLE, may be sent. With `values:` this is the
   *  intersection of the file's own bindings and every value's
   *  (value-bindings.ts `wholeFileBindings`, plan 13 D1 inside one file), so
   *  every caller that treats the file as one datum (a raw holder, a copy, a
   *  whole-file symbol, an upload) gets the narrowest answer without knowing
   *  about values. Only a registered field row widens past it, per value. */
  bindings: string[];
  /** Plan 13 §5.2: the deciding label's `values:` rules, and its own
   *  declared `bindings` (what a value without an entry takes). Both present
   *  or both absent. */
  values?: ValueRule[];
  fileBindings?: string[];
  /** The deciding label's `extract` regex, when it has one (plan 10 §2.4). */
  extract?: string;
  /** The deciding label's reader list and `others` (plan 10 §2.1). */
  readers?: Array<string | { app: string; path?: string; sha256?: string; from?: string; output?: "secret" | "clear" | "mask"; mask?: string[]; script?: string; scriptSha256?: string; prints?: "nothing" }>;
  others?: "deny" | "twin";
  /** The label row that decided — may be an ANCESTOR of the queried path. The
   *  dashboard shows this so an inherited label is never mistaken for a direct
   *  one ("why is this file secret?" must always have an answer). */
  via: string;
  /** `via` is a PATTERN that matched, not a path. A pattern is never an exact
   *  label on one artifact (see the header and derived-labels.ts). */
  glob?: true;
  /** WHICH store minted the deciding row (Plan 9). Absent ⇒ `"user"` — the
   *  pre-Plan-9 shape, and every caller that builds a LabelDecision by hand.
   *  `"derived"` is a machine taint record: a file a HIGH session wrote
   *  (derived-labels.ts, §8). It matters to the caller because the two compose
   *  with the catalog differently — see `overridesCatalog`. */
  origin?: "user" | "derived" | "found";
  /** Does this verdict SUPPRESS the default-secret catalog? A human label does,
   *  in either direction (§6 — "a default that cannot be overridden is not a
   *  default"). A DERIVED label does not: it may only RAISE the catalog's verdict,
   *  never lower it, or a `model-ok` session writing `~/.ssh/id_ed25519`
   *  would declassify a key by machine. Only read when `origin === "derived"`;
   *  a user verdict always overrides. */
  overridesCatalog?: boolean;
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS path_labels (
  path            TEXT PRIMARY KEY,
  confidentiality TEXT    NOT NULL,
  bindings        TEXT,
  recursive       INTEGER NOT NULL DEFAULT 1,
  source          TEXT    NOT NULL DEFAULT 'user',
  updated_at      INTEGER NOT NULL
);
`;

/** Expand `~`, make absolute, normalize `..`, strip the trailing slash.
 *  Everything that enters or queries the store goes through this — a store
 *  keyed by un-normalized paths would miss (`~/.aws/` vs `/home/u/.aws`) and a
 *  miss means the catalog decides, which is a SILENT wrong answer. */
export function normalizeLabelPath(raw: string, home: string = homedir()): string | null {
  if (typeof raw !== "string" || raw.trim() === "") return null;
  let p = raw.trim();
  if (p === "~") p = home;
  else if (p.startsWith("~/")) p = path.posix.join(home, p.slice(2));
  if (!p.startsWith("/")) return null; // relative paths have no stable identity here
  p = path.posix.normalize(p);
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p;
}

/** Is `ancestor` a path-SEGMENT prefix of `p` (or equal to it)?
 *  `/a/docs` is a prefix of `/a/docs/x` but NOT of `/a/docs-public`. */
export function isPathPrefix(ancestor: string, p: string): boolean {
  if (ancestor === p) return true;
  return p.startsWith(ancestor.endsWith("/") ? ancestor : ancestor + "/");
}

/**
 * The pure resolver. Longest segment-prefix wins; an exact match always wins.
 * Returns null when no label covers the path — the caller then falls through to
 * the catalog, which is the fail-closed default.
 */
export function resolvePathLabel(
  rawPath: string | null | undefined,
  labels: ReadonlyMap<string, PathLabel>,
  home: string = homedir(),
): LabelDecision | null {
  if (!rawPath) return null;
  const p = normalizeLabelPath(rawPath, home);
  if (p === null) return null;

  const exact = labels.get(p);
  if (exact && !exact.glob) {
    return decisionOf(exact);
  }

  let best: PathLabel | null = null;
  let bestSpec = -1;
  for (const l of labels.values()) {
    let spec: number;
    if (l.glob) {
      const g = compiledGlobFor(l.path, home);
      if (g === null || !pathGlobMatches(g, p, l.recursive)) continue;
      spec = g.literalPrefix.length;
    } else {
      if (!l.recursive) continue;          // a non-recursive label covers itself only
      if (!isPathPrefix(l.path, p)) continue;
      spec = l.path.length;
    }
    // The MOST SPECIFIC label wins, regardless of whether it is more or less
    // restrictive than a less specific one. See the header for the tie rules.
    if (best === null || spec > bestSpec || (spec === bestSpec && tieBeats(l, best))) {
      best = l;
      bestSpec = spec;
    }
  }
  if (best === null) return null;
  return decisionOf(best);
}

/** The verdict a deciding label gives. With `values:`, `bindings` is the
 *  whole file's (the intersection) and the declared ones ride beside it. */
function decisionOf(l: PathLabel): LabelDecision {
  const values = l.values && l.values.length > 0 ? l.values : undefined;
  return {
    level: l.confidentiality,
    bindings: values ? wholeFileBindings(l.bindings, values) : l.bindings,
    via: l.path,
    ...(l.glob ? { glob: true as const } : {}),
    ...(l.extract ? { extract: l.extract } : {}),
    ...(l.readers ? { readers: l.readers } : {}),
    ...(l.others ? { others: l.others } : {}),
    ...(values ? { values, fileBindings: l.bindings } : {}),
  };
}

/** A pattern label that matched a path and LOST to a closer directory label. */
export interface OutrankedPattern {
  /** The pattern as written in `policy.yaml paths:`. */
  pattern: string;
  level: ConfidentialityLevel;
}

/**
 * OBSERVABILITY ONLY (confidentiality.md §6.1, policy-surface.md §4
 * "Test a flow"): the header's stated consequence, made discoverable. When the
 * verdict for `rawPath` came from a recursive LITERAL DIRECTORY label (an
 * ancestor, never an exact-path label: that is a deliberate act on this very
 * file), list every PATTERN label that also matches the path, lost, and is
 * STRICTER than the winner: "`**\/*.pem` = strict matched too, but `~/notes` is
 * closer to the file". Sorted by pattern text. Empty in every other case (no
 * label, an exact label, a pattern won, nothing stricter lost).
 *
 * It re-runs {@link resolvePathLabel} for the winner and reads nothing else, so
 * it cannot disagree with the decision, and no caller may decide on it.
 */
export function outrankedStricterPatterns(
  rawPath: string | null | undefined,
  labels: ReadonlyMap<string, PathLabel>,
  home: string = homedir(),
): OutrankedPattern[] {
  const won = resolvePathLabel(rawPath, labels, home);
  if (won === null || won.glob) return [];
  const p = normalizeLabelPath(rawPath as string, home);
  if (p === null || won.via === p) return [];
  const out: OutrankedPattern[] = [];
  for (const l of labels.values()) {
    if (!l.glob) continue;
    const g = compiledGlobFor(l.path, home);
    if (g === null || !pathGlobMatches(g, p, l.recursive)) continue;
    if (l.confidentiality === won.level) continue;
    if (maxConfidentiality(l.confidentiality, won.level) !== l.confidentiality) continue;
    out.push({ pattern: l.path, level: l.confidentiality });
  }
  return out.sort((a, b) => (a.pattern < b.pattern ? -1 : a.pattern > b.pattern ? 1 : 0));
}

/** Equal specificity: does `a` beat the current best `b`? (Header, rule 3.) */
function tieBeats(a: PathLabel, b: PathLabel): boolean {
  if (!!a.glob !== !!b.glob) return !!a.glob;
  if (!a.glob) return false; // two literals of equal length covering one path are the same path
  if (a.confidentiality !== b.confidentiality) return maxConfidentiality(a.confidentiality, b.confidentiality) === a.confidentiality;
  return a.path < b.path;
}

/** Compiled patterns, by (home, pattern). The law holds a handful; the bound is
 *  a guard against an unbounded caller, not an expected state. A pattern that
 *  does not compile matches NOTHING here — the validator refuses such a law at
 *  boot/reload, so this is only reachable by a caller that skipped it, and a
 *  label that silently matched more than its author wrote would be worse. */
const GLOB_CACHE = new Map<string, CompiledPathGlob | null>();
export function compiledGlobFor(pattern: string, home: string): CompiledPathGlob | null {
  const key = home + "\0" + pattern;
  let g = GLOB_CACHE.get(key);
  if (g === undefined) {
    const r = compilePathGlob(pattern, home);
    g = "glob" in r ? r.glob : null;
    if (GLOB_CACHE.size >= 4096) GLOB_CACHE.clear();
    GLOB_CACHE.set(key, g);
  }
  return g;
}

export interface PathLabelStoreOptions {
  dbPath?: string;
}

/**
 * The store. In-memory map (labels are low-volume, human-paced state, and the
 * resolver runs on every classify — a per-call SELECT would be silly) written
 * THROUGH to SQLite on every mutation, hydrated on construction. Its own
 * long-lived WAL connection to the arbiter's DB file, matching
 * EgressApprovalStore's rationale exactly.
 */
export class PathLabelStore {
  private readonly db: InstanceType<typeof Database>;
  private readonly labels = new Map<string, PathLabel>();
  /** Bumped on every set/remove — a cheap memo key for composers that merge
   *  this map with the policy document's labels (ipc/server.ts humanLabels). */
  version = 0;

  constructor(opts: PathLabelStoreOptions = {}) {
    const dbPath = opts.dbPath ?? getSymbolDbPath();
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA_SQL);
    this.hydrate();
  }

  private hydrate(): void {
    const rows = this.db
      .prepare("SELECT path, confidentiality, bindings, recursive, source, updated_at FROM path_labels")
      .all() as Array<{
        path: string; confidentiality: string; bindings: string | null;
        recursive: number; source: string; updated_at: number;
      }>;
    for (const r of rows) {
      this.labels.set(r.path, {
        path: r.path,
        // Fail-closed on a corrupt row: an unparseable level is no-model,
        // never public. A hand-edited DB must not be able to open a hole.
        confidentiality: parseConfidentialityLevel(r.confidentiality),
        bindings: parseBindings(r.bindings),
        recursive: r.recursive !== 0,
        source: r.source === "import" ? "import" : "user",
        updatedAt: r.updated_at,
      });
    }
  }

  /** Set (or replace) the label on a path. Returns the stored row, or null when
   *  the input is not a valid labeling act — an un-normalizable path (a relative
   *  path has no stable identity) or a level that is not one of the three.
   *
   *  REJECTS rather than coerces. `parseConfidentialityLevel` maps an ABSENT
   *  level to `public` — correct when parsing a symbol row minted before the
   *  axis existed, and a footgun here: a labeling act with a missing level is a
   *  caller bug, and silently minting `public` would turn it into an
   *  accidental DECLASSIFICATION. This table is new; it has no pre-axis rows to
   *  be lenient about. (Hydration still parses fail-closed — a corrupt row on
   *  disk becomes no-model, never public.) */
  set(input: {
    path: string;
    confidentiality: unknown;
    bindings?: string[];
    recursive?: boolean;
    source?: "user" | "import";
  }, home: string = homedir()): PathLabel | null {
    const p = normalizeLabelPath(input.path, home);
    if (p === null) return null;
    if (!isConfidentialityLevel(input.confidentiality)) return null;
    const row: PathLabel = {
      path: p,
      confidentiality: input.confidentiality,
      bindings: Array.isArray(input.bindings) ? input.bindings.filter((b) => typeof b === "string") : [],
      recursive: input.recursive ?? true,
      source: input.source === "import" ? "import" : "user",
      updatedAt: Date.now(),
    };
    this.db.prepare(
      `INSERT INTO path_labels (path, confidentiality, bindings, recursive, source, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(path) DO UPDATE SET
         confidentiality = excluded.confidentiality,
         bindings        = excluded.bindings,
         recursive       = excluded.recursive,
         source          = excluded.source,
         updated_at      = excluded.updated_at`,
    ).run(row.path, row.confidentiality, JSON.stringify(row.bindings), row.recursive ? 1 : 0, row.source, row.updatedAt);
    this.labels.set(row.path, row);
    this.version++;
    return row;
  }

  /** Remove a label. Returns true if one was there. */
  remove(rawPath: string, home: string = homedir()): boolean {
    const p = normalizeLabelPath(rawPath, home);
    if (p === null) return false;
    const had = this.labels.delete(p);
    if (had) this.version++;
    this.db.prepare("DELETE FROM path_labels WHERE path = ?").run(p);
    return had;
  }

  /** Every label, newest first. The dashboard's standing-release surface. */
  list(): PathLabel[] {
    return [...this.labels.values()].sort((a, b) => b.updatedAt - a.updatedAt);
  }

  /** The live map, for the pure resolver. */
  map(): ReadonlyMap<string, PathLabel> {
    return this.labels;
  }

  /** Resolve a path against the labels. Null ⇒ no label; fall through to the catalog. */
  resolve(rawPath: string | null | undefined, home: string = homedir()): LabelDecision | null {
    return resolvePathLabel(rawPath, this.labels, home);
  }

  close(): void {
    try { this.db.close(); } catch { /* double-close must not throw */ }
  }
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
