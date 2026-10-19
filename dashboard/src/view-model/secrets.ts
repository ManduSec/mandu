/**
 * view-model/secrets — the pure view-model for the Secrets panel (the
 * confidentiality STANDING-RELEASE surface, confidentiality.md §6 item 2;
 * plan 6 Task 4).
 *
 * Mandu-new (no reference origin). This is the render LOGIC for the panel;
 * `public/js/secrets.js` is a thin DOM shell over the structure produced here,
 * exactly as app.js is a shell over toSessionViewModel (the server projects,
 * the browser paints). Keeping it here is what makes the two things §6 actually
 * demands — "list every `model-ok` file and every destination binding" —
 * unit-testable rather than a claim about some DOM.
 *
 * ── THE THREE INVARIANTS THIS MODULE ENCODES ────────────────────────────────
 *
 * 1. NEVER A VALUE. The panel answers "what is confined, at what level, and
 *    where may it go" — never "what is inside". The arbiter's op is shaped so
 *    no value exists on the wire; this module copies fields EXPLICITLY (never
 *    spreads its input) so a future arbiter that started leaking a `value`
 *    could not have it reach the DOM by accident. A key viewer is not the
 *    panel's job, and a dashboard that renders secrets is a secret-exfiltration
 *    surface with a nice CSS theme.
 *
 * 2. OFF IS OFF, NOT "NOTHING CONFINED". With the kill switch off (§11) the
 *    arbiter confines nothing and consults no label. Rendering that as an empty
 *    green list would be the single most dangerous thing this panel could say.
 *    `status: "off"` is therefore a distinct state from `status: "empty"`.
 *
 * 3. A DECLASSIFICATION IS LOUD. A user label WEAKER than the catalog's verdict
 *    (`declassifies: true`) is a standing rule that a file the catalog calls a
 *    credential may now flow freely. §6 requires that surface be visible; the
 *    row carries the flag AND a rendered note so no shell can quietly drop it.
 *
 * `model-ok` gets the same treatment for the dual risk (§6: "the dashboard
 * lists the `model-ok` surface explicitly") — every model-ok path, secret or
 * label, is enumerated in `summary.modelOkPaths`.
 */
import { ADMITS_NOTHING, READS_PLACEHOLDER, judgedAdmitsNothing } from "./reader-runs-code.js";

/** The four levels, in their total order (confidentiality.md §2; plan 11 D1
 *  added `local-model`: only a model the user runs themselves may read it).
 *  Mirrors the arbiter's `ConfidentialityLevel` — declared here, not imported,
 *  because the dashboard package typechecks standalone (same decoupling
 *  rationale as approval-routes). */
export const CONFIDENTIALITY_LEVELS = ["public", "any-model", "local-model", "no-model"] as const;

export type ConfidentialityLevelName = (typeof CONFIDENTIALITY_LEVELS)[number];

/** Is `v` one of the four levels? The route uses this to REJECT an unknown
 *  level (400) rather than coerce it: a labeling act is explicit or it is not
 *  an act, and a coerced level is either a silent leak or a silent lockout. */
export function isConfidentialityLevel(v: unknown): v is ConfidentialityLevelName {
  return typeof v === "string" && (CONFIDENTIALITY_LEVELS as readonly string[]).includes(v);
}

// ── the wire shapes this view-model projects (see arbiter/ipc/protocol.ts) ────

/** One registered secret, as the arbiter reports it. NO value field, by design. */
export interface RegisteredSecretWire {
  path: string;
  symbol: string;
  level: string;
  bindings: string[];
  fields?: number;
  /** Plan 10 §2.1: absent = NO reader list (the structured twin for every
   *  program); present, even empty, = a list exists and a program not on it
   *  gets `others`. */
  readers?: string[];
  /** Plan 13 D8 (2026-10-03): per `readers` entry, same order, the arbiter's
   *  word on whether it admits nothing (by name, path and a pin's hash).
   *  Absent from an older arbiter: the page judges the names. */
  readersAdmitNothing?: boolean[];
  /** Plan 13 D8 (12): per `readers` entry, its program reads the placeholder copy. */
  readersReadTwin?: boolean[];
  /** With `readers`: what a program NOT on the list gets. `deny` (§3.3's
   *  default) or `twin`. */
  others?: "deny" | "twin";
}

/** One user labeling act, as the arbiter reports it. */
export interface PathLabelWire {
  path: string;
  level: string;
  bindings: string[];
  recursive: boolean;
  /** `path` is a gitignore-style pattern (policy.yaml `paths:` only). */
  glob?: boolean;
  source: string;
  updatedAt: number;
  /** True ⇒ the label is WEAKER than the catalog's verdict for this path. */
  declassifies: boolean;
}

/** One DERIVED taint record (plan 9): a file a HIGH session wrote, labeled on
 *  disk at its watermark so a FUTURE session cannot read it back as public. */
export interface DerivedLabelWire {
  path: string;
  /** The watermark of the session that wrote it. */
  level: string;
  bindings: string[];
  /** WHICH session wrote it, and with what — §8 requires the release UI show what
   *  fed the artifact. */
  sessionKey: string;
  tool: string | null;
  updatedAt: number;
  /** The level a future session ACTUALLY classifies the path at (the catalog may
   *  be stricter; an exact user label may override the taint entirely). */
  effective: string;
  /** True ⇒ a user label is overriding this record — the §8 release act, and the
   *  human must be able to SEE that it took effect. */
  overridden: boolean;
}

export interface ConfidentialityStateWire {
  enabled: boolean;
  secrets: RegisteredSecretWire[];
  /** Optional: an arbiter build predating plan 6 has no labels op. */
  labels?: PathLabelWire[];
  /** Optional: an arbiter build predating plan 9 has no derived-label store. */
  derived?: DerivedLabelWire[];
  /** Optional (plan 10 §11.9): the programs that hold a secret. */
  taintedProcesses?: Array<{ procKey: string; app: string; path: string; level: string; session?: string | null; since: number }>;
}

/** Plan 10 §11.9: one program that read a secret raw. UNTRUSTED strings. */
export interface TaintedProcessRow {
  procKey: string;
  app: string;
  path: string;
  level: string;
  levelLabel: string;
  session: string;
  /** ISO time the raw open was granted. */
  since: string;
}

// ── the projected panel ───────────────────────────────────────────────────────

/** CSS/semantic class for a level. `unknown` covers a level string this build
 *  does not know — shown verbatim and treated as NOT model-ok and NOT public. */
export type LevelClass = "public" | "model-ok" | "local-only" | "strict" | "unknown";

export interface SecretRow {
  /** Absolute path of the confined file. UNTRUSTED string — the shell must
   *  insert it with textContent (a path can be attacker-influenced). */
  path: string;
  /** The symbol standing for its contents (never the contents). */
  symbol: string;
  /** The raw level string, verbatim (an unknown level is shown, not hidden). */
  level: string;
  levelClass: LevelClass;
  /** Short human form: "strict" | "local-only" | "model-ok" | "public" | the raw string. */
  levelLabel: string;
  /** A standing grant of MODEL readability (§3.3) — enumerated explicitly. */
  modelOk: boolean;
  /** Bound destinations — each is a standing release rule (§2). */
  bindings: string[];
  /** Pre-rendered bindings cell ("—" when unbound: nowhere, not anywhere). */
  bindingsText: string;
  /** Plan 10 §2.4: how many values carry their own symbol (0 = whole file). */
  fields: number;
  /** Plan 10 §2.1: the programs that may open the raw file (the names on the
   *  list; empty when there is no list OR the list is empty: `readersListed`
   *  tells the two apart). */
  readers: string[];
  /** A reader list EXISTS for this file (§3.3: a program not on it is then
   *  refused, or handed the twin when `others` says so). False = no list:
   *  every program reads the structured twin. */
  readersListed: boolean;
  /** With a list: what a program not on it gets. */
  others: "deny" | "twin";
  /** Pre-rendered readers cell: "twin for every program" (no list), the
   *  names plus what others get, or "none: every program is refused" (an
   *  empty list; before 2026-09-24 this read as the twin for everyone, the
   *  opposite of §3.3). */
  readersText: string;
}

export interface LabelRow {
  path: string;
  level: string;
  levelClass: LevelClass;
  levelLabel: string;
  modelOk: boolean;
  bindings: string[];
  bindingsText: string;
  recursive: boolean;
  /** "subtree" (recursive) | "exact" (this path only). */
  scope: "subtree" | "exact";
  /** A "subtree" label whose path is a file on disk (server/path-kinds.ts):
   *  the product page words it as that one file (dashboard.md §4.25f *A rule
   *  on a file reads as a file*). Absent otherwise. */
  pathIsFile?: true;
  /** `path` is a gitignore-style PATTERN from policy.yaml (confidentiality.md
   *  §6.1), not one path: it is edited in the file, never removed from here. */
  pattern: boolean;
  /** "user" | "import" (stored by the protection service) | "policy-file"
   *  (written in policy.yaml: the inspector's Remove does not change it). */
  source: string;
  updatedAt: number;
  /** WEAKER than the catalog's verdict ⇒ a standing declassification (§6). */
  declassifies: boolean;
  /** The rendered warning for a declassification; null otherwise. */
  note: string | null;
}

/** One derived taint record, projected. The row a human ACTS on when they
 *  release a derived artifact (§8: "declassification must be first-class …
 *  with provenance shown: what secret(s) went into it"). */
export interface DerivedRow {
  path: string;
  level: string;
  levelClass: LevelClass;
  levelLabel: string;
  modelOk: boolean;
  bindings: string[];
  bindingsText: string;
  /** The session that wrote the file, and the tool it used — the provenance line. */
  sessionKey: string;
  tool: string;
  updatedAt: number;
  /** What a future session actually sees (may exceed `level` — the catalog — or
   *  fall below it — a user label released it). */
  effective: string;
  effectiveClass: LevelClass;
  /** True ⇒ a user label overrides this record: the release took effect. */
  overridden: boolean;
  /** The rendered provenance/override line. */
  note: string;
}

export interface SecretsSummary {
  /** Registered secrets — how many files are confined. */
  confined: number;
  /** Of those, how many are strict (no model read). */
  strict: number;
  /** Standing grants of model readability — secrets AND labels at model-ok. */
  modelOk: number;
  /** Every model-ok path, enumerated (§6 requires the surface be listed). */
  modelOkPaths: string[];
  /** User labels in the store. */
  labels: number;
  /** Labels weaker than the catalog's verdict — standing declassifications. */
  declassifications: number;
  /** Standing release rules: every (path, destination) binding pair. */
  bindings: number;
  /** Files a HIGH session wrote, labeled on disk (plan 9) — the watermark
   *  outliving the session that made it. */
  derivedFiles: number;
  /** The one-line coverage statement rendered above the tables. */
  text: string;
}

export interface SecretsPanel {
  /** The axis kill switch (§11). */
  enabled: boolean;
  /** "off" — the axis is disabled (NOT "nothing confined");
   *  "empty" — on, but nothing confined and nothing labeled;
   *  "active" — on, with a surface to show. */
  status: "off" | "empty" | "active";
  statusText: string;
  secrets: SecretRow[];
  labels: LabelRow[];
  /** The DERIVED surface (plan 9) — kept apart from `labels` on purpose: those are
   *  human decisions, these are machine taint records. Rendering a machine taint
   *  as a human label would put words in the human's mouth, and §6's whole point
   *  is that this surface is a legible record of what the human decided. */
  derived: DerivedRow[];
  /** Plan 10 §11.9: programs holding a secret, newest first. */
  tainted: TaintedProcessRow[];
  summary: SecretsSummary;
}

const OFF_TEXT =
  "confidentiality axis OFF — nothing is confined and no label is consulted " +
  "(labels may be stored; they take effect only when the axis is on)";

const EMPTY_TEXT = "axis ON — no secret registered yet and no path labeled";

export function levelClassOf(level: string): LevelClass {
  switch (level) {
    case "public":
      return "public";
    case "any-model":
      return "model-ok";
    case "local-model":
      // Plan 11 D1: readable only by a declared local model. NOT a model-ok
      // grant (an outside model may not read it), so it is not counted in
      // summary.modelOkPaths.
      return "local-only";
    case "no-model":
      return "strict";
    default:
      // An unknown level is NOT quietly treated as public. It renders verbatim
      // and counts as neither a model-ok grant nor a public release.
      return "unknown";
  }
}

function levelLabelOf(level: string): string {
  const cls = levelClassOf(level);
  return cls === "unknown" ? level : cls;
}

function bindingsOf(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter((b): b is string => typeof b === "string" && b !== "");
}

function bindingsTextOf(bindings: string[]): string {
  // "—" = bound NOWHERE (the datum may leave to no destination without a human
  // decision). It must never read as "anywhere".
  return bindings.length === 0 ? "—" : bindings.join(", ");
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** Project one registered secret. Fields are copied EXPLICITLY — never spread —
 *  so no `value`-shaped field on the input can reach the panel (invariant 1). */
function toSecretRow(s: RegisteredSecretWire): SecretRow {
  const level = typeof s.level === "string" ? s.level : "";
  const bindings = bindingsOf(s.bindings);
  const readersListed = Array.isArray(s.readers);
  // Plan 13 §8 decision (b): a bare shell or interpreter admits nothing.
  // Plan 13 D8 (2026-10-03): the arbiter's word per entry when it gave one
  // (a pin by a renamed copy's hash, a script pin), else the names.
  const judged = Array.isArray(s.readersAdmitNothing) ? { admitNothing: s.readersAdmitNothing } : undefined;
  // Plan 13 D8 (12): the arbiter's word that an entry's program reads the
  // placeholder copy (the panel's names carry no `prints:`, so only the
  // arbiter can say).
  const twin = (i: number): boolean => Array.isArray(s.readersReadTwin) && s.readersReadTwin[i] === true;
  const readerNames = readersListed ? s.readers!.flatMap((r, i) => (typeof r !== "string" ? [] : [judgedAdmitsNothing(r, i, judged) ? `${r}${ADMITS_NOTHING}` : twin(i) ? `${r}${READS_PLACEHOLDER}` : r])) : [];
  const others: "deny" | "twin" = s.others === "twin" ? "twin" : "deny";
  return {
    path: String(s.path ?? ""),
    symbol: String(s.symbol ?? ""),
    level,
    levelClass: levelClassOf(level),
    levelLabel: levelLabelOf(level),
    modelOk: level === "any-model",
    bindings,
    bindingsText: bindingsTextOf(bindings),
    fields: typeof s.fields === "number" && s.fields > 0 ? s.fields : 0,
    readers: readerNames,
    readersListed,
    others,
    readersText: readersTextOf(readersListed, readerNames, others),
  };
}

/** The readers cell (§2.1 / §3.3). A list that exists is exhaustive: the
 *  names may open the raw file and everyone else is refused (or handed the
 *  twin when the label says `others: twin`); no list at all is the baseline,
 *  the structured twin for every program. */
export function readersTextOf(listed: boolean, names: string[], others: "deny" | "twin"): string {
  if (!listed) return "twin for every program";
  const rest = others === "twin" ? "every other program gets the twin" : "every other program is refused";
  if (names.length === 0) return others === "twin" ? "none listed: every program gets the twin" : "none: every program is refused (the reader list is empty)";
  return `${names.join(", ")}; ${rest}`;
}

function toLabelRow(l: PathLabelWire, files: ReadonlySet<string>): LabelRow {
  const level = typeof l.level === "string" ? l.level : "";
  const bindings = bindingsOf(l.bindings);
  const declassifies = l.declassifies === true;
  const recursive = l.recursive !== false;
  const isFile = recursive && l.glob !== true && files.has(String(l.path ?? ""));
  return {
    path: String(l.path ?? ""),
    level,
    levelClass: levelClassOf(level),
    levelLabel: levelLabelOf(level),
    modelOk: level === "any-model",
    bindings,
    bindingsText: bindingsTextOf(bindings),
    recursive,
    scope: recursive ? "subtree" : "exact",
    ...(isFile ? { pathIsFile: true as const } : {}),
    pattern: l.glob === true,
    source: String(l.source ?? "user"),
    updatedAt: typeof l.updatedAt === "number" ? l.updatedAt : 0,
    declassifies,
    note: declassifies
      ? (l.glob === true
        ? "DECLASSIFIED — a public pattern: every file it matches may flow freely, including one the catalog calls a secret"
        : "DECLASSIFIED — weaker than the catalog's verdict: this path may now flow freely")
      : null,
  };
}

function toDerivedRow(d: DerivedLabelWire): DerivedRow {
  const level = typeof d.level === "string" ? d.level : "";
  const effective = typeof d.effective === "string" && d.effective !== "" ? d.effective : level;
  const bindings = bindingsOf(d.bindings);
  const overridden = d.overridden === true;
  const sessionKey = String(d.sessionKey ?? "");
  const tool = String(d.tool ?? "?");
  return {
    path: String(d.path ?? ""),
    level,
    levelClass: levelClassOf(level),
    levelLabel: levelLabelOf(level),
    modelOk: level === "any-model",
    bindings,
    bindingsText: bindingsTextOf(bindings),
    sessionKey,
    tool,
    updatedAt: typeof d.updatedAt === "number" ? d.updatedAt : 0,
    effective,
    effectiveClass: levelClassOf(effective),
    overridden,
    // The provenance line §8 asks for: what wrote this, and what a future session
    // will make of it. An overridden row must SAY it is overridden — a release the
    // human cannot see they made is not a release, it is a surprise.
    note: overridden
      ? `RELEASED — your label on this path overrides the taint: a future session reads it as ${levelLabelOf(effective)}`
      : `written by ${tool} in session ${sessionKey} while it held ${levelLabelOf(level)} content`,
  };
}

/**
 * Project the arbiter's `confidentialityState` into the Secrets panel.
 *
 * Pure: same input ⇒ same output, no I/O, no clock. The route calls it and
 * ships the result; the unit tests call it and assert the three invariants.
 * `files`: the label paths that are files on disk (server/path-kinds.ts).
 */
export function toSecretsPanel(state: ConfidentialityStateWire, files: ReadonlySet<string> = new Set()): SecretsPanel {
  const enabled = state.enabled === true;
  const secrets = (Array.isArray(state.secrets) ? state.secrets : []).map(toSecretRow);
  const labels = (Array.isArray(state.labels) ? state.labels : []).map((l) => toLabelRow(l, files));
  const derived = (Array.isArray(state.derived) ? state.derived : []).map(toDerivedRow);
  const tainted: TaintedProcessRow[] = (Array.isArray(state.taintedProcesses) ? state.taintedProcesses : []).map((t) => ({
    procKey: String(t.procKey ?? ""),
    app: String(t.app ?? ""),
    path: String(t.path ?? ""),
    level: String(t.level ?? ""),
    levelLabel: levelLabelOf(String(t.level ?? "")),
    session: String(t.session ?? ""),
    since: Number.isFinite(t.since) ? new Date(Number(t.since)).toISOString() : "",
  }));

  const modelOkPaths: string[] = [];
  for (const row of [...secrets, ...labels]) {
    if (row.modelOk && !modelOkPaths.includes(row.path)) modelOkPaths.push(row.path);
  }
  // A DERIVED model-ok file is a standing grant of model readability too — a
  // future session may read it into context. §6 requires every such path be
  // ENUMERATED, and "the machine put it there" is not an exemption. (An overridden
  // row is not a grant: the human's label decides what a future session sees.)
  for (const d of derived) {
    if (d.overridden) continue;
    if (d.effectiveClass === "model-ok" && !modelOkPaths.includes(d.path)) modelOkPaths.push(d.path);
  }

  const bindings =
    secrets.reduce((n, s) => n + s.bindings.length, 0) +
    labels.reduce((n, l) => n + l.bindings.length, 0);
  const declassifications = labels.filter((l) => l.declassifies).length;
  const strict = secrets.filter((s) => s.levelClass === "strict").length;

  const summary: SecretsSummary = {
    confined: secrets.length,
    strict,
    modelOk: modelOkPaths.length,
    modelOkPaths,
    labels: labels.length,
    declassifications,
    bindings,
    derivedFiles: derived.length,
    text: enabled
      ? [
          `${plural(secrets.length, "secret")} confined`,
          `${plural(modelOkPaths.length, "model-ok grant")}`,
          `${plural(declassifications, "declassification")}`,
          `${plural(bindings, "standing binding")}`,
          `${plural(derived.length, "derived file")}`,
        ].join(" · ")
      : OFF_TEXT,
  };

  const status: SecretsPanel["status"] = !enabled
    ? "off"
    : secrets.length === 0 && labels.length === 0 && derived.length === 0
      ? "empty"
      : "active";

  return {
    enabled,
    status,
    statusText: status === "off" ? OFF_TEXT : status === "empty" ? EMPTY_TEXT : summary.text,
    secrets,
    labels,
    derived,
    tainted,
    summary,
  };
}
