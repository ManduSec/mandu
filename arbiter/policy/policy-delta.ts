/**
 * policy-delta — is a change to the law a TIGHTENING or a RELAXATION?
 * (docs/design/ui/policy-surface.md §8.3).
 *
 * Mandu-new (no reference origin). This is the gate of the monotonic split:
 * any client may tighten the law; only a human may relax it. The confined
 * agent's edits reach the arbiter over the data socket, and whether they apply
 * at once or wait in the Inbox as a proposal is decided HERE, so this module
 * is on the security path.
 *
 * ── FAIL CLOSED, FACET BY FACET ─────────────────────────────────────────────
 * `policyDelta(before, after)` compares two COMPILED laws (lists expanded, so
 * editing a list that a release rule references is seen as the rule change it
 * is). Each facet contributes nothing when unchanged; a changed facet counts
 * as tightening only when it matches one of the PROVEN forms of §3.2; any
 * other change, including one this module does not understand, is a
 * relaxation. A document key this module does not know is a relaxation until
 * someone writes its proof.
 *
 * It is deliberately NOT `relaxationsOf(after) \ relaxationsOf(before)`: a set
 * difference calls "raise a lock to strict" a relaxation (the old restriction
 * disappears) and misses "extend an allow rule's expiry" (the same rule id).
 *
 * ── PATHS: PLAIN STRICT ONLY (§3.3) ─────────────────────────────────────────
 * A user label OVERRIDES the default-secret catalog and the most specific label
 * wins (path-labels.ts), so adding a lock can LOWER protection: a
 * `any-model` lock on `~/.ssh` declassifies the catalog's strict keys.
 * The catalog is runtime discovery, not law, so no comparison of two compiled
 * laws can see what a new label shadows. The only path edits accepted as
 * tightening are those that are tightening under EVERY catalog and DB-label
 * state: a PLAIN STRICT label (no-model, no bindings / readers / others /
 * extract), guarded against the one hazard inside the law itself (a label that
 * starts winning brings its own readers/extract/bindings; see overlapHazard).
 */
import { compareGuardSettings, GUARD_SETTINGS_KEYS } from "./guard-settings.js";
import { compilePathGlob } from "./path-glob.js";
import { BUILTIN_ORIGIN_DEFAULT } from "./policy-engine.js";
import { isPathPrefix, type PathLabel } from "./path-labels.js";
import { connectAllowSpecs, expandListsInDocument, hostMatches, type CompiledPolicy, type CompiledUserRule } from "./compiled-policy.js";
import type { ExecOutputSpec } from "./exec-inbound.js";
import type { PolicyFileConfig } from "./load-policy.js";
import { networksWithin } from "./model-perimeter.js";
import { effectiveLabelMapping, labelLevelRank, type LabelMappingEntry } from "./sensitivity-labels.js";
import { confidentialityRank, parseConfidentialityLevel } from "../symbol-table/confidentiality.js";
import { isActionSpec, isDataSpec, isKeySpec, type SchemaNode, type ToolSpec } from "./schema-types.js";
import { getAdminLayer } from "./admin-layer.js";
import { comparePromptFilters } from "../prompt-filter/policy.js";

export type DeltaFacet =
  | "law" // the comparison itself (boot spec, unknown document keys)
  | "paths"
  | "blob-lock"
  | "origins"
  | "command-output"
  | "tools"
  | "dispositions"
  | "user-rules"
  | "destinations"
  | "apps"
  | "env"
  | "models"
  | "perimeter"
  | "sensitivity-labels"
  | "prompt-filters";

export interface DeltaChange {
  facet: DeltaFacet;
  direction: "relax" | "tighten";
  /** What changed: a path, an origin, a rule id, a tool, a host spec. */
  subject: string;
  /** One plain sentence. */
  detail: string;
}

export interface PolicyDelta {
  relaxations: DeltaChange[];
  tightenings: DeltaChange[];
}

export interface PolicyDeltaOptions {
  /** Rules already expired at this instant are ignored on both sides. */
  now?: number;
}

/** No relaxation at all ⇒ the data plane may apply the change. */
export function isTightening(d: PolicyDelta): boolean {
  return d.relaxations.length === 0;
}

/** The top-level document keys this module has a proof for. `version` and
 *  `lists` have no effect of their own (list members are compared where they
 *  are referenced, expanded). */
const KNOWN_DOCUMENT_KEYS = new Set([
  "version", "lists", "paths", "blobs", "rules", "user_rules", "destinations", "apps", "env", "ssh_agent", "protect", "inbound", "tools", "models", "perimeter",
  "sensitivity_labels", "prompt_filters", "mapped_tools", "issuer_bindings",
]);

export function policyDelta(before: CompiledPolicy, after: CompiledPolicy, opts: PolicyDeltaOptions = {}): PolicyDelta {
  const out: PolicyDelta = { relaxations: [], tightenings: [] };
  const add = (c: DeltaChange): void => {
    (c.direction === "relax" ? out.relaxations : out.tightenings).push(c);
  };
  const relax = (facet: DeltaFacet, subject: string, detail: string): void => add({ facet, direction: "relax", subject, detail });
  const tighten = (facet: DeltaFacet, subject: string, detail: string): void => add({ facet, direction: "tighten", subject, detail });

  if (before.specId !== after.specId) {
    relax("law", "specId", `the two laws were compiled for different agents (${before.specId} vs ${after.specId}); they cannot be compared`);
    return out;
  }
  for (const k of Object.keys(after.document ?? {})) {
    if (!KNOWN_DOCUMENT_KEYS.has(k) && !GUARD_SETTINGS_KEYS.includes(k)) relax("law", k, `the document key '${k}' has no tightening proof, so any change under it counts as a relaxation`);
  }

  comparePaths(before, after, relax, tighten);
  compareBlobLocks(before, after, relax, tighten);
  compareOrigins(before.document, after.document, relax, tighten);
  compareCommandOutput(before.execIndex, after.execIndex, relax, tighten);
  compareTools(before, after, relax, tighten);
  // Plan 10 §11.18: a tool listed under `mapped_tools:` reaches the model
  // unmasked though Mandu has no mapping for it; listing one relaxes.
  for (const t of after.mappedTools) if (!before.mappedTools.includes(t)) relax("law", `mapped_tools:${t}`, `${t} is no longer masked whole for having no mapping`);
  for (const t of before.mappedTools) if (!after.mappedTools.includes(t)) tighten("law", `mapped_tools:${t}`, `${t} is masked whole again (Mandu has no mapping for it)`);
  compareIssuerBindings(before, after, relax, tighten);
  compareDispositions(before.dispositions, after.dispositions, relax, tighten);
  compareUserRules(before.userRules, after.userRules, opts.now ?? Date.now(), relax, tighten);
  compareDestinations(before, after, relax, tighten);
  compareApps(before, after, relax, tighten);
  compareEnv(before, after, relax, tighten);
  compareModels(before, after, relax);
  comparePerimeter(before, after, relax, tighten);
  compareSensitivityLabels(before.document, after.document, relax, tighten);
  comparePromptFilterSwitches(before.document, after.document, relax, tighten);
  return out;
}

type Emit = (facet: DeltaFacet, subject: string, detail: string) => void;

// ── paths ────────────────────────────────────────────────────────────────────

const RANK = (l: string): number => confidentialityRank(parseConfidentialityLevel(l));

function hasExtras(l: PathLabel): boolean {
  return l.bindings.length > 0 || l.readers !== undefined || l.others !== undefined || l.extract !== undefined || (l.values?.length ?? 0) > 0;
}

/** Plan 13 §5.2: the two labels' `values:` are the same rules (by key, each
 *  with the same bindings; order is not meaning). */
function sameValues(a: PathLabel, b: PathLabel): boolean {
  const key = (l: PathLabel): string => JSON.stringify([...(l.values ?? [])].map((v) => [v.key, [...v.bindings].sort()]).sort((x, y) => (x[0]! < y[0]! ? -1 : x[0]! > y[0]! ? 1 : 0)));
  return key(a) === key(b);
}

/** Plan 13 §5.2, the proven form: the same `values:` keys, each entry's
 *  bindings a subset of what it had. Adding a key, removing one (its values
 *  fall back to the file's bindings, which may be wider) or adding a binding
 *  to one is not this form. */
function valuesOnlyShrank(before: PathLabel, after: PathLabel): boolean {
  const b = new Map((before.values ?? []).map((v) => [v.key, v.bindings]));
  const a = after.values ?? [];
  if (a.length !== b.size) return false;
  return a.every((v) => {
    const was = b.get(v.key);
    return was !== undefined && v.bindings.every((x) => was.includes(x));
  });
}

/** The bindings `after`'s values lost against `before`'s, as `KEY: host`. */
function valueBindingsDropped(before: PathLabel, after: PathLabel): string[] {
  const a = new Map((after.values ?? []).map((v) => [v.key, v.bindings]));
  return (before.values ?? []).flatMap((v) => v.bindings.filter((x) => !(a.get(v.key) ?? []).includes(x)).map((x) => `${v.key}: ${x}`));
}

function isPlainStrict(l: PathLabel): boolean {
  return l.confidentiality === "no-model" && !hasExtras(l);
}

/** The label's leading literal segments ("" for a pattern that leads with `**`). */
function literalPrefixOf(l: PathLabel): string {
  if (!l.glob) return l.path;
  const r = compilePathGlob(l.path);
  return "glob" in r ? r.glob.literalPrefix : "";
}

function mayOverlap(a: PathLabel, b: PathLabel): boolean {
  const pa = literalPrefixOf(a);
  const pb = literalPrefixOf(b);
  if (pa === "" || pb === "") return true;
  return isPathPrefix(pa, pb) || isPathPrefix(pb, pa);
}

/**
 * A label that starts winning where another used to win brings its own
 * readers / others / extract / bindings with it, and the loser's may have been
 * stricter (`readers: [aws], others: deny` on `~/.aws`, shadowed by a new label
 * on `~/.aws/credentials`, turns "everyone else denied" into "everyone else gets
 * the twin"). Conservative: any other label, in either law, whose literal prefix
 * is a segment-prefix of this one's (or the reverse) and that carries any of
 * those fields is a hazard.
 */
function overlapHazard(key: string, label: PathLabel, laws: readonly ReadonlyMap<string, PathLabel>[]): PathLabel | null {
  for (const law of laws) {
    for (const [k, other] of law) {
      if (k === key || !hasExtras(other)) continue;
      if (mayOverlap(label, other)) return other;
    }
  }
  return null;
}

function sameList(a: readonly unknown[] | undefined, b: readonly unknown[] | undefined): boolean {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

function sameLabel(a: PathLabel, b: PathLabel): boolean {
  return (
    a.confidentiality === b.confidentiality &&
    a.recursive === b.recursive &&
    sameList([...a.bindings].sort(), [...b.bindings].sort()) &&
    sameList(a.readers, b.readers) &&
    a.others === b.others &&
    a.extract === b.extract &&
    sameValues(a, b)
  );
}

function describeLabel(l: PathLabel): string {
  const extras = [
    l.bindings.length ? `bindings ${l.bindings.join(", ")}` : "",
    l.readers ? "readers" : "",
    l.others ? `others: ${l.others}` : "",
    l.extract ? "extract" : "",
    l.values?.length ? `values ${l.values.map((v) => `${v.key} → ${v.bindings.join(", ") || "nowhere"}`).join("; ")}` : "",
  ].filter(Boolean);
  return `${l.confidentiality}${l.recursive ? "" : " (not recursive)"}${extras.length ? ` with ${extras.join(", ")}` : ""}`;
}

type ReaderList = PathLabel["readers"];
const OUTPUT_RANK: Record<string, number> = { clear: 0, mask: 1, secret: 2 };

/**
 * Plan 13 D3: when two reader lists name the same readers in the same order
 * (app, path, sha256, from, script, scriptSha256) and differ only in `output` / `mask`, which
 * entries' rule rose (toward `clear`: a relaxation) and which fell (toward
 * `secret`, or a mask that keeps every span it masked and adds some).
 * Null when the lists differ in anything else (not this proven form).
 */
function readerOutputDelta(before: ReaderList, after: ReaderList): { raised: Array<{ app: string; output: string }>; lowered: string[] } | null {
  if (before === undefined || after === undefined || before.length !== after.length) return null;
  const raised: Array<{ app: string; output: string }> = [];
  const lowered: string[] = [];
  for (let i = 0; i < before.length; i++) {
    const b = typeof before[i] === "string" ? { app: before[i] as string } : (before[i] as Exclude<NonNullable<ReaderList>[number], string>);
    const a = typeof after[i] === "string" ? { app: after[i] as string } : (after[i] as Exclude<NonNullable<ReaderList>[number], string>);
    // Plan 13 R5: the script and its hash are part of who the reader is.
    const ident = (p: typeof b) => JSON.stringify([p.app, p.path ?? null, p.sha256 ?? null, p.from ?? null, "script" in p ? p.script ?? null : null, "scriptSha256" in p ? p.scriptSha256 ?? null : null, "prints" in p ? p.prints ?? null : null]);
    if (ident(a) !== ident(b)) return null;
    const bo = "output" in b && b.output ? b.output : "secret";
    const ao = "output" in a && a.output ? a.output : "secret";
    const bm = "mask" in b && b.mask ? b.mask : [];
    const am = "mask" in a && a.mask ? a.mask : [];
    if (OUTPUT_RANK[ao]! < OUTPUT_RANK[bo]!) raised.push({ app: a.app, output: ao });
    else if (OUTPUT_RANK[ao]! > OUTPUT_RANK[bo]!) lowered.push(a.app);
    else if (ao === "mask") {
      if (!bm.every((m) => am.includes(m))) raised.push({ app: a.app, output: ao });
      else if (am.length > bm.length) lowered.push(a.app);
    }
  }
  return { raised, lowered };
}

function comparePaths(before: CompiledPolicy, after: CompiledPolicy, relax: Emit, tighten: Emit): void {
  const b = before.pathLabels;
  const a = after.pathLabels;
  const laws = [b, a];
  for (const [key, bl] of b) {
    if (!a.has(key)) relax("paths", bl.path, `the lock on ${bl.path} (${describeLabel(bl)}) is removed; the catalog or a broader label decides there again`);
  }
  for (const [key, al] of a) {
    const bl = b.get(key);
    if (bl === undefined) {
      if (!isPlainStrict(al)) {
        relax("paths", al.path, al.confidentiality === "no-model"
          ? `a new lock on ${al.path} carries ${describeLabel(al)}; only a plain strict lock (no bindings, values, readers, others or extract) is provably tighter`
          : `a new ${al.confidentiality} lock on ${al.path} overrides the secret catalog below it, so it can lower protection there`);
        continue;
      }
      const hazard = overlapHazard(key, al, laws);
      if (hazard) {
        relax("paths", al.path, `a new strict lock on ${al.path} may take over from ${hazard.path}, whose ${describeLabel(hazard)} would stop applying there`);
        continue;
      }
      tighten("paths", al.path, `${al.path} is locked at no-model`);
      continue;
    }
    if (sameLabel(al, bl)) continue;
    // (o) Plan 13 D3: only the output rules on the reader entries changed
    // (the same readers, in the same order, with everything else equal). A
    // rule lowered toward `secret` (or a mask that masks more) only hides
    // more from the model; one raised toward `clear` relaxes.
    const outputs = readerOutputDelta(bl.readers, al.readers);
    if (outputs !== null &&
      al.confidentiality === bl.confidentiality && al.recursive === bl.recursive &&
      sameList([...al.bindings].sort(), [...bl.bindings].sort()) && al.others === bl.others && al.extract === bl.extract && sameValues(al, bl)) {
      if (outputs.raised.length > 0) {
        for (const r of outputs.raised) relax("paths", al.path, `${r.app}'s output after it reads ${al.path} becomes ${r.output}${r.output === "mask" ? " (only the listed spans masked)" : " for the model"}`);
      } else if (outputs.lowered.length > 0) {
        tighten("paths", al.path, `${al.path}: a reader's output is masked more (${outputs.lowered.join(", ")})`);
      }
      continue;
    }
    // (i) only bindings shrank: fewer standing releases, the same winner
    // everywhere. The file's own bindings and each `values:` entry's (plan
    // 13 §5.2, the same keys): a value with no entry takes the file's, so a
    // smaller file list narrows those too.
    const onlyBindingsShrank =
      al.confidentiality === bl.confidentiality &&
      al.recursive === bl.recursive &&
      sameList(al.readers, bl.readers) && al.others === bl.others && al.extract === bl.extract &&
      al.bindings.every((x) => bl.bindings.includes(x)) &&
      valuesOnlyShrank(bl, al);
    if (onlyBindingsShrank) {
      const dropped = [...bl.bindings.filter((x) => !al.bindings.includes(x)), ...valueBindingsDropped(bl, al)];
      tighten("paths", al.path, `${al.path} is no longer released to ${dropped.join(", ")}`);
      continue;
    }
    // (ii) the label becomes plain strict, it had no readers/others/extract to
    // lose, it covers no less than before, and nothing it may overtake carries extras.
    // Dropping `values:` here is no loss: every value then goes where the
    // file does, nowhere (plan 13 §5.2).
    const becomesPlainStrict =
      isPlainStrict(al) &&
      bl.readers === undefined && bl.others === undefined && bl.extract === undefined &&
      !(bl.recursive && !al.recursive);
    if (becomesPlainStrict) {
      const hazard = overlapHazard(key, al, laws);
      if (hazard) {
        relax("paths", al.path, `the lock on ${al.path} becomes strict and may take over from ${hazard.path}, whose ${describeLabel(hazard)} would stop applying there`);
      } else {
        tighten("paths", al.path, `${al.path}: ${describeLabel(bl)} → no-model`);
      }
      continue;
    }
    // Plan 13 §5.2: everything but `values:` the same, and some value may
    // now go somewhere new (a key or a binding added, a key removed so its
    // values take the file's bindings): name each widening.
    if (al.confidentiality === bl.confidentiality && al.recursive === bl.recursive &&
      sameList([...al.bindings].sort(), [...bl.bindings].sort()) &&
      sameList(al.readers, bl.readers) && al.others === bl.others && al.extract === bl.extract) {
      const was = new Map((bl.values ?? []).map((v) => [v.key, v.bindings]));
      const now = new Map((al.values ?? []).map((v) => [v.key, v.bindings]));
      const widened: string[] = [];
      for (const [k, b] of now) for (const x of b) if (!(was.get(k) ?? []).includes(x)) widened.push(`${k} in ${al.path} is bound to ${x} on its own`);
      for (const k of was.keys()) if (!now.has(k)) widened.push(`${k} in ${al.path} now goes where the file may (${al.bindings.join(", ") || "nowhere without an ask"}), no longer only where its own entry said`);
      if (widened.length > 0) {
        for (const w of widened) relax("paths", al.path, w);
        continue;
      }
    }
    const lowered = RANK(al.confidentiality) < RANK(bl.confidentiality);
    relax("paths", al.path, lowered
      ? `${al.path} is lowered from ${bl.confidentiality} to ${al.confidentiality}`
      : `${al.path} changes from ${describeLabel(bl)} to ${describeLabel(al)}, which is not a proven tightening`);
  }
}

// ── blob locks (plan 14 §8.2) ────────────────────────────────────────────────
//
// A blob lock names ONE object by its content hash; the launcher's object
// twins hide it at any level above `public`, and a `public` lock hides
// nothing. It never overrides a path label (the twins hide the union of what
// path labels and blob locks name), so unlike a path lock it cannot shadow a
// stricter rule: adding one above `public`, or raising one, is a tightening
// under every state. Everything else is a relaxation, human only: removing a
// lock, adding one at `public` (a declaration that the object is not secret),
// lowering a level. The note is words only and changes nothing.
function compareBlobLocks(before: CompiledPolicy, after: CompiledPolicy, relax: Emit, tighten: Emit): void {
  const b = before.blobLocks;
  const a = after.blobLocks;
  for (const [id, bl] of b) {
    if (!a.has(id)) relax("blob-lock", id, `the lock on the repository object ${id} (${bl.level}) is removed: the agent may read it again unless a path label covers it`);
  }
  for (const [id, al] of a) {
    const bl = b.get(id);
    if (bl === undefined) {
      if (al.level === "public") relax("blob-lock", id, `the repository object ${id} is labeled public`);
      else tighten("blob-lock", id, `the repository object ${id} is locked at ${al.level}: hidden from the agent's repository reads`);
      continue;
    }
    if (al.level === bl.level) continue;
    if (RANK(al.level) > RANK(bl.level)) tighten("blob-lock", id, `the repository object ${id} is raised from ${bl.level} to ${al.level}`);
    else relax("blob-lock", id, `the repository object ${id} is lowered from ${bl.level} to ${al.level}`);
  }
}

// ── origins (inbound url / channel / dir, legacy *-trust) ────────────────────

function strSet(v: readonly string[] | undefined): Set<string> {
  return new Set((v ?? []).map((s) => s.trim()));
}

function compareOrigins(beforeDoc: PolicyFileConfig | null, afterDoc: PolicyFileConfig | null, relax: Emit, tighten: Emit): void {
  const b = expandListsInDocument(beforeDoc)?.inbound ?? {};
  const a = expandListsInDocument(afterDoc)?.inbound ?? {};
  const allowish = (label: string, bv: readonly string[] | undefined, av: readonly string[] | undefined): void => {
    const bs = strSet(bv);
    const as = strSet(av);
    for (const v of as) if (!bs.has(v)) relax("origins", `${label}:${v}`, `${label} origin ${v} becomes trusted: its data reaches the model unmasked`);
    for (const v of bs) if (!as.has(v)) tighten("origins", `${label}:${v}`, `${label} origin ${v} is no longer trusted`);
  };
  const denyish = (label: string, bv: readonly string[] | undefined, av: readonly string[] | undefined): void => {
    const bs = strSet(bv);
    const as = strSet(av);
    for (const v of bs) if (!as.has(v)) relax("origins", `${label}:${v}`, `${label} origin ${v} is no longer on the untrusted list`);
    for (const v of as) if (!bs.has(v)) tighten("origins", `${label}:${v}`, `${label} origin ${v} is marked untrusted`);
  };
  for (const cat of ["url", "channel", "dir"] as const) {
    const label = cat.toUpperCase();
    allowish(label, b[cat]?.trustedList, a[cat]?.trustedList);
    denyish(label, b[cat]?.untrustedList, a[cat]?.untrustedList);
    // EFFECTIVE defaults (an absent `default` is the category's built-in one,
    // the engine's rule), so creating a section never hides a mode flip.
    const bd = b[cat]?.default ?? BUILTIN_ORIGIN_DEFAULT[cat];
    const ad = a[cat]?.default ?? BUILTIN_ORIGIN_DEFAULT[cat];
    if (bd !== ad) {
      if (ad === "UNTRUSTED") tighten("origins", `${label}:default`, `unlisted ${label} origins default to UNTRUSTED`);
      else relax("origins", `${label}:default`, `unlisted ${label} origins become TRUSTED by default: their data reaches the model unmasked`);
    }
  }
  allowish("URL", b["url-trust"]?.trustedUrls, a["url-trust"]?.trustedUrls);
  denyish("CHANNEL", b["channel-trust"]?.untrustedChannels, a["channel-trust"]?.untrustedChannels);
  denyish("DIR", b["dir-trust"]?.untrustedDirs, a["dir-trust"]?.untrustedDirs);
}

// ── grants: anything that lets data through unmasked ─────────────────────────

/** Every non-UNTRUSTED leaf of a schema, keyed by path and marker. */
function schemaGrants(node: SchemaNode | undefined, prefix: string, out: Set<string>): void {
  if (node === undefined || node === "UNTRUSTED") return;
  if (node === "TRUSTED") { out.add(`${prefix || "*"}=TRUSTED`); return; }
  if (isKeySpec(node)) { out.add(`${prefix || "*"}=key:${node.category}`); return; }
  if (isDataSpec(node)) { out.add(`${prefix || "*"}=data:${node.category}:${node.keyField}`); return; }
  if (typeof node !== "object" || node === null) { out.add(`${prefix || "*"}=?${JSON.stringify(node)}`); return; } // unknown marker: a grant, fail closed
  if ("__items" in node) { schemaGrants((node as { __items: SchemaNode }).__items, prefix ? `${prefix}[]` : "[]", out); return; }
  for (const [k, v] of Object.entries(node as Record<string, SchemaNode>)) schemaGrants(v, prefix ? `${prefix}.${k}` : k, out);
}

function execGrants(spec: ExecOutputSpec | undefined, prefix = "", out = new Set<string>()): Set<string> {
  if (!spec) return out;
  if (spec.trustErrors) out.add(`${prefix}trustErrors`);
  if (spec.trustHelp) out.add(`${prefix}trustHelp`);
  schemaGrants(spec.schema, `${prefix}schema`, out);
  for (const f of (spec as { allowedFlags?: readonly string[] }).allowedFlags ?? []) out.add(`${prefix}flag:${f}`);
  for (const [sub, s] of Object.entries(spec.subcommands ?? {})) execGrants(s, `${prefix}sub ${sub}:`, out);
  return out;
}

function toolGrants(spec: ToolSpec | undefined): Set<string> {
  const out = new Set<string>();
  if (!spec) return out;
  if (isActionSpec(spec)) {
    for (const [action, schema] of Object.entries(spec.schemas)) schemaGrants(schema, `[${action}]`, out);
    schemaGrants(spec.defaultSchema, "[default]", out);
    return out;
  }
  schemaGrants(spec.schema, "", out);
  if (spec.wholeResult !== undefined) schemaGrants(spec.wholeResult, "(whole result)", out);
  return out;
}

function subset(a: Set<string>, b: Set<string>): string[] {
  return [...a].filter((x) => !b.has(x));
}

// ── command output (the exec-output trust index) ─────────────────────────────

function compareCommandOutput(
  b: Readonly<Record<string, ExecOutputSpec>>,
  a: Readonly<Record<string, ExecOutputSpec>>,
  relax: Emit,
  tighten: Emit,
): void {
  for (const key of new Set([...Object.keys(b), ...Object.keys(a)])) {
    const bs = b[key];
    const as = a[key];
    if (bs === as) continue;
    if (as === undefined) { tighten("command-output", key, `${key}'s output is no longer trusted in any part`); continue; }
    const bg = execGrants(bs);
    const ag = execGrants(as);
    const bSubs = Object.keys(bs?.subcommands ?? {}).sort().join("\n");
    const aSubs = Object.keys(as.subcommands ?? {}).sort().join("\n");
    const extra = subset(ag, bg);
    if (extra.length > 0) {
      relax("command-output", key, `${key} gains trust: ${extra.join(", ")}`);
    } else if (bs !== undefined && bSubs !== aSubs && ag.size > 0) {
      relax("command-output", key, `${key}'s subcommand set changes, which moves which output each command line matches`);
    } else if (subset(bg, ag).length > 0) {
      tighten("command-output", key, `${key} loses trust: ${subset(bg, ag).join(", ")}`);
    }
  }
}

// ── tools (the boot spec's inbound / resolve / field tables) ─────────────────

function compareTools(before: CompiledPolicy, after: CompiledPolicy, relax: Emit, tighten: Emit): void {
  const id = after.specId;
  const bi = before.inbound[id];
  const ai = after.inbound[id];
  for (const tool of new Set([...Object.keys(bi), ...Object.keys(ai)])) {
    const bs = bi[tool];
    const as = ai[tool];
    if (bs === as || JSON.stringify(bs) === JSON.stringify(as)) continue;
    if (as === undefined) { tighten("tools", tool, `${tool}'s result falls to the UNTRUSTED default`); continue; }
    const shape = (s: ToolSpec | undefined): string =>
      JSON.stringify({ paramsKeys: s?.paramsKeys ?? null, actionField: s && isActionSpec(s) ? s.actionField : null });
    const extra = subset(toolGrants(as), toolGrants(bs));
    if (extra.length > 0) relax("tools", tool, `${tool} results gain trust: ${extra.join(", ")}`);
    else if (shape(as) !== shape(bs)) relax("tools", tool, `${tool}'s spec changes shape (params keys or action dispatch), which the proof does not cover`);
    else tighten("tools", tool, `${tool} results lose trust: ${subset(toolGrants(bs), toolGrants(as)).join(", ") || "(shape only)"}`);
  }
  const br = before.outboundResolve[id];
  const ar = after.outboundResolve[id];
  for (const tool of new Set([...Object.keys(br), ...Object.keys(ar)])) {
    if (ar[tool] === true && br[tool] !== true) relax("tools", `${tool}:resolve`, `${tool} may desymbolize (send originals)`);
    else if (br[tool] === true && ar[tool] !== true) tighten("tools", `${tool}:resolve`, `${tool} no longer desymbolizes`);
  }
  const bf = before.outboundFieldPolicy[id];
  const af = after.outboundFieldPolicy[id];
  for (const tool of new Set([...Object.keys(bf), ...Object.keys(af)])) {
    const bfields = bf[tool] ?? {};
    const afields = af[tool] ?? {};
    for (const field of new Set([...Object.keys(bfields), ...Object.keys(afields)])) {
      const bv = bfields[field];
      const av = afields[field];
      if (bv === av) continue;
      if (av === "not_resolve") tighten("tools", `${tool}.${field}`, `${tool}.${field} no longer resolves symbols`);
      else relax("tools", `${tool}.${field}`, `${tool}.${field} changes from ${bv ?? "unset"} to ${av ?? "unset"}`);
    }
  }
}

// ── dispositions ─────────────────────────────────────────────────────────────

function compareDispositions(
  b: Readonly<Record<string, "ask" | "block">>,
  a: Readonly<Record<string, "ask" | "block">>,
  relax: Emit,
  tighten: Emit,
): void {
  for (const id of new Set([...Object.keys(b), ...Object.keys(a)])) {
    const bm = b[id] ?? "ask";
    const am = a[id] ?? "ask";
    if (bm === am) continue;
    if (am === "block") tighten("dispositions", id, `${id} blocks without asking`);
    else relax("dispositions", id, `${id} asks again instead of blocking`);
  }
}

// ── user rules: coverage, not identity (§3.4) ────────────────────────────────

/** Does host pattern `p` match every host pattern `q` matches? (hostMatches semantics) */
export function hostPatternCovers(p: string, q: string): boolean {
  const pl = p.toLowerCase();
  const ql = q.toLowerCase();
  if (pl === "*") return true;
  if (ql === "*") return false;
  if (ql.startsWith("*.")) {
    if (!pl.startsWith("*.")) return false;
    const pb = pl.slice(2);
    const qb = ql.slice(2);
    return qb === pb || qb.endsWith("." + pb);
  }
  return hostMatches(pl, ql);
}

function hostsCover(big: readonly string[] | null, small: readonly string[] | null): boolean {
  if (big === null) return true; // any origin
  if (small === null) return false;
  return small.every((q) => big.some((p) => hostPatternCovers(p, q)));
}

/** Does `big` apply to every flow `small` applies to, for at least as long? */
function ruleCovers(big: CompiledUserRule, small: CompiledUserRule): boolean {
  if (!hostsCover(big.from, small.from) || !hostsCover(big.to, small.to)) return false;
  if (big.expiresAt === null) return true;
  return small.expiresAt !== null && small.expiresAt <= big.expiresAt;
}

function describeRule(r: CompiledUserRule): string {
  return `${r.id} (${r.mode} ${r.from === null ? "any origin" : r.from.join(", ")} → ${r.to.join(", ")}${r.expiresAt !== null ? `, until ${new Date(r.expiresAt).toISOString()}` : ""})`;
}

function compareUserRules(
  before: readonly CompiledUserRule[],
  after: readonly CompiledUserRule[],
  now: number,
  relax: Emit,
  tighten: Emit,
): void {
  const live = (rs: readonly CompiledUserRule[], mode: "allow" | "block"): CompiledUserRule[] =>
    rs.filter((r) => r.mode === mode && (r.expiresAt === null || now < r.expiresAt));
  const bAllow = live(before, "allow");
  const aAllow = live(after, "allow");
  const bBlock = live(before, "block");
  const aBlock = live(after, "block");
  for (const r of aAllow) {
    if (!bAllow.some((x) => ruleCovers(x, r))) relax("user-rules", r.id, `allow rule ${describeRule(r)} lets through flows no rule allowed before`);
  }
  for (const r of bBlock) {
    if (!aBlock.some((x) => ruleCovers(x, r))) relax("user-rules", r.id, `block rule ${describeRule(r)} no longer stops everything it stopped`);
  }
  for (const r of bAllow) {
    if (!aAllow.some((x) => ruleCovers(x, r))) tighten("user-rules", r.id, `allow rule ${describeRule(r)} is narrowed or retired`);
  }
  for (const r of aBlock) {
    if (!bBlock.some((x) => ruleCovers(x, r))) tighten("user-rules", r.id, `block rule ${describeRule(r)} stops more`);
  }
}

// ── destinations, apps, env ──────────────────────────────────────────────────

function compareDestinations(before: CompiledPolicy, after: CompiledPolicy, relax: Emit, tighten: Emit): void {
  const b = new Set(connectAllowSpecs(before));
  const a = new Set(connectAllowSpecs(after));
  for (const s of a) if (!b.has(s)) relax("destinations", s, `the agent's processes may connect to ${s}`);
  for (const s of b) if (!a.has(s)) tighten("destinations", s, `${s} is no longer an extra allowed destination`);
}

function compareApps(before: CompiledPolicy, after: CompiledPolicy, relax: Emit, tighten: Emit): void {
  for (const app of new Set([...before.apps.keys(), ...after.apps.keys()])) {
    const b = before.apps.get(app);
    const a = after.apps.get(app);
    if (JSON.stringify(a ?? null) === JSON.stringify(b ?? null)) continue;
    if (a === undefined || a.output === "secret") tighten("apps", app, `${app}'s output is treated as secret once it has read one`);
    // Deprecated (plan 13 D3): the rule clears nothing now, but a change
    // that would have relaxed still waits for the human (fail closed).
    else relax("apps", app, `${app}'s output becomes ${a.output}${a.output === "mask" ? " (only the listed spans masked)" : ""} once it has read a secret (a deprecated program-wide rule)`);
  }
}

function compareEnv(before: CompiledPolicy, after: CompiledPolicy, relax: Emit, tighten: Emit): void {
  const bs = new Set(before.envSecrets.secrets);
  const as = new Set(after.envSecrets.secrets);
  const be = new Set(before.envSecrets.exempt);
  const ae = new Set(after.envSecrets.exempt);
  for (const n of bs) if (!as.has(n)) relax("env", n, `environment variable ${n} is no longer masked as a secret`);
  for (const n of as) if (!bs.has(n)) tighten("env", n, `environment variable ${n} is masked as a secret`);
  for (const n of ae) if (!be.has(n)) relax("env", n, `environment variable ${n} reaches the agent in the clear`);
  for (const n of be) if (!ae.has(n)) tighten("env", n, `environment variable ${n} is no longer exempt from the mask`);
  const bsrc = new Map(before.envSources.map((e) => [e.name, e]));
  const asrc = new Map(after.envSources.map((e) => [e.name, e]));
  for (const [n, a] of asrc) {
    const b = bsrc.get(n);
    const added = a.bindings.filter((h) => !(b?.bindings ?? []).includes(h));
    const removed = (b?.bindings ?? []).filter((h) => !a.bindings.includes(h));
    if (b === undefined) tighten("env", n, `environment variable ${n} is filled from ${a.source.split(":")[0]} and masked as a secret`);
    if (added.length) relax("env", n, `environment variable ${n} may be sent to ${added.join(", ")} without an ask`);
    if (removed.length) tighten("env", n, `environment variable ${n} may no longer be sent to ${removed.join(", ")} without an ask`);
  }
  for (const [n, b] of bsrc) if (!asrc.has(n) && b.bindings.length) tighten("env", n, `environment variable ${n} is no longer sourced, and its bindings are gone`);
  const ba = before.sshAgentReaders, aa = after.sshAgentReaders;
  if (ba === null && aa !== null) tighten("env", "ssh_agent", "only the listed programs may use the ssh-agent");
  else if (ba !== null && aa === null) relax("env", "ssh_agent", "every program may use the ssh-agent again");
  else if (ba !== null && aa !== null && JSON.stringify(ba) !== JSON.stringify(aa)) relax("env", "ssh_agent", "the programs that may use the ssh-agent changed");
  for (const p of after.protect) if (!before.protect.includes(p)) tighten("env", p, `${p} may no longer be deleted or renamed`);
  for (const p of before.protect) if (!after.protect.includes(p)) relax("env", p, `${p} may be deleted or renamed again`);
  // unix_sockets:, write_protect: (guard-settings.ts; sandbox review 2026-09-28).
  compareGuardSettings(before.document, after.document, (s, d) => relax("env", s, d), (s, d) => tighten("env", s, d));
}

// ── models (plan 11 D2) ──────────────────────────────────────────────────────
//
// EVERY change to the declared models is a relaxation: there is no tightening
// form, so the data plane never applies one and a human decides each.
//   - adding or editing a `local: true` entry lets files labeled local-model be
//     sent to that address (inspect-mcp's routing, a local main model's rung 3);
//   - removing or editing ANY entry can leave a user-set ANTHROPIC_BASE_URL or
//     MANDU_OPENAI_BASE_URL undeclared, which makes the next launch skip the
//     model proxy (plan 11 §7.1, §8 row 2);
//   - adding an outside entry changes which base URLs keep the proxy, and a
//     later `local: true` edit of it is one field away.
// Compared on the COMPILED list (defaults applied), so a spelling that means
// the same (`wire: anthropic` written out or left to the default) is no change.

/** A compiled entry without the fields other sections derive onto it. */
function declaredModel(m: CompiledPolicy["models"][number]): Record<string, unknown> {
  const { perimeter: _p, orgDomain: _o, ...rest } = m;
  return rest;
}

function compareModels(before: CompiledPolicy, after: CompiledPolicy, relax: Emit): void {
  const b = new Map(before.models.map((m) => [m.name, m]));
  const a = new Map(after.models.map((m) => [m.name, m]));
  const where = (m: { url: string; local: boolean }): string => `${m.url} (${m.local ? "declared as your own model" : "an outside model"})`;
  // Plan 12 D2: the opt-out is said in the delta a human reads.
  const clear = (m: { allowPlainHttp?: true }): string => (m.allowPlainHttp ? " unencrypted (allow_plain_http)" : "");
  for (const [name, m] of a) {
    const was = b.get(name);
    if (was === undefined) {
      relax("models", name, m.local
        ? `model ${name} at ${m.url} is declared as your own model: files labeled local-model may be sent to it${clear(m)}`
        : `model ${name} at ${where(m)} is declared: it decides whether a main model set to that address keeps the model proxy`);
      continue;
    }
    // Everything but what is derived from other sections (`perimeter`,
    // `orgDomain`: the perimeter facet compares those), so a field added
    // later is compared without anyone listing it here (fail closed).
    if (JSON.stringify(declaredModel(was)) === JSON.stringify(declaredModel(m))) continue;
    const fields = (["url", "wire", "model", "local", "tokenEnv", "helper", "allowPlainHttp", "tls"] as const).filter((k) => JSON.stringify(was[k]) !== JSON.stringify(m[k]));
    if (fields.length === 0) fields.push("url"); // unreachable today; never an empty list in the words
    relax("models", name, `model ${name} changes (${fields.join(", ")}): now ${where(m)}${m.local ? `, and files labeled local-model may be sent there${clear(m)}` : ""}`);
  }
  for (const [name, m] of b) {
    if (!a.has(name)) relax("models", name, `model ${name} (${m.url}) is no longer declared: a main model set to that address would skip the model proxy`);
  }
}

// ── perimeter (plan 12 D4) ───────────────────────────────────────────────────
//
// `perimeter.networks` only ever refuses: a network model must resolve inside
// it. So dropping the list, or a network that is not inside the old list, is a
// relaxation; adding the list, or narrowing it, is a tightening. `domains`
// changes words only (doctor, the dashboard), never a decision.
function comparePerimeter(before: CompiledPolicy, after: CompiledPolicy, relax: Emit, tighten: Emit): void {
  const b = before.perimeter?.networks ?? null;
  const a = after.perimeter?.networks ?? null;
  if (b === null && a === null) return;
  if (a === null) {
    relax("perimeter", "networks", `perimeter.networks is removed: a model on another machine is no longer held to your organization's networks (${b!.join(", ")})`);
    return;
  }
  if (b === null) {
    tighten("perimeter", "networks", `perimeter.networks holds every model on another machine to ${a.join(", ")}`);
    return;
  }
  for (const n of a) {
    if (!networksWithin([n], b)) relax("perimeter", n, `perimeter.networks now admits ${n}: a local model there may receive local-model files`);
  }
  for (const n of b) {
    if (!networksWithin([n], a)) tighten("perimeter", n, `perimeter.networks no longer admits all of ${n}`);
  }
}

// ── prompt filters (confidentiality-plan-15 §6) ─────────────────────────────
//
// The person's `prompt_filters:` under the administrator's layer in force (the
// same on both sides). A filter turned on, a stronger action on any category
// either side names, `on_error: block`, a removed exception and
// `signed_only: false` tighten; the opposites, and anything the comparison
// cannot place, relax (prompt-filter/policy.ts comparePromptFilters).
function comparePromptFilterSwitches(beforeDoc: PolicyFileConfig | null, afterDoc: PolicyFileConfig | null, relax: Emit, tighten: Emit): void {
  for (const c of comparePromptFilters(beforeDoc?.prompt_filters, afterDoc?.prompt_filters, getAdminLayer().promptFilters ?? [])) {
    (c.direction === "relax" ? relax : tighten)("prompt-filters", c.subject, c.detail);
  }
}

// ── sensitivity labels (plan 14 §14.1) ───────────────────────────────────────
//
// The mapping changes what the scans SUGGEST (a labelled Office file becomes
// a lock-path suggestion a human reviews), never what is enforced. Lowering
// it withholds protection the way dismissing a suggestion does, so it follows
// the monotonic split: a new mapping above `public`, or a raised level, is a
// tightening; a removed mapping above `public`, a lowered level, and a new
// `public` mapping (it silences the label's "not mapped" count for good) are
// relaxations; so is a renamed entry (the name is what the review shows the
// person: fail closed). Removing a `public` mapping changes nothing: the
// label was suggesting nothing and still does. Compared per (id, site) on the
// user's document (the administrator's layer is not an edit's to change).
function compareSensitivityLabels(beforeDoc: PolicyFileConfig | null, afterDoc: PolicyFileConfig | null, relax: Emit, tighten: Emit): void {
  const index = (doc: PolicyFileConfig | null): Map<string, LabelMappingEntry> =>
    new Map(effectiveLabelMapping(doc?.sensitivity_labels ?? []).map((e) => [`${e.id}${e.site ? ` (site ${e.site})` : ""}`, e]));
  const b = index(beforeDoc);
  const a = index(afterDoc);
  for (const [k, al] of a) {
    const bl = b.get(k);
    if (bl === undefined) {
      if (al.level === "public") relax("sensitivity-labels", k, `the sensitivity label ${k} (${al.name}) is mapped to public: files carrying it are never suggested`);
      else tighten("sensitivity-labels", k, `the sensitivity label ${k} (${al.name}) is mapped to ${al.level}: files carrying it are suggested at that level`);
      continue;
    }
    const up = labelLevelRank(al.level) - labelLevelRank(bl.level);
    if (up > 0) tighten("sensitivity-labels", k, `the sensitivity label ${k} (${al.name}) is raised from ${bl.level} to ${al.level}`);
    else if (up < 0) relax("sensitivity-labels", k, `the sensitivity label ${k} (${al.name}) is lowered from ${bl.level} to ${al.level}`);
    if (al.name !== bl.name) relax("sensitivity-labels", k, `the sensitivity label ${k} is renamed from ${bl.name} to ${al.name} (the name the review shows)`);
  }
  for (const [k, bl] of b) {
    if (!a.has(k) && bl.level !== "public") relax("sensitivity-labels", k, `the sensitivity label ${k} (${bl.name}, ${bl.level}) is no longer mapped: files carrying it are no longer suggested`);
  }
}

/** confidentiality.md §2.3: `issuer_bindings:`. Turning it on, or taking an
 *  issuer or a value name off its off-lists, lets a key go to its issuer
 *  without asking (a relaxation); the reverse makes such a send ask. */
function compareIssuerBindings(
  before: CompiledPolicy, after: CompiledPolicy,
  relax: (f: DeltaFacet, s: string, d: string) => void, tighten: (f: DeltaFacet, s: string, d: string) => void,
): void {
  const b = before.issuerBindings;
  const a = after.issuerBindings;
  if (!b.enabled && a.enabled) relax("law", "issuer_bindings", "a key whose format names its issuer goes to that issuer's API host without asking");
  if (b.enabled && !a.enabled) tighten("law", "issuer_bindings", "every key asks before it goes to its issuer");
  if (!(b.enabled && a.enabled)) return;
  for (const id of b.issuersOff) if (!a.issuersOff.includes(id)) relax("law", `issuer_bindings.issuers_off:${id}`, `${id} keys go to ${id}'s API host without asking`);
  for (const id of a.issuersOff) if (!b.issuersOff.includes(id)) tighten("law", `issuer_bindings.issuers_off:${id}`, `${id} keys ask before they go to ${id}'s API host`);
  for (const n of b.valuesOff) if (!a.valuesOff.includes(n)) relax("law", `issuer_bindings.values_off:${n}`, `${n} goes to its issuer's API host without asking`);
  for (const n of a.valuesOff) if (!b.valuesOff.includes(n)) tighten("law", `issuer_bindings.values_off:${n}`, `${n} asks before it goes to its issuer's API host`);
}
