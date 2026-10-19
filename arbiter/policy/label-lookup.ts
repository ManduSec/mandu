/**
 * label-lookup — the ONE composition of the label stores (Plan 9, plan 12 D3),
 * shared by the arbiter's live lookup and the discovery worker's snapshot of it
 * (docs/design/architecture/runtime-instances.md §14.2 item 7).
 *
 *   a HUMAN label overrides the catalog in either direction (§6);
 *   a DERIVED label RAISES whatever that yields, and never lowers it (§8),
 *   except where an EXACT human label speaks about the artifact (the §8
 *   release act, which wins);
 *   a derived file whose sources are known is labelled BY REFERENCE to them
 *   (confidentiality plan 13 §4.6): its destinations are the intersection of
 *   its sources' as they stand now, its level at least theirs;
 *   a declared model client key is `no-model` unless a human label decides
 *   (plan 12 D3), never lowered by a machine-derived taint record;
 *   a SESSION label (session-path-labels.ts: an exact path a live session's
 *   proxy registered, e.g. OpenCode 2's background output file) makes the
 *   path `no-model`, bound nowhere, whatever every other store says.
 *
 * Pure: every input is passed in, so a worker thread holding a structured
 * clone of the maps answers exactly what the arbiter would at that instant.
 *
 * Mandu-new (no reference origin).
 */
import { isSecret, maxConfidentiality } from "../symbol-table/confidentiality.js";
import { resolveDerivedLabel, resolveWithDerived, type DerivedLabel } from "./derived-labels.js";
import { intersectBindings } from "./flow-taint.js";
import { holderFileBindings } from "./value-bindings.js";
import { homedir } from "os";
import { compiledGlobFor, normalizeLabelPath, resolvePathLabel, type LabelDecision, type PathLabel } from "./path-labels.js";
import { pathGlobMatches, type CompiledPathGlob } from "./path-glob.js";
import { pathConfidentiality, type LabelLookup, type LabelRoot } from "./secret-catalog.js";
import { DOCUMENT_TWIN_EXTRACT } from "./personal-documents.js";

/** The label stores at one instant: plain data, structured-clone safe. */
export interface LabelSnapshot {
  human: ReadonlyMap<string, PathLabel>;
  derived: ReadonlyMap<string, DerivedLabel>;
  /** The declared model client keys (`modelClientKeyPaths` of the law in force). */
  clientKeys: readonly string[];
  /** The live sessions' exact-path labels (session-path-labels.ts); absent
   *  in an older snapshot, which then knows none. */
  session?: ReadonlyMap<string, { path: string }>;
  /** The content tier's found labels (found-labels.ts): files the launch
   *  walk read and found a credential in, or found to be a personal
   *  document (`kind: "document"`, personal-documents.ts). Absent: none. */
  found?: ReadonlyMap<string, { path: string; kind?: string }>;
}

/** What the live lookup adds to a snapshot (not structured-clone data). */
export interface ComposeOptions {
  /** A source file's bindings beyond its label's: the secret registry's rows
   *  for that file (a field bound to its registry, plan 10 §11.13.1), as
   *  `taintedProcessBindings` counts them for a holder of the file. */
  sourceBindings?: (path: string) => readonly string[];
}

/** Plan 12 D3: a declared model client key is a `no-model` file, the way a
 *  catalog credential is. */
export function clientKeyLabel(p: string, clientKeys: readonly string[]): LabelDecision | null {
  const n = normalizeLabelPath(p) ?? p;
  return clientKeys.includes(n) ? { level: "no-model", bindings: [], via: n } : null;
}

export function composedLabel(p: string, s: LabelSnapshot, opts: ComposeOptions = {}): LabelDecision | null {
  return sessionLabel(p, s) ?? composeAt(p, s, opts, []);
}

/** A session label on exactly `p`: `no-model`, bound nowhere, composed over
 *  every other store (raise-only, and `no-model` is the strictest level, so
 *  nothing it overrides could have been stricter). A machine record: it
 *  never suppresses the catalog (which cannot be stricter either). */
export function sessionLabel(p: string, s: LabelSnapshot): LabelDecision | null {
  if (!s.session || s.session.size === 0) return null;
  const n = normalizeLabelPath(p) ?? p;
  const row = s.session.get(n);
  return row ? { level: "no-model", bindings: [], via: row.path, origin: "derived", overridesCatalog: false } : null;
}

/** How deep a copy of a copy is followed before it counts as bound nowhere
 *  (fail-closed). */
export const MAX_REFERENCE_DEPTH = 8;

function composeAt(p: string, s: LabelSnapshot, opts: ComposeOptions, visiting: readonly string[]): LabelDecision | null {
  const r = byReference(p, resolveWithDerived(p, s.human, s.derived), s, opts, visiting);
  // A human label decides; else a found label (the catalog's content tier,
  // found-labels.ts) where no human label covers the path at all (it
  // overrides the content tier as it overrides the catalog, an ancestor's
  // included); else a declared client key is no-model, never lowered by a
  // machine-derived taint record. A found label is `no-model` and bound
  // nowhere: a derived row or a client key adds nothing over it.
  if (r && r.origin !== "derived") return withDocumentTwin(r, p, s);
  const f = foundLabel(p, s);
  if (f !== null && resolvePathLabel(p, s.human) === null) return f;
  return clientKeyLabel(p, s.clientKeys) ?? r;
}

/** A found label on exactly `p` (no inheritance: it is a fact about one
 *  file's bytes): `no-model`, bound nowhere. A personal document's
 *  (personal-documents.ts, secret-discovery.md §2.7) carries the document
 *  twin's `extract`: its labels stay, every value is a placeholder. */
export function foundLabel(p: string, s: LabelSnapshot): LabelDecision | null {
  if (!s.found || s.found.size === 0) return null;
  const n = normalizeLabelPath(p) ?? p;
  const row = s.found.get(n);
  if (!row) return null;
  return { level: "no-model", bindings: [], via: row.path, origin: "found", ...(row.kind === "document" ? { extract: DOCUMENT_TWIN_EXTRACT } : {}) };
}

/**
 * A human label on a file the content tier found to be a personal document
 * keeps the document twin when it names no `extract` of its own
 * (secret-discovery.md §2.7): the human's label decides the level and the
 * destinations, Mandu's reading of the document the twin's shape. Without
 * it, the human's first *Always* on an upload (holder-send-ask.ts, an exact
 * rule with the host) turned the twin into one whole-file placeholder in
 * the middle of the task, and every placeholder the model held stopped
 * naming a line of the file. A `public` label has no twin. Pure.
 */
function withDocumentTwin(r: LabelDecision, p: string, s: LabelSnapshot): LabelDecision {
  if (r.extract !== undefined || !isSecret(r.level) || !s.found || s.found.size === 0) return r;
  const row = s.found.get(normalizeLabelPath(p) ?? p);
  return row?.kind === "document" ? { ...r, extract: DOCUMENT_TWIN_EXTRACT } : r;
}

/**
 * Confidentiality plan 13 §4.6: a derived file refers to its sources,
 * `Release(copy) = ∩ Release(source)`, evaluated at each lookup, never copied
 * when the file was written. So a copy may go where ALL its sources may (the
 * intersection, D1's join), a binding a human revokes on a source leaves every
 * copy at once, and a source raised to a stricter level raises its copies.
 * Openers and output rules are not inherited: a copy has no reader list, and
 * the program that made it says nothing about who may read it.
 *
 * Applies to a derived row whose sources are known (`sources`, the files the
 * writing process held raw, plan 13 D4), unless an EXACT human label speaks
 * about the artifact (the §8 release act, which decides alone). Under an
 * ANCESTOR human label that outranks the row, that label's destinations are
 * intersected with the sources' too: a copy is never released anywhere its
 * sources could not all go, whatever folder it lands in.
 *
 * Fail-closed: a row with unknown or no sources (a high session's write,
 * Plan 9; a row from before 2026-10-02) stays bound nowhere; a source that no
 * longer classifies secret (its label removed, or lowered to `public`)
 * contributes nothing, i.e. bound nowhere, rather than everything (§4.6 asks
 * for its last label; nowhere is stricter than any last label and needs no
 * stored copy of it); a cycle of copies, or a chain deeper than
 * `MAX_REFERENCE_DEPTH`, is bound nowhere. The derived row itself still stores
 * no binding: a machine records where the bytes came from, never a release
 * (derived-labels.ts).
 */
function byReference(p: string, r: LabelDecision | null, s: LabelSnapshot, opts: ComposeOptions, visiting: readonly string[]): LabelDecision | null {
  if (r === null) return null;
  const row = resolveDerivedLabel(p, s.derived);
  if (row === null) return r;
  // An exact human label on the artifact decides alone (the release act).
  if (r.origin !== "derived" && r.via === row.path && !r.glob) return r;
  // A file a holder or a high session WROTE is no file whose values a human
  // named: its bytes may be any secret the writer held, so an ancestor's or
  // a pattern's `values:` never widens one of its fields past the whole
  // file (plan 13 §5.2). The whole file's bindings stay.
  if (row.sources === null || row.sources.length === 0) return withoutValues(r);
  const here = [...visiting, row.path];
  let level = r.level;
  const perSource: string[][] = r.origin === "derived" ? [] : [r.bindings];
  for (const src of row.sources) {
    if (here.includes(src) || here.length > MAX_REFERENCE_DEPTH) {
      perSource.push([]);
      continue;
    }
    const m = pathConfidentiality(src, undefined, (q) => composeAt(q, s, opts, here));
    if (!isSecret(m.level)) {
      perSource.push([]);
      continue;
    }
    level = maxConfidentiality(level, m.level);
    // A copy holds its source whole: under `values:` the source's whole-file
    // bindings, and none of its field rows' per-value hosts (plan 13 §5.2).
    perSource.push(holderFileBindings(m, opts.sourceBindings?.(src) ?? []));
  }
  // A copy is one datum made from its sources: it carries no `values:` of
  // its own (an ancestor label's per-value bindings would release a field
  // row of the copy past its sources' intersection), plan 13 §5.2.
  return { ...withoutValues(r), level, bindings: intersectBindings(perSource) };
}

/** `r` without its per-value rules (its `bindings` already the whole file's). */
function withoutValues(r: LabelDecision): LabelDecision {
  if (r.values === undefined && r.fileBindings === undefined) return r;
  const { values: _values, fileBindings: _fileBindings, ...rest } = r;
  return rest;
}

/** A lookup over a fixed snapshot (the discovery worker's). */
export function snapshotLookup(s: LabelSnapshot): LabelLookup {
  return (p) => composedLabel(p, s);
}

/**
 * Where the labels above `public` lie (2026-10-17): the places the text
 * scan reads a relative token at when it cannot place it
 * (secret-catalog.ts `findSecretPathsInText`, `LabelLookup.roots`). A human
 * label's path, or a pattern's literal directory prefix (`/` when it has
 * none; `anyDepth` when `**` follows it); every derived, session, found
 * and declared client-key path. Only labels above `public`: a `public` label
 * lowers nothing there. Pure.
 */
export function labelRoots(s: LabelSnapshot, home: string = homedir()): LabelRoot[] {
  const out: LabelRoot[] = [];
  for (const l of s.human.values()) {
    if (!isSecret(l.confidentiality)) continue;
    if (l.glob) {
      const g = compiledGlobFor(l.path, home);
      if (g === null) continue;
      const lead = g.literalPrefix === "" ? 0 : g.literalPrefix.split("/").length - 1;
      const recursive = l.recursive;
      out.push({ path: g.literalPrefix === "" ? "/" : g.literalPrefix, level: l.confidentiality, anyDepth: anyDepthPattern(g.segments, lead), matches: (p) => pathGlobMatches(g, p, recursive) });
    } else {
      out.push({ path: l.path, level: l.confidentiality });
    }
  }
  for (const d of s.derived.values()) if (isSecret(d.confidentiality)) out.push({ path: d.path, level: d.confidentiality });
  for (const r of s.session?.values() ?? []) out.push({ path: r.path, level: "no-model" });
  for (const r of s.found?.values() ?? []) out.push({ path: r.path, level: "no-model" });
  for (const k of s.clientKeys) out.push({ path: k, level: "no-model" });
  return out;
}

/**
 * Where a discovery walk looks for the HUMAN labels above `public`
 * (2026-10-17, confidentiality.md §6 "Read by a program the launch did not
 * see"): each literal label's path and each pattern's literal directory
 * prefix (`labelRoots`), never `/` (a pattern with no literal prefix matches
 * anywhere; the guard gates its files at the open). The derived, session and
 * client-key paths have walks of their own. Sorted, without repeats. Pure.
 */
export function labelWalkRoots(human: ReadonlyMap<string, PathLabel>, home: string = homedir()): string[] {
  const roots = labelRoots({ human, derived: new Map(), clientKeys: [] }, home).map((r) => r.path).filter((p) => p !== "/");
  return [...new Set(roots)].sort();
}

/** A guard label root (2026-10-17, the guard's gate of a labelled file the
 *  launch did not register): where a label lies, and for a pattern the
 *  literal anchors of its last segment (`shape`; absent: any file below). */
export interface GuardLabelRoot {
  path: string;
  shape?: { head: string; tail: string; exact: boolean };
}

/**
 * The roots the guard gates opens under (confidentiality.md §6, "Read by a
 * program the launch did not see"): each human label above `public` (a
 * literal's path; a pattern's literal directory prefix, `/` when it has
 * none, with its last segment's anchors), each declared model client
 * key and each found label's file (the content tier, found-labels.ts: a
 * file the launch did not twin, found by another workspace's walk or past
 * this one's cap). The derived labels have their own list (`derivedLabelsSince`); the
 * session labels are never gated (the agent's own background file). The
 * shape is a PREFILTER the guard applies to every segment below the root
 * (a recursive pattern covers what is below a directory it matches); the
 * arbiter's lookup decides (`labelledLevel`). Sorted, without repeats. Pure.
 */
export function guardLabelRoots(human: ReadonlyMap<string, PathLabel>, clientKeys: readonly string[], home: string = homedir(), found: Iterable<string> = []): GuardLabelRoot[] {
  const out = new Map<string, GuardLabelRoot>();
  const add = (r: GuardLabelRoot): void => {
    const k = `${r.path}\0${r.shape ? `${r.shape.exact ? "=" : ""}${r.shape.head}\0${r.shape.tail}` : "*"}`;
    if (!out.has(k)) out.set(k, r);
  };
  for (const l of human.values()) {
    if (!isSecret(l.confidentiality)) continue;
    if (!l.glob) { add({ path: l.path }); continue; }
    const g = compiledGlobFor(l.path, home);
    if (g === null) continue;
    const root = g.literalPrefix === "" ? "/" : g.literalPrefix;
    const last = g.segments[g.segments.length - 1];
    add(last && last.kind === "name" ? { path: root, shape: segmentShape(last.tokens) } : { path: root });
  }
  for (const k of clientKeys) add({ path: k });
  for (const f of found) add({ path: f });
  return [...out.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/** The literal anchors of one name segment: the literal run before its
 *  first wildcard and after its last (`exact` when it has none). */
function segmentShape(tokens: ReadonlyArray<{ t: string; c?: string }>): { head: string; tail: string; exact: boolean } {
  let head = "";
  let i = 0;
  for (; i < tokens.length && tokens[i]!.t === "lit"; i++) head += tokens[i]!.c ?? "";
  if (i === tokens.length) return { head, tail: head, exact: true };
  let tail = "";
  for (let j = tokens.length - 1; j >= 0 && tokens[j]!.t === "lit"; j--) tail = (tokens[j]!.c ?? "") + tail;
  return { head, tail, exact: false };
}

/** The human label roots above `public` with their levels, as keys
 *  (`<level> <path>`): what changed between two label sets is the keys one
 *  has and the other lacks (a new label, or one raised). Pure. */
export function labelRootKeys(human: ReadonlyMap<string, PathLabel>, home: string = homedir()): Set<string> {
  return new Set(labelRoots({ human, derived: new Map(), clientKeys: [] }, home).filter((r) => r.path !== "/").map((r) => `${r.level} ${r.path}`));
}

/** A pattern that names a SHAPE at any depth below its prefix (`**` right
 *  after the prefix, then a segment with a literal character in it:
 *  `**\/*.pem`, `/proj/**\/secret-*.md`). One that only says "everything
 *  below" (`/proj/vault/**`, `/proj/vault/**\/*`) is a directory, read like
 *  a recursive label: every name matches inside it. */
function anyDepthPattern(segments: CompiledPathGlob["segments"], lead: number): boolean {
  if (segments[lead]?.kind !== "globstar") return false;
  return segments.slice(lead + 1).some((s) => s.kind === "name" && s.tokens.some((t) => t.t === "lit"));
}

/** A lookup with the `roots` of the snapshot `snapshot()` returns when
 *  asked (the arbiter's live lookup). */
export function withLabelRoots(lookup: (p: string) => LabelDecision | null, snapshot: () => LabelSnapshot): LabelLookup {
  const f: LabelLookup = (p) => lookup(p);
  f.roots = () => labelRoots(snapshot());
  return f;
}
