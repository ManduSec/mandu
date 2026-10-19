/**
 * current-bindings — a symbol's bound destinations follow the label law IN
 * FORCE, not the law at the moment the symbol was minted
 * (docs/design/confidentiality/confidentiality.md §2.1).
 *
 * A symbol row stores its `bindings` (the hosts the egress gate releases it
 * to). Before 2026-10-05 the column was written once, at mint, from the
 * label of the row's origin path, and a re-registration REUSED the row by
 * value without touching it. So a binding added to policy.yaml after Mandu
 * first saw a file never applied to that file's symbols (held as
 * `egress:secret-unbound` while `mandu why` said "released"), and a binding
 * REMOVED from policy.yaml kept releasing the symbols minted under it — a
 * stale standing release, the security-relevant direction.
 *
 * Two rules, both pure over the symbol table and a label lookup:
 *
 *   1. A REGISTERED FILE's rows (registry.ts `isRegisteredFileRow`: the base
 *      row and its field rows, no lineage) carry EXACTLY the current label's
 *      bindings for their origin path, plus a field's own wire grant (plan
 *      10 §11.13.1: the launch HOME's `.npmrc` / pip.conf token bound to the
 *      registry its own text names, as the registration RECORDED it,
 *      `wire_grants`; a label binding on the same host neither gives nor
 *      takes it). Both directions: a binding added
 *      releases at once, a binding removed stops releasing at once.
 *
 *   2. Every OTHER secret row that refers to something (a lineage parent in
 *      `derived_from`, the recorded sources of a multi-input derived row
 *      (symbol-sources.ts), an origin that is itself a symbol, an origin
 *      that is an absolute path, or a command's text) is INTERSECTED with
 *      that reference's current bindings. It only ever narrows: such a row
 *      may have been minted narrower than its reference (a multi-source
 *      join, source-label.ts; a client's own `bindings`), so it is never
 *      widened; a binding added after it was minted reaches the next copy,
 *      not this one (fail-closed). A binding removed from the source leaves
 *      every copy at once (the plan 13 §4.6 by-reference rule, applied to
 *      symbols). A command text that no label matches any more is bound
 *      nowhere (2026-10-05: it used to be left alone, so a label removed
 *      entirely kept releasing the rows minted under it).
 *
 *   3. A masked environment variable's row (`env:NAME`) carries EXACTLY the
 *      hosts the law in force binds NAME to (`env.sources`, `models[].
 *      token_env`) plus its own value's wire host, both directions, as rule
 *      1 (2026-10-05: before, a changed `env.sources` binding applied only
 *      at the next launch, so a removed one kept releasing in the running
 *      session).
 *
 * The arbiter runs {@link syncCurrentBindings} whenever the label law
 * changes (a policy swap, a label act, a derived-label write) and at start,
 * before it answers any request (server.ts `syncSymbolBindings`), and
 * registerSecret runs rule 1 for its path before it reuses a row. Changed rows
 * are persisted, so the DB says what the gate decides.
 *
 * AUTOMATIC versus DECLARED bindings (plan 10 §11.13.1, 2026-10-09). Rules 1
 * and 3 give a row two kinds of host: the ones the USER declared (a label's
 * `bindings:`, `env.sources[].bindings`, `models[].token_env`) and the ones
 * Mandu added on its own (a field's wire grant, an env value's wire host, an
 * auth grant). {@link releaseRestsOnWireGrant} tells them apart for one
 * destination: the egress gate puts a credential whose release there rests
 * on an automatic host alone back only in the request's Authorization header
 * (policy-interface.ts `wirePositionRefusal`).
 *
 * Mandu-new (no reference origin).
 */
import type { SymbolEntry, SymbolMap } from "../symbol-table/symbol-table.js";
import { findSymbolByName, getSymbolEntry, persistSymbol, touchSymbolMap, wireGrantOf } from "../symbol-table/symbol-table.js";
import { destinationMatchesBindings } from "../policy/policy-interface.js";
import { isSecret, parseConfidentialityLevel } from "../symbol-table/confidentiality.js";
import { confidentialityForOrigin, pathConfidentiality, type LabelLookup, type SecretCatalogMatch } from "../policy/secret-catalog.js";
import { oneValueBindings, valueBindings, valueKeyMatches } from "../policy/value-bindings.js";
import { extractSecretSpans, secretFileShape } from "../policy/secret-extract.js";
import { envRowVariable, isRegisteredFileRow } from "./registry.js";
import { sourceLabel } from "../symbol-table/source-label.js";

/** How many passes the sync makes at most: a registered derived file's
 *  bindings refer to its sources' rows (label-lookup.ts `MAX_REFERENCE_DEPTH`),
 *  and a copy of a copy to its parent, so one pass may expose another. */
const MAX_PASSES = 9;

/** An origin that is a URL (secret-catalog.ts `confidentialityForOrigin`'s
 *  own test: it never matches a label). */
const URL_ORIGIN_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

export interface SyncBindingsOptions {
  resolveLabel?: LabelLookup;
  /** Only the registered rows of these origin paths (registerSecret's own
   *  path); rules 2 and 3 are skipped. Absent: every row, every rule. */
  paths?: readonly string[];
  /** Rule 3: the hosts the law in force binds a masked environment variable
   *  to (`env.sources[].bindings`, `models[].token_env`). Absent: env rows
   *  are left alone. */
  envBindings?: (name: string) => readonly string[];
  /** Rule 3: the wire host an env row's own value named when this process
   *  saw it registered on the DATA plane (a pip index URL's host, registry.ts
   *  `wireHost`; memory only), or undefined. A human-plane registration
   *  records it instead (`wire_grants`, symbol-table.ts `recordWireGrant`),
   *  which the sync reads when this answers undefined. */
  envWire?: (symbol: string) => string | undefined;
  /** Rule 2: the source symbols a multi-input derived row was joined from
   *  (symbol-sources.ts), or undefined when none were recorded. */
  sourcesOf?: (symbol: string) => readonly string[] | undefined;
  /** Rule 1: the hosts a launch granted a field of an agent's own key file
   *  to (auth-grants.ts, agent-sign-in.md §3), by origin path and field.
   *  Absent: no field keeps such a host. */
  fieldGrants?: (origin: string, field: string) => readonly string[];
}

/** Is this row one of a registered file's own rows (the base row or a field
 *  row, no lineage), obsoleted or not? */
function isRegisteredOwnRow(e: SymbolEntry): boolean {
  return isRegisteredFileRow(e) && e.derived_from === null &&
    typeof e.origin === "string" && e.origin.startsWith("/") && isSecret(parseConfidentialityLevel(e.confidentiality));
}

/** Is this row one of a registered file's own LIVE rows (rule 1)? */
function isRegistryRow(e: SymbolEntry): boolean {
  return e.obsoleted_at === null && isRegisteredOwnRow(e);
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const s = new Set(a);
  return b.every((x) => s.has(x));
}

/** The wire host a field row's own span names (plan 10 §11.13.1), re-read
 *  from its base row's text; null for any other row. */
function ownWireHost(symbolMap: SymbolMap, name: string, row: SymbolEntry, label: LabelLookup | undefined): string | null {
  if (row.field === null || typeof row.origin !== "string") return null;
  const shape = secretFileShape(row.origin);
  if (shape !== "npmrc" && shape !== "pip-conf") return null;
  const dot = name.indexOf(".");
  if (dot < 0) return null;
  const base = symbolMap.symbols.get(name.slice(0, dot));
  if (!base || base.field !== null || base.origin !== row.origin) return null;
  const extract = pathConfidentiality(row.origin, undefined, label).extract;
  const span = extractSecretSpans(row.origin, base.value, extract ? { extract } : {}).spans.find((s) => s.key === row.field);
  return span?.wire?.host ?? null;
}

/**
 * Rule 1: set every registered file row's bindings to its path's current
 * label bindings plus its own wire grant. A field keeps a host beyond what
 * the label declares only when the registration RECORDED it as that field's
 * wire grant (symbol-table.ts `recordWireGrant`) and the field's own text
 * still names it (the registration grants it to the field alone, never to
 * the base). Returns the names it changed (persisted when `dbPath` is given).
 *
 * Until 2026-10-17 the grant was inferred, "the field holds its own wire
 * host and its base row does not", which failed both ways
 * (confidentiality.md §2.1): a label binding on the registry's own host,
 * removed, took the grant with it until the next launch (the base row had
 * held the host too), and a host a `values:` entry gave a workspace
 * `.npmrc` token (never a grant: its base row holds the whole file's
 * bindings) was kept as one after the user removed it, by every later sync.
 */
export function syncRegisteredBindings(symbolMap: SymbolMap, opts: SyncBindingsOptions, dbPath?: string): string[] {
  const only = opts.paths ? new Set(opts.paths) : null;
  const declared = declaredBindingsReader(symbolMap, opts.resolveLabel);
  const next: Array<[string, SymbolEntry, string[]]> = [];
  for (const [name, e] of symbolMap.symbols) {
    if (!isRegistryRow(e) || (only && !only.has(e.origin as string))) continue;
    const want = declared(name, e);
    const granted = e.field !== null ? wireGrantOf(symbolMap, name) : undefined;
    if (granted !== undefined && ownWireHost(symbolMap, name, e, opts.resolveLabel) === granted &&
      !want.some((b) => b.toLowerCase() === granted)) {
      want.push(granted);
    }
    // An auth grant (agent-sign-in.md §3): the field alone, exactly the
    // hosts granted now (both directions, as the label's).
    if (e.field !== null && opts.fieldGrants) {
      for (const h of opts.fieldGrants(e.origin as string, e.field)) {
        if (!want.some((b) => b.toLowerCase() === h)) want.push(h);
      }
    }
    if (!sameSet(e.bindings ?? [], want)) next.push([name, e, want]);
  }
  for (const [name, e, want] of next) {
    e.bindings = want.length > 0 ? want : null;
    if (dbPath !== undefined) persistSymbol(name, e, dbPath);
  }
  if (next.length > 0) touchSymbolMap(symbolMap);
  return next.map(([n]) => n);
}

/**
 * The bindings the law in force DECLARES for one of a registered file's own
 * rows (rule 1 without the hosts Mandu adds on its own): its path's label
 * bindings, or, when the label has `values:` (plan 13 §5.2), the bindings of
 * the values the row holds. The whole-file row, and a field row whose value
 * names cannot be read back (its base row gone, the text no longer parses
 * to that field), take the whole file's, the intersection over every value
 * (value-bindings.ts): never more than any value it might hold. Memoized per
 * origin and per base row for one sweep.
 *
 * A credential the twin's belt found in a COMMENT line (secret-extract.ts
 * `SecretSpan.comment`, 2026-10-17: a commented-out old key) is bound to no
 * host the file's own `bindings` name: the label speaks for the values
 * programs read, and no program sends a comment. Only a `values:` entry that
 * names its field (`cred.OLD_STRIPE_KEY`, `cred.*`) binds it, to that entry's
 * hosts (fail-closed: an old key the human never thought of goes nowhere).
 */
export function declaredBindingsReader(symbolMap: SymbolMap, resolveLabel: LabelLookup | undefined): (name: string, e: SymbolEntry) => string[] {
  const labelOf = new Map<string, SecretCatalogMatch>();
  const namesOf = new Map<string, FieldNames | null>();
  const match = (origin: string): SecretCatalogMatch => {
    let m = labelOf.get(origin);
    if (m === undefined) {
      m = pathConfidentiality(origin, undefined, resolveLabel);
      labelOf.set(origin, m);
    }
    return m;
  };
  return (name, e) => {
    const m = match(e.origin as string);
    if (!isSecret(m.level)) return [];
    if (e.field !== null && fieldNamesOf(symbolMap, name, e, m.extract, namesOf)?.comments.has(e.field)) {
      return (m.values ?? []).some((v) => valueKeyMatches(v.key, e.field!)) ? oneValueBindings([], m.values, e.field) : [];
    }
    if (!m.values || !m.fileBindings || e.field === null) return [...new Set(m.bindings)];
    return valueBindings(m.fileBindings, m.values, rowValueNames(symbolMap, name, e, m.extract, namesOf));
  };
}

/** A file version's field names, read back from its base row: each span's
 *  value names (`rowValueNames`), and the fields found in a comment line
 *  (`SecretSpan.comment`). */
interface FieldNames {
  names: Map<string, string[]>;
  comments: Set<string>;
}

/** The field names of the base row a FIELD row `name` shares its hash with,
 *  memoized per base row; null for a row with no field, no such base row,
 *  or a text that no longer parses. */
function fieldNamesOf(
  symbolMap: SymbolMap, name: string, row: SymbolEntry, extract: string | undefined,
  memo: Map<string, FieldNames | null>,
): FieldNames | null {
  if (row.field === null || typeof row.origin !== "string") return null;
  const dot = name.indexOf(".");
  if (dot < 0) return null;
  const baseName = name.slice(0, dot);
  let got = memo.get(baseName);
  if (got === undefined) {
    got = null;
    const base = symbolMap.symbols.get(baseName);
    if (base && base.field === null && base.origin === row.origin) {
      try {
        const x = extractSecretSpans(row.origin, base.value, extract ? { extract } : {});
        const names = new Map<string, string[]>();
        const comments = new Set<string>();
        for (const span of x.spans) {
          names.set(span.key, [span.key, ...(span.parts ?? []).map((p) => p.key)]);
          for (const p of span.parts ?? []) if (!names.has(p.key)) names.set(p.key, [p.key]);
          if (span.comment) comments.add(span.key);
        }
        got = { names, comments };
      } catch {
        got = null;
      }
    }
    memo.set(baseName, got);
  }
  return got;
}

/**
 * The value names a registered FIELD row's symbol holds (plan 13 §5.2): its
 * span's key and the keys of every secret merged into that span
 * (`SecretSpan.parts`), a part's own key, and for a `KEY.encoded` row (the
 * file's own spelling of a value) the names its value holds. Read back from
 * the row's own base row (the file version whose hash the field shares) with
 * the extractor that minted it. Null when it cannot be (no base row, the
 * field not found): the caller then takes the whole file's bindings.
 */
function rowValueNames(
  symbolMap: SymbolMap, name: string, row: SymbolEntry, extract: string | undefined,
  memo: Map<string, FieldNames | null>,
): string[] | null {
  const names = fieldNamesOf(symbolMap, name, row, extract, memo)?.names ?? null;
  if (names === null || row.field === null) return null;
  const own = names.get(row.field);
  if (own !== undefined) return own;
  if (row.field.endsWith(".encoded")) return names.get(row.field.slice(0, -".encoded".length)) ?? null;
  return null;
}

/** Rule 2's references for one row: the current bindings of each thing it
 *  was minted from that the sync can read (none: the row is left alone).
 *  `byOrigin` memoizes the label answer per origin text for one sweep. */
function referenceBindings(
  symbolMap: SymbolMap, name: string, e: SymbolEntry, opts: SyncBindingsOptions, byOrigin: Map<string, string[] | null>,
): string[][] {
  const label = opts.resolveLabel;
  const refs: string[][] = [];
  if (e.derived_from) {
    const parent = getSymbolEntry(symbolMap, e.derived_from);
    if (parent && isSecret(parseConfidentialityLevel(parent.confidentiality))) refs.push(parent.bindings ?? []);
  }
  // A multi-input derived row: the join of every recorded source as it
  // stands now (the same join that minted it, source-label.ts). A source
  // that is gone binds it nowhere.
  const sources = opts.sourcesOf?.(name);
  if (sources && sources.length > 0) {
    try {
      const joined = sourceLabel(symbolMap, [...sources]);
      if (joined.bindings !== undefined) refs.push(joined.bindings);
    } catch {
      refs.push([]);
    }
  }
  const origin = e.origin;
  if (typeof origin === "string" && origin !== "") {
    const sym = origin.startsWith("$") ? getSymbolEntry(symbolMap, origin) : null;
    if (sym) {
      if (isSecret(parseConfidentialityLevel(sym.confidentiality))) refs.push(sym.bindings ?? []);
    } else {
      let ref = byOrigin.get(origin);
      if (ref === undefined) {
        if (origin.startsWith("/") && !/\s/.test(origin)) {
          // A path: its label as it stands now. A path no longer secret (its
          // label removed or lowered to public) is bound nowhere (plan 13 §4.6).
          const m = pathConfidentiality(origin, undefined, label);
          ref = isSecret(m.level) ? m.bindings : [];
        } else if (URL_ORIGIN_RE.test(origin)) {
          // A URL: no label ever matches one (confidentialityForOrigin), so
          // its row's bindings never came from a label. Not a reference.
          ref = null;
        } else {
          // A command's text, read exactly as its mint read it
          // (server.ts `bindingsForOrigin`: no call directory either), so an
          // unchanged law gives back the bindings it minted. A text no
          // label matches any more (the label removed, or outranked by the
          // catalog, whose matches carry no binding) is bound nowhere: no
          // production client sends a row's own `bindings`, so a bound
          // command row's bindings came from a label, and the label is gone.
          const m = confidentialityForOrigin(origin, undefined, label);
          ref = isSecret(m.level) ? m.bindings : [];
        }
        byOrigin.set(origin, ref);
      }
      if (ref !== null) refs.push(ref);
    }
  }
  return refs;
}

/**
 * Rule 2: narrow every other secret row's bindings to what its references
 * allow now. Never widens. Returns the names it changed.
 */
export function narrowDerivedBindings(symbolMap: SymbolMap, opts: SyncBindingsOptions, dbPath?: string): string[] {
  const changed: string[] = [];
  const byOrigin = new Map<string, string[] | null>();
  for (const [name, e] of symbolMap.symbols) {
    // An env row's origin (`env:NAME`) is not a reference: rule 3 owns it.
    if (e.obsoleted_at !== null || isRegistryRow(e) || envRowVariable(e) !== null) continue;
    const stored = e.bindings ?? [];
    if (stored.length === 0 || !isSecret(parseConfidentialityLevel(e.confidentiality))) continue;
    const refs = referenceBindings(symbolMap, name, e, opts, byOrigin);
    if (refs.length === 0) continue;
    const kept = stored.filter((b) => refs.every((r) => r.includes(b)));
    if (kept.length === stored.length) continue;
    e.bindings = kept.length > 0 ? kept : null;
    if (dbPath !== undefined) persistSymbol(name, e, dbPath);
    changed.push(name);
  }
  if (changed.length > 0) touchSymbolMap(symbolMap);
  return changed;
}

/**
 * Rule 3: a masked environment variable's row (registry.ts
 * `registerEnvSecret`, origin `env:NAME`) carries EXACTLY the hosts the law
 * in force binds NAME to (`env.sources[].bindings`, the `models[]` whose
 * `token_env` it is) plus the wire host its own value named at
 * registration (a pip index URL's host) plus the hosts an auth grant on
 * NAME names (`fieldGrants` with origin `env:NAME`, agent-sign-in.md §3.8;
 * kept across a restart while the launch lives, auth-grants.ts). Both directions, as rule 1: the
 * registration already gives a reused row the bindings of the launch
 * registering it, and this applies a changed law to the running session.
 * The wire host is the one a human-plane registration RECORDED
 * (`wire_grants`, kept across a restart, dropped with the row: 2026-10-17),
 * or the one this process saw a data-plane registration name (memory only:
 * an arbiter restarted after it does not keep it, fail-closed until the
 * next launch registers the variable). Returns the names it changed.
 */
export function syncEnvBindings(symbolMap: SymbolMap, opts: SyncBindingsOptions, dbPath?: string): string[] {
  const law = opts.envBindings;
  if (!law) return [];
  const changed: string[] = [];
  for (const [name, e] of symbolMap.symbols) {
    if (e.obsoleted_at !== null || !isSecret(parseConfidentialityLevel(e.confidentiality))) continue;
    const variable = envRowVariable(e);
    if (variable === null) continue;
    const want = [...new Set(law(variable))];
    // The value's own wire host: this process's memory of a registration
    // (a data-plane one), else the record a human-plane one left
    // (`wire_grants`, kept across a restart; confidentiality.md §2.1).
    const wire = opts.envWire?.(name) ?? wireGrantOf(symbolMap, name);
    if (wire !== undefined && !want.some((b) => b.toLowerCase() === wire.toLowerCase())) want.push(wire);
    // An auth grant on the variable (agent-sign-in.md §3.8): the whole
    // value's row only, exactly the hosts granted now (both directions).
    if (e.field === variable && opts.fieldGrants) {
      for (const h of opts.fieldGrants(`env:${variable}`, variable)) {
        if (!want.some((b) => b.toLowerCase() === h)) want.push(h);
      }
    }
    if (sameSet(e.bindings ?? [], want)) continue;
    e.bindings = want.length > 0 ? want : null;
    if (dbPath !== undefined) persistSymbol(name, e, dbPath);
    changed.push(name);
  }
  if (changed.length > 0) touchSymbolMap(symbolMap);
  return changed;
}

/** How deep {@link releaseRestsOnWireGrant} follows a row's references. */
const MAX_REFERENCE_DEPTH = MAX_PASSES;

/**
 * Does the release of `symbol` at `destination` rest ONLY on a binding Mandu
 * added on its own, never one the user declared (header, "AUTOMATIC versus
 * DECLARED")? The row is the egress gate's own (`findSymbolByName`, the
 * candidate walk), so a mutated token answers as the row it resolves to.
 *
 *   - Not bound at `destination` at all ⇒ false (the unbound branches decide).
 *   - A registered file's row (rule 1): true when the destination matches
 *     none of the bindings its path's label declares now. So the launch
 *     HOME's `.npmrc` token or pip.conf index password at the host its own
 *     file names, and an agent key at the host its auth grant names, are
 *     automatic; the same host in the label's `bindings:` is the user's.
 *     An OBSOLETED row of the file is judged the same way (2026-10-10):
 *     rule 1 no longer keeps its bindings, so they stay frozen with the
 *     wire grant's host in them, and it refers to nothing, so the walk
 *     below would have called it (and a copy whose only parent it is) the
 *     user's binding.
 *   - A masked environment variable's row (rule 3): true when the
 *     destination matches none of the hosts the law binds the variable to
 *     (`envBindings`; absent ⇒ none, fail-closed). So `PIP_INDEX_URL`'s
 *     password at its index host is automatic; an `env.sources` binding is
 *     the user's.
 *   - Any other row (a copy, a derived or joined row, a row whose origin is a
 *     symbol): true when ANY row it was made from is automatic at
 *     `destination` (its bindings only ever narrow those, rule 2), so a copy
 *     of the token does not launder the binding. A chain deeper than
 *     `MAX_REFERENCE_DEPTH` ⇒ true (fail-closed). A row with no reference
 *     got its bindings from a label or its client ⇒ false.
 *
 * Pure over the symbol table and the law (`resolveLabel`, `envBindings`,
 * `sourcesOf`).
 */
export function releaseRestsOnWireGrant(
  symbolMap: SymbolMap,
  symbol: string,
  destination: string,
  opts: Pick<SyncBindingsOptions, "resolveLabel" | "envBindings" | "sourcesOf">,
): boolean {
  const hit = findSymbolByName(symbolMap, symbol);
  if (!hit) return false;
  return wireOnlyAt(symbolMap, hit.name, hit.entry, destination, opts, 0, new Map());
}

function wireOnlyAt(
  symbolMap: SymbolMap, name: string, e: SymbolEntry, destination: string,
  opts: Pick<SyncBindingsOptions, "resolveLabel" | "envBindings" | "sourcesOf">,
  depth: number, memo: Map<string, boolean>,
): boolean {
  if (!destinationMatchesBindings(destination, e.bindings)) return false;
  if (isRegisteredOwnRow(e)) {
    // Per value when the label has `values:` (plan 13 §5.2): a host a value
    // is bound to is the user's, as a host in the file's `bindings:` is.
    return !destinationMatchesBindings(destination, declaredBindingsReader(symbolMap, opts.resolveLabel)(name, e));
  }
  const variable = envRowVariable(e);
  if (variable !== null) return !destinationMatchesBindings(destination, [...(opts.envBindings?.(variable) ?? [])]);
  const known = memo.get(name);
  if (known !== undefined) return known;
  if (depth >= MAX_REFERENCE_DEPTH) return true;
  // In progress: a reference cycle answers true (fail-closed).
  memo.set(name, true);
  const refs: Array<[string, SymbolEntry]> = [];
  const add = (token: string | null | undefined): void => {
    if (!token) return;
    const r = findSymbolByName(symbolMap, token);
    if (r) refs.push([r.name, r.entry]);
  };
  add(e.derived_from);
  for (const s of opts.sourcesOf?.(name) ?? []) add(s);
  if (typeof e.origin === "string" && e.origin.startsWith("$")) add(e.origin);
  const answer = refs.some(([n, r]) => wireOnlyAt(symbolMap, n, r, destination, opts, depth + 1, memo));
  memo.set(name, answer);
  return answer;
}

/** Every rule to a fixpoint. Returns every name changed (deduplicated). */
export function syncCurrentBindings(symbolMap: SymbolMap, opts: SyncBindingsOptions, dbPath?: string): string[] {
  const all = new Set<string>();
  // Env rows refer to nothing another row's sync moves: one pass.
  if (!opts.paths) for (const n of syncEnvBindings(symbolMap, opts, dbPath)) all.add(n);
  for (let pass = 0; pass < MAX_PASSES; pass++) {
    const a = syncRegisteredBindings(symbolMap, opts, dbPath);
    const b = opts.paths ? [] : narrowDerivedBindings(symbolMap, opts, dbPath);
    for (const n of [...a, ...b]) all.add(n);
    if (a.length === 0 && b.length === 0) break;
  }
  return [...all];
}

/**
 * The value and names an ISSUER release may read for `symbol`
 * (confidentiality.md §2.3, issuer-bindings.ts), or null when the row may
 * not use one. Only a SOURCE row the user's own setup minted:
 *
 *   - a registered file's own FIELD row (no lineage, trusted, active, its
 *     origin an absolute path), whose deciding label is the catalog's, its
 *     content tier's or a human label (never a derived label: a file a high
 *     session wrote, whose values the agent's world composed), and whose
 *     field is not a comment line's (an old key the human never thought
 *     of goes nowhere);
 *   - a masked environment variable's whole-value row (`env:NAME`).
 *
 * Never a whole-file row, a copy, a derived or joined row, a tool result's
 * mint or the prompt filter's: those keep asking. The candidate walk
 * (`findSymbolByName`) resolves a mutated token to its row, as the gate
 * does. Pure over the table and the law.
 */
export function issuerSourceOf(
  symbolMap: SymbolMap, symbol: string, resolveLabel: LabelLookup | undefined,
): { value: string; names: string[] } | null {
  const hit = findSymbolByName(symbolMap, symbol);
  if (!hit) return null;
  const e = hit.entry;
  if (e.obsoleted_at !== null || e.integrity !== "trusted" || !isSecret(parseConfidentialityLevel(e.confidentiality))) return null;
  if (typeof e.value !== "string" || e.value === "") return null;
  const variable = envRowVariable(e);
  if (variable !== null) return e.field === variable && e.derived_from === null ? { value: e.value, names: [variable] } : null;
  if (!isRegisteredOwnRow(e) || e.field === null) return null;
  if (isAgentCredentialPath(e.origin as string)) return null;
  const m = pathConfidentiality(e.origin as string, undefined, resolveLabel);
  if (!isSecret(m.level) || m.rule === null || m.rule.startsWith("derived:")) return null;
  const names = fieldNamesOf(symbolMap, hit.name, e, m.extract, new Map());
  if (names === null || names.comments.has(e.field)) return null;
  return { value: e.value, names: [e.field] };
}

/** An AI agent's own login or key file, by its trailing path (wherever the
 *  agent's environment moved it): Claude Code's `.credentials.json` and
 *  `.claude.json`, the SDKs' `~/.anthropic` and `~/.openai`, Codex's and
 *  OpenCode's `auth.json`, Goose's `goose/secrets.yaml`. Their keys reach
 *  the provider only through the launch's auth grant, which ends with the
 *  launch (agent-sign-in.md §3); the issuer binding never stands in for it.
 *  Broad on purpose: a file it names by mistake keeps asking. Pure. */
export function isAgentCredentialPath(p: string): boolean {
  return /(?:^|\/)(?:\.credentials\.json|\.claude\.json|auth\.json)$/.test(p) ||
    /\/goose\/secrets\.ya?ml$/.test(p) ||
    /\/\.(?:anthropic|openai)(?:\/|$)/.test(p);
}
