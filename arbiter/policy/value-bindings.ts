/**
 * value-bindings — per-value destinations for a structured file
 * (confidentiality plan 13 §5.2, `values:`).
 *
 * ```yaml
 * paths:
 *   - path: ~/ws/app/.env
 *     level: no-model
 *     values:
 *       STRIPE_KEY: { bindings: [api.stripe.com] }
 *       "AWS_*":    { bindings: ["*.amazonaws.com"] }
 * ```
 *
 * A `values:` key names a field of the file's structured twin, the name its
 * symbol carries (`$MDU:nomodel_Read[…].STRIPE_KEY`), with `*` matching any
 * run of characters. A key also covers the sub-fields of the value it names
 * (`DATABASE_URL` covers `DATABASE_URL.password`; `STRIPE_KEY` the file's own
 * encoding of it, `STRIPE_KEY.encoded`).
 *
 * THE RULES (each one fail-closed):
 *
 *   - A value's symbol is released at the bindings of the entries that match
 *     its name. Several matching entries: the value may go only where EVERY
 *     one of them allows (the intersection; a more specific key never widens a
 *     broader one). No matching entry: the file's own `bindings`.
 *   - A symbol that holds several values (a span the extractor merged with
 *     others, registry.ts `SecretSpan.parts`) is released only where every
 *     value in it may go.
 *   - A row whose value names cannot be determined (the whole-file row, a
 *     field the file's text no longer has, a parse failure) takes the WHOLE
 *     FILE's destinations, never one value's.
 *   - The whole file, as a raw holder holds it, may go only where every value
 *     may go AND where the file's own bindings allow: the intersection of the
 *     file's `bindings` and every entry's (plan 13 D1 inside one file). It is
 *     computed over every entry, not only the entries that match a value the
 *     file has today: a value added to the file later is covered, and an
 *     entry that matches nothing only narrows.
 *
 * Pure. Mandu-new (no reference origin).
 */
import { intersectBindings } from "./flow-taint.js";

/** One compiled `values:` entry: the field-name pattern and its bindings. */
export interface ValueRule {
  key: string;
  bindings: string[];
}

/** The longest `values:` key the validator accepts. */
export const VALUE_KEY_MAX = 256;

/** A `values:` key: no whitespace, no control character, at most
 *  {@link VALUE_KEY_MAX} characters. */
export function isValueKey(k: unknown): k is string {
  return typeof k === "string" && k !== "" && k.length <= VALUE_KEY_MAX && !/[\s\u0000-\u001f\u007f]/.test(k);
}

const KEY_RE_CACHE = new Map<string, RegExp>();

function keyRegExp(pattern: string): RegExp {
  let re = KEY_RE_CACHE.get(pattern);
  if (re === undefined) {
    const body = pattern.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*");
    // The name itself, or the name of a value it is a sub-field of.
    re = new RegExp(`^(?:${body})(?:\\..*)?$`, "s");
    if (KEY_RE_CACHE.size >= 4096) KEY_RE_CACHE.clear();
    KEY_RE_CACHE.set(pattern, re);
  }
  return re;
}

/** Does the `values:` key `pattern` name the field `field`? `*` matches any
 *  run of characters; a key also matches the sub-fields of what it names
 *  (`field` = a match + `.` + anything). Case-sensitive (a variable's name
 *  is). */
export function valueKeyMatches(pattern: string, field: string): boolean {
  if (!isValueKey(pattern) || typeof field !== "string" || field === "") return false;
  return keyRegExp(pattern).test(field);
}

/** Compile a document's `values:` mapping. Entries that are not well formed
 *  (the validator refuses them at boot) are skipped, which narrows the
 *  values they named to the file's bindings, never widens them. Undefined
 *  for no mapping or an empty one. */
export function compileValueRules(raw: unknown): ValueRule[] | undefined {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const out: ValueRule[] = [];
  for (const [key, v] of Object.entries(raw as Record<string, unknown>)) {
    if (!isValueKey(key) || v === null || typeof v !== "object" || Array.isArray(v)) continue;
    const b = (v as { bindings?: unknown }).bindings;
    const bindings = Array.isArray(b) ? b.filter((x): x is string => typeof x === "string" && x.trim() !== "") : [];
    out.push({ key, bindings });
  }
  return out.length > 0 ? out : undefined;
}

/** The document form of compiled rules (`{ KEY: { bindings } }`), for an
 *  entry written back to policy.yaml. */
export function valueRulesToDocument(values: readonly ValueRule[]): Record<string, { bindings: string[] }> {
  const out: Record<string, { bindings: string[] }> = {};
  for (const v of values) out[v.key] = { bindings: [...v.bindings] };
  return out;
}

/** Where the WHOLE file may go: the file's bindings and every entry's, all
 *  at once (header, last rule). */
export function wholeFileBindings(fileBindings: readonly string[], values: readonly ValueRule[] | undefined): string[] {
  if (!values || values.length === 0) return [...fileBindings];
  return intersectBindings([fileBindings, ...values.map((v) => v.bindings)]);
}

/** Where ONE value, named `field`, may go: the intersection of the matching
 *  entries' bindings, else the file's. */
export function oneValueBindings(fileBindings: readonly string[], values: readonly ValueRule[] | undefined, field: string): string[] {
  const hits = (values ?? []).filter((v) => valueKeyMatches(v.key, field));
  if (hits.length === 0) return [...fileBindings];
  return intersectBindings(hits.map((v) => v.bindings));
}

/**
 * Where a symbol holding the values named `fields` may go: every one of
 * them must be allowed there. `fields` null or empty (the names are not
 * known) gives the whole file's destinations.
 */
export function valueBindings(fileBindings: readonly string[], values: readonly ValueRule[] | undefined, fields: readonly string[] | null): string[] {
  if (!values || values.length === 0) return [...fileBindings];
  if (fields === null || fields.length === 0) return wholeFileBindings(fileBindings, values);
  return intersectBindings(fields.map((f) => oneValueBindings(fileBindings, values, f)));
}

/** Every binding a `values:` entry or the file names (for telling a declared
 *  host from one Mandu added on its own). */
export function declaredAnywhere(fileBindings: readonly string[], values: readonly ValueRule[] | undefined): string[] {
  return [...new Set([...fileBindings, ...(values ?? []).flatMap((v) => v.bindings)])];
}

/**
 * Where a RAW HOLDER of one file may send (server.ts `taintedProcessBindings`,
 * and a copy's sources, label-lookup.ts): the file's label bindings (the
 * whole file's, `label.bindings`) plus the hosts its registry rows carry
 * beyond the law (a field's wire grant, an auth grant). Under `values:` a
 * field row also carries ITS value's bindings, which a holder of the whole
 * file must not get: every host the label declares anywhere is left out of
 * the registry's share, so only the hosts Mandu added on its own remain
 * (one that a value also names is dropped too: fail-closed).
 */
export function holderFileBindings(
  label: { bindings: readonly string[]; values?: readonly ValueRule[]; fileBindings?: readonly string[] },
  registryBindings: readonly string[],
): string[] {
  if (!label.values || !label.fileBindings) return [...label.bindings, ...registryBindings];
  const declared = new Set(declaredAnywhere(label.fileBindings, label.values).map((b) => b.trim().toLowerCase()));
  return [...label.bindings, ...registryBindings.filter((b) => !declared.has(b.trim().toLowerCase()))];
}
