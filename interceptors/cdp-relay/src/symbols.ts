/**
 * symbols — the `$MDU:*` placeholder pattern, mirrored from
 * arbiter/symbol-table/symbol-table.ts `SYMBOL_PATTERN` (the relay is
 * dependency-free of the arbiter package, as net-proxy's egress.ts is).
 * Mandu-new (no reference origin).
 */

/** A FRESH global RegExp each call (the global flag carries lastIndex). */
export function symbolPattern(): RegExp {
  return /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*|\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/g;
}

/** The longest code a placeholder LOOKALIKE may have between its brackets
 *  (a UUID has 36 characters): any longer, the text is prose, typed as it
 *  is. Bounds a key run too (typing.ts). */
export const LOOKALIKE_MAX_CODE = 64;

/** A placeholder LOOKALIKE (docs/design/agents/devtools-relay.md §3.2): the
 *  placeholder's shape (`$MDU:` + a kind + `[` + a code + `]` + `.NAME`
 *  parts) with any code of 1 to LOOKALIKE_MAX_CODE characters that are
 *  neither whitespace nor `]`. Every placeholder is one; `findLookalikes`
 *  keeps the ones that are not placeholders (a UUID, dashes, uppercase hex,
 *  a code too long or too short). A FRESH global RegExp each call. */
export function lookalikePattern(): RegExp {
  return /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[^\s\]]{1,64}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*/g;
}

/** Whether `s` is exactly one placeholder. Pure. */
export function wholePlaceholder(s: string): boolean {
  return new RegExp(`^(?:${symbolPattern().source})$`).test(s);
}

/** Whether `s` is exactly one lookalike that is not a placeholder. Pure. */
export function wholeLookalike(s: string): boolean {
  return new RegExp(`^(?:${lookalikePattern().source})$`).test(s) && !wholePlaceholder(s);
}

/** The lookalikes in `text` that are not placeholders, first occurrence
 *  first, de-duplicated. Each names nothing (the arbiter mints only
 *  placeholders), so no lookup is needed to refuse it. Pure. */
export function findLookalikes(text: string): string[] {
  if (!text || !text.includes("$MDU:")) return [];
  const seen = new Set<string>();
  for (const m of text.matchAll(lookalikePattern())) if (!wholePlaceholder(m[0])) seen.add(m[0]);
  return [...seen];
}

/** The placeholders in `text`, first occurrence first, de-duplicated. */
export function findSymbols(text: string): string[] {
  if (!text || !text.includes("$MDU:")) return [];
  const seen = new Set<string>();
  for (const m of text.matchAll(symbolPattern())) seen.add(m[0]);
  return [...seen];
}

/** `text` with each placeholder replaced by its value in `values`. Every
 *  placeholder found must have a value (the caller decided each one). */
export function substituteSymbols(text: string, values: ReadonlyMap<string, string>): string {
  return text.replace(symbolPattern(), (s) => {
    const v = values.get(s);
    if (v === undefined) throw new Error(`no decision for ${s}`);
    return v;
  });
}
