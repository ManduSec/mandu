/** Multi-input derived labels. NEW Mandu code; symbol-quality.md §7.
 * Join source restrictions at the arbiter, independent of client claims.
 */
import {
  getSymbolEntry,
  resolveAllSymbolsDeep,
  type SymbolEntry,
  type SymbolMap,
} from "./symbol-table.js";
import { maxConfidentiality, parseConfidentialityLevel, type ConfidentialityLevel } from "./confidentiality.js";

export function sourceLabel(map: SymbolMap, symbols: unknown): { level: ConfidentialityLevel; bindings?: string[] } {
  if (!Array.isArray(symbols) || symbols.length < 1 || symbols.length > 16 || symbols.some((s) => typeof s !== "string")) throw new Error("Invalid derived source symbol list");
  let level: ConfidentialityLevel = "public";
  let bindings: string[] | undefined;
  const inherit = (entry: SymbolEntry): boolean => {
    const current = parseConfidentialityLevel(entry.confidentiality);
    level = maxConfidentiality(level, current);
    if (current !== "public") {
      const allowed = entry.bindings ?? [];
      bindings = bindings === undefined ? [...allowed] : bindings.filter((b) => allowed.includes(b));
    }
    return current === "no-model";
  };
  for (const symbol of symbols) {
    const entry = getSymbolEntry(map, symbol);
    if (!entry) throw new Error("Unknown derived source symbol");
    if (inherit(entry)) continue;
    // Inspection resolves wrappers deeply, so their nested source restrictions
    // must travel with the output too. Reuse the resolver's candidate matching,
    // depth/size bounds and strict-symbol skip rather than walking another graph.
    // Conservatively inherit an encountered strict label, but never expand its
    // value. The expanded text remains internal and is deliberately discarded.
    resolveAllSymbolsDeep(entry.value, map, undefined, inherit);
  }
  return { level, ...(bindings !== undefined ? { bindings: [...new Set(bindings)].sort() } : {}) };
}
