/**
 * value-sources — one secret VALUE held by several labelled sources
 * (docs/design/confidentiality/confidentiality.md §2.1, "One value, several
 * sources", 2026-10-19).
 *
 * A registered file's rows carry exactly its own label's bindings
 * (current-bindings.ts rule 1), and a masked environment variable's row its
 * own `env.sources` hosts (rule 3). Two files that hold the SAME value (a
 * card number in `my-details.yaml` and in `wallet.yaml`, a key in `.env` and
 * in `deploy.yaml`) so mint two rows, each bound to its own file's hosts.
 * Whatever names the value later picks ONE of them: the prompt filter masks a
 * page's or a prompt's copy of the value as the strictest row holding it and,
 * on a tie, the first registered (prompt-filter/engine.ts), the egress
 * tripwire judges every row on its own. So the bindings of the file
 * registered first won, and the second file's were silently ignored
 * (2026-10-19, the browser demos: the expense tool was refused the company
 * card because the car demo's file, bound to the registry only, came first).
 * Fail-closed, but not what the user stated: they labelled both files and
 * bound each.
 *
 * THE RULE. For a SOURCE row (a registered file's own row, or a masked
 * environment variable's), the value is judged by every live source row that
 * holds the identical value (its siblings):
 *
 *   - its LEVEL is the strictest of theirs (`maxConfidentiality`): a model
 *     one source admits and another does not is not cleared (the deep resolve
 *     for the quarantined helper, the in-context read). Every live sibling
 *     counts, whatever its file holds today: a level only narrows.
 *   - its BINDINGS are its own plus every sibling's DECLARED bindings (the
 *     label's `bindings:` / `values:` entry for that row, the `env.sources`
 *     hosts): the union. A binding is the user's explicit allow for the
 *     values of that source to that destination, so the union is exactly
 *     what the user stated about this value. It releases nothing a sibling's
 *     own placeholder is not already released for: every host in the union
 *     is a host some live, trusted, user-labelled row holding these very
 *     bytes is bound to under the law in force.
 *
 * What keeps the union from widening anything else:
 *
 *   - only a source row gets it, and only source rows give it (trusted
 *     integrity, registered by the human plane from a labelled file or the
 *     launch environment): a row minted from a tool result, a derived copy or
 *     the prompt filter's own mint never gains a host from another row;
 *   - only DECLARED hosts cross: a sibling's automatic hosts (a wire grant,
 *     an auth grant) stay with that row, so the wire rules (https only, the
 *     Authorization header only) are never escaped through a sibling;
 *   - a FILE sibling gives its bindings only while its file still holds the
 *     value (read back from disk, at most {@link HOLDS_MAX_BYTES}; an
 *     unreadable, larger or changed file gives nothing): a file edited or
 *     deleted stops speaking for a value it no longer holds, and unlabelling
 *     it empties its declared bindings at once;
 *   - it is per VALUE: a raw holder of a whole file (holder-send-ask,
 *     `holderFileBindings`) and a high session keep their own file's
 *     bindings, since they hold the file's other values too.
 *
 * Nothing is stored: the union is computed from the rows and the law in force
 * at each decision, so it follows a label change at once and survives an
 * arbiter restart exactly as the rows it is computed from do.
 *
 * Mandu-new (no reference origin).
 */
import { readFileSync, statSync } from "fs";
import type { SymbolEntry, SymbolMap } from "../symbol-table/symbol-table.js";
import { symbolMapGeneration } from "../symbol-table/symbol-table.js";
import { isSecret, maxConfidentiality, parseConfidentialityLevel, type ConfidentialityLevel } from "../symbol-table/confidentiality.js";
import { envRowVariable, isRegisteredFileRow, registeredDocumentText } from "./registry.js";

/** A file sibling is read back to see whether it still holds the value only
 *  up to this size; a larger one gives no bindings (fail-closed). */
export const HOLDS_MAX_BYTES = 4 * 1024 * 1024;

/** May this row be a source of its value: a registered file's own row (no
 *  lineage, an absolute origin) or a masked environment variable's row?
 *  Static over a row's life (obsoletion and level are checked live). */
function sourceShaped(e: SymbolEntry): boolean {
  if (envRowVariable(e) !== null) return true;
  return isRegisteredFileRow(e) && e.derived_from === null && typeof e.origin === "string" && e.origin.startsWith("/");
}

/** Is `e` a LIVE source row: source-shaped, active, labelled a secret? */
export function isValueSourceRow(e: SymbolEntry): boolean {
  return e.obsoleted_at === null && sourceShaped(e) && isSecret(parseConfidentialityLevel(e.confidentiality));
}

interface ValueIndex {
  generation: number;
  size: number;
  byValue: Map<string, string[]>;
}

const INDEXES = new WeakMap<SymbolMap, ValueIndex>();

/** The source-shaped rows by value, rebuilt when the table changes. */
function indexOf(symbolMap: SymbolMap): ValueIndex {
  const gen = symbolMapGeneration(symbolMap);
  const have = INDEXES.get(symbolMap);
  if (have && have.generation === gen && have.size === symbolMap.symbols.size) return have;
  const byValue = new Map<string, string[]>();
  for (const [name, e] of symbolMap.symbols) {
    if (!sourceShaped(e) || e.value === "") continue;
    const list = byValue.get(e.value);
    if (list) list.push(name); else byValue.set(e.value, [name]);
  }
  const idx = { generation: gen, size: symbolMap.symbols.size, byValue };
  INDEXES.set(symbolMap, idx);
  return idx;
}

/** The OTHER live source rows holding exactly `entry`'s value; empty unless
 *  `entry` is itself a live source row. */
export function valueSiblings(symbolMap: SymbolMap, entry: SymbolEntry): Array<[string, SymbolEntry]> {
  if (!isValueSourceRow(entry)) return [];
  const out: Array<[string, SymbolEntry]> = [];
  for (const name of indexOf(symbolMap).byValue.get(entry.value) ?? []) {
    const e = symbolMap.symbols.get(name);
    if (!e || e === entry || e.value !== entry.value || !isValueSourceRow(e)) continue;
    out.push([name, e]);
  }
  return out;
}

/** Does a file sibling's file still hold its value (read back, at most
 *  HOLDS_MAX_BYTES)? An environment variable's row: yes (its law, not a
 *  file, says where it may go). Any read failure: no. */
export function sourceHoldsNow(e: SymbolEntry): boolean {
  if (envRowVariable(e) !== null) return true;
  const path = e.origin;
  if (typeof path !== "string") return false;
  try {
    const st = statSync(path);
    if (!st.isFile() || st.size > HOLDS_MAX_BYTES) return false;
    // A PDF or Office document's rows hold values of its TEXT (registry.ts
    // `registeredDocumentText`, secret-discovery.md §2.8).
    return readFileSync(path, "utf8").includes(e.value) || (registeredDocumentText(path)?.includes(e.value) ?? false);
  } catch {
    return false;
  }
}

export interface ValueSourceOptions {
  /** The bindings the law in force DECLARES for a source row (its label's
   *  `bindings:` or `values:` entry, current-bindings.ts
   *  `declaredBindingsReader`; for an env row its `env.sources` hosts):
   *  never the hosts Mandu added on its own. */
  declared: (name: string, e: SymbolEntry) => readonly string[];
  /** Does a sibling still hold its value? Default {@link sourceHoldsNow}. */
  holdsNow?: (e: SymbolEntry) => boolean;
}

/** The strictest level among `entry` and its value's other sources. */
export function valueSourceLevel(symbolMap: SymbolMap, entry: SymbolEntry): ConfidentialityLevel {
  let level = parseConfidentialityLevel(entry.confidentiality);
  for (const [, e] of valueSiblings(symbolMap, entry)) level = maxConfidentiality(level, parseConfidentialityLevel(e.confidentiality));
  return level;
}

/** The hosts `entry`'s value's other sources declare for it (each sibling
 *  that still holds the value), deduplicated; empty for no sibling. */
export function siblingDeclaredBindings(symbolMap: SymbolMap, entry: SymbolEntry, opts: ValueSourceOptions): string[] {
  const holds = opts.holdsNow ?? sourceHoldsNow;
  const out: string[] = [];
  const seen = new Set<string>();
  for (const [name, e] of valueSiblings(symbolMap, entry)) {
    if (!holds(e)) continue;
    for (const b of opts.declared(name, e)) {
      const k = b.trim().toLowerCase();
      if (k === "" || seen.has(k)) continue;
      seen.add(k);
      out.push(b);
    }
  }
  return out;
}

/**
 * The row the release decisions judge for `entry` (the egress gate, the
 * tripwire): `entry` itself when its value has no other source, else a COPY
 * with the strictest level of the sources and its own bindings plus the
 * siblings' declared ones. The stored row is never changed.
 */
export function valueSourceView(symbolMap: SymbolMap, entry: SymbolEntry, opts: ValueSourceOptions): SymbolEntry {
  if (valueSiblings(symbolMap, entry).length === 0) return entry;
  const own = entry.bindings ?? [];
  const have = new Set(own.map((b) => b.trim().toLowerCase()));
  const extra = siblingDeclaredBindings(symbolMap, entry, opts).filter((b) => !have.has(b.trim().toLowerCase()));
  const bindings = [...own, ...extra];
  return { ...entry, confidentiality: valueSourceLevel(symbolMap, entry), bindings: bindings.length > 0 ? bindings : null };
}
