/**
 * cell-guard — the run-time guard the openai-proxy puts at the head of every
 * Codex code-mode cell it cannot identify call by call: before the model's
 * code runs, every nested tool Mandu has not mapped is replaced on the `tools`
 * object by a function that throws, and the cell's `store` / `load` are kept
 * to the guarded cells' own keys (confidentiality-plan-10-flow-taint.md
 * §11.18, "The cell guard", 2026-10-11).
 *
 * Mandu Track A (interceptors/openai-proxy). Why: a cell is JavaScript, so
 * what it calls cannot be read off its text in general (`x[k]` with `k`
 * spelling `constructor` reaches the Function constructor, and from there
 * `tools` by a string). !1294 masked a cell whole on what its text MAY call;
 * this guard decides at run time instead, where every way to a tool ends at
 * the one `tools` object.
 *
 * What it relies on, each measured on the real codex-cli 0.162.0 against a
 * scripted model (the drill suite's `codex-cell-tools-guard.test.ts`):
 *
 *   - every nested tool is an own data property of the global `tools`,
 *     configurable, on an extensible object; a property made non-writable
 *     and non-configurable cannot be deleted, redefined or assigned, and
 *     `Object.preventExtensions` stops a new one;
 *   - a tool function is bound to its tool: calling `exec_command` with
 *     another `this` (`call`, `apply`, `bind`, `Reflect.apply`) still runs
 *     `exec_command`;
 *   - `ALL_TOOLS` holds `{name, description}` only; `globalThis.tools`,
 *     `(0, eval)("tools")` and `Function("return this")().tools` are the
 *     same object; a static or dynamic `import` is refused ("Unsupported
 *     import in exec"), so no code runs before the guard;
 *   - each cell is a fresh isolate (cellsAreIsolated): the guard runs in
 *     every guarded cell, and nothing an earlier cell defined survives,
 *     except `store`d values, which must be serializable (a function is
 *     refused) and are kept by key; the guard keeps a guarded cell's keys
 *     under its own prefix, so a guarded `load` never reads a value an
 *     unguarded cell stored.
 *
 * Fail closed: if a tool to switch off cannot be (a non-configurable
 * property that is not the guard's own), or `store` / `load` cannot be
 * replaced, the guard throws before the model's code runs. The request side
 * trusts a cell's guard only when the cell starts with EXACTLY the text
 * `guardPrelude(keep)` writes and every kept name is still mapped; anything
 * else keeps the text rules of cell-resource-tools.ts.
 *
 * Pure and total: never throws.
 */

/** The guard's first bytes (its marker); the keep list follows. */
const HEAD = "/* mandu: nested tools Mandu has not mapped are switched off in this cell */(()=>{const k=new Set(";
/** The guard after its keep list. */
const TAIL =
  "),O=Object,t=tools,off=(n)=>{const f=()=>{throw new Error(\"Mandu: \"+n+\" is switched off inside code cells: Mandu has no mapping for it, so its result could carry a secret. Call it as its own tool call, or ask the user to list it under mapped_tools: in policy.yaml\")};O.defineProperty(f,\"manduOff\",{value:true});return f};" +
  "for(const n of Reflect.ownKeys(t)){if(k.has(n))continue;const d=O.getOwnPropertyDescriptor(t,n);if(d&&!d.configurable){if(d.value&&d.value.manduOff===true)continue;throw new Error(\"Mandu: cannot switch off \"+String(n)+\"; the cell did not run\")}O.defineProperty(t,n,{value:off(String(n)),writable:false,configurable:false,enumerable:true})}O.preventExtensions(t);" +
  "const g=globalThis,sd=O.getOwnPropertyDescriptor(g,\"store\");if(!(sd&&sd.value&&sd.value.manduOff===true)){const st=g.store,ld=g.load,sv=(key,v)=>st(\"mandu:\"+key,v),lv=(key)=>ld(\"mandu:\"+key);O.defineProperty(sv,\"manduOff\",{value:true});O.defineProperty(g,\"store\",{value:sv,writable:false,configurable:false});O.defineProperty(g,\"load\",{value:lv,writable:false,configurable:false})}})();\n";

/** The pragma codex reads off a cell's first line (`// @exec: {…}`): it must
 *  stay first, so the guard goes after it. */
const PRAGMA_RE = /^\/\/ @exec:[^\n]*\n/;
/** A nested tool name the guard keeps: a plain identifier. */
const NAME_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

/** The guard's text for a keep list (sorted, deduplicated). */
export function guardPrelude(keep: readonly string[]): string {
  const names = [...new Set(keep.filter((n) => NAME_RE.test(n)))].sort();
  return `${HEAD}${JSON.stringify(names)}${TAIL}`;
}

/** The cell with the guard put at its head (after a pragma line). */
export function guardCell(src: string, keep: readonly string[]): string {
  const m = PRAGMA_RE.exec(src);
  const pragma = m ? m[0] : "";
  return `${pragma}${guardPrelude(keep)}${src.slice(pragma.length)}`;
}

/** A guarded cell split into its keep list and the model's own code, when
 *  the cell starts (after a pragma line) with exactly the guard's text; null
 *  otherwise. */
export function splitGuardedCell(src: unknown): { keep: string[]; body: string } | null {
  if (typeof src !== "string") return null;
  const m = PRAGMA_RE.exec(src);
  const pragma = m ? m[0] : "";
  const rest = src.slice(pragma.length);
  if (!rest.startsWith(HEAD)) return null;
  const end = rest.indexOf(TAIL, HEAD.length);
  if (end < 0) return null;
  let keep: unknown;
  try { keep = JSON.parse(rest.slice(HEAD.length, end)); } catch { return null; }
  if (!Array.isArray(keep) || !keep.every((n) => typeof n === "string" && NAME_RE.test(n))) return null;
  const prelude = guardPrelude(keep as string[]);
  if (!rest.startsWith(prelude)) return null;
  return { keep: keep as string[], body: `${pragma}${rest.slice(prelude.length)}` };
}

/** The nested tool names a cell's text writes: `tools.NAME`, `tools?.NAME`,
 *  `tools["NAME"]`, and any `mcp__…` identifier anywhere. The guard asks
 *  about each (a name it does not write is switched off unless it is one of
 *  codex's own). */
export function writtenToolNames(src: string): string[] {
  const out = new Set<string>();
  for (const m of src.matchAll(/(?<![A-Za-z0-9_$])tools\s*(?:\?\.|\.)\s*([A-Za-z_$][A-Za-z0-9_$]*)/g)) out.add(m[1]!);
  for (const m of src.matchAll(/(?<![A-Za-z0-9_$])tools\s*(?:\?\.\s*)?\[\s*(?:"([A-Za-z_$][A-Za-z0-9_$]*)"|'([A-Za-z_$][A-Za-z0-9_$]*)')\s*\]/g)) out.add((m[1] ?? m[2])!);
  for (const m of src.matchAll(/(?<![A-Za-z0-9_$])mcp__[A-Za-z0-9_$]+/g)) out.add(m[0]);
  return [...out];
}
