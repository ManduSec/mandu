/**
 * cell-resource-tools — the Codex MCP resource tools that a code-mode
 * cell may call, read off the cell's source (confidentiality-plan-10-flow-taint.md
 * §11.18, "A cell's resource tools", 2026-10-11).
 *
 * Mandu Track A (interceptors/openai-proxy). codex-cli 0.162's code mode
 * declares `read_mcp_resource`, `list_mcp_resources` and
 * `list_mcp_resource_templates` as nested tools of every `exec` cell, even
 * with no MCP server configured (supported-agents.md §6.4). A direct call to
 * one is masked whole (§11.18: they read a server the model names, so no
 * mapping can vouch for them). A cell calling one was classified as an
 * `exec` cell, a built-in, which only the session rule masks: in a session
 * where nothing read a secret raw, a resource reached the model raw through
 * a cell, including a copy of a registered secret the value backstop cannot
 * match (an MCP `blob` is base64) from a server the guard does not run.
 *
 * The rule: a cell the allow-list grammar (mcp-cell.ts) does not identify
 * call by call is read for the resource tools it may call, and the proxy asks
 * the arbiter about each exactly as about the direct call. A cell MAY call
 * them when its source:
 *
 *   - names one: any identifier-like run holding `mcp_resource`, anywhere
 *     (strings and comments included, so `tools["read_mcp_resource"]`, a
 *     destructuring and a renamed tool all count), asked under that name;
 *     and (2026-10-11) any `mcp__<server>__<tool>` it names, asked as that
 *     tool's direct call is (an unregistered server's is masked whole; a
 *     cell calling one had only the cell rule too);
 *   - can call a nested tool by a name it does not spell, or read what an
 *     earlier cell stored: `tools` other than as `tools.NAME`,
 *     `tools?.NAME` or `tools["NAME"]` (a computed name, `Object.keys(tools)`,
 *     an alias), a way to the global object or to code built from a string
 *     (`globalThis`, `eval`, `Function`, `constructor`, `Reflect`, `import`,
 *     `require`, `__proto__`, `getPrototypeOf`), a `\u` escape (an
 *     identifier may be spelled with one), or codex's `load` (a value an
 *     earlier cell `store`d, which may be a resource that cell read): asked
 *     as each of the three.
 *
 * DENY-LIST, so it over-approximates: a word in a string or a comment counts
 * as code. What it cannot see: a computed property key built at run time
 * (`x[k]` with `k` spelling `constructor` from pieces) reaches the Function
 * constructor and from there the `tools` object by a string. The run-time
 * cell guard (cell-guard.ts) closes that: the proxy delivers every cell it
 * cannot identify with the tools Mandu has not mapped switched off, and a
 * cell that carries the guard (verified on the request side) is not asked
 * about here. This text rule stays the fallback for a cell without one.
 *
 * Pure and total: never throws.
 */

/** Codex's MCP resource tools (codex-cli 0.159.1 to 0.162.0, read off the
 *  wire): each reads a server named by the model's own text. */
export const CODEX_RESOURCE_TOOLS: readonly string[] = ["read_mcp_resource", "list_mcp_resources", "list_mcp_resource_templates"];

/** The resource tools a cell may call, and why (for the note the model
 *  reads), or null when it calls none. */
export interface CellResourceTools {
  tools: string[];
  why: string;
  /** The cell carries the proxy's run-time guard (cell-guard.ts) with this
   *  keep list: when every kept tool is still mapped, the guard switched the
   *  rest off before the cell's code ran, and `tools` is not asked. */
  guardKeep?: string[];
}

/** A name run holding `mcp_resource` (identifier characters around it). */
const NAMED_RE = /[A-Za-z0-9_$]*mcp_resource[A-Za-z0-9_$]*/g;
/** An MCP tool name as codex spells it in a cell (`mcp__<server>__<tool>`). */
const MCP_NAMED_RE = /(?<![A-Za-z0-9_$])mcp__[A-Za-z0-9_$]+__[A-Za-z0-9_$]+/g;
/** The `tools` global, as a whole word (`ALL_TOOLS` is another word). */
const TOOLS_RE = /(?<![A-Za-z0-9_$])tools(?![A-Za-z0-9_$])/g;
/** What may follow `tools` for the access to name its tool: `.NAME`,
 *  `?.NAME`, or a bracketed plain string literal (no escape, no newline). */
const STATIC_MEMBER_RE = /^\s*(?:\?\.|\.)\s*[A-Za-z_$][A-Za-z0-9_$]*|^\s*(?:\?\.\s*)?\[\s*(?:"[^"\\\n]*"|'[^'\\\n]*')\s*\]/;
/** Ways to the global object, to code built from a string, or to a value an
 *  earlier cell stored. */
const REACH_RE = /(?<![A-Za-z0-9_$])(globalThis|eval|Function|constructor|Reflect|import|require|__proto__|getPrototypeOf|load)(?![A-Za-z0-9_$])/;

/**
 * The resource tools a cell's source may call (see the module comment).
 * Callers apply it only to a cell the grammar does not identify call by call.
 */
export function cellResourceTools(src: unknown): CellResourceTools | null {
  if (typeof src !== "string" || src === "") return null;
  // the resource tools it names, and (2026-10-11, the follow-up) every MCP
  // tool it names: an unregistered server's tool is masked whole as a
  // direct call (§11.18), and a cell calling one had only the cell rule
  const named = [...new Set([...(src.match(NAMED_RE) ?? []), ...(src.match(MCP_NAMED_RE) ?? [])])];
  const reach = dynamicReach(src);
  if (named.length === 0 && reach === null) return null;
  const tools = reach === null ? named : [...new Set([...named, ...CODEX_RESOURCE_TOOLS])];
  const why = reach === null
    ? `calls ${named.join(", ")}`
    : named.length > 0
      ? `calls ${named.join(", ")} and ${reach}`
      : `${reach}, so it may call ${CODEX_RESOURCE_TOOLS.join(", ")}`;
  return { tools, why };
}

/** Why the cell may reach a nested tool it does not name, or null. */
function dynamicReach(src: string): string | null {
  if (src.includes("\\u")) return "spells something with a \\u escape (a tool name may hide in one)";
  for (const m of src.matchAll(TOOLS_RE)) {
    if (!STATIC_MEMBER_RE.test(src.slice(m.index! + m[0].length))) return "uses `tools` other than by a written tool name";
  }
  const r = REACH_RE.exec(src);
  if (r) return r[1] === "load" ? "reads a value an earlier cell stored (`load`)" : `uses \`${r[1]}\` (a way to a tool by a name it does not write)`;
  return null;
}
