/**
 * inspect-tool — ONE definition of "this tool_result came from the Mandu
 * U-LLM inspect channel", across every agent's namespacing convention.
 *
 * Mandu-new module. Design: docs/design/testing/agent-e2e-harness.md §7.2 (the
 * multi-agent U-LLM channel), symbol-quality.md §8, symbol-quality.md.
 *
 * WHY THIS EXISTS: the inspect tool is ONE tool that Mandu itself mounts, but
 * each agent runtime names it differently, and the name is what the trust rule
 * keys on:
 *
 *   Claude Code (MCP)   mcp__mandu-inspect__inspect_symbol   (double underscore)
 *   OpenCode (MCP)      mandu-inspect_inspect_symbol         (SINGLE underscore)
 *   Goose (MCP)         mandu-inspect__inspect_symbol        (extension key + "__")
 *   OpenClaw (plugin)   inspect_symbol                         (no namespace at all)
 *
 * Before this module the recognition was a single hard-coded Claude Code string,
 * so on the other two agents the inspect result missed the rule and fell to the
 * fail-closed default. That is SAFE (the envelope gets symbolized again —
 * over-symbolization, never under) but it DOUBLE-WRAPS the answer: the model
 * receives a symbol whose content is another symbol, which is exactly the
 * utility the quarantine exists to provide, destroyed.
 *
 * WHY AN EXACT-NAME SET, NOT A REGEX: the matched name unlocks the hybrid
 * pure-symbolic trust rule (claude-code-inbound.ts classifyManduInspectResult),
 * so a loose pattern like /inspect_symbol$/ would extend that rule to any tool
 * a third party happens to name similarly. The set below is derived from ONE
 * server name and ONE tool basename, and every member is a spelling Mandu
 * itself produces when it mounts the channel. Everything else falls through to
 * the ordinary fail-closed path.
 *
 * SECURITY NOTE on the bare `inspect_symbol` spelling (OpenClaw's plugin has no
 * namespace to prefix): a tool NAME on a tool_result is not attacker-chosen —
 * it comes from the agent runtime's own tool registry, echoed from the model's
 * tool_use block, and a name the runtime does not know is rejected before
 * dispatch. And even a match here grants nothing but the pure-symbolic shape
 * check: an opaque token, a bounded model id, and one of a fixed set of
 * content_kind tokens. No prose, no instruction channel.
 */

/** The MCP server / plugin id Mandu mounts the inspect channel under. */
export const MANDU_INSPECT_SERVER = "mandu-inspect";

/** The tool's own (unnamespaced) name. */
export const INSPECT_TOOL_BASENAME = "inspect_symbol";

/** The DECLASSIFY sibling (rung 3), same namespacing rules. */
export const DECLASSIFY_TOOL_BASENAME = "declassify_symbol";

/** Every spelling of a tool basename Mandu's own mount can produce. */
function spellingsOf(basename: string): readonly string[] {
  return [
    // Claude Code MCP: mcp__<server>__<tool>
    `mcp__${MANDU_INSPECT_SERVER}__${basename}`,
    // OpenCode MCP: <server>_<tool> (single underscore — read off the wire)
    `${MANDU_INSPECT_SERVER}_${basename}`,
    // Codex MCP (0.154): the model calls the tool as {name: <tool>, namespace:
    // "mcp__<server with - → _>"}; the openai-proxy joins the two with "__".
    // Read off a live codex exec against a recording Responses server
    // (2026-09-25): namespace "mcp__mandu_inspect".
    `mcp__${MANDU_INSPECT_SERVER.replace(/-/g, "_")}__${basename}`,
    // Goose: <extension key>__<tool>, the key kept as the launcher names it
    // (`--with-extension 'mandu-inspect:<cmd>'`). Read off goose 1.53.0's
    // wire, 2026-10-05 (test/fixtures/goose-tool-surface-2026-10-05.json).
    `${MANDU_INSPECT_SERVER}__${basename}`,
    // OpenClaw plugin tool: registered bare, no namespace (no MCP client)
    basename,
  ];
}

const INSPECT_TOOL_NAMES: ReadonlySet<string> = new Set(spellingsOf(INSPECT_TOOL_BASENAME));
const DECLASSIFY_TOOL_NAMES: ReadonlySet<string> = new Set(spellingsOf(DECLASSIFY_TOOL_BASENAME));

/** The EXACT Claude Code spelling. Kept as a named export because the policy
 *  snapshot and the handling prompt name the tool the model will actually see
 *  under the default (claude-code) spec. */
export const MANDU_INSPECT_TOOL = `mcp__${MANDU_INSPECT_SERVER}__${INSPECT_TOOL_BASENAME}`;

/** Is this tool_result from the Mandu inspect channel, on ANY agent? */
export function isManduInspectTool(toolName: string): boolean {
  return INSPECT_TOOL_NAMES.has(toolName);
}

/** Is this the Mandu declassify (rung 3) tool, on ANY agent? */
export function isManduDeclassifyTool(toolName: string): boolean {
  return DECLASSIFY_TOOL_NAMES.has(toolName);
}

/** Either Mandu-internal quarantine tool. */
export function isManduQuarantineTool(toolName: string): boolean {
  return isManduInspectTool(toolName) || isManduDeclassifyTool(toolName);
}

/** Every recognized inspect spelling — for tests and for the docs that must
 *  enumerate what the trust rule accepts. */
export const INSPECT_TOOL_SPELLINGS: readonly string[] = [...INSPECT_TOOL_NAMES];
