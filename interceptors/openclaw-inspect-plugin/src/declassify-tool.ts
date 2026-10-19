/**
 * declassify-tool — the OpenClaw plugin tool for `declassify_symbol` (§3.3
 * rung 3, the in-context read), the sibling of inspect-tool.ts.
 *
 * Mandu U-LLM channel for OpenClaw (interceptors/openclaw-inspect-plugin),
 * 2026-09-29 (supported-agents.md §5.5 item 3; agent-e2e-harness.md §8.5).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PROVENANCE
 *   - The tool NAME, DESCRIPTION and PARAMETER SCHEMA are reused verbatim from
 *     interceptors/inspect-mcp/src/mcp-server.ts DECLASSIFY_SYMBOL_TOOL, so the
 *     OpenClaw model is offered the identical tool Claude Code and OpenCode
 *     see over MCP.
 *   - The RELAY is interceptors/inspect-mcp/src/declassify-symbol.ts
 *     `declassifySymbol()`, the one the MCP server runs. The arbiter decides
 *     (refusals, the human approval queue, the watermark raised before the
 *     value is handed over); nothing here decides or falls back.
 *   - The tool object shape is the one inspect-tool.ts builds (pi-agent-core
 *     AgentTool, lifted from the reference plugin).
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * SHAPE CONTRACT: a released value comes back as ONE text block, the relay's
 * `[DECLASSIFIED …]` line, a blank line, then the value. The proxy flattens a
 * one-block result to exactly that string, which is the form the arbiter's
 * declassify result rule accepts (arbiter/ipc/server.ts
 * declassifyResultTrusted). Refusals are one prose block with no content.
 * No `details`: the value must not be copied into OpenClaw's UI metadata.
 *
 * THE SESSION (fail closed): the arbiter raises the watermark on the session
 * the call names, and the model proxy gates the session the launcher named
 * (`scopeId`). OpenClaw's own session key is a different string, so a release
 * under it would leave the proxy's session looking clean while the model holds
 * the secret. The deps provider therefore REFUSES when no Mandu scope is
 * configured (register.ts), rather than falling back as inspect_symbol may.
 */

import { declassifySymbol, type DeclassifyDeps } from "../../inspect-mcp/src/declassify-symbol.js";
import { DECLASSIFY_SYMBOL_TOOL } from "../../inspect-mcp/src/mcp-server.js";
import type { PluginAgentTool } from "./openclaw-api.js";

/** The OpenClaw tool name: the bare MCP tool name (plugin tools carry no
 *  namespace). arbiter/policy/inspect-tool.ts recognizes this spelling. */
export const DECLASSIFY_TOOL_NAME: string = DECLASSIFY_SYMBOL_TOOL.name;

/** Lazy dependency provider: the arbiter connection and the Mandu session. A
 *  rejection means the channel is unavailable, and the tool refuses. */
export type GetDeclassifyDeps = () => Promise<DeclassifyDeps>;

export function createDeclassifySymbolPluginTool(getDeps: GetDeclassifyDeps): PluginAgentTool {
  return {
    name: DECLASSIFY_SYMBOL_TOOL.name,
    label: "Declassify Symbol",
    // Model-visible by its bare name on OpenClaw 2026.9.x, whose Tool Search
    // otherwise catalogs plugin tools: the handling prompt names this tool,
    // and a direct call to a cataloged one fails "Tool … not found"
    // (docs/design/testing/agent-e2e-harness.md §8.6).
    catalogMode: "direct-only",
    description: DECLASSIFY_SYMBOL_TOOL.description,
    parameters: DECLASSIFY_SYMBOL_TOOL.inputSchema,
    async execute(_toolCallId, params) {
      let deps: DeclassifyDeps;
      try {
        deps = await getDeps();
      } catch (err) {
        // No arbiter (or no Mandu session) → no gate and no watermark, so no
        // release. There is no degraded mode.
        return {
          content: [{ type: "text", text: `declassify_symbol: Mandu arbiter unavailable, refusing (fail closed): ${msgOf(err)}` }],
        };
      }
      const out = await declassifySymbol(deps, params);
      return { content: [{ type: "text", text: out.ok ? out.text : out.error }] };
    },
  };
}

function msgOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
