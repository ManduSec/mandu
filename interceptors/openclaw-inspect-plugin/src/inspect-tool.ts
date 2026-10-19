/**
 * inspect-tool — the OpenClaw plugin tool wrapping the Mandu inspect core.
 *
 * Mandu U-LLM channel for OpenClaw (interceptors/openclaw-inspect-plugin).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PROVENANCE (a REVERSE lift — Mandu code into an OpenClaw plugin shape):
 *   - The AnyAgentTool OBJECT SHAPE ({name, label, description, parameters,
 *     async execute(toolCallId, params) → {content:[{type:"text",…}]}}) is
 *     lifted from the reference plugin's tool factory,
 *       https://github.com/compsec-snu/dualview/tree/main/plugin/dualview
 *         dualview-inspect-symbol.ts (`createInspectSymbolTool`).
 *   - The tool NAME, DESCRIPTION, and PARAMETER SCHEMA are reused verbatim
 *     from interceptors/inspect-mcp/src/mcp-server.ts INSPECT_SYMBOL_TOOL
 *     (single or multiple symbols + instruction + optional output format,
 *     so both mounts of the same
 *     core present the identical tool to their models).
 *   - The SECURITY CORE is NOT lifted, NOT copied, NOT reimplemented: execute
 *     calls interceptors/inspect-mcp/src/inspect-symbol.ts `inspectSymbol()`
 *     (resolve via arbiter → quarantined U-LLM → RE-SYMBOLIZE → emit,
 *     fail-closed) with the same InspectSymbolDeps the MCP server injects.
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * SHAPE CONTRACT (do not drift — mirrors mcp-server.ts's success builder):
 * the arbiter's inbound data-trust policy trusts an inspect result ONLY when
 * it is pure-symbolic — a $MDU:* token plus the
 * { result_symbol, model, content_kind, next_step? } envelope
 * (arbiter/policy/claude-code-inbound.ts classifyManduInspectResult /
 * isPureSymbolicInspectResult). Claude Code reaches that shape by serializing
 * the MCP content text + structuredContent; OpenClaw has no structuredContent,
 * so this tool returns TWO text blocks — [the bare token][the JSON envelope] —
 * which the pi-ai Anthropic provider forwards verbatim as tool_result content
 * blocks and the anthropic-proxy flattens to `<token>{...}`: exactly accepted
 * form 3 of isPureSymbolicInspectResult (token + envelope, whitespace-
 * tolerant). `content_kind` is a validated token from the closed
 * CONTENT_KINDS vocabulary (raw triage model text never reaches the
 * envelope); `next_step` is the FIXED
 * TCB string from NEXT_STEP_BY_KIND — the policy accepts the key only on an
 * EXACT match keyed off content_kind. Adding any other key or free-text value
 * re-enables the (harmless, fail-closed) double-wrap until the arbiter rule
 * is updated in the same change. ERROR results are intentionally NOT
 * trusted-shaped: a single prose text block (their strings can embed upstream
 * error bodies that may echo the raw untrusted value, so they must stay on
 * the symbolize path).
 */

import {
  inspectSymbol,
  NEXT_STEP_BY_KIND,
  type InspectSymbolDeps,
  type InspectSymbolResult,
  type InspectSymbolParams,
} from "../../inspect-mcp/src/inspect-symbol.js";
import { INSPECT_SYMBOL_TOOL } from "../../inspect-mcp/src/mcp-server.js";
import type { PluginAgentTool, PluginToolResult } from "./openclaw-api.js";

/** The OpenClaw tool name. Deliberately the bare MCP tool name (no `mcp__`
 * server prefix — OpenClaw plugin tools have none): the arbiter's
 * openclaw-agent inbound spec must key its pure-symbolic trust rule on
 * exactly this string. */
export const INSPECT_TOOL_NAME: string = INSPECT_SYMBOL_TOOL.name;

/** Lazy dependency provider. The arbiter connection is established on FIRST
 * use (plugin registration must be synchronous — OpenClaw ignores async
 * register — while the arbiter IPC connect is async). A rejection means the
 * arbiter/U-LLM channel is unavailable: the tool REFUSES (fail closed),
 * never runs symbol-less. */
export type GetInspectDeps = () => Promise<InspectSymbolDeps>;

/** Build the tool result for a core InspectSymbolResult. Exported for the
 * shape-contract unit tests. */
export function buildInspectToolResult(result: InspectSymbolResult): PluginToolResult {
  if (!result.ok) {
    // NOT trusted-shaped, on purpose: one prose block the arbiter's inbound
    // gate fail-closes to symbolize (see the header). No raw untrusted text
    // appears here by inspect-symbol.ts's own contract, but the shape must
    // not be distinguishable-as-trusted either way.
    return { content: [{ type: "text", text: result.error }] };
  }
  const nextStep = NEXT_STEP_BY_KIND[result.contentKind];
  const envelope = {
    result_symbol: result.resultSymbol,
    model: result.model,
    content_kind: result.contentKind,
    ...(nextStep !== undefined ? { next_step: nextStep } : {}),
  };
  return {
    content: [
      // Block 1: the bare re-symbolized token (what T-LLM should use).
      { type: "text", text: result.resultSymbol },
      // Block 2: the envelope — same keys/values as the MCP structuredContent.
      { type: "text", text: JSON.stringify(envelope) },
    ],
    // UI/transcript metadata only (never model context) — and pure-symbolic
    // anyway, so it could leak nothing even if a surface rendered it.
    details: envelope,
  };
}

/**
 * Create the inspect_symbol plugin tool. One tool object per OpenClaw tool
 * resolution (the registrar's factory closes over per-session context).
 */
export function createInspectSymbolPluginTool(getDeps: GetInspectDeps): PluginAgentTool {
  return {
    name: INSPECT_SYMBOL_TOOL.name,
    label: "Inspect Symbol",
    // Model-visible by its bare name on OpenClaw 2026.9.x, whose Tool Search
    // otherwise catalogs plugin tools: the handling prompt names this tool,
    // and a direct call to a cataloged one fails "Tool … not found"
    // (docs/design/testing/agent-e2e-harness.md §8.6).
    catalogMode: "direct-only",
    // Verbatim reuse: the same model-facing guidance (content_kind semantics,
    // re-fetch-on-failure routing) both mounts teach.
    description: INSPECT_SYMBOL_TOOL.description,
    parameters: INSPECT_SYMBOL_TOOL.inputSchema,
    async execute(_toolCallId, params) {
      // Mirror mcp-server.ts's coercion: absent/mis-typed params become empty
      // strings, which the core refuses with its own T-LLM-safe messages.
      const symbol = params?.symbol as string | undefined;
      const symbols = params?.symbols as string[] | undefined;
      const instruction = typeof params?.instruction === "string" ? params.instruction : "";

      let deps: InspectSymbolDeps;
      try {
        deps = await getDeps();
      } catch (err) {
        // Arbiter (or U-LLM) channel unavailable → REFUSE, fail closed. There
        // is deliberately no degraded mode: no arbiter means no symbol table
        // and no re-symbolization, so the inspect must not run at all.
        return {
          content: [
            {
              type: "text",
              text: `inspect_symbol: Mandu arbiter unavailable, refusing (fail closed): ${msgOf(err)}`,
            },
          ],
        };
      }

      let result: InspectSymbolResult;
      try {
        result = await inspectSymbol(deps, { symbol, symbols, instruction, output_format: params?.output_format as InspectSymbolParams["output_format"] });
      } catch (err) {
        // Defensive: inspectSymbol is itself fail-closed, but never let an
        // unexpected throw escape the tool (OpenClaw would surface the raw
        // Error). Report a plain error with no raw text — same play as
        // mcp-server.ts's handleToolsCall.
        return {
          content: [{ type: "text", text: `inspect_symbol: internal error: ${msgOf(err)}` }],
        };
      }

      return buildInspectToolResult(result);
    },
  };
}

function msgOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
