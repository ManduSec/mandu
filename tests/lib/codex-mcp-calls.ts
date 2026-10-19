/**
 * codex-mcp-calls — every MCP tool call a Codex model made, read off the
 * Responses requests Codex sent (codex-mcp.test.ts; the wire
 * shapes are interceptors/openai-proxy/src/responses-types.ts's header).
 *
 * Codex spells an MCP call two ways, and a run may use both:
 *   - the classic wire: a `function_call` item whose `namespace` is the
 *     server (`mcp__mandu_policy`) and whose `name` is the tool's own name;
 *   - the script-cell wire (codex ≥ 0.154, `code_mode_host`): a
 *     `custom_tool_call` named `exec` whose `input` is JavaScript calling the
 *     tool on the `tools` global, `tools.mcp__mandu_policy__mandu_policy_read({…})`
 *     or `tools["mcp__…"](…)`. Live 2026-10-01 (codex-cli 0.159.1, the ChatGPT
 *     backend's gpt-6.1-sol): every call of the run rode this wire, so a
 *     classic-only reader saw none and CMCP-1 failed on a run whose policy
 *     calls had worked.
 * A dynamic call (`tools[name](…)`) names no tool and is not counted.
 */

const CELL_CALL_RE = /\btools\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*(["'`])([^"'`]+)\2\s*\])\s*\(/g;

/** Every MCP call in the bodies, as `<namespace>__<name>` (the classic join). */
export function mcpCallsIn(bodies: string[]): Set<string> {
  const out = new Set<string>();
  for (const b of bodies) {
    let doc: { input?: unknown };
    try { doc = JSON.parse(b) as { input?: unknown }; } catch { continue; }
    if (!Array.isArray(doc.input)) continue;
    for (const item of doc.input as Array<Record<string, unknown>>) {
      if (item["type"] === "function_call" && typeof item["namespace"] === "string") {
        out.add(`${item["namespace"]}__${String(item["name"])}`);
      } else if (item["type"] === "custom_tool_call" && typeof item["input"] === "string") {
        for (const m of item["input"].matchAll(CELL_CALL_RE)) {
          const name = m[1] ?? m[3]!;
          if (name.startsWith("mcp__")) out.add(name);
        }
      }
    }
  }
  return out;
}
