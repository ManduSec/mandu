/**
 * agent-receipt — which tool results the AGENT process itself produced from
 * what it received over its own connections (confidentiality plan 13
 * §4.5.1, the decision of 2026-10-02: the agent's own connection to a
 * holder is masked, not refused). Mandu-new (no reference origin).
 *
 * The agent is never made a holder (D2's exemption): it holds the read end
 * of every tool call's output, and tainting it would refuse its own
 * connections and label every file it writes. So when the agent itself
 * connects to a process that holds a secret (an HTTP MCP server that read
 * `.env`, a local dev server the agent fetches with WebFetch), the guard
 * records the flow at the arbiter (`recordAgentFlow`) and the model exit
 * masks the result of a call whose window overlaps it
 * (`ProvenanceStore.agentReceiptTaint`). Which results that is:
 *
 *   - NOT a shell tool's (`execOutput`): its result is its process tree's
 *     output, which the call tree's fold answers (`callTaint`, D7);
 *   - NOT a file tool's (`paths`): its result is a file the guard and the
 *     labels govern, not bytes from a socket; except a named pipe a holder
 *     writes (2026-10-02, `isAgentFileTool`: masked by an agent flow on a
 *     file-like channel only);
 *   - NOT a harness-local tool's (below: the plan, a todo list, a subagent's
 *     answer, the human's answer to a question): nothing the agent received
 *     on a socket is in it. A subagent's own fetches are masked in ITS
 *     requests, so the answer it returns was written from symbols;
 *   - NOT Mandu's own quarantine and policy tools (they answer in symbols);
 *   - every OTHER tool, an unknown one included (fail-closed): WebFetch, an
 *     MCP tool (an HTTP server's reply reaches the agent over its socket; a
 *     stdio server's tree is `mcpServerTaint`'s), a tool the spec does not
 *     know, and a tool_result with no matching tool_use.
 *
 * Pure: unit-tested in test/unit/agent-receipt.test.ts.
 */

import type { GateSurface } from "./tool-gate-surface.js";
import { isManduQuarantineTool } from "./inspect-tool.js";
import { isManduPolicyTool } from "./policy-tool.js";

/** Tools whose result the agent's harness writes from local state, never
 *  from a socket: Claude Code's plan, todo, subagent, question, skill and
 *  background-kill tools; OpenCode's and OpenClaw's equivalents. A tool not
 *  named here is covered. */
export const HARNESS_LOCAL_TOOLS: ReadonlySet<string> = new Set([
  // Claude Code
  "Task", "Agent", "TodoWrite", "TodoRead", "ExitPlanMode", "EnterPlanMode", "AskUserQuestion",
  "Skill", "SlashCommand", "KillShell", "KillBash",
  // OpenCode
  "task", "todowrite", "todoread",
]);

/** Is `tool`'s result something the agent itself produced from what it
 *  received over its own connections (module docs)? */
export function isAgentReceiptTool(tool: string, surface: Pick<GateSurface, "execOutput" | "paths">): boolean {
  if (Object.prototype.hasOwnProperty.call(surface.execOutput, tool)) return false;
  if (Object.prototype.hasOwnProperty.call(surface.paths, tool)) return false;
  if (HARNESS_LOCAL_TOOLS.has(tool)) return false;
  if (isManduQuarantineTool(tool) || isManduPolicyTool(tool)) return false;
  return true;
}

/**
 * Plan 13 §4.5.1 (2026-10-02): a file tool (`paths`: Read, Grep, Edit, …)
 * that the agent runs ITSELF on a named pipe a holder writes reads the
 * holder's bytes with no process tree to fold: D2 never makes the agent a
 * holder, and the FIFO's path need not carry a label (the writer held it
 * before its taint, or the agent names it by another link). The guard
 * records that read as an agent flow whose channel is the FIFO's path
 * (`isFileChannel`, provenance-store.ts), and a file tool's result is masked by such a flow
 * overlapping its call, and only by one: a socket the agent holds is not
 * what a file tool read.
 */
export function isAgentFileTool(tool: string, surface: Pick<GateSurface, "paths">): boolean {
  return Object.prototype.hasOwnProperty.call(surface.paths, tool);
}
