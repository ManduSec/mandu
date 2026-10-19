/**
 * policy-model.test — unit tests for the dashboard's policy-snapshot helper.
 *
 * Mandu-new test. `ruleForTool` joins a tool-call's tool name to the governing
 * rule in the arbiter policy snapshot the modal renders. Pins: exact match, the
 * MCP-prefix fallback (mirrors the arbiter's getToolInboundSpec prefix rule), and
 * the null-safe paths (no snapshot / undescribed tool → null → fail-closed UI).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ruleForTool, type PolicySnapshot, type ToolRule } from "../../src/policy-model.js";

function rule(tool: string): ToolRule {
  return {
    tool,
    inbound: { kind: "literal", summary: "whole result: UNTRUSTED", fields: [] },
    outbound: { toolResolve: false, destination: "AgentView", summary: "", fields: [] },
  };
}

function snap(): PolicySnapshot {
  return {
    specId: "claude-code",
    origins: [],
    tools: { Bash: rule("Bash"), "mcp__*": rule("mcp__*") },
    fallbackTrust: "UNTRUSTED",
    mcpPrefix: "mcp__",
  };
}

test("ruleForTool returns the exact tool rule", () => {
  assert.equal(ruleForTool(snap(), "Bash")?.tool, "Bash");
});

test("ruleForTool falls back to mcp__* for any mcp__ tool", () => {
  assert.equal(ruleForTool(snap(), "mcp__github__create_issue")?.tool, "mcp__*");
});

test("ruleForTool returns null for an undescribed non-MCP tool", () => {
  assert.equal(ruleForTool(snap(), "TotallyUnknownTool"), null);
});

test("ruleForTool is null-safe for a missing snapshot or tool", () => {
  assert.equal(ruleForTool(null, "Bash"), null);
  assert.equal(ruleForTool(snap(), null), null);
  assert.equal(ruleForTool(undefined, undefined), null);
});
