/**
 * tool-surface.test — the session-health `toolSurface` answer (tool-inbound.ts
 * unknownToolNames): which advertised tools would fail closed on ingress.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  bindSessionSpec,
  clearSessionSpecs,
  getToolInboundSpec,
  inboundSpecNamesInput,
  unknownToolNames,
} from "../../policy/tool-inbound.js";
import { MCP_INBOUND_SPEC } from "../../policy/claude-code-inbound.js";

test("claude-code's own battery is fully known; a tool the spec never mapped is reported once", () => {
  assert.deepEqual(unknownToolNames(["Read", "Bash", "Grep", "Glob", "Edit", "Write"]), []);
  assert.deepEqual(unknownToolNames(["Read", "BrandNewTool", "BrandNewTool", "Bash"]), ["BrandNewTool"]);
});

test("MCP-namespaced tools ride the claude-code spec's mcp__ fallback (known); junk entries are ignored", () => {
  assert.deepEqual(unknownToolNames(["mcp__mandu-inspect__inspect_symbol", "mcp__foo__bar"]), []);
  assert.deepEqual(unknownToolNames(["", "Read"] as string[]), []);
});

test("the Claude Code 2.1.273 battery the live tool_surface event recorded (2026-09-19) is fully known", () => {
  // 34 names as the proxy announced them for watch-percast-proof-u3; 20 were
  // unmapped before the 2026-09-19 spec extension and degraded every session.
  const surface = [
    "Agent", "AskUserQuestion", "Bash", "CronCreate", "CronDelete", "CronList", "Edit",
    "EnterPlanMode", "EnterWorktree", "ExitPlanMode", "ExitWorktree", "FetchInboxMessage",
    "ListAgents", "LSP", "NotebookEdit", "Read", "RemoteTrigger", "ReportFindings",
    "ScheduleWakeup", "SendMessage", "Skill", "TaskCreate", "TaskGet", "TaskList",
    "TaskOutput", "TaskStop", "TaskUpdate", "WaitForMcpServers", "WebFetch", "WebSearch",
    "Workflow", "Write", "mcp__mandu-inspect__declassify_symbol",
    "mcp__mandu-inspect__inspect_symbol",
  ];
  assert.deepEqual(unknownToolNames(surface), []);
  // The still-unlisted harness tools are reported, so the chip keeps catching drift.
  assert.deepEqual(unknownToolNames([...surface, "ToolSearch", "Artifacts"]), ["ToolSearch", "Artifacts"]);
});

test("declassify_symbol is mapped on every agent, to the SAME whole-result UNTRUSTED object Claude Code gets (agent-e2e-harness.md §8.5)", () => {
  const oc = "surface-opencode", ow = "surface-openclaw";
  bindSessionSpec(oc, "opencode");
  bindSessionSpec(ow, "openclaw-agent");
  try {
    const claude = getToolInboundSpec("mcp__mandu-inspect__declassify_symbol");
    assert.equal(claude, MCP_INBOUND_SPEC, "Claude Code: the mcp__ fallback");
    assert.equal(getToolInboundSpec("mandu-inspect_declassify_symbol", oc), claude, "OpenCode's MCP spelling");
    assert.equal(getToolInboundSpec("declassify_symbol", ow), claude, "OpenClaw's bare plugin-tool spelling");
    // off the session-health "unknown tools" list, as its inspect sibling is
    assert.deepEqual(unknownToolNames(["bash", "mandu-inspect_inspect_symbol", "mandu-inspect_declassify_symbol"], oc), []);
    assert.deepEqual(unknownToolNames(["exec", "inspect_symbol", "declassify_symbol"], ow), []);
    // the input scan stays on, exactly as for Claude Code (no divergence)
    const spellings = [["mcp__mandu-inspect__declassify_symbol", undefined], ["mandu-inspect_declassify_symbol", oc], ["declassify_symbol", ow]] as const;
    for (const [name, sk] of spellings) assert.equal(inboundSpecNamesInput(name, sk), false, name);
    // a look-alike name is not the Mandu tool
    assert.equal(getToolInboundSpec("acme_declassify_symbol", oc), undefined);
    assert.equal(getToolInboundSpec("declassify_symbols", ow), undefined);
  } finally {
    clearSessionSpecs();
  }
});
