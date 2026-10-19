/**
 * codex-mcp-calls-lib.test.ts — the MCP-call reader of the real-model Codex
 * MCP suite (tests/lib/codex-mcp-calls.ts), offline: no model, no network.
 *
 * Pins: a classic namespaced `function_call` and a script-cell
 * `tools.mcp__…(…)` / `tools["mcp__…"](…)` call are both read, in the same
 * `<namespace>__<name>` spelling; built-in tools (exec_command, a bare
 * function_call) and dynamic calls are not MCP calls; a body that is not
 * JSON is skipped. The script-cell case is the live shape of 2026-10-01
 * (codex-cli 0.159.1), which the classic-only reader missed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { mcpCallsIn } from "../lib/codex-mcp-calls.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("off"); // no protection decision here: a wire reader only

const body = (...input: unknown[]): string => JSON.stringify({ model: "m", input });

test("a classic namespaced function_call is an MCP call", () => {
  const calls = mcpCallsIn([body(
    { type: "function_call", call_id: "c1", namespace: "mcp__mandu_policy", name: "mandu_policy_read", arguments: "{}" },
    { type: "function_call", call_id: "c2", name: "exec_command", arguments: "{\"cmd\":\"ls\"}" },
  )]);
  assert.deepEqual([...calls], ["mcp__mandu_policy__mandu_policy_read"]);
});

test("a script cell's tools.mcp__… calls are MCP calls, in the same spelling", () => {
  const cell = [
    "const r = await tools.exec_command({cmd:\"cat README.md\"});",
    "text(await tools.mcp__mandu_policy__mandu_policy_read({}));",
    "text(await tools[\"mcp__mandu_policy__mandu_policy_propose\"]({edits:[{op:\"lock-path\",path:\".env\",level:\"no-model\"}]}));",
    "text(await tools . mcp__mandu_inspect__inspect_symbol ({symbol:\"$MDU:x\"}));",
  ].join("\n");
  const calls = mcpCallsIn([body({ type: "custom_tool_call", call_id: "c1", name: "exec", input: cell })]);
  assert.deepEqual([...calls].sort(), [
    "mcp__mandu_inspect__inspect_symbol",
    "mcp__mandu_policy__mandu_policy_propose",
    "mcp__mandu_policy__mandu_policy_read",
  ]);
});

test("a dynamic call, a tool listing and a non-JSON body name no MCP call", () => {
  const cell = "const s = ALL_TOOLS.find(x => /policy/.test(x.name)); text(await tools[s.name]({})); text(ALL_TOOLS);";
  const calls = mcpCallsIn(["not json", body({ type: "custom_tool_call", call_id: "c1", name: "exec", input: cell })]);
  assert.deepEqual([...calls], []);
});

test("both wires in one run are read together, each call once", () => {
  const calls = mcpCallsIn([
    body({ type: "function_call", call_id: "c1", namespace: "mcp__mandu_policy", name: "mandu_policy_read", arguments: "{}" }),
    body(
      { type: "function_call", call_id: "c1", namespace: "mcp__mandu_policy", name: "mandu_policy_read", arguments: "{}" },
      { type: "custom_tool_call", call_id: "c2", name: "exec", input: "text(await tools.mcp__mandu_policy__mandu_policy_read({}));" },
    ),
  ]);
  assert.deepEqual([...calls], ["mcp__mandu_policy__mandu_policy_read"]);
});
