/**
 * transcript.test.ts — the Codex `tllm_call` summaries (src/transcript.ts,
 * 2026-09-26): the `▸ role` transcript of a forwarded Responses request and
 * the model's answer read off the relayed body. The dashboard's trace
 * (dashboard.md §4.2f) finds the typed prompt and the reply in these.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { ResponseSniffer, summarizeOutputItems, summarizeResponsesRequest } from "../../src/transcript.js";
import { buildScriptCellSse, buildTextSse, sseEvent } from "../helpers/mock-upstream.js";
import type { ResponsesRequest } from "../../src/responses-types.js";

const SYM = "$MDU:exec_command[a1b2]";
const text = (t: string) => [{ type: "input_text", text: t }];

function codexRequest(): ResponsesRequest {
  return {
    model: "gpt-5.6-terra",
    instructions: "[mandu:handling-prompt]\nSymbols are opaque.\n\nYou are Codex, a coding agent.",
    input: [
      { type: "additional_tools", id: "at_1", role: "developer", tools: [{ type: "namespace", name: "functions", tools: [] }] },
      { type: "message", role: "developer", content: text("<permissions instructions>sandbox: workspace-write</permissions instructions>") },
      { type: "message", role: "user", content: text("# AGENTS.md instructions for /ws\n\n<INSTRUCTIONS>\nUse pnpm.\n</INSTRUCTIONS>") },
      { type: "message", role: "user", content: text("<environment_context>\n  <cwd>/ws</cwd>\n</environment_context>") },
      { type: "message", role: "user", content: text("Summarize notes.md") },
      { type: "reasoning", id: "rs_1", encrypted_content: "gAAAA" },
      { type: "function_call", call_id: "call_1", name: "exec_command", arguments: '{"cmd":"cat notes.md"}' },
      { type: "function_call_output", call_id: "call_1", output: SYM },
      { type: "message", role: "assistant", content: [{ type: "output_text", text: `The notes say ${SYM}.` }] },
    ],
  } as unknown as ResponsesRequest;
}

test("summarizeResponsesRequest: the typed prompt is the only ▸ user text; runtime context is ▸ system", () => {
  const s = summarizeResponsesRequest(codexRequest(), "You are Codex, a coding agent.");
  const blocks = s.split("\n\n▸ ").map((b, i) => (i ? "▸ " + b : b));
  assert.match(blocks[0]!, /^▸ system\n\[Mandu IPI handling prompt\]\nYou are Codex/);
  assert.doesNotMatch(s, /Symbols are opaque/, "the handling prompt collapses to its placeholder");
  const users = blocks.filter((b) => b.startsWith("▸ user\n"));
  assert.deepEqual(users, ["▸ user\nSummarize notes.md", `▸ user\n[tool_result call_1]\n${SYM}`]);
  assert.ok(blocks.some((b) => b.startsWith("▸ system\n# AGENTS.md instructions")));
  assert.ok(blocks.some((b) => b.startsWith("▸ system\n<environment_context>")));
  assert.ok(blocks.some((b) => b.startsWith("▸ system\n<permissions instructions>")), "developer messages are system");
  assert.ok(s.includes('▸ assistant\n→ exec_command({"cmd":"cat notes.md"})'));
  assert.ok(s.includes(`▸ assistant\nThe notes say ${SYM}.`), "the token stays a token");
  assert.doesNotMatch(s, /additional_tools|gAAAA|namespace/, "the battery and reasoning are not conversation");
});

test("summarizeResponsesRequest: a huge instructions block or tool output never pushes the prompt out", () => {
  const req = codexRequest();
  (req.input as unknown[]).push({ type: "function_call_output", call_id: "call_2", output: "x".repeat(50_000) });
  const s = summarizeResponsesRequest(req, "y".repeat(50_000));
  assert.ok(s.length <= 4096 + 200);
  assert.ok(s.includes("▸ user\nSummarize notes.md"));
  assert.ok(s.includes("▸ user\n[tool_result call_2]"));
});

test("summarizeOutputItems: the answer text first, then one → line per call; multi-line input stays on one line", () => {
  const out = summarizeOutputItems([
    { type: "reasoning", id: "rs" },
    { type: "custom_tool_call", call_id: "c", name: "exec", input: "const r = await tools.exec_command({\"cmd\":\"ls\"});\ntext(r.output);\n" },
    { type: "message", role: "assistant", content: [{ type: "output_text", text: "Listing the files." }] },
  ]);
  const lines = out.split("\n");
  assert.equal(lines[0], "Listing the files.");
  assert.equal(lines.length, 2);
  assert.match(lines[1]!, /^→ exec\("const r = await tools\.exec_command\(\{\\"cmd\\":\\"ls\\"\}\);\\ntext\(r\.output\);\\n"\)$/);
});

test("ResponseSniffer (SSE): reads finished items across arbitrary chunk splits, including a split multi-byte char", () => {
  const sse = buildTextSse("Done — 9 files ✓");
  const bytes = Buffer.from(sse, "utf8");
  const sn = new ResponseSniffer("sse");
  for (let i = 0; i < bytes.length; i += 7) sn.feed(bytes.subarray(i, i + 7));
  assert.deepEqual(sn.finish(), { text: "Done — 9 files ✓", error: null });

  const cell = new ResponseSniffer("sse");
  cell.feed(buildScriptCellSse({ cmd: "ls" }));
  assert.match(cell.finish().text, /^→ exec\(/);
});

test("ResponseSniffer (SSE): an empty response.completed output falls back to nothing lost; completed alone is used when no item.done came", () => {
  const item = { type: "message", role: "assistant", content: [{ type: "output_text", text: "hi" }] };
  const onlyDone = new ResponseSniffer("sse");
  onlyDone.feed(sseEvent("response.output_item.done", { type: "response.output_item.done", item }) +
    sseEvent("response.completed", { type: "response.completed", response: { output: [] } }));
  assert.equal(onlyDone.finish().text, "hi");
  const onlyCompleted = new ResponseSniffer("sse");
  onlyCompleted.feed(sseEvent("response.completed", { type: "response.completed", response: { output: [item] } }));
  assert.equal(onlyCompleted.finish().text, "hi");
  const failed = new ResponseSniffer("sse");
  failed.feed(sseEvent("response.failed", { type: "response.failed", response: { error: { message: "rate limited" } } }));
  assert.deepEqual(failed.finish(), { text: "", error: "rate limited" });
});

test("ResponseSniffer (JSON): the stream:false body's output, or its error", () => {
  const ok = new ResponseSniffer("json");
  ok.feed(JSON.stringify({ output: [{ type: "function_call", call_id: "c", name: "exec_command", arguments: '{"cmd":"pwd"}' }] }));
  assert.equal(ok.finish().text, '→ exec_command({"cmd":"pwd"})');
  const err = new ResponseSniffer("json");
  err.feed(JSON.stringify({ error: { message: "quota exceeded", type: "insufficient_quota" } }));
  assert.deepEqual(err.finish(), { text: "", error: "quota exceeded" });
});
