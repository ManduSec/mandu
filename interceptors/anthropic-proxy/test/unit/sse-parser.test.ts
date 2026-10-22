/**
 * sse-parser.test.ts — unit tests for tool_use reconstruction.
 *
 * Mandu Track A (interceptors/anthropic-proxy). Covers: the SSE parser
 * reconstructs a tool_use name + accumulated input JSON from a canned event
 * stream; robustness to deltas split across chunk boundaries; multiple blocks;
 * flush at stream end; and the non-streaming JSON extraction path.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { SseToolUseParser, extractToolUsesFromJson, type ReconstructedToolUse } from "../../src/sse-parser.js";
import { buildToolUseSse, buildTextSse, sseEvent } from "../helpers/mock-upstream.js";

function collect(feed: (p: SseToolUseParser) => void): ReconstructedToolUse[] {
  const out: ReconstructedToolUse[] = [];
  const parser = new SseToolUseParser((tu) => out.push(tu));
  feed(parser);
  parser.end();
  return out;
}

test("reconstructs a tool_use name + input from a canonical SSE stream", () => {
  const sse = buildToolUseSse({
    id: "toolu_abc",
    name: "Bash",
    input: { command: "ls -la /tmp" },
  });
  const out = collect((p) => p.feed(sse));
  assert.equal(out.length, 1);
  assert.equal(out[0].id, "toolu_abc");
  assert.equal(out[0].name, "Bash");
  assert.deepEqual(out[0].input, { command: "ls -la /tmp" });
});

test("reconstructs input when deltas are split across arbitrary chunk boundaries", () => {
  const sse = buildToolUseSse({
    id: "toolu_x",
    name: "WebFetch",
    input: { url: "https://example.com/page", prompt: "summarize" },
    inputDeltas: 5,
  });
  // Feed one character at a time — the hardest chunking case.
  const out = collect((p) => {
    for (const ch of sse) p.feed(ch);
  });
  assert.equal(out.length, 1);
  assert.equal(out[0].name, "WebFetch");
  assert.deepEqual(out[0].input, { url: "https://example.com/page", prompt: "summarize" });
});

test("reconstructs multiple tool_use blocks in one stream (distinct indices)", () => {
  const a = buildToolUseSse({ id: "t1", name: "Read", input: { file_path: "/a" }, index: 0 });
  const b = buildToolUseSse({ id: "t2", name: "Grep", input: { pattern: "foo" }, index: 1 });
  // Splice the two streams' block events together (share one message frame).
  const out = collect((p) => {
    p.feed(a);
    p.feed(b);
  });
  const byId = new Map(out.map((t) => [t.id, t]));
  assert.equal(byId.get("t1")?.name, "Read");
  assert.deepEqual(byId.get("t1")?.input, { file_path: "/a" });
  assert.equal(byId.get("t2")?.name, "Grep");
  assert.deepEqual(byId.get("t2")?.input, { pattern: "foo" });
});

test("reconstructs the assistant TEXT reply from text_delta events (the empty-output bug)", () => {
  // Regression: streamed text-only replies (the common case for Claude Code)
  // were dropped — emitTllmCall got "" — so the dashboard showed empty LLM output.
  const parser = new SseToolUseParser(() => {});
  parser.feed(buildTextSse("Hello, world", { deltas: 3 })); // split across deltas
  parser.end();
  assert.equal(parser.assistantText(), "Hello, world");
});

test("captures assistant text AND tool_use in the same stream", () => {
  const tools: ReconstructedToolUse[] = [];
  const parser = new SseToolUseParser((tu) => tools.push(tu));
  parser.feed(sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }));
  parser.feed(sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "let me check" } }));
  parser.feed(sseEvent("content_block_stop", { type: "content_block_stop", index: 0 }));
  parser.feed(sseEvent("content_block_start", { type: "content_block_start", index: 1, content_block: { type: "tool_use", id: "t1", name: "Bash", input: {} } }));
  parser.feed(sseEvent("content_block_delta", { type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: '{"command":"ls"}' } }));
  parser.feed(sseEvent("content_block_stop", { type: "content_block_stop", index: 1 }));
  parser.feed(sseEvent("message_stop", { type: "message_stop" }));
  parser.end();
  assert.equal(parser.assistantText(), "let me check");
  assert.equal(tools.length, 1);
  assert.equal(tools[0].name, "Bash");
});

test("tool_use with no input deltas reconstructs to empty-object input", () => {
  let out: ReconstructedToolUse | undefined;
  const parser = new SseToolUseParser((tu) => (out = tu));
  parser.feed(sseEvent("content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: { type: "tool_use", id: "t0", name: "TodoWrite", input: {} },
  }));
  parser.feed(sseEvent("content_block_stop", { type: "content_block_stop", index: 0 }));
  assert.deepEqual(out?.input, {});
  assert.equal(out?.name, "TodoWrite");
});

test("text content blocks are ignored (only tool_use is reconstructed)", () => {
  let count = 0;
  const parser = new SseToolUseParser(() => count++);
  parser.feed(sseEvent("content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: { type: "text", text: "" },
  }));
  parser.feed(sseEvent("content_block_delta", {
    type: "content_block_delta",
    index: 0,
    delta: { type: "text_delta", text: "hello" },
  }));
  parser.feed(sseEvent("content_block_stop", { type: "content_block_stop", index: 0 }));
  parser.end();
  assert.equal(count, 0);
});

test("end() flushes a block left open by a truncated stream", () => {
  const out: ReconstructedToolUse[] = [];
  const parser = new SseToolUseParser((tu) => out.push(tu));
  // Start + one delta, but the stream is cut before content_block_stop.
  parser.feed(sseEvent("content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: { type: "tool_use", id: "t9", name: "Write", input: {} },
  }));
  parser.feed(sseEvent("content_block_delta", {
    type: "content_block_delta",
    index: 0,
    delta: { type: "input_json_delta", partial_json: '{"file_path":"/x"}' },
  }));
  parser.end();
  assert.equal(out.length, 1);
  assert.deepEqual(out[0].input, { file_path: "/x" });
});

test("malformed accumulated input JSON surfaces raw + parse error (no throw)", () => {
  const out: ReconstructedToolUse[] = [];
  const parser = new SseToolUseParser((tu) => out.push(tu));
  parser.feed(sseEvent("content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: { type: "tool_use", id: "tbad", name: "Bash", input: {} },
  }));
  parser.feed(sseEvent("content_block_delta", {
    type: "content_block_delta",
    index: 0,
    delta: { type: "input_json_delta", partial_json: "{not valid json" },
  }));
  parser.feed(sseEvent("content_block_stop", { type: "content_block_stop", index: 0 }));
  assert.equal(out.length, 1);
  assert.ok(out[0].inputParseError);
  assert.deepEqual(out[0].input, { __rawInputJson: "{not valid json" });
});

test("extractToolUsesFromJson pulls tool_use blocks from a non-streaming response", () => {
  const resp = {
    type: "message",
    role: "assistant",
    content: [
      { type: "text", text: "Let me check" },
      { type: "tool_use", id: "tj1", name: "Read", input: { file_path: "/y" } },
      { type: "tool_use", id: "tj2", name: "Bash", input: { command: "pwd" } },
    ],
  };
  const out = extractToolUsesFromJson(resp);
  assert.equal(out.length, 2);
  assert.equal(out[0].name, "Read");
  assert.deepEqual(out[1].input, { command: "pwd" });
});

test("messageId: message_start's message.id, the first one only; undefined without one", () => {
  const p = new SseToolUseParser(() => {});
  p.feed(buildTextSse("hi"));
  p.feed(buildTextSse("again").replace('"id":"msg_txt"', '"id":"msg_second"'));
  assert.equal(p.messageId(), "msg_txt");
  const q = new SseToolUseParser(() => {});
  q.feed(sseEvent("content_block_stop", { type: "content_block_stop", index: 0 }));
  assert.equal(q.messageId(), undefined);
});
