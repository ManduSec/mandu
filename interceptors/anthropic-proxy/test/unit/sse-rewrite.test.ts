/**
 * sse-rewrite.test.ts — unit tests for the streaming tool_use forward rewrite
 * (fs-sync.md §1.3 rule 5: buffer per block, re-emit as one delta).
 *
 * Feeds canonical Anthropic SSE streams (mock-upstream builders) through the
 * rewriter and asserts on BOTH surfaces: the reconstructed tool_use (via the
 * production SseToolUseParser, i.e. what the sniffer/agent sees) and the raw
 * relayed bytes (verbatim passthrough when no rewrite applies).
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { SseToolUseRewriter, type ToolInputTransform } from "../../src/sse-rewrite.js";
import { SseToolUseParser, type ReconstructedToolUse } from "../../src/sse-parser.js";
import { ViewMap } from "../../src/view-map.js";
import { buildToolUseSse, buildTextSse, sseEvent } from "../helpers/mock-upstream.js";

const HUMAN = "/home/u/project/webapp";
const AGENT = "/home/u/.mandu/workspaces/wid/agentview";

function makeMap(): ViewMap {
  return new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" });
}

/** The P2 map-only transform (what the proxy composes, minus the P3 gate). */
function mapTransform(map = makeMap()): ToolInputTransform {
  return async (name, input) => map.rewriteToolUseInput(name, input, "forward");
}

/** Run a whole SSE string through the rewriter in `n` chunks. */
async function rewriteChunked(
  sse: string,
  n: number,
  transform: ToolInputTransform = mapTransform(),
): Promise<string> {
  const rw = new SseToolUseRewriter(transform);
  const size = Math.ceil(sse.length / n) || 1;
  let out = "";
  for (let i = 0; i < sse.length; i += size) out += await rw.feed(sse.slice(i, i + size));
  out += await rw.end();
  return out;
}

/** Parse an SSE string with the production sniffer; return the tool_uses. */
function parseToolUses(sse: string): ReconstructedToolUse[] {
  const seen: ReconstructedToolUse[] = [];
  const p = new SseToolUseParser((tu) => seen.push(tu));
  p.feed(sse);
  p.end();
  return seen;
}

test("Read.file_path with a HumanView path is forward-mapped, re-emitted as ONE delta", async () => {
  const sse = buildToolUseSse({
    id: "tu_1",
    name: "Read",
    input: { file_path: `${HUMAN}/vendor/notes.txt` },
    inputDeltas: 4, // split so no single delta contains the whole path
  });
  const out = await rewriteChunked(sse, 7);

  const tus = parseToolUses(out);
  assert.equal(tus.length, 1);
  assert.deepEqual(tus[0].input, { file_path: `${AGENT}/vendor/notes.txt` });
  assert.equal(tus[0].id, "tu_1");
  assert.equal(tus[0].name, "Read");

  // Exactly one input_json_delta in the output, carrying the full input.
  const deltas = out.split("\n\n").filter((e) => e.includes("input_json_delta"));
  assert.equal(deltas.length, 1);
  assert.ok(!out.includes(HUMAN), "HumanView path must not survive in the relayed stream");
});

test("Bash.command gets textual substitution through the stream", async () => {
  const sse = buildToolUseSse({
    id: "tu_b",
    name: "Bash",
    input: { command: `cat ${HUMAN}/a.txt && ls ${HUMAN}/src` },
    inputDeltas: 3,
  });
  const tus = parseToolUses(await rewriteChunked(sse, 5));
  assert.deepEqual(tus[0].input, { command: `cat ${AGENT}/a.txt && ls ${AGENT}/src` });
});

test("text-only SSE passes through BYTE-VERBATIM at any chunking", async () => {
  const sse = buildTextSse("hello, this mentions " + HUMAN + " as prose", { deltas: 3 });
  for (const n of [1, 2, 9]) {
    assert.equal(await rewriteChunked(sse, n), sse); // text blocks are never rewritten
  }
});

test("unknown tool passes through byte-verbatim (rule 3: no rewrite)", async () => {
  const sse = buildToolUseSse({
    id: "tu_m",
    name: "mcp__srv__thing",
    input: { path: `${HUMAN}/f` },
  });
  assert.equal(await rewriteChunked(sse, 3), sse);
});

test("registry tool with nothing to change passes through byte-verbatim", async () => {
  const sse = buildToolUseSse({
    id: "tu_n",
    name: "Read",
    input: { file_path: "vendor/relative.txt" },
  });
  assert.equal(await rewriteChunked(sse, 2), sse);
});

test("AgentView-prefixed input is idempotent: passes through byte-verbatim", async () => {
  const sse = buildToolUseSse({
    id: "tu_i",
    name: "Read",
    input: { file_path: `${AGENT}/x.txt` },
  });
  assert.equal(await rewriteChunked(sse, 2), sse);
});

test("unparseable input JSON passes through byte-verbatim", async () => {
  let sse = "";
  sse += sseEvent("message_start", { type: "message_start", message: {} });
  sse += sseEvent("content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: { type: "tool_use", id: "tu_x", name: "Read", input: {} },
  });
  sse += sseEvent("content_block_delta", {
    type: "content_block_delta",
    index: 0,
    delta: { type: "input_json_delta", partial_json: `{"file_path": "${HUMAN}/a"` }, // truncated
  });
  sse += sseEvent("content_block_stop", { type: "content_block_stop", index: 0 });
  sse += sseEvent("message_stop", { type: "message_stop" });
  assert.equal(await rewriteChunked(sse, 4), sse);
});

test("a seed input on content_block_start joins the accumulation and is rewritten", async () => {
  let sse = "";
  sse += sseEvent("content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: {
      type: "tool_use",
      id: "tu_s",
      name: "Read",
      input: { file_path: `${HUMAN}/seeded.txt` },
    },
  });
  sse += sseEvent("content_block_stop", { type: "content_block_stop", index: 0 });
  const tus = parseToolUses(await rewriteChunked(sse, 2));
  assert.deepEqual(tus[0].input, { file_path: `${AGENT}/seeded.txt` });
});

test("a stream cut short mid-block is finalized FAIL-CLOSED at end() (parseable → mapped + synthetic stop)", async () => {
  let sse = "";
  sse += sseEvent("content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: { type: "tool_use", id: "tu_c", name: "Read", input: {} },
  });
  sse += sseEvent("content_block_delta", {
    type: "content_block_delta",
    index: 0,
    delta: { type: "input_json_delta", partial_json: `{"file_path":"${HUMAN}/cut"}` },
  });
  // no stop, no message_stop — connection dropped, but the input is complete.
  const rw = new SseToolUseRewriter(mapTransform());
  let out = await rw.feed(sse);
  out += await rw.end();
  // The HumanView path must NOT survive — it is forward-mapped and the block is
  // closed with a synthetic stop so the agent receives the mapped form.
  assert.ok(!out.includes(HUMAN), "HumanView path must never be released un-mapped");
  const tus = parseToolUses(out);
  assert.equal(tus.length, 1);
  assert.deepEqual(tus[0].input, { file_path: `${AGENT}/cut` });
});

test("a stream cut short with UNPARSEABLE input drops the block (fail closed, nothing released)", async () => {
  let sse = "";
  sse += sseEvent("content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: { type: "tool_use", id: "tu_t", name: "Read", input: {} },
  });
  sse += sseEvent("content_block_delta", {
    type: "content_block_delta",
    index: 0,
    delta: { type: "input_json_delta", partial_json: `{"file_path":"${HUMAN}/tr` }, // truncated JSON
  });
  // no stop — connection dropped mid-JSON.
  const rw = new SseToolUseRewriter(mapTransform());
  let out = await rw.feed(sse);
  out += await rw.end();
  assert.ok(!out.includes(HUMAN), "the un-gatable HumanView fragment must not be released");
  assert.equal(parseToolUses(out).length, 0, "the un-gatable block is dropped entirely");
});

test("two sequential tool_use blocks each rewrite independently", async () => {
  const a = buildToolUseSse({ id: "tu_a", name: "Read", input: { file_path: `${HUMAN}/a` }, index: 0 });
  // strip the trailing message events from a, prepend-less: simpler — feed two full streams
  const b = buildToolUseSse({ id: "tu_b", name: "Grep", input: { path: `${HUMAN}/src`, pattern: "x" }, index: 1 });
  const tus = parseToolUses(await rewriteChunked(a + b, 6));
  assert.equal(tus.length, 2);
  assert.deepEqual(tus[0].input, { file_path: `${AGENT}/a` });
  assert.deepEqual(tus[1].input, { path: `${AGENT}/src`, pattern: "x" });
});

test("a ping between deltas does not derail the block rewrite", async () => {
  let sse = "";
  sse += sseEvent("content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: { type: "tool_use", id: "tu_p", name: "Read", input: {} },
  });
  sse += sseEvent("content_block_delta", {
    type: "content_block_delta",
    index: 0,
    delta: { type: "input_json_delta", partial_json: `{"file_path":"${HUMAN}` },
  });
  sse += sseEvent("ping", { type: "ping" });
  sse += sseEvent("content_block_delta", {
    type: "content_block_delta",
    index: 0,
    delta: { type: "input_json_delta", partial_json: `/p.txt"}` },
  });
  sse += sseEvent("content_block_stop", { type: "content_block_stop", index: 0 });
  const out = await rewriteChunked(sse, 3);
  const tus = parseToolUses(out);
  assert.deepEqual(tus[0].input, { file_path: `${AGENT}/p.txt` });
  assert.ok(out.includes(`"type":"ping"`), "the ping survives the transform");
});

test("message_stop with a block left open finalizes FAIL-CLOSED (mapped + gated), never verbatim", async () => {
  let sse = "";
  sse += sseEvent("content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: { type: "tool_use", id: "tu_o", name: "Read", input: {} },
  });
  sse += sseEvent("content_block_delta", {
    type: "content_block_delta",
    index: 0,
    delta: { type: "input_json_delta", partial_json: `{"file_path":"${HUMAN}/x"}` },
  });
  sse += sseEvent("message_stop", { type: "message_stop" }); // stop for the block never came
  const out = await rewriteChunked(sse, 2);
  // The open block is closed with a synthetic stop and forward-mapped; the
  // HumanView path never reaches the agent, and the message_stop still relays.
  assert.ok(!out.includes(HUMAN), "HumanView path must never be released un-mapped");
  assert.ok(out.includes(`"type":"message_stop"`), "the message_stop still relays after the finalized block");
  const tus = parseToolUses(out);
  assert.equal(tus.length, 1);
  assert.deepEqual(tus[0].input, { file_path: `${AGENT}/x` });
});

test("message_stop with an open block whose input is a gated sensitive path yields the denied sentinel", async () => {
  // The transform here is map + a stub gate that denies /etc/shadow: the
  // finalized block must carry the sentinel, not the raw sensitive path.
  const map = makeMap();
  const transform: ToolInputTransform = async (name, input) => {
    const r = map.rewriteToolUseInput(name, input, "forward");
    const cur = (r?.input ?? input) as Record<string, unknown>;
    if (name === "Read" && cur["file_path"] === "/etc/shadow") {
      return { input: { file_path: "/mandu/denied/policy/etc/shadow" }, changed: true };
    }
    return r;
  };
  let sse = "";
  sse += sseEvent("content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: { type: "tool_use", id: "tu_s", name: "Read", input: {} },
  });
  sse += sseEvent("content_block_delta", {
    type: "content_block_delta",
    index: 0,
    delta: { type: "input_json_delta", partial_json: `{"file_path":"/etc/shadow"}` },
  });
  sse += sseEvent("message_stop", { type: "message_stop" });
  const rw = new SseToolUseRewriter(transform);
  let out = await rw.feed(sse);
  out += await rw.end();
  const tus = parseToolUses(out);
  assert.deepEqual(tus[0].input, { file_path: "/mandu/denied/policy/etc/shadow" });
  assert.ok(!out.includes(`"/etc/shadow"`), "the raw sensitive path must not be released");
});
