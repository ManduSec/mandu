/**
 * sse-rewrite.test.ts — unit tests for the Codex Responses function_call
 * argument forward rewriter (fs-sync.md §1.3, P4). Asserts the command
 * string is forward-mapped CONSISTENTLY across every argument-bearing event
 * (delta buffered + re-emitted as one, done, output_item.done, completed) and
 * that non-function-call / no-change / unparseable streams relay verbatim.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ResponsesArgsRewriter, composeArgsTransform } from "../../src/sse-rewrite.js";
import { ViewMap } from "../../src/view-map.js";
import { buildExecCommandSse, buildTextSse, sseEvent } from "../helpers/mock-upstream.js";

const HUMAN = "/home/u/project/webapp";
const AGENT = "/home/u/.mandu/workspaces/wid/agentview";

function makeMap(): ViewMap {
  return new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" });
}

/** A map-only transform (no exec gate) — the prior forward-path-map behavior. */
function mapTransform(map = makeMap()) {
  return composeArgsTransform(map);
}

/** Run an SSE string through the rewriter in `n` chunks. */
async function rewriteChunked(sse: string, n: number, map = makeMap()): Promise<string> {
  const rw = new ResponsesArgsRewriter(mapTransform(map));
  const size = Math.ceil(sse.length / n) || 1;
  let out = "";
  for (let i = 0; i < sse.length; i += size) out += await rw.feed(sse.slice(i, i + size));
  out += await rw.end();
  return out;
}

/** All `data:` JSON objects in an SSE string, by event type. */
function eventsByType(sse: string, type: string): Record<string, unknown>[] {
  const found: Record<string, unknown>[] = [];
  for (const block of sse.split("\n\n")) {
    const dataLine = block.split("\n").find((l) => l.startsWith("data:"));
    if (!dataLine) continue;
    try {
      const obj = JSON.parse(dataLine.slice("data:".length).trim());
      if (obj?.type === type) found.push(obj);
    } catch { /* skip */ }
  }
  return found;
}

test("exec_command with a HumanView path is forward-mapped across ALL argument events", async () => {
  const sse = buildExecCommandSse({ cmd: `cat ${HUMAN}/vendor/notes.txt`, argDeltas: 4 });
  const out = await rewriteChunked(sse, 7);

  const expectedArgs = JSON.stringify({ cmd: `cat ${AGENT}/vendor/notes.txt` });
  // arguments.done carries the rewritten args…
  assert.equal(eventsByType(out, "response.function_call_arguments.done")[0].arguments, expectedArgs);
  // …output_item.done's item.arguments too…
  assert.equal(
    (eventsByType(out, "response.output_item.done")[0].item as { arguments: string }).arguments,
    expectedArgs,
  );
  // …and response.completed's output item.
  const completedOutput = (eventsByType(out, "response.completed")[0].response as { output: Array<{ arguments: string }> }).output;
  assert.equal(completedOutput[0].arguments, expectedArgs);
  // Exactly ONE argument delta is re-emitted (buffered + collapsed), carrying
  // the full rewritten args; the HumanView path is nowhere in the stream.
  const deltas = eventsByType(out, "response.function_call_arguments.delta");
  assert.equal(deltas.length, 1);
  assert.equal(deltas[0].delta, expectedArgs);
  assert.ok(!out.includes(HUMAN), "HumanView path must not survive in the relayed stream");
});

test("a plain text turn relays byte-verbatim at any chunking", async () => {
  const sse = buildTextSse(`done reading ${HUMAN}/a.md`); // path in prose is not a command
  for (const n of [1, 2, 9]) {
    assert.equal(await rewriteChunked(sse, n), sse);
  }
});

// NB: function_call streams are NOT byte-verbatim even when no path changes —
// the buffered deltas are re-emitted as one synthetic delta. The invariant is
// that the RECONSTRUCTED command is unchanged, which these two assert.
test("a command with nothing to map: the reconstructed command is unchanged", async () => {
  const out = await rewriteChunked(buildExecCommandSse({ cmd: "ls -la" }), 3);
  assert.equal(eventsByType(out, "response.function_call_arguments.done")[0].arguments, JSON.stringify({ cmd: "ls -la" }));
});

test("an AgentView-prefixed command is idempotent (command unchanged)", async () => {
  const out = await rewriteChunked(buildExecCommandSse({ cmd: `cat ${AGENT}/x` }), 2);
  assert.equal(eventsByType(out, "response.function_call_arguments.done")[0].arguments, JSON.stringify({ cmd: `cat ${AGENT}/x` }));
});

test("stream cut short after all deltas: end() forward-maps the accumulation and closes the item", async () => {
  let sse = "";
  sse += sseEvent("response.output_item.added", {
    type: "response.output_item.added", output_index: 0,
    item: { type: "function_call", id: "fc_1", call_id: "c1", name: "exec_command", arguments: "" },
  });
  sse += sseEvent("response.function_call_arguments.delta", {
    type: "response.function_call_arguments.delta", item_id: "fc_1", output_index: 0, delta: `{"cmd":"cat ${HUMAN}/x"}`,
  });
  // no .done — connection dropped, but the accumulated arguments are complete.
  const rw = new ResponsesArgsRewriter(mapTransform());
  let out = await rw.feed(sse);
  out += await rw.end();
  // The full accumulation is in hand, so it is forward-mapped — the HumanView
  // path must NOT survive (Codex would run it against the real tree) — and the
  // item is closed with a synthetic .done carrying the mapped command.
  assert.ok(!out.includes(`${HUMAN}/x`), "HumanView path must be mapped, not released raw");
  const done = eventsByType(out, "response.function_call_arguments.done");
  assert.equal(done.length, 1);
  assert.equal(done[0].arguments, JSON.stringify({ cmd: `cat ${AGENT}/x` }));
});

test("stream cut mid-JSON (unparseable accumulation): end() falls back to raw, never swallows", async () => {
  let sse = "";
  sse += sseEvent("response.function_call_arguments.delta", {
    type: "response.function_call_arguments.delta", item_id: "fc_9", output_index: 0, delta: `{"cmd":"cat ${HUMAN}/tr`,
  });
  const rw = new ResponsesArgsRewriter(mapTransform());
  let out = await rw.feed(sse);
  out += await rw.end();
  // Unparseable → conservative "no rewrite": the raw bytes are released (not
  // held forever). The map is view-consistency, not a security boundary here.
  assert.ok(out.includes(`${HUMAN}/tr`), "unparseable accumulation released raw, never swallowed");
});

test(".done with no string arguments AND no buffered deltas relays verbatim (no fabricated empty args)", async () => {
  // A .done that carries neither a string `arguments` nor prior deltas must NOT
  // be re-emitted as `arguments: ""` (which made Codex run an empty command).
  const raw = sseEvent("response.function_call_arguments.done", {
    type: "response.function_call_arguments.done", item_id: "fc_x", output_index: 0,
  });
  const rw = new ResponsesArgsRewriter(mapTransform());
  let out = await rw.feed(raw);
  out += await rw.end();
  assert.equal(out, raw, "the original .done event passes through untouched");
  assert.ok(!out.includes(`"arguments":""`), "no fabricated empty arguments");
});

test("two sequential function_calls each rewrite independently", async () => {
  const a = buildExecCommandSse({ cmd: `cat ${HUMAN}/a`, callId: "c1", itemId: "fc_1" });
  const b = buildExecCommandSse({ cmd: `grep x ${HUMAN}/src`, callId: "c2", itemId: "fc_2" });
  const out = await rewriteChunked(a + b, 6);
  const dones = eventsByType(out, "response.function_call_arguments.done");
  assert.equal(dones.length, 2);
  assert.equal(dones[0].arguments, JSON.stringify({ cmd: `cat ${AGENT}/a` }));
  assert.equal(dones[1].arguments, JSON.stringify({ cmd: `grep x ${AGENT}/src` }));
});
