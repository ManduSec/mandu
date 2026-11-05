/**
 * text-calls (unit) — the reply lines OpenClaw's plain-text tool-call compat
 * layer would run as a tool call (src/text-calls.ts; model-wires.md, "Tool
 * calls written as text"), and their stop on the OpenAI wires
 * (openai-sse.ts `lineTextCalls`: Chat Completions and the Responses API,
 * streamed and buffered).
 *
 * Pinned: each form OpenClaw runs opens a call at a line start (indented
 * too), split across deltas or not; `[name]` only for a declared tool (or
 * any name with no tool list); prose, a bracket mid-line and a footnote pass;
 * a stream that opens one ends with the error event BEFORE the delta that
 * completes the opening, and nothing after it is relayed (no finish, no
 * `[DONE]`, no `response.completed`); a snapshot carrying one (an upstream
 * that sends no deltas) ends it too; a buffered answer carrying one throws
 * (the proxy's 502); without the option nothing changes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { TextCallScan, hasTextCall, textCallStart } from "../../src/text-calls.js";
import { ChatStreamRewriter, ResponsesStreamRewriter, gateChatJson, gateResponsesJson, type CallGate } from "../../src/openai-sse.js";

type Json = Record<string, unknown>;

const gate: CallGate = async () => null;
const NAMES = new Set(["exec", "read", "web_fetch"]);
const OPT = { lineTextCalls: { toolNames: NAMES } };

/** Each form OpenClaw 2026.7.1-2026.10.7 runs (packages/tool-call-repair). */
const FORMS = [
  "[tool:exec] {\"command\":\"touch /tmp/x\"}",
  "[exec]\n{\"command\":\"touch /tmp/x\"}\n[/exec]",
  "[exec]\n{\"command\":\"touch /tmp/x\"}\n[END_TOOL_REQUEST]",
  "<function=exec>\n<parameter=command>touch /tmp/x</parameter>\n</function>",
  "<FUNCTION=exec><parameter=command>x</parameter></FUNCTION>",
  "<|channel|>commentary to=exec code<|message|>{\"command\":\"x\"}<|call|>",
  "commentary to=exec code {\"command\":\"x\"}",
  "  [tool:read] {\"path\":\"a\"}",
];

test("textCallStart: every form OpenClaw runs, at a line start; a bracket only for a declared tool", () => {
  for (const f of FORMS) assert.equal(textCallStart(f, NAMES), true, f);
  assert.equal(textCallStart("[functions_exec]", NAMES), true, "a prefixed spelling of a declared tool (wider than OpenClaw, the fail-closed side)");
  for (const prose of ["[1] a footnote", "[note] see below", "see [exec] in the text", "The final answer is 4.", "a <function=x> mid-line"]) {
    assert.equal(textCallStart(prose, NAMES), false, prose);
  }
  assert.equal(textCallStart("[note]", new Set()), true, "no tool list: any name");
  assert.equal(hasTextCall("Sure.\nHere goes:\n[tool:exec] {}", NAMES), true);
  assert.equal(hasTextCall("All done.\nNothing to run.", NAMES), false);
});

test("TextCallScan: an opening split across deltas is seen on the delta that completes it; runs are separate", () => {
  for (const f of FORMS) {
    for (let cut = 1; cut < Math.min(f.length, 14); cut++) {
      const s = new TextCallScan(NAMES);
      assert.equal(s.add("r", "Sure.\n"), false);
      const first = s.add("r", f.slice(0, cut));
      const second = s.add("r", f.slice(cut));
      assert.ok(first || second, `${JSON.stringify(f)} cut ${cut}`);
    }
  }
  const s = new TextCallScan(NAMES);
  assert.equal(s.add("a", "[ex"), false);
  assert.equal(s.add("b", "ec]"), false, "another run's text does not complete it");
  assert.equal(s.add("a", "ec]"), true);
});

const chunk = (delta: Json, finish: string | null = null, index = 0): string =>
  `data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", created: 1, model: "m", choices: [{ index, delta, finish_reason: finish }] })}\n\n`;

function chatText(sse: string): string {
  let out = "";
  for (const ev of sse.split("\n\n")) {
    const d = ev.startsWith("data: ") ? ev.slice(6) : "";
    if (!d || d === "[DONE]") continue;
    for (const ch of ((JSON.parse(d) as Json)["choices"] as Json[] | undefined) ?? []) {
      const c = (ch["delta"] as Json | undefined)?.["content"];
      if (typeof c === "string") out += c;
    }
  }
  return out;
}

test("Chat stream: a text call ends the stream before the delta that completes its opening; nothing after it", async () => {
  for (const f of FORMS) {
    for (const cut of [0, 2, 5]) {
      const pieces = cut === 0 ? [f] : [f.slice(0, cut), f.slice(cut)];
      const rw = new ChatStreamRewriter(gate, OPT);
      let out = await rw.feed(chunk({ role: "assistant", content: "Sure.\n" }));
      for (const p of pieces) out += await rw.feed(chunk({ content: p }));
      out += await rw.feed(chunk({}, "stop")) + await rw.feed("data: [DONE]\n\n") + await rw.end();
      assert.match(out, /mandu_fail_closed[^\n]*tool call in its reply text/, `${JSON.stringify(f)} cut ${cut}`);
      assert.ok(!chatText(out).includes(f), "the agent never holds the whole call");
      assert.ok(!out.includes("[DONE]") && !out.includes("\"finish_reason\":\"stop\""), "no finish reaches the agent");
    }
  }
  // A content-part array is read too.
  const parts = new ChatStreamRewriter(gate, OPT);
  assert.match(await parts.feed(chunk({ content: [{ type: "text", text: "[tool:exec] {}" }] })), /mandu_fail_closed/);
});

test("Chat stream: prose (a footnote, a bracket mid-line, an undeclared [name]) relays unchanged; without the option a call relays too", async () => {
  const sse = chunk({ content: "See [1] and [note]\n" }) + chunk({ content: "[1] footnote. Use [exec] wisely.\n[note]" }) + chunk({}, "stop");
  const on = new ChatStreamRewriter(gate, OPT);
  assert.equal(await on.feed(sse) + await on.end(), sse);
  const off = new ChatStreamRewriter(gate);
  const call = chunk({ content: "[tool:exec] {}" }) + chunk({}, "stop");
  assert.equal(await off.feed(call) + await off.end(), call);
});

test("Chat buffered: a message carrying a text call is not relayed (the caller answers 502)", async () => {
  const body = { choices: [{ index: 0, message: { role: "assistant", content: "ok\n[tool:exec] {\"command\":\"x\"}" }, finish_reason: "stop" }] };
  await assert.rejects(gateChatJson(structuredClone(body), gate, OPT), /tool call in its reply text/);
  assert.equal(await gateChatJson(structuredClone(body), gate), false);
});

const ev = (type: string, data: Json): string => `event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`;

test("Responses stream: a text call in the deltas ends the stream before the completing delta; nothing after it", async () => {
  const f = "[tool:exec] {\"command\":\"touch /tmp/x\"}";
  for (const cut of [0, 3, 8]) {
    const rw = new ResponsesStreamRewriter(gate, OPT);
    let out = await rw.feed(ev("response.output_item.added", { output_index: 0, item: { id: "m1", type: "message", role: "assistant", content: [] } }));
    const pieces = cut === 0 ? [f] : [f.slice(0, cut), f.slice(cut)];
    for (const p of pieces) out += await rw.feed(ev("response.output_text.delta", { item_id: "m1", output_index: 0, content_index: 0, delta: p }));
    out += await rw.feed(ev("response.output_text.done", { item_id: "m1", output_index: 0, content_index: 0, text: f }));
    out += await rw.feed(ev("response.completed", { response: { id: "r1", output: [{ id: "m1", type: "message", content: [{ type: "output_text", text: f }] }] } }));
    out += await rw.end();
    assert.match(out, /mandu_fail_closed[^\n]*tool call in its reply text/, `cut ${cut}`);
    assert.ok(!out.includes("response.completed") && !out.includes("output_text.done"), "nothing after the error");
  }
});

test("Responses stream: a snapshot carrying a text call (no deltas) ends the stream; prose passes", async () => {
  const f = "<function=exec><parameter=command>x</parameter></function>";
  for (const event of [
    ev("response.output_text.done", { item_id: "m1", output_index: 0, content_index: 0, text: f }),
    ev("response.content_part.done", { item_id: "m1", output_index: 0, content_index: 0, part: { type: "output_text", text: f } }),
    ev("response.output_item.done", { output_index: 0, item: { id: "m1", type: "message", content: [{ type: "output_text", text: f }] } }),
    ev("response.completed", { response: { id: "r1", output: [{ id: "m1", type: "message", content: [{ type: "output_text", text: f }] }] } }),
  ]) {
    const rw = new ResponsesStreamRewriter(gate, OPT);
    assert.match(await rw.feed(event), /mandu_fail_closed/, event.slice(0, 40));
  }
  const prose = ev("response.output_text.delta", { item_id: "m1", output_index: 0, content_index: 0, delta: "Done. See [1].\n" })
    + ev("response.output_text.done", { item_id: "m1", output_index: 0, content_index: 0, text: "Done. See [1].\n" });
  const rw = new ResponsesStreamRewriter(gate, OPT);
  assert.equal(await rw.feed(prose) + await rw.end(), prose);
});

test("Responses buffered: an output message carrying a text call throws (the caller answers 502)", async () => {
  const body = { output: [{ type: "message", content: [{ type: "output_text", text: "[exec]\n{}\n[/exec]" }] }] };
  await assert.rejects(gateResponsesJson(structuredClone(body), gate, OPT), /tool call in its reply text/);
  assert.equal(await gateResponsesJson(structuredClone(body), gate), false);
});
