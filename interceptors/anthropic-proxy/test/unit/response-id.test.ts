/**
 * response-id.test — the response id read off an OpenAI-family answer as
 * the agent is sent it (src/response-id.ts), for `tllm_call`'s
 * `model.responseId` and `mandu scan`'s join
 * (confidentiality-plan-17-past-sessions-scan.md §3 item 6).
 *
 * ONE SUITE, TWO COPIES, like the module: this file is copied VERBATIM to
 * interceptors/openai-proxy/test/unit/response-id.test.ts, and
 * tests/stack/transcript-scan.test.ts fails unless both pairs are
 * byte-identical. Pure: no proxy, no arbiter, no axis read.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { ResponseIdSniffer, responseIdOfBody } from "../../src/response-id.js";

const CHAT_ID = "chatcmpl-AbCdEf0123456789xyz";
const RESP_ID = "resp_0977ab12cd34ef56ab78cd90ef12ab34";

const chunk = (o: Record<string, unknown>): string => `data: ${JSON.stringify(o)}\n\n`;
const chatStream = (id: unknown): string =>
  ": keepalive\n\n"
  + chunk({ id, object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: "hi" }, finish_reason: null }] })
  + chunk({ id: "chatcmpl-later000000000", object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })
  + "data: [DONE]\n\n";

function sniff(wire: "chat" | "responses", text: string, step = text.length): string | undefined {
  const s = new ResponseIdSniffer(wire);
  for (let i = 0; i < text.length; i += step) s.feed(text.slice(i, i + step));
  return s.value();
}

test("chat: the first chunk's id, however the stream is cut; a keepalive and [DONE] carry none", () => {
  const sse = chatStream(CHAT_ID);
  for (const step of [1, 2, 7, 64, sse.length]) assert.equal(sniff("chat", sse, step), CHAT_ID, `cut every ${step}`);
  assert.equal(sniff("chat", sse.replaceAll("\n", "\r\n"), 5), CHAT_ID, "CRLF framing");
});

test("chat: an error event, a usage-only chunk without id and an empty id are passed over; the first id decides", () => {
  const sse = chunk({ error: { type: "mandu_fail_closed", message: "x" } }) + chunk({ usage: { total_tokens: 1 } }) + chunk({ id: "", choices: [] }) + chatStream(CHAT_ID);
  assert.equal(sniff("chat", sse, 3), CHAT_ID);
});

test("chat: an ill-formed first id gives none, never a later one; no id at all gives none", () => {
  for (const bad of ["chatcmpl with spaces", "x".repeat(200), "short", 42, { id: "chatcmpl-nested000000" }]) {
    assert.equal(sniff("chat", chatStream(bad), 4), undefined, JSON.stringify(bad));
  }
  assert.equal(sniff("chat", ": ping\n\ndata: [DONE]\n\n"), undefined);
  assert.equal(sniff("chat", ""), undefined);
});

test("responses: the first response.* event's response.id; other events and output items are passed over", () => {
  const ev = (type: string, data: Record<string, unknown>): string => `event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`;
  const sse = ev("error", { message: "x" })
    + ev("response.output_item.added", { item: { id: "msg_item0000000000", type: "message" } })
    + ev("response.created", { response: { id: RESP_ID, status: "in_progress" } })
    + ev("response.completed", { response: { id: "resp_later00000000", output: [] } });
  for (const step of [1, 9, sse.length]) assert.equal(sniff("responses", sse, step), RESP_ID);
  assert.equal(sniff("chat", sse), undefined, "a Responses stream read as Chat: no top-level id");
});

test("never throws and holds no more than one partial event: garbage, a huge undecided event", () => {
  const s = new ResponseIdSniffer("chat");
  s.feed("data: {not json\n\n");
  s.feed("\u0000\u0001 nonsense \n\n");
  s.feed(`data: ${"x".repeat(2 * 1024 * 1024)}`);
  s.feed(chunk({ id: CHAT_ID }));
  assert.equal(s.value(), undefined, "past the pending cap the id is given up");
  const t = new ResponseIdSniffer("chat");
  t.feed("data: {not json\n\n");
  t.feed(chunk({ id: CHAT_ID }));
  assert.equal(t.value(), CHAT_ID, "an unparseable event is passed over");
});

test("responseIdOfBody: a buffered answer's id, well formed, else none", () => {
  assert.equal(responseIdOfBody({ id: CHAT_ID, choices: [] }), CHAT_ID);
  assert.equal(responseIdOfBody({ id: RESP_ID, output: [] }), RESP_ID);
  for (const b of [{ id: "bad id" }, { error: { message: "rate limited" } }, null, [CHAT_ID], CHAT_ID]) assert.equal(responseIdOfBody(b), undefined, JSON.stringify(b));
});
