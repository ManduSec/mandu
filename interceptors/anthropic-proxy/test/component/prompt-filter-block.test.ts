/**
 * prompt-filter-block (proxy e2e) — the REAL AnthropicProxy over HTTP, a fake
 * upstream and a mock `filterPrompt` answering as the arbiter's phase-2
 * policy does (confidentiality-plan-15 §7, §8).
 *
 * Proves, on the Messages route and on a routed OpenAI-family route:
 *   - a prompt the policy BLOCKS is answered 400 in the wire's own error
 *     shape (Messages: `{"type":"error","error":{"type":
 *     "invalid_request_error"}}`, which Claude Code prints without retrying)
 *     with the arbiter's reason, and NOTHING reaches the model;
 *   - a `prompt_filter` event records the block (action `block`, the
 *     category, never the value);
 *   - the next turn (the refused message resent before it) reaches the model
 *     with the blocked span as `[blocked: <category>]`, never raw;
 *   - count_tokens counts the safe text and refuses nothing;
 *   - a redaction reaches the model as `[redacted: <category>]`;
 *   - a block with no safe text (a filter that could not run) is refused on
 *     every attempt.
 *
 * Axes: secrets (the mock answers as the arbiter does with confidentiality ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";

import { AnthropicProxy, type UpstreamFetcher } from "../../src/proxy.js";
import { CLAUDE_CODE_GATE_SURFACE } from "../../src/gate-surface.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { policyFilter } from "../helpers/mock-prompt-filter.js";
import { sseEvent } from "../helpers/mock-upstream.js";

const CARD = "4111 1111 1111 1111";
const TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const RULES = [
  { needle: CARD, category: "pii.payment-card", action: "block" as const },
  { needle: TOKEN, category: "secret.shape.github-token", action: "redact" as const },
];

function send(port: number, path: string, body: unknown): Promise<{ status: number; body: string }> {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json", "content-length": String(data.length), "x-mandu-session-id": "pf-block" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(data);
  });
}

const SSE = sseEvent("message_start", { type: "message_start", message: { id: "m1", role: "assistant", content: [] } })
  + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } })
  + sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "ok" } })
  + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
  + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn" } })
  + sseEvent("message_stop", { type: "message_stop" });

async function harness(arb: MockArbiter) {
  const forwarded: Array<{ path: string; body: string }> = [];
  const fetcher: UpstreamFetcher = async ({ path, body }) => {
    forwarded.push({ path, body: body.toString("utf8") });
    if (path.includes("count_tokens")) return { status: 200, headers: { "content-type": "application/json" }, body: Readable.from([Buffer.from('{"input_tokens":12}')]) };
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(SSE)]) };
  };
  const chatFetcher: UpstreamFetcher = async ({ path, body }) => {
    forwarded.push({ path, body: body.toString("utf8") });
    return { status: 200, headers: { "content-type": "application/json" }, body: Readable.from([Buffer.from(JSON.stringify({ id: "c", object: "chat.completion", choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }] }))]) };
  };
  const proxy = new AnthropicProxy({ arbiter: arb, sessionKey: "s-block", log: () => {}, upstream: fetcher, openaiUpstreams: { local: "http://127.0.0.1:9/v1" }, openaiFetcher: () => chatFetcher });
  const port = await proxy.listen(0);
  return { proxy, port, forwarded };
}

const turn = (...texts: string[]) => ({
  model: "claude-sonnet-4-5", stream: true, max_tokens: 64, tools: [{ name: "Read", input_schema: {} }],
  messages: texts.flatMap((t, i) => [
    { role: "user", content: [{ type: "text", text: t }] },
    ...(i < texts.length - 1 ? [{ role: "assistant", content: [{ type: "text", text: "(no answer)" }] }] : []),
  ]),
});

test("Messages: a blocked prompt is a 400 the agent shows, nothing is sent, an event records it; the next turn carries [blocked: …]", async () => {
  const arb = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, filterPromptFn: policyFilter(RULES) });
  const h = await harness(arb);
  try {
    const first = `pay ${CARD} and push ${TOKEN}`;
    // count_tokens first (Claude Code counts before it sends): the safe text, no refusal.
    const c = await send(h.port, "/v1/messages/count_tokens", { model: "claude-sonnet-4-5", messages: turn(first).messages });
    assert.equal(c.status, 200, c.body);
    const r = await send(h.port, "/v1/messages", turn(first));
    assert.equal(r.status, 400, r.body);
    const err = JSON.parse(r.body) as { type: string; error: { type: string; message: string } };
    assert.equal(err.type, "error");
    assert.equal(err.error.type, "invalid_request_error");
    assert.match(err.error.message, /Mandu blocked this prompt: it contains pii\.payment-card/);
    assert.ok(!r.body.includes(CARD));
    assert.deepEqual(h.forwarded.map((f) => f.path.split("?")[0]), ["/v1/messages/count_tokens"], "the model received nothing for the blocked turn");
    const next = await send(h.port, "/v1/messages", turn(first, "never mind, say hi"));
    assert.equal(next.status, 200, next.body);
    const sent = h.forwarded.at(-1)!.body;
    assert.ok(sent.includes("pay [blocked: pii.payment-card] and push [redacted: secret.shape.github-token]"), sent);
    for (const f of h.forwarded) {
      assert.ok(!f.body.includes(CARD), "CONFIDENTIALITY VIOLATION: a blocked card reached the provider");
      assert.ok(!f.body.includes(TOKEN), "CONFIDENTIALITY VIOLATION: a redacted token reached the provider");
    }
  } finally {
    await h.proxy.close();
  }
  const ev = arb.eventsOfKind("prompt_filter").map((e) => (e as unknown as { promptFilter: { action: string; findings: Array<{ action: string; category: string }> } }).promptFilter);
  assert.ok(ev.some((d) => d.action === "block" && d.findings.some((f) => f.action === "block" && f.category === "pii.payment-card")), JSON.stringify(ev));
  for (const e of arb.eventsOfKind("prompt_filter")) assert.ok(!JSON.stringify(e).includes(CARD), "an event never carries the value");
});

test("a block with no safe text (a filter that could not run) is refused on every attempt", async () => {
  const arb = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, filterPromptFn: policyFilter(RULES, { noText: true }) });
  const h = await harness(arb);
  try {
    for (let i = 0; i < 2; i++) assert.equal((await send(h.port, "/v1/messages", turn(`pay ${CARD}`))).status, 400);
    assert.equal(h.forwarded.length, 0);
  } finally {
    await h.proxy.close();
  }
});

test("a routed Chat Completions request (OpenClaw): the block is the OpenAI error shape, and nothing is sent", async () => {
  const arb = new MockArbiter({ gateSurfaceFn: () => ({ ...CLAUDE_CODE_GATE_SURFACE, spec: "opencode" }), filterPromptFn: policyFilter(RULES) });
  const h = await harness(arb);
  try {
    const body = { model: "local", stream: false, tools: [{ type: "function", function: { name: "read", parameters: {} } }], messages: [{ role: "user", content: `pay ${CARD}` }] };
    const r = await send(h.port, "/_mandu/openai/local/chat/completions", body);
    assert.equal(r.status, 400, r.body);
    const err = JSON.parse(r.body) as { error: { type: string; message: string } };
    assert.equal(err.error.type, "invalid_request_error");
    assert.match(err.error.message, /pii\.payment-card/);
    assert.equal(h.forwarded.length, 0);
    const again = await send(h.port, "/_mandu/openai/local/chat/completions", { ...body, messages: [...body.messages, { role: "assistant", content: "?" }, { role: "user", content: "say hi" }] });
    assert.equal(again.status, 200, again.body);
    assert.ok(h.forwarded.at(-1)!.body.includes("pay [blocked: pii.payment-card]"));
    assert.ok(!h.forwarded.some((f) => f.body.includes(CARD)));
  } finally {
    await h.proxy.close();
  }
});
