/**
 * prompt-filter-block (proxy e2e) — the REAL OpenAiProxy over HTTP, a fake
 * upstream and a mock `filterPrompt` answering as the arbiter's phase-2
 * policy does (confidentiality-plan-15 §7, §8). The twin of the
 * anthropic-proxy's test, for Codex's Responses and Chat Completions routes.
 *
 * Proves: a prompt the policy BLOCKS is a 400 `invalid_request_error` with
 * the arbiter's reason and nothing reaches the provider; a `prompt_filter`
 * event records it; the next turn (the refused message resent before it)
 * reaches the provider with `[blocked: <category>]`, never raw; a redaction
 * reaches it as `[redacted: <category>]`; a block with no safe text is
 * refused on every attempt.
 *
 * Axes: secrets (the mock answers as the arbiter does with confidentiality ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { OpenAiProxy } from "../../src/proxy.js";
import { MockArbiter, type MockArbiterOptions } from "../helpers/mock-arbiter.js";
import { MockUpstream } from "../helpers/mock-upstream.js";
import { policyFilter } from "../helpers/mock-prompt-filter.js";
import { PromptBlockLedger } from "../../src/prompt-filter.js";
import { rewriteRequest, RewriteBlocked, RewriteRefusal } from "../../src/rewrite-request.js";

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
      { host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json", "content-length": String(data.length), "x-mandu-session-id": "pf-codex-block", authorization: "Bearer sk-test-not-real" } },
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

async function withProxy(opts: MockArbiterOptions, json: unknown, fn: (port: number, upstream: MockUpstream, arbiter: MockArbiter) => Promise<void>): Promise<void> {
  const arbiter = new MockArbiter(opts);
  const upstream = new MockUpstream({ json });
  const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {} });
  const port = await proxy.listen(0);
  try { await fn(port, upstream, arbiter); } finally { await proxy.close(); }
}

const RESPONSE = { id: "r1", object: "response", output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text: "ok" }] }] };
const msg = (text: string) => ({ type: "message", role: "user", content: [{ type: "input_text", text }] });
const responses = (...texts: string[]) => ({ model: "gpt-5", stream: false, tools: [{ type: "function", name: "exec_command", parameters: {} }], input: texts.map(msg) });

test("Responses: a blocked prompt is a 400 with the reason and nothing is sent; the next turn carries [blocked: …]", async () => {
  await withProxy({ filterPromptFn: policyFilter(RULES) }, RESPONSE, async (port, upstream, arbiter) => {
    const first = `pay ${CARD} and push ${TOKEN}`;
    const r = await send(port, "/v1/responses", responses(first));
    assert.equal(r.status, 400, r.body);
    const err = JSON.parse(r.body) as { error: { type: string; message: string } };
    assert.equal(err.error.type, "invalid_request_error");
    assert.match(err.error.message, /Mandu blocked this prompt: it contains pii\.payment-card/);
    assert.equal(upstream.requests.length, 0, "the provider received nothing for the blocked turn");
    const ev = arbiter.eventsOfKind("prompt_filter").map((e) => (e as unknown as { promptFilter: { action: string } }).promptFilter);
    assert.ok(ev.some((d) => d.action === "block"), JSON.stringify(ev));
    const next = await send(port, "/v1/responses", responses(first, "never mind, say hi"));
    assert.equal(next.status, 200, next.body);
    const sent = JSON.stringify(upstream.requests.at(-1)!.json());
    assert.ok(sent.includes("pay [blocked: pii.payment-card] and push [redacted: secret.shape.github-token]"), sent);
    for (const q of upstream.requests) {
      const b = JSON.stringify(q.json());
      assert.ok(!b.includes(CARD), "CONFIDENTIALITY VIOLATION: a blocked card reached the provider");
      assert.ok(!b.includes(TOKEN), "CONFIDENTIALITY VIOLATION: a redacted token reached the provider");
    }
  });
});

test("Chat Completions: the block is a 400 too, and nothing is sent", async () => {
  const chat = { id: "c", object: "chat.completion", choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }] };
  await withProxy({ filterPromptFn: policyFilter(RULES) }, chat, async (port, upstream) => {
    const body = {
      model: "gpt-5", stream: false, tools: [{ type: "function", function: { name: "exec_command", parameters: {} } }],
      messages: [{ role: "user", content: "<environment_context><cwd>/w</cwd></environment_context>" }, { role: "user", content: `pay ${CARD}` }],
    };
    const r = await send(port, "/v1/chat/completions", body);
    assert.equal(r.status, 400, r.body);
    assert.equal(upstream.requests.length, 0);
  });
});

test("a block with no safe text is refused on every attempt; without a ledger every block refuses", async () => {
  await withProxy({ filterPromptFn: policyFilter(RULES, { noText: true }) }, RESPONSE, async (port, upstream) => {
    for (let i = 0; i < 2; i++) assert.equal((await send(port, "/v1/responses", responses(`pay ${CARD}`))).status, 400);
    assert.equal(upstream.requests.length, 0);
  });
  const arbiter = new MockArbiter({ filterPromptFn: policyFilter(RULES) });
  for (let i = 0; i < 2; i++) {
    await assert.rejects(rewriteRequest(responses(`pay ${CARD}`) as never, { arbiter, skipPromptInjection: true }), (e: unknown) => e instanceof RewriteBlocked && e instanceof RewriteRefusal);
  }
  const ledger = new PromptBlockLedger();
  await assert.rejects(rewriteRequest(responses(`pay ${CARD}`) as never, { arbiter, skipPromptInjection: true, promptBlockLedger: ledger }), RewriteBlocked);
  // the same message again with nothing after it is the agent's own retry
  // (2026-10-04): refused again, so the human sees the reason
  await assert.rejects(rewriteRequest(responses(`pay ${CARD}`) as never, { arbiter, skipPromptInjection: true, promptBlockLedger: ledger }), RewriteBlocked);
  const { request } = await rewriteRequest(responses(`pay ${CARD}`, "never mind") as never, { arbiter, skipPromptInjection: true, promptBlockLedger: ledger });
  assert.ok(JSON.stringify(request).includes("[blocked: pii.payment-card]"));
});

test("the agent's own retry of a refused prompt over HTTP (nothing the human wrote after it) is a 400 again; the next turn goes with [blocked: …]", async () => {
  await withProxy({ filterPromptFn: policyFilter(RULES) }, RESPONSE, async (port, upstream) => {
    const first = `pay ${CARD}`;
    for (let i = 0; i < 3; i++) assert.equal((await send(port, "/v1/responses", responses(first))).status, 400);
    assert.equal(upstream.requests.length, 0, "no retry of the refused message reached the provider");
    assert.equal((await send(port, "/v1/responses", responses(first, "ok, without it"))).status, 200);
    const sent = JSON.stringify(upstream.requests.at(-1)!.json());
    assert.ok(sent.includes("pay [blocked: pii.payment-card]") && !sent.includes(CARD), sent);
  });
});
