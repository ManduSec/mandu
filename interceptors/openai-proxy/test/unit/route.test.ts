/**
 * route.test.ts — the fail-closed request-route classifier (src/route.ts,
 * mandu.md §4.1 "Which requests go upstream"). Pure: no server, no arbiter.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { classifyRoute, isChatCompletionsPath, isResponsesPath } from "../../src/route.js";

test("POST …/responses is the transformed wire (query string, base-URL prefix, trailing slash)", () => {
  for (const p of ["/v1/responses", "/responses", "/v1/responses?x=1", "/openai/v1/responses", "/v1/responses/"]) {
    assert.equal(classifyRoute("POST", p, 10).kind, "responses", p);
  }
  assert.ok(!isResponsesPath("/v1/responses/compact"));
  assert.ok(!isResponsesPath("/v1/responses/input_tokens"));
});

test("POST …/chat/completions is the Chat wire, read and masked (chat-wire.ts)", () => {
  for (const p of ["/v1/chat/completions", "/chat/completions", "/v1/chat/completions?x=1", "/openai/v1/chat/completions/"]) {
    assert.equal(classifyRoute("POST", p, 10).kind, "chat", p);
  }
  assert.ok(!isChatCompletionsPath("/v1/completions"));
  assert.ok(!isChatCompletionsPath("/v1/chat/completions/abc"));
  assert.equal(classifyRoute("GET", "/v1/chat/completions", 5).kind, "refuse", "a GET with a body is not a read");
});

test("a bodyless GET/HEAD is relayed (the /models listing)", () => {
  assert.equal(classifyRoute("GET", "/v1/models", 0).kind, "relay");
  assert.equal(classifyRoute("GET", "/v1/models?client_version=0.154.0", 0).kind, "relay");
  assert.equal(classifyRoute("HEAD", "/v1/models", 0).kind, "relay");
});

test("every other generation or content-carrying request is refused, naming mandu and the path", () => {
  const cases: Array<[string, string, number]> = [
    ["POST", "/v1/completions", 50],
    ["PUT", "/v1/chat/completions", 50],
    ["POST", "/v1/embeddings", 50],
    ["POST", "/v1/responses/compact", 50], // older Codex remote compaction: a whole transcript
    ["POST", "/v1/responses/input_tokens", 50],
    ["POST", "/v1/files", 50],
    ["POST", "/v1/realtime/calls", 50],
    ["POST", "/v1/messages", 50],
    ["PUT", "/v1/responses", 50],
    ["DELETE", "/v1/responses/resp_1", 0],
    ["GET", "/v1/models", 5],
  ];
  for (const [m, p, n] of cases) {
    const r = classifyRoute(m, p, n);
    assert.equal(r.kind, "refuse", `${m} ${p}`);
    assert.match(r.message!, /^mandu: refusing /);
    assert.ok(r.message!.includes(p), `the message names the path: ${r.message}`);
  }
});
