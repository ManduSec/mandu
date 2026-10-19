/**
 * route.test.ts — the fail-closed request-route classifier (src/route.ts,
 * mandu.md §4.1 "Which requests go upstream"). Pure: no server, no arbiter.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { classifyOpenAiRoute, classifyRoute, isCountTokensPath, isMessagesPath } from "../../src/route.js";

test("POST /v1/messages is the transformed wire, with a query string and a base-URL prefix", () => {
  for (const p of ["/v1/messages", "/v1/messages?beta=true", "/anthropic/v1/messages", "/v1/messages/"]) {
    assert.equal(classifyRoute("POST", p, 10).kind, "messages", p);
  }
  assert.ok(isMessagesPath("/v1/messages?beta=true"));
  assert.ok(!isMessagesPath("/v1/messages/count_tokens"));
  assert.ok(!isMessagesPath("/v1/messages/batches"));
});

test("POST /v1/messages/count_tokens runs through the rewrite (count_tokens), never raw", () => {
  assert.equal(classifyRoute("POST", "/v1/messages/count_tokens?beta=true", 10).kind, "count_tokens");
  assert.equal(classifyRoute("post", "/x/v1/messages/count_tokens", 10).kind, "count_tokens");
  assert.ok(isCountTokensPath("/v1/messages/count_tokens"));
});

test("a bodyless GET/HEAD is relayed (model listings, Claude Code's /api/hello probe)", () => {
  assert.equal(classifyRoute("GET", "/v1/models", 0).kind, "relay");
  assert.equal(classifyRoute("GET", "/v1/models?limit=100", 0).kind, "relay");
  assert.equal(classifyRoute("HEAD", "/api/hello", 0).kind, "relay");
});

test("every other generation or content-carrying request is refused, naming mandu and the path", () => {
  const cases: Array<[string, string, number]> = [
    ["POST", "/v1/chat/completions", 50], // Anthropic's OpenAI-compatible wire
    ["POST", "/chat/completions", 50], // OpenClaw's openai-completions default
    ["POST", "/v1/complete", 50], // legacy Text Completions
    ["POST", "/v1/messages/batches", 50], // a batch of Messages requests
    ["POST", "/v1/responses", 50],
    ["POST", "/v1/files", 50],
    ["PUT", "/v1/messages", 50],
    ["PATCH", "/v1/messages", 50],
    ["DELETE", "/v1/files/f_1", 0],
    ["POST", "/v1/messages/count_tokens/extra", 50],
    ["GET", "/v1/models", 5], // a GET that carries a body is not a plain read
    ["OPTIONS", "/v1/messages", 0],
  ];
  for (const [m, p, n] of cases) {
    const r = classifyRoute(m, p, n);
    assert.equal(r.kind, "refuse", `${m} ${p}`);
    assert.match(r.message!, /^mandu: refusing /);
    assert.ok(r.message!.includes(p.split("?")[0]!), `the message names the path: ${r.message}`);
  }
});

test("OpenAI routes: chat and responses with or without one /v1 before them (Goose's default base path); nothing else is read", () => {
  const routed = new Set(["openai", "corp"]);
  const ok: Array<[string, "chat" | "responses", string]> = [
    ["/_mandu/openai/openai/chat/completions", "chat", "/chat/completions"],
    ["/_mandu/openai/openai/v1/chat/completions", "chat", "/v1/chat/completions"], // Goose, gpt-4o
    ["/_mandu/openai/openai/v1/responses", "responses", "/v1/responses"], // Goose, gpt-5 / o-series
    ["/_mandu/openai/corp/responses?x=1", "responses", "/responses?x=1"],
    ["/_mandu/openai/corp/api/v1/chat/completions", "chat", "/api/v1/chat/completions"], // Goose's openrouter provider
  ];
  for (const [p, kind, rest] of ok) {
    const r = classifyOpenAiRoute("POST", p, 10, routed);
    assert.equal(r?.kind, kind, p);
    assert.equal(r?.rest, rest, `the rest is forwarded as the agent sent it: ${p}`);
  }
  for (const p of [
    "/_mandu/openai/openai/v1/v1/chat/completions", // one /v1 only
    "/_mandu/openai/openai/v2/chat/completions",
    "/_mandu/openai/openai/v1/embeddings",
    "/_mandu/openai/openai/v1/completions",
    "/_mandu/openai/openai/x/v1/chat/completions",
    "/_mandu/openai/openai/api/v2/chat/completions",
    "/_mandu/openai/openai/api/chat/completions",
    "/_mandu/openai/openai/api/v1/v1/chat/completions",
    "/_mandu/openai/openai/api/alpha/decisions", // OpenRouter's Decisions API: not a wire the gates read
    "/_mandu/openai/openai/api/show", // Ollama's model probe
    "/_mandu/openai/other/v1/chat/completions", // a provider the launcher did not route
  ]) {
    const r = classifyOpenAiRoute("POST", p, 10, routed);
    assert.equal(r?.kind, "refuse", p);
    assert.match(r!.message!, /^mandu: refusing /);
  }
  assert.equal(classifyOpenAiRoute("GET", "/_mandu/openai/openai/v1/models", 0, routed)?.kind, "relay", "Goose's model listing");
  assert.equal(classifyOpenAiRoute("POST", "/v1/chat/completions", 10, routed), null, "outside the prefix: the Messages router decides");
});
