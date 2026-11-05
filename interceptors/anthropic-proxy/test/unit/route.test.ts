/**
 * route.test.ts — the fail-closed request-route classifier (src/route.ts,
 * mandu.md §4.1 "Which requests go upstream"). Pure: no server, no arbiter.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { classifyGoogleRoute, classifyOllamaRoute, classifyOpenAiRoute, classifyRoute, classifyVertexRoute, isCountTokensPath, isMessagesPath, upstreamRest, vertexOrigin } from "../../src/route.js";

test("Vertex AI at the root (model-wires.md §4.1): OpenClaw's path under the session's one Vertex provider; everything else refused or not a Vertex path", () => {
  const V = "/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-2.5-flash";
  assert.deepEqual(classifyVertexRoute("POST", `${V}:streamGenerateContent?alt=sse`, 10, "google-vertex"),
    { kind: "stream", provider: "google-vertex", rest: `${V}:streamGenerateContent?alt=sse`, model: "gemini-2.5-flash", sse: true, location: "us-central1" });
  assert.equal(classifyVertexRoute("POST", `${V}:streamGenerateContent`, 10, "google-vertex")!.sse, false);
  assert.equal(classifyVertexRoute("POST", `${V}:generateContent`, 10, "google-vertex")!.kind, "generate");
  assert.equal(classifyVertexRoute("POST", V.replace("/v1/", "/v1beta1/") + ":generateContent", 10, "google-vertex")!.kind, "generate");
  assert.equal(classifyVertexRoute("GET", "/v1/projects/p/locations/global", 0, "google-vertex")!.kind, "relay");
  // Not Vertex paths: the Messages routes and the provider-prefixed routes.
  for (const p of ["/v1/messages", "/v1/messages/count_tokens", "/_mandu/google/google/models/g:generateContent", "/v1/models", "/v1/projects"]) {
    assert.equal(classifyVertexRoute("POST", p, 10, "google-vertex"), null, p);
  }
  // Refused, with nothing sent.
  const why = (m: string, p: string, n = 10, prov: string | null = "google-vertex"): string => {
    const r = classifyVertexRoute(m, p, n, prov)!;
    assert.equal(r.kind, "refuse", p);
    return r.message!;
  };
  assert.match(why("POST", `${V}:streamGenerateContent`, 10, null), /this session routes no Vertex AI provider through Mandu, so nothing was sent/);
  assert.match(why("POST", "/v1/projects/p/locations/us-east5/publishers/anthropic/models/claude:streamRawPredict"), /not publisher "anthropic".*anthropic-vertex/);
  assert.match(why("POST", `${V}:countTokens`), /only on POST/);
  assert.match(why("GET", `${V}:streamGenerateContent`, 5), /only on POST/, "a GET with a body is not a read");
  for (const loc of ["evil.example", "US-CENTRAL1", "a..b", "-x", "x-", "a%2Fb", "a%20b"]) {
    assert.match(why("POST", `/v1/projects/p/locations/${loc}/publishers/google/models/g:generateContent`), /is not a Vertex region name|only on POST/, loc);
  }
});

test("vertexOrigin: Google's own host per location as OpenClaw picks it, the session's own address for every location, nothing for a name that is not a region", () => {
  assert.equal(vertexOrigin(null, "global"), "https://aiplatform.googleapis.com");
  assert.equal(vertexOrigin(null, "us"), "https://aiplatform.us.rep.googleapis.com");
  assert.equal(vertexOrigin(null, "eu"), "https://aiplatform.eu.rep.googleapis.com");
  assert.equal(vertexOrigin(null, "asia-northeast3"), "https://asia-northeast3-aiplatform.googleapis.com");
  assert.equal(vertexOrigin("https://psc.example", "us-central1"), "https://psc.example");
  for (const bad of ["", "evil.com", "a/b", "a@b", "A", "a--b", "x".repeat(64)]) assert.equal(vertexOrigin(null, bad), null, bad);
});

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
    // OpenClaw's azure-openai-responses: the AzureOpenAI client's api-version query rides along.
    ["/_mandu/openai/corp/responses?api-version=v1", "responses", "/responses?api-version=v1"],
    // OpenClaw's openai-chatgpt-responses joins /codex/responses to its base (model-wires.md §9).
    ["/_mandu/openai/openai/codex/responses", "responses", "/codex/responses"],
    ["/_mandu/openai/openai/codex/responses/", "responses", "/codex/responses/"],
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
    "/_mandu/openai/openai/codex/chat/completions", // only Responses under /codex
    "/_mandu/openai/openai/v1/codex/responses",
    "/_mandu/openai/openai/codex/responses/compact", // the backend's compaction call: not read
    "/_mandu/openai/openai/deployments/gpt/responses", // Azure's deployment path: OpenClaw never sends it
    "/_mandu/openai/other/v1/chat/completions", // a provider the launcher did not route
  ]) {
    const r = classifyOpenAiRoute("POST", p, 10, routed);
    assert.equal(r?.kind, "refuse", p);
    assert.match(r!.message!, /^mandu: refusing /);
  }
  assert.equal(classifyOpenAiRoute("GET", "/_mandu/openai/openai/v1/models", 0, routed)?.kind, "relay", "Goose's model listing");
  assert.equal(classifyOpenAiRoute("POST", "/v1/chat/completions", 10, routed), null, "outside the prefix: the Messages router decides");
});

test("Gemini routes (model-wires.md §4.1): generateContent and streamGenerateContent, with an API version or a Vertex path before them; nothing else is read", () => {
  const routed = new Set(["google", "corp"]);
  const ok: Array<[string, "generate" | "stream", string, boolean | undefined]> = [
    ["/_mandu/google/google/models/gemini-2.5-flash:streamGenerateContent?alt=sse", "stream", "gemini-2.5-flash", true], // OpenClaw, OpenCode
    ["/_mandu/google/google/v1beta/models/gemini-3-pro:streamGenerateContent?alt=sse", "stream", "gemini-3-pro", true], // Goose
    ["/_mandu/google/google/models/gemini-2.5-flash:streamGenerateContent", "stream", "gemini-2.5-flash", false], // the JSON-array stream
    ["/_mandu/google/corp/v1/models/gemini-2.5-pro:generateContent?key=AIza-not-logged", "generate", "gemini-2.5-pro", undefined],
    ["/_mandu/google/corp/v1/projects/p1/locations/us-central1/publishers/google/models/gemini-2.5-pro:generateContent", "generate", "gemini-2.5-pro", undefined],
  ];
  for (const [p, kind, model, sse] of ok) {
    const r = classifyGoogleRoute("POST", p, 10, routed);
    assert.equal(r?.kind, kind, p);
    assert.equal(r?.model, model, p);
    assert.equal(r?.sse, sse, p);
    assert.equal(r?.rest, p.slice(p.indexOf("/", "/_mandu/google/".length)), "the rest is forwarded as the agent sent it");
  }
  for (const p of [
    "/_mandu/google/google/models/gemini-2.5-flash:countTokens",
    "/_mandu/google/google/models/text-embedding-004:embedContent",
    "/_mandu/google/google/models/gemini-2.5-flash:batchGenerateContent",
    "/_mandu/google/google/v1beta/cachedContents",
    "/_mandu/google/google/upload/v1beta/files",
    "/_mandu/google/google/v1beta/interactions",
    "/_mandu/google/google/v2/models/g:generateContent",
    "/_mandu/google/google/x/models/g:generateContent",
    "/_mandu/google/google/models/g:generateContent/extra",
    "/_mandu/google/google/tunedModels/t:generateContent",
    "/_mandu/google/other/models/g:generateContent", // a provider the launcher did not route
  ]) {
    const r = classifyGoogleRoute("POST", p, 10, routed);
    assert.equal(r?.kind, "refuse", p);
    assert.match(String(r?.message), /^mandu: refusing POST/, p);
  }
  assert.equal(classifyGoogleRoute("GET", "/_mandu/google/google/v1beta/models", 0, routed)?.kind, "relay");
  assert.equal(classifyGoogleRoute("GET", "/_mandu/google/google/v1beta/models", 5, routed)?.kind, "refuse");
  assert.equal(classifyGoogleRoute("POST", "/_mandu/openai/google/chat/completions", 5, routed), null, "outside the prefix");
  assert.equal(classifyGoogleRoute("POST", "/v1/messages", 5, routed), null);
});

test("Ollama routes: POST /api/chat gated, /api/show a lookup the proxy checks, bodyless reads relayed, everything else refused", () => {
  const routed = new Set(["ollama", "lan.box"]);
  assert.deepEqual(classifyOllamaRoute("POST", "/_mandu/ollama/ollama/api/chat", 10, routed), { kind: "chat", provider: "ollama", rest: "/api/chat" });
  assert.equal(classifyOllamaRoute("POST", "/_mandu/ollama/lan.box/api/chat?x=1", 10, routed)?.kind, "chat");
  assert.equal(classifyOllamaRoute("POST", "/_mandu/ollama/ollama/api/chat/", 10, routed)?.kind, "chat");
  assert.equal(classifyOllamaRoute("POST", "/_mandu/ollama/ollama/api/show", 10, routed)?.kind, "show");
  for (const p of ["/api/tags", "/api/version", "/api/ps", "/"]) {
    assert.equal(classifyOllamaRoute("GET", `/_mandu/ollama/ollama${p}`, 0, routed)?.kind, "relay", p);
  }
  assert.equal(classifyOllamaRoute("GET", "/_mandu/ollama/ollama/api/tags", 5, routed)?.kind, "refuse", "a GET with a body");
  for (const [m, p] of [["POST", "/api/generate"], ["POST", "/api/embed"], ["POST", "/api/embeddings"], ["POST", "/api/pull"],
    ["POST", "/api/push"], ["POST", "/api/create"], ["POST", "/api/copy"], ["DELETE", "/api/delete"], ["POST", "/api/blobs/sha256:00"],
    ["POST", "/api/web_search"], ["POST", "/v1/chat/completions"], ["POST", "/api/%63hat"]]) {
    const r = classifyOllamaRoute(m!, `/_mandu/ollama/ollama${p}`, 10, routed);
    assert.equal(r?.kind, "refuse", p);
    assert.match(String(r?.message), new RegExp(`^mandu: refusing ${m}`), p);
  }
  const unrouted = classifyOllamaRoute("POST", "/_mandu/ollama/other/api/chat", 10, routed);
  assert.equal(unrouted?.kind, "refuse");
  assert.match(String(unrouted?.message), /did not route that provider/);
  assert.equal(classifyOllamaRoute("POST", "/_mandu/google/ollama/api/chat", 10, routed), null, "outside the prefix");
  assert.equal(classifyOllamaRoute("POST", "/v1/messages", 10, routed), null);
});

test("upstreamRest (model-wires.md §9): below a /codex base, OpenClaw's /codex/responses is /responses; every other path as sent", () => {
  const codex = "https://chatgpt.com/backend-api/codex";
  assert.equal(upstreamRest(codex, "/responses"), "/responses", "the SDK transport");
  assert.equal(upstreamRest(codex, "/codex/responses"), "/responses", "@openclaw/ai's ChatGPT transport");
  assert.equal(upstreamRest(`${codex}/`, "/codex/responses?x=1"), "/responses?x=1");
  assert.equal(upstreamRest("https://gw.example/x", "/codex/responses"), "/codex/responses", "another base: as sent");
  assert.equal(upstreamRest(codex, "/codex/models"), "/codex/models");
  assert.equal(upstreamRest(codex, "/codex/responsesx"), "/codex/responsesx");
  assert.equal(upstreamRest(undefined, "/codex/responses"), "/codex/responses");
  assert.equal(upstreamRest("not a url", "/codex/responses"), "/codex/responses");
});
