/**
 * openai-chat-ullm-client.test: the second quarantined client (Plan 11 D5).
 *
 * A declared `wire: openai-chat` endpoint (Ollama, vLLM) gets ONE
 * `POST {url}/v1/chat/completions` carrying the fixed quarantine system prompt
 * and the single user turn: no tools, no history. Driven against a real local
 * HTTP server so the bytes on the wire are what is asserted.
 *
 * Axes: none. The client is transport only; the arbiter decides what reaches
 * it (confidentiality axis ON is where a local endpoint is ever chosen).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { OpenAiChatUllmClient } from "../../src/ullm-client.js";
import { buildEndpointUllmClient } from "../../src/ullm-config.js";
import { QUARANTINE_SYSTEM_PROMPT } from "../../src/inspect-symbol.js";

interface Seen { method: string; url: string; headers: IncomingMessage["headers"]; body: string }

async function withServer(
  handler: (req: IncomingMessage, body: string, res: import("node:http").ServerResponse) => void,
  fn: (base: string, seen: Seen[]) => Promise<void>,
): Promise<void> {
  const seen: Seen[] = [];
  const server: Server = createServer((req, res) => {
    let body = "";
    req.setEncoding("utf-8");
    req.on("data", (d: string) => { body += d; });
    req.on("end", () => {
      seen.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers, body });
      handler(req, body, res);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${port}`;
  try {
    await fn(base, seen);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
}

function okReply(content: unknown, model = "llama3.2:latest") {
  return (_req: IncomingMessage, _b: string, res: import("node:http").ServerResponse) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ model, choices: [{ index: 0, message: { role: "assistant", content } }] }));
  };
}

const originOf = (u: string) => new URL(u).origin;

test("request shape: one POST to /v1/chat/completions, system + ONE user message, no tools, no history", async () => {
  await withServer(okReply("  summary text  "), async (base, seen) => {
    const c = new OpenAiChatUllmClient({ baseUrl: base + "/", model: "llama3.2", sanctionedOrigins: [originOf(base)] });
    const r = await c.complete({ system: QUARANTINE_SYSTEM_PROMPT, user: "## Instruction\nsummarize\n\n## Data\nX" });
    assert.deepEqual(r, { text: "summary text", model: "llama3.2:latest" });

    assert.equal(seen.length, 1, "exactly one request");
    assert.equal(seen[0].method, "POST");
    assert.equal(seen[0].url, "/v1/chat/completions", "trailing slash on the base is normalized");
    assert.match(String(seen[0].headers["content-type"]), /application\/json/);
    assert.equal(seen[0].headers.authorization, undefined, "no token declared ⇒ no Authorization header");
    const body = JSON.parse(seen[0].body) as Record<string, unknown>;
    assert.deepEqual(Object.keys(body).sort(), ["max_tokens", "messages", "model", "stream"]);
    assert.equal(body.model, "llama3.2");
    assert.equal(body.stream, false);
    assert.deepEqual(body.messages, [
      { role: "system", content: QUARANTINE_SYSTEM_PROMPT },
      { role: "user", content: "## Instruction\nsummarize\n\n## Data\nX" },
    ]);
    assert.ok(!("tools" in body) && !("tool_choice" in body) && !("functions" in body), "no tools on the wire");
  });
});

test("bearer token: sent when given, and read from process-style env by the endpoint factory via tokenEnv", async () => {
  await withServer(okReply("ok"), async (base, seen) => {
    const c = new OpenAiChatUllmClient({ baseUrl: base, model: "m", token: "tok-1", sanctionedOrigins: [originOf(base)] });
    await c.complete({ system: "s", user: "u" });
    assert.equal(seen[0].headers.authorization, "Bearer tok-1");

    const ep = { name: "vllm", url: base, wire: "openai-chat" as const, model: "m", local: true, tokenEnv: "MY_VLLM_TOKEN" };
    const viaFactory = buildEndpointUllmClient(ep, [ep], {}, { MY_VLLM_TOKEN: "tok-from-env" });
    await viaFactory.complete({ system: "s", user: "u" });
    assert.equal(seen[1].headers.authorization, "Bearer tok-from-env", "the token comes from env[tokenEnv], never the IPC");

    const unset = buildEndpointUllmClient(ep, [ep], {}, {});
    await unset.complete({ system: "s", user: "u" });
    assert.equal(seen[2].headers.authorization, undefined, "an unset tokenEnv sends no header");
  });
});

test("response parse: array content parts are joined; a missing choices[0].message.content is an error", async () => {
  await withServer(okReply([{ type: "text", text: "a" }, { type: "text", text: "b" }]), async (base) => {
    const c = new OpenAiChatUllmClient({ baseUrl: base, model: "m", sanctionedOrigins: [originOf(base)] });
    assert.equal((await c.complete({ system: "s", user: "u" })).text, "ab");
  });
  await withServer((_q, _b, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ choices: [] })); }, async (base) => {
    const c = new OpenAiChatUllmClient({ baseUrl: base, model: "m", sanctionedOrigins: [originOf(base)] });
    await assert.rejects(c.complete({ system: "s", user: "u" }), /no choices\[0\]\.message\.content/);
  });
});

test("non-2xx is an error carrying the status and NOT the body (a local server may echo the request)", async () => {
  await withServer((_q, body, res) => { res.writeHead(400, { "content-type": "application/json" }); res.end(JSON.stringify({ error: `bad request: ${body}` })); }, async (base) => {
    const c = new OpenAiChatUllmClient({ baseUrl: base, model: "nope", sanctionedOrigins: [originOf(base)] });
    await assert.rejects(c.complete({ system: "s", user: "LOCAL-SECRET-BYTES" }), (err: Error) => {
      assert.match(err.message, /U-LLM request failed: 400/);
      assert.ok(!err.message.includes("LOCAL-SECRET-BYTES"), "the echoed request never rides out in the error");
      return true;
    });
  });
});

test("a non-JSON 200 body fails without quoting it", async () => {
  await withServer((_q, body, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end(`echo ${body}`); }, async (base) => {
    const c = new OpenAiChatUllmClient({ baseUrl: base, model: "m", sanctionedOrigins: [originOf(base)] });
    await assert.rejects(c.complete({ system: "s", user: "LOCAL-SECRET-BYTES" }), (err: Error) => {
      assert.equal(err.message, "U-LLM response was not valid JSON");
      return true;
    });
  });
});

test("timeout: a server that never answers fails the call after timeoutMs", async () => {
  await withServer(() => { /* never respond */ }, async (base) => {
    const c = new OpenAiChatUllmClient({ baseUrl: base, model: "m", timeoutMs: 150, sanctionedOrigins: [originOf(base)] });
    const t0 = Date.now();
    await assert.rejects(c.complete({ system: "s", user: "u" }), /timed out after 150ms/);
    assert.ok(Date.now() - t0 < 5000);
  });
});

test("construction: a model is required, and loopback is refused unless it is a sanctioned declared origin", () => {
  assert.throws(() => new OpenAiChatUllmClient({ baseUrl: "http://127.0.0.1:11434", model: "", sanctionedOrigins: ["http://127.0.0.1:11434"] }), /model id is required/);
  assert.throws(() => new OpenAiChatUllmClient({ baseUrl: "http://127.0.0.1:11434", model: "m" }), /loopback/);
  assert.doesNotThrow(() => new OpenAiChatUllmClient({ baseUrl: "http://127.0.0.1:11434", model: "m", sanctionedOrigins: ["http://127.0.0.1:11434"] }));
  // The forwarder relays to an external vendor: never sanctioned for this
  // client, even if a caller put its origin in the set.
  assert.throws(() => new OpenAiChatUllmClient({
    baseUrl: "http://127.0.0.1:9999", model: "m",
    sanctionedOrigins: ["http://127.0.0.1:9999"], forwarderUrl: "http://127.0.0.1:9999",
  }), /loopback/);
});
