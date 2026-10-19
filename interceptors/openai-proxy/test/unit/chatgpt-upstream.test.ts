/**
 * chatgpt-upstream.test.ts — the proxy's two fixed upstreams
 * (docs/design/agents/agent-sign-in.md §2.4 item 2, §5, §7 "Unit (openai-proxy)").
 *
 * Codex on a ChatGPT sign-in sends its own bearer plus `chatgpt-account-id`;
 * the proxy relays such a request to the ChatGPT backend's Codex base
 * (`/v1/responses` → `/backend-api/codex/responses`) and every other one to
 * the API. Pinned here, over REAL loopback listeners standing in for both
 * upstreams (the default fetcher, no injected transport):
 *   - the choice follows the header; a declared main model is the only
 *     upstream, and a ChatGPT sign-in bound for it is refused (403), never sent;
 *   - the path mapping for `/responses` and the `/models` listing;
 *   - the sign-in's headers reach the upstream as Codex sent them, and the
 *     tool output is symbolized on the ChatGPT path exactly as on the API path;
 *   - no `authorization` or account id in any emitted event or log line;
 *   - an upstream 401 passes through, and the proxy never makes one up.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  CHATGPT_ACCOUNT_HEADER,
  CHATGPT_UPSTREAM_BASE,
  OpenAiProxy,
  chooseUpstream,
  upstreamRequestPath,
} from "../../src/proxy.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { buildTextSse } from "../helpers/mock-upstream.js";

// Axes: none. The arbiter is the in-test MockArbiter (fail-closed UNTRUSTED,
// no axis resolution); this suite pins the upstream choice and that the
// rewrite runs on it. The real arbiter's confidentiality run on this path is
// tests/stack/codex-chatgpt-relay.test.ts.

// A JWT-shaped dummy bearer and account id: never real, and each must stay
// out of every event and log line.
const BEARER = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjaS1kdW1teSJ9.c2lnbmF0dXJlLWR1bW15LW5vdC1yZWFs";
const ACCOUNT = "acct-dummy-4f1e9c2a";
const SECRET_OUTPUT = "db_password=hunter2-CHATGPT-PATH";

interface Seen { method: string; path: string; headers: Record<string, string | string[] | undefined>; body: string }

async function standIn(status = 200, sse = buildTextSse("hello")): Promise<{ server: Server; origin: string; seen: Seen[] }> {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      seen.push({ method: req.method ?? "", path: req.url ?? "", headers: req.headers, body: b });
      if (status !== 200) {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { message: "stand-in says no" } }));
        return;
      }
      if (req.method === "GET") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ models: [] }));
        return;
      }
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(sse);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { server, origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen };
}

const close = (s: Server): Promise<void> => new Promise((r) => s.close(() => r()));

function send(port: number, method: string, path: string, headers: Record<string, string>, body?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method, path, headers }, (res) => {
      let buf = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (buf += c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

const SIGNED_IN = { authorization: `Bearer ${BEARER}`, [CHATGPT_ACCOUNT_HEADER]: ACCOUNT, "content-type": "application/json", originator: "codex_exec" };
const KEYED = { authorization: "Bearer sk-dummy-key-not-real-000000", "content-type": "application/json" };

function turn2(output: string): string {
  return JSON.stringify({
    model: "gpt-5.4",
    stream: true,
    store: false,
    include: ["reasoning.encrypted_content"],
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "read notes" }] },
      { type: "function_call", call_id: "call_1", name: "exec_command", arguments: '{"cmd":"cat notes.md"}' },
      { type: "function_call_output", call_id: "call_1", output: `Output:\n${output}\n` },
    ],
  });
}

test("chooseUpstream: the header picks the ChatGPT backend; a declared model is the only upstream", () => {
  assert.equal(chooseUpstream({}, false), "api");
  assert.equal(chooseUpstream({ [CHATGPT_ACCOUNT_HEADER]: ACCOUNT }, false), "chatgpt");
  assert.equal(chooseUpstream({ [CHATGPT_ACCOUNT_HEADER]: [ACCOUNT] }, false), "chatgpt");
  // Empty or blank is no sign-in.
  assert.equal(chooseUpstream({ [CHATGPT_ACCOUNT_HEADER]: "" }, false), "api");
  assert.equal(chooseUpstream({ [CHATGPT_ACCOUNT_HEADER]: "  " }, false), "api");
  // A bearer alone (a key, or a saved `codex login --with-api-key`) is the API.
  assert.equal(chooseUpstream({ authorization: "Bearer sk-x" }, false), "api");
  assert.equal(chooseUpstream({}, true), "declared");
  assert.equal(chooseUpstream({ [CHATGPT_ACCOUNT_HEADER]: ACCOUNT }, true), "declared-refuse");
});

test("upstreamRequestPath: the ChatGPT base replaces the proxy's /v1 for /responses and /models", () => {
  const base = new URL(CHATGPT_UPSTREAM_BASE);
  assert.equal(base.origin, "https://chatgpt.com");
  assert.equal(upstreamRequestPath("/v1/responses", base, true), "/backend-api/codex/responses");
  assert.equal(upstreamRequestPath("/v1/models?client_version=0.159.1", base, true), "/backend-api/codex/models?client_version=0.159.1");
});

test("a ChatGPT sign-in goes to the ChatGPT base, symbolized, with its own headers; a key goes to the API", async () => {
  const api = await standIn();
  const chatgpt = await standIn();
  const logs: string[] = [];
  const arbiter = new MockArbiter();
  const proxy = new OpenAiProxy({
    arbiter,
    upstreamOrigin: api.origin,
    chatgptOrigin: `${chatgpt.origin}/backend-api/codex`,
    log: (m) => logs.push(m),
  });
  const port = await proxy.listen(0);
  try {
    const signed = await send(port, "POST", "/v1/responses", SIGNED_IN, turn2(SECRET_OUTPUT));
    assert.equal(signed.status, 200);
    assert.match(signed.body, /hello/);
    const models = await send(port, "GET", "/v1/models?client_version=0.159.1", { authorization: `Bearer ${BEARER}`, [CHATGPT_ACCOUNT_HEADER]: ACCOUNT });
    assert.equal(models.status, 200);
    const keyed = await send(port, "POST", "/v1/responses", KEYED, turn2("benign"));
    assert.equal(keyed.status, 200);

    assert.deepEqual(chatgpt.seen.map((s) => `${s.method} ${s.path}`), [
      "POST /backend-api/codex/responses",
      "GET /backend-api/codex/models?client_version=0.159.1",
    ]);
    assert.deepEqual(api.seen.map((s) => `${s.method} ${s.path}`), ["POST /v1/responses"]);

    const up = chatgpt.seen[0]!;
    // Relayed as Codex sent them: the backend authenticates on these.
    assert.equal(up.headers["authorization"], `Bearer ${BEARER}`);
    assert.equal(up.headers[CHATGPT_ACCOUNT_HEADER], ACCOUNT);
    assert.equal(up.headers["originator"], "codex_exec");
    // The confidentiality rule on the new destination: the tool output is a symbol.
    assert.ok(!up.body.includes(SECRET_OUTPUT), "the tool output never reaches the ChatGPT backend raw");
    assert.match(up.body, /\$MDU:exec_command\[[0-9a-f]{4}\]/);
    // The API request carries no ChatGPT header.
    assert.equal(api.seen[0]!.headers[CHATGPT_ACCOUNT_HEADER], undefined);

    // Neither the bearer nor the account id is in any event or log line.
    const recorded = JSON.stringify(arbiter.emittedEvents) + "\n" + logs.join("\n");
    assert.ok(arbiter.emittedEvents.length > 0, "the exchange emitted events");
    assert.ok(!recorded.includes(BEARER), "no bearer in events or logs");
    assert.ok(!recorded.includes(ACCOUNT), "no account id in events or logs");
  } finally {
    await proxy.close();
    await close(api.server);
    await close(chatgpt.server);
  }
});

test("FAIL-CLOSED on the ChatGPT path: an unreachable arbiter sends nothing to the backend", async () => {
  const chatgpt = await standIn();
  const proxy = new OpenAiProxy({
    arbiter: new MockArbiter({ failClassify: true }),
    upstreamOrigin: "http://127.0.0.1:9",
    chatgptOrigin: `${chatgpt.origin}/backend-api/codex`,
    log: () => {},
  });
  const port = await proxy.listen(0);
  try {
    const r = await send(port, "POST", "/v1/responses", SIGNED_IN, turn2(SECRET_OUTPUT));
    assert.equal(r.status, 502);
    assert.equal(chatgpt.seen.length, 0, "nothing reached the ChatGPT backend");
  } finally {
    await proxy.close();
    await close(chatgpt.server);
  }
});

test("a declared main model: a ChatGPT sign-in is refused 403 and sent nowhere; a keyed request goes to it", async () => {
  const declared = await standIn();
  const chatgpt = await standIn();
  const proxy = new OpenAiProxy({
    arbiter: new MockArbiter(),
    upstreamOrigin: `${declared.origin}/v1`,
    upstreamIsBaseUrl: true,
    chatgptOrigin: `${chatgpt.origin}/backend-api/codex`,
    log: () => {},
  });
  const port = await proxy.listen(0);
  try {
    const refused = await send(port, "POST", "/v1/responses", SIGNED_IN, turn2("benign"));
    assert.equal(refused.status, 403, "refused, and never a made-up 401 (that would make Codex refresh)");
    assert.match(refused.body, /ChatGPT sign-in/);
    assert.ok(!refused.body.includes(BEARER));
    const listing = await send(port, "GET", "/v1/models", { authorization: `Bearer ${BEARER}`, [CHATGPT_ACCOUNT_HEADER]: ACCOUNT });
    assert.equal(listing.status, 403);
    assert.equal(declared.seen.length, 0, "the declared server never saw the sign-in");
    assert.equal(chatgpt.seen.length, 0, "the header did not re-point the proxy");

    const keyed = await send(port, "POST", "/v1/responses", KEYED, turn2("benign"));
    assert.equal(keyed.status, 200);
    assert.deepEqual(declared.seen.map((s) => s.path), ["/v1/responses"]);
  } finally {
    await proxy.close();
    await close(declared.server);
    await close(chatgpt.server);
  }
});

test("an upstream 401 passes through as sent (Codex's own refresh decides), for /responses and /models", async () => {
  const chatgpt = await standIn(401);
  const proxy = new OpenAiProxy({
    arbiter: new MockArbiter(),
    upstreamOrigin: "http://127.0.0.1:9",
    chatgptOrigin: `${chatgpt.origin}/backend-api/codex`,
    log: () => {},
  });
  const port = await proxy.listen(0);
  try {
    const r = await send(port, "POST", "/v1/responses", SIGNED_IN, turn2("benign"));
    assert.equal(r.status, 401);
    assert.match(r.body, /stand-in says no/);
    const m = await send(port, "GET", "/v1/models", { authorization: `Bearer ${BEARER}`, [CHATGPT_ACCOUNT_HEADER]: ACCOUNT });
    assert.equal(m.status, 401);
    assert.equal(chatgpt.seen.length, 2);
  } finally {
    await proxy.close();
    await close(chatgpt.server);
  }
});

test("an injected transport serves both upstreams unless a ChatGPT one is injected (a test never reaches chatgpt.com)", async () => {
  const hits: string[] = [];
  const fetcher = (tag: string) => async ({ path }: { path: string }) => {
    hits.push(`${tag} ${path}`);
    const { Readable } = await import("node:stream");
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([buildTextSse("x")]) };
  };
  const one = new OpenAiProxy({ arbiter: new MockArbiter(), upstream: fetcher("one"), log: () => {} });
  const p1 = await one.listen(0);
  try {
    await send(p1, "POST", "/v1/responses", SIGNED_IN, turn2("benign"));
  } finally {
    await one.close();
  }
  const two = new OpenAiProxy({ arbiter: new MockArbiter(), upstream: fetcher("api"), chatgptUpstream: fetcher("chatgpt"), log: () => {} });
  const p2 = await two.listen(0);
  try {
    await send(p2, "POST", "/v1/responses", SIGNED_IN, turn2("benign"));
    await send(p2, "POST", "/v1/responses", KEYED, turn2("benign"));
  } finally {
    await two.close();
  }
  assert.deepEqual(hits, ["one /v1/responses", "chatgpt /v1/responses", "api /v1/responses"]);
});
