/**
 * auth-substitution — the agent's own key put back in the auth header of the
 * request the proxy forwards (agent-sign-in.md §3): the two header shapes,
 * the upstream's host as the destination, every other place untouched, and
 * every failure keeping the placeholder (the provider then answers 401).
 * Pure functions first, then the proxy over a loopback socket against a mock
 * arbiter and mock upstreams, on the Messages wire and an OpenAI route. Made
 * up keys only; no network.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { authHeaderSymbol, substituteAuthHeaders, upstreamDestination, type AuthCredentialSource } from "../../src/auth-substitution.js";
import { AnthropicProxy } from "../../src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildTextSse } from "../helpers/mock-upstream.js";

const SYM = "$MDU:nomodel_Read[a1b2].ANTHROPIC_API_KEY";
const OSYM = "$MDU:nomodel_Read[a1b2].OPENAI_API_KEY";
const KEY = "sk-ant-api03-MANDUFAKEsubstKEY0123456789";
const OKEY = "sk-proj-MANDUFAKEsubstOPENAI0123456789";

/** An arbiter side that releases `values` at `host` only, and records asks. */
function source(host: string, values: Record<string, string>): AuthCredentialSource & { asks: Array<{ symbol: string; destination: string; scheme: string }> } {
  const asks: Array<{ symbol: string; destination: string; scheme: string }> = [];
  return {
    asks,
    async authCredential(req) {
      asks.push({ symbol: req.symbol, destination: req.destination, scheme: req.scheme });
      if (req.destination.replace(/:\d+$/, "") !== host) return { value: null, reason: `unbound destination '${req.destination}'` };
      const v = values[req.symbol];
      return v === undefined ? { value: null, reason: "unknown" } : { value: v, reason: "bound" };
    },
  };
}

test("authHeaderSymbol: x-api-key holding exactly one placeholder, or Bearer <placeholder>; nothing else", () => {
  assert.equal(authHeaderSymbol("x-api-key", SYM)?.symbol, SYM);
  assert.equal(authHeaderSymbol("X-Api-Key", SYM)?.render("v"), "v");
  assert.equal(authHeaderSymbol("authorization", `Bearer ${OSYM}`)?.symbol, OSYM);
  assert.equal(authHeaderSymbol("Authorization", `bearer ${OSYM}`)?.render("v"), "bearer v");
  for (const [n, v] of [
    ["x-api-key", `${SYM} `], ["x-api-key", `x${SYM}`], ["x-api-key", `${SYM}${SYM}`], ["x-api-key", "sk-ant-real"],
    ["authorization", SYM], ["authorization", `Basic ${SYM}`], ["authorization", `Bearer ${SYM} extra`],
    ["x-goog-api-key", SYM], ["cookie", SYM], ["x-mandu-session-id", SYM], ["user-agent", SYM],
  ] as const) {
    assert.equal(authHeaderSymbol(n, v), null, `${n}: ${v}`);
  }
});

test("upstreamDestination: the upstream's host and scheme, or null", () => {
  assert.deepEqual(upstreamDestination("https://api.anthropic.com"), { host: "api.anthropic.com", scheme: "https" });
  assert.deepEqual(upstreamDestination("http://127.0.0.1:8080/v1"), { host: "127.0.0.1:8080", scheme: "http" });
  assert.equal(upstreamDestination("not a url"), null);
  assert.equal(upstreamDestination("ftp://h"), null);
});

test("substituteAuthHeaders: the key goes in the auth header for the bound host only; every failure keeps the placeholder", async () => {
  const src = source("api.anthropic.com", { [SYM]: KEY, [OSYM]: OKEY });
  const dest = { host: "api.anthropic.com", scheme: "https" as const };
  const h: Record<string, string | string[] | undefined> = { "x-api-key": SYM, authorization: `Bearer ${OSYM}`, "x-other": SYM, "content-type": "application/json" };
  const subs = await substituteAuthHeaders(h, dest, src, "s-1");
  assert.equal(h["x-api-key"], KEY);
  assert.equal(h["authorization"], `Bearer ${OKEY}`);
  assert.equal(h["x-other"], SYM, "a header Mandu does not read keeps its text");
  assert.deepEqual(subs.map((s) => [s.header, s.restored]), [["x-api-key", true], ["authorization", true]]);
  assert.ok(src.asks.every((a) => a.destination === "api.anthropic.com" && a.scheme === "https"));
  assert.ok(!JSON.stringify(subs).includes(KEY) && !JSON.stringify(subs).includes(OKEY), "the records never carry a value");

  // An unbound host, an unknown symbol, no source, no destination, a throw,
  // and a value with a line break: the placeholder stays.
  const cases: Array<[string, AuthCredentialSource | undefined, { host: string; scheme: "https" | "http" } | null]> = [
    ["unbound", src, { host: "evil.example", scheme: "https" }],
    ["no source", undefined, dest],
    ["no destination", src, null],
    ["throws", { authCredential: async () => { throw new Error("arbiter gone"); } }, dest],
    ["null", { authCredential: async () => ({ value: null, reason: "denied" }) }, dest],
    ["crlf", { authCredential: async () => ({ value: `${KEY}\r\nx-evil: 1`, reason: "bound" }) }, dest],
    ["space", { authCredential: async () => ({ value: "a b", reason: "bound" }) }, dest],
  ];
  for (const [why, s, d] of cases) {
    const hh: Record<string, string | string[] | undefined> = { "x-api-key": SYM };
    const r = await substituteAuthHeaders(hh, d, s);
    assert.equal(hh["x-api-key"], SYM, why);
    assert.equal(r[0]?.restored, false, why);
  }
  // An array-valued header is not read.
  const arr: Record<string, string | string[] | undefined> = { "x-api-key": [SYM, SYM] };
  assert.deepEqual(await substituteAuthHeaders(arr, dest, src), []);
});

test("ArbiterClientAdapter.authCredential: the gate then the resolve, both on the HUMAN client; none ⇒ null", async () => {
  const calls: string[] = [];
  const data = {
    async desymbolizationDecision() { calls.push("data:decide"); return { allow: true as const, reason: "x" }; },
    async resolve() { calls.push("data:resolve"); return KEY; },
  } as unknown as RealArbiterClient;
  const human = {
    async symbolShape() { return null; }, async sessionRelay() { return null; }, async noteReserveBlock() {},
    async desymbolizationDecision(req: { symbol: string; destination?: string; scheme?: string; boundary: string }) {
      calls.push(`human:decide:${req.boundary}:${req.destination}:${req.scheme}`);
      return req.destination === "api.anthropic.com" ? { allow: true as const, reason: "bound" } : { allow: false as const, requiresApproval: true, reason: "unbound" };
    },
    async resolve(s: string) { calls.push("human:resolve"); return s === SYM ? KEY : null; },
  };
  const a = new ArbiterClientAdapter(data, human as never);
  assert.deepEqual(await a.authCredential({ symbol: SYM, destination: "api.anthropic.com", scheme: "https" }), { value: KEY, reason: "bound" });
  assert.equal((await a.authCredential({ symbol: SYM, destination: "evil.example", scheme: "https" })).value, null);
  assert.equal((await a.authCredential({ symbol: OSYM, destination: "api.anthropic.com", scheme: "https" })).value, null, "a null resolve");
  assert.deepEqual(calls, [
    "human:decide:network:api.anthropic.com:https", "human:resolve",
    "human:decide:network:evil.example:https",
    "human:decide:network:api.anthropic.com:https", "human:resolve",
  ], "never the data socket");
  const noHuman = new ArbiterClientAdapter(data);
  assert.equal((await noHuman.authCredential({ symbol: SYM, destination: "api.anthropic.com", scheme: "https" })).value, null);
  assert.ok(!calls.some((c) => c.startsWith("data:")), "the data socket is never asked");
});

function send(port: number, method: string, path: string, headers: Record<string, string>, body?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method, path, headers: { "content-type": "application/json", ...headers } }, (res) => {
      let buf = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (buf += c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
    });
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

test("the proxy: the Messages upstream gets the key in x-api-key; the body keeps the symbol; an unbound upstream gets the placeholder", async () => {
  for (const [origin, bound] of [["https://api.anthropic.com", true], ["https://other.example", false]] as const) {
    const arbiter = new MockArbiter();
    const src = source("api.anthropic.com", { [SYM]: KEY });
    Object.assign(arbiter, { authCredential: src.authCredential });
    const up = new MockUpstream({ sse: buildTextSse("hi") });
    const proxy = new AnthropicProxy({ arbiter, upstream: up.fetcher, upstreamOrigin: origin, sessionKey: "s-1", log: () => {} });
    const port = await proxy.listen(0);
    try {
      const body = JSON.stringify({ model: "claude-test", stream: true, messages: [{ role: "user", content: `my key is ${SYM}` }] });
      const r = await send(port, "POST", "/v1/messages", { "x-api-key": SYM, "x-other": SYM }, body);
      assert.equal(r.status, 200);
      const sent = up.requests[0]!;
      assert.equal(sent.headers["x-api-key"], bound ? KEY : SYM, origin);
      assert.equal(sent.headers["x-other"], SYM, "another header is relayed as written");
      assert.ok(!sent.bodyText.includes(KEY), "INVARIANT: the key never enters the request body (the model's context)");
      assert.ok(sent.bodyText.includes(SYM), "the body keeps the symbol");
      // A bodyless relay (GET /v1/models) gets the same header treatment.
      await send(port, "GET", "/v1/models", { "x-api-key": SYM });
      assert.equal(up.requests.at(-1)!.headers["x-api-key"], bound ? KEY : SYM);
    } finally {
      await proxy.close();
    }
  }
});

test("the proxy: an OpenAI route gets the key as Bearer for ITS upstream's host only, on both wires and the relay", async () => {
  const arbiter = new MockArbiter();
  const src = source("api.openai.com", { [OSYM]: OKEY });
  Object.assign(arbiter, { authCredential: src.authCredential });
  const chat = new MockUpstream({ raw: { contentType: "text/event-stream", body: `data: ${JSON.stringify({ id: "c", object: "chat.completion.chunk", created: 1, model: "m", choices: [{ index: 0, delta: { content: "ok" }, finish_reason: "stop" }] })}\n\ndata: [DONE]\n\n` } });
  const other = new MockUpstream({ raw: { contentType: "text/event-stream", body: "data: [DONE]\n\n" } });
  const proxy = new AnthropicProxy({
    arbiter, sessionKey: "s-1", log: () => {},
    upstream: async () => { throw new Error("the Anthropic upstream was called"); },
    openaiUpstreams: { openai: "https://api.openai.com/v1", other: "https://llm.corp.example/v1" },
    openaiFetcher: (p) => (p === "openai" ? chat : other).fetcher,
  });
  const port = await proxy.listen(0);
  try {
    const req = JSON.stringify({ model: "gpt-4o", stream: true, messages: [{ role: "user", content: `key ${OSYM}` }] });
    await send(port, "POST", "/_mandu/openai/openai/chat/completions", { authorization: `Bearer ${OSYM}` }, req);
    const sent = chat.requests[0]!;
    assert.equal(sent.headers["authorization"], `Bearer ${OKEY}`);
    assert.ok(!sent.bodyText.includes(OKEY) && sent.bodyText.includes(OSYM), "INVARIANT: the body keeps the symbol");
    await send(port, "GET", "/_mandu/openai/openai/models", { authorization: `Bearer ${OSYM}` });
    assert.equal(chat.requests.at(-1)!.headers["authorization"], `Bearer ${OKEY}`, "the relay");
    // Another route's upstream is another host: the placeholder stays.
    await send(port, "POST", "/_mandu/openai/other/chat/completions", { authorization: `Bearer ${OSYM}` }, req);
    assert.equal(other.requests[0]!.headers["authorization"], `Bearer ${OSYM}`);
    assert.deepEqual([...new Set(src.asks.map((a) => a.destination))].sort(), ["api.openai.com", "llm.corp.example"]);
  } finally {
    await proxy.close();
  }
});

test("the proxy without the op (no human plane): the placeholder is relayed, nothing else changes", async () => {
  const arbiter = new MockArbiter();
  const up = new MockUpstream({ sse: buildTextSse("hi") });
  const proxy = new AnthropicProxy({ arbiter, upstream: up.fetcher, sessionKey: "s-1", log: () => {} });
  const port = await proxy.listen(0);
  try {
    await send(port, "POST", "/v1/messages", { "x-api-key": SYM }, JSON.stringify({ model: "claude-test", stream: true, messages: [{ role: "user", content: "hi" }] }));
    assert.equal(up.requests[0]!.headers["x-api-key"], SYM);
  } finally {
    await proxy.close();
  }
});
