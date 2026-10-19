/**
 * upstream-transport.test.ts — the default fetcher's transport choice
 * (proxy.ts `upstreamTransport`), and a real round trip over plain HTTP to a
 * loopback upstream: the shape the fresh-agents VM suite drives a real Codex
 * through with no key (docs/design/testing/os-test-matrix.md §10.14). Mirrors
 * anthropic-proxy/test/unit/upstream-transport.test.ts: both proxies apply one
 * rule.
 *
 * The rule under test: https → TLS; http → plain ONLY for a LITERAL loopback
 * address (127.0.0.0/8, ::1; not the name `localhost`); anything else is
 * refused (502 per request), never sent in the clear.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { OpenAiProxy, upstreamRequestPath, upstreamTransport } from "../../src/proxy.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { buildTextSse } from "../helpers/mock-upstream.js";

// Axes: none. The arbiter here is the in-test MockArbiter (no policy, no axis
// resolution); this suite pins transport only, not a protection decision.

test("upstreamTransport: https is TLS, literal-loopback http is plain, any other http is refused", () => {
  assert.equal(upstreamTransport(new URL("https://api.openai.com")), "https");
  assert.equal(upstreamTransport(new URL("https://127.0.0.1:8443")), "https");
  assert.equal(upstreamTransport(new URL("http://127.0.0.1:4100")), "http");
  assert.equal(upstreamTransport(new URL("http://127.9.8.7")), "http");
  assert.equal(upstreamTransport(new URL("http://[::1]:9")), "http");
  // A NAME is not a loopback address: a hosts file can point it anywhere.
  assert.equal(upstreamTransport(new URL("http://localhost:9")), "refuse");
  assert.equal(upstreamTransport(new URL("http://api.openai.com")), "refuse");
  assert.equal(upstreamTransport(new URL("http://10.0.0.1:80")), "refuse");
  assert.equal(upstreamTransport(new URL("http://0.0.0.0:80")), "refuse");
  assert.equal(upstreamTransport(new URL("http://[::ffff:10.0.0.1]:80")), "refuse");
  assert.equal(upstreamTransport(new URL("http://127.0.0.1.evil.example")), "refuse");
  assert.equal(upstreamTransport(new URL("ftp://127.0.0.1")), "refuse");
  assert.equal(upstreamTransport(new URL("ws://127.0.0.1")), "refuse");
});

function post(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/responses", headers: { "content-type": "application/json" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

const BODY = JSON.stringify({
  model: "gpt-5.4",
  stream: true,
  input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "hi" }] }],
});

test("default fetcher: a loopback http upstream gets the request over plain HTTP", async () => {
  const seen: string[] = [];
  const upstream: Server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      seen.push(b);
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(buildTextSse("hello-from-loopback"));
    });
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  const proxy = new OpenAiProxy({ arbiter: new MockArbiter(), upstreamOrigin: origin, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const r = await post(port, BODY);
    assert.equal(r.status, 200);
    assert.match(r.body, /hello-from-loopback/);
    assert.equal(seen.length, 1, "the upstream received exactly the one forwarded request");
  } finally {
    await proxy.close();
    await new Promise<void>((r) => upstream.close(() => r()));
  }
});

test("default fetcher: a non-loopback http upstream is refused (502), nothing is sent", async () => {
  const proxy = new OpenAiProxy({ arbiter: new MockArbiter(), upstreamOrigin: "http://model.invalid:80", log: () => {} });
  const port = await proxy.listen(0);
  try {
    const r = await post(port, BODY);
    assert.equal(r.status, 502);
    assert.match(r.body, /allowed only to a loopback address/);
  } finally {
    await proxy.close();
  }
});

test("default fetcher: http to the NAME localhost is refused before any byte is sent", async () => {
  // A real listener the name would reach: it must see no connection at all.
  let connections = 0;
  const upstream: Server = createServer((_req, res) => { res.end("should-not-happen"); });
  upstream.on("connection", () => { connections++; });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
  const port0 = (upstream.address() as AddressInfo).port;
  const proxy = new OpenAiProxy({ arbiter: new MockArbiter(), upstreamOrigin: `http://localhost:${port0}`, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const r = await post(port, BODY);
    assert.equal(r.status, 502);
    assert.equal(connections, 0, "the refused origin never received a connection");
  } finally {
    await proxy.close();
    await new Promise<void>((r) => upstream.close(() => r()));
  }
});

test("upstreamRequestPath: an origin prefixes; a declared base URL replaces the proxy's /v1 (plan 11 §7.2)", () => {
  const u = (x: string) => new URL(x);
  // Default: the origin has no path, the request path goes through as is.
  assert.equal(upstreamRequestPath("/v1/responses", u("https://api.openai.com"), false), "/v1/responses");
  assert.equal(upstreamRequestPath("/v1/responses", u("http://127.0.0.1:4100/"), false), "/v1/responses");
  // Base URL semantics: Codex's base_url would have been the entry's url.
  assert.equal(upstreamRequestPath("/v1/responses", u("http://127.0.0.1:11434/v1"), true), "/v1/responses");
  assert.equal(upstreamRequestPath("/v1/responses", u("http://127.0.0.1:11434/v1/"), true), "/v1/responses");
  assert.equal(upstreamRequestPath("/v1/responses", u("https://gw.example/openai"), true), "/openai/responses");
  assert.equal(upstreamRequestPath("/v1/responses", u("http://127.0.0.1:8000"), true), "/responses");
  assert.equal(upstreamRequestPath("/v1/models?x=1", u("http://127.0.0.1:8000/api/v1"), true), "/api/v1/models?x=1");
  assert.equal(upstreamRequestPath("/v1", u("http://127.0.0.1:8000/api"), true), "/api");
  // Only a whole /v1 segment is the proxy's base.
  assert.equal(upstreamRequestPath("/v10/responses", u("http://127.0.0.1:8000/api"), true), "/api/v10/responses");
});
