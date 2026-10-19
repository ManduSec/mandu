/**
 * upstream-tls e2e (confidentiality plan 12 D3): a declared main model with
 * `tls:` behind this proxy. The proxy's REAL default upstream fetcher dials an
 * https stand-in model with a private CA; the conversation reaches it only
 * when the entry's checks pass, and a refusal sends NOTHING (the upstream's
 * application sees zero requests; the agent gets a 502).
 *   - the CA unknown to the default store: refused;  `ca_file`: served;
 *   - a pin of an unrelated key: refused;  the server's pin: served;
 *   - a server requiring a client certificate: without it refused, with it
 *     served;
 *   - plan 12 D4, a `perimeter` in the setting: an address outside it (a
 *     literal, or a name's answer) is refused with zero requests, inside
 *     is served;
 *   - MANDU_UPSTREAM_TLS that cannot be used stops the proxy from starting
 *     (upstreamTlsFromEnv throws), never a dial without the checks.
 * Certificates are minted per run with openssl (self-SKIP without it).
 *
 * Axes: none. The arbiter is the in-test MockArbiter; this pins transport.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:https";
import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";

import { AnthropicProxy } from "../../src/proxy.js";
import { upstreamTlsFromEnv } from "../../src/upstream-tls.js";
import type { TlsMaterial } from "../../src/endpoint-tls.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { buildTextSse } from "../helpers/mock-upstream.js";
import { mintTlsFixtures } from "../helpers/tls-fixtures.js";

const fx = mintTlsFixtures();
const skip = fx === null ? "openssl is not on PATH" : false;
process.on("exit", () => fx?.cleanup());

const BODY = JSON.stringify({ model: "claude-opus-4", stream: true, messages: [{ role: "user", content: "hi" }] });

function post(port: number): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(BODY);
  });
}

async function httpsUpstream(mtls = false): Promise<{ origin: string; seen: string[]; close: () => Promise<void> }> {
  const seen: string[] = [];
  const server: Server = createServer({
    cert: fx!.serverCertPem, key: fx!.serverKeyPem,
    ...(mtls ? { requestCert: true, rejectUnauthorized: true, ca: [fx!.clientCaCertPem] } : {}),
  }, (req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      seen.push(b);
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(buildTextSse("hello-over-tls", { deltas: 1 }));
    });
  });
  server.on("tlsClientError", () => { /* refused handshakes are the point */ });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, seen, close: () => new Promise<void>((r) => server.close(() => r())) };
}

async function through(origin: string, upstreamTls: TlsMaterial | undefined): Promise<{ status: number; body: string }> {
  const proxy = new AnthropicProxy({ arbiter: new MockArbiter(), upstreamOrigin: origin, log: () => {}, retry: { maxAttempts: 1 }, ...(upstreamTls ? { upstreamTls } : {}) });
  const port = await proxy.listen(0);
  try { return await post(port); } finally { await proxy.close(); }
}

test("the CA and the pins decide whether the conversation reaches the declared main model", { skip }, async () => {
  const up = await httpsUpstream();
  try {
    const unknownCa = await through(up.origin, undefined);
    assert.equal(unknownCa.status, 502, "the default store does not know the private CA");
    const wrongPin = await through(up.origin, { ca: fx!.caCertPem, pins: [fx!.otherPin] });
    assert.equal(wrongPin.status, 502);
    assert.equal(up.seen.length, 0, "nothing reached the upstream on a refusal");
    const ok = await through(up.origin, { ca: fx!.caCertPem, pins: [fx!.serverPin] });
    assert.equal(ok.status, 200, ok.body);
    assert.match(ok.body, /hello-over-tls/);
    assert.equal(up.seen.length, 1);
  } finally { await up.close(); }
});

test("mutual TLS: the client certificate is presented only when the entry names it", { skip }, async () => {
  const up = await httpsUpstream(true);
  try {
    const none = await through(up.origin, { ca: fx!.caCertPem });
    assert.equal(none.status, 502);
    assert.equal(up.seen.length, 0);
    const ok = await through(up.origin, { ca: fx!.caCertPem, cert: fx!.clientCertPem, key: fx!.clientKeyPem });
    assert.equal(ok.status, 200, ok.body);
    assert.equal(up.seen.length, 1);
  } finally { await up.close(); }
});

test("MANDU_UPSTREAM_TLS: read from files; malformed or unusable throws (the proxy does not start); unset is no option", { skip }, () => {
  assert.deepEqual(upstreamTlsFromEnv(undefined), {});
  assert.deepEqual(upstreamTlsFromEnv(""), {});
  const m = upstreamTlsFromEnv(JSON.stringify({ caFile: fx!.caCert, pinSha256: [fx!.serverPin], clientCert: fx!.clientCert, clientKey: fx!.clientKey }));
  assert.equal(m.upstreamTls?.ca, fx!.caCertPem);
  assert.equal(m.upstreamTls?.key, fx!.clientKeyPem);
  assert.deepEqual(m.upstreamTls?.pins, [fx!.serverPin]);
  assert.throws(() => upstreamTlsFromEnv("{not json"), /not JSON; refusing/);
  assert.throws(() => upstreamTlsFromEnv(JSON.stringify({ caFile: "relative.pem" })), /not a tls setting this proxy can read/);
  assert.throws(() => upstreamTlsFromEnv(JSON.stringify({ caFile: "/nope/ca.pem" })), /tls\.ca_file: cannot read \/nope\/ca\.pem/);
});

test("perimeter (plan 12 D4): outside by literal or by the name's answer → 502 and zero requests; inside → served; carried by MANDU_UPSTREAM_TLS", { skip }, async () => {
  const up = await httpsUpstream();
  try {
    const port = new URL(up.origin).port;
    const outLit = await through(up.origin, { ca: fx!.caCertPem, perimeter: ["10.0.0.0/8"] });
    assert.equal(outLit.status, 502);
    const outName = await through(`https://localhost:${port}`, { ca: fx!.caCertPem, perimeter: ["10.0.0.0/8"] });
    assert.equal(outName.status, 502);
    assert.equal(up.seen.length, 0, "nothing reached the upstream");
    const inName = await through(`https://localhost:${port}`, { ca: fx!.caCertPem, perimeter: ["127.0.0.0/8", "::1/128"] });
    assert.equal(inName.status, 200, inName.body);
    assert.equal(up.seen.length, 1);
    const env = upstreamTlsFromEnv(JSON.stringify({ caFile: fx!.caCert, perimeter: ["10.0.0.0/8"] }));
    assert.deepEqual(env.upstreamTls?.perimeter, ["10.0.0.0/8"]);
    assert.deepEqual(upstreamTlsFromEnv(JSON.stringify({ perimeter: ["10.0.0.0/8"] })).upstreamTls, { perimeter: ["10.0.0.0/8"] }, "a perimeter alone is a setting");
    assert.throws(() => upstreamTlsFromEnv(JSON.stringify({ perimeter: ["10.0.0.0/99"] })), /not a tls setting this proxy can read/);
  } finally { await up.close(); }
});
