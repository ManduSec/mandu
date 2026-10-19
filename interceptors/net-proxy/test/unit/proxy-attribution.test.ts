/**
 * proxy-attribution.test — proves proxy.ts threads a resolved procKey into BOTH
 * gateRequest and observeResponse (renamed from symbolizeResponse, Plan 7), lighting
 * up the taint backstop on the live (unprivileged) net-proxy path. Uses an INJECTED
 * attributeConnection stub (no real /proc), so it is deterministic. Post-Plan-7:
 * the response is returned RAW (no symbolize); the observe-and-tag (taintProcess)
 * half is kept and this file proves it fires via the live proxy path.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { NetProxy, type HttpForwarder } from "../../src/proxy.js";
import { MockArbiter } from "../../src/arbiter-client.js";

const noop = (): void => {};

/** Drive one plaintext GET through the proxy at `port` for `targetUrl`. */
function getThroughProxy(port: number, targetUrl: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const r = httpRequest(
      { host: "127.0.0.1", port, method: "GET", path: targetUrl, headers: { host: u.host } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    r.on("error", reject);
    r.end();
  });
}

/** A forwarder that returns a canned UNTRUSTED text body (so the ingress path fires). */
const cannedForwarder: HttpForwarder = async () => ({
  status: 200,
  headers: { "content-type": "text/plain" },
  body: Buffer.from("untrusted upstream content"),
});

test("attributable connection → procKey threaded into observeResponse (observe-and-tag fires, RAW body returned)", async () => {
  // FLIP (Plan 7): the response is returned RAW (no symbolize); the observe-and-tag
  // (taintProcess) half is KEPT and fires when the procKey is attributable.
  const arbiter = new MockArbiter(); // default classify = UNTRUSTED → observe + tag (no symbolize)
  const proxy = new NetProxy({
    arbiter,
    forwarder: cannedForwarder,
    log: noop,
    attributeConnection: () => "4242-555", // stubbed: a known, attributable key
  });
  const port = await proxy.listen(0);
  try {
    const res = await getThroughProxy(port, "http://example.test/data");
    assert.equal(res.status, 200);
    // RAW body returned (was symbolized pre-Plan-7); observe-and-tag still fires.
    assert.equal(res.body, "untrusted upstream content", "net returns raw post-flip");
    assert.equal(arbiter.symbolizeCalls.length, 0, "net ingress must NOT symbolize post-flip");
    assert.equal(arbiter.taintProcessCalls.length, 1, "observe-and-tag must fire with a real procKey");
    assert.equal(arbiter.taintProcessCalls[0]!.procKey, "4242-555");
    assert.equal(arbiter.taintProcessCalls[0]!.originHost, "example.test");
  } finally {
    await proxy.close();
  }
});

test("attributable + already-tainted proc → taint-driven destination gate blocks (no symbols needed)", async () => {
  const arbiter = new MockArbiter(); // default classify = UNTRUSTED → destination is untrusted
  arbiter.taintProc("4242-555", "evil.example"); // pre-tainted source process
  const proxy = new NetProxy({
    arbiter,
    forwarder: cannedForwarder,
    log: noop,
    attributeConnection: () => "4242-555",
  });
  const port = await proxy.listen(0);
  try {
    const res = await getThroughProxy(port, "http://example.test/exfil");
    assert.equal(res.status, 403, "tainted source → untrusted dest → fail-closed block");
    assert.ok(arbiter.isProcessTaintedCalls.includes("4242-555"), "the gate queried the resolved procKey");
  } finally {
    await proxy.close();
  }
});

test("UN-attributable connection → undefined → RAW body returned, no taint ops", async () => {
  // FLIP (Plan 7): no attribution → RAW body (no symbolize), no taint ops.
  const arbiter = new MockArbiter(); // UNTRUSTED → returns raw + NO taint (no procKey)
  const proxy = new NetProxy({
    arbiter,
    forwarder: cannedForwarder,
    log: noop,
    attributeConnection: () => undefined, // forced miss
  });
  const port = await proxy.listen(0);
  try {
    const res = await getThroughProxy(port, "http://example.test/data");
    assert.equal(res.status, 200);
    assert.equal(res.body, "untrusted upstream content", "net returns raw (no symbolize, no procKey)");
    assert.equal(arbiter.symbolizeCalls.length, 0, "net ingress must NOT symbolize post-flip");
    assert.equal(arbiter.taintProcessCalls.length, 0, "no attribution → no taint tag");
    assert.equal(arbiter.isProcessTaintedCalls.length, 0, "no attribution → no taint query");
  } finally {
    await proxy.close();
  }
});
