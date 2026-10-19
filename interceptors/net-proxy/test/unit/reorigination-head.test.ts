/**
 * reorigination-head — the request head the TLS-inspected leg sends upstream
 * (mitm.ts `reoriginationHead`), and the HTTP Basic substitution that feeds it
 * (egress.ts), as exact bytes.
 *
 * Found on the beta-tester tour (2026-10-05): `curl -u '<STRIPE_KEY
 * placeholder>:' -G -d limit=100 https://api.stripe.com/v1/customers`,
 * released once by the human, reached Stripe as
 *
 *   GET /v1/customers?limit=100 HTTP/1.1
 *   Host: api.stripe.com
 *   Authorization: Basic c2tfbGl2ZV9mYWtlXzEyMzQ1Njo=
 *   User-Agent: curl/8.18.0
 *   Accept: * / *
 *   accept-encoding: identity
 *   host: api.stripe.com            <- a SECOND Host
 *   connection: keep-alive
 *   content-length: 0
 *
 * and nginx answers two Host headers with a plain 400. The Basic credential
 * itself was right. Asserted here: the head is the client's, byte for byte,
 * apart from the headers the proxy owns (one Host naming the CONNECT target,
 * the real Content-Length, identity encoding, no hop-by-hop headers); a value
 * that would split the head throws (the caller sends nothing). Pure: no
 * socket, no arbiter beyond the in-memory mock.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { reoriginationHead, connectAuthority } from "../../src/mitm.js";
import { gateRequest } from "../../src/egress.js";
import { MockArbiter } from "../../src/arbiter-client.js";

const SYM = "$MDU:nomodel_Read[5c6e].STRIPE_KEY";
const KEY = "sk_live_fake_123456";
const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");
const head = (...lines: string[]): string => `${lines.join("\r\n")}\r\n\r\n`;

/** curl 8's request for `-u '<user>:' -G -d limit=100 https://api.stripe.com/v1/customers`, as the parser keeps it. */
const curlHeaders = (user: string): Record<string, string> => ({
  Host: "api.stripe.com",
  Authorization: `Basic ${b64(`${user}:`)}`,
  "User-Agent": "curl/8.18.0",
  Accept: "*/*",
});

test("the tour's curl, released: ONE Host, the Basic pair re-encoded exactly, nothing else but identity encoding", async () => {
  const arbiter = new MockArbiter({
    values: { [SYM]: KEY },
    decisionFn: () => ({ allow: true, requiresApproval: false, reason: "bound" }),
  });
  const headers = curlHeaders(SYM);
  const gate = await gateRequest({
    method: "GET", destinationHost: "api.stripe.com", url: "https://api.stripe.com/v1/customers?limit=100",
    headers, bodyText: "", arbiter, scheme: "https",
  });
  assert.equal(gate.action, "forward");
  assert.deepEqual(gate.resolved, [SYM]);
  // The pair "<symbol>:" decoded, the value put in, re-encoded: base64("sk_live_fake_123456:").
  assert.equal(gate.rewritten!.headers["Authorization"], `Basic ${b64(`${KEY}:`)}`);
  assert.equal(gate.rewritten!.headers["Authorization"], "Basic c2tfbGl2ZV9mYWtlXzEyMzQ1Njo=");

  const sent = reoriginationHead("GET", "/v1/customers?limit=100", gate.rewritten!.headers, connectAuthority("api.stripe.com", 443), 0);
  // What plain curl sends with the real key, plus the one identity line.
  const plain = head("GET /v1/customers?limit=100 HTTP/1.1", ...Object.entries(curlHeaders(KEY)).map(([k, v]) => `${k}: ${v}`));
  assert.equal(sent, plain.replace(/\r\n\r\n$/, "\r\nAccept-Encoding: identity\r\n\r\n"));
  assert.equal((sent.match(/^host:/gim) ?? []).length, 1, "exactly one Host");
  assert.ok(!/content-length/i.test(sent), "no Content-Length on a body-less GET");
  assert.ok(!/connection/i.test(sent), "no Connection header");
});

test("Host: one, at the client's position and case, naming the CONNECT target; inserted when absent; with a non-443 port", () => {
  assert.equal(
    reoriginationHead("GET", "/", { "user-agent": "x", host: "api.stripe.com" }, "api.stripe.com", 0),
    head("GET / HTTP/1.1", "user-agent: x", "host: api.stripe.com", "Accept-Encoding: identity"),
  );
  // A second Host (any case) is dropped; a Host naming another host is rewritten to the judged target.
  assert.equal(
    reoriginationHead("GET", "/", { Host: "elsewhere.example", host: ["a", "b"] }, "api.stripe.com", 0),
    head("GET / HTTP/1.1", "Host: api.stripe.com", "Accept-Encoding: identity"),
  );
  assert.equal(
    reoriginationHead("GET", "/", { Accept: "*/*" }, connectAuthority("bound.example", 8443), 0),
    head("GET / HTTP/1.1", "Host: bound.example:8443", "Accept: */*", "Accept-Encoding: identity"),
  );
  assert.equal(connectAuthority("::1", 443), "[::1]");
  assert.equal(connectAuthority("::1", 8443), "[::1]:8443");
});

test("Content-Length: the real length at the client's position; appended for a chunked body; none for an empty body without one", () => {
  assert.equal(
    reoriginationHead("POST", "/v1/charges", { Host: "h", "Content-Length": "8", "Content-Type": "application/x-www-form-urlencoded" }, "h", 30),
    head("POST /v1/charges HTTP/1.1", "Host: h", "Content-Length: 30", "Content-Type: application/x-www-form-urlencoded", "Accept-Encoding: identity"),
  );
  // Chunked: the parser drops Transfer-Encoding; the body goes with a Content-Length.
  assert.equal(
    reoriginationHead("POST", "/", { Host: "h", "Transfer-Encoding": "chunked" }, "h", 5),
    head("POST / HTTP/1.1", "Host: h", "Content-Length: 5", "Accept-Encoding: identity"),
  );
  assert.equal(
    reoriginationHead("DELETE", "/x", { Host: "h" }, "h", 0),
    head("DELETE /x HTTP/1.1", "Host: h", "Accept-Encoding: identity"),
  );
});

test("Accept-Encoding becomes identity in place; hop-by-hop headers are dropped; repeated headers keep their order", () => {
  assert.equal(
    reoriginationHead("GET", "/", {
      Host: "h", "Accept-Encoding": "gzip, br", Connection: "close", "Keep-Alive": "timeout=5",
      "Proxy-Authorization": "Basic eDp5", "Proxy-Connection": "keep-alive", Cookie: ["a=1", "b=2"],
    }, "h", 0),
    head("GET / HTTP/1.1", "Host: h", "Accept-Encoding: identity", "Cookie: a=1", "Cookie: b=2"),
  );
});

test("a header value holding a line break (a resolved value can) throws: nothing is sent (fail-closed)", () => {
  for (const bad of [`Bearer ${KEY}\r\nX-Smuggled: 1`, `${KEY}\n`, `a\0b`]) {
    assert.throws(() => reoriginationHead("GET", "/", { Host: "h", Authorization: bad }, "h", 0), /line break/);
  }
});
