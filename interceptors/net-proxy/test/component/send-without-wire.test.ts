/**
 * send-without-wire.test — "Send without it" on the forward proxy's wire
 * (confidentiality.md §4 "Send without it", 2026-10-17; src/proxy.ts). Mandu-new.
 *
 * A real NetProxy, a MockArbiter whose decision carries `strip` (the human's
 * one-shot answer) and a recording destination:
 *   (1) the destination receives the marker where the symbol was, never the
 *       value nor the token, with a Content-Length that is the body's;
 *   (2) the value scan over the request is STRICT here: an arbiter without
 *       the scan, a scan that fails, and a scan that finds a secret value
 *       elsewhere in the request each block it (403, nothing sent), where
 *       for an ordinary request a failing scan is a no-op.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";

import { NetProxy, type HttpForwarder } from "../../src/proxy.js";
import { MockArbiter, type DesymbolizationDecision } from "../../src/arbiter-client.js";
import { SEND_WITHOUT_MARKER } from "../../src/egress.js";

const SYM = "$MDU:nomodel_Read[ab12cd34]";
const SECRET = "db-password-hunter2-wire";
const OTHER = "sk-live-OTHER-raw-secret-0000";
const STRIP: DesymbolizationDecision = { allow: false, requiresApproval: false, strip: true, reason: "the user chose Send without it" };

interface Rec { headers: Record<string, string | string[] | undefined>; body: string }

async function startDest() {
  const received: Rec[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      received.push({ headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(201, { "content-type": "application/json" });
      res.end("{\"ok\":true}");
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { server, received, host: `127.0.0.1:${(server.address() as AddressInfo).port}` };
}

function realForwarder(): HttpForwarder {
  return ({ method, url, headers, body }) =>
    new Promise((resolve, reject) => {
      const u = new URL(url);
      const r = httpRequest(
        { hostname: u.hostname, port: u.port || 80, method, path: u.pathname + u.search, headers: { ...headers, host: u.host } },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => resolve({ status: res.statusCode ?? 502, headers: res.headers, body: Buffer.concat(chunks) }));
          res.on("error", reject);
        },
      );
      r.on("error", reject);
      r.end(body);
    });
}

function post(proxyPort: number, url: string, host: string, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port: proxyPort, method: "POST", path: url, headers: { host, "content-type": "application/json", "content-length": Buffer.byteLength(body) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    r.on("error", reject);
    r.end(body);
  });
}

async function run(arbiter: MockArbiter, body: string): Promise<{ res: { status: number; body: string }; received: Rec[] }> {
  const dest = await startDest();
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, forwarder: realForwarder(), log: () => {} });
  const port = await proxy.listen(0);
  try {
    const res = await post(port, `http://${dest.host}/repos/o/r/issues`, dest.host, body);
    return { res, received: dest.received };
  } finally {
    proxy.close();
    dest.server.close();
  }
}

const ISSUE = JSON.stringify({ title: "deploy fails", body: `psql: FATAL password authentication failed (password=${SYM})` });

test("(1) the destination receives the marker, never the value nor the token; Content-Length is the body's", async () => {
  const arbiter = new MockArbiter({ values: { [SYM]: SECRET }, decisionFn: () => STRIP, fingerprintSecrets: [{ symbol: SYM, value: SECRET, level: "no-model", bindings: [] }] });
  const { res, received } = await run(arbiter, ISSUE);
  assert.equal(res.status, 201, res.body);
  assert.equal(received.length, 1);
  const got = received[0]!;
  assert.ok(!got.body.includes(SECRET) && !got.body.includes("$MDU:"), got.body);
  assert.equal((JSON.parse(got.body) as { body: string }).body, `psql: FATAL password authentication failed (password=${SEND_WITHOUT_MARKER})`);
  assert.equal(got.headers["content-length"], String(Buffer.byteLength(got.body)));
  assert.equal(arbiter.fingerprintCalls.length, 1, "the value scan ran over the request");
  assert.ok(arbiter.fingerprintCalls[0]!.surfaces.some((s) => s.text.includes(SEND_WITHOUT_MARKER)), "over the request with the marker in");
});

test("(2) strict scan: no scan, a failing scan, or a secret value elsewhere in the request → 403, nothing sent", async () => {
  const none = new MockArbiter({ values: { [SYM]: SECRET }, decisionFn: () => STRIP });
  (none as { egressFingerprintScan?: unknown }).egressFingerprintScan = undefined;
  const a = await run(none, ISSUE);
  assert.equal(a.res.status, 403);
  assert.equal(a.received.length, 0, "an arbiter that cannot check: not sent");

  const failing = new MockArbiter({ values: { [SYM]: SECRET }, decisionFn: () => STRIP, failFingerprint: true });
  const b = await run(failing, ISSUE);
  assert.equal(b.res.status, 403);
  assert.equal(b.received.length, 0, "a failed check: not sent");

  const hit = new MockArbiter({ values: { [SYM]: SECRET }, decisionFn: () => STRIP, fingerprintSecrets: [{ symbol: "$MDU:nomodel_Read[0ther1]", value: OTHER, level: "no-model", bindings: [] }] });
  const c = await run(hit, JSON.stringify({ body: `pw=${SYM} key=${OTHER}` }));
  assert.equal(c.res.status, 403);
  assert.equal(c.received.length, 0, "a raw secret value elsewhere: not sent");
  assert.ok(!c.res.body.includes(OTHER) && !c.res.body.includes(SECRET));

  // Control: an ordinary request with a failing scan still goes (the scan is a no-op there).
  const plain = new MockArbiter({ failFingerprint: true });
  const d = await run(plain, JSON.stringify({ body: "no secret here" }));
  assert.equal(d.res.status, 201);
});
