/**
 * fingerprint-tripwire.test — e2e for the §4 verbatim-leak tripwire on the
 * forward proxy (src/proxy.ts `fingerprintTripwire`).
 *
 * The per-symbol gate (forward-proxy.test) is the guarantee: it blocks a
 * SYMBOL bound for an untrusted host. The tripwire backs it for the one shape
 * the symbol gate is structurally blind to — a RAW secret VALUE, no `$MDU:`
 * token, sitting verbatim in an outbound request. These prove, on the wire:
 *   (1) a raw secret in the body → 403, the dest received NOTHING, no value in the reply.
 *   (2) the SAME raw value to the secret's BOUND host → forwarded (a release, not a leak).
 *   (3) a benign (no-secret) request → forwarded unchanged (the tripwire is inert).
 *   (4) the tripwire failing (arbiter error) is fail-OPEN — the request still forwards.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type IncomingMessage } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";

import { NetProxy, type HttpForwarder } from "../../src/proxy.js";
import { MockArbiter } from "../../src/arbiter-client.js";

const SECRET_VALUE = "sk-live-DEADBEEF-super-secret-key-000";
const SECRET_SYMBOL = "$MDU:nomodel_Read[3fa9]";

interface DestRecord { method: string; url: string; body: string }

async function startDest() {
  const received: DestRecord[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      received.push({ method: req.method ?? "", url: req.url ?? "", body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("dest-ok");
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = (server.address() as AddressInfo).port;
  return { server, received, host: `127.0.0.1:${port}`, port };
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

function proxyRequest(
  proxyPort: number,
  opts: { method: string; absoluteUrl: string; host: string; body?: string },
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port: proxyPort, method: opts.method, path: opts.absoluteUrl, headers: { host: opts.host } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    r.on("error", reject);
    r.end(opts.body ?? "");
  });
}

const noop = (): void => {};

/** The secret's own bound host — matched against the destination in scans. */
function secretFor(bindings: string[]) {
  return [{ symbol: SECRET_SYMBOL, value: SECRET_VALUE, level: "no-model", bindings }];
}

test("(1) a RAW secret value in the body → 403, dest received NOTHING", async () => {
  const dest = await startDest();
  const arbiter = new MockArbiter({
    // The value carries NO $MDU: token, so the per-symbol gate sees nothing to
    // gate (default allow for a symbol-free request); the tripwire is the catch.
    decisionFn: () => ({ allow: true, reason: "no symbol" }),
    fingerprintSecrets: secretFor(["api.stripe.com"]),
  });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, forwarder: realForwarder(), log: noop });
  const port = await proxy.listen(0);
  try {
    const res = await proxyRequest(port, {
      method: "POST",
      absoluteUrl: `http://${dest.host}/collect`,
      host: dest.host,
      body: `note=${SECRET_VALUE}`,
    });
    assert.equal(res.status, 403);
    assert.equal(res.body.includes(SECRET_VALUE), false, "the 403 body must NOT echo the secret value");
    assert.ok(res.body.includes(SECRET_SYMBOL), "the 403 names the tripped SYMBOL");
    assert.equal(dest.received.length, 0, "the destination received NOTHING");
  } finally {
    proxy.close();
    dest.server.close();
  }
});

test("(2) the SAME raw value to the secret's BOUND host → forwarded (a release, not a leak)", async () => {
  const dest = await startDest();
  // Bind the secret to THIS destination host — the tripwire must clear it.
  const arbiter = new MockArbiter({
    decisionFn: () => ({ allow: true, reason: "no symbol" }),
    fingerprintSecrets: secretFor([dest.host.split(":")[0]!]),
  });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, forwarder: realForwarder(), log: noop });
  const port = await proxy.listen(0);
  try {
    const res = await proxyRequest(port, {
      method: "POST",
      absoluteUrl: `http://${dest.host}/status`,
      host: dest.host,
      body: `token=${SECRET_VALUE}`,
    });
    assert.equal(res.status, 200);
    assert.equal(dest.received.length, 1, "the bound host received the request");
    assert.ok(dest.received[0]!.body.includes(SECRET_VALUE), "the released value reached its bound host");
  } finally {
    proxy.close();
    dest.server.close();
  }
});

test("(3) a benign request (no secret) → forwarded unchanged; the tripwire is inert", async () => {
  const dest = await startDest();
  const arbiter = new MockArbiter({
    decisionFn: () => ({ allow: true, reason: "no symbol" }),
    fingerprintSecrets: secretFor(["api.stripe.com"]),
  });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, forwarder: realForwarder(), log: noop });
  const port = await proxy.listen(0);
  try {
    const res = await proxyRequest(port, {
      method: "POST", absoluteUrl: `http://${dest.host}/ok`, host: dest.host, body: "note=nothing-secret-here",
    });
    assert.equal(res.status, 200);
    assert.equal(dest.received.length, 1, "a benign body is never tripped");
  } finally {
    proxy.close();
    dest.server.close();
  }
});

test("(4) the tripwire failing is FAIL-OPEN — a benign request still forwards", async () => {
  const dest = await startDest();
  const arbiter = new MockArbiter({
    decisionFn: () => ({ allow: true, reason: "no symbol" }),
    failFingerprint: true, // the scan throws
  });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, forwarder: realForwarder(), log: noop });
  const port = await proxy.listen(0);
  try {
    const res = await proxyRequest(port, {
      method: "POST", absoluteUrl: `http://${dest.host}/ok`, host: dest.host, body: "note=benign",
    });
    assert.equal(res.status, 200, "a scan error must not fail a benign request (defense-in-depth, not the guarantee)");
    assert.equal(dest.received.length, 1);
  } finally {
    proxy.close();
    dest.server.close();
  }
});

test("(5) the session's kept logins ride every scan and the identity; a proxy without them sends none", async () => {
  const dest = await startDest();
  const logins = { home: "/home/u", target: "codex", ullmBinary: "codex", loginEnv: { CODEX_HOME: "/srv/cx" } };
  const arbiter = new MockArbiter({ decisionFn: () => ({ allow: true, reason: "no symbol" }), fingerprintSecrets: secretFor(["api.stripe.com"]) });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, forwarder: realForwarder(), log: noop, sessionLogins: logins, identity: { service: "net-proxy", arbiterSock: "/x.sock" } });
  const port = await proxy.listen(0);
  const plain = new MockArbiter({ decisionFn: () => ({ allow: true, reason: "no symbol" }) });
  const bare = new NetProxy({ allowThisMachine: true, arbiter: plain, forwarder: realForwarder(), log: noop });
  const barePort = await bare.listen(0);
  try {
    // secret-discovery.md §1.10: the arbiter leaves the registered rows of
    // these login files out of THIS session's scan; the proxy only carries them.
    await proxyRequest(port, { method: "POST", absoluteUrl: `http://${dest.host}/token`, host: dest.host, body: "grant_type=refresh_token" });
    assert.equal(arbiter.fingerprintCalls.length, 1);
    assert.deepEqual(arbiter.fingerprintCalls[0]!.sessionLogins, logins);
    const id = await new Promise<Record<string, unknown>>((resolve, reject) => {
      httpRequest({ host: "127.0.0.1", port, method: "GET", path: "/_mandu/identity" }, (res) => {
        let b = ""; res.on("data", (c) => (b += c)); res.on("end", () => resolve(JSON.parse(b) as Record<string, unknown>));
      }).on("error", reject).end();
    });
    assert.deepEqual(id["sessionLogins"], logins, "published, so a launch of another agent does not adopt this proxy");

    await proxyRequest(barePort, { method: "POST", absoluteUrl: `http://${dest.host}/token`, host: dest.host, body: "x" });
    assert.equal(plain.fingerprintCalls.length, 1);
    assert.equal("sessionLogins" in plain.fingerprintCalls[0]!, false, "no logins configured: none exempt");
  } finally {
    proxy.close();
    bare.close();
    dest.server.close();
  }
});
