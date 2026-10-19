/**
 * identity.test — e2e for the `/_mandu/identity` endpoint (src/proxy.ts).
 *
 * Boots a real NetProxy (listen 0) and probes it exactly the way the launcher's
 * start-or-reuse safety check does (services/net-proxy.ts → probeIdentity):
 * an ORIGIN-FORM `GET /_mandu/identity` with the Host header pointing at the
 * proxy itself. Asserts:
 *   (1) with an identity configured → { mandu:true, service, arbiterSock, … }
 *       (and the probe is NOT swallowed by the self-loop guard, which sees the
 *       proxy's own address in the Host header);
 *   (2) with NO identity configured → { mandu:false } (a launcher refuses it);
 *   (3) a proxied ABSOLUTE-form URL ending in the path is normal egress — it is
 *       forwarded to the destination, NOT answered by the endpoint.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { NetProxy, IDENTITY_PATH, type HttpForwarder } from "../../src/proxy.js";
import { MockArbiter } from "../../src/arbiter-client.js";

/** Send an ORIGIN-FORM request (`GET /path` + Host header) to the proxy — what
 *  the launcher's probeIdentity sends. */
function originGet(port: number, path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, method: "GET", path, headers: { host: `127.0.0.1:${port}` } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    r.on("error", reject);
    r.end();
  });
}

/** A forwarder that records calls and returns a canned 200 (no real network). */
function makeStubForwarder(): { forwarder: HttpForwarder; calls: { url: string }[] } {
  const calls: { url: string }[] = [];
  const forwarder: HttpForwarder = async ({ url }) => {
    calls.push({ url });
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("stub") };
  };
  return { forwarder, calls };
}

test("origin-form GET /_mandu/identity returns the configured identity (not a self-loop 508)", async () => {
  const proxy = new NetProxy({
    arbiter: new MockArbiter(),
    log: () => {},
    identity: { service: "net-proxy", sessionKey: "sid-e2e", arbiterSock: "/run/x/arbiter.sock" },
  });
  const port = await proxy.listen(0);
  try {
    const r = await originGet(port, IDENTITY_PATH);
    assert.equal(r.status, 200);
    const id = JSON.parse(r.body) as Record<string, unknown>;
    assert.equal(id["mandu"], true);
    assert.equal(id["service"], "net-proxy");
    assert.equal(id["sessionKey"], "sid-e2e");
    assert.equal(id["arbiterSock"], "/run/x/arbiter.sock");
  } finally {
    await proxy.close();
  }
});

test("no identity configured → { mandu:false } (a launcher must refuse to adopt)", async () => {
  const proxy = new NetProxy({ arbiter: new MockArbiter(), log: () => {} });
  const port = await proxy.listen(0);
  try {
    const r = await originGet(port, IDENTITY_PATH);
    assert.equal(r.status, 200);
    assert.deepEqual(JSON.parse(r.body), { mandu: false });
  } finally {
    await proxy.close();
  }
});

test("an ABSOLUTE-form URL ending in the identity path is normal egress (forwarded, not intercepted)", async () => {
  const { forwarder, calls } = makeStubForwarder();
  const proxy = new NetProxy({
    arbiter: new MockArbiter(),
    log: () => {},
    forwarder,
    identity: { service: "net-proxy", arbiterSock: "/run/x/arbiter.sock" },
  });
  const port = await proxy.listen(0);
  try {
    // Absolute-form request line, as an HTTP_PROXY-aware client sends it.
    const r = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = httpRequest(
        {
          host: "127.0.0.1", port, method: "GET",
          path: `http://example.com${IDENTITY_PATH}`,
          headers: { host: "example.com" },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
          res.on("error", reject);
        },
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(r.status, 200);
    assert.equal(r.body, "stub", "served by the destination via the forwarder");
    assert.deepEqual(calls.map((c) => c.url), [`http://example.com${IDENTITY_PATH}`]);
  } finally {
    await proxy.close();
  }
});
