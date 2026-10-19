/**
 * blocked-destinations e2e — a real NetProxy refuses cloud metadata and
 * link-local destinations over plain HTTP and CONNECT, in every spelling, and
 * never dials them (comparisons.md §3.6). The proxy dials from outside the
 * connect guard, so without this an agent could fetch an instance role's
 * credentials through HTTP_PROXY. The opt-out restores forwarding.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { connect as netConnect } from "node:net";

import { NetProxy, type HttpForwarder } from "../../src/proxy.js";
import { MockArbiter } from "../../src/arbiter-client.js";

const noop = (): void => {};

function stubForwarder(): { forwarder: HttpForwarder; calls: string[] } {
  const calls: string[] = [];
  const forwarder: HttpForwarder = async ({ url }) => {
    calls.push(url);
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("role-credentials") };
  };
  return { forwarder, calls };
}

function proxyGet(proxyPort: number, absoluteUrl: string, host: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port: proxyPort, method: "GET", path: absoluteUrl, headers: { host } }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      res.on("error", reject);
    });
    r.on("error", reject);
    r.end();
  });
}

function proxyConnect(proxyPort: number, target: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = netConnect(proxyPort, "127.0.0.1", () => {
      sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
    });
    let buf = "";
    sock.setEncoding("utf8");
    sock.on("data", (chunk: string) => {
      buf += chunk;
      if (buf.includes("\r\n\r\n")) {
        resolve(buf);
        sock.destroy();
      }
    });
    sock.on("error", reject);
    setTimeout(() => reject(new Error(`CONNECT ${target} timed out`)), 5000).unref();
  });
}

function blockedEvents(arbiter: MockArbiter): Array<{ action?: string; destination?: string; reason?: string }> {
  return (arbiter.emittedEvents as Array<{ action?: string; destination?: string; reason?: string }>).filter(
    (e) => e.action === "blocked",
  );
}

test("plain HTTP to the metadata endpoint → 403 in every spelling, nothing forwarded, no gate asked", async () => {
  const arbiter = new MockArbiter();
  const { forwarder, calls } = stubForwarder();
  const proxy = new NetProxy({ arbiter, log: noop, forwarder });
  const port = await proxy.listen(0);
  try {
    for (const [url, host] of [
      ["http://169.254.169.254/latest/meta-data/iam/security-credentials/", "169.254.169.254"],
      ["http://2852039166/latest/meta-data/", "2852039166"],
      ["http://0xa9fea9fe/latest/meta-data/", "0xa9fea9fe"],
      ["http://[::ffff:169.254.169.254]/latest/meta-data/", "[::ffff:169.254.169.254]"],
      ["http://[fd00:ec2::254]/latest/meta-data/", "[fd00:ec2::254]"],
      ["http://metadata.google.internal/computeMetadata/v1/", "metadata.google.internal"],
      ["http://100.100.100.200/latest/meta-data/", "100.100.100.200"],
      ["http://169.254.1.1:8080/", "169.254.1.1:8080"],
    ] as const) {
      const res = await proxyGet(port, url, host);
      assert.equal(res.status, 403, url);
      assert.match(res.body, /always denied/, url);
      assert.doesNotMatch(res.body, /role-credentials/);
    }
    assert.equal(calls.length, 0, "the forwarder was never called");
    assert.equal(arbiter.decisionCalls.length, 0, "refused before the egress gate");
    assert.ok(blockedEvents(arbiter).length >= 8, "every refusal is on the trace");
  } finally {
    await proxy.close();
  }
});

test("CONNECT to the metadata endpoint → 403, by literal and through the dial's own lookup", async () => {
  const arbiter = new MockArbiter();
  const proxy = new NetProxy({ arbiter, log: noop });
  const port = await proxy.listen(0);
  try {
    for (const target of ["169.254.169.254:443", "[fd00:ec2::254]:80", "metadata.google.internal:443"]) {
      const head = await proxyConnect(port, target);
      assert.match(head, /^HTTP\/1\.1 403/, target);
      assert.match(head, /always denied/, target);
    }
    // Not an IP literal as written, so it reaches net.connect's lookup; the
    // guarded lookup sees 169.254.169.254 and refuses before a socket opens.
    const viaLookup = await proxyConnect(port, "2852039166:80");
    assert.match(viaLookup, /^HTTP\/1\.1 403/, "a numeric name that resolves to the endpoint");
    assert.match(viaLookup, /cloud metadata endpoint/);
    assert.ok(blockedEvents(arbiter).some((e) => e.destination === "2852039166:80"));
  } finally {
    await proxy.close();
  }
});

test("a CONNECT to an ordinary host still tunnels", async () => {
  const { createServer } = await import("node:net");
  const echo = createServer((s) => s.pipe(s));
  await new Promise<void>((r) => echo.listen(0, "127.0.0.1", r));
  const echoPort = (echo.address() as { port: number }).port;
  const arbiter = new MockArbiter();
  // The echo listener is on loopback, which a launched proxy refuses
  // (this-machine.test.ts); the in-process opt-out stands in for an
  // ordinary host here, so only the always-denied check is exercised.
  const proxy = new NetProxy({ arbiter, log: noop, allowThisMachine: true });
  const port = await proxy.listen(0);
  try {
    const head = await proxyConnect(port, `localhost:${echoPort}`);
    assert.match(head, /^HTTP\/1\.1 200/, "a name that is not always-denied passes the guarded lookup");
  } finally {
    await proxy.close();
    echo.close();
  }
});

test("MANDU_NET_ALLOW_METADATA opt-out (allowMetadata) forwards the metadata request", async () => {
  const arbiter = new MockArbiter();
  const { forwarder, calls } = stubForwarder();
  const proxy = new NetProxy({ arbiter, log: noop, forwarder, allowMetadata: true });
  const port = await proxy.listen(0);
  try {
    const res = await proxyGet(port, "http://169.254.169.254/latest/meta-data/", "169.254.169.254");
    assert.equal(res.status, 200);
    assert.deepEqual(calls, ["http://169.254.169.254/latest/meta-data/"]);
  } finally {
    await proxy.close();
  }
});
