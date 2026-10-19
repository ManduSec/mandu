/**
 * deny-hosts e2e — a real NetProxy refuses the agent's upload hosts
 * (MANDU_NET_PROXY_DENY_HOSTS; supported-agents.md §5.3.4 rule 1) over plain
 * HTTP and CONNECT with 403, before any gate or dial, and a control host
 * still passes. The payload never appears in the refusal or the trace.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { connect as netConnect, createServer as createNetServer } from "node:net";

import { NetProxy, type HttpForwarder } from "../../src/proxy.js";
import { MockArbiter } from "../../src/arbiter-client.js";
import { parseDenyHosts } from "../../src/deny-hosts.js";

const noop = (): void => {};
const PAYLOAD = "TRANSCRIPT-WITH-ORIGINAL-TOOL-OUTPUT";

function stubForwarder(): { forwarder: HttpForwarder; calls: string[] } {
  const calls: string[] = [];
  const forwarder: HttpForwarder = async ({ url }) => {
    calls.push(url);
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
  };
  return { forwarder, calls };
}

function proxyPost(proxyPort: number, absoluteUrl: string, host: string, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port: proxyPort, method: "POST", path: absoluteUrl, headers: { host, "content-type": "application/json" } },
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

test("plain HTTP to an upload host → 403, nothing forwarded, no gate asked; a control host is forwarded", async () => {
  const arbiter = new MockArbiter();
  const { forwarder, calls } = stubForwarder();
  const proxy = new NetProxy({ arbiter, log: noop, forwarder, denyHosts: parseDenyHosts("us.i.posthog.com,.traces.example,collector.example:4318") });
  const port = await proxy.listen(0);
  try {
    for (const [url, host] of [
      ["http://us.i.posthog.com/capture/", "us.i.posthog.com"],
      ["http://US.I.POSTHOG.COM./capture/", "US.I.POSTHOG.COM."],
      ["http://eu.traces.example/v1/traces", "eu.traces.example"],
      ["http://collector.example:4318/v1/traces", "collector.example:4318"],
    ] as const) {
      const res = await proxyPost(port, url, host, JSON.stringify({ transcript: PAYLOAD }));
      assert.equal(res.status, 403, url);
      assert.match(res.body, /upload host Mandu denies/, url);
      assert.doesNotMatch(res.body, new RegExp(PAYLOAD), "the refusal never echoes the payload");
    }
    assert.equal(calls.length, 0, "the forwarder was never called for a denied host");
    assert.equal(arbiter.decisionCalls.length, 0, "refused before the egress gate");
    const blocked = (arbiter.emittedEvents as Array<{ action?: string; reason?: string }>).filter((e) => e.action === "blocked");
    assert.ok(blocked.length >= 4, "every refusal is on the trace");
    assert.ok(!JSON.stringify(arbiter.emittedEvents).includes(PAYLOAD), "the trace never carries the payload");

    // Control: another port of the port-scoped entry is forwarded (one
    // control only: its untrusted response taints this test process).
    const ok = await proxyPost(port, "http://collector.example:9999/v1/traces", "collector.example:9999", "{}");
    assert.equal(ok.status, 200, ok.body);
    assert.deepEqual(calls, ["http://collector.example:9999/v1/traces"]);
  } finally {
    await proxy.close();
  }
});

test("CONNECT to an upload host → 403 before any dial (a listener there sees nothing); a control CONNECT tunnels", async () => {
  // A listener standing in for the upload host, reached as `localhost`: a
  // denied CONNECT must never dial it.
  let accepted = 0;
  const upload = createNetServer((s) => { accepted++; s.end(); });
  await new Promise<void>((r) => upload.listen(0, "127.0.0.1", r));
  const uploadPort = (upload.address() as { port: number }).port;
  const echo = createNetServer((s) => s.pipe(s));
  await new Promise<void>((r) => echo.listen(0, "127.0.0.1", r));
  const echoPort = (echo.address() as { port: number }).port;

  const arbiter = new MockArbiter();
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, denyHosts: parseDenyHosts(`localhost:${uploadPort},relay.damus.io`) });
  const port = await proxy.listen(0);
  try {
    const head = await proxyConnect(port, `localhost:${uploadPort}`);
    assert.match(head, /^HTTP\/1\.1 403/);
    assert.match(head, /upload host Mandu denies/);
    const relay = await proxyConnect(port, "relay.damus.io:443");
    assert.match(relay, /^HTTP\/1\.1 403/, "a websocket relay over CONNECT is refused too");
    assert.equal(accepted, 0, "the upload host's listener was never dialed");
    const ok = await proxyConnect(port, `localhost:${echoPort}`);
    assert.match(ok, /^HTTP\/1\.1 200/, "the same host on another port tunnels");
  } finally {
    await proxy.close();
    upload.close();
    echo.close();
  }
});

test("the identity publishes the deny list (the launcher's reuse key); none → no field", async () => {
  const get = (p: number): Promise<Record<string, unknown>> => new Promise((resolve, reject) => {
    httpRequest({ host: "127.0.0.1", port: p, path: "/_mandu/identity" }, (res) => {
      let b = "";
      res.on("data", (c) => (b += c));
      res.on("end", () => resolve(JSON.parse(b) as Record<string, unknown>));
    }).on("error", reject).end();
  });
  const a = new NetProxy({ arbiter: new MockArbiter(), log: noop, identity: { service: "net-proxy", arbiterSock: "/s" }, denyHosts: parseDenyHosts("US.I.posthog.com,.traces.example") });
  const b = new NetProxy({ arbiter: new MockArbiter(), log: noop, identity: { service: "net-proxy", arbiterSock: "/s" } });
  const pa = await a.listen(0);
  const pb = await b.listen(0);
  try {
    assert.deepEqual((await get(pa))["denyHosts"], ["us.i.posthog.com", ".traces.example"]);
    assert.equal((await get(pb))["denyHosts"], undefined);
  } finally {
    await a.close();
    await b.close();
  }
});
