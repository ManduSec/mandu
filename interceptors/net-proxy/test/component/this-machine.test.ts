/**
 * this-machine e2e — a real NetProxy (the default dial policy, the real
 * forwarder and tunnel) refuses to relay to this machine: a loopback
 * "dashboard" that serves a secret value to anyone who asks receives NO
 * connection through the proxy, over plain HTTP, CONNECT and TLS
 * inspection, in every spelling (127.0.0.1, localhost, [::1],
 * [::ffff:127.0.0.1], 0.0.0.0, a numeric name that resolves to 127.0.0.1,
 * this machine's own interface address). Each refusal is a 403, a `blocked`
 * net_action, and a `this-machine` refusal note for the sending process.
 * A mock-sites host route (the demo's and the replay runner's loopback
 * listeners) keeps working. Found 2026-10-05: `curl --noproxy '' -x
 * "$HTTP_PROXY" http://127.0.0.1:4500/api/events` read the dashboard's
 * secret values from inside the agent's sandbox, which the connect guard
 * refuses for the direct connect.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpServer, request as httpRequest, type Server } from "node:http";
import { connect as netConnect, type AddressInfo } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { networkInterfaces } from "node:os";
import { once } from "node:events";

import { NetProxy } from "../../src/proxy.js";
import { MockArbiter } from "../../src/arbiter-client.js";
import { MockSites } from "../../src/mock-sites.js";
import { ensureCa, opensslAvailable } from "../../src/ca.js";
import { tmpDir } from "../tmp-dir.js";

const noop = (): void => {};
const SECRET = "THISMACHINE_CANARY_wJalrXUtnFEMIk7MDENG";
const HOLDER = { procKey: "4500-1", ancestors: ["4499-1"] };

/** A loopback service that hands its secret to whoever connects (the
 *  dashboard before its sign-in wall), counting every TCP connection. */
async function startDashboard(host = "0.0.0.0"): Promise<{ server: Server; port: number; connections: () => number }> {
  let n = 0;
  const server = createHttpServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ events: [{ output: { original: SECRET } }] }));
  });
  server.on("connection", () => { n++; });
  server.listen(0, host);
  await once(server, "listening");
  return { server, port: (server.address() as AddressInfo).port, connections: () => n };
}

function proxyGet(proxyPort: number, absoluteUrl: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port: proxyPort, method: "GET", path: absoluteUrl, headers: { host: new URL(absoluteUrl).host } },
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

/** CONNECT, then (if it opened) send a plain GET down the tunnel. Resolves
 *  with everything the client read. */
function proxyConnect(proxyPort: number, target: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = netConnect(proxyPort, "127.0.0.1", () => {
      sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
    });
    let buf = "";
    let sent = false;
    sock.setEncoding("utf8");
    sock.on("data", (chunk: string) => {
      buf += chunk;
      if (!sent && /^HTTP\/1\.1 200/.test(buf) && buf.includes("\r\n\r\n")) {
        sent = true;
        sock.write("GET /api/events?session=s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
      }
    });
    sock.on("close", () => resolve(buf));
    sock.on("error", (e) => (buf ? resolve(buf) : reject(e)));
    setTimeout(() => { sock.destroy(); resolve(buf); }, 5000).unref();
  });
}

function blockedFor(arbiter: MockArbiter, destination: string): boolean {
  return (arbiter.emittedEvents as Array<{ action?: string; destination?: string }>).some(
    (e) => e.action === "blocked" && e.destination === destination,
  );
}

/** This machine's first non-loopback IPv4 address, if it has one. */
function lanAddress(): string | undefined {
  return Object.values(networkInterfaces()).flatMap((l) => l ?? []).find((a) => !a.internal && a.family === "IPv4")?.address;
}

test("plain HTTP through the proxy to a loopback service → 403 in every spelling, the service sees no connection, no secret byte", async () => {
  const dash = await startDashboard();
  const arbiter = new MockArbiter();
  const proxy = new NetProxy({ arbiter, log: noop, sessionId: "s-tm", attributeHolders: () => [HOLDER] });
  const port = await proxy.listen(0);
  try {
    const p = dash.port;
    const urls = [
      `http://127.0.0.1:${p}/api/events?session=s`,
      `http://localhost:${p}/api/events?session=s`,
      `http://LOCALHOST.:${p}/api/events?session=s`,
      `http://dash.localhost:${p}/api/events?session=s`,
      `http://[::1]:${p}/api/events?session=s`,
      `http://[::ffff:127.0.0.1]:${p}/api/events?session=s`,
      `http://0.0.0.0:${p}/api/events?session=s`,
      `http://127.1:${p}/api/events?session=s`, // WHATWG: 127.0.0.1
      `http://2130706433:${p}/api/events?session=s`, // WHATWG: 127.0.0.1
      `http://127.0.0.2:${p}/api/events?session=s`,
    ];
    const lan = lanAddress();
    if (lan) urls.push(`http://${lan}:${p}/api/events?session=s`);
    for (const url of urls) {
      const res = await proxyGet(port, url);
      assert.equal(res.status, 403, url);
      assert.match(res.body, /is this machine/, url);
      assert.ok(!res.body.includes(SECRET), `no secret byte: ${url}`);
    }
    assert.equal(dash.connections(), 0, "the loopback service received no connection through the proxy");
    await new Promise((r) => setTimeout(r, 20));
    assert.ok(blockedFor(arbiter, `127.0.0.1:${p}`), "a blocked net_action");
    assert.equal(arbiter.egressRefusals.length, urls.length, "each refusal is noted");
    for (const n of arbiter.egressRefusals) assert.deepEqual(n, { procKeys: [HOLDER.procKey], kind: "this-machine", sessionKey: "s-tm" });
  } finally {
    await proxy.close();
    dash.server.close();
  }
});

test("CONNECT through the proxy to a loopback service → 403 in every spelling, a name that RESOLVES there included; no tunnel opens", async () => {
  const dash = await startDashboard();
  const arbiter = new MockArbiter();
  const proxy = new NetProxy({ arbiter, log: noop, sessionId: "s-tm", attributeHolders: () => [HOLDER] });
  const port = await proxy.listen(0);
  try {
    const p = dash.port;
    const targets = [
      `127.0.0.1:${p}`,
      `localhost:${p}`,
      `[::1]:${p}`,
      `::1:${p}`,
      `[::ffff:127.0.0.1]:${p}`,
      `0.0.0.0:${p}`,
      // Not an IP literal as written: reaches the dial's lookup, which
      // resolves it to 127.0.0.1 and refuses before a socket opens.
      `2130706433:${p}`,
      `0x7f000001:${p}`,
    ];
    const lan = lanAddress();
    if (lan) targets.push(`${lan}:${p}`);
    for (const t of targets) {
      const got = await proxyConnect(port, t);
      assert.match(got, /^HTTP\/1\.1 403/, t);
      assert.match(got, /is this machine/, t);
      assert.ok(!got.includes(SECRET), `no secret byte: ${t}`);
    }
    assert.equal(dash.connections(), 0, "no tunnel reached the loopback service");
    await new Promise((r) => setTimeout(r, 20));
    assert.ok(blockedFor(arbiter, `2130706433:${p}`), "the dial-time refusal is a blocked net_action too");
    assert.equal(arbiter.egressRefusals.length, targets.length, "each refusal is noted, at the CONNECT or at the dial");
    assert.ok(arbiter.egressRefusals.every((n) => n.kind === "this-machine"));
  } finally {
    await proxy.close();
    dash.server.close();
  }
});

test("TLS inspection on: a loopback CONNECT is refused before termination; a name resolving there is refused at the re-origination", { skip: !opensslAvailable() && "openssl unavailable" }, async () => {
  const dash = await startDashboard();
  const caDir = tmpDir("mandu-this-machine-ca-");
  const arbiter = new MockArbiter({ classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "trusted" }) });
  const proxy = new NetProxy({ arbiter, log: noop, sessionId: "s-tm", attributeHolders: () => [HOLDER], mitm: { caDir } });
  const port = await proxy.listen(0);
  try {
    const literal = await proxyConnect(port, `127.0.0.1:${dash.port}`);
    assert.match(literal, /^HTTP\/1\.1 403/);
    // A name: the CONNECT is accepted and terminated; the decrypted request
    // passes the gate; the re-origination's dial refuses it.
    const host = "2130706433";
    const caPem = ensureCa(caDir).certPem;
    const status = await new Promise<string>((resolve, reject) => {
      const raw = netConnect(port, "127.0.0.1", () => raw.write(`CONNECT ${host}:${dash.port} HTTP/1.1\r\nHost: ${host}\r\n\r\n`));
      let head = "";
      raw.on("data", function onData(chunk: Buffer) {
        head += chunk.toString("latin1");
        const idx = head.indexOf("\r\n\r\n");
        if (idx === -1) return;
        raw.off("data", onData);
        if (!/^HTTP\/1\.1 200/.test(head)) return resolve(head.split("\r\n")[0]!);
        // The client's own name check is not under test (the proxy's CA is
        // pinned): a newer Node (22.2x) refuses a numeric host like this one
        // before any byte is sent, "Host is a non-canonical IP address".
        const tls = tlsConnect({ socket: raw, servername: host, ca: caPem, checkServerIdentity: () => undefined }, () => {
          tls.write(`GET /api/events HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
        });
        let out = "";
        tls.on("data", (c: Buffer) => { out += c.toString("utf8"); });
        tls.on("end", () => resolve(out));
        tls.on("error", reject);
      });
      raw.on("error", reject);
      setTimeout(() => reject(new Error("timed out")), 8000).unref();
    });
    assert.match(status, /^HTTP\/1\.1 403/, status.slice(0, 200));
    assert.match(status, /is this machine/);
    assert.ok(!status.includes(SECRET));
    assert.equal(dash.connections(), 0, "the re-origination never dialed the loopback service");
    assert.ok(arbiter.egressRefusals.every((n) => n.kind === "this-machine"));
    assert.equal(arbiter.egressRefusals.length, 2);
  } finally {
    await proxy.close();
    dash.server.close();
  }
});

test("a mock-sites host route still dials its own loopback listener (demo / replay); an unrouted loopback target stays refused", async () => {
  const listener = await startDashboard("127.0.0.1");
  const arbiter = new MockArbiter({ classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "trusted" }) });
  const mockSites = MockSites.fromYaml(
    `sites:\n  - url: "http://localhost:9/canned"\n    body: "canned-body"\n` +
      `hosts:\n  - host: "api.stripe.com"\n    to: "127.0.0.1:${listener.port}"\n    tls_to: "127.0.0.1:${listener.port}"\n`,
  );
  const proxy = new NetProxy({ arbiter, log: noop, mockSites });
  const port = await proxy.listen(0);
  try {
    const routed = await proxyGet(port, "http://api.stripe.com/v1/customers");
    assert.equal(routed.status, 200, "the route's own loopback dial is exempt");
    const tunneled = await proxyConnect(port, "api.stripe.com:443");
    assert.match(tunneled, /^HTTP\/1\.1 200/, "a routed CONNECT tunnels to its listener");
    assert.equal(listener.connections(), 2, "both reached the route's listener");
    // A canned site is served without any dial, whatever its host.
    const canned = await proxyGet(port, "http://localhost:9/canned");
    assert.equal(canned.status, 200);
    assert.equal(canned.body, "canned-body");
    // The listener itself, named directly, is not routed: refused.
    const direct = await proxyGet(port, `http://127.0.0.1:${listener.port}/`);
    assert.equal(direct.status, 403);
    const directTunnel = await proxyConnect(port, `127.0.0.1:${listener.port}`);
    assert.match(directTunnel, /^HTTP\/1\.1 403/);
    assert.equal(listener.connections(), 2, "nothing more reached it");
  } finally {
    await proxy.close();
    listener.server.close();
  }
});
