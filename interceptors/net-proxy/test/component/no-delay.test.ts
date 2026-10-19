/**
 * no-delay.test — every TCP socket the net-proxy writes HTTP on has Nagle
 * off (plan 13 D6, "The kept-alive floor").
 *
 * The TLS-inspected leg re-originates each decrypted request on a pooled
 * upstream TLS connection. With Nagle on, a request on a kept-alive
 * connection paid ~43 ms: its last small segment waited for the ACK of the
 * one before, which the server delays while it waits for the rest of the
 * request. A latency assertion would be flaky under load, so this pins the
 * cause instead: a real NetProxy (TLS inspection on, and a blind tunnel), a
 * real HTTPS destination and a real TCP one, and `setNoDelay` watched on
 * every socket. Asserted: the accepted client connection, the inspected
 * leg's upstream connection (reused for a second request on the same
 * client connection) and the blind tunnel's upstream connection all had
 * `setNoDelay(true)`, and the requests still arrive whole.
 *
 * Mandu-new (no reference origin). No axis is involved (transport only):
 * the MockArbiter answers every taint question untainted.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { Socket, connect as netConnect, createServer as createNetServer, type AddressInfo } from "node:net";
import { once } from "node:events";

import { NetProxy } from "../../src/proxy.js";
import { MockArbiter } from "../../src/arbiter-client.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";
import type { ProcHolder } from "../../src/conn-attr.js";
import { tmpDir } from "../tmp-dir.js";

const skip = !opensslAvailable() && "openssl unavailable";
const noop = (): void => {};
const holder = (): ProcHolder[] => [{ procKey: "9001-1", ancestors: [] }];

/** Every socket `setNoDelay(true)` was called on, while `fn` runs. */
async function watchingNoDelay<T>(fn: (nodelay: Set<Socket>) => Promise<T>): Promise<T> {
  const seen = new Set<Socket>();
  const orig = Socket.prototype.setNoDelay;
  Socket.prototype.setNoDelay = function (this: Socket, on?: boolean) {
    if (on !== false) seen.add(this);
    return orig.call(this, on);
  };
  try {
    return await fn(seen);
  } finally {
    Socket.prototype.setNoDelay = orig;
  }
}

function connectVia(proxyPort: number, port: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const sock = netConnect(proxyPort, "127.0.0.1", () => sock.write(`CONNECT 127.0.0.1:${port} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n\r\n`));
    let head = "";
    const onData = (c: Buffer): void => {
      head += c.toString("latin1");
      if (!head.includes("\r\n\r\n")) return;
      sock.off("data", onData);
      if (/ 200 /.test(head)) resolve(sock);
      else reject(new Error(head));
    };
    sock.on("data", onData);
    sock.on("error", reject);
  });
}

function post(tls: TLSSocket, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    let buf = "";
    const onData = (c: Buffer): void => {
      buf += c.toString("latin1");
      const i = buf.indexOf("\r\n\r\n");
      if (i < 0) return;
      const cl = Number(/content-length:\s*(\d+)/i.exec(buf.slice(0, i))?.[1] ?? 0);
      if (buf.length - i - 4 < cl) return;
      tls.off("data", onData);
      resolve(Number(buf.slice(9, 12)));
    };
    tls.on("data", onData);
    tls.on("error", reject);
    tls.write(`POST /c HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: ${body.length}\r\nConnection: keep-alive\r\n\r\n${body}`);
  });
}

test("the inspected leg: the client connection and the pooled upstream have Nagle off, and both requests arrive whole", { skip, timeout: 20_000 }, async () => {
  const caDir = tmpDir("mandu-nodelay-");
  const ca = ensureCa(caDir);
  const leaf = leafForHost(ca, "127.0.0.1");
  const got: string[] = [];
  const upstreams = new Set<number>(); // the proxy's source ports at the destination
  const dest = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
    upstreams.add(req.socket.remotePort!);
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      got.push(Buffer.concat(chunks).toString());
      res.writeHead(200, { "content-length": 2 });
      res.end("ok");
    });
  });
  dest.listen(0, "127.0.0.1");
  await once(dest, "listening");
  const destPort = (dest.address() as AddressInfo).port;
  await watchingNoDelay(async (nodelay) => {
    const proxy = new NetProxy({ allowThisMachine: true, arbiter: new MockArbiter(), log: noop, attributeHolders: holder, mitm: { caDir, insecureUpstream: true } });
    const port = await proxy.listen(0);
    let tls: TLSSocket | undefined;
    try {
      const raw = await connectVia(port, destPort);
      tls = await new Promise<TLSSocket>((resolve, reject) => {
        const t = tlsConnect({ socket: raw, servername: "localhost", ca: ca.certPem, checkServerIdentity: () => undefined }, () => resolve(t));
        t.on("error", reject);
      });
      assert.equal(await post(tls, "first=1"), 200);
      assert.equal(await post(tls, "second=2"), 200);
      assert.deepEqual(got, ["first=1", "second=2"]);
      assert.equal(upstreams.size, 1, "the second request reused the pooled upstream connection");
      const sockets = [...nodelay];
      const up = [...upstreams][0]!;
      assert.ok(sockets.some((s) => s.localPort === up && s.remotePort === destPort), "the inspected leg's upstream connection has Nagle off");
      assert.ok(sockets.some((s) => s.remotePort === raw.localPort && s.localPort === port), "the accepted client connection has Nagle off");
    } finally {
      tls?.destroy();
      await proxy.close();
      dest.closeAllConnections();
      dest.close();
    }
  });
});

test("the blind tunnel: the upstream connection has Nagle off, and the bytes arrive whole", { timeout: 20_000 }, async () => {
  const got: Buffer[] = [];
  let upPort = 0;
  const accepted: Socket[] = [];
  const dest = createNetServer((s) => {
    accepted.push(s);
    upPort = s.remotePort!;
    s.on("data", (c: Buffer) => got.push(c));
    s.on("error", noop);
  });
  dest.listen(0, "127.0.0.1");
  await once(dest, "listening");
  const destPort = (dest.address() as AddressInfo).port;
  await watchingNoDelay(async (nodelay) => {
    const proxy = new NetProxy({ allowThisMachine: true, arbiter: new MockArbiter(), log: noop, attributeHolders: holder });
    const port = await proxy.listen(0);
    let raw: Socket | undefined;
    try {
      raw = await connectVia(port, destPort);
      raw.write("one;");
      raw.write("two;");
      for (let i = 0; i < 100 && Buffer.concat(got).toString() !== "one;two;"; i++) await new Promise((r) => setTimeout(r, 20));
      assert.equal(Buffer.concat(got).toString(), "one;two;");
      const sockets = [...nodelay];
      assert.ok(sockets.some((s) => s.localPort === upPort && s.remotePort === destPort), "the tunnel's upstream connection has Nagle off");
      assert.ok(sockets.some((s) => s.remotePort === raw!.localPort && s.localPort === port), "the accepted client connection has Nagle off");
    } finally {
      raw?.destroy();
      await proxy.close();
      for (const s of accepted) s.destroy();
      dest.close();
    }
  });
});
