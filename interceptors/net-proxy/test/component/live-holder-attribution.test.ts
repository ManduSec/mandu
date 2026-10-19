/**
 * live-holder-attribution.test — the live /proc attribution, made cheaper
 * (plan 13 D6, "the full scan's cost"), still judges every request by the
 * processes holding the client's socket at that request.
 *
 * The proxy keeps one thing per connection: the client end's socket inode.
 * Who holds it is read again from /proc at every request. Proved here with
 * a real NetProxy (no injected attribution: live /proc), TLS inspection on,
 * a real HTTPS destination that records what reaches it (the oracle), a
 * MockArbiter whose secret taint is read live by proc key, and real child
 * processes that inherit the client's socket between two requests on ONE
 * kept-alive connection:
 *   - request 1: only this process holds the socket → judged by its own key,
 *     forwarded;
 *   - a child appears holding the socket, its secret bound to the
 *     destination → judged by the child's own key (its first appearance),
 *     forwarded;
 *   - that child exits and another process holds the socket, its secret NOT
 *     bound to the destination → judged by the new process's key, refused
 *     (403), nothing reaches the destination, and the gone child's key is
 *     not among the holders asked about (no stale identity).
 *
 * Mandu-new (no reference origin). The mock carries the axes (no arbiter is
 * built): this is the confidentiality axis's network exit.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { connect as netConnect, type AddressInfo, type Socket } from "node:net";
import { spawn, type ChildProcess } from "node:child_process";
import { readdirSync, readlinkSync } from "node:fs";
import { once } from "node:events";

import { NetProxy } from "../../src/proxy.js";
import { MockArbiter, type TaintedProcessBindings } from "../../src/arbiter-client.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";
import { provisionalProcKey } from "../../src/conn-attr.js";
import { tmpDir } from "../tmp-dir.js";

const skip = (process.platform !== "linux" && "live /proc is Linux-only") || (!opensslAvailable() && "openssl unavailable");
const noop = (): void => {};
const held = (bindings: string[]): TaintedProcessBindings => ({ tainted: true, level: "no-model", files: ["/w/.env"], bindings });

/** A process that holds `sock` as its fd 3 and does nothing else, once its
 *  descriptor table shows it. The descriptor is passed by number: passing
 *  the stream itself would stop this process reading it. */
async function holderOf(sock: Socket): Promise<ChildProcess> {
  const fd = (sock as unknown as { _handle: { fd: number } })._handle.fd;
  assert.ok(fd > 2, "the client socket has a descriptor");
  const child = spawn("sleep", ["60"], { stdio: ["ignore", "ignore", "ignore", fd] });
  const want = readlinkSync(`/proc/self/fd/${fd}`);
  for (let i = 0; i < 200; i++) {
    try {
      if (readdirSync(`/proc/${child.pid}/fd`).some((fd) => { try { return readlinkSync(`/proc/${child.pid}/fd/${fd}`) === want; } catch { return false; } })) return child;
    } catch {
      /* not yet */
    }
    await new Promise((r) => setTimeout(r, 10));
  }
  child.kill("SIGKILL");
  throw new Error("the child never held the socket");
}

async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGKILL");
  await once(child, "exit");
}

function post(tls: TLSSocket, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const done = (r: { status: number; body: string }): void => {
      tls.off("data", onData);
      tls.off("close", onClose);
      resolve(r);
    };
    const onData = (c: Buffer): void => {
      buf = Buffer.concat([buf, c]);
      const sep = buf.indexOf("\r\n\r\n");
      if (sep === -1) return;
      const head = buf.subarray(0, sep).toString("utf8");
      const cl = Number(/content-length:\s*(\d+)/i.exec(head)?.[1] ?? 0);
      if (buf.length - (sep + 4) < cl) return;
      done({ status: Number(/^HTTP\/1\.1\s+(\d{3})/.exec(head)?.[1] ?? 0), body: buf.subarray(sep + 4, sep + 4 + cl).toString("utf8") });
    };
    const onClose = (): void => done({ status: 0, body: "" });
    tls.on("data", onData);
    tls.on("close", onClose);
    tls.on("error", reject);
    tls.write(`POST /collect HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: keep-alive\r\n\r\n${body}`);
    setTimeout(() => reject(new Error("post timed out")), 10_000).unref();
  });
}

test("live /proc, one kept-alive TLS-inspected connection: each request is judged by the processes holding the socket THEN (a new holder by its own key, a replaced one never by the gone key)", { skip, timeout: 30_000 }, async () => {
  const caDir = tmpDir("mandu-live-attr-");
  const ca = ensureCa(caDir);
  const leaf = leafForHost(ca, "127.0.0.1");
  const received: string[] = [];
  const dest = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      received.push(Buffer.concat(chunks).toString("utf8"));
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("dest-ok");
    });
  });
  dest.listen(0, "127.0.0.1");
  await once(dest, "listening");
  const destPort = (dest.address() as AddressInfo).port;

  const taint: Record<string, TaintedProcessBindings> = {};
  const arbiter = new MockArbiter({ secretTaint: taint });
  // No attributeHolders / attributeConnection: the live /proc attribution.
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, mitm: { caDir, insecureUpstream: true } });
  const proxyPort = await proxy.listen(0);
  const children: ChildProcess[] = [];
  let tls: TLSSocket | undefined;
  try {
    const sock = netConnect(proxyPort, "127.0.0.1");
    await once(sock, "connect");
    sock.write(`CONNECT 127.0.0.1:${destPort} HTTP/1.1\r\nHost: 127.0.0.1:${destPort}\r\n\r\n`);
    const [head] = (await once(sock, "data")) as [Buffer];
    assert.match(head.toString("latin1"), / 200 /);
    tls = await new Promise<TLSSocket>((resolve, reject) => {
      const t = tlsConnect({ socket: sock, servername: "localhost", ca: ca.certPem, checkServerIdentity: () => undefined }, () => resolve(t));
      t.on("error", reject);
    });
    const self = provisionalProcKey(process.pid);
    const asked = (from: number): string[] => arbiter.bindingsCalls.slice(from).map((c) => c.procKey);

    // 1. Only this process holds the socket.
    let mark = arbiter.bindingsCalls.length;
    const r1 = await post(tls, "one=1");
    assert.equal(r1.status, 200, r1.body);
    assert.deepEqual([...new Set(asked(mark))], [self], "attributed live, to this process");

    // 2. A child appears holding the socket; its secret is bound here.
    const a = await holderOf(sock);
    children.push(a);
    const keyA = provisionalProcKey(a.pid!);
    assert.notEqual(keyA, self);
    taint[keyA] = held(["127.0.0.1"]);
    mark = arbiter.bindingsCalls.length;
    const r2 = await post(tls, "two=2");
    assert.equal(r2.status, 200, r2.body);
    assert.ok(asked(mark).includes(keyA), "the new holder is judged by its own key");

    // 3. It exits; another process holds the socket, its secret not bound here.
    await stop(a);
    const b = await holderOf(sock);
    children.push(b);
    const keyB = provisionalProcKey(b.pid!);
    taint[keyB] = held([]);
    mark = arbiter.bindingsCalls.length;
    const r3 = await post(tls, "three=3");
    assert.equal(r3.status, 403, r3.body);
    assert.ok(asked(mark).includes(keyB), "the replacing holder is judged by its own key");
    assert.ok(!asked(mark).includes(keyA), "the gone holder's key is not attributed to the connection");
    assert.deepEqual(received, ["one=1", "two=2"], "the refused request never reached the destination");
  } finally {
    tls?.destroy();
    for (const c of children) await stop(c);
    await proxy.close();
    dest.close();
  }
});
