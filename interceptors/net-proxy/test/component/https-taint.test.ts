/**
 * https-taint.test — plan 13 D6: HTTPS through the session proxy is checked
 * against the sending process's taint, on every leg.
 *
 * Before the fix the guard let a process holding a secret reach the
 * session proxy ("proxied HTTP is judged again at the net-proxy"), but only
 * the plain-HTTP leg resolved the sender: the TLS-inspected leg (MITM) called
 * the gate with no process, and a blind CONNECT tunnel had no taint check at
 * all, so a reader using the launcher's own HTTPS_PROXY could send the raw
 * bytes (in any encoding) to any HTTPS host.
 *
 * A real NetProxy with a MockArbiter (`secretTaint`: proc key → its secrets'
 * bindings, ancestors inherit, read live so a test can taint a process
 * mid-connection) and an injected `attributeHolders` (no real /proc), a real
 * HTTPS destination that records every request, and real CONNECT + TLS
 * clients. Asserted, with the destination's record as the oracle:
 *   - TLS-inspected leg: a holder → unbound host: 403, nothing received (the
 *     secret raw, and base64-encoded); → a bound host: forwarded; a process
 *     holding nothing: forwarded; a holder by inheritance (ancestors);
 *     tainted between two keep-alive requests; a holder that appears after
 *     the CONNECT (a fork); an unattributed connection while the session
 *     holds a secret; the arbiter failing; the verbatim tripwire;
 *   - blind CONNECT (MITM off, and a model host with MITM on): a holder →
 *     refused, the tunnel never opens; a bound host → tunneled; tainted
 *     after the CONNECT → the next chunk is not delivered;
 *   - plain HTTP: unattributed while the session holds a secret → 403; a
 *     model host passthrough for a holder → 403;
 *   - the frozen integrity leg is NOT extended to HTTPS.
 *
 * Mandu-new (no reference origin). The mock carries the axes (no arbiter is
 * built): this is the confidentiality axis's network exit.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { connect as netConnect, createServer as createNetServer, type AddressInfo } from "node:net";
import { once } from "node:events";

import { NetProxy, type HttpForwarder } from "../../src/proxy.js";
import { MockArbiter, type TaintedProcessBindings } from "../../src/arbiter-client.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";
import type { ProcHolder } from "../../src/conn-attr.js";
import { tmpDir } from "../tmp-dir.js";

const OPENSSL = opensslAvailable();
const skip = !OPENSSL && "openssl unavailable";
const noop = (): void => {};
const SECRET = "sk_live_D6CANARY_7f3a91c04e";
const B64 = Buffer.from(SECRET).toString("base64");

const held = (bindings: string[], files = ["/w/.env"]): TaintedProcessBindings => ({ tainted: true, level: "no-model", files, bindings });
const one = (procKey: string, ancestors: string[] = []): ProcHolder[] => [{ procKey, ancestors }];

interface Received { method: string; url: string; body: string }

/** A real HTTPS destination on 127.0.0.1 (leaf for `127.0.0.1` under the
 *  session CA, the proxy re-originates with insecureUpstream). */
async function startDest(caDir: string) {
  const ca = ensureCa(caDir);
  const leaf = leafForHost(ca, "127.0.0.1");
  const received: Received[] = [];
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
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
  return { server, received, port: (server.address() as AddressInfo).port, caPem: ca.certPem };
}

/** CONNECT through the proxy. Resolves the raw socket once the proxy
 *  answered 200, or the status line it refused with. */
function connectVia(proxyPort: number, host: string, port: number): Promise<{ status: string; sock: import("node:net").Socket; leftover: Buffer }> {
  return new Promise((resolve, reject) => {
    const sock = netConnect(proxyPort, "127.0.0.1", () => {
      sock.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`);
    });
    let head = Buffer.alloc(0);
    const onData = (c: Buffer): void => {
      head = Buffer.concat([head, c]);
      const idx = head.indexOf("\r\n\r\n");
      if (idx === -1) return;
      sock.off("data", onData);
      const statusLine = head.subarray(0, idx).toString("latin1").split("\r\n")[0]!;
      resolve({ status: statusLine, sock, leftover: head.subarray(idx + 4) });
    };
    sock.on("data", onData);
    sock.on("error", reject);
    setTimeout(() => reject(new Error("CONNECT timed out")), 5000).unref();
  });
}

/** TLS over an established tunnel, trusting the session CA. */
function tlsOver(sock: import("node:net").Socket, leftover: Buffer, caPem: string): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const tls = tlsConnect({ socket: sock, servername: "127.0.0.1", ca: caPem }, () => resolve(tls));
    if (leftover.length) tls.unshift(leftover);
    tls.on("error", reject);
  });
}

/** One request on a TLS socket, its response read by Content-Length. A
 *  closed socket with no response resolves status 0. */
function sendOnTls(tls: TLSSocket, body: string, connection: "keep-alive" | "close" = "keep-alive"): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const finish = (r: { status: number; body: string }): void => {
      tls.off("data", onData);
      tls.off("close", onClose);
      resolve(r);
    };
    const onData = (c: Buffer): void => {
      buf = Buffer.concat([buf, c]);
      const sep = buf.indexOf("\r\n\r\n");
      if (sep === -1) return;
      const headTxt = buf.subarray(0, sep).toString("utf8");
      const cl = Number(/content-length:\s*(\d+)/i.exec(headTxt)?.[1] ?? 0);
      if (buf.length - (sep + 4) < cl) return;
      const m = /^HTTP\/1\.1\s+(\d{3})/.exec(headTxt);
      finish({ status: m ? Number(m[1]) : 0, body: buf.subarray(sep + 4, sep + 4 + cl).toString("utf8") });
    };
    const onClose = (): void => finish({ status: 0, body: "" });
    tls.on("data", onData);
    tls.on("close", onClose);
    tls.on("error", reject);
    tls.write([
      "POST /collect HTTP/1.1", "Host: 127.0.0.1", "Content-Type: text/plain",
      `Content-Length: ${Buffer.byteLength(body)}`, `Connection: ${connection}`, "", body,
    ].join("\r\n"));
    setTimeout(() => reject(new Error("sendOnTls timed out")), 5000).unref();
  });
}

/** CONNECT + TLS + one request (Connection: close). */
async function httpsPost(proxyPort: number, destPort: number, caPem: string, body: string): Promise<{ status: number; body: string; connect: string }> {
  const c = await connectVia(proxyPort, "127.0.0.1", destPort);
  if (!/ 200 /.test(c.status + " ")) {
    c.sock.destroy();
    return { status: 0, body: "", connect: c.status };
  }
  const tls = await tlsOver(c.sock, c.leftover, caPem);
  try {
    return { ...(await sendOnTls(tls, body, "close")), connect: c.status };
  } finally {
    tls.destroy();
  }
}

/** A proxy with TLS inspection on and the given attribution. */
async function mitmProxy(arbiter: MockArbiter, attributeHolders: () => ProcHolder[], extra: Partial<ConstructorParameters<typeof NetProxy>[0]> = {}) {
  const caDir = tmpDir("mandu-d6-");
  const dest = await startDest(caDir);
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, mitm: { caDir, insecureUpstream: true }, attributeHolders, ...extra });
  const port = await proxy.listen(0);
  return { proxy, port, dest, close: async () => { await proxy.close(); dest.server.close(); } };
}

// ── the TLS-inspected leg ─────────────────────────────────────────────────

test("D6 MITM: a process holding a secret sends it to an UNBOUND https host → 403, the host receives nothing (raw or encoded)", { skip }, async () => {
  const arbiter = new MockArbiter({ secretTaint: { "7001-1": held(["bound.example"]) } });
  const s = await mitmProxy(arbiter, () => one("7001-1"));
  try {
    for (const body of [`key=${SECRET}`, `k=${B64}`]) {
      const r = await httpsPost(s.port, s.dest.port, s.dest.caPem, body);
      assert.equal(r.status, 403, `a holder's HTTPS request to an unbound host must be refused (${r.connect} / ${r.status} ${r.body})`);
      assert.ok(!r.body.includes(SECRET), "the refusal carries no secret byte");
    }
    assert.equal(s.dest.received.length, 0, "the unbound host received NOTHING");
    assert.ok(arbiter.bindingsCalls.some((c) => c.procKey === "7001-1"), "the gate asked the holder's taint");
  } finally {
    await s.close();
  }
});

test("D6 MITM: the same holder at a host its secret IS bound to → forwarded (the bound registry keeps working)", { skip }, async () => {
  const arbiter = new MockArbiter({ secretTaint: { "7002-1": held(["127.0.0.1"]) } });
  const s = await mitmProxy(arbiter, () => one("7002-1"));
  try {
    const r = await httpsPost(s.port, s.dest.port, s.dest.caPem, `key=${SECRET}`);
    assert.equal(r.status, 200, r.body);
    assert.deepEqual(s.dest.received.map((x) => x.body), [`key=${SECRET}`], "a bound host gets the request (a release, not a leak)");
  } finally {
    await s.close();
  }
});

test("D6 MITM control: a process holding nothing → forwarded", { skip }, async () => {
  const arbiter = new MockArbiter();
  const s = await mitmProxy(arbiter, () => one("7003-1"));
  try {
    const r = await httpsPost(s.port, s.dest.port, s.dest.caPem, "hello=1");
    assert.equal(r.status, 200, r.body);
    assert.equal(s.dest.received.length, 1);
    assert.equal(arbiter.sessionTaintCalls.length, 0, "an attributed connection never falls back to the session question");
  } finally {
    await s.close();
  }
});

test("D6 MITM: a holder by INHERITANCE (its ancestor read the secret) → 403; the ancestor chain reaches the arbiter", { skip }, async () => {
  const arbiter = new MockArbiter({ secretTaint: { "7004-reader": held([]) } });
  const s = await mitmProxy(arbiter, () => one("7004-child", ["7004-reader", "7004-agent"]));
  try {
    const r = await httpsPost(s.port, s.dest.port, s.dest.caPem, `x=${B64}`);
    assert.equal(r.status, 403);
    assert.equal(s.dest.received.length, 0);
    assert.deepEqual(arbiter.bindingsCalls.find((c) => c.procKey === "7004-child")?.ancestors, ["7004-reader", "7004-agent"]);
  } finally {
    await s.close();
  }
});

test("D6 MITM keep-alive: a process that reads a secret BETWEEN two requests on one connection → the second is refused", { skip }, async () => {
  const taint: Record<string, TaintedProcessBindings> = {};
  const arbiter = new MockArbiter({ secretTaint: taint });
  const s = await mitmProxy(arbiter, () => one("7005-1"));
  try {
    const c = await connectVia(s.port, "127.0.0.1", s.dest.port);
    assert.match(c.status, / 200 /);
    const tls = await tlsOver(c.sock, c.leftover, s.dest.caPem);
    const first = await sendOnTls(tls, "before=1");
    assert.equal(first.status, 200);
    taint["7005-1"] = held(["bound.example"]); // the process reads the secret now
    const second = await sendOnTls(tls, `after=${B64}`);
    assert.equal(second.status, 403, "the next request on the same connection is judged by the taint it has now");
    assert.deepEqual(s.dest.received.map((x) => x.body), ["before=1"], "only the request before the read was delivered");
    tls.destroy();
  } finally {
    await s.close();
  }
});

test("D6 MITM: a holder that appears AFTER the CONNECT (a child that inherited the socket) is judged too", { skip }, async () => {
  const arbiter = new MockArbiter({ secretTaint: { "7006-child": held([]) } });
  let calls = 0;
  // At the CONNECT only the parent holds the socket; by the request a forked
  // child that read the secret holds it as well.
  const s = await mitmProxy(arbiter, () => (++calls === 1 ? one("7006-parent") : [...one("7006-parent"), ...one("7006-child")]));
  try {
    const r = await httpsPost(s.port, s.dest.port, s.dest.caPem, `x=${SECRET}`);
    assert.equal(r.status, 403);
    assert.equal(s.dest.received.length, 0);
  } finally {
    await s.close();
  }
});

test("D6 MITM: an UNATTRIBUTED connection while the session holds a secret → 403 (fail-closed); while none does → forwarded", { skip }, async () => {
  const tainted = new MockArbiter({ sessionTaint: { tainted: true, level: "no-model", files: ["/w/.env"] } });
  const s1 = await mitmProxy(tainted, () => [], { sessionId: "sess-d6" });
  try {
    const r = await httpsPost(s1.port, s1.dest.port, s1.dest.caPem, `x=${SECRET}`);
    assert.equal(r.status, 403);
    assert.match(r.body, /could not be attributed/);
    assert.equal(s1.dest.received.length, 0);
    assert.ok(tainted.sessionTaintCalls.some((c) => c.session === "sess-d6"), "the session asked is the proxy's own");
  } finally {
    await s1.close();
  }
  const clean = new MockArbiter();
  const s2 = await mitmProxy(clean, () => []);
  try {
    const r = await httpsPost(s2.port, s2.dest.port, s2.dest.caPem, "hello=1");
    assert.equal(r.status, 200, r.body);
  } finally {
    await s2.close();
  }
});

test("D6 MITM: the arbiter failing the taint question → 403 (fail-closed), for an attributed and an unattributed sender", { skip }, async () => {
  for (const [arbiter, holders] of [
    [new MockArbiter({ failTaintedProcessBindings: true }), one("7008-1")],
    [new MockArbiter({ failSessionSecretTaint: true }), []],
  ] as const) {
    const s = await mitmProxy(arbiter, () => [...holders]);
    try {
      const r = await httpsPost(s.port, s.dest.port, s.dest.caPem, "hello=1");
      assert.equal(r.status, 403, r.body);
      assert.equal(s.dest.received.length, 0);
    } finally {
      await s.close();
    }
  }
});

test("MITM: the §4 verbatim tripwire runs on the decrypted request too (a raw registered value → 403)", { skip }, async () => {
  const arbiter = new MockArbiter({ fingerprintSecrets: [{ symbol: "$MDU:env[d6d6]", value: SECRET, level: "no-model" }] });
  const s = await mitmProxy(arbiter, () => one("7009-1"));
  try {
    const r = await httpsPost(s.port, s.dest.port, s.dest.caPem, `key=${SECRET}`);
    assert.equal(r.status, 403);
    assert.match(r.body, /fingerprint tripwire/);
    assert.equal(s.dest.received.length, 0);
  } finally {
    await s.close();
  }
});

test("the frozen integrity leg is NOT extended to HTTPS: an integrity-tainted process with no secret is forwarded, and the MITM leg tags no process", { skip }, async () => {
  const arbiter = new MockArbiter();
  arbiter.taintProc("7010-1", "evil.example");
  const s = await mitmProxy(arbiter, () => one("7010-1"));
  try {
    const r = await httpsPost(s.port, s.dest.port, s.dest.caPem, "hello=1");
    assert.equal(r.status, 200, r.body);
    assert.equal(arbiter.isProcessTaintedCalls.length, 0, "the MITM leg never asks the integrity question");
    assert.equal(arbiter.taintProcessCalls.length, 0, "the MITM leg never tags a process (observe-and-tag stays plain-HTTP)");
  } finally {
    await s.close();
  }
});

// ── the blind CONNECT leg ─────────────────────────────────────────────────

/** A TCP listener that records every byte it receives (and echoes it). */
async function recorder() {
  const got: Buffer[] = [];
  const server = createNetServer((s) => {
    s.on("data", (c: Buffer) => {
      got.push(c);
      s.write(c);
    });
    s.on("error", noop);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { got, port: (server.address() as AddressInfo).port, text: () => Buffer.concat(got).toString("utf8"), close: () => server.close() };
}

test("D6 blind CONNECT (TLS inspection off): a holder → refused 403, the tunnel never opens; at a BOUND host → tunneled", async () => {
  const rec = await recorder();
  const taint: Record<string, TaintedProcessBindings> = { "7011-1": held(["bound.example"]) };
  const arbiter = new MockArbiter({ secretTaint: taint });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, attributeHolders: () => one("7011-1") });
  const port = await proxy.listen(0);
  try {
    const c = await connectVia(port, "127.0.0.1", rec.port);
    assert.match(c.status, / 403 /, "a tunnel the proxy cannot read is refused to a process holding a secret not bound there");
    c.sock.write(SECRET);
    await new Promise((r) => setTimeout(r, 100));
    c.sock.destroy();
    assert.equal(rec.got.length, 0, "the destination received nothing");

    taint["7011-1"] = held(["127.0.0.1"]);
    const ok = await connectVia(port, "127.0.0.1", rec.port);
    assert.match(ok.status, / 200 /, "the same process may tunnel to the host its secret is bound to (the guard's answer to a direct connect)");
    ok.sock.write("bound-bytes");
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(rec.text(), "bound-bytes");
    ok.sock.destroy();
  } finally {
    await proxy.close();
    rec.close();
  }
});

test("D6 blind CONNECT to a MODEL host (never inspected): a holder → refused 403", { skip }, async () => {
  const rec = await recorder();
  const caDir = tmpDir("mandu-d6-model-");
  const arbiter = new MockArbiter({ secretTaint: { "7012-1": held(["bound.example"]) } });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, modelHosts: ["127.0.0.1"], mitm: { caDir, insecureUpstream: true }, attributeHolders: () => one("7012-1") });
  const port = await proxy.listen(0);
  try {
    const c = await connectVia(port, "127.0.0.1", rec.port);
    assert.match(c.status, / 403 /);
    c.sock.destroy();
    assert.equal(rec.got.length, 0);
  } finally {
    await proxy.close();
    rec.close();
  }
});

test("D6 blind tunnel: a process that reads a secret AFTER the CONNECT → its next chunk is not delivered and the tunnel closes", { timeout: 15_000 }, async () => {
  const rec = await recorder();
  const taint: Record<string, TaintedProcessBindings> = {};
  const arbiter = new MockArbiter({ secretTaint: taint });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, attributeHolders: () => one("7013-1") });
  const port = await proxy.listen(0);
  try {
    const c = await connectVia(port, "127.0.0.1", rec.port);
    assert.match(c.status, / 200 /);
    c.sock.write("before-read");
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(rec.text(), "before-read");
    taint["7013-1"] = held(["bound.example"]);
    const closed = once(c.sock, "close");
    c.sock.write(`after-read:${SECRET}`);
    await closed;
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(rec.text(), "before-read", "nothing after the read reached the destination");
    const ev = arbiter.emittedEvents.find((e) => /tunnel closed/.test(String((e as { note?: string }).note ?? "")));
    assert.ok(ev, "the closing is on the trace");
  } finally {
    await proxy.close();
    rec.close();
  }
});

test("D6 blind CONNECT: unattributed while the session holds a secret → refused", async () => {
  const rec = await recorder();
  const arbiter = new MockArbiter({ sessionTaint: { tainted: true, level: "no-model", files: ["/w/.env"] } });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, attributeHolders: () => [] });
  const port = await proxy.listen(0);
  try {
    const c = await connectVia(port, "127.0.0.1", rec.port);
    assert.match(c.status, / 403 /);
    c.sock.destroy();
    assert.equal(rec.got.length, 0);
  } finally {
    await proxy.close();
    rec.close();
  }
});

// ── the plain-HTTP leg ────────────────────────────────────────────────────

function plainGet(port: number, url: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method: "GET", path: url, headers: { host: u.host } }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    r.on("error", reject);
    r.end();
  });
}

test("D6 plain HTTP: unattributed while the session holds a secret → 403 (was fail-soft); none held → forwarded", async () => {
  let forwarded = 0;
  const forwarder: HttpForwarder = async () => {
    forwarded++;
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
  };
  const tainted = new MockArbiter({ sessionTaint: { tainted: true, level: "no-model", files: ["/w/.env"] } });
  const p1 = new NetProxy({ allowThisMachine: true, arbiter: tainted, forwarder, log: noop, attributeHolders: () => [] });
  const port1 = await p1.listen(0);
  try {
    const r = await plainGet(port1, "http://example.test/x");
    assert.equal(r.status, 403);
    assert.equal(forwarded, 0);
  } finally {
    await p1.close();
  }
  const clean = new MockArbiter({ trustedOrigins: ["example.test"] });
  const p2 = new NetProxy({ allowThisMachine: true, arbiter: clean, forwarder, log: noop, attributeHolders: () => [] });
  const port2 = await p2.listen(0);
  try {
    assert.equal((await plainGet(port2, "http://example.test/x")).status, 200);
    assert.equal(forwarded, 1);
  } finally {
    await p2.close();
  }
});

test("D6 plain HTTP: a model host is excluded from the symbol gate, not from a holder's network exit → 403", async () => {
  let forwarded = 0;
  const upstream = createHttpServer((_req, res) => {
    forwarded++;
    res.end("model");
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  const arbiter = new MockArbiter({ secretTaint: { "7016-1": held(["bound.example"]) } });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, modelHosts: ["model.example"], attributeHolders: () => one("7016-1"),
    forwarder: async () => { forwarded++; return { status: 200, headers: {}, body: Buffer.from("model") }; } });
  const port = await proxy.listen(0);
  try {
    const r = await plainGet(port, "http://model.example/v1/messages");
    assert.equal(r.status, 403);
    assert.equal(forwarded, 0);
  } finally {
    await proxy.close();
    upstream.close();
  }
});
