/**
 * mitm.test — e2e tests for the OPT-IN MITM TLS-termination path (src/mitm.ts +
 * src/ca.ts), wired through the NetProxy CONNECT branch (src/proxy.ts).
 *
 * Boots a real NetProxy with `mitm:{caDir}` ON + a MockArbiter + a LOCAL HTTPS
 * mock destination, then drives an HTTPS request THROUGH the proxy via CONNECT —
 * the client trusts the session CA (loaded from the proxy's minted CA pem) so the
 * terminated TLS handshake succeeds. This proves the NEW capability a blind CONNECT
 * tunnel cannot: gating a symbol carried in the HTTPS BODY.
 *
 * The upstream HTTPS mock dest signs its leaf with the SAME session CA, and we run
 * the proxy with `insecureUpstream:true` so the proxy's re-origination doesn't need
 * the host system store to trust our self-signed mock (kept fully offline).
 *
 * Asserts:
 *   (1) a symbol in the HTTPS BODY → 403 over the terminated TLS socket, and the
 *       upstream mock dest received NOTHING (the blind-tunnel-couldn't capability).
 *   (2) a benign HTTPS request → decrypted, forwarded, the dest received it, and
 *       the response is returned to the client.
 *   (3) a model host CONNECT is STILL blind-tunneled even with MITM on.
 *
 * SKIPs cleanly (the suite passes with 0 assertions) if openssl is unavailable.
 */

import { test } from "node:test";
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { connect as tlsConnect, type DetailedPeerCertificate } from "node:tls";
import { X509Certificate } from "node:crypto";
import { connect as netConnect, createServer as createNetServer, type AddressInfo } from "node:net";
import { once } from "node:events";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { NetProxy } from "../../src/proxy.js";
import { MockArbiter } from "../../src/arbiter-client.js";
import { tmpDir } from "../tmp-dir.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";

const SYM = "$MDU:web_fetch[c0de]";
const noop = (): void => {};
const OPENSSL = opensslAvailable();

/** Mint a fresh session CA dir for a test (per-test isolation). */
function freshCaDir(): string {
  return tmpDir("mandu-mitm-test-");
}

interface DestRecord {
  method: string;
  url: string;
  body: string;
}

/**
 * Start a local HTTPS mock destination on `host`, with a leaf signed by the
 * SHARED session CA in `caDir` so the proxy (which re-originates with the system
 * store OR insecureUpstream) can reach it. Records every request it receives.
 */
async function startHttpsDest(caDir: string, host: string) {
  const ca = ensureCa(caDir);
  const leaf = leafForHost(ca, host);
  const received: DestRecord[] = [];
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      received.push({ method: req.method ?? "", url: req.url ?? "", body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("dest-says-hello");
    });
  });
  server.listen(0, host);
  await once(server, "listening");
  const port = (server.address() as AddressInfo).port;
  return { server, received, host, port, caCertPem: ca.certPem };
}

/**
 * Drive an HTTPS request THROUGH the proxy: open a CONNECT tunnel, then run TLS
 * (trusting `caPem`, the session CA the proxy presents leaves from) over it and
 * send one request. Resolves with the decrypted status line + body.
 */
function httpsThroughProxy(
  proxyPort: number,
  target: { host: string; port: number },
  caPem: string,
  reqBody: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const raw = netConnect(proxyPort, "127.0.0.1", () => {
      raw.write(`CONNECT ${target.host}:${target.port} HTTP/1.1\r\nHost: ${target.host}:${target.port}\r\n\r\n`);
    });
    let established = false;
    let head = "";
    raw.on("data", function onData(chunk: Buffer) {
      if (established) return;
      head += chunk.toString("latin1");
      const idx = head.indexOf("\r\n\r\n");
      if (idx === -1) return;
      const statusLine = head.split("\r\n")[0]!;
      if (!/^HTTP\/1\.1 200/.test(statusLine)) {
        reject(new Error(`CONNECT failed: ${statusLine}`));
        raw.destroy();
        return;
      }
      established = true;
      raw.off("data", onData);
      // Any bytes after the CONNECT response head are part of TLS — unshift them.
      const leftover = Buffer.from(head.slice(idx + 4), "latin1");
      const tls = tlsConnect({ socket: raw, servername: target.host, ca: caPem }, () => {
        const lines = [
          `POST /collect HTTP/1.1`,
          `Host: ${target.host}`,
          `Content-Type: application/x-www-form-urlencoded`,
          `Content-Length: ${Buffer.byteLength(reqBody)}`,
          `Connection: close`,
          "",
          reqBody,
        ];
        tls.write(lines.join("\r\n"));
      });
      if (leftover.length) tls.unshift(leftover);
      const respChunks: Buffer[] = [];
      tls.on("data", (c: Buffer) => respChunks.push(c));
      tls.on("end", () => {
        const raw2 = Buffer.concat(respChunks).toString("utf8");
        const sep = raw2.indexOf("\r\n\r\n");
        const headTxt = sep === -1 ? raw2 : raw2.slice(0, sep);
        const body = sep === -1 ? "" : raw2.slice(sep + 4);
        const m = headTxt.split("\r\n")[0]!.match(/^HTTP\/1\.1\s+(\d{3})/);
        resolve({ status: m ? Number(m[1]) : 0, body });
      });
      tls.on("error", reject);
    });
    raw.on("error", reject);
    setTimeout(() => reject(new Error("httpsThroughProxy timed out")), 5000).unref();
  });
}

/**
 * Open ONE CONNECT tunnel + run TLS over it (trusting `caPem`) and resolve the
 * established TLSSocket so a test can send SEVERAL sequential requests on the SAME
 * connection (keep-alive). The caller drives requests via `sendOnTls` and closes
 * the socket when done. Used by the keep-alive test (ONE CONNECT, TWO requests).
 */
function openTunnel(
  proxyPort: number,
  target: { host: string; port: number },
  caPem: string,
): Promise<import("node:tls").TLSSocket> {
  return new Promise((resolve, reject) => {
    const raw = netConnect(proxyPort, "127.0.0.1", () => {
      raw.write(`CONNECT ${target.host}:${target.port} HTTP/1.1\r\nHost: ${target.host}:${target.port}\r\n\r\n`);
    });
    let established = false;
    let head = "";
    raw.on("data", function onData(chunk: Buffer) {
      if (established) return;
      head += chunk.toString("latin1");
      const idx = head.indexOf("\r\n\r\n");
      if (idx === -1) return;
      const statusLine = head.split("\r\n")[0]!;
      if (!/^HTTP\/1\.1 200/.test(statusLine)) {
        reject(new Error(`CONNECT failed: ${statusLine}`));
        raw.destroy();
        return;
      }
      established = true;
      raw.off("data", onData);
      const leftover = Buffer.from(head.slice(idx + 4), "latin1");
      const tls = tlsConnect({ socket: raw, servername: target.host, ca: caPem }, () => resolve(tls));
      if (leftover.length) tls.unshift(leftover);
      tls.on("error", reject);
    });
    raw.on("error", reject);
    setTimeout(() => reject(new Error("openTunnel timed out")), 5000).unref();
  });
}

/**
 * Write raw request bytes on an already-established TLS socket and read back EXACTLY
 * ONE HTTP/1.1 response (framed by its Content-Length), so multiple calls can run
 * on a keep-alive connection. Buffers across `data` events; resolves once the head
 * + Content-Length body are in. The socket stays open for the next request.
 */
function sendOnTls(tls: import("node:tls").TLSSocket, rawRequest: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const onData = (c: Buffer): void => {
      buf = Buffer.concat([buf, c]);
      const sep = buf.indexOf("\r\n\r\n");
      if (sep === -1) return;
      const headTxt = buf.subarray(0, sep).toString("utf8");
      const clMatch = headTxt.match(/content-length:\s*(\d+)/i);
      const cl = clMatch ? Number(clMatch[1]) : 0;
      const bodyStart = sep + 4;
      if (buf.length - bodyStart < cl) return; // wait for the full body
      tls.off("data", onData);
      tls.off("error", reject);
      const statusLine = headTxt.split("\r\n")[0]!;
      const m = statusLine.match(/^HTTP\/1\.1\s+(\d{3})/);
      const body = buf.subarray(bodyStart, bodyStart + cl).toString("utf8");
      resolve({ status: m ? Number(m[1]) : 0, body });
    };
    tls.on("data", onData);
    tls.on("error", reject);
    tls.write(rawRequest);
    setTimeout(() => reject(new Error("sendOnTls timed out")), 5000).unref();
  });
}

/** Build a raw HTTP/1.1 request with a Content-Length body and a `Connection` mode. */
function clRequest(host: string, path: string, body: string, connection: "keep-alive" | "close"): string {
  return [
    `POST ${path} HTTP/1.1`,
    `Host: ${host}`,
    `Content-Type: application/x-www-form-urlencoded`,
    `Content-Length: ${Buffer.byteLength(body)}`,
    `Connection: ${connection}`,
    "",
    body,
  ].join("\r\n");
}

/** Build a raw HTTP/1.1 request whose body is sent as Transfer-Encoding: chunked
 * (each element of `chunks` becomes one wire chunk; a 0-chunk + trailing CRLF
 * terminate it). Exercises the new chunked REQUEST-body decode path. */
function chunkedRequest(host: string, path: string, chunks: string[], connection: "keep-alive" | "close"): string {
  const head = [
    `POST ${path} HTTP/1.1`,
    `Host: ${host}`,
    `Content-Type: text/plain`,
    `Transfer-Encoding: chunked`,
    `Connection: ${connection}`,
    "",
    "",
  ].join("\r\n");
  let body = "";
  for (const c of chunks) {
    body += `${Buffer.byteLength(c).toString(16)}\r\n${c}\r\n`;
  }
  body += "0\r\n\r\n"; // last-chunk + (empty) trailer terminator
  return head + body;
}

test("(1) MITM: a symbol in the HTTPS BODY → 403 and the upstream dest received NOTHING", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  const caDir = freshCaDir();
  const dest = await startHttpsDest(caDir, "127.0.0.1");
  const arbiter = new MockArbiter({
    values: { [SYM]: "super-secret-token" },
    decisionFn: () => ({ allow: false, requiresApproval: true, reason: "untrusted destination" }),
  });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, mitm: { caDir, insecureUpstream: true } });
  const port = await proxy.listen(0);
  try {
    const res = await httpsThroughProxy(port, dest, dest.caCertPem, `leak=${SYM}`);
    assert.equal(res.status, 403, "a symbol in the HTTPS body must be BLOCKED (403) by the gate");
    assert.equal(res.body.includes("super-secret-token"), false, "the secret must not appear in the 403 body");
    assert.equal(dest.received.length, 0, "the upstream HTTPS destination must have received NOTHING");
  } finally {
    await proxy.close();
    dest.server.close();
  }
});

test("(2) MITM: a benign HTTPS request → decrypted, forwarded, dest received it, response returned", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  const caDir = freshCaDir();
  const dest = await startHttpsDest(caDir, "127.0.0.1");
  // classify TRUSTED so the response symbolize path isn't exercised here (we assert
  // the decrypted wire body reached the dest + the response came back).
  const arbiter = new MockArbiter({
    classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "trusted" }),
  });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, mitm: { caDir, insecureUpstream: true } });
  const port = await proxy.listen(0);
  try {
    const res = await httpsThroughProxy(port, dest, dest.caCertPem, "hello=world");
    assert.equal(res.status, 200, "a benign HTTPS request must pass the gate (200)");
    assert.equal(res.body, "dest-says-hello", "the upstream response must be returned to the client");
    assert.equal(dest.received.length, 1, "the upstream HTTPS dest must have received the (decrypted) request");
    assert.equal(dest.received[0]!.body, "hello=world", "the dest must receive the decrypted benign body");
    assert.equal(dest.received[0]!.method, "POST");
  } finally {
    await proxy.close();
    dest.server.close();
  }
});

test("(2b) MITM: an UNTRUSTED HTTPS response body is returned RAW (net no longer symbolizes — Plan 7)", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  const caDir = freshCaDir();
  const dest = await startHttpsDest(caDir, "127.0.0.1");
  const arbiter = new MockArbiter(); // default classify = UNTRUSTED
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, mitm: { caDir, insecureUpstream: true } });
  const port = await proxy.listen(0);
  try {
    const res = await httpsThroughProxy(port, dest, dest.caCertPem, "benign=1");
    assert.equal(res.status, 200);
    // FLIP: net returns the raw decrypted body; the T-LLM invariant is at the model proxy.
    assert.equal(res.body, "dest-says-hello", "MITM returns the raw untrusted response post-flip");
    assert.doesNotMatch(res.body, /^\$MDU:/, "net ingress no longer symbolizes the body");
    assert.equal(arbiter.symbolizeCalls.length, 0, "net ingress must NOT call symbolize");
  } finally {
    await proxy.close();
    dest.server.close();
  }
});

test("(3) MITM on: a model host CONNECT is STILL blind-tunneled (NOT terminated)", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  // Stand up a TCP echo and pretend it's the model host by CONNECTing to its
  // host:port but with the model-host name excluded via modelHosts (suffix match
  // on the literal CONNECT host). We assert a raw byte echo round-trips (proving a
  // plain tunnel, NOT a TLS termination — a terminated socket would expect a TLS
  // ClientHello, not echo arbitrary bytes).
  const caDir = freshCaDir();
  const tcpEcho = createNetServer((s) => s.pipe(s));
  tcpEcho.listen(0, "127.0.0.1");
  await once(tcpEcho, "listening");
  const echoPort = (tcpEcho.address() as AddressInfo).port;

  const arbiter = new MockArbiter();
  // Mark 127.0.0.1 as a model host so the MITM branch is skipped for it.
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, modelHosts: ["127.0.0.1"], mitm: { caDir, insecureUpstream: true } });
  const port = await proxy.listen(0);
  try {
    const echoed = await new Promise<boolean>((resolve, reject) => {
      const sock = netConnect(port, "127.0.0.1", () => {
        sock.write(`CONNECT 127.0.0.1:${echoPort} HTTP/1.1\r\nHost: 127.0.0.1:${echoPort}\r\n\r\n`);
      });
      let phase = 0;
      let buf = "";
      sock.on("data", (chunk: Buffer) => {
        if (phase === 0) {
          buf += chunk.toString("utf8");
          if (buf.includes("\r\n\r\n")) {
            assert.match(buf.split("\r\n")[0]!, /^HTTP\/1\.1 200/);
            phase = 1;
            sock.write("ping-through-blind-tunnel");
          }
        } else if (chunk.toString("utf8").includes("ping-through-blind-tunnel")) {
          resolve(true);
          sock.destroy();
        }
      });
      sock.on("error", reject);
      setTimeout(() => reject(new Error("model-host tunnel timed out")), 3000).unref();
    });
    assert.equal(echoed, true, "a model host must be BLIND-TUNNELED even with MITM on (raw bytes echo back)");
    assert.equal(arbiter.decisionCalls.length, 0, "a blind-tunneled model host must NOT hit the egress gate");
  } finally {
    await proxy.close();
    tcpEcho.close();
  }
});

test("(4) MITM off (default): HTTPS CONNECT is blind-tunneled — behavior unchanged", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  // No mitm option → the default path. Prove a raw TCP tunnel still works (the same
  // contract as forward-proxy.test (6b)), so the opt-in is truly default-OFF.
  const tcpEcho = createNetServer((s) => s.pipe(s));
  tcpEcho.listen(0, "127.0.0.1");
  await once(tcpEcho, "listening");
  const echoPort = (tcpEcho.address() as AddressInfo).port;
  const arbiter = new MockArbiter();
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop }); // MITM OFF
  const port = await proxy.listen(0);
  try {
    const echoed = await new Promise<boolean>((resolve, reject) => {
      const sock = netConnect(port, "127.0.0.1", () => {
        sock.write(`CONNECT 127.0.0.1:${echoPort} HTTP/1.1\r\nHost: 127.0.0.1:${echoPort}\r\n\r\n`);
      });
      let phase = 0;
      let buf = "";
      sock.on("data", (chunk: Buffer) => {
        if (phase === 0) {
          buf += chunk.toString("utf8");
          if (buf.includes("\r\n\r\n")) {
            phase = 1;
            sock.write("ping-default-off");
          }
        } else if (chunk.toString("utf8").includes("ping-default-off")) {
          resolve(true);
          sock.destroy();
        }
      });
      sock.on("error", reject);
      setTimeout(() => reject(new Error("default-off tunnel timed out")), 3000).unref();
    });
    assert.equal(echoed, true);
  } finally {
    await proxy.close();
    tcpEcho.close();
  }
});

test("(5) MITM keep-alive: TWO sequential requests on ONE CONNECT are independently gated", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  // ONE CONNECT + TLS, TWO requests on the SAME persistent connection: the first
  // (benign) is delivered; the second (a symbol → untrusted dest) is BLOCKED (403).
  // Proves the keep-alive loop gates each request independently with NO new CONNECT.
  const caDir = freshCaDir();
  const dest = await startHttpsDest(caDir, "127.0.0.1");
  const arbiter = new MockArbiter({
    values: { [SYM]: "super-secret-token" },
    // benign body (no symbol) → no decision call; a symbol → deny (untrusted dest).
    decisionFn: () => ({ allow: false, requiresApproval: true, reason: "untrusted destination" }),
    classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "trusted" }),
  });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, mitm: { caDir, insecureUpstream: true } });
  const port = await proxy.listen(0);
  try {
    const tls = await openTunnel(port, dest, dest.caCertPem);

    // Request #1: benign → delivered, kept alive.
    const r1 = await sendOnTls(tls, clRequest(dest.host, "/collect", "hello=world", "keep-alive"));
    assert.equal(r1.status, 200, "the first (benign) request must be delivered (200)");
    assert.equal(r1.body, "dest-says-hello", "the first request's upstream response must come back");
    assert.equal(dest.received.length, 1, "the dest must have received exactly the first (benign) request");
    assert.equal(dest.received[0]!.body, "hello=world");

    // Request #2 on the SAME socket: a symbol → untrusted dest → BLOCKED.
    const r2 = await sendOnTls(tls, clRequest(dest.host, "/collect", `leak=${SYM}`, "close"));
    assert.equal(r2.status, 403, "the second request (symbol → untrusted dest) must be BLOCKED (403)");
    assert.equal(r2.body.includes("super-secret-token"), false, "the secret must not leak in the 403 body");
    assert.equal(dest.received.length, 1, "the dest must STILL only have the first request (the 2nd was blocked)");

    tls.destroy();
  } finally {
    await proxy.close();
    dest.server.close();
  }
});

test("(6) MITM chunked: a SYMBOL in a chunked HTTPS body → BLOCKED (403), dest received NOTHING", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  // The previously-bypassing case: a chunked request body carrying a symbol used to
  // be treated as EMPTY (gate saw no symbol → forwarded). Now the chunked body is
  // decoded + gated → BLOCKED, and the upstream dest receives NOTHING.
  const caDir = freshCaDir();
  const dest = await startHttpsDest(caDir, "127.0.0.1");
  const arbiter = new MockArbiter({
    values: { [SYM]: "super-secret-token" },
    decisionFn: () => ({ allow: false, requiresApproval: true, reason: "untrusted destination" }),
  });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, mitm: { caDir, insecureUpstream: true } });
  const port = await proxy.listen(0);
  try {
    const tls = await openTunnel(port, dest, dest.caCertPem);
    // Split the symbol-bearing payload across multiple wire chunks.
    const res = await sendOnTls(tls, chunkedRequest(dest.host, "/collect", ["leak=", SYM, "&tail=1"], "close"));
    assert.equal(res.status, 403, "a symbol in a CHUNKED body must now be BLOCKED (403) — was bypassing");
    assert.equal(res.body.includes("super-secret-token"), false, "the secret must not leak in the 403 body");
    assert.equal(dest.received.length, 0, "the dest must have received NOTHING (proves the chunked body was decoded + gated)");
    assert.equal(arbiter.decisionCalls.length >= 1, true, "the gate must have seen the symbol from the decoded chunked body");
    tls.destroy();
  } finally {
    await proxy.close();
    dest.server.close();
  }
});

test("(7) MITM chunked: a BENIGN chunked body → delivered + reassembled intact upstream", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  // A benign (symbol-free) chunked body must be decoded, reassembled, and forwarded
  // with a valid Content-Length (the dest sees the full concatenated payload).
  const caDir = freshCaDir();
  const dest = await startHttpsDest(caDir, "127.0.0.1");
  const arbiter = new MockArbiter({
    classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "trusted" }),
  });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, mitm: { caDir, insecureUpstream: true } });
  const port = await proxy.listen(0);
  try {
    const tls = await openTunnel(port, dest, dest.caCertPem);
    const parts = ["field1=alpha", "&field2=beta", "&field3=gamma"];
    const res = await sendOnTls(tls, chunkedRequest(dest.host, "/collect", parts, "close"));
    assert.equal(res.status, 200, "a benign chunked body must pass the gate (200)");
    assert.equal(res.body, "dest-says-hello", "the upstream response must return to the client");
    assert.equal(dest.received.length, 1, "the dest must have received the (decoded) chunked request");
    assert.equal(dest.received[0]!.body, parts.join(""), "the dest must receive the chunks REASSEMBLED in order, intact");
    tls.destroy();
  } finally {
    await proxy.close();
    dest.server.close();
  }
});

test("(8) MITM: a client that does not trust the session CA refuses the handshake, and the trace says so (tls_rejected)", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  const caDir = freshCaDir();
  const dest = await startHttpsDest(caDir, "127.0.0.1");
  const arbiter = new MockArbiter();
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, mitm: { caDir, insecureUpstream: true, handshakeTimeoutMs: 300 } });
  const port = await proxy.listen(0);
  // A client pinned to ANOTHER authority (a kubeconfig's cluster CA, Java's
  // own store): the session CA's leaf is not trusted.
  const otherCa = ensureCa(freshCaDir());
  try {
    // Like a real tool: the certificate check fails, the program closes the
    // socket (and exits).
    const err = await new Promise<Error>((resolve) => {
      const raw = netConnect(port, "127.0.0.1", () => {
        raw.write(`CONNECT 127.0.0.1:${dest.port} HTTP/1.1\r\nHost: 127.0.0.1:${dest.port}\r\n\r\n`);
      });
      raw.once("data", () => {
        const t = tlsConnect({ socket: raw, servername: "127.0.0.1", ca: readFileSync(otherCa.certPath, "utf8") });
        t.on("error", (e) => { t.destroy(); raw.destroy(); resolve(e); });
        t.on("secureConnect", () => { t.destroy(); resolve(new Error("unexpectedly trusted")); });
      });
    });
    assert.match(err.message, /self[- ]signed|unable to verify|unknown/i, "the client refused the session CA's leaf");
    // The server side sees the close a moment after the client gives up.
    let ev: { action?: string; destination?: string; reason?: string } | undefined;
    for (let n = 0; n < 50 && !ev; n++) {
      await new Promise((r) => setTimeout(r, 20));
      ev = (arbiter.emittedEvents as Array<{ action?: string; destination?: string; reason?: string }>).find((e) => e.action === "tls_rejected");
    }
    assert.ok(ev, "a refused inspection certificate is on the trace");
    assert.equal(ev!.destination, `127.0.0.1:${dest.port}`);
    assert.match(ev!.reason!, /did not complete.*does not trust the session CA/);
    assert.equal(dest.received.length, 0, "nothing was forwarded");
  } finally {
    await proxy.close();
    dest.server.close();
  }
});

// ── a mock-sites host route under MITM (the replay runner's catch-all) ────────

/** An HTTPS listener on loopback whose leaf, for `name`, is signed by its OWN
 *  CA (not the session CA): the route's `tls_ca`. */
async function startRoutedDest(name: string) {
  const routeCaDir = freshCaDir();
  const ca = ensureCa(routeCaDir);
  const leaf = leafForHost(ca, name);
  const received: DestRecord[] = [];
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      received.push({ method: req.method ?? "", url: `${req.headers.host ?? ""}${req.url ?? ""}`, body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("routed-dest-says-hello");
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { server, received, port: (server.address() as AddressInfo).port, caPath: ca.certPath };
}

test("MITM + a host route: the gated request is re-originated to the loopback listener over TLS verified against tls_ca", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  const { MockSites } = await import("../../src/mock-sites.js");
  const dest = await startRoutedDest("httpbin.org");
  const caDir = freshCaDir();
  const arbiter = new MockArbiter({ classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "trusted" }) });
  const mockSites = MockSites.fromYaml(`hosts:\n  - host: "httpbin.org"\n    tls_to: "127.0.0.1:${dest.port}"\n    tls_ca: ${JSON.stringify(dest.caPath)}\n`);
  // NOT insecureUpstream: the route's own CA is what makes the dial verify.
  const proxy = new NetProxy({ arbiter, mockSites, mitm: { caDir }, log: noop });
  const port = await proxy.listen(0);
  try {
    const res = await httpsThroughProxy(port, { host: "httpbin.org", port: 443 }, readFileSync(join(caDir, "mandu-egress-ca.pem"), "utf8"), "hello=1");
    assert.equal(res.status, 200);
    assert.equal(res.body, "routed-dest-says-hello");
    assert.deepEqual(dest.received.map((r) => [r.method, r.url, r.body]), [["POST", "httpbin.org/collect", "hello=1"]], "the listener received the request, Host kept");
    await new Promise((r) => setTimeout(r, 20));
    const ev = arbiter.emittedEvents.find((e) => (e as { action?: string }).action === "forwarded") as Record<string, unknown> | undefined;
    assert.equal(ev?.["mockRoute"], `127.0.0.1:${dest.port}`);
  } finally {
    await proxy.close();
    dest.server.close();
  }
});

test("MITM + a host route without tls_ca: the listener's certificate is not trusted, the request fails closed (502), nothing is read", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  const { MockSites } = await import("../../src/mock-sites.js");
  const dest = await startRoutedDest("httpbin.org");
  const caDir = freshCaDir();
  const arbiter = new MockArbiter({ classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "trusted" }) });
  const mockSites = MockSites.fromYaml(`hosts:\n  - host: "httpbin.org"\n    tls_to: "127.0.0.1:${dest.port}"\n`);
  const proxy = new NetProxy({ arbiter, mockSites, mitm: { caDir }, log: noop });
  const port = await proxy.listen(0);
  try {
    const res = await httpsThroughProxy(port, { host: "httpbin.org", port: 443 }, readFileSync(join(caDir, "mandu-egress-ca.pem"), "utf8"), "hello=1");
    assert.equal(res.status, 502);
    assert.equal(dest.received.length, 0, "an unverified listener is never sent the request");
  } finally {
    await proxy.close();
    dest.server.close();
  }
});

test("(9) MITM: a leaf names its issuer by key id (authorityKeyIdentifier = the session CA's subjectKeyIdentifier), whatever the openssl version's defaults", { skip: !OPENSSL && "openssl unavailable" }, () => {
  const ca = ensureCa(freshCaDir());
  const leaf = leafForHost(ca, "127.0.0.1");
  const dir = tmpDir("mdu-mitm-akid-");
  const leafPath = join(dir, "leaf.pem");
  writeFileSync(leafPath, leaf.certPem);
  // `openssl x509 -ext` prints the extension's hex; the CLI is the one ca.ts minted with.
  const ext = (path: string, name: string): string =>
    execFileSync("openssl", ["x509", "-in", path, "-noout", "-ext", name], { encoding: "utf8" }).split("\n").slice(1).join("").replace(/keyid:/i, "").trim();
  const caSkid = ext(ca.certPath, "subjectKeyIdentifier");
  const leafAkid = ext(leafPath, "authorityKeyIdentifier");
  assert.match(caSkid, /^[0-9A-F]{2}(:[0-9A-F]{2})+$/, "the CA carries a subjectKeyIdentifier");
  assert.equal(leafAkid, caSkid, "the leaf names that key as its issuer");
  assert.match(ext(leafPath, "subjectKeyIdentifier"), /^[0-9A-F]{2}(:[0-9A-F]{2})+$/, "the leaf carries its own key id");
});

test("(10) MITM: Send without it — the decrypted form body goes with the marker (percent-encoded), never the value; a failed strict scan blocks", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  // confidentiality.md §4 "Send without it": the decision carries `strip`.
  const strip = { allow: false as const, requiresApproval: false, strip: true as const, reason: "the user chose Send without it" };
  const caDir = freshCaDir();
  const dest = await startHttpsDest(caDir, "127.0.0.1");
  const arbiter = new MockArbiter({ values: { [SYM]: "super-secret-token" }, decisionFn: () => strip, classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "trusted" }) });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, mitm: { caDir, insecureUpstream: true } });
  const port = await proxy.listen(0);
  try {
    const res = await httpsThroughProxy(port, dest, dest.caCertPem, `title=crash&body=pw%3D${SYM}`);
    assert.equal(res.status, 200, res.body);
    assert.equal(dest.received.length, 1);
    const got = dest.received[0]!.body;
    assert.ok(!got.includes("super-secret-token") && !got.includes("$MDU:"), got);
    assert.equal(new URLSearchParams(got).get("body"), "pw=[hidden by Mandu]");
    assert.equal(arbiter.fingerprintCalls.length, 1, "the strict scan ran over the decrypted request");
  } finally {
    await proxy.close();
    dest.server.close();
  }

  const dest2 = await startHttpsDest(caDir, "127.0.0.1");
  const failing = new MockArbiter({ values: { [SYM]: "super-secret-token" }, decisionFn: () => strip, failFingerprint: true });
  const proxy2 = new NetProxy({ allowThisMachine: true, arbiter: failing, log: noop, mitm: { caDir, insecureUpstream: true } });
  const port2 = await proxy2.listen(0);
  try {
    const res = await httpsThroughProxy(port2, dest2, dest2.caCertPem, `body=${SYM}`);
    assert.equal(res.status, 403, "a scan that cannot run: not sent");
    assert.equal(dest2.received.length, 0);
  } finally {
    await proxy2.close();
    dest2.server.close();
  }
});

test("(11) MITM: a held request (MANDU_EGRESS_HOLD_MS) waits for the card, then goes with the marker; nobody answering refuses it", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  // confidentiality.md §4 "A held request": pending until the human answers
  // Send without it, then THIS decrypted request is decided by that answer.
  const strip = { allow: false as const, requiresApproval: false, strip: true as const, reason: "the user chose Send without it" };
  const pending = { allow: false as const, requiresApproval: true, reason: "secret unbound", approvalId: "egr-7", ruleRef: { source: "rule" as const, id: "egress:secret-unbound" } };
  let answered = false;
  const caDir = freshCaDir();
  const dest = await startHttpsDest(caDir, "127.0.0.1");
  const arbiter = new MockArbiter({ values: { [SYM]: "super-secret-token" }, decisionFn: () => (answered ? strip : pending), classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "trusted" }) });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, mitm: { caDir, insecureUpstream: true }, egressHoldMs: 4_000 });
  const port = await proxy.listen(0);
  try {
    const flip = setTimeout(() => { answered = true; }, 700);
    const res = await httpsThroughProxy(port, dest, dest.caCertPem, `title=crash&body=pw%3D${SYM}`);
    clearTimeout(flip);
    assert.equal(res.status, 200, res.body);
    assert.equal(dest.received.length, 1, "the held request itself went, once");
    const got = dest.received[0]!.body;
    assert.ok(!got.includes("super-secret-token") && !got.includes("$MDU:"), got);
    assert.equal(new URLSearchParams(got).get("body"), "pw=[hidden by Mandu]");
    assert.ok(arbiter.decisionCalls.length >= 2, "asked again while held");
    const fwd = arbiter.emittedEvents.find((e) => (e as { action?: string }).action === "forwarded") as { heldMs?: number; heldFor?: unknown } | undefined;
    assert.ok(fwd && typeof fwd.heldMs === "number" && fwd.heldMs >= 500, "the trace says how long it was held");
    assert.deepEqual(fwd.heldFor, [{ approvalId: "egr-7", rule: "egress:secret-unbound" }], "and which card it waited on, filed by which rule");
  } finally {
    await proxy.close();
    dest.server.close();
  }

  const dest2 = await startHttpsDest(caDir, "127.0.0.1");
  const never = new MockArbiter({ values: { [SYM]: "super-secret-token" }, decisionFn: () => pending });
  const proxy2 = new NetProxy({ allowThisMachine: true, arbiter: never, log: noop, mitm: { caDir, insecureUpstream: true }, egressHoldMs: 1_200 });
  const port2 = await proxy2.listen(0);
  try {
    const res = await httpsThroughProxy(port2, dest2, dest2.caCertPem, `body=${SYM}`);
    assert.equal(res.status, 403, "nobody answered: refused");
    assert.match(res.body, /nobody answered/);
    assert.ok(!res.body.includes("super-secret-token"));
    assert.equal(dest2.received.length, 0);
    const blocked = never.emittedEvents.find((e) => (e as { action?: string }).action === "blocked") as { heldMs?: number; heldFor?: unknown } | undefined;
    assert.deepEqual(blocked?.heldFor, [{ approvalId: "egr-7", rule: "egress:secret-unbound" }], "the refused held request names its card too");
    assert.ok(!res.body.includes("egr-7"), "the agent's 403 never carries the card's id");
  } finally {
    await proxy2.close();
    dest2.server.close();
  }
});

test("(12) MITM: the chain served is the leaf and the session CA, so a client pinning the CA's key (Chrome under `mandu --browser`) finds it", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  const caDir = freshCaDir();
  const proxy = new NetProxy({ allowThisMachine: true, arbiter: new MockArbiter(), log: noop, mitm: { caDir, insecureUpstream: true } });
  const port = await proxy.listen(0);
  const ca = new X509Certificate(readFileSync(join(caDir, "mandu-egress-ca.pem")));
  try {
    // Trusting nothing: what the client learns is only what the proxy sent.
    const sent = await new Promise<DetailedPeerCertificate>((resolve, reject) => {
      const raw = netConnect(port, "127.0.0.1", () => raw.write("CONNECT site.example:443 HTTP/1.1\r\nHost: site.example:443\r\n\r\n"));
      raw.once("data", () => {
        const tls = tlsConnect({ socket: raw, servername: "site.example", rejectUnauthorized: false }, () => {
          resolve(tls.getPeerCertificate(true));
          tls.destroy();
        });
        tls.on("error", reject);
      });
      raw.on("error", reject);
    });
    assert.match(sent.subjectaltname ?? "", /DNS:site\.example/, "the leaf names the host");
    assert.ok(sent.issuerCertificate, "a second certificate was sent");
    assert.equal(sent.issuerCertificate.fingerprint256, ca.fingerprint256, "the second is the session CA");
  } finally {
    await proxy.close();
  }
});
