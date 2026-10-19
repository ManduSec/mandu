/**
 * plain-http-tunnel.test — a CONNECT tunnel that carries PLAIN HTTP, with TLS
 * inspection on (src/proxy.ts `sniffTunnel` / `servePlainTunnel`, 2026-10-09).
 *
 * A client that tunnels an http:// URL sends `CONNECT host:80` and then a
 * plain request (OpenClaw's guarded fetch through an env proxy does, measured
 * on 2026.7.1-2 and 2026.9.9). TLS termination used to fail on it, so the
 * fetch failed under Mandu. The proxy now reads the first byte: a TLS
 * handshake record (0x16) goes to the MITM leg as before; anything else is
 * served by the plaintext leg, under the same gate:
 *   (1) a benign request is forwarded and answered;
 *   (2) a raw secret value in the URL is refused by the verbatim tripwire, the
 *       destination receives nothing;
 *   (3) a symbol bound for an untrusted host is refused by the per-symbol gate;
 *   (4) TLS in a tunnel still goes to the MITM leg (the TLS suites cover it in
 *       depth; here: a handshake through the same proxy succeeds).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import { connect as netConnect, type AddressInfo } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { createServer as createHttpsServer } from "node:https";
import { once } from "node:events";

import { NetProxy, type HttpForwarder } from "../../src/proxy.js";
import { MockArbiter } from "../../src/arbiter-client.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";
import { tmpDir } from "../tmp-dir.js";

const OPENSSL = opensslAvailable();
const SECRET_VALUE = "plain-tunnel-secret-VALUE-7731";
const SECRET_SYMBOL = "$MDU:nomodel_Env[77aa].PARTNER_API_KEY";
const SYM = "$MDU:web_fetch[c0de]";
const noop = (): void => {};

async function startDest() {
  const received: string[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push(`${req.method} ${req.url} ${body}`);
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("dest-ok");
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

/** CONNECT to `target`, then send one plain HTTP request in the tunnel (origin form). */
function plainThroughTunnel(proxyPort: number, target: string, path: string): Promise<{ connect: string; status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const raw = netConnect(proxyPort, "127.0.0.1", () => {
      raw.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
    });
    let buf = "";
    let connectLine = "";
    raw.on("data", (c: Buffer) => {
      buf += c.toString("latin1");
      if (!connectLine) {
        const i = buf.indexOf("\r\n\r\n");
        if (i === -1) return;
        connectLine = buf.split("\r\n")[0]!;
        buf = buf.slice(i + 4);
        if (!/ 200 /.test(connectLine)) { resolve({ connect: connectLine, status: 0, body: "" }); raw.destroy(); return; }
        raw.write(`GET ${path} HTTP/1.1\r\nHost: ${target}\r\nConnection: close\r\n\r\n`);
      }
    });
    raw.on("end", () => {
      const sep = buf.indexOf("\r\n\r\n");
      const m = /^HTTP\/1\.1 (\d{3})/.exec(buf);
      resolve({ connect: connectLine, status: m ? Number(m[1]) : 0, body: sep === -1 ? "" : buf.slice(sep + 4) });
    });
    raw.on("error", reject);
    setTimeout(() => reject(new Error("plainThroughTunnel timed out")), 5000).unref();
  });
}

test("a plain-HTTP CONNECT tunnel under TLS inspection: served by the plaintext leg, benign forwarded, raw secret and untrusted symbol refused", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  const dest = await startDest();
  const arbiter = new MockArbiter({
    values: { [SYM]: "super-secret-token" },
    decisionFn: () => ({ allow: false, requiresApproval: true, reason: "untrusted destination" }),
    fingerprintSecrets: [{ symbol: SECRET_SYMBOL, value: SECRET_VALUE, level: "no-model", bindings: ["api.partner.example"] }],
  });
  const caDir = tmpDir("mandu-plain-tunnel-");
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, forwarder: realForwarder(), log: noop, mitm: { caDir, insecureUpstream: true } });
  const port = await proxy.listen(0);
  try {
    // (1) benign: forwarded through the plaintext leg
    const ok = await plainThroughTunnel(port, dest.host, "/page?probe=benign");
    assert.match(ok.connect, / 200 /);
    assert.equal(ok.status, 200, JSON.stringify(ok));
    assert.equal(ok.body, "dest-ok");
    assert.ok(dest.received.some((r) => r.startsWith("GET /page?probe=benign")), JSON.stringify(dest.received));

    // (2) a raw secret value in the URL: the tripwire refuses, nothing reaches the dest
    const before = dest.received.length;
    const leak = await plainThroughTunnel(port, dest.host, `/collect?k=${SECRET_VALUE}`);
    assert.equal(leak.status, 403, JSON.stringify(leak));
    assert.ok(!leak.body.includes(SECRET_VALUE), "the refusal does not echo the value");
    assert.equal(dest.received.length, before, "the destination received nothing");

    // (3) a symbol bound for an untrusted host: the per-symbol gate refuses
    const sym = await plainThroughTunnel(port, dest.host, `/collect?k=${encodeURIComponent(SYM)}`);
    assert.equal(sym.status, 403, JSON.stringify(sym));
    assert.equal(dest.received.length, before, "still nothing");
  } finally {
    await proxy.close();
    dest.server.close();
  }
});

test("TLS in a CONNECT tunnel still goes to the MITM leg (first byte 0x16)", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  const caDir = tmpDir("mandu-plain-tunnel-tls-");
  const ca = ensureCa(caDir);
  const leaf = leafForHost(ca, "127.0.0.1");
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (_req, res) => { res.writeHead(200); res.end("tls-dest-ok"); });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const destPort = (server.address() as AddressInfo).port;
  const arbiter = new MockArbiter({ decisionFn: () => ({ allow: true, reason: "no symbol" }) });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, mitm: { caDir, insecureUpstream: true } });
  const port = await proxy.listen(0);
  try {
    const body = await new Promise<string>((resolve, reject) => {
      const raw = netConnect(port, "127.0.0.1", () => raw.write(`CONNECT 127.0.0.1:${destPort} HTTP/1.1\r\nHost: 127.0.0.1:${destPort}\r\n\r\n`));
      let head = "";
      raw.on("data", function onData(c: Buffer) {
        head += c.toString("latin1");
        if (!head.includes("\r\n\r\n")) return;
        raw.off("data", onData);
        const tls = tlsConnect({ socket: raw, servername: "127.0.0.1", ca: ca.certPem }, () => {
          tls.write(`GET / HTTP/1.1\r\nHost: 127.0.0.1:${destPort}\r\nConnection: close\r\n\r\n`);
        });
        let out = "";
        tls.on("data", (d: Buffer) => (out += d.toString("utf8")));
        tls.on("end", () => resolve(out));
        tls.on("error", reject);
      });
      raw.on("error", reject);
      setTimeout(() => reject(new Error("timed out")), 5000).unref();
    });
    assert.match(body, /^HTTP\/1\.1 200/);
    assert.match(body, /tls-dest-ok/);
  } finally {
    await proxy.close();
    server.close();
  }
});
