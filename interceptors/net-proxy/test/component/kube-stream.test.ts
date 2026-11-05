/**
 * kube-stream — a Kubernetes cluster's upgrades and streams on the
 * TLS-inspected leg (docs/design/confidentiality/kube-wire-release.md §4.1):
 * an upgrade (`kubectl exec`, `attach`, `port-forward`: SPDY/3.1 or
 * WebSocket) is relayed both ways after its 101, each client chunk judged
 * first; a watch or `logs -f` response is relayed as it comes.
 *
 * A real NetProxy (TLS inspection on) over a MockArbiter that answers the
 * cluster's profile; the cluster is a loopback HTTPS listener with its own
 * CA that answers an upgrade with 101 and echoes, and a watch with a chunked
 * body it writes one event at a time.
 *
 *   1. an upgrade: 101 reaches the client, the cluster's greeting and the
 *      echo of each client chunk come back, the cluster saw the client
 *      certificate on the upgrade request;
 *   2. a holder that holds a secret by the next chunk: that chunk never
 *      reaches the cluster, and the stream is closed (the blind tunnel's
 *      per-chunk rule);
 *   2b. a chunk holding a registered secret verbatim (the tripwire): never
 *      sent, the stream closed;
 *   3. a watch: the first event reaches the client while the cluster still
 *      holds the second (streamed, not buffered), then the rest and the end;
 *
 * Mandu-new (no reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { connect as netConnect, type AddressInfo, type Socket } from "node:net";
import { X509Certificate } from "node:crypto";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { NetProxy } from "../../src/proxy.js";
import { MockArbiter, type TaintedProcessBindings } from "../../src/arbiter-client.js";
import { MockSites } from "../../src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";
import { removeDir, tmpDir } from "../tmp-dir.js";

const OPENSSL = opensslAvailable();

/** CONNECT + TLS (trusting the session CA) to `target`; the TLS socket. */
function tunnel(proxyPort: number, target: string, sessionCa: string): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const raw = netConnect(proxyPort, "127.0.0.1", () => raw.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let head = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      head = Buffer.concat([head, chunk]);
      if (head.indexOf("\r\n\r\n") === -1) return;
      raw.off("data", onData);
      const tls = tlsConnect({ socket: raw, ca: sessionCa, servername: target.replace(/:\d+$/, "") }, () => resolve(tls));
      tls.on("error", reject);
    };
    raw.on("data", onData);
    raw.on("error", reject);
  });
}

/** Collect a socket's bytes; `until(text)` resolves once they contain it. */
function collector(sock: TLSSocket) {
  let text = "";
  const waits: Array<{ needle: string; resolve: () => void }> = [];
  sock.on("data", (d: Buffer) => {
    text += d.toString("latin1");
    for (const w of [...waits]) if (text.includes(w.needle)) { waits.splice(waits.indexOf(w), 1); w.resolve(); }
  });
  const closed = new Promise<void>((resolve) => sock.once("close", () => resolve()));
  return {
    get text() { return text; },
    closed,
    until: (needle: string, ms = 5000): Promise<void> => text.includes(needle) ? Promise.resolve() : new Promise((resolve, reject) => {
      waits.push({ needle, resolve });
      setTimeout(() => reject(new Error(`timed out waiting for ${JSON.stringify(needle)} in ${JSON.stringify(text)}`)), ms).unref();
    }),
  };
}

test("a cluster's upgrade is relayed both ways with each client chunk judged, and a watch streams as it comes", { skip: !OPENSSL && "openssl unavailable", timeout: 60_000 }, async () => {
  const dir = tmpDir("mandu-kube-stream-");
  const clusterCa = ensureCa(join(dir, "cluster-ca"));
  const client = leafForHost(ensureCa(join(dir, "client-ca")), "kube-admin");
  const clientFp = new X509Certificate(client.certPem).fingerprint256;
  const leaf = leafForHost(clusterCa, "k8s.test");
  const upgrades: Array<{ protocol: string | undefined; peer: string | null }> = [];
  const received: string[] = [];
  let releaseSecond: (() => void) | undefined;
  const cluster = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem, requestCert: true, rejectUnauthorized: false }, (req, res) => {
    if (/watch=true/.test(req.url ?? "")) {
      res.writeHead(200, { "content-type": "application/json", "transfer-encoding": "chunked" });
      res.write('{"type":"ADDED","object":{"name":"pod-1"}}\n');
      releaseSecond = () => { res.write('{"type":"MODIFIED","object":{"name":"pod-1"}}\n'); res.end(); };
      return;
    }
    res.writeHead(200, { "content-type": "application/json", "content-length": "2" });
    res.end("{}");
  });
  cluster.on("upgrade", (req, socket: Socket) => {
    const peer = (socket as TLSSocket).getPeerCertificate();
    upgrades.push({ protocol: req.headers.upgrade, peer: peer && peer.raw ? new X509Certificate(peer.raw).fingerprint256 : null });
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: ${req.headers.upgrade}\r\nX-Stream-Protocol-Version: v4.channel.k8s.io\r\n\r\n`);
    socket.write("greeting\n");
    socket.on("data", (d: Buffer) => { received.push(d.toString("utf8")); socket.write(`echo:${d.toString("utf8")}`); });
  });
  cluster.listen(0, "127.0.0.1");
  await once(cluster, "listening");
  const port = (cluster.address() as AddressInfo).port;
  const sites = MockSites.fromYaml(["hosts:", `  - host: "k8s.test"`, `    tls_to: 127.0.0.1:${port}`, ""].join("\n"));
  const taint: Record<string, TaintedProcessBindings> = {};
  const arbiter = new MockArbiter({
    secretTaint: taint,
    fingerprintSecrets: [{ symbol: "$MDU:nomodel_Read[ab12].STRIPE_KEY", value: "sk_live_STREAMTRIP_9d2f", level: "no-model", bindings: ["api.stripe.com"] }],
    kubeUpstream: { "k8s.test:6443": { ca: clusterCa.certPem, insecure: false, client: { cert: client.certPem, key: client.keyPem } } },
  });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: () => {}, mockSites: sites, mitm: { caDir: join(dir, "mitm") }, attributeHolders: () => [{ procKey: "9-1", ancestors: [] }] });
  const proxyPort = await proxy.listen(0);
  const sessionCa = readFileSync(proxy.mitmCaCertPath!, "utf8");
  try {
    // 1. An upgrade, relayed both ways.
    for (const protocol of ["SPDY/3.1", "websocket"]) {
      const tls = await tunnel(proxyPort, "k8s.test:6443", sessionCa);
      const got = collector(tls);
      tls.write(`POST /api/v1/namespaces/default/pods/p/exec?command=sh&stdin=true HTTP/1.1\r\nHost: k8s.test:6443\r\nConnection: Upgrade\r\nUpgrade: ${protocol}\r\nX-Stream-Protocol-Version: v4.channel.k8s.io\r\n\r\n`);
      await got.until("greeting\n");
      assert.match(got.text, /^HTTP\/1\.1 101 /);
      tls.write("ls\n");
      await got.until("echo:ls\n");
      tls.write("pwd\n");
      await got.until("echo:pwd\n");
      tls.end();
      await got.closed;
    }
    assert.deepEqual(upgrades, [{ protocol: "SPDY/3.1", peer: clientFp }, { protocol: "websocket", peer: clientFp }]);
    assert.deepEqual(received, ["ls\n", "pwd\n", "ls\n", "pwd\n"]);

    // 2. The holder reads a secret mid-stream: its next chunk never leaves.
    const tls = await tunnel(proxyPort, "k8s.test:6443", sessionCa);
    const got = collector(tls);
    tls.write("GET /api/v1/namespaces/default/pods/p/attach?stdin=true HTTP/1.1\r\nHost: k8s.test:6443\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
    await got.until("greeting\n");
    tls.write("before\n");
    await got.until("echo:before\n");
    taint["9-1"] = { tainted: true, level: "no-model", files: ["/home/u/.env"], bindings: [] };
    tls.write("after\n");
    await got.closed;
    assert.ok(!received.includes("after\n"), "the chunk after the taint never reached the cluster");
    assert.equal(upgrades.length, 3);
    delete taint["9-1"];

    // 2b. A raw secret in a chunk (the verbatim tripwire): never sent.
    const t = await tunnel(proxyPort, "k8s.test:6443", sessionCa);
    const tripped = collector(t);
    t.write("GET /api/v1/namespaces/default/pods/p/exec?stdin=true HTTP/1.1\r\nHost: k8s.test:6443\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n");
    await tripped.until("greeting\n");
    t.write("echo sk_live_STREAMTRIP_9d2f\n");
    await tripped.closed;
    assert.ok(!received.some((r) => r.includes("sk_live_STREAMTRIP_9d2f")), "the secret never reached the cluster");

    // 3. A watch: the first event arrives while the cluster holds the second.
    const w = await tunnel(proxyPort, "k8s.test:6443", sessionCa);
    const events = collector(w);
    w.write("GET /api/v1/namespaces/default/pods?watch=true HTTP/1.1\r\nHost: k8s.test:6443\r\n\r\n");
    await events.until('"ADDED"');
    assert.ok(!events.text.includes("MODIFIED"));
    assert.match(events.text, /^HTTP\/1\.1 200 [\s\S]*\r\nconnection: close\r\n/i);
    releaseSecond!();
    await events.until('"MODIFIED"');
    await events.closed;
    assert.match(events.text, /0\r\n\r\n$/, "the chunked body's end reached the client");

  } finally {
    await proxy.close();
    cluster.close();
    removeDir(dir);
  }
});
