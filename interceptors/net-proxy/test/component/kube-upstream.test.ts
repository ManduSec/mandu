/**
 * kube-upstream — the TLS-inspected leg dials a Kubernetes cluster as kubectl
 * would (docs/design/confidentiality/kube-wire-release.md): the cluster's own
 * CA as the only trust anchor, and the real client certificate for a request
 * with no Authorization header, from the arbiter's `kubeUpstream` answer.
 *
 * A real NetProxy (TLS inspection on) over a MockArbiter that answers the
 * profile; the cluster is a loopback HTTPS listener with its own CA that
 * asks for (never requires) a client certificate and records it. The route
 * names no CA: only the profile's CA can verify the listener.
 *
 *   1. no Authorization: the profile's client certificate is presented;
 *   2. the next request on the same connection with an Authorization header:
 *      a fresh upstream dial with no client certificate (the pool keeps the
 *      two apart);
 *   3. a host with no profile, routed to the same listener: the system
 *      store refuses it (502), so the CA above was the profile's;
 *   4. an arbiter that cannot answer: 502 and nothing reaches the cluster.
 *
 * Mandu-new (no reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { connect as netConnect, type AddressInfo } from "node:net";
import { X509Certificate } from "node:crypto";
import { once } from "node:events";
import { join } from "node:path";

import { NetProxy } from "../../src/proxy.js";
import { MockArbiter } from "../../src/arbiter-client.js";
import { MockSites } from "../../src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";
import { removeDir, tmpDir } from "../tmp-dir.js";

const OPENSSL = opensslAvailable();

/** Send `requests` over ONE CONNECT + TLS connection (keep-alive), reading
 *  each response; the statuses. */
function overOneConnection(proxyPort: number, target: string, sessionCa: string, requests: Array<Record<string, string>>): Promise<number[]> {
  return new Promise((resolve, reject) => {
    const raw = netConnect(proxyPort, "127.0.0.1", () => raw.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let head = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      head = Buffer.concat([head, chunk]);
      if (head.indexOf("\r\n\r\n") === -1) return;
      raw.off("data", onData);
      const tls = tlsConnect({ socket: raw, ca: sessionCa, servername: target.replace(/:\d+$/, "") });
      const statuses: number[] = [];
      let buf = "";
      const send = (i: number): void => {
        const last = i === requests.length - 1;
        const h = Object.entries(requests[i]!).map(([k, v]) => `${k}: ${v}\r\n`).join("");
        tls.write(`GET /api HTTP/1.1\r\nHost: ${target}\r\n${h}${last ? "Connection: close\r\n" : ""}\r\n`);
      };
      tls.on("secureConnect", () => send(0));
      tls.on("data", (d: Buffer) => {
        buf += d.toString("latin1");
        for (;;) {
          const end = buf.indexOf("\r\n\r\n");
          if (end === -1) return;
          const m = /content-length: (\d+)/i.exec(buf.slice(0, end));
          const len = Number(m?.[1] ?? "0");
          if (buf.length < end + 4 + len) return;
          statuses.push(Number(/^HTTP\/1\.1 (\d{3})/.exec(buf)?.[1] ?? 0));
          buf = buf.slice(end + 4 + len);
          if (statuses.length === requests.length) { tls.end(); resolve(statuses); return; }
          send(statuses.length);
        }
      });
      tls.on("error", reject);
    };
    raw.on("data", onData);
    raw.on("error", reject);
    setTimeout(() => reject(new Error("timed out")), 8000).unref();
  });
}

test("a cluster is dialed with its own CA, and its client certificate only for a request without Authorization; no profile or no answer fails closed", { skip: !OPENSSL && "openssl unavailable" }, async () => {
  const dir = tmpDir("mandu-kube-upstream-");
  const clusterCa = ensureCa(join(dir, "cluster-ca"));
  const client = leafForHost(ensureCa(join(dir, "client-ca")), "kube-admin");
  const clientFp = new X509Certificate(client.certPem).fingerprint256;
  const seen: Array<{ host: string | undefined; peer: string | null; tlsSession: number; auth: string | undefined }> = [];
  const sessions = new WeakMap<object, number>();
  let nextSession = 0;
  const leaf = leafForHost(clusterCa, "k8s.test");
  const cluster = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem, requestCert: true, rejectUnauthorized: false }, (req, res) => {
    const sock = req.socket as TLSSocket;
    if (!sessions.has(sock)) sessions.set(sock, nextSession++);
    const peer = sock.getPeerCertificate();
    seen.push({ host: req.headers.host, peer: peer && peer.raw ? new X509Certificate(peer.raw).fingerprint256 : null, tlsSession: sessions.get(sock)!, auth: req.headers.authorization });
    res.writeHead(200, { "content-type": "application/json", "content-length": "2" });
    res.end("{}");
  });
  cluster.listen(0, "127.0.0.1");
  await once(cluster, "listening");
  const port = (cluster.address() as AddressInfo).port;
  const sites = MockSites.fromYaml(["hosts:", `  - host: "k8s.test"`, `    tls_to: 127.0.0.1:${port}`, `  - host: "noprofile.test"`, `    tls_to: 127.0.0.1:${port}`, ""].join("\n"));
  const profile = { ca: clusterCa.certPem, insecure: false, client: { cert: client.certPem, key: client.keyPem } };

  const run = async (opts: { fail?: boolean }) => {
    const arbiter = new MockArbiter({ kubeUpstream: { "k8s.test:6443": profile }, ...(opts.fail ? { failKubeUpstream: true } : {}) });
    const caDir = join(dir, `mitm-${opts.fail ? "fail" : "ok"}`);
    const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: () => {}, mockSites: sites, mitm: { caDir }, attributeHolders: () => [{ procKey: "9-1", ancestors: [] }] });
    const proxyPort = await proxy.listen(0);
    return { proxy, proxyPort, arbiter, sessionCa: proxy.mitmCaCertPath! };
  };

  try {
    const ok = await run({});
    const sessionCa = (await import("node:fs")).readFileSync(ok.sessionCa, "utf8");
    // 1 + 2: one client connection, two requests.
    assert.deepEqual(await overOneConnection(ok.proxyPort, "k8s.test:6443", sessionCa, [{}, { Authorization: "Bearer someone" }]), [200, 200]);
    assert.equal(seen.length, 2);
    assert.equal(seen[0]!.peer, clientFp, "no Authorization: the real client certificate");
    assert.equal(seen[1]!.peer, null, "with Authorization: none");
    assert.equal(seen[1]!.auth, "Bearer someone");
    assert.notEqual(seen[0]!.tlsSession, seen[1]!.tlsSession, "the pool dialed the second request anew");
    assert.deepEqual(ok.arbiter.kubeUpstreamCalls.slice(0, 1), ["k8s.test:6443"], "asked by the stated destination");
    // 3: no profile, the same listener: the system store refuses its CA.
    assert.deepEqual(await overOneConnection(ok.proxyPort, "noprofile.test:6443", sessionCa, [{}]), [502]);
    assert.equal(seen.length, 2, "nothing reached the cluster");
    await ok.proxy.close();

    // 4: the arbiter cannot answer: 502, nothing sent.
    const bad = await run({ fail: true });
    const badCa = (await import("node:fs")).readFileSync(bad.sessionCa, "utf8");
    assert.deepEqual(await overOneConnection(bad.proxyPort, "k8s.test:6443", badCa, [{}]), [502]);
    assert.equal(seen.length, 2, "nothing reached the cluster");
    await bad.proxy.close();
  } finally {
    cluster.close();
    removeDir(dir);
  }
});
