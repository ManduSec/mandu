/**
 * kube-wire-release — kubectl, helm and Java through the session proxy with
 * no readers entry (docs/design/confidentiality/kube-wire-release.md), over
 * the REAL components: an ArbiterServer, the launch HOME's `~/.kube/config`
 * registered on the human socket as the launcher does, the launcher's
 * KUBECONFIG overlay (`kubeOverlay` op + `kubeOverlayText`), and the REAL
 * NetProxy (TLS inspection on) in its production wiring (`new
 * ArbiterClientAdapter(new ArbiterClient(data), new ArbiterClient(human))`).
 * The clusters are loopback HTTPS listeners with their own CA (none of them
 * trusted by the system store or by the route: the proxy can reach them only
 * with the kubeconfig's CA), recording what reaches them.
 *
 * The client is kubectl's reading of a KUBECONFIG list (client-go's rules:
 * every file must load, a `*-data` field is strict base64; a named entry is
 * taken whole from the first file that has it; the cluster's CA is the only
 * trust anchor; `proxy-url` is the proxy), plus the real `kubectl` when one
 * is on PATH and a real JVM when `java` is.
 *
 *   1. A bearer-token context: the cluster gets the REAL token; the twin
 *      kubectl read holds only its placeholder.
 *   2. A client-certificate context: the cluster sees the REAL client
 *      certificate, presented by the proxy; the overlay and twin hold no key.
 *   3. A request that carries its own Authorization header gets no client
 *      certificate (it authenticates as that token's user).
 *   4. The token's placeholder to a cluster its contexts do not name (a
 *      decoy in the same file): 403, the decoy sees nothing; in plain HTTP to
 *      its own cluster: refused (https only).
 *   4b. `kubectl exec` (an upgrade: SPDY/3.1 and WebSocket) on both contexts
 *      is relayed both ways with the real credential on its upgrade request
 *      only, and `kubectl get -w` (a watch) streams as the cluster writes.
 *   5. `kubeUpstream` (it returns a key) is refused on the data socket, and
 *      a kubeconfig outside the launch HOME gets no overlay.
 *   6. THE ORACLE: no token, key or certificate byte in the twin, the
 *      overlay, or any request but its own cluster's.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { request as httpRequest } from "node:http";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { connect as netConnect, type AddressInfo } from "node:net";
import { X509Certificate } from "node:crypto";
import { once } from "node:events";
import { execFile, spawnSync } from "node:child_process";
import { promisify } from "node:util";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { kubeconfigDocument } from "../../arbiter/policy/kubeconfig.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { MockSites } from "../../interceptors/net-proxy/src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../interceptors/net-proxy/src/ca.js";
import { kubeOverlayText, mintStandInClientCert } from "../../launcher/src/kube-overlay.js";
import { javaToolOptions, javaTrustStore, pemCertificates } from "../../launcher/src/java-trust.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const OPENSSL = opensslAvailable();
const TOKEN = "kubeTok_KUBEWIRE_canary_7f3a9c";
const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");
// The proxy runs in this process: a child it serves is awaited, never run synchronously.
const run = promisify(execFile);
const onPath = (cmd: string): boolean => spawnSync("sh", ["-c", `command -v ${cmd}`], { stdio: "ignore" }).status === 0;

type Seen = { site: string; authorization: string | undefined; peerCert: string | null; raw: string };

/** A cluster: HTTPS for `name`, its leaf signed by the clusters' own CA,
 *  asking for (never requiring) a client certificate. An upgrade (exec,
 *  attach, port-forward) is answered 101, a greeting, then an echo of each
 *  chunk; a watch writes one event, and the next when `releaseWatch()`. */
async function cluster(name: string, ca: ReturnType<typeof ensureCa>, seen: Seen[]) {
  const leaf = leafForHost(ca, name);
  const peerOf = (sock: unknown): string | null => {
    const peer = (sock as TLSSocket).getPeerCertificate();
    return peer && peer.raw ? new X509Certificate(peer.raw).fingerprint256 : null;
  };
  let release: (() => void) | undefined;
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem, requestCert: true, rejectUnauthorized: false }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      seen.push({
        site: name,
        authorization: req.headers["authorization"],
        peerCert: peerOf(req.socket),
        raw: JSON.stringify(req.headers) + req.url + Buffer.concat(chunks).toString("utf8"),
      });
      if (/[?&]watch=true/.test(req.url ?? "")) {
        res.writeHead(200, { "content-type": "application/json", "transfer-encoding": "chunked" });
        res.write('{"type":"ADDED","object":{"kind":"Pod","metadata":{"name":"web-1"}}}\n');
        release = () => { res.write('{"type":"MODIFIED","object":{"kind":"Pod","metadata":{"name":"web-1"}}}\n'); res.end(); };
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"kind":"NamespaceList","apiVersion":"v1","items":[]}');
    });
  });
  server.on("upgrade", (req, socket) => {
    seen.push({ site: name, authorization: req.headers["authorization"], peerCert: peerOf(socket), raw: JSON.stringify(req.headers) + req.url });
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: ${req.headers["upgrade"]}\r\n\r\ngreeting\n`);
    socket.on("data", (d: Buffer) => socket.write(`echo:${d.toString("utf8")}`));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, close: () => server.close(), releaseWatch: () => release?.() };
}

/** kubectl's connection for a streamed request (exec, a watch): the same
 *  route and trust as `kubectlGet`, the request written, the socket and a
 *  reader of what comes back. */
function kubectlOpen(files: string[], request: (target: string, auth: string) => string, context?: string) {
  const { cluster: c, user: u } = kubectlConfig(files, context);
  const server = new URL(c["server"] as string);
  const proxy = new URL(c["proxy-url"] as string);
  const ca = readFileSync(c["certificate-authority"] as string, "utf8");
  const target = `${server.hostname}:${server.port || "443"}`;
  let text = "";
  const waits: Array<{ needle: string; resolve: () => void }> = [];
  const opened = new Promise<TLSSocket>((resolve, reject) => {
    const raw = netConnect(Number(proxy.port), proxy.hostname, () => raw.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let head = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      head = Buffer.concat([head, chunk]);
      if (head.indexOf("\r\n\r\n") === -1) return;
      raw.off("data", onData);
      const tls = tlsConnect({ socket: raw, ca, servername: server.hostname }, () => {
        tls.write(request(target, u["token"] ? `Authorization: Bearer ${u["token"]}\r\n` : ""));
        resolve(tls);
      });
      tls.on("data", (d: Buffer) => {
        text += d.toString("utf8");
        for (const w of [...waits]) if (text.includes(w.needle)) { waits.splice(waits.indexOf(w), 1); w.resolve(); }
      });
      tls.on("error", reject);
    };
    raw.on("data", onData);
    raw.on("error", reject);
  });
  return {
    opened,
    get text() { return text; },
    until: (needle: string): Promise<void> => text.includes(needle) ? Promise.resolve() : new Promise((resolve, reject) => {
      waits.push({ needle, resolve });
      setTimeout(() => reject(new Error(`timed out waiting for ${JSON.stringify(needle)} in ${JSON.stringify(text)}`)), 8000).unref();
    }),
  };
}

/** kubectl's reading of a KUBECONFIG list (client-go's loader): every file
 *  must load (a `*-data` value is strict base64), a named entry comes whole
 *  from the first file that has it, `current-context` from the first that
 *  sets it. */
function kubectlConfig(files: string[], context?: string) {
  const clusters = new Map<string, Record<string, unknown>>();
  const users = new Map<string, Record<string, unknown>>();
  const contexts = new Map<string, Record<string, unknown>>();
  let current: string | undefined;
  for (const f of files) {
    const doc = kubeconfigDocument(readFileSync(f, "utf8"));
    assert.ok(doc, `${f} loads`);
    for (const [list, inner, into] of [["clusters", "cluster", clusters], ["users", "user", users], ["contexts", "context", contexts]] as const) {
      for (const item of (doc[list] as Array<Record<string, unknown>> | undefined) ?? []) {
        const body = item[inner] as Record<string, unknown>;
        for (const [k, v] of Object.entries(body ?? {})) {
          if (k.endsWith("-data")) assert.match(String(v), /^[A-Za-z0-9+/]*={0,2}$/, `${f}: ${k} is base64 (client-go decodes it at load)`);
        }
        if (!into.has(item["name"] as string)) into.set(item["name"] as string, body);
      }
    }
    current ??= doc["current-context"] as string | undefined;
  }
  const ctx = contexts.get(context ?? current!)!;
  return { cluster: clusters.get(ctx["cluster"] as string)!, user: users.get(ctx["user"] as string)! };
}

/** kubectl's request: through the cluster's `proxy-url`, TLS trusting only
 *  the cluster's CA, its user's token or client certificate. */
function kubectlGet(files: string[], path: string, context?: string, extra: Record<string, string> = {}): Promise<number> {
  const { cluster: c, user: u } = kubectlConfig(files, context);
  const server = new URL(c["server"] as string);
  const proxy = new URL(c["proxy-url"] as string);
  const ca = c["certificate-authority"] ? readFileSync(c["certificate-authority"] as string, "utf8") : Buffer.from(c["certificate-authority-data"] as string, "base64").toString("utf8");
  const target = `${server.hostname}:${server.port || "443"}`;
  return new Promise((resolve, reject) => {
    const raw = netConnect(Number(proxy.port), proxy.hostname, () => raw.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let head = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      head = Buffer.concat([head, chunk]);
      const idx = head.indexOf("\r\n\r\n");
      if (idx === -1) return;
      raw.off("data", onData);
      const tls = tlsConnect({
        socket: raw, ca, servername: server.hostname,
        ...(u["client-certificate-data"] ? { cert: Buffer.from(u["client-certificate-data"] as string, "base64"), key: Buffer.from(u["client-key-data"] as string, "base64") } : {}),
      }, () => {
        const auth = u["token"] ? `Authorization: Bearer ${u["token"]}\r\n` : "";
        const more = Object.entries(extra).map(([k, v]) => `${k}: ${v}\r\n`).join("");
        tls.write(`GET ${path} HTTP/1.1\r\nHost: ${target}\r\n${auth}${more}Connection: close\r\n\r\n`);
      });
      const chunks: Buffer[] = [];
      tls.on("data", (d: Buffer) => chunks.push(d));
      tls.on("end", () => resolve(Number(/^HTTP\/1\.1 (\d{3})/.exec(Buffer.concat(chunks).toString("utf8"))?.[1] ?? 0)));
      tls.on("error", reject);
    };
    raw.on("data", onData);
    raw.on("error", reject);
    setTimeout(() => reject(new Error("request timed out")), 8000).unref();
  });
}

/** Any client: CONNECT `target`, TLS trusting the session CA, one GET. */
function viaTls(proxyPort: number, target: string, sessionCa: string, headers: Record<string, string>): Promise<number> {
  return new Promise((resolve, reject) => {
    const raw = netConnect(proxyPort, "127.0.0.1", () => raw.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let head = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      head = Buffer.concat([head, chunk]);
      const idx = head.indexOf("\r\n\r\n");
      if (idx === -1) return;
      raw.off("data", onData);
      const tls = tlsConnect({ socket: raw, ca: sessionCa, servername: target.replace(/:\d+$/, "") }, () => {
        const h = Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join("");
        tls.write(`GET /api/v1/namespaces HTTP/1.1\r\nHost: ${target}\r\n${h}Connection: close\r\n\r\n`);
      });
      const chunks: Buffer[] = [];
      tls.on("data", (d: Buffer) => chunks.push(d));
      tls.on("end", () => resolve(Number(/^HTTP\/1\.1 (\d{3})/.exec(Buffer.concat(chunks).toString("utf8"))?.[1] ?? 0)));
      tls.on("error", reject);
    };
    raw.on("data", onData);
    raw.on("error", reject);
    setTimeout(() => reject(new Error("request timed out")), 8000).unref();
  });
}

function viaPlainProxy(port: number, url: string, authorization: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method: "GET", path: url, headers: { host: u.host, authorization } }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    r.on("error", reject);
    r.end();
  });
}

const JAVA_GET = `
import java.net.*;
import java.io.*;
public class KubeGet {
  public static void main(String[] a) throws Exception {
    HttpURLConnection c = (HttpURLConnection) new URI(a[0]).toURL().openConnection();
    c.setRequestProperty("Authorization", "Bearer " + a[1]);
    System.out.println(c.getResponseCode());
    var h = java.net.http.HttpClient.newBuilder().proxy(ProxySelector.getDefault()).build();
    var r = h.send(java.net.http.HttpRequest.newBuilder(new URI(a[0])).header("Authorization", "Bearer " + a[1]).build(), java.net.http.HttpResponse.BodyHandlers.ofString());
    System.out.println(r.statusCode());
  }
}
`;

test(
  "kubectl, helm and Java reach the launch HOME's clusters through the session proxy: the real token or client certificate only at its own cluster, nothing secret in the twin or the overlay",
  { skip: !OPENSSL && "openssl unavailable", timeout: 120_000 },
  async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-kube-wire-"));
    const home = join(dir, "home");
    mkdirSync(join(home, ".kube"), { recursive: true });
    const kubeconfig = join(home, ".kube", "config");
    const clusterCa = ensureCa(join(dir, "cluster-ca"));
    const clientCa = ensureCa(join(dir, "client-ca"));
    const client = leafForHost(clientCa, "kube-admin");
    const clientFp = new X509Certificate(client.certPem).fingerprint256;
    const caData = b64(clusterCa.certPem);
    writeFileSync(kubeconfig, [
      "apiVersion: v1",
      "kind: Config",
      "clusters:",
      ...["prod:k8s", "secure:mtls", "decoy:decoy"].flatMap((p) => {
        const [name, host] = p.split(":");
        return [`- name: ${name}`, "  cluster:", `    certificate-authority-data: ${caData}`, `    server: https://${host}.example.test:6443`];
      }),
      "contexts:",
      "- name: prod", "  context:", "    cluster: prod", "    user: admin",
      "- name: secure", "  context:", "    cluster: secure", "    user: certuser",
      "current-context: prod",
      "users:",
      "- name: admin", "  user:", `    token: ${TOKEN}`,
      "- name: certuser", "  user:", `    client-certificate-data: ${b64(client.certPem)}`, `    client-key-data: ${b64(client.keyPem)}`,
      "",
    ].join("\n"));
    const secrets = [TOKEN, client.keyPem, b64(client.keyPem), b64(client.certPem)];

    const sock = join(dir, "arbiter.sock");
    const humanSock = join(dir, "human", "h.sock");
    const server = new ArbiterServer({
      socketPath: sock, humanSocketPath: humanSock, adminSocketPath: join(dir, "admin.sock"),
      dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"), log: () => {},
      adminPolicyDir: null, packDir: null, confidentiality: true, integrity: false,
      // The file labelled with no bindings: the token's release rests on the
      // registration's wire grant alone.
      policyDocument: { version: 1, paths: [{ path: kubeconfig, level: "no-model" }] },
    });
    await server.listen();
    const data = new ArbiterClient(sock); await data.connect();
    const human = new ArbiterClient(humanSock); await human.connect();
    const seen: Seen[] = [];
    const prod = await cluster("k8s.example.test", clusterCa, seen);
    const secure = await cluster("mtls.example.test", clusterCa, seen);
    const decoy = await cluster("decoy.example.test", clusterCa, seen);
    // Routes say only where to dial: no tls_ca, so the proxy verifies each
    // cluster with the kubeconfig's CA or not at all.
    const sites = MockSites.fromYaml([
      "hosts:",
      `  - host: "k8s.example.test"`, `    tls_to: 127.0.0.1:${prod.port}`, `    to: 127.0.0.1:${prod.port}`,
      `  - host: "mtls.example.test"`, `    tls_to: 127.0.0.1:${secure.port}`,
      `  - host: "decoy.example.test"`, `    tls_to: 127.0.0.1:${decoy.port}`,
      "",
    ].join("\n"));
    const caDir = join(dir, "mitm");
    const proxy = new NetProxy({
      allowThisMachine: true, log: (m) => { if (process.env["KUBE_DEBUG"]) console.error(m); }, sessionId: "sess-kube", mockSites: sites, mitm: { caDir },
      arbiter: new NetProxyAdapter(data as unknown as NetProxyRealClient, human as never),
      attributeHolders: () => [{ procKey: "7100-1", ancestors: [] }],
    });
    try {
      const port = await proxy.listen(0);
      const sessionCaPath = join(caDir, "mandu-egress-ca.pem");
      const sessionCa = readFileSync(sessionCaPath, "utf8");

      // Registered as the launcher does: the HOME file with the home, on the
      // human socket; the twin is what kubectl reads at ~/.kube/config.
      const reg = await human.registerSecret({ path: kubeconfig, home, sessionKey: "sess-kube" });
      assert.ok(reg.twin, reg.reason);
      const twinPath = join(dir, "twin-config");
      writeFileSync(twinPath, reg.twin!);
      const tokenSym = /token: (\S+)/.exec(reg.twin!)?.[1];
      assert.match(tokenSym ?? "", /^\$MDU:/, "the twin holds the token's placeholder");

      // The launcher's overlay, first in KUBECONFIG.
      const ov = await human.kubeOverlay(kubeconfig, home);
      assert.ok(ov.overlay, ov.reason);
      const overlayPath = join(dir, "kube-overlay.json");
      // With the stand-in client certificate the launcher gives a certificate
      // user (kube-overlay.ts): without it the real kubectl prompts for a
      // username on stdin and never returns (live-clients.md §4.3).
      writeFileSync(overlayPath, kubeOverlayText(ov.overlay!, sessionCaPath, `http://127.0.0.1:${port}`, mintStandInClientCert(dir) ?? undefined));
      const files = [overlayPath, twinPath];

      // 1. The token context: the REAL token at its cluster.
      assert.equal(await kubectlGet(files, "/api/v1/namespaces"), 200);
      assert.deepEqual(seen.map((s) => [s.site, s.authorization, s.peerCert]), [["k8s.example.test", `Bearer ${TOKEN}`, null]]);

      // 2. The client-certificate context: the proxy presents the real one.
      assert.equal(await kubectlGet(files, "/api/v1/namespaces", "secure"), 200);
      assert.deepEqual(seen.slice(1).map((s) => [s.site, s.authorization, s.peerCert]), [["mtls.example.test", undefined, clientFp]]);

      // 3. A request with its own Authorization header: no client certificate.
      assert.equal(await kubectlGet(files, "/api/v1/namespaces", "secure", { Authorization: "Bearer someone-elses-token" }), 200);
      assert.deepEqual(seen.slice(2).map((s) => [s.site, s.peerCert]), [["mtls.example.test", null]]);

      // 4. The token's placeholder where its contexts do not send it, and in
      //    plain HTTP to its own cluster.
      assert.equal(await viaTls(port, "decoy.example.test:6443", sessionCa, { Authorization: `Bearer ${tokenSym}` }), 403);
      assert.equal(await viaTls(port, "mtls.example.test:6443", sessionCa, { Authorization: `Bearer ${tokenSym}` }), 403);
      const plain = await viaPlainProxy(port, "http://k8s.example.test:6443/api/v1/namespaces", `Bearer ${tokenSym}`);
      assert.equal(plain.status, 403);
      assert.match(plain.body, /egress:secret-https-only/);
      // A request with no credential to the decoy: dialed with the decoy's
      // own CA (it is in the file), and no client certificate.
      assert.equal(await viaTls(port, "decoy.example.test:6443", sessionCa, {}), 200);
      assert.deepEqual(seen.slice(3).map((s) => [s.site, s.authorization, s.peerCert]), [["decoy.example.test", undefined, null]]);

      // 4b. Streams: `kubectl exec` (an upgrade, SPDY/3.1 and WebSocket) on
      //     the token context and the certificate context, relayed both ways;
      //     `kubectl get -w` (a watch), streamed as it comes.
      for (const [context, protocol] of [[undefined, "SPDY/3.1"], ["secure", "websocket"]] as const) {
        const before = seen.length;
        const exec = kubectlOpen(files, (target, auth) =>
          `POST /api/v1/namespaces/default/pods/web-1/exec?command=sh&stdin=true&stdout=true HTTP/1.1\r\nHost: ${target}\r\n${auth}Connection: Upgrade\r\nUpgrade: ${protocol}\r\nX-Stream-Protocol-Version: v4.channel.k8s.io\r\n\r\n`, context);
        const tls = await exec.opened;
        await exec.until("greeting\n");
        assert.match(exec.text, /^HTTP\/1\.1 101 /);
        tls.write("ls /\n");
        await exec.until("echo:ls /\n");
        tls.end();
        const up = seen.slice(before);
        assert.deepEqual(up.map((s) => [s.site, s.authorization, s.peerCert]),
          context === undefined ? [["k8s.example.test", `Bearer ${TOKEN}`, null]] : [["mtls.example.test", undefined, clientFp]],
          `${protocol}: the real credential on the upgrade request only`);
      }
      const watch = kubectlOpen(files, (target, auth) => `GET /api/v1/namespaces/default/pods?watch=true HTTP/1.1\r\nHost: ${target}\r\n${auth}\r\n`);
      await watch.opened;
      await watch.until('"ADDED"');
      assert.ok(!watch.text.includes('"MODIFIED"'), "the first event came while the cluster held the second");
      assert.equal(seen.at(-1)?.authorization, `Bearer ${TOKEN}`);
      prod.releaseWatch();
      await watch.until('"MODIFIED"');

      // 5. The upstream profile holds a key: human plane only. A kubeconfig
      //    outside the launch HOME gets no overlay.
      await assert.rejects(data.kubeUpstream("mtls.example.test:6443"), /human-plane/);
      const elsewhere = await human.kubeOverlay(join(dir, "ws", ".kube", "config"), home);
      assert.equal(elsewhere.overlay, null);

      // The real kubectl (and helm's client-go), when installed.
      if (!onPath("kubectl")) t.diagnostic("kubectl is not on PATH: the real-kubectl leg is skipped (the client-go reading above still ran)");
      else {
        const { stdout: out } = await run("kubectl", ["get", "--raw", "/api/v1/namespaces"], {
          env: { PATH: process.env["PATH"] ?? "", HOME: home, KUBECONFIG: files.join(":") }, encoding: "utf8", timeout: 60_000,
        });
        assert.match(out, /NamespaceList/);
        assert.equal(seen.at(-1)?.authorization, `Bearer ${TOKEN}`, "real kubectl: the real token at its cluster");
        const { stdout: out2 } = await run("kubectl", ["--context", "secure", "get", "--raw", "/api/v1/namespaces"], {
          env: { PATH: process.env["PATH"] ?? "", HOME: home, KUBECONFIG: files.join(":") }, encoding: "utf8", timeout: 60_000,
        });
        assert.match(out2, /NamespaceList/);
        assert.equal(seen.at(-1)?.peerCert, clientFp, "real kubectl: the real client certificate at its cluster");
      }

      // A JVM: the session trust store and proxy from JAVA_TOOL_OPTIONS
      // (HttpURLConnection, and HttpClient with the default proxy selector).
      if (!onPath("java")) t.diagnostic("java is not on PATH: the JVM leg is skipped");
      else {
        const store = join(dir, "java-truststore.p12");
        writeFileSync(store, javaTrustStore(pemCertificates(sessionCa)));
        writeFileSync(join(dir, "KubeGet.java"), JAVA_GET);
        const before = seen.length;
        const { stdout: out } = await run("java", [join(dir, "KubeGet.java"), "https://k8s.example.test:6443/api/v1/namespaces", tokenSym!], {
          env: {
            PATH: process.env["PATH"] ?? "", HOME: home,
            JAVA_TOOL_OPTIONS: javaToolOptions({ trustStore: store, proxy: { host: "127.0.0.1", port }, noProxy: "127.0.0.1,localhost,::1" })!,
          },
          encoding: "utf8", timeout: 60_000,
        });
        assert.deepEqual(out.trim().split("\n"), ["200", "200"]);
        assert.deepEqual(seen.slice(before).map((s) => [s.site, s.authorization]), Array(2).fill(["k8s.example.test", `Bearer ${TOKEN}`]));
      }

      // 6. THE ORACLE.
      for (const s of secrets) {
        assert.ok(!reg.twin!.includes(s), "the twin holds no secret byte");
        assert.ok(!readFileSync(overlayPath, "utf8").includes(s), "the overlay holds no secret byte");
      }
      const notProd = seen.filter((s) => s.site !== "k8s.example.test").map((s) => s.raw).join("\n");
      assert.ok(!notProd.includes(TOKEN), "the token reached only its own cluster");
      assert.ok(seen.every((s) => s.peerCert === null || s.site === "mtls.example.test"), "the client certificate reached only its own cluster");
    } finally {
      await proxy.close();
      for (const r of [prod, secure, decoy]) r.close();
      data.close();
      human.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
