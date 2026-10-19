/**
 * issuer-bindings-egress — the default catalog's issuer bindings end to end
 * (confidentiality.md §2.3): a fresh install's law (no label, no binding),
 * a workspace `.env` holding a Stripe-shaped key, registered as the
 * launcher registers it, and a REAL NetProxy with TLS inspection over a REAL
 * ArbiterServer through the production adapter.
 *
 *   - the key's placeholder in the Authorization header (Bearer, and Basic
 *     as curl -u sends it) of an HTTPS request to api.stripe.com reaches
 *     Stripe as the real key, with no Approvals card filed;
 *   - every lookalike host (api.stripe.com.evil.io, api-stripe.com,
 *     stripe.com) gets a 403 and no byte, and a card is filed (the person
 *     is asked, as before);
 *   - at api.stripe.com itself: the key in the body, the key over plain
 *     HTTP, and another value of the same file (a password) in the header
 *     are refused and reach nothing;
 *   - with policy.yaml `issuer_bindings: false` the header send asks again.
 *
 * The oracle: the recording listeners. The real key reaches api.stripe.com
 * only, only in the Authorization header; no other listener sees the key,
 * the password, or a placeholder.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { connect as tlsConnect } from "node:tls";
import { connect as netConnect, type AddressInfo } from "node:net";
import { once } from "node:events";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { MockSites } from "../../interceptors/net-proxy/src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../interceptors/net-proxy/src/ca.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the fresh install's mode

const OPENSSL = opensslAvailable();
const tail = (n: number, seed: number): string => {
  const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let x = seed, out = "";
  while (out.length < n) { x = (Math.imul(x, 1103515245) + 12345) >>> 0; out += abc[(x >>> 16) % abc.length]; }
  return out;
};
const KEY = ["sk", "test", `51ISSUERE2E${tail(90, 17)}`].join("_");
const PASSWORD = "Quay-Plum-ISSUERE2E-4471!";
const basic = (pair: string): string => `Basic ${Buffer.from(pair, "utf8").toString("base64")}`;

type Got = Array<{ host: string; method: string; authorization: string | undefined; raw: string }>;

function record(host: string, got: Got, req: IncomingMessage, res: ServerResponse): void {
  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => chunks.push(c));
  req.on("end", () => {
    got.push({ host, method: req.method ?? "", authorization: req.headers["authorization"], raw: `${req.url} ${JSON.stringify(req.headers)} ${Buffer.concat(chunks).toString("utf8")}` });
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"object":"list","data":[]}');
  });
}

async function httpsRecorder(dir: string, host: string, got: Got) {
  const ca = ensureCa(join(dir, `ca-${host}`));
  const leaf = leafForHost(ca, host);
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => record(host, got, req, res));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

async function httpRecorder(host: string, got: Got) {
  const server = createServer((req, res) => record(host, got, req, res));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, close: () => server.close() };
}

/** CONNECT host:443 through the proxy, TLS trusting the session CA, one request. */
function viaTls(proxyPort: number, host: string, sessionCa: string, req: { method?: string; path: string; headers: Record<string, string>; body?: string }): Promise<number> {
  return new Promise((resolve, reject) => {
    const raw = netConnect(proxyPort, "127.0.0.1", () => raw.write(`CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}:443\r\n\r\n`));
    let head = Buffer.alloc(0);
    const onData = (c: Buffer): void => {
      head = Buffer.concat([head, c]);
      const idx = head.indexOf("\r\n\r\n");
      if (idx === -1) return;
      raw.off("data", onData);
      const status = head.subarray(0, idx).toString("latin1").split("\r\n")[0]!;
      if (!/ 200 /.test(`${status} `)) {
        raw.destroy();
        resolve(Number(/HTTP\/1\.1 (\d{3})/.exec(status)?.[1] ?? 0));
        return;
      }
      const tls = tlsConnect({ socket: raw, servername: host, ca: sessionCa }, () => {
        const body = req.body ?? "";
        const headers = Object.entries({ Host: host, ...req.headers, ...(body ? { "Content-Length": String(Buffer.byteLength(body)) } : {}), Connection: "close" })
          .map(([k, v]) => `${k}: ${v}\r\n`).join("");
        tls.write(`${req.method ?? "GET"} ${req.path} HTTP/1.1\r\n${headers}\r\n${body}`);
      });
      const chunks: Buffer[] = [];
      tls.on("data", (d: Buffer) => chunks.push(d));
      tls.on("end", () => resolve(Number(/^HTTP\/1\.1 (\d{3})/.exec(Buffer.concat(chunks).toString("utf8"))?.[1] ?? 0)));
      tls.on("error", reject);
    };
    raw.on("data", onData);
    raw.on("error", reject);
    setTimeout(() => reject(new Error("request timed out")), 10_000).unref();
  });
}

/** A plain-HTTP GET through the forward proxy. */
function viaPlain(port: number, url: string, authorization: string): Promise<number> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method: "GET", path: url, headers: { host: u.host, authorization } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    r.on("error", reject);
    r.end();
  });
}

test(
  "fresh install: a Stripe-shaped key in .env reaches api.stripe.com in the Authorization header with no card; every lookalike host, the body, plain HTTP and the file's other value are refused and reach nothing",
  { skip: !OPENSSL && "openssl unavailable", timeout: 90_000 },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mdu-issuer-e2e-"));
    const ws = join(dir, "ws", "shop-app");
    mkdirSync(ws, { recursive: true });
    const envFile = join(ws, ".env");
    writeFileSync(envFile, `STRIPE_SECRET_KEY=${KEY}\nDB_PASSWORD=${PASSWORD}\n`);
    const policy = join(dir, "policy.yaml");
    writeFileSync(policy, "version: 1\n"); // no label, no binding: a fresh install
    const sock = join(dir, "arbiter.sock");
    const humanSock = join(dir, "human", "h.sock");
    const adminSock = join(dir, "admin.sock");
    const server = new ArbiterServer({
      socketPath: sock, humanSocketPath: humanSock, adminSocketPath: adminSock, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
      log: () => {}, adminPolicyDir: null, packDir: null, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
    });
    await server.listen();
    const data = new ArbiterClient(sock);
    const human = new ArbiterClient(humanSock);
    const admin = new ArbiterClient(adminSock);
    await admin.connect();
    const got: Got = [];
    const hosts = ["api.stripe.com", "api.stripe.com.evil.io", "api-stripe.com", "stripe.com"];
    const tls = await Promise.all(hosts.map((h) => httpsRecorder(dir, h, got)));
    const plain = await httpRecorder("http:api.stripe.com", got);
    const sites = MockSites.fromYaml([
      "hosts:",
      ...hosts.flatMap((h, i) => [`  - host: ${h}`, `    to: 127.0.0.1:${i === 0 ? plain.port : tls[i]!.port}`, `    tls_to: 127.0.0.1:${tls[i]!.port}`, `    tls_ca: ${JSON.stringify(tls[i]!.caPath)}`]),
      "",
    ].join("\n"));
    const caDir = join(dir, "mitm");
    const proxy = new NetProxy({
      allowThisMachine: true, arbiter: new ArbiterClientAdapter(data as unknown as RealArbiterClient, human as unknown as RealArbiterClient),
      log: () => {}, sessionId: "sess-issuer", mockSites: sites, mitm: { caDir }, attributeHolders: () => [{ procKey: "7000-1", ancestors: [] }],
    });
    try {
      const port = await proxy.listen(0);
      const ca = readFileSync(join(caDir, "mandu-egress-ca.pem"), "utf8");
      // Registered as the launcher registers a workspace credential file.
      const reg = await human.registerSecret({ path: envFile, home: join(dir, "home") });
      assert.ok(reg.symbol && reg.twin, reg.reason);
      assert.ok(!reg.twin!.includes(KEY) && !reg.twin!.includes(PASSWORD), "the twin holds no secret byte");
      const placeholder = (key: string): string => new RegExp(`^${key}='?(\\$MDU:[^\\s']+)'?$`, "m").exec(reg.twin!)![1]!;
      const keySym = placeholder("STRIPE_SECRET_KEY");
      const pwSym = placeholder("DB_PASSWORD");

      // ── released: its own issuer's host, Authorization, HTTPS ──
      assert.equal(await viaTls(port, "api.stripe.com", ca, { path: "/v1/charges?limit=3", headers: { Authorization: `Bearer ${keySym}` } }), 200);
      assert.equal(await viaTls(port, "api.stripe.com", ca, { path: "/v1/customers", headers: { Authorization: basic(`${keySym}:`) } }), 200);
      assert.deepEqual(got.map((g) => [g.host, g.authorization]), [
        ["api.stripe.com", `Bearer ${KEY}`],
        ["api.stripe.com", basic(`${KEY}:`)],
      ], "Stripe got the real key, in the Authorization header");
      assert.equal((await admin.egressApprovals("pending")).length, 0, "no card for the issuer's own host");

      // ── refused: lookalike hosts (each asks: a card, nothing sent) ──
      for (const h of ["api.stripe.com.evil.io", "api-stripe.com", "stripe.com"]) {
        assert.equal(await viaTls(port, h, ca, { path: "/v1/charges", headers: { Authorization: `Bearer ${keySym}` } }), 403, h);
      }
      const asked = (await admin.egressApprovals("pending")).map((p) => p.destination).sort();
      for (const h of ["api-stripe.com", "api.stripe.com.evil.io", "stripe.com"]) assert.ok(asked.some((d) => d === h || d.startsWith(`${h}:`)), `a card for ${h}: ${asked}`);

      // ── refused at the issuer itself: the body, plain HTTP, another value ──
      assert.equal(await viaTls(port, "api.stripe.com", ca, {
        method: "POST", path: "/v1/customers", headers: { Authorization: `Bearer ${keySym}`, "Content-Type": "application/json" },
        body: JSON.stringify({ description: keySym }),
      }), 403, "the key in a body Stripe would store");
      assert.equal(await viaPlain(port, "http://api.stripe.com/v1/charges", `Bearer ${keySym}`), 403, "plain HTTP");
      assert.equal(await viaTls(port, "api.stripe.com", ca, { path: "/v1/charges", headers: { Authorization: `Bearer ${pwSym}` } }), 403, "the file's password is no Stripe key");
      assert.equal(got.length, 2, `nothing else reached any host: ${JSON.stringify(got.map((g) => [g.host, g.method]))}`);

      // ── turned off: the same header send asks again ──
      const read = await admin.policyDocument();
      await admin.applyPolicyDocument({ version: 1, issuer_bindings: false }, "test", read.lawHash!);
      assert.equal(await viaTls(port, "api.stripe.com", ca, { path: "/v1/charges", headers: { Authorization: `Bearer ${keySym}` } }), 403, "issuer_bindings: false");
      assert.equal(got.length, 2);

      // THE ORACLE: only api.stripe.com saw the key, only in Authorization;
      // no listener saw the password or a placeholder.
      const all = got.map((g) => g.raw).join("\n");
      assert.ok(!all.includes(PASSWORD), "the password reached no host");
      assert.ok(!all.includes("$MDU:"), "no placeholder reached a host");
      for (const g of got) {
        assert.equal(g.host, "api.stripe.com");
        assert.ok(!g.raw.replace(JSON.stringify(g.authorization ?? ""), "").includes(KEY), "the key only in the Authorization header");
      }
    } finally {
      await proxy.close();
      for (const t of tls) t.close();
      plain.close();
      data.close();
      human.close();
      admin.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
