/**
 * issuer-catalog-egress — EVERY issuer file of the default catalog, end to
 * end (confidentiality.md §2.3, "Where the table lives, and what checks a
 * file"): the issuer bindings' table is data (arbiter/policy/issuers/, one
 * JSON file per issuer), and this test drives each file's put-back through
 * a REAL NetProxy with TLS inspection over a REAL ArbiterServer through the
 * production adapter, so a file added later is covered with no test edit.
 *
 * For each issuer the table holds (`ISSUERS`, compiled from the files), a
 * real-shaped key is made from its file's first example (each `{x*n}` run
 * replaced by random characters its format accepts, here in memory only)
 * and written to a fresh install's workspace `.env`, registered as the
 * launcher registers it. Then:
 *
 *   - the key's placeholder in the Authorization header of an HTTPS
 *     request to EACH of the issuer's hosts reaches that host as the real
 *     key, with no Approvals card filed;
 *   - the same placeholder to the NEXT issuer's first host gets a 403, a
 *     card, and no byte (a key goes to its own issuer only).
 *
 * A model-API host (`api.openai.com`, egress.ts `isModelHost`) is not this
 * proxy's: the egress proxy never inspects it (the model-API proxy owns it,
 * and with the confidentiality axis on a program's own call there is
 * refused at the CONNECT, model-host-paths.ts), so its row is left to
 * the unit tests here (issuer-bindings.test.ts) and skipped below.
 *
 * The oracle: the recording listeners. Each host saw only its own
 * issuer's key, only in the Authorization header, and no placeholder.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import { connect as tlsConnect } from "node:tls";
import { connect as netConnect, type AddressInfo } from "node:net";
import { once } from "node:events";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ISSUERS, ISSUER_CATALOG_PROBLEMS, issuerOfValue } from "../../arbiter/policy/issuer-bindings.js";
import { ISSUER_FILES } from "../../arbiter/policy/issuers/index.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { MockSites } from "../../interceptors/net-proxy/src/mock-sites.js";
import { isModelHost } from "../../interceptors/net-proxy/src/egress.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../interceptors/net-proxy/src/ca.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the fresh install's mode

const OPENSSL = opensslAvailable();

/** Random-looking characters from `abc`, seeded (never written to disk). */
const tail = (n: number, seed: number, abc: string): string => {
  let x = seed, out = "";
  while (out.length < n) { x = (Math.imul(x, 1103515245) + 12345) >>> 0; out += abc[(x >>> 16) % abc.length]; }
  return out;
};
const ALPHABETS = [
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  "abcdefghijklmnopqrstuvwxyz0123456789",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
  "0123456789abcdef",
  "0123456789",
];

/** A key of `id`'s format made from its file's first example: each run
 *  `{c*n}` becomes n random characters of the first alphabet that keeps
 *  the value this issuer's (and no other's). */
function keyFor(id: string, seed: number): string {
  const file = ISSUER_FILES.find((f) => f.file === `${id}.json`)!.data as { examples: string[] };
  for (const abc of ALPHABETS) {
    let k = 0;
    const v = file.examples[0]!.replace(/\{([0-9A-Za-z])\*(\d+)\}/g, (_m, _c: string, n: string) => tail(Number(n), seed + 101 * k++, abc));
    if (issuerOfValue(v)?.id === id) return v;
  }
  throw new Error(`${id}: no random key fits its format; give its first example a run its format's body accepts`);
}

type Got = Array<{ host: string; authorization: string | undefined; raw: string }>;

async function httpsRecorder(dir: string, host: string, got: Got) {
  const ca = ensureCa(join(dir, `ca-${host}`));
  const leaf = leafForHost(ca, host);
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      got.push({ host, authorization: req.headers["authorization"], raw: `${req.url} ${JSON.stringify(req.headers)} ${Buffer.concat(chunks).toString("utf8")}` });
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { host, port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

/** CONNECT host:443 through the proxy, TLS trusting the session CA, one GET. */
function viaTls(proxyPort: number, host: string, sessionCa: string, authorization: string): Promise<number> {
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
        tls.write(`GET /v1/check HTTP/1.1\r\nHost: ${host}\r\nAuthorization: ${authorization}\r\nConnection: close\r\n\r\n`);
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

test(
  "every issuer file: its key reaches each of its own hosts in the Authorization header with no card, and the next issuer's host is refused and reached by nothing",
  { skip: !OPENSSL && "openssl unavailable", timeout: 120_000 },
  async () => {
    assert.deepEqual(ISSUER_CATALOG_PROBLEMS, [], "every shipped issuer file loaded");
    assert.equal(ISSUERS.length, ISSUER_FILES.length);
    const keys = new Map(ISSUERS.map((i, n) => [i.id, keyFor(i.id, 31 + n)]));
    const varOf = (id: string): string => `${id.toUpperCase().replace(/[^A-Z0-9]/g, "_")}_API_KEY`;

    const dir = mkdtempSync(join(tmpdir(), "mdu-issuer-catalog-e2e-"));
    const ws = join(dir, "ws", "app");
    mkdirSync(ws, { recursive: true });
    const envFile = join(ws, ".env");
    writeFileSync(envFile, ISSUERS.map((i) => `${varOf(i.id)}=${keys.get(i.id)}\n`).join(""));
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
    const proxied = ISSUERS.map((i) => ({ ...i, hosts: i.hosts.filter((h) => !isModelHost(h)) })).filter((i) => i.hosts.length > 0);
    assert.ok(proxied.length >= ISSUERS.length - 1, "at most the model-API issuer is skipped");
    const hosts = proxied.flatMap((i) => i.hosts);
    const tls = await Promise.all(hosts.map((h) => httpsRecorder(dir, h, got)));
    const sites = MockSites.fromYaml([
      "hosts:",
      ...tls.flatMap((t) => [`  - host: ${t.host}`, `    to: 127.0.0.1:${t.port}`, `    tls_to: 127.0.0.1:${t.port}`, `    tls_ca: ${JSON.stringify(t.caPath)}`]),
      "",
    ].join("\n"));
    const caDir = join(dir, "mitm");
    const proxy = new NetProxy({
      allowThisMachine: true, arbiter: new ArbiterClientAdapter(data as unknown as RealArbiterClient, human as unknown as RealArbiterClient),
      log: () => {}, sessionId: "sess-issuer-catalog", mockSites: sites, mitm: { caDir }, attributeHolders: () => [{ procKey: "7000-1", ancestors: [] }],
    });
    try {
      const port = await proxy.listen(0);
      const ca = readFileSync(join(caDir, "mandu-egress-ca.pem"), "utf8");
      const reg = await human.registerSecret({ path: envFile, home: join(dir, "home") });
      assert.ok(reg.symbol && reg.twin, reg.reason);
      for (const k of keys.values()) assert.ok(!reg.twin!.includes(k), "the twin holds no key");
      const placeholder = (name: string): string => {
        const m = new RegExp(`^${name}='?(\\$MDU:[^\\s']+)'?$`, "m").exec(reg.twin!);
        assert.ok(m, `${name} has its own placeholder in the twin`);
        return m[1]!;
      };

      // ── released: each issuer's key at each of its own hosts ──
      const expected: Array<[string, string]> = [];
      for (const i of proxied) {
        const sym = placeholder(varOf(i.id));
        for (const h of i.hosts) {
          assert.equal(await viaTls(port, h, ca, `Bearer ${sym}`), 200, `${i.id} at ${h}`);
          expected.push([h, `Bearer ${keys.get(i.id)}`]);
        }
      }
      assert.deepEqual(got.map((g) => [g.host, g.authorization]), expected, "each host got its own issuer's real key, in the Authorization header");
      assert.equal((await admin.egressApprovals("pending")).length, 0, "no card for an issuer's own host");

      // ── refused: each key at the NEXT issuer's host ──
      for (const [n, i] of proxied.entries()) {
        const other = proxied[(n + 1) % proxied.length]!;
        if (other.id === i.id) continue;
        assert.equal(await viaTls(port, other.hosts[0]!, ca, `Bearer ${placeholder(varOf(i.id))}`), 403, `${i.id} key at ${other.hosts[0]}`);
      }
      assert.equal(got.length, expected.length, "a refused send reached nothing");
      assert.ok((await admin.egressApprovals("pending")).length > 0, "a refused send asks");

      // THE ORACLE: each host saw only its own issuer's key, only in
      // Authorization, and no placeholder.
      for (const g of got) {
        const owner = proxied.find((i) => i.hosts.includes(g.host))!;
        assert.ok(!g.raw.includes("$MDU:"), `no placeholder reached ${g.host}`);
        for (const [id, k] of keys) {
          const rest = g.raw.replace(JSON.stringify(g.authorization ?? ""), "");
          assert.ok(!rest.includes(k), `${g.host}: ${id}'s key only in the Authorization header`);
          if (id !== owner.id) assert.ok(!g.raw.includes(k), `${g.host} never saw ${id}'s key`);
        }
      }
    } finally {
      await proxy.close();
      for (const t of tls) t.close();
      data.close();
      human.close();
      admin.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
