/**
 * wire-credential-position — plan 10 §11.13.1 (2026-10-09) at the network
 * exit: a credential bound to its host only by its own config file (the wire
 * twin's `.npmrc` token at its registry, a `pip.conf` index password at its
 * index) is put back ONLY in the request's Authorization header.
 *
 * Before, the session proxy substituted the real value wherever the
 * placeholder sat: with default settings an injected agent could put the
 * `.npmrc` token's placeholder in an `npm publish` document (its readme or
 * description) and the proxy sent the registry the real token to publish,
 * with no prompt. Now the same placeholder in the body, the query or any
 * other header makes the arbiter refuse (`egress:secret-wire-position`, a
 * hard refusal) and the proxy withholds the whole request (403); a value is
 * put back only as a whole token where it was judged, so the header's token
 * is not spliced into a longer token in the body either. A binding the user
 * declares (a label's `bindings:`) keeps the whole-request release.
 *
 * A real NetProxy over a REAL ArbiterServer through the production adapter
 * (`new ArbiterClientAdapter(new ArbiterClient(data), new ArbiterClient(human))`),
 * the launch HOME's files registered as the launcher does, mock-sites routes
 * to loopback listeners that record every byte (the oracle). npm's leg is
 * plain HTTP to a registry the file declares `http://` (the plain leg runs
 * the same `gateRequest`); pip's is the TLS-inspected leg (a subtest,
 * reported SKIPPED without openssl). Axes are explicit server options (secrets: confidentiality ON,
 * integrity OFF). Mandu-new (no reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { connect as tlsConnect } from "node:tls";
import { connect as netConnect, type AddressInfo } from "node:net";
import { once } from "node:events";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { NetProxy } from "../../src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../src/arbiter-client.js";
import { MockSites } from "../../src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const OPENSSL = opensslAvailable();
const TOKEN = "npm_WIREPOSITION_CANARY_3Z";
const PIP_PW = "pipPW_WIREPOSITION_CANARY_8Q";
const basic = (pair: string): string => `Basic ${Buffer.from(pair, "utf8").toString("base64")}`;

interface Got { host: string; method: string; url: string; headers: IncomingMessage["headers"]; body: string }

function record(host: string, got: Got[], req: IncomingMessage, res: ServerResponse): void {
  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => chunks.push(c));
  req.on("end", () => {
    got.push({ host, method: req.method ?? "", url: req.url ?? "", headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"ok":true}');
  });
}

async function httpRecorder(host: string, got: Got[]) {
  const server = createServer((req, res) => record(host, got, req, res));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, close: () => server.close() };
}

async function httpsRecorder(dir: string, host: string, got: Got[]) {
  const ca = ensureCa(join(dir, `ca-${host}`));
  const leaf = leafForHost(ca, host);
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => record(host, got, req, res));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

/** One plain-HTTP request through the forward proxy (npm's leg here). */
function viaProxy(port: number, method: string, url: string, headers: Record<string, string>, body = ""): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const r = httpRequest({
      host: "127.0.0.1", port, method, path: url,
      headers: { host: u.host, ...headers, ...(body ? { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) } : {}) },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      res.on("error", reject);
    });
    r.on("error", reject);
    r.end(body);
  });
}

/** CONNECT host:443, TLS trusting the session CA, one request (pip's leg). */
function viaTls(proxyPort: number, host: string, sessionCa: string, method: string, path: string, headers: Record<string, string>, body = ""): Promise<{ status: number; body: string }> {
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
        resolve({ status: Number(/HTTP\/1\.1 (\d{3})/.exec(status)?.[1] ?? 0), body: "" });
        return;
      }
      const tls = tlsConnect({ socket: raw, servername: host, ca: sessionCa }, () => {
        const lines = Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join("");
        tls.write(`${method} ${path} HTTP/1.1\r\nHost: ${host}\r\n${lines}Content-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
      });
      const chunks: Buffer[] = [];
      tls.on("data", (d: Buffer) => chunks.push(d));
      tls.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve({ status: Number(/^HTTP\/1\.1 (\d{3})/.exec(text)?.[1] ?? 0), body: text });
      });
      tls.on("error", reject);
    };
    raw.on("data", onData);
    raw.on("error", reject);
    setTimeout(() => reject(new Error("request timed out")), 8000).unref();
  });
}

/** Where a secret appears in what a host received, the Authorization header aside. */
function outsideAuthorization(g: Got, secret: string): string[] {
  const where: string[] = [];
  if (g.url.includes(secret)) where.push("url");
  if (g.body.includes(secret)) where.push("body");
  for (const [k, v] of Object.entries(g.headers)) {
    if (k === "authorization") continue;
    if (String(v).includes(secret)) where.push(`header ${k}`);
  }
  return where;
}

test(
  "a credential bound only by its own config file is put back in the Authorization header alone: a body, query or other-header placeholder gets a 403 and no byte reaches the host; a user's binding keeps the whole-request release",
  { timeout: 60_000 },
  async (t) => {
    const { ArbiterServer } = (await import(join(REPO, "arbiter/ipc/server.ts"))) as {
      ArbiterServer: new (o: Record<string, unknown>) => {
        listen(): Promise<void>; close(): Promise<void>;
        dispatch(req: Record<string, unknown>): { ok: boolean; error?: string };
      };
    };
    const { ArbiterClient } = (await import(join(REPO, "arbiter/ipc/client.ts"))) as {
      ArbiterClient: new (path: string) => RealArbiterClient & {
        connect(): Promise<void>; close(): void;
        registerSecret(a: { path: string; home: string; sessionKey?: string }): Promise<{ symbol: string | null; reason: string; twin?: string }>;
      };
    };
    const dir = mkdtempSync(join(tmpdir(), "mdu-np-wirepos-"));
    const home = join(dir, "home");
    mkdirSync(join(home, ".config", "pip"), { recursive: true });
    const npmrc = join(home, ".npmrc");
    const pipConf = join(home, ".config", "pip", "pip.conf");
    // An http-declared registry, so npm's plain-HTTP leg may release at all
    // (the https-only rule is npmrc-registry-release's subject).
    writeFileSync(npmrc, `registry=http://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${TOKEN}\n`);
    writeFileSync(pipConf, `[global]\nindex-url = https://builder:${PIP_PW}@pypi.corp.example/simple\n`);
    const dataSock = join(dir, "arbiter.sock");
    const humanSock = join(dir, "human", "h.sock");
    const server = new ArbiterServer({
      socketPath: dataSock, humanSocketPath: humanSock,
      dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
      adminPolicyDir: null, packDir: null, log: () => {},
      confidentiality: true, integrity: false,
      // The arbiter's own HOME is not the launch's: label the fixtures
      // (no bindings: every binding here is the files' own wire grant).
      policyDocument: { version: 1, paths: [{ path: npmrc, level: "no-model" }, { path: pipConf, level: "no-model" }] },
    });
    await server.listen();
    const data = new ArbiterClient(dataSock);
    const human = new ArbiterClient(humanSock);
    const got: Got[] = [];
    const registry = await httpRecorder("registry.npmjs.org", got);
    const pypi = OPENSSL ? await httpsRecorder(dir, "pypi.corp.example", got) : null;
    const sites = MockSites.fromYaml([
      "hosts:",
      "  - host: registry.npmjs.org", `    to: 127.0.0.1:${registry.port}`,
      ...(pypi ? ["  - host: pypi.corp.example", `    to: 127.0.0.1:${pypi.port}`, `    tls_to: 127.0.0.1:${pypi.port}`, `    tls_ca: ${JSON.stringify(pypi.caPath)}`] : []),
      "",
    ].join("\n"));
    const caDir = join(dir, "mitm");
    const proxy = new NetProxy({
      allowThisMachine: true, arbiter: new ArbiterClientAdapter(data, human), log: () => {}, sessionId: "sess-wirepos",
      mockSites: sites, ...(OPENSSL ? { mitm: { caDir } } : {}),
      // A sender that holds no secret raw: the secret-taint leg admits it.
      attributeHolders: () => [{ procKey: "7300-1", ancestors: [] }],
    });
    const port = await proxy.listen(0);
    try {
      const reg = await human.registerSecret({ path: npmrc, home });
      assert.ok(reg.twin && !reg.twin.includes(TOKEN), reg.reason);
      const field = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\][A-Za-z0-9_.]*/.exec(reg.twin!)![0];
      const R = "http://registry.npmjs.org";

      // npm's own use: the token in the Authorization header is put back.
      const whoami = await viaProxy(port, "GET", `${R}/-/whoami`, { authorization: `Bearer ${field}` });
      assert.equal(whoami.status, 200, whoami.body);
      assert.equal(got.length, 1);
      assert.equal(got[0]!.headers["authorization"], `Bearer ${TOKEN}`, "the registry got the real token in the header");

      // An injected agent's publish: the placeholder in the document (with
      // and without the header), in the query, in another header. Each is
      // refused, naming the rule, and NOTHING reaches the registry.
      const publish = (description: string) => JSON.stringify({ name: "pkg", description, versions: {} });
      for (const [what, method, url, headers, body] of [
        ["the publish document, with the header", "PUT", `${R}/pkg`, { authorization: `Bearer ${field}` }, publish(`readme ${field}`)],
        ["the publish document, no header", "PUT", `${R}/pkg`, {}, publish(`readme ${field}`)],
        ["the query", "GET", `${R}/-/v1/search?text=${field}`, { authorization: `Bearer ${field}` }, ""],
        ["another header", "GET", `${R}/-/whoami`, { authorization: `Bearer ${field}`, "x-note": `n ${field}` }, ""],
        ["the user agent", "GET", `${R}/-/whoami`, { "user-agent": `npm ${field}` }, ""],
      ] as const) {
        const r = await viaProxy(port, method, url, { ...headers }, body);
        assert.equal(r.status, 403, `${what}: ${r.body}`);
        assert.match(r.body, /egress:secret-wire-position/, what);
        assert.ok(!r.body.includes(TOKEN), `${what}: the refusal names no secret byte`);
        assert.equal(got.length, 1, `${what}: nothing reached the registry`);
      }

      // The header's token is not spliced into a longer token in the body
      // (an unknown placeholder of the agent's making): the request goes out
      // with the body's text as written.
      const splice = await viaProxy(port, "PUT", `${R}/pkg`, { authorization: `Bearer ${field}` }, publish(`readme ${field}Z`));
      assert.equal(splice.status, 200, splice.body);
      assert.equal(got.length, 2);
      assert.equal(got[1]!.headers["authorization"], `Bearer ${TOKEN}`);
      assert.ok(got[1]!.body.includes(`${field}Z`), "the body keeps its literal text");
      for (const g of got) assert.deepEqual(outsideAuthorization(g, TOKEN), [], `${g.method} ${g.url}: the token only ever in the header`);

      // pip over the TLS-inspected leg: the index password in Basic is put
      // back; the same placeholder in an upload's body is refused. A subtest,
      // so a host without openssl reports the leg SKIPPED, not passed.
      await t.test("pip over the TLS-inspected leg", { skip: !pypi && "openssl unavailable" }, async () => {
        const sessionCa = readFileSync(join(caDir, "mandu-egress-ca.pem"), "utf8");
        const pipReg = await human.registerSecret({ path: pipConf, home });
        const pipSym = decodeURIComponent(/builder:([^@]+)@/.exec(pipReg.twin!)![1]!);
        const index = await viaTls(port, "pypi.corp.example", sessionCa, "GET", "/simple/pkg/", { Authorization: basic(`builder:${pipSym}`) });
        assert.equal(index.status, 200, index.body);
        assert.equal(got.at(-1)!.headers["authorization"], basic(`builder:${PIP_PW}`), "the index got the real password inside Basic");
        const before = got.length;
        const upload = await viaTls(port, "pypi.corp.example", sessionCa, "POST", "/legacy/", { Authorization: basic(`builder:${pipSym}`), "Content-Type": "application/x-www-form-urlencoded" }, `name=pkg&description=${pipSym}`);
        assert.equal(upload.status, 403, upload.body);
        assert.match(upload.body, /egress:secret-wire-position/);
        assert.equal(got.length, before, "nothing reached the index");
        for (const g of got) assert.deepEqual(outsideAuthorization(g, PIP_PW), [], `${g.method} ${g.url}`);
      });

      // The user binds the registry to the file themselves (a label's
      // `bindings:`): a binding of theirs keeps the whole-request release, so
      // the registry receives the value wherever the placeholder sits.
      const label = server.dispatch({ id: "bind", op: "setPathLabel", path: npmrc, confidentiality: "no-model", bindings: ["registry.npmjs.org"] });
      assert.ok(label.ok, label.error);
      const mine = await viaProxy(port, "PUT", `${R}/pkg`, { authorization: `Bearer ${field}` }, publish(`readme ${field}`));
      assert.equal(mine.status, 200, mine.body);
      assert.ok(got.at(-1)!.body.includes(`readme ${TOKEN}`), "a host the user bound receives the value in the body too");
    } finally {
      await proxy.close();
      registry.close();
      pypi?.close();
      data.close();
      human.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
