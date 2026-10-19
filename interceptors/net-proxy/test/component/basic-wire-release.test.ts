/**
 * basic-wire-release — plan 10 §11.13.1 (2026-10-03) at the network exit,
 * for the two credential shapes npm and pip send inside HTTP Basic:
 *
 *   - npm: `//host/:username=…` + `//host/:_password=<base64>` in the launch
 *     HOME's `.npmrc`. The twin's `_password` is the base64 of the field
 *     symbol, npm decodes it and sends `Basic base64(username:<symbol>)`;
 *   - pip: `index-url = https://user:<password>@host/simple` in the launch
 *     HOME's `pip.conf`. The twin's password is the percent-encoded symbol,
 *     pip decodes it and sends `Basic base64(user:<symbol>)`.
 *
 * The session proxy decodes the Basic pair, gates the symbol inside it like
 * any other (its bindings, which the registration derived from the HOME
 * file), and puts the REAL password back only at the bound host. Asserted
 * with recording listeners as the oracle: the bound host gets the real
 * credential; a decoy host gets a 403 and no byte (the placeholder is not
 * forwarded either); the symbol of a WORKSPACE pip.conf (no binding) is
 * refused even at the index host; an unattributed connection is refused in
 * a session where a process holds a secret raw (plan 13 D6) and released in
 * a clean one (the binding is the standing release, as for the `_authToken`
 * of !293). Both go over the TLS-inspecting leg (CONNECT + the session CA),
 * the leg npm and pip really use. HTTPS ONLY (2026-10-03): the same
 * placeholders in plain HTTP to their own bound hosts get a 403 naming
 * `egress:secret-https-only` and nothing reaches the host; an index the
 * pip.conf declares `http://` is released in plain HTTP.
 *
 * A real NetProxy over a REAL ArbiterServer through the production adapter
 * (`new ArbiterClientAdapter(new ArbiterClient(data), new ArbiterClient(human))`).
 * Axes are explicit server options (secrets: confidentiality ON, integrity
 * OFF). Mandu-new (no reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type IncomingMessage } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { connect as tlsConnect } from "node:tls";
import { connect as netConnect, type AddressInfo } from "node:net";
import { once } from "node:events";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";

import { NetProxy } from "../../src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../src/arbiter-client.js";
import { MockSites } from "../../src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";
import type { ProcHolder } from "../../src/conn-attr.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const OPENSSL = opensslAvailable();
const NPM_PW = "npmPW_BASICRELEASE_9c";
const PIP_PW = "pipPW_BASICRELEASE_4e";
const PIP_HTTP_PW = "pipHTTPPW_BASICRELEASE_2c";
const ENV_SECRET = "sk_live_BASICRELEASE_D6_77";
const basic = (pair: string): string => `Basic ${Buffer.from(pair, "utf8").toString("base64")}`;

type Got = Array<{ host: string; url: string; authorization: string | undefined; raw: string }>;

/** A plain-HTTP listener recording every request. */
async function httpRecorder(host: string, got: Got) {
  const server = createServer((req, res) => record(host, got, req, res));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, close: () => server.close() };
}

/** An HTTPS listener for `host` under a test CA, recording every request. */
async function httpsRecorder(dir: string, host: string, got: Got) {
  const ca = ensureCa(join(dir, `ca-${host}`));
  const leaf = leafForHost(ca, host);
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => record(host, got, req, res));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

function record(host: string, got: Got, req: IncomingMessage, res: import("node:http").ServerResponse): void {
  const chunks: Buffer[] = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    got.push({ host, url: req.url ?? "", authorization: req.headers["authorization"], raw: JSON.stringify(req.headers) + Buffer.concat(chunks).toString("utf8") });
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
  });
}

/** A plain-HTTP GET through the forward proxy (npm's leg in this test). */
function viaProxy(port: number, url: string, authorization: string): Promise<number> {
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

/** `viaProxy`, with the response body (a refusal names its rule there). */
function viaProxyBody(port: number, url: string, authorization: string): Promise<{ status: number; body: string }> {
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

/** CONNECT host:443, TLS trusting the session CA, one GET (pip's leg). */
function viaTls(proxyPort: number, host: string, sessionCa: string, path: string, authorization: string): Promise<number> {
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
        tls.write(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\nAuthorization: ${authorization}\r\nConnection: close\r\n\r\n`);
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

test(
  "the npm _password and pip index password: their symbols inside HTTP Basic are put back at the bound host only; a decoy gets a 403 and no byte; an unbound symbol and an unattributed sender in a holding session are refused; plain HTTP to the bound host gets nothing unless the URL is declared http",
  { skip: !OPENSSL && "openssl unavailable", timeout: 60_000 },
  async () => {
    const { ArbiterServer } = (await import(join(REPO, "arbiter/ipc/server.ts"))) as {
      ArbiterServer: new (o: Record<string, unknown>) => { listen(): Promise<void>; close(): Promise<void> };
    };
    const { ArbiterClient } = (await import(join(REPO, "arbiter/ipc/client.ts"))) as {
      ArbiterClient: new (path: string) => RealArbiterClient & {
        connect(): Promise<void>; close(): void;
        registerSecret(a: { path: string; home?: string; sessionKey?: string }): Promise<{ symbol: string | null; reason: string; twin?: string }>;
        decideSecretOpen(a: { path: string; exe: string; isAgent: boolean; exeSystem?: boolean; openerEnv?: string[]; procKey: string; session?: string }): Promise<{ verdict: string }>;
      };
    };
    const dir = mkdtempSync(join(tmpdir(), "mdu-np-basic-"));
    const home = join(dir, "home");
    mkdirSync(join(home, ".config", "pip"), { recursive: true });
    mkdirSync(join(dir, "ws"));
    const npmrc = join(home, ".npmrc");
    const pipConf = join(home, ".config", "pip", "pip.conf");
    const wsPip = join(dir, "ws", "pip.conf");
    const envFile = join(dir, "ws", ".env");
    writeFileSync(npmrc, `//registry.corp.example/:username=builder\n//registry.corp.example/:_password=${Buffer.from(NPM_PW).toString("base64")}\n`);
    // The second index is declared over plain http: its password may travel
    // there in plain HTTP (2026-10-03, https only for everything else).
    writeFileSync(pipConf, `[global]\nindex-url = https://builder:${PIP_PW}@pypi.corp.example/simple\nextra-index-url = http://builder:${PIP_HTTP_PW}@plain.corp.example/simple\n`);
    writeFileSync(wsPip, `[global]\nindex-url = https://builder:${PIP_PW}x@pypi.corp.example/simple\n`);
    writeFileSync(envFile, `API_KEY=${ENV_SECRET}\n`);
    const sock = join(dir, "arbiter.sock");
    const humanSock = join(dir, "human", "h.sock");
    const server = new ArbiterServer({
      socketPath: sock, humanSocketPath: humanSock, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
      adminPolicyDir: null, packDir: null, confidentiality: true, integrity: false,
      // The arbiter's own HOME is not the launch's: label the fixtures (the
      // registration derives bindings from the launch `home` it is given).
      policyDocument: { version: 1, paths: [
        { path: npmrc, level: "no-model" }, { path: pipConf, level: "no-model" }, { path: wsPip, level: "no-model" },
        { path: envFile, level: "no-model", readers: ["ssh-add"] },
      ] },
    });
    await server.listen();
    const data = new ArbiterClient(sock);
    await data.connect();
    const guard = new ArbiterClient(humanSock);
    await guard.connect();
    const human = new ArbiterClient(humanSock);
    const got: Got = [];
    // Every host on both legs; a plain-HTTP arrival is recorded as `http:<host>`.
    const registry = await httpsRecorder(dir, "registry.corp.example", got);
    const registryHttp = await httpRecorder("http:registry.corp.example", got);
    const decoyHttp = await httpRecorder("http:decoy.example", got);
    const pypi = await httpsRecorder(dir, "pypi.corp.example", got);
    const pypiHttp = await httpRecorder("http:pypi.corp.example", got);
    const plainIndex = await httpRecorder("http:plain.corp.example", got);
    const decoyTls = await httpsRecorder(dir, "decoy.example", got);
    const both = (host: string, plain: { port: number }, tls: { port: number; caPath: string }) =>
      [`  - host: ${host}`, `    to: 127.0.0.1:${plain.port}`, `    tls_to: 127.0.0.1:${tls.port}`, `    tls_ca: ${JSON.stringify(tls.caPath)}`];
    const sites = MockSites.fromYaml([
      "hosts:",
      ...both("registry.corp.example", registryHttp, registry),
      ...both("pypi.corp.example", pypiHttp, pypi),
      "  - host: plain.corp.example", `    to: 127.0.0.1:${plainIndex.port}`,
      ...both("decoy.example", decoyHttp, decoyTls),
      "",
    ].join("\n"));
    let holders: ProcHolder[] = [{ procKey: "7000-1", ancestors: [] }];
    const proxies: NetProxy[] = [];
    const start = async (sessionId: string): Promise<{ port: number; ca: string }> => {
      const caDir = join(dir, `mitm-${sessionId}`);
      const proxy = new NetProxy({ allowThisMachine: true,
        arbiter: new ArbiterClientAdapter(data, human), log: () => {}, sessionId, mockSites: sites, mitm: { caDir },
        attributeHolders: () => holders,
      });
      proxies.push(proxy);
      const port = await proxy.listen(0);
      return { port, ca: readFileSync(join(caDir, "mandu-egress-ca.pem"), "utf8") };
    };
    try {
      // Registered as the launcher does at launch (the HOME files with the home).
      const npmReg = await human.registerSecret({ path: npmrc, home });
      const pipReg = await human.registerSecret({ path: pipConf, home });
      const wsReg = await human.registerSecret({ path: wsPip, home });
      for (const r of [npmReg, pipReg, wsReg]) assert.ok(r.twin, r.reason);
      // What npm and pip decode the twin into: the field symbols.
      const npmSym = Buffer.from(/:_password=([A-Za-z0-9+/=]+)/.exec(npmReg.twin!)![1]!, "base64").toString("utf8");
      const pipSym = decodeURIComponent(/builder:([^@]+)@/.exec(pipReg.twin!)![1]!);
      const pipHttpSym = decodeURIComponent([...pipReg.twin!.matchAll(/builder:([^@]+)@/g)][1]![1]!);
      const wsSym = decodeURIComponent(/builder:([^@]+)@/.exec(wsReg.twin!)![1]!);
      for (const s of [npmSym, pipSym, pipHttpSym, wsSym]) assert.match(s, /^\$MDU:nomodel_Read\[[0-9a-f]+\]\./);

      const p = await start("sess-basic");
      // npm and pip, over the TLS-inspected leg (what both use): the bound
      // host gets the real password inside Basic.
      assert.equal(await viaTls(p.port, "registry.corp.example", p.ca, "/-/whoami", basic(`builder:${npmSym}`)), 200);
      assert.equal(await viaTls(p.port, "pypi.corp.example", p.ca, "/simple/pkg/", basic(`builder:${pipSym}`)), 200);
      assert.deepEqual(got.map((g) => [g.host, g.authorization]), [
        ["registry.corp.example", basic(`builder:${NPM_PW}`)],
        ["pypi.corp.example", basic(`builder:${PIP_PW}`)],
      ]);

      // HTTPS ONLY (2026-10-03): the same placeholders in plain HTTP to the
      // very hosts they are bound to get nothing (403 naming the rule), and
      // nothing reaches either host's plain listener.
      for (const [url, sym] of [["http://registry.corp.example/-/whoami", npmSym], ["http://pypi.corp.example/simple/pkg/", pipSym]] as const) {
        const r = await viaProxyBody(p.port, url, basic(`builder:${sym}`));
        assert.equal(r.status, 403, url);
        assert.match(r.body, /egress:secret-https-only/, url);
      }
      assert.equal(got.length, 2, `nothing reached a host over plain HTTP: ${JSON.stringify(got.map((g) => g.host))}`);
      // An index the file declares over http: its password is put back in plain HTTP there.
      assert.equal(await viaProxy(p.port, "http://plain.corp.example/simple/pkg/", basic(`builder:${pipHttpSym}`)), 200);
      assert.deepEqual(got[2], { ...got[2]!, host: "http:plain.corp.example", authorization: basic(`builder:${PIP_HTTP_PW}`) });
      got.splice(2, 1);

      // The decoy, on both legs, with either placeholder: 403, nothing reaches it.
      assert.equal(await viaProxy(p.port, "http://decoy.example/collect", basic(`builder:${npmSym}`)), 403);
      assert.equal(await viaProxy(p.port, "http://decoy.example/collect", basic(`builder:${pipSym}`)), 403);
      assert.equal(await viaTls(p.port, "decoy.example", p.ca, "/simple/", basic(`builder:${pipSym}`)), 403);
      assert.equal(await viaTls(p.port, "decoy.example", p.ca, "/simple/", basic(`builder:${npmSym}`)), 403);
      // A cross-binding: npm's password to pip's index is refused too.
      assert.equal(await viaTls(p.port, "pypi.corp.example", p.ca, "/simple/", basic(`builder:${npmSym}`)), 403);
      // The workspace pip.conf's symbol is bound nowhere: refused even at the index.
      assert.equal(await viaTls(p.port, "pypi.corp.example", p.ca, "/simple/", basic(`builder:${wsSym}`)), 403);
      assert.equal(got.length, 2, `nothing else reached any host: ${JSON.stringify(got.map((g) => [g.host, g.url]))}`);

      // Unattributed, in a session where a process holds a secret raw (D6): refused.
      assert.equal((await guard.decideSecretOpen({ path: envFile, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "7100-1", session: "sess-held" })).verdict, "raw");
      const held = await start("sess-held");
      holders = [];
      assert.equal(await viaTls(held.port, "pypi.corp.example", held.ca, "/simple/", basic(`builder:${pipSym}`)), 403);
      assert.equal(got.length, 2, "the unattributed request in the holding session reached nobody");
      // In a clean session, the binding is the standing release (as for !293's _authToken).
      assert.equal(await viaTls(p.port, "pypi.corp.example", p.ca, "/simple/", basic(`builder:${pipSym}`)), 200);
      assert.equal(got[2]!.authorization, basic(`builder:${PIP_PW}`));

      // THE ORACLE: the decoy never saw a password, a placeholder, or any base64 of either.
      const decoy = got.filter((g) => g.host.endsWith("decoy.example"));
      assert.deepEqual(decoy, []);
      const elsewhere = got.filter((g) => g.host !== "pypi.corp.example").map((g) => g.raw).join("\n");
      assert.ok(!elsewhere.includes(PIP_PW) && !elsewhere.includes(Buffer.from(`builder:${PIP_PW}`).toString("base64")), "the pip password reached only its index");
      const notRegistry = got.filter((g) => g.host !== "registry.corp.example").map((g) => g.raw).join("\n");
      assert.ok(!notRegistry.includes(NPM_PW) && !notRegistry.includes(Buffer.from(`builder:${NPM_PW}`).toString("base64")), "the npm password reached only its registry");
    } finally {
      for (const px of proxies) await px.close();
      registry.close();
      registryHttp.close();
      pypiHttp.close();
      plainIndex.close();
      decoyHttp.close();
      pypi.close();
      decoyTls.close();
      data.close();
      human.close();
      guard.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

// ── The real pip, where it is installed (CI's guest has none: self-SKIP) ─────

const HAS_PIP = spawnSync("python3", ["-m", "pip", "--version"], { stdio: "ignore" }).status === 0;

test(
  "LIVE pip: pip reads the pip.conf TWIN (the percent-encoded token), goes through the session proxy (TLS inspected, trusting the session CA), and the index gets the REAL password in Basic; with the raw token in the URL Python cannot even parse it",
  { skip: !OPENSSL ? "openssl unavailable" : !HAS_PIP ? "pip is not installed" : false, timeout: 120_000 },
  async () => {
    const { ArbiterServer } = (await import(join(REPO, "arbiter/ipc/server.ts"))) as {
      ArbiterServer: new (o: Record<string, unknown>) => { listen(): Promise<void>; close(): Promise<void> };
    };
    const { ArbiterClient } = (await import(join(REPO, "arbiter/ipc/client.ts"))) as {
      ArbiterClient: new (path: string) => RealArbiterClient & {
        connect(): Promise<void>; close(): void;
        registerSecret(a: { path: string; home?: string }): Promise<{ symbol: string | null; reason: string; twin?: string }>;
      };
    };
    const dir = mkdtempSync(join(tmpdir(), "mdu-np-livepip-"));
    const home = join(dir, "home");
    mkdirSync(join(home, ".config", "pip"), { recursive: true });
    const pipConf = join(home, ".config", "pip", "pip.conf");
    writeFileSync(pipConf, `[global]\nindex-url = https://builder:${PIP_PW}@pypi.corp.example/simple\n`);
    const server = new ArbiterServer({
      socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
      adminPolicyDir: null, packDir: null, confidentiality: true, integrity: false,
      policyDocument: { version: 1, paths: [{ path: pipConf, level: "no-model" }] },
    });
    await server.listen();
    const data = new ArbiterClient(join(dir, "a.sock"));
    await data.connect();
    const human = new ArbiterClient(join(dir, "human", "h.sock"));
    // The index: a PEP 503 page for one project, 401 without the right credential.
    const ca = ensureCa(join(dir, "ca-index"));
    const leaf = leafForHost(ca, "pypi.corp.example");
    const seen: Array<{ url: string; authorization: string | undefined }> = [];
    const index = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
      seen.push({ url: req.url ?? "", authorization: req.headers["authorization"] });
      if (req.headers["authorization"] !== basic(`builder:${PIP_PW}`)) {
        res.writeHead(401, { "www-authenticate": 'Basic realm="index"' });
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": "text/html" });
      res.end('<!DOCTYPE html><html><body><a href="/files/mandu_wire_fixture-1.0.0-py3-none-any.whl">mandu_wire_fixture-1.0.0-py3-none-any.whl</a></body></html>');
    });
    index.listen(0, "127.0.0.1");
    await once(index, "listening");
    const sites = MockSites.fromYaml([
      "hosts:", "  - host: pypi.corp.example", `    tls_to: 127.0.0.1:${(index.address() as AddressInfo).port}`, `    tls_ca: ${JSON.stringify(ca.certPath)}`, "",
    ].join("\n"));
    const caDir = join(dir, "mitm");
    const proxy = new NetProxy({ allowThisMachine: true,
      arbiter: new ArbiterClientAdapter(data, human), log: () => {}, sessionId: "sess-livepip", mockSites: sites, mitm: { caDir },
      attributeHolders: () => [{ procKey: "8000-1", ancestors: [] }],
    });
    const port = await proxy.listen(0);
    try {
      const reg = await human.registerSecret({ path: pipConf, home });
      assert.ok(reg.twin && !reg.twin.includes(PIP_PW), reg.reason);
      const twin = join(dir, "pip-twin.conf");
      writeFileSync(twin, reg.twin!);
      const sessionCa = join(caDir, "mandu-egress-ca.pem");
      const pip = (conf: string) => spawnAsync("python3", ["-m", "pip", "index", "versions", "mandu-wire-fixture"], {
        PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: join(dir, "pip-home"),
        PIP_CONFIG_FILE: conf, PIP_DISABLE_PIP_VERSION_CHECK: "1", PIP_NO_INPUT: "1", PIP_KEYRING_PROVIDER: "disabled",
        PIP_NO_CACHE_DIR: "1", HTTPS_PROXY: `http://127.0.0.1:${port}`, https_proxy: `http://127.0.0.1:${port}`,
        REQUESTS_CA_BUNDLE: sessionCa, SSL_CERT_FILE: sessionCa, PIP_RETRIES: "0", PIP_TIMEOUT: "10",
      });
      const r = await pip(twin);
      const diag = `\n--- pip (exit ${r.code}) ---\n${r.out}\n--- index saw ---\n${JSON.stringify(seen)}`;
      assert.equal(r.code, 0, `pip failed${diag}`);
      assert.match(r.out, /mandu-wire-fixture \(1\.0\.0\)/, diag);
      assert.ok(seen.length > 0 && seen.every((s) => s.authorization === basic(`builder:${PIP_PW}`)), `the index got the real password on every request${diag}`);
      assert.ok(!r.out.includes(PIP_PW), "pip printed no password");
      // The raw token (the twin before this change): Python's URL parser
      // refuses the brackets in the user information; nothing reaches the index.
      const rawTok = decodeURIComponent(/builder:([^@]+)@/.exec(reg.twin!)![1]!);
      const before = join(dir, "pip-raw-token.conf");
      writeFileSync(before, `[global]\nindex-url = https://builder:${rawTok}@pypi.corp.example/simple\n`);
      const n = seen.length;
      const old = await pip(before);
      assert.notEqual(old.code, 0, `the raw token in the URL: ${old.out}`);
      assert.equal(seen.length, n, "nothing reached the index");
      console.error(`live pip: ${r.out.trim().split("\n")[0]}; ${seen.length} request(s) to the index, all with the real password put back`);
    } finally {
      await proxy.close();
      index.close();
      data.close();
      human.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

function spawnAsync(cmd: string, args: string[], env: Record<string, string>): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    const c = spawn(cmd, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    c.stdout.on("data", (d: Buffer) => { out += d.toString("utf8"); });
    c.stderr.on("data", (d: Buffer) => { out += d.toString("utf8"); });
    c.on("close", (code) => resolve({ code: code ?? -1, out }));
  });
}
