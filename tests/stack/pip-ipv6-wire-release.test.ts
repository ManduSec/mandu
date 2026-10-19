/**
 * pip-ipv6-wire-release — a pip index on an IPv6 literal (plan 10 §11.13.1,
 * 2026-10-17) gets its wire grant, and its password is put back only at
 * that address, over the REAL components: an ArbiterServer, the launch
 * HOME's `pip.conf` and `PIP_INDEX_URL` registered on the human socket as
 * the launcher does, and the REAL NetProxy (TLS inspection on) in its
 * production wiring (`new ArbiterClientAdapter(new ArbiterClient(data), new
 * ArbiterClient(human))`), with recording listeners as the oracle.
 *
 * Before: the wire mark took only a plain host name, so an IPv6-literal index
 * (`https://user:PW@[2001:db8::1]:8443/simple`) got no grant (its password
 * bound nowhere: pip's placeholder refused at its own index, login failed,
 * no leak), the binding rule compared addresses as strings
 * (`[2001:DB8::1]` was not `[2001:db8:0::1]`), and the proxy dialed the
 * bracketed literal as a name and minted the inspecting leaf with a DNS
 * entry for it. Now:
 *
 *   1. the password is released at its index, CONNECT written in any
 *      spelling of the address (canonical text: case and zero runs);
 *   2. another address (a decoy routed like the index) gets a 403 and no
 *      byte; the env variable's password goes to its own index only, and
 *      each index's password never to the other's;
 *   3. an https index's password in plain HTTP to its own address is refused
 *      (`egress:secret-https-only`); an `http://` index on `[::1]` is
 *      released in plain HTTP at `[::1]` only;
 *   4. the decoys never see a password, a placeholder or its Basic pair.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { checkServerIdentity, connect as tlsConnect } from "node:tls";
import { connect as netConnect, type AddressInfo } from "node:net";
import { once } from "node:events";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { MockSites } from "../../interceptors/net-proxy/src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../interceptors/net-proxy/src/ca.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const OPENSSL = opensslAvailable();
const PIP_PW = "pipV6PW_IPV6WIRE_3d";
const LO_PW = "pipLoPW_IPV6WIRE_8a";
const ENV_PW = "envV6PW_IPV6WIRE_5c";
const basic = (pair: string): string => `Basic ${Buffer.from(pair, "utf8").toString("base64")}`;

type Got = Array<{ site: string; authorization: string | undefined; raw: string }>;

function record(site: string, got: Got, req: IncomingMessage, res: ServerResponse): void {
  const chunks: Buffer[] = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    got.push({ site, authorization: req.headers["authorization"], raw: JSON.stringify(req.headers) + req.url + Buffer.concat(chunks).toString("utf8") });
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
  });
}

/** An HTTPS listener whose certificate names the IPv6 address `addr`. */
async function httpsRecorder(dir: string, addr: string, got: Got) {
  const ca = ensureCa(join(dir, `ca-${addr.replace(/:/g, "_")}`));
  const leaf = leafForHost(ca, addr);
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => record(addr, got, req, res));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

async function httpRecorder(site: string, got: Got) {
  const server = createServer((req, res) => record(site, got, req, res));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, close: () => server.close() };
}

/** CONNECT `target`, TLS trusting the session CA and checking the leaf names
 *  `addr` (what pip's TLS does for an address), one GET. */
function viaTls(proxyPort: number, target: string, addr: string, sessionCa: string, path: string, authorization: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const raw = netConnect(proxyPort, "127.0.0.1", () => raw.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
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
      const tls = tlsConnect({ socket: raw, ca: sessionCa, checkServerIdentity: (_h, cert) => checkServerIdentity(addr, cert) }, () => {
        tls.write(`GET ${path} HTTP/1.1\r\nHost: ${target}\r\nAuthorization: ${authorization}\r\nConnection: close\r\n\r\n`);
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

/** A plain-HTTP GET through the forward proxy; the status and the body. */
function viaProxy(port: number, url: string, authorization: string): Promise<{ status: number; body: string }> {
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

test(
  "an IPv6-literal pip index: pip.conf and PIP_INDEX_URL passwords are put back at their own address only (any spelling of it), never at another address, never in plain HTTP unless the index is http://",
  { skip: !OPENSSL && "openssl unavailable", timeout: 60_000 },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-pip-v6-"));
    const home = join(dir, "home");
    mkdirSync(join(home, ".config", "pip"), { recursive: true });
    const pipConf = join(home, ".config", "pip", "pip.conf");
    // The index written in a non-canonical spelling; the http index on loopback.
    writeFileSync(pipConf, `[global]\nindex-url = https://builder:${PIP_PW}@[2001:DB8:0::1]:8443/simple\nextra-index-url = http://user:${LO_PW}@[::1]:8080/simple\n`);
    const sock = join(dir, "arbiter.sock");
    const humanSock = join(dir, "human", "h.sock");
    const server = new ArbiterServer({
      socketPath: sock, humanSocketPath: humanSock, adminSocketPath: join(dir, "admin.sock"),
      dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"), log: () => {},
      adminPolicyDir: null, packDir: null, confidentiality: true, integrity: false,
      // The arbiter's own HOME is not the launch's: label the file, no bindings
      // (every release below rests on the registration's wire grant alone).
      policyDocument: { version: 1, paths: [{ path: pipConf, level: "no-model" }] },
    });
    await server.listen();
    const data = new ArbiterClient(sock); await data.connect();
    const human = new ArbiterClient(humanSock); await human.connect();
    const got: Got = [];
    const index = await httpsRecorder(dir, "2001:db8::1", got);
    const decoy = await httpsRecorder(dir, "2001:db8::2", got);
    const envIndex = await httpsRecorder(dir, "2001:db8::3", got);
    const loIndex = await httpRecorder("::1", got);
    const loDecoy = await httpRecorder("::2", got);
    const plainIndex = await httpRecorder("plain:2001:db8::1", got);
    const tlsRoute = (addr: string, r: { port: number; caPath: string }) =>
      [`  - host: "${addr}"`, `    tls_to: 127.0.0.1:${r.port}`, `    tls_ca: ${JSON.stringify(r.caPath)}`];
    const sites = MockSites.fromYaml([
      "hosts:",
      ...tlsRoute("2001:db8::1", index), `    to: 127.0.0.1:${plainIndex.port}`,
      ...tlsRoute("2001:db8::2", decoy),
      ...tlsRoute("2001:db8::3", envIndex),
      `  - host: "::1"`, `    to: 127.0.0.1:${loIndex.port}`,
      `  - host: "::2"`, `    to: 127.0.0.1:${loDecoy.port}`,
      "",
    ].join("\n"));
    const caDir = join(dir, "mitm");
    const proxy = new NetProxy({
      allowThisMachine: true, log: () => {}, sessionId: "sess-pip-v6", mockSites: sites, mitm: { caDir },
      arbiter: new NetProxyAdapter(data as unknown as NetProxyRealClient, human as never),
      attributeHolders: () => [{ procKey: "7000-1", ancestors: [] }],
    });
    try {
      const port = await proxy.listen(0);
      const ca = readFileSync(join(caDir, "mandu-egress-ca.pem"), "utf8");

      // Registered as the launcher does at launch: the HOME file with the
      // home, the index variable, both on the human socket.
      const reg = await human.registerSecret({ path: pipConf, home, sessionKey: "sess-pip-v6" });
      assert.ok(reg.twin, reg.reason);
      for (const pw of [PIP_PW, LO_PW]) assert.ok(!reg.twin!.includes(pw), "the twin holds no password");
      assert.ok(reg.twin!.includes("@[2001:DB8:0::1]:8443/simple"), "the twin keeps the index URL as written");
      const [pipSym, loSym] = [...reg.twin!.matchAll(/(?:builder|user):([^@]+)@/g)].map((m) => decodeURIComponent(m[1]!));
      for (const s of [pipSym, loSym]) assert.match(s!, /^\$MDU:/);
      const env = await human.registerEnvSecrets({ vars: [{ name: "PIP_INDEX_URL", value: `https://me:${ENV_PW}@[2001:db8::3]:8443/simple` }], sessionKey: "sess-pip-v6" });
      const envSym = env.vars[0]?.symbol;
      assert.equal(typeof envSym, "string", JSON.stringify(env));

      // 1. The index, in three spellings of its address: the real password.
      for (const target of ["[2001:db8::1]:8443", "[2001:DB8::1]:8443", "[2001:0db8:0:0::1]:8443"]) {
        assert.equal(await viaTls(port, target, "2001:db8::1", ca, "/simple/pkg/", basic(`builder:${pipSym}`)), 200, target);
      }
      assert.deepEqual(got.map((g) => [g.site, g.authorization]), Array(3).fill(["2001:db8::1", basic(`builder:${PIP_PW}`)]));
      assert.equal(await viaTls(port, "[2001:db8::3]:8443", "2001:db8::3", ca, "/simple/", basic(`me:${envSym}`)), 200);
      assert.deepEqual(got[3], { ...got[3]!, site: "2001:db8::3", authorization: basic(`me:${ENV_PW}`) });

      // 2. Another address, routed like the index: 403, nothing reaches it.
      assert.equal(await viaTls(port, "[2001:db8::2]:8443", "2001:db8::2", ca, "/simple/", basic(`builder:${pipSym}`)), 403);
      assert.equal(await viaTls(port, "[2001:db8::2]:8443", "2001:db8::2", ca, "/simple/", basic(`me:${envSym}`)), 403);
      // Each index's password at the other's address: refused.
      assert.equal(await viaTls(port, "[2001:db8::3]:8443", "2001:db8::3", ca, "/simple/", basic(`builder:${pipSym}`)), 403);
      assert.equal(await viaTls(port, "[2001:db8::1]:8443", "2001:db8::1", ca, "/simple/", basic(`me:${envSym}`)), 403);
      assert.equal(got.length, 4, `nothing else reached any host: ${JSON.stringify(got.map((g) => g.site))}`);

      // 3. HTTPS only: the https index's password in plain HTTP to its own address.
      const plain = await viaProxy(port, "http://[2001:db8::1]:8443/simple/pkg/", basic(`builder:${pipSym}`));
      assert.equal(plain.status, 403);
      assert.match(plain.body, /egress:secret-https-only/);
      // The http:// index on [::1]: released in plain HTTP there, and only there.
      assert.equal((await viaProxy(port, "http://[::1]:8080/simple/pkg/", basic(`user:${loSym}`))).status, 200);
      assert.deepEqual(got[4], { ...got[4]!, site: "::1", authorization: basic(`user:${LO_PW}`) });
      assert.equal((await viaProxy(port, "http://[::2]:8080/simple/pkg/", basic(`user:${loSym}`))).status, 403);
      assert.equal((await viaProxy(port, "http://[2001:db8::1]:8443/simple/pkg/", basic(`user:${loSym}`))).status, 403);
      assert.equal(got.length, 5, `nothing else reached any host: ${JSON.stringify(got.map((g) => g.site))}`);

      // 4. THE ORACLE: no password, placeholder or Basic pair anywhere but its own index.
      const at = (site: string) => got.filter((g) => g.site !== site).map((g) => g.raw).join("\n");
      for (const [pw, user, site] of [[PIP_PW, "builder", "2001:db8::1"], [LO_PW, "user", "::1"], [ENV_PW, "me", "2001:db8::3"]] as const) {
        const elsewhere = at(site);
        assert.ok(!elsewhere.includes(pw) && !elsewhere.includes(Buffer.from(`${user}:${pw}`).toString("base64")), `${pw} reached only ${site}`);
      }
      assert.deepEqual(got.filter((g) => g.site === "2001:db8::2" || g.site === "::2" || g.site.startsWith("plain:")), [], "the decoys saw nothing");
    } finally {
      await proxy.close();
      for (const r of [index, decoy, envIndex, loIndex, loDecoy, plainIndex]) r.close();
      data.close();
      human.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
