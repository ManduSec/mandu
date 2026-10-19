/**
 * inspected-leg-port — a binding or wire grant with a port is held to that
 * port on every leg of the egress proxy (plan 10 §11.13.1, confidentiality.md
 * §2.1, 2026-10-17), over the REAL components: an ArbiterServer, the launch
 * HOME's `pip.conf` registered on the human socket as the launcher does, a
 * file held raw by a process (the taint leg), and the REAL NetProxy in its
 * production wiring (`new ArbiterClientAdapter(new ArbiterClient(data), new
 * ArbiterClient(human))`), with recording listeners as the oracle. Each
 * mock-site route serves its host on every port, so only the decision can
 * tell `:8443` from `:443`.
 *
 * Before: the TLS-inspected leg and the blind tunnel stated the CONNECT host
 * without its port, and the plain-HTTP leg dropped a default port. The
 * binding rule reads a destination with no port as "not said" and admits it
 * under a binding with a port, so a pip index password granted to
 * `pypi.corp.example:8443` (or `[2001:db8::1]:8443`) also went to port 443
 * of the same host. Now:
 *
 *   1. inspected leg: the ported grant is released at `:8443` and refused at
 *      `:443`, for a named host and an IPv6 literal; a portless grant is
 *      released at both (a binding with no port admits every port);
 *   2. plain-HTTP leg: an `http://` index granted to `:8080` is released
 *      there and refused at the default port 80;
 *   3. blind tunnel (no inspection): a process holding a file bound to
 *      `tunnel.example:8443` may open a tunnel there and not to `:443`;
 *   4. nothing reaches a host at a refused port.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { checkServerIdentity, connect as tlsConnect } from "node:tls";
import { connect as netConnect, isIP, type AddressInfo } from "node:net";
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
import type { ProcHolder } from "../../interceptors/net-proxy/src/conn-attr.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const OPENSSL = opensslAvailable();
const PORTED_PW = "portedPW_LEGPORT_7b";
const V6_PW = "v6PW_LEGPORT_2e";
const PORTLESS_PW = "portlessPW_LEGPORT_9a";
const HTTP_PW = "httpPW_LEGPORT_4c";
const HELD = "sk_live_LEGPORT_HELDKEY_55";
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

async function httpsRecorder(dir: string, host: string, got: Got) {
  const ca = ensureCa(join(dir, `ca-${host.replace(/[^a-z0-9.]/gi, "_")}`));
  const leaf = leafForHost(ca, host);
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => record(host, got, req, res));
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

/** CONNECT `target`; with `sessionCa`, TLS trusting it and checking the leaf
 *  names `name`, one GET; the status (the CONNECT's own on a refusal). */
function viaConnect(proxyPort: number, target: string, name: string, path: string, authorization: string, sessionCa?: string): Promise<number> {
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
      const tls = tlsConnect({
        socket: raw, ...(sessionCa ? { ca: sessionCa } : { rejectUnauthorized: false }),
        ...(isIP(name) ? { checkServerIdentity: (_h: string, cert: import("node:tls").PeerCertificate) => checkServerIdentity(name, cert) } : { servername: name }),
      }, () => {
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

test(
  "a binding or wire grant with a port is held to that port on the inspected leg, the plain leg and the blind tunnel; a portless one admits every port",
  { skip: !OPENSSL && "openssl unavailable", timeout: 90_000 },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-leg-port-"));
    const home = join(dir, "home");
    mkdirSync(join(home, ".config", "pip"), { recursive: true });
    const pipConf = join(home, ".config", "pip", "pip.conf");
    writeFileSync(pipConf, [
      "[global]",
      `index-url = https://builder:${PORTED_PW}@pypi.corp.example:8443/simple`,
      "extra-index-url =",
      `    https://builder:${V6_PW}@[2001:db8::1]:8443/simple`,
      `    https://builder:${PORTLESS_PW}@plain.corp.example/simple`,
      `    http://builder:${HTTP_PW}@http.corp.example:8080/simple`,
      "",
    ].join("\n"));
    const heldFile = join(dir, "ws", ".env");
    mkdirSync(join(dir, "ws"));
    writeFileSync(heldFile, `API_KEY=${HELD}\n`);
    const sock = join(dir, "arbiter.sock");
    const humanSock = join(dir, "human", "h.sock");
    const server = new ArbiterServer({
      socketPath: sock, humanSocketPath: humanSock, adminSocketPath: join(dir, "admin.sock"),
      dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"), log: () => {},
      adminPolicyDir: null, packDir: null, confidentiality: true, integrity: false,
      policyDocument: { version: 1, paths: [
        // No bindings: the pip releases rest on the registration's wire grants alone.
        { path: pipConf, level: "no-model" },
        { path: heldFile, level: "no-model", readers: ["ssh-add"], bindings: ["tunnel.example:8443"] },
      ] },
    });
    await server.listen();
    const data = new ArbiterClient(sock); await data.connect();
    const human = new ArbiterClient(humanSock); await human.connect();
    const got: Got = [];
    const pypi = await httpsRecorder(dir, "pypi.corp.example", got);
    const v6 = await httpsRecorder(dir, "2001:db8::1", got);
    const plainIdx = await httpsRecorder(dir, "plain.corp.example", got);
    const tunnel = await httpsRecorder(dir, "tunnel.example", got);
    const httpIdx = await httpRecorder("http.corp.example", got);
    const tls = (host: string, r: { port: number; caPath: string }) =>
      [`  - host: "${host}"`, `    tls_to: 127.0.0.1:${r.port}`, `    tls_ca: ${JSON.stringify(r.caPath)}`];
    const sites = MockSites.fromYaml([
      "hosts:",
      ...tls("pypi.corp.example", pypi),
      ...tls("2001:db8::1", v6),
      ...tls("plain.corp.example", plainIdx),
      ...tls("tunnel.example", tunnel),
      `  - host: "http.corp.example"`, `    to: 127.0.0.1:${httpIdx.port}`,
      "",
    ].join("\n"));
    const proxies: NetProxy[] = [];
    const start = async (sessionId: string, mitm: boolean, holders: () => ProcHolder[]): Promise<{ port: number; ca?: string }> => {
      const caDir = join(dir, `mitm-${sessionId}`);
      const proxy = new NetProxy({
        allowThisMachine: true, log: () => {}, sessionId, mockSites: sites, ...(mitm ? { mitm: { caDir } } : {}),
        arbiter: new NetProxyAdapter(data as unknown as NetProxyRealClient, human as never),
        attributeHolders: holders,
      });
      proxies.push(proxy);
      const port = await proxy.listen(0);
      return { port, ...(mitm ? { ca: readFileSync(join(caDir, "mandu-egress-ca.pem"), "utf8") } : {}) };
    };
    try {
      const reg = await human.registerSecret({ path: pipConf, home, sessionKey: "sess-port" });
      assert.ok(reg.twin, reg.reason);
      const syms = [...reg.twin!.matchAll(/builder:([^@]+)@/g)].map((m) => decodeURIComponent(m[1]!));
      assert.equal(syms.length, 4, reg.twin);
      const [portedSym, v6Sym, portlessSym, httpSym] = syms as [string, string, string, string];

      // 1. The inspected leg.
      const p = await start("sess-port", true, () => [{ procKey: "7000-1", ancestors: [] }]);
      const at = (target: string, name: string, sym: string) => viaConnect(p.port, target, name, "/simple/pkg/", basic(`builder:${sym}`), p.ca);
      assert.equal(await at("pypi.corp.example:8443", "pypi.corp.example", portedSym), 200, "the granted port");
      assert.equal(await at("pypi.corp.example:443", "pypi.corp.example", portedSym), 403, "another port of the same host");
      assert.equal(await at("[2001:db8::1]:8443", "2001:db8::1", v6Sym), 200, "the granted port (IPv6)");
      assert.equal(await at("[2001:db8::1]:443", "2001:db8::1", v6Sym), 403, "another port of the same address");
      assert.equal(await at("plain.corp.example:443", "plain.corp.example", portlessSym), 200, "a portless grant: the default port");
      assert.equal(await at("plain.corp.example:8443", "plain.corp.example", portlessSym), 200, "a portless grant: any port");
      assert.deepEqual(got.map((g) => [g.site, g.authorization]), [
        ["pypi.corp.example", basic(`builder:${PORTED_PW}`)],
        ["2001:db8::1", basic(`builder:${V6_PW}`)],
        ["plain.corp.example", basic(`builder:${PORTLESS_PW}`)],
        ["plain.corp.example", basic(`builder:${PORTLESS_PW}`)],
      ], "nothing reached a refused port");

      // 2. The plain-HTTP leg: the URL's port, and the default port 80 when it names none.
      assert.equal(await viaProxy(p.port, "http://http.corp.example:8080/simple/pkg/", basic(`builder:${httpSym}`)), 200);
      assert.equal(got[4]!.authorization, basic(`builder:${HTTP_PW}`));
      assert.equal(await viaProxy(p.port, "http://http.corp.example/simple/pkg/", basic(`builder:${httpSym}`)), 403, "port 80, not the granted 8080");
      assert.equal(await viaProxy(p.port, "http://http.corp.example:9090/simple/pkg/", basic(`builder:${httpSym}`)), 403);
      assert.equal(got.length, 5);

      // 3. The blind tunnel: a process holding a file bound to tunnel.example:8443.
      assert.equal((await human.decideSecretOpen({ path: heldFile, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "7100-1", session: "sess-tunnel" })).verdict, "raw");
      const t = await start("sess-tunnel", false, () => [{ procKey: "7100-1", ancestors: [] }]);
      assert.equal(await viaConnect(t.port, "tunnel.example:8443", "tunnel.example", "/", "Bearer none"), 200, "the bound port");
      assert.equal(await viaConnect(t.port, "tunnel.example:443", "tunnel.example", "/", "Bearer none"), 403, "another port: no tunnel");
      assert.equal(got.length, 6, "only the bound port's tunnel reached the host");

      // 4. THE ORACLE: each password reached only its own host.
      for (const [pw, site] of [[PORTED_PW, "pypi.corp.example"], [V6_PW, "2001:db8::1"], [HTTP_PW, "http.corp.example"]] as const) {
        const elsewhere = got.filter((g) => g.site !== site).map((g) => g.raw).join("\n");
        assert.ok(!elsewhere.includes(pw) && !elsewhere.includes(Buffer.from(`builder:${pw}`).toString("base64")), `${pw} reached only ${site}`);
      }
    } finally {
      for (const px of proxies) await px.close();
      for (const r of [pypi, v6, plainIdx, tunnel, httpIdx]) r.close();
      data.close();
      human.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
