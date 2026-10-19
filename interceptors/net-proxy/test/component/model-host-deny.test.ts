/**
 * model-host-deny — a real NetProxy under the model-host deny
 * (model-host-paths.ts; agent-sdks.md §4, "The model-host deny"):
 *   - TLS-inspected leg: a model host is terminated; `/v1/messages`,
 *     `/backend-api/codex/responses` and a dot-segment walk out of an
 *     allowed prefix are refused 403 with nothing sent upstream, while a
 *     listed account call reaches the host;
 *   - TLS inspection off: a CONNECT to a model host is refused whole;
 *   - plain leg: the same path rule;
 *   - deny off: the plain leg's passthrough is unchanged.
 * The model hosts are names a mock-sites host route sends to loopback TLS
 * listeners (the real curl through the proxy, the session CA trusted), so
 * nothing leaves the machine. The MockArbiter: no secret anywhere, so only
 * the path rule can refuse. Mandu-new (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { request as httpRequest } from "node:http";
import { connect as netConnect, type AddressInfo } from "node:net";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile, spawnSync } from "node:child_process";

import { NetProxy, type HttpForwarder } from "../../src/proxy.js";
import { MockArbiter } from "../../src/arbiter-client.js";
import { MockSites } from "../../src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";

const OPENSSL = opensslAvailable();
const HAS_CURL = spawnSync("curl", ["--version"], { stdio: "ignore" }).status === 0;
const SECRET = "sk-live-MODELHOSTDENY-canary-0123456789";
const noop = (): void => {};

/** A loopback HTTPS listener for `host` recording each request line. */
async function listener(dir: string, host: string) {
  const ca = ensureCa(join(dir, `ca-${host}`));
  const leaf = leafForHost(ca, host);
  const seen: string[] = [];
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      seen.push(`${req.method} ${req.url} ${Buffer.concat(chunks).toString("utf8")}`);
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"ok":true}');
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { seen, port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

function curl(args: string[]): Promise<{ code: string; body: string }> {
  return new Promise((resolve) => {
    execFile("curl", ["-sS", "-w", "\n%{http_code}", "--max-time", "20", ...args], (_e, out) => {
      const i = out.lastIndexOf("\n");
      resolve({ code: out.slice(i + 1).trim(), body: out.slice(0, i) });
    });
  });
}

function proxyConnect(proxyPort: number, target: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = netConnect(proxyPort, "127.0.0.1", () => sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let buf = "";
    sock.setEncoding("utf8");
    sock.on("data", (c: string) => {
      buf += c;
      if (buf.includes("\r\n\r\n")) { resolve(buf); sock.destroy(); }
    });
    sock.on("error", reject);
    setTimeout(() => reject(new Error("CONNECT timed out")), 5000).unref();
  });
}

function proxyPost(proxyPort: number, absoluteUrl: string, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(absoluteUrl);
    const r = httpRequest({ host: "127.0.0.1", port: proxyPort, method: "POST", path: absoluteUrl, headers: { host: u.host, "content-type": "application/json" } }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    r.on("error", reject);
    r.end(body);
  });
}

test(
  "TLS-inspected leg: a model call to a model host is refused before any byte reaches it; a listed account call goes through",
  { skip: !OPENSSL ? "openssl unavailable" : !HAS_CURL ? "curl is not installed" : false, timeout: 60_000 },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mdu-np-modelhost-"));
    const anthropic = await listener(dir, "api.anthropic.com");
    const platform = await listener(dir, "platform.claude.com");
    const chatgpt = await listener(dir, "chatgpt.com");
    const sites = MockSites.fromYaml([
      "hosts:",
      "  - host: api.anthropic.com", `    tls_to: 127.0.0.1:${anthropic.port}`, `    tls_ca: ${JSON.stringify(anthropic.caPath)}`,
      "  - host: platform.claude.com", `    tls_to: 127.0.0.1:${platform.port}`, `    tls_ca: ${JSON.stringify(platform.caPath)}`,
      "  - host: chatgpt.com", `    tls_to: 127.0.0.1:${chatgpt.port}`, `    tls_ca: ${JSON.stringify(chatgpt.caPath)}`,
      "",
    ].join("\n"));
    const arbiter = new MockArbiter();
    const caDir = join(dir, "mitm");
    const proxy = new NetProxy({ arbiter, log: noop, mockSites: sites, mitm: { caDir }, modelHostDeny: true, attributeHolders: () => [{ procKey: "4242-1", ancestors: [] }] });
    try {
      const port = await proxy.listen(0);
      const via = ["-x", `http://127.0.0.1:${port}`, "--cacert", join(caDir, "mandu-egress-ca.pem")];
      const body = JSON.stringify({ model: "claude-haiku", messages: [{ role: "user", content: SECRET }] });

      const refused: Array<[string, string[]]> = [
        ["Messages API", ["-X", "POST", "-d", body, "https://api.anthropic.com/v1/messages"]],
        ["Messages API with a query", ["-X", "POST", "-d", body, "https://api.anthropic.com/v1/messages?beta=true"]],
        ["a dot-segment walk out of an allowed prefix", ["--path-as-is", "-X", "POST", "-d", body, "https://api.anthropic.com/api/oauth/profile/../../v1/messages"]],
        ["platform.claude.com's Messages API", ["-X", "POST", "-d", body, "https://platform.claude.com/v1/messages"]],
        ["the ChatGPT backend's model turn", ["-X", "POST", "-d", body, "https://chatgpt.com/backend-api/codex/responses"]],
      ];
      for (const [name, args] of refused) {
        const r = await curl([...via, ...args]);
        assert.equal(r.code, "403", `${name}: ${r.body}`);
        assert.match(r.body, /model host .* is refused/, name);
        assert.ok(!r.body.includes(SECRET), `${name}: the refusal never echoes the body`);
      }
      assert.deepEqual(anthropic.seen, [], "nothing reached api.anthropic.com");
      assert.deepEqual(platform.seen, [], "nothing reached platform.claude.com");
      assert.deepEqual(chatgpt.seen, [], "nothing reached chatgpt.com");

      // The listed calls pass, through the same gate as any inspected request.
      assert.equal((await curl([...via, "https://api.anthropic.com/api/oauth/profile"])).code, "200");
      assert.equal((await curl([...via, "-X", "POST", "-d", "grant_type=refresh_token", "https://platform.claude.com/v1/oauth/token"])).code, "200");
      assert.equal((await curl([...via, "https://chatgpt.com/backend-api/wham/usage"])).code, "200");
      assert.deepEqual(anthropic.seen, ["GET /api/oauth/profile "]);
      assert.deepEqual(platform.seen, ["POST /v1/oauth/token grant_type=refresh_token"]);
      assert.deepEqual(chatgpt.seen, ["GET /backend-api/wham/usage "]);

      const blocked = (arbiter.emittedEvents as Array<{ action?: string; modelHost?: boolean }>).filter((e) => e.action === "blocked" && e.modelHost === true);
      assert.equal(blocked.length, refused.length, "every refusal is on the trace");
      assert.ok(!JSON.stringify(arbiter.emittedEvents).includes(SECRET), "the trace never carries the body");
    } finally {
      await proxy.close();
      anthropic.close();
      platform.close();
      chatgpt.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test("TLS inspection off: a CONNECT to a model host is refused whole (no path can be read)", async () => {
  const arbiter = new MockArbiter();
  const proxy = new NetProxy({ arbiter, log: noop, modelHostDeny: true, attributeHolders: () => [] });
  const port = await proxy.listen(0);
  try {
    for (const target of ["api.anthropic.com:443", "platform.claude.com:443", "api.openai.com:443", "chatgpt.com:443", "x.api.anthropic.com:8443"]) {
      const head = await proxyConnect(port, target);
      assert.match(head, /^HTTP\/1\.1 403/, target);
      assert.match(head, /TLS inspection is off/, target);
    }
  } finally {
    await proxy.close();
  }
});

test("plain leg: the same path rule; with the deny off the model host's passthrough is unchanged", async () => {
  const calls: string[] = [];
  const forwarder: HttpForwarder = async ({ url }) => {
    calls.push(url);
    return { status: 200, headers: { "content-type": "application/json" }, body: Buffer.from("{}") };
  };
  const on = new NetProxy({ arbiter: new MockArbiter(), log: noop, forwarder, modelHostDeny: true, attributeHolders: () => [] });
  const off = new NetProxy({ arbiter: new MockArbiter(), log: noop, forwarder, attributeHolders: () => [] });
  const pOn = await on.listen(0);
  const pOff = await off.listen(0);
  try {
    const refused = await proxyPost(pOn, "http://api.anthropic.com/v1/messages", JSON.stringify({ content: SECRET }));
    assert.equal(refused.status, 403);
    assert.match(refused.body, /POST \/v1\/messages on model host api\.anthropic\.com is refused/);
    assert.deepEqual(calls, [], "nothing forwarded");
    assert.equal((await proxyPost(pOn, "http://api.anthropic.com/api/hello", "")).status, 200);
    assert.deepEqual(calls, ["http://api.anthropic.com/api/hello"]);
    // Deny off (an `off`-mode launch): the old passthrough.
    assert.equal((await proxyPost(pOff, "http://api.anthropic.com/v1/messages", "{}")).status, 200);
    assert.equal(calls.length, 2);
  } finally {
    await on.close();
    await off.close();
  }
});

test("the identity publishes the deny (the launcher's reuse key); off → no field", async () => {
  const get = (p: number): Promise<Record<string, unknown>> => new Promise((resolve, reject) => {
    httpRequest({ host: "127.0.0.1", port: p, path: "/_mandu/identity" }, (res) => {
      let b = "";
      res.on("data", (c) => (b += c));
      res.on("end", () => resolve(JSON.parse(b) as Record<string, unknown>));
    }).on("error", reject).end();
  });
  const a = new NetProxy({ arbiter: new MockArbiter(), log: noop, identity: { service: "net-proxy", arbiterSock: "/s" }, modelHostDeny: true });
  const b = new NetProxy({ arbiter: new MockArbiter(), log: noop, identity: { service: "net-proxy", arbiterSock: "/s" } });
  const pa = await a.listen(0);
  const pb = await b.listen(0);
  try {
    assert.deepEqual((await get(pa))["modelHostDeny"], ["api.anthropic.com", "platform.claude.com", "api.openai.com", "chatgpt.com"]);
    assert.equal((await get(pb))["modelHostDeny"], undefined);
  } finally {
    await a.close();
    await b.close();
  }
});
