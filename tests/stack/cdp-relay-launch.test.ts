/**
 * cdp-relay-launch — a `--browser-cdp` launch's relay
 * (docs/design/agents/devtools-relay.md §6) as the launcher starts it: the
 * launcher's own `startCdpRelay` (launcher/src/services/cdp-relay.ts) spawns
 * the REAL relay process through the checkout layout, on a real
 * ArbiterServer's data and human sockets, and the agent reaches Chrome only
 * through the URL it is given (`BU_CDP_URL`, browser-cdp.ts).
 *
 * Against the relay's fake Chrome (always runs): the agent finds the
 * browser through the relay's /json/version, reads a registered value as its
 * placeholder, and the placeholder it types reaches a bound page as the
 * value; the relay's stop ends it.
 *
 * Against a real headless Chromium (self-SKIP without one, tests/lib/
 * chromium.ts): the path Browser Harness (jev-ultrafast's browser layer)
 * takes with BU_CDP_URL: /json/version, the browser endpoint,
 * Target.createTarget + Target.attachToTarget({flatten: true}), then every
 * command on the session id. The page's value reaches the agent as the
 * placeholder, and its typed placeholder lands as the real value.
 *
 * Secrets axes, explicit.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { startCdpRelay } from "../../launcher/src/services/cdp-relay.js";
import { Layout } from "../../launcher/src/services/layout.js";
import { realDeps } from "../../launcher/src/services/primitives.js";
import { browserCdpAgentEnv, parseBrowserCdp } from "../../launcher/src/browser-cdp.js";
import { FakeChrome } from "../../interceptors/cdp-relay/test/fake-chrome.js";
import { READY, chromiumBinary, startChromium, stopChromium } from "../lib/chromium.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const KEY = "sk_live_51CdpLaunchStackWq7Rt2Yp9Lm4";
const SESSION = "s-cdp-launch";

async function stack(bindings: string[]) {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-cdp-launch-"));
  const env = join(tmp, ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${env}`, "    level: no-model", `    bindings: [${bindings.join(", ")}]`, ""].join("\n"));
  const sock = join(tmp, "a.sock");
  const humanSock = join(tmp, "h", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  const reg = await human.registerSecret({ path: env, sessionKey: SESSION });
  human.close();
  assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
  return {
    tmp, sock, humanSock,
    field: `${reg.symbol}.STRIPE_KEY`,
    close: async () => { await server.close().catch(() => undefined); rmSync(tmp, { recursive: true, force: true }); },
  };
}

/** A DevTools client over Node's WebSocket, flat-session aware. */
async function cdp(wsUrl: string) {
  const ws = new WebSocket(wsUrl);
  await new Promise<void>((ok, bad) => {
    ws.addEventListener("open", () => ok(), { once: true });
    ws.addEventListener("error", () => bad(new Error(`no relay at ${wsUrl}`)), { once: true });
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

/** What Browser Harness does with BU_CDP_URL: /json/version's browser URL. */
async function browserUrl(buCdpUrl: string): Promise<string> {
  const v = (await (await fetch(`${buCdpUrl}/json/version`)).json()) as { webSocketDebuggerUrl: string };
  return v.webSocketDebuggerUrl;
}

const plan = (s: { sock: string; humanSock: string }, upstream: string) =>
  ({ browserCdp: parseBrowserCdp(upstream), arbiterSock: s.sock, arbiterHumanSock: s.humanSock, scopeId: SESSION });

test("the launcher's relay: spawned on the session's arbiter, found through BU_CDP_URL, masking reads and releasing at a bound page", async () => {
  const s = await stack(["vercel.com"]);
  const chrome = new FakeChrome({ url: "https://vercel.com/settings/env", pageText: `Your key: ${KEY}` });
  await chrome.listen();
  const relay = await startCdpRelay(plan(s, chrome.url), Layout.dev(REPO), s.tmp, realDeps);
  let a: Awaited<ReturnType<typeof cdp>> | null = null;
  try {
    const env = browserCdpAgentEnv(relay.url);
    assert.equal(env["BU_CDP_URL"], relay.url);
    const ws = await browserUrl(env["BU_CDP_URL"]!);
    assert.ok(ws.startsWith(`ws://${relay.host}:${relay.port}/`), `the agent is pointed at the relay: ${ws}`);
    a = await cdp(ws);
    const read = await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    const text = String(read.result?.result?.value);
    assert.ok(!text.includes(KEY), `no raw value: ${text}`);
    assert.match(text, /^Your key: \$MDU:/);
    const typed = await a.send("Input.insertText", { text: s.field });
    assert.deepEqual(typed.result, {}, JSON.stringify(typed));
    assert.deepEqual(chrome.typed, [KEY], "the bound page got the real value");
    assert.ok(!JSON.stringify(a.all).includes(KEY), "the agent never saw the value");
  } finally {
    a?.close();
    relay.stop();
    await chrome.close();
    await s.close();
  }
  // Stopped with the session: nothing answers on its port.
  await new Promise((r) => setTimeout(r, 300));
  await assert.rejects(fetch(`${relay.url}/json/version`));
});

const BIN = chromiumBinary();

test("a real headless Chromium, the Browser Harness path: browser endpoint, flat sessions, placeholders both ways", { skip: BIN === null ? "no headless Chromium (MANDU_TEST_CHROMIUM)" : false }, async () => {
  const s = await stack(["127.0.0.1"]);
  const page: Server = createServer((_q, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<html><head><title>Keys</title></head><body><p>Secret key ${KEY}</p><input id="f"></body></html>`);
  });
  await new Promise<void>((r) => page.listen(0, "127.0.0.1", () => r()));
  const pageUrl = `http://127.0.0.1:${(page.address() as AddressInfo).port}/`;
  const profile = mkdtempSync(join(tmpdir(), "mandu-cdp-launch-chromium-"));
  let chrome: ChildProcess | null = null;
  let relay: Awaited<ReturnType<typeof startCdpRelay>> | null = null;
  let a: Awaited<ReturnType<typeof cdp>> | null = null;
  try {
    const started = await startChromium(BIN!, profile, "about:blank");
    chrome = started.proc;
    relay = await startCdpRelay(plan(s, `http://127.0.0.1:${started.port}`), Layout.dev(REPO), s.tmp, realDeps);
    a = await cdp(await browserUrl(browserCdpAgentEnv(relay.url)["BU_CDP_URL"]!));
    const target = await a.send("Target.createTarget", { url: pageUrl });
    const targetId = String(target.result?.targetId);
    const att = await a.send("Target.attachToTarget", { targetId, flatten: true });
    const sid = String(att.result?.sessionId);
    assert.ok(sid.length > 0, JSON.stringify(att));
    for (let i = 0; i < 150; i++) {
      const ready = await a.send("Runtime.evaluate", { expression: READY, returnByValue: true }, sid);
      if (ready.result?.result?.value === true) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    const read = await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true }, sid);
    const text = String(read.result?.result?.value);
    assert.ok(!text.includes(KEY), `no raw value: ${text}`);
    assert.match(text, /Secret key \$MDU:/);

    await a.send("Runtime.evaluate", { expression: "document.getElementById('f').focus()" }, sid);
    const typed = await a.send("Input.insertText", { text: s.field }, sid);
    assert.deepEqual(typed.result, {}, JSON.stringify(typed));
    const back = await a.send("Runtime.evaluate", { expression: "document.getElementById('f').value", returnByValue: true }, sid);
    assert.match(String(back.result?.result?.value), /^\$MDU:/, "the agent reads its field as the placeholder");
    // Chrome itself, past the relay: the real value.
    const direct = await cdp(`ws://127.0.0.1:${started.port}/devtools/page/${targetId}`);
    const real = await direct.send("Runtime.evaluate", { expression: "document.getElementById('f').value", returnByValue: true });
    direct.close();
    assert.equal(real.result?.result?.value, KEY, "the page holds the real value");
    assert.ok(!JSON.stringify(a.all).includes(KEY), "nothing the agent got carried the value");
    await a.send("Target.closeTarget", { targetId });
  } finally {
    a?.close();
    relay?.stop();
    await stopChromium(chrome, profile);
    page.close();
    await s.close();
  }
});
