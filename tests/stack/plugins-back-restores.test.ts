/**
 * plugins-back-restores e2e — Back to the Plugins page returns to where you
 * were, not the page's top (dashboard.md §4.25 *Back and Forward keep your
 * place*, §4.25aj), across the REAL components, laid out as `mandu serve`'s
 * pool lays out its attachment sessions (as plugins-page.test.ts does): a
 * real ArbiterServer on the `secrets` axes, one attachment per OpenClaw
 * agent (`beginAttachment`, kind `openclaw-plugin`), a real anthropic-proxy
 * in its production wiring answering for each, the pool's records and the
 * declared file, and a real DashboardServer over the production
 * ArbiterEventSource, signed in, in a real headless Chromium. Mandu-new.
 *
 * Until 2026-10-31 (#243) Plugins was the one page that opened at its top on
 * Back: with several attached agents, each card a screen on a phone, the
 * person scrolled to find their card again after every look at a session.
 *
 * Six attached agents, a card each, so the page scrolls at both widths. At
 * 390 px (a phone) and at 1280 px:
 *
 *   L1  the page scrolled more than a screen down, the last card's *Open
 *       its session* on the screen (300 px down, as far as the page lets
 *       it be), and followed; the session's page opens, its back link "Back to
 *       Plugins";
 *   L2  "Back to Plugins": Plugins within 3 px of where it was, the last
 *       card on the screen;
 *   L3  a top-bar link to Plugins (from Home) opens it at its top;
 *   L4  the oracle: no drawn page carries the secret's value or a token.
 *
 * Self-SKIPs without a Chromium (probeBrowser: MANDU_TOUR_BROWSER,
 * CHROME_PATH, a Playwright headless shell).
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ATTACHMENT_COVERAGE } from "../../launcher/src/confinement-posture.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { PluginsVM } from "../../dashboard/src/view-model/plugins.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const chromium = tour.probeBrowser({});

const AGENTS = ["main", "work", "ops", "research", "home", "build"];
const sessionOf = (agent: string) => `openclaw:${agent}`;
const LAST = sessionOf(AGENTS[AGENTS.length - 1]!);
const VALUE = `pluginsBackDbPass_${process.pid}_0001`;

test("in a real Chromium at 390 and 1280 px: Back to Plugins from the last card's Open its session lands within 3 px of where you were, the card on screen; a link opens Plugins at its top (secrets axes, explicit)", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-plugins-back-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "shop-app"), { recursive: true });
  const env = join(home, "shop-app", ".env");
  writeFileSync(env, `DB_PASSWORD=${VALUE}\n`);
  const runtime = join(tmp, "run");
  const declaredFile = join(tmp, "mandu-home", "state", "serve-attachments.json");
  mkdirSync(join(tmp, "mandu-home", "state"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, humanSocketPath: humanPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null, confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const service = new ArbiterClient(humanPath);
  await service.connect();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const human = new ArbiterClient(humanPath);
  await human.connect();
  const proxies: AnthropicProxy[] = [];
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    plugins: { runtimeBase: runtime, declaredFile },
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), HOME: home },
    log: () => {},
    ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const { proc, wsUrl } = await tour.startBrowser(chromium as string, join(tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  try {
    // ── The seed: the pool's order, per agent: the attachment, then its proxy ──
    const reg = await service.registerSecret({ path: env, home });
    assert.ok(reg.symbol, reg.reason);
    const declared: { kind: string; agent: string; session: string; port: number }[] = [];
    for (const agent of AGENTS) {
      const session = sessionOf(agent);
      const dir = join(runtime, "attachments", session);
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      const att = await service.beginAttachment({ sessionId: session, kind: "openclaw-plugin", coverage: ATTACHMENT_COVERAGE["openclaw-plugin"] });
      assert.equal(att.posture, "gated");
      const proxy = new AnthropicProxy({
        arbiter: new ArbiterClientAdapter(data, human), upstream: new MockUpstream({ sse: buildTextSse("ok") }).fetcher, sessionKey: session, log: () => {},
        identity: { service: "anthropic-proxy", sessionKey: session, arbiterSock: socketPath },
      });
      proxies.push(proxy);
      const port = await proxy.listen(0);
      writeFileSync(join(dir, "anthropic-proxy.port"), `${port}\n`, { mode: 0o600 });
      writeFileSync(join(dir, "pool.json"), JSON.stringify({ pid: process.pid, proxyPid: process.pid, session, startedAt: new Date().toISOString(), secrets: { found: 1, registered: 1, at: new Date().toISOString() } }), { mode: 0o600 });
      declared.push({ kind: "openclaw-plugin", agent, session, port });
    }
    writeFileSync(join(runtime, "attachments", "pool.json"), JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }), { mode: 0o600 });
    writeFileSync(declaredFile, JSON.stringify({ version: 1, attachments: declared }), { mode: 0o600 });
    const r = await pageFetch(`${base}/api/plugins`, { headers: { cookie: ADMIN_COOKIE } });
    const answer = await r.text();
    assert.equal(r.status, 200, answer);
    const cards = (JSON.parse(answer) as { plugins: PluginsVM }).plugins.hosts.find((h) => h.kind === "openclaw-plugin")!.cards;
    assert.equal(cards.length, AGENTS.length, "a card per attached agent");
    assert.ok(cards.every((c) => c.state === "attached" && c.links.session === c.session), "each attached, with its session page");

    // ── Chromium, signed in ─────────────────────────────────────────────────
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const send = (method: string, params: object = {}) => cdp.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const res = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (res.exceptionDetails) throw new Error(`page script failed: ${res.exceptionDetails.exception?.description ?? res.exceptionDetails.text}`);
      return res.result.value;
    };
    const until = async (what: string, expression: string) => {
      let ok = false;
      for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((res) => setTimeout(res, 100))) {
        try { ok = await evaluate(expression); } catch { /* navigating */ }
      }
      assert.ok(ok, what);
    };
    const pause = (ms: number) => new Promise((res) => setTimeout(res, ms));
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Network.enable");
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });

    const card = `[...document.querySelectorAll("#page-plugins .plugin-card")].find((c) => c.dataset.session === ${JSON.stringify(LAST)})`;
    const link = `${card}?.querySelector('.plugin-links a[data-page-link="agent"]')`;
    const bodies: string[] = [];
    for (const [width, height] of [[390, 700], [1280, 600]] as const) {
      await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 600 });
      await send("Page.navigate", { url: `${base}/plugins` });
      await until(`${width} px: Plugins draws every card`, `location.pathname === "/plugins" && !document.getElementById("page-plugins").hidden && document.querySelectorAll("#page-plugins .plugin-card").length === ${AGENTS.length} && !!${link} && document.fonts.status === "loaded"`);
      assert.equal(await evaluate(`${link}.textContent`), "Open its session");

      // ── L1: the last card's link, 300 px down the screen as far as the
      // page lets it be (the page ends below it), followed ────────────────
      await evaluate(`window.scrollTo(0, ${link}.getBoundingClientRect().top + window.scrollY - 300), true`);
      await pause(500); // past the page's own save of the scroll
      const before = await evaluate(`({ y: window.scrollY, top: ${link}.getBoundingClientRect().top, height: document.documentElement.scrollHeight, inner: window.innerHeight })`);
      assert.ok(before.y > before.inner, `${width} px: more than a screen down the page (${before.y} of ${before.height} px)`);
      assert.ok(before.top >= 300 && before.top < before.inner, `${width} px: the link on the screen, 300 px down or lower (${before.top})`);
      await evaluate(`${link}.click(), true`);
      await until(`${width} px: the session's page`, `!document.getElementById("page-agent").hidden && location.pathname === ${JSON.stringify("/agents/" + encodeURIComponent(LAST))}`);
      assert.equal(await evaluate(`document.getElementById("agent-back").textContent`), "Back to Plugins");
      bodies.push(await evaluate(`document.body.innerText`));

      // ── L2: Back to Plugins, where it was ─────────────────────────────────
      await evaluate(`document.getElementById("agent-back").click(), true`);
      await until(`${width} px: Plugins back`, `!document.getElementById("page-plugins").hidden && location.pathname === "/plugins" && !!${link}`);
      await pause(800); // past its read and the page's own landing
      const back = await evaluate(`({ y: window.scrollY, top: ${link}.getBoundingClientRect().top, card: ${card}.getBoundingClientRect().top, inner: window.innerHeight, body: document.body.innerText })`);
      assert.ok(Math.abs(back.y - before.y) <= 3, `${width} px: Plugins within 3 px of where it was: ${back.y}, was ${before.y}`);
      assert.ok(Math.abs(back.top - before.top) <= 3, `${width} px: the last card's link where it was on the screen (${back.top} px down, was ${before.top})`);
      assert.ok(back.card < back.inner, `${width} px: the last card in view (${back.card} px down)`);
      bodies.push(back.body);

      // ── L3: a link starts fresh ───────────────────────────────────────────
      await evaluate(`document.querySelector('#nav [data-page-link="home"]').click(), true`);
      await until(`${width} px: Home`, `!document.getElementById("page-home").hidden`);
      await evaluate(`document.querySelector('#nav [data-page-link="plugins"]').click(), true`);
      await until(`${width} px: Plugins by its link`, `!document.getElementById("page-plugins").hidden && location.pathname === "/plugins" && !!${link}`);
      await pause(800);
      assert.equal(await evaluate(`window.scrollY`), 0, `${width} px: a top-bar link opens Plugins at its top`);
    }

    // ── L4: the oracle ──────────────────────────────────────────────────────
    for (const b of [...bodies, answer]) {
      assert.ok(!b.includes(VALUE), "CONFIDENTIALITY VIOLATION: the secret's value on a drawn page or in the answer");
      assert.doesNotMatch(b, /\$MDU:/, "nor a token");
    }
  } finally {
    cdp.close();
    await tour.stopProc(proc);
    for (const p of proxies) await p.close();
    await dashboard.close();
    service.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
