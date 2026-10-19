/**
 * section-links.test — an address that names a card of Rules or Settings
 * (`/rules#who`, `/settings#prompt-filters`) opens the PRODUCT page at that
 * card, its heading at the top of the window and focused, in a real headless
 * Chromium over the REAL components (dashboard.md §4.25 *Section links*).
 * Mandu-new.
 *
 * Until 2026-10-18 no card had an address: the page read no hash, and every
 * link to a card, opened in a new tab, landed at the top of a page up to
 * 2,938 px tall at 1280 px.
 *
 * Here a real ArbiterServer (secrets) with six file rules in policy.yaml and
 * a registered key, a real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`), and a headless Chromium driven over the DevTools
 * protocol (scripts/tour-screenshots.mjs, Node's own WebSocket), signed in
 * with the dashboard's session cookie. At 1280×800 and at 390×844:
 *
 *   L1  `/rules#who` and `/settings#prompt-filters` open with that card's
 *       heading focused, the card at the top of the window (or the page
 *       scrolled to its end, when it ends less than a window below the
 *       card), the heading in view, the hash still in the address;
 *   L2  the row of links under each title is in the page's flow (never
 *       sticky or fixed), a link per card (five on Rules, six on Settings
 *       since Appearance, 2026-10-18), inside the page's width;
 *   L3  the oracle: no page carries the registered key or a token.
 *
 * Self-SKIPs without a Chromium (scripts/tour-screenshots.mjs probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell, or one on
 * PATH). Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NO_ADMIN_LAYER, setAdminLayer } from "../../arbiter/policy/admin-layer.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => setAdminLayer(NO_ADMIN_LAYER));

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const browser = tour.probeBrowser({});

const KEY = "sk_live_sectionLinksRegisteredCanary0000001";
const RULES = 6;
const VIEWS = [
  { width: 1280, height: 800, mobile: false },
  { width: 390, height: 844, mobile: true },
];
const CASES = [
  { path: "/rules#who", page: "rules", card: "by-who-block", head: "by-who-title", links: 5 },
  { path: "/settings#prompt-filters", page: "settings", card: "settings-prompt-block", head: "settings-prompt-title", links: 6 },
];

test("an address naming a card of Rules or Settings opens there, its heading focused at the top, in a real Chromium over the real arbiter; no value on the page", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-section-links-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const rules = Array.from({ length: RULES }, (_, i) => `  - { path: "${join(home, `proj${i}`, "secret.txt")}", level: no-model }`).join("\n");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n${rules}\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null, workspaceScan: { env: {}, discovery: { installEnv: {}, selfDir: null } },
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home") }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const { proc, wsUrl } = await tour.startBrowser(browser as string, join(tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  const pages: string[] = [];
  try {
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const s = (method: string, params: object = {}) => cdp.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const r = await s("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    };
    await s("Page.enable");
    await s("Runtime.enable");
    await s("Network.enable");
    const eq = ADMIN_COOKIE.indexOf("=");
    await s("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
    await s("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });

    for (const view of VIEWS) {
      await s("Emulation.setDeviceMetricsOverride", { width: view.width, height: view.height, deviceScaleFactor: 1, mobile: view.mobile });
      for (const c of CASES) {
        const what = `${c.path} at ${view.width} px`;
        await s("Page.navigate", { url: base + c.path });
        let landed = false;
        for (const end = Date.now() + 30_000; Date.now() < end; await new Promise((r) => setTimeout(r, 150))) {
          try { landed = await evaluate(`document.readyState === "complete" && document.activeElement?.id === ${JSON.stringify(c.head)}`); } catch { /* navigating */ }
          if (landed) break;
        }
        assert.ok(landed, `${what}: the card's heading took the focus`);
        // The layout settles (fonts, the last reads).
        await evaluate("new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(() => r(true), 300))))");
        const m = await evaluate(`(() => {
          const card = document.getElementById(${JSON.stringify(c.card)});
          const head = document.getElementById(${JSON.stringify(c.head)});
          const nav = document.querySelector('#page-${c.page} .page-head nav.section-links');
          const max = document.scrollingElement.scrollHeight - innerHeight;
          const ch = card.getBoundingClientRect(), hh = head.getBoundingClientRect();
          return {
            top: Math.round(ch.top), scrollY: Math.round(scrollY), max: Math.round(max), innerHeight,
            headTop: Math.round(hh.top), headBottom: Math.round(hh.bottom), hidden: card.hidden,
            focus: document.activeElement?.id, address: location.pathname + location.hash,
            navPosition: getComputedStyle(nav).position, navLinks: nav.querySelectorAll('a').length,
            navOver: Math.round(nav.scrollWidth - nav.clientWidth), pageOver: Math.round(document.scrollingElement.scrollWidth - innerWidth),
            text: document.body.innerText,
          };
        })()`);
        pages.push(m.text);
        // L1
        assert.equal(m.hidden, false, `${what}: the card is shown`);
        assert.equal(m.focus, c.head, `${what}: its heading keeps the focus`);
        assert.equal(m.address, c.path, `${what}: the address keeps its hash`);
        assert.ok(m.scrollY > 0, `${what}: the page scrolled to the card (${JSON.stringify(m)})`);
        assert.ok(Math.abs(m.top) <= 1 || m.scrollY >= m.max - 1, `${what}: the card is at the top, or the page at its end (${JSON.stringify({ top: m.top, scrollY: m.scrollY, max: m.max })})`);
        assert.ok(m.headTop >= 0 && m.headBottom <= m.innerHeight, `${what}: the heading is in view (${m.headTop}–${m.headBottom} of ${m.innerHeight})`);
        // L2
        assert.equal(m.navPosition, "static", `${what}: the row is in the page's flow`);
        assert.equal(m.navLinks, c.links, `${what}: a link per card`);
        assert.ok(m.navOver <= 0 && m.pageOver <= 0, `${what}: the row wraps inside the page (${m.navOver}, ${m.pageOver})`);
      }
    }

    // L3: the oracle.
    assert.equal(pages.length, VIEWS.length * CASES.length, "every page was read");
    for (const p of pages) {
      assert.ok(!p.includes(KEY), "no page carries the registered key");
      assert.doesNotMatch(p, /\$MDU/, "nor a token");
    }
  } finally {
    cdp.close();
    await tour.stopProc(proc);
    await dashboard.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
