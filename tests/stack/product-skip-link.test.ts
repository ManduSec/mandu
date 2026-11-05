/**
 * product-skip-link.test — the first Tab on the product page shows "Skip to
 * the page", and Enter on it passes the top bar, in a real headless Chromium
 * over the REAL components (dashboard.md §4.25 *A page change moves the
 * focus*, *Skip to the page*). Mandu-new.
 *
 * Until 2026-10-28 a first load (a typed address, a bookmark, a refresh)
 * left the focus at the top of the document, and the first Tabs walked the
 * brand and the seven page links, then the status link, before the page: 8
 * to 10 presses to the first Approve. A plain `<a href="#main">` would not
 * do: the router reads a fragment as a new visit, and on Rules and Settings
 * as a card to land at. Here a real ArbiterServer (`secrets`) with a
 * registered `.env` whose key its real egress gate stops at a host no rule
 * binds it to, so one question waits; a real DashboardServer over the
 * production adapter (`makeApprovalsArbiter`); and a headless Chromium
 * driven over the DevTools protocol (scripts/tour-screenshots.mjs), signed
 * in, with real key presses. On Home, Approvals, Rules and Settings, at
 * 1280 and 390 px:
 *
 *   K1  before any key the link is clipped to a 1 px box, and the focus is
 *       on <body>;
 *   K2  the first Tab focuses it; it is seen (a box of words inside the
 *       window, over the top bar), and the bar keeps its height;
 *   K3  Enter gives the focus to the page's <h1>: the address, the history
 *       and the scroll stay;
 *   K4  the next Tab lands on a control of the page, never the top bar;
 *   K5  in print the link is not drawn, even with the focus;
 *   K6  the oracle: no page drawn here carries the key or a token.
 *
 * Self-SKIPs without a Chromium (scripts/tour-screenshots.mjs probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell, or one on
 * PATH). Axes: secrets (stated).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, ADMIN_TOKEN, SESSION_SECRET } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const browser = tour.probeBrowser({});

const KEY_VALUE = `sk_live_skipLinkCanary_${process.pid}_5e2a`;
const SESSION = `skip-link-${process.pid}`;
const WIDTHS = [1280, 390];
/** Each page, and what says it has drawn. */
const PAGES = [
  { path: "/", ready: `document.getElementById("hero-headline").textContent !== "Checking…" && !!document.querySelector("#home-waiting .ask")` },
  { path: "/approvals", ready: `!!document.querySelector("#approvals-waiting .ask")` },
  { path: "/rules", ready: `!document.getElementById("rules-block").hidden` },
  { path: "/settings", ready: `!!document.getElementById("switch-protection") && !document.getElementById("switch-protection").disabled` },
];

/** Where the focus is, the link's box and the bar's, as the window shows them. */
const state = `(() => {
  const a = document.activeElement;
  const skip = document.getElementById("skip-link");
  const box = (r) => ({ left: r.left, right: r.right, top: r.top, bottom: r.bottom, width: r.width, height: r.height });
  const shown = [...document.querySelectorAll("#main > section[data-page]")].filter((s) => !s.hidden);
  return {
    focus: a === document.body ? "body" : a.id || a.tagName + ":" + (a.textContent || "").trim().slice(0, 40),
    tag: a.tagName, inMain: !!a.closest("#main"), inTop: !!a.closest("#top"), onHeading: shown.length === 1 && a === shown[0].querySelector("h1"),
    skip: box(skip.getBoundingClientRect()), skipDisplay: getComputedStyle(skip).display, ringed: skip.matches(":focus-visible"),
    bar: box(document.getElementById("top").getBoundingClientRect()),
    href: location.href, entries: history.length, y: window.scrollY, w: innerWidth, h: innerHeight,
  };
})()`;
interface Box { left: number; right: number; top: number; bottom: number; width: number; height: number }
interface State {
  focus: string; tag: string; inMain: boolean; inTop: boolean; onHeading: boolean;
  skip: Box; skipDisplay: string; ringed: boolean; bar: Box; href: string; entries: number; y: number; w: number; h: number;
}

test("the first Tab shows Skip to the page, and Enter on it then Tab lands in the page, past the top bar, in a real Chromium over the real arbiter and dashboard (secrets axes)", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 240_000,
}, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-skip-link-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath: join(tmp, "policy.yaml"), policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(socketPath);
  await gate.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production adapter is wired");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, secretsArbiter: wired.secrets,
    postureArbiter: wired.posture, auditArbiter: wired.audit,
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home"), HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  let proc: unknown = null;
  let cdp: Cdp | null = null;
  const pages: string[] = [];
  try {
    // One question waits: the key of a registered `.env`, at a host no rule binds it to.
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const symbol = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(symbol, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const d = await gate.desymbolizationDecision({ symbol, boundary: "network", destination: "api.stripe.com", sessionKey: SESSION, scheme: "https" });
    assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "the gate asks");

    const started = await tour.startBrowser(browser as string, join(tmp, "chrome"), process.env);
    proc = started.proc;
    cdp = await tour.Cdp.connect(started.wsUrl);
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const s = (method: string, params: object = {}) => cdp!.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const r = await s("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    };
    await s("Page.enable");
    await s("Runtime.enable");
    await s("Network.enable");
    // A headless page has the focus of its window, as a page in front does.
    await s("Emulation.setFocusEmulationEnabled", { enabled: true });
    const eq = ADMIN_COOKIE.indexOf("=");
    await s("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
    const settle = () => evaluate("new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(() => r(true), 150))))");
    const key = async (name: "Tab" | "Enter") => {
      const k = name === "Tab" ? { key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 } : { key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 };
      await s("Input.dispatchKeyEvent", { type: "keyDown", ...k, ...(name === "Enter" ? { text: "\r" } : {}) });
      await s("Input.dispatchKeyEvent", { type: "keyUp", ...k });
      await settle();
    };
    const read = () => evaluate(state) as Promise<State>;

    for (const width of WIDTHS) {
      await s("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 640 });
      for (const p of PAGES) {
        const at = `${p.path} at ${width}px`;
        await s("Page.navigate", { url: base + p.path });
        let ok = false;
        for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((r) => setTimeout(r, 100))) {
          try { ok = await evaluate(`document.readyState === "complete" && document.fonts.status === "loaded" && (${p.ready})`); } catch { /* navigating */ }
        }
        assert.ok(ok, `${at}: the page drew`);
        await settle();

        // K1: nothing pressed yet.
        const before = await read();
        assert.equal(before.focus, "body", `${at}: the first load leaves the focus on the page`);
        assert.ok(before.skip.width <= 1 && before.skip.height <= 1, `${at}: the link is clipped until it has the focus (${JSON.stringify(before.skip)})`);

        // K2: the first Tab.
        await key("Tab");
        const tabbed = await read();
        assert.equal(tabbed.focus, "skip-link", `${at}: the first Tab focuses Skip to the page, not ${tabbed.focus}`);
        const b = tabbed.skip;
        assert.ok(b.width > 40 && b.height > 16, `${at}: seen while focused (${JSON.stringify(b)})`);
        assert.ok(b.left >= 0 && b.top >= 0 && b.right <= tabbed.w && b.bottom <= tabbed.h, `${at}: inside the window (${JSON.stringify(b)})`);
        assert.ok(b.top < tabbed.bar.bottom, `${at}: over the top bar`);
        assert.equal(tabbed.ringed, true, `${at}: a keyboard focus, with its ring`);
        assert.equal(tabbed.bar.height, before.bar.height, `${at}: the bar keeps its height`);
        assert.equal(await evaluate(`document.elementFromPoint(${(b.left + b.right) / 2}, ${(b.top + b.bottom) / 2})?.id`), "skip-link", `${at}: drawn over the bar, not under it`);

        // K3: Enter.
        await key("Enter");
        const entered = await read();
        assert.equal(entered.onHeading, true, `${at}: Enter gives the focus to the page's heading, not ${entered.focus}`);
        assert.equal(entered.href, before.href, `${at}: the address stays`);
        assert.equal(entered.entries, before.entries, `${at}: no history entry`);
        assert.equal(entered.y, before.y, `${at}: no scroll`);
        assert.ok(entered.skip.width <= 1, `${at}: the link is clipped again`);

        // K4: the next Tab is in the page.
        await key("Tab");
        const next = await read();
        assert.equal(next.inTop, false, `${at}: the next Tab is not in the top bar (${next.focus})`);
        assert.equal(next.inMain, true, `${at}: the next Tab is a control of the page (${next.focus})`);
        assert.match(next.tag, /^(A|BUTTON|INPUT|SELECT|TEXTAREA|SUMMARY)$/, `${at}: a control (${next.focus})`);
        pages.push(await evaluate("document.documentElement.outerHTML + document.body.innerText"));
      }
    }

    // K5: in print the link is not drawn, even with the focus.
    await evaluate(`document.getElementById("skip-link").focus()`);
    await s("Emulation.setEmulatedMedia", { media: "print" });
    assert.equal((await read()).skipDisplay, "none", "print: no Skip to the page");
    await s("Emulation.setEmulatedMedia", { media: "" });
    assert.notEqual((await read()).skipDisplay, "none", "on screen it is drawn again");

    // K6: the oracle.
    assert.equal(pages.length, WIDTHS.length * PAGES.length, "every page was read");
    for (const page of pages) {
      assert.ok(!page.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: the key's value on a page");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
      assert.ok(!page.includes(ADMIN_TOKEN) && !page.includes(SESSION_SECRET), "no credential on a page");
    }
  } finally {
    cdp?.close();
    if (proc) await tour.stopProc(proc);
    await dashboard.close();
    gate.close();
    wired?.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
