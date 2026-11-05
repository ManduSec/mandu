/**
 * settings-notify-off.test — Settings › Notifications turns notifications
 * off and on in this browser across the REAL components (dashboard.md §4.25
 * *Notifications*). Mandu-new.
 *
 * Until 2026-10-19, once the browser's permission was granted the row read
 * "On. …" with no control, and a page cannot take a permission back: the
 * browser's site settings were the only way to stop the notifications.
 *
 * Here a real ArbiterServer runs at the `secrets` axes with a registered
 * key, and its real egress gate asks about it at hosts no rule binds it to;
 * a real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) serves the page, signed in. The page's
 * `Notification` is a recording stub with the permission granted:
 *
 *   T1  `/settings` (once the first poll primed this browser) shows
 *       *Turn off*; a press stores the choice, the row reads "Off in this
 *       browser. …", and the button, now *Turn on*, keeps the focus;
 *   T2  the gate asks; the next poll counts it in the tab title ("(1)
 *       Mandu …") and records it as seen, but nothing is shown;
 *   T3  *Turn on*; the gate asks again; the next poll shows exactly one
 *       notification, for the second ask, never the first;
 *   T4  the oracle: no page text nor notification carries the key's value
 *       or a token (`$MDU`).
 *
 * Since 2026-10-22 (§4.25 *Send a test*): T5 *Send a test* shows one
 * notification in fixed words and the row says "Sent. …"; in jsdom a
 * `Notification` constructor that throws (Chrome on Android, which shows
 * them only from a service worker) makes the row say this browser cannot
 * show them, in place of "On.". In Chromium the recording stub stands in
 * for the browser's own, as in T1-T4: headless Chromium reports its own
 * permission as denied even after `Browser.grantPermissions`.
 *
 * Once in jsdom over the served page and script (served-page.ts), and once
 * in a real headless Chromium over the DevTools protocol
 * (scripts/tour-screenshots.mjs, as settings-appearance.test does), where
 * the browser's own permission is granted too (`Browser.grantPermissions`).
 * Since 2026-10-26 (§4.25 *Only protection problems*): T6 the row's
 * "Notify me about" menu set to Only protection problems; a real ask is
 * counted and seen but not shown, and a session the real arbiter records
 * with protection failed (a leak-check record naming the key's value) shows
 * exactly one "Mandu: protection failed in …", in fixed words. In Chromium
 * the menu fits the row at 1280 and 390 px, clear of its two buttons.
 *
 * Since 2026-10-29 (§4.25 *No thanks on Home's offer*): T7 with the
 * permission `default`, Home's offer names the alarms too and has *No
 * thanks*; a press stores `mandu.home.notifyOfferHidden`, never asks the
 * browser, and moves the focus to the line's link to Settings ›
 * Notifications; after a reload there is no offer, a real ask still counts
 * in the tab title, and Settings' *Turn on* still asks the browser (and,
 * granted, clears the key). In Chromium the press is a real Enter and the
 * reload a real one; the offer keeps one row at 1280 px and wraps inside
 * its box at 390 px.
 *
 * Since 2026-10-30 (§4.25 *The button does what it says*): T8 Settings
 * drawn at `default` ("Off.", *Turn on*), then the permission granted under
 * it, as another tab's prompt does with no storage event; a press of the
 * row's *Turn on* leaves them on (no `mandu.home.notifyOff` stored, never
 * asking again), the row reads "On. …", and the next real ask shows exactly
 * one notification. Until then the press stored Nothing and none showed.
 *
 * The Chromium test self-SKIPs without a Chromium (probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell, or one on
 * PATH). Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { withTeardown } from "../lib/teardown.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const VALUE = `sk_live_notifyOffCanary_${process.pid}_0000000`;
const SESSION = "1791200000-413";
const OFF_KEY = "mandu.home.notifyOff";
const OFF_WORDS = "Off in this browser. The tab title still counts what waits.";
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  removeProfile: (dir: string) => void;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const browser = tour.probeBrowser({});

/** The recording stub, as page script: `window.__notes` holds what was shown. */
const STUB = `(() => {
  const notes = [];
  function N(title, o) { notes.push({ title, body: (o && o.body) || "", tag: (o && o.tag) || "" }); this.close = () => {}; }
  N.permission = "granted";
  N.requestPermission = () => Promise.resolve("granted");
  Object.defineProperty(window, "Notification", { value: N, configurable: true, writable: true });
  window.__notes = notes;
})();`;

/** Chrome on Android: granted, but the constructor throws. */
const THROWS = `(() => {
  function N() { throw new TypeError("Failed to construct 'Notification': Illegal constructor. Use ServiceWorkerRegistration.showNotification() instead."); }
  N.permission = "granted";
  N.requestPermission = () => Promise.resolve("granted");
  Object.defineProperty(window, "Notification", { value: N, configurable: true, writable: true });
})();`;
/** Permission `default`: `window.__asked` counts the prompts, each granted. */
const ASKING = `(() => {
  const notes = [];
  function N(title, o) { notes.push({ title, body: (o && o.body) || "", tag: (o && o.tag) || "" }); this.close = () => {}; }
  N.permission = "default";
  N.requestPermission = () => { window.__asked++; N.permission = "granted"; return Promise.resolve("granted"); };
  Object.defineProperty(window, "Notification", { value: N, configurable: true, writable: true });
  window.__notes = notes;
  window.__asked = 0;
})();`;
const OFFER_KEY = "mandu.home.notifyOfferHidden";
const OFFER_WORDS = "Get a notification on this computer when an agent needs your OK or protection fails.";
const LATER_WORDS = "You can turn them on later in Settings › Notifications.";
const TEST_TITLE = "Mandu: notifications work";
const TEST_BODY = "This is how Mandu tells you when an agent needs your OK.";
const SENT = /^Sent\. If nothing appeared, your computer may be set to Do Not Disturb or Focus/;

/** A fresh stack: arbiter (secrets axes) with the key registered, the
 *  dashboard over the production wiring, signed in; `ask(host)` has the
 *  real gate ask about the key at `host`. */
async function stack() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-notify-off-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(sock);
  await gate.connect();
  const vars = await gate.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: VALUE }], sessionKey: SESSION });
  const symbol = String(vars.vars[0]?.symbol);
  assert.match(symbol, /^\$MDU:nomodel_Env\[/);
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home") }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  return {
    tmp, base,
    /** A session the leak check counts: protection failed in it. */
    fail: async (session: string): Promise<void> => {
      await gate.emit({
        id: `leak-${session}`, sessionId: session, turn: 1, ts: new Date().toISOString(), seq: 0, callId: "toolu_leak", parentId: null,
        kind: "tool_result", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
        input: null, output: null, invariant: { violatedInvariant: true, detail: `un-symbolized span survived: STRIPE_API_KEY=${VALUE}` },
      } as never);
    },
    ask: async (host: string): Promise<string> => {
      const d = await gate.desymbolizationDecision({ symbol, boundary: "network", destination: host, sessionKey: SESSION, scheme: "https" });
      assert.equal(d.allow, false, host);
      assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, `${host}: the gate asks`);
      return String((d as { approvalId?: string }).approvalId);
    },
    close: async () => {
      await dashboard.close();
      wired.close();
      gate.close();
      await arbiter.close();
      tour.removeProfile(tmp); // the browser's profile is in it: stopProc has ended its whole group
    },
  };
}

function oracle(what: string, text: string) {
  assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${what} carries the key's value`);
  assert.doesNotMatch(text, /\$MDU/, `${what} carries no token`);
}

test("served page: Turn off in Settings, a real ask is counted and seen but not shown; Turn on, the next ask notifies once (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const s = await stack();
  try {
    const primed = (doc: any) => doc.defaultView.localStorage.getItem("mandu.home.notifyPrimed") === "1";
    await servedProductPage(s.base, "/settings", (doc) => primed(doc) && doc.getElementById("notify-enable").textContent === "Turn off", async (doc) => {
      const w = doc.defaultView;
      const notes = w.__notes as { title: string; body: string }[];
      const poll = () => {
        Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
        doc.dispatchEvent(new w.Event("visibilitychange"));
      };
      const seen = (): string[] => JSON.parse(w.localStorage.getItem("mandu.home.seenAsks") || "[]");
      // T1
      const btn = doc.getElementById("notify-enable");
      btn.focus();
      btn.click();
      assert.equal(w.localStorage.getItem(OFF_KEY), "1");
      assert.equal(doc.getElementById("notify-state").textContent, OFF_WORDS);
      assert.equal(btn.textContent, "Turn on");
      assert.equal(doc.activeElement, btn, "the button keeps the focus");
      // T2
      const first = await s.ask("api.stripe.com");
      poll();
      await waitWhile(() => !seen().includes(first));
      assert.ok(seen().includes(first), "the ask is recorded as seen");
      assert.match(doc.title, /^\(1\) Mandu\b/, "the tab title counts it");
      assert.equal(notes.length, 0, "off: nothing shown");
      // T3
      btn.click();
      assert.equal(btn.textContent, "Turn off");
      assert.equal(w.localStorage.getItem(OFF_KEY), null);
      const second = await s.ask("gist.github.com");
      poll();
      await waitWhile(() => !seen().includes(second));
      assert.match(doc.title, /^\(2\) Mandu\b/);
      assert.equal(notes.length, 1, "one notification, for the second ask only");
      assert.match(notes[0]!.title, /^Mandu: .+ needs your OK$/);
      assert.match(notes[0]!.body, /gist\.github\.com/, "it is the second ask's");
      // T4
      oracle("the served page", doc.body.textContent);
      for (const n of notes) oracle("a notification", n.title + n.body);
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: (w) => w.eval(STUB) });
  } finally {
    await s.close();
  }
});

test("in a real Chromium: Turn off in Settings, a real ask is counted and seen but not shown; Turn on, the next ask notifies once (secrets axes, explicit)", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const s = await stack();
  const { proc, wsUrl } = await tour.startBrowser(browser as string, join(s.tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  await withTeardown(async () => {
    await cdp.send("Browser.grantPermissions", { origin: s.base, permissions: ["notifications"] });
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const send = (method: string, params: object = {}) => cdp.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    };
    const until = async (what: string, expression: string) => {
      let ok = false;
      for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((r) => setTimeout(r, 100))) {
        try { ok = await evaluate(expression); } catch { /* navigating */ }
      }
      assert.ok(ok, what);
    };
    const row = () => evaluate(`(() => {
      const b = document.getElementById("notify-enable");
      return { label: b.textContent, hidden: b.hidden, focused: document.activeElement === b,
        state: document.getElementById("notify-state").textContent, off: localStorage.getItem(${JSON.stringify(OFF_KEY)}),
        title: document.title, notes: window.__notes, text: document.body.innerText };
    })()`);
    const poll = () => evaluate(`document.dispatchEvent(new Event("visibilitychange")), true`);
    const seen = (id: string) => `JSON.parse(localStorage.getItem("mandu.home.seenAsks") || "[]").includes(${JSON.stringify(id)})`;
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Network.enable");
    await send("Page.addScriptToEvaluateOnNewDocument", { source: STUB });
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: s.base, httpOnly: true, sameSite: "Strict" });
    await send("Page.navigate", { url: s.base + "/settings" });
    await until("/settings: primed, with Turn off", `localStorage.getItem("mandu.home.notifyPrimed") === "1" && document.getElementById("notify-enable")?.textContent === "Turn off"`);
    const texts: string[] = [];

    // T1: a real click, then the focus and the words.
    await evaluate(`(() => { const b = document.getElementById("notify-enable"); b.scrollIntoView({ block: "center" }); b.focus(); return true; })()`);
    await send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
    await send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
    await until("Enter turned them off", `document.getElementById("notify-enable").textContent === "Turn on"`);
    const off = await row();
    texts.push(off.text);
    assert.equal(off.off, "1", "stored in this browser");
    assert.equal(off.state, OFF_WORDS);
    assert.equal(off.focused, true, "the button keeps the focus");

    // T2: a real ask while off.
    const first = await s.ask("api.stripe.com");
    await poll();
    await until("the ask is recorded as seen", seen(first));
    const counted = await row();
    texts.push(counted.text);
    assert.match(counted.title, /^\(1\) Mandu\b/, "the tab title counts it");
    assert.deepEqual(counted.notes, [], "off: nothing shown");

    // T3: on again; the next ask notifies, once.
    await evaluate(`document.getElementById("notify-enable").click(), true`);
    await until("Turn on took", `document.getElementById("notify-enable").textContent === "Turn off"`);
    const second = await s.ask("gist.github.com");
    await poll();
    await until("the second ask is seen", seen(second));
    const on = await row();
    texts.push(on.text);
    assert.equal(on.off, null);
    assert.match(on.title, /^\(2\) Mandu\b/);
    assert.equal(on.notes.length, 1, "one notification, for the second ask only");
    assert.match(on.notes[0].title, /^Mandu: .+ needs your OK$/);
    assert.match(on.notes[0].body, /gist\.github\.com/);

    // T4: the oracle.
    for (const t of texts) oracle("a page", t);
    for (const n of on.notes) oracle("a notification", n.title + n.body);
  }, () => cdp.close(), () => tour.stopProc(proc), () => s.close());
});

test("served page: Only protection problems in Settings; a real ask is counted and seen but not shown, a session where protection failed notifies once (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const s = await stack();
  try {
    const primed = (doc: any) => doc.defaultView.localStorage.getItem("mandu.home.notifyPrimed") === "1"
      && doc.defaultView.localStorage.getItem("mandu.home.seenFailed") !== null;
    await servedProductPage(s.base, "/settings", (doc) => primed(doc) && !doc.getElementById("notify-kind-row").hidden, async (doc) => {
      const w = doc.defaultView;
      const notes = w.__notes as { title: string; body: string }[];
      const poll = () => {
        Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
        doc.dispatchEvent(new w.Event("visibilitychange"));
      };
      const seen = (): string[] => JSON.parse(w.localStorage.getItem("mandu.home.seenAsks") || "[]");
      // T6: the menu.
      const sel = doc.getElementById("notify-kind");
      assert.equal(sel.value, "all", "Everything by default");
      sel.focus();
      sel.value = "alarms";
      sel.dispatchEvent(new w.Event("change", { bubbles: true }));
      assert.equal(w.localStorage.getItem(OFF_KEY), "alarms");
      assert.match(doc.getElementById("notify-state").textContent, /^On for protection problems only\. .* the tab title still counts the questions waiting\.$/);
      assert.equal(doc.activeElement, sel, "the menu keeps the focus");
      // A real ask: counted and seen, not shown.
      const first = await s.ask("api.stripe.com");
      poll();
      await waitWhile(() => !seen().includes(first));
      assert.ok(seen().includes(first), "the ask is recorded as seen");
      assert.match(doc.title, /^\(1\) /, "the tab title counts it");
      assert.equal(notes.length, 0, "a question: nothing shown");
      // A session where protection failed: one notification.
      await s.fail(`notify-failed-${process.pid}`);
      for (let i = 0; i < 100 && notes.length === 0; i++) {
        poll();
        await waitWhile(() => notes.length === 0, 300);
      }
      assert.equal(notes.length, 1, notes.map((n) => n.title).join(" | "));
      assert.match(notes[0]!.title, /^Mandu: protection failed in .+$/);
      assert.equal(notes[0]!.body, "Something reached the AI unmasked. Open its page to see what.");
      poll();
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(notes.length, 1, "once");
      oracle("the served page", doc.body.textContent);
      for (const n of notes) oracle("a notification", n.title + n.body);
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: (w) => w.eval(STUB) });
  } finally {
    await s.close();
  }
});

test("served page: Send a test shows one notification in fixed words; a constructor that throws makes the row say this browser cannot show them (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const s = await stack();
  try {
    const ready = (doc: any) => doc.getElementById("notify-enable").textContent === "Turn off";
    // T5: a browser that shows them.
    await servedProductPage(s.base, "/settings", ready, async (doc) => {
      const notes = doc.defaultView.__notes as { title: string; body: string }[];
      const btn = doc.getElementById("notify-test");
      assert.equal(btn.hidden, false, "on: Send a test");
      assert.equal(btn.getAttribute("aria-label"), "Send a test notification");
      btn.focus();
      btn.click();
      assert.equal(notes.length, 1, "one notification");
      assert.equal(notes[0]!.title, TEST_TITLE);
      assert.equal(notes[0]!.body, TEST_BODY);
      assert.match(doc.getElementById("notify-test-result").textContent, SENT);
      assert.match(doc.getElementById("notify-state").textContent, /^On\. You get a notification/);
      assert.equal(doc.activeElement, btn, "the button keeps the focus");
      oracle("the served page", doc.body.textContent);
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: (w) => w.eval(STUB) });
    // T5: a browser whose constructor throws.
    await servedProductPage(s.base, "/settings", ready, async (doc) => {
      assert.match(doc.getElementById("notify-state").textContent, /^On\. /, "nothing known before one was tried");
      doc.getElementById("notify-test").click();
      assert.equal(doc.getElementById("notify-test-result").textContent,
        "This browser cannot show Mandu's notifications from this page. Use a desktop browser, or keep this tab open: the tab title still counts what waits.");
      assert.match(doc.getElementById("notify-state").textContent, /^On, but this browser cannot show them from this page\. /);
      oracle("the served page", doc.body.textContent);
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: (w) => w.eval(THROWS) });
  } finally {
    await s.close();
  }
});

test("in a real Chromium: Send a test, pressed with Enter, shows one notification in fixed words and the row says Sent. (secrets axes, explicit)", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const s = await stack();
  const { proc, wsUrl } = await tour.startBrowser(browser as string, join(s.tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  await withTeardown(async () => {
    await cdp.send("Browser.grantPermissions", { origin: s.base, permissions: ["notifications"] });
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const send = (method: string, params: object = {}) => cdp.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    };
    const until = async (what: string, expression: string) => {
      let ok = false;
      for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((r) => setTimeout(r, 100))) {
        try { ok = await evaluate(expression); } catch { /* navigating */ }
      }
      assert.ok(ok, what);
    };
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Network.enable");
    await send("Page.addScriptToEvaluateOnNewDocument", { source: STUB });
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: s.base, httpOnly: true, sameSite: "Strict" });
    await send("Page.navigate", { url: s.base + "/settings" });
    await until("/settings: on, with Send a test", `document.getElementById("notify-test")?.hidden === false`);

    // T5: two buttons fit the row, wide and on a phone: inside it, side by
    // side, and clear of the row's words.
    for (const width of [1280, 390]) {
      await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 500 });
      const g = await evaluate(`(() => {
        const r = (id) => { const b = document.getElementById(id).getBoundingClientRect(); return { l: b.left, r: b.right, t: b.top, b: b.bottom }; };
        const row = document.querySelector("#settings-notify-block .row").getBoundingClientRect();
        return { test: r("notify-test"), enable: r("notify-enable"), kind: r("notify-kind"), words: r("notify-state"), row: { l: row.left, r: row.right, t: row.top, b: row.bottom } };
      })()`);
      const apart = (a: any, b: any) => a.r <= b.l + 0.5 || b.r <= a.l + 0.5 || a.b <= b.t + 0.5 || b.b <= a.t + 0.5;
      for (const k of ["test", "enable"]) {
        assert.ok(g[k].l >= g.row.l - 0.5 && g[k].r <= g.row.r + 0.5, `${width}px: ${k} inside the row ${JSON.stringify(g)}`);
        assert.ok(apart(g[k], g.words), `${width}px: ${k} clear of the words ${JSON.stringify(g)}`);
      }
      assert.ok(apart(g.test, g.enable), `${width}px: the two buttons apart ${JSON.stringify(g)}`);
      // §4.25 *Only protection problems*: the menu too, clear of the words and both buttons.
      assert.ok(g.kind.l >= g.row.l - 0.5 && g.kind.r <= g.row.r + 0.5 && g.kind.b - g.kind.t > 10, `${width}px: the menu inside the row ${JSON.stringify(g)}`);
      for (const k of ["test", "enable", "words"]) assert.ok(apart(g.kind, g[k]), `${width}px: the menu clear of ${k} ${JSON.stringify(g)}`);
      assert.ok(Math.abs(g.test.t - g.enable.t) < 1, `${width}px: the two buttons side by side ${JSON.stringify(g)}`);
    }
    await send("Emulation.clearDeviceMetricsOverride");

    // T5: a real key press on the button.
    await evaluate(`(() => { const b = document.getElementById("notify-test"); b.scrollIntoView({ block: "center" }); b.focus(); return true; })()`);
    await send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
    await send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
    await until("Send a test answered", `!document.getElementById("notify-test-result").hidden`);
    const r = await evaluate(`(() => ({
      result: document.getElementById("notify-test-result").textContent,
      state: document.getElementById("notify-state").textContent,
      focused: document.activeElement === document.getElementById("notify-test"),
      notes: window.__notes, text: document.body.innerText,
    }))()`);
    assert.match(r.result, SENT);
    assert.match(r.state, /^On\. You get a notification/);
    assert.equal(r.focused, true, "the button keeps the focus");
    assert.deepEqual(r.notes, [{ title: TEST_TITLE, body: TEST_BODY, tag: "mandu-test" }], "one notification, in fixed words");
    oracle("a page", r.text);
  }, () => cdp.close(), () => tour.stopProc(proc), () => s.close());
});

test("served page: No thanks on Home's offer, then a reload: no offer, a real ask still counts, and Settings' Turn on still asks (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const s = await stack();
  try {
    // T7: the press.
    let stored: string | null = null;
    await servedProductPage(s.base, "/", (doc) => !doc.getElementById("notify-offer").hidden, async (doc) => {
      const w = doc.defaultView;
      assert.equal(doc.getElementById("notify-offer-words").textContent, OFFER_WORDS);
      const no = doc.getElementById("notify-offer-no");
      assert.equal(no.textContent, "No thanks");
      no.focus();
      no.click();
      stored = w.localStorage.getItem(OFFER_KEY);
      assert.equal(stored, "1", "stored in this browser");
      assert.equal(w.localStorage.getItem(OFF_KEY), null, "Settings' choice untouched");
      assert.equal(doc.getElementById("notify-offer").hidden, true);
      assert.equal(doc.getElementById("notify-offer-later").textContent, LATER_WORDS);
      const link = doc.getElementById("notify-offer-later-link");
      assert.equal(doc.activeElement, link, "the focus is on the link");
      assert.equal(new URL(link.href).pathname + new URL(link.href).hash, "/settings#notifications");
      assert.equal(w.__asked, 0, "the browser was never asked");
      oracle("the served page", doc.body.textContent);
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: (w) => w.eval(ASKING) });

    // T7: a reload (this browser's storage carried over), with a real ask waiting.
    await s.ask("api.stripe.com");
    const reload = (w: any) => { w.eval(ASKING); w.localStorage.setItem(OFFER_KEY, stored as string); };
    await servedProductPage(s.base, "/", (doc) => /^\(1\) /.test(doc.title), async (doc) => {
      assert.equal(doc.getElementById("notify-state").textContent, "Off.", "the controls were drawn");
      assert.equal(doc.getElementById("notify-offer").hidden, true, "no offer after the reload");
      assert.equal(doc.getElementById("notify-offer-later").hidden, true, "and no line");
      assert.match(doc.title, /^\(1\) Mandu\b/, "the real ask counts in the tab title");
      assert.equal(doc.defaultView.__notes.length, 0, "nothing shown: no permission");
      oracle("the served page", doc.body.textContent);
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: reload });

    // T7: Settings' Turn on still asks the browser, and granted clears the key.
    await servedProductPage(s.base, "/settings", (doc) => doc.getElementById("notify-state").textContent === "Off.", async (doc) => {
      const w = doc.defaultView;
      const btn = doc.getElementById("notify-enable");
      assert.equal(btn.textContent, "Turn on");
      btn.click();
      await waitWhile(() => w.__asked === 0 || w.localStorage.getItem(OFFER_KEY) !== null);
      assert.equal(w.__asked, 1, "Settings' Turn on asks the browser");
      assert.equal(w.localStorage.getItem(OFFER_KEY), null, "granted: No thanks is cleared");
      assert.match(doc.getElementById("notify-state").textContent, /^On\. /);
      oracle("the served page", doc.body.textContent);
      for (const n of w.__notes as { title: string; body: string }[]) oracle("a notification", n.title + n.body);
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: reload });
  } finally {
    await s.close();
  }
});

test("served page: Settings drawn at default, the permission granted under it; Turn on leaves them on and the next real ask notifies once (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const s = await stack();
  try {
    const primed = (doc: any) => doc.defaultView.localStorage.getItem("mandu.home.notifyPrimed") === "1";
    await servedProductPage(s.base, "/settings", (doc) => primed(doc) && doc.getElementById("notify-state").textContent === "Off.", async (doc) => {
      const w = doc.defaultView;
      const notes = w.__notes as { title: string; body: string }[];
      const btn = doc.getElementById("notify-enable");
      assert.equal(btn.textContent, "Turn on");
      // T8: Allow in another tab; the stored choice was already Everything, so no storage event.
      w.Notification.permission = "granted";
      btn.focus();
      btn.click();
      await waitWhile(() => doc.getElementById("notify-state").textContent === "Off.");
      assert.equal(w.localStorage.getItem(OFF_KEY), null, "Turn on stored Everything, not Nothing");
      assert.equal(w.__asked, 0, "granted already: the browser was not asked");
      assert.match(doc.getElementById("notify-state").textContent, /^On\. You get a notification/);
      assert.equal(btn.textContent, "Turn off");
      assert.equal(doc.activeElement, btn, "the button keeps the focus");
      const ask = await s.ask("api.stripe.com");
      Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
      doc.dispatchEvent(new w.Event("visibilitychange"));
      const seen = (): string[] => JSON.parse(w.localStorage.getItem("mandu.home.seenAsks") || "[]");
      await waitWhile(() => !seen().includes(ask));
      assert.equal(notes.length, 1, "exactly one notification, for the new ask");
      assert.match(notes[0]!.title, /^Mandu: .+ needs your OK$/);
      assert.match(notes[0]!.body, /api\.stripe\.com/);
      oracle("the served page", doc.body.textContent);
      for (const n of notes) oracle("a notification", n.title + n.body);
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: (w) => w.eval(ASKING) });
  } finally {
    await s.close();
  }
});

test("in a real Chromium: Home's offer keeps one row at 1280 px and wraps in its box at 390 px; No thanks by Enter, then a real reload: no offer (secrets axes, explicit)", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const s = await stack();
  const { proc, wsUrl } = await tour.startBrowser(browser as string, join(s.tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  await withTeardown(async () => {
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const send = (method: string, params: object = {}) => cdp.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    };
    const until = async (what: string, expression: string) => {
      let ok = false;
      for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((r) => setTimeout(r, 100))) {
        try { ok = await evaluate(expression); } catch { /* navigating */ }
      }
      assert.ok(ok, what);
    };
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Network.enable");
    await send("Page.addScriptToEvaluateOnNewDocument", { source: ASKING });
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: s.base, httpOnly: true, sameSite: "Strict" });
    await send("Page.navigate", { url: s.base + "/" });
    await until("Home: the offer", `document.getElementById("notify-offer")?.hidden === false`);

    // T7: the layout. Words and both buttons inside the dashed box, apart;
    // the two buttons side by side; at 1280 px one row.
    for (const width of [1280, 390]) {
      await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 500 });
      const g = await evaluate(`(() => {
        const r = (id) => { const b = document.getElementById(id).getBoundingClientRect(); return { l: b.left, r: b.right, t: b.top, b: b.bottom }; };
        return { box: r("notify-offer"), words: r("notify-offer-words"), no: r("notify-offer-no"), on: r("notify-offer-btn"),
          scroll: document.documentElement.scrollWidth, view: document.documentElement.clientWidth };
      })()`);
      const apart = (a: any, b: any) => a.r <= b.l + 0.5 || b.r <= a.l + 0.5 || a.b <= b.t + 0.5 || b.b <= a.t + 0.5;
      const inside = (a: any) => a.l >= g.box.l - 0.5 && a.r <= g.box.r + 0.5 && a.t >= g.box.t - 0.5 && a.b <= g.box.b + 0.5;
      for (const k of ["words", "no", "on"]) assert.ok(inside(g[k]), `${width}px: ${k} inside the offer ${JSON.stringify(g)}`);
      for (const k of ["no", "on"]) assert.ok(apart(g[k], g.words), `${width}px: ${k} clear of the words ${JSON.stringify(g)}`);
      assert.ok(apart(g.no, g.on), `${width}px: the two buttons apart ${JSON.stringify(g)}`);
      assert.ok(Math.abs(g.no.t - g.on.t) < 1 && g.no.r <= g.on.l, `${width}px: No thanks then Turn on, side by side ${JSON.stringify(g)}`);
      assert.ok(g.scroll <= g.view, `${width}px: nothing wider than the page ${JSON.stringify(g)}`);
      if (width === 1280) {
        const mid = (g.on.t + g.on.b) / 2;
        assert.ok(mid > g.words.t && mid < g.words.b, `1280px: one row ${JSON.stringify(g)}`);
      }
    }
    await send("Emulation.clearDeviceMetricsOverride");

    // T7: a real Enter on No thanks.
    await evaluate(`(() => { const b = document.getElementById("notify-offer-no"); b.scrollIntoView({ block: "center" }); b.focus(); return true; })()`);
    await send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
    await send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
    await until("No thanks took", `document.getElementById("notify-offer").hidden`);
    const after = await evaluate(`(() => ({
      stored: localStorage.getItem(${JSON.stringify(OFFER_KEY)}), asked: window.__asked,
      line: document.getElementById("notify-offer-later").innerText,
      focused: document.activeElement === document.getElementById("notify-offer-later-link"),
      text: document.body.innerText,
    }))()`);
    assert.equal(after.stored, "1");
    assert.equal(after.asked, 0, "the browser was never asked");
    assert.equal(after.line, LATER_WORDS);
    assert.equal(after.focused, true, "the focus is on the link, not on the body");
    oracle("a page", after.text);

    // T7: a real reload, with a real ask waiting.
    await s.ask("api.stripe.com");
    await send("Page.reload", { ignoreCache: true });
    await until("reloaded: the ask counted", `/^\\(1\\) Mandu\\b/.test(document.title) && document.getElementById("notify-state")?.textContent === "Off."`);
    const reloaded = await evaluate(`(() => ({
      offer: document.getElementById("notify-offer").hidden, line: document.getElementById("notify-offer-later").hidden,
      notes: window.__notes, text: document.body.innerText,
    }))()`);
    assert.equal(reloaded.offer, true, "no offer after the reload");
    assert.equal(reloaded.line, true, "and no line");
    assert.deepEqual(reloaded.notes, []);
    oracle("a page", reloaded.text);
  }, () => cdp.close(), () => tour.stopProc(proc), () => s.close());
});
