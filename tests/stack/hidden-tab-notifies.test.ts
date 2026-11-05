/**
 * hidden-tab-notifies.test — a Mandu tab in the background keeps reading
 * Home, so a question that arrives while you work elsewhere notifies then,
 * and the tab's title counts it, across the REAL components (dashboard.md
 * §4.25 *A background tab keeps reading*). Mandu-new.
 *
 * Until 2026-10-25 the page's 10 s poll read only while the tab was
 * `visible`: a tab behind another tab notified on its first poll after you
 * came back to it, while the program that asked waited 60 s for your answer.
 *
 * A real ArbiterServer runs at the `secrets` axes with a policy file; a real
 * DashboardServer over the production adapter (`makeApprovalsArbiter`)
 * serves the page, signed in. The page's `Notification` is a recording stub
 * with the permission granted, its visibility is set by the test and its
 * 10 s tick is captured, so the test fires it:
 *
 *   H1  the first poll primes this browser, showing nothing;
 *   H2  the tab goes to the background; the real egress gate asks about a
 *       masked environment variable at a host no rule binds it to (a
 *       program's request waiting for your answer);
 *   H3  the next tick, still hidden, shows exactly one notification,
 *       "Mandu: <agent> needs your OK", and the title reads "(1) …"; the
 *       screen-reader line says nothing until the tab is shown again;
 *   H4  the oracle: neither the notification's title nor its body holds the
 *       registered secret's value or a `$MDU` token;
 *   H5  the question is answered through the real approvals route (Block):
 *       on the next tick, still hidden, the page closes that notification
 *       (§4.25 *A notification closes once nothing waits*).
 *
 * The question here comes from no recorded session, so Home knows no folder
 * and the title keeps its folderless form; the folder's wording is the unit
 * tests' (home-js-home.test.ts), the folder itself ask-from-session's.
 *
 * Once in jsdom over the served page and script (served-page.ts), and once
 * in a real headless Chromium over the DevTools protocol
 * (scripts/tour-screenshots.mjs, as proposal-notifies does), which
 * self-SKIPs without a Chromium (probeBrowser). Axes: secrets (stated; the
 * arbiter's confidentiality pinned ON).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests());

const VALUE = `ghp_hiddenTabNotifyCanary_${process.pid}_0000000000`;
const NAME = "HIDDEN_TAB_TOKEN";
const HOST = "exfil-hidden.example.net";
const SESSION = `1791500000-${process.pid}`;
const PRIMED_KEY = "mandu.home.notifyPrimed";
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const browser = tour.probeBrowser({});

/** As page script: the recording Notification stub (`window.__notes`, and
 *  the tags it was asked to close, `window.__closed`), the
 *  visibility the test sets (`window.__turn("hidden")`), and the page's
 *  10 s tick, kept for the test to fire (`window.__tick()`). */
const STUB = `(() => {
  const notes = [];
  const closed = [];
  function N(title, o) { notes.push({ title, body: (o && o.body) || "", tag: (o && o.tag) || "" }); this.close = () => { closed.push((o && o.tag) || ""); }; }
  N.permission = "granted";
  N.requestPermission = () => Promise.resolve("granted");
  Object.defineProperty(window, "Notification", { value: N, configurable: true, writable: true });
  window.__notes = notes;
  window.__closed = closed;
  let visibility = "visible";
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => visibility });
  Object.defineProperty(document, "hidden", { configurable: true, get: () => visibility === "hidden" });
  window.__turn = (state) => { visibility = state; document.dispatchEvent(new Event("visibilitychange")); };
  const realInterval = window.setInterval.bind(window);
  const ticks = [];
  window.setInterval = (fn, ms, ...rest) => { if (ms !== 10000) return realInterval(fn, ms, ...rest); ticks.push(fn); return 0; };
  window.__tick = () => { for (const fn of ticks) fn(); return ticks.length; };
})();`;

/** A fresh stack: arbiter (secrets axes) with a policy file, the dashboard
 *  over the production wiring, signed in; `ask()` has a program's send of a
 *  masked variable wait for the person, and returns its card. */
async function stack() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-hidden-tab-notifies-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath, policyPollMs: 0, adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(sock);
  await gate.connect();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc, fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  return {
    tmp, base,
    /** Block the question through the real route, as its card's button does. */
    block: async (id: string) => {
      const r = await pageFetch(`${base}/api/egress/approvals/${id}/deny`, { method: "POST", headers: { Cookie: ADMIN_COOKIE, "X-Mandu-Control": "1" } });
      assert.equal(r.status, 200, "the approvals route answers the Block");
    },
    ask: async () => {
      const vars = await gate.registerEnvSecrets({ vars: [{ name: NAME, value: VALUE }], sessionKey: SESSION });
      const sym = String(vars.vars[0]?.symbol);
      assert.match(sym, /^\$MDU:nomodel_Env\[/);
      const d = await gate.desymbolizationDecision({ symbol: sym, boundary: "network", destination: HOST, sessionKey: SESSION, scheme: "https" });
      assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "the send waits for the person");
      const vm = (await (await pageFetch(`${base}/api/home`, { headers: { Cookie: ADMIN_COOKIE } })).json()) as HomeVM;
      const card = vm.waiting.find((a) => a.id === String((d as { approvalId?: string }).approvalId));
      assert.ok(card, "Home lists the question");
      return card!;
    },
    close: async () => {
      await dashboard.close();
      wired.close();
      gate.close();
      await arbiter.close();
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

function oracle(notes: { title: string; body: string }[]) {
  for (const n of notes) {
    const words = n.title + "\n" + n.body;
    assert.ok(!words.includes(VALUE), `CONFIDENTIALITY VIOLATION: a notification carries the secret's value: ${words}`);
    assert.doesNotMatch(words, /\$MDU/, "a notification carries no token");
  }
}

test("served page: in a background tab, a question that arrives notifies on the next tick and the title counts it, naming no secret value or token (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const s = await stack();
  try {
    const primed = (doc: any) => doc.defaultView.localStorage.getItem(PRIMED_KEY) === "1";
    await servedProductPage(s.base, "/", primed, async (doc) => {
      const w = doc.defaultView;
      const notes = w.__notes as { title: string; body: string; tag: string }[];
      // H1
      assert.equal(notes.length, 0, "primed with nothing waiting");
      // H2
      w.__turn("hidden");
      const card = await s.ask();
      // H3
      assert.equal(w.__tick(), 1, "the page's one 10 s poll");
      await waitWhile(() => notes.length === 0);
      const shown = Array.from(notes, (n) => ({ title: n.title, body: n.body, tag: n.tag }));
      assert.equal(shown.length, 1, "exactly one notification");
      assert.equal(card.askerCwd, undefined, "no recorded session: no folder known");
      assert.equal(shown[0]!.title, `Mandu: ${card.agents[0] || "An agent"} needs your OK`);
      assert.equal(shown[0]!.tag, `mandu-ask-${card.id}`);
      assert.match(doc.title, /^\(1\) /, "the background tab's title counts it");
      assert.equal(doc.getElementById("top-announce").textContent, "", "nothing said to a page no one looks at");
      w.__turn("visible");
      await waitWhile(() => doc.getElementById("top-announce").textContent === "");
      assert.match(doc.getElementById("top-announce").textContent, /needs your OK\. 1 waiting in Approvals\.$/, "said on the return");
      assert.equal(notes.length, 1, "the return does not notify again");
      // H4
      oracle(shown);
      // H5
      const closed = w.__closed as string[];
      assert.deepEqual(Array.from(closed), [], "nothing closed while it waits");
      w.__turn("hidden");
      await s.block(card.id);
      w.__tick();
      await waitWhile(() => closed.length === 0);
      assert.deepEqual(Array.from(closed), [`mandu-ask-${card.id}`], "the answered question's notification closes");
      assert.equal(notes.length, 1, "and nothing new is shown");
    }, { headers: { Cookie: ADMIN_COOKIE }, beforeScripts: (w) => w.eval(STUB) });
  } finally {
    await s.close();
  }
});

test("in a real Chromium: in a background tab, a question that arrives notifies on the next tick and the title counts it, naming no secret value or token (secrets axes, explicit)", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const s = await stack();
  const { proc, wsUrl } = await tour.startBrowser(browser as string, join(s.tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  try {
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
    await send("Page.navigate", { url: s.base + "/" });
    // H1
    await until("the first poll primes this browser", `localStorage.getItem(${JSON.stringify(PRIMED_KEY)}) === "1"`);
    assert.deepEqual(await evaluate("window.__notes"), []);
    // H2
    await evaluate(`window.__turn("hidden"), true`);
    const card = await s.ask();
    // H3
    assert.equal(await evaluate("window.__tick()"), 1, "the page's one 10 s poll");
    await until("the hidden tab notifies", "window.__notes.length > 0");
    const after = await evaluate(`({ title: document.title, notes: window.__notes, said: document.getElementById("top-announce").textContent })`);
    assert.equal(after.notes.length, 1, "exactly one notification");
    assert.equal(card.askerCwd, undefined, "no recorded session: no folder known");
    assert.equal(after.notes[0].title, `Mandu: ${card.agents[0] || "An agent"} needs your OK`);
    assert.match(after.title, /^\(1\) /, "the background tab's title counts it");
    assert.equal(after.said, "", "nothing said to a page no one looks at");
    // H4
    oracle(after.notes);
    // H5
    assert.deepEqual(await evaluate("window.__closed"), [], "nothing closed while it waits");
    await s.block(card.id);
    assert.equal(await evaluate("window.__tick()"), 1);
    await until("the answered question's notification closes", "window.__closed.length > 0");
    assert.deepEqual(await evaluate("window.__closed"), [`mandu-ask-${card.id}`]);
    assert.equal(await evaluate("window.__notes.length"), 1, "and nothing new is shown");
  } finally {
    cdp.close();
    await tour.stopProc(proc);
    await s.close();
  }
});
