/**
 * rules-unsaved-mark — the top bar's Rules link says, on every page, how
 * many levels chosen on Rules wait to be saved, across the REAL components
 * (dashboard.md §4.25n *The top bar says when Rules has changes not
 * saved*). Mandu-new.
 *
 * Until 2026-10-25 a level chosen on Rules waited in *Changes to save* at
 * the bottom of Rules, kept in the browser across pages and reloads, and
 * nothing outside Rules said so: a person who chose No AI for a file and
 * went Home believed it protected while the AI still read it as before.
 * Here a real ArbiterServer runs at the `secrets` axes over a policy.yaml,
 * and a real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) lists a scratch home with `~/shop/notes.txt`
 * (which holds a canary value) and serves the page, signed in:
 *
 *   M1  on Rules the person opens `~/shop` and chooses No AI for the file:
 *       the Rules link reads "Rules 1", named "Rules, 1 change not saved";
 *   M2  on Home the link still reads "Rules 1" and policy.yaml is
 *       unchanged: nothing was saved;
 *   M3  back on Rules, Save changes: the mark is gone, the link named by its
 *       word, and policy.yaml holds the file at no-model;
 *   M4  in a real headless Chromium too, which also reloads Home between
 *       M2 and M3 (the change is kept in the browser, and so is the mark),
 *       and at 320 and 1280 px draws the mark inside the Rules link with the
 *       links fitting their row;
 *   M5  the oracle: no page text, nor any answer read here, carries the
 *       file's value or a minted token.
 *
 * Once in jsdom over the served page and script (served-page.ts), and once
 * in Chromium over the DevTools protocol (scripts/tour-screenshots.mjs, as
 * protection-off-typed does), which self-SKIPs without a Chromium. Axes:
 * secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { withTeardown } from "../lib/teardown.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const VALUE = `sk_live_unsavedMarkCanary_${process.pid}_0000000`;
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ONE = "Rules, 1 change not saved";
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  removeProfile: (dir: string) => void;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const browser = tour.probeBrowser({});

/** A fresh stack: the arbiter (secrets axes) over a policy.yaml, the
 *  dashboard over the production wiring listing a scratch home with
 *  `~/shop/notes.txt`. */
async function stack() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-unsaved-mark-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "shop"), { recursive: true });
  const file = join(home, "shop", "notes.txt");
  writeFileSync(file, `supplier key: ${VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {}, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  return {
    tmp, base, file,
    policy: (): string => readFileSync(policyPath, "utf8"),
    close: async () => {
      await dashboard.close();
      wired.close();
      await arbiter.close();
      resetCurrentPolicyForTests();
      rmSync(tmp, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    },
  };
}

/** A minted token (the Rules panel's own help text names the `$MDU:` form). */
const TOKEN = /\$MDU:[A-Za-z_][A-Za-z0-9_-]*\[[0-9a-f]{4,8}\]/;
function oracle(what: string, text: string) {
  assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${what} carries the file's value`);
  assert.doesNotMatch(text, TOKEN, `${what} carries no token`);
}
/** policy.yaml holds the file at no-model: its path, and that level, in the
 *  same `paths:` entry (an entry starts at its `- `). */
const holds = (policy: string, file: string) =>
  policy.split(/\n(?=\s*- )/).some((entry) => entry.includes(`path: ${file}\n`) && /^\s*level: no-model$/m.test(entry));

test("served page: No AI chosen on Rules shows \"Rules 1\" on Home with nothing saved; Save hides it and policy.yaml holds the label (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const s = await stack();
  try {
    const before = s.policy();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type Doc = any;
    const mark = (doc: Doc) => {
      const m = doc.getElementById("nav-rules-unsaved");
      return { text: m.hidden ? null : m.textContent, name: m.parentElement.getAttribute("aria-label"), title: m.parentElement.getAttribute("title") };
    };
    const navTo = (doc: Doc, page: string) => doc.querySelector(`#nav a[data-page-link="${page}"]`).click();
    const named = (doc: Doc, re: RegExp) => [...doc.querySelectorAll("#files-list .row.file")].find((r: Doc) => re.test(r.querySelector(".file-name")?.textContent ?? ""));
    const shop = (doc: Doc) => named(doc, /^shop\//);
    const row = (doc: Doc) => named(doc, /^notes\.txt/);
    await servedProductPage(s.base, "/rules", (doc: Doc) => !!doc.getElementById("rules-add") && !doc.getElementById("rules-list").hidden, async (doc: Doc) => {
      assert.deepEqual(mark(doc), { text: null, name: null, title: null }, "nothing waits at first");
      // M1: open ~/shop, choose No AI for the file.
      doc.getElementById("rules-add").click();
      await waitWhile(() => !shop(doc));
      shop(doc).querySelector(".file-open").click();
      await waitWhile(() => !row(doc));
      assert.ok(row(doc), `the browser lists ~/shop/notes.txt: ${doc.getElementById("files-list")?.textContent}`);
      const menu = row(doc).querySelector("select.label-select");
      menu.value = "no-model";
      menu.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
      assert.deepEqual(mark(doc), { text: "1", name: ONE, title: ONE }, "Rules 1");
      oracle("the Rules page with a change waiting", doc.body.textContent);
      // M2: on Home the mark stays; nothing was saved.
      navTo(doc, "home");
      assert.equal(doc.querySelector('#nav a[aria-current="page"]').getAttribute("data-page-link"), "home");
      assert.deepEqual(mark(doc), { text: "1", name: ONE, title: ONE }, "Home: Rules 1");
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(s.policy(), before, "policy.yaml is unchanged: nothing saved");
      oracle("Home with a change waiting", doc.body.textContent);
      // M3: Save changes on Rules.
      navTo(doc, "rules");
      assert.equal(doc.getElementById("files-pending").hidden, false, "the bar is there with the change");
      doc.getElementById("files-save").click();
      await waitWhile(() => !doc.getElementById("files-pending").hidden);
      assert.equal(doc.getElementById("files-pending").hidden, true, "saved");
      assert.deepEqual(mark(doc), { text: null, name: null, title: null }, "the mark is gone, the link named by its word");
      assert.ok(holds(s.policy(), s.file), `policy.yaml holds the label:\n${s.policy()}`);
      oracle("the Rules page after Save", doc.body.textContent);
    }, { headers: { Cookie: ADMIN_COOKIE, "X-Mandu-Control": "1" } });
    // M5: the answers.
    for (const route of ["/api/home", "/api/policy/panel", "/rules", "/"]) {
      oracle(route, await (await pageFetch(s.base + route, { headers: { Cookie: ADMIN_COOKIE } })).text());
    }
  } finally {
    await s.close();
  }
});

test("in a real Chromium: No AI chosen on Rules shows \"Rules 1\" on Home and after a reload, with nothing saved; Save hides it; the mark sits in its link at 320 and 1280 px (secrets axes, explicit)", {
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
    const MARK = `document.getElementById("nav-rules-unsaved")`;
    const mark = () => evaluate(`(() => { const m = ${MARK}; const a = m.parentElement;
      return { text: m.hidden ? null : m.textContent, name: a.getAttribute("aria-label"), title: a.getAttribute("title"), shown: !m.hidden && m.getBoundingClientRect().width > 0,
        page: document.querySelector('#nav a[aria-current="page"]')?.dataset.pageLink ?? null, text_: document.body.innerText }; })()`);
    const named = (re: string) => `[...document.querySelectorAll("#files-list .row.file")].find((r) => ${re}.test(r.querySelector(".file-name")?.textContent ?? ""))`;
    const SHOP = named("/^shop\\//");
    const ROW = named("/^notes\\.txt/");
    const texts: string[] = [];
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Network.enable");
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: s.base, httpOnly: true, sameSite: "Strict" });
    await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
    await send("Page.navigate", { url: s.base + "/rules" });
    await until("/rules: the page is drawn", `!!document.getElementById("rules-add") && !document.getElementById("rules-list").hidden`);
    const before = s.policy();
    assert.equal((await mark()).text, null, "nothing waits at first");

    // M1: open ~/shop and choose No AI for the file, as a person does.
    await evaluate(`(() => { document.getElementById("rules-add").click(); return true; })()`);
    await until("the browser lists ~/shop", `!!(${SHOP})`);
    await evaluate(`(() => { (${SHOP}).querySelector(".file-open").click(); return true; })()`);
    await until("the browser lists ~/shop/notes.txt", `!!(${ROW})`);
    await evaluate(`(() => { const m = (${ROW}).querySelector("select.label-select"); m.value = "no-model"; m.dispatchEvent(new Event("change", { bubbles: true })); return true; })()`);
    await until("Rules 1", `${MARK}.textContent === "1" && !${MARK}.hidden`);
    let m = await mark();
    assert.deepEqual({ text: m.text, name: m.name, title: m.title, shown: m.shown }, { text: "1", name: ONE, title: ONE, shown: true });
    texts.push(m.text_);

    // M2: Home, then a reload: the mark stays; nothing was saved.
    await evaluate(`(() => { document.querySelector('#nav a[data-page-link="home"]').click(); return true; })()`);
    await until("Home is the page", `document.querySelector('#nav a[aria-current="page"]')?.dataset.pageLink === "home"`);
    m = await mark();
    assert.deepEqual({ text: m.text, name: m.name, page: m.page }, { text: "1", name: ONE, page: "home" }, "Home: Rules 1");
    await send("Page.navigate", { url: s.base + "/" });
    await until("Home again after a reload, with the mark", `document.readyState === "complete" && document.querySelector('#nav a[aria-current="page"]')?.dataset.pageLink === "home" && ${MARK}.textContent === "1" && !${MARK}.hidden`);
    m = await mark();
    assert.equal(m.name, ONE, "the reloaded page names it");
    texts.push(m.text_);
    assert.equal(s.policy(), before, "policy.yaml is unchanged: nothing saved");

    // M4: the mark in its link; the links fit their row.
    for (const width of [320, 1280]) {
      await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 500 });
      const g = await evaluate(`(() => { const r = (x) => x.getBoundingClientRect(); const m = ${MARK}; const a = m.parentElement; const nav = document.getElementById("nav");
        const mr = r(m), ar = r(a);
        return { inside: mr.left >= ar.left && mr.right <= ar.right && mr.top >= ar.top && mr.bottom <= ar.bottom, over: nav.scrollWidth - nav.clientWidth,
          page: document.scrollingElement.scrollWidth - innerWidth, fill: getComputedStyle(m).backgroundColor, edge: getComputedStyle(m).borderTopWidth }; })()`);
      assert.deepEqual(g, { inside: true, over: 0, page: 0, fill: "rgba(0, 0, 0, 0)", edge: "1px" }, `${width}px: the ring inside the Rules link, the links in their row`);
    }
    await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });

    // M3: back on Rules, Save changes.
    await evaluate(`(() => { document.querySelector('#nav a[data-page-link="rules"]').click(); return true; })()`);
    await until("Rules with its bar", `!document.getElementById("files-pending").hidden`);
    await evaluate(`(() => { document.getElementById("files-save").click(); return true; })()`);
    await until("saved: the bar hides", `document.getElementById("files-pending").hidden`);
    m = await mark();
    assert.deepEqual({ text: m.text, name: m.name, title: m.title }, { text: null, name: null, title: null }, "the mark is gone");
    texts.push(m.text_);
    assert.ok(holds(s.policy(), s.file), `policy.yaml holds the label:\n${s.policy()}`);

    // M5: the oracle.
    for (const t of texts) oracle("a page", t);
  }, () => cdp.close(), () => tour.stopProc(proc), () => s.close());
});
