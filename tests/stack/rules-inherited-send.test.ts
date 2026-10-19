/**
 * rules-inherited-send e2e — on the product page's Rules, a file that
 * gets its label from a folder rule shows its second menu, *Where it may be
 * sent*, greyed with its whole choice, and the menu's name says which rule
 * it follows (dashboard.md §4.25p *A menu says its words whole*), through
 * the PRODUCTION wiring: `makeApprovalsArbiter(dataSock, () => ({
 * socketPath: adminSock }))` over a REAL ArbiterServer (secrets) with a
 * file-backed policy, and a real DashboardServer serving the page, signed
 * in, with Add a rule's browser on the real home folder.
 *
 * Until 2026-10-19 that menu read "Listed hosts without asking
 * (inherited)", which needs 278 px with the menu's padding in a 230 px
 * column: Chromium cut it with an ellipsis at every width.
 *
 * A folder rule (~/proj/notes, No AI, listed host api.example.com) and a
 * file in it with no rule of its own, holding a registered key:
 *
 *   1. jsdom over the served page: the file's second menu shows "Listed
 *      hosts without asking", no "(inherited)", is disabled, has the ring
 *      (`data-from`), and its accessible name and tooltip name the folder
 *      rule; the folder's own row (a rule of yours) keeps its plain name;
 *   2. a real headless Chromium at 1280 px with the served fonts: the
 *      menu's choice fits its text box (the select's width less its
 *      padding, at the select's own font), where the old words did not,
 *      and the accessible name names the folder rule;
 *   3. the oracle: no page or answer read here carries the key, and
 *      policy.yaml is as it was.
 *
 * The Chromium half self-SKIPs without a Chromium (probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell).
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

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
const chromium = tour.probeBrowser({});

const KEY = `sk_live_rulesInheritedSendCanary_${process.pid}_0000`;
const WHOLE = "Listed hosts without asking";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const dirs: string[] = [];
const closers: Array<() => Promise<void>> = [];
after(async () => {
  for (const c of closers.reverse()) await c();
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/** The served stack, once for both tests. */
let stack: { base: string; notes: string; contract: string; policyPath: string; policy: string } | null = null;
async function start() {
  if (stack) return stack;
  const dir = mkdtempSync(join(tmpdir(), "mandu-rules-inherited-send-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const notes = join(home, "proj", "notes");
  mkdirSync(notes, { recursive: true });
  const contract = join(notes, "contract.md");
  writeFileSync(contract, `API_KEY=${KEY}\n`);
  const policyPath = join(dir, "policy.yaml");
  const policy = [
    "version: 1",
    "paths:",
    `  - { path: "${notes}", level: no-model, bindings: [api.example.com] }`,
    "",
  ].join("\n");
  writeFileSync(policyPath, policy);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
  });
  await arbiter.listen();
  const gate = new ArbiterClient(dataSock);
  await gate.connect();
  // The key is registered: a page or an answer carrying it is a leak.
  await gate.registerSecret({ path: contract, sessionKey: "rules-inherited-send" });
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production wiring connects");
  const server = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  closers.push(async () => { await server.close(); wired.close(); gate.close(); await arbiter.close(); });
  stack = { base, notes, contract, policyPath, policy };
  return stack;
}

/** The accessible name of the file's second menu: the choice and the rule. */
const NAME = "Where ~/proj/notes/contract.md may be sent: listed hosts without asking. From your rule on ~/proj/notes. Change it there.";

test("Rules over the real arbiter: a file under a folder rule with a listed host shows its second menu greyed with its whole choice, named by the folder's rule; no key on the page", { timeout: 120_000 }, async () => {
  const { base, notes, contract, policyPath, policy } = await start();
  const answer = await pageFetch(`${base}/api/files/list?path=${encodeURIComponent(notes)}`, { headers: CSRF_ADMIN });
  assert.equal(answer.status, 200);
  const raw = await answer.text();
  assert.ok(!raw.includes(KEY), "CONFIDENTIALITY VIOLATION: the listing carries the key");
  const entry = (JSON.parse(raw) as Doc).entries.find((e: Doc) => e.path === contract);
  assert.equal(entry?.label?.source, "inherited", "the file has no rule of its own");
  assert.deepEqual(entry.label.bindings, ["api.example.com"], "it gets the folder's listed host");

  await servedProductPage(base, "/rules", (doc: Doc) => !!doc.querySelector(`#files-tree .row.file-rule[data-path="${notes}"]`), async (doc: Doc) => {
    // The folder's own rule in Your rules: a menu of yours, as it was.
    const own = doc.querySelector(`#files-tree .row.file-rule[data-path="${notes}"] select.send-select`);
    assert.equal(own.selectedOptions[0].textContent, WHOLE);
    assert.equal(own.disabled, false, "a rule of your own is changed here");
    assert.equal(own.getAttribute("aria-label"), "Where ~/proj/notes may be sent");

    // Add a rule's browser, in the folder.
    doc.getElementById("rules-add").click();
    await waitWhile(() => !doc.querySelector("#files-list .row.file"));
    doc.getElementById("lock-path").value = "~/proj/notes";
    doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
    await waitWhile(() => !doc.querySelector(`#files-list .row.file[data-path="${contract}"]`));
    const row = doc.querySelector(`#files-list .row.file[data-path="${contract}"]`);
    const menu = row.querySelector("select.send-select");
    assert.equal(menu.selectedOptions[0].textContent, WHOLE, "the whole choice, no \"(inherited)\"");
    assert.ok(![...menu.options].some((o: Doc) => /inherited/.test(o.textContent)), "no choice carries the word");
    assert.equal(menu.disabled, true, "greyed: changed on the folder's rule");
    assert.equal(row.querySelector(".send-pick").getAttribute("data-from"), "hosts", "the dot is a ring");
    assert.equal(menu.getAttribute("aria-label"), NAME, "its name names the folder's rule");
    assert.equal(menu.title, menu.getAttribute("aria-label"), "and so does its tooltip");
    assert.match(row.querySelector("select.label-select:not(.send-select)").selectedOptions[0].textContent, /\(inherited\)$/, "the first menu keeps the word");
    assert.match(row.textContent, /From your rule on ~\/proj\/notes/, "the line under the name says it too");
    assert.ok(!doc.documentElement.outerHTML.includes(KEY), "CONFIDENTIALITY VIOLATION: the Rules page carries the key");
  }, { headers: { Cookie: ADMIN_COOKIE } });
  assert.equal(readFileSync(policyPath, "utf8"), policy, "nothing was saved");
});

test("in a real Chromium at 1280 px: the inherited second menu's choice fits its box with the served fonts, and its name names the folder's rule", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const { base, contract, policyPath, policy } = await start();
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-inherited-send-cdp-"));
  dirs.push(tmp);
  const { proc, wsUrl } = await tour.startBrowser(chromium as string, join(tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  try {
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
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
    await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
    await send("Page.navigate", { url: base + "/rules" });
    await until("Your rules drawn", `!!document.querySelector("#files-tree .row.file-rule")`);
    await evaluate(`document.getElementById("rules-add").click(), true`);
    await until("the browser lists the home folder", `!!document.querySelector("#files-list .row.file")`);
    await evaluate(`(() => {
      document.getElementById("lock-path").value = "~/proj/notes";
      document.getElementById("files-go").requestSubmit();
      return true;
    })()`);
    const sel = `#files-list .row.file[data-path=${JSON.stringify(contract)}] select.send-select`;
    await until("the browser lists the folder", `!!document.querySelector(${JSON.stringify(sel)})`);
    const m = await evaluate(`(async () => {
      await document.fonts.ready;
      const s = document.querySelector(${JSON.stringify(sel)});
      const cs = getComputedStyle(s);
      const ctx = document.createElement("canvas").getContext("2d");
      ctx.font = cs.fontStyle + " " + cs.fontWeight + " " + cs.fontSize + " " + cs.fontFamily;
      const box = s.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
      const text = s.selectedOptions[0].textContent;
      return {
        text, box, need: ctx.measureText(text).width, old: ctx.measureText(text + " (inherited)").width,
        disabled: s.disabled, name: s.getAttribute("aria-label"), weight: cs.fontWeight,
        page: document.documentElement.scrollWidth, view: document.documentElement.clientWidth,
        body: document.body.innerText,
      };
    })()`);
    assert.equal(m.text, WHOLE);
    assert.equal(m.disabled, true);
    assert.equal(m.weight, "400", "an inherited choice is drawn regular");
    assert.ok(m.need <= m.box, `the choice fits its box: ${m.need.toFixed(1)}px of words in ${m.box}px`);
    assert.ok(m.old > m.box, `the measure tells: the old words needed ${m.old.toFixed(1)}px of ${m.box}px`);
    assert.equal(m.name, NAME, "its name names the folder's rule");
    assert.ok(m.page <= m.view, `the page does not scroll sideways (${m.page} > ${m.view})`);
    assert.ok(!m.body.includes(KEY), "CONFIDENTIALITY VIOLATION: the Rules page shows the key");
  } finally {
    cdp.close();
    await tour.stopProc(proc);
  }
  assert.equal(readFileSync(policyPath, "utf8"), policy, "nothing was saved");
});
