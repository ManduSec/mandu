/**
 * rules-pending-tabs — Changes to save are the same in every tab of the
 * product page, across the REAL components (dashboard.md §4.25n *Changes to
 * save are the same in every tab*). Mandu-new.
 *
 * Until 2026-10-26 each tab read the changes waiting in this browser once,
 * at load, and wrote its own list over the stored one: with two tabs open, a
 * No AI chosen in one was lost when the other wrote, and a Save in one left
 * the other offering the saved change again. Here a real ArbiterServer runs
 * at the `secrets` axes over a policy.yaml, and a real DashboardServer over
 * the production adapter (`makeApprovalsArbiter`) lists a scratch home with
 * `~/shop/notes.txt` and `~/api/key.txt` (each holding a canary value) and
 * serves the page, signed in. Two tabs of ONE headless Chromium (one browser
 * context, so one localStorage) open Rules, B first:
 *
 *   P1  in tab A the person chooses No AI for `~/shop/notes.txt`, then in
 *       tab B for `~/api/key.txt`: both tabs show 2 waiting, in the bar and
 *       in the top bar's mark;
 *   P2  policy.yaml is unchanged: nothing was saved;
 *   P3  Save changes in B: policy.yaml holds both files at no-model, and
 *       A's bar and mark are gone (no Save left to send again);
 *   P4  the oracle: no page text carries a file's value or a minted token.
 *
 * Over the DevTools protocol (scripts/tour-screenshots.mjs, as
 * rules-unsaved-mark does); self-SKIPs without a Chromium. Axes: secrets
 * (stated; the arbiter's confidentiality pinned ON).
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
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { withTeardown } from "../lib/teardown.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const SHOP_VALUE = `sk_live_pendingTabsShop_${process.pid}_0000000`;
const API_VALUE = `sk_live_pendingTabsApi_${process.pid}_00000000`;
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
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
 *  `~/shop/notes.txt` and `~/api/key.txt`. */
async function stack() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-pending-tabs-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "shop"), { recursive: true });
  mkdirSync(join(home, "api"), { recursive: true });
  const shopFile = join(home, "shop", "notes.txt");
  const apiFile = join(home, "api", "key.txt");
  writeFileSync(shopFile, `supplier key: ${SHOP_VALUE}\n`);
  writeFileSync(apiFile, `api key: ${API_VALUE}\n`);
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
    tmp, base, shopFile, apiFile,
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
  for (const v of [SHOP_VALUE, API_VALUE]) assert.ok(!text.includes(v), `CONFIDENTIALITY VIOLATION: ${what} carries a file's value`);
  assert.doesNotMatch(text, TOKEN, `${what} carries no token`);
}
/** policy.yaml holds the file at no-model: its path, and that level, in the
 *  same `paths:` entry (an entry starts at its `- `). */
const holds = (policy: string, file: string) =>
  policy.split(/\n(?=\s*- )/).some((entry) => entry.includes(`path: ${file}\n`) && /^\s*level: no-model$/m.test(entry));

test("in a real Chromium, two tabs: No AI chosen in each shows 2 waiting in both, nothing saved; Save in one saves both and the other's bar and mark go (secrets axes, explicit)", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const s = await stack();
  const { proc, wsUrl } = await tour.startBrowser(browser as string, join(s.tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  await withTeardown(async () => {
    /** A tab of the browser's one context, on `/rules`, signed in. */
    const tab = async () => {
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
      await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: s.base, httpOnly: true, sameSite: "Strict" });
      await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
      await send("Page.navigate", { url: s.base + "/rules" });
      // The rules are read: the note under Your rules names policy.yaml.
      await until("/rules: the page is drawn", `!!document.getElementById("rules-add") && /policy\\.yaml/.test(document.getElementById("rules-file")?.textContent ?? "")`);
      const named = (re: string) => `[...document.querySelectorAll("#files-list .row.file")].find((r) => ${re}.test(r.querySelector(".file-name")?.textContent ?? ""))`;
      /** Choose No AI for `folder/name` in Add a rule, as a person does. */
      const noAi = async (folder: string, name: string) => {
        await evaluate(`(() => { if (document.getElementById("files-list").closest("[hidden]")) document.getElementById("rules-add").click(); return true; })()`);
        // The folder last shown is kept in the browser too: from another
        // one, the "~" breadcrumb goes home.
        const crumb = `[...document.querySelectorAll("#files-crumbs button, #files-crumbs a")].find((c) => c.textContent.trim() === "~")`;
        const DIR = named(`/^${folder}\\//`);
        await until(`the browser lists a folder`, `!!(${DIR}) || !!(${crumb})`);
        await evaluate(`(() => { const c = ${crumb}; if (!(${DIR}) && c) c.click(); return true; })()`);
        await until(`the browser lists ~/${folder}`, `!!(${DIR})`);
        await evaluate(`(() => { (${DIR}).querySelector(".file-open").click(); return true; })()`);
        const ROW = named(`/^${name.replace(".", "\\.")}/`);
        await until(`the browser lists ~/${folder}/${name}`, `!!(${ROW})`);
        await evaluate(`(() => { const m = (${ROW}).querySelector("select.label-select"); m.value = "no-model"; m.dispatchEvent(new Event("change", { bubbles: true })); return true; })()`);
      };
      /** What waits, as the tab shows it: the bar's count (null: hidden), its
       *  rows, the top bar's mark (null: hidden), and the page's text. */
      const shows = () => evaluate(`(() => { const bar = document.getElementById("files-pending"); const m = document.getElementById("nav-rules-unsaved");
        return { bar: bar.hidden ? null : document.getElementById("files-pending-count").textContent,
          rows: [...document.querySelectorAll("#files-pending-list button")].map((b) => b.getAttribute("aria-label")).sort(),
          mark: m.hidden ? null : m.textContent, text: document.body.innerText }; })()`);
      return { evaluate, until, noAi, shows };
    };
    const texts: string[] = [];
    const before = s.policy();
    // B is opened first: it read the stored list (empty) before A chose.
    const b = await tab();
    const a = await tab();
    assert.equal((await a.shows()).bar, null, "nothing waits at first");

    // P1: No AI in A, then a different file in B.
    await a.noAi("shop", "notes.txt");
    await a.until("A: 1 waiting", `document.getElementById("nav-rules-unsaved").textContent === "1"`);
    await b.until("B: A's choice shows in B", `document.getElementById("nav-rules-unsaved").textContent === "1" && !document.getElementById("files-pending").hidden`);
    await b.noAi("api", "key.txt");
    const both = ["Drop the change to ~/api/key.txt", "Drop the change to ~/shop/notes.txt"];
    await b.until("B: 2 waiting", `document.getElementById("files-pending-count").textContent === "2"`);
    await a.until("A: 2 waiting", `document.getElementById("files-pending-count").textContent === "2"`);
    for (const [name, t] of [["A", a], ["B", b]] as const) {
      const shown = await t.shows();
      assert.deepEqual({ bar: shown.bar, rows: shown.rows, mark: shown.mark }, { bar: "2", rows: both, mark: "2" }, `${name} shows both changes`);
      texts.push(shown.text);
    }
    // P2: nothing saved yet.
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(s.policy(), before, "policy.yaml is unchanged before the Save");

    // P3: Save in B.
    await b.evaluate(`(() => { document.getElementById("files-save").click(); return true; })()`);
    await b.until("B: saved, the bar hides", `document.getElementById("files-pending").hidden`);
    assert.ok(holds(s.policy(), s.shopFile), `policy.yaml holds ~/shop/notes.txt, chosen in A:\n${s.policy()}`);
    assert.ok(holds(s.policy(), s.apiFile), `policy.yaml holds ~/api/key.txt, chosen in B:\n${s.policy()}`);
    await a.until("A: the bar and the mark go", `document.getElementById("files-pending").hidden && document.getElementById("nav-rules-unsaved").hidden`);
    for (const [name, t] of [["A", a], ["B", b]] as const) {
      const shown = await t.shows();
      assert.deepEqual({ bar: shown.bar, rows: shown.rows, mark: shown.mark }, { bar: null, rows: [], mark: null }, `${name}: nothing waits`);
      texts.push(shown.text);
    }

    // P4: the oracle.
    for (const t of texts) oracle("a tab's page", t);
  }, () => cdp.close(), () => tour.stopProc(proc), () => s.close());
});
