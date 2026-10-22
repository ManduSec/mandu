/**
 * rules-add-heads — on the product page's Rules, Add a rule's file browser
 * names its two menus, and a greyed second menu says why, across the REAL
 * components (dashboard.md §4.25p *The browser names its menus*). Mandu-new.
 *
 * Measured 2026-10-19 (seeded headless Chromium, 1280 px): a new row of the
 * browser read "No rule ▾  No rule ▾", nothing named either menu (the heads
 * were Your rules' only, and each menu's caption shows at 1000 px and
 * narrower), and the second menu was greyed with no word on why.
 *
 * A real ArbiterServer (secrets) holds a policy.yaml with one folder rule
 * over a file that holds a key; a real DashboardServer over the production
 * adapter serves Rules, signed in, with Add a rule's browser on the real
 * home folder, its served stylesheets applied as a 1280 px window does:
 *
 *   H1  the browser has its own heads, "File or folder · Which AI may read
 *       it · Where it may be sent", drawn as a grid over the rows' columns
 *       (the tick box first), right over the list;
 *   H2  a file with no rule: its second menu is greyed, and its tooltip and
 *       its name say to choose who may read it first;
 *   H3  No AI picked in its first menu (a change waiting): the second menu
 *       is on, and the sentence is gone;
 *   H4  the oracle: page-side only, so policy.yaml is as it was, and no
 *       page or answer read here carries the key.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_" + "live_rulesAddHeadsStackCanary00000000000";
const FIRST = "Choose who may read it first. Then you can choose where it may be sent.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

test("Rules over the real arbiter: Add a rule's browser has heads over its menus; a file with no rule says why its second menu is greyed, until a level is picked; nothing is written", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-add-heads-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, "app.conf"), `API_KEY=${KEY}\n`);
  writeFileSync(join(home, "notes.txt"), "shopping list\n");
  const policyPath = join(tmp, "policy.yaml");
  const policy = ["version: 1", "paths:", `  - path: "${proj}"`, "    level: no-model", ""].join("\n");
  writeFileSync(policyPath, policy);
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production adapter has the secrets and policy surfaces");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const signedIn = { Cookie: ADMIN_COOKIE };
  const served = async (path: string): Promise<string> => {
    const r = await pageFetch(base + path, { headers: signedIn });
    assert.equal(r.status, 200, `${path} is served`);
    return r.text();
  };
  const notes = join(home, "notes.txt");
  const rowOf = (doc: Doc, path: string): Doc => ([...doc.querySelectorAll("#files-list .row.file:not(.up)")] as Doc[]).find((r) => r.getAttribute("data-path") === path);
  const pages: string[] = [];
  const bodies: string[] = [];
  try {
    const css = resolveCssVars(stylesAt(`${await served("/mandu.css")}\n${await served("/app.css")}`, 1280));
    await servedProductPage(base, "/rules", (doc: Doc) => !!doc.querySelector(`#files-tree .row.file-rule[data-path="${proj}"]`), async (doc: Doc) => {
      const win = doc.defaultView;
      doc.getElementById("rules-add").click();
      await waitWhile(() => !rowOf(doc, notes));
      assert.ok(rowOf(doc, notes), "the browser lists the home folder");

      // ── H1: the heads ──
      const heads = doc.getElementById("files-list-heads");
      assert.ok(doc.getElementById("lock-form").contains(heads), "Add a rule's own heads");
      assert.equal(heads.hidden, false, "the list has rows, so the heads show");
      assert.equal(heads.nextElementSibling, doc.getElementById("files-list"), "right over the list");
      assert.deepEqual(([...heads.querySelectorAll("span")] as Doc[]).map((s) => s.textContent), ["File or folder", "Which AI may read it", "Where it may be sent"]);
      assert.equal(win.getComputedStyle(heads).display, "grid", "1280px: the heads are drawn");
      assert.equal(win.getComputedStyle(heads).gridTemplateColumns, win.getComputedStyle(rowOf(doc, notes)).gridTemplateColumns, "1280px: over the rows' own columns");
      assert.equal(win.getComputedStyle(rowOf(doc, notes).querySelector(".q-cap")).display, "none", "1280px: the heads name the menus");

      // ── H2: a file with no rule ──
      const send = (): Doc => rowOf(doc, notes).querySelector("select.send-select");
      assert.equal(send().disabled, true, "no rule: greyed");
      assert.equal(send().options[send().selectedIndex].textContent, "No rule");
      assert.equal(send().title, FIRST, "the tooltip says why");
      assert.equal(send().getAttribute("aria-label"), `Where ~/notes.txt may be sent. ${FIRST}`, "a screen reader hears why after its name");

      // ── H3: No AI picked: the second menu turns on ──
      const first = rowOf(doc, notes).querySelector("select.label-select:not(.send-select)");
      first.value = "no-model";
      first.dispatchEvent(new win.Event("change", { bubbles: true }));
      assert.ok(rowOf(doc, notes).querySelector(".label-pick.waiting"), "a change waits in Changes to save");
      assert.equal(send().disabled, false, "the second menu is on");
      assert.equal(send().title, "");
      assert.equal(send().getAttribute("aria-label"), "Where ~/notes.txt may be sent");
      pages.push(doc.documentElement.outerHTML);
    }, { headers: signedIn, css });

    // ── H4: the oracle ──
    for (const path of ["/api/policy/panel", `/api/files/list?path=${encodeURIComponent(home)}`, `/api/files/list?path=${encodeURIComponent(proj)}`]) {
      const r = await pageFetch(base + path, { headers: CSRF_ADMIN });
      assert.equal(r.status, 200, `${path} answers`);
      bodies.push(await r.text());
    }
    assert.ok(bodies[2]!.includes("app.conf"), "the listing names the file that holds the key");
    assert.equal(pages.length, 1);
    for (const t of [...pages, ...bodies]) assert.ok(!t.includes(KEY), "CONFIDENTIALITY VIOLATION: a page or an answer carries the key");
    assert.equal(readFileSync(policyPath, "utf8"), policy, "nothing was saved: a change waits until Save");
  } finally {
    await dashboard.close();
    wired.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
