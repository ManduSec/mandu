/**
 * pending-save-focus.test — on the product page's Rules, Changes to save and
 * *Move them into policy.yaml* keep the keyboard focus, across the REAL
 * components (dashboard.md §4.25 *Changes to save keeps the focus*).
 * Mandu-new.
 *
 * Until 2026-10-11 Save went off while the changes were on their way and the
 * bar hid itself once they were saved, Discard hid the bar under its own
 * button and Drop drew the list again under its own: each left the focus on
 * <body>. *Move them into policy.yaml* went off and was drawn away, and a
 * refused move wrote its words into the hidden Changes to save.
 *
 * Here a real ArbiterServer (secrets) holds a policy.yaml rule on a key file
 * and a rule made on the page before rules lived in policy.yaml
 * (`setPathLabel`). A real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`, with its secrets and policy surfaces) serves the
 * Rules page (its own index.html and home.js in jsdom):
 *
 *   F1  signed out, a refused Save gives the focus back to Save, described
 *       by "Sign in first…"; a refused move says so in its own box and
 *       gives its button the focus back, described; nothing changed;
 *   F2  signed in, a file chosen in the browser and saved (a tightening):
 *       the focus is on the Your rules heading, and the arbiter has the
 *       file at its new level;
 *   F3  the same file made Not secret (a loosening): the focus is on the
 *       question, never Save anyway; Save anyway puts it on the heading,
 *       and the arbiter follows;
 *   F4  two changes chosen: Drop on one gives the focus to the bar's
 *       heading; Discard gives it to the Your rules heading; nothing saved;
 *   F5  Move them into policy.yaml: the focus on the Your rules heading,
 *       and the page rule is in policy.yaml;
 *   F6  the oracle: neither the rendered pages nor the answers read here
 *       carry the key.
 *
 * jsdom keeps the focus of a button turned off, so `press` holds the page's
 * POST and drops the focus to <body> while the change is on its way, as
 * Chromium does. Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_" + "live_pendingSaveFocusStackCanary00000001";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** Enter on a button the change turns off: the page's POST is held until
 *  the button is off and the browser has dropped its focus to <body>. */
async function press(btn: Doc): Promise<void> {
  const w = btn.ownerDocument.defaultView;
  const real = w.fetch;
  let open: () => void = () => {};
  const gate = new Promise<void>((r) => { open = r; });
  w.fetch = (url: string, init: Doc = {}) => (init.method === "POST" ? gate.then(() => real(url, init)) : real(url, init));
  btn.focus();
  btn.click();
  await waitWhile(() => !btn.disabled);
  assert.equal(btn.disabled, true, "the change turns its button off while it is on its way");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
  assert.equal(btn.ownerDocument.activeElement, btn.ownerDocument.body);
  w.fetch = real;
  open();
}
/** Enter on a button the change hides or draws away (Drop, Discard). */
function hit(btn: Doc): void {
  btn.focus();
  btn.click();
}
/** The page draws again after a change, then gives the focus back: wait
 *  for it to leave <body> (a short bound, so a failure is quick). */
const landed = (doc: Doc) => waitWhile(() => doc.activeElement === doc.body, 5_000);
const text = (doc: Doc, sel: string): string => doc.querySelector(sel)?.textContent ?? "";
const rowFor = (doc: Doc, name: string) => [...doc.querySelectorAll("#files-list .row.file:not(.up)")]
  .find((r: Doc) => r.querySelector(".file-name").textContent.startsWith(name));
const choose = (row: Doc, level: string) => {
  const m = row.querySelector("select.label-select");
  m.value = level;
  m.dispatchEvent(new m.ownerDocument.defaultView.Event("change", { bubbles: true }));
};
const go = (doc: Doc, path: string) => {
  doc.getElementById("lock-path").value = path;
  doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
};
const treeRow = (doc: Doc, path: string) => [...doc.querySelectorAll("#files-tree .row.file-rule")].find((r: Doc) => r.getAttribute("data-path") === path);
const bar = (doc: Doc) => doc.getElementById("files-pending");
const save = (doc: Doc) => doc.getElementById("files-save");
const heading = (doc: Doc) => doc.getElementById("rules-title");
const moveBtn = (doc: Doc) => doc.querySelector("#files-move button");

test("Changes to save over the real arbiter: Save, the weaker-change question, Drop, Discard and the move keep the focus; refusals give it back described; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-pending-save-focus-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  const old = join(proj, "old");
  mkdirSync(old, { recursive: true });
  writeFileSync(join(proj, "deploy.token"), `${KEY}\n`);
  writeFileSync(join(proj, "notes.txt"), "nothing secret\n");
  writeFileSync(join(proj, "todo.txt"), "nothing secret\n");
  writeFileSync(join(old, "memo.txt"), "nothing secret\n");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${join(proj, "deploy.token")}\n    level: no-model\n`);
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
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
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
  const bodies: string[] = [];
  const pages: string[] = [];
  const level = async (path: string) => (await data.pathLevel(path)) as unknown;
  try {
    // A rule made on the page before rules lived in policy.yaml.
    await admin.setPathLabel({ path: old, confidentiality: "any-model" });
    const notes = join(proj, "notes.txt");
    const notesBefore = await level(notes);

    // F1: signed out, refusals.
    const before = readFileSync(policyPath, "utf8");
    const browse = async (doc: Doc) => {
      doc.getElementById("rules-add").click();
      await waitWhile(() => !doc.querySelector("#files-list .row.file"));
      go(doc, "~/proj/");
      await waitWhile(() => !rowFor(doc, "notes.txt") || !rowFor(doc, "notes.txt").querySelector("select.label-select"));
    };
    await servedProductPage(base, "/rules", (doc) => !!moveBtn(doc), async (doc) => {
      doc.defaultView.confirm = () => true;
      const move = moveBtn(doc);
      await press(move);
      await waitWhile(() => !doc.querySelector("#files-move .ask-error") && !text(doc, "#lock-error"));
      const words = doc.querySelector("#files-move .ask-error");
      assert.ok(words, `the refusal is said in the move's own box, not only in the hidden Changes to save ("${text(doc, "#lock-error")}")`);
      assert.match(words.textContent, /^Sign in first/);
      assert.equal(words.closest("[hidden]"), null, "said where it is seen");
      assert.equal(doc.activeElement, move, "the button pressed, on again");
      assert.equal(move.getAttribute("aria-describedby"), words.id, "described by the refusal's words");

      // The browser lists nothing signed out; Your rules' own menus still draw.
      choose(treeRow(doc, old), "no-model");
      assert.equal(bar(doc).hidden, false, "the change waits");
      await press(save(doc));
      await waitWhile(() => !text(doc, "#lock-error"));
      assert.match(text(doc, "#lock-error"), /^Sign in first/);
      assert.equal(doc.activeElement, save(doc), "Save, on again");
      assert.equal(save(doc).disabled, false);
      assert.equal(save(doc).getAttribute("aria-describedby"), "lock-error", "described by the refusal's words");
      pages.push(doc.body.textContent ?? "");
    });
    assert.equal(readFileSync(policyPath, "utf8"), before, "nothing changed signed out");
    assert.deepEqual(await level(notes), notesBefore);

    await servedProductPage(base, "/rules", (doc) => !!moveBtn(doc), async (doc) => {
      doc.defaultView.confirm = () => true;
      assert.equal(bar(doc).hidden, true, "a new window has nothing waiting");
      await browse(doc);

      // F2: a tightening, saved.
      choose(rowFor(doc, "notes.txt"), "no-model");
      await press(save(doc));
      await waitWhile(() => !bar(doc).hidden);
      await landed(doc);
      assert.equal(bar(doc).hidden, true, "saved: nothing waits");
      assert.equal(doc.activeElement, heading(doc), "the Your rules heading, never <body>");
      assert.equal(doc.getElementById("rules-notice").firstChild.textContent, "1 change saved.");
      assert.match(readFileSync(policyPath, "utf8"), /notes\.txt/);
      const tight = JSON.stringify(await level(notes));
      assert.notEqual(tight, JSON.stringify(notesBefore), "the arbiter has the file at its new level");

      // F3: a loosening asks first.
      await waitWhile(() => !rowFor(doc, "notes.txt")?.querySelector("select.label-select"));
      choose(rowFor(doc, "notes.txt"), "public");
      await press(save(doc));
      await waitWhile(() => doc.getElementById("files-confirm").hidden);
      await landed(doc);
      const question = doc.querySelector("#files-confirm > p");
      assert.equal(save(doc).textContent, "Save anyway");
      assert.equal(doc.activeElement, question, "the question, never Save anyway");
      assert.equal(JSON.stringify(await level(notes)), tight, "asking changes nothing");
      await press(save(doc));
      await waitWhile(() => !bar(doc).hidden);
      await landed(doc);
      assert.equal(doc.activeElement, heading(doc));
      assert.notEqual(JSON.stringify(await level(notes)), tight, "saved anyway: the arbiter follows");

      // F4: Drop, then Discard.
      await waitWhile(() => !rowFor(doc, "todo.txt")?.querySelector("select.label-select"));
      choose(rowFor(doc, "todo.txt"), "no-model");
      choose(rowFor(doc, "notes.txt"), "no-model");
      assert.equal(doc.querySelectorAll("#files-pending-list li").length, 2);
      const policyNow = readFileSync(policyPath, "utf8");
      const drop = [...doc.querySelectorAll("#files-pending-list button")].find((b: Doc) => /todo\.txt$/.test(b.getAttribute("aria-label")));
      hit(drop);
      assert.equal(doc.activeElement, bar(doc).querySelector("h3"), "the bar's heading, never the other row's Drop");
      assert.equal(text(doc, "#files-pending h3"), "Changes to save 1");
      hit(doc.getElementById("files-discard"));
      assert.equal(bar(doc).hidden, true);
      assert.equal(doc.activeElement, heading(doc), "the Your rules heading, never the hidden bar");
      assert.equal(readFileSync(policyPath, "utf8"), policyNow, "nothing saved");

      // F5: the move.
      const move = moveBtn(doc);
      await press(move);
      await waitWhile(() => !doc.getElementById("files-move").hidden);
      await landed(doc);
      assert.equal(doc.activeElement, heading(doc), "the Your rules heading, never <body>");
      assert.match(text(doc, "#rules-notice"), /^Moved 1 rule into policy\.yaml\./);
      assert.match(readFileSync(policyPath, "utf8"), /proj\/old/);
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // F6: the oracle.
    for (const path of ["/api/policy/panel", "/api/secrets", "/api/home", `/api/files/list?path=${encodeURIComponent("~/proj")}`]) {
      bodies.push(await (await pageFetch(base + path, { headers: CSRF_ADMIN })).text());
    }
    for (const t of [...pages, ...bodies]) assert.ok(!t.includes(KEY), "no page or answer carries the key");
  } finally {
    await dashboard.close();
    wired.close();
    admin.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
