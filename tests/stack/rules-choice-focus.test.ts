/**
 * rules-choice-focus.test — on the product page's Rules, a label chosen in
 * Your rules keeps the keyboard focus, and an opened rule's buttons keep it
 * and name their row, across the REAL components (dashboard.md §4.25 *A
 * label chosen in Your rules keeps the focus*). Mandu-new.
 *
 * Until 2026-10-11, in headless Chromium, a choice in a tree row's menu,
 * Remove my rule and Update left the focus on <body> (the tree is drawn
 * again from nothing), a choice in the browser moved it to the row's tick
 * box, Show in policy.yaml dropped it (its button goes off during the read),
 * and Show in its folder left it on the button, out of view, while the page
 * scrolled to the browser.
 *
 * Here a real ArbiterServer (secrets) holds a policy.yaml with a rule on a
 * key file and a sending rule, and a rule made on the page
 * (`setPathLabel`). A real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`, with its secrets and policy surfaces) serves the
 * Rules page (its own index.html and home.js in jsdom):
 *
 *   C1  signed out: a choice in a tree row's menu keeps the focus on that
 *       menu, drawn again with the choice waiting; Show in policy.yaml keeps
 *       it through the read (the route is open), the lines shown; nothing
 *       is written;
 *   C2  signed in: the page rule's menu (a tightening) keeps the focus, and
 *       Save writes it: the arbiter has the folder at its new level;
 *   C3  the key file's opened row: its buttons are named by their row;
 *       Remove my rule keeps the focus on itself, drawn again; Discard;
 *   C4  Show in its folder: the browser opens at the folder with the key
 *       file's row opened, and the focus is on that row's ⋯;
 *   C5  a choice in the browser keeps the focus on the menu, never the
 *       row's tick box;
 *   C6  the sending rule's opened row: named buttons, and Show in
 *       policy.yaml keeps the focus;
 *   C7  the oracle: neither the rendered pages nor the answers read here
 *       carry the key.
 *
 * jsdom keeps the focus of a button turned off, so `press` drops it to
 * <body> as Chromium does. Axes: secrets (stated).
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
import { controlName, reachableControls } from "../../dashboard/test/unit/ui/control-names.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_" + "live_rulesChoiceFocusStackCanary000000001";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** Enter on a button that goes off while it acts: Chromium drops its focus. */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "the button goes off while it acts");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
  assert.equal(btn.ownerDocument.activeElement, btn.ownerDocument.body);
}
/** A choice in a menu with the keyboard: the menu has the focus. */
function choose(sel: Doc, value: string): void {
  sel.focus();
  sel.value = value;
  sel.dispatchEvent(new sel.ownerDocument.defaultView.Event("change", { bubbles: true }));
}
const treeRow = (doc: Doc, path: string) => [...doc.querySelectorAll("#files-tree .row.file-rule")].find((r: Doc) => r.getAttribute("data-path") === path);
const browserRow = (doc: Doc, path: string) => [...doc.querySelectorAll("#files-list .row.file")].find((r: Doc) => r.getAttribute("data-path") === path);
const menuIn = (row: Doc) => row?.querySelector("select.label-select:not(.send-select)");
const button = (box: Doc, words: string) => [...box.querySelectorAll("button")].find((b: Doc) => b.textContent === words);
const listRow = (doc: Doc, subject: string) => [...doc.querySelectorAll("#rules-list .row.rule")].find((r: Doc) => r.querySelector(".rule-text code")?.textContent === subject);
const openTree = (doc: Doc, path: string) => {
  treeRow(doc, path).querySelector(".file-more").click();
  return doc.querySelector("#files-tree .file-detail");
};

test("Rules over the real arbiter: a label chosen in Your rules keeps the focus; an opened rule's buttons keep it and name their row; no key on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-choice-focus-"));
  const home = join(tmp, "home");
  const proj = join(home, "proj");
  const old = join(proj, "old");
  mkdirSync(old, { recursive: true });
  const token = join(proj, "deploy.token");
  writeFileSync(token, `${KEY}\n`);
  writeFileSync(join(proj, "notes.txt"), "nothing secret\n");
  writeFileSync(join(old, "memo.txt"), "nothing secret\n");
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "paths:",
    `  - path: ${token}`,
    "    level: no-model",
    "user_rules:",
    "  - { id: r-0002, kind: release, to: { host: b.example }, mode: block }",
    "",
  ].join("\n"));
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
  const level = async (path: string) => JSON.stringify(await data.pathLevel(path));
  const ready = (doc: Doc) => !!menuIn(treeRow(doc, token)) && !!menuIn(treeRow(doc, old)) && !!listRow(doc, "b.example");
  try {
    // A rule made on the page before rules lived in policy.yaml.
    await admin.setPathLabel({ path: old, confidentiality: "any-model" });
    const oldBefore = await level(old);

    // C1: signed out.
    const before = readFileSync(policyPath, "utf8");
    await servedProductPage(base, "/rules", ready, async (doc) => {
      const was = menuIn(treeRow(doc, old));
      choose(was, "no-model");
      const now = menuIn(treeRow(doc, old));
      assert.notEqual(now, was, "the tree was drawn again");
      assert.equal(doc.activeElement, now, "the same row's menu, never <body>");
      assert.equal(now.value, "no-model");
      assert.equal(now.closest(".label-pick").classList.contains("waiting"), true, "the choice waits");
      doc.getElementById("files-discard").click();
      const box = openTree(doc, token);
      const show = button(box, "Show in policy.yaml");
      assert.equal(controlName(show), "Show in policy.yaml: ~/proj/deploy.token");
      press(show);
      await waitWhile(() => show.textContent !== "Hide policy.yaml");
      await waitWhile(() => doc.activeElement === doc.body, 5_000);
      assert.equal(doc.activeElement, show, "given back after the read");
      assert.equal(controlName(show), "Hide policy.yaml: ~/proj/deploy.token");
      assert.ok(box.querySelector(".rule-source").textContent.includes(token), "the rule's lines");
      pages.push(doc.body.textContent ?? "");
    });
    assert.equal(readFileSync(policyPath, "utf8"), before, "nothing written signed out");
    assert.equal(await level(old), oldBefore);

    await servedProductPage(base, "/rules", ready, async (doc) => {
      doc.defaultView.confirm = () => true;
      // C2: the page rule tightened, focus kept, saved.
      choose(menuIn(treeRow(doc, old)), "no-model");
      const chosen = menuIn(treeRow(doc, old));
      assert.equal(doc.activeElement, chosen);
      doc.getElementById("files-save").click();
      await waitWhile(() => !doc.getElementById("files-pending").hidden);
      assert.notEqual(await level(old), oldBefore, "saved: the arbiter has the folder at its new level");
      // The save reads Your rules again and draws the tree: wait for it.
      await waitWhile(() => menuIn(treeRow(doc, old)) === chosen || !menuIn(treeRow(doc, old)) || menuIn(treeRow(doc, old)).closest(".label-pick").classList.contains("waiting"));
      assert.equal(menuIn(treeRow(doc, old)).value, "no-model", "the rule as saved");

      // C3: the key file's opened row.
      const box = openTree(doc, token);
      assert.deepEqual(reachableControls(box).map(controlName), [
        "May still be sent to (optional, comma-separated)",
        "Update where ~/proj/deploy.token may still be sent",
        "Remove my rule on ~/proj/deploy.token",
        "Show in policy.yaml: ~/proj/deploy.token",
        "Show in its folder: ~/proj/deploy.token",
      ]);
      const remove = doc.getElementById("files-unset");
      remove.focus();
      remove.click();
      assert.notEqual(doc.getElementById("files-unset"), remove, "drawn again");
      assert.equal(doc.activeElement, doc.getElementById("files-unset"), "the same button, never <body>");
      assert.match(doc.getElementById("files-pending-list").textContent, /~\/proj\/deploy\.token/);
      doc.getElementById("files-discard").click();

      // C4: Show in its folder.
      const go = button(doc.querySelector("#files-tree .file-detail"), "Show in its folder");
      go.focus();
      go.click();
      await waitWhile(() => doc.activeElement === go, 10_000);
      const row = browserRow(doc, token);
      assert.ok(row, "the browser lists the folder");
      assert.equal(row.classList.contains("open"), true, "with the file's row opened");
      assert.equal(doc.activeElement, row.querySelector(".file-more"), "the focus followed the page there");
      assert.equal(controlName(doc.activeElement), "Close ~/proj/deploy.token");

      // C5: a choice in the browser.
      const notes = join(proj, "notes.txt");
      await waitWhile(() => !menuIn(browserRow(doc, notes)));
      choose(menuIn(browserRow(doc, notes)), "no-model");
      assert.equal(doc.activeElement, menuIn(browserRow(doc, notes)), "the menu, never the row's tick box");
      doc.getElementById("files-discard").click();

      // C6: the sending rule's opened row.
      listRow(doc, "b.example").querySelector(".file-more").click();
      const detail = listRow(doc, "b.example").nextElementSibling;
      assert.deepEqual(reachableControls(detail).map(controlName), ["Show in policy.yaml: b.example", "Remove the rule for b.example"]);
      const show = button(detail, "Show in policy.yaml");
      press(show);
      await waitWhile(() => show.textContent !== "Hide policy.yaml");
      await waitWhile(() => doc.activeElement === doc.body, 5_000);
      assert.equal(doc.activeElement, show);
      assert.match(detail.querySelector(".rule-source").textContent, /b\.example/);
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // C7: the oracle.
    for (const path of ["/api/policy/panel", "/api/secrets", "/api/home", `/api/files/list?path=${encodeURIComponent(proj)}`]) {
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
