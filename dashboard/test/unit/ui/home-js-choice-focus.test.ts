/**
 * home-js-choice-focus.test — on the product page's Rules, a label chosen in
 * Your rules keeps the keyboard focus, and an opened rule's buttons keep it
 * and name their row (dashboard.md §4.25 *A label chosen in Your rules keeps
 * the focus*).
 *
 * Until 2026-10-11, in headless Chromium:
 *   - a choice in a tree row's menu (either question), Remove my rule and
 *     Update under its opened row left the focus on <body>: the choice waits
 *     in Changes to save, and pendingChanged draws the tree again from
 *     nothing;
 *   - the same choice in the browser (Add a rule) moved the focus to the
 *     row's tick box (renderFiles' row restore);
 *   - Show in policy.yaml went off during its read, and Chromium drops the
 *     focus of a button turned off;
 *   - Show in its folder / Show in the file browser scrolled the page to the
 *     browser and left the focus on the button, out of view;
 *   - the opened row's buttons read "Remove", "Show in policy.yaml", "Update"
 *     with no word of their row.
 * Now the focus goes back to the control drawn at its place that reads the
 * same (pollPlace / pollRefocus), Show in policy.yaml keeps it, Show in its
 * folder hands it to the opened browser row's ⋯, and each button is named by
 * its row, its own words first. A press without the focus moves nothing.
 *
 * jsdom drops the focus of a control removed from the page to <body>, as
 * Chromium does, but keeps the focus of a button turned off; `press` drops
 * it then (home-js-rules-focus.test.ts). Drives the PRODUCT page script
 * (public/js/home.js) in jsdom over the shared fetch stub
 * (home-js-fixtures.ts). Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES, rowFor, menuOf, treeRow, opened } from "./home-js-fixtures.js";
import { controlName, reachableControls } from "./control-names.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const fileRule = (path: string, level: string, covers: "subtree" | "exact") => ({
  id: `lock:${path}`, kind: "lock", subject: path, effect: "x", reach: null, hits: null, covers, bindings: [], level,
  actions: { remove: true, flip: null },
  plain: { subject: path, reach: covers === "subtree" ? "and everything inside" : "this file only", effect: "x" },
});
const PANEL = { panel: { available: true, verdictsKnown: true,
  yourRules: [
    fileRule("/home/u/ws/config", "no-model", "subtree"),
    fileRule("/home/u/ws/README.md", "any-model", "exact"),
    { id: "r-0002", kind: "release-block", subject: "b.example", effect: "sending blocked", reach: "from any source to b.example", hits: 1, actions: { remove: true, flip: "allow" } },
  ],
  queue: [
    { id: "egr-9", status: "denied", scope: "always", where: "file", target: "/home/u/ws/notes.md", count: 1, actions: [{ approve: true, label: "Allow instead" }],
      plain: { subject: "/home/u/ws/notes.md", reach: null, effect: "Always blocked" }, sessions: [], resolvedAt: null },
  ] } };
const SOURCE = (line: string) => ({ found: true, path: "/home/u/.config/mandu/policy.yaml", start: 3, lines: [line], mark: [3] });

function rules() {
  return load({ url: FILES_URL, routes: {
    ...FILES_ROUTES,
    "GET policy/panel": PANEL,
    "GET policy/rules/source?id=lock%3A%2Fhome%2Fu%2Fws%2Fconfig": SOURCE("  - { path: /home/u/ws/config, level: no-model }"),
    "GET policy/rules/source?id=r-0002": SOURCE("  - { id: r-0002, kind: release, to: { host: b.example }, mode: block }"),
  } });
}

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
const sendOf = (row: Doc) => row.querySelector("select.send-select");
const button = (box: Doc, words: string) => [...box.querySelectorAll("button")].find((b: Doc) => b.textContent === words);
const listRow = (doc: Doc, subject: string) => [...doc.querySelectorAll("#rules-list .row.rule")].find((r: Doc) => r.querySelector(".rule-text code")?.textContent === subject);
const openListRow = (doc: Doc, subject: string) => {
  listRow(doc, subject).querySelector(".file-more").click();
  return listRow(doc, subject).nextElementSibling;
};
const openTreeRow = (doc: Doc, name: RegExp) => {
  treeRow(doc, name).querySelector(".file-more").click();
  return opened(doc);
};

test("Your rules tree: a choice in a row's menu, either question, gives the focus back to that row's menu, drawn again with the choice waiting", async () => {
  const { doc } = rules();
  await tick();
  const old = menuOf(treeRow(doc, /^config/));
  choose(old, "any-model");
  const now = menuOf(treeRow(doc, /^config/));
  assert.notEqual(now, old, "the tree was drawn again");
  assert.equal(doc.activeElement, now, "the same row's menu, never <body>");
  assert.equal(now.value, "any-model");
  assert.equal(now.closest(".label-pick").classList.contains("waiting"), true, "the choice waits in Changes to save");
  assert.equal(controlName(now), "Which AI may read ~/ws/config");
  // The second question: where it may be sent.
  const send = sendOf(treeRow(doc, /^config/));
  choose(send, "public");
  assert.equal(doc.activeElement, sendOf(treeRow(doc, /^config/)), "the same row's second menu");
  assert.equal(doc.activeElement.value, "public");
  assert.match(doc.getElementById("files-pending-list").textContent, /~\/ws\/config/);
});

test("the file browser: a choice in a row's menu keeps the focus on that menu, never the row's tick box", async () => {
  const { doc } = rules();
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  choose(menuOf(rowFor(doc, /^README/)), "no-model");
  const now = menuOf(rowFor(doc, /^README/));
  assert.equal(doc.activeElement, now, "the menu chosen in");
  assert.notEqual(doc.activeElement, rowFor(doc, /^README/).querySelector(".file-tick"));
  assert.equal(now.value, "no-model");
});

test("an opened row: Remove my rule and Update keep the focus on the same button, drawn again; Enter in the hosts field keeps it there", async () => {
  const { doc } = rules();
  await tick();
  const box = openTreeRow(doc, /^config/);
  const remove = doc.getElementById("files-unset");
  assert.equal(controlName(remove), "Remove my rule on ~/ws/config");
  remove.focus();
  remove.click();
  assert.notEqual(doc.getElementById("files-unset"), remove, "drawn again");
  assert.equal(doc.activeElement, doc.getElementById("files-unset"));
  assert.match(doc.getElementById("files-pending-list").textContent, /~\/ws\/config.*No rule of its own/);
  doc.getElementById("files-discard").click();
  assert.ok(box, "opened");
  // Update: the same label with the hosts typed.
  const to = doc.getElementById("lock-to");
  to.value = "db.internal";
  const update = doc.getElementById("files-to-update");
  assert.equal(controlName(update), "Update where ~/ws/config may still be sent");
  update.focus();
  update.click();
  assert.equal(doc.activeElement, doc.getElementById("files-to-update"));
  assert.match(doc.getElementById("files-pending-list").textContent, /may be sent to db\.internal/);
  // Enter in the hosts field queues the same and keeps the field.
  const field = doc.getElementById("lock-to");
  field.focus();
  field.value = "db.internal, backup.internal";
  field.dispatchEvent(new doc.defaultView.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
  assert.equal(doc.activeElement, doc.getElementById("lock-to"));
  assert.equal(doc.activeElement.value, "db.internal, backup.internal");
});

test("Show in policy.yaml keeps the focus through its read, in the tree's opened row and under a sending rule; Hide too", async () => {
  const { doc } = rules();
  await tick();
  const box = openTreeRow(doc, /^config/);
  const show = button(box, "Show in policy.yaml");
  assert.equal(controlName(show), "Show in policy.yaml: ~/ws/config");
  press(show);
  await tick();
  assert.equal(doc.activeElement, show, "given back after the read, never <body>");
  assert.equal(show.textContent, "Hide policy.yaml");
  assert.equal(controlName(show), "Hide policy.yaml: ~/ws/config");
  assert.match(box.querySelector(".rule-source").textContent, /level: no-model/);
  show.click();
  assert.equal(doc.activeElement, show);
  assert.equal(controlName(show), "Show in policy.yaml: ~/ws/config");
  // Under an opened sending rule.
  const detail = openListRow(doc, "b.example");
  const show2 = button(detail, "Show in policy.yaml");
  assert.equal(controlName(show2), "Show in policy.yaml: b.example");
  press(show2);
  await tick();
  assert.equal(doc.activeElement, show2);
  assert.match(detail.querySelector(".rule-source").textContent, /host: b\.example/);
});

test("Show in its folder and Show in the file browser give the focus to the browser row they opened", async () => {
  const { doc } = rules();
  await tick();
  const box = openTreeRow(doc, /^README/);
  const go = button(box, "Show in its folder");
  assert.equal(controlName(go), "Show in its folder: ~/ws/README.md");
  go.focus();
  go.click();
  await tick();
  assert.equal(doc.getElementById("lock-form").hidden, false, "the browser is open");
  const row = rowFor(doc, /^README/);
  assert.equal(row.classList.contains("open"), true, "with the file's row opened");
  assert.equal(doc.activeElement, row.querySelector(".file-more"), "the focus followed the page there");
  assert.equal(controlName(doc.activeElement), "Close ~/ws/README.md");
  // An answer about one file: Show in the file browser.
  const detail = openListRow(doc, "~/ws/notes.md");
  const browse = button(detail, "Show in the file browser");
  assert.equal(controlName(browse), "Show in the file browser: ~/ws/notes.md");
  assert.equal(controlName(button(detail, "Remove")), "Remove your answer about ~/ws/notes.md");
  browse.focus();
  browse.click();
  await tick();
  // notes.md is not in the listing: the path box, at the top of the browser.
  assert.equal(doc.activeElement, doc.getElementById("lock-path"));
});

test("the opened rows' buttons are named by their row, and no two share a name", async () => {
  const { doc } = rules();
  await tick();
  openTreeRow(doc, /^config/);
  const sending = openListRow(doc, "b.example");
  assert.equal(controlName(button(sending, "Remove")), "Remove the rule for b.example");
  const names = [...reachableControls(opened(doc)), ...reachableControls(sending)].map(controlName);
  assert.deepEqual(names, [
    "May still be sent to (optional, comma-separated)",
    "Update where ~/ws/config may still be sent",
    "Remove my rule on ~/ws/config",
    "Show in policy.yaml: ~/ws/config",
    "Show in its folder: ~/ws/config",
    "Show in policy.yaml: b.example",
    "Remove the rule for b.example",
  ]);
  assert.equal(new Set(names).size, names.length);
});

test("nothing is taken: a choice or a press made without the focus there moves nothing", async () => {
  const { doc } = rules();
  await tick();
  const add = doc.getElementById("rules-add");
  add.focus();
  // A menu changed by a pointer that left the focus elsewhere.
  const sel = menuOf(treeRow(doc, /^config/));
  sel.value = "any-model";
  sel.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
  assert.equal(doc.activeElement, add, "the focus stays where the person has it");
  // Show in its folder clicked by a browser that does not focus a clicked button.
  const box = openTreeRow(doc, /^README/);
  add.focus();
  button(box, "Show in its folder").click();
  await tick();
  assert.equal(doc.activeElement, add);
  // Show in policy.yaml likewise.
  const show = button(box, "Show in policy.yaml");
  add.focus();
  show.click();
  await tick();
  assert.equal(doc.activeElement, add);
  // Nothing focused at all: the press still takes nothing.
  add.blur();
  assert.equal(doc.activeElement, doc.body);
  button(box, "Show in its folder").click();
  await tick();
  assert.equal(doc.activeElement, doc.body, "no focus given to a press that had none");
});
