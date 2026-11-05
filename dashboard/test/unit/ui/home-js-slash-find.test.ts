/**
 * home-js-slash-find.test — dashboard.md §4.25 *`/` finds*. The product
 * page has four Find boxes and no key to reach them: each took a click or a
 * run of Tabs. Now a `/` typed outside any text box puts the cursor in the
 * page's box, its text selected:
 *
 *   K1  History: *Find a session* (`#history-q`); Approvals: *Find an
 *       answer* (`#answered-q`); Rules: *Find a rule* (`#rules-find`): the
 *       box has the focus, its text is selected, and the key is
 *       `defaultPrevented`, so no `/` lands in the box;
 *   K2  Approvals with *Answered earlier*'s form hidden (no answer yet):
 *       *Find a change* (`#changes-q`);
 *   K3  the key is left alone (no focus moved, not prevented, so the
 *       browser keeps its own `/`): on Home; with the page's box hidden
 *       (#55 on History, #141 on Rules, both forms on Approvals); with the
 *       focus in Describe's text area, in a rule's menu or in another text
 *       box; with Ctrl, Alt or Meta held;
 *   K4  each box names the key: `aria-keyshortcuts="/"` and a title ending
 *       "Press / to come back here.".
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { HTML, home, load, tick, rulesPage } from "./home-js-fixtures.js";

const AT = "http://127.0.0.1:4500/mandu/";
const BOXES = ["history-q", "answered-q", "changes-q", "rules-find"];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
/** A keydown of `/` on `target` (the body unless given), bubbling to the document as a real one does. */
function slash(doc: Doc, mods: Record<string, boolean> = {}, target: Doc = doc.body) {
  const e = new doc.defaultView.KeyboardEvent("keydown", { key: "/", code: "Slash", bubbles: true, cancelable: true, ...mods });
  target.dispatchEvent(e);
  return e;
}
/** The box has the focus and all its text selected. */
function focusedSelected(doc: Doc, id: string) {
  const box = doc.getElementById(id);
  assert.equal(doc.activeElement, box, `the focus is in #${id}`);
  assert.equal(box.selectionStart, 0, "its text selected from the start");
  assert.equal(box.selectionEnd, box.value.length, "to the end");
}

const session = (id: string) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", startedAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-01T10:05:00.000Z", state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null,
});
const HISTORY = { total: 2, rows: [session("s9"), session("s8")], next: null };
const answer = (i: number) => ({
  id: `egr-${i}`, sentence: [{ kind: "text", text: `Claude Code wants to send your secret KEY_${i} to ` }, { kind: "code", text: "api.stripe.com" }],
  outcome: "blocked", decidedAt: Date.now() - (i + 1) * 60_000, sessions: ["s1"], actions: [{ approve: true, scope: "always", label: "Always allow" }],
});
const answered = (n: number) => home({ waiting: [], answered: Array.from({ length: n }, (_, i) => answer(i)), answeredTotal: n, verdict: "secrets-only" });
const change = (i: number) => ({
  id: "pc-" + String(1000 - i).padStart(6, "0"), sentence: "You changed a rule on the Rules page", session: null, createdAt: Date.now() - (i + 1) * 60_000, undone: false, undoable: true,
  rows: [[{ kind: "text", text: "Always allow sending to " }, { kind: "code", text: "api.stripe.com" }]],
});
const changes = (n: number) => ({
  "GET policy/proposals?status=pending": { proposals: [] },
  "GET policy/changes?limit=21": { changes: Array.from({ length: n }, (_, i) => change(i)) },
});

test("K1 History: / on the page puts the cursor in Find a session, its text selected, and no / typed", async () => {
  const { doc, err } = load({ extensions: "", url: AT + "history?q=staging", homeVm: home(), routes: { "GET home/history?q=staging": { ...HISTORY, query: { text: "staging", all: 2 } } } });
  await tick();
  assert.equal(err, null);
  assert.equal(doc.getElementById("history-search").hidden, false);
  assert.equal(doc.getElementById("history-q").value, "staging");
  assert.notEqual(doc.activeElement, doc.getElementById("history-q"));
  const e = slash(doc);
  assert.equal(e.defaultPrevented, true, "the / is kept out of the box and from the browser's own find");
  focusedSelected(doc, "history-q");
  assert.equal(doc.getElementById("history-q").value, "staging", "the text stays, selected to be typed over");
});

test("K1 Approvals: / goes to Find an answer", async () => {
  const { doc } = load({ extensions: "", url: AT + "approvals", homeVm: answered(3), routes: changes(2) });
  await tick(40);
  assert.equal(doc.getElementById("answered-search").hidden, false);
  assert.equal(doc.getElementById("changes-search").hidden, false, "Find a change is there too: the first box is taken");
  const e = slash(doc);
  assert.equal(e.defaultPrevented, true);
  focusedSelected(doc, "answered-q");
});

test("K2 Approvals with Answered earlier's box hidden: / goes to Find a change", async () => {
  const { doc } = load({ extensions: "", url: AT + "approvals", homeVm: answered(0), routes: changes(2) });
  await tick(40);
  assert.equal(doc.getElementById("answered-search").hidden, true, "no answer yet: no box");
  assert.equal(doc.getElementById("changes-search").hidden, false);
  doc.getElementById("changes-q").value = "stripe";
  const e = slash(doc);
  assert.equal(e.defaultPrevented, true);
  focusedSelected(doc, "changes-q");
});

test("K1 Rules: / goes to Find a rule", async () => {
  const { doc } = rulesPage();
  await tick();
  assert.equal(doc.getElementById("rules-find").hidden, false);
  const e = slash(doc);
  assert.equal(e.defaultPrevented, true);
  focusedSelected(doc, "rules-find");
});

/** The key left to the browser: not prevented, the focus where it was. */
function leftAlone(doc: Doc, mods: Record<string, boolean> = {}, target: Doc = doc.body, why = "") {
  const before = doc.activeElement;
  const e = slash(doc, mods, target);
  assert.equal(e.defaultPrevented, false, `not prevented ${why}`);
  assert.equal(doc.activeElement, before, `the focus stays ${why}`);
  assert.ok(!BOXES.some((id) => doc.activeElement === doc.getElementById(id)), `no Find box takes it ${why}`);
}

test("K3 on Home there is no box: / is the browser's", async () => {
  const { doc } = load({ extensions: "", url: AT, homeVm: home() });
  await tick();
  assert.equal(doc.getElementById("page-home").hidden, false);
  leftAlone(doc, {}, doc.body, "on Home");
});

test("K3 a hidden box is not reached: History with nothing to find, Rules with no rule, Approvals with neither form", async () => {
  const hist = load({ extensions: "", url: AT + "history", homeVm: home(), routes: { "GET home/history": { total: 0, rows: [], next: null } } });
  await tick();
  assert.equal(hist.doc.getElementById("history-search").hidden, true);
  leftAlone(hist.doc, {}, hist.doc.body, "on an empty History");

  const rules = load({ extensions: "", url: AT + "rules", routes: { "GET secrets": { panel: { labels: [] } } } });
  await tick();
  assert.equal(rules.doc.getElementById("rules-find").hidden, true, "no rule: no box (#141)");
  leftAlone(rules.doc, {}, rules.doc.body, "on an empty Rules");

  const appr = load({ extensions: "", url: AT + "approvals", homeVm: answered(0), routes: changes(0) });
  await tick(40);
  assert.equal(appr.doc.getElementById("answered-search").hidden, true);
  assert.ok(appr.doc.getElementById("changes-q").closest("[hidden]"), "Find a change hidden too");
  leftAlone(appr.doc, {}, appr.doc.body, "on an Approvals with nothing to find");
});

test("K3 in a text area, a menu or another text box, / is typed there, not taken", async () => {
  const { doc } = rulesPage();
  await tick();
  const describe = doc.getElementById("describe-text");
  describe.focus();
  leftAlone(doc, {}, describe, "in Describe's text area");
  const menu = doc.querySelector("#page-rules select");
  assert.ok(menu, "a rule's menu is drawn");
  menu.focus();
  leftAlone(doc, {}, menu, "in a rule's menu");
  const hist = load({ extensions: "", url: AT + "history", homeVm: home(), routes: { "GET home/history": HISTORY } });
  await tick();
  const day = hist.doc.getElementById("history-day");
  day.focus();
  leftAlone(hist.doc, {}, day, "in Go to a day");
  const editable = hist.doc.createElement("div");
  editable.setAttribute("contenteditable", "true");
  hist.doc.getElementById("page-history").append(editable);
  leftAlone(hist.doc, {}, editable, "in editable text");
});

test("K3 with Ctrl, Alt or Meta held, / is the browser's", async () => {
  const { doc } = load({ extensions: "", url: AT + "history", homeVm: home(), routes: { "GET home/history": HISTORY } });
  await tick();
  assert.equal(doc.getElementById("history-search").hidden, false);
  for (const mod of ["ctrlKey", "altKey", "metaKey"]) leftAlone(doc, { [mod]: true }, doc.body, `with ${mod}`);
  // Shift is not a reason: some keyboards type / with Shift.
  assert.equal(slash(doc, { shiftKey: true }).defaultPrevented, true);
  focusedSelected(doc, "history-q");
});

test("K4 each Find box names the key: aria-keyshortcuts and its title", () => {
  for (const id of BOXES) {
    const tag = new RegExp(`<input[^>]*\\sid="${id}"[^>]*>`).exec(HTML)?.[0] ?? "";
    assert.match(tag, /\saria-keyshortcuts="\/"/, `#${id} carries aria-keyshortcuts="/"`);
    assert.match(tag, /\stitle="[^"]*Press \/ to come back here\."/, `#${id} says so in its title`);
  }
});
