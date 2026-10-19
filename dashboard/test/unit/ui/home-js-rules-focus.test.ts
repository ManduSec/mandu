/**
 * home-js-rules-focus.test — a change made in Your rules on the Rules page
 * keeps the keyboard focus (dashboard.md §4.25 *A change in Your rules keeps
 * the focus*).
 *
 * Until 2026-10-11 a change in a sending rule's menu (Always allowed /
 * Always blocked), on an answer's menu, Remove under an opened rule or
 * answer, and the notice's Undo each left the focus on <body>: the row's
 * menu or button goes off while the change is on its way (`busyRow`), and
 * the list is drawn again after it. Settings had the same fault, fixed the
 * same day (home-js-settings-focus.test.ts); this page reuses its rule:
 *
 *   - after a change in a row's menu, the focus is on that row's menu, drawn
 *     again, reading the new effect. A menu reads as its name ("What happens
 *     for api.example.com"), not its options, and its colour (`data-effect`)
 *     is no key of its place;
 *   - after Remove, or Undo, the "Your rules" heading; never another row's
 *     menu or button;
 *   - a refused change gives the focus back to the menu or button pressed,
 *     described by the refusal's words; a declined question gives it back;
 *   - a focus moved elsewhere meanwhile, or a press made without the focus,
 *     moves nothing.
 *
 * jsdom keeps the focus of a control turned off, so `press` and `pick` drop
 * it to <body>, as Chromium does (home-js-answer-focus.test.ts). Drives the
 * PRODUCT page script (public/js/home.js) in jsdom over the shared fetch
 * stub (home-js-fixtures.ts). Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick } from "./home-js-fixtures.js";
import { controlName } from "./control-names.js";

const RULES_URL = "http://127.0.0.1:4500/mandu/rules";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const sendRule = (id: string, host: string, mode: "allow" | "block") => ({
  id, kind: `release-${mode}`, subject: host, effect: mode === "allow" ? "sending allowed" : "sending blocked",
  reach: `from any source to ${host}`, hits: 1, actions: { remove: true, flip: mode === "allow" ? "block" : "allow" },
});
const answer = (id: string, host: string, approved: boolean) => ({
  id, status: approved ? "approved" : "denied", scope: "always", where: "network", target: host, count: 1,
  actions: [{ approve: !approved, label: approved ? "Block instead" : "Allow instead" }],
  plain: { subject: host, reach: null, effect: approved ? "Always allowed" : "Always blocked" },
  sessions: [], resolvedAt: null,
});
const panelOf = (yourRules: unknown[], queue: unknown[]) => ({ panel: { available: true, verdictsKnown: true, yourRules, queue } });

/** Enter on a button: it has the focus, the click acts, and the browser
 *  drops the focus of the button the change turned off to <body>. */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  drop(btn);
}
/** A pick in a row's menu with the keyboard: the menu has the focus, the
 *  change acts, and the menu turned off loses the focus. */
function pick(sel: Doc, value = "flip"): void {
  sel.focus();
  sel.value = value;
  sel.dispatchEvent(new sel.ownerDocument.defaultView.Event("change", { bubbles: true }));
  drop(sel);
}
function drop(x: Doc): void {
  assert.equal(x.disabled, true, "the change turns its control off while it is on its way");
  x.disabled = false;
  x.blur();
  x.disabled = true;
  assert.equal(x.ownerDocument.activeElement, x.ownerDocument.body);
}
const focused = (doc: Doc) => doc.activeElement;
const rowOf = (doc: Doc, host: string) => [...doc.querySelectorAll("#rules-list .row.rule")].find((r: Doc) => r.querySelector(".rule-text code")?.textContent === host);
const menuOf = (doc: Doc, host: string) => rowOf(doc, host)?.querySelector("select.effect-select");
const effects = (sel: Doc) => [...sel.options].map((o: Doc) => o.textContent);
/** Open a row's ⋯ (unless open) and return the opened part under it. */
const opened = (doc: Doc, host: string) => {
  const more = rowOf(doc, host).querySelector(".file-more");
  if (more.getAttribute("aria-expanded") !== "true") more.click();
  return rowOf(doc, host).nextElementSibling;
};
const removeIn = (box: Doc) => [...box.querySelectorAll("button")].find((b: Doc) => b.textContent === "Remove");
const heading = (doc: Doc) => doc.getElementById("rules-title");

/** The Rules page over a panel that follows the changes posted. */
function rules(routes: Record<string, unknown> = {}) {
  let yourRules: unknown[] = [sendRule("r-0001", "api.example.com", "allow"), sendRule("r-0002", "b.example", "block")];
  let queue: unknown[] = [answer("egr-7", "paste.example", true), answer("egr-6", "old.example", false)];
  const page = load({ url: RULES_URL, routes: {
    "GET policy/panel": () => panelOf(yourRules, queue),
    "POST policy/rules/change": (b: { id: string; action: string }) => {
      if (b.action === "remove") yourRules = yourRules.filter((r) => (r as { id: string }).id !== b.id);
      else yourRules = yourRules.map((r) => ((r as { id: string }).id === b.id ? sendRule(b.id, (r as { subject: string }).subject, b.action as "allow" | "block") : r));
      return { applied: true, changeId: "pc-0007" };
    },
    "POST egress/approvals/egr-7/deny": () => { queue = queue.map((q) => ((q as { id: string }).id === "egr-7" ? answer("egr-7", "paste.example", false) : q)); return { approval: { id: "egr-7" } }; },
    "POST egress/approvals/egr-6/forget": () => { queue = queue.filter((q) => (q as { id: string }).id !== "egr-6"); return { approval: { id: "egr-6" } }; },
    "POST policy/changes/pc-0007/undo": () => { yourRules = [sendRule("r-0001", "api.example.com", "allow"), sendRule("r-0002", "b.example", "block")]; return { ok: true }; },
    ...routes,
  } });
  return page;
}

test("Your rules: a change in a rule's menu gives the focus back to that row's menu, drawn again with the new effect", async () => {
  const { doc } = rules();
  await tick();
  const old = menuOf(doc, "api.example.com");
  assert.deepEqual(effects(old), ["sending allowed", "Always blocked"]);
  pick(old);
  await tick(30);
  const now = menuOf(doc, "api.example.com");
  assert.notEqual(now, old, "the list was drawn again");
  assert.deepEqual(effects(now), ["sending blocked", "Always allowed"], "the row says the new effect");
  assert.equal(focused(doc), now, "the same row's menu, though its options read otherwise now");
  assert.equal(controlName(now), "What happens for api.example.com");
  assert.equal(now.value, "", "it shows the effect in force");
  assert.equal(doc.getElementById("rules-notice").firstChild.textContent, "Now always blocked.");
});

test("Your rules: a change in an answer's menu gives the focus back to that answer's menu", async () => {
  const { doc, calls } = rules();
  await tick();
  pick(menuOf(doc, "paste.example"));
  await tick(30);
  assert.ok(calls.some((c) => c.method === "POST" && c.url === "/mandu/api/egress/approvals/egr-7/deny"));
  const now = menuOf(doc, "paste.example");
  assert.deepEqual(effects(now), ["Always blocked", "Always allowed"]);
  assert.equal(focused(doc), now);
  assert.equal(controlName(now), "What happens for paste.example");
});

test("Your rules: Remove under an opened rule or answer gives the focus to the Your rules heading, never another row's control", async () => {
  const { doc } = rules();
  await tick();
  press(removeIn(opened(doc, "api.example.com")));
  await tick(30);
  assert.equal(rowOf(doc, "api.example.com"), undefined, "removed");
  assert.equal(focused(doc), heading(doc), "the block's heading, not b.example's menu that took the row's place");
  assert.equal(focused(doc).getAttribute("tabindex"), "-1", "no Tab stop");
  assert.equal(doc.getElementById("rules-notice").firstChild.textContent, "Rule removed.");

  press(removeIn(opened(doc, "old.example")));
  await tick(30);
  assert.equal(rowOf(doc, "old.example"), undefined, "the answer is forgotten");
  assert.equal(focused(doc), heading(doc));
  assert.match(doc.getElementById("rules-notice").textContent, /asked again next time/);
});

test("Your rules: the notice's Undo gives the focus to the Your rules heading; a refused Undo too, its words in the notice", async () => {
  const { doc, calls } = rules({ "POST policy/changes/pc-0008/undo": { status: 409, body: { error: "This change was already undone." } } });
  await tick();
  pick(menuOf(doc, "b.example"));
  await tick(30);
  const undo = () => [...doc.querySelectorAll("#rules-notice button")].find((b: Doc) => b.textContent === "Undo");
  press(undo());
  await tick(30);
  assert.ok(calls.some((c) => c.method === "POST" && c.url === "/mandu/api/policy/changes/pc-0007/undo"));
  assert.equal(doc.getElementById("rules-notice").textContent, "Undone.");
  assert.equal(focused(doc), heading(doc));
  assert.deepEqual(effects(menuOf(doc, "b.example")), ["sending blocked", "Always allowed"], "the rule as it was");

  // A refused Undo: the notice says why, with no Undo left to give it to.
  const page = rules({ "POST policy/rules/change": { applied: true, changeId: "pc-0008" }, "POST policy/changes/pc-0008/undo": { status: 409, body: { error: "This change was already undone." } } });
  await tick();
  pick(menuOf(page.doc, "api.example.com"));
  await tick(30);
  press([...page.doc.querySelectorAll("#rules-notice button")].find((b: Doc) => b.textContent === "Undo"));
  await tick(30);
  assert.match(page.doc.getElementById("rules-notice").textContent, /already undone/);
  assert.equal(focused(page.doc), heading(page.doc));
});

test("Your rules: a refused change gives the focus back to the menu or button pressed, described by the refusal's words; a declined question gives it back", async () => {
  const page = rules({
    "POST policy/rules/change": { status: 403, body: { error: "admin session required — run `mandu dashboard` in your own terminal and open the sign-in link it prints (or set DASHBOARD_PASSWORD)" } },
    "POST egress/approvals/egr-6/forget": { status: 403, body: { error: "admin session required" } },
  });
  const { doc } = page;
  await tick();
  const sel = menuOf(doc, "api.example.com");
  pick(sel);
  await tick(30);
  assert.equal(focused(doc), sel, "the same menu, on again");
  assert.equal(sel.disabled, false);
  assert.equal(sel.value, "", "it shows the effect in force");
  const words = rowOf(doc, "api.example.com").querySelector(".ask-error");
  assert.match(words.textContent, /^Sign in first/);
  assert.equal(sel.getAttribute("aria-describedby"), words.id, "the refusal's words are read with the menu");

  const b = removeIn(opened(doc, "old.example"));
  press(b);
  await tick(30);
  assert.equal(focused(doc), b, "Remove, on again");
  assert.equal(b.getAttribute("aria-describedby"), b.closest(".rule-detail").querySelector(".ask-error").id);

  // Remove that loosens asks first; declined, nothing is sent again and the
  // focus is where it was pressed.
  const asked = rules({ "POST policy/rules/change": { applied: false, confirm: true, expected: ["k"] } });
  await tick();
  asked.window.confirm = () => false;
  const r = removeIn(opened(asked.doc, "b.example"));
  press(r);
  await tick(30);
  assert.equal(focused(asked.doc), r);
  assert.equal(r.disabled, false);
  assert.equal(r.getAttribute("aria-describedby"), null, "nothing was refused");
});

test("Your rules: a focus moved elsewhere meanwhile, and a press made without the focus, move nothing", async () => {
  const { doc } = rules();
  await tick();
  pick(menuOf(doc, "api.example.com"));
  const elsewhere = doc.getElementById("rules-add");
  elsewhere.focus();
  await tick(30);
  assert.equal(focused(doc), elsewhere);

  // A click with the focus outside the block (a browser that does not focus
  // a clicked button): nothing is given the focus.
  doc.activeElement.blur();
  const more = rowOf(doc, "b.example").querySelector(".file-more");
  more.click();
  doc.activeElement.blur();
  removeIn(rowOf(doc, "b.example").nextElementSibling).click();
  await tick(30);
  assert.equal(rowOf(doc, "b.example"), undefined, "removed");
  assert.equal(focused(doc), doc.body);
});
