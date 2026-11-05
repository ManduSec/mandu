/**
 * home-js-menu-keys.test — a menu that saves at once waits for Enter from
 * the keyboard (dashboard.md §4.25 *A menu that saves at once waits for
 * Enter from the keyboard*): Your rules' effect menu (a rule, a past answer)
 * and a prompt filter's action in Settings.
 *
 * Chromium on Linux and Windows (and Firefox) pick the next option on an
 * arrow key on a closed `<select>` and fire `change` at once. Until
 * 2026-10-23 each `change` saved, so one Down arrow on a past answer's
 * "Always blocked" posted `…/approve` with no question, and arrowing
 * through a prompt filter's five choices saved each in turn. Pins:
 *
 *   - a browsing key (ArrowDown here), then `change`: nothing is posted, the
 *     menu shows the new choice, and a line under the row (role=status,
 *     describing the menu) names both choices;
 *   - Enter: exactly one POST, the body a click sends, and the focus back on
 *     the row's menu as after a click;
 *   - Escape, or leaving the menu: the choice in force again, no line, no
 *     POST;
 *   - a `change` with no browsing key first (a pointer pick, a pick from the
 *     opened list: Alt+Down, then Enter) posts at once, as before;
 *   - a list drawn again while a choice waits shows it again.
 *
 * jsdom changes no value on a key, so a test presses the key, sets the
 * value, and fires `change`, as the browser does; and it keeps the focus of
 * a control turned off, so `drop` blurs it as Chromium does. Drives the
 * PRODUCT page script (public/js/home.js) over the shared fetch stub
 * (home-js-fixtures.ts). Axes: none (display only: the stub stands in for
 * the server; tests/stack/rules-change-focus.test.ts and
 * dashboard-prompt-settings.test.ts run it over a real arbiter in
 * `secrets`). Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick } from "./home-js-fixtures.js";
import { promptSettingsVM, type PromptFiltersProjection } from "../../../src/view-model/prompt-settings.js";

const RULES_URL = "http://127.0.0.1:4500/mandu/rules";
const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const sendRule = (id: string, host: string, mode: "allow" | "block") => ({
  id, kind: `release-${mode}`, subject: host, effect: mode === "allow" ? "Always allowed" : "Always blocked",
  reach: `from any source to ${host}`, hits: 1, actions: { remove: true, flip: mode === "allow" ? "block" : "allow" },
});
const answer = (id: string, host: string, approved: boolean) => ({
  id, status: approved ? "approved" : "denied", scope: "always", where: "network", target: host, count: 1,
  actions: [{ approve: !approved, label: approved ? "Block instead" : "Allow instead" }],
  plain: { subject: host, reach: null, effect: approved ? "Always allowed" : "Always blocked" },
  sessions: [], resolvedAt: null,
});

/** The Rules page: api.example.com always allowed, and a past answer that
 *  always blocks a send to old.example. */
function rules() {
  let yourRules: unknown[] = [sendRule("r-0001", "api.example.com", "allow")];
  let queue: unknown[] = [answer("egr-6", "old.example", false)];
  return load({ url: RULES_URL, routes: {
    "GET policy/panel": () => ({ panel: { available: true, verdictsKnown: true, yourRules, queue } }),
    "POST policy/rules/change": (b: { id: string; action: string }) => {
      yourRules = yourRules.map((r) => ((r as { id: string }).id === b.id ? sendRule(b.id, (r as { subject: string }).subject, b.action as "allow" | "block") : r));
      return { applied: true, changeId: "pc-0007" };
    },
    "POST egress/approvals/egr-6/approve": () => { queue = [answer("egr-6", "old.example", true)]; return { approval: { id: "egr-6" } }; },
  } });
}

const PROJ: PromptFiltersProjection = {
  filters: [{ id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] }],
  actions: [{ category: "secret.registered", action: "mask", setBy: "default", locked: false }],
  fallback: "redact",
  exceptions: [],
  enforcing: true,
  editable: true,
};
/** Settings over one prompt filter, "A secret Mandu already knows": Hide it. */
function settings() {
  let action = "mask";
  return load({ url: SETTINGS_URL, routes: {
    "GET policy/prompt-filters": () => ({ settings: promptSettingsVM({ ...PROJ, actions: [{ category: "secret.registered", action, setBy: action === "mask" ? "default" : "you", locked: false }] }) }),
    "POST policy/prompt-filters/change": (b: { edit: { action: string } }) => { action = b.edit.action; return { applied: true, changeId: "pc-9" }; },
  } });
}

const rowOf = (doc: Doc, host: string) => [...doc.querySelectorAll("#rules-list .row.rule")].find((r: Doc) => r.querySelector(".rule-text code")?.textContent === host);
const menuOf = (doc: Doc, host: string) => rowOf(doc, host)?.querySelector("select.effect-select");
const kindRow = (doc: Doc) => doc.querySelector('#settings-prompt-kinds .prompt-kind[data-category="secret.registered"]');
const kindMenu = (doc: Doc) => kindRow(doc)?.querySelector("select.prompt-action");
const lineOf = (row: Doc) => row.querySelector(".menu-wait");
const posts = (calls: { method: string; url: string }[]) => calls.filter((c) => c.method === "POST");
const shown = (sel: Doc) => sel.options[sel.selectedIndex]?.textContent;

function key(sel: Doc, k: string, init: Record<string, unknown> = {}): Doc {
  const ev = new sel.ownerDocument.defaultView.KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true, ...init });
  sel.dispatchEvent(ev);
  return ev;
}
function change(sel: Doc, value: string): void {
  sel.value = value;
  sel.dispatchEvent(new sel.ownerDocument.defaultView.Event("change", { bubbles: true }));
}
/** A Down arrow on the closed menu, as Chromium on Linux takes it: the next
 *  choice, and `change` at once. */
function arrow(sel: Doc, value: string): void {
  sel.focus();
  key(sel, "ArrowDown");
  change(sel, value);
}
/** The browser drops the focus of a control the change turned off. */
function drop(x: Doc): void {
  assert.equal(x.disabled, true, "the change turns its menu off while it is on its way");
  x.disabled = false;
  x.blur();
  x.disabled = true;
}
const later = () => new Promise<void>((r) => setTimeout(r, 5));

test("Your rules: a Down arrow on a rule's menu saves nothing and says how to; Enter saves it as a click does, the focus back on the menu", async () => {
  const { doc, calls } = rules();
  await tick();
  const sel = menuOf(doc, "api.example.com");
  arrow(sel, "flip");
  await tick();
  assert.deepEqual(posts(calls), [], "nothing is sent on the arrow key");
  assert.equal(shown(sel), "Always blocked", "the menu shows the new choice");
  const line = lineOf(rowOf(doc, "api.example.com"));
  assert.equal(line.textContent, "Press Enter to change it to Always blocked, or Escape to keep Always allowed.");
  assert.equal(line.getAttribute("role"), "status");
  assert.equal(sel.getAttribute("aria-describedby"), line.id, "a screen reader reads the line with the menu");

  const ev = key(sel, "Enter");
  assert.equal(ev.defaultPrevented, true);
  drop(sel);
  await tick(30);
  assert.deepEqual(posts(calls).map((c) => [c.url, (c as { body?: unknown }).body]), [["/mandu/api/policy/rules/change", { id: "r-0001", action: "block" }]],
    "exactly one POST, the body a click sends");
  const now = menuOf(doc, "api.example.com");
  assert.equal(doc.activeElement, now, "the focus is back on the row's menu, drawn again");
  assert.equal(shown(now), "Always blocked");
  assert.equal(lineOf(rowOf(doc, "api.example.com")), null);
  assert.equal(now.getAttribute("aria-describedby"), null);
  assert.equal(doc.getElementById("rules-notice").firstChild.textContent, "Now always blocked.");
});

test("Your rules: Escape, or leaving the menu, puts back the effect in force; nothing is sent", async () => {
  const { doc, calls } = rules();
  await tick();
  const sel = menuOf(doc, "api.example.com");
  arrow(sel, "flip");
  const ev = key(sel, "Escape");
  assert.equal(ev.defaultPrevented, true, "the Escape is the menu's");
  assert.equal(sel.value, "", "the effect in force");
  assert.equal(shown(sel), "Always allowed");
  assert.equal(lineOf(rowOf(doc, "api.example.com")), null, "the line is gone");
  assert.equal(sel.getAttribute("aria-describedby"), null);
  // An Escape with nothing waiting is not the menu's.
  assert.equal(key(sel, "Escape").defaultPrevented, false);

  arrow(sel, "flip");
  assert.ok(lineOf(rowOf(doc, "api.example.com")));
  doc.getElementById("rules-add").focus();
  await later();
  assert.equal(sel.value, "", "leaving the menu: the effect in force");
  assert.equal(lineOf(rowOf(doc, "api.example.com")), null);
  // An arrow back to the effect in force waits for nothing.
  arrow(sel, "flip");
  key(sel, "ArrowUp");
  change(sel, "");
  assert.equal(lineOf(rowOf(doc, "api.example.com")), null);
  await tick(30);
  assert.deepEqual(posts(calls), [], "no POST at all");
});

test("Your rules: a past answer's Always blocked menu never posts …/approve on a Down arrow alone", async () => {
  const { doc, calls } = rules();
  await tick();
  const sel = menuOf(doc, "old.example");
  assert.equal(shown(sel), "Always blocked");
  arrow(sel, "flip");
  key(sel, "ArrowDown");
  change(sel, "flip");
  sel.blur();
  await later();
  await tick(30);
  assert.ok(!calls.some((c) => c.url.endsWith("/approve")), "the send stays blocked");
  assert.equal(shown(menuOf(doc, "old.example")), "Always blocked");

  // Enter makes it, with the answer's own route.
  arrow(sel, "flip");
  assert.equal(lineOf(rowOf(doc, "old.example")).textContent, "Press Enter to change it to Always allowed, or Escape to keep Always blocked.");
  key(sel, "Enter");
  drop(sel);
  await tick(30);
  assert.deepEqual(posts(calls).map((c) => c.url), ["/mandu/api/egress/approvals/egr-6/approve"]);
  assert.equal(doc.activeElement, menuOf(doc, "old.example"));
});

test("Your rules: a pick with the pointer, or from the opened list, saves at once as before", async () => {
  const { doc, calls } = rules();
  await tick();
  // A pointer press clears a mark left by a key.
  const sel = menuOf(doc, "api.example.com");
  sel.focus();
  key(sel, "ArrowDown");
  sel.dispatchEvent(new doc.defaultView.MouseEvent("mousedown", { bubbles: true }));
  change(sel, "flip");
  assert.equal(lineOf(rowOf(doc, "api.example.com")), null);
  await tick(30);
  assert.deepEqual(posts(calls).map((c) => c.url), ["/mandu/api/policy/rules/change"]);

  // Alt+Down opens the list; a browser that sends the list's keys to the
  // page (an arrow, then Enter) picks at once too.
  const answerMenu = menuOf(doc, "old.example");
  answerMenu.focus();
  key(answerMenu, "ArrowDown", { altKey: true });
  key(answerMenu, "ArrowDown");
  key(answerMenu, "Enter");
  change(answerMenu, "flip");
  await tick(30);
  assert.deepEqual(posts(calls).map((c) => c.url), ["/mandu/api/policy/rules/change", "/mandu/api/egress/approvals/egr-6/approve"]);
});

test("Your rules: the list drawn again while a choice waits shows it again, and Enter on the new menu saves it", async () => {
  const { doc, calls } = rules();
  await tick();
  const old = menuOf(doc, "api.example.com");
  arrow(old, "flip");
  // Rules' find box draws the list again.
  doc.getElementById("rules-find").dispatchEvent(new doc.defaultView.Event("input", { bubbles: true }));
  await tick();
  const now = menuOf(doc, "api.example.com");
  assert.notEqual(now, old, "drawn again");
  assert.equal(shown(now), "Always blocked", "the waiting choice");
  const line = lineOf(rowOf(doc, "api.example.com"));
  assert.ok(line, "with its line");
  assert.equal(rowOf(doc, "api.example.com").lastElementChild, line, "under the row");
  assert.equal(now.getAttribute("aria-describedby"), line.id);
  await later();
  assert.deepEqual(posts(calls), []);
  now.focus();
  key(now, "Enter");
  await tick(30);
  assert.deepEqual(posts(calls).map((c) => (c as { body?: unknown }).body), [{ id: "r-0001", action: "block" }]);
});

test("Settings › Prompt filters: arrowing through the choices saves none; Enter saves the one shown; Escape keeps Hide it", async () => {
  const { doc, calls } = settings();
  await tick();
  let sel = kindMenu(doc);
  assert.equal(shown(sel), "Hide it");
  // From Hide it down to Just note it: four keys, no save on the way.
  sel.focus();
  for (const v of ["redact", "ask", "block", "log"]) { key(sel, "ArrowDown"); change(sel, v); }
  await tick(30);
  assert.deepEqual(posts(calls), [], "nothing is saved on the way");
  assert.equal(sel.disabled, false, "the menu stays on for the next key");
  assert.equal(lineOf(kindRow(doc)).textContent, "Press Enter to change it to Just note it, or Escape to keep Hide it.");
  assert.equal(sel.getAttribute("aria-describedby"), lineOf(kindRow(doc)).id);

  key(sel, "Escape");
  assert.equal(sel.value, "mask");
  assert.equal(lineOf(kindRow(doc)), null);

  // Leaving it.
  key(sel, "End");
  change(sel, "log");
  sel.blur();
  await later();
  assert.equal(sel.value, "mask");
  assert.equal(lineOf(kindRow(doc)), null);
  assert.deepEqual(posts(calls), []);

  // Enter: one POST, the body a pick sends, and the focus back on the menu.
  sel.focus();
  key(sel, "ArrowDown");
  change(sel, "redact");
  key(sel, "Enter");
  drop(sel);
  await tick(30);
  assert.deepEqual(posts(calls).map((c) => (c as { body?: unknown }).body), [{ edit: { op: "set-prompt-action", category: "secret.registered", action: "redact" } }]);
  sel = kindMenu(doc);
  assert.equal(doc.activeElement, sel, "the focus is back on the kind's menu");
  assert.equal(sel.value, "redact");
  assert.match(doc.getElementById("prompt-notice").textContent, /A secret Mandu already knows: Remove it\. It applies to your next message\./);

  // A pick with no key first saves at once, as before.
  change(sel, "block");
  await tick(30);
  assert.equal(posts(calls).length, 2);
});
