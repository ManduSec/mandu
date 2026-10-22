/**
 * home-js-answer-focus.test — an answer keeps the keyboard focus in its list
 * (dashboard.md §4.25 *An answer keeps the focus in its list*).
 *
 * Every answer button of the product page turns its card's buttons off
 * while the answer is on its way, and Chromium drops the focus of a button
 * turned off to <body> (seen 2026-10-11 in a headless Chromium). Until
 * 2026-10-11 it stayed there: after Enter on Allow once the next question,
 * an empty list, or a refusal's words were never read out, and a refused
 * answer's button, on again, had lost the focus. Now:
 *
 *   - an answer that worked to a waiting question gives the focus to the
 *     line it leaves where its card was (dashboard.md §4.25 *An answer says
 *     what it did*, since 2026-10-22; before, the card that took its place,
 *     else the one before it, else the list's line); a rule change's answer
 *     to the next request, else the section's or the page's heading; never
 *     an answer button;
 *   - an answered row still drawn (Block instead, Undo) and a let-through's
 *     row keep it;
 *   - a refused answer gives it back to the button pressed, described by
 *     the refusal's words;
 *   - a poll while the answer is on its way, a focus moved elsewhere, and a
 *     press made without the focus in the card move nothing.
 *
 * jsdom keeps the focus of a button turned off, so `press` drops it to
 * <body> after the click, as Chromium does. Drives the PRODUCT page script
 * (public/js/home.js) in jsdom over the shared fetch stub
 * (home-js-fixtures.ts). Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, ASK, home, load, tick } from "./home-js-fixtures.js";

const ASK2 = { ...ASK, id: "egr-2" };
const ASK3 = { ...ASK, id: "egr-3" };
const APPROVALS = "http://127.0.0.1:4500/mandu/approvals";
const ADMIN_403 = { status: 403, body: { error: "admin session required — run `mandu dashboard` in your own terminal and open the sign-in link it prints (or set DASHBOARD_PASSWORD)" } };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Page = ReturnType<typeof load>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const button = (root: any, label: string) => [...root.querySelectorAll("button")].find((b: any) => b.textContent === label) as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const cardOf = (doc: any, list: string, id: string) => [...doc.getElementById(list).children].find((c: any) => c.dataset.id === id) as any;
/** Enter on a button: it has the focus, the click answers, and the browser
 *  drops the focus of the button the answer turned off to <body>. jsdom
 *  neither drops it nor blurs a button that is off, so the button is on
 *  for the blur only. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function press(btn: any): void {
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "the answer turns its button off while it is on its way");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
  assert.equal(btn.ownerDocument.activeElement, btn.ownerDocument.body);
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const focused = (doc: any) => doc.activeElement;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function poll(doc: any): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
}

test("Approvals: an answer that worked gives the focus to the line it leaves where the card was, each time, above 'Nothing is waiting for you.' at the end", async () => {
  // eslint-disable-next-line prefer-const
  let page: Page;
  const after = (waiting: unknown[]) => () => (page.setHome(home({ waiting })), {});
  page = load({ url: APPROVALS, homeVm: home({ waiting: [ASK, ASK2, ASK3] }), routes: {
    "POST egress/approvals/egr-1/approve-once": after([ASK2, ASK3]),
    "POST egress/approvals/egr-3/deny": after([ASK2]),
    "POST egress/approvals/egr-2/approve": after([]),
  } });
  const { doc } = page;
  await tick();
  const list = doc.getElementById("approvals-waiting");
  press(button(cardOf(doc, "approvals-waiting", "egr-1"), "Allow once"));
  await tick(30);
  assert.equal(focused(doc), doc.querySelector("#approvals-waiting .answer-line"), "the line where the card was");
  assert.equal(focused(doc).getAttribute("tabindex"), "-1", "a line is no Tab stop");
  assert.equal(list.firstElementChild, focused(doc), "in the first card's place");
  // The last card answered: its line, after the card before it.
  press(button(cardOf(doc, "approvals-waiting", "egr-3"), "Block"));
  await tick(30);
  assert.equal(focused(doc), doc.querySelector("#approvals-waiting .answer-line"));
  assert.equal(focused(doc).previousElementSibling, cardOf(doc, "approvals-waiting", "egr-2"));
  // None left: the line, over the one that says so.
  press(button(cardOf(doc, "approvals-waiting", "egr-2"), "Always allow"));
  await tick(30);
  assert.match(focused(doc).textContent, /^Always allowed: /);
  assert.equal(focused(doc).parentElement.id, "approvals-waiting");
  assert.equal(focused(doc).nextElementSibling.textContent, "Nothing is waiting for you.");
});

test("Home: the line where the card was takes the focus, never the next card's Details link nor an answer button", async () => {
  // eslint-disable-next-line prefer-const
  let page: Page;
  page = load({ homeVm: home({ waiting: [ASK, ASK2] }), routes: {
    "POST egress/approvals/egr-1/deny": () => (page.setHome(home({ waiting: [ASK2] })), {}),
  } });
  const { doc } = page;
  await tick();
  press(button(cardOf(doc, "home-waiting", "egr-1"), "Block"));
  await tick(30);
  const card = cardOf(doc, "home-waiting", "egr-2");
  assert.equal(focused(doc), doc.querySelector("#home-waiting .answer-line"));
  assert.equal(focused(doc).tagName, "DIV");
  assert.equal(focused(doc).nextElementSibling, card, "the next question right after it");
  assert.ok(card.querySelector(".ask-details"), "its link is there, after it in the Tab order");
});

test("the agent page: the last card answered leaves its line in Needs your OK, which stays shown, and the line takes the focus", async () => {
  let agent: unknown = { ...AGENT, waiting: [ASK] };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: {
    "GET home/agent?session=s1": () => agent,
    "POST egress/approvals/egr-1/approve-once": () => ((agent = { ...AGENT, waiting: [] }), {}),
  } });
  await tick();
  press(button(cardOf(doc, "agent-waiting", "egr-1"), "Allow once"));
  await tick(40);
  assert.equal(doc.getElementById("agent-waiting-block").hidden, false, "shown while its line is");
  assert.equal(focused(doc), doc.querySelector("#agent-waiting .answer-line"));
});

test("Answered earlier: Block instead keeps the focus on its row, drawn again with the new outcome", async () => {
  const row = (outcome: string, approve: boolean) => ({ id: "egr-9", sentence: [{ kind: "text", text: "Claude Code wanted to send a file" }], outcome, decidedAt: Date.now() - 30_000, actions: [{ approve }] });
  // eslint-disable-next-line prefer-const
  let page: Page;
  page = load({ url: APPROVALS, homeVm: home({ waiting: [ASK], answered: [row("allowed", false)] }), routes: {
    "POST egress/approvals/egr-9/deny": () => (page.setHome(home({ waiting: [ASK], answered: [row("blocked", true)] })), {}),
  } });
  const { doc } = page;
  await tick();
  const before = cardOf(doc, "approvals-answered", "egr-9");
  press(button(before, "Block instead"));
  await tick(30);
  const now = cardOf(doc, "approvals-answered", "egr-9");
  assert.notEqual(now, before, "drawn again");
  assert.equal(focused(doc), now);
  assert.match(now.textContent, /Blocked/);
  // A poll that draws it again while it still has the focus gives the new
  // row the focus back.
  page.setHome(home({ waiting: [ASK, ASK2], answered: [row("blocked", true)] }));
  await poll(doc);
  assert.equal(focused(doc), cardOf(doc, "approvals-answered", "egr-9"));
});

test("a rule change your agent asked for: the next request takes the focus; with none left, the page's heading", async () => {
  const P1 = { id: "pp-000001", status: "pending", requester: "Your agent", createdAt: Date.now() - 60_000, rows: [[{ kind: "text", text: "Trust content from pypi.org" }]], wouldLet: [], capped: false, overBroad: false, reason: "" };
  const P2 = { ...P1, id: "pp-000002" };
  let pending = [P1, P2];
  const { doc } = load({ url: APPROVALS, routes: {
    "GET policy/proposals?status=pending": () => ({ proposals: pending }),
    "POST policy/proposals/pp-000001": () => ((pending = [P2]), {}),
    "POST policy/proposals/pp-000002": () => ((pending = []), {}),
  } });
  await tick();
  press(button(cardOf(doc, "approvals-proposals", "pp-000001"), "Allow"));
  await tick(30);
  assert.equal(focused(doc), cardOf(doc, "approvals-proposals", "pp-000002"));
  press(button(cardOf(doc, "approvals-proposals", "pp-000002"), "Not now"));
  await tick(30);
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, true);
  assert.equal(focused(doc), doc.querySelector("#page-approvals h1"));
});

test("Undo: its row keeps the focus, drawn again as undone", async () => {
  const change = (undoable: boolean) => ({ id: "pc-000001", sentence: "Your agent tightened your rules", rows: [], createdAt: Date.now(), undone: !undoable, undoable });
  let changes = [change(true)];
  const { doc } = load({ url: APPROVALS, routes: {
    "GET policy/changes?limit=21": () => ({ changes }),
    "POST policy/changes/pc-000001/undo": () => ((changes = [change(false)]), {}),
  } });
  await tick();
  press(button(cardOf(doc, "approvals-rule-history", "pc-000001"), "Undo"));
  await tick(30);
  const row = cardOf(doc, "approvals-rule-history", "pc-000001");
  assert.equal(focused(doc), row);
  assert.match(row.textContent, /Undone/);
});

test("a let-through that worked: its row keeps the focus once its buttons go", async () => {
  const note = { lines: ["One value in your prompt was hidden from the AI (an email address)."], items: [
    { eventId: "ev-1", index: 0, category: "pii.email", words: "an email address", state: "hidden", canLetOnce: true, canLetSession: true, canShow: false },
  ], ts: "2026-09-25T10:00:00.000Z" };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: {
    "GET home/agent?session=s1": { ...AGENT, waiting: [], story: [{ ...AGENT.story[0], promptNote: note }, { ...AGENT.story[1], promptNote: null }] },
    "POST prompt-filters/let-through": (b: { scope: string }) => ({ approval: { id: "egr-3" }, scope: b.scope }),
  } });
  await tick();
  const row = doc.querySelector("#agent-story .prompt-note-item");
  press(button(row, "Let it through in this message"));
  await tick(30);
  assert.equal(row.querySelector("button.prompt-let-once"), null, "its buttons are gone");
  assert.equal(focused(doc), row);
});

test("a refused answer gives the focus back to the button pressed, described by the refusal's words", async () => {
  const change = { id: "pc-000001", sentence: "Your agent tightened your rules", rows: [], createdAt: Date.now(), undone: false, undoable: true };
  const { doc } = load({ url: APPROVALS, homeVm: home({ waiting: [ASK, ASK2] }), routes: {
    "POST egress/approvals/egr-2/approve-once": ADMIN_403,
    "GET policy/changes?limit=21": { changes: [change] },
    "POST policy/changes/pc-000001/undo": { status: 409, body: { error: "cannot undo pc-000001: changed again since (paths /x.pem); nothing was changed" } },
  } });
  await tick();
  const card = cardOf(doc, "approvals-waiting", "egr-2");
  press(button(card, "Allow once"));
  await tick(30);
  const again = button(card, "Allow once");
  assert.equal(again.disabled, false);
  assert.equal(focused(doc), again);
  const words = doc.getElementById(again.getAttribute("aria-describedby"));
  assert.ok(card.contains(words));
  assert.match(words.textContent, /^Sign in first: /);
  const row = cardOf(doc, "approvals-rule-history", "pc-000001");
  press(button(row, "Undo"));
  await tick(30);
  assert.equal(focused(doc), button(row, "Undo"));
  assert.match(doc.getElementById(focused(doc).getAttribute("aria-describedby")).textContent, /changed again since/);
});

test("a poll while the answer is on its way moves nothing; the answer's own draw does", async () => {
  // eslint-disable-next-line prefer-const
  let page: Page;
  page = load({ url: APPROVALS, homeVm: home({ waiting: [ASK, ASK2] }), routes: {
    "POST egress/approvals/egr-1/approve-once": () => (page.setHome(home({ waiting: [ASK2] })), {}),
  } });
  const { doc, window } = page;
  await tick();
  let release = (): void => {};
  const held = new Promise<void>((r) => { release = r; });
  const real = window.fetch;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  window.fetch = (url: string, init: any = {}) => (init.method === "POST" ? held.then(() => real(url, init)) : real(url, init));
  press(button(cardOf(doc, "approvals-waiting", "egr-1"), "Allow once"));
  // The poll draws the list again, the question still waiting.
  page.setHome(home({ waiting: [ASK, ASK2, ASK3] }));
  await poll(doc);
  assert.equal(focused(doc), doc.body, "nothing moves while the answer is on its way");
  release();
  await tick(30);
  assert.equal(focused(doc), doc.querySelector("#approvals-waiting .answer-line"));
});

test("a focus moved elsewhere meanwhile is kept, and a press without the focus in its card moves nothing", async () => {
  const ASK4 = { ...ASK, id: "egr-4" };
  // eslint-disable-next-line prefer-const
  let page: Page;
  page = load({ url: APPROVALS, homeVm: home({ waiting: [ASK, ASK2, ASK3, ASK4] }), routes: {
    "POST egress/approvals/egr-1/approve-once": () => (page.setHome(home({ waiting: [ASK2, ASK3, ASK4] })), {}),
    "POST egress/approvals/egr-2/approve-once": () => (page.setHome(home({ waiting: [ASK3, ASK4] })), {}),
    "POST egress/approvals/egr-3/approve-once": () => (page.setHome(home({ waiting: [ASK4] })), {}),
  } });
  const { doc } = page;
  await tick();
  // Moved out of the list: it stays there.
  press(button(cardOf(doc, "approvals-waiting", "egr-1"), "Allow once"));
  const nav = doc.querySelector("#nav [data-page-link=rules]");
  nav.focus();
  await tick(30);
  assert.equal(focused(doc), nav, "the person moved on");
  // Moved to another card, which the answer's draw then draws again: the
  // answer's place does not take it.
  press(button(cardOf(doc, "approvals-waiting", "egr-2"), "Allow once"));
  button(cardOf(doc, "approvals-waiting", "egr-4"), "Block").focus();
  await tick(30);
  assert.equal(cardOf(doc, "approvals-waiting", "egr-2"), undefined, "answered");
  assert.notEqual(focused(doc), cardOf(doc, "approvals-waiting", "egr-3"), "not the answered card's place");
  assert.notEqual(focused(doc), doc.querySelector("#approvals-waiting .answer-line"), "nor its line");
  // A click made with the focus elsewhere (a mouse in a browser that does
  // not focus a clicked button).
  doc.activeElement.blur();
  button(cardOf(doc, "approvals-waiting", "egr-3"), "Allow once").click();
  await tick(30);
  assert.equal(cardOf(doc, "approvals-waiting", "egr-3"), undefined, "answered");
  assert.equal(focused(doc), doc.body);
});
