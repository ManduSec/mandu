/**
 * home-js-agent-phone-short.test — dashboard.md §4.25 *A waiting question is
 * short on a phone*, on a session page (Shoemaker #300). #251 made every
 * waiting card of Approvals short at the page's phone breakpoint; a session
 * page's Needs your OK still drew the full card, its Allow once some 840 px
 * under its top. Now, at `max-width: 760px`:
 *
 *   P1  a send is the short card: its line, the four answers under it, What
 *       each answer does in place of Details in Approvals; a held message
 *       stays full;
 *   P2  What each answer does opens the three cells in place and reads
 *       Hide; a poll with the same page keeps it open and the focus on
 *       Allow once;
 *   P3  wide, or with no matchMedia, every card is full as before;
 *   P4  a flip of the query draws Needs your OK again in the other form
 *       without a poll (the story is not drawn again), a poll after it
 *       leaves it as drawn, and flipping back keeps the opened card open and
 *       the focus on its button;
 *   P5  `?go=waiting` lands on the first card, short; the question a See
 *       what the agent was doing link opened the page for (`?ask=`) stays
 *       full.
 *
 * jsdom has no matchMedia: `phone` stubs one the test can flip.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, ASK, home, load, tick } from "./home-js-fixtures.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const URL1 = "http://127.0.0.1:4500/mandu/agents/s1";

/** A stubbed `(max-width: 760px)` query: `flip(matches)` fires its change. */
function phone(matches: boolean) {
  const q: El = { media: "(max-width: 760px)", matches, listeners: [] as Array<(e: unknown) => void> };
  q.addEventListener = (type: string, fn: (e: unknown) => void) => { if (type === "change") q.listeners.push(fn); };
  q.removeEventListener = () => {};
  const asked: string[] = [];
  return {
    asked,
    before: (w: El) => { w.matchMedia = (m: string) => { asked.push(m); return q; }; },
    flip: (to: boolean) => { q.matches = to; for (const fn of q.listeners) fn({ matches: to, media: q.media }); },
  };
}

const ANSWERS_SHORT = "Allow once and Send without it cover the next request; Always allow and Block are kept under Rules.";
const STANDING = "Mandu remembers it for STRIPE_KEY and api.stripe.com only.";
const FOUR = [
  { approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Always allow" },
  { approve: false, label: "Send without it", scope: "once", strip: true }, { approve: false, label: "Block" },
];
const SEND_1 = {
  ...ASK, id: "send-1",
  answersShortParts: [{ kind: "text", text: ANSWERS_SHORT }], answersShort: ANSWERS_SHORT,
  ifStandingParts: [{ kind: "text", text: STANDING }], ifStanding: STANDING, actions: FOUR,
};
const SEND_2 = { ...SEND_1, id: "send-2" };
const HELD = {
  ...ASK, id: "prompt-1", family: "prompt",
  sentence: [{ kind: "text", text: "Claude Code wants to send your message to the AI." }],
  actions: [{ approve: true, scope: "once", prompt: "send", label: "Send as written" }],
};
const PAGE = { ...AGENT, waiting: [SEND_1, SEND_2, HELD] };
// Home's list holds every waiting question, this session's too: Approvals
// forgets an opened card only once it leaves that list.
const HOME = () => home({ waiting: [SEND_1, SEND_2, HELD] });
const ROUTES = { "GET home/agent?session=s1": PAGE, "GET prompt-filters/holds": { holds: [] } };

const card = (doc: El, id: string) => [...doc.querySelectorAll("#agent-waiting .ask")].find((c: El) => c.dataset.id === id) as El;
const buttons = (c: El) => [...c.querySelectorAll(".ask-actions button")].map((b: El) => b.textContent);
const allowOnce = (doc: El, id: string) => [...card(doc, id).querySelectorAll(".ask-actions button")].find((b: El) => b.textContent === "Allow once") as El;
async function poll(doc: El): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

function assertShort(c: El, id: string) {
  assert.ok(c, `${id}: drawn`);
  assert.ok(!c.classList.contains("expanded"), `${id}: short`);
  assert.equal(c.querySelector(".ask-detail, .ask-without, .ask-standing"), null, `${id}: no cells nor notes`);
  assert.equal(c.querySelector(".ask-details"), null, `${id}: What each answer does, not Details in Approvals`);
  const more = c.querySelector(".ask-sub .ask-more");
  assert.equal(more.textContent, "What each answer does", id);
  assert.equal(more.getAttribute("aria-expanded"), "false", id);
  assert.equal(c.querySelector(".ask-answers").textContent, ANSWERS_SHORT, `${id}: which answers last stays in sight`);
  assert.ok(c.querySelector(".ask-top > .ask-actions"), `${id}: the answers right under its line`);
  assert.deepEqual(buttons(c), ["Allow once", "Always allow", "Send without it", "Block"], id);
}
function assertFull(c: El, id: string) {
  assert.ok(c.classList.contains("expanded"), `${id}: full`);
  assert.equal(c.querySelector(".ask-more"), null, id);
  assert.ok(c.querySelector(".ask-detail"), id);
}

test("P1: on a phone, a session page's sends are short cards with their four answers under the line; a held message stays full", async () => {
  const media = phone(true);
  const { doc } = load({ url: URL1, homeVm: HOME(), routes: ROUTES, before: media.before });
  await tick(40);
  assert.ok(media.asked.includes("(max-width: 760px)"), "the page's phone breakpoint");
  assert.deepEqual([...doc.querySelectorAll("#agent-waiting .ask")].map((c: El) => c.dataset.id), ["send-1", "send-2", "prompt-1"], "the page's own order");
  assert.equal(doc.querySelector("#agent-waiting .ask-group-head"), null, "no heading of ended sessions");
  for (const id of ["send-1", "send-2"]) assertShort(card(doc, id), id);
  assertFull(card(doc, "prompt-1"), "prompt-1");
  assert.ok(buttons(card(doc, "prompt-1")).includes("Send as written for this session"), "a held message's answers, all of them");
});

test("P2: What each answer does opens the three cells in place; a poll with the same page keeps it open and the focus on Allow once", async () => {
  const media = phone(true);
  const { doc } = load({ url: URL1, homeVm: HOME(), routes: ROUTES, before: media.before });
  await tick(40);
  card(doc, "send-1").querySelector(".ask-more").click();
  const open = card(doc, "send-1");
  assert.equal(open.querySelector(".ask-more").textContent, "Hide");
  assert.equal(open.querySelector(".ask-more").getAttribute("aria-expanded"), "true");
  assert.deepEqual([...open.querySelectorAll(".ask-detail .k")].map((k: El) => k.firstChild.textContent), ["Why it stopped", "What the AI has now", "If you click Allow once or Always allow"]);
  assert.equal(open.querySelector(".ask-standing").textContent, "If you click Always allow or Block: " + STANDING);
  assert.equal(card(doc, "send-2").querySelector(".ask-detail"), null, "only the card pressed opens");
  allowOnce(doc, "send-1").focus();
  await poll(doc);
  const after = card(doc, "send-1");
  assert.equal(after.querySelectorAll(".ask-detail .k").length, 3, "still open after a poll");
  assert.equal(after.querySelector(".ask-more").textContent, "Hide");
  assert.equal(doc.activeElement, allowOnce(doc, "send-1"), "the focus stays on Allow once");
});

test("P3: wide, or with no matchMedia, every card of Needs your OK is full as before", async () => {
  for (const before of [phone(false).before, undefined]) {
    const { doc } = load({ url: URL1, homeVm: HOME(), routes: ROUTES, before });
    await tick(40);
    for (const id of ["send-1", "send-2", "prompt-1"]) assertFull(card(doc, id), `${id} (${before ? "wide" : "no matchMedia"})`);
    assert.equal(card(doc, "send-1").querySelectorAll(".ask-detail .k").length, 3);
  }
});

test("P4: a flip of the query draws Needs your OK again in the other form without a poll; a poll then leaves it; back on a phone the opened card is still open and the focus kept", async () => {
  const media = phone(true);
  const { doc, calls } = load({ url: URL1, homeVm: HOME(), routes: ROUTES, before: media.before });
  await tick(40);
  card(doc, "send-1").querySelector(".ask-more").click();
  allowOnce(doc, "send-2").focus();
  const before = card(doc, "send-2");
  const turn = doc.querySelector("#agent-story article.turn");
  const reads = calls.filter((c: El) => c.url.includes("home/agent")).length;
  media.flip(false);
  assert.notEqual(card(doc, "send-2"), before, "drawn again at once");
  assert.equal(calls.filter((c: El) => c.url.includes("home/agent")).length, reads, "without a read");
  assert.equal(doc.querySelector("#agent-story article.turn"), turn, "the story is not drawn again");
  for (const id of ["send-1", "send-2"]) assertFull(card(doc, id), `${id} when wide`);
  assert.equal(doc.activeElement, allowOnce(doc, "send-2"), "the focus stays on Allow once");
  // A poll that brings the same leaves it as drawn: it does not flip back.
  const wide = card(doc, "send-2");
  await poll(doc);
  assert.ok(calls.filter((c: El) => c.url.includes("home/agent")).length > reads, "the poll read the page");
  assert.equal(card(doc, "send-2"), wide, "a poll does not draw it again");
  assert.ok(card(doc, "send-2").classList.contains("expanded"), "still full");
  // Back to a phone: short again, the card opened before still open.
  media.flip(true);
  assertShort(card(doc, "send-2"), "send-2");
  const open = card(doc, "send-1");
  assert.equal(open.querySelectorAll(".ask-detail .k").length, 3, "the opened card is still open");
  assert.equal(open.querySelector(".ask-more").textContent, "Hide");
  assert.equal(doc.activeElement, allowOnce(doc, "send-2"), "the focus is on Allow once again");
});

test("P4b: a flip on a session page that was not found draws no card back", async () => {
  const media = phone(true);
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", homeVm: HOME(), routes: { "GET home/agent?session=s1": { found: false } }, before: media.before });
  await tick(40);
  media.flip(false);
  assert.ok(doc.getElementById("agent-waiting-block").hidden, "Needs your OK stays hidden");
  assert.equal(doc.querySelector("#agent-waiting .ask"), null, "no card from an earlier visit");
});

test("P5: ?go=waiting lands on the first card, short with Allow once beside it; the question ?ask= opened the page for stays full", async () => {
  const media = phone(true);
  const landed = load({ url: URL1 + "?go=waiting", homeVm: HOME(), routes: ROUTES, before: media.before });
  await tick(40);
  const a = landed.doc.activeElement;
  assert.ok(a.classList.contains("ask"), `a card has the focus: ${a.className}`);
  assert.equal(a.dataset.id, "send-1", "the first card");
  assertShort(a, "send-1");

  const asked = load({ url: URL1 + "?ask=send-2", homeVm: HOME(), before: phone(true).before,
    routes: { "GET home/agent?session=s1&ask=send-2": PAGE, "GET prompt-filters/holds": { holds: [] } } });
  await tick(40);
  assertFull(card(asked.doc, "send-2"), "send-2, the question the page was opened for");
  assertShort(card(asked.doc, "send-1"), "send-1");
});
