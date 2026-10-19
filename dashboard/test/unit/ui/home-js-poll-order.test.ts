/**
 * home-js-poll-order.test — a Home poll's answer that comes after a newer
 * poll's is dropped (public/js/home.js `loadHome`; dashboard.md §4.25 *An
 * older poll's answer never draws over a newer one*).
 *
 * Home polls overlap: the read when the page opens, the 10 s poll, a return
 * to the tab, the read after an answer. Until 2026-10-12 whichever answered
 * LAST drew the page, even when it was asked first, so on a slow network:
 *
 *   - the read the page opened with, answered from before the protection
 *     service stopped, drew "Your secrets are guarded." over a newer poll
 *     that knew it had stopped (master pipeline 10542, where Settings ›
 *     Prompt filters then said "did not answer");
 *   - a poll that failed drew "Not connected." over a newer one that
 *     answered;
 *   - a poll asked before you answered a question drew it as waiting again,
 *     with live buttons, until the next poll.
 *
 * Now an answer to a poll asked before the latest one the page took is
 * dropped; answers that come in the order they were asked are each taken.
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts),
 * a route that holds an answer until the test sends it; across the real
 * arbiter and dashboard, tests/stack/home-poll-order.test.ts. Axes: none
 * (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ASK, home, load, tick } from "./home-js-fixtures.js";

const ASK2 = { ...ASK, id: "egr-2" };
const DOWN = { status: 503, body: { error: "the arbiter is not reachable", tenant: "live", unreachable: true } };
const DOWN_HERO = "The protection service is not running, so nothing can be checked. Start it under Settings, or refresh in a moment.";
const NOT_REACHABLE = "Saved as on. The protection service is not reachable, so Mandu cannot say what is on now.";

/** An answer held until the test sends it: `send` answers it, `fail` gives
 *  no answer at all (the page's fetch fails, as with the dashboard gone). */
function held() {
  let send!: (v: unknown) => void;
  let fail!: (e: unknown) => void;
  const answer = new Promise<unknown>((a, b) => { send = a; fail = b; });
  return { answer, send, fail };
}
/** `GET home` answers in turn: each entry is the answer to one poll, the
 *  first to the read when the page opens. */
const inTurn = (answers: unknown[]) => () => (answers.length > 1 ? answers.shift() : answers[0]);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, id: string): string => doc.getElementById(id).textContent;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const cardOf = (doc: any, id: string) => [...doc.getElementById("home-waiting").children].find((c: any) => c.dataset.id === id) as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const button = (root: any, label: string) => [...root.querySelectorAll("button")].find((b: any) => b.textContent === label) as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function poll(doc: any): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
}

test("the read the page opened with, answered from before the service stopped, never draws over the poll that found it stopped", async () => {
  const opened = held();
  const { doc } = load({ routes: { "GET home": inTurn([opened.answer, DOWN]) } });
  await tick();
  assert.equal(text(doc, "hero-headline"), "Checking…", "the first read is on its way");
  await poll(doc);
  assert.equal(text(doc, "hero-headline"), "Not connected.");
  assert.equal(text(doc, "hero-sentence"), DOWN_HERO);
  // The first read answers now, with what it read before the stop.
  opened.send(home());
  await tick(30);
  assert.equal(text(doc, "hero-headline"), "Not connected.", "the older answer is dropped");
  assert.equal(text(doc, "hero-sentence"), DOWN_HERO);
  assert.equal(text(doc, "top-status"), "Not connected");
  assert.equal(text(doc, "nav-approvals-count"), "0");
  assert.equal(doc.querySelector("#home-waiting button"), null, "no answer button for a question it cannot check");
  assert.match(text(doc, "home-waiting"), /^Could not check for waiting questions\. The protection service is not running\./);
  // Settings › Protection reads what runs from the answer the page took.
  doc.querySelector('#nav [data-page-link="settings"]').click();
  await tick(30);
  assert.equal(text(doc, "settings-protect-text"), NOT_REACHABLE, "never what the older answer said runs");
  // The next poll still draws: the page did not stop taking answers.
  await poll(doc);
  assert.equal(text(doc, "hero-headline"), "Not connected.");
});

test("a poll that failed never draws \"Not connected.\" over a newer poll that answered", async () => {
  const lost = held();
  const { doc } = load({ routes: { "GET home": inTurn([home(), lost.answer, home({ headline: "Two questions are waiting for you.", waiting: [ASK, ASK2] })]) } });
  await tick();
  assert.equal(text(doc, "hero-headline"), "One question is waiting for you.");
  await poll(doc); // held
  await poll(doc); // answers
  assert.equal(text(doc, "hero-headline"), "Two questions are waiting for you.");
  lost.fail(new TypeError("Failed to fetch"));
  await tick(30);
  assert.equal(text(doc, "hero-headline"), "Two questions are waiting for you.", "the older failure is dropped");
  assert.equal(text(doc, "top-status"), "Protection on");
  assert.ok(cardOf(doc, "egr-2"), "the newer answer's questions stay");
});

test("a question answered on Home is never drawn as waiting again by a poll asked before the answer", async () => {
  const before = held();
  const { doc } = load({ homeVm: home({ waiting: [ASK, ASK2] }), routes: {
    "GET home": inTurn([home({ waiting: [ASK, ASK2] }), before.answer, home({ headline: "One question is waiting for you.", waiting: [ASK2] })]),
    "POST egress/approvals/egr-1/deny": {},
  } });
  await tick();
  assert.ok(cardOf(doc, "egr-1") && cardOf(doc, "egr-2"));
  await poll(doc); // asked before the answer, held
  button(cardOf(doc, "egr-1"), "Block").focus();
  button(cardOf(doc, "egr-1"), "Block").click();
  await tick(30);
  assert.equal(cardOf(doc, "egr-1"), undefined, "answered: its card is gone");
  assert.equal(doc.activeElement, cardOf(doc, "egr-2"), "the next question has the focus");
  // The poll asked before the answer comes now, with the question waiting.
  before.send(home({ waiting: [ASK, ASK2] }));
  await tick(30);
  assert.equal(cardOf(doc, "egr-1"), undefined, "never drawn as waiting again");
  assert.equal(doc.querySelectorAll("#home-waiting button").length, cardOf(doc, "egr-2").querySelectorAll("button").length, "only the other question's buttons");
  assert.equal(text(doc, "nav-approvals-count"), "1");
  assert.equal(doc.activeElement, cardOf(doc, "egr-2"), "the focus stays");
});

test("answers that come in the order they were asked are each taken, a failure too", async () => {
  const a = held();
  const b = held();
  const e = held();
  const c = held();
  const d = held();
  const { doc } = load({ routes: { "GET home": inTurn([home(), a.answer, b.answer, e.answer, c.answer, d.answer]) } });
  await tick();
  await poll(doc);
  await poll(doc);
  await poll(doc);
  a.send(home({ headline: "Poll A answered." }));
  await tick(30);
  assert.equal(text(doc, "hero-headline"), "Poll A answered.", "the oldest answer, first in, is drawn");
  b.send(home({ headline: "Poll B answered." }));
  await tick(30);
  assert.equal(text(doc, "hero-headline"), "Poll B answered.", "then the next, though a newer read is still out");
  e.send(home({ headline: "Poll E answered." }));
  await tick(30);
  assert.equal(text(doc, "hero-headline"), "Poll E answered.", "then the newest");
  // The same with a failure first: it is said while the newer read is out.
  await poll(doc);
  await poll(doc);
  c.fail(new TypeError("Failed to fetch"));
  await tick(30);
  assert.equal(text(doc, "hero-headline"), "Not connected.", "the older failure, first in, is drawn");
  assert.equal(text(doc, "hero-sentence"), "The dashboard could not reach its own server. Refresh in a moment.");
  d.send(home({ headline: "Poll D answered." }));
  await tick(30);
  assert.equal(text(doc, "hero-headline"), "Poll D answered.", "then the newer answer");
});
