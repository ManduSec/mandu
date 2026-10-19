/**
 * home-js-waiting-line.test — a list with no question never says
 * "Nothing is waiting for you." while a rule change your agent asked for
 * waits (public/js/home.js `renderAsks`; dashboard.md §4.25 *An empty list
 * never says nothing waits over a rule change*).
 *
 * The nav badge and Home's "Approvals waiting (N)" count the questions and
 * the rule changes (`renderTopStatus`); the questions list's empty line
 * knew only the questions. Until 2026-10-12 a headless Chromium drew Home
 * as "Approvals waiting (1)", then "Nothing is waiting for you.", then
 * "1 rule change your agent asked for is in Approvals", and Approvals drew
 * a rule change's live Allow / Not now with "Waiting for your answer:
 * Nothing is waiting for you." right under it. Now, while a rule change
 * waits, the line reads "No question is waiting for you.", on Home and on
 * Approvals, and Approvals' line follows a rule change a poll brings or
 * takes away; with nothing waiting it still reads "Nothing is waiting for
 * you.". A focus on the line stays on it when it is drawn with the other
 * words. The agent page's *Needs your OK* (one agent's questions) is
 * unchanged.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); across the real arbiter and dashboard,
 * tests/stack/waiting-line-rule-change.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, ASK, home, load, tick } from "./home-js-fixtures.js";

const APPROVALS = "http://127.0.0.1:4500/mandu/approvals";
const AGENT_URL = "http://127.0.0.1:4500/mandu/agents/s1";
const PENDING = "GET policy/proposals?status=pending";
const NOTHING = "Nothing is waiting for you.";
const NO_QUESTION = "No question is waiting for you.";

const request = (id: string, over: Record<string, unknown> = {}) => ({
  id, status: "pending", requester: "Your agent", createdAt: Date.now() - 60_000,
  rows: [[{ kind: "text", text: "Let " }, { kind: "code", text: "/srv/app/.env" }, { kind: "text", text: " be sent to api.stripe.com" }]],
  wouldLet: [], capped: false, overBroad: false, reason: null, ...over,
});
const P1 = request("pp-000001");
/** Home with no question waiting (the hero's own count says none). */
const quiet = () => home({ waiting: [], verdict: "protected", headline: "Your secrets are guarded." });

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
/** The words of the empty lines of a list. */
const lines = (doc: Doc, list: string) => [...doc.getElementById(list).querySelectorAll(".empty")].map((e: Doc) => e.textContent);
const line = (doc: Doc, list: string): Doc => doc.getElementById(list).querySelector(".empty");
const badge = (doc: Doc): string => doc.getElementById("nav-approvals-count").textContent;
const button = (root: Doc, label: string) => [...root.querySelectorAll("button")].find((b: Doc) => b.textContent === label) as Doc;
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
}
/** Enter on an answer button: the browser drops the focus of the button
 *  the answer turned off to <body> (home-js-answer-focus.test.ts). */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
}

test("Home: a rule change waits and no question does: 'No question is waiting for you.' under 'Approvals waiting (1)', never 'Nothing'", async () => {
  const { doc } = load({ homeVm: quiet(), routes: { [PENDING]: { proposals: [P1] } } });
  await tick(30);
  assert.equal(badge(doc), "1", "the badge counts the rule change");
  assert.equal(doc.getElementById("home-waiting-title").textContent, "Approvals waiting (1)");
  assert.deepEqual(lines(doc, "home-waiting"), [NO_QUESTION]);
  assert.equal(doc.querySelector("#home-waiting .more").textContent, "1 rule change your agent asked for is in Approvals");
  assert.doesNotMatch(doc.getElementById("home-waiting-block").textContent, /Nothing is waiting/);
});

test("Home: a held change to policy.yaml waits: the same line, and the link says it waits for you", async () => {
  const { doc } = load({ homeVm: quiet(), routes: { [PENDING]: { proposals: [request("pp-000002", { onDisk: true, requester: "A change to policy.yaml" })] } } });
  await tick(30);
  assert.deepEqual(lines(doc, "home-waiting"), [NO_QUESTION]);
  assert.equal(doc.querySelector("#home-waiting .more").textContent, "1 rule change waits for you in Approvals");
});

test("nothing waits at all: Home and Approvals still say 'Nothing is waiting for you.', the heading has no count", async () => {
  const onHome = load({ homeVm: quiet(), routes: { [PENDING]: { proposals: [] } } });
  await tick(30);
  assert.equal(onHome.doc.getElementById("home-waiting-title").textContent, "Approvals waiting");
  assert.deepEqual(lines(onHome.doc, "home-waiting"), [NOTHING]);
  const onApprovals = load({ url: APPROVALS, homeVm: quiet(), routes: { [PENDING]: { proposals: [] } } });
  await tick(30);
  assert.deepEqual(lines(onApprovals.doc, "approvals-waiting"), [NOTHING]);
  assert.equal(onApprovals.doc.getElementById("approvals-proposals-block").hidden, true);
});

test("a question waits beside a rule change: its card, and no line on either page", async () => {
  const onHome = load({ routes: { [PENDING]: { proposals: [P1] } } });
  await tick(30);
  assert.equal(onHome.doc.getElementById("home-waiting-title").textContent, "Approvals waiting (2)");
  assert.deepEqual(lines(onHome.doc, "home-waiting"), []);
  assert.ok(onHome.doc.querySelector('#home-waiting .ask[data-id="egr-1"]'), "the question's card");
  const onApprovals = load({ url: APPROVALS, routes: { [PENDING]: { proposals: [P1] } } });
  await tick(30);
  assert.deepEqual(lines(onApprovals.doc, "approvals-waiting"), []);
  assert.ok(onApprovals.doc.querySelector('#approvals-waiting .ask[data-id="egr-1"]'));
});

test("Approvals: under a rule change's card, 'Waiting for your answer' says no question waits; once it is answered, nothing does", async () => {
  let pending = [P1];
  const { doc } = load({ url: APPROVALS, homeVm: quiet(), routes: {
    [PENDING]: () => ({ proposals: pending }),
    "POST policy/proposals/pp-000001": () => { pending = []; return { proposal: { id: P1.id, status: "denied" } }; },
  } });
  await tick(30);
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, false, "the rule change's card is drawn");
  assert.deepEqual(lines(doc, "approvals-waiting"), [NO_QUESTION]);
  button(doc.querySelector('#approvals-proposals .proposal[data-id="pp-000001"]'), "Not now").click();
  await tick(30);
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, true, "answered: the card is gone");
  assert.equal(badge(doc), "0");
  assert.deepEqual(lines(doc, "approvals-waiting"), [NOTHING]);
});

test("Approvals: a poll that brings a rule change, or takes it away, draws the line again", async () => {
  let pending: unknown[] = [];
  const { doc } = load({ url: APPROVALS, homeVm: quiet(), routes: { [PENDING]: () => ({ proposals: pending }) } });
  await tick(30);
  assert.deepEqual(lines(doc, "approvals-waiting"), [NOTHING]);
  // The agent asks for a rule change: the next poll reads it.
  pending = [P1];
  await poll(doc);
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, false);
  assert.deepEqual(lines(doc, "approvals-waiting"), [NO_QUESTION], "never 'Nothing' under the card");
  // Answered in another tab: the next poll reads none.
  pending = [];
  await poll(doc);
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, true);
  assert.deepEqual(lines(doc, "approvals-waiting"), [NOTHING]);
  // Home follows the same reads.
  pending = [P1];
  doc.querySelector('#nav [data-page-link="home"]').click();
  await poll(doc);
  assert.deepEqual(lines(doc, "home-waiting"), [NO_QUESTION]);
});

test("Approvals: a rule change that comes while a question waits leaves the questions as drawn", async () => {
  let pending: unknown[] = [];
  const { doc } = load({ url: APPROVALS, routes: { [PENDING]: () => ({ proposals: pending }) } });
  await tick(30);
  const card = () => doc.querySelector('#approvals-waiting .ask[data-id="egr-1"]');
  const old = card();
  assert.ok(old, "the question's card");
  pending = [P1];
  await poll(doc);
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, false, "the rule change is drawn");
  assert.equal(card(), old, "the question's card is not drawn again: no line to change");
});

test("Home: the last question answered while a rule change waits: the focus lands on 'No question is waiting for you.'", async () => {
  // eslint-disable-next-line prefer-const
  let page: ReturnType<typeof load>;
  page = load({ homeVm: home({ waiting: [ASK] }), routes: {
    [PENDING]: { proposals: [P1] },
    "POST egress/approvals/egr-1/deny": () => (page.setHome(quiet()), {}),
  } });
  const { doc } = page;
  await tick(30);
  press(button(doc.querySelector('#home-waiting .ask[data-id="egr-1"]'), "Block"));
  await tick(30);
  assert.equal(doc.activeElement, line(doc, "home-waiting"), "the list's line has the focus");
  assert.equal(doc.activeElement.textContent, NO_QUESTION);
  assert.equal(doc.getElementById("home-waiting-title").textContent, "Approvals waiting (1)", "the heading still counts the rule change");
});

test("a focus on the line stays on it when a poll draws it with the other words", async () => {
  // eslint-disable-next-line prefer-const
  let page: ReturnType<typeof load>;
  let pending: unknown[] = [];
  page = load({ url: APPROVALS, homeVm: home({ waiting: [ASK] }), routes: {
    [PENDING]: () => ({ proposals: pending }),
    "POST egress/approvals/egr-1/approve-once": () => (page.setHome(quiet()), {}),
  } });
  const { doc } = page;
  await tick(30);
  press(button(doc.querySelector('#approvals-waiting .ask[data-id="egr-1"]'), "Allow once"));
  await tick(30);
  assert.equal(doc.activeElement.textContent, NOTHING, "the last answer lands on the line");
  pending = [P1];
  await poll(doc);
  assert.equal(doc.activeElement, line(doc, "approvals-waiting"), "the line drawn again keeps the focus");
  assert.equal(doc.activeElement.textContent, NO_QUESTION);
  pending = [];
  await poll(doc);
  assert.equal(doc.activeElement, line(doc, "approvals-waiting"));
  assert.equal(doc.activeElement.textContent, NOTHING);
});

test("the agent page's Needs your OK is one agent's questions: unchanged by a rule change waiting", async () => {
  let vm: unknown = { ...AGENT, waiting: [] };
  const { doc } = load({ url: AGENT_URL, homeVm: quiet(), routes: {
    [PENDING]: { proposals: [P1] },
    "GET home/agent?session=s1": () => vm,
  } });
  await tick(40);
  assert.equal(badge(doc), "1", "the rule change was read");
  assert.deepEqual(lines(doc, "agent-waiting"), [NOTHING]);
  // The agent did more: the page is drawn again with the rule change read.
  vm = { ...AGENT, waiting: [], blocked: 2 };
  await poll(doc);
  assert.deepEqual(lines(doc, "agent-waiting"), [NOTHING]);
});
