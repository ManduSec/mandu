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
 * N1 to N5: the top bar's Approvals link is named for the badge's count,
 * "Approvals, N waiting for your answer", in its aria-label and title, and
 * has neither while nothing waits (§4.25 *The top bar's two marks*).
 *
 * Q1 to Q6: while every question counted is from a session that has ended
 * and no rule change waits (the hero's own rule), the count is the same
 * number in a grey pill (class `ended`) and the link is named "Approvals,
 * 1 question from a session that has ended, no agent is waiting on it";
 * one live question or any rule change keeps the amber and #206's name.
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
  // Answered: the card is gone, its block shown for the line the answer
  // left alone (dashboard.md §4.25 *An answer says what it did*).
  assert.equal(doc.querySelector('#approvals-proposals .proposal'), null, "answered: the card is gone");
  assert.match(doc.querySelector("#approvals-proposals .answer-line").textContent, /^Not now:/);
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

test("Home: the last question answered while a rule change waits: the focus lands on its line, over 'No question is waiting for you.'", async () => {
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
  assert.equal(doc.activeElement, doc.querySelector("#home-waiting .answer-line"), "the answer's line has the focus");
  assert.equal(doc.activeElement.nextElementSibling, line(doc, "home-waiting"));
  assert.equal(line(doc, "home-waiting").textContent, NO_QUESTION);
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
  assert.equal(line(doc, "approvals-waiting").textContent, NOTHING);
  // The line given the focus (the answer gave it to its own line).
  line(doc, "approvals-waiting").setAttribute("tabindex", "-1");
  line(doc, "approvals-waiting").focus();
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

// The Approvals link's name says what its count counts (dashboard.md §4.25
// *The top bar's two marks*, 2026-10-26): the pill alone read "Approvals 2"
// to a screen reader, a bare number. The Rules link's mark already said
// "Rules, 2 changes not saved".
const link = (doc: Doc): Doc => doc.getElementById("nav-approvals-count").parentElement;
const named = (doc: Doc) => [link(doc).getAttribute("aria-label"), link(doc).getAttribute("title")];

test("N1 the Approvals link is named 'Approvals, 1 waiting for your answer' with one waiting, and title says the same", async () => {
  const { doc } = load({ homeVm: quiet(), routes: { [PENDING]: { proposals: [P1] } } });
  await tick(30);
  assert.equal(badge(doc), "1");
  assert.deepEqual(named(doc), ["Approvals, 1 waiting for your answer", "Approvals, 1 waiting for your answer"]);
  assert.match(link(doc).getAttribute("aria-label"), /^Approvals\b/, "the name starts with the link's words (voice control)");
});

test("N2 a question and a rule change: 'Approvals, 2 waiting for your answer'", async () => {
  const { doc } = load({ routes: { [PENDING]: { proposals: [P1] } } });
  await tick(30);
  assert.equal(badge(doc), "2");
  assert.deepEqual(named(doc), ["Approvals, 2 waiting for your answer", "Approvals, 2 waiting for your answer"]);
});

test("N3 nothing waits: no name and no title on the link, the pill hidden; a poll that empties the list takes them off", async () => {
  const quietPage = load({ homeVm: quiet(), routes: { [PENDING]: { proposals: [] } } });
  await tick(30);
  assert.equal(quietPage.doc.getElementById("nav-approvals-count").hidden, true);
  assert.equal(link(quietPage.doc).hasAttribute("aria-label"), false);
  assert.equal(link(quietPage.doc).hasAttribute("title"), false);
  assert.equal(link(quietPage.doc).textContent.trim().startsWith("Approvals"), true);
  let pending: unknown[] = [P1];
  const { doc } = load({ homeVm: quiet(), routes: { [PENDING]: () => ({ proposals: pending }) } });
  await tick(30);
  assert.equal(link(doc).getAttribute("aria-label"), "Approvals, 1 waiting for your answer");
  pending = [];
  await poll(doc);
  assert.equal(doc.getElementById("nav-approvals-count").hidden, true);
  assert.deepEqual(named(doc), [null, null], "both attributes removed");
});

test("N4 the home read failed (count 0): no name on the link, from the start or after a question was named", async () => {
  const { doc } = load({ routes: { "GET home": { status: 500, body: {} }, [PENDING]: { proposals: [] } } });
  await tick(30);
  assert.equal(doc.getElementById("nav-approvals-count").hidden, true);
  assert.deepEqual(named(doc), [null, null]);
  let failing = false;
  const later = load({ routes: { "GET home": () => (failing ? { status: 500, body: {} } : home()), [PENDING]: { proposals: [] } } });
  await tick(30);
  assert.equal(link(later.doc).getAttribute("aria-label"), "Approvals, 1 waiting for your answer");
  failing = true;
  await poll(later.doc);
  assert.equal(later.doc.getElementById("nav-approvals-count").hidden, true);
  assert.deepEqual(named(later.doc), [null, null], "the count is 0: the link reads 'Approvals'");
});

test("N5 a poll with the same count does not touch the link", async () => {
  const { doc } = load({ routes: { [PENDING]: { proposals: [P1] } } });
  await tick(30);
  const writes: string[] = [];
  const el = link(doc);
  const set = el.setAttribute.bind(el);
  const rm = el.removeAttribute.bind(el);
  el.setAttribute = (k: string, v: string) => { writes.push(k); set(k, v); };
  el.removeAttribute = (k: string) => { writes.push(k); rm(k); };
  await poll(doc);
  await poll(doc);
  assert.deepEqual(writes.filter((k) => k === "aria-label" || k === "title"), [], "no write while the count stays 2");
  assert.equal(el.getAttribute("aria-label"), "Approvals, 2 waiting for your answer");
});

// The count in grey while nothing is held up on what it counts (dashboard.md
// §4.25 *The top bar's two marks*, 2026-10-28): every question counted is
// from a session that has ended and no rule change waits, the hero's own
// rule. The amber "1" said something waited on you while the hero right
// under it said no agent did.
const ENDED = { ...ASK, id: "egr-2", askerEnded: true };
const ENDED_2 = { ...ASK, id: "egr-3", askerEnded: true };
const LIVE = { ...ASK, id: "egr-4", askerEnded: false };
const grey = (doc: Doc): boolean => doc.getElementById("nav-approvals-count").classList.contains("ended");
const ENDED_NAME = "Approvals, 1 question from a session that has ended, no agent is waiting on it";

test("Q1 one question from a session that has ended, no rule change: the badge reads '1' in grey, and the link names the ended session", async () => {
  const { doc } = load({ homeVm: home({ waiting: [ENDED] }), routes: { [PENDING]: { proposals: [] } } });
  await tick(30);
  assert.equal(badge(doc), "1", "the same number");
  assert.equal(doc.getElementById("nav-approvals-count").hidden, false);
  assert.equal(grey(doc), true, "the quiet pill");
  assert.deepEqual(named(doc), [ENDED_NAME, ENDED_NAME]);
  assert.match(link(doc).getAttribute("aria-label"), /^Approvals\b/, "the name starts with the link's words (voice control)");
  assert.equal(doc.getElementById("home-waiting-title").textContent, "Approvals waiting (1)", "Home's count is unchanged");
});

test("Q2 two questions, both from ended sessions: '2' in grey, the plural name", async () => {
  const { doc } = load({ homeVm: home({ waiting: [ENDED, ENDED_2] }), routes: { [PENDING]: { proposals: [] } } });
  await tick(30);
  assert.equal(badge(doc), "2");
  assert.equal(grey(doc), true);
  const name = "Approvals, 2 questions from sessions that have ended, no agent is waiting on them";
  assert.deepEqual(named(doc), [name, name]);
});

test("Q3 one ended and one live question: amber, #206's name, counting both", async () => {
  const { doc } = load({ homeVm: home({ waiting: [LIVE, ENDED] }), routes: { [PENDING]: { proposals: [] } } });
  await tick(30);
  assert.equal(badge(doc), "2");
  assert.equal(grey(doc), false, "a live question is held up on you");
  assert.deepEqual(named(doc), ["Approvals, 2 waiting for your answer", "Approvals, 2 waiting for your answer"]);
});

test("Q4 one ended question and a rule change: amber, a rule change holds the rules", async () => {
  const { doc } = load({ homeVm: home({ waiting: [ENDED] }), routes: { [PENDING]: { proposals: [P1] } } });
  await tick(30);
  assert.equal(badge(doc), "2");
  assert.equal(grey(doc), false);
  assert.deepEqual(named(doc), ["Approvals, 2 waiting for your answer", "Approvals, 2 waiting for your answer"]);
});

test("Q5 nothing waits, or the home read failed: hidden, no grey, no name", async () => {
  const quietPage = load({ homeVm: quiet(), routes: { [PENDING]: { proposals: [] } } });
  await tick(30);
  assert.equal(quietPage.doc.getElementById("nav-approvals-count").hidden, true);
  assert.equal(grey(quietPage.doc), false);
  assert.deepEqual(named(quietPage.doc), [null, null]);
  let failing = false;
  const { doc } = load({ routes: { "GET home": () => (failing ? { status: 500, body: {} } : home({ waiting: [ENDED] })), [PENDING]: { proposals: [] } } });
  await tick(30);
  assert.equal(grey(doc), true);
  failing = true;
  await poll(doc);
  assert.equal(doc.getElementById("nav-approvals-count").hidden, true);
  assert.equal(grey(doc), false, "a failed read takes the grey off");
  assert.deepEqual(named(doc), [null, null]);
});

test("Q6 a poll in which the live question's session ends: same count, the pill turns grey and the link is renamed; a rule change brings the amber back", async () => {
  let waiting: unknown[] = [LIVE];
  let pending: unknown[] = [];
  const { doc } = load({ routes: { "GET home": () => home({ waiting }), [PENDING]: () => ({ proposals: pending }) } });
  await tick(30);
  assert.equal(grey(doc), false);
  assert.equal(link(doc).getAttribute("aria-label"), "Approvals, 1 waiting for your answer");
  waiting = [{ ...LIVE, askerEnded: true }];
  await poll(doc);
  assert.equal(badge(doc), "1", "the count did not change");
  assert.equal(grey(doc), true);
  assert.deepEqual(named(doc), [ENDED_NAME, ENDED_NAME], "renamed though the count stayed 1");
  pending = [P1];
  await poll(doc);
  assert.equal(badge(doc), "2");
  assert.equal(grey(doc), false);
  assert.equal(link(doc).getAttribute("aria-label"), "Approvals, 2 waiting for your answer");
});
