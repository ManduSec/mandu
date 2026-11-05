/**
 * home-js-answer-line.test — an answer says what it did (dashboard.md §4.25
 * *An answer says what it did*).
 *
 * Until 2026-10-22 an answered card just went: Home redrew as "Nothing is
 * waiting for you.", and the card's "After you answer, tell the agent to try
 * again" (only on the full Approvals card) was never read by a person who
 * answered from Home. Now, after an answer that worked, the list the card
 * was in (Home's Approvals waiting, Approvals' Waiting for your answer, the
 * session page's Needs your OK) shows one line where the card was:
 *
 *   L1  what you chose and about what, in the ask's own words (`whatParts`,
 *       names as code), the ask's `afterAllow` ("Tell Claude Code to try
 *       again.", "The program goes on now."), and Change your answer to
 *       `/approvals/<id>`; a live status;
 *   L2  each answer's words: Always allowed, Allowed for this session,
 *       Allowed without the secret, Blocked (a send: "Nothing was sent."),
 *       an agent that ended, a held message's answers; an answer its row
 *       on Approvals cannot change (Send without it, a held message, a
 *       HIGH session's ask: `reversible` false) says why and ends with
 *       See your answer, not Change your answer (2026-10-28);
 *   L3  a refusal keeps its words on the card and leaves no line;
 *   L4  a poll keeps the line in its place, whether it draws the list again
 *       or not; the next answer there replaces it; leaving the page drops it;
 *   L5  the line takes the focus the answer's place gave (never a button);
 *       a focus the person moved stays where it is;
 *   L6  the session page keeps Needs your OK shown under its line;
 *   L7  Change your answer opens Approvals at the answered row;
 *   L8  the line's link can be swapped: the last Always of a program's
 *       send links its rule change (Undo it in Approvals, `/approvals/<pc-…>`).
 *   L9  on Approvals the line stays in its card's group, above or under
 *       *From sessions that have ended* (§4.25 *A question from a session
 *       that has ended*).
 *   L10 a rule change is a line place too: Allow or Not now on Approvals
 *       leaves its line in Rule changes your agent asked for, which stays
 *       shown under it, with the focus; Undo it opens the change made
 *       (home-js-proposals.test.ts has its words).
 *   L11 an Always on a file of a send that is not the last leaves no line:
 *       its card's words end with Undo it in Approvals, which a poll that
 *       draws the card again puts back, and which opens that change.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts); over the real arbiter and dashboard,
 * tests/stack/dashboard-answer-line.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, ASK, home, load, tick } from "./home-js-fixtures.js";

const APPROVALS = "http://127.0.0.1:4500/mandu/approvals";
const T = (text: string) => ({ kind: "text", text });
const C = (text: string) => ({ kind: "code", text });
/** A send of a named secret, as the server words it (ask-words.ts). */
const SEND = {
  ...ASK, id: "egr-1", family: "send",
  sentence: [T("Claude Code wants to send your secret "), C("STRIPE_KEY"), T(" to "), C("api.stripe.com")],
  whatParts: [T("send your secret "), C("STRIPE_KEY"), T(" to "), C("api.stripe.com")],
  afterAllow: "Tell Claude Code to try again.",
  actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Always allow" }, { approve: false, label: "Send without it", scope: "once", strip: true }, { approve: false, label: "Block" }],
};
const SEND2 = { ...SEND, id: "egr-2", whatParts: [T("send your secret "), C("GITHUB_TOKEN"), T(" to "), C("api.github.com")] };
const LINE = "Allowed once: send your secret STRIPE_KEY to api.stripe.com. Tell Claude Code to try again. Change your answer";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const button = (root: Doc, label: string): Doc => [...root.querySelectorAll("button")].find((b: Doc) => b.textContent === label);
const cardOf = (doc: Doc, list: string, id: string): Doc => [...doc.getElementById(list).children].find((c: Doc) => c.dataset.id === id);
const lineIn = (doc: Doc, list: string): Doc => doc.querySelector(`#${list} .answer-line`);
const words = (x: Doc): string => String(x.textContent).replace(/\s+/g, " ").trim();
/** Enter on a button: the browser drops the focus of the button the answer
 *  turns off to <body> (home-js-answer-focus.test.ts `press`). */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
}
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
}
/** Home with `waiting`, its answer `verb` (a route's last part) taking the
 *  card away. */
function answered(waiting: unknown[], id: string, verb: string, left: unknown[] = [], url?: string) {
  // eslint-disable-next-line prefer-const
  let page: ReturnType<typeof load>;
  page = load({ ...(url ? { url } : {}), homeVm: home({ waiting }), routes: {
    [`POST egress/approvals/${id}/${verb}`]: () => (page.setHome(home({ waiting: left })), {}),
    "GET prompt-filters/holds": { holds: [] },
    "POST prompt-filters/holds/answer": () => (page.setHome(home({ waiting: left })), {}),
  } });
  return page;
}

test("L1: Allow once on Home leaves a line where the card was: what was allowed, to tell the agent to try again, and Change your answer", async () => {
  const { doc } = answered([SEND, SEND2], "egr-1", "approve-once", [SEND2]);
  await tick();
  press(button(cardOf(doc, "home-waiting", "egr-1"), "Allow once"));
  await tick(30);
  assert.equal(cardOf(doc, "home-waiting", "egr-1"), undefined, "the card went");
  const line = lineIn(doc, "home-waiting");
  assert.equal(words(line), LINE);
  assert.equal(line.getAttribute("role"), "status", "read out as a status");
  assert.equal(doc.getElementById("home-waiting").firstElementChild, line, "where the card was, above the next one");
  assert.deepEqual([...line.querySelectorAll("code")].map((c: Doc) => c.textContent), ["STRIPE_KEY", "api.stripe.com"], "the names as code, as on the card");
  assert.equal(line.querySelector("strong").textContent, "Allowed once:");
  const link = line.querySelector("a");
  assert.equal(link.textContent, "Change your answer");
  assert.equal(link.getAttribute("href"), "/mandu/approvals/egr-1");
  assert.equal(link.dataset.ask, "egr-1");
  assert.equal(doc.activeElement, line, "the line has the focus");
});

test("L2: each answer says what it did", async () => {
  const PROGRAM = { ...SEND, id: "egr-7", family: "read", whatParts: [T("Claude Code's program "), C("/usr/bin/cat"), T(" wants to read a secret file: "), C(".env")], afterAllow: "The program goes on now.", actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Always allow" }, { approve: false, label: "Block" }] };
  const HOLDER = { ...SEND, id: "egr-8", whatParts: [T("Claude Code's program wants to send data from "), C("~/ws/.env"), T(" to "), C("hooks.slack.com")], actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Allow this session" }, { approve: false, label: "Block" }] };
  const RUN = { ...SEND, id: "egr-9", family: "run", whatParts: [T("run a command with network access: "), C("npm install")], actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: false, label: "Block" }] };
  const ENDED = { ...SEND, askerEnded: true };
  const OLD = { ...SEND, whatParts: undefined, afterAllow: undefined };
  const cases: Array<[unknown, string, string, string]> = [
    [SEND, "approve", "Always allow", "Always allowed: send your secret STRIPE_KEY to api.stripe.com. Tell Claude Code to try again. Change your answer"],
    // Send without it answers one request: nothing on its row to change.
    [SEND, "send-without", "Send without it", "Allowed without the secret: send your secret STRIPE_KEY to api.stripe.com. Tell Claude Code to try again. It applied to that request only. See your answer"],
    [SEND, "deny", "Block", "Blocked: send your secret STRIPE_KEY to api.stripe.com. Nothing was sent. Change your answer"],
    [PROGRAM, "approve-once", "Allow once", "Allowed once: Claude Code's program /usr/bin/cat wants to read a secret file: .env. The program goes on now. Change your answer"],
    [PROGRAM, "deny", "Block", "Blocked: Claude Code's program /usr/bin/cat wants to read a secret file: .env. Change your answer"],
    [HOLDER, "approve", "Allow this session", "Allowed for this session: Claude Code's program wants to send data from ~/ws/.env to hooks.slack.com. Tell Claude Code to try again. Change your answer"],
    [RUN, "deny", "Block", "Blocked: run a command with network access: npm install. Change your answer"],
    [ENDED, "approve-once", "Allow once", "Allowed once: send your secret STRIPE_KEY to api.stripe.com. Your answer counts the next time an agent asks. Change your answer"],
    // An older server: the sentence as the card drew it, nothing more.
    [OLD, "approve-once", "Allow once", "Allowed once: Claude Code wants to send your secret STRIPE_KEY to api.stripe.com. Change your answer"],
  ];
  for (const [ask, verb, label, said] of cases) {
    const id = (ask as { id: string }).id;
    const { doc } = answered([ask], id, verb);
    await tick();
    press(button(cardOf(doc, "home-waiting", id), label));
    await tick(30);
    assert.equal(words(lineIn(doc, "home-waiting")), said, label);
    assert.equal(doc.activeElement, lineIn(doc, "home-waiting"), `${label}: the line has the focus`);
  }
  // A held message: what went to the AI, and nothing to tell the agent.
  // Its row on Approvals offers no change (the server marks it `reversible`
  // false): why, and See your answer.
  const PROMPT = { ...SEND, id: "egr-5", family: "prompt", sentence: [T("Claude Code wants to send your message to the AI. It holds "), C("acme.codename"), T(".")], afterAllow: undefined, reversible: false };
  for (const [label, said] of [
    ["Send as written", "Sent as written: the AI reads your message as you wrote it. It applied to that message only. See your answer"],
    ["Send masked", "Sent masked: the AI reads your message with that part masked. It applied to that message only. See your answer"],
    ["Cancel the message", "Cancelled: the AI does not read your message. It applied to that message only. See your answer"],
  ] as const) {
    const { doc } = answered([PROMPT], "egr-5", "-");
    await tick();
    press(button(cardOf(doc, "home-waiting", "egr-5"), label));
    await tick(30);
    assert.equal(words(lineIn(doc, "home-waiting")), said, label);
  }
  // Approvals' session answer of a held message: the row the link opens is
  // the message's, with no change; the session's own row flips it.
  const { doc } = answered([PROMPT], "egr-5", "-", [], APPROVALS);
  await tick();
  press(button(cardOf(doc, "approvals-waiting", "egr-5"), "Send as written for this session"));
  await tick(30);
  assert.equal(words(lineIn(doc, "approvals-waiting")), "Sent as written for this session: the AI reads your message as you wrote it. To change it, use the row for the session in Answered earlier. See your answer");
  assert.equal(lineIn(doc, "approvals-waiting").querySelector("a").getAttribute("href"), "/mandu/approvals/egr-5", "the same target");
  // A HIGH session's ask: its answer is kept in Rules.
  const HIGH = { ...SEND, id: "egr-6", family: "send", whatParts: [T("connect to "), C("example.com")], afterAllow: "Tell Claude Code to try again.", reversible: false, actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: false, label: "Block" }] };
  for (const [verb, label, said] of [
    ["approve-once", "Allow once", "Allowed once: connect to example.com. Tell Claude Code to try again. To change it, remove it in Rules. See your answer"],
    ["deny", "Block", "Blocked: connect to example.com. Nothing was sent. To change it, remove it in Rules. See your answer"],
  ] as const) {
    const { doc } = answered([HIGH], "egr-6", verb);
    await tick();
    press(button(cardOf(doc, "home-waiting", "egr-6"), label));
    await tick(30);
    assert.equal(words(lineIn(doc, "home-waiting")), said, label);
    assert.equal(lineIn(doc, "home-waiting").querySelector("a").getAttribute("href"), "/mandu/approvals/egr-6", `${label}: the marked row`);
  }
});

test("L3: a refused answer keeps its words on the card and leaves no line", async () => {
  const { doc } = load({ homeVm: home({ waiting: [SEND] }), routes: {
    "POST egress/approvals/egr-1/approve-once": { status: 403, body: { error: "admin session required" } },
  } });
  await tick();
  press(button(cardOf(doc, "home-waiting", "egr-1"), "Allow once"));
  await tick(30);
  assert.ok(cardOf(doc, "home-waiting", "egr-1"), "the card stays");
  assert.ok(cardOf(doc, "home-waiting", "egr-1").querySelector(".ask-error"), "with the refusal's words");
  assert.equal(lineIn(doc, "home-waiting"), null, "no line");
});

test("L4: a poll keeps the line in its place; the next answer replaces it; leaving the page drops it", async () => {
  const SEND3 = { ...SEND, id: "egr-3" };
  // eslint-disable-next-line prefer-const
  let page: ReturnType<typeof load>;
  page = load({ homeVm: home({ waiting: [SEND, SEND2] }), routes: {
    "POST egress/approvals/egr-1/approve-once": () => (page.setHome(home({ waiting: [SEND2] })), {}),
    "POST egress/approvals/egr-2/deny": () => (page.setHome(home({ waiting: [SEND3] })), {}),
  } });
  const { doc } = page;
  await tick();
  press(button(cardOf(doc, "home-waiting", "egr-1"), "Allow once"));
  await tick(30);
  const line = lineIn(doc, "home-waiting");
  // The same answer: nothing is drawn again.
  await poll(doc);
  assert.equal(lineIn(doc, "home-waiting"), line);
  assert.equal(doc.activeElement, line, "the focus stays");
  // A new question comes: the list is drawn again, the line put back first.
  const old = cardOf(doc, "home-waiting", "egr-2");
  page.setHome(home({ waiting: [SEND2, SEND3] }));
  await poll(doc);
  assert.notEqual(cardOf(doc, "home-waiting", "egr-2"), old, "drawn again");
  assert.equal(doc.getElementById("home-waiting").firstElementChild, lineIn(doc, "home-waiting"));
  assert.equal(words(lineIn(doc, "home-waiting")), LINE);
  assert.equal(doc.activeElement, lineIn(doc, "home-waiting"), "the line keeps the focus, never <body>");
  // The next answer there replaces it.
  press(button(cardOf(doc, "home-waiting", "egr-2"), "Block"));
  await tick(30);
  assert.equal(doc.querySelectorAll("#home-waiting .answer-line").length, 1, "one line");
  assert.equal(words(lineIn(doc, "home-waiting")), "Blocked: send your secret GITHUB_TOKEN to api.github.com. Nothing was sent. Change your answer");
  // Away and back: gone.
  doc.querySelector("#nav [data-page-link=rules]").click();
  await tick(30);
  doc.querySelector("#nav [data-page-link=home]").click();
  await tick(30);
  assert.equal(lineIn(doc, "home-waiting"), null, "left with the page");
  assert.ok(cardOf(doc, "home-waiting", "egr-3"));
});

test("L5: the line takes the focus only from the page; a focus the person moved stays, and the line is drawn all the same", async () => {
  const { doc } = answered([SEND, SEND2], "egr-1", "approve-once", [SEND2], APPROVALS);
  await tick();
  press(button(cardOf(doc, "approvals-waiting", "egr-1"), "Allow once"));
  const nav = doc.querySelector("#nav [data-page-link=rules]");
  nav.focus();
  await tick(30);
  assert.equal(doc.activeElement, nav, "the person moved on");
  assert.ok(lineIn(doc, "approvals-waiting"), "the line is there");
  assert.equal(doc.getElementById("approvals-waiting").firstElementChild, lineIn(doc, "approvals-waiting"));
  // A click with no focus in the card (a mouse): no focus is moved.
  const { doc: d2 } = answered([SEND, SEND2], "egr-1", "approve-once", [SEND2]);
  await tick();
  button(cardOf(d2, "home-waiting", "egr-1"), "Allow once").click();
  await tick(30);
  assert.ok(lineIn(d2, "home-waiting"));
  assert.notEqual(d2.activeElement, lineIn(d2, "home-waiting"));
  assert.ok(!d2.activeElement.matches("button"), "never an answer button");
});

test("L6: the session page keeps Needs your OK shown under the line of its last question", async () => {
  let agent: unknown = { ...AGENT, waiting: [SEND] };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: {
    "GET home/agent?session=s1": () => agent,
    "POST egress/approvals/egr-1/approve-once": () => ((agent = { ...AGENT, waiting: [] }), {}),
  } });
  await tick();
  press(button(cardOf(doc, "agent-waiting", "egr-1"), "Allow once"));
  await tick(40);
  assert.equal(doc.getElementById("agent-waiting-block").hidden, false);
  assert.equal(words(lineIn(doc, "agent-waiting")), LINE);
  assert.equal(doc.activeElement, lineIn(doc, "agent-waiting"));
  // The agent works on: the page is drawn again with the line.
  agent = { ...AGENT, waiting: [], blocked: 2 };
  await poll(doc);
  assert.equal(doc.getElementById("agent-waiting-block").hidden, false);
  assert.equal(words(lineIn(doc, "agent-waiting")), LINE);
});

test("L7: Change your answer opens Approvals at the answered row", async () => {
  const row = { id: "egr-1", sentence: SEND.sentence, outcome: "allowed-once", decidedAt: Date.now() - 1_000, actions: [{ approve: false }] };
  // eslint-disable-next-line prefer-const
  let page: ReturnType<typeof load>;
  page = load({ homeVm: home({ waiting: [SEND] }), routes: {
    "POST egress/approvals/egr-1/approve-once": () => (page.setHome(home({ waiting: [], answered: [row] })), {}),
  } });
  const { doc, window } = page;
  await tick();
  press(button(cardOf(doc, "home-waiting", "egr-1"), "Allow once"));
  await tick(30);
  lineIn(doc, "home-waiting").querySelector("a").click();
  await tick(40);
  assert.equal(window.location.pathname, "/mandu/approvals/egr-1");
  const answeredRow = cardOf(doc, "approvals-answered", "egr-1");
  assert.ok(answeredRow, "the answered row is listed");
  assert.ok(button(answeredRow, "Block instead"), "with its change");
  assert.equal(lineIn(doc, "home-waiting"), null, "the line went with Home");
});

test("L8: the line's link can be swapped: the last Always of a program's send links its rule change (Undo it in Approvals); Change your answer stays the default", async () => {
  const HOLDER = {
    ...SEND, id: "egr-8",
    sentence: [T("Claude Code's program wants to send data from "), C("~/ws/.env"), T(" to "), C("hooks.slack.com")],
    whatParts: [T("Claude Code's program wants to send data from "), C("~/ws/.env"), T(" to "), C("hooks.slack.com")],
    actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Allow this session" }, { approve: false, label: "Block" }],
    sources: [{ path: "/home/u/ws/.env", name: "~/ws/.env", mayGo: "may go nowhere", blocks: true, always: "Always: add hooks.slack.com to .env" }],
  };
  let agent: unknown = { ...AGENT, waiting: [HOLDER] };
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: {
    "GET home/agent?session=s1": () => agent,
    "POST egress/approvals/egr-8/always-source": () => ((agent = { ...AGENT, waiting: [] }), { applied: true, changeId: "pc-000007", released: true, left: [] }),
    "POST egress/approvals/egr-1/approve-once": () => ((agent = { ...AGENT, waiting: [] }), {}),
  } });
  await tick();
  press(button(cardOf(doc, "agent-waiting", "egr-8"), "Always: add hooks.slack.com to .env"));
  await tick(40);
  assert.equal(cardOf(doc, "agent-waiting", "egr-8"), undefined, "the card went");
  const line = lineIn(doc, "agent-waiting");
  assert.equal(words(line), "Always allowed: Claude Code's program wants to send data from ~/ws/.env to hooks.slack.com. Tell Claude Code to try again. Undo it in Approvals");
  const links = [...line.querySelectorAll("a")];
  assert.equal(links.length, 1, "Undo it in Approvals in place of Change your answer");
  assert.equal(links[0].getAttribute("href"), "/mandu/approvals/pc-000007");
  assert.equal(doc.activeElement, line, "the line has the focus");
  assert.equal(doc.getElementById("agent-waiting-block").hidden, false, "Needs your OK stays shown under it");
  // The next answer there: the default link again.
  agent = { ...AGENT, waiting: [SEND] };
  await poll(doc);
  press(button(cardOf(doc, "agent-waiting", "egr-1"), "Allow once"));
  await tick(40);
  assert.equal(words(lineIn(doc, "agent-waiting")), LINE);
  assert.equal(lineIn(doc, "agent-waiting").querySelector("a").getAttribute("href"), "/mandu/approvals/egr-1");
});

test("L9: on Approvals the line stays in its card's group: under From sessions that have ended for an ended card, above it for one an agent waits on (§4.25 *A question from a session that has ended*)", async () => {
  const L1 = { ...SEND, id: "live-1" };
  const L2 = { ...SEND, id: "live-2" };
  const E1 = { ...SEND, id: "ended-1", askerEnded: true };
  const E2 = { ...SEND, id: "ended-2", askerEnded: true };
  const kids = (doc: Doc) => [...doc.getElementById("approvals-waiting").children].map((c: Doc) => c.dataset.id ?? c.className);
  // An ended card under the heading: its line where it was, under the heading.
  const a = answered([L1, L2, E1, E2], "ended-1", "approve-once", [L1, L2, E2], APPROVALS);
  await tick();
  // Answered from its short card (§4.25 *An ended question is short on Approvals*).
  assert.ok(cardOf(a.doc, "approvals-waiting", "ended-1").querySelector(".ask-more"), "the card is short");
  press(button(cardOf(a.doc, "approvals-waiting", "ended-1"), "Allow once"));
  await tick(30);
  assert.deepEqual(kids(a.doc), ["live-1", "live-2", "ask-group-head", "answer-line", "ended-2"]);
  assert.equal(words(lineIn(a.doc, "approvals-waiting")), "Allowed once: send your secret STRIPE_KEY to api.stripe.com. Your answer counts the next time an agent asks. Change your answer");
  for (const c of a.doc.querySelectorAll("#approvals-waiting .ask")) assert.ok(c.dataset.id, "every card a direct child with its id");
  // The last live card above the heading: its line stays above it.
  const b = answered([L1, L2, E1], "live-2", "approve-once", [L1, E1], APPROVALS);
  await tick();
  press(button(cardOf(b.doc, "approvals-waiting", "live-2"), "Allow once"));
  await tick(30);
  assert.deepEqual(kids(b.doc), ["live-1", "answer-line", "ask-group-head", "ended-1"]);
  // A poll that draws the list again keeps it there.
  b.setHome(home({ waiting: [L1, E1, E2] }));
  await poll(b.doc);
  assert.deepEqual(kids(b.doc), ["live-1", "answer-line", "ask-group-head", "ended-1", "ended-2"]);
});

test("L10: a rule change is a line place: its answer leaves a line that keeps its block shown, with the focus, and Undo it opens the change made", async () => {
  const PROPOSAL = {
    id: "pp-000004", status: "pending", requester: "Your agent", byAgent: true, session: "s1", createdAt: Date.now() - 60_000,
    rows: [[C("~/shop/.env"), T(" may be sent to "), C("api.stripe.com")]], wouldLet: [], capped: false, overBroad: false, reason: null,
  };
  const CHANGE = { id: "pc-000012", sentence: "Claude Code loosened your rules", rows: PROPOSAL.rows, createdAt: Date.now(), undone: false, undoable: true };
  let pending: unknown[] = [PROPOSAL];
  let changes: unknown[] = [];
  const { doc, window } = load({ url: APPROVALS, routes: {
    "GET policy/proposals?status=pending": () => ({ proposals: pending }),
    "GET policy/changes?limit=21": () => ({ changes }),
    "POST policy/proposals/pp-000004": () => ((pending = []), (changes = [CHANGE]), { proposal: { ...PROPOSAL, status: "approved" }, changeId: "pc-000012" }),
  } });
  await tick();
  press(button(cardOf(doc, "approvals-proposals", "pp-000004"), "Allow"));
  await tick(30);
  const line = lineIn(doc, "approvals-proposals");
  assert.ok(line, "the line");
  assert.equal(line.dataset.answerLine, "proposal");
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, false, "its block stays shown under it");
  assert.equal(doc.activeElement, line, "the line has the focus");
  await poll(doc);
  assert.equal(lineIn(doc, "approvals-proposals"), line, "a poll keeps it");
  line.querySelector("a").click();
  await tick(30);
  assert.equal(window.location.pathname, "/mandu/approvals/pc-000012");
  assert.deepEqual([...doc.querySelectorAll("#page-approvals .focus")].map((x: Doc) => x.dataset.id), ["pc-000012"], "the change's row is marked");
  assert.ok(button(cardOf(doc, "approvals-rule-history", "pc-000012"), "Undo"), "with its Undo");
});

test("L11: an Always on a file that is not the last: a poll that draws the card again puts its words back with Undo it in Approvals, which opens that change", async () => {
  const ENV = { path: "/home/u/ws/.env", name: "~/ws/.env", mayGo: "may go nowhere", blocks: true, always: "Always: add hooks.slack.com to .env" };
  const CSV = { path: "/home/u/data/c.csv", name: "~/data/c.csv", mayGo: "may go nowhere", blocks: true, always: "Always: add hooks.slack.com to c.csv" };
  const HOLDER = {
    ...SEND, id: "egr-9",
    sentence: [T("Claude Code's program wants to send data from "), C("~/ws/.env"), T(" and "), C("~/data/c.csv"), T(" to "), C("hooks.slack.com")],
    actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Allow this session" }, { approve: false, label: "Block" }],
    sources: [ENV, CSV],
  };
  const CHANGE = { id: "pc-000013", sentence: "You loosened your rules", rows: [[C("~/ws/.env"), T(" may be sent to "), C("hooks.slack.com")]], createdAt: Date.now(), undone: false, undoable: true };
  let changes: unknown[] = [];
  // eslint-disable-next-line prefer-const
  let page: ReturnType<typeof load>;
  page = load({ url: APPROVALS, homeVm: home({ waiting: [HOLDER] }), routes: {
    "GET policy/changes?limit=21": () => ({ changes }),
    "POST egress/approvals/egr-9/always-source": () => ((changes = [CHANGE]), { applied: true, changeId: "pc-000013", released: false, left: ["/home/u/data/c.csv"] }),
  } });
  const { doc, window } = page;
  await tick();
  press(button(cardOf(doc, "approvals-waiting", "egr-9"), "Always: add hooks.slack.com to .env"));
  await tick(30);
  const said = "Done: ~/ws/.env may go there now. Still in the way: ~/data/c.csv. Undo it in Approvals";
  assert.equal(words(cardOf(doc, "approvals-waiting", "egr-9").querySelector(".prompt-let-done")), said);
  assert.equal(lineIn(doc, "approvals-waiting"), null, "no line: the question still waits");
  // The file may go there now: the server draws it without its Always.
  const old = cardOf(doc, "approvals-waiting", "egr-9");
  page.setHome(home({ waiting: [{ ...HOLDER, sources: [{ ...ENV, mayGo: "may go to: hooks.slack.com", blocks: false, always: undefined }, CSV] }] }));
  await poll(doc);
  const card = cardOf(doc, "approvals-waiting", "egr-9");
  assert.notEqual(card, old, "drawn again");
  assert.deepEqual([...card.querySelectorAll(".ask-source-always")].map((b: Doc) => b.textContent), ["Always: add hooks.slack.com to c.csv"]);
  const done = card.querySelector(".prompt-let-done");
  assert.equal(words(done), said, "the words, and their link, are back");
  const link = done.querySelector("a");
  assert.equal(link.getAttribute("href"), "/mandu/approvals/pc-000013");
  link.click();
  await tick(30);
  assert.equal(window.location.pathname, "/mandu/approvals/pc-000013");
  assert.deepEqual([...doc.querySelectorAll("#page-approvals .focus")].map((x: Doc) => x.dataset.id), ["pc-000013"], "the change's row is marked");
  assert.ok(button(cardOf(doc, "approvals-rule-history", "pc-000013"), "Undo"), "with its Undo");
});
