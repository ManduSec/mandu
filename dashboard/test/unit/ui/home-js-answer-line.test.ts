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
 *       an agent that ended, a held message's answers;
 *   L3  a refusal keeps its words on the card and leaves no line;
 *   L4  a poll keeps the line in its place, whether it draws the list again
 *       or not; the next answer there replaces it; leaving the page drops it;
 *   L5  the line takes the focus the answer's place gave (never a button);
 *       a focus the person moved stays where it is;
 *   L6  the session page keeps Needs your OK shown under its line;
 *   L7  Change your answer opens Approvals at the answered row.
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
    [SEND, "send-without", "Send without it", "Allowed without the secret: send your secret STRIPE_KEY to api.stripe.com. Tell Claude Code to try again. Change your answer"],
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
  const PROMPT = { ...SEND, id: "egr-5", family: "prompt", sentence: [T("Claude Code wants to send your message to the AI. It holds "), C("acme.codename"), T(".")], afterAllow: undefined };
  for (const [label, said] of [
    ["Send as written", "Sent as written: the AI reads your message as you wrote it. Change your answer"],
    ["Send masked", "Sent masked: the AI reads your message with that part masked. Change your answer"],
    ["Cancel the message", "Cancelled: the AI does not read your message. Change your answer"],
  ] as const) {
    const { doc } = answered([PROMPT], "egr-5", "-");
    await tick();
    press(button(cardOf(doc, "home-waiting", "egr-5"), label));
    await tick(30);
    assert.equal(words(lineIn(doc, "home-waiting")), said, label);
  }
  // Approvals' session answer of a held message.
  const { doc } = answered([PROMPT], "egr-5", "-", [], APPROVALS);
  await tick();
  press(button(cardOf(doc, "approvals-waiting", "egr-5"), "Send as written for this session"));
  await tick(30);
  assert.equal(words(lineIn(doc, "approvals-waiting")), "Sent as written for this session: the AI reads your message as you wrote it. Change your answer");
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
