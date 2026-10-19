/**
 * home-js-poll-keeps.test — the product page's 10 s poll keeps your place
 * (dashboard.md §4.25 *The poll keeps your place*, §4.25h).
 *
 * Until 2026-10-09 every poll drew Home's and Approvals' cards, the rule
 * changes and the open agent page again from nothing, whether or not the
 * answer had changed. An agent page opened from an answer scrolled back to
 * the marked step every 10 s. Its open folds and shown text closed. A
 * refused answer's words ("Sign in first: …") vanished, so the click looked
 * dead. A typed ALLOW was emptied, with Allow turned off again and the focus
 * lost. Now:
 *
 *   - a poll whose answer for a section is the one it shows leaves that
 *     section as it is, its moments refreshed in place;
 *   - a write of your own that worked draws again at once;
 *   - the marked step is scrolled to once a visit;
 *   - a redrawn agent page puts the story's toggles back as you left them;
 *   - a typed ALLOW is kept per request, with the focus, and Allow stays off
 *     after a refusal until ALLOW is typed.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the shared
 * fetch stub (home-js-fixtures.ts). Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, ASK, home, load, T, tick } from "./home-js-fixtures.js";

const ADMIN_403 = { status: 403, body: { error: "admin session required — run `mandu dashboard` in your own terminal and open the sign-in link it prints (or set DASHBOARD_PASSWORD)" } };
const SIGN_IN = /^Sign in first: in your own terminal, run mandu dashboard and open the sign-in link it prints/;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function poll(doc: any): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick();
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const button = (root: any, label: string) => [...root.querySelectorAll("button")].find((b: any) => b.textContent === label) as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const turnOf = (doc: any, id: string) => [...doc.querySelectorAll("#agent-story article.turn")].find((t: any) => t.dataset.turnId === id) as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const stepOf = (doc: any, id: string) => [...doc.querySelectorAll("#agent-story [data-step-id]")].find((s: any) => s.dataset.stepId === id) as any;

// ── The agent page ────────────────────────────────────────────────────────────

const plain = (id: string) => ({ kind: "action", id, ts: "2026-09-25T10:01:01.000Z", icon: "run", sentence: [T(`Ran ${id}`)], outcome: "plain", note: null, split: null });
const LONG = "Explain this repository in detail. ".repeat(30);
/** AGENT with a long prompt (Show all) on its first turn, a secret's step
 *  that has a real value to show, and a Your secrets time on step r7, which
 *  is in the second turn's fold. */
function agent(extraSteps = 0) {
  const [t1, t2] = AGENT.story;
  const t1Steps = t1.steps.map((s) => s.id !== "t2" ? s : { ...s, split: { ...s.split, hidden: { text: null, secret: true, truncated: false, secrets: [{ ref: "0123456789abcdef01234567", name: "API_KEY" }] } } });
  const t2Steps = [...t2.steps, ...Array.from({ length: extraSteps }, (_, i) => plain(`n${i}`))];
  return {
    ...AGENT, waiting: [], valuesShown: true,
    story: [{ ...t1, prompt: LONG, steps: t1Steps }, { ...t2, steps: t2Steps }],
    secrets: { mode: "secrets", flagged: false, more: 0, secrets: [
      { what: [T("API_KEY"), T(" in a file")], level: "No AI", lines: [
        { tone: "warn", parts: [T("The AI read it at "), { kind: "time", text: "2026-09-25T10:01:01.000Z", step: "r7" }, T(".")] },
      ] },
    ] },
  };
}

test("the agent page: a poll with the same answer leaves it as it is, with what you opened; its moments are refreshed", async () => {
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": agent() } });
  await tick();
  const t1 = turnOf(doc, "turn:i1");
  const t2 = turnOf(doc, "turn:i2");
  button(t2, "Show 2 more steps").click();
  button(t1, "Show what was hidden").click();
  button(t1, "Show all").click();
  const story = doc.getElementById("agent-story").firstElementChild;
  const when = doc.querySelector("#agent-sub time.when");
  assert.match(when.textContent, / · just now$/);
  const realNow = window.Date.now;
  window.Date.now = () => realNow() + 3_600_000;
  try {
    await poll(doc);
  } finally {
    window.Date.now = realNow;
  }
  assert.equal(doc.getElementById("agent-story").firstElementChild, story, "the story is the one you read");
  assert.equal(t2.querySelector(".steps-more").hidden, false, "the fold stays open");
  assert.equal(t1.querySelector(".hidden-box .hidden-text").hidden, false, "the hidden text stays shown");
  assert.equal(t1.querySelector(".linkish").textContent, "Show less", "the long prompt stays whole");
  assert.equal(doc.querySelector("#agent-sub time.when"), when, "the line is the one drawn");
  assert.match(when.textContent, / · 1 hour ago$/, "and its moment says the time now");
});

test("opened from an answer, the marked step is scrolled to once a visit: never by a poll or a redraw, again on a new visit; a fold you closed stays closed", async () => {
  let page: unknown = { ...agent(), focus: { ask: "egr-7", turnId: "turn:i2", stepId: "r7", match: "exact" } };
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1?ask=egr-7", routes: { "GET home/agent?session=s1&ask=egr-7": () => page } });
  let scrolls = 0;
  window.HTMLElement.prototype.scrollIntoView = function () { scrolls++; };
  window.requestAnimationFrame = (f: () => void) => setImmediate(f);
  await tick();
  assert.equal(scrolls, 1, "scrolled to the marked step once");
  assert.equal(stepOf(doc, "r7").classList.contains("focus"), true);
  await poll(doc);
  assert.equal(scrolls, 1, "a poll leaves you where you scrolled");
  // You close the fold the mark opened; the agent does more.
  const fold = turnOf(doc, "turn:i2").querySelector(".steps-more");
  assert.equal(fold.hidden, false, "the mark opened its fold");
  button(turnOf(doc, "turn:i2"), "Show fewer steps").click();
  page = { ...agent(1), focus: { ask: "egr-7", turnId: "turn:i2", stepId: "r7", match: "exact" } };
  await poll(doc);
  assert.ok(stepOf(doc, "n0"), "the new step is drawn");
  assert.equal(stepOf(doc, "r7").classList.contains("focus"), true, "the step is still marked");
  assert.equal(scrolls, 1, "a redraw does not scroll either");
  assert.equal(turnOf(doc, "turn:i2").querySelector(".steps-more").hidden, true, "the fold you closed stays closed");
  // A new visit: the page opens as from the link, scrolled to the mark again.
  window.history.pushState(null, "", "/mandu/");
  window.dispatchEvent(new window.PopStateEvent("popstate"));
  await tick();
  window.history.pushState(null, "", "/mandu/agents/s1?ask=egr-7");
  window.dispatchEvent(new window.PopStateEvent("popstate"));
  await tick();
  assert.equal(scrolls, 2, "a new visit scrolls to it again");
  assert.equal(turnOf(doc, "turn:i2").querySelector(".steps-more").hidden, false, "with its fold open");
});

test("the agent did more: the page is drawn again with the new step, and what you opened stays open; Show the real value asks again only on a click", async () => {
  let page = agent();
  const { doc, calls } = load({
    url: "http://127.0.0.1:4500/mandu/agents/s1",
    routes: { "GET home/agent?session=s1": () => page, "POST home/reveal": { value: "sk-test-real-value" } },
  });
  await tick();
  const t1 = () => turnOf(doc, "turn:i1");
  const t2 = () => turnOf(doc, "turn:i2");
  button(t2(), "Show 2 more steps").click();
  button(t1(), "Show what was hidden").click();
  button(t1(), "Show all").click();
  button(t1(), "Show the real value").click();
  await tick();
  assert.equal(t1().querySelector(".secret-value").textContent, "sk-test-real-value");
  (doc.querySelector("#agent-secrets .step-link") as any).click();
  assert.equal(stepOf(doc, "r7").classList.contains("shown"), true);
  const reveals = () => calls.filter((c) => c.method === "POST" && c.url.endsWith("/api/home/reveal")).length;
  assert.equal(reveals(), 1);
  const before = doc.getElementById("agent-story").firstElementChild;

  page = agent(2);
  await poll(doc);
  assert.notEqual(doc.getElementById("agent-story").firstElementChild, before, "drawn again");
  assert.ok(stepOf(doc, "n1"), "with the new steps");
  assert.equal(t2().querySelector(".steps-more").hidden, false, "the fold stays open");
  assert.equal(t2().querySelector(".steps-toggle").getAttribute("aria-expanded"), "true");
  assert.equal(t1().querySelector(".hidden-box:not(.secret-value-box) .hidden-text").hidden, false, "the hidden text stays shown");
  assert.equal(t1().querySelector(".linkish").textContent, "Show less", "the long prompt stays whole");
  assert.equal(stepOf(doc, "r7").classList.contains("shown"), true, "the step a Your secrets time marked stays marked");
  assert.equal(t1().querySelector(".secret-reveal").getAttribute("aria-expanded"), "false", "the real value is not on the page again");
  assert.equal(t1().querySelector(".secret-value").textContent, "");
  assert.equal(reveals(), 1, "and not asked for again");
  assert.ok(!doc.body.textContent.includes("sk-test-real-value"));
});

// ── Approvals and Home ────────────────────────────────────────────────────────

test("Approvals: a refused answer's words outlast a poll with the same answer; a write that worked draws the list again at once", async () => {
  let denies = 0;
  const { doc } = load({
    url: "http://127.0.0.1:4500/mandu/approvals",
    routes: { [`POST egress/approvals/${ASK.id}/deny`]: () => (++denies === 1 ? ADMIN_403 : { ok: true }) },
  });
  await tick();
  const card = doc.querySelector("#approvals-waiting .ask") as any;
  button(card, "Block").click();
  await tick();
  assert.match(card.querySelector(".ask-error").textContent, SIGN_IN);
  await poll(doc);
  assert.equal(doc.querySelector("#approvals-waiting .ask"), card, "the card is the one you answered");
  assert.match(card.querySelector(".ask-error").textContent, SIGN_IN, "its words stay");
  assert.equal(button(card, "Block").disabled, false, "and its buttons work");
  // Signed in now, Block works: the list is drawn again even though this
  // stub still lists the question.
  button(card, "Block").click();
  await tick();
  assert.equal(denies, 2);
  const again = doc.querySelector("#approvals-waiting .ask") as any;
  assert.notEqual(again, card, "drawn again after your own answer");
  assert.equal(again.querySelector(".ask-error"), null);
});

test("Home: a refused answer's words outlast a poll; a new question draws the cards again", async () => {
  const { doc, setHome } = load({ routes: { [`POST egress/approvals/${ASK.id}/deny`]: ADMIN_403 } });
  await tick();
  const card = doc.querySelector("#home-waiting .ask") as any;
  button(card, "Block").click();
  await tick();
  await poll(doc);
  assert.equal(doc.querySelector("#home-waiting .ask"), card);
  assert.match(card.querySelector(".ask-error").textContent, SIGN_IN);
  setHome(home({ waiting: [ASK, { ...ASK, id: "egr-2" }] }));
  await poll(doc);
  assert.deepEqual([...doc.querySelectorAll("#home-waiting .ask")].map((c: any) => c.dataset.id), ["egr-1", "egr-2"], "the new question shows");
});

test("Rule changes: a refused Undo's words outlast a poll", async () => {
  const change = { id: "pc-1", sentence: "You let your secrets go to api.example.com", rows: [], createdAt: Date.now() - 60_000, undoable: true, undone: false };
  const { doc } = load({
    url: "http://127.0.0.1:4500/mandu/approvals",
    routes: { "GET policy/changes?limit=21": { changes: [change] }, "POST policy/changes/pc-1/undo": ADMIN_403 },
  });
  await tick();
  const row = doc.querySelector("#approvals-rule-history .row") as any;
  button(row, "Undo").click();
  await tick();
  assert.match(row.querySelector(".ask-error").textContent, SIGN_IN);
  await poll(doc);
  assert.equal(doc.querySelector("#approvals-rule-history .row"), row);
  assert.match(row.querySelector(".ask-error").textContent, SIGN_IN);
});

// ── The typed ALLOW of an over-broad change ─────────────────────────────────

const WIDE = {
  id: "pp-000001", status: "pending", requester: "Your agent", createdAt: Date.now() - 60_000, overBroad: true, capped: false,
  rows: [[T("Let your secrets go to "), { kind: "code", text: "*" }]], wouldLet: [[T("Any website would get your secrets")]], warnings: [], reason: "",
};
const PENDING = "GET policy/proposals?status=pending";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function type(window: any, field: any, text: string): void {
  field.focus();
  field.value = text;
  field.setSelectionRange(text.length, text.length);
  field.dispatchEvent(new window.Event("input"));
}

test("an over-broad change: what you typed stays across a poll, with Allow and the focus; a redrawn list keeps both", async () => {
  let proposals = [WIDE];
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { [PENDING]: () => ({ proposals }) } });
  await tick();
  const field = doc.querySelector(".proposal-confirm") as any;
  type(window, field, "ALLOW");
  assert.equal(button(doc.getElementById("approvals-proposals"), "Allow").disabled, false);
  await poll(doc);
  assert.equal(doc.querySelector(".proposal-confirm"), field, "the same field");
  assert.equal(field.value, "ALLOW");
  assert.equal(doc.activeElement, field, "with the focus");
  assert.equal(button(doc.getElementById("approvals-proposals"), "Allow").disabled, false, "Allow stays on");
  // Another request arrives: the list is drawn again, your word kept.
  proposals = [WIDE, { ...WIDE, id: "pp-000002" }];
  await poll(doc);
  const cards = [...doc.querySelectorAll("#approvals-proposals .proposal")] as any[];
  assert.equal(cards.length, 2, "drawn again");
  const kept = cards[0].querySelector(".proposal-confirm");
  assert.notEqual(kept, field);
  assert.equal(kept.value, "ALLOW", "what you typed stays");
  assert.equal(doc.activeElement, kept, "and so does the focus");
  assert.equal(button(cards[0], "Allow").disabled, false);
  assert.equal(cards[1].querySelector(".proposal-confirm").value, "", "the other request has its own field");
  assert.equal(button(cards[1], "Allow").disabled, true);
});

test("an over-broad change: after a refusal, Allow stays off until ALLOW is typed", async () => {
  const { doc, window } = load({
    url: "http://127.0.0.1:4500/mandu/approvals",
    routes: { [PENDING]: { proposals: [WIDE] }, "POST policy/proposals/pp-000001": ADMIN_403 },
  });
  await tick();
  const card = doc.querySelector("#approvals-proposals .proposal") as any;
  type(window, card.querySelector(".proposal-confirm"), "ALLO");
  button(card, "Not now").click();
  await tick();
  assert.match(card.querySelector(".ask-error").textContent, SIGN_IN);
  assert.equal(button(card, "Not now").disabled, false);
  assert.equal(button(card, "Allow").disabled, true, "not typed: Allow stays off");
  await poll(doc);
  assert.equal(button(card, "Allow").disabled, true);
  assert.match(card.querySelector(".ask-error").textContent, SIGN_IN, "the words stay");
});

// ── A changed list keeps the words of an answer ─────────────────────────────
// A poll whose answer changed draws the list again from nothing: the agent
// asked the same thing again (its count and moment change), a new question
// or request came, a change was undone. Until 2026-10-09 (run 2130) the words
// of a refused answer went with the old card, so the click looked dead again
// whenever the agent was busy. Now each card or row gets them back, by its
// place and id, while it is in the state they answered.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const byId = (doc: any, sel: string, id: string) => [...doc.querySelectorAll(sel)].find((x: any) => x.dataset.id === id) as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const wordsOn = (node: any) => node.querySelector(".ask-error")?.textContent ?? null;

test("Approvals: the agent asked again and a new question came: the card is drawn again with its words; the next button takes them away; a question that left the list takes them with it", async () => {
  const { doc, setHome } = load({
    url: "http://127.0.0.1:4500/mandu/approvals",
    routes: { [`POST egress/approvals/${ASK.id}/deny`]: ADMIN_403, [`POST egress/approvals/${ASK.id}/approve-once`]: { ok: true } },
  });
  await tick();
  const card = byId(doc, "#approvals-waiting .ask", "egr-1");
  button(card, "Block").click();
  await tick();
  assert.match(wordsOn(card), SIGN_IN);
  setHome(home({ waiting: [{ ...ASK, count: 2, askedAt: Date.now() }, { ...ASK, id: "egr-2" }] }));
  await poll(doc);
  const again = byId(doc, "#approvals-waiting .ask", "egr-1");
  assert.notEqual(again, card, "the changed list is drawn again");
  assert.match(again.textContent, /2 times/, "with the new count");
  assert.match(wordsOn(again), SIGN_IN, "and the words of your answer on its card");
  assert.equal(button(again, "Block").disabled, false, "its buttons work");
  assert.equal(wordsOn(byId(doc, "#approvals-waiting .ask", "egr-2")), null, "the new question has none");
  // The next button on the card: the old words go with it. This one works,
  // so the list is drawn again, and this stub still lists the question.
  button(again, "Allow once").click();
  await tick();
  assert.equal(wordsOn(byId(doc, "#approvals-waiting .ask", "egr-1")), null, "an answer that worked leaves no words behind");
  // Refused again, then answered elsewhere: the card leaves, and its words with it.
  button(byId(doc, "#approvals-waiting .ask", "egr-1"), "Block").click();
  await tick();
  assert.match(wordsOn(byId(doc, "#approvals-waiting .ask", "egr-1")), SIGN_IN);
  setHome(home({ waiting: [{ ...ASK, id: "egr-2" }] }));
  await poll(doc);
  assert.equal(byId(doc, "#approvals-waiting .ask", "egr-1"), undefined);
  setHome(home({ waiting: [ASK, { ...ASK, id: "egr-2" }] }));
  await poll(doc);
  assert.equal(wordsOn(byId(doc, "#approvals-waiting .ask", "egr-1")), null, "listed again, it has no old words");
});

test("Approvals › Answered earlier: a refused Block instead keeps its words while the row says the same answer; answered otherwise, they go", async () => {
  const done = (id: string, outcome: string) => ({ id, sentence: [T(`Claude Code wanted to send your secret to ${id}.example`)], outcome, decidedAt: Date.now() - 300_000, sessions: [], actions: [{ approve: outcome !== "allowed" }] });
  const { doc, setHome } = load({
    url: "http://127.0.0.1:4500/mandu/approvals",
    homeVm: home({ answered: [done("egr-9", "allowed")] }),
    routes: { "POST egress/approvals/egr-9/deny": ADMIN_403 },
  });
  await tick();
  const row = byId(doc, "#approvals-answered .row", "egr-9");
  button(row, "Block instead").click();
  await tick();
  assert.match(wordsOn(row), SIGN_IN);
  setHome(home({ answered: [done("egr-8", "blocked"), done("egr-9", "allowed")] }));
  await poll(doc);
  const again = byId(doc, "#approvals-answered .row", "egr-9");
  assert.notEqual(again, row, "drawn again");
  assert.match(wordsOn(again), SIGN_IN, "the same answer: the words stay");
  assert.equal(wordsOn(byId(doc, "#approvals-answered .row", "egr-8")), null);
  // Blocked elsewhere (Rules, another tab): the words answered an answer that is no longer there.
  setHome(home({ answered: [done("egr-8", "blocked"), done("egr-9", "blocked")] }));
  await poll(doc);
  const changed = byId(doc, "#approvals-answered .row", "egr-9");
  assert.ok(button(changed, "Allow instead"), "the row says the new answer");
  assert.equal(wordsOn(changed), null, "and not the old words");
});

test("Home: a new question draws the cards again, and the words of your answer stay on their card", async () => {
  const { doc, setHome } = load({ routes: { [`POST egress/approvals/${ASK.id}/deny`]: ADMIN_403 } });
  await tick();
  button(byId(doc, "#home-waiting .ask", "egr-1"), "Block").click();
  await tick();
  setHome(home({ waiting: [{ ...ASK, count: 2, askedAt: Date.now() }, { ...ASK, id: "egr-2" }] }));
  await poll(doc);
  assert.deepEqual([...doc.querySelectorAll("#home-waiting .ask")].map((c: any) => c.dataset.id), ["egr-1", "egr-2"]);
  assert.match(wordsOn(byId(doc, "#home-waiting .ask", "egr-1")), SIGN_IN);
  assert.equal(wordsOn(byId(doc, "#home-waiting .ask", "egr-2")), null);
});

test("the rule changes your agent asked for and Rule changes: a new request or change draws the list again with the words of your answer; an undone change loses its Undo words", async () => {
  let proposals = [{ ...WIDE, overBroad: false }];
  const change = (id: string, undone = false) => ({ id, sentence: `You let your secrets go to ${id}.example`, rows: [], createdAt: Date.now() - 60_000, undoable: !undone, undone });
  let changes = [change("pc-1")];
  const { doc } = load({
    url: "http://127.0.0.1:4500/mandu/approvals",
    routes: {
      [PENDING]: () => ({ proposals }), "POST policy/proposals/pp-000001": ADMIN_403,
      "GET policy/changes?limit=21": () => ({ changes }), "POST policy/changes/pc-1/undo": ADMIN_403,
    },
  });
  await tick();
  button(byId(doc, "#approvals-proposals .proposal", "pp-000001"), "Not now").click();
  button(byId(doc, "#approvals-rule-history .row", "pc-1"), "Undo").click();
  await tick();
  proposals = [{ ...WIDE, overBroad: false }, { ...WIDE, overBroad: false, id: "pp-000002" }];
  changes = [change("pc-2"), change("pc-1")];
  await poll(doc);
  assert.equal(doc.querySelectorAll("#approvals-proposals .proposal").length, 2, "drawn again");
  assert.match(wordsOn(byId(doc, "#approvals-proposals .proposal", "pp-000001")), SIGN_IN);
  assert.equal(wordsOn(byId(doc, "#approvals-proposals .proposal", "pp-000002")), null);
  assert.equal(doc.querySelectorAll("#approvals-rule-history .row").length, 2, "drawn again");
  assert.match(wordsOn(byId(doc, "#approvals-rule-history .row", "pc-1")), SIGN_IN);
  assert.equal(wordsOn(byId(doc, "#approvals-rule-history .row", "pc-2")), null);
  // Undone elsewhere: no Undo on the row, and no words about one.
  changes = [change("pc-2"), change("pc-1", true)];
  await poll(doc);
  const undone = byId(doc, "#approvals-rule-history .row", "pc-1");
  assert.match(undone.textContent, /Undone/);
  assert.equal(wordsOn(undone), null);
});

test("a refusal that comes back after a poll drew the card again shows on the card drawn now", async () => {
  const { doc, window, setHome } = load({ url: "http://127.0.0.1:4500/mandu/approvals" });
  await tick();
  // The answer is on its way while the poll draws a changed list.
  let answer: (r: unknown) => void = () => {};
  const stub = window.fetch;
  window.fetch = (url: string, init: { method?: string } = {}) => (init.method === "POST" && url.endsWith(`/api/egress/approvals/${ASK.id}/deny`)
    ? new Promise((r) => { answer = r; })
    : stub(url, init));
  const card = byId(doc, "#approvals-waiting .ask", "egr-1");
  button(card, "Block").click();
  await tick();
  setHome(home({ waiting: [{ ...ASK, count: 2, askedAt: Date.now() }, { ...ASK, id: "egr-2" }] }));
  await poll(doc);
  const now = byId(doc, "#approvals-waiting .ask", "egr-1");
  assert.notEqual(now, card, "drawn again while the answer was on its way");
  answer({ ok: false, status: 403, json: () => Promise.resolve(ADMIN_403.body) });
  await tick();
  assert.match(wordsOn(now), SIGN_IN, "the words are on the card you see");
  assert.equal(button(now, "Block").disabled, false, "and its buttons work");
});

// ── The agent page keeps the words of an answer ─────────────────────────────
// While an agent works, its page changes at nearly every poll (a new step,
// the stopped send tried again), and the page is drawn again. Until
// 2026-10-09 (run 2230) that took the words of an answer away: signed out,
// "Sign in first: …" under Block on its Waiting card and under "Let it
// through" in the note under your message; signed in, "Let through in this
// message." went and both buttons came back until the agent's next request
// recorded it. Now each card and note row gets them back, by its id, while
// it is in the state they answered.

const LET = "POST prompt-filters/let-through";
const finding = (eventId: string, index: number, state = "hidden") =>
  ({ eventId, index, category: "pii.email", words: "an email address", state, canLetOnce: state === "hidden", canLetSession: state === "hidden", canShow: false });
const note = (...items: unknown[]) => ({ lines: ["One value in your prompt was hidden from the AI (an email address)."], items, ts: "2026-09-25T10:00:00.000Z" });
/** AGENT with the question waiting, a note under the first message, and
 *  `extraSteps` more steps: the agent doing more. */
function working(extraSteps: number, items: unknown[] = [finding("ev-1", 0), finding("ev-1", 1)], waiting: unknown[] = [ASK]) {
  const [t1, t2] = AGENT.story;
  return { ...AGENT, valuesShown: false, waiting, story: [{ ...t1, promptNote: note(...items) }, { ...t2, steps: [...t2.steps, ...Array.from({ length: extraSteps }, (_, i) => plain(`n${i}`))] }] };
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const noteRows = (doc: any) => [...doc.querySelectorAll("#agent-story .prompt-note-item")] as any[];
const AGENT_PAGE = "http://127.0.0.1:4500/mandu/agents/s1";

test("the agent page: the agent did more and asked again: its Waiting card is drawn again with the words of your answer; a question that left takes them with it", async () => {
  let page: unknown = working(0);
  const { doc } = load({ url: AGENT_PAGE, routes: { "GET home/agent?session=s1": () => page, [`POST egress/approvals/${ASK.id}/deny`]: ADMIN_403 } });
  await tick();
  const card = byId(doc, "#agent-waiting .ask", "egr-1");
  button(card, "Block").click();
  await tick();
  assert.match(wordsOn(card), SIGN_IN);
  page = working(1, undefined, [{ ...ASK, count: 2, askedAt: Date.now() }]);
  await poll(doc);
  assert.ok(stepOf(doc, "n0"), "the page is drawn again with the new step");
  const again = byId(doc, "#agent-waiting .ask", "egr-1");
  assert.notEqual(again, card);
  assert.match(again.textContent, /2 times/);
  assert.match(wordsOn(again), SIGN_IN, "the words of your answer stay on its card");
  assert.equal(button(again, "Block").disabled, false, "and its buttons work");
  assert.equal(wordsOn(byId(doc, "#approvals-waiting .ask", "egr-1")), null, "Approvals' card of the same question keeps its own");
  // Answered elsewhere: the card leaves with its words; asked anew, it has none.
  page = working(2, undefined, []);
  await poll(doc);
  assert.equal(byId(doc, "#agent-waiting .ask", "egr-1"), undefined);
  page = working(3);
  await poll(doc);
  assert.equal(wordsOn(byId(doc, "#agent-waiting .ask", "egr-1")), null, "listed again, it has no old words");
});

test("the note under your message: a refused Let it through keeps its words on its row across a redraw, never on another finding's; the next press takes them", async () => {
  let page: unknown = working(0);
  let lets = 0;
  const { doc } = load({ url: AGENT_PAGE, routes: { "GET home/agent?session=s1": () => page, [LET]: () => (++lets === 1 ? ADMIN_403 : { approval: { id: "egr-3" }, scope: "once" }) } });
  await tick();
  const [row] = noteRows(doc);
  button(row, "Let it through in this message").click();
  await tick();
  assert.match(wordsOn(row), SIGN_IN);
  page = working(1);
  await poll(doc);
  const [again, other] = noteRows(doc);
  assert.notEqual(again, row, "drawn again");
  assert.match(wordsOn(again), SIGN_IN, "its words stay");
  assert.equal(button(again, "Let it through in this message").disabled, false, "and its buttons work");
  assert.equal(wordsOn(other), null, "the other finding has none");
  // Signed in now: the answer works, and the refusal's words go with it.
  button(again, "Let it through in this message").click();
  await tick();
  assert.equal(wordsOn(again), null);
  assert.match(again.textContent, /Let through in this message\./);
});

test("the note under your message: a let-through that worked keeps its line, not the buttons, across a redraw until the agent's next request records it", async () => {
  let page: unknown = working(0);
  const { doc } = load({ url: AGENT_PAGE, routes: { "GET home/agent?session=s1": () => page, [LET]: { approval: { id: "egr-3" }, scope: "session" } } });
  await tick();
  button(noteRows(doc)[0], "Let it through for this session").click();
  await tick();
  // The agent did more, and its next request has not come yet: the server
  // still offers the buttons on the same event.
  page = working(1);
  await poll(doc);
  const [row, other] = noteRows(doc);
  assert.ok(stepOf(doc, "n0"), "drawn again");
  assert.match(row.textContent, /Let through for this session\. The AI reads it from the agent's next request\./);
  assert.equal(row.querySelector(".prompt-let-once"), null, "no button asks again");
  assert.equal(row.querySelector(".prompt-let-session"), null);
  assert.ok(other.querySelector(".prompt-let-once"), "the other finding keeps its own");
  // The next request recorded it: a new event, and the server's own line.
  page = working(2, [finding("ev-2", 0, "let-session"), finding("ev-2", 1)]);
  await poll(doc);
  assert.equal(doc.querySelector("#agent-story .prompt-let-done"), null, "the kept line goes with the event it answered");
  assert.ok(noteRows(doc)[0].querySelector(".prompt-let-once"), "the finding still open keeps its buttons");
});

test("the note under your message: an answer that comes back after a redraw shows on the row drawn now", async () => {
  let page: unknown = working(0);
  const { doc, window } = load({ url: AGENT_PAGE, routes: { "GET home/agent?session=s1": () => page } });
  await tick();
  let answer: (r: unknown) => void = () => {};
  const stub = window.fetch;
  window.fetch = (url: string, init: { method?: string } = {}) => (init.method === "POST" && url.endsWith("/api/prompt-filters/let-through")
    ? new Promise((r) => { answer = r; })
    : stub(url, init));
  const [row] = noteRows(doc);
  button(row, "Let it through in this message").click();
  await tick();
  page = working(1);
  await poll(doc);
  const [now] = noteRows(doc);
  assert.notEqual(now, row, "drawn again while the answer was on its way");
  answer({ ok: false, status: 403, json: () => Promise.resolve(ADMIN_403.body) });
  await tick();
  assert.match(wordsOn(now), SIGN_IN, "the words are on the row you see");
  assert.equal(button(now, "Let it through in this message").disabled, false, "and its buttons work");
});
