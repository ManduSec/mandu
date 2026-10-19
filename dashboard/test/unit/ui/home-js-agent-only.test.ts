/**
 * home-js-agent-only.test — dashboard.md §4.25ae *Only where Mandu stepped
 * in*. A session's page drew every turn as a full card, though most of a
 * real session is ordinary work where Mandu did nothing. A switch beside
 * the *What happened* heading folds those turns away:
 *
 *   O1  the switch counts the turns where Mandu stepped in ("4 of 9
 *       turns"); off (the default) every turn shows; on, each run of quiet
 *       turns folds into one line ("3 turns where Mandu did nothing") whose
 *       button shows them in place and hides them again; a turn with a
 *       block, a mask, a send or a note under your message never folds;
 *   O2  the address says so (`?only=stepped-in`, replaced, not pushed): a
 *       page opened with it opens filtered, a link to a session opens it
 *       whole;
 *   O3  the turn an ask opened the page for (`?ask=`) never folds, even
 *       one where Mandu did nothing;
 *   O4  a poll that draws the page again keeps the switch and the runs you
 *       opened; a focus inside a turn that folds goes to the line it folds
 *       into, never the heading or <body>; a step a link shows opens its run.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, T, load, tick } from "./home-js-fixtures.js";

const URL1 = "http://127.0.0.1:4500/mandu/agents/s1";
const step = (id: string, outcome = "plain") => ({ kind: "action", id, ts: "2026-09-25T10:00:01.000Z", icon: "run", sentence: [T(`Ran ${id}`)], outcome, note: null, split: null });
/** A turn where Mandu did nothing (`tone` plain; its summary is "Nothing
 *  here needed guarding.", as the server says it), or one with `outcome`. */
const turn = (id: string, outcome = "plain", over: Record<string, unknown> = {}) => ({
  ...AGENT.story[1], id, prompt: `Question ${id}`, routine: null, reply: null, moreSteps: 0, promptNote: null,
  summary: outcome === "plain" ? "Nothing here needed guarding." : `Mandu did ${outcome}.`, summaryParts: null, tone: outcome,
  steps: [step(`${id}-a`), step(`${id}-b`, outcome)], ...over,
});
const NOTE = { lines: ["One value in your prompt was hidden from the AI (an email address)."], items: [], ts: "2026-09-25T10:00:00.000Z" };
/** Nine turns: q1 q2 | blocked | q3 | secret | q4 q5 q6 | a note (plain steps). */
const STORY = [
  turn("t:q1"), turn("t:q2"), turn("t:b", "blocked"), turn("t:q3"), turn("t:s", "secret"),
  turn("t:q4"), turn("t:q5"), turn("t:q6", "plain", { summary: null }), turn("t:n", "plain", { promptNote: NOTE }),
];
const PAGE = { ...AGENT, waiting: [], earlier: 0, story: STORY };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const turns = (doc: El) => [...doc.querySelectorAll("#agent-story article.turn[data-turn-id]")] as El[];
const shownTurns = (doc: El) => turns(doc).filter((t) => !t.closest("[hidden]")).map((t) => t.dataset.turnId);
const lines = (doc: El) => [...doc.querySelectorAll("#agent-story .story-quiet")] as El[];
const sw = (doc: El) => doc.getElementById("agent-only");
async function poll(doc: El): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

test("O1: the switch counts the turns where Mandu stepped in; on, each run of quiet turns folds into one line that shows them in place", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  const row = doc.getElementById("agent-only-row");
  assert.equal(row.hidden, false, "shown with a story");
  assert.equal(row.parentElement.querySelector("h2").textContent, "What happened", "beside the heading");
  assert.equal(sw(doc).getAttribute("role"), "switch");
  assert.equal(sw(doc).getAttribute("aria-checked"), "false", "off by default");
  assert.equal(doc.getElementById("agent-only-words").textContent, "Only where Mandu stepped in (3 of 9 turns)");
  assert.equal(doc.getElementById(sw(doc).getAttribute("aria-labelledby")).textContent, "Only where Mandu stepped in (3 of 9 turns)", "the switch is named by its words");
  assert.equal(doc.querySelector('label[for="agent-only"]').id, "agent-only-words", "its words press it too");
  assert.equal(shownTurns(doc).length, 9, "off: the page as before");
  assert.equal(lines(doc).length, 0);

  sw(doc).focus();
  sw(doc).click();
  assert.equal(sw(doc).getAttribute("aria-checked"), "true");
  assert.deepEqual(shownTurns(doc), ["t:b", "t:s", "t:n"], "only the block, the secret and the note under your message");
  assert.deepEqual(lines(doc).map((l) => l.textContent), [
    "2 turns where Mandu did nothing Show them",
    "1 turn where Mandu did nothing Show it",
    "3 turns where Mandu did nothing Show them",
  ], "one line a run, in its place, a summary-less turn with the rest");
  // Each line sits where its run is.
  const story = [...doc.getElementById("agent-story").children] as El[];
  const at = (x: El) => story.indexOf(x);
  const byId = (id: string) => turns(doc).find((t) => t.dataset.turnId === id);
  assert.ok(at(lines(doc)[0]) < at(byId("t:q1")) && at(byId("t:q2")) < at(byId("t:b")));
  assert.ok(at(byId("t:b")) < at(lines(doc)[1]) && at(lines(doc)[1]) < at(byId("t:s")));
  assert.equal(doc.activeElement, sw(doc), "the focus stays on the switch");

  const btn = lines(doc)[2].querySelector("button.quiet-toggle");
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  assert.equal(doc.getElementById(btn.getAttribute("aria-describedby")).textContent, "3 turns where Mandu did nothing", "the button is described by its line");
  btn.click();
  assert.deepEqual(shownTurns(doc), ["t:b", "t:s", "t:q4", "t:q5", "t:q6", "t:n"], "in place");
  assert.equal(btn.getAttribute("aria-expanded"), "true");
  assert.equal(btn.textContent, "Hide them");
  btn.click();
  assert.deepEqual(shownTurns(doc), ["t:b", "t:s", "t:n"], "and hidden again");

  // Off again: every turn, no line.
  sw(doc).click();
  assert.equal(sw(doc).getAttribute("aria-checked"), "false");
  assert.equal(shownTurns(doc).length, 9);
  assert.equal(lines(doc).length, 0);
});

test("O2: ?only=stepped-in opens the page filtered and the switch writes it (replaced); a link opens a session whole", async () => {
  const { doc, window, calls } = load({ url: `${URL1}?only=stepped-in`, routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  assert.equal(window.location.pathname + window.location.search, "/mandu/agents/s1?only=stepped-in", "the address keeps it");
  assert.equal(sw(doc).getAttribute("aria-checked"), "true");
  assert.deepEqual(shownTurns(doc), ["t:b", "t:s", "t:n"]);
  const reads = () => calls.filter((c) => c.url.startsWith("/mandu/api/home/agent?")).length;
  const before = reads();
  const entries = window.history.length;
  sw(doc).click();
  assert.equal(window.location.pathname + window.location.search, "/mandu/agents/s1");
  sw(doc).click();
  assert.equal(window.location.pathname + window.location.search, "/mandu/agents/s1?only=stepped-in");
  assert.equal(window.history.length, entries, "replaced, not pushed");
  assert.equal(reads(), before, "the switch reads nothing: the page has every turn");
  // Any other value is off.
  const other = load({ url: `${URL1}?only=yes`, routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  assert.equal(sw(other.doc).getAttribute("aria-checked"), "false");
  assert.equal(shownTurns(other.doc).length, 9);
  assert.equal(other.window.location.search, "", "an unknown value is dropped from the address");
  // Home, then a link to the session: whole.
  (doc.querySelector('#nav a[data-page-link="home"]') as El).click();
  await tick();
  window.eval(`setPage('agent', true, 's1')`);
  await tick();
  assert.equal(window.location.pathname + window.location.search, "/mandu/agents/s1");
  assert.equal(sw(doc).getAttribute("aria-checked"), "false");
  assert.equal(shownTurns(doc).length, 9);
});

test("O3: the turn an ask opened the page for never folds, even one where Mandu did nothing", async () => {
  const focus = { ask: "egr-7", turnId: "t:q5", stepId: null, match: "exact" };
  const { doc, window } = load({ url: `${URL1}?ask=egr-7&only=stepped-in`, routes: { "GET home/agent?session=s1&ask=egr-7": { ...PAGE, focus } } });
  await tick();
  assert.equal(window.location.pathname + window.location.search, "/mandu/agents/s1?ask=egr-7&only=stepped-in");
  assert.deepEqual(shownTurns(doc), ["t:b", "t:s", "t:q5", "t:n"], "the focus turn stays in sight");
  assert.deepEqual(lines(doc).map((l) => l.querySelector("span").textContent), [
    "2 turns where Mandu did nothing", "1 turn where Mandu did nothing", "1 turn where Mandu did nothing", "1 turn where Mandu did nothing",
  ], "its run splits around it");
  assert.ok(turns(doc).find((t) => t.dataset.turnId === "t:q5").classList.contains("focus"));
  assert.equal(doc.getElementById("agent-only-words").textContent, "Only where Mandu stepped in (3 of 9 turns)", "the count is of where Mandu stepped in");
});

test("O4: a poll redraw keeps the switch and the runs you opened; a focus in a turn that folds goes to its line", async () => {
  let page: unknown = PAGE;
  const { doc } = load({ url: `${URL1}?only=stepped-in`, routes: { "GET home/agent?session=s1": () => page } });
  await tick();
  lines(doc)[0].querySelector("button.quiet-toggle").click();
  assert.deepEqual(shownTurns(doc), ["t:q1", "t:q2", "t:b", "t:s", "t:n"]);
  // The agent did more: a new quiet turn; the page is drawn again.
  page = { ...PAGE, story: [...STORY, turn("t:q7")] };
  const q1 = () => turns(doc).find((t) => t.dataset.turnId === "t:q1");
  const oldQ1 = q1();
  await poll(doc);
  assert.notEqual(q1(), oldQ1, "drawn again");
  assert.equal(sw(doc).getAttribute("aria-checked"), "true", "the switch is kept");
  assert.equal(doc.getElementById("agent-only-words").textContent, "Only where Mandu stepped in (3 of 10 turns)");
  assert.deepEqual(shownTurns(doc), ["t:q1", "t:q2", "t:b", "t:s", "t:n"], "the run you opened stays open, the others folded");
  assert.equal(lines(doc).at(-1).textContent, "1 turn where Mandu did nothing Show it", "the new turn folds after the note");

  // The switch pressed with the focus in a turn it folds (a command that
  // does not move the focus): the focus goes to the line it folds into.
  sw(doc).click();
  q1().setAttribute("tabindex", "-1");
  q1().focus();
  doc.defaultView.eval("flipAgentOnly()");
  assert.equal(q1().hidden, true);
  assert.equal(doc.activeElement, lines(doc)[0].querySelector("button.quiet-toggle"), "the focus goes to the line it folded into");

  // A redraw that folds the turn holding the focus (an earlier quiet turn
  // joins its run, which is a new run, closed): its line, never the heading.
  lines(doc)[0].querySelector("button.quiet-toggle").click();
  q1().focus();
  assert.equal(doc.activeElement, q1());
  page = { ...PAGE, story: [turn("t:q0"), ...STORY, turn("t:q7")] };
  await poll(doc);
  assert.equal(q1().hidden, true, "its run starts at t:q0 now, and that one was never opened");
  assert.equal(lines(doc)[0].dataset.quietFrom, "t:q0");
  assert.equal(doc.activeElement, lines(doc)[0].querySelector("button.quiet-toggle"), "the redraw gives the focus to the line");

  // A step a link shows (a time on a Your secrets card) opens its run.
  assert.equal(q1().hidden, true);
  doc.defaultView.eval(`showStep('t:q1-a')`);
  assert.equal(q1().hidden, false);
  assert.equal(lines(doc)[0].querySelector("button.quiet-toggle").getAttribute("aria-expanded"), "true");
  assert.equal(doc.activeElement.dataset.stepId, "t:q1-a");
});

test("no story, no switch; a page not found hides it", async () => {
  const empty = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...PAGE, story: [] } } });
  await tick();
  assert.equal(empty.doc.getElementById("agent-only-row").hidden, true);
  const gone = load({ url: URL1, routes: { "GET home/agent?session=s1": { found: false } } });
  await tick();
  assert.equal(gone.doc.getElementById("agent-only-row").hidden, true);
  // Every turn where Mandu stepped in: the switch shows, and folds nothing.
  const all = load({ url: `${URL1}?only=stepped-in`, routes: { "GET home/agent?session=s1": { ...PAGE, story: [turn("t:b", "blocked"), turn("t:m", "masked"), turn("t:x", "sent")] } } });
  await tick();
  assert.equal(all.doc.getElementById("agent-only-words").textContent, "Only where Mandu stepped in (3 of 3 turns)");
  assert.equal(lines(all.doc).length, 0);
  assert.equal(shownTurns(all.doc).length, 3);
});
