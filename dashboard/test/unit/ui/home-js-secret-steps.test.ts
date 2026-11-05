/**
 * home-js-secret-steps.test — dashboard.md §4.25b *A card shows its steps*.
 * A secret's card counted what happened to it ("blocked 3 attempts …"), but
 * linked one step a line; to see the others a person read every turn, and
 * *Only where Mandu stepped in* keeps every turn where Mandu masked ANY
 * secret. Now each card with steps on the page has *Show its steps*:
 *
 *   C1  the button shows only on a card with steps (`steps`), beside
 *       *Change it in Rules*; a press folds exactly the turns without its
 *       steps (each run behind one line, "2 turns where Mandu found no step
 *       of this secret", its own Show them), marks its steps (`.step.shown`),
 *       draws the line above the story ("Showing the 2 turns where Mandu
 *       found a step of …", *Show every turn*), which takes the focus, and a
 *       polite status says the same; the card's button reads *Show every
 *       turn*; the words never say a turn did not use it;
 *   C2  *Show every turn* (the line's, then the card's) puts the story back,
 *       the focus to the card's button (from the line) or staying on it;
 *       with the switch on before the press, the switch's folds come back;
 *       the switch turned on or off ends the filter too;
 *   C3  steps in turns older than the ones drawn: "1 earlier turn not shown
 *       here has one too." with Show it, which asks for every turn and comes
 *       back to the line; past what the page shows, the words alone;
 *   C4  a poll that draws the page again keeps the filter and the runs you
 *       opened; a folded turn is `hidden="until-found"`, and a match of
 *       Find in page in it opens its run (`beforematch`); a time on a card
 *       opens its run too;
 *   C5  print prints every turn: `beforeprint` opens the filter's runs and
 *       `afterprint` folds them again; the line is a control print drops;
 *       the filter is not in the address, and a new visit has none;
 *   C6  step by step (queue #244): with two or more of its steps drawn, the
 *       line has *Previous step* and *Next step*; Next goes to each drawn
 *       step in page order (opening a folded run of steps), after the last
 *       the first, Previous the other way; exactly one row is `.secret-at`;
 *       "Step 2 of 3" on the line and in the polite status; a step id the
 *       page does not draw is skipped and not counted; with one drawn step,
 *       no buttons;
 *   C7  a poll keeps the place while its step is drawn and drops it when
 *       not; *Show every turn*, another card and the switch end it;
 *   C8  *Its other sessions* (queue #250, §4.25b *A card finds its other
 *       sessions*): History searched for the card's file, else its key's
 *       name, last on the link line; none on a card with neither.
 *
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, T, load, tick } from "./home-js-fixtures.js";

const URL1 = "http://127.0.0.1:4500/mandu/agents/s1";
const step = (id: string, outcome = "plain") => ({ kind: "action", id, ts: "2026-09-25T10:00:01.000Z", icon: "run", sentence: [T(`Ran ${id}`)], outcome, note: null, split: null });
const turn = (id: string, outcome = "plain") => ({
  ...AGENT.story[1], id, prompt: `Question ${id}`, routine: null, reply: null, moreSteps: 0, promptNote: null,
  summary: outcome === "plain" ? "Nothing here needed guarding." : `Mandu did ${outcome}.`, summaryParts: null, tone: outcome,
  steps: [step(`${id}-a`), step(`${id}-b`, outcome)],
});
/** Seven turns: STRIPE_KEY is read in t2, blocked in t5 (its first step, a
 *  plain-looking one) and sent in t6; DB_PASSWORD only read in t3. */
const STORY = [turn("t1"), turn("t2", "secret"), turn("t3", "secret"), turn("t4"), turn("t5", "blocked"), turn("t6", "sent"), turn("t7")];
const STRIPE = {
  what: [T("The environment variable "), { kind: "code", text: "STRIPE_KEY" }], level: "No AI", saw: "masked",
  lines: [{ tone: "good", parts: [T("The AI got only its masked version, never the real value.")] }], file: "~/app/.env",
  steps: ["t2-b", "t5-a", "t6-b"], turns: ["t2", "t5", "t6"],
};
const DB = {
  what: [{ kind: "code", text: "DB_PASSWORD" }, T(" in "), { kind: "code", text: "~/app/db.env" }], level: "No AI", saw: "masked",
  lines: [{ tone: "good", parts: [T("The AI got only its masked version, never the real value.")] }],
  steps: ["t3-b"], turns: ["t3"],
};
const NONE = { what: [T("The file "), { kind: "code", text: "~/app/old.key" }], level: "No AI", saw: "masked", lines: [], file: "~/app/old.key" };
const secrets = (cards: unknown[]) => ({ mode: "secrets", flagged: false, more: 0, counts: { masked: cards.length, early: 0 }, secrets: cards });
const PAGE = { ...AGENT, waiting: [], earlier: 0, story: STORY, secrets: secrets([STRIPE, DB, NONE]) };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const turns = (doc: El) => [...doc.querySelectorAll("#agent-story article.turn[data-turn-id]")] as El[];
const shownTurns = (doc: El) => turns(doc).filter((t) => !t.closest("[hidden]")).map((t) => t.dataset.turnId);
const lines = (doc: El) => [...doc.querySelectorAll("#agent-story .story-quiet")] as El[];
const cards = (doc: El) => [...doc.querySelectorAll("#agent-secrets .secret-card")] as El[];
const btnOf = (doc: El, i: number) => cards(doc)[i].querySelector("button.secret-steps");
const line = (doc: El) => doc.getElementById("agent-secret-only");
const status = (doc: El) => doc.getElementById("agent-story-status");
const marked = (doc: El) => ([...doc.querySelectorAll("#agent-story .step.shown")] as El[]).map((x) => x.dataset.stepId);
const sw = (doc: El) => doc.getElementById("agent-only");
const text = (x: El) => String(x.textContent).replace(/\s+/g, " ").trim();
async function poll(doc: El): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

test("C1: Show its steps, only on a card with steps, folds the turns without them, marks its steps and draws the line that takes the focus", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  assert.equal(cards(doc).length, 3);
  assert.equal(btnOf(doc, 0).textContent, "Show its steps");
  // Beside Change it in Rules, the row's gap between them, no text (queue #247).
  assert.deepEqual(([...btnOf(doc, 0).parentElement.childNodes] as El[]).map((x) => x.textContent), ["Change it in Rules", "Show its steps", "Its other sessions"], "beside Change it in Rules (and Its other sessions after it, queue #250)");
  assert.ok(btnOf(doc, 1), "a card with no file has it on its own");
  assert.equal(btnOf(doc, 2), null, "no button on a card with no steps");
  assert.equal(doc.getElementById(btnOf(doc, 0).getAttribute("aria-describedby")).textContent, "The environment variable STRIPE_KEY", "described by its card's name");
  assert.equal(shownTurns(doc).length, 7);

  btnOf(doc, 0).click();
  assert.deepEqual(shownTurns(doc), ["t2", "t5", "t6"], "exactly the turns with its steps");
  assert.deepEqual(lines(doc).map((l) => l.querySelector("span").textContent), [
    "1 turn where Mandu found no step of this secret", "2 turns where Mandu found no step of this secret", "1 turn where Mandu found no step of this secret",
  ], "one line a run, in its place; never \"did not use\"");
  assert.deepEqual(lines(doc).map((l) => l.dataset.quietFrom), ["t1", "t3", "t7"]);
  assert.deepEqual(marked(doc), ["t2-b", "t5-a", "t6-b"], "its steps are marked");
  assert.ok(line(doc), "the line above the story");
  assert.equal(doc.getElementById("agent-story").firstElementChild, line(doc), "above the story");
  assert.equal(text(line(doc)), "Showing the 3 turns where Mandu found a step of the environment variable STRIPE_KEY. Previous step Next step Show every turn");
  assert.equal(line(doc).querySelector("code").textContent, "STRIPE_KEY", "its name as code");
  assert.equal(doc.activeElement, line(doc), "the line takes the focus");
  assert.equal(status(doc).getAttribute("role"), "status");
  assert.equal(status(doc).textContent, "Showing the 3 turns where Mandu found a step of the environment variable STRIPE_KEY.", "a polite status says the same");
  assert.equal(btnOf(doc, 0).textContent, "Show every turn", "the card's button says what a press does now");
  assert.equal(btnOf(doc, 1).textContent, "Show its steps");
  // A run's own Show them brings its turns back in place.
  const run = lines(doc)[1].querySelector("button.quiet-toggle");
  run.click();
  assert.deepEqual(shownTurns(doc), ["t2", "t3", "t4", "t5", "t6"]);
  assert.equal(run.textContent, "Hide them");

  // Another card's press moves the filter to it.
  btnOf(doc, 1).click();
  assert.deepEqual(shownTurns(doc), ["t3"]);
  assert.equal(text(line(doc)), "Showing the 1 turn where Mandu found a step of DB_PASSWORD in ~/app/db.env. Show every turn");
  assert.deepEqual(marked(doc), ["t3-b"]);
  assert.equal(btnOf(doc, 0).textContent, "Show its steps");
  assert.equal(btnOf(doc, 1).textContent, "Show every turn");
});

test("C2: Show every turn, the line's or the card's, puts the story back; with the switch on, its folds come back; the switch ends the filter", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  btnOf(doc, 0).click();
  line(doc).querySelector("button.secret-all").click();
  assert.equal(shownTurns(doc).length, 7, "every turn");
  assert.equal(lines(doc).length, 0);
  assert.equal(line(doc), null);
  assert.deepEqual(marked(doc), [], "its marks go with it");
  assert.equal(doc.activeElement, btnOf(doc, 0), "the focus goes back to the card's button");
  assert.equal(btnOf(doc, 0).textContent, "Show its steps");
  assert.equal(status(doc).textContent, "Showing every turn.");

  // The card's button, pressed again, does the same; the focus stays on it.
  btnOf(doc, 0).click();
  btnOf(doc, 0).focus();
  btnOf(doc, 0).click();
  assert.equal(shownTurns(doc).length, 7);
  assert.equal(doc.activeElement, btnOf(doc, 0));

  // With the switch on before the press: Show every turn gives its folds back.
  sw(doc).click();
  const stepped = shownTurns(doc);
  assert.deepEqual(stepped, ["t2", "t3", "t5", "t6"]);
  const quiet = lines(doc).map((l) => l.querySelector("span").textContent);
  btnOf(doc, 0).click();
  assert.deepEqual(shownTurns(doc), ["t2", "t5", "t6"], "the secret's filter takes the switch's place");
  assert.equal(sw(doc).getAttribute("aria-checked"), "true", "the switch is not changed");
  line(doc).querySelector("button.secret-all").click();
  assert.deepEqual(shownTurns(doc), stepped, "the switch's folds again");
  assert.deepEqual(lines(doc).map((l) => l.querySelector("span").textContent), quiet);
  assert.equal(status(doc).textContent, "Showing the turns where Mandu stepped in.");

  // The switch turned off (or on) ends the filter.
  btnOf(doc, 0).click();
  sw(doc).click();
  assert.equal(sw(doc).getAttribute("aria-checked"), "false");
  assert.equal(shownTurns(doc).length, 7, "off: every turn, the filter ended");
  assert.equal(line(doc), null);
  assert.equal(btnOf(doc, 0).textContent, "Show its steps");
  btnOf(doc, 0).click();
  sw(doc).click();
  assert.deepEqual(shownTurns(doc), ["t2", "t3", "t5", "t6"], "on: the switch's own folds");
  assert.equal(line(doc), null);
});

test("C3: steps in turns older than the ones drawn are said, with the earlier turns' Show them; past what the page shows, the words alone", async () => {
  let asked = 0;
  const all = { ...PAGE, earlier: 0, allTurns: true, story: [turn("t0", "blocked"), ...STORY], secrets: secrets([{ ...STRIPE, steps: ["t0-b", ...STRIPE.steps], turns: ["t0", ...STRIPE.turns] }, DB]) };
  const { doc, calls } = load({ url: URL1, routes: {
    "GET home/agent?session=s1": { ...PAGE, earlier: 1, secrets: secrets([{ ...STRIPE, steps: ["t0-b", ...STRIPE.steps], earlierTurns: 1 }, DB]) },
    "GET home/agent?session=s1&turns=all": () => { asked++; return all; },
  } });
  await tick();
  btnOf(doc, 0).click();
  assert.equal(text(line(doc)), "Showing the 3 turns where Mandu found a step of the environment variable STRIPE_KEY. 1 earlier turn not shown here has one too. Show it Previous step Next step Show every turn");
  assert.match(status(doc).textContent, /1 earlier turn not shown here has one too\.$/);
  line(doc).querySelector("button.secret-earlier-turns").click();
  await tick(40);
  assert.equal(asked, 1, "the earlier turns' read");
  assert.ok(calls.some((c) => c.url.includes("turns=all")));
  assert.deepEqual(shownTurns(doc), ["t0", "t2", "t5", "t6"], "the filter is kept, now with the earlier turn");
  assert.equal(text(line(doc)), "Showing the 4 turns where Mandu found a step of the environment variable STRIPE_KEY. Previous step Next step Show every turn");
  assert.equal(doc.activeElement, line(doc), "back to the line");

  const past = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...PAGE, earlier: 3, allTurns: true, secrets: secrets([{ ...STRIPE, earlierTurns: 2 }]) } } });
  await tick();
  btnOf(past.doc, 0).click();
  assert.equal(text(line(past.doc)), "Showing the 3 turns where Mandu found a step of the environment variable STRIPE_KEY. 2 earlier turns past what this page shows have one too. Previous step Next step Show every turn");

  const none = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...PAGE, earlier: 1, secrets: secrets([{ ...STRIPE, steps: ["t0-b"], turns: [], earlierTurns: 1 }]) } } });
  await tick();
  btnOf(none.doc, 0).click();
  assert.deepEqual(shownTurns(none.doc), [], "no drawn turn has one");
  assert.match(text(line(none.doc)), /^Mandu found no step of the environment variable STRIPE_KEY in the turns shown here\. 1 earlier turn not shown here has one too\./);
});

test("C4: a poll redraw keeps the filter and the runs you opened; a folded turn is findable, and a match or a card's time opens its run", async () => {
  let page: unknown = PAGE;
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": () => page } });
  await tick();
  btnOf(doc, 0).click();
  lines(doc)[0].querySelector("button.quiet-toggle").click();
  assert.deepEqual(shownTurns(doc), ["t1", "t2", "t5", "t6"]);
  // The agent did more: a new turn with a send of the key, and a quiet one.
  page = { ...PAGE, story: [...STORY, turn("t8", "sent"), turn("t9")], secrets: secrets([{ ...STRIPE, steps: [...STRIPE.steps, "t8-b"], turns: [...STRIPE.turns, "t8"] }, DB, NONE]) };
  const t1 = () => turns(doc).find((t) => t.dataset.turnId === "t1");
  const old = t1();
  await poll(doc);
  assert.notEqual(t1(), old, "drawn again");
  assert.deepEqual(shownTurns(doc), ["t1", "t2", "t5", "t6", "t8"], "the filter and the run you opened are kept");
  assert.equal(text(line(doc)), "Showing the 4 turns where Mandu found a step of the environment variable STRIPE_KEY. Previous step Next step Show every turn");
  assert.equal(btnOf(doc, 0).textContent, "Show every turn");
  assert.deepEqual(marked(doc), ["t2-b", "t5-a", "t6-b", "t8-b"]);

  // Find in page: a folded turn is hidden="until-found", and a match opens its run.
  const t3 = turns(doc).find((t) => t.dataset.turnId === "t3");
  assert.equal(t3.getAttribute("hidden"), "until-found");
  t3.dispatchEvent(new doc.defaultView.Event("beforematch", { bubbles: true }));
  assert.equal(t3.hidden, false);
  assert.deepEqual(shownTurns(doc), ["t1", "t2", "t3", "t4", "t5", "t6", "t8"], "its whole run opens, through its button");
  assert.equal(lines(doc)[1].querySelector("button.quiet-toggle").getAttribute("aria-expanded"), "true");

  // A time on a card opens the run its step is in; the filter's marks stay.
  const t9 = () => turns(doc).find((t) => t.dataset.turnId === "t9");
  assert.equal(t9().hidden, true);
  doc.defaultView.eval(`showStep('t9-a')`);
  assert.equal(t9().hidden, false);
  assert.equal(doc.activeElement.dataset.stepId, "t9-a");
  assert.deepEqual(marked(doc), ["t2-b", "t5-a", "t6-b", "t8-b", "t9-a"]);

  // The card is gone (or has no step now): the filter ends with it.
  page = { ...PAGE, story: [...STORY, turn("t8", "sent"), turn("t9"), turn("t10")], secrets: secrets([DB, NONE]) };
  await poll(doc);
  assert.equal(line(doc), null);
  assert.equal(shownTurns(doc).length, 10);
});

test("C5: print prints every turn and folds back after; the filter is not in the address, and a new visit has none", async () => {
  const { doc, window } = load({ url: URL1, routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  btnOf(doc, 0).click();
  assert.equal(window.location.pathname + window.location.search, "/mandu/agents/s1", "not in the address");
  const print = (kind: string) => window.dispatchEvent(new window.Event(kind));
  print("beforeprint");
  assert.equal(shownTurns(doc).length, 7, "every turn on paper");
  print("afterprint");
  assert.deepEqual(shownTurns(doc), ["t2", "t5", "t6"], "folded again after");
  assert.equal(lines(doc)[0].querySelector("button.quiet-toggle").getAttribute("aria-expanded"), "false");

  // Home, then back to the session: a new visit, every turn.
  (doc.querySelector('#nav a[data-page-link="home"]') as El).click();
  await tick();
  window.eval(`setPage('agent', true, 's1')`);
  await tick();
  assert.equal(shownTurns(doc).length, 7);
  assert.equal(line(doc), null);
  assert.equal(btnOf(doc, 0).textContent, "Show its steps");
});

/** A turn of nine plain steps: the first six drawn, the last three folded
 *  behind one Show 3 more steps (STEP_FOLD). */
const longTurn = (id: string) => ({ ...turn(id, "secret"), steps: Array.from({ length: 9 }, (_, i) => step(`${id}-${i}`)) });
/** STRIPE_KEY: a step in t2's first six, one in its folded run, one the page
 *  does not draw, and the send in t6. */
const STEPPED = [turn("t1"), longTurn("t2"), turn("t3", "secret"), turn("t4"), turn("t5"), turn("t6", "sent"), turn("t7")];
const STRIPE3 = { ...STRIPE, steps: ["t2-1", "t2-7", "gone", "t6-b"], turns: ["t2", "t6"] };
const STEP_PAGE = { ...PAGE, story: STEPPED, secrets: secrets([STRIPE3, { ...DB, steps: ["t3-b", "gone"] }, NONE]) };
const atRows = (doc: El) => ([...doc.querySelectorAll("#agent-story .secret-at")] as El[]).map((x) => x.dataset.stepId);
const where = (doc: El) => line(doc).querySelector(".secret-where");
const next = (doc: El) => line(doc).querySelector("button.secret-next");
const prev = (doc: El) => line(doc).querySelector("button.secret-prev");
const stepRow = (doc: El, id: string) => ([...doc.querySelectorAll("#agent-story [data-step-id]")] as El[]).find((x) => x.dataset.stepId === id);

test("C6: Next step and Previous step go to each of the card's drawn steps in turn, opening its fold, with one mark and 'Step 2 of 3'", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": STEP_PAGE } });
  await tick();
  btnOf(doc, 0).click();
  assert.deepEqual(shownTurns(doc), ["t2", "t6"]);
  assert.equal(text(line(doc)), "Showing the 2 turns where Mandu found a step of the environment variable STRIPE_KEY. Previous step Next step Show every turn",
    "two buttons before Show every turn, no place before the first press");
  assert.equal(where(doc).textContent, "");
  assert.ok(!next(doc).classList.contains("show-rest") && !prev(doc).classList.contains("show-rest"), "never .show-rest (goToTurn finds the earlier turns by it)");
  const fold = stepRow(doc, "t2-7").closest(".steps-more");
  assert.ok(fold && fold.hidden, "the second step is in a closed run of steps");
  assert.deepEqual(atRows(doc), []);

  next(doc).click();
  assert.deepEqual(atRows(doc), ["t2-1"], "the first drawn step");
  assert.equal(doc.activeElement, stepRow(doc, "t2-1"), "focused");
  assert.equal(where(doc).textContent, "Step 1 of 3", "the step not drawn is not counted");
  assert.equal(status(doc).textContent, "Step 1 of 3");

  next(doc).click();
  assert.deepEqual(atRows(doc), ["t2-7"], "the second, the mark moved");
  assert.equal(fold.hidden, false, "its run of steps opened");
  assert.equal(fold.nextElementSibling.querySelector(".steps-toggle").getAttribute("aria-expanded"), "true", "through its button");
  assert.equal(doc.activeElement, stepRow(doc, "t2-7"));
  assert.equal(where(doc).textContent, "Step 2 of 3");
  assert.equal(status(doc).textContent, "Step 2 of 3", "the polite status says where");
  assert.deepEqual(marked(doc), ["t2-1", "t2-7", "t6-b"], "the filter keeps every one of its marks");

  next(doc).click();
  assert.deepEqual(atRows(doc), ["t6-b"], "the step not drawn is skipped");
  assert.equal(where(doc).textContent, "Step 3 of 3");
  next(doc).click();
  assert.deepEqual(atRows(doc), ["t2-1"], "after the last, the first");
  assert.equal(where(doc).textContent, "Step 1 of 3");
  prev(doc).click();
  assert.deepEqual(atRows(doc), ["t6-b"], "Previous: before the first, the last");
  assert.equal(status(doc).textContent, "Step 3 of 3");
  prev(doc).click();
  assert.deepEqual(atRows(doc), ["t2-7"]);
  assert.equal(where(doc).textContent, "Step 2 of 3");
  assert.equal(text(line(doc)), "Showing the 2 turns where Mandu found a step of the environment variable STRIPE_KEY. Previous step Next step Step 2 of 3 Show every turn");

  // A time on a card marks its step as before; the place keeps its own mark.
  doc.defaultView.eval(`showStep('t1-a')`);
  assert.deepEqual(atRows(doc), ["t2-7"], "never on two rows");

  // Previous first, from no place: the last drawn step.
  btnOf(doc, 0).click();
  btnOf(doc, 0).click();
  assert.equal(where(doc).textContent, "", "a new press starts with no place");
  assert.deepEqual(atRows(doc), []);
  prev(doc).click();
  assert.deepEqual(atRows(doc), ["t6-b"]);
  assert.equal(where(doc).textContent, "Step 3 of 3");

  // A card with one drawn step (its other id not drawn): no buttons.
  btnOf(doc, 1).click();
  assert.equal(text(line(doc)), "Showing the 1 turn where Mandu found a step of DB_PASSWORD in ~/app/db.env. Show every turn");
  assert.equal(next(doc), null);
  assert.equal(prev(doc), null);
  assert.equal(where(doc), null);
  assert.deepEqual(atRows(doc), [], "another card's press ends the place");
});

test("C7: a poll keeps the place while its step is drawn and drops it when not; Show every turn, another card and the switch end it", async () => {
  let page: unknown = STEP_PAGE;
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": () => page } });
  await tick();
  btnOf(doc, 0).click();
  next(doc).click();
  next(doc).click();
  const old = stepRow(doc, "t2-7");
  // The agent did more: a new turn with another send of the key.
  page = { ...STEP_PAGE, story: [...STEPPED, turn("t8", "sent")], secrets: secrets([{ ...STRIPE3, steps: [...STRIPE3.steps, "t8-b"], turns: [...STRIPE3.turns, "t8"] }, DB, NONE]) };
  await poll(doc);
  assert.notEqual(stepRow(doc, "t2-7"), old, "drawn again");
  assert.deepEqual(atRows(doc), ["t2-7"], "the place is kept");
  assert.equal(where(doc).textContent, "Step 2 of 4", "the count grows with the steps drawn");
  assert.equal(stepRow(doc, "t2-7").closest(".steps-more").hidden, false, "its run of steps stays open");
  next(doc).click();
  assert.deepEqual(atRows(doc), ["t6-b"], "and goes on from there");
  assert.equal(where(doc).textContent, "Step 3 of 4");

  // Its step is no longer drawn (the turn is gone from the page): no place.
  page = { ...STEP_PAGE, story: STEPPED.filter((t) => t.id !== "t6"), secrets: secrets([{ ...STRIPE3, turns: ["t2"] }, DB, NONE]) };
  await poll(doc);
  assert.deepEqual(atRows(doc), []);
  assert.equal(where(doc).textContent, "", "no place said");
  assert.equal(status(doc).textContent, "Step 3 of 4", "the status is not spoken again on a poll");
  next(doc).click();
  assert.equal(where(doc).textContent, "Step 1 of 2", "Next starts again from the first");
  page = { ...STEP_PAGE, story: STEPPED.filter((t) => t.id !== "t2"), secrets: secrets([{ ...STRIPE3, turns: ["t6"] }, DB, NONE]) };
  await poll(doc);
  assert.deepEqual(atRows(doc), [], "its step gone: no mark");
  assert.equal(next(doc), null, "one drawn step left: no buttons");
  page = STEP_PAGE;
  await poll(doc);
  assert.deepEqual(atRows(doc), [], "the place stays dropped when the step comes back");
  assert.equal(where(doc).textContent, "");

  // Show every turn ends it; so does the switch; another card's press too.
  next(doc).click();
  assert.deepEqual(atRows(doc), ["t2-1"]);
  line(doc).querySelector("button.secret-all").click();
  assert.deepEqual(atRows(doc), [], "Show every turn: no mark");
  btnOf(doc, 0).click();
  assert.equal(where(doc).textContent, "", "nor a place");
  next(doc).click();
  sw(doc).click();
  assert.deepEqual(atRows(doc), [], "the switch: no mark");
  assert.equal(line(doc), null);
  btnOf(doc, 0).click();
  assert.equal(where(doc).textContent, "");
  next(doc).click();
  btnOf(doc, 1).click();
  assert.deepEqual(atRows(doc), [], "another card: no mark");
  btnOf(doc, 0).click();
  assert.equal(where(doc).textContent, "");
});

// ── dashboard.md §4.25b *A card finds its other sessions* (queue #250) ──────────
test("C8: Its other sessions: a card with a file searches History for it, one with a key but no file for the key, one with neither has none", async () => {
  const KEY = { what: [T("The environment variable "), { kind: "code", text: "GITHUB_TOKEN" }], level: "No AI", saw: "masked", lines: [], key: "GITHUB_TOKEN" };
  const OUTPUT = { what: [T("Output of a "), { kind: "code", text: "Bash" }, T(" step that held a secret")], level: "No AI", saw: "masked", lines: [], steps: ["t4-a"], turns: ["t4"] };
  const page = { ...PAGE, secrets: secrets([STRIPE, KEY, OUTPUT, NONE]) };
  const { doc, window, calls } = load({ url: URL1, routes: { "GET home/agent?session=s1": page,
    "GET home/history?q=~%2Fapp%2F.env": { total: 0, rows: [], next: null, query: { text: "~/app/.env", all: 1 } } } });
  await tick();
  const linkOf = (i: number) => cards(doc)[i].querySelector("a.secret-sessions-link");
  const a = linkOf(0);
  assert.ok(a, "a card with a file has it");
  assert.equal(a.textContent, "Its other sessions");
  assert.equal(a.getAttribute("href"), "/mandu/history?q=" + encodeURIComponent("~/app/.env"), "its file, as the card names it");
  assert.equal(a.getAttribute("data-land"), "q:~/app/.env");
  assert.equal(a.getAttribute("aria-label"), "Its other sessions: ~/app/.env");
  assert.deepEqual(([...a.parentElement.childNodes] as El[]).map((x) => x.textContent), ["Change it in Rules", "Show its steps", "Its other sessions"], "last on the card's link line");
  const k = linkOf(1);
  assert.ok(k, "a key with no file is searched by its name");
  assert.equal(k.getAttribute("href"), "/mandu/history?q=GITHUB_TOKEN");
  assert.equal(k.getAttribute("aria-label"), "Its other sessions: GITHUB_TOKEN");
  assert.equal(linkOf(2), null, "a step's output: no link");
  assert.ok(cards(doc)[2].querySelector("button.secret-steps"), "its other control stays");
  assert.equal(linkOf(3).getAttribute("href"), "/mandu/history?q=" + encodeURIComponent("~/app/old.key"), "a whole file's card");
  // A click opens History searched; the page's text never holds a value.
  a.click();
  await tick();
  assert.equal(window.location.pathname + window.location.search, "/mandu/history?q=" + encodeURIComponent("~/app/.env"));
  assert.equal(doc.getElementById("history-q").value, "~/app/.env");
  assert.ok(calls.some((c: any) => c.url === "/mandu/api/home/history?q=~%2Fapp%2F.env"), calls.map((c: any) => c.url).join(" "));
});
