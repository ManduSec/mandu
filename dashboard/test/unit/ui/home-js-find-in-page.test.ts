/**
 * home-js-find-in-page.test — dashboard.md §4.25b *Find in page opens a
 * fold*. On a session page the browser's Find (Ctrl+F) missed what the
 * page had drawn but folded: the steps past a turn's first six behind
 * "Show N more steps", and the turns *Only where Mandu stepped in* folds
 * behind "N turns where Mandu did nothing". Both were `hidden`, which takes
 * them out of find in page. Now both fold with `hidden="until-found"`, which
 * the browser still searches; on a match it fires `beforematch` at the fold
 * (bubbling) before it shows it, and the page opens the fold through its
 * button:
 *
 *   F1  a run of folded steps is `hidden="until-found"`; a `beforematch`
 *       on it leaves its button reading "Show fewer steps" with
 *       `aria-expanded="true"`; pressed, it folds back to `until-found`,
 *       never a bare `hidden`;
 *   F2  with `?only=stepped-in` a quiet run's turns are `until-found`; a
 *       `beforematch` on its second turn opens every turn of the run, and
 *       its button reads "Hide them"; a match in a folded step run inside a
 *       folded quiet turn opens both;
 *   F3  a poll that draws the page again keeps both folds open (the
 *       existing storyToggles path), and a fold folded again stays
 *       findable;
 *   F4  a time that shows a step (showStep) still opens a find-folded run
 *       and marks the step;
 *   F5  the stylesheet: the `[hidden]` rule that hides with
 *       `display: none !important` no longer matches `until-found`, and an
 *       `until-found` fold takes no room in the flow.
 *
 * jsdom fires no `beforematch` itself: the test fires it as Chromium does
 * (at the folded element, bubbling). tests/stack/story-find-in-page.test.ts
 * has a real Chromium reveal it. Drives the PRODUCT page script
 * (public/js/home.js) over the shared fetch stub (home-js-fixtures.ts).
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { JSDOM } from "jsdom";

import { AGENT, PUB, T, load, tick } from "./home-js-fixtures.js";

const URL1 = "http://127.0.0.1:4500/mandu/agents/s1";
const step = (id: string, outcome = "plain") => ({ kind: "action", id, ts: "2026-09-25T10:00:01.000Z", icon: "run", sentence: [T(`Ran ${id}`)], outcome, note: null, split: null });
const turn = (id: string, outcome = "plain", steps = 2) => ({
  ...AGENT.story[1], id, prompt: `Question ${id}`, routine: null, reply: null, moreSteps: 0, promptNote: null,
  summary: outcome === "plain" ? "Nothing here needed guarding." : `Mandu did ${outcome}.`, summaryParts: null, tone: outcome,
  steps: Array.from({ length: steps }, (_, i) => step(`${id}-${i + 1}`, i === steps - 1 ? outcome : "plain")),
});
/** A turn of 14 ordinary steps (8 fold), a block, and a run of three quiet
 *  turns, the middle one long enough to fold its own steps. */
const STORY = [turn("t:long", "plain", 14), turn("t:b", "blocked"), turn("t:q1"), turn("t:q2", "plain", 14), turn("t:q3")];
const PAGE = { ...AGENT, waiting: [], earlier: 0, story: STORY };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const turnOf = (doc: El, id: string) => [...doc.querySelectorAll("#agent-story article.turn[data-turn-id]")].find((t: El) => t.dataset.turnId === id) as El;
const stepOf = (doc: El, id: string) => [...doc.querySelectorAll("#agent-story [data-step-id]")].find((x: El) => x.dataset.stepId === id) as El;
const toggleOf = (fold: El) => fold.nextElementSibling.querySelector(".steps-toggle");
/** What the browser does on a match inside a fold: `beforematch` at the
 *  folded element, bubbling, then the attribute goes. */
function browserReveals(doc: El, fold: El): void {
  assert.equal(fold.getAttribute("hidden"), "until-found", "the browser reveals only an until-found fold");
  fold.dispatchEvent(new doc.defaultView.Event("beforematch", { bubbles: true }));
  fold.removeAttribute("hidden");
}
async function poll(doc: El): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

test("F1: a run of folded steps is hidden until found; the browser opening it sets its button as a press does, and a press folds it back findable", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  const fold = turnOf(doc, "t:long").querySelector(".steps-more");
  assert.equal(fold.getAttribute("hidden"), "until-found", "folded where Find still searches");
  assert.equal(fold.querySelectorAll(".step").length, 8, "the 8 steps past the first 6");
  assert.ok(fold.contains(stepOf(doc, "t:long-10")), "the 10th step is in it");
  const btn = toggleOf(fold);
  assert.equal(btn.textContent, "Show 8 more steps");
  assert.equal(btn.getAttribute("aria-expanded"), "false");

  browserReveals(doc, fold);
  assert.equal(fold.hasAttribute("hidden"), false, "open");
  assert.equal(btn.textContent, "Show fewer steps");
  assert.equal(btn.getAttribute("aria-expanded"), "true");

  btn.click();
  assert.equal(fold.getAttribute("hidden"), "until-found", "folded again, still findable, never a bare hidden");
  assert.equal(btn.textContent, "Show 8 more steps");
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  btn.click();
  assert.equal(fold.hasAttribute("hidden"), false, "the button opens it as before");
  assert.equal(btn.textContent, "Show fewer steps");

  // A beforematch at an open fold changes nothing (a second event, a stray one).
  fold.dispatchEvent(new doc.defaultView.Event("beforematch", { bubbles: true }));
  assert.equal(fold.hasAttribute("hidden"), false);
  assert.equal(btn.getAttribute("aria-expanded"), "true");
});

test("F2: under Only where Mandu stepped in, a quiet run is hidden until found, and a match in any of its turns opens the whole run", async () => {
  const { doc } = load({ url: `${URL1}?only=stepped-in`, routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  const run = ["t:long", "t:q1", "t:q2", "t:q3"].map((id) => turnOf(doc, id));
  for (const t of run) assert.equal(t.getAttribute("hidden"), "until-found", `${t.dataset.turnId} folded where Find still searches`);
  const lines = [...doc.querySelectorAll("#agent-story .story-quiet")] as El[];
  assert.equal(lines.length, 2);
  const btn = lines[1].querySelector(".quiet-toggle");
  assert.equal(lines[1].textContent, "3 turns where Mandu did nothing Show them");

  browserReveals(doc, turnOf(doc, "t:q2"));
  for (const id of ["t:q1", "t:q2", "t:q3"]) assert.equal(turnOf(doc, id).hasAttribute("hidden"), false, `${id} open: the run opens whole`);
  assert.equal(btn.getAttribute("aria-expanded"), "true");
  assert.equal(btn.textContent, "Hide them");
  assert.equal(turnOf(doc, "t:long").getAttribute("hidden"), "until-found", "another run stays folded");

  btn.click();
  for (const id of ["t:q1", "t:q2", "t:q3"]) assert.equal(turnOf(doc, id).getAttribute("hidden"), "until-found", `${id} folded again, still findable`);
  assert.equal(btn.textContent, "Show them");

  // A match in the folded steps of a folded quiet turn: the browser finds
  // both folds first, then fires at each, the inner first, and removes its
  // attribute; the run and the steps open.
  const inner = turnOf(doc, "t:q2").querySelector(".steps-more");
  const outer = turnOf(doc, "t:q2");
  assert.equal(inner.getAttribute("hidden"), "until-found");
  for (const fold of [inner, outer]) {
    fold.dispatchEvent(new doc.defaultView.Event("beforematch", { bubbles: true }));
    fold.removeAttribute("hidden");
  }
  assert.equal(btn.textContent, "Hide them");
  assert.equal(toggleOf(inner).textContent, "Show fewer steps");
  for (const id of ["t:q1", "t:q2", "t:q3"]) assert.equal(turnOf(doc, id).hasAttribute("hidden"), false);
});

test("F3: a poll that draws the page again keeps the folds a find opened open, and one folded again stays findable", async () => {
  let page: unknown = PAGE;
  const { doc } = load({ url: `${URL1}?only=stepped-in`, routes: { "GET home/agent?session=s1": () => page } });
  await tick();
  browserReveals(doc, turnOf(doc, "t:q1"));
  browserReveals(doc, turnOf(doc, "t:q2").querySelector(".steps-more"));
  // The agent did more: the page is drawn again.
  const old = turnOf(doc, "t:q2");
  page = { ...PAGE, story: [...STORY, turn("t:b2", "blocked")] };
  await poll(doc);
  assert.notEqual(turnOf(doc, "t:q2"), old, "drawn again");
  for (const id of ["t:q1", "t:q2", "t:q3"]) assert.equal(turnOf(doc, id).hasAttribute("hidden"), false, `${id} stays open`);
  const fold = turnOf(doc, "t:q2").querySelector(".steps-more");
  assert.equal(fold.hasAttribute("hidden"), false, "the steps a find opened stay open");
  assert.equal(toggleOf(fold).textContent, "Show fewer steps");
  assert.equal(turnOf(doc, "t:long").getAttribute("hidden"), "until-found", "the run no find opened stays folded");

  // Folded again by its button, then drawn again: still findable.
  toggleOf(fold).click();
  page = { ...PAGE, story: [...STORY, turn("t:b2", "blocked"), turn("t:b3", "blocked")] };
  await poll(doc);
  assert.equal(turnOf(doc, "t:q2").querySelector(".steps-more").getAttribute("hidden"), "until-found");
});

test("F4: a time that shows a step still opens a find-folded run and its quiet turn, and marks the step", async () => {
  const { doc, window } = load({ url: `${URL1}?only=stepped-in`, routes: { "GET home/agent?session=s1": PAGE } });
  await tick();
  assert.equal(window.eval(`showStep('t:q2-10')`), true);
  const s = stepOf(doc, "t:q2-10");
  assert.equal(turnOf(doc, "t:q2").hasAttribute("hidden"), false, "its quiet run opened");
  assert.equal(s.closest(".steps-more").hasAttribute("hidden"), false, "its fold opened");
  assert.equal(toggleOf(s.closest(".steps-more")).getAttribute("aria-expanded"), "true");
  assert.ok(s.classList.contains("shown"), "marked");
  assert.equal(doc.activeElement, s);
});

test("F5: the stylesheet hides [hidden] with display: none except an until-found fold, which takes no room", () => {
  const css = readFileSync(join(PUB, "mandu.css"), "utf8");
  const rules = [...css.replace(/\/\*[\s\S]*?\*\//g, "").matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({ sel: m[1].trim(), body: m[2] }));
  const hides = rules.filter((r) => /\[hidden/.test(r.sel) && /display:\s*none\s*!important/.test(r.body));
  assert.equal(hides.length, 1, "one global rule hides [hidden]");
  const dom = new JSDOM(`<div id="plain" hidden></div><div id="found" hidden="until-found"></div><div id="other" hidden="x"></div>`);
  const by = (id: string) => dom.window.document.getElementById(id)!;
  assert.ok(by("plain").matches(hides[0].sel), "a plain hidden still hides");
  assert.ok(by("other").matches(hides[0].sel), "any other value still hides");
  assert.ok(!by("found").matches(hides[0].sel), "until-found is left to the browser, which still searches it");
  const room = rules.find((r) => r.sel === '[hidden="until-found"]');
  assert.ok(room, "an until-found rule");
  for (const decl of [/position:\s*absolute/, /width:\s*0/, /height:\s*0/, /margin:\s*0/, /padding:\s*0/, /border:\s*0/]) {
    assert.match(room!.body, decl, "folded, it takes no room and no gap in the story");
  }
  // Nothing else in the page's stylesheets gives a fold a display.
  const app = readFileSync(join(PUB, "app.css"), "utf8");
  assert.doesNotMatch(app, /\.steps-more[^{]*\{[^}]*display/, "no display on a step fold");
});
