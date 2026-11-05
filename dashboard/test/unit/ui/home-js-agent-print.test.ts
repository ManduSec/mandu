/**
 * home-js-agent-print.test — dashboard.md §4.25b *A printed session is
 * whole*. A print of a session page (Ctrl+P, Save as PDF) was the screen as
 * it was: the steps past a turn's first 6 were left out, a long reply
 * printed its first 10 lines under the fade, and a question past 360
 * characters its first 360 and "…". Now the browser's `beforeprint` opens
 * them and `afterprint` puts them back:
 *
 *   P1  a 12-step turn, a 900-character question, a ~4,000-character reply
 *       and a setup step's file list: `beforeprint` shows the 7th to 12th
 *       steps, the whole question and the whole reply, and opens the list,
 *       each with its button's words and `aria-expanded`; `afterprint`
 *       puts each back; nothing is asked of the server, no reveal;
 *   P2  a run you opened before stays open after; with *Only where Mandu
 *       stepped in* on, a folded quiet turn and the folded steps in it are
 *       not opened;
 *   P3  a poll while printing draws nothing (a redraw would undo the
 *       opening); after the print the page reads again and draws what
 *       came, folded as you left it;
 *   P4  the stylesheet's print rules: the top bar, the controls and the
 *       Newer/Older links to other sessions go (#293), a count tile and a
 *       step's time stay, a folded reply prints whole,
 *       links print as words, a step is not split across pages.
 *
 * jsdom prints nothing and fires neither event: the test fires them at the
 * window as the browser does. jsdom lays out nothing either: fake-resize.ts
 * gives the page a ResizeObserver, and a reply text's `scrollHeight` is
 * stubbed from its length (home-js-reply-fold.test.ts does the same).
 * tests/stack/agent-page-print.test.ts prints a real page to PDF. Drives
 * the PRODUCT page script (public/js/home.js) over the shared fetch stub
 * (home-js-fixtures.ts).
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { AGENT, PUB, T, load, tick } from "./home-js-fixtures.js";
import { fakeResize } from "./fake-resize.js";

const URL1 = "http://127.0.0.1:4500/mandu/agents/s1";
const step = (id: string, outcome = "plain") => ({ kind: "action", id, ts: "2026-09-25T10:00:01.000Z", icon: "run", sentence: [T(`Ran ${id}`)], outcome, note: null, split: null });
const steps = (id: string, count: number, last = "plain") => Array.from({ length: count }, (_, i) => step(`${id}-${i + 1}`, i === count - 1 ? last : "plain"));
const turn = (id: string, outcome = "plain", over: Record<string, unknown> = {}) => ({
  ...AGENT.story[1], id, prompt: `Question ${id}`, routine: null, reply: null, moreSteps: 0, promptNote: null,
  summary: outcome === "plain" ? "Nothing here needed guarding." : `Mandu did ${outcome}.`, summaryParts: null, tone: outcome,
  steps: steps(id, 2, outcome), ...over,
});
/** A 900-character question; only its end says "end of the question". */
const PROMPT = "Please look at the parser. ".repeat(32).slice(0, 875) + "end of the question here.";
/** A ~4,000-character reply; its last line only says the marker. */
const REPLY = Array.from({ length: 60 }, (_, i) => `- step ${i + 1}: edited src/module-${i}.ts and its tests`).join("\n") + "\n- Last: the reply's last line.";
const SETUP = { kind: "setup", id: "setup-1", files: ["/home/u/ws/.env", "/home/u/ws/config/db.yaml"] };
/** The long turn (a question past the clip, 12 ordinary steps, a long
 *  reply), a blocked turn opening with a setup step, and a quiet run whose
 *  second turn has 12 steps of its own. */
function story(extra = 0) {
  const out = [
    turn("t:long", "secret", { prompt: PROMPT, promptParts: null, steps: steps("t:long", 12), reply: { ts: "2026-09-25T10:01:09.000Z", parts: [T(REPLY)], ai: null } }),
    turn("t:b", "blocked", { steps: [SETUP, step("t:b-1", "blocked")] }),
    turn("t:q1"), turn("t:q2", "plain", { steps: steps("t:q2", 12) }), turn("t:q3"),
  ];
  for (let i = 0; i < extra; i++) out.push(turn(`t:more${i}`, "blocked"));
  return out;
}
const PAGE = { ...AGENT, waiting: [], earlier: 0, story: story() };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
/** The page with reply heights: a text over 1000 characters is 2000 px
 *  tall, a shorter one 60 px; `fit()` measures them as a browser does once
 *  they are laid out. */
function open(url: string, read: () => unknown) {
  const sizes = fakeResize();
  const page = load({ url, routes: { "GET home/agent?session=s1": () => read() }, before: (w: El) => {
    sizes.install(w);
    Object.defineProperty(w.HTMLElement.prototype, "scrollHeight", {
      configurable: true,
      get(this: El) { return this.classList.contains("reply-text") ? (this.textContent.length > 1000 ? 2000 : 60) : 0; },
    });
    w.scrollBy = () => {};
  } });
  const fit = () => { for (const t of page.doc.querySelectorAll("#agent-story .reply-text")) sizes.resized(t); };
  return { ...page, fit };
}
const turnOf = (doc: El, id: string) => [...doc.querySelectorAll("#agent-story article.turn[data-turn-id]")].find((t: El) => t.dataset.turnId === id) as El;
const stepOf = (doc: El, id: string) => [...doc.querySelectorAll("#agent-story [data-step-id]")].find((x: El) => x.dataset.stepId === id) as El;
const toggleOf = (fold: El) => fold.nextElementSibling.querySelector(".steps-toggle");
const shown = (x: El) => !x.closest("[hidden]");
const print = (doc: El, kind: "beforeprint" | "afterprint") => doc.defaultView.dispatchEvent(new doc.defaultView.Event(kind));
async function poll(doc: El): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}
/** Everything a print opens in turn `id`, as drawn now. */
function state(doc: El, id: string) {
  const t = turnOf(doc, id);
  const fold = t.querySelector(".steps-more");
  const q = t.querySelector(".turn-q .q-text");
  const all = q.querySelector("button.linkish");
  const reply = t.querySelector(".reply-text");
  const replyBtn = t.querySelector("button.reply-fold");
  return {
    fold: fold.getAttribute("hidden"), steps: toggleOf(fold).textContent, stepsOpen: toggleOf(fold).getAttribute("aria-expanded"),
    question: q.textContent.includes("end of the question here."), all: all.textContent, allOpen: all.getAttribute("aria-expanded"),
    reply: reply.classList.contains("folded"), replyWords: replyBtn.textContent, replyOpen: replyBtn.getAttribute("aria-expanded"),
  };
}
const FOLDED = {
  fold: "until-found", steps: "Show 6 more steps", stepsOpen: "false", question: false, all: "Show all", allOpen: "false",
  reply: true, replyWords: "Show the whole reply", replyOpen: "false",
};

test("P1: beforeprint shows the folded steps, the whole question, the whole reply and the file list; afterprint puts each back; nothing is asked of the server", async () => {
  const { doc, err, fit, calls } = open(URL1, () => PAGE);
  assert.equal(err, null);
  await tick(40);
  fit();
  assert.deepEqual(state(doc, "t:long"), FOLDED, "drawn folded");
  assert.ok(!shown(stepOf(doc, "t:long-7")), "the 7th step is folded away");
  assert.match(turnOf(doc, "t:long").querySelector(".q-text").textContent, /…/, "the question is cut");
  const files = turnOf(doc, "t:b").querySelector("details.files");
  assert.equal(files.open, false);
  const asked = calls.length;

  print(doc, "beforeprint");
  assert.deepEqual(state(doc, "t:long"), {
    fold: null, steps: "Show fewer steps", stepsOpen: "true", question: true, all: "Show less", allOpen: "true",
    reply: false, replyWords: "Show less", replyOpen: "true",
  }, "everything opened for the print");
  for (let i = 7; i <= 12; i++) assert.ok(shown(stepOf(doc, `t:long-${i}`)), `step ${i} shows`);
  assert.ok(turnOf(doc, "t:long").querySelector(".reply-text").textContent.trimEnd().endsWith("Last: the reply's last line."), "the reply's last line");
  assert.equal(files.open, true, "the file list opens");
  // A browser fires it once a print, but a second one changes nothing.
  print(doc, "beforeprint");
  assert.equal(state(doc, "t:long").stepsOpen, "true");

  print(doc, "afterprint");
  assert.deepEqual(state(doc, "t:long"), FOLDED, "afterprint puts each back");
  assert.equal(files.open, false, "the file list folds back");
  fit();
  assert.ok(turnOf(doc, "t:long").querySelector(".reply-text").classList.contains("folded"), "a new measure keeps the reply folded");
  assert.deepEqual(calls.slice(asked).map((c) => `${c.method} ${c.url}`), [], "nothing asked of the server: no reveal, no read");
  // A value hidden on screen stays hidden: Show what was hidden is not pressed.
  print(doc, "beforeprint");
  for (const b of doc.querySelectorAll("#agent-story button.reveal")) assert.equal(b.getAttribute("aria-expanded"), "false", "no reveal opened");
  for (const pre of doc.querySelectorAll("#agent-story pre.hidden-text")) assert.equal(pre.hidden, true, "a hidden original stays hidden");
  print(doc, "afterprint");
});

test("P2: a run you opened stays open after the print, and the turns Only where Mandu stepped in folds are not opened", async () => {
  const { doc, fit } = open(URL1, () => PAGE);
  await tick(40);
  fit();
  const fold = turnOf(doc, "t:long").querySelector(".steps-more");
  toggleOf(fold).click();
  assert.equal(toggleOf(fold).getAttribute("aria-expanded"), "true", "you opened it");
  print(doc, "beforeprint");
  print(doc, "afterprint");
  assert.equal(fold.getAttribute("hidden"), null, "it stays open");
  assert.equal(toggleOf(fold).textContent, "Show fewer steps");
  assert.equal(state(doc, "t:long").reply, true, "what the print opened alone folds back");

  const f = open(URL1 + "?only=stepped-in", () => PAGE);
  await tick(40);
  f.fit();
  const quiet = turnOf(f.doc, "t:q2");
  const line = f.doc.querySelector("#agent-story .story-quiet");
  assert.ok(line && quiet.hidden, "the quiet run is folded behind its line");
  const inner = quiet.querySelector(".steps-more");
  print(f.doc, "beforeprint");
  assert.ok(quiet.hidden, "a folded quiet turn is not opened");
  assert.equal(line.querySelector(".quiet-toggle").getAttribute("aria-expanded"), "false");
  assert.equal(inner.getAttribute("hidden"), "until-found", "nor the folded steps in it");
  assert.equal(toggleOf(inner).getAttribute("aria-expanded"), "false");
  assert.equal(state(f.doc, "t:long").stepsOpen, "true", "a turn the switch shows opens");
  print(f.doc, "afterprint");
  assert.ok(quiet.hidden);
  assert.deepEqual(state(f.doc, "t:long"), FOLDED);
});

test("P3: a poll while printing draws nothing; after the print the page reads again and draws what came", async () => {
  let extra = 0;
  const { doc, fit, calls } = open(URL1, () => ({ ...PAGE, story: story(extra) }));
  await tick(40);
  fit();
  print(doc, "beforeprint");
  extra = 1;
  await poll(doc);
  assert.ok(calls.some((c) => c.url.includes("home/agent")), "the poll reads");
  assert.equal(turnOf(doc, "t:more0"), undefined, "but draws nothing while printing");
  assert.equal(state(doc, "t:long").stepsOpen, "true", "so the print keeps what it opened");
  const reads = calls.filter((c) => c.url.includes("home/agent")).length;
  print(doc, "afterprint");
  await tick(40);
  assert.equal(calls.filter((c) => c.url.includes("home/agent")).length, reads + 1, "after the print it reads again");
  assert.ok(turnOf(doc, "t:more0"), "and draws what came");
  fit();
  assert.deepEqual(state(doc, "t:long"), FOLDED, "folded as you left it");
  // A print with nothing skipped asks nothing.
  print(doc, "beforeprint");
  print(doc, "afterprint");
  await tick(40);
  assert.equal(calls.filter((c) => c.url.includes("home/agent")).length, reads + 1);
});

test("P4: the stylesheet's print rules drop the top bar, the controls and the Newer/Older links, keep tiles and times, print a folded reply whole and keep a step on one page", () => {
  const css = readFileSync(join(PUB, "app.css"), "utf8");
  const at = css.indexOf("@media print {");
  assert.ok(at >= 0, "app.css has print styles");
  // The block, to its closing brace at the start of a line.
  const block = css.slice(at, css.indexOf("\n}", at));
  const rule = (re: RegExp) => { const m = re.exec(block); assert.ok(m, `a rule ${re}`); return m![0]; };
  const gone = rule(/#top,[^{]*\{ display: none !important; \}/);
  for (const sel of ["#top", "#as-public", "#page-agent .back", "#agent-trace", "#agent-only-row", "#page-agent .help", "#page-agent button:not(.tile):not(.step-link)", "#page-agent .reply-fold-row", "#page-agent .toggle-row", "#page-agent details.files > summary", "#agent-neighbours"]) {
    assert.ok(gone.includes(sel), `${sel} is left out of the print`);
  }
  assert.match(rule(/#page-agent \.reply-text\.folded \{[^}]*\}/), /max-height: none;.*mask-image: none;/, "a folded reply prints whole, without the fade");
  assert.match(rule(/#page-agent a \{[^}]*\}/), /color: inherit; text-decoration: none;/, "links print as their words");
  assert.match(rule(/#page-agent \.step,[^{]*\{ break-inside: avoid; \}/), /#page-agent \.turn-head/, "a step and a turn's head stay on one page");
});
