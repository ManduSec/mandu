/**
 * home-js-latest-turn.test — dashboard.md §4.25ad *Latest turn takes you to
 * the newest turn*. The session page draws its turns oldest first, so what
 * the agent is doing now is the last card of a page up to 60 turns long,
 * and nothing on the page took you there. A link beside the *Only where
 * Mandu stepped in* switch does:
 *
 *   L1  hidden at 0, 1 and 2 turns drawn (the earlier turns the page does
 *       not draw do not count), shown at 3; its words name the newest
 *       turn's time as its card says it, and its name has no arrow; a page
 *       not found hides it;
 *   L2  pressed, the newest turn takes the focus (tabindex -1, not a Tab
 *       stop) and is scrolled to; the page never goes there by itself;
 *   L3  with the switch on and the newest turn folded into a quiet line,
 *       the line's Show it / Show them button takes the focus, never the
 *       hidden card; with that run opened, the card does;
 *   L4  a poll redraw with one more turn rewrites its time, keeps the same
 *       button and leaves the focus on it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, T, load, tick } from "./home-js-fixtures.js";

const URL1 = "http://127.0.0.1:4500/mandu/agents/s1";
const step = (id: string, outcome = "plain") => ({ kind: "action", id, ts: "2026-09-25T10:00:01.000Z", icon: "run", sentence: [T(`Ran ${id}`)], outcome, note: null, split: null });
/** Turn `id` at minute `min` past 10:00 UTC, quiet unless `outcome`. */
const turn = (id: string, min: number, outcome = "plain") => ({
  ...AGENT.story[1], id, ts: `2026-09-25T10:${String(min).padStart(2, "0")}:00.000Z`, prompt: `Question ${id}`, routine: null, reply: null, moreSteps: 0, promptNote: null,
  summary: outcome === "plain" ? "Nothing here needed guarding." : `Mandu did ${outcome}.`, summaryParts: null, tone: outcome,
  steps: [step(`${id}-a`, outcome)],
});
const page = (story: unknown[], over: Record<string, unknown> = {}) => ({ ...AGENT, waiting: [], earlier: 0, story, ...over });

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const latest = (doc: El) => doc.getElementById("agent-latest");
const turns = (doc: El) => [...doc.querySelectorAll("#agent-story article.turn[data-turn-id]")] as El[];
/** The time words the card of the newest turn shows. */
const lastTime = (doc: El) => turns(doc).at(-1).querySelector(".turn-head > time.time").textContent;
/** A button's accessible name as text: what is not aria-hidden. */
const nameOf = (x: El) => [...x.childNodes].filter((c: El) => !(c.getAttribute && c.getAttribute("aria-hidden") === "true")).map((c: El) => c.textContent).join("").trim();
async function poll(doc: El): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

test("L1: hidden at 0, 1 and 2 turns drawn, shown at 3 beside the switch, naming the newest turn's time; a page not found hides it", async () => {
  for (const k of [0, 1, 2]) {
    const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": page([turn("t:a", 1), turn("t:b", 2)].slice(0, k), { earlier: 40 }) } });
    await tick();
    assert.equal(turns(doc).length, k);
    assert.equal(latest(doc).hidden, true, `hidden at ${k} turns, 40 earlier ones not drawn`);
  }
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": page([turn("t:a", 1), turn("t:b", 2), turn("t:c", 31, "blocked")]) } });
  await tick();
  const b = latest(doc);
  assert.equal(b.hidden, false, "shown at 3");
  assert.equal(b.tagName, "BUTTON");
  assert.equal(b.type, "button");
  assert.equal(b.closest(".story-head"), doc.getElementById("agent-only-row").parentElement, "in the story head, beside the switch");
  assert.equal(b.previousElementSibling, doc.getElementById("agent-only-row"));
  assert.ok(lastTime(doc).length > 0, "the newest card shows a time");
  assert.equal(b.textContent, `Latest turn, ${lastTime(doc)} ↓`, "the card's own time words");
  assert.equal(nameOf(b), `Latest turn, ${lastTime(doc)}`, "its name says the same without the arrow");
  assert.equal(b.getAttribute("aria-label"), null, "named by its words");
  assert.equal(doc.defaultView.scrollY, 0, "opening the page does not go there");

  // A newest turn with no time: the words alone.
  const untimed = load({ url: URL1, routes: { "GET home/agent?session=s1": page([turn("t:a", 1), turn("t:b", 2), { ...turn("t:c", 3), ts: null }]) } });
  await tick();
  assert.equal(nameOf(latest(untimed.doc)), "Latest turn");

  // A page not found, and no story: hidden.
  const gone = load({ url: URL1, routes: { "GET home/agent?session=s1": { found: false } } });
  await tick();
  assert.equal(latest(gone.doc).hidden, true);
});

test("L2: pressed, the newest turn takes the focus and is scrolled to its top", async () => {
  const { doc, window } = load({ url: URL1, routes: { "GET home/agent?session=s1": page([turn("t:a", 1), turn("t:b", 2), turn("t:c", 3), turn("t:d", 4)]) } });
  await tick();
  const scrolled: Array<{ id: string; opts: unknown }> = [];
  window.HTMLElement.prototype.scrollIntoView = function (this: El, opts: unknown) { scrolled.push({ id: this.dataset.turnId ?? this.className, opts: JSON.parse(JSON.stringify(opts)) }); };
  latest(doc).focus();
  latest(doc).click();
  const last = turns(doc).at(-1);
  assert.equal(last.dataset.turnId, "t:d");
  assert.equal(doc.activeElement, last, "the newest turn has the focus");
  assert.equal(last.getAttribute("tabindex"), "-1", "a card, not a Tab stop");
  assert.deepEqual(scrolled, [{ id: "t:d", opts: { block: "start" } }], "scrolled to its top");
});

test("L3: with the switch on and the newest turn folded, its line's button takes the focus; with the run opened, the card", async () => {
  const { doc, window } = load({ url: `${URL1}?only=stepped-in`, routes: { "GET home/agent?session=s1": page([turn("t:a", 1), turn("t:b", 2, "blocked"), turn("t:c", 3), turn("t:d", 4)]) } });
  await tick();
  window.HTMLElement.prototype.scrollIntoView = function () {};
  const last = turns(doc).at(-1);
  assert.equal(last.hidden, true, "the newest turn is folded");
  const line = [...doc.querySelectorAll("#agent-story .story-quiet")].at(-1) as El;
  const btn = line.querySelector("button.quiet-toggle");
  assert.equal(btn.textContent, "Show them");
  assert.equal(nameOf(latest(doc)), `Latest turn, ${lastTime(doc)}`, "named by the newest turn, folded or not");
  latest(doc).click();
  assert.equal(doc.activeElement, btn, "the line's Show them, never the hidden card");
  assert.equal(last.hidden, true, "nothing opened by itself");
  btn.click();
  assert.equal(last.hidden, false);
  latest(doc).click();
  assert.equal(doc.activeElement, last, "the run opened: the card itself");
});

test("L4: a poll redraw with one more turn rewrites the time on the same button and leaves the focus on it", async () => {
  let story = [turn("t:a", 1), turn("t:b", 2), turn("t:c", 3)];
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": () => page(story) } });
  await tick();
  const b = latest(doc);
  const before = lastTime(doc);
  b.focus();
  story = [...story, turn("t:d", 47)];
  await poll(doc);
  assert.equal(turns(doc).length, 4, "drawn again");
  assert.notEqual(lastTime(doc), before, "the newest turn has another time");
  assert.equal(latest(doc), b, "the same button");
  assert.equal(nameOf(b), `Latest turn, ${lastTime(doc)}`, "its words follow the newest turn");
  assert.equal(doc.activeElement, b, "the focus stays where it was");
  assert.equal(doc.defaultView.scrollY, 0, "the page did not move");
});
