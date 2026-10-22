/**
 * home-js-agent-back-place.test — Back and Forward to a session's page
 * return to where you left it, with the replies and steps you had opened
 * (public/js/home.js `savePlace`, `agentPlace`, `agentLandPlace`;
 * dashboard.md §4.25 *Back and Forward keep your place*).
 *
 * Until 2026-10-21 the session page was not one of the place pages: a Back
 * from Rules (a secret's "Change it in Rules", "Change it under Rules", a
 * step's "… in Approvals") started it again at its top, every fold you had
 * opened closed and the turns Show them had brought gone. Now:
 *
 *   A1  a push saves the turn you were reading, its height on the screen,
 *       the toggles and what Show them asked for in the entry left; Back
 *       opens the reply and the steps fold again, scrolls the turn back to
 *       its height and gives it the focus; Forward then Back does it again;
 *   A2  a link to the session (Home's row) opens it fresh: at its top,
 *       folded, the focus on its heading;
 *   A3  Show them (earlier turns) pressed before leaving is asked for again
 *       by the first read after Back (`turns=all`);
 *   A4  the oldest turn dropped off the top (a running session past its
 *       cap): the turn you were reading is still where it was on the
 *       screen; the turn gone: the saved `y`;
 *   A5  a scroll while the read is out is yours, and stays;
 *   A6  a toggle pressed just before the browser's own Back (which saves
 *       nothing on its way out) is kept for Forward;
 *   A7  a session's page opened at an ask's moment (`?ask=`) is a link: its
 *       Back starts at the top, as before.
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts).
 * jsdom lays out nothing: each turn is given a box 460 px tall, one under
 * the other from 300 px down the page, and the place is read as the page's
 * scrollTo calls. The real browser is tests/stack/agent-back-restores.test.ts.
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, home, load, tick } from "./home-js-fixtures.js";
import { waitWhile } from "../page-wait.js";

const BASE = "http://127.0.0.1:4500/mandu";
const PAGE_URL = BASE + "/agents/s1";
const TOP = 300;
const TALL = 460;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const LONG = Array.from({ length: 40 }, (_, i) => `- step ${i + 1}: edited src/module-${i}.ts and its tests`).join("\n");
/** A turn with 8 steps (5 shown, a fold of 3) and a long reply. */
const turn = (i: number) => ({
  ...AGENT.story[1], id: `turn:t${i}`, prompt: `Question ${i}`, routine: null,
  reply: { ts: "2026-09-25T10:01:09.000Z", parts: [{ kind: "text", text: LONG }], ai: null },
});
const page = (ids: number[], over: Record<string, unknown> = {}) => ({ ...AGENT, waiting: [], earlier: 0, story: ids.map(turn), ...over });
const FIVE = page([0, 1, 2, 3, 4]);

/** The page with a layout: each drawn turn of the story a box TALL high,
 *  the first TOP down the page; scrollTo moves scrollY and is recorded. */
function open(read: () => unknown, url = PAGE_URL, routes: Record<string, unknown> = {}) {
  const loaded = load({ url, homeVm: home(), routes: { "GET home/agent?session=s1": () => read(), ...routes }, before: (w: Doc) => {
    const zero = { top: 0, bottom: 0, left: 0, right: 0, width: 0, height: 0, x: 0, y: 0 };
    w.HTMLElement.prototype.getBoundingClientRect = function (this: Doc) {
      if (!this.matches("#agent-story article.turn[data-turn-id]")) return zero;
      const i = [...this.ownerDocument.querySelectorAll("#agent-story article.turn[data-turn-id]")].indexOf(this);
      const top = TOP + i * TALL - (w.scrollY || 0);
      return { ...zero, top, bottom: top + TALL, height: TALL, y: top };
    };
  } });
  const to: number[] = [];
  Object.defineProperty(loaded.window, "scrollY", { value: 0, writable: true, configurable: true });
  loaded.window.scrollTo = (_x: number, y: number) => { to.push(y); loaded.window.scrollY = y; };
  return { ...loaded, to };
}
const turns = (doc: Doc) => [...doc.querySelectorAll("#agent-story article.turn[data-turn-id]")] as Doc[];
const turnOf = (doc: Doc, id: string) => turns(doc).find((t) => t.dataset.turnId === id);
const expanded = (x: Doc) => x.getAttribute("aria-expanded");
const replyOf = (doc: Doc, id: string) => turnOf(doc, id).querySelector(".reply-fold");
const foldOf = (doc: Doc, id: string) => turnOf(doc, id).querySelector(".steps-toggle");
const heading = (doc: Doc) => doc.querySelector("#page-agent h1");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function traverse(window: any, way: "back" | "forward") {
  const from = window.location.pathname + window.location.search;
  window.history[way]();
  await waitWhile(() => window.location.pathname + window.location.search === from);
  await tick();
}
async function press(link: Doc) {
  assert.ok(link, "the link is there");
  link.focus();
  link.click();
  await tick();
}
/** Two animation frames and a bit: the page lands again once replies fold. */
const frames = () => new Promise((r) => setTimeout(r, 80));
const agentReads = (calls: { url: string }[]) => calls.filter((c) => c.url.startsWith("/mandu/api/home/agent?")).map((c) => c.url.slice("/mandu/api/".length));
const rulesLink = (doc: Doc) => doc.querySelector('#nav [data-page-link="rules"]');

/** Opens turn 1's reply and steps fold, scrolls turn 2 to 100 px above the
 *  screen's top (y 1320), and leaves for Rules by a link. */
async function readAndLeave(p: ReturnType<typeof open>) {
  const { doc, window } = p;
  await tick();
  replyOf(doc, "turn:t1").click();
  foldOf(doc, "turn:t1").click();
  window.scrollTo(0, TOP + 2 * TALL + 100);
  await press(rulesLink(doc));
  assert.equal(doc.getElementById("page-rules").hidden, false, "Rules is shown");
}

test("A1: Back puts the reply and the steps you opened back open, the turn you were reading at its height, the focus on it; Forward then Back again does it again", async () => {
  const p = open(() => FIVE);
  const { doc, window } = p;
  await tick();
  const saved: Doc[] = [];
  const replace = window.history.replaceState.bind(window.history);
  window.history.replaceState = (state: unknown, ...rest: unknown[]) => { saved.push(state); return replace(state, ...rest); };
  await readAndLeave(p);
  window.history.replaceState = replace;
  const place = JSON.parse(JSON.stringify(saved[0].place));
  assert.equal(place.y, 1320);
  assert.equal(place.turn, "turn:t2", "the first turn whose foot is on the screen");
  assert.equal(place.top, -100, "and how far up the screen its top was");
  assert.deepEqual(place.show, { turns: false, secrets: false, steps: [], background: [] }, "what Show them asked: nothing");
  const open1 = place.story.toggles.filter((x: Doc) => x.open);
  assert.deepEqual(open1, [{ turn: "turn:t1", kind: "fold", i: 0, open: true }, { turn: "turn:t1", kind: "reply", i: 0, open: true }], "the two toggles opened");

  for (const round of [1, 2]) {
    const mark = p.to.length;
    await traverse(window, "back");
    assert.equal(window.location.pathname, "/mandu/agents/s1");
    await waitWhile(() => doc.activeElement !== turnOf(doc, "turn:t2"));
    await frames();
    assert.equal(expanded(replyOf(doc, "turn:t1")), "true", `round ${round}: the reply you unfolded is unfolded`);
    assert.equal(replyOf(doc, "turn:t1").textContent, "Show less");
    assert.equal(expanded(foldOf(doc, "turn:t1")), "true", "the steps you opened are open");
    assert.equal(expanded(replyOf(doc, "turn:t0")), "false", "the rest stay folded");
    assert.equal(expanded(foldOf(doc, "turn:t3")), "false");
    assert.equal(p.to.at(-1), 1320, "the page is back where you were");
    assert.equal(turnOf(doc, "turn:t2").getBoundingClientRect().top, -100, "the turn at the height it had");
    assert.ok(!p.to.slice(mark).includes(0), "never sent to the top on the way");
    assert.equal(doc.activeElement, turnOf(doc, "turn:t2"), "the turn landed on has the focus");
    assert.equal(turnOf(doc, "turn:t2").getAttribute("tabindex"), "-1", "focusable, not a Tab stop");
    if (round === 1) {
      await traverse(window, "forward");
      assert.equal(doc.getElementById("page-rules").hidden, false);
    }
  }
});

test("A2: a link to the session (Home's row) opens it fresh: at its top, folded, the focus on its heading", async () => {
  const p = open(() => FIVE);
  const { doc, window } = p;
  await readAndLeave(p);
  await traverse(window, "back");
  await waitWhile(() => doc.activeElement !== turnOf(doc, "turn:t2"));
  await press(doc.querySelector('#nav [data-page-link="home"]'));
  await press(doc.querySelector('#home-agents a[data-page-link="agent"][data-session="s1"]'));
  await frames();
  assert.equal(window.location.pathname, "/mandu/agents/s1");
  assert.equal(p.to.at(-1), 0, "at its top");
  assert.equal(expanded(replyOf(doc, "turn:t1")), "false", "the reply folded");
  assert.equal(expanded(foldOf(doc, "turn:t1")), "false", "the steps folded");
  assert.equal(doc.activeElement, heading(doc), "the focus on the page's heading");
});

test("A3: Show them (earlier turns) pressed before leaving is asked for again on Back", async () => {
  const capped = page([3, 4], { earlier: 3 });
  const all = page([0, 1, 2, 3, 4], { allTurns: true });
  const p = open(() => capped, PAGE_URL, { "GET home/agent?session=s1&turns=all": all });
  const { doc, window, calls } = p;
  await tick();
  doc.querySelector("#agent-story .story-more button.show-rest").click();
  await tick();
  assert.equal(turns(doc).length, 5, "Show them brought the earlier turns");
  replyOf(doc, "turn:t1").click();
  window.scrollTo(0, TOP + 2 * TALL + 100);
  await press(rulesLink(doc));
  const before = agentReads(calls).length;
  await traverse(window, "back");
  await waitWhile(() => doc.activeElement !== turnOf(doc, "turn:t2"));
  assert.equal(agentReads(calls)[before], "home/agent?session=s1&turns=all", "the first read after Back asks for every turn");
  assert.equal(turns(doc).length, 5, "the turn you were on is drawn");
  assert.equal(expanded(replyOf(doc, "turn:t1")), "true");
  assert.equal(p.to.at(-1), 1320);
});

test("A4: the oldest turn dropped off the top keeps the turn you read where it was; the turn gone, the page uses the saved y", async () => {
  // The oldest turn dropped off: the turn you read is one place higher.
  let read: unknown = FIVE;
  const p = open(() => read);
  await readAndLeave(p);
  read = page([1, 2, 3, 4, 5]);
  await traverse(p.window, "back");
  await waitWhile(() => p.doc.activeElement !== turnOf(p.doc, "turn:t2"));
  await frames();
  assert.equal(p.to.at(-1), 1320 - TALL, "by the turn, not by the pixels");
  assert.equal(turnOf(p.doc, "turn:t2").getBoundingClientRect().top, -100);
  assert.equal(expanded(replyOf(p.doc, "turn:t1")), "true", "the toggles go by the turn too");

  // The turn you read is no longer drawn: the saved y, the focus on the heading.
  let read2: unknown = FIVE;
  const q = open(() => read2);
  await readAndLeave(q);
  read2 = page([0, 1, 3, 4]);
  await traverse(q.window, "back");
  await waitWhile(() => turns(q.doc).length !== 4);
  await frames();
  assert.equal(q.to.at(-1), 1320, "the saved y");
  assert.equal(q.doc.activeElement, heading(q.doc), "no turn to give the focus: the heading keeps it");
});

test("A5: a scroll while the read is out is yours, and the page stays there", async () => {
  const out: ((v: unknown) => void)[] = [];
  let reads = 0;
  const p = open(() => (++reads === 1 ? FIVE : new Promise((r) => out.push(r))));
  await readAndLeave(p);
  await traverse(p.window, "back");
  await waitWhile(() => !out.length);
  p.window.scrollTo(0, 50);
  const mark = p.to.length;
  out[0]!(FIVE);
  await tick();
  await frames();
  assert.deepEqual(p.to.slice(mark), [], "nothing scrolled after yours");
  assert.equal(p.window.scrollY, 50);
  assert.equal(expanded(replyOf(p.doc, "turn:t1")), "true", "what you opened is still opened");
  assert.equal(p.doc.activeElement, heading(p.doc), "the focus stays on the heading");
});

test("A6: a toggle pressed just before the browser's own Back is kept for Forward", async () => {
  const p = open(() => FIVE, BASE + "/");
  const { doc, window } = p;
  await tick();
  await press(doc.querySelector('#home-agents a[data-page-link="agent"][data-session="s1"]'));
  await tick();
  replyOf(doc, "turn:t3").click();
  await new Promise((r) => setTimeout(r, 300));
  await traverse(window, "back");
  assert.equal(doc.getElementById("page-home").hidden, false);
  const drawn = turnOf(doc, "turn:t3");
  await traverse(window, "forward");
  await waitWhile(() => turnOf(doc, "turn:t3") === drawn || expanded(replyOf(doc, "turn:t3")) !== "true");
  assert.notEqual(turnOf(doc, "turn:t3"), drawn, "drawn again by Forward's read");
  assert.equal(expanded(replyOf(doc, "turn:t3")), "true", "the reply opened just before Back");
});

test("A7: a session's page opened at an ask's moment is a link: its Back starts at the top, as before", async () => {
  const p = open(() => FIVE, PAGE_URL + "?ask=ask-1", { "GET home/agent?session=s1&ask=ask-1": FIVE });
  const { doc, window } = p;
  await readAndLeave(p);
  const mark = p.to.length;
  await traverse(window, "back");
  assert.equal(window.location.search, "?ask=ask-1");
  await tick();
  await frames();
  assert.deepEqual(p.to.slice(mark), [0], "at its top");
  assert.equal(expanded(replyOf(doc, "turn:t1")), "false", "folded, as a link opens it");
});
