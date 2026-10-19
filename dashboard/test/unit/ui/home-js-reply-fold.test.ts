/**
 * home-js-reply-fold.test — a long agent reply on the session page folds to
 * its first lines, with "Show the whole reply" (public/js/home.js
 * `foldReply`, `replyNode`; dashboard.md §4.25b *A long reply folds*).
 *
 * Until 2026-10-19 every reply was drawn whole: one 1,392-character reply
 * of a recorded session took 44% of its page at 1280 px, and more than a
 * phone screen at 390 px, pushing the steps after it far down.
 *
 *   - a long reply in the wide form folds, with one button
 *     (`aria-expanded="false"`, `aria-controls` its text); pressed, the
 *     whole text shows, the button reads "Show less" and keeps the focus;
 *   - a short reply shows no button and no fold;
 *   - in the split form one button under the row folds both halves, and
 *     the AI half still holds only the masked text;
 *   - the "kept" secrets line and the "could not fill in" note are outside
 *     the fold;
 *   - a redraw (the agent did more) keeps a fold you opened open;
 *   - a browser scrolling a folded text (find in page) opens it.
 *
 * jsdom lays out nothing: fake-resize.ts gives the page a ResizeObserver,
 * and a reply text's `scrollHeight` is stubbed from its length (the fold
 * height falls back to 210 px with no stylesheet). The real heights are
 * tests/stack/reply-fold.test.ts. Drives the PRODUCT page script in jsdom
 * over the shared fetch stub (home-js-fixtures.ts).
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, M, T, load, tick } from "./home-js-fixtures.js";
import { fakeResize } from "./fake-resize.js";

const PAGE = "http://127.0.0.1:4500/mandu/agents/s1";
const SHOW = "Show the whole reply";
const LESS = "Show less";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** A long reply: 40 lines of a coding agent's summary. */
const LONG = Array.from({ length: 40 }, (_, i) => `- step ${i + 1}: edited src/module-${i}.ts and its tests`).join("\n");
const SHORT = "All green.";
const at = "2026-09-25T10:01:09.000Z";
const C = (text: string) => ({ kind: "code", text });
const KEPT = [T("The reply held your secret "), C("STRIPE_KEY"), T(". The AI wrote it masked, and this page keeps it masked.")];

/** The agent page of s1 with these replies, one turn each; `more` turns: the
 *  agent did more (a changed answer, so the page is drawn again). */
function agentPage(replies: unknown[], more = 0): unknown {
  const page = JSON.parse(JSON.stringify(AGENT));
  page.story = replies.map((reply, i) => ({ ...page.story[1], id: `turn:r${i}`, steps: [], reply }));
  for (let i = 0; i < more; i++) page.story.push({ ...page.story[1], id: `turn:more${i}`, prompt: `Go on ${i}`, steps: [], reply: null });
  return page;
}

/** The page with a ResizeObserver and reply heights: a text over 1000
 *  characters is 2000 px tall, a shorter one 60 px. `fit()` runs every
 *  observer, as a browser does once the replies are laid out. */
function open(read: () => unknown) {
  const sizes = fakeResize();
  const scrolled: number[] = [];
  const page = load({ url: PAGE, routes: { "GET home/agent?session=s1": () => read() }, before: (w: Doc) => {
    sizes.install(w);
    Object.defineProperty(w.HTMLElement.prototype, "scrollHeight", {
      configurable: true,
      get(this: Doc) { return this.classList.contains("reply-text") ? (this.textContent.length > 1000 ? 2000 : 60) : 0; },
    });
    w.scrollBy = (_x: number, y: number) => { scrolled.push(y); };
  } });
  const fit = () => { for (const t of page.doc.querySelectorAll("#agent-story .reply-text")) sizes.resized(t); };
  return { ...page, fit, sizes, scrolled };
}
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}
const replies = (doc: Doc) => [...doc.querySelectorAll("#agent-story .step.reply")] as Doc[];
const shown = (x: Doc) => !x.closest("[hidden]");

test("a long reply folds with one button; pressed, the whole text shows and the button keeps the focus; a short reply has none (§4.25b)", async () => {
  const { doc, err, fit } = open(() => agentPage([{ ts: at, parts: [T(LONG)], ai: null }, { ts: at, parts: [T(SHORT)], ai: null }]));
  assert.equal(err, null);
  await tick(40);
  fit();
  const [long, short] = replies(doc);
  const text = long.querySelector(".reply-text");
  const buttons = long.querySelectorAll("button.reply-fold");
  assert.equal(buttons.length, 1, "one button");
  const btn = buttons[0];
  assert.ok(shown(btn), "the button shows");
  assert.equal(btn.textContent, SHOW);
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  assert.equal(btn.getAttribute("aria-controls"), text.id, "it controls the reply text");
  assert.ok(text.id && doc.getElementById(text.id) === text);
  assert.ok(text.classList.contains("folded"), "the text is folded");
  assert.match(text.textContent, /step 40: edited src\/module-39\.ts and its tests$/, "the whole text is on the page, only cut by its height");

  btn.focus();
  btn.click();
  assert.equal(btn.getAttribute("aria-expanded"), "true");
  assert.equal(btn.textContent, LESS);
  assert.ok(!text.classList.contains("folded"), "the whole text shows");
  assert.equal(doc.activeElement, btn, "the focus stays on the button");
  fit();
  assert.ok(!text.classList.contains("folded"), "a new measure keeps it open");

  btn.click();
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  assert.equal(btn.textContent, SHOW);
  assert.ok(text.classList.contains("folded"), "folded again");
  assert.equal(doc.activeElement, btn);

  // A reply that fits: no button shows, nothing is folded.
  assert.ok(![...short.querySelectorAll("button.reply-fold")].some(shown), "no button under a short reply");
  assert.ok(!short.querySelector(".reply-text").classList.contains("folded"));
  assert.equal(short.querySelector(".reply-text").textContent, SHORT);
});

test("in the split form one button under the row folds both halves; the AI half holds only the masked text (§4.25b)", async () => {
  const secret = "sk_live_split_fold_VALUE";
  const { doc, fit } = open(() => agentPage([{ ts: at, parts: [T(LONG + "\nThe key is "), T(secret), T(".")], ai: [T(LONG + "\nThe key is "), M("masked"), T(".")] }]));
  await tick(40);
  fit();
  const [row] = replies(doc);
  assert.ok(row.classList.contains("split"));
  const saw = row.querySelector(".half.saw .reply-text");
  const real = row.querySelector(".half.real .reply-text");
  const buttons = row.querySelectorAll("button.reply-fold");
  assert.equal(buttons.length, 1, "one button for both halves");
  const btn = buttons[0];
  assert.equal(btn.closest(".reply-fold-row").parentElement, row, "under the row, not in a half");
  assert.ok(!btn.closest(".half"));
  assert.deepEqual(btn.getAttribute("aria-controls").split(" "), [saw.id, real.id], "it controls both texts");
  assert.ok(saw.classList.contains("folded") && real.classList.contains("folded"), "both halves fold together");
  btn.click();
  assert.ok(!saw.classList.contains("folded") && !real.classList.contains("folded"), "and open together");
  assert.ok(!row.querySelector(".half.saw").textContent.includes(secret), "the AI half never gets the filled-in text");
  assert.ok(saw.querySelector(".mask-chip"), "the AI half keeps its chip");
  assert.ok(real.textContent.includes(secret), "your half has it");
});

test("what a reply held stays outside the fold: the kept-secrets line and the could-not-fill-in note (§4.25b)", async () => {
  const { doc, fit } = open(() => agentPage([
    { ts: at, parts: [T(LONG + "\nSTRIPE_KEY='"), M("secret"), T("'")], ai: null, kept: KEPT },
    { ts: at, parts: [T(LONG + "\nIt is "), M("masked"), T(".")], ai: null, unresolved: true },
    { ts: at, parts: [T(LONG + "\ngreen, with "), M("secret")], ai: [T(LONG + "\n"), M("masked"), T(", with "), M("secret")], kept: KEPT },
  ]));
  await tick(40);
  fit();
  const [kept, unfilled, split] = replies(doc);
  for (const [card, sel] of [[kept, ".hidden-note.reply-kept"], [unfilled, ".hidden-note"], [split, ".hidden-note.reply-kept"]] as const) {
    const note = card.querySelector(sel);
    assert.ok(note, `${sel} is drawn`);
    assert.ok(!note.closest(".reply-text"), `${sel} is not in the folded text`);
    const texts = [...card.querySelectorAll(".reply-text")] as Doc[];
    assert.ok(texts.every((t) => t.classList.contains("folded")), "the reply is folded");
    assert.ok(texts.every((t) => !t.contains(note)));
    // Drawn after the text it tells of, before the button.
    const btn = card.querySelector("button.reply-fold");
    const after = (a: Doc, b: Doc) => !!(a.compareDocumentPosition(b) & doc.defaultView.Node.DOCUMENT_POSITION_FOLLOWING);
    assert.ok(after(texts.at(-1), note), `${sel} comes under the text`);
    assert.ok(after(note, btn), `${sel} comes before the button`);
  }
  assert.equal(kept.querySelector(".reply-text").nextElementSibling, kept.querySelector(".hidden-note.reply-kept"), "the line is right under the reply");
  assert.match(unfilled.querySelector(".hidden-note").textContent, /The original was not recorded here/);
});

test("a redraw after a fold was opened keeps it open; a fold left closed stays closed (§4.25 The poll keeps your place)", async () => {
  let vm = agentPage([{ ts: at, parts: [T(LONG)], ai: null }, { ts: at, parts: [T(LONG + "\nsecond")], ai: null }]);
  const { doc, fit } = open(() => vm);
  await tick(40);
  fit();
  const [first, second] = replies(doc).map((r) => r.querySelector("button.reply-fold"));
  second.focus();
  second.click();
  assert.equal(second.getAttribute("aria-expanded"), "true");
  vm = agentPage([{ ts: at, parts: [T(LONG)], ai: null }, { ts: at, parts: [T(LONG + "\nsecond")], ai: null }], 1);
  await poll(doc);
  const [first2, second2] = replies(doc).map((r) => r.querySelector("button.reply-fold"));
  assert.notEqual(second2, second, "the page was drawn again");
  assert.equal(second.isConnected, false);
  fit();
  assert.equal(second2.getAttribute("aria-expanded"), "true", "the reply you opened stays open");
  assert.equal(second2.textContent, LESS);
  assert.ok(!replies(doc)[1].querySelector(".reply-text").classList.contains("folded"));
  assert.equal(first2.getAttribute("aria-expanded"), "false", "the other stays folded");
  assert.ok(replies(doc)[0].querySelector(".reply-text").classList.contains("folded"));
  assert.equal(first.isConnected, false);
});

test("a browser that scrolls a folded reply to show what it found opens the fold and keeps the spot in view (§4.25b)", async () => {
  const { doc, fit, scrolled } = open(() => agentPage([{ ts: at, parts: [T(LONG)], ai: null }]));
  await tick(40);
  fit();
  const [card] = replies(doc);
  const text = card.querySelector(".reply-text");
  const btn = card.querySelector("button.reply-fold");
  assert.ok(text.classList.contains("folded"));
  // A scroll back to the top (the fold opened, or nothing found) is no find.
  text.dispatchEvent(new doc.defaultView.Event("scroll"));
  assert.ok(text.classList.contains("folded"), "a scroll that moved nothing opens nothing");
  Object.defineProperty(text, "scrollTop", { configurable: true, value: 300 });
  text.dispatchEvent(new doc.defaultView.Event("scroll"));
  assert.ok(!text.classList.contains("folded"), "the fold opens");
  assert.equal(btn.getAttribute("aria-expanded"), "true");
  assert.equal(btn.textContent, LESS);
  assert.deepEqual(scrolled, [300], "the page moves by what the text had scrolled, so the found words stay where they were");
});
