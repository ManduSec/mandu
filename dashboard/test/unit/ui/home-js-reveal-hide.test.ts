/**
 * home-js-reveal-hide.test — a real value shown on a session's page hides
 * itself again (dashboard.md §4.25b *Showing a real value*, *The page*):
 * a minute after it shows, and at once when the tab goes to the
 * background. Show the real value (a step's and a Your secrets card's) and
 * a prompt filter's Show what was hidden; never content from outside,
 * which holds no secret and is already on the page.
 *
 * The page script (public/js/home.js) in jsdom over a fetch stub
 * (home-js-fixtures.ts), with a clock of its own for the hide's two timers
 * only (50 s, then 10 s), as home-js-suggested.test.ts fakes its 3 s one.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, load, tick } from "./home-js-fixtures.js";

const STEP_REF = "0123456789abcdef01234567";
const CARD_REF = "fedcba9876543210fedcba98";
const NOTE = {
  lines: ["One value in your prompt was hidden from the AI (an email address)."],
  items: [{ eventId: "ev-1", index: 0, category: "pii.email", words: "an email address", state: "hidden", canLetOnce: false, canLetSession: false, canShow: true }],
  ts: "2026-09-25T10:00:00.000Z",
};
const PAGE = {
  ...AGENT,
  story: [{ ...AGENT.story[0], promptNote: NOTE }, ...AGENT.story.slice(1)],
  secrets: { mode: "secrets", flagged: false, more: 0, counts: { masked: 1, early: 0 },
    secrets: [{ what: [{ kind: "text", text: "The environment variable " }, { kind: "code", text: "API_KEY" }], level: "No AI", lines: [], ref: CARD_REF }] },
};
const VALUE: Record<string, string> = { [STEP_REF]: "sk-live-step-value", [CARD_REF]: "ghp_card_value" };
const ORIGINAL = "me@corp.example";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any;

/** The page, its clock for the hide's timers, and a tab that can go away. */
function page(read: () => unknown = () => PAGE) {
  let now = 0;
  let seq = 1_000_000;
  const timers = new Map<number, { at: number; fn: () => void }>();
  let visibility = "visible";
  const p = load({
    url: "http://127.0.0.1:4500/mandu/agents/s1",
    routes: {
      "GET home/agent?session=s1": () => read(),
      "POST home/reveal": (b: Any) => ({ value: VALUE[b.ref] }),
      "POST prompt-filters/reveal": () => ({ original: ORIGINAL }),
    },
    before: (w: Any) => {
      const real = w.setTimeout.bind(w);
      const realClear = w.clearTimeout.bind(w);
      w.setTimeout = (fn: () => void, ms: number) => {
        if (ms !== 50_000 && ms !== 10_000) return real(fn, ms);
        const id = ++seq;
        timers.set(id, { at: now + ms, fn });
        return id;
      };
      w.clearTimeout = (id: number) => (timers.has(id) ? timers.delete(id) : realClear(id));
      Object.defineProperty(w.document, "visibilityState", { configurable: true, get: () => visibility });
    },
  });
  /** Move the clock on by `ms`, firing each timer due on the way. */
  const advance = (ms: number) => {
    const end = now + ms;
    for (;;) {
      const due = [...timers].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) break;
      timers.delete(due[0]);
      now = due[1].at;
      due[1].fn();
    }
    now = end;
  };
  const away = (state: "hidden" | "visible") => {
    visibility = state;
    p.doc.dispatchEvent(new p.window.Event("visibilitychange"));
  };
  return { ...p, advance, away, pending: () => timers.size };
}

const stepBox = (doc: Any) => {
  const step = [...doc.querySelectorAll("#agent-story .step.split")].find((x: Any) => x.querySelector(".tag").textContent === "Secret hidden") as Any;
  return { btn: step.querySelector("button.secret-reveal"), pre: step.querySelector("pre.secret-value"), caption: step.querySelector(".hidden-caption") };
};
const cardBox = (doc: Any) => {
  const card = doc.querySelector("#agent-secrets .secret-card");
  return { btn: card.querySelector("button.secret-reveal"), pre: card.querySelector("pre.secret-value"), caption: card.querySelector(".hidden-caption") };
};
const promptBox = (doc: Any) => {
  const row = doc.querySelector("#agent-story .prompt-note-item");
  return { btn: row.querySelector(".prompt-reveal"), pre: doc.querySelector("#agent-story .prompt-hidden-text"), caption: row.querySelector(".hidden-caption") };
};
const outsideBox = (doc: Any) => {
  const masked = [...doc.querySelectorAll("#agent-story .step.split")].find((x: Any) => x.querySelector(".tag").textContent === "Masked") as Any;
  return { btn: masked.querySelector("button.reveal"), pre: masked.querySelector(".hidden-text") };
};
const nameOf = (b: Any): string => b.getAttribute("aria-label") ?? b.textContent;

test("a shown real value hides itself again after a minute: the box empties, the button offers it again, the caption said when", async () => {
  const { doc, advance, pending } = page();
  await tick();
  const { btn, pre, caption } = stepBox(doc);
  const offer = nameOf(btn);
  btn.focus();
  btn.click();
  await tick();
  assert.equal(pre.textContent, VALUE[STEP_REF]);
  assert.equal(caption.textContent, "Only you see this. The AI still has only the masked version. Hides again in 1 minute.");
  assert.equal(caption.getAttribute("aria-live"), null, "no live region: a screen reader is not interrupted");
  advance(49_999);
  assert.match(caption.textContent, /Hides again in 1 minute\.$/);
  advance(1);
  assert.equal(caption.textContent, "Only you see this. The AI still has only the masked version. Hides again in a few seconds.", "changed once, at 10 s left");
  advance(9_000);
  assert.equal(pre.textContent, VALUE[STEP_REF], "at 59 s it still shows");
  assert.equal(pre.hidden, false);
  advance(1_000);
  assert.equal(pre.textContent, "", "at 60 s the value leaves the page");
  assert.equal(pre.hidden, true);
  assert.equal(caption.hidden, true);
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  assert.equal(nameOf(btn), offer, "Show the real value again");
  assert.equal(doc.activeElement, btn, "the button keeps the focus it had");
  assert.ok(!doc.body.textContent.includes(VALUE[STEP_REF]));
  assert.equal(pending(), 0, "no timer left");
  // Another click asks the server again.
  btn.click();
  await tick();
  assert.equal(pre.textContent, VALUE[STEP_REF]);
});

test("Hide it again before the minute clears its timer; a second show starts a new minute", async () => {
  const { doc, advance, pending } = page();
  await tick();
  const { btn, pre, caption } = cardBox(doc);
  btn.click();
  await tick();
  assert.equal(pre.textContent, VALUE[CARD_REF]);
  advance(30_000);
  btn.click();
  assert.equal(pre.textContent, "");
  assert.equal(pending(), 0, "the manual hide clears the timer");
  btn.click();
  await tick();
  assert.equal(pre.textContent, VALUE[CARD_REF]);
  assert.match(caption.textContent, /Hides again in 1 minute\.$/);
  advance(59_999);
  assert.equal(pre.textContent, VALUE[CARD_REF], "a new minute, not the rest of the old one");
  advance(1);
  assert.equal(pre.textContent, "");
});

test("the tab going to the background hides every open secret box at once, not a content-from-outside box", async () => {
  const { doc, away, pending } = page();
  await tick();
  const step = stepBox(doc);
  const card = cardBox(doc);
  const prompt = promptBox(doc);
  const outside = outsideBox(doc);
  outside.btn.click();
  step.btn.click();
  card.btn.click();
  prompt.btn.click();
  await tick();
  assert.equal(step.pre.textContent, VALUE[STEP_REF]);
  assert.equal(card.pre.textContent, VALUE[CARD_REF]);
  assert.equal(prompt.pre.textContent, ORIGINAL);
  assert.equal(pending(), 3);
  away("visible");
  assert.equal(card.pre.textContent, VALUE[CARD_REF], "a return to the tab hides nothing");
  away("hidden");
  for (const b of [step, card, prompt]) {
    assert.equal(b.pre.textContent, "");
    assert.equal(b.pre.hidden, true);
    assert.equal(b.btn.getAttribute("aria-expanded"), "false");
  }
  assert.equal(pending(), 0);
  assert.ok(!doc.body.textContent.includes(VALUE[STEP_REF]) && !doc.body.textContent.includes(VALUE[CARD_REF]) && !doc.body.textContent.includes(ORIGINAL));
  assert.equal(outside.pre.hidden, false, "content from outside stays open");
  assert.equal(outside.btn.getAttribute("aria-expanded"), "true");
});

test("a prompt filter's Show what was hidden hides itself again after a minute, and says so", async () => {
  const { doc, advance } = page();
  await tick();
  const { btn, pre, caption } = promptBox(doc);
  assert.equal(caption.hidden, true);
  btn.focus();
  btn.click();
  await tick();
  assert.equal(pre.textContent, ORIGINAL);
  assert.equal(caption.hidden, false);
  assert.equal(caption.textContent, "Hides again in 1 minute.");
  advance(50_000);
  assert.equal(caption.textContent, "Hides again in a few seconds.");
  advance(9_999);
  assert.equal(pre.textContent, ORIGINAL);
  advance(1);
  assert.equal(pre.textContent, "");
  assert.equal(pre.hidden, true);
  assert.equal(caption.hidden, true);
  assert.equal(btn.textContent, "Show what was hidden");
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  assert.equal(doc.activeElement, btn);
});

test("a redraw clears the timers: no timer outlives its box", async () => {
  let vm: Any = PAGE;
  const { doc, away, advance, pending } = page(() => vm);
  await tick();
  const old = stepBox(doc);
  old.btn.click();
  await tick();
  assert.equal(pending(), 1);
  // The agent did more: the poll's read brings a changed answer, and the
  // page is drawn again from nothing.
  vm = { ...PAGE, story: [...PAGE.story, { ...PAGE.story[1], id: "turn:more", promptNote: null }] };
  away("visible");
  await tick(40);
  assert.equal(old.btn.isConnected, false, "drawn again");
  assert.equal(pending(), 0, "the redraw cleared the timer");
  assert.ok(!doc.body.textContent.includes(VALUE[STEP_REF]), "a redraw does not put a value back");
  advance(60_000);
  assert.equal(stepBox(doc).btn.getAttribute("aria-expanded"), "false");
});
