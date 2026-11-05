/**
 * home-js-turn-link.test — dashboard.md §4.25 *A turn's time links to that
 * turn*. Nothing on a session page gave an address for one moment of it:
 * someone pointing a colleague, a note or a bug report at "the turn where
 * the key went out" could only send the session's address. Now each turn's
 * time is a link, `/agents/<id>?turn=<turn id>`:
 *
 *   K1  `parseRoute` reads `?turn=` (an empty, spaced, control-character or
 *       overlong value names no turn); `routeHref` builds it, and the two
 *       round-trip; `?ask=` wins over it;
 *   K2  a turn's time is a link inside its <time>, its words the time, its
 *       name "Link to this turn, 10:24", its address ids only; a stopped
 *       message's card, which is no turn, keeps a plain time;
 *   K3  a plain click replaces the address (no new entry) and marks that
 *       turn, one at a time; a Ctrl, Shift, Meta or middle click is left to
 *       the browser;
 *   K4  opening `?turn=` lands on that turn once the page is drawn: focused,
 *       marked, the address kept; a poll redraw keeps the mark and does not
 *       land again;
 *   K5  a turn before those first drawn: the page asks for every turn (the
 *       Show them read) and then lands on it;
 *   K6  an unknown turn: What happened's heading takes the focus, nothing
 *       marked;
 *   K7  with *Only where Mandu stepped in* on, a folded turn's quiet line
 *       button takes the focus, never the hidden card;
 *   K8  a link to the session opens it without the turn.
 *
 * Axes: none (display only). Mandu-new test.
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
const STORY = [turn("turn:input:e1:0", 1), turn("turn:input:e2:1", 2, "blocked"), turn("turn:input:e3:2", 3)];
const [A, B, C] = STORY.map((t) => t.id);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const plain = (o: unknown) => JSON.parse(JSON.stringify(o));
const where = (w: El) => w.location.pathname + w.location.search;
const turns = (doc: El) => [...doc.querySelectorAll("#agent-story article.turn[data-turn-id]")] as El[];
const turnOf = (doc: El, id: string) => turns(doc).find((t) => t.dataset.turnId === id);
const linkOf = (doc: El, id: string) => turnOf(doc, id).querySelector(".turn-head > time.time > a.turn-link");
const marked = (doc: El) => [...doc.querySelectorAll("#agent-story article.turn.shown")].map((t: El) => t.dataset.turnId);
async function poll(doc: El): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

test("K1: parseRoute reads ?turn= and routeHref builds it; empty or garbled values name no turn; ?ask= wins", () => {
  const { window } = load({ url: URL1 });
  const p = (search: string) => plain(window.parseRoute("/mandu/agents/s1", search));
  assert.deepEqual(p("?turn=t3"), { page: "agent", session: "s1", ask: null, turn: "t3" });
  assert.deepEqual(p("?turn=turn%3Ainput%3Aevt-9%3A2&only=stepped-in"), { page: "agent", session: "s1", ask: null, only: true, turn: "turn:input:evt-9:2" });
  for (const bad of ["?turn=", "?turn=%20", "?turn=a%20b", "?turn=a%0Ab", "?turn=%00", `?turn=${"x".repeat(257)}`]) {
    assert.equal(p(bad).turn, undefined, `${bad} names no turn`);
  }
  assert.equal(p(`?turn=${"x".repeat(256)}`).turn, "x".repeat(256));
  const r = window.routeHref;
  assert.equal(r("agent", "s1", null, null, "turn:input:e1:0"), "/mandu/agents/s1?turn=turn%3Ainput%3Ae1%3A0");
  assert.equal(r("agent", "s1", "egr-1", null, "t3"), "/mandu/agents/s1?ask=egr-1", "an ask's moment wins");
  assert.equal(r("agent", "s1", null, "blocked", "t3"), "/mandu/agents/s1?turn=t3");
  for (const id of ["t3", "turn:input:a&b=c#d:1", "a/b?c"]) {
    const href = new window.URL(r("agent", "s 1", null, null, id), "http://x");
    const back = plain(window.parseRoute(href.pathname, href.search));
    assert.equal(back.session, "s 1");
    assert.equal(back.turn, id, `${id} round-trips`);
  }
});

test("K2: a turn's time is a link to that turn inside its <time>, named 'Link to this turn, <time>'; a stopped message keeps a plain time", async () => {
  const unsent = { lines: ["Your message was not sent to the AI: it holds a card number."], items: [], ts: "2026-09-25T10:04:00.000Z" };
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": page(STORY, { unplacedNotes: [unsent] }) } });
  await tick();
  for (const id of [A, B, C]) {
    const time = turnOf(doc, id).querySelector(".turn-head > time.time");
    const a = linkOf(doc, id);
    assert.ok(a, `${id}: its time holds a link`);
    assert.equal(a.textContent, time.textContent, "its words are the time");
    assert.match(a.textContent, /^\d\d:\d\d$/);
    assert.equal(a.getAttribute("aria-label"), `Link to this turn, ${a.textContent}`);
    assert.equal(a.getAttribute("href"), `/mandu/agents/s1?turn=${encodeURIComponent(id)}`, "the session and the turn, ids only");
    assert.ok(time.getAttribute("title"), "the whole moment stays on hover");
  }
  const note = doc.querySelector("#agent-story article.prompt-unsent");
  assert.match(note.querySelector("time.time").textContent, /^\d\d:\d\d$/, "it has its time");
  assert.equal(note.querySelector("a.turn-link"), null, "a message Mandu stopped is no turn: no link");
  // Latest turn and the day lines still read the time off the <time>.
  assert.equal(doc.getElementById("agent-latest").firstChild.nodeValue, `Latest turn, ${linkOf(doc, C).textContent} `);
});

test("K3: a plain click replaces the address and marks the turn; a modified or middle click is left to the browser", async () => {
  const { doc, window, calls } = load({ url: URL1, routes: { "GET home/agent?session=s1": page(STORY) } });
  await tick();
  const entries = window.history.length;
  const reads = calls.length;
  assert.deepEqual(marked(doc), [], "nothing marked by a plain visit");
  const click = (a: El, o: Record<string, unknown> = {}) => {
    const e = new window.MouseEvent("click", { bubbles: true, cancelable: true, button: 0, ...o });
    a.dispatchEvent(e);
    return e;
  };
  const e = click(linkOf(doc, B));
  assert.equal(e.defaultPrevented, true, "the page handles it");
  assert.equal(where(window), `/mandu/agents/s1?turn=${encodeURIComponent(B)}`, "the address is the turn's");
  assert.equal(window.history.length, entries, "replaced, not pushed");
  assert.deepEqual(marked(doc), [B], "marked");
  assert.equal(calls.length, reads, "nothing read again");
  click(linkOf(doc, A));
  assert.equal(where(window), `/mandu/agents/s1?turn=${encodeURIComponent(A)}`);
  assert.deepEqual(marked(doc), [A], "one mark at a time");
  assert.equal(window.history.length, entries);
  for (const o of [{ ctrlKey: true }, { metaKey: true }, { shiftKey: true }, { altKey: true }, { button: 1 }]) {
    const m = click(linkOf(doc, C), o);
    assert.equal(m.defaultPrevented, false, `${JSON.stringify(o)}: the browser's`);
    assert.equal(where(window), `/mandu/agents/s1?turn=${encodeURIComponent(A)}`, "the address unchanged");
    assert.deepEqual(marked(doc), [A]);
  }
  // The switch's address keeps the turn (stateHref writes it).
  doc.getElementById("agent-only").click();
  assert.equal(where(window), `/mandu/agents/s1?turn=${encodeURIComponent(A)}&only=stepped-in`);
});

test("K4: ?turn= lands on that turn once the page is drawn, marked and focused, the address kept; a poll redraw keeps the mark and does not land again", async () => {
  let story: unknown[] = STORY;
  const { doc, window } = load({ url: `${URL1}?turn=${encodeURIComponent(B)}`, routes: { "GET home/agent?session=s1": () => page(story) } });
  await tick();
  assert.equal(doc.activeElement, turnOf(doc, B), "the turn has the focus");
  assert.equal(doc.activeElement.getAttribute("tabindex"), "-1", "not a Tab stop");
  assert.deepEqual(marked(doc), [B]);
  assert.equal(where(window), `/mandu/agents/s1?turn=${encodeURIComponent(B)}`, "kept, as a fragment is: the landed address can be bookmarked too");
  // The person moves on; the agent does more and the page is drawn again.
  const other = linkOf(doc, C);
  other.focus();
  story = [...STORY, turn("turn:input:e4:3", 4)];
  await poll(doc);
  assert.equal(turns(doc).length, 4, "drawn again");
  assert.deepEqual(marked(doc), [B], "the mark is kept");
  assert.notEqual(doc.activeElement, turnOf(doc, B), "no second landing");
});

test("K5: a turn before those first drawn: the page asks for every turn, then lands on it", async () => {
  const old = turn("turn:input:e0:0", 0);
  const { doc, calls } = load({ url: `${URL1}?turn=${encodeURIComponent(old.id)}`, routes: {
    "GET home/agent?session=s1": page(STORY, { earlier: 1 }),
    "GET home/agent?session=s1&turns=all": page([old, ...STORY], { allTurns: true }),
  } });
  await tick(60);
  assert.ok(calls.some((c) => c.url === "/mandu/api/home/agent?session=s1&turns=all"), "the Show them read");
  assert.equal(doc.activeElement, turnOf(doc, old.id), "the turn that was not drawn has the focus");
  assert.deepEqual(marked(doc), [old.id]);

  // Past what the page can show (no Show them lifts it): the heading.
  const past = load({ url: `${URL1}?turn=${encodeURIComponent(old.id)}`, routes: { "GET home/agent?session=s1": page(STORY, { earlier: 600, allTurns: true }) } });
  await tick();
  assert.ok(!past.calls.some((c) => c.url.endsWith("&turns=all")), "nothing to ask for");
  assert.equal(past.doc.activeElement, past.doc.querySelector("#agent-story-block h2"));
});

test("K6: an unknown turn lands on What happened's heading, nothing marked", async () => {
  const { doc } = load({ url: `${URL1}?turn=turn%3Ainput%3Anope%3A9`, routes: { "GET home/agent?session=s1": page(STORY) } });
  await tick();
  const h = doc.querySelector("#agent-story-block h2");
  assert.equal(doc.activeElement, h, "the story's heading");
  assert.match(h.textContent, /What happened/);
  assert.deepEqual(marked(doc), []);
});

test("K7: with Only where Mandu stepped in on, a folded turn's quiet line takes the focus, never the hidden card", async () => {
  const { doc } = load({ url: `${URL1}?turn=${encodeURIComponent(C)}&only=stepped-in`, routes: { "GET home/agent?session=s1": page(STORY) } });
  await tick();
  const card = turnOf(doc, C);
  assert.ok(card.hidden, "the quiet turn is folded");
  assert.ok(doc.activeElement.classList.contains("quiet-toggle"), `the line's button: ${doc.activeElement.className}`);
  assert.equal(card.hidden, true, "nothing opened by itself");
  assert.deepEqual(marked(doc), [C], "marked for when it is opened");
});

test("K8: a link to the session, and an ask's moment, open it without the turn", async () => {
  const { doc, window } = load({ url: `${URL1}?turn=${encodeURIComponent(B)}`, routes: { "GET home/agent?session=s1": page(STORY) } });
  await tick();
  window.eval(`setPage('home', true)`);
  await tick();
  window.eval(`setPage('agent', true, 's1')`);
  await tick();
  assert.equal(where(window), "/mandu/agents/s1");
  assert.deepEqual(marked(doc), []);
  const ask = load({ url: `${URL1}?ask=egr-1&turn=${encodeURIComponent(B)}`, routes: { "GET home/agent?session=s1&ask=egr-1": page(STORY) } });
  await tick();
  assert.equal(where(ask.window), "/mandu/agents/s1?ask=egr-1");
  assert.deepEqual(marked(ask.doc), []);
});
