/**
 * home-js-story-days.test — dashboard.md §4.25, the per-agent page, *A
 * session on more than one day names its days*. A turn's head showed only
 * its clock time ("23:50") in a plain span: a session left open overnight
 * showed "23:50" then "00:10" with nothing to say a day went by, and a turn
 * at "09:12" the next morning read as if it came before the "23:50" above.
 *
 *   Y1  a session within one day draws no day line; each turn's time (and
 *       a stopped message's) is a <time datetime> that still reads "23:50"
 *       and whose tooltip names the day ("Oct 16, 23:50"); the background
 *       list's times carry the same tooltip; a turn with no time keeps an
 *       empty span;
 *   Y2  turns at 23:50, 23:58 and 00:10, the viewer's local time, draw two
 *       day lines, before the first and the third turn, in the viewer's
 *       local day (TZ is pinned east of UTC, where all three are one UTC
 *       day: a test in UTC would hide an off-by-one); a message Mandu
 *       stopped at 00:02 falls under the second day, its line before it;
 *       a turn with no time starts no day;
 *   Y3  the lines follow the turns drawn: with the earlier turns not shown
 *       a page of one day has none, and "Show them" draws them; with the
 *       switch on (§4.25ae) each day's quiet turns fold behind their own
 *       line, under the day's line;
 *   Y4  a poll with the same page keeps the lines and the focus; a poll
 *       that draws the page again draws the same lines.
 *
 * Axes: none (display only).
 */
process.env.TZ = "Asia/Seoul"; // UTC+9, no daylight saving time

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, T, load, tick } from "./home-js-fixtures.js";

const URL1 = "http://127.0.0.1:4500/mandu/agents/s1";
/** The year words a day of 2026 gets: none while it is 2026. */
const YEAR = new Date().getFullYear() === 2026 ? "" : ", 2026";
const step = (id: string, ts: string, outcome = "plain") => ({ kind: "action", id, ts, icon: "run", sentence: [T(`Ran ${id}`)], outcome, note: null, split: null });
const turn = (id: string, ts: string | null, outcome = "plain", over: Record<string, unknown> = {}) => ({
  ...AGENT.story[1], id, ts, prompt: `Question ${id}`, routine: null, reply: null, moreSteps: 0, promptNote: null,
  summary: outcome === "plain" ? "Nothing here needed guarding." : `Mandu did ${outcome}.`, summaryParts: null, tone: outcome,
  steps: [step(`${id}-a`, ts ?? "2026-10-16T14:50:01.000Z", outcome)], ...over,
});
// 23:50, 23:58 on Friday Oct 16 and 00:10 on Saturday Oct 17 in Seoul; all
// on Oct 16 in UTC.
const T1 = "2026-10-16T14:50:00.000Z";
const T2 = "2026-10-16T14:58:00.000Z";
const T3 = "2026-10-16T15:10:00.000Z";
const UNSENT = { lines: ["Your message was not sent to the AI: it holds a card number."], items: [], ts: "2026-10-16T15:02:00.000Z" };
const ONE_DAY = { ...AGENT, waiting: [], earlier: 0, story: [turn("t:a", "2026-10-16T01:24:00.000Z", "plain", {
  routine: { count: 1, hosts: [], parts: [T("In the background: 1 step.")], items: [{ ts: "2026-10-16T01:24:30.000Z", parts: [T("Checked a command.")] }], moreItems: 0 },
}), turn("t:b", "2026-10-16T05:00:00.000Z", "blocked")], unplacedNotes: [{ ...UNSENT, ts: "2026-10-16T03:00:00.000Z" }] };
const NIGHT = { ...AGENT, waiting: [], earlier: 0, story: [turn("t:1", T1), turn("t:2", T2, "blocked"), turn("t:3", T3)], unplacedNotes: [UNSENT] };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const story = (doc: El) => doc.getElementById("agent-story");
const days = (doc: El) => [...story(doc).querySelectorAll(".story-day")] as El[];
/** The story's cards and lines in page order: a turn by its id, a stopped
 *  message as "unsent", a day line by its words, a fold as "fold". */
const order = (doc: El) => ([...story(doc).children] as El[]).map((x) =>
  x.classList.contains("story-day") ? `day ${x.textContent}`
    : x.classList.contains("prompt-unsent") ? "unsent"
      : x.classList.contains("story-quiet") ? "fold"
        : x.matches("article.turn") ? x.dataset.turnId : x.className);
async function poll(doc: El): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
}

test("Y1: a session within one day draws no day line, and every turn's time is a <time> whose tooltip names the day", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": ONE_DAY } });
  await tick();
  assert.equal(days(doc).length, 0, "no day line within one day");
  assert.deepEqual(order(doc), ["t:a", "unsent", "t:b"], "the page as before");
  const times = [...story(doc).querySelectorAll("article.turn > .turn-head > .time")] as El[];
  assert.equal(times.length, 3);
  for (const t of times) assert.equal(t.tagName, "TIME", `${t.outerHTML} is a <time>`);
  assert.deepEqual(times.map((t) => t.textContent), ["10:24", "12:00", "14:00"], "the clock time, local, in its column");
  assert.deepEqual(times.map((t) => t.getAttribute("datetime")), ["2026-10-16T01:24:00.000Z", "2026-10-16T03:00:00.000Z", "2026-10-16T05:00:00.000Z"]);
  assert.deepEqual(times.map((t) => t.title), [`Oct 16${YEAR}, 10:24`, `Oct 16${YEAR}, 12:00`, `Oct 16${YEAR}, 14:00`], "the whole moment on hover");
  // The background list's times.
  const bg = story(doc).querySelector(".routine-list time");
  assert.equal(bg.textContent, "10:24");
  assert.equal(bg.title, `Oct 16${YEAR}, 10:24`);
  // A turn with no time: an empty span, as before.
  const none = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...ONE_DAY, story: [turn("t:x", null)], unplacedNotes: [] } } });
  await tick();
  const span = none.doc.querySelector("#agent-story article.turn .turn-head > .time");
  assert.equal(span.tagName, "SPAN");
  assert.equal(span.textContent, "");
  assert.equal(span.hasAttribute("title"), false);
});

test("Y2: turns at 23:50, 23:58 and 00:10 draw a line before the first and the third, in the viewer's local day; a stopped message at 00:02 falls under the second", async () => {
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": NIGHT } });
  await tick();
  assert.deepEqual(order(doc), [`day Friday, Oct 16${YEAR}`, "t:1", "t:2", `day Saturday, Oct 17${YEAR}`, "unsent", "t:3"]);
  const [d1, d2] = days(doc);
  assert.equal(d1.tagName, "DIV", "a separator line, not a heading");
  assert.equal(story(doc).querySelectorAll("h1, h2, h3, h4, [role=heading]").length, 0, "no heading in the story");
  const dt = d1.querySelector("time");
  assert.equal(dt.getAttribute("datetime"), "2026-10-16", "the local day, as a <time>");
  assert.equal(d2.querySelector("time").getAttribute("datetime"), "2026-10-17");
  const at = (id: string) => story(doc).querySelector(`article.turn[data-turn-id="${id}"] .turn-head > time`);
  assert.equal(at("t:1").textContent, "23:50");
  assert.equal(at("t:1").title, `Oct 16${YEAR}, 23:50`);
  assert.equal(at("t:3").textContent, "00:10");
  assert.equal(at("t:3").title, `Oct 17${YEAR}, 00:10`);
  assert.equal(story(doc).querySelector(".prompt-unsent .turn-head > time").title, `Oct 17${YEAR}, 00:02`);

  // A turn with no time starts no day, and splits none.
  const gap = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...NIGHT, story: [turn("t:1", T1), turn("t:0", null), turn("t:2", T2), turn("t:3", T3)], unplacedNotes: [] } } });
  await tick();
  assert.deepEqual(order(gap.doc), [`day Friday, Oct 16${YEAR}`, "t:1", "t:0", "t:2", `day Saturday, Oct 17${YEAR}`, "t:3"]);
  // A year other than this one is named.
  const old = load({ url: URL1, routes: { "GET home/agent?session=s1": { ...NIGHT, story: [turn("t:1", "2020-12-31T14:50:00.000Z"), turn("t:2", "2020-12-31T15:10:00.000Z")], unplacedNotes: [] } } });
  await tick();
  assert.deepEqual(days(old.doc).map((d) => d.textContent), ["Thursday, Dec 31, 2020", "Friday, Jan 1, 2021"]);
});

test("Y3: the lines follow the turns drawn: the earlier turns and Show them, and the switch's folds day by day", async () => {
  const capped = { ...NIGHT, earlier: 2, allTurns: false, story: [turn("t:3", T3)], unplacedNotes: [] };
  const all = { ...NIGHT, earlier: 0, allTurns: true, unplacedNotes: [] };
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": capped, "GET home/agent?session=s1&turns=all": all } });
  await tick();
  assert.equal(days(doc).length, 0, "the turns drawn are on one day");
  story(doc).querySelector(".story-more button.show-rest").click();
  await tick();
  assert.deepEqual(order(doc), [`day Friday, Oct 16${YEAR}`, "t:1", "t:2", `day Saturday, Oct 17${YEAR}`, "t:3"], "Show them draws them from the turns it brought");

  // The switch on: each day's quiet turns fold behind their own line.
  const quiet = { ...NIGHT, story: [turn("t:1", T1), turn("t:2", T2), turn("t:3", T3), turn("t:4", "2026-10-16T15:20:00.000Z", "blocked")], unplacedNotes: [] };
  const only = load({ url: `${URL1}?only=stepped-in`, routes: { "GET home/agent?session=s1": quiet } });
  await tick();
  assert.deepEqual(order(only.doc), [`day Friday, Oct 16${YEAR}`, "fold", "t:1", "t:2", `day Saturday, Oct 17${YEAR}`, "fold", "t:3", "t:4"]);
  assert.deepEqual(([...story(only.doc).querySelectorAll(".story-quiet > span")] as El[]).map((s) => s.textContent),
    ["2 turns where Mandu did nothing", "1 turn where Mandu did nothing"]);
  for (const d of days(only.doc)) assert.equal(d.hidden, false, "a day line stays in sight");
  // Off again: the lines stay, the folds go.
  only.doc.getElementById("agent-only").click();
  assert.deepEqual(order(only.doc), [`day Friday, Oct 16${YEAR}`, "t:1", "t:2", `day Saturday, Oct 17${YEAR}`, "t:3", "t:4"]);
});

test("Y4: a poll keeps the lines and the focus; one that draws the page again draws the same lines", async () => {
  let page: unknown = NIGHT;
  const { doc } = load({ url: URL1, routes: { "GET home/agent?session=s1": () => page } });
  await tick();
  const before = days(doc);
  // The focus on a turn of the second day, as a step a link showed would have it.
  const card = story(doc).querySelector('article.turn[data-turn-id="t:3"]');
  card.setAttribute("tabindex", "-1");
  card.focus();
  assert.equal(doc.activeElement, card);
  await poll(doc);
  assert.equal(days(doc).length, 2);
  assert.ok(days(doc).every((d, i) => d === before[i]), "the same page: nothing drawn again");
  assert.equal(doc.activeElement, card, "the focus stays");

  // The agent did more: drawn again, the same lines, a new turn under the second day.
  page = { ...NIGHT, story: [...NIGHT.story, turn("t:5", "2026-10-16T15:40:00.000Z")] };
  await poll(doc);
  assert.notEqual(days(doc)[0], before[0], "drawn again");
  assert.deepEqual(order(doc), [`day Friday, Oct 16${YEAR}`, "t:1", "t:2", `day Saturday, Oct 17${YEAR}`, "unsent", "t:3", "t:5"]);
});
