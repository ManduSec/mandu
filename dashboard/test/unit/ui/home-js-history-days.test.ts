/**
 * home-js-history-days.test — dashboard.md §4.25ae *Sessions sit under their
 * day*. History gave each row its moment only as relative words ("ended 99
 * days ago"), the clock time on hover: nothing said which day a row was
 * from, and two sessions ten hours apart on two days both read "99 days
 * ago". Now a heading line goes before the first row of each day, in the
 * viewer's local time zone:
 *
 *   D1  rows that ended today, yesterday, three days ago and last year sit
 *       under "Today", "Yesterday", "Wednesday, Oct 14" and "Thursday, Jul
 *       10, 2025", each heading once, an h2 before its first row, with the
 *       day as its <time datetime>; the rows are as before;
 *   D2  a running row sits under the day it started, the moment its line
 *       names (a day listed again further down gets a heading of its own,
 *       keyed apart);
 *   D3  the day is the local one: the same rows read in UTC and in Seoul
 *       sit under different days, a row at 00:10 in Seoul under Today;
 *   D4  a poll with one new session on top keeps every heading and row
 *       already drawn the same node, the new row under Today;
 *   D5  past midnight, the next poll says "Yesterday" where "Today" was
 *       (and the day before by its date), no heading or row drawn again;
 *   D6  Show more that starts on the last day drawn adds no second heading;
 *       one that starts on a new day adds its heading, and the first row
 *       it brought (not the heading) takes the focus;
 *   D7  a search shows headings over its matches only, and none over "No
 *       session matches".
 *
 * Axes: none (display only).
 */
process.env.TZ = "Asia/Seoul"; // UTC+9, no daylight saving time

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";

const URL = "http://127.0.0.1:4500/mandu/history";
const row = (id: string, lastAt: string, over: Record<string, unknown> = {}) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", startedAt: lastAt, lastAt, state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null, ...over,
});
/** Saturday Oct 17 2026, 15:00 in Seoul. */
const NOW = Date.parse("2026-10-17T06:00:00.000Z");
const TODAY = "2026-10-17T03:00:00.000Z"; // Oct 17, 12:00 in Seoul
const TODAY_EARLY = "2026-10-16T15:10:00.000Z"; // Oct 17, 00:10 in Seoul; Oct 16 in UTC
const YESTERDAY = "2026-10-16T05:00:00.000Z"; // Friday Oct 16, 14:00
const LATE_YESTERDAY = "2026-10-16T14:50:00.000Z"; // Oct 16, 23:50
const THREE_DAYS = "2026-10-14T05:00:00.000Z"; // Wednesday Oct 14
const LAST_YEAR = "2025-07-10T05:00:00.000Z"; // Thursday Jul 10 2025

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const list = (doc: El) => doc.getElementById("history-list");
const headings = (doc: El) => [...list(doc).querySelectorAll(".history-day")] as El[];
const rowOf = (doc: El, id: string) => ([...list(doc).querySelectorAll(".row.agent")] as El[]).find((r) => r.dataset.session === id);
/** The list in page order: a heading by its words, a row by its id, the
 *  Show more line as "more". */
const order = (doc: El) => ([...list(doc).children] as El[]).map((x) =>
  x.matches(".history-day") ? `# ${x.textContent}` : x.matches(".row.agent") ? x.dataset.session : x.matches(".history-more") ? "more" : x.className);
const poll = async (doc: El) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };
/** A History route answering each read with the next answer (the last one
 *  again once they run out). */
function answers(...list: unknown[]) {
  let i = 0;
  return () => list[Math.min(i++, list.length - 1)];
}
/** The page with its clock at `clock.now` (moved by the test). */
function page(routes: Record<string, unknown>, clock = { now: NOW }, url = URL) {
  return { clock, ...load({ extensions: "", url, homeVm: home(), routes, before: (w: El) => { w.Date.now = () => clock.now; } }) };
}

test("D1: rows of today, yesterday, three days ago and last year sit under their day, each heading once, an h2 before its first row", async () => {
  const rows = [row("a", TODAY), row("b", TODAY_EARLY), row("c", YESTERDAY), row("d", THREE_DAYS), row("e", THREE_DAYS), row("f", LAST_YEAR)];
  const { doc } = page({ "GET home/history": { total: 6, rows, next: null } });
  await tick();
  assert.deepEqual(order(doc), ["# Today", "a", "b", "# Yesterday", "c", "# Wednesday, Oct 14", "d", "e", "# Thursday, Jul 10, 2025", "f"]);
  const h = headings(doc);
  assert.deepEqual(h.map((x) => x.tagName), ["H2", "H2", "H2", "H2"], "a real heading, so a screen reader can go from day to day");
  assert.deepEqual(h.map((x) => x.querySelector("time").getAttribute("datetime")), ["2026-10-17", "2026-10-16", "2026-10-14", "2025-07-10"]);
  assert.equal(doc.querySelectorAll("#page-history h1").length, 1, "the page keeps its one h1 above them");
  assert.match(rowOf(doc, "a").textContent, /ended/, "the rows are as before");
  assert.equal(rowOf(doc, "a").querySelector(".agent-when time").getAttribute("datetime"), TODAY, "the row keeps its whole moment");
});

test("D2: a running row sits under the day it started; a day listed again further down gets its own heading", async () => {
  const rows = [row("r", TODAY, { state: "running", startedAt: LATE_YESTERDAY }), row("a", TODAY), row("c", YESTERDAY)];
  const { doc } = page({ "GET home/history": { total: 3, rows, next: null } });
  await tick();
  assert.deepEqual(order(doc), ["# Yesterday", "r", "# Today", "a", "# Yesterday", "c"]);
  assert.match(rowOf(doc, "r").textContent, /running now, started/);
  const keys = headings(doc).map((x) => x.dataset.session);
  assert.equal(new Set(keys).size, keys.length, `each heading has its own key: ${keys.join(" ")}`);
});

test("D3: the day is the viewer's local one: the same rows in UTC and in Seoul sit under different days", async () => {
  const routes = { "GET home/history": { total: 2, rows: [row("b", TODAY_EARLY), row("c", YESTERDAY)], next: null } };
  const seoul = page(routes);
  await tick();
  assert.deepEqual(order(seoul.doc), ["# Today", "b", "# Yesterday", "c"], "00:10 on Oct 17 in Seoul is today");
  process.env.TZ = "UTC";
  try {
    const utc = page(routes);
    await tick();
    assert.deepEqual(order(utc.doc), ["# Yesterday", "b", "c"], "15:10 on Oct 16 in UTC is yesterday, as is 05:00");
  } finally {
    process.env.TZ = "Asia/Seoul";
  }
});

test("D4: a poll with one new session on top keeps every heading and row already drawn the same node", async () => {
  const first = { total: 3, rows: [row("a", TODAY), row("c", YESTERDAY), row("d", THREE_DAYS)], next: null };
  const after = { total: 4, rows: [row("n", "2026-10-17T05:00:00.000Z", { state: "running" }), ...first.rows], next: null };
  const { doc } = page({ "GET home/history": answers(first, after) });
  await tick();
  const drawn = [...list(doc).children];
  await poll(doc);
  assert.deepEqual(order(doc), ["# Today", "n", "a", "# Yesterday", "c", "# Wednesday, Oct 14", "d"]);
  const now = [...list(doc).children];
  assert.equal(now[0], drawn[0], "the Today heading is the one already there");
  assert.deepEqual(now.slice(2), drawn.slice(1), "every heading and row drawn before is the same node, in place");
});

test("D5: past midnight the next poll says Yesterday where Today was, no heading or row drawn again", async () => {
  const rows = { total: 3, rows: [row("a", TODAY), row("c", YESTERDAY), row("d", THREE_DAYS)], next: null };
  const clock = { now: Date.parse("2026-10-17T14:59:00.000Z") }; // Oct 17, 23:59
  const { doc } = page({ "GET home/history": rows }, clock);
  await tick();
  assert.deepEqual(order(doc), ["# Today", "a", "# Yesterday", "c", "# Wednesday, Oct 14", "d"]);
  const drawn = [...list(doc).children];
  clock.now = Date.parse("2026-10-17T15:01:00.000Z"); // Oct 18, 00:01
  await poll(doc);
  assert.deepEqual(order(doc), ["# Yesterday", "a", "# Friday, Oct 16", "c", "# Wednesday, Oct 14", "d"]);
  assert.deepEqual([...list(doc).children], drawn, "the same nodes: only the words of the headings changed");
});

test("D6: Show more that starts on the last day adds no second heading; one on a new day adds its heading, the focus on the row", async () => {
  const page1 = Array.from({ length: 3 }, (_, i) => row(`a${i}`, TODAY));
  const routes = {
    "GET home/history": { total: 7, rows: page1, next: "a2" },
    "GET home/history?after=a2": { total: 7, rows: [row("a3", TODAY), row("a4", TODAY)], next: "a4" },
    "GET home/history?after=a4": { total: 7, rows: [row("c0", YESTERDAY), row("c1", YESTERDAY)], next: null },
  };
  const { doc } = page(routes);
  await tick();
  doc.querySelector("#history-list .history-more button").click();
  await tick();
  assert.deepEqual(order(doc), ["# Today", "a0", "a1", "a2", "a3", "a4", "more"], "the page continues Today");
  assert.equal(doc.activeElement.closest(".row.agent").dataset.session, "a3", "the first row it brought takes the focus");
  doc.querySelector("#history-list .history-more button").click();
  await tick();
  assert.deepEqual(order(doc), ["# Today", "a0", "a1", "a2", "a3", "a4", "# Yesterday", "c0", "c1"]);
  assert.equal(doc.activeElement.closest(".row.agent")?.dataset.session, "c0", "the row, not its heading, takes the focus");
});

test("D7: a search shows headings over its matches only, and none over No session matches", async () => {
  const routes = {
    "GET home/history?q=staging": { total: 2, rows: [row("a", TODAY), row("d", THREE_DAYS)], next: null, query: { text: "staging", all: 9 } },
    "GET home/history?q=nothing": { total: 0, rows: [], next: null, query: { text: "nothing", all: 9 } },
  };
  const found = page(routes, { now: NOW }, `${URL}?q=staging`);
  await tick();
  assert.deepEqual(order(found.doc), ["# Today", "a", "# Wednesday, Oct 14", "d"]);
  const none = page(routes, { now: NOW }, `${URL}?q=nothing`);
  await tick();
  assert.equal(headings(none.doc).length, 0);
  assert.match(list(none.doc).textContent, /No session matches/);
});
