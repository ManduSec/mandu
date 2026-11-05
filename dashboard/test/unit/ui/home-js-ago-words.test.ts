/**
 * home-js-ago-words.test — dashboard.md §4.25u *Every moment reads absolute
 * and relative*. Every relative moment of the product page comes from
 * home.js `ago()`. Until 2026-10-28 it counted days by rounding hours and
 * never went past days: a step 36 hours back, yesterday, read "2 days ago";
 * one 13 hours back, yesterday evening, read "13 hours ago" under History's
 * "Yesterday"; a year back read "365 days ago"; one day read "1 day ago".
 * Now the words follow the reader's calendar and grow coarser with age:
 *
 *   A1  under an hour: "just now", "1 minute ago", "59 minutes ago";
 *   A2  earlier today, or under 6 hours back across midnight: hours (23:30
 *       yesterday seen at 01:30 reads "2 hours ago");
 *   A3  the previous local day: "yesterday" (09:00 yesterday seen at 08:00;
 *       36 hours back is "yesterday" or "2 days ago" by the calendar, not
 *       by rounding);
 *   A4  2 to 6 days: "3 days ago"; 7 to 29: whole weeks ("1 week ago");
 *       30 to 364: whole 30-day months ("1 month ago"); a year or more:
 *       "over a year ago";
 *   A5  a day of 23 hours (daylight saving) does not shift the count;
 *   A6  a whenNode moment says the clock time beside the new words;
 *   A7  the poll's refreshWhen rewrites a `time.ago` that crossed midnight
 *       from "5 hours ago" to "yesterday".
 *
 * Axes: none (display only).
 */
process.env.TZ = "Asia/Seoul"; // UTC+9, no daylight saving time

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";

const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
/** Saturday Oct 17 2026, 15:00 in Seoul. */
const NOW = Date.parse("2026-10-17T06:00:00.000Z");
/** Seoul's local clock as an instant: `seoul("2026-10-16T23:30")`. */
const seoul = (local: string) => Date.parse(`${local}:00.000+09:00`);

/** The page with its clock at `clock.now` (moved by the test). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function page(clock = { now: NOW }, opts: Record<string, unknown> = {}): { clock: { now: number }; window: any; doc: any } {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return { clock, ...load({ extensions: "", homeVm: home(), ...opts, before: (w: any) => { w.Date.now = () => clock.now; } }) };
}

test("A1: under an hour, minutes as before", () => {
  const { window } = page();
  assert.equal(window.ago(NOW - 20_000), "just now");
  assert.equal(window.ago(NOW + 5 * MIN), "just now", "a moment ahead of the clock");
  assert.equal(window.ago(NOW - MIN), "1 minute ago");
  assert.equal(window.ago(NOW - 59 * MIN), "59 minutes ago");
  assert.equal(window.ago(Number.NaN), "");
});

test("A2: hours earlier today, and under 6 hours back across midnight", () => {
  const { window, clock } = page();
  assert.equal(window.ago(NOW - HOUR), "1 hour ago");
  assert.equal(window.ago(NOW - 5 * HOUR), "5 hours ago");
  assert.equal(window.ago(seoul("2026-10-17T00:30")), "15 hours ago", "earlier today");
  clock.now = seoul("2026-10-17T01:30");
  assert.equal(window.ago(seoul("2026-10-16T23:30")), "2 hours ago", "yesterday, but under 6 hours back");
  assert.equal(window.ago(seoul("2026-10-16T19:40")), "6 hours ago", "5 hours 50 minutes back, under 6");
  assert.equal(window.ago(seoul("2026-10-16T19:20")), "yesterday", "yesterday, 6 hours back or more");
});

test("A3: the previous local day reads 'yesterday', by the calendar, not by rounding hours", () => {
  const { window, clock } = page();
  clock.now = seoul("2026-10-17T08:00");
  assert.equal(window.ago(seoul("2026-10-16T09:00")), "yesterday", "23 hours back");
  assert.equal(window.ago(clock.now - 13 * HOUR), "yesterday", "yesterday evening, 13 hours back");
  assert.equal(window.ago(clock.now - 36 * HOUR), "2 days ago", "36 hours back from 08:00 is 20:00 two days back");
  clock.now = NOW; // 15:00
  assert.equal(window.ago(NOW - 36 * HOUR), "yesterday", "36 hours back from 15:00 is 03:00 yesterday");
  assert.equal(window.ago(NOW - DAY), "yesterday");
  assert.equal(window.ago(seoul("2026-10-16T00:00")), "yesterday", "yesterday's first minute");
  assert.equal(window.ago(seoul("2026-10-15T23:59")), "2 days ago", "the minute before it");
});

test("A4: days, then whole weeks, whole 30-day months, then over a year", () => {
  const { window } = page();
  const cases: [number, string][] = [
    [2, "2 days ago"], [3, "3 days ago"], [6, "6 days ago"],
    [7, "1 week ago"], [13, "1 week ago"], [14, "2 weeks ago"], [29, "4 weeks ago"],
    [30, "1 month ago"], [59, "1 month ago"], [60, "2 months ago"], [99, "3 months ago"], [364, "12 months ago"],
    [365, "over a year ago"], [800, "over a year ago"],
  ];
  for (const [days, words] of cases) assert.equal(window.ago(NOW - days * DAY), words, `${days} days back`);
});

test("A5: a day of 23 hours, when the clocks go forward, does not shift the count", () => {
  process.env.TZ = "America/New_York"; // forward on Sunday Mar 8 2026
  try {
    const clock = { now: Date.parse("2026-03-09T00:30:00.000-04:00") }; // Monday 00:30
    const { window } = page(clock);
    // Saturday 23:00, 24.5 hours back: two calendar days, 47 hours between their midnights.
    assert.equal(window.ago(Date.parse("2026-03-07T23:00:00.000-05:00")), "2 days ago");
    assert.equal(window.ago(Date.parse("2026-03-08T12:00:00.000-04:00")), "yesterday");
  } finally {
    process.env.TZ = "Asia/Seoul";
  }
});

test("A6: a whenNode moment says its clock time beside the new words", () => {
  const { window } = page();
  assert.equal(window.whenNode(seoul("2026-10-16T14:02")).textContent, "Oct 16, 14:02 · yesterday");
  assert.equal(window.whenNode(seoul("2025-09-30T14:12")).textContent, "Sep 30, 2025, 14:12 · over a year ago");
  const t = window.whenNode(NOW - 3 * DAY);
  assert.deepEqual([...t.children].map((x: { className: string; textContent: string }) => [x.className, x.textContent]), [["when-at", "Oct 14, 15:00 ·"], ["when-ago", "3 days ago"]],
    "still its two parts, each kept on one line");
});

test("A7: past midnight the poll rewrites a row's moment from '5 hours ago' to 'yesterday'", async () => {
  const ended = seoul("2026-10-17T18:00");
  const row = {
    id: "e1", agent: "Claude Code", title: "Task e1", cwd: "/home/u/ws", startedAt: new Date(ended - 10 * MIN).toISOString(), lastAt: new Date(ended).toISOString(), state: "idle",
    stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null,
  };
  const { doc, clock } = page({ now: seoul("2026-10-17T23:00") }, { url: "http://127.0.0.1:4500/mandu/history", routes: { "GET home/history": { total: 1, rows: [row], next: null } } });
  await tick();
  const t = doc.querySelector('#history-list .row.agent[data-session="e1"] .agent-when time.ago');
  assert.ok(t, "History drew the row's moment");
  assert.equal(t.parentElement.textContent, "ended 5 hours ago");
  clock.now = seoul("2026-10-18T01:30");
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick();
  assert.equal(doc.querySelector('#history-list .row.agent[data-session="e1"] .agent-when time.ago'), t, "the same <time>, its words said again");
  assert.equal(t.parentElement.textContent, "ended yesterday", "the same word as the Yesterday heading over it");
  assert.equal(doc.querySelector("#history-list .history-day").textContent, "Yesterday");
});
