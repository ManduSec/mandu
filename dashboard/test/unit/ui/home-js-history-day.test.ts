/**
 * home-js-history-day.test — dashboard.md §4.25ae *Go to a day*. History
 * was reachable past its first 25 rows only by Show more, page by page;
 * now a date box beside *Find a session*, "Go to a day", lists the sessions
 * from that day back:
 *
 *   D1  the box: a native date box named "Go to a day", today its latest
 *       day, no earliest; Show the newest hidden while no day is set;
 *   D2  choosing a day reads `?before=` with the moment the next local day
 *       starts (the date's parts, so a clock change is honoured), starts
 *       the list over, writes `day=` into the address (replaced, no new
 *       entry), says `From ${TUE} back` in the status line and
 *       shows Show the newest; Show more and Home's poll keep `before=`;
 *   D3  Show the newest clears the day: the box, the address, the read, the
 *       line; the box takes the focus;
 *   D4  with a search and the switch, every read carries all three, the
 *       address all three, and the line joins them;
 *   D5  nothing on or before the day: "No session on or before Tuesday, Oct
 *       20." with Show the newest, the status line saying it to a screen
 *       reader; with a search, "No session matches “x” on or before …";
 *       the box stays though the narrowed list is empty;
 *   D6  `?day=` on load sets the box and reads it; Back from a session keeps
 *       it; a link to History starts at the newest; a `day=` that is not a
 *       real date is no day;
 *   D7  Day before and Day after (queue #245) beside the box while a day is
 *       set, named by their words then the day they go to; each steps a
 *       calendar day exactly as choosing it in the box (the read, `day=`
 *       replaced, the search and the switch kept), the focus staying on
 *       the pressed button; neither shows with no day;
 *   D8  Day after is hidden on today or later; from yesterday it goes to
 *       today, hides, and the focus moves to Day before;
 *   D9  the steps are calendar days across both clock changes of 2026 in
 *       New York (a 23- and a 25-hour day).
 *
 * TZ pinned to a zone with a clock change (America/New_York): the bound of
 * 2026-11-01, a 25-hour day, is the start of Nov 2 local, not Nov 1 + 24 h.
 */
process.env.TZ = "America/New_York";

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";
import { waitWhile } from "../page-wait.js";

const URL = "http://127.0.0.1:4500/mandu/history";
const row = (id: string, over: Record<string, unknown> = {}) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", startedAt: "2026-10-20T14:00:00.000Z", lastAt: "2026-10-20T14:05:00.000Z", state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null, ...over,
});
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ids = (doc: any) => ([...doc.querySelectorAll("#history-list .row.agent")] as any[]).map((r) => r.dataset.session);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const historyCalls = (calls: any[]) => calls.filter((c) => c.url.startsWith("/mandu/api/home/history")).map((c) => c.url.slice("/mandu/api/".length));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const choose = async (doc: any, day: string) => {
  const box = doc.getElementById("history-day");
  box.focus();
  box.value = day;
  box.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
  await tick();
};

/** The start of the local day after `y-m-d` (the page's `before=`). */
const nextDay = (y: number, m: number, d: number) => new Date(y, m - 1, d + 1).getTime();
const OCT20 = nextDay(2026, 10, 20);
/** Oct 20, 2026 as a heading says it: with its year once the clock is past 2026. */
const TUE = new Date().getFullYear() === 2026 ? "Tuesday, Oct 20" : "Tuesday, Oct 20, 2026";
const ALL = { total: 214, rows: [row("s9", { lastAt: "2026-10-28T14:05:00.000Z" }), row("s8", { lastAt: "2026-10-27T14:05:00.000Z" })], next: "s8" };
const FROM20 = { total: 120, rows: [row("s40"), row("s41")], next: "s41", before: { at: OCT20, all: 214 } };

test("D1: the box is a labelled native date box, today its latest day, no earliest; no Show the newest", async () => {
  const { doc } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": ALL } });
  await tick();
  const box = doc.getElementById("history-day");
  assert.equal(box.getAttribute("type"), "date");
  assert.equal(doc.querySelector('label[for="history-day"]').textContent, "Go to a day");
  assert.equal(box.closest("form"), doc.getElementById("history-search"), "in the search form, beside Find a session");
  const now = new Date();
  const today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
  assert.equal(box.max, today, "no day in the future");
  assert.equal(box.min, "", "no earliest: how long sessions are kept is a setting");
  assert.equal(box.value, "");
  assert.equal(doc.getElementById("history-newest").hidden, true);
});

test("D2: a day chosen reads ?before= the next local day's start, starts over, writes day= and says where the list starts; Show more and the poll keep it", async () => {
  const more = { total: 120, rows: [row("s42")], next: null, before: { at: OCT20, all: 214 } };
  const { doc, window, calls } = load({ extensions: "", url: URL, homeVm: home(), routes: {
    "GET home/history": ALL, [`GET home/history?before=${OCT20}`]: FROM20, [`GET home/history?after=s41&before=${OCT20}`]: more,
  } });
  await tick();
  const entries = window.history.length;
  await choose(doc, "2026-10-20");
  assert.deepEqual(historyCalls(calls), ["home/history", `home/history?before=${OCT20}`]);
  assert.deepEqual(ids(doc), ["s40", "s41"], "the list starts over from the day");
  assert.equal(window.location.pathname + window.location.search, "/mandu/history?day=2026-10-20");
  assert.equal(window.history.length, entries, "replaced, not pushed");
  const count = doc.getElementById("history-count");
  assert.equal(count.hidden, false);
  assert.equal(count.classList.contains("sr-only"), false);
  assert.equal(count.textContent, `From ${TUE} back`);
  assert.equal(doc.getElementById("history-newest").hidden, false, "Show the newest beside the box");
  assert.equal(doc.activeElement, doc.getElementById("history-day"), "the focus stays in the box");
  assert.equal(doc.querySelector("#history-list .history-more span").textContent, "118 more sessions.", "Show more counts the narrowed list");
  assert.equal(doc.querySelector("#history-list .history-day").textContent, TUE, "the first heading is the day");
  doc.querySelector("#history-list .history-more button").click();
  await tick();
  assert.deepEqual(ids(doc), ["s40", "s41", "s42"]);
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick();
  assert.deepEqual(historyCalls(calls).slice(1), [`home/history?before=${OCT20}`, `home/history?after=s41&before=${OCT20}`, `home/history?before=${OCT20}`], "the poll reads the same day");
  // The same day again reads nothing.
  await choose(doc, "2026-10-20");
  assert.equal(historyCalls(calls).length, 4);
});

test("D2b: the bound is the next local day's start, across a clock change (a 25-hour day)", async () => {
  const end = nextDay(2026, 11, 1);
  assert.equal(end - new Date(2026, 10, 1).getTime(), 25 * 3_600_000, "Nov 1, 2026 is 25 hours long in New York");
  const { doc, calls } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": ALL } });
  await tick();
  await choose(doc, "2026-11-01");
  assert.equal(historyCalls(calls).at(-1), `home/history?before=${end}`);
});

test("D3: Show the newest clears the day: the box, the address, the read, the line; the box focused", async () => {
  const { doc, window, calls } = load({ extensions: "", url: `${URL}?day=2026-10-20`, homeVm: home(), routes: { "GET home/history": ALL, [`GET home/history?before=${OCT20}`]: FROM20 } });
  await tick();
  assert.deepEqual(historyCalls(calls), [`home/history?before=${OCT20}`]);
  doc.getElementById("history-newest").click();
  await tick();
  assert.equal(doc.getElementById("history-day").value, "");
  assert.equal(window.location.pathname + window.location.search, "/mandu/history");
  assert.deepEqual(historyCalls(calls), [`home/history?before=${OCT20}`, "home/history"]);
  assert.deepEqual(ids(doc), ["s9", "s8"]);
  assert.equal(doc.getElementById("history-count").hidden, true, "no day, no search: no line");
  assert.equal(doc.getElementById("history-newest").hidden, true);
  assert.equal(doc.activeElement, doc.getElementById("history-day"));
  // Clearing the box itself (the browser's own clear) does the same.
  await choose(doc, "2026-10-20");
  assert.equal(window.location.search, "?day=2026-10-20");
  await choose(doc, "");
  assert.equal(window.location.search, "");
  assert.equal(historyCalls(calls).at(-1), "home/history");
});

test("D4: with a search and the switch, every read carries all three, the address too, and the line joins them", async () => {
  const q = { total: 12, rows: [row("s40")], next: null, query: { text: "deploy", all: 214 } };
  const qd = { total: 3, rows: [row("s40")], next: null, query: { text: "deploy", all: 214 }, before: { at: OCT20, all: 214 } };
  const all3 = { total: 3, rows: [row("s40", { blocked: 1 })], next: null, query: { text: "deploy", all: 214 }, before: { at: OCT20, all: 214 }, only: { through: 3 } };
  const { doc, window, calls } = load({ extensions: "", url: `${URL}?q=deploy`, homeVm: home(), routes: {
    "GET home/history?q=deploy": q, [`GET home/history?q=deploy&before=${OCT20}`]: qd, [`GET home/history?q=deploy&only=stepped-in&before=${OCT20}`]: all3,
  } });
  await tick();
  await choose(doc, "2026-10-20");
  assert.equal(window.location.search, "?q=deploy&day=2026-10-20");
  assert.equal(doc.getElementById("history-count").textContent, `3 of 214 sessions, from ${TUE} back`);
  doc.getElementById("history-only").click();
  await tick();
  assert.equal(window.location.search, "?q=deploy&only=stepped-in&day=2026-10-20");
  assert.deepEqual(historyCalls(calls), ["home/history?q=deploy", `home/history?q=deploy&before=${OCT20}`, `home/history?q=deploy&only=stepped-in&before=${OCT20}`]);
  assert.equal(doc.getElementById("history-count").textContent, `Showing the sessions where Mandu stepped in that match “deploy”, from ${TUE} back`);
});

test("D5: nothing on or before the day says so, with Show the newest; with a search, the search's words too", async () => {
  const none = { total: 0, rows: [], next: null, before: { at: OCT20, all: 214 } };
  const { doc, window, calls } = load({ extensions: "", url: `${URL}?day=2026-10-20`, homeVm: home(), routes: { [`GET home/history?before=${OCT20}`]: none, "GET home/history": ALL } });
  await tick();
  const list = doc.getElementById("history-list");
  assert.equal(list.textContent, `No session on or before ${TUE}. Show the newest`);
  const count = doc.getElementById("history-count");
  assert.equal(count.hidden, false);
  assert.equal(count.classList.contains("sr-only"), true, "the status line says it to a screen reader only");
  assert.equal(count.textContent, `No session on or before ${TUE}.`);
  assert.equal(doc.getElementById("history-search").hidden, false, "the record is not empty: the box stays");
  list.querySelector("button.history-newest").click();
  await tick();
  assert.equal(window.location.search, "");
  assert.deepEqual(historyCalls(calls).at(-1), "home/history");
  assert.deepEqual(ids(doc), ["s9", "s8"]);
  assert.equal(doc.activeElement, doc.getElementById("history-day"));
  // With a search.
  const q = { total: 0, rows: [], next: null, query: { text: "x", all: 214 }, before: { at: OCT20, all: 214 } };
  const s = load({ extensions: "", url: `${URL}?q=x&day=2026-10-20`, homeVm: home(), routes: { [`GET home/history?q=x&before=${OCT20}`]: q } });
  await tick();
  assert.equal(s.doc.getElementById("history-list").textContent, `No session matches “x” on or before ${TUE}. Show the newest`);
  // A record with no session at all: the empty record's words, the box kept by the day.
  const e = load({ extensions: "", url: `${URL}?day=2026-10-20`, homeVm: home(), routes: { [`GET home/history?before=${OCT20}`]: { total: 0, rows: [], next: null, before: { at: OCT20, all: 0 } } } });
  await tick();
  assert.match(e.doc.getElementById("history-list").textContent, /No session has been recorded yet/);
  assert.equal(e.doc.getElementById("history-search").hidden, false, "a day in the address keeps the box, to undo it");
});

test("D6: ?day= on load sets the box; Back from a session keeps it; a link starts at the newest; a day that is no date is none", async () => {
  const { doc, window, calls } = load({ extensions: "", url: `${URL}?day=2026-10-20`, homeVm: home(), routes: { [`GET home/history?before=${OCT20}`]: FROM20, "GET home/history": ALL } });
  await tick();
  assert.equal(doc.getElementById("history-day").value, "2026-10-20");
  assert.equal(doc.getElementById("history-newest").hidden, false);
  doc.querySelector('#history-list .row.agent a[data-page-link="agent"]').click();
  await tick();
  assert.equal(doc.getElementById("page-agent").hidden, false);
  const from = window.location.pathname;
  window.history.back();
  await waitWhile(() => window.location.pathname === from);
  await tick();
  assert.equal(window.location.pathname + window.location.search, "/mandu/history?day=2026-10-20");
  assert.equal(doc.getElementById("history-day").value, "2026-10-20", "Back keeps the day");
  assert.equal(historyCalls(calls).at(-1), `home/history?before=${OCT20}`);
  doc.querySelector('#nav [data-page-link="history"]').click();
  await tick();
  assert.equal(window.location.pathname + window.location.search, "/mandu/history");
  assert.equal(doc.getElementById("history-day").value, "");
  assert.equal(historyCalls(calls).at(-1), "home/history");
  for (const bad of ["2026-02-30", "2026-1-5", "yesterday", "2026-10-20x"]) {
    const b = load({ extensions: "", url: `${URL}?day=${bad}`, homeVm: home(), routes: { "GET home/history": ALL } });
    await tick();
    assert.deepEqual(historyCalls(b.calls), ["home/history"], `?day=${bad} is no day`);
    assert.equal(b.doc.getElementById("history-day").value, "");
  }
});

/** Oct 19 and 21, 2026 as a step button's name says them. */
const y26 = new Date().getFullYear() === 2026 ? "" : ", 2026";
const MON = `Monday, Oct 19${y26}`;
const WED = `Wednesday, Oct 21${y26}`;
/** A local day key `by` days from now. */
const keyFromToday = (by: number) => {
  const n = new Date();
  const d = new Date(n.getFullYear(), n.getMonth(), n.getDate() + by, 12);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
};

test("D7: Day before and Day after step a calendar day as the box does, named by where they go, the search and switch kept, the focus kept", async () => {
  const OCT19 = nextDay(2026, 10, 19);
  const OCT21 = nextDay(2026, 10, 21);
  const page = { total: 3, rows: [row("s40")], next: null, query: { text: "deploy", all: 214 }, only: { through: 3 } };
  const { doc, window, calls } = load({ extensions: "", url: `${URL}?q=deploy&only=stepped-in&day=2026-10-20`, homeVm: home(), routes: {
    [`GET home/history?q=deploy&only=stepped-in&before=${OCT20}`]: { ...page, before: { at: OCT20, all: 214 } },
    [`GET home/history?q=deploy&only=stepped-in&before=${OCT19}`]: { ...page, before: { at: OCT19, all: 214 } },
    [`GET home/history?q=deploy&only=stepped-in&before=${OCT21}`]: { ...page, before: { at: OCT21, all: 214 } },
  } });
  await tick();
  const before = doc.getElementById("history-day-before");
  const after = doc.getElementById("history-day-after");
  const newest = doc.getElementById("history-newest");
  assert.equal(before.hidden, false);
  assert.equal(after.hidden, false);
  assert.equal(before.closest(".history-go-day"), doc.getElementById("history-day").parentElement, "beside the box");
  assert.ok(before.compareDocumentPosition(newest) & 4 && after.compareDocumentPosition(newest) & 4, "before Show the newest");
  assert.equal(before.textContent, "Day before");
  assert.equal(after.textContent, "Day after");
  assert.equal(before.getAttribute("aria-label"), `Day before: ${MON}`);
  assert.equal(after.getAttribute("aria-label"), `Day after: ${WED}`);
  for (const b of [before, after]) assert.ok(b.getAttribute("aria-label").startsWith(b.textContent), "the name starts with the visible words");
  const entries = window.history.length;
  before.focus();
  before.click();
  await tick();
  assert.equal(historyCalls(calls).at(-1), `home/history?q=deploy&only=stepped-in&before=${OCT19}`);
  assert.equal(window.location.search, "?q=deploy&only=stepped-in&day=2026-10-19");
  assert.equal(window.history.length, entries, "replaced, not pushed");
  assert.equal(doc.getElementById("history-day").value, "2026-10-19", "the box shows the new day");
  assert.match(doc.getElementById("history-count").textContent, new RegExp(`from ${MON} back$`));
  assert.equal(doc.activeElement, before, "the focus stays on Day before");
  assert.equal(after.getAttribute("aria-label"), `Day after: ${TUE}`, "the names follow the day");
  after.focus();
  after.click();
  await tick();
  after.click();
  await tick();
  assert.equal(historyCalls(calls).at(-1), `home/history?q=deploy&only=stepped-in&before=${OCT21}`);
  assert.equal(window.location.search, "?q=deploy&only=stepped-in&day=2026-10-21");
  assert.equal(doc.activeElement, after, "the focus stays on Day after");
  assert.deepEqual(historyCalls(calls), [OCT20, OCT19, OCT20, OCT21].map((b) => `home/history?q=deploy&only=stepped-in&before=${b}`), "one read per step");
  // Show the newest: no day, neither button.
  newest.click();
  await tick();
  assert.equal(before.hidden, true);
  assert.equal(after.hidden, true);
  // With no day at all, neither shows.
  const none = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": ALL } });
  await tick();
  assert.equal(none.doc.getElementById("history-day-before").hidden, true);
  assert.equal(none.doc.getElementById("history-day-after").hidden, true);
});

test("D8: Day after is hidden on today or later; from yesterday it goes to today and hides, the focus moving to Day before", async () => {
  const yesterday = keyFromToday(-1);
  const today = keyFromToday(0);
  const { doc, window, calls } = load({ extensions: "", url: `${URL}?day=${yesterday}`, homeVm: home(), routes: {} });
  await tick();
  const before = doc.getElementById("history-day-before");
  const after = doc.getElementById("history-day-after");
  assert.equal(after.hidden, false);
  assert.equal(after.getAttribute("aria-label"), "Day after: today");
  after.focus();
  after.click();
  await tick();
  const [y, m, d] = today.split("-").map(Number);
  assert.equal(historyCalls(calls).at(-1), `home/history?before=${nextDay(y!, m!, d!)}`);
  assert.equal(window.location.search, `?day=${today}`);
  assert.equal(after.hidden, true, "no Day after on today");
  assert.equal(before.hidden, false);
  assert.equal(before.getAttribute("aria-label"), "Day before: yesterday");
  assert.equal(doc.activeElement, before, "the focus moves to Day before, not to the page");
  // A day in the future (an address typed by hand): Day before only.
  const f = load({ extensions: "", url: `${URL}?day=${keyFromToday(3)}`, homeVm: home(), routes: {} });
  await tick();
  assert.equal(f.doc.getElementById("history-day-after").hidden, true);
  assert.equal(f.doc.getElementById("history-day-before").hidden, false);
});

test("D9: the steps are calendar days across a 25-hour and a 23-hour day (New York, 2026)", async () => {
  const step = async (from: string, id: string) => {
    const { doc, window, calls } = load({ extensions: "", url: `${URL}?day=${from}`, homeVm: home(), routes: {} });
    await tick();
    doc.getElementById(id).click();
    await tick();
    return { search: window.location.search, read: historyCalls(calls).at(-1) };
  };
  // Nov 1 is 25 hours long: its midnight + 24 h is still Nov 1.
  assert.deepEqual(await step("2026-11-01", "history-day-after"), { search: "?day=2026-11-02", read: `home/history?before=${nextDay(2026, 11, 2)}` });
  assert.deepEqual(await step("2026-11-02", "history-day-before"), { search: "?day=2026-11-01", read: `home/history?before=${nextDay(2026, 11, 1)}` });
  // Mar 8 is 23 hours long: Mar 9's midnight - 24 h is Mar 7.
  assert.deepEqual(await step("2026-03-09", "history-day-before"), { search: "?day=2026-03-08", read: `home/history?before=${nextDay(2026, 3, 8)}` });
  assert.deepEqual(await step("2026-03-08", "history-day-after"), { search: "?day=2026-03-09", read: `home/history?before=${nextDay(2026, 3, 9)}` });
  // Across a month and a year.
  assert.equal((await step("2026-03-01", "history-day-before")).search, "?day=2026-02-28");
  assert.equal((await step("2025-12-31", "history-day-after")).search, "?day=2026-01-01");
});
