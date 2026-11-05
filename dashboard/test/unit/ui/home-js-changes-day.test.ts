/**
 * home-js-changes-day.test — dashboard.md §4.25 *Go to a day on Rule
 * changes*. Approvals › Rule changes, where a person finds what changed
 * their rules and undoes it, reached past its newest 20 only by Show more,
 * 20 at a time, or by *Find a change* when a file, host or agent was
 * remembered. Now the date box Answered earlier has above it ("Go to a
 * day", §4.25 *Go to a day on Answered earlier*) sits beside Find a change
 * and lists the changes from that day back, cut on the page over the read
 * of the newest 500 a search already makes (no server change):
 *
 *   D1  the box: a native date box named "Go to a day" in Find a change's
 *       form, with History's classes, today its latest day; Show the newest
 *       hidden while no day is set, and outside the live status line;
 *   D2  choosing the middle of three days reads `policy/changes?limit=500`,
 *       heads the list with that day, no newer row; `cday=` in the address
 *       (replaced, no new entry); "From Tuesday, Oct 20 back" in the status
 *       line; Show more goes further back, the next day's heading after,
 *       a change with no time at the very end; a poll with the same read
 *       draws nothing again;
 *   D3  Show the newest clears the day: the box, the address, the line; the
 *       newest 20 again; the box takes the focus;
 *   D4  a search and a day hold together: the address both, the line the
 *       count of matches from the day back, the rows only matches on or
 *       before the day;
 *   D5  a day before every change: "No rule changed on or before Thursday,
 *       Oct 1." with Show the newest, said to a screen reader by the status
 *       line; with a search, "No change matches “x” on or before …";
 *   D6  a read cut at 500: the line says so ("of the newest 500 changes"),
 *       and a day before every one of them says it looked only there;
 *   D7  `?cday=` on load sets the box and lists from it; Back keeps it; a
 *       link to Approvals starts at the newest; a `cday=` that is not a
 *       real date is no day; a change the address opens has none; the day
 *       of Answered earlier (`day=`) is not that of Rule changes.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the shared
 * fetch stub (home-js-fixtures.ts); across the real arbiter and dashboard,
 * tests/stack/changes-day.test.ts. TZ pinned to New York, as History's
 * test: the bound of Oct 20 is the start of Oct 21 there. Axes: none
 * (display only). Mandu-new test.
 */
process.env.TZ = "America/New_York";

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";
import { waitWhile } from "../page-wait.js";

const URL = "http://127.0.0.1:4500/mandu/approvals";
const at = (y: number, m: number, d: number, h = 10) => new Date(y, m - 1, d, h).getTime();
const T = (text: string) => ({ kind: "text", text });
const C = (text: string) => ({ kind: "code", text });
/** A change: a file made secret, or (`stripe`) a send let to a host. */
const change = (id: string, createdAt: number | null, stripe = false) => ({
  id, sentence: "You changed a rule on the Rules page", session: null, createdAt, undone: false, undoable: true,
  rows: stripe ? [[T("Always allow sending to "), C("api.stripe.com")]] : [[T("Make "), C(`~/proj/${id}.pem`), T(" a secret no AI may read")]],
});
/** Oct 2026 days as a heading says them: with the year once the clock is past 2026. */
const year = new Date().getFullYear() === 2026 ? "" : ", 2026";
const TUE = "Tuesday, Oct 20" + year;
const WED14 = "Wednesday, Oct 14" + year;
const MON26 = "Monday, Oct 26" + year;
/** Three days of changes, newest first: 22 on Oct 26, 22 on Oct 20 (every
 *  third lets a send to api.stripe.com), 4 on Oct 14; one with no time
 *  sits among the newest, as a server may list it. */
const D26 = Array.from({ length: 22 }, (_, i) => change(`c26-${i}`, at(2026, 10, 26, 20) - i * 60_000));
const D20 = Array.from({ length: 22 }, (_, i) => change(`c20-${i}`, at(2026, 10, 20, 20) - i * 60_000, i % 3 === 0));
const D14 = Array.from({ length: 4 }, (_, i) => change(`c14-${i}`, at(2026, 10, 14, 20) - i * 60_000));
const UNDATED = change("c-none", null);
const ALL = [...D26.slice(0, 5), UNDATED, ...D26.slice(5), ...D20, ...D14];
const quiet = () => home({ waiting: [], verdict: "protected", headline: "Your secrets are guarded." });
const routesFor = (all: unknown[]) => ({
  "GET policy/proposals?status=pending": { proposals: [] },
  "GET policy/changes?limit=21": () => ({ changes: all.slice(0, 21) }),
  "GET policy/changes?limit=500": () => ({ changes: all.slice(0, 500) }),
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const list = (doc: Doc) => doc.getElementById("approvals-rule-history");
const rows = (doc: Doc) => [...list(doc).querySelectorAll(".row.answered")] as Doc[];
const ids = (doc: Doc) => rows(doc).map((r) => r.dataset.id);
const headings = (doc: Doc) => ([...list(doc).querySelectorAll(".history-day")] as Doc[]).map((h) => h.textContent);
const box = (doc: Doc) => doc.getElementById("changes-day");
const newest = (doc: Doc) => doc.getElementById("changes-newest");
const count = (doc: Doc) => doc.getElementById("changes-count");
const empty = (doc: Doc) => list(doc).querySelector(".empty");
const more = (doc: Doc) => list(doc).querySelector(".changes-more button.show-rest");
const moreWords = (doc: Doc) => list(doc).querySelector(".changes-more #changes-more-words");
const reads = (calls: Array<{ url: string }>) => calls.filter((c) => c.url.startsWith("/mandu/api/policy/changes")).map((c) => c.url.slice("/mandu/api/".length));
/** The reads asked, each once (a page that opens reads, and so does Home's first answer). */
const asked = (calls: Array<{ url: string }>) => [...new Set(reads(calls))];
const choose = async (doc: Doc, day: string) => {
  box(doc).focus();
  box(doc).value = day;
  box(doc).dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
  await tick(40);
};
const type = async (doc: Doc, text: string) => {
  const q = doc.getElementById("changes-q");
  q.focus();
  q.value = text;
  q.dispatchEvent(new doc.defaultView.Event("input", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 300));
  await tick(40);
};
const poll = async (doc: Doc) => {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
};

test("D1: the box is a labelled native date box in Find a change's form, today its latest day; no Show the newest", async () => {
  const { doc } = load({ extensions: "", url: URL, homeVm: quiet(), routes: routesFor(ALL) });
  await tick(40);
  const b = box(doc);
  assert.equal(b.getAttribute("type"), "date");
  assert.equal(doc.querySelector('label[for="changes-day"]').textContent, "Go to a day");
  assert.equal(b.closest("form"), doc.getElementById("changes-search"), "beside Find a change");
  assert.ok(b.closest(".history-go-day"), "the classes of Answered earlier's box, so it wraps the same way");
  assert.equal(doc.getElementById("changes-search").hidden, false);
  assert.equal(newest(doc).hidden, true, "no day, no Show the newest");
  assert.equal(count(doc).contains(newest(doc)), false, "Show the newest is outside the live status line");
  const now = new Date();
  const today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
  assert.equal(b.max, today, "no day in the future");
  assert.equal(b.value, "");
});

test("D2: a day lists its changes and those before it, heading first; the address, the line; Show more goes back; no time at the end; a poll draws nothing again", async () => {
  const { doc, window, calls } = load({ extensions: "", url: URL, homeVm: quiet(), routes: routesFor(ALL) });
  await tick(40);
  assert.deepEqual(asked(calls), ["policy/changes?limit=21"], "the newest 20, as before");
  assert.equal(headings(doc)[0], MON26);
  const entries = window.history.length;
  await choose(doc, "2026-10-20");
  assert.equal(reads(calls).at(-1), "policy/changes?limit=500", "the read of a search: the newest 500, cut on the page");
  assert.deepEqual(ids(doc), D20.slice(0, 20).map((c) => c.id), "its newest 20, no newer row");
  assert.equal(headings(doc)[0], TUE, "the day chosen heads the list");
  assert.equal(window.location.pathname + window.location.search, "/mandu/approvals?cday=2026-10-20");
  assert.equal(window.history.length, entries, "the address is replaced, not pushed");
  assert.equal(count(doc).hidden, false);
  assert.equal(count(doc).textContent, `From ${TUE} back`);
  assert.equal(newest(doc).hidden, false, "Show the newest beside the box");
  assert.match(moreWords(doc).textContent, new RegExp(`^Showing 20 of 27 changes from ${TUE} back\\.$`));
  // A poll with the same read draws nothing again: the rows stay the same elements.
  const before = rows(doc);
  await poll(doc);
  assert.equal(reads(calls).at(-1), "policy/changes?limit=500", "the poll keeps the read of the day");
  assert.ok(rows(doc).every((r, i) => r === before[i]), "the same rows");
  // Show more: further back, with no read; Oct 14 under its own heading, the change with no time last.
  const n = reads(calls).length;
  more(doc).click();
  await tick(40);
  assert.equal(reads(calls).length, n, "from the read kept");
  assert.deepEqual(ids(doc), [...D20, ...D14, UNDATED].map((c) => c.id));
  assert.deepEqual(headings(doc), [TUE, WED14]);
  assert.equal(more(doc), null, "every one drawn");
});

test("D3: Show the newest clears the day: box, address, line; the newest 20 again; the box focused", async () => {
  const { doc, window } = load({ extensions: "", url: URL, homeVm: quiet(), routes: routesFor(ALL) });
  await tick(40);
  await choose(doc, "2026-10-20");
  newest(doc).click();
  await tick(40);
  assert.equal(box(doc).value, "");
  assert.equal(newest(doc).hidden, true);
  assert.equal(window.location.pathname + window.location.search, "/mandu/approvals");
  assert.equal(count(doc).hidden, true, "no line without a search or a day");
  assert.equal(rows(doc).length, 20);
  assert.equal(ids(doc)[0], "c26-0", "the newest first again");
  assert.equal(headings(doc)[0], MON26);
  assert.equal(doc.activeElement, box(doc), "the box takes the focus");
});

test("D4: a search and a day hold together", async () => {
  const { doc, window } = load({ extensions: "", url: URL, homeVm: quiet(), routes: routesFor(ALL) });
  await tick(40);
  await type(doc, "stripe");
  await choose(doc, "2026-10-20");
  const stripe = D20.filter((_, i) => i % 3 === 0).map((c) => c.id);
  assert.deepEqual(ids(doc), stripe, "the matches on or before the day only");
  assert.equal(window.location.pathname + window.location.search, "/mandu/approvals?changes=stripe&cday=2026-10-20");
  assert.equal(count(doc).textContent, `${stripe.length} of 49 changes match, from ${TUE} back`);
  // The day kept while the search changes.
  await type(doc, "c20-1.pem");
  assert.deepEqual(ids(doc), ["c20-1"]);
  assert.equal(count(doc).textContent, `1 of 49 changes matches, from ${TUE} back`);
  assert.equal(box(doc).value, "2026-10-20");
});

test("D5: a day before every change says so, with Show the newest; with a search, its words", async () => {
  const dated = ALL.filter((c) => c !== UNDATED);
  const { doc } = load({ extensions: "", url: URL, homeVm: quiet(), routes: routesFor(dated) });
  await tick(40);
  const OCT1 = "Thursday, Oct 1" + year;
  await choose(doc, "2026-10-01");
  assert.equal(rows(doc).length, 0);
  assert.equal(empty(doc).textContent, `No rule changed on or before ${OCT1}. Show the newest`);
  assert.equal(count(doc).hidden, false, "said by the status line");
  assert.ok(count(doc).classList.contains("sr-only"), "to a screen reader only");
  assert.equal(count(doc).textContent, `No rule changed on or before ${OCT1}.`);
  await type(doc, "stripe");
  assert.equal(empty(doc).firstChild.textContent, `No change matches “stripe” on or before ${OCT1}. `);
  const btn = empty(doc).querySelector("button");
  assert.equal(btn.textContent, "Show the newest");
  btn.click();
  await tick(40);
  assert.equal(box(doc).value, "");
  assert.ok(rows(doc).length > 0, "the matches from the newest");
  // A change with no time is kept, at the end, whatever the day.
  const u = load({ extensions: "", url: `${URL}?cday=2026-10-01`, homeVm: quiet(), routes: routesFor(ALL) });
  await tick(40);
  assert.deepEqual(ids(u.doc), ["c-none"]);
});

test("D6: a read cut at 500 says so, and a day before all of it says it looked only there", async () => {
  const many = Array.from({ length: 520 }, (_, i) => change(`m-${i}`, at(2026, 10, 26, 20) - i * 60_000));
  const { doc } = load({ extensions: "", url: `${URL}?cday=2026-10-20`, homeVm: quiet(), routes: routesFor(many) });
  await tick(40);
  assert.equal(rows(doc).length, 0);
  assert.equal(empty(doc).firstChild.textContent, `None of the newest 500 changes was made on or before ${TUE}. `);
  const some = [...many.slice(0, 495), ...Array.from({ length: 25 }, (_, i) => change(`o-${i}`, at(2026, 10, 19) - i * 60_000))];
  const s = load({ extensions: "", url: `${URL}?cday=2026-10-20`, homeVm: quiet(), routes: routesFor(some) });
  await tick(40);
  assert.deepEqual(ids(s.doc), ["o-0", "o-1", "o-2", "o-3", "o-4"]);
  assert.equal(count(s.doc).textContent, `From ${TUE} back, of the newest 500 changes`);
});

test("D7: ?cday= on load sets the box; Back keeps it; a link starts at the newest; no real date is no day", async () => {
  const { doc, window, calls } = load({ extensions: "", url: `${URL}?cday=2026-10-20`, homeVm: quiet(), routes: routesFor(ALL) });
  await tick(40);
  assert.equal(box(doc).value, "2026-10-20");
  assert.equal(newest(doc).hidden, false);
  assert.deepEqual(asked(calls), ["policy/changes?limit=500"], "the read of the day at once, never that of the newest 20");
  assert.equal(headings(doc)[0], TUE);
  assert.equal(doc.getElementById("answered-day").value, "", "Answered earlier keeps its own day");
  doc.querySelector('#nav [data-page-link="history"]').click();
  await tick(40);
  const from = window.location.pathname;
  window.history.back();
  await waitWhile(() => window.location.pathname === from);
  await tick(40);
  assert.equal(window.location.pathname + window.location.search, "/mandu/approvals?cday=2026-10-20");
  assert.equal(box(doc).value, "2026-10-20", "Back keeps the day");
  assert.equal(headings(doc)[0], TUE, "and its list");
  doc.querySelector('#nav [data-page-link="history"]').click();
  await tick(40);
  doc.querySelector('#nav [data-page-link="approvals"]').click();
  await tick(40);
  assert.equal(window.location.pathname + window.location.search, "/mandu/approvals");
  assert.equal(box(doc).value, "", "a link starts at the newest");
  assert.equal(ids(doc)[0], "c26-0");
  for (const bad of ["2026-02-30", "2026-1-5", "yesterday", "2026-10-20x"]) {
    const b = load({ extensions: "", url: `${URL}?cday=${bad}`, homeVm: quiet(), routes: routesFor(ALL) });
    await tick(40);
    assert.deepEqual(asked(b.calls), ["policy/changes?limit=21"], `?cday=${bad} is no day`);
    assert.equal(box(b.doc).value, "");
  }
  // Answered earlier's day is its own: `day=` leaves Rule changes at the newest.
  const a = load({ extensions: "", url: `${URL}?day=2026-10-20`, homeVm: quiet(), routes: routesFor(ALL) });
  await tick(40);
  assert.equal(box(a.doc).value, "");
  assert.equal(ids(a.doc)[0], "c26-0");
  // A change the address opens has no day, as it has no search.
  const o = load({ extensions: "", url: `${URL}/c26-3?cday=2026-10-20`, homeVm: quiet(), routes: routesFor(ALL) });
  await tick(40);
  assert.equal(box(o.doc).value, "");
});
