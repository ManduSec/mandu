/**
 * home-js-answered-day.test — dashboard.md §4.25 *Go to a day on Answered
 * earlier*. Approvals › Answered earlier was reachable past its newest 20
 * only by Show more, a read of 20 at a time, or by a search when a word of
 * the answer was remembered. Now a date box beside *Find an answer*, "Go to
 * a day", the same as History's (§4.25ae *Go to a day*), lists the answers
 * from that day back:
 *
 *   A1  the box: a native date box named "Go to a day" in the search form,
 *       today its latest day; Show the newest hidden while no day is set;
 *   A2  choosing a day reads `?before=` with the moment the next local day
 *       starts, lists only what that read found (never Home's newest 20),
 *       writes `day=` into the address (replaced, no new entry), says
 *       `From ${TUE} back` in the status line, heads the list with the day
 *       and shows Show the newest; Show more and Home's poll keep `before=`;
 *   A3  Show the newest clears the day: the box, the address, the read, the
 *       line; the newest 20 of Home again; the box takes the focus;
 *   A4  a search and a day hold together: every read carries both, the
 *       address both, and the line says the count from the day back;
 *   A5  nothing on or before the day: "You answered nothing on or before
 *       Tuesday, Oct 20." with Show the newest, said to a screen reader by
 *       the status line; with a search, "No answer matches “x” on or
 *       before …";
 *   A6  `?day=` on load sets the box and reads it; Back keeps it; a link to
 *       Approvals starts at the newest; a `day=` that is not a real date is
 *       no day.
 *
 * TZ pinned to New York, as History's test: the bound of Oct 20 is the
 * start of Oct 21 there.
 */
process.env.TZ = "America/New_York";

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";
import { waitWhile } from "../page-wait.js";

const URL = "http://127.0.0.1:4500/mandu/approvals";
const at = (y: number, m: number, d: number, h = 10) => new Date(y, m - 1, d, h).getTime();
const ans = (id: string, decidedAt: number, over: Record<string, unknown> = {}) => ({
  id,
  sentence: [{ kind: "text", text: `Claude Code wants to send your secret ${id.toUpperCase()} to ` }, { kind: "code", text: "api.stripe.com" }],
  outcome: "blocked", decidedAt, sessions: ["s1"],
  actions: [{ approve: true, scope: "always", label: "Always allow" }], ...over,
});
/** The start of the local day after `y-m-d` (the page's `before=`). */
const nextDay = (y: number, m: number, d: number) => new Date(y, m - 1, d + 1).getTime();
const OCT20 = nextDay(2026, 10, 20);
/** Oct 20, 2026 as a heading says it: with its year once the clock is past 2026. */
const TUE = new Date().getFullYear() === 2026 ? "Tuesday, Oct 20" : "Tuesday, Oct 20, 2026";
const NEWEST = Array.from({ length: 20 }, (_, i) => ans(`new-${i}`, at(2026, 10, 28) - i * 60_000));
const vm = () => home({ waiting: [], answered: NEWEST, answeredTotal: 63, verdict: "secrets-only" });
const FROM20 = { rows: [ans("d20a", at(2026, 10, 20, 15)), ans("d20b", at(2026, 10, 20, 9)), ans("d19", at(2026, 10, 19))], total: 41, next: "d19", before: { at: OCT20, all: 63 } };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const ids = (doc: Doc) => ([...doc.querySelectorAll("#approvals-answered .row.answered")] as Doc[]).map((r) => r.dataset.id);
const reads = (calls: Array<{ url: string }>) => calls.filter((c) => c.url.startsWith("/mandu/api/home/answered")).map((c) => c.url.slice("/mandu/api/".length));
const count = (doc: Doc) => doc.getElementById("answered-count");
const choose = async (doc: Doc, day: string) => {
  const box = doc.getElementById("answered-day");
  box.focus();
  box.value = day;
  box.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
  await tick();
};
const poll = async (doc: Doc) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };

test("A1: the box is a labelled native date box in Find an answer's form, today its latest day; no Show the newest", async () => {
  const { doc } = load({ extensions: "", url: URL, homeVm: vm() });
  await tick();
  const box = doc.getElementById("answered-day");
  assert.equal(box.getAttribute("type"), "date");
  assert.equal(doc.querySelector('label[for="answered-day"]').textContent, "Go to a day");
  assert.equal(box.closest("form"), doc.getElementById("answered-search"), "beside Find an answer");
  assert.ok(box.closest(".history-go-day"), "History's classes, so it wraps the same way");
  assert.equal(count(doc).contains(doc.getElementById("answered-newest")), false, "Show the newest is outside the live status line");
  const now = new Date();
  const today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
  assert.equal(box.max, today, "no day in the future");
  assert.equal(box.value, "");
  assert.equal(doc.getElementById("answered-newest").hidden, true);
});

test("A2: a day chosen reads ?before= the next local day's start, lists that read, writes day=, says where it starts; Show more and the poll keep it", async () => {
  const more = { rows: [ans("d18", at(2026, 10, 18))], total: 41, next: null, before: { at: OCT20, all: 63 } };
  const { doc, window, calls } = load({ extensions: "", url: URL, homeVm: vm(), routes: {
    [`GET home/answered?limit=20&before=${OCT20}`]: FROM20, [`GET home/answered?after=d19&limit=20&before=${OCT20}`]: more,
  } });
  await tick();
  assert.equal(ids(doc).length, 20, "the newest 20 of Home first");
  const entries = window.history.length;
  await choose(doc, "2026-10-20");
  assert.deepEqual(reads(calls), [`home/answered?limit=20&before=${OCT20}`]);
  assert.deepEqual(ids(doc), ["d20a", "d20b", "d19"], "only the answers from the day back, none of the newest");
  assert.equal(window.location.pathname + window.location.search, "/mandu/approvals?day=2026-10-20");
  assert.equal(window.history.length, entries, "replaced, not pushed");
  assert.equal(count(doc).hidden, false);
  assert.equal(count(doc).classList.contains("sr-only"), false);
  assert.equal(count(doc).textContent, `From ${TUE} back`);
  const heads = [...doc.querySelectorAll("#approvals-answered .history-day")].map((h: Doc) => h.textContent);
  assert.equal(heads[0], TUE, "the first heading is the day");
  assert.equal(heads.length, 2, "Oct 20 and Oct 19");
  assert.equal(doc.getElementById("answered-newest").hidden, false, "Show the newest beside the box");
  assert.equal(doc.activeElement, doc.getElementById("answered-day"), "the focus stays in the box");
  assert.equal(doc.querySelector("#approvals-answered .answered-more span").textContent, `Showing 3 of 41 answers from ${TUE} back.`, "Show more counts the cut list");
  doc.querySelector("#approvals-answered .answered-more button").click();
  await tick();
  assert.deepEqual(ids(doc), ["d20a", "d20b", "d19", "d18"]);
  await poll(doc);
  assert.deepEqual(reads(calls), [`home/answered?limit=20&before=${OCT20}`, `home/answered?after=d19&limit=20&before=${OCT20}`, `home/answered?limit=20&before=${OCT20}`], "the poll reads the same day");
  assert.deepEqual(ids(doc).slice(0, 3), ["d20a", "d20b", "d19"], "a poll never draws Home's newest over the day");
  // The same day again reads nothing.
  await choose(doc, "2026-10-20");
  assert.equal(reads(calls).length, 3);
});

test("A3: Show the newest clears the day: the box, the address, the line; the newest 20 again; the box focused", async () => {
  const { doc, window, calls } = load({ extensions: "", url: `${URL}?day=2026-10-20`, homeVm: vm(), routes: { [`GET home/answered?limit=20&before=${OCT20}`]: FROM20 } });
  await tick();
  assert.deepEqual(reads(calls), [`home/answered?limit=20&before=${OCT20}`]);
  assert.deepEqual(ids(doc), ["d20a", "d20b", "d19"]);
  doc.getElementById("answered-newest").click();
  await tick();
  assert.equal(doc.getElementById("answered-day").value, "");
  assert.equal(window.location.pathname + window.location.search, "/mandu/approvals");
  assert.equal(ids(doc).length, 20, "the newest 20 of Home, with no read of its own");
  assert.equal(ids(doc)[0], "new-0");
  assert.equal(count(doc).hidden, true, "no day, no search: no line");
  assert.equal(doc.getElementById("answered-newest").hidden, true);
  assert.equal(doc.activeElement, doc.getElementById("answered-day"));
  // Clearing the box itself (the browser's own clear) does the same.
  await choose(doc, "2026-10-20");
  assert.equal(window.location.search, "?day=2026-10-20");
  await choose(doc, "");
  assert.equal(window.location.search, "");
  assert.equal(ids(doc)[0], "new-0");
});

test("A4: a search and a day hold together: both in every read and the address; the count from the day back", async () => {
  const q = { rows: [ans("q1", at(2026, 10, 27))], total: 12, next: null, query: { text: "stripe", all: 63 } };
  const qd = { rows: [ans("d20a", at(2026, 10, 20, 15)), ans("d19", at(2026, 10, 19))], total: 2, next: null, query: { text: "stripe", all: 63 }, before: { at: OCT20, all: 63 } };
  const { doc, window, calls } = load({ extensions: "", url: `${URL}?q=stripe`, homeVm: vm(), routes: {
    "GET home/answered?limit=20&q=stripe": q, [`GET home/answered?limit=20&q=stripe&before=${OCT20}`]: qd,
  } });
  await tick();
  await choose(doc, "2026-10-20");
  assert.equal(window.location.search, "?q=stripe&day=2026-10-20");
  assert.deepEqual(reads(calls), ["home/answered?limit=20&q=stripe", `home/answered?limit=20&q=stripe&before=${OCT20}`]);
  assert.deepEqual(ids(doc), ["d20a", "d19"]);
  assert.equal(count(doc).textContent, `2 of 63 answers match, from ${TUE} back`);
  // Clearing the search keeps the day.
  doc.getElementById("answered-q").focus();
  doc.getElementById("answered-q").value = "";
  doc.getElementById("answered-search").dispatchEvent(new doc.defaultView.Event("submit", { bubbles: true, cancelable: true }));
  await tick();
  assert.equal(window.location.search, "?day=2026-10-20");
  assert.equal(reads(calls).at(-1), `home/answered?limit=20&before=${OCT20}`);
});

test("A5: nothing on or before the day says so, with Show the newest; with a search, its words too", async () => {
  const none = { rows: [], total: 0, next: null, before: { at: OCT20, all: 63 } };
  const { doc, window } = load({ extensions: "", url: `${URL}?day=2026-10-20`, homeVm: vm(), routes: { [`GET home/answered?limit=20&before=${OCT20}`]: none } });
  await tick();
  const list = doc.getElementById("approvals-answered");
  assert.equal(list.textContent, `You answered nothing on or before ${TUE}. Show the newest`);
  assert.equal(count(doc).hidden, false);
  assert.equal(count(doc).classList.contains("sr-only"), true, "said to a screen reader only");
  assert.equal(count(doc).textContent, `You answered nothing on or before ${TUE}.`);
  assert.equal(doc.getElementById("answered-search").hidden, false, "the box stays");
  list.querySelector("button.history-newest").click();
  await tick();
  assert.equal(window.location.search, "");
  assert.equal(ids(doc)[0], "new-0");
  assert.equal(doc.activeElement, doc.getElementById("answered-day"));
  const q = { rows: [], total: 0, next: null, query: { text: "x", all: 63 }, before: { at: OCT20, all: 63 } };
  const s = load({ extensions: "", url: `${URL}?q=x&day=2026-10-20`, homeVm: vm(), routes: { [`GET home/answered?limit=20&q=x&before=${OCT20}`]: q } });
  await tick();
  assert.equal(s.doc.getElementById("approvals-answered").textContent, `No answer matches “x” on or before ${TUE}. Show the newest`);
});

test("A6: ?day= on load sets the box; Back keeps it; a link starts at the newest; a day that is no date is none", async () => {
  const { doc, window, calls } = load({ extensions: "", url: `${URL}?day=2026-10-20`, homeVm: vm(), routes: { [`GET home/answered?limit=20&before=${OCT20}`]: FROM20 } });
  await tick();
  assert.equal(doc.getElementById("answered-day").value, "2026-10-20");
  assert.equal(doc.getElementById("answered-newest").hidden, false);
  assert.equal(doc.getElementById("answered-search").hidden, false);
  doc.querySelector('#nav [data-page-link="history"]').click();
  await tick();
  const from = window.location.pathname;
  window.history.back();
  await waitWhile(() => window.location.pathname === from);
  await tick();
  assert.equal(window.location.pathname + window.location.search, "/mandu/approvals?day=2026-10-20");
  assert.equal(doc.getElementById("answered-day").value, "2026-10-20", "Back keeps the day");
  assert.deepEqual(ids(doc), ["d20a", "d20b", "d19"], "and its list");
  doc.querySelector('#nav [data-page-link="history"]').click();
  await tick();
  doc.querySelector('#nav [data-page-link="approvals"]').click();
  await tick();
  assert.equal(window.location.pathname + window.location.search, "/mandu/approvals");
  assert.equal(doc.getElementById("answered-day").value, "", "a link starts at the newest");
  assert.equal(ids(doc)[0], "new-0");
  for (const bad of ["2026-02-30", "2026-1-5", "yesterday", "2026-10-20x"]) {
    const b = load({ extensions: "", url: `${URL}?day=${bad}`, homeVm: vm() });
    await tick();
    assert.deepEqual(reads(b.calls), [], `?day=${bad} is no day`);
    assert.equal(b.doc.getElementById("answered-day").value, "");
  }
  // An answer the address opens has no day, as it has no search.
  const o = load({ extensions: "", url: `${URL}/new-3`, homeVm: vm() });
  await tick();
  assert.equal(o.doc.getElementById("answered-day").value, "");
});
