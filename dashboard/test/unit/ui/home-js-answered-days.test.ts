/**
 * home-js-answered-days.test — dashboard.md §4.34 *Answers sit under their
 * day*. Approvals › Answered earlier was one flat run of rows: the day an
 * answer belonged to was only in its small dim time line, and a screen
 * reader had no heading to go from day to day. Now History's day heading
 * (§4.25ae *Sessions sit under their day*) goes before the first answer of
 * each local day, an h3 under the section's h2:
 *
 *   N1  answers of today, yesterday and an older day sit under "Today",
 *       "Yesterday" and "Wednesday, Oct 14", each heading once and in
 *       order, with the day as its <time datetime>; two answers of one day
 *       share one heading; the rows keep their own time line;
 *   N2  an answer with no time starts no day;
 *   N3  Show more that continues the last day adds no second heading; one
 *       that starts a new day adds its heading, and the first row it
 *       brought (not the heading) takes the focus;
 *   N4  a Find result is grouped the same way;
 *   N5  past midnight, the next poll says "Yesterday" where "Today" was;
 *   N6  a heading carries no data-id: a link to an answer marks its row,
 *       never a heading.
 *
 * Axes: none (display only).
 */
process.env.TZ = "Asia/Seoul"; // UTC+9, no daylight saving time

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";

const URL = "http://127.0.0.1:4500/mandu/approvals";
/** Saturday Oct 17 2026, 15:00 in Seoul. */
const NOW = Date.parse("2026-10-17T06:00:00.000Z");
const TODAY = Date.parse("2026-10-17T03:00:00.000Z"); // Oct 17, 12:00 in Seoul
const TODAY_EARLY = Date.parse("2026-10-16T15:10:00.000Z"); // Oct 17, 00:10 in Seoul
const YESTERDAY = Date.parse("2026-10-16T05:00:00.000Z"); // Friday Oct 16, 14:00
const THREE_DAYS = Date.parse("2026-10-14T05:00:00.000Z"); // Wednesday Oct 14
const ans = (id: string, decidedAt: number | null, over: Record<string, unknown> = {}) => ({
  id,
  sentence: [{ kind: "text", text: `Claude Code wants to send your secret KEY_${id} to ` }, { kind: "code", text: "pastebin.com" }],
  outcome: "blocked", decidedAt, sessions: ["s1"],
  actions: [{ approve: true, scope: "always", label: "Always allow" }], ...over,
});
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const list = (doc: El) => doc.getElementById("approvals-answered");
const headings = (doc: El) => [...list(doc).querySelectorAll(".history-day")] as El[];
const rowOf = (doc: El, id: string) => ([...list(doc).querySelectorAll(".row.answered")] as El[]).find((r) => r.dataset.id === id);
/** The list in page order: a heading by its words, a row by its id, the
 *  Show more line as "more". */
const order = (doc: El) => ([...list(doc).children] as El[]).map((x) =>
  x.matches(".history-day") ? `# ${x.textContent}` : x.matches(".row.answered") ? x.dataset.id : x.matches(".answered-more") ? "more" : x.className);
const poll = async (doc: El) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };
const vm = (rows: unknown[], total = rows.length) => home({ waiting: [], answered: rows, answeredTotal: total, verdict: "secrets-only" });
/** Approvals with its clock at `clock.now` (moved by the test). */
function page(rows: unknown[], { total = rows.length, routes = {}, clock = { now: NOW }, url = URL }: { total?: number; routes?: Record<string, unknown>; clock?: { now: number }; url?: string } = {}) {
  return { clock, ...load({ extensions: "", url, homeVm: vm(rows, total), routes, before: (w: El) => { w.Date.now = () => clock.now; } }) };
}

test("N1: answers of today, yesterday and an older day sit under their day, each heading once, an h3 under the section's h2", async () => {
  const { doc } = page([ans("a", TODAY), ans("b", TODAY_EARLY), ans("c", YESTERDAY), ans("d", THREE_DAYS), ans("e", THREE_DAYS)]);
  await tick();
  assert.deepEqual(order(doc), ["# Today", "a", "b", "# Yesterday", "c", "# Wednesday, Oct 14", "d", "e"]);
  const h = headings(doc);
  assert.deepEqual(h.map((x) => x.tagName), ["H3", "H3", "H3"], "a real heading, one level under Answered earlier's h2");
  assert.deepEqual(h.map((x) => x.querySelector("time").getAttribute("datetime")), ["2026-10-17", "2026-10-16", "2026-10-14"]);
  assert.equal(doc.querySelector("#approvals-answered-block h2").textContent, "Answered earlier");
  const when = rowOf(doc, "a").querySelector(".answered-when time.when");
  assert.equal(when.getAttribute("datetime"), new Date(TODAY).toISOString(), "the row keeps its own time line");
  assert.match(when.textContent, /^Oct 17, 12:00 · /);
});

test("N2: an answer with no time starts no day", async () => {
  const { doc } = page([ans("a", TODAY), ans("x", null), ans("c", YESTERDAY)]);
  await tick();
  assert.deepEqual(order(doc), ["# Today", "a", "x", "# Yesterday", "c"]);
  const alone = page([ans("x", null)]);
  await tick();
  assert.deepEqual(order(alone.doc), ["x"]);
});

test("N3: Show more that continues the last day adds no heading; one on a new day adds its heading, the focus on the row", async () => {
  const first = [ans("a0", TODAY), ans("a1", TODAY)];
  const routes = {
    "GET home/answered?after=a1&limit=20": { rows: [ans("a2", TODAY), ans("a3", TODAY)], total: 6, next: "a3" },
    "GET home/answered?after=a3&limit=20": { rows: [ans("c0", YESTERDAY), ans("c1", YESTERDAY)], total: 6, next: null },
  };
  const { doc } = page(first, { total: 6, routes });
  await tick();
  assert.deepEqual(order(doc), ["# Today", "a0", "a1", "more"]);
  list(doc).querySelector(".answered-more button.show-rest").click();
  await tick();
  assert.deepEqual(order(doc), ["# Today", "a0", "a1", "a2", "a3", "more"], "the page continues Today");
  assert.equal(doc.activeElement, rowOf(doc, "a2"), "the first row it brought takes the focus");
  list(doc).querySelector(".answered-more button.show-rest").click();
  await tick();
  assert.deepEqual(order(doc), ["# Today", "a0", "a1", "a2", "a3", "# Yesterday", "c0", "c1"]);
  assert.equal(doc.activeElement, rowOf(doc, "c0"), "the row, not its heading, takes the focus");
});

test("N4: a Find result sits under its days; none over No answer matches", async () => {
  const all = [ans("a", TODAY), ans("b", TODAY), ans("c", YESTERDAY), ans("d", THREE_DAYS)];
  const routes = {
    "GET home/answered?limit=20&q=pastebin": { rows: [ans("a", TODAY), ans("d", THREE_DAYS)], total: 2, next: null, query: { text: "pastebin", all: 4 } },
    "GET home/answered?limit=20&q=nothing": { rows: [], total: 0, next: null, query: { text: "nothing", all: 4 } },
  };
  const found = page(all, { routes, url: `${URL}?q=pastebin` });
  await tick();
  assert.deepEqual(order(found.doc), ["# Today", "a", "# Wednesday, Oct 14", "d"]);
  const none = page(all, { routes, url: `${URL}?q=nothing` });
  await tick();
  assert.equal(headings(none.doc).length, 0);
  assert.match(list(none.doc).textContent, /No answer matches/);
});

test("N5: past midnight the next poll says Yesterday where Today was", async () => {
  const clock = { now: Date.parse("2026-10-17T14:59:00.000Z") }; // Oct 17, 23:59
  const { doc } = page([ans("a", TODAY), ans("c", YESTERDAY)], { clock });
  await tick();
  assert.deepEqual(order(doc), ["# Today", "a", "# Yesterday", "c"]);
  clock.now = Date.parse("2026-10-17T15:01:00.000Z"); // Oct 18, 00:01
  await poll(doc);
  assert.deepEqual(order(doc), ["# Yesterday", "a", "# Friday, Oct 16", "c"]);
});

test("N6: a heading has no data-id, so a link to an answer marks its row", async () => {
  const { doc } = page([ans("a", TODAY), ans("c", YESTERDAY)], { url: `${URL}/c` });
  await tick();
  for (const h of headings(doc)) assert.equal(h.dataset.id, undefined);
  const marked = [...list(doc).querySelectorAll(".focus")] as El[];
  assert.deepEqual(marked.map((x) => x.dataset.id), ["c"], "the row is marked, no heading");
});
