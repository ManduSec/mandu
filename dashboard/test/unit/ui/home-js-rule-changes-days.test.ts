/**
 * home-js-rule-changes-days.test — dashboard.md §4.25 *Changes sit under
 * their day*. Approvals › Rule changes was one flat run of rows: the day a
 * change was made was only in its small dim time line, and a screen reader
 * had no heading to go from day to day. Now History's day heading (§4.25ae
 * *Sessions sit under their day*), as Answered earlier draws it (§4.34
 * *Answers sit under their day*), goes before the first change of each
 * local day, an h3 under the section's h2:
 *
 *   D1  changes of today, yesterday and an older day sit under "Today",
 *       "Yesterday" and "Wednesday, Oct 14", each heading once and in
 *       order, with the day as its <time datetime>; two changes of one day
 *       share one heading; the rows keep their own time line; the patterns
 *       hidden note stays first, above the first heading;
 *   D2  a change with no time starts no day;
 *   D3  Show more that continues the last day adds no second heading; one
 *       that starts a new day adds its heading, and the first row it
 *       brought (not the heading) takes the focus;
 *   D4  a Find result is grouped the same way: a day with no match has no
 *       heading, and "No change matches" has none;
 *   D5  Undo on a row under a heading works, and its words stay on that
 *       row, under the same heading;
 *   D6  a heading carries no data-id nor data-proposal: a link to a change,
 *       by its id or by that of the request it answered, marks its row;
 *   D7  past midnight, the next poll says "Yesterday" where "Today" was.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the shared
 * fetch stub (home-js-fixtures.ts). Axes: none (display only).
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
const T = (text: string) => ({ kind: "text", text });
const C = (text: string) => ({ kind: "code", text });
/** A change: the files make a secret, `host` lets a send to a host. */
const change = (id: string, createdAt: number | null, over: Record<string, unknown> = {}) => ({
  id, sentence: "You changed a rule on the Rules page", session: null, createdAt, undone: false, undoable: true,
  rows: [[T("Make "), C(`~/proj/${id}.pem`), T(" a secret no AI may read")]],
  ...over,
});
const host = (id: string, createdAt: number) => change(id, createdAt, { rows: [[T("Always allow sending to "), C("api.stripe.com")]] });
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;
const list = (doc: El) => doc.getElementById("approvals-rule-history");
const headings = (doc: El) => [...list(doc).querySelectorAll(".history-day")] as El[];
const rowOf = (doc: El, id: string) => ([...list(doc).querySelectorAll(".row.answered")] as El[]).find((r) => r.dataset.id === id);
/** The list in page order: a heading by its words, a row by its id, the
 *  Show more line as "more", the patterns note as "patterns". */
const order = (doc: El) => ([...list(doc).children] as El[]).map((x) =>
  x.matches(".history-day") ? `# ${x.textContent}` : x.matches(".row.answered") ? x.dataset.id
    : x.matches(".changes-more") ? "more" : x.matches(".patterns-hidden") ? "patterns" : x.className);
const poll = async (doc: El) => {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(40);
};
const quiet = () => home({ waiting: [], verdict: "protected", headline: "Your secrets are guarded." });
/** Approvals over `changes` (newest first) with its clock at `clock.now`
 *  (moved by the test): the read of 21 gives the newest 21, that of 41 the
 *  newest 41, that of 500 every one. */
function page(changes: unknown[], { routes = {}, clock = { now: NOW }, url = URL, extra = {} }: { routes?: Record<string, unknown>; clock?: { now: number }; url?: string; extra?: Record<string, unknown> } = {}) {
  const read = (k: number) => () => ({ changes: changes.slice(0, k), ...extra });
  return {
    clock,
    ...load({
      extensions: "", url, homeVm: quiet(),
      routes: {
        "GET policy/proposals?status=pending": { proposals: [] },
        "GET policy/changes?limit=21": read(21), "GET policy/changes?limit=41": read(41), "GET policy/changes?limit=500": read(500),
        ...routes,
      },
      before: (w: El) => { w.Date.now = () => clock.now; },
    }),
  };
}

test("D1: changes of today, yesterday and an older day sit under their day, each heading once, an h3 under the section's h2", async () => {
  const { doc } = page([change("a", TODAY), change("b", TODAY_EARLY), change("c", YESTERDAY), change("d", THREE_DAYS), change("e", THREE_DAYS)], { extra: { patternsHidden: true } });
  await tick(40);
  assert.deepEqual(order(doc), ["patterns", "# Today", "a", "b", "# Yesterday", "c", "# Wednesday, Oct 14", "d", "e"], "the patterns note stays first");
  const h = headings(doc);
  assert.deepEqual(h.map((x) => x.tagName), ["H3", "H3", "H3"], "a real heading, one level under Rule changes' h2");
  assert.deepEqual(h.map((x) => x.querySelector("time").getAttribute("datetime")), ["2026-10-17", "2026-10-16", "2026-10-14"]);
  assert.equal(doc.querySelector("#approvals-rule-history-block h2").textContent, "Rule changes");
  const when = rowOf(doc, "a").querySelector(".answered-when time.when");
  assert.equal(when.getAttribute("datetime"), new Date(TODAY).toISOString(), "the row keeps its own time line");
  assert.match(when.textContent, /^Oct 17, 12:00 · /);
});

test("D2: a change with no time starts no day", async () => {
  const { doc } = page([change("a", TODAY), change("x", null), change("c", YESTERDAY)]);
  await tick(40);
  assert.deepEqual(order(doc), ["# Today", "a", "x", "# Yesterday", "c"]);
  const alone = page([change("x", null)]);
  await tick(40);
  assert.deepEqual(order(alone.doc), ["x"]);
});

test("D3: Show more that continues the last day adds no heading; one on a new day adds its heading, the focus on the row", async () => {
  // 25 of today, then 10 of yesterday: the newest 20, then the rest.
  const today = Array.from({ length: 25 }, (_, i) => change("t" + String(i).padStart(2, "0"), TODAY - i * 60_000));
  const older = Array.from({ length: 10 }, (_, i) => change("y" + i, YESTERDAY - i * 60_000));
  // Only today's: Show more continues Today.
  const sameDay = page(today.slice(0, 22));
  await tick(40);
  assert.deepEqual(order(sameDay.doc), ["# Today", ...today.slice(0, 20).map((c) => c.id), "more"]);
  list(sameDay.doc).querySelector(".changes-more button.show-rest").click();
  await tick(40);
  assert.deepEqual(order(sameDay.doc), ["# Today", ...today.slice(0, 22).map((c) => c.id)], "the page continues Today: no second heading");
  assert.equal(sameDay.doc.activeElement, rowOf(sameDay.doc, "t20"), "the first row it brought takes the focus");
  // Today's 25, then yesterday's: Show more brings Yesterday's heading.
  const both = page([...today, ...older]);
  await tick(40);
  list(both.doc).querySelector(".changes-more button.show-rest").click();
  await tick(40);
  assert.deepEqual(order(both.doc), ["# Today", ...today.map((c) => c.id), "# Yesterday", ...older.map((c) => c.id)]);
  assert.equal(both.doc.activeElement, rowOf(both.doc, "t20"), "a row, never a heading, takes the focus");
});

test("D4: a Find result sits under its days; a day with no match has none, nor does No change matches", async () => {
  const all = [host("a", TODAY), change("b", TODAY), change("c", YESTERDAY), host("d", THREE_DAYS)];
  const found = page(all, { url: URL + "?changes=stripe" });
  await tick(40);
  assert.deepEqual(order(found.doc), ["# Today", "a", "# Wednesday, Oct 14", "d"], "Yesterday had no match: no heading");
  const none = page(all, { url: URL + "?changes=pastebin" });
  await tick(40);
  assert.equal(headings(none.doc).length, 0);
  assert.match(list(none.doc).textContent, /No change matches/);
});

test("D5: Undo on a row under a heading works, and its words stay on that row", async () => {
  let all = [change("a", TODAY), change("c", YESTERDAY), change("d", YESTERDAY)];
  const { doc, calls } = page([], {
    routes: {
      "GET policy/changes?limit=21": () => ({ changes: all.slice(0, 21) }),
      "POST policy/changes/c/undo": () => ((all = all.map((c) => (c.id === "c" ? { ...c, undone: true, undoable: false } : c))), {}),
    },
  });
  await tick(40);
  assert.deepEqual(order(doc), ["# Today", "a", "# Yesterday", "c", "d"]);
  const undo = [...rowOf(doc, "c").querySelectorAll("button")].find((b: El) => b.textContent === "Undo");
  undo.click();
  await tick(60);
  assert.ok(calls.some((c: El) => c.method === "POST" && c.url === "/mandu/api/policy/changes/c/undo"));
  assert.deepEqual(order(doc), ["# Today", "a", "# Yesterday", "c", "d"], "the row stays under its day");
  assert.match(rowOf(doc, "c").textContent, /Undone/);
  for (const h of headings(doc)) assert.doesNotMatch(h.textContent, /Undo/, "no words of the Undo on a heading");
});

test("D6: a heading has no data-id nor data-proposal, so a link to a change marks its row", async () => {
  const all = [change("pc-000003", TODAY), change("pc-000002", YESTERDAY, { proposalId: "pp-000009" }), change("pc-000001", THREE_DAYS)];
  const byId = page(all, { url: URL + "/pc-000002" });
  await tick(40);
  for (const h of headings(byId.doc)) {
    assert.equal(h.dataset.id, undefined);
    assert.equal(h.dataset.proposal, undefined);
    assert.equal(h.matches(".row"), false);
  }
  const marked = (doc: El) => ([...doc.querySelectorAll("#page-approvals .focus")] as El[]).map((x) => x.dataset.id);
  assert.deepEqual(marked(byId.doc), ["pc-000002"], "the row is marked, no heading");
  const byRequest = page(all, { url: URL + "/pp-000009" });
  await tick(40);
  assert.deepEqual(marked(byRequest.doc), ["pc-000002"], "by the request it answered, too");
});

test("D7: past midnight the next poll says Yesterday where Today was", async () => {
  const clock = { now: Date.parse("2026-10-17T14:59:00.000Z") }; // Oct 17, 23:59
  const { doc } = page([change("a", TODAY), change("c", YESTERDAY)], { clock });
  await tick(40);
  assert.deepEqual(order(doc), ["# Today", "a", "# Yesterday", "c"]);
  clock.now = Date.parse("2026-10-17T15:01:00.000Z"); // Oct 18, 00:01
  await poll(doc);
  assert.deepEqual(order(doc), ["# Yesterday", "a", "# Friday, Oct 16", "c"]);
});
