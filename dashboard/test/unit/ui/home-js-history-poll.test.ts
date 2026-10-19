/**
 * home-js-history-poll.test — dashboard.md §4.25ae *History follows the
 * poll*. History (`/history`) was read once, when the page opened: a session
 * that ended kept "running now", a new one never came in and the counts
 * stayed as they were, until the person opened the page again. Now each Home
 * poll that answered reads History's drawn rows again:
 *
 *   P1  a session that ended says so, a new one comes in on top, the counts
 *       and "N more sessions" follow, without a page change;
 *   P2  an answer the same as drawn leaves the list as it is (the same rows,
 *       the focus where it was); a changed one gives the focus back to the
 *       same row's Details, or to Show more;
 *   P3  more rows than one page drawn: the poll asks for that many; rows
 *       pushed down by a new session stay, as does the cursor of Show more;
 *       a row no longer listed goes;
 *   P4  a first read that failed comes back on the next poll; a poll whose
 *       read fails leaves the rows drawn;
 *   P5  no second read while one is out; none on another page; an answer
 *       after the page was left is not drawn;
 *   P6  more new sessions than the read reaches past: the read's rows and
 *       cursor, never the rows drawn before after a gap;
 *   P7  a click on a row the poll kept opens that row's session.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";

const URL = "http://127.0.0.1:4500/mandu/history";
const row = (id: string, over: Record<string, unknown> = {}) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", startedAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-01T10:05:00.000Z", state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 1, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null, ...over,
});
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const historyRows = (doc: any) => [...doc.querySelectorAll("#history-list .row.agent")] as any[];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ids = (doc: any) => historyRows(doc).map((r) => r.dataset.session);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rowOf = (doc: any, id: string) => historyRows(doc).find((r) => r.dataset.session === id);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = async (doc: any) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const historyCalls = (calls: any[]) => calls.filter((c) => c.url.startsWith("/mandu/api/home/history")).map((c) => c.url.slice("/mandu/api/".length));

/** A History route answering each read with the next answer (the last one
 *  again once they run out). */
function answers(...list: unknown[]) {
  let i = 0;
  return () => list[Math.min(i++, list.length - 1)];
}

test("P1: a poll draws History again: a session that ended says so, a new one comes in on top, the counts follow, no page change", async () => {
  const first = { total: 3, rows: [row("s2", { state: "running", secrets: { masked: 0, early: 0 } }), row("s1")], next: "s1" };
  const after = { total: 4, rows: [row("s3", { state: "running" }), row("s2", { lastAt: "2026-09-01T11:00:00.000Z", secrets: { masked: 2, early: 0 }, blocked: 1 }), row("s1")], next: "s1" };
  const { doc, calls } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": answers(first, after) } });
  await tick();
  assert.deepEqual(ids(doc), ["s2", "s1"]);
  assert.match(rowOf(doc, "s2").textContent, /running now, started/);
  assert.equal(doc.querySelector("#history-list .history-more span").textContent, "1 more session.");
  const heading = doc.querySelector("#page-history h1");
  await poll(doc);
  assert.deepEqual(historyCalls(calls), ["home/history", "home/history"], "the poll read History again");
  assert.deepEqual(ids(doc), ["s3", "s2", "s1"], "the new session on top");
  assert.match(rowOf(doc, "s3").textContent, /running now, started/);
  assert.match(rowOf(doc, "s2").textContent, /ended/, "the session that ended says so");
  assert.doesNotMatch(rowOf(doc, "s2").textContent, /running now/);
  assert.equal(rowOf(doc, "s2").querySelector(".dot").className, "dot", "its dot is no longer the running one");
  assert.match(rowOf(doc, "s2").textContent, /2 secrets masked, 1 action blocked/, "its counts follow");
  assert.equal(doc.querySelector("#history-list .history-more span").textContent, "1 more session.");
  assert.equal(doc.getElementById("page-history").hidden, false);
  assert.equal(doc.querySelector("#page-history h1"), heading);
  assert.equal(doc.defaultView.location.pathname, "/mandu/history");
});

test("P2: an answer as drawn leaves the list as it is; a changed one gives the focus back to the same row's Details, or to Show more", async () => {
  const a = { total: 3, rows: [row("s2", { state: "running" }), row("s1")], next: "s1" };
  const b = { total: 3, rows: [row("s2", { secrets: { masked: 3, early: 0 } }), row("s1")], next: "s1" };
  const c = { total: 4, rows: [row("s4", { state: "running" }), row("s2", { secrets: { masked: 3, early: 0 } }), row("s1")], next: "s1" };
  const { doc } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": answers(a, a, b, c) } });
  await tick();
  const drawn = historyRows(doc);
  const details = rowOf(doc, "s2").querySelector("a");
  details.focus();
  await poll(doc);
  assert.equal(historyRows(doc)[0], drawn[0], "the same answer draws nothing again");
  assert.equal(historyRows(doc)[1], drawn[1]);
  assert.equal(doc.activeElement, details, "the focus stays where it was");
  await poll(doc);
  // Only s2 changed: it is drawn anew, s1 is the row already there
  // (*The rows you read stay still*, home-js-rows-stay.test.ts).
  assert.notEqual(rowOf(doc, "s2"), drawn[0], "the changed row is drawn again");
  assert.equal(rowOf(doc, "s1"), drawn[1], "the row that did not change is kept");
  assert.match(rowOf(doc, "s2").textContent, /3 secrets masked/);
  assert.equal(doc.activeElement, rowOf(doc, "s2").querySelector("a"), "the focus is back on the same row's Details");
  doc.querySelector("#history-list .history-more button").focus();
  await poll(doc);
  assert.deepEqual(ids(doc), ["s4", "s2", "s1"]);
  const more = doc.querySelector("#history-list .history-more button");
  assert.equal(doc.activeElement, more, "the focus is back on Show more");
  assert.equal(doc.getElementById(more.getAttribute("aria-describedby")).textContent, "1 more session.");
});

test("P3: more rows than one page: the poll asks for as many; rows pushed down stay, with Show more's cursor; a row no longer listed goes", async () => {
  const page1 = Array.from({ length: 25 }, (_, i) => row(`a${String(i).padStart(2, "0")}`));
  const page2 = Array.from({ length: 5 }, (_, i) => row(`b${i}`));
  const routes = {
    "GET home/history": { total: 40, rows: page1, next: "a24" },
    "GET home/history?after=a24": { total: 40, rows: page2, next: "b4" },
    // A new session on top, a00 no longer listed: the 30 newest are n0, a01..a24, b0..b3.
    "GET home/history?limit=30": { total: 40, rows: [row("n0", { state: "running" }), ...page1.slice(1), ...page2.slice(0, 4)], next: "b3" },
    "GET home/history?after=b4": { total: 40, rows: [row("c0")], next: null },
  };
  const { doc, calls } = load({ extensions: "", url: URL, homeVm: home(), routes });
  await tick();
  doc.querySelector("#history-list .history-more button").click();
  await tick();
  assert.equal(historyRows(doc).length, 30);
  await poll(doc);
  assert.deepEqual(historyCalls(calls).slice(-1), ["home/history?limit=30"], "the poll reads as many rows as are drawn");
  const now = ids(doc);
  assert.equal(now[0], "n0", "the new session on top");
  assert.ok(!now.includes("a00"), "a row no longer listed goes");
  assert.deepEqual(now.slice(-2), ["b3", "b4"], "the row pushed past the read stays");
  assert.equal(now.length, 30);
  assert.equal(doc.querySelector("#history-list .history-more span").textContent, "10 more sessions.");
  doc.querySelector("#history-list .history-more button").click();
  await tick();
  assert.deepEqual(historyCalls(calls).slice(-1), ["home/history?after=b4"], "Show more goes on after the last row drawn");
  assert.equal(ids(doc).slice(-1)[0], "c0");
});

test("P4: a first read that failed comes back on the next poll; a poll whose read fails leaves the rows drawn", async () => {
  const fails = { status: 500, body: { error: "boom" } };
  const ok = { total: 1, rows: [row("s1", { state: "running" })], next: null };
  const { doc } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": answers(fails, ok, fails) } });
  await tick();
  assert.match(doc.getElementById("history-list").textContent, /^Could not read the history\. /);
  await poll(doc);
  assert.deepEqual(ids(doc), ["s1"], "the next poll draws the rows");
  const drawn = rowOf(doc, "s1");
  await poll(doc);
  assert.equal(rowOf(doc, "s1"), drawn, "a failed read leaves the rows as drawn");
  assert.doesNotMatch(doc.getElementById("history-list").textContent, /Could not read/);
});

test("P5: no second read while one is out, none on another page, and an answer after the page was left is not drawn", async () => {
  // Each read is answered when the test says (`answer`), in the order asked.
  const out: ((v: unknown) => void)[] = [];
  const { doc, calls } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": () => new Promise((r) => out.push(r)) } });
  await tick();
  assert.equal(out.length, 1, "the page's own read is out");
  await poll(doc);
  assert.equal(historyCalls(calls).length, 1, "the poll waits for the page's own read");
  out[0]!({ total: 1, rows: [row("s1", { state: "running" })], next: null });
  await tick();
  assert.match(rowOf(doc, "s1").textContent, /running now/);
  await poll(doc);
  assert.equal(historyCalls(calls).length, 2, "the next poll reads History again");
  // The page is left before that read answers: its answer is not drawn.
  doc.querySelector('#nav [data-page-link="home"]').click();
  await tick();
  out[1]!({ total: 1, rows: [row("s9")], next: null });
  await tick();
  assert.deepEqual(ids(doc), ["s1"], "an answer after the page was left is dropped");
  await poll(doc);
  assert.equal(historyCalls(calls).length, 2, "no History read on another page");
});

test("P6: a read that does not reach the rows drawn shows its own rows and cursor, never the old rows after a gap", async () => {
  const fresh = Array.from({ length: 25 }, (_, i) => row(`n${String(i).padStart(2, "0")}`));
  const routes = {
    "GET home/history": answers({ total: 30, rows: [row("s1"), row("s0")], next: "s0" }, { total: 60, rows: fresh, next: "n24" }),
    "GET home/history?after=n24": { total: 60, rows: [row("n25")], next: "n25" },
  };
  const { doc, calls } = load({ extensions: "", url: URL, homeVm: home(), routes });
  await tick();
  assert.deepEqual(ids(doc), ["s1", "s0"]);
  await poll(doc);
  assert.deepEqual(ids(doc), fresh.map((r) => r.id), "the 25 newest, and not s1, s0 under them: n25 and more lie between");
  assert.equal(doc.querySelector("#history-list .history-more span").textContent, "35 more sessions.");
  doc.querySelector("#history-list .history-more button").click();
  await tick();
  assert.deepEqual(historyCalls(calls).slice(-1), ["home/history?after=n24"], "Show more goes on from the read's own cursor");
  assert.equal(ids(doc).slice(-1)[0], "n25");
});

test("P7: a click on a row's prompt opens that session, also on a row the poll kept (one listener for every row, §4.25 *A click on a session's row opens it*)", async () => {
  const a = { total: 3, rows: [row("s3", { state: "running" }), row("s2"), row("s1")], next: null };
  const { doc, calls } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": answers(a) } });
  await tick();
  const third = rowOf(doc, "s1");
  await poll(doc);
  assert.equal(rowOf(doc, "s1"), third, "the poll kept the row's node");
  third.querySelector(".agent-what .sub").dispatchEvent(new doc.defaultView.MouseEvent("click", { bubbles: true, cancelable: true }));
  await tick();
  assert.equal(doc.defaultView.location.pathname, "/mandu/agents/s1", "the third session, not another");
  assert.equal(doc.getElementById("page-agent").hidden, false);
  assert.equal(doc.getElementById("page-history").hidden, true);
  assert.ok(calls.some((c) => c.url === "/mandu/api/home/agent?session=s1"));
});
