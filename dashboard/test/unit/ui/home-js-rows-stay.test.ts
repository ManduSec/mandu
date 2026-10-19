/**
 * home-js-rows-stay.test — dashboard.md §4.25 *The rows you read stay
 * still*. Home's Running now and Earlier and the History page follow the
 * poll, and until 2026-10-15 a change drew the whole list again from
 * nothing. The browser's scroll anchoring holds the rows in view still only
 * while its anchor node stays in the page, so a session coming in above
 * them moved every row in view by a whole row (headless Chromium: History
 * at 1280×800, 73 px; Home's Earlier at 390×844, 148 px). Now a row whose
 * session is drawn from what it was is the node already there:
 *
 *   S1  Running now: a new session on top, a changed row drawn anew, the
 *       rows that did not change kept in place; a focused Details on a kept
 *       row keeps the focus;
 *   S2  Earlier: a session that ended comes in on top, a session no longer
 *       listed goes, the rest are kept; Show them keeps the rows above it
 *       and gives the focus to the first row it brought;
 *   S3  History: a new session on top, a session that ended drawn anew, the
 *       rest kept; Show more keeps the rows drawn and lands on the first new
 *       one; the focus on a changed row's Details comes back to its Details;
 *   S4  a list that turns empty, or could not be read, says so with no row
 *       left, and its rows come back drawn when it can be read again;
 *   S5  the order is the answer's, even when the rows kept change places;
 *   S6  what a kept row holds stays: its opened note.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";

const HISTORY_URL = "http://127.0.0.1:4500/mandu/history";
const NOW = new Date().toISOString();
const agent = (id: string, over: Record<string, unknown> = {}) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", startedAt: NOW, lastAt: NOW, state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 1, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null, ...over,
});
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rowsIn = (doc: any, list: string) => [...doc.querySelectorAll(`#${list} .row.agent`)] as any[];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const idsIn = (doc: any, list: string) => rowsIn(doc, list).map((r) => r.dataset.session);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rowIn = (doc: any, list: string, id: string) => rowsIn(doc, list).find((r) => r.dataset.session === id);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const byId = (doc: any, list: string) => new Map(rowsIn(doc, list).map((r) => [r.dataset.session, r]));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = async (doc: any) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };
/** Watches `list` for rows taken out of it, moves included (a node put
 *  back elsewhere is taken out first, and the browser's anchor goes with
 *  it); the returned call stops and gives them. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function watchTakenOut(doc: any, list: string): () => Set<unknown> {
  const out = new Set<unknown>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const note = (recs: any[]) => { for (const r of recs) for (const x of r.removedNodes) out.add(x); };
  const mo = new doc.defaultView.MutationObserver(note);
  mo.observe(doc.getElementById(list), { childList: true });
  return () => { note(mo.takeRecords()); mo.disconnect(); return out; };
}
/** A route answering each read with the next answer (the last one again once they run out). */
function answers(...list: unknown[]) {
  let i = 0;
  return () => list[Math.min(i++, list.length - 1)];
}
const homeWith = (agents: unknown[]) => home({ waiting: [], waitingKnown: true, verdict: "ok", headline: "Your secrets are guarded.", agents });

test("S1: Running now keeps the rows that did not change: a new session on top, a changed row drawn anew, the focus kept", async () => {
  const r1 = agent("r1", { state: "running" });
  const r2 = agent("r2", { state: "running" });
  const r3 = agent("r3", { state: "running" });
  const { doc, setHome } = load({ extensions: "", homeVm: homeWith([r1, r2, r3]) });
  await tick();
  assert.deepEqual(idsIn(doc, "home-agents"), ["r1", "r2", "r3"]);
  const before = byId(doc, "home-agents");
  const details = before.get("r3").querySelector("a");
  details.focus();
  const takenOut = watchTakenOut(doc, "home-agents");
  setHome(homeWith([agent("r0", { state: "running" }), r1, agent("r2", { state: "running", secrets: { masked: 4, early: 0 } }), r3]));
  await poll(doc);
  const out = takenOut();
  assert.ok(!out.has(before.get("r1")) && !out.has(before.get("r3")), "a kept row is never taken out, not even to be put back");
  assert.deepEqual(idsIn(doc, "home-agents"), ["r0", "r1", "r2", "r3"], "the new session on top, the order as answered");
  assert.equal(rowIn(doc, "home-agents", "r1"), before.get("r1"), "a row that did not change is the node already there");
  assert.equal(rowIn(doc, "home-agents", "r3"), before.get("r3"));
  assert.notEqual(rowIn(doc, "home-agents", "r2"), before.get("r2"), "a changed row is drawn anew");
  assert.match(rowIn(doc, "home-agents", "r2").textContent, /4 secrets masked/);
  assert.equal(doc.activeElement, details, "the focused Details is the same element, never dropped");
  assert.equal(doc.getElementById("home-agents").children.length, 4, "no row twice, nothing left over");
});

test("S2: Earlier keeps its rows when a session that ended comes in on top; one no longer listed goes; Show them keeps the rows above", async () => {
  const ended = Array.from({ length: 12 }, (_, i) => agent(`e${String(i).padStart(2, "0")}`));
  const { doc, setHome } = load({ extensions: "", homeVm: homeWith(ended) });
  await tick();
  assert.equal(rowsIn(doc, "home-earlier").length, 10);
  const before = byId(doc, "home-earlier");
  // A session that just ended comes in on top; e05 is no longer in the window.
  const next = [agent("n0"), ...ended.filter((a) => a.id !== "e05")];
  const takenOut = watchTakenOut(doc, "home-earlier");
  setHome(homeWith(next));
  await poll(doc);
  const out = takenOut();
  const now = idsIn(doc, "home-earlier");
  for (const id of now.slice(1)) assert.ok(!out.has(before.get(id)), `${id} is never taken out`);
  assert.deepEqual(now, next.slice(0, 10).map((a) => a.id), "the answer's first ten, in its order");
  assert.ok(!now.includes("e05"), "the session no longer listed goes");
  for (const id of now.slice(1)) assert.equal(rowIn(doc, "home-earlier", id), before.get(id), `${id} is kept`);
  const kept = rowsIn(doc, "home-earlier");
  doc.querySelector("#home-earlier .earlier-more button").click();
  await tick();
  assert.equal(rowsIn(doc, "home-earlier").length, 12);
  assert.deepEqual(rowsIn(doc, "home-earlier").slice(0, 10), kept, "Show them keeps the rows above it");
  assert.equal(doc.activeElement, rowsIn(doc, "home-earlier")[10], "the first row it brought takes the focus");
  assert.equal(doc.querySelector("#home-earlier .earlier-more"), null);
});

test("S3: History keeps its rows: a new session on top, one that ended drawn anew; Show more keeps the rows drawn; a changed row's Details gets the focus back", async () => {
  const page1 = Array.from({ length: 25 }, (_, i) => agent(`a${String(i).padStart(2, "0")}`));
  const running = agent("a00", { state: "running" });
  const first = [running, ...page1.slice(1)];
  const routes = {
    "GET home/history": { total: 30, rows: first, next: "a24" },
    // A new session on top and a00 ended; the poll reads as many rows as are drawn.
    "GET home/history?limit=30": { total: 31, rows: [agent("n0", { state: "running" }), ...page1, ...["b0", "b1", "b2", "b3"].map((id) => agent(id))], next: "b3" },
    "GET home/history?after=a24": { total: 30, rows: Array.from({ length: 5 }, (_, i) => agent(`b${i}`)), next: null },
  };
  const { doc } = load({ extensions: "", url: HISTORY_URL, homeVm: home(), routes });
  await tick();
  assert.equal(rowsIn(doc, "history-list").length, 25);
  const page = rowsIn(doc, "history-list");
  doc.querySelector("#history-list .history-more button").click();
  await tick();
  assert.equal(rowsIn(doc, "history-list").length, 30);
  assert.deepEqual(rowsIn(doc, "history-list").slice(0, 25), page, "Show more keeps the rows drawn");
  assert.equal(doc.activeElement, rowsIn(doc, "history-list")[25], "and lands on the first row it brought");
  const before = byId(doc, "history-list");
  const details = before.get("a00").querySelector("a");
  details.focus();
  const takenOut = watchTakenOut(doc, "history-list");
  await poll(doc);
  const out = takenOut();
  const now = idsIn(doc, "history-list");
  for (const id of now.slice(2)) assert.ok(!out.has(before.get(id)), `${id} is never taken out`);
  assert.equal(now[0], "n0", "the new session on top");
  assert.deepEqual(now.slice(-5), ["b0", "b1", "b2", "b3", "b4"], "the rows past the read stay");
  assert.notEqual(rowIn(doc, "history-list", "a00"), before.get("a00"), "the session that ended is drawn anew");
  assert.match(rowIn(doc, "history-list", "a00").textContent, /ended/);
  for (const id of now.slice(2)) assert.equal(rowIn(doc, "history-list", id), before.get(id), `${id} is kept`);
  assert.equal(doc.activeElement, rowIn(doc, "history-list", "a00").querySelector("a"), "the focus is back on the changed row's Details");
});

test("S4: a list that turns empty, or could not be read, keeps no row; its rows are drawn again when it can be read", async () => {
  const r1 = agent("r1", { state: "running" });
  const { doc, setHome } = load({ extensions: "", homeVm: homeWith([r1]) });
  await tick();
  const drawn = rowIn(doc, "home-agents", "r1");
  setHome(homeWith([]));
  await poll(doc);
  assert.deepEqual(idsIn(doc, "home-agents"), []);
  assert.match(doc.getElementById("home-agents").textContent, /^No agent is running right now\./);
  assert.equal(doc.getElementById("home-agents").children.length, 1, "only the empty line");
  setHome(homeWith([r1]));
  await poll(doc);
  assert.deepEqual(idsIn(doc, "home-agents"), ["r1"]);
  assert.notEqual(rowIn(doc, "home-agents", "r1"), drawn, "a row that left is drawn anew when it comes back");
  assert.doesNotMatch(doc.getElementById("home-agents").textContent, /No agent is running/);

  const fails = { status: 500, body: { error: "boom" } };
  const ok = { total: 1, rows: [agent("h1")], next: null };
  const empty = load({ extensions: "", url: HISTORY_URL, homeVm: home(), routes: { "GET home/history": answers(fails, ok) } });
  await tick();
  assert.match(empty.doc.getElementById("history-list").textContent, /^Could not read the history\. /);
  await poll(empty.doc);
  assert.deepEqual(idsIn(empty.doc, "history-list"), ["h1"]);
  // The row and its day heading (§4.25ae *Sessions sit under their day*).
  assert.equal(empty.doc.querySelectorAll("#history-list > :not(.history-day)").length, 1, "the failure line went with the read that answered");
  assert.equal(empty.doc.querySelectorAll("#history-list > .history-day").length, 1);
  assert.doesNotMatch(empty.doc.getElementById("history-list").textContent, /Could not read/);
});

test("S5: the order is the answer's, even when kept rows change places", async () => {
  const [r1, r2, r3] = ["r1", "r2", "r3"].map((id) => agent(id, { state: "running" }));
  const { doc, setHome } = load({ extensions: "", homeVm: homeWith([r1, r2, r3]) });
  await tick();
  const before = byId(doc, "home-agents");
  setHome(homeWith([r3, agent("r4", { state: "running" }), r1, r2]));
  await poll(doc);
  assert.deepEqual(idsIn(doc, "home-agents"), ["r3", "r4", "r1", "r2"]);
  for (const id of ["r1", "r2", "r3"]) assert.equal(rowIn(doc, "home-agents", id), before.get(id), `${id} is kept`);
  assert.equal(doc.getElementById("home-agents").children.length, 4);
});

test("S6: a kept row keeps its opened note across a poll that changes another row", async () => {
  const preview = { label: "Gemini CLI", sentence: "Mandu's support for Gemini CLI is new.", issues: "https://example.com/issues" };
  const p1 = agent("p1", { state: "running", agent: "Gemini CLI", preview });
  const r2 = agent("r2", { state: "running" });
  const { doc, setHome } = load({ extensions: "", homeVm: homeWith([p1, r2]) });
  await tick();
  const btn = rowIn(doc, "home-agents", "p1").querySelector(".help-btn");
  btn.click();
  assert.equal(btn.getAttribute("aria-expanded"), "true");
  doc.getElementById("home-history").focus();
  setHome(homeWith([p1, agent("r2", { state: "running", blocked: 2 })]));
  await poll(doc);
  assert.equal(rowIn(doc, "home-agents", "p1").querySelector(".help-btn"), btn, "the row with the note is kept");
  assert.equal(btn.getAttribute("aria-expanded"), "true", "its note stays open");
  assert.equal(doc.getElementById(btn.getAttribute("aria-controls")).hidden, false);
  assert.match(rowIn(doc, "home-agents", "r2").textContent, /2 actions blocked/);
});
