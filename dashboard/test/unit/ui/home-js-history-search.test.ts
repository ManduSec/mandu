/**
 * home-js-history-search.test — dashboard.md §4.25ae *Finding a session*.
 * History listed every session 25 at a time with no way to find one; now a
 * search box above the list ("Find a session") keeps the sessions whose
 * agent or prompt holds the words typed, read from the server
 * (`/api/home/history?q=`):
 *
 *   F1  typing reads once the typing stops (250 ms), not per key; the list
 *       starts over with the matches, the count reads "2 of 214 sessions",
 *       the address carries `?q=` (replaced, no new entry) and the focus
 *       stays in the box;
 *   F2  Show more and Home's poll read with the same `q`, so a poll never
 *       fills the list again unfiltered;
 *   F3  no match: "No session matches “…”." with Clear, which empties the
 *       box and the address, lists every session again and focuses the box;
 *   F4  `/history?q=` on load reads the search and shows it in the box;
 *       Enter reads at once; a link to History starts without a search.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";

const URL = "http://127.0.0.1:4500/mandu/history";
const row = (id: string, over: Record<string, unknown> = {}) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: "/home/u/ws", startedAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-01T10:05:00.000Z", state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null, ...over,
});
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ids = (doc: any) => ([...doc.querySelectorAll("#history-list .row.agent")] as any[]).map((r) => r.dataset.session);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const historyCalls = (calls: any[]) => calls.filter((c) => c.url.startsWith("/mandu/api/home/history")).map((c) => c.url.slice("/mandu/api/".length));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const type = (doc: any, text: string) => {
  const box = doc.getElementById("history-q");
  box.focus();
  box.value = text;
  box.dispatchEvent(new doc.defaultView.Event("input", { bubbles: true }));
};
const settle = async () => { await new Promise((r) => setTimeout(r, 300)); await tick(); };

const ALL = { total: 214, rows: [row("s9"), row("s8")], next: "s8" };
const FOUND = { total: 2, rows: [row("s40", { title: "Fix deploy/staging.conf" }), row("s77", { title: "Why does staging fail?" })], next: null, query: { text: "staging", all: 214 } };

test("F1: typing reads after the typing stops; the matches, their count, ?q= in the address, the focus kept in the box", async () => {
  const { doc, window, calls } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": ALL, "GET home/history?q=staging": FOUND } });
  await tick();
  assert.deepEqual(ids(doc), ["s9", "s8"]);
  const form = doc.getElementById("history-search");
  assert.equal(form.getAttribute("role"), "search");
  assert.equal(doc.querySelector('label[for="history-q"]').textContent, "Find a session");
  assert.equal(doc.getElementById("history-count").hidden, true, "no count without a search");
  const entries = window.history.length;
  type(doc, "sta");
  type(doc, "stag");
  type(doc, "staging");
  await tick();
  assert.deepEqual(historyCalls(calls), ["home/history"], "no read per key");
  await settle();
  assert.deepEqual(historyCalls(calls), ["home/history", "home/history?q=staging"], "one read once the typing stopped");
  assert.deepEqual(ids(doc), ["s40", "s77"], "the list starts over with the matches");
  const count = doc.getElementById("history-count");
  assert.equal(count.hidden, false);
  assert.equal(count.textContent, "2 of 214 sessions");
  assert.equal(count.getAttribute("role"), "status");
  assert.equal(doc.querySelector("#history-list .history-more"), null, "every match is drawn: no Show more");
  assert.equal(window.location.pathname + window.location.search, "/mandu/history?q=staging");
  assert.equal(window.history.length, entries, "the address is replaced, not pushed");
  assert.equal(doc.activeElement, doc.getElementById("history-q"), "the focus stays in the box");
  // Spaces around and between are one: the same search reads nothing again.
  type(doc, "  staging ");
  await settle();
  assert.equal(historyCalls(calls).length, 2);
});

test("F2: Show more and Home's poll keep the search", async () => {
  const first = { total: 30, rows: [row("a1"), row("a2")], next: "a2", query: { text: "deploy", all: 90 } };
  const more = { total: 30, rows: [row("a3")], next: null, query: { text: "deploy", all: 90 } };
  const { doc, calls } = load({ extensions: "", url: `${URL}?q=deploy`, homeVm: home(), routes: { "GET home/history?q=deploy": first, "GET home/history?after=a2&q=deploy": more } });
  await tick();
  assert.deepEqual(ids(doc), ["a1", "a2"]);
  assert.equal(doc.getElementById("history-count").textContent, "30 of 90 sessions");
  assert.equal(doc.querySelector("#history-list .history-more span").textContent, "28 more sessions.", "Show more counts the matches");
  doc.querySelector("#history-list .history-more button").click();
  await tick();
  assert.deepEqual(ids(doc), ["a1", "a2", "a3"]);
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick();
  assert.deepEqual(historyCalls(calls), ["home/history?q=deploy", "home/history?after=a2&q=deploy", "home/history?q=deploy"], "the poll reads the same search");
});

test("F3: no match says so, with Clear: every session again, the address without ?q=, the box focused", async () => {
  const none = { total: 0, rows: [], next: null, query: { text: "nothing here", all: 214 } };
  const { doc, window, calls } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": ALL, "GET home/history?q=nothing%20here": none } });
  await tick();
  type(doc, "nothing   here");
  await settle();
  const list = doc.getElementById("history-list");
  assert.equal(list.textContent, "No session matches “nothing here”. Clear");
  assert.equal(doc.getElementById("history-count").hidden, true, "the line says it; no count");
  assert.equal(window.location.search, "?q=nothing%20here");
  list.querySelector("button.history-clear").click();
  await tick();
  assert.equal(doc.getElementById("history-q").value, "");
  assert.equal(doc.activeElement, doc.getElementById("history-q"));
  assert.equal(window.location.pathname + window.location.search, "/mandu/history");
  assert.deepEqual(ids(doc), ["s9", "s8"]);
  assert.deepEqual(historyCalls(calls), ["home/history", "home/history?q=nothing%20here", "home/history"]);
  // A search on a record with no session at all: the empty record's words.
  const empty = load({ extensions: "", url: `${URL}?q=x`, homeVm: home(), routes: { "GET home/history?q=x": { total: 0, rows: [], next: null, query: { text: "x", all: 0 } } } });
  await tick();
  assert.match(empty.doc.getElementById("history-list").textContent, /No session has been recorded yet/);
});

test("F4: ?q= on load is in the box; Enter reads at once; a link to History starts without a search", async () => {
  const { doc, window, calls } = load({ extensions: "", url: `${URL}?q=Codex`, homeVm: home(), routes: { "GET home/history?q=Codex": { ...FOUND, query: { text: "codex", all: 214 } }, "GET home/history?q=staging": FOUND, "GET home/history": ALL } });
  await tick();
  assert.equal(doc.getElementById("history-q").value, "Codex");
  assert.equal(window.location.search, "?q=Codex", "the address keeps it");
  assert.deepEqual(historyCalls(calls), ["home/history?q=Codex"]);
  const box = doc.getElementById("history-q");
  box.value = "staging";
  doc.getElementById("history-search").dispatchEvent(new window.Event("submit", { cancelable: true }));
  await tick();
  assert.deepEqual(historyCalls(calls).slice(-1), ["home/history?q=staging"], "Enter: no wait");
  assert.equal(window.location.search, "?q=staging");
  // The top bar's History link: a page change that starts over.
  doc.querySelector('#nav [data-page-link="history"]').click();
  await tick();
  assert.equal(window.location.pathname + window.location.search, "/mandu/history");
  assert.equal(doc.getElementById("history-q").value, "");
  assert.deepEqual(historyCalls(calls).slice(-1), ["home/history"]);
  assert.deepEqual(ids(doc), ["s9", "s8"]);
});
