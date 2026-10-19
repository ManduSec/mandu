/**
 * home-js-history-only.test — dashboard.md §4.25ae *Only the sessions where
 * Mandu stepped in*. History listed every session, and the few where Mandu
 * masked a secret, blocked a step, filled in a value or waits for an answer
 * were found only by reading every row, page by page. Now a switch above the
 * list keeps just those, read from the server
 * (`/api/home/history?only=stepped-in`):
 *
 *   O1  off by default; pressed, it reads with the filter, draws only the
 *       rows the server kept, says "Showing the sessions where Mandu
 *       stepped in", writes `?only=stepped-in` into the address (replaced,
 *       no new entry) and keeps the focus; pressed again, every session;
 *   O2  Show more asks with the filter and says how far the look went
 *       ("Looked through 200 of 950 sessions."); a read that found none yet
 *       still has Show more ("has not stepped in in the newest 200");
 *   O3  none at all: "Mandu has not stepped in in any session on record."
 *       with Show every session, which turns the switch off and focuses it;
 *   O4  Home's poll reads with the filter: a session that got its first
 *       block comes in on top, the switch stays on; a poll whose look ended
 *       before the drawn rows leaves them;
 *   O5  `?q=…&only=stepped-in` on load sets both; Back from a session keeps
 *       the switch; a link to History starts with it off.
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts).
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";
import { waitWhile } from "../page-wait.js";

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
const poll = async (doc: any) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const sw = (doc: any) => doc.getElementById("history-only");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const press = async (doc: any) => { sw(doc).focus(); sw(doc).click(); await tick(); };
function answers(...list: unknown[]) {
  let i = 0;
  return () => list[Math.min(i++, list.length - 1)];
}

const ALL = { total: 950, rows: [row("s9"), row("s8", { blocked: 1 }), row("s7")], next: "s7" };
const MASKED = row("s8", { blocked: 1 });
const ONLY = { total: 950, rows: [MASKED, row("s3", { secrets: { masked: 1, early: 0 } })], next: null, only: { through: 950 } };

test("O1: the switch reads with the filter, draws only those rows, says so, writes ?only= and keeps the focus; off again, every session", async () => {
  const { doc, window, calls } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": ALL, "GET home/history?only=stepped-in": ONLY } });
  await tick();
  assert.deepEqual(ids(doc), ["s9", "s8", "s7"]);
  assert.equal(sw(doc).getAttribute("role"), "switch");
  assert.equal(sw(doc).getAttribute("aria-checked"), "false", "off by default");
  assert.equal(doc.getElementById(sw(doc).getAttribute("aria-labelledby")).textContent, "Only sessions where Mandu stepped in");
  assert.equal(doc.querySelector('label[for="history-only"]').id, "history-only-words");
  const entries = window.history.length;
  await press(doc);
  assert.equal(sw(doc).getAttribute("aria-checked"), "true");
  assert.deepEqual(historyCalls(calls), ["home/history", "home/history?only=stepped-in"]);
  assert.deepEqual(ids(doc), ["s8", "s3"], "only the rows the server kept");
  const count = doc.getElementById("history-count");
  assert.equal(count.hidden, false);
  assert.equal(count.textContent, "Showing the sessions where Mandu stepped in");
  assert.equal(doc.querySelector("#history-list .history-more"), null, "every session looked through: no Show more");
  assert.equal(window.location.pathname + window.location.search, "/mandu/history?only=stepped-in");
  assert.equal(window.history.length, entries, "replaced, not pushed");
  assert.equal(doc.activeElement, sw(doc), "the focus stays on the switch");
  await press(doc);
  assert.equal(sw(doc).getAttribute("aria-checked"), "false");
  assert.equal(window.location.pathname + window.location.search, "/mandu/history");
  assert.deepEqual(ids(doc), ["s9", "s8", "s7"]);
  assert.equal(count.hidden, true);
  assert.equal(doc.querySelector("#history-list .history-more span").textContent, "947 more sessions.");
  // The label presses it too (a <label for> a button).
  doc.querySelector('label[for="history-only"]').click();
  await tick();
  assert.equal(sw(doc).getAttribute("aria-checked"), "true");
});

test("O2: Show more asks with the filter and says how far it looked; a read that found none yet still pages on", async () => {
  const routes = {
    "GET home/history?only=stepped-in": { total: 950, rows: [], next: "s199", only: { through: 200 } },
    "GET home/history?after=s199&only=stepped-in": { total: 950, rows: [row("s250", { sent: 1 })], next: "s250", only: { through: 251 } },
    "GET home/history?after=s250&only=stepped-in": { total: 950, rows: [row("s600", { waiting: 1 })], next: null, only: { through: 950 } },
  };
  const { doc, calls } = load({ extensions: "", url: `${URL}?only=stepped-in`, homeVm: home(), routes });
  await tick();
  assert.equal(sw(doc).getAttribute("aria-checked"), "true", "the address turns it on");
  assert.deepEqual(ids(doc), []);
  const list = doc.getElementById("history-list");
  assert.equal(list.querySelector(".history-more span").textContent, "Mandu has not stepped in in the newest 200 of 950 sessions.", "not the end: more to look through");
  assert.equal(doc.getElementById("history-count").hidden, true, "no rows: the line says it");
  list.querySelector(".history-more button").click();
  await tick();
  assert.deepEqual(ids(doc), ["s250"]);
  assert.equal(list.querySelector(".history-more span").textContent, "Looked through 251 of 950 sessions.");
  assert.equal(doc.activeElement, list.querySelector(".row.agent"), "the first new row takes the focus");
  list.querySelector(".history-more button").click();
  await tick();
  assert.deepEqual(ids(doc), ["s250", "s600"]);
  assert.equal(list.querySelector(".history-more"), null, "the end");
  assert.deepEqual(historyCalls(calls), ["home/history?only=stepped-in", "home/history?after=s199&only=stepped-in", "home/history?after=s250&only=stepped-in"]);
});

test("O3: none at all says so, with Show every session: the switch off and focused, every session listed", async () => {
  const { doc, window, calls } = load({ extensions: "", url: `${URL}?only=stepped-in`, homeVm: home(), routes: { "GET home/history?only=stepped-in": { total: 950, rows: [], next: null, only: { through: 950 } }, "GET home/history": ALL } });
  await tick();
  const list = doc.getElementById("history-list");
  assert.equal(list.textContent, "Mandu has not stepped in in any session on record. Show every session");
  list.querySelector("button.history-all").click();
  await tick();
  assert.equal(sw(doc).getAttribute("aria-checked"), "false");
  assert.equal(doc.activeElement, sw(doc));
  assert.equal(window.location.pathname + window.location.search, "/mandu/history");
  assert.deepEqual(ids(doc), ["s9", "s8", "s7"]);
  assert.deepEqual(historyCalls(calls), ["home/history?only=stepped-in", "home/history"]);
  // No session recorded at all: the empty record's words, not the switch's.
  const empty = load({ extensions: "", url: `${URL}?only=stepped-in`, homeVm: home(), routes: { "GET home/history?only=stepped-in": { total: 0, rows: [], next: null, only: { through: 0 } } } });
  await tick();
  assert.match(empty.doc.getElementById("history-list").textContent, /No session has been recorded yet/);
});

test("O4: the poll reads with the filter: a new block comes in on top, the switch stays on; a look that ended before the drawn rows leaves them", async () => {
  const first = { total: 950, rows: [MASKED], next: null, only: { through: 950 } };
  const later = { total: 951, rows: [row("s10", { state: "running", blocked: 1 }), MASKED], next: null, only: { through: 951 } };
  const { doc, calls } = load({ extensions: "", url: `${URL}?only=stepped-in`, homeVm: home(), routes: { "GET home/history?only=stepped-in": answers(first, later) } });
  await tick();
  assert.deepEqual(ids(doc), ["s8"]);
  await poll(doc);
  assert.deepEqual(historyCalls(calls), ["home/history?only=stepped-in", "home/history?only=stepped-in"], "the poll keeps the filter");
  assert.deepEqual(ids(doc), ["s10", "s8"], "a running session's first block on top");
  assert.equal(sw(doc).getAttribute("aria-checked"), "true");

  // Rows drawn deep in a sparse history: the poll's look (200 sessions)
  // reaches none of them, and they stay with their cursor.
  const deep = load({ extensions: "", url: `${URL}?only=stepped-in`, homeVm: home(), routes: {
    "GET home/history?only=stepped-in": answers({ total: 950, rows: [], next: "s199", only: { through: 200 } }, { total: 950, rows: [], next: "s199", only: { through: 200 } }),
    "GET home/history?after=s199&only=stepped-in": { total: 950, rows: [row("s300", { blocked: 2 })], next: "s300", only: { through: 301 } },
  } });
  await tick();
  deep.doc.querySelector("#history-list .history-more button").click();
  await tick();
  assert.deepEqual(ids(deep.doc), ["s300"]);
  await poll(deep.doc);
  assert.deepEqual(ids(deep.doc), ["s300"], "the drawn row stays");
  assert.equal(deep.doc.querySelector("#history-list .history-more span").textContent, "Looked through 301 of 950 sessions.", "and Show more goes on from it");
});

test("O5: ?q= and ?only= on load set both; Back from a session keeps the switch; a link to History starts with it off", async () => {
  const both = { total: 30, rows: [MASKED], next: null, only: { through: 30 }, query: { text: "deploy", all: 950 } };
  const { doc, window, calls } = load({ extensions: "", url: `${URL}?q=deploy&only=stepped-in`, homeVm: home(), routes: { "GET home/history?q=deploy&only=stepped-in": both, "GET home/history": ALL } });
  await tick();
  assert.equal(doc.getElementById("history-q").value, "deploy");
  assert.equal(sw(doc).getAttribute("aria-checked"), "true");
  assert.deepEqual(historyCalls(calls), ["home/history?q=deploy&only=stepped-in"]);
  assert.equal(doc.getElementById("history-count").textContent, "Showing the sessions where Mandu stepped in, of 30 sessions found");
  // A row's Details, then Back: the address and the read keep both.
  const link = doc.querySelector('#history-list .row.agent a[data-page-link="agent"]');
  link.click();
  await tick();
  assert.equal(doc.getElementById("page-agent").hidden, false);
  const from = window.location.pathname;
  window.history.back();
  await waitWhile(() => window.location.pathname === from);
  await tick();
  assert.equal(window.location.pathname + window.location.search, "/mandu/history?q=deploy&only=stepped-in");
  assert.equal(sw(doc).getAttribute("aria-checked"), "true", "Back keeps the switch");
  assert.equal(historyCalls(calls).at(-1)!.endsWith("q=deploy&only=stepped-in"), true, historyCalls(calls).at(-1));
  // The top bar's History link: a page change that starts over.
  doc.querySelector('#nav [data-page-link="history"]').click();
  await tick();
  assert.equal(window.location.pathname + window.location.search, "/mandu/history");
  assert.equal(sw(doc).getAttribute("aria-checked"), "false");
  assert.deepEqual(historyCalls(calls).slice(-1), ["home/history"]);
});
