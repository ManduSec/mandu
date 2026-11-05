/**
 * home-js-history-search.test — dashboard.md §4.25ae *Finding a session*.
 * History listed every session 25 at a time with no way to find one; now a
 * search box above the list ("Find a session") keeps the sessions whose
 * agent, prompt or folder holds the words typed, read from the server
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
 *       the status line says the same sentence to a screen reader only;
 *   F4  `/history?q=` on load reads the search and shows it in the box;
 *       Enter reads at once; a link to History starts without a search;
 *   F5  *An empty History has nothing to find*: with no session on record
 *       and no search, the box and the switch are hidden and the list says
 *       how to start one; the poll that brings the first session shows them
 *       again, the focus left where it was;
 *   F6  a search or the switch keeps the box on an empty record (`?q=x`,
 *       `?only=stepped-in`), and so does a box emptied while it has the
 *       focus;
 *   F7  *On a phone, the box under its label*: under 500 px the box's flex
 *       basis is the whole line, so it wraps under "Find a session" and its
 *       hint reads whole; from 500 px it keeps its 220 px basis beside the
 *       label; Approvals' Find boxes carry the same rule. jsdom does no
 *       layout: tests/stack/product-find-width.test.ts measures the hint in
 *       a real Chromium.
 *   F8  *None found is said*: the status line under the box holds the
 *       list's sentence (no Clear) while a search finds none, `.sr-only`
 *       and not hidden, so a screen reader announces it; a poll that finds
 *       none again leaves its text node as it was (no second announcement);
 *       a search that finds some shows the count, seen; Clear empties it
 *       and hides it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { PUB, home, load, tick } from "./home-js-fixtures.js";
import { flattenCss, stripComments, stylesAt } from "./css-flatten.js";

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
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = async (doc: any) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };
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
  assert.equal(doc.getElementById("history-q").getAttribute("placeholder"), "What you asked, a folder, a secret or a host", "the folder, a secret and a host are searched too");
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
  const count = doc.getElementById("history-count");
  assert.equal(count.hidden, false, "the status line says it too");
  assert.equal(count.classList.contains("sr-only"), true, "to a screen reader only: on screen the list says it");
  assert.equal(count.textContent, "No session matches “nothing here”.", "the list's sentence, without Clear");
  assert.equal(window.location.search, "?q=nothing%20here");
  list.querySelector("button.history-clear").click();
  await tick();
  assert.equal(doc.getElementById("history-q").value, "");
  assert.equal(doc.activeElement, doc.getElementById("history-q"));
  assert.equal(window.location.pathname + window.location.search, "/mandu/history");
  assert.equal(count.hidden, true, "cleared: no line");
  assert.equal(count.textContent, "");
  assert.equal(count.classList.contains("sr-only"), false);
  assert.deepEqual(ids(doc), ["s9", "s8"]);
  assert.deepEqual(historyCalls(calls), ["home/history", "home/history?q=nothing%20here", "home/history"]);
  // A search on a record with no session at all: the empty record's words.
  const empty = load({ extensions: "", url: `${URL}?q=x`, homeVm: home(), routes: { "GET home/history?q=x": { total: 0, rows: [], next: null, query: { text: "x", all: 0 } } } });
  await tick();
  assert.match(empty.doc.getElementById("history-list").textContent, /No session has been recorded yet/);
  assert.equal(empty.doc.getElementById("history-count").hidden, true, "nothing to find: no line");
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

const EMPTY_LINE = "No session has been recorded yet. Start your agent through Mandu, mandu claude or mandu codex, and it shows up here.";

test("F5: no session on record: no box, no switch, how to start one; the first session's poll brings them back, the focus kept", async () => {
  const answers = [{ total: 0, rows: [], next: null }, { total: 0, rows: [], next: null }, { total: 1, rows: [row("s1", { state: "running" })], next: null }];
  let i = 0;
  const { doc, calls } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": () => answers[Math.min(i++, answers.length - 1)] } });
  const form = doc.getElementById("history-search");
  assert.equal(form.hidden, false, "before the first answer the box stays as served: no blink");
  await tick();
  assert.equal(form.hidden, true, "nothing to find: the form is hidden");
  assert.equal(doc.getElementById("history-list").textContent, EMPTY_LINE);
  assert.deepEqual([...doc.querySelectorAll("#history-list .empty code")].map((c: { textContent: string }) => c.textContent), ["mandu claude", "mandu codex"]);
  // A poll with the same empty answer changes nothing.
  await poll(doc);
  assert.equal(form.hidden, true);
  const heading = doc.querySelector("#page-history h1");
  heading.tabIndex = -1;
  heading.focus();
  await poll(doc);
  assert.deepEqual(historyCalls(calls), ["home/history", "home/history", "home/history"]);
  assert.deepEqual(ids(doc), ["s1"], "the first session is listed");
  assert.equal(form.hidden, false, "the form is back, no reload");
  assert.equal(doc.getElementById("history-q").value, "", "its box as it was");
  assert.equal(doc.activeElement, heading, "the focus is left where it was");
});

test("F6: a search or the switch keeps the box on an empty record; a box emptied with the focus in it stays", async () => {
  const none = { total: 0, rows: [], next: null, query: { text: "x", all: 0 } };
  const { doc } = load({ extensions: "", url: `${URL}?q=x`, homeVm: home(), routes: { "GET home/history?q=x": none, "GET home/history": { total: 0, rows: [], next: null } } });
  await tick();
  const form = doc.getElementById("history-search");
  assert.equal(form.hidden, false, "?q= keeps the box, to clear it");
  assert.equal(doc.getElementById("history-q").value, "x");
  assert.equal(doc.getElementById("history-list").textContent, EMPTY_LINE);
  type(doc, "");
  await settle();
  assert.equal(doc.defaultView.location.search, "", "the search is gone");
  assert.equal(form.hidden, false, "the box the focus is in is not taken from under it");
  assert.equal(doc.activeElement, doc.getElementById("history-q"));
  const only = load({ extensions: "", url: `${URL}?only=stepped-in`, homeVm: home(), routes: { "GET home/history?only=stepped-in": { total: 0, rows: [], next: null, only: { through: 0 } } } });
  await tick();
  assert.equal(only.doc.getElementById("history-search").hidden, false, "the switch on keeps the form, to turn it off");
  assert.equal(only.doc.getElementById("history-only").getAttribute("aria-checked"), "true");
});

const BOX = '.history-search input[type="search"]';
/** The box's flex basis a browser `width` px wide applies: the last `flex`
 *  (its third part) or `flex-basis` on it, in the stylesheet's order. */
const basisAt = (width: number): string | null => {
  let basis: string | null = null;
  for (const r of flattenCss(stripComments(stylesAt(readFileSync(join(PUB, "app.css"), "utf8"), width)))) {
    if (!r.selectors.includes(BOX)) continue;
    for (const decl of r.block.split(";")) {
      const [prop, ...rest] = decl.split(":");
      const v = rest.join(":").trim();
      if (prop!.trim() === "flex") basis = v.split(/\s+/)[2] ?? basis;
      else if (prop!.trim() === "flex-basis") basis = v;
    }
  }
  return basis;
};

test("F7: under 500 px the box takes its own line under its label, so its hint reads whole; from 500 px it shares the label's line; Approvals' boxes too", async () => {
  for (const width of [320, 390, 499]) assert.equal(basisAt(width), "100%", `${width}px: the box takes the whole line, under its label`);
  for (const width of [500, 980, 1280]) assert.equal(basisAt(width), "220px", `${width}px: the box keeps its basis beside the label`);
  const { doc } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": ALL } });
  await tick();
  for (const id of ["history-q", "answered-q", "changes-q"]) {
    assert.ok(doc.getElementById(id).matches(BOX), `#${id} follows the rule`);
  }
});

test("F8: none found is said to a screen reader, once; a search that finds some shows its count; Clear empties the line", async () => {
  const none = { total: 0, rows: [], next: null, query: { text: "zzz", all: 214 } };
  const { doc } = load({ extensions: "", url: `${URL}?q=zzz`, homeVm: home(), routes: { "GET home/history?q=zzz": none, "GET home/history?q=staging": FOUND, "GET home/history": ALL } });
  await tick();
  const count = doc.getElementById("history-count");
  assert.equal(count.textContent, "No session matches “zzz”.");
  assert.equal(count.hidden, false, "shown, so its change is announced");
  assert.equal(count.classList.contains("sr-only"), true);
  const said = count.firstChild;
  await poll(doc);
  assert.equal(count.firstChild, said, "a poll that finds none again does not write the line again");
  assert.equal(count.textContent, "No session matches “zzz”.");
  type(doc, "staging");
  await settle();
  assert.equal(count.textContent, "2 of 214 sessions");
  assert.equal(count.hidden, false);
  assert.equal(count.classList.contains("sr-only"), false, "a count is seen, as before");
  type(doc, "zzz");
  await settle();
  assert.equal(count.classList.contains("sr-only"), true, "none again: said again");
  doc.querySelector("#history-list button.history-clear").click();
  await tick();
  assert.equal(count.textContent, "");
  assert.equal(count.hidden, true);
  assert.equal(count.classList.contains("sr-only"), false);
});
