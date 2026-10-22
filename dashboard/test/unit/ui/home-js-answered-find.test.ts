/**
 * home-js-answered-find.test — dashboard.md §4.25 *Finding an answer*.
 * Approvals › Answered earlier could only be paged: the answer to undo had
 * to be found by pressing Show more and reading every row. Now a box above
 * the list ("Find an answer") keeps the answers whose row words hold every
 * word typed, read from the server (`/api/home/answered?q=`):
 *
 *   S1  typing reads once the typing stops, not per key; the list holds the
 *       matches, the count reads "3 of 63 answers match", the address
 *       carries `?q=` (replaced, no new entry), the focus stays in the box;
 *   S2  Show more and the poll read with the same `q`, so a poll never
 *       draws Home's unfiltered newest 20 over the matches;
 *   S3  no match: "No answer matches “…”." with Clear, which empties the box
 *       and the address, lists the newest 20 again and focuses the box;
 *       Escape in the box does the same;
 *   S4  `/approvals?q=` on load reads the search and shows it in the box;
 *       `/approvals/<id>` (an answer the address opens) has none, a link
 *       to Approvals starts without one, and typing a search drops the
 *       marked answer from the address;
 *   S5  no answer at all and no search: no box;
 *   S6  each outcome is drawn in the words the server searches
 *       (ANSWERED_OUTCOME_WORDS), so "blocked" finds the rows that say
 *       Blocked.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";
import { ANSWERED_OUTCOME_WORDS } from "../../../src/view-model/home.js";

const URL = "http://127.0.0.1:4500/mandu/approvals";
const id = (i: number) => `egr-${String(i).padStart(2, "0")}`;
const ans = (i: number, over: Record<string, unknown> = {}) => ({
  id: id(i),
  sentence: [{ kind: "text", text: `Claude Code wants to send your secret KEY_${i} to ` }, { kind: "code", text: i % 3 ? "api.stripe.com" : "pastebin.com" }],
  outcome: "blocked", decidedAt: Date.now() - (i + 1) * 60_000, sessions: ["s1"],
  actions: [{ approve: true, scope: "always", label: "Always allow" }], ...over,
});
const ALL = Array.from({ length: 63 }, (_, i) => ans(i));
const PASTE = ALL.filter((_, i) => i % 3 === 0);
const vm = (rows = ALL.slice(0, 20), total = 63) => home({ waiting: [], answered: rows, answeredTotal: total, verdict: "secrets-only" });
const found = (rows: unknown[], total: number, next: string | null, text = "pastebin") => ({ rows, total, next, query: { text, all: 63 } });
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const rows = (doc: Doc) => [...doc.querySelectorAll("#approvals-answered .row.answered")] as Doc[];
const ids = (doc: Doc) => rows(doc).map((r) => r.dataset.id);
const moreButton = (doc: Doc) => doc.querySelector("#approvals-answered .answered-more button.show-rest");
const said = (doc: Doc) => doc.getElementById(moreButton(doc).getAttribute("aria-describedby"));
const box = (doc: Doc) => doc.getElementById("answered-q");
const count = (doc: Doc) => doc.getElementById("answered-count");
const type = (doc: Doc, text: string) => {
  box(doc).focus();
  box(doc).value = text;
  box(doc).dispatchEvent(new doc.defaultView.Event("input", { bubbles: true }));
};
const poll = async (doc: Doc) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };
const settle = async () => { await new Promise((r) => setTimeout(r, 300)); await tick(); };
const reads = (calls: Array<{ url: string }>) => calls.filter((c) => c.url.startsWith("/mandu/api/home/answered")).map((c) => c.url.slice("/mandu/api/".length));

test("S1: typing reads after the typing stops; the matches, their count, ?q= in the address, the focus kept in the box", async () => {
  const { doc, window, calls } = load({ extensions: "", url: URL, homeVm: vm(), routes: { "GET home/answered?limit=20&q=pastebin": found(PASTE.slice(0, 3), 3, null) } });
  await tick();
  const form = doc.getElementById("answered-search");
  assert.equal(form.hidden, false, "the box is there");
  assert.equal(form.getAttribute("role"), "search");
  assert.equal(doc.querySelector('label[for="answered-q"]').textContent, "Find an answer");
  assert.equal(box(doc).getAttribute("placeholder"), "A secret, a host or the agent");
  assert.equal(count(doc).hidden, true, "no count without a search");
  assert.equal(rows(doc).length, 20);
  const entries = window.history.length;
  type(doc, "paste");
  type(doc, "pastebin");
  await tick();
  assert.deepEqual(reads(calls), [], "no read per key");
  await settle();
  assert.deepEqual(reads(calls), ["home/answered?limit=20&q=pastebin"], "one read once the typing stopped");
  assert.deepEqual(ids(doc), PASTE.slice(0, 3).map((a) => a.id), "only the matches");
  assert.equal(count(doc).hidden, false);
  assert.equal(count(doc).textContent, "3 of 63 answers match");
  assert.equal(count(doc).getAttribute("role"), "status");
  assert.equal(moreButton(doc), null, "every match drawn: no Show more");
  assert.equal(window.location.pathname + window.location.search, "/mandu/approvals?q=pastebin");
  assert.equal(window.history.length, entries, "the address is replaced, not pushed");
  assert.equal(doc.activeElement, box(doc), "the focus stays in the box");
  for (const r of rows(doc)) assert.equal(r.querySelector("button").textContent, "Allow instead", "each found row keeps its reversal");
  // One match: "1 of 63 answers matches".
  const one = load({ extensions: "", url: URL + "?q=KEY_5", homeVm: vm(), routes: { "GET home/answered?limit=20&q=KEY_5": found([ALL[5]], 1, null, "key_5") } });
  await tick();
  assert.equal(count(one.doc).textContent, "1 of 63 answers matches");
});

test("S2: Show more and the poll keep the search: the next page of matches, a poll that reads the matches again, never Home's 20", async () => {
  const { doc, calls, setHome } = load({ extensions: "", url: URL, homeVm: vm(), routes: {
    "GET home/answered?limit=20&q=pastebin": found(PASTE.slice(0, 20), 21, PASTE[19]!.id),
    "GET home/answered?after=egr-57&limit=20&q=pastebin": found(PASTE.slice(20), 21, null),
    "GET home/answered?limit=21&q=pastebin": found(PASTE, 21, null),
  } });
  await tick();
  type(doc, "pastebin");
  await settle();
  assert.equal(rows(doc).length, 20);
  assert.equal(said(doc).textContent, "Showing 20 of 21 answers that match.");
  assert.equal(count(doc).textContent, "21 of 63 answers match");
  moreButton(doc).click();
  await tick();
  assert.deepEqual(reads(calls).slice(-1), ["home/answered?after=egr-57&limit=20&q=pastebin"], "Show more carries the search");
  assert.deepEqual(ids(doc), PASTE.map((a) => a.id));
  assert.equal(doc.activeElement, rows(doc)[20], "the first new row takes the focus");
  setHome(vm([ans(99, { id: "egr-new", decidedAt: Date.now() }), ...ALL.slice(0, 19)], 64));
  await poll(doc);
  assert.deepEqual(reads(calls).slice(-1), ["home/answered?limit=21&q=pastebin"], "the poll reads the matches again, as many as drawn");
  assert.deepEqual(ids(doc), PASTE.map((a) => a.id), "Home's unfiltered 20 are never drawn over them");
  assert.equal(doc.activeElement, rows(doc)[20], "the focus kept");
});

test("S3: no match says so with Clear, which empties the box and the address and lists the newest again; Escape does the same", async () => {
  const { doc, window, calls } = load({ extensions: "", url: URL, homeVm: vm(), routes: { "GET home/answered?limit=20&q=nowhere": found([], 0, null, "nowhere") } });
  await tick();
  type(doc, "nowhere");
  await settle();
  assert.equal(rows(doc).length, 0);
  const empty = doc.querySelector("#approvals-answered .empty");
  assert.equal(empty.textContent, "No answer matches “nowhere”. Clear");
  assert.equal(count(doc).hidden, true, "no count line when nothing matched: the list says so");
  empty.querySelector("button.history-clear").click();
  await tick();
  assert.equal(box(doc).value, "");
  assert.equal(window.location.pathname + window.location.search, "/mandu/approvals");
  assert.deepEqual(ids(doc), ALL.slice(0, 20).map((a) => a.id), "the newest 20 again, with no read");
  assert.equal(reads(calls).length, 1);
  assert.equal(doc.activeElement, box(doc), "the box has the focus");
  assert.equal(said(doc).textContent, "Showing 20 of 63 answers.");
  // Escape in the box: the same.
  type(doc, "nowhere");
  await settle();
  assert.equal(rows(doc).length, 0);
  const esc = new doc.defaultView.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
  box(doc).dispatchEvent(esc);
  await tick();
  assert.equal(esc.defaultPrevented, true, "Escape taken by the box");
  assert.equal(box(doc).value, "");
  assert.equal(window.location.search, "");
  assert.equal(rows(doc).length, 20);
  // An empty box leaves Escape alone.
  const again = new doc.defaultView.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
  box(doc).dispatchEvent(again);
  assert.equal(again.defaultPrevented, false);
});

test("S4: ?q= on load reads the search into the box; /approvals/<id> has none; a link starts without one; a search drops the marked answer", async () => {
  const { doc, calls } = load({ extensions: "", url: URL + "?q=pastebin", homeVm: vm(), routes: { "GET home/answered?limit=20&q=pastebin": found(PASTE.slice(0, 3), 3, null) } });
  await tick();
  assert.equal(box(doc).value, "pastebin", "the box shows the address's search");
  assert.deepEqual(reads(calls), ["home/answered?limit=20&q=pastebin"]);
  assert.deepEqual(ids(doc), PASTE.slice(0, 3).map((a) => a.id), "the matches, never Home's 20 first");
  assert.equal(count(doc).textContent, "3 of 63 answers match");
  // A link to Approvals starts without the search.
  (doc.querySelector('[data-page-link="home"]') as Doc).click();
  await tick();
  (doc.querySelector('[data-page-link="approvals"]') as Doc).click();
  await tick();
  assert.equal(box(doc).value, "");
  assert.equal(rows(doc).length, 20);
  assert.equal(doc.defaultView.location.search, "");

  // An address that opens one answer has no search, so its row is drawn and marked.
  const marked = load({ extensions: "", url: URL + "/" + id(3), homeVm: vm() });
  await tick();
  assert.equal(box(marked.doc).value, "");
  const row = rows(marked.doc).find((r) => r.dataset.id === id(3));
  assert.ok(row.classList.contains("focus"), "the answer is marked");
  // Typing a search there drops the answer from the address, and its mark.
  type(marked.doc, "pastebin");
  await settle();
  assert.equal(marked.window.location.pathname + marked.window.location.search, "/mandu/approvals?q=pastebin");
  assert.equal(marked.doc.getElementById("approvals-focus-note").hidden, true);
  assert.equal(marked.doc.querySelector("#page-approvals .focus"), null, "no mark left");
});

test("S5: no answer at all and no search: no box", async () => {
  const { doc } = load({ extensions: "", url: URL, homeVm: vm([], 0) });
  await tick();
  assert.equal(doc.getElementById("answered-search").hidden, true);
  assert.equal(doc.querySelector("#approvals-answered .empty").textContent, "You have not answered anything yet.");
});

test("S6: each outcome is drawn in the words the server searches", async () => {
  const outcomes = Object.keys(ANSWERED_OUTCOME_WORDS) as Array<keyof typeof ANSWERED_OUTCOME_WORDS>;
  const list = outcomes.map((o, i) => ans(i, { outcome: o, actions: [] }));
  const { doc } = load({ extensions: "", url: URL, homeVm: vm(list, list.length) });
  await tick();
  const drawn = rows(doc);
  assert.equal(drawn.length, outcomes.length);
  outcomes.forEach((o, i) => assert.equal(drawn[i].querySelector(".outcome").textContent, ANSWERED_OUTCOME_WORDS[o], `the ${o} row`));
});
