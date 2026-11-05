/**
 * home-js-rule-change-seek.test — a link to a rule change older than the
 * rows Rule changes draws (`/approvals/<pc-…>`, a rule's origin line links
 * its newest change, dashboard.md §4.25i) reads further back, once, and
 * Rule changes draws down to the page that holds it, marked in place, as
 * Answered earlier does for an answer (§4.25 *Past the newest 20*). The poll
 * after keeps those rows; an id that is nowhere gets the note of today.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the shared
 * fetch stub (home-js-fixtures.ts). Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";

const id = (i: number) => "pc-" + String(1000 - i).padStart(6, "0");
const change = (i: number) => ({
  id: id(i), sentence: "You changed a rule on the Rules page", session: null, createdAt: Date.now() - (i + 1) * 60_000, undone: false, undoable: true,
  rows: [[{ kind: "text", text: "Make " }, { kind: "code", text: `/w/f${i}.pem` }, { kind: "text", text: " a secret no AI may read" }]],
});
// 45 changes on record, newest first.
const ALL = Array.from({ length: 45 }, (_, i) => change(i));
const routes = {
  "GET policy/proposals?status=pending": { proposals: [] },
  "GET policy/changes?limit=21": { changes: ALL.slice(0, 21) },
  "GET policy/changes?limit=41": { changes: ALL.slice(0, 41) },
  "GET policy/changes?limit=500": { changes: ALL },
};
const at = (x: string) => "http://127.0.0.1:4500/mandu/approvals/" + encodeURIComponent(x);
const rows = (doc: any) => [...doc.querySelectorAll("#approvals-rule-history .row.answered")] as any[];
const marked = (doc: any) => [...doc.querySelectorAll("#page-approvals .focus")].map((x: any) => x.dataset.id);
const note = (doc: any) => doc.getElementById("approvals-focus-note");
const reads = (calls: { url: string }[], limit: number) => calls.filter((c) => c.url.endsWith("/api/policy/changes?limit=" + limit)).length;

test("the 30th of 45 changes: one read further back, Rule changes draws 40 rows and marks the 30th, the note says nothing", async () => {
  const { doc, calls, window } = load({ url: at(id(29)), homeVm: home(), routes });
  await tick(60);
  assert.equal(reads(calls, 500), 1, "one read of the changes, up to CHANGES_MAX");
  assert.equal(rows(doc).length, 40, "down to the page that holds it");
  assert.deepEqual(marked(doc), [id(29)]);
  const row = rows(doc)[29];
  assert.ok(row.classList.contains("focus"), "marked in place, the 30th");
  assert.ok([...row.querySelectorAll("button")].some((b: any) => b.textContent === "Undo"), "with its Undo");
  assert.ok(doc.querySelector("#approvals-rule-history .changes-more"), "Show more still reaches the rest");
  assert.equal(note(doc).hidden, true, "nothing in the note");

  // The poll after reads as many as are drawn, and keeps them and the mark.
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick(60);
  assert.ok(reads(calls, 41) >= 1, "the poll reads the 40 drawn, and one more");
  assert.equal(rows(doc).length, 40, "never back to the newest 20");
  assert.deepEqual(marked(doc), [id(29)]);
  assert.equal(reads(calls, 500), 1, "the read further back is not repeated");
});

test("a change among the newest 20 reads nothing further back", async () => {
  const { doc, calls } = load({ url: at(id(3)), homeVm: home(), routes });
  await tick(60);
  assert.equal(reads(calls, 500), 0);
  assert.equal(rows(doc).length, 20);
  assert.deepEqual(marked(doc), [id(3)]);
  assert.equal(note(doc).hidden, true);
});

test("an id that is nowhere: the read further back finds nothing, and the note is today's", async () => {
  const { doc, calls } = load({ url: at("pc-999999"), homeVm: home(), routes });
  await tick(60);
  assert.equal(reads(calls, 500), 1);
  assert.equal(rows(doc).length, 20, "the rows stay the newest 20");
  assert.deepEqual(marked(doc), []);
  assert.equal(note(doc).hidden, false);
  assert.equal(note(doc).textContent, "That rule change is not among the changes listed. Show more, under Rule changes, reaches older ones.");
});

test("the read further back fails: the note is today's, the rows stay", async () => {
  const { doc } = load({ url: at(id(29)), homeVm: home(), routes: { ...routes, "GET policy/changes?limit=500": { status: 502, body: { error: "down" } } } });
  await tick(60);
  assert.equal(rows(doc).length, 20);
  assert.deepEqual(marked(doc), []);
  assert.equal(note(doc).textContent, "That rule change is not among the changes listed. Show more, under Rule changes, reaches older ones.");
});
