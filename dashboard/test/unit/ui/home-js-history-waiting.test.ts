/**
 * home-js-history-waiting.test — dashboard.md §4.25ae *History says what
 * waits for you*. History drew no row's waiting question: a running session
 * that waited for your OK read "running now" with the green dot, where Home's
 * Running now gave it the amber dot and "1 waiting for you", and an ended
 * session whose question still waited said nothing of it, where Earlier said
 * "1 question waiting for you".
 *
 *   W1  a row with questions waiting says how many, in Home's words (the
 *       row keeps its prompt, as Home's rows do) and in its Home row's
 *       order: a running one leads with them, as Running now does, and has
 *       Running now's amber dot; an ended one says them last, as Earlier
 *       does; a row with none says nothing of them;
 *   W2  the poll follows an answer: the next read without the question draws
 *       the row without its count, and the green dot back;
 *   W3  protection failed outranks the amber dot, and the count stays,
 *       after the mark, as on Home.
 *   W4  an ended row whose session left changes unapplied says so after its
 *       counts and before its questions, as Earlier does, with the amber
 *       dot and a link to its page at the block (dashboard.md §4.25b *Home
 *       and History say so*); the poll draws it when the count arrives.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";

const URL = "http://127.0.0.1:4500/mandu/history";
const row = (id: string, over: Record<string, unknown> = {}) => ({
  id, agent: "Claude Code", title: `Task ${id}`, cwd: null, startedAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-01T10:05:00.000Z", state: "idle",
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 1, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, waiting: 0, notice: null, preview: null, ...over,
});
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rowOf = (doc: any, id: string) => [...doc.querySelectorAll("#history-list .row.agent")].find((r: any) => r.dataset.session === id) as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const counts = (doc: any, id: string) => rowOf(doc, id).querySelector(".agent-counts")?.textContent ?? null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const dot = (doc: any, id: string) => rowOf(doc, id).querySelector(".dot").className;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = async (doc: any) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };

function answers(...list: unknown[]) {
  let i = 0;
  return () => list[Math.min(i++, list.length - 1)];
}

test("W1: a History row says the questions it raised that still wait, and a running one that waits has the amber dot", async () => {
  const rows = [
    row("s-wait", { state: "waiting", waiting: 1 }),
    row("s-run", { state: "running" }),
    row("s-ended", { waiting: 2 }),
    row("s-plain"),
  ];
  const { doc } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": { total: 4, rows, next: null } } });
  await tick();
  assert.equal(counts(doc, "s-wait"), "1 question waiting for you, 1 secret masked", "Running now's order: the question first");
  assert.equal(dot(doc, "s-wait"), "dot warn", "Running now's dot for an agent waiting for your OK");
  assert.match(rowOf(doc, "s-wait").textContent, /Task s-wait/, "the row keeps its prompt");
  assert.match(rowOf(doc, "s-wait").textContent, /running now, started/);
  assert.equal(counts(doc, "s-run"), "1 secret masked");
  assert.equal(dot(doc, "s-run"), "dot ok");
  assert.equal(counts(doc, "s-ended"), "1 secret masked, 2 questions waiting for you", "Earlier's words and order for an ended session's questions");
  assert.equal(dot(doc, "s-ended"), "dot", "an ended session's dot, waiting or not");
  assert.match(rowOf(doc, "s-ended").textContent, /ended/);
  assert.equal(counts(doc, "s-plain"), "1 secret masked");
  // The count is a count like the others: number and word kept together.
  const word = [...rowOf(doc, "s-wait").querySelectorAll(".count-word")].map((s: { textContent: string }) => s.textContent);
  assert.ok(word.includes("1 question"), JSON.stringify(word));
});

test("W2: the poll follows an answer: the row loses its count and gets the green dot back", async () => {
  const before = { total: 1, rows: [row("s-wait", { state: "waiting", waiting: 1 })], next: null };
  const after = { total: 1, rows: [row("s-wait", { state: "running" })], next: null };
  const { doc } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": answers(before, after) } });
  await tick();
  assert.equal(counts(doc, "s-wait"), "1 question waiting for you, 1 secret masked");
  assert.equal(dot(doc, "s-wait"), "dot warn");
  await poll(doc);
  assert.equal(counts(doc, "s-wait"), "1 secret masked");
  assert.equal(dot(doc, "s-wait"), "dot ok");
});

test("W3: protection failed outranks the amber dot; the question is still counted", async () => {
  const rows = [row("s-bad", { state: "waiting", waiting: 1, holds: false })];
  const { doc } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": { total: 1, rows, next: null } } });
  await tick();
  assert.equal(dot(doc, "s-bad"), "dot bad");
  assert.equal(counts(doc, "s-bad"), "protection failed, 1 question waiting for you, 1 secret masked", "the mark first, then the question, as on Home");
});

test("W4: an ended History row says 'changes to 1 file not applied' after its counts, with the amber dot, linking its page at the block", async () => {
  const before = { total: 2, rows: [row("s-lost", { waiting: 1, notApplied: 3 }), row("s-old")], next: null };
  const after = { total: 2, rows: [row("s-lost", { waiting: 1, notApplied: 3 }), row("s-old", { notApplied: 1 })], next: null };
  const { doc } = load({ extensions: "", url: URL, homeVm: home(), routes: { "GET home/history": answers(before, after) } });
  await tick();
  assert.equal(counts(doc, "s-lost"), "1 secret masked, changes to 3 files not applied, 1 question waiting for you", "Earlier's order");
  assert.equal(dot(doc, "s-lost"), "dot warn");
  const link = rowOf(doc, "s-lost").querySelector("a.agent-not-applied-link");
  assert.match(link.getAttribute("href"), /\/agents\/s-lost\?go=not-applied$/);
  assert.equal(link.dataset.land, "not-applied");
  // A row from an older server, or one with none: unchanged.
  assert.equal(counts(doc, "s-old"), "1 secret masked");
  assert.equal(dot(doc, "s-old"), "dot");
  await poll(doc);
  assert.equal(counts(doc, "s-old"), "1 secret masked, changes to 1 file not applied", "the poll draws the new count");
  assert.equal(dot(doc, "s-old"), "dot warn");
});
