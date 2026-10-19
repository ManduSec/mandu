/**
 * home-js-proposals-order.test — a read of Approvals' rule-change lists
 * asked before your answer never draws over it (public/js/home.js
 * `readsInOrder`, `loadProposals`, `loadRuleHistory`; dashboard.md §4.25
 * *A read asked before your answer to a rule change never draws over it*).
 *
 * *Rule changes your agent asked for* is read by every Home poll, by the
 * read after an Allow or a Not now, and by Rules; *Rule changes* (the
 * history) by every poll on Approvals, on opening it and after an Undo.
 * Until 2026-10-12 the answer that came LAST drew, even when its read was
 * asked first, so on a slow network:
 *
 *   - a request you allowed came back as waiting, with live Allow and
 *     Not now, and the Approvals badge and the Rules line counted it again,
 *     until the next poll;
 *   - a change you undid lost its "Undone" and got a live Undo back.
 *
 * Now an answer to a read asked before the latest one taken, or before your
 * own answer to that list answered, is dropped; reads answered in order are
 * each taken, and a refused answer changes nothing. Drives home.js in jsdom
 * over the shared fetch stub (home-js-fixtures.ts), with routes that hold an
 * answer until the test sends it; across the real arbiter and dashboard,
 * tests/stack/proposals-order.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick } from "./home-js-fixtures.js";

const APPROVALS = "http://127.0.0.1:4500/mandu/approvals";
const PENDING = "GET policy/proposals?status=pending";
const CHANGES = "GET policy/changes?limit=21";

const request = (id: string, path: string) => ({
  id, status: "pending", requester: "Your agent", createdAt: Date.now() - 60_000,
  rows: [[{ kind: "text", text: "Let " }, { kind: "code", text: path }, { kind: "text", text: " be sent to api.stripe.com" }]],
  wouldLet: [], capped: false, overBroad: false, reason: null,
});
const P1 = request("pp-000001", "/srv/app/.env");
const P2 = request("pp-000002", "/srv/app/deploy.conf");
const P3 = request("pp-000003", "/srv/app/ci.yaml");
const change = (id: string, path: string, over: Record<string, unknown> = {}) => ({
  id, sentence: "Your agent tightened your rules", rows: [[{ kind: "text", text: "Lock " }, { kind: "code", text: path }]],
  createdAt: Date.now() - 60_000, undone: false, undoable: true, ...over,
});
const C1 = change("pc-000001", "/srv/app/.env");
const C2 = change("pc-000002", "/srv/app/deploy.conf");

/** An answer held until the test sends it: `send` answers it, `fail` gives
 *  no answer (the page's read fails). */
function held() {
  let send!: (v: unknown) => void;
  let fail!: (e: unknown) => void;
  const answer = new Promise<unknown>((a, b) => { send = a; fail = b; });
  return { answer, send, fail };
}
/** A GET answered in turn: each entry is the answer to one read, the last
 *  one to every read after it. */
const inTurn = (answers: unknown[]) => () => (answers.length > 1 ? answers.shift() : answers[0]);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const cards = (doc: Doc) => [...doc.querySelectorAll("#approvals-proposals .proposal")] as Doc[];
const cardOf = (doc: Doc, id: string) => cards(doc).find((c) => c.dataset.id === id);
const rows = (doc: Doc) => [...doc.querySelectorAll("#approvals-rule-history .row")] as Doc[];
const rowOf = (doc: Doc, id: string) => rows(doc).find((r) => r.dataset.id === id);
const button = (root: Doc, label: string) => [...root.querySelectorAll("button")].find((b: Doc) => b.textContent === label);
/** Every live (not turned off) answer button of the rule-change requests. */
const liveAnswers = (doc: Doc) => [...doc.querySelectorAll("#approvals-proposals button")].filter((b: Doc) => !b.disabled);
const badge = (doc: Doc): string => doc.getElementById("nav-approvals-count").textContent;
/** A poll, as a return to the tab makes one. */
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
}
/** Press an answer the way a keyboard does: the focus on it first. */
async function press(b: Doc): Promise<void> {
  assert.ok(b, "the button is drawn");
  b.focus();
  b.click();
  await tick(30);
}

test("a request you allowed never comes back as waiting from a poll asked before the answer", async () => {
  const before = held();
  const { doc, calls } = load({ url: APPROVALS, routes: {
    [PENDING]: inTurn([{ proposals: [P1] }, before.answer, { proposals: [] }]),
    "POST policy/proposals/pp-000001": { proposal: { id: P1.id, status: "approved" } },
  } });
  await tick(30);
  assert.ok(cardOf(doc, P1.id), "the request waits");
  assert.equal(badge(doc), "2", "one question and one request");
  await poll(doc); // its read of the requests is held
  await press(button(cardOf(doc, P1.id), "Allow"));
  assert.ok(calls.some((c) => c.method === "POST" && c.url === "/mandu/api/policy/proposals/pp-000001"), "the answer was sent");
  assert.equal(cards(doc).length, 0, "answered: its card is gone");
  assert.equal(badge(doc), "1");
  const focused = doc.activeElement;
  // The poll asked before the answer comes now, with the request waiting.
  before.send({ proposals: [P1] });
  await tick(30);
  assert.equal(cards(doc).length, 0, "never drawn as waiting again");
  assert.equal(liveAnswers(doc).length, 0, "no live Allow or Not now");
  assert.equal(doc.getElementById("approvals-proposals-block").hidden, true);
  assert.equal(badge(doc), "1", "the badge never counts it again");
  assert.equal(doc.activeElement, focused, "the focus stays");
  // The next poll still draws what it reads: the page did not stop taking answers.
  await poll(doc);
  assert.equal(cards(doc).length, 0);
});

test("Not now: the request that took its place keeps the focus when an older read lists the answered one", async () => {
  const before = held();
  const { doc } = load({ url: APPROVALS, routes: {
    [PENDING]: inTurn([{ proposals: [P1, P2] }, before.answer, { proposals: [P2] }]),
    "POST policy/proposals/pp-000001": { proposal: { id: P1.id, status: "denied" } },
  } });
  await tick(30);
  await poll(doc);
  await press(button(cardOf(doc, P1.id), "Not now"));
  assert.deepEqual(cards(doc).map((c) => c.dataset.id), [P2.id]);
  const next = cardOf(doc, P2.id);
  assert.equal(doc.activeElement, next, "the next request has the focus");
  before.send({ proposals: [P1, P2] });
  await tick(30);
  assert.deepEqual(cards(doc).map((c) => c.dataset.id), [P2.id], "the answered request is never drawn again");
  assert.equal(cardOf(doc, P2.id), next, "nor the other drawn anew");
  assert.equal(doc.activeElement, next, "the focus stays on it");
  assert.equal(badge(doc), "2", "one question and one request");
});

test("an older read that answers before the read after your answer never draws the request again either", async () => {
  const before = held();
  const after = held();
  const { doc } = load({ url: APPROVALS, routes: {
    [PENDING]: inTurn([{ proposals: [P1, P2] }, before.answer, after.answer]),
    "POST policy/proposals/pp-000001": { proposal: { id: P1.id, status: "approved" } },
  } });
  await tick(30);
  await poll(doc);
  await press(button(cardOf(doc, P1.id), "Allow")); // the read after it is held too
  // The older read comes first, listing both: its poll draws without the
  // request you answered, as the server now knows it.
  before.send({ proposals: [P1, P2] });
  await tick(30);
  assert.equal(cardOf(doc, P1.id), undefined, "the answered request is not drawn as waiting");
  assert.ok(cardOf(doc, P2.id), "the other still waits");
  assert.deepEqual(liveAnswers(doc).map((b: Doc) => b.closest(".proposal").dataset.id), [P2.id, P2.id], "only the other request's Allow and Not now are live");
  assert.equal(badge(doc), "2");
  // Then the read after the answer: taken, as it is newer than the answer.
  after.send({ proposals: [P2, P3] });
  await tick(30);
  assert.deepEqual(cards(doc).map((c) => c.dataset.id), [P2.id, P3.id], "the read after the answer is drawn");
  assert.equal(badge(doc), "3");
});

test("a refused answer changes nothing: a read asked before it is still taken", async () => {
  const before = held();
  const { doc } = load({ url: APPROVALS, routes: {
    [PENDING]: inTurn([{ proposals: [P1] }, before.answer, { proposals: [P1, P2] }]),
    "POST policy/proposals/pp-000001": { status: 409, body: { error: "the rules changed since this was asked" } },
  } });
  await tick(30);
  await poll(doc);
  await press(button(cardOf(doc, P1.id), "Allow"));
  assert.match(cardOf(doc, P1.id).querySelector(".ask-error").textContent, /the rules changed since this was asked/);
  before.send({ proposals: [P1, P2] });
  await tick(30);
  assert.deepEqual(cards(doc).map((c) => c.dataset.id), [P1.id, P2.id], "the read is newer than anything the page knows: taken");
  assert.match(cardOf(doc, P1.id).querySelector(".ask-error").textContent, /the rules changed since this was asked/, "the refusal's words stay");
});

test("reads of the requests answered in the order they were asked are each taken, and an older one after a newer is dropped", async () => {
  const a = held();
  const b = held();
  const c = held();
  const d = held();
  const { doc } = load({ url: APPROVALS, routes: { [PENDING]: inTurn([{ proposals: [] }, a.answer, b.answer, c.answer, d.answer]) } });
  await tick(30);
  assert.equal(cards(doc).length, 0);
  await poll(doc);
  await poll(doc);
  a.send({ proposals: [P1] });
  await tick(30);
  assert.deepEqual(cards(doc).map((x) => x.dataset.id), [P1.id], "the older read, first in, is drawn");
  b.send({ proposals: [P1, P2] });
  await tick(30);
  assert.deepEqual(cards(doc).map((x) => x.dataset.id), [P1.id, P2.id], "then the newer");
  await poll(doc);
  await poll(doc);
  d.send({ proposals: [P1, P2, P3] });
  await tick(30);
  c.send({ proposals: [] });
  await tick(30);
  assert.deepEqual(cards(doc).map((x) => x.dataset.id), [P1.id, P2.id, P3.id], "an older read that answers after a newer one is dropped");
  assert.equal(badge(doc), "4");
});

test("Rules never counts a request you answered again: its line keeps the newer count", async () => {
  const before = held();
  const { doc } = load({ url: APPROVALS, routes: {
    [PENDING]: inTurn([{ proposals: [P1, P2] }, before.answer, { proposals: [P2] }]),
    "POST policy/proposals/pp-000001": { proposal: { id: P1.id, status: "approved" } },
    "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [] } },
  } });
  await tick(30);
  await poll(doc);
  await press(button(cardOf(doc, P1.id), "Allow"));
  doc.querySelector('#nav [data-page-link="rules"]').click();
  await tick(30);
  const line = doc.getElementById("rules-pending");
  assert.match(line.textContent, /^1 rule change waits for your OK\./);
  before.send({ proposals: [P1, P2] });
  await tick(30);
  assert.match(line.textContent, /^1 rule change waits for your OK\./, "never \"2 rule changes wait\"");
  assert.equal(badge(doc), "2");
});

test("a change you undid never gets its Undo back from a history read asked before the Undo", async () => {
  const before = held();
  const { doc, calls } = load({ url: APPROVALS, routes: {
    // The read on opening the page, the first Home read's, then the poll's.
    [CHANGES]: inTurn([{ changes: [C1, C2] }, { changes: [C1, C2] }, before.answer, { changes: [{ ...C1, undoable: false, undone: true }, C2] }]),
    "POST policy/changes/pc-000001/undo": { undone: C1.id },
  } });
  await tick(30);
  assert.ok(button(rowOf(doc, C1.id), "Undo"));
  await poll(doc); // its history read is held
  await press(button(rowOf(doc, C1.id), "Undo"));
  assert.ok(calls.some((c) => c.method === "POST" && c.url === "/mandu/api/policy/changes/pc-000001/undo"), "the Undo was sent");
  assert.match(rowOf(doc, C1.id).textContent, /Undone$/);
  assert.equal(button(rowOf(doc, C1.id), "Undo"), undefined);
  const focused = doc.activeElement;
  // The poll's read, asked before the Undo, comes with Undo still on.
  before.send({ changes: [C1, C2] });
  await tick(30);
  assert.match(rowOf(doc, C1.id).textContent, /Undone$/, "it still says Undone");
  assert.equal(button(rowOf(doc, C1.id), "Undo"), undefined, "no Undo on a change already undone");
  assert.ok(button(rowOf(doc, C2.id), "Undo"), "the other change keeps its own");
  assert.equal(doc.activeElement, focused, "the focus stays");
});

test("an older history read that answers before the read after the Undo never turns Undo back on", async () => {
  const before = held();
  const after = held();
  const { doc } = load({ url: APPROVALS, routes: {
    [CHANGES]: inTurn([{ changes: [C1] }, { changes: [C1] }, before.answer, after.answer]),
    "POST policy/changes/pc-000001/undo": { undone: C1.id },
  } });
  await tick(30);
  await poll(doc);
  await press(button(rowOf(doc, C1.id), "Undo")); // the read after it is held too
  before.send({ changes: [C1] });
  await tick(30);
  const undo = button(rowOf(doc, C1.id), "Undo");
  assert.ok(!undo || undo.disabled, "Undo never comes back on for a change already undone");
  after.send({ changes: [{ ...C1, undoable: false, undone: true }] });
  await tick(30);
  assert.match(rowOf(doc, C1.id).textContent, /Undone$/, "the read after the Undo is drawn");
  assert.equal(button(rowOf(doc, C1.id), "Undo"), undefined);
});

test("an older history read that failed never hides the list a newer read drew; reads in order are each taken", async () => {
  const lost = held();
  const next = held();
  const { doc } = load({ url: APPROVALS, routes: { [CHANGES]: inTurn([{ changes: [C1] }, { changes: [C1] }, lost.answer, next.answer, { changes: [C1, C2] }]) } });
  await tick(30);
  assert.deepEqual(rows(doc).map((r) => r.dataset.id), [C1.id]);
  await poll(doc); // held
  await poll(doc); // held
  next.send({ changes: [C2, C1] });
  await tick(30);
  assert.deepEqual(rows(doc).map((r) => r.dataset.id), [C2.id, C1.id], "the newer read is drawn");
  lost.fail(new TypeError("Failed to fetch"));
  await tick(30);
  assert.equal(doc.getElementById("approvals-rule-history-block").hidden, false, "the older failure never hides it");
  assert.deepEqual(rows(doc).map((r) => r.dataset.id), [C2.id, C1.id]);
  // In order: the next poll's read is taken.
  await poll(doc);
  assert.deepEqual(rows(doc).map((r) => r.dataset.id), [C1.id, C2.id], "the next read is drawn");
});
