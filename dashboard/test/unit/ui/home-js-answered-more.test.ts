/**
 * home-js-answered-more.test — Approvals' two lists of the past go back
 * past their newest 20 (dashboard.md §4.25 *Past the newest 20*). Until
 * 2026-10-18 Answered earlier drew the 20 answers `/api/home` gave and Rule
 * changes read `?limit=20`, each with nothing after its last row: the 21st
 * answer's reversal was gone from the page, nothing said the list was cut,
 * and `/approvals/<id>` for an older answer said "no longer waiting".
 *
 *   A1  Answered earlier says "Showing 20 of 63 answers." with Show more,
 *       which reads the next 20 after the last row; each new row has its
 *       reversal, and the first one takes the focus;
 *   A2  a Show more that fails says why beside the button, which is on
 *       again and has the focus back; the next press reads the same cursor;
 *   A3  the poll keeps the 40 rows drawn: it reads as many again, an answer
 *       given since comes in on top, the rows pushed down stay;
 *   A4  `/approvals/<id>` for the 30th answer reads it and marks it in
 *       place, "already answered"; one that is nowhere says "no longer
 *       waiting", as before;
 *   A5  Rule changes asks one more than it draws: Show more when it came,
 *       the next read asks 41, the first new row takes the focus, a poll
 *       reads 41 again; a failed Show more says why and keeps the focus;
 *   A6  a link to Approvals starts both lists over at 20.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";

const URL = "http://127.0.0.1:4500/mandu/approvals";
const id = (i: number) => `egr-${String(i).padStart(2, "0")}`;
const ans = (i: number, over: Record<string, unknown> = {}) => ({
  id: id(i),
  sentence: [{ kind: "text", text: `Claude Code wants to send your secret KEY_${i} to ` }, { kind: "code", text: `h${i}.example` }],
  outcome: "allowed", decidedAt: Date.now() - (i + 1) * 60_000, sessions: ["s1"],
  actions: [{ approve: false, label: "Block" }], ...over,
});
const ALL = Array.from({ length: 63 }, (_, i) => ans(i));
const vm = (rows = ALL.slice(0, 20), total = 63) => home({ waiting: [], answered: rows, answeredTotal: total, verdict: "secrets-only" });
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const rows = (doc: Doc) => [...doc.querySelectorAll("#approvals-answered .row.answered")] as Doc[];
const ids = (doc: Doc) => rows(doc).map((r) => r.dataset.id);
const more = (doc: Doc) => doc.querySelector("#approvals-answered .answered-more");
const moreButton = (doc: Doc) => more(doc)?.querySelector("button.show-rest");
const said = (doc: Doc) => doc.getElementById(moreButton(doc).getAttribute("aria-describedby"));
const poll = async (doc: Doc) => { doc.dispatchEvent(new doc.defaultView.Event("visibilitychange")); await tick(); };
const reads = (calls: Array<{ url: string }>, path: string) => calls.filter((c) => c.url.startsWith("/mandu/api/" + path)).map((c) => c.url.slice("/mandu/api/".length));
const answers = (...list: unknown[]) => { let i = 0; return () => list[Math.min(i++, list.length - 1)]; };

test("A1: Answered earlier says how many answers there are and Show more brings the next 20, each with its reversal, the first new one focused", async () => {
  const { doc, calls } = load({ extensions: "", url: URL, homeVm: vm(), routes: { "GET home/answered?after=egr-19&limit=20": { rows: ALL.slice(20, 40), total: 63, next: id(39) } } });
  await tick();
  assert.deepEqual(ids(doc), ALL.slice(0, 20).map((a) => a.id));
  assert.equal(said(doc).textContent, "Showing 20 of 63 answers.", "the list says it is cut");
  assert.equal(moreButton(doc).textContent, "Show more");
  assert.equal(reads(calls, "home/answered").length, 0, "nothing read before the press");
  moreButton(doc).click();
  await tick();
  assert.deepEqual(reads(calls, "home/answered"), ["home/answered?after=egr-19&limit=20"], "the next page after the last row drawn");
  assert.deepEqual(ids(doc), ALL.slice(0, 40).map((a) => a.id));
  for (const r of rows(doc).slice(20)) assert.equal(r.querySelector("button").textContent, "Block instead", "each new row has its reversal");
  assert.equal(doc.activeElement, rows(doc)[20], "the first new row takes the focus");
  assert.equal(said(doc).textContent, "Showing 40 of 63 answers.");
});

test("A1b: no line when every answer is drawn", async () => {
  const { doc } = load({ extensions: "", url: URL, homeVm: vm(ALL.slice(0, 5), 5) });
  await tick();
  assert.equal(rows(doc).length, 5);
  assert.equal(more(doc), null);
});

test("A2: a Show more that fails says why beside the button, which is on with the focus back; the next press reads the same cursor", async () => {
  const route = answers({ status: 503, body: { error: "the approval queue could not be read", unreachable: true } }, { rows: ALL.slice(20, 40), total: 63, next: id(39) });
  const { doc, calls } = load({ extensions: "", url: URL, homeVm: vm(), routes: { "GET home/answered?after=egr-19&limit=20": route } });
  await tick();
  moreButton(doc).focus();
  moreButton(doc).click();
  await tick();
  assert.equal(rows(doc).length, 20, "the rows drawn stay");
  assert.match(said(doc).textContent, /^Could not read more of your answers\. The protection service is not running\./);
  assert.equal(moreButton(doc).disabled, false, "the button is on again");
  assert.equal(doc.activeElement, moreButton(doc), "and has the focus back");
  moreButton(doc).click();
  await tick();
  assert.deepEqual(reads(calls, "home/answered"), ["home/answered?after=egr-19&limit=20", "home/answered?after=egr-19&limit=20"]);
  assert.equal(rows(doc).length, 40);
  assert.equal(doc.activeElement, rows(doc)[20]);
});

test("A3: the poll keeps the 40 rows drawn: it reads as many again, a new answer on top, the rows pushed down stay", async () => {
  const fresh = ans(99, { id: "egr-new", decidedAt: Date.now() });
  const again = { rows: [fresh, ...ALL.slice(0, 39)], total: 64, next: id(38) };
  const { doc, calls, setHome } = load({ extensions: "", url: URL, homeVm: vm(), routes: {
    "GET home/answered?after=egr-19&limit=20": { rows: ALL.slice(20, 40), total: 63, next: id(39) },
    "GET home/answered?limit=40": again,
  } });
  await tick();
  moreButton(doc).click();
  await tick();
  assert.equal(rows(doc).length, 40);
  setHome(vm([fresh, ...ALL.slice(0, 19)], 64));
  await poll(doc);
  assert.deepEqual(reads(calls, "home/answered").slice(-1), ["home/answered?limit=40"], "the poll reads as many as are drawn");
  assert.equal(ids(doc)[0], "egr-new", "the answer given since on top");
  assert.deepEqual(ids(doc).slice(1), ALL.slice(0, 40).map((a) => a.id), "none of the 40 drawn goes");
  assert.equal(said(doc).textContent, "Showing 41 of 64 answers.");
  assert.equal(doc.getElementById("page-approvals").hidden, false);
});

test("A3b: a poll that brings the same answers draws nothing again", async () => {
  const { doc } = load({ extensions: "", url: URL, homeVm: vm(), routes: {
    "GET home/answered?after=egr-19&limit=20": { rows: ALL.slice(20, 40), total: 63, next: id(39) },
    "GET home/answered?limit=40": { rows: ALL.slice(0, 40), total: 63, next: id(39) },
  } });
  await tick();
  moreButton(doc).click();
  await tick();
  const drawn = rows(doc);
  const block = drawn[30].querySelector("button");
  block.focus();
  await poll(doc);
  assert.equal(rows(doc)[30], drawn[30], "the same row, not drawn again");
  assert.equal(doc.activeElement, block, "the focus where it was");
});

test("A4: /approvals/<id> for the 30th answer reads it and marks it in place; one that is nowhere says no longer waiting", async () => {
  const { doc, calls } = load({ extensions: "", url: URL + "/" + id(29), homeVm: vm(), routes: { "GET home/answered?limit=500": { rows: ALL, total: 63, next: null } } });
  await tick();
  assert.deepEqual(reads(calls, "home/answered"), ["home/answered?limit=500"]);
  assert.deepEqual(ids(doc), ALL.slice(0, 40).map((a) => a.id), "drawn down to the page that holds it");
  const row = rows(doc).find((r) => r.dataset.id === id(29));
  assert.ok(row.classList.contains("focus"), "the answer is marked");
  const note = doc.getElementById("approvals-focus-note");
  assert.equal(note.hidden, false);
  assert.equal(note.textContent, "That question was already answered. Its answer is marked below, under Answered earlier.");
  assert.equal(said(doc).textContent, "Showing 40 of 63 answers.", "Show more goes on from there");

  const gone = load({ extensions: "", url: URL + "/egr-zz", homeVm: vm(), routes: { "GET home/answered?limit=500": { rows: ALL, total: 63, next: null } } });
  await tick();
  assert.equal(gone.doc.getElementById("approvals-focus-note").textContent, "That question is no longer waiting for you.");
  assert.equal(rows(gone.doc).length, 20, "no row brought for it");
  // Every answer drawn already: no read at all.
  const all = load({ extensions: "", url: URL + "/egr-zz", homeVm: vm(ALL.slice(0, 5), 5) });
  await tick();
  assert.equal(reads(all.calls, "home/answered").length, 0);
  assert.equal(all.doc.getElementById("approvals-focus-note").textContent, "That question is no longer waiting for you.");
});

const change = (i: number) => ({ id: `pc-${String(i).padStart(3, "0")}`, sentence: `You changed rule ${i}`, rows: [], createdAt: Date.now() - (i + 1) * 60_000, undoable: true, undone: false });
const CH = Array.from({ length: 45 }, (_, i) => change(i));
const changeRows = (doc: Doc) => [...doc.querySelectorAll("#approvals-rule-history .row.answered")] as Doc[];
const changesMore = (doc: Doc) => doc.querySelector("#approvals-rule-history .changes-more button.show-rest");

test("A5: Rule changes asks one more than it draws, offers Show more when it came, reads 41 on, the first new row focused, the poll reads as many", async () => {
  const failing = answers({ status: 503, body: { error: "boom", unreachable: true } }, { changes: CH.slice(0, 41) });
  const { doc, calls } = load({ extensions: "", url: URL, homeVm: vm(), routes: {
    "GET policy/changes?limit=21": { changes: CH.slice(0, 21) },
    "GET policy/changes?limit=41": failing,
  } });
  await tick();
  assert.equal(changeRows(doc).length, 20, "20 drawn of the 21 read");
  assert.equal(doc.getElementById(changesMore(doc).getAttribute("aria-describedby")).textContent, "Showing the newest 20 changes.");
  changesMore(doc).focus();
  changesMore(doc).click();
  await tick();
  assert.equal(changeRows(doc).length, 20, "a failed read keeps the rows");
  assert.match(doc.getElementById(changesMore(doc).getAttribute("aria-describedby")).textContent, /^Could not read more of the rule changes\. The protection service is not running\./);
  assert.equal(doc.activeElement, changesMore(doc), "the button has the focus back");
  changesMore(doc).click();
  await tick();
  assert.equal(changeRows(doc).length, 40);
  assert.equal(doc.activeElement, changeRows(doc)[20], "the first new row takes the focus");
  assert.equal(changeRows(doc)[20].querySelector("button").textContent, "Undo", "with its Undo");
  await poll(doc);
  assert.equal(reads(calls, "policy/changes").slice(-1)[0], "policy/changes?limit=41", "the poll reads as many as are drawn, and one more");
  assert.equal(changeRows(doc).length, 40, "the poll keeps them");
  assert.equal(doc.activeElement, changeRows(doc)[20], "and the focus");
});

test("A5b: no Show more when no more came; the route's most is never passed", async () => {
  const { doc, calls } = load({ extensions: "", url: URL, homeVm: vm(), routes: { "GET policy/changes?limit=21": { changes: CH.slice(0, 7) } } });
  await tick();
  assert.equal(changeRows(doc).length, 7);
  assert.equal(changesMore(doc), null);
  for (const u of reads(calls, "policy/changes")) assert.ok(Number(/limit=(\d+)/.exec(u)![1]) <= 500, u);
});

test("A6: a link to Approvals starts both lists over at their newest 20", async () => {
  const { doc } = load({ extensions: "", url: URL, homeVm: vm(), routes: {
    "GET home/answered?after=egr-19&limit=20": { rows: ALL.slice(20, 40), total: 63, next: id(39) },
    "GET policy/changes?limit=21": { changes: CH.slice(0, 21) },
    "GET policy/changes?limit=41": { changes: CH.slice(0, 41) },
  } });
  await tick();
  moreButton(doc).click();
  changesMore(doc).click();
  await tick();
  assert.equal(rows(doc).length, 40);
  assert.equal(changeRows(doc).length, 40);
  (doc.querySelector('[data-page-link="home"]') as Doc).click();
  await tick();
  (doc.querySelector('[data-page-link="approvals"]') as Doc).click();
  await tick();
  assert.equal(rows(doc).length, 20);
  assert.equal(changeRows(doc).length, 20);
});
