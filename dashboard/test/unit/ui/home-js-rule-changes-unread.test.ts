/**
 * home-js-rule-changes-unread.test — Approvals › Rule changes says when it
 * could not be read, instead of vanishing (dashboard.md §4.25 *Rule changes
 * says when it could not be read*). A poll read that fails keeps its cause:
 * the section stays, with one could-not line in place of its rows (no row,
 * no live Undo), and its section link stays; the next read that works draws
 * the rows again. A link to a rule change whose read failed says the list
 * could not be read, not that the change is missing. A service that offers
 * no rule changes (501) keeps the section hidden, as before.
 *
 *   U1  read, then a read with no answer, then a read: rows, the line, rows
 *   U2  the service not running: its cause in the line
 *   U3  /approvals/pc-… whose first read failed: the could-not-be-read note,
 *       then, after a read without it, today's "not among the changes listed"
 *   U4  501: the section stays hidden, the note is today's
 *   U5  404 "arbiter not connected" (no service behind the route): the line
 *       says so in the words of the page, never "(404)" nor "Refresh"
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the shared
 * fetch stub (home-js-fixtures.ts). Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick } from "./home-js-fixtures.js";

type Doc = any;

const change = (i: number) => ({
  id: "pc-" + String(10 - i).padStart(6, "0"), sentence: "You changed a rule on the Rules page", session: null,
  createdAt: Date.now() - (i + 1) * 60_000, undone: false, undoable: true,
  rows: [[{ kind: "text", text: "Make " }, { kind: "code", text: `/w/f${i}.pem` }, { kind: "text", text: " a secret no AI may read" }]],
});
const THREE = [change(0), change(1), change(2)];
const CHANGES = "GET policy/changes?limit=21";
const URL = "http://127.0.0.1:4500/mandu/approvals";
const LINE = "Could not read your rule changes.";
const NOTE = "Rule changes could not be read just now, so this change cannot be shown. It is still kept; try again in a moment.";

/** Every read of the changes answers what `answer.now` holds (the page and
 *  the Home poll each read once when the page opens). */
function answering(first: unknown) {
  const answer = { now: first };
  return { answer, route: () => answer.now };
}
const NO_ANSWER = { status: 0, body: null };
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(60);
}
const block = (doc: Doc) => doc.getElementById("approvals-rule-history-block");
const host = (doc: Doc) => doc.getElementById("approvals-rule-history");
const rows = (doc: Doc) => [...host(doc).querySelectorAll(".row")];
const undos = (doc: Doc) => [...host(doc).querySelectorAll("button")].filter((b: any) => b.textContent === "Undo");
const link = (doc: Doc) => doc.querySelector('nav.section-links a[data-section="rule-changes"]');
const linkShown = (doc: Doc) => !link(doc).closest("li").hidden;
const note = (doc: Doc) => doc.getElementById("approvals-focus-note");

test("U1: a read with no answer leaves the section, one line in place of the rows and no Undo; the next read draws them again", async () => {
  const { answer, route } = answering({ changes: THREE });
  const { doc } = load({ url: URL, homeVm: home(), routes: { [CHANGES]: route } });
  await tick(60);
  assert.equal(block(doc).hidden, false);
  assert.equal(rows(doc).length, 3);
  assert.equal(undos(doc).length, 3);
  assert.ok(linkShown(doc), "the section link is under the title");

  answer.now = NO_ANSWER;
  await poll(doc);
  assert.equal(block(doc).hidden, false, "the section stays");
  assert.equal(rows(doc).length, 0, "no row of the read before");
  assert.equal(undos(doc).length, 0, "no live Undo");
  assert.equal(host(doc).querySelectorAll(".changes-unread").length, 1);
  assert.equal(host(doc).textContent, LINE + " The dashboard could not reach its own server. Refresh in a moment.");
  assert.ok(linkShown(doc), "its link stays");
  assert.equal(doc.getElementById("changes-search").hidden, true, "no box to find a change in what was not read");

  answer.now = { changes: THREE };
  await poll(doc);
  assert.equal(rows(doc).length, 3, "the rows again");
  assert.equal(undos(doc).length, 3);
  assert.equal(host(doc).querySelector(".changes-unread"), null, "the line went");
  assert.equal(block(doc).hidden, false);
});

test("U2: the protection service not running: the line says so", async () => {
  const { doc } = load({ url: URL, homeVm: home(), routes: { [CHANGES]: { status: 503, body: { error: "arbiter unreachable", unreachable: true } } } });
  await tick(60);
  assert.equal(block(doc).hidden, false);
  assert.equal(rows(doc).length, 0);
  assert.equal(host(doc).textContent, LINE + " The protection service is not running.");
  assert.ok(linkShown(doc));
});

test("U3: a link to a rule change whose first read failed says the list could not be read; after a read without it, the note is today's", async () => {
  const { answer, route } = answering(NO_ANSWER);
  const { doc } = load({ url: URL + "/pc-000003", homeVm: home(), routes: { [CHANGES]: route } });
  await tick(60);
  assert.equal(note(doc).hidden, false);
  assert.equal(note(doc).textContent, NOTE);
  assert.doesNotMatch(note(doc).textContent, /not among the changes listed/);
  assert.equal(block(doc).hidden, false, "the section it points to is there");
  assert.equal(host(doc).textContent, LINE + " The dashboard could not reach its own server. Refresh in a moment.");

  answer.now = { changes: THREE };
  await poll(doc);
  assert.equal(rows(doc).length, 3);
  assert.equal(note(doc).textContent, "That rule change is not among the changes listed.");
});

test("U4: a dashboard whose service offers no rule changes (501) keeps the section hidden, and the note is today's", async () => {
  const { doc } = load({
    url: URL + "/pc-000003", homeVm: home(),
    routes: { [CHANGES]: { status: 501, body: { error: "not supported by this arbiter" } } },
  });
  await tick(60);
  assert.equal(block(doc).hidden, true);
  assert.equal(host(doc).textContent, "");
  assert.equal(linkShown(doc), false, "nor its link");
  assert.equal(note(doc).textContent, "That rule change is not among the changes listed.");
});

test("U5: no service behind the route (404 arbiter not connected): the line says so in the words of the page, never its status", async () => {
  const { doc } = load({ url: URL, homeVm: home(), routes: { [CHANGES]: { status: 404, body: { error: "arbiter not connected" } } } });
  await tick(60);
  assert.equal(block(doc).hidden, false);
  assert.equal(rows(doc).length, 0);
  assert.equal(host(doc).textContent, LINE + " The protection service is not connected.");
  assert.doesNotMatch(host(doc).textContent, /\(404\)|Refresh in a moment/);
});
