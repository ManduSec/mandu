/**
 * home-js-suggested-focus.test — on the product page's Rules, Keys Mandu
 * found keeps the keyboard focus, and an opened row's buttons name their row
 * (dashboard.md §4.25 *Keys Mandu found keeps the focus*).
 *
 * Until 2026-10-11, in headless Chromium:
 *   - a row's ⋯ (open or close) and its tick box left the focus on <body>:
 *     each draws the list again from nothing (renderSuggested), as does the
 *     poll while a scan runs;
 *   - Not a secret went off during its POST, and Chromium drops the focus of
 *     a button turned off; the row is then gone;
 *   - Scan for keys went off for the whole scan and came back on with no
 *     focus; a tick during its POST turned it back on;
 *   - Show in policy.yaml and Not a secret named no row, and Show kept its
 *     words while the lines showed.
 * Now the focus goes back to the control drawn at its place that reads the
 * same (pollPlace / pollRefocus): the row's ⋯ or tick box, Show (as Hide),
 * else the card's heading; a refused Not a secret or Scan is given the focus
 * back, described by the card's error line; Scan stays off through its POST
 * and gets the focus back when the scan ends. A press without the focus,
 * or with the focus elsewhere, moves nothing.
 *
 * Until 2026-10-13 the focus of a pressed Scan for keys stayed on <body> for
 * as long as the scan ran. Now it waits on the card's heading (a scan the
 * poll reads running moves it too), and only a focus still there, or one
 * that fell, goes back to Scan for keys: one the person moved stays.
 *
 * jsdom drops the focus of a control removed from the page to <body>, as
 * Chromium does, but keeps the focus of a button turned off; `press` drops
 * it then (home-js-choice-focus.test.ts), and `pressOff` only while the
 * button still has it, as Chromium does. Drives the PRODUCT page script
 * (public/js/home.js) in jsdom over the shared fetch stub
 * (home-js-fixtures.ts). Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES } from "./home-js-fixtures.js";
import { controlName, nameFaults } from "./control-names.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const REPO = "/home/u/proj";
/** A key the workspace scan found in `rel`, as the arbiter files it. */
function found(id: string, rel: string): SuggestionWire {
  return {
    id, kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: `workspace:path:${REPO}/${rel}`, source: "workspace", repoRoot: REPO,
    edits: [{ op: "lock-path", path: `${REPO}/${rel}`, level: "no-model" }],
    sentence: `Make ~/proj/${rel} a secret no AI may read`,
    evidence: { paths: [rel], blobs: [], historyOnly: false,
      findings: [{ blob: "", paths: [rel], firstCommit: null, lastCommit: null, inHead: false, inIndex: false, stillPresent: true,
        detectors: [{ kind: "content-shape", rule: "github-token", mask: "ghp_…", words: "GitHub token", line: 2 }] }] },
    impact: { historicalVersions: 0, workingTreeChanges: true, files: [rel] },
    historyOnly: false, rotate: false, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
  };
}
const CI = found("pp-000001", "tools/ci.conf");
const STAGING = found("pp-000002", "deploy/staging.conf");
const PROD = found("pp-000003", "deploy/prod.conf");
const listing = (views: SuggestionWire[], scan: unknown = null) => ({ suggestions: suggestionRows(views, "/home/u", "linux"), count: views.length, scan });
const DONE = { running: false, roots: ["~/proj"], includeHome: false, summary: "Scanned ~/proj. 3 possible keys to review.", summaryParts: null, error: null };
const RUNNING = { ...DONE, running: true, summary: null };

const rows = (doc: Doc) => [...doc.querySelectorAll("#files-suggested-list .row.suggested")] as Doc[];
const rowOf = (doc: Doc, id: string) => rows(doc).find((r) => r.dataset.id === id);
const moreOf = (doc: Doc, id: string) => rowOf(doc, id).querySelector(".file-more");
const tickOf = (doc: Doc, id: string) => rowOf(doc, id).querySelector("input.file-tick");
const detail = (doc: Doc) => doc.querySelector("#files-suggested-list .file-detail");
const button = (box: Doc, words: string) => [...box.querySelectorAll("button")].find((b: Doc) => b.textContent === words);
const byId = (doc: Doc, id: string) => doc.getElementById(id);

/** Enter on a button that goes off while it acts: Chromium drops its focus. */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "the button goes off while it acts");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
  assert.equal(btn.ownerDocument.activeElement, btn.ownerDocument.body);
}
/** Enter (or Space) on a control that keeps working: it has the focus. */
function enter(c: Doc): void {
  c.focus();
  c.click();
}
/** A tick made without the focus moving (a pointer elsewhere, a script). */
function untick(box: Doc): void {
  box.checked = !box.checked;
  box.dispatchEvent(new box.ownerDocument.defaultView.Event("change"));
}

async function opened(routes: Record<string, unknown> = {}) {
  const page = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET suggestions": listing([CI, STAGING, PROD], DONE), ...routes } });
  await tick();
  byId(page.doc, "suggest-open").click();
  await tick();
  assert.equal(rows(page.doc).length, 3);
  return page;
}

test("a row's ⋯ opens and closes it with the focus kept on that row's ⋯, drawn again; also with another row open above it", async () => {
  const { doc } = await opened();
  const old = moreOf(doc, "pp-000002");
  enter(old);
  assert.ok(detail(doc), "opened");
  assert.notEqual(moreOf(doc, "pp-000002"), old, "the list was drawn again");
  assert.equal(doc.activeElement, moreOf(doc, "pp-000002"), "the same row's ⋯, never <body>");
  assert.equal(controlName(doc.activeElement), "Close staging.conf");
  enter(moreOf(doc, "pp-000002"));
  assert.equal(detail(doc), null, "closed");
  assert.equal(doc.activeElement, moreOf(doc, "pp-000002"));
  assert.equal(controlName(doc.activeElement), "More about staging.conf");
  // The first row open above it: opening the third closes the first, and
  // the ⋯ pressed keeps the focus, not one drawn at its old rank.
  enter(moreOf(doc, "pp-000001"));
  enter(moreOf(doc, "pp-000003"));
  assert.equal(rowOf(doc, "pp-000003").nextElementSibling, detail(doc));
  assert.equal(doc.activeElement, moreOf(doc, "pp-000003"));
});

test("the tick box keeps the focus through the redraw, unticked and ticked again; Changes to save follows", async () => {
  const { doc } = await opened();
  const old = tickOf(doc, "pp-000001");
  enter(old);
  assert.notEqual(tickOf(doc, "pp-000001"), old, "the list was drawn again");
  assert.equal(doc.activeElement, tickOf(doc, "pp-000001"), "the same row's tick box");
  assert.equal(doc.activeElement.checked, false);
  assert.doesNotMatch(byId(doc, "files-pending-list").textContent, /ci\.conf/, "skipped");
  enter(tickOf(doc, "pp-000001"));
  assert.equal(doc.activeElement, tickOf(doc, "pp-000001"));
  assert.equal(doc.activeElement.checked, true);
  assert.match(byId(doc, "files-pending-list").textContent, /~\/proj\/tools\/ci\.conf/);
});

test("Show in policy.yaml names its row and reads Hide while the lines show; the lines and the focus stay through a redraw", async () => {
  const { doc } = await opened();
  enter(moreOf(doc, "pp-000002"));
  const show = button(detail(doc), "Show in policy.yaml");
  assert.equal(controlName(show), "Show in policy.yaml: staging.conf");
  assert.equal(show.getAttribute("aria-expanded"), "false");
  enter(show);
  assert.equal(show.textContent, "Hide policy.yaml");
  assert.equal(controlName(show), "Hide policy.yaml: staging.conf");
  assert.equal(show.getAttribute("aria-expanded"), "true");
  assert.equal(detail(doc).querySelector(".suggestion-yaml").textContent, "paths:\n  - path: /home/u/proj/deploy/staging.conf\n    level: no-model");
  assert.equal(doc.activeElement, show);
  // Another row skipped: the list is drawn again, the lines stay shown and
  // the focus is on Hide, drawn again.
  untick(tickOf(doc, "pp-000003"));
  const hide = button(detail(doc), "Hide policy.yaml");
  assert.ok(hide, "still Hide");
  assert.notEqual(hide, show, "drawn again");
  assert.ok(detail(doc).querySelector(".suggestion-yaml"), "the lines stay shown");
  assert.equal(doc.activeElement, hide);
  enter(hide);
  assert.equal(hide.textContent, "Show in policy.yaml");
  assert.equal(detail(doc).querySelector(".suggestion-yaml"), null);
  assert.equal(doc.activeElement, hide);
  // Another row opened shows its lines closed.
  enter(hide);
  enter(moreOf(doc, "pp-000001"));
  assert.equal(button(detail(doc), "Show in policy.yaml").getAttribute("aria-expanded"), "false");
  assert.equal(detail(doc).querySelector(".suggestion-yaml"), null);
});

test("Not a secret names its row; done, the row is gone and the focus goes to the card's heading", async () => {
  const dismissed: unknown[] = [];
  const { doc } = await opened({
    "POST suggestions/dismiss": (b: { id: string }) => (dismissed.push(b), { dismissed: b.id, status: "denied", ...listing([CI, PROD], DONE) }),
  });
  enter(moreOf(doc, "pp-000002"));
  const not = button(detail(doc), "Not a secret");
  assert.equal(controlName(not), "Not a secret: staging.conf");
  press(not);
  await tick();
  assert.deepEqual(dismissed, [{ id: "pp-000002" }]);
  assert.equal(rowOf(doc, "pp-000002"), undefined, "the row is gone");
  assert.equal(doc.activeElement, byId(doc, "suggested-title"), "the card's heading, never <body>");
  assert.equal(doc.activeElement.getAttribute("tabindex"), "-1", "a heading is no Tab stop");
  assert.match(byId(doc, "rules-notice").textContent, /staging\.conf is marked as not a secret/);
});

test("Not a secret refused: the focus back on it, on again, described by the card's error line; the row stays", async () => {
  const { doc } = await opened({
    "POST suggestions/dismiss": { status: 403, body: { error: "admin session required: sign in at the dashboard" } },
  });
  enter(moreOf(doc, "pp-000002"));
  const not = button(detail(doc), "Not a secret");
  assert.equal(not.getAttribute("aria-describedby"), null, "described only once refused");
  press(not);
  await tick();
  assert.match(byId(doc, "suggest-error").textContent, /^Sign in first/);
  assert.ok(rowOf(doc, "pp-000002"), "still waiting");
  assert.equal(doc.activeElement, not, "the button pressed");
  assert.equal(not.disabled, false);
  assert.equal(not.getAttribute("aria-describedby"), "suggest-error");
});

/** Enter on Scan for keys, which goes off while it acts. Chromium drops the
 *  focus of a button turned off, but only while the button still has it: a
 *  focus the page moved before turning it off stays where it was put. */
function pressOff(btn: Doc): void {
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "the button goes off while it acts");
  if (btn.ownerDocument.activeElement !== btn) return;
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
}
const heading = (doc: Doc) => byId(doc, "suggested-title");
/** The 3 s re-read while a scan runs, held until the test runs it. */
function heldPolls(window: Doc): Array<() => void> {
  const timers: Array<() => void> = [];
  window.setTimeout = (fn: () => void, ms: number) => (ms === 3000 ? timers.push(fn) : setTimeout(fn, ms), 0);
  return timers;
}

test("Scan for keys stays off through its POST, also when a tick draws the list again; meanwhile the focus waits on the card's heading, and once the scan is done Scan for keys has it back", async () => {
  let answer: (v: unknown) => void = () => {};
  const { doc } = await opened({
    "POST suggestions/scan": () => new Promise((r) => { answer = r; }),
  });
  const scan = byId(doc, "suggest-scan");
  assert.equal(scan.getAttribute("aria-describedby"), "suggest-error", "its error line describes it");
  pressOff(scan);
  assert.equal(doc.activeElement, heading(doc), "the card's heading, never <body>");
  assert.equal(heading(doc).getAttribute("tabindex"), "-1", "a heading is no Tab stop");
  await tick();
  untick(tickOf(doc, "pp-000001"));
  assert.equal(scan.disabled, true, "still off while its POST is on its way");
  assert.equal(scan.textContent, "Scanning…");
  assert.match(byId(doc, "suggest-status").textContent, /^Scanning ~\/proj|^Scanning the projects/);
  assert.equal(doc.activeElement, heading(doc), "a redraw of the list leaves it there");
  answer(listing([CI, STAGING, PROD], DONE));
  await tick();
  assert.equal(scan.disabled, false);
  assert.equal(scan.textContent, "Scan for keys");
  assert.equal(byId(doc, "suggest-status").textContent, "Scanned ~/proj. 3 possible keys to review.");
  assert.equal(doc.activeElement, scan, "Scan for keys, on again");
  // On, a redraw (a tick) moves its focus nowhere, not even for a moment.
  let moved = 0;
  heading(doc).addEventListener("focus", () => moved++);
  untick(tickOf(doc, "pp-000002"));
  assert.equal(doc.activeElement, scan);
  assert.equal(moved, 0, "the heading never took it");
});

test("a scan still running after its POST: the poll draws the list again, a focused tick box keeps the focus, and Scan for keys never takes it", async () => {
  let now = listing([CI, STAGING, PROD], DONE);
  const { doc, window } = await opened({
    "POST suggestions/scan": listing([CI, STAGING], RUNNING),
    "GET suggestions": () => now,
  });
  const timers = heldPolls(window);
  const scan = byId(doc, "suggest-scan");
  pressOff(scan);
  await tick();
  assert.equal(scan.disabled, true, "the scan runs");
  assert.equal(doc.activeElement, heading(doc), "it waits on the heading");
  assert.equal(timers.length, 1, "the poll reads again while it runs");
  // The poll, while the scan runs: a new row; the focused tick box stays.
  enter(tickOf(doc, "pp-000001"));
  const old = tickOf(doc, "pp-000001");
  now = listing([CI, STAGING, PROD], RUNNING);
  timers.shift()!();
  await tick();
  assert.equal(rows(doc).length, 3, "drawn again with the new row");
  assert.notEqual(tickOf(doc, "pp-000001"), old);
  assert.equal(doc.activeElement, tickOf(doc, "pp-000001"), "the same row's tick box");
  assert.equal(scan.disabled, true);
  // The scan ends: the list is drawn again; the tick box keeps the focus
  // the person gave it, and Scan for keys, on again, does not take it.
  now = listing([CI, STAGING, PROD], DONE);
  timers.shift()!();
  await tick();
  assert.equal(scan.disabled, false);
  assert.equal(doc.activeElement, tickOf(doc, "pp-000001"), "the person's focus stays");
});

test("a scan that ends while the focus still waits on the heading gives it back to Scan for keys, after the poll; a poll while it runs leaves it there", async () => {
  let now = listing([CI, STAGING, PROD], DONE);
  const { doc, window } = await opened({
    "POST suggestions/scan": listing([CI], RUNNING),
    "GET suggestions": () => now,
  });
  const timers = heldPolls(window);
  const scan = byId(doc, "suggest-scan");
  pressOff(scan);
  await tick();
  assert.equal(doc.activeElement, heading(doc), "the button is off while the scan runs; the focus waits on the heading");
  now = listing([CI, STAGING], RUNNING);
  timers.shift()!();
  await tick();
  assert.equal(scan.disabled, true, "still running");
  assert.equal(doc.activeElement, heading(doc), "a poll while it runs leaves it there");
  now = listing([CI, STAGING], DONE);
  timers.shift()!();
  await tick();
  assert.equal(scan.disabled, false);
  assert.equal(doc.activeElement, scan);
});

test("a focus that fell from the heading meanwhile (a click on nothing) still goes back to Scan for keys when the scan ends", async () => {
  let now = listing([CI, STAGING, PROD], DONE);
  const { doc, window } = await opened({
    "POST suggestions/scan": listing([CI], RUNNING),
    "GET suggestions": () => now,
  });
  const timers = heldPolls(window);
  const scan = byId(doc, "suggest-scan");
  pressOff(scan);
  await tick();
  heading(doc).blur();
  assert.equal(doc.activeElement, doc.body);
  now = listing([CI, STAGING], DONE);
  timers.shift()!();
  await tick();
  assert.equal(doc.activeElement, scan, "Scan for keys, on again");
  // The wait ended with the scan: a focus that falls later, at a redraw,
  // is not taken to Scan for keys.
  scan.blur();
  untick(tickOf(doc, "pp-000001"));
  assert.equal(doc.activeElement, doc.body, "nothing waits any more");
});

test("a focus the person moves off the heading stays where they put it, also once Not a secret brings it back to the heading", async () => {
  let now = listing([CI, STAGING, PROD], DONE);
  const { doc, window } = await opened({
    "POST suggestions/scan": listing([CI, STAGING, PROD], RUNNING),
    "GET suggestions": () => now,
    "POST suggestions/dismiss": (b: { id: string }) => ({ dismissed: b.id, status: "denied", ...listing([CI, PROD], RUNNING) }),
  });
  const timers = heldPolls(window);
  const scan = byId(doc, "suggest-scan");
  pressOff(scan);
  await tick();
  assert.equal(doc.activeElement, heading(doc));
  // Tab into the list, open a row, and press Not a secret: done, the focus
  // goes to the heading, as it always does.
  enter(moreOf(doc, "pp-000002"));
  press(button(detail(doc), "Not a secret"));
  await tick();
  assert.equal(rowOf(doc, "pp-000002"), undefined, "dismissed");
  assert.equal(doc.activeElement, heading(doc), "Not a secret done: the heading");
  assert.equal(scan.disabled, true, "the scan still runs");
  now = listing([CI, PROD], DONE);
  timers.shift()!();
  await tick();
  assert.equal(scan.disabled, false);
  assert.equal(doc.activeElement, heading(doc), "the end of the scan takes no focus the person moved");
});

test("Enter in the folder box starts the scan, and the focus stays in the box while it runs and after", async () => {
  let now = listing([CI, STAGING, PROD], DONE);
  const { doc, window } = await opened({
    "POST suggestions/scan": listing([CI], RUNNING),
    "GET suggestions": () => now,
  });
  const timers = heldPolls(window);
  const scan = byId(doc, "suggest-scan");
  const root = byId(doc, "suggest-root");
  root.focus();
  byId(doc, "suggest-form").requestSubmit();
  assert.equal(scan.disabled, true, "the scan runs");
  assert.equal(doc.activeElement, root, "never moved to the heading");
  await tick();
  now = listing([CI, STAGING], DONE);
  timers.shift()!();
  await tick();
  assert.equal(scan.disabled, false);
  assert.equal(doc.activeElement, root, "nor to Scan for keys");
});

test("a scan another tab started, read by the poll while Scan for keys has the focus: the focus waits on the heading, and comes back when it ends", async () => {
  let now = listing([CI, STAGING, PROD], DONE);
  const { doc, window } = await opened({ "GET suggestions": () => now });
  const timers = heldPolls(window);
  const scan = byId(doc, "suggest-scan");
  scan.focus();
  now = listing([CI, STAGING, PROD], RUNNING);
  doc.dispatchEvent(new window.Event("visibilitychange"));
  await tick();
  assert.equal(scan.disabled, true, "the poll reads the scan running");
  assert.equal(doc.activeElement, heading(doc), "the card's heading, never <body>");
  now = listing([CI, STAGING, PROD], DONE);
  timers.shift()!();
  await tick();
  assert.equal(scan.disabled, false);
  assert.equal(doc.activeElement, scan, "Scan for keys, on again");
});

test("a scan that ends after the card was closed gives the focus to nothing hidden: it stays on the heading, which a closed card still shows", async () => {
  let now = listing([CI, STAGING, PROD], DONE);
  const { doc, window } = await opened({
    "POST suggestions/scan": listing([CI], RUNNING),
    "GET suggestions": () => now,
  });
  const timers = heldPolls(window);
  const scan = byId(doc, "suggest-scan");
  pressOff(scan);
  await tick();
  byId(doc, "suggest-open").click();
  assert.equal(byId(doc, "files-suggested-view").hidden, true, "closed");
  now = listing([CI, STAGING], DONE);
  timers.shift()!();
  await tick();
  assert.equal(scan.disabled, false);
  assert.equal(doc.activeElement, heading(doc), "never a hidden button");
  assert.equal(heading(doc).closest("[hidden]"), null, "the heading shows");
});

test("Scan for keys refused: the focus waits on the heading while its POST is out, then goes back to it, described by the error line; a refusal that needs a folder goes to the folder box", async () => {
  let n = 0;
  const { doc } = await opened({
    "POST suggestions/scan": () => (++n === 1
      ? { status: 403, body: { error: "admin session required: sign in at the dashboard" } }
      : { status: 400, body: { error: "No project is known yet: no agent has run under Mandu. Type the folder of a project to scan it.", needsRoot: true } }),
  });
  const scan = byId(doc, "suggest-scan");
  pressOff(scan);
  assert.equal(doc.activeElement, heading(doc), "while its POST is out");
  await tick();
  assert.match(byId(doc, "suggest-error").textContent, /^Sign in first/);
  assert.equal(scan.disabled, false);
  assert.equal(doc.activeElement, scan);
  assert.equal(scan.getAttribute("aria-describedby"), "suggest-error");
  pressOff(scan);
  assert.equal(doc.activeElement, heading(doc));
  await tick();
  assert.equal(doc.activeElement, byId(doc, "suggest-root"), "the folder to type");
  assert.equal(scan.disabled, false);
});

test("nothing is taken: a tick, ⋯ or Not a secret pressed with the focus elsewhere, or nowhere, moves nothing", async () => {
  const { doc } = await opened({
    "POST suggestions/dismiss": (b: { id: string }) => ({ dismissed: b.id, status: "denied", ...listing([CI, PROD], DONE) }),
  });
  const root = byId(doc, "suggest-root");
  root.focus();
  untick(tickOf(doc, "pp-000001"));
  assert.equal(doc.activeElement, root, "a tick elsewhere");
  moreOf(doc, "pp-000002").click();
  assert.equal(doc.activeElement, root, "a ⋯ clicked without the focus");
  button(detail(doc), "Not a secret").click();
  await tick();
  assert.equal(rowOf(doc, "pp-000002"), undefined, "dismissed");
  assert.equal(doc.activeElement, root, "Not a secret clicked without the focus");
  // No focus at all: it stays nowhere.
  root.blur();
  enter(moreOf(doc, "pp-000003"));
  doc.activeElement.blur();
  untick(tickOf(doc, "pp-000003"));
  assert.equal(doc.activeElement, doc.body);
});

test("every control in the list is named, and no name is shared, with a row opened", async () => {
  const { doc } = await opened();
  enter(moreOf(doc, "pp-000003"));
  enter(button(detail(doc), "Show in policy.yaml"));
  const list = byId(doc, "files-suggested-list");
  assert.deepEqual(nameFaults(list), { shared: [], unnamed: [] });
  assert.deepEqual([...detail(doc).querySelectorAll("button")].map(controlName), ["Hide policy.yaml: prod.conf", "Not a secret: prod.conf"]);
});
