/**
 * home-js-suggestions-order.test — on the product page's Rules, a read of
 * Keys Mandu found asked before a change's answer never draws over it
 * (public/js/home.js `loadSuggestions` / `setWritten`; dashboard.md §4.25
 * *A read asked before a change never draws over it*).
 *
 * The page reads the suggestions on every Home poll, when the card opens,
 * and every 3 s while a scan runs. A change made on the card (Scan for keys,
 * Save, Not a secret, a model run) answers with the server's new list, which
 * the page draws. Until 2026-10-12 a read asked before the change that
 * answered after it was taken too, so on a slow network:
 *
 *   - a key marked Not a secret, or saved, came back on the next draw (a
 *     tick, a ⋯), ticked, and waited in Changes to save again: a Save then
 *     sent it again;
 *   - a scan's new rows went away, its line went back to the last scan's,
 *     and Scan for keys came back on while the scan still ran;
 *   - a read made after the change (the next poll) waited on that older
 *     read and got its answer;
 *   - a read after a change was compared with what the page drew before
 *     the change, so a key that came back (Undo under Rule changes) with the
 *     list as it was then was never drawn.
 *
 * Now a read's answer (or failure) is dropped when a change's list was
 * taken while it was on its way; a read made then reads again; a read asked
 * after the change is taken, and drawn. Drives home.js in jsdom over the
 * shared fetch stub (home-js-fixtures.ts), with the next suggestions read
 * held until the test answers it; across the real arbiter and dashboard,
 * tests/stack/suggestions-order.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES } from "./home-js-fixtures.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";
import { modelPickerVM, modelPreviewVM, modelRunVM, type ModelPreviewWire, type ModelRunWire } from "../../../src/view-model/suggestion-model.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const HOME = "/home/u";
const REPO = `${HOME}/proj`;
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
const NEW = found("pp-000004", "deploy/new.conf");
const listing = (views: SuggestionWire[], scan: unknown = null, model?: unknown) =>
  ({ suggestions: suggestionRows(views, HOME, "linux"), count: views.length, scan, ...(model === undefined ? {} : { model }) });
const DONE = { running: false, roots: ["~/proj"], includeHome: false, summary: "Scanned ~/proj. 3 possible keys to review.", summaryParts: null, error: null };
const DONE4 = { ...DONE, summary: "Scanned ~/proj. 4 possible keys to review." };
const RUNNING = { ...DONE, running: true, summary: null };

const rows = (doc: Doc) => [...doc.querySelectorAll("#files-suggested-list .row.suggested")] as Doc[];
const ids = (doc: Doc) => rows(doc).map((r) => r.dataset.id);
const rowOf = (doc: Doc, id: string) => rows(doc).find((r) => r.dataset.id === id);
const moreOf = (doc: Doc, id: string) => rowOf(doc, id).querySelector(".file-more");
const tickOf = (doc: Doc, id: string) => rowOf(doc, id).querySelector("input.file-tick");
const detail = (doc: Doc) => doc.querySelector("#files-suggested-list .file-detail");
const button = (box: Doc, words: string) => [...box.querySelectorAll("button")].find((b: Doc) => b.textContent === words);
const byId = (doc: Doc, id: string) => doc.getElementById(id);
const pending = (doc: Doc) => byId(doc, "files-pending-list").textContent as string;

/** Enter (or Space) on a control: it has the focus. */
function enter(c: Doc): void {
  c.focus();
  c.click();
}
/** The Home poll, as on a return to the tab: it reads the suggestions too. */
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
}

/** The Rules page with Keys Mandu found opened over `routes`, and `hold()`:
 *  the next read of the suggestions is held, its answer sent by the test
 *  (`send`, or `refuse` with a status). `reads` counts the reads made. */
async function opened(routes: Record<string, unknown>) {
  const page = load({ url: FILES_URL, routes: { ...FILES_ROUTES, ...routes } });
  const pass = page.window.fetch;
  let holding: Promise<unknown> | null = null;
  let reads = 0;
  page.window.fetch = (url: string, init: { method?: string } = {}) => {
    if ((init.method ?? "GET") !== "GET" || !url.endsWith("/api/suggestions")) return pass(url, init);
    reads++;
    if (!holding) return pass(url, init);
    const answer = holding;
    holding = null;
    return answer;
  };
  await tick();
  byId(page.doc, "suggest-open").click();
  await tick();
  const hold = () => {
    let answered!: (v: unknown) => void;
    holding = new Promise((r) => { answered = r; });
    return {
      send: (body: unknown) => answered({ ok: true, status: 200, json: () => Promise.resolve(body) }),
      refuse: (status: number, body: unknown) => answered({ ok: false, status, json: () => Promise.resolve(body) }),
    };
  };
  return { ...page, hold, reads: () => reads };
}

test("Not a secret: a read asked before it that answers after it never brings the row back, nor sends it again with Save", async () => {
  let now: unknown = listing([CI, STAGING, PROD], DONE);
  const applied: unknown[] = [];
  const { doc, hold } = await opened({
    "GET suggestions": () => now,
    "POST suggestions/dismiss": (b: { id: string }) => ({ dismissed: b.id, status: "denied", ...listing([CI, PROD], DONE) }),
    "POST suggestions/apply": (b: { ids: string[] }) => (applied.push(b), { applied: b.ids.map((id) => ({ id, changeId: "pc-000001" })), refused: [], ...listing([CI], DONE) }),
  });
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000002", "pp-000003"]);
  const before = hold();
  await poll(doc); // asked before Not a secret, held
  now = listing([CI, PROD], DONE);
  enter(moreOf(doc, "pp-000002"));
  enter(button(detail(doc), "Not a secret"));
  await tick();
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000003"], "the row is gone");
  assert.equal(doc.activeElement, byId(doc, "suggested-title"));
  // The read asked before answers now, with the row the server listed then.
  before.send(listing([CI, STAGING, PROD], DONE));
  await tick(30);
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000003"], "never drawn again");
  assert.equal(byId(doc, "files-suggested-count").textContent, "2");
  assert.doesNotMatch(pending(doc), /staging\.conf/, "nor waiting in Changes to save");
  assert.equal(doc.activeElement, byId(doc, "suggested-title"), "the focus stays");
  assert.match(byId(doc, "rules-notice").textContent, /^staging\.conf is marked as not a secret/);
  // The next draw (a tick) draws the list the page took, and Save sends
  // only what is still waiting.
  enter(tickOf(doc, "pp-000001"));
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000003"], "a tick draws the list again without it");
  assert.doesNotMatch(pending(doc), /staging\.conf/);
  byId(doc, "files-save").click();
  await tick(20);
  assert.deepEqual(applied, [{ ids: ["pp-000003"] }], "never the key marked as not a secret");
});

test("Save: a read asked before it that answers after it never brings the saved rows back ticked", async () => {
  let now: unknown = listing([CI, STAGING, PROD], DONE);
  const applied: unknown[] = [];
  const { doc, hold } = await opened({
    "GET suggestions": () => now,
    "POST suggestions/apply": (b: { ids: string[] }) => (applied.push(b), { applied: b.ids.map((id) => ({ id, changeId: "pc-000001" })), refused: [], ...listing([PROD], DONE) }),
  });
  enter(tickOf(doc, "pp-000003")); // skipped: it stays
  const before = hold();
  await poll(doc);
  now = listing([PROD], DONE);
  byId(doc, "files-save").click();
  await tick(20);
  assert.deepEqual(applied, [{ ids: ["pp-000001", "pp-000002"] }]);
  assert.deepEqual(ids(doc), ["pp-000003"]);
  before.send(listing([CI, STAGING, PROD], DONE));
  await tick(30);
  enter(tickOf(doc, "pp-000003"));
  assert.deepEqual(ids(doc), ["pp-000003"], "the saved rows never come back");
  assert.equal(byId(doc, "files-suggested-count").textContent, "1");
  assert.doesNotMatch(pending(doc), /ci\.conf|staging\.conf/, "nor wait to be saved again");
});

test("Scan for keys: a read asked before it that answers after it never takes away the new rows or the line, nor turns Scan back on while the scan runs", async () => {
  let now: unknown = listing([CI, STAGING, PROD], DONE);
  const { doc, window, hold } = await opened({
    "GET suggestions": () => now,
    "POST suggestions/scan": () => listing([CI, STAGING, PROD, NEW], RUNNING),
  });
  const timers: Array<() => void> = [];
  const later = window.setTimeout;
  window.setTimeout = (fn: () => void, ms: number) => (ms === 3000 ? timers.push(fn) : later(fn, ms), 0);
  const scan = byId(doc, "suggest-scan");
  assert.equal(byId(doc, "suggest-status").textContent, DONE.summary);
  const before = hold();
  await poll(doc);
  now = listing([CI, STAGING, PROD, NEW], RUNNING);
  scan.click();
  await tick();
  assert.equal(scan.disabled, true, "the scan runs");
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000002", "pp-000003", "pp-000004"]);
  before.send(listing([CI, STAGING, PROD], DONE));
  await tick(30);
  enter(tickOf(doc, "pp-000001"));
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000002", "pp-000003", "pp-000004"], "the new row stays");
  assert.equal(scan.disabled, true, "Scan for keys stays off while the scan runs");
  assert.equal(scan.textContent, "Scanning…");
  assert.match(byId(doc, "suggest-status").textContent, /^Scanning ~\/proj… /, "never the last scan's line");
  // The scan's own reading goes on and ends it.
  now = listing([CI, STAGING, PROD, NEW], DONE4);
  assert.equal(timers.length, 1, "the page still reads again while the scan runs");
  timers.shift()!();
  await tick(30);
  assert.equal(scan.disabled, false);
  assert.equal(byId(doc, "suggest-status").textContent, DONE4.summary);
});

test("a model run: a read asked before its answer never takes away the row the model filed", async () => {
  const DIGEST = "b".repeat(64);
  const PREVIEW: ModelPreviewWire = {
    axis: true, tier: "contents", digest: DIGEST,
    destination: { kind: "declared", name: "ollama", location: "local", placement: "host", vendor: "127.0.0.1" },
    roots: [{ index: 1, root: REPO, files: 1 }], items: 1, bytes: 900, requests: 1, names: [],
    files: [{ root: 1, name: "deploy/new.conf", bytes: 900, truncated: false }],
    left: { covered: 0, labelled: 0, tooLong: 0, personal: 0, overCap: 0, detector: 0, registered: 0, flagged: 0, unread: 0 },
    promptVersion: "contents-1", confine: { live: true }, expiresAt: 1, walk: { examined: 1, covered: 0, capped: [] },
  };
  const RUN: ModelRunWire = {
    axis: true, running: false, digest: DIGEST, destination: PREVIEW.destination, sent: { requests: 1, items: 1, bytes: 900 },
    counts: { rules: 1, kept: 1, dropped: 0, merged: 0, tooBroad: 0, covered: 0, filed: 1, alreadyPending: 0, dismissed: 0, overCap: 0, failedRequests: 0, public: 0 },
    filed: ["pp-000004"], error: null, ms: 10,
  };
  const PICKER = modelPickerVM(true, [{ name: "ollama", local: true }]);
  let now: unknown = listing([CI], DONE, PICKER);
  const { doc, hold } = await opened({
    "GET suggestions": () => now,
    "POST suggestions/model/preview": { preview: modelPreviewVM(PREVIEW, HOME) },
    "POST suggestions/model/send": () => ({ run: modelRunVM(RUN, "contents"), ...listing([CI, NEW], DONE, PICKER) }),
  });
  const sel = byId(doc, "suggest-model-tier");
  sel.value = "contents";
  sel.dispatchEvent(new doc.defaultView.Event("change"));
  byId(doc, "suggest-model-run").click();
  await tick();
  assert.equal(byId(doc, "suggest-model-preview").hidden, false);
  const before = hold();
  await poll(doc);
  now = listing([CI, NEW], DONE, PICKER);
  byId(doc, "suggest-model-send").click();
  await tick(20);
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000004"], "the filed row is shown");
  before.send(listing([CI], DONE, PICKER));
  await tick(30);
  enter(tickOf(doc, "pp-000001"));
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000004"], "and stays");
  assert.equal(byId(doc, "files-suggested-count").textContent, "2");
});

test("a poll made after Not a secret reads again rather than wait on the read asked before it, and its answer is drawn", async () => {
  let now: unknown = listing([CI, STAGING, PROD], DONE);
  const { doc, hold, reads } = await opened({
    "GET suggestions": () => now,
    "POST suggestions/dismiss": (b: { id: string }) => ({ dismissed: b.id, status: "denied", ...listing([CI, PROD], DONE) }),
  });
  const before = hold();
  await poll(doc);
  enter(moreOf(doc, "pp-000002"));
  enter(button(detail(doc), "Not a secret"));
  await tick();
  // Another scan filed a key meanwhile: the next poll finds it.
  now = listing([CI, PROD, NEW], DONE);
  const asked = reads();
  await poll(doc);
  assert.equal(reads(), asked + 1, "a read of its own");
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000003", "pp-000004"], "drawn while the older read is still out");
  assert.equal(byId(doc, "files-suggested-count").textContent, "3");
  before.send(listing([CI, STAGING, PROD], DONE));
  await tick(30);
  enter(tickOf(doc, "pp-000001"));
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000003", "pp-000004"], "the older answer is dropped");
  // With no change since, two polls share the one read on its way.
  const slow = hold();
  const shared = reads();
  await poll(doc);
  await poll(doc);
  assert.equal(reads(), shared + 1, "one read for both");
  slow.send(listing([CI, NEW], DONE));
  await tick(30);
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000004"], "and its answer is drawn");
});

test("the read made after Not a secret is shared by the next poll, also once the read asked before it has ended", async () => {
  const { doc, hold, reads } = await opened({
    "GET suggestions": listing([CI, STAGING, PROD], DONE),
    "POST suggestions/dismiss": (b: { id: string }) => ({ dismissed: b.id, status: "denied", ...listing([CI, PROD], DONE) }),
  });
  const before = hold();
  await poll(doc);
  enter(moreOf(doc, "pp-000002"));
  enter(button(detail(doc), "Not a secret"));
  await tick();
  const after = hold();
  const asked = reads();
  await poll(doc); // a read of its own, held too
  assert.equal(reads(), asked + 1);
  before.send(listing([CI, STAGING, PROD], DONE)); // ends, dropped
  await tick(30);
  await poll(doc);
  assert.equal(reads(), asked + 1, "the next poll waits on the read made after the change");
  after.send(listing([CI, PROD, NEW], DONE));
  await tick(30);
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000003", "pp-000004"]);
});

test("a read that fails, asked before Not a secret and answering after it, says nothing: the list the change answered stays", async () => {
  const { doc, hold } = await opened({
    "GET suggestions": listing([CI, STAGING, PROD], DONE),
    "POST suggestions/dismiss": (b: { id: string }) => ({ dismissed: b.id, status: "denied", ...listing([CI, PROD], DONE) }),
  });
  const before = hold();
  await poll(doc);
  enter(moreOf(doc, "pp-000002"));
  enter(button(detail(doc), "Not a secret"));
  await tick();
  before.refuse(503, { error: "the arbiter is not reachable", unreachable: true });
  await tick(30);
  assert.equal(byId(doc, "suggest-error").textContent, "", "no error from before the change");
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000003"]);
  // A newer read that fails is said.
  hold().refuse(503, { error: "the arbiter is not reachable", unreachable: true });
  await poll(doc);
  assert.notEqual(byId(doc, "suggest-error").textContent, "", "a read asked after the change is taken, failed too");
});

test("a key a change took away that comes back (Undo under Rule changes) is drawn by the next read, though the list is as it was before the change", async () => {
  let now: unknown = listing([CI, STAGING, PROD], DONE);
  const { doc } = await opened({
    "GET suggestions": () => now,
    "POST suggestions/apply": (b: { ids: string[] }) => ({ applied: b.ids.map((id) => ({ id, changeId: "pc-000001" })), refused: [], ...listing([STAGING, PROD], DONE) }),
  });
  enter(tickOf(doc, "pp-000002"));
  enter(tickOf(doc, "pp-000003"));
  byId(doc, "files-save").click();
  await tick(20);
  assert.deepEqual(ids(doc), ["pp-000002", "pp-000003"], "ci.conf saved");
  // Undone elsewhere: the server lists it again, exactly as before Save.
  now = listing([CI, STAGING, PROD], DONE);
  await poll(doc);
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000002", "pp-000003"], "drawn again");
  assert.equal(byId(doc, "files-suggested-count").textContent, "3");
});

test("reads with no change between them are each taken and drawn", async () => {
  let now: unknown = listing([CI], DONE);
  const { doc } = await opened({ "GET suggestions": () => now });
  assert.deepEqual(ids(doc), ["pp-000001"]);
  now = listing([CI, STAGING], DONE);
  await poll(doc);
  assert.deepEqual(ids(doc), ["pp-000001", "pp-000002"]);
  now = listing([STAGING], DONE);
  await poll(doc);
  assert.deepEqual(ids(doc), ["pp-000002"]);
});
