/**
 * home-js-open-at-card.test — a link to a card on another page of the
 * PRODUCT page opens that page at the card once its reads have drawn
 * (public/js/home.js `openAtCard`, dashboard.md §4.25r *A link opens at its
 * card*), driven in jsdom over the shared fetch stub (home-js-fixtures.ts)
 * with reads held open, as a slow protection service holds them.
 *
 * Until 2026-10-08 the page scrolled at the click, before its reads
 * answered: what they drew above the card (your rules on Rules, Protection
 * and Models on Settings) then pushed it down. With ten rules, Settings ›
 * Sensitivity labels' **Keys Mandu found** left the card fully below a 900 px
 * window, the screen showing Your rules and no Scan for keys.
 *
 * Pins: Settings' note link and Approvals' Review them scroll to Keys Mandu
 * found only once the rules are drawn, and once the folder Add a rule was
 * left open on is listed; Rules' scan-line link scrolls to Sensitivity
 * labels only once Protection and Models are drawn; a scroll, key or tap by
 * the person before then, or another page, means no scroll; a read that
 * fails still opens at the card. Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, list, FILES_ROUTES, WS_LIST } from "./home-js-fixtures.js";
import { labelSettingsVM } from "../../../src/view-model/sensitivity-labels.js";
import { scanSummary, scanSummaryParts, suggestionRows, type SuggestionWire, type SuggestPolicyWire } from "../../../src/view-model/suggestions.js";

const BASE = "http://127.0.0.1:4500/mandu";
const RULES = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [] } };
const NO_SCAN = { suggestions: [], count: 0, scan: null };
const LABELS = { labels: labelSettingsVM(null, undefined, null) };
const AXES = { ok: true, effective: { integrity: false, confidentiality: true }, effectiveMode: "secrets" };
/** A key a scan found in a file, waiting in Keys Mandu found. */
const KEY: SuggestionWire = {
  id: "pp-000001", kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: "k-1", source: "git-history", repoRoot: "/home/u/proj",
  edits: [{ op: "lock-path", path: "/home/u/proj/deploy.sh", level: "no-model" }],
  sentence: "Make ~/proj/deploy.sh a secret no AI may read",
  evidence: { paths: ["/home/u/proj/deploy.sh"], blobs: [], historyOnly: false,
    findings: [{ blob: null, paths: ["/home/u/proj/deploy.sh"], firstCommit: null, lastCommit: null, inHead: false, inIndex: false, stillPresent: true,
      detectors: [{ kind: "content-shape", rule: "stripe-key", mask: "sk_live_…", words: "Stripe key", line: 1 }] }] },
  impact: { historicalVersions: 0, workingTreeChanges: false, files: [] },
  historyOnly: false, rotate: true, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
} as unknown as SuggestionWire;

/** A read held open until `release()`, as a slow service holds it. */
function held<T>(body: T) {
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  return { route: () => gate.then(() => body), release: () => release() };
}
/** Each scroll as [the card's id, what the page had drawn by then]. */
function recordScrolls(window: any, drawn: () => unknown) {
  const scrolled: unknown[][] = [];
  window.HTMLElement.prototype.scrollIntoView = function (this: any) { scrolled.push([this.id, drawn()]); };
  return scrolled;
}
const rulesDrawn = (doc: any) => doc.querySelectorAll("#files-tree .row").length > 0;
const noteLink = (doc: any) => doc.querySelector("#settings-labels .labels-note a") as any;

test("Settings' Keys Mandu found link opens Rules at that card once the rules are drawn, never before", async () => {
  // Settings reads the panel too (Models): held only from the click on.
  let hold: ReturnType<typeof held> | null = null;
  const page = load({ url: BASE + "/settings", routes: {
    ...FILES_ROUTES, "GET policy/sensitivity-labels": LABELS, "GET suggestions": NO_SCAN,
    "GET policy/panel": () => (hold ? hold.route() : RULES),
  } });
  await tick();
  const scrolled = recordScrolls(page.window, () => rulesDrawn(page.doc));
  hold = held(RULES);
  noteLink(page.doc).click();
  await tick();
  assert.equal(page.window.location.pathname, "/mandu/rules", "Rules opens at once");
  assert.equal(rulesDrawn(page.doc), false, "its rules are still being read");
  assert.deepEqual(scrolled, [], "no scroll before they are drawn: they would push the card down");
  hold.release();
  await tick();
  assert.deepEqual(scrolled, [["suggested-block", true]], "one scroll, to Keys Mandu found, once the rules above it are drawn");
  assert.equal(page.doc.getElementById("files-suggested-view").hidden, false, "Keys Mandu found is open");
  assert.equal(page.doc.getElementById("suggest-scan").textContent, "Scan for keys");
});

test("Approvals' Review them: the same, and it waits for the folder Add a rule was left open on", async () => {
  const listing = held(WS_LIST);
  const rules = held(RULES);
  const page = load({
    url: BASE + "/approvals",
    storage: { "mandu.files.view": "all", "mandu.files.folder": "/home/u/ws" },
    routes: { ...FILES_ROUTES, "GET suggestions": { suggestions: suggestionRows([KEY], "/home/u", "linux"), count: 1, scan: null }, "GET policy/panel": rules.route, [list("/home/u/ws")]: listing.route },
  });
  await tick();
  assert.equal(page.doc.getElementById("approvals-suggestions-block").hidden, false, "the card is there");
  const listed = () => page.doc.querySelectorAll("#files-list .row.file").length > 0;
  const scrolled = recordScrolls(page.window, () => [rulesDrawn(page.doc), listed()]);
  page.doc.getElementById("approvals-suggestions-open").click();
  await tick();
  assert.deepEqual(scrolled, []);
  rules.release();
  await tick();
  assert.equal(page.doc.getElementById("lock-form").hidden, false, "Add a rule opens as it was left, above Keys Mandu found");
  assert.equal(listed(), false, "its folder is still being read");
  assert.deepEqual(scrolled, [], "no scroll before the folder is listed: it would push the card down");
  listing.release();
  await tick();
  assert.deepEqual(scrolled, [["suggested-block", [true, true]]]);
  assert.equal(page.doc.getElementById("files-suggested-view").hidden, false, "Keys Mandu found is open");
});

/** A finished scan of ~/docs: one document whose label has no level, so the
 *  line under Scan for keys links Settings › Sensitivity labels. */
const DOCS_WIRE: SuggestPolicyWire = {
  axis: true, running: false, suggestions: [], filed: [], covered: [],
  counts: { findings: 0, suggested: 0, filed: 0, alreadyPending: 0, dismissed: 0, overCap: 0, covered: 0, dropped: 0, superseded: 0 },
  scan: null,
  workspaceScan: {
    roots: [{ root: "/home/u/docs", tier: "workspace" }], counts: { examined: 0, read: 0, cached: 0, bytes: 0, covered: 0 },
    capped: { tooBig: 0, overTotal: 0, overTime: 0, overFiles: 0, binary: 0, symlinks: 0, unreadable: 0, depth: 0 },
    limits: { fileMaxBytes: 262144, totalMaxBytes: 67108864, maxFiles: 20000, timeoutMs: 30000 }, ms: 1,
    labels: {
      mode: "count", examined: 1, read: 1, cached: 0, covered: 0, files: 1, mapped: 0, unmappedFiles: 1,
      unmapped: [{ id: "2a2a0000-0000-4000-8000-000000000002", site: null, files: 1 }], unmappedMore: 0, encrypted: 0, unreadable: 0,
    },
  },
};
const DOCS_SCAN = { running: false, roots: ["~/docs"], summary: scanSummary(DOCS_WIRE, "/home/u"), summaryParts: scanSummaryParts(DOCS_WIRE, "/home/u"), error: null };

test("Rules' Settings › Sensitivity labels link opens Settings at that card once Protection and Models are drawn, never before", async () => {
  let axes: ReturnType<typeof held> | null = null;
  let models: ReturnType<typeof held> | null = null;
  const page = load({ url: BASE + "/rules", storage: { "mandu.files.suggested": "1" }, routes: {
    ...FILES_ROUTES, "GET suggestions": { suggestions: [], count: 0, scan: DOCS_SCAN }, "GET policy/sensitivity-labels": LABELS,
    "GET policy/panel": () => (models ? models.route() : RULES), "GET config/axes": () => (axes ? axes.route() : AXES),
  } });
  await tick();
  const link = page.doc.querySelector("#suggest-status a") as any;
  assert.equal(link.textContent, "Settings › Sensitivity labels");
  const modelsDrawn = () => page.doc.getElementById("settings-models").childElementCount > 0;
  assert.equal(modelsDrawn(), false, "Models has not been drawn yet");
  const scrolled = recordScrolls(page.window, modelsDrawn);
  // Settings reads config/axes for Protection and the panel for Models:
  // both held from the click on.
  axes = held(AXES);
  models = held(RULES);
  link.click();
  await tick();
  assert.equal(page.window.location.pathname, "/mandu/settings");
  assert.deepEqual(scrolled, [], "neither card above it has been read yet");
  models.release();
  await tick();
  assert.equal(modelsDrawn(), true, "Models is drawn");
  assert.deepEqual(scrolled, [], "Protection is still being read");
  axes.release();
  await tick();
  assert.deepEqual(scrolled, [["settings-labels-block", true]], "one scroll, once both cards above it are drawn");
});

test("a scroll, key or tap by the person before the page has drawn is theirs: no scroll then", async () => {
  for (const kind of ["wheel", "keydown", "pointerdown", "touchmove"]) {
    const rules = held(RULES);
    let hold = false;
    const page = load({ url: BASE + "/settings", routes: { ...FILES_ROUTES, "GET policy/sensitivity-labels": LABELS, "GET suggestions": NO_SCAN, "GET policy/panel": () => (hold ? rules.route() : RULES) } });
    await tick();
    const scrolled = recordScrolls(page.window, () => rulesDrawn(page.doc));
    hold = true;
    noteLink(page.doc).click();
    await tick();
    page.window.dispatchEvent(new page.window.Event(kind, { bubbles: true }));
    rules.release();
    await tick();
    assert.equal(rulesDrawn(page.doc), true, `${kind}: the rules are drawn`);
    assert.deepEqual(scrolled, [], `${kind}: the page leaves the scroll to the person`);
  }
});

test("another page before Rules has drawn: no scroll, also when the person comes back to Rules", async () => {
  const first = held(RULES);
  let hold: ReturnType<typeof held> | null = null;
  const page = load({ url: BASE + "/settings", routes: { ...FILES_ROUTES, "GET policy/sensitivity-labels": LABELS, "GET suggestions": NO_SCAN, "GET policy/panel": () => (hold ? hold.route() : RULES) } });
  await tick();
  const scrolled = recordScrolls(page.window, () => rulesDrawn(page.doc));
  hold = first;
  noteLink(page.doc).click();
  await tick();
  hold = null;
  (page.doc.querySelector('#nav [data-page-link="home"]') as any).click();
  (page.doc.querySelector('#nav [data-page-link="rules"]') as any).click();
  await tick();
  first.release();
  await tick();
  assert.equal(page.window.location.pathname, "/mandu/rules");
  assert.deepEqual(scrolled, [], "a plain visit to Rules opens at its top");
});

test("a read that fails still opens at the card, under what the page could not read", async () => {
  let fail = false;
  const page = load({ url: BASE + "/settings", routes: { ...FILES_ROUTES, "GET policy/sensitivity-labels": LABELS, "GET suggestions": NO_SCAN,
    "GET policy/panel": () => (fail ? Promise.reject(new Error("unreachable")) : RULES) } });
  await tick();
  const scrolled = recordScrolls(page.window, () => true);
  fail = true;
  noteLink(page.doc).click();
  await tick();
  assert.deepEqual(scrolled, [["suggested-block", true]]);
});
