/**
 * css-rules-why-width — on Rules, an opened row's *What the rules say*, and
 * a found key's *What the scan found*, give their answers the box's width
 * (dashboard.md §4.25p *The rules' answers keep their width*). Mandu-new.
 *
 * Wider than 1000 px the opened row (`.file-detail`) is two equal columns,
 * and the box takes the right one: 368 to 396 px in a headless Chromium
 * from 1001 to 1600 px. Until 2026-10-16 its <dl> kept the two columns it
 * has across a whole row (`max-content minmax(0, 1fr)`): the longest term,
 * "What the AI sees of their output", took 175 px, and each answer had
 * 179 px at 1280 px and 167 at 1001. That is narrower than on a 390 px
 * phone (264 px), where the box already puts each term over its answer.
 * Now it does so wherever the opened row is two columns: 366 px for each
 * answer at 1280 px, and 13 lines for a rule's answers where there were 21.
 *
 *   Y1  the stylesheet: the stacked terms are one rule, in the width query
 *       that is exactly the complement of the one that makes the opened
 *       row one column (1000 px), so the two change together;
 *   Y2  the page as a 1600, 1280 and 1001 px window: the opened rule's row
 *       is two columns and its What the rules say one; at 1000, 860, 720
 *       and 641 px the row is one column and the box's terms sit beside
 *       their answers; at 640, 390 and 320 px both are one column (the
 *       phone's rule);
 *   Y3  a found key's What the scan found: the same at 1280, 860 and
 *       390 px.
 *
 * jsdom lays out nothing, so the page runs with its stylesheets as a
 * window that wide applies them (css-flatten.ts stylesAt); the widths
 * above are the run's Chromium probe. Across the real arbiter and
 * dashboard: tests/stack/rules-why-width.test.ts. Axes: none (display
 * only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { FILES_ROUTES, FILES_URL, PUB, load, tick, treeRow } from "./home-js-fixtures.js";
import { declValue, flattenCss, resolveCssVars, stripComments, stylesAt } from "./css-flatten.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** The product page's own styles, as index.html links them. */
const CSS = ["mandu.css", "app.css"].map((f) => readFileSync(join(PUB, f), "utf8")).join("\n");

/** The opened row's two columns, one column, and the box's two layouts. */
const TWO = "minmax(0, 1fr) minmax(0, 1fr)";
const ONE = "minmax(0, 1fr)";
const BESIDE = "max-content minmax(0, 1fr)";
/** The phone's rule (`@media (max-width: 640px)`) writes `1fr`. */
const PHONE = "1fr";

test("Y1: the box's terms go over their answers in exactly the windows where the opened row is two columns", () => {
  const rules = flattenCss(stripComments(CSS));
  const where = (selector: string, value: string) =>
    rules.filter((r) => r.selectors.includes(selector) && declValue(r.block, "grid-template-columns") === value).map((r) => String(r.media));
  assert.deepEqual(where(".file-detail", TWO), ["null"], "the opened row is two columns on a wide window");
  const narrow = where(".file-detail", ONE);
  assert.equal(narrow.length, 1, `one query makes the opened row one column: ${JSON.stringify(narrow)}`);
  const max = /^@media \(max-width: (\d+)px\)$/.exec(narrow[0]!);
  assert.ok(max, `the opened row goes to one column in a max-width query: ${narrow[0]}`);
  const stacked = where(".file-detail .file-why dl", ONE);
  assert.deepEqual(stacked, [`@media (min-width: ${Number(max![1]) + 1}px)`], "the box's terms go over their answers from the first width where the opened row is two columns, in one rule");
  assert.deepEqual(where(".file-why dl", BESIDE), ["null"], "across a whole row the terms sit beside their answers, as before");
  assert.deepEqual(where(".file-why dl", PHONE), ["@media (max-width: 640px)"], "a phone stacks them, as before");
});

// ── Y2, Y3: the page ─────────────────────────────────────────────────────────

const PATH = "/home/u/ws/.env";
const PANEL = { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [{
  id: `lock:${PATH}`, kind: "lock", subject: PATH, effect: "x", reach: null, hits: null, covers: "exact", bindings: [], level: "no-model",
  actions: { remove: true, flip: null }, plain: { subject: PATH, reach: "this file only", effect: "No AI" },
}] } };
const WHY = { why: { path: PATH, display: "~/ws/.env", label: { level: "no-model", words: "No AI", source: "yours", from: "Your rule", bindings: [] }, off: false, lines: [
  { term: "Where the label comes from", text: "Your rule (~/ws/.env)" },
  { term: "Programs that get the real file", text: "psql, ssh (only when git starts it)" },
  { term: "What the AI sees of their output", text: "Masked as a whole, for every program above." },
  { term: "May be sent to", text: "Nowhere without your OK." },
] } };
const KEY: SuggestionWire = {
  id: "pp-000001", kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: "workspace:path:/home/u/proj/services/api/app.conf", source: "workspace", repoRoot: "/home/u/proj",
  edits: [{ op: "lock-path", path: "/home/u/proj/services/api/app.conf", level: "no-model" }],
  sentence: "Make ~/proj/services/api/app.conf a secret no AI may read",
  evidence: { paths: ["services/api/app.conf"], blobs: [], historyOnly: false,
    findings: [{ blob: "", paths: ["services/api/app.conf"], firstCommit: null, lastCommit: null, inHead: false, inIndex: false, stillPresent: true,
      detectors: [{ kind: "content-shape", rule: "github-token", mask: "ghp_…", words: "GitHub token", line: 2 }] }] },
  impact: { historicalVersions: 0, workingTreeChanges: true, files: ["services/api/app.conf"] },
  historyOnly: false, rotate: false, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
} as SuggestionWire;

/** Rules with the rule opened (its What the rules say read) and Keys Mandu
 *  found opened on its key, and a sheet whose text `at(width)` sets to the
 *  page's styles as a window that wide applies them. */
async function rulesPage(): Promise<{ doc: El; at: (width: number) => void }> {
  const { doc } = load({ url: FILES_URL, routes: {
    ...FILES_ROUTES,
    "GET policy/panel": PANEL,
    [`GET files/why?path=${encodeURIComponent(PATH)}`]: WHY,
    "GET suggestions": { suggestions: suggestionRows([KEY], "/home/u", "linux"), count: 1, scan: null },
  } });
  await tick();
  treeRow(doc, /ws\/\.env$/).querySelector(".file-more").click();
  doc.getElementById("suggest-open").click();
  await tick();
  doc.querySelector("#files-suggested-list .row.file.suggested .file-more").click();
  await tick();
  const sheet = doc.createElement("style");
  doc.head.append(sheet);
  return { doc, at: (width) => { sheet.textContent = resolveCssVars(stylesAt(CSS, width)); } };
}
/** The opened row's tracks and its box's, for the box named `label`. */
function layout(doc: El, list: string, label: string): { row: string; box: string } {
  const win = doc.defaultView;
  const box = ([...doc.querySelectorAll(`${list} .file-detail .file-why`)] as El[]).find((b) => b.getAttribute("aria-label") === label);
  assert.ok(box, `${label} is drawn in its opened row`);
  assert.ok(box.querySelectorAll("dt").length > 0 && box.querySelectorAll("dd").length > 0, `${label}: its terms and answers are drawn`);
  return { row: win.getComputedStyle(box.closest(".file-detail")).gridTemplateColumns, box: win.getComputedStyle(box.querySelector("dl")).gridTemplateColumns };
}

test("Y2: What the rules say puts its terms over their answers wherever the opened row is two columns, beside them where the box spans the row, and over them on a phone", async () => {
  const { doc, at } = await rulesPage();
  const why = (w: number) => { at(w); return layout(doc, "#files-tree", "What the rules say"); };
  for (const w of [1600, 1280, 1001]) assert.deepEqual(why(w), { row: TWO, box: ONE }, `${w}px: the box is the opened row's right column, a phone's width, so each term goes over its answer`);
  for (const w of [1000, 860, 720, 641]) assert.deepEqual(why(w), { row: ONE, box: BESIDE }, `${w}px: the box spans the opened row, so each term sits beside its answer, as before`);
  for (const w of [640, 390, 320]) assert.deepEqual(why(w), { row: ONE, box: PHONE }, `${w}px: a phone stacks them, as before`);
  const dd = doc.querySelector("#files-tree .file-why dd");
  assert.equal(dd.textContent, "Your rule (~/ws/.env)", "the words are the server's, unchanged");
});

test("Y3: a found key's What the scan found does the same", async () => {
  const { doc, at } = await rulesPage();
  const found = (w: number) => { at(w); return layout(doc, "#files-suggested-list", "What the scan found"); };
  assert.deepEqual(found(1280), { row: TWO, box: ONE }, "1280px: beside the key's own column, each finding over what it says");
  assert.deepEqual(found(860), { row: ONE, box: BESIDE }, "860px: across the row, side by side, as before");
  assert.deepEqual(found(390), { row: ONE, box: PHONE }, "390px: stacked, as before");
  assert.match(doc.querySelector("#files-suggested-list .file-why dd").textContent, /ghp_… on line 2/, "the finding is drawn as before");
});
