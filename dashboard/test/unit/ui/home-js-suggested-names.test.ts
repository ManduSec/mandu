/**
 * home-js-suggested-names.test — on the product page's Rules, two keys in
 * files of the same name are named apart (dashboard.md §4.25 *Keys in files
 * of the same name are named apart*).
 *
 * Until 2026-10-11 every control of a Keys Mandu found row, and the words
 * that name the row, used the file's name alone: with services/api/app.conf
 * and services/web/app.conf both found, two tick boxes read "Save app.conf",
 * two ⋯ "More about app.conf", two Skips in Changes to save "Skip the
 * suggestion for app.conf", and Not a secret asked "Mark app.conf as not a
 * secret?" of either. Now a row whose name another suggestion shares is
 * named by its path (old versions: "1 old version of <path>"); a row whose
 * name is its own keeps it.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub (home-js-fixtures.ts), with the server's own rows
 * (view-model/suggestions.ts suggestionRows). Axes: none (display only).
 * Mandu-new test.
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
/** An old version of `rel` only git history holds, as the arbiter files it. */
function version(id: string, rel: string, blob: string): SuggestionWire {
  return {
    id, kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: `k-${id}`, source: "git-history", repoRoot: REPO,
    edits: [{ op: "lock-blob", blob: `sha1:${blob.repeat(40)}`, level: "no-model" }],
    sentence: `Hide an old version of ~/proj/${rel} from the AI`,
    evidence: { paths: [rel], blobs: [blob.repeat(40)], historyOnly: false,
      findings: [{ blob: blob.repeat(40), paths: [rel], firstCommit: "3333333", lastCommit: "4444444", inHead: false, inIndex: false, stillPresent: true,
        detectors: [{ kind: "content-shape", rule: "github-token", mask: "ghp_…", words: "GitHub token", line: 1 }] }] },
    impact: { historicalVersions: 1, workingTreeChanges: false, files: [] },
    historyOnly: false, rotate: true, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
  };
}
const API = found("pp-000001", "services/api/app.conf");
const WEB = found("pp-000002", "services/web/app.conf");
const CI = found("pp-000003", "tools/ci.conf");
const OLD_API = version("pp-000004", "services/api/config.py", "a");
const OLD_WEB = version("pp-000005", "services/web/config.py", "b");
const listing = (views: SuggestionWire[]) => ({ suggestions: suggestionRows(views, "/home/u", "linux"), count: views.length, scan: null });

const rows = (doc: Doc) => [...doc.querySelectorAll("#files-suggested-list .row.suggested")] as Doc[];
const rowOf = (doc: Doc, id: string) => rows(doc).find((r) => r.dataset.id === id);
const moreOf = (doc: Doc, id: string) => rowOf(doc, id).querySelector(".file-more");
const tickOf = (doc: Doc, id: string) => rowOf(doc, id).querySelector("input.file-tick");
const detail = (doc: Doc) => doc.querySelector("#files-suggested-list .file-detail");
const button = (box: Doc, words: string) => [...box.querySelectorAll("button")].find((b: Doc) => b.textContent === words);
const byId = (doc: Doc, id: string) => doc.getElementById(id);
const skipOf = (doc: Doc, id: string) => byId(doc, "files-pending-list").querySelector(`li[data-id="${id}"] button`);
/** Enter (or Space) on a control that keeps working: it has the focus. */
function enter(c: Doc): void {
  c.focus();
  c.click();
}

async function opened(views: SuggestionWire[], routes: Record<string, unknown> = {}) {
  const page = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET suggestions": listing(views), ...routes } });
  await tick();
  byId(page.doc, "suggest-open").click();
  await tick();
  assert.equal(rows(page.doc).length, views.length);
  return page;
}

test("two app.conf in different folders: each row's tick box and ⋯, and each Skip in Changes to save, name it by its path; a name of its own stays short", async () => {
  const { doc } = await opened([API, WEB, CI]);
  assert.equal(controlName(tickOf(doc, "pp-000001")), "Skip ~/proj/services/api/app.conf");
  assert.equal(controlName(tickOf(doc, "pp-000002")), "Skip ~/proj/services/web/app.conf");
  assert.equal(controlName(moreOf(doc, "pp-000001")), "More about ~/proj/services/api/app.conf");
  assert.equal(controlName(moreOf(doc, "pp-000002")), "More about ~/proj/services/web/app.conf");
  assert.equal(controlName(tickOf(doc, "pp-000003")), "Skip ci.conf", "a name no other row has stays the row's name");
  assert.equal(controlName(moreOf(doc, "pp-000003")), "More about ci.conf");
  assert.equal(controlName(skipOf(doc, "pp-000001")), "Skip the suggestion for ~/proj/services/api/app.conf");
  assert.equal(controlName(skipOf(doc, "pp-000002")), "Skip the suggestion for ~/proj/services/web/app.conf");
  assert.equal(controlName(skipOf(doc, "pp-000003")), "Skip the suggestion for ci.conf");
  assert.deepEqual(nameFaults(byId(doc, "files-suggested-list")), { shared: [], unnamed: [] });
  assert.deepEqual(nameFaults(byId(doc, "files-pending-list")), { shared: [], unnamed: [] });
  // Visible words do not change: the row still shows the file's name, its
  // path under it.
  assert.equal(rowOf(doc, "pp-000001").querySelector(".file-name code").textContent, "app.conf");
  // A tick keeps its focus through the redraw (pollRefocus finds the box
  // by its place, not its name), and names the box by its path again.
  enter(tickOf(doc, "pp-000002"));
  assert.equal(doc.activeElement, tickOf(doc, "pp-000002"));
  assert.equal(controlName(doc.activeElement), "Save ~/proj/services/web/app.conf");
});

test("the opened row of a same-named file: its label, Show in policy.yaml (and Hide) and Not a secret name its path", async () => {
  const { doc } = await opened([API, WEB, CI]);
  enter(moreOf(doc, "pp-000002"));
  assert.equal(controlName(doc.activeElement), "Close ~/proj/services/web/app.conf");
  assert.equal(detail(doc).getAttribute("aria-label"), "About ~/proj/services/web/app.conf");
  const show = button(detail(doc), "Show in policy.yaml");
  assert.equal(controlName(show), "Show in policy.yaml: ~/proj/services/web/app.conf");
  enter(show);
  assert.equal(controlName(show), "Hide policy.yaml: ~/proj/services/web/app.conf");
  assert.equal(controlName(button(detail(doc), "Not a secret")), "Not a secret: ~/proj/services/web/app.conf");
  assert.deepEqual(nameFaults(byId(doc, "files-suggested-list")), { shared: [], unnamed: [] });
  // A row whose name is its own: unchanged.
  enter(moreOf(doc, "pp-000003"));
  assert.equal(detail(doc).getAttribute("aria-label"), "About ci.conf");
  assert.equal(controlName(button(detail(doc), "Not a secret")), "Not a secret: ci.conf");
});

test("Not a secret on a same-named file asks of its path and says its path when done; the other app.conf then has its name to itself", async () => {
  const asked: string[] = [];
  const dismissed: unknown[] = [];
  const { doc, window } = await opened([API, WEB, CI], {
    "POST suggestions/dismiss": (b: { id: string }) => (dismissed.push(b), { dismissed: b.id, status: "denied", ...listing([API, CI]) }),
  });
  window.confirm = (q: string) => (asked.push(q), true);
  enter(moreOf(doc, "pp-000002"));
  enter(button(detail(doc), "Not a secret"));
  await tick();
  assert.deepEqual(asked, ["Mark ~/proj/services/web/app.conf as not a secret? Mandu will not suggest it again, and the AI can still read it."]);
  assert.deepEqual(dismissed, [{ id: "pp-000002" }]);
  assert.equal(byId(doc, "rules-notice").textContent, "~/proj/services/web/app.conf is marked as not a secret. Mandu will not suggest it again.");
  assert.equal(rowOf(doc, "pp-000002"), undefined, "the row is gone");
  assert.equal(controlName(tickOf(doc, "pp-000001")), "Skip app.conf", "no other app.conf is left: the short name again");
  assert.equal(controlName(skipOf(doc, "pp-000001")), "Skip the suggestion for app.conf");
});

test("Not a secret on a file whose name is its own asks and tells with that name, as before", async () => {
  const asked: string[] = [];
  const { doc, window } = await opened([API, WEB, CI], {
    "POST suggestions/dismiss": (b: { id: string }) => ({ dismissed: b.id, status: "denied", ...listing([API, WEB]) }),
  });
  window.confirm = (q: string) => (asked.push(q), true);
  enter(moreOf(doc, "pp-000003"));
  enter(button(detail(doc), "Not a secret"));
  await tick();
  assert.deepEqual(asked, ["Mark ci.conf as not a secret? Mandu will not suggest it again, and the AI can still read it."]);
  assert.equal(byId(doc, "rules-notice").textContent, "ci.conf is marked as not a secret. Mandu will not suggest it again.");
});

test("old versions under two files of the same name are named by the file's path; under a name of its own, as before", async () => {
  const { doc } = await opened([OLD_API, OLD_WEB]);
  assert.equal(controlName(tickOf(doc, "pp-000004")), "Skip 1 old version of ~/proj/services/api/config.py");
  assert.equal(controlName(tickOf(doc, "pp-000005")), "Skip 1 old version of ~/proj/services/web/config.py");
  assert.equal(controlName(moreOf(doc, "pp-000005")), "More about 1 old version of ~/proj/services/web/config.py");
  assert.equal(controlName(skipOf(doc, "pp-000004")), "Skip the suggestion for 1 old version of ~/proj/services/api/config.py");
  enter(moreOf(doc, "pp-000004"));
  assert.equal(controlName(button(detail(doc), "Not a secret")), "Not a secret: 1 old version of ~/proj/services/api/config.py");
  assert.deepEqual(nameFaults(byId(doc, "files-suggested-list")), { shared: [], unnamed: [] });
  assert.deepEqual(nameFaults(byId(doc, "files-pending-list")), { shared: [], unnamed: [] });

  const lone = await opened([OLD_API, CI]);
  assert.equal(controlName(tickOf(lone.doc, "pp-000004")), "Skip 1 old version of config.py");
});
