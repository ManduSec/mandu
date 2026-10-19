/**
 * home-js-suggested.test — the Rules page's Keys Mandu found card and its
 * Approvals card (dashboard.md §4.25r, confidentiality-plan-14 §5.4), driven in jsdom
 * over the fetch stub of home-js-fixtures.ts. The rows are the server's own
 * view model (view-model/suggestions.ts suggestionRows), so the page is
 * tested on what the route sends.
 *
 * Pins: its own card, closed until Review, with its count badge; a path only
 * git history holds is its own greyed row, tagged; old versions of a file sit
 * under the file; each suggestion waits in Changes to save, ticked, its label
 * shown as a chip (no menu: a suggestion only ever hides); unticking skips it (kept in this
 * browser), and Save applies the ticked ones (POST suggestions/apply) with
 * no weaker-change question, before any other waiting change; one that
 * cannot be applied cannot be ticked and says why; the opened row: what the
 * scan found, when, what Save changes, the advice to replace the key, the
 * policy.yaml lines and Not a secret; Scan, with a typed folder, and the
 * folder it asks for; the Approvals card opens the view; server text lands as
 * text. A file the workspace scan found (plan 14 §13.6) is an ordinary row
 * (not greyed, no tag) whose opened row has no commit lines, the detector
 * with its line and the softer advice, and Save, Show in policy.yaml and
 * Not a secret work on it; "Also look in your home folder" sends
 * `includeHome`; the Approvals card names files and git history honestly.
 * A finished scan's line names Settings › Sensitivity labels as a link (the
 * server's `summaryParts`): a plain click opens Settings at that card, a
 * modifier click is the browser's, and a line without parts is its text.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES, choose } from "./home-js-fixtures.js";
import { scanSummary, scanSummaryParts, suggestionRows, type SuggestionWire, type SuggestPolicyWire } from "../../../src/view-model/suggestions.js";

const REPO = "/home/u/proj";
function wire(id: string, over: Partial<SuggestionWire> = {}): SuggestionWire {
  return {
    id, kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: `k-${id}`, source: "git-history", repoRoot: REPO,
    edits: [{ op: "lock-path", path: `${REPO}/deploy/id_rsa`, level: "no-model" }],
    sentence: "Make ~/proj/deploy/id_rsa a secret no AI may read (only in git history)",
    evidence: {
      paths: ["deploy/id_rsa"], blobs: ["a".repeat(40)], historyOnly: true,
      findings: [{ blob: "a".repeat(40), paths: ["deploy/id_rsa"], firstCommit: "1111111aaaa", lastCommit: "2222222bbbb", inHead: false, inIndex: false, stillPresent: false,
        detectors: [{ kind: "content-shape", rule: "private-key", mask: "(key block header)…", words: "private key", line: 1 }] }],
    },
    impact: { historicalVersions: 2, workingTreeChanges: false, files: [] },
    historyOnly: true, rotate: true, applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
    ...over,
  };
}
const KEY = wire("pp-000001");
const ENV = wire("pp-000003", {
  edits: [{ op: "lock-path", path: `${REPO}/<img src=x onerror=alert(1)>.env`, level: "no-model" }],
  sentence: "Make ~/proj/<img src=x onerror=alert(1)>.env a secret no AI may read (only in git history)",
  evidence: { ...KEY.evidence, paths: ["<img src=x onerror=alert(1)>.env"] },
});
const BLOB = wire("pp-000002", {
  edits: [{ op: "lock-blob", blob: `sha1:${"c".repeat(40)}`, level: "no-model" }],
  sentence: "Hide an old version of ~/proj/config.py from the AI",
  evidence: { paths: ["config.py"], blobs: ["c".repeat(40)], historyOnly: false,
    findings: [{ blob: "c".repeat(40), paths: ["config.py"], firstCommit: "3333333", lastCommit: "4444444", inHead: false, inIndex: false, stillPresent: true,
      detectors: [{ kind: "content-shape", rule: "github-token", mask: "ghp_…", words: "GitHub token", line: 1 }] }] },
  impact: { historicalVersions: 1, workingTreeChanges: false, files: [] },
  historyOnly: false, applicable: false,
});
// The Linux words (a macOS host words a history row's impact for macOS:
// suggestions-view-model.test.ts); the page shows whatever the route sends.
const listing = (views: SuggestionWire[], scan: unknown = null) => ({ suggestions: suggestionRows(views, "/home/u", "linux"), count: views.length, scan });
const LIST = listing([KEY, ENV, BLOB]);

const suggestedRows = (doc: any) => [...doc.querySelectorAll("#files-suggested-list .row.suggested")] as any[];
const rowById = (doc: any, id: string) => suggestedRows(doc).find((r) => r.dataset.id === id);
const pendingText = (doc: any) => doc.getElementById("files-pending-list").textContent as string;
/** A suggestion row's label while it is ticked (it waits in Changes to save), else []. */
const pressed = (row: any) => (row.querySelector("input.file-tick").checked ? [row.querySelector(".label-chip").textContent] : []);
const HIDDEN = "No AI";

async function openSuggestedView(routes: Record<string, unknown> = {}, storage: Record<string, string> = {}) {
  const page = load({ url: FILES_URL, storage, routes: { ...FILES_ROUTES, "GET suggestions": LIST, ...routes } });
  await tick();
  page.doc.getElementById("suggest-open").click();
  await tick();
  return page;
}

test("Suggested: a third view with its count; files first, a path only git history holds greyed and tagged, old versions under their file", async () => {
  const page = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET suggestions": LIST } });
  await tick();
  const { doc, calls } = page;
  assert.equal(doc.getElementById("files-suggested-count").textContent, "3", "the badge before the view is opened");
  assert.equal(doc.getElementById("files-pending").hidden, true, "nothing waits until the person has seen them");
  const get = calls.find((c) => c.url === "/mandu/api/suggestions");
  assert.equal(get?.headers["X-Mandu-Control"], "1", "the listing carries the page's control header");
  doc.getElementById("suggest-open").click();
  await tick();
  assert.equal(doc.getElementById("files-suggested-view").hidden, false);
  assert.equal(doc.getElementById("suggest-open").getAttribute("aria-expanded"), "true");
  assert.equal(doc.getElementById("suggest-open").textContent, "Close");
  assert.equal(doc.getElementById("lock-form").hidden, true, "Add a rule stays as it was");
  const rows = suggestedRows(doc);
  assert.deepEqual(rows.map((r) => r.dataset.id), ["pp-000001", "pp-000003", "pp-000002"]);
  const key = rowById(doc, "pp-000001");
  assert.equal(key.classList.contains("history-only"), true, "greyed");
  assert.equal(key.querySelector(".file-tag.history").textContent, "only in git history");
  const parent = doc.querySelector("#files-suggested-list .row.suggested-parent");
  assert.match(parent.textContent, /config\.py~\/proj\/config\.py as it is now: not changed/);
  assert.equal(parent.nextElementSibling, rowById(doc, "pp-000002"), "the old versions sit under their file");
  assert.equal(rowById(doc, "pp-000002").getAttribute("style"), "--depth:1");
  assert.match(rowById(doc, "pp-000002").textContent, /1 old version of config\.py/);
  // Server text is text: the odd file name is a name, not markup.
  assert.equal(doc.querySelector("#files-suggested-list img"), null);
  assert.match(rowById(doc, "pp-000003").textContent, /<img src=x onerror=alert\(1\)>\.env/);
  // Left open, it is remembered.
  assert.equal(page.window.localStorage.getItem("mandu.files.suggested"), "1");
});

test("Suggested: each waits in Changes to save with its label pressed as a change; unticking skips it and is remembered; one that cannot be applied cannot be ticked", async () => {
  const { doc, window } = await openSuggestedView();
  const key = () => rowById(doc, "pp-000001");
  assert.deepEqual(pressed(key()), [HIDDEN]);
  assert.equal(key().querySelector("select"), null, "no menu: a suggestion only ever hides a file");
  assert.equal(doc.getElementById("files-pending").hidden, false);
  assert.equal(doc.getElementById("files-pending-count").textContent, "2", "the two that can be applied");
  assert.match(pendingText(doc), /~\/proj\/deploy\/id_rsa No AI, suggested by Mandu's scan\. Hides 2 old versions/);
  const blob = rowById(doc, "pp-000002");
  assert.equal(blob.querySelector("input[type=checkbox]").disabled, true);
  assert.equal(blob.querySelector("input[type=checkbox]").checked, false);
  assert.match(blob.textContent, /Cannot be saved yet/);
  assert.doesNotMatch(pendingText(doc), /config\.py/);
  // Untick: skipped, not saved, and remembered in this browser.
  const box = key().querySelector("input[type=checkbox]");
  box.checked = false;
  box.dispatchEvent(new window.Event("change"));
  assert.deepEqual(pressed(key()), []);
  assert.match(key().textContent, /Skipped: not saved/);
  assert.equal(doc.getElementById("files-pending-count").textContent, "1");
  assert.deepEqual(JSON.parse(window.localStorage.getItem("mandu.files.skipped")), ["pp-000001"]);
  // The tick saves it again.
  const again = key().querySelector("input[type=checkbox]");
  again.checked = true;
  again.dispatchEvent(new window.Event("change"));
  assert.deepEqual(pressed(key()), [HIDDEN]);
  assert.equal(window.localStorage.getItem("mandu.files.skipped"), null);
  // Skip in the pending list does the same.
  const skip = [...doc.querySelectorAll("#files-pending-list button")].find((b: any) => b.getAttribute("aria-label") === "Skip the suggestion for id_rsa") as any;
  skip.click();
  assert.equal(key().querySelector("input[type=checkbox]").checked, false);
});

test("Suggested: a skip made earlier in this browser is kept after a reload", async () => {
  const { doc } = await openSuggestedView({}, { "mandu.files.skipped": JSON.stringify(["pp-000003"]) });
  assert.equal(rowById(doc, "pp-000003").querySelector("input[type=checkbox]").checked, false);
  assert.equal(doc.getElementById("files-pending-count").textContent, "1");
});

test("Save applies the ticked suggestions, asks nothing, and says so with Undo for one change", async () => {
  const applied: any[] = [];
  const { doc, calls } = await openSuggestedView({
    "POST suggestions/apply": (b: any) => (applied.push(b), { applied: [{ id: "pp-000001", changeId: "pc-000042" }], refused: [], ...listing([ENV, BLOB]) }),
  });
  const box = rowById(doc, "pp-000003").querySelector("input[type=checkbox]");
  box.checked = false;
  box.dispatchEvent(new doc.defaultView.Event("change"));
  doc.getElementById("files-save").click();
  await tick();
  assert.deepEqual(applied, [{ ids: ["pp-000001"] }], "only the ticked one");
  assert.equal(calls.filter((c) => c.url.endsWith("/api/files/labels")).length, 0, "nothing else to save");
  assert.equal(doc.getElementById("files-confirm").hidden, true, "a suggestion only adds protection: no question");
  assert.match(doc.getElementById("rules-notice").textContent, /^1 suggestion saved\.Undo$/);
  assert.equal(rowById(doc, "pp-000001"), undefined, "it is no longer waiting");
  assert.equal(doc.getElementById("files-suggested-count").textContent, "2");
  assert.equal(doc.getElementById("files-pending").hidden, true, "the skipped one stays skipped");
});

test("Save with a suggestion and a label chosen elsewhere: the suggestions first, then the rest; a refusal is said", async () => {
  const order: string[] = [];
  const { doc } = await openSuggestedView({
    "POST suggestions/apply": () => (order.push("suggestions"), { applied: [{ id: "pp-000001", changeId: "pc-000001" }], refused: [{ id: "pp-000003", error: "It is no longer waiting." }], ...listing([BLOB]) }),
    "POST files/labels": () => (order.push("labels"), { applied: true, changeId: "pc-000002", page: 0 }),
    "POST files/impact": { impact: null, page: 0 },
  });
  doc.getElementById("rules-add").click();
  await tick();
  const readme = [...doc.querySelectorAll("#files-list .row.file")].find((r: any) => /README/.test(r.textContent)) as any;
  choose(readme, "no-model");
  await tick();
  assert.equal(doc.getElementById("files-pending-count").textContent, "3");
  doc.getElementById("files-save").click();
  await tick(20);
  assert.deepEqual(order, ["suggestions", "labels"]);
  assert.match(doc.getElementById("lock-error").textContent, /1 suggestion was not saved: It is no longer waiting\./);
  assert.match(doc.getElementById("rules-notice").textContent, /1 change saved, and 1 suggestion\./);
});

test("the opened row: what the scan found, when, what Save changes, the advice to replace the key, the policy.yaml lines, and Not a secret", async () => {
  const dismissed: any[] = [];
  const { doc, window } = await openSuggestedView({
    "POST suggestions/dismiss": (b: any) => (dismissed.push(b), { dismissed: b.id, status: "denied", ...listing([ENV, BLOB]) }),
  });
  rowById(doc, "pp-000001").querySelector(".file-name").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  const detail = doc.querySelector("#files-suggested-list .file-detail");
  assert.ok(detail);
  assert.equal(rowById(doc, "pp-000001").nextElementSibling, detail, "it opens under its row");
  const text = detail.textContent as string;
  assert.match(text, /~\/proj\/deploy\/id_rsa \(in ~\/proj\)/);
  assert.match(text, /Make ~\/proj\/deploy\/id_rsa a secret no AI may read \(only in git history\)/);
  assert.match(text, /only its git history still holds it/);
  assert.match(text, /Hides 2 old versions in git history from the AI\. No file you have now changes\./);
  assert.match(text, /This key was exposed\. Replace it with a new one/);
  assert.match(text, /Suggested by Mandu's scan/);
  assert.match(text, /What the scan foundLooks like a private key\(key block header\)…WhenAdded in 1111111, removed in 2222222/);
  const show = [...detail.querySelectorAll("button")].find((b: any) => b.textContent === "Show in policy.yaml") as any;
  show.click();
  assert.equal(detail.querySelector(".suggestion-yaml").textContent, "paths:\n  - path: /home/u/proj/deploy/id_rsa\n    level: no-model");
  const not = [...detail.querySelectorAll("button")].find((b: any) => b.textContent === "Not a secret") as any;
  not.click();
  await tick();
  assert.deepEqual(dismissed, [{ id: "pp-000001" }]);
  assert.equal(rowById(doc, "pp-000001"), undefined);
  assert.match(doc.getElementById("rules-notice").textContent, /id_rsa is marked as not a secret\. Mandu will not suggest it again\./);
  // The blob row that cannot be applied says why when opened.
  rowById(doc, "pp-000002").querySelector(".file-name").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  assert.match(doc.querySelector("#files-suggested-list .file-detail").textContent, /cannot hide old versions of a file yet/);
});

test("Not a secret asks first; No leaves it waiting", async () => {
  const { doc, window, calls } = await openSuggestedView();
  window.confirm = () => false;
  rowById(doc, "pp-000001").querySelector(".file-more").click();
  ([...doc.querySelectorAll("#files-suggested-list .file-detail button")].find((b: any) => b.textContent === "Not a secret") as any).click();
  await tick();
  assert.equal(calls.filter((c) => c.url.endsWith("/suggestions/dismiss")).length, 0);
});

test("Scan: the projects the agents worked in, or a typed folder; the folder it asks for; still scanning, then the summary", async () => {
  let n = 0;
  const bodies: any[] = [];
  const { doc } = await openSuggestedView({
    "POST suggestions/scan": (b: any) => {
      bodies.push(b);
      n++;
      if (n === 1) return { status: 400, body: { error: "No project is known yet: no agent has run under Mandu. Type the folder of a project to scan it.", needsRoot: true } };
      if (n === 2) return { ...LIST, scan: { running: true, roots: ["~/work/api"], summary: null, error: null } };
      return { ...LIST, scan: { running: false, roots: ["~/work/api"], summary: "Scanned ~/work/api. 3 possible keys to review.", error: null } };
    },
  });
  const form = doc.getElementById("suggest-form");
  form.dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await tick();
  assert.deepEqual(bodies[0], {});
  assert.match(doc.getElementById("suggest-error").textContent, /Type the folder of a project/);
  assert.equal(doc.activeElement, doc.getElementById("suggest-root"));
  (doc.getElementById("suggest-root") as any).value = "~/work/api";
  form.dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await tick();
  assert.deepEqual(bodies[1], { root: "~/work/api" });
  assert.equal(doc.getElementById("suggest-scan").disabled, true, "one scan at a time");
  assert.match(doc.getElementById("suggest-status").textContent, /^Scanning ~\/work\/api… This can take a minute\.$/);
  form.dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await tick();
  assert.equal(doc.getElementById("suggest-scan").disabled, false);
  assert.equal(doc.getElementById("suggest-status").textContent, "Scanned ~/work/api. 3 possible keys to review.");
});

test("Approvals: one card says how many keys the scan found and opens the Suggested view; no card when none wait", async () => {
  const { doc, window } = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { ...FILES_ROUTES, "GET suggestions": LIST } });
  await tick();
  const block = doc.getElementById("approvals-suggestions-block");
  assert.equal(block.hidden, false);
  assert.match(block.textContent, /Keys Mandu found/);
  assert.match(block.textContent, /Mandu found 3 possible keys in this project's git history/);
  assert.match(block.textContent, /the AI can still read them/);
  doc.getElementById("approvals-suggestions-open").click();
  await tick();
  assert.equal(doc.getElementById("page-rules").hidden, false);
  assert.equal(doc.getElementById("files-suggested-view").hidden, false, "Keys Mandu found is open");
  assert.equal(window.location.pathname + window.location.search, "/mandu/rules");
  const none = load({ url: "http://127.0.0.1:4500/mandu/approvals", routes: { "GET suggestions": listing([]) } });
  await tick();
  assert.equal(none.doc.getElementById("approvals-suggestions-block").hidden, true);
});

test("an answer the page cannot use (no admin session, an older service) shows no card and says so in the view", async () => {
  const { doc, calls } = await openSuggestedView({ "GET suggestions": { status: 403, body: { error: "admin session required" } } });
  assert.equal(doc.getElementById("approvals-suggestions-block").hidden, true);
  // In the words of the page, not the gate of the server (dashboard.md §4.25 "Refusals").
  assert.match(doc.getElementById("suggest-error").textContent, /^Sign in first: /);
  assert.doesNotMatch(doc.getElementById("suggest-error").textContent, /admin session required/);
  assert.equal(doc.getElementById("files-suggested-count").textContent, "");
  // The poll stops asking after a refusal (no log line every ten seconds).
  const asked = () => calls.filter((c) => c.url === "/mandu/api/suggestions").length;
  const before = asked();
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick();
  assert.ok(calls.filter((c) => c.url === "/mandu/api/home").length >= 2, "the poll ran");
  assert.equal(asked(), before, "and did not ask for the suggestions again");
});

// ── A file the workspace scan found (plan 14 §13.6) ─────────────────────────

const WS = wire("pp-000004", {
  source: "workspace", findingKey: `workspace:path:${REPO}/deploy/staging.conf`,
  edits: [{ op: "lock-path", path: `${REPO}/deploy/staging.conf`, level: "no-model" }],
  sentence: "Make ~/proj/deploy/staging.conf a secret no AI may read",
  evidence: { paths: ["deploy/staging.conf"], blobs: [], historyOnly: false,
    findings: [{ blob: "", paths: ["deploy/staging.conf"], firstCommit: null, lastCommit: null, inHead: false, inIndex: false, stillPresent: true,
      detectors: [{ kind: "content-shape", rule: "github-token", mask: "ghp_…", words: "GitHub token", line: 2 }] }] },
  impact: { historicalVersions: 0, workingTreeChanges: true, files: ["deploy/staging.conf"] },
  historyOnly: false, rotate: false,
});

test("a file found as it is now: an ordinary row (not greyed, no tag), no commit lines, the detector with its line, the softer advice; Save, Show in policy.yaml and Not a secret work on it", async () => {
  const applied: any[] = [];
  const dismissed: any[] = [];
  const { doc, window } = await openSuggestedView({
    "GET suggestions": listing([WS, KEY]),
    "POST suggestions/apply": (b: any) => (applied.push(b), { applied: [{ id: "pp-000004", changeId: "pc-000050" }], refused: [], ...listing([KEY]) }),
  });
  const row = rowById(doc, "pp-000004");
  assert.ok(row);
  assert.equal(row.classList.contains("history-only"), false, "not greyed");
  assert.equal(row.querySelector(".file-tag"), null, "no 'only in git history' tag");
  assert.match(row.textContent, /staging\.conf~\/proj\/deploy\/staging\.confWill be: /);
  assert.deepEqual(pressed(row), [HIDDEN], "waits in Changes to save, ticked");
  assert.match(pendingText(doc), /~\/proj\/deploy\/staging\.conf No AI, suggested by Mandu's scan\. Hides this file from the AI from the next time an agent starts\./);
  row.querySelector(".file-name").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  const detail = doc.querySelector("#files-suggested-list .file-detail");
  const text = detail.textContent as string;
  assert.match(text, /Make ~\/proj\/deploy\/staging\.conf a secret no AI may read/);
  assert.match(text, /Found in the file as it is now, on this computer\./);
  assert.doesNotMatch(text, /git history still holds it/);
  assert.match(text, /Hides this file from the AI from the next time an agent starts\./);
  assert.match(text, /Suggested by Mandu's scan/);
  const advice = [...detail.querySelectorAll("p")].find((p: any) => /If an AI session read this file before, rotate the key/.test(p.textContent)) as any;
  assert.ok(advice, "the softer advice");
  assert.equal(advice.classList.contains("rule-warn"), false, "not a warning");
  assert.doesNotMatch(text, /This key was exposed/);
  const found = detail.querySelector(".file-why").textContent as string;
  assert.equal(found, "What the scan foundLooks like a GitHub tokenghp_… on line 2", "the detector, its mask and line; no When");
  const show = [...detail.querySelectorAll("button")].find((b: any) => b.textContent === "Show in policy.yaml") as any;
  show.click();
  assert.equal(detail.querySelector(".suggestion-yaml").textContent, "paths:\n  - path: /home/u/proj/deploy/staging.conf\n    level: no-model");
  // Save applies it by its id, like any suggestion.
  const box = rowById(doc, "pp-000001").querySelector("input[type=checkbox]");
  box.checked = false;
  box.dispatchEvent(new window.Event("change"));
  doc.getElementById("files-save").click();
  await tick();
  assert.deepEqual(applied, [{ ids: ["pp-000004"] }]);
  assert.equal(rowById(doc, "pp-000004"), undefined);
  // Not a secret, on a fresh page.
  const again = await openSuggestedView({
    "GET suggestions": listing([WS]),
    "POST suggestions/dismiss": (b: any) => (dismissed.push(b), { dismissed: b.id, status: "denied", ...listing([]) }),
  });
  rowById(again.doc, "pp-000004").querySelector(".file-more").click();
  ([...again.doc.querySelectorAll("#files-suggested-list .file-detail button")].find((b: any) => b.textContent === "Not a secret") as any).click();
  await tick();
  assert.deepEqual(dismissed, [{ id: "pp-000004" }]);
  assert.match(again.doc.getElementById("rules-notice").textContent, /staging\.conf is marked as not a secret/);
});

test("Scan: 'Also look in your home folder' sends includeHome, and the line says so", async () => {
  const bodies: any[] = [];
  const { doc } = await openSuggestedView({
    "POST suggestions/scan": (b: any) => (bodies.push(b), { ...LIST, scan: { running: true, roots: [], includeHome: true, summary: null, error: null } }),
  });
  assert.equal(doc.getElementById("suggest-scan").textContent, "Scan for keys");
  const home = doc.getElementById("suggest-home") as any;
  assert.equal(home.checked, false, "off unless asked");
  assert.match(home.parentElement.textContent, /Also look in your home folder/);
  home.checked = true;
  const form = doc.getElementById("suggest-form");
  form.dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await tick();
  assert.deepEqual(bodies[0], { includeHome: true });
  assert.equal(doc.getElementById("suggest-status").textContent, "Scanning your home folder… This can take a minute.");
});

test("Scan: a typed folder and the home folder together; the running line names both", async () => {
  const bodies: any[] = [];
  const { doc } = await openSuggestedView({
    "POST suggestions/scan": (b: any) => (bodies.push(b), { ...LIST, scan: { running: true, roots: ["~/work/api"], includeHome: true, summary: null, error: null } }),
  });
  (doc.getElementById("suggest-root") as any).value = "~/work/api";
  (doc.getElementById("suggest-home") as any).checked = true;
  doc.getElementById("suggest-form").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await tick();
  assert.deepEqual(bodies[0], { root: "~/work/api", includeHome: true });
  assert.equal(doc.getElementById("suggest-status").textContent, "Scanning ~/work/api and your home folder… This can take a minute.");
});

test("Approvals: the card says where the keys were found, files and git history alike", async () => {
  const approvals = "http://127.0.0.1:4500/mandu/approvals";
  const both = load({ url: approvals, routes: { ...FILES_ROUTES, "GET suggestions": listing([WS, KEY]) } });
  await tick();
  assert.match(both.doc.getElementById("approvals-suggestions-block").textContent, /Mandu found 2 possible keys in this project's files and git history/);
  const files = load({ url: approvals, routes: { ...FILES_ROUTES, "GET suggestions": listing([WS]) } });
  await tick();
  assert.match(files.doc.getElementById("approvals-suggestions-block").textContent, /Mandu found 1 possible key in this project's files/);
  const other = wire("pp-000005", { ...WS, id: "pp-000005", repoRoot: "/home/u/other", edits: [{ op: "lock-path", path: "/home/u/other/app.ini", level: "no-model" }] });
  const two = load({ url: approvals, routes: { ...FILES_ROUTES, "GET suggestions": listing([WS, other]) } });
  await tick();
  assert.match(two.doc.getElementById("approvals-suggestions-block").textContent, /Mandu found 2 possible keys in the files of 2 projects/);
  const inHome = wire("pp-000006", { ...WS, id: "pp-000006", repoRoot: "/home/u", edits: [{ op: "lock-path", path: "/home/u/tools.toml", level: "no-model" }] });
  const home = load({ url: approvals, routes: { ...FILES_ROUTES, "GET suggestions": listing([inHome]) } });
  await tick();
  assert.match(home.doc.getElementById("approvals-suggestions-block").textContent, /Mandu found 1 possible key in your home folder/);
});

test("Keys Mandu found: its own card, closed until Review; Close shuts it and is remembered; the line says where the keys were found", async () => {
  const page = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET suggestions": LIST } });
  await tick();
  const { doc, window } = page;
  const btn = doc.getElementById("suggest-open");
  assert.equal(doc.getElementById("files-suggested-view").hidden, true, "closed until asked for");
  assert.equal(btn.textContent, "Review");
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  assert.equal(doc.getElementById("suggested-line").textContent, "Possible keys in this project's git history that no rule covers yet.");
  assert.ok(doc.getElementById("suggested-block").closest("#page-rules"), "on the Rules page");
  assert.equal(doc.getElementById("lock-form").contains(btn), false, "not inside Add a rule");
  btn.click();
  await tick();
  assert.equal(doc.getElementById("files-suggested-view").hidden, false);
  btn.click();
  assert.equal(doc.getElementById("files-suggested-view").hidden, true);
  assert.equal(btn.textContent, "Review");
  assert.equal(window.localStorage.getItem("mandu.files.suggested"), "0");
  assert.equal(doc.getElementById("files-pending").hidden, false, "what was seen still waits in Changes to save");
});

/** A finished scan of ~/docs: one document whose label has no level. */
const DOCS_SCAN: SuggestPolicyWire = {
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
const DOCS_LINE = "Scanned 1 file in ~/docs. Nothing new to review. 1 file carries a sensitivity label you have not chosen a level for: set it in Settings › Sensitivity labels.";

test("a finished scan's line links Settings › Sensitivity labels: a plain click opens Settings at that card, a modifier click is the browser's", async () => {
  const scan = { running: false, roots: ["~/docs"], summary: scanSummary(DOCS_SCAN, "/home/u"), summaryParts: scanSummaryParts(DOCS_SCAN, "/home/u"), error: null };
  const page = await openSuggestedView({ "GET suggestions": listing([], scan) });
  const line = page.doc.getElementById("suggest-status");
  assert.equal(line.textContent, DOCS_LINE, "the documents it read are counted");
  const links = [...line.querySelectorAll("a")] as any[];
  assert.deepEqual(links.map((a) => [a.textContent, a.getAttribute("href"), a.getAttribute("target")]), [["Settings › Sensitivity labels", "/mandu/settings#sensitivity-labels", null]],
    "one link, to Settings' Sensitivity labels card under the page's base path, in this tab");
  const scrolled: string[] = [];
  page.window.HTMLElement.prototype.scrollIntoView = function (this: any) { scrolled.push(this.id); };
  // A modifier click is left to the browser (a new tab or window on Settings).
  let prevented: boolean | null = null;
  page.doc.addEventListener("click", (e: any) => { prevented = e.defaultPrevented; e.preventDefault(); });
  links[0].dispatchEvent(new page.window.MouseEvent("click", { bubbles: true, cancelable: true, ctrlKey: true }));
  await tick();
  assert.equal(prevented, false);
  assert.equal(page.window.location.pathname, "/mandu/rules", "the page stays");
  assert.deepEqual(scrolled, []);
  // A plain click: Settings, scrolled to its Sensitivity labels card.
  links[0].click();
  await tick();
  assert.equal(prevented, true, "the page handles a plain click itself");
  assert.equal(page.window.location.pathname, "/mandu/settings");
  assert.equal(page.doc.querySelector('#main > section[data-page="settings"]').hidden, false);
  assert.equal(page.doc.querySelector('#main > section[data-page="rules"]').hidden, true);
  assert.deepEqual(scrolled, ["settings-labels-block"], "to the card where a level is set");
  const card = page.doc.getElementById("settings-labels-block");
  assert.equal(card.querySelector("h2").textContent, "Sensitivity labels");
  assert.ok(card.contains(page.doc.getElementById("settings-labels")), "the card that lists the labels");
  assert.ok(page.calls.some((c: any) => c.url === "/mandu/api/policy/sensitivity-labels"), "and reads them");
});

test("a scan line without parts (an older server) is its text; a place the page does not know is text; server text is text", async () => {
  const older = await openSuggestedView({ "GET suggestions": listing([], { running: false, roots: ["~/docs"], summary: DOCS_LINE, error: null }) });
  assert.equal(older.doc.getElementById("suggest-status").textContent, DOCS_LINE);
  assert.equal(older.doc.querySelector("#suggest-status a"), null);
  const odd = await openSuggestedView({ "GET suggestions": listing([], {
    running: false, roots: ["~/docs"], summary: "x", error: null,
    summaryParts: [{ kind: "text", text: "Set it in " }, { kind: "link", text: "<b>Elsewhere</b>", to: "nowhere" }, { kind: "code", text: "<i>c</i>" }],
  }) });
  const line = odd.doc.getElementById("suggest-status");
  assert.equal(line.textContent, "Set it in <b>Elsewhere</b><i>c</i>");
  assert.equal(line.querySelector("a, b, i"), null);
  assert.equal(line.querySelector("code").textContent, "<i>c</i>");
});
