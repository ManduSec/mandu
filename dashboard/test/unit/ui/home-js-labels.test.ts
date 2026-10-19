/**
 * home-js-labels.test — plan 14 §14.1 on the PRODUCT page (public/js/home.js,
 * dashboard.md §4.25r, §4.25s), driven in jsdom over the shared fetch stub
 * (home-js-fixtures.ts), with the server's own view models
 * (view-model/suggestions.ts, view-model/sensitivity-labels.ts).
 *
 * Pins: Settings › Sensitivity labels lists your mappings (a level picker,
 * Save and Remove), your administrator's (read only) and the labels the last
 * scan found with no level (their files, a name box and a level picker set
 * to "No AI"); the note under them links Keys Mandu
 * found on Rules, opened where Scan for keys is, and after a scan that found
 * no labelled document says it found none; after a scan it says which
 * documents the label read left unchecked; Save sends `map` with the typed name and
 * the picked level; Remove asks first when the server says it lowers what
 * Mandu suggests, then sends what was shown; a refusal is said on the row;
 * each change names the mapping's version as the row was read, and one
 * refused because the mapping changed meanwhile says so on the row, keeps
 * the level picked and the name typed, reads the list again and saves
 * against the mapping as it is now (dashboard.md §4.25s);
 * server text is text. In the Suggested view, a document's sensitivity
 * label is an ordinary row, "From the document's sensitivity label", its
 * mapped level's dot pressed as a change waiting and named in Changes to
 * save. Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES } from "./home-js-fixtures.js";
import { NO_SCAN_NOTE, labelSettingsVM, labelStaleWords } from "../../../src/view-model/sensitivity-labels.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";

const URL = "http://127.0.0.1:4500/mandu/settings";
const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const GEN = "1e4f0000-0000-4000-8000-000000000001";
const OTHER = "2a2a0000-0000-4000-8000-000000000002";

const V_HC = "c".repeat(32);
const ABSENT = "0".repeat(32);
const VM = labelSettingsVM(
  { sensitivity_labels: [{ id: HC, name: "Highly <b>Confidential</b>", level: "no-model" }] },
  { sensitivityLabels: [{ id: GEN, name: "General", level: "any-model", file: "/etc/mandu/policy.d/l.yaml" }] },
  { labels: { unmapped: [{ id: OTHER, site: null, files: 7 }], unmappedMore: 0 }, at: 1 },
  { itemVersions: { "sensitivity-labels": { [`${HC}|`]: V_HC } }, absentVersion: ABSENT },
);
const host = (doc: any) => doc.getElementById("settings-labels");
const rowOf = (doc: any, id: string) => [...host(doc).querySelectorAll(".label-row")].find((r: any) => r.dataset.id === id) as any;

test("Settings › Sensitivity labels: yours with Save and Remove, your administrator's read only, and the ones with no level to name and pick", async () => {
  const { doc, calls } = load({ url: URL, routes: { "GET policy/sensitivity-labels": { labels: VM } } });
  await tick();
  const get = calls.find((c) => c.url === "/mandu/api/policy/sensitivity-labels");
  assert.equal(get?.headers["X-Mandu-Control"], "1", "the listing carries the page's control header");
  const mine = rowOf(doc, HC);
  assert.equal(mine.querySelector(".name").textContent, "Highly <b>Confidential</b>", "server text is text");
  assert.equal(host(doc).querySelector("b"), null);
  assert.equal(mine.querySelector("select.label-level").value, "no-model");
  assert.ok(mine.querySelector(".label-remove-btn"));
  const admin = rowOf(doc, GEN);
  assert.match(admin.textContent, /Any AI, when it asks/);
  assert.match(admin.textContent, /Set by your administrator\./);
  assert.equal(admin.querySelector("button"), null, "read only");
  const open = rowOf(doc, OTHER);
  assert.match(open.textContent, /7 files carry it\. No level yet, so Mandu suggests nothing for it\./);
  assert.equal(open.querySelector("select.label-level").value, "no-model", "the default is hidden from the AI");
  assert.deepEqual([...open.querySelectorAll("option")].map((o: any) => o.textContent),
    ["Not secret", "Any AI, when it asks", "Your own AI only", "No AI"]);
  assert.match(open.textContent, /Mandu cannot read your organization's settings, so you choose/);
});

test("Save on a label with no level sends map with the typed name and the picked level, then shows the note and reads the list again", async () => {
  const posts: any[] = [];
  let n = 0;
  const { doc } = load({ url: URL, routes: {
    "GET policy/sensitivity-labels": () => (n++ === 0 ? { labels: VM } : { labels: { ...VM, unmapped: [], note: "Every sensitivity label the last scan found has a level." } }),
    "POST policy/sensitivity-labels/change": (b: any) => (posts.push(b), { applied: true, changeId: "pc-000004", note: "Mandu's next scan suggests with this." }),
  } });
  await tick();
  const open = rowOf(doc, OTHER);
  open.querySelector("input.label-name").value = "Customer Data";
  open.querySelector("select.label-level").value = "local-model";
  open.querySelector(".label-save-btn").click();
  await tick();
  assert.deepEqual(posts, [{ action: "map", id: OTHER, name: "Customer Data", level: "local-model", version: ABSENT }], "a label with no level names the absent version");
  assert.match(doc.getElementById("labels-notice").textContent, /Saved Customer Data\. Mandu's next scan suggests with this\.Undo/);
  assert.equal(rowOf(doc, OTHER), undefined, "read again");
  assert.match(host(doc).textContent, /Every sensitivity label the last scan found has a level\./);
});

test("Remove asks first when the server says it lowers what Mandu suggests, then sends what was shown; a refusal is said on the row", async () => {
  const posts: any[] = [];
  const asked: string[] = [];
  const page = load({ url: URL, routes: {
    "GET policy/sensitivity-labels": { labels: VM },
    "POST policy/sensitivity-labels/change": (b: any) => {
      posts.push(b);
      return b.expected
        ? { status: 409, body: { error: "Your sensitivity labels changed while you were deciding. Nothing was changed. Try again." } }
        : { applied: false, confirm: true, expected: ["k"], rows: [[{ kind: "text", text: "Stop suggesting a label for documents with the sensitivity label " }, { kind: "code", text: HC }]], wouldLet: [[{ kind: "text", text: "Mandu would suggest less" }]], warnings: [] };
    },
  } });
  page.window.confirm = (q: string) => (asked.push(q), true);
  await tick();
  rowOf(page.doc, HC).querySelector(".label-remove-btn").click();
  await tick();
  assert.equal(asked.length, 1);
  assert.match(asked[0]!, /Stop suggesting a label for documents with the sensitivity label 9fbde396/);
  assert.match(asked[0]!, /Mandu would suggest less/);
  assert.deepEqual(posts, [{ action: "unmap", id: HC, version: V_HC }, { action: "unmap", id: HC, version: V_HC, expected: ["k"] }]);
  assert.match(rowOf(page.doc, HC).textContent, /changed while you were deciding/);
});

test("before any scan, the note links Keys Mandu found: a click opens Rules with it open and Scan for keys showing; a modifier click is the browser's", async () => {
  const page = load({ url: URL, routes: { ...FILES_ROUTES, "GET policy/sensitivity-labels": { labels: labelSettingsVM(null, undefined, null) }, "GET suggestions": { suggestions: [], count: 0, scan: null } } });
  await tick();
  const note = host(page.doc).querySelector(".labels-note");
  assert.equal(note.textContent, NO_SCAN_NOTE);
  const links = [...note.querySelectorAll("a")] as any[];
  assert.deepEqual(links.map((a) => [a.textContent, a.getAttribute("href"), a.getAttribute("target")]), [["Keys Mandu found", "/mandu/rules#keys-found", null]],
    "one link, to Rules' Keys Mandu found card under the page's base path, in this tab");
  assert.equal(page.doc.getElementById("files-suggested-view").hidden, true, "Rules hides Scan for keys until Keys Mandu found is opened");
  // A modifier click is left to the browser (a new tab or window on Rules).
  let prevented: boolean | null = null;
  page.doc.addEventListener("click", (e: any) => { prevented = e.defaultPrevented; e.preventDefault(); });
  links[0].dispatchEvent(new page.window.MouseEvent("click", { bubbles: true, cancelable: true, ctrlKey: true }));
  await tick();
  assert.equal(prevented, false);
  assert.equal(page.window.location.pathname, "/mandu/settings", "the page stays");
  // A plain click opens Keys Mandu found on Rules.
  links[0].click();
  await tick();
  assert.equal(prevented, true, "the page handles a plain click itself");
  assert.equal(page.window.location.pathname, "/mandu/rules");
  assert.equal(page.doc.querySelector('#main > section[data-page="rules"]').hidden, false);
  assert.equal(page.doc.querySelector('#main > section[data-page="settings"]').hidden, true);
  assert.equal(page.doc.getElementById("files-suggested-view").hidden, false, "Keys Mandu found is open");
  assert.equal(page.doc.getElementById("suggest-open").getAttribute("aria-expanded"), "true");
  assert.equal(page.doc.getElementById("suggest-scan").textContent, "Scan for keys", "the button the note names is there");
  assert.ok(page.calls.some((c) => c.url === "/mandu/api/suggestions"), "and reads what earlier scans found");
});

test("after a scan that found no document with a label, the note says so and links Keys Mandu found; without parts (an older server) the note is its text", async () => {
  const none = labelSettingsVM(null, undefined, { labels: { unmapped: [], unmappedMore: 0, files: 0 }, at: 1 });
  const a = load({ url: URL, routes: { "GET policy/sensitivity-labels": { labels: none } } });
  await tick();
  const note = host(a.doc).querySelector(".labels-note");
  assert.equal(note.textContent, "The last scan found no sensitivity label on your documents. To look in another folder, open Keys Mandu found in Rules.");
  assert.doesNotMatch(note.textContent, /Every sensitivity label/);
  assert.equal(note.querySelector("a").textContent, "Keys Mandu found");
  const { noteParts: _parts, ...older } = labelSettingsVM(null, undefined, null);
  const b = load({ url: URL, routes: { "GET policy/sensitivity-labels": { labels: older } } });
  await tick();
  const plain = host(b.doc).querySelector(".labels-note");
  assert.equal(plain.textContent, NO_SCAN_NOTE);
  assert.equal(plain.querySelector("a"), null);
  // A place the page does not know is text; server text is text.
  const c = load({ url: URL, routes: { "GET policy/sensitivity-labels": { labels: { ...older, note: "x", noteParts: [{ kind: "link", text: "<b>Elsewhere</b>", to: "nowhere" }] } } } });
  await tick();
  const odd = host(c.doc).querySelector(".labels-note");
  assert.equal(odd.textContent, "<b>Elsewhere</b>");
  assert.equal(odd.querySelector("a, b"), null);
});

test("after a scan that left documents unchecked, the note says which: with its link when it found no label, alone under a label still waiting for a level", async () => {
  const GAPS = "Not checked for a sensitivity label: 2 documents past the 2,000 it looks at and 1 document it could not read.";
  const unchecked = { unreadable: 1, capped: { overFiles: 2, overBytes: 0 }, limits: { maxFiles: 2_000, totalMaxBytes: 32 * 1024 * 1024 } };
  const none = labelSettingsVM(null, undefined, { labels: { unmapped: [], unmappedMore: 0, files: 0, ...unchecked }, at: 1 });
  const a = load({ url: URL, routes: { ...FILES_ROUTES, "GET policy/sensitivity-labels": { labels: none }, "GET suggestions": { suggestions: [], count: 0, scan: null } } });
  await tick();
  const note = host(a.doc).querySelector(".labels-note");
  assert.equal(note.textContent, `The last scan found no sensitivity label on the documents it checked. ${GAPS} To look in another folder, open Keys Mandu found in Rules.`);
  const links = [...note.querySelectorAll("a")] as any[];
  assert.deepEqual(links.map((x) => [x.textContent, x.getAttribute("href")]), [["Keys Mandu found", "/mandu/rules#keys-found"]], "the one link, as before");
  links[0].click();
  await tick();
  assert.equal(a.window.location.pathname, "/mandu/rules");
  assert.equal(a.doc.getElementById("files-suggested-view").hidden, false, "Keys Mandu found is open, where Scan for keys is");
  // A label waiting for a level: the sentence closes the list, after its row, with no link.
  const waiting = labelSettingsVM(null, undefined, { labels: { unmapped: [{ id: OTHER, site: null, files: 2 }], unmappedMore: 0, files: 2, ...unchecked }, at: 1 });
  const b = load({ url: URL, routes: { "GET policy/sensitivity-labels": { labels: waiting } } });
  await tick();
  const kids = [...host(b.doc).children] as any[];
  assert.deepEqual(kids.map((k) => (k.classList.contains("labels-note") ? "note" : k.dataset.id)), [OTHER, "note"], "the row, then the note");
  assert.equal(kids[1].textContent, GAPS);
  assert.equal(kids[1].querySelector("a"), null);
});

test("an unreadable listing says so", async () => {
  const { doc } = load({ url: URL, routes: { "GET policy/sensitivity-labels": { status: 403, body: { error: "Sign in to the dashboard first." } } } });
  await tick();
  assert.match(host(doc).textContent, /Sign in to the dashboard first\./);
});

function labelWire(level: string): SuggestionWire {
  return {
    id: "pp-000009", kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: "sensitivity-label:/home/u/proj/q3.docx",
    source: "sensitivity-label", repoRoot: "/home/u/proj",
    edits: [{ op: "lock-path", path: "/home/u/proj/q3.docx", level }],
    sentence: "Make ~/proj/q3.docx a secret any AI may read when it asks: its sensitivity label is General",
    evidence: { paths: ["q3.docx"], blobs: [], findings: [], historyOnly: false, label: { id: GEN, site: null, name: "General", level } },
    impact: { historicalVersions: 0, workingTreeChanges: true, files: ["q3.docx"] },
    historyOnly: false, rotate: false, humanOnly: level !== "no-model", applicable: true, createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
  };
}

test("Suggested: a document's sensitivity label is an ordinary row at its mapped level, from the document's sensitivity label, with no rotation advice", async () => {
  const listing = { suggestions: suggestionRows([labelWire("any-model")], "/home/u"), count: 1, scan: null };
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET suggestions": listing } });
  await tick();
  doc.getElementById("suggest-open").click();
  await tick();
  const row = doc.querySelector("#files-suggested-list .row.suggested[data-id='pp-000009']") as any;
  assert.ok(row);
  assert.equal(row.classList.contains("history-only"), false);
  assert.equal(row.querySelector(".label-chip").textContent, "Any AI, when it asks", "the mapped level, as its chip");
  assert.equal(row.querySelector("input.file-tick").checked, true, "ticked: a change waiting");
  assert.match(row.textContent, /Will be: Any AI, when it asks \(not saved\)/);
  assert.match(doc.getElementById("files-pending-list").textContent, /~\/proj\/q3\.docx Any AI, when it asks, from the document's sensitivity label\./);
  row.click();
  await tick();
  const detail = doc.querySelector("#files-suggested-list .file-detail") as any;
  assert.match(detail.textContent, /From the document's sensitivity label/);
  assert.match(detail.textContent, /Sensitivity labelGeneral/);
  assert.doesNotMatch(detail.textContent, /rotate|exposed/i, "a label is not a key");
});

test("a Save refused because the label's level changed meanwhile says so on the row, keeps the level picked, reads the list again and saves against the mapping as it is now", async () => {
  const V2 = "d".repeat(32);
  const words = labelStaleWords("Highly Confidential", "map");
  const posts: any[] = [];
  let reads = 0;
  // The second read finds HC changed by someone else (a new level, a new version).
  const now = labelSettingsVM(
    { sensitivity_labels: [{ id: HC, name: "Highly Confidential", level: "local-model" }] }, null,
    { labels: { unmapped: [{ id: OTHER, site: null, files: 7 }], unmappedMore: 0 }, at: 1 },
    { itemVersions: { "sensitivity-labels": { [`${HC}|`]: V2 } }, absentVersion: ABSENT },
  );
  const { doc } = load({ url: URL, routes: {
    "GET policy/sensitivity-labels": () => (++reads === 1 ? { labels: VM } : { labels: now }),
    "POST policy/sensitivity-labels/change": (b: any) => {
      posts.push(b);
      return posts.length === 1
        ? { status: 409, body: { error: words, stale: true, changed: [`sensitivity-labels ${HC}|`] } }
        : { applied: true, changeId: "pc-9", note: "Mandu's next scan suggests with this." };
    },
  } });
  await tick();
  rowOf(doc, HC).querySelector("select.label-level").value = "any-model";
  rowOf(doc, HC).querySelector(".label-save-btn").click();
  await tick();
  assert.equal(posts[0].version, V_HC, "the Save names the mapping as the row was read");
  assert.equal(reads, 2, "the list is read again");
  const row = rowOf(doc, HC);
  assert.equal(row.querySelector(".name").textContent, "Highly Confidential", "the row as it is now");
  assert.equal(row.querySelector("select.label-level").value, "any-model", "the level picked is kept");
  assert.equal(row.querySelector(".ask-error").textContent, words, "said on the row, in the page's words");
  assert.equal(doc.getElementById("labels-notice").hidden, true, "nothing reads as saved");

  row.querySelector(".label-save-btn").click();
  await tick();
  assert.equal(posts[1].version, V2, "the next Save names the mapping as it is now");
  assert.equal(posts[1].level, "any-model");
  assert.match(doc.getElementById("labels-notice").textContent, /^Saved Highly Confidential\./);
});

test("a label given a level somewhere else while its name was typed: the refusal keeps the name and the level on its row, now a mapping", async () => {
  const words = labelStaleWords("Customer Data", "map");
  let reads = 0;
  const now = labelSettingsVM(
    { sensitivity_labels: [{ id: HC, name: "Highly Confidential", level: "no-model" }] }, null,
    { labels: { unmapped: [{ id: OTHER, site: null, files: 7 }], unmappedMore: 0 }, at: 1 },
    { itemVersions: { "sensitivity-labels": { [`${HC}|`]: V_HC } }, absentVersion: ABSENT },
  );
  const { doc } = load({ url: URL, routes: {
    "GET policy/sensitivity-labels": () => (++reads === 1 ? { labels: VM } : { labels: now }),
    "POST policy/sensitivity-labels/change": { status: 409, body: { error: words, stale: true, changed: [`sensitivity-labels ${OTHER}|`] } },
  } });
  await tick();
  const open = rowOf(doc, OTHER);
  open.querySelector("input.label-name").value = "Customer Data";
  open.querySelector("select.label-level").value = "local-model";
  open.querySelector(".label-save-btn").click();
  await tick();
  const again = rowOf(doc, OTHER);
  assert.equal(again.querySelector("input.label-name").value, "Customer Data", "what was typed is kept");
  assert.equal(again.querySelector("select.label-level").value, "local-model");
  assert.equal(again.querySelector(".ask-error").textContent, words);
});

test("a mapping removed somewhere else meanwhile: after the refusal the list says it is no longer there", async () => {
  const words = labelStaleWords("Highly <b>Confidential</b>", "unmap");
  let reads = 0;
  const gone = labelSettingsVM(null, null, null, { itemVersions: {}, absentVersion: ABSENT });
  const page = load({ url: URL, routes: {
    "GET policy/sensitivity-labels": () => (++reads === 1 ? { labels: VM } : { labels: gone }),
    "POST policy/sensitivity-labels/change": { status: 409, body: { error: words, stale: true, changed: [`sensitivity-labels ${HC}|`] } },
  } });
  page.window.confirm = () => true;
  await tick();
  rowOf(page.doc, HC).querySelector(".label-remove-btn").click();
  await tick();
  assert.equal(rowOf(page.doc, HC), undefined);
  assert.equal(page.doc.getElementById("labels-notice").textContent, `${words} It is no longer in the list.`);
});
