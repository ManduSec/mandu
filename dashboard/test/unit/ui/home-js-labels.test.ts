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
 * against the mapping as it is now (dashboard.md §4.25s); on a label that
 * has a level, Save waits for a change: greyed (and sending nothing) while
 * the picker shows the level saved, lit with "Not saved: press Save to use
 * …" under the row once it differs (§4.25s *Save waits for a change*);
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
/** A level picked as a person does: the value, then its `change`. */
const pickLevel = (row: any, level: string) => {
  const pick = row.querySelector("select.label-level");
  pick.value = level;
  pick.dispatchEvent(new pick.ownerDocument.defaultView.Event("change", { bubbles: true }));
};
const unsaved = (row: any) => row.querySelector(".label-unsaved")?.textContent ?? null;
const greyed = (row: any) => row.querySelector(".label-save-btn").getAttribute("aria-disabled") === "true";

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

test("Save waits for a change: greyed at the level saved and sending nothing, lit with 'Not saved' once another level is picked, greyed again when the saved one is picked back", async () => {
  const posts: any[] = [];
  const { doc } = load({ url: URL, routes: {
    "GET policy/sensitivity-labels": { labels: VM },
    "POST policy/sensitivity-labels/change": (b: any) => (posts.push(b), { applied: true, changeId: "pc-7", note: "" }),
  } });
  await tick();
  const row = rowOf(doc, HC);
  const save = row.querySelector(".label-save-btn");
  assert.equal(greyed(row), true, "a mapped row opens with Save greyed");
  assert.equal(save.disabled, false, "greyed, not disabled: it keeps the focus it is given back");
  assert.equal(unsaved(row), null, "no 'Not saved' line");
  save.click();
  await tick();
  assert.deepEqual(posts, [], "a Save at the level saved sends nothing");
  assert.equal(doc.getElementById("labels-notice").hidden, true, "nothing reads as saved");

  pickLevel(row, "any-model");
  assert.equal(greyed(row), false, "another level lights Save");
  assert.equal(unsaved(row), "Not saved: press Save to use Any AI, when it asks.", "in the picker's words");
  assert.equal(row.querySelector(".label-unsaved").previousElementSibling, row.querySelector(".model-actions"), "under the row's controls");
  pickLevel(row, "local-model");
  assert.equal(unsaved(row), "Not saved: press Save to use Your own AI only.", "follows the pick");
  assert.equal(row.querySelectorAll(".label-unsaved").length, 1, "one line");

  pickLevel(row, "no-model");
  assert.equal(greyed(row), true, "the saved level picked back greys it again");
  assert.equal(unsaved(row), null, "and the line goes");

  pickLevel(row, "any-model");
  save.click();
  await tick();
  assert.deepEqual(posts, [{ action: "map", id: HC, name: "Highly <b>Confidential</b>", level: "any-model", version: V_HC }], "the same change as before");

  const open = rowOf(doc, OTHER);
  assert.equal(open.querySelector(".label-save-btn").hasAttribute("aria-disabled"), false, "a label with no level yet: Save is always on");
  assert.equal(unsaved(open), null);
  assert.equal(rowOf(doc, GEN).querySelector("button"), null, "your administrator's: no Save");
});

test("Remove asks first, under the row, when the server says it lowers what Mandu suggests, then sends what was shown; a refusal is said on the row", async () => {
  const posts: any[] = [];
  const page = load({ url: URL, routes: {
    "GET policy/sensitivity-labels": { labels: VM },
    "POST policy/sensitivity-labels/change": (b: any) => {
      posts.push(b);
      return b.expected
        ? { status: 409, body: { error: "Your sensitivity labels changed while you were deciding. Nothing was changed. Try again." } }
        : { applied: false, confirm: true, expected: ["k"], rows: [[{ kind: "text", text: "Stop suggesting a label for documents with the sensitivity label " }, { kind: "code", text: HC }]], wouldLet: [[{ kind: "text", text: "Mandu would suggest less" }]], warnings: [] };
    },
  } });
  await tick();
  rowOf(page.doc, HC).querySelector(".label-remove-btn").click();
  await tick();
  // The question's words, read from the box under the row (until
  // 2026-10-26 from window.confirm, which now fails the test).
  const box = rowOf(page.doc, HC).nextElementSibling;
  assert.ok(box.classList.contains("ask-in-place"), "asked under the row");
  assert.match(box.querySelector(".ask-in-place-words").textContent, /^Stop suggesting a label for documents with the sensitivity label 9fbde396.*\.$/);
  assert.equal(box.querySelector(".ask-in-place-words code").textContent, HC);
  assert.deepEqual([...box.querySelectorAll(".ask-in-place-list li")].map((li: any) => li.textContent), ["Mandu would suggest less"]);
  assert.deepEqual([...box.querySelectorAll("button")].map((b: any) => b.textContent), ["Remove anyway", "Cancel"]);
  assert.deepEqual(posts, [{ action: "unmap", id: HC, version: V_HC }], "nothing more until Remove anyway");
  box.querySelector(".ask-in-place-yes").click();
  await tick();
  assert.deepEqual(posts, [{ action: "unmap", id: HC, version: V_HC }, { action: "unmap", id: HC, version: V_HC, expected: ["k"] }]);
  assert.equal(page.doc.querySelector("#settings-labels .ask-in-place"), null, "the question goes");
  assert.match(rowOf(page.doc, HC).textContent, /changed while you were deciding/);
});

test("a question asked under a row stays through a redraw of the list, with the level picked; Cancel keeps the row as you left it (dashboard.md §4.25n)", async () => {
  const posts: any[] = [];
  const page = load({ url: URL, routes: {
    "GET policy/sensitivity-labels": { labels: VM },
    "POST policy/sensitivity-labels/change": (b: any) => {
      posts.push(b);
      return b.id === HC && !b.expected
        ? { applied: false, confirm: true, expected: ["k"], rows: [[{ kind: "text", text: "Suggest " }, { kind: "code", text: HC }, { kind: "text", text: " at Any AI" }]], wouldLet: [], warnings: [[{ kind: "text", text: "Mandu would suggest less" }]] }
        : { applied: true, changeId: "pc-2", note: "" };
    },
  } });
  await tick();
  const pick = rowOf(page.doc, HC).querySelector("select.label-level");
  pick.value = "any-model";
  rowOf(page.doc, HC).querySelector(".label-save-btn").click();
  await tick();
  let box = rowOf(page.doc, HC).nextElementSibling;
  assert.deepEqual([...box.querySelectorAll("button")].map((b: any) => b.textContent), ["Save anyway", "Cancel"]);
  assert.equal(box.querySelector(".proposal-warn").textContent, "Warning: Mandu would suggest less");
  // Another row's change reads the list again: the question is drawn again.
  rowOf(page.doc, OTHER).querySelector(".label-save-btn").click();
  await tick();
  box = rowOf(page.doc, HC).nextElementSibling;
  assert.ok(box && box.classList.contains("ask-in-place"), "still asked under its row");
  assert.equal(rowOf(page.doc, HC).querySelector("select.label-level").value, "any-model", "the level asked about, not the one in force");
  assert.equal(greyed(rowOf(page.doc, HC)), false, "Save stays lit on the row drawn again");
  assert.equal(unsaved(rowOf(page.doc, HC)), "Not saved: press Save to use Any AI, when it asks.");
  [...box.querySelectorAll("button")].find((b: any) => b.textContent === "Cancel").click();
  await tick();
  assert.equal(host(page.doc).querySelector(".ask-in-place"), null);
  assert.equal(rowOf(page.doc, HC).querySelector("select.label-level").value, "any-model", "Cancel keeps the row as you left it");
  assert.deepEqual(posts.map((b) => [b.id, b.expected ?? null]), [[HC, null], [OTHER, null]], "nothing sent by Cancel");
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
  assert.equal(greyed(row), false, "Save stays lit: the level picked differs from the level read");
  assert.equal(unsaved(row), "Not saved: press Save to use Any AI, when it asks.");
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
  await tick();
  rowOf(page.doc, HC).querySelector(".label-remove-btn").click();
  await tick();
  assert.equal(rowOf(page.doc, HC), undefined);
  assert.equal(page.doc.getElementById("labels-notice").textContent, `${words} It is no longer in the list.`);
});
