/**
 * sensitivity-labels-view-model.test — plan 14 §14.1 in the dashboard
 * (dashboard.md §4.25r, §4.25s): the Suggested view's row for a document's
 * sensitivity label, the scan summary's label sentence, Settings ›
 * Sensitivity labels (the listing and the planned edit), and the words the
 * History and the confirm question give the two new edit ops.
 *
 * Pins: a label row is an ordinary file row from the document's
 * sensitivity label, at the level its MAPPING gives (its dot, its words),
 * naming the mapping's name and no rotation advice; the summary says how
 * many files carry a label with no level and where to set one (a link part
 * naming Settings › Sensitivity labels), counts encrypted documents, and
 * names the documents the label read's own caps left unchecked or it could
 * not read (until 2026-10-08, left out);
 * its file counts take in the documents the label read opened, and those
 * it left closed because a rule covers them; the settings listing puts the person's mappings,
 * then the administrator's (read only), then the labels the last scan found
 * that no mapping names now (a label mapped since drops out; a site-only
 * mapping does not map another tenant's label); the note under it links
 * Keys Mandu found before any scan (a link part naming the place), says a
 * scan found no label when it found none, and says every label found has a
 * level only when it found some; after a scan it ends with what the label
 * read left unchecked, in the scan line's words (until 2026-10-08, left
 * out: "found no sensitivity label on your documents" over documents it
 * never checked); the form's plan normalizes
 * GUIDs and refuses what the validator would; every string passes the
 * product vocabulary sweep.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  LABEL_BY, LABEL_IMPACT, LABEL_NOTE, labelGapWords, labelScanParts, labelScanWords, scanSummary, scanSummaryParts, suggestionRows,
  type LabelScanWire, type ScanSummaryPart, type SuggestionWire, type SuggestPolicyWire,
} from "../../../src/view-model/suggestions.js";
import { ALL_MAPPED_NOTE, NO_LABELS_NOTE, NO_SCAN_NOTE, labelItemKey, labelSettingsVM, labelStaleWords, normalizeGuid, planLabelChange } from "../../../src/view-model/sensitivity-labels.js";
import { editRow, labelLevelWords, relaxLine } from "../../../src/view-model/policy-proposals.js";

const HOME = "/home/u";
const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const GEN = "1e4f0000-0000-4000-8000-000000000001";
const OTHER = "2a2a0000-0000-4000-8000-000000000002";
const TENANT = "5b3c0000-0000-4000-8000-000000000003";
const TENANT2 = "6c6c0000-0000-4000-8000-000000000004";

function labelSuggestion(level: string, over: Partial<SuggestionWire> = {}): SuggestionWire {
  return {
    id: "pp-000009", kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: "sensitivity-label:/home/u/proj/q3-board.docx",
    source: "sensitivity-label", repoRoot: "/home/u/proj",
    edits: [{ op: "lock-path", path: "/home/u/proj/q3-board.docx", level }],
    sentence: "Make ~/proj/q3-board.docx a secret no AI may read: its sensitivity label is Highly Confidential",
    evidence: { paths: ["q3-board.docx"], blobs: [], findings: [], historyOnly: false, label: { id: HC, site: TENANT, name: "Highly Confidential", level } },
    impact: { historicalVersions: 0, workingTreeChanges: true, files: ["q3-board.docx"] },
    historyOnly: false, rotate: false, humanOnly: level !== "no-model", applicable: true,
    createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
    ...over,
  };
}

test("macOS: a sensitivity-label row reads as on Linux (a label locks the file, which a macOS launch makes unreadable; no history caveat, no rotation)", () => {
  const [mac] = suggestionRows([labelSuggestion("no-model")], HOME, "darwin");
  const [linux] = suggestionRows([labelSuggestion("no-model")], HOME, "linux");
  assert.equal(mac!.impact, LABEL_IMPACT);
  assert.deepEqual({ ...mac }, { ...linux });
  assert.doesNotMatch(JSON.stringify(mac), /macOS|on Linux|committed versions/);
  assert.equal(mac!.rotate, null);
});

test("a sensitivity-label row: an ordinary file row from the document's label, at its mapped level, with the mapping's name and no rotation advice", () => {
  const [row] = suggestionRows([labelSuggestion("no-model")], HOME);
  assert.ok(row);
  assert.equal(row.source, "sensitivity-label");
  assert.equal(row.kind, "path");
  assert.equal(row.level, "no-model");
  assert.equal(row.path, "/home/u/proj/q3-board.docx");
  assert.equal(row.display, "~/proj/q3-board.docx");
  assert.equal(row.name, "q3-board.docx");
  assert.equal(row.tag, null);
  assert.equal(row.historyOnly, false);
  assert.equal(row.by, LABEL_BY);
  assert.equal(row.by, "From the document's sensitivity label");
  assert.deepEqual(row.found, [{ words: "Sensitivity label", mask: "Highly Confidential" }]);
  assert.deepEqual(row.label, { name: "Highly Confidential", level: "no-model", admin: false });
  assert.deepEqual(row.when, []);
  assert.equal(row.rotate, null, "a label is not a key");
  assert.equal(row.rotateSoft, false);
  // Plan 14 §14.1 (closed in 4c): a label lowered or removed in Office later
  // does not lower the rule Save writes, and the row says so.
  assert.equal(row.note, LABEL_NOTE);
  assert.equal(row.impact, LABEL_IMPACT);
  assert.match(row.yaml, /^paths:\n {2}- path: \/home\/u\/proj\/q3-board\.docx\n {4}level: no-model$/);
  // A lower mapped level: its dot, and the administrator's mapping flagged.
  const [low] = suggestionRows([labelSuggestion("any-model", { evidence: { ...labelSuggestion("any-model").evidence, label: { id: HC, site: null, name: "General", level: "any-model", adminFile: "/etc/mandu/policy.d/labels.yaml" } } })], HOME);
  assert.equal(low!.level, "any-model");
  assert.equal(low!.applicable, true, "Save applies it on the admin channel");
  assert.deepEqual(low!.label, { name: "General", level: "any-model", admin: true });
  // The other sources keep their level.
  const [key] = suggestionRows([labelSuggestion("no-model", { source: "workspace", evidence: { paths: ["a"], blobs: [], findings: [], historyOnly: false } })], HOME);
  assert.equal(key!.source, "workspace");
  assert.equal(key!.level, "no-model");
  assert.equal(key!.label, null);
});

const LABELS: LabelScanWire = {
  mode: "count", examined: 14, read: 14, cached: 0, covered: 1, files: 13, mapped: 1, unmappedFiles: 12,
  unmapped: [{ id: GEN, site: TENANT, files: 9 }, { id: OTHER, site: null, files: 3 }], unmappedMore: 0, encrypted: 2, unreadable: 1,
};

test("the scan summary says how many files carry a label with no level, and where to set one; encrypted documents are counted", () => {
  assert.equal(labelScanWords(null), null);
  assert.equal(labelScanWords({ ...LABELS, mode: "off" }), null, "no Office file was opened");
  assert.equal(labelScanWords({ ...LABELS, unmappedFiles: 0, encrypted: 0, unreadable: 0 }), null);
  // LABELS has one document it could not read: since 2026-10-08 the line
  // says so (labelGapWords), after the encrypted ones.
  assert.equal(
    labelScanWords(LABELS),
    "12 files carry a sensitivity label you have not chosen a level for: set it in Settings › Sensitivity labels. 2 encrypted documents were not read, so their sensitivity label is not known. " +
      "Not checked for a sensitivity label: 1 document it could not read.",
  );
  assert.equal(labelScanWords({ ...LABELS, unmappedFiles: 1, encrypted: 1, unreadable: 0 }),
    "1 file carries a sensitivity label you have not chosen a level for: set it in Settings › Sensitivity labels. 1 encrypted document was not read, so its sensitivity label is not known.");
  const r: SuggestPolicyWire = {
    axis: true, running: false, suggestions: [], filed: [], covered: [],
    counts: { findings: 0, suggested: 0, filed: 0, alreadyPending: 0, dismissed: 0, overCap: 0, covered: 0, dropped: 0, superseded: 0 },
    scan: null,
    workspaceScan: {
      roots: [{ root: "/home/u/proj", tier: "workspace" }], counts: { examined: 3, read: 3, cached: 0, bytes: 10, covered: 0 },
      capped: { tooBig: 0, overTotal: 0, overTime: 0, overFiles: 0, binary: 0, symlinks: 0, unreadable: 0, depth: 0 },
      limits: { fileMaxBytes: 262144, totalMaxBytes: 67108864, maxFiles: 20000, timeoutMs: 30000 }, ms: 1, labels: LABELS,
    },
  };
  // 3 files read as text and the 14 documents whose labels it read; the one
  // document a rule covers was not opened (until 2026-10-08 both counts
  // left the documents out).
  assert.equal(scanSummary(r, HOME),
    "Scanned 17 files in ~/proj. Nothing new to review. 1 file your rules already protect was not opened. " +
    "12 files carry a sensitivity label you have not chosen a level for: set it in Settings › Sensitivity labels. " +
    "2 encrypted documents were not read, so their sensitivity label is not known. " +
    "Not checked for a sensitivity label: 1 document it could not read.");
});

/** A scan of ~/docs that read no file as text, with this label read. */
function docsScan(labels: LabelScanWire | null, counts: Partial<{ read: number; cached: number; covered: number }> = {}): SuggestPolicyWire {
  return {
    axis: true, running: false, suggestions: [], filed: [], covered: [],
    counts: { findings: 0, suggested: 0, filed: 0, alreadyPending: 0, dismissed: 0, overCap: 0, covered: 0, dropped: 0, superseded: 0 },
    scan: null,
    workspaceScan: {
      roots: [{ root: "/home/u/docs", tier: "workspace" }], counts: { examined: 0, read: 0, cached: 0, bytes: 0, covered: 0, ...counts },
      capped: { tooBig: 0, overTotal: 0, overTime: 0, overFiles: 0, binary: 0, symlinks: 0, unreadable: 0, depth: 0 },
      limits: { fileMaxBytes: 262144, totalMaxBytes: 67108864, maxFiles: 20000, timeoutMs: 30000 }, ms: 1, labels,
    },
  };
}
const ONE_DOC: LabelScanWire = {
  mode: "count", examined: 1, read: 1, cached: 0, covered: 0, files: 1, mapped: 0, unmappedFiles: 1,
  unmapped: [{ id: OTHER, site: TENANT, files: 1 }], unmappedMore: 0, encrypted: 0, unreadable: 0,
};
const LABELS_LINK: ScanSummaryPart = { kind: "link", text: "Settings › Sensitivity labels", to: "labels" };
const links = (parts: readonly ScanSummaryPart[] | null) => (parts ?? []).filter((p) => p.kind === "link");
const joined = (parts: readonly ScanSummaryPart[]) => parts.map((p) => p.text).join("");

test("the scan line counts the documents whose labels it read: never \"Scanned 0 files\" beside \"1 file carries a sensitivity label\"", () => {
  assert.equal(scanSummary(docsScan(ONE_DOC), HOME),
    "Scanned 1 file in ~/docs. Nothing new to review. 1 file carries a sensitivity label you have not chosen a level for: set it in Settings › Sensitivity labels.");
  // A document the cache already knew counts as one checked, like a text file.
  assert.match(scanSummary(docsScan({ ...ONE_DOC, read: 0, cached: 1 }), HOME), /^Scanned 1 file in ~\/docs\. /);
  // Text files and documents add up; a document a rule covers is not opened
  // and is said with the text files a rule covers.
  assert.match(scanSummary(docsScan({ ...ONE_DOC, read: 2, cached: 1, covered: 2 }, { read: 4, cached: 1, covered: 1 }), HOME),
    /^Scanned 8 files in ~\/docs\. Nothing new to review\. 3 files your rules already protect were not opened\. /);
  // No label read (off, or an older arbiter): the text files only, as before.
  assert.equal(scanSummary(docsScan({ ...ONE_DOC, mode: "off", read: 5, covered: 5 }, { read: 2 }), HOME), "Scanned 2 files in ~/docs. Nothing new to review.");
  assert.equal(scanSummary(docsScan(null, { read: 2 }), HOME), "Scanned 2 files in ~/docs. Nothing new to review.");
});

test("the scan line links Settings › Sensitivity labels where it says to set a level: one link part naming the place, never an address", () => {
  const parts = scanSummaryParts(docsScan(ONE_DOC), HOME);
  assert.deepEqual(links(parts), [LABELS_LINK]);
  assert.equal(joined(parts), scanSummary(docsScan(ONE_DOC), HOME), "summary is the parts joined");
  assert.deepEqual(parts.at(-1), { kind: "text", text: "." }, "the sentence ends after the link");
  assert.ok(parts.every((p, i) => i === 0 || !(p.kind === "text" && parts[i - 1]!.kind === "text")), "neighbouring text is one part");
  // The full summary with every other sentence keeps one link, in place.
  const full = scanSummaryParts({ ...docsScan(LABELS), workspaceScan: { ...docsScan(LABELS).workspaceScan!, counts: { examined: 3, read: 3, cached: 0, bytes: 10, covered: 0 } } }, HOME);
  assert.deepEqual(links(full), [LABELS_LINK]);
  assert.match(joined(full), /set it in Settings › Sensitivity labels\. 2 encrypted documents were not read/);
  // Nothing to set: no link. Only encrypted documents, or every label mapped.
  assert.deepEqual(links(labelScanParts({ ...LABELS, unmappedFiles: 0 })), []);
  assert.equal(labelScanWords({ ...LABELS, unmappedFiles: 0, unreadable: 0 }), "2 encrypted documents were not read, so their sensitivity label is not known.");
  assert.deepEqual(links(labelScanParts({ ...LABELS, unmappedFiles: 0, encrypted: 0 })), [], "nor with only a document it could not read");
  assert.equal(labelScanParts({ ...LABELS, unmappedFiles: 0, encrypted: 0, unreadable: 0 }), null);
  assert.equal(labelScanParts(null), null);
  assert.deepEqual(links(scanSummaryParts(docsScan({ ...ONE_DOC, unmappedFiles: 0, mapped: 1 }), HOME)), []);
  // Protection off, or no history and no files: text only.
  assert.deepEqual(scanSummaryParts({ ...docsScan(ONE_DOC), axis: false }, HOME),
    [{ kind: "text", text: "Protection is off, so nothing was scanned. Turn it on in Settings to scan." }]);
});

test("the scan line says which documents the label read left unchecked: its own caps and the documents it could not read, never silence beside \"1 file carries a sensitivity label\"", () => {
  const LIMITS = { maxFiles: 2_000, totalMaxBytes: 32 * 1024 * 1024 };
  const gaps = (capped: { overFiles: number; overBytes: number } | undefined, unreadable = 0, limits: LabelScanWire["limits"] | null = LIMITS) =>
    labelGapWords({ ...ONE_DOC, unreadable, ...(capped ? { capped } : {}), ...(limits ? { limits } : {}) });
  // Nothing left unchecked: nothing to say (an older answer has no capped).
  assert.equal(gaps({ overFiles: 0, overBytes: 0 }), null);
  assert.equal(gaps(undefined), null);
  assert.equal(labelScanWords(ONE_DOC)!.includes("Not checked"), false);
  // Each gap alone, singular and plural, with the label read's own limits.
  assert.equal(gaps({ overFiles: 1, overBytes: 0 }), "Not checked for a sensitivity label: 1 document past the 2,000 it looks at.");
  assert.equal(gaps({ overFiles: 340, overBytes: 0 }), "Not checked for a sensitivity label: 340 documents past the 2,000 it looks at.");
  assert.equal(gaps({ overFiles: 0, overBytes: 3 }), "Not checked for a sensitivity label: 3 documents past the 32 MB it reads in all.");
  assert.equal(gaps({ overFiles: 0, overBytes: 0 }, 1), "Not checked for a sensitivity label: 1 document it could not read.");
  assert.equal(gaps(undefined, 2), "Not checked for a sensitivity label: 2 documents it could not read.");
  // Together, in the terminal's order.
  assert.equal(gaps({ overFiles: 2, overBytes: 1 }, 1),
    "Not checked for a sensitivity label: 2 documents past the 2,000 it looks at, 1 document past the 32 MB it reads in all and 1 document it could not read.");
  // No limits (an older answer): the cap without a number, never a wrong one.
  assert.equal(gaps({ overFiles: 2, overBytes: 1 }, 0, null),
    "Not checked for a sensitivity label: 2 documents past its file limit and 1 document past its size limit.");
  // On the line: after the label and encrypted sentences, after the text
  // read's own "Not checked:", and no new link.
  const doc: LabelScanWire = { ...ONE_DOC, encrypted: 1, unreadable: 1, capped: { overFiles: 2, overBytes: 0 }, limits: LIMITS };
  const r = docsScan(doc, { read: 1 });
  r.workspaceScan!.capped.tooBig = 1;
  const parts = scanSummaryParts(r, HOME);
  assert.equal(joined(parts),
    "Scanned 2 files in ~/docs. Nothing new to review. Not checked: 1 file over 256 KB. There may be more keys in those. " +
    "1 file carries a sensitivity label you have not chosen a level for: set it in Settings › Sensitivity labels. " +
    "1 encrypted document was not read, so its sensitivity label is not known. " +
    "Not checked for a sensitivity label: 2 documents past the 2,000 it looks at and 1 document it could not read.");
  assert.deepEqual(links(parts), [LABELS_LINK]);
  // Only gaps: the sentence alone, no link (nothing to set).
  const only = labelScanParts({ ...ONE_DOC, files: 0, unmappedFiles: 0, unmapped: [], capped: { overFiles: 5, overBytes: 0 }, limits: LIMITS });
  assert.deepEqual(only, [{ kind: "text", text: "Not checked for a sensitivity label: 5 documents past the 2,000 it looks at." }]);
  // No label read (off): nothing, whatever the counts.
  assert.equal(labelScanParts({ ...doc, mode: "off" }), null);
});

test("Settings › Sensitivity labels: yours, then your administrator's (read only), then what the last scan found with no level", () => {
  assert.equal(labelSettingsVM(null, undefined, null).note, NO_SCAN_NOTE, "no scan yet");
  const inForce = { sensitivity_labels: [{ id: `{${HC.toUpperCase()}}`, name: "Highly Confidential", level: "no-model" }, { id: "not-a-guid", name: "x", level: "public" }] };
  const admin = { sensitivityLabels: [{ id: GEN, site: TENANT, name: "General", level: "any-model", file: "/etc/mandu/policy.d/labels.yaml" }] };
  const vm = labelSettingsVM(inForce, admin, {
    labels: { unmapped: [{ id: GEN, site: TENANT, files: 9 }, { id: GEN, site: TENANT2, files: 2 }, { id: OTHER, site: null, files: 1 }, { id: HC, site: null, files: 4 }], unmappedMore: 0 },
    at: 1000,
  });
  assert.deepEqual(vm.mappings, [
    { id: HC, site: null, name: "Highly Confidential", level: "no-model", levelWords: "No AI", admin: null, version: null },
    { id: GEN, site: TENANT, name: "General", level: "any-model", levelWords: "Any AI, when it asks", admin: "/etc/mandu/policy.d/labels.yaml", version: null },
  ], "the GUID normalized; an entry the validator would refuse is left out; no versions read, none carried");
  // HC was mapped since the scan (no site: every tenant); GEN in TENANT is
  // the administrator's; GEN in another tenant is still unmapped.
  assert.deepEqual(vm.unmapped, [
    { id: GEN, site: TENANT2, files: 2, filesWords: "2 files carry it", version: null },
    { id: OTHER, site: null, files: 1, filesWords: "1 file carries it", version: null },
  ]);
  // With the versions a read gave (policy-surface.md §8.4.6): each of your
  // mappings its own, by id and site as the arbiter keys it; a label with no
  // level yet the absent version; the administrator's none.
  const V = "a".repeat(32);
  const ABSENT = "0".repeat(32);
  const versioned = labelSettingsVM(inForce, admin, {
    labels: { unmapped: [{ id: GEN, site: TENANT2, files: 2 }], unmappedMore: 0 }, at: 1,
  }, { itemVersions: { "sensitivity-labels": { [labelItemKey(HC, null)]: V, "x|": "b".repeat(32) } }, absentVersion: ABSENT });
  assert.equal(labelItemKey(HC, null), `${HC}|`);
  assert.equal(labelItemKey(GEN, TENANT2), `${GEN}|${TENANT2}`);
  assert.deepEqual(versioned.mappings.map((m) => m.version), [V, null]);
  assert.deepEqual(versioned.unmapped.map((u) => u.version), [ABSENT]);
  assert.deepEqual(labelSettingsVM(inForce, admin, null, { itemVersions: { "sensitivity-labels": { [`${HC}|`]: "not-hex" } }, absentVersion: ABSENT }).mappings.map((m) => m.version), [null, null],
    "a version that is not one is none");
  assert.deepEqual(labelSettingsVM(inForce, admin, null, { itemVersions: {} }).mappings.map((m) => m.version), [null, null], "no absent version: an older service");
  assert.equal(vm.scannedAt, 1000);
  assert.equal(vm.note, null);
  assert.equal(vm.defaultLevel, "no-model");
  assert.deepEqual(vm.levels.map((l) => l.level), ["public", "any-model", "local-model", "no-model"]);
  assert.equal(labelSettingsVM(inForce, admin, { labels: { unmapped: [{ id: HC, site: null, files: 4 }], unmappedMore: 0 }, at: 1 }).note, ALL_MAPPED_NOTE);
});

test("Settings › Sensitivity labels' note: before a scan it links Keys Mandu found, where Scan for keys is; after a scan that found no label it says so, never that every label found has a level", () => {
  const link = { kind: "link", text: "Keys Mandu found", to: "suggested" };
  const before = labelSettingsVM(null, undefined, null);
  assert.deepEqual(before.noteParts, [
    { kind: "text", text: "Mandu lists here the sensitivity labels it finds on your documents. To look for them, open " },
    link,
    { kind: "text", text: " in Rules and press Scan for keys." },
  ], "the place is a link part, never an address");
  assert.equal(before.note, "Mandu lists here the sensitivity labels it finds on your documents. To look for them, open Keys Mandu found in Rules and press Scan for keys.");
  assert.equal(before.note, NO_SCAN_NOTE, "the note is the parts joined");
  assert.doesNotMatch(before.note!, /in Rules, Keys Mandu found,/, "no longer a trail of names to a button Rules hides until Review");

  // The scan found no document with a label: with or without mappings.
  const mine = { sensitivity_labels: [{ id: HC, name: "Highly Confidential", level: "no-model" }] };
  for (const inForce of [null, mine]) {
    const none = labelSettingsVM(inForce, undefined, { labels: { unmapped: [], unmappedMore: 0, files: 0 }, at: 5 });
    assert.equal(none.note, NO_LABELS_NOTE);
    assert.equal(none.note, "The last scan found no sensitivity label on your documents. To look in another folder, open Keys Mandu found in Rules.");
    assert.notEqual(none.note, ALL_MAPPED_NOTE, "it found no label to have a level");
    assert.deepEqual(none.noteParts!.filter((p) => p.kind === "link"), [link]);
    assert.equal(none.scannedAt, 5);
  }
  // It found labels, each with a level now: the old note, as text.
  const all = labelSettingsVM(mine, undefined, { labels: { unmapped: [{ id: HC, site: null, files: 4 }], unmappedMore: 0, files: 4 }, at: 1 });
  assert.equal(all.note, ALL_MAPPED_NOTE);
  assert.deepEqual(all.noteParts, [{ kind: "text", text: ALL_MAPPED_NOTE }]);
  // An older scan's answer without `files`: as before.
  assert.equal(labelSettingsVM(null, undefined, { labels: { unmapped: [], unmappedMore: 0 }, at: 1 }).note, ALL_MAPPED_NOTE);
  // Labels still to give a level: no note.
  for (const labels of [{ unmapped: [{ id: OTHER, site: null, files: 2 }], unmappedMore: 0, files: 2 }, { unmapped: [], unmappedMore: 3, files: 9 }]) {
    const vm = labelSettingsVM(null, undefined, { labels, at: 1 });
    assert.equal(vm.note, null);
    assert.equal(vm.noteParts, null);
  }
  // Each VM gets its own parts: a page that changed one cannot change the next.
  (labelSettingsVM(null, undefined, null).noteParts![0] as { text: string }).text = "changed";
  assert.equal(labelSettingsVM(null, undefined, null).note, NO_SCAN_NOTE);
  assert.equal(labelSettingsVM(null, undefined, null).noteParts![0]!.text.startsWith("Mandu lists here"), true);
});

test("Settings › Sensitivity labels' note says what the last scan's label read left unchecked, as Rules' scan line does: never \"found no sensitivity label on your documents\" over documents it never checked", () => {
  const link = { kind: "link", text: "Keys Mandu found", to: "suggested" };
  const LIMITS = { maxFiles: 2_000, totalMaxBytes: 32 * 1024 * 1024 };
  const GAPS = "Not checked for a sensitivity label: 2 documents past the 2,000 it looks at and 1 document it could not read.";
  const ENC = "1 encrypted document was not read, so its sensitivity label is not known.";
  const unchecked = { encrypted: 1, unreadable: 1, capped: { overFiles: 2, overBytes: 0 }, limits: LIMITS };
  const mine = { sensitivity_labels: [{ id: HC, name: "Highly Confidential", level: "no-model" }] };

  // Found no labelled document: "on the documents it checked", then which
  // it did not, in the scan line's words and order, then the link.
  const none = labelSettingsVM(null, undefined, { labels: { mode: "count", unmapped: [], unmappedMore: 0, files: 0, ...unchecked }, at: 5 });
  assert.equal(none.note,
    `The last scan found no sensitivity label on the documents it checked. ${ENC} ${GAPS} To look in another folder, open Keys Mandu found in Rules.`);
  assert.deepEqual(none.noteParts, [
    { kind: "text", text: `The last scan found no sensitivity label on the documents it checked. ${ENC} ${GAPS} To look in another folder, open ` },
    link,
    { kind: "text", text: " in Rules." },
  ], "the same one link part");
  assert.doesNotMatch(none.note!, /on your documents/, "never a claim about every document");
  // The same sentences as the scan line ends with (one source of words).
  const line = labelScanWords({ ...ONE_DOC, files: 0, unmappedFiles: 0, unmapped: [], ...unchecked })!;
  assert.equal(line, `${ENC} ${GAPS}`);
  assert.ok(none.note!.includes(line));
  // Each kind alone; no limits (an older answer) says the cap without a number.
  assert.equal(labelSettingsVM(null, undefined, { labels: { unmapped: [], unmappedMore: 0, files: 0, encrypted: 2 }, at: 1 }).note,
    "The last scan found no sensitivity label on the documents it checked. 2 encrypted documents were not read, so their sensitivity label is not known. To look in another folder, open Keys Mandu found in Rules.");
  assert.equal(labelSettingsVM(null, undefined, { labels: { unmapped: [], unmappedMore: 0, files: 0, capped: { overFiles: 0, overBytes: 4 } }, at: 1 }).note,
    "The last scan found no sensitivity label on the documents it checked. Not checked for a sensitivity label: 4 documents past its size limit. To look in another folder, open Keys Mandu found in Rules.");

  // Every label it found has a level: that, then what it left unchecked.
  const all = labelSettingsVM(mine, undefined, { labels: { mode: "mapped", unmapped: [{ id: HC, site: null, files: 4 }], unmappedMore: 0, files: 4, ...unchecked }, at: 1 });
  assert.equal(all.note, `${ALL_MAPPED_NOTE} ${ENC} ${GAPS}`);
  assert.deepEqual(all.noteParts, [{ kind: "text", text: `${ALL_MAPPED_NOTE} ${ENC} ${GAPS}` }], "text only, as before");

  // A label still waits for a level: the sentences alone, under its row.
  for (const labels of [{ unmapped: [{ id: OTHER, site: null, files: 2 }], unmappedMore: 0, files: 2 }, { unmapped: [], unmappedMore: 3, files: 9 }]) {
    const vm = labelSettingsVM(null, undefined, { labels: { ...labels, capped: { overFiles: 1, overBytes: 0 }, limits: LIMITS }, at: 1 });
    assert.equal(vm.note, "Not checked for a sensitivity label: 1 document past the 2,000 it looks at.");
    assert.deepEqual(vm.noteParts, [{ kind: "text", text: vm.note }]);
  }

  // Nothing left unchecked (zero counts, or an older answer without them):
  // the notes as before.
  const zero = { encrypted: 0, unreadable: 0, capped: { overFiles: 0, overBytes: 0 }, limits: LIMITS };
  assert.equal(labelSettingsVM(null, undefined, { labels: { unmapped: [], unmappedMore: 0, files: 0, ...zero }, at: 1 }).note, NO_LABELS_NOTE);
  assert.equal(labelSettingsVM(mine, undefined, { labels: { unmapped: [{ id: HC, site: null, files: 4 }], unmappedMore: 0, files: 4, ...zero }, at: 1 }).note, ALL_MAPPED_NOTE);
  assert.equal(labelSettingsVM(null, undefined, { labels: { unmapped: [{ id: OTHER, site: null, files: 2 }], unmappedMore: 0, files: 2, ...zero }, at: 1 }).note, null);
  // A label read that opened nothing (off): nothing to add, whatever the counts.
  assert.equal(labelSettingsVM(null, undefined, { labels: { mode: "off", unmapped: [], unmappedMore: 0, files: 0, ...unchecked }, at: 1 }).note, NO_LABELS_NOTE);
  // Before any scan: unchanged.
  assert.equal(labelSettingsVM(null, undefined, null).note, NO_SCAN_NOTE);
  // The constant parts are not changed by a note built from them.
  assert.equal(NO_LABELS_NOTE, "The last scan found no sensitivity label on your documents. To look in another folder, open Keys Mandu found in Rules.");
});

test("planLabelChange: map and unmap become the edit grammar, GUIDs normalized; what the validator refuses is refused first", () => {
  assert.equal(normalizeGuid(` {${HC.toUpperCase()}} `), HC);
  assert.equal(normalizeGuid("9fbde396"), null);
  assert.deepEqual(planLabelChange({ action: "map", id: `{${HC.toUpperCase()}}`, name: " Highly Confidential ", level: "no-model" }),
    { ok: true, edits: [{ op: "map-sensitivity-label", id: HC, name: "Highly Confidential", level: "no-model" }], key: `${HC}|`, name: "Highly Confidential" });
  assert.deepEqual(planLabelChange({ action: "map", id: HC, site: TENANT.toUpperCase(), name: "HC", level: "any-model" }),
    { ok: true, edits: [{ op: "map-sensitivity-label", id: HC, site: TENANT, name: "HC", level: "any-model" }], key: `${HC}|${TENANT}`, name: "HC" });
  assert.deepEqual(planLabelChange({ action: "unmap", id: HC, site: "" }), { ok: true, edits: [{ op: "unmap-sensitivity-label", id: HC }], key: `${HC}|`, name: null });
  for (const bad of [
    {}, { action: "rename", id: HC }, { action: "map", id: "x", name: "a", level: "no-model" }, { action: "map", id: HC, name: "", level: "no-model" },
    { action: "map", id: HC, name: "a".repeat(65), level: "no-model" }, { action: "map", id: HC, name: "a\nb", level: "no-model" },
    { action: "map", id: HC, name: "a", level: "secret" }, { action: "map", id: HC, site: "nope", name: "a", level: "no-model" }, { action: "unmap" },
  ]) {
    const p = planLabelChange(bad);
    assert.equal(p.ok, false, JSON.stringify(bad));
    if (!p.ok) assert.equal(p.status, 400);
  }
});

const words = (parts: Array<{ text: string }>): string => parts.map((p) => p.text).join("");

test("the History and the confirm question say the label edits in plain words", () => {
  assert.equal(words(editRow({ op: "map-sensitivity-label", id: HC, name: "Highly Confidential", level: "no-model" })),
    `Suggest No AI for documents with the sensitivity label Highly Confidential (${HC})`);
  assert.equal(words(editRow({ op: "map-sensitivity-label", id: HC, name: "General", level: "public" })),
    `Suggest nothing for documents with the sensitivity label General (${HC})`);
  assert.equal(words(editRow({ op: "unmap-sensitivity-label", id: HC })), `Stop suggesting a label for documents with the sensitivity label ${HC}`);
  assert.equal(words(relaxLine({ facet: "sensitivity-labels", subject: HC })), `Mandu would suggest less for documents with the sensitivity label ${HC}`);
  assert.equal(labelLevelWords("local-model"), "Your own AI only");
});

/** The home page's sweep (home-view-model.test.ts): no inspector term in product copy. */
const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter)\b|\$MDU:/i;

test("every new string uses the product vocabulary only", () => {
  const rows = suggestionRows([labelSuggestion("no-model"), labelSuggestion("local-model")], HOME);
  const vm = labelSettingsVM({ sensitivity_labels: [{ id: HC, name: "HC", level: "no-model" }] }, null, { labels: { unmapped: [{ id: OTHER, site: null, files: 2 }], unmappedMore: 3 }, at: 1 });
  const copy = [
    ...rows.flatMap((r) => [r.name, r.sentence, r.impact, r.by, ...r.found.map((f) => `${f.words} ${f.mask}`)]),
    labelScanWords(LABELS) ?? "", NO_SCAN_NOTE, NO_LABELS_NOTE, ALL_MAPPED_NOTE,
    ...[0, 4].map((files) => labelSettingsVM(null, null, { labels: { unmapped: [], unmappedMore: 0, files, encrypted: 1, unreadable: 1, capped: { overFiles: 2, overBytes: 1 } }, at: 1 }).note ?? ""),
    labelSettingsVM(null, null, { labels: { unmapped: [{ id: OTHER, site: null, files: 2 }], unmappedMore: 0, unreadable: 1 }, at: 1 }).note ?? "",
    labelGapWords({ ...LABELS, capped: { overFiles: 2, overBytes: 1 } }) ?? "", labelGapWords({ ...LABELS, capped: { overFiles: 2, overBytes: 1 }, limits: { maxFiles: 2_000, totalMaxBytes: 1 << 25 } }) ?? "",
    ...vm.mappings.map((m) => m.levelWords), ...vm.unmapped.map((u) => u.filesWords), ...vm.levels.map((l) => l.words),
    words(editRow({ op: "map-sensitivity-label", id: HC, name: "n", level: "any-model" })), words(editRow({ op: "unmap-sensitivity-label", id: HC })),
    words(relaxLine({ facet: "sensitivity-labels", subject: HC })),
    labelStaleWords("Highly Confidential", "map"), labelStaleWords("Highly Confidential", "unmap"),
    ...["map", "unmap"].flatMap((action) => [{}, { action, id: "x" }, { action, id: HC, name: "" }, { action, id: HC, name: "n" }, { action, id: HC, site: "x" }].map((b) => { const p = planLabelChange(b); return p.ok ? "" : p.error; })),
  ].join("\n");
  assert.doesNotMatch(copy, FORBIDDEN, copy);
});
