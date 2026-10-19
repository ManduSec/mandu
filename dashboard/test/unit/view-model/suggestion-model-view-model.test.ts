/**
 * suggestion-model-view-model.test — the Suggested view's model picker, its
 * preview and a run's outcome (dashboard.md §4.25t, confidentiality-plan-14
 * §14.5, §14.11; src/view-model/suggestion-model.ts), and the rows of a
 * model's suggestions and of a sensitivity label (view-model/suggestions.ts).
 *
 * Pins: the picker is Off by default and "not offered yet" without the
 * flag; Contents is disabled with the reason when no model of your own is
 * declared (or the list could not be read); the preview names, for Names
 * only, every line exactly as sent, and for Contents, the files and their
 * sizes, never their text, and where it goes; nothing to send says so; a
 * run's line in both tiers, still reading, failed; the service's refusals in
 * the page's words; a contents row says "Suggested by your model <name>",
 * the reason words, and that your own model read the start of the file; a
 * label row says a label lowered in Office later does not lower the rule;
 * every string passes the product vocabulary sweep.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  MODELS_UNKNOWN, NOT_OFFERED, NOT_OFFERED_LINE, NO_OWN_MODEL, destinationWhere, kbWords, modelErrorWords, modelPickerVM, modelPreviewVM, modelRunVM,
  type ModelPreviewWire, type ModelRunWire,
} from "../../../src/view-model/suggestion-model.js";
import { LABEL_NOTE, MODEL_CONTENTS_NOTE, suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";

const HOME = "/home/u";
const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter|classifier)\b|\$MDU:/i;
const TEXT_CANARY = "DOC-TEXT-CANARY-5e1";

const namesPreview = (over: Partial<ModelPreviewWire> = {}): ModelPreviewWire => ({
  axis: true, tier: "names", digest: "a".repeat(64),
  destination: { kind: "default", name: "Claude (claude -p)", location: "external", placement: "network", vendor: "Anthropic" },
  roots: [{ index: 1, root: `${HOME}/proj`, files: 12 }], items: 3, bytes: 240, requests: 1,
  names: ['d1 root 1 "clients/"', 'f1 root 1 "clients/contract.docx" size=under1KB ext=docx', 'f2 root 1 "README.md" size=under1KB ext=md'],
  files: [],
  left: { covered: 2, labelled: 1, tooLong: 0, personal: 1, overCap: 0, detector: 1, registered: 0, flagged: 0, unread: 0 },
  promptVersion: "names-1", confine: { live: true }, expiresAt: 9, walk: { examined: 16, covered: 2, capped: [] },
  ...over,
});
const contentsPreview = (over: Partial<ModelPreviewWire> = {}): ModelPreviewWire => ({
  ...namesPreview(), tier: "contents", digest: "b".repeat(64),
  destination: { kind: "declared", name: "ollama", location: "local", placement: "host", vendor: "127.0.0.1" },
  items: 2, bytes: 17_300, requests: 2, names: [],
  files: [{ root: 1, name: "docs/contract.md", bytes: 16_384, truncated: true }, { root: 1, name: "notes/meeting.txt", bytes: 916, truncated: false }],
  left: { covered: 1, labelled: 1, tooLong: 0, personal: 0, overCap: 3, detector: 0, registered: 0, flagged: 2, unread: 1 },
  promptVersion: "contents-1", confine: { live: false, note: "the classifier's network confine is unavailable: this install passed no mandu-landlock-apply" },
  ...over,
});
const run = (over: Partial<ModelRunWire> = {}): ModelRunWire => ({
  axis: true, running: false, digest: "b".repeat(64), destination: contentsPreview().destination,
  sent: { requests: 41, items: 41, bytes: 380_000 },
  counts: { rules: 41, kept: 3, dropped: 0, merged: 0, tooBroad: 0, covered: 0, filed: 3, alreadyPending: 1, dismissed: 0, overCap: 0, failedRequests: 0, public: 37 },
  filed: ["pp-000001", "pp-000002", "pp-000003"], error: null, ms: 900,
  ...over,
});

test("the picker: Off by default; not offered yet without the flag; Contents needs a model of your own", () => {
  const off = modelPickerVM(false, []);
  assert.equal(off.offered, false);
  assert.deepEqual(off.options.map((o) => [o.value, o.enabled, o.why]), [["off", true, null], ["names", false, NOT_OFFERED], ["contents", false, NOT_OFFERED]]);
  assert.match(off.hint, /not offered yet/);
  // One sentence (dashboard.md §4.25r *Every field has the page's look*):
  // until 2026-10-16 it read "Asking a model to suggest rules: not offered
  // yet: asking a model is still being tested."
  assert.equal(off.hint, NOT_OFFERED_LINE);
  assert.equal(off.hint, "Asking a model to suggest rules is not offered yet: it is still being tested.");
  const none = modelPickerVM(true, [{ name: "cloud", local: false }]);
  assert.deepEqual(none.options.map((o) => [o.value, o.enabled, o.why]), [["off", true, null], ["names", true, null], ["contents", false, NO_OWN_MODEL]]);
  assert.deepEqual(none.ownModels, []);
  const own = modelPickerVM(true, [{ name: "ollama", local: true, model: "qwen2.5:7b" }, { name: "cloud", local: false }]);
  assert.equal(own.options[2]!.enabled, true);
  assert.deepEqual(own.ownModels, ["ollama"]);
  assert.equal(modelPickerVM(true, null).options[2]!.why, MODELS_UNKNOWN);
  assert.deepEqual(own.options.map((o) => o.label), ["Off", "Names only", "Contents (your own model)"]);
});

test("the Names-only preview: every line as sent, the folder each root is, what was left out, where it goes", () => {
  const p = modelPreviewVM(namesPreview(), HOME);
  assert.equal(p.headline, "This sends 3 file and folder names from 1 folder to Claude (claude -p) (Anthropic, an outside model, outside this computer). No file's content is sent.");
  assert.deepEqual(p.list.map((i) => i.text), namesPreview().names);
  assert.deepEqual(p.roots, ["root 1 is ~/proj (the folder's name is not sent)"]);
  assert.match(p.notes.join(" "), /Not sent: 3 names your rules protect, 1 name that looks like a key, 1 name holding your home folder or user name\./);
  assert.match(p.notes.join(" "), /reach only that model's address/);
  assert.equal(p.empty, null);
  assert.equal(p.digest, "a".repeat(64));
});

test("the Contents preview: the text of N files (X KB) to your own model, the files and sizes, never their text", () => {
  const p = modelPreviewVM(contentsPreview(), HOME);
  assert.equal(p.headline, "This sends the text of 2 files (17 KB) to your own model ollama (this computer).");
  assert.equal(p.where, "ollama: your own model, on this computer");
  assert.equal(p.caption, "The files it reads (their text is not shown here)");
  assert.deepEqual(p.list, [{ text: "root 1/docs/contract.md", size: "16 KB (the first 16 KB)" }, { text: "root 1/notes/meeting.txt", size: "916 bytes" }]);
  const notes = p.notes.join(" ");
  assert.match(notes, /Not sent: 2 documents your rules or a sensitivity label protects, 2 documents that hold something like a key, 1 document too large or not text, 3 documents past the first 200\./);
  assert.match(notes, /cannot limit the request/);
  assert.ok(!notes.includes("mandu-landlock-apply"), "the service's note is not shown raw");
  assert.ok(!JSON.stringify(p).includes(TEXT_CANARY));
  const empty = modelPreviewVM(contentsPreview({ digest: "", items: 0, files: [] }), HOME);
  assert.match(empty.empty!, /No document to send/);
  assert.equal(destinationWhere({ ...contentsPreview().destination, placement: "network" }), "your own model, on your organization's network");
  assert.equal(kbWords(17_300), "17 KB");
});

test("a run in one line: contents, names, still reading, failed; refusals in the page's words", () => {
  assert.equal(modelRunVM(run(), "contents").line, "ollama read 41 files: 3 look sensitive and wait here for you, 37 do not (1 already waiting here).");
  assert.equal(modelRunVM(run({ counts: { ...run().counts, rules: 3, filed: 1, tooBroad: 1, alreadyPending: 0, public: 0 } }), "names").line, "ollama suggested 3 rules: 1 waits here for you, 1 too broad to suggest.");
  assert.equal(modelRunVM(run({ running: true }), "contents").running, true);
  const failed = modelRunVM(run({ error: "modelSuggest: the model run failed: the arbiter's classifier crashed", counts: { ...run().counts, rules: 0 } }), "contents");
  assert.equal(failed.line, "The model did not finish: the model run failed: the protection service's model helper crashed. Nothing was added.");
  assert.equal(modelErrorWords("modelSuggestPreview: the model tier is not available in this install (the arbiter was started without a classifier)"), "Asking a model is not available in this install of Mandu");
  assert.equal(modelErrorWords("modelSuggest: this preview is no longer held (it is kept 15 minutes, and not across a restart): look again"), "This preview has expired. Look again before you send");
  assert.equal(modelErrorWords("modelSuggestPreview: file contents go only to your own model: 'x' is not declared local: true"), "file contents go only to your own model: 'x' is not declared local: true");
});

test("rows: a document your own model read, and a sensitivity label's note", () => {
  const base: SuggestionWire = {
    id: "pp-000011", kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: "k", source: "model-contents", repoRoot: `${HOME}/proj`,
    edits: [{ op: "lock-path", path: `${HOME}/proj/hr.csv`, level: "local-model" }],
    sentence: "Make ~/proj/hr.csv a secret only your own AI may read (read by your own model ollama: looks like personnel records)",
    evidence: { paths: ["hr.csv"], blobs: [], findings: [], historyOnly: false },
    impact: { historicalVersions: 0, workingTreeChanges: true, files: ["hr.csv"] },
    historyOnly: false, rotate: false, humanOnly: true, applicable: true,
    model: { endpoint: "ollama", level: "local-model", reason: "personnel", reasonWords: "looks like personnel records", candidate: "file", files: 1, covers: [] },
    createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
  };
  const label: SuggestionWire = {
    ...base, id: "pp-000012", source: "sensitivity-label", model: undefined, humanOnly: false,
    edits: [{ op: "lock-path", path: `${HOME}/proj/board.docx`, level: "no-model" }],
    evidence: { paths: ["board.docx"], blobs: [], findings: [], historyOnly: false, label: { id: "9fbde396-1a24-4c79-8edf-9254a0f35055", site: null, name: "Highly Confidential", level: "no-model" } },
    sentence: "Make ~/proj/board.docx a secret no AI may read: its sensitivity label is Highly Confidential",
  };
  const [row, lab] = suggestionRows([base, label], HOME);
  // macOS: a model row and a label row promise only the file: the same words as on Linux.
  assert.deepEqual(suggestionRows([base, label], HOME, "darwin"), suggestionRows([base, label], HOME, "linux"));
  assert.equal(row!.source, "model-contents");
  assert.equal(row!.level, "local-model");
  assert.equal(row!.by, "Suggested by your model ollama");
  assert.equal(row!.note, MODEL_CONTENTS_NOTE);
  assert.deepEqual(row!.found, [{ words: "Looks like personnel records", mask: "from what the file says" }]);
  assert.equal(row!.impact, "Hides this file from the AI from the next time an agent starts.");
  assert.equal(row!.rotate, null);
  assert.equal(lab!.note, LABEL_NOTE);
  assert.match(LABEL_NOTE, /lowered or removed in Office later, this rule stays as it is/);
  const copy = [row, lab].flatMap((r) => [r!.by, r!.note ?? "", r!.impact, ...r!.found.map((f) => f.words + f.mask)]).join(" ");
  assert.doesNotMatch(copy, FORBIDDEN, copy);
});

test("every string the picker, the previews and the runs show uses the product vocabulary only", () => {
  const strings = [
    JSON.stringify(modelPickerVM(false, [])), JSON.stringify(modelPickerVM(true, [])), JSON.stringify(modelPickerVM(true, null)),
    JSON.stringify(modelPreviewVM(namesPreview(), HOME)), JSON.stringify(modelPreviewVM(contentsPreview(), HOME)),
    JSON.stringify(modelPreviewVM(contentsPreview({ digest: "", files: [], items: 0 }), HOME)),
    JSON.stringify(modelRunVM(run(), "contents")), JSON.stringify(modelRunVM(run({ running: true }), "names")),
    modelErrorWords("modelSuggestPreview: the model tier is not available in this install (the arbiter was started without a classifier)"),
  ].join(" ");
  assert.doesNotMatch(strings, FORBIDDEN, strings);
});
