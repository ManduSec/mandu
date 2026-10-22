/**
 * home-js-suggest-model.test — the Suggested view's model picker and its
 * preview dialog (dashboard.md §4.25t, confidentiality-plan-14 §14.5,
 * §14.11), driven in jsdom over the fetch stub of home-js-fixtures.ts. The
 * picker, the preview and the run are the server's own view models
 * (view-model/suggestion-model.ts), so the page is tested on what the routes
 * send.
 *
 * Pins: Off by default; not offered, only Off can be picked and the line
 * says "not offered yet"; Contents disabled with the reason when no model of
 * your own is set up; picking a tier enables the button, which asks for the
 * preview with the typed folder and "Also look in your home folder"; the
 * preview dialog shows the headline, where it goes, the folders, the files
 * and their sizes (or every name as sent), what was left out, and nothing is
 * sent until Send; Cancel sends nothing; Send posts exactly the preview's
 * digest and the tier, shows the run's line and the new rows ("Suggested by
 * your model <name>"); a refusal shows the server's words; server text lands
 * as text.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick, FILES_URL, FILES_ROUTES } from "./home-js-fixtures.js";
import { suggestionRows, type SuggestionWire } from "../../../src/view-model/suggestions.js";
import { modelPickerVM, modelPreviewVM, modelRunVM, type ModelPreviewWire, type ModelRunWire } from "../../../src/view-model/suggestion-model.js";

const HOME = "/home/u";
const DIGEST = "b".repeat(64);
const PREVIEW: ModelPreviewWire = {
  axis: true, tier: "contents", digest: DIGEST,
  destination: { kind: "declared", name: "ollama", location: "local", placement: "host", vendor: "127.0.0.1" },
  roots: [{ index: 1, root: `${HOME}/proj`, files: 4 }], items: 2, bytes: 17_300, requests: 2, names: [],
  files: [{ root: 1, name: "docs/contract.md", bytes: 16_384, truncated: true }, { root: 1, name: "<img src=x onerror=alert(1)>.md", bytes: 916, truncated: false }],
  left: { covered: 1, labelled: 0, tooLong: 0, personal: 0, overCap: 0, detector: 0, registered: 0, flagged: 1, unread: 0 },
  promptVersion: "contents-1", confine: { live: true }, expiresAt: 1, walk: { examined: 4, covered: 1, capped: [] },
};
const RUN: ModelRunWire = {
  axis: true, running: false, digest: DIGEST, destination: PREVIEW.destination, sent: { requests: 2, items: 2, bytes: 17_300 },
  counts: { rules: 2, kept: 1, dropped: 0, merged: 0, tooBroad: 0, covered: 0, filed: 1, alreadyPending: 0, dismissed: 0, overCap: 0, failedRequests: 0, public: 1 },
  filed: ["pp-000021"], error: null, ms: 10,
};
const FILED: SuggestionWire = {
  id: "pp-000021", kind: "suggestion", status: "pending", requestedBy: "mandu:scan", findingKey: "k21", source: "model-contents", repoRoot: `${HOME}/proj`,
  edits: [{ op: "lock-path", path: `${HOME}/proj/docs/contract.md`, level: "no-model" }],
  sentence: "Make ~/proj/docs/contract.md a secret no AI may read (read by your own model ollama: looks like legal documents)",
  evidence: { paths: ["docs/contract.md"], blobs: [], findings: [], historyOnly: false },
  impact: { historicalVersions: 0, workingTreeChanges: true, files: ["docs/contract.md"] },
  historyOnly: false, rotate: false, humanOnly: false, applicable: true,
  model: { endpoint: "ollama", level: "no-model", reason: "legal", reasonWords: "looks like legal documents", candidate: "file", files: 1, covers: [] },
  createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
};
const listing = (model: unknown, views: SuggestionWire[] = []) => ({ suggestions: suggestionRows(views, HOME), count: views.length, scan: null, model });
const OFFERED = modelPickerVM(true, [{ name: "ollama", local: true }]);

async function open(routes: Record<string, unknown>) {
  const page = load({ url: FILES_URL, routes: { ...FILES_ROUTES, ...routes } });
  await tick();
  page.doc.getElementById("suggest-open").click();
  await tick();
  return page;
}
const pick = (doc: any, v: string) => {
  const sel = doc.getElementById("suggest-model-tier");
  sel.value = v;
  sel.dispatchEvent(new doc.defaultView.Event("change"));
};

test("not offered: only Off, and the line says not offered yet", async () => {
  const { doc } = await open({ "GET suggestions": listing(modelPickerVM(false, [])) });
  const sel = doc.getElementById("suggest-model-tier");
  assert.equal(sel.value, "off", "Off by default");
  assert.deepEqual([...sel.options].map((o: any) => [o.value, o.disabled]), [["off", false], ["names", true], ["contents", true]]);
  assert.match(doc.getElementById("suggest-model-why").textContent, /not offered yet/);
  assert.equal(doc.getElementById("suggest-model-run").disabled, true);
  assert.equal(doc.getElementById("suggest-model-preview").hidden, true);
});

test("offered without a model of your own: Names only can be picked, Contents says why not", async () => {
  const { doc } = await open({ "GET suggestions": listing(modelPickerVM(true, [{ name: "cloud", local: false }])) });
  const sel = doc.getElementById("suggest-model-tier");
  assert.deepEqual([...sel.options].map((o: any) => o.disabled), [false, false, true]);
  assert.match(sel.options[2].title, /No model of your own is set up/);
  assert.match(doc.getElementById("suggest-model-why").textContent, /Contents \(your own model\): No model of your own is set up/);
  pick(doc, "names");
  assert.equal(doc.getElementById("suggest-model-run").disabled, false);
});

test("Contents: the preview dialog shows the files and sizes and where they go; nothing is sent until Send; Send posts the digest and shows the run", async () => {
  const bodies: Array<{ path: string; body: any }> = [];
  const { doc, calls } = await open({
    "GET suggestions": listing(OFFERED),
    "POST suggestions/model/preview": (b: any) => (bodies.push({ path: "preview", body: b }), { preview: modelPreviewVM(PREVIEW, HOME) }),
    "POST suggestions/model/send": (b: any) => (bodies.push({ path: "send", body: b }), { run: modelRunVM(RUN, "contents"), ...listing(OFFERED, [FILED]) }),
  });
  doc.getElementById("suggest-root").value = "~/proj";
  doc.getElementById("suggest-home").checked = true;
  pick(doc, "contents");
  doc.getElementById("suggest-model-run").click();
  await tick();
  assert.deepEqual(bodies, [{ path: "preview", body: { tier: "contents", root: "~/proj", includeHome: true } }]);
  const dlg = doc.getElementById("suggest-model-preview");
  assert.equal(dlg.hidden, false);
  assert.equal(dlg.getAttribute("role"), "dialog");
  assert.equal(doc.getElementById("suggest-model-head").textContent, "This sends the text of 2 files (17 KB) to your own model ollama (this computer).");
  assert.equal(doc.getElementById("suggest-model-where").textContent, "Where it goes: ollama: your own model, on this computer.");
  assert.match(doc.getElementById("suggest-model-roots").textContent, /root 1 is ~\/proj/);
  const items = [...doc.querySelectorAll("#suggest-model-list li")].map((li: any) => li.textContent);
  assert.deepEqual(items, ["root 1/docs/contract.md  16 KB (the first 16 KB)", "root 1/<img src=x onerror=alert(1)>.md  916 bytes"]);
  assert.equal(doc.querySelector("#suggest-model-preview img"), null, "server text is text");
  assert.match(doc.getElementById("suggest-model-notes").textContent, /Not sent: 1 document your rules or a sensitivity label protects, 1 document that holds something like a key\./);
  assert.equal(doc.getElementById("suggest-model-status").textContent, "Nothing is sent until you press Send.");
  assert.equal(calls.filter((c) => c.url.includes("model/send")).length, 0);
  doc.getElementById("suggest-model-send").click();
  await tick(20);
  assert.deepEqual(bodies[1], { path: "send", body: { digest: DIGEST, tier: "contents" } });
  assert.equal(dlg.hidden, true);
  assert.equal(doc.getElementById("suggest-model-status").textContent, "ollama read 2 files: 1 looks sensitive and waits here for you, 1 does not.");
  const row = doc.querySelector('#files-suggested-list .row.suggested[data-id="pp-000021"]');
  assert.ok(row, "the new row is shown");
  row.click();
  await tick();
  assert.match(doc.getElementById("files-suggested-list").textContent, /Suggested by your model ollama/);
  assert.match(doc.getElementById("files-suggested-list").textContent, /Your own model read the start of this file/);
});

test("Names only with a named model; Cancel sends nothing; a refusal shows the server's words", async () => {
  const names = modelPreviewVM({ ...PREVIEW, tier: "names", digest: "a".repeat(64), destination: { kind: "default", name: "Claude (claude -p)", location: "external", placement: "network", vendor: "Anthropic" }, names: ['f1 root 1 "README.md" size=under1KB ext=md'], files: [] }, HOME);
  const { doc, calls } = await open({
    "GET suggestions": listing(OFFERED),
    "POST suggestions/model/preview": { preview: names },
  });
  pick(doc, "names");
  doc.getElementById("suggest-model-run").click();
  await tick();
  assert.deepEqual([...doc.querySelectorAll("#suggest-model-list li")].map((li: any) => li.textContent), ['f1 root 1 "README.md" size=under1KB ext=md']);
  assert.match(doc.getElementById("suggest-model-head").textContent, /No file's content is sent/);
  doc.getElementById("suggest-model-cancel").click();
  await tick();
  assert.equal(doc.getElementById("suggest-model-preview").hidden, true);
  assert.equal(doc.getElementById("suggest-model-status").textContent, "Nothing was sent.");
  assert.equal(calls.filter((c) => c.url.includes("model/send")).length, 0);

  const refused = await open({
    "GET suggestions": listing(OFFERED),
    "POST suggestions/model/preview": { status: 422, body: { error: "file contents go only to your own model: 'x' is not declared local: true" } },
  });
  pick(refused.doc, "contents");
  refused.doc.getElementById("suggest-model-run").click();
  await tick();
  assert.equal(refused.doc.getElementById("suggest-error").textContent, "file contents go only to your own model: 'x' is not declared local: true");
  assert.equal(refused.doc.getElementById("suggest-model-preview").hidden, true);
});

test("offered without a model of your own: the line says the same words, Settings › Models a link to that card", async () => {
  const { doc } = await open({ "GET suggestions": listing(modelPickerVM(true, [{ name: "cloud", local: false }])) });
  const why = doc.getElementById("suggest-model-why");
  const vm = modelPickerVM(true, [{ name: "cloud", local: false }]);
  assert.equal(why.textContent, `${vm.hint} Contents (your own model): ${vm.options[2]!.why}`, "the words are unchanged");
  assert.deepEqual([...why.querySelectorAll("a")].map((a: any) => [a.textContent, a.getAttribute("href")]), [["Settings › Models", "/mandu/settings#models"]]);
  // Picked away from Off, the reasons are not listed, and with them the link.
  pick(doc, "names");
  assert.equal(why.textContent, vm.hint);
  assert.equal(why.querySelector("a"), null);
});
