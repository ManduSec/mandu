/**
 * home-js-settings-follow.test — Settings shows a model, sensitivity label
 * or prompt filter changed elsewhere while it is open, as Rules does
 * (public/js/home.js `followSettings`; dashboard.md §4.25 *Settings follows
 * a change made elsewhere*; queue item #238).
 *
 * Until 2026-11-04 Settings read Models, Sensitivity labels and Prompt
 * filters when it opened and after its own changes: a model added in a
 * second tab, or a label given a level by hand in policy.yaml, stayed
 * missing until a reload, and the person learned of it only from a refused
 * Save. All three are sections of policy.yaml, so `rulesVersion` of
 * /api/home moves with them:
 *
 *   S1  the same version: nothing is read again, no line;
 *   S2  a new version: each card read once; the card that changed draws and
 *       says so on its own line, the ones that did not draw nothing and say
 *       nothing; the next poll at that version reads nothing;
 *   S3  an answer given in Approvals (the panel's queue moves, its models
 *       do not): Models draws nothing and says nothing;
 *   S4  a label's picker changed and not saved, the model form open, the
 *       focus in the prompt exception box: that card is kept as it is, the
 *       others follow; the first poll after it settles reads it;
 *   S5  the page's own save takes the next version silently, and its
 *       notice (with its Undo) stays: the line never takes its place;
 *   S6  a hidden tab reads nothing;
 *   S7  a server with no `rulesVersion`: nothing is read again;
 *   S8  a follow read keeps the exception kind chosen and the notice's Undo;
 *   S9  a follow read that fails keeps what is drawn, and a later poll
 *       follows again.
 *
 * Drives the PRODUCT page script in jsdom over the shared fetch stub
 * (home-js-fixtures.ts), with the server's own view models. Axes: none
 * (display only). Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { home, load, tick, type Call } from "./home-js-fixtures.js";
import { labelSettingsVM } from "../../../src/view-model/sensitivity-labels.js";
import { promptSettingsVM, type PromptFiltersProjection } from "../../../src/view-model/prompt-settings.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const URL = "http://127.0.0.1:4500/mandu/settings";
const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const OTHER = "2a2a0000-0000-4000-8000-000000000002";

const OLLAMA = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", wireWords: "OpenAI chat", model: "llama3.2", local: true, tokenEnv: null, placementWords: "On this computer", version: "a".repeat(32) };
const VLLM = { name: "vllm", url: "http://127.0.0.1:8000", wire: "openai-chat", wireWords: "OpenAI chat", model: null, local: true, tokenEnv: null, placementWords: "On this computer", version: "b".repeat(32) };
const panelOf = (models: unknown[], queue: unknown[] = []) => ({ panel: { available: true, verdictsKnown: true, queue, yourRules: [], models } });

const labelsAt = (level: string) => labelSettingsVM(
  { sensitivity_labels: [{ id: HC, name: "Highly Confidential", level }] },
  null,
  { labels: { unmapped: [{ id: OTHER, site: null, files: 3 }], unmappedMore: 0 }, at: 1 },
  { itemVersions: { "sensitivity-labels": { [`${HC}|`]: level.charAt(0).repeat(32) } }, absentVersion: "0".repeat(32) },
);

const PROJ: PromptFiltersProjection = {
  filters: [{ id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] }],
  actions: [
    { category: "secret.registered", action: "mask", setBy: "default", locked: false },
    { category: "pii.email", action: "redact", setBy: "you", locked: false },
    { category: "pii.phone", action: "redact", setBy: "default", locked: false },
  ],
  fallback: "redact",
  exceptions: [],
  enforcing: true,
  editable: true,
};
const promptWith = (exceptions: PromptFiltersProjection["exceptions"]) => promptSettingsVM({ ...PROJ, exceptions });

/** Settings open over answers the test switches (`now`), at `rulesVersion`
 *  v1 (or none). */
async function settings(opts: { version?: string | null; routes?: Record<string, unknown> } = {}) {
  const now = { models: panelOf([OLLAMA]) as unknown, labels: labelsAt("no-model") as unknown, prompt: promptWith([]) as unknown, labelsFail: false };
  const version = opts.version === undefined ? "v1" : opts.version;
  const page = load({
    url: URL,
    homeVm: home(version === null ? {} : { rulesVersion: version }),
    routes: {
      "GET policy/panel": () => now.models,
      "GET policy/sensitivity-labels": () => (now.labelsFail ? { status: 500, body: { error: "boom" } } : { labels: now.labels }),
      "GET policy/prompt-filters": () => ({ settings: now.prompt }),
      ...opts.routes,
    },
  });
  assert.equal(page.err, null);
  await tick();
  // The first poll asked after the reads the page opened with gives the
  // version they are at.
  await poll(page.doc);
  return { ...page, now };
}
async function poll(doc: Doc): Promise<void> {
  Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
  doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));
  await tick(30);
}
const reads = (calls: Call[]) => ({
  models: calls.filter((c) => c.url.endsWith("/api/policy/panel")).length,
  labels: calls.filter((c) => c.url.endsWith("/api/policy/sensitivity-labels") && c.method === "GET").length,
  prompt: calls.filter((c) => c.url.endsWith("/api/policy/prompt-filters") && c.method === "GET").length,
});
const line = (doc: Doc, card: string) => doc.getElementById(card + "-changed");
const modelNames = (doc: Doc) => [...doc.querySelectorAll("#settings-models .model-row")].map((r: Doc) => r.dataset.name);
const labelRow = (doc: Doc, id: string) => [...doc.querySelectorAll("#settings-labels .label-row")].find((r: Doc) => r.dataset.id === id) as Doc;
const exceptions = (doc: Doc) => [...doc.querySelectorAll("#settings-prompt-exceptions .prompt-exception")].map((r: Doc) => r.dataset.match);
const pickLevel = (row: Doc, level: string) => {
  const pick = row.querySelector("select.label-level");
  pick.value = level;
  pick.dispatchEvent(new pick.ownerDocument.defaultView.Event("change", { bubbles: true }));
};

test("S1: the same rulesVersion on each poll reads nothing again and says nothing", async () => {
  const { doc, calls } = await settings();
  const n = reads(calls);
  assert.deepEqual(n, { models: 1, labels: 1, prompt: 1 }, "each card read once, when Settings opened");
  await poll(doc);
  await poll(doc);
  assert.deepEqual(reads(calls), n, "no read while the version holds");
  for (const card of ["models", "labels", "prompt"]) assert.equal(line(doc, card).hidden, true, card);
});

test("S2: a new rulesVersion reads each card once; only the card that changed draws and says so", async () => {
  const { doc, calls, setHome, now } = await settings();
  const modelRow = doc.querySelector("#settings-models .model-row");
  const kindRow = doc.querySelector("#settings-prompt-kinds .prompt-kind");
  assert.equal(labelRow(doc, HC).querySelector("select.label-level").value, "no-model");
  now.labels = labelsAt("local-model");
  setHome(home({ rulesVersion: "v2" }));
  const n = reads(calls);
  await poll(doc);
  assert.deepEqual(reads(calls), { models: n.models + 1, labels: n.labels + 1, prompt: n.prompt + 1 }, "one read per card");
  assert.equal(labelRow(doc, HC).querySelector("select.label-level").value, "local-model", "the label's new level is drawn");
  assert.equal(line(doc, "labels").hidden, false);
  assert.equal(line(doc, "labels").textContent, "Your sensitivity labels changed since this page was read. It shows them now.");
  assert.equal(line(doc, "labels").getAttribute("role"), "status");
  assert.equal(line(doc, "models").hidden, true, "Models did not change: no line");
  assert.equal(line(doc, "prompt").hidden, true, "Prompt filters did not change: no line");
  assert.equal(doc.querySelector("#settings-models .model-row"), modelRow, "Models drew nothing");
  assert.equal(doc.querySelector("#settings-prompt-kinds .prompt-kind"), kindRow, "Prompt filters drew nothing");
  assert.equal(doc.getElementById("labels-notice").hidden, true, "the notice place is left to the page's own changes");

  // A model added elsewhere, at v3: Models draws it and says so; the labels line stays.
  now.models = panelOf([OLLAMA, VLLM]);
  setHome(home({ rulesVersion: "v3" }));
  await poll(doc);
  assert.deepEqual(modelNames(doc), ["ollama", "vllm"]);
  assert.equal(line(doc, "models").textContent, "Your models changed since this page was read. It shows them now.");
  assert.equal(line(doc, "labels").hidden, false, "the labels line stays until the page reads the card itself");
  const m = reads(calls);
  await poll(doc);
  assert.deepEqual(reads(calls), m, "the next poll at v3 reads nothing");

  // An exception added elsewhere, at v4.
  now.prompt = promptWith([{ category: "pii.email", match: "*@example.com", setBy: "you", inForce: true }]);
  setHome(home({ rulesVersion: "v4" }));
  await poll(doc);
  assert.deepEqual(exceptions(doc), ["*@example.com"]);
  assert.equal(line(doc, "prompt").textContent, "Your prompt filters changed since this page was read. It shows them now.");
});

test("S3: an answer given in Approvals moves rulesVersion and the panel's queue, not the models: Models draws nothing and says nothing", async () => {
  const { doc, calls, setHome, now } = await settings();
  const row = doc.querySelector("#settings-models .model-row");
  now.models = panelOf([OLLAMA], [{ id: "egr-9", status: "approved", scope: "always", resolvedAt: Date.now() }]);
  setHome(home({ rulesVersion: "v2" }));
  const n = reads(calls);
  await poll(doc);
  assert.equal(reads(calls).models, n.models + 1, "read once");
  assert.equal(doc.querySelector("#settings-models .model-row"), row, "not drawn again");
  for (const card of ["models", "labels", "prompt"]) assert.equal(line(doc, card).hidden, true, card);
});

test("S4: a label picked and not saved, the model form open, the focus in the exception box: that card waits; the first poll after it settles reads it", async () => {
  const { window, doc, calls, setHome, now } = await settings();
  // A label's level picked, not saved.
  pickLevel(labelRow(doc, HC), "public");
  // The model form open (Add a model), then the focus moved out of it.
  doc.getElementById("model-open").click();
  await tick();
  assert.equal(doc.getElementById("model-form").hidden, false);
  doc.activeElement.blur();
  now.labels = labelsAt("local-model");
  now.models = panelOf([OLLAMA, VLLM]);
  now.prompt = promptWith([{ category: "pii.email", match: "*@example.com", setBy: "you", inForce: true }]);
  setHome(home({ rulesVersion: "v2" }));
  const n = reads(calls);
  await poll(doc);
  assert.deepEqual(reads(calls), { models: n.models, labels: n.labels, prompt: n.prompt + 1 }, "Models and labels wait; Prompt filters follows");
  assert.equal(labelRow(doc, HC).querySelector("select.label-level").value, "public", "the level picked stays");
  assert.match(labelRow(doc, HC).querySelector(".label-unsaved").textContent, /^Not saved/);
  assert.deepEqual(modelNames(doc), ["ollama"]);
  assert.equal(line(doc, "labels").hidden, true);
  assert.equal(line(doc, "models").hidden, true);

  // The picker back at its level: labels follow; the form still open: Models waits.
  pickLevel(labelRow(doc, HC), "no-model");
  await poll(doc);
  assert.equal(reads(calls).labels, n.labels + 1, "read once it settled");
  assert.equal(labelRow(doc, HC).querySelector("select.label-level").value, "local-model");
  assert.equal(line(doc, "labels").hidden, false);
  assert.equal(reads(calls).models, n.models, "the form is still open");
  doc.getElementById("model-cancel").click();
  await tick();
  doc.activeElement?.blur?.();
  await poll(doc);
  assert.equal(reads(calls).models, n.models + 1, "read once the form closed");
  assert.deepEqual(modelNames(doc), ["ollama", "vllm"]);

  // The focus in the exception box: Prompt filters waits until it leaves.
  const match = doc.getElementById("prompt-exception-match");
  match.focus();
  assert.equal(doc.activeElement, match);
  now.prompt = promptWith([]);
  setHome(home({ rulesVersion: "v3" }));
  const p = reads(calls).prompt;
  await poll(doc);
  assert.equal(reads(calls).prompt, p, "not while the focus is in the card");
  assert.deepEqual(exceptions(doc), ["*@example.com"]);
  assert.equal(doc.activeElement, match, "the focus stays where it was");
  // A word typed in it, the focus gone: it still waits.
  match.value = "ci-*";
  match.blur();
  await poll(doc);
  assert.equal(reads(calls).prompt, p, "not while an exception is being written");
  match.value = "";
  await poll(doc);
  assert.equal(reads(calls).prompt, p + 1, "read once it settled");
  assert.deepEqual(exceptions(doc), []);
  // An unmapped label's name typed: labels wait.
  labelRow(doc, OTHER).querySelector(".label-name").value = "Secret";
  now.labels = labelsAt("no-model");
  setHome(home({ rulesVersion: "v4" }));
  const l = reads(calls).labels;
  await poll(doc);
  assert.equal(reads(calls).labels, l, "not while a name is typed");
  assert.equal(window.document, doc);
});

test("S5: the page's own save takes the next version silently; its notice and Undo stay", async () => {
  const { doc, calls, setHome, now } = await settings({ routes: {
    "POST policy/sensitivity-labels/change": { applied: true, changeId: "pc-7", note: "" },
  } });
  pickLevel(labelRow(doc, HC), "local-model");
  now.labels = labelsAt("local-model");
  labelRow(doc, HC).querySelector(".label-save-btn").click();
  await tick(30);
  const notice = doc.getElementById("labels-notice");
  assert.equal(notice.hidden, false);
  assert.match(notice.textContent, /^Saved Highly Confidential\./);
  const undo = [...notice.querySelectorAll("button")].find((b: Doc) => b.textContent === "Undo");
  assert.ok(undo, "the notice has its Undo");
  setHome(home({ rulesVersion: "v2" }));
  const n = reads(calls);
  await poll(doc);
  assert.equal(reads(calls).labels, n.labels, "the first poll after the page's own read gives the version, no read");
  assert.equal(line(doc, "labels").hidden, true, "never says a change of its own was made elsewhere");
  assert.equal(line(doc, "models").hidden, true, "the other cards read again and found nothing new");
  assert.equal(line(doc, "prompt").hidden, true);
  assert.ok(notice.contains(undo), "the notice and its Undo stay");
  await poll(doc);
  assert.equal(reads(calls).labels, n.labels);
});

test("S6: a hidden tab reads nothing", async () => {
  const { window, doc, calls, setHome, now } = await settings();
  now.labels = labelsAt("local-model");
  setHome(home({ rulesVersion: "v2" }));
  Object.defineProperty(doc, "visibilityState", { value: "hidden", configurable: true });
  const n = reads(calls);
  const homes = calls.filter((c) => c.url.endsWith("/api/home")).length;
  await window.loadHome();
  await tick(30);
  assert.equal(calls.filter((c) => c.url.endsWith("/api/home")).length, homes + 1, "the poll ran");
  assert.deepEqual(reads(calls), n, "no card read in a hidden tab");
  assert.equal(line(doc, "labels").hidden, true);
  await poll(doc);
  assert.equal(reads(calls).labels, n.labels + 1, "read once the tab is seen");
  assert.equal(line(doc, "labels").hidden, false);
});

test("S7: a server with no rulesVersion keeps today's behaviour: nothing is read again", async () => {
  const { doc, calls, now } = await settings({ version: null });
  now.labels = labelsAt("local-model");
  now.models = panelOf([OLLAMA, VLLM]);
  const n = reads(calls);
  await poll(doc);
  await poll(doc);
  assert.deepEqual(reads(calls), n);
  for (const card of ["models", "labels", "prompt"]) assert.equal(line(doc, card).hidden, true, card);
});

test("S8: a follow read keeps the exception kind chosen and the Prompt filters notice with its Undo", async () => {
  const { doc, setHome, now } = await settings({ routes: {
    "POST policy/prompt-filters/change": { applied: true, changeId: "pc-8" },
  } });
  // The page's own change leaves its notice and Undo.
  const sel = doc.querySelector("#settings-prompt-kinds .prompt-kind[data-category='pii.email'] select.prompt-action");
  sel.value = "mask";
  sel.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
  await tick(30);
  const notice = doc.getElementById("prompt-notice");
  assert.equal(notice.hidden, false);
  assert.ok([...notice.querySelectorAll("button")].some((b: Doc) => b.textContent === "Undo"));
  doc.activeElement?.blur?.();
  await poll(doc); // takes the version after the page's own read
  const kind = doc.getElementById("prompt-exception-kind");
  assert.ok(kind.options.length > 1, "more than one kind to choose");
  kind.value = kind.options[1].value;
  const chosen = kind.value;
  now.prompt = promptWith([{ category: "pii.email", match: "*@example.com", setBy: "you", inForce: true }]);
  setHome(home({ rulesVersion: "v2" }));
  await poll(doc);
  assert.deepEqual(exceptions(doc), ["*@example.com"], "followed");
  assert.equal(line(doc, "prompt").hidden, false);
  assert.equal(doc.getElementById("prompt-exception-kind").value, chosen, "the kind chosen stays");
  assert.equal(notice.hidden, false, "the notice stays");
  assert.ok([...notice.querySelectorAll("button")].some((b: Doc) => b.textContent === "Undo"), "with its Undo");
});

test("S9: a follow read that fails keeps what is drawn and says nothing; a later poll follows again", async () => {
  const { doc, calls, setHome, now } = await settings();
  now.labels = labelsAt("local-model");
  now.labelsFail = true;
  setHome(home({ rulesVersion: "v2" }));
  const n = reads(calls);
  await poll(doc);
  assert.equal(reads(calls).labels, n.labels + 1);
  assert.equal(labelRow(doc, HC).querySelector("select.label-level").value, "no-model", "the list drawn stays");
  assert.equal(line(doc, "labels").hidden, true);
  now.labelsFail = false;
  await poll(doc);
  assert.equal(reads(calls).labels, n.labels + 2, "followed again");
  assert.equal(labelRow(doc, HC).querySelector("select.label-level").value, "local-model");
  assert.equal(line(doc, "labels").hidden, false);
});
