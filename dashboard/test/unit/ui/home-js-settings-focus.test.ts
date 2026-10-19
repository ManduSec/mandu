/**
 * home-js-settings-focus.test — a Settings row's button names its row, and a
 * change made in a Settings card keeps the keyboard focus (dashboard.md §4.25
 * *A Settings row's button names its row; a change keeps the focus*).
 *
 * Until 2026-10-11 Chromium's accessibility tree read 27 controls on Settings,
 * 16 of them sharing a name: "Remove" ×7, "Test connection" ×3, "Edit",
 * "Save" and "Use the default" ×2. And every change there (a label's Save, a
 * model's Remove, Use the default, even Test connection) left the focus on
 * <body>: the row's buttons go off while the change is on its way, and the
 * card's list is drawn again after it. Now:
 *
 *   - each row's button is named by its row, its own words first (a model's
 *     name, a label's name or id, a kind of finding, an exception's kind and
 *     pattern); no two controls share a name;
 *   - after a change the focus goes back to the control drawn at its place
 *     that reads the same (Save on the same label, Test connection on the
 *     same model), else the card's heading; never another row's button (two
 *     exceptions of one kind are two places);
 *   - a refused change gives it back to the button pressed, described by the
 *     refusal's words; a cancelled one gives it back too;
 *   - Undo gives it to the card's heading;
 *   - a focus moved elsewhere meanwhile, or a press without the focus, moves
 *     nothing.
 *
 * jsdom keeps the focus of a button turned off, so `press` drops it to
 * <body>, as Chromium does (home-js-answer-focus.test.ts). Drives the
 * PRODUCT page script (public/js/home.js) in jsdom over the shared fetch
 * stub (home-js-fixtures.ts) and the server's own view models. Axes: none
 * (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick } from "./home-js-fixtures.js";
import { controlName, nameFaults } from "./control-names.js";
import { labelSettingsVM } from "../../../src/view-model/sensitivity-labels.js";
import { promptSettingsVM, type PromptFiltersProjection } from "../../../src/view-model/prompt-settings.js";

const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";
const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const CONF = "2b2b0000-0000-4000-8000-000000000003";
const GEN = "1e4f0000-0000-4000-8000-000000000001";
const OTHER = "2a2a0000-0000-4000-8000-000000000002";

const OLLAMA = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", wireWords: "OpenAI chat", model: "llama3.2", local: true, placementWords: "On this computer" };
const LAB = { name: "lab", url: "https://lab.example/v1", wire: "openai-chat", wireWords: "OpenAI chat", model: "mistral", local: true, placementWords: "On your network" };
const CORP = { name: "corp", url: "https://llm.corp.example/v1", wire: "openai-chat", wireWords: "OpenAI chat", local: true, admin: true, locked: false };
const panelOf = (models: unknown[], removed: string[] = []) => ({ panel: {
  available: true, verdictsKnown: true, queue: [], yourRules: [], models,
  modelsAdmin: { files: ["/etc/mandu/policy.d/10-org.yaml"], locked: false, removed: removed.map((name) => ({ name })) },
} });

const labelsOf = (own: Array<{ id: string; name: string; level: string }>, unmapped = true) => ({ labels: labelSettingsVM(
  { sensitivity_labels: own },
  { sensitivityLabels: [{ id: GEN, name: "General", level: "any-model", file: "/etc/mandu/policy.d/l.yaml" }] },
  { labels: { unmapped: unmapped ? [{ id: OTHER, site: null, files: 7 }] : [], unmappedMore: 0 }, at: 1 },
) });
const LABELS = [{ id: HC, name: "Highly Confidential", level: "no-model" }, { id: CONF, name: "Confidential", level: "local-model" }];

const EMAIL_A = { category: "pii.email", match: "*@example.com", setBy: "you", inForce: true };
const EMAIL_B = { category: "pii.email", match: "*@corp.example", setBy: "you", inForce: true };
const KEY_X = { category: "secret.shape", match: "pk_test_*", setBy: "you", inForce: true };
const promptsOf = (over: Partial<PromptFiltersProjection> = {}) => ({ settings: promptSettingsVM({
  filters: [{ id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] }],
  actions: [
    { category: "secret.registered", action: "mask", setBy: "default", locked: false },
    { category: "pii.email", action: "mask", setBy: "you", locked: false },
    { category: "pii.phone", action: "redact", setBy: "you", locked: false },
  ],
  fallback: "redact",
  exceptions: [EMAIL_A, EMAIL_B, KEY_X],
  enforcing: true,
  editable: true,
  ...over,
}) });

const NOTE = "New sessions use this. Restart a running agent to use it there.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
/** Enter on a button: it has the focus, the click acts, and the browser
 *  drops the focus of the button the change turned off to <body>. jsdom
 *  neither drops it nor blurs a button that is off, so the button is on
 *  for the blur only. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function press(btn: any): void {
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "the change turns its button off while it is on its way");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
  assert.equal(btn.ownerDocument.activeElement, btn.ownerDocument.body);
}
const focused = (doc: Doc) => doc.activeElement;
const rowBy = (doc: Doc, sel: string, key: string, value: string) => [...doc.querySelectorAll(sel)].find((r: Doc) => r.dataset[key] === value);
const labelRow = (doc: Doc, id: string) => rowBy(doc, "#settings-labels .label-row", "id", id);
const modelRow = (doc: Doc, name: string) => rowBy(doc, "#settings-models .model-row:not(.model-removed)", "name", name);
const kindRow = (doc: Doc, cat: string) => rowBy(doc, "#settings-prompt-kinds .prompt-kind", "category", cat);
const exceptionRow = (doc: Doc, match: string) => [...doc.querySelectorAll("#settings-prompt-exceptions .prompt-exception")].find((r: Doc) => r.querySelector("code:last-of-type")?.textContent === match);

function settings(routes: Record<string, unknown> = {}) {
  return load({ url: SETTINGS_URL, routes: {
    "GET policy/panel": panelOf([CORP, OLLAMA, LAB], ["corp-big"]),
    "GET policy/sensitivity-labels": labelsOf(LABELS),
    "GET policy/prompt-filters": promptsOf(),
    ...routes,
  } });
}

test("Settings: each row's button names its row, its own words first; no two controls on the page share a name, none has none", async () => {
  const { doc } = settings();
  await tick();
  const names = (sel: string) => [...doc.querySelectorAll(sel)].map((b: Doc) => controlName(b));
  assert.deepEqual(names("#settings-models button"), [
    "Test connection to corp", "Remove the model corp",
    "Test connection to ollama", "Edit the model ollama", "Remove the model ollama",
    "Test connection to lab", "Edit the model lab", "Remove the model lab",
    "Bring back the model corp-big",
  ]);
  assert.deepEqual(names("#settings-labels button"), [
    "Save the level for Highly Confidential", "Remove the level for Highly Confidential",
    "Save the level for Confidential", "Remove the level for Confidential",
    "Save the level for " + OTHER,
  ]);
  assert.deepEqual(names("#settings-prompt-kinds button"), ["Use the default for an email address", "Use the default for a phone number"]);
  assert.deepEqual(names("#settings-prompt-exceptions button"), [
    "Remove the exception for an email address matching *@example.com",
    "Remove the exception for an email address matching *@corp.example",
    "Remove the exception for something shaped like a key or password matching pk_test_*",
  ]);
  // A kind's words keep their own capitals inside the sentence.
  assert.equal(controlName(kindRow(doc, "secret.registered").querySelector("select")), "What happens to a secret Mandu already knows");
  // The words a person sees are unchanged, and come first in each name
  // (a voice command says what it sees).
  for (const b of doc.querySelectorAll("#page-settings .table button")) {
    assert.ok(controlName(b).startsWith(b.textContent), `"${controlName(b)}" starts with "${b.textContent}"`);
  }
  const faults = nameFaults(doc.getElementById("page-settings"));
  assert.deepEqual(faults, { shared: [], unnamed: [] }, "every control on Settings says which it is");
});

test("Settings › Sensitivity labels: Save gives the focus back to Save on the same label, drawn again; on a label with no level, to Save on the row it became", async () => {
  let mapped = false;
  const { doc } = settings({
    "GET policy/sensitivity-labels": () => (mapped ? labelsOf([...LABELS, { id: OTHER, name: "Customer Data", level: "no-model" }], false) : labelsOf(LABELS)),
    "POST policy/sensitivity-labels/change": (b: { id: string }) => ((mapped ||= b.id === OTHER), { applied: true, changeId: "pc-1", note: "Mandu's next scan suggests with this." }),
  });
  await tick();
  const old = labelRow(doc, CONF).querySelector(".label-save-btn");
  press(old);
  await tick(30);
  const now = labelRow(doc, CONF).querySelector(".label-save-btn");
  assert.notEqual(now, old, "the list was drawn again");
  assert.equal(focused(doc), now, "Save on the same label, never another label's");
  assert.equal(controlName(focused(doc)), "Save the level for Confidential");

  const open = labelRow(doc, OTHER);
  open.querySelector("input.label-name").value = "Customer Data";
  press(open.querySelector(".label-save-btn"));
  await tick(30);
  assert.ok(labelRow(doc, OTHER).querySelector(".label-remove-btn"), "the label has a level now");
  assert.equal(focused(doc), labelRow(doc, OTHER).querySelector(".label-save-btn"));
});

test("Settings › Models: Remove gives the focus to the Models heading once the row is gone, never another model's button; Bring back too", async () => {
  let models: unknown[] = [CORP, OLLAMA, LAB];
  let removed = ["corp-big"];
  const { doc } = settings({
    "GET policy/panel": () => panelOf(models, removed),
    "POST policy/models/change": (b: { action: string; name: string }) => {
      if (b.action === "remove") models = models.filter((m) => (m as { name: string }).name !== b.name);
      if (b.action === "restore") { removed = []; models = [...models, { ...CORP, name: "corp-big" }]; }
      return { applied: true, changeId: "pc-2", note: NOTE };
    },
  });
  await tick();
  press(modelRow(doc, "ollama").querySelector(".model-remove-btn"));
  await tick(30);
  assert.equal(modelRow(doc, "ollama"), undefined, "removed");
  assert.equal(focused(doc), doc.getElementById("settings-models-title"), "the card's heading, not lab's Remove that took the row's place");
  assert.equal(focused(doc).getAttribute("tabindex"), "-1", "no Tab stop");
  assert.match(doc.getElementById("models-notice").textContent, /^Removed ollama\./);

  press(doc.querySelector("#settings-models .model-restore-btn"));
  await tick(30);
  assert.ok(modelRow(doc, "corp-big"), "brought back");
  assert.equal(focused(doc), doc.getElementById("settings-models-title"));
});

test("Settings › Models: Test connection gives the focus back to the same button, the result under it", async () => {
  const { doc } = settings({
    "POST policy/models/test": { result: { name: "lab", ok: true, lines: [{ tone: "ok", text: "Connected to lab.example." }] } },
  });
  await tick();
  const b = modelRow(doc, "lab").querySelector(".model-test-btn");
  press(b);
  await tick(30);
  assert.equal(focused(doc), b);
  assert.equal(b.disabled, false);
  assert.equal(modelRow(doc, "lab").querySelector(".model-test").textContent, "Connected to lab.example.");
});

test("Settings › Prompt filters: Use the default, its button gone, gives the focus to the card's heading; Remove on one of two exceptions of a kind never gives it to the other's Remove", async () => {
  let prompts = promptsOf();
  const { doc } = settings({
    "GET policy/prompt-filters": () => prompts,
    "POST policy/prompt-filters/change": (b: { edit: { op: string; match?: string } }) => {
      if (b.edit.op === "remove-prompt-action") prompts = promptsOf({ actions: [
        { category: "secret.registered", action: "mask", setBy: "default", locked: false },
        { category: "pii.email", action: "redact", setBy: "default", locked: false },
        { category: "pii.phone", action: "redact", setBy: "you", locked: false },
      ] });
      if (b.edit.op === "remove-prompt-exception") prompts = promptsOf({ exceptions: [EMAIL_B, KEY_X] });
      return { applied: true, changeId: "pc-3" };
    },
  });
  await tick();
  press(kindRow(doc, "pii.email").querySelector(".prompt-reset-btn"));
  await tick(30);
  assert.equal(kindRow(doc, "pii.email").querySelector(".prompt-reset-btn"), null, "back to the default");
  assert.equal(focused(doc), doc.getElementById("settings-prompt-title"), "not the menu beside it, not phone's Use the default");

  press(exceptionRow(doc, "*@example.com").querySelector("button"));
  await tick(30);
  assert.equal(exceptionRow(doc, "*@example.com"), undefined, "removed");
  assert.notEqual(focused(doc), exceptionRow(doc, "*@corp.example").querySelector("button"), "the other email exception's Remove is another action");
  assert.equal(focused(doc), doc.getElementById("settings-prompt-title"));
});

test("Settings: a refused change gives the focus back to the button pressed, described by the refusal's words; a cancelled one gives it back too", async () => {
  const page = settings({
    "POST policy/sensitivity-labels/change": { status: 403, body: { error: "admin session required — run `mandu dashboard` in your own terminal and open the sign-in link it prints (or set DASHBOARD_PASSWORD)" } },
    "POST policy/models/change": { applied: false, confirm: true, expected: ["k"], rows: [[{ kind: "text", text: "Remove lab" }]], wouldLet: [], warnings: [] },
  });
  const { doc } = page;
  await tick();
  const b = labelRow(doc, HC).querySelector(".label-remove-btn");
  press(b);
  await tick(30);
  assert.equal(focused(doc), b, "the same button, on again");
  assert.equal(b.disabled, false);
  const words = labelRow(doc, HC).querySelector(".ask-error");
  assert.match(words.textContent, /^Sign in first/);
  assert.equal(b.getAttribute("aria-describedby"), words.id, "the refusal's words are read with the button");

  page.window.confirm = () => false;
  const r = modelRow(doc, "lab").querySelector(".model-remove-btn");
  press(r);
  await tick(30);
  assert.equal(focused(doc), r, "a change not made leaves the focus where it was pressed");
  assert.equal(r.getAttribute("aria-describedby"), null, "nothing was refused");
});

test("Settings: Undo under a card gives the focus to its heading; a focus moved elsewhere meanwhile, and a press made without the focus, move nothing", async () => {
  const { doc } = settings({
    "POST policy/sensitivity-labels/change": { applied: true, changeId: "pc-4", note: "" },
    "POST policy/changes/pc-4/undo": { ok: true },
  });
  await tick();
  press(labelRow(doc, CONF).querySelector(".label-save-btn"));
  await tick(30);
  const undo = [...doc.querySelectorAll("#labels-notice button")].find((x: Doc) => x.textContent === "Undo");
  press(undo);
  await tick(30);
  assert.equal(doc.getElementById("labels-notice").textContent, "Undone.");
  assert.equal(focused(doc), doc.getElementById("settings-labels-title"));

  // Moved elsewhere while the change is on its way: it stays there.
  press(labelRow(doc, CONF).querySelector(".label-save-btn"));
  const elsewhere = doc.getElementById("model-open");
  elsewhere.focus();
  await tick(30);
  assert.equal(focused(doc), elsewhere);

  // A click with the focus outside the card (a browser that does not focus
  // a clicked button): nothing is given the focus.
  doc.activeElement.blur();
  labelRow(doc, CONF).querySelector(".label-save-btn").click();
  await tick(30);
  assert.equal(focused(doc), doc.body);
});
