/**
 * home-js-notice-undo.test — a notice's Undo says which change it undoes
 * (dashboard.md §4.25 *A notice's Undo says which change it undoes*).
 *
 * A change made in Rules › Your rules, or in a Settings card (Models,
 * Sensitivity labels, Prompt filters), shows a notice above the card's list
 * with an Undo. A notice stays until the next change in its own card, so a
 * model removed, then a label saved, then a kind's choice changed leave
 * three notices on Settings. Until 2026-10-11 each one's button was a bare
 * "Undo": a screen reader's list of buttons said "Undo" three times, and a
 * Tab onto one read "Undo, button", with no word of the change it reverses.
 * Now:
 *
 *   - each notice's Undo is named by its card, its own word first ("Undo the
 *     change in Models"), so no two controls on Settings share a name;
 *   - it is described by its notice's words ("Removed lab. …"), so the
 *     change itself is read with it;
 *   - a sighted reader still sees "Undo";
 *   - Undo in one card leaves the other cards' notices, and their Undo, as
 *     they were; an undone or refused notice has no button.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub (home-js-fixtures.ts) and the server's own view models.
 * Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick } from "./home-js-fixtures.js";
import { controlName, nameFaults } from "./control-names.js";
import { labelSettingsVM } from "../../../src/view-model/sensitivity-labels.js";
import { promptSettingsVM } from "../../../src/view-model/prompt-settings.js";

const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";
const RULES_URL = "http://127.0.0.1:4500/mandu/rules";
const CONF = "2b2b0000-0000-4000-8000-000000000003";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

const OLLAMA = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", wireWords: "OpenAI chat", model: "llama3.2", local: true, placementWords: "On this computer" };
const LAB = { name: "lab", url: "https://lab.example/v1", wire: "openai-chat", wireWords: "OpenAI chat", model: "mistral", local: true, placementWords: "On your network" };
const panelOf = (models: unknown[]) => ({ panel: { available: true, verdictsKnown: true, queue: [], yourRules: [], models, modelsAdmin: { files: [], locked: false, removed: [] } } });
const labelsOf = (level: string) => ({ labels: labelSettingsVM({ sensitivity_labels: [{ id: CONF, name: "Confidential", level }] }, { sensitivityLabels: [] }, { labels: { unmapped: [], unmappedMore: 0 }, at: 1 }) });
const promptsOf = (action: string) => ({ settings: promptSettingsVM({
  filters: [{ id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] }],
  actions: [
    { category: "secret.registered", action: "mask", setBy: "default", locked: false },
    { category: "pii.email", action, setBy: "you", locked: false },
  ],
  fallback: "redact", exceptions: [], enforcing: true, editable: true,
}) });

const NOTE = "New sessions use this. Restart a running agent to use it there.";
const CARDS = [
  { notice: "models-notice", name: "Undo the change in Models", words: /^Removed lab\. New sessions use this\./ },
  { notice: "labels-notice", name: "Undo the change in Sensitivity labels", words: /^Saved Confidential\./ },
  { notice: "prompt-notice", name: "Undo the change in Prompt filters", words: /It applies to your next message\.$/ },
];

/** Settings over routes that follow the changes posted; Undo in
 *  Sensitivity labels puts the label back, or is refused. */
function settings(undo: unknown = undefined) {
  let models: unknown[] = [OLLAMA, LAB];
  let level = "local-model";
  let action = "mask";
  const page = load({ url: SETTINGS_URL, routes: {
    "GET policy/panel": () => panelOf(models),
    "GET policy/sensitivity-labels": () => labelsOf(level),
    "GET policy/prompt-filters": () => promptsOf(action),
    "POST policy/models/change": (b: { name: string }) => { models = models.filter((m) => (m as { name: string }).name !== b.name); return { applied: true, changeId: "pc-1", note: NOTE }; },
    "POST policy/sensitivity-labels/change": (b: { level: string }) => { level = b.level; return { applied: true, changeId: "pc-2", note: "" }; },
    "POST policy/prompt-filters/change": (b: { edit: { action: string } }) => { action = b.edit.action; return { applied: true, changeId: "pc-3" }; },
    "POST policy/changes/pc-2/undo": undo ?? (() => { level = "local-model"; return { ok: true }; }),
  } });
  page.window.confirm = () => true;
  return page;
}

/** The three changes, one per card: a model removed, a label's level
 *  saved, a kind's choice changed. */
async function threeChanges(doc: Doc): Promise<void> {
  const row = (sel: string, key: string, value: string) => [...doc.querySelectorAll(sel)].find((r: Doc) => r.dataset[key] === value);
  row("#settings-models .model-row", "name", "lab").querySelector(".model-remove-btn").click();
  await tick(30);
  const label = row("#settings-labels .label-row", "id", CONF);
  label.querySelector("select.label-level").value = "no-model";
  label.querySelector(".label-save-btn").click();
  await tick(30);
  const kind = row("#settings-prompt-kinds .prompt-kind", "category", "pii.email").querySelector("select");
  kind.value = "block";
  kind.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
  await tick(30);
}

const undoIn = (doc: Doc, notice: string) => [...doc.querySelectorAll(`#${notice} button`)];
/** The words a button is described by, as a browser reads them. */
const description = (b: Doc) => (b.getAttribute("aria-describedby") ?? "").split(/\s+/).filter(Boolean)
  .map((id: string) => b.ownerDocument.getElementById(id)?.textContent ?? "").join(" ");

test("Settings: three notices open at once are three Undo buttons, each named by its card, its own word first, and described by its notice's words; no two controls share a name", async () => {
  const { doc } = settings();
  await tick();
  await threeChanges(doc);
  for (const card of CARDS) {
    const buttons = undoIn(doc, card.notice);
    assert.equal(buttons.length, 1, `${card.notice} has its Undo`);
    const [b] = buttons;
    assert.equal(b.textContent, "Undo", "a sighted reader still sees Undo");
    assert.equal(controlName(b), card.name);
    assert.ok(controlName(b).startsWith(b.textContent), "its own word first (a voice command says what it sees)");
    assert.match(description(b), card.words, "described by its notice's words");
    assert.doesNotMatch(description(b), /Undo/, "the words alone, not the button");
    assert.equal(doc.getElementById(card.notice).textContent, description(b) + "Undo", "the whole notice, nothing more");
  }
  assert.deepEqual(nameFaults(doc.getElementById("page-settings")), { shared: [], unnamed: [] }, "no two controls on Settings share a name");
});

test("Settings: Undo in one card leaves the other cards' notices and their Undo as they were; its own notice says Undone, with no button", async () => {
  const { doc, calls } = settings();
  await tick();
  await threeChanges(doc);
  const others = ["models-notice", "prompt-notice"].map((id) => [id, doc.getElementById(id).textContent, undoIn(doc, id)[0]] as const);
  undoIn(doc, "labels-notice")[0].click();
  await tick(30);
  assert.ok(calls.some((c) => c.method === "POST" && c.url === "/mandu/api/policy/changes/pc-2/undo"), "the label's change, and only it, was undone");
  assert.ok(!calls.some((c) => /changes\/pc-[13]\/undo/.test(c.url)));
  assert.equal(doc.getElementById("labels-notice").textContent, "Undone.");
  assert.equal(undoIn(doc, "labels-notice").length, 0);
  for (const [id, text, b] of others) {
    assert.equal(doc.getElementById(id).textContent, text, `${id} is as it was`);
    assert.equal(undoIn(doc, id)[0], b, `${id}'s Undo is the same button`);
    assert.equal(controlName(b), CARDS.find((c) => c.notice === id)!.name);
    assert.ok(description(b).length > 0);
  }
  assert.deepEqual(nameFaults(doc.getElementById("page-settings")), { shared: [], unnamed: [] });
});

test("Settings: a refused Undo says why in its notice, with no button left to name", async () => {
  const { doc } = settings({ status: 409, body: { error: "This change was already undone." } });
  await tick();
  await threeChanges(doc);
  undoIn(doc, "labels-notice")[0].click();
  await tick(30);
  assert.match(doc.getElementById("labels-notice").textContent, /already undone/);
  assert.equal(undoIn(doc, "labels-notice").length, 0);
  assert.equal(controlName(undoIn(doc, "models-notice")[0]), "Undo the change in Models");
});

test("Rules: the notice's Undo is named \"Undo the change in Your rules\" and described by the notice's words", async () => {
  const rule = { id: "r-0001", kind: "release-allow", subject: "api.example.com", effect: "sending allowed", reach: "from any source to api.example.com", hits: 1, actions: { remove: true, flip: "block" } };
  const { doc } = load({ url: RULES_URL, routes: {
    "GET policy/panel": { panel: { available: true, verdictsKnown: true, yourRules: [rule], queue: [] } },
    "POST policy/rules/change": { applied: true, changeId: "pc-7" },
  } });
  await tick();
  const sel = doc.querySelector("#rules-list .row.rule select.effect-select");
  sel.value = "flip";
  sel.dispatchEvent(new doc.defaultView.Event("change", { bubbles: true }));
  await tick(30);
  const [b] = undoIn(doc, "rules-notice");
  assert.equal(b.textContent, "Undo");
  assert.equal(controlName(b), "Undo the change in Your rules");
  assert.equal(description(b), "Now always blocked.");
  assert.deepEqual(nameFaults(doc.getElementById("page-rules")), { shared: [], unnamed: [] });
});
