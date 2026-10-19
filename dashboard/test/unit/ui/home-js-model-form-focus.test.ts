/**
 * home-js-model-form-focus.test — the Models form on the product page's
 * Settings keeps the keyboard focus (dashboard.md §4.25 *The Models form
 * keeps the focus*).
 *
 * Until 2026-10-11 a headless Chromium left the focus on <body> after every
 * Cancel of the form (opened by Add a model or by a row's Edit), every Save
 * that worked (Add or Edit, by the button or Enter in a field), and every
 * refused Save, which its error line did not describe. Now:
 *
 *   - Cancel, and a Save that worked, give the focus back to what opened the
 *     form: Add a model, or the Edit of the model's row (after a Save, the
 *     row of the name saved), else the Models heading;
 *   - a refused Save, or one declined at its question, gives it back to
 *     Save, on again; Save is described by the form's error line;
 *   - Enter in a field that is refused leaves the focus in the field;
 *   - a focus moved elsewhere meanwhile, or a press made without the focus
 *     in the form, moves nothing;
 *   - the token field and the exception form's pattern box are named by
 *     their label alone and described by their hint.
 *
 * jsdom keeps the focus of a button turned off, so `press` drops it to
 * <body>, as Chromium does (home-js-settings-focus.test.ts); it also keeps
 * the focus in a form hidden under it, which the page counts as fallen.
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub (home-js-fixtures.ts). Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick } from "./home-js-fixtures.js";
import { controlName, reachableControls } from "./control-names.js";

const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";
const OLLAMA = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", wireWords: "OpenAI chat", model: "llama3.2", local: true, placementWords: "On this computer" };
const LAB = { name: "lab", url: "https://lab.example/v1", wire: "openai-chat", wireWords: "OpenAI chat", model: "mistral", local: false };
const panelOf = (models: unknown[]) => ({ panel: { available: true, verdictsKnown: true, queue: [], yourRules: [], models } });
const NOTE = "New sessions use this. Restart a running agent to use it there.";
const SIGN_IN = { status: 403, body: { error: "admin session required — run `mandu dashboard` in your own terminal and open the sign-in link it prints (or set DASHBOARD_PASSWORD)" } };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
/** Enter on Save: it has the focus, the click submits, and the browser
 *  drops the focus of the button the change turned off to <body>. jsdom
 *  neither drops it nor blurs a button that is off, so the button is on
 *  for the blur only. */
function press(btn: Doc): void {
  btn.focus();
  btn.click();
  assert.equal(btn.disabled, true, "Save goes off while the change is on its way");
  btn.disabled = false;
  btn.blur();
  btn.disabled = true;
  assert.equal(btn.ownerDocument.activeElement, btn.ownerDocument.body);
}
const focused = (doc: Doc) => doc.activeElement;
const byId = (doc: Doc, id: string) => doc.getElementById(id);
const modelRow = (doc: Doc, name: string) => [...doc.querySelectorAll("#settings-models .model-row")].find((r: Doc) => r.dataset.name === name);
const editOf = (doc: Doc, name: string) => modelRow(doc, name).querySelector(".model-edit-btn");
/** Enter on a button that only opens or closes the form. */
function enter(btn: Doc): void {
  btn.focus();
  btn.click();
}

/** A Models list the POSTs change, as the server does. */
function settings(post: unknown = undefined) {
  let models: Array<Record<string, unknown>> = [OLLAMA, LAB];
  const page = load({ url: SETTINGS_URL, routes: {
    "GET policy/panel": () => panelOf(models),
    "POST policy/models/change": post ?? ((b: { action: string; name?: string; model: Record<string, unknown> }) => {
      if (b.action === "add") models = [...models, { ...b.model, wireWords: "OpenAI chat" }];
      if (b.action === "update") models = models.map((m) => (m.name === b.name ? { ...m, ...b.model } : m));
      return { applied: true, changeId: "pc-7", note: NOTE };
    }),
  } });
  return page;
}

test("Settings › Models: Cancel gives the focus back to what opened the form: Add a model, or the Edit of that model's row; never <body>", async () => {
  const { doc } = settings();
  await tick();
  enter(byId(doc, "model-open"));
  assert.equal(byId(doc, "model-form").hidden, false);
  assert.equal(focused(doc), byId(doc, "model-name"), "the form takes the focus at its first field");
  enter(byId(doc, "model-cancel"));
  assert.equal(byId(doc, "model-form").hidden, true, "the form closes");
  assert.equal(focused(doc), byId(doc, "model-open"), "Add a model, which opened it");

  enter(editOf(doc, "lab"));
  assert.equal(byId(doc, "model-name").value, "lab");
  enter(byId(doc, "model-cancel"));
  assert.equal(byId(doc, "model-form").hidden, true);
  assert.equal(focused(doc), editOf(doc, "lab"), "the Edit of lab's row, never ollama's");
  assert.equal(controlName(focused(doc)), "Edit the model lab");
});

test("Settings › Models: a Save that worked gives the focus back to what opened the form, drawn again: Add a model after an add; after an edit, the Edit of the row under the name saved", async () => {
  const { doc } = settings();
  await tick();
  enter(byId(doc, "model-open"));
  byId(doc, "model-name").value = "zdr";
  byId(doc, "model-url").value = "https://zdr.example/v1";
  press(byId(doc, "model-save"));
  await tick(30);
  assert.ok(modelRow(doc, "zdr"), "added");
  assert.equal(byId(doc, "model-form").hidden, true);
  assert.match(byId(doc, "models-notice").textContent, /^Added zdr\./);
  assert.equal(focused(doc), byId(doc, "model-open"), "Add a model, not the new row's buttons");

  const old = editOf(doc, "lab");
  enter(old);
  byId(doc, "model-name").value = "lab2";
  press(byId(doc, "model-save"));
  await tick(30);
  assert.equal(modelRow(doc, "lab"), undefined, "renamed");
  assert.notEqual(editOf(doc, "lab2"), old, "the list was drawn again");
  assert.equal(focused(doc), editOf(doc, "lab2"), "the Edit of the row under its saved name");
  assert.match(byId(doc, "models-notice").textContent, /^Saved lab2\./);
});

test("Settings › Models: with the row it came from gone after a Save, or Add a model hidden, the focus goes to the Models heading", async () => {
  const { doc } = load({ url: SETTINGS_URL, routes: {
    "GET policy/panel": (() => { let n = 0; return () => panelOf(n++ ? [OLLAMA] : [OLLAMA, LAB]); })(),
    "POST policy/models/change": { applied: true, changeId: "pc-8", note: NOTE },
  } });
  await tick();
  enter(editOf(doc, "lab"));
  press(byId(doc, "model-save"));
  await tick(30);
  assert.equal(modelRow(doc, "lab"), undefined);
  assert.equal(focused(doc), byId(doc, "settings-models-title"), "the heading, never ollama's Edit");
  assert.equal(focused(doc).getAttribute("tabindex"), "-1", "no Tab stop");

  // A list that cannot be read again hides Add a model: the heading too.
  const unread = load({ url: SETTINGS_URL, routes: {
    "GET policy/panel": (() => { let n = 0; return () => (n++ ? { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [] } } : panelOf([OLLAMA])); })(),
    "POST policy/models/change": { applied: true, changeId: "pc-9", note: NOTE },
  } });
  await tick();
  enter(byId(unread.doc, "model-open"));
  byId(unread.doc, "model-name").value = "zdr";
  byId(unread.doc, "model-url").value = "https://zdr.example/v1";
  press(byId(unread.doc, "model-save"));
  await tick(30);
  assert.equal(byId(unread.doc, "model-open").hidden, true, "no Add while the list cannot be read");
  assert.equal(focused(unread.doc), byId(unread.doc, "settings-models-title"), "the heading, never the hidden Add a model");
});

test("Settings › Models: a refused Save gives the focus back to Save, on again and described by the refusal's words; one declined at its question gives it back too", async () => {
  const page = settings(SIGN_IN);
  const { doc } = page;
  await tick();
  const save = byId(doc, "model-save");
  assert.equal(save.getAttribute("aria-describedby"), "model-error", "Save is described by the form's error line");
  enter(editOf(doc, "lab"));
  press(save);
  await tick(30);
  assert.equal(byId(doc, "model-form").hidden, false, "the form stays open to fix");
  assert.equal(focused(doc), save, "Save, on again");
  assert.equal(save.disabled, false);
  assert.match(byId(doc, "model-error").textContent, /^Sign in first/);

  const asked = settings({ applied: false, confirm: true, expected: ["k"], rows: [[{ kind: "text", text: "Change lab" }]], wouldLet: [], warnings: [] });
  await tick();
  asked.window.confirm = () => false;
  enter(editOf(asked.doc, "lab"));
  press(byId(asked.doc, "model-save"));
  await tick(30);
  assert.equal(byId(asked.doc, "model-form").hidden, false);
  assert.equal(focused(asked.doc), byId(asked.doc, "model-save"), "a change not made gives the focus back to Save");
  assert.equal(byId(asked.doc, "model-error").textContent, "", "nothing was refused, so nothing describes it");
});

test("Settings › Models: Enter in a field that worked gives the focus to what opened the form; one refused leaves it in the field", async () => {
  const { doc, window } = settings();
  await tick();
  enter(editOf(doc, "ollama"));
  const field = byId(doc, "model-model");
  field.value = "llama3.3";
  field.focus();
  doc.getElementById("model-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  await tick(30);
  assert.equal(byId(doc, "model-form").hidden, true);
  assert.equal(focused(doc), editOf(doc, "ollama"), "out of the hidden form, to ollama's Edit");

  const refused = settings({ status: 422, body: { error: "This model entry is not valid.", problems: ["url: must be an http(s) URL"] } });
  await tick();
  enter(byId(refused.doc, "model-open"));
  const url = byId(refused.doc, "model-url");
  url.value = "ftp://x";
  url.focus();
  refused.doc.getElementById("model-form").dispatchEvent(new refused.window.Event("submit", { cancelable: true }));
  await tick(30);
  assert.equal(focused(refused.doc), url, "the field keeps the focus to fix it");
  assert.match(byId(refused.doc, "model-error").textContent, /^This model entry is not valid\./);
});

test("Settings › Models: a focus moved elsewhere while the change is on its way, and a press made without the focus in the form, move nothing", async () => {
  const { doc } = settings();
  await tick();
  enter(editOf(doc, "lab"));
  press(byId(doc, "model-save"));
  const elsewhere = byId(doc, "model-open");
  elsewhere.focus();
  await tick(30);
  assert.equal(byId(doc, "model-form").hidden, true);
  assert.equal(focused(doc), elsewhere, "where the person put it, not lab's Edit");

  // Moved to a row the list draws again: the person's choice, never handed
  // to the control that opened the form.
  enter(editOf(doc, "lab"));
  press(byId(doc, "model-save"));
  modelRow(doc, "ollama").querySelector(".model-test-btn").focus();
  await tick(30);
  assert.equal(byId(doc, "model-form").hidden, true);
  assert.notEqual(focused(doc), editOf(doc, "lab"), "not lab's Edit");

  enter(byId(doc, "model-open"));
  doc.activeElement.blur();
  byId(doc, "model-cancel").click();
  assert.equal(byId(doc, "model-form").hidden, true);
  assert.equal(focused(doc), doc.body, "a click that did not focus Cancel (a browser that does not focus a clicked button) moves nothing");
});

test("Settings: the token field and the exception box are named by their label alone, described by their hint; each control in the Models form has its own name", async () => {
  const { doc } = settings();
  await tick();
  enter(byId(doc, "model-open"));
  const token = byId(doc, "model-token-env");
  assert.equal(controlName(token), "Token variable name (optional)");
  assert.match(byId(doc, token.getAttribute("aria-describedby")).textContent, /^An environment variable's name\./);
  const match = byId(doc, "prompt-exception-match");
  assert.equal(controlName(match), "When it matches");
  assert.match(byId(doc, match.getAttribute("aria-describedby")).textContent, /^For example \*@example\.com\./);
  // The form's controls a person reaches (its hidden input is none).
  const names = reachableControls(byId(doc, "model-form")).filter((c: Doc) => c.type !== "hidden").map((c: Doc) => controlName(c));
  assert.deepEqual(names, [
    "Name", "Address", "API style", "Model (optional)", "This is my own model", "About your own model",
    "About sending without encryption", "About the model that reads your own-model files",
    "Token variable name (optional)", "Cancel", "Save model",
  ]);
});
