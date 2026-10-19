/**
 * home-js-model-form-escape.test — Escape closes the Models form on the
 * product page's Settings, as Cancel does (dashboard.md §4.25 *The Models
 * form keeps the focus*, *Escape closes it*).
 *
 * Until 2026-10-11 only Cancel closed the form: Escape did nothing in any
 * of its fields, menus or tick boxes (a headless Chromium probe on master).
 * Now Escape in the form closes it, drops what was typed, and gives the
 * focus back to what opened it (Add a model, or the Edit of the model's
 * row). Not:
 *
 *   - an Escape an open note in the form takes: it closes the note alone;
 *   - an Escape that ends an IME composition (`isComposing`, or keyCode
 *     229), or one with Shift, Ctrl, Alt or Meta;
 *   - while Save's change is on its way: its answer decides;
 *   - an Escape outside the form.
 *
 * Drives the PRODUCT page script (public/js/home.js) in jsdom over the
 * shared fetch stub (home-js-fixtures.ts). Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { load, tick } from "./home-js-fixtures.js";
import { controlName } from "./control-names.js";

const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";
const OLLAMA = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", wireWords: "OpenAI chat", model: "llama3.2", local: true, placementWords: "On this computer" };
const LAB = { name: "lab", url: "https://lab.example/v1", wire: "openai-chat", wireWords: "OpenAI chat", model: "mistral", local: false };
const panelOf = (models: unknown[]) => ({ panel: { available: true, verdictsKnown: true, queue: [], yourRules: [], models } });
const NOTE = "New sessions use this. Restart a running agent to use it there.";
const SIGN_IN = { status: 403, body: { error: "admin session required — run `mandu dashboard` in your own terminal and open the sign-in link it prints (or set DASHBOARD_PASSWORD)" } };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const focused = (doc: Doc) => doc.activeElement;
const byId = (doc: Doc, id: string) => doc.getElementById(id);
const modelRow = (doc: Doc, name: string) => [...doc.querySelectorAll("#settings-models .model-row")].find((r: Doc) => r.dataset.name === name);
const editOf = (doc: Doc, name: string) => modelRow(doc, name).querySelector(".model-edit-btn");
const formOpen = (doc: Doc) => !byId(doc, "model-form").hidden;
const sent = (calls: Array<{ method: string; url: string }>) => calls.filter((c) => c.method === "POST" && c.url.endsWith("/policy/models/change")).length;
/** Enter on a button that opens or closes something. */
function enter(btn: Doc): void {
  btn.focus();
  btn.click();
}
/** Escape where the focus is, as a browser sends it: a keydown that
 *  bubbles; `init` adds a modifier, isComposing or a legacy keyCode. */
function escape(doc: Doc, init: Record<string, unknown> = {}): Doc {
  const ev = new doc.defaultView.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true, ...init });
  (doc.activeElement ?? doc.body).dispatchEvent(ev);
  return ev;
}

/** A Models list the POSTs change, as the server does. */
function settings(post: unknown = undefined) {
  let models: Array<Record<string, unknown>> = [OLLAMA, LAB];
  return load({ url: SETTINGS_URL, routes: {
    "GET policy/panel": () => panelOf(models),
    "POST policy/models/change": post ?? ((b: { action: string; name?: string; model: Record<string, unknown> }) => {
      if (b.action === "add") models = [...models, { ...b.model, wireWords: "OpenAI chat" }];
      if (b.action === "update") models = models.map((m) => (m.name === b.name ? { ...m, ...b.model } : m));
      return { applied: true, changeId: "pc-7", note: NOTE };
    }),
  } });
}

test("Settings › Models: Escape in the form opened by Add a model closes it as Cancel does: the focus is back on Add a model, what was typed is gone, nothing is sent", async () => {
  const { doc, calls } = settings();
  await tick();
  enter(byId(doc, "model-open"));
  assert.ok(formOpen(doc));
  assert.equal(focused(doc), byId(doc, "model-name"));
  byId(doc, "model-name").value = "half";
  byId(doc, "model-url").value = "https://half.example/v1";
  byId(doc, "model-url").focus();
  const ev = escape(doc);
  assert.equal(formOpen(doc), false, "Escape closes the form");
  assert.equal(ev.defaultPrevented, true, "the Escape is taken");
  assert.equal(focused(doc), byId(doc, "model-open"), "Add a model, which opened it; never <body>");
  assert.equal(byId(doc, "model-open").getAttribute("aria-expanded"), "false");
  assert.equal(sent(calls), 0, "nothing is sent");

  enter(byId(doc, "model-open"));
  assert.equal(byId(doc, "model-name").value, "", "what was typed is gone, as after Cancel");
  assert.equal(byId(doc, "model-url").value, "");
});

test("Settings › Models: Escape from a row's Edit, on the API style menu or a tick box, gives the focus back to that row's Edit; the model is unchanged", async () => {
  const { doc, calls } = settings();
  await tick();
  enter(editOf(doc, "lab"));
  assert.equal(byId(doc, "model-name").value, "lab");
  byId(doc, "model-url").value = "https://other.example/v1";
  byId(doc, "model-wire").focus();
  escape(doc);
  assert.equal(formOpen(doc), false);
  assert.equal(focused(doc), editOf(doc, "lab"), "lab's Edit, which opened it");
  assert.equal(controlName(focused(doc)), "Edit the model lab");

  enter(editOf(doc, "ollama"));
  byId(doc, "model-local").focus();
  escape(doc);
  assert.equal(formOpen(doc), false);
  assert.equal(focused(doc), editOf(doc, "ollama"), "ollama's Edit, never lab's");
  assert.equal(sent(calls), 0, "nothing is sent");
  enter(editOf(doc, "lab"));
  assert.equal(byId(doc, "model-url").value, "https://lab.example/v1", "the edit was dropped");
});

test("Settings › Models: an Escape an open note in the form takes closes the note alone; the next Escape closes the form", async () => {
  const { doc } = settings();
  await tick();
  enter(byId(doc, "model-open"));
  const help = byId(doc, "model-form").querySelector(".help-btn");
  assert.equal(controlName(help), "About your own model");
  enter(help);
  assert.equal(help.getAttribute("aria-expanded"), "true", "the note is open");
  const ev = escape(doc);
  assert.equal(ev.defaultPrevented, true, "the note took it");
  assert.equal(help.getAttribute("aria-expanded"), "false", "the note closes");
  assert.ok(formOpen(doc), "the form stays open");
  assert.equal(focused(doc), help);

  escape(doc);
  assert.equal(formOpen(doc), false, "the next Escape closes the form");
  assert.equal(focused(doc), byId(doc, "model-open"));
});

test("Settings › Models: Escape while Save's change is on its way closes nothing, and the answer closes the form as a Save does; after a refusal, Escape closes it", async () => {
  let release: () => void = () => {};
  let models: Array<Record<string, unknown>> = [OLLAMA, LAB];
  const { doc, window } = load({ url: SETTINGS_URL, routes: {
    "GET policy/panel": () => panelOf(models),
    "POST policy/models/change": (b: { name: string; model: Record<string, unknown> }) => new Promise((r) => {
      release = () => {
        models = models.map((m) => (m.name === b.name ? { ...m, ...b.model } : m));
        r({ applied: true, changeId: "pc-9", note: NOTE });
      };
    }),
  } });
  await tick();
  enter(editOf(doc, "lab"));
  const field = byId(doc, "model-model");
  field.value = "mistral-large";
  field.focus();
  // Enter in a field: the focus stays in it while Save is off.
  byId(doc, "model-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  assert.equal(byId(doc, "model-save").disabled, true, "the change is on its way");
  const ev = escape(doc);
  assert.equal(ev.defaultPrevented, false, "not taken");
  assert.ok(formOpen(doc), "the form stays open: the change cannot be called back");
  assert.equal(focused(doc), field);
  release();
  await tick(30);
  assert.equal(formOpen(doc), false, "the answer closes it");
  assert.match(byId(doc, "models-notice").textContent, /^Saved lab\./);
  assert.equal(focused(doc), editOf(doc, "lab"), "lab's Edit, drawn again, as after a Save");

  // A refused Save turns Save on again: Escape closes the form.
  const refused = settings(SIGN_IN);
  await tick();
  enter(editOf(refused.doc, "lab"));
  const save = byId(refused.doc, "model-save");
  save.focus();
  save.click();
  await tick(30);
  assert.match(byId(refused.doc, "model-error").textContent, /^Sign in first/);
  assert.equal(save.disabled, false);
  assert.equal(focused(refused.doc), save);
  escape(refused.doc);
  assert.equal(formOpen(refused.doc), false);
  assert.equal(focused(refused.doc), editOf(refused.doc, "lab"));
});

test("Settings › Models: an Escape that ends an IME composition, one with a modifier, and one outside the form close nothing; a plain one then does", async () => {
  const { doc } = settings();
  await tick();
  enter(byId(doc, "model-open"));
  const name = byId(doc, "model-name");
  name.value = "한";
  for (const init of [{ isComposing: true }, { keyCode: 229 }, { shiftKey: true }, { ctrlKey: true }, { altKey: true }, { metaKey: true }]) {
    const ev = escape(doc, init);
    assert.ok(formOpen(doc), `the form stays open: ${JSON.stringify(init)}`);
    assert.equal(ev.defaultPrevented, false, `not taken: ${JSON.stringify(init)}`);
    assert.equal(focused(doc), name);
  }
  assert.equal(name.value, "한", "nothing typed is lost");

  // Outside the form: Add a model (which toggles it), a row's button, and
  // the page.
  for (const outside of [byId(doc, "model-open"), modelRow(doc, "ollama").querySelector(".model-test-btn"), doc.body]) {
    outside.focus();
    if (outside !== doc.body) assert.equal(focused(doc), outside);
    else doc.activeElement.blur();
    const ev = escape(doc);
    assert.ok(formOpen(doc), `Escape outside the form closes nothing: ${outside.id || outside.className || "body"}`);
    assert.equal(ev.defaultPrevented, false);
  }

  name.focus();
  escape(doc);
  assert.equal(formOpen(doc), false, "a plain Escape in the form closes it");
  assert.equal(focused(doc), byId(doc, "model-open"));
});
