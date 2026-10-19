/**
 * home-js-settings-rows.test — Settings rows whose last cell is a choice and
 * its buttons fit them (dashboard.md §4.25s *A row's controls fit it*): the
 * PRODUCT page (public/js/home.js) in jsdom with its own stylesheets applied
 * (public/mandu.css, public/app.css), over the server's own view models.
 *
 * Until 2026-10-08 a label's level picker and a prompt filter's choice sat in
 * the plain service row's 120px third column with no layout of their own
 * (only Models' `.model-row .model-actions` was a flex row): the picker read
 * "Secret, hidden from th" past the row's border, Save and Remove stacked,
 * and the hint under a label with no level filled the 180px name column.
 *
 * Pins, for every kind of row (your label, your administrator's, one with no
 * level; a default kind, a locked kind, your own with Use the default, one
 * with no choice):
 *   - the row's third column is sized to its controls, up to half the row;
 *   - the controls cell lays them out on one line, wrapping;
 *   - the notes under a row ("Set by your administrator.", the hint) and a
 *     refusal span the row;
 *   - Models keeps its own grid, its buttons still on one line;
 *   - a narrow screen stacks these rows, the controls on the left;
 *   - a prompt filter exception reads as one sentence in the row's widest
 *     cell, who added it on the line under it, Remove at the end, and a
 *     long pattern or kind breaks inside its chip (§4.25y *An exception
 *     reads as a sentence*).
 *
 * jsdom does no layout and ignores width media queries, so the wide screen's
 * declared values are read from the computed style, and the narrow screen's
 * from the stylesheet's text. Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { load, tick, PUB } from "./home-js-fixtures.js";
import { declValue, flattenCss, resolveCssVars, stripComments } from "./css-flatten.js";
import { labelSettingsVM } from "../../../src/view-model/sensitivity-labels.js";
import { promptSettingsVM, type PromptFiltersProjection } from "../../../src/view-model/prompt-settings.js";

const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";
const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const GEN = "1e4f0000-0000-4000-8000-000000000001";
const OTHER = "2a2a0000-0000-4000-8000-000000000002";

const LABELS = labelSettingsVM(
  { sensitivity_labels: [{ id: HC, name: "Highly Confidential", level: "no-model" }] },
  { sensitivityLabels: [{ id: GEN, name: "General", level: "any-model", file: "/etc/mandu/policy.d/l.yaml" }] },
  { labels: { unmapped: [{ id: OTHER, site: null, files: 7 }], unmappedMore: 0 }, at: 1 },
);
const PROJ: PromptFiltersProjection = {
  filters: [{ id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] }],
  actions: [
    { category: "secret.registered", action: "mask", setBy: "default", locked: false },
    { category: "secret.shape", action: "redact", setBy: "administrator", locked: true, file: "/etc/mandu/policy.d/10-org.yaml" },
    { category: "pii.payment-card", action: "block", setBy: "administrator", locked: true, file: "/etc/mandu/policy.d/20-cards.yaml" },
    { category: "pii.email", action: "redact", setBy: "you", locked: false },
  ],
  fallback: "redact",
  exceptions: [],
  enforcing: true,
  editable: true,
};
const PROMPTS = promptSettingsVM(PROJ);
const PANEL = {
  panel: {
    available: true, verdictsKnown: true, queue: [], yourRules: [],
    models: [{ name: "office-llm", url: "https://llm.corp.example/v1", wire: "openai", wireWords: "OpenAI-style", local: true, placementWords: "On your network", admin: false }],
  },
};

/** The product page's two stylesheets, in its own order, with the theme's
 *  tokens resolved (jsdom reads a shorthand holding a `var()` as nothing). */
const STYLES = resolveCssVars(readFileSync(join(PUB, "mandu.css"), "utf8") + "\n" + readFileSync(join(PUB, "app.css"), "utf8"));
const RULES = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function settings(routes: Record<string, unknown> = {}): { doc: any; css: (e: any) => any } {
  const { doc } = load({
    url: SETTINGS_URL,
    routes: { "GET policy/sensitivity-labels": { labels: LABELS }, "GET policy/prompt-filters": { settings: PROMPTS }, "GET policy/panel": PANEL, ...routes },
  });
  const s = doc.createElement("style");
  s.textContent = STYLES;
  doc.head.append(s);
  return { doc, css: (e) => doc.defaultView.getComputedStyle(e) };
}

const FIT = "180px minmax(0, 1fr) fit-content(50%)";

test("Settings › Sensitivity labels: each row's level picker and buttons share one cell sized to them; the notes under a row span it", async () => {
  const { doc, css } = settings();
  await tick();
  const rows = [...doc.querySelectorAll("#settings-labels .row.label-row")];
  assert.deepEqual(rows.map((r: any) => r.dataset.id), [HC, GEN, OTHER], "your label, your administrator's, one with no level");
  for (const row of rows) {
    assert.equal(css(row).display, "grid");
    assert.equal(css(row).gridTemplateColumns, FIT, `${row.dataset.id}: the third column takes what its controls need, never a fixed 120px`);
  }
  const [mine, admin, open] = rows;
  // Yours: the picker, Save and Remove in the one cell, laid out as a row.
  const acts = mine.querySelector(".model-actions");
  assert.equal(acts, mine.children[2], "the controls are the row's third cell");
  assert.deepEqual([...acts.children].map((c: any) => c.tagName + "." + c.className), ["SELECT.label-level", "BUTTON.btn small label-save-btn", "BUTTON.btn small label-remove-btn"]);
  assert.equal(css(acts).display, "flex", "one line, not one control under another");
  assert.equal(css(acts).flexWrap, "wrap", "wrapping only when the row is too narrow");
  assert.equal(css(acts).gap, "8px");
  assert.equal(css(acts).justifyContent, "flex-end");
  // Your administrator's: the level in the third cell, the note under the row.
  assert.equal(admin.children[2].className, "label-level-words");
  const note = admin.querySelector(".model-admin");
  assert.equal(note.textContent, "Set by your administrator.");
  assert.equal(css(note).gridColumn, "1 / -1", "the note spans the row, as in Models");
  assert.equal(css(note).fontSize, "13px");
  // One with no level: the name box, the picker and Save in the cell; the hint spans the row.
  const openActs = open.querySelector(".model-actions");
  assert.deepEqual([...openActs.children].map((c: any) => c.tagName), ["INPUT", "SELECT", "BUTTON"]);
  assert.equal(css(openActs).display, "flex");
  const box = openActs.querySelector("input.label-name");
  assert.equal(css(box).height, "32px", "the name box is as tall as the picker beside it");
  assert.equal(css(box).height, css(openActs.querySelector("select")).height);
  const hint = open.querySelector(".field-hint");
  assert.match(hint.textContent, /^A label your organization lets cloud AI read is usually/);
  assert.equal(css(hint).gridColumn, "1 / -1", "the hint spans the row, not the 180px name column");
  assert.equal(css(hint).fontSize, "13px");
});

test("Settings › Prompt filters: each kind's choice, and Use the default beside it, share one cell sized to them", async () => {
  const { doc, css } = settings();
  await tick();
  const rows = [...doc.querySelectorAll("#settings-prompt-kinds .row.prompt-kind")];
  const by = (cat: string) => rows.find((r: any) => r.dataset.category === cat);
  assert.equal(rows.length, 4);
  for (const row of rows) {
    assert.equal(css(row).gridTemplateColumns, FIT, `${row.dataset.category}: the third column takes what its choice needs`);
    const acts = row.querySelector(".model-actions");
    assert.equal(acts, row.children[2], `${row.dataset.category}: the controls are the row's third cell`);
    assert.equal(css(acts).display, "flex");
    assert.equal(css(acts).flexWrap, "wrap");
  }
  const own = by("pii.email").querySelector(".model-actions");
  assert.deepEqual([...own.children].map((c: any) => c.className), ["prompt-action", "btn small prompt-reset-btn"], "your own kind: the choice, then Use the default");
  assert.equal(by("secret.registered").querySelector("select.prompt-action").value, "mask");
  assert.equal(by("pii.payment-card").querySelector(".model-actions").textContent, "Block the message", "a kind with no choice says what happens");
});

test("a refusal on a label or a prompt filter row spans the row, under its controls", async () => {
  const { doc, css } = settings({
    "POST policy/sensitivity-labels/change": { status: 422, body: { error: "the policy file has a problem" } },
    "POST policy/prompt-filters/change": { status: 409, body: { error: "the rules changed meanwhile" } },
  });
  await tick();
  const label = doc.querySelector(`#settings-labels .label-row[data-id="${HC}"]`);
  label.querySelector(".label-save-btn").click();
  await tick();
  const labelError = label.querySelector(".ask-error");
  assert.ok(labelError && labelError.parentElement === label, "the refusal is said on the row");
  assert.match(labelError.textContent, /the policy file has a problem/);
  assert.equal(css(labelError).gridColumn, "1 / -1");
  const kind = doc.querySelector('#settings-prompt-kinds .prompt-kind[data-category="pii.email"]');
  kind.querySelector(".prompt-reset-btn").click();
  await tick();
  const kindError = kind.querySelector(".ask-error");
  assert.ok(kindError && kindError.parentElement === kind);
  assert.match(kindError.textContent, /the rules changed meanwhile/);
  assert.equal(css(kindError).gridColumn, "1 / -1");
});

test("Settings › Models keeps its own grid, its buttons on one line", async () => {
  const { doc, css } = settings();
  await tick();
  const row = doc.querySelector('#settings-models .row.model-row[data-name="office-llm"]');
  assert.ok(row, "the model is listed");
  assert.equal(css(row).gridTemplateColumns, "160px minmax(0, 1fr) minmax(120px, 220px) auto");
  const acts = row.querySelector(".model-actions");
  assert.deepEqual([...acts.querySelectorAll("button")].map((b: any) => b.textContent), ["Test connection", "Edit", "Remove"]);
  assert.equal(css(acts).display, "flex");
  assert.equal(css(acts).justifyContent, "flex-end");
});

test("app.css: these rows have their own grid with a third column sized to its controls, stacked on a narrow screen with the controls on the left", () => {
  const wide = (sel: string) => RULES.filter((r) => r.media === null && r.selectors.includes(sel));
  const narrow = (sel: string) => RULES.filter((r) => r.media?.includes("max-width: 760px") && r.selectors.includes(sel));
  for (const sel of [".row.service.label-row", ".row.service.prompt-kind"]) {
    const grid = wide(sel).map((r) => declValue(r.block, "grid-template-columns")).filter(Boolean);
    assert.deepEqual(grid, [FIT], `${sel}: one grid; the third column fits its controls, up to half the row`);
    assert.ok(narrow(sel).some((r) => declValue(r.block, "grid-template-columns") === "1fr"),
      `${sel}: its own grid outranks the plain service row's narrow rule, so it needs one of its own`);
  }
  // The controls cell is a flex row in every service row, not in Models' alone.
  const acts = wide(".row.service .model-actions");
  assert.equal(acts.length, 1);
  assert.equal(declValue(acts[0]!.block, "display"), "flex");
  assert.equal(declValue(acts[0]!.block, "flex-wrap"), "wrap");
  assert.ok(!RULES.some((r) => r.selectors.includes(".model-row .model-actions")), "no layout kept for Models alone");
  assert.ok(narrow(".row.service .model-actions").some((r) => declValue(r.block, "justify-content") === "flex-start"),
    "stacked, the controls sit on the left like the row's other lines");
  for (const sel of [".row.service > .ask-error", ".label-row > .field-hint", ".label-row > .model-admin"]) {
    assert.ok(wide(sel).some((r) => declValue(r.block, "grid-column") === "1 / -1"), `${sel} spans the row`);
  }
});

// ── §4.25y *An exception reads as a sentence* ───────────────────────────────
// Until 2026-10-08 an exception was a plain service row: its sentence a flex
// box in the 180px name column, three to five lines tall, and a long
// pattern's or kind's chip ran over "Set by your administrator" beside it.

const LONG_KIND = "acme.customeraccountnumber";
const LONG_MATCH = "build-notifications-and-release-announcements@very-long-subdomain.example.org";
const PROMPTS_EX = promptSettingsVM({
  ...PROJ,
  filters: [...(PROJ.filters ?? []), { id: "acme-dlp", on: true, categories: [{ category: LONG_KIND, action: "redact" }] }],
  exceptions: [
    { category: "pii.email", match: "*@corp.example.com", setBy: "administrator", file: "/etc/mandu/policy.d/10-org.yaml", inForce: true },
    { category: "pii.email", match: LONG_MATCH, setBy: "you", inForce: true },
    { category: LONG_KIND, match: "CUST0000*", setBy: "you", inForce: true },
    { category: "secret.shape", match: "pk_*", setBy: "you", inForce: false },
  ],
});
const EX_GRID = "minmax(0, 1fr) auto";

test("Settings › Prompt filters › Exceptions: each reads as one sentence in the row's widest cell, who added it on the line under it, Remove at the end", async () => {
  const { doc, css } = settings({ "GET policy/prompt-filters": { settings: PROMPTS_EX } });
  await tick();
  const rows = [...doc.querySelectorAll("#settings-prompt-exceptions .row.prompt-exception")];
  assert.equal(rows.length, 4);
  for (const row of rows) {
    const what = row.children[0];
    assert.equal(css(row).display, "grid");
    assert.equal(css(row).gridTemplateColumns, EX_GRID, `${what.textContent}: the sentence takes the row's width, never a 180px name column`);
    assert.equal(what.className, "prompt-exception-what", "the sentence and who added it share the first cell");
    assert.deepEqual([...what.children].map((c: any) => c.className), ["name", "sub"], "who added it is the line under the sentence");
    assert.equal(css(what).display, "flex");
    assert.equal(css(what).flexDirection, "column");
    assert.equal(css(what).gap, "2px");
    assert.equal(css(what).minWidth, "0px", "the cell may be narrower than its longest chip, which then breaks");
    const name = what.querySelector(".name");
    assert.equal(css(name).display, "block", "the sentence wraps as words, not as flex items side by side");
    for (const code of name.querySelectorAll("code")) {
      assert.equal(css(code).overflowWrap, "anywhere", `${code.textContent}: a long pattern or kind breaks inside its chip`);
    }
  }
  const [admin, long, named, out] = rows;
  assert.equal(admin.querySelector(".name").textContent, "An email address matching *@corp.example.com");
  assert.equal(admin.querySelector(".sub").textContent, "Set by your administrator (10-org.yaml).");
  assert.equal(admin.children.length, 1, "your administrator's has no Remove");
  assert.equal(long.querySelector(".name code").textContent, LONG_MATCH);
  assert.deepEqual([...long.children].map((c: any) => c.className), ["prompt-exception-what", "btn small right prompt-exception-remove"], "Remove is the row's last cell");
  assert.equal(css(long.children[1]).justifySelf, "end");
  assert.deepEqual([...named.querySelectorAll(".name code")].map((c: any) => c.textContent), [LONG_KIND, "CUST0000*"], "an organization's kind as code, then its pattern");
  assert.equal(named.querySelector(".name").textContent, LONG_KIND + " matching CUST0000*");
  assert.equal(out.querySelector(".sub").textContent, "Added by you. Not in force: your administrator locked this kind.");
});

test("Settings › Prompt filters: an organization's kind with a long name breaks inside its chip in the name column", async () => {
  const { doc, css } = settings({ "GET policy/prompt-filters": { settings: PROMPTS_EX } });
  await tick();
  const row = doc.querySelector(`#settings-prompt-kinds .prompt-kind[data-category="${LONG_KIND}"]`);
  assert.ok(row, "the kind is listed");
  assert.equal(css(row).gridTemplateColumns, FIT, "the kinds keep their 180px name column");
  const chip = row.querySelector(".name code");
  assert.equal(chip.textContent, LONG_KIND);
  assert.equal(css(chip).overflowWrap, "anywhere", "never over the words in the next column");
});

test("a refusal on an exception row spans the row, under the sentence and Remove", async () => {
  const { doc, css } = settings({
    "GET policy/prompt-filters": { settings: PROMPTS_EX },
    "POST policy/prompt-filters/change": { status: 409, body: { error: "the rules changed meanwhile" } },
  });
  await tick();
  const row = doc.querySelectorAll("#settings-prompt-exceptions .row.prompt-exception")[1];
  row.querySelector(".prompt-exception-remove").click();
  await tick();
  const error = row.querySelector(".ask-error");
  assert.ok(error && error.parentElement === row, "the refusal is said on the row");
  assert.match(error.textContent, /the rules changed meanwhile/);
  assert.equal(css(error).gridColumn, "1 / -1");
});

test("app.css: an exception row has its own grid, the sentence first and Remove after it, stacked on a narrow screen", () => {
  const wide = (sel: string) => RULES.filter((r) => r.media === null && r.selectors.includes(sel));
  const narrow = (sel: string) => RULES.filter((r) => r.media?.includes("max-width: 760px") && r.selectors.includes(sel));
  assert.deepEqual(wide(".row.service.prompt-exception").map((r) => declValue(r.block, "grid-template-columns")).filter(Boolean), [EX_GRID]);
  assert.ok(narrow(".row.service.prompt-exception").some((r) => declValue(r.block, "grid-template-columns") === "1fr"),
    "its own grid outranks the plain service row's narrow rule, so it needs one of its own");
  assert.deepEqual(wide(".prompt-exception-what > .name").map((r) => declValue(r.block, "display")), ["block"], "the sentence is not the name cell's flex box");
  assert.deepEqual(wide(".row.service .name code").map((r) => declValue(r.block, "overflow-wrap")), ["anywhere"], "a chip in a Settings row's name breaks inside it");
});
