/**
 * home-js-empty-states.test — the PRODUCT page's empty and fallback states
 * (public/js/home.js, public/app.css; dashboard.md §4.25 "Empty states"):
 * what a fresh install shows before its first agent runs.
 *
 * - A command in a sentence the page writes is `code`, as on the first-run
 *   card: Home › Running now, Home › Where your data lives (its failure and
 *   its "open to others" note), Settings › Protection service.
 * - Approvals › Answered earlier says it could not check while the queue is
 *   unknown, not a bare heading.
 * - A text button (`button.link-btn`, "Add a rule") reads as a link:
 *   app.css gives it the link look at zero specificity, so a text button
 *   with a class of its own keeps that look, and the agent page's anchor
 *   button keeps its hover to itself.
 * - An empty state has one frame: a list holding only its empty state draws
 *   no frame of its own, a note among a list's rows is drawn as a row, and a
 *   list with nothing in it is not drawn (the rules read as text, then
 *   applied in jsdom with the theme's tokens resolved).
 * - A list that could not be read says so, never "none yet", and offers
 *   nothing that needs it: Rules with no protection service (the route's
 *   `available: false` panel) says your rules could not be read, once, and
 *   keeps the way to All files; Settings › Models says why and hides Add;
 *   Settings › Prompt filters hides its Exceptions heading, note and the
 *   meanings with their "What the choices mean" fold (signed out, the fold
 *   stood under the sign-in note and opened on nothing until 2026-10-09).
 *
 * Drives home.js in jsdom over the shared fetch stub (home-js-fixtures.ts);
 * the served page against the real server is
 * test/component/product-empty-states.test.ts. Axes: none (display only).
 * Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { load, tick, home, rulesPage, PUB, FILES_ROUTES } from "./home-js-fixtures.js";
import { declValue, flattenCss, resolveCssVars, stripComments } from "./css-flatten.js";
import { promptSettingsVM } from "../../../src/view-model/prompt-settings.js";
import { labelSettingsVM } from "../../../src/view-model/sensitivity-labels.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const codes = (node: any): string[] => [...node.querySelectorAll("code")].map((c: any) => c.textContent);

test("Running now, no agent: the sentence reads the same, and both commands are code", async () => {
  // Only an idle agent in the window: Running now lists none.
  const idle = home().agents.filter((a) => a.state === "idle");
  const { doc, err } = load({ homeVm: home({ verdict: "quiet", waiting: [], agents: idle }) });
  assert.equal(err, null);
  await tick();
  const empty = doc.querySelector("#home-agents .empty");
  assert.equal(empty.textContent, "No agent is running right now. Start one with mandu claude or mandu codex.");
  assert.deepEqual(codes(empty), ["mandu claude", "mandu codex"]);
});

const LOCATIONS = {
  home: "~/.mandu",
  locations: [
    { name: "events", path: "~/.mandu/events", where: "home", holds: "session history", exists: true, mode: "0755", ownerOnly: false },
    { name: "packs", path: "~/.mandu/packs", where: "home", holds: "rule packs", exists: true, mode: "0755", ownerOnly: false },
  ],
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function openDataWhere(doc: any, window: any): void {
  const d = doc.getElementById("home-data");
  d.open = true;
  d.dispatchEvent(new window.Event("toggle"));
}

test("Where your data lives: the note on open places and the failed load name mandu paths as code", async () => {
  const ok = load({ routes: { "GET data-locations": LOCATIONS } });
  await tick();
  openDataWhere(ok.doc, ok.window);
  await tick();
  const note = ok.doc.getElementById("home-data-open");
  assert.equal(note.hidden, false);
  assert.equal(note.textContent, "Other people on this computer can open 2 places in Mandu's folder. Run mandu paths in a terminal for the command that makes them yours only.");
  assert.deepEqual(codes(note), ["mandu paths"]);

  // Every place owner-only again: the note goes, code and all.
  const tight = load({ routes: { "GET data-locations": { ...LOCATIONS, locations: LOCATIONS.locations.map((l) => ({ ...l, ownerOnly: true })) } } });
  await tick();
  openDataWhere(tight.doc, tight.window);
  await tick();
  assert.equal(tight.doc.getElementById("home-data-open").hidden, true);
  assert.equal(tight.doc.getElementById("home-data-open").textContent, "");

  const bad = load({ routes: { "GET data-locations": { status: 500, body: {} } } });
  await tick();
  openDataWhere(bad.doc, bad.window);
  await tick();
  const empty = bad.doc.querySelector("#home-data-list .empty");
  assert.equal(empty.textContent, "The list could not be loaded. Run mandu paths in a terminal to see it.");
  assert.deepEqual(codes(empty), ["mandu paths"]);
});

test("Settings › Protection service without the service controls: mandu dashboard is code", async () => {
  for (const r of [{ summary: null }, { status: 404, body: { error: "control plane disabled" } }]) {
    const { doc } = load({ url: "http://127.0.0.1:4500/mandu/settings", routes: { "GET control/summary": r } });
    await tick();
    const empty = doc.querySelector("#settings-services .service-none");
    assert.equal(empty.textContent, "This dashboard was started without the service controls. Start it with mandu dashboard to manage the protection service here.");
    assert.deepEqual(codes(empty), ["mandu dashboard"]);
  }
});

test("Approvals › Answered earlier: an unknown queue says it could not check; a known empty one keeps its own line", async () => {
  const url = "http://127.0.0.1:4500/mandu/approvals";
  const unknown = load({ url, homeVm: home({ verdict: "unknown", waitingKnown: false, waiting: [], answered: [] }) });
  await tick();
  assert.equal(unknown.doc.getElementById("approvals-answered").textContent, "Could not check your earlier answers. The protection service may be unreachable.");
  assert.match(unknown.doc.getElementById("approvals-waiting").textContent, /^Could not check for waiting questions\./, "the block above says the same");

  const known = load({ url, homeVm: home({ verdict: "quiet", waitingKnown: true, waiting: [], answered: [] }) });
  await tick();
  assert.equal(known.doc.getElementById("approvals-answered").textContent, "You have not answered anything yet.");
});

test("Rules › Your rules with no file rule yet: Add a rule is a text button that opens the file browser", async () => {
  const { doc } = rulesPage({
    "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [] } },
    "GET secrets": { panel: { labels: [] } },
    ...FILES_ROUTES, // All files opens the agent's folder, ~/ws
  });
  await tick();
  const row = doc.querySelector("#files-tree .empty-row");
  assert.equal(row.textContent, "No file or folder has a rule of yours yet. Add a rule to mark one secret.");
  const btn = row.querySelector("button");
  assert.equal(btn.className, "link-btn", "a bare text button: its look is the base rule's");
  btn.click();
  await tick();
  assert.equal(doc.getElementById("rules-add").getAttribute("aria-expanded"), "true");
  assert.equal(doc.getElementById("lock-form").hidden, false);
  assert.ok(doc.querySelector("#files-list .row.file"), "the folder is listed");
});

const RULES = flattenCss(stripComments(readFileSync(join(PUB, "app.css"), "utf8")));

test("app.css: a text button looks like a link at zero specificity, and underlines on hover", () => {
  const base = RULES.find((r) => r.selectors.includes(":where(button.link-btn)") && r.media === null);
  assert.ok(base, "a :where(button.link-btn) rule: zero specificity, so .rule-source-btn, .file-open, .crumb … keep their own look");
  assert.equal(declValue(base!.block, "color"), "var(--accent)", "the link color (mandu.css a)");
  assert.equal(declValue(base!.block, "border"), "none");
  assert.equal(declValue(base!.block, "background"), "none");
  assert.equal(declValue(base!.block, "padding"), "0");
  const hover = RULES.find((r) => r.selectors.includes(":where(button.link-btn:hover)"));
  assert.ok(hover, "a zero-specificity hover");
  assert.equal(declValue(hover!.block, "color"), "var(--accent-ink)", "as mandu.css a:hover");
  assert.equal(declValue(hover!.block, "text-decoration"), "underline");
});

test("app.css: the anchor button's hover (no underline, ink) applies to anchors only", () => {
  // `.link-btn:hover` once matched every text button and, coming later at the
  // same specificity, beat .rule-source-btn:hover: "Show in policy.yaml"
  // turned ink with no underline.
  const hovers = RULES.flatMap((r) => r.selectors.filter((s) => /\.link-btn:hover/.test(s) && !s.startsWith(":where(")).map((s) => ({ s, block: r.block })));
  assert.ok(hovers.length > 0, "the agent page's Detailed trace keeps its hover");
  for (const h of hovers) assert.match(h.s, /^a\.link-btn:hover$/, `${h.s} must not reach a text button`);
  const own = RULES.find((r) => r.selectors.includes(".rule-source-btn:hover"));
  assert.equal(declValue(own!.block, "text-decoration"), "underline", "the text buttons' own hover stands");
});

test("app.css: an empty state has one frame; a note among rows is a row; an empty list is not drawn", () => {
  const only = RULES.find((r) => r.selectors.includes(".table:has(> .empty:only-child)") && r.media === null);
  assert.ok(only, "a list holding only its empty state has a rule of its own");
  assert.equal(declValue(only!.block, "border"), "none", "the dashed box is the only frame");
  assert.equal(declValue(only!.block, "background"), "none", "on the page, as in a card list");
  const note = RULES.find((r) => r.selectors.includes(".table > .empty:not(:only-child)") && r.media === null);
  assert.ok(note, "a note among a list's rows has a rule of its own");
  const row = RULES.find((r) => r.selectors.includes(".row") && r.media === null);
  assert.equal(declValue(note!.block, "border"), "none", "no dashed box inside the list");
  assert.equal(declValue(note!.block, "border-bottom"), declValue(row!.block, "border-bottom"), "the rows' divider");
  assert.equal(declValue(note!.block, "padding"), declValue(row!.block, "padding"), "the rows' padding");
  const last = RULES.find((r) => r.selectors.includes(".table > .empty:not(:only-child):last-child"));
  assert.equal(declValue(last!.block, "border-bottom"), "none", "the last one has no divider, as .row:last-child");
  const none = RULES.find((r) => r.selectors.includes(".table:empty"));
  assert.equal(declValue(none!.block, "display"), "none", "an empty list draws no stray line");
});

/** The product page's own styles, applied, with the theme's tokens resolved
 *  (jsdom reads `border: 1px dashed var(--line)` as no border at all). */
const STYLES = resolveCssVars(readFileSync(join(PUB, "mandu.css"), "utf8") + "\n" + readFileSync(join(PUB, "app.css"), "utf8"));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function styled(doc: any): (e: any) => any {
  const s = doc.createElement("style");
  s.textContent = STYLES;
  doc.head.append(s);
  return (e) => doc.defaultView.getComputedStyle(e);
}
const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";

test("Settings › Prompt filters: its notes are rows of the list, and No exceptions has one frame", async () => {
  const vm = promptSettingsVM({
    filters: [{ id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] }],
    actions: [
      { category: "secret.registered", action: "mask", setBy: "default", locked: false },
      { category: "pii.email", action: "redact", setBy: "you", locked: false },
    ],
    fallback: "redact", exceptions: [], enforcing: false, editable: false,
  });
  const { doc } = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings: vm } } });
  await tick();
  const css = styled(doc);
  const kinds = doc.getElementById("settings-prompt-kinds");
  assert.ok(kinds.querySelector(".row.prompt-kind"), "the kinds are listed");
  assert.equal(css(kinds).borderTopStyle, "solid", "a list with rows keeps its frame");
  for (const cls of ["prompt-readonly", "prompt-off"]) {
    const n = kinds.querySelector("." + cls);
    assert.ok(n, `the ${cls} note is shown`);
    assert.equal(css(n).borderTopStyle, "none", `${cls}: no dashed box inside the list`);
    assert.equal(css(n).borderBottomStyle, "solid", `${cls}: the rows' divider`);
    assert.equal(css(n).paddingTop, "14px", `${cls}: the rows' padding`);
  }
  const ex = doc.getElementById("settings-prompt-exceptions");
  assert.equal(ex.textContent, "No exceptions. Everything Mandu finds gets the choice above.");
  assert.equal(css(ex).borderTopStyle, "none", "the list draws no frame around its empty state");
  assert.equal(css(ex).backgroundColor, "rgba(0, 0, 0, 0)", "nor a fill");
  assert.equal(css(ex.firstElementChild).borderTopStyle, "dashed", "the empty state's own frame is the one");
});

test("Settings › Sensitivity labels: a note under the rows is the last row, with no divider under it", async () => {
  const vm = labelSettingsVM(
    { sensitivity_labels: [{ id: "9fbde396-1a24-4c79-8edf-9254a0f35055", name: "Highly Confidential", level: "no-model" }] },
    {},
    { labels: { unmapped: [], unmappedMore: 0 }, at: 1 },
  );
  const { doc } = load({ url: SETTINGS_URL, routes: { "GET policy/sensitivity-labels": { labels: { ...vm, note: "Every sensitivity label the last scan found has a level." } } } });
  await tick();
  const css = styled(doc);
  const note = doc.querySelector("#settings-labels .labels-note");
  assert.ok(note && note.previousElementSibling?.classList.contains("label-row"), "the note follows the label's row");
  assert.equal(css(note).borderTopStyle, "none");
  assert.equal(css(note).borderBottomStyle, "none", "the list's own frame closes it");
  assert.equal(css(doc.getElementById("settings-labels")).borderTopStyle, "solid", "the list keeps its frame");
});

test("Settings › Prompt filters, refused: the refusal has one frame and the empty Exceptions list draws nothing", async () => {
  const { doc } = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { status: 403, body: { error: "Sign in to the dashboard first." } } } });
  await tick();
  const css = styled(doc);
  const kinds = doc.getElementById("settings-prompt-kinds");
  assert.equal(kinds.textContent, "Sign in to the dashboard first.");
  assert.equal(css(kinds).borderTopStyle, "none", "no frame around the refusal's own");
  assert.equal(css(kinds.firstElementChild).borderTopStyle, "dashed");
  const ex = doc.getElementById("settings-prompt-exceptions");
  assert.equal(ex.childNodes.length, 0, "nothing could be read, so nothing is listed");
  assert.equal(css(ex).display, "none", "not a stray line under the Exceptions heading");
});

// ── A list that could not be read says so (dashboard.md §4.25 "Empty states") ─

/** What /api/policy/panel answers with no protection service: the server's
 *  own projection of no snapshot, `available: false` and no rules. */
const UNREAD_PANEL = { panel: toPolicyPanelViewModel(null) };

test("Rules with no protection service: your rules could not be read, never \"no rules\"; add a rule still opens the file browser", async () => {
  assert.equal(UNREAD_PANEL.panel.available, false, "the route's shape with no service");
  const { doc } = rulesPage({ "GET policy/panel": UNREAD_PANEL, "GET secrets": { panel: { labels: [] } }, ...FILES_ROUTES });
  await tick();
  const row = doc.querySelector("#files-tree .empty-row");
  assert.equal(row.textContent, "Your rules could not be read. The protection service may be unreachable. You can still add a rule.");
  assert.equal(doc.getElementById("rules-list").hidden, true, "the list below says nothing rather than the same sentence again");
  assert.doesNotMatch(doc.getElementById("page-rules").textContent, /No rules yet|No file or folder has a rule of yours yet/);
  const btn = row.querySelector("button");
  assert.equal(btn.className, "link-btn", "a text button, drawn as a link");
  btn.click();
  await tick();
  assert.equal(doc.getElementById("rules-add").getAttribute("aria-expanded"), "true");
  assert.ok(doc.querySelector("#files-list .row.file"), "the folder is listed");

  // Read and empty: the page's own "none yet" sentences stand.
  const empty = rulesPage({ "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [] } }, "GET secrets": { panel: { labels: [] } } });
  await tick();
  assert.equal(empty.doc.querySelector("#files-tree .empty-row").textContent, "No file or folder has a rule of yours yet. Add a rule to mark one secret.");
  assert.equal(empty.doc.getElementById("rules-list").hidden, true, "no other group to show: the one sentence above says it");
});

test("Settings › Models, unread: it says why, offers no Add, and an open form closes; read again, Add is back", async () => {
  const MODEL = { name: "ollama", url: "http://127.0.0.1:11434", wire: "anthropic", local: true };
  let reads = 0;
  const { doc } = load({ url: SETTINGS_URL, routes: {
    // Read once, then the service goes away.
    "GET policy/panel": () => (++reads === 1 ? { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [], models: [MODEL] } } : UNREAD_PANEL),
    "POST policy/models/change": { applied: true, changeId: "pc-000001", note: "" },
  } });
  await tick();
  const open = doc.getElementById("model-open");
  assert.equal(open.hidden, false, "a list that was read offers Add");
  open.click();
  assert.equal(doc.getElementById("model-form").hidden, false);
  doc.querySelector("#settings-models .model-remove-btn").click();
  await tick(20);
  assert.equal(reads, 2, "the list was read again after the change");
  assert.equal(doc.getElementById("settings-models").textContent, "The model list could not be read. The protection service may be unreachable.");
  assert.equal(open.hidden, true, "nothing to add to");
  assert.equal(doc.getElementById("model-form").hidden, true, "the open form closed");
  assert.equal(open.getAttribute("aria-expanded"), "false");

  const back = load({ url: SETTINGS_URL, routes: { "GET policy/panel": { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [], models: [] } } } });
  await tick();
  assert.equal(back.doc.getElementById("model-open").hidden, false);
});

test("Settings › Prompt filters, unread: the refusal alone, no Exceptions heading, note, meanings or their fold; read, they are back", async () => {
  const parts = ["settings-prompt-meanings-fold", "settings-prompt-meanings", "settings-prompt-exceptions-head", "settings-prompt-exceptions-about", "settings-prompt-exceptions"];
  const refused = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { status: 403, body: { error: "admin session required: open the login link" } } } });
  await tick();
  assert.equal(refused.doc.getElementById("settings-prompt-kinds").textContent, "Sign in first: in your own terminal, run mandu dashboard and open the sign-in link it prints (each link works once), or sign in with the dashboard's password if it has one.");
  assert.deepEqual(codes(refused.doc.getElementById("settings-prompt-kinds")), ["mandu dashboard"]);
  for (const id of parts) assert.equal(refused.doc.getElementById(id).hidden, true, `${id} hidden`);
  assert.equal(refused.doc.getElementById("prompt-exception-form").hidden, true);
  // A service that cannot give the filters: the server's own projection,
  // `available: false` with its note (and the meanings, which stay hidden).
  const old = promptSettingsVM(null);
  assert.equal(old.available, false);
  const off = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings: old } } });
  await tick();
  assert.equal(off.doc.getElementById("settings-prompt-kinds").textContent, old.note);
  for (const id of parts) assert.equal(off.doc.getElementById(id).hidden, true, `${id} hidden`);
  assert.equal(off.doc.querySelector("#settings-prompt-meanings dt"), null, "no meanings listed");

  const vm = promptSettingsVM({
    filters: [{ id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] }],
    actions: [{ category: "secret.registered", action: "mask", setBy: "default", locked: false }],
    fallback: "redact", exceptions: [], enforcing: true, editable: true,
  });
  const read = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings: vm } } });
  await tick();
  for (const id of parts) assert.equal(read.doc.getElementById(id).hidden, false, `${id} shown`);
  assert.equal(read.doc.getElementById("settings-prompt-exceptions-head").textContent, "Exceptions");
  assert.ok(read.doc.querySelector("#settings-prompt-meanings dt"), "the meanings are listed");
  assert.equal(read.doc.querySelector("#settings-prompt-meanings-fold > summary").textContent, "What the choices mean");
});

test("Settings › Prompt filters, signed out: no \"What the choices mean\" under the sign-in note; a fold with no meanings is never drawn", async () => {
  // Signed out, the route refuses (403). The fold used to stay, a link
  // under the sign-in note that opened on nothing.
  const out = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { status: 403, body: { error: "admin session required: open the login link" } } } });
  await tick();
  const block = out.doc.getElementById("settings-prompt-block");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const drawn = [...block.querySelectorAll("summary")].filter((s: any) => !s.closest("[hidden]")).map((s: any) => s.textContent);
  assert.deepEqual(drawn, ["More"], "only the block's own More is drawn");
  assert.equal(out.doc.getElementById("settings-prompt-meanings-fold").hidden, true);

  // Read, from a server that sends no meanings: the kinds are drawn, and
  // the fold, with nothing to open on, is not.
  const vm = promptSettingsVM({
    filters: [{ id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] }],
    actions: [{ category: "secret.registered", action: "mask", setBy: "default", locked: false }],
    fallback: "redact", exceptions: [], enforcing: true, editable: true,
  });
  const bare = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings: { ...vm, meanings: [] } } } });
  await tick();
  assert.ok(bare.doc.querySelector("#settings-prompt-kinds .prompt-kind"), "the kinds are drawn");
  assert.equal(bare.doc.getElementById("settings-prompt-meanings-fold").hidden, true, "no fold with nothing in it");
  assert.equal(bare.doc.getElementById("settings-prompt-exceptions-head").hidden, false, "the Exceptions heading stays");

  // And back with meanings: the fold returns.
  const read = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings: vm } } });
  await tick();
  assert.equal(read.doc.getElementById("settings-prompt-meanings-fold").hidden, false);
  assert.equal(read.doc.querySelectorAll("#settings-prompt-meanings dt").length, vm.meanings.length);
});
