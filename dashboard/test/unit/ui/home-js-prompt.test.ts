/**
 * home-js-prompt.test — plan 15 phase 4 on the PRODUCT page
 * (public/js/home.js; confidentiality-plan-15-prompt-filter.md §13.7;
 * dashboard.md §4.25y), in jsdom over the shared fetch stub
 * (home-js-fixtures.ts) with the server's own view model
 * (view-model/prompt-settings.ts).
 *
 * Pins, Settings › Prompt filters: the listing carries the page's control
 * header; each kind in plain words with its choice (a select), who set it,
 * and a locked kind's file; one locked at the strictest is words only; a
 * choice sends ONE typed edit; a change that lets more through is asked
 * about first, then resent with what was shown; a refusal (a lock) is said
 * on the row; Use the default and Remove send their edit; the add form sends
 * `add-prompt-exception`; read only shows no control; server text is text.
 * The note over Exceptions says how to write one only over the form that
 * takes one; with no kind an exception may name (a default install: the
 * secrets Mandu knows alone), why none can be added, in the server's words
 * (2026-10-16; it taught a `*` pattern for a form it did not draw). Under
 * that reason the empty list says only "No exceptions.", since the reason
 * already says what happens to what Mandu finds (2026-10-16, nightly run 1130).
 *
 * Pins, the note under your message: its lines under "You asked"; "Let it
 * through" asks, then posts the finding's event and index to the
 * let-through route; "Show what was hidden" posts the same names to the
 * reveal route and shows the answer as text; a message that never reached
 * the AI is its own card, placed by time; no symbol anywhere on the page.
 * A finding under a locked administrator's row that is not `ask` has no
 * let-through button and says why (`lockedWhy`, work ledger P1, 2026-10-07).
 *
 * Pins, Try a message (dashboard.md §4.25y *Try a message*): the fold posts
 * the typed text alone to the try route with the page's control header;
 * each found span of the typed text is marked and its line names the kind
 * (the server's words) and what would happen to it; no finding says
 * "Nothing in it …"; protection off says Mandu would only note these; an
 * exception in force is said under the answer; a refusal is drawn as text;
 * the fold is hidden while the card is unread; server text is text and no
 * `$MDU:` string reaches the page, even one the server sent by mistake.
 * The answer follows the card (*The answer follows the card*, queue item
 * #255): a change made on it (a kind's choice, its Undo, an exception added)
 * asks again for the text that was tried, not the box's, and redraws in
 * place; with no answer drawn, or a refusal, nothing is asked; a re-ask that
 * fails keeps the answer with one line saying it is from before the change,
 * never an error; a change while Try it is out asks again once it answers,
 * and never leaves Try it off; Ctrl+Enter / Cmd+Enter press Try it.
 *
 * Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, load, tick } from "./home-js-fixtures.js";
import { promptSettingsVM, type PromptFiltersProjection } from "../../../src/view-model/prompt-settings.js";

const SETTINGS_URL = "http://127.0.0.1:4500/mandu/settings";
const PROJ: PromptFiltersProjection = {
  filters: [
    { id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] },
    { id: "acme-dlp", on: true, categories: [{ category: "acme.<b>codename</b>", action: "redact" }] },
  ],
  actions: [
    { category: "secret.registered", action: "mask", setBy: "default", locked: false },
    { category: "secret.shape", action: "redact", setBy: "administrator", locked: true, file: "/etc/mandu/policy.d/10-org.yaml" },
    { category: "pii.payment-card", action: "block", setBy: "administrator", locked: true, file: "/etc/mandu/policy.d/20-cards.yaml" },
    { category: "pii.email", action: "redact", setBy: "you", locked: false },
  ],
  fallback: "redact",
  exceptions: [
    { category: "pii.email", match: "*@example.com", setBy: "you", inForce: true },
    { category: "acme.<b>codename</b>", match: "public-*", setBy: "administrator", file: "/etc/mandu/policy.d/10-org.yaml", inForce: true },
  ],
  enforcing: true,
  editable: true,
};
const VM = promptSettingsVM(PROJ);
const kindRow = (doc: any, cat: string) => ([...doc.querySelectorAll("#settings-prompt-kinds .prompt-kind")] as any[]).find((r) => r.dataset.category === cat);

test("Settings › Prompt filters: each kind with its choice and who set it; a lock names its file; server text is text", async () => {
  const { doc, calls } = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings: VM } } });
  await tick();
  const get = calls.find((c) => c.url === "/mandu/api/policy/prompt-filters");
  assert.equal(get?.headers["X-Mandu-Control"], "1", "the listing carries the page's control header");
  const reg = kindRow(doc, "secret.registered");
  assert.equal(reg.querySelector(".name").textContent, "A secret Mandu already knows");
  assert.equal(reg.querySelector("select.prompt-action").value, "mask");
  assert.deepEqual([...reg.querySelectorAll("option")].map((o: any) => o.textContent), ["Hide it", "Remove it", "Ask me", "Block the message", "Just note it"]);
  assert.equal(reg.querySelector(".prompt-reset-btn"), null, "no Reset on Mandu's default");
  const shape = kindRow(doc, "secret.shape");
  assert.match(shape.textContent, /Locked by your administrator \(10-org\.yaml\)\./);
  assert.ok(![...shape.querySelectorAll("option")].some((o: any) => o.value === "log"), "never weaker than the lock");
  const card = kindRow(doc, "pii.payment-card");
  assert.equal(card.querySelector("select"), null, "locked at the strictest: nothing to choose");
  assert.match(card.textContent, /Block the message/);
  assert.match(card.textContent, /20-cards\.yaml/);
  const org = kindRow(doc, "acme.<b>codename</b>");
  assert.equal(org.querySelector(".name code").textContent, "acme.<b>codename</b>", "an organization's kind as written, as text");
  assert.equal(doc.querySelector("#page-settings b"), null);
  assert.match(doc.getElementById("settings-prompt-meanings").textContent, /Hide itThe AI gets a short code in its place/);
  const exc = [...doc.querySelectorAll("#settings-prompt-exceptions .prompt-exception")] as any[];
  assert.equal(exc.length, 2);
  assert.ok(exc[0].querySelector(".prompt-exception-remove"));
  assert.equal(exc[1].querySelector("button"), null, "the administrator's exception is read only");
  assert.match(exc[1].textContent, /Set by your administrator \(10-org\.yaml\)/);
  assert.equal(doc.getElementById("prompt-exception-form").hidden, false);
  assert.deepEqual([...doc.querySelectorAll("#prompt-exception-kind option")].map((o: any) => o.value), ["pii.email", "acme.<b>codename</b>"],
    "no registered secret, no locked kind");
  assert.match(doc.getElementById("settings-prompt-dev").getAttribute("href"), /\/mandu\/dev\/rules$/);
});

test("a choice sends one typed edit; a relaxation asks first, under the row, and Apply anyway resends what was shown; a lock's refusal is said on the row", async () => {
  const posts: any[] = [];
  const page = load({ url: SETTINGS_URL, routes: {
    "GET policy/prompt-filters": { settings: VM },
    "POST policy/prompt-filters/change": (b: any) => {
      posts.push(b);
      if (b.edit.category === "secret.shape") return { status: 422, body: { error: "This prompt filter change is not valid.", problems: ["secret.shape is set by your administrator (/etc/mandu/policy.d/10-org.yaml) as redact; mask would relax it"] } };
      if (b.edit.action === "log" && !b.expected) {
        return { applied: false, confirm: true, expected: ["k"], rows: [[{ kind: "text", text: "In your prompts, " }, { kind: "code", text: "secret.registered" }, { kind: "text", text: " is only recorded" }]], wouldLet: [[{ kind: "text", text: "Your prompts would carry more to the AI" }]], warnings: [] };
      }
      return { applied: true, changeId: "pc-9" };
    },
  } });
  await tick();
  const sel = kindRow(page.doc, "secret.registered").querySelector("select");
  sel.value = "block";
  sel.dispatchEvent(new page.window.Event("change"));
  await tick();
  assert.deepEqual(posts.shift(), { edit: { op: "set-prompt-action", category: "secret.registered", action: "block" } });
  assert.equal(page.doc.querySelector("#settings-prompt-kinds .ask-in-place"), null, "a tightening is not asked about");
  assert.match(page.doc.getElementById("prompt-notice").textContent, /A secret Mandu already knows: Block the message\. It applies to your next message\.Undo/);

  const sel2 = kindRow(page.doc, "secret.registered").querySelector("select");
  sel2.value = "log";
  sel2.dispatchEvent(new page.window.Event("change"));
  await tick();
  const box = kindRow(page.doc, "secret.registered").nextElementSibling;
  assert.ok(box.classList.contains("ask-in-place"), "asked under the row");
  assert.equal(box.querySelector(".ask-in-place-words").textContent, "In your prompts, secret.registered is only recorded.");
  assert.deepEqual([...box.querySelectorAll(".ask-in-place-list li")].map((li: any) => li.textContent), ["Your prompts would carry more to the AI"]);
  assert.deepEqual([...box.querySelectorAll("button")].map((b: any) => b.textContent), ["Apply anyway", "Cancel"]);
  assert.equal(posts.length, 1, "nothing more until Apply anyway");
  box.querySelector(".ask-in-place-yes").click();
  await tick();
  assert.deepEqual(posts.splice(0), [
    { edit: { op: "set-prompt-action", category: "secret.registered", action: "log" } },
    { edit: { op: "set-prompt-action", category: "secret.registered", action: "log" }, expected: ["k"] },
  ]);

  const shape = kindRow(page.doc, "secret.shape").querySelector("select");
  shape.value = "mask";
  shape.dispatchEvent(new page.window.Event("change"));
  await tick();
  assert.match(kindRow(page.doc, "secret.shape").textContent, /set by your administrator \(\/etc\/mandu\/policy\.d\/10-org\.yaml\)/);
});

test("Cancel at the question changes nothing; Use the default, Remove and Add send their edits", async () => {
  const posts: any[] = [];
  const page = load({ url: SETTINGS_URL, routes: {
    "GET policy/prompt-filters": { settings: VM },
    "POST policy/prompt-filters/change": (b: any) => (posts.push(b), b.edit.op === "add-prompt-exception" && !b.expected
      ? { applied: false, confirm: true, expected: ["x"], rows: [[{ kind: "text", text: "Let it through" }]], wouldLet: [], warnings: [] }
      : { applied: true, changeId: "pc-1" }),
  } });
  await tick();
  const form = page.doc.getElementById("prompt-exception-form");
  const match = page.doc.getElementById("prompt-exception-match") as any;
  match.value = "*@corp.example";
  (page.doc.getElementById("prompt-exception-kind") as any).value = "pii.email";
  form.dispatchEvent(new page.window.Event("submit", { cancelable: true }));
  await tick();
  // Asked in the form, above its button (dashboard.md §4.25n).
  let box = form.querySelector(".ask-in-place");
  assert.equal(box.nextElementSibling, form.querySelector(".form-actions"));
  assert.equal(box.querySelector(".ask-in-place-words").textContent, "Let it through.");
  [...box.querySelectorAll("button")].find((b: any) => b.textContent === "Cancel").click();
  await tick();
  assert.deepEqual(posts.splice(0), [{ edit: { op: "add-prompt-exception", category: "pii.email", match: "*@corp.example" } }], "Cancel: not resent");
  assert.equal(form.querySelector(".ask-in-place"), null);
  assert.equal(match.value, "*@corp.example", "Cancel keeps what was typed");
  form.dispatchEvent(new page.window.Event("submit", { cancelable: true }));
  await tick();
  box = form.querySelector(".ask-in-place");
  box.querySelector(".ask-in-place-yes").click();
  await tick();
  assert.deepEqual(posts.splice(0).map((p) => p.expected ?? null), [null, ["x"]]);
  assert.equal(match.value, "", "added: the box is empty again");
  kindRow(page.doc, "pii.email").querySelector(".prompt-reset-btn").click();
  await tick();
  assert.deepEqual(posts.splice(0), [{ edit: { op: "remove-prompt-action", category: "pii.email" } }]);
  page.doc.querySelector("#settings-prompt-exceptions .prompt-exception-remove").click();
  await tick();
  assert.deepEqual(posts.splice(0), [{ edit: { op: "remove-prompt-exception", category: "pii.email", match: "*@example.com" } }]);
});

test("read only: no control at all, and the page says why; an unreadable listing says so", async () => {
  const ro = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings: promptSettingsVM({ ...PROJ, editable: false }) } } });
  await tick();
  assert.equal(ro.doc.querySelector("#settings-prompt-kinds select, #settings-prompt-kinds button, #settings-prompt-exceptions button"), null);
  assert.match(ro.doc.getElementById("settings-prompt-kinds").textContent, /cannot be changed from this page/);
  assert.equal(ro.doc.getElementById("prompt-exception-form").hidden, true);
  const bad = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { status: 403, body: { error: "Sign in to the dashboard first." } } } });
  await tick();
  assert.match(bad.doc.getElementById("settings-prompt-kinds").textContent, /Sign in to the dashboard first\./);
});

/** What a reader sees of an element: its text without the hidden parts. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const shownText = (node: any): string => {
  const copy = node.cloneNode(true);
  for (const h of [...copy.querySelectorAll("[hidden]")] as any[]) h.remove();
  return copy.textContent.replace(/\s+/g, " ").trim();
};
/** A default install's listing: the built-in rows alone, so the one kind is
 *  a registered secret (arbiter/prompt-filter/policy.ts DEFAULT_ON). */
const DEFAULT_VM = promptSettingsVM({
  filters: [{ id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] }],
  actions: [{ category: "secret.registered", action: "mask", setBy: "default", locked: false }],
  fallback: "redact", exceptions: [], enforcing: true, editable: true,
});
const ABOUT = "What matches an exception goes to the AI as you wrote it.";

test("Exceptions: how to write one only over the form; with no kind it may name, why not instead; read only, neither", async () => {
  // A default install: no form, so no pattern to learn; the reason instead.
  const plain = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings: DEFAULT_VM } } });
  await tick();
  const about = plain.doc.getElementById("settings-prompt-exceptions-about");
  assert.equal(plain.doc.getElementById("prompt-exception-form").hidden, true);
  assert.equal(plain.doc.getElementById("settings-prompt-exceptions-head").hidden, false, "the heading stays over the list");
  assert.equal(plain.doc.getElementById("settings-prompt-exceptions-how").hidden, true);
  assert.equal(plain.doc.getElementById("settings-prompt-exceptions-why").hidden, false);
  assert.equal(shownText(about), `${ABOUT} Exceptions are not offered for a secret Mandu already knows: the choice above decides what happens to it.`);
  assert.doesNotMatch(shownText(plain.doc.getElementById("settings-prompt-block")), /for any text|\*@example\.com/, "no pattern taught for a form that is not there");
  assert.equal(shownText(plain.doc.getElementById("settings-prompt-exceptions")), "No exceptions.", "the reason says what happens: the empty line does not say it again");

  // With the form: how to write one, and no reason.
  const full = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings: VM } } });
  await tick();
  assert.equal(full.doc.getElementById("prompt-exception-form").hidden, false);
  assert.equal(full.doc.getElementById("settings-prompt-exceptions-how").hidden, false);
  assert.equal(full.doc.getElementById("settings-prompt-exceptions-why").hidden, true);
  assert.equal(full.doc.getElementById("settings-prompt-exceptions-why").textContent, "");
  assert.equal(shownText(full.doc.getElementById("settings-prompt-exceptions-about")), `${ABOUT} Use a * for any text, as in *@example.com.`);
  assert.deepEqual([...full.doc.querySelectorAll("#settings-prompt-exceptions-how code")].map((c: any) => c.textContent), ["*", "*@example.com"]);

  // Read only: the first sentence alone (the note above the kinds says why).
  const ro = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings: promptSettingsVM({ ...PROJ, editable: false }) } } });
  await tick();
  assert.equal(shownText(ro.doc.getElementById("settings-prompt-exceptions-about")), ABOUT);

  // The server's words are text.
  const odd = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings: { ...DEFAULT_VM, exceptionNotOffered: "<b>Not</b> offered." } } } });
  await tick();
  assert.equal(odd.doc.getElementById("settings-prompt-exceptions-why").textContent, "<b>Not</b> offered.");
  assert.equal(odd.doc.querySelector("#settings-prompt-exceptions-about b"), null);
  // An older server sends no reason: the how-to still goes with the form.
  const { exceptionNotOffered: _gone, ...older } = DEFAULT_VM;
  const old = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings: older } } });
  await tick();
  assert.equal(shownText(old.doc.getElementById("settings-prompt-exceptions-about")), ABOUT);
});

const FULL_EMPTY = "No exceptions. Everything Mandu finds gets the choice above.";

test("Exceptions: under a reason the empty list says only that it is empty; with the form, read only or no reason, the full line", async () => {
  const shown = async (settings: unknown) => {
    const p = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings } } });
    await tick();
    return {
      list: shownText(p.doc.getElementById("settings-prompt-exceptions")),
      empties: p.doc.querySelectorAll("#settings-prompt-exceptions .empty").length,
      about: shownText(p.doc.getElementById("settings-prompt-exceptions-about")),
    };
  };
  // Each reason the server gives: the reason once, then "No exceptions."
  const lockedShape = { category: "secret.shape", action: "redact", setBy: "administrator", locked: true, file: "/etc/mandu/policy.d/10-org.yaml" };
  const both = promptSettingsVM({
    filters: [
      { id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] },
      { id: "key-shapes", on: true, categories: [{ category: "secret.shape", action: "redact" }] },
    ],
    actions: [{ category: "secret.registered", action: "mask", setBy: "default", locked: false }, lockedShape],
    fallback: "redact", exceptions: [], enforcing: true, editable: true,
  });
  for (const vm of [DEFAULT_VM, both,
    { ...DEFAULT_VM, exceptionNotOffered: "Your administrator locked every kind above, so none can have an exception." },
    { ...DEFAULT_VM, exceptionNotOffered: "There is no kind to add an exception for." }]) {
    assert.ok(vm.exceptionNotOffered, "a reason is given");
    const s = await shown(vm);
    assert.equal(s.about, `${ABOUT} ${vm.exceptionNotOffered}`);
    assert.equal(s.list, "No exceptions.", vm.exceptionNotOffered);
    assert.equal(s.empties, 1, "one empty line");
  }
  // With the form, no reason: the empty line says what happens.
  assert.equal((await shown({ ...VM, exceptions: [] })).list, FULL_EMPTY);
  // Read only: no reason either (the note above the kinds says why).
  assert.equal((await shown(promptSettingsVM({ ...PROJ, exceptions: [], editable: false }))).list, FULL_EMPTY);
  // An older server sends no reason: as before.
  const { exceptionNotOffered: _gone, ...older } = DEFAULT_VM;
  assert.equal((await shown(older)).list, FULL_EMPTY);
  // A reason over exceptions that are there (written before a lock): the
  // rows, and no empty line.
  const kept = await shown({ ...DEFAULT_VM, exceptions: VM.exceptions.slice(0, 1) });
  assert.equal(kept.empties, 0);
  assert.match(kept.list, /\*@example\.com/);
  assert.doesNotMatch(kept.list, /No exceptions/);
});

test("Exceptions: a read that brings the form (or takes it away) swaps the how-to and the reason", async () => {
  const reads = [DEFAULT_VM, { ...VM, exceptions: [] }, DEFAULT_VM];
  const page = load({ url: SETTINGS_URL, routes: {
    "GET policy/prompt-filters": () => ({ settings: reads.length > 1 ? reads.shift() : reads[0] }),
    "POST policy/prompt-filters/change": () => ({ applied: true, changeId: "pc-2" }),
  } });
  await tick();
  const about = page.doc.getElementById("settings-prompt-exceptions-about");
  const list = page.doc.getElementById("settings-prompt-exceptions");
  assert.match(shownText(about), /are not offered/);
  assert.equal(shownText(list), "No exceptions.");
  // A change, then the section is read again: now a kind may have one.
  const sel = kindRow(page.doc, "secret.registered").querySelector("select");
  sel.value = "block";
  sel.dispatchEvent(new page.window.Event("change"));
  await tick();
  assert.equal(page.doc.getElementById("prompt-exception-form").hidden, false);
  assert.equal(shownText(about), `${ABOUT} Use a * for any text, as in *@example.com.`);
  assert.equal(shownText(list), FULL_EMPTY, "no reason now: the empty line says what happens");
  // And back: the form goes, the reason returns, the how-to with the form.
  const again = kindRow(page.doc, "secret.registered").querySelector("select");
  again.value = "mask";
  again.dispatchEvent(new page.window.Event("change"));
  await tick();
  assert.equal(page.doc.getElementById("prompt-exception-form").hidden, true);
  assert.equal(shownText(about), `${ABOUT} Exceptions are not offered for a secret Mandu already knows: the choice above decides what happens to it.`);
  assert.equal(shownText(list), "No exceptions.");
  assert.equal(list.querySelectorAll(".empty").length, 1, "redrawn, not added to");
});

// ── The note under your message ──────────────────────────────────────────────

const NOTE = {
  lines: ["One value in your prompt was hidden from the AI (an email address).", "One value in your prompt was hidden from the AI (a secret Mandu already knows)."],
  items: [
    { eventId: "ev-<i>1</i>", index: 0, category: "pii.email", words: "an email address", state: "hidden", canLetOnce: true, canLetSession: true, canShow: true },
    { eventId: "ev-1", index: 1, category: "secret.registered", words: "a secret Mandu already knows", state: "hidden", canLetOnce: false, canLetSession: false, canShow: false },
  ],
  ts: "2026-09-25T10:00:00.000Z",
};
const UNSENT = { lines: ["Your message was not sent to the AI: it holds a card number."], items: [], ts: "2026-09-25T10:00:30.000Z" };
const AGENT_WITH_NOTES = {
  ...AGENT,
  story: [{ ...AGENT.story[0], promptNote: NOTE }, { ...AGENT.story[1], promptNote: null }],
  unplacedNotes: [UNSENT],
};
const AGENT_URL = "http://127.0.0.1:4500/mandu/agents/s1";
/** Let it through on a note's row: its button opens the question in the
 *  row (dashboard.md §4.25y), and the question's own Let it through sends. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function letThrough(item: any, which: ".prompt-let-once" | ".prompt-let-session"): Promise<void> {
  item.querySelector(which).click();
  await tick();
  item.querySelector(".ask-in-place .ask-in-place-yes").click();
  await tick();
}

test("the note: its lines under your message; Let it through asks in the note, then names the finding to the let-through route", async () => {
  const posts: any[] = [];
  const page = load({ url: AGENT_URL, routes: {
    "GET home/agent?session=s1": AGENT_WITH_NOTES,
    "POST prompt-filters/let-through": (b: any) => (posts.push(b), { approval: { id: "egr-3" }, scope: b.scope }),
  } });
  await tick();
  const turn = page.doc.querySelector('#agent-story article.turn[data-turn-id="turn:i1"]');
  const note = turn.querySelector(".turn-q .prompt-note");
  assert.ok(note, "the note sits under the question");
  assert.deepEqual([...note.querySelectorAll(".prompt-note-line")].map((l: any) => l.textContent), NOTE.lines);
  const items = [...note.querySelectorAll(".prompt-note-item")] as any[];
  assert.equal(items.length, 1, "a finding with nothing to do shows no row");
  assert.match(items[0].textContent, /^An email address/);
  const session = items[0].querySelector(".prompt-let-session");
  session.focus();
  session.click();
  await tick();
  const box = items[0].querySelector(".ask-in-place");
  assert.ok(box, "asked in the row of the note");
  assert.equal(box.querySelector(".ask-in-place-words").textContent,
    "Let an email address through for the rest of this session? The AI reads it as you wrote it in every message of this session.");
  assert.equal(page.doc.activeElement, box.querySelector(".ask-in-place-words"), "the sentence has the focus, never Let it through");
  assert.deepEqual([...box.querySelectorAll("button")].map((b: any) => b.textContent), ["Let it through", "Cancel"]);
  assert.deepEqual(posts, [], "nothing is sent until the second press");
  box.querySelector(".ask-in-place-yes").click();
  await tick();
  assert.deepEqual(posts, [{ session: "s1", eventId: "ev-<i>1</i>", index: 0, scope: "session" }]);
  assert.equal(items[0].querySelector(".ask-in-place"), null, "the question goes");
  assert.equal(items[0].querySelector(".prompt-let-once"), null, "answered: the buttons go");
  assert.match(items[0].textContent, /Let through for this session\./);
  assert.equal(page.doc.querySelector("#agent-story i"), null);
  assert.ok(!page.doc.body.textContent.includes("$MDU:"));
});

test("the note: a poll that draws the story again keeps the question in the row, its sentence holding the focus", async () => {
  let reads = 0;
  const page = load({ url: AGENT_URL, routes: {
    // Each read differs (a field the page does not show), so each poll
    // draws the story again.
    "GET home/agent?session=s1": () => ({ ...AGENT_WITH_NOTES, read: ++reads }),
  } });
  await tick();
  const once = page.doc.querySelector("#agent-story .prompt-note-item .prompt-let-once");
  once.focus();
  once.click();
  await tick();
  const before = page.doc.querySelector("#agent-story .ask-in-place");
  const was = reads;
  Object.defineProperty(page.doc, "visibilityState", { value: "visible", configurable: true });
  page.doc.dispatchEvent(new page.window.Event("visibilitychange"));
  await tick(40);
  assert.ok(reads > was, "the poll read the page");
  const after = page.doc.querySelector("#agent-story .prompt-note-item .ask-in-place");
  assert.ok(after, "the question is drawn again");
  assert.notEqual(after, before, "in the new story");
  assert.equal(page.doc.activeElement, after.querySelector(".ask-in-place-words"), "the focus on its sentence again");
});

test("the note: Cancel and Escape change nothing; a refusal is said; Show what was hidden fetches the original on a click, as text", async () => {
  const posts: any[] = [];
  const page = load({ url: AGENT_URL, routes: {
    "GET home/agent?session=s1": AGENT_WITH_NOTES,
    "POST prompt-filters/let-through": (b: any) => (posts.push(b), { status: 409, body: { error: "this finding cannot be let through" } }),
    "POST prompt-filters/reveal": (b: any) => (posts.push(b), { original: "<img src=x onerror=alert(1)>me@corp.example" }),
  } });
  await tick();
  const item = page.doc.querySelector("#agent-story .prompt-note-item");
  const once = item.querySelector(".prompt-let-once");
  once.focus();
  once.click();
  await tick();
  assert.equal(item.querySelector(".ask-in-place-words").textContent,
    "Let an email address through in this message? The AI reads it as you wrote it from the agent's next request on.");
  [...item.querySelectorAll(".ask-in-place button")].find((b: any) => b.textContent === "Cancel").click();
  await tick();
  assert.equal(item.querySelector(".ask-in-place"), null);
  assert.equal(page.doc.activeElement, once, "Cancel gives the focus back to the button that asked");
  once.click();
  await tick();
  item.querySelector(".ask-in-place-words").dispatchEvent(new page.window.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
  await tick();
  assert.equal(item.querySelector(".ask-in-place"), null, "Escape is Cancel");
  assert.equal(page.doc.activeElement, once);
  assert.deepEqual(posts, [], "Cancel: nothing sent");
  await letThrough(item, ".prompt-let-once");
  assert.deepEqual(posts.splice(0), [{ session: "s1", eventId: "ev-<i>1</i>", index: 0, scope: "once" }]);
  assert.match(item.textContent, /this finding cannot be let through/);
  assert.equal(page.doc.activeElement, once, "the answer is said on the row, the focus on the button that asked");
  const pre = page.doc.querySelector("#agent-story .prompt-hidden-text");
  assert.equal(pre.hidden, true);
  assert.equal(pre.textContent, "", "the page has no original before the click");
  item.querySelector(".prompt-reveal").click();
  await tick();
  assert.deepEqual(posts.splice(0), [{ session: "s1", eventId: "ev-<i>1</i>", index: 0 }]);
  assert.equal(pre.hidden, false);
  assert.equal(pre.textContent, "<img src=x onerror=alert(1)>me@corp.example");
  assert.equal(page.doc.querySelector("#agent-story img"), null);
  item.querySelector(".prompt-reveal").click();
  assert.equal(pre.hidden, true);
  assert.equal(pre.textContent, "", "hidden again, the text is dropped");
});

test("the note under a locked administrator's ask row: no session button, the reason as text; once still works and the reason goes with the buttons (plan 15 §12, 2026-10-04)", async () => {
  const WHY = "Your administrator set this to ask every time, so it can be let through in this message only, not for the whole session.";
  const locked = {
    ...NOTE,
    items: [
      { eventId: "ev-2", index: 0, category: "acme.codename", words: null, state: "masked-answer", canLetOnce: true, canLetSession: false, canShow: false, onlyThisMessage: `<b>${WHY}</b>` },
      // No message reference: no button at all, the reason still says why.
      { eventId: "ev-2", index: 1, category: "acme.ticket", words: null, state: "removed", canLetOnce: false, canLetSession: false, canShow: false, onlyThisMessage: WHY },
    ],
  };
  const posts: any[] = [];
  const page = load({ url: AGENT_URL, routes: {
    "GET home/agent?session=s1": { ...AGENT_WITH_NOTES, story: [{ ...AGENT.story[0], promptNote: locked }, { ...AGENT.story[1], promptNote: null }] },
    "POST prompt-filters/let-through": (b: any) => (posts.push(b), { approval: { id: "egr-4" }, scope: b.scope }),
  } });
  await tick();
  const items = [...page.doc.querySelectorAll("#agent-story .prompt-note-item")] as any[];
  assert.equal(items.length, 2);
  for (const it of items) assert.equal(it.querySelector(".prompt-let-session"), null, "no session button under the lock");
  assert.equal(items[0].querySelector(".prompt-let-once-only").textContent, `<b>${WHY}</b>`, "the reason, as text");
  assert.equal(page.doc.querySelector("#agent-story .prompt-note-item b"), null);
  assert.equal(items[1].querySelector(".prompt-let-once"), null);
  assert.equal(items[1].querySelector(".prompt-let-once-only").textContent, WHY);
  await letThrough(items[0], ".prompt-let-once");
  assert.deepEqual(posts, [{ session: "s1", eventId: "ev-2", index: 0, scope: "once" }]);
  assert.equal(items[0].querySelector(".prompt-let-once-only"), null, "answered: the reason goes with the buttons");
  assert.match(items[0].textContent, /Let through in this message\./);
});

test("the note under a locked administrator's row that is not ask: no let-through at all, the reason as text; Show what was hidden stays (work ledger P1, 2026-10-07)", async () => {
  const WHY = "Your administrator set this to block the message every time, so it cannot be let through.";
  const HIDDEN = "Your administrator set this to be hidden every time, so it cannot be let through.";
  const locked = {
    ...NOTE,
    items: [
      { eventId: "ev-3", index: 0, category: "pii.payment-card", words: "a card number", state: "blocked-earlier", canLetOnce: false, canLetSession: false, canShow: false, lockedWhy: `<b>${WHY}</b>` },
      { eventId: "ev-3", index: 1, category: "acme.codename", words: null, state: "hidden", canLetOnce: false, canLetSession: false, canShow: true, lockedWhy: HIDDEN },
      { eventId: "ev-3", index: 2, category: "pii.email", words: "an email address", state: "hidden", canLetOnce: true, canLetSession: true, canShow: false },
    ],
  };
  const posts: any[] = [];
  const page = load({ url: AGENT_URL, routes: {
    "GET home/agent?session=s1": { ...AGENT_WITH_NOTES, story: [{ ...AGENT.story[0], promptNote: locked }, { ...AGENT.story[1], promptNote: null }] },
    "POST prompt-filters/let-through": (b: any) => (posts.push(b), { approval: { id: "egr-5" }, scope: b.scope }),
  } });
  await tick();
  const items = [...page.doc.querySelectorAll("#agent-story .prompt-note-item")] as any[];
  assert.equal(items.length, 3, "a locked finding keeps its row, to say why");
  for (const it of items.slice(0, 2)) {
    assert.equal(it.querySelector(".prompt-let-once"), null, "no let-through the arbiter refuses");
    assert.equal(it.querySelector(".prompt-let-session"), null);
  }
  assert.match(items[0].textContent, /^A card number/);
  assert.equal(items[0].querySelector(".prompt-let-locked").textContent, `<b>${WHY}</b>`, "the reason, as text");
  assert.equal(page.doc.querySelector("#agent-story .prompt-note-item b"), null);
  assert.equal(items[1].querySelector(".prompt-let-locked").textContent, HIDDEN);
  assert.ok(items[1].querySelector(".prompt-reveal"), "Show what was hidden lets nothing through: it stays");
  assert.equal(items[2].querySelector(".prompt-let-locked"), null, "an unlocked kind says no lock");
  await letThrough(items[2], ".prompt-let-once");
  assert.deepEqual(posts, [{ session: "s1", eventId: "ev-3", index: 2, scope: "once" }]);
});

test("a message that never reached the AI is its own card, placed by its time", async () => {
  const page = load({ url: AGENT_URL, routes: { "GET home/agent?session=s1": AGENT_WITH_NOTES } });
  await tick();
  const cards = [...page.doc.querySelectorAll("#agent-story article.turn")] as any[];
  assert.deepEqual(cards.map((c) => c.dataset.turnId ?? "unsent"), ["turn:i1", "unsent", "turn:i2"]);
  assert.match(cards[1].textContent, /A message you wrote.*Your message was not sent to the AI: it holds a card number\./);
});

// ── Try a message ────────────────────────────────────────────────────────────
const TRY_TEXT = "mail ann@corp.test the key sk-123";
/** Type `text` into the box and press Try it. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function tryMessage(page: any, text: string): Promise<void> {
  page.doc.getElementById("prompt-try-text").value = text;
  page.doc.getElementById("prompt-try-form").dispatchEvent(new page.window.Event("submit", { cancelable: true }));
  await tick();
}

test("Try a message: the typed text with each found span marked, one line per finding naming its kind and what would happen", async () => {
  const posts: unknown[] = [];
  const page = load({ url: SETTINGS_URL, routes: {
    "GET policy/prompt-filters": { settings: VM },
    "POST policy/prompt-filters/try": (b: unknown) => (posts.push(b), {
      enforcing: true, action: "rewrite",
      findings: [
        // out of order, and one carrying a symbol the page must never draw
        { start: 27, end: 33, category: "acme.<b>key</b>", name: "acme.<b>key</b>", named: true, action: "block", symbol: "$MDU:prompt_filter[1a2b3c4d]" },
        { start: 5, end: 18, category: "pii.email", name: "An email address", named: false, action: "mask" },
      ],
    }),
  } });
  await tick();
  const fold = page.doc.getElementById("settings-prompt-try");
  assert.equal(fold.hidden, false);
  assert.match(fold.textContent, /Nothing is sent to an AI, and nothing is kept/);
  assert.equal(page.doc.getElementById("prompt-try-text").getAttribute("maxlength"), "65536", "the bench's BENCH_MAX_CHARS");
  await tryMessage(page, TRY_TEXT);
  assert.deepEqual(posts, [{ text: TRY_TEXT }], "the text alone: the server fixes the origin");
  const call = page.calls.find((c) => c.url === "/mandu/api/policy/prompt-filters/try");
  assert.equal(call?.headers["X-Mandu-Control"], "1");
  const said = page.doc.querySelector("#prompt-try-answer .prompt-try-said");
  assert.equal(said.textContent, TRY_TEXT, "the typed text again, whole");
  assert.deepEqual([...said.querySelectorAll("mark")].map((m: any) => m.textContent), ["ann@corp.test", "sk-123"]);
  const lines = [...page.doc.querySelectorAll("#prompt-try-answer .prompt-try-line")].map((l: any) => l.textContent);
  assert.deepEqual(lines, [
    "An email address: hidden. The AI would get a short code in its place.",
    "acme.<b>key</b>: blocked. The message would not be sent.",
  ]);
  assert.equal(page.doc.querySelector("#prompt-try-answer .prompt-try-line code").textContent, "acme.<b>key</b>", "an organization's kind as code, as text");
  assert.equal(page.doc.querySelector("#page-settings b"), null, "server text is never HTML");
  assert.match(page.doc.getElementById("prompt-try-answer").textContent, /What matches one of your exceptions is not marked/);
  assert.equal(page.doc.querySelector(".prompt-try-off"), null);
  assert.ok(!page.doc.body.textContent.includes("$MDU:"), "no symbol on the page");
  assert.ok(!page.doc.body.innerHTML.includes("$MDU:"), "not even in an attribute");
  assert.equal(page.doc.getElementById("prompt-try-text").value, TRY_TEXT, "the text stays in the box");
});

test("Try a message: nothing found says so; protection off says Mandu would only note these; a refusal is text", async () => {
  let answer: unknown = { enforcing: true, action: "pass", findings: [] };
  const page = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings: DEFAULT_VM }, "POST policy/prompt-filters/try": () => answer } });
  await tick();
  await tryMessage(page, "hello there");
  const box = page.doc.getElementById("prompt-try-answer");
  assert.equal(box.hidden, false);
  assert.equal(box.textContent, "Nothing in it would be held or masked.", "no exception in force: no exception line");

  answer = { enforcing: false, action: "pass", findings: [{ start: 0, end: 5, category: "secret.registered", name: "A secret Mandu already knows", named: false, action: "log" }] };
  await tryMessage(page, "hunter2 is it");
  assert.match(box.textContent, /A secret Mandu already knows: sent as written\. Mandu would only note it\./);
  assert.match(page.doc.querySelector(".prompt-try-off").textContent, /^Protection is off, so Mandu would only note these\.$/);

  answer = { enforcing: true, action: "block", reason: "Mandu could not check this prompt: the prompt filter acme did not run.", findings: [] };
  await tryMessage(page, "anything");
  assert.equal(box.textContent, "Mandu could not check this prompt: the prompt filter acme did not run.");

  answer = { status: 413, body: { error: "The message is <i>longer</i> than 65,536 characters." } };
  await tryMessage(page, "x");
  assert.equal(box.hidden, true, "a refusal replaces the answer");
  assert.equal(page.doc.getElementById("prompt-try-error").textContent, "The message is <i>longer</i> than 65,536 characters.");
  assert.equal(page.doc.querySelector("#page-settings i"), null);

  const before = page.calls.length;
  await tryMessage(page, "   ");
  assert.equal(page.calls.length, before, "an empty box asks nothing");
  assert.equal(page.doc.getElementById("prompt-try-error").textContent, "Type a message to try.");
});

test("Try a message is hidden while the card cannot be read, as Exceptions is", async () => {
  const bad = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { status: 502, body: { error: "The protection service did not answer." } } } });
  await tick();
  assert.equal(bad.doc.getElementById("settings-prompt-try").hidden, true);
  assert.equal(bad.doc.getElementById("settings-prompt-exceptions-head").hidden, true);
});

// ── Try a message follows the card (dashboard.md §4.25y *The answer follows the card*) ──
const TRIED = "mail ann@example.com today";
const EMAIL = (action: string) => ({ enforcing: true, action: "rewrite", findings: [{ start: 5, end: 20, category: "pii.email", name: "An email address", named: false, action }] });
const NO_EXC_VM = promptSettingsVM({ ...PROJ, exceptions: [] });
const tryPosts = (page: any): unknown[] => page.calls.filter((c: any) => c.url === "/mandu/api/policy/prompt-filters/try").map((c: any) => c.body);
const answerLines = (doc: any): string[] => ([...doc.querySelectorAll("#prompt-try-answer .prompt-try-line")] as any[]).map((l) => l.textContent);

test("Try a message follows the card: an exception added there asks again for the tried text, not the box's, and the new answer ends with the exceptions line", async () => {
  let vm = NO_EXC_VM;
  const page = load({ url: SETTINGS_URL, routes: {
    "GET policy/prompt-filters": () => ({ settings: vm }),
    "POST policy/prompt-filters/change": (b: any) => b.expected
      ? (vm = VM, { applied: true, changeId: "pc-2" })
      : { applied: false, confirm: true, expected: ["e"], rows: [[{ kind: "text", text: "Let it through" }]], wouldLet: [], warnings: [] },
    "POST policy/prompt-filters/try": () => (tryPosts(page).length === 1 ? EMAIL("mask") : { enforcing: true, action: "pass", findings: [] }),
  } });
  await tick();
  await tryMessage(page, TRIED);
  const box = page.doc.getElementById("prompt-try-answer");
  assert.deepEqual(answerLines(page.doc), ["An email address: hidden. The AI would get a short code in its place."]);
  assert.equal(page.doc.querySelector(".prompt-try-except"), null, "no exception in force yet");
  // The box is edited after the try: the answer is still about what was tried.
  page.doc.getElementById("prompt-try-text").value = "something else";
  const form = page.doc.getElementById("prompt-exception-form");
  (page.doc.getElementById("prompt-exception-kind") as any).value = "pii.email";
  (page.doc.getElementById("prompt-exception-match") as any).value = "*@example.com";
  form.dispatchEvent(new page.window.Event("submit", { cancelable: true }));
  await tick();
  assert.equal(tryPosts(page).length, 1, "the question alone asks nothing again");
  form.querySelector(".ask-in-place .ask-in-place-yes").click();
  await tick(20);
  assert.deepEqual(tryPosts(page), [{ text: TRIED }, { text: TRIED }], "asked again with the tried text, with no second press");
  assert.equal(box.hidden, false);
  assert.equal(page.doc.querySelector("#prompt-try-answer mark"), null, "the address is no longer marked");
  assert.equal(box.lastElementChild.className, "prompt-try-except");
  assert.match(box.textContent, /^Nothing in it would be held or masked\.What matches one of your exceptions is not marked/);
  assert.equal(page.doc.getElementById("prompt-try-text").value, "something else", "the box keeps what is in it");
  assert.equal(page.doc.getElementById("prompt-try-go").disabled, false, "no busy button for a re-ask");
  assert.equal(page.doc.getElementById("prompt-try-form").getAttribute("aria-busy"), null);
  assert.equal(page.doc.getElementById("prompt-try-error").textContent, "");
});

test("Try a message follows the card: a kind's choice and its Undo each ask again, each answer drawn", async () => {
  let action = "mask";
  const page = load({ url: SETTINGS_URL, routes: {
    "GET policy/prompt-filters": () => ({ settings: promptSettingsVM({ ...PROJ, actions: (PROJ.actions ?? []).map((a) => (a.category === "pii.email" ? { ...a, action } : a)) }) }),
    "POST policy/prompt-filters/change": (b: any) => (action = b.edit.action, { applied: true, changeId: "pc-3" }),
    "POST policy/changes/pc-3/undo": () => (action = "mask", { ok: true }),
    "POST policy/prompt-filters/try": () => EMAIL(action),
  } });
  await tick();
  await tryMessage(page, TRIED);
  assert.deepEqual(answerLines(page.doc), ["An email address: hidden. The AI would get a short code in its place."]);
  const sel = kindRow(page.doc, "pii.email").querySelector("select");
  sel.value = "log";
  sel.dispatchEvent(new page.window.Event("change"));
  await tick(20);
  assert.equal(tryPosts(page).length, 2);
  assert.deepEqual(answerLines(page.doc), ["An email address: sent as written. Mandu would only note it."]);
  [...page.doc.querySelectorAll("#prompt-notice button")].find((b: any) => b.textContent === "Undo").click();
  await tick(20);
  assert.equal(page.doc.getElementById("prompt-notice").textContent, "Undone.");
  assert.deepEqual(tryPosts(page), [{ text: TRIED }, { text: TRIED }, { text: TRIED }], "the Undo asks again too");
  assert.deepEqual(answerLines(page.doc), ["An email address: hidden. The AI would get a short code in its place."]);
});

test("Try a message follows the card only while an answer is drawn: none, or a refusal, asks nothing", async () => {
  let refuse = false;
  const page = load({ url: SETTINGS_URL, routes: {
    "GET policy/prompt-filters": { settings: VM },
    "POST policy/prompt-filters/change": { applied: true, changeId: "pc-4" },
    "POST policy/prompt-filters/try": () => (refuse ? { status: 502, body: { error: "The protection service did not answer." } } : EMAIL("mask")),
  } });
  await tick();
  const choose = async (v: string) => {
    const sel = kindRow(page.doc, "secret.registered").querySelector("select");
    sel.value = v;
    sel.dispatchEvent(new page.window.Event("change"));
    await tick(20);
  };
  await choose("block");
  assert.equal(page.doc.getElementById("prompt-notice").hidden, false, "the change was made");
  assert.deepEqual(tryPosts(page), [], "no answer drawn: nothing asked");
  refuse = true;
  await tryMessage(page, TRIED);
  assert.equal(page.doc.getElementById("prompt-try-answer").hidden, true);
  await choose("mask");
  assert.equal(tryPosts(page).length, 1, "a refusal is not asked again");
});

test("Try a message: a re-ask that fails keeps the answer and says it is from before the change, never in red", async () => {
  const page = load({ url: SETTINGS_URL, routes: {
    "GET policy/prompt-filters": { settings: VM },
    "POST policy/prompt-filters/change": { applied: true, changeId: "pc-5" },
    "POST policy/prompt-filters/try": () => (tryPosts(page).length === 2 ? { status: 403, body: { error: "Sign in to the dashboard first." } } : EMAIL("mask")),
  } });
  await tick();
  await tryMessage(page, TRIED);
  const box = page.doc.getElementById("prompt-try-answer");
  const sel = kindRow(page.doc, "pii.email").querySelector("select");
  sel.value = "block";
  sel.dispatchEvent(new page.window.Event("change"));
  await tick(20);
  assert.equal(tryPosts(page).length, 2, "asked again");
  assert.equal(box.hidden, false, "the old answer stays");
  assert.deepEqual(answerLines(page.doc), ["An email address: hidden. The AI would get a short code in its place."]);
  assert.equal(box.lastElementChild.className, "prompt-try-stale");
  assert.equal(box.lastElementChild.textContent, "This answer is from before your last change. Press Try it to check again.");
  assert.equal(page.doc.getElementById("prompt-try-error").textContent, "", "no refusal for a read the person did not ask for");
  await tryMessage(page, TRIED);
  assert.equal(page.doc.querySelector(".prompt-try-stale"), null, "a press draws a fresh answer");
});

test("Try a message: a change while Try it is out asks again once it answers, and Try it is never left off", async () => {
  let release: () => void = () => {};
  const page = load({ url: SETTINGS_URL, routes: {
    "GET policy/prompt-filters": { settings: VM },
    "POST policy/prompt-filters/change": { applied: true, changeId: "pc-6" },
    "POST policy/prompt-filters/try": () => (tryPosts(page).length === 1 ? new Promise((r) => { release = () => r(EMAIL("mask")); }) : EMAIL("block")),
  } });
  await tick();
  await tryMessage(page, TRIED);
  const go = page.doc.getElementById("prompt-try-go");
  assert.equal(go.disabled, true, "the press is out");
  const sel = kindRow(page.doc, "pii.email").querySelector("select");
  sel.value = "block";
  sel.dispatchEvent(new page.window.Event("change"));
  await tick(20);
  assert.equal(tryPosts(page).length, 1, "not asked again while the press is out");
  release();
  await tick(20);
  assert.equal(go.disabled, false, "the press's button is back");
  assert.equal(page.doc.getElementById("prompt-try-form").getAttribute("aria-busy"), null);
  assert.deepEqual(tryPosts(page), [{ text: TRIED }, { text: TRIED }], "asked again once it answered");
  assert.deepEqual(answerLines(page.doc), ["An email address: blocked. The message would not be sent."]);
});

test("Try a message: Ctrl+Enter and Cmd+Enter press Try it; Enter alone, with Alt, or while composing does not", async () => {
  const page = load({ url: SETTINGS_URL, routes: { "GET policy/prompt-filters": { settings: VM }, "POST policy/prompt-filters/try": () => EMAIL("mask") } });
  await tick();
  const input = page.doc.getElementById("prompt-try-text");
  input.value = TRIED;
  const key = async (init: Record<string, unknown>) => {
    const e = new page.window.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true, ...init });
    input.dispatchEvent(e);
    await tick();
    return e.defaultPrevented;
  };
  for (const init of [{}, { shiftKey: true }, { ctrlKey: true, altKey: true }, { ctrlKey: true, isComposing: true }, { metaKey: true, isComposing: true }]) {
    assert.equal(await key(init), false, `left alone: ${JSON.stringify(init)}`);
  }
  assert.equal(tryPosts(page).length, 0, "Enter alone makes a new line");
  assert.equal(await key({ ctrlKey: true }), true);
  assert.equal(tryPosts(page).length, 1, "Ctrl+Enter presses Try it");
  assert.deepEqual(answerLines(page.doc), ["An email address: hidden. The AI would get a short code in its place."]);
  assert.equal(await key({ metaKey: true }), true);
  assert.equal(tryPosts(page).length, 2, "Cmd+Enter too");
});
