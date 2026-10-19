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

test("a choice sends one typed edit; a relaxation asks first and resends what was shown; a lock's refusal is said on the row", async () => {
  const posts: any[] = [];
  const asked: string[] = [];
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
  page.window.confirm = (q: string) => (asked.push(q), true);
  await tick();
  const sel = kindRow(page.doc, "secret.registered").querySelector("select");
  sel.value = "block";
  sel.dispatchEvent(new page.window.Event("change"));
  await tick();
  assert.deepEqual(posts.shift(), { edit: { op: "set-prompt-action", category: "secret.registered", action: "block" } });
  assert.equal(asked.length, 0, "a tightening is not asked about");
  assert.match(page.doc.getElementById("prompt-notice").textContent, /A secret Mandu already knows: Block the message\. It applies to your next message\.Undo/);

  const sel2 = kindRow(page.doc, "secret.registered").querySelector("select");
  sel2.value = "log";
  sel2.dispatchEvent(new page.window.Event("change"));
  await tick();
  assert.equal(asked.length, 1);
  assert.match(asked[0]!, /In your prompts, secret\.registered is only recorded\./);
  assert.match(asked[0]!, /Your prompts would carry more to the AI/);
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

test("declining the question changes nothing; Use the default, Remove and Add send their edits", async () => {
  const posts: any[] = [];
  const page = load({ url: SETTINGS_URL, routes: {
    "GET policy/prompt-filters": { settings: VM },
    "POST policy/prompt-filters/change": (b: any) => (posts.push(b), b.edit.op === "add-prompt-exception" && !b.expected
      ? { applied: false, confirm: true, expected: ["x"], rows: [[{ kind: "text", text: "Let it through" }]], wouldLet: [], warnings: [] }
      : { applied: true, changeId: "pc-1" }),
  } });
  await tick();
  page.window.confirm = () => false;
  (page.doc.getElementById("prompt-exception-match") as any).value = "*@corp.example";
  (page.doc.getElementById("prompt-exception-kind") as any).value = "pii.email";
  page.doc.getElementById("prompt-exception-form").dispatchEvent(new page.window.Event("submit", { cancelable: true }));
  await tick();
  assert.deepEqual(posts.splice(0), [{ edit: { op: "add-prompt-exception", category: "pii.email", match: "*@corp.example" } }], "declined: not resent");
  page.window.confirm = () => true;
  page.doc.getElementById("prompt-exception-form").dispatchEvent(new page.window.Event("submit", { cancelable: true }));
  await tick();
  assert.deepEqual(posts.splice(0).map((p) => p.expected ?? null), [null, ["x"]]);
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

test("the note: its lines under your message; Let it through asks, then names the finding to the let-through route", async () => {
  const posts: any[] = [];
  const asked: string[] = [];
  const page = load({ url: AGENT_URL, routes: {
    "GET home/agent?session=s1": AGENT_WITH_NOTES,
    "POST prompt-filters/let-through": (b: any) => (posts.push(b), { approval: { id: "egr-3" }, scope: b.scope }),
  } });
  page.window.confirm = (q: string) => (asked.push(q), true);
  await tick();
  const turn = page.doc.querySelector('#agent-story article.turn[data-turn-id="turn:i1"]');
  const note = turn.querySelector(".turn-q .prompt-note");
  assert.ok(note, "the note sits under the question");
  assert.deepEqual([...note.querySelectorAll(".prompt-note-line")].map((l: any) => l.textContent), NOTE.lines);
  const items = [...note.querySelectorAll(".prompt-note-item")] as any[];
  assert.equal(items.length, 1, "a finding with nothing to do shows no row");
  assert.match(items[0].textContent, /^An email address/);
  items[0].querySelector(".prompt-let-session").click();
  await tick();
  assert.equal(asked.length, 1);
  assert.match(asked[0]!, /Let an email address through for the rest of this session\?/);
  assert.deepEqual(posts, [{ session: "s1", eventId: "ev-<i>1</i>", index: 0, scope: "session" }]);
  assert.equal(items[0].querySelector(".prompt-let-once"), null, "answered: the buttons go");
  assert.match(items[0].textContent, /Let through for this session\./);
  assert.equal(page.doc.querySelector("#agent-story i"), null);
  assert.ok(!page.doc.body.textContent.includes("$MDU:"));
});

test("the note: declining changes nothing; a refusal is said; Show what was hidden fetches the original on a click, as text", async () => {
  const posts: any[] = [];
  const page = load({ url: AGENT_URL, routes: {
    "GET home/agent?session=s1": AGENT_WITH_NOTES,
    "POST prompt-filters/let-through": (b: any) => (posts.push(b), { status: 409, body: { error: "this finding cannot be let through" } }),
    "POST prompt-filters/reveal": (b: any) => (posts.push(b), { original: "<img src=x onerror=alert(1)>me@corp.example" }),
  } });
  page.window.confirm = () => false;
  await tick();
  const item = page.doc.querySelector("#agent-story .prompt-note-item");
  item.querySelector(".prompt-let-once").click();
  await tick();
  assert.deepEqual(posts, [], "declined: nothing sent");
  page.window.confirm = () => true;
  item.querySelector(".prompt-let-once").click();
  await tick();
  assert.deepEqual(posts.splice(0), [{ session: "s1", eventId: "ev-<i>1</i>", index: 0, scope: "once" }]);
  assert.match(item.textContent, /this finding cannot be let through/);
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
  page.window.confirm = () => true;
  await tick();
  const items = [...page.doc.querySelectorAll("#agent-story .prompt-note-item")] as any[];
  assert.equal(items.length, 2);
  for (const it of items) assert.equal(it.querySelector(".prompt-let-session"), null, "no session button under the lock");
  assert.equal(items[0].querySelector(".prompt-let-once-only").textContent, `<b>${WHY}</b>`, "the reason, as text");
  assert.equal(page.doc.querySelector("#agent-story .prompt-note-item b"), null);
  assert.equal(items[1].querySelector(".prompt-let-once"), null);
  assert.equal(items[1].querySelector(".prompt-let-once-only").textContent, WHY);
  items[0].querySelector(".prompt-let-once").click();
  await tick();
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
  page.window.confirm = () => true;
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
  items[2].querySelector(".prompt-let-once").click();
  await tick();
  assert.deepEqual(posts, [{ session: "s1", eventId: "ev-3", index: 2, scope: "once" }]);
});

test("a message that never reached the AI is its own card, placed by its time", async () => {
  const page = load({ url: AGENT_URL, routes: { "GET home/agent?session=s1": AGENT_WITH_NOTES } });
  await tick();
  const cards = [...page.doc.querySelectorAll("#agent-story article.turn")] as any[];
  assert.deepEqual(cards.map((c) => c.dataset.turnId ?? "unsent"), ["turn:i1", "unsent", "turn:i2"]);
  assert.match(cards[1].textContent, /A message you wrote.*Your message was not sent to the AI: it holds a card number\./);
});
