/**
 * prompt-settings-view-model.test — Settings › Prompt filters on the product
 * page (confidentiality-plan-15-prompt-filter.md §6, §13.7; dashboard.md
 * §4.25y; src/view-model/prompt-settings.ts), built over the developer
 * panel's projection.
 *
 * Pins: every kind a rule names and every kind a check that is on finds,
 * Mandu's own first; each in plain words with the action in force and who
 * set it; the five choices (hide, remove, ask me, block, just note it) and
 * `pass` only where a row has it; a kind the administrator locked names the
 * file and offers only as strict or stricter (none at all when the lock is
 * the strictest); Reset only on the person's own row; nothing to choose when
 * the page cannot write; the exceptions, the administrator's read only and
 * one a lock keeps out of force; with no kind an exception may name, why
 * none can be added (2026-10-16: a default install finds only the secrets
 * it knows, and the page taught a pattern for a form it did not draw); no
 * inspector word in any string. `lockOf`
 * mirrors the arbiter's `lockedAction` + `lockedAsk` (the strictest locked
 * row; whether any locked `ask` row covers the kind).
 *
 * Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  categoryWords, effectiveAction, exceptionNotOffered, kindName, lockOf, NOT_OFFERED_LOCKED, NOT_OFFERED_NO_KIND, NOT_OFFERED_REGISTERED,
  NOT_OFFERED_REGISTERED_LOCKED, promptSettingsVM, SETTINGS_PROMPT_OPS, type PromptFiltersProjection,
} from "../../../src/view-model/prompt-settings.js";

const PROJ: PromptFiltersProjection = {
  filters: [
    { id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] },
    { id: "key-shapes", on: true, categories: [{ category: "secret.shape", action: "redact" }] },
    { id: "acme-dlp", on: true, categories: [{ category: "acme.codename", action: "redact" }, { category: "acme.ticket", action: "block" }] },
    { id: "off-pack", on: false, categories: [{ category: "other.thing", action: "redact" }] },
  ],
  actions: [
    { category: "secret.registered", action: "mask", setBy: "default", locked: false },
    { category: "secret.shape", action: "redact", setBy: "administrator", locked: true, file: "/etc/mandu/policy.d/10-org.yaml" },
    { category: "acme.ticket", action: "block", setBy: "you", locked: false },
    { category: "pii.payment-card", action: "block", setBy: "administrator", locked: true, file: "/etc/mandu/policy.d/20-cards.yaml" },
    { category: "pii.email", action: "pass", setBy: "you", locked: false },
  ],
  fallback: "redact",
  exceptions: [
    { category: "pii.email", match: "*@example.com", setBy: "you", inForce: true },
    { category: "secret.shape", match: "AKIA*", setBy: "you", inForce: false },
    { category: "acme.codename", match: "public-*", setBy: "administrator", file: "/etc/mandu/policy.d/10-org.yaml", inForce: true },
  ],
  enforcing: true,
  editable: true,
};

test("categoryWords: Mandu's own kinds in plain words; an organization's kind has none", () => {
  assert.equal(categoryWords("secret.registered"), "a secret Mandu already knows");
  assert.equal(categoryWords("secret.shape.github-token"), "a GitHub token");
  assert.equal(categoryWords("secret.shape.something-new"), "something shaped like a key or password");
  assert.equal(categoryWords("pii.email"), "an email address");
  assert.equal(categoryWords("pii.payment-card"), "a card number");
  assert.equal(categoryWords("pii.passport"), "personal information");
  assert.equal(categoryWords("acme.codename"), null);
  assert.equal(kindName("pii.email"), "An email address");
  assert.equal(kindName("acme.codename"), "acme.codename");
});

test("effectiveAction mirrors the arbiter: the longest row, never below a locked one, else the fallback", () => {
  const rows = PROJ.actions!;
  assert.equal(effectiveAction(rows, "secret.shape.github-token", "redact").action, "redact");
  assert.equal(effectiveAction(rows, "acme.codename", "redact").action, "redact");
  assert.equal(effectiveAction(rows, "acme.codename", "redact").row, null);
  const locked = effectiveAction([...rows, { category: "secret.shape.github-token", action: "log", setBy: "you", locked: false }], "secret.shape.github-token", "redact");
  assert.equal(locked.action, "redact", "a person's weaker row never goes below the lock");
  assert.equal(locked.floor?.file, "/etc/mandu/policy.d/10-org.yaml");
});

test("lockOf mirrors the arbiter's lockedAction and lockedAsk: the strictest locked row, any locked ask row; a person's or a default row is no lock", () => {
  const rows = [
    { category: "pii", action: "mask", setBy: "administrator", locked: true },
    { category: "pii.payment-card", action: "block", setBy: "administrator", locked: true },
    { category: "acme", action: "ask", setBy: "administrator", locked: true },
    { category: "acme.ticket", action: "block", setBy: "administrator", locked: true },
    { category: "acme.codename", action: "block", setBy: "you", locked: false },
    { category: "secret.registered", action: "mask", setBy: "default", locked: true },
    { category: "secret.shape", action: "block", setBy: "administrator", locked: false },
  ];
  assert.deepEqual(lockOf(rows, "pii.email"), { action: "mask", ask: false }, "a dotted parent's lock covers the kind");
  assert.deepEqual(lockOf(rows, "pii.payment-card"), { action: "block", ask: false }, "the strictest of the locks that cover it");
  assert.deepEqual(lockOf(rows, "acme.codename"), { action: "ask", ask: true }, "the person's own row is no lock");
  assert.deepEqual(lockOf(rows, "acme.ticket"), { action: "block", ask: true }, "a stricter lock decides, and the ask lock still counts");
  assert.equal(lockOf(rows, "secret.registered"), null, "Mandu's default row is no lock");
  assert.equal(lockOf(rows, "secret.shape.github-token"), null, "an administrator's row that is not locked is no lock");
  assert.equal(lockOf(rows, "piix"), null, "a prefix covers only at a dot");
  assert.equal(lockOf([], "pii.email"), null);
});

test("the kinds: rules and checks that are on, Mandu's first, each with its action, who set it and its choices", () => {
  const vm = promptSettingsVM(PROJ);
  assert.equal(vm.available, true);
  assert.equal(vm.editable, true);
  assert.deepEqual(vm.kinds.map((k) => k.category), ["secret.registered", "secret.shape", "pii.email", "pii.payment-card", "acme.codename", "acme.ticket"],
    "a check that is off adds nothing");
  const by = (c: string) => vm.kinds.find((k) => k.category === c)!;
  assert.deepEqual([by("secret.registered").name, by("secret.registered").actionWords, by("secret.registered").who], ["A secret Mandu already knows", "Hide it", "Mandu's default"]);
  assert.deepEqual(by("secret.registered").choices.map((c) => c.words), ["Hide it", "Remove it", "Ask me", "Block the message", "Just note it"]);
  assert.equal(by("secret.registered").canReset, false);
  // The administrator's lock: the file named, only as strict or stricter.
  const shape = by("secret.shape");
  assert.equal(shape.locked, true);
  assert.equal(shape.lockedBy, "10-org.yaml");
  assert.equal(shape.who, "Locked by your administrator (10-org.yaml).");
  assert.deepEqual(shape.choices.map((c) => c.action), ["mask", "redact", "ask", "block"], "never Just note it");
  // Locked at the strictest: nothing to choose.
  const card = by("pii.payment-card");
  assert.equal(card.locked, true);
  assert.deepEqual(card.choices, []);
  assert.equal(card.actionWords, "Block the message");
  assert.match(card.who, /20-cards\.yaml/);
  // The person's own row: Reset; `pass` offered only because it has it.
  const email = by("pii.email");
  assert.deepEqual([email.who, email.canReset, email.actionWords], ["Set by you", true, "Send as written"]);
  assert.ok(email.choices.some((c) => c.action === "pass"));
  assert.ok(!by("acme.ticket").choices.some((c) => c.action === "pass"));
  // An organization's kind keeps its own name, shown as written.
  const code = by("acme.codename");
  assert.deepEqual([code.name, code.named, code.who, code.actionWords], ["acme.codename", true, "Mandu's default", "Remove it"]);
});

test("the exceptions: yours removable, the administrator's read only, one a lock keeps out of force; the add form leaves out registered secrets and locked kinds", () => {
  const vm = promptSettingsVM(PROJ);
  assert.deepEqual(vm.exceptions.map((x) => [x.name, x.match, x.who, x.removable, x.inForce]), [
    ["An email address", "*@example.com", "Added by you", true, true],
    ["Something shaped like a key or password", "AKIA*", "Added by you", true, false],
    ["acme.codename", "public-*", "Set by your administrator (10-org.yaml)", false, true],
  ]);
  assert.ok(!vm.exceptionKinds.some((k) => k.category === "secret.registered"));
  assert.ok(vm.exceptionKinds.some((k) => k.category === "pii.email"));
  assert.ok(!vm.exceptionKinds.some((k) => k.category === "secret.shape"), "nor a kind the administrator locked");
});

/** A default install's projection: the built-in rows alone (arbiter/prompt-filter/policy.ts
 *  DEFAULT_ON, DEFAULT_ACTION_ROWS), so the one kind is a registered secret. */
const DEFAULT_PROJ: PromptFiltersProjection = {
  filters: [
    { id: "registered-value", on: true, categories: [{ category: "secret.registered", action: "mask" }] },
    { id: "key-shapes", on: false, categories: [{ category: "secret.shape", action: "redact" }] },
  ],
  actions: [{ category: "secret.registered", action: "mask", setBy: "default", locked: false }],
  fallback: "redact",
  exceptions: [],
  enforcing: true,
  editable: true,
};

test("no kind an exception may name: the section says why none can be added, by what the kinds are", () => {
  // A default install: the registered secrets alone.
  const plain = promptSettingsVM(DEFAULT_PROJ);
  assert.deepEqual(plain.kinds.map((k) => k.category), ["secret.registered"]);
  assert.deepEqual(plain.exceptionKinds, []);
  assert.equal(plain.exceptionNotOffered, NOT_OFFERED_REGISTERED);
  assert.equal(NOT_OFFERED_REGISTERED, "Exceptions are not offered for a secret Mandu already knows: the choice above decides what happens to it.");
  // The other kinds all locked by the administrator.
  const lockedShape = { category: "secret.shape", action: "redact", setBy: "administrator", locked: true, file: "/etc/mandu/policy.d/10-org.yaml" };
  const both = promptSettingsVM({ ...DEFAULT_PROJ, filters: [DEFAULT_PROJ.filters![0]!, { id: "key-shapes", on: true, categories: [{ category: "secret.shape", action: "redact" }] }], actions: [...DEFAULT_PROJ.actions!, lockedShape] });
  assert.deepEqual(both.kinds.map((k) => [k.category, k.locked]), [["secret.registered", false], ["secret.shape", true]]);
  assert.equal(both.exceptionNotOffered, NOT_OFFERED_REGISTERED_LOCKED);
  assert.equal(NOT_OFFERED_REGISTERED_LOCKED, "Exceptions are not offered for a secret Mandu already knows, and your administrator locked the other kinds.");
  // The registered kind locked too stays a registered kind; a locked row
  // over a wider kind ("secret") lists that kind as well, locked.
  const own = promptSettingsVM({ ...DEFAULT_PROJ, actions: [{ category: "secret.registered", action: "block", setBy: "administrator", locked: true, file: "/etc/mandu/policy.d/10-org.yaml" }] });
  assert.deepEqual(own.kinds.map((k) => [k.category, k.locked]), [["secret.registered", true]]);
  assert.equal(own.exceptionNotOffered, NOT_OFFERED_REGISTERED);
  const wide = promptSettingsVM({ ...DEFAULT_PROJ, actions: [{ category: "secret", action: "block", setBy: "administrator", locked: true, file: "/etc/mandu/policy.d/10-org.yaml" }] });
  assert.deepEqual(wide.kinds.map((k) => [k.category, k.locked]).sort(), [["secret", true], ["secret.registered", true]]);
  assert.equal(wide.exceptionNotOffered, NOT_OFFERED_REGISTERED_LOCKED);
  // One kind an exception may name: the form, and no reason.
  const email = promptSettingsVM({ ...DEFAULT_PROJ, actions: [...DEFAULT_PROJ.actions!, { category: "pii.email", action: "redact", setBy: "you", locked: false }] });
  assert.deepEqual(email.exceptionKinds.map((k) => k.category), ["pii.email"]);
  assert.equal(email.exceptionNotOffered, null);
  assert.equal(promptSettingsVM(PROJ).exceptionNotOffered, null, "the full projection offers the form");
  // Read only: the note above the kinds says why nothing can be changed.
  assert.equal(promptSettingsVM({ ...DEFAULT_PROJ, editable: false }).exceptionNotOffered, null);
  assert.equal(promptSettingsVM(null).exceptionNotOffered, null, "unread: the section is its refusal");
});

test("exceptionNotOffered: each mix of kinds, as the add form's own rule decides it", () => {
  const k = (category: string, locked = false) => ({ category, locked });
  assert.equal(exceptionNotOffered(true, [k("secret.registered")]), NOT_OFFERED_REGISTERED);
  assert.equal(exceptionNotOffered(true, [k("secret.registered.env")]), NOT_OFFERED_REGISTERED, "a registered kind's sub-kind");
  assert.equal(exceptionNotOffered(true, [k("secret.registered", true)]), NOT_OFFERED_REGISTERED, "a locked registered kind is still a registered one");
  assert.equal(exceptionNotOffered(true, [k("secret.registered"), k("secret.shape", true), k("acme.ticket", true)]), NOT_OFFERED_REGISTERED_LOCKED);
  assert.equal(exceptionNotOffered(true, [k("pii.email", true)]), NOT_OFFERED_LOCKED);
  assert.equal(NOT_OFFERED_LOCKED, "Your administrator locked every kind above, so none can have an exception.");
  assert.equal(exceptionNotOffered(true, []), NOT_OFFERED_NO_KIND);
  assert.equal(exceptionNotOffered(true, [k("secret.registered"), k("secret.shape", true), k("acme.ticket")]), null, "one open kind: the form");
  assert.equal(exceptionNotOffered(false, [k("secret.registered")]), null, "read only");
});

test("read only: no choice, no Reset, no Remove, and the page says why; no projection at all says so too", () => {
  const vm = promptSettingsVM({ ...PROJ, editable: false });
  assert.equal(vm.editable, false);
  assert.ok(vm.kinds.every((k) => k.choices.length === 0 && !k.canReset));
  assert.ok(vm.exceptions.every((x) => !x.removable));
  assert.match(vm.note, /cannot be changed from this page/);
  for (const p of [null, undefined, {} as PromptFiltersProjection]) {
    const none = promptSettingsVM(p);
    assert.equal(none.available, false);
    assert.deepEqual(none.kinds, []);
  }
});

test("the section's ops are the four the product page offers (no switch, no pack)", () => {
  assert.deepEqual([...SETTINGS_PROMPT_OPS], ["set-prompt-action", "remove-prompt-action", "add-prompt-exception", "remove-prompt-exception"]);
});

const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter|filterPrompt|redact|segment|category)\b|\$MDU:|\b[Pp]laceholders?\b/i;

test("every string the section shows is in the product's words", () => {
  for (const p of [PROJ, { ...PROJ, editable: false }, { ...PROJ, enforcing: false }, null, DEFAULT_PROJ]) {
    const vm = promptSettingsVM(p);
    const copy = [vm.note, vm.exceptionNotOffered ?? "", ...vm.kinds.flatMap((k) => [k.named ? "" : k.name, k.actionWords, k.who, ...k.choices.map((c) => c.words)]),
      ...vm.exceptions.flatMap((x) => [x.named ? "" : x.name, x.who]), ...vm.meanings.flatMap((m) => [m.words, m.meaning])].join("\n");
    assert.doesNotMatch(copy, FORBIDDEN, copy.match(FORBIDDEN)?.[0]);
  }
});
