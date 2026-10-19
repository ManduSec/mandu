/**
 * prompt-notes.test — the note under your own message on the product agent
 * page (confidentiality-plan-15-prompt-filter.md §7, §13.7; dashboard.md
 * §4.25y; src/view-model/prompt-notes.ts and its use in agent-page.ts).
 *
 * Pins: one plain line per outcome, the category in plain words ("One value
 * in your prompt was hidden from the AI (an email address)."); only the
 * human's own text, only believed events, only while the confidentiality
 * axis enforced; a message's newest event tells where it stands (a let); a
 * note goes under the story turn whose message arrived in a request one of
 * its events names, and one no turn shows (a blocked message) is returned
 * apart; "let it through" only for an enforced, referenced finding that is
 * not a registered secret (once only with the message's reference); "show
 * what was hidden" only for the filter's own mint outside the secret kinds;
 * and NO value, symbol or reference besides the event's id in the data; and
 * the trace keeps a conversation going when an earlier message is resent in
 * another form (dual-lanes `samePromptMessage`). A finding the arbiter marked
 * `onceOnly` (a locked administrator's `ask` row) offers no session
 * let-through and says why (plan 15 §12, 2026-10-04). Under the locks in
 * force (`PromptLocks`, the arbiter's rows), a finding a locked row that is
 * not `ask` covers offers no let-through at all and says why, and a locked
 * `ask` row keeps the session button away even with no mark on the event
 * (the work ledger's P1, 2026-10-07).
 *
 * Axes: none (display only; the notes read the `enforcing` the proxies recorded).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { findingState, LET_ONLY_THIS_MESSAGE, lockedWords, noteLine, promptNotes, type PromptNote } from "../../../src/view-model/prompt-notes.js";
import { lockOf } from "../../../src/view-model/prompt-settings.js";
import { buildAgentPage } from "../../../src/view-model/agent-page.js";
import { toSessionViewModel, type SessionViewModel } from "../../../src/view-model.js";
import type { ManduEvent, PromptFilterDetail } from "../../../src/event-model.js";
import { samePromptMessage, type DualStep } from "../../../src/view-model/dual-lanes.js";
import type { PairedTurn } from "../../../src/view-model/paired-rows.js";

const REF_A = "a".repeat(32);
const REF_B = "b".repeat(32);
const TURN_1 = "1".repeat(32);
const TURN_2 = "2".repeat(32);
const SYM = "$MDU:prompt_filter[1a2b3c4d]";
const SECRET_TEXT = "falconridgeproject";

let seq = 0;
function pf(over: Partial<PromptFilterDetail> & { findings: PromptFilterDetail["findings"] }, ev: Partial<ManduEvent> = {}): ManduEvent {
  seq++;
  return {
    id: `pf-${seq}`, sessionId: "s1", turn: 1, ts: `2026-10-03T10:00:${String(seq).padStart(2, "0")}.000Z`, seq, callId: null, parentId: null,
    kind: "prompt_filter", view: "AgentView", boundary: "ingress", emitter: "anthropic-proxy",
    input: { symbolized: `prompt filter: hidden as ${SYM}`, original: SECRET_TEXT, differs: true, symbols: [] }, output: null,
    promptFilter: { agent: "claude-code", segmentId: "m0.b0.p0", origin: "human", action: "rewrite", skipped: 0, enforcing: true, digest: { policy: "p", packs: "k" }, ...over },
    ...ev,
  } as unknown as ManduEvent;
}
const finding = (over: Partial<PromptFilterDetail["findings"][number]>): PromptFilterDetail["findings"][number] =>
  ({ filterId: "acme-dlp", category: "pii.email", action: "mask", start: 0, end: 5, ...over });

test("findingState: each action and each way an ask ended", () => {
  const d = { action: "rewrite" as const };
  assert.equal(findingState(d, finding({ action: "mask", symbol: SYM })), "hidden");
  assert.equal(findingState(d, finding({ action: "redact" })), "removed");
  assert.equal(findingState({ action: "block" }, finding({ action: "block" })), "blocked");
  assert.equal(findingState(d, finding({ action: "block" })), "blocked-earlier");
  assert.equal(findingState(d, finding({ action: "log" })), null, "a note only when something changed");
  assert.equal(findingState(d, finding({ action: "pass" })), null);
  assert.equal(findingState(d, finding({ action: "mask", let: "once" })), "let-once");
  assert.equal(findingState(d, finding({ action: "redact", let: "session" })), "let-session");
  assert.equal(findingState(d, finding({ action: "ask", hold: { state: "sent" }, let: "once" })), "sent-answer");
  assert.equal(findingState(d, finding({ action: "ask", hold: { state: "masked" }, symbol: SYM })), "masked-answer");
  assert.equal(findingState(d, finding({ action: "ask", hold: { state: "timed-out" }, symbol: SYM })), "timed-out");
  assert.equal(findingState(d, finding({ action: "ask", hold: { state: "cancelled" } })), "cancelled");
  assert.equal(findingState(d, finding({ action: "ask", hold: { state: "default" }, symbol: SYM })), "hidden");
  assert.equal(findingState(d, finding({ action: "ask", hold: { state: "default" } })), "removed", "an ask's default without a level is a removal");
});

test("noteLine: the maintainer's sentence, counted, with the kind in plain words", () => {
  assert.equal(noteLine("hidden", [{ words: "an email address", category: "pii.email" }]), "One value in your prompt was hidden from the AI (an email address).");
  assert.equal(noteLine("removed", [{ words: "a card number", category: "pii.payment-card" }, { words: null, category: "acme.codename" }]),
    "Two values in your prompt were removed before the AI read your message (a card number, acme.codename).");
  assert.equal(noteLine("blocked", [{ words: "a card number", category: "pii.payment-card" }]), "Your message was not sent to the AI: it holds a card number.");
  assert.match(noteLine("let-session", [{ words: null, category: "acme.codename" }]), /you let it through for this session \(acme\.codename\)\.$/);
});

test("promptNotes: a note per message under its turn; harness text, a claimed event and a logged-only one are not the person's note", () => {
  const events = [
    pf({ turn: TURN_1, findings: [finding({ action: "mask", symbol: SYM, ref: REF_A })] }, { turn: 3 }),
    pf({ origin: "harness", findings: [finding({ action: "redact", ref: REF_B })] }, { turn: 3 }),
    pf({ turn: TURN_2, findings: [finding({ action: "redact", category: "acme.codename", ref: REF_B })] }, { turn: 5, claimed: true }),
    pf({ enforcing: false, findings: [finding({ action: "mask", symbol: SYM, ref: REF_B })] }, { turn: 5 }),
  ];
  const { byTurn, unplaced } = promptNotes(events, [{ id: "turn:a", requestTurn: 3 }, { id: "turn:b", requestTurn: 5 }]);
  assert.deepEqual([...byTurn.keys()], ["turn:a"]);
  assert.deepEqual(byTurn.get("turn:a")!.lines, ["One value in your prompt was hidden from the AI (an email address)."]);
  assert.equal(unplaced.length, 0);
});

test("promptNotes: the message's newest event tells where it stands; let it through and show it only where allowed", () => {
  const first = pf({ turn: TURN_1, findings: [
    finding({ action: "mask", symbol: SYM, ref: REF_A }),
    finding({ action: "mask", category: "secret.registered", filterId: "registered-value", symbol: "$MDU:env_STRIPE[9f8e7d6c]", how: "value" }),
    finding({ action: "redact", category: "acme.codename", ref: REF_B }),
  ] }, { turn: 2 });
  const [note] = [...promptNotes([first], [{ id: "t", requestTurn: 2 }]).byTurn.values()] as PromptNote[];
  assert.deepEqual(note!.lines, [
    "Two values in your prompt were hidden from the AI (an email address, a secret Mandu already knows).",
    "One value in your prompt was removed before the AI read your message (acme.codename).",
  ]);
  const email = note!.items.find((i) => i.category === "pii.email")!;
  assert.deepEqual({ once: email.canLetOnce, session: email.canLetSession, show: email.canShow }, { once: true, session: true, show: true });
  const reg = note!.items.find((i) => i.category === "secret.registered")!;
  assert.deepEqual({ once: reg.canLetOnce, session: reg.canLetSession, show: reg.canShow }, { once: false, session: false, show: false }, "a registered secret is never let through or shown");
  const code = note!.items.find((i) => i.category === "acme.codename")!;
  assert.equal(code.canShow, false, "a removal keeps nothing to show");
  assert.equal(code.words, null);
  assert.equal(code.eventId, first.id);
  assert.equal(code.index, 2, "the let-through route names the finding by event and index");

  // The person let the email through: the next request's event says so.
  const later = pf({ turn: TURN_1, findings: [finding({ action: "mask", symbol: SYM, ref: REF_A, let: "once" })] }, { turn: 4 });
  const after = [...promptNotes([first, later], [{ id: "t", requestTurn: 2 }]).byTurn.values()][0]!;
  assert.deepEqual(after.lines, ["One value in your prompt went to the AI as you wrote it: you let it through in this message (an email address)."]);
  assert.equal(after.items[0]!.canLetOnce, false);
  assert.equal(after.items[0]!.canShow, false);
});

test("promptNotes: once needs the message's reference; a merged or registered-value symbol is never shown; a secret kind is never shown", () => {
  const ev = pf({ findings: [
    finding({ action: "mask", symbol: SYM, ref: REF_A }),
    finding({ action: "mask", category: "acme.codename", symbol: SYM, ref: REF_B, how: "merged" }),
    finding({ action: "mask", category: "secret.shape.github-token", filterId: "key-shapes", symbol: SYM, ref: "c".repeat(32) }),
  ] }, { turn: 1 });
  const note = [...promptNotes([ev], [{ id: "t", requestTurn: 1 }]).byTurn.values()][0]!;
  assert.deepEqual(note.items.map((i) => [i.category, i.canLetOnce, i.canLetSession, i.canShow]), [
    ["pii.email", false, true, true],
    ["acme.codename", false, true, false],
    ["secret.shape.github-token", false, true, false],
  ]);
});

test("promptNotes: a finding the arbiter marked onceOnly (a locked administrator's ask row) offers no session let-through, and says why in plain words", () => {
  const ev = pf({ turn: TURN_1, findings: [
    finding({ action: "ask", category: "acme.codename", symbol: SYM, ref: REF_A, hold: { state: "masked", approvalId: "egr-1" }, onceOnly: true }),
    finding({ action: "mask", symbol: SYM, ref: REF_B }),
  ] }, { turn: 1 });
  const note = [...promptNotes([ev], [{ id: "t", requestTurn: 1 }]).byTurn.values()][0]!;
  const locked = note.items.find((i) => i.category === "acme.codename")!;
  assert.deepEqual({ once: locked.canLetOnce, session: locked.canLetSession }, { once: true, session: false }, "this message only");
  assert.equal(locked.onlyThisMessage, LET_ONLY_THIS_MESSAGE);
  assert.match(LET_ONLY_THIS_MESSAGE, /^Your administrator set this to ask every time, so it can be let through in this message only/);
  assert.doesNotMatch(LET_ONLY_THIS_MESSAGE, /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter|symbol)\b|\$MDU:/i, "the product's vocabulary");
  const email = note.items.find((i) => i.category === "pii.email")!;
  assert.deepEqual({ once: email.canLetOnce, session: email.canLetSession, why: email.onlyThisMessage }, { once: true, session: true, why: undefined }, "no lock, no note");
  // Already let through: nothing to offer, no note either.
  const done = pf({ turn: TURN_1, findings: [finding({ action: "mask", category: "acme.codename", symbol: SYM, ref: REF_A, let: "once", onceOnly: true })] }, { turn: 2 });
  const after = [...promptNotes([ev, done], [{ id: "t", requestTurn: 1 }]).byTurn.values()][0]!;
  assert.equal(after.items[0]!.onlyThisMessage, undefined);
});

test("promptNotes: under the administrator's locks in force, a finding locked to block, hide or remove offers no let-through and says why; a locked ask is this message only; no locks, the event alone (work ledger P1, 2026-10-07)", () => {
  const REF_C = "c".repeat(32);
  const REF_D = "d".repeat(32);
  const ev = pf({ turn: TURN_1, findings: [
    finding({ action: "block", category: "pii.payment-card", ref: REF_A }),
    finding({ action: "mask", category: "acme.codename", symbol: SYM, ref: REF_B }),
    finding({ action: "redact", category: "acme.ticket", ref: REF_C }),
    finding({ action: "mask", category: "pii.email", symbol: SYM, ref: REF_D }),
  ] }, { turn: 1 });
  // The arbiter's rows as `promptFilters` reports them (the route's lookup).
  const rows = [
    { category: "pii.payment-card", action: "block", setBy: "administrator", locked: true },
    { category: "acme", action: "mask", setBy: "administrator", locked: true },
    { category: "acme.ticket", action: "ask", setBy: "administrator", locked: true },
    { category: "pii.email", action: "block", setBy: "you", locked: false },
  ];
  const note = [...promptNotes([ev], [{ id: "t", requestTurn: 1 }], (c) => lockOf(rows, c)).byTurn.values()][0]!;
  const by = (c: string) => note.items.find((i) => i.category === c)!;
  const offer = (c: string) => ({ once: by(c).canLetOnce, session: by(c).canLetSession, only: by(c).onlyThisMessage, why: by(c).lockedWhy });
  assert.deepEqual(offer("pii.payment-card"), { once: false, session: false, only: undefined, why: lockedWords("block") }, "a locked block: the arbiter refuses both");
  assert.deepEqual(offer("acme.codename"), { once: false, session: false, only: undefined, why: lockedWords("mask") }, "a parent's locked mask covers it");
  assert.deepEqual(offer("acme.ticket"), { once: true, session: false, only: LET_ONLY_THIS_MESSAGE, why: undefined },
    "the strictest lock is ask: this message only, though the event carries no mark");
  assert.deepEqual(offer("pii.email"), { once: true, session: true, only: undefined, why: undefined }, "the person's own row is no lock");
  assert.deepEqual(note.items.map((i) => i.state), ["blocked-earlier", "hidden", "removed", "hidden"], "what became of each is unchanged");
  assert.equal(by("acme.codename").canShow, true, "Show what was hidden stays: it lets nothing through");
  // No locks known (no arbiter, an older one): the event alone decides.
  const bare = [...promptNotes([ev], [{ id: "t", requestTurn: 1 }]).byTurn.values()][0]!;
  for (const i of bare.items) assert.deepEqual({ once: i.canLetOnce, session: i.canLetSession, why: i.lockedWhy }, { once: true, session: true, why: undefined }, i.category);
  // Already let through, or a registered value: nothing offered, no lock said.
  const done = pf({ turn: TURN_1, findings: [finding({ action: "block", category: "pii.payment-card", ref: REF_A, let: "once" })] }, { turn: 2 });
  const after = [...promptNotes([ev, done], [{ id: "t", requestTurn: 1 }], (c) => lockOf(rows, c)).byTurn.values()][0]!;
  assert.equal(after.items[0]!.lockedWhy, undefined);
  // The words, in the product's vocabulary.
  assert.equal(lockedWords("block"), "Your administrator set this to block the message every time, so it cannot be let through.");
  assert.equal(lockedWords("mask"), "Your administrator set this to be hidden every time, so it cannot be let through.");
  assert.equal(lockedWords("redact"), "Your administrator set this to be removed every time, so it cannot be let through.");
  assert.equal(lockedWords("log"), "Your administrator set how Mandu treats this, so it cannot be let through.");
  for (const a of ["block", "mask", "redact", "log"]) {
    assert.doesNotMatch(lockedWords(a), /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter|symbol|locked|policy)\b|\$MDU:/i, "the product's vocabulary");
  }
});

test("promptNotes: a message Mandu blocked that no turn shows is returned apart; resent with it removed, it joins its turn", () => {
  const blocked = pf({ action: "block", turn: TURN_2, findings: [finding({ action: "block", category: "pii.payment-card", ref: REF_A })] }, { turn: 7 });
  const alone = promptNotes([blocked], [{ id: "t", requestTurn: 1 }]);
  assert.equal(alone.byTurn.size, 0);
  assert.deepEqual(alone.unplaced.map((n) => n.lines), [["Your message was not sent to the AI: it holds a card number."]]);
  assert.equal(alone.unplaced[0]!.ts, blocked.ts);
  const resent = pf({ action: "rewrite", turn: TURN_2, findings: [finding({ action: "block", category: "pii.payment-card", ref: REF_A })] }, { turn: 8 });
  const joined = promptNotes([blocked, resent], [{ id: "t8", requestTurn: 8 }]);
  assert.equal(joined.unplaced.length, 0);
  assert.deepEqual(joined.byTurn.get("t8")!.lines, ["Mandu stopped your message once. It then went with that part removed (a card number)."]);
});

test("promptNotes: no value, no symbol, no reference in the data", () => {
  const events = [
    pf({ turn: TURN_1, findings: [finding({ action: "mask", symbol: SYM, ref: REF_A }), finding({ action: "ask", hold: { state: "timed-out", approvalId: "egr-9" }, symbol: SYM, ref: REF_B })] }, { turn: 1 }),
    pf({ action: "block", turn: TURN_2, findings: [finding({ action: "block", ref: REF_A })] }, { turn: 9 }),
  ];
  const out = promptNotes(events, [{ id: "t", requestTurn: 1 }]);
  const json = JSON.stringify({ byTurn: [...out.byTurn.values()], unplaced: out.unplaced });
  for (const bad of [SECRET_TEXT, "$MDU:", REF_A, REF_B, TURN_1, TURN_2, "egr-9"]) assert.ok(!json.includes(bad), `${bad} leaked into the note's data: ${json}`);
});

// ── In the agent page ────────────────────────────────────────────────────────

function vmOf(steps: DualStep[], turns: PairedTurn[]): SessionViewModel {
  const base = toSessionViewModel("s1", []);
  return { ...base, dualLanes: { ...base.dualLanes, steps }, paired: { integrity: "on", mode: null, maskedCount: 0, turns } as SessionViewModel["paired"] };
}

test("buildAgentPage: the note rides the turn whose message arrived in that request; the unplaced one rides the page", () => {
  const steps: DualStep[] = [
    { step: "input", id: "in1", ts: "2026-10-03T10:00:00.000Z", turn: 1, violated: false, text: "hello" },
    { step: "input", id: "in2", ts: "2026-10-03T10:01:00.000Z", turn: 3, violated: false, text: `mail ${SYM}` },
  ];
  const turns: PairedTurn[] = [
    { id: "turn:in1", inputId: "in1", rows: [], background: [] },
    { id: "turn:in2", inputId: "in2", rows: [], background: [] },
  ];
  const events = [
    pf({ turn: TURN_1, findings: [finding({ action: "mask", symbol: SYM, ref: REF_A })] }, { turn: 3 }),
    pf({ action: "block", turn: TURN_2, findings: [finding({ action: "block", category: "pii.payment-card", ref: REF_B })] }, { turn: 2 }),
  ];
  const vm = buildAgentPage({ session: null, id: "s1", vm: vmOf(steps, turns), cwd: null, waiting: [], events });
  assert.equal(vm.story[0]!.promptNote, null);
  assert.deepEqual(vm.story[1]!.promptNote!.lines, ["One value in your prompt was hidden from the AI (an email address)."]);
  assert.deepEqual(vm.unplacedNotes.map((n) => n.lines[0]), ["Your message was not sent to the AI: it holds a card number."]);
  assert.ok(!JSON.stringify(vm).includes("$MDU:"), "the page's data carries no symbol");
  // The locks in force reach the notes (the route's `promptLocks`).
  const lockedVm = buildAgentPage({ session: null, id: "s1", vm: vmOf(steps, turns), cwd: null, waiting: [], events,
    promptLocks: (c) => (c === "pii.email" ? { action: "mask", ask: false } : null) });
  assert.deepEqual(lockedVm.story[1]!.promptNote!.items.map((i) => [i.canLetOnce, i.canLetSession, i.lockedWhy]), [[false, false, lockedWords("mask")]]);
  assert.equal(lockedVm.unplacedNotes[0]!.items[0]!.canLetSession, true, "an unlocked kind keeps its button");
  // Without events (pure use), no note.
  const bare = buildAgentPage({ session: null, id: "s1", vm: vmOf(steps, turns), cwd: null, waiting: [] });
  assert.equal(bare.story[1]!.promptNote, null);
  assert.deepEqual(bare.unplacedNotes, []);
});

// ── The story keeps going when an earlier message goes in another form ───────

test("samePromptMessage: equal but for the prompt filter's marks on either side; never a message that is all marks", () => {
  const raw = "deploy ACME-20417 with the key please";
  const masked = "deploy $MDU:prompt_filter[1a2b3c4d] with the key please";
  const removed = "deploy [redacted: acme.ticket] with the key please";
  assert.equal(samePromptMessage(raw, raw), true);
  assert.equal(samePromptMessage(removed, masked), true, "a policy change: removed, then masked");
  assert.equal(samePromptMessage(masked, raw), true, "let through: masked, then as written");
  assert.equal(samePromptMessage(raw, removed), true);
  assert.equal(samePromptMessage("deploy [redacted: acme.ticket] and $MDU:env_KEY[9f8e7d6c] now", "deploy ACME-1 and $MDU:env_KEY[9f8e7d6c] now"), true);
  assert.equal(samePromptMessage(raw, "deploy ACME-20417 with the key"), false, "another message");
  assert.equal(samePromptMessage(masked, "summarize this page for me please"), false);
  assert.equal(samePromptMessage("deploy [redacted: acme.ticket] with", "deploy  with"), false, "a mark stands for some text, never none");
  assert.equal(samePromptMessage("$MDU:prompt_filter[1a2b3c4d]", "anything at all"), false, "all marks matches nothing");
  assert.equal(samePromptMessage("hello there", "hello world"), false, "no mark: equality only");
});
