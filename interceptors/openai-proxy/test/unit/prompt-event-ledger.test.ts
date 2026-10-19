/**
 * prompt-event-ledger — which `prompt_filter` events the openai-proxy records
 * (src/prompt-filter.ts PromptEventLedger, the anthropic-proxy twin; confidentiality-plan-15-prompt-filter.md
 * §8, §13.7). Pure.
 *
 * Proves: a segment's first finding is recorded, an unchanged resend is not,
 * a changed outcome (a verdict, an ask's answer) is; a segment recorded with
 * a finding and now answered with none is recorded ONCE with no findings and
 * the turn remembered from before (the arbiter names none then), and again
 * when the finding comes back; a segment never recorded with a finding
 * records nothing, unless the arbiter names its turn (a noted message, plan
 * 15 §13.7 item 10): then a fresh ledger (a restarted proxy) or an evicted
 * entry records the clearing once; sessions and texts are kept apart; the
 * ledger is bounded, oldest out. Never the value: the entries are outcome keys and opaque
 * references.
 *
 * Axes: none is pinned (no arbiter; pure bookkeeping).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { PromptEventLedger } from "../../src/prompt-filter.js";
import type { PromptFindingWire } from "../../src/arbiter-client.js";

const TURN = "a".repeat(32);
const finding = (over: Partial<PromptFindingWire> = {}): PromptFindingWire => ({ start: 4, end: 14, category: "acme.ticket", filterId: "acme-dlp", action: "redact", ...over });
const seg = (findings: PromptFindingWire[], over: { hash?: string; action?: "pass" | "rewrite" | "block"; skipped?: number; turn?: string } = {}) => ({
  hash: over.hash ?? "h1", action: over.action ?? (findings.length ? "rewrite" as const : "pass" as const), skipped: over.skipped ?? 0, findings, ...(over.turn !== undefined ? { turn: over.turn } : {}),
});

test("first finding recorded with its turn; an unchanged resend is not; a changed outcome is", () => {
  const l = new PromptEventLedger();
  assert.deepEqual(l.next("s", seg([finding()], { turn: TURN })), { turn: TURN });
  assert.equal(l.next("s", seg([finding()], { turn: TURN })), null, "the resend of the same outcome");
  assert.deepEqual(l.next("s", seg([finding({ let: "once" })], { turn: TURN })), { turn: TURN }, "a verdict let it through");
  assert.deepEqual(l.next("s", seg([finding({ action: "ask", hold: { state: "sent" } })], { turn: TURN })), { turn: TURN }, "an ask's answer");
});

test("a finding gone (an exception) is recorded once with no findings and the remembered turn; it coming back is recorded again", () => {
  const l = new PromptEventLedger();
  assert.deepEqual(l.next("s", seg([finding()], { turn: TURN })), { turn: TURN });
  assert.deepEqual(l.next("s", seg([])), { turn: TURN }, "no findings now: recorded, under the message's turn");
  assert.equal(l.next("s", seg([])), null, "already recorded as clear");
  assert.deepEqual(l.next("s", seg([finding()], { turn: TURN })), { turn: TURN }, "the finding back (the exception removed)");
});

test("a segment never recorded with a finding records nothing; skipped values alone are an outcome", () => {
  const l = new PromptEventLedger();
  assert.equal(l.next("s", seg([])), null);
  assert.equal(l.next("s", seg([])), null);
  assert.deepEqual(l.next("s", seg([], { hash: "h2", skipped: 1 })), {}, "a value the prompt floor left as typed, no turn");
  assert.deepEqual(l.next("s", seg([], { hash: "h2" })), {}, "and it gone");
});

test("sessions and texts are kept apart; bounded, oldest out", () => {
  const l = new PromptEventLedger(2);
  assert.ok(l.next("s1", seg([finding()], { turn: TURN })));
  assert.ok(l.next("s2", seg([finding()], { turn: TURN })), "another session's same text is its own");
  assert.ok(l.next("s1", seg([finding()], { hash: "h9" })), "another text is its own");
  // s1|h1 was evicted (cap 2): with no turn from the arbiter its clearing
  // cannot be told, so nothing is recorded; with the noted turn it is.
  assert.equal(l.next("s1", seg([])), null);
  assert.deepEqual(l.next("s2", seg([])), { turn: TURN });
  assert.deepEqual(l.next("s1", seg([], { turn: TURN })), { turn: TURN });
});

test("a restarted proxy (a fresh ledger): a no-finding answer carrying the arbiter's turn is recorded once under it; without a turn nothing (plan 15 §13.7 item 10)", () => {
  const a = new PromptEventLedger();
  assert.deepEqual(a.next("s", seg([finding()], { turn: TURN })), { turn: TURN }, "proxy A records the finding");
  const b = new PromptEventLedger(); // proxy B: nothing of A's memory
  assert.equal(b.next("s", seg([])), null, "no turn named: the note is kept (fail-closed), nothing recorded");
  assert.deepEqual(b.next("s", seg([], { turn: TURN })), { turn: TURN }, "the noted message's turn: the clearing is recorded");
  assert.equal(b.next("s", seg([], { turn: TURN })), null, "once");
  assert.deepEqual(b.next("s", seg([finding()], { turn: TURN })), { turn: TURN }, "the finding back is recorded again");
  // A finding the policy now only logs (no reference, so no turn of its own)
  // is a changed outcome, recorded under the noted turn.
  const c = new PromptEventLedger();
  assert.deepEqual(c.next("s", seg([finding({ action: "log" })], { action: "pass", turn: TURN })), { turn: TURN });
});
