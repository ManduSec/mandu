/**
 * send-without-actions.test — which Approvals cards offer "Send without it"
 * (dashboard.md §4.34, confidentiality.md §4 "Send without it", 2026-10-17), and how an
 * answered one reads. Mandu-new.
 *
 * The arbiter decides (its read-time `stripOffered` mark on a waiting card
 * about a secret's placeholder in a request); the panel only follows it,
 * keeping the mark on the row (never on a HIGH session's or a program's
 * send card, even if marked), and the PRODUCT's card adds the answer
 * between Always allow and Block (`sendWithoutActions`). The panel's own
 * `actions` stay the three answers: the inspector keys a once-scoped action
 * to Allow once, so it must never be handed this one. An answered one is
 * "Sent without it" with no reversal button, never "Blocked".
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import type { PolicySnapshot, VerdictEntry } from "../../../src/policy-model.js";
import { answeredOutcome, buildHomeViewModel, sendWithoutActions, type HomeInput } from "../../../src/view-model/home.js";

const BARE: PolicySnapshot = { specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__" };
const EXT = { posture: { integrity: false, confidentiality: true }, usage: { rules: [], sensitivePaths: [] } };
const SYM = "$MDU:nomodel_Read[ab12cd34]";
const panel = (rows: VerdictEntry[]) => toPolicyPanelViewModel({ ...BARE, ...EXT, verdicts: rows } as PolicySnapshot);
const row = (over: Partial<VerdictEntry> = {}): VerdictEntry => ({
  id: "egr-1", symbol: SYM, destination: "api.github.com", status: "pending", reason: "secret at unbound destination",
  count: 1, firstSeen: 10, lastSeen: 20, sessions: ["s-1"], ...over,
});

test("a card the arbiter marks: the product's card offers Send without it, between Always allow and Block; the panel's actions stay three", () => {
  const q = panel([row({ stripOffered: true })]).queue[0]!;
  assert.equal(q.stripOffered, true);
  assert.deepEqual(q.actions.map((a) => a.label), ["Allow once", "Always allow", "Block"], "the inspector is never handed it");
  const product = sendWithoutActions(q);
  assert.deepEqual(product.map((a) => a.label), ["Allow once", "Always allow", "Send without it", "Block"]);
  assert.deepEqual(product[2], { approve: false, scope: "once", strip: true, label: "Send without it" });
  assert.deepEqual(sendWithoutActions({ actions: product, stripOffered: true }), product, "added once");
});

test("an unmarked card, a HIGH session's card and a program's send card never offer it", () => {
  const plain = panel([row()]).queue[0]!;
  assert.equal(plain.stripOffered, undefined, "unmarked (an older arbiter, or not a secret's placeholder)");
  assert.ok(!sendWithoutActions(plain).some((a) => a.strip));
  const session = panel([row({ symbol: "session-net:s-1", destination: "evil.example", stripOffered: true })]).queue[0]!;
  assert.equal(session.stripOffered, undefined, "a HIGH session's request: content-agnostic");
  assert.ok(!sendWithoutActions(session).some((a) => a.strip));
  const holder = panel([row({ symbol: `holder-send:${JSON.stringify({ session: "s-1", files: ["/home/u/.env"] })}`, destination: "evil.example", stripOffered: true })]).queue[0]!;
  assert.equal(holder.stripOffered, undefined, "a program holding a secret: content-agnostic");
  assert.ok(!sendWithoutActions(holder).some((a) => a.strip));
  const answered = panel([row({ status: "approved", stripOffered: true })]).queue[0]!;
  assert.equal(answered.stripOffered, undefined, "an answered card");
});

test("an answered Send without it: no reversal, and it reads as sent without it, never Blocked", () => {
  const q = panel([row({ status: "denied", scope: "once", strip: true, consumedAt: 30, resolvedAt: 25 })]).queue[0]!;
  assert.deepEqual(q.actions, []);
  assert.equal(q.strip, true);
  assert.equal(answeredOutcome(q), "without-used");
  assert.equal(answeredOutcome({ ...q, consumedAt: null }), "without");
  // a plain once denial is still Blocked
  const plain = panel([row({ status: "denied", scope: "once", resolvedAt: 25 })]).queue[0]!;
  assert.equal(answeredOutcome(plain), "blocked");
});

test("the product's home: a marked waiting card carries the answer, an answered one reads Sent without it", () => {
  const input: HomeInput = {
    sessions: [], facts: new Map(), configuredMode: "secrets", nowMs: 1_000, windowHours: 24, historyTotal: 0, home: "/home/u",
    panel: panel([row({ stripOffered: true }), row({ id: "egr-2", destination: "other.example", status: "denied", scope: "once", strip: true, consumedAt: 30, resolvedAt: 25 })]),
  };
  const vm = buildHomeViewModel(input);
  assert.deepEqual(vm.waiting[0]!.actions.map((a) => a.label), ["Allow once", "Always allow", "Send without it", "Block"]);
  const done = vm.answered.find((a) => a.id === "egr-2")!;
  assert.equal(done.outcome, "without-used");
  assert.deepEqual(done.actions, []);
});
