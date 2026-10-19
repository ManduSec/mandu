/**
 * metrics.test — node:test unit tests for the metrics aggregator.
 *
 * Aggregates a mix of attack + benign case outcomes and asserts asr /
 * blockedRate / passRate; checks the TAP-style printout footer; and verifies
 * compareOverhead computes token / latency deltas. Offline.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  aggregate,
  compareOverhead,
  printReport,
  type CaseOutcome,
  type EvalReport,
} from "./metrics.js";

function atk(id: string, outcome: CaseOutcome["outcome"], extra: Partial<CaseOutcome> = {}): CaseOutcome {
  return { id, kind: "attack", outcome, detail: "", ...extra };
}
function ben(id: string, outcome: CaseOutcome["outcome"], extra: Partial<CaseOutcome> = {}): CaseOutcome {
  return { id, kind: "benign", outcome, detail: "", ...extra };
}

// ── aggregate ───────────────────────────────────────────────────────────────────

test("aggregate computes asr / blockedRate / passRate over a mix", () => {
  const cases: CaseOutcome[] = [
    atk("A1", "attack_success"),
    atk("A2", "attack_blocked"),
    atk("A3", "attack_blocked"),
    atk("A4", "no_attack"),
    ben("B1", "pass"),
    ben("B2", "pass"),
    ben("B3", "fail"),
  ];
  const r = aggregate("full", cases);

  assert.equal(r.defense, "full");
  // 4 attacks: 1 success, 2 blocked, 1 no-attack.
  assert.equal(r.attack.total, 4);
  assert.equal(r.attack.success, 1);
  assert.equal(r.attack.blocked, 2);
  assert.equal(r.attack.noAttack, 1);
  assert.equal(r.attack.asr, 1 / 4);
  assert.equal(r.attack.blockedRate, 2 / 4);
  // 3 benign: 2 pass, 1 fail.
  assert.equal(r.benign.total, 3);
  assert.equal(r.benign.pass, 2);
  assert.equal(r.benign.fail, 1);
  assert.equal(r.benign.passRate, 2 / 3);
});

test("aggregate handles empty / single-sided case lists without dividing by zero", () => {
  const empty = aggregate("none", []);
  assert.equal(empty.attack.asr, 0);
  assert.equal(empty.attack.blockedRate, 0);
  assert.equal(empty.benign.passRate, 0);

  const attacksOnly = aggregate("none", [atk("A1", "attack_success"), atk("A2", "attack_success")]);
  assert.equal(attacksOnly.attack.asr, 1, "no-defense baseline: every attack succeeds → ASR 1.0");
  assert.equal(attacksOnly.benign.total, 0);
  assert.equal(attacksOnly.benign.passRate, 0);
});

// ── printReport ─────────────────────────────────────────────────────────────────

test("printReport emits a TAP-style pass/fail footer a CI suite can parse", () => {
  const r = aggregate("full", [
    atk("A1", "attack_success"), // undesirable → fail
    atk("A2", "attack_blocked"), // good        → pass
    atk("A3", "no_attack"),      // good        → pass
    ben("B1", "pass"),           // good        → pass
    ben("B2", "fail"),           // undesirable → fail
  ]);
  const out = printReport(r);
  assert.match(out, /# tests 5/);
  assert.match(out, /# pass 3/);
  assert.match(out, /# fail 2/);
  // The headline metrics render.
  assert.match(out, /ASR\s+:\s+33\.3%/);
  assert.match(out, /defense: full/);
  // Per-case rows mark undesirable outcomes "not ok".
  assert.match(out, /not ok \[atk\] A1/);
  assert.match(out, /ok\s+\[atk\] A2/);
  assert.match(out, /not ok \[ben\] B2/);
});

// ── the honest benign heading (BenignMeasure) ──────────────────────────────────

test("a fidelity report's benign block uses the canonical fidelity label + not-utility note", () => {
  const r = aggregate("full", [ben("B1", "pass"), atk("A1", "attack_blocked")], "fidelity");
  assert.equal(r.benignMeasure, "fidelity");
  const out = printReport(r);
  // The canonical user-facing term.
  assert.match(out, /Benign fidelity \(byte-fidelity \+ no-over-block\)/);
  assert.ok(!out.includes("Utility (benign)"), "a fidelity report must not carry the task-utility heading");
  // The annotation that defuses misreadings: not task completion, the NONE/FULL
  // benign contrast is uninformative, and where the real utility oracles live.
  assert.match(out, /NOT task completion/);
  assert.match(out, /NONE\/FULL[\s\S]*benign contrast carries no information/);
  assert.match(out, /EXACT-ANSWER/);
  assert.match(out, /AgentDojo/);
});

test("a task-utility (live) report keeps the utility heading and no fidelity note", () => {
  const live = printReport(aggregate("live-fake-full", [ben("B1", "pass")], "task_utility"));
  assert.match(live, /Utility \(benign\)/);
  assert.ok(!live.includes("byte-fidelity"), "live reports must not carry the fidelity note");

  // benignMeasure absent (back-compat) also defaults to the utility heading.
  const bare = printReport(aggregate("full", [ben("B1", "pass")]));
  assert.match(bare, /Utility \(benign\)/);
  assert.ok(!bare.includes("byte-fidelity"));
});

// ── compareOverhead ─────────────────────────────────────────────────────────────

test("compareOverhead computes token + latency deltas from per-case usage", () => {
  const baseline: EvalReport = aggregate("none", [
    atk("A1", "attack_success", { usage: { tokensIn: 100, tokensOut: 100 }, ms: 1000 }),
    ben("B1", "pass", { usage: { tokensIn: 300, tokensOut: 0 }, ms: 1000 }),
  ]);
  // Defended run: 50% more tokens (500 → 750), 20% more latency (2000 → 2400).
  const defended: EvalReport = aggregate("full", [
    atk("A1", "attack_blocked", { usage: { tokensIn: 200, tokensOut: 100 }, ms: 1200 }),
    ben("B1", "pass", { usage: { tokensIn: 450, tokensOut: 0 }, ms: 1200 }),
  ]);

  const overhead = compareOverhead(baseline, defended);
  // baseline tokens = 500, defended = 750 → +50%.
  assert.ok(overhead.tokensPct !== undefined);
  assert.ok(Math.abs(overhead.tokensPct! - 0.5) < 1e-9, `tokensPct=${overhead.tokensPct}`);
  // baseline ms = 2000, defended = 2400 → +20%.
  assert.ok(overhead.msPct !== undefined);
  assert.ok(Math.abs(overhead.msPct! - 0.2) < 1e-9, `msPct=${overhead.msPct}`);

  // Fold the overhead into the report and confirm it prints.
  defended.overhead = overhead;
  const out = printReport(defended);
  assert.match(out, /tokens\s+:\s+\+50\.0%/);
  assert.match(out, /latency\s+:\s+\+20\.0%/);
});

test("compareOverhead omits a delta when either side lacks that signal", () => {
  const baseline = aggregate("none", [atk("A1", "attack_success")]); // no usage / ms
  const defended = aggregate("full", [atk("A1", "attack_blocked", { usage: { tokensIn: 10, tokensOut: 0 } })]);
  const overhead = compareOverhead(baseline, defended);
  assert.equal(overhead.tokensPct, undefined, "baseline has no token usage → no token delta");
  assert.equal(overhead.msPct, undefined, "neither side has ms → no latency delta");
});

test("compareOverhead computes a negative (savings) delta", () => {
  const baseline = aggregate("none", [atk("A1", "attack_success", { ms: 2000 })]);
  const defended = aggregate("full", [atk("A1", "attack_blocked", { ms: 1500 })]);
  const overhead = compareOverhead(baseline, defended);
  assert.ok(Math.abs(overhead.msPct! - -0.25) < 1e-9, `msPct=${overhead.msPct}`);
});
