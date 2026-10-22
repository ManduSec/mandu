/**
 * launch-budget-verdict — the launch-time budget check's arithmetic
 * (tests/lib/launch-budget.ts, runtime-instances.md §14.11): a cell's
 * medians, the baseline file, and when a cell fails. The launches
 * themselves run in the nightly (tests/env/launch-budget.test.ts); this is
 * the part that decides, checked every push.
 *
 * Pure: no launch, no arbiter, no axis read (mode `off`, stated).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { stateAxes } from "../lib/axes.js";
import {
  baselineOf, budgetVerdict, DEFAULT_SLACK, FLOOR_MS, measureCell, parseBaseline, WARN_FLOOR_MS, WARN_SLACK, type CellMeasure, type LaunchBudgetBaseline,
} from "../lib/launch-budget.js";
import { LAUNCH_STEPS } from "../../launcher/src/launch-timings.js";

stateAxes("off");

const HERE = dirname(fileURLToPath(import.meta.url));

const cell = (wallMs: number, steps: Record<string, number> = {}): CellMeasure => ({ wallMs, totalMs: wallMs - 40, steps });
const base = (cells: Record<string, CellMeasure>): LaunchBudgetBaseline =>
  ({ v: 1, recorded: "2026-10-21", where: "the CI guest", commit: "abc", runs: 7, cells });

test("measureCell: the median wall time, the median launch total, each step's median over the runs that have it", () => {
  const run = (wallMs: number, history?: number) => ({
    wallMs,
    timings: { v: 1 as const, totalMs: wallMs - 50, steps: [{ step: "plan", ms: wallMs / 100 }, ...(history !== undefined ? [{ step: "secrets.history", ms: history }] : [])] },
  });
  const m = measureCell([run(900, 40), run(1500), run(1100, 60)]);
  assert.equal(m.wallMs, 1100);
  assert.equal(m.totalMs, 1050);
  assert.deepEqual(m.steps, { plan: 11, "secrets.history": 50 });
});

test("a cell fails only over BOTH the slack and the floor; at or under either it passes", () => {
  assert.equal(DEFAULT_SLACK, 0.5);
  assert.equal(FLOOR_MS, 300);
  const b = base({ "claude empty": cell(1000), "codex empty": cell(400) });
  assert.deepEqual(budgetVerdict({ "claude empty": cell(1500) }, b).failures, [], "+50% exactly: not over");
  assert.equal(budgetVerdict({ "claude empty": cell(1501) }, b).failures.length, 1, "over +50% and +300 ms");
  assert.match(budgetVerdict({ "claude empty": cell(2040) }, b).failures[0]!, /^claude empty: 2040 ms against a baseline of 1000 ms \(\+104%/);
  assert.deepEqual(budgetVerdict({ "codex empty": cell(690) }, b).failures, [], "+72% but only +290 ms: a short launch's noise");
  assert.equal(budgetVerdict({ "codex empty": cell(701) }, b).failures.length, 1);
  assert.deepEqual(budgetVerdict({ "claude empty": cell(700) }, b).failures, [], "faster is never a failure");
  assert.deepEqual(budgetVerdict({ "claude empty": cell(1400) }, b, { slack: 0.3 }).failures.length, 1, "the slack is a knob");
});

test("creep: a WARN line, never a failure, past +20% AND +150 ms but within the budget; it names the steps that grew most", () => {
  assert.equal(WARN_SLACK, 0.2);
  assert.equal(WARN_FLOOR_MS, 150);
  const b = base({ "claude devhome": cell(1000, { services: 300, secrets: 200, "secrets.history": 150, agent: 160 }), "codex empty": cell(500) });
  const v = budgetVerdict({ "claude devhome": cell(1250, { services: 320, secrets: 400, "secrets.history": 330, agent: 170 }) }, b);
  assert.deepEqual(v.failures, []);
  assert.equal(v.warnings.length, 1);
  assert.equal(v.warnings[0], "WARN claude devhome: 1250 ms against a baseline of 1000 ms (+25%, over +20% and +150 ms; not a failure); grew most: secrets +200 ms, services +20 ms");
  assert.ok(v.report.includes(v.warnings[0]!), "the WARN line is in the printed breakdown too");
  assert.deepEqual(budgetVerdict({ "claude devhome": cell(1200) }, b).warnings, [], "+20% exactly: no warning");
  assert.deepEqual(budgetVerdict({ "codex empty": cell(640) }, b).warnings, [], "+28% but only +140 ms: no warning");
  assert.equal(budgetVerdict({ "codex empty": cell(651) }, b).warnings.length, 1);
  const failing = budgetVerdict({ "claude devhome": cell(1600) }, b);
  assert.equal(failing.failures.length, 1);
  assert.deepEqual(failing.warnings, [], "over the budget is a failure, not also a warning");
  assert.deepEqual(budgetVerdict({ "claude devhome": cell(1250) }, null).warnings, [], "no baseline: nothing to creep from");
});

test("steps are compared and marked, never failed; the report is printed either way", () => {
  const b = base({ "claude repo": cell(1000, { services: 240, "secrets.history": 50, agent: 160 }) });
  const v = budgetVerdict({ "claude repo": cell(1100, { services: 250, "secrets.history": 400, agent: 160, "teardown.exit": 4 }) }, b);
  assert.deepEqual(v.failures, [], "a step over its own baseline alone fails nothing");
  const line = (re: RegExp): string => v.report.find((l) => re.test(l)) ?? "";
  assert.match(v.report[0]!, /against the baseline of 2026-10-21 \(the CI guest, abc\)/);
  assert.match(line(/^claude repo:/), /wall 1100 ms against 1000 ms \(\+10%\)/);
  assert.match(line(/history/), /^ {4}history +400 ms {2}\(baseline +50 ms, \+700%\) {2}over$/, "a part under its step, marked");
  assert.ok(!line(/services/).endsWith("over"), "+4%: not marked");
  assert.match(line(/teardown\.exit/), /^ {2}teardown\.exit +4 ms$/, "a step the baseline lacks: just its number");
});

test("no baseline, a new cell, a missing cell: reported, never failed", () => {
  assert.deepEqual(budgetVerdict({ "claude empty": cell(5000) }, null).failures, []);
  assert.match(budgetVerdict({ "claude empty": cell(5000) }, null).report[0]!, /no baseline recorded/);
  const v = budgetVerdict({ "goose empty": cell(5000) }, base({ "claude empty": cell(900) }));
  assert.deepEqual(v.failures, []);
  assert.ok(v.report.some((l) => /^goose empty: .*no baseline for this cell/.test(l)));
  assert.ok(v.report.some((l) => /^claude empty: not measured this run/.test(l)));
});

test("the baseline file: what a run prints parses back; a broken one says why", () => {
  const measured = { "claude empty": cell(900, { plan: 20 }) };
  const b = baselineOf(measured, { recorded: "2026-10-21", where: "guest", commit: "abc", runs: 7 });
  assert.deepEqual(parseBaseline(JSON.stringify(b)), b);
  assert.match(String(parseBaseline("{")), /^not JSON/);
  assert.match(String(parseBaseline('{"v":2,"cells":{}}')), /not a v1 baseline/);
  assert.match(String(parseBaseline('{"v":1,"cells":{"x":{"wallMs":1}}}')), /cell x/);
});

test("the recorded baseline (tests/env/launch-budget-baseline.json) parses, names claude and codex from both places, and only documented steps", () => {
  const b = parseBaseline(readFileSync(join(HERE, "..", "env", "launch-budget-baseline.json"), "utf8"));
  assert.ok(typeof b !== "string", String(b));
  for (const name of ["claude empty", "claude repo", "claude devhome", "codex empty", "codex repo", "codex devhome"]) assert.ok(name in b.cells, name);
  const known = new Set<string>(LAUNCH_STEPS.map(([n]) => n));
  for (const [name, c] of Object.entries(b.cells)) {
    for (const s of Object.keys(c.steps)) assert.ok(known.has(s), `${name}: ${s} is a documented step`);
    assert.ok(c.wallMs >= c.totalMs && c.totalMs > 0, `${name}: the wall time holds the launch's total`);
  }
});
