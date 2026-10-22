/**
 * launch-timings — the launch's step timer (runtime-instances.md §14.11):
 * each named step and its parts recorded in launch order, a part closed by
 * the next step, nothing a misuse or a broken clock can make throw, the
 * record read back from a log, medians, the two printed forms; and the
 * steps are one fixed, documented set.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  asLaunchTimings, countGitCall, countGitSandbox, formatCost, formatTimings, formatTimingsTable, gitCounts, LAUNCH_STEPS, LaunchTimer, median, medianTimings,
  stepOrder, timingsFromLog, timingsLogLine, TIMINGS_LINE_PREFIX, type LaunchTimings,
} from "../../src/launch-timings.js";
import { launchPostureEvent, sessionExitEvent } from "../../src/services/observe.js";

/** A clock the test moves by hand. */
function clock(start = 1000): { now: () => number; tick: (ms: number) => void } {
  let t = start;
  return { now: () => t, tick: (ms) => { t += ms; } };
}

/** A record's times alone (the costs have their own test). */
function timesOnly(t: LaunchTimings): LaunchTimings {
  return { v: t.v, totalMs: t.totalMs, steps: t.steps.map((s) => ({ step: s.step, ms: s.ms })) };
}

test("steps are recorded in order, each until the next starts; the total counts from the timer's start", () => {
  const c = clock();
  const t = new LaunchTimer({ now: c.now });
  t.step("plan"); c.tick(10);
  t.step("arbiter"); c.tick(25);
  t.step("services"); c.tick(300);
  t.end(); c.tick(5);
  assert.deepEqual(timesOnly(t.snapshot()), {
    v: 1, totalMs: 340,
    steps: [{ step: "plan", ms: 10 }, { step: "arbiter", ms: 25 }, { step: "services", ms: 300 }],
  });
});

test("the `mandu` command: a `node` step from the process start, and the total counts from there", () => {
  const c = clock(176);
  const t = new LaunchTimer({ cli: true, now: c.now });
  assert.equal(t.started, false, "only the node step: not a launch yet");
  t.step("plan"); c.tick(4);
  t.end();
  assert.equal(t.started, true);
  assert.deepEqual(timesOnly(t.snapshot()), { v: 1, totalMs: 180, steps: [{ step: "node", ms: 176 }, { step: "plan", ms: 4 }] });
});

test("parts nest under the running step, in the order they started; an open part ends with its step", () => {
  const c = clock();
  const t = new LaunchTimer({ now: c.now });
  t.step("secrets"); c.tick(2);
  const endDiscovery = t.span("discovery"); c.tick(100);
  endDiscovery();
  endDiscovery(); // a second end does nothing
  c.tick(3);
  t.span("history"); // never ended by its caller (it threw)
  c.tick(50);
  t.step("placeholder-check"); c.tick(1);
  t.end();
  const s = timesOnly(t.snapshot());
  assert.deepEqual(s.steps, [
    { step: "secrets", ms: 155 },
    { step: "secrets.discovery", ms: 100 },
    { step: "secrets.history", ms: 50 },
    { step: "placeholder-check", ms: 1 },
  ]);
  assert.ok(s.steps[0]!.ms >= s.steps[1]!.ms + s.steps[2]!.ms, "a step's time includes its parts'");
});

test("snapshot: only finished steps; `from` keeps one step and those after it (the session_exit event's part)", () => {
  const c = clock();
  const t = new LaunchTimer({ now: c.now });
  t.step("posture"); c.tick(1);
  t.step("agent"); c.tick(40);
  assert.deepEqual(t.snapshot().steps.map((s) => s.step), ["posture"], "the running step is not in it");
  t.step("teardown.index"); c.tick(2);
  t.step("teardown.services"); c.tick(7);
  t.end();
  assert.deepEqual(timesOnly(t.snapshot({ from: "agent" })).steps, [
    { step: "agent", ms: 40 }, { step: "teardown.index", ms: 2 }, { step: "teardown.services", ms: 7 },
  ]);
  assert.deepEqual(t.snapshot({ from: "teardown.records" }).steps, [], "a step never started: nothing");
});

test("failure-safe: a misuse is ignored, a throwing clock never throws, a runaway loop cannot grow the record", () => {
  const c = clock();
  const t = new LaunchTimer({ now: c.now });
  t.end(); // nothing running
  assert.doesNotThrow(() => t.span("discovery")()); // a part outside any step: a no-op
  assert.deepEqual(t.snapshot().steps, []);
  const broken = new LaunchTimer({ now: () => { throw new Error("no clock"); } });
  assert.doesNotThrow(() => { broken.step("plan"); broken.span("x")(); broken.end(); broken.snapshot(); });
  assert.equal(broken.snapshot().v, 1);
  t.step("secrets");
  for (let i = 0; i < 10_000; i++) t.span("history")();
  t.end();
  assert.ok(t.snapshot().steps.length <= 128, "bounded");
  const back = new LaunchTimer({ now: () => -5 });
  back.step("plan"); back.end();
  assert.ok(back.snapshot().steps.every((s) => s.ms >= 0), "never a negative time");
});

test("overhead: a step and a part cost far under a millisecond", () => {
  // CPU time, best of five after a warm-up: wall time on a loaded CI guest
  // measured the scheduler, not the timer (master pipeline 12720, 0.1 ms).
  const n = 100;
  const run = (): number => {
    const t = new LaunchTimer();
    const c0 = process.cpuUsage();
    for (let i = 0; i < n; i++) { t.step("secrets"); t.span("history")(); }
    t.end();
    t.snapshot();
    const c = process.cpuUsage(c0);
    return (c.user + c.system) / 1000 / n;
  };
  run();
  const best = Math.min(...Array.from({ length: 5 }, run));
  assert.ok(best < 0.05, `well under 1 ms for a whole launch's ~30 marks (${best.toFixed(4)} ms a mark)`);
});

test("costs: each top-level step's CPU time, git calls and sandboxes from the counters; none on a part; the whole record's from the origin", () => {
  const c = clock();
  let cpu = 5_000; // µs
  const n = { git: 7, sandboxes: 2 }; // what ran before this launch
  const t = new LaunchTimer({ now: c.now, cpuUs: () => cpu, counts: () => ({ ...n }) });
  t.step("arbiter"); c.tick(10); cpu += 4_000; n.git += 1; n.sandboxes += 1;
  t.step("secrets");
  const endHistory = t.span("history");
  c.tick(100); cpu += 30_400; n.git += 40;
  endHistory();
  t.step("agent"); c.tick(50); cpu += 1_000;
  t.step("teardown.placeholder"); c.tick(80); cpu += 9_600; n.git += 12; n.sandboxes += 12;
  t.end();
  const s = t.snapshot();
  assert.deepEqual(s.steps, [
    { step: "arbiter", ms: 10, cpuMs: 4, git: 1, sandboxes: 1 },
    { step: "secrets", ms: 100, cpuMs: 30, git: 40, sandboxes: 0 },
    { step: "secrets.history", ms: 100 },
    { step: "agent", ms: 50, cpuMs: 1, git: 0, sandboxes: 0 },
    { step: "teardown.placeholder", ms: 80, cpuMs: 10, git: 12, sandboxes: 12 },
  ], "a part's window overlaps its siblings': no cost on it");
  assert.deepEqual(s.cost, { cpuMs: 45, git: 53, sandboxes: 13 }, "the whole record's, the calls before the timer's start left out");
  assert.equal(t.snapshot({ from: "agent" }).cost, undefined, "a part of the record has no whole-record cost");
  // The `mandu` command: its process's CPU time and counters count from zero.
  const cli = new LaunchTimer({ cli: true, now: () => 120, cpuUs: () => 90_000, counts: () => ({ git: 1, sandboxes: 0 }) });
  cli.step("plan"); cli.end();
  assert.deepEqual(cli.snapshot().steps[0], { step: "node", ms: 120, cpuMs: 90, git: 1, sandboxes: 0 });
  // A counter that throws costs the record its costs, never the record.
  const broken = new LaunchTimer({ now: c.now, cpuUs: () => { throw new Error("no getrusage"); } });
  broken.step("plan"); c.tick(3); broken.end();
  assert.deepEqual(broken.snapshot().steps, [{ step: "plan", ms: 3 }]);
  assert.equal(broken.snapshot().cost, undefined);
});

test("the counters: a git call and a sandbox counted by the runners, read by every timer", () => {
  const before = gitCounts();
  countGitCall(true);
  countGitCall(false);
  countGitSandbox();
  assert.deepEqual(gitCounts(), { git: before.git + 2, sandboxes: before.sandboxes + 2 });
  const t = new LaunchTimer();
  t.step("secrets");
  countGitCall(false);
  t.end();
  const s = t.snapshot().steps[0]!;
  assert.equal(s.git, 1);
  assert.equal(s.sandboxes, 0);
  assert.ok(Number.isInteger(s.cpuMs) && s.cpuMs! >= 0);
});

test("the log line round-trips; the last one in a log wins (the end's, over the one before the agent); junk is no record", () => {
  const a: LaunchTimings = { v: 1, totalMs: 900, steps: [{ step: "plan", ms: 3 }] };
  const b: LaunchTimings = { v: 1, totalMs: 1800, steps: [{ step: "plan", ms: 3 }, { step: "agent", ms: 600 }] };
  assert.ok(timingsLogLine(a).startsWith(TIMINGS_LINE_PREFIX));
  const log = ["mandu 0.2: launch of claude", timingsLogLine(a), "mandu: something", timingsLogLine(b), `${TIMINGS_LINE_PREFIX}{not json`].join("\n");
  assert.deepEqual(timingsFromLog(log), b);
  assert.equal(timingsFromLog("mandu: nothing here\n"), null);
  assert.equal(asLaunchTimings({ v: 2, totalMs: 1, steps: [] }), null);
  assert.equal(asLaunchTimings({ v: 1, totalMs: 1, steps: [{ step: "x", ms: "1" }] }), null);
  // Costs: kept when valid; a bad one is left out, never the record.
  const withCost = { v: 1, totalMs: 9, steps: [{ step: "secrets", ms: 5, cpuMs: 3, git: 40, sandboxes: 0 }], cost: { cpuMs: 8, git: 52, sandboxes: 13 } };
  assert.deepEqual(timingsFromLog(timingsLogLine(withCost as LaunchTimings)), withCost);
  assert.deepEqual(asLaunchTimings({ v: 1, totalMs: 9, steps: [{ step: "s", ms: 5, git: -1, sandboxes: "2", cpuMs: Infinity }], cost: { git: "x" } }),
    { v: 1, totalMs: 9, steps: [{ step: "s", ms: 5 }] });
});

test("medians: per step over the records that have it, and of the totals", () => {
  assert.equal(median([3, 1, 2]), 2);
  assert.equal(median([4, 1, 3, 2]), 2.5);
  assert.equal(median([]), 0);
  const r = (total: number, plan: number, extra?: number): LaunchTimings => ({
    v: 1, totalMs: total, steps: [{ step: "plan", ms: plan }, ...(extra !== undefined ? [{ step: "secrets.history", ms: extra }] : [])],
  });
  const m = medianTimings([r(1000, 10, 100), r(2000, 30), r(1500, 20, 300)]);
  assert.equal(m.totalMs, 1500);
  assert.deepEqual(m.steps, [{ step: "plan", ms: 20 }, { step: "secrets.history", ms: 200 }]);
  assert.equal(m.cost, undefined, "no record held a cost");
  const c = medianTimings([{ ...r(1, 1), cost: { git: 50, sandboxes: 13 } }, { ...r(1, 1), cost: { git: 60, sandboxes: 13, cpuMs: 400 } }, r(1, 1)]);
  assert.deepEqual(c.cost, { cpuMs: 400, git: 55, sandboxes: 13 }, "each cost over the records that hold it");
  assert.deepEqual(stepOrder([{ v: 1, totalMs: 1, steps: [{ step: "future-step", ms: 1 }, { step: "agent", ms: 1 }, { step: "plan", ms: 1 }] }]),
    ["plan", "agent", "future-step"], "the documented order first, an unknown step after");
});

test("the printed forms: --verbose's breakdown and `mandu log --timings`'s table (median first)", () => {
  const t: LaunchTimings = { v: 1, totalMs: 1837, steps: [{ step: "secrets", ms: 666 }, { step: "secrets.discovery", ms: 120 }, { step: "agent", ms: 192 }] };
  const lines = formatTimings(t);
  assert.equal(lines[0], "mandu: launch timings: 1837 ms in all");
  assert.match(lines[1]!, /^ {2}secrets +666 ms$/);
  assert.match(lines[2]!, /^ {4}discovery +120 ms$/, "a part is indented under its step");
  const table = formatTimingsTable([
    { label: "10-21 09:12", timings: t },
    { label: "10-21 09:10", timings: { ...t, totalMs: 1700 } },
  ]);
  assert.match(table[0]!, /^step \(ms\) +median +10-21 09:12 +10-21 09:10$/);
  assert.match(table[1]!, /^total +1769 +1837 +1700$/);
  assert.equal(formatTimingsTable([]).length, 0);
  assert.ok(!formatTimingsTable([{ label: "one", timings: t }])[0]!.includes("median"), "one launch: no median column");
  assert.ok(!table.some((l) => /git calls|sandboxes|cpu/.test(l)), "no cost rows for records without costs");
  // With costs: beside each top-level step, after the total, and as rows of the table.
  const c: LaunchTimings = {
    v: 1, totalMs: 900, cost: { cpuMs: 400, git: 69, sandboxes: 13 },
    steps: [{ step: "secrets", ms: 150, cpuMs: 250, git: 38, sandboxes: 0 }, { step: "secrets.history", ms: 120 }, { step: "teardown.placeholder", ms: 110, cpuMs: 56, git: 12, sandboxes: 12 }],
  };
  const cl = formatTimings(c);
  assert.equal(cl[0], "mandu: launch timings: 900 ms in all (cpu 400 ms, 69 git, 13 sandboxes)");
  assert.match(cl[1]!, /^ {2}secrets +150 ms {3}cpu 250 ms, 38 git, 0 sandboxes$/);
  assert.match(cl[2]!, /^ {4}history +120 ms$/, "a part: its time alone");
  assert.match(cl[3]!, /^ {2}teardown\.placeholder +110 ms {3}cpu 56 ms, 12 git, 12 sandboxes$/);
  assert.equal(formatCost({ sandboxes: 1 }), "1 sandbox");
  const ct = formatTimingsTable([{ label: "a", timings: c }, { label: "b", timings: t }]);
  assert.match(ct[2]!, /^ {2}cpu +400 +400 +-$/);
  assert.match(ct[3]!, /^ {2}git calls +69 +69 +-$/);
  assert.match(ct[4]!, /^ {2}sandboxes +13 +13 +-$/);
});

test("the events carry the record: launch_posture the steps before the agent, session_exit the rest", () => {
  const before: LaunchTimings = { v: 1, totalMs: 1300, steps: [{ step: "plan", ms: 3 }] };
  const after: LaunchTimings = { v: 1, totalMs: 1800, steps: [{ step: "agent", ms: 400 }] };
  const posture = launchPostureEvent({ scopeId: "s", target: "claude", argv0: "claude", notes: [], timings: before });
  assert.deepEqual(posture["timings"], before);
  assert.ok(!("timings" in launchPostureEvent({ scopeId: "s", target: "claude", argv0: "claude", notes: [] })));
  assert.deepEqual(sessionExitEvent({ scopeId: "s", code: 0, durationMs: 1, timings: after })["timings"], after);
});

test("the steps are one fixed set, each named in runtime-instances.md §14.11, with no name twice", () => {
  const names = LAUNCH_STEPS.map(([n]) => n);
  assert.equal(new Set(names).size, names.length);
  for (const [n] of LAUNCH_STEPS) {
    const dot = n.indexOf(".");
    if (dot > 0 && n.startsWith("secrets.")) assert.ok(names.indexOf("secrets") < names.indexOf(n), `${n} after its step`);
  }
  const doc = readFileSync(join(import.meta.dirname, "..", "..", "..", "docs", "design", "architecture", "runtime-instances.md"), "utf8");
  const section = doc.slice(doc.indexOf("### 14.11"));
  assert.ok(section.length > 0 && doc.includes("### 14.11"), "the section exists");
  for (const n of names) assert.ok(section.includes(`\`${n}\``), `the doc names the step \`${n}\``);
});
