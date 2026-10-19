/**
 * session-batches.test — unit tests for the pure sidebar-shaping rules:
 * groupSessionsIntoBatches (sessions sharing a `batchId` were run together;
 * batch-less sessions group per LOCAL day and interleave chronologically),
 * batchTitle (human-meaningful headers) and buildSidebarSections (the
 * LIVE/TESTING split + test-run result join, dashboard.md §4.10). app.js only
 * RENDERS this.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  groupSessionsIntoBatches,
  buildSidebarSections,
  batchTitle,
  DAY_BATCH_PREFIX,
  DAY_TESTING_BATCH_PREFIX,
  RUNNING_WINDOW_MS,
  type SidebarTestRun,
} from "../../src/session-batches.js";
import { sessionTags, type SessionRef } from "../../src/event-source.js";

// These call the grouper with no `tz`, which keys days in the AMBIENT zone (the
// fallback for when server and browser share a host). That makes the fixtures'
// `day:` ids zone-dependent, so pin the zone: the Z-suffixed timestamps below
// then key to exactly the day they spell, and these tests stay about GROUPING.
// The zone behaviour this pin deliberately holds still — viewer-zone bucketing,
// UTC-midnight straddles — is local-day.test.ts's job, and it passes tz
// explicitly rather than leaning on the ambient one.
process.env.TZ = "UTC";

function s(
  id: string,
  batchId: string | undefined,
  lastTs: string | null,
  violated = false,
  label: string | null = null,
): SessionRef {
  return { id, label, eventCount: 1, firstTs: null, lastTs, violated, batchId, tags: sessionTags(id) };
}

test("groups sessions by batchId, newest batch first, input order within a batch", () => {
  const out = groupSessionsIntoBatches([
    s("a1", "B1", "2026-06-20T10:00:00.000Z"),
    s("a2", "B1", "2026-06-20T10:00:05.000Z"),
    s("b1", "B2", "2026-06-20T11:00:00.000Z"),
  ]);
  assert.deepEqual(out.map((b) => b.id), ["B2", "B1"], "B2 (newer) sorts first");
  assert.equal(out[1]!.sessions.length, 2);
  assert.deepEqual(out[1]!.sessions.map((x) => x.id), ["a1", "a2"], "within-batch input order preserved");
  assert.equal(out[0]!.lastTs, "2026-06-20T11:00:00.000Z");
});

test("batch-less sessions group per UTC day and INTERLEAVE chronologically (no pinned catch-all)", () => {
  const out = groupSessionsIntoBatches([
    s("u1", undefined, "2026-06-21T23:00:00.000Z"), // most recent overall → its day group leads
    s("a1", "B1", "2026-06-20T10:00:00.000Z"),
    s("u2", undefined, "2026-06-19T09:00:00.000Z"), // older day → separate group, after B1
  ]);
  assert.deepEqual(
    out.map((b) => b.id),
    [`${DAY_BATCH_PREFIX}2026-06-21`, "B1", `${DAY_BATCH_PREFIX}2026-06-19`],
    "day groups sort among the real batches by recency",
  );
  assert.equal(out[0]!.ungrouped, true);
  assert.equal(out[0]!.title, "2026-06-21", "a day group is titled by its ISO day (client prettifies)");
  assert.deepEqual(out[0]!.sessions.map((x) => x.id), ["u1"]);
  assert.deepEqual(out[2]!.sessions.map((x) => x.id), ["u2"]);
});

test("same-day batch-less sessions share one day group, input order preserved", () => {
  const out = groupSessionsIntoBatches([
    s("u1", undefined, "2026-06-20T23:00:00.000Z"),
    s("u2", undefined, "2026-06-20T09:00:00.000Z"),
  ]);
  assert.equal(out.length, 1);
  assert.equal(out[0]!.id, `${DAY_BATCH_PREFIX}2026-06-20`);
  assert.deepEqual(out[0]!.sessions.map((x) => x.id), ["u1", "u2"]);
});

test("a ts-less batch-less session lands in an 'undated' group that sinks last", () => {
  const out = groupSessionsIntoBatches([
    s("u1", undefined, null),
    s("a1", "B1", "2026-06-20T10:00:00.000Z"),
  ]);
  assert.deepEqual(out.map((b) => b.id), ["B1", `${DAY_BATCH_PREFIX}undated`]);
  assert.equal(out[1]!.title, "undated");
});

test("batch.violated rolls up any member; batch.lastTs is the max member ts", () => {
  const out = groupSessionsIntoBatches([
    s("a1", "B1", "2026-06-20T10:00:00.000Z", false),
    s("a2", "B1", "2026-06-20T10:00:09.000Z", true),
  ]);
  assert.equal(out[0]!.violated, true, "a folded batch still flags a violated member");
  assert.equal(out[0]!.lastTs, "2026-06-20T10:00:09.000Z");
});

test("empty → empty", () => {
  assert.deepEqual(groupSessionsIntoBatches([]), []);
});

// ── batchTitle: human-meaningful batch headers ────────────────────────────────

test("a live batch is titled by its first member's task label; label-less → 'run'", () => {
  const out = groupSessionsIntoBatches([
    s("1750000000-42", "L1", "2026-07-06T10:00:00.000Z", false, "Summarize notes.md and email me."),
    s("1750000001-43", "L1", "2026-07-06T10:01:00.000Z"),
    s("1750000002-44", "L2", "2026-07-06T09:00:00.000Z"),
  ]);
  assert.equal(out[0]!.title, "Summarize notes.md and email me.", "named by what the run did");
  assert.equal(out[1]!.title, "run", "no label anywhere → generic");
});

test("a long live label truncates with an ellipsis in the title", () => {
  const long = "A very long task prompt that would otherwise blow out the one-line batch header entirely";
  assert.equal(batchTitle([s("1750000000-42", "L1", null, false, long)]).length, 60);
  assert.match(batchTitle([s("1750000000-42", "L1", null, false, long)]), /…$/);
});

test("a test batch is titled by its members' e2e suite", () => {
  assert.equal(
    batchTitle([s("claude-e2e-bash-ipi-1750000002001", "R1", null)]),
    "claude e2e run",
  );
  assert.equal(
    batchTitle([s("replay-e2e-ipi-text-1750000002000", "R1", null)]),
    "replay e2e run",
  );
  assert.equal(
    batchTitle([
      s("claude-e2e-bash-ipi-1750000002001", "R1", null),
      s("replay-e2e-ipi-text-1750000002000", "R1", null),
    ]),
    "e2e run",
    "mixed suites → the generic e2e title",
  );
});

// ── buildSidebarSections: LIVE/TESTING split + run join (dashboard.md §4.10) ──

function run(runId: string, state: string, results: SidebarTestRun["results"] = []): SidebarTestRun {
  const counts = { pass: 0, fail: 0, skip: 0 };
  for (const r of results ?? []) counts[r.status] += 1;
  return { runId, suite: "e2e", label: "e2e → dashboard", state, since: 1, finishedAt: 2, counts, results };
}

test("splits by the test tag: TEST sessions → testing, the rest → live, each side batched independently", () => {
  const out = buildSidebarSections([
    s("1750000000-42", "L1", "2026-07-06T10:00:00.000Z"),           // live, batched
    s("1750000001-43", undefined, "2026-07-06T09:00:00.000Z"),      // live, loose
    s("replay-e2e-ipi-text-1750000002000", "R1", "2026-07-06T08:00:00.000Z"), // test, batched
    s("e2e-legacy-1750000003000", undefined, "2026-07-06T07:00:00.000Z"),      // test, loose (legacy id)
  ]);
  assert.deepEqual(out.live.map((b) => b.id), ["L1", `${DAY_BATCH_PREFIX}2026-07-06`]);
  assert.deepEqual(out.testing.map((b) => b.id), ["R1", `${DAY_TESTING_BATCH_PREFIX}2026-07-06`],
    "the testing side's day groups are re-keyed so the two sections never share a batch id");
  assert.deepEqual(out.live.flatMap((b) => b.sessions.map((x) => x.id)),
    ["1750000000-42", "1750000001-43"]);
  assert.deepEqual(out.testing.flatMap((b) => b.sessions.map((x) => x.id)),
    ["replay-e2e-ipi-text-1750000002000", "e2e-legacy-1750000003000"],
    "each side gets its OWN day groups");
});

test("joins a testing batch with its run (batch id === runId): title, summary, per-scenario results", () => {
  const runs = [run("R1", "failed", [
    { name: "replay-e2e[ipi-text]: replays", cls: "replay-e2e", scenario: "ipi-text", status: "pass" },
    { name: "claude-e2e[bash-ipi]: live", cls: "claude-e2e", scenario: "bash-ipi", status: "fail" },
    { name: "claude-e2e[greeting]: live", cls: "claude-e2e", scenario: "greeting", status: "skip" },
  ])];
  const sessions = [
    s("replay-e2e-ipi-text-1750000002000", "R1", "2026-07-06T08:00:00.000Z"),
    s("claude-e2e-bash-ipi-1750000002001", "R1", "2026-07-06T08:01:00.000Z"),
    s("claude-e2e-unknown-1750000002002", "R1", "2026-07-06T08:02:00.000Z"), // not in results
  ];
  const out = buildSidebarSections(sessions, runs);
  const batch = out.testing[0]!;
  assert.equal(batch.title, "e2e → dashboard", "the run's label overrides the member-derived title");
  assert.equal(batch.run?.runId, "R1");
  assert.equal(batch.run?.state, "failed");
  assert.deepEqual(batch.run?.counts, { pass: 1, fail: 1, skip: 1 });
  const byId = Object.fromEntries(batch.sessions.map((x) => [x.id, x.testResult]));
  assert.equal(byId["replay-e2e-ipi-text-1750000002000"], "pass");
  assert.equal(byId["claude-e2e-bash-ipi-1750000002001"], "fail");
  assert.equal(byId["claude-e2e-unknown-1750000002002"], undefined, "no result → no mark");
  // The input refs are NOT mutated (copies only).
  assert.equal(sessions[0]!.testResult, undefined);
});

test("the run's runtime carries onto BatchRunSummary (immediate docker/host batch badge)", () => {
  const dockerRun: SidebarTestRun = { ...run("RD", "running"), runtime: "docker" };
  const out = buildSidebarSections(
    [s("claude-e2e-reasoning-1750000004000", "RD", "2026-07-06T08:00:00.000Z")],
    [dockerRun],
  );
  assert.equal(out.testing[0]!.run?.runtime, "docker", "docker run → docker batch badge, from the run record");

  // A host run (or a legacy record without runtime) carries nothing → no chip.
  const out2 = buildSidebarSections(
    [s("claude-e2e-reasoning-1750000005000", "RH", "2026-07-06T08:00:00.000Z")],
    [run("RH", "passed")],
  );
  assert.equal(out2.testing[0]!.run?.runtime, undefined);
});

test("buildSidebarSections preserves checksVerdict/historyFidelity on testing session refs", () => {
  const out = buildSidebarSections(
    [
      // (a) joined with a run record → the annotate path copies ({ ...s, testResult }).
      { ...s("claude-e2e-bash-ipi-1750000002001", "R1", "2026-07-06T08:01:00.000Z"),
        checksVerdict: "pass", historyFidelity: "pass" },
      // (b) no matching run → the batch passes through untouched.
      { ...s("replay-e2e-ipi-text-1750000002000", "R2", "2026-07-06T08:00:00.000Z"),
        checksVerdict: "fail" },
    ],
    [run("R1", "passed", [
      { name: "claude-e2e[bash-ipi]: live", cls: "claude-e2e", scenario: "bash-ipi", status: "pass" },
    ])],
  );
  const joined = out.testing.find((b) => b.id === "R1")!.sessions[0]!;
  assert.equal(joined.testResult, "pass", "the run result is joined");
  assert.equal(joined.checksVerdict, "pass", "verdict survives the annotate copy");
  assert.equal(joined.historyFidelity, "pass", "fidelity survives the annotate copy");
  const passthrough = out.testing.find((b) => b.id === "R2")!.sessions[0]!;
  assert.equal(passthrough.checksVerdict, "fail", "verdict survives the run-less passthrough");
  assert.equal(passthrough.historyFidelity, undefined, "an absent fidelity stays absent");
});

test("testing batch rows sort by badge number (E2 < E10 < Re1; unnumbered trail by id); live keeps input order", () => {
  const out = buildSidebarSections([
    { ...s("replay-e2e-ipi-text-1750000002004", "R1", "2026-07-06T08:04:00.000Z"), testNumber: "Re1" },
    { ...s("claude-e2e-chain-fetch-write-read-1750000002003", "R1", "2026-07-06T08:03:00.000Z"), testNumber: "E10" },
    { ...s("claude-e2e-unregistered-1750000002002", "R1", "2026-07-06T08:02:00.000Z") }, // not in TEST_REGISTRY → no number
    { ...s("claude-e2e-reasoning-1750000002001", "R1", "2026-07-06T08:01:00.000Z"), testNumber: "E2" },
    s("1750000000-43", "L1", "2026-07-06T10:01:00.000Z"),
    s("1750000000-42", "L1", "2026-07-06T10:00:00.000Z"),
  ]);
  assert.deepEqual(
    out.testing[0]!.sessions.map((x) => x.testNumber ?? x.id),
    ["E2", "E10", "Re1", "claude-e2e-unregistered-1750000002002"],
    "numeric badge order (not lexicographic), prefix-grouped, unnumbered last",
  );
  assert.deepEqual(out.live[0]!.sessions.map((x) => x.id), ["1750000000-43", "1750000000-42"],
    "the Live side keeps its newest-first input order");
});

test("testing batches tally member verdicts into marks (testResult ?? checksVerdict); verdict-less → no marks", () => {
  const out = buildSidebarSections(
    [
      // The run joins testResult "skip", which overrides this session's own pass verdict.
      { ...s("claude-e2e-reasoning-1750000002001", "R1", "2026-07-06T08:01:00.000Z"), checksVerdict: "pass" },
      { ...s("claude-e2e-bash-ipi-1750000002002", "R1", "2026-07-06T08:02:00.000Z"), checksVerdict: "fail" },
      s("claude-e2e-unchecked-1750000002003", "R1", "2026-07-06T08:03:00.000Z"), // no verdict → uncounted
      s("replay-e2e-ipi-text-1750000002004", "R2", "2026-07-06T08:00:00.000Z"),  // run-less batch, no verdicts
      // A loose (batch-less) test session lands in a day-testing group WITH marks.
      { ...s("e2e-legacy-1750000003000", undefined, "2026-07-06T07:00:00.000Z"), checksVerdict: "pass" },
    ],
    [run("R1", "failed", [
      { name: "claude-e2e[reasoning]: live", cls: "claude-e2e", scenario: "reasoning", status: "skip" },
    ])],
  );
  assert.deepEqual(out.testing.find((b) => b.id === "R1")!.marks, { pass: 0, fail: 1, skip: 1 },
    "run-joined testResult wins over the session's own verdict; verdict-less members are uncounted");
  assert.equal(out.testing.find((b) => b.id === "R2")!.marks, undefined,
    "no member verdict → no marks (the header shows nothing, not '0 pass')");
  assert.deepEqual(out.testing.find((b) => b.id === `${DAY_TESTING_BATCH_PREFIX}2026-07-06`)!.marks,
    { pass: 1, fail: 0, skip: 0 }, "day-testing groups tally too");
  assert.equal(out.live.every((b) => b.marks === undefined), true, "live batches carry no marks");
});

// ── firstTs + the simplified P/R/F status (sidebar elapsed times + badges) ────

test("batch.firstTs is the EARLIEST member firstTs (batch start); no member firstTs → null", () => {
  const out = groupSessionsIntoBatches([
    { ...s("a1", "B1", "2026-06-20T10:05:00.000Z"), firstTs: "2026-06-20T10:01:00.000Z" },
    { ...s("a2", "B1", "2026-06-20T10:09:00.000Z"), firstTs: "2026-06-20T10:00:00.000Z" },
    s("b1", "B2", "2026-06-20T11:00:00.000Z"), // helper default: firstTs null
  ]);
  assert.equal(out.find((b) => b.id === "B1")!.firstTs, "2026-06-20T10:00:00.000Z");
  assert.equal(out.find((b) => b.id === "B2")!.firstTs, null);
});

test("status: the effective verdict (testResult ?? checksVerdict) maps to pass/fail/skip", () => {
  const out = buildSidebarSections(
    [
      { ...s("claude-e2e-a-1750000002001", "R1", "2026-07-06T08:01:00.000Z"), checksVerdict: "pass" },
      { ...s("claude-e2e-b-1750000002002", "R1", "2026-07-06T08:02:00.000Z"), checksVerdict: "fail" },
    ],
    [run("R1", "failed", [
      { name: "claude-e2e[c]: live", cls: "claude-e2e", scenario: "c", status: "skip" },
    ])],
  );
  const byId = Object.fromEntries(out.testing[0]!.sessions.map((x) => [x.id, x.status]));
  assert.equal(byId["claude-e2e-a-1750000002001"], "pass");
  assert.equal(byId["claude-e2e-b-1750000002002"], "fail");
});

test("status: a member of a RUNNING run with no result yet is running; batch status follows the run state", () => {
  const nowMs = Date.parse("2026-07-06T09:00:00.000Z");
  const out = buildSidebarSections(
    [
      { ...s("claude-e2e-done-1750000002001", "R1", "2026-07-06T08:01:00.000Z"), checksVerdict: "pass" },
      s("claude-e2e-going-1750000002002", "R1", "2026-07-06T08:02:00.000Z"), // no verdict, run still running
    ],
    [run("R1", "running")],
    nowMs,
  );
  const batch = out.testing[0]!;
  assert.equal(batch.status, "running", "running run → running batch");
  const byId = Object.fromEntries(batch.sessions.map((x) => [x.id, x.status]));
  assert.equal(byId["claude-e2e-done-1750000002001"], "pass", "a finished scenario keeps its verdict mid-run");
  assert.equal(byId["claude-e2e-going-1750000002002"], "running");
});

test("status: run states map onto the batch badge (passed/failed/error/canceled)", () => {
  const mk = (state: string) =>
    buildSidebarSections(
      [s("claude-e2e-x-1750000002001", "R1", "2026-07-06T08:01:00.000Z")],
      [run("R1", state)],
    ).testing[0]!.status;
  assert.equal(mk("passed"), "pass");
  assert.equal(mk("failed"), "fail");
  assert.equal(mk("error"), "fail");
  assert.equal(mk("canceled"), undefined, "canceled → no badge (the run badge spells it out)");
});

test("status: a verdict-less session is RUNNING while its last event is inside the activity window, else unbadged", () => {
  const nowMs = Date.parse("2026-07-06T10:10:00.000Z");
  const recent = new Date(nowMs - (RUNNING_WINDOW_MS - 60_000)).toISOString();
  const stale = new Date(nowMs - (RUNNING_WINDOW_MS + 60_000)).toISOString();
  const out = buildSidebarSections(
    [
      { ...s("1750000000-42", "L1", recent), firstTs: recent },
      { ...s("1750000001-43", "L2", stale), firstTs: stale },
    ],
    [],
    nowMs,
  );
  const active = out.live.find((b) => b.id === "L1")!;
  const ended = out.live.find((b) => b.id === "L2")!;
  assert.equal(active.sessions[0]!.status, "running", "recent activity → still running");
  assert.equal(active.status, "running", "a running member rolls up to the batch");
  assert.equal(ended.sessions[0]!.status, undefined, "quiet live session → no status (no pass/fail concept)");
  assert.equal(ended.status, undefined);
});

test("status: a session whose agent exited (`exited`) is never RUNNING by recency; a verdict or a running run still decides (§4.10.4)", () => {
  const nowMs = Date.parse("2026-07-06T10:10:00.000Z");
  const recent = new Date(nowMs - 60_000).toISOString();
  const out = buildSidebarSections(
    [
      { ...s("1750000000-42", "L1", recent), firstTs: recent, exited: true },
      { ...s("1750000001-43", "L2", recent), firstTs: recent },
    ],
    [],
    nowMs,
  );
  const ended = out.live.find((b) => b.id === "L1")!;
  const going = out.live.find((b) => b.id === "L2")!;
  assert.equal(ended.sessions[0]!.status, undefined, "exited a minute ago → not running, though its last event is recent");
  assert.equal(ended.status, undefined, "nor is its batch");
  assert.equal(going.sessions[0]!.status, "running", "no recorded exit → recent activity is still running");

  // An exited session that ran with no verdict in a day group of its own.
  const day = buildSidebarSections([{ ...s("1750000002-44", undefined, recent), exited: true }], [], nowMs);
  assert.equal(day.live[0]!.status, undefined, "a day group of exited sessions is not running");
  assert.equal(day.live[0]!.sessions[0]!.status, undefined);

  // A verdict still decides, and so does a joined run still executing.
  const graded = buildSidebarSections([{ ...s("1750000003-45", "L3", recent), exited: true, checksVerdict: "fail" }], [], nowMs);
  assert.equal(graded.live[0]!.sessions[0]!.status, "fail");
  const inRun = buildSidebarSections(
    [{ ...s("claude-e2e-going-1750000002002", "R1", recent), exited: true }],
    [run("R1", "running")],
    nowMs,
  );
  assert.equal(inRun.testing[0]!.sessions[0]!.status, "running", "a member of a running test run with no result yet stays running");
});

test("status: nowMs omitted disables the recency rule (deterministic legacy callers)", () => {
  const out = buildSidebarSections([s("1750000000-42", "L1", "2026-07-06T10:00:00.000Z")]);
  assert.equal(out.live[0]!.sessions[0]!.status, undefined);
});

test("status: a run-less testing batch rolls up member verdicts (fail beats pass)", () => {
  const out = buildSidebarSections([
    { ...s("claude-e2e-a-1750000002001", "R9", "2026-07-06T08:01:00.000Z"), checksVerdict: "pass" },
    { ...s("claude-e2e-b-1750000002002", "R9", "2026-07-06T08:02:00.000Z"), checksVerdict: "fail" },
  ]);
  assert.equal(out.testing[0]!.status, "fail");
});

test("a testing batch with no matching run (standalone npm test) stays run-less; live batches never join", () => {
  const out = buildSidebarSections(
    [
      s("replay-e2e-ipi-text-1750000002000", "replay-1750000002000", "2026-07-06T08:00:00.000Z"),
      s("1750000000-42", "L1", "2026-07-06T10:00:00.000Z"),
    ],
    [run("L1", "passed")], // pathological: a run id colliding with a LIVE batch id
  );
  assert.equal(out.testing[0]!.run, undefined, "no run record → batch still renders, without run info");
  assert.equal(out.testing[0]!.title, "replay e2e run", "run-less test batch titled by its suite");
  assert.equal(out.live[0]!.run, undefined, "live batches never carry a run");
});

test("runtime: the joined run's runtime wins; else the members' uniform runtime; mixed or absent → omitted", () => {
  const rt = (ref: SessionRef, runtime: "docker" | "host"): SessionRef => ({ ...ref, runtime });
  const out = buildSidebarSections(
    [
      // R1 joins a docker run record — it wins even over a member's 'host' tag
      // (the record is authoritative and known at run start).
      rt(s("claude-e2e-a-1750000001001", "R1", "2026-07-06T08:01:00.000Z"), "host"),
      // R2 has no run record; both members emitted runtime=docker → uniform backfill.
      rt(s("claude-e2e-b-1750000002001", "R2", "2026-07-06T08:02:00.000Z"), "docker"),
      rt(s("claude-e2e-c-1750000002002", "R2", "2026-07-06T08:02:30.000Z"), "docker"),
      // R3 mixes docker and host members → badging either would lie; omitted.
      rt(s("claude-e2e-d-1750000003001", "R3", "2026-07-06T08:03:00.000Z"), "docker"),
      rt(s("claude-e2e-e-1750000003002", "R3", "2026-07-06T08:03:30.000Z"), "host"),
      // R4 carries no runtime anywhere → omitted.
      s("claude-e2e-f-1750000004001", "R4", "2026-07-06T08:04:00.000Z"),
    ],
    [{ ...run("R1", "passed"), runtime: "docker" }],
  );
  const byId = new Map(out.testing.map((b) => [b.id, b]));
  assert.equal(byId.get("R1")!.runtime, "docker", "the run record's runtime wins");
  assert.equal(byId.get("R2")!.runtime, "docker", "uniform member runtime backfills a run-less batch");
  assert.equal(byId.get("R3")!.runtime, undefined, "mixed member runtimes → no batch runtime");
  assert.equal(byId.get("R4")!.runtime, undefined, "no runtime anywhere → omitted");
});

test("origin: uniform member origin badges the batch CI; mixed or absent → omitted", () => {
  const og = (ref: SessionRef, origin: "ci" | "local"): SessionRef => ({ ...ref, origin });
  const out = buildSidebarSections(
    [
      // R1: a GitLab pipeline's batch. There is NO run record for a CI batch — the
      // pipeline never goes through the dashboard's TestRunner — so the members'
      // stamped events are the only source. This is the case the badge exists for.
      og(s("claude-e2e-a-1750000001001", "R1", "2026-07-06T08:01:00.000Z"), "ci"),
      og(s("claude-e2e-b-1750000001002", "R1", "2026-07-06T08:01:30.000Z"), "ci"),
      // R2: a human's local run → "local" is the implicit default, so nothing renders,
      // but the batch still carries it (the frontend's originBadge drops it).
      og(s("claude-e2e-c-1750000002001", "R2", "2026-07-06T08:02:00.000Z"), "local"),
      // R3 mixes CI and local members → badging either way would lie about half the
      // rows, exactly as with a mixed-runtime day group.
      og(s("claude-e2e-d-1750000003001", "R3", "2026-07-06T08:03:00.000Z"), "ci"),
      og(s("claude-e2e-e-1750000003002", "R3", "2026-07-06T08:03:30.000Z"), "local"),
      // R4: sessions recorded before the field existed → omitted, not guessed.
      s("claude-e2e-f-1750000004001", "R4", "2026-07-06T08:04:00.000Z"),
    ],
    [],
  );
  const byId = new Map(out.testing.map((b) => [b.id, b]));
  assert.equal(byId.get("R1")!.origin, "ci", "uniform ci members → CI batch (no run record needed)");
  assert.equal(byId.get("R2")!.origin, "local", "uniform local members → local batch");
  assert.equal(byId.get("R3")!.origin, undefined, "mixed origins → no batch origin");
  assert.equal(byId.get("R4")!.origin, undefined, "no origin anywhere → omitted (pre-field sessions)");

  // origin is ORTHOGONAL to runtime, not a third value of it: a CI batch is ALSO a
  // docker batch, and folding them into one enum would destroy the distinction.
  const both = buildSidebarSections(
    [{ ...og(s("claude-e2e-g-1750000005001", "R5", "2026-07-06T08:05:00.000Z"), "ci"), runtime: "docker" }],
    [],
  );
  assert.equal(both.testing[0]!.origin, "ci", "a CI batch reports its origin…");
  assert.equal(both.testing[0]!.runtime, "docker", "…AND its runtime — both badges show");
});

test("a DRILLS batch whose id is a watch run's runId gains the run's label + verdict tally (dashboard.md §4.22)", () => {
  const ref = (id: string, batchId: string): SessionRef => ({ id, batchId, lastTs: "2026-09-18T08:00:00.000Z", tags: sessionTags(id) } as SessionRef);
  const sessions = [ref("watch-1-p1", "watch-1"), ref("other-session", "other-batch")];
  const watchRuns = [{ runId: "watch-1", label: "🎬 watch · U1 I1", state: "failed", since: 1, finishedAt: 2, counts: { pass: 1, fail: 1, skip: 0 }, sessions: ["watch-1-p1", "old-watch-session"], recorded: true }];
  const sections = buildSidebarSections([...sessions, ref("old-watch-session", "")], [], undefined, undefined, watchRuns);
  const watched = sections.drills.find((b) => b.id === "watch-1")!;
  assert.ok(watched, "the watch session groups as a batch of the DRILLS section");
  assert.equal(watched.title, "🎬 watch · U1 I1");
  assert.equal(watched.run?.suite, "watch");
  assert.equal(watched.run?.state, "failed");
  assert.deepEqual(watched.run?.counts, { pass: 1, fail: 1, skip: 0 });
  // every session the run drove carries the per-row 🎬 annotation — including one
  // with no batch stamp, which joins the run that names it (2026-09-25; it used
  // to fall into a day group)
  assert.deepEqual(watched.sessions[0]!.watch, { runId: "watch-1", recorded: true, verdict: "FAIL" });
  const oldBatch = sections.drills.find((b) => b.sessions.some((s) => s.id === "old-watch-session"))!;
  assert.equal(oldBatch.id, "watch-1", "an unstamped session the run names joins the run's batch");
  assert.deepEqual(oldBatch.sessions.find((s) => s.id === "old-watch-session")!.watch, { runId: "watch-1", recorded: true, verdict: "FAIL" });
  assert.equal(sections.drills.length, 1, "no stray day group");
  const plain = sections.live.find((b) => b.id === "other-batch")!;
  assert.equal(plain.run, undefined, "a live batch that is not a watch run carries no run");
  assert.equal(plain.sessions[0]!.watch, undefined, "a session no watch run drove carries no annotation");
  assert.deepEqual(sections.live.map((b) => b.id), ["other-batch"], "Live holds only what no watch run drove");
  assert.equal(sections.testing.length, 0);
  // a run that died before recording its sessions: its scope-id prefix still places the row
  const orphan = buildSidebarSections([ref("watch-1-boot", "")], [], undefined, undefined, [{ ...watchRuns[0]!, sessions: [] }]);
  assert.equal(orphan.drills.flatMap((b) => b.sessions).length, 1);
  assert.equal(orphan.drills[0]!.id, "watch-1", "…and joins that run's batch");
  assert.equal(orphan.live.length, 0);
  // a drill driven under the test tenant (the private-arbiter recipe) is still a drill
  const tenanted = buildSidebarSections([{ ...ref("watch-1-p1", "watch-1"), tenant: "test" } as SessionRef], [], undefined, undefined, watchRuns);
  assert.equal(tenanted.drills.length, 1);
  assert.equal(tenanted.testing.length, 0);
  // an unrecorded run annotates recorded:false
  const bare = buildSidebarSections(sessions, [], undefined, undefined, [{ ...watchRuns[0]!, recorded: false, counts: { pass: 2, fail: 0, skip: 1 } }]);
  assert.deepEqual(bare.drills.find((b) => b.id === "watch-1")!.sessions[0]!.watch, { runId: "watch-1", recorded: false, verdict: "WARN" });
});


test("a watch run with one session per scenario: rows are named by their scenario, ordered as the run ran them, and marked by their OWN verdict (dashboard.md §4.22)", () => {
  const ref = (id: string, lastTs: string): SessionRef => ({ id, batchId: "watch-3", lastTs, tags: sessionTags(id) } as SessionRef);
  // newest-first input, as the server sorts; the run ran U1 → I1 → I4
  const sessions = [ref("watch-3-i4", "2026-09-19T08:03:00.000Z"), ref("watch-3-i1", "2026-09-19T08:02:00.000Z"), ref("watch-3-u1", "2026-09-19T08:01:00.000Z"), ref("watch-3-boot", "2026-09-19T08:00:00.000Z")];
  const run = {
    runId: "watch-3", label: "🎬 watch · U1 I1 I4", state: "running", since: 1, finishedAt: null, counts: { pass: 1, fail: 0, skip: 1 },
    sessions: ["watch-3-u1", "watch-3-i1", "watch-3-i4", "watch-3-boot"], recorded: true,
    scenarios: [
      { sessionId: "watch-3-u1", id: "U1", title: "reasoning", setting: "P1", verdict: "PASS" as const },
      { sessionId: "watch-3-i1", id: "I1", title: "stored injection", setting: "P1", verdict: "WARN" as const },
      { sessionId: "watch-3-i4", id: "I4", title: "web", setting: "P2", recorded: false },
    ],
  };
  const batch = buildSidebarSections(sessions, [], Date.parse("2026-09-19T08:03:30.000Z"), undefined, [run]).drills.find((b) => b.id === "watch-3")!;
  assert.deepEqual(batch.sessions.map((s) => s.id), ["watch-3-u1", "watch-3-i1", "watch-3-i4", "watch-3-boot"], "run order, then the non-scenario session");
  const [u1, i1, i4, boot] = batch.sessions;
  assert.deepEqual(u1!.watch, { runId: "watch-3", recorded: true, verdict: "PASS", scenario: { id: "U1", title: "reasoning", setting: "P1" } });
  assert.equal(u1!.status, "pass", "its own verdict marks the row P");
  assert.equal(i1!.status, "skip", "WARN is the third bucket, like a skipped test");
  assert.equal(i1!.watch?.verdict, "WARN");
  assert.equal(i4!.status, "running", "ungraded while the run is running");
  assert.equal(i4!.watch?.verdict, "running");
  assert.equal(i4!.watch?.recorded, false, "its OWN cast is missing → struck chip, whatever the run has");
  assert.equal(u1!.watch?.recorded, true, "no per-scenario flag → the run's");
  assert.equal(boot!.watch?.scenario, undefined, "a session that is no scenario keeps the run-level annotation");
  assert.equal(boot!.watch?.verdict, "running");
  assert.equal(batch.status, "running");
  // the run ended: the ungraded scenario has no verdict and no status; the batch rolls up from the run
  const done = buildSidebarSections(sessions, [], Date.parse("2026-09-19T09:00:00.000Z"), undefined, [{ ...run, state: "failed", counts: { pass: 1, fail: 1, skip: 1 }, scenarios: [run.scenarios[0]!, run.scenarios[1]!, { ...run.scenarios[2]!, verdict: "TIMEOUT" as const }] }]).drills.find((b) => b.id === "watch-3")!;
  assert.equal(done.sessions[2]!.status, "fail", "TIMEOUT marks F");
  assert.equal(done.sessions[3]!.status, undefined, "the run's rollup is not a per-row verdict on a non-scenario session");
  assert.equal(done.status, "fail");
  // PAUSED (the model's safeguards stopped the drill, 2026-10-02) is never a pass: F, like TIMEOUT
  const paused = buildSidebarSections(sessions, [], Date.parse("2026-09-19T09:00:00.000Z"), undefined, [{ ...run, state: "failed", counts: { pass: 1, fail: 1, skip: 1 }, scenarios: [run.scenarios[0]!, run.scenarios[1]!, { ...run.scenarios[2]!, verdict: "PAUSED" as const }] }]).drills.find((b) => b.id === "watch-3")!;
  assert.equal(paused.sessions[2]!.status, "fail", "PAUSED marks F");
  assert.equal(paused.sessions[2]!.watch?.verdict, "PAUSED");
});

test("a drill scenario that ended before its first model call (no batch stamp) groups with its run, and a longer run id wins the prefix (2026-09-25)", () => {
  // watch-20260924-p10-drills-all2-s4-haiku timed out at launch: only launcher /
  // net events, none from the model proxy, so no `batchId` — it sat in a day
  // group among an unrelated run's rows.
  const at = "2026-09-24T11:28:00.000Z";
  const stamped: SessionRef = { id: "watch-9-drills-all2-s3-haiku", batchId: "watch-9-drills-all2", lastTs: at, tags: ["test"], tenant: "test" } as SessionRef;
  const timedOut: SessionRef = { id: "watch-9-drills-all2-s4-haiku", lastTs: at, tags: ["test"], tenant: "test" } as SessionRef;
  const run = (runId: string, sessions: string[]) => ({ runId, label: `🎬 ${runId}`, state: "failed", since: 1, finishedAt: 2, counts: { pass: 1, fail: 1, skip: 0 }, sessions, recorded: true });
  const named = buildSidebarSections([stamped, timedOut], [], undefined, undefined, [run("watch-9-drills-all2", [stamped.id, timedOut.id])]);
  assert.deepEqual(named.drills.map((b) => [b.id, b.sessions.map((s) => s.id)]), [["watch-9-drills-all2", [stamped.id, timedOut.id]]]);
  assert.equal(named.testing.length, 0, "test tenant, still a drill");
  // the run never recorded its sessions: the id prefix places it, and the LONGEST
  // matching run id wins (`watch-9-drills` is a prefix of `watch-9-drills-all2`)
  const prefixed = buildSidebarSections([timedOut], [], undefined, undefined, [run("watch-9-drills", []), run("watch-9-drills-all2", [])]);
  assert.deepEqual(prefixed.drills.map((b) => b.id), ["watch-9-drills-all2"]);
  // the input ref is copied, never mutated
  assert.equal(timedOut.batchId, undefined);
});

test("RECORD LOST (2026-10-02, dashboard.md §4.22): with the store read, a drill session whose run is not in it is annotated record lost (run named, nothing else joined), and its batch too; without a store read, nothing", () => {
  const at = "2026-09-29T23:38:13.588Z";
  const ref = (id: string, batchId?: string): SessionRef => ({ id, ...(batchId ? { batchId } : {}), lastTs: at, tags: sessionTags(id) } as SessionRef);
  // the 2026-09-29 drill-tier runs: events, no record anywhere
  const lost = [ref("watch-20260929T232943-s6", "watch-20260929T232943"), ref("watch-20260929T232943-u7", "watch-20260929T232943"), ref("watch-20260929T231422-u23")];
  // a stored run, and an ordinary session
  const stored = ref("watch-3-u1", "watch-3");
  const plain = ref("1790000000-1", "L1");
  const run = { runId: "watch-3", label: "🎬 watch · U1", state: "passed", since: 1, finishedAt: 2, counts: { pass: 1, fail: 0, skip: 0 }, sessions: ["watch-3-u1"], recorded: true };
  const sec = buildSidebarSections([...lost, stored, plain], [], undefined, undefined, [run], { watchStoreRead: true });
  const byId = new Map(sec.drills.flatMap((b) => b.sessions).map((x) => [x.id, x]));
  assert.deepEqual(byId.get("watch-20260929T232943-s6")!.watch, { runId: "watch-20260929T232943", recorded: false, recordLost: true, runMissing: true });
  assert.deepEqual(byId.get("watch-20260929T231422-u23")!.watch, { runId: "watch-20260929T231422", recorded: false, recordLost: true, runMissing: true }, "no batch stamp: the run is read off the id");
  assert.equal(byId.get("watch-20260929T232943-s6")!.status, undefined, "no verdict is invented");
  const lostBatch = sec.drills.find((b) => b.id === "watch-20260929T232943")!;
  assert.equal(lostBatch.recordLost, true, "every member lost: the batch header says so");
  assert.deepEqual(byId.get("watch-3-u1")!.watch, { runId: "watch-3", recorded: true, verdict: "PASS" }, "a stored run's session is untouched");
  assert.equal(sec.drills.find((b) => b.id === "watch-3")!.recordLost, undefined);
  assert.equal(sec.live.flatMap((b) => b.sessions)[0]!.watch, undefined, "an ordinary session is never record lost");
  // a session of a stored run that its meta does not list (a boot failure) is the run's, not lost
  const boot = buildSidebarSections([ref("watch-3-c9", "watch-3")], [], undefined, undefined, [run], { watchStoreRead: true });
  assert.equal(boot.drills[0]!.sessions[0]!.watch, undefined);
  assert.equal(boot.drills[0]!.recordLost, undefined);
  // no store read (a caller with no watch dir): absence proves nothing
  const unread = buildSidebarSections(lost, [], undefined, undefined, []);
  for (const x of unread.drills.flatMap((b) => b.sessions)) assert.equal(x.watch, undefined);
  assert.equal(unread.drills.some((b) => b.recordLost), false);
});

test("RECORD LOST from a stored run: the run's flag marks its batch and a shared row; a scenario's own flag marks only its row", () => {
  const ref = (id: string): SessionRef => ({ id, batchId: "watch-7", lastTs: "2026-10-01T08:00:00.000Z", tags: sessionTags(id) } as SessionRef);
  const base = { runId: "watch-7", label: "🎬 watch · U1 I1", state: "failed", since: 1, finishedAt: 2, counts: { pass: 1, fail: 1, skip: 0 }, recorded: false };
  const whole = buildSidebarSections([ref("watch-7-p1")], [], undefined, undefined, [{ ...base, sessions: ["watch-7-p1"], recordLost: true as const }], { watchStoreRead: true });
  assert.equal(whole.drills[0]!.recordLost, true);
  assert.deepEqual(whole.drills[0]!.sessions[0]!.watch, { runId: "watch-7", recorded: false, recordLost: true, verdict: "FAIL" }, "a shared row takes the run's flag; runMissing absent: the run is stored");
  const part = buildSidebarSections([ref("watch-7-u1"), ref("watch-7-i1")], [], undefined, undefined, [{
    ...base, recorded: true, sessions: ["watch-7-u1", "watch-7-i1"],
    scenarios: [
      { sessionId: "watch-7-u1", id: "U1", title: "a", setting: "secrets", verdict: "PASS" as const, recorded: true },
      { sessionId: "watch-7-i1", id: "I1", title: "b", setting: "secrets", verdict: "FAIL" as const, recorded: false, recordLost: true as const },
    ],
  }], { watchStoreRead: true });
  const rows = new Map(part.drills[0]!.sessions.map((x) => [x.id, x]));
  assert.equal(rows.get("watch-7-i1")!.watch?.recordLost, true);
  assert.equal(rows.get("watch-7-u1")!.watch?.recordLost, undefined);
  assert.equal(part.drills[0]!.recordLost, undefined, "one row's cast gone is not the whole run's");
});

// ── Replay drills (dashboard.md §4.28, test-reorganization.md §7.1) ──────────

function replayRef(runId: string, key: string, verdict: "PASS" | "WARN" | "FAIL" | "TIMEOUT", extra: Partial<NonNullable<SessionRef["replay"]>> = {}): SessionRef {
  return {
    id: `${runId}/${key}`, label: `drill ${key}`, eventCount: 2, firstTs: "2026-10-01T09:00:06.000Z", lastTs: "2026-10-01T09:00:40.000Z",
    violated: false, batchId: runId, agent: "claude",
    replay: {
      runId, key, drill: key.split("-")[0]!, title: `drill ${key}`, agent: "claude", size: "120x40", mode: "interactive", verdict,
      tally: { security: { pass: 2, total: 2 }, utility: { pass: 1, total: 1 }, fidelity: { pass: 0, total: 0 } },
      script: { version: "a1b2c3", origin: "hand" }, engine: 1, recorded: true, plainRecorded: true,
      run: { commit: "4f1c2e9a0b1c2d3e4f5a", ref: "master", source: "ci", startedAt: "2026-10-01T09:00:00Z" },
      ...extra,
    },
  };
}

test("buildSidebarSections: recorded replay sessions form the Replay drills section, one batch per run, decided before everything else", () => {
  const sessions = [
    s("live-1", undefined, "2026-10-01T09:00:00.000Z"),
    replayRef("gl-501-7", "zeta-claude-120x40", "PASS"),
    replayRef("gl-501-7", "alpha-codex-80x24", "FAIL", { agent: "codex", size: "80x24" }),
    replayRef("gl-501-7", "mid-claude-120x40", "WARN"),
    replayRef("gl-500-1", "alpha-claude-120x40", "TIMEOUT", { run: { commit: "0123456789abcdef", source: "local", startedAt: "2026-09-30T09:00:00Z" } }),
    // even a watch- or test-shaped id stays a replay drill: `replay` decides first
    replayRef("watch-20260101T000000", "claude-e2e-x-claude-1x1", "PASS"),
  ];
  const sec = buildSidebarSections(sessions, [], Date.parse("2026-10-01T09:01:00.000Z"));
  assert.deepEqual(Object.keys(sec).sort(), ["drills", "live", "replay", "testing"]);
  assert.deepEqual(sec.live.flatMap((b) => b.sessions).map((x) => x.id), ["live-1"]);
  assert.equal(sec.drills.length, 0);
  assert.equal(sec.testing.length, 0);
  const run = sec.replay.find((b) => b.id === "gl-501-7")!;
  assert.equal(run.title, "replay · master · 4f1c2e9a");
  assert.deepEqual(run.sessions.map((x) => x.id), ["gl-501-7/alpha-codex-80x24", "gl-501-7/mid-claude-120x40", "gl-501-7/zeta-claude-120x40"], "rows by drill, agent, size");
  assert.deepEqual(run.sessions.map((x) => x.status), ["fail", "skip", "pass"], "FAIL → fail, WARN → the third bucket, PASS → pass");
  assert.equal(run.status, "fail");
  assert.deepEqual(run.run && { suite: run.run.suite, state: run.run.state, counts: run.run.counts, since: run.run.since }, {
    suite: "replay", state: "failed", counts: { pass: 1, fail: 1, skip: 1 }, since: Date.parse("2026-10-01T09:00:00Z"),
  });
  assert.deepEqual(run.replayRun, { commit: "4f1c2e9a0b1c2d3e4f5a", ref: "master", source: "ci", startedAt: "2026-10-01T09:00:00Z" });
  const local = sec.replay.find((b) => b.id === "gl-500-1")!;
  assert.equal(local.title, "replay · local · 01234567", "no ref: the source names it");
  assert.equal(local.sessions[0]!.status, "fail", "TIMEOUT is a fail");
  assert.equal(sec.replay.find((b) => b.id === "watch-20260101T000000")!.sessions.length, 1);
});

test("buildSidebarSections: an arbiter session with a `/` in its id but no replay annotation is NOT a replay drill", () => {
  const sec = buildSidebarSections([s("gl-1/forged-claude-1x1", undefined, "2026-10-01T09:00:00.000Z")], []);
  assert.equal(sec.replay.length, 0);
  assert.equal(sec.live.flatMap((b) => b.sessions).length, 1);
});
