/**
 * proc-tree.test — the darwin agent-tree teardown's planning, on injected `ps`
 * tables (portable-wrapper-cross-platform.md §3.5). No host process is read
 * or signalled; the live proof is test/component/darwin-teardown.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AGE_SLACK_MS, PS_ARGV, PS_ENV, ProcTreeTracker, descendantPids, endTree, inertTree, newTreeRecord, observe,
  parseEtime, parsePsTable, readPsTable, type ProcRow, type PsRunner, type TreeDeps,
} from "../../src/platform/proc-tree.js";
import { LINUX_TREE_SKIP, linuxPlatform } from "../../src/platform/linux.js";
import { DARWIN_TREE_SAMPLE_MS, darwinPlatform } from "../../src/platform/darwin.js";

const T0 = 1_800_000_000_000; // the launch (Date.now() when tracking began)
const SELF = 500; // the launcher

/** A row; `age` in seconds (etime), start token derived from pid unless given. */
function row(pid: number, ppid: number, pgid: number, age: number, extra: Partial<ProcRow> = {}): ProcRow {
  return { pid, ppid, pgid, stat: "S", ageSec: age, start: `start-of-${pid}`, ...extra };
}

/** The host around every table: launchd, the user's shell, the launcher. */
const HOST: ProcRow[] = [
  row(1, 0, 1, 90_000),
  row(400, 1, 400, 9_000), // the user's terminal shell
  row(500, 400, 500, 30), // the launcher (the user's shell's job)
  row(600, 1, 600, 20_000), // an unrelated long-lived process of this user
];

const pids = (rows: ProcRow[]) => rows.map((r) => r.pid).sort((a, b) => a - b);

test("parseEtime reads [[dd-]hh:]mm:ss; anything else is NaN", () => {
  assert.equal(parseEtime("00:07"), 7);
  assert.equal(parseEtime("12:34"), 754);
  assert.equal(parseEtime("01:00:01"), 3601);
  assert.equal(parseEtime("2-03:04:05"), 2 * 86400 + 3 * 3600 + 4 * 60 + 5);
  assert.ok(Number.isNaN(parseEtime("abc")));
  assert.ok(Number.isNaN(parseEtime("")));
});

test("parsePsTable reads `ps -x -o pid=,ppid=,pgid=,stat=,etime=,lstart=` (C locale), collapsing the lstart spacing", () => {
  assert.deepEqual(PS_ARGV, ["-x", "-o", "pid=,ppid=,pgid=,stat=,etime=,lstart="]);
  const text = [
    "70657     1 70645 S        00:03 Tue Sep 29 11:55:32 2026",
    "  301   300   300 Ss    1-02:03:04 Wed Sep  2 09:05:01 2026",
    "  302   301   300 Z+       00:00 Wed Sep  2 09:05:01 2026",
    "garbage line",
    "  303   301   300 S     not-an-etime Wed Sep  2 09:05:01 2026",
    "",
  ].join("\n");
  assert.deepEqual(parsePsTable(text), [
    { pid: 70657, ppid: 1, pgid: 70645, stat: "S", ageSec: 3, start: "Tue Sep 29 11:55:32 2026" },
    { pid: 301, ppid: 300, pgid: 300, stat: "Ss", ageSec: 93784, start: "Wed Sep 2 09:05:01 2026" },
    { pid: 302, ppid: 301, pgid: 300, stat: "Z+", ageSec: 0, start: "Wed Sep 2 09:05:01 2026" },
  ]);
});

test("descendantPids walks ppid links from a root (the root excluded)", () => {
  const rows = [...HOST, row(700, 500, 700, 1), row(701, 700, 700, 1), row(702, 701, 702, 1), row(703, 1, 703, 1)];
  assert.deepEqual(descendantPids(rows, 700).sort(), [701, 702]);
  assert.deepEqual(descendantPids(rows, 9999), []);
});

test("sampling records the root, its descendants and their process groups; nothing of the host", () => {
  const rec = newTreeRecord(700, T0);
  // chain root 700 (setsid by the launcher), its child 701 in the same group,
  // and 702 that moved to a session of its own (BSD script's child, a detached Bash command).
  const rows = [...HOST, row(700, 500, 700, 0), row(701, 700, 700, 0), row(702, 701, 702, 0)];
  const seen = observe(rec, rows, { selfPid: SELF, nowMs: T0 + 100 });
  assert.deepEqual(pids(seen), [700, 701, 702]);
  assert.deepEqual([...rec.members.keys()].sort(), [700, 701, 702]);
  assert.deepEqual([...rec.groups].sort(), [700, 702]);
});

test("after the chain exits: a reparented background job is found by its recorded group, and a child forked after the last sample too", () => {
  const rec = newTreeRecord(700, T0);
  observe(rec, [...HOST, row(700, 500, 700, 0), row(701, 700, 700, 0)], { selfPid: SELF, nowMs: T0 + 100 });
  // 700 exited; 701 (`sleep &`) now belongs to launchd; 705 was forked by 701's
  // sibling after the last sample and orphaned too: never seen, but in group 700.
  const later = [...HOST, row(701, 1, 700, 5), row(705, 1, 700, 1)];
  assert.deepEqual(pids(observe(rec, later, { selfPid: SELF, nowMs: T0 + 5000 })), [701, 705]);
});

test("a member in a group of its own is still found by identity once reparented, with its new children", () => {
  const rec = newTreeRecord(700, T0);
  observe(rec, [...HOST, row(700, 500, 700, 0), row(710, 700, 710, 0)], { selfPid: SELF, nowMs: T0 + 100 });
  // 710 setsid'd, 700 exited; 710 then forked 711 into yet another session.
  const later = [...HOST, row(710, 1, 710, 4), row(711, 710, 711, 1)];
  assert.deepEqual(pids(observe(rec, later, { selfPid: SELF, nowMs: T0 + 4000 })), [710, 711]);
});

test("a recycled pid (same number, different start time) outside the recorded groups is not the member", () => {
  const rec = newTreeRecord(700, T0);
  observe(rec, [...HOST, row(700, 500, 700, 0), row(710, 700, 710, 0)], { selfPid: SELF, nowMs: T0 + 100 });
  const later = [...HOST, row(710, 1, 999, 1, { start: "a different process" })];
  assert.deepEqual(observe(rec, later, { selfPid: SELF, nowMs: T0 + 5000 }), []);
});

test("never a target: the launcher, its ancestors, its process group, launchd, zombies, or anything older than the launch", () => {
  const rec = newTreeRecord(700, T0);
  observe(rec, [...HOST, row(700, 500, 700, 0), row(701, 700, 700, 0)], { selfPid: SELF, nowMs: T0 + 100 });
  rec.groups.add(500); rec.groups.add(400); rec.groups.add(1); // even a poisoned record
  const later = [
    ...HOST,
    row(501, 500, 500, 1), // a `ps` the launcher spawned: in the launcher's group
    row(701, 1, 700, 3, { stat: "Z" }), // a zombie member
    row(720, 1, 700, 3_600), // group 700 but older than the launch: not the agent's
  ];
  assert.deepEqual(observe(rec, later, { selfPid: SELF, nowMs: T0 + 3000 }), []);
});

test("the age floor tolerates one-second etime and the spawn racing the tracker (AGE_SLACK_MS)", () => {
  const rec = newTreeRecord(700, T0);
  // The root reports 2 s of age 100 ms after tracking began: within the slack.
  assert.deepEqual(pids(observe(rec, [...HOST, row(700, 500, 700, 2)], { selfPid: SELF, nowMs: T0 + 100 })), [700]);
  const rec2 = newTreeRecord(700, T0);
  const tooOld = Math.ceil((100 + AGE_SLACK_MS) / 1000) + 1;
  assert.deepEqual(observe(rec2, [...HOST, row(700, 500, 700, tooOld)], { selfPid: SELF, nowMs: T0 + 100 }), []);
});

test("a recorded group whose id now names a different process was recycled: its members are left alone", () => {
  const rec = newTreeRecord(700, T0);
  observe(rec, [...HOST, row(700, 500, 700, 0), row(730, 700, 730, 0)], { selfPid: SELF, nowMs: T0 + 100 });
  // 730 (a group leader we recorded) is gone; pid 730 came back as another
  // process leading a new group 730 with a member.
  const later = [...HOST, row(730, 1, 730, 1, { start: "someone else" }), row(731, 730, 730, 1)];
  assert.deepEqual(observe(rec, later, { selfPid: SELF, nowMs: T0 + 5000 }), []);
  // A zombie leader still names the SAME group: its orphaned members are found.
  const rec2 = newTreeRecord(700, T0);
  observe(rec2, [...HOST, row(700, 500, 700, 0), row(730, 700, 730, 0)], { selfPid: SELF, nowMs: T0 + 100 });
  const zombieLeader = [...HOST, row(730, 1, 730, 2, { stat: "Z" }), row(732, 1, 730, 1)];
  assert.deepEqual(pids(observe(rec2, zombieLeader, { selfPid: SELF, nowMs: T0 + 3000 })), [732]);
});

test("a recorded group expires once it empties: an orphan that later reuses its id without a leader is not the agent's", () => {
  // Session A recorded 730 (a Bash tool call's shell, setsid'd: a group of its own).
  const rec = newTreeRecord(700, T0);
  observe(rec, [...HOST, row(700, 500, 700, 0), row(730, 700, 730, 0)], { selfPid: SELF, nowMs: T0 + 1000 });
  assert.ok(rec.groups.has(730));
  // The next sample: 730 exited and nothing is left in its group, so its id is free.
  observe(rec, [...HOST, row(700, 500, 700, 1)], { selfPid: SELF, nowMs: T0 + 2000 });
  assert.ok(!rec.groups.has(730), "an emptied group is dropped");
  // An hour later the pid counter wrapped: another session's shell got pid 730,
  // led a new group 730, left a server in it and exited (leader absent, the
  // server started after A's launch, so it passes the age floor).
  const later = [...HOST, row(7355, 1, 730, 60)];
  assert.deepEqual(observe(rec, later, { selfPid: SELF, nowMs: T0 + 3_600_000 }), [], "no target: that group is not ours");
  assert.ok(!rec.groups.has(730), "and it is not recorded again");
});

test("a group `recycled` flags is dropped at once: its members stay out after the new leader exits too", () => {
  const rec = newTreeRecord(700, T0);
  observe(rec, [...HOST, row(700, 500, 700, 0), row(730, 700, 730, 0)], { selfPid: SELF, nowMs: T0 + 100 });
  // pid 730 came back as another process leading group 730, with a member 731.
  const t1 = [...HOST, row(730, 1, 730, 1, { start: "someone else" }), row(731, 730, 730, 1)];
  assert.deepEqual(observe(rec, t1, { selfPid: SELF, nowMs: T0 + 5000 }), []);
  assert.ok(!rec.groups.has(730));
  // That leader exits: 731 is orphaned in group 730, with no leader to compare.
  const t2 = [...HOST, row(731, 1, 730, 2)];
  assert.deepEqual(observe(rec, t2, { selfPid: SELF, nowMs: T0 + 6000 }), []);
});

test("a group that still holds a process stays recorded across samples, leader gone or not", () => {
  const rec = newTreeRecord(700, T0);
  observe(rec, [...HOST, row(700, 500, 700, 0), row(701, 700, 700, 0)], { selfPid: SELF, nowMs: T0 + 100 });
  for (let t = 1; t <= 5; t++) observe(rec, [...HOST, row(701, 1, 700, t)], { selfPid: SELF, nowMs: T0 + t * 1000 });
  assert.ok(rec.groups.has(700));
  // 701 forked 706 after the last sample and exited: 706 is found by the group.
  assert.deepEqual(pids(observe(rec, [...HOST, row(706, 1, 700, 1)], { selfPid: SELF, nowMs: T0 + 6000 })), [706]);
});

test("readPsTable runs /bin/ps with PS_ARGV in the C locale and UTC (TZ pinned: a zone change cannot rewrite lstart)", async () => {
  assert.deepEqual(PS_ENV, { LC_ALL: "C", TZ: "UTC0", PATH: "/usr/bin:/bin" });
  const calls: Array<{ file: string; args: readonly string[]; env: Record<string, string> }> = [];
  const run: PsRunner = (file, args, opts, done) => {
    calls.push({ file, args, env: opts.env });
    done(null, "  701     1   700 S        00:03 Tue Sep 29 04:17:03 2026\n");
  };
  assert.deepEqual(await readPsTable(run), [{ pid: 701, ppid: 1, pgid: 700, stat: "S", ageSec: 3, start: "Tue Sep 29 04:17:03 2026" }]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.file, "/bin/ps");
  assert.deepEqual(calls[0]!.args, PS_ARGV);
  assert.deepEqual(calls[0]!.env, { LC_ALL: "C", TZ: "UTC0", PATH: "/usr/bin:/bin" }, "only these: no inherited TZ or locale");
  const failing: PsRunner = (_f, _a, _o, done) => done(new Error("ps: timed out"), "");
  assert.equal(await readPsTable(failing), null, "an unreadable table is null (then nothing is signalled)");
});

test("the documented residual: a new session whose parent exited between two samples is never seen", () => {
  const rec = newTreeRecord(700, T0);
  observe(rec, [...HOST, row(700, 500, 700, 0)], { selfPid: SELF, nowMs: T0 + 100 });
  // 740 (a detached Bash command) forked 741 and exited before the next sample.
  const later = [...HOST, row(700, 500, 700, 2), row(741, 1, 740, 1)];
  assert.deepEqual(pids(observe(rec, later, { selfPid: SELF, nowMs: T0 + 2000 })), [700]);
});

/** A fake host for endTree: a mutable table; kill() applies the signal. */
function fakeHost(rows: ProcRow[], opts: { ignoreTerm?: number[]; onTerm?: (pid: number, h: FakeHost) => void } = {}) {
  const h: FakeHost = {
    rows: [...rows], signals: [] as Array<[number, NodeJS.Signals]>, clock: T0 + 10_000, tableFails: false,
    deps: undefined as unknown as TreeDeps,
  };
  h.deps = {
    table: async () => (h.tableFails ? null : h.rows.map((r) => ({ ...r }))),
    kill: (pid, sig) => {
      h.signals.push([pid, sig]);
      if (!h.rows.some((r) => r.pid === pid)) throw Object.assign(new Error("ESRCH"), { code: "ESRCH" });
      if (sig === "SIGKILL" || (sig === "SIGTERM" && !opts.ignoreTerm?.includes(pid))) {
        h.rows = h.rows.filter((r) => r.pid !== pid);
        if (sig === "SIGTERM") opts.onTerm?.(pid, h);
      }
    },
    sleep: async (ms) => { h.clock += ms; },
    now: () => h.clock,
    selfPid: SELF,
  };
  return h;
}
interface FakeHost { rows: ProcRow[]; signals: Array<[number, NodeJS.Signals]>; clock: number; tableFails: boolean; deps: TreeDeps }

function recordedTree(): ReturnType<typeof newTreeRecord> {
  const rec = newTreeRecord(700, T0);
  observe(rec, [...HOST, row(700, 500, 700, 0), row(701, 700, 700, 0), row(710, 700, 710, 0)], { selfPid: SELF, nowMs: T0 + 100 });
  return rec;
}

test("endTree: SIGTERM (+SIGCONT) to each survivor; nothing needs SIGKILL when they exit", async () => {
  const h = fakeHost([...HOST, row(701, 1, 700, 10), row(710, 1, 710, 10)]);
  const r = await endTree(recordedTree(), h.deps, { settleMs: 0 });
  assert.deepEqual(r.terminated.sort(), [701, 710]);
  assert.deepEqual(r.killed, []);
  assert.deepEqual(r.survivors, []);
  assert.deepEqual(h.signals.filter(([p]) => p === 701).map(([, s]) => s), ["SIGTERM", "SIGCONT"]);
  assert.ok(!h.signals.some(([p]) => p === 400 || p === 500 || p === 600 || p === 1), "host untouched");
});

test("endTree: a process that ignores SIGTERM gets SIGKILL after the grace", async () => {
  const h = fakeHost([...HOST, row(701, 1, 700, 10)], { ignoreTerm: [701] });
  const start = h.clock;
  const r = await endTree(recordedTree(), h.deps, { settleMs: 0, graceMs: 1000 });
  assert.deepEqual(r.terminated, [701]);
  assert.deepEqual(r.killed, [701]);
  assert.deepEqual(r.survivors, []);
  assert.ok(h.clock - start >= 1000, "waited out the grace first");
  assert.equal(h.signals.filter(([, s]) => s === "SIGTERM").length, 1, "one SIGTERM per process, not one per poll");
});

test("endTree: a child forked during the grace (a TERM trap) is found and ended too", async () => {
  const h = fakeHost([...HOST, row(701, 1, 700, 10)], {
    onTerm: (pid, host) => { if (pid === 701) host.rows.push(row(750, 1, 700, 0)); },
  });
  const r = await endTree(recordedTree(), h.deps, { settleMs: 0 });
  assert.deepEqual(r.terminated.sort(), [701, 750]);
  assert.deepEqual(r.survivors, []);
});

test("endTree: what exits on its own during the settle is not counted as left running", async () => {
  const h = fakeHost([...HOST, row(701, 1, 700, 10), row(710, 1, 710, 10)]);
  const deps: TreeDeps = { ...h.deps, sleep: async (ms) => { h.clock += ms; h.rows = h.rows.filter((r) => r.pid !== 710); } };
  const r = await endTree(recordedTree(), deps, { settleMs: 250 });
  assert.deepEqual(r.terminated, [701]);
});

test("endTree: an unreadable process table signals nothing (never kill blind)", async () => {
  const h = fakeHost([...HOST, row(701, 1, 700, 10)]);
  h.tableFails = true;
  const r = await endTree(recordedTree(), h.deps);
  assert.deepEqual(r, { terminated: [], killed: [], survivors: [] });
  assert.deepEqual(h.signals, []);
});

test("endTree: an unkillable survivor is reported, after three SIGKILL rounds", async () => {
  const h = fakeHost([...HOST, row(701, 1, 700, 10)]);
  const deps: TreeDeps = { ...h.deps, kill: (pid, sig) => { h.signals.push([pid, sig]); } }; // nothing ever dies
  const r = await endTree(recordedTree(), deps, { settleMs: 0, graceMs: 300 });
  assert.deepEqual(r.killed, [701]);
  assert.deepEqual(r.survivors, [701]);
  assert.equal(h.signals.filter(([, s]) => s === "SIGKILL").length, 3);
});

test("ProcTreeTracker samples at once and on its (unref'd) timer; stop() waits for the sample in flight", async () => {
  let calls = 0;
  let release = (): void => {};
  const tables: ProcRow[][] = [
    [...HOST, row(700, 500, 700, 0)],
    [...HOST, row(700, 500, 700, 0), row(760, 700, 760, 0)],
  ];
  const tracker = new ProcTreeTracker(700, {
    selfPid: SELF,
    now: () => T0,
    table: async () => {
      const t = tables[Math.min(calls++, tables.length - 1)]!;
      if (calls === 2) await new Promise<void>((r) => { release = r; });
      return t;
    },
  }, 20);
  // The timer fires and the 2nd sample blocks (polled, not a fixed delay: a loaded host is slow).
  for (let i = 0; i < 300 && calls < 2; i++) await new Promise((r) => setTimeout(r, 10));
  assert.equal(calls, 2, "one sample at once, one from the timer; the timer does not stack samples");
  const stopped = tracker.stop();
  let done = false;
  void stopped.then(() => { done = true; });
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(done, false, "stop() waits for the in-flight sample");
  release();
  await stopped;
  assert.ok(tracker.record.members.has(760), "the in-flight sample landed in the record");
  const after = calls;
  await new Promise((r) => setTimeout(r, 60));
  assert.equal(calls, after, "no sample after stop()");
  await tracker.sample(); // a no-op once stopped
  assert.equal(calls, after);
});

test("an adopted chain (the reply filter started with the services): the age floor is ITS spawn, or the whole tree is missed", async () => {
  // The filter (700) and its own node child (701) were spawned 8 s before the
  // agent was handed to it; the agent (702) and its background job (703, in a
  // session of its own) came after. macOS wrapper suite 2026-10-09: tracked
  // from the hand-off, the root read as older than the launch and the session
  // end stopped nothing.
  const table = [...HOST, row(700, 500, 700, 8), row(701, 700, 700, 8), row(702, 701, 700, 3), row(703, 702, 703, 1)];
  const deps = { selfPid: SELF, now: () => T0, table: async () => table };
  const fromHandOff = new ProcTreeTracker(700, deps, 60_000);
  await fromHandOff.stop();
  assert.deepEqual([...fromHandOff.record.members.keys()], [], "tracked from the hand-off: nothing is the agent's (the bug)");
  const fromSpawn = new ProcTreeTracker(700, deps, 60_000, T0 - 8_000);
  await fromSpawn.stop();
  assert.deepEqual([...fromSpawn.record.members.keys()].sort((a, b) => a - b), [700, 701, 702, 703]);
  assert.equal(fromSpawn.record.sinceMs, T0 - 8_000);
  // A spawn time in the future (a clock step) never moves the floor past now.
  const future = new ProcTreeTracker(700, deps, 60_000, T0 + 60_000);
  await future.stop();
  assert.equal(future.record.sinceMs, T0);
});

test("inertTree: nothing sampled, stop resolves", async () => {
  const t = inertTree(42);
  assert.equal(t.rootPid, 42);
  await t.sample();
  await t.stop();
});

// ── the Platform methods over this engine ──────────────────────────────────

test("linux: trackTree is inert and killTree ends nothing (the kernel scope holds the tree) and says so", async () => {
  const tree = linuxPlatform.trackTree(4242);
  assert.equal(tree.rootPid, 4242);
  await tree.sample();
  const r = await linuxPlatform.killTree(tree);
  assert.deepEqual({ ...r, skipped: undefined }, { terminated: [], killed: [], survivors: [], skipped: undefined });
  assert.equal(r.skipped, LINUX_TREE_SKIP);
  assert.match(LINUX_TREE_SKIP, /^linux: the launcher does not end the agent tree/);
  await tree.stop();
});

test("darwin: killTree refuses a tree its own trackTree did not record (nothing signalled)", async () => {
  const r = await darwinPlatform.killTree({ rootPid: 1, sample: async () => {}, stop: async () => {} });
  assert.deepEqual(r, { terminated: [], killed: [], survivors: [], skipped: "darwin: this tree was not tracked by trackTree" });
});

test("darwin: the tracker samples once a second by default (one `ps -x` per tick)", () => {
  assert.equal(DARWIN_TREE_SAMPLE_MS, 1000);
});
