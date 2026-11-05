/**
 * mandu-running-live.test — `liveLaunches` (src/mandu-running.ts): which
 * sessions' `mandu <agent>` launches are alive, so an agent quiet past the
 * listing's five-minute recency window still counts as running while its
 * launch is (dashboard.md §4.10.4, *A live launch keeps R*).
 *
 * Pins:
 * - a `<runtimeBase>/<epochSec>-<pid>` dir whose pid is alive is listed by
 *   its name (the session's scope id); a dead pid, and any other name in
 *   the base (instances, human, a dashboard's files, `--id` names), is not;
 * - a pid whose process started more than 10 s after the dir's epoch was
 *   reused by another process: not listed; a start time that cannot be
 *   read: alive is enough (the cautious stance of `manduNotRunning`);
 * - an unreadable base: none;
 * - over the real filesystem and /proc, this process's own launch dir is
 *   listed when its epoch is now, and not when its epoch is long before
 *   this process started (Linux, where the start time can be read);
 * - `procStartedAt` reads field 22 after the last ')' (a command name with
 *   spaces and parentheses) plus /proc/stat's btime.
 *
 * Axes: display only, no arbiter; none read.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";

import { liveLaunches, procStartedAt, type RunningProbeDeps } from "../../src/mandu-running.js";

const BASE = "/run/u/mandu";

function probe(over: { names?: string[] | null; alive?: number[]; started?: Record<number, number | null> } = {}): RunningProbeDeps {
  return {
    exists: () => false,
    list: (d) => (d === BASE && over.names ? over.names : []),
    readJson: () => null,
    pidAlive: (pid) => (over.alive ?? []).includes(pid),
    ...(over.started ? { startedAt: (pid: number) => over.started![pid] ?? null } : {}),
  };
}

test("liveLaunches: an alive launch's dir is listed by its scope id; a dead one and other names are not", () => {
  const names = ["1760000000-77", "1760000100-78", "instances", "human", "current", "dashboard-77.port", "my-run", "17x-77", "1760000000-0"];
  assert.deepEqual([...liveLaunches(BASE, probe({ names, alive: [77, 0] }))], ["1760000000-77"], "only the alive pid's launch dir; pid 0 is never a launch");
  assert.deepEqual([...liveLaunches(BASE, probe({ names, alive: [] }))], [], "no pid alive: none");
  assert.deepEqual([...liveLaunches(BASE, probe({ names: ["1760000000-77", "1760000100-78"], alive: [77, 78] }))].sort(), ["1760000000-77", "1760000100-78"]);
});

test("liveLaunches: a pid that started well after the launch was reused, not counted; an unreadable start time is", () => {
  const names = ["1760000000-77"];
  // The launcher started before it stamped its scope id.
  assert.equal(liveLaunches(BASE, probe({ names, alive: [77], started: { 77: 1759999990 } })).size, 1, "started before the epoch: the launch");
  assert.equal(liveLaunches(BASE, probe({ names, alive: [77], started: { 77: 1760000005 } })).size, 1, "within the slack: the launch");
  assert.equal(liveLaunches(BASE, probe({ names, alive: [77], started: { 77: 1760000060 } })).size, 0, "60 s after: another process with the reused pid");
  assert.equal(liveLaunches(BASE, probe({ names, alive: [77], started: { 77: null } })).size, 1, "a start time that cannot be read: alive is enough");
  assert.equal(liveLaunches(BASE, probe({ names, alive: [77] })).size, 1, "no start-time reader: alive is enough");
});

test("liveLaunches: an unreadable base lists none", () => {
  assert.equal(liveLaunches(BASE, probe({ names: null, alive: [77] })).size, 0);
  assert.equal(liveLaunches(join(tmpdir(), "mandu-no-such-runtime-base-304")).size, 0, "the real reader over an absent dir");
});

test("liveLaunches: the real filesystem and /proc, this process as the launcher", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-live-launches-"));
  try {
    const now = Math.floor(Date.now() / 1000);
    const mine = `${now}-${process.pid}`;
    mkdirSync(join(dir, mine));
    mkdirSync(join(dir, "instances"));
    assert.deepEqual([...liveLaunches(dir)], [mine], "this live process's launch dir");
    rmSync(join(dir, mine), { recursive: true });
    assert.equal(liveLaunches(dir).size, 0, "teardown removed it: none");
    if (platform() === "linux") {
      // An epoch an hour before this process started: its pid was reused.
      mkdirSync(join(dir, `${now - Math.ceil(process.uptime()) - 3600}-${process.pid}`));
      assert.equal(liveLaunches(dir).size, 0, "a launch dir older than its pid's process is not that process's");
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("procStartedAt: field 22 after the last ')', in ticks, plus btime; null when unreadable", () => {
  // Fields 3..21 as 0, field 22 = 12345 ticks, a command with ") (" in it.
  const rest = ["S", ...Array.from({ length: 18 }, () => "0"), "12345", "0", "0"].join(" ");
  const files: Record<string, string> = {
    "/proc/42/stat": `42 (my) (odd cmd) ${rest}`,
    "/proc/stat": "cpu  1 2 3\nbtime 1760000000\nprocesses 9\n",
  };
  const read = (p: string): string => {
    if (!(p in files)) throw new Error("ENOENT");
    return files[p]!;
  };
  assert.equal(procStartedAt(42, read), 1760000000 + 123.45);
  assert.equal(procStartedAt(43, read), null, "no such process");
  assert.equal(procStartedAt(42, (p) => (p === "/proc/stat" ? "cpu 1\n" : read(p))), null, "no btime");
  if (platform() === "linux") {
    const started = procStartedAt(process.pid);
    assert.ok(started !== null, "this process's start time reads on Linux");
    const expected = Date.now() / 1000 - process.uptime();
    assert.ok(Math.abs(started - expected) < 5, `within seconds of process.uptime's (${started} vs ${expected})`);
  }
});
