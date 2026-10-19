/**
 * child-run.test — the hung-runner regression oracle for the live suites'
 * child spawner (tests/lib/child-run.ts).
 *
 * THE BUG CLASS UNDER TEST (2026-07-11): awaiting a spawned agent CLI's
 * "close" event hangs when a DESCENDANT inherits the stdio write-ends and
 * outlives the child — the pipes never EOF, the scenario burns its whole
 * timeout and is misreported as "timed out", and the leaked pipe fds hold the
 * node:test runner's event loop open forever (the TAP epilogue never prints).
 * runChildToExit settles on EXIT with a short close-grace and SIGKILLs the
 * child's whole process group, so these tests prove:
 *   1. a clean child resolves promptly with its output and exit code;
 *   2. a child whose backgrounded descendant holds stdout/stderr STILL
 *      settles within the grace (not the timeout), and the descendant is
 *      reaped (killed), leaving nothing to hold the loop;
 *   3. the timeout path rejects and reaps the whole group.
 * Deterministic: bash children only, no agent CLI, no network, no arbiter.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runChildToExit } from "../lib/child-run.js";

const ENV = { PATH: process.env["PATH"] };
const CWD = process.cwd();

/** Is `pid` still alive (signal 0 probe)? */
function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

test("clean child: resolves with exit code and captured output", async () => {
  const r = await runChildToExit(
    "bash",
    ["-c", "echo out-marker; echo err-marker >&2; exit 3"],
    { cwd: CWD, env: ENV, timeoutMs: 10_000, label: "bash" },
  );
  assert.equal(r.code, 3);
  assert.match(r.stdout, /out-marker/);
  assert.match(r.stderr, /err-marker/);
});

test("descendant holding stdio: settles within the close-grace, not the timeout, and the descendant is reaped", async () => {
  const started = Date.now();
  // The child backgrounds a long sleep (which inherits stdout/stderr — the
  // exact shape of an orphaned MCP server), prints ITS pid, and exits 0.
  const r = await runChildToExit(
    "bash",
    ["-c", "sleep 304.2 & echo orphan-pid=$!; exit 0"],
    { cwd: CWD, env: ENV, timeoutMs: 60_000, label: "bash", closeGraceMs: 1500 },
  );
  const elapsed = Date.now() - started;
  assert.equal(r.code, 0, "the child's real exit code is reported (not a fake timeout)");
  const orphanPid = Number(r.stdout.match(/orphan-pid=(\d+)/)?.[1]);
  assert.ok(Number.isFinite(orphanPid), `stdout carries the orphan pid (got ${JSON.stringify(r.stdout)})`);
  assert.ok(elapsed < 30_000, `settled via the close-grace (${elapsed}ms), not the 60s timeout`);
  // The group SIGKILL reaped the descendant — nothing survives to hold pipes.
  for (let i = 0; i < 20 && alive(orphanPid); i++) await new Promise((res) => setTimeout(res, 100));
  assert.equal(alive(orphanPid), false, "the stdio-holding descendant was killed with the group");
});

test("timeout: rejects and reaps the whole group", async () => {
  // The sleeper writes its own pid to a file (exec keeps the pid), so the
  // check below probes exactly that process — never a host-wide pgrep that a
  // suite running alongside could match (test-organization.md §8.4).
  const dir = mkdtempSync(join(tmpdir(), "child-run-"));
  const pidFile = join(dir, "sleeper.pid");
  let caught: unknown;
  try {
    await runChildToExit(
      "bash",
      ["-c", `echo $$ > '${pidFile}'; exec sleep 305.7`],
      { cwd: CWD, env: ENV, timeoutMs: 1500, label: "sleepy" },
    );
  } catch (err) {
    caught = err;
  }
  assert.ok(caught instanceof Error, "the timeout path rejects");
  assert.match((caught as Error).message, /sleepy timed out after 2s/);
  const sleeperPid = Number(readFileSync(pidFile, "utf8").trim());
  rmSync(dir, { recursive: true, force: true });
  assert.ok(Number.isInteger(sleeperPid) && sleeperPid > 0, "the sleeper recorded its pid");
  // The group reap killed the sleeper itself — nothing survives.
  for (let i = 0; i < 20 && alive(sleeperPid); i++) await new Promise((res) => setTimeout(res, 100));
  assert.equal(alive(sleeperPid), false, "no sleeper survives the group reap");
});
