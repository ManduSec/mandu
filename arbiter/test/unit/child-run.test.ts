/**
 * Unit: child-run — the runner every arbiter git call goes through
 * (src/child-run.ts, docs/design/architecture/write-protection.md §8.5.1). A call ALWAYS
 * settles: its exit status and output; killed at its deadline with its
 * whole process group (a process it put in the background dies with it); a
 * straggler outside the group that holds the output open costs the grace,
 * not forever, and fails the call; an owner's kill settles it; output over
 * the cap fails it; a program that cannot start is an error. And the case
 * that hung CI (pipelines 7777, 7778): bubblewrap SIGKILLed in its start-up
 * leaves no sandbox child holding the pipes, because the kill reaches the
 * group (probe-gated on a working bubblewrap git sandbox). On macOS the same
 * kills of the Seatbelt git sandbox settle the same way (`sandbox-exec`
 * execs git in place: there is no sandbox child and no such window).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runChild, type RunningChild } from "../../src/child-run.js";
import { GIT_SANDBOX_FLAG_SETS, gitCommand, gitSandbox, isSeatbeltGitSandbox } from "../../src/hardened-git.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the runner is axis-free; stated per the convention

const env = { PATH: process.env["PATH"] ?? "/usr/bin:/bin" };
const cwd = process.cwd();
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const alive = (pid: number): boolean => {
  try { process.kill(pid, 0); } catch { return false; }
  // A zombie still answers signal 0: dead once it is one. Its state from
  // /proc on Linux, from ps where there is no /proc (macOS).
  if (process.platform === "linux") {
    try { return !/^\S+ \(.*\) Z/.test(readFileSync(`/proc/${pid}/stat`, "utf8")); } catch { return false; }
  }
  const state = spawnSync("ps", ["-o", "stat=", "-p", String(pid)], { encoding: "utf8" }).stdout?.trim() ?? "";
  return state !== "" && !state.startsWith("Z");
};
// A process in a session (so a group) of its own that inherits the output.
// Through perl's POSIX::setsid: util-linux's setsid(1) is Linux-only (macOS
// has none, and `setsid sleep 30 &` there leaves no straggler at all), and
// perl ships with macOS and is essential on Debian and Ubuntu.
// Publish readiness only after setsid: a shell's echo of $! merely says
// the process was spawned, and a loaded host can kill it before it escapes.
const straggler = "perl -MPOSIX -e 'POSIX::setsid() >= 0 or die; my $ready = shift @ARGV; $| = 1; print qq($$\\n); open my $f, q(>), $ready or die; close $f; exec @ARGV'";
/** Does `pid` lead a process group of its own (so it was outside the
 *  child's group)? Read with ps on both hosts: deterministic, where a
 *  liveness check right after the group kill can race on a loaded host. */
const leadsOwnGroup = (pid: number): boolean =>
  spawnSync("ps", ["-o", "pgid=", "-p", String(pid)], { encoding: "utf8" }).stdout?.trim() === String(pid);
async function gone(pid: number, ms = 3000): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (!alive(pid)) return true; await sleep(20); }
  return !alive(pid);
}

test("an exit: its code, its output and stderr; stdin carries the input; complete only for code 0", async () => {
  const ok = await runChild("sh", ["-c", "cat; echo err >&2"], { cwd, env, input: "hello\n", timeoutMs: 10_000 });
  assert.deepEqual({ code: ok.code, stdout: ok.stdout, stderr: ok.stderr, complete: ok.complete, killed: ok.killed }, { code: 0, stdout: "hello\n", stderr: "err\n", complete: true, killed: false });
  const bad = await runChild("sh", ["-c", "echo out; exit 3"], { cwd, env, timeoutMs: 10_000 });
  assert.equal(bad.code, 3);
  assert.equal(bad.stdout, "out\n");
  assert.equal(bad.complete, false);
  const chunks: string[] = [];
  const streamed = await runChild("sh", ["-c", "printf 'a\\nb\\n'"], { cwd, env, timeoutMs: 10_000, onStdout: (c) => chunks.push(c) });
  assert.equal(streamed.stdout, "", "handed over, not collected");
  assert.equal(chunks.join(""), "a\nb\n");
});

test("the deadline kills the whole process group: a process the child put in the background dies too, and the call settles as a failure", async () => {
  const t0 = Date.now();
  const r = await runChild("sh", ["-c", "sleep 30 & echo $!; sleep 30"], { cwd, env, timeoutMs: 300 });
  assert.ok(Date.now() - t0 < 3000, `settled in ${Date.now() - t0} ms`);
  assert.equal(r.killed, true);
  assert.equal(r.code, 1);
  assert.equal(r.complete, false);
  assert.match(r.stderr, /killed at its 300 ms deadline/);
  assert.doesNotMatch(r.stderr, /did not close/, "the group kill closed the output: nothing was abandoned");
  const bg = Number(r.stdout.trim());
  assert.ok(bg > 0);
  assert.ok(await gone(bg), "the background process was in the group and was killed");
});

test("a straggler OUTSIDE the group holding the output: an exit settles after the close grace, a kill after the kill grace; both failures", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-straggler-"));
  const children = new Set<RunningChild>();
  let s1 = 0;
  let s2 = 0;
  try {
    // The shell exits only after Perl has detached and published readiness.
    // Startup has its own generous deadline; the 300 ms close grace still
    // measures only abandonment after exit, independently of CPU load.
    const exited = await runChild("sh", ["-c", `${straggler} "$1" sleep 30 & while [ ! -f "$1" ]; do sleep 0.02; done; exit 0`, "sh", join(dir, "exit-ready")], {
      cwd, env, timeoutMs: 20_000, closeGraceMs: 300,
    });
    s1 = Number(exited.stdout.trim());
    assert.ok(s1 > 0 && leadsOwnGroup(s1), `the straggler leads a group of its own (outside the child's): ${exited.stderr}`);
    assert.equal(exited.code, 1, "an exit whose output never closed is a failure (its output may be incomplete)");
    assert.equal(exited.complete, false);
    assert.match(exited.stderr, /kept its output open/);
    try { process.kill(s1, "SIGKILL"); } catch { /* gone */ }

    let output = "";
    let markReady!: () => void;
    const ready = new Promise<void>((resolve) => { markReady = resolve; });
    const p = runChild("sh", ["-c", `${straggler} "$1" sleep 30 & sleep 30`, "sh", join(dir, "kill-ready")], {
      cwd, env, timeoutMs: 20_000, killGraceMs: 300,
      onStdout: (c) => { output += c; if (/^\d+\n$/.test(output)) markReady(); },
    }, children);
    assert.equal(await Promise.race([ready.then(() => true), p.then(() => false)]), true, "the straggler detached before the group was killed");
    s2 = Number(output.trim());
    assert.ok(s2 > 0 && leadsOwnGroup(s2), "the ready process leads its own group");
    const t0 = Date.now();
    for (const child of children) child.kill("stopped after the straggler detached");
    const killed = await p;
    assert.ok(Date.now() - t0 < 3000, `settled in ${Date.now() - t0} ms`);
    assert.ok(leadsOwnGroup(s2), "the outside straggler survives the group kill and holds the pipes");
    assert.equal(killed.killed, true);
    assert.equal(killed.code, 1);
    assert.equal(killed.complete, false);
    assert.match(killed.stderr, /stopped after the straggler detached; its output did not close after the kill/);
  } finally {
    for (const child of children) child.kill("test cleanup");
    for (const pid of [s1, s2]) if (pid > 0) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an owner's kill settles the call at once and removes it from the owner's set", async () => {
  const children = new Set<RunningChild>();
  const p = runChild("sleep", ["30"], { cwd, env, timeoutMs: 60_000 }, children);
  assert.equal(children.size, 1);
  const t0 = Date.now();
  for (const c of children) c.kill("the owner stopped");
  const r = await p;
  assert.ok(Date.now() - t0 < 2000);
  assert.equal(r.killed, true);
  assert.match(r.stderr, /the owner stopped/);
  assert.equal(children.size, 0);
});

test("output over the cap kills the call (never a silently truncated answer); a program that cannot start is an error", async () => {
  const big = await runChild("sh", ["-c", "yes"], { cwd, env, timeoutMs: 10_000, maxStdout: 1 << 16 });
  assert.equal(big.killed, true);
  assert.equal(big.code, 1);
  assert.match(big.stderr, /its output passed 65536 characters/);
  const none = await runChild("/nonexistent/mandu-no-such-program", [], { cwd, env, timeoutMs: 10_000 });
  assert.equal(none.code, 1);
  assert.equal(none.complete, false);
  assert.match(none.error ?? "", /ENOENT/);
});

// The CI hang: bubblewrap's sandbox child blocks on an eventfd until its
// parent has set it up and only later binds its life to that parent; a
// SIGKILL of bubblewrap alone in that window left it reparented to init,
// blocked forever, holding the pipes (5% of kills within 10 ms of the
// spawn, measured). The group kill reaches it: every call closes by itself.
// Without the group kill this test fails (a few of its 256 kills land in
// the window: 20 of 600 on the host it was written on).
const sandbox = gitSandbox();

/** 256 runs of `argv`, 16 at a time, each killed by its owner within 8 ms of
 *  its spawn: the stderr of every run whose output was left to the grace. */
async function killedInStartUp(argv: readonly string[]): Promise<string[]> {
  const runs = 256;
  let next = 0;
  const abandoned: string[] = [];
  const lane = async (): Promise<void> => {
    while (next < runs) {
      next++;
      const children = new Set<RunningChild>();
      const p = runChild(argv[0]!, argv.slice(1), { cwd, env, timeoutMs: 60_000, killGraceMs: 5_000 }, children);
      await sleep(Math.random() * 8);
      for (const c of children) c.kill("stopped in its start-up");
      const r = await p;
      if (/did not close/.test(r.stderr)) abandoned.push(r.stderr);
    }
  };
  await Promise.all(Array.from({ length: 16 }, lane));
  return abandoned;
}

test("bubblewrap (the git sandbox, under nice 19) killed in its start-up: every call's output closes by itself; none is left to the grace", { skip: sandbox === null || isSeatbeltGitSandbox(sandbox) ? "no bubblewrap git sandbox here" : false }, async () => {
  if (sandbox === null || isSeatbeltGitSandbox(sandbox)) return;
  const flags = sandbox.flags.length > 0 ? sandbox.flags : GIT_SANDBOX_FLAG_SETS[0]!;
  const abandoned = await killedInStartUp(["nice", "-n", "19", sandbox.bwrap, ...flags, "--", "git", "--version"]);
  assert.deepEqual(abandoned, [], "a sandbox child outlived the kill and held the output");
});

// macOS: `sandbox-exec` applies the profile and execs git in place (one
// process, no sandbox child), so there is no start-up window to fall in;
// the same kills, on the command line an R3 build runs, settle the same way.
test("the Seatbelt git sandbox (macOS, under nice 19) killed in its start-up: every call's output closes by itself", { skip: sandbox === null || !isSeatbeltGitSandbox(sandbox) ? "no Seatbelt git sandbox here" : false }, async () => {
  if (sandbox === null || !isSeatbeltGitSandbox(sandbox)) return;
  const cmd = gitCommand(["--version"], sandbox);
  assert.equal(cmd.file, "/usr/bin/sandbox-exec");
  const abandoned = await killedInStartUp(["/usr/bin/nice", "-n", "19", cmd.file, ...cmd.args]);
  assert.deepEqual(abandoned, [], "a process outlived the group kill and held the output");
});
