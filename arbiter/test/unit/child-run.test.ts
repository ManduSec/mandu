/**
 * Unit: child-run — the runner every arbiter git call goes through
 * (src/child-run.ts, docs/design/architecture/write-protection.md §8.5.1). A call ALWAYS
 * settles: its exit status and output; killed at its deadline with its
 * whole process group (a process it put in the background dies with it); a
 * descendant that left the group dies with a kill too; a straggler neither
 * in the group nor a descendant that holds the output open costs the grace,
 * not forever, and fails the call; an owner's kill settles it; output over
 * the cap fails it; a program that cannot start is an error. And the case
 * that hung CI (pipelines 7777, 7778): bubblewrap SIGKILLed in its start-up
 * leaves no sandbox child holding the pipes, because the kill reaches the
 * group, nor a sandbox running on after its pid 1's setsid, because the
 * kill reaches the descendants too (CI, 2026-10-21; both probe-gated on a
 * working bubblewrap git sandbox). On macOS the same
 * kills of the Seatbelt git sandbox settle the same way (`sandbox-exec`
 * execs git in place: there is no sandbox child and no such window).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { descendants, runChild, type RunningChild } from "../../src/child-run.js";
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
// `leaver` stays the child's descendant (bubblewrap's sandbox child after
// its setsid has that shape), which a kill reaches; `straggler` forks
// first and publishes only once its parent is gone, so it is no
// descendant either: out of every kill's reach.
const leaver = "perl -MPOSIX -e 'POSIX::setsid() >= 0 or die; my $ready = shift @ARGV; $| = 1; print qq($$\\n); open my $f, q(>), $ready or die; close $f; exec @ARGV'";
const straggler = "perl -MPOSIX -e 'my $ready = shift @ARGV; my $parent = $$; defined(my $p = fork) or die; exit 0 if $p; select(undef, undef, undef, 0.01) while getppid() == $parent; POSIX::setsid() >= 0 or die; $| = 1; print qq($$\\n); open my $f, q(>), $ready or die; close $f; exec @ARGV'";
/** Does this host list a process's children in /proc (Linux), which the
 *  runner's kill reads? */
const procChildren = ((): boolean => {
  try { readFileSync(`/proc/${process.pid}/task/${process.pid}/children`, "utf8"); return true; } catch { return false; }
})();
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

test("stdoutEncoding latin1: collected stdout is one character per byte (a binary answer, bytes that are not UTF-8 kept); the default decodes UTF-8", async () => {
  const bytes = "printf '\\377\\376\\303\\000\\342\\202'";
  const bin = await runChild("sh", ["-c", bytes], { cwd, env, timeoutMs: 10_000, stdoutEncoding: "latin1" });
  assert.deepEqual([...Buffer.from(bin.stdout, "latin1")], [0xff, 0xfe, 0xc3, 0x00, 0xe2, 0x82]);
  const text = await runChild("sh", ["-c", bytes], { cwd, env, timeoutMs: 10_000 });
  assert.ok(text.stdout.includes("�"), "UTF-8 by default: the invalid bytes replaced");
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

test("a straggler OUTSIDE the group and no descendant of the child, holding the output: an exit settles after the close grace, a kill after the kill grace; both failures", async () => {
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
    assert.ok(leadsOwnGroup(s2), "the outside straggler survives the kill and holds the pipes");
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

test("a descendant that left the group (a session of its own, as bubblewrap's sandbox child after its setsid) dies with a kill: the output closes by itself", { skip: procChildren ? false : "no /proc children lists here" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-leaver-"));
  const children = new Set<RunningChild>();
  let s = 0;
  try {
    let output = "";
    let markReady!: () => void;
    const ready = new Promise<void>((resolve) => { markReady = resolve; });
    const p = runChild("sh", ["-c", `${leaver} "$1" sleep 30 & sleep 30`, "sh", join(dir, "ready")], {
      cwd, env, timeoutMs: 20_000, killGraceMs: 5_000,
      onStdout: (c) => { output += c; if (/^\d+\n$/.test(output)) markReady(); },
    }, children);
    assert.equal(await Promise.race([ready.then(() => true), p.then(() => false)]), true, "it left the group before the kill");
    s = Number(output.trim());
    assert.ok(s > 0 && leadsOwnGroup(s), "it leads a group of its own, out of the group kill's reach");
    const t0 = Date.now();
    for (const child of children) child.kill("stopped after a descendant left the group");
    const killed = await p;
    assert.ok(Date.now() - t0 < 3000, `settled in ${Date.now() - t0} ms`);
    assert.equal(killed.killed, true);
    assert.doesNotMatch(killed.stderr, /did not close/, "the kill reached it: the output closed by itself");
    assert.ok(await gone(s), "the descendant was killed");
  } finally {
    for (const child of children) child.kill("test cleanup");
    if (s > 0) { try { process.kill(s, "SIGKILL"); } catch { /* gone */ } }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("descendants: a running tree's children and grandchildren, parents first; none for a pid that is not there", { skip: procChildren ? false : "no /proc children lists here" }, async () => {
  const tree = spawn("sh", ["-c", "sh -c 'sleep 30 & sleep 30 & wait' & sleep 30 & wait"], { stdio: "ignore" });
  try {
    let found: number[] = [];
    const end = Date.now() + 10_000;
    while (Date.now() < end && found.length < 4) { await sleep(20); found = descendants(tree.pid!); }
    assert.equal(found.length, 4, `sh's sleep and inner sh, the inner sh's two sleeps: ${found}`);
    const ppid = (pid: number): number => Number(/^\d+ \(.*\) \S (\d+)/.exec(readFileSync(`/proc/${pid}/stat`, "utf8"))![1]);
    for (const [i, pid] of found.entries()) {
      const parent = ppid(pid);
      assert.ok(parent === tree.pid || found.slice(0, i).includes(parent), `${pid}'s parent ${parent} is listed before it`);
    }
    assert.deepEqual(descendants(2 ** 30), []);
  } finally {
    for (const pid of descendants(tree.pid!)) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } }
    tree.kill("SIGKILL");
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
// The second window (CI, 2026-10-21): after its setsid that child leads a
// session of its own and binds its life to bubblewrap only after it forked
// the command, so a kill in between left the sandbox running the command
// to its end. The runner also kills the descendants it reads before the
// kill. With `git --version` such a sandbox held the output past a 5 s
// grace only when starved (nice 19 in a busy cgroup); with `sleep 300`
// every one does, so the second test sees the window on an idle host too
// (without the descendant kill: 3 of 512 kills there).
// The grace is long (START_UP_KILL_GRACE_MS): at nice 19 on a CPU-bound
// host even KILLED processes wait to exit. In a guest with four busy loops
// per vCPU, killed bubblewraps sat in the kernel for up to 64 s (state D,
// in rtnl_lock, while their clone made the network namespace) with nothing
// left running. What these tests catch never closes within it: the first
// window's orphan never closes, the second window's sandbox runs its
// `sleep 300`.
const sandbox = gitSandbox();
const START_UP_KILL_GRACE_MS = 120_000;

/** `runs` runs of `argv`, 16 at a time, each killed by its owner within 8 ms of
 *  its spawn: the stderr of every run whose output was left to the grace. */
async function killedInStartUp(argv: readonly string[], runs = 256): Promise<string[]> {
  let next = 0;
  const abandoned: string[] = [];
  const lane = async (): Promise<void> => {
    while (next < runs) {
      next++;
      const children = new Set<RunningChild>();
      const p = runChild(argv[0]!, argv.slice(1), { cwd, env, timeoutMs: 600_000, killGraceMs: START_UP_KILL_GRACE_MS }, children);
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

test("bubblewrap (the git sandbox, under nice 19) killed in its start-up while its sandbox would run 300 s: no sandbox outlives the kill (its pid 1 after its setsid included)", { skip: sandbox === null || isSeatbeltGitSandbox(sandbox) ? "no bubblewrap git sandbox here" : false }, async () => {
  if (sandbox === null || isSeatbeltGitSandbox(sandbox)) return;
  const flags = sandbox.flags.length > 0 ? sandbox.flags : GIT_SANDBOX_FLAG_SETS[0]!;
  const abandoned = await killedInStartUp(["nice", "-n", "19", sandbox.bwrap, ...flags, "--", "sleep", "300"], 512);
  assert.deepEqual(abandoned, [], "a sandbox outlived the kill and ran on, holding the output");
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
