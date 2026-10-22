/**
 * Unit: the launcher's production git runner (git-object-twins.ts
 * `defaultGitRunner`) runs through `runChild` (src/child-run.ts,
 * docs/design/architecture/write-protection.md §8.5.1): its exit code, output and input as
 * before, and a deadline that kills the call's whole process group (a
 * process the call put in the background dies with it) and always settles
 * the call as a failure. The deadline landing in bubblewrap's start-up is
 * the kernel test (test/kernel/git-sandbox.test.ts).
 *
 * A stand-in `git` on PATH (the sandbox off) makes the calls deterministic.
 */
process.env["MANDU_GIT_SANDBOX"] = "0";

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { defaultGitRunner, type GitRunner } from "../../src/git-object-twins.js";
import {
  GIT_SESSION_RUNNER_SOURCE, hostPtraceScope, openGitSession, perCallGitRunner, sandboxExitCode, sessionAllowed, sessionRunnerCommand,
  sessionSandboxFlags, SESSION_PROC_FLAGS, type GitSession, type GitSessionOpts,
} from "../../src/git-session.js";
import { gitCommand } from "../../src/hardened-git.js";
import { gitCounts } from "../../src/launch-timings.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the runner serves the confidentiality axis's launch prep; it reads no axis

const dir = mkdtempSync(join(tmpdir(), "mdu-git-runner-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const savedPath = process.env["PATH"];
after(() => { process.env["PATH"] = savedPath; });

/** Put a stand-in `git` running `body` (sh) first on PATH. */
function fakeGit(body: string): void {
  const bin = mkdtempSync(join(dir, "bin-"));
  writeFileSync(join(bin, "git"), `#!/bin/sh\n${body}\n`);
  chmodSync(join(bin, "git"), 0o755);
  process.env["PATH"] = `${bin}:${savedPath ?? "/usr/bin:/bin"}`;
}

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

test("an exit: its code, stdout and stderr; the input reaches stdin; the hardened arguments come first", async () => {
  fakeGit(`cat; echo "args: $*"; echo oops >&2; exit 3`);
  const r = await defaultGitRunner(["cat-file", "--batch"], { cwd: dir, input: "HEAD:f\n" });
  assert.equal(r.code, 3);
  assert.match(r.stdout, /^HEAD:f\nargs: /);
  assert.match(r.stdout, /-c core\.quotepath=off .*cat-file --batch$/m);
  assert.equal(r.stderr, "oops\n");
  fakeGit(`cat; exit 0`);
  const empty = await defaultGitRunner(["hash-object", "--stdin"], { cwd: dir });
  assert.deepEqual(empty, { code: 0, stdout: "", stderr: "" }, "no input: stdin closed empty");
});

test("the deadline kills the call's whole process group and settles it as a failure", async () => {
  fakeGit(`sleep 30 & echo $!; sleep 30`);
  const t0 = Date.now();
  // 1 s, not less: on macOS a fresh script's first exec can take over 300 ms
  // (one run of the darwin set killed it before its echo).
  const r = await defaultGitRunner(["log"], { cwd: dir, timeoutMs: 1000 });
  assert.ok(Date.now() - t0 < 3000, `settled in ${Date.now() - t0} ms`);
  assert.equal(r.code, 1, "a killed call is a failure: the caller refuses or fails the repository");
  assert.match(r.stderr, /killed at its 1000 ms deadline/);
  const bg = Number(r.stdout.trim());
  assert.ok(bg > 0);
  const end = Date.now() + 3000;
  while (alive(bg) && Date.now() < end) await new Promise((res) => setTimeout(res, 20));
  assert.equal(alive(bg), false, "the process the call put in the background was in its group and died");
});

test("a process the call started outside its group, holding the output, fails the call instead of hanging it", async () => {
  // A session (so a group) of its own through perl's POSIX::setsid:
  // util-linux's setsid(1) is Linux-only (macOS has none, and `setsid sleep
  // 30 &` there leaves no straggler at all).
  fakeGit(`perl -MPOSIX -e 'POSIX::setsid(); exec @ARGV' sleep 30 & echo $!; exit 0`);
  // The close grace is runChild's default (10 s): the call settles, as a
  // failure (its output may be incomplete), not never.
  const r = await defaultGitRunner(["rev-list"], { cwd: dir, timeoutMs: 60_000 });
  const s = Number(r.stdout.trim());
  try {
    assert.equal(r.code, 1);
    assert.match(r.stderr, /kept its output open/);
  } finally {
    try { process.kill(s, "SIGKILL"); } catch { /* gone */ }
  }
});

// ── One sandbox for many calls (git-session.ts, write-protection.md §8.5.3) ──
//
// The session's runner runs BARE here (no bubblewrap: `runnerCommand` starts
// node directly), so the protocol, the per-call rules and every failure path
// are proven with no privilege; the same runner inside the real sandbox is
// the kernel test (test/kernel/git-sandbox.test.ts).

const BARE: GitSessionOpts = {
  sandbox: () => ({ bwrap: "/unused/bwrap", flags: [] }),
  runnerCommand: () => ({ file: process.execPath, args: ["-e", GIT_SESSION_RUNNER_SOURCE] }),
  // The per-call path as this file runs it: no sandbox (MANDU_GIT_SANDBOX=0).
  perCall: (c) => perCallGitRunner(c, () => null),
  ptraceScope: () => 1,
};
const sessions: GitSession[] = [];
after(() => { for (const s of sessions) s.close(); });
function session(extra: Partial<GitSessionOpts> = {}): GitSession {
  const s = openGitSession({ ...BARE, ...extra });
  sessions.push(s);
  return s;
}
/** A runner that frames by hand (a broken or hostile runner). */
function fakeRunner(body: string): GitSessionOpts["runnerCommand"] {
  const src = `const f=(t,id,p)=>{const h=Buffer.alloc(9);h.writeUInt8(t,0);h.writeUInt32BE(id,1);h.writeUInt32BE(p.length,5);process.stdout.write(Buffer.concat([h,p]));};${body}`;
  return () => ({ file: process.execPath, args: ["-e", src] });
}
/** The last argument a fake git was given (the hardened ones come first). */
const LAST = `for a; do last=$a; done`;
const waitDead = async (pid: number): Promise<boolean> => {
  const end = Date.now() + 3000;
  while (alive(pid) && Date.now() < end) await new Promise((res) => setTimeout(res, 20));
  return !alive(pid);
};
/** Where a stand-in git that the runner's death leaves running writes its
 *  pid (`echo $$ > …` in its body). */
const pidFile = (name: string): string => join(dir, `${name}.pid`);
/** Kill the whole group of the stand-in git that wrote `pidFile(name)`, if
 *  it did, and wait for it to die. A BARE runner (no bubblewrap) has no pid
 *  namespace: SIGKILLed (close(), a crash) it cannot take its calls down
 *  with it, so the git it started (a group of its own) and that git's
 *  children run on. In the real sandbox they die with its pid namespace
 *  (test/kernel/git-sandbox.test.ts); here the test kills what it started,
 *  or it outlives the suite. */
async function killLeftGroup(name: string): Promise<void> {
  let pid: number;
  try { pid = Number(readFileSync(pidFile(name), "utf8").trim()); } catch { return; /* never started */ }
  rmSync(pidFile(name), { force: true });
  if (!(pid > 0)) return;
  try { process.kill(-pid, "SIGKILL"); } catch { /* gone */ }
  try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
  assert.ok(await waitDead(pid), `the stand-in git ${pid} died`);
}

test("a session answers byte for byte as the per-call runner: output, exit codes, stderr, input, env, paths, non-UTF-8 bytes", async () => {
  process.env["PATH"] = savedPath;
  const repo = mkdtempSync(join(dir, "repo-"));
  const env = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x" };
  const g = (...a: string[]): string => execFileSync("git", a, { cwd: repo, env, encoding: "utf8" });
  g("init", "-q");
  writeFileSync(join(repo, "f.txt"), "one\r\ntwo\n");
  writeFileSync(join(repo, "ünï cödé.txt"), "named\n");
  // Not UTF-8, and over a pipe's 64 KiB: decoded across chunk boundaries.
  writeFileSync(join(repo, "bin.dat"), Buffer.concat([Buffer.from([0xff, 0xfe, 0xc3]), Buffer.alloc(200_000, "é"), Buffer.from([0xe2, 0x82])]));
  g("add", ".");
  g("commit", "-qm", "one");
  writeFileSync(join(repo, "f.txt"), "three\n");
  g("commit", "-qam", "two");
  const tips = g("rev-list", "--all").trim();
  const calls: Array<[string[], { cwd: string; input?: string; env?: Record<string, string> }]> = [
    [["rev-parse", "--show-object-format", "--git-common-dir", "--git-path", "shallow"], { cwd: repo }],
    [["config", "-z", "--get-regexp", "^core\\."], { cwd: repo }],
    [["config", "--get", "no.such"], { cwd: repo }],
    [["rev-list", "--all", "--no-walk"], { cwd: repo }],
    [["ls-files", "-z", "-s"], { cwd: repo }],
    [["ls-files", "--", "ünï cödé.txt"], { cwd: repo }],
    [["cat-file", "-p", "HEAD:bin.dat"], { cwd: repo }],
    [["hash-object", "--stdin"], { cwd: repo, input: "hello\n" }],
    [["rev-list", "--no-walk", "--ignore-missing", "--stdin"], { cwd: repo, input: `${tips}\n${"0".repeat(40)}\n` }],
    [["log", "--format=%H %s", "--", "f.txt"], { cwd: repo }],
    [["show", "no-such-ref"], { cwd: repo }],
    [["rev-parse", "HEAD"], { cwd: dir, env: { GIT_DIR: join(repo, ".git") } }],
    [["rev-parse", "HEAD"], { cwd: join(dir, "no-such-dir") }],
  ];
  const s = session();
  const run = s.runner();
  const viaSession = await Promise.all(calls.map(([a, o]) => run(a, o)));
  for (let i = 0; i < calls.length; i++) {
    const [a, o] = calls[i]!;
    const want = await defaultGitRunner(a, o);
    const got = viaSession[i]!;
    if (o.cwd.endsWith("no-such-dir")) {
      // A missing cwd: the spawn fails in both, worded by whichever spawned.
      assert.deepEqual([want.code, got.code, got.stdout], [1, 1, ""], `${a.join(" ")}: a failure in both`);
      continue;
    }
    assert.deepEqual(got, want, `${a.join(" ")} (cwd ${o.cwd})`);
  }
  assert.ok(viaSession[6]!.stdout.length > 100_000 && viaSession[6]!.stdout.includes("�"), "the non-UTF-8 blob decoded the same way");
  assert.equal(viaSession[2]!.code, 1, "config's 'none set' is exit 1 in both, not a generic failure");
  assert.equal(viaSession[10]!.code, 128);
  assert.deepEqual([s.stats.sandboxes, s.stats.inSession, s.stats.perCall], [1, calls.length, 0]);
});

test("`binary: true` answers byte for byte (one character per byte) in a session and per call, and is its own shared-answer key", async () => {
  process.env["PATH"] = savedPath;
  const repo = mkdtempSync(join(dir, "repo-bin-"));
  const env = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x" };
  execFileSync("git", ["init", "-q"], { cwd: repo, env });
  // A tree's entries hold raw object ids; a blob over a pipe's 64 KiB with
  // bytes that are not UTF-8 crosses chunk boundaries.
  writeFileSync(join(repo, "bin.dat"), Buffer.concat([Buffer.from([0xff, 0xfe, 0xc3]), Buffer.alloc(150_000, 0xe9), Buffer.from([0xe2, 0x82])]));
  execFileSync("git", ["add", "."], { cwd: repo, env });
  execFileSync("git", ["commit", "-qm", "one"], { cwd: repo, env });
  const input = "HEAD^{tree}\nHEAD:bin.dat\n";
  const want = execFileSync("git", ["cat-file", "--batch"], { cwd: repo, env, input });
  const s = session();
  try {
    for (const [name, run] of [["session", s.runner()], ["per call", defaultGitRunner]] as const) {
      const r = await run(["cat-file", "--batch"], { cwd: repo, input, binary: true });
      assert.equal(r.code, 0, name);
      assert.ok(Buffer.from(r.stdout, "latin1").equals(want), `${name}: the answer's bytes, every one`);
      const text = await run(["cat-file", "--batch"], { cwd: repo, input });
      assert.ok(!Buffer.from(text.stdout, "latin1").equals(want), `${name}: without it the answer is decoded as UTF-8`);
    }
  } finally { s.close(); }
  const { sharedCallKey } = await import("../../src/git-shared-answers.js");
  assert.notEqual(sharedCallKey(["cat-file", "--batch"], { cwd: repo, binary: true }), sharedCallKey(["cat-file", "--batch"], { cwd: repo }));
});

test("a session passes argv and the environment exactly (no shell), and keeps concurrent calls apart", async () => {
  fakeGit(`${LAST}; case "$last" in d*) sleep "\${last#d}";; esac; printf '%s\\0' "$@"; env | LC_ALL=C sort`);
  const odd = ["a b", "'q'", "$(id)", "x\ny", "üé", "", "--", "*", "\\", "%s"];
  const run = session().runner();
  const want = await defaultGitRunner(odd, { cwd: dir, env: { GIT_DIR: "/x y", EXTRA: "1\n2" } });
  const got = await run(odd, { cwd: dir, env: { GIT_DIR: "/x y", EXTRA: "1\n2" } });
  assert.deepEqual(got, want);
  assert.ok(got.stdout.includes("$(id)\0x\ny\0"), "argv arrives as given");
  // Twenty at once, finishing out of order: each answer is its own call's.
  const delays = Array.from({ length: 20 }, (_, i) => `d0.${(i * 7) % 3}${i}`);
  const all = await Promise.all(delays.map((d) => run([d], { cwd: dir })));
  all.forEach((r, i) => {
    assert.equal(r.code, 0);
    assert.ok(r.stdout.split("\0").includes(delays[i]!), `call ${i} got its own answer`);
  });
});

test("a session's deadline kills that call's whole group, settles it as a failure, and the others run on in the same sandbox", async () => {
  fakeGit(`${LAST}; if [ "$last" = hang ]; then sleep 30 & echo $!; sleep 30; fi; echo "ok $last"`);
  const s = session();
  const run = s.runner();
  const t0 = Date.now();
  const [hung, ...others] = await Promise.all([
    run(["hang"], { cwd: dir, timeoutMs: 1000 }),
    run(["a"], { cwd: dir }), run(["b"], { cwd: dir }), run(["c"], { cwd: dir }),
  ]);
  assert.ok(Date.now() - t0 < 4000, `settled in ${Date.now() - t0} ms`);
  assert.equal(hung!.code, 1);
  assert.match(hung!.stderr, /killed at its 1000 ms deadline/);
  assert.ok(await waitDead(Number(hung!.stdout.trim())), "the process the call put in the background died with its group");
  assert.deepEqual(others.map((r) => [r.code, r.stdout.trim()]), [[0, "ok a"], [0, "ok b"], [0, "ok c"]]);
  assert.equal((await run(["d"], { cwd: dir })).stdout.trim(), "ok d", "the session still answers");
  assert.deepEqual([s.stats.sandboxes, s.stats.inSession, s.stats.perCall], [1, 5, 0]);
  assert.equal(s.stats.ended, undefined);
});

test("a session: an exit kills what the call left in its group (its sandbox went with it), and a signal is 128 + n as bubblewrap says", async () => {
  fakeGit(`${LAST}; if [ "$last" = term ]; then kill -TERM $$; fi; sleep 30 & echo $!; exit 0`);
  const run = session().runner();
  const t0 = Date.now();
  const r = await run(["bg"], { cwd: dir });
  assert.ok(Date.now() - t0 < 3000, `settled in ${Date.now() - t0} ms, not after the close grace`);
  assert.equal(r.code, 0);
  assert.ok(await waitDead(Number(r.stdout.trim())));
  assert.equal((await run(["term"], { cwd: dir })).code, 128 + 15);
  assert.equal(sandboxExitCode(null, "SIGKILL"), 137);
  assert.equal(sandboxExitCode(3, null), 3);
});

test("a session: a process a call started outside its group, holding its output, fails the call and ends the sandbox (calls in flight fail; later ones run per call)", async () => {
  fakeGit(`${LAST}; if [ "$last" = slow ]; then echo $$ > "${pidFile("escape-slow")}"; sleep 3; echo slow; exit 0; fi; if [ "$last" = escape ]; then perl -MPOSIX -e 'POSIX::setsid(); exec @ARGV' sleep 30 & echo $!; sleep 0.5; exit 0; fi; echo "ok $last"`);
  const s = session({ closeGraceMs: 300 });
  const run = s.runner();
  const [esc, slow] = await Promise.all([run(["escape"], { cwd: dir }), run(["slow"], { cwd: dir })]);
  try {
    assert.equal(esc.code, 1);
    assert.match(esc.stderr, /kept its output open/);
    assert.equal(slow.code, 1, "a call in flight when the sandbox ends fails: never a partial answer");
    assert.match(slow.stderr, /the git sandbox ended|kept its output open/);
    assert.match(s.stats.ended ?? "", /kept its output open/);
    const later = await run(["later"], { cwd: dir });
    assert.deepEqual([later.code, later.stdout.trim()], [0, "ok later"]);
    assert.equal(s.stats.perCall, 1, "after the sandbox ended, a call runs one sandbox of its own");
  } finally {
    try { process.kill(Number(esc.stdout.trim()), "SIGKILL"); } catch { /* gone */ }
    await killLeftGroup("escape-slow");
  }
});

test("a session: the runner dying mid-launch fails every call in flight (fail closed); later calls run per call", async () => {
  fakeGit(`${LAST}; case "$last" in die) kill -9 $PPID; exit 0;; slow) echo $$ > "${pidFile("die-slow")}"; sleep 2;; esac; echo "ok $last"`);
  const s = session();
  const run = s.runner();
  try {
    const [die, slow] = await Promise.all([run(["die"], { cwd: dir }), run(["slow"], { cwd: dir })]);
    assert.equal(die.code, 1);
    assert.equal(slow.code, 1);
    assert.match(slow.stderr, /the git sandbox ended/);
    assert.equal(slow.stdout, "", "no partial answer");
    const later = await run(["later"], { cwd: dir });
    assert.deepEqual([later.code, later.stdout.trim()], [0, "ok later"]);
    assert.deepEqual([s.stats.sandboxes, s.stats.perCall], [1, 1]);
  } finally {
    await killLeftGroup("die-slow");
  }
});

test("a session: a runner that never says it is ready ran nothing, so its calls run per call and succeed", async () => {
  fakeGit(`${LAST}; echo "ok $last"`);
  const s = session({ runnerCommand: () => ({ file: process.execPath, args: ["-e", "process.exit(3)"] }) });
  const run = s.runner();
  const got = await Promise.all([run(["a"], { cwd: dir }), run(["b"], { cwd: dir })]);
  assert.deepEqual(got.map((r) => [r.code, r.stdout.trim()]), [[0, "ok a"], [0, "ok b"]]);
  assert.deepEqual([s.stats.sandboxes, s.stats.inSession, s.stats.perCall], [1, 2, 2]);
  assert.match(s.stats.ended ?? "", /ended/);
  // A frame before `ready` is never taken as an answer either.
  const forged = session({ runnerCommand: fakeRunner(`f(1,1,Buffer.from("FORGED"));f(4,1,Buffer.from('{"code":0,"signal":null}'));setTimeout(()=>{},5000);`) });
  const r = await forged.runner()(["x"], { cwd: dir });
  assert.deepEqual([r.code, r.stdout.trim()], [0, "ok x"], "the call ran per call; the forged frame was dropped");
});

test("a session: an unreadable frame from the runner fails the call in flight, never a partial or made-up answer", async () => {
  fakeGit(`echo ok`);
  const s = session({ runnerCommand: fakeRunner(`f(6,0,Buffer.from("ready"));process.stdin.once("data",()=>{f(1,1,Buffer.from("partial"));f(99,1,Buffer.alloc(0));});setTimeout(()=>{},5000);`) });
  const r = await s.runner()(["x"], { cwd: dir });
  assert.equal(r.code, 1);
  assert.match(r.stderr, /unreadable frame/);
});

test("a session: close() fails the calls in flight and later ones, and its runner is gone", async () => {
  fakeGit(`echo $$ > "${pidFile("close")}"; sleep 30`);
  const s = session();
  const run = s.runner();
  const inFlight = run(["x"], { cwd: dir });
  try {
    // In flight: its git is running.
    for (const end = Date.now() + 5000; !existsSync(pidFile("close")) && Date.now() < end;) await new Promise((res) => setTimeout(res, 20));
    assert.ok(existsSync(pidFile("close")), "the call's git started");
    const pid = s.runnerPid;
    assert.ok(pid !== undefined);
    s.close();
    const r = await inFlight;
    assert.equal(r.code, 1);
    assert.match(r.stderr, /closed/);
    assert.equal((await run(["y"], { cwd: dir })).code, 1, "a closed session runs nothing");
    assert.ok(await waitDead(pid!));
  } finally {
    await killLeftGroup("close");
  }
});

test("a session: a call that writes, no sandbox, or Seatbelt runs per call; the runner command is the probe's bubblewrap and flags with nothing bound", async () => {
  const seen: string[] = [];
  const perCall = (): GitRunner => async (a) => { seen.push(a.join(" ")); return { code: 0, stdout: "", stderr: "" }; };
  const w = session({ perCall });
  await w.runner()(["pack-objects"], { cwd: dir, writable: [dir] });
  const none = session({ perCall, sandbox: () => null });
  await none.runner()(["none"], { cwd: dir });
  const sb = session({ perCall, sandbox: () => ({ sandboxExec: "/usr/bin/sandbox-exec", git: "/usr/bin/git" }) });
  await sb.runner()(["seatbelt"], { cwd: dir });
  assert.deepEqual(seen, ["pack-objects", "none", "seatbelt"]);
  assert.deepEqual([w.stats.sandboxes, none.stats.sandboxes, sb.stats.sandboxes], [0, 0, 0]);
  const flags = ["--unshare-user", "--unshare-pid", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"];
  const cmd = sessionRunnerCommand({ bwrap: "/usr/bin/bwrap", flags }, "/usr/bin/node");
  assert.equal(cmd.file, "/usr/bin/bwrap");
  const kept = ["--unshare-user", "--unshare-pid", "--ro-bind", "/", "/", "--dev", "/dev"];
  assert.deepEqual(cmd.args, [...kept, "--tmpfs", "/proc", "--remount-ro", "/proc", "--", "/usr/bin/node", "-e", GIT_SESSION_RUNNER_SOURCE],
    "the probe's flags, but an EMPTY read-only /proc after the root bind (never the host's showing through)");
  assert.deepEqual(cmd.args.slice(0, kept.length), gitCommand(["x"], { bwrap: "/usr/bin/bwrap", flags }).args.slice(0, kept.length), "gitCommand's flags otherwise");
  assert.ok(!cmd.args.includes("--proc") && !cmd.args.includes("--bind"), "no procfs, nothing read-write");
  assert.deepEqual(sessionSandboxFlags(["--ro-bind", "/", "/"]), ["--ro-bind", "/", "/", ...SESSION_PROC_FLAGS], "added where the probe had no --proc too");
  assert.match(GIT_SESSION_RUNNER_SOURCE, /spawn\("git", q\.args/, "the runner starts git and nothing else");
  assert.doesNotMatch(GIT_SESSION_RUNNER_SOURCE, /\/proc/, "the runner needs no /proc");
});

test("a session shares a sandbox only where Yama ptrace_scope is 1 or more; 0, absent or unreadable runs one sandbox per call", async () => {
  const seen: string[] = [];
  const perCall = (): GitRunner => async (a) => { seen.push(a.join(" ")); return { code: 0, stdout: "per-call", stderr: "" }; };
  for (const scope of [0, null]) {
    const s = session({ perCall, ptraceScope: () => scope });
    s.warm();
    const r = await s.runner()(["rev-parse"], { cwd: dir });
    assert.equal(r.stdout, "per-call");
    assert.deepEqual([s.stats.sandboxes, s.stats.inSession, s.stats.perCall], [0, 0, 1], `scope ${scope}: no shared sandbox`);
    assert.match(s.stats.perCallWhy ?? "", /ptrace_scope is (0|absent or unreadable)/);
  }
  assert.equal(seen.length, 2);
  for (const scope of [1, 2, 3]) assert.equal(sessionAllowed(scope), true);
  assert.equal(sessionAllowed(0), false);
  assert.equal(sessionAllowed(null), false);
  assert.equal(hostPtraceScope(() => "1\n"), 1);
  assert.equal(hostPtraceScope(() => "0\n"), 0);
  assert.equal(hostPtraceScope(() => "-1\n"), null);
  assert.equal(hostPtraceScope(() => ""), null);
  assert.equal(hostPtraceScope(() => { throw Object.assign(new Error("no Yama"), { code: "ENOENT" }); }), null, "no Yama in this kernel");
});

test("the launch's costs (launch-timings.ts): a call is one git; per call it is one sandbox unless none is made, in a session the sandbox is the session's one", async () => {
  fakeGit(`echo ok`);
  // Per call with no sandbox: a git, no sandbox.
  let c0 = gitCounts();
  assert.equal((await perCallGitRunner(undefined, () => null)(["status"], { cwd: dir })).code, 0);
  assert.deepEqual(gitCounts(), { git: c0.git + 1, sandboxes: c0.sandboxes });
  // Per call in a sandbox (a stand-in bubblewrap that runs what follows `--`): a git and its sandbox.
  const fakeBwrap = join(dir, "fake-bwrap");
  writeFileSync(fakeBwrap, `#!/bin/sh\nwhile [ "$1" != "--" ]; do shift; done\nshift\nexec "$@"\n`);
  chmodSync(fakeBwrap, 0o755);
  c0 = gitCounts();
  const r = await perCallGitRunner(undefined, () => ({ bwrap: fakeBwrap, flags: [] }))(["status"], { cwd: dir });
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(gitCounts(), { git: c0.git + 1, sandboxes: c0.sandboxes + 1 });
  // A session: three calls, one sandbox (its runner), whatever their order.
  c0 = gitCounts();
  const s = session();
  const run = s.runner();
  const rs = await Promise.all([run(["a"], { cwd: dir }), run(["b"], { cwd: dir }), run(["c"], { cwd: dir })]);
  assert.ok(rs.every((x) => x.code === 0), JSON.stringify(rs));
  assert.deepEqual(gitCounts(), { git: c0.git + 3, sandboxes: c0.sandboxes + 1 });
  assert.deepEqual([s.stats.sandboxes, s.stats.inSession], [1, 3], "the session's own stats agree");
  process.env["PATH"] = savedPath;
});

test("a session left open and idle does not keep the process alive", () => {
  const script = join(dir, "idle.mts");
  writeFileSync(script, [
    `import { openGitSession, GIT_SESSION_RUNNER_SOURCE } from ${JSON.stringify(join(process.cwd(), "src", "git-session.ts"))};`,
    `const s = openGitSession({ sandbox: () => ({ bwrap: "/unused", flags: [] }), runnerCommand: () => ({ file: process.execPath, args: ["-e", GIT_SESSION_RUNNER_SOURCE] }) });`,
    `const r = await s.runner()(["--version"], { cwd: "/" });`,
    `console.log(r.code === 0 ? "answered" : "failed " + r.stderr);`,
  ].join("\n"));
  process.env["PATH"] = savedPath;
  const r = spawnSync(process.execPath, ["--import", "tsx", script], { cwd: process.cwd(), encoding: "utf8", timeout: 20_000 });
  assert.equal(r.signal, null, "it exited on its own (not killed at the test's deadline)");
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /answered/);
});
