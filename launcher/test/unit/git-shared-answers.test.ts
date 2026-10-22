/**
 * git-shared-answers — the launch's one git question asked once
 * (git-shared-answers.ts; confidentiality.md §7.2a "The same question
 * once"), against a scripted runner:
 *
 *   - identical concurrent or settled calls start one call; any difference
 *     in arguments, work tree, stdin or environment starts its own; a call
 *     that writes is never shared; after `close` nothing is;
 *   - each caller keeps its own deadline: joining a longer call it is cut
 *     off at its own (the runner's cut-off shape), joining a shorter one it
 *     takes only a success and asks a failure again;
 *   - a failure reaches every caller as a failure (the answer is the call's);
 *   - a production base keeps the wrapper production (the step's `git
 *     version` from the probe).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { GitRun, GitRunner } from "../../src/git-object-twins.js";
import { shareGitAnswers, sharedCallKey } from "../../src/git-shared-answers.js";
import { isProductionGitRunner, openGitSession } from "../../src/git-session.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the runner serves the confidentiality axis's history step

interface Pending { args: string[]; opts: Parameters<GitRunner>[1]; resolve: (r: GitRun) => void }

/** A base runner whose calls settle when the test says. */
function scripted(): { base: GitRunner; calls: Pending[] } {
  const calls: Pending[] = [];
  const base: GitRunner = (args, opts) => new Promise((resolve) => { calls.push({ args, opts, resolve }); });
  return { base, calls };
}

const ok = (stdout: string): GitRun => ({ code: 0, stdout, stderr: "" });
const tick = (): Promise<void> => new Promise((r) => setImmediate(r));

test("an identical call is started once, concurrent or settled; any other difference starts its own", async () => {
  const { base, calls } = scripted();
  const s = shareGitAnswers(base);
  const a = s.runner(["rev-list", "--all", "--no-walk"], { cwd: "/r" });
  const b = s.runner(["rev-list", "--all", "--no-walk"], { cwd: "/r" });
  await tick();
  assert.equal(calls.length, 1, "joined while in flight");
  calls[0]!.resolve(ok("aaaa\n"));
  assert.deepEqual(await a, ok("aaaa\n"));
  assert.deepEqual(await b, ok("aaaa\n"));
  assert.deepEqual(await s.runner(["rev-list", "--all", "--no-walk"], { cwd: "/r" }), ok("aaaa\n"), "settled: shared");
  assert.equal(calls.length, 1);
  // Each of these differs in one thing: its own call.
  const others = [
    s.runner(["rev-list", "--all"], { cwd: "/r" }),
    s.runner(["rev-list", "--all", "--no-walk"], { cwd: "/other" }),
    s.runner(["rev-list", "--all", "--no-walk"], { cwd: "/r", input: "x\n" }),
    s.runner(["rev-list", "--all", "--no-walk"], { cwd: "/r", env: { GIT_DIR: "/s" } }),
  ];
  await tick();
  assert.equal(calls.length, 5);
  for (const c of calls.slice(1)) c.resolve(ok(""));
  await Promise.all(others);
  assert.deepEqual(s.stats, { started: 5, shared: 2 });
  assert.equal(sharedCallKey(["a"], { cwd: "/r", env: { B: "1", A: "2" } }), sharedCallKey(["a"], { cwd: "/r", env: { A: "2", B: "1" } }), "env order is not a difference");
});

test("a call that writes is never shared, and after close nothing is", async () => {
  const { base, calls } = scripted();
  const s = shareGitAnswers(base);
  const w1 = s.runner(["pack-objects", "p"], { cwd: "/r", writable: ["/cache"] });
  const w2 = s.runner(["pack-objects", "p"], { cwd: "/r", writable: ["/cache"] });
  await tick();
  assert.equal(calls.length, 2);
  calls[0]!.resolve(ok("")); calls[1]!.resolve(ok(""));
  await Promise.all([w1, w2]);
  const a = s.runner(["ls-files", "-s", "-z", "--", ".env"], { cwd: "/r" });
  await tick();
  calls[2]!.resolve(ok("first"));
  assert.equal((await a).stdout, "first");
  s.close();
  const b = s.runner(["ls-files", "-s", "-z", "--", ".env"], { cwd: "/r" });
  await tick();
  assert.equal(calls.length, 4, "closed: the call is asked afresh (the check after the agent exits)");
  calls[3]!.resolve(ok("after"));
  assert.equal((await b).stdout, "after");
});

test("a failure reaches every caller as a failure: a joiner with a deadline as short gets it, a longer one asks again and fails itself", async () => {
  const { base, calls } = scripted();
  const s = shareGitAnswers(base);
  const fail: GitRun = { code: 128, stdout: "", stderr: "fatal: bad object deadbeef" };
  // The step (120 s) first, the watch (5 s) joins: the watch gets the
  // step's failure, as its own call would have failed.
  const step = s.runner(["rev-list", "--all", "--no-walk"], { cwd: "/r" });
  const watch = s.runner(["rev-list", "--all", "--no-walk"], { cwd: "/r", timeoutMs: 5000 });
  await tick();
  assert.equal(calls.length, 1);
  calls[0]!.resolve(fail);
  assert.deepEqual(await step, fail);
  assert.deepEqual(await watch, fail);

  // The watch (5 s) first, the step (120 s) joins: a failed answer is not
  // taken (it may be a cut-off the step would outlive); the step asks again.
  const s2 = shareGitAnswers(base);
  const w = s2.runner(["ls-files", "-s", "-z", "--", ".env"], { cwd: "/r", timeoutMs: 5000 });
  const st = s2.runner(["ls-files", "-s", "-z", "--", ".env"], { cwd: "/r" });
  await tick();
  assert.equal(calls.length, 2);
  calls[1]!.resolve({ code: 1, stdout: "", stderr: "killed at its 5000 ms deadline" });
  assert.equal((await w).code, 1);
  await tick();
  assert.equal(calls.length, 3, "the step asked under its own deadline");
  assert.equal(calls[2]!.opts.timeoutMs, undefined);
  calls[2]!.resolve(fail);
  assert.deepEqual(await st, fail, "and sees its own failure");

  // The watch first, the step joins, the watch's call succeeds: shared.
  const s3 = shareGitAnswers(base);
  const w3 = s3.runner(["ls-files", "-s", "-z", "--", ".env"], { cwd: "/r", timeoutMs: 5000 });
  const st3 = s3.runner(["ls-files", "-s", "-z", "--", ".env"], { cwd: "/r" });
  await tick();
  calls[3]!.resolve(ok("100644 abc 0\t.env\0"));
  assert.equal((await w3).stdout, (await st3).stdout);
  assert.equal(calls.length, 4);
});

test("joining a longer call, a caller is cut off at its own deadline (the runner's cut-off answer) while the call goes on", async () => {
  const { base, calls } = scripted();
  const s = shareGitAnswers(base);
  const step = s.runner(["rev-list", "--all", "--no-walk"], { cwd: "/r" });
  const t0 = Date.now();
  const watch = await s.runner(["rev-list", "--all", "--no-walk"], { cwd: "/r", timeoutMs: 50 });
  assert.ok(Date.now() - t0 >= 45);
  assert.equal(watch.code, 1);
  assert.match(watch.stderr, /killed at its 50 ms deadline/);
  calls[0]!.resolve(ok("bbbb\n"));
  assert.deepEqual(await step, ok("bbbb\n"), "the longer caller's call was not cut");
});

test("a production base keeps the wrapper production; another base does not", () => {
  const session = openGitSession();
  try {
    assert.equal(isProductionGitRunner(shareGitAnswers(session.runner()).runner), true);
    assert.equal(isProductionGitRunner(shareGitAnswers(scripted().base).runner), false);
  } finally {
    session.close();
  }
});
