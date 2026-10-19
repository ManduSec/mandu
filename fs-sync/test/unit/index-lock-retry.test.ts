/**
 * index-lock-retry.test.ts — a git another process is running on the same
 * worktree holds its `index.lock`; fs-sync's commit-pair git calls wait for it
 * (bounded) instead of failing at once, and never delete a lock they did not
 * take (fs-sync.md §2.4a).
 *
 * Mandu-new test. REGRESSION ORIGIN (2026-10-04): the golden-path canary's
 * post-exit sweep failed once on CI with `…/worktrees/agentview/index.lock:
 * File exists`. The cause was the launcher's teardown SIGTERMing the eager
 * watcher's whole process group, git included (launcher fs-view.ts, fixed
 * there); this file covers the other half, a sibling git still running (the
 * agent's own `git status` in its AgentView), with a lock held by a separate
 * process and released while the call waits.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { INDEX_LOCK_RETRY, gitExecSync, mduCommit, stageFiles } from "../../src/git.js";
import { removeDir, tmpDir } from "../helpers/tmp-dir.js";

function repo(): { dir: string; lock: string } {
  const dir = tmpDir("fs-sync-lock-");
  const g = (...a: string[]): void => { execFileSync("git", a, { cwd: dir, stdio: "ignore" }); };
  g("init", "-q");
  g("config", "user.name", "fs-sync-test");
  g("config", "user.email", "fs-sync@test.local");
  writeFileSync(join(dir, "a.txt"), "a\n");
  g("add", "a.txt");
  g("commit", "-qm", "seed");
  return { dir, lock: join(dir, ".git", "index.lock") };
}

/** Hold `lock` from ANOTHER process (as a sibling git would) and release it
 *  after `ms`: the call under test blocks this thread while it waits. */
function holdLockFor(lock: string, ms: number): Promise<void> {
  writeFileSync(lock, "");
  const c = spawn("sh", ["-c", `sleep ${ms / 1000}; rm -f "$1"`, "sh", lock], { stdio: "ignore" });
  return new Promise((resolve) => c.on("exit", () => resolve()));
}

test("a lock a sibling releases: stage + commit wait for it and succeed", async () => {
  const { dir, lock } = repo();
  try {
    writeFileSync(join(dir, "agent-note.txt"), "hello-from-agent\n");
    const released = holdLockFor(lock, 400);
    stageFiles({ cwd: dir }, ["agent-note.txt"]);
    mduCommit({ cwd: dir }, { trusted: true, toolName: "launcher", files: ["agent-note.txt"] });
    await released;
    const files = gitExecSync(["ls-tree", "--name-only", "HEAD"], { cwd: dir }).stdout;
    assert.match(files, /agent-note\.txt/, "the write was committed once the lock was released");
    const subject = gitExecSync(["log", "-1", "--format=%s"], { cwd: dir }).stdout;
    assert.match(subject, /^\[MDU-TRUSTED\]/);
  } finally { removeDir(dir); }
});

test("a lock nobody releases (its git died holding it): the call fails as before after the bound, and the lock is left alone", () => {
  const { dir, lock } = repo();
  try {
    writeFileSync(lock, "");
    const t0 = Date.now();
    assert.throws(
      () => mduCommit({ cwd: dir }, { trusted: true, toolName: "launcher" }),
      /git commit failed: .*index\.lock': File exists/,
    );
    const waited = Date.now() - t0;
    const bound = INDEX_LOCK_RETRY.tries * INDEX_LOCK_RETRY.delayMs;
    assert.ok(waited >= bound * 0.8, `it waited for the bound (${waited} ms of ${bound})`);
    assert.ok(existsSync(lock), "Mandu never deletes a lock it did not take");
  } finally { removeDir(dir); }
});

test("any other git failure is not retried", () => {
  const { dir } = repo();
  try {
    const t0 = Date.now();
    const r = gitExecSync(["rev-parse", "--verify", "no-such-ref"], { cwd: dir });
    assert.ok(r.stderr.length > 0, "the failure's stderr is returned");
    assert.ok(Date.now() - t0 < INDEX_LOCK_RETRY.delayMs * 5, "returned without the lock retry's waits");
  } finally { removeDir(dir); }
});
