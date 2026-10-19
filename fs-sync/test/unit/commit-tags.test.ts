/**
 * Unit: the shadow-repo commit tags — `[MDU-*] mdu:` written today, the
 * original ADFI spelling still READ, the pre-2026-09-28 spellings not
 * (docs/design/integrity/fs-sync.md §3.7a).
 */

import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  LEGACY_TAG_NAMESPACES,
  TAG_NAMESPACE,
  mduCommit,
  mduHumanCommit,
  getCommitMessage,
  gitExecSync,
  parseMduCommitMessage,
  tagGrepArgs,
  type GitCtx,
} from "../../src/git.js";

const IDENT = {
  GIT_AUTHOR_NAME: "fs-sync-test",
  GIT_AUTHOR_EMAIL: "fs-sync@test.local",
  GIT_COMMITTER_NAME: "fs-sync-test",
  GIT_COMMITTER_EMAIL: "fs-sync@test.local",
};

function tempRepo(): { dir: string; git: (args: string[]) => string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-tags-"));
  const git = (args: string[]) =>
    execFileSync("git", args, { cwd: dir, encoding: "utf8", env: { ...process.env, ...IDENT } });
  git(["init", "-q", "-b", "main"]);
  return { dir, git, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("the current namespace is MDU; ADFI is read-only legacy", () => {
  assert.equal(TAG_NAMESPACE, "MDU");
  assert.deepEqual([...LEGACY_TAG_NAMESPACES], ["ADFI"]);
  assert.deepEqual(tagGrepArgs("UNTRUSTED"), ["--grep=[MDU-UNTRUSTED]", "--grep=[ADFI-UNTRUSTED]"]);
});

test("parseMduCommitMessage reads every namespace, current and legacy", () => {
  for (const [ns, body] of [["MDU", "mdu"], ["ADFI", "adfi"]] as const) {
    const t = parseMduCommitMessage(`[${ns}-TRUSTED] ${body}: tool=Write callId=c1 run=r1 files=a.md`);
    assert.deepEqual(t, { trusted: true, toolName: "Write", callId: "c1", runId: "r1" }, ns);
    const u = parseMduCommitMessage(`[${ns}-UNTRUSTED] ${body}: tool=Read callId=c2 run=r1`);
    assert.equal(u?.trusted, false, ns);
    const h = parseMduCommitMessage(`[${ns}-HUMAN] ${body}: source=human files=n.md promoted=none`);
    assert.equal(h?.human, true, ns);
  }
  assert.equal(parseMduCommitMessage("chore: unrelated"), null);
  // The retired pre-2026-09-28 namespaces are not read.
  assert.equal(parseMduCommitMessage("[DV-TRUSTED] dv: tool=Write callId=c1 run=r1 files=a.md"), null);
});

test("new commits are written in the MDU namespace, and the legacy grep finds ADFI ones (real git)", () => {
  const repo = tempRepo();
  try {
    const ctx: GitCtx = { cwd: repo.dir, env: IDENT };
    writeFileSync(join(repo.dir, "a.md"), "alpha\n");
    repo.git(["add", "a.md"]);
    mduCommit(ctx, { trusted: false, toolName: "Write", callId: "c1", runId: "r1", files: ["a.md"] });
    const head = repo.git(["rev-parse", "HEAD"]).trim();
    assert.match(getCommitMessage(ctx, head), /^\[MDU-UNTRUSTED\] mdu: tool=Write callId=c1 run=r1/);

    // An older shadow repo: one commit in the legacy namespace.
    writeFileSync(join(repo.dir, "c.md"), "charlie\n");
    repo.git(["add", "c.md"]);
    repo.git(["commit", "-q", "-m", "[ADFI-UNTRUSTED] adfi: tool=Write callId=c3 run=r1 files=c.md"]);

    const { stdout } = gitExecSync(["log", "--fixed-strings", "--reverse", "--format=%s", ...tagGrepArgs("UNTRUSTED")], ctx);
    const subjects = stdout.trim().split("\n");
    assert.equal(subjects.length, 2, `both namespaces found:\n${stdout}`);
    assert.deepEqual(subjects.map((s) => parseMduCommitMessage(s)?.callId), ["c1", "c3"]);

    writeFileSync(join(repo.dir, "n.md"), "note\n");
    repo.git(["add", "n.md"]);
    mduHumanCommit(ctx, { files: ["n.md"], promotedSymbols: [] });
    const human = repo.git(["log", "-1", "--format=%s"]).trim();
    assert.match(human, /^\[MDU-HUMAN\] mdu: source=human/);
  } finally {
    repo.cleanup();
  }
});
