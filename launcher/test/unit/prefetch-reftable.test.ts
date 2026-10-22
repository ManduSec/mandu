/**
 * Unit: the history prefetch's fingerprint over a REFTABLE repository
 * (twin-prefetch.ts `stateFingerprint`; a security fix, 2026-10-21;
 * confidentiality.md §7.2a "The prefetch"): a linked worktree's HEAD and its
 * own refs live in its OWN reftable/, and moving them changes the
 * fingerprint. Needs a git that can make a reftable repository (2.45): the
 * PATH's, or the CI image's own build (test/lib/reftable-git.ts); else it
 * skips with the reason. Its end-to-end form: test/component/
 * prefetch-reftable-worktree.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultGitRunner, RepoReads } from "../../src/git-object-twins.js";
import { stateFingerprint } from "../../src/twin-prefetch.js";
import { useReftableGit } from "../lib/reftable-git.js";
import { stateAxes } from "../axes.js";

// Before any git call of the file: the production runner resolves git once.
const noReftable = useReftableGit();

stateAxes("secrets"); // the confidentiality axis is what the object twins serve

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...args: string[]): string => execFileSync("git", args, { cwd, encoding: "utf8", env: { ...ENV, PATH: process.env["PATH"] } });

/** A reftable repository (`git init --ref-format=reftable`, git 2.45+) with
 *  one commit and a linked worktree, or null when this git cannot make one. */
function reftableRepo(tmp: string): { ws: string; wt: string; c1: string } | null {
  const ws = join(tmp, "rt");
  try {
    git(tmp, "init", "-q", "--ref-format=reftable", "-b", "main", ws);
  } catch {
    return null;
  }
  writeFileSync(join(ws, "README"), "readme\n");
  git(ws, "add", ".");
  git(ws, "commit", "-qm", "one");
  const wt = join(tmp, "rt-wt");
  git(ws, "worktree", "add", "-q", "--detach", wt);
  return { ws, wt, c1: git(ws, "rev-parse", "HEAD").trim() };
}

test("stateFingerprint, reftable (security fix 2026-10-21): a linked worktree's HEAD and own refs moved in its reftable change it", { skip: noReftable ?? false }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-prefetch-rt-"));
  try {
    const r = reftableRepo(tmp);
    if (r === null) { t.skip("this git cannot make a reftable repository"); return; }
    assert.ok(existsSync(join(r.ws, ".git", "worktrees", "rt-wt", "reftable", "tables.list")), "the worktree keeps its own reftable");
    git(r.ws, "commit", "-q", "--allow-empty", "-m", "two");
    const c2 = git(r.ws, "rev-parse", "HEAD").trim();
    const facts = await new RepoReads(defaultGitRunner).factsOf(r.ws);
    const fp = async (): Promise<string> => (await stateFingerprint([r.ws, r.wt], facts))!.digest;
    let last = await fp();
    assert.equal(await fp(), last, "stable");
    // Plumbing that writes only the worktree's own reftable (no index, no
    // object, nothing in the common dir): what the fingerprint missed.
    for (const [what, args] of [
      ["the worktree's HEAD moved", ["update-ref", "--no-deref", "HEAD", c2]],
      ["a per-worktree ref (refs/bisect) written", ["update-ref", "refs/bisect/bad", r.c1]],
      ["a per-worktree ref (refs/worktree) written", ["update-ref", "refs/worktree/kept", c2]],
    ] as const) {
      git(r.wt, ...args);
      const now = await fp();
      assert.notEqual(now, last, what);
      last = now;
    }
    assert.equal(git(r.ws, "rev-parse", "HEAD").trim(), c2, "the main HEAD is untouched by those");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
