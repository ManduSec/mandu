/**
 * temp-repo — REAL git repo in a temp dir for the fs-sync test suite.
 *
 * The task mandates exercising the view-sync against REAL git (not a git mock)
 * with a MOCK arbiter. This helper creates an isolated git repo under os.tmpdir,
 * configures a deterministic identity, and returns the paths + a cleanup fn. The
 * view state base is a sibling temp dir so no state lands in the workspace.
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { ViewLayout } from "../../src/layout.js";
import { removeDir, tmpDir } from "./tmp-dir.js";

export interface TempRepo {
  /** HumanView path (the git repo working tree). */
  workspacePath: string;
  /** view state base (sibling temp dir; .mandu-style state lives here). */
  stateBase: string;
  cleanup: () => void;
}

function git(cwd: string, args: string[]): void {
  execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "fs-sync-test",
      GIT_AUTHOR_EMAIL: "fs-sync@test.local",
      GIT_COMMITTER_NAME: "fs-sync-test",
      GIT_COMMITTER_EMAIL: "fs-sync@test.local",
    },
  });
}

/**
 * Create a temp git repo. `seed` maps relative paths to file contents that are
 * committed as the initial HumanView state.
 */
export function makeTempRepo(seed: Record<string, string> = {}): TempRepo {
  // Removed by cleanup(), or at the latest when the process exits (tmp-dir.ts).
  const root = tmpDir("fs-sync-");
  const workspacePath = join(root, "workspace");
  const stateBase = join(root, "view-state");
  mkdirSync(workspacePath, { recursive: true });
  mkdirSync(stateBase, { recursive: true });

  git(workspacePath, ["init", "-q", "-b", "main"]);
  git(workspacePath, ["config", "user.name", "fs-sync-test"]);
  git(workspacePath, ["config", "user.email", "fs-sync@test.local"]);

  for (const [rel, content] of Object.entries(seed)) {
    writeFileSync(join(workspacePath, rel), content);
  }
  // Always create at least one commit so HEAD / branch ops work.
  if (Object.keys(seed).length === 0) {
    writeFileSync(join(workspacePath, ".gitkeep"), "");
  }
  git(workspacePath, ["add", "-A"]);
  git(workspacePath, ["commit", "-q", "-m", "seed: initial HumanView"]);

  return {
    workspacePath,
    stateBase,
    cleanup: () => {
      removeDir(root);
    },
  };
}

/** Run an arbitrary git command in the temp repo (test convenience). */
export function gitIn(cwd: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "fs-sync-test",
      GIT_AUTHOR_EMAIL: "fs-sync@test.local",
      GIT_COMMITTER_NAME: "fs-sync-test",
      GIT_COMMITTER_EMAIL: "fs-sync@test.local",
    },
  });
}

/**
 * Run a git command against the SHADOW substrate repo of a temp workspace
 * (fs-sync.md §3): GIT_DIR = the state dir's repo.git, GIT_WORK_TREE =
 * the workspace. This is where every [MDU-*] commit and the mdu-main /
 * mdu-trusted refs live; the workspace's own .git must stay untouched (assert
 * that with plain `gitIn`).
 */
export function gitInShadow(
  repo: Pick<TempRepo, "workspacePath" | "stateBase">,
  args: string[],
): string {
  const layout = new ViewLayout(repo.workspacePath, repo.stateBase);
  return execFileSync("git", args, {
    cwd: repo.workspacePath,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_DIR: layout.gitDir,
      GIT_WORK_TREE: repo.workspacePath,
    },
  });
}
