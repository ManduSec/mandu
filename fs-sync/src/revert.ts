/**
 * revert — full-state filesystem rollback over the Mandu commit history.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/dualview-revert.ts
 *   Purpose: enumerate write cycles (T/U commit pairs), plan a revert (files
 *   kept/removed), and execute the 3-command full-state reset (reset HEAD to
 *   U(N), point mdu-trusted at T(N), reset the AgentView worktree). Design:
 *   docs/adfi-reference/design/revert.md.
 *
 * Adaptation for Mandu (OpenClaw coupling stripped):
 *   - Takes a `ViewLayout` and operates on its SHADOW substrate repo +
 *     AgentView worktree (fs-sync.md §3.3), replacing the
 *     `getWorktreePath(gitRoot)` dualview import. No symbol-table interaction
 *     (the revert design notes the symbol table is append-only and unaffected —
 *     abandoned symbols are harmless), so the arbiter is not needed here.
 *   - Logic is otherwise unchanged: revert walks the [MDU-UNTRUSTED] commits on
 *     the shadow main line (`mdu-main`) and the [MDU-TRUSTED] commits on
 *     mdu-trusted. The `reset --hard` restores the WORKSPACE FILES to U(N) but
 *     moves only shadow refs — from the user's own repo's perspective a revert
 *     is ordinary working-tree modification, never a ref move (their commits
 *     are never dragged into a reflog).
 */

import { existsSync } from "node:fs";
import { join } from "node:path";

import {
  agentViewRef,
  getWorktreePath,
  type GitCtx,
  gitExecSync,
  parseMduCommitMessage,
  type ParsedMduCommit,
  shadowCtx,
  tagGrepArgs,
} from "./git.js";
import type { ViewLayout } from "./layout.js";

export interface WriteCycle {
  /** 1-based write number (oldest = 1). */
  number: number;
  /** The [MDU-UNTRUSTED] commit hash on the main branch. */
  untrustedCommit: string;
  /** The [MDU-TRUSTED] commit hash on the main branch (parent of untrusted). */
  trustedCommit: string;
  meta: ParsedMduCommit;
  /** Files affected (from files= metadata, if present). */
  files: string[];
  timestamp: string;
}

export interface RevertPlan {
  target: WriteCycle;
  abandonedCount: number;
  filesKept: string[];
  filesRemoved: string[];
}

/** List all write cycles, oldest-first, 1-based. */
export function listWriteCycles(layout: ViewLayout): WriteCycle[] {
  const ctx: GitCtx = shadowCtx(layout);
  // Multiple --grep are OR'd by git, so this matches the current
  // [MDU-UNTRUSTED] tag and the legacy ADFI namespace (tagGrepArgs).
  const { stdout } = gitExecSync(
    ["log", "--fixed-strings", "--reverse", "--format=%H|%aI", ...tagGrepArgs("UNTRUSTED")],
    ctx,
  );
  if (!stdout.trim()) return [];

  const lines = stdout.trim().split("\n").filter(Boolean);
  const cycles: WriteCycle[] = [];

  for (let i = 0; i < lines.length; i++) {
    const [hash, timestamp] = lines[i]!.split("|");
    if (!hash) continue;

    const { stdout: parentOut } = gitExecSync(["rev-parse", `${hash}~1`], ctx);
    const trustedCommit = parentOut.trim();

    const { stdout: msgOut } = gitExecSync(["log", "-1", "--format=%B", hash], ctx);
    const meta = parseMduCommitMessage(msgOut.trim());
    if (!meta) continue;

    const filesMatch = msgOut.match(/files=([^\s]+)/);
    const files = filesMatch ? filesMatch[1]!.split(",") : [];

    cycles.push({ number: i + 1, untrustedCommit: hash, trustedCommit, meta, files, timestamp: timestamp ?? "" });
  }

  return cycles;
}

/** Find a specific write cycle by number (1-based). */
export function findWriteCycleByNumber(layout: ViewLayout, n: number): WriteCycle {
  const cycles = listWriteCycles(layout);
  if (n < 1 || n > cycles.length) {
    throw new Error(`Write #${n} not found (${cycles.length} write cycles exist)`);
  }
  return cycles[n - 1]!;
}

/** Compute what a revert to write cycle N would do, without executing it. */
export function planRevert(layout: ViewLayout, targetNumber: number): RevertPlan {
  const ctx: GitCtx = shadowCtx(layout);
  const cycles = listWriteCycles(layout);
  if (targetNumber < 1 || targetNumber > cycles.length) {
    throw new Error(`Write #${targetNumber} not found (${cycles.length} write cycles exist)`);
  }

  const target = cycles[targetNumber - 1]!;
  const abandonedCount = cycles.length - targetNumber;

  const { stdout: targetFiles } = gitExecSync(
    ["ls-tree", "-r", "--name-only", target.untrustedCommit],
    ctx,
  );
  const filesKept = targetFiles.trim().split("\n").filter((f) => f && f !== ".gitkeep");

  const { stdout: currentFiles } = gitExecSync(["ls-tree", "-r", "--name-only", "HEAD"], ctx);
  const currentSet = new Set(currentFiles.trim().split("\n").filter(Boolean));

  const keptSet = new Set(filesKept);
  const filesRemoved = [...currentSet].filter((f) => !keptSet.has(f) && f !== ".gitkeep");

  return { target, abandonedCount, filesKept, filesRemoved };
}

/**
 * Revert the filesystem to the state after write cycle N. Full-state rollback:
 *   1. git reset --hard U(N) on the shadow main line (restores workspace FILES;
 *      the user's own repo sees only working-tree modification, no ref moves)
 *   2. point mdu-trusted at the N-th [MDU-TRUSTED] commit
 *   3. reset the AgentView worktree to mdu-trusted
 * Abandoned commits remain in the shadow repo's reflog.
 */
export function revertToWriteCycle(layout: ViewLayout, targetNumber: number): RevertPlan {
  const ctx: GitCtx = shadowCtx(layout);
  const plan = planRevert(layout, targetNumber);

  const { stderr: resetErr } = gitExecSync(["reset", "--hard", plan.target.untrustedCommit], ctx);
  if (resetErr && resetErr.includes("fatal:")) {
    throw new Error(`git reset failed: ${resetErr.trim()}`);
  }

  const ref = agentViewRef(ctx);
  const { stdout: trustedLog } = gitExecSync(
    ["log", "--fixed-strings", "--reverse", "--format=%H", ...tagGrepArgs("TRUSTED"), ref],
    ctx,
  );
  const trustedCommits = trustedLog.trim().split("\n").filter(Boolean);
  if (targetNumber >= 1 && targetNumber <= trustedCommits.length) {
    const targetTrustedCommit = trustedCommits[targetNumber - 1]!;
    gitExecSync(["update-ref", `refs/heads/${ref}`, targetTrustedCommit], ctx);
  }

  const wtPath = getWorktreePath(layout);
  if (existsSync(join(wtPath, ".git"))) {
    gitExecSync(["reset", "--hard", ref], { cwd: wtPath });
  }

  return plan;
}
