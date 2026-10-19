/**
 * git — git operation wrappers + AgentView worktree management for the `ViewSync`.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/dualview-git.ts
 *   Purpose: gitExec(Sync), changed-file scan, the [MDU-TRUSTED]/[MDU-UNTRUSTED]/
 *   [MDU-HUMAN] commit helpers + parser, the mdu-trusted worktree lifecycle
 *   (init/reset/remove + the trusted-only ref advance), the mkdir commit lock,
 *   the conflicts.log writer, path rewrite, and a `git blame` helper.
 *
 * Adaptation for Mandu (OpenClaw coupling stripped):
 *   - The reference imported workspace-path helpers from `./adfi-dualview.js`.
 *     fs-sync threads a `ViewLayout` (src/layout.ts) explicitly instead, so
 *     state placement is caller-controlled (per-scope for the fs-supervisor, a
 *     temp dir for tests) rather than a homedir() default.
 *   - PinchBench-specific comments retained where the *logic* still matters
 *     (defensive .git/info creation, stale-worktree cleanup) since those guard
 *     real races; the bench name is just illustrative.
 *   - `addBlame()` is NEW (small): the reference re-symbolization design names
 *     `git blame` (docs/adfi-reference/design/human-edit-policy.md, plan §5) but
 *     adfi-human-edit.ts compared resolved values rather than calling blame
 *     directly. We expose blame so the human-edit reconciler can attribute
 *     changed regions to commits (and skip [MDU-HUMAN] re-touches). No symbol
 *     logic here.
 */

import { execFile, spawnSync } from "node:child_process";
import {
  appendFileSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  rmdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import { dirname, join, relative } from "node:path";

import type { ViewLayout } from "./layout.js";
import { hardenedGitArgs, hardenedGitEnv } from "./hardened-git.js";

// ─────────────────────────────────────────────────────────────────────────────
// Exec wrappers
// ─────────────────────────────────────────────────────────────────────────────

export interface ChangedFile {
  status: string;
  path: string;
}

export interface MduCommitOpts {
  trusted: boolean;
  toolName: string;
  callId?: string;
  runId?: string;
  files?: string[];
}

export interface ParsedMduCommit {
  trusted: boolean;
  toolName: string;
  callId: string;
  runId: string;
  /** True if this is a human-edit commit ([MDU-HUMAN]). */
  human?: boolean;
  /** Symbols promoted (obsoleted) by this human edit. */
  promotedSymbols?: string[];
}

export interface GitExecResult {
  stdout: string;
  stderr: string;
  code: number;
}

export interface GitExecSyncResult {
  stdout: string;
  stderr: string;
}

export interface GitExecOpts {
  cwd: string;
  env?: Record<string, string>;
}

/**
 * A git execution context — where a command runs and which repo it addresses.
 * Two contexts exist per `ViewSync` (fs-sync.md §3.3):
 *   - the SHADOW context (`shadowCtx`): cwd = the workspace, GIT_DIR = the
 *     state dir's `repo.git`, GIT_WORK_TREE = the workspace — every substrate
 *     op (status/stage/commit/blame/revert/branch/worktree admin) runs here and
 *     NEVER touches the user's own `.git`;
 *   - the AGENTVIEW context: cwd = the agentview worktree (its `.git` file
 *     points into `repo.git/worktrees/`), no env.
 */
export type GitCtx = GitExecOpts;

/** The shadow-substrate context for a layout (see `GitCtx`). */
export function shadowCtx(layout: ViewLayout): GitCtx {
  return {
    cwd: layout.humanPath,
    env: { GIT_DIR: layout.gitDir, GIT_WORK_TREE: layout.humanPath },
  };
}

/**
 * Every fs-sync git call runs HARDENED (hardened-git.ts, docs/design/
 * write-protection.md §8): the program-starting config keys git knows forced off
 * (fsmonitor, hooks, signing and signature checks, transports, auto gc and
 * maintenance, submodule recursion), no pager, and an environment with no
 * inherited `GIT_*` (the context's own GIT_DIR / GIT_WORK_TREE go back on
 * top). What `-c` cannot reach is a driver the substrate's config names by a
 * free name (filter, textconv, merge): in `full` mode the agent can write
 * the shadow `repo.git` (a home carve-out), so that residual is stated in
 * write-protection.md §8.6 and protection-modes.md §10's ledger (the axis is frozen).
 */
export function gitExec(
  args: string[],
  { cwd, env }: GitExecOpts = { cwd: "." },
): Promise<GitExecResult> {
  return new Promise((resolve, reject) => {
    execFile(
      "git",
      hardenedGitArgs(args),
      { cwd, env: hardenedGitEnv(process.env, env), maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err && err.killed) return reject(err);
        resolve({
          stdout: stdout ?? "",
          stderr: stderr ?? "",
          code: ((err as NodeJS.ErrnoException)?.code as unknown as number) ?? 0,
        });
      },
    );
  });
}

/**
 * The failure git reports when another git holds the index lock (the only
 * failure gitExecSync retries). Every command that writes the index takes the
 * lock before it changes anything, so a call that failed on it did nothing
 * and is safe to run again.
 */
const INDEX_LOCK_BUSY = /Unable to create '[^']*index\.lock': File exists/;
/** The retry bound on a busy index lock: about 2 s, longer than any git a
 *  sibling runs on a Mandu worktree (the agent's own `git status` in its
 *  AgentView, an fs-sync process ending). A lock still there after it is a
 *  stale one (its git died holding it) and the call fails as before: Mandu
 *  never deletes a lock it did not take (fs-sync.md §2.4a). */
export const INDEX_LOCK_RETRY = { tries: 20, delayMs: 100 };

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export function gitExecSync(
  args: string[],
  { cwd, env }: GitExecOpts = { cwd: "." },
): GitExecSyncResult {
  for (let attempt = 1; ; attempt++) {
    const r = spawnSync("git", hardenedGitArgs(args), {
      cwd,
      env: hardenedGitEnv(process.env, env),
      maxBuffer: 10 * 1024 * 1024,
      encoding: "utf8",
    });
    const failed = r.error !== undefined || r.status !== 0;
    const stderr = r.stderr ?? "";
    if (failed && attempt < INDEX_LOCK_RETRY.tries && INDEX_LOCK_BUSY.test(stderr)) {
      sleepSync(INDEX_LOCK_RETRY.delayMs);
      continue;
    }
    // git's stderr reaches ours, as it did when the child inherited it.
    if (stderr) process.stderr.write(stderr);
    return { stdout: r.stdout ?? "", stderr: failed ? stderr : "" };
  }
}

/** Discover the git root from a starting directory. */
export function findGitRoot(startDir: string): string {
  const { stdout } = gitExecSync(["rev-parse", "--show-toplevel"], { cwd: startDir });
  const root = stdout.trim();
  if (!root) throw new Error(`Not a git repository: ${startDir}`);
  return root;
}

function parsePorcelain(stdout: string): ChangedFile[] {
  const records = stdout.split("\0");
  const files: ChangedFile[] = [];
  for (let i = 0; i < records.length; i++) {
    const record = records[i]!;
    if (!record) continue;
    const status = record.slice(0, 2).trim();
    files.push({ status, path: record.slice(3) });
    // Porcelain -z puts the destination first, then a separate source path.
    if (/[RC]/.test(status)) i++;
  }
  return files;
}

/** NUL delimiters preserve Unicode, whitespace, quotes and newlines literally. */
export function getTrackedFiles(ctx: GitCtx): string[] {
  const { stdout } = gitExecSync(["ls-files", "-z"], ctx);
  return stdout.split("\0").filter(Boolean);
}

/**
 * Get changed files via `git status --porcelain` in a git context.
 *
 * `-uall` IS LOAD-BEARING, not tidiness. Git's default (`-unormal`) COLLAPSES an
 * untracked directory into a single `?? subdir/` entry instead of listing the
 * files inside it. Every consumer of this list treats an entry as a FILE:
 * `syncToHuman` re-symbolizes each one with `readFileSync` before the
 * [MDU-TRUSTED] commit, so a collapsed directory entry threw
 * `EISDIR: illegal operation on a directory` and killed the whole sync (found
 * 2026-08-06 by the OpenClaw fsSync e2e scenario, whose agent creates a
 * subdirectory in its CWD; Claude Code's scenarios happened never to).
 *
 * The fix must be EXPANSION, not skipping directories. `git add -- subdir/`
 * stages the files inside quite happily, so a "skip anything that isn't a file"
 * patch would leave those files staged into the AgentView snapshot WITHOUT the
 * step-0 re-symbolization — raw untrusted bytes committed into the view whose
 * entire contract is that it holds symbols. A crash is a loud failure; that
 * would have been a silent one.
 */
export function getChangedFiles(ctx: GitCtx): ChangedFile[] {
  const { stdout } = gitExecSync(["status", "--porcelain", "-z", "-uall"], ctx);
  return parsePorcelain(stdout);
}

/** Stage specific files. */
export function stageFiles(ctx: GitCtx, filePaths: string[]): void {
  if (filePaths.length === 0) return;
  gitExecSync(["add", "--", ...filePaths], ctx);
}

/** Commit with Mandu file-tracking metadata. */
export function mduCommit(
  ctx: GitCtx,
  { trusted, toolName, callId, runId, files }: MduCommitOpts,
): void {
  const tag = trusted ? "[MDU-TRUSTED]" : "[MDU-UNTRUSTED]";
  const filesMeta = files && files.length > 0 ? ` files=${files.join(",")}` : "";
  const msg = `${tag} mdu: tool=${toolName || "unknown"} callId=${callId || "none"} run=${runId || "none"}${filesMeta}`;
  const flags = trusted ? [] : ["--no-verify"];
  const { stderr } = gitExecSync(["commit", "-m", msg, "--allow-empty", ...flags], ctx);
  if (stderr && (stderr.includes("fatal:") || stderr.includes("error:"))) {
    throw new Error(`git commit failed: ${stderr.trim()}`);
  }
}

/** Create a human-edit commit ([MDU-HUMAN]) in the given git context. */
export function mduHumanCommit(
  ctx: GitCtx,
  { files, promotedSymbols }: { files: string[]; promotedSymbols: string[] },
): void {
  const filesList = files.join(",");
  const promoted = promotedSymbols.length > 0 ? promotedSymbols.join(",") : "none";
  const msg = `[MDU-HUMAN] mdu: source=human files=${filesList} promoted=${promoted}`;
  const { stderr } = gitExecSync(["commit", "-m", msg, "--allow-empty"], ctx);
  if (stderr && (stderr.includes("fatal:") || stderr.includes("error:"))) {
    throw new Error(`git commit failed: ${stderr.trim()}`);
  }
}

/**
 * The commit-tag namespaces: `MDU` is written today; `ADFI`, the original
 * adfi-openclaw tag, is only READ. The pre-2026-09-28 spellings (`AOS`, `DV`)
 * are not read: no backward compatibility, and a shadow repo is rebuilt under
 * the `~/.mandu/state` state base (docs/design/integrity/fs-sync.md §3.7a).
 */
export const TAG_NAMESPACE = "MDU";
export const LEGACY_TAG_NAMESPACES = ["ADFI"] as const;

/** `--grep=` arguments matching one tag kind in the current AND legacy namespaces. */
export function tagGrepArgs(kind: "TRUSTED" | "UNTRUSTED" | "HUMAN"): string[] {
  return [TAG_NAMESPACE, ...LEGACY_TAG_NAMESPACES].map((ns) => `--grep=[${ns}-${kind}]`);
}

/** Get the commit message for a given commit hash. */
export function getCommitMessage(ctx: GitCtx, commitHash: string): string {
  const { stdout } = gitExecSync(["log", "-1", "--format=%B", commitHash], ctx);
  return stdout.trim();
}

/**
 * Parse a Mandu file-tracking commit message.
 * Recognizes the current [MDU-TRUSTED] / [MDU-UNTRUSTED] / [MDU-HUMAN] tags
 * (`mdu:` body prefix) AND the legacy namespaces in {@link
 * LEGACY_TAG_NAMESPACES} (the original `ADFI` tags with `adfi:`).
 */
export function parseMduCommitMessage(message: string): ParsedMduCommit | null {
  const agentMatch = message.match(
    /^\[(?:MDU|ADFI)-(TRUSTED|UNTRUSTED)\]\s+(?:mdu|adfi):\s+tool=(\S+)\s+callId=(\S+)\s+run=(\S+)/,
  );
  if (agentMatch) {
    return {
      trusted: agentMatch[1] === "TRUSTED",
      toolName: agentMatch[2]!,
      callId: agentMatch[3]!,
      runId: agentMatch[4]!,
    };
  }

  const humanMatch = message.match(
    /^\[(?:MDU|ADFI)-HUMAN\]\s+(?:mdu|adfi):\s+source=human\s+files=(\S+)\s+promoted=(\S+)/,
  );
  if (humanMatch) {
    const promoted = humanMatch[2] === "none" ? [] : humanMatch[2]!.split(",");
    return {
      trusted: true,
      human: true,
      toolName: "human",
      callId: "none",
      runId: "none",
      promotedSymbols: promoted,
    };
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// git blame — region attribution for human-edit re-symbolization
// ─────────────────────────────────────────────────────────────────────────────

export interface BlameLine {
  /** 1-indexed line number in the final file. */
  line: number;
  /** Commit hash that last touched this line. */
  commit: string;
  /** Subject of that commit (first line of its message). */
  summary: string;
}

/**
 * Run `git blame --porcelain` for a file and return per-line attribution.
 * Used by the human-edit reconciler to find which lines changed since the last
 * Mandu commit (i.e. were edited by a human rather than the agent) so only those
 * regions are re-symbolized. Empty array if blame fails (e.g. untracked file).
 */
export function blameFile(ctx: GitCtx, filePath: string): BlameLine[] {
  const { stdout } = gitExecSync(["blame", "--porcelain", "--", filePath], ctx);
  if (!stdout.trim()) return [];
  const lines: BlameLine[] = [];
  const summaries = new Map<string, string>();
  let curCommit = "";
  let curFinalLine = 0;
  for (const raw of stdout.split("\n")) {
    // Header line: "<40-hex> <orig-line> <final-line> [<count>]"
    const header = raw.match(/^([0-9a-f]{40})\s+\d+\s+(\d+)/);
    if (header) {
      curCommit = header[1]!;
      curFinalLine = parseInt(header[2]!, 10);
      continue;
    }
    if (raw.startsWith("summary ")) {
      summaries.set(curCommit, raw.slice("summary ".length));
      continue;
    }
    if (raw.startsWith("\t")) {
      // The actual file content line; emit the attribution row.
      lines.push({
        line: curFinalLine,
        commit: curCommit,
        summary: summaries.get(curCommit) ?? "",
      });
    }
  }
  return lines;
}

// ─────────────────────────────────────────────────────────────────────────────
// Commit lock (serialize concurrent git operations)
// ─────────────────────────────────────────────────────────────────────────────

const LOCK_STALE_MS = 30_000;

export function acquireLock(layout: ViewLayout): void {
  const lockDir = layout.commitLockPath;
  if (!existsSync(layout.workspaceDir)) mkdirSync(layout.workspaceDir, { recursive: true });

  if (existsSync(lockDir)) {
    try {
      const stat = statSync(lockDir);
      if (Date.now() - stat.mtimeMs > LOCK_STALE_MS) rmdirSync(lockDir);
    } catch {
      /* best effort stale-lock cleanup */
    }
  }

  try {
    mkdirSync(lockDir);
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error("Mandu commit lock is held by another process");
    }
    throw err;
  }
}

export function releaseLock(layout: ViewLayout): void {
  try {
    rmdirSync(layout.commitLockPath);
  } catch {
    /* ignore */
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentView worktree management
// ─────────────────────────────────────────────────────────────────────────────

/** The AgentView (trusted/symbolized) worktree path for a layout. */
export function getWorktreePath(layout: ViewLayout): string {
  return layout.agentViewPath;
}

function getWorktreeAdminDir(wtPath: string): string | null {
  const gitEntry = join(wtPath, ".git");
  if (!existsSync(gitEntry)) return null;
  try {
    const raw = readFileSync(gitEntry, "utf8");
    const match = raw.match(/gitdir:\s*(.+)/i);
    if (!match?.[1]) return null;
    const gitdirRaw = match[1].trim();
    return gitdirRaw.startsWith("/") ? gitdirRaw : join(wtPath, gitdirRaw);
  } catch {
    return null;
  }
}

/** Check that the AgentView worktree is initialized and valid. */
export function isWorktreeInitialized(layout: ViewLayout): boolean {
  const wtPath = getWorktreePath(layout);
  try {
    if (!existsSync(wtPath)) return false;
    const gitEntry = join(wtPath, ".git");
    if (!existsSync(gitEntry)) return false;
    const stat = statSync(gitEntry);
    if (!stat.isFile()) return false;
    const gitdir = getWorktreeAdminDir(wtPath);
    if (!gitdir) return false;
    return existsSync(join(gitdir, "HEAD"));
  } catch {
    return false;
  }
}

/**
 * Ensure the SHADOW repo's info directory exists. Idempotent; defensive against
 * a state dir recreated out from under us. (Also the Mandu-owned exclude
 * slot: `repo.git/info/exclude`, empty for now — fs-sync.md §3.3.)
 */
export function ensureGitInfoDir(gitDir: string): void {
  const infoDir = join(gitDir, "info");
  try {
    if (!existsSync(infoDir)) mkdirSync(infoDir, { recursive: true });
  } catch {
    /* best effort */
  }
}

/** The AgentView branch name. New workspaces use "mdu-trusted". */
export const AGENT_VIEW_REF = "mdu-trusted";
/** The pre-rename AgentView branch name, adopted transparently where present. */
export const LEGACY_AGENT_VIEW_REF = "adfi-trusted";
/** The shadow repo's main line (the T/U pair chain + [MDU-HUMAN] commits).
 *  Pinned by symbolic-ref at init — immune to `init.defaultBranch` variance. */
export const SHADOW_MAIN_REF = "mdu-main";

/**
 * The AgentView ref in use for a git context: the current "mdu-trusted" if it
 * exists, else a legacy "adfi-trusted" left by a workspace initialized under
 * the old scheme, else "mdu-trusted" for a fresh init. Every ref read/write
 * (init, advance, reset, revert) routes through this so a mid-upgrade
 * workspace can't split-brain across the two branch names.
 */
export function agentViewRef(ctx: GitCtx): string {
  const exists = (b: string) =>
    gitExecSync(["branch", "--list", b], ctx).stdout.trim() !== "";
  if (exists(AGENT_VIEW_REF)) return AGENT_VIEW_REF;
  if (exists(LEGACY_AGENT_VIEW_REF)) return LEGACY_AGENT_VIEW_REF;
  return AGENT_VIEW_REF;
}

/** Admin context: addresses the shadow repo WITHOUT a work tree — for
 *  branch/worktree/ref surgery, where a GIT_WORK_TREE override could confuse
 *  the linked-worktree machinery. Work-tree ops use `shadowCtx` instead. */
function shadowAdminCtx(layout: ViewLayout): GitCtx {
  return { cwd: layout.workspaceDir, env: { GIT_DIR: layout.gitDir } };
}

/** True when the shadow substrate repo exists (`repo.git/HEAD` present). */
export function isShadowRepoInitialized(layout: ViewLayout): boolean {
  return existsSync(join(layout.gitDir, "HEAD"));
}

/**
 * Create the shadow substrate repo (fs-sync.md §3.2) if absent — a
 * bare repo at `<state>/repo.git` addressed with `GIT_WORK_TREE=<workspace>`
 * (the classic bare-repo/dotfiles pattern), with:
 *   - HEAD pinned to `mdu-main` BEFORE the first commit;
 *   - a local Mandu committer identity (bookkeeping commits stop
 *     impersonating the human, and no global git config is required);
 *   - a baseline `[MDU-TRUSTED] tool=init` snapshot of the workspace
 *     (`git add -A`: `.gitignore` honored — git reads it from the work-tree —
 *     and `.git` dirs skipped by git's own walker; nested repos gitlink
 *     exactly as they would in any repo).
 * The user's own `.git` (if the workspace even has one) is never touched.
 * Idempotent.
 */
export function initShadowRepo(layout: ViewLayout): void {
  if (isShadowRepoInitialized(layout)) return;
  if (!existsSync(layout.workspaceDir)) mkdirSync(layout.workspaceDir, { recursive: true });

  const admin = shadowAdminCtx(layout);
  const { stderr: initErr } = gitExecSync(["init", "--bare", layout.gitDir], admin);
  if (initErr && initErr.includes("fatal:")) {
    throw new Error(`Failed to init the shadow repo at ${layout.gitDir}: ${initErr.trim()}`);
  }
  gitExecSync(["symbolic-ref", "HEAD", `refs/heads/${SHADOW_MAIN_REF}`], admin);
  gitExecSync(["config", "user.name", "Mandu"], admin);
  gitExecSync(["config", "user.email", "mandu@localhost"], admin);
  ensureGitInfoDir(layout.gitDir);

  const ctx = shadowCtx(layout);
  gitExecSync(["add", "-A"], ctx);
  mduCommit(ctx, { trusted: true, toolName: "init" });
}

/**
 * Initialize the AgentView worktree at the canonical agentview path. Ensures
 * the shadow substrate exists, creates an `mdu-trusted` branch from its
 * `mdu-main` tip (or adopts an existing one) and adds it as a worktree OF THE
 * SHADOW REPO — the registration lives in `repo.git/worktrees/`, never in the
 * user's `.git`. Returns the path.
 */
export function initWorktree(layout: ViewLayout): string {
  const wtPath = getWorktreePath(layout);

  if (isWorktreeInitialized(layout)) return wtPath;

  initShadowRepo(layout);
  ensureGitInfoDir(layout.gitDir);
  writeFileSync(layout.workspaceJsonPath, JSON.stringify(layout.metadata(), null, 2) + "\n");

  const admin = shadowAdminCtx(layout);

  // Create the AgentView branch from the shadow main tip if neither the new
  // nor the legacy name exists yet.
  const ref = agentViewRef(admin);
  const { stdout: branchList } = gitExecSync(["branch", "--list", ref], admin);
  if (!branchList.trim()) {
    const { stderr: branchErr } = gitExecSync(["branch", ref, SHADOW_MAIN_REF], admin);
    if (branchErr && branchErr.includes("fatal:")) {
      throw new Error(`Failed to create ${ref} branch: ${branchErr.trim()}`);
    }
  }

  // Clean up stale worktree state if the .git marker exists but admin dir is gone.
  const staleGitFile = join(wtPath, ".git");
  if (existsSync(staleGitFile) && !isWorktreeInitialized(layout)) {
    try {
      gitExecSync(["worktree", "remove", "--force", wtPath], admin);
    } catch {
      try {
        rmSync(wtPath, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    }
    gitExecSync(["worktree", "prune"], admin);
  }

  if (!existsSync(join(wtPath, ".git"))) {
    const { stderr: wtErr } = gitExecSync(["worktree", "add", wtPath, ref], admin);
    if (wtErr && wtErr.includes("fatal:")) {
      throw new Error(`Failed to add worktree: ${wtErr.trim()}`);
    }
  }

  // Rewrite absolute gitdir paths to relative for cross-mount portability.
  const wtGitFile = join(wtPath, ".git");
  const adminDir = getWorktreeAdminDir(wtPath);
  const adminGitdir = adminDir ? join(adminDir, "gitdir") : null;
  if (existsSync(wtGitFile)) {
    if (!adminDir) throw new Error(`Worktree gitdir missing for ${wtPath}`);
    writeFileSync(wtGitFile, `gitdir: ${relative(wtPath, adminDir)}\n`);
  }
  if (adminGitdir && existsSync(adminGitdir)) {
    writeFileSync(adminGitdir, `${relative(adminDir!, wtGitFile)}\n`);
  }

  if (!isWorktreeInitialized(layout)) {
    throw new Error(`Worktree creation appeared to succeed but validation failed (${wtPath})`);
  }

  return wtPath;
}

/**
 * Advance the mdu-trusted ref: create a new commit on mdu-trusted with the
 * same tree as HEAD (the latest [MDU-TRUSTED] commit on the main line),
 * parented to the previous mdu-trusted commit. Keeps mdu-trusted free of
 * [MDU-UNTRUSTED] ancestors.
 */
export function updateTrustedRef(ctx: GitCtx): void {
  const ref = agentViewRef(ctx);
  const { stdout: treeOut } = gitExecSync(["rev-parse", "HEAD^{tree}"], ctx);
  const tree = treeOut.trim();

  const { stdout: msgOut } = gitExecSync(["log", "-1", "--format=%B"], ctx);
  const msg = msgOut.trim();

  const { stdout: commitOut } = gitExecSync(["commit-tree", tree, "-p", ref, "-m", msg], ctx);
  const newCommit = commitOut.trim();
  if (!newCommit) throw new Error("git commit-tree returned empty hash");

  gitExecSync(["update-ref", `refs/heads/${ref}`, newCommit], ctx);
}

/** Reset the AgentView worktree to the AgentView ref (symbolized state). */
export function resetTrustedWorktree(layout: ViewLayout): void {
  const wtPath = getWorktreePath(layout);
  gitExecSync(["reset", "--hard", agentViewRef(shadowAdminCtx(layout))], { cwd: wtPath });
}

/** Remove the AgentView worktree (manual cleanup; relative gitdir pointers). */
export function removeWorktree(layout: ViewLayout): void {
  if (!isWorktreeInitialized(layout)) return;
  const wtPath = getWorktreePath(layout);
  const adminDir = getWorktreeAdminDir(wtPath);
  try {
    rmSync(wtPath, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
  if (adminDir) {
    try {
      rmSync(adminDir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
  if (isShadowRepoInitialized(layout)) {
    gitExecSync(["worktree", "prune"], shadowAdminCtx(layout));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy in-repo substrate migration (fs-sync.md §3.6)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The AgentView worktree's admin dir IFF it lives inside the USER's workspace
 * `.git` — i.e. the workspace was initialized under the pre-shadow substrate.
 * Null for shadow-registered worktrees and uninitialized workspaces.
 */
export function legacyWorktreeAdminDir(layout: ViewLayout): string | null {
  const admin = getWorktreeAdminDir(getWorktreePath(layout));
  if (!admin) return null;
  const userGit = join(layout.humanPath, ".git");
  return admin === userGit || admin.startsWith(userGit + "/") ? admin : null;
}

export interface LegacyMigrationResult {
  /** Rel paths of dirty legacy-worktree files copied aside before teardown. */
  backedUp: string[];
  /** Where they were copied ("" when nothing was dirty). */
  backupDir: string;
  /** AgentView branches deleted from the USER's repo. */
  removedBranches: string[];
}

/**
 * Migrate a workspace off the legacy in-user-repo substrate: back up any
 * unsynced (dirty) AgentView files, then remove Mandu's residue from the
 * user's repo — the worktree registration and the mdu-trusted/adfi-trusted
 * branch. These are the ONLY writes Mandu ever makes to the user's repo
 * again, and they only remove what Mandu itself created. The legacy
 * `[MDU-*]` commits interleaved in the user's history are LEFT ALONE
 * (rewriting the user's history is the user's call, never fs-sync's).
 * Returns null when the workspace is not in the legacy shape.
 */
export function migrateLegacyWorkspace(layout: ViewLayout): LegacyMigrationResult | null {
  if (!legacyWorktreeAdminDir(layout)) return null;
  const wtPath = getWorktreePath(layout);
  const userCtx: GitCtx = { cwd: layout.humanPath };

  // 1. Preserve unsynced agent writes (no silent loss).
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupDir = join(layout.workspaceDir, `migration-backup-${stamp}`);
  const backedUp: string[] = [];
  for (const f of getChangedFiles({ cwd: wtPath })) {
    const src = join(wtPath, f.path);
    if (!existsSync(src) || isSymlink(src)) continue;
    if (statSync(src).isDirectory()) continue;
    const dest = join(backupDir, f.path);
    mkdirSync(dirname(dest), { recursive: true });
    copyFileSync(src, dest);
    backedUp.push(f.path);
  }

  // 2. Remove the worktree registration from the user's repo.
  gitExecSync(["worktree", "remove", "--force", wtPath], userCtx);
  try {
    rmSync(wtPath, { recursive: true, force: true }); // belt: remove may have failed
  } catch {
    /* best effort */
  }
  gitExecSync(["worktree", "prune"], userCtx);

  // 3. Delete the AgentView branch(es) Mandu created there.
  const removedBranches: string[] = [];
  for (const b of [AGENT_VIEW_REF, LEGACY_AGENT_VIEW_REF]) {
    const exists = gitExecSync(["branch", "--list", b], userCtx).stdout.trim() !== "";
    if (!exists) continue;
    gitExecSync(["branch", "-D", b], userCtx);
    removedBranches.push(b);
  }

  return { backedUp, backupDir: backedUp.length > 0 ? backupDir : "", removedBranches };
}

// ─────────────────────────────────────────────────────────────────────────────
// Conflict log (DualFS race detection)
// ─────────────────────────────────────────────────────────────────────────────

export interface ConflictLogEntry {
  /** Race id: R1 human->agent, R2 agent->human, R3 symbol alloc; SYMLINK =
   * refusal to sync/copy through a symbolic link (gap class 3, P5);
   * IGNORED-NOT-SYNCED = an agent write to an ignored path that fs-sync
   * leaves in the AgentView (a denied directory, a cap), logged once per path
   * (fs-sync.md §3.4.1). */
  race: "R1" | "R2" | "R3" | "SYMLINK" | "IGNORED-NOT-SYNCED";
  source: string;
  /** Affected file path (relative to gitRoot) or symbol name. */
  target: string;
  reason: string;
  extra?: Record<string, unknown>;
}

/** Append a race-detection event to the workspace's conflicts.log as JSONL. */
/**
 * lstat-based symlink probe (never follows the link; a missing path is false).
 * fs-sync refuses to READ, WRITE or COPY through symlinks in either view —
 * a link planted in the AgentView (or tracked in the HumanView) aliases paths
 * OUTSIDE the workspace, so following one would let fs-sync's own privileged
 * IO escape the two trees (fs-sync.md §1.4 gap class 3, P5).
 */
export function isSymlink(p: string): boolean {
  try {
    return lstatSync(p).isSymbolicLink();
  } catch {
    return false;
  }
}

export function writeConflictLog(layout: ViewLayout, entry: ConflictLogEntry): void {
  try {
    if (!existsSync(layout.workspaceDir)) mkdirSync(layout.workspaceDir, { recursive: true });
    const record = JSON.stringify({ ts: new Date().toISOString(), ...entry });
    appendFileSync(layout.conflictsLogPath, record + "\n");
  } catch {
    /* conflict logging must never wedge the caller */
  }
}

/**
 * Rewrite a file path from the HumanView into the AgentView worktree. Returns
 * null if the path is not within the HumanView root. Returns the path unchanged
 * if it is already inside the AgentView. This is the exact rewrite the Rust
 * fs-supervisor will perform on `openat()` for tracked workspaces.
 */
export function rewriteToWorktree(layout: ViewLayout, filePath: string): string | null {
  const gitRoot = layout.humanPath;
  const wtPath = getWorktreePath(layout);
  const resolvedPath = filePath.startsWith("~/")
    ? join(os.homedir(), filePath.slice(2))
    : filePath;

  if (resolvedPath.startsWith(wtPath + "/") || resolvedPath === wtPath) return resolvedPath;
  if (!resolvedPath.startsWith(gitRoot + "/") && resolvedPath !== gitRoot) return null;
  return wtPath + resolvedPath.slice(gitRoot.length);
}
