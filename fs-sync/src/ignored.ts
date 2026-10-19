/**
 * ignored: the `.gitignore`d files of the HumanView, brought into the
 * AgentView as symbolized twins (fs-sync.md §3.4.1).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 * The DualView reference (docs/adfi-reference/design/fs-level-tracking.md)
 * rewrote paths per tool call and never had a git-built view, so it had no
 * notion of ignored files. Mandu's AgentView is a git worktree of the shadow
 * repo, and the shadow baseline honors `.gitignore`, so an ignored file (a
 * `.env`, a local notes file, a generated report) used to be simply ABSENT
 * from the view the AI works in: the AI could not read it at all while the
 * integrity axis was ON. This module closes that gap without putting the
 * files into git:
 *
 *   - enumeration: `git ls-files --others --ignored --exclude-standard
 *     --directory` in a given git context, then a walk of every collapsed
 *     directory, under a deny list of heavy directories and three caps;
 *   - the manifest (`<state>/workspaces/<id>/ignored.json`): per path the
 *     sha256 of the HumanView bytes and of the AgentView twin, the re-launch
 *     fast path's record and the write-back's race guard.
 *
 * The twins themselves are minted by `ViewSync` (view-sync.ts), through the
 * arbiter, whole-file, exactly like a tracked file's seed. Nothing here reads
 * a file's content beyond its size (the caller reads and symbolizes).
 *
 * SECURITY: the twins live in the AgentView worktree as plain untracked
 * files. The worktree's own `.gitignore` cannot keep them out of `git status`
 * (it is itself a seeded twin, a symbol, so the worktree ignores nothing);
 * instead `ViewSync` drops every manifest path, and every path the HumanView's
 * rules ignore (`humanIgnoredSet`), from the tracked seed and sync lists. So a
 * twin, or an agent write to an ignored path, is never committed on either
 * line, and raw bytes of an ignored file never enter `repo.git`.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { type GitCtx, gitExecSync } from "./git.js";
import { hardenedGitArgs, hardenedGitEnv } from "./hardened-git.js";
import { MANDU_HOME_DIR_NAME } from "./layout.js";

/** Directory names never walked for ignored files: dependency trees, build
 *  outputs and caches. Heavy, regenerable, and mostly third-party code; a
 *  read-only bind of them into the box is a separate, unbuilt decision
 *  (fs-sync.md §3.4.1 "Follow-up"). Matched against EVERY directory
 *  segment of a path, so `packages/a/node_modules/…` is denied too. `.git`
 *  and `.mandu` are always denied (`ALWAYS_DENIED_DIRS`). */
export const DEFAULT_IGNORED_DENY_DIRS: readonly string[] = [
  "node_modules",
  ".venv",
  "venv",
  "target",
  "dist",
  "build",
  "__pycache__",
  ".next",
  ".cache",
  ".gradle",
  ".tox",
  "coverage",
];

/** Never walked, whatever the configuration says: a nested repository and
 *  Mandu's own directory (its name from the path table). */
export const ALWAYS_DENIED_DIRS: readonly string[] = [".git", MANDU_HOME_DIR_NAME];

/** HumanView directory names whose changes are never a human edit of
 *  workspace content (the human-edit clock, fs-sync-cli.ts). */
export const CLOCK_IGNORED_DIRS: readonly string[] = [".git", MANDU_HOME_DIR_NAME, "node_modules"];

/** Whether a changed path (as `fs.watch` names it, `/` or `\` separated) sits
 *  in a `CLOCK_IGNORED_DIRS` directory, at any depth. Pure. */
export function humanEditClockIgnores(name: string): boolean {
  return name.split(/[\\/]/).some((s) => CLOCK_IGNORED_DIRS.includes(s));
}

export interface IgnoredLimits {
  /** A file larger than this is skipped (`too-large`). */
  maxFileBytes: number;
  /** At most this many files are included (`file-cap` beyond it). */
  maxFiles: number;
  /** At most this many bytes in all (`total-cap` beyond it). */
  maxTotalBytes: number;
  /** Directory names skipped as a whole (`deny-dir`). */
  denyDirs: readonly string[];
}

export const DEFAULT_IGNORED_LIMITS: IgnoredLimits = {
  maxFileBytes: 1024 * 1024,
  maxFiles: 2000,
  maxTotalBytes: 64 * 1024 * 1024,
  denyDirs: DEFAULT_IGNORED_DENY_DIRS,
};

export type IgnoredSkipReason =
  | "deny-dir"
  | "symlink"
  | "not-regular"
  | "too-large"
  | "file-cap"
  | "total-cap"
  | "binary"
  | "unreadable";

export interface IgnoredSkip {
  rel: string;
  reason: IgnoredSkipReason;
}

export interface IgnoredListing {
  /** Included files, sorted, with their size. */
  files: Array<{ rel: string; size: number }>;
  /** Everything left out, with the reason (a denied directory is ONE entry). */
  skipped: IgnoredSkip[];
}

/**
 * The limits from the environment (the launcher's env reaches `fs-sync-cli`):
 * `MANDU_FS_IGNORED_DENY` adds comma-separated directory names to the default
 * deny list. Anything malformed is ignored (the defaults stay). Pure.
 */
export function ignoredLimitsFromEnv(env: NodeJS.ProcessEnv): IgnoredLimits {
  const extra = (env["MANDU_FS_IGNORED_DENY"] ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "" && !s.includes("/") && s !== "." && s !== "..");
  if (extra.length === 0) return DEFAULT_IGNORED_LIMITS;
  return { ...DEFAULT_IGNORED_LIMITS, denyDirs: [...new Set([...DEFAULT_IGNORED_DENY_DIRS, ...extra])] };
}

/** Whether ignored-file inclusion is on (default ON; `MANDU_FS_IGNORED=0`
 *  turns it off, restoring the old "absent from the AgentView" behavior). */
export function ignoredInclusionEnabled(env: NodeJS.ProcessEnv): boolean {
  return env["MANDU_FS_IGNORED"] !== "0";
}

function deniedSegment(segments: readonly string[], deny: readonly string[]): boolean {
  return segments.some((s) => ALWAYS_DENIED_DIRS.includes(s) || deny.includes(s));
}

/**
 * Apply the caps to a sorted candidate list. Pure (unit-tested): the first
 * `maxFiles` files within `maxTotalBytes` are kept, in path order, so the
 * choice is stable across launches.
 */
export function applyIgnoredCaps(
  candidates: ReadonlyArray<{ rel: string; size: number }>,
  limits: IgnoredLimits,
): IgnoredListing {
  const files: Array<{ rel: string; size: number }> = [];
  const skipped: IgnoredSkip[] = [];
  let total = 0;
  for (const c of [...candidates].sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0))) {
    if (c.size > limits.maxFileBytes) { skipped.push({ rel: c.rel, reason: "too-large" }); continue; }
    if (files.length >= limits.maxFiles) { skipped.push({ rel: c.rel, reason: "file-cap" }); continue; }
    if (total + c.size > limits.maxTotalBytes) { skipped.push({ rel: c.rel, reason: "total-cap" }); continue; }
    total += c.size;
    files.push(c);
  }
  return { files, skipped };
}

/**
 * List the ignored files under `root` as `ctx` sees them: the HumanView
 * through the shadow context, or the AgentView worktree (`{cwd: worktree}`).
 * Symlinks are never followed or included (P5), nor anything that is not a
 * regular file. Binary detection is the caller's (it reads the bytes anyway).
 */
export function listIgnoredFiles(ctx: GitCtx, root: string, limits: IgnoredLimits): IgnoredListing {
  const { stdout } = gitExecSync(
    ["ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory"],
    ctx,
  );
  return expandIgnoredEntries(stdout.split("\0"), root, limits);
}

/**
 * Which of `paths` the HumanView's ignore rules exclude: `git check-ignore`
 * in the shadow context (the workspace's `.gitignore` files and the global
 * excludes; the user's own `.git/info/exclude` is not read, as for the
 * baseline). A path need not exist in the HumanView: git matches the pattern
 * against the path and its leading directories. A path the shadow repo TRACKS
 * is never reported (git's rule), so a tracked-but-ignored file stays on the
 * tracked sync. A directory entry keeps its trailing `/`. Any git failure
 * answers "none ignored", which leaves those paths on the tracked sync (the
 * pre-2026-09-28 behavior), never on a path with weaker handling.
 */
export function humanIgnoredSet(ctx: GitCtx, paths: readonly string[]): Set<string> {
  if (paths.length === 0) return new Set();
  let out = "";
  try {
    // Hardened (hardened-git.ts): an index read starts `core.fsmonitor`.
    out = execFileSync("git", hardenedGitArgs(["check-ignore", "-z", "--stdin"]), {
      cwd: ctx.cwd,
      env: hardenedGitEnv(process.env, ctx.env),
      input: paths.join("\0") + "\0",
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (err) {
    // Exit 1 = nothing matched (stdout empty); anything else = no answer.
    out = (err as { stdout?: string }).stdout ?? "";
  }
  return new Set(out.split("\0").filter(Boolean));
}

/**
 * The AgentView side: the untracked entries of the worktree that the
 * HUMANVIEW's rules ignore. The worktree's own ignore rules cannot be used:
 * its `.gitignore` is a seeded twin (a symbol), so the worktree ignores
 * nothing, and an agent write to `.env` or `notes/x.md` would otherwise look
 * like an ordinary new file. `--others` without `--exclude-standard` also
 * keeps the global excludes out, so the HumanView's rules decide alone.
 */
export function listAgentViewIgnored(
  agentViewRoot: string,
  rulesCtx: GitCtx,
  limits: IgnoredLimits,
): IgnoredListing {
  const { stdout } = gitExecSync(["ls-files", "-z", "--others", "--directory"], { cwd: agentViewRoot });
  const entries = stdout.split("\0").filter(Boolean);
  const ignored = humanIgnoredSet(rulesCtx, entries);
  return expandIgnoredEntries(entries.filter((e) => ignored.has(e)), agentViewRoot, limits);
}

/** Expand `ls-files --directory` style entries (a directory ends in `/`)
 *  into the files under `root`, under the deny list and the caps. */
export function expandIgnoredEntries(
  entries: readonly string[],
  root: string,
  limits: IgnoredLimits,
): IgnoredListing {
  const candidates: Array<{ rel: string; size: number }> = [];
  const skipped: IgnoredSkip[] = [];

  const consider = (rel: string): void => {
    let st;
    try {
      st = lstatSync(join(root, rel));
    } catch {
      skipped.push({ rel, reason: "unreadable" });
      return;
    }
    if (st.isSymbolicLink()) { skipped.push({ rel, reason: "symlink" }); return; }
    if (st.isDirectory()) { walk(rel); return; }
    if (!st.isFile()) { skipped.push({ rel, reason: "not-regular" }); return; }
    candidates.push({ rel, size: st.size });
  };

  const walk = (relDir: string): void => {
    const segments = relDir.split("/").filter(Boolean);
    if (deniedSegment(segments, limits.denyDirs)) { skipped.push({ rel: `${relDir}/`, reason: "deny-dir" }); return; }
    let entries;
    try {
      entries = readdirSync(join(root, relDir), { withFileTypes: true });
    } catch {
      skipped.push({ rel: `${relDir}/`, reason: "unreadable" });
      return;
    }
    for (const e of entries) consider(`${relDir}/${e.name}`);
  };

  for (const raw of entries) {
    if (raw === "") continue;
    const isDir = raw.endsWith("/");
    const rel = raw.replace(/\/+$/, "");
    if (rel === "" || rel.startsWith("../")) continue;
    const segments = rel.split("/");
    // A file's LAST segment is its own name; only directory segments deny.
    const dirSegments = isDir ? segments : segments.slice(0, -1);
    if (deniedSegment(dirSegments, limits.denyDirs)) {
      skipped.push({ rel: isDir ? `${rel}/` : rel, reason: "deny-dir" });
      continue;
    }
    consider(rel);
  }

  const capped = applyIgnoredCaps(candidates, limits);
  return { files: capped.files, skipped: [...skipped, ...capped.skipped] };
}

/** One included path's record. */
export interface IgnoredEntry {
  /** sha256 of the HumanView bytes the twin was minted from (or written back). */
  humanSha: string;
  /** sha256 of the AgentView twin as fs-sync last wrote or saw it. */
  agentSha: string;
}

export interface IgnoredManifest {
  version: 1;
  entries: Record<string, IgnoredEntry>;
  /** The last enumeration's skips (surfaced by `fs-sync-cli init` and the log). */
  skipped: IgnoredSkip[];
  /** AgentView paths already reported as not written back (logged once). */
  notSynced: string[];
}

export function emptyManifest(): IgnoredManifest {
  return { version: 1, entries: {}, skipped: [], notSynced: [] };
}

export function sha256(buf: Buffer | string): string {
  return createHash("sha256").update(buf).digest("hex");
}

/** Load the manifest; a missing or malformed file is an empty manifest. That
 *  only costs re-mints (every twin re-seeded), never a leak. */
export function loadIgnoredManifest(path: string): IgnoredManifest {
  try {
    if (!existsSync(path)) return emptyManifest();
    const x = JSON.parse(readFileSync(path, "utf8")) as Partial<IgnoredManifest>;
    if (x.version !== 1 || typeof x.entries !== "object" || x.entries === null) return emptyManifest();
    const entries: Record<string, IgnoredEntry> = {};
    for (const [rel, e] of Object.entries(x.entries)) {
      if (e && typeof e.humanSha === "string" && typeof e.agentSha === "string") {
        entries[rel] = { humanSha: e.humanSha, agentSha: e.agentSha };
      }
    }
    return {
      version: 1,
      entries,
      skipped: Array.isArray(x.skipped) ? x.skipped : [],
      notSynced: Array.isArray(x.notSynced) ? x.notSynced.filter((s) => typeof s === "string") : [],
    };
  } catch {
    return emptyManifest();
  }
}

/** Write the manifest atomically (tmp + rename). */
export function saveIgnoredManifest(path: string, m: IgnoredManifest): void {
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(m, null, 2) + "\n");
  renameSync(tmp, path);
}

/** Per-reason counts of a skip list. Pure. */
export function skipCounts(skipped: readonly IgnoredSkip[]): Partial<Record<IgnoredSkipReason, number>> {
  const out: Partial<Record<IgnoredSkipReason, number>> = {};
  for (const s of skipped) out[s.reason] = (out[s.reason] ?? 0) + 1;
  return out;
}

/** True when some existing ancestor of `rel` under `root` (or `rel` itself)
 *  is a symbolic link: writing or reading there could leave the view (P5). */
export function pathCrossesSymlink(root: string, rel: string): boolean {
  let cur = root;
  for (const seg of rel.split("/")) {
    cur = join(cur, seg);
    try {
      if (lstatSync(cur).isSymbolicLink()) return true;
    } catch {
      return false; // does not exist yet: nothing below it can be a link
    }
  }
  return false;
}
