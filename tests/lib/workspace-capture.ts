/**
 * workspace-capture — the FINAL per-view file-tree capture behind the
 * `workspace_final` event (the `workspace_seed` twin; see assertions.ts
 * buildFinalEvent and docs/design/ui/dashboard.md §4.12).
 *
 * Shared by claude-e2e (both views) and codex-e2e (HumanView only) — unlike the
 * 10-line per-suite `collectSeededFiles`, this walk carries budget accounting
 * and pruning, so ONE implementation, not two drifting copies. Lives outside
 * assertions.ts on purpose: that lib is pure evals + builders (its offline test
 * suite depends on it); this module does disk I/O.
 *
 * CAPS — the seed capture has none (prepared files are tiny by construction);
 * the final walk sees whatever the agent produced, so every dimension is
 * bounded to keep the event's NDJSON line small (~1.2 MiB worst case for two
 * views). The dashboard ships the event to the browser per session
 * (/api/events) — do not raise these casually.
 *
 * PRUNING is load-bearing, not cosmetic: unlike the seed walk (which runs
 * BEFORE any fsSync git init), this one runs AFTER — the HumanView workspace
 * carries the full dual-view history under `.git/` (binary objects that would
 * blow every budget), and the AgentView worktree carries a `.git` POINTER FILE.
 * Skip any dirent named `.git` (either type); never follow symlinks (cycles /
 * workspace escape).
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import type { FinalFile, FinalWorkspaceView } from "./assertions.js";

/** Per-file shipped-content cap; longer content is cut + `truncated`. */
export const FINAL_CONTENT_CAP = 64 * 1024;
/** Files above this are never read (content:null + truncated). */
export const FINAL_READ_CEILING = 1024 * 1024;
/** Per-VIEW total content budget; files past it ship content:null + truncated. */
export const FINAL_TOTAL_BUDGET = 512 * 1024;
/** Per-view file-count cap; beyond it files are dropped + view.truncated. */
export const FINAL_FILE_COUNT_CAP = 200;

/** Recursively list `root`'s file paths (workspace-relative, `/`-separated,
 *  sorted), pruning `.git` dirents (dir or pointer file) and symlinks. */
function walk(root: string, relDir = ""): string[] {
  const out: string[] = [];
  for (const d of readdirSync(join(root, relDir), { withFileTypes: true })) {
    if (d.name === ".git" || d.isSymbolicLink()) continue;
    const rel = relDir ? `${relDir}/${d.name}` : d.name;
    if (d.isDirectory()) out.push(...walk(root, rel));
    else if (d.isFile()) out.push(rel);
  }
  return out.sort((a, b) => a.localeCompare(b));
}

/**
 * Capture one view's FINAL file tree under `root` as a FinalWorkspaceView.
 * Per file: over the read ceiling → unread (content:null, truncated); binary
 * (NUL in the first 8 KiB) → content:null, binary; over the remaining per-view
 * budget → content:null, truncated; else content, cut at FINAL_CONTENT_CAP.
 * Fail-soft per file (a racing unlink yields size 0 + no content), fail-soft
 * per view (an unreadable root yields an empty file list) — capture must never
 * fail a scenario.
 */
export function collectFinalFiles(
  root: string,
  view: "AgentView" | "HumanView",
): FinalWorkspaceView {
  let paths: string[] = [];
  try {
    paths = walk(root);
  } catch {
    paths = [];
  }
  const truncated = paths.length > FINAL_FILE_COUNT_CAP;
  let budget = FINAL_TOTAL_BUDGET;
  const files: FinalFile[] = [];
  for (const rel of paths.slice(0, FINAL_FILE_COUNT_CAP)) {
    try {
      const size = statSync(join(root, rel)).size;
      if (size > FINAL_READ_CEILING) {
        files.push({ path: rel, content: null, size, truncated: true, binary: false });
        continue;
      }
      const buf = readFileSync(join(root, rel));
      if (buf.subarray(0, 8192).includes(0)) {
        files.push({ path: rel, content: null, size: buf.length, truncated: false, binary: true });
        continue;
      }
      if (buf.length > budget) {
        files.push({ path: rel, content: null, size: buf.length, truncated: true, binary: false });
        continue;
      }
      const cut = buf.length > FINAL_CONTENT_CAP;
      const content = (cut ? buf.subarray(0, FINAL_CONTENT_CAP) : buf).toString("utf8");
      budget -= content.length;
      files.push({ path: rel, content, size: buf.length, truncated: cut, binary: false });
    } catch {
      files.push({ path: rel, content: null, size: 0, truncated: true, binary: false });
    }
  }
  return { view, root, files, truncated };
}
