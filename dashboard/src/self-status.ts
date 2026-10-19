/**
 * self-status — the dashboard server's OWN identity + staleness, for the
 * control panel.
 *
 * Mandu-new (NO reference origin). Mirrors the supervisor's arbiter-staleness
 * scheme (supervisor.ts helloProbe/isStale) for the dashboard process itself —
 * the same "stale daemon serving old code" incident applies to the dashboard:
 * the view-model is computed server-side and tsx imports sources once at boot,
 * so a dashboard started before a code change keeps rendering with the old
 * model until restarted. The server captures its boot identity (pid, start
 * time, git rev) once; status() re-derives freshness per request from two
 * signals, either of which flags stale:
 *
 *   - COMMITTED drift: repo HEAD moved since boot AND the commit range touches
 *     this package. A commit elsewhere in the repo does NOT flag — over-eager
 *     staleness would train users to ignore the badge.
 *   - UNCOMMITTED drift: a file under `<packageDir>/src` (or package.json) has
 *     an mtime after boot. `public/` and `dev/` are deliberately EXCLUDED: static assets
 *     are re-read from disk per request, so they need a browser reload, not a
 *     server restart.
 */

import { execFileSync } from "node:child_process";
import { readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { hardenedGitArgs, hardenedGitEnv } from "./hardened-git.js";

/** The dashboard's self-identity block returned under `/api/control/status`. */
export interface DashboardSelfStatus {
  pid: number;
  /** ISO time this server process started. */
  startedAt: string;
  /** Short git rev of the repo at boot ("nogit" when unavailable). */
  bootRev: string;
  /** Short git rev of the repo NOW ("nogit" when unavailable). */
  repoRev: string;
  /** True when this process is serving code older than what's on disk. */
  stale: boolean;
  /** Human-readable cause when stale, else null. */
  staleReason: string | null;
}

export interface DashboardSelfOptions {
  /** Repo root (git queries run here). */
  repoRoot: string;
  /** This package's dir (the staleness scope), e.g. `<repoRoot>/dashboard`. */
  packageDir: string;
  /** TEST SEAMS — default to the real implementations below. */
  pid?: number;
  bootTimeMs?: number;
  gitRev?: (repoRoot: string) => string;
  gitChangedInRange?: (repoRoot: string, from: string, to: string, dir: string) => string[] | null;
  newestMtimeMs?: (roots: string[]) => number;
}

export class DashboardSelf {
  private readonly pid: number;
  private readonly bootTimeMs: number;
  private readonly bootRev: string;
  private readonly opts: Required<DashboardSelfOptions>;

  constructor(opts: DashboardSelfOptions) {
    this.opts = {
      repoRoot: opts.repoRoot,
      packageDir: opts.packageDir,
      pid: opts.pid ?? process.pid,
      bootTimeMs: opts.bootTimeMs ?? Date.now(),
      gitRev: opts.gitRev ?? gitShortRev,
      gitChangedInRange: opts.gitChangedInRange ?? gitChangedFiles,
      newestMtimeMs: opts.newestMtimeMs ?? newestMtime,
    };
    this.pid = this.opts.pid;
    this.bootTimeMs = this.opts.bootTimeMs;
    this.bootRev = this.opts.gitRev(opts.repoRoot);
  }

  status(): DashboardSelfStatus {
    const repoRev = this.opts.gitRev(this.opts.repoRoot);
    let stale = false;
    let staleReason: string | null = null;

    // Committed drift, scoped to this package. A failed diff (null) fails
    // QUIET here: bootRev is self-captured from this checkout, so not resolving
    // it means repo breakage (rebase/gc), not evidence of drift. Contrast the
    // supervisor's arbiterStaleness, which fails LOUD on an unresolvable rev —
    // its rev comes from a foreign daemon (supervisor-defs.ts).
    if (this.bootRev !== "nogit" && repoRev !== "nogit" && this.bootRev !== repoRev) {
      const touched = this.opts.gitChangedInRange(
        this.opts.repoRoot,
        this.bootRev,
        repoRev,
        this.opts.packageDir,
      );
      if (touched !== null && touched.length > 0) {
        stale = true;
        staleReason =
          `dashboard code changed in git since boot (${this.bootRev} → ${repoRev}, ` +
          `${touched.length} file${touched.length === 1 ? "" : "s"})`;
      }
    }

    // Uncommitted drift: server-side sources newer than this process.
    if (!stale) {
      const newest = this.opts.newestMtimeMs([
        join(this.opts.packageDir, "src"),
        join(this.opts.packageDir, "package.json"),
      ]);
      if (newest > this.bootTimeMs) {
        stale = true;
        staleReason = `dashboard source modified on disk since boot (${new Date(newest).toISOString()})`;
      }
    }

    return {
      pid: this.pid,
      startedAt: new Date(this.bootTimeMs).toISOString(),
      bootRev: this.bootRev,
      repoRev,
      stale,
      staleReason,
    };
  }
}

/** Best-effort short git rev ("nogit" when unavailable). Shared with the
 *  supervisor (its staleness reference for the adopted arbiter's identity). */
export function gitShortRev(repoRoot: string): string {
  try {
    return (
      // Hardened (hardened-git.ts): Mandu's checkout may be an agent's workspace.
      execFileSync("git", hardenedGitArgs(["rev-parse", "--short", "HEAD"]), {
        cwd: repoRoot, encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"], env: hardenedGitEnv(),
      }).trim() || "nogit"
    );
  } catch {
    return "nogit";
  }
}

/** Files changed between two revs UNDER `dir` (repo-relative paths). A git
 *  failure (unknown rev after a rebase, a foreign checkout's rev, no git) is
 *  DISTINGUISHABLE: it returns null, not []. Callers pick their own failure
 *  semantics — DashboardSelf treats null as fresh (its bootRev is self-captured,
 *  fail-quiet); the supervisor's arbiterStaleness treats null as stale (its rev
 *  is a foreign daemon's claim, fail-loud). */
export function gitChangedFiles(repoRoot: string, from: string, to: string, dir: string): string[] | null {
  try {
    const scope = relative(repoRoot, dir) || ".";
    // Two commits, names only: no work tree, no driver (hardened-git.ts).
    const out = execFileSync("git", hardenedGitArgs(["diff", "--no-ext-diff", "--no-textconv", "--name-only", from, to, "--", scope]), {
      cwd: repoRoot, encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"], env: hardenedGitEnv(),
    });
    return out.split("\n").filter((l) => l.trim().length > 0);
  } catch {
    return null;
  }
}

/** Newest mtime (ms) across the given roots — each a file or a directory walked
 *  recursively. Missing/unreadable entries are skipped; no matches → 0. */
export function newestMtime(roots: string[]): number {
  let newest = 0;
  const visit = (path: string): void => {
    let st;
    try {
      st = statSync(path);
    } catch {
      return;
    }
    if (st.isDirectory()) {
      let entries: string[];
      try {
        entries = readdirSync(path);
      } catch {
        return;
      }
      for (const e of entries) visit(join(path, e));
      return;
    }
    if (st.mtimeMs > newest) newest = st.mtimeMs;
  };
  for (const r of roots) visit(r);
  return newest;
}
