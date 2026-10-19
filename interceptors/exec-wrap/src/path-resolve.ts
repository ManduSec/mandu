/**
 * path-resolve — find the REAL shadowed binary on PATH, EXCLUDING the shim dir.
 *
 * The exec chokepoint runs inside a shim whose dir is on the agent's PATH; when
 * we decide to ALLOW, we must exec the actual /usr/bin/curl (etc.), NOT our own
 * shim — otherwise the shim would re-invoke us forever (infinite recursion). So
 * the PATH scan SKIPS the shim dir (MANDU_EXECWRAP_SHIM_DIR).
 *
 * Pure + filesystem-only (no exec), so it is unit-testable directly.
 */

import { accessSync, constants as fsConstants } from "node:fs";
import { join, isAbsolute } from "node:path";

/** Normalize a dir for comparison (strip a single trailing slash, keep "/"). */
export function normalizeDir(d: string): string {
  return d.length > 1 && d.endsWith("/") ? d.slice(0, -1) : d;
}

/** Default executable predicate: an X_OK-accessible path. */
function defaultIsExecutable(p: string): boolean {
  try {
    accessSync(p, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export interface FindRealOpts {
  /** The PATH to scan (defaults to process.env.PATH). */
  path?: string;
  /** The shim dir to EXCLUDE (the anti-recursion guard). */
  shimDir?: string;
  /** cwd used to resolve a relative PATH entry (defaults to process.cwd()). */
  cwd?: string;
  /** Injectable executable predicate (tests stub this; prod uses access X_OK). */
  isExecutable?: (p: string) => boolean;
}

/**
 * Find the REAL `cmd` binary by scanning PATH, EXCLUDING the shim dir. Returns the
 * resolved path or null if not found.
 *
 * A command containing "/" is treated as a path (not a PATH lookup).
 */
export function findRealCommand(cmd: string, opts: FindRealOpts = {}): string | null {
  const isExecutable = opts.isExecutable ?? defaultIsExecutable;
  const cwd = opts.cwd ?? process.cwd();

  if (cmd.includes("/")) {
    return isExecutable(cmd) ? cmd : null;
  }

  const pathEnv = opts.path ?? process.env["PATH"] ?? "";
  const shimResolved = opts.shimDir ? normalizeDir(opts.shimDir) : null;

  for (const dir of pathEnv.split(":")) {
    if (dir === "") continue;
    if (shimResolved !== null && normalizeDir(dir) === shimResolved) {
      continue; // SKIP the shim dir — anti-recursion guard.
    }
    const candidate = isAbsolute(dir) ? join(dir, cmd) : join(cwd, dir, cmd);
    if (isExecutable(candidate)) return candidate;
  }
  return null;
}
