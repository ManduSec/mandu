/**
 * bwrap-path — which bubblewrap Mandu runs when it runs the distribution's
 * (docs/design/confidentiality/rootless-confinement-ubuntu-2404.md §0.7).
 *
 * DECISION A (the maintainer, 2026-10-09): Mandu uses the distribution's
 * bubblewrap. It bundles none and downloads none; `mandu setup` copies the
 * distribution's to Mandu's own root-owned path (bwrap-grant.ts) only so
 * Ubuntu's AppArmor can grant that copy alone. Claude Code and Codex do the
 * same (§0.7 has the comparison). This module answers "which binary is the
 * distribution's", for every place Mandu runs one outside Mandu's own copy.
 *
 * 1. An administrator's `bwrap_path:` (Claude Code's managed-only
 *    `sandbox.bwrapPath`), set in a file under ADMIN_POLICY_DIR, the
 *    administrator's policy layer (arbiter/policy/admin-layer.ts reads the
 *    same files and accepts the key). Honoured only when nobody but root can
 *    have written it: the file, every directory above it, the binary and
 *    every directory above that, root-owned and writable by neither group nor
 *    others. Set but not trustworthy (or unreadable as one plain absolute
 *    path) means NO bubblewrap, with the reason, never a silent fall back to
 *    PATH: the administrator named a binary, and another one is not it.
 * 2. Else the first `bwrap` on PATH, skipping every entry that is empty or
 *    relative (both mean "the current directory") or that lies inside the
 *    current directory, and every candidate whose real path lies inside it,
 *    as Codex does (codex-rs/sandboxing/src/bwrap.rs). The current directory
 *    is the workspace the agent writes: a `bwrap` planted there (a
 *    repository's `bin/` or `node_modules/.bin` on PATH through direnv or an
 *    npm script, a `.` on PATH) is never run. The answer is the candidate's
 *    real path, so what runs is what was checked. A current directory of `/`
 *    excludes nothing more (it would exclude every binary).
 *
 * Absent: null. A caller never falls back to a bare `bwrap` (the kernel's
 * PATH search would find the planted one this skips).
 *
 * ONE FILE, FOUR COPIES: launcher/src, arbiter/src, dashboard/src and
 * fs-sync/src each ship this file byte-identical (hardened-git.ts imports
 * it). tests/stack/hardened-git-parity.test.ts holds the copies equal.
 * Change the launcher's copy and copy it out.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code; the PATH rule
 * follows Codex's (codex-rs/sandboxing/src/bwrap.rs, Apache-2.0), rewritten.
 */
import { accessSync, constants, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";

/** The administrator's policy layer (arbiter/policy/admin-layer.ts
 *  ADMIN_POLICY_DIR). A build can change it; nothing at run time can. */
export const ADMIN_POLICY_DIR = "/etc/mandu/policy.d";

/** The top-level key an administrator's file sets. */
export const ADMIN_BWRAP_KEY = "bwrap_path";

export interface BwrapStat { uid: number; mode: number; isFile: boolean; isDir: boolean }

export interface BwrapPathDeps {
  /** The PATH to search (default: this process's). */
  path?: string;
  /** The current directory (default: process.cwd()). */
  cwd?: string;
  /** A regular file this user may execute. */
  executable?: (p: string) => boolean;
  realpath?: (p: string) => string | null;
  stat?: (p: string) => BwrapStat | null;
  /** The names in a directory, or null when it cannot be listed. */
  listDir?: (dir: string) => string[] | null;
  readText?: (p: string) => string | null;
  /** The administrator's directory (default ADMIN_POLICY_DIR); tests only. */
  adminDir?: string;
}

const realpathOrNull = (p: string): string | null => {
  try { return realpathSync(p); } catch { return null; }
};
const executableRegular = (p: string): boolean => {
  try { return statSync(p).isFile() && (accessSync(p, constants.X_OK), true); } catch { return false; }
};
const statOrNull = (p: string): BwrapStat | null => {
  try { const s = statSync(p); return { uid: s.uid, mode: s.mode, isFile: s.isFile(), isDir: s.isDirectory() }; } catch { return null; }
};
const listOrNull = (dir: string): string[] | null => {
  try { return readdirSync(dir); } catch { return null; }
};
const readOrNull = (p: string): string | null => {
  try { return readFileSync(p, "utf8"); } catch { return null; }
};

/** `p` is `dir` or below it (both absolute, normalized). `/` contains
 *  nothing here: excluding it would exclude every binary. Pure. */
export function insideDir(p: string, dir: string): boolean {
  const d = dir.replace(/\/+$/, "");
  if (d === "") return false;
  return p === d || p.startsWith(`${d}/`);
}

/** The first `bwrap` on `deps.path`, outside the current directory, by its
 *  real path; null when none. */
export function findBwrapOnPath(deps: BwrapPathDeps = {}): string | null {
  const executable = deps.executable ?? executableRegular;
  const realpath = deps.realpath ?? realpathOrNull;
  const cwd = deps.cwd ?? process.cwd();
  const cwdReal = realpath(cwd) ?? cwd;
  for (const raw of (deps.path ?? process.env["PATH"] ?? "").split(":")) {
    // Empty and relative entries name the current directory, or one below it.
    if (!raw.startsWith("/")) continue;
    const dir = raw.replace(/\/+$/, "") || "/";
    if (insideDir(dir, cwd) || insideDir(dir, cwdReal)) continue;
    const dirReal = realpath(dir);
    if (dirReal === null || insideDir(dirReal, cwdReal)) continue;
    const cand = `${dir === "/" ? "" : dir}/bwrap`;
    if (!executable(cand)) continue;
    const real = realpath(cand);
    if (real === null || insideDir(real, cwdReal) || !executable(real)) continue;
    return real;
  }
  return null;
}

/** Root-owned and writable by neither group nor others. */
function rootOnly(s: BwrapStat | null): boolean {
  return s !== null && s.uid === 0 && (s.mode & 0o022) === 0;
}

/** `p` and every directory above it are root's alone. */
function rootOnlyChain(p: string, stat: (p: string) => BwrapStat | null): boolean {
  for (let q = p; ; q = q.slice(0, q.lastIndexOf("/")) || "/") {
    if (!rootOnly(stat(q))) return false;
    if (q === "/") return true;
  }
}

/** One plain absolute path from a `bwrap_path:` line's value, or null.
 *  Pure. */
function plainPath(v: string): string | null {
  let s = v.replace(/\s+#.*$/, "").trim();
  const q = /^(["'])(.*)\1$/.exec(s);
  if (q !== null) s = q[2]!;
  if (!s.startsWith("/") || /[\s"'#]/.test(s)) return null;
  if (s.split("/").some((c) => c === "." || c === "..")) return null;
  return s;
}

/** An administrator's `bwrap_path:` in one file's text: absent, a plain
 *  path, or present but not one plain absolute path on its line (a block
 *  scalar, a flow mapping, a relative path). Pure. */
export function adminBwrapLine(text: string): { kind: "absent" } | { kind: "path"; path: string } | { kind: "unreadable" } {
  let found: { kind: "path"; path: string } | { kind: "unreadable" } | null = null;
  for (const line of text.split("\n")) {
    const m = new RegExp(`^${ADMIN_BWRAP_KEY}\\s*:(.*)$`).exec(line.replace(/\r$/, ""));
    if (m === null) continue;
    const p = plainPath(m[1]!);
    found = p === null ? { kind: "unreadable" } : { kind: "path", path: p };
  }
  return found ?? { kind: "absent" };
}

/** The administrator's choice: none, a trusted binary, or a reason it
 *  cannot be used. */
export type AdminBwrap =
  | { kind: "none" }
  | { kind: "path"; path: string; file: string }
  | { kind: "refused"; file: string; why: string };

/**
 * Read `bwrap_path:` from the administrator's files (`*.yaml`/`*.yml`, in
 * name order; the last file that sets it wins, as in any `.d` directory).
 * A file that is not root's alone (by its real path) is skipped as if absent:
 * anyone who could write it could name their own binary, and skipping it
 * leaves the PATH answer a launch gets with no administrator at all.
 */
export function adminBwrap(deps: BwrapPathDeps = {}): AdminBwrap {
  const dir = deps.adminDir ?? ADMIN_POLICY_DIR;
  const stat = deps.stat ?? statOrNull;
  const realpath = deps.realpath ?? realpathOrNull;
  const names = (deps.listDir ?? listOrNull)(dir);
  if (names === null) return { kind: "none" };
  let chosen: AdminBwrap = { kind: "none" };
  for (const n of names.filter((x) => /\.ya?ml$/.test(x)).sort()) {
    const file = `${dir}/${n}`;
    const s = stat(file);
    if (s === null || !s.isFile) continue;
    const text = (deps.readText ?? readOrNull)(file);
    if (text === null) continue;
    const line = adminBwrapLine(text);
    if (line.kind === "absent") continue;
    const fileReal = realpath(file);
    if (fileReal === null || !rootOnlyChain(fileReal, stat)) continue;
    if (line.kind === "unreadable") {
      chosen = { kind: "refused", file, why: `${ADMIN_BWRAP_KEY} in ${file} is not one absolute path on its line` };
      continue;
    }
    const real = realpath(line.path);
    const rs = real === null ? null : stat(real);
    if (real === null || rs === null || !rs.isFile) {
      chosen = { kind: "refused", file, why: `${line.path} (${ADMIN_BWRAP_KEY} in ${file}) does not exist` };
    } else if (!rootOnlyChain(real, stat)) {
      chosen = { kind: "refused", file, why: `${line.path} (${ADMIN_BWRAP_KEY} in ${file}) is not root's alone (it, or a directory above it, is not root-owned or is writable by others)` };
    } else {
      chosen = { kind: "path", path: real, file };
    }
  }
  return chosen;
}

/** Which bubblewrap is the distribution's here, and why. */
export interface SystemBwrap {
  /** Absolute, resolved; null when none may be used. */
  bin: string | null;
  source: "admin" | "path" | null;
  /** When `source` is null because of the administrator: why their
   *  `bwrap_path` cannot be used. */
  refused?: string;
}

/** The administrator's `bwrap_path` when set, else the first `bwrap` on
 *  PATH outside the current directory. */
export function systemBwrap(deps: BwrapPathDeps = {}): SystemBwrap {
  const admin = adminBwrap(deps);
  if (admin.kind === "path") return { bin: admin.path, source: "admin" };
  if (admin.kind === "refused") return { bin: null, source: null, refused: admin.why };
  const bin = findBwrapOnPath(deps);
  return { bin, source: bin === null ? null : "path" };
}

/** systemBwrap's binary alone. */
export const systemBwrapBin = (deps: BwrapPathDeps = {}): string | null => systemBwrap(deps).bin;
