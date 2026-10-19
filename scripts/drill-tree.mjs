#!/usr/bin/env node
// drill-tree — where the maintainers' drill tree is, or that this checkout has
// none (test-organization.md §5, "The drill tree"). The drills (catalog, runners, replay
// engine) are kept out of the public snapshot, so public code never names
// their directory: it asks here and degrades when the answer is "none" (the
// public tree, an installed bundle). A drill file is then named by its path
// under the tree's root (`live/drill-policy.yaml`).
//
// The answer, in order:
//   1. MANDU_DRILL_TREE: a directory, absolute or relative to the repo root
//      (a drill tree kept elsewhere; set but not a directory = none);
//   2. tests/package.json's `mandu.drillTree`: a directory relative to tests/
//      (the source repository declares it there; the public export removes
//      the member, so the public tree answers none);
//   3. none.
// The dashboard ships standalone and carries the same rule in TypeScript
// (the developer view's drill-tree.ts); its unit test holds the two equal.
//
// Usage:
//   node scripts/drill-tree.mjs [<repo root>]   # prints the tree's absolute path; exit 1 when none
import { readFileSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const DRILL_TREE_ENV = "MANDU_DRILL_TREE";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function isDir(p) {
  try { return statSync(p).isDirectory(); } catch { return false; }
}

/** The declared tests/-relative directory, or null (no declaration, or one
 *  that is absolute, climbs out with `..`, or is not a plain string). */
export function declaredTree(testsDir) {
  let pkg;
  try { pkg = JSON.parse(readFileSync(join(testsDir, "package.json"), "utf8")); } catch { return null; }
  const rel = pkg?.mandu?.drillTree;
  if (typeof rel !== "string" || !rel || rel.includes("\0") || isAbsolute(rel) || rel.split(/[\\/]/).includes("..")) return null;
  return rel;
}

/**
 * The drill tree of the checkout at `repoRoot`: `{ root, testsDir, rel }`
 * (absolute root, the tests package it runs from, and the root relative to
 * it, the form a runner's argv takes), or null when there is none.
 */
export function drillTree(repoRoot = REPO_ROOT, env = process.env) {
  const testsDir = join(repoRoot, "tests");
  let root = null;
  const fromEnv = env[DRILL_TREE_ENV];
  if (typeof fromEnv === "string" && fromEnv !== "") root = resolve(repoRoot, fromEnv);
  else {
    const rel = declaredTree(testsDir);
    if (rel !== null) root = join(testsDir, rel);
  }
  if (root === null || !isDir(root)) return null;
  return { root, testsDir, rel: relative(testsDir, root) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const t = drillTree(resolve(process.argv[2] ?? REPO_ROOT));
  if (t) process.stdout.write(`${t.root}\n`);
  process.exitCode = t ? 0 : 1;
}
