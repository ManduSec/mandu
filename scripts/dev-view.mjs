#!/usr/bin/env node
// dev-view — where the dashboard's developer view is, or that this checkout
// has none (dashboard.md §4.25ac). The developer view (the inspector at
// /dev/, its runners and run stores) is kept out of the public snapshot, so
// public code never names its directory: it asks here and degrades when the
// answer is "none" (the public tree, an installed bundle). A file of it is
// then named by its path in its package (`src/ci-runs.ts`).
//
// The answer: the package whose module dashboard/package.json names in
// `mandu.devExtension` (relative to dashboard/; the dashboard's loader,
// src/extension-loader.ts, reads the same member), its root being the
// nearest directory above that module holding a package.json, when it
// exists. The public export removes the member, so the public tree answers
// none.
//
// Usage:
//   node scripts/dev-view.mjs [<repo root>]   # prints the package's absolute path; exit 1 when none
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The developer view's package root in the checkout at `repoRoot`, or null. */
export function devView(repoRoot = REPO_ROOT) {
  const dashboard = join(repoRoot, "dashboard");
  let rel;
  try { rel = JSON.parse(readFileSync(join(dashboard, "package.json"), "utf8"))?.mandu?.devExtension; } catch { return null; }
  if (typeof rel !== "string" || rel === "" || rel.includes("\0")) return null;
  const mod = resolve(dashboard, rel);
  if (!existsSync(mod)) return null;
  for (let d = dirname(mod); d !== dirname(d) && d.startsWith(repoRoot); d = dirname(d)) {
    if (d !== dashboard && existsSync(join(d, "package.json"))) return d;
  }
  return null;
}

/** A file of the developer view by its path in its package, or null when
 *  this checkout has no developer view. */
export function devViewFile(path, repoRoot = REPO_ROOT) {
  const root = devView(repoRoot);
  return root === null ? null : join(root, path);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const root = devView(process.argv[2] ? resolve(process.argv[2]) : REPO_ROOT);
  if (root === null) process.exit(1);
  console.log(root);
}
