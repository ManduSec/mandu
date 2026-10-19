#!/usr/bin/env node
// scripts/ci/lane.mjs — what an MR pipeline runs: the per-push kinds; the docs
// lane when the MR changes documentation only (docs/design/testing/continuous-integration.md
// §5.5); a scoped lane when every code path it changes is in a scope the
// manifest declares (§5.8). The `test` job in .gitlab-ci.yml calls it on the
// runner host before vm-run.sh; it reads git, the manifest and the entries'
// files, and runs nothing from the commit's tests.
//
//   node scripts/ci/lane.mjs --base <sha> --head <sha>
//
// Prints the vm-run.sh selection on one line: `--only <id,id,…>` (the docs
// lane: the entries marked `docsLane: true`; a scoped lane: the per-push
// entries that can reach a changed scope, plus the docs lane's), or
// `--kind unit,component,stack,replay-drill,sandbox`. Fail-safe: whatever it
// cannot prove selects the full run — a git error, a missing base, an empty
// diff, a code path in no scope, a missing manifest. The diff lists renames as
// a delete plus an add (--no-renames), so moving a source file under docs/
// still names the source path. A master pipeline always runs in full.

import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { PER_PUSH_KINDS, REPO_ROOT, entryClaims, loadManifest, selectEntries } from "../suites.mjs";

export const FULL = `--kind ${PER_PUSH_KINDS.join(",")}`;

// Documentation: anything under docs/, and markdown anywhere else.
const DOCS = [/^docs\//, /\.md$/i];

// …except the paths a build, a package or a suite outside the docs lane reads,
// so a change to them must run everything (the audit behind this list:
// continuous-integration.md §5.5).
const NOT_DOCS = [
  /^launcher\/README\.md$/, // ships in the npm tarball; npm-pack.test.ts compares it
  /(^|\/)fixtures\//, // test data, e.g. arbiter's handling-prompt golden .md files
];

export function isDocsPath(p) {
  return DOCS.some((re) => re.test(p)) && !NOT_DOCS.some((re) => re.test(p));
}

/** "docs" when every path is documentation, else "full" (an empty list is "full"). */
export function classify(paths) {
  return paths.length > 0 && paths.every(isDocsPath) ? "docs" : "full";
}

export function docsLaneIds(entries) {
  return entries.filter((x) => x.docsLane === true).map((x) => x.id);
}

const SHA = /^[0-9a-f]{7,64}$/;

export function changedPaths(base, head, cwd) {
  if (!SHA.test(base) || !SHA.test(head)) throw new Error("base and head must be commit SHAs");
  const out = execFileSync("git", ["diff", "--name-only", "--no-renames", "-z", `${base}...${head}`, "--"], {
    cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  });
  return out.split("\0").filter(Boolean);
}

// ── scoped lanes (§5.8) ────────────────────────────────────────────────────────
// A scope is { id, owns(path), marks: [RegExp], via: [path], runs(entry) }:
// the paths it owns, the text that shows a file reads them (a mark), the
// files that reach it whoever runs them (via), and the entries it always
// runs. An entry reaches a scope when a file it runs (its claims), or one
// those import, is owned, is a via file, or holds a mark.

const IMPORT = /(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|^\s*import\s+)["'](\.{1,2}\/[^"'\n]+)["']/gm;
const COMMENT = /\/\*[\s\S]*?\*\/|(^|[\s;])\/\/.*$/gm;
const SHELL_COMMENT = /(^|[\s;])#.*$/gm;
const SKIP_DIRS = new Set(["node_modules", "target", ".git", "dist", ".mandu"]);
// A shell script's path-like words (`scripts/ci/lib.sh`, `"$HERE/lib.sh"`),
// tried against the script's directory and the repository root.
const SHELL_PATH = /(?:^|[\s"'=(:])(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\/)?((?:\.{1,2}\/)?(?:[\w.-]+\/)*[\w.-]+\.(?:sh|mjs|cjs|js|ts|mts))\b/g;
const SCRIPT = /\.(?:ts|mts|cts|mjs|cjs|js)$/;
const SHELL = /\.(?:sh|bash)$/;
const isFile = (p) => { try { return statSync(p).isFile(); } catch { return false; } };

/** The repo-relative file a relative import names, or null. A `.js` specifier may name a `.ts` source. */
export function resolveImport(from, spec, root = REPO_ROOT) {
  const base = resolve(dirname(join(root, from)), spec);
  const stem = base.replace(/\.(?:m|c)?js$/, "");
  for (const p of [base, `${stem}.ts`, `${stem}.mts`, `${stem}.cts`, `${stem}.tsx`, `${base}.ts`, `${base}.mjs`, `${base}.js`,
    join(base, "index.ts"), join(base, "index.mjs"), join(base, "index.js")]) {
    if (isFile(p)) return relative(root, p);
  }
  return null;
}

/** Every file under a repo-relative directory, build output and dependencies left out. */
function packageFiles(dir, root) {
  const out = [];
  const walk = (d) => {
    for (const e of readdirSync(join(root, d), { withFileTypes: true })) {
      if (SKIP_DIRS.has(e.name)) continue;
      const rel = `${d}/${e.name}`;
      if (e.isDirectory()) walk(rel);
      else if (e.isFile()) out.push(rel);
    }
  };
  walk(dir);
  return out;
}

/**
 * What an entry can read: { files (repo-relative), open }. Its claimed files
 * (what its cmd runs) or, when it claims none (a `tsc -p`, a `cargo test`),
 * every file of its package (its cwd); then, transitively, the relative
 * imports of each script and the path-like words of each shell script.
 * `open` (it reaches every scope) when it claims no file and runs at the
 * repository root: what cannot be followed is not proven apart. A relative
 * import that resolves to nothing is a fixture's text (a source file held in
 * a test's string), not followed: a real one would not load.
 */
export function entryReach(x, root = REPO_ROOT, read = (p) => readFileSync(join(root, p), "utf8")) {
  let start = [...entryClaims(x, root, { runs: true }).files];
  if (!start.length) {
    const cwd = (x.cwd ?? ".").replace(/\/+$/, "");
    if (cwd === "." || cwd === "" || cwd.startsWith("..")) return { files: new Set(), open: true, why: "claims no file and runs at the root" };
    start = packageFiles(cwd, root);
  }
  const files = new Set();
  const stack = [...start];
  while (stack.length) {
    const f = stack.pop();
    if (files.has(f) || /(^|\/)node_modules\//.test(f)) continue;
    files.add(f);
    if (!SCRIPT.test(f) && !SHELL.test(f)) continue;
    let src;
    try { src = read(f); } catch { continue; }
    if (SCRIPT.test(f)) {
      for (const m of src.replace(COMMENT, "$1").matchAll(IMPORT)) {
        const r = resolveImport(f, m[1], root);
        if (r != null) stack.push(r);
      }
      continue;
    }
    for (const m of src.replace(SHELL_COMMENT, "$1").matchAll(SHELL_PATH)) {
      for (const p of [join(dirname(f), m[1]), m[1]]) {
        const rel = relative(root, resolve(root, p));
        if (!rel.startsWith("..") && isFile(join(root, rel))) stack.push(rel);
      }
    }
  }
  return { files, open: false };
}

/** Why an entry's reach touches the scope (a phrase), or null. */
export function reachWhy(reach, scope, read) {
  if (reach.open) return `open: ${reach.why}`;
  for (const f of reach.files) {
    if (scope.owns(f) || (scope.via ?? []).includes(f)) return `runs ${f}`;
    if (!(scope.marks ?? []).length) continue;
    let src;
    try { src = read(f); } catch { continue; }
    const re = scope.marks.find((m) => m.test(src));
    if (re) return `${f} names ${src.match(re)[0]}`;
  }
  return null;
}

/**
 * The scoped lane for these code paths: { touched, kept, skipped } (each entry
 * with why it runs), { stray } when a path is in no scope, or null with no
 * path or no scope. `entries` is the per-push selection; a docs-lane entry
 * always runs, as on a docs-only change.
 */
export function scopedSelection(codePaths, entries, scopes, { root = REPO_ROOT } = {}) {
  if (!codePaths.length || !scopes.length) return null;
  const stray = codePaths.find((p) => !scopes.some((s) => s.owns(p)));
  if (stray) return { stray };
  const touched = scopes.filter((s) => codePaths.some((p) => s.owns(p)));
  const cache = new Map();
  const read = (p) => { if (!cache.has(p)) cache.set(p, readFileSync(join(root, p), "utf8")); return cache.get(p); };
  const kept = [];
  const skipped = [];
  for (const x of entries) {
    let why = x.docsLane ? "docs lane" : null;
    for (const s of touched) {
      if (why) break;
      why = s.runs?.(x) ? `scope ${s.id} runs it` : reachWhy(entryReach(x, root, read), s, read);
    }
    (why ? kept : skipped).push({ id: x.id, why });
  }
  return { touched: touched.map((s) => s.id), kept, skipped };
}

/** The selection line for vm-run.sh, and why. Never throws: any doubt is FULL. */
export async function selection({ base, head, cwd = REPO_ROOT, manifest, root = REPO_ROOT } = {}) {
  let paths;
  try { paths = changedPaths(base ?? "", head ?? "", cwd); } catch (e) {
    return { lane: "full", line: FULL, why: `no diff (${String(e.message).split("\n")[0]})` };
  }
  if (!paths.length) return { lane: "full", line: FULL, why: "empty diff" };
  let m;
  try { m = manifest ?? await loadManifest({ root }); } catch (e) {
    return { lane: "full", line: FULL, why: `no manifest (${String(e.message).split("\n")[0]})` };
  }
  if (classify(paths) === "docs") {
    const ids = docsLaneIds(m.entries ?? []);
    if (ids.length === 0) return { lane: "full", line: FULL, why: "no manifest entry is in the docs lane" };
    return { lane: "docs", line: `--only ${ids.join(",")}`, why: `${paths.length} paths, all docs` };
  }
  const code = paths.filter((p) => !isDocsPath(p));
  let s;
  try {
    const perPush = selectEntries(m.entries ?? [], { kinds: PER_PUSH_KINDS, platform: "linux" }).selected;
    s = scopedSelection(code, perPush, m.scopes ?? [], { root });
  } catch (e) {
    return { lane: "full", line: FULL, why: `no scoped lane (${String(e.message).split("\n")[0]})` };
  }
  if (s == null || s.stray) {
    return { lane: "full", line: FULL, why: `${paths.length} paths, ${s?.stray ?? code[0]} is not docs${s?.stray ? " and in no scope" : ""}` };
  }
  if (!s.skipped.length) return { lane: "full", line: FULL, why: `${paths.length} paths in scope ${s.touched.join(",")}; every entry reaches it` };
  return {
    lane: "scoped", line: `--only ${s.kept.map((x) => x.id).join(",")}`,
    why: `${paths.length} paths in scope ${s.touched.join(",")}; ${s.kept.length} entries run, ${s.skipped.length} skipped`,
    kept: s.kept, skipped: s.skipped,
  };
}

async function main(argv) {
  const opt = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (argv[i] === "--base") opt.base = argv[i + 1];
    else if (argv[i] === "--head") opt.head = argv[i + 1];
    else { process.stderr.write("usage: node scripts/ci/lane.mjs --base <sha> --head <sha>\n"); return 2; }
  }
  const s = await selection(opt);
  process.stderr.write(`lane: ${s.lane} (${s.why})\n`);
  if (s.skipped) process.stderr.write(`lane: skipped (they cannot reach the scope): ${s.skipped.map((x) => x.id).join(" ")}\n`);
  process.stdout.write(`${s.line}\n`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) process.exitCode = await main(process.argv.slice(2));
