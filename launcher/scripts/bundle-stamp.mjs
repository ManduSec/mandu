#!/usr/bin/env node
/**
 * bundle-stamp.mjs — the build record that says whether a dist/ bundle still
 * matches the source it was built from (packaging.md §5.1).
 *
 * build-bundle.mjs writes `<dist>/.bundle-stamp.json` at the end of a clean
 * build: every file the bundles were built from (esbuild's own metafile
 * inputs, so the list is exact rather than a directory guess) plus what shapes
 * the build without being an input (each source package's package.json and
 * tsconfig.json, each node_modules tree's `.package-lock.json`, which npm
 * rewrites on every install while it backdates the extracted files, and the
 * build scripts themselves), each with its mtime and size, and each output's
 * mtime and size. A checkout's launch (launcher/mandu-run.sh) runs the bundle
 * only when `checkStamp` finds every one of them unchanged; anything else (no
 * record, a missing or changed input, a missing or changed output) is stale,
 * and a stale bundle is rebuilt or bypassed, never run.
 *
 * The record is written only when no input changed while the build ran: the
 * build notes the filesystem's own clock at its start (the mtime of a probe
 * file, the same clock the inputs' mtimes come from), and an input whose
 * mtime is not older than that may have been read before its edit. The build
 * then leaves no record, so the next launch rebuilds.
 *
 * Plain JS with no dependencies: the launcher shim runs `node bundle-stamp.mjs
 * <dist>` before anything is built, and it must not load esbuild to say
 * "fresh". Exit 0 when fresh, 1 when stale (the reason on stderr with --why).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { existsSync, readFileSync, realpathSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

/** The record's file name inside the dist directory. */
export const STAMP_NAME = ".bundle-stamp.json";
const STAMP_VERSION = 1;

/** The build's own files, relative to the repo root: a change to how the
 *  bundles are made invalidates them as surely as a source change. */
export const BUILD_SCRIPT_INPUTS = [
  "launcher/bundle-manifest.json",
  "launcher/scripts/build-bundle.mjs",
  "launcher/scripts/bundle-stamp.mjs",
  "launcher/package.json",
  // The esbuild version lives here (npm rewrites it on every install).
  "launcher/node_modules/.package-lock.json",
];

/** [mtimeMs, size] of a path, or null when it does not exist. */
function defaultStat(p) {
  try {
    const s = statSync(p);
    return [s.mtimeMs, s.size];
  } catch {
    return null;
  }
}

const toPosix = (p) => p.split(sep).join("/");

/** A path with its symlinks resolved (the build knows its root as node's
 *  realpath of the script, a shell as `pwd`); the path itself if it is gone. */
const realPath = (p) => {
  try { return realpathSync(p); } catch { return resolve(p); }
};

/**
 * Every file the record covers, relative to `repoRoot`: the esbuild metafile
 * inputs (relative to the build's working directory, which build-bundle sets
 * to the repo root), each source input's package.json and tsconfig.json (the
 * nearest package.json above it, inside the repo), each node_modules tree's
 * `.package-lock.json`, and the build scripts. Sorted, deduplicated; only
 * files that exist are kept (a missing tsconfig is not an input).
 */
export function stampInputs(repoRoot, metaInputs, exists = existsSync) {
  const out = new Set();
  const add = (rel) => { if (exists(join(repoRoot, rel))) out.add(toPosix(rel)); };
  const pkgDirs = new Set();
  for (const raw of metaInputs) {
    // esbuild names a few virtual inputs (`<define:…>`, `<runtime>`); a
    // `ns:path` input is not a file either.
    if (raw.startsWith("<") || /^[a-z]+:/.test(raw)) continue;
    const rel = toPosix(isAbsolute(raw) ? relative(repoRoot, raw) : raw);
    add(rel);
    const nm = rel.split("/").indexOf("node_modules");
    if (nm >= 0) {
      add([...rel.split("/").slice(0, nm + 1), ".package-lock.json"].join("/"));
      continue;
    }
    // The nearest package.json above the file, inside the repo.
    let dir = dirname(rel);
    for (;;) {
      if (pkgDirs.has(dir)) break;
      if (exists(join(repoRoot, dir, "package.json"))) { pkgDirs.add(dir); break; }
      if (dir === "." || dir === "" || dir.startsWith("..")) break;
      dir = dirname(dir);
    }
  }
  for (const d of pkgDirs) {
    add(join(d, "package.json"));
    add(join(d, "tsconfig.json"));
  }
  for (const f of BUILD_SCRIPT_INPUTS) add(f);
  return [...out].sort();
}

/**
 * The filesystem's clock now: the mtime of a probe file written in `dir`.
 * Input mtimes come from the same clock, so "older than the build start" is
 * judged without mixing it with Date.now().
 */
export function fsClockMs(dir) {
  const probe = join(dir, `.bundle-clock-${process.pid}`);
  writeFileSync(probe, "");
  try {
    return statSync(probe).mtimeMs;
  } finally {
    try { unlinkSync(probe); } catch { /* gone */ }
  }
}

/** Remove the record (a build that is starting, or failed, leaves none). */
export function clearStamp(distDir) {
  try { unlinkSync(join(distDir, STAMP_NAME)); } catch { /* none */ }
}

/**
 * Write the record for a clean build, or decline when an input changed during
 * it. Returns null when written, else the reason it was not.
 */
export function writeStamp(distDir, { repoRoot, inputs, outputs, startMs, stat = defaultStat }) {
  const rec = { version: STAMP_VERSION, root: repoRoot, startMs, inputs: {}, outputs: {} };
  for (const rel of inputs) {
    const s = stat(join(repoRoot, rel));
    if (s === null) return `${rel} disappeared during the build`;
    if (s[0] >= startMs) return `${rel} changed during the build`;
    rec.inputs[rel] = s;
  }
  for (const rel of outputs) {
    const s = stat(join(distDir, rel));
    if (s === null) return `the output ${rel} is missing`;
    rec.outputs[rel] = s;
  }
  const path = join(distDir, STAMP_NAME);
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(rec));
  renameSync(tmp, path);
  return null;
}

/**
 * Is the bundle in `distDir` what its source would build now? Fresh only when
 * the record exists, names this repo, and every input and output it lists has
 * the mtime and size it recorded. `{ fresh: false, reason }` otherwise.
 */
export function checkStamp(distDir, { repoRoot, stat = defaultStat, readFile = (p) => readFileSync(p, "utf8") } = {}) {
  let rec;
  try {
    rec = JSON.parse(readFile(join(distDir, STAMP_NAME)));
  } catch {
    return { fresh: false, reason: "it has no build record (never built here, or its last build did not finish)" };
  }
  if (rec === null || typeof rec !== "object" || rec.version !== STAMP_VERSION
      || typeof rec.root !== "string" || rec.inputs === null || typeof rec.inputs !== "object"
      || rec.outputs === null || typeof rec.outputs !== "object") {
    return { fresh: false, reason: "its build record is from another version of the build" };
  }
  if (repoRoot !== undefined && realPath(rec.root) !== realPath(repoRoot)) {
    return { fresh: false, reason: `it was built from ${rec.root}, not ${repoRoot}` };
  }
  const same = (a, b) => Array.isArray(b) && a !== null && a[0] === b[0] && a[1] === b[1];
  const inputs = Object.entries(rec.inputs);
  if (inputs.length === 0) return { fresh: false, reason: "its build record lists no inputs" };
  for (const [rel, want] of inputs) {
    if (!same(stat(join(rec.root, rel)), want)) return { fresh: false, reason: `${rel} changed since the build` };
  }
  for (const [rel, want] of Object.entries(rec.outputs)) {
    if (!same(stat(join(distDir, rel)), want)) return { fresh: false, reason: `the built ${rel} is missing or was replaced` };
  }
  return { fresh: true, inputs: inputs.length };
}

// CLI: node bundle-stamp.mjs [--why] [--root=<repo>] <distDir>
// (exit 0 fresh, 1 stale). --root also requires the record to name that repo.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const why = args.includes("--why");
  const root = args.find((a) => a.startsWith("--root="))?.slice("--root=".length);
  const dist = args.find((a) => !a.startsWith("--"));
  if (!dist) {
    process.stderr.write("usage: bundle-stamp.mjs [--why] [--root=<repo>] <distDir>\n");
    process.exit(2);
  }
  const r = checkStamp(resolve(dist), root ? { repoRoot: resolve(root) } : {});
  if (!r.fresh && why) process.stderr.write(`${r.reason}\n`);
  process.exit(r.fresh ? 0 : 1);
}
