#!/usr/bin/env node
// Install a TS package's node_modules and those of the sibling packages whose
// sources it compiles. There is no repo-root workspace: tests/ (and a few
// others) import other packages' sources, and node resolves a bare import
// such as `js-yaml` from the importing file's own package, so `tsc` and `tsx`
// in tests/ need arbiter/, dashboard/, net-proxy/... installed too.
// scripts/test-all.sh and CI install every package first; this covers the
// by-hand `npm run typecheck` / `npm test` in a fresh worktree, where the
// failure was a bare "Cannot find module 'js-yaml'" in a file of another
// package (docs/development.md "Per package").
//
// The siblings are declared in the package's package.json, repo-root-relative:
//   "mandu": { "siblings": ["arbiter", "dashboard", ...] }
// and scripts/test/install-deps.test.mjs keeps the list equal to what the
// package's relative imports actually reach (`reachedPackages` below).
//
// Usage (the package's `pretypecheck` / `pretest` scripts run it):
//   node ../../scripts/install-deps.mjs            # cwd = the package (../ from tests/)
//   node scripts/install-deps.mjs <package-dir>    # from the repo root
//   node scripts/install-deps.mjs --reach <dir>    # print the siblings its imports reach
// A package counts as installed when its node_modules exists (test-all.sh's
// rule). A missing one gets `npm ci` (a lockfile exists) or `npm install`.
// MANDU_NO_AUTO_INSTALL=1 only reports what is missing (exit 1). Concurrent
// runs (two packages' typechecks under run-suites --jobs) take a per-package,
// per-user lock, so one npm writes a given node_modules.
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function readPkg(dir) {
  return JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
}

/** The package's declared siblings, repo-root-relative, as written. */
export function declaredSiblings(pkgDir) {
  const m = readPkg(pkgDir).mandu ?? {};
  const out = [];
  // `privateSiblings`: siblings outside the public tree, which a file only the
  // source repository has (the drill suite) reaches; the export strips the
  // list (public-strip), so a public checkout names none.
  for (const key of ["siblings", "privateSiblings"]) {
    const s = m[key] ?? [];
    if (!Array.isArray(s) || s.some((x) => typeof x !== "string")) {
      throw new Error(`${join(pkgDir, "package.json")}: "mandu.${key}" must be an array of repo-relative paths`);
    }
    out.push(...s);
  }
  return out;
}

/** The dirs (the package first, then its siblings) whose node_modules is missing. */
export function missingDirs(root, pkgDir) {
  const dirs = [pkgDir, ...declaredSiblings(pkgDir).map((s) => resolve(root, s))];
  for (const d of dirs) {
    if (!existsSync(join(d, "package.json"))) {
      throw new Error(`sibling ${relative(root, d) || "."} (declared by ${relative(root, pkgDir)}) has no package.json`);
    }
  }
  return dirs.filter((d) => !existsSync(join(d, "node_modules")));
}

/** The npm command that installs `dir`: lockfile-exact where a lockfile exists. */
export function installCommand(dir) {
  return existsSync(join(dir, "package-lock.json"))
    ? ["npm", "ci", "--no-audit", "--no-fund"]
    : ["npm", "install", "--no-audit", "--no-fund"];
}

function sleepMs(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function pidAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === "EPERM"; }
}

/**
 * The install lock of `dir` under `lockRoot`: named per user
 * (`mandu-npm-install-<uid>-<hash>.lock`), so two accounts installing the same
 * checkout path (a shared host's /tmp) never wait on each other's lock, nor
 * find one they cannot remove, as the runtime dir's `mandu-<uid>` (2026-10-09).
 */
export function lockPath(dir, lockRoot = tmpdir(), uid = typeof process.getuid === "function" ? process.getuid() : null) {
  const hash = createHash("sha256").update(resolve(dir)).digest("hex").slice(0, 16);
  return join(lockRoot, `mandu-npm-install-${uid === null ? "" : `${uid}-`}${hash}.lock`);
}

/**
 * Take the per-package install lock (a mkdir under `lockRoot`), waiting while a
 * live process holds it; a lock whose holder is gone is taken over. Returns the
 * release function.
 */
export function acquireLock(dir, { lockRoot = tmpdir(), timeoutMs = 15 * 60_000, pollMs = 200 } = {}) {
  const lock = lockPath(dir, lockRoot);
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      mkdirSync(lock);
      writeFileSync(join(lock, "pid"), String(process.pid));
      return () => rmSync(lock, { recursive: true, force: true });
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
    }
    let holder = NaN;
    try { holder = Number(readFileSync(join(lock, "pid"), "utf8")); } catch { /* being written */ }
    if (Number.isInteger(holder) && holder > 0 && !pidAlive(holder)) {
      rmSync(lock, { recursive: true, force: true });
      continue;
    }
    if (Date.now() > deadline) throw new Error(`timed out waiting for the install lock ${lock}`);
    sleepMs(pollMs);
  }
}

function defaultRun(cmd, cwd) {
  const r = spawnSync(cmd[0], cmd.slice(1), { cwd, stdio: ["ignore", process.stderr, process.stderr] });
  return r.status ?? 1;
}

/**
 * Install every missing dir, one at a time, each under its lock. Every dir,
 * installed or not, is checked under its lock: npm creates node_modules at the
 * start of an install, so a present node_modules whose lock is held is one
 * still being written, and the run waits for it. Returns the dirs it
 * installed; throws on a failed install.
 */
export function installMissing(root, pkgDir, { run = defaultRun, lockRoot, log = (m) => process.stderr.write(`${m}\n`) } = {}) {
  missingDirs(root, pkgDir); // validates the declared siblings before any lock
  const done = [];
  for (const dir of [pkgDir, ...declaredSiblings(pkgDir).map((s) => resolve(root, s))]) {
    const release = acquireLock(dir, { lockRoot });
    try {
      if (existsSync(join(dir, "node_modules"))) continue;
      const cmd = installCommand(dir);
      log(`install-deps: ${relative(root, dir)}: node_modules missing, running '${cmd.join(" ")}'`);
      const status = run(cmd, dir);
      if (status !== 0) throw new Error(`'${cmd.join(" ")}' failed in ${relative(root, dir)} (exit ${status})`);
      done.push(dir);
    } finally {
      release();
    }
  }
  return done;
}

// ── the reach check: which packages a package's relative imports compile ────
const SOURCE_EXT = /\.(?:ts|mts|tsx|mjs|js)$/;
const SKIP_DIRS = new Set(["node_modules", "dist", "target", ".git", "coverage"]);
const IMPORT_RE = /\b(?:import|export)\s[^'";]*?\bfrom\s*["']([^"']+)["']|\bimport\s*\(\s*["']([^"']+)["']\s*\)|\bimport\s+["']([^"']+)["']/g;

/** The package's own source files: a nested directory with its own
 *  package.json is another package (tests/conformance inside tests/), whose
 *  files are its own and are reached only through an import. */
function* sourceFiles(dir) {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    if (ent.isDirectory()) {
      const sub = join(dir, ent.name);
      if (!SKIP_DIRS.has(ent.name) && !existsSync(join(sub, "package.json"))) yield* sourceFiles(sub);
    } else if (ent.isFile() && SOURCE_EXT.test(ent.name) && !ent.name.endsWith(".d.ts")) {
      yield join(dir, ent.name);
    }
  }
}

function isFile(p) {
  try { return statSync(p).isFile(); } catch { return false; }
}

function resolveRelative(from, spec) {
  const base = resolve(dirname(from), spec);
  const cands = [];
  if (/\.js$/.test(base)) cands.push(base.replace(/\.js$/, ".ts"), base.replace(/\.js$/, ".tsx"), base);
  else if (/\.mjs$/.test(base)) cands.push(base.replace(/\.mjs$/, ".mts"), base);
  else cands.push(base, `${base}.ts`, `${base}.js`, join(base, "index.ts"), join(base, "index.js"));
  return cands.find(isFile) ?? null;
}

/** The nearest dir at or above `file`'s dir (inside `root`) holding a package.json, or null. */
function owningPackage(root, file) {
  for (let d = dirname(file); d.startsWith(root + sep) || d === root; d = dirname(d)) {
    if (d === root) return null;
    if (existsSync(join(d, "package.json"))) return d;
  }
  return null;
}

/**
 * The other packages (repo-root-relative, sorted) whose files `pkgDir`'s
 * sources reach through relative imports, followed transitively. Bare
 * specifiers (npm packages, node: builtins) are not followed; they resolve in
 * whichever package holds the importing file, which is why that package must
 * be installed.
 */
export function reachedPackages(root, pkgDir) {
  root = resolve(root); pkgDir = resolve(pkgDir);
  const seen = new Set();
  const queue = [...sourceFiles(pkgDir)];
  const pkgs = new Set();
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    if (file.split(sep).includes("node_modules")) continue;
    const owner = owningPackage(root, file);
    if (owner && owner !== pkgDir) pkgs.add(relative(root, owner));
    let text;
    try { text = readFileSync(file, "utf8"); } catch { continue; }
    for (const m of text.matchAll(IMPORT_RE)) {
      const spec = m[1] ?? m[2] ?? m[3];
      if (!spec.startsWith(".")) continue;
      const target = resolveRelative(file, spec);
      if (target && (target.startsWith(root + sep)) && !seen.has(target)) queue.push(target);
    }
  }
  return [...pkgs].sort();
}

function main(argv) {
  if (argv[0] === "--reach") {
    const dir = resolve(argv[1] ?? ".");
    for (const p of reachedPackages(REPO_ROOT, dir)) process.stdout.write(`${p}\n`);
    return 0;
  }
  const pkgDir = resolve(argv[0] ?? ".");
  if (!existsSync(join(pkgDir, "package.json"))) {
    process.stderr.write(`install-deps: ${pkgDir} has no package.json\n`);
    return 2;
  }
  if (process.env.MANDU_NO_AUTO_INSTALL === "1") {
    const missing = missingDirs(REPO_ROOT, pkgDir);
    for (const d of missing) process.stderr.write(`install-deps: ${relative(REPO_ROOT, d)}: node_modules missing (MANDU_NO_AUTO_INSTALL=1: not installing)\n`);
    return missing.length ? 1 : 0;
  }
  try {
    installMissing(REPO_ROOT, pkgDir);
    return 0;
  } catch (e) {
    process.stderr.write(`install-deps: ${e.message}\n`);
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}
