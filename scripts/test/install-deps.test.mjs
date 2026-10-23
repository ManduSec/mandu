// Tests for scripts/install-deps.mjs: every package that compiles another
// package's sources declares it in "mandu.siblings" and installs it before its
// typecheck and tests, so `npm run typecheck` works in a fresh worktree (a
// bare "Cannot find module 'js-yaml'" in arbiter/ from tests/integration (now tests/) was
// the failure, 2026-09-30). Run: node --test <this file>.
// docs-lane-exempt: its one `git ls-files` lists package-lock.json files,
// which a docs-only change cannot touch.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

import { tmpDir } from "./lib/tmp-dir.mjs";
import {
  REPO_ROOT, acquireLock, declaredSiblings, installCommand, installDirs, installMissing, lockPath, missingDirs, reachedPackages,
} from "../install-deps.mjs";
import { bundlePackageDirs } from "../suites.mjs";

const SCRIPT = join(REPO_ROOT, "scripts", "install-deps.mjs");
/** The pre-script a package at `dir` runs: install-deps by its path from the package. */
const hookFor = (dir) => `node ${relative(dir, SCRIPT)}`;

function packageDirs() {
  const r = spawnSync(process.execPath, [join(REPO_ROOT, "scripts", "suites.mjs"), "packages"], { cwd: REPO_ROOT, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.split("\n").filter(Boolean);
}

// ── the repo's own packages ─────────────────────────────────────────────────

test("every package declares each sibling package its imports reach, and installs them first", () => {
  const dirs = packageDirs();
  assert.ok(dirs.includes("tests"), "the manifest lists tests");
  const reachedBy = {};
  for (const rel of dirs) {
    const dir = join(REPO_ROOT, rel);
    const reached = reachedPackages(REPO_ROOT, dir);
    reachedBy[rel] = reached;
    const declared = declaredSiblings(dir);
    const undeclared = reached.filter((p) => !declared.includes(p));
    assert.deepEqual(undeclared, [], `${rel} imports sources of ${undeclared.join(", ")}: add them to "mandu.siblings" in ${rel}/package.json`);
    for (const s of declared) {
      assert.ok(existsSync(join(REPO_ROOT, s, "package.json")), `${rel} declares sibling ${s}, which has no package.json`);
    }
    if (declared.length) {
      const scripts = readPkg(dir).scripts ?? {};
      for (const hook of ["pretypecheck", "pretest"]) {
        if (!scripts[hook.slice(3)]) continue;
        assert.equal(scripts[hook], hookFor(dir), `${rel}: "${hook}" must run install-deps (its siblings must be installed before "${hook.slice(3)}")`);
      }
    }
  }
  // The scan itself: the known cross-package reaches stay found.
  for (const p of ["arbiter", "dashboard", "interceptors/net-proxy"]) {
    assert.ok(reachedBy.tests.includes(p), `tests reaches ${p}`);
  }
  // tests/conformance is a package of its own inside tests/: its files are not tests/'s.
  assert.ok(!reachedBy.tests.includes("tests/conformance"), "a nested package's files are its own");
  assert.deepEqual(reachedBy["interceptors/openclaw-inspect-plugin"], ["interceptors/inspect-mcp"]);
  assert.deepEqual(reachedBy.arbiter, [], "the arbiter compiles only its own sources");
});

test("a package that starts the real arbiter declares it, though no import reaches it", () => {
  // The import scan cannot see a spawned entry point: the dashboard's
  // supervisor runs arbiter/ipc/server-main.ts through arbiter's own tsx
  // (named `"ipc/server-main.ts"` relative to arbiter/ until 2026-10-04, now
  // `"arbiter/ipc/server-main.ts"` from the repo root, packaging.md §5.1),
  // and its supervisor-home e2e failed in a fresh worktree on a missing
  // arbiter/node_modules (2026-09-30). The launcher's own source spawns are
  // the next test's (tests/, which runs the launcher, declares them).
  const spawnsArbiter = (rel) => ["src", "test"]
    .filter((sub) => existsSync(join(REPO_ROOT, rel, sub)))
    .flatMap((sub) => readdirSync(join(REPO_ROOT, rel, sub), { recursive: true })
      .filter((f) => /\.(ts|mjs)$/.test(f))
      .map((f) => join(REPO_ROOT, rel, sub, f)))
    .some((file) => /"(arbiter\/)?ipc\/server-main\.ts"/.test(readFileSync(file, "utf8")));
  const spawning = packageDirs().filter((rel) => rel !== "arbiter" && rel !== "launcher" && spawnsArbiter(rel));
  assert.ok(spawning.includes("dashboard"), "the scan finds the dashboard supervisor's arbiter spawn");
  for (const rel of spawning) {
    assert.ok(declaredSiblings(join(REPO_ROOT, rel)).includes("arbiter"),
      `${rel}'s tests start arbiter/ipc/server-main.ts: add "arbiter" to "mandu.siblings" in ${rel}/package.json`);
  }
});

test("tests/, which runs the launcher from source, declares every package the launcher runs from source", () => {
  // The drill replay and the live suites start launcher/src/run.ts, which
  // runs the interceptors from their checkouts with each package's own tsx
  // (launcher/src/services/layout.ts devTsx). No import reaches them, so a
  // fresh worktree left interceptors/exec-wrap uninstalled: every curl shim
  // of a replay died on a missing tsx, nothing reached the sink, and
  // conf-bound-host-release graded the Mandu side as never sending
  // (2026-10-04).
  const files = readdirSync(join(REPO_ROOT, "launcher", "src"), { recursive: true })
    .filter((f) => /\.ts$/.test(f))
    .map((f) => readFileSync(join(REPO_ROOT, "launcher", "src", f), "utf8"));
  const run = new Set();
  for (const text of files) {
    for (const m of text.matchAll(/"interceptors",\s*"([a-z0-9-]+)"/g)) run.add(`interceptors/${m[1]}`);
    for (const m of text.matchAll(/join\(this\.repoRoot,\s*"([a-z0-9-]+)"\)/g)) run.add(m[1]);
    for (const m of text.matchAll(/\.daemon\("[a-z0-9-]+",\s*"([a-z0-9-]+)"/g)) run.add(m[1]);
  }
  const pkgs = [...run].filter((p) => existsSync(join(REPO_ROOT, p, "package.json"))).sort();
  for (const p of ["interceptors/exec-wrap", "interceptors/reply-filter", "interceptors/net-proxy", "fs-sync", "arbiter"]) {
    assert.ok(pkgs.includes(p), `the scan finds the launcher running ${p}`);
  }
  const declared = declaredSiblings(join(REPO_ROOT, "tests"));
  const missing = pkgs.filter((p) => !declared.includes(p));
  assert.deepEqual(missing, [], `the launcher runs ${missing.join(", ")} from source: add them to "mandu.siblings" in tests/package.json`);
});

test("every committed lockfile's root entry matches its package.json, so an install leaves it unchanged", () => {
  // npm rewrites a lockfile whose root entry disagrees with package.json; the
  // openclaw-inspect-plugin's lacked the "license" field, so every install
  // there dirtied the main checkout and the maintainers' updater refused the next
  // update (2026-10-01).
  const r = spawnSync("git", ["ls-files", "*package-lock.json"], { cwd: REPO_ROOT, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const locks = r.stdout.split("\n").filter(Boolean);
  assert.ok(locks.includes("arbiter/package-lock.json"), "the scan finds the arbiter's lockfile");
  for (const lock of locks) {
    const pkg = readPkg(join(REPO_ROOT, lock, ".."));
    const root = JSON.parse(readFileSync(join(REPO_ROOT, lock), "utf8")).packages?.[""] ?? {};
    for (const key of ["name", "version", "license", "dependencies", "devDependencies", "optionalDependencies"]) {
      assert.deepEqual(root[key], pkg[key], `${lock}: "${key}" differs from package.json; run npm install --package-lock-only there and commit it`);
    }
  }
});

function readPkg(dir) {
  return JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
}

// ── a scratch repo ──────────────────────────────────────────────────────────

function scratchRepo() {
  const root = tmpDir("mandu-install-deps-");
  const pkg = (rel, body = {}, files = {}) => {
    const dir = join(root, rel);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: rel.replace(/\//g, "-"), ...body }));
    for (const [f, text] of Object.entries(files)) {
      mkdirSync(join(dir, f, ".."), { recursive: true });
      writeFileSync(join(dir, f), text);
    }
    return dir;
  };
  return { root, pkg };
}

test("reachedPackages follows relative imports transitively and ignores bare ones", () => {
  const { root, pkg } = scratchRepo();
  const a = pkg("a", {}, { "src/x.ts": `import { y } from "../../b/src/y.js";\nimport yaml from "js-yaml";\n` });
  pkg("b", {}, { "src/y.ts": `export { z } from "../../c/z.js";\nexport const y = 1;\n` });
  pkg("c", {}, { "z.ts": `export const z = await import("./deep/w.js");\n`, "deep/w.ts": "export {};\n" });
  pkg("d", {}, { "unused.ts": "export {};\n" });
  // A file with no owning package (like scripts/) is followed but not counted.
  mkdirSync(join(root, "loose"), { recursive: true });
  writeFileSync(join(root, "loose", "l.mjs"), `import "../d/unused.ts";\n`);
  writeFileSync(join(a, "src", "side.ts"), `import "../../loose/l.mjs";\n`);
  assert.deepEqual(reachedPackages(root, a), ["b", "c", "d"]);
});

test("a package nested inside another is its own: its files are not the outer package's", () => {
  // tests/ holds tests/conformance (test-reorganization.md §5.3): the outer
  // package does not reach what only the nested one imports.
  const { root, pkg } = scratchRepo();
  const outer = pkg("tests", {}, { "stack/s.ts": `import "../../b/y.js";\n` });
  pkg("tests/conformance", {}, { "run.ts": `import "../../c/z.js";\n` });
  pkg("b", {}, { "y.ts": "export {};\n" });
  pkg("c", {}, { "z.ts": "export {};\n" });
  assert.deepEqual(reachedPackages(root, outer), ["b"]);
  assert.deepEqual(reachedPackages(root, join(root, "tests", "conformance")), ["c"]);
});

test("missingDirs lists the package and its declared siblings without node_modules", () => {
  const { root, pkg } = scratchRepo();
  const b = pkg("b");
  const a = pkg("a", { mandu: { siblings: ["b", "c"] } });
  pkg("c");
  mkdirSync(join(root, "c", "node_modules"));
  assert.deepEqual(missingDirs(root, a), [a, b]);
});

test("a declared sibling with no package.json is an error, not a silent skip", () => {
  const { root, pkg } = scratchRepo();
  const a = pkg("a", { mandu: { siblings: ["nope"] } });
  assert.throws(() => missingDirs(root, a), /sibling nope .*has no package\.json/);
  const bad = pkg("bad", { mandu: { siblings: "b" } });
  assert.throws(() => declaredSiblings(bad), /must be an array/);
});

test("installMissing runs npm ci where a lockfile exists, npm install otherwise, and only once", () => {
  const { root, pkg } = scratchRepo();
  const b = pkg("b");
  writeFileSync(join(b, "package-lock.json"), "{}");
  const a = pkg("a", { mandu: { siblings: ["b"] } });
  assert.deepEqual(installCommand(b), ["npm", "ci", "--no-audit", "--no-fund"]);
  assert.deepEqual(installCommand(a), ["npm", "install", "--no-audit", "--no-fund"]);
  const calls = [];
  const run = (cmd, cwd) => { calls.push([cmd[1], cwd]); mkdirSync(join(cwd, "node_modules")); return 0; };
  const lockRoot = tmpDir("mandu-install-deps-locks-");
  assert.deepEqual(installMissing(root, a, { run, lockRoot, log: () => {} }), [a, b]);
  assert.deepEqual(calls, [["install", a], ["ci", b]]);
  assert.deepEqual(installMissing(root, a, { run, lockRoot, log: () => {} }), [], "a second run installs nothing");
  assert.equal(calls.length, 2);
});

test("installDirs installs exactly the dirs it is given (root-relative or absolute), each once, no siblings", () => {
  const { root, pkg } = scratchRepo();
  const a = pkg("a", { mandu: { siblings: ["c"] } });
  const b = pkg("nested/b");
  writeFileSync(join(b, "package-lock.json"), "{}");
  pkg("c");
  const lockRoot = tmpDir("mandu-install-deps-locks-");
  const calls = [];
  const run = (cmd, cwd) => { calls.push([cmd[1], cwd]); mkdirSync(join(cwd, "node_modules")); return 0; };
  assert.deepEqual(installDirs(root, ["a", b], { run, lockRoot, log: () => {} }), [a, b]);
  assert.deepEqual(calls, [["install", a], ["ci", b]], "c, a's declared sibling, is not installed");
  assert.deepEqual(installDirs(root, ["a", "nested/b"], { run, lockRoot, log: () => {} }), [], "a second run installs nothing");
});

test("--bundle: the launcher bundle's packages (suites.mjs packages --bundle); MANDU_NO_AUTO_INSTALL=1 names the missing ones, runs no npm", () => {
  const dirs = bundlePackageDirs(REPO_ROOT);
  for (const d of ["arbiter", "dashboard", "launcher", "interceptors/anthropic-proxy"]) assert.ok(dirs.includes(d), d);
  const { bin, log } = fakeNpm();
  const r = spawnSync(process.execPath, [SCRIPT, "--bundle"], {
    encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, MANDU_NO_AUTO_INSTALL: "1" },
  });
  const missing = dirs.filter((d) => !existsSync(join(REPO_ROOT, d, "node_modules")));
  assert.equal(r.status, missing.length ? 1 : 0, r.stderr);
  assert.deepEqual([...r.stderr.matchAll(/install-deps: (\S+): node_modules missing/g)].map((m) => m[1]), missing);
  assert.equal(existsSync(log), false, "npm never ran");
});

test("a failed install throws and releases its lock", () => {
  const { root, pkg } = scratchRepo();
  const a = pkg("a");
  const lockRoot = tmpDir("mandu-install-deps-locks-");
  assert.throws(() => installMissing(root, a, { run: () => 7, lockRoot, log: () => {} }), /'npm install --no-audit --no-fund' failed in a \(exit 7\)/);
  const release = acquireLock(a, { lockRoot, timeoutMs: 1000 });
  release();
});

test("the lock waits for a live holder and takes over a dead one's", () => {
  const { pkg } = scratchRepo();
  const a = pkg("a");
  const lockRoot = tmpDir("mandu-install-deps-locks-");
  const release = acquireLock(a, { lockRoot });
  assert.throws(() => acquireLock(a, { lockRoot, timeoutMs: 300, pollMs: 50 }), /timed out waiting for the install lock/);
  release();

  // A holder that died without releasing: its pid is gone, the lock is taken over.
  const dead = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], { encoding: "utf8" });
  const held = acquireLock(a, { lockRoot });
  const lockDir = readdirLock(lockRoot);
  writeFileSync(join(lockDir, "pid"), dead.stdout);
  const again = acquireLock(a, { lockRoot, timeoutMs: 2000, pollMs: 50 });
  again();
  held(); // already gone; releasing twice is harmless
});

test("the install lock is named per user: another account's lock for the same checkout is a different name", () => {
  const { pkg } = scratchRepo();
  const a = pkg("a");
  const lockRoot = tmpDir("mandu-install-deps-locks-");
  assert.match(lockPath(a, lockRoot, 1007), /\/mandu-npm-install-1007-[0-9a-f]{16}\.lock$/);
  assert.notEqual(lockPath(a, lockRoot, 1007), lockPath(a, lockRoot, 1008), "one checkout, two accounts, two locks");
  assert.equal(lockPath(a, lockRoot, 1007), lockPath(a, lockRoot, 1007));
  // Another account's lock (a live holder: this process) does not hold this one up.
  if (typeof process.getuid === "function") {
    const other = lockPath(a, lockRoot, process.getuid() + 1);
    mkdirSync(other);
    writeFileSync(join(other, "pid"), String(process.pid));
    const release = acquireLock(a, { lockRoot, timeoutMs: 300, pollMs: 50 });
    assert.ok(existsSync(lockPath(a, lockRoot)), "this account's own lock is taken");
    release();
  }
});

function readdirLock(lockRoot) {
  return join(lockRoot, readdirSync(lockRoot).find((n) => n.endsWith(".lock")));
}

test("installMissing waits while another run installs a dir, then skips it", async () => {
  const { root, pkg } = scratchRepo();
  const a = pkg("a", { mandu: { siblings: ["b"] } });
  const b = pkg("b");
  mkdirSync(join(a, "node_modules"));
  const lockRoot = tmpDir("mandu-install-deps-locks-");
  // Another process holds b's lock, with node_modules half written, for ~400 ms.
  const holder = spawn(process.execPath, ["--input-type=module", "-e", `
    import { acquireLock } from ${JSON.stringify(SCRIPT)};
    import { mkdirSync } from "node:fs";
    const release = acquireLock(${JSON.stringify(b)}, { lockRoot: ${JSON.stringify(lockRoot)} });
    mkdirSync(${JSON.stringify(join(b, "node_modules"))});
    process.stdout.write("held\\n");
    setTimeout(() => { release(); }, 400);
  `], { stdio: ["ignore", "pipe", "inherit"] });
  await new Promise((res) => holder.stdout.once("data", res));
  const t0 = Date.now();
  const calls = [];
  installMissing(root, a, { run: (cmd, cwd) => { calls.push(cwd); return 0; }, lockRoot, log: () => {} });
  assert.ok(Date.now() - t0 >= 250, "the run waited for the holder's lock");
  assert.deepEqual(calls, [], "the dir the holder installed is not installed again");
  await new Promise((res) => holder.on("exit", res));
});

// ── the CLI ─────────────────────────────────────────────────────────────────

function fakeNpm() {
  const bin = tmpDir("mandu-install-deps-bin-");
  const log = join(bin, "calls.log");
  writeFileSync(join(bin, "npm"), `#!/bin/sh\necho "$PWD $*" >> ${JSON.stringify(log)}\nmkdir -p node_modules\n`);
  chmodSync(join(bin, "npm"), 0o755);
  return { bin, log };
}

test("the CLI installs a fresh repo package's siblings from the package's own dir (the pretypecheck form)", () => {
  // Runs against the real repo layout copied as package.json-only stubs, so
  // nothing touches the checkout's node_modules.
  const { root, pkg } = scratchRepo();
  const sibs = declaredSiblings(join(REPO_ROOT, "tests"));
  for (const s of sibs) pkg(s);
  mkdirSync(join(root, "scripts"));
  writeFileSync(join(root, "scripts", "install-deps.mjs"), readFileSync(SCRIPT));
  const integ = pkg("tests", { mandu: { siblings: sibs } });
  mkdirSync(join(integ, "node_modules"));
  const { bin, log } = fakeNpm();
  const r = spawnSync(process.execPath, ["../scripts/install-deps.mjs"], {
    cwd: integ, encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, MANDU_NO_AUTO_INSTALL: "" },
  });
  assert.equal(r.status, 0, r.stderr);
  const calls = readFileSync(log, "utf8").trim().split("\n");
  assert.deepEqual(calls.map((l) => l.split(" ")[0]), sibs.map((s) => join(root, s)));
  assert.match(r.stderr, /install-deps: arbiter: node_modules missing, running 'npm install --no-audit --no-fund'/);
});

test("MANDU_NO_AUTO_INSTALL=1 reports what is missing and installs nothing", () => {
  const { root, pkg } = scratchRepo();
  pkg("b");
  const a = pkg("a", { mandu: { siblings: ["b"] } });
  mkdirSync(join(a, "node_modules"));
  mkdirSync(join(root, "scripts"));
  writeFileSync(join(root, "scripts", "install-deps.mjs"), readFileSync(SCRIPT));
  const { bin, log } = fakeNpm();
  const r = spawnSync(process.execPath, [join(root, "scripts", "install-deps.mjs"), a], {
    encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, MANDU_NO_AUTO_INSTALL: "1" },
  });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /b: node_modules missing \(MANDU_NO_AUTO_INSTALL=1: not installing\)/);
  assert.equal(existsSync(log), false, "npm never ran");
});

test("a failing npm fails the CLI with the package named", () => {
  const { root, pkg } = scratchRepo();
  const a = pkg("a");
  mkdirSync(join(root, "scripts"));
  writeFileSync(join(root, "scripts", "install-deps.mjs"), readFileSync(SCRIPT));
  const bin = tmpDir("mandu-install-deps-bin-");
  writeFileSync(join(bin, "npm"), "#!/bin/sh\nexit 3\n");
  chmodSync(join(bin, "npm"), 0o755);
  const r = spawnSync(process.execPath, [join(root, "scripts", "install-deps.mjs"), a], {
    encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, MANDU_NO_AUTO_INSTALL: "" },
  });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /failed in a \(exit 3\)/);
});
