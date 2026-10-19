/**
 * launch-cwd — the directory a launch is for is the REAL cwd; `$PWD` only
 * spells it (packaging.md §1, "The launch directory"). A PWD naming another
 * folder (a script's chdir without exporting PWD, `subprocess.run(cwd=…)`)
 * must never move the launch there.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { REAL_LAUNCH_CWD_DEPS, resolveLaunchCwd, type LaunchCwdDeps } from "../../src/launch-cwd.js";
import { parse } from "../../src/parse.js";
import { stateAxes } from "../axes.js";

stateAxes("off"); // pure path resolution; no arbiter, no axis involved

/** A fake filesystem: path → inode; the real cwd is `cwd`. */
function fake(cwd: string, inodes: Record<string, number>): LaunchCwdDeps {
  return {
    cwd: () => cwd,
    stat: (p) => (p in inodes ? { dev: 1, ino: inodes[p]! } : null),
  };
}

const FS = { "/real/proj": 10, "/home/u/proj": 10, "/other": 20 };

test("PWD equal to the real cwd: the real cwd", () => {
  assert.equal(resolveLaunchCwd("/real/proj", fake("/real/proj", FS)), "/real/proj");
});

test("PWD a symlinked spelling of the same directory: kept (the human's spelling)", () => {
  assert.equal(resolveLaunchCwd("/home/u/proj", fake("/real/proj", FS)), "/home/u/proj");
});

test("PWD naming ANOTHER directory: ignored, the real cwd wins", () => {
  assert.equal(resolveLaunchCwd("/other", fake("/real/proj", FS)), "/real/proj");
});

test("PWD unset or empty: the real cwd", () => {
  assert.equal(resolveLaunchCwd(undefined, fake("/real/proj", FS)), "/real/proj");
  assert.equal(resolveLaunchCwd("", fake("/real/proj", FS)), "/real/proj");
});

test("PWD relative or not normal: ignored even when it would name the same directory", () => {
  const deps: LaunchCwdDeps = { cwd: () => "/real/proj", stat: () => ({ dev: 1, ino: 10 }) };
  for (const pwd of ["proj", "./proj", "/real/./proj", "/real/x/../proj", "/real/proj/", "//real/proj"]) {
    assert.equal(resolveLaunchCwd(pwd, deps), "/real/proj", pwd);
  }
});

test("PWD that does not exist: the real cwd", () => {
  assert.equal(resolveLaunchCwd("/gone/proj", fake("/real/proj", FS)), "/real/proj");
});

test("same inode on another device is another directory", () => {
  const deps: LaunchCwdDeps = {
    cwd: () => "/real/proj",
    stat: (p) => (p === "/real/proj" ? { dev: 1, ino: 10 } : { dev: 2, ino: 10 }),
  };
  assert.equal(resolveLaunchCwd("/mnt/proj", deps), "/real/proj");
});

test("a removed cwd refuses with a plain message (no folder to launch for)", () => {
  const deps: LaunchCwdDeps = { cwd: () => { throw new Error("ENOENT: uv_cwd"); }, stat: () => null };
  assert.throws(() => resolveLaunchCwd("/real/proj", deps), /the current directory no longer exists/);
});

test("on the real filesystem: a symlink spelling is kept, a stale PWD is not", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "mandu-launch-cwd-")));
  try {
    const proj = join(root, "proj");
    const other = join(root, "other");
    mkdirSync(proj);
    mkdirSync(other);
    symlinkSync(proj, join(root, "link"));
    const deps: LaunchCwdDeps = { ...REAL_LAUNCH_CWD_DEPS, cwd: () => proj };
    assert.equal(resolveLaunchCwd(join(root, "link"), deps), join(root, "link"));
    assert.equal(resolveLaunchCwd(other, deps), proj);
    assert.equal(resolveLaunchCwd(join(root, "nope"), deps), proj);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("parse(): the plan's cwd and humanCwd are the real cwd, not a PWD naming another folder", () => {
  const p = parse(["--", "claude"], { PWD: "/nonexistent/mandu-launch-cwd-elsewhere", XDG_RUNTIME_DIR: "/run/u" });
  assert.equal(p.cwd, process.cwd());
  assert.equal(p.humanCwd, process.cwd());
  // An in-process caller's explicit launch directory wins over both.
  const q = parse(["--", "claude"], { PWD: "/elsewhere", XDG_RUNTIME_DIR: "/run/u" }, "/w");
  assert.equal(q.cwd, "/w");
  assert.equal(q.humanCwd, "/w");
});
