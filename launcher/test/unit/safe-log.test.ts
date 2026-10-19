/**
 * safe-log — every component on a log's way is checked (runtime-instances.md
 * §2, "planted paths", 2026-10-17): the pure rules, then real directories.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, closeSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { atOrBelow, dirProblem, openSafeLog, tightenedMode } from "../../src/safe-log.js";
import { stateAxes } from "../axes.js";

stateAxes("off"); // file handling only: no arbiter decides anything here

const me = process.getuid?.() ?? 1000;

test("dirProblem: the system's or this user's, never writable by every account unless sticky; at the root only this user's", () => {
  const sys = [0, 65534];
  assert.equal(dirProblem({ uid: me, mode: 0o40700 }, me, false, sys), null);
  assert.equal(dirProblem({ uid: me, mode: 0o40775 }, me, false, sys), null, "group write (umask 002, user private groups) above the root");
  assert.equal(dirProblem({ uid: 0, mode: 0o40755 }, me, false, sys), null, "root's /run");
  assert.equal(dirProblem({ uid: 65534, mode: 0o40755 }, me, false, sys), null, "an owner a user namespace does not map");
  assert.equal(dirProblem({ uid: 0, mode: 0o41777 }, me, false, sys), null, "/tmp: sticky");
  assert.match(dirProblem({ uid: 0, mode: 0o40777 }, me, false, sys) ?? "", /writable by every account/);
  assert.match(dirProblem({ uid: me + 1, mode: 0o40700 }, me, false, sys) ?? "", /owned by uid/, "another account's");
  assert.match(dirProblem({ uid: 0, mode: 0o40700 }, me, true, sys) ?? "", /not by you/, "at or below the root: this user's only");
  assert.equal(dirProblem({ uid: me + 1, mode: 0o40777 }, null, false, sys), null, "no uid: no owner checks");
});

test("tightenedMode drops group and other write only; atOrBelow is by component", () => {
  assert.equal(tightenedMode(0o40700), null);
  assert.equal(tightenedMode(0o40755), null);
  assert.equal(tightenedMode(0o40775), 0o755);
  assert.equal(tightenedMode(0o40777), 0o755);
  assert.equal(atOrBelow("/run/u/mandu", "/run/u/mandu"), true);
  assert.equal(atOrBelow("/run/u/mandu/logs", "/run/u/mandu/"), true);
  assert.equal(atOrBelow("/run/u/mandu2", "/run/u/mandu"), false);
  assert.equal(atOrBelow("/run/u", "/run/u/mandu"), false);
  assert.equal(atOrBelow("/run/u/mandu", undefined), false);
});

function tmp(): string {
  return realpathSync(mkdtempSync(join(tmpdir(), "safe-log-")));
}

test("a missing chain is made one directory at a time, 0700, and the log appended to", () => {
  const dir = tmp();
  try {
    const log = join(dir, "base", "logs", "a.log");
    for (const line of ["one\n", "two\n"]) {
      const fd = openSafeLog(log);
      writeSync(fd, line);
      closeSync(fd);
    }
    assert.equal(readFileSync(log, "utf8"), "one\ntwo\n");
    for (const d of [join(dir, "base"), join(dir, "base", "logs")]) assert.equal(statSync(d).mode & 0o777, 0o700, d);
    const fd = openSafeLog(log, { truncate: true });
    closeSync(fd);
    assert.equal(readFileSync(log, "utf8"), "", "truncate empties it after the checks");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a logs/ that is a link to a folder gets nothing: refused, the folder untouched", () => {
  const dir = tmp();
  try {
    const victim = join(dir, "victim");
    mkdirSync(victim);
    writeFileSync(join(victim, "keep"), "keep\n");
    mkdirSync(join(dir, "base"), { mode: 0o700 });
    symlinkSync(victim, join(dir, "base", "logs"));
    assert.throws(() => openSafeLog(join(dir, "base", "logs", "a.log")), /base\/logs is a symbolic link on the way to the log/);
    assert.deepEqual(readdirSync(victim), ["keep"], "no log made in the linked-to folder");
    // A dangling one: its target is not made (the old `mkdir -p` made it).
    symlinkSync(join(dir, "absent", "deeper"), join(dir, "base", "logs2"));
    assert.throws(() => openSafeLog(join(dir, "base", "logs2", "a.log")), /symbolic link on the way/);
    assert.equal(existsSync(join(dir, "absent")), false);
    // A link of this user's higher up, too.
    symlinkSync(join(dir, "base"), join(dir, "base-link"));
    assert.throws(() => openSafeLog(join(dir, "base-link", "x.log")), /base-link is a symbolic link on the way/);
    assert.equal(existsSync(join(dir, "base", "x.log")), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("at the root: a shared directory of this user's is tightened on its descriptor, and left alone without one", () => {
  const dir = tmp();
  try {
    const base = join(dir, "base");
    mkdirSync(join(base, "logs"), { recursive: true });
    chmodSync(base, 0o700);
    chmodSync(join(base, "logs"), 0o775);
    closeSync(openSafeLog(join(base, "logs", "a.log"), { root: base }));
    assert.equal(statSync(join(base, "logs")).mode & 0o777, 0o755, "group write dropped");
    // Without the root, the same directory is left as it is.
    chmodSync(join(base, "logs"), 0o775);
    closeSync(openSafeLog(join(base, "logs", "a.log")));
    assert.equal(statSync(join(base, "logs")).mode & 0o777, 0o775);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("at the name: a link, a hard link to someone's file, a FIFO, or a directory is refused", () => {
  const dir = tmp();
  try {
    const victim = join(dir, "victim.rc");
    writeFileSync(victim, "keep me\n");
    symlinkSync(victim, join(dir, "linked.log"));
    assert.throws(() => openSafeLog(join(dir, "linked.log")), /is a symbolic link; refusing to write through it/);
    assert.equal(readFileSync(victim, "utf8"), "keep me\n");
    mkdirSync(join(dir, "d.log"));
    assert.throws(() => openSafeLog(join(dir, "d.log")));
    assert.ok(lstatSync(join(dir, "d.log")).isDirectory());
    assert.throws(() => openSafeLog("relative/a.log"), /absolute, normalized/);
    assert.throws(() => openSafeLog(`${dir}/x/../a.log`), /absolute, normalized/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
