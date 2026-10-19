/**
 * arbiter-sock.test — the launcher's rendezvous resolution
 * (runtime-instances.md §3/§5 mirror). The order under test is the split-brain
 * fix: a promoted `current` instance MUST win over the legacy fixed path, and
 * a bare environment MUST resolve to the `current` SPELLING (mode "autostart")
 * so the launcher starts an instance-mode arbiter instead of pinning a second
 * resident daemon beside a promoted stack.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, lstatSync, mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assertRuntimeBaseTrusted, movedBaseHint, resolveArbiterSock, runtimeBase } from "../../src/arbiter-sock.js";

function withBase(fn: (base: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sock-"));
  try { fn(join(dir, "mandu")); } finally { rmSync(dir, { recursive: true, force: true }); }
}

test("runtimeBase: MANDU_RUNTIME_DIR > XDG_RUNTIME_DIR > TMPDIR > os.tmpdir() > /tmp; too long → /tmp/mandu-<uid>", () => {
  assert.equal(runtimeBase({ MANDU_RUNTIME_DIR: "/x/base/" }), "/x/base");
  assert.equal(runtimeBase({ XDG_RUNTIME_DIR: "/run/u" }), "/run/u/mandu");
  assert.equal(runtimeBase({ TMPDIR: "/t" }), `/t/mandu-${process.getuid!()}`, "per-user (2026-10-09)");
  assert.equal(runtimeBase({}), `/tmp/mandu-${process.getuid!()}`, "TMPDIR unset → /tmp, never os.tmpdir(); never the shared /tmp/mandu");
  // The macOS per-user TMPDIR leaves no room for an instance socket (§3b).
  assert.equal(
    runtimeBase({ TMPDIR: "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/" }, { platform: "darwin", uid: 501, fallbackRoot: "/tmp" }),
    "/tmp/mandu-501",
  );
});

test("the /tmp fallback: resolution returns its current spelling, and REFUSES when the dir exists but is not private", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sock-fb-"));
  try {
    const opts = { platform: "darwin", uid: 501, fallbackRoot: dir };
    const env = { TMPDIR: "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/" };
    const base = join(dir, "mandu-501");
    // Absent: nothing to trust yet — the autostart will create it 0700.
    const r = resolveArbiterSock(env, opts, { uid: 501 });
    assert.deepEqual([r.base, r.mode, r.sock], [base, "autostart", join(base, "current", "arbiter.sock")]);
    // Present and private (owner simulated): trusted, `current` honoured.
    const inst = join(base, "instances", "i1");
    mkdirSync(inst, { recursive: true, mode: 0o700 });
    chmodSync(base, 0o700);
    writeFileSync(join(inst, "arbiter.sock"), "");
    symlinkSync(join("instances", "i1"), join(base, "current"));
    const mine = { uid: 501, lstat: (p: string) => ({ isDirectory: () => true, isSymbolicLink: () => false, uid: 501, mode: lstatSync(p).mode }) };
    assert.equal(resolveArbiterSock(env, opts, mine).mode, "current");
    // Someone else's dir (simulated owner) or a shared one: refused BEFORE the
    // `current` socket in it is trusted.
    const theirs = { uid: 501, lstat: (p: string) => ({ isDirectory: () => true, isSymbolicLink: () => false, uid: 666, mode: lstatSync(p).mode }) };
    assert.throws(() => resolveArbiterSock(env, opts, theirs), /owned by uid 666/);
    chmodSync(base, 0o755);
    assert.throws(() => resolveArbiterSock(env, opts, mine), /is shared \(mode 0755/);
    // A pinned sock is the caller's path, but the registry still lives under
    // the base: refused too; trusted once the dir is private again.
    assert.throws(() => resolveArbiterSock({ ...env, MANDU_ARBITER_SOCK: "/pin.sock" }, opts, mine), /is shared/);
    assert.throws(() => assertRuntimeBaseTrusted(env, opts, mine), /^Error: mandu: the Mandu runtime dir .* is shared/);
    chmodSync(base, 0o700);
    assert.equal(resolveArbiterSock({ ...env, MANDU_ARBITER_SOCK: "/pin.sock" }, opts, mine).mode, "pinned");
    assert.doesNotThrow(() => assertRuntimeBaseTrusted(env, opts, mine));
    // Not the fallback, and not directly in a shared sticky dir: never checked
    // (an explicit or XDG base in a dir of the user's own is the user's choice).
    assert.doesNotThrow(() => assertRuntimeBaseTrusted({ MANDU_RUNTIME_DIR: base + "-x" }, opts, theirs));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("env pin wins verbatim (legacy MANDU_ARBITER_SOCKET alias too)", () => {
  const r = resolveArbiterSock({ MANDU_ARBITER_SOCK: "/pin/a.sock", XDG_RUNTIME_DIR: "/run/u" });
  assert.deepEqual([r.sock, r.mode], ["/pin/a.sock", "pinned"]);
  const alias = resolveArbiterSock({ MANDU_ARBITER_SOCKET: "/pin/b.sock", XDG_RUNTIME_DIR: "/run/u" });
  assert.deepEqual([alias.sock, alias.mode], ["/pin/b.sock", "pinned"]);
});

test("promoted current beats the legacy fixed path", () => {
  withBase((base) => {
    // A promoted instance: instances/<id>/arbiter.sock + current -> instances/<id>
    const inst = join(base, "instances", "20260715-0001-abc-p1");
    mkdirSync(inst, { recursive: true });
    writeFileSync(join(inst, "arbiter.sock"), ""); // stand-in for the bound socket
    symlinkSync(join("instances", "20260715-0001-abc-p1"), join(base, "current"));
    writeFileSync(join(base, "arbiter.sock"), ""); // a stale legacy socket too
    const r = resolveArbiterSock({ MANDU_RUNTIME_DIR: base });
    // The SPELLING is kept (…/current/arbiter.sock), not the resolved target:
    // reconnects must follow later promotions.
    assert.equal(r.sock, join(base, "current", "arbiter.sock"));
    assert.equal(r.mode, "current");
  });
});

test("legacy fixed path is honored when no promoted instance exists", () => {
  withBase((base) => {
    mkdirSync(base, { recursive: true });
    writeFileSync(join(base, "arbiter.sock"), "");
    const r = resolveArbiterSock({ MANDU_RUNTIME_DIR: base });
    assert.deepEqual([r.sock, r.mode], [join(base, "arbiter.sock"), "legacy"]);
  });
});

test("dangling current is skipped (falls through to legacy/autostart)", () => {
  withBase((base) => {
    mkdirSync(base, { recursive: true });
    symlinkSync(join("instances", "gone"), join(base, "current")); // dead promotion
    const r = resolveArbiterSock({ MANDU_RUNTIME_DIR: base });
    assert.equal(r.mode, "autostart");
    assert.equal(r.sock, join(base, "current", "arbiter.sock"));
  });
});

test("bare environment → the current SPELLING + mode autostart (instance-mode start)", () => {
  withBase((base) => {
    const r = resolveArbiterSock({ MANDU_RUNTIME_DIR: base });
    assert.equal(r.mode, "autostart");
    assert.equal(r.sock, join(base, "current", "arbiter.sock"));
    assert.equal(r.base, base);
  });
});

test("a base DIRECTLY in a shared sticky dir (/tmp/mandu on Linux without XDG_RUNTIME_DIR): trusted only when ours and writable by nobody else", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sock-sticky-"));
  const sticky = join(dir, "tmp");
  mkdirSync(sticky);
  chmodSync(sticky, 0o1777); // stands in for /tmp
  try {
    const base = join(sticky, "mandu");
    const env = { MANDU_RUNTIME_DIR: base };
    const opts = { platform: "linux", uid: 1000 };
    // Absent: nothing to trust yet.
    assert.equal(resolveArbiterSock(env, opts).mode, "autostart");
    // The 0755 dir an earlier arbiter made with the umask, holding a live `current`: trusted.
    const inst = join(base, "instances", "i1");
    mkdirSync(inst, { recursive: true });
    chmodSync(base, 0o755);
    writeFileSync(join(inst, "arbiter.sock"), "");
    symlinkSync(join("instances", "i1"), join(base, "current"));
    assert.equal(resolveArbiterSock(env, opts).mode, "current");
    // Another account's /tmp/mandu (simulated owner): its `current` is never dialled.
    const theirs = { uid: 1000, lstat: (p: string) => ({ isDirectory: () => true, isSymbolicLink: () => false, uid: 1001, mode: lstatSync(p).mode }) };
    assert.throws(() => resolveArbiterSock(env, opts, theirs), /owned by uid 1001, not by you \(uid 1000\)/);
    // Ours but group-writable: refused too, and never chmod-repaired.
    chmodSync(base, 0o775);
    assert.throws(() => assertRuntimeBaseTrusted(env, opts), /^Error: mandu: the Mandu runtime dir .*mandu is writable by other accounts \(mode 0775/);
    assert.equal(lstatSync(base).mode & 0o777, 0o775);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("movedBaseHint (2026-10-09): an older version's stack of THIS user still at the shared /tmp/mandu is named once; another account's /tmp/mandu is not", () => {
  const opts = { platform: "linux", uid: 1000, fallbackRoot: "/tmp" };
  const live = (p: string): boolean => p === "/tmp/mandu/current/arbiter.sock";
  const hint = movedBaseHint({}, opts, live, () => true);
  assert.equal(
    hint,
    "mandu: a Mandu stack is still running under /tmp/mandu, where older versions kept it; this launch uses /tmp/mandu-1000. " +
      "Stop the old one: MANDU_RUNTIME_DIR=/tmp/mandu mandu stop --all",
  );
  assert.equal(movedBaseHint({}, opts, live, () => false), null, "another account's /tmp/mandu is not our stack");
  assert.equal(movedBaseHint({ TMPDIR: "/var/tmp" }, opts, (p) => p === "/var/tmp/mandu/current/arbiter.sock", () => true)?.includes("/var/tmp/mandu-1000"), true);
  assert.equal(movedBaseHint({}, opts, () => false, () => true), null, "nothing live there");
  assert.equal(movedBaseHint({}, { ...opts, uid: null }, live, () => true), null, "no uid: the base did not move");
});

test("movedBaseHint: the default base moved to the /tmp fallback while a stack still answers at the old $TMPDIR/mandu → one line naming it and how to stop it", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sock-moved-"));
  try {
    const longTmp = join(dir, "t".repeat(40)); // cand > 44 bytes: rule 4 on Linux
    const old = join(longTmp, "mandu");
    const opts = { platform: "linux", uid: 1000, fallbackRoot: "/tmp" };
    const env = { TMPDIR: longTmp };
    assert.equal(movedBaseHint(env, opts), null, "nothing under the old base");
    const inst = join(old, "instances", "i1");
    mkdirSync(inst, { recursive: true });
    writeFileSync(join(inst, "arbiter.sock"), "");
    symlinkSync(join("instances", "i1"), join(old, "current"));
    const hint = movedBaseHint(env, opts);
    assert.equal(
      hint,
      `mandu: a Mandu stack is still running under ${old}, where older versions kept it; this launch uses /tmp/mandu-1000. ` +
        `Stop the old one: MANDU_RUNTIME_DIR=${old} mandu stop --all`,
    );
    assert.equal(hint!.split("\n").length, 1, "one line");
    // Not printed when the user chose the base, when XDG_RUNTIME_DIR decides it,
    // or when the old `current` is dangling.
    assert.equal(movedBaseHint({ ...env, MANDU_RUNTIME_DIR: "/srv/rt" }, opts), null);
    assert.equal(movedBaseHint({ ...env, XDG_RUNTIME_DIR: "/run/user/1000" }, opts), null);
    assert.equal(movedBaseHint({ TMPDIR: "/t" }, opts, () => true), null, "an old base that is not a directory of this user (here: absent) names no stack");
    rmSync(inst, { recursive: true });
    assert.equal(movedBaseHint(env, opts), null, "a dangling current is not a live stack");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
