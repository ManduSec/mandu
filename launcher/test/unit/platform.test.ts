/**
 * platform.test — scope planning + runtimeDir, per OS, without touching the host.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { linuxPlatform } from "../../src/platform/linux.js";
import { darwinPlatform } from "../../src/platform/darwin.js";

const noCmd = () => false;
const yesCmd = () => true;

test("linux: systemd available → systemd-run scope prefix, not detached", () => {
  const s = linuxPlatform.planScope({
    scopeId: "sid", env: { MANDU_SCOPE_ID: "sid", ANTHROPIC_BASE_URL: "http://p:1" },
    noScope: false, commandExists: yesCmd, systemdUserOk: () => true,
  });
  assert.equal(s.detached, false);
  assert.equal(s.prefix[0], "systemd-run");
  assert.ok(s.prefix.includes("--user"));
  assert.ok(s.prefix.includes("--scope"));
  assert.ok(s.prefix.some((a) => a === "--setenv=MANDU_SCOPE_ID=sid"));
  assert.ok(s.prefix.some((a) => a === "--setenv=ANTHROPIC_BASE_URL=http://p:1"));
  assert.equal(s.prefix[s.prefix.length - 1], "--");
});

test("linux: no systemd → detached pgid, empty prefix", () => {
  const s = linuxPlatform.planScope({
    scopeId: "sid", env: {}, noScope: false, commandExists: noCmd, systemdUserOk: () => false,
  });
  assert.deepEqual(s.prefix, []);
  assert.equal(s.detached, true);
});

test("--no-scope forces pgid on linux even with systemd", () => {
  const s = linuxPlatform.planScope({
    scopeId: "sid", env: {}, noScope: true, commandExists: yesCmd, systemdUserOk: () => true,
  });
  assert.deepEqual(s.prefix, []);
  assert.equal(s.detached, true);
});

test("darwin: always pgid (no systemd)", () => {
  const s = darwinPlatform.planScope({
    scopeId: "sid", env: {}, noScope: false, commandExists: yesCmd, systemdUserOk: () => true,
  });
  assert.deepEqual(s.prefix, []);
  assert.equal(s.detached, true);
});

test("runtimeDir: the path table's runtime-dir on both platforms, a TMPDIR too long for an instance socket giving the private /tmp/mandu-<uid>", () => {
  assert.equal(linuxPlatform.runtimeDir({ XDG_RUNTIME_DIR: "/run/u" }), "/run/u/mandu");
  assert.equal(linuxPlatform.runtimeDir({ TMPDIR: "/tmp/x/" }), `/tmp/x/mandu-${process.getuid!()}`);
  assert.equal(darwinPlatform.runtimeDir({ TMPDIR: "/tmp/x/" }), `/tmp/x/mandu-${process.getuid!()}`);
  // MANDU_RUNTIME_DIR moves it, as it moves the arbiter's instances.
  assert.equal(linuxPlatform.runtimeDir({ MANDU_RUNTIME_DIR: "/rt/", XDG_RUNTIME_DIR: "/run/u" }), "/rt");
  assert.equal(darwinPlatform.runtimeDir({ MANDU_RUNTIME_DIR: "/rt", TMPDIR: "/tmp/x" }), "/rt");
  // The macOS per-user TMPDIR (49 bytes) leaves no room for an instance
  // socket under either platform's sun_path (runtime-instances.md §3b).
  const uid = process.getuid?.();
  if (uid !== undefined) {
    const env = { TMPDIR: "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/", MANDU_RUNTIME_FALLBACK_ROOT: "/fb" };
    assert.equal(darwinPlatform.runtimeDir(env), `/fb/mandu-${uid}`);
    assert.equal(linuxPlatform.runtimeDir(env), `/fb/mandu-${uid}`);
  }
});
