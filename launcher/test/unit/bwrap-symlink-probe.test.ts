/**
 * bwrap-symlink-probe.test: the CVE-2026-87766 probe's argv, its pure
 * classifier and the doctor / launch wording (sandbox-security-review-2026-09-28
 * finding 14: probe and warn, never refuse). No bwrap is run here: the real
 * host run is tests/sandbox/bind-only-posture.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, lstatSync, readlinkSync } from "node:fs";
import { join } from "node:path";
import {
  classifySymlinkProbe,
  CVE_FIXED_IN,
  olderThanFix,
  parseBwrapVersion,
  probeBwrapSymlink,
  PROBE_MARKER,
  SYMLINK_CVE_FIX,
  symlinkCveFix,
  symlinkProbeArgv,
  symlinkProbeRow,
  symlinkProbeWarning,
  withVersion,
} from "../../src/bwrap-symlink-probe.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // no arbiter here; stated per the suite rule

test("argv: the whole-agent wrap's base, one bind onto the symlink, a test through its target", () => {
  const a = symlinkProbeArgv("/t");
  assert.deepEqual(a, ["--dev-bind", "/", "/", "--bind", "/t/src", "/t/link", "--", "test", "-e", `/t/real/${PROBE_MARKER}`]);
});

test("classifier: only an accepted bind that landed on the link's target is `vulnerable`; the fix's refusal is `fixed`; anything else is `unknown`", () => {
  const rows: Array<[{ status: number | null; stderr: string; error?: boolean }, string]> = [
    // unpatched bubblewrap (0.9.0-1ubuntu0.3 on the development host): followed the link, marker visible
    [{ status: 0, stderr: "" }, "vulnerable"],
    // patched (0.9.0-1ubuntu0.2, run by hand under unshare -Ur on the development host 2026-09-28)
    [{ status: 1, stderr: "bwrap: Can't mount on symlink destination /tmp/x/link\n" }, "fixed"],
    // bwrap cannot run at all: never a warning
    [{ status: 1, stderr: "bwrap: setting up uid map: Permission denied\n" }, "unknown"],
    [{ status: 1, stderr: "bwrap: No permissions to create new namespace, likely because the kernel does not allow non-privileged user namespaces.\n" }, "unknown"],
    [{ status: null, stderr: "", error: true }, "unknown"], // ENOENT / timeout
    [{ status: null, stderr: "" }, "unknown"],
    // accepted, but the marker is not under the target: did not follow (not flagged)
    [{ status: 1, stderr: "" }, "unknown"],
    // exit 0 with a bwrap complaint is not a clean acceptance
    [{ status: 0, stderr: "bwrap: something odd\n" }, "unknown"],
  ];
  for (const [r, verdict] of rows) assert.equal(classifySymlinkProbe(r).verdict, verdict, JSON.stringify(r));
  assert.match(classifySymlinkProbe({ status: 1, stderr: "bwrap: setting up uid map: Permission denied" }).detail!, /uid map/);
});

test("probeBwrapSymlink: one run, in a fresh temp dir holding link -> real and the marker; the dir is removed; never throws", () => {
  let seen: { bin: string; args: string[]; linkTarget: string; marker: boolean; realIsDir: boolean } | null = null;
  let runs = 0;
  const r = probeBwrapSymlink("/usr/lib/mandu/bin/bwrap", {
    version: () => null,
    run: (bin, args) => {
      runs++;
      const dir = args[4]!.replace(/\/src$/, "");
      seen = {
        bin, args,
        linkTarget: readlinkSync(join(dir, "link")),
        marker: existsSync(join(dir, "src", PROBE_MARKER)),
        realIsDir: lstatSync(join(dir, "real")).isDirectory(),
      };
      return { status: 0, stderr: "" };
    },
  });
  assert.equal(runs, 1);
  assert.deepEqual(r, { bwrap: "/usr/lib/mandu/bin/bwrap", verdict: "vulnerable" });
  assert.equal(seen!.bin, "/usr/lib/mandu/bin/bwrap");
  assert.equal(seen!.linkTarget, "real");
  assert.ok(seen!.marker && seen!.realIsDir);
  assert.ok(!existsSync(seen!.args[4]!), "the temp dir is gone");
  // a run that throws, or a temp root that does not exist: unknown, no throw
  assert.equal(probeBwrapSymlink("bwrap", { version: () => null, run: () => { throw new Error("boom"); } }).verdict, "unknown");
  assert.equal(probeBwrapSymlink("bwrap", { version: () => null, tmpRoot: "/nonexistent/for/sure" }).verdict, "unknown");
});

test("version: parse `bwrap --version`, compare with 0.12.0 (the fix)", () => {
  assert.equal(CVE_FIXED_IN, "0.12.0");
  const parsed: Array<[string | null, string | null]> = [
    ["bubblewrap 0.11.1", "0.11.1"], ["bubblewrap 0.9.0", "0.9.0"], ["bubblewrap 0.12.0\n", "0.12.0"],
    ["0.13.1", "0.13.1"], ["bubblewrap 0.12", "0.12.0"], ["bubblewrap 1.0.0", "1.0.0"],
    ["", null], [null, null], ["bubblewrap", null], ["bwrap: unknown option --version", null],
  ];
  for (const [line, v] of parsed) assert.equal(parseBwrapVersion(line), v, String(line));
  const older: Array<[string, boolean | null]> = [
    ["0.9.0", true], ["0.11.1", true], ["0.11.99", true], ["0.12.0", false], ["0.12.1", false], ["0.13.1", false], ["1.0.0", false], ["junk", null],
  ];
  for (const [v, want] of older) assert.equal(olderThanFix(v), want, v);
});

test("withVersion: the behavior wins where it answered; an unknown answer from a pre-0.12.0 bubblewrap is `version-affected`", () => {
  // vulnerable: the version is named, the verdict stays
  assert.deepEqual(withVersion({ verdict: "vulnerable" }, "bubblewrap 0.11.1"), { verdict: "vulnerable", version: "0.11.1" });
  // a vulnerable build that claims a fixed version: still vulnerable (the version never clears a finding)
  assert.deepEqual(withVersion({ verdict: "vulnerable" }, "bubblewrap 0.13.0"), { verdict: "vulnerable", version: "0.13.0" });
  // fixed: a distro backport on an old version string (Ubuntu 0.9.0-1ubuntu0.2) stays fixed
  assert.deepEqual(withVersion({ verdict: "fixed" }, "bubblewrap 0.9.0"), { verdict: "fixed" });
  // unknown + old: told; unknown + new or unreadable: silent as before
  assert.deepEqual(withVersion({ verdict: "unknown", detail: "bwrap: setting up uid map: Permission denied" }, "bubblewrap 0.11.1"),
    { verdict: "version-affected", detail: "bwrap: setting up uid map: Permission denied", version: "0.11.1" });
  assert.deepEqual(withVersion({ verdict: "unknown", detail: "x" }, "bubblewrap 0.12.0"), { verdict: "unknown", detail: "x", version: "0.12.0" });
  assert.deepEqual(withVersion({ verdict: "unknown", detail: "x" }, null), { verdict: "unknown", detail: "x" });
});

test("probeBwrapSymlink reads the version only when the behavior did not say fixed (a fixed host spawns nothing more)", () => {
  const fixedRun = () => ({ status: 1, stderr: "bwrap: Can't mount on symlink destination /t/link\n" });
  let asked = 0;
  const version = (): string => { asked++; return "bubblewrap 0.11.1"; };
  assert.deepEqual(probeBwrapSymlink("bwrap", { run: fixedRun, version }), { bwrap: "bwrap", verdict: "fixed" });
  assert.equal(asked, 0);
  assert.deepEqual(probeBwrapSymlink("bwrap", { run: () => ({ status: 0, stderr: "" }), version }), { bwrap: "bwrap", verdict: "vulnerable", version: "0.11.1" });
  assert.equal(asked, 1);
  const unk = probeBwrapSymlink("bwrap", { run: () => ({ status: 1, stderr: "bwrap: setting up uid map: Permission denied\n" }), version });
  assert.equal(unk.verdict, "version-affected");
  assert.equal(asked, 2);
  // a version reader that throws: the behavior alone
  assert.equal(probeBwrapSymlink("bwrap", { run: () => ({ status: 1, stderr: "bwrap: no\n" }), version: () => { throw new Error("x"); } }).verdict, "unknown");
});

test("wording with the version: named in the row and the line; version-affected says it could not be tested and what to check instead; Mandu's own copy adds mandu setup", () => {
  const v = { bwrap: "/usr/bin/bwrap", verdict: "vulnerable" as const, version: "0.11.1" };
  assert.match(symlinkProbeRow(v)!, /^  ✗ bubblewrap on this host follows symlinks while it sets up a sandbox \(CVE-2026-87766\) \(\/usr\/bin\/bwrap, version 0\.11\.1\): /);
  assert.match(symlinkProbeWarning(v)!, /^WARNING: mandu: bubblewrap on this host follows symlinks while it sets up a sandbox \(CVE-2026-87766\) \(\/usr\/bin\/bwrap, version 0\.11\.1\); the mount layer is still used\./);
  const a = { bwrap: "bwrap", verdict: "version-affected" as const, version: "0.11.1", detail: "bwrap: setting up uid map: Permission denied" };
  const row = symlinkProbeRow(a)!;
  assert.match(row, /^  ✗ bubblewrap 0\.11\.1 \(bwrap\) reports a version older than 0\.12\.0, the first upstream release with the fix for CVE-2026-87766 \(it follows symlinks while it sets up a sandbox\), and Mandu could not test this build itself \(bwrap: setting up uid map: Permission denied\), so it may be affected; /);
  // A version number is not proof (distros backport and revert): the row
  // says so, and says what to check instead.
  assert.match(row, /the version number does not settle it: distributions backport the fix without changing it, and have dropped a backport again \(Ubuntu shipped the fix in 0\.9\.0-1ubuntu0\.2 and 0\.11\.1-1ubuntu0\.2, and removed it in the ubuntu0\.3 update of each\)/);
  assert.match(row, /its changelog must list CVE-2026-87766 \(Debian, Ubuntu: apt changelog bubblewrap; Fedora: rpm -q --changelog bubblewrap\)/);
  assert.match(row, /mandu doctor where bubblewrap can create a user namespace/);
  assert.match(row, /A warning only: the launch goes ahead\. fix: a bubblewrap with the fix/);
  assert.doesNotMatch(row, /a distro build may carry the fix/, "the old wording is gone");
  const w = symlinkProbeWarning(a)!;
  assert.match(w, /^WARNING: mandu: bubblewrap 0\.11\.1 \(bwrap\) reports a version older than 0\.12\.0, .*; the mount layer is still used\. Fix: .*Details: mandu doctor$/);
  assert.ok(!w.includes("\n"), "one line");
  // Every fix ends by testing the build, never by trusting a version string.
  assert.equal(symlinkCveFix("bwrap"), `${SYMLINK_CVE_FIX}; then run mandu doctor, which tests the build itself (a version number is not proof)`);
  // Mandu's own copy: upgrading the package is not enough
  assert.match(symlinkCveFix("/usr/lib/mandu/bin/bwrap"), /; then run mandu setup, which refreshes Mandu's own copy \(\/usr\/lib\/mandu\/bin\/bwrap\) from it; then run mandu doctor, which tests the build itself \(a version number is not proof\)$/);
  assert.match(symlinkProbeWarning({ ...v, bwrap: "/usr/lib/mandu/bin/bwrap" })!, /then run mandu setup/);
  for (const s of [row, w]) assert.doesNotMatch(s, / — /, "no em-dash interjections");
});

test("wording: the doctor row and the launch warning name the CVE and the fix; nothing for unknown; a fixed bwrap is a ✓ row", () => {
  const v = { bwrap: "bwrap", verdict: "vulnerable" as const };
  const row = symlinkProbeRow(v)!;
  assert.match(row, /^  ✗ bubblewrap on this host follows symlinks while it sets up a sandbox \(CVE-2026-87766\)/);
  assert.match(row, /fix: a bubblewrap with the fix: upgrade the distro package when it ships one \(Debian, Ubuntu: sudo apt update && sudo apt install --only-upgrade bubblewrap; .*\), or bubblewrap 0\.12\.0 or newer \(an administrator can point Mandu at one with bwrap_path in \/etc\/mandu\/policy\.d\); then run mandu doctor, which tests the build itself \(a version number is not proof\)$/);
  assert.match(row, /A warning only/);
  assert.match(symlinkProbeRow({ bwrap: "bwrap", verdict: "fixed" })!, /^  ✓ bubblewrap \(bwrap\) refuses to mount onto a symlink/);
  assert.equal(symlinkProbeRow({ bwrap: "bwrap", verdict: "unknown" }), null);
  assert.equal(symlinkProbeRow(undefined), null);
  const w = symlinkProbeWarning(v)!;
  assert.match(w, /^WARNING: mandu: .*CVE-2026-87766.*\(bwrap\); the mount layer is still used\. Fix: .*Details: mandu doctor$/);
  assert.ok(!w.includes("\n"), "one line");
  assert.equal(symlinkProbeWarning({ bwrap: "bwrap", verdict: "fixed" }), null);
  assert.equal(symlinkProbeWarning({ bwrap: "bwrap", verdict: "unknown" }), null);
  for (const s of [row, w]) assert.doesNotMatch(s, / — /, "no em-dash interjections");
});
