import { test } from "node:test";
import assert from "node:assert/strict";
import {
  APPARMOR_USERNS_SYSCTL,
  BWRAP_PROBE_ARGV,
  MAX_USER_NAMESPACES_SYSCTL,
  UNSHARE_PROBE_ARGV,
  USERNS_CLONE_SYSCTL,
  probeUserns,
  usernsGapHint,
} from "../../src/userns.js";

// ── probeUserns ───────────────────────────────────────────────────────────────

function recorder(results: Record<string, boolean>) {
  const calls: string[] = [];
  const runOk = (cmd: string, args: string[]): boolean => {
    calls.push(cmd);
    if (cmd === "bwrap") assert.deepEqual(args, BWRAP_PROBE_ARGV);
    if (cmd === "unshare") assert.deepEqual(args, UNSHARE_PROBE_ARGV);
    return results[cmd] ?? false;
  };
  return { calls, runOk };
}

test("probeUserns: a distribution bwrap and its probe passes → true, unshare never consulted", () => {
  const r = recorder({ bwrap: true, unshare: false });
  assert.equal(probeUserns({ bwrapBin: () => "bwrap", runOk: r.runOk }), true);
  assert.deepEqual(r.calls, ["bwrap"]);
});

test("probeUserns: the distribution bwrap decides even when it FAILS (per-binary AppArmor grant is what matters)", () => {
  const r = recorder({ bwrap: false, unshare: true });
  assert.equal(probeUserns({ bwrapBin: () => "bwrap", runOk: r.runOk }), false);
  assert.deepEqual(r.calls, ["bwrap"]);
});

test("probeUserns: no bwrap → unshare decides", () => {
  for (const ok of [true, false]) {
    const r = recorder({ unshare: ok });
    assert.equal(probeUserns({ bwrapBin: () => null, runOk: r.runOk }), ok);
    assert.deepEqual(r.calls, ["unshare"]);
  }
});

test("probeUserns: both fail → false", () => {
  const r = recorder({});
  assert.equal(probeUserns({ bwrapBin: () => "bwrap", runOk: r.runOk }), false);
  assert.equal(probeUserns({ bwrapBin: () => null, runOk: r.runOk }), false);
});

// ── usernsGapHint ─────────────────────────────────────────────────────────────

const files = (m: Record<string, string>) => (p: string): string | null => (p in m ? m[p]! : null);

test("usernsGapHint: AppArmor restriction on → names the sysctl + the shipped grants", () => {
  const hint = usernsGapHint(files({ [APPARMOR_USERNS_SYSCTL]: "1\n", [USERNS_CLONE_SYSCTL]: "1\n" }));
  assert.match(hint, /kernel\.apparmor_restrict_unprivileged_userns=1/);
  assert.match(hint, /`mandu setup`/);
  // The host-global sysctl is never the suggested fix (rootless-confinement §3.2).
  assert.doesNotMatch(hint, /sysctl to 0/);
  // A checkout-only path is useless to an npm-installed user.
  assert.doesNotMatch(hint, /scripts\/apparmor/);
});

test("usernsGapHint: unprivileged_userns_clone=0 → that sysctl fix", () => {
  const hint = usernsGapHint(files({ [APPARMOR_USERNS_SYSCTL]: "0\n", [USERNS_CLONE_SYSCTL]: "0\n" }));
  assert.match(hint, /kernel\.unprivileged_userns_clone=0/);
  assert.match(hint, /set it to 1/);
  assert.doesNotMatch(hint, /apparmor_restrict/);
});

test("usernsGapHint: max_user_namespaces=0 → the quota fix", () => {
  const hint = usernsGapHint(files({ [MAX_USER_NAMESPACES_SYSCTL]: "0" }));
  assert.match(hint, /user\.max_user_namespaces=0/);
});

test("usernsGapHint: AppArmor wins over the other knobs (precedence)", () => {
  const hint = usernsGapHint(files({
    [APPARMOR_USERNS_SYSCTL]: "1", [USERNS_CLONE_SYSCTL]: "0", [MAX_USER_NAMESPACES_SYSCTL]: "0",
  }));
  assert.match(hint, /apparmor_restrict_unprivileged_userns=1/);
});

test("usernsGapHint: knobs open or files missing → the generic cause (a missing file is never 'shut')", () => {
  for (const read of [files({}), files({ [APPARMOR_USERNS_SYSCTL]: "0", [USERNS_CLONE_SYSCTL]: "1", [MAX_USER_NAMESPACES_SYSCTL]: "1000" })]) {
    const hint = usernsGapHint(read);
    assert.match(hint, /probe failed/);
    assert.match(hint, /CONFIG_USER_NS/);
  }
});

test("usernsGapHint: default reader runs against the live /proc without throwing", () => {
  assert.equal(typeof usernsGapHint(), "string");
});

test("probeUserns: Mandu's own bubblewrap in force answers first (bwrap-grant.ts); nothing else is probed", () => {
  const r = recorder({ bwrap: false, unshare: false });
  assert.equal(probeUserns({ bwrapBin: () => "bwrap", runOk: r.runOk, manduBwrapInForce: () => true }), true);
  assert.deepEqual(r.calls, []);
  // not in force: the old order, unchanged
  assert.equal(probeUserns({ bwrapBin: () => "bwrap", runOk: r.runOk, manduBwrapInForce: () => false }), false);
  assert.deepEqual(r.calls, ["bwrap"]);
});
