/**
 * self-status.test — unit tests for the dashboard's own staleness detection
 * (src/self-status.ts): the two drift signals (committed, package-scoped git
 * drift; uncommitted src mtime drift), their fail-quiet behavior on unknown
 * revs, and the real-fs/newest-mtime + no-git fallbacks of the default seams.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import { join } from "node:path";
import { mkdirSync, writeFileSync, rmSync, utimesSync } from "node:fs";

import {
  DashboardSelf,
  gitShortRev,
  gitChangedFiles,
  newestMtime,
  type DashboardSelfOptions,
} from "../../src/self-status.js";
import { tmpDir } from "./tmp-dir.js";

const BOOT = Date.UTC(2026, 6, 8, 0, 0, 0); // 2026-07-08T00:00:00Z

/** A DashboardSelf with all seams faked; override per test. */
function makeSelf(overrides: Partial<DashboardSelfOptions> = {}): DashboardSelf {
  return new DashboardSelf({
    repoRoot: "/repo",
    packageDir: "/repo/dashboard",
    pid: 4242,
    bootTimeMs: BOOT,
    gitRev: () => "aaaa111",
    gitChangedInRange: () => [],
    newestMtimeMs: () => BOOT - 60_000, // sources predate boot
    ...overrides,
  });
}

test("fresh: same rev + no newer sources → not stale, identity fields filled", () => {
  const s = makeSelf().status();
  assert.equal(s.stale, false);
  assert.equal(s.staleReason, null);
  assert.equal(s.pid, 4242);
  assert.equal(s.startedAt, new Date(BOOT).toISOString());
  assert.equal(s.bootRev, "aaaa111");
  assert.equal(s.repoRev, "aaaa111");
});

test("committed drift OUTSIDE the package → not stale (scoped diff empty)", () => {
  let now = "aaaa111";
  const self = makeSelf({
    gitRev: () => now,
    gitChangedInRange: () => [], // HEAD moved, but nothing under dashboard/
  });
  now = "bbbb222";
  const s = self.status();
  assert.equal(s.repoRev, "bbbb222");
  assert.equal(s.stale, false);
});

test("committed drift touching the package → stale with both revs in the reason", () => {
  let now = "aaaa111";
  const self = makeSelf({
    gitRev: () => now,
    gitChangedInRange: (_root, from, to, dir) => {
      assert.equal(from, "aaaa111");
      assert.equal(to, "bbbb222");
      assert.equal(dir, "/repo/dashboard");
      return ["dashboard/src/view-model.ts"];
    },
  });
  now = "bbbb222";
  const s = self.status();
  assert.equal(s.stale, true);
  assert.match(s.staleReason!, /aaaa111 → bbbb222/);
  assert.match(s.staleReason!, /1 file\b/);
});

test("uncommitted drift: src mtime after boot → stale even at the same rev", () => {
  const self = makeSelf({
    newestMtimeMs: (roots) => {
      // The scan covers exactly the server-side surface: src/ + package.json.
      assert.deepEqual(roots, ["/repo/dashboard/src", "/repo/dashboard/package.json"]);
      return BOOT + 5_000;
    },
  });
  const s = self.status();
  assert.equal(s.stale, true);
  assert.match(s.staleReason!, /modified on disk since boot/);
});

test("unknown revs (nogit) fail quiet: only the mtime signal can flag", () => {
  const changed = ["dashboard/src/server.ts"];
  const s1 = makeSelf({ gitRev: () => "nogit", gitChangedInRange: () => changed }).status();
  assert.equal(s1.stale, false, "nogit → the git signal never flags");
  const s2 = makeSelf({
    gitRev: () => "nogit",
    gitChangedInRange: () => changed,
    newestMtimeMs: () => BOOT + 1,
  }).status();
  assert.equal(s2.stale, true, "the mtime signal still works without git");
});

// ── default seams against the real fs/git ────────────────────────────────────

test("newestMtime walks nested dirs, skips missing roots, and returns 0 on no matches", () => {
  const dir = tmpDir("mandu-selfstatus-");
  try {
    mkdirSync(join(dir, "a", "b"), { recursive: true });
    writeFileSync(join(dir, "a", "old.ts"), "x");
    writeFileSync(join(dir, "a", "b", "new.ts"), "y");
    const oldT = new Date("2026-01-01T00:00:00Z");
    const newT = new Date("2026-06-01T00:00:00Z");
    utimesSync(join(dir, "a", "old.ts"), oldT, oldT);
    utimesSync(join(dir, "a", "b", "new.ts"), newT, newT);
    const got = newestMtime([join(dir, "a"), join(dir, "does-not-exist")]);
    assert.equal(got, newT.getTime());
    assert.equal(newestMtime([join(dir, "nope")]), 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("gitShortRev / gitChangedFiles signal failure outside a git repo", () => {
  const dir = tmpDir("mandu-selfstatus-nogit-");
  try {
    assert.equal(gitShortRev(dir), "nogit");
    // null (NOT []) — a failed diff must stay distinguishable from an empty one:
    // DashboardSelf treats it as fresh, the supervisor's arbiterStaleness as stale.
    assert.equal(gitChangedFiles(dir, "aaaa111", "bbbb222", join(dir, "sub")), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("committed drift with an UNRESOLVABLE boot rev → self-check stays fresh (fail-quiet)", () => {
  // bootRev is self-captured from this checkout: if git can no longer resolve it
  // (rebase/gc), that is repo breakage, not evidence the dashboard is stale.
  let now = "aaaa111";
  const self = makeSelf({ gitRev: () => now, gitChangedInRange: () => null });
  now = "bbbb222";
  const s = self.status();
  assert.equal(s.stale, false);
  assert.equal(s.staleReason, null);
});
