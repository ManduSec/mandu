/**
 * The kernel tests' guard pick (tests/lib/native-guard.ts): the newest FRESH
 * build wins; when every build is stale the newest is named with the reason,
 * so the test fails instead of exercising an older guard.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pickGuard } from "../lib/native-guard.js";

function target(): { dir: string; release: string; debug: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-guard-pick-"));
  const release = join(dir, "release", "mandu-net-guard");
  const debug = join(dir, "debug", "mandu-net-guard");
  for (const b of [release, debug]) {
    mkdirSync(join(b, ".."), { recursive: true });
    writeFileSync(b, "");
  }
  // debug is the newer build
  utimesSync(release, new Date(1_000_000), new Date(1_000_000));
  utimesSync(debug, new Date(2_000_000), new Date(2_000_000));
  return { dir, release, debug, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("the newest fresh build wins; a newer stale one is passed over", () => {
  const t = target();
  try {
    assert.deepEqual(pickGuard(t.dir, () => null), { path: t.debug, stale: null });
    const staleDebug = (b: string) => (b === t.debug ? { newestSource: "src/x.rs" } : null);
    assert.deepEqual(pickGuard(t.dir, staleDebug), { path: t.release, stale: null });
  } finally {
    t.cleanup();
  }
});

test("every build stale: the newest is named with the reason, so the test fails loudly", () => {
  const t = target();
  try {
    const pick = pickGuard(t.dir, () => ({ newestSource: "src/secret_open.rs" }));
    assert.equal(pick.path, t.debug);
    assert.match(pick.stale ?? "", /older than its sources.*secret_open\.rs.*scripts\/build-native\.sh/);
  } finally {
    t.cleanup();
  }
});

test("nothing built: no path, no staleness (the kernel tests skip)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-guard-pick-"));
  try {
    assert.deepEqual(pickGuard(dir, () => null), { path: undefined, stale: null });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
