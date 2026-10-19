/**
 * exit-guard-clean.fixture — the NEGATIVE control: guard installed, passing
 * test, NO leak. The e2e asserts this runner exits 0 quickly WITHOUT emitting
 * any `[exit-guard:` line — the guard is provably silent on healthy runners
 * (the grace timer is unref'd, so a drained loop exits before it can fire).
 *
 * Mandu (tests/). NEW code, no reference origin. Named *.fixture.ts so
 * the normal `stack/*.test.ts` and `drills/` test globs can NEVER
 * pick it up — it only runs as a spawned child of the exit-guard e2e.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { installExitGuard } from "../lib/exit-guard.js";

installExitGuard("fixture", { graceMs: 1500 });

test("passes and leaks nothing", () => {
  assert.equal(2 * 21, 42);
});
