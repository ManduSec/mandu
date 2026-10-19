/**
 * exit-guard-leaky-fail.fixture — a FAILING one-test suite with the same
 * deliberate leak (a never-closed listening net.Server). The e2e asserts the
 * guard still fires AND the forced exit preserves the red run's exit code 1
 * (node:test sets process.exitCode=1 on failure before the grace timer fires).
 *
 * Mandu (tests/). NEW code, no reference origin. Named *.fixture.ts so
 * the normal `stack/*.test.ts` and `drills/` test globs can NEVER
 * pick it up — it only runs as a spawned child of the exit-guard e2e.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";

import { installExitGuard } from "../lib/exit-guard.js";

installExitGuard("fixture", { graceMs: 1500 });

// THE LEAK: same ref'd never-closed server as the passing twin.
createServer().listen(0);

test("fails, and the module leaked a server handle", () => {
  assert.fail("deliberate red run — the guard must preserve exit code 1");
});
