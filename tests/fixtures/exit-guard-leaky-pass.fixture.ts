/**
 * exit-guard-leaky-pass.fixture — a PASSING one-test suite that deliberately
 * LEAKS a ref'd handle (a never-closed listening net.Server). Without the
 * exit guard this runner would never exit; the e2e (tests/stack/exit-guard.test.ts)
 * spawns it and asserts the guard diagnoses the leak and force-exits 0.
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

// THE LEAK: a ref'd listening server nothing ever closes. It holds the event
// loop exactly like the leaked arbiter sockets the guard exists to catch.
createServer().listen(0);

test("passes, but the module leaked a server handle", () => {
  assert.equal(1 + 1, 2);
});
