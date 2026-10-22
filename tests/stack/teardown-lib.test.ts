/**
 * teardown-lib.test — tests/lib/teardown.ts `withTeardown`: a teardown
 * that fails does not hide the body's own error (a `finally` that throws
 * does), every step runs even when an earlier one threw, and a teardown
 * failure after a passing body still fails. Pure (no arbiter, no browser):
 * no protection axis is involved.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { withTeardown } from "../lib/teardown.js";

test("withTeardown: the body's error wins over a failing teardown, and every step still runs in order", async () => {
  const ran: string[] = [];
  const bodyError = new assert.AssertionError({ message: "the real failure" });
  const quiet = console.error;
  const said: string[] = [];
  console.error = (...a: unknown[]) => { said.push(a.map(String).join(" ")); };
  try {
    await assert.rejects(
      withTeardown(
        async () => { ran.push("body"); throw bodyError; },
        () => { ran.push("cdp"); },
        async () => { ran.push("browser"); throw new Error("ENOTEMPTY: directory not empty, rmdir 'chrome/Default'"); },
        () => { ran.push("stack"); },
      ),
      (e) => e === bodyError,
    );
  } finally {
    console.error = quiet;
  }
  assert.deepEqual(ran, ["body", "cdp", "browser", "stack"]);
  assert.equal((bodyError as unknown as { teardownErrors: Error[] }).teardownErrors.length, 1);
  assert.match(said.join("\n"), /teardown also failed .*ENOTEMPTY/s, "the teardown's failure is still said");
});

test("withTeardown: after a passing body, a failing teardown fails the test with its own error; a clean one returns the body's value", async () => {
  const ran: string[] = [];
  await assert.rejects(
    withTeardown(async () => 1, () => { throw new Error("first"); }, () => { ran.push("second"); throw new Error("second"); }),
    /first/,
  );
  assert.deepEqual(ran, ["second"], "the later step ran though the first threw");
  assert.equal(await withTeardown(async () => 42, () => {}, async () => {}), 42);
});
