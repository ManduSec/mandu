/**
 * teardown — run a test's body, then its teardown steps, without letting a
 * teardown failure hide the body's own error. Mandu-new.
 *
 * A `finally` block that throws replaces the error the `try` threw: a test
 * whose assertion failed, and whose browser profile then would not come
 * off the disk, reported only the ENOTEMPTY of the removal (GitHub CI,
 * 2026-10-22), and the failure it hid was lost. `withTeardown` runs every
 * step in order, each even when an earlier one threw, then throws:
 *   - the body's error, when the body threw; the teardown's errors are
 *     printed on stderr beside it, and attached as its `teardownErrors`;
 *   - else the first teardown error (a teardown that fails after a passing
 *     body still fails the test: a leaked browser or directory is a fault).
 */

export type TeardownStep = () => unknown;

export async function withTeardown<T>(body: () => Promise<T>, ...steps: TeardownStep[]): Promise<T> {
  let result: T | undefined;
  let primary: { error: unknown } | null = null;
  try {
    result = await body();
  } catch (error) {
    primary = { error };
  }
  const failures: unknown[] = [];
  for (const step of steps) {
    try {
      await step();
    } catch (error) {
      failures.push(error);
    }
  }
  if (primary !== null) {
    if (failures.length) {
      for (const f of failures) console.error(`teardown also failed (the test's own error is the one reported): ${f instanceof Error ? f.stack ?? f.message : String(f)}`);
      if (primary.error !== null && typeof primary.error === "object") {
        try { Object.assign(primary.error, { teardownErrors: failures }); } catch { /* frozen */ }
      }
    }
    throw primary.error;
  }
  if (failures.length) throw failures[0];
  return result as T;
}
