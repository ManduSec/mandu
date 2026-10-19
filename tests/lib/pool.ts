/**
 * pool — bounded eager-start scenario pool for the live e2e suites.
 *
 * Mandu (tests/). NEW code, no reference origin.
 *
 * WHY THIS SHAPE: node:test runs a file's top-level test() calls sequentially,
 * so a live suite of N scenarios — each a real `claude -p` (network-bound, not
 * CPU-bound) — pays N× wall-clock for no reason. The obvious alternatives both
 * break the dashboard: nesting subtests under a `{ concurrency }` parent emits
 * INDENTED TAP that the TestRunner's `^`-anchored parser (dashboard/src/
 * test-runner.ts TAP_LINE) cannot see, and one-test-per-file explodes the
 * suite. This pool instead starts the scenario WORK eagerly (bounded, FIFO)
 * while the test() registrations stay top-level and sequential — each test
 * body just awaits its pre-started result — so the TAP stream is byte-shaped
 * exactly as before and per-test timeouts stay honest (pool order = test
 * order, so by the time test k awaits, scenario k has already started).
 *
 * Results are PRE-SETTLED ({ err? } instead of a rejecting promise): a
 * scenario that fails before its test body awaits it must not raise an
 * unhandledRejection and kill the whole test child process.
 */

export interface PoolResult {
  /** The scenario's thrown error, if it failed; absent on success. */
  err?: unknown;
}

/**
 * Start every item's work NOW, at most `concurrency` in flight, FIFO. Returns
 * a map from item name to its settled-result promise (never rejects).
 *
 * Do not call when the suite is gated off (SKIP_REASON): starting the work is
 * the point, so the caller must guard.
 */
export function startScenarioPool<T extends { name: string }>(
  items: readonly T[],
  run: (item: T) => Promise<void>,
  concurrency: number,
): Map<string, Promise<PoolResult>> {
  const limit = Math.max(1, Math.floor(concurrency) || 1);
  let active = 0;
  const waiters: Array<() => void> = [];
  const acquire = async (): Promise<void> => {
    if (active < limit) {
      active++;
      return;
    }
    await new Promise<void>((resolve) => waiters.push(resolve));
    active++;
  };
  const release = (): void => {
    active--;
    waiters.shift()?.();
  };
  const started = new Map<string, Promise<PoolResult>>();
  for (const item of items) {
    started.set(
      item.name,
      (async (): Promise<PoolResult> => {
        await acquire();
        try {
          await run(item);
          return {};
        } catch (err) {
          return { err };
        } finally {
          release();
        }
      })(),
    );
  }
  return started;
}

/** Parse a concurrency env var: a finite number ≥ 1 wins, else the default. */
export function concurrencyFromEnv(raw: string | undefined, fallback: number): number {
  const n = Number(raw);
  return Number.isFinite(n) && n >= 1 ? Math.floor(n) : fallback;
}

/**
 * Parse MANDU_E2E_ONLY (comma-separated scenario names): a non-empty set
 * means "run ONLY these scenarios", an empty/unset value disables the filter.
 * The cheap-validation knob for the live pool suites: the pool eagerly starts
 * EVERY runnable scenario at module load, so without this even a
 * `--test-name-pattern` run spends the whole battery's real-model budget —
 * with it, unselected scenarios SKIP and their work never starts.
 */
export function onlyFilterFromEnv(raw: string | undefined): Set<string> {
  return new Set(
    (raw ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
  );
}
