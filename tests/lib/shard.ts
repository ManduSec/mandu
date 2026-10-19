/**
 * shard — pick one shard of a test table, so the suite manifest can run a
 * long table of independent live cases as several entries side by side
 * (tests/suites.mjs `shards`; docs/design/testing/continuous-integration.md §5).
 *
 * `spec` is `k/n` (1 ≤ k ≤ n): the items at indexes k-1, k-1+n, k-1+2n, …
 * Unset or empty: every item. Anything else throws, so a typo can never run a
 * shard of nothing and pass. The cases outside the shard are not registered at
 * all (not skipped): a kernel entry's `ci.maxSkip: 0` would read a skip as a
 * missing prerequisite.
 */
export function shardOf<T>(items: readonly T[], spec: string | undefined): T[] {
  const mine = shardPicker(spec);
  return items.filter((_, i) => mine(i));
}

/** The shard's rule as a predicate over indexes (0-based), for a file whose
 *  cases are `test()` calls rather than a table: call it with each case's
 *  place in registration order and register the case only when it says so.
 *  The same `spec` rules as shardOf; a bad spec throws at once. */
export function shardPicker(spec: string | undefined): (index: number) => boolean {
  if (spec === undefined || spec === "") return () => true;
  const m = /^(\d+)\/(\d+)$/.exec(spec);
  const k = m ? Number(m[1]) : NaN;
  const n = m ? Number(m[2]) : NaN;
  if (!(n >= 1 && k >= 1 && k <= n)) throw new Error(`bad shard spec ${JSON.stringify(spec)}: want k/n with 1 ≤ k ≤ n`);
  return (i) => i % n === k - 1;
}
