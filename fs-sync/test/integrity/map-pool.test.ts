/**
 * Unit: mapPool, the bounded-concurrency map the re-launch seed runs its twin
 * checks through (view-sync.ts; fs-sync.md §3 "Re-launch fast path").
 */
import { strict as assert } from "node:assert";
import { test } from "node:test";

import { mapPool } from "../../src/view-sync.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // pure helper; the suite states its axes

const tick = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("mapPool keeps input order whatever order the work finishes in", async () => {
  const out = await mapPool([30, 1, 20, 5, 0], 3, async (ms) => { await tick(ms); return ms * 2; });
  assert.deepEqual(out, [60, 2, 40, 10, 0]);
});

test("mapPool never runs more than the limit at once, and uses it", async () => {
  let inFlight = 0;
  let peak = 0;
  await mapPool(Array.from({ length: 50 }, (_, i) => i), 7, async () => {
    inFlight++;
    peak = Math.max(peak, inFlight);
    await tick(2);
    inFlight--;
  });
  assert.equal(peak, 7);
});

test("mapPool: an empty list, a limit above the length, and a rejection that propagates", async () => {
  assert.deepEqual(await mapPool([], 4, async (x: number) => x), []);
  assert.deepEqual(await mapPool([1, 2], 100, async (x) => x + 1), [2, 3]);
  await assert.rejects(mapPool([1, 2, 3], 2, async (x) => { if (x === 2) throw new Error("boom"); return x; }), /boom/);
});
