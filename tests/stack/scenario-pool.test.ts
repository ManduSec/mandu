/**
 * scenario-pool.test.ts — deterministic offline tests for the bounded
 * eager-start pool the live suites use (tests/lib/pool.ts).
 *
 * Mandu (tests/). No network, no claude, no arbiter — pure scheduling
 * semantics: the concurrency cap holds, starts are FIFO, per-item failures are
 * pre-settled (never an unhandledRejection), and the env parser clamps.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { startScenarioPool, concurrencyFromEnv, onlyFilterFromEnv } from "../lib/pool.js";

interface Gate {
  name: string;
  open: () => void;
  promise: Promise<void>;
}

function gate(name: string): Gate {
  let open!: () => void;
  const promise = new Promise<void>((resolve) => (open = resolve));
  return { name, open, promise };
}

const tick = (): Promise<void> => new Promise((r) => setImmediate(r));

test("pool: never exceeds the concurrency cap, and starts are FIFO", async () => {
  const items = Array.from({ length: 7 }, (_, i) => gate(`s${i}`));
  const startOrder: string[] = [];
  let inFlight = 0;
  let maxInFlight = 0;

  const started = startScenarioPool(
    items,
    async (it) => {
      startOrder.push(it.name);
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await it.promise;
      inFlight--;
    },
    3,
  );
  assert.equal(started.size, 7);

  await tick();
  // Only the first 3 have started; the rest are queued.
  assert.deepEqual(startOrder, ["s0", "s1", "s2"]);

  // Finishing one admits exactly the NEXT queued item, in order.
  items[1]!.open();
  await tick();
  assert.deepEqual(startOrder, ["s0", "s1", "s2", "s3"]);

  for (const it of items) it.open();
  const results = await Promise.all(items.map((it) => started.get(it.name)!));
  assert.deepEqual(startOrder, ["s0", "s1", "s2", "s3", "s4", "s5", "s6"]);
  assert.equal(maxInFlight, 3, `cap violated: saw ${maxInFlight} in flight`);
  for (const r of results) assert.equal(r.err, undefined);
});

test("pool: a failing item settles to { err } for ITS entry only, frees its slot, and never rejects", async () => {
  const boom = new Error("scenario exploded");
  const seen: string[] = [];
  const started = startScenarioPool(
    [{ name: "ok1" }, { name: "bad" }, { name: "ok2" }],
    async (it) => {
      seen.push(it.name);
      if (it.name === "bad") throw boom;
    },
    1,
  );
  // Settle everything BEFORE any consumer awaits — the eager-start posture. A
  // rejecting promise here would raise unhandledRejection and kill the process
  // (which is exactly what the pre-settled { err } shape prevents).
  await tick();
  await tick();
  assert.deepEqual(seen, ["ok1", "bad", "ok2"], "a failure must not starve the queue");
  assert.equal((await started.get("ok1")!).err, undefined);
  assert.equal((await started.get("bad")!).err, boom);
  assert.equal((await started.get("ok2")!).err, undefined);
});

test("pool: concurrency 1 preserves strict serial order (the sequential fallback)", async () => {
  const events: string[] = [];
  const started = startScenarioPool(
    [{ name: "a" }, { name: "b" }, { name: "c" }],
    async (it) => {
      events.push(`start:${it.name}`);
      await tick();
      events.push(`end:${it.name}`);
    },
    1,
  );
  await Promise.all([...started.values()]);
  assert.deepEqual(events, ["start:a", "end:a", "start:b", "end:b", "start:c", "end:c"]);
});

test("concurrencyFromEnv: finite ≥1 wins (floored), everything else falls back", () => {
  assert.equal(concurrencyFromEnv("4", 9), 4);
  assert.equal(concurrencyFromEnv("2.9", 9), 2);
  assert.equal(concurrencyFromEnv("1", 9), 1);
  assert.equal(concurrencyFromEnv("0", 9), 9);
  assert.equal(concurrencyFromEnv("-3", 9), 9);
  assert.equal(concurrencyFromEnv("banana", 9), 9);
  assert.equal(concurrencyFromEnv("", 9), 9);
  assert.equal(concurrencyFromEnv(undefined, 9), 9);
});

test("onlyFilterFromEnv: comma list trims + drops empties; unset/empty disables (empty set)", () => {
  assert.deepEqual([...onlyFilterFromEnv("reasoning")], ["reasoning"]);
  assert.deepEqual([...onlyFilterFromEnv(" a , b ,,c ")], ["a", "b", "c"]);
  assert.equal(onlyFilterFromEnv("").size, 0);
  assert.equal(onlyFilterFromEnv("  ,  ").size, 0);
  assert.equal(onlyFilterFromEnv(undefined).size, 0);
});
