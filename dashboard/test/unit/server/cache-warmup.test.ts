/**
 * cache-warmup.test — the boot warm-up's runner (src/server/cache-warmup.ts,
 * dashboard.md §4.30): in-process steps run one at a time, each after a turn
 * of the event loop (work queued meanwhile, a request, runs first); a
 * concurrent step (a child process) starts in its turn and the steps after
 * it run beside it; a failing step is
 * recorded and the rest still run; a stop flag starts no further step; the
 * results come back in step order with one log line.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { describeWarmup, runWarmup, type WarmStep } from "../../../src/server/cache-warmup.js";

test("steps run in order, one at a time, each after a turn of the event loop", async () => {
  const seen: string[] = [];
  const step = (name: string): WarmStep => ({
    name,
    run: () => {
      seen.push(`start ${name}`);
      // queued work (a request's handler) during a step runs before the next step
      setImmediate(() => seen.push(`queued during ${name}`));
    },
  });
  const results = await runWarmup([step("a"), step("b"), step("c")]);
  assert.deepEqual(results.map((r) => [r.name, r.ok]), [["a", true], ["b", true], ["c", true]]);
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(seen, ["start a", "queued during a", "start b", "queued during b", "start c", "queued during c"]);
});

test("a concurrent step starts in its turn and the next steps run beside it; a failure is recorded and the rest still run", async () => {
  const order: string[] = [];
  let release!: () => void;
  const child = new Promise<void>((r) => { release = r; });
  const results = await runWarmup([
    { name: "first", run: () => { order.push("first"); } },
    { name: "boom", run: () => { order.push("boom"); throw new Error("no store"); } },
    { name: "child", concurrent: true, run: async () => { order.push("child started"); await child; order.push("child done"); } },
    { name: "last", run: () => { order.push("last"); release(); } },
  ]);
  assert.deepEqual(order, ["first", "boom", "child started", "last", "child done"], "last ran while child was still out");
  assert.deepEqual(results.map((r) => r.name), ["first", "boom", "child", "last"], "results in step order");
  assert.equal(results[1]!.ok, false);
  assert.equal(results[1]!.error, "no store");
  assert.match(describeWarmup(results, 1234), /^caches warm in 1\.2 s \(first \d+ ms, boom failed: no store, child \d+ ms, last \d+ ms\)$/);
});

test("a stopped server starts no further step", async () => {
  let stopped = false;
  const ran: string[] = [];
  const results = await runWarmup([
    { name: "a", run: () => { ran.push("a"); stopped = true; } },
    { name: "b", run: () => { ran.push("b"); } },
    { name: "c", concurrent: true, run: () => { ran.push("c"); } },
  ], () => stopped);
  assert.deepEqual(ran, ["a"]);
  assert.deepEqual(results.map((r) => r.name), ["a"]);
  assert.deepEqual(await runWarmup([{ name: "x", concurrent: true, run: () => { throw new Error("never"); } }], () => true), [], "stopped before it began: nothing starts");
});
