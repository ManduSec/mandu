/**
 * test-shard.test — the shard picker the live tables run under
 * (tests/lib/shard.ts): the shards of a table are disjoint and cover it, and a
 * malformed spec throws instead of selecting nothing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { shardOf, shardPicker } from "../lib/shard.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // no arbiter here; stated because every test states its axes

test("unset or empty: the whole table", () => {
  assert.deepEqual(shardOf([1, 2, 3], undefined), [1, 2, 3]);
  assert.deepEqual(shardOf([1, 2, 3], ""), [1, 2, 3]);
});

test("the n shards are disjoint, cover the table, and keep its order", () => {
  const items = Array.from({ length: 18 }, (_, i) => i);
  for (const n of [1, 2, 3, 4, 7, 18, 20]) {
    const shards = Array.from({ length: n }, (_, k) => shardOf(items, `${k + 1}/${n}`));
    assert.deepEqual(shards.flat().sort((a, b) => a - b), items, `n=${n} covers every item once`);
    for (const s of shards) assert.deepEqual(s, [...s].sort((a, b) => a - b), "table order kept");
  }
  assert.deepEqual(shardOf(items, "2/3"), [1, 4, 7, 10, 13, 16]);
});

test("a malformed spec throws", () => {
  for (const bad of ["0/3", "4/3", "1/0", "3", "a/b", "1/3 ", "-1/3"]) {
    assert.throws(() => shardOf([1, 2], bad), /bad shard spec/, bad);
    assert.throws(() => shardPicker(bad), /bad shard spec/, bad);
  }
});

test("shardPicker: the same rule over registration indexes; unset picks every case", () => {
  const items = Array.from({ length: 13 }, (_, i) => i);
  for (const spec of ["1/3", "2/3", "3/3", "2/5"]) {
    const mine = shardPicker(spec);
    assert.deepEqual(items.filter((i) => mine(i)), shardOf(items, spec), spec);
  }
  assert.ok(items.every((i) => shardPicker(undefined)(i) && shardPicker("")(i)));
});
