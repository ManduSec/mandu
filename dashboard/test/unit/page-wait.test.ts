/**
 * page-wait.test — the waits the served-page tests share (page-wait.ts):
 * `pollWhile` polls at once, again every `everyMs` while the condition
 * holds, and stops the moment it does not, or at its budget. Axes: none
 * (no arbiter; a helper of the tests).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { pollWhile, waitWhile } from "./page-wait.js";

test("pollWhile polls at once and not again once the condition goes", async () => {
  let polls = 0;
  const n = await pollWhile(() => polls < 1, () => { polls += 1; }, 50);
  assert.equal(n, 1);
  assert.equal(polls, 1);
});

test("pollWhile polls again every everyMs while the condition holds", async () => {
  let polls = 0;
  const start = Date.now();
  const n = await pollWhile(() => polls < 3, () => { polls += 1; }, 40);
  assert.equal(n, 3, "a poll each period until the third answered");
  assert.ok(Date.now() - start >= 80, "the polls are a period apart");
});

// The count is bounded by the time the wait took, not by budget / period: on
// the loaded CI guest a 20 ms timer fires late and only 2 polls fit in 100 ms
// (pipelines 10920, 10921, 2026-10-16), which the old `polls >= 3` failed.
test("pollWhile gives up at its budget, with the polls it made", async () => {
  let polls = 0;
  const start = Date.now();
  const n = await pollWhile(() => true, () => { polls += 1; }, 30, 100);
  const took = Date.now() - start;
  assert.equal(n, polls);
  assert.ok(took >= 100, `it waited out its budget (${took} ms)`);
  assert.ok(polls >= 1, "it polled at once");
  assert.ok(polls <= Math.floor(took / 30) + 1, `at most one poll per period (${polls} in ${took} ms)`);
});

test("pollWhile with the condition already gone polls nothing", async () => {
  let polls = 0;
  assert.equal(await pollWhile(() => false, () => { polls += 1; }), 0);
  assert.equal(polls, 0);
});

test("waitWhile returns once the condition goes", async () => {
  let n = 0;
  await waitWhile(() => ++n < 3);
  assert.equal(n, 3);
});
