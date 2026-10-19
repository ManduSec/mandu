/**
 * level-marker.test — fs-sync's copy of the arbiter's marker parse
 * (`levelOfSymbolName`, KEEP IN SYNC with arbiter/symbol-table/symbol-format.ts
 * `levelFromSymbolName`). fs-sync compares it with the path's current level to
 * decide whether a seeded twin must be re-minted; a marker it does not know
 * would re-mint every twin on every launch (plan 11 D1 added `localmodel_`).
 *
 * Pure string logic: no protection axis is exercised.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { levelOfSymbolName } from "../../src/arbiter-client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is exercised

test("every marker maps to its level; no marker is public", () => {
  assert.equal(levelOfSymbolName("$MDU:nomodel_Read[3fa9]"), "no-model");
  assert.equal(levelOfSymbolName("$MDU:localmodel_Read[c4d8].content"), "local-model");
  assert.equal(levelOfSymbolName("$MDU:anymodel_Read[7b21]"), "any-model");
  assert.equal(levelOfSymbolName("$MDU:Read[1234]"), "public");
  assert.equal(levelOfSymbolName("$MDU:t_localmodel_x[1234]"), "public", "a reserved-prefix tool tag is not a marker");
});
