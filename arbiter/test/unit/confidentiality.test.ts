import { test } from "node:test";
import assert from "node:assert/strict";
import {
  admits,
  CONFIDENTIALITY_LEVELS,
  confidentialityRank,
  maxConfidentiality,
  parseConfidentialityLevel,
  isSecret,
} from "../../symbol-table/confidentiality.js";
import { resolveConfidentialityEnabled } from "../../policy/confidentiality-flag.js";

test("total order: public ⊑ any-model ⊑ no-model", () => {
  assert.equal(maxConfidentiality("public", "any-model"), "any-model");
  assert.equal(maxConfidentiality("any-model", "no-model"), "no-model");
  assert.equal(maxConfidentiality("no-model", "public"), "no-model");
  assert.equal(maxConfidentiality(), "public");
});

test("parse: valid levels pass through; absent → public (pre-axis rows)", () => {
  assert.equal(parseConfidentialityLevel("no-model"), "no-model");
  assert.equal(parseConfidentialityLevel("any-model"), "any-model");
  assert.equal(parseConfidentialityLevel("public"), "public");
  assert.equal(parseConfidentialityLevel(null), "public");
  assert.equal(parseConfidentialityLevel(undefined), "public");
  assert.equal(parseConfidentialityLevel(""), "public");
});

test("parse: UNKNOWN level value fails closed to no-model", () => {
  // Forward-compat (§13.5): a level minted by a newer build must never
  // degrade to public in an older one; junk must never grant model-ok.
  assert.equal(parseConfidentialityLevel("secret-compartment-hr"), "no-model");
  assert.equal(parseConfidentialityLevel("model-ok"), "no-model");
  assert.equal(parseConfidentialityLevel(42), "no-model");
});

test("isSecret", () => {
  assert.equal(isSecret("public"), false);
  assert.equal(isSecret("any-model"), true);
  assert.equal(isSecret("local-model"), true);
  assert.equal(isSecret("no-model"), true);
});

test("plan 11 D1: local-model sits between any-model and no-model; the order stays total", () => {
  assert.deepEqual([...CONFIDENTIALITY_LEVELS], ["public", "any-model", "local-model", "no-model"]);
  assert.deepEqual(CONFIDENTIALITY_LEVELS.map(confidentialityRank), [0, 1, 2, 3]);
  assert.equal(maxConfidentiality("any-model", "local-model"), "local-model");
  assert.equal(maxConfidentiality("local-model", "no-model"), "no-model");
  assert.equal(maxConfidentiality("public", "local-model", "any-model"), "local-model");
  assert.equal(parseConfidentialityLevel("local-model"), "local-model", "round-trips");
  assert.equal(parseConfidentialityLevel("local"), "no-model", "a near miss fails closed");
});

test("plan 11 D4: admits(location, level) is exactly the 4×2 table", () => {
  const table: Array<[string, boolean, boolean]> = [
    // level          external  local
    ["public",        true,     true],
    ["any-model",     true,     true],
    ["local-model",   false,    true],
    ["no-model",      false,    false],
  ];
  for (const [level, ext, loc] of table) {
    assert.equal(admits("external", level as never), ext, `${level} at external`);
    assert.equal(admits("local", level as never), loc, `${level} at local`);
  }
  // An undeclared endpoint is external by construction (modelLocation);
  // no-model is refused at every location, which no declaration can change.
  for (const l of ["local", "external"] as const) assert.equal(admits(l, "no-model"), false);
});

test("kill switch resolves from env; nothing stated ⇒ ON (the default mode is `secrets`, protection-modes.md)", () => {
  assert.equal(resolveConfidentialityEnabled({}), true);
  assert.equal(resolveConfidentialityEnabled({ MANDU_MODE: "injection" }), false);
  assert.equal(resolveConfidentialityEnabled({ MANDU_CONFIDENTIALITY: "1" }), true);
  assert.equal(resolveConfidentialityEnabled({ MANDU_CONFIDENTIALITY: "true" }), true);
  assert.equal(resolveConfidentialityEnabled({ MANDU_CONFIDENTIALITY: "on" }), true);
  assert.equal(resolveConfidentialityEnabled({ MANDU_CONFIDENTIALITY: "0" }), false);
  assert.equal(resolveConfidentialityEnabled({ MANDU_CONFIDENTIALITY: "off" }), false);
  assert.equal(resolveConfidentialityEnabled({ MANDU_CONFIDENTIALITY: "" }), true, "empty is unset ⇒ the default");
});
