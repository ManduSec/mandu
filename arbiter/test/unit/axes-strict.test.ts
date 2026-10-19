/**
 * axes-strict — the "every suite states its axes" guard
 * (docs/design/architecture/protection-modes.md §4.1).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { assertAxisStated, axesStrict } from "../../policy/axes-strict.js";
import { resolveIntegrityEnabled } from "../../policy/integrity-flag.js";
import { resolveConfidentialityEnabled } from "../../policy/confidentiality-flag.js";

test("strict is OFF unless asked for: production never throws on an unstated axis", () => {
  assert.equal(axesStrict({}), false);
  assert.equal(axesStrict({ MANDU_AXES_STRICT: "0" }), false);
  assert.doesNotThrow(() => resolveIntegrityEnabled({}));
  assert.doesNotThrow(() => resolveConfidentialityEnabled({}));
});

test("strict ON: an unstated axis throws and names the variable and the fix", () => {
  const env = { MANDU_AXES_STRICT: "1" };
  assert.equal(axesStrict(env), true);
  assert.throws(() => resolveIntegrityEnabled(env), /MANDU_INTEGRITY is not stated.*protection-modes\.md/s);
  assert.throws(() => resolveConfidentialityEnabled(env), /MANDU_CONFIDENTIALITY is not stated/);
  assert.throws(() => assertAxisStated("MANDU_INTEGRITY", { ...env, MANDU_INTEGRITY: "  " }), /not stated/, "blank is not a statement");
});

test("strict ON: a stated axis resolves as usual, in both directions", () => {
  const on = { MANDU_AXES_STRICT: "1", MANDU_INTEGRITY: "1", MANDU_CONFIDENTIALITY: "1" };
  const off = { MANDU_AXES_STRICT: "1", MANDU_INTEGRITY: "0", MANDU_CONFIDENTIALITY: "0" };
  assert.equal(resolveIntegrityEnabled(on), true);
  assert.equal(resolveConfidentialityEnabled(on), true);
  assert.equal(resolveIntegrityEnabled(off), false);
  assert.equal(resolveConfidentialityEnabled(off), false);
});
