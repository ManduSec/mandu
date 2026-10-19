/**
 * protection-mode — MANDU_MODE at the arbiter, and the single built-in
 * default (docs/design/architecture/protection-modes.md §3.1).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_MODE, MODE_AXES, PROTECTION_MODES, modeFromEnv, modeOf } from "../../policy/protection-mode.js";
import { resolveIntegrityEnabled } from "../../policy/integrity-flag.js";
import { resolveConfidentialityEnabled } from "../../policy/confidentiality-flag.js";

const pair = (env: NodeJS.ProcessEnv) => ({
  integrity: resolveIntegrityEnabled(env),
  confidentiality: resolveConfidentialityEnabled(env),
});

test("four modes, four pairs, modeOf is the inverse", () => {
  assert.deepEqual([...PROTECTION_MODES], ["secrets", "injection", "full", "off"]);
  const seen = new Set(PROTECTION_MODES.map((m) => JSON.stringify(MODE_AXES[m])));
  assert.equal(seen.size, 4);
  for (const m of PROTECTION_MODES) assert.equal(modeOf(MODE_AXES[m]), m);
});

test("nothing stated: BOTH flag modules run the one DEFAULT_MODE (the default cannot half-move)", () => {
  assert.deepEqual(pair({}), MODE_AXES[DEFAULT_MODE]);
  assert.deepEqual(pair({ MANDU_INTEGRITY: "", MANDU_CONFIDENTIALITY: "", MANDU_MODE: " " }), MODE_AXES[DEFAULT_MODE]);
});

test("MANDU_MODE states both axes at the arbiter, with no launcher in between", () => {
  for (const m of PROTECTION_MODES) assert.deepEqual(pair({ MANDU_MODE: m }), MODE_AXES[m], m);
  assert.deepEqual(pair({ MANDU_MODE: " FULL " }), MODE_AXES.full);
});

test("an axis variable beats the mode for THAT axis only", () => {
  assert.deepEqual(pair({ MANDU_MODE: "full", MANDU_INTEGRITY: "0" }), MODE_AXES.secrets);
  assert.deepEqual(pair({ MANDU_MODE: "off", MANDU_CONFIDENTIALITY: "1" }), MODE_AXES.secrets);
  assert.deepEqual(pair({ MANDU_MODE: "secrets", MANDU_INTEGRITY: "1" }), MODE_AXES.full);
});

test("an unrecognized axis value fails toward protection (ON); only 0/false/off turns an axis off", () => {
  assert.equal(resolveIntegrityEnabled({ MANDU_INTEGRITY: "yes", MANDU_MODE: "off" }), true);
  assert.equal(resolveConfidentialityEnabled({ MANDU_CONFIDENTIALITY: "yes", MANDU_MODE: "off" }), true);
});

test("a MANDU_MODE that names no mode throws at start: a typo never becomes the default", () => {
  assert.throws(() => modeFromEnv({ MANDU_MODE: "standard" }), /not a protection mode.*secrets\|injection\|full\|off/);
  assert.throws(() => resolveIntegrityEnabled({ MANDU_MODE: "standard" }), /not a protection mode/);
  // …but a fully stated pair never consults the mode, so it cannot throw there.
  assert.doesNotThrow(() => pair({ MANDU_MODE: "standard", MANDU_INTEGRITY: "1", MANDU_CONFIDENTIALITY: "0" }));
});

test("strict mode: MANDU_MODE counts as stating both axes", () => {
  assert.deepEqual(pair({ MANDU_AXES_STRICT: "1", MANDU_MODE: "secrets" }), MODE_AXES.secrets);
  assert.throws(() => pair({ MANDU_AXES_STRICT: "1" }), /not stated/);
});
