/**
 * mode — the mode table, the per-level resolution rule and the effective pair
 * (docs/design/architecture/protection-modes.md §3.2, §4 "mode → axis resolution table
 * including overrides").
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_MODE, INTEGRITY_OPT_IN_ENV, MODE_AXES, MODES, PRODUCT_MODES, arbiterAxisEnv, effectiveAxes, integrityFrozenMessage,
  integrityOptedIn, modeHelpLines, modeOf, parseMode, resolveRequestedAxes,
} from "../../src/mode.js";

test("the four modes cover the four axis pairs, and modeOf is the inverse", () => {
  assert.deepEqual([...MODES], ["secrets", "injection", "full", "off"]);
  assert.deepEqual(MODE_AXES.secrets, { integrity: false, confidentiality: true });
  assert.deepEqual(MODE_AXES.injection, { integrity: true, confidentiality: false });
  assert.deepEqual(MODE_AXES.full, { integrity: true, confidentiality: true });
  assert.deepEqual(MODE_AXES.off, { integrity: false, confidentiality: false });
  for (const m of MODES) assert.equal(modeOf(MODE_AXES[m]), m);
});

test("parseMode: case/space tolerant, empty is unset, unknown is a usage error naming the four", () => {
  assert.equal(parseMode(" Full ", "--mode"), "full");
  assert.equal(parseMode("", "MANDU_MODE"), undefined);
  assert.equal(parseMode(undefined, "--mode"), undefined);
  assert.throws(() => parseMode("standard", "--mode"), /unknown mode 'standard'.*secrets\|injection\|full\|off/);
});

test("nothing said at any level requests nothing (the arbiter's posture stands)", () => {
  assert.deepEqual(resolveRequestedAxes([{}, {}, {}]), {});
});

test("a mode speaks for both axes", () => {
  assert.deepEqual(resolveRequestedAxes([{ mode: "secrets" }]), { integrity: false, confidentiality: true });
});

test("inside one level an explicit axis beats the mode for THAT axis only", () => {
  // mandu --mode secrets --integrity  ⇒ full
  assert.deepEqual(
    resolveRequestedAxes([{ mode: "secrets", integrity: true }]),
    { integrity: true, confidentiality: true },
  );
  // mode = "full" + confidentiality = false in config.toml ⇒ injection, never an error
  assert.deepEqual(
    resolveRequestedAxes([{}, {}, { mode: "full", confidentiality: false }]),
    { integrity: true, confidentiality: false },
  );
});

test("across levels the first level that speaks about an axis wins it (flag > env > config)", () => {
  // --mode full beats an exported MANDU_INTEGRITY=0 and a config mode
  assert.deepEqual(
    resolveRequestedAxes([{ mode: "full" }, { integrity: false }, { mode: "off" }]),
    { integrity: true, confidentiality: true },
  );
  // a flag that names ONE axis leaves the other to the next level down
  assert.deepEqual(
    resolveRequestedAxes([{ integrity: true }, { mode: "secrets" }, {}]),
    { integrity: true, confidentiality: true },
  );
  // env axis beats the config mode for that axis; the config mode fills the other
  assert.deepEqual(
    resolveRequestedAxes([{}, { confidentiality: false }, { mode: "full" }]),
    { integrity: true, confidentiality: false },
  );
});

test("effectiveAxes: the arbiter's report wins, then the request, then the default mode", () => {
  assert.deepEqual(effectiveAxes({}, {}), MODE_AXES[DEFAULT_MODE]);
  assert.deepEqual(effectiveAxes({ integrity: false, confidentiality: true }, {}), MODE_AXES.secrets);
  assert.deepEqual(
    effectiveAxes({}, { integrity: false, confidentiality: true }),
    MODE_AXES.secrets,
    "an unflagged launch that joins a secrets arbiter runs secrets",
  );
  assert.deepEqual(
    effectiveAxes({ integrity: true }, { confidentiality: true }),
    { integrity: true, confidentiality: true },
  );
});

test("--help lists the product modes (secrets, off), marks exactly one default, and names the frozen pair with its opt-in", () => {
  const lines = modeHelpLines();
  assert.equal(lines.length, 3);
  for (const m of ["secrets", "off"]) assert.ok(lines.some((l) => l.startsWith(`  ${m} `)), m);
  for (const m of ["injection", "full"]) assert.ok(!lines.some((l) => l.startsWith(`  ${m} `)), m);
  assert.equal(lines.filter((l) => l.includes("(default)")).length, 1);
  assert.ok(lines.find((l) => l.includes("(default)"))!.trimStart().startsWith(DEFAULT_MODE));
  assert.equal(lines[2], "  (frozen: injection, full; need MANDU_EXPERIMENTAL_INTEGRITY=1)");
});

// ── frozen integrity axis (docs/design/architecture/protection-modes.md §10) ──────────────────

test("frozen integrity: the product modes are exactly the integrity-OFF modes, and include the default", () => {
  assert.deepEqual([...PRODUCT_MODES], ["secrets", "off"]);
  assert.deepEqual(MODES.filter((m) => !MODE_AXES[m].integrity), [...PRODUCT_MODES].sort((a, b) => MODES.indexOf(a) - MODES.indexOf(b)));
  assert.ok(PRODUCT_MODES.includes(DEFAULT_MODE));
});

test("frozen integrity: only an explicit 1/true/on/yes opts in", () => {
  assert.equal(INTEGRITY_OPT_IN_ENV, "MANDU_EXPERIMENTAL_INTEGRITY");
  for (const v of ["1", "true", "on", "yes", " TRUE ", "Yes"]) assert.equal(integrityOptedIn({ [INTEGRITY_OPT_IN_ENV]: v }), true, v);
  for (const v of [undefined, "", "0", "false", "off", "no", "2", "enabled"]) {
    assert.equal(integrityOptedIn({ [INTEGRITY_OPT_IN_ENV]: v }), false, String(v));
  }
  assert.equal(integrityOptedIn({}), false);
});

test("frozen integrity: the refusal names its source, the freeze doc, the product modes and the opt-in", () => {
  const m = integrityFrozenMessage("this launch's flags");
  assert.match(m, /^mandu: /);
  assert.match(m, /this launch's flags/);
  assert.match(m, /docs\/design\/architecture\/protection-modes\.md/);
  assert.match(m, /mode secrets \(the default\) or off/);
  assert.match(m, /MANDU_EXPERIMENTAL_INTEGRITY=1/);
});

test("arbiterAxisEnv: requested axes only; an integrity-ON request forwards the opt-in to the daemon it starts", () => {
  assert.deepEqual(arbiterAxisEnv({}), {}, "nothing requested: an exported variable still wins");
  assert.deepEqual(arbiterAxisEnv(MODE_AXES.secrets), { MANDU_CONFIDENTIALITY: "1", MANDU_INTEGRITY: "0" });
  assert.deepEqual(arbiterAxisEnv(MODE_AXES.off), { MANDU_CONFIDENTIALITY: "0", MANDU_INTEGRITY: "0" });
  assert.deepEqual(arbiterAxisEnv({ confidentiality: true }), { MANDU_CONFIDENTIALITY: "1" });
  assert.deepEqual(arbiterAxisEnv(MODE_AXES.full), { MANDU_CONFIDENTIALITY: "1", MANDU_INTEGRITY: "1", MANDU_EXPERIMENTAL_INTEGRITY: "1" });
  assert.deepEqual(arbiterAxisEnv({ integrity: true }), { MANDU_INTEGRITY: "1", MANDU_EXPERIMENTAL_INTEGRITY: "1" });
});
