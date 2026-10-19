/**
 * axis-defaults-parity.test.ts — ONE default, ONE mode table, everywhere
 * (docs/design/architecture/protection-modes.md §3.1: "flip all of them in one change, with
 * a parity test that fails if they drift").
 *
 * The built-in default pair used to be written down four times (two arbiter
 * flag modules, the dashboard's AXIS_DEFAULTS, launcher comments). Now:
 *   - arbiter/policy/protection-mode.ts   DEFAULT_MODE, read by BOTH flag modules
 *   - launcher/src/mode.ts                DEFAULT_MODE (effective mode, --help, init template)
 *   - dashboard/src/config-axes.ts        DEFAULT_MODE → AXIS_DEFAULTS, served to the browser
 * The three packages ship standalone, so the constant is mirrored, and this
 * test is what keeps the mirrors honest. It also pins the two surgical
 * config.toml editors (launcher `mandu mode`, dashboard Protection drawer)
 * to byte-identical output, and the per-package test helpers to one text.
 *
 * The FROZEN integrity axis (docs/design/architecture/protection-modes.md §10) adds two more
 * mirrors: the opt-in variable's NAME and the list of modes the product
 * offers. The arbiter daemon, the launcher and the dashboard each refuse an
 * integrity-ON start or save without the opt-in, so the three must agree on
 * what the variable is called and on which values open it; a drift would
 * let one surface accept what the next one refuses (or the reverse).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as arbiterMode from "../../arbiter/policy/protection-mode.js";
import * as arbiterIntegrity from "../../arbiter/policy/integrity-flag.js";
import { resolveConfidentialityEnabled } from "../../arbiter/policy/confidentiality-flag.js";
import * as launcherMode from "../../launcher/src/mode.js";
import { applyModeEdit as launcherApplyModeEdit, MODE_PROVENANCE_COMMENT as LAUNCHER_COMMENT } from "../../launcher/src/config-edit.js";
import { DEFAULT_CONFIG_TOML } from "../../launcher/src/config.js";
import { usageText } from "../../launcher/src/usage.js";
import * as dash from "../../dashboard/src/config-axes.js";
import { MODE_AXES as HELPER_AXES, axesEnv } from "../lib/axes.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("the default mode is the same in the arbiter, the launcher and the dashboard", () => {
  assert.equal(launcherMode.DEFAULT_MODE, arbiterMode.DEFAULT_MODE, "launcher/src/mode.ts DEFAULT_MODE drifted from the arbiter's");
  assert.equal(dash.DEFAULT_MODE, arbiterMode.DEFAULT_MODE, "dashboard/src/config-axes.ts DEFAULT_MODE drifted from the arbiter's");
});

test("what the arbiter ACTUALLY runs with nothing stated is that mode's pair (both flag modules)", () => {
  const pair = { integrity: arbiterIntegrity.resolveIntegrityEnabled({}), confidentiality: resolveConfidentialityEnabled({}) };
  assert.deepEqual(pair, arbiterMode.MODE_AXES[arbiterMode.DEFAULT_MODE]);
  assert.deepEqual({ ...dash.AXIS_DEFAULTS }, pair, "the dashboard's AXIS_DEFAULTS (served as `defaults`) is the same pair");
  assert.deepEqual(launcherMode.effectiveAxes({}, {}), pair, "the launcher's effective pair for an unreported, unrequested launch");
});

test("the mode table is identical everywhere it is written down", () => {
  assert.deepEqual([...launcherMode.MODES], [...arbiterMode.PROTECTION_MODES]);
  assert.deepEqual([...dash.MODES], [...arbiterMode.PROTECTION_MODES]);
  for (const m of arbiterMode.PROTECTION_MODES) {
    assert.deepEqual(launcherMode.MODE_AXES[m], arbiterMode.MODE_AXES[m], `launcher ${m}`);
    assert.deepEqual(dash.MODE_AXES[m], arbiterMode.MODE_AXES[m], `dashboard ${m}`);
    assert.deepEqual(HELPER_AXES[m], arbiterMode.MODE_AXES[m], `test helper ${m}`);
    assert.equal(launcherMode.modeOf(arbiterMode.MODE_AXES[m]), m);
    assert.equal(dash.modeOf(arbiterMode.MODE_AXES[m]), m);
  }
});

test("every package's axes helper is the same text", () => {
  // Each package's test/axes.ts; the tests/ package keeps its copy in tests/lib/.
  const copies = [...["arbiter", "launcher", "fs-sync", "interceptors/reply-filter"].map((p) => join(REPO, p, "test", "axes.ts")),
    join(REPO, "tests", "lib", "axes.ts")];
  const first = readFileSync(copies[0]!, "utf8");
  for (const c of copies.slice(1)) assert.equal(readFileSync(c, "utf8"), first, `${c} drifted from ${copies[0]}`);
});

test("the launcher's user-facing text marks the same default", () => {
  const marked = usageText().split("\n").filter((l) => l.includes("(default)"));
  assert.equal(marked.length, 1);
  assert.ok(marked[0]!.trimStart().startsWith(arbiterMode.DEFAULT_MODE + " "), marked[0]);
  assert.ok(
    DEFAULT_CONFIG_TOML.includes(`# mode = "${arbiterMode.DEFAULT_MODE}"`),
    "the `mandu init` template shows the default mode, commented out",
  );
});

test("the two surgical config.toml editors produce byte-identical files", () => {
  assert.equal(dash.MODE_PROVENANCE_COMMENT, LAUNCHER_COMMENT);
  const inputs = [
    "",
    "proxy-port = 0\n",
    "proxy-port = 0", // no trailing newline
    `mode = "full"\n`,
    `  mode = "full"   # chosen in March\nnet-guard = true\n`,
    `mode = "a#b"  # odd\n`,
    `# mode = "off"\nullm-mode = "x"\n`,
    "integrity = true  # expert\nconfidentiality = false\n",
    `mode = "full"\nmode = "off"\nintegrity = false\n`,
    `[section]\nmode = 'secrets'\r\nfs-sync = true\r\n`,
    `${LAUNCHER_COMMENT}\nmode = "injection"\n`,
  ];
  for (const text of inputs) {
    for (const m of arbiterMode.PROTECTION_MODES) {
      assert.equal(dash.applyModeEdit(text, m), launcherApplyModeEdit(text, m), `${JSON.stringify(text)} → ${m}`);
    }
  }
});

test("the frozen-integrity opt-in has ONE name, and the product offers the same modes (arbiter, launcher, dashboard)", () => {
  assert.equal(arbiterIntegrity.INTEGRITY_OPT_IN_ENV, "MANDU_EXPERIMENTAL_INTEGRITY");
  assert.equal(launcherMode.INTEGRITY_OPT_IN_ENV, arbiterIntegrity.INTEGRITY_OPT_IN_ENV, "launcher/src/mode.ts drifted");
  assert.equal(dash.INTEGRITY_OPT_IN_ENV, arbiterIntegrity.INTEGRITY_OPT_IN_ENV, "dashboard/src/config-axes.ts drifted");
  assert.deepEqual([...dash.PRODUCT_MODES], [...launcherMode.PRODUCT_MODES], "the dashboard offers what the launcher offers");
  // The product modes are exactly the modes with the frozen axis OFF, and the
  // default is one of them (a cold start must never need the opt-in).
  const unfrozen = arbiterMode.PROTECTION_MODES.filter((m) => !arbiterMode.MODE_AXES[m].integrity);
  assert.deepEqual([...launcherMode.PRODUCT_MODES].sort(), [...unfrozen].sort());
  assert.ok(launcherMode.PRODUCT_MODES.includes(arbiterMode.DEFAULT_MODE), "the default mode needs no opt-in");
  // The shared test helper opts in exactly for the frozen modes, under that name.
  for (const m of arbiterMode.PROTECTION_MODES) {
    const env = axesEnv(m) as Record<string, string>;
    assert.equal(arbiterIntegrity.integrityOptedIn(env), arbiterMode.MODE_AXES[m].integrity, `test helper axesEnv(${m})`);
  }
});

test("integrityOptedIn reads the same values the same way in all three packages", () => {
  // Only an explicit yes opens the frozen axis; a typo keeps it refused.
  const table: Array<[string | undefined, boolean]> = [
    ["1", true], ["true", true], ["on", true], ["yes", true], ["YES", true], [" 1 ", true],
    ["0", false], ["", false], ["maybe", false], [undefined, false],
  ];
  for (const [value, want] of table) {
    const env: Record<string, string | undefined> = value === undefined ? {} : { MANDU_EXPERIMENTAL_INTEGRITY: value };
    const label = JSON.stringify(value) ?? "undefined";
    assert.equal(arbiterIntegrity.integrityOptedIn(env), want, `arbiter ${label}`);
    assert.equal(launcherMode.integrityOptedIn(env), want, `launcher ${label}`);
    assert.equal(dash.integrityOptedIn(env), want, `dashboard ${label}`);
  }
});
