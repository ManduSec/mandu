/**
 * config-axes-mode.test — the four protection MODES in src/config-axes.ts
 * (docs/design/architecture/protection-modes.md §3.3, dashboard.md §4.19): the mode table
 * + `modeOf` (every axis pair has a name, no "custom"), the `mode` key on the
 * read side (valid / invalid / absent / mode + axis conflict), the surgical
 * `applyModeEdit` writer (the byte-identical mirror of
 * launcher/src/config-edit.ts: the cross-package parity test lives in
 * tests/stack/), the single-axis write's mode-line re-align, and the arbiter
 * spawn-env fill's mode precedence, and the integrity freeze's pure half
 * (PRODUCT_MODES, integrityOptedIn, readAxesState `integrityAllowed`;
 * docs/design/architecture/protection-modes.md §10).
 *
 * Mandu-new test (NO reference origin). Pure functions + a temp dir; no
 * server, no arbiter, no process.env mutation (env is always passed in).
 * Nothing here hardcodes WHICH mode is the default: expectations derive from
 * DEFAULT_MODE, so the planned default flip changes one constant, not tests.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  AXIS_DEFAULTS,
  DEFAULT_MODE,
  MODES,
  MODE_AXES,
  MODE_PROVENANCE_COMMENT,
  INTEGRITY_OPT_IN_ENV,
  PRODUCT_MODES,
  applyAxesEdit,
  applyModeEdit,
  arbiterAxisSpawnEnv,
  configuredMode,
  integrityOptedIn,
  modeOf,
  readAxesState,
  writeAxes,
  writeMode,
  type Mode,
} from "../../src/config-axes.js";
import { tmpDir } from "./tmp-dir.js";

function withFile<T>(text: string | null, fn: (path: string, dir: string) => T): T {
  const dir = tmpDir("mandu-config-mode-");
  try {
    const path = join(dir, "config.toml");
    if (text !== null) writeFileSync(path, text);
    return fn(path, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ── the mode table ───────────────────────────────────────────────────────────

test("the four modes cover all four axis pairs: modeOf names every pair, no custom", () => {
  assert.deepEqual([...MODES], ["secrets", "injection", "full", "off"]);
  const pairs: [boolean, boolean, Mode][] = [
    [false, true, "secrets"],
    [true, false, "injection"],
    [true, true, "full"],
    [false, false, "off"],
  ];
  for (const [integrity, confidentiality, mode] of pairs) {
    assert.equal(modeOf({ integrity, confidentiality }), mode);
    assert.deepEqual(MODE_AXES[mode], { integrity, confidentiality });
  }
  for (const m of MODES) assert.equal(modeOf(MODE_AXES[m]), m, "round-trip");
});

test("AXIS_DEFAULTS is DERIVED from MODE_AXES[DEFAULT_MODE] (one constant names the default)", () => {
  assert.ok((MODES as readonly string[]).includes(DEFAULT_MODE));
  assert.deepEqual(AXIS_DEFAULTS, MODE_AXES[DEFAULT_MODE]);
});

// ── the integrity freeze (docs/design/architecture/protection-modes.md §10) ───────────────────

test("PRODUCT_MODES are exactly the modes with integrity OFF, the default among them", () => {
  assert.deepEqual([...PRODUCT_MODES], ["secrets", "off"]);
  assert.deepEqual(MODES.filter((m) => !MODE_AXES[m].integrity), [...PRODUCT_MODES]);
  assert.ok(PRODUCT_MODES.includes(DEFAULT_MODE), "the default is never a frozen mode");
  assert.equal(INTEGRITY_OPT_IN_ENV, "MANDU_EXPERIMENTAL_INTEGRITY");
});

test("integrityOptedIn: only an explicit 1/true/on/yes (trimmed, any case) opts in", () => {
  for (const v of ["1", "true", "on", "yes", "TRUE", " On ", "Yes"]) {
    assert.equal(integrityOptedIn({ [INTEGRITY_OPT_IN_ENV]: v }), true, JSON.stringify(v));
  }
  for (const v of [undefined, "", "0", "false", "off", "no", "2", "yes please", "y", "enabled"]) {
    assert.equal(integrityOptedIn({ [INTEGRITY_OPT_IN_ENV]: v }), false, JSON.stringify(v));
  }
  assert.equal(integrityOptedIn({ MANDU_INTEGRITY: "1", MANDU_MODE: "full" }), false,
    "turning the axis on is not the opt-in");
});

test("readAxesState: integrityAllowed follows the env opt-in only, never the file", () => {
  for (const text of [null, 'mode = "full"\n', "integrity = true\n", 'mode = "secrets"\n']) {
    withFile(text, (path, dir) => {
      assert.equal(readAxesState({ MANDU_HOME: dir }).integrityAllowed, false, JSON.stringify(text));
      assert.equal(readAxesState({ MANDU_HOME: dir, [INTEGRITY_OPT_IN_ENV]: "1" }).integrityAllowed, true);
      assert.equal(readAxesState({ MANDU_HOME: dir, [INTEGRITY_OPT_IN_ENV]: "0" }).integrityAllowed, false);
    });
  }
  // An unresolvable path still answers the field.
  assert.equal(readAxesState({}).integrityAllowed, false);
  assert.equal(readAxesState({ [INTEGRITY_OPT_IN_ENV]: "yes" }).integrityAllowed, true);
});

// ── the read side: the `mode` key ────────────────────────────────────────────

test("configuredMode: valid (trimmed, case-folded), invalid → badMode, absent / empty / non-string → null", () => {
  assert.deepEqual(configuredMode('mode = "secrets"\n'), { mode: "secrets" });
  assert.deepEqual(configuredMode("mode = ' FULL '  # loud\n"), { mode: "full" });
  assert.deepEqual(configuredMode('mode = "paranoid"\n'), { mode: null, badMode: "paranoid" });
  assert.deepEqual(configuredMode(""), { mode: null });
  assert.deepEqual(configuredMode('mode = ""\n'), { mode: null });
  assert.deepEqual(configuredMode("mode = true\n"), { mode: null });
  assert.deepEqual(configuredMode('# mode = "off"\nullm-mode = "off"\n'), { mode: null },
    "a commented-out line and a longer key are not the mode key");
  assert.deepEqual(configuredMode('mode = "off"\nmode = "full"\n'), { mode: "full" }, "duplicates: LAST wins");
});

test("GET shape: a valid mode fills `effective` for axes with no key; configured stays the AXIS KEY value", () => {
  for (const m of MODES) {
    withFile(`mode = "${m}"\n`, (path, dir) => {
      const st = readAxesState({ MANDU_HOME: dir });
      assert.equal(st.mode, m);
      assert.equal("badMode" in st, false);
      assert.deepEqual(st.configured, { integrity: null, confidentiality: null });
      assert.deepEqual(st.effective, MODE_AXES[m]);
      assert.equal(st.effectiveMode, m);
      assert.equal(st.defaultMode, DEFAULT_MODE);
      assert.deepEqual(st.defaults, MODE_AXES[DEFAULT_MODE]);
    });
  }
});

test("GET shape: an invalid mode is ignored (defaults rule) and reported as badMode", () => {
  withFile('mode = "paranoid"\n', (path, dir) => {
    const st = readAxesState({ MANDU_HOME: dir });
    assert.equal(st.mode, null);
    assert.equal(st.badMode, "paranoid");
    assert.deepEqual(st.effective, MODE_AXES[DEFAULT_MODE]);
    assert.equal(st.effectiveMode, DEFAULT_MODE);
  });
});

test("GET shape: absent mode (and a missing file) → mode null, effectiveMode = the default, no badMode", () => {
  for (const text of ["proxy-port = 0\n", null]) {
    withFile(text, (path, dir) => {
      const st = readAxesState({ MANDU_HOME: dir });
      assert.equal(st.mode, null);
      assert.equal("badMode" in st, false);
      assert.equal(st.effectiveMode, DEFAULT_MODE);
      assert.equal(st.defaultMode, DEFAULT_MODE);
    });
  }
});

test("GET shape: mode + axis conflict → the axis key beats the mode for THAT axis only, never an error", () => {
  withFile('mode = "full"\nintegrity = false\n', (path, dir) => {
    const st = readAxesState({ MANDU_HOME: dir });
    assert.equal(st.mode, "full", "the file's mode string is reported as written");
    assert.deepEqual(st.configured, { integrity: false, confidentiality: null });
    assert.deepEqual(st.effective, { integrity: false, confidentiality: true });
    assert.equal(st.effectiveMode, "secrets", "the name of the pair that actually runs");
  });
  withFile('mode = "off"\nconfidentiality = true\nintegrity = true\n', (path, dir) => {
    assert.equal(readAxesState({ MANDU_HOME: dir }).effectiveMode, "full");
  });
});

// ── applyModeEdit (byte-identical mirror of launcher/src/config-edit.ts) ─────

test("applyModeEdit: an empty file gains the provenance comment + the mode line, nothing else", () => {
  assert.equal(applyModeEdit("", "secrets"), `${MODE_PROVENANCE_COMMENT}\nmode = "secrets"\n`);
});

test("applyModeEdit: the provenance comment's VALUE is the launcher's (the shared constant)", () => {
  assert.equal(MODE_PROVENANCE_COMMENT,
    "# mode below is managed by Mandu (`mandu mode`, or the dashboard's Protection drawer)");
});

test("applyModeEdit: replaces in place, keeping the indent and the inline comment", () => {
  assert.equal(
    applyModeEdit('proxy-port = 0\n  mode = "injection"   # my pick\nfoo = 1\n', "full"),
    'proxy-port = 0\n  mode = "full"  # my pick\nfoo = 1\n',
  );
  // A `#` INSIDE the quoted value is not a comment.
  assert.equal(applyModeEdit('mode = "inj#ection"\n', "off"), 'mode = "off"\n');
  assert.equal(applyModeEdit("mode = 'x#y' # real\n", "off"), 'mode = "off"  # real\n');
  // Every occurrence is replaced (the last-wins read stays coherent).
  assert.equal(applyModeEdit('mode = "off"\nmode = "full"\n', "secrets"), 'mode = "secrets"\nmode = "secrets"\n');
});

test("applyModeEdit: a commented-out `# mode = …` and a longer key (`ullm-mode`) stay untouched", () => {
  const text = '# mode = "off"\nullm-mode = "fast"\nmode-extra = 1\n';
  const out = applyModeEdit(text, "full");
  assert.ok(out.startsWith(text), "every prior byte verbatim");
  assert.equal(out, `${text}\n${MODE_PROVENANCE_COMMENT}\nmode = "full"\n`);
});

test("applyModeEdit: EXISTING axis lines are re-aligned to the mode's pair, none appended", () => {
  const out = applyModeEdit("integrity = true   # paper defense\nproxy-port = 0\n", "secrets");
  assert.equal(out,
    `integrity = false  # paper defense\nproxy-port = 0\n\n${MODE_PROVENANCE_COMMENT}\nmode = "secrets"\n`);
  assert.doesNotMatch(out, /confidentiality/, "an absent axis line is never appended");
  assert.equal(
    applyModeEdit('confidentiality = "true"\nintegrity = false\nmode = "secrets"\n', "injection"),
    'confidentiality = false\nintegrity = true\nmode = "injection"\n',
  );
});

test("applyModeEdit: appends complete an unterminated last line; the comment is added ONCE", () => {
  assert.equal(applyModeEdit("foo = 1", "off"), `foo = 1\n\n${MODE_PROVENANCE_COMMENT}\nmode = "off"\n`);
  // The comment survives a user deleting the mode line: a re-append reuses it.
  const once = applyModeEdit("", "full").replace('mode = "full"\n', "");
  const again = applyModeEdit(once, "off");
  assert.equal(again.split(MODE_PROVENANCE_COMMENT).length - 1, 1);
});

test("applyModeEdit: round-trip for all four modes from several starting texts reads back as that mode", () => {
  const starts = [
    "",
    "proxy-port = 0\n",
    'mode = "paranoid"\n',
    "integrity = true\nconfidentiality = true\n",
    'mode = "full"\nintegrity = false # stale\n',
    '[section]\n  mode = "off"\n  confidentiality = true\n',
    "no-trailing-newline = 1",
  ];
  for (const start of starts) {
    let text = start;
    for (const m of [...MODES, ...[...MODES].reverse()]) {
      text = applyModeEdit(text, m);
      withFile(text, (path, dir) => {
        const st = readAxesState({ MANDU_HOME: dir });
        assert.equal(st.mode, m, `mode key after writing ${m} onto ${JSON.stringify(start)}`);
        assert.equal(st.effectiveMode, m, "the file never contradicts itself");
        assert.deepEqual(st.effective, MODE_AXES[m]);
        assert.equal("badMode" in st, false);
      });
      assert.equal(applyModeEdit(text, m), text, "idempotent");
    }
  }
});

test("writeMode: creates the file + parent dir, tmp+rename, returns the post-write GET shape", () => {
  const dir = tmpDir("mandu-config-mode-");
  try {
    const path = join(dir, "deep", "config.toml");
    const st = writeMode({ MANDU_HOME: join(dir, "deep") }, "secrets");
    assert.equal(readFileSync(path, "utf8"), `${MODE_PROVENANCE_COMMENT}\nmode = "secrets"\n`);
    assert.equal(st.mode, "secrets");
    assert.deepEqual(st.effective, MODE_AXES.secrets);
    assert.throws(() => writeMode({}, "full"), /cannot resolve the config path/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── the single-axis write keeps the file self-consistent ─────────────────────

test("applyAxesEdit: a single-axis write REWRITES an existing mode line to the resulting pair's name", () => {
  // mode = full, no axis lines; integrity off → the pair is secrets.
  const out = applyAxesEdit('mode = "full"  # chosen in the drawer\n', { integrity: false });
  assert.match(out, /^mode = "secrets" {2}# chosen in the drawer$/m, "in place, inline comment kept");
  assert.match(out, /^integrity = false$/m);
  withFile(out, (path, dir) => {
    const st = readAxesState({ MANDU_HOME: dir });
    assert.equal(st.mode, "secrets");
    assert.equal(st.effectiveMode, "secrets");
    assert.deepEqual(st.effective, { integrity: false, confidentiality: true },
      "the OTHER axis keeps what the old mode gave it");
  });
  // An invalid mode line is a mode line too: it is repaired to the real pair.
  const fixed = applyAxesEdit('mode = "paranoid"\n', { confidentiality: !AXIS_DEFAULTS.confidentiality });
  withFile(fixed, (path, dir) => {
    const st = readAxesState({ MANDU_HOME: dir });
    assert.equal("badMode" in st, false);
    assert.equal(st.mode, st.effectiveMode);
  });
});

test("applyAxesEdit: a file WITHOUT a mode line gains none (the narrow single-axis act stays narrow)", () => {
  const out = applyAxesEdit('# mode = "full"\nullm-mode = "x"\n', { integrity: false });
  assert.doesNotMatch(out, /^mode\s*=/m);
  assert.match(out, /^# mode = "full"$/m, "a commented-out mode line is untouched");
  assert.match(out, /^ullm-mode = "x"$/m);
});

test("writeAxes: the re-align holds through the FS wrapper", () => {
  withFile('mode = "injection"\n', (path, dir) => {
    const st = writeAxes({ MANDU_HOME: dir }, { confidentiality: true });
    assert.equal(st.mode, "full");
    assert.equal(st.effectiveMode, "full");
    assert.match(readFileSync(path, "utf8"), /^mode = "full"$/m);
  });
});

// ── arbiterAxisSpawnEnv with modes (launcher precedence) ─────────────────────

test("arbiterAxisSpawnEnv: a file mode alone resolves into BOTH explicit axis vars", () => {
  const want: Record<Mode, Record<string, string>> = {
    secrets: { MANDU_INTEGRITY: "0", MANDU_CONFIDENTIALITY: "1" },
    injection: { MANDU_INTEGRITY: "1", MANDU_CONFIDENTIALITY: "0" },
    full: { MANDU_INTEGRITY: "1", MANDU_CONFIDENTIALITY: "1" },
    off: { MANDU_INTEGRITY: "0", MANDU_CONFIDENTIALITY: "0" },
  };
  for (const m of MODES) {
    withFile(`mode = "${m}"\n`, (path, dir) => {
      assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: dir }), want[m]);
    });
  }
});

test("arbiterAxisSpawnEnv: file mode + file axis → the axis key beats the mode for that axis only", () => {
  withFile('mode = "full"\nintegrity = false\n', (path, dir) => {
    assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: dir }),
      { MANDU_INTEGRITY: "0", MANDU_CONFIDENTIALITY: "1" });
  });
});

test("arbiterAxisSpawnEnv: an invalid file mode states nothing (arbiter defaults rule)", () => {
  withFile('mode = "paranoid"\n', (path, dir) => {
    assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: dir }), {});
  });
});

test("arbiterAxisSpawnEnv: an explicit env AXIS var wins that one axis; the file mode fills the other", () => {
  withFile('mode = "full"\n', (path, dir) => {
    assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: dir, MANDU_INTEGRITY: "0" }),
      { MANDU_CONFIDENTIALITY: "1" });
  });
});

test("arbiterAxisSpawnEnv: env MANDU_MODE speaks for BOTH axes: the file is not consulted, the mode is translated", () => {
  withFile('mode = "full"\nintegrity = true\nconfidentiality = true\n', (path, dir) => {
    assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: dir, MANDU_MODE: "off" }),
      { MANDU_INTEGRITY: "0", MANDU_CONFIDENTIALITY: "0" });
    // An explicit env axis var still beats the env mode for that axis, and
    // the file STILL does not leak in for it.
    assert.deepEqual(
      arbiterAxisSpawnEnv({ MANDU_HOME: dir, MANDU_MODE: " Secrets ", MANDU_CONFIDENTIALITY: "0" }),
      { MANDU_INTEGRITY: "0" });
    // An EMPTY MANDU_MODE names nothing (the launcher's rule): the file rules.
    assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: dir, MANDU_MODE: "" }),
      { MANDU_INTEGRITY: "1", MANDU_CONFIDENTIALITY: "1" });
  });
  // No config file at all: the env mode is still translated.
  assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_MODE: "secrets" }),
    { MANDU_INTEGRITY: "0", MANDU_CONFIDENTIALITY: "1" });
  assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: "/dev/null/mandu-test-home", MANDU_MODE: "full" }),
    { MANDU_INTEGRITY: "1", MANDU_CONFIDENTIALITY: "1" });
});

test("arbiterAxisSpawnEnv: an env MANDU_MODE naming no mode is ignored like a bad file mode: the file still speaks", () => {
  withFile('mode = "full"\n', (path, dir) => {
    assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: dir, MANDU_MODE: "paranoid" }),
      { MANDU_INTEGRITY: "1", MANDU_CONFIDENTIALITY: "1" });
  });
});

test("arbiterAxisSpawnEnv: the policy-file seeding is independent of the env mode", () => {
  withFile('mode = "full"\npolicy-file = "~/law.yaml"\n', (path, dir) => {
    assert.deepEqual(arbiterAxisSpawnEnv({ MANDU_HOME: dir, MANDU_MODE: "off" }), {
      MANDU_INTEGRITY: "0", MANDU_CONFIDENTIALITY: "0", MANDU_POLICY_FILE: "~/law.yaml",
    });
  });
});
