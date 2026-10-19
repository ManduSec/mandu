/**
 * config-edit — the surgical `mode` editor (protection-modes.md §3.2, §4
 * "config.toml editor round-trip with `mode`").
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { MODE_PROVENANCE_COMMENT, applyModeEdit, writeModeToConfig } from "../../src/config-edit.js";
import { configLevel, savedMode } from "../../src/mode-command.js";
import { MODES } from "../../src/mode.js";
import { tmpDir } from "../lib/tmp-dir.js";

test("an empty file gets the provenance comment and the mode line, nothing else", () => {
  assert.equal(applyModeEdit("", "secrets"), `${MODE_PROVENANCE_COMMENT}\nmode = "secrets"\n`);
});

test("an existing mode line is replaced in place; indent and inline comment survive; no second comment", () => {
  const before = `# mine\nproxy-port = 0\n  mode = "full"   # chosen in March\nnet-guard = true\n`;
  const after = applyModeEdit(before, "off");
  assert.equal(after, `# mine\nproxy-port = 0\n  mode = "off"  # chosen in March\nnet-guard = true\n`);
  assert.ok(!after.includes(MODE_PROVENANCE_COMMENT));
});

test("every other byte is preserved, including a commented-out mode line and longer keys", () => {
  const before = `# mode = "off"\nullm-mode = "x"\nfs-sync = true`;
  const after = applyModeEdit(before, "full");
  assert.ok(after.startsWith(before + "\n"), "the original text is an untouched prefix");
  assert.ok(after.endsWith(`mode = "full"\n`));
});

test("existing axis lines are RE-ALIGNED to the mode (a stale axis key would silently beat it), never appended", () => {
  const before = `integrity = true  # expert\nconfidentiality = true\n`;
  const after = applyModeEdit(before, "secrets");
  assert.match(after, /^integrity = false {2}# expert$/m);
  assert.match(after, /^confidentiality = true$/m);
  const none = applyModeEdit("proxy-port = 0\n", "secrets");
  assert.ok(!/^integrity|^confidentiality/m.test(none));
});

test("round-trip: whatever was there, the file reads back as the mode just written", () => {
  const starts = ["", "integrity = false\n", `mode = "full"\nconfidentiality = false\n`, `mode = "bogus"\n`];
  for (const start of starts) {
    for (const m of MODES) {
      const { level, badMode } = configLevel(applyModeEdit(start, m));
      assert.equal(badMode, undefined);
      assert.equal(savedMode(level).mode, m, `${JSON.stringify(start)} → ${m}`);
    }
  }
});

test("writeModeToConfig creates the file and its directory, and rewrites atomically", () => {
  const dir = tmpDir("mdu-mode-");
  const path = join(dir, "nested", "config.toml");
  writeModeToConfig(path, "full");
  assert.equal(readFileSync(path, "utf8"), `${MODE_PROVENANCE_COMMENT}\nmode = "full"\n`);
  writeFileSync(path, `proxy-port = 0\n` + readFileSync(path, "utf8"));
  writeModeToConfig(path, "secrets");
  assert.equal(readFileSync(path, "utf8"), `proxy-port = 0\n${MODE_PROVENANCE_COMMENT}\nmode = "secrets"\n`);
});
