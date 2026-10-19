/**
 * subcommand-help.test (e2e) — `mandu <verb> --help` through the REAL CLI
 * entry prints the verb's usage, exits 0 and does nothing else (release
 * checklist d8: `setup --help` said "unknown option"; `stop`, `reap`, `init`
 * and `dashboard` used to act on it). Runs in an empty HOME and runtime dir,
 * so an accidental action would show as files written there.
 * No protection axis is involved (no arbiter, no agent).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const PKG = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..");

test("mandu <verb> --help prints usage, exits 0, and touches nothing", { timeout: 180_000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-help-e2e-"));
  try {
    const home = join(dir, "home");
    const run = join(dir, "run");
    // Three spawns, not one per verb: every verb answers --help through one
    // dispatcher branch, which test/unit/subcommand-help.test.ts drives for
    // each verb and both spellings. These prove the real CLI entry reaches it:
    // `setup -h` (the verb that said "unknown option") and the two verbs that
    // would write files here if they acted instead (`init`: a config;
    // `dashboard`: the runtime registry).
    for (const [verb, flag] of [["setup", "-h"], ["init", "--help"], ["dashboard", "--help"]] as const) {
      const r = spawnSync(join(PKG, "node_modules", ".bin", "tsx"), [join(PKG, "src", "run.ts"), verb, flag], {
        cwd: PKG,
        env: { PATH: process.env["PATH"], HOME: home, XDG_RUNTIME_DIR: run, XDG_CONFIG_HOME: join(home, ".config") },
        encoding: "utf8",
      });
      assert.equal(r.status, 0, `${verb} ${flag}: ${r.stderr}`);
      assert.match(r.stdout, new RegExp(`^usage: mandu ${verb}\\b`), `${verb} ${flag}`);
      assert.doesNotMatch(r.stderr, /unknown option/, `${verb} ${flag}`);
    }
    // Nothing was written: no config (init), no runtime registry (dashboard).
    assert.deepEqual(readdirSync(dir), [], "no HOME or runtime dir was created");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
