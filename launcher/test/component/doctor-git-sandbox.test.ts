/**
 * doctor-git-sandbox e2e — `mandu doctor` through the real CLI entry (a child
 * process with the REAL host probes) says whether Mandu's own git on the AI's
 * repositories runs in its sandbox here (write-protection.md §8, hardened-git.ts
 * probeGitSandbox): the row agrees with the probe run in this process, and
 * MANDU_GIT_SANDBOX=0 turns it to "turned off" whatever the host can do.
 * Linux: bubblewrap; macOS: Seatbelt (git-hardening.md §5.2).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCli } from "../lib/run-cli.js";
import { isSeatbeltGitSandbox, probeGitSandbox } from "../../src/hardened-git.js";

test("mandu doctor's git sandbox row agrees with the host's probe; MANDU_GIT_SANDBOX=0 says it is turned off", { skip: process.platform !== "linux" && process.platform !== "darwin" ? "the git sandbox is built for Linux and macOS" : false }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-doctor-gitsb-"));
  const home = join(dir, "home");
  mkdirSync(home);
  const env = {
    HOME: home,
    PATH: process.env["PATH"],
    MANDU_HOME: join(dir, "mandu-home"),
    XDG_RUNTIME_DIR: dir,
    MANDU_ARBITER_SOCK: join(dir, "absent.sock"),
  };
  try {
    const r = await runCli(["doctor"], env);
    assert.equal(r.code, 0, r.stderr);
    const who = "Mandu's background and launch-prep git on folders the AI can change";
    const sandbox = probeGitSandbox({ env: { PATH: env.PATH } });
    if (sandbox !== null && isSeatbeltGitSandbox(sandbox)) {
      assert.ok(r.stdout.includes(`✓ ${who}: hardened, and run in a sandbox with no network, a read-only view and no other program (${sandbox.sandboxExec}, git ${sandbox.git})`), r.stdout);
    } else if (sandbox !== null) {
      assert.ok(r.stdout.includes(`✓ ${who}: hardened, and run in a sandbox with no network and a read-only view (${sandbox.bwrap})`), r.stdout);
    } else if (process.platform === "linux") {
      assert.ok(r.stdout.includes(`✗ ${who}: hardened, but not in a sandbox: no bubblewrap here can start one`), r.stdout);
    } else {
      // macOS without one: a reason, never the Linux words.
      assert.match(r.stdout, new RegExp(`[✗·] ${who.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}: hardened, (but )?not in a sandbox`), r.stdout);
      assert.doesNotMatch(r.stdout, /no bubblewrap here/);
    }
    const off = await runCli(["doctor"], { ...env, MANDU_GIT_SANDBOX: "0" });
    assert.equal(off.code, 0, off.stderr);
    assert.ok(off.stdout.includes(`· ${who}: hardened; its sandbox is turned off (MANDU_GIT_SANDBOX=0)`), off.stdout);
    assert.doesNotMatch(off.stdout, /[✓✗] Mandu's background and launch-prep git/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
