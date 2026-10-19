/**
 * doctor-yama e2e — `mandu doctor` through the real CLI entry (a child
 * process: run.ts → runSubcommand → runDoctor with the REAL host probes)
 * reports Yama's `ptrace_scope`, which every same-account boundary (the
 * dashboard sign-in, the human plane, the reply filter) assumes is 1 or more
 * (rootless-confinement-ubuntu-2404.md §3.3). The oracle is this host's own
 * `/proc/sys/kernel/yama/ptrace_scope`: a ✓ row naming its value at 1 or
 * more, a ✗ warning with the fix at 0 or with no Yama. Linux only (macOS has
 * no Yama, and doctor prints no row there, also asserted).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCli } from "../lib/run-cli.js";

const YAMA = "/proc/sys/kernel/yama/ptrace_scope";

test("mandu doctor reports this host's Yama ptrace_scope in the secrets section: ok at 1 or more, a warning with the fix at 0 or with no Yama", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-doctor-yama-"));
  const home = join(dir, "home");
  mkdirSync(home);
  try {
    const r = await runCli(["doctor"], {
      HOME: home, PATH: process.env["PATH"], MANDU_HOME: join(dir, "mandu-home"),
      XDG_RUNTIME_DIR: dir, MANDU_RUNTIME_DIR: join(dir, "rt"), MANDU_ARBITER_SOCK: join(dir, "absent.sock"),
    });
    assert.equal(r.code, 0, `doctor is a diagnostic: always exits 0\n${r.stderr}`);
    const out = r.stdout;
    if (process.platform !== "linux") {
      assert.doesNotMatch(out, /Yama/, "no Yama off Linux: no row");
      return;
    }
    const secrets = out.slice(out.indexOf("Your secrets"), out.indexOf("What Mandu enforces"));
    let raw: string | null = null;
    try { raw = readFileSync(YAMA, "utf8").trim(); } catch { raw = null; }
    if (raw === null) {
      assert.match(secrets, /✗ Yama is not in this kernel \(no \/proc\/sys\/kernel\/yama\/ptrace_scope\)/, out);
    } else if (raw === "0") {
      assert.match(secrets, /✗ Yama ptrace_scope is 0: .*fix: sudo sysctl kernel\.yama\.ptrace_scope=1/, out);
    } else {
      assert.match(secrets, new RegExp(`✓ Yama ptrace_scope ${raw}: `), out);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
