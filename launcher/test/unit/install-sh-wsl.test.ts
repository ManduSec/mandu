/**
 * install-sh on WSL (scripts/install.sh; launcher/src/wsl.ts): WSL1 is refused
 * before anything is downloaded, with the conversion command; a WSL2 kernel
 * release passes the check. Offline: a stub `uname` reports the release.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const INSTALL = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "scripts", "install.sh");
const TOOLS = ["sh", "awk", "sed", "tar", "gzip", "mkdir", "rm", "mktemp", "dirname", "id", "chmod", "cat", "env", "printf"];

/** Run the installer's dry run with a `uname` that reports Linux, x86_64 and `release`. */
function dryRunOn(release: string): { code: number | null; out: string } {
  const root = mkdtempSync(join(tmpdir(), "mandu-install-wsl-"));
  try {
    const bin = join(root, "sysbin");
    mkdirSync(bin, { recursive: true });
    for (const t of TOOLS) {
      const w = spawnSync("sh", ["-c", `command -v ${t}`], { encoding: "utf8" }).stdout.trim();
      if (w) writeFileSync(join(bin, t), `#!/bin/sh\nexec ${w} "$@"\n`, { mode: 0o755 });
    }
    writeFileSync(join(bin, "uname"), `#!/bin/sh\ncase "$1" in -m) echo x86_64 ;; -r) echo ${release} ;; *) echo Linux ;; esac\n`, { mode: 0o755 });
    const r = spawnSync("sh", [INSTALL, "--dry-run", "--prefix", join(root, "p"), "--bin-dir", join(root, "b")], {
      encoding: "utf8", env: { PATH: bin, HOME: root }, timeout: 60_000,
    });
    return { code: r.status, out: r.stdout + r.stderr };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("WSL1 is refused before anything runs, naming the conversion", () => {
  const r = dryRunOn("4.4.0-19041-Microsoft");
  assert.notEqual(r.code, 0);
  assert.match(r.out, /this is WSL1, which cannot run Mandu's protections .*wsl --set-version <distro> 2/);
  assert.doesNotMatch(r.out, /would run/);
});

test("WSL2 kernel releases (with and without the WSL2 suffix) pass the WSL check", () => {
  for (const rel of ["5.15.167.4-microsoft-standard-WSL2", "4.19.104-microsoft-standard", "6.8.0-139-generic"]) {
    const r = dryRunOn(rel);
    assert.doesNotMatch(r.out, /WSL1/, rel);
  }
});
