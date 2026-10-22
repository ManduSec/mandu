/**
 * reftable-git — a git that can make a reftable repository, for the tests
 * that need one (git >= 2.45: `git init --ref-format=reftable`).
 *
 * The PATH's git when it can; else the CI image's own build
 * (scripts/ci/pins.env GIT_REFTABLE_*, built by scripts/ci/guest/provision.sh
 * into /usr/local/lib/mandu-ci/git, off the PATH, since Ubuntu 24.04 ships
 * 2.43), or $MANDU_TEST_REFTABLE_GIT_DIR, put FIRST on this test process's
 * PATH, so the test's own git calls and the production runner's (which
 * finds git on the PATH) both use it. Call it at module load, before any
 * git call of the file: the production runner resolves git once per
 * process. Only the reftable test files call it, so every other suite keeps
 * the distro's git.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Where the CI image builds it (provision.sh step 3b). */
export const CI_REFTABLE_GIT_DIR = "/usr/local/lib/mandu-ci/git/bin";

function canMakeReftable(): boolean {
  const d = mkdtempSync(join(tmpdir(), "mandu-reftable-probe-"));
  try {
    const r = spawnSync("git", ["init", "-q", "--ref-format=reftable", join(d, "r")], {
      encoding: "utf8", env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" },
    });
    return r.status === 0;
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

/** null when a reftable-capable git is first on this process's PATH (put
 *  there if need be); else why not, for the test's skip. */
export function useReftableGit(): string | null {
  if (canMakeReftable()) return null;
  const pathGit = spawnSync("git", ["version"], { encoding: "utf8" }).stdout.trim() || "no git";
  for (const dir of [process.env["MANDU_TEST_REFTABLE_GIT_DIR"], CI_REFTABLE_GIT_DIR]) {
    if (dir === undefined || dir === "" || !existsSync(join(dir, "git"))) continue;
    const was = process.env["PATH"];
    process.env["PATH"] = `${dir}:${was ?? ""}`;
    if (canMakeReftable()) return null;
    if (was === undefined) delete process.env["PATH"]; else process.env["PATH"] = was;
  }
  return `no git here can make a reftable repository (the PATH's: ${pathGit}; it needs 2.45; the CI image builds one into ${CI_REFTABLE_GIT_DIR})`;
}
