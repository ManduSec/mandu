/**
 * Unit: fs-sync's git runs HARDENED (src/hardened-git.ts,
 * docs/design/architecture/write-protection.md §8.6): its runner and its ignore check force
 * off every program-starting key git knows and scrub the inherited `GIT_*`
 * (the context's own GIT_DIR / GIT_WORK_TREE go back on top). A repository
 * whose config names `core.fsmonitor`, hooks, a commit signer and
 * `log.showSignature` starts none of them through fs-sync. (What `-c` cannot
 * reach, a filter or merge driver the substrate's config names, is the
 * frozen axis's stated residual, §6.)
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { gitExec, gitExecSync } from "../../src/git.js";
import { humanIgnoredSet } from "../../src/ignored.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is exercised

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const ENV = {
  PATH: process.env["PATH"] ?? "/usr/bin:/bin", LC_ALL: "C", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
};

test("the runner, a commit and the ignore check start no program the repository names; an inherited GIT_DIR does not reach git", async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-fssync-githard-")));
  dirs.push(dir);
  const root = join(dir, "repo");
  const marker = join(dir, "fired");
  const prog = join(dir, "trap.sh");
  writeFileSync(prog, `#!/bin/sh\necho "$0 $*" >> '${marker}'\nexit 0\n`);
  chmodSync(prog, 0o755);
  const hooks = join(dir, "hooks");
  mkdirSync(hooks);
  for (const h of ["pre-commit", "commit-msg", "post-commit", "post-index-change", "reference-transaction", "pre-auto-gc"]) {
    writeFileSync(join(hooks, h), `#!/bin/sh\necho "hook $0" >> '${marker}'\nexit 0\n`);
    chmodSync(join(hooks, h), 0o755);
  }
  execFileSync("git", ["init", "-q", root], { env: ENV });
  writeFileSync(join(root, "a.txt"), "one\n");
  writeFileSync(join(root, ".gitignore"), "node_modules/\n");
  const past = new Date(Date.now() - 3_600_000);
  for (const f of ["a.txt", ".gitignore"]) utimesSync(join(root, f), past, past);
  execFileSync("git", ["add", "."], { cwd: root, env: ENV });
  execFileSync("git", ["commit", "-qm", "one"], { cwd: root, env: ENV });
  for (const [k, v] of [
    ["core.fsmonitor", prog], ["core." + "hooksPath", hooks], ["log.showSignature", "true"], ["gpg.program", prog],
    ["commit.gpgSign", "true"], ["gc.auto", "1"], ["gc.autoPackLimit", "1"], ["maintenance.auto", "true"],
    ["user.name", "t"], ["user.email", "t@x"],
  ]) execFileSync("git", ["config", k!, v!], { cwd: root, env: ENV });

  const saved = process.env["GIT_DIR"];
  process.env["GIT_DIR"] = join(dir, "nowhere.git");
  try {
    const ctx = { cwd: root };
    assert.ok(gitExecSync(["ls-files", "-s"], ctx).stdout.includes("a.txt"), "an inherited GIT_DIR is dropped");
    assert.ok(gitExecSync(["log", "--format=%H %s"], ctx).stdout.includes(" one"));
    const c = await gitExec(["commit", "-q", "--allow-empty", "-m", "sync"], ctx);
    assert.equal(c.code, 0, c.stderr);
    assert.deepEqual([...humanIgnoredSet(ctx, ["node_modules/x", "a.txt"])], ["node_modules/x"]);
  } finally {
    if (saved === undefined) delete process.env["GIT_DIR"]; else process.env["GIT_DIR"] = saved;
  }
  assert.equal(existsSync(marker), false, `a trap ran: ${existsSync(marker) ? readFileSync(marker, "utf8") : ""}`);
});
