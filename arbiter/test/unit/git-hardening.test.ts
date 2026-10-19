/**
 * Unit: the arbiter's git runs HARDENED (docs/design/architecture/write-protection.md §8): the
 * scan's and the lock resolver's runners (secret-history-scan.ts
 * HARDENED_GIT_ARGS / historyGitEnv / historyGitCommand, lock-resolution.ts
 * hardenedResolverGit) and the start-up rev read (instance.ts gitRevOf, whose
 * dirty flag no longer runs `git status`: that re-hashed a stat-changed file
 * through the repository's clean filter).
 *
 * A small hostile repository: `core.fsmonitor`, `log.showSignature` +
 * `gpg.program` and a clean filter all name a marker program; none may run.
 * The git sandbox is off here (MANDU_GIT_SANDBOX=0: a marker could not write
 * from inside it); the full matrix is tests/stack/
 * git-hardening.test.ts.
 */
process.env["MANDU_GIT_SANDBOX"] = "0";

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import type { RunningChild } from "../../src/child-run.js";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { HARDENED_GIT_ARGS, historyGitCommand, historyGitEnv, defaultHistoryGitRunner } from "../../policy/secret-history-scan.js";
import { hardenedResolverGit } from "../../policy/lock-resolution.js";
import { gitRevOf, parseLsFilesDebug, statDiffers } from "../../ipc/instance.js";
import { GIT_NO_PROGRAM_CONFIG } from "../../src/hardened-git.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is read

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const ENV = {
  PATH: process.env["PATH"] ?? "/usr/bin:/bin", LC_ALL: "C", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
};

/** A repository with a signed commit, then its traps set. */
function hostile(): { root: string; marker: string } {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-arb-githard-")));
  dirs.push(dir);
  const root = join(dir, "repo");
  const marker = join(dir, "fired");
  const prog = join(dir, "trap.sh");
  writeFileSync(prog, `#!/bin/sh\necho "$0 $*" >> '${marker}'\nexit 0\n`);
  chmodSync(prog, 0o755);
  const signer = join(dir, "signer.sh");
  writeFileSync(signer, "#!/bin/sh\ncat >/dev/null\necho '[GNUPG:] SIG_CREATED ' >&2\nprintf -- '-----BEGIN PGP SIGNATURE-----\\n\\nx\\n-----END PGP SIGNATURE-----\\n'\n");
  chmodSync(signer, 0o755);
  const git = (...a: string[]) => execFileSync("git", a, { cwd: root, env: ENV, stdio: "ignore" });
  execFileSync("git", ["init", "-q", root], { env: ENV });
  writeFileSync(join(root, "a.txt"), "one\n");
  git("add", "a.txt");
  git("-c", `gpg.program=${signer}`, "commit", "-q", "-S", "-m", "signed");
  for (const [k, v] of [["core.fsmonitor", prog], ["log.showSignature", "true"], ["gpg.program", prog], ["filter.evil.clean", prog], ["filter.evil.required", "true"]]) {
    git("config", k!, v!);
  }
  writeFileSync(join(root, ".gitattributes"), "* filter=evil\n");
  const later = new Date(Date.now() + 120_000);
  utimesSync(join(root, "a.txt"), later, later);
  return { root, marker };
}

test("HARDENED_GIT_ARGS: every program-starting key forced, the pager off, literal pathspecs; the env scrubbed", () => {
  for (const kv of GIT_NO_PROGRAM_CONFIG) {
    const i = HARDENED_GIT_ARGS.indexOf(kv);
    assert.ok(i > 0 && HARDENED_GIT_ARGS[i - 1] === "-c", `${kv} forced`);
  }
  for (const f of ["--no-pager", "--literal-pathspecs"]) assert.ok(HARDENED_GIT_ARGS.includes(f));
  assert.ok(HARDENED_GIT_ARGS.includes("core.quotepath=off") && HARDENED_GIT_ARGS.includes("core.untrackedCache=false"));
  const saved = process.env["GIT_EXTERNAL_DIFF"];
  process.env["GIT_EXTERNAL_DIFF"] = "/x";
  try {
    const env = historyGitEnv();
    assert.equal(env["GIT_EXTERNAL_DIFF"], undefined);
    assert.equal(env["GIT_NO_LAZY_FETCH"], "1");
    assert.equal(env["GIT_OPTIONAL_LOCKS"], "0");
  } finally {
    if (saved === undefined) delete process.env["GIT_EXTERNAL_DIFF"]; else process.env["GIT_EXTERNAL_DIFF"] = saved;
  }
  assert.deepEqual(historyGitCommand(["log"]), { file: "git", args: [...HARDENED_GIT_ARGS, "log"] }, "the sandbox off: git itself");
});

test("the scan's runner and the lock resolver's runner start no program the repository names", async () => {
  const { root, marker } = hostile();
  const log = await defaultHistoryGitRunner(["log", "--format=commit %H", "--raw", "--no-abbrev"], { cwd: root, timeoutMs: 20_000 });
  assert.equal(log.code, 0);
  const idx = await defaultHistoryGitRunner(["ls-files", "-s", "-z"], { cwd: root, timeoutMs: 20_000 });
  assert.equal(idx.code, 0);
  const children = new Set<RunningChild>();
  const resolver = hardenedResolverGit(children);
  const r = await resolver(["log", "-1", "--format=%H"], { cwd: root, timeoutMs: 20_000 });
  assert.equal(r.complete, true);
  const r2 = await resolver(["ls-files", "-s", "-z"], { cwd: root, timeoutMs: 20_000 });
  assert.equal(r2.complete, true);
  assert.equal(existsSync(marker), false, `a trap ran: ${existsSync(marker) ? readFileSync(marker, "utf8") : ""}`);
});

test("gitRevOf: rev and dirty with no program the repository names started (no git status)", () => {
  const { root, marker } = hostile();
  const got = gitRevOf(root);
  assert.match(got.rev, /^[0-9a-f]{4,}$/);
  assert.equal(got.dirty, true, "a stat-changed tracked file and an untracked .gitattributes");
  assert.equal(existsSync(marker), false, `a trap ran: ${existsSync(marker) ? readFileSync(marker, "utf8") : ""}`);

  // A clean checkout reads clean.
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-arb-gitrev-")));
  dirs.push(dir);
  execFileSync("git", ["init", "-q", dir], { env: ENV });
  writeFileSync(join(dir, "x.txt"), "x\n");
  const past = new Date(Date.now() - 3_600_000);
  utimesSync(join(dir, "x.txt"), past, past);
  execFileSync("git", ["add", "x.txt"], { cwd: dir, env: ENV });
  execFileSync("git", ["commit", "-qm", "x"], { cwd: dir, env: ENV });
  assert.equal(gitRevOf(dir).dirty, false);
  writeFileSync(join(dir, "x.txt"), "changed\n");
  assert.equal(gitRevOf(dir).dirty, true, "an edited tracked file");
});

test("parseLsFilesDebug / statDiffers: git's size + mtime test, seconds only when the index has no nanoseconds", () => {
  const out = "a.txt\n  ctime: 10:5\n  mtime: 100:7\n  dev: 1\tino: 2\n  uid: 1\tgid: 1\n  size: 12\tflags: 0\n" +
    "\"we\\nird\"\n  mtime: 1:0\n  size: 1\tflags: 0\nsub\n  mtime: 0:0\n  size: 0\tflags: 0\n";
  const e = parseLsFilesDebug(out);
  assert.deepEqual(e.map((x) => x.path), ["a.txt", "sub"], "a quoted name is left out");
  assert.deepEqual(e[0], { path: "a.txt", mtimeSec: 100, mtimeNsec: 7, size: 12 });
  const a = e[0]!;
  assert.equal(statDiffers(a, { isDir: false, size: 12, mtimeNs: 100_000_000_007n }), false);
  assert.equal(statDiffers(a, { isDir: false, size: 13, mtimeNs: 100_000_000_007n }), true, "size");
  assert.equal(statDiffers(a, { isDir: false, size: 12, mtimeNs: 101_000_000_007n }), true, "mtime seconds");
  assert.equal(statDiffers(a, { isDir: false, size: 12, mtimeNs: 100_000_000_008n }), true, "mtime nanoseconds");
  assert.equal(statDiffers({ ...a, mtimeNsec: 0 }, { isDir: false, size: 12, mtimeNs: 100_000_000_008n }), false, "an index without nanoseconds");
  assert.equal(statDiffers(a, null), true, "a missing file");
  assert.equal(statDiffers(e[1]!, { isDir: true, size: 4096, mtimeNs: 5n }), false, "a submodule directory");
});
