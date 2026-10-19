/**
 * kernel — the arbiter's prepared copies (confidentiality-plan-14 §11.1 R3)
 * run their git in the git sandbox (docs/design/architecture/write-protection.md §8.5), like
 * the arbiter's other runners.
 *
 * `prepared-copies.ts` `prepGit` runs every call hardened and, where a git
 * sandbox can be made (bubblewrap on Linux, the kind this file tests;
 * Seatbelt on macOS), sandboxed: reads (`rev-parse`) with no writable bind;
 * the build (`init` of the private bare repository, `pack-objects`,
 * `index-pack`) with ONE writable bind, the build's own work directory in the
 * cache. This file proves, with a real bubblewrap:
 *
 *   - a program git starts inside a build's sandbox (here a clean filter run
 *     on purpose, past the hardening) writes in the work directory only: not
 *     into another copy in the same cache, not into the repository, not
 *     anywhere else;
 *   - the production preparer, sandboxed, still builds a copy of a real
 *     repository's pack without the locked id and seals it.
 *
 * Self-SKIPs where bubblewrap cannot make the sandbox (and where the
 * sandbox is macOS's Seatbelt one, whose refusals are EPERM, not EROFS:
 * launcher/test/darwin/git-sandbox-live.test.ts). Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { stateAxes } from "../lib/axes.js";
import { gitSandbox, isSeatbeltGitSandbox, probeGitSandbox } from "../../arbiter/src/hardened-git.js";
import { idxLookupFile, niceBinary, PreparedCopies, prepGitCommand, prepGitEnv } from "../../arbiter/policy/prepared-copies.js";
import { CacheSealStore } from "../../arbiter/policy/cache-seals.js";

stateAxes("secrets"); // the locks and their copies are the confidentiality axis's

const sandbox = probeGitSandbox({ env: {} });
const skip = sandbox === null || isSeatbeltGitSandbox(sandbox) ? "bubblewrap cannot make the git sandbox here" : false;
const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const ENV = {
  PATH: process.env["PATH"] ?? "/usr/bin:/bin", LC_ALL: "C", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
};

test("a program started inside a build's sandbox writes only in the build's work directory: not another copy, not the repository", { skip }, async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-prep-sandbox-")));
  dirs.push(dir);
  const repo = join(dir, "repo");
  const cacheDir = join(dir, "cache", "object-twins");
  const work = join(cacheDir, `.tmp-${"a".repeat(32)}-${process.pid}-prep`);
  const other = join(cacheDir, "b".repeat(32));
  mkdirSync(repo);
  mkdirSync(work, { recursive: true });
  mkdirSync(other, { recursive: true });
  execFileSync("git", ["init", "-q"], { cwd: repo, env: ENV });
  writeFileSync(join(repo, "f.txt"), "content\n");
  writeFileSync(join(repo, ".gitattributes"), "f.txt filter=x\n");

  const prog = join(dir, "filter.cjs");
  const report = join(work, "report");
  writeFileSync(prog, `#!/usr/bin/env node
const fs = require("fs");
const r = (k, v) => fs.appendFileSync(${JSON.stringify(report)}, k + "=" + v + "\\n");
for (const [k, p] of [["other", ${JSON.stringify(join(other, "planted.pack"))}], ["repo", ${JSON.stringify(join(repo, "planted"))}], ["cache", ${JSON.stringify(join(cacheDir, "planted"))}], ["outside", ${JSON.stringify(join(dir, "planted"))}]]) {
  try { fs.writeFileSync(p, "x"); r(k, "written"); } catch (e) { r(k, e.code); }
}
process.stdin.pipe(process.stdout);
`);
  chmodSync(prog, 0o755);

  // The filter runs on purpose: a later -c outranks the hardening's, and a
  // filter is a driver no -c can switch off by name. Only the sandbox stands
  // in its way. The command is the build's own (prepGitCommand), bound to
  // its work directory, at nice 19.
  const cmd = prepGitCommand(["-c", `filter.x.clean=${prog}`, "-c", "filter.x.required=true", "hash-object", "--", "f.txt"], { writable: [work], lowPriority: true }, sandbox);
  assert.equal(cmd.file, niceBinary() ?? prepGitCommand([], { writable: [work] }, sandbox).file,
    "nice by a fixed system path around the sandbox (the sandbox itself where the host has none)");
  const child = spawn(cmd.file, cmd.args, { cwd: repo, env: prepGitEnv(), stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  let err = "";
  child.stdout.on("data", (c) => { out += c; });
  child.stderr.on("data", (c) => { err += c; });
  const code = await new Promise<number | null>((res) => child.on("close", res));
  assert.equal(code, 0, `git ran in the sandbox: ${err}`);
  assert.match(out.trim(), /^[0-9a-f]{40}$/);

  const got = Object.fromEntries(readFileSync(report, "utf8").trim().split("\n").map((l) => l.split("=")));
  assert.deepEqual(got, { other: "EROFS", repo: "EROFS", cache: "EROFS", outside: "EROFS" }, "only the work directory is writable");
  for (const p of [join(other, "planted.pack"), join(repo, "planted"), join(cacheDir, "planted"), join(dir, "planted")]) {
    assert.equal(existsSync(p), false, `${p} not written`);
  }
});

test("the production preparer, sandboxed, builds and seals a copy without the locked id", { skip }, async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-prep-sandbox-")));
  dirs.push(dir);
  const root = join(dir, "work", "a");
  mkdirSync(join(root, "deploy"), { recursive: true });
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: root, env: ENV, encoding: "utf8" });
  git("init", "-q", "-b", "main");
  writeFileSync(join(root, "README.md"), "# a\n");
  writeFileSync(join(root, "deploy", "id_rsa"), "KEY\n");
  git("add", "."); git("commit", "-qm", "init");
  const blob = git("rev-parse", "HEAD:deploy/id_rsa").trim();
  git("rm", "-q", "deploy/id_rsa"); git("commit", "-qm", "rm");
  git("repack", "-adq");

  const saved = process.env["MANDU_GIT_SANDBOX"];
  delete process.env["MANDU_GIT_SANDBOX"];
  const cacheDir = join(dir, "cache", "object-twins");
  const store = new CacheSealStore({ dbPath: join(dir, "mandu.db"), confidentiality: true });
  try {
    assert.notEqual(gitSandbox(), null, "the production runner runs git sandboxed here");
    const prep = new PreparedCopies({ cacheDir, seals: store, repos: () => [root], lockedSet: () => ({ sha1: [blob], sha256: [] }) });
    await prep.runCycle();
    await prep.idle();
    const s = prep.summary();
    assert.deepEqual(s.failed, [], "no build failed inside the sandbox");
    assert.deepEqual(s.ready.map((x) => x.root), [root]);
    const keys = readdirSync(cacheDir).filter((n) => /^[0-9a-f]{32}$/.test(n));
    assert.equal(keys.length, 1);
    const files = readdirSync(join(cacheDir, keys[0]!));
    const sealed = store.seals("object-twin", files.map((n) => `${keys[0]}/${n}`));
    assert.equal(sealed.seals.length, 3, "the .pack, .idx and .rev each sealed");
    assert.deepEqual(idxLookupFile(join(cacheDir, keys[0]!, files.find((n) => n.endsWith(".idx"))!), [blob]), [], "the copy lacks the locked id");
    assert.deepEqual(readdirSync(cacheDir).filter((n) => n.startsWith(".tmp-")), [], "the work directory is gone");
  } finally {
    store.markShutdown();
    if (saved !== undefined) process.env["MANDU_GIT_SANDBOX"] = saved;
  }
});
