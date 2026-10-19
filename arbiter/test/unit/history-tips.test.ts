/**
 * Unit (real repositories, no privilege): the arbiter's history readers
 * start from every ref and every reflog entry WITHOUT `git --reflog`
 * (policy/history-tips.ts over src/reflog-tips.ts, the launcher's reader;
 * confidentiality.md §7.2a "Cost on a relaunch", the arbiter's readers).
 *
 * The security property: the commits the background lock resolution and
 * the git-history secret scan see NEVER shrink relative to `--all
 * --reflog`. Pinned on a fixture whose secrets live in commits only a
 * reflog names (a commit reset away: HEAD's and main's logs; a detached
 * commit left behind in a linked worktree: that worktree's own HEAD log; an
 * older stash entry: the stash's log):
 *   - the tips equal git's `rev-list --all --reflog --no-walk`, the walk's
 *     objects equal `rev-list --all --reflog --objects`;
 *   - the scan finds all three secrets and git never enumerates the reflogs;
 *   - the resolver locks the reflog-only versions of a labelled path;
 *   - every doubt the launcher falls back on (a symlink, a FIFO, a line that
 *     is not an entry, a symlinked worktree, another ref storage, a failed
 *     rev-parse) runs git's own `--reflog` form, with the same findings.
 * The cross-package proof (the launcher's key, a real ArbiterServer):
 * tests/stack/reflog-tips-parity.test.ts.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { appendFileSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  hexLines, historyTipsOf, reflogNamesOf, reflogRevArgs, refStorageOf, REFLOG_CONFIG_ARGS, type ReflogNames, type TipsGit,
} from "../../policy/history-tips.js";
import {
  defaultHistoryGitLines, defaultHistoryGitRunner, scanSecretHistory, type HistoryGitLines, type HistoryGitRunner,
} from "../../policy/secret-history-scan.js";
import { hardenedResolverGit, LockResolver, type ResolverGit } from "../../policy/lock-resolution.js";
import type { HistoryLabel } from "../../policy/history-labels.js";
import { stateAxes } from "../axes.js";
import { randomSecretBody } from "../helpers/random-secret.js";

stateAxes("secrets"); // the scan and the locks serve the confidentiality axis

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...a: string[]): string => execFileSync("git", a, { cwd, encoding: "utf8", env: ENV });
const blobOf = (cwd: string, body: string): string =>
  execFileSync("git", ["hash-object", "--stdin"], { cwd, input: body, encoding: "utf8", env: ENV }).trim();
// Random, assembled at run time: no credential-shaped literal in this file.
const token = (): string => "gh" + "p_" + `${randomSecretBody(34)}a7`;
const Z = "0".repeat(40);
const A = "a".repeat(40);

interface Fixture { root: string; wt: string; secrets: Record<string, string>; blobs: Record<string, string> }

/** A repository whose three secrets only a reflog names. */
function fixture(): Fixture {
  const d = realpathSync(mkdtempSync(join(tmpdir(), "mdu-histtips-")));
  dirs.push(d);
  const root = join(d, "repo");
  git(d, "init", "-q", "-b", "main", root);
  const put = (cwd: string, rel: string, body: string): void => {
    mkdirSync(join(cwd, rel, ".."), { recursive: true });
    writeFileSync(join(cwd, rel), body);
  };
  const secrets: Record<string, string> = { reset: `TOKEN=${token()}\n`, detached: `TOKEN=${token()}\n`, stash: `TOKEN=${token()}\n` };
  put(root, "README", "one\n");
  put(root, "deploy/key", "placeholder\n");
  git(root, "add", "."); git(root, "commit", "-qm", "c1");
  // Reset away: only HEAD's and main's reflogs name it.
  put(root, "deploy/key", secrets["reset"]!);
  git(root, "commit", "-qam", "r1");
  git(root, "reset", "-q", "--hard", "HEAD~1");
  // An older stash entry: only the stash's reflog names it.
  put(root, "deploy/key", secrets["stash"]!);
  git(root, "stash", "-q");
  put(root, "README", "two\n");
  git(root, "stash", "-q");
  // A linked worktree's detached commit left behind: only that worktree's
  // own HEAD reflog (<common>/worktrees/<id>/logs/HEAD) names it.
  const wt = join(d, "wt");
  git(root, "worktree", "add", "-q", "-b", "side", wt);
  git(wt, "checkout", "-q", "--detach");
  put(wt, "deploy/key", secrets["detached"]!);
  git(wt, "commit", "-qam", "d1");
  git(wt, "checkout", "-q", "side");
  const blobs: Record<string, string> = {};
  for (const [k, v] of Object.entries(secrets)) blobs[k] = blobOf(root, v);
  return { root, wt, secrets, blobs };
}

const tipsGitAt = (cwd: string, calls?: string[][]): TipsGit => (args, input) => {
  calls?.push(args);
  return defaultHistoryGitRunner(args, { cwd, timeoutMs: 60_000, ...(input !== undefined ? { input } : {}) });
};
const set = (out: string): string[] => [...new Set(out.split("\n").map((l) => l.split(" ")[0]!.trim()).filter((l) => l !== ""))].sort();
const usedReflog = (calls: string[][]): boolean => calls.some((a) => a.includes("--reflog"));

/** The doubts the reader must fall back on (the launcher's set, plus a
 *  symlinked worktree directory). */
const DOUBTS: Array<[string, (f: Fixture) => void]> = [
  ["a symlinked log", (f) => symlinkSync("/etc/hostname", join(f.root, ".git", "logs", "refs", "heads", "planted"))],
  ["a FIFO", (f) => execFileSync("mkfifo", [join(f.root, ".git", "worktrees", "wt", "logs", "fifo")])],
  ["a line that is not an entry", (f) => appendFileSync(join(f.root, ".git", "logs", "HEAD"), "not a reflog line\n")],
  ["a symlinked worktree", (f) => symlinkSync(join(f.root, ".git", "worktrees", "wt"), join(f.root, ".git", "worktrees", "alias"))],
];

// ── pure ─────────────────────────────────────────────────────────────────────

test("pure: refStorageOf, hexLines and reflogRevArgs", () => {
  assert.equal(refStorageOf(""), "");
  assert.equal(refStorageOf("extensions.refstorage\nreftable\0"), "reftable");
  assert.equal(refStorageOf("extensions.refStorage\nfiles\0extensions.refstorage\nreftable\0"), "reftable", "the last value wins");
  assert.equal(refStorageOf("extensions.refstorage\0"), "true", "a bare key is not the files backend");
  assert.deepEqual(hexLines(`${A}\n  ${"b".repeat(64)} \nnot\n${A.slice(1)}\n`), [A, "b".repeat(64)]);
  assert.deepEqual(reflogRevArgs({ oids: null, fallback: "x" }), { args: ["--all", "--reflog"] }, "a doubt: git's own form");
  assert.deepEqual(reflogRevArgs({ oids: [], fallback: null }), { args: ["--all"] });
  assert.deepEqual(reflogRevArgs({ oids: [A, Z.replace(/^0/, "1")], fallback: null }),
    { args: ["--all", "--ignore-missing", "--stdin"], input: `${A}\n1${"0".repeat(39)}\n` });
  assert.deepEqual(REFLOG_CONFIG_ARGS, ["config", "-z", "--get-regexp", "^extensions\\.refstorage$"]);
});

// ── the reader against git's own answer ─────────────────────────────────────

test("tips and walk objects equal git's `--all --reflog` from either work tree; git never enumerates the reflogs", async () => {
  const f = fixture();
  // A reflog entry naming an object that does not exist (pruned): git skips it.
  appendFileSync(join(f.root, ".git", "logs", "refs", "heads", "side"), `${Z} ${"1234567890".repeat(4)} t <t@x> 1700000000 +0000\tpruned\n`);
  for (const cwd of [f.root, f.wt]) {
    const calls: string[][] = [];
    const tg = tipsGitAt(cwd, calls);
    const names = await reflogNamesOf(tg, cwd);
    assert.equal(names.fallback, null, "read from the files");
    const got = await historyTipsOf(tg, names);
    assert.ok("tips" in got);
    assert.deepEqual(got.tips, set(git(cwd, "rev-list", "--all", "--reflog", "--no-walk")), `${cwd}: the same tips`);
    const from = reflogRevArgs(names);
    const objs = await tg(["rev-list", ...from.args, "--objects"], from.input);
    assert.equal(objs.code, 0, objs.stderr);
    assert.deepEqual(set(objs.stdout), set(git(cwd, "rev-list", "--all", "--reflog", "--objects")), `${cwd}: the same objects`);
    for (const b of Object.values(f.blobs)) assert.ok(set(objs.stdout).includes(b), "every reflog-only secret is walked");
    assert.equal(usedReflog(calls), false, "no --reflog");
  }
});

test("a deleted branch whose reflog remains: its commits stay tips (a superset of git's, never fewer)", async () => {
  const f = fixture();
  git(f.root, "branch", "gone", "HEAD");
  const only = git(f.root, "commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", "gone-only").trim();
  git(f.root, "update-ref", "-m", "move", "refs/heads/gone", only);
  // git deletes the branch's log with the branch; one left behind (a crash,
  // a copy) is what git then skips and the reader still reads.
  const log = join(f.root, ".git", "logs", "refs", "heads", "gone");
  const kept = execFileSync("cat", [log], { encoding: "utf8" });
  git(f.root, "update-ref", "-d", "refs/heads/gone");
  writeFileSync(log, kept);
  const tg = tipsGitAt(f.root);
  const got = await historyTipsOf(tg, await reflogNamesOf(tg, f.root));
  assert.ok("tips" in got);
  const gits = set(git(f.root, "rev-list", "--all", "--reflog", "--no-walk"));
  assert.deepEqual(gits.filter((t) => !got.tips.includes(t)), [], "never fewer than git's");
  assert.ok(got.tips.includes(only));
});

test("fallback: each doubt (and another ref storage, a failed rev-parse) runs git's own --reflog form; the tips equal git's", async () => {
  for (const [what, plant] of DOUBTS) {
    const f = fixture();
    plant(f);
    const calls: string[][] = [];
    const tg = tipsGitAt(f.root, calls);
    const names = await reflogNamesOf(tg, f.root);
    assert.notEqual(names.fallback, null, `${what}: a doubt`);
    assert.deepEqual(reflogRevArgs(names), { args: ["--all", "--reflog"] }, `${what}: the walk's own form`);
    const got = await historyTipsOf(tg, names);
    assert.ok("tips" in got);
    assert.ok(calls.some((a) => a.join(" ") === "rev-list --all --reflog --no-walk"), `${what}: git answered`);
    assert.deepEqual(got.tips, set(git(f.root, "rev-list", "--all", "--reflog", "--no-walk")), `${what}: the same tips`);
  }
  const f = fixture();
  const real = tipsGitAt(f.root);
  const reftable: TipsGit = async (args, input) =>
    args[0] === "config" ? { code: 0, stdout: "extensions.refstorage\nreftable\0", stderr: "" } : real(args, input);
  assert.match((await reflogNamesOf(reftable, f.root)).fallback ?? "", /reftable/);
  const unreadable: TipsGit = async (args, input) => args[0] === "config" ? { code: 3, stdout: "", stderr: "bad config" } : real(args, input);
  assert.match((await reflogNamesOf(unreadable, f.root)).fallback ?? "", /config/);
  const noRevParse: TipsGit = async (args, input) => args[0] === "rev-parse" ? { code: 128, stdout: "", stderr: "x" } : real(args, input);
  assert.match((await reflogNamesOf(noRevParse, f.root)).fallback ?? "", /rev-parse/);
  const ok: ReflogNames = await reflogNamesOf(real, f.root);
  assert.equal(ok.fallback, null, "the files backend set explicitly is read from the files too");
});

// ── the secret scan ─────────────────────────────────────────────────────────

/** A scan with every git call recorded. */
async function scan(root: string): Promise<{ found: Set<string>; calls: string[][] }> {
  const calls: string[][] = [];
  const g: HistoryGitRunner = (args, o) => { calls.push(args); return defaultHistoryGitRunner(args, o); };
  const lines: HistoryGitLines = (args, o) => { calls.push(args); return defaultHistoryGitLines(args, o); };
  const s = await scanSecretHistory([root], { git: g, gitLines: lines });
  assert.equal(s.capped.unlisted, false, s.capped.lines.join("; "));
  return { found: new Set(s.findings.map((x) => x.blob)), calls };
}

test("scan: a secret only a reflog names (reset away, a worktree's detached commit, an older stash) is found; git never enumerates the reflogs", async () => {
  const f = fixture();
  const { found, calls } = await scan(f.root);
  for (const [k, b] of Object.entries(f.blobs)) assert.ok(found.has(b), `the ${k} secret is found`);
  assert.equal(usedReflog(calls), false, "no --reflog");
  assert.ok(calls.some((a) => a[0] === "rev-list" && a.includes("--objects") && a.includes("--stdin")), "the reflogs' names on stdin");
});

test("scan fallback: under every doubt git's own --reflog runs and the same secrets are found", async () => {
  for (const [what, plant] of DOUBTS) {
    const f = fixture();
    plant(f);
    const { found, calls } = await scan(f.root);
    for (const [k, b] of Object.entries(f.blobs)) assert.ok(found.has(b), `${what}: the ${k} secret is found`);
    assert.ok(calls.some((a) => a.join(" ") === "rev-list --all --reflog --objects"), `${what}: git's own listing`);
  }
});

// ── the lock resolution ─────────────────────────────────────────────────────

test("lock resolution: the reflog-only versions of a labelled path are locked, read from the files; a doubt falls back with the same set", async () => {
  for (const plant of [null, DOUBTS[2]!, DOUBTS[1]!]) {
    const f = fixture();
    if (plant) plant[1](f);
    const calls: string[][] = [];
    const real = hardenedResolverGit(new Set());
    const g: ResolverGit = (args, o) => { calls.push(args); return real(args, o); };
    const labels: HistoryLabel[] = [{ path: join(f.root, "deploy", "key"), level: "no-model", recursive: true }];
    const home = realpathSync(mkdtempSync(join(tmpdir(), "mdu-histtips-home-")));
    dirs.push(home);
    const res = new LockResolver({ labels: () => labels, blobLocks: () => [], home, git: g });
    try {
      res.note([f.root], "launch");
      await res.runCycle(); await res.idle();
      const snap = res.snapshot([f.root]);
      const what = plant?.[0] ?? "no doubt";
      assert.equal(snap.complete, true, `${what}: resolved`);
      for (const [k, b] of Object.entries(f.blobs)) assert.ok(snap.lockedSet.sha1.includes(b), `${what}: the ${k} version is locked`);
      const entry = snap.repos.find((x) => x.root === f.root)!;
      if (plant === null) {
        assert.equal(usedReflog(calls), false, "no --reflog");
        assert.equal(res.reflogFallbacks.size, 0);
        assert.ok(calls.some((a) => a[0] === "log" && a.includes("--stdin")), "the walk starts from the tips");
      } else {
        assert.equal(res.reflogFallbacks.size, 1, `${what}: recorded`);
        assert.ok(calls.some((a) => a.join(" ") === "rev-list --all --reflog --no-walk"), `${what}: git's own tips`);
      }
      assert.ok(entry.blobs.length >= 3);
    } finally { await res.stop(); }
  }
});
