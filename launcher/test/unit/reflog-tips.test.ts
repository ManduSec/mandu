/**
 * Unit (real repositories, no privilege): the history walk's tips read
 * without `git rev-list --reflog` (reflog-tips.ts; git-object-twins.ts
 * `historyStateOfRoots`; confidentiality.md §7.2a "Cost on a relaunch"), and
 * the reads one launch shares between work trees of one object store.
 *
 * The security property: the tips NEVER shrink relative to git's own `rev-list
 * --all --reflog --no-walk` (a tip left out could leave a protected version
 * un-twinned). Pinned on a fixture with linked worktrees, a stash with two
 * entries, a reset-away commit, a detached HEAD left behind, a deleted
 * branch whose reflog remains, a reflog entry naming a pruned object, a tag
 * object in a reflog and per-worktree refs: set-equality with git where git
 * reads the same logs, a superset where git skips one. Every doubt (a
 * symlink, a FIFO, a line that is not a reflog entry, another ref storage)
 * falls back to git's own command, which is pinned too.
 *
 * The same twins under the real wrap (the store's protected versions missing
 * for git inside it, from either work tree): launcher/test/kernel/
 * git-object-twins.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  appendFileSync, chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  defaultGitRunner, historyStateOf, historyStateOfRoots, idxObjectNames, parseRepoConfig, parseRepoFacts, prepareGitObjectTwins,
  RepoReads, repoFactsOf, REPO_FACTS_ARGS, type GitRunner,
} from "../../src/git-object-twins.js";
import { parseReflog, readReflogOids } from "../../src/reflog-tips.js";
import { probeGitSandbox } from "../../src/hardened-git.js";
import { stateAxes } from "../axes.js";
import { memorySeals } from "../lib/memory-seals.js";

stateAxes("secrets"); // the tips decide which committed versions the confidentiality axis hides

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...args: string[]): string => execFileSync("git", args, { cwd, encoding: "utf8", env: ENV });
const rev = (cwd: string, r: string): string => git(cwd, "rev-parse", r).trim();
const Z = "0".repeat(40);
const A = "a".repeat(40);
const B = "b".repeat(40);

/** git's own answer from `root`. */
async function gitTips(root: string): Promise<Set<string>> {
  const r = await defaultGitRunner(["rev-list", "--all", "--reflog", "--no-walk"], { cwd: root });
  assert.equal(r.code, 0, r.stderr);
  return new Set(r.stdout.split("\n").filter((l) => l !== ""));
}

const missingFrom = (want: Set<string>, got: readonly string[]): string[] => [...want].filter((x) => !got.includes(x));

interface Repo { tmp: string; main: string; wt1: string; wt2: string; only: Record<string, string>; done: () => void }

/** A repository whose tips come from every place `--all --reflog` looks. */
function repo(): Repo {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-tips-")));
  const main = join(tmp, "main");
  git(tmp, "init", "-q", "-b", "main", main);
  const commit = (cwd: string, file: string, body: string, msg: string): string => {
    writeFileSync(join(cwd, file), body);
    git(cwd, "add", file);
    git(cwd, "commit", "-qm", msg);
    return rev(cwd, "HEAD");
  };
  const only: Record<string, string> = {};
  commit(main, "README", "one\n", "c1");
  commit(main, "secret.env", "TOKEN=v1\n", "c2");
  // A commit reset away: only the reflogs (HEAD's, main's) name it.
  only["reset"] = commit(main, "secret.env", "TOKEN=reset-away\n", "r1");
  git(main, "reset", "-q", "--hard", "HEAD~1");
  // Two stash entries: stash@{1} only in the stash's reflog.
  writeFileSync(join(main, "README"), "stashed one\n");
  git(main, "stash", "-q");
  only["stash1"] = rev(main, "refs/stash");
  writeFileSync(join(main, "README"), "stashed two\n");
  git(main, "stash", "-q");
  // An annotated tag object as a reflog's new value (git peels it).
  git(main, "tag", "-a", "-m", "t", "v1");
  git(main, "-c", "core.logAllRefUpdates=always", "update-ref", "refs/notes/tagged", rev(main, "v1"));
  // A branch moved back: its old tip only in its reflog.
  git(main, "branch", "feature");
  git(main, "checkout", "-q", "feature");
  only["feature-old"] = commit(main, "f.txt", "f\n", "f1");
  git(main, "reset", "-q", "--hard", "HEAD~1");
  git(main, "checkout", "-q", "main");
  // A reflog entry naming an object that does not exist (pruned): skipped by git.
  appendFileSync(join(main, ".git", "logs", "refs", "heads", "feature"), `${Z} ${"1234567890".repeat(4)} t <t@x> 1700000000 +0000\tpruned\n`);
  // Worktree 1: a detached commit left behind (only its HEAD reflog names
  // it), and a per-worktree ref without a log (only its own --all names it).
  const wt1 = join(tmp, "wt1");
  git(main, "worktree", "add", "-q", "-b", "wtbranch", wt1);
  commit(wt1, "w.txt", "w\n", "w1");
  git(wt1, "checkout", "-q", "--detach");
  only["detached"] = commit(wt1, "secret.env", "TOKEN=detached\n", "d1");
  git(wt1, "checkout", "-q", "wtbranch");
  // (a commit HEAD never pointed at: no reflog names it)
  only["bisect"] = git(wt1, "commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", "bisect-only").trim();
  git(wt1, "update-ref", "refs/bisect/bad", only["bisect"]);
  // Worktree 2: a detached HEAD (every --all names it) and a logged
  // per-worktree ref moved back (only its log names the old value).
  const wt2 = join(tmp, "wt2");
  git(main, "worktree", "add", "-q", "--detach", wt2, "main");
  commit(wt2, "d2.txt", "d2\n", "d2");
  only["wt-ref-old"] = commit(wt2, "d3.txt", "d3\n", "d3");
  git(wt2, "-c", "core.logAllRefUpdates=always", "update-ref", "refs/worktree/mine", "HEAD");
  git(wt2, "-c", "core.logAllRefUpdates=always", "update-ref", "refs/worktree/mine", "HEAD~1");
  git(wt2, "reset", "-q", "--hard", "HEAD~1");
  return { tmp, main, wt1, wt2, only, done: () => rmSync(tmp, { recursive: true, force: true }) };
}

test("parseReflog: both names of every entry, the zero name out; any line that is not an entry is a doubt (null)", () => {
  const line = (o: string, n: string, rest = " t <t@x> 1700000000 +0000\tmsg") => `${o} ${n}${rest}`;
  assert.deepEqual(parseReflog("", 40), []);
  assert.deepEqual(parseReflog(`${line(Z, A)}\n${line(A, B)}\n`, 40), [A, A, B]);
  assert.deepEqual(parseReflog(`${line(A, B)}`, 40), [A, B], "a last line with no newline counts (git skips it: a superset)");
  assert.deepEqual(parseReflog(`${line("c".repeat(64), "d".repeat(64))}\n`, 64), ["c".repeat(64), "d".repeat(64)]);
  for (const bad of [
    "garbage\n", `${line(A, B)}\n\n${line(A, B)}\n`, `${line(A.toUpperCase(), B)}\n`, `${line(A, B)}\n${A}\n`,
    `${line("c".repeat(64), "d".repeat(64))}\n`, `${A}  ${B} x\n`, `${A} ${B}`,
  ]) assert.equal(parseReflog(bad, 40), null, JSON.stringify(bad));
  assert.equal(parseReflog(`${line(A, B)}\n`, 64), null, "a SHA-1 line in a SHA-256 repository");
});

test("parseRepoFacts / parseRepoConfig: one rev-parse, one config read", () => {
  assert.deepEqual(REPO_FACTS_ARGS.slice(0, 3), ["rev-parse", "--show-object-format", "--git-common-dir"]);
  assert.deepEqual(parseRepoFacts("sha256\n.git\n.git/shallow\n/abs/info/grafts\n.git/info/attributes\n", "/w"), {
    hashLen: 32, commonDir: "/w/.git", shallow: "/w/.git/shallow", grafts: "/abs/info/grafts", infoAttributes: "/w/.git/info/attributes",
  });
  assert.equal(parseRepoFacts("sha1\n.git\n", "/w"), null);
  assert.equal(parseRepoFacts("--show-object-format\n.git\na\nb\nc\n", "/w"), null, "an older git echoes the option: the split asks again");
  const cfg = parseRepoConfig("core.autocrlf\ninput\0core.attributesfile\n/a\0extensions.refstorage\nreftable\0core.eol\0", true);
  assert.deepEqual(cfg, { eol: ["-c", "core.autocrlf=input", "-c", "core.eol=true"], attributesFile: "/a", refStorage: "reftable" });
  assert.deepEqual(parseRepoConfig("", true), { eol: [], attributesFile: "", refStorage: "" });
  assert.equal(parseRepoConfig("", false).refStorage, null, "a config git could not read is a doubt");
  assert.equal(parseRepoConfig("extensions.refstorage\0", true).refStorage, "true", "a bare key is not the files backend");
});

test("repoFactsOf: a git that refuses the one call gets the old split (format from its own call, SHA-1 when that fails too)", async () => {
  const calls: string[][] = [];
  const fake: GitRunner = async (args) => {
    calls.push(args);
    if (args.includes("--show-object-format")) return { code: 129, stdout: "", stderr: "unknown option" };
    return { code: 0, stdout: ".git\n.git/shallow\n.git/info/grafts\n.git/info/attributes\n", stderr: "" };
  };
  const f = await repoFactsOf(fake, "/w");
  assert.deepEqual(f, { hashLen: 20, commonDir: "/w/.git", shallow: "/w/.git/shallow", grafts: "/w/.git/info/grafts", infoAttributes: "/w/.git/info/attributes" });
  assert.equal(calls.length, 3);
});

test("the tips equal git's `rev-list --all --reflog --no-walk` from every work tree (worktrees, stash, reset-away and detached commits, a pruned entry, a tag in a reflog)", async () => {
  const r = repo();
  try {
    for (const root of [r.main, r.wt1, r.wt2]) {
      const reads = new RepoReads(defaultGitRunner);
      const mine = (await historyStateOf(defaultGitRunner, root, reads)).tips;
      const theirs = await gitTips(root);
      assert.deepEqual([...reads.reflogFallbacks], [], "no doubt: read from the files");
      assert.deepEqual(missingFrom(theirs, mine), [], `${root}: no tip of git's is missing`);
      assert.deepEqual(mine, [...theirs].sort(), `${root}: the same set`);
      for (const k of ["reset", "stash1", "feature-old", "detached", "wt-ref-old"]) assert.ok(mine.includes(r.only[k]!), `${root}: the ${k} commit`);
      assert.ok(!mine.includes("1234567890".repeat(4)), "a pruned object is not a tip");
      assert.ok(mine.includes(rev(r.main, "v1^{commit}")) && !mine.includes(rev(r.main, "v1")), "a tag object peels to its commit");
    }
    // The work trees of one store together: every work tree's own refs too
    // (refs/bisect/bad lives in wt1 only, unlogged).
    const group = (await historyStateOfRoots(defaultGitRunner, [r.main, r.wt1, r.wt2].sort())).tips;
    const union = new Set([...await gitTips(r.main), ...await gitTips(r.wt1), ...await gitTips(r.wt2)]);
    assert.deepEqual(group, [...union].sort());
    assert.ok(group.includes(r.only["bisect"]!));
    assert.ok(!(await gitTips(r.main)).has(r.only["bisect"]!), "precondition: main's own --all does not see wt1's refs/bisect");
  } finally { r.done(); }
});

test("a deleted branch whose reflog remains: its commits stay tips (a superset of git's where git skips the log)", async () => {
  const r = repo();
  try {
    git(r.main, "branch", "gone");
    git(r.main, "checkout", "-q", "gone");
    writeFileSync(join(r.main, "secret.env"), "TOKEN=gone\n");
    git(r.main, "commit", "-qam", "g1");
    const g1 = rev(r.main, "HEAD");
    git(r.main, "checkout", "-q", "main");
    git(r.main, "reflog", "expire", "--expire=now", "HEAD"); // only the branch's own log names g1
    unlinkSync(join(r.main, ".git", "refs", "heads", "gone")); // the ref gone, its log left
    const reads = new RepoReads(defaultGitRunner);
    const mine = (await historyStateOf(defaultGitRunner, r.main, reads)).tips;
    const theirs = await gitTips(r.main);
    assert.deepEqual(missingFrom(theirs, mine), [], "never fewer than git");
    assert.ok(mine.includes(g1), "the deleted branch's commit is a tip");
    assert.ok([...mine].every((t) => theirs.has(t) || t === g1), "nothing else beyond git's");
  } finally { r.done(); }
});

test("fallback: a symlink, a FIFO or a line that is not an entry in the reflogs, or another ref storage, asks git's own command; the tips equal git's", async () => {
  const doubts: Array<[string, (r: Repo) => void]> = [
    ["a symlinked log", (r) => symlinkSync("/etc/hostname", join(r.main, ".git", "logs", "refs", "heads", "planted"))],
    ["a FIFO", (r) => execFileSync("mkfifo", [join(r.main, ".git", "worktrees", "wt1", "logs", "fifo")])],
    ["a line that is not an entry", (r) => appendFileSync(join(r.main, ".git", "logs", "HEAD"), "not a reflog line\n")],
    ["a symlinked worktree", (r) => symlinkSync(join(r.main, ".git", "worktrees", "wt1"), join(r.main, ".git", "worktrees", "alias"))],
  ];
  for (const [what, plant] of doubts) {
    const r = repo();
    try {
      plant(r);
      const calls: string[][] = [];
      const counting: GitRunner = (args, o) => { calls.push(args); return defaultGitRunner(args, o); };
      const reads = new RepoReads(counting);
      const mine = (await historyStateOf(counting, r.main, reads)).tips;
      assert.equal(reads.reflogFallbacks.size, 1, `${what}: a doubt`);
      assert.ok(calls.some((a) => a.join(" ") === "rev-list --all --reflog --no-walk"), `${what}: git's own command answered`);
      assert.deepEqual(mine, [...await gitTips(r.main)].sort(), `${what}: the same tips`);
    } finally { r.done(); }
  }
  // A ref storage other than files (as the config says): git answers.
  const r = repo();
  try {
    const calls: string[][] = [];
    const fake: GitRunner = async (args, o) => {
      calls.push(args);
      if (args[0] === "config" && args.includes("--get-regexp")) return { code: 0, stdout: "extensions.refstorage\nreftable\0", stderr: "" };
      return defaultGitRunner(args, o);
    };
    const reads = new RepoReads(fake);
    const mine = (await historyStateOf(fake, r.main, reads)).tips;
    assert.match([...reads.reflogFallbacks.values()][0]!, /reftable/);
    assert.ok(calls.some((a) => a.join(" ") === "rev-list --all --reflog --no-walk"));
    assert.deepEqual(mine, [...await gitTips(r.main)].sort());
    mkdirSync(join(r.main, ".git", "reftable"));
    assert.deepEqual(readReflogOids(join(r.main, ".git"), 40), { fallback: "a reftable directory" });
  } finally { r.done(); }
});

test("readReflogOids: every name of every log under logs/ and worktrees/*/logs/, read once; nothing there is no tip", () => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-tips-raw-")));
  try {
    const entry = (o: string, n: string) => `${o} ${n} t <t@x> 1700000000 +0000\tm\n`;
    mkdirSync(join(tmp, "logs", "refs", "heads", "deep", "er"), { recursive: true });
    mkdirSync(join(tmp, "worktrees", "w", "logs", "refs", "worktree"), { recursive: true });
    writeFileSync(join(tmp, "logs", "HEAD"), entry(Z, A));
    writeFileSync(join(tmp, "logs", "refs", "heads", "deep", "er", "x"), entry(A, B));
    writeFileSync(join(tmp, "worktrees", "w", "logs", "HEAD"), entry(B, "c".repeat(40)));
    writeFileSync(join(tmp, "worktrees", "w", "logs", "refs", "worktree", "y"), entry(Z, "d".repeat(40)));
    assert.deepEqual(readReflogOids(tmp, 40), { oids: [A, B, "c".repeat(40), "d".repeat(40)] });
    const empty = realpathSync(mkdtempSync(join(tmpdir(), "mandu-tips-none-")));
    try { assert.deepEqual(readReflogOids(empty, 40), { oids: [] }); } finally { rmSync(empty, { recursive: true, force: true }); }
    // An unreadable log is a doubt, never skipped.
    chmodSync(join(tmp, "logs", "HEAD"), 0o000);
    let readable = true;
    try { readFileSync(join(tmp, "logs", "HEAD")); } catch { readable = false; }
    if (!readable) assert.ok("fallback" in readReflogOids(tmp, 40));
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});

test("one object store, two work trees: the tips, the base and each walk once; ONE plan whose sanitized pack excludes both work trees' protected versions", async () => {
  const r = repo();
  try {
    // a.env is protected in main, b.env in wt1 (a path committed on wtbranch only).
    writeFileSync(join(r.main, "a.env"), "A=1\n");
    git(r.main, "add", "a.env");
    git(r.main, "commit", "-qm", "a1");
    writeFileSync(join(r.wt1, "b.env"), "B=1\n");
    git(r.wt1, "add", "b.env");
    git(r.wt1, "commit", "-qm", "b1");
    // The same path protected in both work trees: one shared walk.
    git(r.main, "repack", "-adq");
    const blob = (body: string) => execFileSync("git", ["hash-object", "--stdin"], { cwd: r.main, input: body, encoding: "utf8", env: ENV }).trim();
    const calls: string[][] = [];
    const counting: GitRunner = (args, o) => { calls.push(args); return defaultGitRunner(args, o); };
    const denyFile = join(r.tmp, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    const opts = { cacheDir: join(r.tmp, "cache"), walkCacheDir: join(r.tmp, "walks"), denyFile, seals: memorySeals(), git: counting };
    const got = await prepareGitObjectTwins(
      [join(r.main, "a.env"), join(r.main, "secret.env"), join(r.wt1, "b.env"), join(r.wt1, "secret.env")], opts,
    );
    assert.equal(got.repos, 1, "one object store");
    assert.equal(got.packsRebuilt, 1, "its pack sanitized once");
    const targets = got.twins.map((t) => t.targetPath);
    assert.equal(new Set(targets).size, targets.length, "one twin per object file (never two exclusions racing for one bind)");
    const idx = got.twins.find((t) => t.targetPath.endsWith(".idx"))!.twinPath;
    const listed = new Set(idxObjectNames(readFileSync(idx)));
    for (const body of ["A=1\n", "B=1\n", "TOKEN=v1\n", "TOKEN=reset-away\n", "TOKEN=detached\n"]) {
      assert.ok(!listed.has(blob(body)), `the version ${JSON.stringify(body)} is excluded`);
    }
    assert.ok(listed.has(blob("one\n")), "every other object stays");
    const n = (s: string) => calls.filter((a) => a.join(" ").startsWith(s)).length;
    assert.equal(n("rev-list --all --reflog"), 0, "git never enumerates the reflogs");
    assert.equal(n("rev-list --all --no-walk"), 2, "each work tree's own refs, once each");
    assert.equal(n("rev-list --no-walk --ignore-missing --stdin"), 1, "the reflogs' commits once for the store");
    assert.equal(n("for-each-ref"), 1, "the replace refs once for the store");
    assert.equal(n("rev-parse"), 2, "one rev-parse per work tree");
    assert.equal(n("config"), 2, "one config read per work tree");
    assert.equal(n("ls-files"), 2, "each work tree's own index");
    assert.equal(n("log"), 2, "one walk per set of paths (main: a.env secret.env; wt1: b.env secret.env)");
    // A relaunch: the walks hit, nothing rebuilt.
    calls.length = 0;
    const again = await prepareGitObjectTwins(
      [join(r.main, "a.env"), join(r.main, "secret.env"), join(r.wt1, "b.env"), join(r.wt1, "secret.env")], opts,
    );
    assert.deepEqual(again.walks, { hit: 2, incremental: 0, full: 0 });
    assert.equal(again.cacheHits, 1);
    assert.equal(n("log"), 0);
    // The same paths in both work trees: one walk for both.
    calls.length = 0;
    const same = await prepareGitObjectTwins([join(r.main, "secret.env"), join(r.wt1, "secret.env")], { ...opts, walkCacheDir: join(r.tmp, "walks2") });
    assert.equal(same.walks.full, 1, "one walk serves both work trees");
    assert.equal(n("log"), 1);
  } finally { r.done(); }
});

test("probeGitSandbox keeps the probe's `git --version` output, so the launch asks the version no second time", { skip: process.platform !== "linux" }, () => {
  const got = probeGitSandbox({ env: {}, rootOwned: () => false, run: () => ({ ok: true, stdout: "git version 9.9.9\n" }) });
  assert.equal(got?.gitVersion, "git version 9.9.9\n");
  const odd = probeGitSandbox({ env: {}, rootOwned: () => false, run: () => ({ ok: true, stdout: "" }) });
  assert.equal(odd?.gitVersion, undefined, "no version printed: the caller asks");
});
