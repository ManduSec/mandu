/**
 * Unit (real repositories, no privilege): the object twins hide what the
 * arbiter's `gitHistoryLocks` names beyond the confined files
 * (confidentiality-plan-14 §8.1, §8.2; confidentiality.md §7.2a):
 *
 *   - a labelled path that is GONE from the work tree (the deploy key
 *     committed and deleted, C17): every version the history holds is
 *     excluded, found with no confined file at all;
 *   - a `public` carve-out under a labelled folder stays readable;
 *   - a BLOB LOCK: exactly the locked version, the file's other versions
 *     untouched, only in a repository of the id's object format (SHA-1 vs
 *     SHA-256);
 *   - the label walk is cached per labels, and nothing is walked when no
 *     label above public reaches a repository.
 *
 * The same twins under the real wrap, with `git show` failing and no key
 * reaching the model, are tests/sandbox/git-history-locks.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  defaultGitRunner, idxObjectNames, lockedNamesFor, parseLsFilesStagePaths, parseRawLogBlobPaths, parseWalkCache,
  historyStateOf, planWalk, prepareGitObjectTwins, repoRootAt, walkCacheFile, type GitObjectTwinResult, type GitRunner,
} from "../../src/git-object-twins.js";
import {
  compileHistoryLabels, historyPathspecs, labelFilterKey, labelWalkKey, resolutionKey, type HistoryLabel,
} from "../../src/history-labels.js";
import { stateAxes } from "../axes.js";
import { memorySeals } from "../lib/memory-seals.js";

stateAxes("secrets"); // the confidentiality axis is what hides the committed bytes

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...args: string[]): string => execFileSync("git", args, { cwd, encoding: "utf8", env: ENV });
/** A key-shaped canary assembled at run time (no key literal in the file). */
const KEY = ["DEPLOY", "KEY", "CANARY", "7731", "q".repeat(24)].join("_");

interface Fixture { tmp: string; ws: string; denyFile: string; cacheDir: string; done: () => void }
function fixture(init: string[] = []): Fixture {
  // realpath: macOS reaches the temp dir through a link (/tmp, /var →
  // /private/…). A label spelled through the link gets its real spelling
  // added (withRealSpellings), and each spelling finds the work tree, so the
  // repository would be walked twice; the fixture spells it once.
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-histlock-")));
  const ws = join(tmp, "ws");
  git(tmp, "init", "-q", ...init, ws);
  const denyFile = join(tmp, "denied");
  writeFileSync(denyFile, "");
  chmodSync(denyFile, 0o000);
  return { tmp, ws, denyFile, cacheDir: join(tmp, "cache"), done: () => rmSync(tmp, { recursive: true, force: true }) };
}
const put = (ws: string, rel: string, body: string): void => {
  mkdirSync(join(ws, rel, ".."), { recursive: true });
  writeFileSync(join(ws, rel), body);
};
const blobOf = (ws: string, body: string): string =>
  execFileSync("git", ["hash-object", "--stdin"], { cwd: ws, input: body, encoding: "utf8", env: ENV }).trim();
const label = (path: string, level: string, recursive = true): HistoryLabel => ({ path, level, recursive });
/** The names a result's sanitized index lists, or null when no pack was twinned. */
const listed = (got: GitObjectTwinResult, hashLen = 20): Set<string> | null => {
  const idx = got.twins.find((x) => x.kind === "object" && x.targetPath.endsWith(".idx"));
  return idx ? new Set(idxObjectNames(readFileSync(idx.twinPath), hashLen)) : null;
};
const deniedLoose = (got: GitObjectTwinResult): string[] =>
  got.twins.filter((x) => x.kind === "deny" && /\/objects\/[0-9a-f]{2}\/[0-9a-f]+$/.test(x.targetPath))
    .map((x) => x.targetPath.split("/").slice(-2).join(""));

test("parsers: (blob, path) pairs from the raw log and the index; the locked ids of a repository's object format", () => {
  const a = "a".repeat(40), b = "b".repeat(40), z = "0".repeat(40);
  const raw = `\n:000000 100644 ${z} ${a} A\0deploy/id_rsa\0\n\n:100644 000000 ${a} ${z} D\0deploy/id_rsa\0:160000 160000 ${a} ${b} M\0sub\0:100644 100644 ${a} ${b} M\0dir with space/f\0`;
  assert.deepEqual(parseRawLogBlobPaths(raw), [[a, "deploy/id_rsa"], [a, "deploy/id_rsa"], [a, "dir with space/f"], [b, "dir with space/f"]]);
  assert.deepEqual(parseLsFilesStagePaths(`100644 ${a} 0\tx/y\x00160000 ${b} 0\tsub\x00100644 ${b} 2\tz\x00`), [[a, "x/y"], [b, "z"]]);
  const s256 = "c".repeat(64);
  const locks = [`sha1:${a}`, `sha256:${s256}`, `sha1:${"A".repeat(40)}`, `sha256:${a}`, "md5:x"];
  assert.deepEqual(lockedNamesFor(locks, 20), [a], "SHA-1 repositories: the sha1 ids only, well formed");
  assert.deepEqual(lockedNamesFor(locks, 32), [s256], "SHA-256 repositories: the sha256 ids only");
});

test("repoRootAt: a path gone from the work tree still finds its repository through its nearest folder", () => {
  const f = fixture();
  try {
    assert.equal(repoRootAt(join(f.ws, "deploy", "id_rsa"), (p) => { try { readFileSync(p); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EISDIR"; } }), f.ws);
    assert.equal(repoRootAt(f.ws, (p) => p === join(f.ws, ".git")), f.ws, "the repository's own root");
    assert.equal(repoRootAt(join(f.ws, ".git", "x"), () => true), null);
  } finally { f.done(); }
});

test("a labelled deploy key committed and then deleted: every version is hidden, loose and packed, with no confined file; the rest reads", async () => {
  const f = fixture();
  try {
    put(f.ws, "README.md", "hello\n");
    git(f.ws, "add", ".");
    git(f.ws, "commit", "-qm", "init");
    put(f.ws, "deploy/id_rsa", `${KEY} v1\n`);
    git(f.ws, "add", ".");
    git(f.ws, "commit", "-qm", "add key");
    put(f.ws, "deploy/id_rsa", `${KEY} v2\n`);
    git(f.ws, "commit", "-qam", "rotate in place");
    git(f.ws, "rm", "-rq", "deploy");
    git(f.ws, "commit", "-qm", "remove it");
    const v1 = blobOf(f.ws, `${KEY} v1\n`), v2 = blobOf(f.ws, `${KEY} v2\n`), readme = blobOf(f.ws, "hello\n");
    const labels = [label(join(f.ws, "deploy", "id_rsa"), "no-model")];

    const before = await prepareGitObjectTwins([], { cacheDir: f.cacheDir, denyFile: f.denyFile });
    assert.equal(before.twins.length, 0, "without the label nothing leads the launch to the history (the C17 boundary)");

    const loose = await prepareGitObjectTwins([], { cacheDir: f.cacheDir, denyFile: f.denyFile, labels });
    assert.equal(loose.repos, 1);
    assert.equal(loose.blobs, 2);
    assert.deepEqual(deniedLoose(loose).sort(), [v1, v2].sort(), "both loose versions are made unreadable");
    // Plan 14 §11.1 R4: the resolved versions go to the guard's backstop,
    // which refuses them in every repository this launch did not prepare.
    assert.deepEqual(loose.lockedIds, [`sha1:${v1}`, `sha1:${v2}`].sort());

    git(f.ws, "repack", "-adq");
    const packed = await prepareGitObjectTwins([], { cacheDir: f.cacheDir, denyFile: f.denyFile, labels });
    const names = listed(packed)!;
    assert.ok(names.size > 0);
    assert.ok(!names.has(v1) && !names.has(v2), "the sanitized pack lists no version of the key");
    assert.ok(names.has(readme), "every other object reads as before");

    const dirLabel = await prepareGitObjectTwins([], { cacheDir: f.cacheDir, denyFile: f.denyFile, labels: [label(join(f.ws, "deploy"), "any-model")] });
    const dn = listed(dirLabel)!;
    assert.ok(!dn.has(v1) && !dn.has(v2), "a label on the gone FOLDER hides what it held (any level above public)");
    const pub = await prepareGitObjectTwins([], { cacheDir: f.cacheDir, denyFile: f.denyFile, labels: [label(join(f.ws, "deploy", "id_rsa"), "public")] });
    assert.equal(pub.twins.length, 0, "a public label hides nothing");
  } finally { f.done(); }
});

test("a public carve-out under a labelled repository stays readable; a pattern label decides every history path it matches", async () => {
  const f = fixture();
  try {
    put(f.ws, "README.md", "readme v1\n");
    put(f.ws, "keys/a.pem", `${KEY} pem\n`);
    put(f.ws, "src/app.py", "print(1)\n");
    git(f.ws, "add", ".");
    git(f.ws, "commit", "-qm", "one");
    git(f.ws, "rm", "-q", "keys/a.pem");
    git(f.ws, "commit", "-qm", "two");
    git(f.ws, "repack", "-adq");
    const readme = blobOf(f.ws, "readme v1\n"), pem = blobOf(f.ws, `${KEY} pem\n`), app = blobOf(f.ws, "print(1)\n");

    const carve = await prepareGitObjectTwins([], {
      cacheDir: f.cacheDir, denyFile: f.denyFile, repoHints: [f.ws],
      labels: [label(f.ws, "no-model"), label(join(f.ws, "README.md"), "public")],
    });
    const n = listed(carve)!;
    assert.ok(!n.has(pem) && !n.has(app), "the folder label hides every other version");
    assert.ok(n.has(readme), "the public carve-out keeps its history");

    const glob = await prepareGitObjectTwins([], {
      cacheDir: f.cacheDir, denyFile: f.denyFile, repoHints: [f.ws],
      labels: [{ path: "**/*.pem", level: "no-model", recursive: true, glob: true }],
    });
    const g = listed(glob)!;
    assert.ok(!g.has(pem), "the unrooted pattern matches the gone keys/a.pem");
    assert.ok(g.has(readme) && g.has(app));
  } finally { f.done(); }
});

test("a blob lock hides exactly the locked version (the key once inline in a file that is public now), in the workspace's repository", async () => {
  const f = fixture();
  try {
    put(f.ws, "config.py", `API_KEY = "${KEY}"\n`);
    git(f.ws, "add", ".");
    git(f.ws, "commit", "-qm", "inline key");
    put(f.ws, "config.py", "API_KEY = os.environ[\"API_KEY\"]\n");
    git(f.ws, "commit", "-qam", "read it from the environment");
    git(f.ws, "repack", "-adq");
    const old = blobOf(f.ws, `API_KEY = "${KEY}"\n`), now = blobOf(f.ws, "API_KEY = os.environ[\"API_KEY\"]\n");
    const opts = { cacheDir: f.cacheDir, denyFile: f.denyFile, repoHints: [f.ws] };

    const got = await prepareGitObjectTwins([], { ...opts, blobLocks: [`sha1:${old}`] });
    assert.equal(got.repos, 1);
    assert.equal(got.blobs, 1, "the count is what the repository holds");
    const n = listed(got)!;
    assert.ok(!n.has(old), "the locked version is excluded");
    assert.ok(n.has(now), "the current file's version reads normally");

    const wrongFormat = await prepareGitObjectTwins([], { ...opts, blobLocks: [`sha256:${old}${"0".repeat(24)}`] });
    assert.equal(wrongFormat.twins.length, 0, "a sha256 id never applies to a SHA-1 repository");
    const absent = await prepareGitObjectTwins([], { ...opts, blobLocks: [`sha1:${"e".repeat(40)}`] });
    assert.equal(absent.twins.length, 0, "a lock on an object this repository does not hold changes nothing");
    assert.deepEqual(absent.lockedIds, [`sha1:${"e".repeat(40)}`], "R4: yet the id still goes to the guard's backstop (another repository may hold it)");
    assert.deepEqual(wrongFormat.lockedIds, [], "no id of this repository's format");
    const noHint = await prepareGitObjectTwins([], { cacheDir: f.cacheDir, denyFile: f.denyFile, blobLocks: [`sha1:${old}`] });
    assert.equal(noHint.repos, 0, "a blob lock reaches the repositories the launch is given (the workspace), not every one");
  } finally { f.done(); }
});

test("SHA-256 repositories: a sha256 lock applies, a sha1 one does not", async (t) => {
  let f: Fixture;
  try { f = fixture(["--object-format=sha256"]); } catch {
    t.skip("this git cannot make a SHA-256 repository");
    return;
  }
  try {
    put(f.ws, "config.py", `TOKEN = "${KEY}"\n`);
    git(f.ws, "add", ".");
    git(f.ws, "commit", "-qm", "one");
    put(f.ws, "config.py", "TOKEN = None\n");
    git(f.ws, "commit", "-qam", "two");
    git(f.ws, "repack", "-adq");
    const old = blobOf(f.ws, `TOKEN = "${KEY}"\n`), now = blobOf(f.ws, "TOKEN = None\n");
    assert.equal(old.length, 64);
    const opts = { cacheDir: f.cacheDir, denyFile: f.denyFile, repoHints: [f.ws] };
    assert.equal((await prepareGitObjectTwins([], { ...opts, blobLocks: [`sha1:${old.slice(0, 40)}`] })).twins.length, 0);
    const got = await prepareGitObjectTwins([], { ...opts, blobLocks: [`sha256:${old}`] });
    const n = listed(got, 32)!;
    assert.ok(!n.has(old) && n.has(now));
  } finally { f.done(); }
});

test("the label walk is cached per labels: a relaunch does not walk, a new carve-out walks again; no label reaching the repository costs no git call", async () => {
  const f = fixture();
  try {
    put(f.ws, "deploy/id_rsa", `${KEY}\n`);
    git(f.ws, "add", ".");
    git(f.ws, "commit", "-qm", "one");
    git(f.ws, "rm", "-rq", "deploy");
    git(f.ws, "commit", "-qm", "two");
    const walkCacheDir = join(f.tmp, "walks");
    const labels = [label(join(f.ws, "deploy"), "no-model")];
    // The walk cache is trusted only through the seals (plan 14 §11.2).
    const opts = { cacheDir: f.cacheDir, denyFile: f.denyFile, walkCacheDir, seals: memorySeals() };
    const first = await prepareGitObjectTwins([], { ...opts, labels });
    assert.deepEqual(first.walks, { hit: 0, incremental: 0, full: 1 });
    const second = await prepareGitObjectTwins([], { ...opts, labels });
    assert.deepEqual(second.walks, { hit: 1, incremental: 0, full: 0 });
    assert.deepEqual(second.twins, first.twins);
    const third = await prepareGitObjectTwins([], { ...opts, labels: [...labels, label(join(f.ws, "deploy", "README"), "public")] });
    assert.deepEqual(third.walks, { hit: 0, incremental: 0, full: 1 }, "other labels, another cache entry");

    // The cache entry names its filter: another filter is never a hit, and a
    // label walk never shares a file with a walk by path.
    const files = readdirSync(walkCacheDir).filter((n) => n.endsWith(".json"));
    const entries = files.map((n) => parseWalkCache(readFileSync(join(walkCacheDir, n), "utf8"))!);
    const e = entries.find((x) => x.filter !== undefined)!;
    assert.equal(join(walkCacheDir, files[entries.indexOf(e)]!), walkCacheFile(walkCacheDir, e.root, e.rels, e.filter));
    assert.notEqual(walkCacheFile(walkCacheDir, e.root, e.rels, e.filter), walkCacheFile(walkCacheDir, e.root, e.rels));
    assert.deepEqual(planWalk(e, e.root, e.rels, e.base, e.tips, "another"), { kind: "full" });
    assert.deepEqual(planWalk(e, e.root, e.rels, e.base, e.tips), { kind: "full" }, "a walk by path never reads a label walk's entry");
    assert.deepEqual(planWalk(e, e.root, e.rels, e.base, e.tips, e.filter), { kind: "hit" });

    let calls = 0;
    const counting: GitRunner = (args, o) => { calls++; return defaultGitRunner(args, o); };
    const none = await prepareGitObjectTwins([], { ...opts, git: counting, repoHints: [f.ws], labels: [label("/elsewhere/x", "no-model"), label(join(f.ws, "README"), "public")] });
    assert.equal(none.twins.length, 0);
    assert.equal(calls, 0, "no label above public reaches the repository: no git call");
  } finally { f.done(); }
});

test("plan 14 §11.1 R2: the arbiter's resolution stands in for the label walk ONLY on an equal key; any other key walks as before", async () => {
  const f = fixture();
  try {
    put(f.ws, "deploy/id_rsa", `${KEY}\n`);
    put(f.ws, "app.txt", "app\n");
    git(f.ws, "add", ".");
    git(f.ws, "commit", "-qm", "one");
    git(f.ws, "rm", "-rq", "deploy");
    git(f.ws, "commit", "-qm", "two");
    const root = realpathSync(f.ws);
    const labels = [label(join(root, "deploy"), "no-model")];
    const keyBlob = blobOf(f.ws, `${KEY}\n`);
    // The key the arbiter computes, from the shared module's own functions.
    const specs = historyPathspecs(root, compileHistoryLabels(labels));
    const state = await historyStateOf(defaultGitRunner, root);
    const key = resolutionKey(root, labelFilterKey(labelWalkKey(labels, null), specs), state.base, state.tips);
    const logs: string[][] = [];
    const counting: GitRunner = (args, o) => { if (args[0] === "log") logs.push(args); return defaultGitRunner(args, o); };
    const opts = { cacheDir: f.cacheDir, denyFile: f.denyFile, git: counting, labels };
    const walked = await prepareGitObjectTwins([], { ...opts, resolved: new Map() });
    assert.equal(walked.fromArbiter, 0);
    assert.equal(logs.length, 1, "nothing resolved: the launcher walks");
    logs.length = 0;
    const stood = await prepareGitObjectTwins([], { ...opts, resolved: new Map([[root, { key, blobs: [keyBlob] }]]) });
    assert.equal(stood.fromArbiter, 1);
    assert.equal(logs.length, 0, "an equal key: no walk");
    assert.deepEqual(stood.twins.map((t) => [t.targetPath, t.kind]), walked.twins.map((t) => [t.targetPath, t.kind]), "the same twins");
    const hidden = (got: GitObjectTwinResult): boolean => deniedLoose(got).includes(keyBlob) || (listed(got) !== null && !listed(got)!.has(keyBlob));
    assert.ok(hidden(stood));
    for (const stale of [key.replace(/.$/, (c) => (c === "0" ? "1" : "0")), "", "x".repeat(64)]) {
      logs.length = 0;
      const got = await prepareGitObjectTwins([], { ...opts, resolved: new Map([[root, { key: stale, blobs: [] }]]) });
      assert.equal(got.fromArbiter, 0);
      assert.equal(logs.length, 1, "a stale or foreign key walks");
      assert.ok(hidden(got), "and still hides the version");
    }
    // A new commit moves the tips: the old key no longer stands in.
    put(f.ws, "deploy/id_rsa", `${KEY}-2\n`);
    git(f.ws, "add", ".");
    git(f.ws, "commit", "-qm", "three");
    logs.length = 0;
    const moved = await prepareGitObjectTwins([], { ...opts, resolved: new Map([[root, { key, blobs: [keyBlob] }]]) });
    assert.equal(moved.fromArbiter, 0);
    assert.equal(logs.length, 1);
  } finally { f.done(); }
});
