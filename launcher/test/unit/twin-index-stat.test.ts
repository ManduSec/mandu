/**
 * twin-index-stat: a tracked protected file looks clean to git in the
 * agent's world (confidentiality.md §7.2a "A twinned file git tracks looks
 * clean").
 *
 * The agent's world is simulated without a mount: after the commit, the
 * work tree's `.env` is overwritten with the twin's bytes (what git in the
 * agent's world reads at that path) and serves as the twin itself; the real
 * bytes are handed to the code by `readReal`. Real git throughout. Each
 * case pins what the mechanism must and must not do:
 *
 *   C1 clean: `git status`, `diff-files`, `update-index --refresh` see
 *      nothing; the blob id, mode and every other entry are unchanged; the
 *      checksum is valid (git reads the index); in index versions 2, 3, 4,
 *      SHA-256, and with `index.skipHash`.
 *   C2 an edit of the twin shows modified (and `git commit -a` would take
 *      it: the placeholder watch's case), a `touch` too.
 *   C3 the demo-c4 flow: `git filter-branch --index-filter 'git rm --cached
 *      …' -- --all` without untracking first runs (it refused "You have
 *      unstaged changes" before), and `git stash`, `git rebase` too; red
 *      without the patch.
 *   C4 only where true: a real file that differs from its blob, a conflict
 *      (stages), an assume-unchanged or skip-worktree entry, an executable,
 *      a path the index does not hold: nothing written.
 *   C5 git's lock wins: an `index.lock` present leaves the index as is; a
 *      symlinked index and a split index are refused.
 *   C6 the restore puts the launch stat back only when the entry still
 *      holds the session's stat and blob.
 *   C7 parse: a truncated or corrupted index throws, never a wrong patch.
 *
 * The crash record (in a scratch Mandu home):
 *   R1 written 0600 BEFORE the patched index lands; the end restores and
 *      removes it.
 *   R2 a dead session's record is restored by the next launch and removed;
 *      a live one is left.
 *   R3 a record that cannot be written (the walk cache a link) leaves the
 *      index alone and the lock released.
 *   R4 two sessions on one repository, both end orders: the launch index
 *      at the end.
 *   R5 a lock held through the end keeps the record; the next launch
 *      finishes it.
 *   R6 the record's exact shape; a broken one dropped, another version's
 *      left.
 *   R7 a removed repository: the record goes, no retry.
 *   R8 a final failure (a symlinked or split index since): said once, the
 *      record dropped.
 *   R9 a lock held past TWIN_RECORD_MAX_AGE_MS: the record goes.
 *   U1 a twinned file the session untracked is reported, and named unless
 *      .gitignore names it.
 *   C8 a required extension (first byte not A-Z) other than `sdir` refused.
 */
import { test } from "node:test";
import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { GitRunner } from "../../src/git-object-twins.js";
import type { WatchedRepo } from "../../src/placeholder-commits.js";
import {
  cleanTwinsInIndex, endTwinIndexSession, indexStatOf, parseIndex, parseTwinIndexRecord, patchIndexBuffer, patchIndexFile, readTwinIndexRecords,
  restorePendingTwinIndexes, restoreTwinIndexes, IndexUnsupported, TwinIndexRecorder, twinIndexRecordDir, TWIN_MTIME_BACK_S, TWIN_RECORD_MAX_AGE_MS,
  untrackedNotice,
} from "../../src/twin-index-stat.js";
import { stateAxes } from "../axes.js";
import { tmpDir } from "../lib/tmp-dir.js";

stateAxes("secrets"); // the twins exist only with the confidentiality axis on

const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", FILTER_BRANCH_SQUELCH_WARNING: "1",
};
const git = (cwd: string, args: string[]): string => execFileSync("git", args, { cwd, encoding: "utf8", env: GIT_ENV, stdio: ["ignore", "pipe", "pipe"] });
const gitRun = (cwd: string, args: string[]): { code: number; out: string } => {
  const r = spawnSync("git", args, { cwd, encoding: "utf8", env: GIT_ENV });
  return { code: r.status ?? -1, out: `${r.stdout}${r.stderr}` };
};
const runner: GitRunner = async (args, o) => {
  const r = spawnSync("git", args, { cwd: o.cwd, encoding: "utf8", env: GIT_ENV });
  return { code: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
};

const REAL = "API_KEY=sk-real-0123456789abcdef\nDB_URL=postgres://u:pw@h/db\n";
const TWIN = "API_KEY=$MDU:nomodel_File[0001].API_KEY\nDB_URL=$MDU:nomodel_File[0002].DB_URL\n";

interface Repo { root: string; oid: string }

/** A repository with `.env` (REAL) and app.js committed twice, then `.env`
 *  overwritten with the twin's bytes: the agent's view of the work tree. */
function repo(opts: { init?: string[]; config?: string[][] } = {}): Repo {
  // removed when the test process exits, also when a test fails (§8.5)
  const root = tmpDir("twin-index-");
  git(root, ["init", "-q", "-b", "main", ...(opts.init ?? []), "."]);
  for (const kv of opts.config ?? []) git(root, ["config", ...kv]);
  writeFileSync(join(root, ".env"), REAL);
  writeFileSync(join(root, "app.js"), "one\n");
  git(root, ["add", "-A"]);
  git(root, ["commit", "-q", "-m", "one"]);
  writeFileSync(join(root, "app.js"), "two\n");
  git(root, ["commit", "-q", "-a", "-m", "two"]);
  const oid = git(root, ["rev-parse", "HEAD:.env"]).trim();
  // The twin, as the agent's git finds it at the path (written at launch).
  writeFileSync(join(root, ".env"), TWIN);
  return { root, oid };
}

const watched = (r: Repo, index: string[] = [r.oid]): WatchedRepo[] => [{
  root: r.root, tips: null, paths: [{ rel: ".env", ids: [], index, twin: join(r.root, ".env") }],
}];
const clean = (r: Repo, index?: string[]): ReturnType<typeof cleanTwinsInIndex> =>
  cleanTwinsInIndex(watched(r, index), { git: runner, readReal: () => Buffer.from(REAL) });
const status = (r: Repo): string => git(r.root, ["status", "--porcelain"]);
const indexPath = (r: Repo): string => join(r.root, ".git", "index");

test("C0 (the defect): without the patch the twin of a tracked file is modified, and filter-branch refuses", () => {
  const r = repo();
  assert.match(status(r), /^ M \.env$/m);
  const fb = gitRun(r.root, ["filter-branch", "-f", "--index-filter", "git rm --cached --ignore-unmatch -q -- .env", "--prune-empty", "--", "--all"]);
  assert.notEqual(fb.code, 0);
  assert.match(fb.out, /unstaged changes/);
  rmSync(r.root, { recursive: true, force: true });
});

for (const [name, init, config] of [
  ["v2", [], [["index.version", "2"]]],
  ["v3 (an intent-to-add entry sets the extended flags)", [], [["index.version", "3"]]],
  ["v4", [], [["index.version", "4"]]],
  ["sha256", ["--object-format=sha256"], []],
  ["index.skipHash", [], [["index.skipHash", "true"]]],
] as Array<[string, string[], string[][]]>) {
  test(`C1 ${name}: the twin is clean to git; blob, mode and other entries unchanged; the index still reads`, async () => {
    const r = repo({ init, config });
    if (name.startsWith("v3")) {
      writeFileSync(join(r.root, "new.txt"), "n\n");
      git(r.root, ["add", "-N", "new.txt"]);
    }
    const before = git(r.root, ["ls-files", "-s"]);
    const got = await clean(r);
    assert.equal(got.length, 1);
    assert.deepEqual(got[0]!.entries.map((e) => e.rel), [".env"]);
    assert.doesNotMatch(status(r), /\.env/);
    assert.equal(gitRun(r.root, ["diff-files", "--quiet"]).code, name.startsWith("v3") ? 1 : 0); // the i-t-a entry is a change of its own
    assert.equal(gitRun(r.root, ["update-index", "-q", "--refresh"]).code, 0);
    assert.equal(git(r.root, ["ls-files", "-s"]), before, "blob ids, modes and stages unchanged");
    const st = lstatSync(join(r.root, ".env"));
    assert.ok(st.mtimeMs <= Date.now() - (TWIN_MTIME_BACK_S - 1) * 1000, "the twin's mtime set back: never racily clean");
    // A later index write (git's own) keeps it clean: not smudged as racy.
    writeFileSync(join(r.root, "app.js"), "three\n");
    git(r.root, ["add", "app.js"]);
    assert.doesNotMatch(status(r), /\.env/);
    rmSync(r.root, { recursive: true, force: true });
  });
}

test("C2 an edit of the twin, or a touch, shows modified; commit -a then takes the twin (the placeholder watch's case)", async () => {
  const r = repo();
  await clean(r);
  assert.equal(status(r), "");
  writeFileSync(join(r.root, ".env"), `${TWIN}EXTRA=1\n`);
  assert.match(status(r), /^ M \.env$/m);
  const r2 = repo();
  await clean(r2);
  const now = Date.now() / 1000;
  utimesSync(join(r2.root, ".env"), now, now);
  assert.match(status(r2), /^ M \.env$/m, "a touch: git reads it, and the twin is not the blob");
  git(r2.root, ["commit", "-q", "-a", "-m", "agent"]);
  assert.equal(git(r2.root, ["cat-file", "-p", "HEAD:.env"]), TWIN, "commit -a after a change records the twin: what the exit check names");
  for (const x of [r, r2]) rmSync(x.root, { recursive: true, force: true });
});

test("C2b a commit -a after an UNRELATED edit no longer records the twin", async () => {
  const r = repo();
  await clean(r);
  writeFileSync(join(r.root, "app.js"), "three\n");
  git(r.root, ["commit", "-q", "-a", "-m", "agent"]);
  assert.equal(git(r.root, ["rev-parse", "HEAD:.env"]).trim(), r.oid);
  rmSync(r.root, { recursive: true, force: true });
});

test("C3 demo-c4: filter-branch without untracking first runs and drops the file from every commit; stash and rebase run", async () => {
  const r = repo();
  await clean(r);
  const fb = gitRun(r.root, ["filter-branch", "-f", "--index-filter", "git rm --cached --ignore-unmatch -q -- .env", "--prune-empty", "--", "--all"]);
  assert.equal(fb.code, 0, fb.out);
  assert.match(git(r.root, ["show-ref"]), /refs\/original\/refs\/heads\/main/, "the backup ref, as git always leaves it");
  assert.equal(git(r.root, ["log", "main", "--format=%H", "--", ".env"]), "", "main no longer holds .env");
  assert.equal(git(r.root, ["ls-files", ".env"]), "", "the index no longer tracks it");
  const r2 = repo();
  await clean(r2);
  writeFileSync(join(r2.root, "app.js"), "wip\n");
  assert.equal(gitRun(r2.root, ["stash"]).code, 0);
  assert.equal(readFileSync(join(r2.root, ".env"), "utf8"), TWIN, "stash's reset left the twin alone");
  assert.equal(gitRun(r2.root, ["stash", "pop"]).code, 0);
  git(r2.root, ["commit", "-q", "-m", "wip", "--", "app.js"]);
  // A branch from the first commit (same .env blob), then main rebased on it.
  git(r2.root, ["checkout", "-q", "-b", "side", "HEAD~2"]);
  writeFileSync(join(r2.root, "b.txt"), "b\n");
  git(r2.root, ["add", "b.txt"]);
  git(r2.root, ["commit", "-q", "-m", "side"]);
  git(r2.root, ["checkout", "-q", "main"]);
  const rb = gitRun(r2.root, ["rebase", "side"]);
  assert.equal(rb.code, 0, rb.out);
  for (const x of [r, r2]) rmSync(x.root, { recursive: true, force: true });
});

test("C4 only where true: a dirty real file, a conflict, assume-unchanged, skip-worktree, an executable, an untracked path: nothing written", async () => {
  // The real file differs from its blob: it IS modified, and stays so.
  const r = repo();
  const raw = readFileSync(indexPath(r));
  assert.deepEqual(await cleanTwinsInIndex(watched(r), { git: runner, readReal: () => Buffer.from(`${REAL}X=1\n`) }), []);
  assert.ok(readFileSync(indexPath(r)).equals(raw));
  // Two index blobs (a conflict) or none (untracked).
  assert.deepEqual(await clean(r, [r.oid, "0".repeat(40)]), []);
  assert.deepEqual(await clean(r, []), []);
  // A pure patch refuses each flag and mode.
  for (const prep of [["update-index", "--assume-unchanged", ".env"], ["update-index", "--skip-worktree", ".env"], ["update-index", "--chmod=+x", ".env"]]) {
    const x = repo();
    git(x.root, prep);
    const buf = readFileSync(indexPath(x));
    const st = indexStatOf(lstatSync(join(x.root, ".env"), { bigint: true }));
    const oid = git(x.root, ["ls-files", "-s", ".env"]).split(" ")[1]!;
    assert.deepEqual(patchIndexBuffer(buf, 20, [{ rel: ".env", oid, stat: st }]), [], prep.join(" "));
    rmSync(x.root, { recursive: true, force: true });
  }
  // A blob that is not the entry's.
  const buf = readFileSync(indexPath(r));
  assert.deepEqual(patchIndexBuffer(buf, 20, [{ rel: ".env", oid: "1".repeat(40), stat: indexStatOf(lstatSync(join(r.root, ".env"), { bigint: true })) }]), []);
  rmSync(r.root, { recursive: true, force: true });
});

test("C5 git's lock wins; a symlinked index and a split index are refused", async () => {
  const r = repo();
  const raw = readFileSync(indexPath(r));
  writeFileSync(`${indexPath(r)}.lock`, "");
  const logs: string[] = [];
  assert.deepEqual(await cleanTwinsInIndex(watched(r), { git: runner, readReal: () => Buffer.from(REAL), log: (m) => logs.push(m) }), []);
  assert.match(logs.join("\n"), /index lock/);
  assert.ok(readFileSync(indexPath(r)).equals(raw));
  assert.equal(readFileSync(`${indexPath(r)}.lock`, "utf8"), "", "git's lock left alone");
  rmSync(`${indexPath(r)}.lock`);
  // A symlinked index: never read or written through.
  renameSync(indexPath(r), join(r.root, ".git", "real-index"));
  symlinkSync("real-index", indexPath(r));
  assert.throws(() => patchIndexFile(indexPath(r), 20, [{ rel: ".env", oid: r.oid, stat: indexStatOf(lstatSync(join(r.root, ".env"), { bigint: true })) }]));
  assert.ok(lstatSync(indexPath(r)).isSymbolicLink());
  rmSync(r.root, { recursive: true, force: true });
  // A split index.
  const s = repo({ config: [["core.splitIndex", "true"]] });
  git(s.root, ["update-index", "--split-index"]);
  assert.throws(() => parseIndex(readFileSync(indexPath(s)), 20), (e: unknown) => e instanceof IndexUnsupported && /split index/.test(e.message));
  rmSync(s.root, { recursive: true, force: true });
});

test("C6 the restore puts the launch stat back only over the session's own stat and blob", async () => {
  const r = repo();
  const launch = readFileSync(indexPath(r));
  const got = await clean(r);
  assert.equal(got.length, 1);
  assert.deepEqual(restoreTwinIndexes(got).back, [join(r.root, ".env")]);
  const back = readFileSync(indexPath(r));
  assert.ok(back.equals(launch), "byte for byte the launch's index");
  // The agent staged the twin: another blob; the restore leaves it.
  const r2 = repo();
  const got2 = await clean(r2);
  writeFileSync(join(r2.root, ".env"), `${TWIN}X=1\n`);
  git(r2.root, ["add", ".env"]);
  const staged = readFileSync(indexPath(r2));
  assert.deepEqual(restoreTwinIndexes(got2).back, []);
  assert.ok(readFileSync(indexPath(r2)).equals(staged));
  // git outside staged the real file (same blob, its own stat): left alone.
  const r3 = repo();
  const got3 = await clean(r3);
  writeFileSync(join(r3.root, ".env"), REAL); // the human's view: the real file
  git(r3.root, ["add", ".env"]);
  const refreshed = readFileSync(indexPath(r3));
  assert.deepEqual(restoreTwinIndexes(got3).back, []);
  assert.ok(readFileSync(indexPath(r3)).equals(refreshed));
  assert.equal(status(r3), "", "outside, the real file is clean");
  for (const x of [r, r2, r3]) rmSync(x.root, { recursive: true, force: true });
});

test("C6b THE TRADE-OFF: during the session git OUTSIDE sees the real file as modified (the cached size is the twin's), with no content change; the restore ends it", async () => {
  const r = repo();
  const got = await clean(r);
  // The human's view: the real file, unchanged.
  writeFileSync(join(r.root, ".env"), REAL);
  utimesSync(join(r.root, ".env"), Date.now() / 1000 - 60, Date.now() / 1000 - 60);
  assert.match(status(r), /^ M \.env$/m, "git does not re-read a file whose size differs from a non-zero cached size");
  assert.equal(git(r.root, ["diff", "--stat"]), "", "no content change");
  const fb = gitRun(r.root, ["filter-branch", "-f", "--index-filter", "true", "--", "--all"]);
  assert.match(fb.out, /unstaged changes/, "a clean-tree command refuses outside while the session runs");
  assert.equal(restoreTwinIndexes(got).back.length, 1);
  // The launch stat is back; a refresh (the human's next status) finds the
  // real file clean.
  git(r.root, ["update-index", "-q", "--refresh"]);
  assert.equal(status(r), "");
  // A change of the real file is never hidden.
  writeFileSync(join(r.root, ".env"), `${REAL}NEW=1\n`);
  assert.match(status(r), /^ M \.env$/m);
  rmSync(r.root, { recursive: true, force: true });
});

test("C7 a truncated or corrupted index throws, never a wrong patch", () => {
  const r = repo();
  const buf = readFileSync(indexPath(r));
  assert.doesNotThrow(() => parseIndex(buf, 20));
  assert.throws(() => parseIndex(buf.subarray(0, buf.length - 3), 20), IndexUnsupported);
  const bad = Buffer.from(buf);
  bad[20] = bad[20]! ^ 0xff;
  assert.throws(() => parseIndex(bad, 20), /checksum/);
  assert.throws(() => parseIndex(Buffer.from("DIRC\0\0\0\x09\0\0\0\0" + "\0".repeat(20), "latin1"), 20), /version/);
  assert.throws(() => parseIndex(buf, 32), IndexUnsupported, "the wrong hash length never parses");
  // Size cap and git's statSync agree with what we read.
  assert.ok(statSync(indexPath(r)).size === buf.length);
  rmSync(r.root, { recursive: true, force: true });
});

// ── The crash record ────────────────────────────────────────────────────────

/** A Mandu home with the record folder under it. */
function manduHome(): { home: string; dir: string } {
  const home = tmpDir("twin-index-home-");
  return { home, dir: twinIndexRecordDir(join(home, "state", "object-walks")) };
}
const DEAD = (): boolean => false;
const LIVE = (): boolean => true;

test("R1 the record is written BEFORE the patched index lands, 0600, in the Mandu home, and reads back", async () => {
  const r = repo();
  const h = manduHome();
  const rec = new TwinIndexRecorder(h.dir, h.home, "scope-1");
  let indexAtSave: Buffer | null = null;
  const save = rec.save.bind(rec);
  rec.save = () => { indexAtSave = readFileSync(indexPath(r)); return save(); };
  const launch = readFileSync(indexPath(r));
  const got = await cleanTwinsInIndex(watched(r), { git: runner, readReal: () => Buffer.from(REAL), recorder: rec });
  assert.equal(got.length, 1);
  assert.ok(indexAtSave !== null && (indexAtSave as Buffer).equals(launch), "the index was still the launch's when the record was saved");
  assert.ok(rec.file !== null);
  assert.equal(statSync(rec.file!).mode & 0o777, 0o600);
  const back = readTwinIndexRecords(h.dir, h.home);
  assert.equal(back.length, 1);
  assert.deepEqual(back[0]!.rec.indexes, got);
  // The session's end: put back and the record gone.
  const end = endTwinIndexSession(got, rec);
  assert.equal(end.complete, true);
  assert.ok(readFileSync(indexPath(r)).equals(launch));
  assert.deepEqual(readTwinIndexRecords(h.dir, h.home), []);
  for (const d of [r.root, h.home]) rmSync(d, { recursive: true, force: true });
});

test("R2 a crashed session (no end ran): the next launch puts the launch stat back and removes the record; a live session's record is left", async () => {
  const r = repo();
  const h = manduHome();
  const launch = readFileSync(indexPath(r));
  const rec = new TwinIndexRecorder(h.dir, h.home, "crashed");
  await cleanTwinsInIndex(watched(r), { git: runner, readReal: () => Buffer.from(REAL), recorder: rec });
  // The human's view meanwhile: the real file, which shows modified.
  writeFileSync(join(r.root, ".env"), REAL);
  utimesSync(join(r.root, ".env"), Date.now() / 1000 - 60, Date.now() / 1000 - 60);
  assert.match(status(r), /^ M \.env$/m);
  assert.deepEqual(restorePendingTwinIndexes(h.dir, h.home, { live: LIVE }), [], "a live session is never restored under it");
  assert.equal(readTwinIndexRecords(h.dir, h.home).length, 1);
  assert.deepEqual(restorePendingTwinIndexes(h.dir, h.home, { live: DEAD }), [r.root]);
  assert.ok(readFileSync(indexPath(r)).equals(launch), "byte for byte the launch's index");
  assert.deepEqual(readTwinIndexRecords(h.dir, h.home), [], "the record removed");
  git(r.root, ["update-index", "-q", "--refresh"]);
  assert.equal(status(r), "");
  for (const d of [r.root, h.home]) rmSync(d, { recursive: true, force: true });
});

test("R3 a record that cannot be written leaves the index alone", async () => {
  const r = repo();
  const h = manduHome();
  // The walk cache swapped for a link: never written through.
  mkdirSync(join(h.home, "state"), { recursive: true });
  const elsewhere = tmpDir("twin-index-elsewhere-");
  symlinkSync(elsewhere, join(h.home, "state", "object-walks"));
  const raw = readFileSync(indexPath(r));
  const logs: string[] = [];
  const got = await cleanTwinsInIndex(watched(r), { git: runner, readReal: () => Buffer.from(REAL), recorder: new TwinIndexRecorder(h.dir, h.home, "s"), log: (m) => logs.push(m) });
  assert.deepEqual(got, []);
  assert.ok(readFileSync(indexPath(r)).equals(raw));
  assert.equal(existsSync(`${indexPath(r)}.lock`), false, "the lock released");
  assert.match(logs.join("\n"), /crash record could not be written/);
  assert.deepEqual(readdirSync(elsewhere), []);
  for (const d of [r.root, h.home, elsewhere]) rmSync(d, { recursive: true, force: true });
});

test("R4 two sessions on one repository: the second inherits the first's launch stat; whichever ends last puts the real one back", async () => {
  for (const order of ["first-ends-first", "second-ends-first"] as const) {
    const r = repo();
    const h = manduHome();
    const launch = readFileSync(indexPath(r));
    const rec1 = new TwinIndexRecorder(h.dir, h.home, "one");
    const got1 = await cleanTwinsInIndex(watched(r), { git: runner, readReal: () => Buffer.from(REAL), recorder: rec1 });
    // The second session's twin: another file, another stat.
    const twin2 = join(r.root, "twin2");
    writeFileSync(twin2, TWIN);
    const rec2 = new TwinIndexRecorder(h.dir, h.home, "two", Date.now() + 1);
    const w2: WatchedRepo[] = [{ root: r.root, tips: null, paths: [{ rel: ".env", ids: [], index: [r.oid], twin: twin2 }] }];
    const got2 = await cleanTwinsInIndex(w2, {
      git: runner, readReal: () => Buffer.from(REAL), recorder: rec2,
      peers: () => readTwinIndexRecords(h.dir, h.home).map((x) => x.rec).filter((x) => x.scopeId === "one"),
    });
    assert.equal(got2.length, 1);
    assert.deepEqual(got2[0]!.entries[0]!.before, got1[0]!.entries[0]!.before, "the second's launch stat is the real one");
    if (order === "first-ends-first") {
      assert.equal(endTwinIndexSession(got1, rec1).back.length, 0, "the first finds the second's stat: left");
      assert.equal(endTwinIndexSession(got2, rec2).back.length, 1);
    } else {
      assert.equal(endTwinIndexSession(got2, rec2).back.length, 1);
      assert.equal(endTwinIndexSession(got1, rec1).back.length, 0, "already the real stat");
    }
    assert.ok(readFileSync(indexPath(r)).equals(launch), `${order}: the launch's index at the end`);
    assert.deepEqual(readTwinIndexRecords(h.dir, h.home), []);
    for (const d of [r.root, h.home]) rmSync(d, { recursive: true, force: true });
  }
});

test("R5 a lock held through the restore: the record is kept, and the next launch finishes it", async () => {
  const r = repo();
  const h = manduHome();
  const launch = readFileSync(indexPath(r));
  const rec = new TwinIndexRecorder(h.dir, h.home, "s");
  const got = await cleanTwinsInIndex(watched(r), { git: runner, readReal: () => Buffer.from(REAL), recorder: rec });
  writeFileSync(`${indexPath(r)}.lock`, "");
  const end = endTwinIndexSession(got, rec, { lockWaitMs: 100 });
  assert.equal(end.complete, false);
  assert.equal(readTwinIndexRecords(h.dir, h.home).length, 1, "kept for later");
  assert.equal(readFileSync(`${indexPath(r)}.lock`, "utf8"), "", "the other git's lock untouched");
  rmSync(`${indexPath(r)}.lock`);
  assert.deepEqual(restorePendingTwinIndexes(h.dir, h.home, { live: DEAD }), [r.root]);
  assert.ok(readFileSync(indexPath(r)).equals(launch));
  assert.deepEqual(readTwinIndexRecords(h.dir, h.home), []);
  for (const d of [r.root, h.home]) rmSync(d, { recursive: true, force: true });
});

test("R7 a crashed session's repository removed since: nothing to put back, and the record goes (never retried at every launch)", async () => {
  const r = repo();
  const h = manduHome();
  await cleanTwinsInIndex(watched(r), { git: runner, readReal: () => Buffer.from(REAL), recorder: new TwinIndexRecorder(h.dir, h.home, "gone") });
  rmSync(r.root, { recursive: true, force: true });
  const logs: string[] = [];
  assert.deepEqual(restorePendingTwinIndexes(h.dir, h.home, { live: DEAD, log: (m) => logs.push(m) }), []);
  assert.deepEqual(readTwinIndexRecords(h.dir, h.home), []);
  assert.deepEqual(logs, []);
  rmSync(h.home, { recursive: true, force: true });
});

test("R8 a failure no later try would fix (the index made a symlink, split since) is final: said once, the record dropped (review of !1642 L1)", async () => {
  for (const how of ["symlink", "split"] as const) {
    const r = repo();
    const h = manduHome();
    await cleanTwinsInIndex(watched(r), { git: runner, readReal: () => Buffer.from(REAL), recorder: new TwinIndexRecorder(h.dir, h.home, "s") });
    if (how === "symlink") {
      renameSync(indexPath(r), join(r.root, ".git", "real-index"));
      symlinkSync("real-index", indexPath(r));
    } else {
      git(r.root, ["update-index", "--split-index"]);
    }
    const logs: string[] = [];
    assert.deepEqual(restorePendingTwinIndexes(h.dir, h.home, { live: DEAD, log: (m) => logs.push(m) }), []);
    assert.equal(logs.length, 1, `${how}: said once: ${logs.join("\n")}`);
    assert.match(logs[0]!, /was not put back .*git add/);
    assert.deepEqual(readTwinIndexRecords(h.dir, h.home), [], `${how}: the record dropped, never retried at every launch`);
    for (const d of [r.root, h.home]) rmSync(d, { recursive: true, force: true });
  }
});

test("R9 a lock held for longer than TWIN_RECORD_MAX_AGE_MS: the record goes after one more try", async () => {
  const r = repo();
  const h = manduHome();
  await cleanTwinsInIndex(watched(r), { git: runner, readReal: () => Buffer.from(REAL), recorder: new TwinIndexRecorder(h.dir, h.home, "s") });
  writeFileSync(`${indexPath(r)}.lock`, "");
  restorePendingTwinIndexes(h.dir, h.home, { live: DEAD, lockWaitMs: 50 });
  assert.equal(readTwinIndexRecords(h.dir, h.home).length, 1, "kept while young");
  restorePendingTwinIndexes(h.dir, h.home, { live: DEAD, lockWaitMs: 50, now: Date.now() + TWIN_RECORD_MAX_AGE_MS + 60_000 });
  assert.deepEqual(readTwinIndexRecords(h.dir, h.home), [], "dropped when old");
  for (const d of [r.root, h.home]) rmSync(d, { recursive: true, force: true });
});

test("U1 a twinned file the session untracked is reported at the end, and named unless .gitignore names it", async () => {
  const r = repo();
  const got = await clean(r);
  git(r.root, ["rm", "-q", "--cached", ".env"]);
  const end = restoreTwinIndexes(got);
  assert.deepEqual(end.untracked, [{ root: r.root, rel: ".env" }]);
  const lines = await untrackedNotice(end.untracked, { git: runner });
  assert.equal(lines.length, 1);
  assert.match(lines[0]!, /\.env is no longer tracked by git .*\.gitignore does not name it/);
  writeFileSync(join(r.root, ".gitignore"), ".env\n");
  assert.deepEqual(await untrackedNotice(end.untracked, { git: runner }), [], "ignored: nothing to say");
  // Still tracked: not reported.
  const r2 = repo();
  assert.deepEqual(restoreTwinIndexes(await clean(r2)).untracked, []);
  for (const d of [r.root, r2.root]) rmSync(d, { recursive: true, force: true });
});

test("C8 an extension git requires (first byte not A-Z) other than the sparse index is refused, as git does", () => {
  const r = repo();
  const buf = readFileSync(indexPath(r));
  const end = buf.length - 20;
  for (const [sig, ok] of [["ABCD", true], ["1xyz", false], ["zzzz", false], ["_abc", false]] as Array<[string, boolean]>) {
    const ext = Buffer.concat([Buffer.from(sig, "latin1"), Buffer.from([0, 0, 0, 0])]);
    const body = Buffer.concat([buf.subarray(0, end), ext]);
    const full = Buffer.concat([body, createHash("sha1").update(body).digest()]);
    if (ok) assert.doesNotThrow(() => parseIndex(full, 20), sig);
    else assert.throws(() => parseIndex(full, 20), /required extension/, sig);
  }
  rmSync(r.root, { recursive: true, force: true });
});

test("R6 a record is read only in its exact shape; a broken one is dropped, another version's left", () => {
  const h = manduHome();
  const st = { ctimeSec: 1, ctimeNsec: 2, mtimeSec: 3, mtimeNsec: 4, dev: 5, ino: 6, mode: 0o100644, uid: 7, gid: 8, size: 9 };
  const good = { v: 1, pid: 99999, startTicks: null, bootId: null, scopeId: "s", at: 1, indexes: [{ root: "/r", indexPath: "/r/.git/index", hashBytes: 20, entries: [{ rel: ".env", oid: "a".repeat(40), before: st, after: st }] }] };
  assert.ok(parseTwinIndexRecord(JSON.stringify(good)) !== null);
  const bad = (f: (o: typeof good) => void): string => { const o = JSON.parse(JSON.stringify(good)); f(o); return JSON.stringify(o); };
  for (const [why, text] of [
    ["a relative index path", bad((o) => { o.indexes[0]!.indexPath = "index"; })],
    ["a path out of the work tree", bad((o) => { o.indexes[0]!.entries[0]!.rel = "../x"; })],
    ["an object name of the other format", bad((o) => { o.indexes[0]!.entries[0]!.oid = "a".repeat(64); })],
    ["a stat word over 32 bits", bad((o) => { (o.indexes[0]!.entries[0]!.before as { size: number }).size = 2 ** 32; })],
    ["a stat word missing", bad((o) => { delete (o.indexes[0]!.entries[0]!.after as Partial<typeof st>).ino; })],
    ["a hash length", bad((o) => { (o.indexes[0] as { hashBytes: number }).hashBytes = 16; })],
  ] as Array<[string, string]>) assert.equal(parseTwinIndexRecord(text), null, why);
  mkdirSync(h.dir, { recursive: true });
  writeFileSync(join(h.dir, "1-2-bad.json"), "{not json");
  writeFileSync(join(h.dir, "1-3-newer.json"), JSON.stringify({ v: 2 }));
  writeFileSync(join(h.dir, "notes.txt"), "x");
  assert.deepEqual(readTwinIndexRecords(h.dir, h.home), []);
  assert.deepEqual(readdirSync(h.dir).sort(), ["1-3-newer.json", "notes.txt"]);
  rmSync(h.home, { recursive: true, force: true });
});
