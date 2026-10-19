/**
 * placeholder-commits unit tests (launcher/src/placeholder-commits.ts;
 * confidentiality.md §7.2a "A placeholder in your repository"):
 *
 *   - the ids `git add` stores for a twin: the same as `git hash-object
 *     --no-filters` in a SHA-1 and a SHA-256 repository, and the CRLF form
 *     the same as what `core.autocrlf` stages;
 *   - the parsers of the git output the watch and the check read;
 *   - the detection over a REAL repository (git as the production runner
 *     runs it, without the sandbox): a `git commit -a` of the twin after an
 *     unrelated edit is found and named by commit, a staged twin is found,
 *     an untracked protected file added by `git add -A` is found, an
 *     ignored one added by `git add -f` too, a commit on a side branch
 *     merged away with `-s ours` is found (--full-history), and a commit of
 *     another file only is not;
 *   - the repair is REMOVE-ONLY, and is RUN with real git: what is only
 *     staged is unstaged first (back to what HEAD holds, or out of the
 *     index), a placeholder in HEAD leaves the index and the commit records
 *     that; nothing is ever put back (neither the file on disk nor a version
 *     from another commit or branch); a branch with no commit yet (`git rm
 *     --cached -f`, never `git restore --staged`, which fails there); HEAD
 *     not read, cut off, dangling or broken is never taken for an unborn
 *     one;
 *   - THE LEAK ORACLE, after every printed command is run: the real value
 *     is in no ref's tip (but one that held it before and did not move),
 *     not in the index, and in no commit reachable from a ref that did not
 *     hold it before. Run for TWO SESSIONS (a
 *     never-tracked file staged by a killed session and committed by the
 *     next, with the same and a changed symbol; a tracked file the killed
 *     session committed over, with a newer value on disk), for the BRANCH
 *     SWITCH of the 2026-10-10 review (the real `.env` only on a local
 *     branch, the agent's commit on another), in one session and across a
 *     killed one whose real version the user purged in between, and for a
 *     record of each earlier build of this check (`tracked`; `source` and
 *     `headPlaceholder`), whose repair is remove-only too;
 *   - no printed command, for any finding (consistent or not, every path
 *     shape), ever runs `git add`, takes `--source`, checks out, switches,
 *     resets, restores without `--staged`, or commits with `-a` or a
 *     pathspec: each is parsed by the real shell;
 *   - the warning: amend only for an unpushed HEAD whose refs were read; an
 *     older commit is named and rewriting it left to the user; what leaves
 *     git, that the user adds back one that belongs there, and `.gitignore`;
 *     ref names shown safely; never a claim it did not check; no secret;
 *   - the record: its shape round-trips, a bad one is refused, an earlier
 *     build's reads without its extra fields, a pending one (its launcher
 *     gone) is checked once and removed, one whose check did not complete
 *     (a call cut off, the budget spent between its repositories) is kept
 *     until it is checked again, a live one is kept, a newer version's left
 *     alone, a file not named as a record never read; a records folder
 *     swapped for a link outside the home is neither read, written, cleaned
 *     nor MADE through it; the watch's calls are short.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hardenedGitArgs, hardenedGitEnv } from "../../src/hardened-git.js";
import type { GitRunner } from "../../src/git-object-twins.js";
import {
  checkPendingPlaceholderRecords, checkPlaceholderRecord, checkPlaceholderRepo, findPlaceholders, gitBlobId, newPlaceholderRecord,
  parseCommitChanges, parseLsTree, parsePlaceholderRecord, parseWatchList, placeholderBlobIds, placeholderCheckDir,
  placeholderWarning, preparePlaceholderWatch, readPlaceholderRecord, recordDirSafe, removePlaceholderRecord, repairCommands, shellWord,
  whereCommit, writePlaceholderRecord, ensureRecordDir, plainNo, recheckEarlierRecords, unsaidBlocks,
  WATCH_GIT_TIMEOUT_MS, type CheckBlock, type PlaceholderRecord, type RepoFinding, type RepoState, type TwinSource, type WatchedRepo,
} from "../../src/placeholder-commits.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the twins exist only with the confidentiality axis on

const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, args: string[], input?: string): string =>
  execFileSync("git", args, { cwd, encoding: "utf8", env: GIT_ENV, ...(input !== undefined ? { input } : {}) });

/** The production runner's git (hardened args and env), without the
 *  sandbox: a unit test runs no bubblewrap. */
const plainGit: GitRunner = async (args, opts) => {
  const r = spawnSync("git", hardenedGitArgs(["-c", "core.quotepath=off", ...args], { literalPathspecs: true }), {
    cwd: opts.cwd, encoding: "utf8", ...(opts.input !== undefined ? { input: opts.input } : {}),
    env: hardenedGitEnv(process.env, { GIT_OPTIONAL_LOCKS: "0", LC_ALL: "C", GIT_CONFIG_GLOBAL: "/dev/null", ...(opts.env ?? {}) }),
  });
  return { code: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
};

const CANARY = "sk_live_REALVALUE_7f3a91c0d2e4b6_NEVER_PRINTED";
const INI_PW = "fakePw_Zq81xT0_REAL";
const REAL_ENV = `API_TOKEN=${CANARY}\nDEBUG=1\n`;
const TWIN_ENV = "API_TOKEN='$MDU:nomodel_Read[6555].API_TOKEN'\nDEBUG=1\n";
const REAL_INI = `[db]\nDB_PASSWORD=${INI_PW}\n`;
const TWIN_INI = "[db]\r\nDB_PASSWORD=$MDU:nomodel_Read[048a].db.DB_PASSWORD\r\n";

test("the ids are git's own: hash-object --no-filters in SHA-1 and SHA-256, and the CRLF form autocrlf stages", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-ids-"));
  try {
    const s1 = join(tmp, "s1");
    git(tmp, ["init", "-q", s1]);
    const ids = placeholderBlobIds(TWIN_INI);
    assert.equal(ids.length, 4, "raw and CRLF→LF, each in both formats");
    const raw = git(s1, ["hash-object", "--no-filters", "--stdin"], TWIN_INI).trim();
    assert.equal(gitBlobId(Buffer.from(TWIN_INI), "sha1"), raw);
    assert.ok(ids.includes(raw));
    // What `git add` stores with core.autocrlf=true: the LF form.
    writeFileSync(join(s1, "settings.ini"), TWIN_INI);
    git(s1, ["-c", "core.autocrlf=true", "add", "settings.ini"]);
    const staged = /^\d{6} ([0-9a-f]{40}) /.exec(git(s1, ["ls-files", "-s", "settings.ini"]))![1]!;
    assert.notEqual(staged, raw, "autocrlf converted it");
    assert.ok(ids.includes(staged), "the converted form is one of the ids");
    // SHA-256 repositories (git ≥ 2.29).
    const s2 = join(tmp, "s2");
    if (spawnSync("git", ["init", "-q", "--object-format=sha256", s2], { env: GIT_ENV }).status === 0) {
      const raw256 = git(s2, ["hash-object", "--no-filters", "--stdin"], TWIN_INI).trim();
      assert.equal(raw256.length, 64);
      assert.ok(ids.includes(raw256));
    }
    // An LF-only twin has one form.
    assert.equal(placeholderBlobIds(TWIN_ENV).length, 2);
    assert.deepEqual(placeholderBlobIds(TWIN_ENV), placeholderBlobIds(Buffer.from(TWIN_ENV)));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("the parsers: ls-files -s -o, ls-tree -r, log --raw -m with merges", () => {
  const a = "a".repeat(40);
  const b = "b".repeat(40);
  const w = parseWatchList(`new.env\x00100644 ${a} 0\t.env\x00100644 ${b} 1\tconf/x.ini\x00100644 ${a} 2\tconf/x.ini\x00160000 ${b} 0\tsub\0`);
  assert.deepEqual([...w.untracked], ["new.env"]);
  assert.deepEqual(w.tracked.get(".env"), [a]);
  assert.deepEqual(w.tracked.get("conf/x.ini"), [b, a], "every stage of a conflict");
  assert.equal(w.tracked.has("sub"), false, "a gitlink is no file");
  assert.deepEqual([...parseLsTree(`100644 blob ${a}\t.env\x00100644 blob ${b}\tdir with space/f\0`)], [[".env", a], ["dir with space/f", b]]);
  const c1 = "1".repeat(40);
  const c2 = "2".repeat(40);
  const log = `\x01${c1}\0\n:100644 100644 ${b} ${a} M\0.env\0\x01${c2}\0\n:100644 100644 ${a} ${b} M\0.env\0\x01${c2}\0\n:000000 100644 ${"0".repeat(40)} ${b} A\0new.env\0`;
  assert.deepEqual(parseCommitChanges(log), [
    { sha: c1, changes: [[a, ".env"]] },
    { sha: c2, changes: [[b, ".env"], [b, "new.env"]] },
  ], "newest first, a merge's two sides under one commit, only the commit's own side");
});

// ── The leak oracle ─────────────────────────────────────────────────────────

/** Every ref and HEAD, with the commit each names. */
function refTips(ws: string): Map<string, string> {
  const tips = new Map<string, string>();
  for (const l of git(ws, ["for-each-ref", "--format=%(refname) %(objectname)"]).split("\n")) {
    const [ref, sha] = l.split(" ");
    if (ref && sha) tips.set(ref, sha);
  }
  const head = spawnSync("git", ["rev-parse", "-q", "--verify", "HEAD"], { cwd: ws, env: GIT_ENV, encoding: "utf8" }).stdout.trim();
  if (head !== "") tips.set("HEAD", head);
  return tips;
}

/** The commits `revs` (rev-list arguments) reach whose tree holds `secret`
 *  anywhere (git grep over each of them). */
function commitsHolding(ws: string, secret: string, revs: readonly string[]): string[] {
  const commits = git(ws, ["rev-list", ...revs]).split("\n").filter((l) => l !== "");
  if (commits.length === 0) return [];
  const r = spawnSync("git", ["grep", "-l", "-F", "-e", secret, ...commits], { cwd: ws, env: GIT_ENV, encoding: "utf8" });
  assert.ok(r.status === 0 || r.status === 1, r.stderr);
  return [...new Set(r.stdout.split("\n").filter((l) => l !== "").map((l) => l.split(":")[0]!))];
}

interface Before { secret: string; tips: Map<string, string>; held: Set<string> }

/** What git holds of `secret` before the session: each ref's tip, and the
 *  refs from which some commit holding it is reachable. */
function before(ws: string, secret: string): Before {
  const tips = refTips(ws);
  return { secret, tips, held: new Set([...tips].filter(([, sha]) => commitsHolding(ws, secret, [sha]).length > 0).map(([ref]) => ref)) };
}

/** After the printed commands ran: the real value is in no ref's tip (but
 *  one that held it before and did not move), not in the index, and in no
 *  commit reachable from a ref (HEAD included) that did not hold it before.
 *  (A commit made in the session on a branch that tracked the real file
 *  holds it legitimately, inherited; what the repair commits is a tip.) */
function assertNoLeak(ws: string, b: Before, what: string): void {
  const idx = spawnSync("git", ["grep", "-l", "-F", "-e", b.secret, "--cached"], { cwd: ws, env: GIT_ENV, encoding: "utf8" });
  assert.equal(idx.status, 1, `${what}: the real value is in the index: ${idx.stdout}${idx.stderr}`);
  for (const [ref, tip] of refTips(ws)) {
    const unmoved = b.held.has(ref) && b.tips.get(ref) === tip;
    if (!unmoved) assert.deepEqual(commitsHolding(ws, b.secret, [tip, "--max-count=1"]), [], `${what}: the real value is in ${ref}'s tip`);
    if (!b.held.has(ref)) assert.deepEqual(commitsHolding(ws, b.secret, [tip]), [], `${what}: the real value is reachable from ${ref}, which did not hold it before`);
  }
}

/** The printed repair commands in `lines`, in order. */
const printedCommands = (lines: readonly string[]): string[] => lines.filter((l) => /^ {4}git /.test(l)).map((l) => l.trim());

/** Every printed repair command: only git's record, and nothing put back
 *  (no add, no --source, no commit with -a or a pathspec). */
const SAFE_REPAIR = /^git (restore --staged -- |rm --cached -f -- |commit (--amend --no-edit --allow-empty|-m '[^']*')$)/;

/** Run each command as the user would, outside; each must succeed. */
function runPrinted(ws: string, cmds: readonly string[]): void {
  for (const cmd of cmds) {
    assert.match(cmd, SAFE_REPAIR, cmd);
    const r = spawnSync("sh", ["-c", cmd], { cwd: ws, env: GIT_ENV, encoding: "utf8" });
    assert.equal(r.status, 0, `${cmd}: ${r.stderr}`);
  }
}

const inGit = (ws: string, spec: string): boolean => spawnSync("git", ["cat-file", "-e", spec], { cwd: ws, env: GIT_ENV }).status === 0;

// ── Detection and the repair, one session ───────────────────────────────────

/** A repository with a tracked .env and settings.ini (real content), a
 *  README, and an untracked, unignored local.env. */
function seedRepo(tmp: string): { ws: string; base: string } {
  const ws = join(tmp, "ws");
  git(tmp, ["init", "-q", ws]);
  writeFileSync(join(ws, ".env"), REAL_ENV);
  writeFileSync(join(ws, "settings.ini"), REAL_INI);
  writeFileSync(join(ws, "README.md"), "hello\n");
  writeFileSync(join(ws, ".gitignore"), "ignored.env\n");
  git(ws, ["add", "."]);
  git(ws, ["commit", "-qm", "init"]);
  writeFileSync(join(ws, "local.env"), "LOCAL=real-local-value\n");
  writeFileSync(join(ws, "ignored.env"), "IGN=real\n");
  return { ws, base: git(ws, ["rev-parse", "HEAD"]).trim() };
}

/** What git in the agent's world does: it reads the twins, then the real
 *  files are back as they are outside that world. */
function asTheAgent(ws: string, act: () => void): void {
  writeFileSync(join(ws, ".env"), TWIN_ENV);
  writeFileSync(join(ws, "settings.ini"), TWIN_INI);
  writeFileSync(join(ws, "local.env"), "LOCAL='$MDU:nomodel_Read[11aa].LOCAL'\n");
  try { act(); } finally {
    writeFileSync(join(ws, ".env"), REAL_ENV);
    writeFileSync(join(ws, "settings.ini"), REAL_INI);
    writeFileSync(join(ws, "local.env"), "LOCAL=real-local-value\n");
  }
}

function sources(ws: string, twinDir?: string) {
  return [
    { targetPath: join(ws, ".env"), content: TWIN_ENV, ...(twinDir ? { twinPath: join(twinDir, "000-.env") } : {}) },
    { targetPath: join(ws, "settings.ini"), content: TWIN_INI },
    { targetPath: join(ws, "local.env"), content: "LOCAL='$MDU:nomodel_Read[11aa].LOCAL'\n" },
    { targetPath: join(ws, "ignored.env"), content: "IGN='$MDU:nomodel_Read[22bb].IGN'\n" },
    { targetPath: join(tmp0(), "not-in-a-repo.env"), content: "X=$MDU:x\n" },
  ];
}
let tmpRoot = "";
const tmp0 = (): string => tmpRoot;

test("detection over a real repository: commit -a of the twin after an unrelated edit, a staged twin, an added untracked file; a commit of another file is clean; each repair, run, puts nothing back", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-repo-"));
  tmpRoot = tmp;
  try {
    const { ws } = seedRepo(tmp);
    const logs: string[] = [];
    const watch = await preparePlaceholderWatch(sources(ws), { git: plainGit, log: (m) => logs.push(m) });
    assert.equal(watch.length, 1, `one repository: ${logs.join(" | ")}`);
    assert.equal(watch[0]!.root, ws);
    assert.deepEqual(watch[0]!.paths.map((p) => [p.rel, (p.index ?? []).length]),
      [[".env", 1], ["ignored.env", 0], ["local.env", 0], ["settings.ini", 1]],
      "tracked and untracked files, the ignored one too (`git add -f` takes it)");
    assert.deepEqual(Object.keys(watch[0]!.paths[0]!).sort(), ["ids", "index", "rel"], "ids, index entries and the path: nothing else");
    assert.ok(watch[0]!.tips !== null && watch[0]!.tips.length === 1);
    const was = { env: before(ws, CANARY), ini: before(ws, INI_PW) };

    // A commit of another file only: clean.
    writeFileSync(join(ws, "other.txt"), "x\n");
    asTheAgent(ws, () => { git(ws, ["add", "other.txt"]); git(ws, ["commit", "-qm", "other"]); });
    assert.deepEqual(await checkPlaceholderRepo(watch[0]!, { git: plainGit }), { finding: null }, "git add <other file> + commit gives no warning");

    // The agent's `git commit -a` after an unrelated edit.
    writeFileSync(join(ws, "README.md"), "hello more\n");
    asTheAgent(ws, () => git(ws, ["commit", "-qam", "agent"]));
    const head = git(ws, ["rev-parse", "HEAD"]).trim();
    assert.match(git(ws, ["show", "HEAD:.env"]), /\$MDU:/, "precondition: the twin is in HEAD");
    const got = await checkPlaceholderRepo(watch[0]!, { git: plainGit });
    const f = got.finding!;
    assert.ok(f, "found");
    assert.equal(got.failed, undefined, "every call answered");
    assert.deepEqual(f.commits.map((c) => [c.sha, c.rels]), [[head, [".env", "settings.ini"]]], "names the commit and both files (the CRLF twin too)");
    assert.deepEqual(f.inHead, [".env", "settings.ini"]);
    assert.deepEqual(f.staged, [], "the index matches HEAD: the commit repair covers it");
    assert.deepEqual(f.leaves, [".env", "settings.ini"], "both leave git: nothing is put back");
    assert.equal(f.amend, true, "HEAD, not pushed: amend");
    const lines = placeholderWarning(f);
    const text = lines.join("\n");
    assert.match(lines[0]!, /^WARNING: mandu: /);
    assert.ok(text.includes(head.slice(0, 10)), text);
    for (const secret of [CANARY, INI_PW, "real-local-value"]) assert.ok(!text.includes(secret), `no secret in the warning: ${secret}`);

    // Run the repair it prints, outside (as the user would): the files leave
    // git, the files on disk are untouched, no new commit holds a value.
    const cmds = printedCommands(lines);
    assert.deepEqual(cmds, ["git rm --cached -f -- .env settings.ini", "git commit --amend --no-edit --allow-empty"]);
    runPrinted(ws, cmds);
    assert.ok(!inGit(ws, "HEAD:.env") && !inGit(ws, "HEAD:settings.ini"), "out of HEAD");
    assert.equal(git(ws, ["ls-files", "--", ".env", "settings.ini"]), "", "and out of the index");
    assert.equal(git(ws, ["show", "HEAD^:.env"]), REAL_ENV, "the commit before the session is untouched");
    assert.match(git(ws, ["show", "HEAD:README.md"]), /hello more/, "the agent's own change is kept");
    assert.equal(readFileSync(join(ws, ".env"), "utf8"), REAL_ENV, "the file on disk is untouched");
    assertNoLeak(ws, was.env, "commit -a");
    assertNoLeak(ws, was.ini, "commit -a (settings.ini)");
    assert.deepEqual(await checkPlaceholderRepo({ ...watch[0]!, tips: [git(ws, ["rev-parse", "HEAD"]).trim()] }, { git: plainGit }), { finding: null });

    // `git add -A` then nothing committed: staged (the files are untracked
    // now, local.env too), unstaged by the repair.
    asTheAgent(ws, () => git(ws, ["add", "-A"]));
    const st = (await checkPlaceholderRepo({ ...watch[0]!, tips: [git(ws, ["rev-parse", "HEAD"]).trim()] }, { git: plainGit })).finding!;
    assert.deepEqual(st.commits, []);
    assert.deepEqual(st.staged, [".env", "local.env", "settings.ini"]);
    assert.deepEqual(printedCommands(placeholderWarning(st)), ["git restore --staged -- .env local.env settings.ini"]);
    runPrinted(ws, repairCommands(st));
    assert.equal(git(ws, ["diff", "--cached", "--name-only"]), "", "nothing staged after the repair");

    // Untracked protected files committed by `git add -A && git commit`:
    // taken out of git again, never `git add` (that would commit a value).
    const prev = git(ws, ["rev-parse", "HEAD"]).trim();
    asTheAgent(ws, () => { git(ws, ["add", "-A"]); git(ws, ["commit", "-qm", "all"]); });
    const un = (await checkPlaceholderRepo({ ...watch[0]!, tips: [prev] }, { git: plainGit })).finding!;
    assert.deepEqual(repairCommands(un), ["git rm --cached -f -- .env local.env settings.ini", "git commit --amend --no-edit --allow-empty"]);
    assert.match(placeholderWarning(un).join("\n"), /\n {2}If not, list them in \.gitignore/);
    runPrinted(ws, repairCommands(un));
    for (const p of [".env", "local.env", "settings.ini"]) assert.ok(!inGit(ws, `HEAD:${p}`), `${p} out of HEAD`);
    assert.equal(git(ws, ["rev-parse", "HEAD"]).trim() !== prev && git(ws, ["rev-parse", "HEAD^"]).trim() === prev, true, "the amend replaced the agent's commit");
    assertNoLeak(ws, was.env, "add -A and commit");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("the twin's bytes at the check are looked up too (the agent edited the twin, then committed)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-edit-"));
  tmpRoot = tmp;
  try {
    const { ws } = seedRepo(tmp);
    const twinDir = join(tmp, "twins");
    mkdirSync(twinDir);
    const twin = join(twinDir, "000-.env");
    writeFileSync(twin, TWIN_ENV);
    const watch = await preparePlaceholderWatch(sources(ws, twinDir), { git: plainGit });
    const edited = `${TWIN_ENV}NEW_KEY=1\n`;
    writeFileSync(twin, edited); // the agent's edit lands in the twin
    writeFileSync(join(ws, ".env"), edited);
    git(ws, ["commit", "-qam", "edited"]);
    writeFileSync(join(ws, ".env"), REAL_ENV);
    const f = (await checkPlaceholderRepo(watch[0]!, { git: plainGit })).finding;
    assert.ok(f !== null && f.commits.length === 1 && f.commits[0]!.rels.includes(".env"), "the edited twin's commit is found");
    // A twin that holds no placeholder any more is not trusted as one.
    writeFileSync(twin, "nothing to see\n");
    const g = (await checkPlaceholderRepo(watch[0]!, { git: plainGit })).finding;
    assert.equal(g, null, "only placeholder bytes count");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

function finding(over: Partial<RepoFinding>): RepoFinding {
  return { root: "/w", commits: [], inHead: [], staged: [], leaves: [], head: null, headRef: "refs/heads/main", amend: false, ...over };
}

test("the warning and its repair: remove-only; amend only for an unpushed HEAD; an older commit is named, its rewriting left to the user; what leaves git, and adding it back is the user's", () => {
  const head = "c".repeat(40);
  const pushed = finding({
    head, commits: [{ sha: head, rels: [".env"], refs: ["refs/heads/main", "refs/remotes/origin/main"] }], inHead: [".env"], leaves: [".env"],
  });
  assert.deepEqual(repairCommands(pushed), ["git rm --cached -f -- .env", "git commit -m 'Take the placeholder copy of a protected file out of git'"]);
  const text = placeholderWarning(pushed).join("\n");
  assert.match(text, /already pushed: origin\/main/);
  assert.match(text, /\n {2}Commit cccccccccc keeps the placeholder in your history after this repair \(it is already on origin\/main\): taking it out of that commit means rewriting history, which is your decision\./);
  assert.match(text, /\n {2}After this, git no longer tracks \.env\. If it belongs in git, check what the file on disk holds and add it back yourself: what you add is your real file\. Mandu prints no command that puts it back\.\n {2}If not, list it in \.gitignore \(if it is not there yet\): untracked, a later git add -A would take your real file\./);
  const stash = finding({ head, commits: [{ sha: "d".repeat(40), rels: ["settings.ini"], refs: ["refs/stash"] }] });
  assert.match(placeholderWarning(stash).join("\n"), /Commit dddddddddd is in the stash: do not apply or pop that stash entry/);
  const other = finding({ head, commits: [{ sha: "e".repeat(40), rels: [".env"], refs: ["refs/heads/feature"] }] });
  const otherText = placeholderWarning(other).join("\n");
  assert.match(otherText, /\n {2}Your checked-out commit does not hold this placeholder\.\n/);
  assert.match(otherText, /Commit eeeeeeeeee keeps the placeholder in your history: taking it out of that commit means rewriting history, which is your decision\. Do not merge feature as it is; checking it out can write the placeholder over your real file\./);
  assert.match(otherText, /\n {2}Meanwhile, do NOT run git checkout/, "no command printed: no 'Until then'");
  // An older commit of the checked-out branch, HEAD amended on top of it.
  const older = finding({
    head, amend: true, inHead: [".env"], leaves: [".env"],
    commits: [{ sha: head, rels: [".env"], refs: ["refs/heads/main"] }, { sha: "f".repeat(40), rels: [".env"], refs: ["refs/heads/main"] }],
  });
  const olderText = placeholderWarning(older).join("\n");
  assert.doesNotMatch(olderText, /Commit cccccccccc keeps/, "the amend replaces HEAD: not named as kept");
  assert.match(olderText, /Commit ffffffffff keeps the placeholder in your history after this repair: taking it out of that commit means rewriting history, which is your decision\.\n/);
  // Refs that could not be read: never "on no branch", never amended.
  const unread = finding({ head, inHead: [".env"], leaves: [".env"], commits: [{ sha: head, rels: [".env"], refs: [], refsUnread: true }] });
  assert.match(placeholderWarning(unread).join("\n"), /commit cccccccccc \(where it is could not be read\)/);
  const weird = finding({ staged: ["-rf", "a b'c", "x\ny"] });
  assert.deepEqual(repairCommands(weird), ["git restore --staged -- '-rf' 'a b'\\''c' 'x?y'"], "every path one quoted word, behind --");
  const mixed = finding({ head, amend: true, inHead: ["a", "b", "d"], staged: ["c"], leaves: ["a", "b", "d"] });
  assert.deepEqual(repairCommands(mixed), ["git restore --staged -- c", "git rm --cached -f -- a b d", "git commit --amend --no-edit --allow-empty"],
    "unstage, take out, then the commit");
  const mixedText = placeholderWarning(mixed).join("\n");
  assert.match(mixedText, /in this order \(no command here adds your file on disk to git, or brings back a version of it from another commit or branch\):/);
  assert.match(mixedText, /\n {2}After this, git no longer tracks a, b, d\. If one of them belongs in git/);
  assert.match(mixedText, /\n {2}If not, list them in \.gitignore \(if they are not there yet\)/);
  assert.match(mixedText, /What git recorded there is the placeholder, not your secret\./);
  // Ref names are the agent's to write: shown with control characters as `?`.
  const esc = finding({ head, commits: [{ sha: "9".repeat(40), rels: [".env"], refs: ["refs/heads/x\x1b[2J", "refs/remotes/o/\x07y"] }] });
  const escText = placeholderWarning(esc).join("\n");
  assert.ok(!/[\x00-\x09\x0b-\x1f\x7f]/.test(escText), JSON.stringify(escText));
  assert.match(escText, /x\?\[2J/);
  assert.equal(whereCommit(["refs/heads/a\x1bb", "refs/tags/t\x00"]), "a?b, tag t?; not pushed");
  for (const f of [pushed, stash, other, older, unread, weird, mixed, esc]) {
    for (const cmd of repairCommands(f)) {
      assert.match(cmd, SAFE_REPAIR, cmd);
      assert.doesNotMatch(cmd, /checkout|reset|stash|switch|--hard|--source|\badd\b/, cmd);
    }
    const lines = placeholderWarning(f);
    assert.deepEqual(printedCommands(lines), repairCommands(f), "the printed commands are exactly these");
    assert.match(lines.at(-1)!.startsWith("  (Not") ? lines.at(-2)! : lines.at(-1)!, /do NOT run git checkout, git restore without --staged, git reset --hard or git stash \(push or pop\)/);
    assert.doesNotMatch(lines.join("\n"), /no secret was written|still holds? your real content|--source|knows of no commit|commit your real/, "no claim the check did not verify, nothing put back");
  }
  assert.equal(whereCommit([]), "on no branch");
  assert.equal(whereCommit(["refs/heads/main"]), "main; not pushed");
  assert.equal(whereCommit(["refs/stash"]), "the stash");
  assert.equal(whereCommit(["refs/remotes/origin/x"]), "already pushed: origin/x");
  assert.equal(shellWord("conf/.env"), "conf/.env");
});

test("no printed command, for any finding (consistent or not, every path shape), adds, takes --source, checks out, switches, resets, restores without --staged, or commits with -a or a pathspec: each parsed by the real shell", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-words-"));
  try {
    const head = "c".repeat(40);
    const paths: string[][] = [[], [".env"], ["-rf", "x; git add .env", "--source=HEAD", "$(git add -A)", "`git checkout -- .`", "a'b", "line\nbreak", "sp ace", "-- "]];
    const commitSets: RepoFinding["commits"][] = [
      [],
      [{ sha: head, rels: [".env"], refs: ["refs/heads/main"] }],
      [{ sha: head, rels: [".env"], refs: ["refs/heads/main", "refs/remotes/origin/main"] }],
      [{ sha: "e".repeat(40), rels: [".env"], refs: ["refs/heads/main"] }],
      [{ sha: "e".repeat(40), rels: [".env"], refs: ["refs/heads/priv"] }],
      [{ sha: "d".repeat(40), rels: [".env"], refs: ["refs/stash"] }],
      [{ sha: "d".repeat(40), rels: [".env"], refs: ["refs/tags/v1"] }],
      [{ sha: head, rels: [".env"], refs: [], refsUnread: true }],
    ];
    const seen = new Map<string, { staged: string[]; inHead: string[] }>();
    let findings = 0;
    for (const staged of paths) for (const inHead of paths) for (const commits of commitSets) {
      for (const unborn of [false, true]) for (const amend of [false, true]) for (const headUnread of [false, true]) {
        const f = finding({
          head, commits, inHead, staged, leaves: [...inHead], amend,
          ...(unborn ? { unborn: true } : {}), ...(headUnread ? { headUnread: true } : {}),
        });
        findings++;
        const cmds = repairCommands(f);
        const lines = placeholderWarning(f);
        assert.deepEqual(printedCommands(lines), cmds, "every printed command line is one of repairCommands");
        for (const c of cmds) seen.set(c, { staged, inHead });
        // Inline mentions in the prose (the path names masked, longest
        // first): only what is safe, or what not to run.
        let text = lines.filter((l) => !/^ {4}git /.test(l)).join("\n");
        for (const p of [...new Set([...staged, ...inHead, ".env"])].map((x) => x.replace(/[\u0000-\u001f\u007f]/g, "?")).sort((a, b) => b.length - a.length)) {
          text = text.split(p).join("<path>");
        }
        assert.doesNotMatch(text, /--source|git add (--|\.|[^-])|git commit -a|git checkout --|git reset(?! --hard or)/, text);
      }
    }
    assert.equal(findings, 576);
    for (const [cmd, { staged, inHead }] of seen) {
      // The real shell splits the line into words (single quotes keep each
      // path one word: nothing in it runs).
      const argv = execFileSync("sh", ["-c", `set -- ${cmd}; printf '%s\\0' "$@"`], { cwd: tmp, encoding: "utf8" }).split("\0").slice(0, -1);
      assert.equal(argv[0], "git", cmd);
      const [sub, ...rest] = argv.slice(1);
      const dashdash = rest.indexOf("--");
      const opts = dashdash < 0 ? rest : rest.slice(0, dashdash);
      const named = dashdash < 0 ? [] : rest.slice(dashdash + 1);
      const shownPaths = (ps: string[]): string[] => ps.map((p) => p.replace(/[\u0000-\u001f\u007f]/g, "?"));
      switch (sub) {
        case "restore":
          assert.deepEqual(opts, ["--staged"], `${cmd}: restore only --staged, no --source, no --worktree`);
          assert.deepEqual(named, shownPaths(staged), cmd);
          break;
        case "rm":
          assert.deepEqual(opts, ["--cached", "-f"], `${cmd}: rm only from the index`);
          assert.ok(JSON.stringify(named) === JSON.stringify(shownPaths(staged)) || JSON.stringify(named) === JSON.stringify(shownPaths(inHead)), cmd);
          break;
        case "commit":
          assert.ok(dashdash < 0, `${cmd}: a commit names no path`);
          assert.ok(JSON.stringify(opts) === JSON.stringify(["--amend", "--no-edit", "--allow-empty"]) || (opts.length === 2 && opts[0] === "-m"), `${cmd}: no -a, no --include, no --only`);
          break;
        default:
          assert.fail(`${cmd}: no other git command is ever printed (${sub})`);
      }
      for (const w of opts) assert.doesNotMatch(w, /^(add|checkout|switch|reset|stash|merge|cherry-pick|read-tree|update-index|-a|--all|-i|--include|-o|--only|-p|--patch|--source.*|-s|-W|--worktree)$/, cmd);
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("findPlaceholders: a staged twin under a clean HEAD, a placeholder already in HEAD, nothing", () => {
  const ids = placeholderBlobIds(TWIN_ENV);
  const repo: WatchedRepo = { root: "/w", tips: [], paths: [{ rel: ".env", ids }] };
  const base: RepoState = { index: new Map(), commits: [], head: null, headRef: null, headBlobs: new Map(), refsOf: new Map() };
  assert.equal(findPlaceholders(repo, base), null);
  assert.equal(findPlaceholders(repo, { ...base, index: new Map([[".env", ["f".repeat(40)]]]) }), null, "a real blob staged is no finding");
  const staged = findPlaceholders(repo, { ...base, index: new Map([[".env", [ids[0]!]]]) })!;
  assert.deepEqual(staged.staged, [".env"]);
  assert.deepEqual(staged.leaves, [".env"], "HEAD read and without it: unstaged, it leaves git");
  assert.deepEqual(findPlaceholders(repo, { ...base, index: new Map([[".env", [ids[0]!]]]), headBlobs: new Map([[".env", "f".repeat(40)]]) })!.leaves, [],
    "HEAD holds another version: unstaged, the index is back to it and the file stays tracked");
  assert.deepEqual(findPlaceholders(repo, { ...base, index: new Map([[".env", [ids[0]!]]]), headBlobs: null })!.leaves, [], "HEAD not read: nothing said of it");
  const inHead = findPlaceholders(repo, { ...base, index: new Map([[".env", [ids[0]!]]]), headBlobs: new Map([[".env", ids[0]!]]) })!;
  assert.deepEqual([inHead.staged, inHead.inHead, inHead.leaves, inHead.amend], [[], [".env"], [".env"], false], "no new commit: a new commit, not amend");
  assert.match(placeholderWarning(inHead).join("\n"), /your checked-out commit holds the placeholder of \.env/);
  // HEAD is the session's commit: amend only when its refs were read.
  const sha = "1".repeat(40);
  const commit = { sha, changes: [[ids[0]!, ".env"]] as Array<[string, string]> };
  const atHead = { ...base, head: sha, commits: [commit], headBlobs: new Map([[".env", ids[0]!]]) };
  assert.equal(findPlaceholders(repo, { ...atHead, refsOf: new Map([[sha, ["refs/heads/main"]]]) })!.amend, true);
  assert.equal(findPlaceholders(repo, atHead)!.amend, false, "refs unread: maybe pushed, a new commit");
  assert.equal(findPlaceholders(repo, { ...atHead, refsOf: new Map([[sha, ["refs/heads/main", "refs/remotes/o/main"]]]) })!.amend, false);
  // A staged file HEAD lacks leaves git when unstaged: the .gitignore advice.
  const fresh: WatchedRepo = { ...repo, paths: [{ rel: "new.env", ids }] };
  const leaving = findPlaceholders(fresh, { ...base, index: new Map([["new.env", [ids[0]!]]]) })!;
  assert.deepEqual([leaving.staged, leaving.leaves], [["new.env"], ["new.env"]]);
  assert.match(placeholderWarning(leaving).join("\n"), /If not, list it in \.gitignore/);
  // Staged before the session (said by the session before): not said again.
  const before: WatchedRepo = { ...repo, paths: [{ ...repo.paths[0]!, index: [ids[0]!] }] };
  assert.equal(findPlaceholders(before, { ...base, index: new Map([[".env", [ids[0]!]]]) }), null);
  assert.deepEqual(findPlaceholders(before, { ...base, index: new Map([[".env", [ids[1]!]]]) })?.staged, [".env"], "another placeholder staged in the session is");
});

test("the record: round trip, refused shapes, earlier builds' records read without their extra fields, pending checked once and removed, live kept", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-rec-"));
  tmpRoot = tmp;
  try {
    const { ws } = seedRepo(tmp);
    const watch = await preparePlaceholderWatch(sources(ws), { git: plainGit });
    const home = join(tmp, "home");
    const dir = placeholderCheckDir(join(home, "state", "object-walks"));
    const none = { blocks: [], records: [], kept: [] };
    assert.equal(recordDirSafe(dir, home), false, "no folder yet: nothing to read");
    assert.deepEqual(await checkPendingPlaceholderRecords(dir, home, { git: plainGit }), none);
    const rec = newPlaceholderRecord("scope-1", watch);
    const file = writePlaceholderRecord(dir, home, rec)!;
    assert.ok(file !== null && existsSync(file));
    assert.deepEqual(readPlaceholderRecord(file), rec);
    assert.equal(parsePlaceholderRecord("{"), null);
    assert.equal(parsePlaceholderRecord(JSON.stringify({ ...rec, v: 2 })), null);
    assert.equal(parsePlaceholderRecord(JSON.stringify({ ...rec, repos: [{ ...rec.repos[0], root: "relative" }] })), null);
    assert.equal(parsePlaceholderRecord(JSON.stringify({ ...rec, repos: [{ ...rec.repos[0], paths: [{ rel: "../x", ids: ["a".repeat(40)] }] }] })), null);
    assert.equal(parsePlaceholderRecord(JSON.stringify({ ...rec, repos: [{ ...rec.repos[0], paths: [{ rel: "x", ids: ["zz"] }] }] })), null);
    // Earlier builds' records: a `tracked` flag (the first), a `source`
    // commit and a `headPlaceholder` flag (the second), whatever they hold,
    // read as the same file without them.
    for (const extra of [{ tracked: true }, { source: "b".repeat(40), headPlaceholder: true }, { source: "HEAD; rm -rf ~", headPlaceholder: "x" }]) {
      const old = parsePlaceholderRecord(JSON.stringify({ ...rec, repos: [{ ...rec.repos[0], paths: [{ rel: ".env", ids: ["a".repeat(40)], ...extra }] }] }));
      assert.ok(old !== null, JSON.stringify(extra));
      assert.deepEqual(old.repos[0]!.paths, [{ rel: ".env", ids: ["a".repeat(40)] }], JSON.stringify(extra));
    }

    // The session's commit, then its launcher is gone (a crash).
    writeFileSync(join(ws, "README.md"), "edit\n");
    asTheAgent(ws, () => git(ws, ["commit", "-qam", "crashed session"]));
    const head = git(ws, ["rev-parse", "HEAD"]).trim();
    // Live (this process): kept, unchecked.
    assert.deepEqual(await checkPendingPlaceholderRecords(dir, home, { git: plainGit }), none);
    assert.ok(existsSync(file));
    // Gone: checked once, said, removed.
    const pending = await checkPendingPlaceholderRecords(dir, home, { git: plainGit, live: () => false });
    const blocks = pending.blocks;
    assert.deepEqual(blocks.map((b) => b.root), [ws]);
    assert.deepEqual(pending.records, [rec], "the records checked come back (the check after the agent)");
    assert.deepEqual(pending.kept, [], "its check completed: nothing kept");
    const lines = blocks[0]!.lines;
    assert.deepEqual(lines.slice(1), blocks[0]!.body, "the body is the check's own lines");
    assert.match(lines[0]!, new RegExp(`^mandu: an earlier session \\(scope-1, started .*\\) ended before Mandu could check ${ws}; checked now:$`));
    assert.ok(lines.some((l) => l.includes(head.slice(0, 10))), lines.join("\n"));
    assert.ok(!lines.join("\n").includes(CANARY));
    assert.deepEqual(readdirSync(dir), [], "the record is cleared once checked");
    assert.deepEqual(await checkPendingPlaceholderRecords(dir, home, { git: plainGit, live: () => false }), none, "said once");
    // Only a file named as a record is read or removed: one this version
    // cannot read is dropped; one of another version (a newer launcher's)
    // and any other file are left alone.
    writeFileSync(join(dir, "junk.json"), "{");
    writeFileSync(join(dir, "1-2-broken.json"), "{");
    writeFileSync(join(dir, "1-3-bad-shape.json"), JSON.stringify({ ...rec, repos: "x" }));
    writeFileSync(join(dir, "1-4-newer.json"), JSON.stringify({ ...rec, v: 2 }));
    assert.deepEqual(await checkPendingPlaceholderRecords(dir, home, { git: plainGit, live: () => false }), none);
    assert.deepEqual(readdirSync(dir).sort(), ["1-4-newer.json", "junk.json"]);
    removePlaceholderRecord(join(dir, "junk.json"), home);
    assert.ok(existsSync(join(dir, "junk.json")), "removal takes only a file named as a record");
    rmSync(join(dir, "junk.json"));
    rmSync(join(dir, "1-4-newer.json"));
    // The whole record, checked directly (the launch's own exit path).
    assert.ok((await checkPlaceholderRecord(rec, { git: plainGit }))[0]!.lines.some((l) => l.includes(head.slice(0, 10))));
    // The next session's own watch starts from that state: unchanged, it
    // says nothing (the record before it said it).
    const again = await preparePlaceholderWatch(sources(ws), { git: plainGit });
    assert.deepEqual(await checkPlaceholderRecord(newPlaceholderRecord("scope-2", again), { git: plainGit }), []);
    // A directory that cannot be made: no record, no throw.
    assert.equal(writePlaceholderRecord("/dev/null/x", home, rec), null);

    // The walk cache swapped for a link to a folder outside the home
    // (planted while something ran unconfined): never read, written or
    // cleaned through it, a pending record and a bad one there included.
    const outside = join(tmp, "elsewhere");
    mkdirSync(join(outside, "placeholder-checks"), { recursive: true });
    const theirs = join(outside, "placeholder-checks", "1-5-theirs.json");
    const pendingThere = join(outside, "placeholder-checks", `${rec.at}-${rec.pid}-scope-1.json`);
    writeFileSync(theirs, "not json");
    writeFileSync(pendingThere, JSON.stringify(rec));
    const walks = join(home, "state", "object-walks");
    renameSync(walks, join(tmp, "old-walks"));
    symlinkSync(join(tmp, "elsewhere"), walks);
    assert.equal(recordDirSafe(dir, home), false);
    assert.deepEqual(await checkPendingPlaceholderRecords(dir, home, { git: plainGit, live: () => false }), none);
    assert.ok(existsSync(theirs) && existsSync(pendingThere), "nothing removed through the link");
    assert.equal(writePlaceholderRecord(dir, home, newPlaceholderRecord("scope-3", watch)), null, "nothing written through it");
    // Nor MADE through it: the link's target has no records folder yet, and
    // gets none (the parent is checked before anything is made in it).
    rmSync(join(outside, "placeholder-checks"), { recursive: true });
    assert.equal(writePlaceholderRecord(dir, home, newPlaceholderRecord("scope-4", watch)), null);
    assert.equal(existsSync(join(outside, "placeholder-checks")), false, "no folder made through the swapped link");
    mkdirSync(join(outside, "placeholder-checks"));
    writeFileSync(theirs, "not json");
    writeFileSync(pendingThere, JSON.stringify(rec));
    removePlaceholderRecord(pendingThere.replace(join(tmp, "elsewhere"), walks), home);
    assert.ok(existsSync(pendingThere));
    // The records folder itself a link, inside the home or not: refused too.
    rmSync(walks);
    mkdirSync(walks);
    symlinkSync(join(outside, "placeholder-checks"), dir);
    assert.equal(recordDirSafe(dir, home), false);
    rmSync(dir);
    mkdirSync(dir);
    assert.equal(recordDirSafe(dir, realpathSync(home)), true, "a real folder inside the home");
    assert.equal(recordDirSafe(dir, outside), false, "outside the home given");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("a git that fails is named, never thrown, and marks the check as failed; a repository git cannot read is not watched", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-fail-"));
  tmpRoot = tmp;
  try {
    const { ws } = seedRepo(tmp);
    const watch = await preparePlaceholderWatch(sources(ws), { git: plainGit });
    const broken: GitRunner = async () => ({ code: 128, stdout: "", stderr: "fatal: boom" });
    const r = await checkPlaceholderRepo(watch[0]!, { git: broken });
    assert.equal(r.finding, null);
    assert.equal(r.failed, true);
    assert.match(r.error ?? "", /git ls-files failed: fatal: boom/);
    assert.match((await checkPlaceholderRecord(newPlaceholderRecord("s", watch), { git: broken }))[0]!.lines[0]!, /could not check .* for a placeholder copy/);
    const logs: string[] = [];
    assert.deepEqual(await preparePlaceholderWatch(sources(ws), { git: broken, log: (m) => logs.push(m) }), []);
    assert.match(logs.join("\n"), /is not checked for a placeholder commit this session \(git: fatal: boom\)/);
    // A hit whose for-each-ref fails: where the commit is is unknown (said
    // so, never "on no branch"), and HEAD is not amended.
    writeFileSync(join(ws, "README.md"), "edit\n");
    asTheAgent(ws, () => git(ws, ["commit", "-qam", "agent"]));
    const noRefs: GitRunner = async (args, opts) => args[0] === "for-each-ref" ? { code: 128, stdout: "", stderr: "fatal: refs" } : plainGit(args, opts);
    const g = await checkPlaceholderRepo(watch[0]!, { git: noRefs });
    assert.equal(g.failed, true);
    assert.equal(g.finding!.amend, false);
    assert.deepEqual(repairCommands(g.finding!), ["git rm --cached -f -- .env settings.ini", "git commit -m 'Take the placeholder copy of protected files out of git'"]);
    assert.match(placeholderWarning(g.finding!).join("\n"), /\(where it is could not be read\)[\s\S]*Not fully checked: git for-each-ref failed: fatal: refs/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("the repair, run with real git: one file's placeholder in HEAD and two others only staged; the staged ones are unstaged FIRST, so the commit cannot take them along, and nothing comes back", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-mixed-"));
  tmpRoot = tmp;
  try {
    const { ws, base } = seedRepo(tmp);
    const watch = await preparePlaceholderWatch(sources(ws), { git: plainGit });
    const was = before(ws, CANARY);
    // The agent: `git commit -a` (the tracked twins ride along), then `git
    // add -A` (the untracked local.env's twin staged) and `git add -f` of the
    // ignored one, never committed.
    writeFileSync(join(ws, "README.md"), "agent edit\n");
    asTheAgent(ws, () => {
      writeFileSync(join(ws, "ignored.env"), "IGN='$MDU:nomodel_Read[22bb].IGN'\n");
      git(ws, ["commit", "-qam", "agent"]);
      git(ws, ["add", "-A"]);
      git(ws, ["add", "-f", "ignored.env"]);
    });
    writeFileSync(join(ws, "ignored.env"), "IGN=real\n");
    const f = (await checkPlaceholderRepo(watch[0]!, { git: plainGit })).finding!;
    assert.deepEqual(f.inHead, [".env", "settings.ini"]);
    assert.deepEqual(f.staged, ["ignored.env", "local.env"], "the untracked file's twin and the ignored one's, staged");
    assert.equal(f.amend, true);
    const lines = placeholderWarning(f);
    const cmds = printedCommands(lines);
    assert.deepEqual(cmds, [
      "git restore --staged -- ignored.env local.env",
      "git rm --cached -f -- .env settings.ini",
      "git commit --amend --no-edit --allow-empty",
    ], "unstage first, then out of the index, then the commit");
    const text = lines.join("\n");
    assert.match(text, /in this order \(no command here adds your file on disk to git, or brings back a version of it from another commit or branch\):/);
    assert.match(text, /Before the commit: it takes everything staged, so check `git status`/);
    assert.match(text, /After this, git no longer tracks \.env, ignored\.env, local\.env, settings\.ini\./);
    runPrinted(ws, cmds);
    for (const p of [".env", "settings.ini", "local.env", "ignored.env"]) assert.ok(!inGit(ws, `HEAD:${p}`), `${p}: neither placeholder nor value in HEAD`);
    assert.equal(git(ws, ["rev-parse", "HEAD^"]).trim(), base, "the amend replaced the agent's commit");
    assert.match(git(ws, ["show", "HEAD:README.md"]), /agent edit/, "the agent's own change is kept");
    assert.equal(git(ws, ["diff", "--cached", "--name-only"]), "", "nothing staged");
    assert.equal(readFileSync(join(ws, ".env"), "utf8"), REAL_ENV, "the file on disk is untouched");
    assertNoLeak(ws, was, "mixed");
    assert.deepEqual(await checkPlaceholderRepo({ ...watch[0]!, tips: [git(ws, ["rev-parse", "HEAD"]).trim()] }, { git: plainGit }), { finding: null });
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("a branch with no commit yet: the staged placeholders leave the index with `git rm --cached -f` (`git restore --staged` fails there); a HEAD git could not read is never taken for one", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-unborn-"));
  tmpRoot = tmp;
  try {
    const ws = join(tmp, "ws");
    git(tmp, ["init", "-q", ws]);
    writeFileSync(join(ws, ".env"), REAL_ENV);
    writeFileSync(join(ws, "local.env"), "LOCAL=real-local-value\n");
    git(ws, ["add", ".env"]); // staged by the user before the session, never committed
    const watch = await preparePlaceholderWatch(sources(ws).filter((f) => /\/(\.env|local\.env)$/.test(f.targetPath)), { git: plainGit });
    assert.deepEqual(watch[0]!.paths.map((p) => [p.rel, (p.index ?? []).length]), [[".env", 1], ["local.env", 0]]);
    assert.deepEqual(watch[0]!.tips, [], "no commit: no tips");
    asTheAgent(ws, () => git(ws, ["add", "-A"]));
    const f = (await checkPlaceholderRepo(watch[0]!, { git: plainGit })).finding!;
    assert.deepEqual([f.head, f.unborn, f.staged, f.commits], [null, true, [".env", "local.env"], []]);
    assert.notEqual(spawnSync("git", ["restore", "--staged", "--", ".env"], { cwd: ws, env: GIT_ENV }).status, 0, "precondition: restore --staged fails with no HEAD");
    const cmds = repairCommands(f);
    assert.deepEqual(cmds, ["git rm --cached -f -- .env local.env"]);
    runPrinted(ws, cmds);
    assert.equal(git(ws, ["ls-files", "-s", "--", ".env", "local.env"]), "", "out of the index");
    for (const [p, real] of [[".env", REAL_ENV], ["local.env", "LOCAL=real-local-value\n"]] as const) {
      assert.equal(readFileSync(join(ws, p), "utf8"), real, `${p} on disk untouched`);
    }
    // HEAD not read (any failure but a plain "no such commit"): never
    // unborn, so the repair never untracks a file HEAD may hold.
    asTheAgent(ws, () => git(ws, ["add", "-A"]));
    const flaky: GitRunner = async (args, opts) => args[0] === "rev-parse" ? { code: 128, stdout: "", stderr: "fatal: boom" } : plainGit(args, opts);
    const g = (await checkPlaceholderRepo(watch[0]!, { git: flaky })).finding!;
    assert.equal(g.unborn, undefined);
    assert.deepEqual(repairCommands(g), ["git restore --staged -- .env local.env"]);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("--full-history: a placeholder commit on a side branch merged away with `-s ours`, then deleted, is still found, and named as kept in the history", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-side-"));
  tmpRoot = tmp;
  try {
    const { ws } = seedRepo(tmp);
    const watch = await preparePlaceholderWatch(sources(ws), { git: plainGit });
    let side = "";
    asTheAgent(ws, () => {
      git(ws, ["checkout", "-q", "-b", "side"]);
      git(ws, ["commit", "-qam", "on side"]);
      side = git(ws, ["rev-parse", "HEAD"]).trim();
      git(ws, ["checkout", "-q", "-"]);
      git(ws, ["merge", "-q", "-s", "ours", "--no-edit", "side"]);
      git(ws, ["branch", "-q", "-D", "side"]);
    });
    assert.match(git(ws, ["show", `${side}:.env`]), /\$MDU:/, "precondition: the side commit holds the placeholder");
    // What git's default walk sees: the merge is the same as its first
    // parent for these paths, so the side is pruned. (git 2.53's `-m` alone
    // happens to keep it; --full-history is the documented switch, kept so
    // the check does not rest on that.)
    const head = git(ws, ["rev-parse", "HEAD"]).trim();
    assert.doesNotMatch(git(ws, ["log", "--format=%H", `${watch[0]!.tips![0]}..${head}`, "--", ".env"]), new RegExp(side), "precondition: the default walk misses it");
    const f = (await checkPlaceholderRepo(watch[0]!, { git: plainGit })).finding!;
    assert.ok(f !== null, "found");
    assert.deepEqual(f.commits.map((c) => [c.sha, c.rels]), [[side, [".env", "settings.ini"]]]);
    assert.deepEqual([f.inHead, f.staged], [[], []], "HEAD and the index hold the real files");
    const text = placeholderWarning(f).join("\n");
    assert.deepEqual(repairCommands(f), [], "nothing to take out of HEAD");
    assert.match(text, /\n {2}Your checked-out commit does not hold this placeholder\.\n/);
    assert.match(text, new RegExp(`Commit ${side.slice(0, 10)} keeps the placeholder in your history: taking it out of that commit means rewriting history, which is your decision\\.`));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

// ── Two sessions, the repair run as printed (the blocker of 2026-10-10) ────

/** One launch as run.ts makes it, against the records in `dir`: the
 *  pending check (blocks said at launch), this launch's watch, its record. */
async function launchWith(dir: string, home: string, files: readonly TwinSource[]) {
  const pending = await checkPendingPlaceholderRecords(dir, home, { git: plainGit, live: () => false });
  const watch = await preparePlaceholderWatch(files, { git: plainGit });
  return { pending, watch, rec: newPlaceholderRecord("next", watch) };
}

/** The same launch's exit, as run.ts says it: its own check, then each
 *  earlier record checked again unless it says the very same. */
async function exitOf(l: Awaited<ReturnType<typeof launchWith>>): Promise<{ own: CheckBlock[]; again: CheckBlock[]; lines: string[] }> {
  const own = await checkPlaceholderRecord(l.rec, { git: plainGit });
  const again = unsaidBlocks(own, await recheckEarlierRecords(l.pending.records, { git: plainGit }));
  return { own, again, lines: [...own, ...again].flatMap((b) => b.lines) };
}

const LOCAL_REAL = `LOCAL_TOKEN=${CANARY}\n`;
const twinOf = (sym: string): string => `LOCAL_TOKEN='$MDU:nomodel_Read[${sym}].LOCAL_TOKEN'\n`;

/** A repository with one commit (README) and a protected local.env holding
 *  the canary that git never tracked. */
function neverTracked(tmp: string): { ws: string; home: string; dir: string } {
  const ws = join(tmp, "ws");
  git(tmp, ["init", "-q", ws]);
  writeFileSync(join(ws, "README.md"), "hello\n");
  git(ws, ["add", "."]);
  git(ws, ["commit", "-qm", "init"]);
  writeFileSync(join(ws, "local.env"), LOCAL_REAL);
  const home = join(tmp, "home");
  return { ws, home, dir: placeholderCheckDir(join(home, "state", "object-walks")) };
}

/** git as the agent runs it: `rel` reads as `twin`. */
function asAgentWith(ws: string, rel: string, twin: string, real: string, act: () => void): void {
  writeFileSync(join(ws, rel), twin);
  try { act(); } finally { writeFileSync(join(ws, rel), real); }
}

test("TWO SESSIONS, run as printed: session 1's `git add -A` stages a never-tracked file's placeholder and is killed; session 2 starts before the repair and commits; every command printed after it, run in order, leaks nothing", async () => {
  for (const symbolChanged of [false, true]) {
    const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-two-"));
    try {
      const { ws, home, dir } = neverTracked(tmp);
      const was = before(ws, CANARY);
      const t1 = twinOf("11aa");
      const t2 = symbolChanged ? twinOf("22bb") : t1;
      // Session 1: its record, the agent's `git add -A`, then a kill (no check).
      const w1 = await preparePlaceholderWatch([{ targetPath: join(ws, "local.env"), content: t1 }], { git: plainGit });
      assert.ok(writePlaceholderRecord(dir, home, newPlaceholderRecord("first", w1)) !== null);
      asAgentWith(ws, "local.env", t1, LOCAL_REAL, () => git(ws, ["add", "-A"]));

      // Session 2 launches before any repair: the index holds session 1's
      // placeholder (an early build took it for a tracked file and printed
      // `git add -- local.env`).
      const s2 = await launchWith(dir, home, [{ targetPath: join(ws, "local.env"), content: t2 }]);
      const atLaunch = s2.pending.blocks.flatMap((b) => b.lines);
      assert.match(atLaunch.join("\n"), /ended before Mandu could check .*; checked now:\n[\s\S]*staged for your next commit: local\.env/);
      assert.deepEqual(printedCommands(atLaunch), ["git restore --staged -- local.env"]);
      assert.ok(!JSON.stringify(s2.rec).includes(CANARY), "the record holds no value");

      // Session 2's agent: an unrelated edit, then `git commit -a` (local.env
      // is in the index now, so it goes in).
      writeFileSync(join(ws, "README.md"), "agent edit\n");
      asAgentWith(ws, "local.env", t2, LOCAL_REAL, () => git(ws, ["commit", "-qam", "agent work"]));
      assert.match(git(ws, ["show", "HEAD:local.env"]), /\$MDU:/, "precondition: the placeholder is committed");

      const end = await exitOf(s2);
      const text = end.lines.join("\n");
      const cmds = printedCommands(end.lines);
      assert.deepEqual(cmds, ["git rm --cached -f -- local.env", "git commit --amend --no-edit --allow-empty"], text);
      assert.match(text, /After this, git no longer tracks local\.env\. If it belongs in git, check what the file on disk holds and add it back yourself/);
      assert.match(text, /If not, list it in \.gitignore/);
      assert.doesNotMatch(`${atLaunch.join("\n")}\n${text}`, /no secret was written|still holds? your real content|git add --|--source/);
      assert.ok(!`${atLaunch.join("\n")}\n${text}`.includes(CANARY), "no value in any line");

      runPrinted(ws, cmds);
      assert.ok(!inGit(ws, "HEAD:local.env"), "local.env out of HEAD");
      assert.equal(git(ws, ["ls-files", "-s", "--", "local.env"]), "", "and out of the index");
      assertNoLeak(ws, was, `symbol changed: ${symbolChanged}`);
      assert.match(git(ws, ["show", "HEAD:README.md"]), /agent edit/, "the agent's own change is kept");
      assert.equal(readFileSync(join(ws, "local.env"), "utf8"), LOCAL_REAL, "the file on disk is untouched");
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }
});

test("TWO SESSIONS, committed, the symbol changed in between: the killed session's commit is named at the next launch, the next agent's commit after it; run as printed, both placeholders leave HEAD and the earlier commit is left to the user", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-two-c-"));
  try {
    const { ws, home, dir } = neverTracked(tmp);
    const was = before(ws, CANARY);
    const t1 = twinOf("11aa");
    const t2 = twinOf("22bb");
    const w1 = await preparePlaceholderWatch([{ targetPath: join(ws, "local.env"), content: t1 }], { git: plainGit });
    writePlaceholderRecord(dir, home, newPlaceholderRecord("first", w1));
    asAgentWith(ws, "local.env", t1, LOCAL_REAL, () => { git(ws, ["add", "-A"]); git(ws, ["commit", "-qm", "first session"]); });
    const c1 = git(ws, ["rev-parse", "HEAD"]).trim();

    const s2 = await launchWith(dir, home, [{ targetPath: join(ws, "local.env"), content: t2 }]);
    assert.deepEqual(printedCommands(s2.pending.blocks.flatMap((b) => b.lines)), ["git rm --cached -f -- local.env", "git commit --amend --no-edit --allow-empty"],
      "the killed session's own check at launch");

    writeFileSync(join(ws, "README.md"), "agent edit\n");
    asAgentWith(ws, "local.env", t2, LOCAL_REAL, () => git(ws, ["commit", "-qam", "second session"]));
    const end = await exitOf(s2);
    const cmds = printedCommands(end.lines);
    assert.deepEqual(cmds, ["git rm --cached -f -- local.env", "git commit --amend --no-edit --allow-empty"], end.lines.join("\n"));
    // The earlier record, checked again: its commit is in the history, not
    // in HEAD (which holds the second placeholder, said by the block above).
    assert.equal(end.again.length, 1);
    const againText = end.again[0]!.lines.join("\n");
    assert.ok(againText.includes(`commit ${c1.slice(0, 10)}`), againText);
    assert.match(againText, /checked again now:[\s\S]*Your checked-out commit does not hold this placeholder\.\n[\s\S]*Commit [0-9a-f]{10} keeps the placeholder in your history: taking it out of that commit means rewriting history, which is your decision\./);
    assert.deepEqual(printedCommands(end.again[0]!.lines), [], "nothing to run for an older commit");
    runPrinted(ws, cmds);
    assert.ok(!inGit(ws, "HEAD:local.env"));
    assert.equal(git(ws, ["ls-files", "-s", "--", "local.env"]), "");
    assertNoLeak(ws, was, "after the repair");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("TWO SESSIONS, a tracked file the killed session committed its placeholder over, a newer value on disk since: run as printed, the file leaves git; neither its committed value nor the newer one goes into a new commit", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-two-t-"));
  tmpRoot = tmp;
  try {
    const { ws, base } = seedRepo(tmp);
    const home = join(tmp, "home");
    const dir = placeholderCheckDir(join(home, "state", "object-walks"));
    const envOnly = (content: string): TwinSource[] => [{ targetPath: join(ws, ".env"), content }];
    const was = before(ws, CANARY);
    const NEWER = "API_TOKEN=sk_live_NEWER_never_committed_42\nDEBUG=1\n";
    const wasNewer = before(ws, "NEWER_never_committed");
    const t1 = TWIN_ENV;
    const t2 = TWIN_ENV.replace("6555", "7777");
    const w1 = await preparePlaceholderWatch(envOnly(t1), { git: plainGit });
    writePlaceholderRecord(dir, home, newPlaceholderRecord("first", w1));
    writeFileSync(join(ws, "README.md"), "first edit\n");
    asAgentWith(ws, ".env", t1, REAL_ENV, () => git(ws, ["commit", "-qam", "first session"]));
    // Meanwhile the real file on disk took a NEW value, never committed.
    writeFileSync(join(ws, ".env"), NEWER);

    const s2 = await launchWith(dir, home, envOnly(t2));
    writeFileSync(join(ws, "README.md"), "second edit\n");
    asAgentWith(ws, ".env", t2, NEWER, () => git(ws, ["commit", "-qam", "second session"]));
    const end = await exitOf(s2);
    const cmds = printedCommands(end.lines);
    assert.deepEqual(cmds, ["git rm --cached -f -- .env", "git commit --amend --no-edit --allow-empty"], end.lines.join("\n"));
    runPrinted(ws, cmds);
    assert.ok(!inGit(ws, "HEAD:.env"), "out of HEAD: nothing put back");
    assert.equal(git(ws, ["show", `${base}:.env`]), REAL_ENV, "the commit from before the sessions is untouched");
    assertNoLeak(ws, was, "the committed value");
    assertNoLeak(ws, wasNewer, "the value on disk");
    assert.equal(readFileSync(join(ws, ".env"), "utf8"), NEWER, "the file on disk is untouched");
    assert.match(git(ws, ["show", "HEAD:README.md"]), /second edit/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

// ── The branch switch (the blocker of the 2026-10-10 second review) ─────────

const PRIV_REAL = "TOKEN=sk_REAL_SECRET_only_on_priv_5c1d\n";
const PRIV_TWIN = "TOKEN='$MDU:nomodel_Read[1].TOKEN'\n";

/** `main` with a README only; `priv`, a local branch on top of it, with the
 *  real .env committed. HEAD on priv, the real .env on disk. */
function privBranch(tmp: string): { ws: string; init: string; priv: string; home: string; dir: string } {
  const ws = join(tmp, "ws");
  git(tmp, ["init", "-q", "-b", "main", ws]);
  writeFileSync(join(ws, "README"), "hi\n");
  git(ws, ["add", "."]);
  git(ws, ["commit", "-qm", "init"]);
  const init = git(ws, ["rev-parse", "HEAD"]).trim();
  git(ws, ["switch", "-q", "-c", "priv"]);
  writeFileSync(join(ws, ".env"), PRIV_REAL);
  git(ws, ["add", ".env"]);
  git(ws, ["commit", "-qm", "private config"]);
  const home = join(tmp, "home");
  return { ws, init, priv: git(ws, ["rev-parse", "HEAD"]).trim(), home, dir: placeholderCheckDir(join(home, "state", "object-walks")) };
}

/** The agent moves HEAD to main, keeping the work tree, and commits all. */
function agentCommitsOnMain(ws: string, init: string): void {
  asAgentWith(ws, ".env", PRIV_TWIN, PRIV_REAL, () => {
    git(ws, ["symbolic-ref", "HEAD", "refs/heads/main"]);
    git(ws, ["reset", "-q", "--mixed", init]);
    git(ws, ["add", "-A"]);
    git(ws, ["commit", "-qm", "agent work on main"]);
  });
}

test("BRANCH SWITCH, run as printed: the real .env only on a local branch, the launch there, the agent's commit on main: main never gets the real value (the review's repro), and priv is untouched", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-branch-"));
  try {
    const { ws, init, priv } = privBranch(tmp);
    const was = before(ws, "sk_REAL_SECRET");
    assert.deepEqual([...was.held].sort(), ["HEAD", "refs/heads/priv"], "precondition: only priv holds it");
    const watch = await preparePlaceholderWatch([{ targetPath: join(ws, ".env"), content: PRIV_TWIN }], { git: plainGit });
    assert.deepEqual(Object.keys(watch[0]!.paths[0]!).sort(), ["ids", "index", "rel"], "no commit is recorded to restore from");
    const rec = newPlaceholderRecord("s", watch);
    agentCommitsOnMain(ws, init);
    assert.match(git(ws, ["show", "main:.env"]), /\$MDU:/, "precondition: main holds the placeholder");

    const lines = (await checkPlaceholderRecord(rec, { git: plainGit })).flatMap((b) => b.lines);
    const cmds = printedCommands(lines);
    assert.deepEqual(cmds, ["git rm --cached -f -- .env", "git commit --amend --no-edit --allow-empty"], lines.join("\n"));
    assert.ok(!lines.join("\n").includes(priv.slice(0, 10)), "priv's commit is never named as a source");
    runPrinted(ws, cmds);
    assert.equal(git(ws, ["symbolic-ref", "HEAD"]).trim(), "refs/heads/main");
    assert.ok(!inGit(ws, "main:.env"), "main holds no .env at all");
    assert.equal(git(ws, ["show", "priv:.env"]), PRIV_REAL, "priv is untouched");
    assertNoLeak(ws, was, "branch switch");
    assert.equal(readFileSync(join(ws, ".env"), "utf8"), PRIV_REAL, "the file on disk is untouched");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("BRANCH SWITCH across TWO SESSIONS, with a record of each earlier build of this check (`source` = priv's commit): the user purges priv in between; the next launch's printed repair, run, puts the real value nowhere", async () => {
  for (const build of ["round-1", "round-2", "this"] as const) {
    const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-branch2-"));
    try {
      const { ws, init, priv, home, dir } = privBranch(tmp);
      // Session 1 on priv: its record (as that build wrote it), the agent's
      // commit on main, then a kill.
      const watch = await preparePlaceholderWatch([{ targetPath: join(ws, ".env"), content: PRIV_TWIN }], { git: plainGit });
      const rec = newPlaceholderRecord("first", watch);
      const extra = build === "round-1" ? { tracked: true } : build === "round-2" ? { source: priv, headPlaceholder: false } : {};
      const onDisk = { ...rec, repos: rec.repos.map((r) => ({ ...r, paths: r.paths.map((p) => ({ ...p, ...extra })) })) };
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, `${rec.at}-${rec.pid}-first.json`), JSON.stringify(onDisk));
      agentCommitsOnMain(ws, init);
      // The user purges the real version from priv (the old commit stays in
      // the object store): no ref holds it any more.
      git(ws, ["branch", "-q", "-f", "priv", init]);
      assert.ok(inGit(ws, `${priv}:.env`), "precondition: the purged commit is still in the object store");
      const was = before(ws, "sk_REAL_SECRET");
      assert.deepEqual([...was.held], [], "precondition: no ref holds the real value");

      // Session 2's launch: the killed session's block, run as printed then.
      const s2 = await launchWith(dir, home, [{ targetPath: join(ws, ".env"), content: PRIV_TWIN }]);
      const atLaunch = s2.pending.blocks.flatMap((b) => b.lines);
      const cmds = printedCommands(atLaunch);
      assert.deepEqual(cmds, ["git rm --cached -f -- .env", "git commit --amend --no-edit --allow-empty"], `${build}: ${atLaunch.join("\n")}`);
      assert.doesNotMatch(atLaunch.join("\n"), /--source|git add --/);
      runPrinted(ws, cmds);
      assert.ok(!inGit(ws, "main:.env"), `${build}: main holds no .env`);
      assertNoLeak(ws, was, `${build}: purged in between`);
      // And the second session's own check finds nothing more to say.
      assert.deepEqual((await exitOf(s2)).own, []);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }
});

test("an agent's own content committed in an earlier session: the repair takes the next placeholder out and puts nothing back, neither that content nor the real file", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-agent-"));
  try {
    const { ws } = neverTracked(tmp);
    const files = (content: string): TwinSource[] => [{ targetPath: join(ws, "local.env"), content }];
    // Session 1: the agent overwrites its copy with content of its own and
    // commits it. Not a placeholder: nothing to say.
    const w1 = await preparePlaceholderWatch(files(twinOf("11aa")), { git: plainGit });
    asAgentWith(ws, "local.env", "LOCAL_TOKEN=agent-wrote-this\n", LOCAL_REAL, () => { git(ws, ["add", "local.env"]); git(ws, ["commit", "-qm", "agent content"]); });
    assert.deepEqual(await checkPlaceholderRepo(w1[0]!, { git: plainGit }), { finding: null });
    const was = before(ws, CANARY);
    // Session 2: the agent commits the placeholder over it.
    const w2 = await preparePlaceholderWatch(files(twinOf("11aa")), { git: plainGit });
    writeFileSync(join(ws, "README.md"), "edit\n");
    asAgentWith(ws, "local.env", twinOf("11aa"), LOCAL_REAL, () => git(ws, ["commit", "-qam", "agent"]));
    const f = (await checkPlaceholderRepo(w2[0]!, { git: plainGit })).finding!;
    const cmds = repairCommands(f);
    assert.deepEqual(cmds, ["git rm --cached -f -- local.env", "git commit --amend --no-edit --allow-empty"]);
    runPrinted(ws, cmds);
    assert.ok(!inGit(ws, "HEAD:local.env"), "nothing put back");
    assertNoLeak(ws, was, "the real value");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("unborn, and a HEAD that is not: a dangling or broken branch ref (real git), a rev-parse cut off at its deadline, a ref show-ref cannot read: never `git rm --cached` for a staged file", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-head-"));
  tmpRoot = tmp;
  try {
    // Real git: a branch ref pointing at a missing commit, then an empty one.
    for (const broken of ["1234567890123456789012345678901234567890\n", ""]) {
      const { ws } = seedRepo(join(mkdtempSync(join(tmp, "r-"))));
      const watch = await preparePlaceholderWatch(sources(ws), { git: plainGit });
      asTheAgent(ws, () => git(ws, ["add", "-A"]));
      const ref = git(ws, ["symbolic-ref", "HEAD"]).trim();
      writeFileSync(join(ws, ".git", ref), broken);
      const f = (await checkPlaceholderRepo(watch[0]!, { git: plainGit })).finding!;
      assert.ok(f !== null, `found (${JSON.stringify(broken)})`);
      assert.equal(f.unborn, undefined, `a broken ref is no unborn branch (${JSON.stringify(broken)})`);
      assert.ok(!repairCommands(f).some((c) => c.startsWith("git rm")), repairCommands(f).join(" | "));
    }
    // An unborn branch, with git's answers swapped one at a time.
    const ws = join(tmp, "unborn");
    git(tmp, ["init", "-q", ws]);
    writeFileSync(join(ws, "local.env"), "LOCAL=real-local-value\n");
    const watch = await preparePlaceholderWatch([{ targetPath: join(ws, "local.env"), content: "LOCAL='$MDU:nomodel_Read[11aa].LOCAL'\n" }], { git: plainGit });
    writeFileSync(join(ws, "local.env"), "LOCAL='$MDU:nomodel_Read[11aa].LOCAL'\n");
    git(ws, ["add", "-A"]);
    writeFileSync(join(ws, "local.env"), "LOCAL=real-local-value\n");
    const swap = (cmd: string, r: { code: number; stdout: string; stderr: string }): GitRunner => async (args, opts) => args[0] === cmd ? r : plainGit(args, opts);
    const unbornOf = async (g: GitRunner): Promise<boolean | undefined> => (await checkPlaceholderRepo(watch[0]!, { git: g })).finding!.unborn;
    assert.equal(await unbornOf(plainGit), true, "a real unborn branch");
    assert.equal(plainNo({ code: 1, stdout: "", stderr: "" }), true);
    assert.equal(await unbornOf(swap("rev-parse", { code: 1, stdout: "", stderr: "killed at its 30000 ms deadline" })), undefined, "a rev-parse cut off");
    assert.equal(await unbornOf(swap("show-ref", { code: 128, stdout: "", stderr: "fatal: bad ref refs/heads/main" })), undefined, "a ref that is there, unreadable");
    assert.equal(await unbornOf(swap("show-ref", { code: 1, stdout: "", stderr: "killed at its 30000 ms deadline" })), undefined, "a show-ref cut off");
    assert.equal(await unbornOf(swap("show-ref", { code: 0, stdout: "", stderr: "" })), undefined, "the ref exists");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("the watch's calls are two and short (WATCH_GIT_TIMEOUT_MS, 5 s); the launch's pending check is short and bounded too, between records and between a record's repositories", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-short-"));
  tmpRoot = tmp;
  try {
    assert.equal(WATCH_GIT_TIMEOUT_MS, 5_000);
    const { ws } = seedRepo(tmp);
    const seen: Array<[string, number | undefined]> = [];
    const spy = (over?: (args: string[]) => { code: number; stdout: string; stderr: string } | null): GitRunner => async (args, opts) => {
      seen.push([args[0]!, opts.timeoutMs]);
      return over?.(args) ?? plainGit(args, opts);
    };
    const envOnly: TwinSource[] = [{ targetPath: join(ws, ".env"), content: TWIN_ENV }];
    assert.equal((await preparePlaceholderWatch(envOnly, { git: spy() })).length, 1);
    assert.deepEqual(seen.map(([c]) => c).sort(), ["ls-files", "rev-list"], "two calls, nothing read of any commit's content");
    assert.ok(seen.every(([, t]) => t !== undefined && t <= WATCH_GIT_TIMEOUT_MS), JSON.stringify(seen));
    const killed = { code: 1, stdout: "", stderr: "killed at its 5000 ms deadline" };
    const tipsCut = await preparePlaceholderWatch(envOnly, { git: spy((a) => a[0] === "rev-list" ? killed : null) });
    assert.equal(tipsCut[0]!.tips, null, "tips cut off: unknown (only the index is checked)");

    // The launch's check of earlier records: each call (the walk too) as
    // short as asked, and no record started once the budget is gone.
    const home = join(tmp, "home");
    const dir = placeholderCheckDir(join(home, "state", "object-walks"));
    const watch = await preparePlaceholderWatch(sources(ws), { git: plainGit });
    for (const [i, scope] of ["a", "b", "c"].entries()) writePlaceholderRecord(dir, home, { ...newPlaceholderRecord(scope, watch), at: 1000 + i });
    writeFileSync(join(ws, "README.md"), "edit\n");
    asTheAgent(ws, () => git(ws, ["commit", "-qam", "crashed"]));
    seen.length = 0;
    let clock = 0;
    const first = await checkPendingPlaceholderRecords(dir, home, {
      git: spy(), live: () => false, timeoutMs: WATCH_GIT_TIMEOUT_MS, budgetMs: 15_000, now: () => (clock += 20_000),
    });
    assert.ok(seen.length > 0 && seen.every(([, t]) => t === WATCH_GIT_TIMEOUT_MS), JSON.stringify(seen));
    assert.deepEqual(first.records.map((r) => r.scopeId), ["a"], "over the budget after the first: the rest wait");
    assert.deepEqual(first.kept, [], "the first was checked in full: removed");
    assert.equal(readdirSync(dir).length, 2, "left on disk for the next launch");
    const rest = await checkPendingPlaceholderRecords(dir, home, { git: plainGit, live: () => false });
    assert.deepEqual(rest.records.map((r) => r.scopeId), ["b", "c"]);
    assert.deepEqual(readdirSync(dir), []);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("a pending record whose check at launch does not complete (a call cut off; the budget spent between its repositories) stays on disk, is checked in full after the agent, then removed: a launch killed in turn loses nothing", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-kept-"));
  tmpRoot = tmp;
  try {
    // Three repositories, each with the crashed session's commit.
    const roots: string[] = [];
    const files: TwinSource[] = [];
    for (const n of ["r1", "r2", "r3"]) {
      const { ws } = seedRepo(join(mkdtempSync(join(tmp, `${n}-`))));
      roots.push(ws);
      files.push({ targetPath: join(ws, ".env"), content: TWIN_ENV });
    }
    const watch = await preparePlaceholderWatch(files, { git: plainGit });
    assert.equal(watch.length, 3);
    const home = join(tmp, "home");
    const dir = placeholderCheckDir(join(home, "state", "object-walks"));
    const file = writePlaceholderRecord(dir, home, newPlaceholderRecord("crashed", watch))!;
    for (const ws of roots) {
      writeFileSync(join(ws, "README.md"), "edit\n");
      asTheAgent(ws, () => git(ws, ["commit", "-qam", "crashed"]));
    }

    // (1) A walk cut off at its deadline: what the index and HEAD still
    // show is said, with the cut named (never read as "no commit"), and the
    // record is kept.
    const killed = { code: 1, stdout: "", stderr: "killed at its 5000 ms deadline" };
    const cut: GitRunner = async (args, opts) => args[0] === "log" ? killed : plainGit(args, opts);
    const p1 = await checkPendingPlaceholderRecords(dir, home, { git: cut, live: () => false, timeoutMs: WATCH_GIT_TIMEOUT_MS });
    assert.equal(p1.blocks.length, 3);
    assert.ok(p1.blocks.every((b) => /Not fully checked: git log failed: killed at its 5000 ms deadline/.test(b.lines.join("\n"))), p1.blocks.map((b) => b.lines.join("\n")).join("\n"));
    assert.ok(p1.blocks.every((b) => !/git commit --amend/.test(b.lines.join("\n"))), "the commits unknown: no amend");
    assert.deepEqual(p1.kept, [file], "not complete: kept for the second check");
    assert.ok(existsSync(file), "still on disk: a launch killed now loses nothing");
    // This launch killed too: the next launch finds the same record.
    const p2 = await checkPendingPlaceholderRecords(dir, home, { git: plainGit, live: () => false, timeoutMs: WATCH_GIT_TIMEOUT_MS });
    assert.equal(p2.blocks.length, 3);
    for (const b of p2.blocks) assert.deepEqual(printedCommands(b.lines), ["git rm --cached -f -- .env", "git commit --amend --no-edit --allow-empty"], b.lines.join("\n"));
    assert.deepEqual(p2.kept, [], "complete this time: removed");
    assert.equal(existsSync(file), false);

    // (2) The budget spent after the first repository: the others are not
    // started at launch, the record is kept, the check after the agent says
    // all three, and run.ts then removes it.
    const file2 = writePlaceholderRecord(dir, home, newPlaceholderRecord("crashed-2", watch))!;
    let clock = 0;
    const p3 = await checkPendingPlaceholderRecords(dir, home, {
      git: plainGit, live: () => false, timeoutMs: WATCH_GIT_TIMEOUT_MS, budgetMs: 15_000, now: () => (clock += 20_000),
    });
    assert.equal(p3.blocks.length, 1, "only the first repository at launch");
    assert.deepEqual(p3.kept, [file2]);
    const after = await recheckEarlierRecords(p3.records, { git: plainGit });
    assert.deepEqual(after.map((b) => b.root).sort(), [...roots].sort(), "all three after the agent");
    assert.ok(after.every((b) => /checked again now:$/.test(b.lines[0]!)));
    for (const f of p3.kept) removePlaceholderRecord(f, home);
    assert.deepEqual(readdirSync(dir), []);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("the records' folder is made one level at a time, each level checked first: never made through a link, nor outside the home", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-ph-mkdir-"));
  try {
    const home = join(tmp, "home");
    const dir = placeholderCheckDir(join(home, "state", "object-walks"));
    assert.equal(ensureRecordDir(dir, home), true, "a fresh home: made");
    for (const d of [join(home, "state"), join(home, "state", "object-walks"), dir]) {
      assert.equal(statSync(d).mode & 0o777, 0o700, `${d} 0700`);
    }
    assert.equal(ensureRecordDir(join(tmp, "elsewhere", "x"), home), false, "outside the home");
    assert.equal(ensureRecordDir(home, home), false);
    // `state` swapped for a link, to a folder inside the home or out of it.
    for (const target of [join(tmp, "out"), join(home, "inside")]) {
      rmSync(join(home, "state"), { recursive: true, force: true });
      mkdirSync(target, { recursive: true });
      symlinkSync(target, join(home, "state"));
      assert.equal(ensureRecordDir(dir, home), false);
      assert.deepEqual(readdirSync(target), [], `nothing made through the link to ${target}`);
      rmSync(join(home, "state"));
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("unsaidBlocks (pure): a block is dropped only when it says the very same for the same work tree", () => {
  const blk = (root: string, body: string[], head = "h"): CheckBlock => ({ root, body, lines: [head, ...body] });
  const own = [blk("/w", ["WARNING x", "    git rm --cached -f -- a"], "")];
  const earlier = [
    blk("/w", ["WARNING x", "    git rm --cached -f -- a"]),
    blk("/w", ["WARNING y", "    git restore --staged -- a"]),
    blk("/v", ["WARNING x", "    git rm --cached -f -- a"]),
    blk("/w", ["WARNING y", "    git restore --staged -- a"], "h2"),
  ];
  assert.deepEqual(unsaidBlocks(own, earlier).map((b) => [b.root, b.body[0]]), [["/w", "WARNING y"], ["/v", "WARNING x"]]);
});
