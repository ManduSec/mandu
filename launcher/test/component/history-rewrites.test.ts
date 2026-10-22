/**
 * What the history walk does not let a repository hide (security fix
 * 2026-10-21; confidentiality.md §7.2a "What the walk does not let a
 * repository hide"; hardened-git.ts, history-labels.ts walkShallowRule),
 * end to end with real git:
 *
 * a graft (`info/grafts`), a replace ref (`refs/replace/*`) or a shallow
 * file (`shallow`) written into a repository, as an agent in a confined
 * session can, cut commits out of `git log` while their objects stay in the
 * store. The next launch's walk then missed the protected versions only
 * those commits hold, and `git show <commit>:<file>` still read them. Now,
 * for each of the three:
 *
 *   - every protected version is in the step's locked set, and in the
 *     agent's world (the twins applied to a copy of the repository) git
 *     cannot read it, whatever rewrite options it is run with;
 *   - a protected version reachable ONLY through a replace ref's target is
 *     locked too (a replace ref is a ref: its target is walked);
 *   - a real `git clone --depth 1` still launches (its true boundary is
 *     honoured), and a forged entry beside a true boundary refuses the
 *     step (fail-closed);
 *   - the placeholder check after the agent exits finds a placeholder
 *     commit a shallow file written in the session would have hidden;
 *   - the walk's base key is never one the earlier rule computed (a cached
 *     walk of the old rule is never used).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultGitRunner, GitObjectTwinError, idxObjectNames, prepareGitObjectTwins, type GitObjectTwinResult, type GitRunner } from "../../src/git-object-twins.js";
import { isHistoryRecheckNotice } from "../../src/cache-seals.js";
import { HISTORY_WALK_ARGS, walkBaseKey } from "../../src/history-labels.js";
import { checkPlaceholderRepo, preparePlaceholderWatch } from "../../src/placeholder-commits.js";
import { stateAxes } from "../axes.js";
import { memorySeals } from "../lib/memory-seals.js";

stateAxes("secrets"); // the confidentiality axis is what the object twins serve

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, args: string[], input?: string): string =>
  execFileSync("git", args, { cwd, encoding: "utf8", env: ENV, ...(input !== undefined ? { input } : {}) });
/** A key-shaped canary assembled at run time (no key literal in the file). */
const key = (v: number): string => ["REWRITE", "CANARY", String(v), "Qz".repeat(14)].join("_");
const body = (v: number): string => `TOKEN=${key(v)}\n`;
const blobOf = (cwd: string, text: string): string => git(cwd, ["hash-object", "--stdin"], text).trim();

interface Repo { tmp: string; ws: string; c: string[]; v: string[]; denyFile: string; opts: { cacheDir: string; denyFile: string; walkCacheDir: string } }

/** Three commits of `.env` (versions 1 and 2 only in the history), packed,
 *  the reflogs expired: commit 3's parents are the only way to 1 and 2. */
function repo(): Repo {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rewrites-"));
  const ws = join(tmp, "ws");
  git(tmp, ["init", "-q", "-b", "main", ws]);
  writeFileSync(join(ws, "README"), "readme\n");
  const c: string[] = [];
  for (const v of [1, 2, 3]) {
    writeFileSync(join(ws, ".env"), body(v));
    git(ws, ["add", "."]);
    git(ws, ["commit", "-qm", `v${v}`]);
    c.push(git(ws, ["rev-parse", "HEAD"]).trim());
  }
  git(ws, ["reflog", "expire", "--expire=now", "--all"]);
  git(ws, ["repack", "-adq"]);
  const denyFile = join(tmp, "denied");
  writeFileSync(denyFile, "");
  chmodSync(denyFile, 0o000);
  return {
    tmp, ws, c, v: [1, 2, 3].map((n) => blobOf(ws, body(n))), denyFile,
    opts: { cacheDir: join(tmp, "cache"), denyFile, walkCacheDir: join(tmp, "walks") },
  };
}

const step = (r: Repo): Promise<GitObjectTwinResult> => prepareGitObjectTwins([join(r.ws, ".env")], { ...r.opts, seals: memorySeals() });

/** The agent's world over `r` (the twins as the wrap applies them, on a
 *  copy): a sanitized pack served in place of the real one, a denied file
 *  gone. Every rewrite the agent wrote is removed and switched off too, so
 *  its git reads the objects as they are. */
function agentView(r: Repo, got: GitObjectTwinResult): string {
  const view = join(r.tmp, `view-${Math.random().toString(36).slice(2)}`);
  cpSync(r.ws, view, { recursive: true });
  for (const t of got.twins) {
    if (!t.targetPath.startsWith(`${r.ws}/`)) continue;
    const at = join(view, t.targetPath.slice(r.ws.length + 1));
    rmSync(at, { force: true }); // git's object files are read-only
    if (t.kind === "object") copyFileSync(t.twinPath, at);
  }
  rmSync(join(view, ".git", "info", "grafts"), { force: true });
  rmSync(join(view, ".git", "shallow"), { force: true });
  return view;
}

/** `git show <commit>:.env` in the agent's world, replace refs and grafts
 *  off: null when git cannot read it. */
function agentShows(view: string, commit: string): string | null {
  const r = spawnSync("git", ["--no-replace-objects", "show", `${commit}:.env`], { cwd: view, encoding: "utf8", env: { ...ENV, GIT_GRAFT_FILE: "/dev/null" } });
  return r.status === 0 ? r.stdout : null;
}

/** Every version locked, and unreadable to the agent from any commit. */
function assertAllHidden(r: Repo, got: GitObjectTwinResult, what: string): void {
  for (const [i, v] of r.v.entries()) assert.ok(got.lockedIds!.includes(`sha1:${v}`), `${what}: version ${i + 1} locked`);
  const served = got.twins.filter((x) => x.kind === "object" && x.targetPath.endsWith(".idx")).flatMap((x) => idxObjectNames(readFileSync(x.twinPath)));
  for (const v of r.v) assert.ok(!served.includes(v), `${what}: no served pack holds a version`);
  const view = agentView(r, got);
  for (const [i, c] of r.c.entries()) assert.equal(agentShows(view, c), null, `${what}: git show of commit ${i + 1}'s .env fails in the agent's world`);
  // The control: the same world reads every other object (the view is a
  // working repository, so the failures above are the twins').
  const readme = spawnSync("git", ["--no-replace-objects", "show", `${r.c[0]}:README`], { cwd: view, encoding: "utf8", env: ENV });
  assert.equal(readme.stdout, "readme\n", `${what}: the agent's world still reads the rest (${readme.stderr})`);
}

test("a graft written into the repository hides no protected version", async () => {
  const r = repo();
  try {
    mkdirSync(join(r.ws, ".git", "info"), { recursive: true });
    writeFileSync(join(r.ws, ".git", "info", "grafts"), `${r.c[2]}\n`); // commit 3 parentless
    assert.equal(git(r.ws, ["log", "--format=%s"]).trim(), "v3", "git log sees one commit");
    assertAllHidden(r, await step(r), "graft");
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("a replace ref written into the repository hides no protected version; one reachable only through its target is locked", async () => {
  const r = repo();
  try {
    // Commit 3 replaced by a parentless commit whose tree holds version 4,
    // which nothing else holds.
    const v4 = git(r.ws, ["hash-object", "-w", "--stdin"], body(4)).trim();
    const readme = git(r.ws, ["rev-parse", `${r.c[2]}:README`]).trim();
    const tree = git(r.ws, ["mktree"], `100644 blob ${v4}\t.env\n100644 blob ${readme}\tREADME\n`).trim();
    const lone = git(r.ws, ["commit-tree", tree, "-m", "replacement"]).trim();
    git(r.ws, ["replace", r.c[2]!, lone]);
    git(r.ws, ["repack", "-adq"]);
    assert.equal(git(r.ws, ["log", "--format=%s"]).trim(), "replacement", "git log sees the replacement alone");
    const got = await step(r);
    assertAllHidden(r, got, "replace ref");
    assert.ok(got.lockedIds!.includes(`sha1:${v4}`), "the version only the replacement holds is locked");
    assert.equal(agentShows(agentView(r, got), lone), null, "and unreadable through it");
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("a shallow file written into a full history hides no protected version", async () => {
  const r = repo();
  try {
    writeFileSync(join(r.ws, ".git", "shallow"), `${r.c[2]}\n`);
    assert.equal(git(r.ws, ["log", "--format=%s"]).trim(), "v3", "git log stops at the forged boundary");
    assertAllHidden(r, await step(r), "shallow file");
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("a real shallow clone still launches (its true boundary honoured); a forged entry beside it refuses the step", async () => {
  const r = repo();
  try {
    const sc = join(r.tmp, "sc");
    git(r.tmp, ["clone", "-q", "--depth", "2", `file://${r.ws}`, sc]);
    const got = await prepareGitObjectTwins([join(sc, ".env")], { ...r.opts, seals: memorySeals() });
    for (const n of [2, 3]) assert.ok(got.lockedIds!.includes(`sha1:${r.v[n - 1]}`), `the clone's version ${n} locked`);
    // A forged entry (its parent is in the store) beside the true one: the
    // shallow file is ignored, the walk meets the missing parent, and the
    // step refuses rather than walk less.
    writeFileSync(join(sc, ".git", "shallow"), `${readFileSync(join(sc, ".git", "shallow"), "utf8")}${r.c[2]}\n`);
    const refused = await prepareGitObjectTwins([join(sc, ".env")], { ...r.opts, seals: memorySeals() }).then(() => null, (e: unknown) => e);
    assert.ok(refused instanceof GitObjectTwinError, `refused: ${String(refused)}`);
    assert.match(refused.message, /\.git\/shallow file names a commit whose parent IS in the repository/, "the refusal says what it is");
    assert.match(refused.message, /git fetch --unshallow/, "and how to fix it");
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("a graft over history the repository does not have refuses the step, saying what it is and how to fix it; the fix it names launches", async () => {
  const r = repo();
  try {
    // A partial copy made the deprecated way: a depth-1 clone whose cut is
    // a graft, not a shallow file.
    const gc = join(r.tmp, "gc");
    git(r.tmp, ["clone", "-q", "--depth", "1", `file://${r.ws}`, gc]);
    const cut = readFileSync(join(gc, ".git", "shallow"), "utf8");
    rmSync(join(gc, ".git", "shallow"));
    writeFileSync(join(gc, ".git", "info", "grafts"), cut);
    const refused = await prepareGitObjectTwins([join(gc, ".env")], { ...r.opts, seals: memorySeals() }).then(() => null, (e: unknown) => e);
    assert.ok(refused instanceof GitObjectTwinError, `refused: ${String(refused)}`);
    assert.match(refused.message, /\.git\/info\/grafts file \(a git feature git has deprecated\)/, "the refusal says what it is");
    assert.match(refused.message, /cut -d' ' -f1 \.git\/info\/grafts >> \.git\/shallow && rm \.git\/info\/grafts/, "and how to fix it");
    // The fix, as printed: the cut becomes a true shallow boundary.
    execFileSync("sh", ["-c", "cut -d' ' -f1 .git/info/grafts >> .git/shallow && rm .git/info/grafts"], { cwd: gc });
    const fixed = await prepareGitObjectTwins([join(gc, ".env")], { ...r.opts, seals: memorySeals() });
    assert.ok(fixed.lockedIds!.includes(`sha1:${r.v[2]}`), "it launches, its version locked");
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("the placeholder check after the session: a shallow file written in it does not hide a placeholder commit", async () => {
  const r = repo();
  try {
    const placeholder = "TOKEN=$MDU:nomodel_File[0].TOKEN\n";
    const [watched] = await preparePlaceholderWatch([{ targetPath: join(r.ws, ".env"), content: placeholder }]);
    assert.ok(watched !== undefined && watched.tips !== null);
    // In the session: the placeholder committed, the file put back in a
    // commit on top, and a shallow file that cuts the walk below that
    // commit (whose own tree holds no placeholder).
    writeFileSync(join(r.ws, ".env"), placeholder);
    git(r.ws, ["commit", "-qam", "placeholder"]);
    const p = git(r.ws, ["rev-parse", "HEAD"]).trim();
    writeFileSync(join(r.ws, ".env"), body(3));
    git(r.ws, ["commit", "-qam", "put back"]);
    writeFileSync(join(r.ws, ".git", "shallow"), `${git(r.ws, ["rev-parse", "HEAD"]).trim()}\n`);
    const c = await checkPlaceholderRepo(watched);
    assert.ok(c.finding !== null && c.finding.commits.some((x) => x.sha === p), `the placeholder commit is found: ${JSON.stringify(c)}`);
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("a cached walk kept under another base key (a new git, a new walk rule) is walked anew with the one re-check notice; an unchanged one is not", async () => {
  const r = repo();
  try {
    const seals = memorySeals();
    // A runner whose `git version` the test chooses (its base key part).
    const withVersion = (v: string): GitRunner => (args, o) =>
      args[0] === "version" ? Promise.resolve({ code: 0, stdout: `git version ${v}\n`, stderr: "" }) : defaultGitRunner(args, o);
    const run = async (v: string): Promise<{ got: GitObjectTwinResult; said: string[] }> => {
      const said: string[] = [];
      const got = await prepareGitObjectTwins([join(r.ws, ".env")], { ...r.opts, seals, git: withVersion(v), log: (m) => said.push(m) });
      return { got, said: said.filter(isHistoryRecheckNotice) };
    };
    assert.deepEqual((await run("2.53.0")).said, [], "the first walk: nothing cached, nothing to say");
    const same = await run("2.53.0");
    assert.deepEqual(same.got.walks, { hit: 1, incremental: 0, full: 0 });
    assert.deepEqual(same.said, [], "an unchanged base: a hit, no notice");
    const moved = await run("2.99.0");
    assert.deepEqual(moved.got.walks, { hit: 0, incremental: 0, full: 1 }, "another base: the whole history walked");
    assert.equal(moved.said.length, 1, "said once");
    assert.match(moved.said[0]!, /how Mandu reads git history changed since the last launch.*re-checking the git history of 1 repository \(slower this once\)$/);
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("the walk's base key is never one the earlier rule computed (its cached walks are not used)", () => {
  const old = (p: { gitVersion: string; shallow: string; grafts: string; replaceRefs: string }): string =>
    createHash("sha256").update(JSON.stringify([HISTORY_WALK_ARGS, p.gitVersion.trim(), p.shallow, p.grafts, p.replaceRefs])).digest("hex");
  for (const shallow of ["", "a".repeat(40)]) {
    assert.notEqual(walkBaseKey({ gitVersion: "git version 2.53.0", shallow }), old({ gitVersion: "git version 2.53.0", shallow, grafts: "", replaceRefs: "" }));
  }
});
