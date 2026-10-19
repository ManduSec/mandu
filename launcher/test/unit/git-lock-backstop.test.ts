/**
 * git-lock-backstop — the launcher's half of the guard's backstop for locked
 * git objects (confidentiality-plan-14-policy-suggestions.md §11.1 R4): the
 * locked set handed to the guard, and the notice the person reads when the
 * guard refused a repository.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  EMPTY_BLOB_IDS, GIT_LOCK_NOTICE_NAME, NOTICE_MAX, agentGitStoreOf, gitLockNoticeFile, gitLockNoticeLines, gitLocksField, lockedIdsOf, parseGitLockNotice, readGitLockNotice,
  registerRefusedRepositories,
} from "../../src/git-lock-backstop.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const A = `sha1:${"a".repeat(40)}`;
const B = `sha1:${"b".repeat(40)}`;
const S = `sha256:${"c".repeat(64)}`;

test("the locked set: blob locks above public, the resolved ids and the global set; well-formed, sorted, once", () => {
  assert.deepEqual(lockedIdsOf({
    blobs: [{ id: B, level: "no-model" }, { id: `sha1:${"d".repeat(40)}`, level: "public" }, { id: "sha1:nope", level: "no-model" }],
    resolved: [A, B],
    lockedSet: { sha1: [], sha256: [S.slice("sha256:".length), "E".repeat(64), "f".repeat(63)] },
  }), [A, B, S]);
  assert.deepEqual(lockedIdsOf({}), []);
});

test("the empty blob is never locked: a protected file once empty must not lock every repository with an empty file", () => {
  assert.deepEqual(lockedIdsOf({ resolved: [...EMPTY_BLOB_IDS, A], blobs: [{ id: "sha1:e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", level: "no-model" }] }), [A]);
});

test("the policy field: absent with no lock (the guard checks nothing), else the ids and the notice file in the scope dir", () => {
  assert.deepEqual(gitLocksField([], "/run/scope"), {});
  assert.deepEqual(gitLocksField([A, S], "/run/scope"), { gitLocks: { ids: [A, S], noticeFile: `/run/scope/${GIT_LOCK_NOTICE_NAME}` } });
  assert.equal(gitLockNoticeFile("/run/scope"), "/run/scope/git-lock-refusals");
});

test("the notice file is read defensively: absolute repositories, once each, no control characters, capped", () => {
  const text = [
    "/w/a\tits git history holds an object you locked",
    "/w/a\tagain",
    "relative/path\tx",
    "/w/\u001b[31mb\u0007\tforged \u001b]0;title\u0007",
    "",
    "/w/c",
  ].join("\n");
  assert.deepEqual(parseGitLockNotice(text), [
    { repo: "/w/a", why: "its git history holds an object you locked" },
    { repo: "/w/ [31mb", why: "forged  ]0;title" },
    { repo: "/w/c", why: "" },
  ]);
  const many = Array.from({ length: 50 }, (_, i) => `/r/${i}\tx`).join("\n");
  assert.equal(parseGitLockNotice(many).length, NOTICE_MAX);
});

test("the notice names each repository and the two fixes; an undecidable file says why", () => {
  assert.deepEqual(gitLockNoticeLines([]), []);
  const one = gitLockNoticeLines([{ repo: "/w/a", why: "its git history holds an object you locked, and this launch has no sanitized copy of that repository" }]);
  assert.match(one[0]!, /^mandu: git was refused in this repository for the session: its history holds a key you locked/);
  assert.equal(one[1], "  /w/a");
  assert.match(one[2]!, /start mandu in it .*mandu policy suggest --root <repository>/);
  const two = gitLockNoticeLines([{ repo: "/w/a", why: "x" }, { repo: "/w/b", why: "a lock is in force and whether this file holds a locked object could not be told (its pack has no index)" }]);
  assert.match(two[0]!, /in these 2 repositories .* their history/);
  assert.equal(two[2], "  /w/b (a lock is in force and whether this file holds a locked object could not be told (its pack has no index))");
});

test("agentGitStoreOf: OpenCode's snapshot store under XDG_DATA_HOME or ~/.local/share (or the shape anywhere); every other repository is the person's", () => {
  const env = { HOME: "/home/u" };
  assert.equal(agentGitStoreOf("/home/u/.local/share/opencode/snapshot/global/0123abcd", env), "opencode");
  assert.equal(agentGitStoreOf("/home/u/.local/share/opencode/snapshot", env), "opencode");
  assert.equal(agentGitStoreOf("/data/xdg/opencode/snapshot/p1", { HOME: "/home/u", XDG_DATA_HOME: "/data/xdg" }), "opencode");
  assert.equal(agentGitStoreOf("/other/home/.local/share/opencode/snapshot/p1", {}), "opencode", "the shape, whatever the home");
  for (const repo of ["/home/u/src/app", "/home/u/.local/share/opencode", "/home/u/.local/share/opencode/snapshots-old", "/home/u/src/opencode/snapshot", "/data/xdg/opencode/snapshot"]) {
    assert.equal(agentGitStoreOf(repo, env), null, repo);
  }
  // A relative XDG_DATA_HOME is not a data home (the default applies).
  assert.equal(agentGitStoreOf("/home/u/.local/share/opencode/snapshot/p", { HOME: "/home/u", XDG_DATA_HOME: "rel" }), "opencode");
});

test("the exit notice for OpenCode's own snapshot store says what it is and that nothing needs doing, never \"start mandu in it\"", () => {
  const env = { HOME: "/home/u" };
  const store = { repo: "/home/u/.local/share/opencode/snapshot/global/0123abcd", why: "its git history holds an object you locked, and this launch has no sanitized copy of that repository" };
  const only = gitLockNoticeLines([store], env);
  assert.match(only[0]!, /^mandu: OpenCode's own snapshot history \(the copy of your files it keeps for undo\) holds a file you marked secret, so Mandu kept OpenCode from reading it in this session/);
  assert.equal(only[1], "  ~/.local/share/opencode/snapshot/global/0123abcd");
  assert.match(only[2]!, /Nothing needs doing: it is OpenCode's own store, not one of your repositories/);
  // What really happens (tests/sandbox/git-history-locks.test.ts K15): nothing
  // prepares a copy of the store, so it comes back; and how to stop it.
  assert.match(only[2]!, /this notice comes back in each session where OpenCode reads it \(Mandu prepares no copy of OpenCode's store\)/);
  // A packed store's pack holds every file's older version, so its new
  // snapshots fail too (K15b).
  assert.match(only[2]!, /undo and cleanup of that older history fail \(once OpenCode has packed that history, its new snapshots too\)/);
  assert.match(only[2]!, /To stop it, remove that folder outside Mandu: OpenCode starts a new history and loses only the undo of earlier changes\.$/);
  assert.doesNotMatch(only.join("\n"), /next launch/);
  assert.equal(only.length, 3);
  for (const l of only) assert.doesNotMatch(l, /git was refused|start mandu in it|policy suggest/);
  // Beside a repository of the person's: each gets its own lines, the repository its fixes.
  const both = gitLockNoticeLines([store, { repo: "/w/a", why: "x" }], env);
  assert.match(both[0]!, /^mandu: git was refused in this repository for the session/);
  assert.equal(both[1], "  /w/a");
  assert.match(both[2]!, /start mandu in it/);
  assert.match(both[3]!, /^mandu: OpenCode's own snapshot history/);
  assert.equal(both.length, 6);
  // Without env, the shape alone is read.
  assert.match(gitLockNoticeLines([store])[0]!, /^mandu: OpenCode's own snapshot history/);
});

test("each refused repository is registered with the arbiter (registerRepository {root}); a refusal or an older arbiter changes nothing", async () => {
  const calls: Array<[string, Record<string, unknown>]> = [];
  const added = await registerRefusedRepositories([{ repo: "/w/a", why: "" }, { repo: "/w/bare.git", why: "" }, { repo: "/w/known", why: "" }], async (op, args) => {
    calls.push([op, args]);
    if (args["root"] === "/w/bare.git") throw new Error("registerRepository: /w/bare.git is not a git work tree");
    return { axis: true, root: args["root"], added: args["root"] === "/w/a", known: 2 };
  });
  assert.deepEqual(calls.map(([op, a]) => [op, a["root"]]), [["registerRepository", "/w/a"], ["registerRepository", "/w/bare.git"], ["registerRepository", "/w/known"]]);
  assert.deepEqual(added, ["/w/a"]);
  assert.deepEqual(await registerRefusedRepositories([{ repo: "/w/a", why: "" }], async () => { throw new Error("unknown op: registerRepository"); }), []);
  assert.deepEqual(await registerRefusedRepositories([], async () => { throw new Error("never called"); }), []);
});

test("readGitLockNotice: an absent file prints nothing; a written one prints its notice", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-git-lock-notice-"));
  try {
    const f = gitLockNoticeFile(dir);
    assert.deepEqual(readGitLockNotice(f), []);
    writeFileSync(f, "/w/a\twhy\n");
    const lines = readGitLockNotice(f);
    assert.equal(lines.length, 3);
    assert.equal(lines[1], "  /w/a");
    // A symlink planted in the scope dir is not followed.
    const other = join(dir, "other");
    writeFileSync(other, "/etc/secretish\tx\n");
    rmSync(f);
    symlinkSync(other, f);
    assert.deepEqual(readGitLockNotice(f), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
