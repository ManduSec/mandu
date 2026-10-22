/**
 * Every stored object is checked once (store-scan.ts; a security fix,
 * 2026-10-21; confidentiality.md §7.2a "Every stored object is checked
 * once"), end to end through the launch's history step
 * (prepareGitObjectTwins, the production git session) with real git.
 *
 * Before it, a protected file's version that NO launch ever found
 * protected stayed readable by object id through the object twins. For each
 * way that happens, the version is now in the step's locked set, no
 * sanitized pack holds it, and in the agent's world (the twins applied to a
 * copy of the repository, as the wrap applies them) `git cat-file -p <id>`
 * fails, while the rest of the repository reads as before:
 *
 *   - history cut before Mandu first walked the repository: an orphan
 *     branch, the old branch deleted, the reflogs expired, the old commits
 *     kept in a pack (`repack -k`) and loose;
 *   - a tree in no ref (`git write-tree` of an index holding a version);
 *   - a blob written by plumbing (`git hash-object -w`), in no tree, no
 *     index, no working copy: an older `.env` sharing a credential with the
 *     current one (a blob sharing nothing stays readable);
 *
 * and a second launch with nothing new asks git nothing and reads no object.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { idxObjectNames, prepareGitObjectTwins, type GitObjectTwinResult } from "../../src/git-object-twins.js";
import { stateAxes } from "../axes.js";
import { memorySeals, type MemorySeals } from "../lib/memory-seals.js";

stateAxes("secrets"); // the confidentiality axis is what the object twins serve

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, args: string[], input?: string, env: Record<string, string> = {}): string =>
  execFileSync("git", args, { cwd, encoding: "utf8", env: { ...ENV, ...env }, ...(input !== undefined ? { input } : {}) });
/** A key-shaped canary assembled at run time (no key literal in the file). */
const key = (v: number): string => ["STORE", "SCAN", "CANARY", String(v), "Qz".repeat(14)].join("_");

interface Repo { tmp: string; ws: string; seals: MemorySeals; opts: { cacheDir: string; denyFile: string; walkCacheDir: string } }

function repo(): Repo {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-store-scan-"));
  const ws = join(tmp, "ws");
  git(tmp, ["init", "-q", "-b", "main", ws]);
  writeFileSync(join(ws, "README"), "readme\n");
  const denyFile = join(tmp, "denied");
  writeFileSync(denyFile, "");
  chmodSync(denyFile, 0o000);
  return { tmp, ws, seals: memorySeals(), opts: { cacheDir: join(tmp, "cache"), denyFile, walkCacheDir: join(tmp, "walks") } };
}
const commit = (r: Repo, text: string, msg: string): string => {
  writeFileSync(join(r.ws, ".env"), text);
  git(r.ws, ["add", "-A"]);
  git(r.ws, ["commit", "-qm", msg]);
  return git(r.ws, ["rev-parse", "HEAD"]).trim();
};
const blobOf = (r: Repo, text: string): string => git(r.ws, ["hash-object", "--stdin"], text).trim();
const launch = (r: Repo): Promise<GitObjectTwinResult> => prepareGitObjectTwins([join(r.ws, ".env")], { ...r.opts, seals: r.seals });

/** The agent's world over `r`: the twins applied to a copy (a sanitized
 *  pack in place of the real one, a denied file gone), as the wrap does. */
function agentView(r: Repo, got: GitObjectTwinResult): string {
  const view = join(r.tmp, `view-${Math.random().toString(36).slice(2)}`);
  cpSync(r.ws, view, { recursive: true });
  for (const t of got.twins) {
    if (!t.targetPath.startsWith(`${r.ws}/`)) continue;
    const at = join(view, t.targetPath.slice(r.ws.length + 1));
    rmSync(at, { force: true });
    if (t.kind === "object") copyFileSync(t.twinPath, at);
  }
  return view;
}
/** `git cat-file -p <id>` in the agent's world: null when git cannot read it. */
const agentReads = (view: string, id: string): string | null => {
  const x = spawnSync("git", ["cat-file", "-p", id], { cwd: view, encoding: "utf8", env: ENV });
  return x.status === 0 ? x.stdout : null;
};

/** `ids` locked, in no served pack, unreadable by id in the agent's world;
 *  README read as before. */
function assertHidden(r: Repo, got: GitObjectTwinResult, ids: readonly string[], what: string): void {
  const served = got.twins.filter((x) => x.kind === "object" && x.targetPath.endsWith(".idx")).flatMap((x) => idxObjectNames(readFileSync(x.twinPath)));
  const view = agentView(r, got);
  for (const id of ids) {
    assert.ok(got.lockedIds!.includes(`sha1:${id}`), `${what}: ${id} locked`);
    assert.ok(!served.includes(id), `${what}: no served pack holds ${id}`);
    assert.notEqual(agentReads(r.ws, id), null, `${what}: the real repository holds ${id} (the control)`);
    assert.equal(agentReads(view, id), null, `${what}: git cat-file -p ${id} fails in the agent's world`);
  }
  assert.equal(agentReads(view, "HEAD:README"), "readme\n", `${what}: the agent's world reads the rest`);
}

test("history cut before the first walk (an orphan branch, the reflogs expired): every old version is hidden, packed or loose", async () => {
  const r = repo();
  try {
    const v = [1, 2, 3].map((n) => `TOKEN=${key(n)}\n`);
    commit(r, v[0]!, "v1");
    commit(r, v[1]!, "v2");
    git(r.ws, ["checkout", "-q", "--orphan", "fresh"]);
    commit(r, "TOKEN=$MDU:nomodel_File[0].TOKEN\n", "fresh");
    git(r.ws, ["branch", "-D", "main"]);
    git(r.ws, ["reflog", "expire", "--expire=now", "--all"]);
    // Versions 1 and 2 kept in a pack that holds the unreachable too.
    git(r.ws, ["repack", "-adkq"]);
    // Version 3: committed and cut the same way, left loose.
    git(r.ws, ["checkout", "-q", "-b", "side"]);
    commit(r, v[2]!, "v3");
    git(r.ws, ["checkout", "-q", "fresh"]);
    git(r.ws, ["branch", "-D", "side"]);
    git(r.ws, ["reflog", "expire", "--expire=now", "--all"]);
    assert.equal(git(r.ws, ["log", "--all", "--format=%s"]).trim(), "fresh", "nothing reaches the old commits");
    const got = await launch(r);
    assert.equal(got.scans!.first, 1, "the store's first scan");
    assertHidden(r, got, v.map((t) => blobOf(r, t)), "a cut history");
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("a tree in no ref (git write-tree of an index holding a version): the version is hidden", async () => {
  const r = repo();
  try {
    commit(r, `TOKEN=${key(1)}\n`, "v1");
    const v2 = git(r.ws, ["hash-object", "-w", "--stdin"], `TOKEN=${key(2)}\n`).trim();
    const idx = join(r.tmp, "scratch-index");
    git(r.ws, ["read-tree", "HEAD"], undefined, { GIT_INDEX_FILE: idx });
    git(r.ws, ["update-index", "--add", "--cacheinfo", `100644,${v2},.env`], undefined, { GIT_INDEX_FILE: idx });
    git(r.ws, ["write-tree"], undefined, { GIT_INDEX_FILE: idx });
    rmSync(idx);
    assertHidden(r, await launch(r), [v2], "a tree in no ref");
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("a blob written by plumbing (an older .env sharing a credential): hidden; one sharing nothing stays readable; a second launch with nothing new reads no object", async () => {
  const r = repo();
  try {
    commit(r, `TOKEN=${key(1)}\nDB_PASSWORD=${key(9)}\n`, "v1");
    const old = git(r.ws, ["hash-object", "-w", "--stdin"], `TOKEN=${key(1)}\nDB_PASSWORD=${key(8)}\n`).trim();
    const plain = git(r.ws, ["hash-object", "-w", "--stdin"], "nothing to hide here\n").trim();
    // Past the racy window (a directory written within two seconds of a
    // scan is listed again at the next), so the second launch is steady.
    await new Promise((res) => setTimeout(res, 2200));
    const got = await launch(r);
    assertHidden(r, got, [old], "a plumbing blob");
    assert.ok(!got.lockedIds!.includes(`sha1:${plain}`), "a blob sharing nothing is not locked");
    assert.equal(agentReads(agentView(r, got), plain), "nothing to hide here\n", "and the agent reads it");
    // Nothing new since: the scan asks git nothing and reads no object; the
    // same versions are hidden.
    const again = await launch(r);
    assert.equal(again.scans!.unchanged, 1, JSON.stringify(again.scans));
    assert.deepEqual([again.scans!.asked, again.scans!.read, again.scans!.gitCalls, again.scans!.loose, again.scans!.listed], [0, 0, 0, 0, 0]);
    assert.deepEqual(again.lockedIds, got.lockedIds);
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});
