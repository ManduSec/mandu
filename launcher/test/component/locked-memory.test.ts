/**
 * A version once locked stays locked (locked-memory.ts; a security fix,
 * 2026-10-21; confidentiality.md §7.2a "A version once locked stays
 * locked"), end to end with real git. An agent can write `.git` in a
 * confined session and so make a protected version unreachable while its
 * objects stay in the store:
 *
 *   - a commit object deleted under a forged shallow boundary (the shallow
 *     rule must believe a boundary whose parent is gone);
 *   - a branch moved to an orphan and the reflogs expired, with the walk
 *     cache walked anew (a new seal epoch);
 *
 * and in both the next launch still locks every version an earlier launch
 * found (its loose copy unreadable to the agent, its id in the locked set),
 * where before only what git still reached was. A path no longer protected
 * brings nothing back, and a garbled memory reads as the walk's own answer.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { prepareGitObjectTwins, type GitObjectTwinResult } from "../../src/git-object-twins.js";
import { stateAxes } from "../axes.js";
import { memorySeals, type MemorySeals } from "../lib/memory-seals.js";

stateAxes("secrets"); // the confidentiality axis is what the object twins serve

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, args: string[], input?: string): string =>
  execFileSync("git", args, { cwd, encoding: "utf8", env: ENV, ...(input !== undefined ? { input } : {}) });
/** A key-shaped canary assembled at run time (no key literal in the file). */
const key = (v: number): string => ["MEMORY", "CANARY", String(v), "Qz".repeat(14)].join("_");
const body = (v: number): string => `TOKEN=${key(v)}\n`;

interface Repo { tmp: string; ws: string; c: string[]; v: string[]; seals: MemorySeals; opts: { cacheDir: string; denyFile: string; walkCacheDir: string } }

/** Three commits of `.env`, every object LOOSE (as in a repository between
 *  two `gc`s), so the agent can delete one. */
function repo(): Repo {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-memory-"));
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
  const denyFile = join(tmp, "denied");
  writeFileSync(denyFile, "");
  chmodSync(denyFile, 0o000);
  return {
    tmp, ws, c, v: [1, 2, 3].map((n) => git(ws, ["hash-object", "--stdin"], body(n)).trim()), seals: memorySeals(),
    opts: { cacheDir: join(tmp, "cache"), denyFile, walkCacheDir: join(tmp, "walks") },
  };
}

const launch = (r: Repo, paths = [join(r.ws, ".env")]): Promise<GitObjectTwinResult> =>
  prepareGitObjectTwins(paths, { ...r.opts, seals: r.seals });
const loose = (r: Repo, name: string): string => join(r.ws, ".git", "objects", name.slice(0, 2), name.slice(2));

function assertLocked(r: Repo, got: GitObjectTwinResult, n: number, what: string): void {
  const name = r.v[n - 1]!;
  assert.ok(got.lockedIds!.includes(`sha1:${name}`), `${what}: version ${n} locked`);
  assert.ok(got.twins.some((t) => t.kind === "deny" && t.targetPath === loose(r, name)), `${what}: its loose copy unreadable in the agent's world`);
}

test("a forged shallow boundary over a deleted parent commit unlocks nothing an earlier launch locked", async () => {
  const r = repo();
  try {
    const first = await launch(r);
    for (const n of [1, 2, 3]) assertLocked(r, first, n, "launch 1");
    // In the session: the parent of commit 3 deleted, commit 3 written into
    // the shallow file. The shallow rule finds no parent of it in the store
    // and honours the file: git log now stops at commit 3.
    rmSync(loose(r, r.c[1]!), { force: true });
    writeFileSync(join(r.ws, ".git", "shallow"), `${r.c[2]}\n`);
    assert.equal(git(r.ws, ["log", "--format=%s"]).trim(), "v3");
    const second = await launch(r);
    for (const n of [1, 2, 3]) assertLocked(r, second, n, "launch 2");
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("history made unreachable (an orphan branch, the reflogs expired) and the walk cache walked anew unlock nothing an earlier launch locked", async () => {
  const r = repo();
  try {
    await launch(r);
    git(r.ws, ["checkout", "-q", "--orphan", "fresh"]);
    writeFileSync(join(r.ws, ".env"), "TOKEN=$MDU:nomodel_File[0].TOKEN\n");
    git(r.ws, ["add", "."]);
    git(r.ws, ["commit", "-qm", "fresh"]);
    git(r.ws, ["branch", "-D", "main"]);
    git(r.ws, ["reflog", "expire", "--expire=now", "--all"]);
    assert.equal(git(r.ws, ["log", "--all", "--format=%s"]).trim(), "fresh", "nothing reaches the old commits");
    assert.equal(git(r.ws, ["cat-file", "-p", r.v[0]!]), body(1), "but their objects are in the store");
    r.seals.rotate("unprotected-ended"); // every cache walked anew
    const got = await launch(r);
    assert.equal(got.walks.full, 1, "the history was walked anew");
    for (const n of [1, 2, 3]) assertLocked(r, got, n, "after the cut");
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("a path no longer protected brings nothing back; a garbled memory reads as the walk's own answer", async () => {
  const r = repo();
  try {
    await launch(r);
    const other = await launch(r, [join(r.ws, "README")]);
    for (const v of r.v) assert.ok(!other.lockedIds!.includes(`sha1:${v}`), "`.env` is not protected in this launch: none of its versions is locked");
    const dir = join(r.opts.walkCacheDir, "locked-memory");
    for (const f of readdirSync(dir)) writeFileSync(join(dir, f), "{garbled");
    const got = await launch(r);
    for (const n of [1, 2, 3]) assertLocked(r, got, n, "with a garbled memory, the walk finds them");
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});
