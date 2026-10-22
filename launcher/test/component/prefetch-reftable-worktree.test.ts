/**
 * The history prefetch over a REFTABLE repository with a linked worktree
 * (twin-prefetch.ts `stateFingerprint`; confidentiality.md §7.2a "The
 * prefetch"; a security fix, 2026-10-21), end to end with real git:
 *
 * a reftable repository keeps each linked worktree's HEAD in the worktree's
 * own `reftable/` (its HEAD file is a stub). The prefetch reads the store's
 * tips at launch start; the worktree's HEAD then moves to a commit holding a
 * protected version that nothing else reaches; the launch's history step
 * must not use the prefetched tips: the version is locked (in the step's
 * locked set, its loose copy unreadable to the agent), exactly as a launch
 * without the prefetch hides it. Before the fix the fingerprint did not see
 * the worktree's reftable, the stale tips were used, and the version stayed
 * readable through `git show <commit>:.env`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { prepareGitObjectTwins, type GitObjectTwinResult } from "../../src/git-object-twins.js";
import { launchHintFile, readLaunchHint } from "../../src/launch-hint.js";
import { RACY_WINDOW_NS, TwinPrefetch } from "../../src/twin-prefetch.js";
import { stateAxes } from "../axes.js";
import { memorySeals } from "../lib/memory-seals.js";
import { useReftableGit } from "../lib/reftable-git.js";

stateAxes("secrets"); // the confidentiality axis is what the object twins serve

// A git that can make a reftable repository, first on this process's PATH
// (the CI image builds one off the PATH: test/lib/reftable-git.ts), before
// any git call of the file.
const noReftable = useReftableGit();

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, args: string[], extra: Record<string, string> = {}, input?: string): string =>
  execFileSync("git", args, { cwd, encoding: "utf8", env: { ...ENV, PATH: process.env["PATH"], ...extra }, ...(input !== undefined ? { input } : {}) });
/** A key-shaped canary assembled at run time (no key literal in the file). */
const key = (v: number): string => ["REFTABLE", "CANARY", String(v), "Qz".repeat(14)].join("_");
/** Past the racy window for files written just now (its own test: twin-prefetch.test.ts). */
const later = (): bigint => BigInt(Date.now()) * 1_000_000n + 10n * RACY_WINDOW_NS;
const shape = (g: GitObjectTwinResult): string => JSON.stringify({
  twins: g.twins.map((x) => [x.kind, x.targetPath]).sort(), lockedIds: g.lockedIds, repos: g.repos, blobs: g.blobs,
});

test("a reftable worktree's HEAD moved to a protected version between the prefetch and its use: the version is locked all the same", { skip: noReftable ?? false }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-prefetch-reftable-"));
  try {
    const ws = join(tmp, "repo");
    try {
      git(tmp, ["init", "-q", "--ref-format=reftable", "-b", "main", ws]);
    } catch {
      t.skip(`this git cannot make a reftable repository (${git(tmp, ["version"]).trim()}; needs 2.45)`);
      return;
    }
    writeFileSync(join(ws, "README"), "readme\n");
    writeFileSync(join(ws, ".env"), `TOKEN=${key(1)}\n`);
    git(ws, ["add", "."]);
    git(ws, ["commit", "-qm", "one"]);
    git(ws, ["repack", "-adq"]);
    const wt = join(tmp, "wt");
    git(ws, ["worktree", "add", "-q", "--detach", wt]);
    assert.ok(existsSync(join(ws, ".git", "worktrees", "wt", "reftable")), "the worktree keeps its HEAD in its own reftable");
    // A commit holding version 2 that NO ref or reflog reaches (plumbing:
    // no ref, no reflog, no index of the repository's written).
    const v2 = git(ws, ["hash-object", "-w", "--stdin"], {}, `TOKEN=${key(2)}\n`).trim();
    const idx = join(tmp, "scratch-index");
    git(ws, ["read-tree", "HEAD"], { GIT_INDEX_FILE: idx });
    git(ws, ["update-index", "--add", "--cacheinfo", `100644,${v2},.env`], { GIT_INDEX_FILE: idx });
    const tree = git(ws, ["write-tree"], { GIT_INDEX_FILE: idx }).trim();
    const c2 = git(ws, ["commit-tree", tree, "-p", "HEAD", "-m", "two"]).trim();

    const denyFile = join(tmp, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    const walkCacheDir = join(tmp, "walks");
    const hintFile = launchHintFile(walkCacheDir, [ws]);
    // The store scan (store-scan.ts) finds version 2 by itself (a commit in
    // the store, reachable or not); it is off here so the test isolates
    // what the walk reaches through the tips the prefetch read.
    const opts = { cacheDir: join(tmp, "cache"), denyFile, walkCacheDir, hintFile, seals: memorySeals(), maxScanObjects: 0 };
    const secrets = [join(ws, ".env"), join(wt, ".env")];

    // Launch 1: version 2 is reachable from nothing, so nothing hides it.
    const first = await prepareGitObjectTwins(secrets, opts);
    assert.ok(!first.lockedIds!.includes(`sha1:${v2}`), "unreachable at first");
    assert.deepEqual(readLaunchHint(hintFile)!.stores, [[ws, wt].sort()], "the store is hinted with both work trees");

    // Launch 2: the prefetch reads the tips...
    const pre = TwinPrefetch.start({ hintFile, cacheDir: opts.cacheDir, now: later });
    assert.ok(pre !== null);
    await pre.ready();
    // ...then the worktree's HEAD moves to the commit holding version 2
    // (only its own reftable is written)...
    git(wt, ["update-ref", "--no-deref", "HEAD", c2]);
    assert.equal(git(wt, ["show", "HEAD:.env"]), `TOKEN=${key(2)}\n`, "git reads version 2 through the worktree's HEAD");
    // ...and the launch's history step runs with the prefetch.
    const got = await prepareGitObjectTwins(secrets, { ...opts, statePrefetch: pre, hashes: pre.hashes });
    pre.close();
    assert.ok(got.lockedIds!.includes(`sha1:${v2}`), `version 2 is locked (prefetch: ${JSON.stringify(pre.stats)})`);
    const loose = join(ws, ".git", "objects", v2.slice(0, 2), v2.slice(2));
    assert.ok(got.twins.some((x) => x.kind === "deny" && x.targetPath === loose), "its loose copy is unreadable in the agent's world (`git show` fails)");
    assert.equal(pre.stats.used, 0, "the prefetched state was not used");
    assert.match(pre.stats.discarded.join("\n"), /refs, reflogs or objects changed/);
    const plain = await prepareGitObjectTwins(secrets, opts);
    assert.equal(shape(got), shape(plain), "exactly what a launch without the prefetch hides");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
