/**
 * e2e — a protected file's COMMITTED bytes are absent from the agent's world
 * (git-object-twins.ts; docs/design/confidentiality/confidentiality.md §7.2a), with a REAL
 * repository and the REAL twin wrap: every version of the file (packed with a
 * bitmap and a multi-pack-index, committed loose, staged in the index) is
 * missing for `git log -p`, `git show` and `git cat-file --batch-all-objects`
 * run inside the wrap, while every other object reads as before and a new
 * commit still works. The guard-only posture of the same twins is proven by
 * interceptors/net-supervisor/tests/guard_integration.rs
 * (object_store_twins_serve_sanitized_packs_deny_exposers_and_hide_shadow_repos).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { defaultGitRunner, idxObjectNames, prepareGitObjectTwins, type GitObjectTwinResult, type GitRunner } from "../../src/git-object-twins.js";
import { hostPtraceScope, openGitSession, sessionAllowed } from "../../src/git-session.js";
import { gitSandbox, isSeatbeltGitSandbox } from "../../src/hardened-git.js";
import { launchHintFile } from "../../src/launch-hint.js";
import { RACY_WINDOW_NS, TwinPrefetch } from "../../src/twin-prefetch.js";
import { withObjectTwins } from "../../src/secret-twins.js";
import { stateAxes } from "../axes.js";
import { memorySeals } from "../lib/memory-seals.js";

stateAxes("secrets"); // the confidentiality axis is what hides the committed bytes

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...args: string[]): string => execFileSync("git", args, { cwd, encoding: "utf8", env: ENV });
const canary = (v: number): string => `COMMITTED_CANARY_V${v}_${"x".repeat(30)}`;

function bwrapWorks(): boolean {
  return spawnSync("bwrap", ["--dev-bind", "/", "/", "--cap-drop", "ALL", "--", "true"], { stdio: "ignore", timeout: 10_000 }).status === 0;
}

test("every committed, packed, loose and staged version of a protected file is hidden; the rest of the history reads", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gitobj-"));
  try {
    const ws = join(tmp, "ws");
    mkdirSync(join(ws, "notes"), { recursive: true });
    const secret = join(ws, "notes", "secret.md");
    git(tmp, "init", "-q", ws);
    writeFileSync(join(ws, "README"), "README-ONE\n");
    writeFileSync(secret, `${canary(1)}\n`);
    git(ws, "add", ".");
    git(ws, "commit", "-qm", "one");
    writeFileSync(secret, `${canary(2)}\n`);
    writeFileSync(join(ws, "README"), "README-TWO\n");
    git(ws, "commit", "-qam", "two");
    git(ws, "repack", "-adbq", "--write-midx");
    writeFileSync(secret, `${canary(3)}\n`);
    git(ws, "commit", "-qam", "three (loose)");
    writeFileSync(secret, `${canary(4)}\n`);
    git(ws, "add", "notes/secret.md"); // staged, never committed
    writeFileSync(secret, `${canary(5)}\n`); // the working copy (twinned at launch)
    const packDir = join(ws, ".git", "objects", "pack");
    assert.ok(existsSync(join(packDir, "multi-pack-index")), "precondition: a multi-pack-index");

    const cacheDir = join(tmp, "cache");
    const denyFile = join(tmp, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    const logs: string[] = [];
    // The caches are trusted only through the arbiter's seals (plan 14 §11.2).
    const seals = memorySeals();
    const got = await prepareGitObjectTwins([secret], { cacheDir, denyFile, seals, log: (m) => logs.push(m) });
    assert.equal(got.repos, 1);
    assert.equal(got.blobs, 5, "v1 v2 v3 committed, v4 staged, v5 hashed as git add would");
    assert.equal(got.packsRebuilt, 1);
    const byKind = (k: string) => got.twins.filter((x) => x.kind === k).map((x) => x.targetPath.slice(packDir.length - "pack".length - 1));
    assert.deepEqual(byKind("object").map((p) => p.replace(/pack-[0-9a-f]+/, "pack-N")).sort(), ["/pack/pack-N.idx", "/pack/pack-N.pack", "/pack/pack-N.rev"]);
    const denied = got.twins.filter((x) => x.kind === "deny").map((x) => x.targetPath);
    assert.ok(denied.some((p) => p.endsWith("/multi-pack-index")), "the midx indexes the real pack by position");
    assert.ok(denied.some((p) => /\.bitmap$/.test(p)), "so does the bitmap");
    assert.equal(denied.filter((p) => /\/objects\/[0-9a-f]{2}\/[0-9a-f]{38}$/.test(p)).length, 2, "the loose v3 and the staged v4");
    const protectedNames = new Set([1, 2].map((v) =>
      execFileSync("git", ["hash-object", "--stdin"], { cwd: ws, input: `${canary(v)}\n`, encoding: "utf8", env: ENV }).trim()));
    const sanitizedIdx = got.twins.find((x) => x.targetPath.endsWith(".idx"))!.twinPath;
    const listed = idxObjectNames(readFileSync(sanitizedIdx));
    assert.ok(listed.length > 0 && listed.every((n) => !protectedNames.has(n)), "the sanitized index lists no protected version");

    const again = await prepareGitObjectTwins([secret], { cacheDir, denyFile, seals });
    assert.equal(again.packsRebuilt, 0);
    assert.equal(again.cacheHits, 1, "a relaunch reuses the sanitized pack");

    if (!bwrapWorks()) {
      t.diagnostic("SKIP the wrapped read: bwrap cannot start here");
      return;
    }
    const wrap = withObjectTwins(["bwrap", "--dev-bind", "/", "/", "--cap-drop", "ALL", "--"], got.twins, []);
    const inWrap = (...args: string[]) =>
      spawnSync(wrap[0]!, [...wrap.slice(1), "git", ...args], { cwd: ws, encoding: "utf8", env: ENV, timeout: 60_000 });
    const log = inWrap("log", "-p", "--all");
    const all = inWrap("cat-file", "--batch-all-objects", "--batch");
    const showOld = inWrap("show", "HEAD~1:notes/secret.md");
    const showIndex = inWrap("show", ":notes/secret.md");
    const readme = inWrap("show", "HEAD:README");
    const everything = [log, all, showOld, showIndex, readme].map((r) => `${r.stdout}${r.stderr}`).join("\n");
    for (const v of [1, 2, 3, 4]) assert.ok(!everything.includes(canary(v)), `version ${v} never reaches the wrapped git`);
    assert.notEqual(showOld.status, 0, "a protected version is a missing object");
    assert.notEqual(showIndex.status, 0, "so is the staged one");
    assert.equal(readme.stdout, "README-TWO\n", "every other object reads as before");
    // A patch of the protected file itself stops the log there ("unable to
    // read"): fail-closed. The history of every other path still reads.
    const readmeLog = inWrap("log", "-p", "--", "README");
    assert.equal(readmeLog.status, 0, readmeLog.stderr);
    assert.match(readmeLog.stdout, /README-ONE/, "history of other files still shows");
    assert.match(log.stdout, /three \(loose\)/, "the log itself runs up to the protected patch");
    writeFileSync(join(ws, "README"), "README-THREE\n");
    const commit = inWrap("commit", "-qm", "four", "--", "README");
    assert.equal(commit.status, 0, `a new commit works: ${commit.stderr}`);
    // Outside the wrap nothing changed: the user's repository is intact.
    assert.match(git(ws, "show", "HEAD~2:notes/secret.md"), /COMMITTED_CANARY_V2/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("a repository that cannot be sanitized loses only its own cover: continueOnFailure names it and keeps every other repository's twins; without it the first failure throws", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gitobj-two-"));
  try {
    // `big` holds a protected file in a pack over the cap; `small` in one under it.
    const repo = (name: string, bytes: number): string => {
      const ws = join(tmp, name);
      git(tmp, "init", "-q", ws);
      writeFileSync(join(ws, "filler"), randomBytes(bytes)); // incompressible: the pack is about this size
      writeFileSync(join(ws, ".env"), `${canary(1)}\n`);
      git(ws, "add", ".");
      git(ws, "commit", "-qm", "one");
      git(ws, "repack", "-adq");
      return join(ws, ".env");
    };
    const big = repo("big", 400_000);
    const small = repo("small", 100);
    const denyFile = join(tmp, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    const opts = { cacheDir: join(tmp, "cache"), denyFile, maxRebuildBytes: 200_000 };
    await assert.rejects(prepareGitObjectTwins([big, small], opts), /big: sanitizing its git history needs .* over the 0 MiB cap/);
    const got = await prepareGitObjectTwins([big, small], { ...opts, continueOnFailure: true });
    assert.deepEqual(got.failed?.map((f) => f.root), [join(tmp, "big")]);
    assert.equal(got.repos, 1);
    assert.ok(got.twins.length > 0 && got.twins.every((x) => x.targetPath.startsWith(join(tmp, "small"))), "only the repository that could be sanitized has twins, and it has them");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("the history walk is cached: a relaunch does not walk, new commits walk only themselves, and a torn cache or a pruned old tip walks it all; every version stays hidden", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gitobj-walk-"));
  try {
    const ws = join(tmp, "ws");
    git(tmp, "init", "-q", ws);
    const secret = join(ws, ".env");
    const blob = (v: number) =>
      execFileSync("git", ["hash-object", "--stdin"], { cwd: ws, input: `${canary(v)}\n`, encoding: "utf8", env: ENV }).trim();
    const commit = (v: number, msg: string) => {
      writeFileSync(secret, `${canary(v)}\n`);
      git(ws, "add", ".env");
      git(ws, "commit", "-qm", msg);
    };
    writeFileSync(join(ws, "README"), "R\n");
    git(ws, "add", "README");
    commit(1, "one");
    commit(2, "two");
    git(ws, "repack", "-adq");
    const walkCacheDir = join(tmp, "walks");
    const denyFile = join(tmp, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    const opts = { cacheDir: join(tmp, "cache"), denyFile, walkCacheDir, seals: memorySeals() };
    const run = () => prepareGitObjectTwins([secret], opts);
    /** The protected names the sanitized index still lists (must be none). */
    const leaked = (got: Awaited<ReturnType<typeof run>>, versions: number[]) => {
      const idx = got.twins.find((x) => x.targetPath.endsWith(".idx"))!.twinPath;
      const listed = new Set(idxObjectNames(readFileSync(idx)));
      return versions.filter((v) => listed.has(blob(v)));
    };

    const first = await run();
    assert.deepEqual(first.walks, { hit: 0, incremental: 0, full: 1 }, "the first launch walks the history");
    assert.equal(first.blobs, 2, "v1 from history, v2 committed + staged + working copy");
    assert.deepEqual(leaked(first, [1, 2]), []);

    const second = await run();
    assert.deepEqual(second.walks, { hit: 1, incremental: 0, full: 0 }, "an unchanged repository is not walked again");
    assert.deepEqual(second.twins, first.twins);

    // v3 lives ONLY in history (v4 is committed, staged and in the working
    // copy): only the walk can find it.
    commit(3, "three");
    commit(4, "four");
    git(ws, "repack", "-adq");
    const third = await run();
    assert.deepEqual(third.walks, { hit: 0, incremental: 1, full: 0 }, "new commits walk only themselves");
    assert.equal(third.blobs, 4);
    assert.deepEqual(leaked(third, [1, 2, 3, 4]), [], "the version only history holds is hidden too");

    const file = readdirSync(walkCacheDir).filter((n) => n.endsWith(".json"));
    assert.equal(file.length, 1);
    writeFileSync(join(walkCacheDir, file[0]!), "{\"v\":1,\"root\":");
    const torn = await run();
    assert.deepEqual(torn.walks, { hit: 0, incremental: 0, full: 1 }, "a torn cache file walks it all");
    assert.equal(torn.blobs, 4);

    // Every cached tip pruned: git refuses the incremental walk, the launcher
    // walks it all. v5 lives only in the new history.
    git(ws, "checkout", "-q", "--orphan", "fresh");
    commit(5, "five");
    commit(6, "six");
    for (const b of git(ws, "for-each-ref", "--format=%(refname:short)", "refs/heads/").split("\n")) {
      if (b !== "" && b !== "fresh") git(ws, "branch", "-qD", b);
    }
    git(ws, "reflog", "expire", "--expire=now", "--all");
    git(ws, "gc", "-q", "--prune=now");
    assert.throws(() => git(ws, "cat-file", "-e", blob(3)), "precondition: the old history is gone");
    const pruned = await run();
    assert.deepEqual(pruned.walks, { hit: 0, incremental: 0, full: 1 }, "a pruned old tip falls back to the whole walk");
    assert.equal(pruned.blobs, 2, "v5 from history, v6 committed");
    assert.deepEqual(leaked(pruned, [5, 6]), []);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("a worktree and its main checkout (one object store): one twin per object file, and neither work tree's protected versions, nor one only a worktree's reflog names, reach git in the wrap from either work tree", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gitobj-wt-"));
  try {
    const main = join(tmp, "main");
    git(tmp, "init", "-q", "-b", "main", main);
    writeFileSync(join(main, "README"), "README\n");
    writeFileSync(join(main, "a.env"), `${canary(1)}\n`);
    git(main, "add", ".");
    git(main, "commit", "-qm", "one");
    const wt = join(tmp, "wt");
    git(main, "worktree", "add", "-q", "-b", "side", wt);
    writeFileSync(join(wt, "b.env"), `${canary(2)}\n`);
    git(wt, "add", "b.env");
    git(wt, "commit", "-qm", "b");
    // A commit only the worktree's HEAD reflog names (detached, left behind).
    git(wt, "checkout", "-q", "--detach");
    writeFileSync(join(wt, "b.env"), `${canary(3)}\n`);
    git(wt, "commit", "-qam", "detached");
    git(wt, "checkout", "-q", "side");
    git(main, "repack", "-adq");
    const denyFile = join(tmp, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    const got = await prepareGitObjectTwins([join(main, "a.env"), join(wt, "b.env")], { cacheDir: join(tmp, "cache"), denyFile, seals: memorySeals() });
    assert.equal(got.repos, 1, "one object store");
    const targets = got.twins.map((x) => x.targetPath);
    assert.equal(new Set(targets).size, targets.length, "one twin per object file");
    if (!bwrapWorks()) {
      t.diagnostic("SKIP the wrapped read: bwrap cannot start here");
      return;
    }
    const wrap = withObjectTwins(["bwrap", "--dev-bind", "/", "/", "--cap-drop", "ALL", "--"], got.twins, []);
    for (const cwd of [main, wt]) {
      const inWrap = (...args: string[]) =>
        spawnSync(wrap[0]!, [...wrap.slice(1), "git", ...args], { cwd, encoding: "utf8", env: ENV, timeout: 60_000 });
      const all = inWrap("cat-file", "--batch-all-objects", "--batch");
      const log = inWrap("log", "-p", "--all", "--reflog");
      const everything = `${all.stdout}${all.stderr}${log.stdout}${log.stderr}`;
      for (const v of [1, 2, 3]) assert.ok(!everything.includes(canary(v)), `${cwd}: version ${v} never reaches the wrapped git`);
      assert.equal(inWrap("show", "HEAD:README").stdout, "README\n", `${cwd}: every other object reads`);
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

/** `git` run inside the twin wrap from `cwd`: what every object and every
 *  patch of every ref and reflog entry reads as there. */
function readInWrap(twins: Parameters<typeof withObjectTwins>[1], cwd: string): string {
  const wrap = withObjectTwins(["bwrap", "--dev-bind", "/", "/", "--cap-drop", "ALL", "--"], twins, []);
  const inWrap = (...args: string[]) =>
    spawnSync(wrap[0]!, [...wrap.slice(1), "git", ...args], { cwd, encoding: "utf8", env: ENV, timeout: 60_000 });
  const all = inWrap("cat-file", "--batch-all-objects", "--batch");
  const log = inWrap("log", "-p", "--all", "--reflog");
  return `${all.stdout}${all.stderr}${log.stdout}${log.stderr}`;
}

test("two repositories sharing a pack through objects/info/alternates (git clone --shared): one twin per object file, and neither repository's protected versions reach git in the wrap from either, in either order", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gitobj-alt-"));
  try {
    // A protects a.env; B, a `clone --shared` of A, protects b.env, whose
    // version 2 was committed in A (A does not protect b.env), so it lives
    // only in A's pack, which B reads through its alternates.
    const a = join(tmp, "a");
    git(tmp, "init", "-q", "-b", "main", a);
    writeFileSync(join(a, "README"), "README\n");
    writeFileSync(join(a, "a.env"), `${canary(1)}\n`);
    writeFileSync(join(a, "b.env"), `${canary(2)}\n`);
    git(a, "add", ".");
    git(a, "commit", "-qm", "one");
    git(a, "repack", "-adq");
    const b = join(tmp, "b");
    git(tmp, "clone", "-q", "--shared", a, b);
    assert.ok(existsSync(join(b, ".git", "objects", "info", "alternates")), "precondition: B borrows A's objects");
    writeFileSync(join(b, "b.env"), `${canary(3)}\n`);
    git(b, "commit", "-qam", "b's own");
    git(b, "repack", "-adlq");
    const denyFile = join(tmp, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    for (const order of [[join(a, "a.env"), join(b, "b.env")], [join(b, "b.env"), join(a, "a.env")]]) {
      const got = await prepareGitObjectTwins(order, { cacheDir: join(tmp, "cache"), denyFile, seals: memorySeals() });
      const targets = got.twins.map((x) => x.targetPath);
      assert.ok(targets.some((p) => p.startsWith(join(a, ".git", "objects", "pack"))), "A's pack is twinned");
      assert.equal(got.repos, 2, "both repositories hold a protected version");
      if (bwrapWorks()) {
        for (const cwd of [a, b]) {
          const everything = readInWrap(got.twins, cwd);
          for (const v of [1, 2, 3]) assert.ok(!everything.includes(canary(v)), `${cwd}: version ${v} never reaches the wrapped git`);
          const wrap = withObjectTwins(["bwrap", "--dev-bind", "/", "/", "--cap-drop", "ALL", "--"], got.twins, []);
          const readme = spawnSync(wrap[0]!, [...wrap.slice(1), "git", "show", "HEAD:README"], { cwd, encoding: "utf8", env: ENV, timeout: 60_000 });
          assert.equal(readme.stdout, "README\n", `${cwd}: every other object reads`);
        }
      } else {
        t.diagnostic("SKIP the wrapped read: bwrap cannot start here");
      }
      assert.equal(new Set(targets).size, targets.length, `one twin per object file (${[...targets].sort().join(", ")})`);
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("an alternate's own alternates are followed: a protected version only in the pack two links away is twinned", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gitobj-alt2-"));
  try {
    // A ← B ← C (each a `clone --shared` of the one before). Only C is in the
    // launch; the protected version lives only in A's pack.
    const a = join(tmp, "a");
    git(tmp, "init", "-q", "-b", "main", a);
    writeFileSync(join(a, "README"), "README\n");
    writeFileSync(join(a, "c.env"), `${canary(1)}\n`);
    git(a, "add", ".");
    git(a, "commit", "-qm", "one");
    git(a, "repack", "-adq");
    const b = join(tmp, "b");
    git(tmp, "clone", "-q", "--shared", a, b);
    const c = join(tmp, "c");
    git(tmp, "clone", "-q", "--shared", b, c);
    writeFileSync(join(c, "c.env"), `${canary(2)}\n`);
    git(c, "commit", "-qam", "c's own");
    const denyFile = join(tmp, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    const got = await prepareGitObjectTwins([join(c, "c.env")], { cacheDir: join(tmp, "cache"), denyFile, seals: memorySeals() });
    if (bwrapWorks()) {
      const everything = readInWrap(got.twins, c);
      for (const v of [1, 2]) assert.ok(!everything.includes(canary(v)), `version ${v} never reaches the wrapped git`);
    } else {
      t.diagnostic("SKIP the wrapped read: bwrap cannot start here");
    }
    assert.ok(got.twins.some((x) => x.targetPath.startsWith(join(a, ".git", "objects", "pack"))), "A's pack (two links away) is twinned");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("an alternates file the launcher cannot read refuses the repository: the raw pack is never left behind", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gitobj-alt3-"));
  try {
    const a = join(tmp, "a");
    git(tmp, "init", "-q", "-b", "main", a);
    writeFileSync(join(a, "s.env"), `${canary(1)}\n`);
    git(a, "add", ".");
    git(a, "commit", "-qm", "one");
    git(a, "repack", "-adq");
    const b = join(tmp, "b");
    git(tmp, "clone", "-q", "--shared", a, b);
    git(b, "repack", "-adq"); // B holds every object itself, so git in B works whatever the alternates say
    const alternates = join(b, ".git", "objects", "info", "alternates");
    rmSync(alternates);
    // Not a regular file: git skips it, and the launcher cannot tell which
    // stores it would name (the agent could make it name A's again).
    mkdirSync(alternates);
    const denyFile = join(tmp, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    await assert.rejects(
      prepareGitObjectTwins([join(b, "s.env")], { cacheDir: join(tmp, "cache"), denyFile }),
      (e: Error) => e.name === "GitObjectTwinError" && /alternates/.test(e.message),
    );
    const got = await prepareGitObjectTwins([join(b, "s.env")], { cacheDir: join(tmp, "cache"), denyFile, continueOnFailure: true });
    assert.deepEqual(got.failed?.map((f) => f.root), [b], "under --best-effort it is named");
    assert.equal(got.twins.length, 0);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("repositories are read concurrently (git version asked once), and the twins are what a one-at-a-time run gives", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gitobj-many-"));
  try {
    const secrets: string[] = [];
    for (let r = 0; r < 5; r++) {
      const ws = join(tmp, `r${r}`);
      git(tmp, "init", "-q", ws);
      for (const v of [1, 2]) {
        writeFileSync(join(ws, ".env"), `${canary(10 * r + v)}\n`);
        git(ws, "add", ".env");
        git(ws, "commit", "-qm", `v${v}`);
      }
      git(ws, "repack", "-adq");
      secrets.push(join(ws, ".env"));
    }
    const denyFile = join(tmp, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    // The runner every call goes through: which repositories have a call in
    // flight at once, and how often `git version` runs.
    const active = new Map<string, number>();
    let overlap = 0;
    let versions = 0;
    const counting: GitRunner = async (args, o) => {
      if (args[0] === "version") versions++;
      active.set(o.cwd, (active.get(o.cwd) ?? 0) + 1);
      overlap = Math.max(overlap, [...active.values()].filter((n) => n > 0).length);
      try { return await defaultGitRunner(args, o); } finally { active.set(o.cwd, active.get(o.cwd)! - 1); }
    };
    const got = await prepareGitObjectTwins(secrets, { cacheDir: join(tmp, "cache"), denyFile, walkCacheDir: join(tmp, "walks"), git: counting });
    assert.equal(got.repos, 5);
    assert.ok(overlap > 1, `repositories overlap (peak ${overlap} with a call in flight)`);
    assert.equal(versions, 1, "git version is asked once, not per repository");
    // One repository at a time (a fresh cache dir: nothing reused) gives the same twins.
    const seq: typeof got.twins = [];
    for (const s of secrets) {
      seq.push(...(await prepareGitObjectTwins([s], { cacheDir: join(tmp, "cache2"), denyFile, walkCacheDir: join(tmp, "walks2") })).twins);
    }
    const shape = (ts: typeof got.twins) => ts.map((t) => `${t.kind} ${t.targetPath}`).sort();
    assert.deepEqual(shape(got.twins), shape(seq));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

/** A writable directory on another filesystem than `dir`, or null. Never
 *  under the real $HOME (test-organization.md §8.4): the candidates are
 *  /dev/shm, /var/tmp and the per-user runtime dir (a tmpfs). */
function otherFilesystem(dir: string): string | null {
  const dev = statSync(dir).dev;
  const runtime = process.env["XDG_RUNTIME_DIR"];
  for (const c of ["/dev/shm", "/var/tmp", ...(runtime ? [runtime] : [])]) {
    try {
      if (statSync(c).dev !== dev) return mkdtempSync(join(c, "mandu-gitobj-xdev-"));
    } catch { /* absent or unwritable */ }
  }
  return null;
}

test("the view state on another filesystem than the repository: the sanitized pack is built there, the same as on one filesystem (git pack-objects renamed across devices: EXDEV)", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gitobj-xdev-"));
  const other = otherFilesystem(tmp);
  try {
    if (other === null) {
      t.skip("no second filesystem to put the cache on");
      return;
    }
    const ws = join(tmp, "ws");
    mkdirSync(ws, { recursive: true });
    const secret = join(ws, "secret.md");
    git(tmp, "init", "-q", ws);
    writeFileSync(join(ws, "README"), "README\n");
    writeFileSync(secret, `${canary(1)}\n`);
    git(ws, "add", ".");
    git(ws, "commit", "-qm", "one");
    writeFileSync(secret, `${canary(2)}\n`);
    git(ws, "commit", "-qam", "two");
    git(ws, "repack", "-adq");
    const denyFile = join(tmp, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    const across = await prepareGitObjectTwins([secret], { cacheDir: join(other, "cache"), denyFile });
    assert.equal(across.packsRebuilt, 1, "the pack was rebuilt into the other filesystem");
    const same = await prepareGitObjectTwins([secret], { cacheDir: join(tmp, "cache"), denyFile });
    const names = (x: typeof across) => x.twins.filter((w) => w.kind === "object").map((w) => w.twinPath.slice(w.twinPath.lastIndexOf("/") + 1)).sort();
    assert.deepEqual(names(across), names(same), "the same sanitized pack either way");
    const idx = across.twins.find((w) => w.targetPath.endsWith(".idx"))!.twinPath;
    assert.deepEqual(idxObjectNames(readFileSync(idx)), idxObjectNames(readFileSync(same.twins.find((w) => w.targetPath.endsWith(".idx"))!.twinPath)));
    assert.deepEqual(readdirSync(join(other, "cache")).filter((n) => n.startsWith(".tmp-")), [], "no temporary directory left behind");
    assert.deepEqual(readdirSync(join(ws, ".git", "objects", "pack")).filter((n) => n.startsWith("tmp_")), [], "nothing written into the repository");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
    if (other) rmSync(other, { recursive: true, force: true });
  }
});

test("the launch-start prefetch (twin-prefetch.ts): the twins are identical with and without it, and a secret committed between the prefetch and the use never reaches git in the real wrap", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gitobj-prefetch-"));
  try {
    // A main checkout and a worktree (one store, as on a dev host).
    const main = join(tmp, "main");
    git(tmp, "init", "-q", "-b", "main", main);
    writeFileSync(join(main, "README"), "README\n");
    writeFileSync(join(main, "a.env"), `${canary(1)}\n`);
    git(main, "add", ".");
    git(main, "commit", "-qm", "one");
    writeFileSync(join(main, "a.env"), `${canary(2)}\n`);
    git(main, "commit", "-qam", "two");
    const wt = join(tmp, "wt");
    git(main, "worktree", "add", "-q", "-b", "side", wt);
    git(main, "repack", "-adq");
    const secrets = [join(main, "a.env"), join(wt, "a.env")];
    const denyFile = join(tmp, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    const walkCacheDir = join(tmp, "walks");
    const opts = { cacheDir: join(tmp, "cache"), denyFile, walkCacheDir, hintFile: launchHintFile(walkCacheDir, [main]), seals: memorySeals() };
    const shape = (g: GitObjectTwinResult) => JSON.stringify([g.twins.map((x) => `${x.kind} ${x.targetPath} ${x.twinPath}`).sort(), g.lockedIds]);
    // Ten seconds on: the files were all written just now (the racy rule
    // has its own unit test).
    const later = () => BigInt(Date.now()) * 1_000_000n + 10n * RACY_WINDOW_NS;

    await prepareGitObjectTwins(secrets, opts); // leaves the hint
    const plain = await prepareGitObjectTwins(secrets, opts);
    const pre = TwinPrefetch.start({ hintFile: opts.hintFile, cacheDir: opts.cacheDir, now: later });
    assert.ok(pre !== null, "the hint names the store");
    await pre.ready();
    const withPre = await prepareGitObjectTwins(secrets, { ...opts, statePrefetch: pre, hashes: pre.hashes });
    pre.close();
    assert.equal(pre.stats.used, 1, JSON.stringify(pre.stats));
    assert.equal(shape(withPre), shape(plain), "the same twins, the same locked ids");

    // A secret committed (then overwritten, so only the history holds it)
    // after the prefetch read the tips: discarded, found, hidden.
    const pre2 = TwinPrefetch.start({ hintFile: opts.hintFile, cacheDir: opts.cacheDir, now: later });
    assert.ok(pre2 !== null);
    await pre2.ready();
    writeFileSync(join(wt, "a.env"), `${canary(3)}\n`);
    git(wt, "commit", "-qam", "three");
    writeFileSync(join(wt, "a.env"), `${canary(4)}\n`);
    git(wt, "commit", "-qam", "four");
    git(main, "repack", "-adq");
    const after = await prepareGitObjectTwins(secrets, { ...opts, statePrefetch: pre2, hashes: pre2.hashes });
    pre2.close();
    assert.equal(pre2.stats.used, 0, "the state read before the commit is not used");
    const fresh = await prepareGitObjectTwins(secrets, { ...opts, cacheDir: join(tmp, "cache-fresh"), walkCacheDir: join(tmp, "walks-fresh") });
    const targets = (g: GitObjectTwinResult) => JSON.stringify(g.twins.map((x) => `${x.kind} ${x.targetPath}`).sort());
    assert.equal(targets(after), targets(fresh), "what a launch without the prefetch twins");
    assert.deepEqual(after.lockedIds, fresh.lockedIds);
    if (!bwrapWorks()) {
      t.diagnostic("SKIP the wrapped read: bwrap cannot start here");
      return;
    }
    for (const cwd of [main, wt]) {
      const everything = readInWrap(after.twins, cwd);
      for (const v of [1, 2, 3, 4]) assert.ok(!everything.includes(canary(v)), `${cwd}: version ${v} never reaches the wrapped git`);
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

// git-session.ts (write-protection.md §8.5.3): the step's git calls run in
// ONE git sandbox. What it masks must be exactly what one sandbox per call
// masked, and a sandbox that dies under it must refuse, never mask less.
test("the step in ONE git sandbox (git-session.ts): the twins, sanitized packs and locked ids are the per-call runner's; a runner killed under the step refuses it", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gitobj-session-"));
  try {
    const secrets: string[] = [];
    for (let r = 0; r < 3; r++) {
      const ws = join(tmp, `r${r}`);
      git(tmp, "init", "-q", ws);
      writeFileSync(join(ws, "README"), `README-${r}\n`);
      for (const v of [1, 2]) {
        writeFileSync(join(ws, ".env"), `${canary(10 * r + v)}\n`);
        git(ws, "add", ".");
        git(ws, "commit", "-qm", `v${v}`);
      }
      git(ws, "repack", "-adq");
      writeFileSync(join(ws, ".env"), `${canary(10 * r + 3)}\n`);
      git(ws, "commit", "-qam", "v3 (loose)");
      writeFileSync(join(ws, ".env"), `${canary(10 * r + 4)}\n`); // the working copy
      secrets.push(join(ws, ".env"));
    }
    const denyFile = join(tmp, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    const shape = (g: GitObjectTwinResult) => JSON.stringify([g.twins.map((x) => `${x.kind} ${x.targetPath}`).sort(), g.lockedIds, g.blobs, g.repos, g.packsRebuilt]);
    const packNames = (g: GitObjectTwinResult) => g.twins.filter((x) => x.kind === "object" && x.targetPath.endsWith(".idx"))
      .map((x) => `${x.targetPath} ${idxObjectNames(readFileSync(x.twinPath)).sort().join(",")}`).sort();

    const perCall = await prepareGitObjectTwins(secrets, { cacheDir: join(tmp, "c1"), walkCacheDir: join(tmp, "w1"), denyFile, git: defaultGitRunner });
    const session = openGitSession();
    let viaSession: GitObjectTwinResult;
    try {
      viaSession = await prepareGitObjectTwins(secrets, { cacheDir: join(tmp, "c2"), walkCacheDir: join(tmp, "w2"), denyFile, gitSession: session });
    } finally {
      session.close();
    }
    assert.equal(perCall.blobs, 12, "v1-v4 of each of three repositories");
    assert.equal(shape(viaSession), shape(perCall), "the same twins, versions and locked ids");
    assert.deepEqual(packNames(viaSession), packNames(perCall), "each sanitized pack lists the same objects");
    // The step's own session when the caller passes none (closed at its end).
    const own = await prepareGitObjectTwins(secrets, { cacheDir: join(tmp, "c3"), walkCacheDir: join(tmp, "w3"), denyFile });
    assert.equal(shape(own), shape(perCall));

    const sb = gitSandbox();
    if (sb === null || isSeatbeltGitSandbox(sb)) {
      t.diagnostic("SKIP the one-sandbox and runner-death checks: no bubblewrap git sandbox here (the session ran per call)");
      return;
    }
    if (!sessionAllowed(hostPtraceScope())) {
      assert.equal(session.stats.sandboxes, 0, "Yama scope 0 or absent: never a shared sandbox");
      t.diagnostic("SKIP the one-sandbox and runner-death checks: Yama ptrace_scope below 1 here (one sandbox per call)");
      return;
    }
    assert.equal(session.stats.sandboxes, 1, JSON.stringify(session.stats));
    assert.ok(session.stats.inSession > 10, `the reads ran in the session (${JSON.stringify(session.stats)})`);
    assert.ok(session.stats.perCall > 0, "the pack builds (they write the cache) ran one sandbox each");

    // The runner killed under the step, a strict read in flight: refused.
    const dying = openGitSession();
    try {
      const run = dying.runner();
      assert.equal((await run(["version"], { cwd: tmp })).code, 0, "the sandbox is up");
      let killed = false;
      const killing: GitRunner = (a, o) => {
        if (!killed && a[0] === "rev-list" && a[1] === "--all") {
          killed = true;
          process.kill(-dying.runnerPid!, "SIGKILL");
        }
        return run(a, o);
      };
      await assert.rejects(
        prepareGitObjectTwins(secrets, { cacheDir: join(tmp, "c4"), walkCacheDir: join(tmp, "w4"), denyFile, git: killing }),
        (e: Error) => /the git sandbox ended/.test(e.message),
      );
      assert.ok(killed);
    } finally {
      dying.close();
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("a version no launch's walk found (history cut before the first walk, a tree in no ref, a blob written by plumbing) is unreadable by id through the real wrap (store-scan.ts)", async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-gitobj-scan-"));
  try {
    const ws = join(tmp, "ws");
    git(tmp, "init", "-q", "-b", "main", ws);
    writeFileSync(join(ws, "README"), "README-ONE\n");
    const env = (text: string): void => { writeFileSync(join(ws, ".env"), text); git(ws, "add", "-A"); };
    const plumb = (args: string[], input: string): string => execFileSync("git", args, { cwd: ws, input, encoding: "utf8", env: ENV }).trim();
    env(`TOKEN=${canary(1)}\n`);
    git(ws, "commit", "-qm", "one");
    env(`TOKEN=${canary(2)}\n`);
    git(ws, "commit", "-qm", "two");
    // The history cut before any launch: an orphan branch, the old one and
    // the reflogs gone, the old objects packed with the unreachable kept.
    git(ws, "checkout", "-q", "--orphan", "fresh");
    env(`TOKEN=${canary(3)}\nPASSWORD=${canary(9)}\n`);
    git(ws, "commit", "-qm", "fresh");
    git(ws, "branch", "-D", "main");
    git(ws, "reflog", "expire", "--expire=now", "--all");
    git(ws, "repack", "-adkq");
    // A tree in no ref, and a blob written by plumbing sharing a credential.
    const v4 = plumb(["hash-object", "-w", "--stdin"], `TOKEN=${canary(4)}\n`);
    const readme = git(ws, "rev-parse", "HEAD:README").trim();
    plumb(["mktree"], `100644 blob ${v4}\t.env\n100644 blob ${readme}\tREADME\n`);
    const v5 = plumb(["hash-object", "-w", "--stdin"], `TOKEN=${canary(5)}\nPASSWORD=${canary(9)}\n`);
    const hidden = [plumb(["hash-object", "--stdin"], `TOKEN=${canary(1)}\n`), plumb(["hash-object", "--stdin"], `TOKEN=${canary(2)}\n`), v4, v5];
    for (const h of hidden) assert.equal(git(ws, "cat-file", "-t", h).trim(), "blob", "precondition: the store holds it");
    const denyFile = join(tmp, "denied");
    writeFileSync(denyFile, "");
    chmodSync(denyFile, 0o000);
    const got = await prepareGitObjectTwins([join(ws, ".env")], { cacheDir: join(tmp, "cache"), denyFile, walkCacheDir: join(tmp, "walks"), seals: memorySeals() });
    for (const h of hidden) assert.ok(got.lockedIds!.includes(`sha1:${h}`), `${h} locked`);
    if (!bwrapWorks()) {
      t.diagnostic("SKIP the wrapped read: bwrap cannot start here");
      return;
    }
    const wrap = withObjectTwins(["bwrap", "--dev-bind", "/", "/", "--cap-drop", "ALL", "--"], got.twins, []);
    const inWrap = (...args: string[]) => spawnSync(wrap[0]!, [...wrap.slice(1), "git", ...args], { cwd: ws, encoding: "utf8", env: ENV, timeout: 60_000 });
    const byId = hidden.map((h) => inWrap("cat-file", "-p", h));
    const all = inWrap("cat-file", "--batch-all-objects", "--batch");
    const everything = [...byId, all].map((r) => `${r.stdout}${r.stderr}`).join("\n");
    for (const v of [1, 2, 4, 5]) assert.ok(!everything.includes(canary(v)), `version ${v} never reaches the wrapped git`);
    for (const r of byId) assert.notEqual(r.status, 0, "a hidden version is a missing object");
    assert.equal(inWrap("show", "HEAD:README").stdout, "README-ONE\n", "every other object reads as before");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
