/**
 * git-hardening e2e — no program a repository names runs when MANDU reads
 * the repository (docs/design/architecture/write-protection.md §8.7, the sandbox-escape
 * oracle).
 *
 * The launcher, the arbiter, the dashboard and fs-sync run git outside every
 * sandbox, on repositories an agent can write. An agent in a confined
 * session can plant a program in `.git/config` (and name it for a path in
 * `.gitattributes`); if Mandu's git started it, it would run UNCONFINED. The
 * fixture (tests/lib/hostile-git-repo.ts) points every config key and
 * attribute git knows that starts a program at a MARKER. Each Mandu call path
 * below runs, through the production code and its default git runner, over
 * that repository, and the markers directory must stay empty:
 *
 *   - launch prep: `prepareGitObjectTwins` (history walk, label walk, index,
 *     the working copies' hashes, the object inventory, the pack rebuild),
 *     the net guard's remote read, `mandu revert`'s work-tree probe;
 *   - the arbiter, through the REAL data socket (ArbiterServer +
 *     ArbiterClient): `registerRepository`, `gitHistoryLocks {roots}` (the
 *     lock resolver), `scanSecretHistory` (`mandu doctor --secrets`),
 *     `suggestPolicy`; and its start-up `gitRevOf`;
 *   - the arbiter's prepared copies (plan 14 §11.1 R3): a known repository
 *     holding a locked version (packed), one preparation cycle (the
 *     inventory, the private bare repository, `pack-objects`,
 *     `index-pack`); the copy holds every other object, is sealed with its
 *     bytes, and git over it reads the history but not the locked version;
 *   - the dashboard's self-status rev reads (the developer view's commit
 *     list, commit detail and file browser are dashboard-dev-git-hardening's);
 *   - fs-sync's git runner and ignore check (the frozen axis: the parts `-c`
 *     closes);
 *   - a partial clone with a missing blob: the scan, its blob reader and the
 *     launch prep, with no lazy fetch (its ssh transport is a marker).
 *
 * The control: a stock git over the same repository springs the traps
 * (`unhardenedFires`), so an empty markers directory means Mandu's git, not
 * a dud fixture. The git SANDBOX is off here (MANDU_GIT_SANDBOX=0): its
 * read-only filesystem would stop a marker from writing, and it is the
 * hardening that is under test; the sandbox has its own kernel test
 * (launcher/test/kernel/git-sandbox.test.ts).
 *
 * Axes stated: secrets (the history-lock and scan ops answer only with
 * confidentiality ON).
 */
process.env["MANDU_GIT_SANDBOX"] = "0";

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, copyFileSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";

import { stateAxes } from "../lib/axes.js";
import { hostileRepo, unhardenedFires, type HostileRepo } from "../lib/hostile-git-repo.js";
import { prepareGitObjectTwins } from "../../launcher/src/git-object-twins.js";
import { readGitRemotes } from "../../launcher/src/net-guard-setup.js";
import { realRevertDeps } from "../../launcher/src/revert-command.js";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { gitRevOf } from "../../arbiter/ipc/instance.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { defaultBlobReader, scanSecretHistory } from "../../arbiter/policy/secret-history-scan.js";
import { idxObjectNames } from "../../arbiter/policy/prepared-copies.js";
import { gitChangedFiles, gitShortRev } from "../../dashboard/src/self-status.js";
import { gitExecSync } from "../../fs-sync/src/git.js";
import { humanIgnoredSet } from "../../fs-sync/src/ignored.js";

stateAxes("secrets");

const repos: HostileRepo[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const r of repos) r.cleanup();
});
function fresh(opts: { promisor?: boolean; packed?: boolean } = {}): HostileRepo {
  const r = hostileRepo(opts);
  repos.push(r);
  return r;
}

/** Nothing the repository names ran. */
function quiet(r: HostileRepo, what: string): void {
  assert.deepEqual(r.fired(), [], `${what} started a program the repository named`);
}

test("control: a stock git over the hostile repository springs its traps", () => {
  const r = fresh();
  const f = (args: string[], input?: string) => unhardenedFires(r, args, input);
  assert.ok(f(["log", "--format=%H", "-1", "HEAD~1"]).includes("gpg"), "log.showSignature hands the signed commit to gpg.program");
  assert.ok(f(["ls-files", "-s"]).some((m) => m.startsWith("fsmonitor")), "an index read starts core.fsmonitor");
  assert.ok(f(["hash-object", "--", r.crlfRel]).includes("filter-clean"), "hash-object runs the clean filter");
  assert.ok(f(["status", "--porcelain"]).some((m) => m.startsWith("filter-")), "status re-hashes a stat-dirty file through the filter");
  assert.ok(f(["check-ignore", "-z", "--stdin"], "x\0").some((m) => m.startsWith("fsmonitor")), "check-ignore reads the index");
});

test("launch prep: the object twins (walks, index, working-copy hashes, pack rebuild), the net guard's remotes and revert's probe start nothing", async () => {
  const r = fresh();
  const cacheDir = join(r.dir, "cache");
  const walkCacheDir = join(r.dir, "walks");
  mkdirSync(cacheDir);
  const denyFile = join(r.dir, "deny");
  closeSync(openSync(denyFile, "w", 0o000));
  const labels = [{ path: join(r.root, r.goneRel), level: "no-model", recursive: false }];
  // Loose objects first, then packed (the pack rebuild runs pack-objects).
  for (const round of ["loose", "packed"]) {
    const got = await prepareGitObjectTwins([realpathSync(join(r.root, r.secretRel))], { cacheDir, denyFile, walkCacheDir, labels });
    assert.equal(got.repos, 1, `${round}: the repository holds protected versions`);
    assert.ok(got.blobs >= 3, `${round}: the secret's versions, its working copy and the gone key are protected (${got.blobs})`);
    quiet(r, `prepareGitObjectTwins (${round})`);
    if (round === "loose") {
      // Pack with a stock git that springs nothing (no hooks, no gc driver).
      unhardenedFires(r, ["-c", "core.fsmonitor=false", "repack", "-adq"]);
    }
  }
  assert.deepEqual(readGitRemotes(r.root), ["ssh://mandu-test.invalid/hostile.git"]);
  quiet(r, "the net guard's remote read");
  assert.equal(realRevertDeps({} as never, process.env).gitRoot(r.root), r.root);
  quiet(r, "mandu revert's work-tree probe");
});

test("the arbiter's data-plane ops (registerRepository, gitHistoryLocks roots, scanSecretHistory, suggestPolicy) and gitRevOf start nothing", async () => {
  const r = fresh();
  const home = join(r.dir, "home");
  mkdirSync(home);
  const sock = join(r.dir, "a.sock");
  const doc = { version: 1, paths: [{ path: join(r.root, r.goneRel), level: "no-model" }] };
  const s = new ArbiterServer({
    socketPath: sock, dbPath: join(r.dir, "db.sqlite"), eventDir: join(r.dir, "ev"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0, policyDocument: doc as never,
    lockResolution: { home, selfDir: null },
  });
  await s.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  try {
    const reg = await data.registerRepository(r.root);
    assert.equal(reg.root, r.root);
    quiet(r, "registerRepository");

    const t0 = Date.now();
    let locks = await data.gitHistoryLocks([r.root]);
    while (!(locks.complete && locks.repos.some((x) => x.root === r.root))) {
      assert.ok(Date.now() - t0 < 30_000, `not resolved in 30 s: ${JSON.stringify({ pending: locks.pending })}`);
      await new Promise((res) => setTimeout(res, 50));
      locks = await data.gitHistoryLocks([r.root]);
    }
    assert.equal(locks.repos.find((x) => x.root === r.root)!.blobs.length, 1, "the gone key's version is resolved");
    quiet(r, "gitHistoryLocks (the lock resolver)");

    const scan = await data.scanSecretHistory([r.root], home);
    assert.ok(scan.findings.length > 0, "the token in the history is found (the trace walk runs git log)");
    quiet(r, "scanSecretHistory");

    const sug = await data.suggestPolicy([r.root], { home, waitMs: 30_000 });
    assert.equal(sug.axis, true);
    quiet(r, "suggestPolicy");
  } finally {
    data.close();
    await s.close();
  }
  const rev = gitRevOf(r.root);
  assert.match(rev.rev, /^[0-9a-f]{4,}$/);
  assert.equal(rev.dirty, true, "untracked and stat-changed files read as dirty");
  quiet(r, "gitRevOf");
});

test("R3, the arbiter's prepared copies: a known repository with a locked version, a preparation cycle; nothing starts, the copy is correct and sealed", async () => {
  const r = fresh({ packed: true });
  const home = join(r.dir, "home");
  mkdirSync(home);
  const sock = join(r.dir, "p.sock");
  const humanSock = join(r.dir, "h", "h.sock");
  const cacheDir = join(r.dir, "prep-cache", "object-twins");
  const doc = { version: 1, paths: [{ path: join(r.root, r.goneRel), level: "no-model" }] };
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(r.dir, "p.sqlite"), eventDir: join(r.dir, "p-ev"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0, policyDocument: doc as never, packDir: null,
    lockResolution: { home, selfDir: null },
    preparedCopies: { cacheDir },
  });
  await s.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  try {
    // Known (as the guard registers a repository on a refusal), resolved,
    // then one preparation cycle: the inventory's rev-parse, the private
    // bare repository's init, pack-objects and index-pack.
    assert.equal((await data.registerRepository(r.root)).added, true);
    await s.prepareCopiesNow();
    const locks = await data.gitHistoryLocks();
    assert.ok(locks.lockedSet.sha1.includes(r.goneBlob), "the gone key's version is in the global locked set");
    assert.deepEqual((locks.prepared ?? []).map((p) => p.root), [r.root], "the hostile repository is prepared");
    assert.deepEqual(locks.preparation?.failed, []);
    quiet(r, "the prepared copies' cycle (inventory, init, pack-objects, index-pack)");

    // The copy: exactly the source pack's objects without the locked one,
    // each file sealed in the current epoch with its bytes on disk.
    const srcDir = join(r.root, ".git", "objects", "pack");
    const srcIdx = readdirSync(srcDir).filter((n) => n.endsWith(".idx"));
    assert.equal(srcIdx.length, 1);
    const want = idxObjectNames(readFileSync(join(srcDir, srcIdx[0]!))).filter((o) => o !== r.goneBlob).sort();
    const keys = readdirSync(cacheDir).filter((n) => /^[0-9a-f]{32}$/.test(n));
    assert.equal(keys.length, 1, "one copy, of the one pack");
    const files = readdirSync(join(cacheDir, keys[0]!)).sort();
    assert.deepEqual(files.map((n) => n.slice(n.lastIndexOf("."))), [".idx", ".pack", ".rev"]);
    const idxName = files.find((n) => n.endsWith(".idx"))!;
    assert.deepEqual(idxObjectNames(readFileSync(join(cacheDir, keys[0]!, idxName))).sort(), want, "the copy holds every other object");
    const sealed = await human.cacheSeals("object-twin", files.map((n) => `${keys[0]}/${n}`));
    assert.equal(sealed.honoured, true);
    for (const n of files) {
      const seal = sealed.seals.find((x) => x.key === `${keys[0]}/${n}`);
      assert.ok(seal, `${n} is sealed`);
      assert.equal(seal.sha256, createHash("sha256").update(readFileSync(join(cacheDir, keys[0]!, n))).digest("hex"), `${n}: sealed with its bytes`);
    }
    // git over the copy alone (a clean probe repository, not the hostile
    // one): the history reads, the locked version does not.
    const probe = join(r.dir, "probe.git");
    const env = { PATH: process.env["PATH"] ?? "/usr/bin:/bin", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
    execFileSync("git", ["init", "-q", "--bare", probe], { env });
    for (const n of files) copyFileSync(join(cacheDir, keys[0]!, n), join(probe, "objects", "pack", n));
    const head = readFileSync(join(r.root, ".git", "refs", "heads", "main"), "utf8").trim();
    assert.match(execFileSync("git", ["--git-dir", probe, "cat-file", "-p", head], { env, encoding: "utf8" }), /^tree /);
    assert.throws(() => execFileSync("git", ["--git-dir", probe, "cat-file", "-p", r.goneBlob], { env, stdio: "pipe" }));
    quiet(r, "reading the copy");
  } finally {
    data.close();
    human.close();
    await s.close();
  }
});

test("the dashboard's self-status and fs-sync's git start nothing", () => {
  const r = fresh();
  assert.match(gitShortRev(r.root), /^[0-9a-f]+$/);
  assert.deepEqual(gitChangedFiles(r.root, "HEAD~1", "HEAD", r.root), ["config.env", "deploy/id_rsa"]);
  quiet(r, "the dashboard's self-status");

  const ctx = { cwd: r.root };
  assert.ok(gitExecSync(["ls-files", "-s"], ctx).stdout.includes(r.secretRel));
  assert.ok(gitExecSync(["log", "--format=%H %s"], ctx).stdout.includes("signed"));
  humanIgnoredSet(ctx, ["node_modules/x", r.secretRel]);
  quiet(r, "fs-sync's git runner and ignore check");
});

test("a partial clone with a missing blob: the scan, its blob reader and the launch prep never lazily fetch (the ssh transport is a marker)", async () => {
  const r = fresh({ promisor: true });
  assert.ok(unhardenedFires(r, ["cat-file", "--batch"], "0000000000000000000000000000000000000001\n").includes("ssh"),
    "control: a stock git fetches a missing object from the promisor remote over ssh");
  await scanSecretHistory([r.root]).catch(() => null);
  quiet(r, "scanSecretHistory on a partial clone");
  await defaultBlobReader(r.root, ["0000000000000000000000000000000000000001"], { timeoutMs: 20_000 });
  quiet(r, "the scan's blob reader on a missing object");
  const cacheDir = join(r.dir, "cache");
  mkdirSync(cacheDir);
  const denyFile = join(r.dir, "deny");
  closeSync(openSync(denyFile, "w", 0o000));
  await prepareGitObjectTwins([realpathSync(join(r.root, r.secretRel))], {
    cacheDir, denyFile, labels: [{ path: join(r.root, "old.txt"), level: "no-model", recursive: false }], continueOnFailure: true,
  }).catch(() => null);
  quiet(r, "prepareGitObjectTwins on a partial clone");
});
