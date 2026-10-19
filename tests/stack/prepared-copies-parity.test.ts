/**
 * Parity and e2e — the copies the arbiter prepares ahead of time
 * (confidentiality-plan-14 §11.1 R3) over the PRODUCTION wiring: the
 * launcher's socket adapter (`socketSecretArbiter(sock, { humanSock })`,
 * what applySecretTwins calls: its `gitHistoryLocks` read through
 * `asGitHistoryLocks`, its seal ops turned into the twins' seal client by
 * `sealClientOf`) against a REAL ArbiterServer with its human socket, its
 * lock resolution and its preparation, over REAL repositories:
 *
 *   - the arbiter's ported pack code keys a copy as the launcher does
 *     (`rebuildKey`, `idxLookup` over one corpus);
 *   - a repository A holding a locked id, registered: the arbiter prepares
 *     and seals its copy; the adapter's answer lists A `prepared`; the
 *     launcher's `preparedCopyTwins` verifies the copy against the seals by
 *     hash and binds it (pack, idx, rev); the copy git reads has every
 *     object but the locked one, and holds no byte of the key;
 *   - the launcher's own twins for A (A the workspace, the global set
 *     passed) take the arbiter's copy as a cache hit: the two build paths
 *     share the key and the seal;
 *   - a launch whose locked set is not the one the copy was prepared for
 *     (an id more that the pack holds) binds nothing (the backstop keeps
 *     A); a copy replaced under its seal is refused, reported, and rebuilt
 *     by the arbiter at its next cycle;
 *   - the alternates closure is ONE file in both packages (git-alternates.ts,
 *     held byte-identical here), and an A <- B <- C chain of `clone
 *     --shared` repositories with only C registered gets a copy of every
 *     pack C reads, A's two links away keyed by the union of the locked
 *     versions it holds, which the launcher binds for C
 *     (confidentiality.md §7.2a "Stores shared through alternates").
 *
 * The kernel oracle through a real confined launch in another repository
 * is tests/sandbox/git-history-locks.test.ts (K9-K11).
 * Axes stated: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { inflateSync } from "node:zlib";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { idxLookup as arbiterIdxLookup, rebuildKey as arbiterRebuildKey } from "../../arbiter/policy/prepared-copies.js";
import { objectStoreClosure as arbiterClosure } from "../../arbiter/src/git-alternates.js";
import { asGitHistoryLocks, sealClientOf, socketSecretArbiter } from "../../launcher/src/secret-setup.js";
import {
  idxLookup as launcherIdxLookup, keepCopiesInUse, objectStoreClosure as launcherClosure, preparedCopyTwins, prepareGitObjectTwins, servedCopyDirs,
  rebuildKey as launcherRebuildKey,
} from "../../launcher/src/git-object-twins.js";
import { lockedIdsOf } from "../../launcher/src/git-lock-backstop.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the confidentiality axis is what the locks and the copies serve

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...a: string[]): string => execFileSync("git", a, { cwd, encoding: "utf8", env: ENV });
const KEY = ["PARITY", "PREPARED", "COPY", "KEY", "Jm".repeat(14)].join("_");

function inflated(buf: Buffer): string {
  let out = "";
  for (let i = 12; i < buf.length - 2; i++) {
    if (buf[i] !== 0x78) continue;
    try { out += `${inflateSync(buf.subarray(i)).toString("latin1")}\n`; } catch { /* not a stream start */ }
  }
  return out;
}

interface Rig {
  dir: string; a: string; blob: string; readme: string; sock: string; humanSock: string; cacheDir: string; denyFile: string;
  server: ArbiterServer; admin: ArbiterClient; data: ArbiterClient; close: () => Promise<void>;
}

async function rig(): Promise<Rig> {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-prep-parity-")));
  const a = join(dir, "a");
  git(dir, "init", "-q", "-b", "main", a);
  writeFileSync(join(a, "README"), "readme of a\n");
  writeFileSync(join(a, "id_rsa"), `${KEY}\n`);
  git(a, "add", "."); git(a, "commit", "-qm", "1");
  const blob = git(a, "rev-parse", "HEAD:id_rsa").trim();
  const readme = git(a, "rev-parse", "HEAD:README").trim();
  git(a, "rm", "-q", "id_rsa"); git(a, "commit", "-qm", "2");
  git(a, "repack", "-adq");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  const adminSock = join(dir, "admin.sock");
  const cacheDir = join(dir, "home", ".mandu", "cache", "object-twins");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0, packDir: null,
    lockResolution: { home: join(dir, "no-home"), selfDir: null },
    preparedCopies: { cacheDir },
  });
  await server.listen();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  const data = new ArbiterClient(sock);
  await data.connect();
  const denyFile = join(dir, "denied");
  writeFileSync(denyFile, "");
  chmodSync(denyFile, 0o000);
  return {
    dir, a, blob, readme, sock, humanSock, cacheDir, denyFile, server, admin, data,
    close: async () => { admin.close(); data.close(); await server.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

test("parity: the arbiter's ported pack code keys and looks up a copy exactly as the launcher does", () => {
  const cases: Array<[string, string[]]> = [
    ["/r/.git/objects/pack/pack-" + "1".repeat(40), ["a".repeat(40)]],
    ["/r/.git/objects/pack/pack-" + "2".repeat(64), ["f".repeat(64), "0".repeat(64)]],
    ["pack-x", []],
    ["/x/pack-" + "3".repeat(40), ["c".repeat(40), "b".repeat(40), "c".repeat(40)]],
  ];
  for (const [base, ex] of cases) assert.equal(arbiterRebuildKey(base, ex), launcherRebuildKey(base, ex), base);
  // One real index, looked up by both.
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-prep-idx-")));
  try {
    const r = join(dir, "r");
    git(dir, "init", "-q", r);
    for (let i = 0; i < 40; i++) writeFileSync(join(r, `f${i}`), `file ${i}\n`);
    git(r, "add", "."); git(r, "commit", "-qm", "x"); git(r, "repack", "-adq");
    const packDir = join(r, ".git", "objects", "pack");
    const idx = readFileSync(join(packDir, readdirSync(packDir).find((n) => n.endsWith(".idx"))!));
    const read = (o: number, l: number): Buffer => idx.subarray(o, o + l);
    const names = [...git(r, "ls-tree", "HEAD").split("\n").filter(Boolean).map((l) => l.split(/\s+/)[2]!).slice(0, 7), "e".repeat(40), "0".repeat(40)];
    assert.deepEqual(arbiterIdxLookup(read, names), launcherIdxLookup(read, names));
    assert.equal(arbiterIdxLookup(read, names).length, 7);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("e2e: a copy the arbiter prepared is listed by the production adapter, verified by hash against its seal, and bound; the launcher's own twins take it as a cache hit", async () => {
  const r = await rig();
  try {
    const applied = await r.admin.policyPropose({ edits: [{ op: "lock-blob", blob: `sha1:${r.blob}`, level: "no-model" }], reason: "R3", requestedBy: "dashboard" });
    assert.equal((applied as { applied?: boolean }).applied, true, JSON.stringify(applied));
    const adapter = socketSecretArbiter(r.sock, { humanSock: r.humanSock });
    assert.equal((await r.data.registerRepository(r.a)).added, true);
    await r.server.prepareCopiesNow();

    const locks = asGitHistoryLocks(await adapter.gitHistoryLocks!([]));
    assert.deepEqual(locks.prepared, [{ root: r.a, format: "sha1" }], "the adapter reads A as prepared");
    const lockedIds = lockedIdsOf({ blobs: locks.blobs, ...(locks.lockedSet ? { lockedSet: locks.lockedSet } : {}) });
    assert.deepEqual(lockedIds, [`sha1:${r.blob}`]);
    const seals = sealClientOf(adapter)!;
    const logs: string[] = [];
    const got = await preparedCopyTwins(locks.prepared!, { cacheDir: r.cacheDir, denyFile: r.denyFile, lockedIds, seals, log: (m) => logs.push(m) });
    assert.deepEqual(got.bound, [r.a], JSON.stringify({ got, logs }));
    assert.deepEqual(got.notReady, []);
    const exts = got.twins.map((t) => t.targetPath.slice(t.targetPath.lastIndexOf("."))).sort();
    assert.deepEqual(exts, [".idx", ".pack", ".rev"]);
    for (const t of got.twins) {
      assert.equal(t.kind, "object");
      assert.ok(t.twinPath.startsWith(`${r.cacheDir}/`), "served from the shared cache");
      assert.ok(t.targetPath.startsWith(join(r.a, ".git", "objects", "pack")));
    }
    const served = got.twins.find((t) => t.targetPath.endsWith(".pack"))!.twinPath;
    assert.ok(!inflated(readFileSync(served)).includes(KEY), "the copy holds no byte of the key");
    // git over the copy: the other objects read, the locked one does not.
    const probe = join(r.dir, "probe");
    git(r.dir, "init", "-q", "--bare", probe);
    for (const t of got.twins) writeFileSync(join(probe, "objects", "pack", t.twinPath.slice(t.twinPath.lastIndexOf("/") + 1)), readFileSync(t.twinPath));
    assert.equal(execFileSync("git", ["--git-dir", probe, "cat-file", "-p", r.readme], { env: ENV, encoding: "utf8" }), "readme of a\n");
    assert.throws(() => execFileSync("git", ["--git-dir", probe, "cat-file", "-p", r.blob], { env: ENV, stdio: "pipe" }));

    // The launcher's own build path (A as the workspace, the global set
    // passed): the same key, the same seal, a cache hit.
    const own = await prepareGitObjectTwins([], {
      cacheDir: r.cacheDir, denyFile: r.denyFile, walkCacheDir: join(r.dir, "walks"), seals,
      blobLocks: locks.blobs.map((b) => b.id), globalLocked: lockedIds, repoHints: [r.a],
    });
    assert.equal(own.packsRebuilt, 0, "nothing rebuilt");
    assert.equal(own.cacheHits, 1, "the arbiter's copy is the launcher's cache hit");
    assert.equal(own.twins.find((t) => t.targetPath.endsWith(".pack"))!.twinPath, served);
    assert.ok(own.roots?.includes(r.a));
    // With A prepared by the launch itself, the prepared pass leaves it alone.
    const skipped = await preparedCopyTwins(locks.prepared!, { cacheDir: r.cacheDir, denyFile: r.denyFile, lockedIds, seals, skipRoots: new Set(own.roots) });
    assert.deepEqual(skipped.bound, []);
  } finally {
    await r.close();
  }
});

test("e2e: a launch whose locked set is not the copy's binds nothing; a copy replaced under its seal is refused, reported, and rebuilt by the arbiter", async () => {
  const r = await rig();
  try {
    await r.admin.policyPropose({ edits: [{ op: "lock-blob", blob: `sha1:${r.blob}`, level: "no-model" }], reason: "R3", requestedBy: "dashboard" });
    const adapter = socketSecretArbiter(r.sock, { humanSock: r.humanSock });
    await r.data.registerRepository(r.a);
    await r.server.prepareCopiesNow();
    const locks = asGitHistoryLocks(await adapter.gitHistoryLocks!([]));
    const seals = sealClientOf(adapter)!;
    const lockedIds = [`sha1:${r.blob}`];
    // One id more that the pack holds (this launch resolved a version the
    // arbiter has not yet): the copy still holds it, so it is not the one.
    const more = await preparedCopyTwins(locks.prepared!, { cacheDir: r.cacheDir, denyFile: r.denyFile, lockedIds: [...lockedIds, `sha1:${r.readme}`], seals });
    assert.deepEqual(more.bound, []);
    assert.match(more.notReady[0]!.reason, /not prepared yet/);
    // An unconfined writer replaces the copy's pack with the real pack's bytes.
    const good = await preparedCopyTwins(locks.prepared!, { cacheDir: r.cacheDir, denyFile: r.denyFile, lockedIds, seals });
    const served = good.twins.find((t) => t.targetPath.endsWith(".pack"))!.twinPath;
    const realDir = join(r.a, ".git", "objects", "pack");
    rmSync(served);
    writeFileSync(served, readFileSync(join(realDir, readdirSync(realDir).find((n) => n.endsWith(".pack"))!)));
    assert.ok(inflated(readFileSync(served)).includes(KEY), "precondition: the planted pack holds the key");
    const logs: string[] = [];
    const planted = await preparedCopyTwins(locks.prepared!, { cacheDir: r.cacheDir, denyFile: r.denyFile, lockedIds, seals, log: (m) => logs.push(m) });
    assert.deepEqual(planted.bound, [], "the planted copy is never bound");
    assert.match(planted.notReady[0]!.reason, /not sealed/);
    assert.ok(logs.some((l) => /did not match its seal/.test(l)), logs.join("\n"));
    // The arbiter heard the rejection and rebuilds the copy at its next cycle.
    await r.server.prepareCopiesNow();
    const rebuilt = await preparedCopyTwins(locks.prepared!, { cacheDir: r.cacheDir, denyFile: r.denyFile, lockedIds, seals });
    assert.deepEqual(rebuilt.bound, [r.a]);
    assert.ok(!inflated(readFileSync(rebuilt.twins.find((t) => t.targetPath.endsWith(".pack"))!.twinPath)).includes(KEY));
  } finally {
    await r.close();
  }
});

test("the two copies of git-alternates.ts (the launcher's twins and the arbiter's prepared copies read one closure) are byte-identical", () => {
  // confidentiality.md §7.2a: a pack one of them reaches and the other does
  // not is a pack with no sanitized copy.
  assert.equal(
    readFileSync(join(ROOT, "arbiter", "src", "git-alternates.ts"), "utf8"),
    readFileSync(join(ROOT, "launcher", "src", "git-alternates.ts"), "utf8"),
    "arbiter/src/git-alternates.ts drifted from launcher/src/git-alternates.ts; copy the launcher's file out again",
  );
});

test("e2e: an A ← B ← C chain (clone --shared twice), C registered alone: the arbiter prepares every pack C reads, A's two links away excluding the union; the launcher's closure is the arbiter's and it binds them all for C", async () => {
  const r = await rig();
  try {
    // A (the rig's) holds X; one more version, W, goes into A's pack too.
    const commitKey = (root: string, file: string, body: string): string => {
      writeFileSync(join(root, file), `${body}\n`);
      git(root, "add", "."); git(root, "commit", "-qm", `add ${file}`);
      const id = git(root, "rev-parse", `HEAD:${file}`).trim();
      git(root, "rm", "-q", file); git(root, "commit", "-qm", `remove ${file}`);
      return id;
    };
    const keyW = KEY.replace("PARITY", "WIDER");
    const keyB = KEY.replace("PARITY", "BLINK");
    const keyC = KEY.replace("PARITY", "CLINK");
    const w = commitKey(r.a, "staging.env", keyW);
    git(r.a, "repack", "-adq");
    const b = join(r.dir, "b");
    git(r.dir, "clone", "-q", "--shared", r.a, b);
    const y = commitKey(b, "id_b", keyB);
    git(b, "repack", "-adlq");
    const c = join(r.dir, "c");
    git(r.dir, "clone", "-q", "--shared", b, c);
    const z = commitKey(c, "id_c", keyC);
    git(c, "repack", "-adlq");
    const objs = (root: string): string => join(root, ".git", "objects");
    const packOf = (root: string): string => {
      const d = join(objs(root), "pack");
      return join(d, readdirSync(d).find((n) => n.endsWith(".pack"))!.slice(0, -5));
    };
    assert.deepEqual(launcherClosure(objs(c)), [objs(c), objs(b), objs(r.a)], "the launcher reaches A through B's file");
    assert.deepEqual(arbiterClosure(objs(c)), launcherClosure(objs(c)), "and the arbiter the same");

    const ids = [r.blob, w, y, z];
    const applied = await r.admin.policyPropose({
      edits: ids.map((id) => ({ op: "lock-blob" as const, blob: `sha1:${id}`, level: "no-model" })), reason: "R3 chain", requestedBy: "dashboard",
    });
    assert.equal((applied as { applied?: boolean }).applied, true, JSON.stringify(applied));
    const adapter = socketSecretArbiter(r.sock, { humanSock: r.humanSock });
    assert.equal((await r.data.registerRepository(c)).added, true);
    await r.server.prepareCopiesNow();
    const locks = asGitHistoryLocks(await adapter.gitHistoryLocks!([]));
    assert.deepEqual(locks.prepared, [{ root: c, format: "sha1" }], "C alone is known, and prepared");
    const keys = readdirSync(r.cacheDir).filter((n) => /^[0-9a-f]{32}$/.test(n)).sort();
    assert.deepEqual(keys, [
      launcherRebuildKey(packOf(r.a), [r.blob, w]), launcherRebuildKey(packOf(b), [y]), launcherRebuildKey(packOf(c), [z]),
    ].sort(), "one copy per pack C reads; A's keyed by the union of the locked versions it holds");

    const lockedIds = lockedIdsOf({ blobs: locks.blobs, ...(locks.lockedSet ? { lockedSet: locks.lockedSet } : {}) });
    const logs: string[] = [];
    const got = await preparedCopyTwins(locks.prepared!, { cacheDir: r.cacheDir, denyFile: r.denyFile, lockedIds, seals: sealClientOf(adapter)!, log: (m) => logs.push(m) });
    assert.deepEqual(got.bound, [c], JSON.stringify({ got, logs }));
    const packs = got.twins.filter((t) => t.targetPath.endsWith(".pack"));
    assert.deepEqual(packs.map((t) => t.targetPath).sort(), [packOf(r.a), packOf(b), packOf(c)].map((p) => `${p}.pack`).sort());
    // git over the three copies: every other object reads, no locked one does.
    const probe = join(r.dir, "probe-chain");
    git(r.dir, "init", "-q", "--bare", probe);
    for (const t of got.twins) {
      assert.ok(t.twinPath.startsWith(`${r.cacheDir}/`), t.targetPath);
      writeFileSync(join(probe, "objects", "pack", t.twinPath.slice(t.twinPath.lastIndexOf("/") + 1)), readFileSync(t.twinPath));
      for (const key of [KEY, keyW, keyB, keyC]) assert.ok(!inflated(readFileSync(t.twinPath)).includes(key), `${t.targetPath}: no byte of a key`);
    }
    assert.equal(execFileSync("git", ["--git-dir", probe, "cat-file", "-p", r.readme], { env: ENV, encoding: "utf8" }), "readme of a\n");
    git(probe, "cat-file", "-e", git(c, "rev-parse", "HEAD").trim());
    for (const id of ids) assert.throws(() => execFileSync("git", ["--git-dir", probe, "cat-file", "-p", id], { env: ENV, stdio: "pipe" }), id);
  } finally {
    await r.close();
  }
});

test("e2e (plan 14 §11.1 R3 (a)): a lock added mid-session gives the pack a new key; the copy the running launch serves is kept while it marks it used (keepCopiesInUse), and pruned past the grace once the session ends", async () => {
  const r = await rig();
  try {
    await r.admin.policyPropose({ edits: [{ op: "lock-blob", blob: `sha1:${r.blob}`, level: "no-model" }], reason: "R3a", requestedBy: "dashboard" });
    const adapter = socketSecretArbiter(r.sock, { humanSock: r.humanSock });
    await r.data.registerRepository(r.a);
    await r.server.prepareCopiesNow();
    const locks = asGitHistoryLocks(await adapter.gitHistoryLocks!([]));
    const got = await preparedCopyTwins(locks.prepared!, { cacheDir: r.cacheDir, denyFile: r.denyFile, lockedIds: [`sha1:${r.blob}`], seals: sealClientOf(adapter)! });
    assert.deepEqual(got.bound, [r.a]);
    const packDir = join(r.a, ".git", "objects", "pack");
    const packOf = (_root: string): string => join(packDir, readdirSync(packDir).find((n) => n.endsWith(".pack"))!.slice(0, -5));
    const served = servedCopyDirs(got.twins, r.cacheDir);
    assert.deepEqual(served, [join(r.cacheDir, launcherRebuildKey(packOf(r.a), [r.blob]))], "one copy, the directory the guard serves it from");
    // The session's marker, its timer driven by hand.
    let tick: (() => void) | null = null;
    let cleared = 0;
    const inUse = keepCopiesInUse(served, { every: (fn) => { tick = fn; return { clear: () => { cleared++; } }; } });
    // The launch bound it 20 minutes ago, past the arbiter's 10-minute grace.
    const longAgo = (): void => { const t = new Date(Date.now() - 20 * 60_000); utimesSync(served[0]!, t, t); };
    longAgo();
    // Mid-session the person locks one more version the pack holds: the
    // pack's copy gets a new key, the served one is no longer wanted.
    await r.admin.policyPropose({ edits: [{ op: "lock-blob", blob: `sha1:${r.readme}`, level: "no-model" }], reason: "R3a more", requestedBy: "dashboard" });
    tick!();
    await r.server.prepareCopiesNow();
    const wanted = join(r.cacheDir, launcherRebuildKey(packOf(r.a), [r.blob, r.readme].sort()));
    assert.ok(existsSync(wanted), "the new key's copy is built");
    assert.ok(existsSync(join(served[0]!, readdirSync(served[0]!).find((n) => n.endsWith(".pack"))!)), "the served copy is kept while the session marks it used");
    // The session ends; with no mark for longer than the grace it goes.
    inUse.stop();
    inUse.stop();
    assert.equal(cleared, 1, "stopped once");
    longAgo();
    await r.server.prepareCopiesNow();
    assert.ok(!existsSync(served[0]!), "pruned once nothing serves it");
    assert.ok(existsSync(wanted));
  } finally {
    await r.close();
  }
});
