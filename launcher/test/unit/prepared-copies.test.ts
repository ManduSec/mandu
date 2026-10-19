/**
 * Unit (real repositories, no privilege): the launcher's use of the copies
 * the arbiter prepares ahead of time (confidentiality-plan-14 §11.1 R3,
 * git-object-twins.ts `preparedCopyTwins`), and the global locked set in
 * the launch's own twins:
 *
 *   - a repository whose copy is present and sealed in the current epoch is
 *     bound: its pack, index and reverse index served the copy, its bitmap
 *     made unreadable; one that is not (no copy, an unsealed or a changed
 *     one, an unconfined period live, another locked set) is left to the
 *     guard's backstop, all or nothing, with why;
 *   - the caps: repositories, packs and bytes checked per launch
 *     (MANDU_GIT_PREPARED_REPOS);
 *   - a repository the launch prepared itself, an object format that does
 *     not match, and a locked object only stored loose are not bound;
 *   - `globalLocked`: the launch's own twins exclude an id the global set
 *     holds even when no label of the launch reaches it (a twin is served
 *     before the backstop runs).
 *
 * The copies here are built the way the arbiter builds them, by the
 * launcher's own twins for the repository (the same key and seal: pinned
 * against the arbiter's code by tests/stack/
 * prepared-copies-parity.test.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  COPIES_IN_USE_INTERVAL_MS, GitObjectTwinError, idxObjectNames, keepCopiesInUse, preparedCopyTwins, preparedMaxReposFromEnv, prepareGitObjectTwins, PREPARED_MAX_REPOS, sameNames, servedCopyDirs,
  type PreparedCopyOpts,
} from "../../src/git-object-twins.js";
import { stateAxes } from "../axes.js";
import { memorySeals, type MemorySeals } from "../lib/memory-seals.js";

stateAxes("secrets"); // the confidentiality axis is what hides the committed bytes

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...args: string[]): string => execFileSync("git", args, { cwd, encoding: "utf8", env: ENV });
const KEY = ["PREPARED", "KEY", "CANARY", "7731", "w".repeat(24)].join("_");

interface Fx { tmp: string; a: string; blob: string; cacheDir: string; denyFile: string; seals: MemorySeals; done: () => void }

/** Repository A: a key committed then deleted, repacked with a bitmap. */
function fx(repack: string[] = ["repack", "-adbq"]): Fx {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-prepcopy-"));
  const a = join(tmp, "a");
  git(tmp, "init", "-q", a);
  writeFileSync(join(a, "README"), "readme\n");
  writeFileSync(join(a, "id_rsa"), `${KEY}\n`);
  git(a, "add", "."); git(a, "commit", "-qm", "1");
  const blob = git(a, "rev-parse", "HEAD:id_rsa").trim();
  git(a, "rm", "-q", "id_rsa"); git(a, "commit", "-qm", "2");
  if (repack.length > 0) git(a, ...repack);
  const denyFile = join(tmp, "denied");
  writeFileSync(denyFile, "");
  chmodSync(denyFile, 0o000);
  return { tmp, a, blob, cacheDir: join(tmp, "cache"), denyFile, seals: memorySeals(), done: () => rmSync(tmp, { recursive: true, force: true }) };
}

/** What the arbiter does for A: the copy under the shared key, sealed. */
async function prepare(f: Fx, ids: string[]): Promise<void> {
  const got = await prepareGitObjectTwins([], { cacheDir: f.cacheDir, denyFile: f.denyFile, globalLocked: ids, repoHints: [f.a], seals: f.seals });
  assert.equal(got.packsRebuilt, 1);
}

const opts = (f: Fx, o: Partial<PreparedCopyOpts> = {}): PreparedCopyOpts =>
  ({ cacheDir: f.cacheDir, denyFile: f.denyFile, lockedIds: [`sha1:${f.blob}`], seals: f.seals, ...o });

test("a prepared, sealed copy is bound: pack, index and reverse index served the copy, the bitmap made unreadable; the copy lacks the locked id", async () => {
  const f = fx();
  try {
    await prepare(f, [`sha1:${f.blob}`]);
    const got = await preparedCopyTwins([{ root: f.a, format: "sha1" }], opts(f));
    assert.deepEqual(got.bound, [f.a]);
    assert.deepEqual(got.notReady, []);
    const byExt = new Map(got.twins.map((t) => [t.targetPath.slice(t.targetPath.lastIndexOf(".")), t]));
    for (const ext of [".pack", ".idx", ".rev"]) {
      assert.equal(byExt.get(ext)?.kind, "object", ext);
      assert.ok(byExt.get(ext)!.twinPath.startsWith(`${f.cacheDir}/`));
    }
    assert.equal(byExt.get(".bitmap")?.kind, "deny", "the real pack's bitmap indexes it by position: unreadable");
    assert.equal(byExt.get(".bitmap")?.twinPath, f.denyFile);
    assert.ok(!idxObjectNames(readFileSync(byExt.get(".idx")!.twinPath)).includes(f.blob));
    // A verified copy refreshes its seals; nothing was rejected.
    assert.deepEqual(f.seals.rejected, []);
  } finally {
    f.done();
  }
});

test("left to the backstop, with why: no copy, a copy whose seals a rotation voided, a changed copy, an unconfined period, another locked set", async () => {
  const f = fx();
  try {
    const none = await preparedCopyTwins([{ root: f.a, format: "sha1" }], opts(f));
    assert.deepEqual(none.bound, []);
    assert.match(none.notReady[0]!.reason, /not prepared yet/);
    await prepare(f, [`sha1:${f.blob}`]);
    f.seals.unconfined = true;
    const during = await preparedCopyTwins([{ root: f.a, format: "sha1" }], opts(f));
    assert.match(during.notReady[0]!.reason, /not sealed in the current epoch/);
    f.seals.unconfined = false;
    f.seals.rotate();
    const voided = await preparedCopyTwins([{ root: f.a, format: "sha1" }], opts(f));
    assert.match(voided.notReady[0]!.reason, /not sealed/);
    assert.equal(f.seals.rejected.at(-1)?.reason, "unsealed");
    await prepare(f, [`sha1:${f.blob}`]);
    // Changed under its seal: the real pack's bytes (the key inside).
    const ok = await preparedCopyTwins([{ root: f.a, format: "sha1" }], opts(f));
    const served = ok.twins.find((t) => t.targetPath.endsWith(".pack"))!.twinPath;
    const realDir = join(f.a, ".git", "objects", "pack");
    rmSync(served);
    writeFileSync(served, readFileSync(join(realDir, readdirSync(realDir).find((n) => n.endsWith(".pack"))!)));
    const changed = await preparedCopyTwins([{ root: f.a, format: "sha1" }], opts(f));
    assert.deepEqual(changed.bound, []);
    assert.equal(f.seals.rejected.at(-1)?.reason, "mismatch");
    // Another locked set: the README's id too (the pack holds it), so the
    // copy that excludes only the key is not the one this launch needs.
    await prepare(f, [`sha1:${f.blob}`]);
    const readme = git(f.a, "rev-parse", "HEAD:README").trim();
    const other = await preparedCopyTwins([{ root: f.a, format: "sha1" }], opts(f, { lockedIds: [`sha1:${f.blob}`, `sha1:${readme}`] }));
    assert.deepEqual(other.bound, []);
    assert.match(other.notReady[0]!.reason, /not prepared yet/);
  } finally {
    f.done();
  }
});

test("the caps: repositories (MANDU_GIT_PREPARED_REPOS), packs and bytes checked per launch", async () => {
  const f = fx();
  try {
    await prepare(f, [`sha1:${f.blob}`]);
    const repos = await preparedCopyTwins([{ root: f.a, format: "sha1" }], opts(f, { maxRepos: 0 }));
    assert.deepEqual(repos.overCap, [f.a]);
    assert.deepEqual(repos.bound, []);
    const packs = await preparedCopyTwins([{ root: f.a, format: "sha1" }], opts(f, { maxPacks: 0 }));
    assert.deepEqual(packs.overCap, [f.a]);
    const bytes = await preparedCopyTwins([{ root: f.a, format: "sha1" }], opts(f, { maxVerifyBytes: 10 }));
    assert.deepEqual(bytes.overCap, [f.a]);
    assert.equal(preparedMaxReposFromEnv({}), PREPARED_MAX_REPOS);
    assert.equal(preparedMaxReposFromEnv({ MANDU_GIT_PREPARED_REPOS: "0" }), 0);
    assert.equal(preparedMaxReposFromEnv({ MANDU_GIT_PREPARED_REPOS: "3" }), 3);
    assert.equal(preparedMaxReposFromEnv({ MANDU_GIT_PREPARED_REPOS: "-1" }), PREPARED_MAX_REPOS);
  } finally {
    f.done();
  }
});

test("a pack two prepared repositories reach (B a `clone --shared` of A, C of B: alternates followed two links) is verified and served once; both are bound", async () => {
  const f = fx();
  try {
    await prepare(f, [`sha1:${f.blob}`]);
    const b = join(f.tmp, "b");
    git(f.tmp, "clone", "-q", "--shared", f.a, b);
    const c = join(f.tmp, "c");
    git(f.tmp, "clone", "-q", "--shared", b, c);
    const got = await preparedCopyTwins([{ root: c, format: "sha1" }, { root: f.a, format: "sha1" }], opts(f));
    assert.deepEqual(got.bound, [c, f.a], JSON.stringify(got));
    const targets = got.twins.map((t) => t.targetPath);
    assert.equal(new Set(targets).size, targets.length, "each target once");
    const pack = targets.find((t) => t.endsWith(".pack"))!;
    assert.ok(pack.startsWith(`${join(f.a, ".git", "objects", "pack")}/`), "C, two links from A, is served A's copy");
    const alone = await preparedCopyTwins([{ root: f.a, format: "sha1" }], opts(f));
    assert.deepEqual(got.twins, alone.twins, "the same twins as A alone");
  } finally {
    f.done();
  }
});

test("not bound: a repository the launch prepared itself, a format that does not match, a locked object stored only loose, no locked set", async () => {
  const f = fx();
  try {
    await prepare(f, [`sha1:${f.blob}`]);
    assert.deepEqual((await preparedCopyTwins([{ root: f.a, format: "sha1" }], opts(f, { skipRoots: new Set([f.a]) }))).bound, []);
    const fmt = await preparedCopyTwins([{ root: f.a, format: "sha256" }], opts(f));
    assert.match(fmt.notReady[0]!.reason, /object format/);
    assert.deepEqual((await preparedCopyTwins([{ root: f.a, format: "sha1" }], opts(f, { lockedIds: [] }))).bound, []);
  } finally {
    f.done();
  }
  const loose = fx([]);
  try {
    const got = await preparedCopyTwins([{ root: loose.a, format: "sha1" }], opts(loose));
    assert.deepEqual(got, { twins: [], bound: [], notReady: [], overCap: [] }, "no pack holds it: the backstop refuses that object alone");
  } finally {
    loose.done();
  }
});

/**
 * A CRAFTED pack, what an agent that can write a repository's object store
 * can plant: the key blob's bytes indexed under another name N, and the
 * key's own id L indexed at another blob's bytes (so the pack "holds" L and
 * is rebuilt). pack-objects copies an object's bytes under the name the
 * source index gives it: before the index of a sanitized pack was rebuilt
 * from its content, the twin carried the key as N and its index passed the
 * "lists no excluded id" check.
 */
function crafted(tmp: string): { root: string; L: string; N: string } {
  const root = join(tmp, "crafted");
  git(tmp, "init", "-q", root);
  const put = (body: string): string => execFileSync("git", ["hash-object", "-w", "--stdin"], { cwd: root, input: body, encoding: "utf8", env: ENV }).trim();
  const L = put(`${KEY}\n`);
  const R = put("readme\n");
  const X = put("other\n");
  execFileSync("git", ["pack-objects", "-q", join(root, ".git", "objects", "pack", "pack")], { cwd: root, input: `${L}\n${R}\n${X}\n`, env: ENV });
  git(root, "prune-packed");
  const packDir = join(root, ".git", "objects", "pack");
  const idxName = readdirSync(packDir).find((n) => n.endsWith(".idx"))!;
  const idx = readFileSync(join(packDir, idxName));
  const n = idx.readUInt32BE(8 + 255 * 4);
  const names = 8 + 256 * 4, crcs = names + n * 20, offs = crcs + n * 4;
  const entry = new Map<string, { crc: number; off: number }>();
  for (let i = 0; i < n; i++) entry.set(idx.subarray(names + i * 20, names + (i + 1) * 20).toString("hex"), { crc: idx.readUInt32BE(crcs + i * 4), off: idx.readUInt32BE(offs + i * 4) });
  const N = (L[0] === "0" ? "1" : "0") + L.slice(1);
  const fake = ([[L, entry.get(X)!], [N, entry.get(L)!], [R, entry.get(R)!]] as Array<[string, { crc: number; off: number }]>).sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const out = Buffer.alloc(8 + 256 * 4 + fake.length * 28 + 40);
  out.writeUInt32BE(0xff744f63, 0); out.writeUInt32BE(2, 4);
  for (let b = 0; b < 256; b++) out.writeUInt32BE(fake.filter(([h]) => parseInt(h.slice(0, 2), 16) <= b).length, 8 + b * 4);
  fake.forEach(([h, e], i) => {
    Buffer.from(h, "hex").copy(out, names + i * 20);
    out.writeUInt32BE(e.crc, names + fake.length * 20 + i * 4);
    out.writeUInt32BE(e.off, names + fake.length * 24 + i * 4);
  });
  const pack = readFileSync(join(packDir, idxName.replace(/\.idx$/, ".pack")));
  pack.subarray(pack.length - 20).copy(out, out.length - 40);
  createHash("sha1").update(out.subarray(0, out.length - 20)).digest().copy(out, out.length - 20);
  rmSync(join(packDir, idxName), { force: true });
  rmSync(join(packDir, idxName.replace(/\.idx$/, ".rev")), { force: true });
  writeFileSync(join(packDir, idxName), out);
  return { root, L, N };
}

test("a crafted pack in the workspace (the key's bytes indexed under another name) cannot be sanitized: the rebuilt index names the key, the launch refuses", async () => {
  const f = fx();
  try {
    const c = crafted(f.tmp);
    await assert.rejects(
      prepareGitObjectTwins([], { cacheDir: f.cacheDir, denyFile: f.denyFile, repoHints: [c.root], blobLocks: [`sha1:${c.L}`] }),
      (e: Error) => e instanceof GitObjectTwinError && /do not hash to the names its index gives them/.test(e.message),
    );
    // Nothing of it was kept for a later launch to serve.
    let kept: string[] = [];
    try { kept = readdirSync(f.cacheDir).filter((n) => !n.startsWith(".")); } catch { /* none */ }
    assert.deepEqual(kept, []);
    assert.equal(sameNames(["b", "a", "a"], ["a", "b"]), true);
    assert.equal(sameNames(["a"], ["a", "b"]), false);
  } finally {
    f.done();
  }
});

test("globalLocked: the launch's own twins exclude an id of the global set no label of the launch reaches", async () => {
  const f = fx();
  try {
    const without = await prepareGitObjectTwins([], { cacheDir: f.cacheDir, denyFile: f.denyFile, repoHints: [f.a] });
    assert.equal(without.twins.length, 0, "before: nothing names the key in this repository, so no twin (the backstop would refuse the pack)");
    const got = await prepareGitObjectTwins([], { cacheDir: f.cacheDir, denyFile: f.denyFile, repoHints: [f.a], globalLocked: [`sha1:${f.blob}`] });
    const idx = got.twins.find((t) => t.targetPath.endsWith(".idx"))!;
    assert.ok(!idxObjectNames(readFileSync(idx.twinPath)).includes(f.blob), "the workspace's twin excludes the globally locked id");
    assert.deepEqual(got.lockedIds, [`sha1:${f.blob}`]);
    // Roots are real work-tree roots (the hint's realpath: a temp dir spelled
    // through macOS's /tmp → /private/tmp link lists the real one).
    assert.deepEqual(got.roots, [realpathSync(f.a)]);
  } finally {
    f.done();
  }
});

test("servedCopyDirs: the cache entry of every object twin, once; deny twins and paths outside the cache are not entries", () => {
  const cache = "/h/.mandu/cache/object-twins";
  const k1 = `${cache}/${"a".repeat(32)}`;
  const k2 = `${cache}/${"b".repeat(32)}`;
  const twins = [
    { targetPath: "/r/.git/objects/pack/pack-1.pack", twinPath: `${k2}/p-x.pack`, kind: "object" as const },
    { targetPath: "/r/.git/objects/pack/pack-1.idx", twinPath: `${k2}/p-x.idx`, kind: "object" as const },
    { targetPath: "/s/.git/objects/pack/pack-2.pack", twinPath: `${k1}/p-y.pack`, kind: "object" as const },
    { targetPath: "/r/.git/objects/pack/pack-1.bitmap", twinPath: "/scope/secret-twins/denied", kind: "deny" as const },
    { targetPath: "/t/x.pack", twinPath: `${cache}/loose.pack`, kind: "object" as const },
    { targetPath: "/t/y.pack", twinPath: `${k1}/sub/deeper.pack`, kind: "object" as const },
    { targetPath: "/t/z.pack", twinPath: "/elsewhere/q/p.pack", kind: "object" as const },
  ];
  assert.deepEqual(servedCopyDirs(twins, `${cache}/`), [k1, k2]);
  assert.deepEqual(servedCopyDirs([], cache), []);
});

test("keepCopiesInUse: every interval marks each served copy used (the arbiter's prune keeps it); stop ends it; nothing to keep starts no timer", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-inuse-"));
  try {
    const a = join(dir, "a".repeat(32));
    const b = join(dir, "b".repeat(32));
    for (const d of [a, b]) execFileSync("mkdir", [d]);
    const old = new Date(Date.now() - 3600_000);
    for (const d of [a, b]) utimesSync(d, old, old);
    const marked = (d: string): boolean => statSync(d).mtimeMs > Date.now() - 60_000;
    // The real timer, short.
    const inUse = keepCopiesInUse([a, b], { intervalMs: 20 });
    await new Promise((res) => setTimeout(res, 120));
    assert.ok(marked(a) && marked(b), "marked used");
    inUse.stop();
    for (const d of [a, b]) utimesSync(d, old, old);
    await new Promise((res) => setTimeout(res, 80));
    assert.ok(!marked(a) && !marked(b), "stopped: no mark after");
    // A copy gone meanwhile (pruned by an older arbiter, removed by hand): best effort, never a throw.
    let ticks = 0;
    let tick: (() => void) | null = null;
    const gone = keepCopiesInUse([join(dir, "gone")], { every: (fn, ms) => { tick = fn; assert.equal(ms, COPIES_IN_USE_INTERVAL_MS); return { clear: () => {} }; } });
    tick!(); ticks++;
    gone.stop();
    assert.equal(ticks, 1);
    assert.ok(COPIES_IN_USE_INTERVAL_MS < 10 * 60_000, "under the arbiter's prune grace");
    // Nothing served: no timer at all.
    let started = false;
    keepCopiesInUse([], { every: () => { started = true; return { clear: () => {} }; } }).stop();
    assert.equal(started, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
