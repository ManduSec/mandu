/**
 * Unit: prepared-copies — sanitized copies built ahead of time for every
 * known repository holding a locked object (confidentiality-plan-14 §11.1
 * R3): the plan of a cycle (ready, pending across cycles, capped by the
 * cycle and the total caps, an unsupported layout), the exclusion set, the
 * caps from the environment; the preparer over real repositories and a real
 * seal store: a copy built, sealed part by part in the current epoch, its
 * index free of the locked id and git unable to read it; NEVER built while an
 * unconfined launch is live (and resumed after its end); a copy whose build
 * spanned a rotation never sealed; sealed again from memory after a rotation
 * without a rebuild, but rebuilt when its bytes changed; a copy a launcher
 * found changed rebuilt; pruning when a lock is lifted or a pack is gone; and
 * the hardening (no repository config: a configured fsmonitor program, hook
 * or pack setting is never used); the daemon's gate (`preparedCopiesOff`:
 * Linux only, the one host whose launch uses a copy). Parity with the
 * launcher's twins: tests/stack/prepared-copies-parity.test.ts.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  exclusionSet, EMPTY_BLOBS, heldIn, inventoryStores, idxLookupFile, NICE_CANDIDATES, niceBinary, planPreparation, PreparedCopies, preparedCopiesOff, prepGit,
  prepGitCommand, prepGitEnv, prepLimitsFromEnv, resolveNice, rebuildKey, type PrepDir, type PrepGit, type PrepPack, type PrepLimits, type PrepRepo,
} from "../../policy/prepared-copies.js";
import type { AlternatesIo } from "../../src/git-alternates.js";
import { HARDENED_GIT_ARGS } from "../../policy/secret-history-scan.js";
import { gitSeatbeltProfile } from "../../src/hardened-git.js";
import { CacheSealStore } from "../../policy/cache-seals.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the locks and their copies are the confidentiality axis's

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = realpathSync(mkdtempSync(join(tmpdir(), "mdu-prep-"))); dirs.push(d); return d; };
const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...a: string[]): string => execFileSync("git", a, { cwd, encoding: "utf8", env: ENV });
const KEY = ["PREP", "COPY", "KEY", "7731", "Hx".repeat(14)].join("_");

/** A repository whose history holds a key (committed, then deleted), packed. */
function repo(name = "a"): { root: string; blob: string; packDir: string } {
  const root = join(tmp(), name);
  git(join(root, ".."), "init", "-q", "-b", "main", root);
  writeFileSync(join(root, "README"), "readme\n");
  writeFileSync(join(root, "id_rsa"), `${KEY}\n`);
  git(root, "add", "."); git(root, "commit", "-qm", "1");
  const blob = git(root, "rev-parse", "HEAD:id_rsa").trim();
  git(root, "rm", "-q", "id_rsa"); git(root, "commit", "-qm", "2");
  git(root, "repack", "-adq");
  return { root, blob, packDir: join(root, ".git", "objects", "pack") };
}

interface Rig { dir: string; cacheDir: string; store: CacheSealStore; prep: PreparedCopies; locked: { sha1: string[]; sha256: string[] }; repos: string[] }

function rig(opts: { cycleMB?: number; totalMB?: number; hashFile?: (p: string) => Promise<{ sha256: string; size: number }>; pruneGraceMs?: number; git?: PrepGit; limits?: Partial<PrepLimits>; log?: (m: string) => void } = {}): Rig {
  const dir = tmp();
  const cacheDir = join(dir, "cache", "object-twins");
  const store = new CacheSealStore({ dbPath: join(dir, "mandu.db"), confidentiality: true });
  const r: Rig = { dir, cacheDir, store, locked: { sha1: [], sha256: [] }, repos: [], prep: undefined as unknown as PreparedCopies };
  r.prep = new PreparedCopies({
    cacheDir, seals: store, repos: () => r.repos, lockedSet: () => r.locked,
    limits: {
      ...(opts.cycleMB !== undefined ? { cycleBytes: opts.cycleMB * 1048576 } : {}),
      ...(opts.totalMB !== undefined ? { totalBytes: opts.totalMB * 1048576 } : {}),
      pruneGraceMs: opts.pruneGraceMs ?? 0,
      ...(opts.limits ?? {}),
    },
    ...(opts.log ? { log: opts.log } : {}),
    ...(opts.hashFile ? { hashFile: opts.hashFile } : {}),
    ...(opts.git ? { git: opts.git } : {}),
  });
  return r;
}

async function cycle(r: Rig): Promise<void> {
  await r.prep.runCycle();
  await r.prep.idle();
}

/** The copy directories in the cache (not the temporary ones). */
const copies = (r: Rig): string[] => (existsSync(r.cacheDir) ? readdirSync(r.cacheDir).filter((n) => /^[0-9a-f]{32}$/.test(n)).sort() : []);

/** The current epoch's object-twin seals for a copy's files. */
function sealsOf(r: Rig, key: string): Array<{ key: string; sha256: string; size: number }> {
  const names = readdirSync(join(r.cacheDir, key));
  return r.store.seals("object-twin", names.map((n) => `${key}/${n}`)).seals;
}

// ── Pure ────────────────────────────────────────────────────────────────────

const P = (key: string, size: number, ready = false): PrepRepo["packs"][number] => ({ base: `/r/.git/objects/pack/pack-${key}`, exclude: ["a".repeat(40)], key, size, hasRev: true, ready });
const MB = 1048576;

test("plan: a repository with every copy ready is ready; missing packs are built while the cycle's budget lasts, the rest pending", () => {
  const repos: PrepRepo[] = [
    { root: "/r1", format: "sha1", packs: [P("k1", 10 * MB, true)] },
    { root: "/r2", format: "sha1", packs: [P("k2", 30 * MB), P("k3", 30 * MB)] },
    { root: "/r3", format: "sha1", packs: [P("k4", 10 * MB)] },
  ];
  const p = planPreparation(repos, { cycleBytes: 50 * MB, totalBytes: 1000 * MB });
  assert.equal(p.state.get("/r1")!.state, "ready");
  assert.deepEqual(p.build.map((b) => b.pack.key), ["k2"], "one at a time, in order; the first pack that does not fit ends the cycle's building");
  assert.equal(p.state.get("/r2")!.state, "pending");
  assert.equal(p.state.get("/r3")!.state, "pending", "a later repository waits its turn (lowest priority, in order)");
  assert.deepEqual([...p.wanted].sort(), ["k1", "k2", "k3", "k4"]);
  assert.equal(p.wantedBytes, 80 * MB);
});

test("plan: a pack over the cycle cap, or a repository past the total cap, is capped; nothing of it is built or kept", () => {
  const repos: PrepRepo[] = [
    { root: "/big", format: "sha1", packs: [P("kb", 200 * MB)] },
    { root: "/ok", format: "sha1", packs: [P("ko", 40 * MB)] },
    { root: "/over", format: "sha1", packs: [P("kv", 70 * MB, true)] },
  ];
  const p = planPreparation(repos, { cycleBytes: 100 * MB, totalBytes: 100 * MB });
  assert.equal(p.state.get("/big")!.state, "capped");
  assert.match(p.state.get("/big")!.reason!, /over the 100 MiB a cycle may rebuild/);
  assert.equal(p.state.get("/ok")!.state, "pending");
  assert.equal(p.state.get("/over")!.state, "capped", "a ready copy past the total cap is not kept");
  assert.match(p.state.get("/over")!.reason!, /past their 100 MiB cap/);
  assert.deepEqual([...p.wanted], ["ko"]);
  assert.deepEqual(p.build.map((b) => b.pack.key), ["ko"]);
});

test("plan: a cycle cap of 0 builds nothing (every repository with a missing copy is capped); an unsupported layout fails", () => {
  const p = planPreparation([
    { root: "/a", format: "sha1", packs: [P("k1", 1)] },
    { root: "/m", format: "sha1", packs: [P("k2", 1)], unsupported: "an incremental multi-pack-index" },
    { root: "/none", format: "sha1", packs: [] },
  ], { cycleBytes: 0, totalBytes: 1000 * MB });
  assert.equal(p.state.get("/a")!.state, "capped");
  assert.equal(p.state.get("/m")!.state, "failed");
  assert.equal(p.state.has("/none"), false, "a repository holding nothing locked is not listed");
  assert.equal(p.build.length, 0);
});

test("the exclusion set: well-formed ids of each format, never the empty blob; the caps from the environment", () => {
  const x = exclusionSet({ sha1: [EMPTY_BLOBS.sha1, "b".repeat(40), "b".repeat(40), "nothex", "c".repeat(64)], sha256: [EMPTY_BLOBS.sha256, "d".repeat(64)] });
  assert.deepEqual(x, { sha1: ["b".repeat(40)], sha256: ["d".repeat(64)] });
  assert.deepEqual(prepLimitsFromEnv({}), {});
  assert.deepEqual(prepLimitsFromEnv({ MANDU_GIT_TWIN_MAX_MB: "300" }), { cycleBytes: 300 * MB }, "the cycle cap defaults to the launcher's rebuild cap");
  assert.deepEqual(prepLimitsFromEnv({ MANDU_GIT_TWIN_MAX_MB: "300", MANDU_GIT_PREP_CYCLE_MB: "0", MANDU_GIT_PREP_TOTAL_MB: "10" }), { cycleBytes: 0, totalBytes: 10 * MB });
  assert.deepEqual(prepLimitsFromEnv({ MANDU_GIT_PREP_CYCLE_MB: "-1", MANDU_GIT_PREP_TOTAL_MB: "x" }), {}, "a malformed cap is ignored");
});

test("the daemon's gate: prepared on Linux only (the one host whose launch uses a copy); MANDU_GIT_PREPARE=0 turns it off anywhere", () => {
  assert.equal(preparedCopiesOff({}, "linux"), null, "Linux: on, as before");
  assert.equal(preparedCopiesOff({ MANDU_GIT_PREPARE: "1" }, "linux"), null);
  assert.equal(preparedCopiesOff({ MANDU_GIT_PREPARE: "0" }, "linux"), "MANDU_GIT_PREPARE=0");
  for (const platform of ["darwin", "win32", "freebsd"] as const) {
    const why = preparedCopiesOff({}, platform);
    assert.ok(why !== null && why.includes("only a Linux launch uses them") && why.endsWith(`this host is ${platform}`), `${platform}: ${why}`);
    assert.ok(preparedCopiesOff({ MANDU_GIT_PREPARE: "1" }, platform) !== null, "no switch turns it on where nothing uses it");
  }
  assert.equal(preparedCopiesOff({ MANDU_GIT_PREPARE: "0" }, "darwin"), "MANDU_GIT_PREPARE=0", "the explicit switch is named first");
  assert.equal(preparedCopiesOff({}), process.platform === "linux" ? null : preparedCopiesOff({}, process.platform), "default: this host");
});

test("heldIn: the same answer by binary search (a small set) and by one read of the name table (a set large next to the index)", () => {
  const root = join(tmp(), "many");
  git(join(root, ".."), "init", "-q", root);
  for (let i = 0; i < 60; i++) writeFileSync(join(root, `f${i}`), `file ${i}\n`);
  git(root, "add", "."); git(root, "commit", "-qm", "x"); git(root, "repack", "-adq");
  const packDir = join(root, ".git", "objects", "pack");
  const idx = join(packDir, readdirSync(packDir).find((n) => n.endsWith(".idx"))!);
  const all = git(root, "ls-tree", "HEAD").split("\n").filter(Boolean).map((l) => l.split(/\s+/)[2]!);
  const small = [all[3]!, "e".repeat(40)];
  assert.deepEqual(heldIn(idx, small), idxLookupFile(idx, small));
  assert.deepEqual(heldIn(idx, small), [all[3]!]);
  const large = [...all.slice(0, 30), ...Array.from({ length: 200 }, (_, i) => i.toString(16).padStart(40, "f"))];
  assert.deepEqual(heldIn(idx, large), idxLookupFile(idx, large));
  assert.equal(heldIn(idx, large).length, 30);
});

// ── The preparer over real repositories ─────────────────────────────────────

test("a locked id's pack gets a copy without it, keyed as the launcher keys it, each file sealed in the current epoch; git cannot read the id through it", async () => {
  const a = repo();
  const clean = repo("clean");
  const r = rig();
  r.repos = [a.root, clean.root];
  r.locked = { sha1: [a.blob], sha256: [] };
  // The clean repository holds the same key too (the same bytes, the same id):
  // covered by id. A third repository holds nothing locked.
  const other = join(tmp(), "other");
  git(join(other, ".."), "init", "-q", other);
  writeFileSync(join(other, "x"), "x\n"); git(other, "add", "."); git(other, "commit", "-qm", "x"); git(other, "repack", "-adq");
  r.repos.push(other);
  await cycle(r);
  const s = r.prep.summary();
  assert.deepEqual(s.ready.map((x) => x.root).sort(), [a.root, clean.root].sort());
  assert.deepEqual(s.pending, []);
  const packName = readdirSync(a.packDir).find((n) => n.endsWith(".pack"))!;
  const key = rebuildKey(join(a.packDir, packName.slice(0, -5)), [a.blob]);
  assert.ok(copies(r).includes(key), "the copy sits under the launcher's cache key");
  const files = readdirSync(join(r.cacheDir, key)).sort();
  assert.deepEqual(files.map((f) => f.slice(f.lastIndexOf("."))).sort(), [".idx", ".pack", ".rev"]);
  const seals = sealsOf(r, key);
  assert.equal(seals.length, 3, "the .pack, .idx and .rev each sealed");
  for (const f of files) {
    const bytes = readFileSync(join(r.cacheDir, key, f));
    const seal = seals.find((x) => x.key === `${key}/${f}`)!;
    assert.equal(seal.size, bytes.length);
  }
  const idx = join(r.cacheDir, key, files.find((f) => f.endsWith(".idx"))!);
  assert.deepEqual(idxLookupFile(idx, [a.blob]), [], "the copy's index lists no locked id");
  // git over the copy alone: every other object reads, the locked one does not.
  const probe = join(tmp(), "probe");
  git(join(probe, ".."), "init", "-q", "--bare", probe);
  mkdirSync(join(probe, "objects", "pack"), { recursive: true });
  for (const f of files) writeFileSync(join(probe, "objects", "pack", f), readFileSync(join(r.cacheDir, key, f)));
  const head = git(a.root, "rev-parse", "HEAD").trim();
  assert.match(execFileSync("git", ["--git-dir", probe, "cat-file", "-p", head], { env: ENV, encoding: "utf8" }), /^tree /);
  assert.throws(() => execFileSync("git", ["--git-dir", probe, "cat-file", "-p", a.blob], { env: ENV, stdio: "pipe" }));
  // Nothing of the key in any copy's raw bytes either (it is not stored).
  for (const k of copies(r)) for (const f of readdirSync(join(r.cacheDir, k))) assert.ok(!readFileSync(join(r.cacheDir, k, f)).includes(KEY));
  // A second cycle builds nothing.
  await cycle(r);
  assert.equal(r.prep.lastBuilt, 0);
  r.store.markShutdown();
});

test("never built while an unconfined launch is live; resumed after its end", async () => {
  const a = repo();
  const r = rig();
  r.repos = [a.root];
  r.locked = { sha1: [a.blob], sha256: [] };
  const live = r.store.beginLaunch({ pid: process.pid, mode: "off", posture: "confined", writeProtect: false });
  assert.equal(live.confined, false);
  await cycle(r);
  assert.equal(copies(r).length, 0, "nothing is built during an unconfined period");
  assert.match(r.prep.summary().paused ?? "", /unconfined launch/);
  assert.equal(r.prep.summary().ready.length, 0);
  r.store.endLaunch(live.token);
  r.prep.voided(); // what the server's rotation hook calls
  await cycle(r);
  assert.equal(r.prep.summary().paused, undefined);
  assert.deepEqual(r.prep.summary().ready.map((x) => x.root), [a.root]);
  assert.equal(copies(r).length, 1);
  r.store.markShutdown();
});

test("a build that spans a rotation is never sealed (the copy is dropped); the next cycle builds it", async () => {
  const a = repo();
  let store: CacheSealStore | null = null;
  let rotateOnce = true;
  const r = rig({
    hashFile: async (p) => {
      if (rotateOnce && store !== null) { rotateOnce = false; store.rotate("an unconfined launch ended (test)"); }
      const b = readFileSync(p);
      const { createHash } = await import("node:crypto");
      return { sha256: createHash("sha256").update(b).digest("hex"), size: b.length };
    },
  });
  store = r.store;
  r.repos = [a.root];
  r.locked = { sha1: [a.blob], sha256: [] };
  await cycle(r);
  assert.equal(copies(r).length, 0, "the copy built across the rotation is removed, not sealed");
  assert.equal(r.prep.summary().failed.length, 1);
  assert.match(r.prep.summary().failed[0]!.reason, /not sealed/);
  await cycle(r);
  assert.equal(copies(r).length, 1);
  assert.equal(sealsOf(r, copies(r)[0]!).length, 3);
  r.store.markShutdown();
});

test("after a rotation a copy this process built is sealed again from memory without a rebuild; changed bytes are rebuilt", async () => {
  const a = repo();
  const r = rig();
  r.repos = [a.root];
  r.locked = { sha1: [a.blob], sha256: [] };
  await cycle(r);
  const key = copies(r)[0]!;
  r.store.rotate("test");
  assert.equal(sealsOf(r, key).length, 0, "the rotation voided the seals");
  r.prep.voided();
  assert.equal(r.prep.summary().ready.length, 0, "not ready while its seals are void");
  await cycle(r);
  assert.equal(r.prep.lastBuilt, 0, "the same bytes are sealed again, not rebuilt");
  assert.equal(sealsOf(r, key).length, 3);
  assert.equal(r.prep.summary().ready.length, 1);
  // Bytes written over the copy during an unconfined period: not what this
  // process built, so not sealed again; rebuilt.
  r.store.rotate("test");
  const packFile = readdirSync(join(r.cacheDir, key)).find((f) => f.endsWith(".pack"))!;
  const real = readdirSync(a.packDir).find((f) => f.endsWith(".pack"))!;
  rmSync(join(r.cacheDir, key, packFile));
  writeFileSync(join(r.cacheDir, key, packFile), readFileSync(join(a.packDir, real)));
  const before = r.prep.builtTotal;
  await cycle(r);
  assert.equal(r.prep.builtTotal - before, 1, "the planted pack is rebuilt");
  const now = readFileSync(join(r.cacheDir, key, readdirSync(join(r.cacheDir, key)).find((f) => f.endsWith(".pack"))!));
  const seal = sealsOf(r, key).find((x) => x.key.endsWith(".pack"))!;
  assert.equal(seal.size, now.length);
  assert.notDeepEqual(now, readFileSync(join(a.packDir, real)));
  r.store.markShutdown();
});

test("a copy a launcher found changed under its seal is rebuilt", async () => {
  const a = repo();
  const r = rig();
  r.repos = [a.root];
  r.locked = { sha1: [a.blob], sha256: [] };
  await cycle(r);
  const key = copies(r)[0]!;
  const before = r.prep.builtTotal;
  r.prep.distrust([`${key}/whatever.pack`, "not-a-key/x"]);
  await cycle(r);
  assert.equal(r.prep.builtTotal - before, 1);
  await cycle(r);
  assert.equal(r.prep.lastBuilt, 0, "trusted again once rebuilt");
  r.store.markShutdown();
});

test("caps: a cycle cap of 0 builds nothing and reports the repository capped; a total cap too small keeps nothing", async () => {
  const a = repo();
  const zero = rig({ cycleMB: 0 });
  zero.repos = [a.root];
  zero.locked = { sha1: [a.blob], sha256: [] };
  await cycle(zero);
  assert.equal(copies(zero).length, 0);
  assert.deepEqual(zero.prep.summary().capped.map((c) => c.root), [a.root]);
  zero.store.markShutdown();
  const tiny = rig({ totalMB: 0 });
  tiny.repos = [a.root];
  tiny.locked = { sha1: [a.blob], sha256: [] };
  await cycle(tiny);
  assert.equal(copies(tiny).length, 0);
  assert.match(tiny.prep.summary().capped[0]!.reason, /past their 0 MiB cap/);
  tiny.store.markShutdown();
});

test("pruning: a lock lifted, or a pack repacked away, removes the copy this process made (a new pack gets its own)", async () => {
  const a = repo();
  const r = rig();
  r.repos = [a.root];
  r.locked = { sha1: [a.blob], sha256: [] };
  await cycle(r);
  const first = copies(r);
  assert.equal(first.length, 1);
  // A new commit and a repack: the old pack is gone, a new one holds the id.
  writeFileSync(join(a.root, "more"), "more\n"); git(a.root, "add", "."); git(a.root, "commit", "-qm", "3"); git(a.root, "repack", "-adq");
  await cycle(r);
  const second = copies(r);
  assert.equal(second.length, 1);
  assert.notEqual(second[0], first[0], "the gone pack's copy is pruned, the new pack's built");
  // The lock is lifted: nothing is wanted, the copy goes.
  r.locked = { sha1: [], sha256: [] };
  await cycle(r);
  assert.deepEqual(copies(r), []);
  assert.equal(r.prep.summary().ready.length, 0);
  r.store.markShutdown();
});

test("a copy used by a launch within the grace is not pruned; a failed inventory keeps what the repository had", async () => {
  const a = repo();
  const r = rig({ pruneGraceMs: 3600_000 });
  r.repos = [a.root];
  r.locked = { sha1: [a.blob], sha256: [] };
  await cycle(r);
  r.locked = { sha1: [], sha256: [] };
  await cycle(r);
  assert.equal(copies(r).length, 1, "used recently: kept for the grace");
  r.store.markShutdown();
  const b = repo("b");
  const s = rig();
  s.repos = [b.root];
  s.locked = { sha1: [b.blob], sha256: [] };
  await cycle(s);
  const moved = `${b.root}-moved`;
  execFileSync("mv", [b.root, moved]);
  await cycle(s);
  assert.equal(s.prep.summary().failed.length, 1, "the inventory failed");
  assert.equal(copies(s).length, 1, "and the copy it had is kept");
  s.store.markShutdown();
});

/**
 * A CRAFTED pack, what an agent that can write an object store can plant:
 * the key blob's bytes indexed under another name N, and the key's own id L
 * indexed at another blob's bytes (so the pack "holds" L and is rebuilt).
 * pack-objects copies an object's bytes under the name the source index
 * gives it, so the copy would carry the key as N unless its index is
 * rebuilt from the content.
 */
function crafted(): { root: string; L: string; N: string } {
  const root = join(tmp(), "crafted");
  git(join(root, ".."), "init", "-q", "-b", "main", root);
  const put = (body: string): string => execFileSync("git", ["hash-object", "-w", "--stdin"], { cwd: root, input: body, encoding: "utf8", env: ENV }).trim();
  const L = put(`${KEY}\n`);
  const R = put("readme\n");
  const X = put("other\n");
  execFileSync("git", ["pack-objects", "-q", join(root, ".git", "objects", "pack", "pack")], { cwd: root, input: `${L}\n${R}\n${X}\n`, env: ENV });
  git(root, "prune-packed");
  const packDir = join(root, ".git", "objects", "pack");
  const idxName = readdirSync(packDir).find((n) => n.endsWith(".idx"))!;
  const packName = idxName.replace(/\.idx$/, ".pack");
  const idx = readFileSync(join(packDir, idxName));
  const n = idx.readUInt32BE(8 + 255 * 4);
  const names = 8 + 256 * 4, crcs = names + n * 20, offs = crcs + n * 4;
  const entry = new Map<string, { crc: number; off: number }>();
  for (let i = 0; i < n; i++) entry.set(idx.subarray(names + i * 20, names + (i + 1) * 20).toString("hex"), { crc: idx.readUInt32BE(crcs + i * 4), off: idx.readUInt32BE(offs + i * 4) });
  const N = "0" + L.slice(1) === L ? "1" + L.slice(1) : "0" + L.slice(1);
  const fake = [[L, entry.get(X)!], [N, entry.get(L)!], [R, entry.get(R)!]] as Array<[string, { crc: number; off: number }]>;
  fake.sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const out = Buffer.alloc(8 + 256 * 4 + fake.length * 28 + 40);
  out.writeUInt32BE(0xff744f63, 0); out.writeUInt32BE(2, 4);
  for (let b = 0; b < 256; b++) out.writeUInt32BE(fake.filter(([h]) => parseInt(h.slice(0, 2), 16) <= b).length, 8 + b * 4);
  fake.forEach(([h, e], i) => {
    Buffer.from(h, "hex").copy(out, names + i * 20);
    out.writeUInt32BE(e.crc, names + fake.length * 20 + i * 4);
    out.writeUInt32BE(e.off, names + fake.length * 24 + i * 4);
  });
  const pack = readFileSync(join(packDir, packName));
  pack.subarray(pack.length - 20).copy(out, out.length - 40);
  createHash("sha1").update(out.subarray(0, out.length - 20)).digest().copy(out, out.length - 20);
  rmSync(join(packDir, idxName), { force: true });
  rmSync(join(packDir, idxName.replace(/\.idx$/, ".rev")), { force: true });
  writeFileSync(join(packDir, idxName), out);
  return { root, L, N };
}

test("a crafted pack (the key's bytes indexed under another name) is never prepared: the copy's index, rebuilt from its content, names the key", async () => {
  const c = crafted();
  const r = rig();
  r.repos = [c.root];
  r.locked = { sha1: [c.L], sha256: [] };
  await cycle(r);
  const s = r.prep.summary();
  assert.deepEqual(s.ready, []);
  assert.equal(s.failed.length, 1, JSON.stringify(s));
  assert.match(s.failed[0]!.reason, /do not hash to the names its index gives them/);
  assert.deepEqual(copies(r), [], "nothing kept, nothing sealed");
  r.store.markShutdown();
});

test("hardening: no repository config is used (a configured fsmonitor program and hooks never run; a pack setting does not reach the build)", async () => {
  const a = repo();
  const d = tmp();
  const marker = join(d, "ran");
  const hook = join(d, "hook.sh");
  writeFileSync(hook, `#!/bin/sh\ntouch '${marker}'\nexit 1\n`);
  chmodSync(hook, 0o755);
  git(a.root, "config", "core.fsmonitor", hook);
  git(a.root, "config", "core.hooksPath", d);
  for (const h of ["pre-auto-gc", "post-checkout", "reference-transaction"]) { writeFileSync(join(d, h), `#!/bin/sh\ntouch '${marker}'\n`); chmodSync(join(d, h), 0o755); }
  // A pack setting that would make the copy unusable (no reverse index).
  git(a.root, "config", "pack.writeReverseIndex", "false");
  git(a.root, "config", "pack.packSizeLimit", "1k");
  const r = rig();
  r.repos = [a.root];
  r.locked = { sha1: [a.blob], sha256: [] };
  await cycle(r);
  assert.equal(existsSync(marker), false, "no repository-configured program ran");
  assert.equal(r.prep.summary().ready.length, 1);
  const key = copies(r)[0]!;
  assert.equal(readdirSync(join(r.cacheDir, key)).filter((f) => f.endsWith(".pack")).length, 1, "one pack (no packSizeLimit split)");
  r.store.markShutdown();
});

// ── The runner: hardened, sandboxed (docs/design/architecture/write-protection.md §8.2, §8.5) ───

test("prepGitCommand: the hardened global options before the call's own; in the sandbox with only the given binds; nice (a fixed system path) wraps the sandbox", () => {
  const nice = "/usr/bin/nice";
  // No sandbox (none can be made, or MANDU_GIT_SANDBOX=0).
  assert.deepEqual(prepGitCommand(["rev-parse", "--git-common-dir"], {}, null, nice), { file: "git", args: [...HARDENED_GIT_ARGS, "rev-parse", "--git-common-dir"] });
  assert.deepEqual(prepGitCommand(["index-pack"], { lowPriority: true }, null, nice), { file: "/usr/bin/nice", args: ["-n", "19", "git", ...HARDENED_GIT_ARGS, "index-pack"] });
  // In the sandbox: its flags, one --bind per writable directory, then git.
  const sb = { bwrap: "/usr/bin/bwrap", flags: ["--unshare-net", "--ro-bind", "/", "/"] };
  assert.deepEqual(prepGitCommand(["pack-objects", "-q", "/w/out/p"], { writable: ["/w"], lowPriority: true }, sb, nice), {
    file: "/usr/bin/nice",
    args: ["-n", "19", "/usr/bin/bwrap", "--unshare-net", "--ro-bind", "/", "/", "--bind", "/w", "/w", "--", "git", ...HARDENED_GIT_ARGS, "pack-objects", "-q", "/w/out/p"],
  });
  // macOS: sandbox-exec running the probed git under the profile, whose one
  // writable path (besides /dev/null) is the work directory; nice around it.
  const seatbelt = { sandboxExec: "/usr/bin/sandbox-exec", git: "/opt/git/bin/git" };
  const work = "/nonexistent-mandu-prep/w";
  const mac = prepGitCommand(["pack-objects", "-q", `${work}/out/p`], { writable: [work], lowPriority: true }, seatbelt, nice);
  assert.deepEqual(mac, {
    file: "/usr/bin/nice",
    args: ["-n", "19", "/usr/bin/sandbox-exec", "-p", gitSeatbeltProfile(seatbelt.git, [work]), "/opt/git/bin/git", ...HARDENED_GIT_ARGS, "pack-objects", "-q", `${work}/out/p`],
  });
  assert.match(mac.args[4]!, /\(allow file-write\* \(literal "\/dev\/null"\) \(subpath "\/nonexistent-mandu-prep\/w"\)\)/);
  assert.match(mac.args[4]!, /\(allow process-exec \(literal "\/opt\/git\/bin\/git"\)\)/);
  assert.doesNotMatch(prepGitCommand(["rev-parse"], {}, seatbelt, nice).args[1]!, /subpath/, "a read binds nothing on macOS either");
  // A read binds nothing: the whole filesystem stays read-only.
  const read = prepGitCommand(["rev-parse"], {}, sb, nice);
  assert.equal(read.file, "/usr/bin/bwrap");
  assert.equal(read.args.includes("--bind"), false);
  for (const kv of ["core.fsmonitor=false", "core." + "hooksPath=/dev/null", "protocol.allow=never", "log.showSignature=false"]) {
    assert.ok(read.args.includes(kv), `forced: ${kv}`);
  }
  // The default is this process's own nice (niceBinary): one of the fixed
  // paths, or none at all.
  assert.equal(prepGitCommand(["index-pack"], { lowPriority: true }, sb).file, niceBinary() ?? "/usr/bin/bwrap");
});

test("the nice of a low-priority call: /usr/bin/nice, else /bin/nice, never one found on PATH; with neither the call runs without it, still sandboxed", () => {
  assert.deepEqual(NICE_CANDIDATES, ["/usr/bin/nice", "/bin/nice"]);
  const asked: string[] = [];
  const has = (present: readonly string[]) => (p: string): boolean => { asked.push(p); return present.includes(p); };
  assert.equal(resolveNice(has(["/usr/bin/nice", "/bin/nice"])), "/usr/bin/nice", "/usr/bin/nice present: that one");
  assert.equal(resolveNice(has(["/bin/nice"])), "/bin/nice", "only /bin/nice (busybox): that one");
  asked.length = 0;
  assert.equal(resolveNice(has(["/run/current-system/sw/bin/nice", "/home/u/.local/bin/nice"])), null, "neither (NixOS, Guix): none");
  assert.deepEqual(asked, ["/usr/bin/nice", "/bin/nice"], "nothing but the fixed paths is looked at (no PATH search)");
  const here = niceBinary();
  assert.ok(here === null || NICE_CANDIDATES.includes(here), String(here));
  // Each resolved nice wraps the command it is given.
  const sb = { bwrap: "/usr/bin/bwrap", flags: ["--unshare-net"] };
  assert.deepEqual(prepGitCommand(["index-pack"], { writable: ["/w"], lowPriority: true }, sb, "/bin/nice").args.slice(0, 3), ["-n", "19", "/usr/bin/bwrap"]);
  // With none, the build runs as sandboxed as ever, only at normal priority:
  // the argv starts with the sandbox (or git), never a nice.
  assert.deepEqual(prepGitCommand(["index-pack"], { writable: ["/w"], lowPriority: true }, sb, null), {
    file: "/usr/bin/bwrap", args: ["--unshare-net", "--bind", "/w", "/w", "--", "git", ...HARDENED_GIT_ARGS, "index-pack"],
  });
  const seatbelt = { sandboxExec: "/usr/bin/sandbox-exec", git: "/opt/git/bin/git" };
  const work = "/nonexistent-mandu-prep/w";
  assert.deepEqual(prepGitCommand(["index-pack"], { writable: [work], lowPriority: true }, seatbelt, null), {
    file: "/usr/bin/sandbox-exec", args: ["-p", gitSeatbeltProfile(seatbelt.git, [work]), "/opt/git/bin/git", ...HARDENED_GIT_ARGS, "index-pack"],
  });
  assert.deepEqual(prepGitCommand(["index-pack"], { lowPriority: true }, null, null), { file: "git", args: [...HARDENED_GIT_ARGS, "index-pack"] });
});

test("prepGitEnv: no inherited GIT_* reaches git; the system config skipped, no lazy fetch, no prompt; the call's own variables on top", () => {
  const names = ["GIT_DIR", "GIT_OBJECT_DIRECTORY", "GIT_SSH_COMMAND"] as const;
  const saved = names.map((k) => process.env[k]);
  process.env["GIT_DIR"] = "/elsewhere";
  process.env["GIT_OBJECT_DIRECTORY"] = "/elsewhere/objects";
  process.env["GIT_SSH_COMMAND"] = "/tmp/planted";
  try {
    const env = prepGitEnv({ GIT_CONFIG_GLOBAL: "/dev/null", GIT_OBJECT_DIRECTORY: "/w/odb" });
    assert.equal(env["GIT_DIR"], undefined);
    assert.equal(env["GIT_SSH_COMMAND"], undefined);
    assert.equal(env["GIT_OBJECT_DIRECTORY"], "/w/odb", "the call's own, not the inherited one");
    assert.equal(env["GIT_CONFIG_GLOBAL"], "/dev/null");
    assert.equal(env["GIT_CONFIG_NOSYSTEM"], "1");
    assert.equal(env["GIT_NO_LAZY_FETCH"], "1");
    assert.equal(env["GIT_TERMINAL_PROMPT"], "0");
    assert.equal(env["LC_ALL"], "C");
  } finally {
    names.forEach((k, i) => { const v = saved[i]; if (v === undefined) delete process.env[k]; else process.env[k] = v; });
  }
});

test("the build's calls: reads bind nothing; init, pack-objects and index-pack bind only the build's own work directory, which holds the private bare repository; no caller repeats the hardening", async () => {
  const a = repo();
  const calls: Array<{ args: string[]; cwd: string; writable: readonly string[]; lowPriority: boolean; env: Record<string, string> }> = [];
  const real = prepGit(new Set(), () => null);
  const git: PrepGit = (args, opts) => {
    calls.push({ args, cwd: opts.cwd, writable: opts.writable ?? [], lowPriority: opts.lowPriority === true, env: opts.env ?? {} });
    return real(args, opts);
  };
  const r = rig({ git });
  r.repos = [a.root];
  r.locked = { sha1: [a.blob], sha256: [] };
  await cycle(r);
  assert.equal(r.prep.summary().ready.length, 1, "the copy is built through the recorded runner");
  const sub = (c: { args: string[] }): string => c.args.find((x) => !x.startsWith("-") && !x.includes("="))!;
  assert.deepEqual(calls.map(sub), ["rev-parse", "init", "rev-parse", "pack-objects", "index-pack"]);
  for (const c of calls) {
    assert.equal(c.args.includes("--no-pager"), false, "the runner, not the caller, adds the hardened options");
    assert.equal(c.args.some((x) => x.startsWith("core.")), false, "no caller-side core.* override");
  }
  for (const c of calls.filter((x) => sub(x) === "rev-parse")) {
    assert.deepEqual(c.writable, [], "a read binds nothing");
    assert.equal(c.cwd, a.root);
  }
  const writers = calls.filter((x) => sub(x) !== "rev-parse");
  const work = writers[0]!.writable;
  assert.equal(work.length, 1, "one writable bind");
  assert.match(work[0]!, new RegExp(`^${r.cacheDir}/\\.tmp-[0-9a-f]{32}-\\d+-prep$`), "the build's own work directory in the cache");
  for (const c of writers) {
    assert.deepEqual(c.writable, work, `${sub(c)}: the same single bind`);
    assert.equal(c.env["GIT_CONFIG_GLOBAL"], "/dev/null", `${sub(c)}: no user config`);
    assert.equal(c.cwd, r.cacheDir, `${sub(c)}: never run in the repository`);
  }
  const gitDir = join(work[0]!, "git");
  assert.ok(calls.find((x) => sub(x) === "init")!.args.includes(gitDir), "the private bare repository is inside the bind");
  for (const c of calls.filter((x) => sub(x) === "pack-objects" || sub(x) === "index-pack")) {
    assert.ok(c.args.includes(`--git-dir=${gitDir}`), `${sub(c)}: against the private bare repository`);
    assert.equal(c.lowPriority, true, `${sub(c)}: at nice 19`);
  }
  assert.equal(existsSync(work[0]!), false, "the work directory is removed");
  r.store.markShutdown();
});

// ── Never hang (write-protection.md §8.5.1; CI pipelines 7777 and 7778) ───────────

// The real timers, taken before any test mocks them: a hang guard keeps
// counting while a test drives the preparer's deadlines by hand.
const { setTimeout: realSetTimeout, clearTimeout: realClearTimeout } = globalThis;
const sleep = (ms: number): Promise<void> => new Promise((res) => realSetTimeout(res, ms));
/** `p`, or a failure naming `what` after `ms` of real time (the timer cleared either way). */
async function within<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let t: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([p, new Promise<never>((_, rej) => { t = realSetTimeout(() => rej(new Error(`${what} did not return within ${ms} ms`)), ms); })]);
  } finally {
    realClearTimeout(t);
  }
}
/** Let the event loop run what is ready (I/O callbacks, immediates). */
const turns = async (n = 20): Promise<void> => { for (let i = 0; i < n; i++) await new Promise((res) => setImmediate(res)); };

test("a git call that never settles is given up at its deadline plus the grace: the cycle ends, the repository is failed (left to the backstop) and the log says so", async () => {
  const a = repo();
  const logs: string[] = [];
  const never: PrepGit = () => new Promise(() => { /* a runner that never answers */ });
  const r = rig({ git: never, limits: { inventoryTimeoutMs: 50, settleGraceMs: 50 }, log: (m) => logs.push(m) });
  r.repos = [a.root];
  r.locked = { sha1: [a.blob], sha256: [] };
  await within(cycle(r), 5000, "the cycle");
  const s = r.prep.summary();
  assert.deepEqual(s.ready, []);
  assert.deepEqual(s.failed.map((f) => f.root), [a.root]);
  assert.match(s.failed[0]!.reason, /git rev-parse did not finish within its 50 ms deadline/);
  assert.ok(logs.some((l) => /git rev-parse did not settle within 100 ms; given up \(the repository is left to the backstop\)/.test(l)), logs.join("\n"));
  assert.equal(copies(r).length, 0, "nothing built, nothing sealed");
  r.store.markShutdown();
});

// The deadline here is the preparer's clock, never the host's speed: with
// setTimeout mocked, the stalled call is given up exactly when the test moves
// the clock past its deadline plus the grace, and the retry's REAL git runs
// with no deadline that can fire (none fires unless ticked). With real timers
// the retry's own pack-objects and index-pack ran under the same 50 ms
// deadline, at nice 19, and a loaded runner killed them ("built on the next
// cycle", 0 !== 1: CI pipelines 7902, 7960 and 7996; write-protection.md §8.5.1).
test("a build whose pack-objects never settles fails its repository at the deadline: nothing sealed, the work directory removed, the next cycle tries again", async (t) => {
  const a = repo();
  const real = prepGit(new Set(), () => null);
  let stall = true;
  let stalled = (): void => {};
  const stalling = new Promise<void>((res) => { stalled = res; });
  const git: PrepGit = (args, opts) => {
    if (!(stall && args.includes("pack-objects"))) return real(args, opts);
    stalled();
    return new Promise(() => { /* stuck */ });
  };
  const r = rig({ git, limits: { packTimeoutMs: 50, settleGraceMs: 50 } });
  r.repos = [a.root];
  r.locked = { sha1: [a.blob], sha256: [] };
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let ended = false;
  const first = cycle(r).then(() => { ended = true; });
  await within(stalling, 10_000, "the stalled pack-objects");
  t.mock.timers.tick(99);
  await turns();
  assert.equal(ended, false, "not given up before its deadline plus the grace");
  t.mock.timers.tick(1);
  await within(first, 10_000, "the cycle");
  assert.match(r.prep.summary().failed[0]?.reason ?? "", /git pack-objects failed: git pack-objects did not finish within its 50 ms deadline/);
  assert.equal(copies(r).length, 0, "nothing sealed");
  assert.deepEqual(readdirSync(r.cacheDir).filter((n) => n.startsWith(".tmp-")), [], "the build's work directory is removed");
  stall = false;
  await within(cycle(r), 60_000, "the next cycle");
  assert.equal(r.prep.summary().ready.length, 1, "built on the next cycle");
  assert.equal(copies(r).length, 1, "one copy");
  assert.deepEqual(readdirSync(r.cacheDir).filter((n) => n.startsWith(".tmp-")), [], "no work directory left");
  t.mock.timers.reset();
  r.store.markShutdown();
});

test("stop() during a call that never settles returns at once, and no call starts after it", async () => {
  const a = repo();
  let calls = 0;
  const never: PrepGit = () => { calls++; return new Promise(() => { /* stuck */ }); };
  const r = rig({ git: never });
  r.repos = [a.root];
  r.locked = { sha1: [a.blob], sha256: [] };
  void r.prep.runCycle();
  for (let i = 0; i < 200 && calls === 0; i++) await sleep(5);
  assert.equal(calls, 1);
  await within(r.prep.stop(), 2000, "stop()");
  r.prep.kick();
  await r.prep.runCycle();
  assert.equal(calls, 1, "nothing runs once stopped");
  r.store.markShutdown();
});

// The CI hang itself: an ArbiterServer's close() stops the preparer while a
// background cycle (kicked by a resolution, a rotation, a launch) is
// starting a call. With bubblewrap (the git sandbox where it works) killed
// in its start-up, the call used to never settle and stop() never returned
// (15 of 200 races on the host this was written on).
// On macOS this runs real git under the Seatbelt git sandbox (hardened-git.ts,
// write-protection.md §8.5.2) wherever that sandbox can be made.
test("stop() racing a cycle's real git (in the git sandbox where one can be made: bubblewrap on Linux, Seatbelt on macOS) always returns", async () => {
  const a = repo();
  const races = 48;
  let next = 0;
  const lane = async (): Promise<void> => {
    while (next < races) {
      next++;
      const r = rig();
      r.repos = [a.root];
      r.locked = { sha1: [a.blob], sha256: [] };
      void r.prep.runCycle();
      await sleep(Math.random() * 40);
      await within(r.prep.stop(), 8000, "stop()");
      await within(r.prep.idle(), 1000, "idle()");
      r.store.markShutdown();
    }
  };
  await Promise.all(Array.from({ length: 8 }, lane));
});

// ── Stores shared through alternates (confidentiality.md §7.2a) ─────────────

const KEYS = {
  a: ["CHAIN", "A", "KEY", "7731", "Qa".repeat(12)].join("_"),
  w: ["CHAIN", "W", "KEY", "7731", "Qw".repeat(12)].join("_"),
  b: ["CHAIN", "B", "KEY", "7731", "Qb".repeat(12)].join("_"),
  c: ["CHAIN", "C", "KEY", "7731", "Qc".repeat(12)].join("_"),
};

/** One version of a key committed then deleted in `root`. Its blob id. */
function commitKey(root: string, file: string, key: string): string {
  writeFileSync(join(root, file), `${key}\n`);
  git(root, "add", "."); git(root, "commit", "-qm", `add ${file}`);
  const blob = git(root, "rev-parse", `HEAD:${file}`).trim();
  git(root, "rm", "-q", file); git(root, "commit", "-qm", `remove ${file}`);
  return blob;
}

/** The one pack of a repository's own object directory (no extension). */
function packOf(root: string): string {
  const d = join(root, ".git", "objects", "pack");
  const n = readdirSync(d).filter((x) => x.endsWith(".pack"));
  assert.equal(n.length, 1, `${root}: one pack`);
  return join(d, n[0]!.slice(0, -5));
}

/**
 * A ← B ← C: B is `git clone --shared` of A and C of B (each reads its
 * parent's objects through `objects/info/alternates`, so C reaches A only
 * through B's file). A's pack holds two locked versions (X and W), B's and
 * C's their own (Y, Z): each repacked LOCAL (`repack -adl`), so a borrowed
 * object stays in the parent's pack.
 */
function chain(): { a: string; b: string; c: string; x: string; w: string; y: string; z: string } {
  const top = tmp();
  const a = join(top, "a");
  git(top, "init", "-q", "-b", "main", a);
  writeFileSync(join(a, "README"), "readme of a\n");
  git(a, "add", "."); git(a, "commit", "-qm", "readme");
  const x = commitKey(a, "id_rsa", KEYS.a);
  const w = commitKey(a, "staging.env", KEYS.w);
  git(a, "repack", "-adq");
  const b = join(top, "b");
  git(top, "clone", "-q", "--shared", a, b);
  const y = commitKey(b, "id_b", KEYS.b);
  git(b, "repack", "-adlq");
  const c = join(top, "c");
  git(top, "clone", "-q", "--shared", b, c);
  const z = commitKey(c, "id_c", KEYS.c);
  git(c, "repack", "-adlq");
  return { a, b, c, x, w, y, z };
}

const alternatesOf = (root: string): string => join(root, ".git", "objects", "info", "alternates");

/** Every copy of the cache: its index free of every locked id, no key's bytes. */
function assertNoLockedId(r: Rig, ids: readonly string[]): void {
  for (const k of copies(r)) {
    const idx = readdirSync(join(r.cacheDir, k)).find((f) => f.endsWith(".idx"))!;
    assert.deepEqual(idxLookupFile(join(r.cacheDir, k, idx), ids), [], `${k}: the copy lists no locked id`);
    for (const f of readdirSync(join(r.cacheDir, k))) {
      const bytes = readFileSync(join(r.cacheDir, k, f));
      for (const key of Object.values(KEYS)) assert.ok(!bytes.includes(key), `${k}/${f}: no key's bytes`);
    }
  }
}

test("inventoryStores (pure): each real object directory inventoried once, its pack entries shared by every repository reading it; two object formats or an unreadable index fail every reader", async () => {
  const calls: string[] = [];
  const pack = (dir: string): PrepPack => ({ base: `${dir}/pack/pack-1`, exclude: ["a".repeat(40)], key: `k-${dir}`, size: 1, hasRev: false, ready: false });
  const inv = (dir: string): PrepDir => {
    calls.push(dir);
    if (dir === "/bad") throw new Error("pack index truncated");
    return dir === "/empty" ? { packs: [] } : { packs: [pack(dir)] };
  };
  const set = { sha1: ["a".repeat(40)], sha256: ["b".repeat(64)] };
  const got = await inventoryStores([
    { root: "/c", format: "sha1", dirs: ["/c/o", "/b/o", "/a/o"] },
    { root: "/b", format: "sha1", dirs: ["/b/o", "/a/o"] },
    { root: "/clean", format: "sha1", dirs: ["/empty"] },
    { root: "/x", format: "sha1", dirs: ["/x/o", "/bad"] },
    { root: "/y", format: "sha1", dirs: ["/bad"] },
    { root: "/s1", format: "sha1", dirs: ["/s1/o", "/mixed"] },
    { root: "/s256", format: "sha256", dirs: ["/s256/o", "/mixed"] },
  ], set, { inventoryDir: inv });
  assert.deepEqual(calls.sort(), ["/a/o", "/b/o", "/bad", "/c/o", "/empty", "/s1/o", "/s256/o", "/x/o"], "each directory once; the mixed one never read with a wrong hash length");
  const c = got.repos.find((r) => r.root === "/c")!;
  const b = got.repos.find((r) => r.root === "/b")!;
  assert.deepEqual(c.packs.map((p) => p.key), ["k-/c/o", "k-/b/o", "k-/a/o"], "C reads A two links away");
  assert.equal(c.packs[2], b.packs[1], "the SAME entry: one copy, built once, ready for both");
  assert.equal(got.repos.some((r) => r.root === "/clean"), false, "nothing locked: left out");
  assert.match(got.failed.get("/x")!, /could not read the object store \/bad: pack index truncated/);
  assert.match(got.failed.get("/y")!, /\/bad/, "every reader of the directory fails");
  assert.match(got.failed.get("/s1")!, /two object formats/);
  assert.match(got.failed.get("/s256")!, /two object formats/);
});

test("plan: a pack several repositories read counts once against the total and is built once", () => {
  const shared = P("ks", 40 * MB);
  const repos: PrepRepo[] = [
    { root: "/a", format: "sha1", packs: [shared] },
    { root: "/b", format: "sha1", packs: [P("kb", 10 * MB), shared] },
    { root: "/c", format: "sha1", packs: [P("kc", 10 * MB), { ...shared }] },
  ];
  const p = planPreparation(repos, { cycleBytes: 1000 * MB, totalBytes: 60 * MB });
  assert.deepEqual(p.build.map((x) => x.pack.key), ["ks", "kb", "kc"], "the shared pack once");
  assert.equal(p.wantedBytes, 60 * MB, "40 + 10 + 10: the shared pack's bytes once (three times would cap B and C)");
  for (const r of ["/a", "/b", "/c"]) assert.equal(p.state.get(r)!.state, "pending", r);
  const failed = planPreparation([{ root: "/m", format: "sha1", packs: [], unsupported: "/mixed is read by repositories of two object formats" }], { cycleBytes: MB, totalBytes: MB });
  assert.equal(failed.state.get("/m")!.state, "failed", "an unsupported layout fails even with no pack found");
});

test("a chain A ← B ← C: C registered alone gets a copy of every pack it reads, A's two links away included, A's copy excluding the union of the locked ids it holds", async () => {
  const ch = chain();
  assert.equal(readFileSync(alternatesOf(ch.c), "utf8").trim(), join(ch.b, ".git", "objects"), "C names only B; A is B's alternate");
  const r = rig();
  r.repos = [ch.c];
  r.locked = { sha1: [ch.x, ch.w, ch.y, ch.z], sha256: [] };
  await cycle(r);
  const s = r.prep.summary();
  assert.deepEqual(s.ready, [{ root: ch.c, format: "sha1" }], JSON.stringify(s));
  const want = [
    rebuildKey(packOf(ch.a), [ch.x, ch.w]),
    rebuildKey(packOf(ch.b), [ch.y]),
    rebuildKey(packOf(ch.c), [ch.z]),
  ].sort();
  assert.deepEqual(copies(r), want, "one copy per pack C reads: A's keyed by the union of what it holds");
  assertNoLockedId(r, [ch.x, ch.w, ch.y, ch.z]);
  await cycle(r);
  assert.equal(r.prep.lastBuilt, 0);
  r.store.markShutdown();
});

test("a clone --shared pair, each locking a different version in the shared pack: ONE copy of A's pack, excluding both, built once; both repositories ready", async () => {
  const ch = chain();
  const r = rig();
  // B first: the order the registry lists them in must not matter.
  r.repos = [ch.b, ch.a];
  r.locked = { sha1: [ch.x, ch.w, ch.y], sha256: [] };
  await cycle(r);
  assert.deepEqual(r.prep.summary().ready.map((x) => x.root).sort(), [ch.a, ch.b].sort());
  assert.equal(r.prep.lastBuilt, 2, "A's pack once, B's once");
  assert.deepEqual(copies(r), [rebuildKey(packOf(ch.a), [ch.x, ch.w]), rebuildKey(packOf(ch.b), [ch.y])].sort());
  const sizes = [packOf(ch.a), packOf(ch.b)].reduce((n, p) => n + statSync(`${p}.pack`).size, 0);
  assert.equal(r.prep.summary().bytes, sizes, "the shared pack counted once");
  assertNoLockedId(r, [ch.x, ch.w, ch.y]);
  r.store.markShutdown();
});

test("alternates: a cycle (A names C) ends; a relative entry resolves against the directory whose file names it", async () => {
  const ch = chain();
  writeFileSync(alternatesOf(ch.a), `${join(ch.c, ".git", "objects")}\n`);
  writeFileSync(alternatesOf(ch.c), "../../../b/.git/objects\n");
  const r = rig();
  r.repos = [ch.c, ch.a];
  r.locked = { sha1: [ch.x, ch.w, ch.y, ch.z], sha256: [] };
  await cycle(r);
  assert.deepEqual(r.prep.summary().ready.map((x) => x.root).sort(), [ch.a, ch.c].sort());
  assert.deepEqual(r.prep.summary().failed, []);
  assert.equal(r.prep.lastBuilt, 3, "three packs, each once, whichever repository reached it");
  assert.equal(copies(r).length, 3);
  r.store.markShutdown();
});

test("fail closed: an odd or unreadable alternates file, in C's own directory or two links away, gives C no copy and the cycle ends (a FIFO never blocks it)", async () => {
  const cases: Array<{ what: string; setup: (ch: ReturnType<typeof chain>) => void; why: RegExp }> = [
    { what: "a FIFO", setup: (ch) => { rmSync(alternatesOf(ch.c)); execFileSync("mkfifo", [alternatesOf(ch.c)]); }, why: /not a regular file/ },
    { what: "a directory", setup: (ch) => { rmSync(alternatesOf(ch.c)); mkdirSync(alternatesOf(ch.c)); }, why: /not a regular file/ },
    { what: "a quoted entry git would not unquote", setup: (ch) => writeFileSync(alternatesOf(ch.c), "\"/unterminated\n"), why: /closing quote/ },
    { what: "a NUL", setup: (ch) => writeFileSync(alternatesOf(ch.c), `${join(ch.b, ".git", "objects")}\0\n`), why: /NUL/ },
    { what: "B's file (two links from C) not UTF-8", setup: (ch) => writeFileSync(alternatesOf(ch.b), Buffer.from([0x2f, 0xff, 0x0a])), why: /not UTF-8/ },
  ];
  for (const k of cases) {
    const ch = chain();
    k.setup(ch);
    const r = rig();
    r.repos = [ch.c];
    r.locked = { sha1: [ch.x, ch.w, ch.y, ch.z], sha256: [] };
    await cycle(r);
    const s = r.prep.summary();
    assert.deepEqual(s.ready, [], k.what);
    assert.equal(s.failed.length, 1, k.what);
    assert.match(s.failed[0]!.reason, k.why, `${k.what}: ${s.failed[0]!.reason}`);
    assert.deepEqual(copies(r), [], `${k.what}: no copy (the backstop keeps refusing), never one of a shorter list`);
    r.store.markShutdown();
  }
  // Unreadable (a permission root would read through): the reader throws.
  const ch = chain();
  const r = rig();
  const io: AlternatesIo = {
    read: (d) => {
      if (d.startsWith(ch.b)) throw new Error("EACCES");
      return d.startsWith(ch.c) ? `${join(ch.b, ".git", "objects")}\n` : null;
    },
    realDir: (p) => { try { return realpathSync(p); } catch { return null; } },
  };
  const prep = new PreparedCopies({
    cacheDir: r.cacheDir, seals: r.store, repos: () => [ch.c], lockedSet: () => ({ sha1: [ch.x], sha256: [] }), alternatesIo: io, limits: { pruneGraceMs: 0 },
  });
  await prep.runCycle();
  await prep.idle();
  assert.match(prep.summary().failed[0]?.reason ?? "", /alternates of .* cannot be read \(EACCES\)/);
  assert.deepEqual(copies(r), []);
  r.store.markShutdown();
});
