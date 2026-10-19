/**
 * Unit: git-object-twins — the pure parsers and the planner that decide which
 * object-store files hide a protected file's committed bytes
 * (docs/design/confidentiality/confidentiality.md §7.2a).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ALTERNATES_MAX_BYTES,
  ALTERNATES_MAX_DEPTH,
  clusterObjectStores,
  defaultAlternatesIo,
  objectStoreClosure,
  parseAlternates,
  type AlternatesIo,
  alternateObjectDirsEnv,
  groupByRepo,
  idxLookup,
  idxObjectNames,
  maxRebuildBytesFromEnv,
  parseHashLines,
  parseLsFilesStage,
  parseRawLogBlobs,
  parseWalkCache,
  planObjectTwins,
  planWalk,
  prepareGitObjectTwins,
  rebuildKey,
  repoRootOf,
  walkBaseKey,
  walkCacheFile,
  type GitRunner,
  type WalkCacheEntry,
  type ObjectDirInventory,
} from "../../src/git-object-twins.js";
import { withObjectTwins } from "../../src/secret-twins.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // pure planning; the confidentiality axis is what uses it

const A = "a".repeat(40);
const B = "b".repeat(40);
const C = "c".repeat(40);
const Z = "0".repeat(40);

/** A version-2 pack index listing `names` (sorted, SHA-1). */
function idxV2(names: string[]): Buffer {
  const sorted = [...names].sort();
  const fan = Buffer.alloc(256 * 4);
  for (let i = 0; i < 256; i++) fan.writeUInt32BE(sorted.filter((n) => parseInt(n.slice(0, 2), 16) <= i).length, i * 4);
  const head = Buffer.alloc(8);
  head.writeUInt32BE(0xff744f63, 0);
  head.writeUInt32BE(2, 4);
  return Buffer.concat([head, fan, ...sorted.map((n) => Buffer.from(n, "hex")), Buffer.alloc(40)]);
}

test("idxObjectNames reads a v2 index and refuses anything else", () => {
  assert.deepEqual(idxObjectNames(idxV2([B, A, C])), [A, B, C]);
  assert.deepEqual(idxObjectNames(idxV2([])), []);
  assert.throws(() => idxObjectNames(Buffer.alloc(10)), /too small/);
  const v1 = idxV2([A]);
  v1.writeUInt32BE(1, 4);
  assert.throws(() => idxObjectNames(v1), /version-2/);
  assert.throws(() => idxObjectNames(idxV2([A, B]).subarray(0, 8 + 1024 + 20)), /truncated/);
});

test("parseRawLogBlobs: both sides of every change, never a gitlink or the zero name", () => {
  const out =
    `:000000 100644 ${Z} ${A} A\x00notes/secret.md\x00` +
    `\n:100644 100644 ${A} ${B} M\x00notes/secret.md\x00` +
    `:160000 160000 ${C} ${C} M\x00vendor/sub\x00`;
  assert.deepEqual(parseRawLogBlobs(out), [A, B]);
  assert.deepEqual(parseRawLogBlobs(""), []);
});

test("parseLsFilesStage: every stage's blob; parseHashLines: one name per line", () => {
  assert.deepEqual(parseLsFilesStage(`100644 ${A} 0\tnotes/secret.md\x00100644 ${B} 2\t.env\x00160000 ${C} 0\tsub\x00`), [A, B]);
  assert.deepEqual(parseHashLines(`${A}\n${B}\nnot a hash\n`), [A, B]);
});

test("repoRootOf: the nearest .git, never a file inside .git itself", () => {
  const have = new Set(["/w/.git", "/w/sub/.git"]);
  const exists = (p: string) => have.has(p);
  assert.equal(repoRootOf("/w/notes/secret.md", exists), "/w");
  assert.equal(repoRootOf("/w/sub/.env", exists), "/w/sub", "a submodule or nested repo is its own");
  assert.equal(repoRootOf("/elsewhere/.env", exists), null);
  assert.equal(repoRootOf("/w/.git/config", exists), null);
  assert.deepEqual([...groupByRepo(["/w/b", "/w/a", "/w/a", "/x/y"], exists)], [["/w", ["a", "b"]]]);
});

function dir(over: Partial<ObjectDirInventory> = {}): ObjectDirInventory {
  return {
    dir: "/w/.git/objects",
    packs: [
      { base: "/w/.git/objects/pack/pack-1", held: [A, B, C], hasRev: true, hasBitmap: true, hasMtimes: false, size: 100 },
      { base: "/w/.git/objects/pack/pack-2", held: [C], hasRev: false, hasBitmap: false, hasMtimes: false, size: 10 },
    ],
    looseProtected: ["/w/.git/objects/bb/" + "b".repeat(38)],
    midx: ["/w/.git/objects/pack/multi-pack-index"],
    incrementalMidx: false,
    ...over,
  };
}

test("planObjectTwins: rebuild the packs holding a protected blob, deny what indexes them by position and every loose copy", () => {
  const p = planObjectTwins([dir()], [A, B]);
  assert.deepEqual(p.rebuild.map((r) => [r.pack.base, r.exclude]), [["/w/.git/objects/pack/pack-1", [A, B]]]);
  assert.equal(p.rebuild[0]!.key, rebuildKey("/w/.git/objects/pack/pack-1", [B, A]), "the key ignores order");
  assert.deepEqual(p.deny, [
    "/w/.git/objects/bb/" + "b".repeat(38),
    "/w/.git/objects/pack/multi-pack-index",
    "/w/.git/objects/pack/pack-1.bitmap",
  ]);
  assert.deepEqual(p.unsupported, []);
});

test("planObjectTwins: nothing protected, nothing touched; a pack-free directory denies only loose copies", () => {
  assert.deepEqual(planObjectTwins([dir()], []), { rebuild: [], deny: [], unsupported: [] });
  const loose = planObjectTwins([dir({ packs: [], midx: ["/m"] })], [B]);
  assert.deepEqual(loose.rebuild, []);
  assert.deepEqual(loose.deny, ["/w/.git/objects/bb/" + "b".repeat(38)], "no pack rewritten: the midx still matches its packs");
});

test("planObjectTwins: an incremental multi-pack-index is refused (fail-closed), a cruft pack's mtimes denied", () => {
  const p = planObjectTwins([dir({ incrementalMidx: true })], [A]);
  assert.equal(p.unsupported.length, 1);
  const m = planObjectTwins([dir({ packs: [{ base: "/p/pack-9", held: [A], hasRev: false, hasBitmap: false, hasMtimes: true, size: 1 }] })], [A]);
  assert.ok(m.deny.includes("/p/pack-9.mtimes"));
});

test("rebuildKey differs by pack and by excluded set", () => {
  assert.notEqual(rebuildKey("/x/pack-1", [A]), rebuildKey("/x/pack-2", [A]));
  assert.notEqual(rebuildKey("/x/pack-1", [A]), rebuildKey("/x/pack-1", [A, B]));
  assert.equal(rebuildKey("/x/pack-1", [A]), rebuildKey("/other/dir/pack-1", [A]), "keyed by the pack's name, not where it sits");
});

test("maxRebuildBytesFromEnv: MiB from the env, the default otherwise", () => {
  assert.equal(maxRebuildBytesFromEnv({ MANDU_GIT_TWIN_MAX_MB: "8" }), 8 * 1048576);
  assert.equal(maxRebuildBytesFromEnv({ MANDU_GIT_TWIN_MAX_MB: "nope" }), 1024 * 1048576);
  assert.equal(maxRebuildBytesFromEnv({}), 1024 * 1048576);
});

test("prepareGitObjectTwins: a file in no repository costs no git call; a git failure is a GitObjectTwinError", async () => {
  let calls = 0;
  const git: GitRunner = async () => { calls++; return { code: 128, stdout: "", stderr: "fatal: boom" }; };
  const none = await prepareGitObjectTwins(["/nowhere/.env"], { cacheDir: "/c", denyFile: "/d", git, exists: () => false });
  assert.deepEqual(none.twins, []);
  assert.equal(calls, 0);
  await assert.rejects(
    prepareGitObjectTwins(["/w/.env"], { cacheDir: "/c", denyFile: "/d", git, exists: (p) => p === "/w/.git" }),
    (e: Error) => e.name === "GitObjectTwinError" && /git rev-parse failed.*boom/.test(e.message),
  );
});

test("withObjectTwins: masks then binds before the trailing --, deduplicated; an empty wrap stays empty", () => {
  const wrap = ["bwrap", "--dev-bind", "/", "/", "--bind", "/t/0", "/s", "--"];
  assert.deepEqual(
    withObjectTwins(wrap, [
      { targetPath: "/r/p.pack", twinPath: "/c/p.pack" },
      { targetPath: "/r/o/ab", twinPath: "/deny" },
      { targetPath: "/r/p.pack", twinPath: "/c/other" },
    ], ["/h/.mandu/workspaces"]),
    ["bwrap", "--dev-bind", "/", "/", "--bind", "/t/0", "/s", "--tmpfs", "/h/.mandu/workspaces", "--bind", "/deny", "/r/o/ab", "--bind", "/c/p.pack", "/r/p.pack", "--"],
  );
  assert.deepEqual(withObjectTwins([], [{ targetPath: "/a", twinPath: "/b" }], ["/m"]), []);
});

// ── idxLookup: the protected names a pack lists, without reading it whole ──

const reader = (buf: Buffer, seen?: number[]) => (offset: number, len: number) => {
  seen?.push(len);
  return buf.subarray(offset, offset + len);
};

test("idxLookup finds exactly the listed names among the asked ones, as idxObjectNames would", () => {
  const listed = Array.from({ length: 500 }, (_, i) => createHash("sha1").update(`o${i}`).digest("hex"));
  const idx = idxV2(listed);
  const absent = [A, B, "0f".repeat(20), "ff".repeat(20), "00".repeat(20)];
  const ask = [listed[0]!, listed[250]!, listed[499]!, ...absent];
  const want = ask.filter((n) => idxObjectNames(idx).includes(n)).sort();
  assert.deepEqual(idxLookup(reader(idx), ask), want);
  assert.deepEqual(idxLookup(reader(idx), listed), [...listed].sort(), "every listed name is found");
  assert.deepEqual(idxLookup(reader(idx), absent), [], "no absent name is found");
  assert.deepEqual(idxLookup(reader(idxV2([])), [A]), [], "an empty pack lists nothing");
  assert.deepEqual(idxLookup(reader(idx), ["not-hex", "ab"]), [], "a malformed name is never a match");
});

test("idxLookup reads the header and a few entries per name, never the whole index", () => {
  const listed = Array.from({ length: 20_000 }, (_, i) => createHash("sha1").update(`p${i}`).digest("hex"));
  const idx = idxV2(listed);
  const seen: number[] = [];
  assert.deepEqual(idxLookup(reader(idx, seen), [listed[1234]!]), [listed[1234]!]);
  const bytes = seen.reduce((a, b) => a + b, 0);
  assert.ok(bytes < 2 * 1024, `read ${bytes} bytes of a ${idx.length}-byte index`);
});

test("idxLookup refuses what is not a version-2 index (the caller fails closed)", () => {
  assert.throws(() => idxLookup(reader(Buffer.alloc(10)), [A]), /too small/);
  const v1 = idxV2([A]);
  v1.writeUInt32BE(1, 4);
  assert.throws(() => idxLookup(reader(v1), [A]), /version-2/);
  const cut = idxV2([A, B, C]).subarray(0, 8 + 1024 + 20);
  assert.throws(() => idxLookup(reader(cut), [A]), /truncated/);
});

// ── the history-walk cache ──────────────────────────────────────────────────

const entry = (over: Partial<WalkCacheEntry> = {}): WalkCacheEntry =>
  ({ v: 1, root: "/w", rels: ["a", "b"], base: "K", tips: [A, B], blobs: [C], ...over });

test("planWalk: the same tips hit, new tips walk only what the old tips cannot reach, anything else walks it all", () => {
  assert.deepEqual(planWalk(null, "/w", ["a", "b"], "K", [A, B]), { kind: "full" }, "no cache");
  assert.deepEqual(planWalk(entry(), "/w", ["b", "a"], "K", [B, A]), { kind: "hit" }, "same tips, any order");
  assert.deepEqual(planWalk(entry(), "/w", ["a", "b"], "K", [A]), { kind: "hit" }, "a tip gone: the cached names are a superset");
  assert.deepEqual(planWalk(entry(), "/w", ["a", "b"], "K", [A, B, C]), { kind: "incremental", include: [C], exclude: [A, B] });
  assert.deepEqual(planWalk(entry(), "/w", ["a", "b"], "K2", [A, B]), { kind: "full" }, "another base (git, grafts, shallow, replace refs)");
  assert.deepEqual(planWalk(entry(), "/w", ["a"], "K", [A, B]), { kind: "full" }, "other paths");
  assert.deepEqual(planWalk(entry(), "/w", ["a", "c"], "K", [A, B]), { kind: "full" }, "other paths, same count");
  assert.deepEqual(planWalk(entry(), "/v", ["a", "b"], "K", [A, B]), { kind: "full" }, "another repository");
});

test("parseWalkCache: a torn, foreign or malformed file is no entry (the caller walks it all)", () => {
  assert.deepEqual(parseWalkCache(JSON.stringify(entry())), entry());
  assert.equal(parseWalkCache(""), null);
  assert.equal(parseWalkCache(JSON.stringify(entry()).slice(0, 20)), null);
  assert.equal(parseWalkCache(JSON.stringify({ ...entry(), v: 2 })), null);
  assert.equal(parseWalkCache(JSON.stringify({ ...entry(), blobs: ["zz"] })), null);
  assert.equal(parseWalkCache(JSON.stringify({ ...entry(), tips: "x" })), null);
  assert.equal(parseWalkCache("null"), null);
});

test("walkCacheFile is per (repository, paths), path order aside; walkBaseKey moves with what rewrites history", () => {
  assert.equal(walkCacheFile("/c", "/w", ["a", "b"]), walkCacheFile("/c", "/w", ["b", "a"]));
  assert.notEqual(walkCacheFile("/c", "/w", ["a"]), walkCacheFile("/c", "/w", ["a", "b"]));
  assert.notEqual(walkCacheFile("/c", "/w", ["a"]), walkCacheFile("/c", "/v", ["a"]));
  const k = { gitVersion: "git version 2.43.0\n", shallow: "", grafts: "", replaceRefs: "" };
  const base = walkBaseKey(k);
  assert.equal(walkBaseKey({ ...k, gitVersion: "git version 2.43.0" }), base);
  for (const f of ["gitVersion", "shallow", "grafts", "replaceRefs"] as const) {
    assert.notEqual(walkBaseKey({ ...k, [f]: `${k[f]}x` }), base, `${f} is part of the base`);
  }
});

test("alternateObjectDirsEnv: colon-separated, deduplicated, and an entry with a colon or a leading quote C-quoted", () => {
  assert.equal(alternateObjectDirsEnv(["/r/.git/objects", "/a/objects", "/r/.git/objects"]), "/r/.git/objects:/a/objects");
  assert.equal(alternateObjectDirsEnv(["/odd:dir/objects", '"q/objects']), '"/odd:dir/objects":"\\"q/objects"');
});

// ── Alternates (confidentiality.md §7.2a "Stores shared through alternates") ──

test("parseAlternates: one entry per line as git reads them; comments and empty lines skipped, C-quoted entries unquoted, a trimmed spelling added", () => {
  assert.deepEqual(parseAlternates("/a/objects\n# a comment\n\n../../b/objects\n"), ["/a/objects", "../../b/objects"]);
  assert.deepEqual(parseAlternates("/a/objects"), ["/a/objects"], "no final newline");
  assert.deepEqual(parseAlternates('"/odd\\tdir/\\"q\\"/obj\\303\\251cts"\n'), ['/odd\tdir/"q"/objécts'], "named escapes and octal bytes");
  assert.deepEqual(parseAlternates("/a/objects \r\n"), ["/a/objects \r", "/a/objects"], "git's spelling (untrimmed) and the trimmed one: a superset");
  assert.deepEqual(parseAlternates(" # not a comment\n"), [" # not a comment", "# not a comment"]);
});

test("parseAlternates: what git would not read the same way throws (the caller fails closed)", () => {
  for (const bad of ['"/a/objects\n', '"/a/objects"x\n', '"/a\\q"\n', '"/a\\', "/a\0/objects\n", '"/a\\377"\n']) {
    assert.throws(() => parseAlternates(bad), Error, JSON.stringify(bad));
  }
});

/** An AlternatesIo over a map: objects dir → its alternates file text; the
 *  real directories are the map's keys plus `extra`, `links` maps a
 *  spelling to its real path. */
function fakeIo(files: Record<string, string | Error>, extra: string[] = [], links: Record<string, string> = {}): AlternatesIo {
  const dirs = new Set([...Object.keys(files), ...extra]);
  return {
    read(d) {
      const f = files[d];
      if (f instanceof Error) throw f;
      return f ?? null;
    },
    realDir(p) {
      const parts: string[] = [];
      for (const seg of p.split("/")) {
        if (seg === "" || seg === ".") continue;
        if (seg === "..") parts.pop();
        else parts.push(seg);
      }
      const n = `/${parts.join("/")}`;
      const r = links[n] ?? n;
      return dirs.has(r) ? r : null;
    },
  };
}

test("objectStoreClosure: the own directory first, then every alternate breadth first, an alternate's alternates too, each once by its real path", () => {
  const io = fakeIo({
    "/c/.git/objects": "/b/.git/objects\n../../a-link/.git/objects\n/gone/objects\n",
    "/b/.git/objects": "/a/.git/objects\n",
    "/a/.git/objects": "/base/objects\n/c/.git/objects\n", // a cycle back to C
  }, ["/base/objects"], { "/a-link/.git/objects": "/a/.git/objects" });
  assert.deepEqual(objectStoreClosure("/c/.git/objects", io), ["/c/.git/objects", "/b/.git/objects", "/a/.git/objects", "/base/objects"]);
  assert.deepEqual(objectStoreClosure("/lonely/objects", fakeIo({})), ["/lonely/objects"], "no alternates: the own directory alone");
});

test("objectStoreClosure: fail closed on an alternates file it cannot read or parse, past the depth bound and past the store bound; never a shorter list", () => {
  const unreadable = fakeIo({ "/r/objects": "/a/objects\n", "/a/objects": new Error("EACCES") });
  assert.throws(() => objectStoreClosure("/r/objects", unreadable), (e: Error) => e.name === "GitObjectTwinError" && /alternates of \/a\/objects/.test(e.message));
  assert.throws(() => objectStoreClosure("/r/objects", fakeIo({ "/r/objects": '"/a/objects\n' })), (e: Error) => e.name === "GitObjectTwinError");
  // A chain of n links: the bound is the number of links followed.
  const chain = (n: number): Record<string, string> =>
    Object.fromEntries(Array.from({ length: n + 1 }, (_, i) => [`/s${i}`, i < n ? `/s${i + 1}\n` : ""]));
  assert.equal(objectStoreClosure("/s0", fakeIo(chain(4)), 4).length, 5, "exactly at the bound");
  assert.throws(() => objectStoreClosure("/s0", fakeIo(chain(5)), 4), /nested deeper than 4/);
  assert.equal(objectStoreClosure("/s0", fakeIo(chain(ALTERNATES_MAX_DEPTH))).length, ALTERNATES_MAX_DEPTH + 1, "git's six levels are well inside the default");
  const wide = fakeIo({ "/r": Array.from({ length: 5 }, (_, i) => `/w${i}`).join("\n") }, Array.from({ length: 5 }, (_, i) => `/w${i}`));
  assert.equal(objectStoreClosure("/r", wide, 4, 6).length, 6);
  assert.throws(() => objectStoreClosure("/r", wide, 4, 5), /more than 5 object directories/);
  const odd: AlternatesIo = { read: () => "/x\n", realDir: (p) => { if (p === "/x") throw new Error("ELOOP"); return p; } };
  assert.throws(() => objectStoreClosure("/r", odd), (e: Error) => e.name === "GitObjectTwinError" && /ELOOP/.test(e.message));
});

test("defaultAlternatesIo: absent is none; a directory, a FIFO (never blocking), an oversized or non-UTF-8 file throw; a symlink to a regular file reads", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-alt-io-"));
  try {
    const objs = (name: string): string => { const d = join(tmp, name, "objects"); mkdirSync(join(d, "info"), { recursive: true }); return d; };
    assert.equal(defaultAlternatesIo.read(objs("none")), null);
    const ok = objs("ok");
    writeFileSync(join(ok, "info", "alternates"), "/a/objects\n");
    assert.equal(defaultAlternatesIo.read(ok), "/a/objects\n");
    const linked = objs("linked");
    symlinkSync(join(ok, "info", "alternates"), join(linked, "info", "alternates"));
    assert.equal(defaultAlternatesIo.read(linked), "/a/objects\n");
    const dir = objs("dir");
    mkdirSync(join(dir, "info", "alternates"));
    assert.throws(() => defaultAlternatesIo.read(dir), /not a regular file/);
    const fifo = objs("fifo");
    if (spawnSync("mkfifo", [join(fifo, "info", "alternates")]).status === 0) {
      assert.throws(() => defaultAlternatesIo.read(fifo), /not a regular file/);
    }
    const big = objs("big");
    writeFileSync(join(big, "info", "alternates"), Buffer.alloc(ALTERNATES_MAX_BYTES + 1, 0x41));
    assert.throws(() => defaultAlternatesIo.read(big), /larger than/);
    const latin = objs("latin");
    writeFileSync(join(latin, "info", "alternates"), Buffer.from([0x2f, 0xe9, 0x0a]));
    assert.throws(() => defaultAlternatesIo.read(latin), /not UTF-8/);
    assert.equal(defaultAlternatesIo.realDir(join(tmp, "nothing")), null);
    assert.equal(defaultAlternatesIo.realDir(join(ok, "info", "alternates")), null, "a file is no object directory");
    assert.equal(defaultAlternatesIo.realDir(join(linked, "..", "..", "ok", "objects")), ok);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("clusterObjectStores: a directory two stores read is planned once with the UNION of their names; stores linked through a chain are one cluster, unrelated ones apart", () => {
  const clusters = clusterObjectStores([
    { id: "A", hashLen: 20, dirs: ["/a/objects"], found: [A] },
    { id: "B", hashLen: 20, dirs: ["/b/objects", "/a/objects"], found: [B] }, // clone --shared of A
    { id: "X", hashLen: 20, dirs: ["/x/objects"], found: [C] },
    { id: "C", hashLen: 20, dirs: ["/c/objects", "/b/objects", "/a/objects"], found: [C] }, // clone --shared of B
  ]);
  assert.equal(clusters.length, 2);
  const [abc, x] = clusters;
  assert.deepEqual(abc!.stores, ["A", "B", "C"]);
  assert.deepEqual(abc!.dirs.map((d) => [d.dir, d.names, d.by]), [
    ["/a/objects", [A, B, C], ["A", "B", "C"]],
    ["/b/objects", [B, C], ["B", "C"]],
    ["/c/objects", [C], ["C"]],
  ]);
  assert.deepEqual(abc!.unsupported, []);
  assert.deepEqual(x!.stores, ["X"]);
  assert.deepEqual(x!.dirs.map((d) => [d.dir, d.names]), [["/x/objects", [C]]]);
  // Two stores bridged only by a third that borrows from both.
  const bridged = clusterObjectStores([
    { id: "P", hashLen: 20, dirs: ["/p"], found: [A] },
    { id: "Q", hashLen: 20, dirs: ["/q"], found: [B] },
    { id: "R", hashLen: 20, dirs: ["/r", "/p", "/q"], found: [] },
  ]);
  assert.deepEqual(bridged.map((c) => c.stores), [["P", "Q", "R"]]);
});

test("clusterObjectStores: a directory read by repositories of two object formats is unsupported (fail closed)", () => {
  const [c] = clusterObjectStores([
    { id: "S1", hashLen: 20, dirs: ["/s"], found: [A] },
    { id: "S2", hashLen: 32, dirs: ["/t", "/s"], found: ["d".repeat(64)] },
  ]);
  assert.equal(c!.unsupported.length, 1);
  assert.match(c!.unsupported[0]!, /^\/s /);
});

test("planObjectTwins over a clustered directory: one rebuild per shared pack, excluding every store's names (two per-store plans gave two keys)", () => {
  const shared: ObjectDirInventory = {
    dir: "/a/objects", packs: [{ base: "/a/objects/pack/pack-1", held: [A, B], hasRev: true, hasBitmap: false, hasMtimes: false, size: 1 }],
    looseProtected: [], midx: [], incrementalMidx: false,
  };
  const [c] = clusterObjectStores([
    { id: "A", hashLen: 20, dirs: ["/a/objects"], found: [A] },
    { id: "B", hashLen: 20, dirs: ["/b/objects", "/a/objects"], found: [B] },
  ]);
  const d = c!.dirs.find((x) => x.dir === "/a/objects")!;
  const plan = planObjectTwins([shared], d.names);
  assert.deepEqual(plan.rebuild.map((r) => r.exclude), [[A, B]]);
  const perStore = [planObjectTwins([shared], [A]), planObjectTwins([shared], [B])].map((p) => p.rebuild[0]!.key);
  assert.notEqual(perStore[0], perStore[1], "the bug: one pack, two twins with different exclusions");
});

test("prepareGitObjectTwins: an alternates file that cannot be read refuses the launch (a GitObjectTwinError naming it), and under continueOnFailure names the repository", async () => {
  // A fake git: one SHA-1 repository at /w with nothing in its history.
  const git: GitRunner = async (args) => {
    if (args[0] === "rev-parse") return { code: 0, stdout: "sha1\n.git\n.git/shallow\n.git/info/grafts\n.git/info/attributes\n", stderr: "" };
    if (args[0] === "version") return { code: 0, stdout: "git version 2.43.0\n", stderr: "" };
    if (args[0] === "config") return { code: 1, stdout: "", stderr: "" };
    if (args[0] === "hash-object") return { code: 0, stdout: `${A}\n`, stderr: "" };
    return { code: 0, stdout: "", stderr: "" };
  };
  const alternatesIo = fakeIo({ "/w/.git/objects": new Error("EACCES") });
  const blobLocks = [`sha1:${A}`]; // something to hide, so the store is read
  const exists = (p: string): boolean => p === "/w/.git";
  await assert.rejects(
    prepareGitObjectTwins(["/w/.env"], { cacheDir: "/c", denyFile: "/d", git, exists, alternatesIo, blobLocks }),
    (e: Error) => e.name === "GitObjectTwinError" && /alternates of \/w\/\.git\/objects/.test(e.message),
  );
  const got = await prepareGitObjectTwins(["/w/.env"], { cacheDir: "/c", denyFile: "/d", git, exists, alternatesIo, blobLocks, continueOnFailure: true });
  assert.deepEqual(got.failed?.map((f) => f.root), ["/w"]);
  assert.deepEqual(got.twins, []);
});
