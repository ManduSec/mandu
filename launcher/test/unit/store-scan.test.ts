/**
 * Unit: the object-store scan (src/store-scan.ts; confidentiality.md §7.2a
 * "Every stored object is checked once"): its pure parts (the sorted id
 * sets and records, git's answers, tree entries, loose headers, the token
 * rule, the places a tree nothing names is read at, the kept state's
 * shape) and its decisions over real repositories with a plain git runner:
 *
 *   - incremental: a second scan with nothing new asks git nothing and
 *     reads nothing; a repack costs reading the new `.idx` and asks git
 *     nothing; a commit's loose objects are read here, git asked nothing;
 *   - path attribution: history no ref reaches, a folder renamed (an old
 *     tree at a new place), a tree no commit names (`git write-tree`), a
 *     subtree whose parent is gone (read under every folder a protected
 *     path names);
 *   - the pathless blob rule: a blob no tree names sharing a credential
 *     token with a protected version is hidden as a version of that path,
 *     for good (a tree written later naming it does not bring it back); one
 *     sharing nothing is not; one an index holds is not;
 *   - a new set of protected paths is answered from the records, git asked
 *     nothing; a new seal epoch, a changed data file and a new rule scan
 *     anew; a directory written within the racy window is listed again.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { appendFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateSync } from "node:zlib";
import { SealSession } from "../../src/cache-seals.js";
import type { GitRunner } from "../../src/git-object-twins.js";
import {
  cmpBytes, commitTree, credentialTokens, ENTRY_BLOB, ENTRY_OTHER, ENTRY_TREE, hasId, isRacy, mergeSorted, metasOf, newStoreScanStats,
  parseBatch, parseBatchCheck, parseLooseHeader, parseScanState, readLooseObject, recordWidth, scanStore, sortRecords, sortedIdBuffer,
  storeScanDir, STORE_SCAN_RULE, tagTarget, topPrefixes, topProtected, treeEntries, unseenOfSorted, type ScanPredicate, type StoreScanStats,
} from "../../src/store-scan.js";
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
/** A plain runner (no sandbox) that honours `binary`. */
const runner: GitRunner = (args, opts) => new Promise((res) => {
  const c = execFile("git", args, { cwd: opts.cwd, env: ENV, maxBuffer: 1 << 28, encoding: opts.binary === true ? "latin1" : "utf8" }, (err, stdout, stderr) => {
    res({ code: err === null ? 0 : typeof err.code === "number" ? err.code : 1, stdout: String(stdout), stderr: String(stderr) });
  });
  c.stdin!.end(opts.input ?? "");
});
/** A key-shaped canary assembled at run time (no key literal in the file). */
const key = (v: number): string => ["SCAN", "CANARY", String(v), "Qz".repeat(14)].join("_");
const h = (s: string): Buffer => Buffer.from(s, "hex");

// ── Pure ────────────────────────────────────────────────────────────────────

test("sorted id sets: compare, search, the unseen of a sorted run, merge, sort with duplicates out", () => {
  const ids = ["00".repeat(20), "0a".repeat(20), "ff".repeat(20)];
  const seen = sortedIdBuffer([h(ids[2]!), h(ids[0]!), h(ids[0]!)], 20);
  assert.equal(seen.length, 40, "a duplicate out");
  assert.ok(hasId(seen, 20, h(ids[0]!)) && hasId(seen, 20, h(ids[2]!)) && !hasId(seen, 20, h(ids[1]!)));
  const run = Buffer.concat(ids.map(h));
  assert.deepEqual(unseenOfSorted(run, 0, 3, seen, 20).map((b) => b.toString("hex")), [ids[1]]);
  assert.deepEqual(unseenOfSorted(run, 0, 3, Buffer.alloc(0), 20).length, 3, "against nothing, all are unseen");
  assert.ok(mergeSorted(seen, h(ids[1]!), 20).equals(run));
  assert.ok(mergeSorted(run, run, 20).equals(run), "a union holds each once");
  assert.equal(cmpBytes(h("0001"), 0, h("0002"), 0, 2), -1);
  const w = recordWidth(20);
  const rec = (id: string, meta: number): Buffer => { const b = Buffer.alloc(w); h(id).copy(b); b.writeUInt32BE(meta, 20); return b; };
  const recs = sortRecords(Buffer.concat([rec(ids[2]!, 7), rec(ids[0]!, 3), rec(ids[0]!, 1), rec(ids[0]!, 3)]), w);
  assert.equal(recs.length, 3 * w);
  assert.deepEqual(metasOf(recs, 20, h(ids[0]!)), [1, 3]);
  assert.deepEqual(metasOf(recs, 20, h(ids[1]!)), []);
});

test("git's answers: --batch-check lines, --batch objects, a tree's entries, a commit's tree, a tag's target; a malformed answer throws", () => {
  const a = "a".repeat(40);
  const b = "b".repeat(40);
  assert.deepEqual(parseBatchCheck(`${a} tree 30\n${b} missing\n`, 40), { found: [{ oid: a, type: "tree", size: 30 }], missing: [b] });
  assert.throws(() => parseBatchCheck(`${a} tree\n`, 40));
  const blobId = h("c".repeat(40));
  const tree = Buffer.concat([
    Buffer.from("100644 .env\0"), blobId, Buffer.from("40000 cfg\0"), blobId, Buffer.from("160000 sub\0"), blobId,
    Buffer.from("100755 run.sh\0"), blobId, Buffer.from("120000 link\0"), blobId,
  ]);
  assert.deepEqual(treeEntries(tree, 20).map((e) => [e.kind, e.name]), [
    [ENTRY_BLOB, ".env"], [ENTRY_TREE, "cfg"], [ENTRY_OTHER, "sub"], [ENTRY_BLOB, "run.sh"], [ENTRY_BLOB, "link"],
  ]);
  assert.throws(() => treeEntries(Buffer.concat([Buffer.from("100644 x\0"), blobId.subarray(0, 5)]), 20), /malformed/);
  const out = Buffer.concat([Buffer.from(`${a} tree ${tree.length}\n`), tree, Buffer.from(`\n${b} missing\n`)]);
  const parsed = parseBatch(out, 40);
  assert.equal(parsed.objects.length, 1);
  assert.ok(parsed.objects[0]!.body.equals(tree));
  assert.deepEqual(parsed.missing, [b]);
  assert.throws(() => parseBatch(Buffer.from(`${a} tree 99\nshort\n`), 40), /shorter/);
  assert.equal(commitTree(Buffer.from(`tree ${a}\nparent ${b}\n\nmsg`), 40), a);
  assert.equal(commitTree(Buffer.from("garbage"), 40), null);
  assert.deepEqual(tagTarget(Buffer.from(`object ${a}\ntype tree\ntag t\n`), 40), { object: a, type: "tree" });
});

test("a loose object read here: its header, its body when asked; anything uncertain is left to git", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-scan-loose-"));
  try {
    const put = (hex: string, raw: Buffer): void => { mkdirSync(join(dir, hex.slice(0, 2)), { recursive: true }); writeFileSync(join(dir, hex.slice(0, 2), hex.slice(2)), deflateSync(raw)); };
    put("ab".repeat(20), Buffer.from("tree 3\0xyz"));
    assert.deepEqual(readLooseObject(dir, "ab".repeat(20), () => true), { type: "tree", size: 3, body: Buffer.from("xyz") });
    assert.deepEqual(readLooseObject(dir, "ab".repeat(20), () => false), { type: "tree", size: 3, body: null });
    put("cd".repeat(20), Buffer.from("tree 5\0xyz"));
    assert.equal(readLooseObject(dir, "cd".repeat(20), () => true), null, "a body shorter than declared");
    put("ef".repeat(20), Buffer.from("tree 2\0xyz"));
    assert.equal(readLooseObject(dir, "ef".repeat(20), () => true), null, "a body longer than declared");
    put("12".repeat(20), Buffer.from("bogus 1\0x"));
    assert.equal(readLooseObject(dir, "12".repeat(20), () => true), null, "an unknown type");
    assert.equal(readLooseObject(dir, "34".repeat(20), () => true), null, "absent");
    assert.equal(parseLooseHeader(Buffer.from("blob 007\0")), null, "a size git would not write");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("the token rule: values, keys, digests and KEY=value lines are tokens; a variable's name alone is not", () => {
  const t = credentialTokens(`ANTHROPIC_API_KEY=${key(1)}\nDEBUG=true\nexport DB_URL = postgres://u:pw@db/x\n# a comment\n`);
  assert.ok(t.has(key(1)), "the value");
  assert.ok(t.has(`ANTHROPIC_API_KEY=${key(1)}`), "the line");
  assert.ok(t.has("export DB_URL=postgres://u:pw@db/x"), "a KEY=value line with an 8+ character value, spacing normalized");
  assert.ok(!t.has("ANTHROPIC_API_KEY"), "a name with no digit is not a token");
  assert.ok(![...t].some((x) => x.includes("DEBUG")), "a short value is not a token");
  assert.ok(!credentialTokens("process.env.ANTHROPIC_API_KEY ?? readConfig()").size, "code naming the variable shares nothing");
});

test("a tree nothing names is read as a root and under every folder of a protected path", () => {
  assert.deepEqual(topPrefixes(["config/prod/.env", ".env"], ["deploy/keys"]), ["", "config/", "config/prod/", "deploy/", "deploy/keys/"]);
  const p: ScanPredicate = { key: "k", isProtected: (r) => r === "config/prod/.env", prefixes: topPrefixes(["config/prod/.env"]) };
  assert.ok(topProtected(".env", p), "a `config/prod/` subtree whose parent is gone");
  assert.ok(topProtected("prod/.env", p), "a `config/` subtree");
  assert.ok(topProtected("config/prod/.env", p), "a root");
  assert.ok(!topProtected("other.env", p));
});

test("identities: too recent is racy; the kept state's shape is checked, anything else is scanned anew", () => {
  const now = 1_000_000;
  assert.ok(isRacy([1, 2, 3, now - 100, now - 5000], now));
  assert.ok(!isRacy([1, 2, 3, now - 2500, now - 2500], now));
  const good = {
    v: 1, rule: STORE_SCAN_RULE, commonDir: "/r/.git", hashLen: 20, gen: "0123456789abcdef",
    files: { seen: [1, 2, 3, 4, 5], pairs: [1, 2, 3, 4, 5], paths: [1, 2, 3, 4, 5] },
    dirs: [{ dir: "/r/.git/objects", objects: [1, 2, 3, 4, 5], pack: null, packs: {}, loose: { "0a": null } }],
    answers: [{ key: "k", pairs: [["ab".repeat(20), ".env"]] }],
    candidates: { ["cd".repeat(20)]: { size: 3, s: "m", path: ".env" } },
  };
  assert.notEqual(parseScanState(JSON.stringify(good), "/r/.git"), null);
  assert.equal(parseScanState(JSON.stringify(good), "/other/.git"), null, "another store");
  assert.equal(parseScanState(JSON.stringify({ ...good, rule: "store-scan:v0" }), "/r/.git"), null, "another rule");
  assert.equal(parseScanState(JSON.stringify({ ...good, candidates: { x: { size: 1, s: "m" } } }), "/r/.git"), null, "a bad candidate");
  assert.equal(parseScanState(JSON.stringify({ ...good, candidates: { ["cd".repeat(20)]: { size: 1, s: "m" } } }), "/r/.git"), null, "a hidden candidate with no path");
  assert.equal(parseScanState(JSON.stringify({ ...good, files: { seen: [1] } }), "/r/.git"), null, "a torn identity");
  assert.equal(parseScanState("{garbled", "/r/.git"), null);
});

// ── Real repositories ───────────────────────────────────────────────────────

interface Repo { tmp: string; ws: string; state: string; seals: MemorySeals }

function repo(): Repo {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-scan-"));
  const ws = join(tmp, "ws");
  git(tmp, ["init", "-q", "-b", "main", ws]);
  writeFileSync(join(ws, "README"), "readme\n");
  return { tmp, ws, state: join(tmp, "state"), seals: memorySeals() };
}
const commitEnv = (r: Repo, text: string, msg: string, path = ".env"): void => {
  mkdirSync(join(r.ws, path, ".."), { recursive: true });
  writeFileSync(join(r.ws, path), text);
  git(r.ws, ["add", "-A"]);
  git(r.ws, ["commit", "-qm", msg]);
};
const blobOf = (r: Repo, text: string): string => git(r.ws, ["hash-object", "--stdin"], text).trim();
const protect = (...rels: string[]): ScanPredicate => ({ key: JSON.stringify(rels), isProtected: (x) => rels.includes(x), prefixes: topPrefixes(rels) });

async function scan(r: Repo, pred: ScanPredicate, opts: { known?: Array<[string, string]>; now?: number; working?: Array<[string, string]>; git?: GitRunner } = {}): Promise<{ pairs: Array<[string, string]>; hidden: Array<[string, string]>; stats: StoreScanStats }> {
  const stats = newStoreScanStats();
  const sealing = new SealSession(r.seals, undefined, () => { throw new Error("no file is hashed here"); });
  const commonDir = join(r.ws, ".git");
  const s = await scanStore({
    git: opts.git ?? runner, cwd: r.ws, commonDir, hashLen: 20, dirs: [join(commonDir, "objects")], stateRoot: r.state, sealing, stats,
    ...(opts.now !== undefined ? { now: () => opts.now! } : {}),
  }, pred);
  const hidden = await s.finish([...(opts.known ?? []), ...s.pairs], opts.working ?? []);
  await sealing.flush();
  return { pairs: s.pairs, hidden, stats };
}
/** Well past the racy window of anything written now. */
const later = (): number => Date.now() + 10_000;
const names = (pairs: Array<[string, string]>): string[] => [...new Set(pairs.map(([n]) => n))].sort();

test("history no ref reaches is found at its path; a second scan with nothing new asks git nothing and reads nothing", async () => {
  const r = repo();
  try {
    commitEnv(r, `TOKEN=${key(1)}\n`, "v1");
    commitEnv(r, `TOKEN=${key(2)}\n`, "v2");
    // The history cut: an orphan branch, the old branch and reflogs gone.
    git(r.ws, ["checkout", "-q", "--orphan", "fresh"]);
    commitEnv(r, "TOKEN=$MDU:x\n", "fresh");
    git(r.ws, ["branch", "-D", "main"]);
    git(r.ws, ["reflog", "expire", "--expire=now", "--all"]);
    assert.equal(git(r.ws, ["log", "--all", "--format=%s"]).trim(), "fresh");
    const first = await scan(r, protect(".env"), { now: later() });
    for (const v of [1, 2]) assert.ok(first.pairs.some(([n, p]) => n === blobOf(r, `TOKEN=${key(v)}\n`) && p === ".env"), `version ${v} found at .env`);
    assert.equal(first.stats.first, 1);
    const second = await scan(r, protect(".env"), { now: later() });
    assert.deepEqual(names(second.pairs), names(first.pairs));
    assert.deepEqual([second.stats.unchanged, second.stats.gitCalls, second.stats.asked, second.stats.read, second.stats.listed, second.stats.loose], [1, 0, 0, 0, 0, 0]);
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("a repack costs its .idx and asks git nothing; a new commit's loose objects are read here; a racy directory is listed again", async () => {
  const r = repo();
  try {
    commitEnv(r, `TOKEN=${key(1)}\n`, "v1");
    await scan(r, protect(".env"), { now: later() });
    git(r.ws, ["repack", "-adq"]);
    const repacked = await scan(r, protect(".env"), { now: later() });
    assert.ok(repacked.stats.listed > 0, "the new pack's index is read");
    assert.deepEqual([repacked.stats.asked, repacked.stats.read, repacked.stats.gitCalls], [0, 0, 0], "no id is new: git is asked nothing");
    commitEnv(r, `TOKEN=${key(2)}\n`, "v2");
    const after = await scan(r, protect(".env"), { now: later() });
    assert.equal(after.stats.gitCalls, 0, "the commit's objects are loose: read here");
    assert.equal(after.stats.loose, 3, "a blob, a tree, a commit");
    assert.ok(after.pairs.some(([n]) => n === blobOf(r, `TOKEN=${key(2)}\n`)));
    // Listed within the racy window: not trusted unchanged next time.
    commitEnv(r, `TOKEN=${key(3)}\n`, "v3");
    await scan(r, protect(".env"));
    const again = await scan(r, protect(".env"), { now: later() });
    assert.ok(again.stats.listed > 0 && again.stats.unchanged === 0, "a directory written within two seconds is listed again");
    const steady = await scan(r, protect(".env"), { now: later() });
    assert.equal(steady.stats.unchanged, 1);
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("an old tree met at a new place (a renamed folder) is read there; a tree no commit names and a subtree whose parent is gone are found", async () => {
  const r = repo();
  try {
    commitEnv(r, `TOKEN=${key(1)}\n`, "v1", "cfg/.env");
    await scan(r, protect("config/.env"), { now: later() });
    git(r.ws, ["mv", "cfg", "config"]);
    git(r.ws, ["commit", "-qm", "rename"]);
    const renamed = await scan(r, protect("config/.env"), { now: later() });
    assert.ok(renamed.pairs.some(([n, p]) => n === blobOf(r, `TOKEN=${key(1)}\n`) && p === "config/.env"), "the version first committed under cfg/ is found at config/.env");
    // A tree no commit names: an index written to a tree, nothing more.
    const v2 = git(r.ws, ["hash-object", "-w", "--stdin"], `TOKEN=${key(2)}\n`).trim();
    const idx = join(r.tmp, "scratch-index");
    git(r.ws, ["read-tree", "HEAD"], undefined, { GIT_INDEX_FILE: idx });
    git(r.ws, ["update-index", "--add", "--cacheinfo", `100644,${v2},config/.env`], undefined, { GIT_INDEX_FILE: idx });
    git(r.ws, ["write-tree"], undefined, { GIT_INDEX_FILE: idx });
    // A subtree whose parent is gone: `config/`'s content alone.
    const v3 = git(r.ws, ["hash-object", "-w", "--stdin"], `TOKEN=${key(3)}\n`).trim();
    git(r.ws, ["mktree"], `100644 blob ${v3}\t.env\n`);
    const got = await scan(r, protect("config/.env"), { now: later() });
    assert.ok(got.pairs.some(([n, p]) => n === v2 && p === "config/.env"), "a tree no commit names: read as a root");
    assert.ok(got.pairs.some(([n, p]) => n === v3 && p === "config/.env"), "a parentless subtree: read under config/");
    assert.ok(!got.pairs.some(([, p]) => p !== "config/.env"));
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("a new set of protected paths is answered from the records (git asked nothing); a new epoch, a changed data file, a garbled state scan anew", async () => {
  const r = repo();
  try {
    commitEnv(r, `TOKEN=${key(1)}\n`, "v1", "deploy/id_key");
    commitEnv(r, `TOKEN=${key(2)}\n`, "v2");
    const a = await scan(r, protect(".env"), { now: later() });
    assert.deepEqual(a.pairs.map(([, p]) => p), [".env"]);
    const b = await scan(r, protect(".env", "deploy/id_key"), { now: later() });
    assert.equal(b.stats.reevaluated, 1);
    assert.equal(b.stats.gitCalls, 0, "answered from what was recorded");
    assert.deepEqual([...new Set(b.pairs.map(([, p]) => p))].sort(), [".env", "deploy/id_key"]);
    r.seals.rotate("unprotected-ended");
    assert.equal((await scan(r, protect(".env"), { now: later() })).stats.first, 1, "a new epoch: nothing kept is trusted");
    const dir = storeScanDir(r.state, join(r.ws, ".git"));
    const gen = (JSON.parse(readFileSync(join(dir, "state.json"), "utf8")) as { gen: string }).gen;
    assert.ok(readdirSync(dir).includes(`pairs-${gen}.bin`));
    appendFileSync(join(dir, `pairs-${gen}.bin`), Buffer.alloc(24));
    // Nothing new: the answer kept in the sealed state stands, no data file
    // is read. Something new: the data files are read, found not as kept.
    assert.equal((await scan(r, protect(".env"), { now: later() })).stats.unchanged, 1);
    commitEnv(r, `TOKEN=${key(3)}\n`, "v3");
    assert.equal((await scan(r, protect(".env"), { now: later() })).stats.first, 1, "a data file not as kept: scanned anew");
    writeFileSync(join(dir, "state.json"), "{garbled");
    const c = await scan(r, protect(".env"), { now: later() });
    assert.equal(c.stats.first, 1);
    assert.deepEqual(names(c.pairs), [...names(a.pairs), blobOf(r, `TOKEN=${key(3)}\n`)].sort(), "the same versions, found anew");
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("a blob no tree names: hidden when it shares a credential token with a protected version, for good; not when it shares nothing or an index holds it", async () => {
  const r = repo();
  try {
    commitEnv(r, `TOKEN=${key(1)}\nDB_PASSWORD=${key(9)}\n`, "v1");
    const current: Array<[string, string]> = [[blobOf(r, `TOKEN=${key(1)}\nDB_PASSWORD=${key(9)}\n`), ".env"]];
    // An older .env written by plumbing (the token unchanged, the password
    // older), a blob that shares nothing, and a staged file sharing a token.
    const old = git(r.ws, ["hash-object", "-w", "--stdin"], `TOKEN=${key(1)}\nDB_PASSWORD=${key(8)}\n`).trim();
    const plain = git(r.ws, ["hash-object", "-w", "--stdin"], "nothing secret here\n").trim();
    writeFileSync(join(r.ws, "notes.txt"), `copied ${key(9)}\n`);
    git(r.ws, ["add", "notes.txt"]);
    const staged = blobOf(r, `copied ${key(9)}\n`);
    const working: Array<[string, string]> = [[join(r.ws, ".env"), ".env"]];
    const first = await scan(r, protect(".env"), { known: current, working, now: later() });
    assert.deepEqual(first.hidden, [[old, ".env"]], "the older .env, as a version of .env");
    assert.ok(!first.hidden.some(([n]) => n === plain || n === staged));
    // Unstaged: no index holds it any more; it shares the password.
    git(r.ws, ["rm", "-q", "--cached", "notes.txt"]);
    const second = await scan(r, protect(".env"), { known: current, working, now: later() });
    assert.deepEqual(names(second.hidden), [old, staged].sort());
    // A tree written later naming the hidden blob (the agent can) does not
    // bring it back.
    git(r.ws, ["mktree"], `100644 blob ${old}\tharmless.txt\n`);
    const third = await scan(r, protect(".env"), { known: current, working, now: later() });
    assert.ok(third.hidden.some(([n, p]) => n === old && p === ".env"), "still hidden");
    // Nothing new: the rule reads nothing.
    const fourth = await scan(r, protect(".env"), { known: current, working, now: later() });
    assert.deepEqual([fourth.stats.read, fourth.stats.gitCalls], [0, 0]);
    // The path no longer protected brings it back.
    const off = await scan(r, protect("README"), { known: [], working: [], now: later() });
    assert.ok(!off.hidden.some(([n]) => n === old));
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("an id git could not answer is not taken as seen: its pack is listed again and the id asked again next time", async () => {
  const r = repo();
  try {
    commitEnv(r, `TOKEN=${key(1)}\n`, "v1");
    git(r.ws, ["repack", "-adq"]); // every object packed: asked of git
    const v1 = blobOf(r, `TOKEN=${key(1)}\n`);
    const tree = git(r.ws, ["rev-parse", "HEAD^{tree}"]).trim();
    // A runner that reports the commit's tree missing (as git does for an
    // object it cannot read at that moment).
    const flaky: GitRunner = async (args, opts) => {
      const got = await runner(args, opts);
      return args[1]?.startsWith("--batch-check") === true ? { ...got, stdout: got.stdout.replace(new RegExp(`^${tree} tree \\d+$`, "m"), `${tree} missing`) } : got;
    };
    const first = await scan(r, protect(".env"), { git: flaky, now: later() });
    assert.ok(!first.pairs.some(([n]) => n === v1), "the tree was not answered: its blob is not found yet");
    const second = await scan(r, protect(".env"), { now: later() });
    assert.equal(second.stats.unchanged, 0, "not trusted unchanged");
    assert.equal(second.stats.asked, 1, "the one id asked again");
    assert.ok(second.pairs.some(([n, p]) => n === v1 && p === ".env"), "and its blob found");
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});

test("a store over the cap is not scanned", async () => {
  const r = repo();
  try {
    commitEnv(r, `TOKEN=${key(1)}\n`, "v1");
    const stats = newStoreScanStats();
    const commonDir = join(r.ws, ".git");
    const s = await scanStore({ git: runner, cwd: r.ws, commonDir, hashLen: 20, dirs: [join(commonDir, "objects")], stateRoot: r.state, stats, maxObjects: 2 }, protect(".env"));
    assert.ok(s.overCap !== null && s.overCap > 2);
    assert.deepEqual(s.pairs, []);
    assert.equal(stats.overCap, 1);
  } finally { rmSync(r.tmp, { recursive: true, force: true }); }
});
