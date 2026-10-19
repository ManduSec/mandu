/**
 * secret-history-cache.test — the git-history scan's cache
 * (docs/design/confidentiality/secret-discovery.md §3.2 item 8; confidentiality-plan-14 §3):
 * the pure plan and parser, the file store (owner-only, bounded, pruned),
 * and the scan over REAL temporary repositories with the git runner and the
 * blob reader counted:
 *
 *   - an unchanged repository lists nothing and reads no blob, and answers
 *     the same findings;
 *   - a new commit lists and reads only its new objects;
 *   - a rewritten history (reset + reflog expiry + gc) lists again, reads
 *     nothing it read before, and drops the blob that went away;
 *   - an entry of another detector rescans everything;
 *   - a repository reached through a symlink is one entry, keyed by the
 *     canonical root git answers;
 *   - a capped scan resumes where it stopped;
 *   - coverage, the catalog and the index are recomputed on every call;
 *   - a shallow clone is not cached;
 *   - the cache file carries no value: no key, no 8-character run of one.
 *
 * Fixture keys are assembled at run time, so this file holds no
 * credential-shaped literal.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import {
  defaultBlobReader,
  defaultHistoryGitRunner,
  historyDetectorFingerprint,
  parseRawRecord,
  scanSecretHistory,
  type BlobBatchReader,
  type HistoryGitRunner,
  type HistoryScanOptions,
  type PathClassifier,
  type SecretHistoryScan,
} from "../../policy/secret-history-scan.js";
import {
  defaultHistoryCacheDir,
  fileHistoryScanCache,
  historyCacheBase,
  historyCacheFile,
  parseHistoryCache,
  planHistoryScan,
  type HistoryScanCacheEntry,
} from "../../policy/secret-history-cache.js";
import { reflogNamesOf, reflogRevArgs, type TipsGit } from "../../policy/history-tips.js";
import { stateAxes } from "../axes.js";
import { randomSecretBody } from "../helpers/random-secret.js";

stateAxes("secrets");

// ── fixture values (random, assembled: never a literal) ──────────────────────
// A letter and a digit, no placeholder run: a value the detectors take
// (a plain random draw has no digit 0.19% of the time; random-secret.ts).
const alnum = randomSecretBody;
/** A body with a letter and a digit in every window the detector wants. */
const body = (n: number): string => `${alnum(n - 2)}a7`;
const GH = [body(36), body(36), body(36), body(36)];
const ghToken = (i: number): string => "gh" + "p_" + GH[i]!;
const PEM_BODY = body(96);
const PEM = `-----BEGIN OPENSSH ` + `PRIVATE KEY-----\n${PEM_BODY}\n-----END OPENSSH PRIVATE KEY-----\n`;
const RUNS = [...GH, PEM_BODY].flatMap((b) => Array.from({ length: b.length - 7 }, (_, i) => b.slice(i, i + 8)));

function assertNoValue(text: string, what: string): void {
  for (const b of [...GH, PEM_BODY]) assert.ok(!text.includes(b), `${what} carries a key`);
  const hit = RUNS.find((r) => text.includes(r));
  assert.equal(hit, undefined, `${what} carries an 8-character run of a key's body`);
}

// ── the pure plan and parser ─────────────────────────────────────────────────

const A = "a".repeat(40);
const B = "b".repeat(40);
const C = "c".repeat(40);

function entry(over: Partial<HistoryScanCacheEntry> = {}): HistoryScanCacheEntry {
  return { v: 1, repoRoot: "/r", base: "base", tips: [A, B], blobs: [], scanned: [], binary: [], hits: {}, traces: {}, ...over };
}

test("plan: fresh without a usable entry, hit on the same tips, incremental on new tips, relist when a tip went away", () => {
  assert.deepEqual(planHistoryScan(null, "/r", "base", [A]), { kind: "fresh" });
  assert.deepEqual(planHistoryScan(entry({ base: "other" }), "/r", "base", [A, B]), { kind: "fresh" }, "another detector / format / git");
  assert.deepEqual(planHistoryScan(entry({ repoRoot: "/s" }), "/r", "base", [A, B]), { kind: "fresh" }, "another repository");
  assert.deepEqual(planHistoryScan(entry(), "/r", "base", [A, B]), { kind: "hit" });
  assert.deepEqual(planHistoryScan(entry(), "/r", "base", [A, B, C]), { kind: "incremental", include: [C], exclude: [A, B] });
  assert.deepEqual(planHistoryScan(entry(), "/r", "base", [A, C]), { kind: "relist" }, "B went away (a rewrite)");
  assert.notEqual(historyCacheBase({ detector: "d1", objectFormat: "sha1", gitVersion: "git 2", replaceRefs: "" }),
    historyCacheBase({ detector: "d2", objectFormat: "sha1", gitVersion: "git 2", replaceRefs: "" }), "the detector is in the base");
  assert.notEqual(historyCacheBase({ detector: "d1", objectFormat: "sha1", gitVersion: "git 2", replaceRefs: "" }),
    historyCacheBase({ detector: "d1", objectFormat: "sha256", gitVersion: "git 2", replaceRefs: "" }), "the object format is in the base");
  assert.match(historyDetectorFingerprint(), /^[0-9a-f]{64}$/);
  assert.equal(historyDetectorFingerprint(), historyDetectorFingerprint(), "stable within a build");
});

test("parser: a well-formed entry round-trips; anything else is refused", () => {
  const e = entry({
    blobs: [[C, 12, "a/b.txt"], [A, 0, null]], scanned: [C], binary: [A],
    hits: { [C]: [{ shape: "github-token", line: 1, preview: "ghp_…" }] },
    traces: { [C]: { first: A, last: B, paths: ["a/b.txt"] } },
  });
  assert.deepEqual(parseHistoryCache(JSON.stringify(e)), e);
  const bad: unknown[] = [
    "not json", "null", "[]",
    { ...e, v: 2 },
    { ...e, tips: ["xyz"] },
    { ...e, blobs: [[C, -1, null]] },
    { ...e, blobs: [[C, 1]] },
    { ...e, scanned: [C.slice(1)] },
    { ...e, hits: { [C]: [{ shape: "github-token", line: 1, preview: "x".repeat(301) }] } },
    { ...e, hits: { [C]: [{ shape: "Bad Shape", line: 1, preview: "ghp_…" }] } },
    { ...e, hits: { [C]: [{ shape: "github-token", line: 0, preview: "ghp_…" }] } },
    { ...e, traces: { [C]: { first: "no", last: null, paths: [] } } },
  ];
  for (const b of bad) assert.equal(parseHistoryCache(typeof b === "string" ? b : JSON.stringify(b)), null, JSON.stringify(b).slice(0, 80));
  const rec = parseRawRecord(`:100644 000000 ${A} ${"0".repeat(40)} D\t"a\\tb"`);
  assert.deepEqual(rec, { src: A, dst: "0".repeat(40), path: "a\tb" });
  assert.equal(parseRawRecord("commit " + A), null);
});

test("store: owner-only files, atomic, a foreign or torn file reads as none, too large is not stored, pruned by count and age", () => {
  const base = mkdtempSync(join(tmpdir(), "mdu-hcache-"));
  try {
    const dir = join(base, "object-walks", "history-scan");
    let clock = 1_000_000_000_000;
    const cache = fileHistoryScanCache(dir, { maxEntries: 2, maxAgeMs: 10_000, now: () => clock });
    assert.equal(cache.load("/r"), null);
    assert.equal(cache.save(entry()), true);
    assert.equal(statSync(dir).mode & 0o777, 0o700);
    assert.equal(statSync(historyCacheFile(dir, "/r")).mode & 0o777, 0o600);
    assert.deepEqual(cache.load("/r"), entry());
    assert.equal(cache.load("/s"), null);
    // A file whose name is /s's but whose content names /r is foreign.
    writeFileSync(historyCacheFile(dir, "/s"), JSON.stringify(entry()));
    assert.equal(cache.load("/s"), null);
    writeFileSync(historyCacheFile(dir, "/s"), "{\"v\":1,");
    assert.equal(cache.load("/s"), null, "torn");
    rmSync(historyCacheFile(dir, "/s"));

    const tiny = fileHistoryScanCache(dir, { maxEntryBytes: 64 });
    assert.equal(tiny.save(entry({ repoRoot: "/big" })), false);
    assert.equal(tiny.load("/big"), null);

    // Count: the least recently used goes first.
    const at = (root: string, t: number): void => { const d = new Date(t); utimesSync(historyCacheFile(dir, root), d, d); };
    at("/r", clock - 3000);
    assert.equal(cache.save(entry({ repoRoot: "/s" })), true);
    at("/s", clock - 2000);
    assert.equal(cache.save(entry({ repoRoot: "/t" })), true);
    assert.equal(cache.load("/r"), null, "over the count: the oldest went");
    assert.notEqual(cache.load("/s"), null);
    // Age: unused past maxAge goes on the next save.
    at("/s", clock - 20_000);
    clock += 1;
    assert.equal(cache.save(entry({ repoRoot: "/t" })), true);
    assert.equal(cache.load("/s"), null, "unused too long");
    cache.touch("/t");
    assert.equal(readdirSync(dir).length, 1);
    assert.equal(defaultHistoryCacheDir({ MANDU_HOME: "/m" }, "/home/u"), "/m/state/object-walks/history-scan");
    assert.equal(defaultHistoryCacheDir({}, "/home/u"), "/home/u/.mandu/state/object-walks/history-scan");
  } finally { rmSync(base, { recursive: true, force: true }); }
});

// ── real repositories ────────────────────────────────────────────────────────

const GIT_ENV = { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };

interface Repo { base: string; root: string; cacheDir: string; git: (...a: string[]) => string; put: (rel: string, body: string) => void; done: () => void }

function repo(): Repo {
  // realpath: the cache is keyed by git's canonical root, and macOS /tmp is a link.
  const base = realpathSync(mkdtempSync(join(tmpdir(), "mdu-hcache-repo-")));
  const root = join(base, "repo");
  mkdirSync(root);
  const env = { ...GIT_ENV, HOME: base };
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: root, env, encoding: "utf8" });
  git("init", "-q", "-b", "main");
  const put = (rel: string, b: string): void => {
    mkdirSync(join(root, rel, ".."), { recursive: true });
    writeFileSync(join(root, rel), b);
  };
  return { base, root, cacheDir: join(base, "cache"), git, put, done: () => rmSync(base, { recursive: true, force: true }) };
}

/** A scan with the git runner and the blob reader counted. */
interface Counted { scan: SecretHistoryScan; read: string[]; gitCalls: string[][] }

async function counted(r: Repo, over: Partial<HistoryScanOptions> = {}): Promise<Counted> {
  const read: string[] = [];
  const gitCalls: string[][] = [];
  const git: HistoryGitRunner = (args, o) => { gitCalls.push(args); return defaultHistoryGitRunner(args, o); };
  const readBlobs: BlobBatchReader = (root, oids, o) => { read.push(...oids); return defaultBlobReader(root, oids, o); };
  const scan = await scanSecretHistory([r.root], { git, readBlobs, cache: fileHistoryScanCache(r.cacheDir), classifyPaths: classify, ...over });
  return { scan, read, gitCalls };
}

const classify: PathClassifier = (paths) => paths.map((p) =>
  /\/\.env$/.test(p) ? { level: "no-model", rule: "catalog:dotenv" } : { level: "public", rule: null });

/** What a finding says, without the clock. */
const view = (s: SecretHistoryScan) => s.findings;
const listed = (c: Counted): number => c.gitCalls.filter((a) => a[0] === "rev-list" && a.includes("--objects")).length;
const sized = (c: Counted): number => c.gitCalls.filter((a) => a[0] === "cat-file").length;

test("cache: an unchanged repository reads no blob and lists nothing, and answers the same", async () => {
  const r = repo();
  try {
    r.put("README.md", "hello\n");
    r.put("config.py", `TOKEN = "${ghToken(0)}"\n`);
    r.git("add", "."); r.git("commit", "-qm", "init");
    r.put("deploy/id_ed25519", PEM);
    r.git("add", "."); r.git("commit", "-qm", "add key");
    r.git("rm", "-q", "deploy/id_ed25519"); r.git("commit", "-qm", "remove key");

    const first = await counted(r);
    assert.deepEqual(first.scan.repos[0]!.cache, { plan: "fresh", read: 3, stored: true });
    assert.equal(first.read.length, 3);
    assert.equal(first.scan.findings.length, 2);

    const second = await counted(r);
    assert.deepEqual(second.scan.repos[0]!.cache, { plan: "hit", read: 0, stored: false });
    assert.equal(second.read.length, 0, "no cat-file --batch read");
    assert.equal(sized(second), 0, "no cat-file --batch-check either");
    assert.equal(listed(second), 0, "no rev-list --objects");
    assert.equal(second.gitCalls.filter((a) => a[0] === "log").length, 0, "the traces come from the cache");
    assert.deepEqual(view(second.scan), view(first.scan));
    assert.deepEqual(second.scan.counts, first.scan.counts);
    assert.deepEqual(second.scan.capped, first.scan.capped);
    const key = second.scan.findings.find((f) => f.paths.includes("deploy/id_ed25519"))!;
    assert.ok(key.firstCommit !== null && key.lastCommit !== null, "traced, from the cache");

    const files = readdirSync(r.cacheDir);
    assert.equal(files.length, 1);
    assertNoValue(readFileSync(join(r.cacheDir, files[0]!), "utf8"), "the cache file");
    assertNoValue(JSON.stringify(second.scan), "the scan");
  } finally { r.done(); }
});

test("cache: a new commit lists and reads only its new blobs; a commit that deletes a key re-traces it", async () => {
  const r = repo();
  try {
    r.put("a.txt", "one\n");
    r.put("k.txt", `k ${ghToken(0)}\n`);
    r.git("add", "."); r.git("commit", "-qm", "init");
    const init = r.git("rev-parse", "HEAD").trim();
    const first = await counted(r);
    assert.equal(first.read.length, 2);

    r.put("b.txt", `b ${ghToken(1)}\n`);
    r.put("c.txt", "three\n");
    r.git("add", "."); r.git("commit", "-qm", "two more");
    const newBlobs = [r.git("rev-parse", "HEAD:b.txt").trim(), r.git("rev-parse", "HEAD:c.txt").trim()].sort();
    const second = await counted(r);
    assert.equal(second.scan.repos[0]!.cache!.plan, "incremental");
    assert.deepEqual([...second.read].sort(), newBlobs, "only the new commit's blobs");
    assert.equal(second.gitCalls.filter((a) => a[0] === "rev-list" && a.includes("--all") && a.includes("--objects")).length, 0, "not the whole history");
    assert.equal(second.scan.findings.length, 2);

    // Deleting k.txt touches its blob: the trace moves to the deletion.
    r.git("rm", "-q", "k.txt"); r.git("commit", "-qm", "drop k");
    const dropped = r.git("rev-parse", "HEAD").trim();
    const third = await counted(r);
    assert.equal(third.scan.repos[0]!.cache!.plan, "incremental");
    assert.equal(third.read.length, 0, "a deletion adds no blob");
    const k = third.scan.findings.find((f) => f.paths.includes("k.txt"))!;
    assert.equal(k.firstCommit, init);
    assert.equal(k.lastCommit, dropped);
    assert.equal(k.stillPresent, false);
    // And what a fresh scan says, the cache says.
    const fresh = await scanSecretHistory([r.root], { classifyPaths: classify });
    assert.deepEqual(third.scan.findings, fresh.findings);
  } finally { r.done(); }
});

test("cache: a rewritten history (reset, reflog expired, gc) lists again, reads nothing twice, drops what went away", async () => {
  const r = repo();
  try {
    r.put("a.txt", `a ${ghToken(0)}\n`);
    r.git("add", "."); r.git("commit", "-qm", "init");
    r.put("b.txt", `b ${ghToken(1)}\n`);
    r.git("add", "."); r.git("commit", "-qm", "oops");
    const first = await counted(r);
    assert.equal(first.scan.findings.length, 2);

    r.git("reset", "-q", "--hard", "HEAD~1");
    r.git("reflog", "expire", "--expire=now", "--all");
    r.git("gc", "-q", "--prune=now");
    const second = await counted(r);
    assert.equal(second.scan.repos[0]!.cache!.plan, "relist");
    assert.equal(second.read.length, 0, "a.txt's blob was read before");
    assert.deepEqual(second.scan.findings.map((f) => f.paths), [["a.txt"]], "b.txt's blob is gone from the history");
    const fresh = await scanSecretHistory([r.root], { classifyPaths: classify });
    assert.deepEqual(second.scan.findings, fresh.findings);
    const stored = parseHistoryCache(readFileSync(historyCacheFile(r.cacheDir, r.root), "utf8"))!;
    const gone = first.scan.findings.find((f) => f.paths.includes("b.txt"))!.blob;
    assert.equal(stored.blobs.some(([o]) => o === gone) || stored.scanned.includes(gone) || gone in stored.hits, false, "pruned from the cache");

    // A force-push that replaces the tip with a new commit: the new one's blobs only.
    r.put("c.txt", `c ${ghToken(2)}\n`);
    r.git("add", "."); r.git("commit", "-qm", "again");
    const third = await counted(r);
    assert.equal(third.read.length, 1);
    assert.equal(third.scan.findings.length, 2);
  } finally { r.done(); }
});

test("cache: an entry of another detector (or git, or object format) rescans every blob", async () => {
  const r = repo();
  try {
    r.put("a.txt", `a ${ghToken(0)}\n`);
    r.put("b.txt", "b\n");
    r.git("add", "."); r.git("commit", "-qm", "init");
    await counted(r);
    const file = historyCacheFile(r.cacheDir, r.root);
    const e = parseHistoryCache(readFileSync(file, "utf8"))!;
    const old = historyCacheBase({ detector: "an older detector", objectFormat: "sha1", gitVersion: "git", replaceRefs: "" });
    writeFileSync(file, JSON.stringify({ ...e, base: old, hits: {} }));
    const again = await counted(r);
    assert.equal(again.scan.repos[0]!.cache!.plan, "fresh");
    assert.equal(again.read.length, 2, "every blob read again");
    assert.equal(again.scan.findings.length, 1, "the stale entry's (emptied) hits are not trusted");
    assert.equal(parseHistoryCache(readFileSync(file, "utf8"))!.base, e.base, "rewritten with the current base");
  } finally { r.done(); }
});

test("cache: a repository reached through a symlink is one entry, keyed by git's canonical root", async () => {
  const r = repo();
  try {
    r.put("a.txt", `a ${ghToken(0)}\n`);
    r.git("add", "."); r.git("commit", "-qm", "init");
    const link = join(r.base, "link");
    symlinkSync(r.root, link);
    const viaLink = await counted({ ...r, root: link });
    assert.equal(viaLink.scan.repos[0]!.repoRoot, r.root, "the canonical root, not the spelling");
    assert.deepEqual(viaLink.scan.repos[0]!.cache, { plan: "fresh", read: 1, stored: true });
    const direct = await counted(r);
    assert.deepEqual(direct.scan.repos[0]!.cache, { plan: "hit", read: 0, stored: false }, "the other spelling hits the same entry");
    const again = await counted({ ...r, root: link });
    assert.equal(again.scan.repos[0]!.cache!.plan, "hit", "and back: no thrash");
    assert.deepEqual(readdirSync(r.cacheDir), [basename(historyCacheFile(r.cacheDir, r.root))], "one file, named by the canonical root");
  } finally { r.done(); }
});

test("cache: a capped scan is not complete: the next call reads what the cap left, then nothing", async () => {
  const r = repo();
  try {
    for (let i = 0; i < 4; i++) r.put(`f${i}.txt`, `v ${ghToken(i)}\n` + "x".repeat(200));
    r.git("add", "."); r.git("commit", "-qm", "init");
    const limits = { totalMaxBytes: 600 };
    const first = await counted(r, { limits });
    assert.equal(first.read.length, 2);
    assert.equal(first.scan.capped.overTotal, 2);
    assert.equal(first.scan.findings.length, 2);
    const second = await counted(r, { limits });
    assert.equal(second.scan.repos[0]!.cache!.plan, "hit");
    assert.equal(second.read.length, 2);
    assert.equal(new Set([...first.read, ...second.read]).size, 4, "the other two, not the same two");
    assert.equal(second.scan.capped.overTotal, 0);
    assert.equal(second.scan.findings.length, 4);
    const third = await counted(r, { limits });
    assert.equal(third.read.length, 0);
    assert.equal(third.scan.findings.length, 4);
    assert.equal(third.scan.capped.lines.length, 0, third.scan.capped.lines.join("; "));
  } finally { r.done(); }
});

test("cache: coverage, the catalog and the index are the law's and the work tree's now, not the cache's", async () => {
  const r = repo();
  try {
    r.put(".env", "MODE=dev\n");
    r.put("gone.txt", `g ${ghToken(0)}\n`);
    r.git("add", "."); r.git("commit", "-qm", "init");
    r.git("rm", "-q", "gone.txt", ".env"); r.git("commit", "-qm", "rm");
    const first = await counted(r, { classifyPaths: (ps) => ps.map(() => ({ level: "public", rule: null })) });
    assert.deepEqual(first.scan.findings.map((f) => f.paths), [["gone.txt"]], "the catalog calls nothing a secret yet");
    assert.equal(first.scan.findings[0]!.pathStillSecretByCatalog, false);

    // The law moves: a label on the gone path, and a catalog rule for .env.
    const second = await counted(r, { labelledAbovePublic: (ps) => ps.map((p) => p.endsWith("/gone.txt")) });
    assert.equal(second.read.length, 0);
    const gone = second.scan.findings.find((f) => f.paths.includes("gone.txt"))!;
    assert.equal(gone.pathStillSecretByCatalog, true, "covered now, from a cached verdict");
    const env = second.scan.findings.find((f) => f.paths.includes(".env"))!;
    assert.equal(env.detector.kind, "catalog-path");

    // The index moves: a staged key is read (one blob) and reported staged.
    r.put("staged.txt", `s ${ghToken(1)}\n`);
    r.git("add", "staged.txt");
    const third = await counted(r);
    assert.equal(third.scan.repos[0]!.cache!.plan, "hit", "the tips did not move");
    assert.equal(third.read.length, 1);
    const staged = third.scan.findings.find((f) => f.paths.includes("staged.txt"))!;
    assert.equal(staged.inIndex, true);
    assert.equal(staged.firstCommit, null);
  } finally { r.done(); }
});

test("cache: a shallow clone is not cached (its boundary moves what is reachable without moving a tip)", async () => {
  const r = repo();
  try {
    r.put("a.txt", `a ${ghToken(0)}\n`);
    r.git("add", "."); r.git("commit", "-qm", "one");
    r.put("b.txt", "b\n");
    r.git("add", "."); r.git("commit", "-qm", "two");
    const clone = join(r.base, "clone");
    execFileSync("git", ["clone", "-q", "--depth", "1", `file://${r.root}`, clone], { env: { ...GIT_ENV, HOME: r.base } });
    const cache = fileHistoryScanCache(r.cacheDir);
    const s = await scanSecretHistory([clone], { cache });
    assert.deepEqual(s.repos[0]!.cache, { plan: "off", read: 2, stored: false });
    assert.equal(s.findings.length, 1);
    assert.equal(cache.load(clone), null);
  } finally { r.done(); }
});

test("traces: one pass over the history traces many findings as each one's own --find-object walk would", async () => {
  const r = repo();
  try {
    r.put("a.txt", `a ${ghToken(0)}\n`);
    r.put("b.txt", `b ${ghToken(1)}\n`);
    r.git("add", "."); r.git("commit", "-qm", "one");
    r.git("mv", "a.txt", "moved.txt"); r.git("commit", "-qm", "rename");
    r.git("checkout", "-q", "-b", "side");
    r.put("c.txt", `c ${ghToken(2)}\n`);
    r.git("add", "."); r.git("commit", "-qm", "side");
    r.git("checkout", "-q", "main");
    r.git("rm", "-q", "b.txt"); r.git("commit", "-qm", "rm b");
    r.git("merge", "-q", "--no-ff", "-m", "merge", "side");
    const logs: string[][] = [];
    const s = await scanSecretHistory([r.root], {
      classifyPaths: classify,
      git: (args, o) => { logs.push(args); return defaultHistoryGitRunner(args, o); },
    });
    assert.equal(s.findings.length, 3);
    assert.equal(logs.filter((a) => a.some((x) => x.startsWith("--find-object="))).length, 0, "no per-finding walk");
    // Each finding's own walk from the same start the scan uses (every ref
    // and the reflogs' names on stdin, history-tips.ts): commits of one
    // second tie in git's date order, and a tie goes by where a start was
    // given, so the oracle starts where the scan does.
    const tg: TipsGit = (args, input) => defaultHistoryGitRunner(args, { cwd: r.root, timeoutMs: 30_000, ...(input !== undefined ? { input } : {}) });
    const start = reflogRevArgs(await reflogNamesOf(tg, r.root));
    assert.deepEqual(start.args, ["--all", "--ignore-missing", "--stdin"], "the reflogs were read from their files");
    for (const f of s.findings) {
      const run = await tg(["log", ...start.args, "-m", "--root", "--no-renames", "--raw", "--no-abbrev", "--format=commit %H", `--find-object=${f.blob}`], start.input);
      assert.equal(run.code, 0, run.stderr);
      const own = run.stdout;
      const commits = [...new Set([...own.matchAll(/^commit ([0-9a-f]{40})/gm)].map((m) => m[1]!))];
      assert.equal(f.lastCommit, commits[0], `last commit of ${f.paths.join(",")}`);
      assert.equal(f.firstCommit, commits.at(-1), `first commit of ${f.paths.join(",")}`);
    }
    assert.deepEqual(s.findings.find((f) => f.paths.includes("moved.txt"))!.paths, ["a.txt", "moved.txt"], "every path the trace saw");
  } finally { r.done(); }
});
