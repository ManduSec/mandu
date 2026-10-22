/**
 * twin-prefetch — the git-object twins' reads started at launch start
 * (twin-prefetch.ts, launch-hint.ts; confidentiality.md §7.2a "The
 * prefetch"), with REAL repositories:
 *
 *   - the hint: its exact shape and bounds, one file per workspace, written
 *     by prepareGitObjectTwins (the stores it read, the packs it served);
 *   - a prefetched state is used only for exactly the same work trees and
 *     unchanged inputs, and the twins are then what a launch without the
 *     prefetch computes;
 *   - THE INVARIANT: a secret committed between the prefetch and the use
 *     is hidden all the same (the state is discarded, the version found);
 *     so are a new loose object, a work tree added to the store, a config
 *     change, a racily fresh fingerprint;
 *   - the fingerprint: what changes it and what it refuses (a symlink);
 *   - a failing prefetch never fails or weakens the launch; close kills
 *     every git call still running and leaves nothing behind.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { appendFileSync, chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { defaultGitRunner, idxObjectNames, prepareGitObjectTwins, RepoReads, type GitObjectTwinResult, type GitRunner } from "../../src/git-object-twins.js";
import { GIT_SESSION_RUNNER_SOURCE, openGitSession, perCallGitRunner } from "../../src/git-session.js";
import { HINT_MAX_BYTES, launchHintFile, parseLaunchHint, readLaunchHint, writeLaunchHint } from "../../src/launch-hint.js";
import { fingerprintEntries, RACY_WINDOW_NS, stateFingerprint, TwinPrefetch } from "../../src/twin-prefetch.js";
import { Pacer } from "../../src/reflog-tips.js";
import { stateAxes } from "../axes.js";
import { memorySeals } from "../lib/memory-seals.js";

stateAxes("secrets"); // the confidentiality axis is what the object twins serve

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...args: string[]): string => execFileSync("git", args, { cwd, encoding: "utf8", env: ENV });
/** A key-shaped canary assembled at run time (no key literal in the file). */
const key = (v: number): string => ["PREFETCH", "CANARY", String(v), "Qz".repeat(14)].join("_");
const blobOf = (cwd: string, text: string): string =>
  execFileSync("git", ["hash-object", "--stdin"], { cwd, input: text, encoding: "utf8", env: ENV }).trim();
/** Ten seconds from now: past the racy window for files written just now
 *  (the racy rule has its own test). */
const later = (): bigint => BigInt(Date.now()) * 1_000_000n + 10n * RACY_WINDOW_NS;

interface Fx { tmp: string; ws: string; secret: string; seals: ReturnType<typeof memorySeals>; opts: { cacheDir: string; denyFile: string; walkCacheDir: string; hintFile: string }; done: () => void }

function fixture(): Fx {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-prefetch-"));
  const ws = join(tmp, "ws");
  git(tmp, "init", "-q", "-b", "main", ws);
  writeFileSync(join(ws, "README"), "readme\n");
  const secret = join(ws, ".env");
  writeFileSync(secret, `TOKEN=${key(1)}\n`);
  git(ws, "add", ".");
  git(ws, "commit", "-qm", "one");
  writeFileSync(secret, `TOKEN=${key(2)}\n`);
  git(ws, "commit", "-qam", "two");
  git(ws, "repack", "-adq");
  const denyFile = join(tmp, "denied");
  writeFileSync(denyFile, "");
  chmodSync(denyFile, 0o000);
  const walkCacheDir = join(tmp, "walks");
  return {
    tmp, ws, secret, seals: memorySeals(),
    opts: { cacheDir: join(tmp, "cache"), denyFile, walkCacheDir, hintFile: launchHintFile(walkCacheDir, [ws]) },
    done: () => rmSync(tmp, { recursive: true, force: true }),
  };
}

/** A launch's twins: the twin list and the ids it locks. */
const shape = (g: GitObjectTwinResult): string => JSON.stringify({
  twins: g.twins.map((x) => [x.kind, x.targetPath, x.twinPath]).sort(), lockedIds: g.lockedIds, repos: g.repos, blobs: g.blobs,
});
const servedIdxNames = (g: GitObjectTwinResult): string[] =>
  idxObjectNames(readFileSync(g.twins.find((x) => x.kind === "object" && x.targetPath.endsWith(".idx"))!.twinPath));

function start(f: Fx, extra: { now?: () => bigint; git?: GitRunner } = {}): TwinPrefetch {
  const p = TwinPrefetch.start({ hintFile: f.opts.hintFile, cacheDir: f.opts.cacheDir, now: extra.now ?? later, ...(extra.git ? { git: extra.git } : {}) });
  assert.ok(p !== null, "a hint was left by the launch before");
  return p;
}

test("the launch hint: one file per workspace, an exact bounded shape (anything else is no hint), written atomically", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-hint-"));
  try {
    assert.notEqual(launchHintFile(tmp, ["/a"]), launchHintFile(tmp, ["/b"]));
    assert.match(launchHintFile(tmp, ["/a"]), /\/launch-hints\/[0-9a-f]{32}\.json$/);
    const good = { v: 1, stores: [["/r/a", "/r/b"]], packs: ["0".repeat(32)] };
    assert.deepEqual(parseLaunchHint(JSON.stringify(good)), { stores: good.stores, packs: good.packs });
    for (const bad of [
      { ...good, v: 2 },
      { ...good, stores: [["relative/root"]] },
      { ...good, stores: [["/r/b", "/r/a"]] }, // unsorted
      { ...good, stores: [["/r/a", "/r/a"]] }, // a duplicate
      { ...good, stores: [[]] },
      { ...good, packs: ["../escape"] },
      { ...good, stores: Array.from({ length: 17 }, (_, i) => [`/r/${i}`]) },
    ]) assert.equal(parseLaunchHint(JSON.stringify(bad)), null, JSON.stringify(bad));
    assert.equal(parseLaunchHint("{torn"), null);
    assert.equal(parseLaunchHint(" ".repeat(HINT_MAX_BYTES + 1)), null);

    const file = launchHintFile(tmp, ["/ws"]);
    writeLaunchHint(file, { stores: [["/r/b", "/r/a"]], packs: ["f".repeat(32), "not-a-key"] });
    assert.deepEqual(readLaunchHint(file), { stores: [["/r/a", "/r/b"]], packs: ["f".repeat(32)] });
    assert.deepEqual(readdirSync(join(tmp, "launch-hints")), [file.split("/").at(-1)], "no temp file left");
    const link = launchHintFile(tmp, ["/link"]);
    symlinkSync(file, link);
    assert.equal(readLaunchHint(link), null, "a symlink is not followed");
    assert.equal(readLaunchHint(join(tmp, "absent.json")), null);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("prepareGitObjectTwins leaves the hint (the stores whose state it read, the packs it served); the prefetch then hashes those packs and computes that state, and the twins are what a launch without it computes", async () => {
  const f = fixture();
  try {
    const first = await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals });
    const hint = readLaunchHint(f.opts.hintFile)!;
    assert.deepEqual(hint.stores, [[f.ws]]);
    assert.deepEqual(hint.packs, readdirSync(f.opts.cacheDir).filter((n) => /^[0-9a-f]{32}$/.test(n)));
    const plain = await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals });
    assert.equal(shape(plain), shape(first));

    // Counting the launch's own git calls: with the prefetch its tips are
    // not read again.
    const calls: string[] = [];
    const counting: GitRunner = (args, o) => { calls.push(args.join(" ")); return defaultGitRunner(args, o); };
    const pre = start(f);
    await pre.ready();
    assert.equal(pre.stats.hashedFiles, 3, "the served pack's .pack, .idx and .rev");
    const withPre = await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals, git: counting, statePrefetch: pre, hashes: pre.hashes });
    pre.close();
    assert.equal(pre.stats.used, 1, JSON.stringify(pre.stats));
    assert.equal(shape(withPre), shape(plain), "the same twins, the same ids");
    assert.ok(!calls.some((c) => c.startsWith("rev-list --all")), `the tips came from the prefetch: ${calls.join(" | ")}`);
  } finally { f.done(); }
});

test("THE INVARIANT: a secret committed between the prefetch and the use is hidden (the prefetched state is discarded and the new version found)", async () => {
  const f = fixture();
  try {
    await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals });
    const pre = start(f);
    await pre.ready(); // the prefetch has read the tips...
    writeFileSync(f.secret, `TOKEN=${key(3)}\n`);
    git(f.ws, "commit", "-qam", "three"); // ...and then the human commits a new secret,
    writeFileSync(f.secret, `TOKEN=${key(4)}\n`);
    git(f.ws, "commit", "-qam", "four"); // and another: version 3 is now only in the history
    git(f.ws, "repack", "-adq"); // packed, so the twin's index says what it excludes
    const v3 = blobOf(f.ws, `TOKEN=${key(3)}\n`);
    const got = await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals, statePrefetch: pre, hashes: pre.hashes });
    pre.close();
    assert.equal(pre.stats.used, 0);
    assert.match(pre.stats.discarded.join("\n"), /refs, reflogs or objects changed/);
    assert.ok(got.lockedIds!.includes(`sha1:${v3}`), "the new version is protected");
    assert.ok(!servedIdxNames(got).includes(v3), "and absent from the pack served");
    const plain = await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals });
    assert.equal(shape(got), shape(plain), "exactly what a launch without the prefetch hides");
  } finally { f.done(); }
});

test("a prefetched state is discarded when its inputs changed: a new loose object, a config change; and never offered for another set of work trees (a worktree added)", async () => {
  const f = fixture();
  try {
    await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals });

    let pre = start(f);
    await pre.ready();
    execFileSync("git", ["hash-object", "-w", "--stdin"], { cwd: f.ws, input: "a new loose object\n", env: ENV });
    await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals, statePrefetch: pre, hashes: pre.hashes });
    pre.close();
    assert.equal(pre.stats.used, 0, "a loose object written (its fan-out directory changed)");

    pre = start(f);
    await pre.ready();
    git(f.ws, "config", "core.autocrlf", "input");
    await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals, statePrefetch: pre, hashes: pre.hashes });
    pre.close();
    assert.equal(pre.stats.used, 0, "the config changed");
    assert.equal(pre.stats.discarded.length, 1);

    // A worktree added between: its HEAD is a tip of the store's state, so
    // a state of the main work tree alone is never offered for both.
    pre = start(f);
    await pre.ready();
    const wt = join(f.tmp, "wt");
    git(f.ws, "worktree", "add", "-q", "-b", "side", wt);
    const wtSecret = join(wt, ".env");
    writeFileSync(wtSecret, `TOKEN=${key(4)}\n`);
    git(wt, "commit", "-qam", "side secret");
    writeFileSync(wtSecret, `TOKEN=${key(5)}\n`);
    git(wt, "commit", "-qam", "side secret again"); // version 4 only in the side branch's history
    const v4 = blobOf(f.ws, `TOKEN=${key(4)}\n`);
    const both = await prepareGitObjectTwins([f.secret, wtSecret], { ...f.opts, seals: f.seals, statePrefetch: pre, hashes: pre.hashes });
    pre.close();
    assert.equal(pre.stats.used, 0);
    assert.ok(both.lockedIds!.includes(`sha1:${v4}`), "the worktree's version is protected");
  } finally { f.done(); }
});

test("a fingerprint taken while an entry is racily fresh (younger than the racy window) is never used", async () => {
  const f = fixture();
  try {
    await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals });
    git(f.ws, "commit", "-q", "--allow-empty", "-m", "just now");
    const pre = start(f, { now: () => BigInt(Date.now()) * 1_000_000n });
    await pre.ready();
    await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals, statePrefetch: pre, hashes: pre.hashes });
    pre.close();
    assert.equal(pre.stats.used, 0);
    assert.match(pre.stats.discarded.join("\n"), /no prefetched state/);
  } finally { f.done(); }
});

test("stateFingerprint: unchanged when nothing changes; changed by a commit, a reflog entry, a packed-refs rewrite, a new pack, a new worktree; null for a symlink in refs/", async () => {
  const f = fixture();
  try {
    const facts = await new RepoReads(defaultGitRunner).factsOf(f.ws);
    const fp = async (): Promise<string> => (await stateFingerprint([f.ws], facts))!.digest;
    const a = await fp();
    assert.equal(await fp(), a, "stable");
    const steps: Array<[string, () => void]> = [
      ["a commit", () => git(f.ws, "commit", "-q", "--allow-empty", "-m", "x")],
      ["a reflog entry (reset to the same commit)", () => git(f.ws, "reset", "-q", "HEAD")],
      ["a packed-refs rewrite", () => git(f.ws, "pack-refs", "--all")],
      ["a new pack", () => git(f.ws, "repack", "-dq")],
      ["a new worktree", () => git(f.ws, "worktree", "add", "-q", "--detach", join(f.tmp, "wt2"))],
    ];
    let last = a;
    for (const [what, step] of steps) {
      step();
      const now = await fp();
      assert.notEqual(now, last, what);
      last = now;
    }
    mkdirSync(join(f.ws, ".git", "refs", "linked"), { recursive: true });
    symlinkSync("/tmp", join(f.ws, ".git", "refs", "linked", "away"));
    assert.equal(await stateFingerprint([f.ws], facts), null, "a symlink in refs/ is a doubt");
  } finally { f.done(); }
});

test("fingerprintEntries covers EXACTLY the listed inputs (confidentiality.md §7.2a \"The prefetch\"): every one present, nothing else", async () => {
  const f = fixture();
  try {
    // Every kind of input present: a linked worktree (its .git a file) with
    // its own config.worktree, refs, logs and reftable; the common dir's
    // config.worktree, shallow and reftable/; an alternate object directory.
    const wt = join(f.tmp, "wt");
    git(f.ws, "worktree", "add", "-q", "-b", "side", wt);
    git(wt, "commit", "-q", "--allow-empty", "-m", "side");
    git(f.ws, "tag", "-a", "-m", "t", "v1");
    const c = join(f.ws, ".git");
    const id = readdirSync(join(c, "worktrees"))[0]!;
    const wd = join(c, "worktrees", id);
    writeFileSync(join(c, "config.worktree"), "");
    writeFileSync(join(wd, "config.worktree"), "");
    writeFileSync(join(c, "shallow"), "");
    for (const d of [c, wd]) { mkdirSync(join(d, "reftable"), { recursive: true }); writeFileSync(join(d, "reftable", "tables.list"), ""); }
    mkdirSync(join(wd, "refs", "bisect"), { recursive: true });
    writeFileSync(join(wd, "refs", "bisect", "good"), `${git(f.ws, "rev-parse", "HEAD").trim()}\n`);
    const alt = join(f.tmp, "alt-objects");
    mkdirSync(join(alt, "pack"), { recursive: true });
    mkdirSync(join(alt, "ab"), { recursive: true });
    writeFileSync(join(c, "objects", "info", "alternates"), `${alt}\n`);
    git(f.ws, "commit", "-q", "--allow-empty", "-m", "loose");

    const facts = await new RepoReads(defaultGitRunner).factsOf(f.ws);
    const got = await fingerprintEntries([f.ws, wt], facts);
    assert.ok(got !== null);
    const paths = got.lines.map((l) => l.split("\0")[0]!);
    assert.equal(new Set(paths).size, paths.length, "each entry once");

    // The listed inputs, enumerated here independently of the walk: a new
    // input is added in both places, and one dropped from the walk fails.
    const want = new Set<string>();
    const walk = (p: string): void => {
      want.add(p);
      let st;
      try { st = lstatSync(p); } catch { return; }
      if (st.isDirectory()) for (const n of readdirSync(p)) walk(join(p, n));
    };
    want.add(join(f.ws, ".git"));
    want.add(join(wt, ".git"));
    for (const n of ["HEAD", "packed-refs", "config", "config.worktree", "shallow", "worktrees"]) want.add(join(c, n));
    for (const t of ["refs", "logs", "reftable"]) walk(join(c, t));
    want.add(wd);
    for (const n of ["HEAD", "commondir", "gitdir", "config.worktree"]) want.add(join(wd, n));
    for (const t of ["refs", "logs", "reftable"]) walk(join(wd, t));
    for (const d of [join(c, "objects"), alt]) {
      for (const n of ["", "pack", "info", join("info", "alternates")]) want.add(join(d, n));
      for (const n of readdirSync(d)) if (/^[0-9a-f]{2}$/.test(n)) want.add(join(d, n));
    }
    assert.deepEqual([...new Set(paths)].sort(), [...want].sort());
    // The fixture holds each kind for real (the set above is not vacuous).
    for (const p of [
      join(c, "refs", "tags", "v1"), join(c, "logs", "refs", "heads", "side"), join(wd, "logs", "HEAD"), join(wd, "refs", "bisect", "good"),
      join(wd, "reftable", "tables.list"), join(c, "reftable", "tables.list"), join(alt, "ab"), join(c, "objects", "info", "alternates"),
      join(c, "config.worktree"), join(wd, "config.worktree"), join(c, "shallow"),
    ]) {
      assert.ok(existsSync(p) && paths.includes(p), `${p} is there and fingerprinted`);
    }
    assert.ok(paths.some((p) => /\/objects\/[0-9a-f]{2}$/.test(p) && existsSync(p)), "a loose fan-out directory is fingerprinted");
  } finally { f.done(); }
});

test("paced (2026-10-21): in a store with many worktrees the fingerprint hands the event loop back and answers the same; a change in the last worktree still shows", async () => {
  const f = fixture();
  try {
    const c = join(f.ws, ".git");
    // Many linked worktrees' admin folders (what the fingerprint stats).
    for (let i = 0; i < 120; i++) {
      const d = join(c, "worktrees", `w${String(i).padStart(3, "0")}`);
      mkdirSync(join(d, "logs"), { recursive: true });
      for (const n of ["HEAD", "commondir", "gitdir"]) writeFileSync(join(d, n), `${n}\n`);
      writeFileSync(join(d, "logs", "HEAD"), "x\n");
    }
    const facts = await new RepoReads(defaultGitRunner).factsOf(f.ws);
    const whole = await stateFingerprint([f.ws], facts, undefined, new Pacer(Infinity));
    let ran = 0;
    const tick = setInterval(() => { ran++; }, 0);
    const pace = new Pacer(0);
    let paced;
    try {
      paced = await stateFingerprint([f.ws], facts, undefined, pace);
    } finally { clearInterval(tick); }
    assert.ok(whole !== null && paced !== null);
    assert.equal(paced.digest, whole.digest, "the same fingerprint, paced or in one go");
    assert.ok(pace.yields > 0 && ran > 0, `the event loop ran during it (${pace.yields} yields, ${ran} timer turns)`);
    appendFileSync(join(c, "worktrees", "w119", "logs", "HEAD"), "y\n");
    assert.notEqual((await stateFingerprint([f.ws], facts, undefined, new Pacer(0)))!.digest, whole.digest, "the last worktree's log is still covered");
  } finally { f.done(); }
});

test("the prefetch and the step over the launch's ONE git session (git-session.ts): the twins are the same, and the prefetch's close kills only its own calls", async () => {
  const f = fixture();
  // The session's runner bare (no bubblewrap) and its per-call path plain:
  // the kernel test runs the same in the real sandbox.
  const session = openGitSession({
    sandbox: () => ({ bwrap: "/unused/bwrap", flags: [] }),
    runnerCommand: () => ({ file: process.execPath, args: ["-e", GIT_SESSION_RUNNER_SOURCE] }),
    perCall: (c) => perCallGitRunner(c, () => null),
    ptraceScope: () => 1,
  });
  try {
    await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals }); // leaves the hint
    const plain = await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals });
    session.warm();
    const pre = TwinPrefetch.start({ hintFile: f.opts.hintFile, cacheDir: f.opts.cacheDir, now: later, gitSession: session });
    assert.ok(pre !== null);
    await pre.ready();
    const asked = session.stats.inSession;
    assert.ok(asked > 0, "the prefetch's reads ran in the session");
    const withPre = await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals, statePrefetch: pre, hashes: pre.hashes, gitSession: session });
    pre.close();
    assert.equal(pre.stats.used, 1, JSON.stringify(pre.stats));
    assert.equal(shape(withPre), shape(plain), "the same twins, the same ids");
    assert.ok(session.stats.inSession > asked, "so did the step's");
    assert.equal(session.stats.sandboxes, 1, "one sandbox for both");

    // A prefetch closed at once: its calls in the session are killed, the
    // session (the step's) answers on.
    const pre2 = TwinPrefetch.start({ hintFile: f.opts.hintFile, cacheDir: f.opts.cacheDir, now: later, gitSession: session });
    assert.ok(pre2 !== null);
    pre2.close();
    await pre2.ready();
    const after = await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals, gitSession: session });
    assert.equal(shape(after), shape(plain));
    assert.equal(session.stats.ended, undefined, "the session was not ended by the prefetch's close");
  } finally {
    session.close();
    f.done();
  }
});

test("a prefetch that fails never fails or weakens the launch; close kills every git call still running and leaves nothing behind", async () => {
  const f = fixture();
  try {
    const plain = await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals });
    const failing: GitRunner = async () => { throw new Error("git is broken in the prefetch"); };
    const bad = start(f, { git: failing });
    const got = await prepareGitObjectTwins([f.secret], { ...f.opts, seals: f.seals, statePrefetch: bad, hashes: bad.hashes });
    bad.close();
    assert.equal(shape(got), shape(plain));
    assert.equal(bad.stats.used, 0);

    // Real git calls, closed at once: none outlives the close.
    const before = readdirSync(f.tmp).sort();
    const pre = start(f, { git: undefined });
    pre.close();
    await pre.ready();
    const deadline = Date.now() + 5_000;
    let kids: string[] = [];
    do {
      kids = childrenOf(process.pid);
      if (kids.length === 0) break;
      await sleep(50);
    } while (Date.now() < deadline);
    assert.deepEqual(kids, [], "no git process left behind");
    assert.deepEqual(readdirSync(f.tmp).sort(), before, "nothing written");
    assert.equal(await pre.take([f.ws], new RepoReads(defaultGitRunner)), null, "a closed prefetch offers nothing");
  } finally { f.done(); }
});

/** The git-side children whose parent is `pid`: from /proc on Linux, from
 *  `ps` where there is none (macOS: there git may run as /usr/bin/git, the
 *  xcrun shim, or under sandbox-exec, Mandu's git sandbox). */
function childrenOf(pid: number): string[] {
  const out: string[] = [];
  const GIT_SIDE = new Set(["git", "bwrap", "nice", "sandbox-exec", "xcrun"]);
  if (!existsSync("/proc/self")) {
    const ps = execFileSync("ps", ["-A", "-o", "pid=,ppid=,comm="], { encoding: "utf8" });
    for (const line of ps.split("\n")) {
      const m = /^\s*(\d+)\s+(\d+)\s+(.+)$/.exec(line);
      if (!m || Number(m[2]) !== pid) continue;
      const comm = m[3]!.trim().split("/").pop()!;
      if (GIT_SIDE.has(comm)) out.push(`${m[1]} ${comm}`);
    }
    return out;
  }
  for (const d of readdirSync("/proc")) {
    if (!/^\d+$/.test(d)) continue;
    try {
      const stat = readFileSync(`/proc/${d}/stat`, "utf8");
      const ppid = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1]);
      if (ppid === pid && existsSync(`/proc/${d}`)) {
        const comm = readFileSync(`/proc/${d}/comm`, "utf8").trim();
        if (GIT_SIDE.has(comm)) out.push(`${d} ${comm}`);
      }
    } catch { /* gone */ }
  }
  return out;
}
