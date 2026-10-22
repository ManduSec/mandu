/**
 * Unit: lock-resolution — every path label resolved to blob ids in the
 * background (confidentiality-plan-14 §11.1 R2): the streaming raw-log
 * parser, the cache plan and its keys, the label roots, the blob-lock split;
 * the resolver over real repositories (a gone path, a hit, an incremental
 * walk after a new commit, a restart served from mandu.db, a label change
 * pending until resolved, the caps, a failure's retry), the labels the
 * HOME walk's macOS re-entry is fed (above public, real spellings), and
 * the hardening: a repository-configured fsmonitor program or signature
 * verifier is never started. Parity with the launcher's walk:
 * tests/stack/lock-resolution-parity.test.ts.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  hardenedResolverGit, labelRepoRoots, LockResolver, parseLsFilesStagePaths, parseResolution, planResolution, RawLogBlobPaths,
  splitBlobLocks, type RepoResolution, type ResolverGit,
} from "../../policy/lock-resolution.js";
import { compileHistoryLabels, labelFilterKey, labelWalkKey, resolutionKey, type HistoryLabel } from "../../policy/history-labels.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the locks are the confidentiality axis's

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = realpathSync(mkdtempSync(join(tmpdir(), "mdu-lockres-"))); dirs.push(d); return d; };
const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...a: string[]): string => execFileSync("git", a, { cwd, encoding: "utf8", env: ENV });
const blobOf = (cwd: string, body: string): string =>
  execFileSync("git", ["hash-object", "--stdin"], { cwd, input: body, encoding: "utf8", env: ENV }).trim();
const L = (path: string, level = "no-model", o: { recursive?: boolean; glob?: true } = {}): HistoryLabel =>
  ({ path, level, recursive: o.recursive ?? true, ...(o.glob ? { glob: true as const } : {}) });

/** A repository with a file committed and then deleted, and a kept one. */
function repo(): { root: string; gone: string; kept: string } {
  const root = join(tmp(), "repo");
  mkdirSync(join(root, "deploy"), { recursive: true });
  git(root, "init", "-q", "-b", "main");
  writeFileSync(join(root, "deploy", "key"), "gone-v1\n");
  writeFileSync(join(root, "app.txt"), "app\n");
  git(root, "add", "."); git(root, "commit", "-qm", "1");
  writeFileSync(join(root, "deploy", "key"), "gone-v2\n");
  git(root, "commit", "-qam", "2");
  git(root, "rm", "-q", "deploy/key"); git(root, "commit", "-qm", "3");
  return { root, gone: blobOf(root, "gone-v1\n"), kept: blobOf(root, "gone-v2\n") };
}

/** A git runner that records every call (the production one underneath). */
function counting(): { git: ResolverGit; calls: string[][] } {
  const calls: string[][] = [];
  const real = hardenedResolverGit(new Set());
  return { calls, git: (args, opts) => { calls.push(args); return real(args, opts); } };
}

// ── pure ─────────────────────────────────────────────────────────────────────

test("RawLogBlobPaths: fed in any chunks, it yields the pairs of one feed; gitlinks, the zero name and a torn tail are dropped", () => {
  const A = "a".repeat(40), B = "b".repeat(40), Z = "0".repeat(40), G = "c".repeat(40);
  const out = `\n:100644 100644 ${A} ${B} M\0dir/x\0:000000 100644 ${Z} ${A} A\0we ird\npath\0:160000 160000 ${G} ${G} M\0sub\0\n:100644 000000 ${B} ${Z} D\0y\0:100644 100644 ${A} ${B} M`;
  const oneFeed: Array<[string, string]> = [];
  const p1 = new RawLogBlobPaths((b, path) => oneFeed.push([b, path]));
  p1.feed(out); p1.end();
  assert.deepEqual(oneFeed, [[A, "dir/x"], [B, "dir/x"], [A, "we ird\npath"], [B, "y"]]);
  for (let cut = 1; cut < out.length; cut += 7) {
    const got: Array<[string, string]> = [];
    const p = new RawLogBlobPaths((b, path) => got.push([b, path]));
    for (let i = 0; i < out.length; i += cut) p.feed(out.slice(i, i + cut));
    p.end();
    assert.deepEqual(got, oneFeed, `chunks of ${cut}`);
  }
  assert.deepEqual(parseLsFilesStagePaths(`100644 ${A} 0\ta b\x00160000 ${G} 0\tsub\x00100644 ${B} 2\tc\x00`), [[A, "a b"], [B, "c"]]);
});

test("planResolution: the same tips hit, new tips walk only themselves, another filter, base or pathspec walks it all", () => {
  const e: RepoResolution = {
    v: 1, root: "/r", format: "sha1", filter: "f", specs: ["a"], base: "B", tips: ["1".repeat(40)], history: [], index: [], key: "k", at: 0,
  };
  const t2 = "2".repeat(40);
  assert.deepEqual(planResolution(e, "/r", "f", ["a"], "B", ["1".repeat(40)]), { kind: "hit" });
  assert.deepEqual(planResolution(e, "/r", "f", ["a"], "B", []), { kind: "hit" }, "a tip gone: the cached names are a superset");
  assert.deepEqual(planResolution(e, "/r", "f", ["a"], "B", ["1".repeat(40), t2]), { kind: "incremental", include: [t2], exclude: ["1".repeat(40)] });
  for (const [what, args] of [
    ["filter", ["/r", "g", ["a"], "B"]], ["base", ["/r", "f", ["a"], "C"]], ["specs", ["/r", "f", ["b"], "B"]], ["root", ["/s", "f", ["a"], "B"]],
  ] as const) {
    assert.deepEqual(planResolution(e, args[0], args[1], args[2], args[3], e.tips), { kind: "full" }, what);
  }
  assert.deepEqual(planResolution(null, "/r", "f", ["a"], "B", []), { kind: "full" });
  assert.equal(parseResolution(JSON.stringify(e))?.key, "k");
  for (const bad of ["{", "null", JSON.stringify({ ...e, v: 2 }), JSON.stringify({ ...e, history: ["zz"] }), JSON.stringify({ ...e, format: "md5" }),
    JSON.stringify({ ...e, format: "sha256", history: ["a".repeat(40)] })]) {
    assert.equal(parseResolution(bad), null, bad);
  }
});

test("labelRepoRoots: literal paths and patterns' literal prefixes above public name their work trees; splitBlobLocks by format", () => {
  const c = compileHistoryLabels([L("/w/a/deploy/key"), L("/w/b/README", "public"), L("/w/c/**/*.pem", "no-model", { glob: true }), L("**/.env", "no-model", { glob: true })]);
  const at = (p: string): string | null => (p.startsWith("/w/") ? p.split("/").slice(0, 3).join("/") : null);
  assert.deepEqual(labelRepoRoots(c, at), ["/w/a", "/w/c"], "a public label names none; an unrooted pattern has no prefix");
  assert.deepEqual(splitBlobLocks([`sha1:${"a".repeat(40)}`, `sha256:${"b".repeat(64)}`, `sha1:${"c".repeat(64)}`, "junk", `sha1:${"a".repeat(40)}`]),
    { sha1: ["a".repeat(40)], sha256: ["b".repeat(64)] });
});

// ── the resolver over real repositories ─────────────────────────────────────

test("resolver: a gone path's every version is locked; the key is the launcher's; an unchanged repository is a hit, a new commit walks only itself", async () => {
  const r = repo();
  const labels = [L(join(r.root, "deploy", "key"))];
  const { git: g, calls } = counting();
  const res = new LockResolver({ labels: () => labels, blobLocks: () => [], home: tmp(), git: g });
  try {
    assert.equal(res.note([r.root], "launch").length, 1);
    await res.runCycle(); await res.idle();
    const s = res.snapshot([r.root]);
    assert.deepEqual(s.lockedSet.sha1, [r.gone, r.kept].sort());
    assert.equal(s.complete, true);
    const entry = s.repos.find((x) => x.root === r.root)!;
    assert.deepEqual(entry.blobs, [r.gone, r.kept].sort());
    // The key is what the launcher computes from the same inputs.
    const tips = git(r.root, "rev-list", "--all", "--reflog", "--no-walk").split("\n").filter(Boolean).sort();
    const filter = labelFilterKey(labelWalkKey(labels, null), ["deploy/key"]);
    const logs = (): number => calls.filter((c) => c[0] === "log").length;
    assert.equal(logs(), 1, "one full walk");
    assert.equal(entry.key.length, 64);
    assert.notEqual(entry.key, resolutionKey(r.root, filter, "other-base", tips), "the base is part of the key");
    await res.runCycle();
    assert.equal(logs(), 1, "unchanged: a hit, no walk");
    mkdirSync(join(r.root, "deploy"), { recursive: true });
    writeFileSync(join(r.root, "deploy", "key"), "gone-v3\n");
    git(r.root, "add", "."); git(r.root, "commit", "-qm", "4");
    await res.runCycle();
    const incr = calls.filter((c) => c[0] === "log");
    assert.equal(incr.length, 2);
    assert.ok(incr[1]!.includes("--stdin"), "the new commit only");
    assert.ok(res.snapshot().lockedSet.sha1.includes(blobOf(r.root, "gone-v3\n")));
  } finally { await res.stop(); }
});

test("resolver (security fix 2026-10-21): a version once resolved stays resolved when a walk anew no longer reaches it (an orphan branch, the reflogs expired, another base)", async () => {
  const r = repo();
  const labels = [L(join(r.root, "deploy", "key"))];
  const { git: g, calls } = counting();
  const res = new LockResolver({ labels: () => labels, blobLocks: () => [], home: tmp(), git: g });
  try {
    res.note([r.root], "launch");
    await res.runCycle(); await res.idle();
    assert.deepEqual(res.snapshot([r.root]).lockedSet.sha1, [r.gone, r.kept].sort());
    // An agent cuts the history away: an orphan branch, main deleted, the
    // reflogs expired; a shallow file on the orphan root (a true boundary:
    // it has no parent) moves the base, so the next cycle walks anew.
    git(r.root, "checkout", "-q", "--orphan", "fresh");
    git(r.root, "commit", "-q", "--allow-empty", "-m", "fresh");
    git(r.root, "branch", "-D", "main");
    git(r.root, "reflog", "expire", "--expire=now", "--all");
    writeFileSync(join(r.root, ".git", "shallow"), `${git(r.root, "rev-parse", "HEAD").trim()}\n`);
    const before = calls.filter((c) => c.includes("log")).length;
    await res.runCycle(); await res.idle();
    assert.ok(calls.filter((c) => c.includes("log")).length > before, "walked anew");
    assert.deepEqual(res.snapshot([r.root]).lockedSet.sha1, [r.gone, r.kept].sort(), "both versions still locked");
  } finally { await res.stop(); }
});

test("resolver: a restart is served from mandu.db without a walk; a label change is pending until resolved, the old versions kept meanwhile", async () => {
  const r = repo();
  const home = tmp();
  const db = join(home, "mandu.db");
  let labels = [L(join(r.root, "deploy", "key"))];
  const first = new LockResolver({ labels: () => labels, blobLocks: () => [], home, dbPath: db });
  first.note([r.root], "launch");
  await first.runCycle(); await first.idle();
  await first.stop();
  const { git: g, calls } = counting();
  const second = new LockResolver({ labels: () => labels, blobLocks: () => [], home, dbPath: db, git: g });
  try {
    assert.deepEqual(second.snapshot().lockedSet.sha1, [r.gone, r.kept].sort(), "answered from mandu.db before any cycle");
    await second.runCycle();
    assert.equal(calls.filter((c) => c[0] === "log").length, 0, "a hit: no walk after the restart");
    // A carve-out makes the deploy folder public: pending until the next cycle.
    labels = [L(join(r.root, "deploy")), L(join(r.root, "deploy", "key"), "public")];
    const mid = second.snapshot();
    assert.equal(mid.complete, false);
    assert.deepEqual(mid.pending, [r.root]);
    assert.deepEqual(mid.lockedSet.sha1, [r.gone, r.kept].sort(), "the earlier versions stay while pending (a superset only hides more)");
    await second.idle(); await second.runCycle();
    const after = second.snapshot();
    assert.equal(after.complete, true);
    assert.deepEqual(after.lockedSet.sha1, [], "the carve-out wins once resolved");
  } finally { await second.stop(); }
});

test("resolver: over a repository's cap or the set's cap it is pending; a failure waits unless asked for by name; no label, no walk", async () => {
  const r = repo();
  const labels = [L(join(r.root, "deploy", "key"))];
  const capped = new LockResolver({ labels: () => labels, blobLocks: () => [], home: tmp(), limits: { maxRepoBlobs: 1 } });
  try {
    capped.note([r.root], "launch");
    await capped.runCycle(); await capped.idle();
    const s = capped.snapshot();
    assert.deepEqual([s.complete, s.pending, s.lockedSet.sha1], [false, [r.root], []]);
  } finally { await capped.stop(); }
  const setCap = new LockResolver({ labels: () => labels, blobLocks: () => [`sha1:${"e".repeat(40)}`], home: tmp(), limits: { maxLockedSet: 2 } });
  try {
    setCap.note([r.root], "launch");
    await setCap.runCycle(); await setCap.idle();
    const s = setCap.snapshot();
    assert.deepEqual([s.complete, s.pending, s.lockedSet.sha1], [false, [r.root], ["e".repeat(40)]], "the blob lock stays; the repository's versions do not fit");
  } finally { await setCap.stop(); }

  let fail = true;
  const calls: string[][] = [];
  const real = hardenedResolverGit(new Set());
  const flaky: ResolverGit = (args, opts) => { calls.push(args); return fail && args[0] === "rev-list" ? Promise.resolve({ code: 128, stdout: "", stderr: "boom", complete: false }) : real(args, opts); };
  const res = new LockResolver({ labels: () => labels, blobLocks: () => [], home: tmp(), git: flaky });
  try {
    res.note([r.root], "launch");
    await res.runCycle(); await res.idle();
    assert.deepEqual(res.snapshot().pending, [r.root]);
    fail = false;
    const before = calls.length;
    await res.runCycle();
    assert.equal(calls.length, before, "a failed repository waits for its retry time");
    res.note([r.root], "launch"); // asked for by name: tried now
    await res.idle(); await res.runCycle(); await res.idle();
    assert.equal(res.snapshot().complete, true);
  } finally { await res.stop(); }

  const { git: g, calls: c2 } = counting();
  const none = new LockResolver({ labels: () => [L("/elsewhere/key")], blobLocks: () => [], home: tmp(), git: g });
  try {
    none.note([r.root], "launch");
    await none.runCycle(); await none.idle();
    assert.equal(c2.length, 0, "no label reaches the repository: no git call");
    assert.deepEqual(none.snapshot(), { lockedSet: { sha1: [], sha256: [] }, repos: [], complete: true, pending: [] });
  } finally { await none.stop(); }
});

test("the HOME walk, macOS: the labels this resolver locks by (above public, real spellings included) keep a pruned folder walked where one concerns it; Linux walks it regardless", async () => {
  // The label source cannot reach this repository (it walks UP from a
  // label, and nothing above the project is a work tree): only the walk can.
  const home = tmp();
  const cloud = join(home, "Library", "Mobile Documents", "com~apple~CloudDocs");
  const icloud = join(cloud, "proj");
  mkdirSync(icloud, { recursive: true });
  git(icloud, "init", "-q", "-b", "main");
  const link = join(tmp(), "home-link");
  symlinkSync(home, link); // a label written through a symlinked HOME
  const found = async (labels: HistoryLabel[], platform: NodeJS.Platform): Promise<string[]> => {
    const res = new LockResolver({ labels: () => labels, blobLocks: () => [], home, platform, selfDir: null, env: {} });
    try {
      const r = await res.walkHome();
      assert.equal(res.registry.has(icloud), r.roots.includes(icloud), "the walk's roots are the registry's walk source");
      assert.equal(res.rootOf(cloud), null, "the label source names no work tree for the folder");
      return r.roots;
    } finally { await res.stop(); }
  };
  assert.deepEqual(await found([], "darwin"), [], "no label: ~/Library is not entered");
  assert.deepEqual(await found([L(cloud)], "darwin"), [icloud], "a folder label above the repository");
  assert.deepEqual(await found([L(join(link, "Library", "Mobile Documents", "com~apple~CloudDocs"))], "darwin"), [icloud],
    "spelled through a link: its real spelling is the walk's");
  assert.deepEqual(await found([L(`${home}/Library/**/id_rsa`, "no-model", { glob: true })], "darwin"), [icloud], "a pattern rooted above it");
  assert.deepEqual(await found([L(cloud, "public")], "darwin"), [], "a public label locks nothing, so it walks nothing");
  assert.deepEqual(await found([], "linux"), [icloud]);
});

test("hardening: a repository-configured fsmonitor program or signature verifier is never started", async () => {
  const r = repo();
  const d = tmp();
  const marker = join(d, "ran");
  const hook = join(d, "hook.sh");
  writeFileSync(hook, `#!/bin/sh\ntouch '${marker}'\nexit 1\n`);
  chmodSync(hook, 0o755);
  // A signed commit (a gpgsig header) so a signature verifier would be asked.
  const tree = git(r.root, "write-tree").trim();
  const head = git(r.root, "rev-parse", "HEAD").trim();
  const signed = execFileSync("git", ["hash-object", "-t", "commit", "-w", "--stdin"], {
    cwd: r.root, env: ENV, encoding: "utf8",
    input: `tree ${tree}\nparent ${head}\nauthor t <t@x> 1 +0000\ncommitter t <t@x> 1 +0000\ngpgsig -----BEGIN PGP ` + `SIGNATURE-----\n \n abc\n -----END PGP SIGNATURE-----\n\nsigned\n`,
  }).trim();
  git(r.root, "update-ref", "refs/heads/main", signed);
  git(r.root, "config", "core.fsmonitor", hook);
  git(r.root, "config", "log.showSignature", "true");
  git(r.root, "config", "gpg.program", hook);
  // The trap is armed: plain git runs the program.
  execFileSync("git", ["log", "--format=", "-1"], { cwd: r.root, env: ENV });
  assert.equal(existsSync(marker), true, "the fixture's trap works without the hardening");
  rmSync(marker);
  const res = new LockResolver({ labels: () => [L(join(r.root, "deploy", "key"))], blobLocks: () => [], home: tmp() });
  try {
    res.note([r.root], "launch");
    await res.runCycle(); await res.idle();
    assert.equal(res.snapshot().complete, true);
    assert.equal(existsSync(marker), false, "the arbiter must not run a program the repository names");
  } finally { await res.stop(); }
});

// write-protection.md §8.5.1 (CI pipelines 7777 and 7778): stop() while a cycle
// is starting its (sandboxed, where a git sandbox can be made: bubblewrap on
// Linux, Seatbelt on macOS) git always returns,
// and no call starts once stopped.
test("stop() racing a cycle's real git always returns; no git runs once stopped", async () => {
  const r = repo();
  const sleep = (ms: number): Promise<void> => new Promise((res) => setTimeout(res, ms));
  const races = 32;
  let next = 0;
  const lane = async (): Promise<void> => {
    while (next < races) {
      next++;
      const res = new LockResolver({ labels: () => [L(join(r.root, "deploy", "key"))], blobLocks: () => [], home: tmp() });
      res.note([r.root], "launch");
      void res.runCycle();
      await sleep(Math.random() * 40);
      let t: NodeJS.Timeout | undefined;
      await Promise.race([res.stop(), new Promise<never>((_, rej) => { t = setTimeout(() => rej(new Error("stop() did not return within 8000 ms")), 8000); })]);
      clearTimeout(t);
    }
  };
  await Promise.all(Array.from({ length: 8 }, lane));
  const calls: string[][] = [];
  const res = new LockResolver({
    labels: () => [L(join(r.root, "deploy", "key"))], blobLocks: () => [], home: tmp(),
    git: async (args) => { calls.push(args); return { code: 0, stdout: "", stderr: "", complete: true }; },
  });
  await res.stop();
  await res.runCycle();
  assert.equal((await res.register(r.root)).ok, false, "the registration's own git is refused once stopped");
  assert.deepEqual(calls, []);
});
