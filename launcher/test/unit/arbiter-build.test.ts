/**
 * arbiter-build.test — two builds of one Mandu release are told apart
 * (runtime-instances.md §4.1; reply-row-reservation.md §18.2, S8).
 *
 * The arbiter's `hello` carries `build` (arbiter/ipc/build-identity.ts); the
 * launcher compares it with the build it would start itself. Pure decisions
 * (parseBuild, compareBuilds, versionVerdict with builds, skewAction's full
 * table over version × build × in use × pinned × started), the launcher's own
 * build (ownArbiterBuild), and the driver (enforceRelease) with two launches
 * racing on one stack over the real release gate in a temp dir. Nothing is
 * spawned or signalled.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  afterRestartRefusal, checkArbiterRelease, compareBuilds, enforceRelease, ownArbiterBuild, parseBuild, skewAction,
  versionVerdict, type BuildIdentity, type SkewAction, type SkewInput, type VersionVerdict,
} from "../../src/arbiter-version.js";
import { acquireRestartLock, markReleaseCheckPending, pendingReleaseChecks, realGateDeps } from "../../src/release-gate.js";

const OURS = "0.2.0-beta.6";
const REAL = { pid: 4242, protocolVersion: 1, gitRev: "abc1234" };
const A: BuildIdentity = { bundle: "aaaaaaaaaaaaaaaa", rev: "abc1234" };
const B: BuildIdentity = { bundle: "bbbbbbbbbbbbbbbb", rev: "def5678" };

test("parseBuild: hex fields only (the rev later reaches a git argv); nothing usable is none", () => {
  assert.deepEqual(parseBuild({ build: { bundle: "aaaaaaaaaaaaaaaa", rev: "abc1234" } }), A);
  assert.deepEqual(parseBuild({ build: { bundle: null, rev: "abc1234" } }), { bundle: null, rev: "abc1234" });
  assert.deepEqual(parseBuild({ build: { bundle: "AAAA-not-hex", rev: "--output=/tmp/x" } }), null);
  assert.deepEqual(parseBuild({ build: { bundle: "aaaa", rev: "HEAD~1" } }), { bundle: "aaaa", rev: null });
  for (const h of [undefined, null, {}, { build: null }, { build: "x" }, { build: { bundle: null, rev: null } }]) {
    assert.equal(parseBuild(h), null, JSON.stringify(h));
  }
});

test("compareBuilds: bundles by hash, else checkout revs (scope-honest), else two places", () => {
  const trees = (same: boolean | null) => () => same;
  // Two bundles: the hash decides, whatever the revs say.
  assert.equal(compareBuilds(A, { ...A, rev: "fff0000" }), "same", "one bundle from two commits that did not touch the arbiter");
  assert.equal(compareBuilds(A, { ...B, rev: A.rev }), "different", "a rebuild with uncommitted edits");
  // A bundle and a source run of one checkout: the revs.
  assert.equal(compareBuilds(A, { bundle: null, rev: "abc1234" }), "same");
  assert.equal(compareBuilds(A, { bundle: null, rev: "def5678" }, trees(true)), "same", "the arbiter/ trees are identical");
  assert.equal(compareBuilds(A, { bundle: null, rev: "def5678" }, trees(false)), "different");
  assert.equal(compareBuilds(A, { bundle: null, rev: "def5678" }, trees(null)), "different", "a rev this checkout cannot resolve");
  assert.equal(compareBuilds(A, { bundle: null, rev: "def5678" }), "different");
  // An install's bundle against a checkout's source: two places.
  assert.equal(compareBuilds({ bundle: "aaaa", rev: null }, { bundle: null, rev: "abc1234" }), "different");
  assert.equal(compareBuilds({ bundle: null, rev: "abc1234" }, { bundle: "aaaa", rev: null }), "different");
  // No evidence on either side.
  assert.equal(compareBuilds(null, A), "unknown");
  assert.equal(compareBuilds(A, null), "unknown");
  assert.equal(compareBuilds({ bundle: null, rev: null }, A), "unknown");
});

test("versionVerdict: this release of another build is `build`; our own build is read only then", () => {
  let reads = 0;
  const deps = (own: BuildIdentity | null) => ({ own: () => { reads++; return own; } });
  assert.deepEqual(versionVerdict(OURS, { ...REAL, version: OURS, build: A }, deps(A)), { kind: "match", theirs: OURS });
  assert.deepEqual(versionVerdict(OURS, { ...REAL, version: OURS, build: B }, deps(A)),
    { kind: "build", theirs: OURS, theirsBuild: B, oursBuild: A });
  assert.equal(reads, 2);
  assert.equal(versionVerdict(OURS, { ...REAL, version: OURS, build: B }, deps(null)).kind, "match", "we cannot say our own: version only");
  assert.equal(versionVerdict(OURS, { ...REAL, version: OURS, build: B }).kind, "match", "no build deps: version only");
  const before = reads;
  assert.equal(versionVerdict(OURS, { ...REAL, version: OURS }, deps(A)).kind, "match", "an arbiter that reports no build");
  assert.equal(versionVerdict(OURS, { ...REAL, version: "0.1.0", build: B }, deps(A)).kind, "older", "another release: the version decides");
  assert.equal(reads, before, "our build is not read when there is nothing to compare it with");
});

function input(verdict: VersionVerdict, over: Partial<SkewInput> = {}): SkewInput {
  return {
    verdict, ours: OURS, sock: "/run/user/1/mandu/current/arbiter.sock", mode: "current", started: false,
    base: "/run/user/1/mandu", arbiterPid: 4242, peers: [], ...over,
  };
}

// The decision table (runtime-instances.md §4.1): what the launch does, by the
// arbiter's version and build, whether this launch started it, whether its
// socket is pinned, and whether another session uses it.
const VERDICTS: Record<string, VersionVerdict> = {
  "same version, same build": { kind: "match", theirs: OURS },
  "same version, no build to compare": { kind: "match", theirs: OURS },
  "no answer": { kind: "unknown" },
  "same version, other build": { kind: "build", theirs: OURS, theirsBuild: B, oursBuild: A },
  "older version": { kind: "older", theirs: "0.2.0-beta.5" },
  "newer version": { kind: "newer", theirs: "0.3.0" },
};
type Want = SkewAction["kind"];
function expected(name: string, started: boolean, pinned: boolean, inUse: boolean): Want {
  const v = VERDICTS[name]!;
  if (v.kind === "match" || v.kind === "unknown") return "proceed";
  if (started || pinned) return "refuse";
  if (v.kind === "newer") return "refuse";
  return inUse ? "refuse" : "restart";
}

test("skewAction: the whole table, version × build × started × pinned × in use", () => {
  const rows: string[] = [];
  for (const name of Object.keys(VERDICTS)) {
    for (const started of [false, true]) {
      for (const pinned of [false, true]) {
        for (const inUse of [false, true]) {
          const a = skewAction(input(VERDICTS[name]!, {
            started, mode: pinned ? "pinned" : started ? "autostart" : "current", peers: inUse ? [777] : [],
          }));
          const want = expected(name, started, pinned, inUse);
          assert.equal(a.kind, want, `${name}, started=${started}, pinned=${pinned}, in use=${inUse}`);
          rows.push(`${name} | ${started} | ${pinned} | ${inUse} | ${a.kind}`);
        }
      }
    }
  }
  assert.equal(rows.length, 48);
});

test("skewAction: every refusal and restart of another build names both builds", () => {
  const v = VERDICTS["same version, other build"]!;
  const both = /another build of Mandu 0\.2\.0-beta\.6 \(bundle bbbbbbbbbbbbbbbb, rev def5678\) than this mandu \(bundle aaaaaaaaaaaaaaaa, rev abc1234\)/;
  const started = skewAction(input(v, { started: true, mode: "autostart" })) as { kind: string; message: string };
  assert.match(started.message, both);
  assert.match(started.message, /the arbiter this launch started .*refusing to launch against another build/);
  const pinned = skewAction(input(v, { mode: "pinned", sock: "/tmp/a.sock" })) as { message: string };
  assert.match(pinned.message, both);
  assert.match(pinned.message, /the arbiter at \/tmp\/a\.sock \(MANDU_ARBITER_SOCK, pid 4242\).*unset MANDU_ARBITER_SOCK/);
  const inUse = skewAction(input(v, { peers: [111, 222] })) as { message: string };
  assert.match(inUse.message, both);
  assert.match(inUse.message, /2 other mandu sessions use them \(pid 111, 222\)/);
  assert.match(inUse.message, /mandu stop --stack \/run\/user\/1\/mandu$/);
  const restart = skewAction(input(v)) as { kind: string; note: string };
  assert.equal(restart.kind, "restart");
  assert.match(restart.note, both);
  assert.match(restart.note, /restarting them as this build$/);
});

test("checkArbiterRelease: another build is scanned for sessions like an older release", async () => {
  let scans = 0;
  const r = await checkArbiterRelease(
    { ours: OURS, sock: "/s", mode: "current", started: false, base: "/b" },
    { hello: async () => ({ ...REAL, version: OURS, build: B }), peers: () => { scans++; return []; }, build: { own: () => A } },
  );
  assert.equal(scans, 1);
  assert.equal(r.verdict.kind, "build");
  assert.equal(r.action.kind, "restart");
});

test("afterRestartRefusal: the restarted arbiter must be this build too", () => {
  const m = afterRestartRefusal({ kind: "build", theirs: OURS, theirsBuild: B, oursBuild: A }, OURS, "/s");
  assert.match(m!, /the restarted Mandu arbiter at \/s runs another build of Mandu 0\.2\.0-beta\.6 \(bundle bbbbbbbbbbbbbbbb, rev def5678\)/);
});

test("ownArbiterBuild: the bundle it spawns, and the checkout's rev in a dev layout", () => {
  const sha16 = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 16);
  const files: Record<string, string> = { "/pkg/dist/arbiter.mjs": "installed bundle", "/repo/launcher/dist/arbiter.mjs": "checkout bundle" };
  const readFile = (p: string): Uint8Array => {
    const f = files[p];
    if (f === undefined) throw new Error(`ENOENT ${p}`);
    return Buffer.from(f);
  };
  const revOf = (dir: string) => (dir === "/repo" ? "abc1234" : "nogit");
  assert.deepEqual(ownArbiterBuild({ mode: "installed", bundled: true, pkgRoot: "/pkg", repoRoot: "/pkg" }, { readFile, revOf }),
    { bundle: sha16("installed bundle"), rev: null }, "an install has no rev");
  assert.deepEqual(ownArbiterBuild({ mode: "dev", bundled: true, pkgRoot: "/repo/launcher", repoRoot: "/repo" }, { readFile, revOf }),
    { bundle: sha16("checkout bundle"), rev: "abc1234" });
  assert.deepEqual(ownArbiterBuild({ mode: "dev", bundled: false, pkgRoot: "/repo/launcher", repoRoot: "/repo" }, { readFile, revOf }),
    { bundle: null, rev: "abc1234" }, "from source: the rev");
  assert.equal(ownArbiterBuild({ mode: "dev", bundled: false, pkgRoot: "/x/launcher", repoRoot: "/x" }, { readFile, revOf }), null,
    "no git, no bundle: nothing to compare");
});

// ── The racing launches (release-gate.ts) ────────────────────────────────────

/** A stack the fake launches share: which build answers, and the calls. */
interface FakeStack { build: BuildIdentity | null; stops: number; starts: number }

function launch(stack: FakeStack, base: string, pid: number, livePeers: () => number[], notes: string[]): Promise<{ restarted: boolean }> {
  const deps = { ...realGateDeps, pidAlive: () => true };
  const releaseDeps = {
    hello: async () => (stack.build ? { ...REAL, version: OURS, build: stack.build } : undefined),
    peers: (b: string) => {
      const pending = pendingReleaseChecks(b, deps);
      return livePeers().filter((p) => p !== pid && !pending.has(p));
    },
    build: { own: () => A },
  };
  const check = (started: boolean) => checkArbiterRelease({ ours: OURS, sock: "/s", mode: "current", started, base }, releaseDeps);
  return enforceRelease({
    check, started: false, pinned: () => false,
    markPending: () => markReleaseCheckPending(base, pid, deps),
    acquireLock: () => acquireRestartLock(base, { pid, pollMs: 5, waitMs: 10_000 }, deps),
    note: (m) => notes.push(`${pid}: ${m}`),
    stop: async () => {
      stack.stops++;
      await new Promise((r) => setTimeout(r, 30));
      stack.build = null;
      return { survivors: [] };
    },
    startThisBuild: async () => {
      await new Promise((r) => setTimeout(r, 30));
      if (stack.build === null) { stack.build = A; stack.starts++; }
      return { verdict: (await check(true)).verdict, sock: "/s" };
    },
    ours: OURS, base,
  });
}

test("racing launches on one unused stack of another build: one replaces it, the other adopts the new one", async () => {
  const base = mkdtempSync(join(tmpdir(), "mandu-gate-"));
  try {
    const stack: FakeStack = { build: B, stops: 0, starts: 0 };
    const notes: string[] = [];
    // Both launches are live `mandu` processes on the stack; each one's peer
    // scan sees the other.
    const live = () => [101, 202];
    const [r1, r2] = await Promise.all([launch(stack, base, 101, live, notes), launch(stack, base, 202, live, notes)]);
    assert.equal([r1, r2].filter((r) => r.restarted).length, 1, `one restart: ${JSON.stringify([r1, r2])}`);
    assert.equal(stack.stops, 1, "the stack was stopped once");
    assert.equal(stack.starts, 1, "and this build's started once");
    assert.deepEqual(stack.build, A);
    assert.equal(notes.length, 1, notes.join("\n"));
    assert.deepEqual([...pendingReleaseChecks(base, { ...realGateDeps, pidAlive: () => true })], [], "no marker is left behind");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("racing launches beside a real session still refuse, and leave the stack alone", async () => {
  const base = mkdtempSync(join(tmpdir(), "mandu-gate-"));
  try {
    const stack: FakeStack = { build: B, stops: 0, starts: 0 };
    const live = () => [101, 202, 303]; // 303 is a session: it marked nothing
    const results = await Promise.allSettled([launch(stack, base, 101, live, []), launch(stack, base, 202, live, [])]);
    for (const r of results) {
      assert.equal(r.status, "rejected");
      assert.match(String((r as PromiseRejectedResult).reason), /another mandu session uses them \(pid 303\)/);
    }
    assert.equal(stack.stops, 0);
    assert.deepEqual(stack.build, B);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("release gate: only what a launch writes is a marker (the agent's mkdir, a wrong content or a planted link is not)", () => {
  const base = mkdtempSync(join(tmpdir(), "mandu-gate-"));
  const other = mkdtempSync(join(tmpdir(), "mandu-gate-elsewhere-"));
  try {
    const deps = { ...realGateDeps, pidAlive: () => true };
    const gate = join(base, "release-check");
    mkdirSync(gate);
    // The guard lets the agent make a bare directory, nothing else here.
    mkdirSync(join(gate, "pending-4242"));
    writeFileSync(join(gate, "pending-4243"), "999"); // a file whose content is another pid
    symlinkSync(join(other, "x"), join(gate, "pending-4244"));
    writeFileSync(join(other, "x"), "4244");
    assert.deepEqual([...pendingReleaseChecks(base, deps)], [], "no forged marker counts");
    const clear = markReleaseCheckPending(base, 4245, deps);
    assert.deepEqual([...pendingReleaseChecks(base, deps)], [4245], "a launch's own marker does");
    clear();
    // A link planted at release-check itself puts no gate elsewhere.
    const base2 = mkdtempSync(join(tmpdir(), "mandu-gate-"));
    try {
      writeFileSync(join(other, "pending-77"), "77");
      symlinkSync(other, join(base2, "release-check"));
      assert.deepEqual([...pendingReleaseChecks(base2, deps)], [], "markers behind a link are not read");
      markReleaseCheckPending(base2, 78, deps)();
      assert.ok(!existsSync(join(other, "pending-78")), "and nothing is written through it");
    } finally {
      rmSync(base2, { recursive: true, force: true });
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
    rmSync(other, { recursive: true, force: true });
  }
});

test("release gate: an ownerless lock (all the agent can make there) is taken over after a few seconds", async () => {
  const base = mkdtempSync(join(tmpdir(), "mandu-gate-"));
  try {
    mkdirSync(join(base, "release-check", "lock"), { recursive: true });
    const t = Date.now();
    const deps = { ...realGateDeps, pidAlive: () => true, now: () => Date.now() + 6_000 };
    const got = await acquireRestartLock(base, { pid: 9, pollMs: 5, waitMs: 10_000 }, deps);
    assert.ok(got, "taken over");
    assert.ok(Date.now() - t < 2_000);
    got!();
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("release gate: a stale marker or a dead lock holder counts for nothing; the base is never created", async () => {
  const base = mkdtempSync(join(tmpdir(), "mandu-gate-"));
  try {
    const dead = new Set([555]);
    const deps = { ...realGateDeps, pidAlive: (p: number) => !dead.has(p) };
    markReleaseCheckPending(base, 555, deps);
    const clear = markReleaseCheckPending(base, 556, deps);
    assert.deepEqual([...pendingReleaseChecks(base, deps)], [556], "a dead pid's marker is no pending check");
    assert.deepEqual([...pendingReleaseChecks(base, { ...deps, now: () => Date.now() + 11 * 60_000 })], [], "an old marker neither");
    clear();
    assert.deepEqual([...pendingReleaseChecks(base, deps)], []);
    // A lock held by a dead launch is taken over at once.
    const held = await acquireRestartLock(base, { pid: 555 }, deps);
    assert.ok(held);
    const t0 = Date.now();
    const mine = await acquireRestartLock(base, { pid: 556, pollMs: 5, waitMs: 2_000 }, deps);
    assert.ok(mine, "taken over");
    assert.ok(Date.now() - t0 < 1_000);
    // A live holder makes the next one wait, and the wait can run out.
    assert.equal(await acquireRestartLock(base, { pid: 557, pollMs: 5, waitMs: 50 }, deps), null);
    mine!();
    const next = await acquireRestartLock(base, { pid: 557, pollMs: 5, waitMs: 50 }, deps);
    assert.ok(next, "free again once released");
    next!();
    // No runtime dir, no gate: nothing is created there.
    const missing = join(base, "no-such-runtime-dir");
    markReleaseCheckPending(missing, 1, deps)();
    assert.equal(await acquireRestartLock(missing, { pid: 1 }, deps), null);
    assert.throws(() => realGateDeps.readdir(missing));
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
