/**
 * probe-cache.test — the launch's kernel probes kept per boot
 * (src/probe-cache.ts; packaging.md §5.4, rootless-confinement-ubuntu-2404.md
 * §12.6).
 *
 * Pins, with no kernel and no privilege:
 *   - KEYING: the key moves with the boot, each probed binary's identity, the
 *     uid, the userns knobs, the namespaces / seccomp the launcher runs in,
 *     PATH, the argv and this code's own identity; it is stable otherwise;
 *   - ONLY PASSES ARE KEPT: a failed probe is asked again on every launch, a
 *     planted negative / foreign / malformed entry is ignored, a kept pass
 *     whose key no longer matches (a new boot, a changed binary) is re-probed;
 *   - THE FILE: written 0600 in a 0700 dir; refused (a miss) when it is a
 *     symlink, not the caller's, group/other-accessible, in a loose dir, too
 *     large or unparsable;
 *   - ONLY THE LAUNCH READS IT: without enableProbeCache every call probes;
 *     MANDU_PROBE_CACHE=0 reads nothing; `mandu setup` and a failed launch
 *     that used a kept pass drop the file;
 *   - the git sandbox keeps only its best answer and never its version.
 */
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  PROBE_CACHE_ENV, PROBE_CACHE_MAX_AGE_MS, PROBE_CACHE_VERSION,
  bestGitSandbox, cachedProbe, cachedProbeAsync, clearProbeCacheFile, disableProbeCache, enableProbeCache, forgetAfterFailure,
  launchGitSandbox, parseCacheFile, probeCacheFile, probeCacheHits, probeContext, probeKey, readProbeCacheFile,
  type ProbeCacheIo, type ProbeInputs,
} from "../../src/probe-cache.js";
import { GIT_SANDBOX_FLAG_SETS, MANDU_OWN_BWRAP } from "../../src/hardened-git.js";
import { runSetup, type SetupDeps, type SetupFacts } from "../../src/setup.js";
import { LANDLOCK_NET_PROBE_ARGV, planInspectNetConfine } from "../../src/inspect-net-confine.js";
import { spawnSync } from "node:child_process";

const UID = process.getuid!();

afterEach(() => disableProbeCache());

/** A host made of maps: files, links, identities, PATH entries. */
function fakeIo(over: { files?: Record<string, string>; ids?: Record<string, string>; links?: Record<string, string>; onPath?: Record<string, string> } = {}): ProbeCacheIo & { files: Record<string, string>; ids: Record<string, string>; links: Record<string, string> } {
  const files: Record<string, string> = {
    "/proc/sys/kernel/random/boot_id": "boot-1",
    "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": "1",
    "/proc/sys/user/max_user_namespaces": "1000",
    "/proc/self/status": "Uid:\t1000\t1000\t1000\t1000\nNoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\nCapEff:\t0000000000000000\n",
    "/proc/self/attr/current": "unconfined",
    ...over.files,
  };
  const ids: Record<string, string> = { "/usr/bin/bwrap": "/usr/bin/bwrap|1|100|1|10|10", "/usr/bin/git": "/usr/bin/git|1|200|1|10|10", ...over.ids };
  const links: Record<string, string> = { "/proc/self/ns/user": "user:[4026531837]", "/proc/self/ns/mnt": "mnt:[4026531841]", ...over.links };
  const onPath: Record<string, string> = { bwrap: "/usr/bin/bwrap", git: "/usr/bin/git", ...over.onPath };
  return {
    files, ids, links,
    readText: (p) => files[p] ?? null,
    readLink: (p) => links[p] ?? null,
    identity: (p) => ids[p] ?? null,
    which: (n) => onPath[n] ?? null,
  };
}

const ENV = { PATH: "/usr/bin" };
const BWRAP_IN: ProbeInputs = { bins: ["bwrap"], argv: ["--unshare-user", "--", "true"] };
const keyOf = (io: ProbeCacheIo, inputs: ProbeInputs = BWRAP_IN, env: Record<string, string> = ENV): string =>
  probeKey("userns", inputs, probeContext(env, io), env, io);

// ── keying ────────────────────────────────────────────────────────────────────

test("key: stable for the same host, and moves with every input a probe reads", () => {
  const base = keyOf(fakeIo());
  assert.equal(keyOf(fakeIo()), base, "same inputs, same key");
  assert.match(base, /^[0-9a-f]{64}$/);
  const moved: Array<[string, string]> = [
    ["a new boot", keyOf(fakeIo({ files: { "/proc/sys/kernel/random/boot_id": "boot-2" } }))],
    ["bwrap replaced (new inode)", keyOf(fakeIo({ ids: { "/usr/bin/bwrap": "/usr/bin/bwrap|1|101|1|10|10" } }))],
    ["bwrap touched (new mtime)", keyOf(fakeIo({ ids: { "/usr/bin/bwrap": "/usr/bin/bwrap|1|100|1|11|11" } }))],
    ["a different bwrap first on PATH", keyOf(fakeIo({ onPath: { bwrap: "/home/u/bin/bwrap" }, ids: { "/home/u/bin/bwrap": "/home/u/bin/bwrap|2|5|1|1|1" } }))],
    ["bwrap gone", keyOf(fakeIo({ onPath: { bwrap: "" } }))],
    ["the AppArmor userns knob", keyOf(fakeIo({ files: { "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": "0" } }))],
    ["the userns quota", keyOf(fakeIo({ files: { "/proc/sys/user/max_user_namespaces": "0" } }))],
    ["inside another user namespace", keyOf(fakeIo({ links: { "/proc/self/ns/user": "user:[4026532000]" } }))],
    ["under a seccomp filter", keyOf(fakeIo({ files: { "/proc/self/status": "Uid:\t1000\nSeccomp:\t2\nSeccomp_filters:\t1\n" } }))],
    ["under an AppArmor profile", keyOf(fakeIo({ files: { "/proc/self/attr/current": "unpriv_bwrap (enforce)" } }))],
    ["Mandu's bwrap profile file added", keyOf(fakeIo({ ids: { "/etc/apparmor.d/mandu-bwrap": "x|1|7|1|1|1" } }))],
    ["Mandu's own bubblewrap installed", keyOf(fakeIo({ ids: { "/usr/lib/mandu/bin/bwrap": "y|1|8|1|1|1" } }))],
    ["another argv", keyOf(fakeIo(), { bins: ["bwrap"], argv: ["--unshare-user", "--unshare-net", "--", "true"] })],
    ["another PATH", keyOf(fakeIo(), BWRAP_IN, { PATH: "/opt/bin:/usr/bin" })],
    ["MANDU_GIT_SANDBOX set", keyOf(fakeIo(), BWRAP_IN, { PATH: "/usr/bin", MANDU_GIT_SANDBOX: "0" })],
  ];
  for (const [why, k] of moved) assert.notEqual(k, base, `the key must move with ${why}`);
  // A different probe never shares a key.
  const io = fakeIo();
  assert.notEqual(probeKey("nesting", BWRAP_IN, probeContext(ENV, io), ENV, io), base);
});

test("context: never reads the AppArmor revision file (it blocks until the next policy change)", () => {
  const read: string[] = [];
  const io = fakeIo();
  probeContext(ENV, { ...io, readText: (p) => { read.push(p); return io.readText(p); } });
  assert.ok(read.includes("/proc/sys/kernel/random/boot_id"));
  assert.ok(!read.some((p) => p.includes("/apparmor/revision")), read.join("\n"));
});

// ── the file ─────────────────────────────────────────────────────────────────

function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "mandu-probe-cache-"));
  chmodSync(d, 0o700);
  return d;
}

test("parse: only the current version, known probe names and well-formed entries survive", () => {
  const k = "a".repeat(64);
  assert.equal(parseCacheFile("{"), null);
  assert.equal(parseCacheFile("[]"), null);
  assert.equal(parseCacheFile(JSON.stringify({ v: PROBE_CACHE_VERSION + 1, entries: {} })), null);
  const p = parseCacheFile(JSON.stringify({
    v: PROBE_CACHE_VERSION,
    entries: {
      userns: { key: k, at: 1 },
      "not-a-probe": { key: k, at: 1 },
      "bwrap-help": { key: k, at: 1 },
      nesting: { key: "short", at: 1 },
      "landlock-net": { key: k, at: "1" },
      "git-sandbox": { key: k, at: 1, value: { bwrap: "/tmp/evil", flags: [] } },
    },
  }));
  assert.deepEqual(Object.keys(p!.entries).sort(), ["bwrap-help", "git-sandbox", "userns"]);
  assert.deepEqual(p!.entries["git-sandbox"], { key: k, at: 1 }, "no value is ever read from the file: an entry is a pass, nothing more");
});

test("read: refuses a symlink, a foreign owner, a loose mode, a loose dir, a big or broken file (each a miss)", () => {
  const d = tmp();
  try {
    const f = join(d, "kernel-probes.json");
    const good = JSON.stringify({ v: PROBE_CACHE_VERSION, entries: { userns: { key: "b".repeat(64), at: 5 } } });
    assert.equal(readProbeCacheFile(f, UID).refused, "absent");
    writeFileSync(f, good, { mode: 0o600 });
    assert.deepEqual(readProbeCacheFile(f, UID), { entries: { userns: { key: "b".repeat(64), at: 5 } } });
    assert.equal(readProbeCacheFile(f, UID + 1).refused, "foreign-owner");
    chmodSync(f, 0o644);
    assert.equal(readProbeCacheFile(f, UID).refused, "loose-mode");
    chmodSync(f, 0o600);
    chmodSync(d, 0o755);
    assert.equal(readProbeCacheFile(f, UID).refused, "bad-dir");
    chmodSync(d, 0o700);
    writeFileSync(f, "{not json", { mode: 0o600 });
    assert.equal(readProbeCacheFile(f, UID).refused, "unparsable");
    writeFileSync(f, " ".repeat(70 * 1024), { mode: 0o600 });
    assert.equal(readProbeCacheFile(f, UID).refused, "too-large");
    rmSync(f);
    const real = join(d, "elsewhere.json");
    writeFileSync(real, good, { mode: 0o600 });
    symlinkSync(real, f);
    assert.equal(readProbeCacheFile(f, UID).refused, "symlink");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

// ── the launch's cache ───────────────────────────────────────────────────────

/** One "launch": enable, ask, report what ran. */
function launchAsk(file: string, io: ProbeCacheIo, answer: boolean, env: Record<string, string> = {}, now = 1_000_000): { got: boolean; probed: number; hits: readonly string[] } {
  enableProbeCache({ ...ENV, ...env }, { file, io, procEnv: ENV, now: () => now });
  let probed = 0;
  const got = cachedProbe("userns", () => BWRAP_IN, () => { probed++; return answer; });
  // The same question twice in one launch is asked once.
  const again = cachedProbe("userns", () => BWRAP_IN, () => { probed++; return answer; });
  assert.equal(again, got);
  const hits = [...probeCacheHits()];
  disableProbeCache();
  return { got, probed, hits };
}

test("a pass is kept 0600 and answers the next launch without a probe", () => {
  const d = tmp();
  try {
    // A runtime dir looser than it should be (one was found 0775): the cache
    // keeps to its own 0700 directory inside it.
    mkdirSync(join(d, "rt"));
    chmodSync(join(d, "rt"), 0o775);
    const f = join(d, "rt", "probe-cache", "kernel-probes.json");
    const io = fakeIo();
    assert.deepEqual(launchAsk(f, io, true), { got: true, probed: 1, hits: [] });
    assert.equal(statSync(f).mode & 0o777, 0o600);
    assert.equal(statSync(join(d, "rt", "probe-cache")).mode & 0o777, 0o700);
    assert.deepEqual(launchAsk(f, io, false), { got: true, probed: 0, hits: ["userns"] }, "kept: the probe does not run");
    // Its directory loosened: nothing is read from it, nor written to it.
    chmodSync(join(d, "rt", "probe-cache"), 0o775);
    assert.deepEqual(launchAsk(f, io, false), { got: false, probed: 1, hits: [] });
    rmSync(f);
    assert.deepEqual(launchAsk(f, io, true), { got: true, probed: 1, hits: [] });
    assert.equal(existsSync(f), false, "never written into a directory others can write");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("a failure is never kept: every launch probes again, so a fixed host is noticed at once", () => {
  const d = tmp();
  try {
    const f = join(d, "kernel-probes.json");
    const io = fakeIo();
    assert.deepEqual(launchAsk(f, io, false), { got: false, probed: 1, hits: [] });
    assert.equal(existsSync(f), false, "nothing written for a failure");
    assert.deepEqual(launchAsk(f, io, false), { got: false, probed: 1, hits: [] });
    // The host is fixed (no setup needed): the very next launch sees it.
    assert.deepEqual(launchAsk(f, io, true), { got: true, probed: 1, hits: [] });
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("a kept pass is re-probed when its inputs change (new boot, new binary) or it is too old; a re-probe that fails drops it", () => {
  const d = tmp();
  try {
    const f = join(d, "kernel-probes.json");
    const io = fakeIo();
    launchAsk(f, io, true);
    const rebooted = fakeIo({ files: { "/proc/sys/kernel/random/boot_id": "boot-2" } });
    assert.deepEqual(launchAsk(f, rebooted, false), { got: false, probed: 1, hits: [] }, "a new boot asks again");
    assert.equal(parseCacheFile(readFileSync(f, "utf8"))!.entries["userns"], undefined, "the failed re-probe dropped the entry");
    launchAsk(f, io, true);
    const newBwrap = fakeIo({ ids: { "/usr/bin/bwrap": "/usr/bin/bwrap|1|999|1|10|10" } });
    assert.equal(launchAsk(f, newBwrap, true).probed, 1, "an upgraded bwrap asks again");
    launchAsk(f, io, true);
    assert.equal(launchAsk(f, io, true, {}, 1_000_000 + PROBE_CACHE_MAX_AGE_MS + 1).probed, 1, "too old: asked again");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("a planted file can only claim a pass for the exact inputs; a planted negative or junk is ignored", () => {
  const d = tmp();
  try {
    const f = join(d, "kernel-probes.json");
    const io = fakeIo();
    writeFileSync(f, JSON.stringify({ v: PROBE_CACHE_VERSION, entries: { userns: { key: "c".repeat(64), at: 1_000_000, value: false } } }), { mode: 0o600 });
    assert.deepEqual(launchAsk(f, io, true), { got: true, probed: 1, hits: [] }, "a foreign key is a miss");
    writeFileSync(f, JSON.stringify({ v: PROBE_CACHE_VERSION, entries: { userns: { key: keyOf(io), at: 1_000_000 } } }));
    chmodSync(f, 0o644);
    assert.deepEqual(launchAsk(f, io, false), { got: false, probed: 1, hits: [] }, "a group/other-readable file is refused");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("MANDU_PROBE_CACHE=0 reads nothing (fresh probes), and still keeps a fresh pass", () => {
  const d = tmp();
  try {
    const f = join(d, "kernel-probes.json");
    const io = fakeIo();
    launchAsk(f, io, true);
    assert.deepEqual(launchAsk(f, io, true, { [PROBE_CACHE_ENV]: "0" }), { got: true, probed: 1, hits: [] });
    assert.deepEqual(launchAsk(f, io, false, { [PROBE_CACHE_ENV]: "0" }), { got: false, probed: 1, hits: [] }, "the bypass sees the host as it is");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("only a launch reads the cache: without enableProbeCache (doctor, setup) every call probes", () => {
  disableProbeCache();
  let probed = 0;
  for (let i = 0; i < 3; i++) assert.equal(cachedProbe("userns", () => BWRAP_IN, () => { probed++; return true; }), true);
  assert.equal(probed, 3);
  assert.deepEqual(probeCacheHits(), []);
});

test("a failed launch that used a kept pass drops the file; one that used none leaves it", () => {
  const d = tmp();
  try {
    const f = join(d, "kernel-probes.json");
    const io = fakeIo();
    enableProbeCache(ENV, { file: f, io, procEnv: ENV });
    cachedProbe("userns", () => BWRAP_IN, () => true);
    assert.equal(forgetAfterFailure(), false, "a fresh answer: nothing to blame on the cache");
    assert.ok(existsSync(f));
    enableProbeCache(ENV, { file: f, io, procEnv: ENV });
    cachedProbe("userns", () => BWRAP_IN, () => { throw new Error("must not probe"); });
    assert.equal(forgetAfterFailure(), true);
    assert.equal(existsSync(f), false, "the next launch probes afresh");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("the file lives in the per-boot runtime dir; clearProbeCacheFile removes it", () => {
  assert.equal(probeCacheFile({ MANDU_RUNTIME_DIR: "/run/user/7/mandu" }, "/home/u"), "/run/user/7/mandu/probe-cache/kernel-probes.json");
  assert.equal(probeCacheFile({ XDG_RUNTIME_DIR: "/run/user/7" }, "/home/u"), "/run/user/7/mandu/probe-cache/kernel-probes.json");
  const d = tmp();
  try {
    mkdirSync(join(d, "mandu"), { mode: 0o700 });
    mkdirSync(join(d, "mandu", "probe-cache"), { recursive: true, mode: 0o700 });
    writeFileSync(join(d, "mandu", "probe-cache", "kernel-probes.json"), "{}", { mode: 0o600 });
    clearProbeCacheFile({ XDG_RUNTIME_DIR: d }, "/home/u");
    assert.equal(existsSync(join(d, "mandu", "probe-cache", "kernel-probes.json")), false);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("clearProbeCacheFile never deletes through a planted probe-cache link, nor out of a dir others can reach (runtime-instances.md §3b)", () => {
  const d = tmp();
  try {
    // A runtime base someone else could control holds `probe-cache` -> a dir
    // of the victim's with a file of that name: the delete must not follow.
    const elsewhere = join(d, "elsewhere");
    mkdirSync(elsewhere, { mode: 0o700 });
    writeFileSync(join(elsewhere, "kernel-probes.json"), "keep");
    mkdirSync(join(d, "mandu"), { mode: 0o700 });
    symlinkSync(elsewhere, join(d, "mandu", "probe-cache"));
    clearProbeCacheFile({ XDG_RUNTIME_DIR: d }, "/home/u");
    assert.equal(readFileSync(join(elsewhere, "kernel-probes.json"), "utf8"), "keep", "the link was followed");
    // A cache dir with group/other bits is not the launch's own either.
    rmSync(join(d, "mandu", "probe-cache"));
    mkdirSync(join(d, "mandu", "probe-cache"));
    chmodSync(join(d, "mandu", "probe-cache"), 0o777);
    writeFileSync(join(d, "mandu", "probe-cache", "kernel-probes.json"), "{}");
    clearProbeCacheFile({ XDG_RUNTIME_DIR: d }, "/home/u");
    assert.equal(existsSync(join(d, "mandu", "probe-cache", "kernel-probes.json")), true);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("mandu setup drops the cache whatever it does next (but not for --print)", async () => {
  const facts: SetupFacts = {
    platform: "linux", systemBwrap: "/usr/bin/bwrap", usernsOk: true, nestingOk: true, apparmorRestricted: false,
    apparmorParser: true, copy: "absent", profileFile: null, legacy: { bwrap: null, unshare: null },
    sameName: { bwrap: [], unshare: [] }, usernsHint: "",
  };
  let cleared = 0;
  const deps: SetupDeps = {
    facts: () => facts, profile: () => ({ path: "/x", text: "# Mandu: profile\n" }), sudo: () => 0,
    confirm: async () => false, isTTY: false, out: () => {}, err: () => {}, clearProbeCache: () => { cleared++; },
  };
  await runSetup(["--print"], deps);
  assert.equal(cleared, 0);
  await runSetup([], deps);
  assert.equal(cleared, 1);
  await runSetup(["--uninstall"], deps);
  assert.equal(cleared, 2);
});

// ── the git sandbox ──────────────────────────────────────────────────────────

test("git sandbox: only the best answer is kept, and a kept one carries no version (the runner asks git itself)", { skip: process.platform !== "linux" ? "Linux only" : false }, () => {
  const d = tmp();
  try {
    const f = join(d, "kernel-probes.json");
    const io = fakeIo();
    const best = bestGitSandbox(() => false, () => "bwrap")!;
    assert.deepEqual(best, { bwrap: "bwrap", flags: GIT_SANDBOX_FLAG_SETS[0] });
    assert.equal(bestGitSandbox((p) => p === MANDU_OWN_BWRAP, () => null)?.bwrap, MANDU_OWN_BWRAP);
    assert.equal(bestGitSandbox(() => false, () => null), null, "no bubblewrap: no best, nothing kept");
    assert.equal(bestGitSandbox(() => false, () => "/usr/bin/bwrap")?.bwrap, "/usr/bin/bwrap", "the distribution's by absolute path");
    const run = (probe: () => ReturnType<typeof bestGitSandbox> | null): { s: ReturnType<typeof launchGitSandbox>; probed: number } => {
      enableProbeCache(ENV, { file: f, io, procEnv: ENV });
      let probed = 0;
      const deps = { probe: () => { probed++; return probe(); }, rootOwned: () => false, systemBwrap: () => "bwrap" };
      const s = launchGitSandbox(deps);
      assert.equal(launchGitSandbox(deps), s, "one answer per launch");
      disableProbeCache();
      return { s, probed };
    };
    // A weaker answer (bubblewrap < 0.8: no --disable-userns) is used, never kept.
    const weaker = { bwrap: "bwrap", flags: GIT_SANDBOX_FLAG_SETS[1]!, gitVersion: "git version 2.43.0\n" };
    assert.deepEqual(run(() => weaker), { s: weaker, probed: 1 });
    assert.deepEqual(run(() => weaker), { s: weaker, probed: 1 });
    // No sandbox: never kept either.
    assert.deepEqual(run(() => null), { s: null, probed: 1 });
    // The best: kept; the next launch gets it with no probe and no version.
    const fresh = { ...best, gitVersion: "git version 2.43.0\n" };
    assert.deepEqual(run(() => fresh), { s: fresh, probed: 1 });
    const kept = run(() => { throw new Error("must not probe"); });
    assert.equal(kept.probed, 0);
    assert.deepEqual(kept.s, best);
    assert.equal(kept.s!.gitVersion, undefined);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

// ── the Landlock wrap a kept pass enables fails closed ───────────────────────

test("landlock: a kept pass on a kernel that cannot confine TCP stops inspect-mcp at the applier (exit 71), never runs it unconfined", () => {
  const d = tmp();
  try {
    // A stand-in applier on a kernel below Landlock ABI 4, with the real
    // one's behaviour: it degrades only under --skip-unsupported, else exit 71.
    const applier = join(d, "mandu-landlock-apply");
    writeFileSync(applier, [
      "#!/bin/sh",
      "skip=0; for a in \"$@\"; do [ \"$a\" = --skip-unsupported ] && skip=1; [ \"$a\" = -- ] && break; done",
      "[ $skip = 1 ] || { echo 'mandu-landlock-apply: TCP-net unavailable' >&2; exit 71; }",
      "while [ $# -gt 0 ] && [ \"$1\" != -- ]; do shift; done; shift; exec \"$@\"",
      "",
    ].join("\n"));
    chmodSync(applier, 0o755);
    const f = join(d, "kernel-probes.json");
    const io = fakeIo({ ids: { [applier]: `${applier}|1|1|1|1|1` } });
    const inputs = (): ProbeInputs => ({ bins: [applier], argv: LANDLOCK_NET_PROBE_ARGV });
    // Poison: a kept pass for this applier.
    enableProbeCache(ENV, { file: f, io, procEnv: ENV });
    assert.equal(cachedProbe("landlock-net", inputs, () => true), true);
    disableProbeCache();
    enableProbeCache(ENV, { file: f, io, procEnv: ENV });
    // The Linux plan (on macOS Landlock does not exist and no wrap is planned);
    // the stand-in applier is a shell script, so it runs on either.
    const r = planInspectNetConfine({ ullmForwarder: { host: "127.0.0.1", port: 41001 } }, { platform: "linux", resolveBin: () => applier, staleNote: () => null, log: () => {} });
    assert.deepEqual(probeCacheHits(), ["landlock-net"], "answered from the cache, no probe");
    assert.ok(r);
    const marker = join(d, "ran");
    const run = spawnSync(r.wrapArgv[0]!, [...r.wrapArgv.slice(1), "sh", "-c", `touch ${marker}`], { encoding: "utf8" });
    assert.equal(run.status, 71, run.stderr);
    assert.equal(existsSync(marker), false, "the wrapped server never ran");
    // Control: the old degrade-capable wrap would have run it unconfined.
    const lax = spawnSync(applier, ["--net-only", "--skip-unsupported", "--", "sh", "-c", `touch ${marker}`]);
    assert.equal(lax.status, 0);
    assert.equal(existsSync(marker), true);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});


test("git sandbox: the Linux launch cache delegates macOS to Seatbelt, with no persisted or negative answer", () => {
  const dir = tmp();
  try {
    const file = join(dir, "kernel-probes.json");
    enableProbeCache(ENV, { file, io: fakeIo(), procEnv: ENV });
    const seatbelt = { kind: "seatbelt" as const, sandboxExec: "/usr/bin/sandbox-exec", git: "/opt/bin/git", profile: "(version 1)", gitVersion: "git version 2.43.0\n" };
    let calls = 0;
    const deps = { platform: "darwin", probe: () => { calls++; return calls === 1 ? null : seatbelt; } };
    assert.equal(launchGitSandbox(deps), null, "a transient miss stays a miss");
    assert.equal(launchGitSandbox(deps), seatbelt, "the next probe can recover");
    assert.equal(calls, 2, "a negative macOS answer is not memoized by the Linux cache");
    assert.equal(existsSync(file), false, "no Linux probe entry is persisted for Seatbelt");
    assert.deepEqual(probeCacheHits(), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a kept probe and setup's deletion use the stack's short runtime fallback, never the oversized TMPDIR candidate", () => {
  const dir = tmp();
  try {
    const longTmp = join(dir, "T".repeat(70));
    mkdirSync(longTmp);
    const env = { ...ENV, TMPDIR: longTmp, MANDU_RUNTIME_FALLBACK_ROOT: dir };
    const fallback = join(dir, `mandu-${UID}`);
    const file = join(fallback, "probe-cache", "kernel-probes.json");
    assert.equal(probeCacheFile(env, "/irrelevant-home"), file, "the cache follows the socket-aware runtime rule");
    enableProbeCache(env, { io: fakeIo(), procEnv: env });
    assert.equal(cachedProbe("userns", () => BWRAP_IN, () => true), true);
    assert.equal(existsSync(file), true, "a positive probe was persisted under the selected fallback");
    assert.equal(statSync(join(fallback, "probe-cache")).mode & 0o777, 0o700);
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.deepEqual(readdirSync(longTmp), [], "the old TMPDIR/mandu candidate was never created");
    disableProbeCache();
    enableProbeCache(env, { io: fakeIo(), procEnv: env });
    assert.equal(cachedProbe("userns", () => BWRAP_IN, () => { throw new Error("the fallback pass should be reused"); }), true);
    clearProbeCacheFile(env);
    assert.equal(existsSync(file), false, "setup clears the very cache the launch read");
    assert.deepEqual(readdirSync(longTmp), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── a probe the launch awaits (cachedProbeAsync: the exec-wrap shim's load probe) ──

const SHIM_IN: ProbeInputs = { bins: ["/usr/bin/env", "bash", "node"], argv: ["curl"], extra: { template: "t1" } };

test("async: a pass is kept and answers the next launch without a probe; a changed key probes again; the bypass probes afresh", async () => {
  const d = tmp();
  try {
    const f = join(d, "kernel-probes.json");
    const io = fakeIo({ ids: { "/usr/bin/env": "env|1", "/usr/bin/bash": "bash|1", "/usr/bin/node": "node|1" }, onPath: { bash: "/usr/bin/bash", node: "/usr/bin/node" } });
    let probed = 0;
    const ask = async (inputs: ProbeInputs = SHIM_IN, env: Record<string, string> = {}): Promise<boolean> => {
      enableProbeCache({ ...ENV, ...env }, { file: f, io, procEnv: ENV, now: () => 1_000_000 });
      try { return await cachedProbeAsync("exec-shim", () => inputs, async () => { probed++; return true; }); }
      finally { disableProbeCache(); }
    };
    assert.equal(await ask(), true);
    assert.equal(probed, 1);
    assert.ok(parseCacheFile(readFileSync(f, "utf8"))!.entries["exec-shim"], "the pass is kept under its own name");
    assert.equal(await ask(), true);
    assert.equal(probed, 1, "kept: the probe does not run");
    const t2 = { ...SHIM_IN, extra: { template: "t2" } };
    assert.equal(await ask(t2), true);
    assert.equal(probed, 2, "a changed input is a new question");
    io.ids["/usr/bin/node"] = "node|2";
    assert.equal(await ask(t2), true);
    assert.equal(probed, 3, "a replaced node is a new question");
    assert.equal(await ask(t2), true);
    assert.equal(probed, 3);
    assert.equal(await ask(t2, { [PROBE_CACHE_ENV]: "0" }), true);
    assert.equal(probed, 4, "MANDU_PROBE_CACHE=0 probes afresh");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("async: a failure (false or a rejection) is never kept, drops a kept pass (bypass too), and the rejection reaches the caller unchanged", async () => {
  const d = tmp();
  try {
    const f = join(d, "kernel-probes.json");
    const io = fakeIo();
    const boom = new Error("the exec-wrap shim cannot load (exit 1)");
    let probed = 0;
    const launchOnce = async (fresh: () => Promise<boolean>, env: Record<string, string> = {}): Promise<boolean | Error> => {
      enableProbeCache({ ...ENV, ...env }, { file: f, io, procEnv: ENV });
      try { return await cachedProbeAsync("exec-shim", () => SHIM_IN, async () => { probed++; return fresh(); }); }
      catch (e) { return e as Error; }
      finally { disableProbeCache(); }
    };
    assert.equal(await launchOnce(async () => { throw boom; }), boom, "the probe's own error, unchanged");
    assert.equal(existsSync(f), false, "nothing written for a failure");
    assert.equal(await launchOnce(async () => { throw boom; }), boom);
    assert.equal(probed, 2, "a failure is asked again on every launch");
    assert.equal(await launchOnce(async () => false), false);
    assert.equal(existsSync(f), false);
    const kept = (): boolean => parseCacheFile(readFileSync(f, "utf8"))!.entries["exec-shim"] !== undefined;
    // A pass is kept; a fresh failure under the bypass (which read nothing)
    // still drops it.
    assert.equal(await launchOnce(async () => true), true);
    assert.equal(kept(), true);
    assert.equal(await launchOnce(async () => { throw boom; }, { [PROBE_CACHE_ENV]: "0" }), boom);
    assert.equal(kept(), false, "the bypass's failed probe dropped the kept pass");
    // A kept pass whose re-probe (a changed key) fails is dropped too.
    assert.equal(await launchOnce(async () => true), true);
    enableProbeCache(ENV, { file: f, io, procEnv: ENV });
    await assert.rejects(cachedProbeAsync("exec-shim", () => ({ ...SHIM_IN, extra: { template: "changed" } }), async () => { throw boom; }), (e) => e === boom);
    disableProbeCache();
    assert.equal(kept(), false, "the failed re-probe dropped the kept pass");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("async: without an enabled cache every call probes; a launch that used a kept shim pass and then failed drops the file", async () => {
  disableProbeCache();
  let probed = 0;
  for (let i = 0; i < 2; i++) assert.equal(await cachedProbeAsync("exec-shim", () => SHIM_IN, async () => { probed++; return true; }), true);
  assert.equal(probed, 2);
  const d = tmp();
  try {
    const f = join(d, "kernel-probes.json");
    enableProbeCache(ENV, { file: f, io: fakeIo(), procEnv: ENV });
    await cachedProbeAsync("exec-shim", () => SHIM_IN, async () => true);
    disableProbeCache();
    enableProbeCache(ENV, { file: f, io: fakeIo(), procEnv: ENV });
    await cachedProbeAsync("exec-shim", () => SHIM_IN, async () => { throw new Error("must not probe"); });
    assert.deepEqual(probeCacheHits(), ["exec-shim"]);
    assert.equal(forgetAfterFailure(), true);
    assert.equal(existsSync(f), false, "the next launch probes afresh");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});
