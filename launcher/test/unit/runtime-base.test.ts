/**
 * runtime-base.test — the launcher's mirror of the runtime-base rule and the
 * private /tmp fallback (src/runtime-base.ts; runtime-instances.md §3b).
 *
 * Every branch with platform / uid / fallback root / tmpdir injected, the
 * private-dir checks, and the account rendezvous on darwin. The cross-package
 * parity oracle (tests/integration/test/e2e/runtime-base-parity.test.ts) holds
 * this mirror to the arbiter's answers; this file proves the mirror alone.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, statSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  FALLBACK_ROOT_ENV, INSTANCE_ID_MAX, INSTANCE_SOCK_SUFFIX_MAX,
  accountRendezvous, assertOwnedDirIfPresent, assertPrivateDirIfPresent, assertTrustedIfPresent, defaultRuntimeBaseOf,
  ensureOwnedDir, ensurePrivateDir, ensurePrivateIfFallback, fallbackBaseContaining, instanceBaseProblem,
  instanceSockSuffix, isSharedStickyMode, maxPidDigitsFor, ownedDirProblem, privateDirProblem, resolveRuntimeBase,
  sharedParentBaseContaining, sunPathMaxFor, tmpdirCandidate, legacyTmpdirBase, type DirStat,
  assertRuntimeBaseIfPresent, ensureRuntimeBaseDir, runtimeBaseContaining, runtimeBaseVerdict, sealedFromOthers,
} from "../../src/runtime-base.js";

const DARWIN_T = "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/";
const DARWIN = { platform: "darwin", uid: 501, fallbackRoot: "/tmp" } as const;
const LINUX = { platform: "linux", uid: 1000, fallbackRoot: "/tmp" } as const;

function scratch(): { dir: string; cleanup: () => void } {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-rtbase-")));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const stat = (o: Partial<{ dir: boolean; link: boolean; uid: number; mode: number }>): DirStat => ({
  isDirectory: () => o.dir ?? true, isSymbolicLink: () => o.link ?? false, uid: o.uid ?? 501, mode: o.mode ?? 0o40700,
});

test("the budget: 63 bytes for /instances/<longest id>/arbiter.sock; sun_path 104 on darwin/BSD, 108 elsewhere", () => {
  assert.equal(INSTANCE_ID_MAX, "20261231-2359".length + "-".length + 16 + "-p".length + "4194304".length);
  assert.equal(INSTANCE_SOCK_SUFFIX_MAX, 63);
  assert.deepEqual(["darwin", "freebsd", "linux"].map(sunPathMaxFor), [104, 104, 108]);
});

test("rule: MANDU_RUNTIME_DIR → XDG_RUNTIME_DIR/mandu → short TMPDIR/mandu-<uid> → /tmp/mandu-<uid>", () => {
  assert.deepEqual(resolveRuntimeBase({ MANDU_RUNTIME_DIR: "/x/base/", XDG_RUNTIME_DIR: "/run/u" }, DARWIN), { base: "/x/base", source: "explicit" });
  assert.deepEqual(resolveRuntimeBase({ XDG_RUNTIME_DIR: "/run/u/", TMPDIR: DARWIN_T }, LINUX), { base: "/run/u/mandu", source: "xdg" });
  assert.deepEqual(resolveRuntimeBase({ TMPDIR: "/t/" }, LINUX), { base: "/t/mandu-1000", source: "tmpdir" });
  assert.deepEqual(resolveRuntimeBase({}, LINUX), { base: "/tmp/mandu-1000", source: "tmpdir" }, "TMPDIR unset → /tmp (only env counts), per-user since 2026-10-09");
  assert.deepEqual(resolveRuntimeBase({}, { ...LINUX, uid: null }), { base: "/tmp/mandu", source: "tmpdir" }, "no uid: the shared name");
  assert.deepEqual(resolveRuntimeBase({ TMPDIR: DARWIN_T }, DARWIN), { base: "/tmp/mandu-501", source: "fallback" });
  assert.equal(resolveRuntimeBase({ TMPDIR: DARWIN_T, [FALLBACK_ROOT_ENV]: "/fb/" }, { platform: "darwin", uid: 9 }).base, "/fb/mandu-9", "the test hook");
  assert.equal(resolveRuntimeBase({ TMPDIR: DARWIN_T }, { ...DARWIN, uid: null }).source, "tmpdir", "no uid: no fallback");
  assert.deepEqual(defaultRuntimeBaseOf({ MANDU_RUNTIME_DIR: "/x", TMPDIR: DARWIN_T }, DARWIN), { base: "/tmp/mandu-501", source: "fallback" });
});

test("rule: the TMPDIR boundary is cand + 63 < sun_path, in bytes", () => {
  // cand = TMPDIR + "/mandu-<uid>".
  const tmpOf = (candBytes: number, plat: { uid: number } = DARWIN): string => "/" + "t".repeat(candBytes - `/mandu-${plat.uid}`.length - 1);
  assert.equal(resolveRuntimeBase({ TMPDIR: tmpOf(40) }, DARWIN).source, "tmpdir");
  assert.equal(resolveRuntimeBase({ TMPDIR: tmpOf(41) }, DARWIN).source, "fallback");
  assert.equal(resolveRuntimeBase({ TMPDIR: tmpOf(44, LINUX) }, LINUX).source, "tmpdir");
  assert.equal(resolveRuntimeBase({ TMPDIR: tmpOf(45, LINUX) }, LINUX).source, "fallback");
  assert.equal(resolveRuntimeBase({ TMPDIR: "/" + "é".repeat(15) }, DARWIN).source, "fallback", "41 bytes");
});

test("instanceBaseProblem names the budget and MANDU_RUNTIME_DIR; the fallback always fits", () => {
  assert.equal(instanceBaseProblem("/tmp/mandu-4294967294", "darwin"), null);
  assert.match(String(instanceBaseProblem("/" + "a".repeat(40), "darwin")), /41 bytes.*104 bytes.*103-byte limit.*MANDU_RUNTIME_DIR/);
  assert.equal(instanceBaseProblem("/" + "a".repeat(43), "linux"), null);
});

test("private dir: created 0700; 0755, symlink, file and a foreign owner refused", () => {
  const { dir, cleanup } = scratch();
  try {
    const fb = join(dir, "mandu-1");
    ensurePrivateDir(fb);
    assert.equal(statSync(fb).mode & 0o777, 0o700);
    const shared = join(dir, "shared");
    mkdirSync(shared);
    chmodSync(shared, 0o755);
    assert.throws(() => ensurePrivateDir(shared), /is shared \(mode 0755/);
    const link = join(dir, "link");
    symlinkSync(fb, link);
    assert.throws(() => ensurePrivateDir(link), /is a symlink/);
    assert.throws(() => ensurePrivateDir("/tmp/mandu-501", {
      mkdir: () => { throw Object.assign(new Error("EEXIST"), { code: "EEXIST" }); },
      lstat: () => stat({ uid: 0 }), uid: 501,
    }), /owned by uid 0, not by you \(uid 501\)/);
    assert.equal(privateDirProblem(stat({ mode: 0o40701 }), 501)?.startsWith("is shared"), true);
    // Verify-only: absent passes and is NOT created.
    assertPrivateDirIfPresent(join(dir, "absent"));
    assert.equal(existsSync(join(dir, "absent")), false);
    assert.throws(() => assertPrivateDirIfPresent(shared), /is shared/);
  } finally {
    cleanup();
  }
});

test("fallbackBaseContaining / ensurePrivateIfFallback: both spellings of the fallback; nothing else is touched", () => {
  const { dir, cleanup } = scratch();
  try {
    const real = join(dir, "real");
    mkdirSync(real);
    const alias = join(dir, "alias");
    symlinkSync(real, alias);
    const opts = { uid: 7, fallbackRoot: alias };
    assert.equal(fallbackBaseContaining(join(alias, "mandu-7", "current", "arbiter.sock"), {}, opts), join(alias, "mandu-7"));
    assert.equal(fallbackBaseContaining(join(real, "mandu-7"), {}, opts), join(real, "mandu-7"));
    assert.equal(fallbackBaseContaining(join(alias, "mandu-70"), {}, opts), null);
    ensurePrivateIfFallback(join(real, "mandu-7", "123-4", "events"), {}, opts);
    assert.equal(statSync(join(real, "mandu-7")).mode & 0o777, 0o700);
    assert.equal(existsSync(join(real, "mandu-7", "123-4")), false, "only the base is made; the caller mkdirs the rest");
    ensurePrivateIfFallback(join(dir, "other", "x"), {}, opts);
    assert.equal(existsSync(join(dir, "other")), false);
  } finally {
    cleanup();
  }
});

test("accountRendezvous: Linux /run/user/<uid>/mandu; darwin /tmp/mandu-<uid> from DARWIN_USER_TEMP_DIR", () => {
  assert.equal(accountRendezvous(1000, { platform: "linux" }), "/run/user/1000/mandu");
  assert.equal(accountRendezvous(501, { platform: "darwin", darwinTempDir: () => DARWIN_T }), "/tmp/mandu-501");
});

// ── the real suffix (the autostart preflight, finding linux-2) ──────────────

test("instanceSockSuffix: the REAL bytes an instance socket adds (rev as instanceId() spells it, the platform's widest pid)", () => {
  assert.equal(maxPidDigitsFor("darwin"), 5);
  assert.equal(maxPidDigitsFor("linux"), 7);
  // /instances/ (11) + yyyymmdd-hhmm (13) + - + rev + -p + pid + /arbiter.sock (13)
  assert.equal(instanceSockSuffix("335883df", 7), 11 + 13 + 1 + 8 + 2 + 7 + 13);
  assert.equal(instanceSockSuffix("nogit", 5), 50);
  assert.equal(instanceSockSuffix("", 7), instanceSockSuffix("nogit", 7), "nothing left → nogit");
  assert.equal(instanceSockSuffix("a/b c", 7), instanceSockSuffix("abc", 7), "sanitised like instanceId()");
  assert.equal(instanceSockSuffix("f".repeat(40), 7), INSTANCE_SOCK_SUFFIX_MAX, "the worst case is the 16-char slice");
});

test("instanceBaseProblem with the real suffix: a 46-byte Linux base fits an 8-char rev (it used to be refused); the advice keeps the safe budget", () => {
  const base46 = "/home/firstname.lastname/.local/state/mandu-rt";
  assert.equal(Buffer.byteLength(base46), 46);
  const real = instanceSockSuffix("335883df", maxPidDigitsFor("linux")); // 55
  assert.notEqual(instanceBaseProblem(base46, "linux"), null, "the worst case (63) does not fit");
  assert.equal(instanceBaseProblem(base46, "linux", real), null, "101 bytes < 108: the arbiter binds it");
  const base52 = "/" + "a".repeat(51);
  assert.equal(instanceBaseProblem(base52, "linux", real), null, "52 + 55 = 107 < 108");
  const base53 = "/" + "a".repeat(52);
  const p = instanceBaseProblem(base53, "linux", real);
  assert.match(String(p), /is 53 bytes: .*can reach 108 bytes, over the 107-byte limit/);
  assert.match(String(p), /at most 44 bytes/, "the advice is the worst-case budget: a dir that size always fits");
});

test("tmpdirCandidate: rule 3's per-user candidate whether or not it fits; legacyTmpdirBase the shared name before 2026-10-09", () => {
  assert.equal(tmpdirCandidate({ TMPDIR: DARWIN_T }, { uid: 501 }), "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/mandu-501");
  assert.equal(tmpdirCandidate({ TMPDIR: "/" }, { uid: 7 }), "/mandu-7");
  assert.equal(tmpdirCandidate({}, { uid: 7 }), "/tmp/mandu-7");
  assert.equal(tmpdirCandidate({}, { uid: null }), "/tmp/mandu");
  assert.equal(legacyTmpdirBase({}), "/tmp/mandu");
});

test("a squatted /tmp/mandu (another account's, made first) no longer decides anything: the default base is this account's own name (runtime-instances.md §3b)", () => {
  for (const uid of [1000, 1001]) {
    const r = resolveRuntimeBase({}, { platform: "linux", uid, fallbackRoot: "/tmp" });
    assert.equal(r.base, `/tmp/mandu-${uid}`);
    assert.notEqual(r.base, "/tmp/mandu");
  }
  // The per-user base in /tmp is the fallback's own name, so it gets the
  // STRICT private check: created 0700, else ours with no group/other bits.
  const foreign = { lstat: () => ({ isDirectory: () => true, isSymbolicLink: () => false, uid: 1001, mode: 0o40700 }), uid: 1000, mkdir: () => { const e = new Error("exists") as NodeJS.ErrnoException; e.code = "EEXIST"; throw e; }, chmod: () => {} };
  assert.throws(() => ensurePrivateIfFallback("/tmp/mandu-1000/current/arbiter.sock", {}, LINUX, foreign), /owned by uid 1001/, "a squatter of the PER-USER name is still refused");
});

// ── a base directly in a shared sticky dir (finding linux-4) ────────────────

test("ownedDirProblem: our dir with no group/other WRITE passes (0700, 0755); a write bit, a foreign owner, a symlink, a file refuse", () => {
  assert.equal(ownedDirProblem(stat({ mode: 0o40700 }), 501), null);
  assert.equal(ownedDirProblem(stat({ mode: 0o40755 }), 501), null, "the umask-made dir of an earlier arbiter");
  assert.match(String(ownedDirProblem(stat({ mode: 0o40775 }), 501)), /writable by other accounts \(mode 0775/);
  assert.match(String(ownedDirProblem(stat({ mode: 0o40757 }), 501)), /writable by other accounts \(mode 0757/);
  assert.match(String(ownedDirProblem(stat({ uid: 0 }), 501)), /owned by uid 0, not by you \(uid 501\)/);
  assert.equal(ownedDirProblem(stat({ link: true }), 501), "is a symlink");
  assert.equal(ownedDirProblem(stat({ dir: false }), 501), "is not a directory");
  assert.equal(isSharedStickyMode(0o41777), true);
  assert.equal(isSharedStickyMode(0o40777), false, "world-writable without the sticky bit is not this case");
  assert.equal(isSharedStickyMode(0o41755), false);
});

/** A scratch dir standing in for /tmp: world-writable with the sticky bit. */
function stickyScratch(): { dir: string; cleanup: () => void } {
  const s = scratch();
  const sticky = join(s.dir, "tmp");
  mkdirSync(sticky);
  chmodSync(sticky, 0o1777);
  return { dir: sticky, cleanup: s.cleanup };
}

test("sharedParentBaseContaining: the resolved or default base, when its parent is sticky and world-writable; nothing else", () => {
  const { dir, cleanup } = stickyScratch();
  try {
    // Scratch paths are long, so the base comes from rule 1 or rule 2 here
    // (rule 3 would move a long TMPDIR to the fallback); the check keys on the
    // parent's mode, not on where the base came from.
    const base = join(dir, "mandu");
    const explicit = { MANDU_RUNTIME_DIR: base };
    assert.equal(sharedParentBaseContaining(join(base, "current", "arbiter.sock"), explicit, LINUX), base, "the resolved base");
    assert.equal(sharedParentBaseContaining(base, explicit, LINUX), base);
    const xdg = { MANDU_RUNTIME_DIR: "/elsewhere/rt", XDG_RUNTIME_DIR: dir };
    assert.equal(sharedParentBaseContaining(join(base, "123-4", "events"), xdg, LINUX), base, "the DEFAULT base (the scope-dir root)");
    assert.equal(sharedParentBaseContaining(join(dir, "other"), explicit, LINUX), null, "a path outside every base");
    assert.equal(sharedParentBaseContaining(join(dir, "mandu-x"), explicit, LINUX), null, "a sibling is not inside");
    assert.equal(sharedParentBaseContaining(dir, { MANDU_RUNTIME_DIR: dir }, LINUX), null, "the sticky dir itself is not the base's parent");
    // A parent without the sticky bit: not this rule.
    chmodSync(dir, 0o777);
    assert.equal(sharedParentBaseContaining(base, explicit, LINUX), null);
    // The parent's mode is injectable: rule 3's /tmp/mandu-<uid> (Linux
    // without XDG_RUNTIME_DIR) under the host's /tmp, simulated.
    assert.equal(sharedParentBaseContaining("/tmp/mandu-1000/x", {}, LINUX, { statMode: () => 0o41777 }), "/tmp/mandu-1000");
    assert.equal(sharedParentBaseContaining("/tmp/mandu/x", {}, LINUX, { statMode: () => 0o41777 }), null, "the shared name is no base any more");
    assert.equal(sharedParentBaseContaining("/run/user/1/mandu", { XDG_RUNTIME_DIR: "/run/user/1" }, LINUX, { statMode: () => 0o40700 }), null);
  } finally {
    chmodSync(dir, 0o755);
    cleanup();
  }
});

test("ensurePrivateIfFallback on a base in a shared sticky dir: created 0700; our 0755 passes; group-writable, foreign or a symlink refuse", () => {
  const { dir, cleanup } = stickyScratch();
  try {
    const base = join(dir, "mandu");
    const env = { MANDU_RUNTIME_DIR: base };
    ensurePrivateIfFallback(join(base, "current", "arbiter.sock"), env, LINUX);
    assert.equal(statSync(base).mode & 0o777, 0o700, "created, and only the base");
    assert.equal(existsSync(join(base, "current")), false);
    chmodSync(base, 0o755);
    assert.doesNotThrow(() => ensurePrivateIfFallback(base, env, LINUX), "a self-made 0755 dir passes");
    assert.doesNotThrow(() => assertTrustedIfPresent(base, env, LINUX));
    chmodSync(base, 0o775);
    assert.throws(() => ensurePrivateIfFallback(base, env, LINUX), (e: Error) =>
      /runtime dir .*mandu is writable by other accounts \(mode 0775/.test(e.message) && /rm -rf/.test(e.message) && /MANDU_RUNTIME_DIR/.test(e.message));
    assert.throws(() => assertTrustedIfPresent(join(base, "x"), env, LINUX), /writable by other accounts/);
    assert.equal(statSync(base).mode & 0o777, 0o775, "never chmod-repaired");
    chmodSync(base, 0o755);
    const theirs = { lstat: () => stat({ uid: 4242, mode: 0o40755 }), uid: 501 };
    assert.throws(() => ensurePrivateIfFallback(base, env, LINUX, theirs), /owned by uid 4242, not by you \(uid 501\)/);
    assert.throws(() => assertTrustedIfPresent(base, env, LINUX, theirs), /owned by uid 4242/);
    rmSync(base, { recursive: true });
    const real = join(dir, "elsewhere");
    mkdirSync(real, { mode: 0o700 });
    symlinkSync(real, base);
    assert.throws(() => ensurePrivateIfFallback(base, env, LINUX), /is a symlink/);
    // Verify-only never creates.
    rmSync(base);
    assertTrustedIfPresent(base, env, LINUX);
    assert.equal(existsSync(base), false);
    assertOwnedDirIfPresent(base);
    ensureOwnedDir(base);
    assert.equal(statSync(base).mode & 0o777, 0o700);
  } finally {
    cleanup();
  }
});

test("the fallback keeps the STRICT rule even inside a sticky dir: 0755 is refused there", () => {
  const { dir, cleanup } = stickyScratch();
  try {
    const opts = { platform: "darwin", uid: process.getuid?.() ?? 0, fallbackRoot: dir };
    const fb = join(dir, `mandu-${opts.uid}`);
    mkdirSync(fb);
    chmodSync(fb, 0o755);
    assert.throws(() => ensurePrivateIfFallback(fb, { TMPDIR: DARWIN_T }, opts), /is shared \(mode 0755/);
    assert.throws(() => assertTrustedIfPresent(fb, { TMPDIR: DARWIN_T }, opts), /is shared/);
  } finally {
    cleanup();
  }
});

// ── any other base: made 0700, tightened when sealed (2026-10-17) ───────────

const ME = process.getuid?.() ?? 0;

/** Run `fn` under umask `mask`, restored after. */
function withUmask<T>(mask: number, fn: () => T): T {
  const old = process.umask(mask);
  try {
    return fn();
  } finally {
    process.umask(old);
  }
}

test("path resolution never gives the shared /tmp/mandu on Linux with a known uid, whatever the env (runtime-instances.md §3b)", () => {
  const envs = [
    {}, { TMPDIR: "" }, { TMPDIR: "/tmp" }, { TMPDIR: "/tmp/" }, { TMPDIR: "/t".repeat(40) },
    { XDG_RUNTIME_DIR: "" }, { XDG_RUNTIME_DIR: "/run/user/1007" }, { MANDU_RUNTIME_DIR: "" },
  ];
  for (const env of envs) {
    for (const uid of [0, 1000, 1003, 1007]) {
      const opts = { platform: "linux", uid, fallbackRoot: "/tmp" };
      for (const base of [resolveRuntimeBase(env, opts).base, defaultRuntimeBaseOf(env, opts).base]) {
        assert.notEqual(base, "/tmp/mandu", `${JSON.stringify(env)} uid ${uid}`);
        assert.ok(base === "/run/user/1007/mandu" || base.endsWith(`/mandu-${uid}`), `${JSON.stringify(env)} uid ${uid}: ${base} is per-user`);
      }
    }
  }
});

test("runtimeBaseVerdict: ours and private ok; group/other bits tightened when sealed, else the relaxed rule; a symlink, a file, a foreign owner refused", () => {
  assert.deepEqual(runtimeBaseVerdict(stat({ mode: 0o40700 }), 501, false), { kind: "ok" });
  assert.deepEqual(runtimeBaseVerdict(stat({ mode: 0o40775 }), 501, true), { kind: "tighten" });
  assert.deepEqual(runtimeBaseVerdict(stat({ mode: 0o40755 }), 501, true), { kind: "tighten" });
  assert.deepEqual(runtimeBaseVerdict(stat({ mode: 0o40755 }), 501, false), { kind: "ok" }, "readable by others, writable by none: the relaxed rule passes it");
  const v = runtimeBaseVerdict(stat({ mode: 0o40775 }), 501, false);
  assert.equal(v.kind, "refuse");
  assert.match((v as { problem: string }).problem, /writable by other accounts \(mode 0775/);
  assert.equal(runtimeBaseVerdict(stat({ mode: 0o40757 }), 501, false).kind, "refuse");
  assert.deepEqual(runtimeBaseVerdict(stat({ link: true, mode: 0o120777 }), 501, true), { kind: "refuse", problem: "is a symlink" });
  assert.deepEqual(runtimeBaseVerdict(stat({ dir: false, mode: 0o100600 }), 501, true), { kind: "refuse", problem: "is not a directory" });
  assert.equal(runtimeBaseVerdict(stat({ uid: 4242, mode: 0o40700 }), 501, true).kind, "refuse", "another uid's dir, even private and sealed");
});

test("sealedFromOthers: an ancestor of ours or root's with no group/other search seals; none (or an unreadable one) does not", () => {
  const tree: Record<string, { uid: number; mode: number }> = {
    "/": { uid: 0, mode: 0o40755 },
    "/run": { uid: 0, mode: 0o40755 },
    "/run/user": { uid: 0, mode: 0o40755 },
    "/run/user/501": { uid: 501, mode: 0o40700 }, // logind's
    "/run/user/502": { uid: 502, mode: 0o40700 }, // another account's: it could have set anything
    "/tmp": { uid: 0, mode: 0o41777 },
    "/tmp/open": { uid: 501, mode: 0o40755 },
    "/tmp/grp": { uid: 501, mode: 0o40750 },
    "/sealed-by-root": { uid: 0, mode: 0o40700 },
  };
  const statDir = (p: string): { uid: number; mode: number } => {
    const st = tree[p];
    if (!st) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    return st;
  };
  const deps = { uid: 501, statDir };
  assert.equal(sealedFromOthers("/run/user/501/mandu", deps), true);
  assert.equal(sealedFromOthers("/run/user/501/a/b/mandu", { uid: 501, statDir: (p: string) => tree[p] ?? { uid: 501, mode: 0o40775 } }), true, "a higher ancestor seals");
  assert.equal(sealedFromOthers("/run/user/502/mandu", deps), false, "another uid's 0700 dir does not seal it for us");
  assert.equal(sealedFromOthers("/tmp/open/mandu", deps), false, "0755 → /tmp → /: everyone can reach it");
  assert.equal(sealedFromOthers("/tmp/grp/mandu", deps), false, "group search is enough to reach it");
  assert.equal(sealedFromOthers("/sealed-by-root/mandu", deps), true, "root's own sealed dir");
  assert.equal(sealedFromOthers("/nowhere/mandu", deps), false, "an ancestor that cannot be read: fail closed");
  // The real filesystem: a mkdtemp dir (0700, ours) seals what is inside it.
  const { dir, cleanup } = scratch();
  try {
    assert.equal(sealedFromOthers(join(dir, "mandu")), true);
  } finally {
    cleanup();
  }
});

test("ensureRuntimeBaseDir under a 002 umask: an absent base (and its missing ancestors) is created 0700, never 0775", () => {
  const { dir, cleanup } = scratch();
  try {
    const base = join(dir, "run", "user", "mandu");
    withUmask(0o002, () => ensureRuntimeBaseDir(base));
    assert.equal(statSync(base).mode & 0o777, 0o700, "the base");
    assert.equal(statSync(join(dir, "run")).mode & 0o777, 0o700, "an ancestor it made");
    withUmask(0o002, () => ensureRuntimeBaseDir(base)); // idempotent on our own private dir
    assert.equal(statSync(base).mode & 0o777, 0o700);
  } finally {
    cleanup();
  }
});

test("ensureRuntimeBaseDir on an EXISTING base: our 0775 one in a sealed parent is tightened to 0700; the reader passes it untouched", () => {
  const { dir, cleanup } = scratch(); // mkdtemp: 0700, ours — the /run/user/<uid> stand-in
  try {
    const base = join(dir, "mandu");
    mkdirSync(base);
    chmodSync(base, 0o775);
    assert.doesNotThrow(() => assertRuntimeBaseIfPresent(base), "sealed: nobody else could have reached in");
    assert.equal(statSync(base).mode & 0o777, 0o775, "the verify-only form does not chmod");
    ensureRuntimeBaseDir(base);
    assert.equal(statSync(base).mode & 0o777, 0o700, "tightened");
  } finally {
    cleanup();
  }
});

test("ensureRuntimeBaseDir on an EXISTING base others can reach: 0775 refused and never chmod-repaired; 0755 passes; a symlink and a foreign owner refused", () => {
  const { dir, cleanup } = scratch();
  try {
    const base = join(dir, "mandu");
    mkdirSync(base);
    // The parent reachable by everyone (simulated: the real scratch is sealed).
    const open = { statDir: () => ({ uid: ME, mode: 0o40755 }) };
    chmodSync(base, 0o775);
    assert.throws(() => ensureRuntimeBaseDir(base, open), (e: Error) =>
      /runtime dir .*mandu is writable by other accounts \(mode 0775/.test(e.message) && /MANDU_RUNTIME_DIR/.test(e.message));
    assert.throws(() => assertRuntimeBaseIfPresent(base, open), /writable by other accounts/);
    assert.equal(statSync(base).mode & 0o777, 0o775, "never chmod-repaired: a link may already be planted");
    chmodSync(base, 0o755);
    assert.doesNotThrow(() => ensureRuntimeBaseDir(base, open));
    assert.equal(statSync(base).mode & 0o777, 0o755);
    const theirs = { ...open, lstat: () => stat({ uid: 4242, mode: 0o40700 }), uid: 501 };
    assert.throws(() => ensureRuntimeBaseDir(base, theirs), /owned by uid 4242, not by you \(uid 501\)/);
    assert.throws(() => assertRuntimeBaseIfPresent(base, theirs), /owned by uid 4242/);
    rmSync(base, { recursive: true });
    const real = join(dir, "elsewhere");
    mkdirSync(real, { mode: 0o700 });
    symlinkSync(real, base);
    assert.throws(() => ensureRuntimeBaseDir(base), /is a symlink/);
    assert.throws(() => assertRuntimeBaseIfPresent(base), /is a symlink/);
    rmSync(base);
    assertRuntimeBaseIfPresent(base); // absent: passes, creates nothing
    assert.equal(existsSync(base), false);
  } finally {
    cleanup();
  }
});

test("ensurePrivateIfFallback / assertTrustedIfPresent on $XDG_RUNTIME_DIR/mandu: created 0700 under a 002 umask, a sealed 0775 one tightened; a path under no base untouched", () => {
  const { dir, cleanup } = scratch();
  try {
    const xdg = join(dir, "run");
    mkdirSync(xdg, { mode: 0o700 });
    const env = { XDG_RUNTIME_DIR: xdg };
    const base = join(xdg, "mandu");
    assert.equal(runtimeBaseContaining(join(base, "current", "arbiter.sock"), env, LINUX), base);
    assert.equal(runtimeBaseContaining(join(xdg, "mandu-x"), env, LINUX), null);
    assertTrustedIfPresent(join(base, "current", "arbiter.sock"), env, LINUX);
    assert.equal(existsSync(base), false, "the reader never creates");
    withUmask(0o002, () => ensurePrivateIfFallback(join(base, "current", "arbiter.sock"), env, LINUX));
    assert.equal(statSync(base).mode & 0o777, 0o700, "created 0700, and only the base");
    assert.equal(existsSync(join(base, "current")), false);
    chmodSync(base, 0o775);
    assertTrustedIfPresent(base, env, LINUX);
    ensurePrivateIfFallback(join(base, "instances"), env, LINUX);
    assert.equal(statSync(base).mode & 0o777, 0o700, "tightened");
    ensurePrivateIfFallback(join(dir, "other", "x"), env, LINUX);
    assert.equal(existsSync(join(dir, "other")), false, "a path under no base is left alone");
    // An explicit MANDU_RUNTIME_DIR takes the same rule.
    const explicit = join(dir, "rt");
    ensurePrivateIfFallback(explicit, { MANDU_RUNTIME_DIR: explicit, XDG_RUNTIME_DIR: xdg }, LINUX);
    assert.equal(statSync(explicit).mode & 0o777, 0o700);
  } finally {
    cleanup();
  }
});
