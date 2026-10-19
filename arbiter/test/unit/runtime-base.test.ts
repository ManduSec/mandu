/**
 * runtime-base.test — the runtime-base rule and the private /tmp fallback
 * (ipc/runtime-base.ts; docs/design/architecture/runtime-instances.md §3b).
 *
 * Every branch of the rule with the platform, uid, fallback root and tmpdir
 * injected (so darwin is pinned on a Linux runner and vice versa), the
 * INSTANCE_SOCK_SUFFIX_MAX pin against instanceId(), the private-dir checks
 * (created 0700; a symlink, a foreign owner, a 0755 dir, a file refused) and
 * the account rendezvous on darwin. The launcher and dashboard mirrors are held
 * to the same answers by tests/stack/runtime-base-parity.test.ts.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { instanceId, instancePaths } from "../../ipc/instance.js";
import {
  DEFAULT_FALLBACK_ROOT,
  FALLBACK_ROOT_ENV,
  INSTANCE_SOCK_SUFFIX_MAX,
  accountRendezvous,
  assertPrivateDirIfPresent,
  assertTrustedIfPresent,
  darwinUserTempDir,
  defaultRuntimeBaseOf,
  ensurePrivateDir,
  ensurePrivateIfFallback,
  fallbackBase,
  fallbackBaseContaining,
  instanceBaseProblem,
  instanceSockSuffix,
  isSharedStickyMode,
  maxPidDigitsFor,
  ownedDirProblem,
  privateDirProblem,
  resolveRuntimeBase,
  sharedParentBaseContaining,
  sunPathMaxFor,
  tmpdirCandidate,
  legacyTmpdirBase,
  assertRuntimeBaseIfPresent,
  ensureRuntimeBaseDir,
  runtimeBaseContaining,
  runtimeBaseVerdict,
  sealedFromOthers,
  type DirStat,
} from "../../ipc/runtime-base.js";

/** The macOS per-user TMPDIR shape (49 bytes with its trailing slash). */
const DARWIN_T = "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/";
const DARWIN = { platform: "darwin", uid: 501, fallbackRoot: "/tmp" } as const;
const LINUX = { platform: "linux", uid: 1000, fallbackRoot: "/tmp" } as const;

function scratch(): { dir: string; cleanup: () => void } {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-rtbase-")));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function stat(o: Partial<{ dir: boolean; link: boolean; uid: number; mode: number }>): DirStat {
  return {
    isDirectory: () => o.dir ?? true,
    isSymbolicLink: () => o.link ?? false,
    uid: o.uid ?? 501,
    mode: o.mode ?? 0o40700,
  };
}

// ── the suffix pin ──────────────────────────────────────────────────────────

test("INSTANCE_SOCK_SUFFIX_MAX is exactly what the longest instanceId() adds: /instances/<id>/arbiter.sock = 63", () => {
  // Longest id: a 16+-char rev (sliced to 16) and a 7-digit pid (Linux pid_max 4194304).
  const id = instanceId(new Date("2026-12-31T23:59:00Z"), "0123456789abcdef-and-more", 4_194_304);
  assert.equal(id.length, 39, id);
  const suffix = instancePaths("/B", id).sockPath.slice("/B".length);
  assert.equal(Buffer.byteLength(suffix), INSTANCE_SOCK_SUFFIX_MAX);
  assert.equal(INSTANCE_SOCK_SUFFIX_MAX, 63);
});

test("instanceSockSuffix is exactly what instanceId() adds for a given rev and pid width (the autostart preflight's REAL suffix)", () => {
  const when = new Date("2026-09-29T12:34:00Z");
  for (const rev of ["335883df", "1234567", "nogit", "", "a/b c", "f".repeat(40)]) {
    for (const pid of [1, 99_999, 4_194_304]) {
      const sock = instancePaths("/B", instanceId(when, rev, pid)).sockPath;
      assert.equal(Buffer.byteLength(sock) - "/B".length, instanceSockSuffix(rev, String(pid).length), `${rev} p${pid}`);
    }
  }
  assert.equal(maxPidDigitsFor("darwin"), String(99_999).length, "darwin PID_MAX 99999");
  assert.equal(maxPidDigitsFor("linux"), String(4_194_304).length, "Linux pid_max ceiling");
  assert.equal(instanceSockSuffix("f".repeat(40), 7), INSTANCE_SOCK_SUFFIX_MAX);
  // The preflight's budget with that suffix: a 46-byte Linux base fits an 8-char rev.
  assert.equal(instanceBaseProblem("/" + "a".repeat(45), "linux", instanceSockSuffix("335883df", 7)), null);
  assert.notEqual(instanceBaseProblem("/" + "a".repeat(52), "linux", instanceSockSuffix("335883df", 7)), null);
});

test("sunPathMaxFor: 104 on darwin and the BSDs, 108 elsewhere", () => {
  assert.equal(sunPathMaxFor("darwin"), 104);
  assert.equal(sunPathMaxFor("freebsd"), 104);
  assert.equal(sunPathMaxFor("openbsd"), 104);
  assert.equal(sunPathMaxFor("linux"), 108);
});

// ── the rule ────────────────────────────────────────────────────────────────

test("rule 1: MANDU_RUNTIME_DIR verbatim, one trailing slash stripped, wins over everything", () => {
  const env = { MANDU_RUNTIME_DIR: "/x/base/", XDG_RUNTIME_DIR: "/run/u", TMPDIR: DARWIN_T };
  assert.deepEqual(resolveRuntimeBase(env, DARWIN), { base: "/x/base", source: "explicit" });
  assert.deepEqual(resolveRuntimeBase({ MANDU_RUNTIME_DIR: "/" }, DARWIN), { base: "/", source: "explicit" });
  // Even an over-long explicit dir is honoured as given (the preflight refuses it).
  const long = "/" + "d".repeat(90);
  assert.equal(resolveRuntimeBase({ MANDU_RUNTIME_DIR: long }, DARWIN).base, long);
});

test("rule 2: XDG_RUNTIME_DIR/mandu, unchanged on Linux (and honoured on darwin too)", () => {
  assert.deepEqual(resolveRuntimeBase({ XDG_RUNTIME_DIR: "/run/user/1000" }, LINUX), { base: "/run/user/1000/mandu", source: "xdg" });
  assert.deepEqual(resolveRuntimeBase({ XDG_RUNTIME_DIR: "/run/user/1000/", TMPDIR: "/t" }, LINUX), { base: "/run/user/1000/mandu", source: "xdg" });
  assert.deepEqual(resolveRuntimeBase({ XDG_RUNTIME_DIR: "/run/u" }, DARWIN), { base: "/run/u/mandu", source: "xdg" });
});

test("rule 3: a short TMPDIR gives the PER-USER TMPDIR/mandu-<uid> on both platforms (2026-10-09)", () => {
  assert.deepEqual(resolveRuntimeBase({ TMPDIR: "/tmp/" }, LINUX), { base: "/tmp/mandu-1000", source: "tmpdir" });
  assert.deepEqual(resolveRuntimeBase({ TMPDIR: "/t" }, DARWIN), { base: "/t/mandu-501", source: "tmpdir" });
  // TMPDIR unset or empty → /tmp: only env counts (the path table's
  // `runtime-dir`, on-disk-layout.md §5), never the process's os.tmpdir().
  // Never the shared /tmp/mandu another account could make first.
  assert.deepEqual(resolveRuntimeBase({}, LINUX), { base: "/tmp/mandu-1000", source: "tmpdir" });
  assert.deepEqual(resolveRuntimeBase({ TMPDIR: "" }, LINUX), { base: "/tmp/mandu-1000", source: "tmpdir" });
  assert.notEqual(resolveRuntimeBase({}, { ...LINUX, uid: 1001 }).base, resolveRuntimeBase({}, LINUX).base, "two accounts, two bases");
  // An unknown uid keeps the shared name (no per-user name is possible).
  assert.deepEqual(resolveRuntimeBase({}, { ...LINUX, uid: null }), { base: "/tmp/mandu", source: "tmpdir" });
});

test("rule 3/4 boundary: cand + 63 must be < sun_path (darwin 104 → cand ≤ 40 bytes; Linux 108 → cand ≤ 44)", () => {
  // cand = TMPDIR + "/mandu-<uid>" (11 bytes for uid 1000, 10 for 501).
  const tmpOf = (candBytes: number, plat: { uid: number } = DARWIN): string => "/" + "t".repeat(candBytes - `/mandu-${plat.uid}`.length - 1);
  assert.equal(resolveRuntimeBase({ TMPDIR: tmpOf(40) }, DARWIN).source, "tmpdir");
  assert.equal(resolveRuntimeBase({ TMPDIR: tmpOf(41) }, DARWIN).source, "fallback");
  assert.equal(resolveRuntimeBase({ TMPDIR: tmpOf(44, LINUX) }, LINUX).source, "tmpdir");
  assert.equal(resolveRuntimeBase({ TMPDIR: tmpOf(45, LINUX) }, LINUX).source, "fallback");
  // Byte length, not characters.
  assert.equal(resolveRuntimeBase({ TMPDIR: "/" + "é".repeat(15) }, DARWIN).source, "fallback", "26 characters, 41 bytes");
});

test("rule 4: the macOS per-user TMPDIR falls back to /tmp/mandu-<uid>", () => {
  assert.deepEqual(resolveRuntimeBase({ TMPDIR: DARWIN_T }, DARWIN), { base: "/tmp/mandu-501", source: "fallback" });
  // The fallback root: the test hook in env, or opts (opts win).
  assert.equal(resolveRuntimeBase({ TMPDIR: DARWIN_T, [FALLBACK_ROOT_ENV]: "/scratch/" }, { platform: "darwin", uid: 7 }).base, "/scratch/mandu-7");
  assert.equal(resolveRuntimeBase({ TMPDIR: DARWIN_T, [FALLBACK_ROOT_ENV]: "/scratch" }, DARWIN).base, "/tmp/mandu-501");
  assert.equal(DEFAULT_FALLBACK_ROOT, "/tmp");
  // No uid (no getuid): no fallback is possible; the candidate stands.
  assert.deepEqual(resolveRuntimeBase({ TMPDIR: DARWIN_T }, { ...DARWIN, uid: null }), {
    base: "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/mandu", source: "tmpdir",
  });
});

test("defaultRuntimeBaseOf ignores MANDU_RUNTIME_DIR (the scope-dir root rule)", () => {
  assert.deepEqual(defaultRuntimeBaseOf({ MANDU_RUNTIME_DIR: "/x", TMPDIR: DARWIN_T }, DARWIN), { base: "/tmp/mandu-501", source: "fallback" });
  assert.equal(fallbackBase({}, { uid: 3, fallbackRoot: "/" }), "/mandu-3");
  assert.equal(fallbackBase({}, { uid: null }), null);
});

test("instanceBaseProblem: null when any instance socket fits; else names the budget and MANDU_RUNTIME_DIR", () => {
  assert.equal(instanceBaseProblem("/tmp/mandu-501", "darwin"), null);
  assert.equal(instanceBaseProblem("/" + "a".repeat(39), "darwin"), null, "40 + 63 = 103 < 104");
  const p = instanceBaseProblem("/" + "a".repeat(40), "darwin");
  assert.match(String(p), /is 41 bytes: .*can reach 104 bytes, over the 103-byte limit/);
  assert.match(String(p), /MANDU_RUNTIME_DIR at a directory of at most 40 bytes/);
  assert.equal(instanceBaseProblem("/" + "a".repeat(43), "linux"), null);
  assert.notEqual(instanceBaseProblem("/" + "a".repeat(44), "linux"), null);
});

// ── the private fallback ────────────────────────────────────────────────────

test("privateDirProblem: symlink, non-directory, foreign owner and group/other bits are each refused", () => {
  assert.equal(privateDirProblem(stat({}), 501), null);
  assert.equal(privateDirProblem(stat({ link: true }), 501), "is a symlink");
  assert.equal(privateDirProblem(stat({ dir: false }), 501), "is not a directory");
  assert.match(String(privateDirProblem(stat({ uid: 502 }), 501)), /owned by uid 502, not by you \(uid 501\)/);
  assert.match(String(privateDirProblem(stat({ mode: 0o40755 }), 501)), /shared \(mode 0755/);
  assert.match(String(privateDirProblem(stat({ mode: 0o40710 }), 501)), /shared \(mode 0710/);
  assert.equal(privateDirProblem(stat({ uid: 0 }), null), null, "an unknown uid skips only the owner check");
});

test("ensurePrivateDir: an absent dir is CREATED 0700 (whatever the umask), then passes", () => {
  const { dir, cleanup } = scratch();
  const old = process.umask(0o100); // would make mkdir 0600: the chmod pins 0700
  try {
    const fb = join(dir, "mandu-1");
    ensurePrivateDir(fb);
    assert.equal(statSync(fb).mode & 0o777, 0o700);
    ensurePrivateDir(fb); // idempotent on our own private dir
  } finally {
    process.umask(old);
    cleanup();
  }
});

test("ensurePrivateDir: a pre-existing 0755 dir, a symlink and a file are REFUSED with the fix named", () => {
  const { dir, cleanup } = scratch();
  try {
    const shared = join(dir, "shared");
    mkdirSync(shared);
    chmodSync(shared, 0o755);
    assert.throws(() => ensurePrivateDir(shared), (e: Error) =>
      /runtime dir .*shared is shared \(mode 0755/.test(e.message) && /rm -rf/.test(e.message) && /MANDU_RUNTIME_DIR/.test(e.message));
    assert.equal(statSync(shared).mode & 0o777, 0o755, "never chmod-repaired");

    const real = join(dir, "real");
    mkdirSync(real, { mode: 0o700 });
    const link = join(dir, "link");
    symlinkSync(real, link);
    assert.throws(() => ensurePrivateDir(link), /is a symlink/);

    const file = join(dir, "file");
    writeFileSync(file, "");
    assert.throws(() => ensurePrivateDir(file), /is not a directory/);

    assert.throws(() => ensurePrivateDir(join(dir, "no", "parent")), /could not be created/, "non-recursive: a missing parent is reported");
  } finally {
    cleanup();
  }
});

test("ensurePrivateDir: a dir owned by ANOTHER uid is refused (simulated through the injected lstat)", () => {
  assert.throws(
    () => ensurePrivateDir("/tmp/mandu-501", {
      mkdir: () => { throw Object.assign(new Error("EEXIST"), { code: "EEXIST" }); },
      lstat: () => stat({ uid: 666, mode: 0o40700 }),
      uid: 501,
    }),
    /owned by uid 666, not by you \(uid 501\)/,
  );
});

test("assertPrivateDirIfPresent: absent passes (nothing to trust yet), private passes, shared refuses; never creates", () => {
  const { dir, cleanup } = scratch();
  try {
    const fb = join(dir, "mandu-1");
    assertPrivateDirIfPresent(fb);
    assert.equal(existsSync(fb), false);
    mkdirSync(fb, { mode: 0o700 });
    chmodSync(fb, 0o700);
    assertPrivateDirIfPresent(fb);
    chmodSync(fb, 0o775);
    assert.throws(() => assertPrivateDirIfPresent(fb), /is shared \(mode 0775/);
  } finally {
    cleanup();
  }
});

test("fallbackBaseContaining: the base and paths under it, in both spellings (a symlinked root); nothing else", () => {
  const { dir, cleanup } = scratch();
  try {
    const realRoot = join(dir, "real");
    mkdirSync(realRoot);
    const linkRoot = join(dir, "alias"); // the macOS /tmp → /private/tmp shape
    symlinkSync(realRoot, linkRoot);
    const opts = { uid: 42, fallbackRoot: linkRoot };
    assert.equal(fallbackBaseContaining(join(linkRoot, "mandu-42"), {}, opts), join(linkRoot, "mandu-42"));
    assert.equal(fallbackBaseContaining(join(linkRoot, "mandu-42", "current", "arbiter.sock"), {}, opts), join(linkRoot, "mandu-42"));
    assert.equal(fallbackBaseContaining(join(realRoot, "mandu-42", "123-4"), {}, opts), join(realRoot, "mandu-42"), "canonical spelling");
    assert.equal(fallbackBaseContaining(join(linkRoot, "mandu-420"), {}, opts), null, "a sibling is not inside");
    assert.equal(fallbackBaseContaining(join(dir, "elsewhere", "mandu"), {}, opts), null);
    assert.equal(fallbackBaseContaining("/x", {}, { uid: null }), null);
  } finally {
    cleanup();
  }
});

test("ensurePrivateIfFallback: creates the fallback for a path under it; a non-fallback path is left alone (no mkdir)", () => {
  const { dir, cleanup } = scratch();
  try {
    const env = { [FALLBACK_ROOT_ENV]: dir };
    const uid = process.getuid?.() ?? 0;
    ensurePrivateIfFallback(join(dir, `mandu-${uid}`, "instances", "x", "arbiter.sock"), env);
    assert.equal(statSync(join(dir, `mandu-${uid}`)).mode & 0o777, 0o700);
    ensurePrivateIfFallback(join(dir, "other", "mandu"), env);
    assert.equal(existsSync(join(dir, "other")), false);
  } finally {
    cleanup();
  }
});

// ── the account rendezvous (§13) ────────────────────────────────────────────

test("accountRendezvous: Linux /run/user/<uid>/mandu (unchanged); darwin the default base of DARWIN_USER_TEMP_DIR", () => {
  assert.equal(accountRendezvous(1000, { platform: "linux" }), "/run/user/1000/mandu");
  assert.equal(accountRendezvous(501, { platform: "darwin", darwinTempDir: () => DARWIN_T }), "/tmp/mandu-501");
  // A short per-user temp dir would keep <T>/mandu — the same rule, not a special case.
  assert.equal(accountRendezvous(501, { platform: "darwin", darwinTempDir: () => "/tmp/u" }), "/tmp/u/mandu-501");
});

test("accountRendezvous never reads the fallback-root test hook or this process's TMPDIR", () => {
  const saved = { hook: process.env[FALLBACK_ROOT_ENV], tmp: process.env.TMPDIR };
  process.env[FALLBACK_ROOT_ENV] = "/scratch";
  process.env.TMPDIR = "/t";
  try {
    assert.equal(accountRendezvous(501, { platform: "darwin", darwinTempDir: () => DARWIN_T }), "/tmp/mandu-501");
  } finally {
    if (saved.hook === undefined) delete process.env[FALLBACK_ROOT_ENV]; else process.env[FALLBACK_ROOT_ENV] = saved.hook;
    if (saved.tmp === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = saved.tmp;
  }
});

test("darwinUserTempDir: on macOS it is the per-user T/ dir from getconf, cached", { skip: process.platform !== "darwin" && "macOS only" }, () => {
  const t = darwinUserTempDir();
  assert.match(t, /\/T\/?$/, t);
  assert.equal(darwinUserTempDir(), t, "cached");
});

// ── a base directly in a shared sticky dir (runtime-instances.md §3b) ───────

test("tmpdirCandidate is rule 3's per-user candidate, fitting or not; legacyTmpdirBase the shared name before 2026-10-09", () => {
  assert.equal(tmpdirCandidate({ TMPDIR: "/tmp/" }, { uid: 7 }), "/tmp/mandu-7");
  assert.equal(tmpdirCandidate({ TMPDIR: DARWIN_T }, { uid: 501 }), "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/mandu-501");
  assert.equal(tmpdirCandidate({}, { uid: 7 }), "/tmp/mandu-7");
  assert.equal(tmpdirCandidate({}, { uid: null }), "/tmp/mandu");
  assert.equal(legacyTmpdirBase({}), "/tmp/mandu");
  assert.equal(legacyTmpdirBase({ TMPDIR: "/var/tmp/" }), "/var/tmp/mandu");
});

test("ownedDirProblem: the RELAXED rule — ours, a real directory, no group/other WRITE (0755 passes, 0775/0757 refuse)", () => {
  assert.equal(ownedDirProblem(stat({ mode: 0o40755 }), 501), null);
  assert.equal(ownedDirProblem(stat({ mode: 0o40700 }), 501), null);
  assert.match(String(ownedDirProblem(stat({ mode: 0o40775 }), 501)), /writable by other accounts \(mode 0775/);
  assert.match(String(ownedDirProblem(stat({ mode: 0o40757 }), 501)), /writable by other accounts \(mode 0757/);
  assert.match(String(ownedDirProblem(stat({ uid: 7 }), 501)), /owned by uid 7/);
  assert.equal(ownedDirProblem(stat({ link: true }), 501), "is a symlink");
  assert.equal(ownedDirProblem(stat({ dir: false }), 501), "is not a directory");
  assert.equal(isSharedStickyMode(0o41777), true);
  assert.equal(isSharedStickyMode(0o40777), false);
  assert.equal(isSharedStickyMode(0o41775), false);
});

test("ensurePrivateIfFallback: a base whose parent is a shared sticky dir is created 0700, kept at 0755, refused when writable by others or foreign", () => {
  const { dir, cleanup } = scratch();
  const sticky = join(dir, "tmp");
  mkdirSync(sticky);
  chmodSync(sticky, 0o1777); // stands in for /tmp
  try {
    const base = join(sticky, "mandu");
    const env = { MANDU_RUNTIME_DIR: base };
    assert.equal(sharedParentBaseContaining(join(base, "instances"), env, LINUX), base);
    ensurePrivateIfFallback(base, env, LINUX);
    assert.equal(statSync(base).mode & 0o777, 0o700);
    chmodSync(base, 0o755);
    ensurePrivateIfFallback(base, env, LINUX);
    assertTrustedIfPresent(base, env, LINUX);
    chmodSync(base, 0o777);
    assert.throws(() => ensurePrivateIfFallback(base, env, LINUX), /writable by other accounts \(mode 0777/);
    assert.throws(() => assertTrustedIfPresent(base, env, LINUX), /writable by other accounts/);
    chmodSync(base, 0o755);
    assert.throws(() => ensurePrivateIfFallback(base, env, LINUX, {
      mkdir: () => { throw Object.assign(new Error("EEXIST"), { code: "EEXIST" }); },
      lstat: () => stat({ uid: 666, mode: 0o40755 }),
      uid: 501,
    }), /owned by uid 666, not by you \(uid 501\)/);
    // A base in a dir that is NOT shared and sticky: untouched, as before.
    chmodSync(sticky, 0o755);
    chmodSync(base, 0o777);
    assert.doesNotThrow(() => ensurePrivateIfFallback(base, env, LINUX));
  } finally {
    cleanup();
  }
});

test("any other base ($XDG_RUNTIME_DIR/mandu, an explicit one; 2026-10-17): created 0700 under a 002 umask; a sealed 0775 one tightened; an open 0775 one refused, an open 0755 one kept", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-rtbase-"))); // 0700, ours: the /run/user/<uid> stand-in
  try {
    const xdg = join(dir, "run");
    mkdirSync(xdg, { mode: 0o700 });
    const env = { XDG_RUNTIME_DIR: xdg };
    const base = join(xdg, "mandu");
    const old = process.umask(0o002);
    try {
      ensurePrivateIfFallback(join(base, "current", "arbiter.sock"), env, LINUX);
    } finally {
      process.umask(old);
    }
    assert.equal(statSync(base).mode & 0o777, 0o700, "created 0700, never the umask's 0775");
    assert.equal(existsSync(join(base, "current")), false, "only the base is made");
    chmodSync(base, 0o775);
    assertTrustedIfPresent(base, env, LINUX); // a reader passes a sealed one and never chmods
    assert.equal(statSync(base).mode & 0o777, 0o775);
    ensurePrivateIfFallback(base, env, LINUX);
    assert.equal(statSync(base).mode & 0o777, 0o700, "tightened: only this uid could have set the bits or reached in");
    // Reachable by others (simulated ancestors): the relaxed rule decides.
    const open = { statDir: () => ({ uid: process.getuid?.() ?? 0, mode: 0o40755 }) };
    chmodSync(base, 0o775);
    assert.throws(() => ensureRuntimeBaseDir(base, open), /is writable by other accounts \(mode 0775/);
    assert.throws(() => assertRuntimeBaseIfPresent(base, open), /writable by other accounts/);
    assert.equal(statSync(base).mode & 0o777, 0o775, "never chmod-repaired");
    chmodSync(base, 0o755);
    assert.doesNotThrow(() => ensureRuntimeBaseDir(base, open));
    assert.equal(runtimeBaseVerdict(stat({ uid: 4242 }), 501, true).kind, "refuse", "another uid's base");
    assert.equal(sealedFromOthers(base), true);
    assert.equal(runtimeBaseContaining(join(dir, "elsewhere"), env, LINUX), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
