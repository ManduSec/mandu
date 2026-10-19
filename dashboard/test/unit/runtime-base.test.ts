/**
 * runtime-base.test — the dashboard's mirror of the runtime-base rule and the
 * private /tmp fallback (src/runtime-base.ts; runtime-instances.md §3b).
 * server-main.ts derives RUNTIME_BASE from it and refuses to start on a
 * fallback that is not private. The cross-package parity oracle
 * (tests/integration/test/e2e/runtime-base-parity.test.ts) holds this mirror
 * to the arbiter's answers; this file proves the mirror alone.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, statSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  FALLBACK_ROOT_ENV, INSTANCE_SOCK_SUFFIX_MAX,
  assertPrivateDirIfPresent, assertTrustedIfPresent, defaultRuntimeBaseOf, ensurePrivateDir, ensurePrivateIfFallback,
  fallbackBaseContaining, instanceBaseProblem, instanceSockSuffix, ownedDirProblem, privateDirProblem,
  resolveRuntimeBase, sunPathMaxFor, type DirStat,
  assertRuntimeBaseIfPresent, ensureRuntimeBaseDir, runtimeBaseContaining, runtimeBaseVerdict, sealedFromOthers,
} from "../../src/runtime-base.js";

const DARWIN_T = "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/";
const DARWIN = { platform: "darwin", uid: 501, fallbackRoot: "/tmp" } as const;
const LINUX = { platform: "linux", uid: 1000, fallbackRoot: "/tmp" } as const;

const stat = (o: Partial<{ dir: boolean; link: boolean; uid: number; mode: number }>): DirStat => ({
  isDirectory: () => o.dir ?? true, isSymbolicLink: () => o.link ?? false, uid: o.uid ?? 501, mode: o.mode ?? 0o40700,
});

test("the budget and the sun_path sizes", () => {
  assert.equal(INSTANCE_SOCK_SUFFIX_MAX, 63);
  assert.deepEqual(["darwin", "netbsd", "linux"].map(sunPathMaxFor), [104, 104, 108]);
  assert.equal(instanceBaseProblem("/tmp/mandu-501", "darwin"), null);
  assert.match(String(instanceBaseProblem("/" + "a".repeat(40), "darwin")), /MANDU_RUNTIME_DIR/);
});

test("rule: MANDU_RUNTIME_DIR → XDG_RUNTIME_DIR/mandu → short TMPDIR/mandu-<uid> → /tmp/mandu-<uid>", () => {
  assert.deepEqual(resolveRuntimeBase({ MANDU_RUNTIME_DIR: "/x/" }, DARWIN), { base: "/x", source: "explicit" });
  assert.deepEqual(resolveRuntimeBase({ XDG_RUNTIME_DIR: "/run/user/1000" }, LINUX), { base: "/run/user/1000/mandu", source: "xdg" });
  assert.deepEqual(resolveRuntimeBase({ TMPDIR: "/tmp/" }, LINUX), { base: "/tmp/mandu-1000", source: "tmpdir" });
  assert.deepEqual(resolveRuntimeBase({}, LINUX), { base: "/tmp/mandu-1000", source: "tmpdir" }, "TMPDIR unset → /tmp (only env counts), per-user since 2026-10-09");
  assert.deepEqual(resolveRuntimeBase({ TMPDIR: DARWIN_T }, DARWIN), { base: "/tmp/mandu-501", source: "fallback" });
  assert.equal(resolveRuntimeBase({ TMPDIR: DARWIN_T, [FALLBACK_ROOT_ENV]: "/fb" }, { platform: "darwin", uid: 2 }).base, "/fb/mandu-2");
  assert.equal(resolveRuntimeBase({ TMPDIR: DARWIN_T }, { ...DARWIN, uid: null }).source, "tmpdir");
  const tmpOf = (candBytes: number, plat: { uid: number } = DARWIN): string => "/" + "t".repeat(candBytes - `/mandu-${plat.uid}`.length - 1);
  assert.equal(resolveRuntimeBase({ TMPDIR: tmpOf(40) }, DARWIN).source, "tmpdir");
  assert.equal(resolveRuntimeBase({ TMPDIR: tmpOf(41) }, DARWIN).source, "fallback");
  assert.equal(resolveRuntimeBase({ TMPDIR: tmpOf(44, LINUX) }, LINUX).source, "tmpdir");
  assert.equal(resolveRuntimeBase({ TMPDIR: tmpOf(45, LINUX) }, LINUX).source, "fallback");
  assert.equal(defaultRuntimeBaseOf({ MANDU_RUNTIME_DIR: "/x", XDG_RUNTIME_DIR: "/run/u" }, LINUX).base, "/run/u/mandu");
});

test("private dir: created 0700; shared, symlink and a foreign owner refused; verify-only never creates", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-dash-rt-")));
  try {
    const fb = join(dir, "mandu-1");
    ensurePrivateDir(fb);
    assert.equal(statSync(fb).mode & 0o777, 0o700);
    const shared = join(dir, "shared");
    mkdirSync(shared);
    chmodSync(shared, 0o755);
    assert.throws(() => ensurePrivateDir(shared), /is shared \(mode 0755/);
    symlinkSync(fb, join(dir, "link"));
    assert.throws(() => ensurePrivateDir(join(dir, "link")), /is a symlink/);
    assert.match(String(privateDirProblem(stat({ uid: 9 }), 501)), /owned by uid 9/);
    assert.throws(() => ensurePrivateDir("/tmp/mandu-501", {
      mkdir: () => { throw Object.assign(new Error("EEXIST"), { code: "EEXIST" }); }, lstat: () => stat({ uid: 9 }), uid: 501,
    }), /owned by uid 9/);
    assertPrivateDirIfPresent(join(dir, "absent"));
    assert.equal(existsSync(join(dir, "absent")), false);
    // The fallback, recognized by path in either spelling; anything else untouched.
    const alias = join(dir, "alias");
    symlinkSync(dir, alias);
    assert.equal(fallbackBaseContaining(join(alias, "mandu-3", "dashboards"), {}, { uid: 3, fallbackRoot: alias }), join(alias, "mandu-3"));
    assert.equal(fallbackBaseContaining(join(dir, "mandu-3"), {}, { uid: 3, fallbackRoot: alias }), join(dir, "mandu-3"));
    ensurePrivateIfFallback(join(dir, "mandu-3", "dashboards"), {}, { uid: 3, fallbackRoot: alias });
    assert.equal(statSync(join(dir, "mandu-3")).mode & 0o777, 0o700);
    ensurePrivateIfFallback(join(dir, "else", "x"), {}, { uid: 3, fallbackRoot: alias });
    assert.equal(existsSync(join(dir, "else")), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the real suffix and the relaxed rule for a base in a shared sticky dir (the mirror)", () => {
  assert.equal(instanceSockSuffix("335883df", 7), 55);
  assert.equal(instanceBaseProblem("/" + "a".repeat(45), "linux", 55), null);
  assert.equal(ownedDirProblem(stat({ mode: 0o40755 }), 501), null);
  assert.match(String(ownedDirProblem(stat({ mode: 0o40775 }), 501)), /writable by other accounts/);
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-dash-sticky-")));
  const sticky = join(dir, "tmp");
  mkdirSync(sticky);
  chmodSync(sticky, 0o1777);
  try {
    // The dashboard's own start (server-main.ts main()): RUNTIME_BASE in a
    // sticky dir is created 0700, a group-writable one is refused.
    const base = join(sticky, "mandu");
    const env = { MANDU_RUNTIME_DIR: base };
    ensurePrivateIfFallback(base, env, { platform: "linux" });
    assert.equal(statSync(base).mode & 0o777, 0o700);
    chmodSync(base, 0o775);
    assert.throws(() => ensurePrivateIfFallback(base, env, { platform: "linux" }), /writable by other accounts \(mode 0775/);
    assert.throws(() => assertTrustedIfPresent(join(base, "dashboards"), env, { platform: "linux" }), /writable by other accounts/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
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
