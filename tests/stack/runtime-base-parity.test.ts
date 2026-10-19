/**
 * runtime-base-parity.test — the copies of the runtime-base rule agree
 * (runtime-instances.md §3b, 2026-09-29):
 *   1. arbiter/ipc/runtime-base.ts        (the owner; instance.ts runtimeBase,
 *                                          accountIdentity)
 *   2. launcher/src/runtime-base.ts       (mirror; arbiter-sock.ts runtimeBase,
 *                                          parse.ts scope-dir root,
 *                                          platform/{darwin,linux} runtimeDir,
 *                                          arbiter.ts accountOf)
 *   3. dashboard/src/runtime-base.ts      (mirror; server-main RUNTIME_BASE)
 *
 * Why an oracle instead of one shared module: the packages are standalone
 * (the arbiter-client boundary, CONTRIBUTING.md) — and before this rule the SAME
 * base was spelled five different ways (one ignored MANDU_RUNTIME_DIR, one
 * dropped XDG_RUNTIME_DIR on darwin, two kept a trailing slash). What must never
 * happen is drift: a launcher polling `current` under one base while the
 * arbiter binds under another. Every copy gets the same env × platform × uid ×
 * fallback-root × tmpdir matrix and must return the same base; the byte budget
 * is pinned against the arbiter's own instanceId(). The launcher's autostart
 * preflight sizes the REAL socket (the rev the arbiter will read, the widest
 * pid), so its rev reader is held to the arbiter's gitRevOf, and the
 * shared-sticky-dir rule (a base directly in /tmp must be ours) to one
 * verdict everywhere.
 *
 * Run: npm test  (tests/)
 */

import { test } from "node:test";
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as arbiterRule from "../../arbiter/ipc/runtime-base.js";
import { accountIdentity, gitRevOf, instanceId, instancePaths, runtimeBase as arbiterRuntimeBase } from "../../arbiter/ipc/instance.js";
import { SUN_PATH_MAX } from "../../arbiter/ipc/socket-path.js";
import * as launcherRule from "../../launcher/src/runtime-base.js";
import { runtimeBase as launcherRuntimeBase, resolveArbiterSock } from "../../launcher/src/arbiter-sock.js";
import { accountOf, arbiterRevDir, arbiterRevOf } from "../../launcher/src/arbiter.js";
import { Layout } from "../../launcher/src/services/layout.js";
import { parse } from "../../launcher/src/parse.js";
import { darwinPlatform } from "../../launcher/src/platform/darwin.js";
import { linuxPlatform } from "../../launcher/src/platform/linux.js";
import * as dashboardRule from "../../dashboard/src/runtime-base.js";
import { manduPath } from "../../launcher/src/generated/mandu-paths.js";

type Env = Record<string, string | undefined>;

const DARWIN_T = "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/";
/** The shell copy of the rule (scripts/lib/runtime-base.sh). */
const SHELL_RULE = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "scripts", "lib", "runtime-base.sh");
const ENVS: Array<[string, Env]> = [
  ["explicit", { MANDU_RUNTIME_DIR: "/srv/mandu-rt", XDG_RUNTIME_DIR: "/run/user/1", TMPDIR: DARWIN_T }],
  ["explicit, trailing slash", { MANDU_RUNTIME_DIR: "/srv/mandu-rt/" }],
  ["explicit, over budget", { MANDU_RUNTIME_DIR: "/" + "d".repeat(80) }],
  ["xdg", { XDG_RUNTIME_DIR: "/run/user/1000", TMPDIR: DARWIN_T }],
  ["xdg, trailing slash", { XDG_RUNTIME_DIR: "/run/user/1000/" }],
  ["short TMPDIR", { TMPDIR: "/tmp" }],
  ["short TMPDIR, trailing slash", { TMPDIR: "/tmp/" }],
  ["macOS per-user TMPDIR", { TMPDIR: DARWIN_T }],
  ["TMPDIR of 34 bytes (the old darwin edge)", { TMPDIR: "/" + "t".repeat(33) }],
  ["TMPDIR of 35 bytes", { TMPDIR: "/" + "t".repeat(34) }],
  ["TMPDIR of 38 bytes (the old Linux edge)", { TMPDIR: "/" + "t".repeat(37) }],
  ["TMPDIR of 39 bytes", { TMPDIR: "/" + "t".repeat(38) }],
  ["multi-byte TMPDIR", { TMPDIR: "/" + "é".repeat(17) }],
  ["TMPDIR unset", {}],
  ["the fallback-root hook", { TMPDIR: DARWIN_T, MANDU_RUNTIME_FALLBACK_ROOT: "/scratch/fb/" }],
  ["the hook with a short TMPDIR (unused)", { TMPDIR: "/t", MANDU_RUNTIME_FALLBACK_ROOT: "/scratch/fb" }],
];
const OPTS: arbiterRule.RuntimeBaseOptions[] = [];
for (const platform of ["darwin", "linux", "freebsd"]) {
  for (const uid of [0, 501, 1000, 4294967294, null]) {
    for (const fallbackRoot of [undefined, "/tmp", "/x/root/"]) {
      OPTS.push({ platform, uid, ...(fallbackRoot !== undefined ? { fallbackRoot } : {}) });
    }
  }
}

test("the byte budget is one number everywhere, pinned against the arbiter's instanceId()", () => {
  const longest = instanceId(new Date("2099-12-31T23:59:00Z"), "f".repeat(40), 4_194_304);
  const suffix = Buffer.byteLength(instancePaths("/B", longest).sockPath) - "/B".length;
  assert.equal(arbiterRule.INSTANCE_SOCK_SUFFIX_MAX, suffix);
  assert.equal(launcherRule.INSTANCE_SOCK_SUFFIX_MAX, suffix);
  assert.equal(dashboardRule.INSTANCE_SOCK_SUFFIX_MAX, suffix);
  assert.equal(suffix, 63);
  for (const p of ["darwin", "linux", "freebsd", "openbsd", "netbsd", "win32"]) {
    assert.equal(launcherRule.sunPathMaxFor(p), arbiterRule.sunPathMaxFor(p), p);
    assert.equal(dashboardRule.sunPathMaxFor(p), arbiterRule.sunPathMaxFor(p), p);
  }
  assert.equal(SUN_PATH_MAX, arbiterRule.sunPathMaxFor(process.platform));
});

test("resolveRuntimeBase / defaultRuntimeBaseOf / fallbackBase / instanceBaseProblem: arbiter ≡ launcher ≡ dashboard over the whole matrix", () => {
  let cases = 0;
  for (const [label, env] of ENVS) {
    for (const opts of OPTS) {
      const what = `${label} ${JSON.stringify(opts)}`;
      const want = arbiterRule.resolveRuntimeBase(env, opts);
      assert.deepEqual(launcherRule.resolveRuntimeBase(env, opts), want, `launcher: ${what}`);
      assert.deepEqual(dashboardRule.resolveRuntimeBase(env, opts), want, `dashboard: ${what}`);
      assert.equal(launcherRuntimeBase(env, opts), want.base, `launcher arbiter-sock: ${what}`);
      const def = arbiterRule.defaultRuntimeBaseOf(env, opts);
      assert.deepEqual(launcherRule.defaultRuntimeBaseOf(env, opts), def, `launcher default: ${what}`);
      assert.deepEqual(dashboardRule.defaultRuntimeBaseOf(env, opts), def, `dashboard default: ${what}`);
      assert.equal(launcherRule.fallbackBase(env, opts), arbiterRule.fallbackBase(env, opts), `fallback: ${what}`);
      assert.equal(dashboardRule.fallbackBase(env, opts), arbiterRule.fallbackBase(env, opts), `fallback: ${what}`);
      const platform = opts.platform!;
      const problem = arbiterRule.instanceBaseProblem(want.base, platform);
      assert.equal(launcherRule.instanceBaseProblem(want.base, platform), problem, `preflight: ${what}`);
      assert.equal(dashboardRule.instanceBaseProblem(want.base, platform), problem, `preflight: ${what}`);
      // The rule's own promise: a DEFAULT base (not an explicit one, not an
      // unknown uid) always has room for the longest instance socket.
      if (want.source !== "explicit" && want.source !== "xdg" && opts.uid !== null) {
        assert.equal(problem, null, `a default base must fit: ${what} → ${want.base}`);
      }
      cases++;
    }
  }
  assert.ok(cases > 600, `${cases} cases`);
});

test("with the process defaults (real uid, os.tmpdir): instance.ts ≡ arbiter-sock ≡ platform runtimeDir ≡ parse's scope root", () => {
  for (const [label, env] of ENVS) {
    const e = { MANDU_RUNTIME_FALLBACK_ROOT: "/scratch/fb", ...env }; // never the host's /tmp
    const base = arbiterRuntimeBase(e as NodeJS.ProcessEnv);
    assert.equal(launcherRuntimeBase(e), base, label);
    assert.equal(dashboardRule.resolveRuntimeBase(e).base, base, label);
    // The platform seam and the scope-dir root are the same base (the path
    // table's `runtime-dir` under the rule: MANDU_RUNTIME_DIR moves them too).
    assert.equal(darwinPlatform.runtimeDir(e), base, `darwin ${label}`);
    assert.equal(linuxPlatform.runtimeDir(e), base, `linux ${label}`);
    // Rules 1–2 ARE the path table (on-disk-layout.md §5); rule 3 is the
    // table under TMPDIR, per-user (runtime-instances.md §3b, 2026-10-09).
    const source = arbiterRule.resolveRuntimeBase(e).source;
    const table = manduPath("runtime-dir", e, "/home/u").replace(/(.)\/$/, "$1");
    if (source === "explicit" || source === "xdg") assert.equal(base, table, `path table ${label}`);
    if (source === "tmpdir") assert.equal(base, `${table}-${process.getuid!()}`, `per-user rule 3 ${label}`);
    // The shell copy the VM harnesses use (scripts/lib/runtime-base.sh).
    if (process.platform === "linux" && source !== "fallback") {
      const sh = execFileSync("bash", ["-c", '. "$0"; mandu_runtime_base', SHELL_RULE], { encoding: "utf8", env: { PATH: process.env["PATH"], ...e } as NodeJS.ProcessEnv }).trim();
      assert.equal(sh, base, `shell copy ${label}`);
    }
    // parse() and the resolver READ the base (the trust check, §3b): a base
    // directly in the host's /tmp (TMPDIR=/tmp) is the host's real /tmp/mandu-<uid>,
    // which this suite does not own. When the host's copy is one the rule
    // refuses (another account's, or group-writable from a umask-002 run),
    // the oracle is that both refuse alike, not that they resolve.
    let hostRefusal: string | null = null;
    try { launcherRule.assertTrustedIfPresent(base, e); } catch (err) { hostRefusal = (err as Error).message; }
    if (hostRefusal !== null) {
      assert.equal(arbiterRule.sharedParentBaseContaining(base, e), launcherRule.sharedParentBaseContaining(base, e), label);
      assert.throws(() => parse(["--id", "sid", "--", "claude"], { HOME: "/home/u", PWD: "/w", ...e }), (err: Error) => err.message.endsWith(hostRefusal!));
      assert.throws(() => resolveArbiterSock(e), (err: Error) => err.message.endsWith(hostRefusal!));
      continue;
    }
    const plan = parse(["--id", "sid", "--", "claude"], { HOME: "/home/u", PWD: "/w", ...e });
    assert.equal(plan.eventDir, `${base}/sid/events`, `scope dir ${label}`);
    assert.equal(plan.arbiterRuntimeBase, base, `plan base ${label}`);
    assert.equal(resolveArbiterSock(e).base, base, `resolver base ${label}`);
  }
});

test("the private-dir verdicts agree (arbiter ≡ launcher ≡ dashboard)", () => {
  const stats = [
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 501, mode: 0o40700 },
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 501, mode: 0o40755 },
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 501, mode: 0o40701 },
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 0, mode: 0o40700 },
    { isDirectory: () => true, isSymbolicLink: () => true, uid: 501, mode: 0o120777 },
    { isDirectory: () => false, isSymbolicLink: () => false, uid: 501, mode: 0o100600 },
  ];
  for (const st of stats) {
    for (const uid of [501, 0, null]) {
      const want = arbiterRule.privateDirProblem(st, uid);
      assert.equal(launcherRule.privateDirProblem(st, uid), want);
      assert.equal(dashboardRule.privateDirProblem(st, uid), want);
    }
  }
});

test("the account rendezvous agrees (arbiter accountIdentity ≡ launcher accountOf): Linux /run/user/<uid>/mandu, macOS /tmp/mandu-<uid>", () => {
  for (const platform of ["linux", "darwin"]) {
    for (const t of [DARWIN_T, "/tmp/u"]) {
      const deps = { platform, getuid: () => 501, homedir: () => "/home/u", darwinTempDir: () => t };
      assert.deepEqual(accountOf(deps), accountIdentity(deps), `${platform} ${t}`);
      assert.equal(launcherRule.accountRendezvous(501, deps), arbiterRule.accountRendezvous(501, deps));
    }
  }
  assert.equal(arbiterRule.accountRendezvous(501, { platform: "darwin", darwinTempDir: () => DARWIN_T }), "/tmp/mandu-501");
  assert.equal(arbiterRule.accountRendezvous(501, { platform: "linux" }), "/run/user/501/mandu");
});

test("the REAL suffix the launcher's preflight uses is instanceId()'s, in every copy; its rev reader agrees with the arbiter's gitRevOf", () => {
  const when = new Date("2026-09-29T00:00:00Z");
  for (const rev of ["335883df", "abcdef1", "nogit", "", "x y/z", "f".repeat(40)]) {
    for (const pid of [7, 99_999, 4_194_304]) {
      const want = Buffer.byteLength(instancePaths("/B", instanceId(when, rev, pid)).sockPath) - "/B".length;
      const digits = String(pid).length;
      assert.equal(arbiterRule.instanceSockSuffix(rev, digits), want, `${rev} p${pid}`);
      assert.equal(launcherRule.instanceSockSuffix(rev, digits), want);
      assert.equal(dashboardRule.instanceSockSuffix(rev, digits), want);
    }
  }
  for (const p of ["darwin", "linux", "freebsd"]) {
    assert.equal(launcherRule.maxPidDigitsFor(p), arbiterRule.maxPidDigitsFor(p), p);
    assert.equal(dashboardRule.maxPidDigitsFor(p), arbiterRule.maxPidDigitsFor(p), p);
    for (const bytes of [40, 46, 52, 53, 54, 60]) {
      const base = "/" + "a".repeat(bytes - 1);
      const suffix = arbiterRule.instanceSockSuffix("335883df", arbiterRule.maxPidDigitsFor(p));
      const want = arbiterRule.instanceBaseProblem(base, p, suffix);
      assert.equal(launcherRule.instanceBaseProblem(base, p, suffix), want, `${p} ${bytes}`);
      assert.equal(dashboardRule.instanceBaseProblem(base, p, suffix), want, `${p} ${bytes}`);
    }
  }
  // arbiter/ipc/server-main.ts: REPO_DIR = <arbiter/ipc>/../.. — the launcher's
  // arbiterRevDir for a checkout layout names the same dir, and reads the same rev.
  const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
  const serverMainRepoDir = join(repo, "arbiter", "ipc", "..", "..");
  assert.equal(arbiterRevDir(Layout.dev(serverMainRepoDir)), serverMainRepoDir);
  assert.equal(arbiterRevOf(serverMainRepoDir), gitRevOf(serverMainRepoDir).rev);
  assert.equal(arbiterRevOf("/nonexistent/mandu"), gitRevOf("/nonexistent/mandu").rev, "nogit both");
});

test("the shared-sticky-dir rule agrees (arbiter ≡ launcher ≡ dashboard): which base is guarded, and the relaxed verdicts", () => {
  const stats = [
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 501, mode: 0o40700 },
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 501, mode: 0o40755 },
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 501, mode: 0o40775 },
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 501, mode: 0o40757 },
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 0, mode: 0o40755 },
    { isDirectory: () => true, isSymbolicLink: () => true, uid: 501, mode: 0o120777 },
    { isDirectory: () => false, isSymbolicLink: () => false, uid: 501, mode: 0o100600 },
  ];
  for (const st of stats) {
    for (const uid of [501, 0, null]) {
      const want = arbiterRule.ownedDirProblem(st, uid);
      assert.equal(launcherRule.ownedDirProblem(st, uid), want);
      assert.equal(dashboardRule.ownedDirProblem(st, uid), want);
    }
  }
  let cases = 0;
  for (const [label, env] of ENVS) {
    for (const opts of OPTS.slice(0, 60)) {
      assert.equal(launcherRule.tmpdirCandidate(env, opts), arbiterRule.tmpdirCandidate(env, opts), label);
      assert.equal(dashboardRule.tmpdirCandidate(env, opts), arbiterRule.tmpdirCandidate(env, opts), label);
      assert.equal(launcherRule.legacyTmpdirBase(env), arbiterRule.legacyTmpdirBase(env), label);
      assert.equal(dashboardRule.legacyTmpdirBase(env), arbiterRule.legacyTmpdirBase(env), label);
      const base = arbiterRule.resolveRuntimeBase(env, opts).base;
      for (const sticky of [0o41777, 0o40755]) {
        const deps = { statMode: () => sticky };
        for (const p of [base, `${base}/current/arbiter.sock`, `${base}-x`, "/elsewhere/x"]) {
          const want = arbiterRule.sharedParentBaseContaining(p, env, opts, deps);
          assert.equal(launcherRule.sharedParentBaseContaining(p, env, opts, deps), want, `${label} ${p}`);
          assert.equal(dashboardRule.sharedParentBaseContaining(p, env, opts, deps), want, `${label} ${p}`);
          if (sticky === 0o40755) assert.equal(want, null, "not shared and sticky: never guarded");
          cases++;
        }
      }
    }
  }
  assert.ok(cases > 1000, `${cases} cases`);
});

test("any other base (2026-10-17) agrees (arbiter ≡ launcher ≡ dashboard): which base a path is under, whether it is sealed, and the verdict", () => {
  const stats = [
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 501, mode: 0o40700 },
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 501, mode: 0o40755 },
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 501, mode: 0o40775 },
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 501, mode: 0o40757 },
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 0, mode: 0o40700 },
    { isDirectory: () => true, isSymbolicLink: () => true, uid: 501, mode: 0o120777 },
    { isDirectory: () => false, isSymbolicLink: () => false, uid: 501, mode: 0o100600 },
  ];
  for (const st of stats) {
    for (const uid of [501, 0, null]) {
      for (const sealed of [true, false]) {
        const want = arbiterRule.runtimeBaseVerdict(st, uid, sealed);
        assert.deepEqual(launcherRule.runtimeBaseVerdict(st, uid, sealed), want);
        assert.deepEqual(dashboardRule.runtimeBaseVerdict(st, uid, sealed), want);
      }
    }
  }
  const ancestors: Array<Record<string, { uid: number; mode: number }>> = [
    { "/run/user/501": { uid: 501, mode: 0o40700 } },
    { "/run/user/501": { uid: 502, mode: 0o40700 } },
    { "/run/user/501": { uid: 501, mode: 0o40750 } },
    {},
  ];
  for (const tree of ancestors) {
    const deps = { uid: 501, statDir: (p: string) => tree[p] ?? { uid: 0, mode: 0o40755 } };
    for (const dir of ["/run/user/501/mandu", "/run/user/501/a/mandu", "/srv/mandu"]) {
      const want = arbiterRule.sealedFromOthers(dir, deps);
      assert.equal(launcherRule.sealedFromOthers(dir, deps), want, dir);
      assert.equal(dashboardRule.sealedFromOthers(dir, deps), want, dir);
    }
  }
  let cases = 0;
  for (const [label, env] of ENVS) {
    for (const opts of OPTS.slice(0, 60)) {
      const base = arbiterRule.resolveRuntimeBase(env, opts).base;
      for (const p of [base, `${base}/current/arbiter.sock`, `${base}-x`, "/elsewhere/x"]) {
        const want = arbiterRule.runtimeBaseContaining(p, env, opts);
        assert.equal(launcherRule.runtimeBaseContaining(p, env, opts), want, `${label} ${p}`);
        assert.equal(dashboardRule.runtimeBaseContaining(p, env, opts), want, `${label} ${p}`);
        cases++;
      }
    }
  }
  assert.ok(cases > 500, `${cases} cases`);
});
