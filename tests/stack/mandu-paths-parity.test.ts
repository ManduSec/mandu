/**
 * mandu-paths-parity.test — every package's generated copy of the path table
 * (scripts/paths/mandu-paths.mjs, on-disk-layout.md §5) resolves exactly like
 * the table, and the hand-written owners of the paths agree with it.
 *
 * scripts/test/mandu-paths.test.mjs proves each copy is the text the table
 * generates; this file proves that text BEHAVES like the table's reference
 * resolver (the TS template and the reference are two implementations), and
 * cross-checks the live owners (the arbiter's event dir, runtime base,
 * policy file, symbol DB, pack dirs, view-state base and install prefix; the
 * dashboard's CI dir and test-tenant defaults; the launcher's
 * config; fs-sync's state base) on the one home (phase 3c). The dashboard's switched resolvers (watch,
 * matrix, test history, config, docker home, bin dir) are checked on every
 * fixture too. The Rust copy carries its own generated
 * cases (`cargo test -p mandu-paths`).
 *
 * Phase 4 retired the per-path overrides (on-disk-layout.md §5, §9.1): only
 * MANDU_HOME moves the home. Every copy and every owner is checked under an
 * env that sets each retired variable, and must resolve exactly as if none
 * were set.
 *
 * Run: npm test  (integration)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { homedir } from "node:os";
import { posix } from "node:path";

import {
  BASES, FIXTURES, PATHS, resolvePath,
} from "../../scripts/paths/mandu-paths.mjs";
import * as arbiterCopy from "../../arbiter/src/generated/mandu-paths.js";
import * as launcherCopy from "../../launcher/src/generated/mandu-paths.js";
import * as dashboardCopy from "../../dashboard/src/generated/mandu-paths.js";
import * as fsSyncCopy from "../../fs-sync/src/generated/mandu-paths.js";
import * as evalCopy from "../../eval/lib/generated/mandu-paths.js";

import { getEventDir } from "../../arbiter/events/event-store.js";
import { runtimeBase } from "../../arbiter/ipc/instance.js";
import { defaultPolicyFilePath } from "../../arbiter/policy/policy-file-validate.js";
import { getSymbolDbPath } from "../../arbiter/symbol-table/symbol-table.js";
import { defaultPackDirs } from "../../arbiter/policy/consumer-packs.js";
import {
  defaultInstallPrefix,
  defaultStateBase as arbiterDefaultStateBase,
} from "../../arbiter/policy/secret-discovery.js";
import { defaultEventDir } from "../../dashboard/src/event-dir.js";
import { testTenantPaths } from "../../dashboard/src/supervisor/supervisor-defs.js";
import { resolveConfigPath as dashboardConfigPath } from "../../dashboard/src/config-axes.js";
import { configPath } from "../../launcher/src/config.js";
import { runtimeBase as launcherRuntimeBase } from "../../launcher/src/arbiter-sock.js";
import { accountRendezvous } from "../../launcher/src/arbiter.js";
import { policyFilePath as launcherPolicyFilePath } from "../../launcher/src/policy-level-spelling.js";
import { ownFiles as launcherOwnFiles } from "../../launcher/src/write-protect.js";
import { ownStoresHidden } from "../../launcher/src/secret-setup.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { MANDU_HOME_DIR_NAME, defaultStateBase } from "../../fs-sync/src/layout.js";
import { ALWAYS_DENIED_DIRS, humanEditClockIgnores } from "../../fs-sync/src/ignored.js";

const COPIES = { arbiter: arbiterCopy, launcher: launcherCopy, dashboard: dashboardCopy, "fs-sync": fsSyncCopy, eval: evalCopy };

test("every TS copy resolves every entry like the table, on every fixture", () => {
  for (const [pkg, copy] of Object.entries(COPIES)) {
    assert.deepEqual(Object.keys(copy.MANDU_PATHS), PATHS.map((e) => e.name), `${pkg}: the same entries, in order`);
    assert.deepEqual(Object.keys(copy.MANDU_BASES), Object.keys(BASES), `${pkg}: the same bases`);
    for (const e of PATHS) {
      const { note: _note, ...meta } = e;
      assert.deepEqual({ ...copy.MANDU_PATHS[e.name as launcherCopy.ManduPathName] }, meta, `${pkg}: ${e.name} metadata`);
    }
    for (const [label, env, home] of FIXTURES) {
      for (const e of PATHS) {
        assert.equal(
          copy.manduPath(e.name as launcherCopy.ManduPathName, env, home),
          resolvePath(e.name, env, home),
          `${pkg} / ${label} / ${e.name}`,
        );
      }
    }
  }
});

/** The per-path overrides phase 4 retired (on-disk-layout.md §5, §9.1). */
const RETIRED = [
  "MANDU_CONFIG", "MANDU_SECRETS", "MANDU_SYMBOL_DB", "MANDU_VIEW_STATE", "MANDU_EVENT_DIR",
  "MANDU_CI_RUNS_DIR", "MANDU_MATRIX_RESULTS_DIR", "MANDU_DOCKER_HOME", "MANDU_CI_CACHE",
];
const RETIRED_SET: NodeJS.ProcessEnv = Object.fromEntries(RETIRED.map((k) => [k, `/o/${k.toLowerCase()}`]));

/** `env` with every retired variable removed: what it must resolve like. */
function withoutRetired(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out = { ...env };
  for (const k of RETIRED) delete out[k];
  return out;
}

/** Env shapes for the owners; each keeps HOME set, as a login does. */
const OWNER_ENVS: Array<[string, NodeJS.ProcessEnv]> = [
  ["HOME only", { HOME: "/home/alice", TMPDIR: "/tmp" }],
  ["XDG roots", { HOME: "/home/alice", XDG_STATE_HOME: "/x/state", XDG_CONFIG_HOME: "/x/config", XDG_RUNTIME_DIR: "/run/user/1" }],
  ["empty XDG", { HOME: "/home/alice", XDG_STATE_HOME: "", XDG_CONFIG_HOME: "", XDG_RUNTIME_DIR: "", TMPDIR: "/var/tmp" }],
  ["MANDU_HOME and the kept overrides", { HOME: "/h", MANDU_HOME: "/m", MANDU_RUNTIME_DIR: "/o/rt", MANDU_PREFIX: "/o/prefix" }],
  ["retired overrides move nothing", { HOME: "/h", ...RETIRED_SET }],
  ["retired overrides beside MANDU_HOME", { HOME: "/h", MANDU_HOME: "/m", ...RETIRED_SET }],
];

test("a retired per-path override moves nothing in any copy", () => {
  for (const e of PATHS) assert.ok(!RETIRED.includes(e.env ?? ""), `table: ${e.name} still names ${e.env}`);
  for (const [pkg, copy] of Object.entries(COPIES)) {
    for (const base of [{}, { MANDU_HOME: "/m" }] as NodeJS.ProcessEnv[]) {
      for (const e of PATHS) {
        const name = e.name as launcherCopy.ManduPathName;
        assert.equal(copy.MANDU_PATHS[name].env, e.env, `${pkg}: ${e.name} env`);
        assert.equal(copy.manduPath(name, { ...base, ...RETIRED_SET }, "/home/u"), copy.manduPath(name, base, "/home/u"), `${pkg}: ${e.name}`);
      }
    }
  }
  for (const e of PATHS) {
    assert.equal(resolvePath(e.name, RETIRED_SET, "/home/u"), resolvePath(e.name, {}, "/home/u"), `table: ${e.name}`);
  }
});

/** The runtime base: the table's `runtime-dir` for rules 1-2, and under
 *  TMPDIR per-user since 2026-10-09 (rule 3, runtime-instances.md §3b; every
 *  owner env here has a short TMPDIR or none). */
function runtimeRule(env: NodeJS.ProcessEnv): string {
  const table = launcherCopy.manduPath("runtime-dir", env, env.HOME!).replace(/(.)\/$/, "$1");
  return env.MANDU_RUNTIME_DIR || env.XDG_RUNTIME_DIR ? table : `${table}-${process.getuid!()}`;
}

test("the hand-written owners of the paths agree with the table", () => {
  const at = (name: launcherCopy.ManduPathName, env: NodeJS.ProcessEnv): string => launcherCopy.manduPath(name, env, env.HOME!);
  for (const [label, env] of OWNER_ENVS) {
    assert.equal(getEventDir(env), at("events", env), `${label}: arbiter getEventDir`);
    assert.equal(defaultEventDir(env), at("events", env), `${label}: dashboard defaultEventDir`);
    assert.equal(runtimeBase(env), runtimeRule(env), `${label}: arbiter runtimeBase`);
    assert.equal(configPath(env), at("config-toml", env), `${label}: launcher configPath`);
    assert.equal(defaultPolicyFilePath(env), at("policy", env), `${label}: arbiter defaultPolicyFilePath`);
    assert.equal(getSymbolDbPath(env, env.HOME!), at("symbol-db", env), `${label}: arbiter getSymbolDbPath`);
    assert.deepEqual(
      defaultPackDirs(env, env.HOME!),
      { packDir: at("packs", env), keysDir: at("pack-keys", env) },
      `${label}: arbiter defaultPackDirs`,
    );
    assert.equal(arbiterDefaultStateBase(env.HOME!), at("view-state", { HOME: env.HOME }), `${label}: arbiter defaultStateBase`);
    assert.equal(defaultInstallPrefix(env.HOME!), at("install-prefix", { HOME: env.HOME }), `${label}: arbiter defaultInstallPrefix`);
    const t = testTenantPaths({ arbiterSock: "/r/arbiter.sock" }, env);
    assert.equal(t.symbolDb, at("symbol-db-test", env), `${label}: test-tenant DB`);
    assert.equal(t.eventDir, at("events-test", env), `${label}: test-tenant events`);
    // The table ignores the retired variables, so every owner must too.
    const bare = withoutRetired(env);
    assert.equal(getEventDir(env), getEventDir(bare), `${label}: getEventDir ignores the retired variables`);
    assert.equal(defaultEventDir(env), defaultEventDir(bare), `${label}: dashboard defaultEventDir ignores them`);
    assert.equal(getSymbolDbPath(env, env.HOME!), getSymbolDbPath(bare, env.HOME!), `${label}: getSymbolDbPath ignores them`);
    assert.equal(defaultPolicyFilePath(env), defaultPolicyFilePath(bare), `${label}: defaultPolicyFilePath ignores them`);
    assert.equal(configPath(env), configPath(bare), `${label}: launcher configPath ignores them`);
    assert.deepEqual(testTenantPaths({ arbiterSock: "/r/arbiter.sock" }, bare), t, `${label}: the test tenant ignores them`);
  }
  assert.equal(defaultStateBase({}, homedir()), launcherCopy.manduPath("view-state", {}, homedir()), "fs-sync defaultStateBase");
});

test("fs-sync asks the table (phase 3b): its state base, and the name of Mandu's dir it never walks", () => {
  const envs: Array<[string, NodeJS.ProcessEnv]> = [
    ["HOME only", { HOME: "/home/alice" }],
    ["XDG roots do not move it", { HOME: "/home/alice", XDG_STATE_HOME: "/x/state" }],
    ["MANDU_HOME moves it", { HOME: "/h", MANDU_HOME: "/m" }],
    ["retired MANDU_VIEW_STATE moves nothing", { HOME: "/h", MANDU_VIEW_STATE: "/o/view-state/" }],
  ];
  for (const [label, env] of envs) {
    assert.equal(defaultStateBase(env, env.HOME!), resolvePath("view-state", env, env.HOME!), `${label}: fs-sync defaultStateBase`);
    assert.equal(defaultStateBase(env, env.HOME!), defaultStateBase(withoutRetired(env), env.HOME!), `${label}: no retired variable`);
  }
  assert.equal(defaultStateBase(), fsSyncCopy.manduPath("view-state", process.env, homedir()), "the no-argument form reads this process");
  assert.equal(MANDU_HOME_DIR_NAME, posix.basename(resolvePath("mandu-home", {}, "/home/alice")), "fs-sync's own-dir name");
  assert.ok(ALWAYS_DENIED_DIRS.includes(MANDU_HOME_DIR_NAME), "the ignored-file walk never enters it");
  assert.equal(humanEditClockIgnores(`src/${MANDU_HOME_DIR_NAME}/x`), true, "nor does the human-edit clock count it");
});

// Phase 3b (on-disk-layout.md §7), the launcher: every owner resolves through
// its generated copy, so each agrees with the table on every owner env.
test("the launcher's owners ask the table (phase 3b)", () => {
  const at = (name: launcherCopy.ManduPathName, env: NodeJS.ProcessEnv): string => launcherCopy.manduPath(name, env, env.HOME!);
  for (const [label, env] of OWNER_ENVS) {
    assert.equal(launcherRuntimeBase(env), runtimeRule(env), `${label}: launcher runtimeBase`);
    assert.equal(launcherPolicyFilePath(env), at("policy", env), `${label}: launcher policyFilePath`);
    const own = launcherOwnFiles(env).map((e) => e.path);
    // One rule for the home (on-disk-layout.md §4): the whole Mandu home, so
    // every part of it where the table puts it (no retired variable moves
    // one), and the install at MANDU_PREFIX when set.
    assert.ok(own.includes(at("mandu-home", env)), `${label}: launcher write-protect covers the Mandu home`);
    assert.ok(own.includes(at("install-prefix", env)), `${label}: launcher write-protect covers install-prefix`);
    const covered = (p: string): boolean => own.some((o) => p === o || p.startsWith(`${o}/`));
    for (const name of ["config-toml", "policy", "events", "runs-root", "cache-root", "symbol-db", "symbol-db-test", "view-state"] as const) {
      assert.ok(covered(at(name, env)), `${label}: launcher write-protect covers ${name}`);
    }
    assert.deepEqual(own, launcherOwnFiles(withoutRetired(env)).map((e) => e.path), `${label}: write-protect ignores the retired variables`);
    const plan = { integrity: false, eventDir: "", cwd: "/w", humanCwd: "/w" } as unknown as LaunchPlan;
    const hidden = ownStoresHidden(plan, env.HOME!, env, "/r/sid", () => false, (p) => p);
    // The one deny rule hides the whole home, so every store in it.
    assert.ok(hidden.guard.includes(at("mandu-home", env)), `${label}: launcher ownStoresHidden covers the Mandu home`);
    const hides = (p: string): boolean => hidden.guard.some((g) => p === g || p.startsWith(`${g}/`));
    for (const name of ["symbol-db", "symbol-db-test", "events", "events-test", "view-state", "config-toml", "policy"] as const) {
      assert.ok(hides(at(name, env)), `${label}: launcher ownStoresHidden covers ${name}`);
    }
  }
  assert.equal(accountRendezvous(1000, "/home/alice"), at("runtime-dir", { HOME: "/home/alice", XDG_RUNTIME_DIR: "/run/user/1000" }));
});

test("the dashboard's resolvers are the table's entries (phase 3b), on every owner env and every table fixture", () => {
  const cases: Array<[string, NodeJS.ProcessEnv, string]> = [
    ...OWNER_ENVS.map(([label, env]): [string, NodeJS.ProcessEnv, string] => [label, env, env.HOME!]),
    ...FIXTURES.map(([label, env, home]: [string, Record<string, string>, string]): [string, NodeJS.ProcessEnv, string] => [
      `fixture ${label}`, { ...env, HOME: home }, home,
    ]),
  ];
  for (const [label, env, home] of cases) {
    const at = (name: launcherCopy.ManduPathName): string => resolvePath(name, env, home);
    assert.equal(dashboardConfigPath(env), at("config-toml"), `${label}: dashboard resolveConfigPath`);
    const t = testTenantPaths({ arbiterSock: "/r/arbiter.sock" }, env);
    assert.equal(t.symbolDb, at("symbol-db-test"), `${label}: test-tenant DB`);
    assert.equal(t.eventDir, at("events-test"), `${label}: test-tenant events`);
  }
});
