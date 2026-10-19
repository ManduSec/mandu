/**
 * test-tenant-paths.test — where the supervisor puts the TEST-tenant arbiter
 * (policy-surface.md §2.7 1b; supervisor-defs.ts testTenantPaths +
 * the `test-arbiter` service definition) and how every arbiter it spawns is
 * told its stores (on-disk-layout.md §5).
 *
 * Pins: the test tenant's DB and event dir are the path table's
 * `symbol-db-test` / `events-test` under the Mandu home (never the live
 * paths), the socket is pinned under `<base>/test/` (never promoted), the
 * store paths reach an arbiter ONLY as `--symbol-db` / `--event-dir` flags
 * (the live arbiter gets them only when an option names a path; the test
 * arbiter always), and the retired per-path variables (MANDU_SYMBOL_DB,
 * MANDU_EVENT_DIR) move nothing and are never set. The service definition
 * spawns node directly with the admin channel and MANDU_TENANT=test while the
 * live arbiter is stamped MANDU_TENANT=live. The frozen integrity axis
 * (docs/design/architecture/protection-modes.md §10): the test arbiter's definition carries
 * MANDU_EXPERIMENTAL_INTEGRITY=1 (it runs the frozen lane), the live
 * arbiter's definition never does.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

import { arbiterStoreArgs, buildDefinitions, testTenantPaths, SERVICE_IDS } from "../../../src/supervisor/supervisor-defs.js";
import { INTEGRITY_OPT_IN_ENV } from "../../../src/config-axes.js";
import { manduPath } from "../../../src/generated/mandu-paths.js";

const RETIRED = { MANDU_SYMBOL_DB: "/retired/sym.sqlite", MANDU_EVENT_DIR: "/retired/ev" };
// The checkout's source form (packaging.md §5.1): arbiter's own tsx, one node process.
const DEV_ARGS = ["--import", pathToFileURL("/repo/arbiter/node_modules/tsx/dist/esm/index.mjs").href, "/repo/arbiter/ipc/server-main.ts"];

/** Resolved supervisor options, as the constructor fills them. */
function opts(extra: Record<string, unknown> = {}): never {
  return {
    repoRoot: "/repo",
    arbiterSock: "/run/mandu/current/arbiter.sock",
    arbiterInstanceBase: "/run/mandu",
    modelProxyPort: 8788,
    openaiProxyPort: 8789,
    egressProxyPort: 8790,
    proxyHost: "127.0.0.1",
    upstreamAnthropic: "https://api.anthropic.com",
    upstreamOpenai: "https://api.openai.com",
    logRingMax: 10,
    startTimeoutMs: 100,
    stopGraceMs: 100,
    autoStartArbiter: true,
    axisEnv: () => ({}),
    gitRev: () => "abc",
    gitChangedInRange: () => [],
    procCmdline: () => null,
    killPid: () => {},
    discoverSocketOwner: () => null,
    log: () => {},
    ...extra,
  } as never;
}

test("testTenantPaths: the path table's symbol-db-test / events-test under the Mandu home; socket pinned under <base>/test", () => {
  const p = testTenantPaths({ arbiterSock: "/run/mandu/current/arbiter.sock", arbiterInstanceBase: "/run/mandu" }, { HOME: "/home/u" });
  assert.deepEqual(p, {
    sock: "/run/mandu/test/arbiter.sock",
    symbolDb: "/home/u/.mandu/state/mandu-test.db",
    eventDir: "/home/u/.mandu/events/test",
  });
  const pinned = testTenantPaths({ arbiterSock: "/tmp/mandu/arbiter.sock" }, { HOME: "/home/u" });
  assert.equal(pinned.sock, "/tmp/mandu/test/arbiter.sock", "no instance base → dirname of the pinned live socket");
  const mh = testTenantPaths({ arbiterSock: "/tmp/mandu/arbiter.sock" }, { HOME: "/home/u", MANDU_HOME: "/mh" });
  assert.equal(mh.symbolDb, "/mh/state/mandu-test.db");
  assert.equal(mh.eventDir, "/mh/events/test");
  const xdg = testTenantPaths({ arbiterSock: "/tmp/mandu/arbiter.sock" }, { HOME: "/home/u", XDG_STATE_HOME: "/xdg" });
  assert.equal(xdg.eventDir, "/home/u/.mandu/events/test", "XDG_STATE_HOME places nothing");
  for (const env of [{ HOME: "/home/u" }, { HOME: "/home/u", MANDU_HOME: "/mh" }, { HOME: "/home/u", MANDU_HOME: "" }]) {
    const q = testTenantPaths({ arbiterSock: "/tmp/a.sock" }, env);
    assert.equal(q.symbolDb, manduPath("symbol-db-test", env, "/home/u"));
    assert.equal(q.eventDir, manduPath("events-test", env, "/home/u"));
  }
});

test("testTenantPaths: the retired MANDU_SYMBOL_DB / MANDU_EVENT_DIR move nothing", () => {
  for (const home of [{ HOME: "/home/u" }, { HOME: "/home/u", MANDU_HOME: "/mh" }]) {
    const plain = testTenantPaths({ arbiterSock: "/tmp/a.sock" }, home);
    const withRetired = testTenantPaths({ arbiterSock: "/tmp/a.sock" }, { ...home, ...RETIRED });
    assert.deepEqual(withRetired, plain);
  }
});

test("arbiterStoreArgs: a flag per given path, none for an unset or empty one", () => {
  assert.deepEqual(arbiterStoreArgs({}), []);
  assert.deepEqual(arbiterStoreArgs({ symbolDb: "", eventDir: "" }), []);
  assert.deepEqual(arbiterStoreArgs({ symbolDb: "/d/x.db" }), ["--symbol-db", "/d/x.db"]);
  assert.deepEqual(arbiterStoreArgs({ eventDir: "/e" }), ["--event-dir", "/e"]);
  assert.deepEqual(arbiterStoreArgs({ symbolDb: "/d/x.db", eventDir: "/e" }), ["--symbol-db", "/d/x.db", "--event-dir", "/e"]);
});

test("buildDefinitions: the live arbiter gets NO store flags by default (the home defaults), the test arbiter its table paths as flags", () => {
  const defs = buildDefinitions(opts(), { HOME: "/home/u", MANDU_HOME: "/mh" });
  assert.deepEqual(defs.arbiter.args, DEV_ARGS, "no option → no flag: the arbiter resolves its own home defaults");
  assert.deepEqual(defs["test-arbiter"].args, [...DEV_ARGS, "--symbol-db", "/mh/state/mandu-test.db", "--event-dir", "/mh/events/test"]);
  for (const id of ["arbiter", "test-arbiter"] as const) {
    for (const k of ["MANDU_SYMBOL_DB", "MANDU_EVENT_DIR"]) {
      assert.equal(k in defs[id].env, false, `${id} env never sets the retired ${k}`);
    }
  }
});

test("buildDefinitions: an explicit live path rides the live arbiter's argv; the test tenant stays in the home", () => {
  const defs = buildDefinitions(opts({ eventDir: "/scratch/events", symbolDb: "/scratch/mandu.db" }), { HOME: "/home/u" });
  assert.deepEqual(defs.arbiter.args, [...DEV_ARGS, "--symbol-db", "/scratch/mandu.db", "--event-dir", "/scratch/events"]);
  assert.deepEqual(defs["test-arbiter"].args, [...DEV_ARGS, "--symbol-db", "/home/u/.mandu/state/mandu-test.db", "--event-dir", "/home/u/.mandu/events/test"]);
  const onlyEvents = buildDefinitions(opts({ eventDir: "/scratch/events" }), { HOME: "/home/u" });
  assert.deepEqual(onlyEvents.arbiter.args, [...DEV_ARGS, "--event-dir", "/scratch/events"]);
});

test("buildDefinitions: the retired MANDU_SYMBOL_DB / MANDU_EVENT_DIR in the dashboard's env move nothing", () => {
  const home = { HOME: "/home/u", MANDU_HOME: "/mh" };
  const plain = buildDefinitions(opts(), home);
  const withRetired = buildDefinitions(opts(), { ...home, ...RETIRED });
  for (const id of ["arbiter", "test-arbiter"] as const) {
    assert.deepEqual(withRetired[id].args, plain[id].args, `${id} argv`);
    assert.deepEqual(withRetired[id].env, plain[id].env, `${id} env`);
  }
});

test("buildDefinitions: the installed layout appends the same store flags after the bundle", () => {
  const defs = buildDefinitions(opts({ layout: { mode: "installed", pkgRoot: "/pkg" } }), { HOME: "/home/u" });
  assert.deepEqual(defs.arbiter.args, ["--no-warnings=ExperimentalWarning", "/pkg/dist/arbiter.mjs"]);
  assert.deepEqual(defs["test-arbiter"].args, [
    "--no-warnings=ExperimentalWarning", "/pkg/dist/arbiter.mjs",
    "--symbol-db", "/home/u/.mandu/state/mandu-test.db", "--event-dir", "/home/u/.mandu/events/test",
  ]);
});

test("buildDefinitions: five services; test-arbiter is a tenanted direct-node spawn with its own store; the live arbiter is stamped live", () => {
  assert.deepEqual(SERVICE_IDS, ["arbiter", "anthropic-proxy", "openai-proxy", "net-proxy", "test-arbiter"]);
  const defs = buildDefinitions(opts(), { HOME: "/home/u" });
  const live = defs.arbiter;
  assert.equal(live.env.MANDU_TENANT, "live");
  assert.equal(live.command, process.execPath, "direct node spawn keeps the inherited admin fd");
  assert.equal(live.adminChannel, true);
  const t = defs["test-arbiter"];
  assert.equal(t.env.MANDU_TENANT, "test");
  assert.equal(t.env.MANDU_ARBITER_SOCK, "/run/mandu/test/arbiter.sock");
  assert.equal(t.env.MANDU_PROMOTE, "", "a test arbiter is never promoted to `current`");
  // STATED axes (protection-modes.md §4): integrity ON, confidentiality OFF,
  // whatever the product default is; the ungrouped live suites prove the
  // symbol-only invariant on this arbiter.
  assert.equal(t.env.MANDU_INTEGRITY, "1", "shared test arbiter STATES its axes (injection) …");
  assert.equal(t.env.MANDU_CONFIDENTIALITY, "0", "… never the built-in default, never the operator's live config");
  assert.equal(t.command, process.execPath);
  assert.deepEqual(t.args.slice(0, DEV_ARGS.length), DEV_ARGS);
  assert.equal(t.adminChannel, true);
  assert.deepEqual(t.requires, []);
  assert.deepEqual(t.ready, { kind: "socket", path: "/run/mandu/test/arbiter.sock" });
  // The proxies keep depending on the LIVE arbiter only.
  for (const id of ["anthropic-proxy", "openai-proxy", "net-proxy"] as const) {
    assert.deepEqual(defs[id].requires, ["arbiter"]);
    assert.equal(defs[id].env.MANDU_ARBITER_SOCK, "/run/mandu/current/arbiter.sock");
  }
});

test("buildDefinitions: MANDU_TEST_INTEGRITY / MANDU_TEST_CONFIDENTIALITY pin the TEST arbiter's posture (a grouped live run's fold) — the live one is untouched", () => {
  const o = opts();
  // The operator's LIVE axis env must not leak into the test arbiter …
  const leak = buildDefinitions(o, { HOME: "/home/u", MANDU_CONFIDENTIALITY: "1", MANDU_INTEGRITY: "0" });
  assert.equal(leak["test-arbiter"].env.MANDU_CONFIDENTIALITY, "0", "the live axis env never leaks into the test arbiter");
  assert.equal(leak["test-arbiter"].env.MANDU_INTEGRITY, "1");
  // … only the explicit TEST posture does, and it never touches the live arbiter's env.
  const pinned = buildDefinitions(o, { HOME: "/home/u", MANDU_TEST_CONFIDENTIALITY: "1", MANDU_TEST_INTEGRITY: "1" });
  assert.equal(pinned["test-arbiter"].env.MANDU_CONFIDENTIALITY, "1");
  assert.equal(pinned["test-arbiter"].env.MANDU_INTEGRITY, "1");
  assert.equal(pinned.arbiter.env.MANDU_CONFIDENTIALITY, undefined);
});

test("buildDefinitions: the TEST arbiter opts into the frozen integrity axis; the LIVE arbiter and the proxies never get the opt-in", () => {
  const o = opts();
  assert.equal(INTEGRITY_OPT_IN_ENV, "MANDU_EXPERIMENTAL_INTEGRITY");
  // Whatever the dashboard's own env says (absent, an explicit no, or a
  // grouped run pinning the test fold), the definitions say the same thing.
  for (const extra of [{}, { [INTEGRITY_OPT_IN_ENV]: "0" }, { MANDU_TEST_INTEGRITY: "0", MANDU_TEST_CONFIDENTIALITY: "1" }]) {
    const env = { HOME: "/home/u", ...extra };
    const defs = buildDefinitions(o, env);
    assert.equal(defs["test-arbiter"].env[INTEGRITY_OPT_IN_ENV], "1",
      `the test arbiter runs the frozen lane (env ${JSON.stringify(env)})`);
    assert.equal(defs["test-arbiter"].env.MANDU_TENANT, "test");
    for (const id of ["arbiter", "anthropic-proxy", "openai-proxy", "net-proxy"] as const) {
      assert.equal(INTEGRITY_OPT_IN_ENV in defs[id].env, false, `${id} never carries the opt-in in its definition`);
    }
  }
});
