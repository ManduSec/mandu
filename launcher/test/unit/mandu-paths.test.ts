/**
 * mandu-paths.test — the launcher's generated copy of the path table
 * (src/generated/mandu-paths.ts, from scripts/paths/mandu-paths.mjs;
 * on-disk-layout.md §5). Phase 3c: everything Mandu keeps lives in the one
 * home (§3), and the resolvers are pure functions of (env, home).
 * The copy-vs-table oracles: scripts/test/mandu-paths.test.mjs (text) and
 * tests/stack/mandu-paths-parity.test.ts (behavior).
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  MANDU_PATHS, manduBase, manduPath, type ManduPathName,
} from "../../src/generated/mandu-paths.js";

test("home only: the one Mandu home, the runtime dir and the install", () => {
  const at = (name: ManduPathName): string => manduPath(name, {}, "/home/u");
  assert.equal(at("mandu-home"), "/home/u/.mandu");
  assert.equal(at("config-toml"), "/home/u/.mandu/config.toml");
  assert.equal(at("policy"), "/home/u/.mandu/policy.yaml");
  assert.equal(at("symbol-db"), "/home/u/.mandu/state/mandu.db");
  assert.equal(at("workspaces"), "/home/u/.mandu/state/workspaces");
  assert.equal(at("object-walks"), "/home/u/.mandu/state/object-walks");
  assert.equal(at("events"), "/home/u/.mandu/events");
  assert.equal(at("events-test"), "/home/u/.mandu/events/test");
  assert.equal(at("test-runs"), "/home/u/.mandu/runs/test-runs.json");
  assert.equal(at("ci-runs"), "/home/u/.mandu/runs/ci");
  assert.equal(at("replay-drill-runs"), "/home/u/.mandu/runs/drills/replay");
  assert.equal(at("drill-baselines"), "/home/u/.mandu/runs/drills/baselines");
  assert.equal(at("docker-e2e-home"), "/home/u/.mandu/dev/docker-e2e-home");
  assert.equal(at("object-twins"), "/home/u/.mandu/cache/object-twins");
  assert.equal(at("exec-box-cache"), "/home/u/.local/share/mandu/exec-box");
  assert.equal(at("runtime-dir"), "/tmp/mandu");
  assert.equal(at("install-prefix"), "/home/u/.local/share/mandu");
  assert.equal(at("bin-dir"), "/home/u/.local/bin");
});

test("MANDU_HOME, the runtime chain, and overrides; the XDG roots no longer place anything", () => {
  assert.equal(manduPath("events", { MANDU_HOME: "/m" }, "/h"), "/m/events");
  assert.equal(manduPath("config-toml", { XDG_CONFIG_HOME: "/c" }, "/h"), "/h/.mandu/config.toml");
  assert.equal(manduPath("events", { XDG_STATE_HOME: "/s" }, "/h"), "/h/.mandu/events");
  assert.equal(manduPath("runtime-dir", { XDG_RUNTIME_DIR: "/run/user/1", TMPDIR: "/t" }, "/h"), "/run/user/1/mandu");
  assert.equal(manduPath("runtime-dir", { XDG_RUNTIME_DIR: "", TMPDIR: "/t" }, "/h"), "/t/mandu");
  assert.equal(manduPath("runtime-dir", { MANDU_RUNTIME_DIR: "/rt" }, "/h"), "/rt");
  // The per-path overrides are retired: only MANDU_HOME moves a store.
  const retired = {
    MANDU_CONFIG: "/o/c", MANDU_SECRETS: "/o/s", MANDU_SYMBOL_DB: "/o/db", MANDU_VIEW_STATE: "/o/v",
    MANDU_EVENT_DIR: "/o/e", MANDU_CI_RUNS_DIR: "/o/r", MANDU_MATRIX_RESULTS_DIR: "/o/m",
    MANDU_DOCKER_HOME: "/o/d", MANDU_CI_CACHE: "/o/k",
  } as Record<string, string>;
  for (const name of Object.keys(MANDU_PATHS) as Array<keyof typeof MANDU_PATHS>) {
    assert.equal(manduPath(name, retired, "/h"), manduPath(name, {}, "/h"), `${name} ignores the retired overrides`);
  }
  assert.equal(manduBase("mandu", { MANDU_HOME: "" }, "/h/"), "/h/.mandu");
});

test("pure: reads only the variables it names, and never process.env", () => {
  const read: string[] = [];
  const env = new Proxy({} as Record<string, string | undefined>, {
    get: (_t, k) => { read.push(String(k)); return undefined; },
  });
  const saved = process.env["MANDU_HOME"];
  process.env["MANDU_HOME"] = "/must/not/be/read";
  try {
    assert.equal(manduPath("events", env, "/h"), "/h/.mandu/events");
  } finally {
    if (saved === undefined) delete process.env["MANDU_HOME"];
    else process.env["MANDU_HOME"] = saved;
  }
  assert.deepEqual(read, ["MANDU_HOME"]);
});

test("agent-denied stores are owner-only; the program is readable", () => {
  for (const e of Object.values(MANDU_PATHS)) {
    if (!e.agentReadable) assert.equal(e.mode, e.kind === "dir" ? 0o700 : 0o600, e.name);
  }
  assert.equal(MANDU_PATHS["install-prefix"].agentReadable, true);
  assert.equal(MANDU_PATHS["symbol-db"].agentReadable, false);
  assert.equal(MANDU_PATHS["events"].agentReadable, false);
});
