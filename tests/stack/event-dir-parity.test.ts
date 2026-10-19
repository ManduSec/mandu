/**
 * event-dir-parity.test — the THREE copies of the event-dir default rule
 * produce the same path for the same environment (runtime-instances.md §12):
 *   1. arbiter/events/event-store.ts   getEventDir       (the owner)
 *   2. dashboard/src/event-dir.ts      defaultEventDir   (TS mirror — the
 *      dashboard is an arbiter CLIENT and does not import the arbiter package;
 *      since 2026-09-29 it resolves through the dashboard's generated copy of
 *      the path table, on-disk-layout.md §5)
 *   3. scripts/ci/docker-run.sh        --publish-events  (shell mirror; host
 *      side of the bind mount that puts CI sessions in the host dashboard;
 *      since 2026-09-29 it resolves through the generated shell copy of the
 *      path table, scripts/paths/mandu-paths.sh, on the passwd home)
 *
 * Why an oracle instead of one shared module: the copies are the
 * arbiter-client boundary (CONTRIBUTING.md) and a shell script; what must never
 * happen is silent drift — a CI run "published" into a directory no dashboard
 * reads. This test is cheap (pure functions + a few --dry-runs) and fails the
 * moment any copy diverges. Copy 3 keys on the invoking uid's PASSWD home
 * rather than $HOME (the GitLab runner overrides HOME to its CI home), so it
 * is compared under an env where the two coincide, plus the MANDU_HOME
 * branch that does not involve HOME at all.
 *
 * Phase 4 (on-disk-layout.md §5, §9.1) retired MANDU_EVENT_DIR: only
 * MANDU_HOME moves the event dir. The container side of --publish-events is
 * therefore a MANDU_HOME whose `events/` is the host's event dir, bind-mounted;
 * the container's arbiter and its test tenant (`events/test`) resolve into it
 * by the table alone. Setting the retired variable on the host moves nothing.
 *
 * The all-rules oracle is mandu-paths-parity.test.ts (every entry of the path
 * table, every generated copy; scripts/test/mandu-paths.test.mjs checks the
 * shell copy). This file keeps the end-to-end check that docker-run.sh wires
 * the shell copy's answer, keyed on the passwd home, into its bind mount.
 *
 * Run: npm test  (integration)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";

import { getEventDir } from "../../arbiter/events/event-store.js";
import { defaultEventDir } from "../../dashboard/src/event-dir.js";
import { testTenantPaths } from "../../dashboard/src/supervisor/supervisor-defs.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const DOCKER_RUN = join(REPO, "scripts", "ci", "docker-run.sh");

const ENVS: Array<[string, NodeJS.ProcessEnv]> = [
  ["retired MANDU_EVENT_DIR moves nothing", { MANDU_EVENT_DIR: "/srv/mandu/events", XDG_RUNTIME_DIR: "/run/user/1", HOME: "/h" }],
  ["retired MANDU_EVENT_DIR beside MANDU_HOME", { MANDU_EVENT_DIR: "/srv/mandu/events", MANDU_HOME: "/m", HOME: "/h" }],
  ["MANDU_HOME set", { MANDU_HOME: "/var/lib/mandu", XDG_RUNTIME_DIR: "/run/user/1", HOME: "/h" }],
  ["XDG_STATE_HOME does not move it", { XDG_STATE_HOME: "/var/lib/mandu-state", HOME: "/h" }],
  ["HOME only", { HOME: "/home/alice", XDG_RUNTIME_DIR: "/run/user/1" }],
  ["HOME only, no runtime dir", { HOME: "/home/alice" }],
  ["empty MANDU_HOME", { MANDU_HOME: "", HOME: "/home/alice" }],
];

function withoutEventDir(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const { MANDU_EVENT_DIR: _retired, ...rest } = env;
  return rest;
}

test("arbiter getEventDir ≡ dashboard defaultEventDir for every env shape", () => {
  for (const [label, env] of ENVS) {
    assert.equal(defaultEventDir(env), getEventDir(env), label);
    assert.equal(getEventDir(env), getEventDir(withoutEventDir(env)), `${label}: MANDU_EVENT_DIR is retired`);
  }
});

test("the default never resolves under the runtime dir (a reboot-wiped tmpfs)", () => {
  for (const [label, env] of ENVS) {
    const d = getEventDir(env);
    assert.ok(!env.XDG_RUNTIME_DIR || !d.startsWith(env.XDG_RUNTIME_DIR), `${label}: ${d}`);
  }
});

const RETIRED = [
  "MANDU_CONFIG", "MANDU_SECRETS", "MANDU_SYMBOL_DB", "MANDU_VIEW_STATE", "MANDU_EVENT_DIR",
  "MANDU_CI_RUNS_DIR", "MANDU_MATRIX_RESULTS_DIR", "MANDU_DOCKER_HOME", "MANDU_CI_CACHE",
];

const strip = (p: string): string => posix.normalize(p).replace(/(.)\/+$/, "$1");

/** What docker-run.sh --publish-events would wire under `env` (dry run; no
 *  docker needed): the container's MANDU_HOME, and the HOST dir bind-mounted
 *  at that home's `events/`. */
function shellPublish(env: NodeJS.ProcessEnv): { hostEvents: string; containerHome: string } {
  const clean: NodeJS.ProcessEnv = { PATH: process.env.PATH, ...env };
  const r = spawnSync("bash", [DOCKER_RUN, "core", "--publish-events", "--dry-run", "--", "true"], { env: clean, encoding: "utf8" });
  assert.equal(r.status, 0, `dry run failed: ${r.stdout}\n${r.stderr}`);
  const argv = r.stdout.split("\n");
  const mounts: Array<[string, string]> = [];
  const vars = new Map<string, string>();
  for (let i = 0; i + 1 < argv.length; i++) {
    if (argv[i] === "-v") {
      const [src, dst] = argv[i + 1].split(":");
      mounts.push([src, dst]);
    } else if (argv[i] === "-e") {
      const eq = argv[i + 1].indexOf("=");
      if (eq > 0) vars.set(argv[i + 1].slice(0, eq), argv[i + 1].slice(eq + 1));
    }
  }
  for (const k of RETIRED) assert.ok(!vars.has(k), `the container gets retired ${k}: ${r.stdout}`);
  const containerHome = vars.get("MANDU_HOME");
  assert.ok(containerHome, `no MANDU_HOME in dry-run argv: ${r.stdout}\n${r.stderr}`);
  // The container's arbiter resolves its event dir by the table alone.
  const containerEvents = getEventDir({ MANDU_HOME: containerHome });
  const m = mounts.find(([, dst]) => strip(dst) === strip(containerEvents));
  assert.ok(m, `no mount at the container home's events/ (${containerEvents}): ${r.stdout}`);
  // The container's test tenant (the dashboard's own rule) lands inside it.
  const tenant = testTenantPaths({ arbiterSock: "/r/arbiter.sock" }, { MANDU_HOME: containerHome }).eventDir;
  assert.ok(tenant.startsWith(`${strip(containerEvents)}/`), `the container's test tenant ${tenant} is outside the mount`);
  return { hostEvents: strip(m[0]), containerHome };
}

test("scripts/ci/docker-run.sh --publish-events ≡ the TS rule (MANDU_HOME, passwd-home default, retired override)", () => {
  const scratch = mkdtempSync(join(tmpdir(), "mandu-evparity-"));
  try {
    // The branch that does not involve HOME: the copies must be identical.
    const home = { MANDU_HOME: join(scratch, "mandu-home"), HOME: process.env.HOME };
    assert.equal(shellPublish(home).hostEvents, getEventDir(home));
    // The HOME branch: the shell copy keys on the passwd home. Under a normal
    // login the two coincide; under the CI runner's overridden HOME they must
    // NOT (that is the whole point) — assert both.
    const passwdHome = userInfo().homedir;
    const published = shellPublish({ HOME: passwdHome });
    assert.equal(published.hostEvents, getEventDir({ HOME: passwdHome }));
    // The host's test tenant is the mount's `test/`, the dashboard's rule.
    assert.equal(
      join(published.hostEvents, "test"),
      testTenantPaths({ arbiterSock: "/r/arbiter.sock" }, { HOME: passwdHome }).eventDir,
      "the container's test tenant is the host's",
    );
    const overridden = shellPublish({ HOME: join(scratch, "ci-home") });
    assert.equal(overridden.hostEvents, getEventDir({ HOME: passwdHome }), "an overridden HOME still publishes to the user's dashboard dir");
    // The retired override moves nothing, and never reaches the container.
    const retired = shellPublish({ HOME: passwdHome, MANDU_EVENT_DIR: join(scratch, "explicit-events") });
    assert.equal(retired.hostEvents, getEventDir({ HOME: passwdHome }), "MANDU_EVENT_DIR is retired");
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
