/**
 * unit-restart-race.test.ts — a launch during a restart of the systemd user
 * service that runs the stack ends up on the service's stack, with no second
 * dashboard or arbiter of its own (runtime-instances.md §4.1c; the
 * 2026-10-21 incident: a launch in the two-second gap of a
 * mandu-dashboard.service restart autostarted an ownerless stack, and the
 * service's dashboard adopted its arbiter for four days).
 *
 * A REAL transient user unit (`systemd-run --user`, Restart=always) runs a
 * stand-in for the service's dashboard: it loads for two seconds, then runs
 * a real arbiter of this release (tests/fixtures/older-arbiter.fixture.ts,
 * titled, bound in its instance dir, promoted to `current`). The unit is
 * restarted, and while its new process is still loading the launcher's real
 * autostart (`startArbiterInstance`, with the real service detection and the
 * real socket poll) runs: it must spawn nothing, report the arbiter
 * attached, and `current` must answer from the unit's process.
 *
 * Skips where there is no systemd user manager (the CI guest, macOS).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { startArbiterInstance } from "../../launcher/src/arbiter.js";
import { Layout, type DaemonSpec } from "../../launcher/src/services/layout.js";
import { ndjsonCall } from "../../launcher/src/secret-setup.js";
import { launcherVersion } from "../../launcher/src/update-check.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("off"); // the autostart's wait is axis-independent

const HERE = dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = join(HERE, "..");
const REPO = join(TESTS_DIR, "..");
const FIXTURE = join(TESTS_DIR, "fixtures", "older-arbiter.fixture.ts");

function userSystemd(): string | false {
  if (process.platform !== "linux") return "systemd user units are Linux-only";
  const run = spawnSync("systemd-run", ["--user", "--version"], { stdio: "ignore", timeout: 5_000 });
  if (run.status !== 0) return "no systemd-run";
  const st = spawnSync("systemctl", ["--user", "is-system-running"], { encoding: "utf8", timeout: 5_000 });
  const state = (st.stdout ?? "").trim();
  return state === "running" || state === "degraded" ? false : `no systemd user manager (${state || "no answer"})`;
}
const SKIP = userSystemd();

function systemctl(...args: string[]): { status: number | null; out: string } {
  const r = spawnSync("systemctl", ["--user", ...args], { encoding: "utf8", timeout: 20_000 });
  return { status: r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

function mainPid(unit: string): number {
  return Number(systemctl("show", "-p", "MainPID", "--value", unit).out.trim());
}

async function until(check: () => boolean | Promise<boolean>, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await check()) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return check();
}

async function answers(sock: string): Promise<Record<string, unknown> | null> {
  try { return await ndjsonCall<Record<string, unknown>>(sock, "hello", {}, 2_000); } catch { return null; }
}

test("a launch during the service's restart waits for the service's arbiter: nothing spawned, attached, current is the unit's", { skip: SKIP, timeout: 180_000 }, async () => {
  const tmp = realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : TESTS_DIR, "mdu-urr-")));
  const base = join(tmp, "mandu");
  mkdirSync(join(tmp, "state"), { recursive: true });
  const unit = `mandu-race-test-${process.pid}-${Date.now()}.service`;
  const current = join(base, "current", "arbiter.sock");
  try {
    // The stand-in dashboard: two seconds of loading, then the arbiter.
    const tsx = join(TESTS_DIR, "node_modules", "tsx", "dist", "loader.mjs");
    const cmd = `sleep 2; exec ${JSON.stringify(process.execPath)} --import ${JSON.stringify(tsx)} ${JSON.stringify(FIXTURE)} ${JSON.stringify(base)} ${launcherVersion()} ${JSON.stringify(join(tmp, "state"))}`;
    const started = spawnSync("systemd-run", [
      "--user", `--unit=${unit}`, "-p", "Restart=always", "-p", "RestartSec=100ms", "--collect",
      `--working-directory=${TESTS_DIR}`, "-E", `MANDU_RUNTIME_DIR=${base}`, "-E", `MANDU_HOME=${join(tmp, "home")}`,
      "--", "/bin/bash", "-c", cmd,
    ], { encoding: "utf8", timeout: 20_000 });
    assert.equal(started.status, 0, `the transient unit started: ${started.stderr}`);
    assert.ok(await until(async () => (await answers(current)) !== null, 60_000), "the service's arbiter came up");

    // The restart: the old arbiter goes (current dangles), the new process loads.
    assert.equal(systemctl("restart", "--no-block", unit).status, 0);
    assert.ok(await until(async () => (await answers(current)) === null, 30_000), "the restart took the old arbiter away");
    assert.equal(existsSync(current), false, "no arbiter at current: a launch now would autostart");

    const spawned: DaemonSpec[] = [];
    const logs: string[] = [];
    const handle = await startArbiterInstance(Layout.dev(REPO), base, join(tmp, "autostart.log"), {}, {
      spawnDaemon: (spec) => { spawned.push(spec); },
      log: (m) => logs.push(m),
      env: { ...process.env, MANDU_RUNTIME_DIR: base },
      runtimeEnv: { ...process.env, MANDU_RUNTIME_DIR: base },
    })();
    assert.deepEqual(spawned, [], `no dashboard or arbiter of the launch's own (log: ${logs.join(" | ")})`);
    assert.equal(handle?.attached, true, "the service's arbiter, attached");
    assert.ok(logs.some((l) => new RegExp(`starting under the systemd user service ${unit.replace(/\./g, "\\.")}`).test(l)), logs.join("\n"));
    const hello = await answers(current);
    assert.equal(hello?.["pid"], mainPid(unit), "current answers from the unit's own process");
    assert.equal(existsSync(join(base, "dashboards")) ? readdirSync(join(base, "dashboards")).length : 0, 0, "no dashboard registered");
  } finally {
    systemctl("stop", unit);
    systemctl("reset-failed", unit);
    rmSync(tmp, { recursive: true, force: true });
  }
});

// Keeps the reader honest about what the stand-in is: the fixture this test
// runs as the unit's process must exist where it says.
test("the stand-in's fixture is present", () => {
  assert.ok(readFileSync(FIXTURE, "utf8").includes("mandu-arbiter"));
});
