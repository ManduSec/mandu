/**
 * autostart-arbiter-exit.test — E2E: the REAL dashboard entrypoint as the
 * launcher's stack autostart spawns it (DASHBOARD_AUTOSTART=arbiter, instance
 * mode under an isolated runtime dir), when its supervised arbiter misses the
 * readiness deadline the launcher hands it (MANDU_SERVICE_READY_TIMEOUT_MS):
 *   - the supervisor uses THAT deadline, not its fixed 10 s default;
 *   - the dashboard EXITS (code 1) instead of serving with no arbiter, so the
 *     launcher starts its own fallback at once rather than waiting out its
 *     grace window for a promotion that can never come (runtime-instances.md
 *     §10 "Autostart deadlines under load").
 * A 1 ms deadline stands in for a saturated host: no arbiter answers in 1 ms.
 * The second test needs its arbiter UP, so it hands the deadline the launcher
 * would on a loaded host instead of leaving the supervisor its fixed 10 s.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SERVER_TEST_TIMEOUT_MS, START_DEADLINE_MS } from "./server-up.js";
import { tmpDir } from "../unit/tmp-dir.js";

const PKG_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const TSX = join(PKG_DIR, "node_modules", ".bin", "tsx");
const SERVER_MAIN = join(PKG_DIR, "src", "server-main.ts");

async function exited(child: ChildProcess, ms: number): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((r) => { child.once("exit", () => r()); setTimeout(r, ms).unref(); });
}

test("DASHBOARD_AUTOSTART=arbiter: an arbiter that misses the launcher's deadline makes the dashboard exit 1 (the launcher falls back at once)", { timeout: SERVER_TEST_TIMEOUT_MS }, async () => {
  const dir = tmpDir("mandu-dash-autoexit-");
  let stderr = "";
  const env: Record<string, string | undefined> = {
    ...process.env,
    DASHBOARD_AUTOSTART: "arbiter",
    MANDU_SERVICE_READY_TIMEOUT_MS: "1",
    DASHBOARD_PORT: "0",
    DASHBOARD_PASSWORD: "",
    DASHBOARD_BASIC_AUTH: "",
    DASHBOARD_TRUST_FRONT: "",
    DASHBOARD_ALLOW_HOSTS: "",
    MANDU_PORT_FILE: join(dir, "port"),
    MANDU_RUNTIME_DIR: join(dir, "rt"),
    MANDU_HOME: join(dir, "home"),
    MANDU_OWNER_PID: "none",
    MANDU_MODE: "off",
    MANDU_TEST_DASHBOARD: "",
  };
  // Instance mode, as the launcher's autostart runs it: no pinned socket.
  delete env["MANDU_ARBITER_SOCK"];
  delete env["MANDU_ARBITER_SOCKET"];
  delete env["DASHBOARD_HOST"];
  const child = spawn(TSX, [SERVER_MAIN], { cwd: PKG_DIR, env, stdio: ["ignore", "ignore", "pipe"] });
  child.stderr!.on("data", (d: Buffer) => { stderr += d.toString(); });
  try {
    await exited(child, START_DEADLINE_MS);
    assert.equal(child.exitCode, 1, `exit 1 (stderr: ${stderr})`);
    assert.match(stderr, /\[dashboard\] up on /, "it did come up first (the failure is the arbiter's, not the server's)");
    assert.match(stderr, /readiness timeout after 1ms/, "the supervisor used the handed deadline, not its 10 s default");
    assert.match(stderr, /the arbiter did not come up; exiting so the launcher starts one itself/);
    assert.ok(!existsSync(join(dir, "rt", "current", "arbiter.sock")), "nothing was promoted");
  } finally {
    child.kill("SIGKILL");
    await exited(child, 5_000);
    rmSync(dir, { recursive: true, force: true });
  }
});

// The dashboard's own start, then its arbiter's: two start deadlines, as the
// launcher waits two readiness deadlines for its supervisor (§10).
const ARBITER_UP_DEADLINE_MS = 2 * START_DEADLINE_MS;

test("DASHBOARD_AUTOSTART=arbiter: the arbiter exiting under a running dashboard (another dashboard replaced it) ends the dashboard too", { timeout: SERVER_TEST_TIMEOUT_MS + START_DEADLINE_MS }, async () => {
  // The 2026-10-21 orphan (runtime-instances.md §4.1b): a launch's stack
  // dashboard whose arbiter another dashboard took over kept serving with
  // nothing to supervise. It exits now, so the next launch starts the stack
  // whole instead of a second dashboard beside it.
  const dir = tmpDir("mandu-dash-arbexit-");
  const rt = join(dir, "rt");
  let stderr = "";
  const env: Record<string, string | undefined> = {
    ...process.env,
    DASHBOARD_AUTOSTART: "arbiter",
    // What the launcher hands its supervisor (launcher arbiter.ts, its
    // load-aware serviceReadyDeadlineMs). Without it the supervisor's fixed
    // 10 s default applied, and on a loaded CI host the arbiter's cold tsx
    // start missed it: the dashboard exited "the arbiter did not come up"
    // before this test could kill anything (MR !2278, CI job 18263; pinned
    // to 2 cores beside 24 busy loops it failed 3 of 3).
    MANDU_SERVICE_READY_TIMEOUT_MS: String(START_DEADLINE_MS),
    DASHBOARD_PORT: "0",
    DASHBOARD_PASSWORD: "",
    DASHBOARD_BASIC_AUTH: "",
    DASHBOARD_TRUST_FRONT: "",
    DASHBOARD_ALLOW_HOSTS: "",
    MANDU_PORT_FILE: join(dir, "port"),
    MANDU_RUNTIME_DIR: rt,
    MANDU_HOME: join(dir, "home"),
    MANDU_OWNER_PID: "none",
    MANDU_MODE: "off",
    MANDU_TEST_DASHBOARD: "",
  };
  delete env["MANDU_ARBITER_SOCK"];
  delete env["MANDU_ARBITER_SOCKET"];
  delete env["DASHBOARD_HOST"];
  const child = spawn(TSX, [SERVER_MAIN], { cwd: PKG_DIR, env, stdio: ["ignore", "ignore", "pipe"] });
  child.stderr!.on("data", (d: Buffer) => { stderr += d.toString(); });
  const arbiterPid = (): number | null => {
    try {
      for (const id of readdirSync(join(rt, "instances"))) {
        const m = JSON.parse(readFileSync(join(rt, "instances", id, "manifest.json"), "utf8")) as { pid?: unknown };
        if (typeof m.pid === "number") return m.pid;
      }
    } catch { /* not yet */ }
    return null;
  };
  let pid: number | null = null;
  try {
    const deadline = Date.now() + ARBITER_UP_DEADLINE_MS;
    while (!(/autostart: 1\/\d+ services running/.test(stderr) && (pid = arbiterPid()) !== null)) {
      if (child.exitCode !== null || Date.now() > deadline) assert.fail(`the dashboard and its arbiter came up (stderr: ${stderr})`);
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.equal(readdirSync(join(rt, "dashboards")).filter((n) => n.endsWith(".json")).length, 1, "the dashboard registered");
    process.kill(pid!, "SIGTERM"); // what a replacing dashboard does to it
    await exited(child, START_DEADLINE_MS); // returns at the exit; the bound is a deadline
    assert.equal(child.exitCode, 1, `the dashboard exited 1 with its arbiter (stderr: ${stderr})`);
    assert.match(stderr, /\[dashboard\] the arbiter this dashboard supervises exited \(crashed while running \(code 0\)\); exiting with it/);
    assert.deepEqual(readdirSync(join(rt, "dashboards")).filter((n) => n.endsWith(".json")), [], "its registry entry is gone");
  } finally {
    child.kill("SIGKILL");
    await exited(child, 5_000);
    if (pid !== null) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } }
    rmSync(dir, { recursive: true, force: true });
  }
});
