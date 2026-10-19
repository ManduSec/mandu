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
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
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
