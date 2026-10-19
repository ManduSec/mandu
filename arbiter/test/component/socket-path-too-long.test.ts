/**
 * socket-path-too-long (e2e) — the real arbiter daemon started on a socket
 * path the kernel would shorten exits with the reason, binds nothing, and
 * leaves no instance dir behind (ipc/socket-path.ts; runtime-instances.md §3a).
 *
 * Mandu-new test (no reference origin). This is how the 2026-09-28 case
 * started: `scripts/dev-arbiter.sh` runs server-main with an explicit path,
 * which skips the launcher's own check.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SUN_PATH_MAX } from "../../ipc/socket-path.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_MAIN = join(ARBITER_DIR, "ipc", "server-main.ts");
const TSX = join(ARBITER_DIR, "node_modules", ".bin", "tsx");

test("server-main on a 113-byte socket path exits 1 naming the limit, and binds nothing", { timeout: 30_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-"));
  try {
    const sockDir = join(dir, "arb");
    mkdirSync(sockDir);
    const sock = join(sockDir, "s".repeat(113 - sockDir.length - 1));
    assert.equal(Buffer.byteLength(sock), 113);
    const runtime = join(dir, "mandu");
    let err = "";
    const child = spawn(TSX, [SERVER_MAIN, sock], {
      cwd: ARBITER_DIR,
      env: {
        ...process.env,
        MANDU_HOME: join(dir, "home"),
        MANDU_RUNTIME_DIR: runtime,
        MANDU_LIFELINE: "",
      },
      stdio: ["ignore", "ignore", "pipe"],
    });
    child.stderr!.on("data", (d) => { err += String(d); });
    const code = await new Promise<number | null>((resolve) => child.once("exit", (c) => resolve(c)));
    assert.equal(code, 1, `the daemon must refuse; stderr:\n${err}`);
    // The platform's own limit (107 on Linux, 103 on macOS / the BSDs).
    assert.match(err, new RegExp(`arbiter socket: the socket path is 113 bytes, over the ${SUN_PATH_MAX - 1}-byte limit`));
    assert.deepEqual(readdirSync(sockDir), [], "nothing bound at the shortened name");
    const instances = join(runtime, "instances");
    assert.deepEqual(existsSync(instances) ? readdirSync(instances) : [], [], "no instance dir left behind");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
