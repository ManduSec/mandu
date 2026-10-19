/**
 * prepared-copies-gate e2e — the REAL daemon entrypoint (server-main) decides
 * whether it prepares sanitized git copies ahead of time
 * (confidentiality-plan-14-policy-suggestions.md §11.1 R3, "Linux only"):
 * only a Linux launch uses a prepared copy (the launcher's object twins and
 * the file guard are Linux only), so on any other host the daemon builds
 * none, says so once on its log, and its `gitHistoryLocks` answer carries no
 * `preparation` (what `mandu doctor --secrets` reads). On Linux the daemon
 * prepares, as before. Asserted for the host the suite runs on (the pure
 * decision, both platforms: unit/prepared-copies.test.ts `preparedCopiesOff`).
 * In mode `off` there is no resolver and so nothing to prepare on any host,
 * and the daemon does not log that preparation is off.
 *
 * The daemon runs against a fixture HOME and Mandu home (its HOME walk never
 * reads the real one). Axes stated: secrets (the file), and each daemon's
 * own mode, `secrets` or `off`, in its environment.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterClient } from "../../ipc/client.js";
import type { GitHistoryLocksResult } from "../../ipc/protocol.js";
import { CURRENT_LINK } from "../../ipc/instance.js";
import { axesEnv, stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the copies serve the confidentiality axis

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_MAIN = join(ARBITER_DIR, "ipc", "server-main.ts");

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null) return;
  await new Promise<void>((resolve) => {
    const kill = setTimeout(() => child.kill("SIGKILL"), 30_000);
    kill.unref();
    child.once("exit", () => { clearTimeout(kill); resolve(); });
    child.kill("SIGTERM");
  });
}

/** Start the real daemon in `mode` against a fixture HOME, ask it for its
 *  git-history locks, and hand the answer and its log to `check`. */
async function withDaemon(
  mode: "secrets" | "off",
  check: (r: GitHistoryLocksResult, stderr: string) => void,
): Promise<void> {
  // Short: the instance socket lives under it (a Mac's sun_path is 104 bytes).
  const root = mkdtempSync(join(tmpdir(), "mdu-pg-"));
  dirs.push(root);
  const home = join(root, "h");
  mkdirSync(home, { recursive: true });
  writeFileSync(join(root, "policy.yaml"), "version: 1\n");
  const env: NodeJS.ProcessEnv = {
    ...process.env, ...axesEnv(mode), HOME: home, MANDU_HOME: join(root, "m"), MANDU_RUNTIME_DIR: join(root, "r"),
    MANDU_ARBITER_SOCK: "", MANDU_ARBITER_HUMAN_SOCK: "", MANDU_PROMOTE: "1", MANDU_MODE: mode,
    MANDU_POLICY_FILE: join(root, "policy.yaml"),
  };
  delete env["MANDU_GIT_PREPARE"];
  delete env["MANDU_LOCK_RESOLUTION"];
  const child = spawn(process.execPath, ["--import", "tsx", SERVER_MAIN, "--symbol-db", join(root, "mandu.db"), "--event-dir", join(root, "ev")], {
    cwd: ARBITER_DIR, env, stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr!.setEncoding("utf8");
  child.stderr!.on("data", (c: string) => { stderr += c; });
  const sock = join(root, "r", CURRENT_LINK, "arbiter.sock");
  let data: ArbiterClient | undefined;
  try {
    const t0 = Date.now();
    while (!existsSync(sock) && child.exitCode === null && Date.now() - t0 < 60_000) await sleep(100);
    assert.equal(child.exitCode, null, stderr);
    assert.ok(existsSync(sock), `the daemon did not come up: ${stderr}`);
    data = new ArbiterClient(sock);
    const r = await data.gitHistoryLocks();
    // The axis line follows the preparation line in the log: once it is
    // read, an absent preparation line is absent, not merely late.
    const axis = `[arbiter] confidentiality axis: ${mode === "off" ? "OFF" : "ON"}`;
    while (!stderr.includes(axis) && Date.now() - t0 < 60_000) await sleep(20);
    assert.ok(stderr.includes(axis), stderr);
    check(r, stderr);
  } finally {
    data?.close();
    await stop(child);
  }
}

const OFF_LINE = /git copies prepared ahead of time \(plan 14 §11\.1 R3\): off/;

test(`the real daemon on this host (${process.platform}) ${process.platform === "linux" ? "prepares copies" : "prepares none and says why"}`, { timeout: 120_000 }, async () => {
  await withDaemon("secrets", (r, stderr) => {
    assert.equal(r.axis, true, "secrets mode: the confidentiality axis is ON");
    if (process.platform === "linux") {
      assert.ok(r.preparation !== undefined, `Linux prepares copies: ${JSON.stringify(r)}`);
      assert.doesNotMatch(stderr, OFF_LINE);
    } else {
      assert.equal(r.preparation, undefined, `${process.platform}: no preparation in the answer`);
      assert.equal(r.prepared, undefined);
      assert.match(stderr, new RegExp(`git copies prepared ahead of time \\(plan 14 §11\\.1 R3\\): off: only a Linux launch uses them .*this host is ${process.platform}`));
    }
  });
});

test("mode off, on any host: no resolver, so nothing to prepare, and the daemon does not log that preparation is off", { timeout: 120_000 }, async () => {
  await withDaemon("off", (r, stderr) => {
    assert.equal(r.axis, false);
    assert.equal(r.preparation, undefined);
    assert.equal(r.prepared, undefined);
    assert.doesNotMatch(stderr, OFF_LINE, "the line is for a daemon whose copies could have run");
  });
});
