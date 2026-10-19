/**
 * lifeline.test (e2e) — the REAL arbiter daemon honors the lifeline
 * (ipc/lifeline.ts; runtime-instances.md §8): spawned with
 * MANDU_LIFELINE=stdin and a pipe, it runs the SAME graceful shutdown as
 * SIGTERM when the pipe's write end closes (its spawner died — even SIGKILL),
 * and WITHOUT the env a closed stdin is ignored (the shared stack must outlive
 * launchers; a leaked pipe must not fell it).
 *
 * Run: npm run test:component
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { connect } from "node:net";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_MAIN = join(ARBITER_DIR, "ipc", "server-main.ts");
const TSX = join(ARBITER_DIR, "node_modules", ".bin", "tsx");

// Bounds are DEADLINES, not expected durations: every wait below returns as
// soon as its condition holds (~1 s on an idle host). They are generous
// because the per-push CI runs ~16 suites at once (continuous-integration.md), and
// there a cold `tsx` start of the daemon plus its graceful close can take tens
// of seconds; the old fixed 10 s start poll and 15 s exit race timed the
// suite out there while it stayed green alone.
const START_DEADLINE_MS = 90_000;
const EXIT_DEADLINE_MS = 60_000;
const TEST_TIMEOUT_MS = 240_000;

async function pollUntil(check: () => boolean, deadlineMs: number, delayMs = 100): Promise<boolean> {
  const end = Date.now() + deadlineMs;
  while (Date.now() < end) {
    if (check()) return true;
    await new Promise((r) => setTimeout(r, delayMs));
  }
  return check();
}

/** The daemon's last startup line: it registers its instance, then (in the
 *  same synchronous run) arms the lifeline or not. Waiting for the socket
 *  alone raced the stderr read below (the socket exists before these lines). */
const READY = /\[arbiter\] (pinned socket .* registered as instance|instance \S+ (PROMOTED|NOT promoted|\(un-promoted))/;

/** Resolve the exit code, or null after `ms` (the timer never outlives it). */
function exitWithin(child: ChildProcess, ms: number): Promise<number | null> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(child.exitCode);
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), ms);
    child.once("exit", (code) => { clearTimeout(timer); resolve(code); });
  });
}

/** Tear a spawned daemon down WITHOUT orphaning it: SIGTERM first (tsx relays
 *  it to the node child that runs the daemon; a bare SIGKILL of tsx left that
 *  child alive holding our stderr pipe, so a failed run hung the whole file
 *  until the runner's timeout), SIGKILL only if it ignores that, and drop our
 *  pipe ends so a straggler can never keep this test process alive. */
async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGTERM");
    if (await exitWithin(child, 20_000) === null) child.kill("SIGKILL");
  }
  child.stdin?.destroy();
  child.stderr?.destroy();
  child.unref();
}

/** Does the daemon still accept a connection on its socket? */
function accepts(sock: string): Promise<boolean> {
  return new Promise((resolve) => {
    const s = connect(sock);
    s.once("connect", () => { s.destroy(); resolve(true); });
    s.once("error", () => resolve(false));
  });
}

function spawnArbiter(dir: string, lifeline: boolean): { child: ChildProcess; sock: string; stderr: () => string } {
  const sock = join(dir, "arbiter.sock");
  let err = "";
  const child = spawn(TSX, [SERVER_MAIN, sock], {
    cwd: ARBITER_DIR,
    env: {
      ...process.env,
      MANDU_HOME: join(dir, "home"),
      // Pinned arbiters register a registry-only instance dir — keep it in
      // the test's tmp tree, never the host's real runtime base.
      MANDU_RUNTIME_DIR: join(dir, "mandu"),
      ...(lifeline ? { MANDU_LIFELINE: "stdin" } : { MANDU_LIFELINE: undefined as unknown as string }),
    },
    stdio: ["pipe", "ignore", "pipe"],
  });
  child.stderr!.on("data", (d) => { err += String(d); });
  return { child, sock, stderr: () => err };
}

test("lifeline armed: closing the pipe shuts the daemon down gracefully", { timeout: TEST_TIMEOUT_MS }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-"));
  const { child, sock, stderr } = spawnArbiter(dir, true);
  try {
    assert.ok(await pollUntil(() => /lifeline armed/.test(stderr()), START_DEADLINE_MS),
      `the daemon came up and reported the armed lifeline (stderr: ${stderr()})`);
    assert.ok(existsSync(sock), "the socket is up");

    child.stdin!.end(); // the spawner "dies": the only write end closes
    const code = await exitWithin(child, EXIT_DEADLINE_MS);
    assert.notEqual(code, null, "daemon exited after the lifeline was severed");
    assert.equal(code, 0, `graceful shutdown (stderr: ${stderr()})`);
    assert.match(stderr(), /lifeline EOF/, "shutdown attributed to the lifeline");
  } finally {
    await stop(child);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("no env: a closed stdin does NOT fell the daemon (shared-stack semantics)", { timeout: TEST_TIMEOUT_MS }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-"));
  const { child, sock, stderr } = spawnArbiter(dir, false);
  try {
    // READY is printed in the same synchronous run that would arm the lifeline.
    assert.ok(await pollUntil(() => READY.test(stderr()) && existsSync(sock), START_DEADLINE_MS),
      `arbiter came up (stderr: ${stderr()})`);
    assert.doesNotMatch(stderr(), /lifeline armed/);

    let exited = false;
    child.once("exit", () => { exited = true; });
    child.stdin!.end();
    await new Promise((r) => setTimeout(r, 1_500));
    assert.equal(exited, false, "daemon survived the closed stdin (it is not lifeline-bound)");
    assert.ok(await accepts(sock), "and it still serves its socket");
    assert.doesNotMatch(stderr(), /lifeline EOF/);

    // Normal teardown still works.
    child.kill("SIGTERM");
    assert.ok(await pollUntil(() => exited, EXIT_DEADLINE_MS), "daemon exits on SIGTERM");
  } finally {
    await stop(child);
    rmSync(dir, { recursive: true, force: true });
  }
});
