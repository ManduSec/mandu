/**
 * server-up — wait for a spawned `server-main.ts` to publish its bound port
 * (MANDU_PORT_FILE, written atomically), for the e2e files that start the REAL
 * entrypoint.
 *
 * The bound is a DEADLINE, not an expected duration: the wait returns as soon
 * as the port file lands (about a second on an idle host) and fails fast when
 * the server exits first. It is generous because the per-push CI runs ~16
 * suites at once (docs/design/testing/continuous-integration.md), and there a cold `tsx`
 * start of the server can take far longer than the old fixed 15 s poll: the
 * local-full-3 run failed `server came up (stderr: )` with the server simply
 * not started yet. Same pattern as arbiter/test/component/lifeline.test.ts.
 */
import assert from "node:assert/strict";
import type { ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

/** How long a loaded machine may take to start the server. */
export const START_DEADLINE_MS = 90_000;
/** A test that starts the server once: the start deadline plus its own work. */
export const SERVER_TEST_TIMEOUT_MS = 180_000;

/** Poll `check` every `delayMs` until it holds or `deadlineMs` passes. */
export async function pollUntil(check: () => boolean, deadlineMs: number, delayMs = 100): Promise<boolean> {
  const end = Date.now() + deadlineMs;
  while (Date.now() < end) {
    if (check()) return true;
    await new Promise((r) => setTimeout(r, delayMs));
  }
  return check();
}

/** The port `portFile` names, once the server has published it; asserts
 *  (with the server's stderr) when it exits first or the deadline passes. */
export async function waitForPort(
  portFile: string,
  child: ChildProcess,
  stderr: () => string,
  deadlineMs = START_DEADLINE_MS,
): Promise<number> {
  const gone = (): boolean => child.exitCode !== null || child.signalCode !== null;
  await pollUntil(() => existsSync(portFile) || gone(), deadlineMs);
  assert.ok(existsSync(portFile),
    `server came up (${gone() ? `it exited first: ${child.exitCode ?? child.signalCode}` : `not within ${deadlineMs} ms`}; stderr: ${stderr()})`);
  const port = Number(readFileSync(portFile, "utf8"));
  assert.ok(Number.isInteger(port) && port > 0, `a bound port in the port file (${port})`);
  return port;
}
