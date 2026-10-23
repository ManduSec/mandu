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
import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";
import { once } from "node:events";
import { existsSync, readFileSync } from "node:fs";
import { createServer, type Socket } from "node:net";

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

/** How long a SIGTERMed server may take over its graceful exit (it stops
 *  the services it supervises, each with its own grace) before the SIGKILL. */
export const STOP_GRACE_MS = 30_000;

/**
 * Start `server-main.ts` as THE spawned process: `node --import tsx`, never
 * the tsx CLI. The CLI relays a SIGTERM to its child and SIGKILLs it unless
 * the child reports the signal back within 30 ms (tsx 4 `relaySignals`),
 * which a loaded run misses: the server then died without its exit path, and
 * the services its supervisor had started (detached, each in its own process
 * group) outlived it (dashboard.md §4.8, *A start under way when the
 * dashboard exits*). `opts.cwd` must reach a `tsx` in its node_modules.
 */
export function spawnServer(serverMain: string, opts: SpawnOptions): ChildProcess {
  return spawn(process.execPath, ["--import", "tsx", serverMain], opts);
}

/** Has `child` exited, or does it within `ms`? */
function exitWithin(child: ChildProcess, ms: number): Promise<boolean> {
  const gone = (): boolean => child.exitCode !== null || child.signalCode !== null;
  if (gone()) return Promise.resolve(true);
  return new Promise((resolve) => {
    const onExit = (): void => { clearTimeout(timer); resolve(true); };
    const timer = setTimeout(() => { child.off("exit", onExit); resolve(gone()); }, ms);
    child.once("exit", onExit);
  });
}

/**
 * Wait (up to `deadlineMs`) for a server expected to exit on its own (a
 * start-up refusal), and for its output pipes to end: `exit` can come before
 * a pipe's last line has been read, and the server is the spawned process
 * itself (spawnServer), so no wrapper's exit comes after it.
 */
export async function waitForExit(child: ChildProcess, deadlineMs = START_DEADLINE_MS): Promise<void> {
  const end = Date.now() + deadlineMs;
  await exitWithin(child, deadlineMs);
  const open = [child.stdout, child.stderr].filter((s) => s !== null && !s.closed);
  await Promise.all(open.map((s) => new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, Math.max(0, end - Date.now()));
    s!.once("close", () => { clearTimeout(timer); resolve(); });
  })));
}

/**
 * Stop a spawned server and wait for it: SIGTERM, then SIGKILL once
 * `graceMs` passes, its exit awaited either way. Then this process lets go
 * of the child's pipes, so a grandchild still holding their other end cannot
 * keep the test file's process alive. Asserts that the child is gone.
 */
export async function stopServer(child: ChildProcess, graceMs = STOP_GRACE_MS): Promise<void> {
  if (!(await exitWithin(child, 0))) {
    child.kill("SIGTERM");
    if (!(await exitWithin(child, graceMs))) {
      child.kill("SIGKILL");
      await exitWithin(child, graceMs);
    }
  }
  for (const s of [child.stdin, child.stdout, child.stderr]) s?.destroy();
  assert.ok(child.exitCode !== null || child.signalCode !== null, `the server (pid ${child.pid}) exited`);
}

/**
 * A stand-in arbiter on `sockPath` that accepts and never answers (the
 * dashboard's boot only awaits socket connects). `close()` also ends every
 * connection it accepted: `Server.close()` alone leaves them open, and one
 * held by a process the test never stopped (an orphaned proxy that dialled
 * this socket) kept the test file's process alive until the suite's
 * deadline.
 */
export async function silentArbiter(sockPath: string): Promise<{ close: () => Promise<void> }> {
  const conns = new Set<Socket>();
  const server = createServer((s) => {
    conns.add(s);
    s.on("close", () => conns.delete(s));
    s.on("data", () => {});
    s.on("error", () => {});
  });
  server.listen(sockPath);
  await once(server, "listening");
  return {
    close: async () => {
      for (const s of conns) s.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
