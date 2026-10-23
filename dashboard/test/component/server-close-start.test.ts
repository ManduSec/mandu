/**
 * server-close-start.test — E2E over the real DashboardServer and the real
 * Supervisor: the dashboard's exit (`DashboardServer.close()`, what
 * server-main's SIGTERM handler runs) leaves no service behind that was
 * still being started when it began (dashboard.md §4.8, *A start under way
 * when the dashboard exits*, 2026-10-23).
 *
 * The autostart's start is held before its spawn (the bundle check every
 * spawn of a bundled definition awaits, as the hello probe held it in the
 * incident), the server closes, and only then does the wait end: no process
 * is spawned, the start fails, and a service that was running is stopped.
 * Fake services (node one-liners) stand in for the arbiter and a proxy.
 * Axes: none (process control only; no arbiter decision is taken).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { Supervisor, type ServiceDefinition } from "../../src/supervisor/supervisor.js";
import type { BundleFreshness } from "../../src/supervisor/supervisor-defs.js";
import { ADMIN_OPTS } from "../unit/admin-session.js";
import { tmpDir } from "../unit/tmp-dir.js";
import { pollUntil, SERVER_TEST_TIMEOUT_MS, START_DEADLINE_MS } from "./server-up.js";

/** Writes its pid to FAKE_MARK, then listens on FAKE_SOCK. */
const MARK_SCRIPT = `
const net = require('net');
const fs = require('fs');
fs.writeFileSync(process.env.FAKE_MARK, String(process.pid));
try { fs.unlinkSync(process.env.FAKE_SOCK); } catch {}
net.createServer(() => {}).listen(process.env.FAKE_SOCK);
setInterval(() => {}, 1e9);
`;

function fakeDef(dir: string, name: string, bundled: boolean): { def: ServiceDefinition; mark: string } {
  const sock = join(dir, `${name}.sock`);
  const mark = join(dir, `${name}.spawned`);
  const args = ["-e", MARK_SCRIPT];
  return {
    mark,
    def: {
      label: `Fake ${name}`, command: process.execPath, args, cwd: dir,
      env: { FAKE_SOCK: sock, FAKE_MARK: mark },
      ready: { kind: "socket", path: sock }, endpoint: sock,
      ...(bundled ? { checkoutBundle: { command: process.execPath, args, cwd: dir, env: {}, distDir: join(dir, "dist"), repoRoot: dir } } : {}),
    },
  };
}

const alive = (pid: number): boolean => {
  try { process.kill(pid, 0); return true; } catch { return false; }
};

test("the dashboard's close() during the autostart: the service still before its spawn never starts; the running one is stopped", { timeout: SERVER_TEST_TIMEOUT_MS }, async () => {
  const dir = tmpDir("mandu-close-start-");
  const arbiter = fakeDef(dir, "arbiter", false);
  const proxy = fakeDef(dir, "proxy", true);
  let onReached!: () => void;
  let release!: () => void;
  const reached = new Promise<void>((r) => { onReached = r; });
  const held = new Promise<void>((r) => { release = r; });
  const supervisor = new Supervisor({
    repoRoot: dir, arbiterSock: join(dir, "arbiter.sock"), startTimeoutMs: START_DEADLINE_MS, stopGraceMs: 5_000, log: () => {},
    definitions: { arbiter: arbiter.def, "anthropic-proxy": proxy.def },
    bundleFresh: async (): Promise<BundleFreshness> => { onReached(); await held; return { fresh: false, reason: "held by the test" }; },
  });
  const server = new DashboardServer({ source: new FileEventSource(dir), supervisor, log: () => {}, ...ADMIN_OPTS });
  await server.listen(0);
  let closed = false;
  try {
    await supervisor.start("arbiter");
    const arbiterPid = supervisor.status().find((s) => s.id === "arbiter")!.pid!;
    // The autostart's order: the arbiter is up, a proxy's start waits before its spawn.
    const starting = supervisor.start("anthropic-proxy");
    starting.catch(() => { /* asserted below */ });
    await reached;

    await server.close();
    closed = true;
    assert.ok(await pollUntil(() => !alive(arbiterPid), START_DEADLINE_MS), "the running service is stopped");

    release();
    await assert.rejects(starting, /not started: the dashboard is shutting down/);
    await new Promise((r) => setTimeout(r, 300));
    assert.ok(!existsSync(proxy.mark), "the proxy was never spawned: nothing outlives the dashboard");
    assert.equal(supervisor.status().find((s) => s.id === "anthropic-proxy")!.state, "stopped");
  } finally {
    release();
    if (!closed) await server.close();
    await supervisor.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
