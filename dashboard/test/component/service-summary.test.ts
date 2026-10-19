/**
 * service-summary e2e — GET /api/control/summary over a REAL Supervisor and
 * DashboardServer (dashboard.md §4.25 Settings): the product page's one row
 * follows the main service through stopped → running, its button's path
 * really starts it, and a helper that crashes on start surfaces only as the
 * one note (a merely stopped helper does not).
 *
 * The supervised children are fakes (node one-liners: a Unix-socket listener
 * for the main service, an immediate exit for the helper), as port-file e2e
 * does, so nothing real is spawned. Axes: none (display only; no arbiter
 * decision is taken). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import { join } from "node:path";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { Supervisor } from "../../src/supervisor/supervisor.js";
import type { ServiceSummary } from "../../src/view-model/service-summary.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../unit/admin-session.js";
import { SERVER_TEST_TIMEOUT_MS, START_DEADLINE_MS } from "./server-up.js";
import { tmpDir } from "../unit/tmp-dir.js";

test("summary: stopped → Start (the named path) → running; a crashed helper adds the note", { timeout: SERVER_TEST_TIMEOUT_MS }, async () => {
  const dir = tmpDir("mandu-svc-summary-");
  const sock = join(dir, "arbiter.sock");
  // Answers every request line with an error, so the supervisor's post-start
  // hello probe settles (identity null) instead of waiting on a silent socket.
  const listen = "require('net').createServer((s) => s.on('data', () => s.write(JSON.stringify({ ok: false, error: 'fake' }) + '\\n'))).listen(process.argv[1]); setInterval(() => {}, 1e9);";
  const supervisor = new Supervisor({
    repoRoot: dir, arbiterSock: sock, autoStartArbiter: false, startTimeoutMs: START_DEADLINE_MS, log: () => {},
    definitions: {
      arbiter: {
        label: "main (fake)", command: process.execPath, args: ["-e", listen, sock], cwd: dir, env: {},
        ready: { kind: "socket", path: sock }, endpoint: sock,
      },
      "net-proxy": {
        label: "helper (fake, exits)", command: process.execPath, args: ["-e", "process.exit(1)"], cwd: dir, env: {},
        ready: { kind: "tcp", host: "127.0.0.1", port: 9 }, endpoint: "127.0.0.1:9",
      },
    },
  });
  const server = new DashboardServer({ source: new FileEventSource(dir), supervisor, log: () => {}, ...ADMIN_OPTS });
  const origin = `http://127.0.0.1:${await server.listen(0)}`;
  const summary = async (): Promise<ServiceSummary> => {
    const res = await fetch(`${origin}/api/control/summary`);
    assert.equal(res.status, 200);
    return ((await res.json()) as { summary: ServiceSummary }).summary;
  };
  try {
    const cold = await summary();
    assert.equal(cold.state, "stopped");
    assert.equal(cold.name, "Stopped");
    assert.equal(cold.helperNote, null, "stopped helpers are not an outage");
    assert.deepEqual(cold.action, { label: "Start", path: "control/arbiter/start", confirm: null }, "Start asks nothing");

    const start = await fetch(`${origin}/api/${cold.action!.path}`, { method: "POST", headers: CSRF_ADMIN });
    assert.equal(start.status, 200, await start.clone().text());
    const warm = await summary();
    assert.equal(warm.state, "running");
    assert.equal(warm.name, "Running");
    assert.equal(warm.action?.label, "Restart");
    assert.match(warm.action?.confirm ?? "", /^Restart Mandu\?/, "Restart carries the question the page asks first");
    assert.equal(typeof warm.since, "number");

    await fetch(`${origin}/api/control/net-proxy/start`, { method: "POST", headers: CSRF_ADMIN });
    const withCrash = await summary();
    assert.match(withCrash.helperNote ?? "", /stopped unexpectedly/);
    assert.equal(withCrash.name, "Running", "the helper's crash does not change the main row");
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("summary without a supervisor: 404, like the rest of the control plane", { timeout: SERVER_TEST_TIMEOUT_MS }, async () => {
  const dir = tmpDir("mandu-svc-summary-none-");
  const server = new DashboardServer({ source: new FileEventSource(dir), log: () => {}, ...ADMIN_OPTS });
  const origin = `http://127.0.0.1:${await server.listen(0)}`;
  try {
    assert.equal((await fetch(`${origin}/api/control/summary`)).status, 404);
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
