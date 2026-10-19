/**
 * remote-allowlist (e2e) — the dashboard's fail-closed source-IP gate over a
 * REAL non-loopback socket (dashboard.md §6 reverse-proxy exposure).
 *
 * Binds a DashboardServer to 0.0.0.0 and connects via one of this host's
 * non-internal interface addresses, so the server sees a genuine non-loopback
 * remoteAddress (connecting to a local interface IP makes the kernel pick that
 * same IP as the source). Asserts the invariant both ways:
 *   - no allowlist          → remote client 403 (fail-closed), loopback 200
 *   - address allowlisted   → remote client 200
 * Skips (never false-greens) on a host with no non-internal IPv4 interface.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";

import { DashboardServer } from "../../src/server.js";
import type { EventSource, SessionRef } from "../../src/event-source.js";
import type { ManduEvent } from "../../src/event-model.js";

const fakeSource: EventSource = {
  async listSessions(): Promise<SessionRef[]> {
    return [];
  },
  async readEvents(): Promise<ManduEvent[]> {
    return [];
  },
  subscribe(): () => void {
    return () => {};
  },
  close(): void {},
};

/** A non-internal IPv4 address of this host (undefined → the suite skips). */
const externalIp = Object.values(os.networkInterfaces())
  .flat()
  .find((i) => i && i.family === "IPv4" && !i.internal)?.address;

describe("dashboard remote source-IP gate (real socket)", { skip: !externalIp }, () => {
  const servers: DashboardServer[] = [];
  after(async () => {
    for (const s of servers) await s.close();
  });

  async function listenAll(allowedClientIps?: string[]): Promise<number> {
    const server = new DashboardServer({ source: fakeSource, allowedClientIps, log: () => {} });
    servers.push(server);
    return server.listen(0, "0.0.0.0");
  }

  it("denies a non-loopback client 403 when no allowlist is configured (fail-closed)", async () => {
    const port = await listenAll();
    const remote = await fetch(`http://${externalIp}:${port}/api/sessions`);
    assert.equal(remote.status, 403);
    assert.equal(await remote.text(), "Forbidden"); // no app detail leaks
    // …including /login: the gate runs before every route.
    const login = await fetch(`http://${externalIp}:${port}/login`);
    assert.equal(login.status, 403);
    // Loopback stays fully served on the same wide bind.
    const local = await fetch(`http://127.0.0.1:${port}/api/sessions`);
    assert.equal(local.status, 200);
  });

  it("admits an allowlisted non-loopback client", async () => {
    const port = await listenAll([externalIp!]);
    const remote = await fetch(`http://${externalIp}:${port}/api/sessions`);
    assert.equal(remote.status, 200);
  });

  it("still denies addresses outside the allowlist on the same server", async () => {
    const port = await listenAll(["203.0.113.7"]); // TEST-NET-3: never this host
    const remote = await fetch(`http://${externalIp}:${port}/api/sessions`);
    assert.equal(remote.status, 403);
  });
});
