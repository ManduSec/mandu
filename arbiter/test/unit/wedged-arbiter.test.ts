/**
 * wedged-arbiter.test — a WEDGED arbiter must fail CLOSED, not hang.
 *
 * Mandu-new test (no reference origin). The gap this pins was found by the
 * §12 confidentiality oracle (2026-07-12): the first fail-closed test written
 * against an alive-but-unresponsive arbiter did not fail — it HUNG, for five
 * minutes, until the runner killed it.
 *
 * The asymmetry it exposed:
 *   - a DEAD arbiter (socket gone) → `connect` errors → the call rejects → the
 *     caller's catch turns it into its fail-closed answer. Correct.
 *   - a WEDGED arbiter (SIGSTOPped, blocked on disk I/O, wedged on a poison
 *     row) → the socket is still OPEN, so nothing errors and nothing closes.
 *     A reply was the only thing that could settle the request, and no reply is
 *     coming. The await never returns — so the fail-closed `catch` is never
 *     REACHED. The model turn wedges instead of failing closed.
 *
 * Fail-closed is a property of the CALLER's catch block, and a caller that
 * never returns never reaches it. Hence the deadline in ArbiterClient.request().
 * The fs/exec gates already bounded their own awaits; this generalizes the bound
 * to every op of every adapter — classify/symbolize on the proxies' ingress path
 * included, which is what the oracle was actually testing.
 *
 * The fixture is the honest one: a real Unix server that ACCEPTS and never
 * replies. (Testing against an unreachable socket tests the DEAD case — the one
 * that already worked.)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterClient } from "../../ipc/client.js";
import { ArbiterServer } from "../../ipc/server.js";
import { createDefaultPolicyEngine } from "../../policy/policy-interface.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

/** An arbiter that is ALIVE (accepts, holds the connection open) and never
 *  answers a single request. The SIGSTOPped-arbiter simulator. */
function wedgedArbiter(path: string): Promise<{ close: () => Promise<void> }> {
  const socks: net.Socket[] = [];
  const server = net.createServer((sock) => {
    socks.push(sock);
    sock.on("data", () => { /* swallow the request — never reply */ });
    sock.on("error", () => { /* ignore */ });
  });
  return new Promise((resolve) => {
    server.listen(path, () => resolve({
      close: () => new Promise<void>((done) => {
        for (const s of socks) { try { s.destroy(); } catch { /* ignore */ } }
        server.close(() => done());
      }),
    }));
  });
}

function tmpDir(): string {
  return mkdtempSync(join(tmpdir(), "mdu-wedged-"));
}

test("a WEDGED arbiter (accepts, never replies) fails CLOSED within the deadline — it does not hang", async () => {
  const dir = tmpDir();
  const sockPath = join(dir, "arbiter.sock");
  const wedged = await wedgedArbiter(sockPath);
  // Short budget so the test is fast; the production default is 5000ms.
  const client = new ArbiterClient(sockPath, { requestTimeoutMs: 300 });

  try {
    const started = Date.now();
    await assert.rejects(
      // classify is the proxies' INGRESS path — the one the gaps' bound did not
      // cover, because the fs/exec bounds live in the gate helpers, not here.
      () => client.classify({ tool: "Read", field: "content", value: "x" } as never),
      /timed out after 300ms/,
      "a wedged arbiter must REJECT the call, so the caller reaches its fail-closed catch",
    );
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 3000, `must reject promptly, took ${elapsed}ms`);
  } finally {
    client.close();
    await wedged.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("symbolize — the other half of the ingress path — is bounded too", async () => {
  const dir = tmpDir();
  const sockPath = join(dir, "arbiter.sock");
  const wedged = await wedgedArbiter(sockPath);
  const client = new ArbiterClient(sockPath, { requestTimeoutMs: 300 });

  try {
    await assert.rejects(
      () => client.symbolize({ tool: "Read", value: "secret-content", field: "content" }),
      /arbiter symbolize timed out/,
    );
  } finally {
    client.close();
    await wedged.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the deadline does not hold the event loop open past the call", async () => {
  // Regression guard: an un-disarmed timer would keep the process alive for the
  // rest of the window after close() — the exit-guard bug class the `closed`
  // flag was added for. A HEALTHY call must leave no armed timer behind.
  const dir = tmpDir();
  const sockPath = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sockPath,
    policy: createDefaultPolicyEngine(),
    dbPath: join(dir, "arbiter.db"),
    eventDir: join(dir, "events"),
  });
  await server.listen();
  const client = new ArbiterClient(sockPath, { requestTimeoutMs: 60_000 });

  try {
    await client.ping();
    client.close();
    // If the 60s deadline timer were still armed, this handle count would
    // include it. (An armed timer is a live handle regardless of its callback.)
    const timers = (process as unknown as { _getActiveHandles(): unknown[] })
      ._getActiveHandles()
      .filter((h) => h?.constructor?.name === "Timeout");
    assert.equal(timers.length, 0, "no request deadline may outlive its call");
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("server.close() resolves with a LIVE client connection open", async () => {
  // Node's Server.close() only stops the listener: it waits for every
  // established connection to end on its own. With a client connected (the
  // normal state — a proxy holds its ArbiterClient open for the session),
  // close() would never resolve, so the DB handles were never released and the
  // socket file was never unlinked.
  const dir = tmpDir();
  const sockPath = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sockPath,
    policy: createDefaultPolicyEngine(),
    dbPath: join(dir, "arbiter.db"),
    eventDir: join(dir, "events"),
  });
  await server.listen();

  const client = new ArbiterClient(sockPath);
  await client.ping(); // establish for real — a connected, idle client

  try {
    const started = Date.now();
    await Promise.race([
      server.close(),
      new Promise((_, rej) => setTimeout(() => rej(new Error("server.close() hung with a live connection")), 5000)),
    ]);
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 3000, `close() must not wait on live connections, took ${elapsed}ms`);
  } finally {
    client.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("close() rejects the in-flight requests it tears down — fail closed, not silence", async () => {
  const dir = tmpDir();
  const sockPath = join(dir, "arbiter.sock");
  const wedged = await wedgedArbiter(sockPath);
  const client = new ArbiterClient(sockPath, { requestTimeoutMs: 60_000 });

  try {
    const inflight = client.classify({ tool: "Read", field: "content", value: "x" } as never);
    // Let the request reach the (wedged) server before we pull the rug.
    await new Promise((r) => setTimeout(r, 50));
    client.close();
    // The long deadline has NOT elapsed — the rejection must come from the
    // teardown, not the timer. Either way the caller fails closed.
    await assert.rejects(() => inflight, /closed/);
  } finally {
    await wedged.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
