/**
 * event-retention.test.ts — the arbiter's observability retention sweep over
 * a real Unix socket (Mandu-new, no reference origin; runtime-instances.md
 * §12). Mirrors delete-session.test.ts: a real ArbiterServer on a temp socket
 * + real ArbiterClients.
 *
 * Pins the contract (ArbiterServerOptions.eventRetentionMs):
 *   - listen() runs one sweep immediately: files idle past the window are
 *     gone before the first client connects (a daemon that was down for
 *     weeks catches up at boot); fresh files and the reserved `arbiter-admin`
 *     stream survive;
 *   - the sweep goes through the deleteSession path: a live subscribe stream
 *     on a pruned session is ENDED, and a later emit to the reused id starts
 *     back at seq 1 without reaching the stale subscriber;
 *   - the periodic timer fires (short cadence here) and is unref'd — the
 *     process exits without the test having to clear it;
 *   - with no retention option nothing is ever pruned (every existing test's
 *     server keeps today's behavior);
 *   - retention is observability-only: the symbol table is untouched.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ADMIN_SESSION_ID, ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const HOUR = 3_600_000;
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function seed(dir: string, id: string, ageMs: number): string {
  mkdirSync(dir, { recursive: true });
  const p = join(dir, `${id}.ndjson`);
  writeFileSync(p, JSON.stringify({ sessionId: id, id: `${id}-1`, seq: 1, ts: new Date().toISOString() }) + "\n");
  const t = new Date(Date.now() - ageMs);
  utimesSync(p, t, t);
  return p;
}

interface Rig { workdir: string; eventDir: string; server: ArbiterServer; client: ArbiterClient; logs: string[] }

async function rig(opts: { retentionMs?: number; sweepMs?: number }): Promise<Rig> {
  const workdir = mkdtempSync(join(tmpdir(), "mandu-retention-"));
  const eventDir = join(workdir, "events");
  const logs: string[] = [];
  const server = new ArbiterServer({
    socketPath: join(workdir, "arbiter.sock"),
    humanSocketPath: join(workdir, "human", "h.sock"),
    dbPath: join(workdir, "symbols.db"),
    eventDir,
    eventRetentionMs: opts.retentionMs,
    eventRetentionSweepMs: opts.sweepMs,
    log: (m) => logs.push(m),
  });
  // The observability store (sessions / subscribe) is read over the human
  // plane (arbiter-human-plane.md), as the dashboard does.
  return { workdir, eventDir, server, client: new ArbiterClient(join(workdir, "human", "h.sock")), logs };
}

async function teardown(r: Rig): Promise<void> {
  try { await r.client.close(); } catch { /* ignore */ }
  try { await r.server.close(); } catch { /* ignore */ }
  rmSync(r.workdir, { recursive: true, force: true });
}

test("listen() sweeps once: idle sessions removed, fresh + admin kept, one log line names them", async () => {
  const r = await rig({ retentionMs: 24 * HOUR, sweepMs: 10 * HOUR });
  try {
    const old = seed(r.eventDir, "old-session", 30 * HOUR);
    seed(r.eventDir, "fresh-session", HOUR);
    const admin = seed(r.eventDir, ADMIN_SESSION_ID, 60 * HOUR);
    await r.server.listen();
    assert.ok(!existsSync(old), "idle session file removed at boot");
    assert.ok(existsSync(admin), "the audit stream is exempt however old");
    const ids = (await r.client.sessions()).map((s) => s.sessionId).sort();
    assert.deepEqual(ids, [ADMIN_SESSION_ID, "fresh-session"]);
    const l = r.logs.find((m) => m.startsWith("retention:"));
    assert.ok(l && /removed 1 session\(s\) idle > 1d: old-session/.test(l), `log line: ${l}`);
  } finally {
    await teardown(r);
  }
});

test("pruning goes through the deleteSession path: live stream ended, reused id restarts at seq 1", async () => {
  const r = await rig({ retentionMs: 24 * HOUR, sweepMs: 10 * HOUR });
  try {
    await r.server.listen();
    await r.client.emit({ sessionId: "s-live", id: "e1" });
    await r.client.emit({ sessionId: "s-live", id: "e2" });
    const seen: number[] = [];
    const sub = await r.client.subscribe("s-live", 0, (e) => seen.push(e.seq));
    await sleep(150);
    assert.deepEqual(seen, [1, 2], "backlog delivered");
    // Age the file behind the store's back (the sweep judges by mtime).
    const t = new Date(Date.now() - 48 * HOUR);
    utimesSync(join(r.eventDir, "s-live.ndjson"), t, t);
    assert.deepEqual(r.server.pruneStaleSessions(), ["s-live"]);
    assert.ok(!existsSync(join(r.eventDir, "s-live.ndjson")));
    // The reused id starts fresh (seq 1) and the stale subscriber sees nothing.
    const seq = await r.client.emit({ sessionId: "s-live", id: "e3" });
    assert.equal(seq, 1);
    await sleep(150);
    assert.deepEqual(seen, [1, 2], "ended stream received no further events");
    sub.close();
    assert.deepEqual(r.server.pruneStaleSessions(), [], "a just-written file is not stale");
  } finally {
    await teardown(r);
  }
});

test("the periodic sweep fires on its own (short cadence) and is unref'd", async () => {
  const r = await rig({ retentionMs: HOUR, sweepMs: 40 });
  try {
    await r.server.listen();
    const p = seed(r.eventDir, "goes-stale", 0);
    assert.deepEqual((await r.client.sessions()).map((s) => s.sessionId), ["goes-stale"]);
    const t = new Date(Date.now() - 2 * HOUR);
    utimesSync(p, t, t);
    const t0 = Date.now();
    while (existsSync(p) && Date.now() - t0 < 2000) await sleep(20);
    assert.ok(!existsSync(p), "timer sweep removed the aged file");
    assert.deepEqual(await r.client.sessions(), []);
  } finally {
    await teardown(r); // close() clears the timer; unref means it would not have held the process anyway
  }
});

test("no retention option → nothing is ever pruned (pruneStaleSessions is inert)", async () => {
  const r = await rig({});
  try {
    const old = seed(r.eventDir, "ancient", 365 * 24 * HOUR);
    await r.server.listen();
    assert.ok(existsSync(old));
    assert.deepEqual(r.server.pruneStaleSessions(), []);
    assert.ok(existsSync(old));
    assert.deepEqual((await r.client.sessions()).map((s) => s.sessionId), ["ancient"]);
    assert.equal(r.logs.filter((m) => m.startsWith("retention:")).length, 0);
  } finally {
    await teardown(r);
  }
});

test("retention is observability-only: symbols survive the sweep", async () => {
  const r = await rig({ retentionMs: HOUR, sweepMs: 10 * HOUR });
  try {
    await r.server.listen();
    const sym = await r.client.symbolize({ tool: "web_fetch", field: "content", value: "untrusted body" });
    await r.client.emit({ sessionId: "s-sym", id: "e1" });
    const t = new Date(Date.now() - 2 * HOUR);
    utimesSync(join(r.eventDir, "s-sym.ndjson"), t, t);
    assert.deepEqual(r.server.pruneStaleSessions(), ["s-sym"]);
    // Same value → same symbol (content-addressed reuse) proves the table
    // still holds the allocation the sweep must never touch.
    const again = await r.client.symbolize({ tool: "web_fetch", field: "content", value: "untrusted body" });
    assert.match(sym, /^\$MDU:/, "a real symbol was allocated");
    assert.equal(again, sym, "symbol table untouched by the event sweep");
  } finally {
    await teardown(r);
  }
});
