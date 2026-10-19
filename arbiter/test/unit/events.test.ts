/**
 * events.test.ts — unit/integration tests for the arbiter observability event
 * stream over a real Unix socket (Mandu-new, no reference origin).
 *
 * Stands up an actual ArbiterServer on a temp socket with a temp event
 * dir, connects real ArbiterClients, and exercises the four event
 * ops:
 *   - emit assigns increasing per-session seq + persists one NDJSON line/event
 *   - events returns since-seq slices in seq order
 *   - sessions lists sessions with counts + ts bounds
 *   - subscribe (on a dedicated connection) delivers the backlog then a
 *     live-pushed event to a SECOND connection while the first client keeps
 *     emitting
 *   - emit rejects events missing id / sessionId
 *
 * Run: npm run test:unit
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

let workdir: string;
let eventDir: string;
let server: ArbiterServer;
let client: ArbiterClient;
/** The human-plane client (arbiter-human-plane.md): events / sessions /
 *  subscribe carry originals and are refused on the data socket, so the
 *  interceptors `emit` on data and the dashboard reads over the human plane. */
let human: ArbiterClient;
let socketPath: string;
let humanPath: string;

before(async () => {
  workdir = mkdtempSync(join(tmpdir(), "mandu-events-"));
  eventDir = join(workdir, "events");
  socketPath = join(workdir, "arbiter.sock");
  humanPath = join(workdir, "human", "h.sock");
  server = new ArbiterServer({
    socketPath,
    humanSocketPath: humanPath,
    dbPath: join(workdir, "symbols.db"),
    eventDir,
    log: () => {}, // silence
  });
  await server.listen();
  client = new ArbiterClient(socketPath);
  await client.connect();
  human = new ArbiterClient(humanPath);
  await human.connect();
});

after(async () => {
  client.close();
  human.close();
  await server.close();
  rmSync(workdir, { recursive: true, force: true });
});

/** Build a minimal-but-valid opaque event (structurally an ManduEvent). */
function ev(sessionId: string, id: string, extra: Record<string, unknown> = {}) {
  return { sessionId, id, ts: new Date().toISOString(), kind: "tllm_call", ...extra };
}

test("emit assigns increasing per-session seq and persists one NDJSON line/event", async () => {
  const s = "sess-emit";
  const seq1 = await client.emit(ev(s, "e1"));
  const seq2 = await client.emit(ev(s, "e2"));
  const seq3 = await client.emit(ev(s, "e3"));
  assert.equal(seq1, 1);
  assert.equal(seq2, 2);
  assert.equal(seq3, 3);

  // Persisted to <eventDir>/<sessionId>.ndjson, one JSON object per line.
  const path = join(eventDir, `${s}.ndjson`);
  assert.ok(existsSync(path), "per-session NDJSON file must exist");
  const lines = readFileSync(path, "utf8").split("\n").filter((l) => l.trim() !== "");
  assert.equal(lines.length, 3, "one line per emitted event");
  const parsed = lines.map((l) => JSON.parse(l));
  assert.deepEqual(parsed.map((p) => p.seq), [1, 2, 3]);
  assert.deepEqual(parsed.map((p) => p.id), ["e1", "e2", "e3"]);
  // The arbiter-assigned seq is merged into the opaque event.
  assert.equal(parsed[0].sessionId, s);
  assert.equal(parsed[0].kind, "tllm_call");
});

test("seq is independent per session", async () => {
  const a = "sess-a";
  const b = "sess-b";
  assert.equal(await client.emit(ev(a, "a1")), 1);
  assert.equal(await client.emit(ev(b, "b1")), 1); // separate counter
  assert.equal(await client.emit(ev(a, "a2")), 2);
  assert.equal(await client.emit(ev(b, "b2")), 2);
});

test("events returns since-seq slices in seq order", async () => {
  const s = "sess-since";
  for (const id of ["x1", "x2", "x3", "x4"]) await client.emit(ev(s, id));

  const all = await human.events(s); // default sinceSeq 0
  assert.deepEqual(all.map((e) => e.seq), [1, 2, 3, 4]);
  assert.deepEqual(all.map((e) => e.id), ["x1", "x2", "x3", "x4"]);

  const after2 = await human.events(s, 2);
  assert.deepEqual(after2.map((e) => e.seq), [3, 4]);

  const afterAll = await human.events(s, 4);
  assert.deepEqual(afterAll, []);
});

test("events on an unknown session returns []", async () => {
  assert.deepEqual(await human.events("no-such-session"), []);
});

test("sessions lists known sessions with counts + ts bounds", async () => {
  const s = "sess-summary";
  const t0 = "2026-01-01T00:00:00.000Z";
  const t1 = "2026-01-01T00:00:01.000Z";
  await client.emit({ sessionId: s, id: "s1", ts: t0, kind: "classify" });
  await client.emit({ sessionId: s, id: "s2", ts: t1, kind: "classify" });

  const sessions = await human.sessions();
  const row = sessions.find((r) => r.sessionId === s);
  assert.ok(row, "summary row for the session must exist");
  assert.equal(row!.count, 2);
  assert.equal(row!.firstTs, t0);
  assert.equal(row!.lastTs, t1);
});

test("subscribe delivers the backlog then a live-pushed event to a second connection", async () => {
  const s = "sess-sub";
  // Pre-existing backlog: two events emitted before anyone subscribes.
  await client.emit(ev(s, "b1"));
  await client.emit(ev(s, "b2"));

  const received: Array<{ id: string; seq: number }> = [];
  // Dedicated subscription connection (separate from `client`'s shared conn).
  const subClient = new ArbiterClient(humanPath);
  const gotLive = deferred<void>();
  const handle = await subClient.subscribe(s, 0, (e) => {
    received.push({ id: String(e.id), seq: e.seq });
    if (e.id === "live1") gotLive.resolve();
  });

  // The one-req-one-res ops keep working on the OTHER connection while the
  // subscription is live: emit a NEW event, which must be pushed to subClient.
  const liveSeq = await client.emit(ev(s, "live1"));
  assert.equal(liveSeq, 3, "live event continues the per-session seq");

  await withTimeout(gotLive.promise, 2000, "live event was not pushed to subscriber");

  // Backlog (b1, b2) arrived first, then the live event (live1), in seq order.
  assert.deepEqual(received, [
    { id: "b1", seq: 1 },
    { id: "b2", seq: 2 },
    { id: "live1", seq: 3 },
  ]);

  handle.close();
  subClient.close();
});

test("subscribe with sinceSeq skips the matching backlog", async () => {
  const s = "sess-sub-since";
  await client.emit(ev(s, "p1"));
  await client.emit(ev(s, "p2"));
  await client.emit(ev(s, "p3"));

  const received: number[] = [];
  const subClient = new ArbiterClient(humanPath);
  const got = deferred<void>();
  const handle = await subClient.subscribe(s, 2, (e) => {
    received.push(e.seq);
    if (e.id === "p4") got.resolve();
  });

  await client.emit(ev(s, "p4")); // seq 4
  await withTimeout(got.promise, 2000, "live event after sinceSeq was not pushed");

  // Backlog filtered to seq>2 → only p3 (seq 3), then live p4 (seq 4).
  assert.deepEqual(received, [3, 4]);

  handle.close();
  subClient.close();
});

test("emit rejects an event missing sessionId", async () => {
  await assert.rejects(
    // @ts-expect-error — deliberately omitting required sessionId
    () => client.emit({ id: "no-session" }),
    /sessionId/,
  );
});

test("emit rejects an event missing id", async () => {
  await assert.rejects(
    // @ts-expect-error — deliberately omitting required id
    () => client.emit({ sessionId: "sess-noid" }),
    /id is required/,
  );
});

test("emit rejects a path-traversal sessionId (no escape from the event dir)", async () => {
  await assert.rejects(
    () => client.emit({ sessionId: "../escape", id: "x" }),
    /sessionId/,
  );
});

test("subscribe sent on a shared one-req-one-res connection is rejected", async () => {
  // Reach past the typed client to send a raw `subscribe` over a normal conn
  // and confirm the arbiter steers callers to a dedicated connection. (The typed
  // client.subscribe() always uses a dedicated socket, so this is the misuse
  // guard.) Note: the connection-layer peek turns ANY `subscribe` line into a
  // stream; the dispatch-level guard covers the in-process dispatch path.
  const verdict = server.dispatch({ id: 7, op: "subscribe", sessionId: "x" });
  assert.equal(verdict.ok, false);
  assert.match((verdict as { error: string }).error, /dedicated connection/);
});

test("a runaway burst of identical events is coalesced before it balloons the log", async () => {
  // Defense-in-depth backstop: emitting 1000 identical events (as the net-proxy
  // self-loop once did 35,723×) must NOT persist 1000 lines. Beyond the verbatim
  // burst they collapse; a distinct event afterwards flushes a `coalesced` summary
  // carrying the suppressed count. Nothing is dropped silently.
  const s = "sess-runaway";
  for (let i = 0; i < 1000; i++) await client.emit(ev(s, `dup-${i}`)); // identical signature
  await client.emit(ev(s, "distinct", { kind: "net_action", destination: "elsewhere:1" }));

  const all = await human.events(s);
  assert.ok(all.length < 200, `the 1000-event runaway shrank to ${all.length} persisted lines`);
  const summaries = all.filter((e) => (e as { action?: string }).action === "coalesced");
  assert.equal(summaries.length, 1, "exactly one run-end coalesced summary");
  assert.equal((summaries[0]!.coalesced as { suppressed: number }).suppressed, 900, "discloses all 900 suppressed");
  // The summary is a canonical, renderable event (valid invariant + ts + id).
  assert.equal((summaries[0]!.invariant as { violatedInvariant: boolean }).violatedInvariant, false);
  assert.equal(typeof summaries[0]!.ts, "string");
  // The distinct event after the run is preserved verbatim.
  assert.ok(all.some((e) => e.id === "distinct"), "the distinct event still persists");
});

test("coalesceEvents:false persists every emit verbatim (the escape hatch)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-nocoalesce-"));
  const sock = join(dir, "b.sock");
  const srv = new ArbiterServer({
    socketPath: sock,
    humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "symbols.db"),
    eventDir: join(dir, "events"),
    coalesceEvents: false,
    log: () => {},
  });
  await srv.listen();
  const cli = new ArbiterClient(sock);
  await cli.connect();
  const humanCli = new ArbiterClient(join(dir, "human", "h.sock"));
  try {
    const s = "sess-raw";
    for (let i = 0; i < 150; i++) await cli.emit({ sessionId: s, id: `r-${i}`, kind: "tllm_call", ts: new Date().toISOString() });
    const all = await humanCli.events(s);
    assert.equal(all.length, 150, "with coalescing off, all 150 identical events persist");
  } finally {
    cli.close();
    humanCli.close();
    await srv.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── tiny async helpers ───────────────────────────────────────────────────────

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void } {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}

function withTimeout<T>(p: Promise<T>, ms: number, msg: string): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) => setTimeout(() => reject(new Error(msg)), ms)),
  ]);
}
