/**
 * arbiter-source-sessions.test — ArbiterEventSource.listSessions / readEvents against a
 *   MOCK arbiter socket: parsing (incl. sinceSeq paging + the computed `violated`
 *   flag), the (count,lastTs) memoization, and the sidebar list's scale + fault
 *   isolation (dashboard.md §3.3).
 *
 * Mandu-new test (NO reference origin). The mock arbiter and canned events
 * live in arbiter-source-fixtures.ts (split out of the former
 * arbiter-source.test.ts).
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";

import { ArbiterEventSource } from "../../src/event-source.js";
import type { ManduEvent } from "../../src/event-model.js";
import { ev, HEALTHY, startMockArbiter, startSharedFixtures, type MockArbiter } from "./arbiter-source-fixtures.js";

// ── Shared fixtures ───────────────────────────────────────────────────────────

let arbiter: MockArbiter;
let source: ArbiterEventSource;

before(async () => {
  ({ arbiter, source } = await startSharedFixtures());
});

after(async () => {
  source.close();
  await arbiter.close();
});

// ── 1. listSessions / readEvents parse correctly ──────────────────────────────

test("ArbiterEventSource.listSessions maps arbiter summaries to SessionRefs (+violated)", async () => {
  const sessions = await source.listSessions();
  const ids = sessions.map((s) => s.id);
  assert.ok(ids.includes("sess-live"));
  assert.ok(ids.includes("sess-bad"));

  const live = sessions.find((s) => s.id === "sess-live")!;
  assert.equal(live.eventCount, 3);
  assert.equal(live.lastTs, "2026-06-14T10:00:02.000Z");
  assert.equal(live.violated, false);

  const bad = sessions.find((s) => s.id === "sess-bad")!;
  assert.equal(bad.eventCount, 2);
  assert.equal(bad.violated, true, "violated flag computed from the session's events");

  // Most-recent session first.
  assert.equal(sessions[0]!.id, "sess-live");
});

test("ArbiterEventSource.listSessions exposes batchId from a session's events", async () => {
  const sessions = await source.listSessions();
  const batched = sessions.find((s) => s.id === "sess-batch")!;
  assert.equal(batched.batchId, "run-7", "batchId is read from the arbiter session's events");
  const live = sessions.find((s) => s.id === "sess-live")!;
  assert.equal(live.batchId, undefined, "a session whose events carry no batchId has none");
});

test("ArbiterEventSource.readEvents parses + canonically sorts the arbiter events", async () => {
  const events = await source.readEvents("sess-live");
  assert.equal(events.length, 3);
  assert.deepEqual(events.map((e) => e.id), ["e0", "e1", "e2"]);
  assert.equal(events[2]!.kind, "tool_result");
});

test("ArbiterEventSource.readEvents honors sinceSeq paging", async () => {
  const events = await source.readEvents("sess-live", 0);
  assert.deepEqual(events.map((e) => e.seq), [1, 2]);
  assert.ok(events.every((e) => e.seq > 0));
  const none = await source.readEvents("sess-live", 99);
  assert.equal(none.length, 0);
});

test("ArbiterEventSource.readEvents tolerates an unknown session", async () => {
  const events = await source.readEvents("nope");
  assert.deepEqual(events, []);
});

// ── 5. listSessions memoization: only changed sessions re-fetch events ─────────

test("listSessions memoizes SessionRef derivations by (count,lastTs); only changed sessions re-fetch", async () => {
  const store: Record<string, ManduEvent[]> = {
    "memo-a": [ev({ id: "a0", sessionId: "memo-a", seq: 0, ts: "2026-06-14T12:00:00.000Z" })],
    "memo-b": [
      ev({ id: "b0", sessionId: "memo-b", seq: 0, ts: "2026-06-14T12:01:00.000Z" }),
      ev({ id: "b1", sessionId: "memo-b", seq: 1, ts: "2026-06-14T12:01:01.000Z" }),
    ],
  };
  const mock = await startMockArbiter(store);
  const src = new ArbiterEventSource({ socketPath: mock.socketPath });
  try {
    const eventOps = () => mock.opLog.filter((o) => o.startsWith("events:"));

    await src.listSessions();
    assert.equal(eventOps().length, 2, "cold list derives every session from its events");

    mock.opLog.length = 0;
    const warm = await src.listSessions();
    assert.equal(eventOps().length, 0, "unchanged sessions answer from the ref cache");
    assert.equal(warm.find((s) => s.id === "memo-b")!.eventCount, 2);

    // Growth in ONE session (a new event, and a violating one at that): exactly
    // that session re-fetches, and its derivations refresh.
    store["memo-b"]!.push(
      ev({
        id: "b2", sessionId: "memo-b", seq: 2, ts: "2026-06-14T12:01:05.000Z",
        kind: "tool_result",
        invariant: { violatedInvariant: true, detail: "unsymbolized" },
      }),
    );
    mock.opLog.length = 0;
    const after = await src.listSessions();
    assert.deepEqual(eventOps(), ["events:memo-b"], "only the changed session re-fetches");
    const b = after.find((s) => s.id === "memo-b")!;
    assert.equal(b.eventCount, 3);
    assert.equal(b.lastTs, "2026-06-14T12:01:05.000Z");
    assert.equal(b.violated, true, "refreshed derivation sees the new violating event");
    assert.equal(after.find((s) => s.id === "memo-a")!.violated, false);

    // A vanished session drops out of the listing (cache evicted, not resurrected).
    delete store["memo-a"];
    const final = await src.listSessions();
    assert.deepEqual(final.map((s) => s.id), ["memo-b"]);
  } finally {
    src.close();
    await mock.close();
  }
});

test("listSessions marks a session whose agent exited (`exited`, dashboard.md §4.10.4); a stale ref kept while the replay fails never keeps the mark", async () => {
  const store: Record<string, ManduEvent[]> = {
    "sess-ended": [
      ...[...HEALTHY].map((e) => ({ ...e, sessionId: "sess-ended" })),
      ev({ id: "x3", sessionId: "sess-ended", seq: 3, ts: "2026-06-14T10:00:03.000Z", kind: "session_exit", view: "HumanView", emitter: "launcher" }),
    ],
    "sess-going": [...HEALTHY].map((e) => ({ ...e, sessionId: "sess-going" })),
  };
  const mock = await startMockArbiter(store);
  const src = new ArbiterEventSource({ socketPath: mock.socketPath, connectTimeoutMs: 300 });
  const quiet = console.error;
  console.error = () => {};
  try {
    const first = await src.listSessions();
    assert.equal(first.find((s) => s.id === "sess-ended")!.exited, true, "the recorded exit marks the row");
    assert.equal(first.find((s) => s.id === "sess-going")!.exited, undefined, "no exit, no mark");

    // The log grows (the agent resumed) while its replay wedges: the last
    // derived ref is kept for its label and verdicts, but its exit is stale.
    mock.hang.add("sess-ended");
    store["sess-ended"]!.push(ev({ id: "x4", sessionId: "sess-ended", seq: 4, ts: "2026-06-14T10:05:00.000Z", kind: "tllm_call" }));
    const stale = (await src.listSessions()).find((s) => s.id === "sess-ended")!;
    assert.equal(stale.eventCount, 5, "the summary's current count");
    assert.equal(stale.lastTs, "2026-06-14T10:05:00.000Z");
    assert.equal(stale.exited, undefined, "a stale ref never claims the agent exited");

    // The replay answers again: derived from the events, activity after the exit.
    mock.hang.delete("sess-ended");
    assert.equal((await src.listSessions()).find((s) => s.id === "sess-ended")!.exited, undefined, "activity after the exit: not exited");
  } finally {
    console.error = quiet;
    src.close();
    await mock.close();
  }
});

// ── 6. Scale + fault isolation of the sidebar list (dashboard.md §3.3, 2026-09-17) ──

test("listSessions frames a 16 MB single-line `events` reply in linear time (well inside the 5 s default deadline)", async () => {
  // The live shape: one long interactive session whose `events` reply is ONE
  // ~16 MB NDJSON line. The old per-chunk buffer re-scan was quadratic (6–7 s
  // measured, past the 5 s default deadline → /api/sessions 500 → an EMPTY
  // rail although every session was logged). Linear framing lands it in
  // well under a second; the bound below rules the quadratic shape out.
  const big: ManduEvent[] = [];
  const blob = "z".repeat(64 * 1024);
  for (let i = 0; i < 256; i++) {
    big.push(ev({ id: `big-${i}`, sessionId: "sess-huge", seq: i, ts: `2026-09-17T05:${String(i % 60).padStart(2, "0")}:00.000Z`,
      input: { symbolized: `${i}:${blob}`, original: null, differs: false, symbols: [] } }));
  }
  const mock = await startMockArbiter({ "sess-huge": big, "sess-small": [...HEALTHY] });
  // Calibrate against THIS host right now: one linear pass over the same
  // bytes (encode, decode, find the newline, parse) is ~100 ms idle. Linear
  // framing costs a small multiple of it; the quadratic shape far more.
  // The regression is CPU work (a re-scan per chunk), so both sides are
  // measured as this process's CPU time (the mock arbiter and the client
  // both run here), never wall time: under the loaded CI guest a linear
  // listing waited 2.4 s for a core while its calibration had run in 98 ms
  // (2026-10-02, pipeline 8108), and waiting is no framing bug. Same
  // measure as the arbiter's twin (arbiter/test/unit/ipc.test.ts, 2026-09-29).
  const cpuMsSince = (c: NodeJS.CpuUsage): number => {
    const d = process.cpuUsage(c);
    return (d.user + d.system) / 1000;
  };
  const line = JSON.stringify({ ok: true, result: big }) + "\n";
  const c0 = process.cpuUsage();
  JSON.parse(Buffer.from(line).toString("utf8").slice(0, line.indexOf("\n")));
  const linearMs = Math.max(1, cpuMsSince(c0));
  // Measured 2026-10-02 in CPU time: the linear listing costs ~2.4× the
  // pass (≈220 ms over ≈92 ms), the quadratic idiom ~27× (≈2.5 s). 12× sits
  // between them with room on both sides.
  const boundMs = Math.max(1000, 12 * linearMs);
  // The product default is 5 s of wall time; the read gets a generous
  // deadline so the CPU bound below, not the deadline, decides the verdict.
  const src = new ArbiterEventSource({ socketPath: mock.socketPath, connectTimeoutMs: 90_000 });
  try {
    const t0 = process.cpuUsage();
    const sessions = await src.listSessions();
    const cpuMs = cpuMsSince(t0);
    const huge = sessions.find((s) => s.id === "sess-huge");
    assert.ok(huge, "the 16 MB session is listed");
    assert.equal(huge!.eventCount, 256);
    assert.ok(huge!.label?.startsWith("0:zzz"), "label derived from the replayed events");
    assert.ok(sessions.some((s) => s.id === "sess-small"));
    assert.ok(
      cpuMs < boundMs,
      `listSessions cost ${cpuMs.toFixed(0)} ms of CPU over a 16 MB reply; one linear pass cost ${linearMs.toFixed(0)} ms here, bound ${boundMs.toFixed(0)} ms (quadratic framing costs ~27× a linear pass)`,
    );
  } finally {
    src.close();
    await mock.close();
  }
});

test("listSessions keeps listing when ONE session's replay wedges: summary-only row, retried next poll", async () => {
  const store: Record<string, ManduEvent[]> = {
    "sess-ok": [...HEALTHY].map((e) => ({ ...e, sessionId: "sess-ok" })),
    "sess-wedged": [
      ev({ id: "w0", sessionId: "sess-wedged", seq: 0, ts: "2026-09-17T06:00:00.000Z",
        input: { symbolized: "fix the sidebar", original: null, differs: false, symbols: [] } }),
      ev({ id: "w1", sessionId: "sess-wedged", seq: 1, ts: "2026-09-17T06:00:01.000Z", kind: "tool_result",
        invariant: { violatedInvariant: true, detail: "x" } }),
    ],
  };
  const mock = await startMockArbiter(store);
  // A short deadline so the wedged replay fails fast (the default is 5 s).
  const src = new ArbiterEventSource({ socketPath: mock.socketPath, connectTimeoutMs: 300 });
  const quiet = console.error;
  const logged: string[] = [];
  console.error = (...a: unknown[]) => { logged.push(a.map(String).join(" ")); };
  try {
    mock.hang.add("sess-wedged");
    const first = await src.listSessions(); // must NOT reject
    const wedged = first.find((s) => s.id === "sess-wedged");
    assert.ok(wedged, "the wedged session is still a row (from its summary)");
    assert.equal(wedged!.eventCount, 2, "counts come from the summary");
    assert.equal(wedged!.lastTs, "2026-09-17T06:00:01.000Z");
    assert.equal(wedged!.label, null, "no events → no label");
    assert.equal(wedged!.violated, false, "no events → nothing to flag (yet)");
    assert.equal(first.find((s) => s.id === "sess-ok")!.eventCount, 3, "the healthy session is fully derived");
    assert.equal(logged.filter((l) => l.includes("sess-wedged")).length, 1, "the failure is logged");

    // Second poll while still wedged: no second log line (one per streak).
    await src.listSessions();
    assert.equal(logged.filter((l) => l.includes("sess-wedged")).length, 1, "logged once per failure streak");

    // Un-wedge: the next poll derives it fully (nothing was cached for it).
    mock.hang.delete("sess-wedged");
    const healed = (await src.listSessions()).find((s) => s.id === "sess-wedged")!;
    assert.equal(healed.violated, true, "derived from the events once the replay answers");
    assert.equal(healed.label, "fix the sidebar");

    // Wedge AGAIN after a successful derivation: the last good ref is kept
    // (stale label/verdicts) rather than downgraded to the summary stub.
    mock.hang.add("sess-wedged");
    store["sess-wedged"]!.push(ev({ id: "w2", sessionId: "sess-wedged", seq: 2, ts: "2026-09-17T06:00:02.000Z" }));
    const stale = (await src.listSessions()).find((s) => s.id === "sess-wedged")!;
    assert.equal(stale.label, "fix the sidebar", "last derived label survives a later wedge");
    assert.equal(stale.violated, true);
    assert.equal(stale.eventCount, 3, "…with the CURRENT count from the summary");
    assert.equal(stale.lastTs, "2026-09-17T06:00:02.000Z");
  } finally {
    console.error = quiet;
    src.close();
    await mock.close();
  }
});
