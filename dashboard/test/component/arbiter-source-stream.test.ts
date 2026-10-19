/**
 * arbiter-source-stream.test — ArbiterEventSource.subscribe against a MOCK arbiter
 *   socket (backlog then live, the close handle stops delivery), and the
 *   dashboard API server fed by it: /api/sessions + /api/events, and an
 *   appended event pushed over /api/stream end-to-end (incl. ?sinceSeq=).
 *
 * Mandu-new test (NO reference origin). The mock arbiter and canned events
 * live in arbiter-source-fixtures.ts (split out of the former
 * arbiter-source.test.ts).
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";

import { DashboardServer } from "../../src/server.js";
import { ArbiterEventSource } from "../../src/event-source.js";
import type { ManduEvent } from "../../src/event-model.js";
import { ev, LIVE_EVENT, startSharedFixtures, type MockArbiter } from "./arbiter-source-fixtures.js";

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

// ── 2. subscribe: backlog then live, close handle stops it ─────────────────────

test("ArbiterEventSource.subscribe delivers backlog then a live event; close stops it", async () => {
  const received: ManduEvent[] = [];
  const unsubscribe = source.subscribe("sess-live", (e) => received.push(e));

  // Backlog (the 3 existing events) should arrive shortly after connect.
  await waitFor(() => received.length >= 3, "backlog not delivered");
  assert.deepEqual(received.map((e) => e.id), ["e0", "e1", "e2"]);
  await waitFor(() => arbiter.subscriberCount() >= 1, "stream not registered");

  // A pushed live event arrives over the same connection.
  arbiter.pushLive("sess-live", LIVE_EVENT);
  await waitFor(() => received.length >= 4, "live event not delivered");
  assert.equal(received[3]!.id, "e3");

  // The close handle tears the stream down: the arbiter drops the subscriber and
  // a subsequent push is NOT delivered.
  unsubscribe();
  await waitFor(() => arbiter.subscriberCount() === 0, "stream not torn down by close handle");
  arbiter.pushLive("sess-live", ev({ id: "e4", seq: 4, ts: "2026-06-14T10:00:04.000Z" }));
  await delay(50);
  assert.equal(received.length, 4, "no events delivered after unsubscribe");
});

// ── 3. full dashboard API e2e fed by ArbiterEventSource ─────────────────────────

test("DashboardServer over ArbiterEventSource: /api/sessions + /api/events + /api/stream e2e", async () => {
  const e2eSource = new ArbiterEventSource({ socketPath: arbiter.socketPath });
  const server = new DashboardServer({ source: e2eSource, log: () => {} });
  const port = await server.listen(0);
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // REST: /api/sessions
    const sres = await fetch(`${baseUrl}/api/sessions`);
    assert.equal(sres.status, 200);
    const sbody = (await sres.json()) as { sessions: { id: string; violated: boolean }[] };
    assert.ok(sbody.sessions.some((s) => s.id === "sess-live"));
    assert.equal(sbody.sessions.find((s) => s.id === "sess-bad")!.violated, true);

    // REST: /api/events returns raw events + derived view-model.
    const eres = await fetch(`${baseUrl}/api/events?session=sess-live`);
    assert.equal(eres.status, 200);
    const ebody = (await eres.json()) as { events: ManduEvent[]; viewModel: { invariant: { holds: boolean } } };
    assert.deepEqual(ebody.events.map((e) => e.id), ["e0", "e1", "e2"]);
    assert.equal(ebody.viewModel.invariant.holds, true);

    // SSE: /api/stream relays appended events end-to-end. The subscribe stream
    // replays the backlog as `append` frames first (a browser dedupes by id),
    // then the pushed live event; assert the live event reaches the SSE client.
    // The dashboard writes its SSE `hello` frame before its arbiter subscribe
    // socket has registered on the arbiter, so wait for the arbiter subscriber
    // first, then push (and keep pushing) the live event.
    const before = arbiter.subscriberCount();
    const live = ev({ id: "stream1", seq: 10, ts: "2026-06-14T10:01:00.000Z" });
    const got = await streamAwaitAppend(`${baseUrl}/api/stream?session=sess-live`, "stream1", async () => {
      await waitFor(() => arbiter.subscriberCount() > before, "dashboard did not register a arbiter subscriber");
      arbiter.pushLive("sess-live", live);
    });
    assert.equal(got.id, "stream1", "the appended event reached the SSE client");
  } finally {
    await server.close();
  }
});

test("DashboardServer /api/stream forwards ?sinceSeq= so the backlog is NOT replayed", async () => {
  // The dashboard client fetches a session's events via /api/events BEFORE it
  // opens the SSE stream, so it tells the server the highest seq it already has.
  // /api/stream must forward that as the subscribe `sinceSeq`, making the backlog
  // (seq > sinceSeq) empty — otherwise the arbiter replays EVERY event as an
  // `append` and the client's per-append re-render storms the page (the flicker
  // bug). sess-live = e0(0),e1(1),e2(2); sinceSeq=2 ⇒ zero backlog appends, and a
  // pushed live e3(3) still arrives.
  const e2eSource = new ArbiterEventSource({ socketPath: arbiter.socketPath });
  const server = new DashboardServer({ source: e2eSource, log: () => {} });
  const port = await server.listen(0);
  const baseUrl = `http://127.0.0.1:${port}`;
  let pushTimer: ReturnType<typeof setInterval> | undefined;
  try {
    const live = ev({ id: "live-after", seq: 3, ts: "2026-06-14T10:01:00.000Z" });
    // Push the live event on a short interval until the SSE client receives it:
    // this rides out the arbiter-subscriber registration window without depending
    // on a (racy) subscriberCount delta against prior tests' teardown. The source
    // de-dupes by seq, so re-pushing the same seq-3 event never double-emits.
    const { backlogIds, live: got } = await streamCollectThenAwait(
      `${baseUrl}/api/stream?session=sess-live&sinceSeq=2`,
      "live-after",
      () => {
        pushTimer = setInterval(() => arbiter.pushLive("sess-live", live), 25);
      },
    );
    assert.deepEqual(backlogIds, [], "no backlog events should replay when sinceSeq covers them");
    assert.equal(got.id, "live-after", "a genuinely new (post-sinceSeq) event still streams through");
  } finally {
    if (pushTimer) clearInterval(pushTimer);
    await server.close();
  }
});

// ── helpers ────────────────────────────────────────────────────────────────────

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Open an SSE stream; collect every `event: append` id that arrives BEFORE the
 * one matching `wantId` (the backlog), then resolve once `wantId` arrives. Lets a
 * test assert exactly which backlog events the relay replayed. Mirrors
 * streamAwaitAppend but surfaces the pre-`wantId` ids too.
 */
async function streamCollectThenAwait(
  url: string,
  wantId: string,
  trigger: () => void | Promise<void>,
): Promise<{ backlogIds: string[]; live: ManduEvent }> {
  const ac = new AbortController();
  const res = await fetch(url, { signal: ac.signal, headers: { Accept: "text/event-stream" } });
  assert.equal(res.status, 200);
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  let triggered = false;
  const backlogIds: string[] = [];
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) throw new Error(`stream closed before append id=${wantId}`);
      buf += decoder.decode(value, { stream: true });
      if (!triggered && buf.includes("event: hello")) {
        triggered = true;
        // Swallow trigger errors here so a failing trigger surfaces as the read
        // loop's eventual timeout rather than an unhandledRejection that hangs
        // the whole runner.
        Promise.resolve()
          .then(trigger)
          .catch(() => {});
      }
      let sep: number;
      while ((sep = buf.indexOf("\n\n")) >= 0) {
        const record = buf.slice(0, sep);
        buf = buf.slice(sep + 2);
        if (!record.startsWith("event: append")) continue;
        const m = /data: (.+)/.exec(record);
        if (!m) continue;
        const event = JSON.parse(m[1]!) as ManduEvent;
        if (event.id === wantId) return { backlogIds, live: event };
        backlogIds.push(event.id);
      }
    }
  } finally {
    ac.abort();
    reader.cancel().catch(() => {});
  }
}

async function waitFor(cond: () => boolean, msg: string, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error(`timeout: ${msg}`);
    await delay(10);
  }
}

/**
 * Open an SSE connection, run `trigger` once the stream is live (after the
 * `hello` frame), and resolve with the `event: append` payload whose id matches
 * `wantId` (skipping any backlog appends that arrive first). Uses the fetch
 * streaming body so it exercises the real /api/stream relay path.
 */
async function streamAwaitAppend(
  url: string,
  wantId: string,
  trigger: () => void | Promise<void>,
): Promise<ManduEvent> {
  const ac = new AbortController();
  const res = await fetch(url, { signal: ac.signal, headers: { Accept: "text/event-stream" } });
  assert.equal(res.status, 200);
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  let triggered = false;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) throw new Error(`stream closed before append id=${wantId}`);
      buf += decoder.decode(value, { stream: true });
      // Once the hello frame is seen the subscription is opening → fire the
      // trigger (which itself waits for the arbiter subscriber to register).
      if (!triggered && buf.includes("event: hello")) {
        triggered = true;
        void Promise.resolve(trigger());
      }
      // Consume complete SSE records (separated by a blank line); scan each
      // `event: append` for the wanted id.
      let sep: number;
      while ((sep = buf.indexOf("\n\n")) >= 0) {
        const record = buf.slice(0, sep);
        buf = buf.slice(sep + 2);
        if (!record.startsWith("event: append")) continue;
        const m = /data: (.+)/.exec(record);
        if (!m) continue;
        const event = JSON.parse(m[1]!) as ManduEvent;
        if (event.id === wantId) return event;
      }
    }
  } finally {
    ac.abort();
    reader.cancel().catch(() => {});
  }
}
