/**
 * event-store-cache.test.ts — the incremental sessions() summary cache
 * (Mandu-new, no reference origin).
 *
 * sessions() must cost one stat per unchanged file and parse only appended
 * suffixes — but its OBSERVABLE contract is unchanged from the pre-cache full
 * scan. These tests drive the store directly (no socket) through the shapes the
 * cache must survive: warm re-list, growth via the store AND via an external
 * O_APPEND writer, torn tails completed later, multi-byte UTF-8 (byte-domain
 * offsets), same-id file replacement, truncation, and delete().
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { EventStore } from "../../events/event-store.js";

function freshStore(): { store: EventStore; dir: string; done: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-evcache-"));
  return { store: new EventStore(dir), dir, done: () => rmSync(dir, { recursive: true, force: true }) };
}

function line(sessionId: string, id: string, seq: number, ts: string | null): string {
  const o: Record<string, unknown> = { sessionId, id, seq };
  if (ts !== null) o.ts = ts;
  return JSON.stringify(o) + "\n";
}

test("warm re-list is stable and appends update count/lastTs (incl. UTF-8 payloads)", () => {
  const { store, done } = freshStore();
  try {
    store.append({ sessionId: "s1", id: "a", ts: "2026-07-18T01:00:00Z", note: "🔑 emoji payload 😈" });
    store.append({ sessionId: "s1", id: "b", ts: "2026-07-18T01:00:01Z" });

    const first = store.sessions();
    assert.deepEqual(first, [
      { sessionId: "s1", count: 2, firstTs: "2026-07-18T01:00:00Z", lastTs: "2026-07-18T01:00:01Z" },
    ]);
    // Unchanged file → cached path must return the identical summary.
    assert.deepEqual(store.sessions(), first);

    // Growth after a warm cache: multi-byte content before this append must not
    // skew the byte-domain resume offset.
    store.append({ sessionId: "s1", id: "c", ts: "2026-07-18T01:00:02Z", note: "더 많은 데이터" });
    assert.deepEqual(store.sessions(), [
      { sessionId: "s1", count: 3, firstTs: "2026-07-18T01:00:00Z", lastTs: "2026-07-18T01:00:02Z" },
    ]);
  } finally {
    done();
  }
});

test("an external O_APPEND writer's lines are picked up on the next list", () => {
  const { store, dir, done } = freshStore();
  try {
    store.append({ sessionId: "ext", id: "a", ts: "2026-07-18T02:00:00Z" });
    assert.equal(store.sessions()[0]!.count, 1);

    appendFileSync(join(dir, "ext.ndjson"), line("ext", "b", 2, "2026-07-18T02:00:05Z"));
    assert.deepEqual(store.sessions(), [
      { sessionId: "ext", count: 2, firstTs: "2026-07-18T02:00:00Z", lastTs: "2026-07-18T02:00:05Z" },
    ]);
  } finally {
    done();
  }
});

test("a torn tail is excluded until its newline lands, then counted exactly once", () => {
  const { store, dir, done } = freshStore();
  try {
    const path = join(dir, "torn.ndjson");
    writeFileSync(path, line("torn", "a", 1, "2026-07-18T03:00:00Z"));
    const partial = JSON.stringify({ sessionId: "torn", id: "b", seq: 2, ts: "2026-07-18T03:00:01Z" });
    appendFileSync(path, partial.slice(0, 25)); // no newline: a record mid-write

    assert.equal(store.sessions()[0]!.count, 1);

    appendFileSync(path, partial.slice(25) + "\n"); // writer finishes the record
    assert.deepEqual(store.sessions(), [
      { sessionId: "torn", count: 2, firstTs: "2026-07-18T03:00:00Z", lastTs: "2026-07-18T03:00:01Z" },
    ]);
  } finally {
    done();
  }
});

test("replacing a session file (smaller, different content) resyncs from scratch", () => {
  const { store, dir, done } = freshStore();
  try {
    const path = join(dir, "swap.ndjson");
    writeFileSync(
      path,
      line("swap", "a", 1, "2026-07-18T04:00:00Z") +
        line("swap", "b", 2, "2026-07-18T04:00:01Z") +
        line("swap", "c", 3, "2026-07-18T04:00:02Z"),
    );
    assert.equal(store.sessions()[0]!.count, 3);

    unlinkSync(path);
    writeFileSync(path, line("swap", "z", 1, "2026-07-18T05:00:00Z"));
    assert.deepEqual(store.sessions(), [
      { sessionId: "swap", count: 1, firstTs: "2026-07-18T05:00:00Z", lastTs: "2026-07-18T05:00:00Z" },
    ]);
  } finally {
    done();
  }
});

test("a truncated (shrunk) file falls back to a full re-parse", () => {
  const { store, dir, done } = freshStore();
  try {
    const path = join(dir, "trunc.ndjson");
    writeFileSync(path, line("trunc", "a", 1, "2026-07-18T06:00:00Z") + line("trunc", "b", 2, "2026-07-18T06:00:01Z"));
    assert.equal(store.sessions()[0]!.count, 2);

    writeFileSync(path, line("trunc", "only", 7, "2026-07-18T06:30:00Z")); // in-place shrink
    assert.deepEqual(store.sessions(), [
      { sessionId: "trunc", count: 1, firstTs: "2026-07-18T06:30:00Z", lastTs: "2026-07-18T06:30:00Z" },
    ]);
  } finally {
    done();
  }
});

test("delete() forgets the session; garbage-only and vanished files stay unlisted", () => {
  const { store, dir, done } = freshStore();
  try {
    store.append({ sessionId: "gone", id: "a", ts: "2026-07-18T07:00:00Z" });
    store.append({ sessionId: "stays", id: "a", ts: "2026-07-18T07:00:01Z" });
    writeFileSync(join(dir, "garbage.ndjson"), "not json at all\n{also broken\n");
    assert.deepEqual(
      store.sessions().map((s) => s.sessionId),
      ["gone", "stays"],
    );

    assert.equal(store.delete("gone"), true);
    assert.deepEqual(
      store.sessions().map((s) => s.sessionId),
      ["stays"],
    );

    // External rm (no delete() call): evicted on the next list, others intact.
    unlinkSync(join(dir, "stays.ndjson"));
    assert.deepEqual(store.sessions(), []);
  } finally {
    done();
  }
});

test("events without ts keep null bounds through the cached path", () => {
  const { store, done } = freshStore();
  try {
    const stored = store.append({ sessionId: "nots", id: "a" });
    assert.equal(stored.seq, 1);
    assert.deepEqual(store.sessions(), [{ sessionId: "nots", count: 1, firstTs: null, lastTs: null }]);
    store.append({ sessionId: "nots", id: "b", ts: "2026-07-18T08:00:00Z" });
    assert.deepEqual(store.sessions(), [
      { sessionId: "nots", count: 2, firstTs: "2026-07-18T08:00:00Z", lastTs: "2026-07-18T08:00:00Z" },
    ]);
  } finally {
    done();
  }
});
