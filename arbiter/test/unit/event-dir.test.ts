/**
 * event-dir.test.ts — the event store's DEFAULT LOCATION rule, the
 * stale-session listing, and the retention-days env knob (Mandu-new, no reference origin; runtime-instances.md §12).
 *
 * The behavior under test is the fix for a live incident: three host reboots
 * on 2026-09-04 erased every session trace and the dashboard's CI-run history
 * because the default event dir sat on the per-boot tmpfs
 * (`${XDG_RUNTIME_DIR}/events`). Pins:
 *   - the rule: ${MANDU_HOME:-$HOME/.mandu}/events (the one home,
 *     on-disk-layout.md §3) — never under XDG_RUNTIME_DIR again, and no
 *     per-path variable moves it (the daemon's --event-dir does);
 *   - staleSessions() judges by mtime, honors the exempt set, and is inert
 *     for maxAge 0 / a missing dir;
 *   - MANDU_EVENT_RETENTION_DAYS parses with a 90-day default and 0 = off.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_EVENT_RETENTION_DAYS,
  EventStore,
  eventRetentionDaysFromEnv,
  getEventDir,
} from "../../events/event-store.js";

const HOUR = 3_600_000;

function line(sessionId: string, seq: number): string {
  return JSON.stringify({ sessionId, id: `${sessionId}-${seq}`, seq, ts: new Date().toISOString() }) + "\n";
}

/** Write a session file and set its mtime `ageMs` in the past. */
function seedSession(dir: string, id: string, ageMs: number): string {
  mkdirSync(dir, { recursive: true });
  const p = join(dir, `${id}.ndjson`);
  writeFileSync(p, line(id, 1) + line(id, 2));
  const t = new Date(Date.now() - ageMs);
  utimesSync(p, t, t);
  return p;
}

// ── the rule ──────────────────────────────────────────────────────────────────

test("getEventDir: MANDU_HOME moves it; the retired MANDU_EVENT_DIR moves nothing", () => {
  assert.equal(getEventDir({ MANDU_HOME: "/mh", HOME: "/h" }), "/mh/events");
  assert.equal(getEventDir({ MANDU_EVENT_DIR: "/pinned/events", XDG_STATE_HOME: "/s", HOME: "/h" }), "/h/.mandu/events");
  assert.equal(getEventDir({ MANDU_EVENT_DIR: "/pinned/events", MANDU_HOME: "/mh", HOME: "/h" }), "/mh/events");
});

test("getEventDir: default is ~/.mandu/events (the one home, on disk), never the runtime dir, whatever XDG says", () => {
  const env = { XDG_STATE_HOME: "/home/u/.local/state", XDG_RUNTIME_DIR: "/run/user/1001", HOME: "/home/u" };
  assert.equal(getEventDir(env), "/home/u/.mandu/events");
  assert.ok(!getEventDir(env).startsWith("/run/user"), "a reboot-wiped tmpfs must never be the default");
});

test("getEventDir: MANDU_HOME moves it; env.HOME is read first", () => {
  assert.equal(getEventDir({ HOME: "/home/u", MANDU_HOME: "/data/mandu" }), "/data/mandu/events");
  assert.equal(getEventDir({ HOME: "/home/u", MANDU_HOME: "" }), "/home/u/.mandu/events");
});

// ── staleSessions ─────────────────────────────────────────────────────────────

test("staleSessions: by mtime — idle files past maxAge are listed, fresh ones and exempt ids are not", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-evstale-"));
  try {
    seedSession(dir, "old-a", 3 * HOUR);
    seedSession(dir, "old-b", 26 * HOUR);
    seedSession(dir, "fresh", 0);
    seedSession(dir, "arbiter-admin", 40 * HOUR);
    writeFileSync(join(dir, "stray.txt"), "x");
    const store = new EventStore(dir);
    assert.deepEqual(store.staleSessions(HOUR, Date.now(), new Set(["arbiter-admin"])), ["old-a", "old-b"]);
    assert.deepEqual(store.staleSessions(HOUR), ["arbiter-admin", "old-a", "old-b"], "no exempt set → the admin stream is eligible too");
    assert.deepEqual(store.staleSessions(50 * HOUR), [], "generous window keeps everything (admin is 40h old)");
    assert.deepEqual(store.staleSessions(0), [], "maxAge 0 = retention off");
    assert.deepEqual(store.staleSessions(-5), []);
    // A live session keeps its mtime fresh by construction: appending renews it.
    store.append({ sessionId: "old-a", id: "renew" });
    assert.deepEqual(store.staleSessions(HOUR, Date.now(), new Set(["arbiter-admin"])), ["old-b"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("staleSessions: a missing dir lists nothing", () => {
  const store = new EventStore(join(tmpdir(), "mandu-evstale-missing-" + Math.random().toString(36).slice(2)));
  assert.deepEqual(store.staleSessions(HOUR), []);
});

// ── the env knob ──────────────────────────────────────────────────────────────

test("eventRetentionDaysFromEnv: default 90, 0 disables, garbage/negative fall back to the default", () => {
  assert.equal(DEFAULT_EVENT_RETENTION_DAYS, 90);
  assert.equal(eventRetentionDaysFromEnv({}), 90);
  assert.equal(eventRetentionDaysFromEnv({ MANDU_EVENT_RETENTION_DAYS: "" }), 90);
  assert.equal(eventRetentionDaysFromEnv({ MANDU_EVENT_RETENTION_DAYS: " 30 " }), 30);
  assert.equal(eventRetentionDaysFromEnv({ MANDU_EVENT_RETENTION_DAYS: "0.5" }), 0.5);
  assert.equal(eventRetentionDaysFromEnv({ MANDU_EVENT_RETENTION_DAYS: "0" }), 0);
  assert.equal(eventRetentionDaysFromEnv({ MANDU_EVENT_RETENTION_DAYS: "forever" }), 90);
  assert.equal(eventRetentionDaysFromEnv({ MANDU_EVENT_RETENTION_DAYS: "-3" }), 90);
});
