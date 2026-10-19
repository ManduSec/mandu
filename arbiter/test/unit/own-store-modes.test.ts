/**
 * The stores of originals are owner-only (docs/design/architecture/on-disk-layout.md §1,
 * §3): the symbol DB (every `$MDU:` placeholder's original) and the event log
 * (`DualRepr.original`). Before 2026-09-29 neither set a mode, so SQLite's
 * 0644 and a 0775 `~/.mandu` let any local user read the originals.
 *
 * Which directories are Mandu's own comes from the path table, resolved in
 * the env given (a temp HOME here): the one home's `state/` and `events/`
 * with the home above them. Any other directory keeps its mode, the older
 * layouts' included (a clean start, on-disk-layout.md §6).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openSymbolDb, ownDbDirs } from "../../symbol-table/symbol-table.js";
import { EventStore, ownEventDirs } from "../../events/event-store.js";

const mode = (p: string): number => statSync(p).mode & 0o777;

function scratch(): { dir: string; env: NodeJS.ProcessEnv; done: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-modes-"));
  return { dir, env: { HOME: dir }, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("symbol DB: a new ~/.mandu/state is 0700 under a 0700 home, and the DB, its WAL and SHM are 0600", () => {
  const { dir, env, done } = scratch();
  try {
    const home = join(dir, ".mandu");
    const state = join(home, "state");
    const db = openSymbolDb(join(state, "mandu.db"), env);
    db.exec("CREATE TABLE IF NOT EXISTS t (x TEXT); INSERT INTO t VALUES ('secret');");
    assert.equal(mode(home), 0o700);
    assert.equal(mode(state), 0o700);
    for (const f of ["mandu.db", "mandu.db-wal", "mandu.db-shm"]) assert.equal(mode(join(state, f)), 0o600, f);
    db.close();
  } finally {
    done();
  }
});

test("symbol DB: a loose home, state/ and DB left by an older version are tightened on open", () => {
  const { dir, env, done } = scratch();
  try {
    const home = join(dir, ".mandu");
    const state = join(home, "state");
    const path = join(state, "mandu.db");
    openSymbolDb(path, env).close();
    chmodSync(home, 0o775);
    chmodSync(state, 0o755);
    chmodSync(path, 0o644);
    openSymbolDb(path, env).close();
    assert.equal(mode(home), 0o700);
    assert.equal(mode(state), 0o700);
    assert.equal(mode(path), 0o600);
  } finally {
    done();
  }
});

test("symbol DB: MANDU_HOME names the home the rule tightens", () => {
  const { dir, env, done } = scratch();
  try {
    const home = join(dir, "custom-home");
    const state = join(home, "state");
    mkdirSync(state, { recursive: true, mode: 0o755 });
    chmodSync(home, 0o755);
    chmodSync(state, 0o755);
    openSymbolDb(join(state, "mandu.db"), { ...env, MANDU_HOME: home }).close();
    assert.equal(mode(home), 0o700);
    assert.equal(mode(state), 0o700);
  } finally {
    done();
  }
});

test("symbol DB: a --symbol-db directory outside the home keeps its mode; the DB file is still 0600", () => {
  const { dir, env, done } = scratch();
  try {
    const shared = join(dir, "shared");
    mkdirSync(shared);
    chmodSync(shared, 0o755);
    openSymbolDb(join(shared, "arb.db"), env).close();
    assert.equal(mode(shared), 0o755);
    assert.equal(mode(join(shared, "arb.db")), 0o600);
    // A directory that merely ends in `state` is not Mandu's.
    const other = join(dir, "work", "state");
    mkdirSync(other, { recursive: true });
    chmodSync(other, 0o755);
    openSymbolDb(join(other, "mandu.db"), env).close();
    assert.equal(mode(other), 0o755);
  } finally {
    done();
  }
});

test("ownDbDirs: the table's state/ and home; nothing else", () => {
  const env = { HOME: "/h" };
  assert.deepEqual(ownDbDirs("/h/.mandu/state", env), ["/h/.mandu/state", "/h/.mandu"]);
  assert.deepEqual(ownDbDirs("/m/state", { ...env, MANDU_HOME: "/m" }), ["/m/state", "/m"]);
  // The retired MANDU_SYMBOL_DB changes nothing.
  assert.deepEqual(ownDbDirs("/elsewhere", { ...env, MANDU_SYMBOL_DB: "/elsewhere/x.db" }), []);
  for (const d of ["/h", "/h/.mandu", "/h/work/state", "/h/.local/state/mandu", "/elsewhere"]) assert.deepEqual(ownDbDirs(d, env), [], d);
});

test("event log: a new ~/.mandu/events is 0700, a record file 0600; a loose one and its home are tightened", () => {
  const { dir, env, done } = scratch();
  try {
    const home = join(dir, ".mandu");
    const events = join(home, "events");
    new EventStore(events, env).append({ sessionId: "s1", id: "a", ts: "2026-09-29T00:00:00Z", note: "original" });
    assert.equal(mode(events), 0o700);
    assert.equal(mode(home), 0o700);
    assert.equal(mode(join(events, "s1.ndjson")), 0o600);

    chmodSync(home, 0o775);
    chmodSync(events, 0o775);
    new EventStore(events, env).append({ sessionId: "s1", id: "b", ts: "2026-09-29T00:00:01Z" });
    assert.equal(mode(events), 0o700);
    assert.equal(mode(home), 0o700);

    const test = join(events, "test");
    mkdirSync(test, { recursive: true });
    chmodSync(test, 0o775);
    chmodSync(events, 0o775);
    new EventStore(test, env).append({ sessionId: "s2", id: "c", ts: "2026-09-29T00:00:02Z" });
    assert.equal(mode(test), 0o700, "the test tenant's dir too");
    assert.equal(mode(events), 0o700, "and the events dir above it");
  } finally {
    done();
  }
});

test("event log: an --event-dir outside the home keeps its mode; record files are still 0600", () => {
  const { dir, env, done } = scratch();
  try {
    const custom = join(dir, "my-events");
    mkdirSync(custom);
    chmodSync(custom, 0o755);
    new EventStore(custom, env).append({ sessionId: "s1", id: "a", ts: "2026-09-29T00:00:00Z" });
    assert.equal(mode(custom), 0o755);
    assert.equal(mode(join(custom, "s1.ndjson")), 0o600);
    // A directory named like Mandu's but not at the table's path is not Mandu's.
    const lookalike = join(dir, "srv", "mandu", "events");
    mkdirSync(lookalike, { recursive: true });
    chmodSync(lookalike, 0o755);
    new EventStore(lookalike, env).append({ sessionId: "s1", id: "a", ts: "2026-09-29T00:00:00Z" });
    assert.equal(mode(lookalike), 0o755);
  } finally {
    done();
  }
});

test("ownEventDirs: the table's events (+ home), events/test (+ events, home); nothing else", () => {
  const env = { HOME: "/h" };
  assert.deepEqual(ownEventDirs("/h/.mandu/events", env), ["/h/.mandu/events", "/h/.mandu"]);
  assert.deepEqual(ownEventDirs("/h/.mandu/events/test", env), ["/h/.mandu/events/test", "/h/.mandu/events", "/h/.mandu"]);
  assert.deepEqual(ownEventDirs("/m/events", { ...env, MANDU_HOME: "/m" }), ["/m/events", "/m"]);
  // The retired MANDU_EVENT_DIR changes nothing.
  assert.deepEqual(ownEventDirs("/pinned", { ...env, MANDU_EVENT_DIR: "/pinned" }), []);
  for (const d of ["/pinned", "/h/.mandu", "/srv/mandu/events", "/h/events", "/h/.local/state/mandu/events"]) assert.deepEqual(ownEventDirs(d, env), [], d);
  assert.deepEqual(ownEventDirs("/x/mandu/events-test", { ...env, XDG_STATE_HOME: "/x" }), [], "XDG_STATE_HOME places nothing");
});
