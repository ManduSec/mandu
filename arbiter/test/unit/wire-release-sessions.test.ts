/**
 * wire-release-sessions — the session's word that its egress proxy inspects
 * TLS (plan 10 §11.13.1, `registerWireRelease`), kept across an arbiter
 * restart while the launcher that gave it runs (2026-10-17):
 *   - a word with a live launcher pid is written to mandu.db and taken back
 *     by a new store on the same file; one whose launcher is gone, or whose
 *     pid now belongs to another process (a new start time), is not, and its
 *     row is pruned at the next write;
 *   - a word without a pid, or with a pid this process cannot see, stays in
 *     memory only (and removes an older row of the session);
 *   - `clear` (the session's end) drops it in memory and on disk; with a pid,
 *     only that launcher's word;
 *   - a stored row is read as data: malformed hosts are none, a malformed
 *     list drops the row.
 *
 * No arbiter is built (the store alone, with liveness seams), so no axes
 * are stated; the restart through the real arbiter and net-proxy is
 * tests/stack/wire-release-restart.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "../../db/sqlite.js";
import { MAX_DIRECT_HOSTS, WireReleaseStore, parseDirectHosts } from "../../secret-registry/wire-release-sessions.js";

function withDb(fn: (dbPath: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "mandu-wire-sessions-"));
  try {
    fn(join(dir, "mandu.db"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Liveness seams: `alive` maps a pid to its start time (absent = gone). */
function seams(alive: Map<number, string>) {
  return { pidExists: (pid: number) => alive.has(pid), procStartTime: (pid: number) => alive.get(pid) ?? null };
}

test("a live launcher's word survives a new store on the same mandu.db; a gone or reused pid's does not", () => {
  withDb((dbPath) => {
    const alive = new Map([[100, "t100"], [200, "t200"], [300, "t300"]]);
    const a = new WireReleaseStore({ dbPath, ...seams(alive) });
    a.set("sess-live", ["127.0.0.1", "llm.lan"], 100);
    a.set("sess-gone", [], 200);
    a.set("sess-reused", [], 300);
    assert.deepEqual(a.get("sess-live"), { direct: ["127.0.0.1", "llm.lan"] });
    assert.equal(a.persisted().length, 3);
    a.close();

    alive.delete(200); // that launch ended
    alive.set(300, "t300-other"); // the pid now names another process
    const b = new WireReleaseStore({ dbPath, ...seams(alive) });
    assert.equal(b.restored, 1);
    assert.deepEqual(b.get("sess-live"), { direct: ["127.0.0.1", "llm.lan"] }, "the live session keeps npm on the twin");
    assert.equal(b.get("sess-gone"), undefined, "an ended launch's word is not taken back (npm reads raw: fail-closed)");
    assert.equal(b.get("sess-reused"), undefined, "a reused pid is no proof of the launcher");
    // The next write prunes the dead launchers' rows.
    b.set("sess-other", [], 100);
    assert.deepEqual(b.persisted().map((r) => r.sessionKey).sort(), ["sess-live", "sess-other"]);
    b.close();
  });
});

test("a word with no pid, or a pid this process cannot see, is memory only, and replaces the session's older row", () => {
  withDb((dbPath) => {
    const alive = new Map([[100, "t100"]]);
    const a = new WireReleaseStore({ dbPath, ...seams(alive) });
    a.set("sess-a", [], 100);
    a.set("sess-a", ["10.0.0.1"]); // an older launcher's word: no pid
    a.set("sess-b", [], 4242); // not visible here
    assert.deepEqual(a.get("sess-a"), { direct: ["10.0.0.1"] });
    assert.ok(a.get("sess-b"));
    assert.deepEqual(a.persisted(), [], "nothing on disk");
    a.close();
    const b = new WireReleaseStore({ dbPath, ...seams(alive) });
    assert.equal(b.restored, 0);
    assert.equal(b.get("sess-a"), undefined);
    assert.equal(b.get("sess-b"), undefined);
    b.close();
  });
});

test("the session's end drops the word in memory and on disk; with a pid, only that launcher's word", () => {
  withDb((dbPath) => {
    const alive = new Map([[100, "t100"], [101, "t101"]]);
    const a = new WireReleaseStore({ dbPath, ...seams(alive) });
    a.set("sess", [], 101); // a later launch under the same key
    assert.equal(a.clear("sess", 100), false, "another launcher's end leaves it");
    assert.ok(a.get("sess"));
    assert.equal(a.clear("sess", 101), true);
    assert.equal(a.get("sess"), undefined);
    assert.deepEqual(a.persisted(), []);
    a.set("sess2", [], 100);
    assert.equal(a.clear("sess2"), true, "no pid: cleared whoever gave it");
    assert.equal(a.clear("never"), false);
    a.close();
    const b = new WireReleaseStore({ dbPath, ...seams(alive) });
    assert.equal(b.restored, 0, "an ended session is not taken back");
    b.close();
  });
});

test("a stored row is data: hosts that are no strings are dropped, a list that does not parse drops the row", () => {
  withDb((dbPath) => {
    const alive = new Map([[100, "t100"]]);
    new WireReleaseStore({ dbPath, ...seams(alive) }).close();
    const raw = new Database(dbPath);
    const ins = raw.prepare("INSERT INTO wire_release_sessions (session_key, direct, pid, pid_start, registered_at) VALUES (?, ?, ?, ?, ?)");
    ins.run("sess-mixed", JSON.stringify(["ok.example", 7, null, "b.example"]), 100, "t100", 1);
    ins.run("sess-bad", "{not json", 100, "t100", 2);
    ins.run("", "[]", 100, "t100", 3);
    raw.close();
    const s = new WireReleaseStore({ dbPath, ...seams(alive) });
    assert.equal(s.restored, 1);
    assert.deepEqual(s.get("sess-mixed"), { direct: ["ok.example", "b.example"] });
    assert.equal(s.get("sess-bad"), undefined);
    s.close();
  });
});

test("parseDirectHosts: strings only, bounded; anything else is none", () => {
  assert.deepEqual(parseDirectHosts(["a", 1, "b"]), ["a", "b"]);
  assert.deepEqual(parseDirectHosts("a,b"), []);
  assert.deepEqual(parseDirectHosts(undefined), []);
  assert.equal(parseDirectHosts(Array.from({ length: 1000 }, (_, i) => `h${i}`)).length, MAX_DIRECT_HOSTS);
});

test("with no DB the store is memory only", () => {
  const s = new WireReleaseStore({ pidExists: () => true, procStartTime: () => "t" });
  s.set("sess", ["x"], 1);
  assert.deepEqual(s.get("sess"), { direct: ["x"] });
  assert.deepEqual(s.persisted(), []);
  assert.equal(s.clear("sess"), true);
  s.close();
});
