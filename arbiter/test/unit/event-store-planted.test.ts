/**
 * event-store-planted — the event store never appends through a link
 * (runtime-instances.md §2, "planted paths", 2026-10-17). A per-launch
 * arbiter's event dir is `<scope dir>/events`, which the agent may write
 * while its session runs, and the session id is the scope id: a link
 * planted at `<session>.ndjson` (or at the dir itself) made the arbiter
 * append its records, which the agent can steer, to whatever file it named.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventStore } from "../../events/event-store.js";
import { stateAxes } from "../axes.js";

stateAxes("off"); // the store's file handling only: no policy decides anything here

const ev = (sessionId: string, id: string) => ({ sessionId, id, kind: "note", ts: new Date().toISOString() });

test("a link planted at a session's event file: the append is refused, the linked file untouched; another session still records", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "evstore-planted-")));
  try {
    const events = join(dir, "events");
    mkdirSync(events, { mode: 0o700 });
    const victim = join(dir, "victim.rc");
    writeFileSync(victim, "# rc\n");
    symlinkSync(victim, join(events, "s1.ndjson"));
    const store = new EventStore(events);
    assert.throws(() => store.append(ev("s1", "a")), /symbolic link; refusing to write through it/);
    assert.equal(readFileSync(victim, "utf8"), "# rc\n");
    store.append(ev("s2", "b"));
    assert.match(readFileSync(join(events, "s2.ndjson"), "utf8"), /"id":"b"/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an event dir that is a link of this user's to a folder: nothing is recorded there", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "evstore-planted-")));
  try {
    const victim = join(dir, "victim");
    mkdirSync(victim);
    symlinkSync(victim, join(dir, "events"));
    const store = new EventStore(join(dir, "events"));
    assert.throws(() => store.append(ev("s1", "a")), /events is a symbolic link on the way/);
    assert.deepEqual(readdirSync(victim), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a missing event dir is made 0700, one directory at a time", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "evstore-planted-")));
  try {
    const store = new EventStore(join(dir, "a", "events"));
    store.append(ev("s1", "a"));
    store.append(ev("s1", "b"));
    const lines = readFileSync(join(dir, "a", "events", "s1.ndjson"), "utf8").trim().split("\n");
    assert.equal(lines.length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
