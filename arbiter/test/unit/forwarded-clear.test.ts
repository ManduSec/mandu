/**
 * forwarded-clear.test — the model proxies' forwarded-in-clear call ids in
 * mandu.db (confidentiality.md §7.1, "Masked after the fact", *Across a
 * resume*; symbol-table/forwarded-clear.ts). Mandu-new, no reference origin.
 *
 * The proxies' after-the-fact note needs to know which results reached the
 * model in clear in an earlier request. A conversation resumed under a new
 * launch (`claude --resume`) re-sends its history to a proxy that never saw
 * it, so the ids are kept by the arbiter: the store (ids only, idempotent,
 * bounded, survives a restart) and the two ops over it (`recordForwardedClear`
 * and `forwardedClear`, human plane only, malformed ids skipped).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer, humanPlaneOnlyError, type IpcChannel } from "../../ipc/server.js";
import type { ArbiterRequest } from "../../ipc/protocol.js";
import { ForwardedClearStore, MAX_IDS_PER_REQUEST, isCallId } from "../../symbol-table/forwarded-clear.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); the ops answer the same on any axis

function withDir<T>(fn: (dir: string) => Promise<T> | T): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-fwd-clear-"));
  return Promise.resolve(fn(dir)).finally(() => rmSync(dir, { recursive: true, force: true }));
}

test("isCallId: provider call ids pass; empty, over-long, spaced, control-char and non-string ids do not", () => {
  for (const ok of ["toolu_01AbCdEf", "call_9x", "a", "x".repeat(256)]) assert.equal(isCallId(ok), true, ok);
  for (const bad of ["", "x".repeat(257), "toolu 1", "toolu\n1", "toolé", 7, null, undefined, {}]) {
    assert.equal(isCallId(bad), false, String(bad));
  }
});

test("ForwardedClearStore: records ids once, answers the recorded subset in the order asked, and survives a reopen (a new launch)", () =>
  withDir((dir) => {
    const dbPath = join(dir, "mandu.db");
    const s1 = new ForwardedClearStore({ dbPath });
    assert.equal(s1.record(["toolu_a", "toolu_b"]), 2);
    assert.equal(s1.record(["toolu_b", "toolu_c"]), 1, "an id already recorded is not counted again");
    assert.deepEqual(s1.known(["toolu_c", "toolu_x", "toolu_a"]), ["toolu_c", "toolu_a"]);
    s1.close();
    const s2 = new ForwardedClearStore({ dbPath });
    assert.deepEqual(s2.known(["toolu_a", "toolu_b", "toolu_c", "toolu_d"]), ["toolu_a", "toolu_b", "toolu_c"]);
    s2.close();
  }));

test("ForwardedClearStore: past its bound the OLDEST ids go first (only a note is lost), across a reopen too", () =>
  withDir((dir) => {
    const dbPath = join(dir, "mandu.db");
    const s1 = new ForwardedClearStore({ dbPath, maxRows: 3 });
    s1.record(["a", "b"]);
    s1.record(["c", "d"]);
    assert.deepEqual(s1.known(["a", "b", "c", "d"]), ["b", "c", "d"]);
    s1.close();
    const s2 = new ForwardedClearStore({ dbPath, maxRows: 3 });
    s2.record(["e"]);
    assert.deepEqual(s2.known(["a", "b", "c", "d", "e"]), ["c", "d", "e"]);
    s2.close();
  }));

test("ForwardedClearStore: ids only: the table holds the call id and a time, never a result byte", () =>
  withDir((dir) => {
    const dbPath = join(dir, "mandu.db");
    const s = new ForwardedClearStore({ dbPath });
    s.record(["toolu_only_an_id"]);
    s.close();
    const bytes = readFileSync(dbPath).toString("latin1") + (() => { try { return readFileSync(`${dbPath}-wal`).toString("latin1"); } catch { return ""; } })();
    assert.match(bytes, /toolu_only_an_id/);
    assert.match(bytes, /CREATE TABLE forwarded_clear \(\s*call_id\s+TEXT PRIMARY KEY,\s*recorded_at INTEGER NOT NULL\s*\)/);
  }));

function server(dir: string): ArbiterServer {
  mkdirSync(join(dir, "human"), { recursive: true, mode: 0o700 });
  return new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "mandu.db"),
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
  });
}

type Resp = { ok: boolean; result?: unknown; error?: string };
const call = (s: ArbiterServer, req: Record<string, unknown>, channel: IpcChannel): Resp =>
  s.dispatch({ id: "t", ...req } as ArbiterRequest, { channel }) as Resp;

test("recordForwardedClear / forwardedClear: human plane only; a later arbiter over the same mandu.db (a new launch) answers the ids an earlier one recorded", () =>
  withDir(async (dir) => {
    const s1 = server(dir);
    try {
      for (const op of ["recordForwardedClear", "forwardedClear"]) {
        const r = call(s1, { op, ids: ["toolu_1"] }, "data");
        assert.equal(r.ok, false, `${op} on data`);
        assert.equal(r.error, humanPlaneOnlyError(op));
      }
      assert.deepEqual(call(s1, { op: "forwardedClear", ids: ["toolu_1"] }, "human").result, { ids: [], generation: 0 }, "the refused record wrote nothing");
      const rec = call(s1, { op: "recordForwardedClear", ids: ["toolu_1", "toolu_2", "toolu_1", "", "has space", 42] }, "human");
      assert.deepEqual(rec, { id: "t", ok: true, result: { recorded: 2, skipped: 3 } }, "malformed ids are skipped, duplicates recorded once");
    } finally {
      await s1.close();
    }
    const s2 = server(dir);
    try {
      assert.deepEqual(call(s2, { op: "forwardedClear", ids: ["toolu_2", "toolu_9", "toolu_1", " "] }, "human").result, { ids: ["toolu_2", "toolu_1"], generation: 2 });
      assert.deepEqual(call(s2, { op: "forwardedClear", ids: ["toolu_2"] }, "admin").result, { ids: ["toolu_2"], generation: 2 });
    } finally {
      await s2.close();
    }
  }));

test("recordForwardedClear / forwardedClear: a non-array or an over-long list is refused whole", () =>
  withDir(async (dir) => {
    const s = server(dir);
    try {
      for (const op of ["recordForwardedClear", "forwardedClear"]) {
        assert.match(call(s, { op, ids: "toolu_1" }, "human").error ?? "", new RegExp(`^${op}: ids must be an array`));
        assert.match(call(s, { op }, "human").error ?? "", new RegExp(`^${op}: ids must be an array`));
        const many = Array.from({ length: MAX_IDS_PER_REQUEST + 1 }, (_, i) => `toolu_${i}`);
        assert.match(call(s, { op, ids: many }, "human").error ?? "", new RegExp(`^${op}: at most ${MAX_IDS_PER_REQUEST} ids`));
      }
      assert.deepEqual(call(s, { op: "forwardedClear", ids: ["toolu_0"] }, "human").result, { ids: [], generation: 0 }, "the refused record wrote nothing");
    } finally {
      await s.close();
    }
  }));

// ── Two launches at once (confidentiality.md §7.1, 2026-10-17) ───────────────
// Two proxies resumed on one conversation, each over its own arbiter on the
// same mandu.db: an id one did not know at its first ask may be recorded by
// the other later. `forwardedClear` answers the store's generation, and with
// `since` the ids recorded after it, so the other learns it in one op.

test("ForwardedClearStore: the generation grows with each new row, is shared by every store over the file, and `since` lists the rows after it", () =>
  withDir((dir) => {
    const dbPath = join(dir, "mandu.db");
    const a = new ForwardedClearStore({ dbPath });
    const b = new ForwardedClearStore({ dbPath }); // another launch's arbiter
    assert.equal(a.generation(), 0);
    a.record(["toolu_a1", "toolu_a2"]);
    const g = b.generation();
    assert.equal(g, 2);
    b.record(["toolu_a1"]);
    assert.equal(a.generation(), 2, "a duplicate adds no row");
    b.record(["toolu_b1"]);
    assert.deepEqual(a.since(g), { ids: ["toolu_b1"], complete: true });
    assert.deepEqual(a.since(0, 2), { ids: ["toolu_a1", "toolu_a2"], complete: false }, "cut short past the limit");
    a.close(); b.close();
  }));

test("forwardedClear with since: the ids recorded after it, from another arbiter over the same mandu.db; a since above the generation gets no list; human plane only", () =>
  withDir(async (dir) => {
    const s1 = server(dir);
    const d2 = join(dir, "second"); mkdirSync(d2);
    mkdirSync(join(d2, "human"), { recursive: true, mode: 0o700 });
    const s2 = new ArbiterServer({
      socketPath: join(d2, "arbiter.sock"), humanSocketPath: join(d2, "human", "h.sock"), dbPath: join(dir, "mandu.db"), eventDir: join(d2, "events"),
      log: () => {}, confidentiality: true, integrity: false,
    });
    try {
      const first = call(s1, { op: "forwardedClear", ids: ["toolu_x"] }, "human").result as { ids: string[]; generation: number };
      assert.deepEqual(first, { ids: [], generation: 0 });
      call(s2, { op: "recordForwardedClear", ids: ["toolu_x"] }, "human");
      assert.deepEqual(call(s1, { op: "forwardedClear", ids: [], since: first.generation }, "human").result, { ids: [], generation: 1, recent: ["toolu_x"], recentComplete: true });
      assert.deepEqual(call(s1, { op: "forwardedClear", ids: [], since: 99 }, "human").result, { ids: [], generation: 1 }, "a since the store never reached: no list (the proxy sees the regress)");
      assert.deepEqual(call(s1, { op: "forwardedClear", ids: [], since: -1 }, "human").result, { ids: [], generation: 1 });
      const data = call(s1, { op: "forwardedClear", ids: [], since: 0 }, "data");
      assert.equal(data.ok, false);
      assert.equal(data.error, humanPlaneOnlyError("forwardedClear"));
    } finally {
      await s1.close();
      await s2.close();
    }
  }));
