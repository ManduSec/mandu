/**
 * noteReserveBlock / reserveBlock (reply-row-reservation.md §3.8): the store
 * in isolation and the ops through `dispatch`, no socket. The proxy records
 * each block it expands; the reply filter reads one back by hash when a
 * continuation row reaches the screen but its head never did. Both ops are
 * human-plane. Mandu-new, no reference origin. The socket path over the
 * production client is pinned in test/component/reply-row-reservation.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer, humanPlaneOnlyError, type IpcChannel } from "../../ipc/server.js";
import { ReserveBlockStore, parseReserveBlock, reserveBlockHash } from "../../ipc/reply-reservation.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

type Res = { ok: boolean; error?: string; result?: unknown };

const T = "$MDU:nomodel_Bash[464e]";

async function withServer(fn: (srv: ArbiterServer) => void | Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-reserveblock-"));
  const srv = new ArbiterServer({
    socketPath: join(dir, "a.sock"), dbPath: join(dir, "symbols.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyDocument: {}, policyPollMs: 0,
  });
  try { await fn(srv); } finally { await srv.close().catch(() => {}); rmSync(dir, { recursive: true, force: true }); }
}

function note(srv: ArbiterServer, body: Record<string, unknown>, channel: IpcChannel = "human"): Res {
  return srv.dispatch({ id: 1, op: "noteReserveBlock", ...body } as never, { channel }) as Res;
}
function get(srv: ArbiterServer, sessionKey: unknown, hash: unknown, channel: IpcChannel = "human"): Res {
  return srv.dispatch({ id: 2, op: "reserveBlock", sessionKey, hash } as never, { channel }) as Res;
}

test("reserveBlockHash: the bracket hash of a token, with or without a field path", () => {
  assert.equal(reserveBlockHash(T), "464e");
  assert.equal(reserveBlockHash("$MDU:Bash[0badc0de].stdout"), "0badc0de");
  assert.equal(reserveBlockHash("no token"), null);
});

test("store: note/get round trip by session and hash; a copy; the last note wins", () => {
  const s = new ReserveBlockStore();
  s.note({ sessionKey: "s1", hash: "464e", token: T, n: 5 });
  const got = s.get("s1", "464e")!;
  assert.deepEqual(got, { token: T, n: 5 });
  got.n = 99;
  assert.equal(s.get("s1", "464e")!.n, 5, "get returns a copy");
  assert.equal(s.get("s2", "464e"), null, "per-session isolation");
  assert.equal(s.get("s1", "beef"), null);
  s.note({ sessionKey: "s1", hash: "464e", token: `${T}.stdout`, n: 7, width: 78, first: 78 });
  assert.deepEqual(s.get("s1", "464e"), { token: `${T}.stdout`, n: 7, width: 78, first: 78 });
  assert.equal(s.delete("s1"), true);
  assert.equal(s.get("s1", "464e"), null);
});

test("store: bounded per session and in sessions — the least recently noted goes first", () => {
  const s = new ReserveBlockStore(2, 3);
  for (const h of ["aaaa", "bbbb", "cccc", "dddd"]) s.note({ sessionKey: "s1", hash: h, token: `$MDU:x[${h}]`, n: 2 });
  assert.equal(s.get("s1", "aaaa"), null, "past 3 blocks the oldest is forgotten");
  assert.ok(s.get("s1", "dddd"));
  s.note({ sessionKey: "s2", hash: "aaaa", token: "$MDU:x[aaaa]", n: 2 });
  s.note({ sessionKey: "s1", hash: "eeee", token: "$MDU:x[eeee]", n: 2 }); // s1 is now the most recent
  s.note({ sessionKey: "s3", hash: "aaaa", token: "$MDU:x[aaaa]", n: 2 });
  assert.equal(s.get("s2", "aaaa"), null, "past 2 sessions the least recently noted is evicted");
  assert.ok(s.get("s1", "eeee"));
  assert.ok(s.get("s3", "aaaa"));
});

test("parseReserveBlock: n, the layout pair, and the session key are validated", () => {
  const ok = parseReserveBlock({ sessionKey: "k", n: 5 }, T);
  assert.deepEqual(ok, { sessionKey: "k", hash: "464e", token: T, n: 5 });
  assert.deepEqual(parseReserveBlock({ sessionKey: "k", n: 3, width: 78, first: 0 }, T),
    { sessionKey: "k", hash: "464e", token: T, n: 3, width: 78, first: 0 });
  for (const [body, re] of [
    [{ n: 5 }, /sessionKey required/],
    [{ sessionKey: "k", n: 1 }, /n must be an integer from 2 to 200/],
    [{ sessionKey: "k", n: 201 }, /n must be an integer from 2 to 200/],
    [{ sessionKey: "k", n: 2.5 }, /n must be an integer/],
    [{ sessionKey: "k", n: 5, width: 78 }, /width and first come together/],
    [{ sessionKey: "k", n: 5, first: 78 }, /width and first come together/],
    [{ sessionKey: "k", n: 5, width: 19, first: 19 }, /noteReserveBlock: width must be an integer from 20/],
    [{ sessionKey: "k", n: 5, width: 80, first: 39 }, /noteReserveBlock: first must be 0 or an integer from 40 to 80/],
  ] as Array<[Record<string, unknown>, RegExp]>) {
    const r = parseReserveBlock(body, T);
    assert.equal(typeof r, "string", JSON.stringify(body));
    assert.match(r as string, re, JSON.stringify(body));
  }
});

test("noteReserveBlock → reserveBlock over dispatch: round trip; an escaped token is stored canonical", async () => {
  await withServer((srv) => {
    const r = note(srv, { sessionKey: "k1", token: "\\$MDU:nomodel\\_Bash[464e]", n: 5 });
    assert.equal(r.ok, true, r.error);
    assert.deepEqual(get(srv, "k1", "464e").result, { token: T, n: 5 });
    assert.equal(get(srv, "k1", "beef").result, null);
    assert.equal(get(srv, "k2", "464e").result, null);
  });
});

test("noteReserveBlock: only exactly one symbol token; nothing is stored on a refusal", async () => {
  await withServer((srv) => {
    for (const token of [`text ${T}`, `${T} ${T}`, "not a token", 42]) {
      const r = note(srv, { sessionKey: "k1", token, n: 5 });
      assert.equal(r.ok, false, JSON.stringify(token));
    }
    assert.equal(note(srv, { sessionKey: "k1", token: T, n: 1 }).ok, false);
    assert.equal(get(srv, "k1", "464e").result, null, "no refused note was stored");
  });
});

test("reserveBlock: a malformed hash or session key is refused", async () => {
  await withServer((srv) => {
    assert.match(get(srv, "k1", "XYZ!").error ?? "", /hash must be 4 to 8 hex digits/);
    assert.match(get(srv, "k1", "464").error ?? "", /hash must be 4 to 8 hex digits/);
    assert.match(get(srv, "", "464e").error ?? "", /sessionKey required/);
  });
});

test("noteReserveBlock / reserveBlock: refused on data (human-plane), served on human and admin", async () => {
  await withServer((srv) => {
    const refused = note(srv, { sessionKey: "k1", token: T, n: 5 }, "data");
    assert.equal(refused.ok, false);
    assert.equal(refused.error, humanPlaneOnlyError("noteReserveBlock"));
    assert.match(refused.error!, /records a reserve block's token and row count/);
    assert.equal(get(srv, "k1", "464e", "data").error, humanPlaneOnlyError("reserveBlock"));
    assert.equal(note(srv, { sessionKey: "k1", token: T, n: 5 }, "admin").ok, true);
    assert.deepEqual(get(srv, "k1", "464e", "human").result, { token: T, n: 5 });
  });
});

test("deleteSession clears the session's reserve blocks", async () => {
  await withServer((srv) => {
    const sid = "reserve-delete-test-1";
    const emitted = srv.dispatch({
      id: 1, op: "emit", event: { sessionId: sid, id: "e1", ts: new Date().toISOString(), kind: "tllm_call" },
    } as never) as Res;
    assert.equal(emitted.ok, true, emitted.error);
    note(srv, { sessionKey: sid, token: T, n: 5 });
    note(srv, { sessionKey: "other", token: T, n: 5 });
    const del = srv.dispatch({ id: 3, op: "deleteSession", sessionId: sid }) as Res;
    assert.equal(del.ok, true, del.error);
    assert.equal(get(srv, sid, "464e").result, null, "a reused id starts with no blocks");
    assert.ok(get(srv, "other", "464e").result, "other sessions are untouched");
  });
});
