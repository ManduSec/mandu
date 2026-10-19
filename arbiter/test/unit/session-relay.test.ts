/**
 * setSessionRelay / sessionRelay (reply-row-reservation.md §3.6, §11.5): the
 * store in isolation and the ops through `dispatch`, no socket. Both ops are
 * human-plane since v2 (the relay's `cols` sets the wrap width): the helpers
 * dispatch on the human channel, and the data channel's refusal is pinned
 * below. Mandu-new, no reference origin. The socket path over the production
 * client is pinned in test/component/reply-row-reservation.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer, humanPlaneOnlyError, type IpcChannel } from "../../ipc/server.js";
import { SessionRelayStore, parseSessionRelay, SESSION_RELAY_MAX_DIM } from "../../ipc/reply-reservation.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

type Res = { ok: boolean; error?: string; result?: unknown };

function withServer(fn: (srv: ArbiterServer, eventDir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sessionrelay-"));
  const srv = new ArbiterServer({
    socketPath: join(dir, "a.sock"), dbPath: join(dir, "symbols.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyDocument: {}, policyPollMs: 0,
  });
  try { fn(srv, join(dir, "events")); } finally { srv.close().catch(() => {}); rmSync(dir, { recursive: true, force: true }); }
}

function set(srv: ArbiterServer, body: Record<string, unknown>, channel: IpcChannel = "human"): Res {
  return srv.dispatch({ id: 1, op: "setSessionRelay", ...body } as never, { channel }) as Res;
}
function get(srv: ArbiterServer, sessionKey: unknown, channel: IpcChannel = "human"): Res {
  return srv.dispatch({ id: 2, op: "sessionRelay", sessionKey } as never, { channel }) as Res;
}

test("store: set/get round trip, stamped updatedAt, returns a copy", () => {
  const s = new SessionRelayStore();
  assert.equal(s.get("k"), null);
  s.set({ sessionKey: "k", mode: "pty", reserve: true, cols: 80, rows: 24 }, 1000);
  const e = s.get("k")!;
  assert.deepEqual(e, { mode: "pty", reserve: true, cols: 80, rows: 24, updatedAt: 1000 });
  e.mode = "pipe";
  assert.equal(s.get("k")!.mode, "pty", "callers cannot mutate the stored entry");
});

test("store: bounded — past the cap the least-recently-reported session is evicted", () => {
  const s = new SessionRelayStore(3);
  s.set({ sessionKey: "a", mode: "pty", reserve: true }, 1);
  s.set({ sessionKey: "b", mode: "pty", reserve: true }, 2);
  s.set({ sessionKey: "c", mode: "pty", reserve: true }, 3);
  s.set({ sessionKey: "a", mode: "pty", reserve: true }, 4); // a is now the freshest
  s.set({ sessionKey: "d", mode: "pty", reserve: true }, 5);
  assert.equal(s.size, 3);
  assert.equal(s.get("b"), null, "the stalest report is evicted (reads null ⇒ no expansion)");
  assert.ok(s.get("a") && s.get("c") && s.get("d"));
});

test("parseSessionRelay: optional dims are omitted, never defaulted", () => {
  assert.deepEqual(parseSessionRelay({ sessionKey: "k", mode: "pipe", reserve: false }),
    { sessionKey: "k", mode: "pipe", reserve: false });
});

test("setSessionRelay → sessionRelay: round trip over dispatch", () => {
  withServer((srv) => {
    const before = Date.now();
    assert.deepEqual(set(srv, { sessionKey: "s1", mode: "pty", reserve: true, cols: 160, rows: 40 }),
      { id: 1, ok: true, result: { ok: true } });
    const r = get(srv, "s1");
    assert.equal(r.ok, true, r.error);
    const w = r.result as { mode: string; reserve: boolean; cols: number; rows: number; updatedAt: number };
    assert.equal(w.mode, "pty");
    assert.equal(w.reserve, true);
    assert.equal(w.cols, 160);
    assert.equal(w.rows, 40);
    assert.ok(w.updatedAt >= before && w.updatedAt <= Date.now(), "updatedAt is the receive time (ms)");
  });
});

test("sessionRelay: never reported → null", () => {
  withServer((srv) => {
    assert.deepEqual(get(srv, "never-set"), { id: 2, ok: true, result: null });
  });
});

test("setSessionRelay: per-session isolation", () => {
  withServer((srv) => {
    set(srv, { sessionKey: "a", mode: "pty", reserve: true, cols: 80, rows: 24 });
    set(srv, { sessionKey: "b", mode: "pipe", reserve: false });
    assert.equal((get(srv, "a").result as { mode: string }).mode, "pty");
    const b = get(srv, "b").result as Record<string, unknown>;
    assert.equal(b.mode, "pipe");
    assert.equal(b.reserve, false);
    assert.ok(!("cols" in b) && !("rows" in b), "b carries no dims it did not report");
    assert.equal(get(srv, "c").result, null);
  });
});

test("setSessionRelay: a re-report overwrites (resize, mode change) and re-stamps", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sessionrelay-"));
  const srv = new ArbiterServer({
    socketPath: join(dir, "a.sock"), dbPath: join(dir, "symbols.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyDocument: {}, policyPollMs: 0,
  });
  try {
    set(srv, { sessionKey: "s", mode: "pty", reserve: true, cols: 80, rows: 24 });
    const first = get(srv, "s").result as { updatedAt: number };
    await new Promise((r) => setTimeout(r, 5));
    set(srv, { sessionKey: "s", mode: "pty", reserve: true, cols: 120, rows: 30 });
    const second = get(srv, "s").result as { cols: number; rows: number; updatedAt: number };
    assert.equal(second.cols, 120);
    assert.equal(second.rows, 30);
    assert.ok(second.updatedAt > first.updatedAt, "updatedAt advances on overwrite");
    set(srv, { sessionKey: "s", mode: "passthrough", reserve: false });
    assert.deepEqual(
      Object.keys(get(srv, "s").result as object).sort(), ["mode", "reserve", "updatedAt"],
      "an overwrite replaces the entry; stale dims do not linger",
    );
  } finally {
    await srv.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("setSessionRelay: strict validation — every malformed body is refused and stores nothing", () => {
  withServer((srv) => {
    const good = { sessionKey: "v", mode: "pty", reserve: true };
    const bad: Array<[Record<string, unknown>, RegExp]> = [
      [{ ...good, sessionKey: "" }, /sessionKey required/],
      [{ ...good, sessionKey: undefined }, /sessionKey required/],
      [{ ...good, sessionKey: 42 }, /sessionKey required/],
      [{ ...good, sessionKey: "k".repeat(513) }, /sessionKey longer/],
      [{ ...good, mode: "tty" }, /mode must be one of pty, pipe, passthrough/],
      [{ ...good, mode: undefined }, /mode must be one of/],
      [{ ...good, reserve: "true" }, /reserve must be a boolean/],
      [{ ...good, reserve: undefined }, /reserve must be a boolean/],
      [{ ...good, cols: 0 }, /cols must be a positive integer/],
      [{ ...good, cols: -1 }, /cols must be a positive integer/],
      [{ ...good, cols: 80.5 }, /cols must be a positive integer/],
      [{ ...good, cols: "80" }, /cols must be a positive integer/],
      [{ ...good, cols: SESSION_RELAY_MAX_DIM + 1 }, /cols must be a positive integer/],
      [{ ...good, rows: null }, /rows must be a positive integer/],
      [{ ...good, rows: Number.NaN }, /rows must be a positive integer/],
      [{ ...good, wrap: "true" }, /wrap must be a boolean/],
      [{ ...good, wrap: null }, /wrap must be a boolean/],
    ];
    for (const [body, re] of bad) {
      const r = set(srv, body);
      assert.equal(r.ok, false, `refused: ${JSON.stringify(body).slice(0, 80)}`);
      assert.match(r.error!, re);
    }
    assert.equal(get(srv, "v").result, null, "no refused report left anything behind");
    // The edges that ARE valid.
    assert.equal(set(srv, { ...good, cols: 1, rows: SESSION_RELAY_MAX_DIM }).ok, true);
  });
});

test("sessionRelay: a missing session key is refused", () => {
  withServer((srv) => {
    for (const k of [undefined, "", 3]) {
      const r = get(srv, k);
      assert.equal(r.ok, false);
      assert.match(r.error!, /sessionRelay: sessionKey required/);
    }
  });
});

test("setSessionRelay / sessionRelay: refused on data (human-plane, §11.5), served on human and admin", () => {
  withServer((srv) => {
    const body = { sessionKey: "d", mode: "pty", reserve: true, cols: 80, rows: 24, wrap: true };
    const refusedSet = set(srv, body, "data");
    assert.equal(refusedSet.ok, false, "the agent's world cannot choose the wrap width");
    assert.equal(refusedSet.error, humanPlaneOnlyError("setSessionRelay"));
    assert.match(refusedSet.error!, /^human-plane: 'setSessionRelay' /);
    assert.equal(get(srv, "d").result, null, "a refused report stored nothing");

    assert.equal(set(srv, body, "human").ok, true, "the reply filter reports over the human socket");
    const refusedGet = get(srv, "d", "data");
    assert.equal(refusedGet.ok, false);
    assert.equal(refusedGet.error, humanPlaneOnlyError("sessionRelay"));
    assert.equal(refusedGet.result, undefined, "a refusal carries no relay state");
    assert.equal((get(srv, "d", "human").result as { cols: number }).cols, 80);

    assert.equal(set(srv, { ...body, cols: 120 }, "admin").ok, true);
    assert.equal((get(srv, "d", "admin").result as { cols: number }).cols, 120);
  });
});

test("setSessionRelay: `wrap` round trip — true, false, and absent (a v1 filter) stays absent", () => {
  withServer((srv) => {
    set(srv, { sessionKey: "w1", mode: "pty", reserve: true, cols: 80, rows: 24, wrap: true });
    set(srv, { sessionKey: "w0", mode: "pty", reserve: true, cols: 80, rows: 24, wrap: false });
    set(srv, { sessionKey: "v1", mode: "pty", reserve: true, cols: 80, rows: 24 });
    assert.equal((get(srv, "w1").result as { wrap?: boolean }).wrap, true);
    assert.equal((get(srv, "w0").result as { wrap?: boolean }).wrap, false);
    const v1 = get(srv, "v1").result as Record<string, unknown>;
    assert.ok(!("wrap" in v1), "a v1 filter's report carries no wrap (read: false)");
    // A re-report without wrap drops it (an overwrite replaces the entry).
    set(srv, { sessionKey: "w1", mode: "pty", reserve: true, cols: 100, rows: 24 });
    assert.ok(!("wrap" in (get(srv, "w1").result as object)));
  });
});

test("parseSessionRelay: wrap is stored when present, refused unless boolean", () => {
  assert.deepEqual(parseSessionRelay({ sessionKey: "k", mode: "pty", reserve: true, wrap: true }),
    { sessionKey: "k", mode: "pty", reserve: true, wrap: true });
  assert.deepEqual(parseSessionRelay({ sessionKey: "k", mode: "pty", reserve: true, wrap: false }),
    { sessionKey: "k", mode: "pty", reserve: true, wrap: false });
  for (const wrap of ["true", 1, 0, null, {}]) {
    assert.equal(parseSessionRelay({ sessionKey: "k", mode: "pty", reserve: true, wrap }),
      "setSessionRelay: wrap must be a boolean", JSON.stringify(wrap));
  }
});

test("setSessionRelay (§17): `rule` round trip — terminal, ink, absent stays absent; anything else refused and nothing stored", () => {
  withServer((srv) => {
    set(srv, { sessionKey: "g", mode: "pty", reserve: true, cols: 80, rows: 24, wrap: true, rule: "terminal" });
    set(srv, { sessionKey: "c", mode: "pty", reserve: true, cols: 80, rows: 24, wrap: true, rule: "ink" });
    set(srv, { sessionKey: "o", mode: "pty", reserve: true, cols: 80, rows: 24, wrap: true });
    assert.equal((get(srv, "g").result as { rule?: string }).rule, "terminal");
    assert.equal((get(srv, "c").result as { rule?: string }).rule, "ink");
    assert.ok(!("rule" in (get(srv, "o").result as object)), "an older filter's report carries no rule (read: ink)");
    for (const rule of ["char", "", null, 1, true]) {
      const r = set(srv, { sessionKey: "bad", mode: "pty", reserve: true, rule });
      assert.equal(r.ok, false, JSON.stringify(rule));
      assert.equal(r.error, "setSessionRelay: rule must be one of ink, terminal");
    }
    assert.equal(get(srv, "bad").result, null);
    assert.equal(set(srv, { sessionKey: "g", mode: "pty", reserve: true, rule: "terminal" }, "data").ok, false, "human plane only");
  });
});

test("store: the wrap flag round-trips through set/get", () => {
  const s = new SessionRelayStore();
  s.set({ sessionKey: "k", mode: "pty", reserve: true, cols: 80, rows: 24, wrap: true }, 7);
  assert.deepEqual(s.get("k"), { mode: "pty", reserve: true, cols: 80, rows: 24, wrap: true, updatedAt: 7 });
});

test("deleteSession clears the session's relay state", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sessionrelay-"));
  const srv = new ArbiterServer({
    socketPath: join(dir, "a.sock"), dbPath: join(dir, "symbols.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyDocument: {}, policyPollMs: 0,
  });
  try {
    const sid = "relay-delete-test-1";
    const emitted = srv.dispatch({
      id: 1, op: "emit", event: { sessionId: sid, id: "e1", ts: new Date().toISOString(), kind: "tllm_call" },
    } as never) as Res;
    assert.equal(emitted.ok, true, emitted.error);
    set(srv, { sessionKey: sid, mode: "pty", reserve: true });
    set(srv, { sessionKey: "other", mode: "pty", reserve: true });
    const del = srv.dispatch({ id: 3, op: "deleteSession", sessionId: sid }) as Res;
    assert.equal(del.ok, true, del.error);
    assert.equal(get(srv, sid).result, null, "a reused id starts with no relay report");
    assert.ok(get(srv, "other").result, "other sessions are untouched");
  } finally {
    await srv.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
