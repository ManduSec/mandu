/**
 * config-audit-loop.test — the WHOLE dashboard-side config_change audit loop
 * (dashboard.md §4.19 ②'s who/when trail) over the real HTTP server + the
 * real arbiter socket-op contract.
 *
 * Mandu-new test (NO reference origin). Follows posture-loop.test.ts's
 * harness conventions: a self-contained MOCK arbiter server on a temp Unix
 * socket speaking NDJSON ({id,op,…} → {id,ok,result|error} — the
 * arbiter/ipc/protocol.ts framing), a real DashboardServer on an ephemeral
 * port with MANDU_HOME pinned at a per-run temp dir, driven with
 * `fetch`. The mock speaks the arbiter's REAL observability semantics for the
 * two ops the ConfigAuditArbiter surface rides:
 *
 *   - `emit` {event} → {seq}: append the OPAQUE event to a per-session store,
 *     assign the monotonic seq (server.ts case "emit");
 *   - `events` {sessionId, sinceSeq?} → {events}: the stored events in seq
 *     order (server.ts case "events").
 *
 * What it pins (the unit tier covers the routes over an in-process fake;
 * NOTHING else covers the loop over the real socket framing):
 *   1. POST /api/config/axes flipping an axis puts ONE config_change on the
 *      WIRE — kind/sessionId "arbiter-admin"/emitter "dashboard" + the
 *      top-level SIEM scalars axis/from/to/requestedBy — and the answer's
 *      `audit` block reflects the freshly-stored event (read back over the
 *      real events op, not an in-process shortcut);
 *   2. a second act on the same axis wins the GET attribution (latest per
 *      axis over the real store);
 *   3. POST without X-Mandu-Control → 403 and NO op reaches the socket;
 *   4. a no-flip write puts NOTHING on the wire;
 *   5. the integrity freeze (docs/design/architecture/protection-modes.md §10): on a dashboard
 *      WITHOUT MANDU_EXPERIMENTAL_INTEGRITY, a write that leaves integrity on
 *      answers 403 {frozen} and NOTHING reaches the socket; turning it off
 *      still lands its one config_change.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, connect, type Server } from "node:net";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  DashboardServer,
  type ConfigAuditArbiter,
  type AxesStateWithAudit,
} from "../../src/server.js";
import { ADMIN_OPTS, ADMIN_COOKIE } from "../unit/admin-session.js";
import { INTEGRITY_OPT_IN_ENV } from "../../src/config-axes.js";
import type { EventSource, SessionRef } from "../../src/event-source.js";
import type { ManduEvent } from "../../src/event-model.js";
import { tmpDir } from "../unit/tmp-dir.js";

const fakeSource: EventSource = {
  async listSessions(): Promise<SessionRef[]> {
    return [];
  },
  async readEvents(): Promise<ManduEvent[]> {
    return [];
  },
  subscribe(): () => void {
    return () => {};
  },
  close(): void {},
};

// ── Mock arbiter: one NDJSON socket server, one per-session event store ───────

interface StoredWireEvent extends Record<string, unknown> {
  seq: number;
}

interface MockArbiter {
  socketPath: string;
  /** Every op frame the socket served, in order — the "did anything reach the
   *  arbiter at all" oracle. */
  ops: { op: string; payload: Record<string, unknown> }[];
  /** The mock's arbiter-admin stream (assertable arbiter-held state). */
  stream(sessionId: string): StoredWireEvent[];
  close(): Promise<void>;
}

function startMockArbiter(): Promise<MockArbiter> {
  const dir = tmpDir("mandu-config-audit-loop-");
  const socketPath = join(dir, "arbiter.sock");
  const stores = new Map<string, StoredWireEvent[]>();
  const ops: MockArbiter["ops"] = [];

  const server: Server = createServer((sock) => {
    sock.setEncoding("utf8");
    let buf = "";
    const writeFrame = (obj: unknown): void => {
      sock.write(JSON.stringify(obj) + "\n");
    };
    sock.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim() === "") continue;
        let req: Record<string, unknown>;
        try {
          req = JSON.parse(line) as Record<string, unknown>;
        } catch {
          continue;
        }
        const op = String(req.op ?? "");
        ops.push({ op, payload: req });
        if (op === "emit") {
          // The arbiter's opaque append (server.ts case "emit"): assign the
          // per-session monotonic seq, return it.
          const event = req.event as Record<string, unknown> | undefined;
          const sessionId = event ? String(event.sessionId ?? "") : "";
          if (!event || !sessionId) {
            writeFrame({ id: req.id, ok: false, error: "emit: event.sessionId required" });
            continue;
          }
          const store = stores.get(sessionId) ?? [];
          const stored: StoredWireEvent = { ...event, seq: store.length + 1 };
          store.push(stored);
          stores.set(sessionId, store);
          writeFrame({ id: req.id, ok: true, result: { seq: stored.seq } });
        } else if (op === "events") {
          const sessionId = String(req.sessionId ?? "");
          const sinceSeq = typeof req.sinceSeq === "number" ? req.sinceSeq : 0;
          const store = stores.get(sessionId) ?? [];
          writeFrame({
            id: req.id,
            ok: true,
            result: { events: store.filter((e) => e.seq > sinceSeq) },
          });
        } else {
          writeFrame({ id: req.id, ok: false, error: `unknown op: ${op}` });
        }
      }
    });
    sock.on("error", () => {
      /* a client teardown mid-write is expected; ignore */
    });
  });

  return new Promise((resolve) => {
    server.listen(socketPath, () => {
      resolve({
        socketPath,
        ops,
        stream: (sessionId) => stores.get(sessionId) ?? [],
        async close() {
          await new Promise<void>((res) => server.close(() => res()));
          rmSync(dir, { recursive: true, force: true });
        },
      });
    });
  });
}

// ── The in-test ConfigAuditArbiter adapter (the wire ops server-main's runtime
//    arbiter/ipc/client.ts import speaks; this package never imports it) ───────

/** One-shot NDJSON request/response over a fresh connection (the requestOnce
 *  framing posture-loop.test.ts uses). */
function requestOnce<T>(socketPath: string, req: Record<string, unknown>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const id = 1;
    const sock = connect(socketPath);
    sock.setEncoding("utf8");
    let buf = "";
    let settled = false;
    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      sock.removeAllListeners();
      sock.end();
      sock.destroy();
      fn();
    };
    sock.once("connect", () => {
      sock.write(JSON.stringify({ id, ...req }) + "\n");
    });
    sock.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim() === "") continue;
        let resp: { id?: unknown; ok?: boolean; result?: unknown; error?: unknown };
        try {
          resp = JSON.parse(line) as typeof resp;
        } catch {
          continue;
        }
        if (resp.id !== id) continue;
        if (resp.ok === false) {
          finish(() => reject(new Error(String(resp.error ?? "arbiter error"))));
          return;
        }
        finish(() => resolve(resp.result as T));
        return;
      }
    });
    sock.on("error", (err: Error) => finish(() => reject(err)));
    sock.on("close", () => finish(() => reject(new Error("arbiter connection closed before reply"))));
  });
}

/** ConfigAuditArbiter over the socket — the same {op:"emit",event} /
 *  {op:"events",sessionId,sinceSeq} frames the real client's request()
 *  serializes, results unwrapped the same way (emit → seq, events → list). */
function socketAuditArbiter(socketPath: string): ConfigAuditArbiter {
  return {
    async emit(event): Promise<number> {
      const r = await requestOnce<{ seq: number }>(socketPath, { op: "emit", event });
      return r.seq;
    },
    async events(sessionId, sinceSeq): Promise<Record<string, unknown>[]> {
      const r = await requestOnce<{ events: Record<string, unknown>[] }>(socketPath, {
        op: "events",
        sessionId,
        ...(sinceSeq !== undefined ? { sinceSeq } : {}),
      });
      return r.events;
    },
  };
}

// ── Shared fixtures ───────────────────────────────────────────────────────────

let arbiter: MockArbiter;
let server: DashboardServer;
let baseUrl: string;
let dir: string;

const CSRF = { "X-Mandu-Control": "1", "Content-Type": "application/json", Cookie: ADMIN_COOKIE };

function postAxes(body: unknown, headers: Record<string, string> = CSRF): Promise<Response> {
  return fetch(`${baseUrl}/api/config/axes`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

before(async () => {
  arbiter = await startMockArbiter();
  dir = tmpDir("mandu-config-audit-cfg-");
  // The sequence below flips the INTEGRITY axis off and on again. Its starting
  // value is STATED in the file, never inherited from the built-in default
  // (which moved to `secrets`, integrity OFF, on 2026-09-21): a first "turn it
  // off" against an implicit OFF would be a no-flip and put nothing on the wire.
  mkdirSync(join(dir, "mandu"), { recursive: true });
  writeFileSync(join(dir, "mandu", "config.toml"), "integrity = true\n");
  server = new DashboardServer({
    source: fakeSource,
    // The sequence turns the FROZEN integrity axis back on
    // (docs/design/architecture/protection-modes.md §10), so this dashboard opts in by name;
    // the last test proves the refusal on a dashboard that did not.
    configEnv: { MANDU_HOME: join(dir, "mandu"), [INTEGRITY_OPT_IN_ENV]: "1" },
    auditArbiter: socketAuditArbiter(arbiter.socketPath),
    log: () => {},
    ...ADMIN_OPTS,
  });
  const port = await server.listen(0);
  baseUrl = `http://127.0.0.1:${port}`;
});

after(async () => {
  await server.close();
  await arbiter.close();
  rmSync(dir, { recursive: true, force: true });
});

// ── tests (state carries forward: the mock's store IS the audit trail) ────────

test("a CSRF-less POST reaches neither the file nor the socket", async () => {
  const res = await postAxes({ integrity: false }, { "Content-Type": "application/json" });
  assert.equal(res.status, 403);
  assert.equal(arbiter.ops.length, 0, "no op crossed the wire for a refused act");
});

test("flipping an axis puts ONE config_change on the wire; the answer attributes it", async () => {
  const res = await postAxes({ integrity: false });
  assert.equal(res.status, 200);

  const emits = arbiter.ops.filter((o) => o.op === "emit");
  assert.equal(emits.length, 1, "exactly one emit for one flipped axis");
  const event = emits[0]!.payload.event as Record<string, unknown>;
  assert.equal(event.kind, "config_change");
  assert.equal(event.sessionId, "arbiter-admin");
  assert.equal(event.emitter, "dashboard");
  assert.deepEqual(
    { axis: event.axis, from: event.from, to: event.to, requestedBy: event.requestedBy },
    { axis: "integrity", from: true, to: false, requestedBy: "dashboard" },
    "the top-level SIEM scalars rode the wire",
  );

  // The arbiter now HOLDS the event (assigned seq 1)…
  assert.equal(arbiter.stream("arbiter-admin").length, 1);
  // …and the POST's answer already read it back over the real events op.
  const body = (await res.json()) as AxesStateWithAudit;
  assert.equal(body.audit?.integrity?.to, false);
  assert.equal(body.audit?.integrity?.requestedBy, "dashboard");
});

test("a second act on the same axis wins the GET attribution (latest per axis)", async () => {
  const res = await postAxes({ integrity: true });
  assert.equal(res.status, 200);
  assert.equal(arbiter.stream("arbiter-admin").length, 2);

  const get = (await (await fetch(`${baseUrl}/api/config/axes`)).json()) as AxesStateWithAudit;
  assert.deepEqual(
    { from: get.audit?.integrity?.from, to: get.audit?.integrity?.to },
    { from: false, to: true },
  );
  assert.equal(get.audit?.confidentiality, undefined, "no act on the axis → no claim");
});

test("a no-flip write puts NOTHING on the wire (applied-only discipline)", async () => {
  const emitsBefore = arbiter.ops.filter((o) => o.op === "emit").length;
  // integrity is now configured true — writing true again flips nothing.
  const res = await postAxes({ integrity: true });
  assert.equal(res.status, 200);
  assert.equal(arbiter.ops.filter((o) => o.op === "emit").length, emitsBefore);
  assert.equal(arbiter.stream("arbiter-admin").length, 2, "the stream did not grow");
});

// ── the four MODES over the same wire (protection-modes.md §3.3) ─────────────

test("a MODE write puts one config_change per FLIPPED axis on the wire, and the file names the mode", async () => {
  // State carried forward: integrity = true is configured, confidentiality is
  // absent. Pin the pair explicitly first so this test does not depend on
  // which mode is the built-in default.
  assert.equal((await postAxes({ mode: "injection" })).status, 200);
  const before = arbiter.ops.filter((o) => o.op === "emit").length;

  // injection → secrets flips BOTH axes.
  const res = await postAxes({ mode: "secrets" });
  assert.equal(res.status, 200);
  const emits = arbiter.ops.filter((o) => o.op === "emit").slice(before)
    .map((o) => o.payload.event as Record<string, unknown>);
  assert.deepEqual(
    emits.map((e) => ({ kind: e.kind, axis: e.axis, from: e.from, to: e.to, requestedBy: e.requestedBy })),
    [
      { kind: "config_change", axis: "integrity", from: true, to: false, requestedBy: "dashboard" },
      { kind: "config_change", axis: "confidentiality", from: false, to: true, requestedBy: "dashboard" },
    ],
  );
  const body = (await res.json()) as AxesStateWithAudit & { mode: string; effectiveMode: string };
  assert.equal(body.mode, "secrets");
  assert.equal(body.effectiveMode, "secrets");
  assert.equal(body.audit?.confidentiality?.to, true, "read back over the real events op");
  const text = readFileSync(join(dir, "mandu", "config.toml"), "utf8");
  assert.match(text, /^mode = "secrets"$/m);
  assert.match(text, /^integrity = false$/m, "the EXISTING axis line was re-aligned to the mode's pair");
  assert.doesNotMatch(text, /^confidentiality\s*=/m, "no axis line was appended");
});

test("an unknown mode, or a mode mixed with axis keys, is refused with 400 and nothing crosses the wire", async () => {
  const before = arbiter.ops.length;
  assert.equal((await postAxes({ mode: "paranoid" })).status, 400);
  assert.equal((await postAxes({ mode: "full", integrity: true })).status, 400);
  assert.equal(arbiter.ops.length, before);
});

test("a single-axis write re-aligns the mode line: one event, and the file never contradicts itself", async () => {
  const before = arbiter.ops.filter((o) => o.op === "emit").length;
  const res = await postAxes({ integrity: true }); // secrets + masking on = full
  assert.equal(res.status, 200);
  assert.equal(arbiter.ops.filter((o) => o.op === "emit").length, before + 1);
  const body = (await res.json()) as AxesStateWithAudit & { mode: string; effectiveMode: string };
  assert.equal(body.mode, "full");
  assert.equal(body.effectiveMode, "full");
  assert.match(readFileSync(join(dir, "mandu", "config.toml"), "utf8"), /^mode = "full"$/m);
});

test("the integrity freeze: without the opt-in a frozen act reaches neither the file nor the socket; turning it off still audits", async () => {
  const frozenDir = tmpDir("mandu-config-audit-frozen-");
  const cfg = join(frozenDir, "mandu", "config.toml");
  mkdirSync(join(frozenDir, "mandu"), { recursive: true });
  writeFileSync(cfg, 'mode = "full"\n');
  const frozen = new DashboardServer({
    source: fakeSource,
    configEnv: { MANDU_HOME: join(frozenDir, "mandu") },
    auditArbiter: socketAuditArbiter(arbiter.socketPath),
    log: () => {},
    ...ADMIN_OPTS,
  });
  const port = await frozen.listen(0);
  const post = (body: unknown) => fetch(`http://127.0.0.1:${port}/api/config/axes`, {
    method: "POST", headers: CSRF, body: JSON.stringify(body),
  });
  try {
    const get = (await (await fetch(`http://127.0.0.1:${port}/api/config/axes`)).json()) as { integrityAllowed: boolean };
    assert.equal(get.integrityAllowed, false);
    const opsBefore = arbiter.ops.length;
    for (const body of [{ mode: "injection" }, { mode: "full" }, { integrity: true }, { confidentiality: false }]) {
      const res = await post(body);
      assert.equal(res.status, 403, JSON.stringify(body));
      assert.equal(((await res.json()) as { frozen: boolean }).frozen, true);
    }
    assert.equal(arbiter.ops.length, opsBefore, "no op crossed the wire for a refused act");
    assert.equal(readFileSync(cfg, "utf8"), 'mode = "full"\n', "the file is untouched");

    const emitsBefore = arbiter.ops.filter((o) => o.op === "emit").length;
    const res = await post({ mode: "secrets" });
    assert.equal(res.status, 200, "turning integrity off is never refused");
    const emits = arbiter.ops.filter((o) => o.op === "emit").slice(emitsBefore)
      .map((o) => o.payload.event as Record<string, unknown>);
    assert.deepEqual(emits.map((e) => [e.axis, e.from, e.to]), [["integrity", true, false]]);
  } finally {
    await frozen.close();
    rmSync(frozenDir, { recursive: true, force: true });
  }
});
