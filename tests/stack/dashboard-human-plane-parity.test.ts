/**
 * dashboard-human-plane-parity — the dashboard's arbiter adapters over a REAL
 * ArbiterServer that serves the human plane (docs/design/architecture/arbiter-human-plane.md;
 * CONTRIBUTING.md parity rule: the production wiring, no test bridge).
 *
 * The dashboard is a human-facing consumer: `sessions` / `events` / `subscribe`
 * / `desymbolize` / shallow `resolve` return originals, and the arbiter serves
 * them only on its human socket. Pinned here:
 *   (1) ArbiterEventSource with an EXPLICIT human socket answers every
 *       forwarded op (listSessions, readEvents, subscribe, desymbolize,
 *       resolveSymbol) and keeps the data-plane reads (policySnapshot,
 *       handlingPrompt) on the data socket;
 *   (2) with only the data socket named, it DISCOVERS the human socket from
 *       `hello` (the supervisor-less / adopted dashboard) and answers the same;
 *   (3) against an arbiter with NO human socket, every human-plane read fails
 *       ("human plane unavailable") and is never answered from the data socket;
 *       the live stream delivers nothing;
 *   (4) makeApprovalsArbiter's config-audit `events` read-back rides the human
 *       socket (discovered from `hello`).
 * Mandu-new test code (no reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import type { ManduEvent } from "../../dashboard/src/event-model.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const SESSION = "dash-human-parity";
const SECRET_VALUE = "sk-live-dashboard-parity-0042";

async function rig(withHuman: boolean) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-dash-human-"));
  const dataSock = join(dir, "arbiter.sock");
  const humanSock = humanSockIn(dir);
  const adminSock = join(dir, "admin.sock");
  const server = new ArbiterServer({
    socketPath: dataSock,
    adminSocketPath: adminSock,
    ...(withHuman ? { humanSocketPath: humanSock } : {}),
    dbPath: join(dir, "mandu.db"),
    eventDir: join(dir, "events"),
    adminPolicyDir: null,
    packDir: null,
    log: () => {},
  });
  await server.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  const inner = await data.symbolize({ tool: "Read", field: "notes", value: "# Notes: ship it", sessionKey: SESSION });
  const secret = await data.symbolize({ tool: "Read", field: "env", value: `API_KEY=${SECRET_VALUE}`, confidentiality: "any-model", sessionKey: SESSION });
  const outerValue = `1\t${inner}\n2\t${secret}`;
  const outer = await data.symbolize({ tool: "Read", value: outerValue, sessionKey: SESSION });
  const now = () => new Date().toISOString();
  await data.emit({ id: "p1", sessionId: SESSION, ts: now(), kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy" } as never);
  return {
    dir, dataSock, humanSock, adminSock, data, inner, secret, outer, outerValue,
    emit: (id: string) => data.emit({ id, sessionId: SESSION, ts: now(), kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy" } as never),
    close: async () => {
      data.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

async function exercise(source: ArbiterEventSource, r: Awaited<ReturnType<typeof rig>>, label: string): Promise<void> {
  const sessions = await source.listSessions();
  assert.ok(sessions.some((s) => s.id === SESSION), `${label}: listSessions over the human socket`);
  const events = await source.readEvents(SESSION);
  assert.equal(events.length, 1, `${label}: readEvents over the human socket`);

  // subscribe: the backlog, then a live event.
  const seen: string[] = [];
  let gotLive!: () => void;
  const live = new Promise<void>((res) => (gotLive = res));
  const stop = source.subscribe(SESSION, (e: ManduEvent) => {
    seen.push(e.id);
    if (e.id === "p2") gotLive();
  });
  try {
    for (let i = 0; i < 100 && seen.length === 0; i++) await new Promise((res) => setTimeout(res, 20));
    await r.emit("p2");
    await Promise.race([live, new Promise((_, rej) => setTimeout(() => rej(new Error(`${label}: no live event`)), 4000))]);
    assert.deepEqual(seen, ["p1", "p2"], `${label}: backlog then live over the human socket`);
  } finally {
    stop();
  }

  assert.equal(await source.resolveSymbol(r.outer), r.outerValue, `${label}: shallow resolve is one level`);
  assert.match(await source.desymbolize(r.outer), new RegExp(SECRET_VALUE), `${label}: deep desymbolize`);
  // The data-plane reads stay on the data socket.
  assert.ok(await source.handlingPrompt(), `${label}: handlingPrompt (data plane)`);
}

test("(1) explicit human socket: every forwarded human-plane op answers; data-plane reads stay on the data socket", async () => {
  const r = await rig(true);
  const source = new ArbiterEventSource({ socketPath: r.dataSock, humanSocketPath: r.humanSock });
  try {
    await exercise(source, r, "explicit");
  } finally {
    source.close();
    await r.close();
  }
});

test("(2) only the data socket named: the human socket is discovered from hello", async () => {
  const r = await rig(true);
  const source = new ArbiterEventSource({ socketPath: r.dataSock });
  try {
    assert.equal((await r.data.hello()).humanSock, r.humanSock, "hello names the human socket");
    await exercise(source, r, "discovered");
  } finally {
    source.close();
    await r.close();
  }
});

test("(3) an arbiter with no human socket: every human-plane read fails, none is answered from the data socket", async () => {
  const r = await rig(false);
  const source = new ArbiterEventSource({ socketPath: r.dataSock });
  try {
    assert.equal((await r.data.hello()).humanSock, null);
    await assert.rejects(source.listSessions(), /human plane unavailable/);
    await assert.rejects(source.readEvents(SESSION), /human plane unavailable/);
    await assert.rejects(source.desymbolize(r.outer), /human plane unavailable/);
    await assert.rejects(source.resolveSymbol(r.outer), /human plane unavailable/);
    // The data socket itself refuses exactly those ops.
    await assert.rejects(r.data.events(SESSION), /human-plane/);
    await assert.rejects(r.data.desymbolize(r.outer), /human-plane/);
    // The live stream delivers nothing (no fallback stream).
    const seen: string[] = [];
    const stop = source.subscribe(SESSION, (e) => seen.push(e.id));
    await new Promise((res) => setTimeout(res, 200));
    await r.emit("p9");
    await new Promise((res) => setTimeout(res, 200));
    stop();
    assert.deepEqual(seen, [], "no event reaches the dashboard without the human plane");
    // The data-plane read still works.
    assert.ok(await source.handlingPrompt());
  } finally {
    source.close();
    await r.close();
  }
});

test("(4) makeApprovalsArbiter's audit read-back rides the human socket (discovered from hello)", async () => {
  const r = await rig(true);
  const wired = await makeApprovalsArbiter(r.dataSock, () => ({ socketPath: r.adminSock }));
  try {
    assert.ok(wired?.audit, "the audit surface is wired");
    await wired.audit.emit({ id: "a1", sessionId: SESSION, ts: new Date().toISOString(), kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "dashboard" });
    const events = await wired.audit.events(SESSION);
    assert.deepEqual(events.map((e) => e["id"]).sort(), ["a1", "p1"], "events read back over the human socket");
  } finally {
    wired?.close();
    await r.close();
  }
});
