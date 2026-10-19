/**
 * human-plane-parity — the net-proxy adapter's PRODUCTION wiring over a REAL
 * ArbiterServer (CONTRIBUTING.md arbiter-client pattern; docs/design/
 * arbiter-human-plane.md): `new ArbiterClientAdapter(new ArbiterClient(dataSock),
 * new ArbiterClient(humanSock))`, no test bridge, every forwarded op called.
 *   - resolve rides the HUMAN socket and returns the original;
 *   - a symbol ALLOWED by the gate reaches the wire resolved through it;
 *   - with the human client absent, or pointed at the data socket (which
 *     refuses resolve), the same allowed symbol is WITHHELD — the request is
 *     blocked and the original never reaches the wire.
 * Axes are stated as explicit server options (secrets: confidentiality ON,
 * integrity OFF). Mandu-new (no reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterClientAdapter, type RealArbiterClient } from "../../src/arbiter-client.js";
import { gateRequest } from "../../src/egress.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const VALUE = "hello-human-plane-parity-value";

interface Srv {
  listen(): Promise<void>;
  close(): Promise<void>;
  dispatch(req: Record<string, unknown>): { ok: boolean; error?: string };
}

test("parity: the production adapter resolves over the human socket; without it an allowed symbol is withheld", async () => {
  const { ArbiterServer } = (await import(join(REPO, "arbiter/ipc/server.ts"))) as {
    ArbiterServer: new (o: Record<string, unknown>) => Srv;
  };
  const { ArbiterClient } = (await import(join(REPO, "arbiter/ipc/client.ts"))) as {
    ArbiterClient: new (path: string) => RealArbiterClient;
  };
  const dir = mkdtempSync(join(tmpdir(), "mdu-np-parity-"));
  const dataSock = join(dir, "arbiter.sock");
  const humanSock = join(dir, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: dataSock, humanSocketPath: humanSock,
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    adminPolicyDir: null, packDir: null, log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const data = new ArbiterClient(dataSock);
  const human = new ArbiterClient(humanSock);
  const dataAsHuman = new ArbiterClient(dataSock);
  try {
    const adapter = new ArbiterClientAdapter(data, human);
    // Every forwarded op, over the production wiring.
    const sym = await adapter.symbolize({ tool: "Read", field: "content", value: VALUE });
    assert.match(sym, /^\$MDU:/);
    assert.equal(await adapter.resolve(sym), VALUE, "resolve rides the human socket");
    const decision = await adapter.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "api.example.com" });
    assert.equal(typeof decision.allow, "boolean");
    assert.equal(typeof (await adapter.classify({ tool: "WebFetch", value: "x", boundary: "network", origin: "https://api.example.com" })).trust, "string");
    assert.equal(typeof (await adapter.emit({ sessionId: "np-parity", id: "e1" })).seq, "number");
    await adapter.taintProcess({ procKey: "p:1:1", originHost: "evil.example" });
    assert.equal((await adapter.isProcessTainted("p:1:1")).tainted, true);
    assert.equal(typeof (await adapter.taintedProcessBindings({ procKey: "p:2:2" })).tainted, "boolean");
    assert.equal(typeof (await adapter.egressFingerprintScan({ surfaces: [{ where: "body", text: "nothing" }], destination: "api.example.com" })).tripped, "boolean");

    // The gate, end to end, for a symbol ALLOWED at this destination: the
    // human answers the queued ask (an in-process dispatch is the admin channel).
    if (!decision.allow) {
      assert.ok(decision.approvalId, JSON.stringify(decision));
      const v = server.dispatch({ id: "approve", op: "resolveEgressApproval", approvalId: decision.approvalId, approve: true });
      assert.ok(v.ok, v.error);
    }
    const allowed = await adapter.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "api.example.com" });
    assert.equal(allowed.allow, true, `the approved symbol is allowed out (${JSON.stringify(allowed)})`);
    const req = (arbiter: ArbiterClientAdapter) => ({
      method: "POST", destinationHost: "api.example.com", url: "http://api.example.com/x",
      headers: {}, bodyText: `{"v":"${sym}"}`, arbiter,
    });
    const ok = await gateRequest(req(adapter));
    assert.equal(ok.action, "forward", JSON.stringify(ok));
    assert.ok(ok.action === "forward" && ok.rewritten?.bodyText?.includes(VALUE), "the allowed original reaches the wire");

    for (const [name, a] of [
      ["no human client", new ArbiterClientAdapter(data, null)],
      ["the data socket posing as the human one", new ArbiterClientAdapter(data, dataAsHuman)],
    ] as const) {
      const r = await gateRequest(req(a));
      assert.equal(r.action, "block", `${name}: withheld`);
      assert.ok(!JSON.stringify(r).includes(VALUE), `${name}: the original never appears`);
    }
    await assert.rejects(dataAsHuman.resolve(sym), /human-plane/, "the data socket refuses a shallow resolve");
  } finally {
    data.close(); human.close(); dataAsHuman.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("parity (plan 13 D9 leftovers): the production adapter sends the holder chain on the human socket, where it is believed; a data-only wiring's chain is a claim", async () => {
  const { ArbiterServer } = (await import(join(REPO, "arbiter/ipc/server.ts"))) as {
    ArbiterServer: new (o: Record<string, unknown>) => Srv;
  };
  const { ArbiterClient } = (await import(join(REPO, "arbiter/ipc/client.ts"))) as {
    ArbiterClient: new (path: string) => RealArbiterClient;
  };
  const { DatabaseSync } = await import("node:sqlite");
  const dir = mkdtempSync(join(tmpdir(), "mdu-np-chain-"));
  const dataSock = join(dir, "arbiter.sock");
  const humanSock = join(dir, "human", "h.sock");
  const dbPath = join(dir, "db.sqlite");
  const server = new ArbiterServer({
    socketPath: dataSock, humanSocketPath: humanSock, dbPath, eventDir: join(dir, "events"),
    adminPolicyDir: null, packDir: null, log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const data = new ArbiterClient(dataSock);
  const human = new ArbiterClient(humanSock);
  try {
    await new ArbiterClientAdapter(data, human).taintedProcessBindings({ procKey: "np-child:1", ancestors: ["np-parent:1"], session: "np-chain" });
    await new ArbiterClientAdapter(data, null).taintedProcessBindings({ procKey: "np-child:2", ancestors: ["np-parent:2"], session: "np-chain" });
    // arbiter-human-plane.md §10.2: the proxy's events ride the human client
    // too, where they are believed; a data-only wiring's are claims.
    const ev = (id: string) => ({ id, sessionId: "np-chain", ts: new Date().toISOString(), kind: "net_action", emitter: "net-proxy" });
    await new ArbiterClientAdapter(data, human).emit(ev("np-ev-1"));
    await new ArbiterClientAdapter(data, null).emit(ev("np-ev-2"));
    const evs = await (human as unknown as { events(s: string): Promise<Array<{ id: string; claimed?: unknown }>> }).events("np-chain");
    const mark = new Map(evs.map((e) => [e.id, e.claimed]));
    // MASTER: the production wiring sent it on the data socket
    assert.equal(mark.get("np-ev-1"), undefined, "believed");
    assert.equal(mark.get("np-ev-2"), true, "a claim");
    const db = new DatabaseSync(dbPath, { readOnly: true });
    try {
      const believed = db.prepare("SELECT child_key, parent_key FROM process_lineage ORDER BY child_key").all();
      const claimed = db.prepare("SELECT child_key, parent_key FROM process_lineage_claims ORDER BY child_key").all();
      // MASTER: the production wiring sent the chain on the data socket, so
      // np-child:1's edge was a claim and nothing was believed.
      assert.deepEqual(believed.map((r) => `${String(r.child_key)}>${String(r.parent_key)}`), ["np-child:1>np-parent:1"], "the human socket's chain is believed");
      assert.deepEqual(claimed.map((r) => `${String(r.child_key)}>${String(r.parent_key)}`), ["np-child:2>np-parent:2"], "the data socket's chain is a claim");
    } finally { db.close(); }
  } finally {
    data.close(); human.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("parity (arbiter-human-plane.md §10.3): the production adapter asks the egress decision on the human socket, so the proxy's ask is the one that spends a human's Allow once", async () => {
  const { ArbiterServer } = (await import(join(REPO, "arbiter/ipc/server.ts"))) as {
    ArbiterServer: new (o: Record<string, unknown>) => Srv;
  };
  const { ArbiterClient } = (await import(join(REPO, "arbiter/ipc/client.ts"))) as {
    ArbiterClient: new (path: string) => RealArbiterClient;
  };
  const dir = mkdtempSync(join(tmpdir(), "mdu-np-once-"));
  const dataSock = join(dir, "arbiter.sock");
  const humanSock = join(dir, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: dataSock, humanSocketPath: humanSock,
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    adminPolicyDir: null, packDir: null, log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const data = new ArbiterClient(dataSock);
  const human = new ArbiterClient(humanSock);
  try {
    const adapter = new ArbiterClientAdapter(data, human);
    const sym = await adapter.symbolize({ tool: "Read", field: "content", value: "np-once-parity-value", confidentiality: "secret" } as never);
    const ask = () => adapter.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "evil.example", sessionKey: "np-once" });
    const first = await ask();
    assert.equal(first.allow, false);
    assert.ok(first.approvalId, JSON.stringify(first));
    // The human answers Allow once (an in-process dispatch is the admin channel).
    const v = server.dispatch({ id: "once", op: "resolveEgressApproval", approvalId: first.approvalId, approve: true, scope: "once" });
    assert.ok(v.ok, v.error);
    // A data-only wiring (what a program of the agent reaches) is not
    // granted the human's once, and does not spend it.
    const dataOnly = new ArbiterClientAdapter(data, null);
    const agentAsk = await dataOnly.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "evil.example", sessionKey: "np-once" });
    assert.equal(agentAsk.allow, false, "the data socket is not granted the once");
    // With the data client gone, only the human socket can answer the gate.
    data.close();
    const use = await ask();
    assert.equal(use.allow, true, `the gate's ask, over the human socket, gets the one use (${JSON.stringify(use)})`);
    const again = await ask();
    assert.equal(again.allow, false, "spent: it asks again");
    assert.equal(again.approvalId, first.approvalId, "the same row");
  } finally {
    data.close(); human.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
