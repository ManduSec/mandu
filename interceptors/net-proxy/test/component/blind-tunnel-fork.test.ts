/**
 * blind-tunnel-fork.test — a forked child writing into its parent's blind
 * tunnel is judged as a sender (plan 13 D6; the P0 triage's item 2a).
 *
 * A blind tunnel (TLS inspection off, or a model host, which is never
 * inspected) is opened for the holders found at the CONNECT. Before the fix
 * the check before each chunk asked about those holders only: a child that
 * inherited the client socket after the CONNECT and then read a secret was
 * never asked about, so its `after-fork:<secret>` chunk reached a host its
 * secret is not bound to. The TLS-inspected leg already judged the holders
 * of every request (https-taint.test.ts "a holder that appears AFTER the
 * CONNECT").
 *
 * A real NetProxy, a MockArbiter (`secretTaint`: proc key → its secrets'
 * bindings, read live), an injected attribution (the parent at the CONNECT;
 * the parent and its holder child afterwards) and a real TCP destination
 * that records every byte. Asserted, with the destination's record as the
 * oracle:
 *   - the child's chunk after it read a secret is not delivered and the
 *     tunnel closes (TLS inspection off, and a model host with it on);
 *   - the per-chunk check does not pay a full holder rescan while the
 *     arbiter reports no live holder of a secret, and finds the child once
 *     it reads one (the tainted-candidate path);
 *   - an arbiter without the tainted-process op (or failing it) falls back
 *     to a full rescan per chunk, never to the frozen holders alone;
 *   - controls: no fork, and a forked child that holds nothing, keep the
 *     tunnel working; a child whose secret IS bound to the host is let
 *     through.
 *
 * Mandu-new (no reference origin). The mock carries the axes (no arbiter is
 * built): this is the confidentiality axis's network exit.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { connect as netConnect, createServer as createNetServer, type AddressInfo, type Socket } from "node:net";
import { once } from "node:events";

import { NetProxy } from "../../src/proxy.js";
import { MockArbiter, type TaintedProcessBindings } from "../../src/arbiter-client.js";
import { opensslAvailable } from "../../src/ca.js";
import type { ProcHolder } from "../../src/conn-attr.js";
import { tmpDir } from "../tmp-dir.js";

const noop = (): void => {};
const SECRET = "sk_live_FORKCANARY_19d0c7e2";
const held = (bindings: string[], files = ["/w/.env"]): TaintedProcessBindings => ({ tainted: true, level: "no-model", files, bindings });
const PARENT: ProcHolder = { procKey: "8101-parent", ancestors: ["8100-shell"] };
const CHILD: ProcHolder = { procKey: "8102-child", ancestors: ["8101-parent", "8100-shell"] };

/** A TCP listener that records every byte it receives. */
async function recorder() {
  const got: Buffer[] = [];
  const server = createNetServer((s) => {
    s.on("data", (c: Buffer) => got.push(c));
    s.on("error", noop);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, text: () => Buffer.concat(got).toString("utf8"), close: () => server.close() };
}

/** CONNECT through the proxy; resolves the socket and the status line. */
function connectVia(proxyPort: number, host: string, port: number): Promise<{ status: string; sock: Socket }> {
  return new Promise((resolve, reject) => {
    const sock = netConnect(proxyPort, "127.0.0.1", () => {
      sock.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`);
    });
    let head = Buffer.alloc(0);
    const onData = (c: Buffer): void => {
      head = Buffer.concat([head, c]);
      const idx = head.indexOf("\r\n\r\n");
      if (idx === -1) return;
      sock.off("data", onData);
      resolve({ status: head.subarray(0, idx).toString("latin1").split("\r\n")[0]!, sock });
    };
    sock.on("data", onData);
    sock.on("error", reject);
    setTimeout(() => reject(new Error("CONNECT timed out")), 5000).unref();
  });
}

const settle = (ms = 150): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** The attribution a fork produces: the parent alone until `fork()`, then
 *  the parent and the child (they share the client socket). Counts calls. */
function forkingAttribution() {
  let forked = false;
  const a = {
    calls: 0,
    fork: () => { forked = true; },
    holders: (): ProcHolder[] => {
      a.calls++;
      return forked ? [PARENT, CHILD] : [PARENT];
    },
  };
  return a;
}

/** Open a tunnel, send `before-fork`, fork, (let the child read), send the
 *  child's chunk. Returns what the destination got and whether the client
 *  socket was closed by the proxy. */
async function forkScenario(opts: {
  taint: Record<string, TaintedProcessBindings>;
  childReads?: TaintedProcessBindings;
  arbiter?: (taint: Record<string, TaintedProcessBindings>) => MockArbiter;
  model?: boolean;
}) {
  const rec = await recorder();
  const arbiter = opts.arbiter ? opts.arbiter(opts.taint) : new MockArbiter({ secretTaint: opts.taint });
  const attr = forkingAttribution();
  const proxy = new NetProxy({
    allowThisMachine: true,
    arbiter,
    log: noop,
    attributeHolders: attr.holders,
    ...(opts.model ? { modelHosts: ["127.0.0.1"], mitm: { caDir: tmpDir("mandu-fork-model-"), insecureUpstream: true } } : {}),
  });
  const port = await proxy.listen(0);
  try {
    const c = await connectVia(port, "127.0.0.1", rec.port);
    assert.match(c.status, / 200 /, "a parent that holds nothing opens the tunnel");
    let closed = false;
    c.sock.on("close", () => { closed = true; });
    c.sock.on("error", noop);
    c.sock.write("before-fork;");
    await settle();
    assert.equal(rec.text(), "before-fork;", "the parent's chunk is delivered");
    attr.fork();
    if (opts.childReads) opts.taint[CHILD.procKey] = opts.childReads; // the child reads a secret now
    c.sock.write(`after-fork:${SECRET};`);
    await settle(300);
    const out = { got: rec.text(), closed, attributionCalls: attr.calls, arbiter };
    c.sock.destroy();
    return out;
  } finally {
    await proxy.close();
    rec.close();
  }
}

test("2a: a child forked AFTER the CONNECT that reads a secret → its chunk in the inherited blind tunnel is not delivered; the tunnel closes", async () => {
  const r = await forkScenario({ taint: {}, childReads: held(["bound.example"]) });
  assert.equal(r.got, "before-fork;", "nothing the child sent after its read reached the unbound destination");
  assert.ok(!r.got.includes(SECRET), "the secret never left");
  assert.ok(r.closed, "the proxy closed the tunnel");
  assert.ok(r.arbiter.bindingsCalls.some((c) => c.procKey === CHILD.procKey), "the child was asked about");
  const ev = r.arbiter.emittedEvents.find((e) => /tunnel closed/.test(String((e as { note?: string }).note ?? "")));
  assert.ok(ev, "the closing is on the trace");
});

test("2a: the same through a MODEL host's tunnel (never inspected, TLS inspection on) → not delivered", { skip: !opensslAvailable() && "openssl unavailable" }, async () => {
  const r = await forkScenario({ taint: {}, childReads: held(["bound.example"]), model: true });
  assert.equal(r.got, "before-fork;");
  assert.ok(r.closed);
});

test("2a control: no fork, nothing read → every chunk is delivered (the tunnel keeps working)", async () => {
  const rec = await recorder();
  const arbiter = new MockArbiter({ secretTaint: {} });
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, attributeHolders: () => [PARENT] });
  const port = await proxy.listen(0);
  try {
    const c = await connectVia(port, "127.0.0.1", rec.port);
    assert.match(c.status, / 200 /);
    for (let i = 0; i < 5; i++) {
      c.sock.write(`chunk${i};`);
      await settle(40);
    }
    await settle();
    assert.equal(rec.text(), "chunk0;chunk1;chunk2;chunk3;chunk4;");
    c.sock.destroy();
  } finally {
    await proxy.close();
    rec.close();
  }
});

test("2a control: a forked child that holds nothing → its chunk is delivered", async () => {
  const r = await forkScenario({ taint: {} });
  assert.equal(r.got, `before-fork;after-fork:${SECRET};`, "a fork alone is not refused (no over-block)");
  assert.ok(!r.closed);
});

test("2a control: a forked child whose secret IS bound to the destination → delivered (the bound registry keeps working)", async () => {
  const r = await forkScenario({ taint: {}, childReads: held(["127.0.0.1"]) });
  assert.equal(r.got, `before-fork;after-fork:${SECRET};`);
  assert.ok(!r.closed);
});

test("2a cost: while no live process holds a secret the per-chunk check does no holder rescan; it rescans once one does", async () => {
  const clean = await forkScenario({ taint: {} });
  assert.equal(clean.attributionCalls, 1, "the CONNECT's scan only: no holder of a secret, no rescan per chunk");
  const read = await forkScenario({ taint: {}, childReads: held(["bound.example"]) });
  assert.ok(read.attributionCalls >= 2, "a live holder of a secret → the chunk's holders are looked up");
  assert.equal(read.got, "before-fork;");
});

test("2a: a process that already held a secret and RECEIVES the socket after the CONNECT (SCM_RIGHTS: no lineage to the holder) → its chunk is not delivered", async () => {
  const rec = await recorder();
  const OUTSIDER: ProcHolder = { procKey: "8200-outsider", ancestors: ["8199-elsewhere"] };
  const arbiter = new MockArbiter({ secretTaint: { [OUTSIDER.procKey]: held(["bound.example"]) } });
  let passed = false;
  const proxy = new NetProxy({ allowThisMachine: true, arbiter, log: noop, attributeHolders: () => (passed ? [PARENT, OUTSIDER] : [PARENT]) });
  const port = await proxy.listen(0);
  try {
    const c = await connectVia(port, "127.0.0.1", rec.port);
    assert.match(c.status, / 200 /, "the parent holds nothing: the tunnel opens though a process of the session holds a secret");
    c.sock.on("error", noop);
    c.sock.write("before-pass;");
    await settle();
    assert.equal(rec.text(), "before-pass;");
    passed = true;
    c.sock.write(`after-pass:${SECRET};`);
    await settle(300);
    assert.equal(rec.text(), "before-pass;");
    assert.ok(c.sock.destroyed || c.sock.readableEnded);
    c.sock.destroy();
  } finally {
    await proxy.close();
    rec.close();
  }
});

test("2a fail-closed: a narrowing that cannot answer (null, or a throw) → a full rescan of every holder", async () => {
  for (const narrow of [() => null, () => { throw new Error("injected"); }]) {
    let full = 0;
    const rec = await recorder();
    const taint: Record<string, TaintedProcessBindings> = {};
    const arbiter = new MockArbiter({ secretTaint: taint });
    let forked = false;
    const proxy = new NetProxy({
      allowThisMachine: true, arbiter, log: noop,
      attributeHolders: () => { full++; return forked ? [PARENT, CHILD] : [PARENT]; },
      attributeTaintedHolders: narrow,
    });
    const port = await proxy.listen(0);
    try {
      const c = await connectVia(port, "127.0.0.1", rec.port);
      c.sock.on("error", noop);
      c.sock.write("a;");
      await settle();
      forked = true;
      taint[CHILD.procKey] = held(["bound.example"]);
      c.sock.write(`b:${SECRET};`);
      await settle(300);
      assert.equal(rec.text(), "a;");
      assert.ok(full >= 2, "every holder was rescanned");
      c.sock.destroy();
    } finally {
      await proxy.close();
      rec.close();
    }
  }
});

test("2a fail-closed: an arbiter WITHOUT the tainted-process op, or failing it → a full rescan per chunk (never the frozen holders alone)", async () => {
  class NoTaintedOp extends MockArbiter {
    constructor(taint: Record<string, TaintedProcessBindings>) {
      super({ secretTaint: taint });
      (this as { taintedProcesses?: unknown }).taintedProcesses = undefined;
    }
  }
  for (const arbiter of [
    (t: Record<string, TaintedProcessBindings>) => new NoTaintedOp(t),
    (t: Record<string, TaintedProcessBindings>) => new MockArbiter({ secretTaint: t, failTaintedProcesses: true }),
  ]) {
    const r = await forkScenario({ taint: {}, childReads: held(["bound.example"]), arbiter });
    assert.equal(r.got, "before-fork;", "the child's chunk is not delivered");
    assert.ok(r.closed);
    assert.ok(r.attributionCalls >= 2, "the chunk's holders were rescanned");
  }
});
