/**
 * human-plane-adapter — the net-proxy adapter's split
 * (docs/design/architecture/arbiter-human-plane.md): the shallow `resolve` of an ALLOWED
 * symbol goes to the HUMAN-plane client and nowhere else; with no human client
 * it throws, and the egress gate WITHHOLDS (blocks) rather than resolving.
 * The data client's `resolve` is never called. Mandu-new (no reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ArbiterClientAdapter,
  HUMAN_SOCK_ENV,
  humanSockFromEnv,
  type DesymbolizationRequest,
  type RealArbiterClient,
} from "../../src/arbiter-client.js";
import { gateRequest } from "../../src/egress.js";

const SYM = "$MDU:Read[1a2b]";
const RAW = "the-original-value";

function fakeData(calls: string[]): RealArbiterClient {
  return {
    connect: async () => {},
    desymbolizationDecision: async (_req: DesymbolizationRequest) => ({ allow: true as const, reason: "fake allow" }),
    resolve: async () => { calls.push("data.resolve"); return RAW; },
    symbolize: async () => SYM,
    classify: async () => ({ trust: "TRUSTED" as const, category: null, reason: "fake" }),
    taintProcess: async () => {},
    isProcessTainted: async () => ({ tainted: false }),
    close: () => {},
  };
}

function input(arbiter: ArbiterClientAdapter) {
  return {
    method: "POST",
    destinationHost: "api.example.com",
    url: "http://api.example.com/x",
    headers: {},
    bodyText: `{"v":"${SYM}"}`,
    arbiter,
  };
}

test("humanSockFromEnv reads only MANDU_ARBITER_HUMAN_SOCK", () => {
  assert.equal(HUMAN_SOCK_ENV, "MANDU_ARBITER_HUMAN_SOCK");
  assert.equal(humanSockFromEnv({ MANDU_ARBITER_HUMAN_SOCK: "/h.sock" }), "/h.sock");
  assert.equal(humanSockFromEnv({ MANDU_ARBITER_SOCK: "/data.sock" }), null);
  assert.equal(humanSockFromEnv({ MANDU_ARBITER_HUMAN_SOCK: "" }), null);
});

test("resolve goes to the human client; the data client's resolve is never called", async () => {
  const calls: string[] = [];
  const adapter = new ArbiterClientAdapter(fakeData(calls), {
    resolve: async (s) => { calls.push(`human.resolve:${s}`); return RAW; },
    close: () => {},
  });
  assert.equal(await adapter.resolve(SYM), RAW);
  assert.deepEqual(calls, [`human.resolve:${SYM}`]);
  const r = await gateRequest(input(adapter));
  assert.equal(r.action, "forward", JSON.stringify(r));
  assert.ok(!calls.includes("data.resolve"));
});

test("no human client → resolve throws and the gate WITHHOLDS (block), never the data socket", async () => {
  const calls: string[] = [];
  const adapter = new ArbiterClientAdapter(fakeData(calls));
  await assert.rejects(adapter.resolve(SYM), /MANDU_ARBITER_HUMAN_SOCK/);
  const r = await gateRequest(input(adapter));
  assert.equal(r.action, "block");
  assert.ok(r.action === "block" && r.withheld.some((w) => w.symbol === SYM && /resolve failed after allow/.test(w.reason)));
  assert.deepEqual(calls, [], "the data client was never asked to resolve");
});

test("an unreachable human client → the same withhold", async () => {
  const adapter = new ArbiterClientAdapter(fakeData([]), {
    resolve: async () => { throw new Error("connect ENOENT /h.sock"); },
    close: () => {},
  });
  const r = await gateRequest(input(adapter));
  assert.equal(r.action, "block");
});

// Plan 13 D9 leftovers (arbiter-human-plane.md §10): the holder chains a
// `taintedProcessBindings` carries are believed only on the human socket.
const NO_TAINT = { tainted: false, level: null, files: [], bindings: [] };

test("taintedProcessBindings rides the human client when there is one; the data client is not asked", async () => {
  const calls: string[] = [];
  const data: RealArbiterClient = { ...fakeData(calls), taintedProcessBindings: async (a) => { calls.push(`data:${a.procKey}`); return NO_TAINT; } };
  const adapter = new ArbiterClientAdapter(data, {
    resolve: async () => RAW,
    taintedProcessBindings: async (a) => { calls.push(`human:${a.procKey}:${(a.ancestors ?? []).join(">")}`); return NO_TAINT; },
    close: () => {},
  });
  await adapter.taintedProcessBindings({ procKey: "c:1", ancestors: ["p:1"], session: "s" });
  assert.deepEqual(calls, ["human:c:1:p:1"]);
});

test("taintedProcessBindings falls back to the data socket (a claim) when the human client is absent or fails, with the same answer", async () => {
  const tainted = { tainted: true, level: "no-model", files: ["/x/.env"], bindings: ["a.example"] };
  for (const human of [null, { resolve: async () => RAW, close: () => {} }, {
    resolve: async () => RAW,
    taintedProcessBindings: async () => { throw new Error("human socket gone"); },
    close: () => {},
  }]) {
    const calls: string[] = [];
    const data: RealArbiterClient = { ...fakeData(calls), taintedProcessBindings: async (a) => { calls.push(`data:${a.procKey}`); return tainted; } };
    const adapter = new ArbiterClientAdapter(data, human);
    assert.deepEqual(await adapter.taintedProcessBindings({ procKey: "c:2", ancestors: ["p:2"] }), tainted);
    assert.deepEqual(calls, ["data:c:2"]);
  }
});

// arbiter-human-plane.md §10.3: only an ask on the human socket spends a
// human's Allow once, so the egress decision rides the human client.
test("desymbolizationDecision rides the human client when it has the op; the data client otherwise; a human failure blocks and is not retried on the data socket", async () => {
  const calls: string[] = [];
  const data: RealArbiterClient = {
    ...fakeData(calls),
    desymbolizationDecision: async (req) => { calls.push(`data:${req.symbol}`); return { allow: false, requiresApproval: true, reason: "data" }; },
  };
  const viaHuman = new ArbiterClientAdapter(data, {
    resolve: async () => RAW,
    desymbolizationDecision: async (req) => { calls.push(`human:${req.symbol}@${req.destination}`); return { allow: true, reason: "human-approved" }; },
    close: () => {},
  });
  const r = await gateRequest(input(viaHuman));
  assert.equal(r.action, "forward", JSON.stringify(r));
  assert.deepEqual(calls, [`human:${SYM}@api.example.com`], "the gate's ask, on the human socket");

  calls.length = 0;
  await new ArbiterClientAdapter(data, { resolve: async () => RAW, close: () => {} }).desymbolizationDecision({ symbol: SYM, boundary: "network" });
  await new ArbiterClientAdapter(data, null).desymbolizationDecision({ symbol: SYM, boundary: "network" });
  assert.deepEqual(calls, [`data:${SYM}`, `data:${SYM}`], "a human client without the op, or none: the data client");

  calls.length = 0;
  const failing = new ArbiterClientAdapter(data, {
    resolve: async () => RAW,
    desymbolizationDecision: async () => { throw new Error("human socket gone"); },
    close: () => {},
  });
  const blocked = await gateRequest(input(failing));
  assert.equal(blocked.action, "block", "fail-closed");
  assert.deepEqual(calls, [], "never retried on the data socket");
});
