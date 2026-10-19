/**
 * arbiter-client unit test: the adapter forwards each op verbatim to the real
 * client's method of the same name, and fails the call (never guesses) when
 * the connected arbiter predates an op.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { PolicyArbiterAdapter, type RealArbiterClient } from "../../src/arbiter-client.js";

test("the adapter forwards every op verbatim", async () => {
  const seen: Array<[string, unknown]> = [];
  const real: RealArbiterClient = {
    connect: async () => {},
    close: () => {},
    policyExplain: async (a) => (seen.push(["policyExplain", a]), { ok: 1 }),
    testFlow: async (r) => (seen.push(["testFlow", r]), { inbound: { trust: "TRUSTED" }, probe: { level: "public" }, egress: null }),
    policyPropose: async (r) => (seen.push(["policyPropose", r]), { applied: true, changeId: null, delta: [] }),
    policySchema: async () => (seen.push(["policySchema", undefined]), { edits: { type: "array" } }),
  };
  const a = new PolicyArbiterAdapter(real);
  await a.policyExplain({ audience: "agent", sessionKey: "s" });
  await a.testFlow({ destination: "x.example", boundary: "network" });
  await a.policyPropose({ edits: [], reason: "r", sessionKey: "s" });
  assert.deepEqual((await a.policySchema()).edits, { type: "array" });
  assert.deepEqual(seen, [
    ["policyExplain", { audience: "agent", sessionKey: "s" }],
    ["testFlow", { destination: "x.example", boundary: "network" }],
    ["policyPropose", { edits: [], reason: "r", sessionKey: "s" }],
    ["policySchema", undefined],
  ]);
});

test("an arbiter without the op fails the call", async () => {
  const a = new PolicyArbiterAdapter({ connect: async () => {}, close: () => {} });
  await assert.rejects(() => a.policySchema(), /arbiter has no 'policySchema' op/);
  await assert.rejects(() => a.policyPropose({ edits: [] }), /policyPropose/);
});
