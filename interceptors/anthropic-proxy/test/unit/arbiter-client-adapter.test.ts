/**
 * arbiter-client-adapter.test — the adapter over the REAL arbiter client must
 * forward each op in the real client's OWN shape. The plan 10 `callTaint`
 * forwarding once wrapped everything in one object where the client takes
 * `(callId, opts)`; the arbiter refused the request and every live Bash
 * result masked fail-closed (2026-09-24). Pinned here with a recording fake
 * of the real client's signatures; the production wiring itself is proven
 * end to end in tests/stack/proxy-real-client-parity.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { ArbiterClientAdapter, type CallTaintWire, type RealArbiterClient } from "../../src/arbiter-client.js";

const verdict: CallTaintWire = { level: "no-model", files: ["/h/.env"], apps: ["cat"], rule: "secret", mask: [], root: "p1", denied: [] };

function recordingClient(): { client: RealArbiterClient; calls: unknown[][] } {
  const calls: unknown[][] = [];
  const client = {
    connect: async () => {},
    classify: async () => { throw new Error("unused"); },
    symbolize: async () => { throw new Error("unused"); },
    emit: async () => ({ seq: 1 }),
    callTaint: async (...args: unknown[]) => { calls.push(["callTaint", ...args]); return verdict; },
    scanSecretValues: async (...args: unknown[]) => { calls.push(["scanSecretValues", ...args]); return { hits: [] }; },
    close: () => {},
  } as unknown as RealArbiterClient;
  return { client, calls };
}

test("callTaint is forwarded as (callId, {command, session}) — the real client's shape, never one object", async () => {
  const { client, calls } = recordingClient();
  const a = new ArbiterClientAdapter(client);
  assert.deepEqual(await a.callTaint!({ callId: "toolu_1", command: "cat .env", sessionKey: "s1" }), verdict);
  assert.deepEqual(calls, [["callTaint", "toolu_1", { command: "cat .env", session: "s1" }]]);
  calls.length = 0;
  await a.callTaint!({ callId: "toolu_2" });
  assert.deepEqual(calls, [["callTaint", "toolu_2", {}]], "no command / session: an empty options object, callId still positional");
  calls.length = 0;
  await a.callTaint!({ callId: "toolu_3", command: "cat .env", output: "K='$MDU:nomodel_Read[9bbd].K'" });
  assert.deepEqual(calls, [["callTaint", "toolu_3", { command: "cat .env", output: "K='$MDU:nomodel_Read[9bbd].K'" }]], "the §11.8 output rides in the options object");
});

test("an arbiter without the op yields the neutral verdict instead of throwing (older arbiter, nothing to render)", async () => {
  const { client } = recordingClient();
  delete (client as unknown as { callTaint?: unknown }).callTaint;
  const a = new ArbiterClientAdapter(client);
  assert.deepEqual(await a.callTaint!({ callId: "toolu_1" }), { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] });
});

test("scanSecretValues forwards the text positionally", async () => {
  const { client, calls } = recordingClient();
  const a = new ArbiterClientAdapter(client);
  await a.scanSecretValues!("hello");
  assert.deepEqual(calls, [["scanSecretValues", "hello"]]);
});

test("filterPrompt forwards one object (never a dry run); a client without the op throws (fail-closed)", async () => {
  const { client, calls } = recordingClient();
  (client as unknown as { filterPrompt: unknown }).filterPrompt = async (...args: unknown[]) => {
    calls.push(["filterPrompt", ...args]);
    return { segments: [], enforcing: true, dryRun: false, digest: { policy: "", packs: "", values: "" } };
  };
  const a = new ArbiterClientAdapter(client);
  const segments = [{ id: "m0.p0", origin: "human" as const, text: "hi" }];
  await a.filterPrompt!({ session: "s1", agent: "claude-code", segments, dryRun: true } as never);
  assert.deepEqual(calls, [["filterPrompt", { session: "s1", agent: "claude-code", segments }]], "no dryRun reaches the wire from a proxy");
  delete (client as unknown as { filterPrompt?: unknown }).filterPrompt;
  await assert.rejects(new ArbiterClientAdapter(client).filterPrompt!({ agent: "claude-code", segments }), /filterPrompt/);
});

test("emit: the real client's bare seq number is normalized to {seq}; a {seq} object passes through; no op ⇒ seq -1", async () => {
  const { client } = recordingClient();
  (client as unknown as { emit: unknown }).emit = async () => 42;
  assert.deepEqual(await new ArbiterClientAdapter(client).emit({} as never), { seq: 42 });
  (client as unknown as { emit: unknown }).emit = async () => ({ seq: 7 });
  assert.deepEqual(await new ArbiterClientAdapter(client).emit({} as never), { seq: 7 });
  delete (client as unknown as { emit?: unknown }).emit;
  assert.deepEqual(await new ArbiterClientAdapter(client).emit({} as never), { seq: -1 });
});

test("reply row reservation: symbolShape and sessionRelay go to the HUMAN-plane client only (§5.3, §11.5); an older arbiter or no human client answers null", async () => {
  const calls: unknown[][] = [];
  const relay = { mode: "pty" as const, reserve: true, cols: 80, rows: 24, wrap: true, updatedAt: 5 };
  const client = {
    connect: async () => {},
    classify: async () => { throw new Error("unused"); },
    symbolize: async () => { throw new Error("unused"); },
    symbolShape: async () => { throw new Error("the data socket refuses symbolShape — never asked there"); },
    sessionRelay: async () => { throw new Error("the data socket refuses sessionRelay — never asked there"); },
    close: () => {},
  } as unknown as RealArbiterClient;
  const human = {
    symbolShape: async (...args: unknown[]) => { calls.push(["human.symbolShape", ...args]); return args.length > 1 ? { lines: 3, rows: 5 } : { lines: 3 }; },
    sessionRelay: async (...args: unknown[]) => { calls.push(["human.sessionRelay", ...args]); return relay; },
  };
  const a = new ArbiterClientAdapter(client, human);
  assert.deepEqual(await a.symbolShape!("$MDU:nomodel_Bash[464e]"), { lines: 3 });
  assert.deepEqual(await a.symbolShape!("$MDU:nomodel_Bash[464e]", { width: 78, first: 40 }), { lines: 3, rows: 5 });
  assert.deepEqual(await a.symbolShape!("$MDU:nomodel_Bash[464e]", { width: 80, first: 67, rule: "terminal" }), { lines: 3, rows: 5 });
  assert.deepEqual(await a.sessionRelay!("scope-1"), relay);
  assert.deepEqual(calls, [
    ["human.symbolShape", "$MDU:nomodel_Bash[464e]"],
    ["human.symbolShape", "$MDU:nomodel_Bash[464e]", { width: 78, first: 40 }],
    ["human.symbolShape", "$MDU:nomodel_Bash[464e]", { width: 80, first: 67, rule: "terminal" }],
    ["human.sessionRelay", "scope-1"],
  ], "the real client's shapes: (token) or (token, {width, first[, rule]}); (sessionKey); no rule key unless given (§17)");
  // No human-plane client: no shape and no relay, and the data client is never asked.
  const dataOnly = new ArbiterClientAdapter(client);
  assert.equal(await dataOnly.symbolShape!("$MDU:x[ab12]"), null);
  assert.equal(await dataOnly.sessionRelay!("scope-1"), null);
  const older = new ArbiterClientAdapter(recordingClient().client, {});
  assert.equal(await older.symbolShape!("$MDU:x[ab12]"), null);
  assert.equal(await older.sessionRelay!("scope-1"), null);
  const odd = new ArbiterClientAdapter(client, {
    symbolShape: async () => ({ lines: "3" }) as never,
    sessionRelay: async () => undefined as never,
  });
  assert.equal(await odd.symbolShape!("$MDU:x[ab12]"), null, "a malformed answer is no shape");
  assert.equal(await odd.sessionRelay!("s"), null);
  const noRows = new ArbiterClientAdapter(client, { symbolShape: async () => ({ lines: 2, rows: "4" }) as never });
  assert.deepEqual(await noRows.symbolShape!("$MDU:x[ab12]", { width: 78, first: 78 }), { lines: 2 }, "a non-numeric rows is dropped");
});

test("plan 13 D9: execGate and callTaint go to the HUMAN-plane client when there is one (only there does the arbiter bind a call); without it, the data client", async () => {
  const { client, calls } = recordingClient();
  (client as unknown as { execGate: unknown }).execGate = async (...args: unknown[]) => { calls.push(["data.execGate", ...args]); return { decision: "allow" }; };
  const human = {
    execGate: async (...args: unknown[]) => { calls.push(["human.execGate", ...args]); return { decision: "allow" }; },
    callTaint: async (...args: unknown[]) => { calls.push(["human.callTaint", ...args]); return verdict; },
  } as unknown as Pick<RealArbiterClient, "execGate" | "callTaint">;
  const a = new ArbiterClientAdapter(client, human);
  await a.execGate({ command: "ls", sessionKey: "s1", callId: "toolu_9" } as never);
  assert.deepEqual(await a.callTaint!({ callId: "toolu_9", command: "ls", sessionKey: "s1" }), verdict);
  assert.deepEqual(calls, [
    ["human.execGate", { command: "ls", sessionKey: "s1", callId: "toolu_9" }],
    ["human.callTaint", "toolu_9", { command: "ls", session: "s1" }],
  ], "both on the human client, in the real client's shapes");
  calls.length = 0;
  const dataOnly = new ArbiterClientAdapter(client);
  await dataOnly.execGate({ command: "ls", callId: "toolu_10" } as never);
  await dataOnly.callTaint!({ callId: "toolu_10", command: "ls" });
  assert.deepEqual(calls, [["data.execGate", { command: "ls", callId: "toolu_10" }], ["callTaint", "toolu_10", { command: "ls" }]], "no human client: the data client (the arbiter then binds nothing: fail-closed)");
});

test("plan 13 D9 follow-up: recordCallCommand goes to the HUMAN-plane client as one object; without it, the data client; an arbiter without the op records nothing (no throw)", async () => {
  const { client, calls } = recordingClient();
  (client as unknown as { recordCallCommand: unknown }).recordCallCommand = async (...args: unknown[]) => { calls.push(["data.recordCallCommand", ...args]); return { recorded: false, reason: "unauthenticated" }; };
  const human = {
    recordCallCommand: async (...args: unknown[]) => { calls.push(["human.recordCallCommand", ...args]); return { recorded: true }; },
  };
  const a = new ArbiterClientAdapter(client, human as never);
  assert.deepEqual(await a.recordCallCommand!({ callId: "c1", command: "cat /v/x", sessionKey: "s1" }), { recorded: true });
  const dataOnly = new ArbiterClientAdapter(client);
  assert.deepEqual(await dataOnly.recordCallCommand!({ callId: "c2", command: "ls" }), { recorded: false });
  assert.deepEqual(calls, [
    ["human.recordCallCommand", { callId: "c1", command: "cat /v/x", sessionKey: "s1" }],
    ["data.recordCallCommand", { callId: "c2", command: "ls" }],
  ]);
  const old = new ArbiterClientAdapter(recordingClient().client);
  assert.deepEqual(await old.recordCallCommand!({ callId: "c3", command: "ls" }), { recorded: false });
});

test("arbiter-human-plane.md §10.3: the network and path gates ask on the HUMAN-plane client when there is one (only an ask there spends a human's Allow once); without it, the data client; a human-client failure is not retried on the data socket", async () => {
  const { client, calls } = recordingClient();
  const net = { symbol: "$MDU:x[ab12]", boundary: "network" as const, destination: "evil.example", sessionKey: "s1" };
  const fs = { tool: "Read", path: "/opt/x", mode: "read" as const, workspaceRoots: [], sessionKey: "s1" };
  Object.assign(client as object, {
    desymbolizationDecision: async (...args: unknown[]) => { calls.push(["data.desymbolizationDecision", ...args]); return { allow: false, requiresApproval: true, reason: "data" }; },
    fsPathDecision: async (...args: unknown[]) => { calls.push(["data.fsPathDecision", ...args]); return { allow: false, requiresApproval: true, reason: "data" }; },
  });
  const human = {
    desymbolizationDecision: async (...args: unknown[]) => { calls.push(["human.desymbolizationDecision", ...args]); return { allow: true, reason: "human-approved" }; },
    fsPathDecision: async (...args: unknown[]) => { calls.push(["human.fsPathDecision", ...args]); return { allow: true, reason: "human-approved" }; },
  };
  const a = new ArbiterClientAdapter(client, human as never);
  assert.equal((await a.desymbolizationDecision(net)).reason, "human-approved");
  assert.equal((await a.fsPathDecision(fs)).reason, "human-approved");
  assert.deepEqual(calls, [["human.desymbolizationDecision", net], ["human.fsPathDecision", fs]], "both on the human client, one object each");
  calls.length = 0;
  const dataOnly = new ArbiterClientAdapter(client);
  await dataOnly.desymbolizationDecision(net);
  await dataOnly.fsPathDecision(fs);
  assert.deepEqual(calls, [["data.desymbolizationDecision", net], ["data.fsPathDecision", fs]], "no human client: the data client");
  calls.length = 0;
  const failing = new ArbiterClientAdapter(client, {
    desymbolizationDecision: async () => { throw new Error("human socket gone"); },
    fsPathDecision: async () => { throw new Error("human socket gone"); },
  } as never);
  await assert.rejects(failing.desymbolizationDecision(net), /human socket gone/, "a gate error: the net gate blocks");
  await assert.rejects(failing.fsPathDecision(fs), /human socket gone/, "a gate error: the path gate blocks");
  assert.deepEqual(calls, [], "never retried on the data socket");
});
