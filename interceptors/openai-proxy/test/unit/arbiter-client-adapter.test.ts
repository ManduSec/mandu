/**
 * arbiter-client-adapter.test — the adapter over the REAL arbiter client
 * forwards each op in the real client's OWN shape (the plan 10 `callTaint`
 * lesson, anthropic-proxy's arbiter-client-adapter.test.ts). Here: reply row
 * reservation's `symbolShape` and `sessionRelay` (reply-row-reservation.md
 * §5.3, §11.5, §11.7) go to the HUMAN-plane client only, never the data
 * socket, and answer null without it. The production wiring itself is proven
 * end to end in tests/stack/proxy-real-client-parity.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../src/arbiter-client.js";

test("reply row reservation: symbolShape and sessionRelay go to the HUMAN-plane client only; an older arbiter or no human client answers null", async () => {
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
  assert.deepEqual(await a.symbolShape("$MDU:nomodel_exec_command[464e]"), { lines: 3 });
  assert.deepEqual(await a.symbolShape("$MDU:nomodel_exec_command[464e]", { width: 78, first: 40 }), { lines: 3, rows: 5 });
  assert.deepEqual(await a.sessionRelay("scope-1"), relay);
  assert.deepEqual(calls, [
    ["human.symbolShape", "$MDU:nomodel_exec_command[464e]"],
    ["human.symbolShape", "$MDU:nomodel_exec_command[464e]", { width: 78, first: 40 }],
    ["human.sessionRelay", "scope-1"],
  ], "the real client's shapes: (token) or (token, {width, first}); (sessionKey)");
  // No human-plane client: no shape and no relay, and the data client is never asked.
  const dataOnly = new ArbiterClientAdapter(client);
  assert.equal(await dataOnly.symbolShape("$MDU:x[ab12]"), null);
  assert.equal(await dataOnly.sessionRelay("scope-1"), null);
  const older = new ArbiterClientAdapter(client, {});
  assert.equal(await older.symbolShape("$MDU:x[ab12]"), null);
  assert.equal(await older.sessionRelay("scope-1"), null);
  const odd = new ArbiterClientAdapter(client, {
    symbolShape: async () => ({ lines: "3" }) as never,
    sessionRelay: async () => undefined as never,
  });
  assert.equal(await odd.symbolShape("$MDU:x[ab12]"), null, "a malformed answer is no shape");
  assert.equal(await odd.sessionRelay("s"), null);
  const noRows = new ArbiterClientAdapter(client, { symbolShape: async () => ({ lines: 2, rows: "4" }) as never });
  assert.deepEqual(await noRows.symbolShape("$MDU:x[ab12]", { width: 78, first: 78 }), { lines: 2 }, "a non-numeric rows is dropped");
});

test("filterPrompt (plan 15) forwards one object on the data client, never a dry run; no op throws (fail-closed)", async () => {
  const calls: unknown[][] = [];
  const answer = { segments: [], enforcing: true, dryRun: false, digest: { policy: "", packs: "", values: "" } };
  const client = {
    filterPrompt: async (...args: unknown[]) => { calls.push(args); return answer; },
    close: () => {},
  } as unknown as RealArbiterClient;
  const segments = [{ id: "i0.c0.p0", origin: "human" as const, text: "hi" }];
  assert.deepEqual(await new ArbiterClientAdapter(client).filterPrompt({ session: "s", agent: "codex", segments, dryRun: true } as never), answer);
  assert.deepEqual(calls, [[{ session: "s", agent: "codex", segments }]]);
  await assert.rejects(new ArbiterClientAdapter({ close: () => {} } as unknown as RealArbiterClient).filterPrompt({ agent: "codex", segments }), /filterPrompt/);
});

test("plan 13 D9: execGate and callTaint go to the HUMAN-plane client when there is one (only there does the arbiter bind a call); without it, the data client", async () => {
  const calls: unknown[][] = [];
  const verdict = { level: null, files: [], apps: [], rule: "secret" as const, mask: [], root: "p1", denied: [] };
  const client = {
    connect: async () => {},
    classify: async () => { throw new Error("unused"); },
    symbolize: async () => { throw new Error("unused"); },
    execGate: async (...args: unknown[]) => { calls.push(["data.execGate", ...args]); return { decision: "allow" }; },
    callTaint: async (...args: unknown[]) => { calls.push(["data.callTaint", ...args]); return verdict; },
    close: () => {},
  } as unknown as RealArbiterClient;
  const human = {
    execGate: async (...args: unknown[]) => { calls.push(["human.execGate", ...args]); return { decision: "allow" }; },
    callTaint: async (...args: unknown[]) => { calls.push(["human.callTaint", ...args]); return verdict; },
  } as unknown as Pick<RealArbiterClient, "execGate" | "callTaint">;
  const a = new ArbiterClientAdapter(client, human);
  await a.execGate({ command: "ls", sessionKey: "s1", callId: "call_9" } as never);
  await a.callTaint({ callId: "call_9", command: "ls", sessionKey: "s1" });
  assert.deepEqual(calls, [
    ["human.execGate", { command: "ls", sessionKey: "s1", callId: "call_9" }],
    ["human.callTaint", "call_9", { command: "ls", session: "s1" }],
  ]);
  calls.length = 0;
  const dataOnly = new ArbiterClientAdapter(client);
  await dataOnly.execGate({ command: "ls", callId: "call_10" } as never);
  await dataOnly.callTaint({ callId: "call_10", command: "ls" });
  assert.deepEqual(calls, [["data.execGate", { command: "ls", callId: "call_10" }], ["data.callTaint", "call_10", { command: "ls" }]]);
});

test("plan 13 D9 follow-up: recordCallCommand goes to the HUMAN-plane client as one object; without it, the data client; an arbiter without the op records nothing (no throw)", async () => {
  const calls: unknown[][] = [];
  const base = { connect: async () => {}, classify: async () => { throw new Error("unused"); }, symbolize: async () => { throw new Error("unused"); }, close: () => {} };
  const client = {
    ...base,
    recordCallCommand: async (...args: unknown[]) => { calls.push(["data.recordCallCommand", ...args]); return { recorded: false, reason: "unauthenticated" }; },
  } as unknown as RealArbiterClient;
  const human = { recordCallCommand: async (...args: unknown[]) => { calls.push(["human.recordCallCommand", ...args]); return { recorded: true }; } };
  assert.deepEqual(await new ArbiterClientAdapter(client, human as never).recordCallCommand({ callId: "call_1", command: "ls /v", sessionKey: "s" }), { recorded: true });
  assert.deepEqual(await new ArbiterClientAdapter(client).recordCallCommand({ callId: "call_2", command: "ls" }), { recorded: false });
  assert.deepEqual(calls, [
    ["human.recordCallCommand", { callId: "call_1", command: "ls /v", sessionKey: "s" }],
    ["data.recordCallCommand", { callId: "call_2", command: "ls" }],
  ]);
  assert.deepEqual(await new ArbiterClientAdapter(base as unknown as RealArbiterClient).recordCallCommand({ callId: "call_3", command: "ls" }), { recorded: false });
});
