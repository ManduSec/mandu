/**
 * correlate.test.ts — unit tests for correlateUllmCalls (view-model/correlate):
 * the display-only pre-pass that attaches orphan `ullm_call` events to the
 * inspect `tool_use` that invoked them.
 *
 * The gap under test: the MCP protocol gives inspect-mcp no way to learn the
 * Anthropic tool_use id, so its ullm_call events arrive with callId null /
 * turn 0 and the dual-lanes fold could never fire. The pre-pass matches each
 * orphan to the nearest PRECEDING inspect tool_use whose args contain the
 * inspected symbol token, claiming each tool_use at most once, and never
 * mutates the input events.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { correlateUllmCalls, toTimeline } from "../../../src/view-model.js";
import type { ManduEvent } from "../../../src/event-model.js";

let seq = 0;
function ev(partial: Partial<ManduEvent> & { kind: ManduEvent["kind"] }): ManduEvent {
  seq += 1;
  return {
    id: `ev${seq}`,
    sessionId: "s",
    turn: 0,
    ts: new Date(Date.parse("2026-07-10T07:30:10.000Z") + seq * 1000).toISOString(),
    seq,
    callId: null,
    parentId: null,
    view: "AgentView",
    boundary: "model_context",
    emitter: "anthropic-proxy",
    input: null,
    output: null,
    invariant: { violatedInvariant: false },
    ...partial,
  } as ManduEvent;
}

function repr(symbolized: string, original: string | null = null) {
  return { symbolized, original, differs: original !== null && symbolized !== original, symbols: [] };
}

const INSPECT = "mcp__mandu-inspect__inspect_symbol";

/** An inspect tool_use whose args reference `symbol` (the live event shape). */
function inspectUse(callId: string, symbol: string, extra: Partial<ManduEvent> = {}): ManduEvent {
  return ev({
    kind: "tool_use", callId,
    input: repr(`${INSPECT}({"symbol":"${symbol}","instruction":"Count occurrences."})`),
    ...extra,
  });
}

/** An orphan ullm_call as inspect-mcp emits it: callId null, turn 0. */
function orphanUllm(symbol: string, extra: Partial<ManduEvent> = {}): ManduEvent {
  return ev({
    kind: "ullm_call", callId: null, turn: 0, view: "Quarantine",
    emitter: "inspect-mcp" as never,
    input: repr(symbol, "<raw inspected content>"),
    output: repr("$MDU:inspect[3021].result", "6"),
    ...extra,
  });
}

test("(a) the live two-event shape correlates: callId + turn adopted from the tool_use", () => {
  const tu = inspectUse("toolu_017za9ziyiJ9sQxHEPqxah8k", "$MDU:WebFetch[5227]", {
    turn: 7, ts: "2026-07-10T07:30:40.498Z",
  });
  const u = orphanUllm("$MDU:WebFetch[5227]", { ts: "2026-07-10T07:30:54.764Z" });
  const out = correlateUllmCalls([tu, u]);
  const cu = out.find((e) => e.kind === "ullm_call")!;
  assert.equal(cu.callId, "toolu_017za9ziyiJ9sQxHEPqxah8k");
  assert.equal(cu.turn, 7, "the emitter's placeholder turn 0 adopts the tool_use turn");
  assert.equal(out.find((e) => e.kind === "tool_use"), tu, "the tool_use passes through by reference");
});

test("(a') a nonzero ullm_call turn is preserved — only the placeholder 0 adopts", () => {
  const tu = inspectUse("c1", "$MDU:Read[1a9f]", { turn: 7 });
  const u = orphanUllm("$MDU:Read[1a9f]", { turn: 5 });
  const cu = correlateUllmCalls([tu, u]).find((e) => e.kind === "ullm_call")!;
  assert.equal(cu.callId, "c1");
  assert.equal(cu.turn, 5, "an emitter that DID know its turn keeps it");
});

test("(b) an already-correlated ullm_call (callId set) is untouched", () => {
  const tu = inspectUse("c1", "$MDU:Read[1a9f]", { turn: 7 });
  const u = orphanUllm("$MDU:Read[1a9f]", { callId: "c1", turn: 3 });
  const out = correlateUllmCalls([tu, u]);
  assert.equal(out.find((e) => e.kind === "ullm_call"), u, "same reference — no clone, no rewrite");
  assert.equal(u.turn, 3);
});

test("(c) no matching inspect tool_use → the orphan stays untouched", () => {
  const read = ev({ kind: "tool_use", callId: "r1", turn: 2,
    input: repr('Read({"file_path":"/ws/notes.md"})') });
  const u = orphanUllm("$MDU:Read[1a9f]");
  const out = correlateUllmCalls([read, u]);
  const cu = out.find((e) => e.kind === "ullm_call")!;
  assert.equal(cu, u, "a non-inspect tool_use is never a candidate");
  assert.equal(cu.callId, null);
  assert.equal(cu.turn, 0);
});

test("(c'') each of Mandu's spellings of the inspect tool is a match target; another server's tool of that name is not", () => {
  for (const tool of ["mandu-inspect_inspect_symbol", "mcp__mandu_inspect__inspect_symbol", "mandu-inspect__inspect_symbol", "inspect_symbol"]) {
    const tu = ev({ kind: "tool_use", callId: "c1", turn: 4, input: repr(`${tool}({"symbol":"$MDU:Read[1a9f]","instruction":"Count."})`) });
    const cu = correlateUllmCalls([tu, orphanUllm("$MDU:Read[1a9f]")]).find((e) => e.kind === "ullm_call")!;
    assert.equal(cu.callId, "c1", tool);
    assert.equal(cu.turn, 4, tool);
  }
  for (const tool of ["mcp__other__inspect_symbol", "other_inspect_symbol"]) {
    const tu = ev({ kind: "tool_use", callId: "c1", turn: 4, input: repr(`${tool}({"symbol":"$MDU:Read[1a9f]"})`) });
    const u = orphanUllm("$MDU:Read[1a9f]");
    assert.equal(correlateUllmCalls([tu, u]).find((e) => e.kind === "ullm_call"), u, tool);
  }
});

test("(c') an inspect tool_use AFTER the ullm_call is not a candidate (must precede)", () => {
  const u = orphanUllm("$MDU:Read[1a9f]");
  const tu = inspectUse("c1", "$MDU:Read[1a9f]", { turn: 7 }); // later ts
  const out = correlateUllmCalls([u, tu]);
  assert.equal(out.find((e) => e.kind === "ullm_call"), u, "the orphan card remains");
});

test("(d) two inspects + two ullm_calls pair by SYMBOL, not adjacency", () => {
  const tuA = inspectUse("cA", "$MDU:WebFetch[1111]", { turn: 3 });
  const tuB = inspectUse("cB", "$MDU:Read[2222]", { turn: 4 });
  // Both ullm_calls arrive after BOTH tool_uses: the nearest-preceding
  // candidate for uA is tuB, but the symbol-containment preference picks tuA.
  const uA = orphanUllm("$MDU:WebFetch[1111]");
  const uB = orphanUllm("$MDU:Read[2222]");
  const out = correlateUllmCalls([tuA, tuB, uA, uB]);
  const [cA, cB] = out.filter((e) => e.kind === "ullm_call");
  assert.equal(cA!.callId, "cA", "paired with ITS symbol despite tuB being nearer");
  assert.equal(cA!.turn, 3);
  assert.equal(cB!.callId, "cB");
  assert.equal(cB!.turn, 4);
});

test("(e) two ullm_calls, one inspect tool_use → only one claims it", () => {
  const tu = inspectUse("c1", "$MDU:Read[1a9f]", { turn: 2 });
  const u1 = orphanUllm("$MDU:Read[1a9f]");
  const u2 = orphanUllm("$MDU:Read[1a9f]");
  const out = correlateUllmCalls([tu, u1, u2]);
  const [c1, c2] = out.filter((e) => e.kind === "ullm_call");
  assert.equal(c1!.callId, "c1", "the earlier orphan claims the tool_use");
  assert.equal(c2, u2, "the later orphan finds no unclaimed candidate — untouched");
  assert.equal(c2!.callId, null);
});

test("(e') a natively-correlated ullm_call pre-claims its tool_use", () => {
  const tu = inspectUse("c1", "$MDU:Read[1a9f]", { turn: 2 });
  const native = orphanUllm("$MDU:Read[1a9f]", { callId: "c1" });
  const stray = orphanUllm("$MDU:Read[1a9f]");
  const out = correlateUllmCalls([tu, native, stray]);
  const cs = out.filter((e) => e.kind === "ullm_call" && e.callId === "c1");
  assert.equal(cs.length, 1, "two quarantine runs never fold onto one tool card");
});

test("(f) the input events array and its elements are never mutated", () => {
  const tu = inspectUse("c1", "$MDU:Read[1a9f]", { turn: 7 });
  const u = orphanUllm("$MDU:Read[1a9f]");
  const events = [tu, u];
  const snapshot = JSON.stringify(events);
  const out = correlateUllmCalls(events);
  assert.notEqual(out, events, "a repair returns a NEW array");
  assert.equal(JSON.stringify(events), snapshot, "inputs byte-identical after the pass");
  assert.equal(u.callId, null, "the original orphan element is untouched");
  assert.equal(u.turn, 0);
  assert.notEqual(out[1], u, "the repaired event is a shallow clone");
});

test("a correlated ullm_call is NOT hoisted ahead of its invoking tool_use in the timeline", () => {
  // lanes.ts pulls model calls ahead of same-turn tool_use runs (a tllm_call is
  // finalized AFTER the tool_use blocks it produced). A correlated ullm_call
  // adopts the tool_use's turn, but it was invoked BY that tool_use — hoisting
  // it would invert reason→decision. Guarded in leadModelCallsBeforeToolUses.
  const tu = inspectUse("c1", "$MDU:Read[1a9f]", { turn: 7 });
  const u = orphanUllm("$MDU:Read[1a9f]");
  const rows = toTimeline(correlateUllmCalls([tu, u]));
  assert.deepEqual(rows.map((r) => r.kind), ["tool_use", "ullm_call"]);
});
