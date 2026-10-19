/**
 * symbol-timeline.test.ts — unit tests for the §4.14 symbol-table timeline
 * view-model surface: the per-symbol BIRTH exposed on the inspector rows
 * (symbols.ts SymbolInspectorRow.birthSeq/birthTurn/birthTs/birthEventId) and
 * the per-step freshly-minted names on the trace steps (dual-lanes.ts
 * DualToolStep.newSymbols).
 *
 * The contract under test: ONE birth per name per session, by canonical order
 * (ts then seq, §3.2), no matter how many turns re-emit the symbol — the
 * stateless-API history re-sends fold exactly as toDualLanes already folds
 * them — and the birth data supports the modal's ≤/== anchor cut (a later-born
 * symbol is excluded from an earlier anchor's table).
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { toDualLanes, toSymbolInspector } from "../../../src/view-model.js";
import type { ManduEvent, SymbolRef } from "../../../src/event-model.js";

let seq = 0;
function ev(partial: Partial<ManduEvent> & { kind: ManduEvent["kind"] }): ManduEvent {
  seq += 1;
  return {
    id: `ev${seq}`,
    sessionId: "s",
    turn: 0,
    ts: new Date(Date.parse("2026-07-09T10:00:10.000Z") + seq * 1000).toISOString(),
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

function repr(symbolized: string, original: string | null = null, symbols: SymbolRef[] = []) {
  return { symbolized, original, differs: original !== null && symbolized !== original, symbols };
}

const BASH_SYM: SymbolRef = {
  name: "$MDU:Bash[4fcb]", tool: "Bash", field: null,
  origin: "http://example.test/setup-guide", value: "<html>injected</html>",
};
const READ_SYM: SymbolRef = {
  name: "$MDU:Read[3951]", tool: "Read", field: null,
  origin: "/ws/doc.md", value: "1\t$MDU:Bash[4fcb]",
};

/** The re-emission trace: call c1 mints Bash[4fcb], re-guarded twice on later
 *  turns; call c2 then mints Read[3951] whose refs ALSO carry Bash[4fcb] (the
 *  chain-fetch-write-read twin shape — the re-reference must not re-birth it). */
function chainEvents(): ManduEvent[] {
  seq = 0;
  const bashOut = repr("$MDU:Bash[4fcb]", "<html>injected</html>", [BASH_SYM]);
  const readOut = repr("$MDU:Read[3951]", "1\t$MDU:Bash[4fcb]", [READ_SYM, BASH_SYM]);
  return [
    ev({ kind: "tool_use", callId: "c1", turn: 1, input: repr('Bash({"command":"curl -s http://example.test/setup-guide"})') }),
    ev({ kind: "symbolize", callId: "c1", turn: 2, output: bashOut }), // ← the BIRTH (seq 2)
    ev({ kind: "tool_result", callId: "c1", turn: 2, output: bashOut, policy: { trust: "UNTRUSTED", reason: "fail-closed" } }),
    // Turns 3–4: the SAME result re-guarded on later model calls (history re-sends).
    ev({ kind: "symbolize", callId: "c1", turn: 3, output: bashOut }),
    ev({ kind: "tool_result", callId: "c1", turn: 3, output: bashOut, policy: { trust: "UNTRUSTED" } }),
    ev({ kind: "symbolize", callId: "c1", turn: 4, output: bashOut }),
    ev({ kind: "tool_result", callId: "c1", turn: 4, output: bashOut, policy: { trust: "UNTRUSTED" } }),
    // Call c2 (later): mints Read[3951]; its refs re-reference Bash[4fcb].
    ev({ kind: "tool_use", callId: "c2", turn: 4, input: repr('Read({"file_path":"/ws/doc.md"})') }),
    ev({ kind: "symbolize", callId: "c2", turn: 5, output: readOut }), // ← Read's BIRTH (seq 9)
    ev({ kind: "tool_result", callId: "c2", turn: 5, output: readOut, policy: { trust: "UNTRUSTED" } }),
  ];
}

// ── birth exposure on the inspector rows ──────────────────────────────────────

test("birth exposure: the row carries seq/turn/ts/id of the FIRST-referencing event (== flow[0])", () => {
  const rows = toSymbolInspector(chainEvents());
  const bash = rows.find((r) => r.name === BASH_SYM.name)!;
  assert.ok(bash, "the Bash symbol has a row");
  assert.equal(bash.birthSeq, 2, "birth = the first symbolize, not a later re-emission");
  assert.equal(bash.birthTurn, 2);
  assert.equal(bash.birthTs, "2026-07-09T10:00:12.000Z");
  assert.equal(bash.birthEventId, "ev2");
  // The birth IS flow[0] — one source of truth, two spellings.
  assert.equal(bash.flow[0]!.role, "created");
  assert.equal(bash.flow[0]!.seq, bash.birthSeq);
  assert.equal(bash.flow[0]!.eventId, bash.birthEventId);
});

test("one birth per name despite re-emissions: 3 turns of re-guards + a cross-call re-reference never move it", () => {
  const rows = toSymbolInspector(chainEvents());
  const bash = rows.find((r) => r.name === BASH_SYM.name)!;
  // 3× symbolize + 3× tool_result on c1, + symbolize/tool_result on c2 = 8 refs…
  assert.equal(bash.flow.length, 8, "every referencing event is in the flow");
  // …but exactly ONE is the birth.
  assert.equal(bash.flow.filter((f) => f.role === "created").length, 1);
  assert.equal(bash.birthSeq, 2, "the c2 re-reference (seq 9/10) did not re-birth the symbol");
});

test("the ≤/== cut basis: a later-born symbol has a strictly larger birthSeq and falls out of an earlier anchor", () => {
  const rows = toSymbolInspector(chainEvents());
  const bash = rows.find((r) => r.name === BASH_SYM.name)!;
  const read = rows.find((r) => r.name === READ_SYM.name)!;
  assert.ok(read.birthSeq > bash.birthSeq, "later mint → larger birthSeq");
  // The modal's cut (app.js renderSymTableModal): rows with birthSeq ≤ anchor.
  const atBashBirth = rows.filter((r) => r.birthSeq <= bash.birthSeq);
  assert.deepEqual(atBashBirth.map((r) => r.name), [BASH_SYM.name], "the earlier anchor excludes the later-born symbol");
  const atReadBirth = rows.filter((r) => r.birthSeq <= read.birthSeq);
  assert.equal(atReadBirth.length, 2, "the later anchor is the fuller table");
});

// ── per-step freshly-minted names (the assignment markers' source) ────────────

test("newSymbols: the minting step lists the name ONCE; re-emitting steps/calls list nothing", () => {
  const dv = toDualLanes(chainEvents());
  const tools = dv.steps.filter((s) => s.step === "tool");
  assert.equal(tools.length, 2, "one step per call, re-sends folded");
  const [c1, c2] = tools;
  if (c1!.step !== "tool" || c2!.step !== "tool") return assert.fail("tool steps expected");
  assert.deepEqual(c1.newSymbols, [BASH_SYM.name], "the Bash symbol is born at c1 — exactly once despite 3 re-guards");
  assert.deepEqual(c2.newSymbols, [READ_SYM.name], "c2 mints only its OWN symbol — the re-referenced Bash name is not re-born");
});

test("re-minted NAMES for an already-banded value are folds, not births (no marker)", () => {
  seq = 0;
  const mk = (name: string) => repr(name, "SAME RAW VALUE", [{ name, tool: "Read", field: null, origin: "/ws/a.md", value: "SAME RAW VALUE" }]);
  const events = [
    ev({ kind: "tool_use", callId: "c1", input: repr('Read({"file_path":"/ws/a.md"})') }),
    ev({ kind: "symbolize", callId: "c1", output: mk("$MDU:Read[1a9f]") }),
    ev({ kind: "tool_result", callId: "c1", output: mk("$MDU:Read[1a9f]"), policy: { trust: "UNTRUSTED" } }),
    // Later turns: the arbiter minted FRESH names for the same value (the fold
    // toDualLanes already applies) — these are re-emissions, not new births.
    ev({ kind: "symbolize", callId: "c1", output: mk("$MDU:Read[4026]") }),
    ev({ kind: "symbolize", callId: "c1", output: mk("$MDU:Read[a124]") }),
  ];
  const t = toDualLanes(events).steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.deepEqual(t.newSymbols, ["$MDU:Read[1a9f]"], "only the first minted name is a birth");
});

test("a step can mint several names — all badged on that one step", () => {
  seq = 0;
  const a: SymbolRef = { name: "$MDU:WebFetch[a1b2].title", tool: "WebFetch", field: null, origin: "http://x", value: "T" };
  const b: SymbolRef = { name: "$MDU:WebFetch[a1b2].body", tool: "WebFetch", field: null, origin: "http://x", value: "B" };
  const out = repr("$MDU:WebFetch[a1b2].title $MDU:WebFetch[a1b2].body", "T B", [a, b]);
  const events = [
    ev({ kind: "tool_use", callId: "w1", input: repr('WebFetch({"url":"http://x"})') }),
    ev({ kind: "symbolize", callId: "w1", output: out }),
    ev({ kind: "tool_result", callId: "w1", output: out, policy: { trust: "UNTRUSTED" } }),
  ];
  const t = toDualLanes(events).steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.deepEqual(t.newSymbols, [a.name, b.name]);
});
