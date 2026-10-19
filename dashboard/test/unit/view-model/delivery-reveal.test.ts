/**
 * delivery-reveal.test.ts — unit tests for revealDeliveredReply (view-model
 * §4.2c delivery-zone deep reveal).
 *
 * The gap under test (found live, claude-e2e-trusted-and-untrusted 2026-07-09):
 * under the fs dual-view chokepoint the delivered reply's symbol is a NESTED
 * chain — the proxy-minted Read symbol's event-carried value is the AgentView
 * twin's on-disk content, itself a `$MDU:*` token minted by fs-sync
 * before the session's first event — so a one-level, event-mined substitution
 * shows the human a literal symbol token in the "Agent Response" card. The
 * reveal must ask the arbiter (deep desymbolize) for exactly those symbols,
 * and degrade to the event value when the arbiter can't answer (utility-only
 * posture: display fidelity, never a throw).
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { toDualLanes, revealDeliveredReply } from "../../../src/view-model.js";
import type { ManduEvent, SymbolRef } from "../../../src/event-model.js";

let seq = 0;
function ev(partial: Partial<ManduEvent> & { kind: ManduEvent["kind"] }): ManduEvent {
  seq += 1;
  return {
    id: `ev${seq}`,
    sessionId: "s",
    turn: 0,
    ts: new Date(Date.parse("2026-07-09T20:27:10.000Z") + seq * 1000).toISOString(),
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

// The live shape: the outer proxy symbol's value is the twin's on-disk content,
// which still contains the inner fs-sync symbol (with a field-path suffix).
const OUTER = "$MDU:Read[f435]";
const INNER = "$MDU:Read[d9ce].notes.md";
const TWIN_CONTENT = `1\t${INNER}\n2\t`;
const RAW_NOTES = "# Project notes\n\nTODO: ship the proxy.\n";
const OUTER_SYM = {
  name: OUTER, tool: "Read", field: null,
  origin: "/view-state/workspaces/w-1/agentview/notes.md", value: TWIN_CONTENT,
};

/** The trusted-and-untrusted session in miniature: one Read whose result is the
 *  nested symbol, then the final reply carrying the OUTER token. */
function nestedReplyEvents(): ManduEvent[] {
  const symOut = repr(OUTER, TWIN_CONTENT, [OUTER_SYM]);
  return [
    ev({ kind: "tool_use", callId: "c1", input: repr(`Read({"file_path":"/ws/notes.md"})`) }),
    ev({ kind: "symbolize", callId: "c1", output: symOut }),
    ev({ kind: "tool_result", callId: "c1", output: symOut, policy: { trust: "UNTRUSTED" } }),
    ev({
      kind: "tllm_call",
      input: repr("▸ user\nRead notes.md and summarize."),
      output: repr(`Found notes.md. The contents are: ${OUTER}`),
    }),
  ];
}

/** A desymbolizer over a canned symbol table (deep, like the arbiter op). */
function tableDesymbolizer(table: Record<string, string>, calls?: string[]) {
  return async (text: string): Promise<string> => {
    calls?.push(text);
    let current = text;
    for (let i = 0; i < 8; i++) {
      const next = current.replace(/\$MDU:\w+\[\w+\](?:\.\w+)*/g, (m) => table[m] ?? m);
      if (next === current) return next;
      current = next;
    }
    return current;
  };
}

test("a nested (still symbol-bearing) band value is deep-resolved to the original", async () => {
  const dual = toDualLanes(nestedReplyEvents());
  const calls: string[] = [];
  const revealed = await revealDeliveredReply(
    dual,
    tableDesymbolizer({ [OUTER]: TWIN_CONTENT, [INNER]: RAW_NOTES }, calls),
  );

  assert.equal(revealed, 1, "the one delivered-reply symbol was deepened");
  assert.deepEqual(calls, [OUTER], "exactly the reply's symbol goes to the arbiter");
  const final = dual.steps.find((s) => s.step === "response" && s.final);
  assert.ok(final && final.step === "response");
  const band = final.symbols.find((s) => s.name === OUTER)!;
  assert.equal(band.value, `1\t${RAW_NOTES}\n2\t`, "the band carries the FULL original");
  assert.doesNotMatch(band.value!, /\$MDU:/, "no symbol token survives in the revealed value");
});

test("a symbol with NO event-carried value resolves too (minted before the session's events)", async () => {
  // A reply that references the fs-sync symbol directly: no event carries its value.
  const events = [
    ev({
      kind: "tllm_call",
      input: repr("▸ user\nWhat does notes.md say?"),
      output: repr(`The file holds: ${INNER}`),
    }),
  ];
  const dual = toDualLanes(events);
  const revealed = await revealDeliveredReply(dual, tableDesymbolizer({ [INNER]: RAW_NOTES }));
  assert.equal(revealed, 1);
  const final = dual.steps.find((s) => s.step === "response" && s.final);
  assert.ok(final && final.step === "response");
  assert.equal(final.symbols[0]!.value, RAW_NOTES);
});

test("an unknown symbol (desymbolize returns the name unchanged) keeps the event value", async () => {
  const dual = toDualLanes(nestedReplyEvents());
  const revealed = await revealDeliveredReply(dual, tableDesymbolizer({}));
  assert.equal(revealed, 0, "nothing counted as revealed");
  const final = dual.steps.find((s) => s.step === "response" && s.final);
  assert.ok(final && final.step === "response");
  assert.equal(final.symbols[0]!.value, TWIN_CONTENT, "fail toward symbolic: the event value stays");
});

test("a throwing desymbolizer degrades to the event value and never rejects", async () => {
  const dual = toDualLanes(nestedReplyEvents());
  const revealed = await revealDeliveredReply(dual, async () => {
    throw new Error("arbiter away");
  });
  assert.equal(revealed, 0);
  const final = dual.steps.find((s) => s.step === "response" && s.final);
  assert.ok(final && final.step === "response");
  assert.equal(final.symbols[0]!.value, TWIN_CONTENT);
});

test("a flat (token-free) band value costs no arbiter round-trip", async () => {
  const flat = {
    name: "$MDU:Read[aa11]", tool: "Read", field: null,
    origin: "/ws/a.md", value: "already the original",
  };
  const events = [
    ev({ kind: "tool_use", callId: "c1", input: repr(`Read({"file_path":"/ws/a.md"})`) }),
    ev({ kind: "tool_result", callId: "c1", output: repr(flat.name, flat.value, [flat]), policy: { trust: "UNTRUSTED" } }),
    ev({ kind: "tllm_call", input: repr("▸ user\nRead a.md."), output: repr(`Done: ${flat.name}`) }),
  ];
  const dual = toDualLanes(events);
  const calls: string[] = [];
  const revealed = await revealDeliveredReply(dual, tableDesymbolizer({}, calls));
  assert.equal(revealed, 0);
  assert.deepEqual(calls, [], "a full-fidelity value is not re-resolved");
});

// ── Foreign-arbiter sessions (claude-e2e-chain-fetch-write-read, 2026-07-16) ──
// A docker/CI e2e run boots its own in-container arbiter and shares only the
// EVENT dir with the host, so the dashboard's arbiter knows none of the run's
// symbols and `desymbolize` answers unchanged. The reveal must then collapse
// the nested chain from the session's OWN bands: the inner symbol's value was
// banded on its minting tool step. Fixture cut from the live session: curl →
// Bash[a1ae] (the raw page), the model writes the TOKEN into setup.md, the
// Read of the AgentView twin re-symbolizes it as Read[ba5e] whose value is
// literally `1\t$MDU:Bash[a1ae]`, and the delivered reply hands back Read[ba5e].
const CHAIN_BASH = "$MDU:Bash[a1ae]";
const CHAIN_READ = "$MDU:Read[ba5e]";
const CHAIN_HTML = "<html><body><h1>Setup</h1><p>Run the installer.</p></body></html>";
const CHAIN_TWIN = `1\t${CHAIN_BASH}`;
const CHAIN_BASH_SYM = {
  name: CHAIN_BASH, tool: "Bash", field: null,
  origin: "curl -s http://example.test/setup-guide", value: CHAIN_HTML,
};
const CHAIN_READ_SYM = {
  name: CHAIN_READ, tool: "Read", field: null,
  origin: "/view-state/workspaces/w-1/agentview/setup.md", value: CHAIN_TWIN,
};

function foreignArbiterEvents(): ManduEvent[] {
  const bashOut = repr(CHAIN_BASH, CHAIN_HTML, [CHAIN_BASH_SYM]);
  const readOut = repr(CHAIN_READ, CHAIN_TWIN, [CHAIN_READ_SYM]);
  return [
    ev({ kind: "tool_use", callId: "c1", input: repr(`Bash({"command":"curl -s http://example.test/setup-guide"})`) }),
    ev({ kind: "symbolize", callId: "c1", output: bashOut }),
    ev({ kind: "tool_result", callId: "c1", output: bashOut, policy: { trust: "UNTRUSTED" } }),
    ev({ kind: "tool_use", callId: "c2", input: repr(`Read({"file_path":"/ws/setup.md"})`) }),
    ev({ kind: "tool_result", callId: "c2", output: readOut, policy: { trust: "UNTRUSTED" } }),
    ev({
      kind: "tllm_call",
      input: repr("▸ user\nFetch the guide, save it, read it back."),
      output: repr(`Following the setup guide:\n\n${CHAIN_READ}`),
    }),
  ];
}

test("a foreign-arbiter nested chain collapses from the session's own bands", async () => {
  const dual = toDualLanes(foreignArbiterEvents());
  // The arbiter knows NOTHING (the run's symbol DB died with its container).
  const revealed = await revealDeliveredReply(dual, tableDesymbolizer({}));
  assert.equal(revealed, 1, "the local collapse still counts as a reveal");
  const final = dual.steps.find((s) => s.step === "response" && s.final);
  assert.ok(final && final.step === "response");
  const band = final.symbols.find((s) => s.name === CHAIN_READ)!;
  assert.equal(band.value, `1\t${CHAIN_HTML}`, "the inner token resolved from the Bash mint band");
  assert.doesNotMatch(band.value!, /\$MDU:/, "no symbol token survives in the revealed value");
});

test("no desymbolizer at all (arbiter-less source): the local collapse still runs", async () => {
  const dual = toDualLanes(foreignArbiterEvents());
  const revealed = await revealDeliveredReply(dual);
  assert.equal(revealed, 1);
  const final = dual.steps.find((s) => s.step === "response" && s.final);
  assert.ok(final && final.step === "response");
  assert.equal(final.symbols[0]!.value, `1\t${CHAIN_HTML}`);
});

test("an arbiter answer that still carries a foreign inner token gets the local finish", async () => {
  const dual = toDualLanes(foreignArbiterEvents());
  // The arbiter knows the OUTER symbol only (e.g. minted live, inner foreign):
  // its deep resolve returns the twin content with the inner token unresolved.
  const revealed = await revealDeliveredReply(dual, tableDesymbolizer({ [CHAIN_READ]: CHAIN_TWIN }));
  assert.equal(revealed, 1);
  const final = dual.steps.find((s) => s.step === "response" && s.final);
  assert.ok(final && final.step === "response");
  assert.equal(final.symbols[0]!.value, `1\t${CHAIN_HTML}`);
});

test("a truly unknown chain (no local value either) keeps the event value", async () => {
  // Same shape but the inner symbol's value never appears in ANY event: the
  // local table has nothing to substitute, so the band keeps the one-level
  // event value — fail toward symbolic, never fabricate.
  const readOut = repr(CHAIN_READ, CHAIN_TWIN, [CHAIN_READ_SYM]);
  const events = [
    ev({ kind: "tool_use", callId: "c2", input: repr(`Read({"file_path":"/ws/setup.md"})`) }),
    ev({ kind: "tool_result", callId: "c2", output: readOut, policy: { trust: "UNTRUSTED" } }),
    ev({
      kind: "tllm_call",
      input: repr("▸ user\nRead it back."),
      output: repr(`Done: ${CHAIN_READ}`),
    }),
  ];
  const dual = toDualLanes(events);
  const revealed = await revealDeliveredReply(dual, tableDesymbolizer({}));
  assert.equal(revealed, 0);
  const final = dual.steps.find((s) => s.step === "response" && s.final);
  assert.ok(final && final.step === "response");
  assert.equal(final.symbols[0]!.value, CHAIN_TWIN, "the one-level event value stays");
});

test("only the FINAL response step is revealed; interim response cards stay symbolic", async () => {
  const symOut = repr(OUTER, TWIN_CONTENT, [OUTER_SYM]);
  const events = [
    ev({ kind: "tool_use", callId: "c1", input: repr(`Read({"file_path":"/ws/notes.md"})`) }),
    ev({ kind: "tool_result", callId: "c1", output: symOut, policy: { trust: "UNTRUSTED" } }),
    // An interim prose turn referencing the symbol, then the delivered reply.
    ev({ kind: "tllm_call", input: repr("▸ user\nRead it."), output: repr(`Got ${OUTER}, summarizing next.`) }),
    ev({ kind: "tllm_call", input: repr("▸ user\nRead it."), output: repr(`Summary: ${OUTER}`) }),
  ];
  const dual = toDualLanes(events);
  const calls: string[] = [];
  await revealDeliveredReply(dual, tableDesymbolizer({ [OUTER]: TWIN_CONTENT, [INNER]: RAW_NOTES }, calls));

  const responses = dual.steps.filter((s) => s.step === "response");
  assert.equal(responses.length, 2);
  const [interim, final] = responses as [typeof responses[0], typeof responses[0]];
  assert.ok(interim.step === "response" && final.step === "response");
  assert.equal(final.final, true);
  assert.equal(calls.length, 1, "one resolve for the delivered reply only");
  assert.equal(interim.symbols[0]!.value, TWIN_CONTENT, "the interim card keeps the event value");
  assert.doesNotMatch(final.symbols[0]!.value!, /\$MDU:/);
});
