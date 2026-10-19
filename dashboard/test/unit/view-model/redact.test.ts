/**
 * redact.test — the signed-out projection of a session's events
 * (src/view-model/redact.ts; dashboard.md §6 "Reads and the admin session").
 *
 * Pure: each place a value sits is emptied (an original, a symbol's value, a
 * seeded file, a HumanView final file), what the AI saw stays (the
 * symbolized form, symbol names and levels, decisions, the AgentView final
 * file), the input is never mutated, and a view-model derived from the
 * projection carries no value at any depth.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { redactEvent, redactEvents } from "../../../src/view-model/redact.js";
import { toSessionViewModel } from "../../../src/view-model.js";
import type { ManduEvent } from "../../../src/event-model.js";

const CANARY = "sk-redact-canary-55aa";
const SYM = "$MDU:Read[beef]";

function ev(over: Partial<ManduEvent>): ManduEvent {
  return {
    id: "e1", sessionId: "s1", turn: 1, ts: "2026-10-05T10:00:00.000Z", seq: 1, callId: "c1", parentId: null,
    kind: "tool_result", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
    input: null, output: null, invariant: { violatedInvariant: false }, ...over,
  } as ManduEvent;
}

const dual = () => ({
  symbolized: `key=${SYM}`, original: `key=${CANARY}`, differs: true,
  symbols: [{ name: SYM, tool: "Read", field: null, origin: "/w/.env", value: CANARY, confidentiality: "no-model" }],
});

test("every value goes; what the AI saw stays; the input is untouched", () => {
  const e = ev({ input: dual(), output: dual(), policy: { trust: "TRUSTED", confidentiality: "no-model" } });
  const before = JSON.stringify(e);
  const r = redactEvent(e);
  assert.equal(JSON.stringify(e), before, "never mutated");
  for (const d of [r.input!, r.output!]) {
    assert.equal(d.original, null);
    assert.equal(d.symbolized, `key=${SYM}`);
    assert.equal(d.differs, true, "that it was masked is metadata");
    assert.deepEqual(d.symbols.map((s) => [s.name, s.value, s.confidentiality]), [[SYM, null, "no-model"]]);
  }
  assert.deepEqual(r.policy, e.policy);
  assert.ok(!JSON.stringify(r).includes(CANARY));
});

test("the placeholders the original held as written are kept by name (an echo stays an echo signed out), never a value", () => {
  const refusal = ev({ output: { symbolized: `refused ${SYM}`, original: `refused ${SYM} (value ${CANARY})`, differs: true, symbols: [] } });
  const r = redactEvent(refusal);
  assert.deepEqual(r.output!.originalTokens, [SYM]);
  assert.equal(r.output!.original, null);
  assert.ok(!JSON.stringify(r).includes(CANARY));
  // no placeholder in the original: no field
  assert.equal(redactEvent(ev({ output: dual() })).output!.originalTokens, undefined);
});

test("a seeded file and a HumanView final file lose their content, marked withheld; the AgentView file stays", () => {
  const seed = redactEvent(ev({ kind: "workspace_seed" as ManduEvent["kind"], seedFiles: [{ path: ".env", content: `K=${CANARY}`, poisoned: false }] }));
  assert.deepEqual(seed.seedFiles, [{ path: ".env", content: "", poisoned: false, withheld: true }]);
  const final = redactEvent(ev({
    kind: "workspace_final" as ManduEvent["kind"],
    finalViews: [
      { view: "HumanView", root: "/w", truncated: false, files: [{ path: "a", content: CANARY, size: 9, truncated: false, binary: false }] },
      { view: "AgentView", root: "/a", truncated: false, files: [{ path: "a", content: SYM, size: 4, truncated: false, binary: false }] },
    ],
  }));
  assert.deepEqual(final.finalViews![0]!.files, [{ path: "a", content: null, size: 9, truncated: false, binary: false, withheld: true }]);
  assert.equal(final.finalViews![1]!.files[0]!.content, SYM);
  assert.ok(!JSON.stringify(final).includes(CANARY));
});

test("a view-model derived from the projection carries no value at any depth", () => {
  const events = [
    ev({ id: "t", kind: "tllm_call", seq: 1, input: { symbolized: "read it", original: null, differs: false, symbols: [] } }),
    ev({ id: "r", kind: "tool_result", seq: 2, output: dual() }),
    ev({ id: "d", kind: "desymbolize", seq: 3, view: "HumanView", boundary: "network", emitter: "net-supervisor", input: dual() }),
  ];
  assert.ok(JSON.stringify(toSessionViewModel("s1", events)).includes(CANARY), "the full record has it (what there is to leave out)");
  assert.ok(!JSON.stringify(toSessionViewModel("s1", redactEvents(events))).includes(CANARY));
});

// Found by nightly run 2026-10-06-0330: until 2026-10-06 a `symbolize` event
// recorded the value BEFORE masking as its input, in both fields
// (anthropic-proxy and openai-proxy `makeSymbolize`:
// `makeDualRepr(original, original, [])`; fs-sync `makeBirthEvent`:
// `{ symbolized: original, original, … }`). The projection keeps every
// `symbolized`, so the value the AI never saw stayed in the signed-out
// payload. The emitters now record the symbol there; logs written before
// keep that shape, and this pins dashboard.md §6 ("every value the AI did
// not see goes") for them.
test("a symbolize event's input is the value before masking: signed out it goes, the symbol it became stays", () => {
  const shapes: Partial<ManduEvent>[] = [
    // anthropic-proxy / openai-proxy makeSymbolize
    { kind: "symbolize", emitter: "anthropic-proxy",
      input: { symbolized: `key=${CANARY}`, original: `key=${CANARY}`, differs: false, symbols: [] },
      output: { symbolized: SYM, original: `key=${CANARY}`, differs: true, symbols: [{ name: SYM, tool: "Read", field: null, origin: "/w/.env", value: `key=${CANARY}`, confidentiality: "no-model" }] } },
    // fs-sync makeBirthEvent (a twin's field)
    { kind: "symbolize", emitter: "fs-sync", boundary: "filesystem",
      input: { symbolized: CANARY, original: CANARY, differs: false, symbols: [] },
      output: { symbolized: SYM, original: CANARY, differs: true, symbols: [{ name: SYM, tool: "Read", field: "KEY", origin: "/w/.env", value: CANARY }] } },
  ];
  for (const over of shapes) {
    const r = redactEvent(ev(over));
    assert.equal(r.output!.symbolized, SYM, `${over.emitter}: the symbol stays`);
    assert.ok(!JSON.stringify(r).includes(CANARY), `${over.emitter}: the value before masking stays in the signed-out projection`);
  }
});

// The same pattern on the reply filter (until 2026-10-06): its `desymbolize`
// event recorded the whole terminal write, or the whole json-mode record, as
// its `symbolized` form. Either can hold text the AI never saw: a tool's
// output as the agent process got it, the human's prompt before the prompt
// filter. Signed out only the placeholders it named stay.
test("a reply-filter frame keeps only its placeholders signed out; the frame and the value go", () => {
  const frame = `  ⎿  API_KEY=${CANARY}\n● Saved it as ${SYM}.`;
  const r = redactEvent(ev({
    kind: "desymbolize", view: "HumanView", emitter: "reply-filter", callId: null,
    input: { symbolized: frame, original: null, differs: false, symbols: [] },
    output: { symbolized: frame, original: frame.replace(SYM, CANARY), differs: true, symbols: [] },
  }));
  assert.equal(r.input!.symbolized, SYM);
  assert.equal(r.output!.symbolized, SYM);
  assert.equal(r.output!.original, null);
  assert.ok(!JSON.stringify(r).includes(CANARY) && !JSON.stringify(r).includes("API_KEY"), "nothing around the placeholder stays");
  // Another emitter's desymbolize keeps its `symbolized` (what the AI wrote).
  const fill = redactEvent(ev({ kind: "desymbolize", emitter: "arbiter", input: dual() }));
  assert.equal(fill.input!.symbolized, `key=${SYM}`);
});
