/**
 * tool-unit-policy.test — unit tests for the PER-TOOL-CALL policy aggregator.
 *
 * Mandu-new test (NO reference origin). A tool call's policy DECISION is split
 * across its phase events: the INBOUND trust decision rides the classify/symbolize
 * (output-guard) event; the OUTBOUND usage decision rides the
 * desymbolize/egress_* (input-guard) event; the shell rides the exec_action.
 * `toolUnitPolicy` folds those into one { inbound, outbound } summary the modal
 * renders. These run under `node --test` (pure, no DOM).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import type { ManduEvent } from "../../../src/event-model.js";
import {
  toTimeline,
  groupToolCalls,
  extractToolUses,
  toolUnitPolicy,
  toSessionViewModel,
  type ToolCallGroup,
} from "../../../src/view-model.js";

let seq = 0;
function ev(partial: Partial<ManduEvent> & Pick<ManduEvent, "kind" | "view">): ManduEvent {
  const s = seq++;
  const ts = new Date(Date.parse("2026-02-01T00:00:00.000Z") + s * 1000).toISOString();
  return {
    id: `id-${s}`,
    sessionId: "t",
    turn: partial.turn ?? 1,
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

function byId(events: ManduEvent[]): Map<string, ManduEvent> {
  return new Map(events.map((e) => [e.id, e]));
}

function firstToolUnit(events: ManduEvent[]): ToolCallGroup {
  const units = groupToolCalls(toTimeline(events), extractToolUses(events));
  const u = units.find((x): x is ToolCallGroup => x.unit === "toolcall");
  assert.ok(u, "expected a tool-call unit");
  return u;
}

test("folds inbound trust (from classify) + outbound usage/shell (from egress/exec)", () => {
  const events = [
    ev({ kind: "classify", view: "Quarantine", callId: "c1", boundary: "model_context",
      policy: { trust: "UNTRUSTED", category: "URL", reason: "url not on allowlist → symbolize" } }),
    ev({ kind: "egress_decision", view: "HumanView", callId: "c1", boundary: "network",
      policy: { usage: "needs_approval", reason: "untrusted symbol → untrusted destination" } }),
    ev({ kind: "exec_action", view: "HumanView", callId: "c1", boundary: "shell",
      policy: { shell: "HumanShell" } }),
  ];
  const p = toolUnitPolicy(firstToolUnit(events), byId(events));
  assert.deepEqual(p.inbound, {
    trust: "UNTRUSTED",
    category: "URL",
    reason: "url not on allowlist → symbolize",
  });
  assert.deepEqual(p.outbound, {
    usage: "needs_approval",
    shell: "HumanShell",
    reason: "untrusted symbol → untrusted destination",
  });
});

test("outbound is null when the tool call has no egress/exec guard", () => {
  const events = [
    ev({ kind: "classify", view: "Quarantine", callId: "c2",
      policy: { trust: "TRUSTED", category: null, reason: "schema rule: literal TRUSTED" } }),
    ev({ kind: "tool_result", view: "AgentView", callId: "c2" }),
  ];
  const p = toolUnitPolicy(firstToolUnit(events), byId(events));
  assert.equal(p.inbound?.trust, "TRUSTED");
  assert.equal(p.outbound, null);
});

test("inbound falls back to the unit's aggregated result trust when no guard policy", () => {
  // A tool_result carrying trust but NO classify/symbolize policy event.
  const events = [
    ev({ kind: "tool_result", view: "Quarantine", callId: "c3",
      policy: { trust: "UNTRUSTED" } }),
  ];
  const p = toolUnitPolicy(firstToolUnit(events), byId(events));
  // unit.trust is derived from the tool_result; inbound mirrors it, category/reason null.
  assert.equal(p.inbound?.trust, "UNTRUSTED");
  assert.equal(p.inbound?.category, null);
});

test("toSessionViewModel attaches .policy to every tool-call unit", () => {
  const events = [
    ev({ kind: "classify", view: "Quarantine", callId: "c4",
      policy: { trust: "UNTRUSTED", category: "DIR", reason: "DIR.classify → UNTRUSTED" } }),
    ev({ kind: "egress_request", view: "HumanView", callId: "c4",
      policy: { usage: "deny", reason: "denied by human" } }),
  ];
  const vm = toSessionViewModel("s", events);
  const unit = vm.toolUnits.find((u): u is ToolCallGroup => u.unit === "toolcall");
  assert.ok(unit?.policy, "expected an attached policy on the tool unit");
  assert.equal(unit!.policy.inbound?.category, "DIR");
  assert.equal(unit!.policy.outbound?.usage, "deny");
});
