/**
 * policy-crosslink.test — the trace ⇄ policy join (policy-surface.md §9.5).
 *
 * The invariants under test:
 *   1. a gate event's ruleRef rides the dual-lanes projection: a correlated
 *      fs_action/exec_action puts {text, ruleRef} on the tool card's gates; an
 *      uncorrelated one puts ruleRef on its OS card. Pre-provenance events
 *      (no policy.ruleRef) degrade to null, never invent a ref.
 *   2. toRuleRefCounts counts decisions per ruleRef.id over the session —
 *      the Policy panel's "decided N here" reverse link.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { toDualLanes } from "../../../src/view-model/dual-lanes.js";
import { toApprovalIdCounts, toRuleRefCounts } from "../../../src/view-model.js";
import { ev, repr } from "./dual-lanes-fixtures.js";

const FS_DENY_REF = { source: "fail-closed" as const, id: "fs:default-deny" };
const VERDICT_REF = { source: "verdict" as const, id: "verdict:egr-2" };

test("a correlated fs_action's ruleRef rides the tool card's gate line", () => {
  const events = [
    ev({ kind: "tool_use", callId: "c1", input: repr('Glob({"path":"/opt/x"})') }),
    ev({
      kind: "fs_action", callId: "c1", boundary: "filesystem",
      input: repr("Glob.path → /opt/x"),
      output: repr("DENIED → /mandu/denied/policy/opt/x"),
      policy: { usage: "needs_approval", reason: "fail-closed", ruleRef: FS_DENY_REF },
    }),
  ];
  const dv = toDualLanes(events);
  const tool = dv.steps.find((s) => s.step === "tool") as { gates: { text: string; ruleRef: unknown }[] };
  assert.ok(tool, "tool card present");
  assert.equal(tool.gates.length, 1);
  assert.match(tool.gates[0]!.text, /DENIED/);
  assert.deepEqual(tool.gates[0]!.ruleRef, FS_DENY_REF);
});

test("a verdict-decided gate carries verdict:<id>; a pre-provenance event degrades to null", () => {
  const events = [
    ev({ kind: "tool_use", callId: "c1", input: repr("Glob({})") }),
    ev({
      kind: "fs_action", callId: "c1", boundary: "filesystem",
      input: repr("Glob.path → /opt/x"), output: repr("DENIED → sentinel-a"),
      policy: { usage: "deny", reason: "human-denied", ruleRef: VERDICT_REF },
    }),
    ev({
      kind: "fs_action", callId: "c1", boundary: "filesystem",
      input: repr("Glob.path → /opt/y"), output: repr("DENIED → sentinel-b"),
      policy: { usage: "deny", reason: "old event, no provenance" },
    }),
  ];
  const dv = toDualLanes(events);
  const tool = dv.steps.find((s) => s.step === "tool") as { gates: { ruleRef: unknown }[] };
  assert.equal(tool.gates.length, 2);
  assert.deepEqual(tool.gates[0]!.ruleRef, VERDICT_REF);
  assert.equal(tool.gates[1]!.ruleRef, null, "no invented provenance");
});

test("an uncorrelated net_action block carries its ruleRef on the OS card", () => {
  const events = [
    ev({
      kind: "net_action", callId: null, boundary: "network",
      input: repr("WebFetch → evil.test"), output: repr("BLOCKED → denied"),
      policy: { usage: "deny", reason: "high session", ruleRef: { source: "rule", id: "session:high-unbound" } },
    }),
  ];
  const dv = toDualLanes(events);
  const os = dv.steps.find((s) => s.step === "os") as { ruleRef: unknown };
  assert.ok(os, "OS card present");
  assert.deepEqual(os.ruleRef, { source: "rule", id: "session:high-unbound" });
});

test("toRuleRefCounts counts per id across the session", () => {
  const events = [
    ev({ kind: "fs_action", policy: { usage: "deny", reason: "r", ruleRef: FS_DENY_REF } }),
    ev({ kind: "fs_action", policy: { usage: "deny", reason: "r", ruleRef: FS_DENY_REF } }),
    ev({ kind: "net_action", policy: { usage: "deny", reason: "r", ruleRef: VERDICT_REF } }),
    ev({ kind: "tool_result", policy: { trust: "UNTRUSTED", reason: "no ref here" } }),
  ];
  assert.deepEqual(toRuleRefCounts(events), {
    "fs:default-deny": 2,
    "verdict:egr-2": 1,
  });
});

test("toApprovalIdCounts counts queued denies per queue row; no invented joins", () => {
  const events = [
    // Two attempts bumping the same Pending row, one touching another.
    ev({ kind: "fs_action", policy: { usage: "needs_approval", reason: "r", ruleRef: FS_DENY_REF, approvalId: "egr-8" } }),
    ev({ kind: "fs_action", policy: { usage: "needs_approval", reason: "r", ruleRef: FS_DENY_REF, approvalId: "egr-8" } }),
    ev({ kind: "net_action", policy: { usage: "needs_approval", reason: "r", approvalId: "egr-3" } }),
    // Pre-provenance deny and a verdict short-circuit: no approvalId, no count.
    ev({ kind: "fs_action", policy: { usage: "deny", reason: "old event" } }),
    ev({ kind: "fs_action", policy: { usage: "deny", reason: "human-denied", ruleRef: VERDICT_REF } }),
  ];
  assert.deepEqual(toApprovalIdCounts(events), { "egr-8": 2, "egr-3": 1 });
});
