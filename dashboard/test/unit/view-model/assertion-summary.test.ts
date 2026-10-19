/**
 * assertion-summary.test — unit tests for the PURE e2e SECURITY/UTILITY assertion
 * projector (view-model.ts toAssertionSummary) and its integration into
 * toSessionViewModel.
 *
 * Mandu-new test. Runs under `node --test`, no DOM. Covers: grouping into
 * security (blocking) vs utility (non-blocking) vs fidelity (render ≡ recorded
 * history), the security `aspect` split (integrity → confidentiality → an
 * unsplit legacy group for aspect-less checks), the `pass/effective` scoring
 * (skip + warn excluded from the denominator), the overall verdict label/level,
 * the null result for a non-e2e session, and — critically — that the meta
 * `assertion` event is kept OUT of the trace projections.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import type { ManduEvent, AssertionCheck } from "../../../src/event-model.js";
import { toAssertionSummary, toSessionViewModel } from "../../../src/view-model.js";

function base(partial: Partial<ManduEvent>): ManduEvent {
  return {
    id: "e", sessionId: "s", turn: 0, ts: "2026-07-07T00:00:00.000Z", seq: 1,
    callId: null, parentId: null, kind: "tllm_call", view: "AgentView",
    boundary: "model_context", emitter: "anthropic-proxy",
    input: null, output: null, invariant: { violatedInvariant: false },
    ...partial,
  } as ManduEvent;
}

function assertionEvent(checks: AssertionCheck[], id = "a1"): ManduEvent {
  return base({
    id, kind: "assertion", view: "HumanView", emitter: "test-harness",
    ts: "2026-07-07T00:01:00.000Z", assertions: checks,
  });
}

const chk = (over: Partial<AssertionCheck>): AssertionCheck => ({
  label: "c", category: "security", status: "pass", reason: "ok", ...over,
});

test("toAssertionSummary returns null when the session has no assertion event", () => {
  assert.equal(toAssertionSummary([base({ kind: "tllm_call" })]), null);
});

test("groups into security + utility + fidelity with per-group pass/effective scores", () => {
  const s = toAssertionSummary([
    assertionEvent([
      chk({ label: "sym", category: "security", status: "pass" }),
      chk({ label: "raw", category: "security", status: "pass" }),
      chk({ label: "exit", category: "utility", status: "pass" }),
      chk({ label: "stdout", category: "utility", status: "warn" }),
      chk({ label: "history-final-reply-matches", category: "fidelity", status: "pass" }),
    ]),
  ]);
  assert.ok(s);
  assert.deepEqual(s!.groups.map((g) => g.category), ["security", "utility", "fidelity"], "security first, fidelity last");
  const sec = s!.groups[0]!;
  assert.equal(sec.pass, 2);
  assert.equal(sec.effective, 2);
  assert.equal(sec.level, "ok");
  const util = s!.groups[1]!;
  assert.equal(util.pass, 1);
  assert.equal(util.warn, 1);
  assert.equal(util.effective, 1, "warn is excluded from the denominator");
  assert.equal(util.level, "warn");
  const fid = s!.groups[2]!;
  assert.equal(fid.pass, 1);
  assert.equal(fid.effective, 1);
  assert.equal(fid.level, "ok");
  // Overall: no blocking fail, one non-blocking warn.
  assert.equal(s!.blockingFail, 0);
  assert.equal(s!.nonBlocking, 1);
  assert.equal(s!.level, "warn");
  assert.match(s!.label, /PASSED, 1 non-blocking/);
});

test("security checks split into integrity → confidentiality subgroups by aspect", () => {
  const s = toAssertionSummary([
    assertionEvent([
      chk({ label: "conf-wire", aspect: "confidentiality", status: "pass" }),
      chk({ label: "sym", aspect: "integrity", status: "pass" }),
      chk({ label: "raw", aspect: "integrity", status: "fail", reason: "leaked" }),
      chk({ label: "exit", category: "utility", status: "pass" }),
    ]),
  ]);
  assert.ok(s);
  assert.deepEqual(
    s!.groups.map((g) => [g.category, g.aspect]),
    [["security", "integrity"], ["security", "confidentiality"], ["utility", undefined]],
    "integrity first, confidentiality second; no legacy group when every security check carries an aspect",
  );
  const integ = s!.groups[0]!;
  assert.equal(integ.pass, 1);
  assert.equal(integ.fail, 1);
  assert.equal(integ.level, "violation");
  const conf = s!.groups[1]!;
  assert.equal(conf.pass, 1);
  assert.equal(conf.level, "ok");
  // The split refines the display only — the overall tallies are unchanged.
  assert.equal(s!.blockingFail, 1);
  assert.equal(s!.level, "violation");
});

test("aspect-less (legacy) security checks render as an unsplit Security group after the aspect subgroups", () => {
  const s = toAssertionSummary([
    assertionEvent([
      chk({ label: "old-check", status: "pass" }), // a pre-aspect persisted event
      chk({ label: "sym", aspect: "integrity", status: "pass" }),
    ]),
  ]);
  assert.ok(s);
  assert.deepEqual(
    s!.groups.map((g) => [g.category, g.aspect]),
    [["security", "integrity"], ["security", undefined]],
    "legacy events keep rendering — never dropped, never mislabeled",
  );
});

test("a fidelity FAIL is blocking (drift between render and recorded history goes red)", () => {
  const s = toAssertionSummary([
    assertionEvent([
      chk({ label: "raw", category: "security", status: "pass" }),
      chk({ label: "history-final-reply-matches", category: "fidelity", status: "fail", reason: "mismatch" }),
    ]),
  ]);
  assert.ok(s);
  assert.equal(s!.blockingFail, 1);
  assert.equal(s!.level, "violation");
  assert.equal(s!.groups.find((g) => g.category === "fidelity")!.level, "violation");
});

test("a warned check (the human was told, 2026-10-17) is its own group, after utility and before fidelity; its fail is blocking", () => {
  const s = toAssertionSummary([
    assertionEvent([
      chk({ label: "history-final-reply-matches", category: "fidelity", status: "pass" }),
      chk({ label: "warned", category: "warned", status: "fail", reason: "NOT WARNED" }),
      chk({ label: "exit", category: "utility", status: "pass" }),
      chk({ label: "raw", category: "security", status: "pass" }),
    ]),
  ]);
  assert.ok(s);
  assert.deepEqual(s!.groups.map((g) => g.category), ["security", "utility", "warned", "fidelity"]);
  assert.equal(s!.blockingFail, 1);
  assert.equal(s!.groups.find((g) => g.category === "warned")!.level, "violation");
});

test("a security FAIL makes the overall verdict a blocking violation", () => {
  const s = toAssertionSummary([
    assertionEvent([
      chk({ label: "raw", category: "security", status: "fail", reason: "leaked" }),
      chk({ label: "exit", category: "utility", status: "pass" }),
    ]),
  ]);
  assert.ok(s);
  assert.equal(s!.blockingFail, 1);
  assert.equal(s!.level, "violation");
  assert.match(s!.label, /1 FAILED/);
  assert.equal(s!.groups[0]!.level, "violation");
});

test("all-pass yields ALL PASSED with an ok level", () => {
  const s = toAssertionSummary([
    assertionEvent([chk({ category: "security", status: "pass" }), chk({ category: "utility", status: "pass" })]),
  ]);
  assert.equal(s!.level, "ok");
  assert.equal(s!.label, "ALL PASSED");
  assert.equal(s!.pass, 2);
  assert.equal(s!.effective, 2);
});

test("skip is excluded from the score denominator", () => {
  const s = toAssertionSummary([
    assertionEvent([
      chk({ category: "security", status: "pass" }),
      chk({ category: "security", status: "skip" }),
    ]),
  ]);
  assert.equal(s!.groups[0]!.effective, 1, "skip excluded");
  assert.equal(s!.pass, 1);
});

test("the LAST assertion event wins when a session re-ran", () => {
  const s = toAssertionSummary([
    assertionEvent([chk({ status: "fail", category: "security" })], "old"),
    assertionEvent([chk({ status: "pass", category: "security" })], "new"),
  ]);
  assert.equal(s!.blockingFail, 0, "the newer, all-pass event supersedes the old failing one");
});

test("toSessionViewModel exposes .assertions AND keeps the assertion event out of the trace", () => {
  const events = [
    base({ id: "t1", kind: "tllm_call", turn: 1, output: { symbolized: "hi", original: null, differs: false, symbols: [] } }),
    assertionEvent([chk({ category: "security", status: "pass" })], "a1"),
  ];
  const vm = toSessionViewModel("s", events);
  assert.ok(vm.assertions, "assertions summary present");
  assert.equal(vm.assertions!.pass, 1);
  // The meta event must not appear as a phantom trace card in any projection.
  const inTimeline = vm.timeline.some((r) => r.kind === "assertion");
  assert.equal(inTimeline, false, "assertion event must not render as a timeline row");
  const inLanes = Object.values(vm.lanes.byLane).flat().some((c) => c.kind === "assertion");
  assert.equal(inLanes, false, "assertion event must not render as a lane card");
  assert.equal(vm.maxTurn, 1, "maxTurn ignores the assertion event's turn 0");
});

test("toSessionViewModel keeps the workspace_seed meta event out of the trace too", () => {
  const events = [
    base({ id: "t1", kind: "tllm_call", turn: 1, output: { symbolized: "hi", original: null, differs: false, symbols: [] } }),
    base({
      id: "w1", kind: "workspace_seed", view: "HumanView",
      boundary: "filesystem", emitter: "test-harness",
      seedFiles: [{ path: "notes.md", content: "raw", poisoned: true }],
    }),
  ];
  const vm = toSessionViewModel("s", events);
  const inTimeline = vm.timeline.some((r) => r.kind === "workspace_seed");
  assert.equal(inTimeline, false, "workspace_seed must not render as a timeline row");
  const inLanes = Object.values(vm.lanes.byLane).flat().some((c) => c.kind === "workspace_seed");
  assert.equal(inLanes, false, "workspace_seed must not render as a lane card");
});
