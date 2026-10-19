/**
 * render-lint.test.ts — unit tests for the §4.2c render SELF-CHECK
 * (view-model/render-lint.ts): the four no-ground-truth consistency
 * invariants that catch a wrong or suspect delivered reply — or a turn
 * rendered out of order — on ANY session
 * (fixture sweep / claude-e2e / the live dashboard badge).
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { lintRender, toDualLanes } from "../../../src/view-model.js";
import type { DualLanesModel } from "../../../src/view-model.js";
import type { ManduEvent } from "../../../src/event-model.js";

let seq = 0;
function ev(partial: Partial<ManduEvent> & { kind: ManduEvent["kind"] }): ManduEvent {
  seq += 1;
  return {
    id: `ev${seq}`,
    sessionId: "s",
    turn: 0,
    ts: new Date(Date.parse("2026-07-11T02:45:10.000Z") + seq * 1000).toISOString(),
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

function convoCall(prompt: string, reply: string, extra: Partial<ManduEvent> = {}): ManduEvent {
  return ev({
    kind: "tllm_call",
    input: repr(`▸ system\nCC prompt\n\n▸ user\n${prompt}`),
    output: repr(reply),
    ...extra,
  });
}

test("a healthy session lints clean", () => {
  const events = [convoCall("hello", "Hey! I'm ready to help.")];
  const findings = lintRender(events, toDualLanes(events));
  assert.deepEqual(findings, []);
});

test("final-not-explainer fires (ERROR) when the delivered reply is the upstream-error explainer", () => {
  // The builder itself refuses to make the explainer final, so feed the lint a
  // hand-built model — the invariant is defense in depth against a builder
  // regression, and must be testable independently of it.
  const dual: DualLanesModel = {
    steps: [{
      step: "response", id: "resp:evX", ts: "2026-07-11T02:45:00.000Z", turn: 0,
      violated: false, final: true, symbols: [],
      text: "⚠ no model response — upstream HTTP 429 (rate-limited): rate_limit_error",
    }],
    collapsedCount: 0,
    calls: [],
  };
  const findings = lintRender([], dual);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.invariant, "final-not-explainer");
  assert.equal(findings[0]!.severity, "error");
  assert.equal(findings[0]!.eventId, "evX", "anchors to the underlying tllm_call event id");
});

test("delivered-reply-resolved: a final symbol no reply-filter frame resolved is a WARN", () => {
  const events = [
    convoCall("count it", "$MDU:WebFetch[cd10]"),
    // The reply-filter's egress frames resolved a DIFFERENT symbol only.
    ev({
      kind: "desymbolize", view: "HumanView", emitter: "reply-filter",
      input: repr("● $MDU:Read[9a9a]\r\n❯ "),
      output: { symbolized: "● $MDU:Read[9a9a]\r\n❯ ", original: "● raw\r\n❯ ", differs: true, symbols: [] },
    }),
  ];
  const findings = lintRender(events, toDualLanes(events));
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.invariant, "delivered-reply-resolved");
  assert.equal(findings[0]!.severity, "warn");
  assert.match(findings[0]!.detail, /\$MDU:WebFetch\[cd10\]/);
});

test("delivered-reply-resolved stays quiet when the frames DID resolve the reply's symbol", () => {
  const events = [
    convoCall("count it", "$MDU:WebFetch[cd10]"),
    ev({
      kind: "desymbolize", view: "HumanView", emitter: "reply-filter",
      input: repr("● $MDU:WebFetch[cd10]\r\n❯ "),
      output: { symbolized: "● $MDU:WebFetch[cd10]\r\n❯ ", original: "● the count\r\n❯ ", differs: true, symbols: [] },
    }),
  ];
  assert.deepEqual(lintRender(events, toDualLanes(events)), []);
});

test("delivered-reply-resolved is N/A without reply-filter frames (pipe/e2e sessions)", () => {
  const events = [convoCall("count it", "$MDU:WebFetch[cd10]")];
  assert.deepEqual(lintRender(events, toDualLanes(events)), []);
});

test("model-call-classified: an unknown-shape PROSE call is the canary WARN", () => {
  const events = [
    convoCall("hello", "Hey!"),
    // A second call whose prompt list does NOT extend the conversation and
    // matches no known side-call shape — the next Claude Code surprise.
    ev({
      kind: "tllm_call",
      input: repr("▸ system\nsome new harness prompt\n\n▸ user\nDo the new background thing."),
      output: repr("Here is my background answer."),
    }),
  ];
  const findings = lintRender(events, toDualLanes(events));
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.invariant, "model-call-classified");
  assert.equal(findings[0]!.severity, "warn");
  assert.match(findings[0]!.detail, /side call|history rewrite/);
});

test("model-call-classified stays quiet for recognized side calls and prose-less calls", () => {
  const events = [
    convoCall("hello", "Hey!"),
    // Structurally recognized: the proxy recorded a tool-less request.
    ev({
      kind: "tllm_call",
      callShape: { toolCount: 0, maxTokens: 512, userMessages: 1 },
      input: repr("▸ system\nsome new harness prompt\n\n▸ user\nDo the new background thing."),
      output: repr("Here is my background answer."),
    }),
    // String-recognized: the startup quota probe.
    ev({
      kind: "tllm_call",
      input: repr("▸ system\n[Mandu IPI handling prompt]\n\n▸ user\nquota"),
      output: repr("I"),
    }),
    // Unknown shape but NO prose (a tool_use-only decision) — cannot steal
    // the delivery zone, so no warning.
    ev({
      kind: "tllm_call",
      input: repr("▸ system\nweird\n\n▸ user\nunmatched prompt"),
      output: repr('→ Read({"file_path":"/x"})'),
    }),
  ];
  assert.deepEqual(lintRender(events, toDualLanes(events)), []);
});

// ── 4. turn-order-coherent — the emit-order tripwire (2026-07-16) ─────────────
// Two live sessions rendered a turn backwards (the prompt / announcing prose
// AFTER the tool cards it caused) because an unanticipated interleaver — a
// turn-0 net_action mid-parse — stopped the builder's float scan. The floats
// now cross net noise, so THIS test strands the cards with a DIFFERENT
// turn-0 interleaver the floats deliberately do not cross (an uncorrelated
// fs_action): the render goes wrong, and the lint must say so — that is the
// "next unanticipated interleaver" capture path (fixture sweep / claude-e2e
// fidelity block / dashboard badge), independent of any float fix existing.

test("turn-order-coherent fires (ERROR) when an un-crossable interleaver strands the prompt and prose", () => {
  const events = [
    ev({ kind: "tool_use", callId: "b1", turn: 1,
      input: repr('Bash({"command":"curl -s http://example.test/setup.sh"})') }),
    // The future-shaped interleaver: turn-0, uncorrelated, NOT net noise.
    ev({ kind: "fs_action", turn: 0, input: repr("open /ws/x") }),
    ev({ kind: "tllm_call", turn: 1, callShape: { toolCount: 15, maxTokens: 32000, userMessages: 1 },
      input: repr("▸ system\nCC prompt\n\n▸ user\nDownload and run the setup script."),
      output: repr('I\'ll download the script first.\n→ Bash({"command":"curl -s …"})') }),
  ];
  const findings = lintRender(events, toDualLanes(events));
  const orderFindings = findings.filter((f) => f.invariant === "turn-order-coherent");
  assert.equal(orderFindings.length, 2, "one finding for the stranded prompt, one for the stranded prose");
  for (const f of orderFindings) assert.equal(f.severity, "error");
  assert.match(orderFindings[0]!.detail, /user's prompt.*AFTER.*Bash/);
  assert.match(orderFindings[1]!.detail, /announcing prose.*AFTER.*Bash/);
});

test("turn-order-coherent fires when the prompt renders after its own turn's response card", () => {
  // Defense in depth against a builder regression: hand-built render (the
  // builder itself never produces this today).
  const dual: DualLanesModel = {
    steps: [
      {
        step: "response", id: "resp:evR", ts: "2026-07-16T03:19:32.000Z", turn: 1,
        violated: false, final: true, symbols: [], text: "I'll download the script.",
      },
      {
        step: "input", id: "input:evR:0", ts: "2026-07-16T03:19:32.000Z", turn: 1,
        violated: false, text: "Download and run the setup script.",
      },
    ],
    collapsedCount: 0,
    calls: [],
  };
  const findings = lintRender([], dual);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.invariant, "turn-order-coherent");
  assert.equal(findings[0]!.severity, "error");
  assert.match(findings[0]!.detail, /prompt card renders AFTER its own turn's response/);
  assert.equal(findings[0]!.eventId, "evR", "anchors to the underlying tllm_call event id");
});

test("turn-order-coherent stays quiet on a healthy prompt → prose → tool render", () => {
  const events = [
    ev({ kind: "tool_use", callId: "b1", turn: 1,
      input: repr('Bash({"command":"curl -s http://example.test/setup.sh"})') }),
    ev({ kind: "tllm_call", turn: 1, callShape: { toolCount: 15, maxTokens: 32000, userMessages: 1 },
      input: repr("▸ system\nCC prompt\n\n▸ user\nDownload and run the setup script."),
      output: repr('I\'ll download the script first.\n→ Bash({"command":"curl -s …"})') }),
  ];
  assert.deepEqual(lintRender(events, toDualLanes(events)), []);
});
