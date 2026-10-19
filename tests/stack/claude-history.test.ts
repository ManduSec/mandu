/**
 * claude-history.test — unit tests for the history-fidelity oracle
 * (tests/lib/claude-history.ts). Pure + deterministic: it reads two committed
 * fixtures from disk and computes the view-model locally, so it runs under the
 * tests package's default `npm test` with NO arbiter, daemon, agent, or
 * network. (It lives here in tests/stack/ alongside assertions-lib.test.ts — the
 * package's default `npm test` globs stack/*.test.ts — even though the parser
 * itself ships with the drill runners' shared library; the parser is pure, the LIVE wiring is not.)
 *
 * The load-bearing test is `comparator over the incident fixture`: it runs the
 * REPO's current toDualLanes over the real incident event log
 * (fixtures/incident-events-1783711204.ndjson — the away-recap regression session)
 * and asserts the 4 fidelity checks PASS against the parsed incident transcript.
 * That pins BOTH fixed regressions forever: (1) the recap side call minted no
 * bogus input card, (2) the real inspect reply kept `final`. If a future
 * dual-lanes change reintroduces either, this test goes red WITHOUT needing a live
 * run.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { HISTORY_FIDELITY_ASSERTS, type ManduEvent } from "../../dashboard/src/event-model.js";
import { toDualLanes, type DualLanesModel } from "../../dashboard/src/view-model/dual-lanes.js";
import {
  parseClaudeHistory,
  cleanPromptText,
  slugifyCwd,
  historyPathFor,
  normalizeReply,
  collapseSymbolHashes,
  toolNameMatches,
  renderedFromDualLanes,
  historyFidelityChecks,
  renderLintChecks,
  interactiveStartupChecks,
  interactiveTypeaheadCheck,
  INTERACTIVE_SHAPE_ASSERT,
  evalHistoryPromptsRendered,
  evalNoBogusInputCards,
  evalFinalReplyMatchesHistory,
  evalHistoryToolsRendered,
  evalDaemonFresh,
  daemonUnreachableCheck,
  type ClaudeHistory,
  type RenderedDualLanes,
} from "../lib/claude-history.js";

const FIXTURES = join(import.meta.dirname, "..", "fixtures");
const INCIDENT_JSONL = readFileSync(join(FIXTURES, "claude-history-incident.jsonl"), "utf8");
const INCIDENT_EVENTS = readFileSync(join(FIXTURES, "incident-events-1783711204.ndjson"), "utf8")
  .trim()
  .split("\n")
  .map((l) => JSON.parse(l) as ManduEvent);

/** A minimal tllm_call event for the interactive-shape tests (only the fields
 *  toDualLanes reads: input/output symbolized + callShape). */
let tllmSeq = 0;
function tllm(
  label: string,
  callShape: { toolCount: number; maxTokens: number | null; userMessages: number },
  inputSym: string,
  outputSym: string,
): ManduEvent {
  tllmSeq += 1;
  return {
    id: `tllm-${label}-${tllmSeq}`, sessionId: "int", turn: tllmSeq,
    ts: `2026-07-11T04:00:${String(tllmSeq).padStart(2, "0")}.000Z`, seq: tllmSeq,
    callId: null, parentId: null, kind: "tllm_call", view: "AgentView",
    boundary: "model_context", emitter: "anthropic-proxy",
    input: { symbolized: inputSym, original: null, differs: false, symbols: [] },
    output: { symbolized: outputSym, original: null, differs: false, symbols: [] },
    callShape, invariant: { violatedInvariant: false },
  } as ManduEvent;
}

const GT_PROMPTS = ["hello", "can you download labs.example.test?", "download into html. then count the word security"];
const GT_FINAL =
  'The word "security" appears **$MDU:inspect[d155]** times on the labs.example.test homepage.\n\nWould you like me to save the HTML content to a file as well?';
const GT_TOOLS = ["WebFetch", "mcp__mandu-inspect__inspect_symbol"];

// ── The parser ────────────────────────────────────────────────────────────────

test("parseClaudeHistory: exactly the three typed prompts (command/meta/sidechain noise dropped)", () => {
  const h = parseClaudeHistory(INCIDENT_JSONL);
  assert.deepEqual(h.prompts, GT_PROMPTS);
});

test("parseClaudeHistory: final reply is the LAST prose turn (requestId-grouped, verbatim symbol)", () => {
  const h = parseClaudeHistory(INCIDENT_JSONL);
  assert.equal(h.finalText, GT_FINAL);
  // The symbol token rides verbatim (history is recorded post-proxy).
  assert.match(h.finalText!, /\$MDU:inspect\[d155\]/);
});

test("parseClaudeHistory: tool_use names extracted; sidechain-only tool excluded", () => {
  const h = parseClaudeHistory(INCIDENT_JSONL);
  assert.deepEqual(h.toolNames, GT_TOOLS);
  assert.ok(!h.toolNames.includes("SidechainOnlyTool"), "a sidechain tool_use must not leak into ground truth");
});

test("parseClaudeHistory: array-content user records (tool_result) are NOT prompts", () => {
  const h = parseClaudeHistory(INCIDENT_JSONL);
  // The two tool_result records carry $MDU:* strings; none may appear as a prompt.
  assert.ok(!h.prompts.some((p) => p.includes("$MDU:")), "tool_result content must never be read as a prompt");
});

test("parseClaudeHistory: sidechain assistant prose never becomes the final reply", () => {
  const h = parseClaudeHistory(INCIDENT_JSONL);
  assert.ok(!h.finalText!.includes("SIDECHAIN LEAK"));
});

test("parseClaudeHistory: tolerant of blank + corrupt lines", () => {
  const noisy = `\n{ not json \n${INCIDENT_JSONL}\n   \n`;
  const h = parseClaudeHistory(noisy);
  assert.deepEqual(h.prompts, GT_PROMPTS);
});

test("parseClaudeHistory: no assistant text at all → finalText null (tool-use-only run)", () => {
  const jsonl = [
    JSON.stringify({ type: "user", message: { role: "user", content: "do a thing" } }),
    JSON.stringify({ type: "assistant", requestId: "r1", message: { role: "assistant", content: [{ type: "tool_use", name: "Bash", id: "t1", input: {} }] } }),
  ].join("\n");
  const h = parseClaudeHistory(jsonl);
  assert.equal(h.finalText, null);
  assert.deepEqual(h.prompts, ["do a thing"]);
  assert.deepEqual(h.toolNames, ["Bash"]);
});

test("parseClaudeHistory: a trailing tool-use-only turn leaves the last PROSE turn as final", () => {
  const jsonl = [
    JSON.stringify({ type: "user", message: { role: "user", content: "go" } }),
    JSON.stringify({ type: "assistant", requestId: "rA", message: { role: "assistant", content: [{ type: "text", text: "here is the answer" }] } }),
    JSON.stringify({ type: "assistant", requestId: "rB", message: { role: "assistant", content: [{ type: "tool_use", name: "Bash", id: "t2", input: {} }] } }),
  ].join("\n");
  const h = parseClaudeHistory(jsonl);
  assert.equal(h.finalText, "here is the answer");
});

test("cleanPromptText: strips harness tag spans + [system-reminder] lines", () => {
  const body = "<system-reminder>ctx</system-reminder>\nwhat is 2+2?\n[system-reminder]";
  assert.equal(cleanPromptText(body), "what is 2+2?");
});

// ── The locator (pure path helpers) ───────────────────────────────────────────

test("slugifyCwd: replaces / and . with -", () => {
  assert.equal(slugifyCwd("/home/user/project/mandu"), "-home-user-project-mandu");
  assert.equal(slugifyCwd("/tmp/a.b/c"), "-tmp-a-b-c");
});

test("historyPathFor: <home>/.claude/projects/<slug>/<uuid>.jsonl", () => {
  assert.equal(
    historyPathFor("/home/u", "/home/u/proj", "abc-123"),
    "/home/u/.claude/projects/-home-u-proj/abc-123.jsonl",
  );
});

// ── Normalization helpers ─────────────────────────────────────────────────────

test("collapseSymbolHashes: hash → [#], name + field suffix preserved", () => {
  assert.equal(collapseSymbolHashes("x $MDU:Bash[565e] y"), "x $MDU:Bash[#] y");
  assert.equal(collapseSymbolHashes("$MDU:read[a1b2].notes.md"), "$MDU:read[#].notes.md");
});

test("normalizeReply: hash-collapse + whitespace-collapse make re-mints/joins compare equal", () => {
  const a = "count: $MDU:inspect[d155]\n\ndone";
  const b = "count:   $MDU:inspect[9f0a]  done";
  assert.equal(normalizeReply(a), normalizeReply(b));
});

test("toolNameMatches: exact + MCP-prefixed either direction; unrelated names don't match", () => {
  assert.ok(toolNameMatches("WebFetch", "WebFetch"));
  assert.ok(toolNameMatches("mcp__mandu-inspect__inspect_symbol", "inspect_symbol"));
  assert.ok(toolNameMatches("inspect_symbol", "mcp__mandu-inspect__inspect_symbol"));
  assert.ok(!toolNameMatches("Bash", "WebFetch"));
  assert.ok(!toolNameMatches("Read", "spect_symbol"), "must match on the __ boundary, not a bare suffix");
});

// ── THE regression pin: the 4 checks over the incident fixture × repo lanes ────

test("comparator over the incident fixture: all 4 fidelity checks PASS (pins both fixed regressions)", () => {
  const history = parseClaudeHistory(INCIDENT_JSONL);
  const dual = toDualLanes(INCIDENT_EVENTS);
  const checks = historyFidelityChecks(history, dual);
  const failed = checks.filter((c) => c.status !== "pass");
  assert.equal(
    failed.length,
    0,
    `expected all fidelity checks to pass over the incident event log, but: ${failed.map((c) => `${c.label} [${c.status}] ${c.reason}`).join(" | ")}`,
  );
  // Name the two regressions explicitly so a failure reads meaningfully.
  const byLabel = new Map(checks.map((c) => [c.label, c]));
  assert.equal(byLabel.get("no-bogus-input-cards")!.status, "pass", "the away-recap must not mint a bogus input card");
  assert.equal(byLabel.get("history-final-reply-matches")!.status, "pass", "the real inspect reply must keep final=true (recap must not steal it)");
  // The oracle's checks ride the dedicated fidelity category, not utility.
  assert.ok(checks.every((c) => c.category === "fidelity"), "every history-fidelity check carries category=fidelity");
});

test("renderedFromDualLanes over the incident event log: 3 inputs, inspect final, 2 tools", () => {
  const r = renderedFromDualLanes(toDualLanes(INCIDENT_EVENTS));
  assert.deepEqual(r.inputTexts.map(cleanPromptText), GT_PROMPTS);
  assert.ok(r.hasFinal);
  assert.match(normalizeReply(r.finalResponseText!), /\$MDU:inspect\[#\]/);
  for (const t of GT_TOOLS) assert.ok(r.toolNames.some((dn) => toolNameMatches(dn, t)), `${t} should render as a tool card`);
});

// ── The comparator's negative cases (it must actually catch drift) ────────────

function rendered(over: Partial<RenderedDualLanes>): RenderedDualLanes {
  return { inputTexts: [], finalResponseText: null, hasFinal: false, toolNames: [], ...over };
}
const GT: ClaudeHistory = { prompts: GT_PROMPTS, finalText: GT_FINAL, toolNames: GT_TOOLS, toolErrors: [] };

test("evalNoBogusInputCards: FAILS on a recap-style phantom card", () => {
  const r = rendered({ inputTexts: [...GT_PROMPTS, "The user stepped away and is coming back. Recap…"] });
  assert.equal(evalNoBogusInputCards(GT, r).status, "fail");
});

test("evalHistoryPromptsRendered: FAILS when a prompt is missing", () => {
  const r = rendered({ inputTexts: GT_PROMPTS.slice(0, 2) });
  assert.equal(evalHistoryPromptsRendered(GT, r).status, "fail");
});

test("evalHistoryPromptsRendered: FAILS on out-of-order prompts", () => {
  const r = rendered({ inputTexts: [GT_PROMPTS[1]!, GT_PROMPTS[0]!, GT_PROMPTS[2]!] });
  assert.equal(evalHistoryPromptsRendered(GT, r).status, "fail");
});

test("evalHistoryPromptsRendered: FAILS when one prompt renders twice", () => {
  const r = rendered({ inputTexts: [GT_PROMPTS[0]!, GT_PROMPTS[0]!, GT_PROMPTS[1]!, GT_PROMPTS[2]!] });
  assert.equal(evalHistoryPromptsRendered(GT, r).status, "fail");
});

test("evalFinalReplyMatchesHistory: PASS on hash re-mint, FAIL on real divergence, SKIP on tool-use-only", () => {
  const remint = rendered({ hasFinal: true, finalResponseText: GT_FINAL.replace("d155", "9f0a") });
  assert.equal(evalFinalReplyMatchesHistory(GT, remint).status, "pass");

  const wrong = rendered({ hasFinal: true, finalResponseText: "You asked me to download the page and count security." });
  assert.equal(evalFinalReplyMatchesHistory(GT, wrong).status, "fail");

  const noFinalCard = rendered({ hasFinal: false });
  assert.equal(evalFinalReplyMatchesHistory(GT, noFinalCard).status, "fail");

  const toolOnly: ClaudeHistory = { ...GT, finalText: null };
  assert.equal(evalFinalReplyMatchesHistory(toolOnly, rendered({})).status, "skip");
});

test("evalHistoryToolsRendered: PASS with loose match, FAIL when a tool card is missing", () => {
  const ok = rendered({ toolNames: ["WebFetch", "mcp__mandu-inspect__inspect_symbol"] });
  assert.equal(evalHistoryToolsRendered(GT, ok).status, "pass");
  const missing = rendered({ toolNames: ["WebFetch"] });
  assert.equal(evalHistoryToolsRendered(GT, missing).status, "fail");
});

test("history-fidelity assert keys match the dashboard's HISTORY_FIDELITY_ASSERTS (sidebar verdict contract)", () => {
  // WHY: the dashboard derives the sidebar's fid✓/fid✗ badge by filtering the
  // session's `assertion` event on HISTORY_FIDELITY_ASSERTS
  // (dashboard/src/event-source.ts assertionVerdicts). If the oracle's assert
  // keys drift from that set, the filter matches nothing and the badge silently
  // vanishes — no error anywhere. This test pins the two packages together.
  // The fidelity block is historyFidelityChecks PLUS the render self-check
  // (renderLintChecks) — both feed the verdict, so both contribute keys.
  const dual = toDualLanes(INCIDENT_EVENTS);
  const checks = [...historyFidelityChecks(null, dual), ...renderLintChecks(INCIDENT_EVENTS, dual)];
  const oracleKeys = new Set(checks.map((c) => c.assert));
  assert.deepEqual(oracleKeys, new Set(HISTORY_FIDELITY_ASSERTS));
});

test("historyFidelityChecks(null, …): every check FAILS with a located-transcript reason", () => {
  const checks = historyFidelityChecks(null, toDualLanes(INCIDENT_EVENTS));
  assert.equal(checks.length, 4);
  assert.ok(checks.every((c) => c.status === "fail"));
  assert.ok(checks.every((c) => /not found under ~\/\.claude\/projects/.test(c.reason)));
});

// ── The render self-check evaluator (renderLintChecks) ────────────────────────
// lintRender's invariants are unit-tested in the dashboard (render-lint.test.ts);
// these pin THIS package's severity→status mapping and the proof-of-run check.

test("renderLintChecks: a clean lint returns ONE passing render-self-check (proof the check ran)", () => {
  const dual = toDualLanes(INCIDENT_EVENTS);
  const checks = renderLintChecks(INCIDENT_EVENTS, dual);
  assert.equal(checks.length, 1);
  assert.equal(checks[0]!.label, "render-self-check");
  assert.equal(checks[0]!.status, "pass");
  assert.equal(checks[0]!.assert, "render_lint");
  assert.equal(checks[0]!.category, "fidelity");
});

test("renderLintChecks: an error-severity finding maps to a BLOCKING fail with a stable label", () => {
  // Hand-built model (as in the dashboard's own lint tests): the delivery zone
  // shows the proxy's upstream-error explainer — wrong by construction.
  const dual: DualLanesModel = {
    steps: [{
      step: "response", id: "resp:evX", ts: "2026-07-11T00:00:00.000Z", turn: 0,
      violated: false, final: true, symbols: [],
      text: "⚠ no model response — upstream HTTP 429 (rate-limited): rate_limit_error",
    }],
    collapsedCount: 0,
    calls: [],
  };
  const checks = renderLintChecks([], dual);
  assert.equal(checks.length, 1);
  assert.equal(checks[0]!.label, "render-lint:final-not-explainer");
  assert.equal(checks[0]!.status, "fail", "an error-severity finding must BLOCK the run");
  assert.equal(checks[0]!.assert, "render_lint");
  assert.match(checks[0]!.reason, /event evX/, "the finding's anchor event id rides in the reason");
});

test("renderLintChecks: a warn-severity finding maps to a non-blocking warn", () => {
  // An unknown-shape PROSE model call — the new-side-call canary (warn).
  const dual: DualLanesModel = {
    steps: [],
    collapsedCount: 0,
    calls: [{ id: "evC", ts: "2026-07-11T00:00:00.000Z", turn: 6, cls: "unknown", prose: true }],
  };
  const checks = renderLintChecks([], dual);
  assert.equal(checks.length, 1);
  assert.equal(checks[0]!.label, "render-lint:model-call-classified");
  assert.equal(checks[0]!.status, "warn", "a warn-severity finding is advisory, never blocking");
  assert.equal(checks[0]!.assert, "render_lint");
});

// ── The interactive-startup shape checks (claude-e2e interactive scenarios) ───
// interactiveStartupChecks grades the structural property print-mode e2e can't:
// no interactive-only side call (startup quota probe / title generation) takes
// the delivery zone. Built on the dual-lanes `calls` classification.

test("interactiveStartupChecks: healthy interactive session — reply is conversation, side calls seen", () => {
  // The real interactive shape (verified live): quota probe + title-gen (both
  // tool-less → side) then the conversation turn (tool battery → conversation).
  const evs: ManduEvent[] = [
    tllm("side probe", { toolCount: 0, maxTokens: 1, userMessages: 1 }, "▸ user\nquota", "I"),
    tllm("side title", { toolCount: 0, maxTokens: 32000, userMessages: 1 }, "▸ user\nhi", '{"title": "Greeting"}'),
    tllm("convo", { toolCount: 38, maxTokens: 32000, userMessages: 1 }, "▸ system\nCC\n\n▸ user\nsay pong", "PONG"),
  ];
  const checks = interactiveStartupChecks(toDualLanes(evs));
  const byLabel = Object.fromEntries(checks.map((c) => [c.label, c]));
  assert.equal(byLabel["interactive-reply-not-side"]!.status, "pass");
  assert.equal(byLabel["interactive-reply-not-side"]!.assert, INTERACTIVE_SHAPE_ASSERT);
  assert.equal(byLabel["interactive-side-calls-seen"]!.status, "pass");
});

test("interactiveStartupChecks: a side call in the delivery zone is a BLOCKING fail", () => {
  // Hand-built: the final card maps (resp:<id>) to a call classified "side" —
  // the exact bug this probe guards against.
  const dual: DualLanesModel = {
    steps: [{
      step: "response", id: "resp:evSide", ts: "2026-07-11T00:00:00.000Z", turn: 0,
      violated: false, final: true, symbols: [], text: "show the lines with security",
    }],
    collapsedCount: 0,
    calls: [{ id: "evSide", ts: "2026-07-11T00:00:00.000Z", turn: 0, cls: "side", prose: true }],
  };
  const checks = interactiveStartupChecks(dual);
  const notSide = checks.find((c) => c.label === "interactive-reply-not-side")!;
  assert.equal(notSide.status, "fail", "a side call taking the delivery zone must BLOCK");
});

test("interactiveStartupChecks: no reply rendered → reply-not-side degrades to WARN (TUI timing)", () => {
  // Only startup side calls flowed (the keystrokes never submitted a prompt).
  const evs: ManduEvent[] = [
    tllm("side probe", { toolCount: 0, maxTokens: 1, userMessages: 1 }, "▸ user\nquota", "I"),
  ];
  const checks = interactiveStartupChecks(toDualLanes(evs));
  const byLabel = Object.fromEntries(checks.map((c) => [c.label, c]));
  assert.equal(byLabel["interactive-reply-not-side"]!.status, "warn", "a flaky boot must not red the build");
  assert.equal(byLabel["interactive-side-calls-seen"]!.status, "pass", "but the side call that DID flow is still seen");
});

test("interactiveTypeaheadCheck: a live typeahead call carries tools yet must classify as side", () => {
  // The 1783675777 shape: the SUGGESTION call carries the FULL tool battery
  // (toolCount 38, so callShape can't flag it) — only the string heuristic does.
  const evs: ManduEvent[] = [
    tllm("convo", { toolCount: 38, maxTokens: 32000, userMessages: 1 }, "▸ system\nCC\n\n▸ user\nwhat is 2+2", "4"),
    tllm("suggest", { toolCount: 38, maxTokens: 32000, userMessages: 2 },
      "▸ system\nCC\n\n▸ user\nwhat is 2+2\n\n▸ user\n[SUGGESTION MODE: Suggest what the user might type next.]", "and 3+3?"),
  ];
  const dual = toDualLanes(evs);
  const check = interactiveTypeaheadCheck(evs, dual);
  assert.equal(check.status, "pass", "the typeahead call must be classified side despite carrying tools");
  assert.equal(check.assert, INTERACTIVE_SHAPE_ASSERT);
});

test("interactiveTypeaheadCheck: no typeahead this run → SKIP (feature/timing dependent)", () => {
  const evs: ManduEvent[] = [
    tllm("convo", { toolCount: 38, maxTokens: 32000, userMessages: 1 }, "▸ user\nhi", "hello"),
  ];
  const check = interactiveTypeaheadCheck(evs, toDualLanes(evs));
  assert.equal(check.status, "skip");
});

test("interactiveTypeaheadCheck: a typeahead classified NON-side is a BLOCKING fail", () => {
  // Hand-built: the typeahead event maps to a call the classifier did NOT bucket
  // as side — the regression this guards (it could reach the delivery zone).
  const evs: ManduEvent[] = [
    tllm("suggest", { toolCount: 38, maxTokens: 32000, userMessages: 2 },
      "▸ user\n[SUGGESTION MODE: predict next]", "show the lines with security"),
  ];
  const misclassified: DualLanesModel = {
    steps: [], collapsedCount: 0,
    calls: [{ id: evs[0]!.id, ts: evs[0]!.ts, turn: 0, cls: "conversation", prose: true }],
  };
  const check = interactiveTypeaheadCheck(evs, misclassified);
  assert.equal(check.status, "fail", "a typeahead that isn't classified side could steal the reply");
  assert.match(check.reason, /1783675777/);
});

// ── The stale-daemon alarm ────────────────────────────────────────────────────

test("evalDaemonFresh: PASS when repo and daemon render identically", () => {
  const r = renderedFromDualLanes(toDualLanes(INCIDENT_EVENTS));
  assert.equal(evalDaemonFresh(r, r).status, "pass");
});

test("evalDaemonFresh: FAILS when the daemon's input cards diverge (stale code)", () => {
  const local = renderedFromDualLanes(toDualLanes(INCIDENT_EVENTS));
  const staleServed: RenderedDualLanes = {
    ...local,
    // A stale daemon (pre-fix) rendered the away-recap as a 4th input card.
    inputTexts: [...local.inputTexts, "The user stepped away and is coming back. Recap…"],
  };
  assert.equal(evalDaemonFresh(local, staleServed).status, "fail");
});

test("evalDaemonFresh: FAILS when the daemon's final reply diverges (the actual incident)", () => {
  const local = renderedFromDualLanes(toDualLanes(INCIDENT_EVENTS));
  const staleServed: RenderedDualLanes = {
    ...local,
    // The exact 5-hour bug: the stale daemon showed the recap as the delivered reply.
    finalResponseText: "You asked me to download labs.example.test as HTML and count occurrences of security.",
  };
  assert.equal(evalDaemonFresh(local, staleServed).status, "fail");
});

test("daemonUnreachableCheck: a non-blocking WARN (arbiter-only runs must not go red)", () => {
  const c = daemonUnreachableCheck("http://127.0.0.1:4500", "ECONNREFUSED");
  assert.equal(c.status, "warn");
  assert.match(c.reason, /unreachable/);
});
