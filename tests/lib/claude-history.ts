/**
 * claude-history — parse Claude Code's OWN execution history (the session
 * transcript JSONL it writes under ~/.claude/projects/<cwd-slug>/<uuid>.jsonl)
 * and use it as GROUND TRUTH for a dashboard "history-fidelity" oracle: the
 * dashboard's rendered trace (input cards, the delivered reply, tool cards)
 * must match the conversation the client itself recorded.
 *
 * PROVENANCE: Mandu-new — no reference (adfi-openclaw) origin. The projects
 * JSONL is a Claude-INTERNAL format with no published schema, so every rule here
 * is calibrated against a real transcript (the incident session
 * 0d7adbc5-e15a-4e31-9f9f-e4009937ecbc.jsonl) and kept deliberately CONSERVATIVE
 * — we only assert properties that are stable across the shapes observed. Read
 * the parser doc comments before tightening anything.
 *
 * WHY THIS EXISTS (real incident, session 1783711204-2455055): the dashboard
 * derives its input/response/final cards by re-parsing the proxy's flattened
 * `▸ role` transcript (dashboard/src/view-model/dual-lanes.ts). Two live
 * regressions slipped past unit tests because they came from real-client shapes:
 * slash-command tag noise buried the typed prompt, and Claude Code's "away-recap"
 * side call minted a bogus input card and stole `final` from the real reply. Both
 * are fixed in dual-lanes.ts; THIS oracle is the drift alarm for the next such
 * harness change — it re-derives the same three facts straight from the client's
 * transcript and asserts the dashboard agrees.
 */

import type { ManduEvent, AssertionCheck, AssertionStatus } from "../../dashboard/src/event-model.js";
// The pure transcript parser + locator moved to ./claude-transcript.js; import
// what this module's comparators use, and re-export the full parsing API so
// importers of ./claude-history.js are unchanged.
import { cleanPromptText, type ClaudeHistory } from "./claude-transcript.js";
export {
  cleanPromptText,
  parseClaudeHistory,
  slugifyCwd,
  historyPathFor,
  locateTranscript,
  type ClaudeHistory,
  type LocateOpts,
} from "./claude-transcript.js";
import type { DualLanesModel } from "../../dashboard/src/view-model/dual-lanes.js";
// The dashboard's OWN render self-check (§4.2c render-lint.ts) — re-run here so
// the live fidelity block grades it alongside the history oracle.
import { lintRender } from "../../dashboard/src/view-model/render-lint.js";

// ── Normalization (shared by the comparators) ─────────────────────────────────

/** Collapse `$MDU:<name>[<hash>]` → `$MDU:<name>[#]`: the proxy can
 *  re-mint a fresh hash for the same value across turns, so two faithful renders
 *  of the SAME reply can differ only in the hash. Keeps the tool name + any
 *  field-path suffix (`…[#].notes.md`) — those must still match. */
export function collapseSymbolHashes(s: string): string {
  return s.replace(/(\$MDU:\w+)\[\w+\]/g, "$1[#]");
}

/** Reply-comparison normal form: hash-collapsed + whitespace-collapsed. The
 *  proxy's multi-text-block join separator is not load-bearing, so collapsing
 *  runs of whitespace to a single space makes the comparison robust to it. */
export function normalizeReply(s: string): string {
  return collapseSymbolHashes(s).replace(/\s+/g, " ").trim();
}

// ── The rendered side: extract the comparable facts from a DualLanesModel ─────

export interface RenderedDualLanes {
  /** Input-card texts, in flow order. */
  inputTexts: string[];
  /** The text of the `final: true` response card, or null if none rendered. */
  finalResponseText: string | null;
  /** Whether ANY response card carries final=true. */
  hasFinal: boolean;
  /** Tool-card names, in flow order. */
  toolNames: string[];
}

export function renderedFromDualLanes(dual: DualLanesModel): RenderedDualLanes {
  const inputTexts: string[] = [];
  const toolNames: string[] = [];
  let finalResponseText: string | null = null;
  let hasFinal = false;
  for (const s of dual.steps) {
    if (s.step === "input") inputTexts.push(s.text);
    else if (s.step === "tool") toolNames.push(s.tool);
    else if (s.step === "response" && s.final) {
      hasFinal = true;
      finalResponseText = s.text;
    }
  }
  return { inputTexts, finalResponseText, hasFinal, toolNames };
}

// ── The check primitives (mirror tests/lib/assertions.ts decide/skip style) ────

// Every check in this file grades RENDERING FIDELITY — the dashboard shows what
// the client itself recorded — not task success, so it carries the dedicated
// `fidelity` assertion category (2026-07-11; formerly filed under utility).
const CATEGORY = "fidelity" as const;
const TOOL = "dashboard";

function mk(
  label: string,
  assert: string,
  ok: boolean,
  passReason: string,
  failReason: string,
  opts: { soft?: boolean; description?: string } = {},
): AssertionCheck {
  const status: AssertionStatus = ok ? "pass" : opts.soft ? "warn" : "fail";
  return {
    label,
    ...(opts.description ? { description: opts.description } : {}),
    category: CATEGORY,
    status,
    reason: ok ? passReason : failReason,
    tool: TOOL,
    assert,
  };
}

function mkSkip(label: string, assert: string, reason: string, description?: string): AssertionCheck {
  return {
    label,
    ...(description ? { description } : {}),
    category: CATEGORY,
    status: "skip",
    reason,
    tool: TOOL,
    assert,
  };
}

function arraysEqual(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** Loose tool-name match: the dashboard may show the MCP-prefixed name
 *  (`mcp__<server>__<tool>`) while history has the short tool name, or vice
 *  versa. Equal, or one is the `__`-suffix of the other. One direction only is
 *  NOT required by the caller (the dashboard may show extra OS-level steps). */
export function toolNameMatches(dashName: string, gtName: string): boolean {
  return (
    dashName === gtName ||
    dashName.endsWith(`__${gtName}`) ||
    gtName.endsWith(`__${dashName}`)
  );
}

// ── The four fidelity evaluators ──────────────────────────────────────────────

/** Every ground-truth prompt appears as exactly ONE input card, in order, with
 *  exact (cleaned) text. Paired with evalNoBogusInputCards below, the two mean
 *  the input cards equal the ground-truth prompts one-for-one. */
export function evalHistoryPromptsRendered(h: ClaudeHistory, r: RenderedDualLanes): AssertionCheck {
  const label = "history-prompts-rendered";
  const assert = "history_prompts";
  const gt = h.prompts.map(cleanPromptText);
  const cards = r.inputTexts.map(cleanPromptText);
  // The cards that ARE ground-truth prompts, in render order, must equal gt
  // exactly — enforcing presence + order + exactly-once + exact text.
  const gtSet = new Set(gt);
  const matched = cards.filter((c) => gtSet.has(c));
  const ok = arraysEqual(matched, gt);
  return mk(
    label,
    assert,
    ok,
    `all ${gt.length} typed prompt(s) rendered as input cards, in order, exact text`,
    `input cards do not match the ${gt.length} typed prompt(s): history=${JSON.stringify(gt)} cards=${JSON.stringify(cards)}`,
    { description: "every prompt the client recorded renders as exactly one input card, in order" },
  );
}

/** No input card exists that is NOT a ground-truth prompt — the away-recap alarm
 *  (a harness side call that extends the prompt list must not mint a card). */
export function evalNoBogusInputCards(h: ClaudeHistory, r: RenderedDualLanes): AssertionCheck {
  const label = "no-bogus-input-cards";
  const assert = "no_bogus_input";
  const gtSet = new Set(h.prompts.map(cleanPromptText));
  const bogus = r.inputTexts.map(cleanPromptText).filter((c) => !gtSet.has(c));
  const ok = bogus.length === 0;
  return mk(
    label,
    assert,
    ok,
    "no input card lacks a matching typed prompt (no recap-style bogus card)",
    `${bogus.length} input card(s) have no matching typed prompt (recap-style leak?): ${JSON.stringify(bogus.slice(0, 3))}`,
    { description: "no harness side call (away-recap/typeahead) minted a phantom input card" },
  );
}

/** The delivered reply the client recorded equals the LAST response card's text,
 *  and that card is final=true. Whitespace + hash normalized. Tool-use-only final
 *  (history has no assistant prose) → skip. */
export function evalFinalReplyMatchesHistory(h: ClaudeHistory, r: RenderedDualLanes): AssertionCheck {
  const label = "history-final-reply-matches";
  const assert = "final_reply_matches";
  if (h.finalText === null) {
    return mkSkip(
      label,
      assert,
      "history recorded no assistant prose (tool-use-only run) — no delivered reply to match",
      "the delivered reply card equals the client's recorded final reply",
    );
  }
  if (!r.hasFinal || r.finalResponseText === null) {
    return mk(label, assert, false, "", "no final=true response card was rendered, but history recorded a delivered reply", {
      description: "the delivered reply card equals the client's recorded final reply",
    });
  }
  const want = normalizeReply(h.finalText);
  const got = normalizeReply(r.finalResponseText);
  const ok = want === got;
  return mk(
    label,
    assert,
    ok,
    "the final=true response card matches the client's recorded delivered reply",
    `delivered reply mismatch:\n history=${JSON.stringify(want.slice(0, 200))}\n card=${JSON.stringify(got.slice(0, 200))}`,
    { description: "the delivered reply card equals the client's recorded final reply" },
  );
}

/** Every ground-truth tool_use name has a matching tool card (loose match). The
 *  reverse is NOT required — the dashboard may render extra OS-level steps. */
export function evalHistoryToolsRendered(h: ClaudeHistory, r: RenderedDualLanes): AssertionCheck {
  const label = "history-tools-rendered";
  const assert = "history_tools";
  const distinct = [...new Set(h.toolNames)];
  const missing = distinct.filter((gt) => !r.toolNames.some((dn) => toolNameMatches(dn, gt)));
  const ok = missing.length === 0;
  return mk(
    label,
    assert,
    ok,
    `all ${distinct.length} tool(s) the client recorded have a matching tool card`,
    `${missing.length} recorded tool(s) have NO tool card: ${JSON.stringify(missing)} (cards=${JSON.stringify(r.toolNames)})`,
    { description: "every tool the client invoked renders as a tool card (loose MCP-name match)" },
  );
}

/** The 4-check history-fidelity block for one session. `history === null` means
 *  the transcript could not be located: record every check FAILED (not skipped)
 *  — `claude -p` DOES write a projects JSONL, so a miss is a real problem. */
export function historyFidelityChecks(history: ClaudeHistory | null, dual: DualLanesModel): AssertionCheck[] {
  if (history === null) {
    const reason =
      "Claude Code session transcript not found under ~/.claude/projects — cannot verify history fidelity (`claude -p` should have written one)";
    return [
      mk("history-prompts-rendered", "history_prompts", false, "", reason),
      mk("no-bogus-input-cards", "no_bogus_input", false, "", reason),
      mk("history-final-reply-matches", "final_reply_matches", false, "", reason),
      mk("history-tools-rendered", "history_tools", false, "", reason),
    ];
  }
  const r = renderedFromDualLanes(dual);
  return [
    evalHistoryPromptsRendered(history, r),
    evalNoBogusInputCards(history, r),
    evalFinalReplyMatchesHistory(history, r),
    evalHistoryToolsRendered(history, r),
  ];
}

// ── Render self-check (dashboard/src/view-model/render-lint.ts) ───────────────

/** The ONE assert key every render-lint check carries (pass or finding) — a
 *  member of the dashboard's HISTORY_FIDELITY_ASSERTS, so the self-check feeds
 *  the sidebar's per-session fidelity verdict like the history oracle does. */
export const RENDER_LINT_ASSERT = "render_lint";

/**
 * Run the dashboard's no-ground-truth render self-check (final-not-explainer /
 * delivered-reply-resolved / model-call-classified / turn-order-coherent) over
 * the SAME events + dual-lanes model the history oracle graded, and fold the findings into the
 * fidelity block: severity "error" → FAIL (blocking — the render is wrong by
 * construction), "warn" → WARN (advisory). A clean lint returns ONE passing
 * check so the assertion panel shows the self-check actually ran. Labels are
 * stable per invariant (`render-lint:<invariant>`); all checks share the
 * `render_lint` assert key.
 */
export function renderLintChecks(events: ManduEvent[], dual: DualLanesModel): AssertionCheck[] {
  const findings = lintRender(events, dual);
  if (findings.length === 0) {
    return [
      mk(
        "render-self-check",
        RENDER_LINT_ASSERT,
        true,
        "all render self-check invariants hold — no findings",
        "",
        { description: "the dashboard's no-ground-truth render self-check found nothing suspect" },
      ),
    ];
  }
  return findings.map((f) =>
    mk(
      `render-lint:${f.invariant}`,
      RENDER_LINT_ASSERT,
      false,
      "",
      f.detail + (f.eventId ? ` (event ${f.eventId})` : ""),
      {
        soft: f.severity === "warn",
        description: `render self-check invariant "${f.invariant}" (view-model/render-lint.ts)`,
      },
    ),
  );
}

// ── Interactive-startup shape checks (the claude-e2e interactive scenarios) ───

/** The assert key the interactive-startup structural checks carry (fidelity). */
export const INTERACTIVE_SHAPE_ASSERT = "interactive_shape";

/**
 * The structural guarantee an INTERACTIVE session must uphold — the exact
 * property print-mode claude-e2e cannot exercise, because the shapes that break
 * it (the startup quota probe, title generation, typeahead, away-recap) are
 * interactive-only. Graded on the dual-lanes `calls` classification
 * (conversation / side / unknown, keyed off the proxy's structural `callShape`):
 *
 *   - interactive-reply-not-side (BLOCKING when a reply rendered): the delivered
 *     reply's model call is NOT a side call. A side call taking the delivery
 *     zone is precisely the live bug (sessions 1783675777 / 1783711204 /
 *     1783733223). When the TUI produced no reply at all (keystroke timing on a
 *     real terminal is best-effort), this DEGRADES to a WARN — a flaky boot must
 *     not red the build, but it must be visible.
 *   - interactive-side-calls-seen (advisory): at least one side call was
 *     observed, i.e. the interactive startup traffic actually flowed and was
 *     bucketed — otherwise the probe proved nothing and says so.
 *
 * render-lint (renderLintChecks) grades the same session's no-ground-truth
 * invariants; this adds the crisp "no side call stole the reply" statement on
 * the structural `callShape` data itself.
 */
export function interactiveStartupChecks(dual: DualLanesModel): AssertionCheck[] {
  const checks: AssertionCheck[] = [];
  const finalStep = dual.steps.find(
    (s): s is Extract<DualLanesModel["steps"][number], { step: "response" }> =>
      s.step === "response" && s.final,
  );
  if (!finalStep) {
    checks.push(
      mk(
        "interactive-reply-not-side",
        INTERACTIVE_SHAPE_ASSERT,
        false,
        "",
        "the interactive session rendered NO delivered reply — keystroke timing on the real TUI " +
          "produced no conversation turn; the reply-not-side guarantee could not be exercised",
        { soft: true, description: "the interactive delivered reply comes from a conversation call, not a side call" },
      ),
    );
  } else {
    // Response step ids are `resp:<tllm_call eventId>`; the calls list keys on
    // the same eventId, so the final card maps back to its model call's class.
    const finalCallId = finalStep.id.replace(/^resp:/, "");
    const finalCall = dual.calls.find((c) => c.id === finalCallId);
    const ok = finalCall !== undefined && finalCall.cls === "conversation";
    checks.push(
      mk(
        "interactive-reply-not-side",
        INTERACTIVE_SHAPE_ASSERT,
        ok,
        "the delivered reply comes from a conversation-classified model call — no side call stole the delivery zone",
        finalCall
          ? `the delivered reply's model call is classified "${finalCall.cls}", not "conversation" — a side call took the delivery zone`
          : "the delivered reply's model call could not be classified (no matching callShape)",
        { description: "the interactive delivered reply comes from a conversation call, not a side call" },
      ),
    );
  }
  const sideSeen = dual.calls.filter((c) => c.cls === "side").length;
  checks.push(
    mk(
      "interactive-side-calls-seen",
      INTERACTIVE_SHAPE_ASSERT,
      sideSeen > 0,
      `${sideSeen} interactive side call(s) (startup quota probe / title generation) observed and classified`,
      "no side call was observed — the interactive startup shapes did not flow, so the probe proved nothing",
      { soft: true, description: "the interactive startup side calls flowed and were classified" },
    ),
  );
  return checks;
}

/** The marker Claude Code's typeahead SUGGESTION request carries as its trailing
 *  user instruction (dual-lanes.ts isSideCall keys on the same string). */
const SUGGESTION_MARKER = "[SUGGESTION MODE:";

/** True iff this tllm_call is a typeahead SUGGESTION request — its trailing user
 *  message is the suggestion instruction. Checks the flattened prompt summary
 *  AND the structured fullInput user blocks (either may carry it). Exported for
 *  the interactive driver's turn counting: the SUGGESTION call carries the FULL
 *  tool battery + prose output, so a naive toolCount>0 "conversation turn"
 *  predicate would count it — this is the exclusion that prevents that. */
export function isTypeaheadCall(e: ManduEvent): boolean {
  if ((e.input?.symbolized ?? "").includes(SUGGESTION_MARKER)) return true;
  return (e.fullInput?.blocks ?? []).some(
    (b) => b.role === "user" && b.text.includes(SUGGESTION_MARKER),
  );
}

/**
 * The typeahead-specific guard for the interactive probe. Claude Code's
 * typeahead SUGGESTION call (fired while the user types a NEXT message after a
 * completed turn) is the shape that stole the delivery zone in session
 * 1783675777 — and, unlike the startup probes, it carries the agent's FULL tool
 * battery, so `callShape.toolCount` does NOT flag it: only the string heuristic
 * (isSideCall) catches it. This check proves that heuristic holds on LIVE
 * typeahead traffic — the emulated-typing probe types a partial second message
 * and pauses to make the call fire:
 *
 *   - a typeahead call was observed AND dual-lanes classified it "side" → PASS
 *     (it can never reach the delivery zone);
 *   - a typeahead call was observed but classified conversation/unknown → FAIL
 *     (blocking — it could steal the reply, the 1783675777 regression);
 *   - no typeahead call fired this run (feature/timing dependent) → SKIP.
 */
export function interactiveTypeaheadCheck(events: ManduEvent[], dual: DualLanesModel): AssertionCheck {
  const label = "interactive-typeahead-classified";
  const base = {
    label, category: "fidelity" as const, tool: "dashboard",
    assert: INTERACTIVE_SHAPE_ASSERT,
    description: "a live typeahead SUGGESTION call is classified a side call, never the delivered reply",
  };
  const typeahead = events.find((e) => e.kind === "tllm_call" && isTypeaheadCall(e));
  if (!typeahead) {
    return {
      ...base, status: "skip" as AssertionStatus,
      reason: "no typeahead (SUGGESTION MODE) call fired this run — feature/timing dependent, nothing to guard",
    };
  }
  const call = dual.calls.find((c) => c.id === typeahead.id);
  const ok = call?.cls === "side";
  return {
    ...base,
    status: (ok ? "pass" : "fail") as AssertionStatus,
    reason: ok
      ? "the live typeahead SUGGESTION call is classified a side call — it cannot take the delivery zone"
      : `a typeahead SUGGESTION call is classified "${call?.cls ?? "unmapped"}", not "side" — it could steal the delivered reply (the 1783675777 regression)`,
  };
}

// ── Stale-daemon alarm ────────────────────────────────────────────────────────

export const DAEMON_FRESH_LABEL = "dashboard-daemon-fresh";
const DAEMON_FRESH_ASSERT = "daemon_fresh";

/**
 * Compare the trace the RUNNING daemon served (`served`) against the one the
 * REPO's current view-model code computes (`local`) from the same events. Any
 * divergence in input-card texts or the final reply means the deployed daemon is
 * running STALE code — the exact failure that hid the last regression for 5 hours
 * (daemon started 23:04, the dual-lanes fix landed 04:18, so the live dashboard
 * kept rendering the recap as the delivered reply while the repo tests were
 * green). Comparing over the SAME event set (fetch the daemon with limit=0) makes
 * a diff attributable to code, not to a truncated slice. FAIL on mismatch.
 */
export function evalDaemonFresh(local: RenderedDualLanes, served: RenderedDualLanes): AssertionCheck {
  const localInputs = local.inputTexts.map(cleanPromptText);
  const servedInputs = served.inputTexts.map(cleanPromptText);
  const inputsMatch = arraysEqual(localInputs, servedInputs);
  const finalMatch =
    local.hasFinal === served.hasFinal &&
    normalizeReply(local.finalResponseText ?? "") === normalizeReply(served.finalResponseText ?? "");
  const ok = inputsMatch && finalMatch;
  const diffs: string[] = [];
  if (!inputsMatch) diffs.push(`input cards differ (repo=${JSON.stringify(localInputs)} daemon=${JSON.stringify(servedInputs)})`);
  if (!finalMatch) {
    diffs.push(
      `final reply differs (repo=${JSON.stringify(normalizeReply(local.finalResponseText ?? "").slice(0, 120))} daemon=${JSON.stringify(normalizeReply(served.finalResponseText ?? "").slice(0, 120))})`,
    );
  }
  return mk(
    DAEMON_FRESH_LABEL,
    DAEMON_FRESH_ASSERT,
    ok,
    "the running dashboard daemon renders the same trace as the current repo code (not stale)",
    `the deployed daemon is running STALE view-model code: ${diffs.join("; ")}`,
    { description: "the deployed dashboard daemon's rendering matches the repo's current view-model" },
  );
}

/** The daemon HTTP could not be reached — a WARN (non-blocking), not a fail: the
 *  live suite's skip gate only guarantees the arbiter socket, so an arbiter-only
 *  run (no dashboard HTTP) must not turn red on this alarm. */
export function daemonUnreachableCheck(url: string, err: string): AssertionCheck {
  return {
    label: DAEMON_FRESH_LABEL,
    description: "the deployed dashboard daemon's rendering matches the repo's current view-model",
    category: CATEGORY,
    status: "warn",
    reason: `dashboard HTTP unreachable at ${url} (${err}) — stale-daemon alarm skipped`,
    tool: TOOL,
    assert: DAEMON_FRESH_ASSERT,
  };
}
