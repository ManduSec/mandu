/**
 * view-model — PURE event(s) → view-model functions (DOM-free, unit-testable).
 *
 * Mandu-new (NO reference origin), but encodes the rendering *decisions* the
 * reference dashboard makes (trusted/untrusted lane tinting, before/after
 * two-block detail, symbol table) as data, per docs/design/ui/dashboard.md §4.
 *
 * CRITICAL DESIGN POINT (task requirement #3): all rendering logic lives here as
 * pure functions `event(s) → view-model`. They take plain ManduEvent objects
 * and return plain data — NO document/window/DOM access — so they run under
 * `node --test` with zero browser. The browser layer (dev/js/render.js +
 * app.js) is a thin shell that turns these view-models into HTML and is NOT
 * unit-tested (no DOM in Node); ALL testable logic is here.
 *
 * This same compiled module is what the unit/e2e tests import. To avoid a
 * hand-kept JS twin drifting from this tested TS, the SERVER computes the
 * view-model (toSessionViewModel) and ships it in the `/api/events` response;
 * the browser shell (public/js/app.js) consumes that derived model and only
 * turns it into HTML. So this one module is the single source of truth, exercised
 * by tests here and rendered (server-side-computed) in the page.
 */

import type { ManduEvent } from "./event-model.js";

// The ullm_call→tool_use correlation pre-pass (display-only repair for the
// MCP-blinded inspect-mcp emitter — see the module header for why the emitter
// cannot set callId itself); re-exported like the other view-model modules.
export * from "./view-model/correlate.js";
import { traceEvents } from "./view-model/session-counts.js";

// §4.13 assertion panel lives in its own module; re-exported here so the
// public view-model API (and `toSessionViewModel` below) is unchanged.
export * from "./view-model/assertions.js";
import { type AssertionSummary, toAssertionSummary } from "./view-model/assertions.js";

// §4.1/§4.6 invariant / oracle banner lives in its own leaf module;
// re-exported here so the public view-model API is unchanged.
export * from "./view-model/invariant.js";
import { type InvariantStatus, invariantStatus } from "./view-model/invariant.js";

// §2.5/§4.4 T-LLM vs U-LLM classification lives in its own leaf module;
// re-exported here so the public view-model API is unchanged.
export * from "./view-model/classify.js";

// §4.2 three-lane trace + annotated timeline live in their own module (depend on
// modelFamily + firstSymbol); re-exported here so the public view-model API is
// unchanged. Import back what the barrel's remaining sections (§4.2b/§4.2c) + the
// bundle still call.
export * from "./view-model/lanes.js";
import {
  toLaneModel, toTimeline,
  type LaneModel, type TimelineRow,
} from "./view-model/lanes.js";

// §4.2b tool-centric grouping lives in its own module (depends on the lane
// timeline row/annotation types); re-exported here so the public view-model API
// is unchanged. Import back what §4.2c + the bundle still call.
export * from "./view-model/tool-calls.js";
import {
  extractToolUses, groupToolCalls, toolUnitPolicy, type TimelineUnit,
} from "./view-model/tool-calls.js";
// §4.2c dual-lane mode lives in its own module (depends on eventTitle/
// eventTool from lanes + extractToolUses from tool-calls + the transcript
// parser); re-exported here so the public view-model API is unchanged. Import
// toDualLanes + DualLanesModel back for toSessionViewModel.
export * from "./view-model/dual-lanes.js";
import { type DualLanesModel, toDualLanes } from "./view-model/dual-lanes.js";
export { type PairedModel, type PairedTurn, type PairedRow, type PairedToolRow, type BackgroundGroup, type RecordedProtection, toPairedTurns, recordedProtection, revealPairedOriginals } from "./view-model/paired-rows.js";
import { type PairedModel, toPairedTurns, recordedProtection } from "./view-model/paired-rows.js";

// §4.2c delivery-zone deep reveal: an ASYNC post-pass the /api/events route
// applies over the assembled bundle (it needs the arbiter, which this pure
// projection layer must not); re-exported so consumers import one barrel.
export * from "./view-model/delivery.js";

// §4.2c render self-check (render-lint.ts): the four no-ground-truth
// consistency invariants over a session's events + dual-lanes render (final
// never the upstream-error explainer; delivered-reply symbols resolved by the
// reply-filter; every prose model call classified; each turn's prompt/prose
// ordered before its tool cards). Re-exported so the fixture
// sweep, claude-e2e, and the server badge all import one barrel.
export * from "./view-model/render-lint.js";
import { type RenderLintFinding, lintRender } from "./view-model/render-lint.js";

// §4.3 call-detail panel lives in its own module (depends on modelFamily);
// re-exported here so the public view-model API is unchanged. It is an on-demand
// per-event projection — not part of the session bundle — so nothing local
// imports it back.
export * from "./view-model/call-detail.js";

// §4.5 symbol inspector (+ the shared firstSymbol helper) lives in its own leaf
// module. Re-export the public projectors; import back what the bundle still
// calls. firstSymbol is used by lanes/egress, not the barrel.
export { type SymbolFlowStep, type SymbolInspectorRow, toSymbolInspector } from "./view-model/symbols.js";
import { toSymbolInspector, type SymbolInspectorRow } from "./view-model/symbols.js";


// §4.15 symbol data-lineage graph (symbol-lineage.md §3): one flow per
// derivation closure, every edge evidence-backed.
export * from "./view-model/lineage.js";
import { type SessionLineage, toSessionLineage, withReadFirst } from "./view-model/lineage.js";

// The confidentiality Secrets panel (§6 standing-release surface, plan 6). NOT
// part of the per-session bundle below: it projects the arbiter's live
// `confidentialityState` (a whole-arbiter fact), not this session's events —
// which is why /api/secrets ships it rather than /api/events.
export * from "./view-model/secrets.js";

// ── A single bundle the API can serve / the frontend can consume ──────────────

export interface SessionViewModel {
  sessionId: string;
  invariant: InvariantStatus;
  /** The single annotated trace the UI renders (§4.2) — the flat, proxy/pipeline
   *  perspective (one row per event). */
  timeline: TimelineRow[];
  /** The SAME trace grouped into tool calls (§4.2b) — the agent's perspective,
   *  one unit per tool call (defense steps nested) + standalone model turns. */
  toolUnits: TimelineUnit[];
  /** The dual-lane mode (§4.2c) — the DEFAULT main-frame view: deduplicated
   *  steps for the AgentView/HumanView lanes + translation bands. */
  dualLanes: DualLanesModel;
  /** §4.2f the paired-rows trace the /dev/ main pane renders: `dualLanes`'s
   *  steps grouped into turns, one row per step, background folded. */
  paired: PairedModel;
  /** The ordered-card model the timeline derives from (sort/turns/causal links);
   *  the three-lane columns are no longer rendered, but this stays the canonical
   *  ordering/grouping source and keeps the pure projections independently tested. */
  lanes: LaneModel;
  symbols: SymbolInspectorRow[];
  /** The symbol data-lineage graph (§4.15 / symbol-lineage.md): one flow per
   *  derivation closure, every edge backed by a recorded event. */
  lineage: SessionLineage;
  /** The e2e SECURITY/UTILITY assertion verdict (§4.13), or null for a session
   *  that carries no `assertion` event (a normal, non-e2e session). */
  assertions: AssertionSummary | null;
  /** Render self-check findings (render-lint.ts) — empty for a healthy render.
   *  The UI surfaces these on the verdict strip so a wrong or suspect
   *  delivered reply announces itself. */
  renderLint: RenderLintFinding[];
  /** highest turn seen, for the "turn N/M" header. */
  maxTurn: number;
  /** Decision-provenance counts (policy-surface.md §9.5): ruleRef.id → how
   *  many decisions that rule/verdict made in THIS session. The Policy panel
   *  renders these as per-row "decided N here" links back into the trace. */
  ruleRefCounts: Record<string, number>;
  /** Approval-queue joins (policy-surface.md §9.5): queue entry id (`egr-<n>`)
   *  → how many of THIS session's queued denies created/bumped that row. The
   *  Pending tab highlights its rows that this session touched. */
  approvalIdCounts: Record<string, number>;
}

/** Assemble the full per-session view-model from raw events. */
export function toSessionViewModel(sessionId: string, events: ManduEvent[]): SessionViewModel {
  // The per-session `assertion` verdict and the harness's `workspace_seed` /
  // `workspace_final` records are META events (the harness's own check results
  // / prepared- and final-disk records), NOT trace steps — keep them out of
  // every trace projection so they never render as phantom lane cards, while
  // still feeding their panels (assertion panel §4.13, test-setup banner §4.11,
  // Files-tab event fallback §4.12).
  // Correlation pre-pass BEFORE every projection (timeline, toolUnits,
  // dualLanes, lanes, symbols, egress all benefit): attach orphan ullm_call
  // events (inspect-mcp cannot learn the invoking tool_use id over MCP) to
  // their inspect tool_use, so the quarantine folds into the tool card
  // instead of rendering a standalone orphan box. Display-only; pure.
  const trace = traceEvents(events);
  const timeline = toTimeline(trace);
  const toolUnits = groupToolCalls(timeline, extractToolUses(trace));
  // Enrich each tool-call unit with its folded per-call policy decision (the
  // rows carry only `trust`; the full EventPolicy lives on the raw events).
  const eventsById = new Map(trace.map((e) => [e.id, e]));
  for (const u of toolUnits) {
    if (u.unit === "toolcall") u.policy = toolUnitPolicy(u, eventsById);
  }
  const dualLanes = toDualLanes(trace);
  const symbols = toSymbolInspector(trace);
  return {
    sessionId,
    invariant: invariantStatus(trace),
    timeline,
    toolUnits,
    dualLanes,
    paired: toPairedTurns(dualLanes, symbols, recordedProtection(trace)),
    lanes: toLaneModel(trace),
    symbols,
    // An item the AI read as it was before it was masked (§4.15): the
    // trace's `maskedLater` results, so no line says it was masked first.
    lineage: withReadFirst(toSessionLineage(trace), dualLanes.steps.flatMap((s) => (s.step === "tool" && s.maskedLater ? [s.maskedLater] : []))),
    assertions: toAssertionSummary(events),
    renderLint: lintRender(trace, dualLanes),
    maxTurn: trace.reduce((m, e) => Math.max(m, e.turn), 0),
    ruleRefCounts: toRuleRefCounts(trace),
    approvalIdCounts: toApprovalIdCounts(trace),
  };
}

/** Count decisions per ruleRef id over a session's trace (pure; policy-
 * visibility.md §5). Every event whose EventPolicy carries a ruleRef counts —
 * gate events today, audit events in the arbiter-admin stream, whatever gains
 * provenance later. */
export function toRuleRefCounts(events: ManduEvent[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const e of events) {
    const id = e.policy?.ruleRef?.id;
    if (!id) continue;
    counts[id] = (counts[id] ?? 0) + 1;
  }
  return counts;
}

/** Count queued denies per approval-queue entry id over a session's trace
 * (pure; policy-surface.md §9.5). A gate event whose deny created/bumped a
 * Pending row carries `policy.approvalId` (`egr-<n>`); the Pending tab uses
 * these counts to highlight the rows THIS session touched. Pre-provenance
 * events (no approvalId) contribute nothing — no invented joins. */
export function toApprovalIdCounts(events: ManduEvent[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const e of events) {
    const id = e.policy?.approvalId;
    if (!id) continue;
    counts[id] = (counts[id] ?? 0) + 1;
  }
  return counts;
}
