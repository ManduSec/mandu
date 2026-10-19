/**
 * view-model/render-lint — the dashboard's render SELF-CHECK (§4.2c fidelity).
 *
 * Mandu-new (no reference origin). WHY this exists: three live incidents
 * (sessions 1783675777, 1783711204, 1783733223) rendered the WRONG delivered
 * reply because a Claude Code harness side call stole `final`, and each was
 * found by a human squinting at the delivery zone — the live claude-e2e suite
 * could not see them because it drives `claude -p` (print mode) while every
 * stealing shape is interactive-only (typeahead, away-recap, a rate-limited
 * startup probe). These checks need NO ground-truth transcript, so they run on
 * ANY session: as a unit sweep over the captured-live fixture corpus, inside
 * claude-e2e's fidelity block, and live in the dashboard itself (a badge on the
 * verdict strip) — a mis-render announces itself instead of waiting to
 * be noticed.
 *
 * The four invariants:
 *   1. final-not-explainer (ERROR): the delivered-reply card is never the
 *      proxy's synthesized "⚠ no model response — upstream HTTP …" explainer —
 *      an errored turn delivered nothing, so the explainer in the delivery
 *      zone is by construction a wrong render.
 *   2. delivered-reply-resolved (WARN): when the session has reply-filter
 *      `desymbolize` events (the PTY/pipe egress frames — ground truth for
 *      what the human's terminal actually showed), every symbol the delivered
 *      reply references must appear in some frame the reply-filter resolved.
 *      A final card referencing a symbol the reply-filter never touched means
 *      the delivery zone shows a reply the human never received. WARN, not
 *      error: the reply-filter degrades to passthrough (utility posture), so
 *      an unresolved-but-delivered symbol is possible without a render bug.
 *   3. model-call-classified (WARN): every prose-producing tllm_call is either
 *      part of the conversation (its prompt list extends the history) or a
 *      RECOGNIZED side call (dual-lanes `ModelCallClass`). An "unknown" prose
 *      call is exactly the shape that steals the delivery zone — the canary
 *      that fires when a Claude Code release invents a new side call (or a
 *      history rewrite — prompt edit/resubmit, /compact — degrades the
 *      render), instead of the trace going silently wrong.
 *   4. turn-order-coherent (ERROR): within one turn, the prompt (input card)
 *      renders before the turn's response card and tool cards, and the
 *      response's announcing prose renders before the tool cards it issued.
 *      The proxy emits tool_use mid-SSE-stream but the prose/prompt-bearing
 *      tllm_call at stream END, so the builder FLOATS inputs/responses back
 *      over their own turn's tool/os cards; two live sessions (chain-fetch-
 *      write-read, exec-curl-run-blindspot, 2026-07-16) rendered backwards
 *      ("Now saving…" after its Write card; the user's prompt after the Bash
 *      it caused) because an unanticipated interleaver — a turn-0 net_action
 *      card mid-parse — stopped the float scan. This invariant asserts the
 *      ORDER CONTRACT on the render itself, so the NEXT unanticipated
 *      interleaver shape fails the fixture sweep / claude-e2e fidelity block /
 *      dashboard badge instead of waiting for a human to squint at a session.
 */

import type { ManduEvent } from "../event-model.js";
import { matchSymbols, type DualLanesModel } from "./dual-lanes.js";

/** The invariant a finding violated (stable ids — asserted on by e2e checks). */
export type RenderLintInvariant =
  | "final-not-explainer"
  | "delivered-reply-resolved"
  | "model-call-classified"
  | "turn-order-coherent";

/** error = the render is wrong by construction (blocking in test harnesses);
 *  warn = the render is suspect but a benign explanation exists (advisory). */
export type RenderLintSeverity = "error" | "warn";

export interface RenderLintFinding {
  invariant: RenderLintInvariant;
  severity: RenderLintSeverity;
  /** Human-readable evidence — what looked wrong and where. */
  detail: string;
  /** The event this finding anchors to, when one exists. */
  eventId: string | null;
}

/** The proxy's synthesized upstream-error stand-in (proxy.ts; mirrored by
 *  dual-lanes' isNoModelResponse — kept private there, re-tested here). */
const EXPLAINER_PREFIX = "⚠ no model response";

/**
 * Run the three self-consistency invariants over one session's events and its
 * dual-lanes render. Pure and cheap (one pass over events + steps); returns an
 * empty array for a healthy session.
 */
export function lintRender(events: ManduEvent[], dual: DualLanesModel): RenderLintFinding[] {
  const findings: RenderLintFinding[] = [];
  const final = dual.steps.find((s) => s.step === "response" && s.final);

  // 1 — final-not-explainer.
  if (final && final.step === "response" && final.text.trimStart().startsWith(EXPLAINER_PREFIX)) {
    findings.push({
      invariant: "final-not-explainer",
      severity: "error",
      detail:
        "the delivered-reply card is the proxy's upstream-error explainer " +
        `(${JSON.stringify(final.text.slice(0, 80))}) — an errored turn delivered nothing`,
      eventId: final.id.replace(/^resp:/, ""),
    });
  }

  // 2 — delivered-reply-resolved: the reply-filter frames are ground truth for
  // what reached the human's terminal.
  if (final && final.step === "response") {
    const frames = events.filter((e) => e.kind === "desymbolize" && e.emitter === "reply-filter");
    if (frames.length > 0) {
      const resolved = new Set<string>();
      for (const f of frames) {
        for (const t of matchSymbols(f.input?.symbolized)) resolved.add(t);
        for (const t of matchSymbols(f.output?.symbolized)) resolved.add(t);
      }
      const unseen = matchSymbols(final.text).filter((t) => !resolved.has(t));
      if (unseen.length > 0) {
        findings.push({
          invariant: "delivered-reply-resolved",
          severity: "warn",
          detail:
            `the delivered reply references ${unseen.join(", ")} but no reply-filter frame ` +
            "ever resolved it — the human may never have received this reply",
          eventId: final.id.replace(/^resp:/, ""),
        });
      }
    }
  }

  // 3 — model-call-classified: the new-side-call canary.
  for (const c of dual.calls) {
    if (c.cls !== "unknown" || !c.prose) continue;
    findings.push({
      invariant: "model-call-classified",
      severity: "warn",
      detail:
        `turn ${c.turn}: a prose model call is neither conversation-extending nor a recognized ` +
        "side call — a new harness side-call shape, or a history rewrite (prompt edit, /compact); " +
        "its response card may not belong in the conversation lane",
      eventId: c.id,
    });
  }

  // 4 — turn-order-coherent: within a turn, prompt → announcing prose → tool
  // cards. A turn-T tool card is minted by turn T's model response, so the
  // input/response cards of the SAME turn must render before it — a render
  // where they don't shows the user's prompt (or the model's announcing text)
  // AFTER the action it caused. Stated on the render, not the builder: any
  // future interleaver the float scan doesn't anticipate fires this.
  const firstToolAt = new Map<number, { idx: number; tool: string }>();
  for (let idx = 0; idx < dual.steps.length; idx++) {
    const s = dual.steps[idx]!;
    if (s.step === "tool" && !firstToolAt.has(s.turn)) firstToolAt.set(s.turn, { idx, tool: s.tool });
  }
  const respAt = new Map<number, number>();
  for (let idx = 0; idx < dual.steps.length; idx++) {
    const s = dual.steps[idx]!;
    if (s.step === "response" && !respAt.has(s.turn)) respAt.set(s.turn, idx);
  }
  for (let idx = 0; idx < dual.steps.length; idx++) {
    const s = dual.steps[idx]!;
    if (s.step !== "input" && s.step !== "response") continue;
    const tool = firstToolAt.get(s.turn);
    if (tool && idx > tool.idx) {
      findings.push({
        invariant: "turn-order-coherent",
        severity: "error",
        detail:
          `turn ${s.turn}: the ${s.step === "input" ? "user's prompt" : "response's announcing prose"} ` +
          `card renders AFTER its own turn's ${tool.tool} tool card — ` +
          "the trace shows the action before the words that caused it",
        eventId: s.id.replace(/^(?:input|resp):/, "").replace(/:\d+$/, ""),
      });
    }
    const resp = respAt.get(s.turn);
    if (s.step === "input" && resp !== undefined && idx > resp) {
      findings.push({
        invariant: "turn-order-coherent",
        severity: "error",
        detail: `turn ${s.turn}: the user's prompt card renders AFTER its own turn's response card`,
        eventId: s.id.replace(/^input:/, "").replace(/:\d+$/, ""),
      });
    }
  }

  return findings;
}
