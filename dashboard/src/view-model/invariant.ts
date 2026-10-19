/**
 * view-model/invariant — §4.1/§4.6 the top-bar invariant / oracle banner.
 *
 * Extracted verbatim from view-model.ts (agent-legibility split, behavior-preserving).
 * A leaf module: it only reads the per-event `violatedInvariant` flag the proxy
 * oracle stamped at emit time — the UI never recomputes the predicate.
 */

import type { ManduEvent } from "../event-model.js";

export interface InvariantStatus {
  /** ∀ events: !violatedInvariant. The whole point — green when true. */
  holds: boolean;
  /** Number of violating events (0 when holds). */
  violationCount: number;
  /** ids of violating events, for the jump-to-link. */
  violationIds: string[];
  /** First violation's detail string, for the banner subtitle. */
  firstDetail: string | null;
  /** "ok" → green banner; "violation" → red banner. */
  level: "ok" | "violation";
  label: string; //  "INVARIANT HOLDS" | "INVARIANT VIOLATION"
}

/**
 * Compute the oracle verdict purely from the per-event flags (§4.6). The UI
 * NEVER computes the predicate itself — it only renders what the proxy oracle
 * stamped at emit time, so the dashboard can never mask a violation.
 */
export function invariantStatus(events: ManduEvent[]): InvariantStatus {
  const violating = events.filter((e) => e.invariant.violatedInvariant);
  const holds = violating.length === 0;
  return {
    holds,
    violationCount: violating.length,
    violationIds: violating.map((e) => e.id),
    firstDetail: violating.length ? violating[0]!.invariant.detail ?? null : null,
    level: holds ? "ok" : "violation",
    label: holds ? "INVARIANT HOLDS" : "INVARIANT VIOLATION",
  };
}
