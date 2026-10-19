/**
 * view-model/detail — the shared ⓘ-drawer detail vocabulary.
 *
 * Moved out of view-model/policy-panel.ts (2026-07-30) so the trace's
 * per-event drawers (dual-lanes.ts) and the Policy panel's per-row drawers
 * (policy-panel.ts, §8) share ONE structured shape — the fixed section template
 * cannot drift when both surfaces speak the same type. policy-panel re-exports
 * these for its existing importers; `whereLabel` (the §8 chokepoint vocabulary)
 * stays in policy-panel.
 */

/** One line of ⓘ-drawer detail. When `ms` is present the shell appends a
 * locale-formatted time (null ⇒ the honest word "unknown") — timestamps stay
 * epoch-typed here so the projection is deterministic and locale-free.
 * `pre: true` renders the text as preformatted block content (monospace,
 * whitespace preserved — for verbatim payloads like the handling prompt,
 * §8.8) instead of a detail line; still textContent-only, never markup. */
export interface DetailItem {
  text: string;
  ms?: number | null;
  pre?: boolean;
}

/** One labeled section of the ⓘ drawer — every drawer renders the same
 * fixed template (§8): what this is / what it does / where it's specified /
 * when it applies / activity. */
export interface DetailSection {
  label: string;
  items: DetailItem[];
}
