/**
 * view-model/assertions — §4.13 e2e SECURITY / UTILITY assertion panel.
 *
 * Extracted verbatim from view-model.ts (agent-legibility split, behavior-preserving).
 * PROVENANCE (CONTRIBUTING.md reuse policy): the group split + `pass/effective` scoring
 * + overall verdict logic are lifted from the reference DualView dashboard
 *   https://github.com/compsec-snu/dualview/blob/main/dashboard/js/conversation.js (lines 1671-1762 at port time)
 * (the correctness/utility group panel). Adapted: the reference groups
 * correctness vs utility; here security (blocking) vs utility (non-blocking) vs
 * fidelity (the render matches what the client recorded) — with security
 * sub-grouped by `aspect` (integrity | confidentiality, event-model.ts
 * SecurityAspect; aspect-less legacy checks render as an unsplit group), and
 * this is a PURE projector over the session's `assertion` event rather than a
 * browser-side reducer over parsed log lines. `warn` is the reference's
 * non-blocking failure; `skip` its inapplicable check — both excluded from the
 * group denominator (`effective = total − skip − warn`) so the headline score
 * reflects only genuinely-evaluated checks.
 */

import type {
  ManduEvent, AssertionCheck, AssertionCategory, AssertionStatus, SecurityAspect,
} from "../event-model.js";

/** Per-category tallies + the `pass/effective` score the panel header shows. */
export interface AssertionGroup {
  category: AssertionCategory;
  /** Set on the split security subgroups (integrity | confidentiality); absent
   *  on utility/fidelity and on the legacy unsplit Security group (aspect-less
   *  checks from pre-aspect persisted events). */
  aspect?: SecurityAspect;
  checks: AssertionCheck[];
  pass: number;
  fail: number;
  warn: number;
  skip: number;
  /** total − skip − warn — the score denominator (evaluated checks only). */
  effective: number;
  /** "ok" (all pass) | "warn" (only non-blocking warns) | "violation" (a fail). */
  level: "ok" | "warn" | "violation";
}

export interface AssertionSummary {
  /** security first (split integrity → confidentiality → legacy aspect-less),
   *  then utility, then warned, then fidelity (only groups that have checks). */
  groups: AssertionGroup[];
  /** BLOCKING failures across all groups (status==="fail"). Test-failing. */
  blockingFail: number;
  /** Non-blocking warns across all groups (status==="warn"). */
  nonBlocking: number;
  /** pass count / effective count summed across groups (the headline score). */
  pass: number;
  effective: number;
  /** "ok" | "warn" | "violation" — the panel header accent. */
  level: "ok" | "warn" | "violation";
  /** "ALL PASSED" | "PASSED, N non-blocking" | "N FAILED[, M non-blocking]". */
  label: string;
  /** ISO ts of the assertion event, for the panel subtitle. */
  ts: string | null;
}

// `warned` (the human was told; event-model.ts AssertionCategory) after
// utility: a drill's third measure, its own group
const ASSERTION_GROUP_ORDER: AssertionCategory[] = ["security", "utility", "warned", "fidelity"];
const SECURITY_ASPECT_ORDER: SecurityAspect[] = ["integrity", "confidentiality"];

function tally(checks: AssertionCheck[], status: AssertionStatus): number {
  return checks.filter((c) => c.status === status).length;
}

/** The ordered (category, aspect?) partitions the panel renders. Security is
 *  sub-grouped by `aspect` (integrity → confidentiality → an unsplit legacy
 *  remainder for aspect-less checks from pre-aspect events); utility and
 *  fidelity stay whole. Empty partitions are dropped. */
function partitionChecks(
  checks: AssertionCheck[],
): Array<{ category: AssertionCategory; aspect?: SecurityAspect; checks: AssertionCheck[] }> {
  const parts: Array<{ category: AssertionCategory; aspect?: SecurityAspect; checks: AssertionCheck[] }> = [];
  for (const category of ASSERTION_GROUP_ORDER) {
    const groupChecks = checks.filter((c) => c.category === category);
    if (groupChecks.length === 0) continue;
    if (category !== "security") {
      parts.push({ category, checks: groupChecks });
      continue;
    }
    for (const aspect of SECURITY_ASPECT_ORDER) {
      const sub = groupChecks.filter((c) => c.aspect === aspect);
      if (sub.length > 0) parts.push({ category, aspect, checks: sub });
    }
    const legacy = groupChecks.filter((c) => !SECURITY_ASPECT_ORDER.includes(c.aspect as SecurityAspect));
    if (legacy.length > 0) parts.push({ category, checks: legacy });
  }
  return parts;
}

/**
 * Project the session's `assertion` event into the grouped summary the panel
 * renders. Returns null when the session carries no assertion event (a normal,
 * non-e2e session → the panel stays hidden). If more than one assertion event
 * exists (a re-run wrote a second), the LAST one wins.
 */
export function toAssertionSummary(events: ManduEvent[]): AssertionSummary | null {
  const assertionEvents = events.filter((e) => e.kind === "assertion");
  if (assertionEvents.length === 0) return null;
  const latest = assertionEvents[assertionEvents.length - 1]!;
  const checks = Array.isArray(latest.assertions) ? latest.assertions : [];
  if (checks.length === 0) return null;

  const groups: AssertionGroup[] = [];
  let blockingFail = 0;
  let nonBlocking = 0;
  let pass = 0;
  let effective = 0;
  for (const part of partitionChecks(checks)) {
    const groupChecks = part.checks;
    const p = tally(groupChecks, "pass");
    const f = tally(groupChecks, "fail");
    const w = tally(groupChecks, "warn");
    const s = tally(groupChecks, "skip");
    const eff = groupChecks.length - s - w;
    const level: AssertionGroup["level"] = f > 0 ? "violation" : w > 0 ? "warn" : "ok";
    groups.push({
      category: part.category,
      ...(part.aspect ? { aspect: part.aspect } : {}),
      checks: groupChecks, pass: p, fail: f, warn: w, skip: s, effective: eff, level,
    });
    blockingFail += f;
    nonBlocking += w;
    pass += p;
    effective += eff;
  }

  const level: AssertionSummary["level"] =
    blockingFail > 0 ? "violation" : nonBlocking > 0 ? "warn" : "ok";
  const nbSuffix = nonBlocking > 0 ? `, ${nonBlocking} non-blocking` : "";
  const label =
    blockingFail > 0
      ? `${blockingFail} FAILED${nbSuffix}`
      : nonBlocking > 0
        ? `PASSED${nbSuffix}`
        : "ALL PASSED";
  return { groups, blockingFail, nonBlocking, pass, effective, level, label, ts: latest.ts ?? null };
}
