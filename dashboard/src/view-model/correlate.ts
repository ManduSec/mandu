/**
 * view-model/correlate — display-only correlation pre-pass: attach orphan
 * `ullm_call` events to the inspect `tool_use` that invoked them.
 *
 * WHY THIS EXISTS: the MCP protocol gives a tool server no way to learn the
 * Anthropic `tool_use` id that invoked it — an MCP `tools/call` carries only
 * the tool name + arguments. So inspect-mcp emits its `ullm_call`
 * observability event with `callId: null, parentId: null, turn: 0`: the
 * EMITTER cannot correlate. The dual-lanes builder already folds a ullm_call
 * into its tool card when `callId` matches a known tool_use — without this
 * pass that logic can never fire, and every inspect run renders an orphan
 * standalone "U-LLM (quarantined)" box instead of attaching to the inspect
 * tool card.
 *
 * The heuristic lives in the DASHBOARD (not the emitter or the arbiter)
 * because it is off the security path: events are observability, and this is
 * display-only grouping. A wrong guess mis-groups a card; it can never leak
 * data or alter a policy decision.
 *
 * Deliberately generic-but-conservative:
 *   - only `ullm_call` events with `callId == null` are repaired;
 *   - only `tool_use` events invoking the inspect tool, under any of
 *     Mandu's spellings (inspect-answer.ts; `mcp__mandu-inspect__inspect_symbol(...)`
 *     on Claude Code, `mandu-inspect_inspect_symbol(...)` on OpenCode), are
 *     match targets;
 *   - a match must PRECEDE the ullm_call (ts, seq tiebreak) — the quarantined
 *     model call happens strictly after the decision that spawned it;
 *   - candidates whose args CONTAIN the inspected symbol token (the
 *     ullm_call's `input.symbolized`) are preferred, nearest-preceding first,
 *     and each tool_use is claimed by at most one ullm_call;
 *   - an unmatched ullm_call is left untouched — the orphan card remains,
 *     which is correct for genuinely uncorrelatable events.
 *
 * Pure: never mutates the input array or its elements. A matched ullm_call is
 * returned as a SHALLOW CLONE with `callId` — and, when the emitter's
 * placeholder `turn: 0` is present (inspect-mcp cannot know the turn either) —
 * `turn` adopted from the matched tool_use.
 */

import type { ManduEvent } from "../event-model.js";
import { MANDU_INSPECT_TOOL_SPELLINGS } from "./inspect-answer.js";

/** The inspect tool's call prefixes in a tool_use's input args, one per
 *  spelling of Mandu's own mount. */
const INSPECT_CALL_PREFIXES = MANDU_INSPECT_TOOL_SPELLINGS.map((name) => `${name}(`);

/** Canonical trace order: ts, then seq — the same tiebreak the lane builders use. */
function byCanonical(a: ManduEvent, b: ManduEvent): number {
  return a.ts !== b.ts ? (a.ts < b.ts ? -1 : 1) : a.seq - b.seq;
}

/** True iff `a` is at-or-before `b` in canonical order. */
function atOrBefore(a: ManduEvent, b: ManduEvent): boolean {
  return a.ts !== b.ts ? a.ts < b.ts : a.seq <= b.seq;
}

/**
 * The pre-pass: repair each orphan `ullm_call` (callId null) by adopting the
 * callId/turn of the inspect `tool_use` that invoked it, per the header's
 * matching rules. Returns a new array when anything was repaired (untouched
 * events pass through by reference); returns the input array unchanged when
 * there is nothing to do.
 */
export function correlateUllmCalls(events: ManduEvent[]): ManduEvent[] {
  // Match targets: inspect-tool tool_use events, in canonical order.
  const inspects = events
    .filter((e) =>
      e.kind === "tool_use" && e.callId !== null &&
      INSPECT_CALL_PREFIXES.some((p) => (e.input?.symbolized ?? "").trimStart().startsWith(p)))
    .sort(byCanonical);
  if (inspects.length === 0) return events;

  // A callId already carried by some ullm_call (an emitter that CAN correlate,
  // or a prior pass) is claimed — never fold two quarantine runs onto one card.
  const claimed = new Set<string>(
    events
      .filter((e) => e.kind === "ullm_call" && e.callId !== null)
      .map((e) => e.callId!),
  );

  // Repair orphans in canonical order so claiming is deterministic.
  const orphans = events
    .filter((e) => e.kind === "ullm_call" && e.callId === null)
    .sort(byCanonical);

  const repaired = new Map<ManduEvent, ManduEvent>();
  for (const u of orphans) {
    const preceding = inspects.filter((tu) => atOrBefore(tu, u) && !claimed.has(tu.callId!));
    if (preceding.length === 0) continue;
    // Prefer candidates whose args contain the inspected symbol token (pairs
    // each ullm_call with ITS symbol, not mere adjacency); among the preferred
    // pool — or, token-less, among all unclaimed — take the NEAREST preceding.
    const token = (u.input?.symbolized ?? "").trim();
    const containing = token.length > 0
      ? preceding.filter((tu) => (tu.input?.symbolized ?? "").includes(token))
      : [];
    const pool = containing.length > 0 ? containing : preceding;
    const match = pool[pool.length - 1]!;
    claimed.add(match.callId!);
    repaired.set(u, {
      ...u,
      callId: match.callId,
      // inspect-mcp stamps a placeholder turn 0 (it cannot know the T-LLM
      // request index either) — adopt the invoking tool_use's turn for it.
      turn: u.turn === 0 ? match.turn : u.turn,
    });
  }
  if (repaired.size === 0) return events;
  return events.map((e) => repaired.get(e) ?? e);
}
