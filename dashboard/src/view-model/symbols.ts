/**
 * view-model/symbols — §4.5 symbol inspector (symbol → value → flow).
 *
 * Extracted verbatim from view-model.ts (agent-legibility split, behavior-preserving).
 * Also owns the shared `firstSymbol` helper: it was file-private in view-model.ts
 * but is used by the lane-card titles (`lanes`) and the egress queue (`egress`),
 * so it lives here as the lowest module those two import from (keeps the graph
 * acyclic). `firstSymbol` is intentionally NOT re-exported from the barrel — it
 * stays an internal helper, so the public view-model API is unchanged.
 */

import type { ManduEvent, SymbolRef, EventKind, View } from "../event-model.js";

export interface SymbolFlowStep {
  eventId: string;
  kind: EventKind;
  view: View;
  turn: number;
  ts: string;
  /** canonical-order tiebreak of the referencing event (§3.2). */
  seq: number;
  /** "created" on the first event that referenced the symbol; else "seen". */
  role: "created" | "seen";
}

export interface SymbolInspectorRow {
  name: string;
  tool: string;
  field: string | null;
  origin: string | null;
  /** privileged resolved value (click-to-reveal in UI); null if unknown. */
  value: string | null;
  derivedFrom: string | null;
  lineRange: string | null;
  /** §4.14 birth — the FIRST-referencing event in canonical order (ts then seq;
   *  === flow[0]). One birth per name per session no matter how many turns
   *  re-emit the symbol: the anchor cut (birthSeq ≤ anchor) and the assignment
   *  markers both key off this. */
  birthSeq: number;
  birthTurn: number;
  birthTs: string;
  birthEventId: string;
  /** every event whose DualRepr.symbols references this symbol (§4.5 flow). */
  flow: SymbolFlowStep[];
}

/** First symbol referenced across an event's input/output reprs, or null.
 *  Shared helper (lane-card titles + egress queue); not part of the public API. */
export function firstSymbol(event: ManduEvent): SymbolRef | null {
  for (const r of [event.input, event.output]) {
    if (r && r.symbols.length) return r.symbols[0]!;
  }
  return null;
}

function eventSymbols(event: ManduEvent): SymbolRef[] {
  const out: SymbolRef[] = [];
  for (const r of [event.input, event.output]) {
    if (r) out.push(...r.symbols);
  }
  return out;
}

/**
 * §4.5 — cumulative symbol table across the session, each with its cross-event
 * flow trace ("created at tool_result t0 → read by tllm_call t1 → …"). This is
 * the inspector the reference dashboard lacks (it shows a table but not the
 * cross-event flow).
 */
export function toSymbolInspector(events: ManduEvent[]): SymbolInspectorRow[] {
  const ordered = [...events].sort((a, b) =>
    a.ts !== b.ts ? (a.ts < b.ts ? -1 : 1) : a.seq - b.seq,
  );
  const rows = new Map<string, SymbolInspectorRow>();
  for (const e of ordered) {
    for (const s of eventSymbols(e)) {
      let row = rows.get(s.name);
      if (!row) {
        row = {
          name: s.name,
          tool: s.tool,
          field: s.field,
          origin: s.origin,
          value: s.value,
          derivedFrom: s.derivedFrom ?? null,
          lineRange: s.lineRange ?? null,
          // Birth = THIS event (the first reference, in canonical order); later
          // re-emissions only enrich the row — they never move the birth (§4.14).
          birthSeq: e.seq,
          birthTurn: e.turn,
          birthTs: e.ts,
          birthEventId: e.id,
          flow: [],
        };
        rows.set(s.name, row);
      }
      // Enrich a resolved value / provenance if a later ref carries more.
      if (row.value === null && s.value !== null) row.value = s.value;
      if (row.derivedFrom === null && s.derivedFrom) row.derivedFrom = s.derivedFrom;
      if (row.lineRange === null && s.lineRange) row.lineRange = s.lineRange;
      row.flow.push({
        eventId: e.id,
        kind: e.kind,
        view: e.view,
        turn: e.turn,
        ts: e.ts,
        seq: e.seq,
        role: row.flow.length === 0 ? "created" : "seen",
      });
    }
  }
  return [...rows.values()];
}
