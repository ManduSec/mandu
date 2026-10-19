/**
 * view-model/call-detail — §4.3 the call-detail panel (symbolized vs original).
 *
 * Extracted verbatim from view-model.ts (agent-legibility split, behavior-preserving).
 * An on-demand per-event projection (selecting any trace row → its side-by-side
 * detail); not part of the session bundle. Depends only on `modelFamily`.
 */

import type {
  ManduEvent, DualRepr, FullInput, SymbolRef, View, EventKind,
} from "../event-model.js";
import { type ModelFamily, modelFamily } from "./classify.js";

export interface ReprPanel {
  /** Which payload this is. */
  role: "input" | "output";
  /** present iff the event carries this repr. */
  present: boolean;
  /** What T-LLM/AgentView saw ($MDU:* spans live here). */
  symbolized: string;
  /** What HumanView saw; null → "(revealed on demand)" (§7.1). */
  original: string | null;
  /** True → render the two panes side-by-side; false → collapse to one. */
  sideBySide: boolean;
  /** Symbols referenced, for click→inspector wiring. */
  symbols: SymbolRef[];
}

export interface CallDetail {
  id: string;
  kind: EventKind;
  view: View;
  turn: number;
  callId: string | null;
  boundary: string;
  emitter: string;
  modelFamily: ModelFamily;
  model: { id: string; inputTokens?: number; outputTokens?: number } | null;
  trust: "TRUSTED" | "UNTRUSTED" | null;
  policyReason: string | null;
  usage: "allow" | "deny" | "needs_approval" | null;
  shell: "AgentShell" | "HumanShell" | null;
  input: ReprPanel;
  output: ReprPanel;
  /** §4.3 footer: green when this event's invariant held, red + quote when not. */
  invariant: { violated: boolean; detail: string | null; footer: string };
  /** §4.3.3 — the COMPLETE, untruncated, source-tagged model-call input, so the
   *  frontend can render the "Show full input" reveal + highlight the mandu
   *  injection. null when the event carries none (older events / non-model kinds). */
  fullInput: FullInput | null;
}

function reprPanel(role: "input" | "output", repr: DualRepr | null): ReprPanel {
  if (repr === null) {
    return {
      role,
      present: false,
      symbolized: "",
      original: null,
      sideBySide: false,
      symbols: [],
    };
  }
  return {
    role,
    present: true,
    symbolized: repr.symbolized,
    original: repr.original,
    // §4.3: side-by-side when differs, collapsed when identical/absent.
    sideBySide: repr.differs,
    symbols: repr.symbols,
  };
}

/** §4.3 — selecting any event → the side-by-side detail view-model. */
export function toCallDetail(event: ManduEvent): CallDetail {
  const violated = event.invariant.violatedInvariant;
  return {
    id: event.id,
    kind: event.kind,
    view: event.view,
    turn: event.turn,
    callId: event.callId,
    boundary: event.boundary,
    emitter: event.emitter,
    modelFamily: modelFamily(event),
    model: event.model ?? null,
    trust: event.policy?.trust ?? null,
    policyReason: event.policy?.reason ?? null,
    usage: event.policy?.usage ?? null,
    shell: event.policy?.shell ?? null,
    input: reprPanel("input", event.input),
    output: reprPanel("output", event.output),
    invariant: {
      violated,
      detail: event.invariant.detail ?? null,
      footer: violated
        ? `VIOLATION: un-symbolized untrusted data reached T-LLM` +
          (event.invariant.detail ? ` — ${event.invariant.detail}` : "")
        : `untrusted text reached T-LLM only as symbols`,
    },
    // Pass the complete, source-tagged input through (or null) so the frontend
    // can render the "Show full input" reveal + highlight the mandu injection.
    fullInput: event.fullInput ?? null,
  };
}
