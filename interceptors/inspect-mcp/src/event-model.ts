/**
 * event-model — the subset of the canonical Mandu event schema this package
 * emits, declared locally so inspect-mcp typechecks standalone.
 *
 * Mandu M4 (interceptors/inspect-mcp). The canonical schema is owned by the
 * dashboard package (dashboard/src/event-model.ts, docs/design/ui/dashboard.md §2)
 * and is concurrently edited by a sibling sub-agent. Following the same
 * decoupling rationale as the anthropic-proxy's arbiter-client (declare the dep's
 * shape rather than importing a sibling package), we mirror ONLY the fields the
 * `ullm_call` event uses. The arbiter→event seam projects/validates the full
 * record; the arbiter tolerates extra/missing optional fields.
 *
 * MUST stay structurally compatible with dashboard/src/event-model.ts. The
 * load-bearing pieces for the U-LLM lane:
 *   - view "Quarantine"  — the U-LLM lane.
 *   - kind "ullm_call"   — a quarantined model call.
 *   - DualRepr           — input/output carried in BOTH symbolized + original.
 *   - invariant          — false for a healthy re-symbolized inspect_symbol.
 */

// ── The view dimension — the lane each event renders in ───────────────────────
export type View = "AgentView" | "HumanView" | "Quarantine";

// ── Symbol provenance — mirrors arbiter SymbolEntry / dashboard SymbolRef ───────
export interface SymbolRef {
  name: string;
  tool: string;
  field: string | null;
  origin: string | null;
  value: string | null;
  derivedFrom?: string;
  lineRange?: string;
}

// ── The two-representation model ──────────────────────────────────────────────
export interface DualRepr {
  /** What T-LLM / AgentView saw. Untrusted spans are $MDU:* here. */
  symbolized: string;
  /** What HumanView / the quarantined U-LLM saw. null if not desymbolized. */
  original: string | null;
  /** True iff symbolized !== original, i.e. symbolization actually occurred. */
  differs: boolean;
  /** Symbols referenced in `symbolized`, with provenance. */
  symbols: SymbolRef[];
}

export type EventKind =
  | "tllm_call"
  | "ullm_call"
  | "tool_use"
  | "tool_result"
  | "classify"
  | "symbolize"
  | "desymbolize"
  | "egress_request"
  | "egress_decision"
  | "fs_action"
  | "net_action"
  | "exec_action";

export type Boundary = "model_context" | "network" | "filesystem" | "shell";

export type Emitter =
  | "anthropic-proxy"
  | "arbiter"
  | "fs-supervisor"
  | "net-supervisor"
  | "exec-supervisor"
  | "inspect-mcp"; // M4 cooperative U-LLM path (this package).

export interface EventPolicy {
  trust?: "TRUSTED" | "UNTRUSTED";
  category?: string | null;
  reason?: string;
  usage?: "allow" | "deny" | "needs_approval";
  shell?: "AgentShell" | "HumanShell";
}

export interface EventInvariant {
  /** True iff this event would put UN-symbolized UNTRUSTED data into T-LLM's
   *  context. MUST be false for every event in a healthy session. */
  violatedInvariant: boolean;
  detail?: string;
}

export interface EventModel {
  id: string;
  inputTokens?: number;
  outputTokens?: number;
}

/**
 * One block of a model call's COMPLETE, untruncated input, tagged by source so
 * the dashboard can reveal the full prompt and HIGHLIGHT what Mandu injected.
 * For the U-LLM lane: the quarantine/system instructions are source "mandu";
 * the inspected (symbolized) data is source "conversation". `text` is the FULL
 * SYMBOLIZED text — no cap, and NEVER the raw untrusted value. MUST stay
 * structurally compatible with dashboard/src/event-model.ts `fullInput.blocks`.
 */
export interface FullInputBlock {
  role: "system" | "user" | "assistant" | "tool_result";
  source: "mandu" | "agent" | "conversation";
  text: string;
  label?: string;
}

/** The complete, untruncated structured input to a model call (ullm_call). */
export interface FullInput {
  blocks: FullInputBlock[];
}

/** Which model endpoint a quarantined call ran on (Plan 11 D6). `location`
 *  is `local` only for an endpoint policy.yaml `models:` declares `local:
 *  true`; the default U-LLM is `{ name: "default", location: "external" }`.
 *  Plan 12 D6: a declared endpoint also carries its `placement` (`host` =
 *  this computer, `network` = another machine, derived from its url), and
 *  `plainHttp: true` when the call went over plain http to another machine
 *  by the entry's `allow_plain_http` opt-out. */
export interface InspectEndpoint {
  name: string;
  location: "local" | "external";
  placement?: "host" | "network";
  plainHttp?: true;
}

export interface ManduEvent {
  id: string;
  sessionId: string;
  turn: number;
  ts: string;
  seq: number;
  callId: string | null;
  parentId: string | null;
  kind: EventKind;
  view: View;
  boundary: Boundary;
  emitter: Emitter;
  input: DualRepr | null;
  output: DualRepr | null;
  policy?: EventPolicy;
  invariant: EventInvariant;
  model?: EventModel;
  /** Complete, untruncated input to a model call (ullm_call), each block tagged
   *  by source. Optional — only the model-call emitters set it. */
  fullInput?: FullInput;
  /** The endpoint a `ullm_call` ran on (inspect-mcp sets it on every
   *  quarantined call, the triage included; Plan 11 D6). */
  endpoint?: InspectEndpoint;
}

/**
 * Construct a DualRepr, computing `differs` from the values so it can never
 * drift out of sync (mirrors dashboard/src/event-model.ts makeDualRepr).
 */
export function makeDualRepr(
  symbolized: string,
  original: string | null,
  symbols: SymbolRef[] = [],
): DualRepr {
  return {
    symbolized,
    original,
    differs: original !== null && symbolized !== original,
    symbols,
  };
}
