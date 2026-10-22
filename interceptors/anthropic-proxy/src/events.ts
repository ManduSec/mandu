/**
 * events — the Track A observability-event builder (best-effort, off the
 * security path).
 *
 * Mandu Track A (interceptors/anthropic-proxy). The proxy enforces the AgentView
 * context boundary (symbolize untrusted tool_result spans, inject the handling
 * prompt, record tool_use). This module lets it ALSO EMIT the canonical
 * `ManduEvent` records (docs/design/ui/dashboard.md §2) so the dashboard can
 * render the dual-view trace.
 *
 * IMPORTANT design constraints:
 *   - This is a LOCAL builder. We deliberately do NOT import the dashboard
 *     package (`dashboard/src/event-model.ts`) — the proxy stays dependency-free
 *     of the dashboard. The interfaces below mirror that schema field-for-field
 *     so the arbiter→dashboard seam stays compatible. If the dashboard schema
 *     drifts, this mirror is the single place to reconcile.
 *   - Emission is BEST-EFFORT and OFF THE SECURITY PATH. The proxy fires events
 *     via `arbiter.emit(...)` wrapped so a failed/slow emit can never block or
 *     fail the request (see `safeEmit`). Events carry the ORIGINAL (raw,
 *     untrusted) bytes in `DualRepr.original`, which go ONLY to the arbiter's
 *     privileged event log / dashboard — they are NEVER fed back upstream toward
 *     T-LLM. The proxy never reads anything back from an emit.
 *
 * The §9 invariant oracle predicate lives here too (`survivingUntrusted`) so the
 * proxy can compute `invariant.violatedInvariant` at emit time from the same
 * predicate the e2e oracle asserts: NO un-symbolized untrusted byte may appear
 * in the forwarded model request.
 */

import { getSymbolPattern } from "./arbiter-client.js";

// ── Mirror of dashboard/src/event-model.ts (§2). Kept local on purpose. ───────

export type View = "AgentView" | "HumanView" | "Quarantine";

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
  | "path_rewrite"
  | "fs_action"
  | "net_action"
  | "exec_action"
  // Session-health kinds (dashboard.md §4.21): client_info / tool_surface are
  // emitted here; the others by the launcher and the reply-filter.
  | "launch_posture" | "relay_mode" | "client_info" | "tool_surface" | "session_exit"
  // Reply row reservation (reply-row-reservation.md §3.4, §3.5), emitted
  // here only; the dashboard renders an unknown kind generically.
  | "reserve_residual" | "reserve_expand"
  // The prompt filter (confidentiality-plan-15 §8): one per segment with a
  // finding or a value the prompt floor let through. Never the value.
  | "prompt_filter";

export type Boundary = "model_context" | "network" | "filesystem" | "shell";

export type Emitter =
  | "anthropic-proxy"
  | "arbiter"
  | "fs-supervisor"
  | "net-supervisor"
  | "exec-supervisor";

/** Symbol provenance (§2.3) — mirrors arbiter SymbolEntry projected to camelCase. */
export interface SymbolRef {
  name: string;
  tool: string;
  field: string | null;
  origin: string | null;
  value: string | null;
  derivedFrom?: string;
  lineRange?: string;
  /** Confidentiality level (confidentiality.md §2). Only a SECRET level is
   *  carried; "public" is the absence of a claim. */
  confidentiality?: string;
}

/** The two-representation model (§2.2). */
export interface DualRepr {
  symbolized: string;
  original: string | null;
  differs: boolean;
  symbols: SymbolRef[];
}

export interface EventPolicy {
  trust?: "TRUSTED" | "UNTRUSTED";
  category?: string | null;
  reason?: string;
  usage?: "allow" | "deny" | "needs_approval";
  shell?: "AgentShell" | "HumanShell";
  /** Decision provenance (policy-surface.md §9.3): which standing rule /
   *  human verdict / fail-closed default decided this. Mirrors
   *  arbiter/policy/rule-ref.ts RuleRef; the dashboard joins on `id`. */
  ruleRef?: { source: "rule" | "verdict" | "fail-closed"; id: string };
  /** The approval-queue row a queued deny created/bumped (`egr-<n>`) — the
   *  dashboard's Pending-tab join (policy-surface.md §9.5). */
  approvalId?: string;
  /** The OTHER half of the 2×3 label (confidentiality.md §2). A TRUSTED trust
   *  WITH a secret level is the normal shape for a credential file. */
  confidentiality?: string;
}

export interface EventInvariant {
  violatedInvariant: boolean;
  detail?: string;
}

export interface EventModelMeta {
  id: string;
  inputTokens?: number;
  outputTokens?: number;
  /** The provider's id for this response (the Messages API's `msg_…`; on a
   *  routed OpenAI-family wire Chat's `chatcmpl-…` or the Responses API's
   *  `resp_…`, as the agent was sent it, response-id.ts), as the agent's own
   *  transcript keeps it: `mandu scan` joins on it to tell a past session
   *  under Mandu exactly (confidentiality-plan-17 §3 item 6). Only on a
   *  tllm_call whose response carried one. */
  responseId?: string;
  /** The agent's own id of its session, as the request carried it
   *  (OpenCode 1.x and 2.x send it with every model request, whatever the
   *  wire, and keep it as the session's row id; {@link agentSessionIdOf}):
   *  `mandu scan` joins on it where the agent keeps no response id
   *  (confidentiality-plan-17 §3 item 6). An opaque id the agent made up,
   *  already sent to the provider; never a secret. */
  agentSessionId?: string;
}

/** A provider's response id as an event keeps it: a short run of id
 *  characters (`msg_…`, `resp_…`), else nothing. Nothing else from the
 *  response is taken. Pure. */
export function responseIdOf(v: unknown): string | undefined {
  return typeof v === "string" && /^[A-Za-z0-9_-]{8,128}$/.test(v) ? v : undefined;
}

/** The request headers that carry the agent's own session id, the first
 *  present one deciding: OpenCode 2.x's `x-opencode-session-id` (the
 *  session's own id; its `X-Session-Id` may name another), OpenCode 1.x's
 *  `X-Session-Id` (with `x-session-affinity`, sent to every provider but
 *  its own), and 1.x's `x-opencode-session` (its own `opencode` provider).
 *  Read off OpenCode 1.18.13's and 2.0.23's requests
 *  (confidentiality-plan-17 §3 item 6). */
export const AGENT_SESSION_HEADERS = ["x-opencode-session-id", "x-session-id", "x-opencode-session"] as const;

/** OpenCode's session id: `ses_` and id characters. */
const AGENT_SESSION_ID_RE = /^ses_[A-Za-z0-9]{8,120}$/;

/** The agent's session id a request carried, when it has OpenCode's shape
 *  (`ses_` and id characters, at most 124 in all), else nothing: a header
 *  of another shape is never taken, so nothing else a header holds can
 *  reach the event. Pure; never throws. */
export function agentSessionIdOf(headers: Record<string, string | string[] | undefined>): string | undefined {
  for (const h of AGENT_SESSION_HEADERS) {
    const v = headers[h];
    if (v === undefined) continue;
    return typeof v === "string" && AGENT_SESSION_ID_RE.test(v) ? v : undefined;
  }
  return undefined;
}

/**
 * One block of a model call's COMPLETE, untruncated input, tagged by source so
 * the dashboard can reveal the full prompt and HIGHLIGHT what Mandu injected.
 *   - source "mandu"      — the injected IPI handling prompt (full text).
 *   - source "agent"        — the agent's own system prompt / blocks.
 *   - source "conversation" — the messages (user/assistant/tool_result turns).
 * `text` is the FULL SYMBOLIZED text — no system/prompt cap is applied. Mirrors
 * dashboard/src/event-model.ts `ManduEvent.fullInput.blocks` field-for-field.
 */
export interface FullInputBlock {
  role: "system" | "user" | "assistant" | "tool_result";
  source: "mandu" | "agent" | "conversation";
  text: string;
  label?: string;
}

/** The complete, untruncated structured input to a model call (tllm_call). */
export interface FullInput {
  blocks: FullInputBlock[];
}

/**
 * Structural request metadata on a `tllm_call` — what the proxy KNOWS about the
 * call it forwarded, so the dashboard can separate the agent CONVERSATION loop
 * (always carries the agent's tool battery) from harness side calls (title gen,
 * quota probe, typeahead, away-recap, WebFetch summarizer — all send zero tools)
 * STRUCTURALLY instead of by string heuristics over prompt text. Mirrors
 * dashboard/src/event-model.ts `TllmCallShape` field-for-field (§4.2c).
 */
export interface TllmCallShape {
  /** Number of entries in the request's `tools` array (0 when absent). */
  toolCount: number;
  /** The request's `max_tokens`, if present (the quota probe sends 1). */
  maxTokens: number | null;
  /** Count of user-role messages (a stateless one-shot side call has 1). */
  userMessages: number;
}

/** Kind-specific detail for a `path_rewrite` event: one ViewMap application on
 *  the model wire (fs-sync.md §1.3 P2). Both spellings are carried so the
 *  dashboard can render the translation without string-scraping:
 *    - `human` — the HumanView spelling (what T-LLM speaks on the model wire).
 *    - `agent` — the AgentView spelling (what the agent process executes on).
 *  `direction` says which way this application ran: "forward" = model→agent
 *  (response tool_use args, human→agent), "reverse" = agent→model (request
 *  tool_result content / echoed tool_use args, agent→human). Mirrors
 *  dashboard/src/event-model.ts `PathRewriteDetail` field-for-field. */
export interface PathRewriteDetail {
  direction: "forward" | "reverse";
  tool: string | null;
  /** The rewritten typed field (file_path/path/…), "command" for Bash text,
   *  "content" for tool_result free text, or "text" for conversation free
   *  text (the latter two are roots-level reports). */
  field: string | null;
  human: string;
  agent: string;
}

/** The canonical event (§2.4). The arbiter stamps `seq`; everything else is set
 *  here. `id` is a sortable-ish unique id; we generate one without a ULID dep. */
export interface ManduEvent {
  id: string;
  sessionId: string;
  turn: number;
  ts: string;
  /** Set by the arbiter's emit reply; the proxy leaves it 0 (arbiter is the
   *  authority for the monotonic per-session counter). */
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
  model?: EventModelMeta;
  /** Complete, untruncated input to a model call (tllm_call/ullm_call), each
   *  block tagged by source. Optional — only the model-call emitters set it. */
  fullInput?: FullInput;
  /** Batch id shared by sessions run together, so the dashboard sidebar can group
   *  them. Set from the `x-mandu-batch-id` request header (like sessionId rides
   *  `x-mandu-session-id`). Absent for un-batched traffic. */
  batchId?: string;
  /** Tenant stamp (policy-surface.md §2.7): "live" or "test". From the
   *  `x-mandu-tenant` header (packed like the batch id) or MANDU_TENANT on
   *  this process; absent for pre-tenancy launchers. */
  tenant?: "live" | "test";
  /** Kind-specific detail, present only on kind "path_rewrite". */
  rewrite?: PathRewriteDetail;
  /** Structural request shape, present only on kind "tllm_call" — the
   *  dashboard's side-call detection seam (dashboard.md §4.2c). */
  callShape?: TllmCallShape;
}

// ── Builders ──────────────────────────────────────────────────────────────────

/**
 * Construct a DualRepr, computing `differs` from the values so it can never
 * drift out of sync with them (§2.5). Mirrors dashboard `makeDualRepr`.
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

/** Monotonic-ish unique id without a ULID dependency: time prefix + counter +
 *  random suffix. Sorts roughly by emit time within a process. */
let _idCounter = 0;
export function newEventId(): string {
  const t = Date.now().toString(36).padStart(9, "0");
  const c = (_idCounter++ & 0xffffff).toString(36).padStart(5, "0");
  const r = Math.floor(Math.random() * 0xffffff).toString(36).padStart(5, "0");
  return `ev_${t}${c}${r}`;
}

/** Fields every event shares for one /v1/messages exchange. */
export interface EventContext {
  sessionId: string;
  turn: number;
  /** Batch id for "run together" grouping in the dashboard sidebar (from the
   *  `x-mandu-batch-id` header). Stamped onto every event built from this ctx. */
  batchId?: string;
  /** Tenant stamp for every event built from this ctx (§2.7). */
  tenant?: "live" | "test";
}

function baseEvent(
  ctx: EventContext,
  kind: EventKind,
  extra: Partial<ManduEvent> = {},
): ManduEvent {
  return {
    id: newEventId(),
    sessionId: ctx.sessionId,
    turn: ctx.turn,
    ts: new Date().toISOString(),
    seq: 0,
    callId: null,
    parentId: null,
    kind,
    view: "AgentView",
    boundary: "model_context",
    emitter: "anthropic-proxy",
    input: null,
    output: null,
    invariant: { violatedInvariant: false },
    ...(ctx.batchId ? { batchId: ctx.batchId } : {}),
    ...(ctx.tenant ? { tenant: ctx.tenant } : {}),
    ...extra,
  };
}

// ── The §9 oracle predicate (shared with the e2e oracle's intent) ─────────────

/**
 * Strip every symbol token (`$MDU:*`) from `text`. What remains is the
 * NON-symbol surface. Used by `survivingUntrusted` to decide whether any raw
 * untrusted bytes survived symbolization in the forwarded prompt.
 */
function stripSymbols(text: string): string {
  const pat = getSymbolPattern();
  pat.lastIndex = 0;
  return text.replace(pat, "");
}

/**
 * The §9 oracle predicate, reusable: given the forwarded (symbolized) prompt
 * surface and the set of raw untrusted values that were SUPPOSED to be
 * symbolized away, return the FIRST surviving raw fragment (or null if clean).
 *
 * "Clean" = no raw untrusted value appears verbatim in the forwarded text once
 * the symbol tokens themselves are removed (so a symbol whose hash happens to be
 * a substring of nothing real does not false-positive). This is exactly the
 * invariant the e2e oracle asserts: the attack payload reaches the model request
 * ONLY as a symbol, never verbatim.
 */
export function survivingUntrusted(
  forwardedSymbolizedText: string,
  rawUntrustedValues: string[],
): string | null {
  if (rawUntrustedValues.length === 0) return null;
  const surface = stripSymbols(forwardedSymbolizedText);
  for (const raw of rawUntrustedValues) {
    // A blank value carries no data; whitespace "surviving" is not a leak.
    if (raw.trim() === "") continue;
    if (surface.includes(raw)) return raw;
  }
  return null;
}

/**
 * The shortest raw value (trimmed) the oracle still looks for OUTSIDE the
 * result's own forwarded block. Below it a verbatim match elsewhere in the
 * request is coincidence, not survival: the live i19 drill flagged six calls
 * because a `wc -l` result of "9" also occurs in `ws-i19-opus`, a path in a
 * trusted Write confirmation (2026-09-26).
 */
export const DISTINCTIVE_RAW_CHARS = 8;

/**
 * The §9 oracle for ONE symbolized result, scoped two ways (2026-09-26):
 *   - its OWN forwarded block (the symbol, plus the trusted body or header in
 *     a split result; the proxy-authored notes removed) must carry none of its
 *     raw spans, at any length: that block is exactly where survival happens;
 *   - the rest of the ${word} is searched only for DISTINCTIVE spans (at least
 *     `DISTINCTIVE_RAW_CHARS` after trimming), which still catches the same
 *     untrusted bytes reaching the model through another result.
 * `crossSpans` (default: `rawSpans`) narrows what the second scope looks for:
 * the proxy leaves out a dropped harness token-budget reminder, which the
 * harness appends verbatim to every result of a turn (rewrite-request.ts
 * crossResultSpans, 2026-09-29).
 * Returns the first surviving span, or null when clean.
 */
export function survivingResult(
  ownForwarded: string,
  haystack: string,
  rawSpans: readonly string[],
  crossSpans: readonly string[] = rawSpans,
): string | null {
  return survivingUntrusted(ownForwarded, [...rawSpans])
    ?? survivingUntrusted(haystack, crossSpans.filter((r) => r.trim().length >= DISTINCTIVE_RAW_CHARS));
}

// ── Event constructors used by the proxy ──────────────────────────────────────

/** A symbol referenced by an emitted event, with the provenance the proxy has. */
export function symbolRef(
  name: string,
  tool: string,
  value: string | null,
  origin: string | null,
  field: string | null = null,
  /** Confidentiality level (confidentiality.md §2). Only a SECRET level is
   *  carried — "public" is the absence of a claim. */
  confidentiality?: string,
): SymbolRef {
  const ref: SymbolRef = { name, tool, field, origin, value };
  if (confidentiality && confidentiality !== "public") ref.confidentiality = confidentiality;
  return ref;
}

export interface TllmCallArgs {
  ctx: EventContext;
  model: string;
  /** Symbolized prompt summary T-LLM saw. */
  inputSymbolized: string;
  /** The original (pre-symbolization) prompt summary, if known; else null. */
  inputOriginal: string | null;
  /** Symbols referenced in the forwarded prompt. */
  inputSymbols: SymbolRef[];
  /** Assistant text + tool_use names parsed from the response. */
  outputText: string;
  /** Did any un-symbolized untrusted span survive? (oracle predicate result) */
  violatedInvariant: boolean;
  invariantDetail?: string;
  /** The COMPLETE, untruncated structured input (each block source-tagged) so
   *  the dashboard can reveal the full prompt + highlight the mandu injection.
   *  Additive: the capped `inputSymbolized` stays the default inline summary. */
  fullInput?: FullInput;
  /** Structural shape of the forwarded request (tools/max_tokens/user turns) —
   *  the dashboard's side-call detection seam (dashboard.md §4.2c). */
  callShape?: TllmCallShape;
  /** The response's id (`msg_…`, `chatcmpl-…`, `resp_…`), when it carried a well-formed one. */
  responseId?: string;
  /** The agent's session id the request carried ({@link agentSessionIdOf}). */
  agentSessionId?: string;
}

export function makeTllmCall(a: TllmCallArgs): ManduEvent {
  const inv: EventInvariant = a.invariantDetail
    ? { violatedInvariant: a.violatedInvariant, detail: a.invariantDetail }
    : { violatedInvariant: a.violatedInvariant };
  return baseEvent(a.ctx, "tllm_call", {
    input: makeDualRepr(a.inputSymbolized, a.inputOriginal, a.inputSymbols),
    output: makeDualRepr(a.outputText, null, []),
    model: {
      id: a.model,
      ...(responseIdOf(a.responseId) ? { responseId: a.responseId! } : {}),
      ...(a.agentSessionId !== undefined && AGENT_SESSION_ID_RE.test(a.agentSessionId) ? { agentSessionId: a.agentSessionId } : {}),
    },
    invariant: inv,
    ...(a.fullInput ? { fullInput: a.fullInput } : {}),
    ...(a.callShape ? { callShape: a.callShape } : {}),
  });
}

export interface ToolResultEventArgs {
  ctx: EventContext;
  callId: string;
  tool: string;
  /** Raw (untrusted) content the tool produced. */
  original: string;
  /** What T-LLM saw: the symbol token when symbolized, else the original. */
  symbolized: string;
  /** Symbols allocated for this result (folded in). */
  symbols: SymbolRef[];
  trust: "TRUSTED" | "UNTRUSTED";
  reason?: string;
  /** Confidentiality level (confidentiality.md §2). A TRUSTED trust WITH a
   *  secret level is the normal shape for a credential file. */
  confidentiality?: string;
  /** Did THIS result leak an un-symbolized untrusted span into the forwarded
   *  prompt? (computed by the proxy with the oracle predicate.) */
  violatedInvariant: boolean;
  /** The `[mandu:twin]` note appended to this result (symbol-twin-shell-
   *  blindness.md §4.6): which paths were symbolic twins and how many tokens
   *  the note carried. No content. Absent when no note was appended. */
  twinNote?: { paths: string[]; tokens: number };
  /** Plan 10 §4.2: the process-tree taint behind a Bash result (files and
   *  programs by name, the rule, whether the whole result was masked, the
   *  opens refused). No content. */
  secretTaint?: { level: string; files: string[]; apps: string[]; rule: string; maskWhole: boolean; denied: Array<{ path: string; app: string; reason: string }> };
  /** The `[mandu:secret]` note appended to the result (§11.8). */
  secretNote?: string;
}

export function makeToolResult(a: ToolResultEventArgs): ManduEvent {
  const policy: EventPolicy = { trust: a.trust };
  if (a.reason !== undefined) policy.reason = a.reason;
  if (a.confidentiality && a.confidentiality !== "public") {
    policy.confidentiality = a.confidentiality;
  }
  const ev = baseEvent(a.ctx, "tool_result", {
    callId: a.callId,
    // The tool result re-enters context: its "output" is what landed in T-LLM's
    // input, carried in both representations.
    output: makeDualRepr(a.symbolized, a.original, a.symbols),
    policy,
    invariant: { violatedInvariant: a.violatedInvariant },
  });
  const extra: Record<string, unknown> = {};
  if (a.twinNote) extra["twinNote"] = a.twinNote;
  if (a.secretTaint) extra["secretTaint"] = a.secretTaint;
  if (a.secretNote) extra["secretNote"] = a.secretNote;
  return Object.keys(extra).length > 0 ? Object.assign(ev, extra) : ev;
}

export interface SymbolizeEventArgs {
  ctx: EventContext;
  callId: string;
  tool: string;
  symbol: string;
  /** Raw untrusted value behind the symbol. */
  original: string;
  origin: string | null;
  /** Confidentiality level the classify verdict carried (confidentiality.md
   *  §2). Present only for a secret-labeled datum. */
  confidentiality?: string;
}

export function makeSymbolize(a: SymbolizeEventArgs): ManduEvent {
  const ref = symbolRef(a.symbol, a.tool, a.original, a.origin, null, a.confidentiality);
  return baseEvent(a.ctx, "symbolize", {
    callId: a.callId,
    // input = the raw value; output = the symbol it became. The model never
    // saw the raw value, so the input's AgentView form is the symbol too and
    // the value sits only in `original`: the dashboard's signed-out
    // projection keeps every `symbolized` (dashboard.md §6).
    input: makeDualRepr(a.symbol, a.original, []),
    output: makeDualRepr(a.symbol, a.original, [ref]),
    invariant: { violatedInvariant: false },
  });
}

export interface ToolUseEventArgs {
  ctx: EventContext;
  callId: string;
  name: string;
  input: unknown;
}

export interface FsGateEventArgs {
  ctx: EventContext;
  /** The tool_use id whose path was gated. */
  callId: string;
  tool: string;
  field: string;
  /** The out-of-workspace path the model asked for. */
  path: string;
  /** The `/mandu/denied/…` sentinel the field was rewritten to. */
  sentinel: string;
  /** The policy (or unreachable) reason. */
  reason: string;
  /** True when the arbiter verdict said a human can approve a retry. */
  requiresApproval: boolean;
  /** Decision provenance (policy-surface.md §9.3). */
  ruleRef?: { source: "rule" | "verdict" | "fail-closed"; id: string };
  /** The approval-queue row this deny created/bumped (`egr-<n>`) — the
   * Pending-tab join (policy-surface.md §9.5). */
  approvalId?: string;
}

/** The P3 sensitive-path gate denying a tool_use path field (fs-sync.md §1
 * §4.1): an `fs_action` on the filesystem boundary. `input` carries the asked
 * path, `output` the sentinel actually delivered to the agent. */
export function makeFsGate(a: FsGateEventArgs): ManduEvent {
  return baseEvent(a.ctx, "fs_action", {
    callId: a.callId,
    boundary: "filesystem",
    input: makeDualRepr(`${a.tool}.${a.field} → ${a.path}`, null, []),
    output: makeDualRepr(`DENIED → ${a.sentinel}`, null, []),
    policy: {
      usage: a.requiresApproval ? "needs_approval" : "deny",
      reason: a.reason,
      ...(a.ruleRef ? { ruleRef: a.ruleRef } : {}),
      ...(a.approvalId ? { approvalId: a.approvalId } : {}),
    },
    invariant: { violatedInvariant: false },
  });
}

export interface FsLabelEventArgs {
  ctx: EventContext;
  /** The tool_use id whose write was labeled. */
  callId: string;
  tool: string;
  field: string;
  /** The HumanView path being written. */
  path: string;
  /** The level a FUTURE session will now classify that path at. */
  level: string;
  reason: string;
  /** Set only when the write was DENIED (arbiter unreachable ⇒ fail closed). */
  sentinel?: string;
}

/**
 * The DERIVED ON-DISK LABEL (Plan 9, §4/§8) — an `fs_action` on the filesystem
 * boundary. This is the event that shows a human the watermark OUTLIVING the
 * session: a high session wrote a file, and the file now carries the level, so
 * the NEXT session cannot read it back as public. On a fail-closed deny (the
 * arbiter could not be reached, so the label could not be recorded) it carries
 * the sentinel instead — an unlabeled write from a possibly-high session is the
 * hole, so we do not make it.
 */
export function makeFsLabel(a: FsLabelEventArgs): ManduEvent {
  const denied = a.sentinel !== undefined;
  return baseEvent(a.ctx, "fs_action", {
    callId: a.callId,
    boundary: "filesystem",
    input: makeDualRepr(`${a.tool}.${a.field} → ${a.path}`, null, []),
    output: makeDualRepr(
      denied ? `DENIED (unlabelable) → ${a.sentinel}` : `LABELED ${a.level} on disk`,
      null,
      [],
    ),
    policy: {
      usage: denied ? "deny" : "allow",
      reason: a.reason,
      ...(denied ? {} : { confidentiality: a.level }),
    },
    invariant: { violatedInvariant: false },
  });
}

export interface ExecGateEventArgs {
  ctx: EventContext;
  /** The tool_use id whose command was gated. */
  callId: string;
  tool: string;
  field: string;
  /** allow | block. */
  decision: "allow" | "block";
  /** The policy (or unreachable) reason. */
  reason: string;
  /** Symbols implicated in a command-position block (empty on allow). */
  symbols: string[];
  /** Non-blocking evasion signals recorded for Phase 1 routing + the UI. */
  evasion: { kind: string; evidence: string }[];
  /** The shell the command WOULD route to (informational). */
  shell: string;
  /** The `exit 77` sentinel the command was rewritten to (block only). */
  sentinel?: string;
  /** Decision provenance (policy-surface.md §9.3). */
  ruleRef?: { source: "rule" | "verdict" | "fail-closed"; id: string };
  /** The approval-queue entry a PROVENANCE block is waiting on
   * (exec-routing.md §8.7a) — same field as the fs / net gate events. */
  approvalId?: string;
  /** The net-fetched program text the provenance gate decided on. */
  programText?: { path: string; originHost: string };
}

/** The Phase-0 exec gate (exec-routing.md §3): an `exec_action` on the shell
 * boundary. On block, `output` carries the failing sentinel the agent runs
 * instead; on allow, it records the classification (evasion signals + shell).
 * A provenance decision (§7a) names the program text + its origin host in the
 * input summary and carries the pending approval id in `policy`. */
export function makeExecGate(a: ExecGateEventArgs): ManduEvent {
  const evasion = a.evasion.map((e) => `${e.kind}:${e.evidence}`).join(", ");
  const program = a.programText ? ` [program text: ${a.programText.path} ← ${a.programText.originHost}]` : "";
  const inSummary = `${a.tool}.${a.field}${evasion ? ` [evasion: ${evasion}]` : ""}${program}`;
  const outSummary =
    a.decision === "block" ? `BLOCKED → ${a.sentinel ?? "exit 77"}` : `ALLOW (${a.shell})`;
  return baseEvent(a.ctx, "exec_action", {
    callId: a.callId,
    boundary: "shell",
    // The implicated symbols ride as structured refs (symbol-lineage.md §3.2
    // `gated` edge) — mined from their own names, so no raw bytes.
    input: makeDualRepr(inSummary, null, minedSymbolRefs(a.symbols.join(" "))),
    output: makeDualRepr(outSummary, null, []),
    policy: {
      usage: a.decision === "block" ? "deny" : "allow",
      reason: a.reason,
      shell: a.shell === "HumanShell" ? "HumanShell" : "AgentShell",
      ...(a.ruleRef ? { ruleRef: a.ruleRef } : {}),
      ...(a.approvalId ? { approvalId: a.approvalId } : {}),
    },
    invariant: { violatedInvariant: false },
  });
}

export interface NetGateEventArgs {
  ctx: EventContext;
  callId: string | null;
  tool: string;
  /** The destination the model asked for, or null when the tool names none. */
  destination: string | null;
  decision: "allow" | "block";
  reason: string;
  sentinel?: string;
  /** Decision provenance (policy-surface.md §9.3). */
  ruleRef?: { source: "rule" | "verdict" | "fail-closed"; id: string };
  /** The Approvals row the refusal filed or bumped (`egr-<n>`): the session
   *  page's "Mandu asked for your OK in Approvals" link (dashboard.md §4.34). */
  approvalId?: string;
}

/**
 * The HIGH-SESSION network gate (Plan 8, §4) — a `net_action` on the model-API
 * boundary. This is the event that shows a human the thing the per-symbol egress
 * gate could never see: a network tool_use blocked with NO SYMBOL in it, because
 * the SESSION has read secret content into context and anything the model emits
 * may now be derived from it.
 */
export function makeNetGate(a: NetGateEventArgs): ManduEvent {
  const dest = a.destination ?? "(no destination named)";
  const outSummary = a.decision === "block"
    ? `BLOCKED → ${a.sentinel ?? "denied"}`
    : `ALLOW (${dest})`;
  return baseEvent(a.ctx, "net_action", {
    callId: a.callId,
    boundary: "network",
    input: makeDualRepr(`${a.tool} → ${dest}`, null, []),
    output: makeDualRepr(outSummary, null, []),
    policy: {
      usage: a.decision === "block" ? "deny" : "allow",
      reason: a.reason,
      ...(a.ruleRef ? { ruleRef: a.ruleRef } : {}),
      ...(a.decision === "block" && a.approvalId ? { approvalId: a.approvalId } : {}),
    },
    invariant: { violatedInvariant: false },
  });
}

export interface PathRewriteEventArgs {
  ctx: EventContext;
  /** The tool_use id the rewritten span belongs to (null for uncorrelated text). */
  callId: string | null;
  tool: string | null;
  /** Rewritten field name; "command" (Bash text) / "content" (tool_result text). */
  field: string | null;
  direction: "forward" | "reverse";
  /** HumanView spelling — what T-LLM speaks on the model wire. */
  human: string;
  /** AgentView spelling — what the agent process executes on. */
  agent: string;
}

/** The P2 ViewMap applying one HumanView↔AgentView path translation on the
 * model wire (fs-sync.md §1.3). Observability only — the rewrite already
 * happened; this records WHEN and HOW so the dashboard's translation lane can
 * show it. `input` carries the spelling that arrived, `output` the spelling
 * that left, and `rewrite` the structured detail (both spellings + direction). */
export function makePathRewrite(a: PathRewriteEventArgs): ManduEvent {
  const where = a.tool ? `${a.tool}${a.field ? "." + a.field : ""}` : a.field ?? "text";
  const [from, to] = a.direction === "forward" ? [a.human, a.agent] : [a.agent, a.human];
  return baseEvent(a.ctx, "path_rewrite", {
    callId: a.callId,
    input: makeDualRepr(`${where}: ${from}`, null, []),
    output: makeDualRepr(`${where}: ${to}`, null, []),
    policy: {
      reason:
        a.direction === "forward"
          ? "view-map forward (model→agent): HumanView → AgentView spelling"
          : "view-map reverse (agent→model): AgentView → HumanView spelling",
    },
    invariant: { violatedInvariant: false },
    rewrite: {
      direction: a.direction,
      tool: a.tool,
      field: a.field,
      human: a.human,
      agent: a.agent,
    },
  });
}

/**
 * Mine the symbol tokens the model ECHOED into text (the `echoed` lineage
 * edge, symbol-lineage.md §3.2/G3) into structured refs, so event readers
 * need no regex twin. Provenance is only what the TOKEN itself carries — the
 * short tool tag and the field path; origin/value stay null (the proxy does
 * not resolve symbols here, and a mined ref must never carry raw bytes).
 */
export function minedSymbolRefs(text: string): SymbolRef[] {
  const pat = getSymbolPattern();
  pat.lastIndex = 0;
  const seen = new Set<string>();
  const refs: SymbolRef[] = [];
  for (const m of text.matchAll(pat)) {
    const name = m[0];
    if (seen.has(name)) continue;
    seen.add(name);
    const tag = name.slice(name.indexOf(":") + 1, name.indexOf("["));
    const close = name.indexOf("]");
    const field = name[close + 1] === "." ? name.slice(close + 2) : null;
    refs.push({ name, tool: tag, field, origin: null, value: null });
  }
  return refs;
}

export function makeToolUse(a: ToolUseEventArgs): ManduEvent {
  let inputStr: string;
  try {
    inputStr = JSON.stringify(a.input ?? {});
  } catch {
    inputStr = String(a.input);
  }
  // A tool_use decision is made BY T-LLM over a symbolized context, so its
  // symbolized and original surfaces are the same (no desymbolization here).
  return baseEvent(a.ctx, "tool_use", {
    callId: a.callId,
    input: makeDualRepr(`${a.name}(${inputStr})`, null, minedSymbolRefs(inputStr)),
    invariant: { violatedInvariant: false },
  });
}

// ── Session-health events (dashboard.md §4.21) ───────────────────────────────

/** `client_info`: the agent CLI as it identified itself on its FIRST request
 *  (user-agent → "which Claude Code is this"). Once per session. */
export function makeClientInfo(ctx: EventContext, a: { userAgent: string; clientVersion: string | null; model: string | null }): ManduEvent {
  const ev = baseEvent(ctx, "client_info", {
    view: "HumanView",
    input: {
      symbolized: `agent client: ${a.clientVersion ? `claude-code ${a.clientVersion}` : a.userAgent || "(no user-agent)"}` + (a.model ? ` · model ${a.model}` : ""),
      original: null, differs: false, symbols: [],
    },
  });
  return Object.assign(ev, { userAgent: a.userAgent, clientVersion: a.clientVersion, ...(a.model ? { clientModel: a.model } : {}) });
}

/** `tool_surface`: the tool battery the agent advertised on its first request
 *  and which names the arbiter's active inbound spec does NOT know — their
 *  outputs fail closed (symbolized whole), a utility loss worth a chip. */
export function makeToolSurface(ctx: EventContext, a: { names: string[]; unknown: string[] }): ManduEvent {
  const ev = baseEvent(ctx, "tool_surface", {
    view: "HumanView",
    input: {
      symbolized: `${a.names.length} tool(s) advertised` +
        (a.unknown.length ? ` · ${a.unknown.length} UNKNOWN to the inbound spec: ${a.unknown.join(", ")}` : " · all known to the inbound spec"),
      original: null, differs: false, symbols: [],
    },
  });
  return Object.assign(ev, { names: a.names, unknown: a.unknown });
}

// ── Reply row reservation (reply-row-reservation.md) ─────────────────────────

/** `reserve_residual`: the request-side strip removed reserve-block fragments
 *  a well-formed collapse did not account for (a client-edited turn, a tool
 *  that read the agent's transcript). Carries counts and locations only. */
export function makeReserveResidual(
  ctx: EventContext,
  a: { removed: number; where: string[]; route: "messages" | "count_tokens" },
): ManduEvent {
  const ev = baseEvent(ctx, "reserve_residual", {
    input: {
      symbolized: `reply reserve: stripped ${a.removed} leftover row marker(s) before the model` +
        (a.where.length ? ` (${a.where.join(", ")})` : ""),
      original: null, differs: false, symbols: [],
    },
  });
  return Object.assign(ev, { removed: a.removed, where: a.where, route: a.route });
}

/** `reserve_expand`: a token went to the agent as an N-row reserve block
 *  (v1: alone on its line; v2, reply-row-reservation.md §11.3: at content
 *  width W with a head row F wide, possibly inside a line). The token is
 *  opaque; no value is known here, only the counts. */
export function makeReserveExpand(
  ctx: EventContext,
  a: { hash: string; rows: number; token: string; width?: number; first?: number },
): ManduEvent {
  const v2 = typeof a.width === "number" && typeof a.first === "number";
  const ev = baseEvent(ctx, "reserve_expand", {
    view: "HumanView",
    input: {
      symbolized: `reply reserve: ${a.token} reserved ${a.rows} rows` +
        (v2 ? ` (width ${a.width}, first row ${a.first})` : ""),
      original: null, differs: false, symbols: [],
    },
  });
  return Object.assign(ev, { hash: a.hash, rows: a.rows }, v2 ? { head: "v2", W: a.width, F: a.first } : { head: "v1" });
}

/** The detail of a `prompt_filter` event (confidentiality-plan-15 §8): which
 *  segment, who wrote it, what the filters found and did. Offsets, categories
 *  and symbols only; never the value, never the segment's text. Mirrored in
 *  dashboard/src/event-model.ts `PromptFilterDetail` and the openai-proxy. */
export interface PromptFilterDetail {
  agent: string;
  segmentId: string;
  origin: "human" | "harness" | "side-call";
  /** `block`: the request was refused (plan 15 §7); a blocked segment
   *  forwarded later with its safe text is `rewrite`. */
  action: "pass" | "rewrite" | "block";
  findings: Array<{
    filterId: string; category: string; action: string; symbol?: string; how?: string; start: number; end: number;
    /** Phase 3 (§7): the span's opaque reference (a "let it through" names it). */
    ref?: string;
    /** Phase 3: a human verdict let the span through as written. */
    let?: "once" | "session";
    /** Phase 3: an `ask` finding's hold (`sent`, `masked`, `cancelled`,
     *  `timed-out`, `default`). */
    hold?: { state: string; approvalId?: string };
    /** The arbiter's word (plan 15 §12, 2026-10-04): a locked administrator's
     *  `ask` row covers the category, so a "let it through" or an answer
     *  covers this message only. */
    onceOnly?: true;
  }>;
  /** Phase 3: the message's opaque reference (a "let it through, once"). */
  turn?: string;
  /** Registered values the prompt floor let through (counted, never named). */
  skipped: number;
  /** False with the confidentiality axis OFF: the findings were logged only. */
  enforcing: boolean;
  digest: { policy: string; packs: string };
}

/** One sentence for the event's input pane, with the symbols (which the
 *  dashboard resolves on demand, as it does for the transcript). */
export function promptFilterSummary(d: PromptFilterDetail): string {
  const where = d.origin === "human" ? "the human's prompt" : d.origin === "side-call" ? "a side call's text" : "text the agent's harness added";
  // A span let through (or an ask, below) went as the human chose: not "hidden".
  const of = (action: string): PromptFilterDetail["findings"] => d.findings.filter((f) => f.action === action && (f.let === undefined || action === "ask"));
  const what = (fs: Array<{ category: string }>): string =>
    fs.every((f) => f.category === "secret.registered") ? "registered value(s)" : `finding(s) (${[...new Set(fs.map((f) => f.category))].join(", ")})`;
  const masked = of("mask");
  const redacted = of("redact");
  const blocked = of("block");
  const logged = of("log");
  const parts: string[] = [];
  if (masked.length) parts.push(`${masked.length} ${what(masked)} in ${where} hidden from the model as ${[...new Set(masked.map((f) => f.symbol ?? "?"))].join(", ")}`);
  if (redacted.length) parts.push(`${redacted.length} ${what(redacted)} in ${where} redacted (the model reads [redacted: <category>])`);
  if (blocked.length) {
    parts.push(d.action === "block"
      ? `${blocked.length} ${what(blocked)} in ${where} blocked: the request was refused and nothing was sent`
      : `${blocked.length} ${what(blocked)} in ${where} blocked earlier: sent as [blocked: <category>]`);
  }
  if (logged.length) parts.push(`${logged.length} ${what(logged)} in ${where} logged only${d.enforcing ? "" : " (the confidentiality axis is off)"}`);
  // Plan 15 §7 (phase 3): an ask's outcome, and spans the human let through.
  const asked = of("ask");
  const how = (st: string | undefined): string =>
    st === "sent" ? "sent as written (your answer)" : st === "masked" ? "sent masked (your answer)" : st === "cancelled" ? "cancelled by you: nothing was sent"
      : st === "timed-out" ? "sent masked (no answer in time)" : "sent masked (not asked)";
  for (const st of [...new Set(asked.map((f) => f.hold?.state))]) {
    const n = asked.filter((f) => f.hold?.state === st);
    parts.push(`${n.length} ${what(n)} in ${where} held for your answer: ${how(st)}`);
  }
  const let_ = d.findings.filter((f) => f.let !== undefined && f.action !== "ask");
  if (let_.length) parts.push(`${let_.length} ${what(let_)} in ${where} let through as written (your answer)`);
  if (d.skipped) parts.push(`${d.skipped} registered value(s) in ${where} left as typed (too short or too simple to mask in a prompt)`);
  return `prompt filter: ${parts.join("; ") || "nothing found"}`;
}

/** `prompt_filter`: what the prompt filter did to one segment. */
export function makePromptFilter(ctx: EventContext, d: PromptFilterDetail): ManduEvent {
  const text = promptFilterSummary(d);
  const ev = baseEvent(ctx, "prompt_filter", {
    input: { symbolized: text, original: null, differs: false, symbols: minedSymbolRefs(text) },
  });
  return Object.assign(ev, { promptFilter: d });
}
