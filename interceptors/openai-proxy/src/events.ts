/**
 * events — the Track A observability-event builder for the OpenAI (Responses-API)
 * proxy (best-effort, off the security path).
 *
 * Mandu Track A (interceptors/openai-proxy). The proxy enforces the AgentView
 * context boundary (classify + symbolize untrusted function_call_output spans,
 * inject the handling prompt). This module lets it ALSO EMIT the canonical
 * `ManduEvent` records (docs/design/ui/dashboard.md §2) so the dashboard can render
 * the dual-view trace for Codex sessions too — closing the gap where the Codex
 * path was previously invisible to the dashboard.
 *
 * IMPORTANT design constraints (mirror anthropic-proxy/src/events.ts):
 *   - This is a LOCAL builder. We deliberately do NOT import the dashboard
 *     package (`dashboard/src/event-model.ts`) — the proxy stays dependency-free
 *     of the dashboard. The interfaces below mirror that schema field-for-field
 *     so the arbiter→dashboard seam stays compatible. If the dashboard schema
 *     drifts, this mirror is the single place to reconcile.
 *   - Emission is BEST-EFFORT and OFF THE SECURITY PATH. The proxy fires events
 *     via `arbiter.emit(...)` wrapped so a failed/slow emit can never block or
 *     fail the request (see the proxy's `safeEmit`). Events carry the ORIGINAL
 *     (raw, untrusted) bytes in `DualRepr.original`, which go ONLY to the arbiter's
 *     privileged event log / dashboard — they are NEVER fed back upstream toward
 *     T-LLM. The proxy never reads anything back from an emit.
 *
 * Responses-API specifics: symbolization is request-side only (the P4 view map
 * at most path-rewrites the stream in flight). The `tllm_call` carries the
 * `▸ role` transcript of the forwarded (symbolized) request as its input and
 * the model's answer, read passively off the relayed body, as its output
 * (transcript.ts, 2026-09-26; before, the input was the raw body capped at
 * 4 KB and the output was always empty). The §9 invariant oracle predicate
 * (`survivingResult`) is computed over the forwarded tool outputs, so the
 * dashboard's invariant banner is stamped from the same predicate the
 * live/e2e oracles assert.
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
  | "fs_action"
  | "net_action"
  | "exec_action"
  // Reply row reservation (reply-row-reservation.md §3.4, §3.5, §11.7), as
  // the anthropic-proxy emits them; the dashboard renders an unknown kind
  // generically.
  | "reserve_residual" | "reserve_expand"
  // The prompt filter (confidentiality-plan-15 §8): one per segment with a
  // finding or a value the prompt floor let through. Never the value.
  | "prompt_filter";

export type Boundary = "model_context" | "network" | "filesystem" | "shell";

/**
 * "openai-proxy" is this package's emitter (the Codex Track A interceptor); the
 * dashboard's canonical `Emitter` enum (dashboard/src/event-model.ts) includes it
 * and derives the per-session claude/codex agent badge from it — keep the value
 * in sync. The arbiter treats events as opaque JSON either way.
 */
export type Emitter =
  | "openai-proxy"
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
  /** The OTHER half of the 2×3 label (confidentiality.md §2). A TRUSTED trust
   *  WITH a secret level is the normal shape for a credential file. */
  confidentiality?: string;
  /** Decision provenance (policy-surface.md §9.3), as the anthropic-proxy's. */
  ruleRef?: { source: "rule" | "verdict" | "fail-closed"; id: string };
  /** The approval-queue row a deny created (`egr-<n>`), the Pending-tab join. */
  approvalId?: string;
}

export interface EventInvariant {
  violatedInvariant: boolean;
  detail?: string;
}

export interface EventModelMeta {
  id: string;
  inputTokens?: number;
  outputTokens?: number;
  /** The provider's id for this response (the Responses API's `resp_…`, as
   *  Codex's rollout keeps it in `token_usage_record.response_id`; Chat
   *  Completions' `chatcmpl-…` as the agent was sent it, response-id.ts):
   *  `mandu scan` joins on it to tell a past session under Mandu exactly
   *  (confidentiality-plan-17 §3 item 6). Only on a tllm_call whose
   *  response carried one. */
  responseId?: string;
}

/** A provider's response id as an event keeps it: a short run of id
 *  characters (`resp_…`, `chatcmpl-…`), else nothing. Nothing else from the
 *  response is taken. Pure. Copied from the Anthropic proxy's. */
export function responseIdOf(v: unknown): string | undefined {
  return typeof v === "string" && /^[A-Za-z0-9_-]{8,128}$/.test(v) ? v : undefined;
}

/**
 * Structural request metadata on a `tllm_call` — what the proxy KNOWS about the
 * call it forwarded, so the dashboard can separate the agent CONVERSATION loop
 * (always carries the agent's tool battery) from harness side calls (which send
 * zero tools) STRUCTURALLY instead of by string heuristics over prompt text.
 * Mirrors dashboard/src/event-model.ts `TllmCallShape` field-for-field (§4.2c).
 */
export interface TllmCallShape {
  /** Number of entries in the request's `tools` array (0 when absent). */
  toolCount: number;
  /** The request's max-token budget, if present (Responses API:
   *  `max_output_tokens`); null when absent or non-numeric. */
  maxTokens: number | null;
  /** Count of user-role messages (a stateless one-shot side call has 1). */
  userMessages: number;
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

/** Fields every event shares for one /v1/responses exchange. */
export interface EventContext {
  sessionId: string;
  turn: number;
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
    emitter: "openai-proxy",
    input: null,
    output: null,
    invariant: { violatedInvariant: false },
    ...extra,
  };
}

// ── The §9 oracle predicate (shared with the e2e oracle's intent) ─────────────

/**
 * Strip every symbol token (`$MDU:*`) from `text`. What remains is the
 * NON-symbol surface. Used by `survivingUntrusted` to decide whether any raw
 * untrusted bytes survived symbolization in the forwarded request.
 */
function stripSymbols(text: string): string {
  const pat = getSymbolPattern();
  pat.lastIndex = 0;
  return text.replace(pat, "");
}

/**
 * The §9 oracle predicate, reusable: given the forwarded (symbolized) request
 * surface and the set of raw untrusted values that were SUPPOSED to be
 * symbolized away, return the FIRST surviving raw fragment (or null if clean).
 *
 * "Clean" = no raw untrusted value appears verbatim in the forwarded text once
 * the symbol tokens themselves are removed. This is exactly the invariant the
 * live/e2e oracles assert: the attack payload reaches the model request ONLY as a
 * symbol, never verbatim.
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
 * Returns the first surviving span, or null when clean.
 */
export function survivingResult(
  ownForwarded: string,
  haystack: string,
  rawSpans: readonly string[],
): string | null {
  return survivingUntrusted(ownForwarded, [...rawSpans])
    ?? survivingUntrusted(haystack, rawSpans.filter((r) => r.trim().length >= DISTINCTIVE_RAW_CHARS));
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
  /** The `▸ role` transcript of the forwarded (symbolized) request. */
  inputSymbolized: string;
  /** The original (pre-symbolization) request body, if known; else null. */
  inputOriginal: string | null;
  /** Symbols referenced in the forwarded request. */
  inputSymbols: SymbolRef[];
  /** The model's answer: its text, then one `→ name(args)` line per tool
   *  call; or the "⚠ no model response" explainer for an upstream error. */
  outputText: string;
  /** Did any un-symbolized untrusted span survive? (oracle predicate result) */
  violatedInvariant: boolean;
  invariantDetail?: string;
  /** Structural shape of the forwarded request (tools/max tokens/user turns) —
   *  the dashboard's side-call detection seam (dashboard.md §4.2c). */
  callShape?: TllmCallShape;
  /** The response's id (`resp_…`, `chatcmpl-…`), when it carried a well-formed one. */
  responseId?: string;
}

export function makeTllmCall(a: TllmCallArgs): ManduEvent {
  const inv: EventInvariant = a.invariantDetail
    ? { violatedInvariant: a.violatedInvariant, detail: a.invariantDetail }
    : { violatedInvariant: a.violatedInvariant };
  return baseEvent(a.ctx, "tllm_call", {
    input: makeDualRepr(a.inputSymbolized, a.inputOriginal, a.inputSymbols),
    output: makeDualRepr(a.outputText, null, []),
    model: { id: a.model, ...(responseIdOf(a.responseId) ? { responseId: a.responseId! } : {}) },
    invariant: inv,
    ...(a.callShape ? { callShape: a.callShape } : {}),
  });
}

export interface ToolUseEventArgs {
  ctx: EventContext;
  callId: string;
  /** The tool the model called (the shell function a script cell runs). */
  name: string;
  /** The call's argument JSON text, as the model wrote it (its own decision). */
  argumentsJson: string;
}

/**
 * `tool_use`: the model's tool-call decision as it left the response stream
 * (2026-09-24). Its two surfaces are the same — a decision made BY T-LLM
 * over a symbolized context needs no desymbolization — and its symbols are
 * the tokens mined from the arguments. Mirrors anthropic-proxy makeToolUse:
 * `<name>(<arguments JSON>)`, so the dashboard and the drill oracles read
 * both agents' decisions the same way (the runner's "gate exercised" and
 * sabotage checks key on this event).
 */
export function makeToolUse(a: ToolUseEventArgs): ManduEvent {
  const text = `${a.name}(${a.argumentsJson})`;
  const pat = getSymbolPattern();
  pat.lastIndex = 0;
  const seen = new Set<string>();
  const symbols: SymbolRef[] = [];
  for (const m of a.argumentsJson.matchAll(pat)) {
    if (seen.has(m[0])) continue;
    seen.add(m[0]);
    const name = m[0];
    const tag = name.slice(name.indexOf(":") + 1, name.indexOf("["));
    const close = name.indexOf("]");
    symbols.push({ name, tool: tag, field: name[close + 1] === "." ? name.slice(close + 2) : null, origin: null, value: null });
  }
  return baseEvent(a.ctx, "tool_use", {
    callId: a.callId,
    input: makeDualRepr(text, null, symbols),
    invariant: { violatedInvariant: false },
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
   *  request? (computed by the proxy with the oracle predicate.) */
  violatedInvariant: boolean;
  /** Plan 10 §4.2: the process-tree taint behind an exec_command result
   *  (files and programs by name, the rule, whether the whole result was
   *  masked, the opens refused). No content. Mirrors anthropic-proxy/src/events.ts. */
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
  if (a.secretTaint) extra["secretTaint"] = a.secretTaint;
  if (a.secretNote) extra["secretNote"] = a.secretNote;
  return Object.keys(extra).length > 0 ? Object.assign(ev, extra) : ev;
}

export interface ExecGateEventArgs {
  ctx: EventContext;
  /** The function_call id whose command was gated (empty if unknown). */
  callId: string;
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
}

/** The Phase-0 exec gate (exec-routing.md §3): an `exec_action` on the shell
 * boundary. On block, `output` carries the failing sentinel Codex runs instead;
 * on allow, it records the classification (evasion signals + shell). */
export function makeExecGate(a: ExecGateEventArgs): ManduEvent {
  const evasion = a.evasion.map((e) => `${e.kind}:${e.evidence}`).join(", ");
  const inSummary = `function_call.command${evasion ? ` [evasion: ${evasion}]` : ""}`;
  const outSummary =
    a.decision === "block" ? `BLOCKED → ${a.sentinel ?? "exit 77"}` : `ALLOW (${a.shell})`;
  return baseEvent(a.ctx, "exec_action", {
    callId: a.callId,
    boundary: "shell",
    input: makeDualRepr(inSummary, null, []),
    output: makeDualRepr(outSummary, null, []),
    policy: {
      usage: a.decision === "block" ? "deny" : "allow",
      reason: a.reason,
      shell: a.shell === "HumanShell" ? "HumanShell" : "AgentShell",
    },
    invariant: { violatedInvariant: false },
  });
}

export interface FsGateEventArgs {
  ctx: EventContext;
  /** The call whose path was withheld. */
  callId: string;
  tool: string;
  /** Where in the input the path sat (keys and indexes joined by "."). */
  field: string;
  /** The HumanView path the model named. */
  path: string;
  /** What the call reached the agent with instead (a path naming no file). */
  sentinel: string;
  reason: string;
  /** True when the person can allow it on the Approvals page. */
  requiresApproval: boolean;
  ruleRef?: { source: "rule" | "verdict" | "fail-closed"; id: string };
  approvalId?: string;
}

/** The unmapped upload leg withholding a path (unmapped-upload.ts): an
 *  `fs_action` on the filesystem boundary, the anthropic-proxy's makeFsGate
 *  shape. `input` carries the path asked for, `output` what was delivered. */
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

// ── Reply row reservation (reply-row-reservation.md §11.7) ────────────────────
// The same records the anthropic-proxy emits (its src/events.ts), so the
// dashboard reads Codex and Claude sessions alike.

/** `reserve_residual`: the request-side strip removed reserve-block fragments
 *  a well-formed collapse did not account for (a client-edited turn, a tool
 *  that read the agent's transcript). Carries counts and locations only. */
export function makeReserveResidual(
  ctx: EventContext,
  a: { removed: number; where: string[]; route: "responses" },
): ManduEvent {
  const ev = baseEvent(ctx, "reserve_residual", {
    input: makeDualRepr(
      `reply reserve: stripped ${a.removed} leftover row marker(s) before the model` +
        (a.where.length ? ` (${a.where.join(", ")})` : ""),
      null,
    ),
  });
  return Object.assign(ev, { removed: a.removed, where: a.where, route: a.route });
}

/** `reserve_expand`: a token went to the agent as an N-row reserve block
 *  (v1: alone on its line; v2, §11.3: at content width W with a head row F
 *  wide, possibly inside a line). The token is opaque; no value is known
 *  here, only the counts. */
export function makeReserveExpand(
  ctx: EventContext,
  a: { hash: string; rows: number; token: string; width?: number; first?: number },
): ManduEvent {
  const v2 = typeof a.width === "number" && typeof a.first === "number";
  const ev = baseEvent(ctx, "reserve_expand", {
    view: "HumanView",
    input: makeDualRepr(
      `reply reserve: ${a.token} reserved ${a.rows} rows` + (v2 ? ` (width ${a.width}, first row ${a.first})` : ""),
      null,
    ),
  });
  return Object.assign(ev, { hash: a.hash, rows: a.rows }, v2 ? { head: "v2", W: a.width, F: a.first } : { head: "v1" });
}

/** The detail of a `prompt_filter` event (confidentiality-plan-15 §8).
 *  Offsets, categories and symbols only; never the value, never the
 *  segment's text. Mirrors anthropic-proxy/src/events.ts and
 *  dashboard/src/event-model.ts `PromptFilterDetail`. */
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
  skipped: number;
  enforcing: boolean;
  digest: { policy: string; packs: string };
}

/** One sentence for the event's input pane, with the symbols. */
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
  const pat = getSymbolPattern();
  pat.lastIndex = 0;
  const names = [...new Set([...text.matchAll(pat)].map((m) => m[0]))];
  const refs: SymbolRef[] = names.map((name) => {
    const close = name.indexOf("]");
    return { name, tool: name.slice(name.indexOf(":") + 1, name.indexOf("[")), field: name[close + 1] === "." ? name.slice(close + 2) : null, origin: null, value: null };
  });
  const ev = baseEvent(ctx, "prompt_filter", { input: makeDualRepr(text, null, refs) });
  return Object.assign(ev, { promptFilter: d });
}
