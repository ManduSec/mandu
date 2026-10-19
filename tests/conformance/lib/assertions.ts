/**
 * assertions — the Mandu conformance assertion DSL + evaluator.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PROVENANCE
 *   The declarative shape is lifted from
 *     DualView (adfi-openclaw) tests/lib/assertions.ts
 *   — the `FieldMatcher` (equals / contains / matches / not_contains /
 *   min_length) and the per-step `assert: <kind>` table evaluated against a
 *   captured system state. adfi evaluates its steps against the AUDIT LOG +
 *   filesystem/git; Mandu evaluates them against the LIVE components a
 *   `buildStack()` boots — the FORWARDED model request, the arbiter symbol table,
 *   the emitted ManduEvents, the dashboard view-model, and the arbiter's
 *   egress / exec policy ops.
 *
 *   adfi step → Mandu step (the mapping the build spec calls for):
 *     AgentNoUntrusted / no-leak oracle  → agent_sees_only_symbol {payload_absent}
 *     ToolSymbolized                     → result_symbolized
 *     ToolInbound trust:trusted          → not_symbolized
 *     SymbolResolved / SymbolAllocated   → symbol_resolves_to {contains}
 *     the §9 oracle                      → invariant_holds
 *     (dashboard lane render)            → event_view {kind, view}
 *     ToolOutbound / data-usage gate     → egress_decision {boundary, expect}
 *     (exec classification)              → exec_shell {argv, expect}
 *     the U-LLM invariant                → ullm_resymbolized
 * ─────────────────────────────────────────────────────────────────────────────
 */

import type { ManduEvent } from "../../../dashboard/src/event-model.js";
import { toLaneModel, invariantStatus } from "../../../dashboard/src/view-model.js";
import type { Stack, Target, DriveIngressArgs } from "./harness.js";

// ─────────────────────────────────────────────────────────────────────────────
// FieldMatcher — mirrors adfi-openclaw/test/lib/assertions.ts `FieldMatcher`.
// ─────────────────────────────────────────────────────────────────────────────
export interface FieldMatcher {
  equals?: string | number | boolean;
  contains?: string;
  not_contains?: string;
  matches?: string;
  min_length?: number;
}

export type FieldMatcherOrValue = FieldMatcher | string | number | boolean;

function normalize(m: FieldMatcherOrValue): FieldMatcher {
  if (typeof m === "string" || typeof m === "number" || typeof m === "boolean") return { equals: m };
  return m;
}

/** Evaluate a matcher against a value. Returns [passed, reason]. (adfi parity.) */
export function evaluateFieldMatcher(value: unknown, matcher: FieldMatcherOrValue): [boolean, string] {
  const m = normalize(matcher);
  const strVal = typeof value === "string" ? value : String(value ?? "");

  if (m.equals !== undefined) {
    if (value === m.equals || strVal === String(m.equals)) return [true, `equals ${JSON.stringify(m.equals)}`];
    return [false, `expected ${JSON.stringify(m.equals)}, got ${JSON.stringify(value)}`];
  }
  if (m.contains !== undefined && !strVal.includes(m.contains)) {
    return [false, `does not contain "${m.contains}"`];
  }
  if (m.not_contains !== undefined && strVal.includes(m.not_contains)) {
    return [false, `contains "${m.not_contains}" (should not)`];
  }
  if (m.matches !== undefined && !new RegExp(m.matches).test(strVal)) {
    return [false, `does not match /${m.matches}/`];
  }
  if (m.min_length !== undefined && strVal.length < m.min_length) {
    return [false, `length ${strVal.length} < ${m.min_length}`];
  }
  return [true, "matches"];
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario + step shapes (the YAML contract).
// ─────────────────────────────────────────────────────────────────────────────

/** One ingress drive (a tool result re-entering T-LLM's context). */
export interface IngressSpec {
  tool: string;
  value: string;
  input?: Record<string, unknown>;
}

/** An egress desymbolization-gate check. `symbol` resolves to the last minted
 *  symbol via the literal "$LAST_SYMBOL" when omitted. */
export interface EgressSpec {
  boundary: "model_context" | "network" | "filesystem" | "shell";
  destination?: string;
  asCommand?: boolean;
}

/** An exec-classification check. */
export interface ExecSpec {
  argv: string[];
  cwd?: string;
  needsNetwork?: boolean;
  needsOriginalFs?: boolean;
  params?: Record<string, unknown>;
}

/** A U-LLM (inspect_symbol) drive. */
export interface UllmSpec {
  instruction: string;
}

export interface AssertionStep {
  /** The step kind (the Mandu DSL verb). */
  assert: string;
  /** Optional human label (auto-generated from kind when absent). */
  name?: string;
  // result_symbolized / not_symbolized / symbol_resolves_to operands
  field?: string;
  contains?: string;
  not_contains?: string;
  payload_absent?: string | string[];
  // event_view operands
  kind?: string;
  view?: string;
  // egress_decision operands
  boundary?: EgressSpec["boundary"];
  destination?: string;
  asCommand?: boolean;
  expect?: string;
  // exec_shell operands
  argv?: string[];
  needsNetwork?: boolean;
  needsOriginalFs?: boolean;
}

export interface Scenario {
  id: string;
  name: string;
  tags?: string[];
  target: Target;
  /** Pre-drive: an ingress tool result (mints a symbol the assertions reference). */
  ingress?: IngressSpec;
  /** A standalone egress-gate scenario (no ingress needed; uses an unknown sym). */
  egress?: EgressSpec;
  /** A standalone exec-classification scenario. */
  exec?: ExecSpec;
  /** A U-LLM re-symbolization scenario (driven against the ingress symbol). */
  ullm?: UllmSpec;
  assertions: AssertionStep[];
}

export interface StepResult {
  label: string;
  passed: boolean;
  reason: string;
}

/** Generate a default label for a step (adfi `autoName` analog). */
function autoName(step: AssertionStep): string {
  if (step.name) return step.name;
  switch (step.assert) {
    case "agent_sees_only_symbol": return "agent_sees_only_symbol (no raw untrusted byte forwarded)";
    case "result_symbolized": return "result_symbolized (untrusted result → $MDU:*)";
    case "not_symbolized": return `not_symbolized (${step.field ?? "field"} TRUSTED → passthrough)`;
    case "symbol_resolves_to": return "symbol_resolves_to (arbiter holds the original bytes)";
    case "invariant_holds": return "invariant_holds (§9 oracle: !violatedInvariant)";
    case "event_view": return `event_view (${step.kind} → ${step.view})`;
    case "egress_decision": return `egress_decision (${step.boundary} → ${step.expect})`;
    case "exec_shell": return `exec_shell (${(step.argv ?? []).join(" ")} → ${step.expect})`;
    case "ullm_resymbolized": return "ullm_resymbolized (U-LLM reply returned as a NEW symbol)";
    default: return step.assert;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Captured state passed to step evaluators (built once per scenario).
// ─────────────────────────────────────────────────────────────────────────────
interface ScenarioState {
  scenario: Scenario;
  stack: Stack;
  /** The forwarded model request body, if an ingress drive ran. */
  forwarded: string | null;
  /** The symbol the ingress drive minted (null if not symbolized / no ingress). */
  symbol: string | null;
  /** The ingress HTTP status. */
  ingressStatus: number | null;
  /** Persisted events for the session (after the drives). */
  events: ManduEvent[];
  /** The U-LLM drive result, if a ullm drive ran. */
  ullm: Awaited<ReturnType<Stack["driveUllm"]>> | null;
}

/** The $MDU:* token shape. */
const SYMBOL_RE = /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*/;

// ─────────────────────────────────────────────────────────────────────────────
// evaluate(scenario, stack) — run the scenario's drives, then its assertions.
// ─────────────────────────────────────────────────────────────────────────────

export async function evaluate(scenario: Scenario, stack: Stack): Promise<StepResult[]> {
  // ── Run the scenario's drives (ingress → ullm), capturing state. ──
  let forwarded: string | null = null;
  let symbol: string | null = null;
  let ingressStatus: number | null = null;
  let ullm: ScenarioState["ullm"] = null;

  if (scenario.ingress) {
    const r = await stack.driveIngress(scenario.ingress satisfies DriveIngressArgs);
    forwarded = r.forwarded;
    symbol = r.symbol;
    ingressStatus = r.status;
  }
  if (scenario.ullm) {
    // The U-LLM scenario inspects the symbol the ingress drive minted.
    if (!symbol) throw new Error("ullm scenario requires an ingress that mints a symbol");
    ullm = await stack.driveUllm(symbol, scenario.ullm.instruction);
  }

  // Read events back (best-effort emission lands a tick after the HTTP response).
  const wantKinds = new Set(scenario.assertions.filter((a) => a.assert === "event_view").map((a) => a.kind));
  const events = await stack.events((evs) => {
    if (wantKinds.size === 0) return evs.length > 0 || (!scenario.ingress && !scenario.ullm);
    return [...wantKinds].every((k) => evs.some((e) => e.kind === k));
  });

  const state: ScenarioState = { scenario, stack, forwarded, symbol, ingressStatus, events, ullm };

  // ── Evaluate each assertion step. ──
  const results: StepResult[] = [];
  for (const step of scenario.assertions) {
    const label = autoName(step);
    try {
      const [passed, reason] = await evalStep(step, state);
      results.push({ label, passed, reason });
    } catch (err) {
      results.push({ label, passed: false, reason: `evaluator error: ${(err as Error).message}` });
    }
  }
  return results;
}

async function evalStep(step: AssertionStep, st: ScenarioState): Promise<[boolean, string]> {
  switch (step.assert) {
    case "agent_sees_only_symbol":
      return evalAgentSeesOnlySymbol(step, st);
    case "result_symbolized":
      return evalResultSymbolized(step, st);
    case "not_symbolized":
      return evalNotSymbolized(step, st);
    case "symbol_resolves_to":
      return evalSymbolResolvesTo(step, st);
    case "invariant_holds":
      return evalInvariantHolds(step, st);
    case "event_view":
      return evalEventView(step, st);
    case "egress_decision":
      return evalEgressDecision(step, st);
    case "exec_shell":
      return evalExecShell(step, st);
    case "ullm_resymbolized":
      return evalUllmResymbolized(step, st);
    default:
      return [false, `unknown assertion kind '${step.assert}'`];
  }
}

// ── agent_sees_only_symbol (= adfi AgentNoUntrusted) ──────────────────────────
// The FORWARDED model request must contain NO raw untrusted bytes (the payload /
// fragments) — only the $MDU:* token. This is the §9 invariant observed at
// the proxy egress, by the component that did NOT do the symbolizing.
function evalAgentSeesOnlySymbol(step: AssertionStep, st: ScenarioState): [boolean, string] {
  if (st.forwarded === null) return [false, "no ingress was driven (nothing forwarded)"];
  if (st.ingressStatus !== 200) return [false, `proxy did not forward (status ${st.ingressStatus})`];
  const fragments = fragmentsOf(step.payload_absent, st);
  for (const frag of fragments) {
    if (frag && st.forwarded.includes(frag)) {
      return [false, `raw untrusted fragment leaked into the forwarded request: ${snippet(frag)}`];
    }
  }
  if (!SYMBOL_RE.test(st.forwarded)) {
    return [false, "no $MDU:* token found in the forwarded request (was the result symbolized?)"];
  }
  return [true, `forwarded request carries only the symbol; ${fragments.length} raw fragment(s) absent`];
}

// ── result_symbolized (= adfi ToolSymbolized) ─────────────────────────────────
// The ingress result was REPLACED by a $MDU:* token in the forwarded body.
function evalResultSymbolized(_step: AssertionStep, st: ScenarioState): [boolean, string] {
  if (st.forwarded === null) return [false, "no ingress was driven"];
  if (st.symbol === null) {
    return [false, "the result was NOT symbolized (no symbol in the forwarded request)"];
  }
  return [true, `result replaced by ${st.symbol}`];
}

// ── not_symbolized (= adfi ToolInbound trust:trusted — no over-symbolization) ──
// A TRUSTED field/tool passed through unchanged. Driven via the arbiter classify
// op (per-field trust), so it proves the data-trust policy without depending on
// the proxy's whole-result classification.
async function evalNotSymbolized(step: AssertionStep, st: ScenarioState): Promise<[boolean, string]> {
  const ing = st.scenario.ingress;
  if (!ing) return [false, "not_symbolized requires an ingress spec"];
  const field = step.field;
  const value = step.contains ?? ing.value;
  const verdict = await st.stack.arbiter.classify({
    tool: ing.tool,
    field,
    value,
    boundary: "model_context",
    origin: originHint(ing),
    params: ing.input,
  });
  if (verdict.trust !== "TRUSTED") {
    return [false, `field '${field ?? "(whole)"}' classified ${verdict.trust} (expected TRUSTED) — ${verdict.reason}`];
  }
  return [true, `field '${field ?? "(whole)"}' is TRUSTED → not symbolized (${verdict.reason})`];
}

// ── symbol_resolves_to (= adfi SymbolResolved / SymbolAllocated) ──────────────
// arbiter.resolve(symbol) returns the original bytes (round-trip authority).
async function evalSymbolResolvesTo(step: AssertionStep, st: ScenarioState): Promise<[boolean, string]> {
  if (st.symbol === null) return [false, "no symbol was minted to resolve"];
  const resolved = await st.stack.arbiter.resolve(st.symbol);
  if (resolved === null) return [false, `arbiter.resolve(${st.symbol}) returned null (symbol not in table)`];
  const want = step.contains;
  if (want !== undefined && !resolved.includes(want)) {
    return [false, `resolved value does not contain "${snippet(want)}"`];
  }
  return [true, `arbiter resolved ${st.symbol} → original bytes (${resolved.length} chars)`];
}

// ── invariant_holds (= the §9 oracle) ─────────────────────────────────────────
// The emitted tllm_call event has invariant.violatedInvariant === false.
function evalInvariantHolds(_step: AssertionStep, st: ScenarioState): [boolean, string] {
  const tllm = st.events.find((e) => e.kind === "tllm_call");
  if (!tllm) return [false, "no tllm_call event was emitted to the arbiter"];
  if (tllm.invariant.violatedInvariant) {
    return [false, `tllm_call flagged a §9 VIOLATION: ${tllm.invariant.detail ?? "(no detail)"}`];
  }
  // Cross-check the dashboard's pure oracle agrees over ALL events.
  const status = invariantStatus(st.events);
  if (!status.holds) return [false, `dashboard invariantStatus reports ${status.violationCount} violation(s)`];
  return [true, "tllm_call invariant holds + dashboard invariantStatus: HOLDS (green)"];
}

// ── event_view (dashboard lane render) ────────────────────────────────────────
// The event of `kind` lands in the expected dashboard lane (`view`), driving the
// PURE view-model toLaneModel (the same code the dashboard renders).
function evalEventView(step: AssertionStep, st: ScenarioState): [boolean, string] {
  const kind = step.kind;
  const view = step.view as "AgentView" | "Quarantine" | "HumanView" | undefined;
  if (!kind || !view) return [false, "event_view requires { kind, view }"];
  const lanes = toLaneModel(st.events);
  const inLane = lanes.byLane[view]?.some((c) => c.kind === kind);
  if (!inLane) {
    const found = st.events.filter((e) => e.kind === kind).map((e) => e.view);
    return [false, `no ${kind} card in the ${view} lane (found ${kind} in: ${found.join(", ") || "nowhere"})`];
  }
  return [true, `${kind} renders in the ${view} lane`];
}

// ── egress_decision (= adfi ToolOutbound / data-usage gate) ───────────────────
// Assert arbiter.desymbolizationDecision(...) for the minted symbol.
async function evalEgressDecision(step: AssertionStep, st: ScenarioState): Promise<[boolean, string]> {
  const boundary = step.boundary;
  const expect = step.expect; // "allow" | "requires_approval"
  if (!boundary || !expect) return [false, "egress_decision requires { boundary, expect }"];
  // Use the minted ingress symbol when present; else a fabricated unknown symbol
  // (the gate ALLOWS unknown symbols — there is nothing secret to leak).
  const symbol = st.symbol ?? "$MDU:unknown[dead]";
  const d = await st.stack.arbiter.desymbolizationDecision({
    symbol,
    boundary,
    destination: step.destination,
    asCommand: step.asCommand,
  });
  const got = d.allow ? "allow" : d.requiresApproval ? "requires_approval" : "deny";
  if (got !== expect) {
    return [false, `expected '${expect}', got '${got}' — ${d.reason}`];
  }
  return [true, `egress gate → ${got} (${d.reason})`];
}

// ── exec_shell (exec classification) ──────────────────────────────────────────
// Assert arbiter.classifyExec(...) selects the expected shell view.
async function evalExecShell(step: AssertionStep, st: ScenarioState): Promise<[boolean, string]> {
  const argv = step.argv ?? st.scenario.exec?.argv;
  const expect = step.expect; // "AgentShell" | "HumanShell"
  if (!argv || !expect) return [false, "exec_shell requires { argv, expect }"];
  const d = await st.stack.arbiter.classifyExec({
    argv,
    needsNetwork: step.needsNetwork ?? st.scenario.exec?.needsNetwork,
    needsOriginalFs: step.needsOriginalFs ?? st.scenario.exec?.needsOriginalFs,
    params: st.scenario.exec?.params,
  });
  if (d.shell !== expect) {
    return [false, `expected ${expect}, got ${d.shell} — ${d.reason}`];
  }
  return [true, `classifyExec → ${d.shell} (${d.reason})`];
}

// ── ullm_resymbolized (the U-LLM invariant) ───────────────────────────────────
// Driving inspect_symbol returns a NEW symbol — NEVER the raw U-LLM reply.
function evalUllmResymbolized(_step: AssertionStep, st: ScenarioState): [boolean, string] {
  if (!st.ullm) return [false, "no ullm drive ran"];
  const r = st.ullm.result;
  if (!r.ok) return [false, `inspect_symbol refused: ${r.error}`];
  if (!r.resultSymbol.startsWith("$MDU:")) {
    return [false, `inspect_symbol returned a non-symbol: ${snippet(r.resultSymbol)}`];
  }
  if (st.symbol && r.resultSymbol === st.symbol) {
    return [false, "inspect_symbol returned the SAME symbol (expected a distinct re-symbolized token)"];
  }
  // The U-LLM saw the raw (desymbolized) value, but carried NO T-LLM context.
  const sawTllmContext = st.ullm.ullmUserMessages.some((u) => u.includes("You are Claude Code"));
  if (sawTllmContext) return [false, "the quarantined U-LLM carried T-LLM system context (isolation breach)"];
  return [true, `inspect_symbol returned a NEW symbol ${r.resultSymbol} (raw reply never returned to T-LLM)`];
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Resolve the set of raw fragments that must be absent. Defaults to the whole
 *  ingress value when `payload_absent` is omitted. */
function fragmentsOf(payloadAbsent: AssertionStep["payload_absent"], st: ScenarioState): string[] {
  if (payloadAbsent === undefined) return st.scenario.ingress ? [st.scenario.ingress.value] : [];
  return Array.isArray(payloadAbsent) ? payloadAbsent : [payloadAbsent];
}

/** The origin hint the arbiter keys trust off (url / file_path / command). */
function originHint(ing: IngressSpec): string | undefined {
  const i = ing.input ?? {};
  const s = (k: string) => (typeof i[k] === "string" ? (i[k] as string) : undefined);
  return s("url") ?? s("file_path") ?? s("path") ?? s("command") ?? s("query");
}

function snippet(s: string, max = 80): string {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length <= max ? t : t.slice(0, max) + "…";
}
