/**
 * view-model/tool-calls — §4.2b tool-centric grouping (one card per TOOL CALL).
 *
 * Extracted verbatim from view-model.ts (agent-legibility split, behavior-preserving).
 * The flat timeline is the proxy/defense-pipeline view (one row per step); this
 * groups the pipeline rows sharing a `callId` into ONE tool call with the defense
 * steps as nested phases, so the trace reads from the AGENT's perspective. Depends
 * on the timeline row/annotation types from ./lanes.
 */

import type { ManduEvent } from "../event-model.js";
import type { TimelineRow, TimelineAnnotation } from "./lanes.js";
import { isPatchTool } from "./patch-files.js";

/** A tool call's name and args, recovered by {@link extractToolUses}.
 *  `patches`: the args of every patch call recorded under its callId (a
 *  code-mode cell may patch several times), absent when there is none. */
export interface ToolUseRecord {
  tool: string;
  input: string;
  patches?: string[];
}

// ── §4.2b — tool-centric grouping (one card per TOOL CALL) ────────────────────
// The flat timeline is the proxy/defense-pipeline view (one row per step:
// symbolize, tool_result, tllm_call…). This groups the pipeline events that share
// a `callId` into ONE tool call (Read/Bash/WebFetch…), with the defense steps as
// nested phases — so the trace reads from the AGENT's perspective. Rows with no
// callId (a model turn, or an uncorrelated OS action) stay standalone.

/** The INBOUND (data-trust) decision a tool call's result received — folded from
 *  its classify/symbolize (output-guard) phase event. */
export interface ToolUnitInbound {
  trust: "TRUSTED" | "UNTRUSTED" | null;
  category: string | null;
  reason: string | null;
}

/** The OUTBOUND (data-usage / egress) decision a tool call's input received —
 *  folded from its desymbolize/egress_* (input-guard) + exec_action phases. */
export interface ToolUnitOutbound {
  usage: "allow" | "deny" | "needs_approval" | null;
  shell: "AgentShell" | "HumanShell" | null;
  reason: string | null;
}

/** A tool call's per-call policy DECISION, aggregated across its phase events —
 *  the dynamic half of the policy modal (joined with the static governing rule
 *  from the arbiter policy snapshot, by tool name). Either side is null when the
 *  call has no such phase. */
export interface ToolUnitPolicy {
  inbound: ToolUnitInbound | null;
  outbound: ToolUnitOutbound | null;
}

/** A run of pipeline rows sharing a callId, presented as one tool call. */
export interface ToolCallGroup {
  unit: "toolcall";
  callId: string;
  /** Tool name (Read/Bash/WebFetch…); "tool" if unknowable. */
  tool: string;
  turn: number;
  firstInTurn: boolean;
  /** Lane annotation used for the card accent. */
  annotation: TimelineAnnotation;
  violated: boolean;
  /** Trust of the tool's RESULT (from its classify/symbolize/tool_result rows) —
   *  drives the card colour: TRUSTED → green, UNTRUSTED → pink, null → treated as
   *  untrusted (fail-closed). NOT a flat per-tool colour. */
  trust: "TRUSTED" | "UNTRUSTED" | null;
  // Phases (null/[] when the session didn't include that phase). The card renders
  // them as: input-guard → input → output → output-guard (the user's order):
  input: string | null;          // the tool's input ARGS — from a tool_use event,
                                 //   else reconstructed from the tllm_call transcript
  output: TimelineRow | null;    // tool_result — what the tool returned
  inputGuard: TimelineRow[];     // desymbolize / egress_* — guard the ARGS (egress)
  outputGuard: TimelineRow[];    // classify / symbolize — guard the RESULT (ingress)
  os: TimelineRow[];             // fs/net/exec_action — the OS chokepoint action
  /** All member rows in canonical order (for the jump-list count + detail). */
  rows: TimelineRow[];
  /** The per-call inbound/outbound policy DECISION, folded from the phase events
   *  (filled by toSessionViewModel, which has the raw events). Defaults to
   *  {inbound:null,outbound:null} until enriched. */
  policy: ToolUnitPolicy;
}

/** A standalone (non-tool-call) row: a model turn, or an uncorrelated OS action. */
export interface TimelineEventUnit {
  unit: "event";
  row: TimelineRow;
}

export type TimelineUnit = ToolCallGroup | TimelineEventUnit;

/**
 * Recover each tool call's name + input ARGS keyed by callId, so a tool card can
 * show its input even when the `tool_use` is not its own event (the offline
 * single-request replays carry the tool calls only inside the request history).
 * Two sources, the real `tool_use` event winning:
 *   - a `tool_use` event whose input is `Name({args})`
 *   - a `tllm_call` transcript line `→ Name({args})` immediately preceding the
 *     `[tool_result <callId>]` it produced.
 * Several `tool_use` events under one callId are a Codex code-mode cell's
 * calls (the openai-proxy records each `tools.exec_command` literal and each
 * literal `tools.apply_patch` under the cell's id): the last names the call,
 * except that a patch never renames a call another tool named (the cell ran
 * that tool, and its gates speak of it); every patch's args are kept in
 * `patches` (dashboard.md §4.25b "A patch in a code cell").
 */
export function extractToolUses(events: readonly ManduEvent[]): Map<string, ToolUseRecord> {
  const out = new Map<string, ToolUseRecord>();
  const fromEvent = new Set<string>();
  // Hyphens included: MCP tools are `mcp__<server>__<tool>` and servers may be
  // hyphenated (mcp__mandu-inspect__inspect_symbol) — without `-` the parse
  // fails and every MCP call rendered as a bare "tool".
  const NAME_ARGS = /^\s*→?\s*([A-Za-z_][A-Za-z0-9_-]*)\s*\(([\s\S]*)\)\s*$/;
  for (const e of events) {
    if (e.kind === "tool_use" && e.callId) {
      const m = (e.input?.symbolized ?? "").match(NAME_ARGS);
      if (!m) continue;
      // real event wins
      const id = e.callId;
      const prev = fromEvent.has(id) ? out.get(id) : undefined;
      const patch = isPatchTool(m[1]!);
      const patches = [...(prev?.patches ?? []), ...(patch ? [m[2]!] : [])];
      const named = prev && patch && !isPatchTool(prev.tool) ? prev : { tool: m[1]!, input: m[2]! };
      out.set(id, { tool: named.tool, input: named.input, ...(patches.length ? { patches } : {}) });
      fromEvent.add(id);
      continue;
    }
    if (e.kind === "tllm_call" && e.input?.symbolized) {
      let pending: { tool: string; input: string } | null = null;
      for (const line of e.input.symbolized.split("\n")) {
        const tu = line.match(NAME_ARGS);
        if (tu && line.trimStart().startsWith("→")) { pending = { tool: tu[1]!, input: tu[2]! }; continue; }
        const tr = line.match(/^\[tool_result\s+([^\]]+)\]/);
        if (tr && pending) { const id = tr[1]!.trim(); if (!out.has(id)) out.set(id, pending); pending = null; }
      }
    }
  }
  return out;
}

/**
 * Collapse the flat timeline into tool-centric units. Rows carrying a `callId` are
 * grouped (in first-occurrence order) into a ToolCallGroup; rows without one
 * (tllm_call / ullm_call / uncorrelated fs|net|exec) stay standalone. `toolUses`
 * (from extractToolUses) fills each group's tool name + input args.
 */
export function groupToolCalls(
  rows: TimelineRow[],
  toolUses: Map<string, { tool: string; input: string }> = new Map(),
): TimelineUnit[] {
  const units: TimelineUnit[] = [];
  const byCall = new Map<string, ToolCallGroup>();
  for (const r of rows) {
    if (!r.callId) {
      units.push({ unit: "event", row: r });
      continue;
    }
    let g = byCall.get(r.callId);
    if (!g) {
      g = {
        unit: "toolcall", callId: r.callId, tool: "", turn: r.turn,
        firstInTurn: r.firstInTurn, annotation: r.annotation, violated: false, trust: null,
        input: null, output: null, inputGuard: [], outputGuard: [], os: [], rows: [],
        policy: { inbound: null, outbound: null },
      };
      byCall.set(r.callId, g);
      units.push(g);
    }
    g.rows.push(r);
    g.violated = g.violated || r.violated;
    switch (r.kind) {
      case "tool_use": break; // the input args come from toolUses, not a phase row
      case "tool_result": g.output = r; g.annotation = r.annotation; break;
      case "classify": case "symbolize": g.outputGuard.push(r); break;
      case "desymbolize": case "egress_request": case "egress_decision":
      case "path_rewrite": g.inputGuard.push(r); break;
      case "fs_action": case "net_action": case "exec_action": g.os.push(r); break;
    }
    if (!g.tool && r.tool) g.tool = r.tool;
  }
  for (const u of units) {
    if (u.unit !== "toolcall") continue;
    const tu = toolUses.get(u.callId);
    if (tu) {
      if (!u.tool) u.tool = tu.tool;
      u.input = tu.input;
    }
    if (!u.tool) u.tool = "tool";
    // Trust of the result: the classify/symbolize guard wins, else the tool_result.
    u.trust = u.outputGuard.find((r) => r.trust)?.trust ?? u.output?.trust ?? null;
  }
  return units;
}

/**
 * Fold a tool call's phase events into its per-call policy DECISION:
 *   - INBOUND  ← the first output-guard (classify/symbolize) event carrying a
 *     trust (with its category + reason); falls back to the unit's aggregated
 *     result trust (the card-colour source) when no guard event has a policy.
 *   - OUTBOUND ← usage + reason from the first input-guard (desymbolize/egress_*)
 *     event carrying a usage, plus the shell from the first exec_action.
 * `eventsById` maps row id → raw event (the rows carry only `trust`; the full
 * EventPolicy lives on the raw event). Pure.
 */
export function toolUnitPolicy(
  unit: ToolCallGroup,
  eventsById: Map<string, ManduEvent>,
): ToolUnitPolicy {
  let inbound: ToolUnitInbound | null = null;
  for (const r of unit.outputGuard) {
    const p = eventsById.get(r.id)?.policy;
    if (p?.trust) {
      inbound = { trust: p.trust, category: p.category ?? null, reason: p.reason ?? null };
      break;
    }
  }
  if (!inbound && unit.trust) {
    inbound = { trust: unit.trust, category: null, reason: null };
  }

  let usage: ToolUnitOutbound["usage"] = null;
  let reason: string | null = null;
  for (const r of unit.inputGuard) {
    const p = eventsById.get(r.id)?.policy;
    if (p?.usage) {
      usage = p.usage;
      reason = p.reason ?? null;
      break;
    }
  }
  let shell: ToolUnitOutbound["shell"] = null;
  for (const r of unit.os) {
    const p = eventsById.get(r.id)?.policy;
    if (p?.shell) {
      shell = p.shell;
      break;
    }
  }
  const outbound: ToolUnitOutbound | null = usage || shell ? { usage, shell, reason } : null;

  return { inbound, outbound };
}
