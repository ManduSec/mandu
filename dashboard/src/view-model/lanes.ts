/**
 * view-model/lanes — §4.2 the three-lane trace + the single annotated
 * timeline (one row per event).
 *
 * Extracted verbatim from view-model.ts (agent-legibility split, behavior-preserving).
 * `toLaneModel` is the canonical sort/turns/causal-links source; `toTimeline`
 * flattens its cards into the single annotated column the UI renders. Kept in one
 * module because the timeline reuses the lane model's cards. Depends on
 * `modelFamily` (classify) and the shared `firstSymbol` (symbols).
 */

import type { ManduEvent, DualRepr, View, EventKind } from "../event-model.js";
import { type ModelFamily, modelFamily } from "./classify.js";
import { firstSymbol } from "./symbols.js";

// ── §4.2 — the three-lane trace ──────────────────────────────────────

/** The lane an event renders in IS its view (§4.2: "lane position is the view"). */
export type Lane = View;

export interface LaneCard {
  id: string;
  seq: number;
  turn: number;
  ts: string;
  kind: EventKind;
  view: View;
  lane: Lane;
  callId: string | null;
  parentId: string | null;
  /** "T-LLM" | "U-LLM" | null — for the model-family tag/color (§4.4). */
  modelFamily: ModelFamily;
  /** Accent token name for the lane/card, mapping to a CSS var (§4 color code). */
  accent: LaneAccent;
  /** Short human title for the card, e.g. "tool_result · read". */
  title: string;
  /** Collapsed DualRepr badge state (§4.2: 🔣 symbolized / 👁 original pills). */
  badge: DualBadge;
  /** True when this card must flare red (§4.6 per-event violation). */
  violated: boolean;
  /** Trust badge text if a classify/policy decision is attached. */
  trust: "TRUSTED" | "UNTRUSTED" | null;
  /** The tool this event belongs to (Read/Bash/WebFetch…), for grouping the
   *  pipeline events that share a callId into one tool card. null = no tool. */
  tool: string | null;
}

export type LaneAccent = "green" | "pink" | "cool";

export interface DualBadge {
  /** Does this event carry any symbolized representation worth a 🔣 pill? */
  hasSymbolized: boolean;
  /** Does it carry an original (revealed) representation worth a 👁 pill? */
  hasOriginal: boolean;
  /** Count of distinct symbols referenced across input+output. */
  symbolCount: number;
}

/** Lane → accent token (AgentView green, Quarantine pink, HumanView cool). */
export function laneAccent(view: View): LaneAccent {
  switch (view) {
    case "AgentView":
      return "green";
    case "Quarantine":
      return "pink";
    case "HumanView":
      return "cool";
  }
}

export function eventTitle(event: ManduEvent): string {
  const fam = modelFamily(event);
  // A model call shows ONLY its family (T-LLM / U-LLM) — the raw kind
  // (`tllm_call`/`ullm_call`) is redundant with it, so we drop it and keep the one
  // readable label.
  if (fam) return fam;
  // For tool/fs/net/exec events, suffix the tool/origin when we can find one,
  // else a hint from the OS-interceptor action's own fields (e.g. destination).
  const sym = firstSymbol(event);
  const hint = sym?.tool ?? actionHint(event);
  return hint ? `${event.kind} · ${hint}` : event.kind;
}

/** A short suffix for an OS-interceptor action card, read from the trace's own
 *  (kind-specific, non-canonical) fields so e.g. a net_action reads
 *  "net_action · tunneled api.example.com:443" rather than a bare "net_action". */
function actionHint(event: ManduEvent): string | null {
  const e = event as unknown as Record<string, unknown>;
  const str = (k: string): string | null => (typeof e[k] === "string" ? (e[k] as string) : null);
  const act = str("action");
  if (event.kind === "net_action") return [act, str("destination")].filter(Boolean).join(" ") || null;
  if (event.kind === "fs_action") return [act, str("path")].filter(Boolean).join(" ") || null;
  if (event.kind === "exec_action") return [act, str("argv0") ?? str("command")].filter(Boolean).join(" ") || null;
  return act;
}

function dualBadge(event: ManduEvent): DualBadge {
  const reprs = [event.input, event.output].filter((r): r is DualRepr => r !== null);
  const names = new Set<string>();
  let hasSymbolized = false;
  let hasOriginal = false;
  for (const r of reprs) {
    if (r.symbolized.length > 0) hasSymbolized = true;
    if (r.original !== null) hasOriginal = true;
    for (const s of r.symbols) names.add(s.name);
  }
  return { hasSymbolized, hasOriginal, symbolCount: names.size };
}

function trustOf(event: ManduEvent): "TRUSTED" | "UNTRUSTED" | null {
  return event.policy?.trust ?? null;
}

export function toLaneCard(event: ManduEvent): LaneCard {
  return {
    id: event.id,
    seq: event.seq,
    turn: event.turn,
    ts: event.ts,
    kind: event.kind,
    view: event.view,
    lane: event.view,
    callId: event.callId,
    parentId: event.parentId,
    modelFamily: modelFamily(event),
    accent: laneAccent(event.view),
    title: eventTitle(event),
    badge: dualBadge(event),
    violated: event.invariant.violatedInvariant,
    trust: trustOf(event),
    tool: eventTool(event),
  };
}

/**
 * The tool a tool-call event belongs to — used to group the pipeline events
 * (tool_use / classify / symbolize / tool_result / fs|net|exec_action) that share
 * a `callId` into ONE tool card. For a `tool_use` the leading `Name(args)` of its
 * input is authoritative — its structured refs (G3) name the tools of the ARGUMENT
 * symbols the model echoed, not the tool being called (an inspect_symbol call over
 * a Bash-born symbol is not a Bash card). Other kinds derive from the minted
 * symbol's tool (untrusted results). null when there is no tool (a model turn, or
 * an uncorrelated OS action).
 */
export function eventTool(event: ManduEvent): string | null {
  if (event.kind === "tool_use") {
    // Hyphens included for MCP tool names (mcp__<server>__<tool>).
    const m = (event.input?.symbolized ?? "").match(/^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*\(/);
    if (m) return m[1]!;
  }
  const sym = firstSymbol(event);
  if (sym?.tool) return sym.tool;
  return null;
}

export interface CausalLink {
  /** source event id (the parent / earlier correlated event) */
  fromId: string;
  /** target event id */
  toId: string;
  /** the correlation key that joined them */
  via: "callId" | "parentId";
}

export interface TurnGroup {
  turn: number;
  /** card ids in this turn, in canonical order. */
  cardIds: string[];
}

export interface LaneModel {
  /** ordered lanes left→right (§4.2). */
  lanes: { view: View; accent: LaneAccent }[];
  /** every event as a card (already lane-tagged). */
  cards: LaneCard[];
  /** cards grouped by lane, in canonical order, for column rendering. */
  byLane: Record<View, LaneCard[]>;
  /** horizontal turn rails (§4.2). */
  turns: TurnGroup[];
  /** cross-lane causal lines via callId/parentId (§4.2). */
  links: CausalLink[];
}

/**
 * THE core view-model builder (§4.2): events → three-lane trace model.
 * View tagging places each event in its lane; turn rails group by `turn`;
 * causal links join correlated events across lanes via callId/parentId.
 */
/**
 * A `tllm_call`/`ullm_call` is finalized at stream-END, so it lands with a LATER
 * ts/seq than the `tool_use` block(s) it produced in the same turn — leaving the
 * trace reading decision→reason (the tool call before the model turn that emitted
 * it). Pull each model call ahead of the maximal run of same-turn `tool_use` rows
 * it directly precedes, so it reads reason→decision. The turn's INPUT rows
 * (tool_result/symbolize from the prior tool) are NOT tool_use, so they stay
 * ahead; tool_use rows from a different turn are guarded out. Stable + in place.
 */
function leadModelCallsBeforeToolUses(ordered: ManduEvent[]): ManduEvent[] {
  const out = [...ordered];
  for (let i = 0; i < out.length; i++) {
    const e = out[i]!;
    if (e.kind !== "tllm_call" && e.kind !== "ullm_call") continue;
    // A CORRELATED ullm_call (callId set — natively or via the correlate.ts
    // pre-pass) was invoked BY a tool_use; it never PRODUCED the preceding
    // tool_use blocks, so hoisting it ahead would invert reason→decision.
    if (e.kind === "ullm_call" && e.callId !== null) continue;
    let j = i;
    while (j > 0 && out[j - 1]!.kind === "tool_use" && out[j - 1]!.turn === e.turn) j--;
    if (j < i) out.splice(j, 0, out.splice(i, 1)[0]!);
  }
  return out;
}

export function toLaneModel(events: ManduEvent[]): LaneModel {
  const ordered = leadModelCallsBeforeToolUses(
    [...events].sort((a, b) => (a.ts !== b.ts ? (a.ts < b.ts ? -1 : 1) : a.seq - b.seq)),
  );
  const cards = ordered.map(toLaneCard);

  const byLane: Record<View, LaneCard[]> = {
    AgentView: [],
    Quarantine: [],
    HumanView: [],
  };
  for (const c of cards) byLane[c.lane].push(c);

  // Turn rails (§4.2): group cards by `turn`, preserving canonical order.
  const turnMap = new Map<number, string[]>();
  for (const c of cards) {
    const arr = turnMap.get(c.turn) ?? [];
    arr.push(c.id);
    turnMap.set(c.turn, arr);
  }
  const turns: TurnGroup[] = [...turnMap.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([turn, cardIds]) => ({ turn, cardIds }));

  // Causal links (§4.2): an event with a parentId links to its parent; events
  // sharing a callId link to the first occurrence of that callId. We emit each
  // distinct (from,to) pair once.
  const links: CausalLink[] = [];
  const seenPair = new Set<string>();
  const byId = new Map(ordered.map((e) => [e.id, e]));
  const firstByCallId = new Map<string, string>();
  for (const e of ordered) {
    if (e.callId && !firstByCallId.has(e.callId)) firstByCallId.set(e.callId, e.id);
  }
  for (const e of ordered) {
    if (e.parentId && byId.has(e.parentId)) {
      const key = `${e.parentId}->${e.id}`;
      if (!seenPair.has(key)) {
        seenPair.add(key);
        links.push({ fromId: e.parentId, toId: e.id, via: "parentId" });
      }
    } else if (e.callId) {
      const root = firstByCallId.get(e.callId);
      if (root && root !== e.id) {
        const key = `${root}->${e.id}`;
        if (!seenPair.has(key)) {
          seenPair.add(key);
          links.push({ fromId: root, toId: e.id, via: "callId" });
        }
      }
    }
  }

  return {
    lanes: [
      { view: "AgentView", accent: "green" },
      { view: "Quarantine", accent: "pink" },
      { view: "HumanView", accent: "cool" },
    ],
    cards,
    byLane,
    turns,
    links,
  };
}

// ── §4.2 — the single annotated timeline (one row per event) ──────────────────

/**
 * The per-row annotation in the single-column trace (dashboard.md §4.2). It is
 * exactly the four categories an OpenClaw/Mandu-style audit timeline distinguishes:
 * the privileged model call (T-LLM), the quarantined model call (U-LLM), and
 * every other action by the view it ran in — what the agent saw (AgentView) vs
 * what the real world saw (HumanView). `modelFamily ?? view`, collapsed so the
 * U-LLM's Quarantine view reads as "U-LLM".
 */
export type TimelineAnnotation = "T-LLM" | "U-LLM" | "AgentView" | "HumanView";

/** Classify an event into its timeline annotation (pure; keys off kind + view). */
export function timelineAnnotation(event: Pick<ManduEvent, "kind" | "view">): TimelineAnnotation {
  if (event.kind === "tllm_call") return "T-LLM";
  if (event.kind === "ullm_call") return "U-LLM";
  // Anything else in the Quarantine lane (e.g. a re-symbolization) belongs to
  // the U-LLM family; otherwise the annotation IS the view.
  if (event.view === "Quarantine") return "U-LLM";
  return event.view === "HumanView" ? "HumanView" : "AgentView";
}

/**
 * The actor/stage behind an event — answers "WHO acted", a different axis from the
 * lane annotation, so a defense step (`symbolize`) reads as GUARD rather than an
 * agent tool call:
 *   AGENT — the model's own activity (tllm_call / ullm_call / tool_use)
 *   GUARD — the arbiter defense (classify / symbolize / desymbolize / tool_result /
 *           egress_request / egress_decision)
 *   OS    — the chokepoint interceptors (fs_action / net_action / exec_action)
 */
export type EventCategory = "AGENT" | "GUARD" | "OS";

const CATEGORY_BY_KIND: Record<EventKind, EventCategory> = {
  tllm_call: "AGENT", ullm_call: "AGENT", tool_use: "AGENT",
  classify: "GUARD", symbolize: "GUARD", desymbolize: "GUARD",
  tool_result: "GUARD", egress_request: "GUARD", egress_decision: "GUARD",
  path_rewrite: "GUARD",
  fs_action: "OS", net_action: "OS", exec_action: "OS",
  // The DevTools relay: an interceptor on the browser connection, as the
  // net proxy is on the network.
  browser_action: "OS",
  // A human verdict landing on the approval queue — arbiter defense state.
  approval_resolved: "GUARD",
  // A once-scoped verdict spent by its one use — the same defense-state family.
  approval_consumed: "GUARD",
  // A SIEM-triggered egress-posture change (lockdown) — arbiter defense state.
  posture_change: "GUARD",
  // A Protection-drawer config act (an axis turned on/off) — defense state too:
  // the human reconfigured the guard, not an agent/OS step.
  config_change: "GUARD",
  // A names-only model run for policy suggestions (plan 14 §14.5): the
  // arbiter's own quarantined call, counts only — defense state.
  policy_model_call: "GUARD",
  // The e2e verdict is a privileged HumanView check, not an agent/OS trace step.
  assertion: "GUARD",
  // The harness's prepared-workspace record — a meta event like `assertion`
  // (filtered out of the trace projections), never an agent/OS step.
  workspace_seed: "GUARD",
  // Its end-of-run twin (the final per-view trees) — the same meta posture.
  workspace_final: "GUARD",
  // Session-health kinds (dashboard.md §4.21): meta events about the run's
  // posture — the launcher's, the relay's, the proxy's — not agent actions.
  launch_posture: "GUARD",
  relay_mode: "GUARD",
  client_info: "GUARD",
  tool_surface: "GUARD",
  session_exit: "GUARD",
  // The arbiter raised the session's high-watermark: defense state.
  session_level: "GUARD",
  // The prompt filter's report on one segment of the user's turn
  // (confidentiality-plan-15 §8): the proxy's defense step, not the agent's.
  prompt_filter: "GUARD",
};

/** Classify an event kind into its actor/stage category (pure). */
export function eventCategory(kind: EventKind): EventCategory {
  return CATEGORY_BY_KIND[kind] ?? "GUARD";
}

/** A lane card flattened into the single timeline, annotated for the one column. */
export interface TimelineRow extends LaneCard {
  /** T-LLM | U-LLM | AgentView | HumanView — the row's primary tag/accent (§4.2). */
  annotation: TimelineAnnotation;
  /** AGENT | GUARD | OS — who acted (model / arbiter defense / OS chokepoint), so a
   *  defense step like `symbolize` reads as GUARD, not an agent tool call. */
  category: EventCategory;
  /** True for the first row of a `turn`, so the renderer can draw a turn divider. */
  firstInTurn: boolean;
}

/**
 * §4.2 — the trace as a SINGLE chronological list of annotated rows (replacing
 * the three-lane split). Reuses `toLaneModel`'s canonical sort + cards (so the
 * ordering, causal links, and turn rails stay the single source of truth) and
 * adds the per-row `annotation` + a `firstInTurn` flag for the turn dividers.
 */
export function toTimeline(events: ManduEvent[]): TimelineRow[] {
  const { cards } = toLaneModel(events);
  let prevTurn: number | null = null;
  return cards.map((c) => {
    const firstInTurn = c.turn !== prevTurn;
    prevTurn = c.turn;
    return { ...c, annotation: timelineAnnotation(c), category: eventCategory(c.kind), firstInTurn };
  });
}
