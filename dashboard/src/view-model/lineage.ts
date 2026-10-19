/**
 * view-model/lineage — the symbol data-lineage graph (symbol-lineage.md §3).
 *
 * For every untrusted datum the session touched, reconstruct the recorded
 * chain  origin → symbol ($MDU:*) → model context → tool-call echo → egress
 * verdict  as a small DAG, plus a per-session flow summary (the §9.1 shadow
 * sentence: "N flows where untrusted data reached the model and touched an
 * egress").
 *
 * THE EVIDENCE RULE (symbol-lineage.md §1): every edge carries the {eventId,
 * seq} of the event that PROVES it, and an edge with no event does not exist.
 * No inference, no interpolation — a symbol whose birth was never recorded
 * (a pre-G1 legacy session) renders as `minted:false`, never as a synthetic
 * minted edge. This is what makes the graph usable as audit evidence
 * rather than illustration.
 *
 * Pure projection over the event stream, like every sibling module — the
 * dashboard never opens the symbol DB.
 */

import type { ManduEvent, SymbolRef, View } from "../event-model.js";
import { askIdOf } from "./dual-lanes.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export type LineageVerdict = "allowed" | "approved" | "denied" | "blocked" | "pending";

export type LineageLane = "External" | View;

export type LineageNodeKind = "origin" | "symbol" | "context" | "action" | "sink";

export interface LineageNode {
  id: string;
  kind: LineageNodeKind;
  /** Trust-geometry x-position (§5.1): External | HumanView | AgentView | Quarantine. */
  lane: LineageLane;
  label: string;
  /** kind "symbol": the fullest provenance ref seen for it. */
  symbol?: SymbolRef;
  /** kind "symbol": false ⇒ no `symbolize` birth event exists in this session
   *  (legacy / pre-G1) — the UI shows "birth unrecorded", never a fake edge. */
  minted?: boolean;
  /** kind "symbol": true ⇒ the token appears ONLY on model-authored text
   *  surfaces (reply prose / tool args) — the model composed a token-shaped
   *  string that was never minted (seen live: an invented `.field` suffix on
   *  a real token). Not a symbol; no birth exists to lose, so the G1 oracle
   *  ignores it. Only ever set alongside `minted: false`. */
  modelAuthored?: boolean;
  /** kind "symbol": the U-LLM triage verdict (symbol-quality.md §4.1), when a
   *  triage ullm_call for this symbol exists in the stream. */
  contentKind?: string;
  /** kind "context": how many model calls this node collapses (×N). */
  count?: number;
  /** kind "sink"/"action": terminal outcome. */
  verdict?: LineageVerdict;
  eventId: string;
  seq: number;
  turn: number;
}

export type LineageEdgeKind =
  | "fetched_by" //       tool_use ↔ tool_result via callId — the fetching cause
  | "minted" //           symbolize birth: origin → symbol
  | "entered_context" //  tllm_call carrying the symbol
  | "echoed" //           the model wrote the token into tool args
  | "derived_inspect" //  U-LLM re-symbolization parent → child
  | "derived_split" //    human-edit split parent → child
  | "gated" //            an OS chokepoint decided the echoing call
  | "egress" //           per-symbol desymbolization request/verdict at a boundary
  | "revealed_reply" //   a desymbolize resolved it: the reply filter's for the
  //                      human terminal (`snk:human`), any other emitter's on `snk:fill`
  | "declassified"; //    in-context read (dormant until declassify emits events)

export interface LineageEdge {
  from: string;
  to: string;
  kind: LineageEdgeKind;
  verdict?: LineageVerdict;
  /** THE EVIDENCE — the event that proves this edge. Mandatory. */
  eventId: string;
  seq: number;
  /** A `gated` or `egress` edge that stopped the data (blocked, denied,
   *  pending): the Approvals row its evidence event says the arbiter filed
   *  for the person (`policy.approvalId`, by dual-lanes `askIdOf`, the rule
   *  the trace and *Your secrets* read it by; dashboard.md §4.15, *A block
   *  says Mandu asked*). Absent when it filed none. */
  askId?: string;
}

export interface FlowSummary {
  root: string;
  originLabel: string | null;
  /** Birth recorded in-session (G1). */
  minted: boolean;
  /** True ⇒ the root is a model-composed token-shaped string, not a symbol
   *  (see LineageNode.modelAuthored). Only ever set alongside minted:false. */
  modelAuthored?: boolean;
  /** Model calls that carried any symbol of this flow. */
  contextTurns: number;
  echoed: boolean;
  /** Worst egress outcome, or the non-egress shape of the flow. "shown":
   *  the reply filter put the real value on the person's own screen and
   *  nothing else released it (a `revealed_reply` edge is not a send,
   *  dashboard.md §4.15 "Shown to you is not a send"). */
  terminal: LineageVerdict | "shown" | "quarantined" | "context-only" | "dormant";
  /** The flow's data is a secret (`isSecretFlow`), not untrusted text: the
   *  inspector calls it a secret item. Absent from an older payload. */
  secret?: boolean;
  /** When the AI got this item's content as it was, before any request
   *  carried it masked (`withReadFirst`: a result read unmasked and re-sent
   *  masked once its file was labelled, dual-lanes `maskedLater`). Absent:
   *  nothing recorded such a read, and the mask came first. */
  readFirst?: string;
}

export interface SymbolLineage {
  /** The ancestor-most (earliest-born) symbol of the derivation closure. */
  root: string;
  nodes: LineageNode[];
  edges: LineageEdge[];
  summary: FlowSummary;
}

export interface SessionFlowStats {
  /** The masked items: the flows less the tokens the model composed itself
   *  (`summary.modelAuthored`, counted in `composed`). Every count below is
   *  over these items. Until 2026-10-09 it counted every flow, so a
   *  composed token was "1 masked" on the session's row. */
  flows: number;
  /** Of `flows`, the SECRET ones (confidentiality axis: a `nomodel_`/`localmodel_`/`anymodel_`
   *  twin, or any symbol in the flow carrying a secret level). The rest are
   *  untrusted (integrity axis). The plain-language copy names each kind by
   *  its own word: a secrets-mode session masks under plan 10 rule (i) and
   *  has no "untrusted item" at all (2026-09-24). */
  secret: number;
  /** minted + entered context + touched an egress surface (§3.1). */
  complete: number;
  egressAllowed: number;
  egressBlocked: number;
  egressPending: number;
  /** Items per outcome their evidence edges recorded, each item counted
   *  under EVERY outcome it had (a token sent to its bound host and blocked
   *  at another counts as allowed and as blocked). The `egress*` counts
   *  above keep one outcome per item, the worst, for the badges; this is
   *  what "Where each went" tallies, so no recorded release disappears
   *  behind a block (dashboard.md §4.15). `denied` counts as blocked.
   *  Absent from an older payload. */
  outcomes?: FlowOutcomes;
  /** Of `flows`, the ones the AI read as they were before they were masked
   *  (`summary.readFirst`). Absent from an older payload: none known. */
  readFirst?: number;
  /** The flows that are tokens the model composed itself, not counted in
   *  `flows`. Absent: none (or an older payload, which counted them there). */
  composed?: number;
}

export interface FlowOutcomes {
  /** Items a release let out (a network send, an egress queue row, another
   *  emitter's fill) or a gate let through; never the reply filter's reveal,
   *  which is `shown`. */
  allowed: number;
  approved: number;
  blocked: number;
  pending: number;
  /** Items the reply filter showed on the person's own screen (a
   *  `revealed_reply` edge): not a send, so never under `allowed`. Absent
   *  from an older payload: none counted. */
  shown?: number;
}

export interface SessionLineage {
  flows: SymbolLineage[];
  stats: SessionFlowStats;
}

// ── Shared plumbing ───────────────────────────────────────────────────────────

/** Symbol-token grammar, INCLUDING split-field suffixes (`.__mdu_split[0]`).
 *  Twin of arbiter/symbol-table SYMBOL_PATTERN (the fuller of the dashboard's
 *  twinned regexes — dual-lanes' misses bracketed field segments). */
const SYM_TOKEN_RE =
  /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*/g;

/** The 7-token triage vocabulary (symbol-quality.md §4.1) — a triage ullm_call
 *  carries exactly one of these as its whole symbolized output. */
const CONTENT_KIND_RE =
  /^(?:as_requested|wrong_content|substantive|error_or_refusal|auth_wall|empty|unknown)$/;

function canonical(events: ManduEvent[]): ManduEvent[] {
  return [...events].sort((a, b) => (a.ts !== b.ts ? (a.ts < b.ts ? -1 : 1) : a.seq - b.seq));
}

function structuredRefs(e: ManduEvent): SymbolRef[] {
  const out: SymbolRef[] = [];
  for (const r of [e.input, e.output]) if (r) out.push(...r.symbols);
  return out;
}

/** Tokens mined from one text surface. A trailing dot-run is sentence
 *  punctuation the token grammar swallows (field segments may contain dots:
 *  `…result.` ending a sentence is the token `…result` plus a period) — trim
 *  it so prose-glued sightings unify with the real name. A genuine
 *  dot-terminal field name would be mis-mined, but sentence glue is the
 *  common case by far and the untrimmed form never matched refs either. */
function minedTokens(text: string): Set<string> {
  const out = new Set<string>();
  SYM_TOKEN_RE.lastIndex = 0;
  for (const m of text.matchAll(SYM_TOKEN_RE)) out.add(m[0].replace(/\.+$/, ""));
  return out;
}

/** Every symbol NAME an event references: structured refs first, then tokens
 *  mined from the symbolized text surfaces (pre-G3 tool_use, reply-filter). */
function referencedNames(e: ManduEvent): Set<string> {
  const names = new Set<string>();
  for (const s of structuredRefs(e)) names.add(s.name);
  for (const r of [e.input, e.output]) {
    if (!r) continue;
    for (const t of minedTokens(r.symbolized)) names.add(t);
  }
  return names;
}

/** Kinds whose TEXT is system-written (mint/ingress records): a token sighted
 *  there was put there by an interceptor or the arbiter, so it names a real
 *  symbol. The complement — tllm_call OUTPUT prose, tool_use args, and the
 *  relay/gate events that echo them — is model-authored text: the model can
 *  compose token-shaped strings that were never minted (seen live: a model
 *  appending an invented `.field` suffix to a real token in its final reply).
 *  Structured `symbols` refs are system-attached and count on EVERY kind. */
const SYSTEM_TEXT_KINDS: ReadonlySet<ManduEvent["kind"]> = new Set([
  "symbolize", "classify", "tool_result", "ullm_call", "fs_action", "path_rewrite",
  "workspace_seed", "workspace_final",
]);

/** Secret-twin names (presentation-only prefix parse — twin of arbiter
 *  symbol-format.ts `levelFromSymbolName`; decisions read the table, this only
 *  labels). Twins are pre-registered arbiter-side and the model learns their
 *  names from the SYSTEM PROMPT — a surface the DualRepr text mining cannot
 *  see — so a twin's first visible sighting is often the model echoing it.
 *  So a twin's name is never model-authored by itself (`composedByModel`),
 *  unless it extends a symbol minted in this session by a field path. */
const isSecretTwinName = (name: string): boolean =>
  name.startsWith("$MDU:nomodel_") || name.startsWith("$MDU:localmodel_") || name.startsWith("$MDU:anymodel_");

/** The names `name` extends by a field path, shortest first:
 *  `$MDU:t[ab12].a.b` → `$MDU:t[ab12]`, `$MDU:t[ab12].a`. None for a name
 *  with no field path. */
function fieldParents(name: string): string[] {
  const close = name.indexOf("]");
  if (close < 0) return [];
  const out: string[] = [];
  for (let i = name.indexOf(".", close); i >= 0; i = name.indexOf(".", i + 1)) out.push(name.slice(0, i));
  return out;
}

/** Loose fields the net-proxy spreads onto net_action events (not part of the
 *  typed schema — same read the e2e oracle uses). `withheld`/`resolved` come in
 *  BOTH wire shapes: `string[]` (net-proxy proxy.ts) and `{symbol}[]` (the
 *  refuse body) — normalize via `looseSym`, same class as the drawer builder. */
interface LooseNetFields {
  action?: string;
  destination?: string;
  withheld?: Array<{ symbol?: string } | string>;
  resolved?: Array<{ symbol?: string } | string>;
}

const looseSym = (w: { symbol?: string } | string): string | undefined =>
  typeof w === "string" ? w : w.symbol;

const short = (s: string, n = 60): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/** The Approvals row `e` says it filed, on an edge whose verdict stopped
 *  the data; nothing on one that let it through. */
function askOn(e: ManduEvent, verdict: LineageVerdict): { askId: string } | Record<string, never> {
  const id = askIdOf(e.policy?.approvalId, verdict === "blocked" || verdict === "denied" || verdict === "pending");
  return id ? { askId: id } : {};
}

// ── The builder ───────────────────────────────────────────────────────────────

interface SymbolState {
  name: string;
  ref: SymbolRef;
  minted: boolean;
  /** Seen on a system-written surface (structured ref / SYSTEM_TEXT_KINDS /
   *  net-proxy loose fields / first entry via tllm_call input). false + not
   *  minted ⇒ model-authored token, not a symbol (`composedByModel`, which
   *  also reads a secret twin's name). */
  systemWitnessed: boolean;
  mintEvent?: ManduEvent;
  quarantineBorn: boolean;
  contentKind?: string;
  contextGroups: Array<{ first: ManduEvent; count: number; lastTurn: number }>;
  echoes: ManduEvent[]; // tool_use events echoing the token
  gateHits: ManduEvent[]; // gate events (exec_action) citing the token themselves
  netEgress: Array<{ e: ManduEvent; verdict: LineageVerdict; destination: string }>;
  egressRequests: Array<{ e: ManduEvent; verdict: LineageVerdict }>;
  reveals: ManduEvent[]; // desymbolize events resolving it for the human
  firstEvent: ManduEvent;
}

/** Assemble the session's lineage. Pure; input is the same filtered trace the
 *  other projections receive (no assertion/workspace_seed/workspace_final meta
 *  events). */
export function toSessionLineage(events: ManduEvent[]): SessionLineage {
  const ordered = canonical(events);

  // ── pass 1: per-symbol state ────────────────────────────────────────────────
  const syms = new Map<string, SymbolState>();
  const stateOf = (name: string, ref: SymbolRef | null, e: ManduEvent): SymbolState => {
    let s = syms.get(name);
    if (!s) {
      s = {
        name,
        ref: ref ?? { name, tool: name.replace(/^\$MDU:/, "").split("[")[0] ?? "", field: null, origin: null, value: null },
        minted: false,
        systemWitnessed: false,
        quarantineBorn: false,
        contextGroups: [],
        echoes: [],
        gateHits: [],
        netEgress: [],
        egressRequests: [],
        reveals: [],
        firstEvent: e,
      };
      syms.set(name, s);
    }
    if (ref) {
      // Enrich with the fullest provenance seen (mirrors toSymbolInspector).
      if (s.ref.value === null && ref.value !== null) s.ref = { ...ref, ...pickRicher(s.ref, ref) };
      if (!s.ref.derivedFrom && ref.derivedFrom) s.ref.derivedFrom = ref.derivedFrom;
      if (!s.ref.lineRange && ref.lineRange) s.ref.lineRange = ref.lineRange;
      if (!s.ref.origin && ref.origin) s.ref.origin = ref.origin;
      if (!s.ref.confidentiality && ref.confidentiality) s.ref.confidentiality = ref.confidentiality;
    }
    return s;
  };

  // egress_decision events by callId (pairs egress_request → verdict).
  const decisions = new Map<string, ManduEvent>();
  for (const e of ordered) {
    if (e.kind === "egress_decision" && e.callId) decisions.set(e.callId, e);
  }

  for (const e of ordered) {
    const refsByName = new Map(structuredRefs(e).map((r) => [r.name, r]));
    const names = referencedNames(e);

    // net_action carries its symbols in LOOSE fields (withheld/resolved),
    // outside the typed DualRepr — same read the e2e oracle uses. The proxy
    // matched these against the symbol table, so they witness real symbols.
    const looseNames = new Set<string>();
    if (e.kind === "net_action") {
      const loose = e as unknown as LooseNetFields;
      for (const w of [...(loose.withheld ?? []), ...(loose.resolved ?? [])]) {
        const sym = looseSym(w);
        if (sym) {
          names.add(sym);
          looseNames.add(sym);
        }
      }
    }

    // Triage verdict ullm_call: whole output is one enum token; attach to the
    // INPUT symbol, do not treat the enum text as a context reference.
    if (e.kind === "ullm_call" && e.output && CONTENT_KIND_RE.test(e.output.symbolized.trim())) {
      for (const r of e.input?.symbols ?? []) {
        const s = stateOf(r.name, r, e);
        if (!s.contentKind) s.contentKind = e.output.symbolized.trim();
      }
      continue;
    }

    for (const name of names) {
      const known = syms.has(name);
      const s = stateOf(name, refsByName.get(name) ?? null, e);
      // System-witness rule: a structured ref, a system-written text surface,
      // a net-proxy loose field, or FIRST entry via tllm_call input (the
      // system-assembled context) proves the token names a real symbol. A
      // later input sighting of a token first seen in model OUTPUT is just
      // conversation history echoing the model's own prose — no witness.
      // A secret twin's name is judged after this pass (`composedByModel`).
      if (!s.systemWitnessed) {
        s.systemWitnessed =
          refsByName.has(name) ||
          SYSTEM_TEXT_KINDS.has(e.kind) ||
          looseNames.has(name) ||
          (e.kind === "tllm_call" && !known && !!e.input && minedTokens(e.input.symbolized).has(name));
      }
      switch (e.kind) {
        case "symbolize": {
          // A birth only when THIS symbol is the minted output.
          const isMint = (e.output?.symbols ?? []).some((r) => r.name === name);
          if (isMint && !s.minted) {
            s.minted = true;
            s.mintEvent = e;
          }
          break;
        }
        case "ullm_call": {
          // The re-symbolized RESULT is born here (quarantine lane).
          const isResult = (e.output?.symbols ?? []).some((r) => r.name === name);
          if (isResult && !s.minted) {
            s.minted = true;
            s.mintEvent = e;
            s.quarantineBorn = true;
          }
          break;
        }
        case "tllm_call": {
          // Consecutive model calls (same or adjacent turn) collapse into one
          // context node — the stateless Messages API re-sends every symbol
          // each turn, and per-call nodes would drown the graph (§5.5).
          const last = s.contextGroups[s.contextGroups.length - 1];
          if (last && e.turn <= last.lastTurn + 1) {
            last.count++;
            last.lastTurn = Math.max(last.lastTurn, e.turn);
          } else {
            s.contextGroups.push({ first: e, count: 1, lastTurn: e.turn });
          }
          break;
        }
        case "tool_use":
          s.echoes.push(e);
          break;
        case "net_action": {
          const loose = e as unknown as LooseNetFields;
          const withheld = (loose.withheld ?? []).some((w) => looseSym(w) === name);
          const resolved = (loose.resolved ?? []).some((w) => looseSym(w) === name);
          const dest = loose.destination ?? "(unknown destination)";
          if (withheld && (loose.action === "blocked" || loose.action === "block")) {
            s.netEgress.push({ e, verdict: "blocked", destination: dest });
          } else if (resolved || ((loose.action === "forwarded" || loose.action === "forward") && withheld === false && (loose.withheld !== undefined || loose.resolved !== undefined))) {
            s.netEgress.push({ e, verdict: "allowed", destination: dest });
          }
          break;
        }
        case "egress_request": {
          const d = e.callId ? decisions.get(e.callId) : undefined;
          const verdict: LineageVerdict =
            d?.policy?.usage === "allow" ? "approved"
            : d?.policy?.usage === "deny" ? "denied"
            : e.policy?.usage === "allow" ? "allowed"
            : e.policy?.usage === "deny" ? "denied"
            : "pending";
          s.egressRequests.push({ e, verdict });
          break;
        }
        case "desymbolize":
          s.reveals.push(e);
          break;
        case "exec_action":
          // The exec gate cites the implicated symbols itself (G3 structured
          // refs). Keep the hit: on a BLOCK the wire rewrite strips the token
          // from the recorded tool_use input (the gate's refusal echo replaces
          // the command), so this event is the only echo evidence that
          // survives — pass 4 joins it when no tool_use echo exists.
          s.gateHits.push(e);
          break;
        default:
          break; // classify/tool_result/fs_action/etc: presence only
      }
    }
  }

  // A token the model composed itself (`modelAuthored`): no recorded birth,
  // never seen on a system-written surface, and not a secret twin's name,
  // which may reach the model where mining cannot see. A twin's name that
  // extends a symbol minted in this session by a field path is the model's
  // after all (seen live at Secrets, 2026-10-09: "I will send
  // `$MDU:nomodel_Bash[93d1].value`" after the result `$MDU:nomodel_Bash[93d1]`):
  // the model learned the symbol from a recorded result, and a real field of
  // it would have reached the model in that result.
  const composedByModel = (s: SymbolState): boolean =>
    !s.minted && !s.systemWitnessed &&
    (!isSecretTwinName(s.name) || fieldParents(s.name).some((p) => syms.get(p)?.minted === true));

  // ── pass 2: index tool_use → gate events (callId join) ─────────────────────
  const gatesByCall = new Map<string, ManduEvent[]>();
  for (const e of ordered) {
    if ((e.kind === "exec_action" || e.kind === "net_action" || e.kind === "fs_action") && e.callId) {
      const arr = gatesByCall.get(e.callId) ?? [];
      arr.push(e);
      gatesByCall.set(e.callId, arr);
    }
  }
  const toolUseByCall = new Map<string, ManduEvent>();
  for (const e of ordered) {
    if (e.kind === "tool_use" && e.callId && !toolUseByCall.has(e.callId)) toolUseByCall.set(e.callId, e);
  }

  // ── pass 3: derivation closures → one flow per closure ─────────────────────
  const parentOf = new Map<string, string>();
  for (const s of syms.values()) {
    const p = s.ref.derivedFrom;
    if (p && syms.has(p)) parentOf.set(s.name, p);
  }
  const closureRootOf = (name: string): string => {
    let cur = name;
    const seen = new Set<string>();
    while (parentOf.has(cur) && !seen.has(cur)) {
      seen.add(cur);
      cur = parentOf.get(cur)!;
    }
    return cur;
  };
  const closures = new Map<string, string[]>();
  for (const name of syms.keys()) {
    const root = closureRootOf(name);
    const members = closures.get(root) ?? [];
    members.push(name);
    closures.set(root, members);
  }

  // ── pass 4: emit per-flow nodes + edges ─────────────────────────────────────
  const flows: SymbolLineage[] = [];
  for (const [root, members] of closures) {
    const nodes = new Map<string, LineageNode>();
    const edges: LineageEdge[] = [];
    const addNode = (n: LineageNode): LineageNode => {
      const existing = nodes.get(n.id);
      if (existing) return existing;
      nodes.set(n.id, n);
      return n;
    };

    let contextTurns = 0;
    let echoed = false;
    let shown = false;
    const verdicts: LineageVerdict[] = [];

    for (const name of members) {
      const s = syms.get(name)!;
      const symNode = addNode({
        id: `sym:${name}`,
        kind: "symbol",
        lane: s.quarantineBorn ? "Quarantine" : "AgentView",
        label: name,
        symbol: s.ref,
        minted: s.minted,
        ...(composedByModel(s) ? { modelAuthored: true } : {}),
        ...(s.contentKind ? { contentKind: s.contentKind } : {}),
        eventId: s.firstEvent.id,
        seq: s.firstEvent.seq,
        turn: s.firstEvent.turn,
      });

      // Birth: origin → symbol (only with a recorded mint — the evidence rule).
      if (s.minted && s.mintEvent) {
        const origin = s.ref.origin;
        const parent = s.ref.derivedFrom;
        if (parent && syms.has(parent)) {
          // Derivation edge (inspect or split) — parent symbol → this symbol.
          const kind: LineageEdgeKind =
            s.quarantineBorn || s.ref.tool === "inspect"
              ? "derived_inspect"
              : "derived_split";
          edges.push({ from: `sym:${parent}`, to: symNode.id, kind, eventId: s.mintEvent.id, seq: s.mintEvent.seq });
        } else if (origin) {
          const orgNode = addNode({
            id: `org:${origin}`,
            kind: "origin",
            lane: "External",
            label: short(origin),
            eventId: s.mintEvent.id,
            seq: s.mintEvent.seq,
            turn: s.mintEvent.turn,
          });
          edges.push({ from: orgNode.id, to: symNode.id, kind: "minted", eventId: s.mintEvent.id, seq: s.mintEvent.seq });
          // The fetching cause, when the mint is callId-correlated to a
          // T-LLM-authored tool call.
          const callId = s.mintEvent.callId;
          const fetcher = callId ? toolUseByCall.get(callId) : undefined;
          if (fetcher) {
            const fNode = addNode({
              id: `act:${callId}`,
              kind: "action",
              lane: "AgentView",
              label: short(fetcher.input?.symbolized ?? "tool call"),
              eventId: fetcher.id,
              seq: fetcher.seq,
              turn: fetcher.turn,
            });
            edges.push({ from: fNode.id, to: orgNode.id, kind: "fetched_by", eventId: s.mintEvent.id, seq: s.mintEvent.seq });
          }
        } else {
          edges.push({ from: addNode({
            id: `org:unknown:${name}`,
            kind: "origin",
            lane: "External",
            label: "(origin unrecorded)",
            eventId: s.mintEvent.id,
            seq: s.mintEvent.seq,
            turn: s.mintEvent.turn,
          }).id, to: symNode.id, kind: "minted", eventId: s.mintEvent.id, seq: s.mintEvent.seq });
        }
      }

      // Context presence, collapsed ×N per group.
      for (const g of s.contextGroups) {
        contextTurns += g.count;
        const cNode = addNode({
          id: `ctx:${name}:${g.first.id}`,
          kind: "context",
          lane: "AgentView",
          label: g.count > 1 ? `model context ×${g.count}` : "model context",
          count: g.count,
          eventId: g.first.id,
          seq: g.first.seq,
          turn: g.first.turn,
        });
        edges.push({ from: symNode.id, to: cNode.id, kind: "entered_context", eventId: g.first.id, seq: g.first.seq });
      }

      // Echoes into tool calls + the OS gates that decided them.
      const drawGate = (aNode: LineageNode, gate: ManduEvent): void => {
        const usage = gate.policy?.usage;
        const verdict: LineageVerdict =
          usage === "deny" ? "blocked" : usage === "needs_approval" ? "pending" : "allowed";
        verdicts.push(verdict);
        const sNode = addNode({
          id: `snk:${gate.boundary}:${gate.id}`,
          kind: "sink",
          lane: "HumanView",
          label: `${gate.boundary}: ${short(gate.output?.symbolized ?? gate.input?.symbolized ?? "", 40)}`,
          verdict,
          eventId: gate.id,
          seq: gate.seq,
          turn: gate.turn,
        });
        edges.push({ from: aNode.id, to: sNode.id, kind: "gated", verdict, eventId: gate.id, seq: gate.seq, ...askOn(gate, verdict) });
      };
      const echoedCallIds = new Set<string>();
      for (const tu of s.echoes) {
        echoed = true;
        if (tu.callId) echoedCallIds.add(tu.callId);
        const aNode = addNode({
          id: `act:${tu.callId ?? tu.id}`,
          kind: "action",
          lane: "AgentView",
          label: short(tu.input?.symbolized ?? "tool call"),
          eventId: tu.id,
          seq: tu.seq,
          turn: tu.turn,
        });
        edges.push({ from: symNode.id, to: aNode.id, kind: "echoed", eventId: tu.id, seq: tu.seq });
        for (const gate of tu.callId ? gatesByCall.get(tu.callId) ?? [] : []) {
          drawGate(aNode, gate);
        }
      }

      // Enforcement-side echoes: the gate event itself cites the symbol. Live,
      // a BLOCKED exec's tool_use records the REWRITTEN command — the token is
      // gone from it — so the exec_action's refs are the only echo evidence
      // left; without this join the gate's block never reaches the graph.
      for (const gate of s.gateHits) {
        if (gate.callId && echoedCallIds.has(gate.callId)) continue; // drawn via the tool_use echo
        echoed = true;
        const tu = gate.callId ? toolUseByCall.get(gate.callId) : undefined;
        const anchor = tu ?? gate;
        const aNode = addNode({
          id: `act:${gate.callId ?? gate.id}`,
          kind: "action",
          lane: "AgentView",
          label: short(tu?.input?.symbolized ?? gate.input?.symbolized ?? "tool call"),
          eventId: anchor.id,
          seq: anchor.seq,
          turn: anchor.turn,
        });
        edges.push({ from: symNode.id, to: aNode.id, kind: "echoed", eventId: gate.id, seq: gate.seq });
        drawGate(aNode, gate);
      }

      // Per-symbol network egress verdicts (the E28 shape).
      for (const n of s.netEgress) {
        verdicts.push(n.verdict);
        const sNode = addNode({
          id: `snk:net:${n.destination}`,
          kind: "sink",
          lane: "HumanView",
          label: short(n.destination, 40),
          verdict: n.verdict,
          eventId: n.e.id,
          seq: n.e.seq,
          turn: n.e.turn,
        });
        edges.push({ from: symNode.id, to: sNode.id, kind: "egress", verdict: n.verdict, eventId: n.e.id, seq: n.e.seq, ...askOn(n.e, n.verdict) });
      }

      // Arbiter egress queue rows (when emitted).
      for (const r of s.egressRequests) {
        verdicts.push(r.verdict);
        const sNode = addNode({
          id: `snk:egress:${r.e.id}`,
          kind: "sink",
          lane: "HumanView",
          label: short(r.e.input?.symbolized ?? "egress request", 40),
          verdict: r.verdict,
          eventId: r.e.id,
          seq: r.e.seq,
          turn: r.e.turn,
        });
        edges.push({ from: symNode.id, to: sNode.id, kind: "egress", verdict: r.verdict, eventId: r.e.id, seq: r.e.seq, ...askOn(r.e, r.verdict) });
      }

      // Reply-filter reveals collapse into ONE human sink per symbol. The
      // edge keeps the reply filter's "allowed", but the flow's outcome is
      // "shown", never a release: the person's own screen is not a send.
      // Only the reply filter's own events say that. A `desymbolize` from
      // any other emitter (a fill for a request, say) keeps the old reading,
      // a release, on its own sink: it may have left (fail-closed).
      const replies = s.reveals.filter((e) => e.emitter === "reply-filter");
      const fills = s.reveals.filter((e) => e.emitter !== "reply-filter");
      if (replies.length > 0) {
        const first = replies[0]!;
        shown = true;
        const hNode = addNode({
          id: `snk:human`,
          kind: "sink",
          lane: "HumanView",
          label: "human terminal",
          verdict: "allowed",
          eventId: first.id,
          seq: first.seq,
          turn: first.turn,
        });
        edges.push({ from: symNode.id, to: hNode.id, kind: "revealed_reply", verdict: "allowed", eventId: first.id, seq: first.seq });
      }
      if (fills.length > 0) {
        const first = fills[0]!;
        verdicts.push("allowed");
        const fNode = addNode({
          id: `snk:fill`,
          kind: "sink",
          lane: "HumanView",
          label: `real value filled in (${first.emitter})`,
          verdict: "allowed",
          eventId: first.id,
          seq: first.seq,
          turn: first.turn,
        });
        edges.push({ from: symNode.id, to: fNode.id, kind: "revealed_reply", verdict: "allowed", eventId: first.id, seq: first.seq });
      }
    }

    const rootState = syms.get(root)!;
    const worst: FlowSummary["terminal"] =
      verdicts.includes("blocked") || verdicts.includes("denied")
        ? "blocked"
        : verdicts.includes("pending")
          ? "pending"
          : verdicts.includes("approved")
            ? "approved"
            : verdicts.includes("allowed")
              ? "allowed"
              : shown
                ? "shown"
                : members.some((m) => syms.get(m)!.quarantineBorn)
                  ? "quarantined"
                  : contextTurns > 0
                    ? "context-only"
                    : "dormant";

    const flow: SymbolLineage = {
      root,
      nodes: [...nodes.values()].sort((a, b) => a.seq - b.seq),
      edges,
      summary: {
        root,
        originLabel: rootState.ref.origin,
        minted: rootState.minted,
        ...(composedByModel(rootState) ? { modelAuthored: true } : {}),
        contextTurns,
        echoed,
        terminal: worst,
      },
    };
    flow.summary.secret = isSecretFlow(flow);
    flows.push(flow);
  }

  flows.sort((a, b) => {
    const sa = syms.get(a.root)!.firstEvent;
    const sb = syms.get(b.root)!.firstEvent;
    return sa.ts !== sb.ts ? (sa.ts < sb.ts ? -1 : 1) : sa.seq - sb.seq;
  });

  const isComplete = (f: SymbolLineage): boolean =>
    f.summary.minted &&
    f.summary.contextTurns > 0 &&
    f.edges.some((e) => e.kind === "egress" || e.kind === "gated" || e.kind === "revealed_reply");

  const terminal = (f: SymbolLineage): string => f.summary.terminal;
  // The reply filter's reveal on the person's screen is not a release: it
  // counts as `shown` (any other emitter's reveal stays a release).
  const onScreen = (e: LineageEdge): boolean => e.kind === "revealed_reply" && e.to === "snk:human";
  const had = (f: SymbolLineage, ...vs: LineageVerdict[]): boolean =>
    f.edges.some((e) => !onScreen(e) && e.verdict !== undefined && vs.includes(e.verdict));
  // The stats count what Mandu masked: a token the model composed itself is
  // a flow (its row and card show the evidence), never a masked item.
  const items = flows.filter((f) => !f.summary.modelAuthored);
  const composed = flows.length - items.length;
  return {
    flows,
    stats: {
      flows: items.length,
      secret: items.filter(isSecretFlow).length,
      complete: items.filter(isComplete).length,
      egressAllowed: items.filter((f) => terminal(f) === "allowed" || terminal(f) === "approved").length,
      egressBlocked: items.filter((f) => terminal(f) === "blocked").length,
      egressPending: items.filter((f) => terminal(f) === "pending").length,
      outcomes: {
        allowed: items.filter((f) => had(f, "allowed")).length,
        approved: items.filter((f) => had(f, "approved")).length,
        blocked: items.filter((f) => had(f, "blocked", "denied")).length,
        pending: items.filter((f) => had(f, "pending")).length,
        shown: items.filter((f) => f.edges.some(onScreen)).length,
      },
      ...(composed ? { composed } : {}),
    },
  };
}

/** A result the AI read as it was that later requests carried masked
 *  (dual-lanes `maskedLater`: its first delivery held no token). */
export interface ReadBeforeMasked {
  deliveredTs: string;
  symbols: readonly string[];
}

/** `$MDU:tool[hash]` without its field path: a field token of a result and
 *  the result's own token name the same delivery. */
export function symbolBase(name: string): string {
  const i = name.indexOf("]");
  return i >= 0 ? name.slice(0, i + 1) : name;
}

/** When the AI first read each item as it was, before it was masked: the
 *  earliest `deliveredTs` of the `maskedLater` results naming it, keyed by
 *  `symbolBase`. The one rule `withReadFirst` and an Approvals card's words
 *  (dashboard.md §4.34) both read. Pure. */
export function readFirstByBase(later: readonly ReadBeforeMasked[]): Map<string, string> {
  const first = new Map<string, string>();
  for (const l of later) {
    for (const s of l.symbols) {
      const b = symbolBase(s);
      const ts = first.get(b);
      if (ts === undefined || l.deliveredTs < ts) first.set(b, l.deliveredTs);
    }
  }
  return first;
}

/** When the AI first read each FILE as it was, before it was masked: the
 *  earliest `deliveredTs` of the `maskedLater` results whose tokens came
 *  from it, keyed by the token's origin (`originOf`, the session's symbol
 *  rows). Only an absolute path counts: a program's request to read a secret
 *  file names its file so (an `open:`/`trust:` row's destination), and a web
 *  address or a command is no file. The rule `readFirstByBase` applies, by
 *  file, for an Approvals card about a program (dashboard.md §4.34). Pure. */
export function readFirstByFile(later: readonly ReadBeforeMasked[], originOf: (symbol: string) => string | null | undefined): Map<string, string> {
  const first = new Map<string, string>();
  for (const l of later) {
    for (const s of l.symbols) {
      const o = originOf(s);
      if (typeof o !== "string" || !o.startsWith("/")) continue;
      const ts = first.get(o);
      if (ts === undefined || l.deliveredTs < ts) first.set(o, l.deliveredTs);
    }
  }
  return first;
}

/** The flows whose content the AI had already read as it was when Mandu
 *  masked it (dashboard.md §4.15, "Read before it was masked"): each flow
 *  with a symbol that a `maskedLater` names, by base, gets `readFirst` (the
 *  earliest such delivery) and is counted in `stats.readFirst`, so no line
 *  says it was masked before the AI read it. A token the model composed
 *  itself shares its base with the symbol it extends, but is no item: it is
 *  left as it is. Pure; no input is changed. */
export function withReadFirst(lineage: SessionLineage, later: readonly ReadBeforeMasked[]): SessionLineage {
  const first = readFirstByBase(later);
  if (!first.size) return lineage;
  let n = 0;
  const flows = lineage.flows.map((f) => {
    if (f.summary.modelAuthored) return f;
    let ts: string | undefined;
    for (const node of f.nodes) {
      if (node.kind !== "symbol") continue;
      const t = first.get(symbolBase(node.id.replace(/^sym:/, "")));
      if (t !== undefined && (ts === undefined || t < ts)) ts = t;
    }
    if (ts === undefined) return f;
    n += 1;
    return { ...f, summary: { ...f.summary, readFirst: ts } };
  });
  return { flows, stats: { ...lineage.stats, readFirst: n } };
}

function pickRicher(a: SymbolRef, b: SymbolRef): Partial<SymbolRef> {
  return {
    value: a.value ?? b.value,
    origin: a.origin ?? b.origin,
    field: a.field ?? b.field,
  };
}

// ── Verdict copy (§9.1 shadow wording — phase 3) ─────────────────────────────

/** Human copy for a verdict, keyed to the enforcement mode: an observe-only
 *  (shadow) deployment reports what WOULD have happened — same graph, honest
 *  words (symbol-lineage.md §1, shadow mode). */
export function verdictCopy(verdict: LineageVerdict, enforced = true): string {
  if (enforced) {
    switch (verdict) {
      case "allowed": return "allowed";
      case "approved": return "approved by human";
      case "denied": return "denied";
      case "blocked": return "blocked";
      case "pending": return "awaiting approval";
    }
  }
  switch (verdict) {
    case "allowed": return "would have been allowed";
    case "approved": return "would have required approval (granted)";
    case "denied": return "would have been denied";
    case "blocked": return "would have been blocked";
    case "pending": return "would have required approval";
  }
}

/** A flow whose data is SECRET (the confidentiality axis) rather than
 *  untrusted: rooted at a secret twin, or carrying a secret level on any of
 *  its symbols. Level strings come from the arbiter; "public" and absent are
 *  the only non-secret answers (an unknown level counts as secret, the
 *  fail-closed reading the Secrets panel uses too). */
export function isSecretFlow(f: SymbolLineage): boolean {
  if (isSecretTwinName(f.root)) return true;
  return f.nodes.some((n) => {
    const level = n.symbol?.confidentiality;
    return typeof level === "string" && level !== "" && level !== "public";
  });
}

/** The items phrase of the plain-language register: each kind by its own
 *  word, so a secrets-mode session (rule (i) masks, nothing untrusted) never
 *  reads "untrusted items", and a full-mode session with both says both.
 *  Zero of everything keeps the old "0 untrusted items" (the axis that
 *  masks by default in every mode but secrets). */
export function itemsPhrase(stats: Pick<SessionFlowStats, "flows" | "secret">): string {
  const secret = Math.max(0, Math.min(stats.secret ?? 0, stats.flows));
  const untrusted = stats.flows - secret;
  const parts: string[] = [];
  if (untrusted > 0 || secret === 0) parts.push(`${untrusted} untrusted item${untrusted === 1 ? "" : "s"}`);
  if (secret > 0) parts.push(`${secret} secret item${secret === 1 ? "" : "s"}`);
  return parts.join(" and ");
}

/** What a tally of the "Where each went" rows says for one outcome: the
 *  rows' own chip words when enforced, the §9.1 shadow wording otherwise.
 *  "shown" reads the same in both: the reply filter did show it. */
export function outcomeCopy(outcome: keyof FlowOutcomes, enforced = true): string {
  if (outcome === "shown") return "shown to you in replies";
  if (!enforced) return verdictCopy(outcome, false);
  switch (outcome) {
    case "allowed": return "left with permission";
    case "approved": return "left with your approval";
    case "blocked": return "blocked from leaving";
    case "pending": return "waiting for your OK";
  }
}

/** When the items reached the AI masked: all of them first, or how many
 *  were masked first and how many the AI read as they were before. */
export function maskedPhrases(stats: Pick<SessionFlowStats, "flows" | "readFirst">): string[] {
  const read = Math.max(0, Math.min(stats.readFirst ?? 0, stats.flows));
  if (read === 0) return ["all masked before reaching the AI"];
  const masked = stats.flows - read;
  return [
    ...(masked > 0 ? [`${masked} masked before reaching the AI`] : []),
    `${read} read by the AI before ${read === 1 ? "it was" : "they were"} masked`,
  ];
}

/** The §9.1 flows-summary sentence, always visible in the lineage mode.
 *  Plain-language register (2026-07-16, dashboard.md §4.16 vocabulary rule):
 *  items are "masked", not "symbolized". It tallies the rows under it, by
 *  item: an item counts under every outcome it had (`stats.outcomes`), so
 *  "2 left with permission · 1 blocked from leaving" can describe 2 items
 *  (2026-10-05; it used to say "N attempts to send data out" over the items'
 *  worst outcomes, which hid a release behind a block and counted no
 *  attempt). An older payload without `outcomes` tallies the worst ones.
 *  The enforced/shadow flip stays in `outcomeCopy` — a shadow deployment
 *  still reads "1 would have been blocked". An item the AI read before it
 *  was masked (`stats.readFirst`) is never "masked before reaching the AI":
 *  "2 masked before reaching the AI · 1 read by the AI before it was
 *  masked" (2026-10-05). An item the reply filter showed on the person's
 *  screen is "shown to you in replies", last, never "left with permission"
 *  (2026-10-06): "1 left with permission · 3 shown to you in replies". */
export function flowsSummaryLine(stats: SessionFlowStats, enforced = true): string {
  const o: FlowOutcomes = stats.outcomes ?? {
    allowed: stats.egressAllowed, approved: 0, blocked: stats.egressBlocked, pending: stats.egressPending,
  };
  const parts = [itemsPhrase(stats), ...maskedPhrases(stats)];
  for (const k of ["allowed", "approved", "blocked", "pending", "shown"] as const) {
    const n = o[k] ?? 0;
    if (n > 0) parts.push(`${n} ${outcomeCopy(k, enforced)}`);
  }
  return parts.join(" · ");
}
