/**
 * why-symbol — `mandu why <symbol>` for a prompt finding
 * (confidentiality-plan-15-prompt-filter.md §11 phase 4, as built in §13.8).
 * Mandu-new (no reference origin).
 *
 * One question: "this `$MDU:` placeholder in the agent's reply or transcript,
 * where did it come from?" When the prompt filter made it (a span of the
 * person's own message, hidden from the model), the answer is the finding's
 * filter and category, its action and how a hold ended, the session and the
 * turn, the human verdicts that now cover it, and the policy row that decides
 * the category today. Built from what the arbiter already holds:
 *
 *   - the symbol table row: who minted it (tool `prompt_filter` for a span
 *     the filter minted; a registered secret keeps its own row), its level,
 *     its session; for a registered secret, the file path or the variable
 *     name it stands for (never the value);
 *   - the session logs' `prompt_filter` events that name the symbol, BELIEVED
 *     ones only (a `claimed: true` event is the sender's word,
 *     arbiter-human-plane.md §10.2: a program of the agent cannot make the
 *     answer say what it likes);
 *   - the Inbox rows (`prompt:<category>#<ref>` × `model:<session>[#turn:…]`)
 *     for those findings: held, answered, let through;
 *   - the effective `prompt_filters:` (the person's under the
 *     administrator's layer): the category's action now, who set it, a lock.
 *
 * NEVER the value: neither the span, nor the symbol row's value, nor an
 * event's panes (`input`/`output`, whose `original` can hold one) are read
 * into the answer; only the event's `promptFilter` detail fields are copied,
 * field by field. The op is HUMAN PLANE all the same (server.ts
 * `HUMAN_PLANE_OPS`): the session events it reads are human-plane facts
 * (`events`, `sessions`), so from the data socket a caller gets no more than
 * it gets today (`symbolProvenance`: the minting tool).
 *
 * Pure: the server hands in the row, the events, the rows and the config.
 */
import type { EgressApproval } from "../policy/egress-approvals.js";
import type { SymbolEntry } from "../symbol-table/symbol-table.js";
import { parsePromptRow, PROMPT_REF_RE } from "./holds.js";
import { coversCategory, lockedAction, lockedAsk, resolveAction, type EffectivePromptConfig } from "./policy.js";
import { REGISTERED_VALUE_CATEGORY, REGISTERED_VALUE_FILTER_ID } from "./registered-value-filter.js";

/** At most this many distinct findings (newest first). */
export const WHY_SYMBOL_MAX_FINDINGS = 10;
/** At most this many sessions are searched (the symbol's own first). */
export const WHY_SYMBOL_MAX_SESSIONS = 24;

/** A `$MDU:` name as the CLI may send it: the complete name, a field path allowed. */
export const WHY_SYMBOL_RE = /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[A-Za-z_][A-Za-z0-9_[\].]{0,255})?$/;

/** The tool a prompt-filter span's row is minted under (server.ts `mintPromptSymbol`). */
export const PROMPT_FILTER_TOOL = "prompt_filter";
/** The tool a side call masked whole is minted under (plan 13 §4.5.1, the !292 scan). */
export const SIDE_CALL_TOOL = "side_call";

/** One distinct finding that named the symbol (one message of one session). */
export interface WhySymbolFindingWire {
  session: string;
  /** The first and the latest request that carried it. */
  firstTs: string | null;
  lastTs: string | null;
  /** The T-LLM request index of the first request that carried it. */
  turn: number | null;
  /** How many requests carried it (an agent resends the conversation). */
  requests: number;
  agent: string;
  origin: "human" | "harness" | "side-call";
  filterId: string;
  category: string;
  /** The policy's action at the time: mask, ask, … (a span the human let
   *  through keeps its action and carries `let`). */
  action: string;
  /** The latest request's outcome for the segment. */
  segmentAction: "pass" | "rewrite" | "block";
  /** An `ask`'s hold, as the latest request recorded it. */
  hold?: { state: string; approvalId?: string };
  /** A human verdict let the span through as written. */
  let?: "once" | "session";
  /** False with the confidentiality axis off (logged only). */
  enforcing: boolean;
  /** The finding's opaque references (what a "let it through" names). */
  ref?: string;
  turnRef?: string;
}

/** A human verdict now on file for one of those findings (the Inbox row). */
export interface WhySymbolVerdictWire {
  approvalId: string;
  session: string;
  category: string;
  /** `message`: that one message (wherever resent); `session`: the span in the session. */
  scope: "message" | "session";
  /** `pending`: held, waiting for the human; `approved`: sent (or let) through
   *  as written; `denied`: sent masked, or cancelled. */
  status: "pending" | "approved" | "denied";
  resolvedAt: number | null;
}

/** The policy that decides a category now. */
export interface WhySymbolPolicyWire {
  category: string;
  action: string;
  /** The row that decides it (longest prefix), or null: the fallback. */
  row: string | null;
  setBy: "default" | "you" | "administrator";
  /** A locked administrator's row covers it (`lockedAction`). */
  locked: { action: string; file?: string } | null;
  /** A locked administrator's `ask` row covers it (`lockedAsk`, plan 15 §12,
   *  2026-10-04), even when another row decides the action: an answer or a
   *  "let it through" covers one message only. `file`: the row's file. */
  onceOnly?: { file?: string };
  /** Exceptions in force on this category (their globs stay in policy.yaml). */
  exceptions: number;
}

export interface WhySymbolOpResult {
  symbol: string;
  axis: boolean;
  /** The symbol table holds it. */
  known: boolean;
  /** What minted the row: `prompt-filter` (a span of a message the filter
   *  masked), `side-call` (a harness side call masked whole), `secret` (a
   *  registered secret: a file or a variable), `other` (a tool result and
   *  the like), `unknown` (no row). */
  source: "prompt-filter" | "side-call" | "secret" | "other" | "unknown";
  level: string | null;
  /** The row's tool (the minting chokepoint), null when unknown. */
  tool: string | null;
  /** A registered secret's file path or `env:<NAME>`; never a value. */
  origin: string | null;
  /** A structured secret's key name (`STRIPE_KEY`); never a value. */
  field: string | null;
  session: string | null;
  createdAt: number | null;
  obsolete: boolean;
  findings: WhySymbolFindingWire[];
  verdicts: WhySymbolVerdictWire[];
  policy: WhySymbolPolicyWire[];
  /** The filters the findings name: built in, a pattern pack or a plugin,
   *  and a pack's description. */
  filters: Array<{ id: string; kind: "built-in" | "pack" | "plugin"; description?: string }>;
  /** How many sessions were searched for findings. */
  searched: number;
}

/** The event fields read (a structural subset of the stored event). */
export interface WhySymbolEvent {
  id?: unknown;
  sessionId?: unknown;
  ts?: unknown;
  turn?: unknown;
  kind?: unknown;
  claimed?: unknown;
  promptFilter?: unknown;
}

const str = (v: unknown): string => (typeof v === "string" ? v : "");
const ORIGINS = ["human", "harness", "side-call"] as const;

/** The sessions to search, in order: the symbol's own, the caller's hint,
 *  then the most recently active sessions active since the symbol was
 *  minted (a registered value found in a prompt keeps the row of the session
 *  that registered it). Pure. */
export function whySymbolSessions(
  entry: Pick<SymbolEntry, "session_key" | "created_at"> | null,
  hint: string | undefined,
  sessions: ReadonlyArray<{ sessionId: string; lastTs: string | null }>,
  exclude: ReadonlySet<string>,
): string[] {
  const out: string[] = [];
  const add = (s: string | null | undefined): void => {
    if (typeof s === "string" && s !== "" && !exclude.has(s) && !out.includes(s) && sessions.some((x) => x.sessionId === s)) out.push(s);
  };
  add(entry?.session_key);
  add(hint);
  const since = entry ? entry.created_at - 60_000 : -Infinity;
  const recent = sessions
    .filter((s) => s.lastTs !== null && Date.parse(s.lastTs) >= since)
    .sort((a, b) => ((a.lastTs ?? "") < (b.lastTs ?? "") ? 1 : (a.lastTs ?? "") > (b.lastTs ?? "") ? -1 : 0));
  for (const s of recent) {
    if (out.length >= WHY_SYMBOL_MAX_SESSIONS) break;
    add(s.sessionId);
  }
  return out.slice(0, WHY_SYMBOL_MAX_SESSIONS);
}

function sourceOf(entry: SymbolEntry | null): WhySymbolOpResult["source"] {
  if (entry === null) return "unknown";
  if (entry.tool === PROMPT_FILTER_TOOL) return "prompt-filter";
  if (entry.tool === SIDE_CALL_TOOL) return "side-call";
  const o = entry.origin ?? "";
  if (entry.integrity === "trusted" && entry.confidentiality !== "public" && (o.startsWith("/") || o.startsWith("env:"))) return "secret";
  return "other";
}

/** The findings naming `symbol` in `events` (believed `prompt_filter` events
 *  only), one per message × category × filter, newest first. Pure. */
export function whySymbolFindings(symbol: string, events: Iterable<WhySymbolEvent>): WhySymbolFindingWire[] {
  const groups = new Map<string, WhySymbolFindingWire>();
  for (const e of events) {
    if (e.kind !== "prompt_filter" || e.claimed === true) continue;
    const d = e.promptFilter as Record<string, unknown> | null | undefined;
    if (!d || typeof d !== "object" || !Array.isArray(d["findings"])) continue;
    const session = str(e.sessionId);
    if (session === "") continue;
    const ts = typeof e.ts === "string" ? e.ts : null;
    const turnRef = typeof d["turn"] === "string" && PROMPT_REF_RE.test(d["turn"]) ? d["turn"] : undefined;
    const origin = (ORIGINS as readonly string[]).includes(str(d["origin"])) ? (d["origin"] as WhySymbolFindingWire["origin"]) : "harness";
    const segAction = d["action"] === "rewrite" || d["action"] === "block" ? d["action"] : "pass";
    for (const f of d["findings"] as Array<Record<string, unknown> | null>) {
      if (!f || f["symbol"] !== symbol) continue;
      const category = str(f["category"]);
      const filterId = str(f["filterId"]);
      const ref = typeof f["ref"] === "string" && PROMPT_REF_RE.test(f["ref"]) ? f["ref"] : undefined;
      // One message: its reference when the segment has one, else the event.
      const key = [session, turnRef ?? `event:${str(e.id)}`, category, filterId].join("\0");
      const hold = f["hold"] && typeof f["hold"] === "object" && typeof (f["hold"] as { state?: unknown }).state === "string"
        ? { state: (f["hold"] as { state: string }).state, ...(typeof (f["hold"] as { approvalId?: unknown }).approvalId === "string" ? { approvalId: (f["hold"] as { approvalId: string }).approvalId } : {}) }
        : undefined;
      const let_ = f["let"] === "once" || f["let"] === "session" ? f["let"] : undefined;
      const turn = typeof e.turn === "number" && Number.isFinite(e.turn) ? e.turn : null;
      const prev = groups.get(key);
      if (prev === undefined) {
        groups.set(key, {
          session, firstTs: ts, lastTs: ts, turn, requests: 1, agent: str(d["agent"]), origin, filterId, category,
          action: str(f["action"]), segmentAction: segAction, ...(hold ? { hold } : {}), ...(let_ ? { let: let_ } : {}),
          enforcing: d["enforcing"] === true, ...(ref ? { ref } : {}), ...(turnRef ? { turnRef } : {}),
        });
        continue;
      }
      prev.requests += 1;
      const later = ts !== null && (prev.lastTs === null || ts >= prev.lastTs);
      if (ts !== null && (prev.firstTs === null || ts < prev.firstTs)) {
        prev.firstTs = ts;
        prev.turn = turn;
      }
      if (later) {
        // The latest request's word on the segment, its hold and a let.
        prev.lastTs = ts;
        prev.action = str(f["action"]);
        prev.segmentAction = segAction;
        prev.enforcing = d["enforcing"] === true;
        if (hold) prev.hold = hold; else delete prev.hold;
        if (let_) prev.let = let_; else delete prev.let;
        if (ref) prev.ref = ref;
      }
    }
  }
  return [...groups.values()]
    .sort((a, b) => ((a.lastTs ?? "") < (b.lastTs ?? "") ? 1 : (a.lastTs ?? "") > (b.lastTs ?? "") ? -1 : 0))
    .slice(0, WHY_SYMBOL_MAX_FINDINGS);
}

/** The Inbox rows on file for `findings` (holds, answers, let-throughs). Pure. */
export function whySymbolVerdicts(findings: readonly WhySymbolFindingWire[], rows: readonly EgressApproval[]): WhySymbolVerdictWire[] {
  const out: WhySymbolVerdictWire[] = [];
  for (const row of rows) {
    const p = parsePromptRow(row);
    if (p === null) continue;
    const hit = findings.some((f) => f.ref === p.ref && f.category === p.category && f.session === p.session && (p.turn === undefined || p.turn === f.turnRef));
    if (!hit || out.some((v) => v.approvalId === row.id)) continue;
    out.push({ approvalId: row.id, session: p.session, category: p.category, scope: p.turn === undefined ? "session" : "message", status: row.status, resolvedAt: row.resolvedAt });
  }
  return out;
}

/** The policy that decides each category now. Pure. */
export function whySymbolPolicy(categories: Iterable<string>, cfg: EffectivePromptConfig): WhySymbolPolicyWire[] {
  const out: WhySymbolPolicyWire[] = [];
  for (const category of new Set(categories)) {
    if (category === "") continue;
    let row: EffectivePromptConfig["rows"][number] | null = null;
    for (const r of cfg.rows) if (coversCategory(r.category, category) && (row === null || r.category.length > row.category.length)) row = r;
    const locked = lockedAction(cfg, category);
    const once = lockedAsk(cfg, category);
    out.push({
      category,
      action: resolveAction(cfg, category),
      row: row?.category ?? null,
      setBy: row?.setBy ?? "default",
      locked: locked ? { action: locked.action, ...(locked.file ? { file: locked.file } : {}) } : null,
      ...(once !== null ? { onceOnly: once.file ? { file: once.file } : {} } : {}),
      exceptions: cfg.exceptions.filter((e) => e.inForce && coversCategory(e.category, category)).length,
    });
  }
  return out;
}

/** The whole answer. Pure. */
export function whySymbol(args: {
  symbol: string;
  axis: boolean;
  entry: SymbolEntry | null;
  events: Iterable<WhySymbolEvent>;
  rows: readonly EgressApproval[];
  config: EffectivePromptConfig;
  /** The filters known now (id, kind, a pack's description). */
  filters?: ReadonlyArray<{ id: string; kind: "built-in" | "pack" | "plugin"; description?: string }>;
  searched: number;
}): WhySymbolOpResult {
  const { entry } = args;
  const source = sourceOf(entry);
  const findings = whySymbolFindings(args.symbol, args.events);
  const named = new Set(findings.map((f) => f.filterId));
  return {
    symbol: args.symbol,
    axis: args.axis,
    known: entry !== null,
    source,
    level: entry?.confidentiality ?? null,
    tool: entry?.tool ?? null,
    // A registered secret's path or variable name, never anything else the
    // origin column may hold for another row (a URL, a command).
    origin: source === "secret" ? entry!.origin : null,
    field: source === "secret" ? entry!.field : null,
    session: entry?.session_key ?? null,
    createdAt: entry?.created_at ?? null,
    obsolete: entry !== null && entry.obsoleted_at !== null,
    findings,
    verdicts: whySymbolVerdicts(findings, args.rows),
    policy: whySymbolPolicy(findings.map((f) => f.category), args.config),
    filters: (args.filters ?? []).filter((f) => named.has(f.id)).map((f) => ({ id: f.id, kind: f.kind, ...(f.description !== undefined ? { description: f.description } : {}) })),
    searched: args.searched,
  };
}

/** A finding the prompt filter's own policy can never let through: a value
 *  Mandu holds as a secret (its own release paths apply). */
export function isRegisteredPromptFinding(f: Pick<WhySymbolFindingWire, "filterId" | "category">): boolean {
  return f.filterId === REGISTERED_VALUE_FILTER_ID || coversCategory(REGISTERED_VALUE_CATEGORY, f.category);
}
