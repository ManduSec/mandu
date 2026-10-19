/**
 * view-model/paired-rows — §4.2f the paired-rows trace (2026-09-26): the
 * dual lanes regrouped so one row is one step, with "what the AI saw" on
 * the left and "what really happened" on the right of the SAME row.
 *
 * Mandu-new (no reference origin). WHY: a 15-session review of the §4.2c
 * lane mode found that 65% of its rows were OS cards and 92% of those either
 * repeated a fact a tool card already showed (path mappings, reply-filter
 * resolutions, the U-LLM call record, allowed command checks) or were
 * background connections (model API, plugins, telemetry); a one-question
 * session was 1,758 px tall; and a masked file read (a twin read, the most
 * common untrusted ingress) left the HumanView lane EMPTY, so the reader never
 * saw what the AI was kept from reading. This module is a pure projection of
 * the existing `DualLanesModel` (toDualLanes stays the dedupe/order source of
 * truth) into:
 *   - turns, one per user prompt (plus a leading setup turn), in step order;
 *   - rows that REFERENCE steps by id (the browser renders the step), each
 *     carrying the classification the browser must not re-derive: masked or
 *     not, the deep original of a masked result, whether trust was checked;
 *   - a per-turn background fold (counts + step ids, so every folded card's
 *     ⓘ drawer stays one click away).
 *
 * Originals ship to the privileged dashboard only (the same values the lane
 * bands and the symbol card already ship); nothing here flows toward T-LLM.
 * Local resolution is fixpoint substitution over the session's own recorded
 * values (unknown tokens stay tokens: fail toward symbolic, never fabricate);
 * `revealPairedOriginals` then deepens what is still tokened through the
 * arbiter's `desymbolize`, like the delivered-reply reveal (delivery.ts).
 */

import { readByWords, type ModelEndpointRef } from "./model-endpoints.js";
import {
  matchSymbols,
  type DualLanesModel,
  type DualOsStep,
  type DualResponseStep,
  type DualStep,
  type DualToolStep,
} from "./dual-lanes.js";
import type { Desymbolizer } from "./delivery.js";
import { echoedTokens } from "./held-tokens.js";
import { inspectAnswer, isInspectCall } from "./inspect-answer.js";
import { refusedReadWords } from "./secret-note.js";
import type { SymbolInspectorRow } from "./symbols.js";

/** What the background fold groups. */
export type BackgroundCategory =
  | "connections"     // allowed network traffic (model API, plugins, telemetry, fetches)
  | "paths"           // uncorrelated path_rewrite (the view-map at work)
  | "reply-checks"    // reply-filter resolutions in the human's terminal
  | "sandbox-records" // the U-LLM call record of an inspect_symbol row already shown
  | "command-checks"; // allowed exec checks

export interface BackgroundGroup {
  category: BackgroundCategory;
  /** Folded actions, counting each card's own `repeats`. */
  count: number;
  /** Distinct destinations (connections only), in first-seen order. */
  labels: string[];
  /** The folded OS steps, so the browser can list them with their ⓘ drawers. */
  stepIds: string[];
}

/** An inspect_symbol call, unpacked for the paired row. */
export interface PairedInspect {
  instruction: string | null;
  /** The symbol the AI asked about, and its deep original. */
  inputSymbol: string | null;
  inputOriginal: string | null;
  /** The token the AI got back, and the answer it stands for. */
  answerSymbol: string | null;
  answerOriginal: string | null;
  /** What the AI's result held after the answer (an agent's appended note,
   *  kept or masked: inspect-answer.ts). Absent when there was none. */
  tail?: string;
  /** Plan 11 D6: which model read the datum, and the words for it ("read by
   *  your own model (ollama)" / "read by the helper"). Both absent when the
   *  inspect event predates the `endpoint` field. */
  readBy?: ModelEndpointRef;
  readByWords?: string;
}

export type PairedRow =
  /** The fs-sync workspace seed: one line, file names instead of token names. */
  | { row: "setup"; stepId: string; files: string[] }
  /** An interim AI message (narration before or between tool calls). */
  | { row: "note"; stepId: string }
  /** The turn's reply. `original` = the text with its tokens resolved (what
   *  the reply-filter showed the human), null when the text carried none. */
  | { row: "reply"; stepId: string; original: string | null }
  /** A prose model call outside the conversation (a /compact summary): kept,
   *  but folded — it is not something the AI said to the human. */
  | { row: "aside"; stepId: string; chars: number }
  | PairedToolRow
  /** An OS card that stays inline: a block, a denial, a violation, an
   *  uncorrelated fs action — anything that is a decision, not bookkeeping. */
  | { row: "action"; stepId: string };

export interface PairedToolRow {
  row: "tool";
  stepId: string;
  /** The AI received at least one token in place of the result: any token
   *  but one proven an echo (held-tokens.ts `echoedTokens`). */
  masked: boolean;
  /** On a row that is not masked: the placeholders its result only repeats
   *  as the AI sent them in its call (Mandu's refusal naming the token it
   *  withheld). Absent when there are none. */
  echoed?: string[];
  /** Mandu refused programs' reads of secret files on this call (the step's
   *  `readRefused`): what it did, in the session page's words (secret-note.ts
   *  `refusedReadWords`). Absent otherwise. */
  refusedRead?: string;
  /** Deep original of what the AI received (masked rows); null otherwise. */
  original: string | null;
  /** The view-map translated a path for this call. */
  pathMapped: boolean;
  /** False when the result was never classified (integrity axis OFF). */
  checked: boolean;
  /** inspect_symbol only. */
  inspect: PairedInspect | null;
  /** On a violated step: the raw text the proxy's leak check found in the
   *  forwarded request (the step's original result). */
  flaggedValue: string | null;
}

export interface PairedTurn {
  /** "turn:start" for the leading setup group, else "turn:" + the input step id. */
  id: string;
  /** The user prompt's step id; null for the setup group. */
  inputId: string | null;
  rows: PairedRow[];
  background: BackgroundGroup[];
}

export type ProtectionMode = "secrets" | "injection" | "full" | "off";

/** The protection the launcher recorded on `launch_posture.protection`
 *  (launcher services/observe.ts), when the arbiter itself reported it. */
export interface RecordedProtection {
  mode: ProtectionMode;
  integrity: boolean;
}

export interface PairedModel {
  /** Whether this session's tool results were trust-classified. From the
   *  launcher's recorded protection when present; else inferred: "off" when
   *  the arbiter answered with the integrity-axis-OFF reason, "on" when any
   *  result was classified, "unknown" with no tool results. */
  integrity: "on" | "off" | "unknown";
  /** The recorded protection mode; null for a session that did not record
   *  one (older launcher, proxy-only session, arbiter that did not report). */
  mode: ProtectionMode | null;
  /** Tool rows whose result reached the AI as a token. */
  maskedCount: number;
  turns: PairedTurn[];
}

/** The arbiter's classification reason when the integrity axis is OFF
 *  (arbiter/policy/policy-interface.ts), as recorded: bare, or behind the
 *  anthropic-proxy's prefix for a secret it masked by provenance
 *  (rewrite-request.ts: "secret content (no-model) symbolized by
 *  provenance: integrity axis OFF — …"). That result was masked as a
 *  secret, not judged: its TRUSTED is the axis's default. Only that prefix,
 *  so a reason that merely mentions the phrase stays a classification. */
const INTEGRITY_OFF_RE = /^(?:secret content \([^)]*\) symbolized by provenance: )?integrity axis OFF\b/;
/** Claude Code's context-compaction summary: an analysis block, then a
 *  summary block. It rides a call that still EXTENDS the conversation (the
 *  harness replays history into it), so the call class cannot catch it. */
const COMPACTION_RE = /^\s*<analysis>[\s\S]*<summary>/;
const SYM_RE_G = /\$MDU:\w+\[\w+\](?:\.\w+)*/g;
const SYM_RE = /\$MDU:\w+\[\w+\](?:\.\w+)*/;

/** Fixpoint-substitute known values; unknown tokens stay tokens. */
export function collapseTokens(text: string, table: Map<string, string>): string {
  let cur = text;
  for (let i = 0; i < 8; i++) {
    const next = cur.replace(SYM_RE_G, (m) => table.get(m) ?? m);
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

function valueTable(dual: DualLanesModel, symbols: SymbolInspectorRow[]): Map<string, string> {
  const t = new Map<string, string>();
  for (const r of symbols) if (r.value != null && !t.has(r.name)) t.set(r.name, r.value);
  for (const s of dual.steps) {
    const bands = s.step === "tool" ? [...s.upSyms, ...s.downSyms] : s.step === "response" ? s.symbols : [];
    for (const b of bands) if (b.value !== null && !t.has(b.name)) t.set(b.name, b.value);
  }
  return t;
}

function parseJson(text: string | null): Record<string, unknown> | null {
  if (!text) return null;
  try {
    const j = JSON.parse(text) as unknown;
    return j && typeof j === "object" && !Array.isArray(j) ? (j as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

function isInspect(t: DualToolStep): boolean {
  return isInspectCall(t.tool);
}

function toolRow(t: DualToolStep, table: Map<string, string>): PairedToolRow {
  const checked = !INTEGRITY_OFF_RE.test(t.reason ?? "");
  const flaggedValue = t.violated ? t.resultHuman : null;
  if (isInspect(t)) {
    const args = parseJson(t.input);
    // The answer from the result's head, in any shape the agent forwarded.
    const res = inspectAnswer(t.resultAgent);
    const inputSymbol = str(args?.["symbol"]);
    const answerSymbol = res?.answer ?? null;
    // The U-LLM output's result_symbol holds the answer itself when the
    // quarantine recorded it; else resolve the token like any other.
    const rawAnswer = inspectAnswer(t.resultHuman)?.answer ?? null;
    const answerOriginal = rawAnswer && rawAnswer !== answerSymbol
      ? rawAnswer
      : answerSymbol ? collapseTokens(answerSymbol, table) : null;
    return {
      row: "tool", stepId: t.id,
      masked: answerSymbol !== null && SYM_RE.test(answerSymbol),
      original: answerOriginal, pathMapped: t.pathRewrites.length > 0, checked,
      inspect: {
        instruction: str(args?.["instruction"]),
        inputSymbol,
        inputOriginal: inputSymbol ? collapseTokens(inputSymbol, table) : null,
        answerSymbol,
        answerOriginal,
        ...(res?.tail ? { tail: res.tail } : {}),
        ...(t.readBy ? { readBy: t.readBy, readByWords: readByWords(t.readBy)! } : {}),
      },
      flaggedValue,
    };
  }
  // Masked = a token in what the AI got that the result kept from it. One the
  // call itself sent, which the tool's own result holds as written (Mandu's
  // refusal naming the placeholder it withheld), is an echo: the AI got what
  // the tool printed, so the row is one card, not two halves (§4.2f). Any
  // token not proven an echo (another spelling of the grammar included)
  // keeps the masked reading.
  const echoes = new Set(echoedTokens(t));
  const masked = matchSymbols(t.resultAgent).some((n) => !echoes.has(n));
  const echoed = masked ? [] : [...echoes];
  return {
    row: "tool", stepId: t.id, masked,
    original: masked && t.resultAgent !== null ? collapseTokens(t.resultAgent, table) : null,
    pathMapped: t.pathRewrites.length > 0, checked, inspect: null, flaggedValue,
    ...(echoed.length ? { echoed } : {}),
    ...(t.readRefused ? { refusedRead: refusedReadWords(t.readRefused) } : {}),
  };
}

/** Where an uncorrelated OS card goes: a background category, or null to
 *  keep it inline. Anything violated, denied or blocked is a decision and
 *  stays inline. */
function backgroundOf(s: DualOsStep, hasInspectRow: boolean): BackgroundCategory | null {
  if (s.violated) return null;
  if (s.usage === "deny" || s.usage === "needs_approval") return null;
  switch (s.kind) {
    case "path_rewrite":
      return "paths";
    case "desymbolize":
      return s.title.startsWith("user reply") ? "reply-checks" : null;
    case "ullm_call":
      return hasInspectRow ? "sandbox-records" : null;
    case "net_action":
      // A send that carried a masked item (its real value filled in) is a
      // moment data left this machine: a step, never background.
      if (s.carried?.length) return null;
      return s.action === null || /^(tunneled|forwarded|passthrough|allow(ed)?)$/.test(s.action) ? "connections" : null;
    case "exec_action":
      return s.usage === "allow" || s.usage === null ? "command-checks" : null;
    default:
      return null;
  }
}

function fold(turn: PairedTurn, cat: BackgroundCategory, s: DualOsStep): void {
  let g = turn.background.find((b) => b.category === cat);
  if (!g) {
    g = { category: cat, count: 0, labels: [], stepIds: [] };
    turn.background.push(g);
  }
  g.count += s.repeats;
  g.stepIds.push(s.id);
  if (cat === "connections") {
    const host = (s.target ?? "").replace(/:443$/, "");
    if (host && !g.labels.includes(host)) g.labels.push(host);
  }
}

function setupFiles(s: DualOsStep, byName: Map<string, SymbolInspectorRow>): string[] {
  return (s.newSymbols ?? []).map((n) => {
    const r = byName.get(n);
    return r?.field ?? r?.origin?.split("/").pop() ?? n;
  });
}

const MODES: readonly string[] = ["secrets", "injection", "full", "off"];

/** The session's recorded protection: the FIRST `launch_posture` event's
 *  `protection`, used only when the arbiter itself reported the axes (a
 *  launch-side guess is no better than the inference it would replace). */
export function recordedProtection(events: readonly { kind: string }[]): RecordedProtection | null {
  const posture = events.find((e) => e.kind === "launch_posture") as { protection?: unknown } | undefined;
  const p = posture?.protection as { mode?: unknown; integrity?: unknown; reported?: unknown } | undefined;
  if (!p || p.reported !== true || typeof p.integrity !== "boolean") return null;
  if (typeof p.mode !== "string" || !MODES.includes(p.mode)) return null;
  return { mode: p.mode as ProtectionMode, integrity: p.integrity };
}

/**
 * THE paired-rows projection (pure). `symbols` = the session's symbol
 * inspector rows (the fs-sync seed births carry the twin originals);
 * `protection` = the launcher's recorded mode, when the session has one.
 */
export function toPairedTurns(
  dual: DualLanesModel,
  symbols: SymbolInspectorRow[],
  protection: RecordedProtection | null = null,
): PairedModel {
  const table = valueTable(dual, symbols);
  const byName = new Map(symbols.map((r) => [r.name, r]));
  const hasInspectRow = dual.steps.some((s) => s.step === "tool" && isInspect(s));

  let integrity: PairedModel["integrity"] = "unknown";
  if (protection) {
    integrity = protection.integrity ? "on" : "off";
  } else {
    for (const s of dual.steps) {
      if (s.step !== "tool" || s.trust === null) continue;
      if (INTEGRITY_OFF_RE.test(s.reason ?? "")) { if (integrity === "unknown") integrity = "off"; }
      else integrity = "on";
    }
  }

  const turns: PairedTurn[] = [{ id: "turn:start", inputId: null, rows: [], background: [] }];
  const isAside = (s: DualResponseStep): boolean => COMPACTION_RE.test(s.text);

  for (const s of dual.steps as DualStep[]) {
    if (s.step === "input") {
      turns.push({ id: "turn:" + s.id, inputId: s.id, rows: [], background: [] });
      continue;
    }
    const turn = turns[turns.length - 1]!;
    if (s.step === "response") {
      turn.rows.push(isAside(s) ? { row: "aside", stepId: s.id, chars: s.text.length } : { row: "note", stepId: s.id });
    } else if (s.step === "tool") {
      turn.rows.push(toolRow(s, table));
    } else if (s.kind === "symbolize" && s.newSymbols?.length) {
      turn.rows.push({ row: "setup", stepId: s.id, files: setupFiles(s, byName) });
    } else {
      const cat = backgroundOf(s, hasInspectRow);
      if (cat) fold(turn, cat, s);
      else turn.rows.push({ row: "action", stepId: s.id });
    }
  }

  // The LAST AI message of each turn is its reply; earlier ones are notes.
  const stepById = new Map(dual.steps.map((s) => [s.id, s]));
  for (const turn of turns) {
    for (let i = turn.rows.length - 1; i >= 0; i--) {
      const r = turn.rows[i]!;
      if (r.row !== "note") continue;
      const step = stepById.get(r.stepId) as DualResponseStep;
      const original = matchSymbols(step.text).length ? collapseTokens(step.text, table) : null;
      turn.rows[i] = { row: "reply", stepId: r.stepId, original };
      break;
    }
  }

  const kept = turns.filter((t) => t.inputId !== null || t.rows.length || t.background.length);
  const maskedCount = kept.reduce(
    (n, t) => n + t.rows.filter((r) => r.row === "tool" && r.masked).length, 0,
  );
  return { integrity, mode: protection?.mode ?? null, maskedCount, turns: kept };
}

/**
 * Deepen every paired original that still carries a token through the
 * arbiter (deep/fixpoint `desymbolize`, the reply-filter's egress). Utility-
 * only posture, like revealDeliveredReply: a failed or unchanged answer keeps
 * the locally collapsed text (symbols stay opaque). Bounded so a huge session
 * cannot turn one page load into hundreds of IPC round trips. Returns how many
 * texts were deepened.
 */
export async function revealPairedOriginals(
  paired: PairedModel,
  desymbolize?: Desymbolizer,
  max = 200,
): Promise<number> {
  if (!desymbolize) return 0;
  let n = 0;
  let budget = max;
  const deepen = async (text: string | null): Promise<string | null> => {
    if (text === null || !SYM_RE.test(text) || budget <= 0) return text;
    budget--;
    try {
      const out = await desymbolize(text);
      if (out !== text) { n++; return out; }
    } catch {
      /* display fidelity only — keep the local text */
    }
    return text;
  };
  for (const t of paired.turns) {
    for (const r of t.rows) {
      if (r.row === "reply") r.original = await deepen(r.original);
      if (r.row !== "tool") continue;
      r.original = await deepen(r.original);
      if (r.inspect) {
        r.inspect.inputOriginal = await deepen(r.inspect.inputOriginal);
        r.inspect.answerOriginal = await deepen(r.inspect.answerOriginal);
      }
    }
  }
  return n;
}
