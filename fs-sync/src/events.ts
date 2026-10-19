/**
 * events — fs-sync's symbol-BIRTH event emission (symbol-lineage.md G1).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. The builder mirrors the canonical event shape of
 *   interceptors/anthropic-proxy/src/events.ts (`makeSymbolize`/`baseEvent`)
 *   field-for-field, and the schema documented in dashboard/src/event-model.ts.
 *   Deliberately a LOCAL mirror — fs-sync does not import the dashboard or the
 *   proxy (each package typechecks standalone; the wire is plain JSON).
 *
 * WHY THIS EXISTS: event emission is CALLER-side (design D1 — the caller has
 * the context the arbiter lacks at op time), and until this module the model
 * proxies were the only callers that emitted. Every fs-sync mint — the seeded
 * AgentView twin, the on-demand read, the human-edit split — was therefore
 * INVISIBLE to the event stream, so the dashboard's lineage view could show a
 * symbol flowing through a session whose birth was never recorded (gap G1).
 *
 * OBSERVABILITY ONLY, BEST-EFFORT: emission failures are swallowed (never on
 * the security path — a lost birth event means a degraded trace, never a
 * leak), and a mint with no session to file the event under is skipped (the
 * event log is per-session; a birth without a session has no home).
 */

import type { SymbolArbiter } from "./arbiter-client.js";

/** Minimal local mirror of the canonical ManduEvent for the one kind fs-sync
 *  emits. The dashboard's tolerant read path (`coerceEvent`) accepts it as-is. */
export interface FsSyncSymbolRef {
  name: string;
  tool: string;
  field: string | null;
  origin: string | null;
  value: string | null;
  derivedFrom?: string;
  lineRange?: string;
}

export interface FsSyncDualRepr {
  symbolized: string;
  original: string | null;
  differs: boolean;
  symbols: FsSyncSymbolRef[];
}

export interface FsSyncBirthEvent {
  id: string;
  sessionId: string;
  turn: number;
  ts: string;
  seq: number;
  callId: string | null;
  parentId: null;
  kind: "symbolize";
  view: "AgentView";
  boundary: "filesystem";
  emitter: "fs-sync";
  input: FsSyncDualRepr;
  output: FsSyncDualRepr;
  invariant: { violatedInvariant: false };
}

/** Monotonic-ish unique id without a ULID dependency — same scheme as the
 *  proxy's newEventId (time prefix + counter + random suffix). */
let _idCounter = 0;
export function newEventId(): string {
  const t = Date.now().toString(36).padStart(9, "0");
  const c = (_idCounter++ & 0xffffff).toString(36).padStart(5, "0");
  const r = Math.floor(Math.random() * 0xffffff).toString(36).padStart(5, "0");
  return `ev_${t}${c}${r}`;
}

export interface BirthEventArgs {
  sessionKey: string;
  symbol: string;
  /** Raw untrusted value behind the symbol. Goes ONLY to the privileged event
   *  log (the arbiter's per-session NDJSON), never toward the AgentView. */
  original: string;
  tool: string;
  field?: string;
  origin?: string;
  callId?: string;
  /** Parent symbol for a derived mint (human-edit split). */
  derivedFrom?: string;
  /** End-exclusive `start:end` span within the parent value. */
  lineRange?: string;
}

/** Build the canonical `symbolize` birth event for an fs-sync mint. Mirrors
 *  the proxy's makeSymbolize: input = the raw value, output = the symbol it
 *  became, with the full provenance ref folded in. The agent reads only the
 *  symbol, so that is the input's AgentView (`symbolized`) form too; the raw
 *  value sits only in `original` (dashboard.md §6: the signed-out projection
 *  keeps every `symbolized`). */
export function makeBirthEvent(a: BirthEventArgs): FsSyncBirthEvent {
  const ref: FsSyncSymbolRef = {
    name: a.symbol,
    tool: a.tool,
    field: a.field ?? null,
    origin: a.origin ?? null,
    value: a.original,
    ...(a.derivedFrom !== undefined ? { derivedFrom: a.derivedFrom } : {}),
    ...(a.lineRange !== undefined ? { lineRange: a.lineRange } : {}),
  };
  return {
    id: newEventId(),
    sessionId: a.sessionKey,
    turn: 0,
    ts: new Date().toISOString(),
    seq: 0,
    callId: a.callId ?? null,
    parentId: null,
    kind: "symbolize",
    view: "AgentView",
    boundary: "filesystem",
    emitter: "fs-sync",
    input: { symbolized: a.symbol, original: a.original, differs: a.symbol !== a.original, symbols: [] },
    output: { symbolized: a.symbol, original: a.original, differs: true, symbols: [ref] },
    invariant: { violatedInvariant: false },
  };
}

/**
 * Best-effort birth emission: no `emit` capability or no session → silently
 * skip; an emit error is swallowed. NEVER throws — callers sit on the mint
 * path, and a trace gap must not become a mint failure.
 */
export async function emitBirth(
  arbiter: SymbolArbiter,
  args: Omit<BirthEventArgs, "sessionKey"> & { sessionKey?: string },
): Promise<void> {
  if (arbiter.emit === undefined || !args.sessionKey) return;
  try {
    await arbiter.emit(makeBirthEvent({ ...args, sessionKey: args.sessionKey }));
  } catch {
    // Best-effort by contract (see module header).
  }
}
