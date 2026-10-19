/**
 * arbiter-client — the arbiter dependency the inspect_symbol MCP server speaks to.
 *
 * Mandu M4 cooperative U-LLM path (interceptors/inspect-mcp). The MCP server
 * never opens the symbol-table DB directly: the arbiter (arbiter/) is the single
 * owner of the symbol table + policy engine + event stream, and we call it over
 * its Unix-socket NDJSON IPC. This module defines the NARROW interface the
 * inspect_symbol tool needs (`Arbiter`) plus a thin adapter
 * (`ArbiterClientAdapter`) that fulfils it via the real arbiter IPC client
 * (arbiter/ipc/client.ts).
 *
 * Decoupling rationale (mirrors interceptors/anthropic-proxy/src/arbiter-client.ts):
 * the tool is written against `Arbiter`, not the concrete client. Tests inject a
 * MockArbiter (test/helpers/mock-arbiter.ts) so the suite does not depend on the
 * arbiter daemon — nor on the arbiter `emit` op, which the arbiter sub-agent is
 * adding in parallel — actually landing.
 *
 * The op shapes mirror arbiter/ipc/protocol.ts and arbiter/ipc/client.ts exactly:
 *   - resolve(symbol)                                  → string | null
 *   - symbolize({tool, value, field?, origin?, ...})   → symbol string
 *   - emit(event)                                      → {seq}   (NEW arbiter op)
 *   - modelEndpoints()                                 → ModelEndpoint[]  (Plan 11 D5)
 *
 * `emit` is the NEW op the arbiter sub-agent is adding in parallel; we code
 * against its agreed contract here:  req `{op:"emit", event}` → `{seq}`.
 */

import type { ManduEvent } from "./event-model.js";

/** Mirrors arbiter/ipc/protocol.ts `SymbolizeRequest` (minus id/op). */
export interface SymbolizeArgs {
  tool: string;
  value: string;
  field?: string;
  origin?: string;
  sessionKey?: string;
  callId?: string;
  /** Parent symbol name for a derived value (symbol-lineage.md G2): the
   *  re-symbolized U-LLM result names the inspected input symbol here so the
   *  table's derived_from matches the event-side SymbolRef.derivedFrom. */
  derivedFrom?: string;
}

/**
 * One declared model endpoint (Plan 11 D2): an entry of policy.yaml `models:`,
 * served by the arbiter's `modelEndpoints` op (`{op:"modelEndpoints"}` →
 * `{endpoints}`). The list is LAW read from the arbiter, never from this
 * process's env. `local: true` is the operator's declaration that the
 * endpoint is their own model (never inferred from a loopback address);
 * every endpoint NOT on the list, including the default U-LLM, is external.
 * `tokenEnv` NAMES an environment variable holding the endpoint's token; the
 * token itself never travels over the IPC.
 */
export interface ModelEndpoint {
  name: string;
  url: string;
  wire: "anthropic" | "openai-chat";
  model?: string;
  local: boolean;
  tokenEnv?: string;
  /** policy.yaml `helper: true` (present only when true): the helper's model. */
  helper?: true;
  /** policy.yaml `allow_plain_http: true` (plan 12 D2, present only when
   *  true): plain http to this entry on another machine is accepted. */
  allowPlainHttp?: true;
  /** policy.yaml `tls:` (plan 12 D3): absolute paths and pins, only the
   *  fields given. Checked strictly before use (endpoint-tls.ts asTlsConfig). */
  tls?: { caFile?: string; pinSha256?: readonly string[]; clientCert?: string; clientKey?: string };
  /** policy.yaml `perimeter.networks` (plan 12 D4), on a `local: true` entry
   *  on another machine: every address the name resolves to must be inside
   *  one of these CIDRs, at every connection (endpoint-tls.ts). */
  perimeter?: readonly string[];
  /** The host is under one of `perimeter.domains` (words only). */
  orgDomain?: true;
}

/** Per-call resolve options on the narrow seam. `endpoint` names the declared
 *  model endpoint the resolved bytes are bound for (Plan 11 D4); the arbiter
 *  derives the location from ITS OWN registry (undeclared ⇒ external) and
 *  admits the level there. Absent ⇒ today's behavior (external). */
export interface ResolveOptions {
  endpoint?: string;
}

/** Mirrors arbiter/ipc/protocol.ts `SymbolProvenanceResult` — the tool call
 *  that produced a symbol's value (symbol-quality.md §4.1 v2). toolName /
 *  toolInput are T-LLM-AUTHORED (the privileged principal's own call), not
 *  untrusted data. */
export interface SymbolProvenance {
  tool: string | null;
  callId: string | null;
  toolName: string | null;
  toolInput?: unknown;
}

/**
 * The narrow arbiter surface the inspect_symbol tool depends on. Anything that
 * satisfies this — the real adapter or a mock — can drive the tool.
 */
export interface Arbiter {
  /** Resolve one symbol name to its raw value, or null if the symbol is
   *  unknown. Unknown symbols are REFUSED by the tool (never processed).
   *  Implementations must return FULL-FIDELITY data (nested symbol chains
   *  collapsed — the adapter passes `deep` to the arbiter): the quarantined
   *  U-LLM processes original content, never `$MDU:*` placeholders.
   *  `opts.endpoint` (Plan 11 D4) names the declared model endpoint the value
   *  is bound for; the arbiter admits the level at that endpoint only. */
  resolve(symbol: string, opts?: ResolveOptions): Promise<string | null>;
  /** OPTIONAL (Plan 11 D5): the declared model endpoints (policy.yaml
   *  `models:`, `[]` when absent). Only consulted when an input carries the
   *  `localmodel_` marker; an arbiter without the op (or a failing op) makes
   *  such a call REFUSE, never route to the default U-LLM. */
  modelEndpoints?(): Promise<ModelEndpoint[]>;
  /** Allocate a symbol for an (untrusted) value — used to RE-SYMBOLIZE the
   *  U-LLM result before it returns to T-LLM. This is the security boundary:
   *  the raw U-LLM output never leaves un-symbolized. */
  symbolize(args: SymbolizeArgs): Promise<string>;
  /** Multi-source output requires arbiter-side label inheritance; no fallback. */
  symbolizeDerived?(args: SymbolizeArgs & { sourceSymbols: string[] }): Promise<string>;
  /** Append an observability event to the arbiter's event stream.
   *  (NEW arbiter op — coded against the agreed contract `{op:"emit", event}` →
   *  `{seq}`.) */
  emit(event: ManduEvent): Promise<{ seq: number }>;
  /** OPTIONAL, utility-only (symbol-quality.md §4.1 v2): the tool call that
   *  produced the symbol's value, for request-aware triage. Absent method,
   *  null fields, or an implementation error all degrade the triage to its
   *  provenance-free form — NEVER a refusal (this is not on the security
   *  path). */
  provenance?(symbol: string): Promise<SymbolProvenance>;
  /** OPTIONAL (Plan 8, §3.3 rung 3): the IN-CONTEXT READ. Unlike `resolve`,
   *  whose result is confined to the quarantine, this returns raw content to
   *  T-LLM — so it is a DECLASSIFICATION, gated by the arbiter and, when
   *  allowed, it HIGH-WATERMARKS the session. Absent on an older arbiter, in
   *  which case the tool reports that rung 3 is unavailable (never a leak). */
  declassify?(args: {
    symbol: string;
    sessionKey?: string;
    reason?: string;
  }): Promise<DeclassifyResult>;
}

/** The arbiter's verdict on an in-context read. */
export interface DeclassifyResult {
  /** Raw content — ONLY when allowed. null on every refusal. */
  value: string | null;
  allowed: boolean;
  /** true ⇒ a human decision is pending. false on a HARD refusal (an untrusted
   *  datum, or a strict one — neither of which any approval opens). */
  requiresApproval: boolean;
  reason: string;
  watermark?: string;
}

/**
 * Structural shape of the real arbiter IPC client (arbiter/ipc/client.ts). We
 * declare it here rather than importing so this package typechecks standalone
 * (the arbiter is a sibling package owned by another sub-agent).
 *
 * `resolve` and `symbolize` have landed on the real client. `emit` has ALSO
 * landed; its signature differs slightly from this package's `Arbiter` interface
 * (the real client resolves to the BARE seq number, ours to `{ seq }`), and the
 * adapter below bridges them:
 *   - real:  emit(event): Promise<number>
 *     ours:  emit(event): Promise<{ seq: number }>
 * `emit` is typed OPTIONAL so the adapter can detect an older arbiter build that
 * predates it and FAIL CLOSED (refuse the inspect_symbol call) rather than
 * returning a quarantined result whose re-symbolization could not be recorded.
 * The event is typed `unknown` on the real-client seam because the arbiter uses
 * its own `ArbiterEvent` shape; our `ManduEvent` is structurally compatible
 * (it carries the required `id` + `sessionId` and the arbiter assigns `seq`).
 */
export interface RealArbiterClient {
  connect(): Promise<void>;
  /** `opts.deep` (arbiter ResolveRequest) expands symbols nested INSIDE the
   *  value to fixpoint. Optional on the seam so an older arbiter build (which
   *  ignores the unknown field) degrades to a shallow value, never an error. */
  resolve(symbol: string, opts?: { deep?: boolean; endpoint?: string }): Promise<string | null>;
  symbolize(args: SymbolizeArgs): Promise<string>;
  /** Plan 11 D5: `{op:"modelEndpoints"}` → the declared endpoints (landed on
   *  arbiter/ipc/client.ts as `modelEndpoints(): Promise<ModelEndpointWire[]>`).
   *  Optional so an older arbiter client simply lacks it (the adapter then
   *  throws and a `localmodel_` inspect refuses). */
  modelEndpoints?(): Promise<ModelEndpoint[]>;
  /** Multi-source output requires arbiter-side label inheritance; no fallback. */
  symbolizeDerived?(args: SymbolizeArgs & { sourceSymbols: string[] }): Promise<string>;
  declassifySymbol?(args: {
    symbol: string; sessionKey?: string; reason?: string;
  }): Promise<DeclassifyResult>;
  // NEW op: append an event, resolves to the arbiter-assigned seq number.
  emit?(event: unknown): Promise<number>;
  /** Optional: symbol → originating tool call (arbiter symbolProvenance op,
   *  symbol-quality.md §4.1 v2). Older arbiter builds lack it — the adapter
   *  degrades to nulls. */
  symbolProvenance?(symbol: string): Promise<SymbolProvenance>;
  /** Stop the connection holding the process's event loop open. Only matters
   *  when this client is EMBEDDED in a host we do not own (the OpenClaw plugin
   *  mount) — a stdio MCP server owns its own process and wants the handle.
   *  Optional so an older arbiter client simply lacks it. */
  unref?(): void;
  close(): void;
}

/**
 * Adapter: present the real arbiter IPC client as a `Arbiter`. Used at deployment
 * (src/server-main.ts), never in tests. If the connected arbiter predates the
 * `emit` op, the adapter throws on use — which the tool treats as a arbiter
 * error and FAILS CLOSED (refuses the request) rather than returning raw text.
 */
export class ArbiterClientAdapter implements Arbiter {
  constructor(private readonly client: RealArbiterClient) {}

  async resolve(symbol: string, opts?: ResolveOptions): Promise<string | null> {
    // DEEP resolve: the quarantined U-LLM must see the FULL original data.
    // Under the dual view a symbol's value can itself be a symbol (the fs-sync
    // AgentView twin Read → proxy re-symbolization stack); a shallow resolve
    // hands the U-LLM a literal `$MDU:*` placeholder and every
    // "summarize this file" degrades to describing the token. Deep is safe
    // HERE because the quarantine has no egress (its output is re-symbolized
    // before returning to T-LLM); per-symbol GATED egress paths (net-proxy)
    // must stay shallow.
    //
    // `endpoint` (Plan 11 D4) is forwarded ONLY when named: with no endpoint
    // the request is byte-for-byte today's `{deep:true}`. An older client or
    // arbiter that drops the field resolves as external, which refuses a
    // local-model datum (null): fail closed, never a wider admission.
    const endpoint = opts?.endpoint;
    return this.client.resolve(symbol, endpoint ? { deep: true, endpoint } : { deep: true });
  }

  async modelEndpoints(): Promise<ModelEndpoint[]> {
    if (!this.client.modelEndpoints) {
      throw new Error("this arbiter does not list model endpoints (modelEndpoints); upgrade required");
    }
    const list = await this.client.modelEndpoints();
    if (!Array.isArray(list)) throw new Error("arbiter modelEndpoints returned a non-list");
    return list;
  }

  async symbolize(args: SymbolizeArgs): Promise<string> {
    return this.client.symbolize(args);
  }

  async symbolizeDerived(args: SymbolizeArgs & { sourceSymbols: string[] }): Promise<string> {
    if (!this.client.symbolizeDerived) throw new Error("Arbiter lacks multi-source derivation; upgrade required");
    return this.client.symbolizeDerived(args);
  }

  async declassify(args: {
    symbol: string; sessionKey?: string; reason?: string;
  }): Promise<DeclassifyResult> {
    if (!this.client.declassifySymbol) {
      // An arbiter that predates rung 3. Report unavailable — NEVER fall back
      // to `resolve`, which would hand raw content to T-LLM with no watermark
      // and no gate. That is the exact laundering this whole plan prevents.
      return {
        value: null, allowed: false, requiresApproval: false,
        reason: "this arbiter does not support in-context reads (declassifySymbol) — use inspect_symbol",
      };
    }
    return this.client.declassifySymbol(args);
  }

  async emit(event: ManduEvent): Promise<{ seq: number }> {
    if (!this.client.emit) {
      throw new Error(
        "arbiter does not implement emit (op not yet landed) — fail closed",
      );
    }
    // Bridge the real client's bare-seq return into our { seq } shape.
    const seq = await this.client.emit(event);
    return { seq };
  }

  async provenance(symbol: string): Promise<SymbolProvenance> {
    // Utility-only enrichment: an arbiter that predates the op (missing
    // method, or the server rejecting the unknown op) and any transient
    // failure degrade to nulls — provenance-free triage — never a refusal.
    if (!this.client.symbolProvenance) {
      return { tool: null, callId: null, toolName: null };
    }
    try {
      return await this.client.symbolProvenance(symbol);
    } catch {
      return { tool: null, callId: null, toolName: null };
    }
  }
}
