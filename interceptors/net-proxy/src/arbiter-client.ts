/**
 * arbiter-client — the arbiter dependency the egress proxy speaks to.
 *
 * Mandu (interceptors/net-proxy). The proxy never opens the symbol-table DB
 * directly: the arbiter (arbiter/) is the single owner of the symbol table + policy
 * engine, and we call it over its Unix-socket NDJSON IPC. This module defines the
 * NARROW interface the proxy needs (`Arbiter`) plus a thin adapter
 * (`ArbiterClientAdapter`) that fulfils it via the real arbiter IPC client
 * (arbiter/ipc/client.ts), plus an in-test `MockArbiter`.
 *
 * Decoupling rationale (mirrors interceptors/anthropic-proxy/src/arbiter-client.ts):
 * the proxy is written against `Arbiter`, not the concrete client. Tests inject a
 * MockArbiter so the suite does not depend on the arbiter daemon. At integration
 * time the adapter wires the real client.
 *
 * The op shapes mirror arbiter/ipc/protocol.ts + arbiter/policy/policy-interface.ts
 * EXACTLY:
 *   - desymbolizationDecision({symbol, boundary, destination?, asCommand?, scheme?, positions?})
 *                  → {allow:true, reason} | {allow:false, requiresApproval, reason}
 *   - resolve(symbol)                          → string | null
 *   - symbolize({tool, value, field?, origin?, sessionKey?, callId?}) → symbol
 *   - classify({tool, field?, value, boundary, origin?, params?})     → {trust,...}
 *   - emit(event)                              → {seq}  (best-effort, off path)
 *   - handlingPrompt({capabilities, sessionKey?}) → the note (model-note.ts)
 *   - takeRelayNotices({sessionKey?}) → the relay's pending refusals, cleared
 *                                        (relay-notice.ts)
 *
 * THE HUMAN PLANE (docs/design/architecture/arbiter-human-plane.md): the shallow `resolve`
 * returns an ORIGINAL, so the arbiter serves it only on its human-plane socket
 * ($MANDU_ARBITER_HUMAN_SOCK), never on the data socket the agent world can
 * reach. The adapter therefore takes a SECOND client, over the human socket,
 * for `resolve`. No human client, or one that cannot answer → `resolve`
 * throws, and the egress gate WITHHOLDS the symbol (egress.ts: resolve failed
 * after allow → block, fail-closed). The data socket is never asked instead.
 *
 * The decision rides the human client too (arbiter-human-plane.md §10.3,
 * confidentiality plan 13 D9): a human's *Allow once* is spent only by an
 * ask on a channel the agent's processes cannot reach, so the proxy's ask is
 * the one that spends it, and the agent's own ask on the data socket neither
 * spends it nor is granted it. With no human client the decision goes to the
 * data socket (no once is granted there, and nothing allowed could be
 * resolved anyway); a human client that fails is a gate error (block), never
 * a retry on the data socket.
 *
 * The holder chains (confidentiality plan 13 D9 leftovers, 2026-10-02): the
 * `ancestors` a `taintedProcessBindings` carries are lineage REPORTS, believed
 * only on the human socket (arbiter-human-plane.md §10, `ATTESTED_REPORT_OPS`)
 * and claims (which only widen a walk) on the data socket. The proxy reads
 * them from `/proc` outside the agent's tree, as the guard does, so it sends
 * them on the human client. No human client, or one that fails, asks the
 * data socket instead: the answer (a tightening) is the same, and the chain
 * is only a claim there, which is what it was before.
 */

/** The env var naming the human-plane socket (arbiter/ipc/instance.ts
 *  HUMAN_SOCK_ENV, mirrored so this package typechecks standalone). */
export const HUMAN_SOCK_ENV = "MANDU_ARBITER_HUMAN_SOCK";

/** The human-plane socket the proxy resolves over, or null. ONLY
 *  $MANDU_ARBITER_HUMAN_SOCK: the data socket is never a fallback. */
export function humanSockFromEnv(env: NodeJS.ProcessEnv = process.env): string | null {
  const v = env[HUMAN_SOCK_ENV];
  return typeof v === "string" && v !== "" ? v : null;
}

/** The ops the proxy asks of the human plane: the shallow resolve, and the
 *  holder chains it reports (optional: a test double may carry resolve only). */
export interface HumanResolveClient {
  resolve(symbol: string): Promise<string | null>;
  /** The egress gate, asked here so the proxy's ask is the one that may
   *  spend a human's *Allow once* (header). Optional: a test double may carry
   *  resolve only, and then the data client decides. */
  desymbolizationDecision?(req: DesymbolizationRequest): Promise<DesymbolizationDecision>;
  taintedProcessBindings?(args: TaintedProcessBindingsArgs): Promise<TaintedProcessBindings>;
  /** The proxy's events, believed only here (arbiter-human-plane.md §10.2). */
  emit?(event: ArbiterEvent): Promise<number>;
  /** Plan 10 §11.8, "Refused connections": an attested report, so only here. */
  recordEgressRefusal?(args: EgressRefusalReport): Promise<{ recorded: boolean }>;
  close(): void;
}

/** Plan 10 §11.8: one refusal as reported to the arbiter. `procKeys` are
 *  the sending process and its holders; empty only with `unattributed`
 *  ("A refusal no process is tied to": no holder found, so the arbiter ties
 *  the note to the calls running then). A kind, never a host. */
export interface EgressRefusalReport {
  procKeys: string[];
  kind: EgressRefusalKind;
  sessionKey?: string;
  unattributed?: boolean;
}

/** Why this proxy refused a connection, as the arbiter records it (mirrors
 *  arbiter/ipc/protocol.ts EGRESS_REFUSAL_KINDS). A kind, never a host. */
export type EgressRefusalKind = "tainted" | "unattributed" | "symbol" | "fingerprint" | "blocked-destination" | "this-machine" | "shell-expanded" | "fail-closed" | "session-asked" | "session-blocked" | "symbol-destination";

/** Mirrors arbiter/ipc/protocol.ts `StrippedPlaceholdersResultWire`: the
 *  asked names that are secret-labelled rows, and the deciding rule. */
export interface StrippedPlaceholdersResult {
  found: string[];
  ruleRef?: RuleRef;
}

import type { SessionLogins } from "./session-logins.js";
import type { RelayNotice } from "./relay-notice.js";
import { createHash } from "node:crypto";
import { destinationMatchesBindings } from "./host-bindings.js";

/** The boundary at which data crosses out of the agent. For NETWORK egress this
 * proxy ALWAYS uses the "network" literal — verified against
 * arbiter/policy/policy-interface.ts `Boundary` + `decideDesymbolization`, which
 * branches on `req.boundary === "network"` (and checks `destination` against the
 * URL trust category). Mirrors arbiter/policy/policy-interface.ts `Boundary`. */
export type Boundary = "model_context" | "network" | "filesystem" | "shell";

/** The exact boundary literal this proxy passes for every network-egress gate. */
export const NETWORK_BOUNDARY: Boundary = "network";

/** Mirrors arbiter/policy/policy-interface.ts `Trust`. */
export type Trust = "TRUSTED" | "UNTRUSTED";

/** Mirrors arbiter/policy/policy-interface.ts `ClassifyRequest`. */
export interface ClassifyRequest {
  tool: string;
  field?: string;
  value: string;
  boundary: Boundary;
  origin?: string;
  params?: Record<string, unknown>;
}

/** Mirrors arbiter/policy/policy-interface.ts `ClassifyResult`. */
export interface ClassifyResult {
  trust: Trust;
  category: string | null;
  reason: string;
}

/** Mirrors arbiter/policy/policy-interface.ts `DesymbolizationRequest`. */
export interface DesymbolizationRequest {
  symbol: string;
  boundary: Boundary;
  destination?: string;
  asCommand?: boolean;
  /** ATTRIBUTION-ONLY (never a decision input): rides to the approval-queue
   * row so the arbiter can attribute it to a session. Additive; old arbiters
   * ignore it. */
  sessionKey?: string;
  /** The scheme the request travels in (`http` on the plain leg, `https` on
   *  the TLS-inspected leg): a wire-twin credential declared for https is
   *  never put back without `https` (plan 10 §11.13.1, 2026-10-03). */
  scheme?: "http" | "https";
  /** Every place in the request the symbol sits (egress.ts
   *  `requestSymbolPositions`): a credential bound only by its own config
   *  file or an auth grant is put back only when every position is
   *  `authorization` (plan 10 §11.13.1, 2026-10-09). */
  positions?: RequestPosition[];
  /** One id per request this proxy judges (egress.ts `gateRequest`): a
   *  human's *once* answer on a card about a whole file is spent by the
   *  request, not by its first placeholder (egress-hold.md, "One card per
   *  file"). Additive; old arbiters ignore it (a once then covers one ask). */
  requestId?: string;
  /** Every placeholder this request carries (egress.ts `gateSymbols`): two
   *  or more of one registered file ask on that file's ONE card. Attribution
   *  of the card only; additive (an old arbiter files a card per
   *  placeholder). */
  requestSymbols?: string[];
}

/** Mirrors arbiter/policy/policy-interface.ts `RequestPosition`: where a
 *  symbol sits in a request. `authorization` = the request's `Authorization`
 *  header (its value, or the decoded pair of `Basic`); `url` = the URL or
 *  its host; `header` = any other header; `body` = the body. */
export type RequestPosition = "authorization" | "url" | "header" | "body";

/** Mirrors arbiter/policy/policy-interface.ts `DesymbolizationDecision`. */
export type DesymbolizationDecision =
  | {
      allow: true; reason: string; ruleRef?: RuleRef;
      /** A pre-check's reading of a "Send without it" answer (the model
       *  proxy's; this proxy never pre-checks). With it set the gate still
       *  never resolves the symbol: it sends the marker (egress.ts). */
      strip?: true;
    }
  | {
      allow: false; requiresApproval: boolean; reason: string; ruleRef?: RuleRef;
      /** "Send without it" (confidentiality.md §4): the human's one-shot
       *  answer, spent by this ask. The value is not released; this request
       *  goes with `SEND_WITHOUT_MARKER` where the symbol is (egress.ts). */
      strip?: true;
      /** The approval-queue row this ask created/bumped (`egr-<n>`), stamped
       *  on the block's `net_action` event so the dashboard can find the
       *  moment an answer was asked (dashboard.md §4.25h). Attribution only. */
      approvalId?: string;
    };

/** Decision provenance (arbiter/policy/rule-ref.ts; policy-surface.md §9.3):
 *  WHICH rule decided. Carried, never interpreted, by this proxy. No index
 *  signature, so the real client's answer (the arbiter's closed `RuleRef`)
 *  is assignable: the human-plane client is passed uncast. */
export interface RuleRef {
  source: string;
  id: string;
}

/** The `taintedProcessBindings` question (plan 10 §4.3). `destination`
 *  (plan 13 §5.4): the send the proxy is about to refuse, named so the
 *  arbiter consults (and spends) the human's answer for {session, these
 *  files} × destination or files the question; believed on the human
 *  socket only. */
export interface TaintedProcessBindingsArgs {
  procKey: string;
  ancestors?: string[];
  session?: string;
  destination?: string;
}

/** The `taintedProcessBindings` answer (plan 10 §4.3). */
export interface TaintedProcessBindings {
  tainted: boolean;
  level: string | null;
  files: string[];
  bindings: string[];
  /** With `destination` outside `bindings`: the human's answer (`approved`
   *  lets this send go) or the question filed (`pending`). Absent: none.
   *  `question: "session"` (confidentiality.md §4, 2026-10-12): the process
   *  holds only what its HIGH session read, so the question is that
   *  session's network ask (`session-net:<session>` × host), not a holder's
   *  send question. */
  ask?: { approvalId: string; status: "pending" | "approved" | "denied"; scope?: "once" | "always"; question?: "session" | "holder" };
}

/** The `sessionSecretTaint` answer (plan 13 D6): whether any process of the
 *  session holds a secret (a raw read on record), and which files. */
export interface SessionSecretTaint {
  tainted: boolean;
  level: string | null;
  files: string[];
}

/** The `secretTaintedProcesses` answer (mirrors arbiter/ipc/protocol.ts
 *  `SecretTaintedProcessesResultWire`): process keys, never files. */
export interface SecretTaintedProcesses {
  procKeys: string[];
}

/** Mirrors arbiter/ipc/protocol.ts `IsProcessTaintedResult`. */
export interface IsProcessTaintedResult {
  tainted: boolean;
  originHost?: string;
}

/** Mirrors arbiter/ipc/protocol.ts `EgressFingerprintScanOpRequest` (minus
 * id/op): the §4 verbatim-leak tripwire surfaces + destination. */
export interface FingerprintScanArgs {
  surfaces: { where: string; text: string }[];
  destination: string;
  /** The session's kept logins (session-logins.ts): their registered rows
   *  are not scanned for this session (secret-discovery.md §1.10). */
  sessionLogins?: SessionLogins;
}

/** Mirrors arbiter/ipc/protocol.ts `EgressFingerprintScanResultWire`. Carries
 * SYMBOL names only — the result rides an observability event and must never
 * itself carry the raw secret value. */
export interface FingerprintScanResult {
  tripped: boolean;
  hits: { symbol: string; level: string; where: string }[];
}

/** Mirrors arbiter/ipc/protocol.ts `SymbolizeRequest` (minus id/op). */
export interface SymbolizeArgs {
  tool: string;
  value: string;
  field?: string;
  origin?: string;
  sessionKey?: string;
  callId?: string;
}

/**
 * An observability event handed to the arbiter's privileged event log. The proxy
 * treats it as an opaque record (the canonical `ManduEvent` shape lives in the
 * dashboard's event-model). Kept as `unknown` so this module stays decoupled
 * from the event builder.
 */
export type ArbiterEvent = unknown;

/** Reply to `emit`: the arbiter stamps a monotonic per-session sequence number.
 * The proxy IGNORES this (emission is fire-and-forget / off the security path). */
export interface EmitResult {
  seq: number;
}

/**
 * The narrow arbiter surface the egress proxy depends on. Anything that satisfies
 * this — the real adapter or a mock — can drive the proxy.
 */
export interface Arbiter {
  /** Data-usage / egress gate: may this symbol be resolved at this boundary? */
  desymbolizationDecision(req: DesymbolizationRequest): Promise<DesymbolizationDecision>;
  /** Resolve a single symbol name to its raw value (null if unknown). */
  resolve(symbol: string): Promise<string | null>;
  /** Allocate a symbol for an untrusted value (ingress: response symbolization). */
  symbolize(args: SymbolizeArgs): Promise<string>;
  /** Data-trust policy: classify a response body TRUSTED/UNTRUSTED. */
  classify(req: ClassifyRequest): Promise<ClassifyResult>;
  /**
   * Emit an observability event (best-effort, OFF the security path). The proxy
   * always wraps this so a failed/slow emit can never block or fail a request.
   */
  emit(event: ArbiterEvent): Promise<EmitResult>;
  /**
   * Provenance (Plan 1 `taintProcess`): mark a process tainted because it touched
   * an untrusted host. Called by the OBSERVE-AND-TAG ingress path as a supplement
   * to (NOT a replacement for) body symbolization. Best-effort but on the security
   * path for the egress backstop — the caller fails closed where it matters.
   */
  taintProcess(args: { procKey: string; originHost: string; session?: string }): Promise<void>;
  /**
   * Provenance (Plan 1 `isProcessTainted`): is this process (or a transitive
   * ancestor) network-tainted? Powers the taint-driven egress gate.
   */
  isProcessTainted(procKey: string): Promise<IsProcessTaintedResult>;
  /** Plan 10 §4.3: the hosts a SECRET-tainted process may still reach (the
   *  bindings of the secrets it and its ancestors hold). `ancestors` (nearest
   *  first) records a fork-only child's lineage before the lookup. Optional:
   *  an arbiter predating plan 10 has no process secret taint. A THROW is
   *  unreachable ⇒ the caller blocks. */
  taintedProcessBindings?(args: TaintedProcessBindingsArgs): Promise<TaintedProcessBindings>;
  /** Plan 13 D6: does ANY process of the session hold a secret (a raw read on
   *  record)? Asked for a connection the proxy cannot attribute to a process:
   *  such a leg is refused while the answer is yes. Absent or a THROW ⇒ the
   *  caller blocks the unattributed leg. */
  sessionSecretTaint?(args: { session?: string }): Promise<SessionSecretTaint>;
  /** Plan 13 D6, a blind tunnel's chunks (2026-10-07): every process key the
   *  arbiter would answer `taintedProcessBindings` tainted for (raw-read
   *  rows, closed forward over the recorded lineage, claims and flows), so
   *  the proxy looks for those processes, and their live descendants, among
   *  a tunnel's holders before each chunk instead of rescanning every
   *  process's descriptors. Absent or a THROW ⇒ the caller rescans every
   *  holder (never the CONNECT's holders alone). */
  secretTaintedProcesses?(): Promise<SecretTaintedProcesses>;
  /** Plan 10 §11.8, "Refused connections": tell the arbiter a connection
   *  from these processes was refused, so the tool call whose tree holds one
   *  says so. Best-effort, off the security path (the refusal stands either
   *  way); human plane only. Optional: absent ⇒ nothing recorded. With no
   *  holder, `procKeys: []` and `unattributed: true`. */
  recordEgressRefusal?(args: EgressRefusalReport): Promise<void>;
  /**
   * The §4 verbatim-leak TRIPWIRE (confidentiality.md §4). Scan the outbound
   * surfaces against the arbiter's known secret VALUES; trips on a verbatim
   * match at a non-released destination. This BACKS the per-symbol gate — it is
   * defense-in-depth, not the guarantee, so the proxy treats a scan error as an
   * inert no-op (the load-bearing gate already failed closed). OPTIONAL so an
   * arbiter build predating it degrades gracefully.
   */
  egressFingerprintScan?(args: FingerprintScanArgs): Promise<FingerprintScanResult>;
  /** Confidentiality.md §7, "A placeholder the agent's shell would expand":
   *  which of these `$MDU:` names (rebuilt from text whose `$MDU` a shell
   *  expanded to nothing) are secret-labelled rows. Names only. A utility
   *  check, not a gate: the text it finds holds no value, so an absent op or
   *  a THROW leaves the request to the gates as before. */
  strippedPlaceholders?(args: { candidates: string[]; sessionKey?: string }): Promise<StrippedPlaceholdersResult>;
  /** Confidentiality.md §4, "A held request": which of these approval rows
   *  still wait for the human's answer. A read that only paces a held
   *  request's re-asks (egress.ts `holdForAnswer`); the decision is always
   *  the re-ask's, so an absent op or a THROW just means "ask again". */
  awaitingApprovals?(ids: readonly string[]): Promise<ReadonlySet<string>>;
  /** Mandu's handling note for a browser agent's own model call
   *  (model-note.ts; the arbiter's `handlingPrompt` op, the text the model
   *  proxies inject). Utility, not a gate: an absent op or a THROW sends the
   *  request as written. */
  handlingPrompt?(args: { capabilities: HandlingNoteCapabilities; sessionKey?: string }): Promise<string>;
  /** The DevTools relay's pending refusals for this session, cleared by the
   *  take (relay-notice.ts; the arbiter's `takeRelayNotices` op). Utility,
   *  not a gate: an absent op or a THROW sends the call without them. */
  takeRelayNotices?(args: { sessionKey?: string }): Promise<RelayNotice[]>;
}

/** The capability facts the note is built for (arbiter/ipc/protocol.ts
 *  `handlingPrompt` capabilities, mirrored so this package typechecks
 *  standalone). */
export interface HandlingNoteCapabilities {
  inspect?: boolean;
  policyTools?: boolean;
  exec?: boolean;
  fsView?: boolean;
  browser?: boolean;
}

/**
 * Structural shape of the real arbiter IPC client (arbiter/ipc/client.ts). We
 * declare it here rather than importing so this package typechecks standalone
 * (the arbiter is a sibling package). `emit` resolves to a bare `number` (the
 * seq) on the real client; the adapter wraps it into `{seq}`.
 */
export interface RealArbiterClient {
  connect(): Promise<void>;
  desymbolizationDecision(req: DesymbolizationRequest): Promise<DesymbolizationDecision>;
  resolve(symbol: string): Promise<string | null>;
  symbolize(args: SymbolizeArgs): Promise<string>;
  classify(req: ClassifyRequest): Promise<ClassifyResult>;
  /** Real client returns the bare seq; optional so the adapter can degrade
   * GRACEFULLY (NOT fail closed) on a arbiter build that predates it. */
  emit?(event: ArbiterEvent): Promise<number>;
  taintProcess(args: { procKey: string; originHost: string; session?: string }): Promise<void>;
  isProcessTainted(procKey: string): Promise<IsProcessTaintedResult>;
  /** Plan 10 §4.3 (see `Arbiter.taintedProcessBindings`). */
  taintedProcessBindings?(args: TaintedProcessBindingsArgs): Promise<TaintedProcessBindings>;
  /** Plan 13 D6 (see `Arbiter.sessionSecretTaint`). */
  sessionSecretTaint?(args: { session?: string }): Promise<SessionSecretTaint>;
  /** Plan 13 D6, a blind tunnel's chunks (see `Arbiter.secretTaintedProcesses`). */
  secretTaintedProcesses?(): Promise<SecretTaintedProcesses>;
  /** Optional — an arbiter predating the §4 tripwire simply has no method here,
   *  and the adapter degrades to an inert no-op. */
  egressFingerprintScan?(args: FingerprintScanArgs): Promise<FingerprintScanResult>;
  /** Optional — an arbiter predating it has none (see `Arbiter.strippedPlaceholders`). */
  strippedPlaceholders?(args: { candidates: string[]; sessionKey?: string }): Promise<StrippedPlaceholdersResult>;
  /** The queue's listing (`egressApprovals`): `awaitingApprovals` reads the
   *  pending rows. Optional: a test double may have none. */
  egressApprovals?(status?: "pending"): Promise<Array<{ id: string; status: string }>>;
  /** The real client's positional form (mode, capabilities, sessionKey).
   *  Optional: a test double may have none. */
  handlingPrompt?(mode?: "full" | "dual-only", capabilities?: HandlingNoteCapabilities, sessionKey?: string): Promise<string>;
  /** Optional: an arbiter predating it has none. */
  takeRelayNotices?(args: { sessionKey?: string }): Promise<{ notices: RelayNotice[] }>;
  close(): void;
}

/**
 * Adapter: present the real arbiter IPC client as a `Arbiter`. Used at deployment
 * (src/server-main.ts) and by the parity test. `client` is over the DATA
 * socket; `human` (the shallow resolve's only channel, and the decision's)
 * over the HUMAN-PLANE socket, or null when none was named — then every
 * resolve throws and the gate withholds.
 */
export class ArbiterClientAdapter implements Arbiter {
  constructor(
    private readonly client: RealArbiterClient,
    private readonly human: HumanResolveClient | null = null,
  ) {}

  async desymbolizationDecision(req: DesymbolizationRequest): Promise<DesymbolizationDecision> {
    // On the human client when there is one (header): only an ask from there
    // spends a human's *Allow once*. A failure there throws (the gate
    // blocks); it is not retried on the data socket.
    const via = this.human?.desymbolizationDecision ? this.human : this.client;
    return via.desymbolizationDecision!(req);
  }

  async resolve(symbol: string): Promise<string | null> {
    // Human plane only (see the header). Never `this.client.resolve`: the
    // data socket refuses it, and asking it would be the reach this closes.
    if (this.human === null) {
      throw new Error(`no ${HUMAN_SOCK_ENV}: the human-plane socket is required to resolve an allowed symbol`);
    }
    return this.human.resolve(symbol);
  }

  async symbolize(args: SymbolizeArgs): Promise<string> {
    return this.client.symbolize(args);
  }

  async classify(req: ClassifyRequest): Promise<ClassifyResult> {
    return this.client.classify(req);
  }

  async emit(event: ArbiterEvent): Promise<EmitResult> {
    // Emission is BEST-EFFORT and off the security path. A arbiter that predates
    // `emit` must NOT fail the request — degrade to a no-op (seq:-1). The proxy
    // additionally wraps every emit in its own try/catch.
    // arbiter-human-plane.md §10.2: on the human client when there is one,
    // where the event is believed; else (or on a failure there) the data
    // socket, where the arbiter stores it as a claim.
    if (this.human?.emit) {
      try {
        return { seq: await this.human.emit(event) };
      } catch { /* the data socket below */ }
    }
    if (!this.client.emit) return { seq: -1 };
    const seq = await this.client.emit(event);
    return { seq };
  }

  async taintProcess(args: { procKey: string; originHost: string; session?: string }): Promise<void> {
    return this.client.taintProcess(args);
  }

  async isProcessTainted(procKey: string): Promise<IsProcessTaintedResult> {
    return this.client.isProcessTainted(procKey);
  }

  async taintedProcessBindings(args: TaintedProcessBindingsArgs): Promise<TaintedProcessBindings> {
    // Plan 13 D9: the chain is believed only on the human socket. A human
    // client that cannot answer falls back to the data socket, where the
    // same question gets the same answer and the chain is a claim.
    if (this.human?.taintedProcessBindings) {
      try {
        return await this.human.taintedProcessBindings(args);
      } catch {
        /* the data socket below */
      }
    }
    if (!this.client.taintedProcessBindings) return { tainted: false, level: null, files: [], bindings: [] };
    return this.client.taintedProcessBindings(args);
  }

  async recordEgressRefusal(args: EgressRefusalReport): Promise<void> {
    // An attested report: the human client only. From the data socket the
    // arbiter records nothing, so there is no fallback.
    if (!this.human?.recordEgressRefusal || (args.procKeys.length === 0 && args.unattributed !== true)) return;
    await this.human.recordEgressRefusal(args);
  }

  async sessionSecretTaint(args: { session?: string }): Promise<SessionSecretTaint> {
    // No fail-soft default: an arbiter that cannot answer leaves an
    // unattributed leg unjudged, so the caller blocks it (plan 13 D6).
    if (!this.client.sessionSecretTaint) throw new Error("the arbiter has no sessionSecretTaint op");
    return this.client.sessionSecretTaint(args);
  }

  async secretTaintedProcesses(): Promise<SecretTaintedProcesses> {
    // A read-only list (process keys): the data socket answers it. An
    // arbiter without the op throws, and the caller rescans every holder.
    if (!this.client.secretTaintedProcesses) throw new Error("the arbiter has no secretTaintedProcesses op");
    return this.client.secretTaintedProcesses();
  }

  async egressFingerprintScan(args: FingerprintScanArgs): Promise<FingerprintScanResult> {
    // An arbiter that predates the tripwire has no method → inert no-op (never
    // a leak: the per-symbol gate is the guarantee, this only ADDS blocks).
    if (!this.client.egressFingerprintScan) return { tripped: false, hits: [] };
    return this.client.egressFingerprintScan(args);
  }

  async strippedPlaceholders(args: { candidates: string[]; sessionKey?: string }): Promise<StrippedPlaceholdersResult> {
    // An arbiter that predates the op: nothing found (the request goes to
    // the gates as before; the text holds no value either way).
    if (!this.client.strippedPlaceholders) return { found: [] };
    return this.client.strippedPlaceholders(args);
  }

  async awaitingApprovals(ids: readonly string[]): Promise<ReadonlySet<string>> {
    // The queue's listing on the data socket (the dashboard reads it there
    // too): names and statuses, no value. An arbiter without it throws, and
    // the held request asks again instead (egress.ts holdForAnswer).
    if (!this.client.egressApprovals) throw new Error("the arbiter has no egressApprovals op");
    const want = new Set(ids);
    const rows = await this.client.egressApprovals("pending");
    return new Set(rows.filter((r) => r.status === "pending" && want.has(r.id)).map((r) => r.id));
  }

  async handlingPrompt(args: { capabilities: HandlingNoteCapabilities; sessionKey?: string }): Promise<string> {
    // On the data socket, as the model proxies ask it: the note is Mandu's
    // fixed text, no original. An arbiter without the op throws, and the
    // request leaves as written (model-note.ts).
    if (!this.client.handlingPrompt) throw new Error("the arbiter has no handlingPrompt op");
    return this.client.handlingPrompt(undefined, args.capabilities, args.sessionKey);
  }

  async takeRelayNotices(args: { sessionKey?: string }): Promise<RelayNotice[]> {
    // On the data socket, where the relay reports them: names only. An
    // arbiter without the op: none (the call goes without them).
    if (!this.client.takeRelayNotices) return [];
    const r = await this.client.takeRelayNotices(args.sessionKey !== undefined ? { sessionKey: args.sessionKey } : {});
    return Array.isArray(r?.notices) ? r.notices : [];
  }
}

// ── In-test MockArbiter ───────────────────────────────────────────────────────

export interface MockArbiterOptions {
  /** Per-symbol egress decision. Default: deny (fail-closed) for any symbol. */
  decisionFn?: (req: DesymbolizationRequest) => DesymbolizationDecision;
  /** Symbol → raw value table, so resolve() returns the secret on allow. */
  values?: Record<string, string>;
  /** Tools/origins to classify TRUSTED (response symbolization). Else UNTRUSTED. */
  trustedTools?: string[];
  trustedOrigins?: string[];
  /** Custom classify override (takes precedence). */
  classifyFn?: (req: ClassifyRequest) => ClassifyResult;
  /** Inject failures to exercise the proxy's fail-closed path. */
  failDecision?: boolean;
  failResolve?: boolean;
  failClassify?: boolean;
  failSymbolize?: boolean;
  /** Make emit() throw, to prove emission is off the security path. */
  failEmit?: boolean;
  /** Make taintProcess()/isProcessTainted() throw, to exercise fail-closed paths. */
  failTaintProcess?: boolean;
  failIsProcessTainted?: boolean;
  /** Plan 10: procKey → the bindings answer (absent key ⇒ untainted). */
  secretTaint?: Record<string, TaintedProcessBindings>;
  failTaintedProcessBindings?: boolean;
  /** Plan 13 §5.4: the human's answer the arbiter gives a tainted holder's
   *  ask that names a destination (default: a question filed, pending). */
  holderAsk?: (args: TaintedProcessBindingsArgs, taint: TaintedProcessBindings) => NonNullable<TaintedProcessBindings["ask"]> | undefined;
  /** Plan 13 D6: the session-wide answer for an unattributed leg (default:
   *  no process of the session holds a secret). */
  sessionTaint?: SessionSecretTaint;
  failSessionSecretTaint?: boolean;
  /** Make secretTaintedProcesses() throw (the caller must rescan). */
  failTaintedProcesses?: boolean;
  /** Raw secret values the §4 tripwire scans outbound surfaces against. A hit
   *  (verbatim match at a non-bound destination) trips the block. */
  fingerprintSecrets?: { symbol: string; value: string; level: string; bindings?: string[] }[];
  /** Make egressFingerprintScan() throw, to prove the tripwire is inert-on-error. */
  failFingerprint?: boolean;
  /** The `$MDU:` names `strippedPlaceholders` reports as secret rows. */
  knownSecretSymbols?: string[];
  /** Make strippedPlaceholders() throw (the request goes to the gates). */
  failStripped?: boolean;
  /** `awaitingApprovals`: which of these rows still wait (absent: the op
   *  throws, and a held request asks again on every poll). */
  awaitingFn?: (ids: readonly string[]) => ReadonlySet<string>;
  /** `handlingPrompt`'s answer (absent: the op throws, and the request
   *  leaves as written). */
  handlingNote?: string;
  /** Make takeRelayNotices() throw (the call goes without them). */
  failRelayNotices?: boolean;
}

/**
 * An in-memory Arbiter for the net-proxy test suite. Implements the same narrow
 * `Arbiter` interface the proxy depends on WITHOUT the real arbiter daemon, so the
 * suite never depends on the arbiter landing. Mirrors the arbiter's real contract
 * closely enough to exercise the gate (fail-closed default), resolution, response
 * symbolization, and failure injection.
 */
export class MockArbiter implements Arbiter {
  /** Every decision call, for assertions. */
  readonly decisionCalls: DesymbolizationRequest[] = [];
  /** Every classify call, for assertions. */
  readonly classifyCalls: ClassifyRequest[] = [];
  /** Every symbolize call, for assertions. */
  readonly symbolizeCalls: SymbolizeArgs[] = [];
  /** Every emitted observability event, in arrival order. */
  readonly emittedEvents: unknown[] = [];
  /** Every recordEgressRefusal report, in arrival order. */
  readonly egressRefusals: EgressRefusalReport[] = [];

  async recordEgressRefusal(args: EgressRefusalReport): Promise<void> {
    this.egressRefusals.push(args);
  }

  private readonly values: Map<string, string>;
  private readonly trustedTools: Set<string>;
  private readonly trustedOrigins: Set<string>;
  private emitSeq = 0;
  /** value → symbol, so symbolize is stable per value (round-trip assertions). */
  private readonly symbolOf = new Map<string, string>();
  /** procKeys the mock treats as tainted (default: empty → not tainted). */
  private readonly taintedProcs = new Map<string, string>(); // procKey → originHost
  /** Every taintProcess call, for assertions. */
  readonly taintProcessCalls: { procKey: string; originHost: string; session?: string }[] = [];
  /** Every isProcessTainted call, for assertions. */
  readonly isProcessTaintedCalls: string[] = [];

  constructor(private readonly opts: MockArbiterOptions = {}) {
    this.values = new Map(Object.entries(opts.values ?? {}));
    this.trustedTools = new Set(opts.trustedTools ?? []);
    this.trustedOrigins = new Set(opts.trustedOrigins ?? []);
  }

  async desymbolizationDecision(req: DesymbolizationRequest): Promise<DesymbolizationDecision> {
    this.decisionCalls.push(req);
    if (this.opts.failDecision) throw new Error("mock arbiter: decision failure (injected)");
    if (this.opts.decisionFn) return this.opts.decisionFn(req);
    // Default: fail-closed deny (mirrors the arbiter's conservative default).
    return {
      allow: false,
      requiresApproval: true,
      reason: "mock fail-closed: no decisionFn → deny",
    };
  }

  async resolve(symbol: string): Promise<string | null> {
    if (this.opts.failResolve) throw new Error("mock arbiter: resolve failure (injected)");
    return this.values.has(symbol) ? this.values.get(symbol)! : null;
  }

  async classify(req: ClassifyRequest): Promise<ClassifyResult> {
    this.classifyCalls.push(req);
    if (this.opts.failClassify) throw new Error("mock arbiter: classify failure (injected)");
    if (this.opts.classifyFn) return this.opts.classifyFn(req);

    let trust: Trust = "UNTRUSTED";
    let reason = "mock fail-closed: not allowlisted -> UNTRUSTED";
    if (this.trustedTools.has(req.tool)) {
      trust = "TRUSTED";
      reason = `mock: tool '${req.tool}' allowlisted TRUSTED`;
    } else if (req.origin && this.trustedOrigins.has(req.origin)) {
      trust = "TRUSTED";
      reason = `mock: origin '${req.origin}' allowlisted TRUSTED`;
    }
    return { trust, category: null, reason };
  }

  async symbolize(args: SymbolizeArgs): Promise<string> {
    this.symbolizeCalls.push(args);
    if (this.opts.failSymbolize) throw new Error("mock arbiter: symbolize failure (injected)");
    const existing = this.symbolOf.get(args.value);
    if (existing) return existing;
    const hash = createHash("sha256").update(args.value).digest("hex").slice(0, 4);
    const tool = args.tool.replace(/[^a-zA-Z0-9_]/g, "_") || "t";
    const symbol = `$MDU:${/^[a-zA-Z_]/.test(tool) ? tool : `t_${tool}`}[${hash}]`;
    this.symbolOf.set(args.value, symbol);
    this.values.set(symbol, args.value);
    return symbol;
  }

  async emit(event: ArbiterEvent): Promise<EmitResult> {
    if (this.opts.failEmit) throw new Error("mock arbiter: emit failure (injected)");
    const seq = this.emitSeq++;
    this.emittedEvents.push(event);
    return { seq };
  }

  async taintProcess(args: { procKey: string; originHost: string; session?: string }): Promise<void> {
    this.taintProcessCalls.push(args);
    if (this.opts.failTaintProcess) throw new Error("mock arbiter: taintProcess failure (injected)");
    this.taintedProcs.set(args.procKey, args.originHost);
  }

  /** Every taintedProcessBindings call, for assertions. */
  readonly bindingsCalls: TaintedProcessBindingsArgs[] = [];
  /** Every sessionSecretTaint call, for assertions. */
  readonly sessionTaintCalls: { session?: string }[] = [];

  async taintedProcessBindings(args: TaintedProcessBindingsArgs): Promise<TaintedProcessBindings> {
    this.bindingsCalls.push(args);
    if (this.opts.failTaintedProcessBindings) throw new Error("mock arbiter: taintedProcessBindings failure (injected)");
    // Like the arbiter, a process inherits its ancestors' taint: the first
    // tainted key on the chain answers. Read live, so a test can taint a
    // process mid-connection. A named destination gets the injected answer
    // (`holderAsk`), else a question filed (plan 13 §5.4).
    for (const k of [args.procKey, ...(args.ancestors ?? [])]) {
      const t = this.opts.secretTaint?.[k];
      if (t?.tainted) {
        if (args.destination === undefined) return t;
        const ask = this.opts.holderAsk?.(args, t) ?? { approvalId: `egr-holder-${this.bindingsCalls.length}`, status: "pending" as const };
        return { ...t, ask };
      }
    }
    return { tainted: false, level: null, files: [], bindings: [] };
  }

  async sessionSecretTaint(args: { session?: string }): Promise<SessionSecretTaint> {
    this.sessionTaintCalls.push(args);
    if (this.opts.failSessionSecretTaint) throw new Error("mock arbiter: sessionSecretTaint failure (injected)");
    return this.opts.sessionTaint ?? { tainted: false, level: null, files: [] };
  }

  /** Every secretTaintedProcesses call (a count), for assertions. */
  taintedProcessesCalls = 0;

  async secretTaintedProcesses(): Promise<SecretTaintedProcesses> {
    this.taintedProcessesCalls++;
    if (this.opts.failTaintedProcesses) throw new Error("mock arbiter: secretTaintedProcesses failure (injected)");
    // The keys `taintedProcessBindings` answers tainted for by their own
    // entry (the mock has no lineage: a descendant is found by the proxy
    // through its ancestor chain). Read live, like that op.
    return { procKeys: Object.entries(this.opts.secretTaint ?? {}).filter(([, t]) => t.tainted).map(([k]) => k) };
  }

  async isProcessTainted(procKey: string): Promise<IsProcessTaintedResult> {
    this.isProcessTaintedCalls.push(procKey);
    if (this.opts.failIsProcessTainted) throw new Error("mock arbiter: isProcessTainted failure (injected)");
    const originHost = this.taintedProcs.get(procKey);
    return originHost === undefined ? { tainted: false } : { tainted: true, originHost };
  }

  /** Test helper: mark a procKey tainted (simulates a prior untrusted-host touch). */
  taintProc(procKey: string, originHost = "evil.example"): void {
    this.taintedProcs.set(procKey, originHost);
  }

  /** Every strippedPlaceholders call, for assertions. */
  readonly strippedCalls: Array<{ candidates: string[]; sessionKey?: string }> = [];

  async strippedPlaceholders(args: { candidates: string[]; sessionKey?: string }): Promise<StrippedPlaceholdersResult> {
    this.strippedCalls.push(args);
    if (this.opts.failStripped) throw new Error("mock arbiter: strippedPlaceholders failure (injected)");
    const known = new Set(this.opts.knownSecretSymbols ?? []);
    const found = [...new Set(args.candidates)].filter((c) => known.has(c));
    return { found, ...(found.length > 0 ? { ruleRef: { source: "rule" as const, id: "egress:shell-expanded-placeholder" } } : {}) };
  }

  /** Every awaitingApprovals call, for assertions. */
  readonly awaitingCalls: string[][] = [];

  async awaitingApprovals(ids: readonly string[]): Promise<ReadonlySet<string>> {
    this.awaitingCalls.push([...ids]);
    if (!this.opts.awaitingFn) throw new Error("mock arbiter: no awaitingFn");
    return this.opts.awaitingFn(ids);
  }

  /** Every handlingPrompt call, for assertions. */
  readonly noteCalls: Array<{ capabilities: HandlingNoteCapabilities; sessionKey?: string }> = [];

  async handlingPrompt(args: { capabilities: HandlingNoteCapabilities; sessionKey?: string }): Promise<string> {
    this.noteCalls.push(args);
    if (this.opts.handlingNote === undefined) throw new Error("mock arbiter: no handlingNote");
    return this.opts.handlingNote;
  }

  /** Every takeRelayNotices call's session key, for assertions. */
  readonly noticeTakes: Array<string | undefined> = [];
  /** The pending refusals, per session key (the arbiter's queue; a test
   *  sets them, the take clears them). */
  readonly pendingNotices = new Map<string, RelayNotice[]>();

  async takeRelayNotices(args: { sessionKey?: string }): Promise<RelayNotice[]> {
    this.noticeTakes.push(args.sessionKey);
    if (this.opts.failRelayNotices) throw new Error("mock arbiter: takeRelayNotices failure (injected)");
    const key = args.sessionKey ?? "";
    const out = this.pendingNotices.get(key) ?? [];
    this.pendingNotices.delete(key);
    return out;
  }

  /** Every fingerprint-scan call, for assertions. */
  readonly fingerprintCalls: FingerprintScanArgs[] = [];

  async egressFingerprintScan(args: FingerprintScanArgs): Promise<FingerprintScanResult> {
    this.fingerprintCalls.push(args);
    if (this.opts.failFingerprint) throw new Error("mock arbiter: fingerprint scan failure (injected)");
    const secrets = this.opts.fingerprintSecrets ?? [];
    const hits: { symbol: string; level: string; where: string }[] = [];
    // The real arbiter's destinationIsBound: the one binding rule
    // (host-bindings.ts), which takes a URL, a host or `host:port`.
    for (const s of secrets) {
      if (s.level === "public" || !s.value || s.value.length < 8) continue;
      if (destinationMatchesBindings(args.destination, s.bindings ?? [])) continue;
      const surface = args.surfaces.find((sf) => sf.text.includes(s.value));
      if (surface) hits.push({ symbol: s.symbol, level: s.level, where: surface.where });
    }
    return { tripped: hits.length > 0, hits };
  }
}
