/**
 * arbiter-client — the arbiter dependency the DevTools relay speaks to
 * (docs/design/agents/devtools-relay.md §5). Mandu-new (no reference origin).
 *
 * The relay never opens the symbol-table DB: it calls the arbiter over its
 * Unix-socket NDJSON IPC (arbiter/ipc/client.ts). This module is the NARROW
 * interface the relay needs (`Arbiter`), a thin adapter over the real client
 * (`ArbiterClientAdapter`), and nothing else; the tests carry their own mock
 * (test/mock-arbiter.ts). Mirrors interceptors/net-proxy/src/arbiter-client.ts.
 *
 * Five ops:
 *   - filterPrompt   (data socket): what Chrome sends the agent, as `harness`
 *                    segments; a registered secret comes back as its symbol.
 *   - desymbolizationDecision (HUMAN socket): may this placeholder be put
 *                    into a page of this origin (the network boundary, the
 *                    page's host as the destination)?
 *   - resolve        (HUMAN socket): the value, once allowed.
 *   - placeholderKnown (HUMAN socket): whether a typed placeholder's base
 *                    (`$MDU:kind[code]`) names a row, asked on the key that
 *                    closes its code (devtools-relay.md §3.3). Names only.
 *   - relayNotice    (data socket): a refusal, kept by the arbiter for the
 *                    browser agent's next model call, which the egress proxy
 *                    tells it (devtools-relay.md §3.4). Names only.
 *
 * THE HUMAN PLANE (docs/design/architecture/arbiter-human-plane.md): the
 * shallow `resolve` returns an ORIGINAL and is served only on the human
 * socket; the decision rides it too, so the relay's ask is the one that may
 * spend a human's Allow once (§10.3). No human client → the release is
 * refused (fail-closed); the data socket is never asked instead.
 */

/** The env var naming the human-plane socket (arbiter/ipc/instance.ts
 *  HUMAN_SOCK_ENV, mirrored so this package typechecks standalone). */
export const HUMAN_SOCK_ENV = "MANDU_ARBITER_HUMAN_SOCK";

/** The human-plane socket, or null. Only $MANDU_ARBITER_HUMAN_SOCK. */
export function humanSockFromEnv(env: NodeJS.ProcessEnv = process.env): string | null {
  const v = env[HUMAN_SOCK_ENV];
  return typeof v === "string" && v !== "" ? v : null;
}

/** One piece of text the relay asks about, as a prompt-filter segment. */
export interface TextSegment {
  id: string;
  text: string;
}

/** The filter's answer for one segment (arbiter/ipc/protocol.ts
 *  `FilterPromptSegmentWire`, the fields the relay reads). */
export interface FilteredSegment {
  id: string;
  action: "pass" | "rewrite" | "hold" | "block";
  /** `rewrite`: the text the agent may read; `block`: the same with each
   *  blocked span as `[blocked: <category>]`, absent when a filter could not
   *  run (nothing of the segment may go). */
  text?: string;
}

/** Mirrors arbiter/policy/policy-interface.ts `RequestPosition`. */
export type RequestPosition = "authorization" | "url" | "header" | "body";

/** Mirrors the egress gate's request (net-proxy `DesymbolizationRequest`). */
export interface DesymbolizationRequest {
  symbol: string;
  boundary: "network";
  /** The page's host: typing a value into a page gives it to that origin. */
  destination: string;
  asCommand: false;
  sessionKey?: string;
  scheme?: "http" | "https";
  positions?: RequestPosition[];
}

/** Mirrors arbiter/policy/policy-interface.ts `DesymbolizationDecision`. */
export type DesymbolizationDecision =
  | { allow: true; reason: string; strip?: true }
  | { allow: false; requiresApproval: boolean; reason: string; approvalId?: string; strip?: true };

/** A refusal, as the model is told it (arbiter/ipc/relay-notices.ts
 *  `RelayNoticeWire`, mirrored so this package typechecks standalone).
 *  Structured names only: a kind, a cause, the page's host, placeholders. */
export interface RelayNotice {
  /** `malformed`: a lookalike (release.ts), which `symbols` never names
   *  (it stays empty: a lookalike's code is free text). */
  kind: "unknown" | "malformed" | "not-allowed" | "needs-approval" | "declined" | "failed";
  page?: string;
  symbols: string[];
  shown?: string[];
  cause?: "no-field" | "page-moved" | "frame" | "no-page" | "page-refused" | "unavailable";
}

/** What the relay needs of the arbiter. */
export interface Arbiter {
  /** Mask what Chrome sends the agent. Throws when the arbiter cannot
   *  answer: the caller withholds the message (fail-closed). */
  filterText(segments: TextSegment[], session?: string): Promise<FilteredSegment[]>;
  /** The release gate, on the human plane. Throws when it cannot ask. */
  desymbolizationDecision(req: DesymbolizationRequest): Promise<DesymbolizationDecision>;
  /** The value of an allowed placeholder, on the human plane (null: unknown). */
  resolve(symbol: string): Promise<string | null>;
  /** Whether a placeholder's BASE (`$MDU:kind[code]`) names a row, its own
   *  or a field's, on the human plane (§3.3). Throws when it cannot ask: the
   *  caller refuses (fail-closed). */
  placeholderKnown(base: string): Promise<boolean>;
  /** One trace event (events.ts), best-effort: the caller ignores a failure. */
  emit(event: Record<string, unknown>): Promise<void>;
  /** Report a refusal for the agent's model (§3.4), best-effort: the
   *  caller ignores a failure (the agent still gets the error). */
  relayNotice(notice: RelayNotice, session?: string): Promise<void>;
}

/** The agent name the relay's filter calls carry (the arbiter requires one). */
export const RELAY_AGENT = "browser";

/** Structural shape of the real arbiter client's ops the adapter forwards. */
export interface RealArbiterClient {
  filterPrompt(args: {
    session?: string;
    agent: string;
    segments: Array<{ id: string; origin: "human" | "harness" | "side-call"; text: string }>;
  }): Promise<{ segments: Array<{ id: string; action: "pass" | "rewrite" | "hold" | "block"; text?: string }> }>;
  desymbolizationDecision(request: DesymbolizationRequest): Promise<DesymbolizationDecision>;
  resolve(symbol: string): Promise<string | null>;
  placeholderKnown(args: { base: string }): Promise<{ known: boolean }>;
  emit(event: Record<string, unknown>): Promise<number>;
  /** Optional: an arbiter predating it has none (the agent is told by the
   *  error only). */
  relayNotice?(args: { notice: RelayNotice; sessionKey?: string }): Promise<unknown>;
  close(): void;
}

/** The production wiring: the filter on the data client, the release on the
 *  human client (none → every release is refused). */
export class ArbiterClientAdapter implements Arbiter {
  constructor(
    private readonly client: Pick<RealArbiterClient, "filterPrompt" | "emit" | "relayNotice">,
    private readonly human: Pick<RealArbiterClient, "desymbolizationDecision" | "resolve" | "placeholderKnown"> | null,
  ) {}

  async emit(event: Record<string, unknown>): Promise<void> {
    await this.client.emit(event);
  }

  async relayNotice(notice: RelayNotice, session?: string): Promise<void> {
    // On the data socket: names only, no original. An arbiter without the op:
    // nothing to do (the refusal still answers the command).
    if (!this.client.relayNotice) return;
    await this.client.relayNotice({ notice, ...(session !== undefined && session !== "" ? { sessionKey: session } : {}) });
  }

  async filterText(segments: TextSegment[], session?: string): Promise<FilteredSegment[]> {
    const r = await this.client.filterPrompt({
      ...(session !== undefined && session !== "" ? { session } : {}),
      agent: RELAY_AGENT,
      segments: segments.map((s) => ({ id: s.id, origin: "harness" as const, text: s.text })),
    });
    return r.segments.map((s) => ({ id: s.id, action: s.action, ...(typeof s.text === "string" ? { text: s.text } : {}) }));
  }

  async desymbolizationDecision(req: DesymbolizationRequest): Promise<DesymbolizationDecision> {
    if (this.human === null) throw new Error(`${HUMAN_SOCK_ENV} is not set: the release gate cannot be asked`);
    return this.human.desymbolizationDecision(req);
  }

  async resolve(symbol: string): Promise<string | null> {
    if (this.human === null) throw new Error(`${HUMAN_SOCK_ENV} is not set: a value cannot be resolved`);
    return this.human.resolve(symbol);
  }

  async placeholderKnown(base: string): Promise<boolean> {
    if (this.human === null) throw new Error(`${HUMAN_SOCK_ENV} is not set: a placeholder cannot be looked up`);
    const r = await this.human.placeholderKnown({ base });
    // Only a literal true is known: any other answer refuses (fail-closed).
    return r?.known === true;
  }
}
