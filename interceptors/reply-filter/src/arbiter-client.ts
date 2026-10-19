/**
 * arbiter-client — the arbiter dependency the reply-filter chokepoint speaks to.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. Pattern mirrored from
 *     interceptors/exec-wrap/src/arbiter-client.ts / inspect-mcp/src/arbiter-client.ts
 *   (narrow interface + adapter over the real arbiter IPC client + a mock for
 *   tests). No reference-source origin — the reference resolves in-process; the
 *   OS-level port resolves over the arbiter IPC.
 *
 * The op shapes mirror arbiter/ipc/protocol.ts + arbiter/ipc/client.ts exactly:
 *   - desymbolize(text) -> text     DEEP (fixpoint): nested symbol chains
 *                                   collapse to raw server-side. This is the
 *                                   full-fidelity HumanView op — the user-reply
 *                                   channel is exactly such a surface (mandu.md
 *                                   §2 "Nested symbolization and deep resolution").
 *   - emit(event)       -> seq      best-effort observability, off the output path.
 *   - setSessionRelay(r) -> void    the session's relay mode (pty / pipe /
 *                                   passthrough) and whether this filter paints
 *                                   reserve blocks; the proxy expands a
 *                                   multi-line token into a reserve block only
 *                                   for a PTY relay that said `reserve: true`
 *                                   (docs/design/ui/reply-row-reservation.md §3.6).
 *                                   Best-effort: an arbiter without the op means
 *                                   no expansion, which is today's rendering.
 *
 * POSTURE NOTE (inverted from exec-wrap): reply-filter is UTILITY-ONLY. If an op
 * fails the caller passes text through UNCHANGED — symbols stay opaque, nothing
 * can leak, only display fidelity is lost. Never block the agent's output.
 *
 * THE HUMAN PLANE (docs/design/architecture/arbiter-human-plane.md): `desymbolize` returns
 * originals, so the arbiter serves it ONLY on the human-plane socket
 * ($MANDU_ARBITER_HUMAN_SOCK), never on the data socket the agent world can
 * reach. The adapter is therefore built over a client of the HUMAN socket
 * (run.ts `humanSockFromEnv`); when that socket is unset or unreachable the
 * filter runs PASSTHROUGH. It never falls back to $MANDU_ARBITER_SOCK: the data
 * socket refuses the op anyway, and a filter that asked it would be exactly
 * the reach this plane exists to close.
 */

/** The env var naming the human-plane socket (arbiter/ipc/instance.ts
 *  HUMAN_SOCK_ENV, mirrored so this package typechecks standalone). */
export const HUMAN_SOCK_ENV = "MANDU_ARBITER_HUMAN_SOCK";

/** The human-plane socket the filter resolves over, or null (→ PASSTHROUGH).
 *  Deliberately reads ONLY $MANDU_ARBITER_HUMAN_SOCK: no data-socket fallback. */
export function humanSockFromEnv(env: NodeJS.ProcessEnv = process.env): string | null {
  const v = env[HUMAN_SOCK_ENV];
  return typeof v === "string" && v !== "" ? v : null;
}

/** The env the AGENT (the wrapped child) runs with: ours minus the
 *  human-plane socket path. Hygiene, not the control — the launcher's wall
 *  (net-guard deny, the secret-twins tmpfs, Seatbelt) is what keeps the agent
 *  world off the socket; the agent simply has no reason to be told its name. */
export function childEnv(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = { ...env };
  delete out[HUMAN_SOCK_ENV];
  // The filter's own layout hint (reserve-block.ts WRAP_RULE_ENV): the
  // launcher sets it for the filter, the agent has no use for it.
  delete out["MANDU_REPLY_WRAP_RULE"];
  return out;
}

/**
 * The narrow arbiter surface the reply filter depends on. Anything that
 * satisfies this — the real adapter or a mock — can drive the filter.
 */
export interface ReplyArbiter {
  /** Deep text desymbolization ($MDU:* → original; unknown stay literal). */
  desymbolize(text: string): Promise<string>;
  /** Append an observability event to the arbiter's event stream (best-effort). */
  emit(event: unknown): Promise<number>;
  /** Report this session's relay mode (best-effort; reply-row-reservation.md §3.6). */
  setSessionRelay(relay: SessionRelay): Promise<void>;
  /** The block the proxy recorded for a continuation row's hash
   *  (reply-row-reservation.md §3.8), or null. Utility-only. */
  reserveBlock(sessionKey: string, hash: string): Promise<ReserveBlockInfo | null>;
}

/** `reserveBlock`'s answer: the head's token, N, and W/F for a v2 head. */
export interface ReserveBlockInfo {
  token: string;
  n: number;
  width?: number;
  first?: number;
}

/** The `setSessionRelay` op's arguments (arbiter/ipc/protocol.ts). `cols`
 *  sets v2's content width (reply-row-reservation.md §11.4); `rows` is
 *  recorded. The op is HUMAN-PLANE only (§11.5): send it over the client of
 *  $MANDU_ARBITER_HUMAN_SOCK, never the data socket. */
export interface SessionRelay {
  /** The session key the proxy shares (MANDU_SCOPE_ID = MANDU_SESSION_KEY). */
  sessionKey: string;
  mode: "pty" | "pipe" | "passthrough";
  /** True only for a PTY relay that paints reserve blocks (not killed by
   *  MANDU_REPLY_RESERVE=0). */
  reserve: boolean;
  /** True when this filter paints v2 heads (`T/1:N:W:F`, §11.3); sent with
   *  `reserve: true`. The proxy sends v2 heads only to a relay that said so. */
  wrap?: boolean;
  cols?: number;
  rows?: number;
  /** The agent's TUI wraps its reply by this rule (§17; reserve-layout.ts
   *  LayoutRule). Sent only for `terminal`; absent means `ink`. */
  rule?: "ink" | "terminal";
}

/**
 * Structural shape of the real arbiter IPC client (arbiter/ipc/client.ts). We
 * declare it here rather than importing so this package typechecks standalone
 * (the arbiter is a sibling package). `emit` is typed OPTIONAL so an older
 * arbiter build without it degrades to "no observability" rather than a crash.
 */
export interface RealArbiterClient {
  connect(): Promise<void>;
  /** Times the client moved to a re-learned human socket (a restarted
   *  arbiter, arbiter-human-plane.md §5.1); absent on an older client. */
  readonly rediscoveries?: number;
  desymbolize(text: string): Promise<string>;
  emit?(event: unknown): Promise<number>;
  /** OPTIONAL like `emit`: an arbiter build without the op leaves the
   *  session unreported (the proxy then never expands a reserve block). */
  setSessionRelay?(relay: SessionRelay): Promise<unknown>;
  /** OPTIONAL: an arbiter without the op leaves a headless block's rows
   *  blank (§3.8). */
  reserveBlock?(sessionKey: string, hash: string): Promise<ReserveBlockInfo | null>;
  close(): void;
}

/** Adapter: present the real arbiter IPC client as a `ReplyArbiter`. The
 *  client MUST be one over the human-plane socket: on the data socket every
 *  `desymbolize` is refused (and the filter passes the text through). */
export class ArbiterClientAdapter implements ReplyArbiter {
  constructor(private readonly client: RealArbiterClient) {}

  desymbolize(text: string): Promise<string> {
    return this.client.desymbolize(text);
  }

  async emit(event: unknown): Promise<number> {
    if (!this.client.emit) return -1; // pre-emit arbiter → observability off
    return this.client.emit(event);
  }

  async setSessionRelay(relay: SessionRelay): Promise<void> {
    if (!this.client.setSessionRelay) return; // pre-reservation arbiter → no expansion
    await this.client.setSessionRelay(relay);
  }

  async reserveBlock(sessionKey: string, hash: string): Promise<ReserveBlockInfo | null> {
    if (!this.client.reserveBlock) return null; // pre-§3.8 arbiter → headless rows stay blank
    return (await this.client.reserveBlock(sessionKey, hash)) ?? null;
  }
}
