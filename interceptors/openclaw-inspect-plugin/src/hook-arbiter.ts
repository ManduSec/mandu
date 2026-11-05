/**
 * hook-arbiter — the arbiter surface the plugin's hooks speak to, and the
 * seam for the reply release no arbiter op serves yet.
 *
 * Mandu OpenClaw plugin (interceptors/openclaw-inspect-plugin). The
 * arbiter-client pattern (CONTRIBUTING.md): a NARROW interface (`HookArbiter`),
 * an adapter over the real IPC client (arbiter/ipc/client.ts), a mock in
 * test/helpers/mock-hook-arbiter.ts, and a parity test that builds the
 * PRODUCTION wiring over a real ArbiterServer
 * (tests/stack/openclaw-plugin-parity.test.ts). Mandu-new.
 *
 * THE DATA SOCKET ONLY (openclaw-plugin.md §3.3). The plugin lives in the
 * Gateway, among the agent's programs, so it holds no human-plane socket:
 * what it emits is stored as a claim, and no op it calls returns an
 * original. Both ops below are data-plane ops:
 *   - egressFingerprintScan(surfaces, destination) → {tripped, hits}
 *       the §4 verbatim-leak tripwire: a registered secret value found
 *       verbatim, bound for a destination no binding admits. The hits carry
 *       the placeholder, the level and the surface, never the value.
 *   - emit(event) → seq   best-effort observability, never on the decision.
 *
 * THE RELEASE SEAM (`ReplyReleaser`). Putting a real value back in a chat
 * reply where a rule binds that destination needs an op that both DECIDES
 * for a chat destination (channel, account, conversation) and RETURNS the
 * value over the data socket. None exists: `desymbolize` and `resolve` are
 * human-plane ops (refused here), and the egress gate's bindings are hosts,
 * not chat destinations. Until one exists the plugin runs `NO_RELEASE`:
 * every placeholder stays, which is the safe direction. The op it needs is
 * written down in openclaw-plugin.md §3.5.
 */

/** One surface for the tripwire (`where` is for the audit only). */
export interface FingerprintSurface {
  where: string;
  text: string;
}

/** The tripwire's answer (arbiter/ipc/protocol.ts EgressFingerprintScanResultWire). */
export interface FingerprintScanResult {
  tripped: boolean;
  hits: Array<{ symbol: string; level: string; where: string }>;
}

/** The narrow arbiter surface the hooks depend on. */
export interface HookArbiter {
  /** `scope: "reply"`: the surfaces are a reply the model wrote (the
   *  arbiter then counts a whole-masked tool result only by its secrets). */
  egressFingerprintScan(surfaces: FingerprintSurface[], destination: string, scope?: "reply"): Promise<FingerprintScanResult>;
  /** Best-effort; the seq, or -1 when the arbiter has no emit. */
  emit(event: unknown): Promise<number>;
}

/** Structural shape of the real arbiter IPC client (the subset used). */
export interface RealHookArbiterClient {
  egressFingerprintScan(args: { surfaces: FingerprintSurface[]; destination: string; scope?: "reply" }): Promise<FingerprintScanResult>;
  emit?(event: never): Promise<number>;
}

/** Adapter: the real arbiter IPC client as a `HookArbiter`. Built over a
 *  client of the DATA socket (the only one the plugin is given). */
export class HookArbiterAdapter implements HookArbiter {
  constructor(private readonly client: RealHookArbiterClient) {}

  async egressFingerprintScan(surfaces: FingerprintSurface[], destination: string, scope?: "reply"): Promise<FingerprintScanResult> {
    const r = await this.client.egressFingerprintScan({ surfaces, destination, ...(scope ? { scope } : {}) });
    // A malformed answer is no answer: the caller treats a throw as "could
    // not check" (the reply keeps its placeholders, see hooks.ts).
    if (r === null || typeof r !== "object" || typeof r.tripped !== "boolean" || !Array.isArray(r.hits)) {
      throw new Error("egressFingerprintScan: malformed answer");
    }
    return { tripped: r.tripped, hits: r.hits.map((h) => ({ symbol: String(h.symbol), level: String(h.level), where: String(h.where) })) };
  }

  async emit(event: unknown): Promise<number> {
    if (!this.client.emit) return -1;
    return this.client.emit(event as never);
  }
}

/** Where a reply goes (message_sending's event `to` and context). */
export interface ReplyDestination {
  channel: string;
  accountId?: string;
  conversationId?: string;
  to: string;
  threadId?: string;
}

/** What a release answers: the reply with the bound values put back, and
 *  the placeholders it released. Every other placeholder stays. */
export interface ReleaseAnswer {
  text: string;
  released: string[];
}

/** The release seam (see the header). */
export interface ReplyReleaser {
  /** True when a real release op backs this releaser. */
  readonly live: boolean;
  release(args: { sessionKey: string; destination: ReplyDestination; text: string; placeholders: string[] }): Promise<ReleaseAnswer>;
}

/** Today's releaser: no op decides a chat destination, so nothing is put
 *  back and every placeholder stays. */
export const NO_RELEASE: ReplyReleaser = {
  live: false,
  async release({ text }) {
    return { text, released: [] };
  },
};
