/**
 * reserve-eligibility — the arbiter-backed half of reply row reservation's
 * eligibility for the Codex proxy: the kill switch, the session relayed
 * through a PTY by a filter that paints reserve blocks, whether it paints v2
 * heads (`wrap` and `cols`), and each token's shape from `symbolShape`.
 *
 * Mandu Track A (interceptors/openai-proxy). Design:
 * docs/design/ui/reply-row-reservation.md §3.2, §3.3, §3.6, §11.4, §11.5, §11.7.
 *
 * PROVENANCE: copied VERBATIM (2026-09-30) from the eligibility section of
 * interceptors/anthropic-proxy/src/sse-reserve-expand.ts (`ReserveEligibility`
 * and its types, from "eligibility (the proxy's callbacks)" to the end of
 * that file). The Claude proxy keeps it next to its Messages expander; here
 * it stands alone because the Responses expander (sse-reserve-expand.ts) is
 * a different stream. Change both together.
 *
 * Every failure answers null: no expansion ("no rewrite, never guess").
 */

/** A v2 shape answer: `rows` is absent from an arbiter predating v2;
 *  `last`, the width of the last row, from one predating §14. */
export interface ReserveShape {
  lines: number;
  rows?: number;
  last?: number;
}

// ── eligibility (the proxy's callbacks) ──────────────────────────────────────

/** The relay state eligibility reads (reply-row-reservation.md §3.6, §11.5). */
export interface ReserveRelay {
  mode: string;
  reserve: boolean;
  /** The terminal's columns (v2 needs it). */
  cols?: number;
  /** The filter paints v2 heads. */
  wrap?: boolean;
  /** Where the agent's TUI counts a reply TAB's stops from (§19.7); absent:
   *  `screen`. */
  tabs?: string;
}

/** The arbiter ops eligibility reads (both optional: absent = no expansion).
 *  Both answer on the HUMAN plane (§5.3, §11.5). */
export interface ReserveArbiter {
  symbolShape?(token: string, opts?: { width: number; first: number; indent?: number }): Promise<ReserveShape | null>;
  sessionRelay?(sessionKey: string): Promise<ReserveRelay | null>;
  /** §3.8: record an expanded block (optional; absent = not recorded). */
  noteReserveBlock?(args: { sessionKey: string; token: string; n: number; width?: number; first?: number }): Promise<void>;
}

export interface ReserveEligibilityOptions {
  /** Kill switch (`MANDU_REPLY_RESERVE=0` → false). */
  enabled: boolean;
  /** The session key the reply filter reports under (MANDU_SESSION_KEY). */
  sessionKey?: string;
  /** Deadline for each arbiter call (default 150 ms). */
  timeoutMs?: number;
  /** How long a sessionRelay answer is reused (default 1000 ms). */
  relayTtlMs?: number;
  /** Bounded per-process shape cache (default 4096 entries). */
  shapeCacheMax?: number;
  /** Injectable clock for tests. */
  now?: () => number;
}

export const RESERVE_TIMEOUT_MS = 150;
export const RESERVE_RELAY_TTL_MS = 1000;
export const RESERVE_SHAPE_CACHE_MAX = 4096;

const TIMEOUT = Symbol("timeout");

/** `p`, or TIMEOUT after `ms`. Never rejects (a rejection becomes TIMEOUT). */
function withDeadline<T>(p: Promise<T>, ms: number): Promise<T | typeof TIMEOUT> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(TIMEOUT), ms);
    timer.unref?.();
    p.then(
      (v) => { clearTimeout(timer); resolve(v); },
      () => { clearTimeout(timer); resolve(TIMEOUT); },
    );
  });
}

/** What a relay answer allows: `ok` = expansion at all (PTY, reserve);
 *  `cols` = v2 heads (the filter reports `wrap: true` and its columns). */
interface RelayVerdict {
  ok: boolean;
  cols: number | null;
  /** The TUI counts a TAB's stops from the content area (§19.7). */
  contentTabs: boolean;
}

/**
 * The eligibility checks of reply-row-reservation.md §3.2 / §11.4 that need
 * the arbiter: the kill switch, the session relayed through a PTY by a
 * filter that paints reserve blocks (cached per session for one second),
 * whether it paints v2 heads (`wrap` and `cols`), and the token's shape
 * (cached for the process lifetime, bounded, keyed by token AND layout).
 * Every failure answers null: no expansion.
 */
export class ReserveEligibility {
  private readonly timeoutMs: number;
  private readonly relayTtlMs: number;
  private readonly shapeCacheMax: number;
  private readonly now: () => number;
  private relay: { at: number; v: RelayVerdict } | null = null;
  private readonly shapes = new Map<string, ReserveShape>();

  constructor(private readonly arbiter: ReserveArbiter, private readonly opts: ReserveEligibilityOptions) {
    this.timeoutMs = opts.timeoutMs ?? RESERVE_TIMEOUT_MS;
    this.relayTtlMs = opts.relayTtlMs ?? RESERVE_RELAY_TTL_MS;
    this.shapeCacheMax = opts.shapeCacheMax ?? RESERVE_SHAPE_CACHE_MAX;
    this.now = opts.now ?? Date.now;
  }

  /** Whether expansion can ever fire here (cheap; no arbiter call). */
  get possible(): boolean {
    return this.opts.enabled && !!this.opts.sessionKey &&
      typeof this.arbiter.symbolShape === "function" && typeof this.arbiter.sessionRelay === "function";
  }

  /** This session's relay verdict (cached; a timeout or error is not). */
  private async relayVerdict(): Promise<RelayVerdict> {
    if (!this.possible) return { ok: false, cols: null, contentTabs: false };
    const t = this.now();
    if (this.relay && t - this.relay.at < this.relayTtlMs) return this.relay.v;
    const r = await withDeadline(this.arbiter.sessionRelay!(this.opts.sessionKey!), this.timeoutMs);
    // A timeout or error is not cached: the next response asks again.
    if (r === TIMEOUT) return { ok: false, cols: null, contentTabs: false };
    const ok = r !== null && typeof r === "object" && r.mode === "pty" && r.reserve === true;
    const cols = ok && r!.wrap === true && typeof r!.cols === "number" && Number.isInteger(r!.cols) && r!.cols > 0
      ? r!.cols
      : null;
    const v = { ok, cols, contentTabs: ok && r!.tabs === "content" };
    this.relay = { at: t, v };
    return v;
  }

  /** Whether this session's relay paints reserve blocks (cached). */
  async relayReserves(): Promise<boolean> {
    return (await this.relayVerdict()).ok;
  }

  /** The `layout` callback for SseReserveExpander: the relay's columns when
   *  it paints v2 heads, with the TUI's TAB origin (§19.7), else null (v1). */
  readonly layout = async (): Promise<{ cols: number; tabs?: "content" } | null> => {
    const v = await this.relayVerdict();
    if (!v.ok || v.cols === null) return null;
    return v.contentTabs ? { cols: v.cols, tabs: "content" } : { cols: v.cols };
  };

  /** One bounded, cached symbolShape call. */
  private async ask(token: string, layout?: { width: number; first: number; indent?: number }): Promise<ReserveShape | null> {
    const key = layout ? `${token}\u0000${layout.width}\u0000${layout.first}\u0000${layout.indent ?? 0}` : token;
    const hit = this.shapes.get(key);
    if (hit !== undefined) return hit;
    const call = layout ? this.arbiter.symbolShape!(token, layout) : this.arbiter.symbolShape!(token);
    const r = await withDeadline(call, this.timeoutMs);
    if (r === TIMEOUT || r === null || typeof r !== "object") return null;
    const n = r.lines;
    if (typeof n !== "number" || !Number.isInteger(n) || n < 0) return null;
    const shape: ReserveShape = { lines: n };
    if (layout && typeof r.rows === "number" && Number.isInteger(r.rows) && r.rows >= 0) shape.rows = r.rows;
    if (layout && typeof r.last === "number" && Number.isInteger(r.last) && r.last >= 0) shape.last = r.last;
    if (this.shapes.size >= this.shapeCacheMax) {
      const oldest = this.shapes.keys().next().value;
      if (oldest !== undefined) this.shapes.delete(oldest);
    }
    this.shapes.set(key, shape);
    return shape;
  }

  /** The `lines` callback for SseReserveExpander (v1 heads). */
  readonly lines = async (token: string): Promise<number | null> => {
    if (!(await this.relayReserves())) return null;
    return (await this.ask(token))?.lines ?? null;
  };

  /** The `register` callback for SseReserveExpander (§3.8): record the block
   *  under this session, bounded by the same deadline as every other call.
   *  A timeout or failure is swallowed: the block still goes out. */
  readonly register = async (e: { token: string; rows: number; width?: number; first?: number }): Promise<void> => {
    if (!this.opts.sessionKey || typeof this.arbiter.noteReserveBlock !== "function") return;
    await withDeadline(this.arbiter.noteReserveBlock({
      sessionKey: this.opts.sessionKey, token: e.token, n: e.rows,
      ...(e.width !== undefined && e.first !== undefined ? { width: e.width, first: e.first } : {}),
    }), this.timeoutMs);
  };

  /** The `shape` callback for SseReserveExpander (v2 heads). */
  readonly shape = async (token: string, width: number, first: number, indent?: number): Promise<ReserveShape | null> => {
    if (!(await this.relayReserves())) return null;
    // `indent` (§11.2, TAB stops) only when it moves one: 0 is the default.
    return this.ask(token, {
      width, first, ...(indent !== undefined && Number.isInteger(indent) && indent > 0 ? { indent } : {}),
    });
  };
}
