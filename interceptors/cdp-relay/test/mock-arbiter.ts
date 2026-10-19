/**
 * mock-arbiter — the relay's `Arbiter` for unit and component tests.
 * Registered values come back as their symbols (the prompt filter's
 * registered-value rule); a symbol is released only to the hosts bound to
 * it. Mandu-new (no reference origin).
 */
import type { Arbiter, RelayNotice, DesymbolizationDecision, DesymbolizationRequest, FilteredSegment, TextSegment } from "../src/arbiter-client.js";

export interface MockSecret {
  value: string;
  symbol: string;
  /** Host suffixes the value may be released to. */
  bindings: string[];
}

export class MockArbiter implements Arbiter {
  /** Every text the relay asked about. */
  readonly filtered: string[] = [];
  readonly decisions: DesymbolizationRequest[] = [];
  readonly resolved: string[] = [];
  /** Every refusal the relay reported for the model (§3.4). */
  readonly notices: Array<{ notice: RelayNotice; session?: string }> = [];
  /** Set to make relayNotice throw (it must never matter). */
  noticeDown = false;
  /** Every event the relay emitted. */
  readonly events: Array<Record<string, unknown>> = [];
  /** Set to make emit throw (it must never matter). */
  emitDown = false;
  /** Set to make the filter throw (the arbiter unreachable). */
  filterDown = false;
  /** Set to make the release gate throw. */
  gateDown = false;
  /** Set to make resolve throw (after an allow). */
  resolveDown = false;
  /** A segment containing this text is answered `hold`. */
  holdOn: string | null = null;
  /** Symbols answered "needs the person's approval". */
  readonly asks = new Set<string>();
  /** Symbols answered "Send without it". */
  readonly strips = new Set<string>();

  constructor(readonly secrets: MockSecret[]) {}

  async emit(event: Record<string, unknown>): Promise<void> {
    if (this.emitDown) throw new Error("connect ENOENT arbiter.sock");
    this.events.push(event);
  }

  async relayNotice(notice: RelayNotice, session?: string): Promise<void> {
    if (this.noticeDown) throw new Error("connect ENOENT arbiter.sock");
    this.notices.push({ notice, ...(session !== undefined ? { session } : {}) });
  }

  async filterText(segments: TextSegment[]): Promise<FilteredSegment[]> {
    if (this.filterDown) throw new Error("connect ENOENT arbiter.sock");
    return segments.map((s) => {
      this.filtered.push(s.text);
      if (this.holdOn !== null && s.text.includes(this.holdOn)) return { id: s.id, action: "hold" as const };
      let text = s.text;
      for (const sec of this.secrets) text = text.split(sec.value).join(sec.symbol);
      return text === s.text ? { id: s.id, action: "pass" as const } : { id: s.id, action: "rewrite" as const, text };
    });
  }

  async desymbolizationDecision(req: DesymbolizationRequest): Promise<DesymbolizationDecision> {
    if (this.gateDown) throw new Error("connect ENOENT human.sock");
    this.decisions.push(req);
    if (this.strips.has(req.symbol)) return { allow: false, requiresApproval: false, reason: "send without it", strip: true };
    if (this.asks.has(req.symbol)) return { allow: false, requiresApproval: true, reason: "needs approval", approvalId: "ap-1" };
    const sec = this.secrets.find((s) => s.symbol === req.symbol);
    if (sec === undefined) return { allow: true, reason: "unknown symbol" };
    const bound = sec.bindings.some((b) => req.destination === b || req.destination.endsWith(`.${b}`));
    return bound ? { allow: true, reason: `bound to ${req.destination}` } : { allow: false, requiresApproval: false, reason: `not bound to ${req.destination}` };
  }

  /** Every base the relay looked up (placeholderKnown, §3.3). */
  readonly looked: string[] = [];
  /** Set to make placeholderKnown throw (the human plane unreachable). */
  lookupDown = false;

  async placeholderKnown(base: string): Promise<boolean> {
    if (this.lookupDown) throw new Error("connect ENOENT human.sock");
    this.looked.push(base);
    // The arbiter's rule: the base's own row, or a field's beneath it.
    return this.secrets.some((s) => s.symbol === base || s.symbol.startsWith(`${base}.`));
  }

  async resolve(symbol: string): Promise<string | null> {
    if (this.resolveDown) throw new Error("connect ENOENT human.sock");
    this.resolved.push(symbol);
    return this.secrets.find((s) => s.symbol === symbol)?.value ?? null;
  }
}
