/**
 * resolve-health — the reply filter's record of its own lookups
 * (docs/design/ui/reply-row-reservation.md §18, "A resolver that refuses").
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code, no reference
 * origin (the reference resolves in-process and cannot fail this way).
 *
 * The filter is a utility surface: when a `desymbolize` call fails it passes
 * the text through UNCHANGED, so the placeholder stays opaque on the human's
 * terminal and nothing leaks. Before this module that fallback was silent: a
 * filter whose every lookup the arbiter refused (the 2026-09-30 S8 drill: a
 * reply filter built before the human plane asked the data socket, which a
 * newer arbiter refuses, nine times) showed raw `$MDU:nomodel_Bash[…]` tokens
 * and left no record of why. The arbiter logged nine refusals from "an unknown
 * process"; the session's events had no `desymbolize` and no degradation.
 *
 * `WatchedResolver` wraps the resolver the stream filter and the screen
 * reconciler share. It changes no result and no error (a failure still
 * throws, so every caller keeps its own pass-through fallback); it only
 * notices the state changes:
 *   - the first failure after a healthy state → `onDegraded(reason)` (the
 *     wrapper records a `relay_mode` event carrying `resolveFailure`, which
 *     the dashboard's session health turns into a broken chip);
 *   - the first success after a failure → `onRecovered()` (a plain
 *     `relay_mode` again, so the LAST record says the relay resolves);
 * and keeps a count for the note the wrapper prints when the agent exits.
 *
 * The reason is the error's message, clipped: the arbiter's refusal text and
 * a socket error carry no original (a refusal names only the op; the filter
 * never sends a value, only the agent's own placeholders).
 */

/** The one capability watched (filter.ts ReplyResolver). */
export interface Desymbolizer {
  desymbolize(text: string): Promise<string>;
}

export interface ResolveHealthHooks {
  /** The first failure after a healthy state (or the first ever). */
  onDegraded?: (reason: string) => void;
  /** The first success after a failure, or the first success on a NEW
   *  endpoint (`epoch` moved: the client re-learned a restarted arbiter's
   *  human socket, arbiter-human-plane.md §5.1). */
  onRecovered?: () => void;
  /** A counter the client bumps each time it moves to a rediscovered
   *  endpoint (ArbiterClient `rediscoveries`); absent = it never moves. */
  epoch?: () => number;
}

/** Longest reason kept: an error message is a sentence, not a payload. */
export const RESOLVE_REASON_MAX = 240;
/** State changes reported per session at most: a flapping arbiter must not
 *  flood the event log (the count and the exit note still see every failure). */
export const RESOLVE_HEALTH_EVENTS_MAX = 20;

/** An error's message as a one-line reason, clipped. */
export function resolveFailureReason(err: unknown): string {
  const raw = err instanceof Error ? err.message : typeof err === "string" ? err : "unknown error";
  const line = raw.replace(/\s+/g, " ").trim() || "unknown error";
  return line.length > RESOLVE_REASON_MAX ? `${line.slice(0, RESOLVE_REASON_MAX - 1)}…` : line;
}

export class WatchedResolver implements Desymbolizer {
  /** Lookups that failed, all session. */
  failures = 0;
  /** Lookups that answered, all session. */
  successes = 0;
  /** The first failure's reason (the exit note names it). */
  firstReason: string | null = null;
  private degraded = false;
  private seenEpoch = 0;
  /** Successes that came on a new endpoint (a restarted arbiter). */
  moves = 0;
  private reported = 0;

  constructor(
    private readonly inner: Desymbolizer,
    private readonly hooks: ResolveHealthHooks = {},
  ) {}

  private epochNow(): number {
    try {
      const e = this.hooks.epoch?.();
      return typeof e === "number" && Number.isFinite(e) ? e : this.seenEpoch;
    } catch {
      return this.seenEpoch;
    }
  }

  /** True while the last lookup failed. */
  get isDegraded(): boolean {
    return this.degraded;
  }

  async desymbolize(text: string): Promise<string> {
    let out: string;
    try {
      out = await this.inner.desymbolize(text);
    } catch (err) {
      this.failures += 1;
      const reason = resolveFailureReason(err);
      if (this.firstReason === null) this.firstReason = reason;
      if (!this.degraded) {
        this.degraded = true;
        this.report(() => this.hooks.onDegraded?.(reason));
      }
      throw err;
    }
    this.successes += 1;
    const epoch = this.epochNow();
    const moved = epoch !== this.seenEpoch;
    if (moved) {
      this.seenEpoch = epoch;
      this.moves += 1;
    }
    if (this.degraded || moved) {
      this.degraded = false;
      this.report(() => this.hooks.onRecovered?.());
    }
    return out;
  }

  /** The line the wrapper prints when the agent exits, or null when every
   *  lookup answered. Says what the human saw and that nothing leaked. */
  exitNote(): string | null {
    if (this.failures === 0) return null;
    const n = this.failures;
    return `${n} placeholder lookup${n === 1 ? "" : "s"} failed (first: ${this.firstReason ?? "unknown error"}); ` +
      "those $MDU: placeholders stayed opaque on your terminal (nothing leaked).";
  }

  private report(fn: () => void): void {
    if (this.reported >= RESOLVE_HEALTH_EVENTS_MAX) return;
    this.reported += 1;
    try {
      fn();
    } catch {
      /* observability never disturbs the stream */
    }
  }
}
