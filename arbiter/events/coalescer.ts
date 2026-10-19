/**
 * coalescer — a arbiter-side backstop that collapses runaway bursts of identical
 * observability events before they hit the append-only event store.
 *
 * Mandu-new (no reference origin). DEFENSE IN DEPTH: net-proxy's self-loop guard
 * (interceptors/net-proxy/src/proxy.ts `isSelfDestination`) stops the specific bug
 * that once emitted 35,723 near-identical `net_action` events in ~21s; this layer
 * is the generic backstop one level down — it bounds the *event-log* blow-up for
 * ANY emitter, present or future, so the dashboard never has to load a 15MB file.
 *
 * Mechanism: per session, watch the signature of consecutive events. The first
 * `burst` of an identical-consecutive run are persisted verbatim; beyond that they
 * are suppressed, and a single `coalesced` summary event is emitted periodically
 * (every `discloseEvery` suppressed) and once when the run ends — each carrying the
 * running suppressed count, so NOTHING is dropped silently (the "no silent caps"
 * rule). The summary is a canonical `net_action`-shaped event the dashboard renders
 * like any other row.
 *
 * SAFETY: this is observability only (off the security path). It NEVER coalesces an
 * invariant-violating event (`invariant.violatedInvariant === true`) — those always
 * pass through verbatim — and it only collapses events whose salient fields are
 * byte-identical, so genuinely distinct events always break the run.
 */

import type { ArbiterEvent } from "./event-store.js";

export interface CoalescerOptions {
  /** Persist the first N identical-consecutive events verbatim before suppressing
   *  (default 100). A short legitimate burst is never touched. */
  burst?: number;
  /** While suppressing a run, emit one `coalesced` summary every M suppressed
   *  events (default 5000) so an unending runaway still discloses progress. */
  discloseEvery?: number;
  /** Clock for the summary `ts` (injectable for tests). Default: ISO now. */
  now?: () => string;
}

/** Fields whose equality defines "the same event repeating". Conservative: any
 *  difference (different destination, status, action, …) breaks the run. The
 *  invariant flag is included so a security event can never share a run with a
 *  benign one, and `claimed` so a run the agent's own programs forge can never
 *  fold a believed event into its summary (arbiter-human-plane.md §10.2). */
const SIG_FIELDS = ["kind", "action", "method", "destination", "status", "boundary", "view", "emitter", "claimed"] as const;

function isImportant(e: ArbiterEvent): boolean {
  const inv = e.invariant as { violatedInvariant?: unknown } | undefined;
  return inv?.violatedInvariant === true;
}

function signature(e: ArbiterEvent): string {
  const parts = SIG_FIELDS.map((f) => String(e[f] ?? ""));
  parts.push(isImportant(e) ? "violated" : "ok");
  return parts.join("");
}

/** Salient fields of a run, copied from its first event, so a summary can mirror
 *  the run it represents (kind/view/boundary/emitter for canonical rendering). */
interface RunSample {
  kind: unknown;
  action: unknown;
  destination: unknown;
  view: unknown;
  boundary: unknown;
  emitter: unknown;
}

interface RunState {
  sig: string;
  sample: RunSample;
  /** How many of this run were persisted verbatim (≤ burst). */
  kept: number;
  /** Total suppressed in this run (disclosed in every summary). */
  totalSuppressed: number;
  /** Suppressed since the last disclosure (resets at each `discloseEvery`). */
  sinceDisclosure: number;
}

export class EmitCoalescer {
  private readonly burst: number;
  private readonly discloseEvery: number;
  private readonly now: () => string;
  private readonly runs = new Map<string, RunState>();
  /** Monotonic counter making every emitted summary id unique. */
  private summarySeq = 0;

  constructor(opts: CoalescerOptions = {}) {
    this.burst = Math.max(1, opts.burst ?? 100);
    this.discloseEvery = Math.max(1, opts.discloseEvery ?? 5000);
    this.now = opts.now ?? (() => new Date().toISOString());
  }

  /**
   * Decide what to persist for one incoming event. Returns the events the arbiter
   * should actually `append` (and fan out), in order: 0 (suppressed), 1 (the event
   * verbatim, OR a periodic summary that stands in for it), or 2 (a run-end summary
   * for the just-ended run, then the new event).
   */
  consider(event: ArbiterEvent): ArbiterEvent[] {
    const sessionId = String(event.sessionId);

    // Security events are never coalesced: flush any pending run summary, emit the
    // event verbatim, and clear the run so it can't begin a suppressible streak.
    if (isImportant(event)) {
      const out = this.flush(sessionId);
      this.runs.delete(sessionId);
      out.push(event);
      return out;
    }

    const sig = signature(event);
    const st = this.runs.get(sessionId);

    if (!st || st.sig !== sig) {
      // The run changed → close out the previous run (summary if it suppressed),
      // then start a fresh run with this event kept.
      const out = this.flush(sessionId);
      this.runs.set(sessionId, {
        sig,
        sample: {
          kind: event.kind,
          action: event.action,
          destination: event.destination,
          view: event.view,
          boundary: event.boundary,
          emitter: event.emitter,
        },
        kept: 1,
        totalSuppressed: 0,
        sinceDisclosure: 0,
      });
      out.push(event);
      return out;
    }

    // Same run as the previous event.
    if (st.kept < this.burst) {
      st.kept++;
      return [event];
    }
    // Beyond the burst → suppress, disclosing a running summary periodically.
    st.totalSuppressed++;
    st.sinceDisclosure++;
    if (st.sinceDisclosure >= this.discloseEvery) {
      st.sinceDisclosure = 0;
      return [this.summary(sessionId, st)];
    }
    return [];
  }

  /** Forget a session's run state without flushing (its event log was DELETED —
   *  the `deleteSession` op): a suppressed-tail summary would only recreate a
   *  file for a session that no longer exists. */
  drop(sessionId: string): void {
    this.runs.delete(sessionId);
  }

  /** Flush a pending run-end summary for `sessionId` (empty if it suppressed
   *  nothing). Does not clear the run — the caller decides what comes next. */
  private flush(sessionId: string): ArbiterEvent[] {
    const st = this.runs.get(sessionId);
    if (st && st.totalSuppressed > 0) return [this.summary(sessionId, st)];
    return [];
  }

  /** Build one canonical `coalesced` net_action-shaped summary for a run. */
  private summary(sessionId: string, st: RunState): ArbiterEvent {
    const suppressed = st.totalSuppressed;
    return {
      kind: st.sample.kind ?? "net_action",
      sessionId,
      id: `${sessionId}:coalesced:${this.summarySeq++}`,
      ts: this.now(),
      turn: 0,
      callId: null,
      parentId: null,
      view: st.sample.view ?? "AgentView",
      boundary: st.sample.boundary ?? "network",
      emitter: st.sample.emitter ?? "arbiter",
      input: null,
      output: null,
      invariant: { violatedInvariant: false },
      action: "coalesced",
      coalesced: { ofAction: st.sample.action ?? null, destination: st.sample.destination ?? null, suppressed },
      reason: `${suppressed} identical ${String(st.sample.kind ?? "event")}/${String(st.sample.action ?? "?")} events coalesced (arbiter rate backstop)`,
    };
  }
}
