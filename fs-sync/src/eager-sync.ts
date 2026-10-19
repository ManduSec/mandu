/**
 * eager-sync — the coalescing AgentView→HumanView sync driver behind the
 * launcher's `--fs-sync-eager` rung (docs/design/integrity/fs-sync.md §2.3–§4,
 * option B, Phase 1).
 *
 * Mandu-new (NO reference origin). The reference fired `syncToHuman` from an
 * OpenClaw `after_tool_call` hook; Mandu lost that hook in the port and this
 * driver recovers the same tool-call-boundary cadence from the arbiter's
 * observability event stream: a `tool_result` crossing the context proxy is the
 * first signal any component has that a tool call (and its writes) finished, so
 * each one becomes a coalesced `syncToHuman` trigger. The event is only a
 * clock — `syncToHuman` diffs the whole worktree, so the trigger never needs to
 * know which paths a tool touched, and over-triggering early-returns cheaply.
 *
 * Coalescing rule (design §3): at most ONE sync in flight and ONE pending; a
 * trigger arriving during an in-flight sync sets the pending slot; the pending
 * run uses the LATEST provenance. A burst of N triggers therefore produces at
 * most in-flight + 1 syncs.
 *
 * FAIL-SAFE, NEVER FAIL-CLOSED (design §5): sync-back is utility-class, like
 * reply-filter — no security property may depend on a trigger firing. Every
 * failure path here (malformed event, filter error, sync throw, arbiter
 * hiccup) warns and keeps consuming; nothing throws out of the driver and no
 * rejection escapes it. A lost trigger or failed sync means a staler HumanView
 * until the next trigger or the launcher's UNCONDITIONAL post-exit sweep —
 * never anything worse. Symbols stay opaque throughout: this driver only moves
 * WHEN the existing trusted-destination desymbolization (ViewSync.syncToHuman)
 * runs, never what it does.
 */

import type { Logger, WriteProvenance } from "./view-sync.js";

const NOOP_LOG: Logger = { info: () => {}, warn: () => {}, error: () => {} };

/** Provenance fallback when neither the event nor a correlated tool_use names
 * the tool (e.g. a TRUSTED result that allocated no symbols and whose tool_use
 * predates this driver). Honest: the trigger WAS a tool_result. */
const FALLBACK_TOOL = "tool_result";

/** Bound on the callId→toolName correlation cache (a long session emits one
 * tool_use per call; evict oldest-first so memory stays flat). */
const TOOL_NAME_CACHE_MAX = 512;

/**
 * The one thing the driver needs from the `ViewSync`: the two-stage commit.
 * Narrow on purpose so unit tests drive the coalescer with a mock and the
 * watch CLI can wrap the real `ViewSync` without this module importing it.
 */
export interface EagerSyncTarget {
  syncToHuman(prov: WriteProvenance): Promise<string[]>;
  /**
   * HumanView → AgentView: reconcile what the HUMAN changed since the last
   * recorded state (ViewSync.reconcileHumanEdits). Optional so a sync-only
   * target keeps working. When present it runs FIRST in every run, inside the
   * same single slot as the sync — see `run` for why the order and the shared
   * slot both matter.
   */
  reconcileHumanEdits?(): Promise<unknown>;
}

/** A run the HUMAN-EDIT CLOCK asked for: reconcile only. It must NOT sync —
 *  there is no tool call behind it, and a sync it ran would commit the agent's
 *  pending writes under no callId, stealing the commit pair from the
 *  tool_result that is about to name them. */
const RECONCILE_ONLY = Symbol("reconcile-only");
type Run = WriteProvenance | typeof RECONCILE_ONLY;

export interface EagerSyncOptions {
  target: EagerSyncTarget;
  log?: Logger;
  /**
   * Optional session scoping (design §4): return true when the event's session
   * belongs to this workspace, false when it PROVABLY belongs to another one,
   * undefined when it can't be matched. Unknown — and a throwing filter —
   * degrade to "sync on any tool_result": the worktree diff is the source of
   * truth and early-returns when nothing changed, so over-triggering is cheap
   * and safe, while under-triggering would silently starve the HumanView.
   */
  sessionMatches?: (sessionId: string) => boolean | undefined;
}

/**
 * Coalescing sync driver. Feed it raw arbiter events via `handleEvent` (any
 * shape — it is tolerant like the event-store readers); it triggers the target
 * on each in-scope `tool_result`, mapping the event onto `WriteProvenance`:
 *
 *   - toolName ← the result's `output.symbols[0].tool` (the emitting tool the
 *     proxy recorded on the symbol) when present, else the name learned from
 *     the `tool_use` event sharing the same `callId`, else "tool_result".
 *   - callId   ← the event's `callId` (the Anthropic tool_use id).
 *   - runId    ← the event's `sessionId` (the Mandu scope id).
 */
export class EagerSync {
  private readonly target: EagerSyncTarget;
  private readonly log: Logger;
  private readonly sessionMatches?: (sessionId: string) => boolean | undefined;
  /** callId → tool name, learned from tool_use events (bounded, oldest-out). */
  private readonly toolNames = new Map<string, string>();
  private inFlight = false;
  private pending: Run | null = null;
  private idleWaiters: Array<() => void> = [];
  /** Observability counters (the watch loop logs them; tests may assert). */
  syncsRun = 0;
  syncsFailed = 0;
  reconcilesFailed = 0;

  constructor(opts: EagerSyncOptions) {
    this.target = opts.target;
    this.log = opts.log ?? NOOP_LOG;
    this.sessionMatches = opts.sessionMatches;
  }

  /**
   * Consume one raw event from the subscription. NEVER throws (fail-safe): a
   * malformed event is warned about and dropped — the sweep remains the
   * catch-all.
   */
  handleEvent(raw: unknown): void {
    try {
      if (raw === null || typeof raw !== "object") return;
      const ev = raw as Record<string, unknown>;
      if (ev["kind"] === "tool_use") {
        this.learnToolName(ev);
        return;
      }
      if (ev["kind"] !== "tool_result") return;
      if (!this.eventInScope(ev)) return;
      this.trigger(this.provenanceOf(ev));
    } catch (err) {
      this.log.warn(
        `[fs-sync] eager-sync: dropped a malformed event (sweep remains the catch-all): ${(err as Error).message}`,
      );
    }
  }

  /**
   * Request a sync with the given provenance, coalescing (design §3): if one is
   * already in flight the request parks in the single pending slot — the LATEST
   * provenance wins, earlier parked triggers are absorbed (the sync diffs the
   * whole worktree, so their changes ride along).
   */
  trigger(prov: WriteProvenance): void {
    if (this.inFlight) {
      this.pending = prov;
      return;
    }
    void this.run(prov);
  }

  /**
   * The human-edit clock's trigger (fs-sync.md §2.5a): something changed
   * under the HumanView, so run a RECONCILE soon (no sync — see RECONCILE_ONLY).
   * Same single slot as `trigger`; a parked sync is never replaced by it.
   */
  triggerReconcile(): void {
    if (this.inFlight) {
      // a parked sync run reconciles first anyway
      if (this.pending === null) this.pending = RECONCILE_ONLY;
      return;
    }
    void this.run(RECONCILE_ONLY);
  }

  /** Resolves once no sync is in flight and none is pending. For clean
   * shutdown (finish the in-flight commit pair) and deterministic tests. */
  idle(): Promise<void> {
    if (!this.inFlight && this.pending === null) return Promise.resolve();
    return new Promise((resolve) => this.idleWaiters.push(resolve));
  }

  private async run(job: Run): Promise<void> {
    this.inFlight = true;
    if (job !== RECONCILE_ONLY) this.syncsRun++;
    // RECONCILE, THEN SYNC, in ONE slot (fs-sync.md §2.5a).
    //  * Order: a human-edited file is HumanView-dirty, which the sync R2-refuses
    //    forever; reconciling first records the edit, so the same run's sync can
    //    proceed on that path.
    //  * One slot: both take the layout's commit lock, which THROWS when held,
    //    and the sync desymbolizes untrusted bytes into the HumanView before it
    //    commits them — a reconcile that observed that window would import them
    //    as human-authored. Serialized here, it never can: after a sync the
    //    paths it wrote are clean against the shadow HEAD.
    // FAIL-SAFE like the sync: a failed reconcile warns and the run goes on.
    if (this.target.reconcileHumanEdits) {
      try {
        await this.target.reconcileHumanEdits();
      } catch (err) {
        this.reconcilesFailed++;
        this.log.warn(
          `[fs-sync] human-edit reconcile failed; the AgentView keeps the pre-edit twin until the next ` +
            `trigger or the next launch's seed: ${(err as Error).message}`,
        );
      }
    }
    try {
      if (job !== RECONCILE_ONLY) await this.target.syncToHuman(job);
    } catch (err) {
      const prov = job as WriteProvenance;
      // FAIL-SAFE (design §5): a failed sync means a staler HumanView until
      // the next trigger or the post-exit sweep — warn and keep consuming.
      this.syncsFailed++;
      this.log.warn(
        `[fs-sync] eager sync failed (tool=${prov.toolName} callId=${prov.callId ?? "none"}); ` +
          `HumanView stays stale until the next trigger or the post-exit sweep: ${(err as Error).message}`,
      );
    } finally {
      this.inFlight = false;
      const next = this.pending;
      this.pending = null;
      if (next) void this.run(next);
      else this.notifyIdle();
    }
  }

  private notifyIdle(): void {
    const waiters = this.idleWaiters;
    this.idleWaiters = [];
    for (const w of waiters) w();
  }

  /** Positive-mismatch-only filter: skip when the filter says false; sync on
   * true, unknown, or a throwing filter (degrade per design §4). */
  private eventInScope(ev: Record<string, unknown>): boolean {
    if (!this.sessionMatches) return true;
    const sessionId = typeof ev["sessionId"] === "string" ? ev["sessionId"] : "";
    let verdict: boolean | undefined;
    try {
      verdict = this.sessionMatches(sessionId);
    } catch {
      verdict = undefined; // can't be matched → sync on any tool_result
    }
    return verdict !== false;
  }

  /** Record callId→name from a `tool_use` event. The proxies render tool_use
   * input as `Name({...json...})` (see anthropic-proxy events.ts makeToolUse);
   * the name prefix is all we need for the commit-pair provenance. */
  private learnToolName(ev: Record<string, unknown>): void {
    const callId = ev["callId"];
    if (typeof callId !== "string" || callId === "") return;
    const input = ev["input"];
    const symbolized =
      input !== null && typeof input === "object"
        ? (input as Record<string, unknown>)["symbolized"]
        : undefined;
    if (typeof symbolized !== "string") return;
    const m = /^([A-Za-z_][A-Za-z0-9_-]*)\(/.exec(symbolized);
    if (!m) return;
    if (this.toolNames.size >= TOOL_NAME_CACHE_MAX) {
      const oldest = this.toolNames.keys().next().value;
      if (oldest !== undefined) this.toolNames.delete(oldest);
    }
    this.toolNames.set(callId, m[1]!);
  }

  /** Map a tool_result event onto the commit-pair provenance (header note). */
  private provenanceOf(ev: Record<string, unknown>): WriteProvenance {
    const callId = typeof ev["callId"] === "string" && ev["callId"] !== "" ? ev["callId"] : undefined;
    const runId = typeof ev["sessionId"] === "string" && ev["sessionId"] !== "" ? ev["sessionId"] : undefined;
    return { toolName: this.toolNameOf(ev, callId), callId, runId };
  }

  private toolNameOf(ev: Record<string, unknown>, callId: string | undefined): string {
    // Primary: the tool recorded on the result's symbols (a symbolized —
    // UNTRUSTED — result always carries it; see the tool_result event shape).
    const output = ev["output"];
    if (output !== null && typeof output === "object") {
      const symbols = (output as Record<string, unknown>)["symbols"];
      if (Array.isArray(symbols) && symbols.length > 0) {
        const first = symbols[0] as Record<string, unknown> | null;
        const tool = first !== null && typeof first === "object" ? first["tool"] : undefined;
        if (typeof tool === "string" && tool !== "") return tool;
      }
    }
    // Fallback: the tool_use we saw earlier for this callId (a TRUSTED result
    // carries no symbols — e.g. a Write confirmation — but its tool_use named it).
    if (callId !== undefined) {
      const learned = this.toolNames.get(callId);
      if (learned !== undefined) return learned;
    }
    return FALLBACK_TOOL;
  }
}
