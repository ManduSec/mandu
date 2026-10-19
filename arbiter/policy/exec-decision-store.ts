/**
 * exec-decision-store — the proxy↔execve correlation memory (exec-routing.md §4
 * step 1). Mandu-new, no reference origin.
 *
 * The model proxy's `execGate` verdict is RECORDED here keyed by the command's
 * `execSignature`, so the exec-supervisor can later fetch "what did the proxy,
 * with full session context, decide about this command?" and take the MORE
 * RESTRICTIVE of that and its own ground-truth `classifyExec` (defense in depth).
 *
 * NON-PERSISTENT + BOUNDED: correlation is a within-run, best-effort hint (a miss
 * costs only the hint, never security — the supervisor still fail-closes to
 * AgentShell). The store is a simple insertion-ordered map capped at `capacity`;
 * the oldest entry is evicted on overflow so a long run can't grow it unbounded.
 * Single-threaded (Node event loop) → no locking.
 */

/** The proxy's recorded exec decision for one command signature. */
export interface RecordedExecDecision {
  /** The proxy's execGate verdict: did it block the command? */
  block: boolean;
  /** The shell the proxy's classification pointed at (informational). */
  shell: "AgentShell" | "HumanShell";
  /** Non-blocking evasion signals the proxy recorded (absolute-path net tool, …). */
  evasion: { kind: string; evidence: string }[];
  /** Audit reason from the proxy's execGate. */
  reason: string;
  /** Optional session tag (observability; lookup is signature-keyed). */
  sessionKey?: string;
  /** The tool_use id the proxy attributed this command to. The exec supervisor
   * reads it off its signature-keyed lookup to key the clean-verdict report
   * (exec-routing.md §8.5) — the callId leg of the proxy↔OS correlation.
   * Utility-only: a same-signature rerun overwrites with the freshest callId,
   * and a mis-attribution can never upgrade anything (the verdict is
   * hash-bound to the invocation's actual output bytes). */
  callId?: string;
  /** Insertion epoch (monotonic counter — NOT wall-clock; ordering only). */
  seq: number;
}

export class ExecDecisionStore {
  private readonly bySignature = new Map<string, RecordedExecDecision>();
  private seq = 0;
  private readonly capacity: number;

  constructor(opts: { capacity?: number } = {}) {
    this.capacity = Math.max(1, opts.capacity ?? 1024);
  }

  /** Record (or overwrite) the proxy's decision for `signature`. Empty signatures
   * are ignored (nothing to correlate on). Evicts the oldest entry on overflow. */
  record(
    signature: string,
    decision: Omit<RecordedExecDecision, "seq">,
  ): void {
    if (!signature) return;
    // Re-insert to move it to the end of insertion order (freshest).
    this.bySignature.delete(signature);
    this.bySignature.set(signature, { ...decision, seq: ++this.seq });
    while (this.bySignature.size > this.capacity) {
      const oldest = this.bySignature.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.bySignature.delete(oldest);
    }
  }

  /** The proxy's recorded decision for `signature`, or undefined on a miss. */
  lookup(signature: string): RecordedExecDecision | undefined {
    if (!signature) return undefined;
    return this.bySignature.get(signature);
  }

  /** Entry count (tests / observability). */
  size(): number {
    return this.bySignature.size;
  }
}
