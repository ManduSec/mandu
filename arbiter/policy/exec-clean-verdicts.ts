/**
 * exec-clean-verdicts — the per-invocation CLEAN-verdict store for the
 * exec-output trust upgrade, rung 2 (docs/design/integrity/exec-routing.md §8.4–§5).
 * Mandu-new, no reference origin. Sibling of exec-decision-store.ts (the
 * proxy→supervisor correlation memory); this store carries the OPPOSITE
 * direction — the exec supervisor's runtime verdict flowing back to
 * classification time.
 *
 * SEMANTICS (§5, enforced here so every caller inherits them):
 *   - A verdict qualifies as CLEAN only when EVERY gate passes; any absent or
 *     failing input resolves the verdict UNCLEAN with the failing gate named
 *     in `reason` (fail-closed — the blanket UNTRUSTED rule then simply
 *     stands at classify time; a miss is a utility miss, never a leak).
 *   - Gates: the supervisor's own `clean` claim; `boxed` (the invocation ran
 *     inside the exec box — only boxed AgentShell invocations qualify, §5);
 *     `shell === "AgentShell"`; a `procKey` the ARBITER ITSELF re-checks
 *     against the taint registry (`isProcessTainted` — a supervisor cannot
 *     vouch for its parent's lineage, §5); and a 64-hex `outputSha256`.
 *   - `outputSha256` is LOAD-BEARING, not metadata: the verdict vouches for an
 *     INVOCATION, but the classify-time value arrives via the agent harness's
 *     tool_result, which the threat model treats as attacker-reachable. The
 *     hash binds the revealed bytes to the invocation the box actually ran —
 *     without it, a forged tool_result on a clean callId would ride raw.
 *   - WHO REPORTS (2026-09-28, sandbox-security-review finding 4): a claim is
 *     only as good as its reporter. Today's reporter, `mandu-exec-box`, is
 *     started by the agent's own shim, so it runs inside the agent's process
 *     tree with the agent's uid: code there can preload into it, trace it, or
 *     skip it and write the report to the data socket itself. Such a report
 *     (`via: "data-socket"`) resolves UNCLEAN before any other gate. Only a
 *     reporter outside the agent tree, authenticated by the arbiter
 *     (`via: "authenticated-supervisor"`: the session's guard, which runs the
 *     clean attempt itself and holds a token only it could claim,
 *     clean-reporters.ts, exec-routing.md §8.5.3), can yield CLEAN. Such a
 *     verdict names the session the token was issued for, whatever the report
 *     says, and classify honors it only for that session.
 *   - MONOTONIC DOWNWARD: once a callId resolves UNCLEAN, no later report can
 *     flip it clean (a re-report can still downgrade clean → unclean). This
 *     makes duplicate/racing reports safe without trusting report order.
 *
 * NON-PERSISTENT + BOUNDED, like its sibling: a verdict is a within-run fact
 * consumed by the very next tool_result classify; the insertion-ordered map is
 * capped and evicts oldest-first. Single-threaded (Node event loop).
 */

/** What the exec supervisor reports for one finished invocation. */
export interface ExecCleanVerdictReport {
  /** The originating tool_use id (the proxy↔OS correlation key, §2). */
  callId: string;
  /** The supervisor's own claim: influence set clean (files ⊆ trusted ∧ net = ∅). */
  clean: boolean;
  /** The invocation ran inside the exec box (Landlock clean view). */
  boxed?: boolean;
  /** Which shell world ran it — only "AgentShell" qualifies. */
  shell?: string;
  /** The invocation's proc key, for the arbiter's OWN taint re-check. */
  procKey?: string;
  /** sha256 (hex) of the exact bytes returned to the harness as this
   *  invocation's tool_result body. */
  outputSha256?: string;
  /** Supervisor audit note (which ruleset, how many paths, …). */
  reason?: string;
  /** Optional session tag (observability). */
  sessionKey?: string;
}

/** How a report reached the arbiter. `data-socket`: any client, the agent
 *  tree included, so the claim is not honored. `authenticated-supervisor`: the
 *  session's guard, authenticated by its reporter token (clean-reporters.ts,
 *  exec-routing.md §8.5.3); the session is the token's. */
export type ReportChannel = "data-socket" | { via: "authenticated-supervisor"; sessionKey: string };

/** The RESOLVED verdict this store records and classification consumes. */
export interface ExecCleanVerdict {
  callId: string;
  /** True only when every §5 gate passed at report time. */
  clean: boolean;
  /** Why clean, or the FIRST failing gate. */
  reason: string;
  /** Present iff clean (consumers hash-match the classified span against it). */
  outputSha256?: string;
  procKey?: string;
  sessionKey?: string;
  /** Insertion epoch (monotonic counter — ordering only). */
  seq: number;
}

const SHA256_HEX = /^[0-9a-f]{64}$/;

export class ExecCleanVerdictStore {
  private readonly byCallId = new Map<string, ExecCleanVerdict>();
  private seq = 0;
  private readonly capacity: number;
  private readonly isProcessTainted?: (procKey: string) => boolean;

  constructor(opts: {
    capacity?: number;
    /** The arbiter's taint oracle (provenance store). ABSENT ⇒ every verdict
     *  resolves UNCLEAN — a store that cannot check lineage must not upgrade. */
    isProcessTainted?: (procKey: string) => boolean;
  } = {}) {
    this.capacity = Math.max(1, opts.capacity ?? 1024);
    this.isProcessTainted = opts.isProcessTainted;
  }

  /** Resolve `report` through the §5 gates and record it. Returns the resolved
   *  verdict (also what a duplicate report resolved to, post-monotonicity).
   *  An empty callId records nothing and resolves UNCLEAN. */
  report(report: ExecCleanVerdictReport, via: ReportChannel): ExecCleanVerdict {
    // An authenticated verdict speaks for the token's session, never for the
    // one the report names.
    const r = via === "data-socket" ? report : { ...report, sessionKey: via.sessionKey };
    const resolved = this.resolve(r, via);
    if (!report.callId) return resolved;
    const prior = this.byCallId.get(report.callId);
    // Monotonic downward: an existing UNCLEAN verdict is never overwritten by
    // a clean one; anything else (fresh, clean→clean, clean→unclean) records.
    if (prior && !prior.clean && resolved.clean) return prior;
    this.byCallId.delete(report.callId); // re-insert freshest for eviction order
    this.byCallId.set(report.callId, resolved);
    while (this.byCallId.size > this.capacity) {
      const oldest = this.byCallId.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.byCallId.delete(oldest);
    }
    return resolved;
  }

  /** The resolved verdict for `callId`, or undefined on a miss. */
  lookup(callId: string): ExecCleanVerdict | undefined {
    if (!callId) return undefined;
    return this.byCallId.get(callId);
  }

  /** Entry count (tests / observability). */
  size(): number {
    return this.byCallId.size;
  }

  /** The §5 gate chain — first failure names itself and resolves UNCLEAN. */
  private resolve(r: ExecCleanVerdictReport, via: ReportChannel): ExecCleanVerdict {
    const base = {
      callId: r.callId,
      ...(r.procKey ? { procKey: r.procKey } : {}),
      ...(r.sessionKey ? { sessionKey: r.sessionKey } : {}),
      seq: ++this.seq,
    };
    const unclean = (reason: string): ExecCleanVerdict => ({ ...base, clean: false, reason });
    if (!r.callId) return unclean("no callId — nothing to correlate on");
    if (via === "data-socket") {
      return unclean(
        "reported over the data socket: the reporter runs inside the agent's process tree and " +
          "cannot be authenticated, so its claim is not honored (exec-routing.md §8.5.3)",
      );
    }
    if (r.clean !== true) return unclean(`supervisor reported unclean${r.reason ? `: ${r.reason}` : ""}`);
    if (r.boxed !== true) return unclean("invocation did not run inside the exec box (§5: boxed only)");
    if (r.shell !== "AgentShell") {
      return unclean(`shell ${JSON.stringify(r.shell ?? null)} — only AgentShell qualifies (§5)`);
    }
    if (!r.procKey) return unclean("no procKey — the arbiter cannot re-check lineage taint (§5)");
    if (!this.isProcessTainted) return unclean("no taint oracle wired — cannot verify lineage (§5)");
    if (this.isProcessTainted(r.procKey)) {
      return unclean(`process ${r.procKey} is lineage-tainted — a tainted parent poisons the invocation (§5)`);
    }
    if (!r.outputSha256 || !SHA256_HEX.test(r.outputSha256)) {
      return unclean("no output sha256 — the verdict cannot be bound to the tool_result bytes");
    }
    return {
      ...base,
      clean: true,
      outputSha256: r.outputSha256,
      reason: r.reason
        ? `clean (boxed AgentShell, lineage untainted): ${r.reason}`
        : "clean (boxed AgentShell, lineage untainted)",
    };
  }
}
