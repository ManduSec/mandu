/**
 * session-posture — the SIEM-triggered lockdown posture (docs/design/
 * siem-integration.md §4.3, scenario D: Mandu as policy ACTUATOR).
 *
 * A SIEM active-response callback (a `setSessionPosture` IPC op) can TIGHTEN the
 * arbiter's egress posture — e.g. after a cross-session IPI campaign fires (rule
 * 100220), lock down so that EVERY network egress requires human approval. The
 * enforcement lives in the arbiter (`decideDesymWithApprovals`); this store is
 * just the small piece of server state it consults. Two invariants:
 *
 *   1. TIGHTEN-ONLY BY DEFAULT. A plain request (`requestGlobal`) may only RAISE
 *      the posture (normal → lockdown), never lower it. A SIEM rule must never
 *      be able to relax policy — relaxation is a human act, via the existing
 *      per-egress approval flow (a human approves a specific egress even under
 *      lockdown) or an EXPLICIT relax: `requestGlobal(to, { allowRelax: true })`
 *      — the `setSessionPosture` op's `allowRelax` flag, sent only by the
 *      human-driven dashboard route (policy-surface.md §9.8.6) and audited
 *      exactly like a tighten — or the direct in-process `relaxGlobal`. An
 *      un-flagged loosen stays a refused no-op; that is the one-directional
 *      guarantee for every legacy/SIEM caller.
 *   2. GLOBAL scope (today). The network egress gate carries no sessionId (the
 *      `DesymbolizationRequest` has no session field), so only a GLOBAL,
 *      campaign-wide lockdown is enforceable at that chokepoint — which is also
 *      exactly what a cross-session campaign response wants. Per-session lockdown
 *      is deliberately NOT stored here (a posture nothing reads is the bug class
 *      confidentiality.md §12 exists to catch); it awaits a sessionId at the
 *      egress gate. See scenario D notes in siem-integration.md §4.3.
 */
export type Posture = "normal" | "lockdown";

const RANK: Record<Posture, number> = { normal: 0, lockdown: 1 };

export interface PostureChange {
  from: Posture;
  to: Posture;
  /** false when the guard refused (an un-flagged loosen or a same-level no-op). */
  applied: boolean;
  reason: string;
}

export class SessionPostureStore {
  private global: Posture = "normal";
  private readonly history: PostureChange[] = [];

  /**
   * Posture request — TIGHTEN-ONLY unless `allowRelax` is set. Applies `to` if
   * it is STRICTLY tighter than the current global posture; a same-level request
   * is refused (`applied: false`) in both directions. A loosen is refused too,
   * UNLESS `opts.allowRelax` is true — the explicit human-driven flag
   * (policy-surface.md §9.8.6) — in which case it applies. The bare call is
   * exactly the legacy SIEM callback path.
   */
  requestGlobal(to: Posture, opts?: { allowRelax?: boolean }): PostureChange {
    const from = this.global;
    let change: PostureChange;
    if (RANK[to] < RANK[from] && opts?.allowRelax) {
      this.global = to;
      change = { from, to, applied: true, reason: `relaxed ${from}→${to} (explicit allowRelax)` };
    } else if (RANK[to] < RANK[from]) {
      change = { from, to: from, applied: false, reason: `tighten-only: refusing to loosen ${from}→${to}` };
    } else if (RANK[to] === RANK[from]) {
      change = { from, to: from, applied: false, reason: `already ${from}` };
    } else {
      this.global = to;
      change = { from, to, applied: true, reason: `tightened ${from}→${to}` };
    }
    this.history.push(change);
    return change;
  }

  /**
   * Direct human/admin RELAX — always applies, no guard. Kept for in-process
   * de-escalation and for tests. Over IPC a relax IS reachable since
   * policy-surface.md §9.8.6, but only through the guarded
   * `requestGlobal(to, { allowRelax: true })` (the op's explicit flag) — a plain
   * `setSessionPosture` call remains tighten-only and never lands here.
   */
  relaxGlobal(to: Posture = "normal"): PostureChange {
    const change: PostureChange = { from: this.global, to, applied: true, reason: `human relax ${this.global}→${to}` };
    this.global = to;
    this.history.push(change);
    return change;
  }

  /** Is the arbiter globally locked down? Consulted by the egress gate. */
  isLockedDown(): boolean {
    return this.global === "lockdown";
  }

  globalPosture(): Posture {
    return this.global;
  }

  /** The most recent change (applied or refused), or null if never touched. */
  lastChange(): PostureChange | null {
    return this.history.length ? this.history[this.history.length - 1]! : null;
  }

  /** Count of APPLIED changes — a cheap health/observability signal. */
  appliedCount(): number {
    return this.history.reduce((n, c) => n + (c.applied ? 1 : 0), 0);
  }
}

/** Parse an untrusted posture string from the wire; null if not a known posture. */
export function parsePosture(v: unknown): Posture | null {
  return v === "normal" || v === "lockdown" ? v : null;
}
