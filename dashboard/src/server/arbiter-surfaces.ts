/**
 * server/arbiter-surfaces — the narrow arbiter surfaces the production
 * adapter (arbiter-adapter.ts) builds for front-ends beyond the product page
 * (dashboard.md §4.25ac): the posture op and the human-plane `whySymbol`.
 * Types only. They describe arbiter ops, not a page, so they stay with the
 * adapter that implements them while the routes that call them live with
 * the developer view (dashboard.md §4.25ac). Each mirrors arbiter/ipc/protocol.ts
 * EXACTLY (declared here, not imported: the dashboard package typechecks
 * standalone, as approval-routes.ts).
 */

/** The arbiter's `setSessionPosture` result (`SetSessionPostureResult`). */
export interface PostureChangeResult {
  /** The CURRENT global posture after the request (applied or refused). */
  posture: "normal" | "lockdown";
  applied: boolean;
  from: "normal" | "lockdown";
  to: "normal" | "lockdown";
  reason: string;
}

/**
 * The posture surface (the arbiter-client pattern — see
 * anthropic-proxy/src/arbiter-client.ts), beside ApprovalsArbiter /
 * SecretsArbiter in attachArbiterSurfaces. server-main wires the real
 * arbiter IPC client behind this; the tests inject an in-memory fake.
 */
export interface PostureArbiter {
  /** The audited posture op. `allowRelax` is the §4.19 additive flag: without
   *  it a loosen is refused (tighten-only); with it the human relax applies. */
  setSessionPosture(args: {
    posture: "normal" | "lockdown";
    requestedBy: string;
    allowRelax?: boolean;
  }): Promise<PostureChangeResult>;
}

/** The arbiter's `whySymbol` answer (arbiter/prompt-filter/why-symbol.ts). */
export interface WhySymbolWire {
  symbol: string;
  axis: boolean;
  known: boolean;
  source: "prompt-filter" | "side-call" | "secret" | "other" | "unknown";
  level: string | null;
  tool: string | null;
  origin: string | null;
  field: string | null;
  session: string | null;
  createdAt: number | null;
  obsolete: boolean;
  findings: Array<{
    session: string; firstTs: string | null; lastTs: string | null; turn: number | null; requests: number;
    agent: string; origin: "human" | "harness" | "side-call"; filterId: string; category: string; action: string;
    segmentAction: "pass" | "rewrite" | "block"; hold?: { state: string; approvalId?: string }; let?: "once" | "session";
    enforcing: boolean; ref?: string; turnRef?: string;
  }>;
  verdicts: Array<{ approvalId: string; session: string; category: string; scope: "message" | "session"; status: "pending" | "approved" | "denied"; resolvedAt: number | null }>;
  policy: Array<{ category: string; action: string; row: string | null; setBy: "default" | "you" | "administrator"; locked: { action: string; file?: string } | null; onceOnly?: { file?: string }; exceptions: number }>;
  filters?: Array<{ id: string; kind: "built-in" | "pack" | "plugin"; description?: string }>;
  searched: number;
}

/** `whySymbol` on the HUMAN plane. Optional: an arbiter predating plan 15
 *  §13.8 → 501. */
export interface WhySymbolArbiter {
  whySymbol?(symbol: string, session?: string): Promise<WhySymbolWire>;
}
