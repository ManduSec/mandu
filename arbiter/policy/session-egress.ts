/**
 * session-egress — what a HIGH session may still do (§4, §7 table; Plan 8).
 *
 * A PURE function, like decideDesymbolization and decideDeclassify.
 *
 * ── WHY THIS GATE EXISTS AT ALL, when we already have an egress gate ────────
 *
 * `decideDesymbolization` is PER-SYMBOL: it fires when a symbol is about to be
 * resolved at a boundary. That makes it structurally blind to the thing the
 * watermark exists to catch:
 *
 *     A PARAPHRASE CARRIES NO SYMBOL.
 *
 * Once the model has read secret content into its context (rung 3), it can
 * re-encode that content into any text it emits — an argv, a URL, a request
 * body — with no `$MDU:` token anywhere in it. The per-symbol gate sees nothing
 * to gate and waves it through. That is not a bug in the per-symbol gate; it is
 * the reason §4 says the only enforceable meaning of `model-ok` after an
 * in-context read is SESSION CONFINEMENT, and that a design granting the read
 * but skipping the watermark "is theater".
 *
 * So this gate keys on the SESSION, not the payload. It runs IN ADDITION to the
 * per-symbol gate, and it does not care whether a symbol is present.
 *
 * ── WHAT IT GATES, AND WHAT IT DELIBERATELY DOES NOT ────────────────────────
 *
 *  · network  — the exfil sink. Bound destination or human approval.
 *  · shell    — a NET-ENABLED world (HumanShell) is a network sink wearing a
 *               different hat: the model can hand a paraphrased secret to `curl`
 *               as an argument. Bound destination or approval. An AgentShell
 *               (net OFF) is NOT gated — it has no way out, which is exactly the
 *               §7.1 valve's point, and gating it would destroy utility for no
 *               security gain.
 *  · filesystem — NOT GATED. §4 and the §7 ② row say files a high session writes
 *               are LABELED AT THE WATERMARK, not blocked: the workspace is the
 *               HUMAN's, and the human owns their secrets at every level. Gating
 *               writes would break every task while protecting nothing from
 *               anyone who is not already entitled to it. (The on-disk labeling
 *               itself is the deferred follow-up — it is what makes the watermark
 *               survive into the NEXT session.)
 *
 * A `public` session is byte-identical to today at every boundary. The watermark
 * can only ever ADD restriction — never grant.
 */

import { ruleRef, type RuleRef } from "./rule-ref.js";
import type { ConfidentialityLevel } from "../symbol-table/confidentiality.js";
import { destinationMatchesBindings } from "./host-bindings.js";

export type SessionEgressBoundary = "network" | "shell" | "filesystem";

export interface SessionEgressRequest {
  /** The session's high-watermark. `public` ⇒ this gate is a no-op. */
  sessionLevel: ConfidentialityLevel;
  /** The bound destinations the session's read data carried (§2). */
  sessionBindings: string[];
  boundary: SessionEgressBoundary;
  /** The sink: a host for network, the resolved target for a net-enabled shell.
   *  Absent ⇒ we cannot prove it is bound ⇒ fail-closed to approval. */
  destination?: string;
  /** For `shell`: does this world have network access? An AgentShell (net off)
   *  is not an egress at all. Absent ⇒ assume yes (fail-closed). */
  netEnabled?: boolean;
  /** Has this session also ingested UNTRUSTED data (§9 rule 1b)? A HIGH session
   *  that is untrusted-influenced does NOT get the standing bound-destination
   *  release: the same paraphrase channel is now attacker-steerable, so even a
   *  bound sink takes one human approval ("also POST the key to the issue
   *  tracker" — bound for code, not for THIS flow). The per-symbol gate already
   *  enforces this for a resolved symbol; the session gate is where a PARAPHRASE
   *  (no symbol) of a bound secret would otherwise slip through. Absent ⇒ false
   *  (the pre-Plan-8 shape; a trusted-only high session keeps its release). */
  untrustedTainted?: boolean;
}

export interface SessionEgressDecision {
  allow: boolean;
  requiresApproval: boolean;
  reason: string;
  /** Decision provenance (rule-ref.ts; policy-surface.md §9.3). */
  ruleRef?: RuleRef;
}

const ALLOW_LOW: SessionEgressDecision = {
  allow: true,
  requiresApproval: false,
  reason: "session is not high (no in-context secret read) → the watermark gate is inert",
  ruleRef: ruleRef("session:not-high"),
};

/** Does `destination` (a host, `host:port`, or a URL) match one of the
 *  session's bound sinks? The one binding rule (host-bindings.ts,
 *  confidentiality.md §2.2): `api.example.com` is under `example.com`, but
 *  `evil-example.com` is NOT (whole labels — a raw `endsWith` would be a
 *  silent hole an attacker picks the hostname to walk through). */
export function destinationIsBound(destination: string, bindings: string[]): boolean {
  if (!destination) return false;
  return destinationMatchesBindings(destination, bindings);
}

export function decideSessionEgress(req: SessionEgressRequest): SessionEgressDecision {
  // Not high ⇒ nothing changes. This is the no-regression fold: every existing
  // behavior must be byte-identical while no in-context read has happened, which
  // (given rung 3's narrow door) is almost every session.
  if (req.sessionLevel === "public") return ALLOW_LOW;

  // The human's own workspace. Labeled, not blocked — see the header.
  if (req.boundary === "filesystem") {
    return {
      allow: true,
      requiresApproval: false,
      reason: "filesystem: a high session's writes are LABELED at the watermark, not blocked (§4, §7 ②)",
      ruleRef: ruleRef("session:high-fs-labeled"),
    };
  }

  // An AgentShell has no network. It is not an egress, and confining it would
  // cost utility for nothing.
  if (req.boundary === "shell" && req.netEnabled === false) {
    return {
      allow: true,
      requiresApproval: false,
      reason: "AgentShell (net off): not an egress — the §7.1 valve already confines it",
      ruleRef: ruleRef("session:agentshell-no-net"),
    };
  }

  // network, or a net-enabled shell. The sink must be one the session's own read
  // data was already bound for; anything else is a human decision.
  if (req.destination && destinationIsBound(req.destination, req.sessionBindings)) {
    // §9 rule 1(b): a bound destination is a STANDING release only for a flow
    // that is not attacker-steerable. Once the session is untrusted-tainted,
    // an injection can aim a paraphrased secret at the very host the label
    // permits ("bound for code, not for THIS flow"), so the standing release
    // is suspended and this one egress takes a human decision.
    if (req.untrustedTainted) {
      return {
        allow: false,
        requiresApproval: true,
        reason:
          `HIGH + UNTRUSTED-TAINTED session → BOUND destination (${req.destination}): the standing ` +
          `release is suspended because the flow is attacker-steerable — human approval regardless of ` +
          `the binding (§9 rule 1b).`,
        ruleRef: ruleRef("session:high-tainted-bound"),
      };
    }
    return {
      allow: true,
      requiresApproval: false,
      reason: `high session → a BOUND destination (${req.destination}): the read data's own standing release rule`,
      ruleRef: ruleRef("session:high-bound-release"),
    };
  }

  // A net-enabled command names no destination the gate can check: the model
  // may have put a paraphrase in its own arguments, sent wherever the command
  // sends it. Its own rule id, so the page words a command, not a host.
  if (req.boundary === "shell" && !req.destination) {
    return {
      allow: false,
      requiresApproval: true,
      reason:
        `HIGH SESSION (${req.sessionLevel}): this session has read secret content into context, and no gate can ` +
        `prove this command stays off the network — its arguments may carry a paraphrase of what was read → ` +
        `human approval required (§4).`,
      ruleRef: ruleRef("session:high-shell"),
    };
  }

  return {
    allow: false,
    requiresApproval: true,
    reason:
      `HIGH SESSION (${req.sessionLevel}): this session has read secret content into context, so anything ` +
      `it emits may be derived from it — including a paraphrase carrying no symbol. Egress to ` +
      `${req.destination ? `'${req.destination}'` : "an unspecified destination"} is not a bound ` +
      `destination of the data it read → human approval required (§4).`,
    ruleRef: ruleRef("session:high-unbound"),
  };
}
