/**
 * declassify — the IN-CONTEXT READ decision (§3.3 rung 3, §9 rule 2; Plan 8).
 *
 * A PURE function (request → decision), unit-tested as an oracle. The stateful
 * half (raising the watermark, queueing the approval) lives in the arbiter
 * server, exactly as decideDesymbolization/EgressApprovalStore are split.
 *
 * Rung 3 is what happens when a task genuinely needs `model-ok` content in the
 * MAIN conversation — the model must branch on it, weave it through multi-step
 * work — rather than merely process it in the quarantine (rung 2). It
 * desymbolizes the content into T-LLM's context and HIGH-WATERMARKS the session.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WE DIVERGE FROM §9 RULE 2 AS WRITTEN, AND DELIBERATELY. Read this.
 *
 * §9 rule 2 says the `model-ok` clearance is suspended for in-context reads when
 * "the datum's integrity is untrusted OR the session is untrusted-tainted — that
 * combination escalates to HUMAN APPROVAL at the moment of the read."
 *
 * Those two conditions look alike and are not. They are questions in DIFFERENT
 * lattices, and rung 3 answers them differently:
 *
 *  ── The datum is UNTRUSTED → REFUSED. No approval path. ──
 *
 *  Rung 3 puts RAW CONTENT into the privileged model's context. If that content
 *  is integrity-untrusted, this is precisely — not analogously, precisely — the
 *  thing the entire system exists to prevent:
 *
 *      "Untrusted data reaches the privileged model ONLY as an opaque symbol.
 *       Any change that COULD let un-symbolized untrusted data into the model
 *       context is a security regression."   — CONTRIBUTING.md, the one invariant
 *
 *  An approval dialog does not fix that; it only moves the regression behind a
 *  click. And it is a click no human can evaluate: approving "read this
 *  contract" is not approving "be injected by whatever is hidden on page 40",
 *  yet that is what it would authorize. The human cannot audit a document for
 *  injections — that is why the defense exists.
 *
 *  We refuse instead. This costs real utility (see below) and it is the right
 *  trade, because §9 rule 3 ALREADY GIVES the danger cell its answer:
 *  "Quarantined reads remain allowed in the danger cell... the quarantine is the
 *  designated mechanism for PROCESSING doubly-labeled data." Rung 2 is the path.
 *  The refusal message says so, and the handling prompt teaches it.
 *
 *  ── The SESSION is untrusted-tainted → APPROVAL. (Rule 2, as written.) ──
 *
 *  Different question entirely. Here the DATUM is trusted — putting it in
 *  context injects nothing. The risk is that the model has ALREADY ingested
 *  untrusted symbols, so an injected model would be holding the secret and could
 *  paraphrase it onward. That is a CONFIDENTIALITY exposure, and a human CAN
 *  meaningfully authorize it ("this session has touched untrusted data; still
 *  show the model the contract?"). Approval is the right answer, and the
 *  watermark then confines every subsequent egress.
 *
 *  THE COST, stated plainly: under the real Claude Code inbound policy a `Read`
 *  tool_result is UNTRUSTED-by-integrity. So for a contract that arrived through
 *  `Read`, rung 3 is simply UNAVAILABLE and the agent must use `inspect_symbol`.
 *  Rung 3 is reachable for TRUSTED×model-ok data — registry-registered secrets
 *  (registerSecret mints integrity: "trusted"), and any tool whose inbound policy
 *  marks its results trusted. That is a narrow door, and narrow is correct: §10
 *  says rung 3 is the WEAKEST guarantee in the design (confinement, not opacity)
 *  and rungs 1–2 are to be preferred. A door this narrow is the design working.
 *
 *  If a deployment ever genuinely needs an approved in-context read of untrusted
 *  content, that is a deliberate, separately-argued erosion of the one invariant
 *  — not a side effect of shipping the watermark. It does not happen here.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import {
  admits,
  type ConfidentialityLevel,
  type IntegrityLabel,
  type ModelLocation,
} from "../symbol-table/confidentiality.js";

export interface DeclassifyRequest {
  /** The symbol's stored confidentiality level. */
  level: ConfidentialityLevel;
  /** The symbol's stored integrity label. */
  integrity: IntegrityLabel;
  /** Has this session already ingested untrusted data? (§9 rule 2.) */
  sessionUntrustedTainted: boolean;
  /** Where the session's T-LLM runs (plan 11 D3/D4, phase 3): `local` only
   *  when the launcher bound the session to a `models:` entry the law in
   *  force declares `local: true` (policy/session-upstreams.ts); absent means
   *  external. */
  tllmLocation?: ModelLocation;
}

export interface DeclassifyDecision {
  /** May the raw content enter T-LLM's context now? */
  allow: boolean;
  /** Is a human decision the thing standing in the way? (false on a hard
   *  refusal — there is no approval that opens it.) */
  requiresApproval: boolean;
  /** The level to raise the session watermark to, when allowed. `null` ⇒ no
   *  watermark (a public datum floats nothing). */
  watermark: ConfidentialityLevel | null;
  reason: string;
}

export function decideDeclassify(req: DeclassifyRequest): DeclassifyDecision {
  // A public datum is not a declassification at all — there is nothing to
  // protect and nothing to float. (The model normally holds public symbols for
  // integrity reasons; resolving one into context is the integrity gate's
  // business, not ours, and it is NOT what this op is for.)
  if (req.level === "public") {
    return {
      allow: false,
      requiresApproval: false,
      watermark: null,
      reason:
        "not a secret symbol — declassify_symbol is for confidential data; " +
        "use inspect_symbol to process an ordinary symbol's content",
    };
  }

  // THE ONE INVARIANT. Raw untrusted content must never enter T-LLM's context,
  // and no human click may authorize it. See the header.
  if (req.integrity === "untrusted") {
    return {
      allow: false,
      requiresApproval: false,
      watermark: null,
      reason:
        "REFUSED: this datum is untrusted-integrity, and reading it into context " +
        "would put un-symbolized untrusted data in front of the privileged model. " +
        "No approval opens this. Use inspect_symbol — the quarantine is the " +
        "designated way to process untrusted confidential data (§9 rule 3).",
    };
  }

  // no-model: no model reads it. Not with approval, not ever — that
  // refusal IS the data-residency claim (§3.2). The way to make a strict datum
  // model-readable is to RELABEL it `model-ok`: an explicit, visible change to
  // the standing surface, not a click-through.
  if (req.level === "no-model") {
    return {
      allow: false,
      requiresApproval: false,
      watermark: null,
      reason:
        "REFUSED: no-model data is readable by NO model. If the model must " +
        "read it, relabel the file any-model — that is a deliberate change " +
        "to the standing release surface, not an approval.",
    };
  }

  // local-model: only the user's own model may read it (plan 11 D3). Rung 3
  // puts the bytes in front of the T-LLM, so it opens only when the T-LLM
  // itself is a declared local endpoint; under an external one it is refused
  // exactly as no-model is, with no approval path. The quarantined helper
  // (inspect_symbol) is how such a datum gets processed.
  const location: ModelLocation = req.tllmLocation ?? "external";
  if (!admits(location, req.level)) {
    return {
      allow: false,
      requiresApproval: false,
      watermark: null,
      reason:
        "REFUSED: local-model data is readable only by the user's own model, and " +
        "the model reading this context is not one. No approval opens this. Use " +
        "inspect_symbol, which sends it to the declared local model.",
    };
  }

  // ── any-model (or local-model under a local T-LLM) × trusted ───────
  // The model is a cleared reader for this datum. The only remaining
  // question is §9 rule 2's session half. The watermark is the datum's own
  // level, so a local-model read floats the session to local-model.
  if (req.sessionUntrustedTainted) {
    return {
      allow: false,
      requiresApproval: true,
      watermark: req.level,
      reason:
        "this session has already ingested untrusted data, so an injected model " +
        "would be holding the secret — §9 rule 2 suspends the standing clearance " +
        "and asks the human",
    };
  }

  return {
    allow: true,
    requiresApproval: false,
    watermark: req.level,
    reason: `${req.level} in a clean session: allowed as a logged declassification; the session is now HIGH`,
  };
}
