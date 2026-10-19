/**
 * assertions-core — the shared primitive of the e2e assertion library: the
 * CheckSpec shape, decide()/skip() (fold a boolean into a typed
 * AssertionCheck), and the two symbol-token regexes. Every evaluator module
 * (assertions-security / -utility / -lineage / -report) builds on this; the
 * public surface is re-exported by assertions.ts, which also carries the
 * library's provenance header.
 */
import type {
  AssertionCheck,
  AssertionCategory,
  AssertionStatus,
  SecurityAspect,
  SeededFile,
  FinalFile,
  FinalWorkspaceView,
} from "../../dashboard/src/event-model.js";

export type {
  AssertionCheck, AssertionCategory, AssertionStatus, SecurityAspect,
  SeededFile, FinalFile, FinalWorkspaceView,
};

/** The token every T-LLM-facing symbol carries (arbiter symbol prefix). */
export const SYM = /\$MDU:/;
/** The short re-symbolization tag the U-LLM (inspect_symbol) result rides under. */
export const INSPECT_SYM = /\$MDU:inspect\[/;

// ── The primitive: fold a boolean into a typed check ──────────────────────────

export interface CheckSpec {
  label: string;
  description?: string;
  category: AssertionCategory;
  /** REQUIRED on every security spec (event-model.ts SecurityAspect): which
   *  property the check proves, by what the attacker would gain on failure —
   *  `integrity` (steer the agent) or `confidentiality` (learn secret data). */
  aspect?: SecurityAspect;
  /** The assertion primitive name (mirrors the reference's `assert:` field). */
  assert: string;
  tool?: string;
}

/**
 * Build one check from a boolean outcome. A failure is BLOCKING (`fail`) unless
 * `soft` — a soft failure degrades to a non-blocking `warn` (the reference's
 * `active: "wip"` mechanism; used for inherently model-dependent checks like a
 * live model's stdout wording). `passReason`/`failReason` are the evidence.
 */
export function decide(
  spec: CheckSpec,
  ok: boolean,
  passReason: string,
  failReason: string,
  soft = false,
): AssertionCheck {
  const status: AssertionStatus = ok ? "pass" : soft ? "warn" : "fail";
  return {
    label: spec.label,
    ...(spec.description ? { description: spec.description } : {}),
    category: spec.category,
    ...(spec.aspect ? { aspect: spec.aspect } : {}),
    status,
    reason: ok ? passReason : failReason,
    ...(spec.tool ? { tool: spec.tool } : {}),
    assert: spec.assert,
  };
}

/** A check that does not apply to this scenario — recorded (not silently
 *  dropped) so the panel can show it as ⊘ skipped rather than pretend it ran. */
export function skip(spec: CheckSpec, reason: string): AssertionCheck {
  return {
    label: spec.label,
    ...(spec.description ? { description: spec.description } : {}),
    category: spec.category,
    ...(spec.aspect ? { aspect: spec.aspect } : {}),
    status: "skip",
    reason,
    ...(spec.tool ? { tool: spec.tool } : {}),
    assert: spec.assert,
  };
}
