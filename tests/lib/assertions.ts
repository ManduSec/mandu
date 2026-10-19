/**
 * assertions — the SECURITY / UTILITY assertion library for the Mandu e2e
 * suites (claude-e2e live + replay-e2e). (The third assertion category,
 * `fidelity` — the dashboard renders what the client itself recorded — has its
 * evaluators in tests/lib/claude-history.ts; this file's line format,
 * parser, and event builder carry all three categories.)
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Ported from the reference DualView e2e harness
 *     DualView (adfi-openclaw) tests/lib/assertions.ts
 *     DualView (adfi-openclaw) test/lib/security-oracle.ts
 *   The reference splits checks into `correctness` (the DualView information-flow
 *   invariants — BLOCKING) and `utility` (the benign task still completed —
 *   advisory), records each as `AssertionResult = [label, passed, reason, active?]`,
 *   and emits one greppable log line per check
 *     `PASS: <label> -- <reason> [category=correctness tool=… assert=… …]`
 *   which its dashboard parses back into a typed result and renders as a
 *   correctness/utility panel.
 *
 *   ADAPTED for Mandu:
 *     - The blocking category is renamed `security` (the one invariant this repo
 *       serves — untrusted data reaches T-LLM only symbolized, raw never leaks,
 *       trusted rides verbatim), keeping `utility` as-is. Every security check
 *       additionally carries an `aspect` (2026-07-16): `integrity` (untrusted
 *       data cannot steer the agent) or `confidentiality` (secret data cannot
 *       leak) — the panel splits the Security group on it (event-model.ts
 *       SecurityAspect has the classification rule).
 *     - The reference evaluates against its plugin's audit rows; Mandu has no
 *       such log — the evidence is the MODEL-FACING trace (tllm_call
 *       input/output.symbolized read back from the arbiter event store) plus the
 *       exit code / stdout / dual-view on-disk state. So each evaluator here takes
 *       already-extracted evidence and is PURE + unit-testable; the messy IO
 *       (git/fs reads) stays in the runner.
 *     - Results are carried BOTH as a greppable stdout line (`MDUASSERT …`, for
 *       the dashboard TestRunner + CI logs) AND as one `assertion` ManduEvent
 *       per session (the dashboard's per-session panel data source). The arbiter
 *       persists the event opaquely (event-store.ts), so no arbiter change.
 *
 * The `AssertionCheck` type is the SHARED one from the dashboard event model, so
 * the emitted event and the dashboard projector agree by construction.
 */
// Split into cohesive modules (2026-09-11 overnight cleanup); this barrel keeps
// the public surface identical — import from here, not from the parts.
export type {
  AssertionCheck, AssertionCategory, AssertionStatus, SecurityAspect,
  SeededFile, FinalFile, FinalWorkspaceView,
} from "./assertions-core.js";
export * from "./assertions-security.js";
export * from "./assertions-utility.js";
export * from "./assertions-lineage.js";
export * from "./assertions-report.js";
