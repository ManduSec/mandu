/**
 * integrity-flag — the ONE switch for the whole integrity axis (the classic
 * Mandu IPI defense: inbound data-TRUST classification and the untrusted-
 * symbol machinery it feeds).
 *
 * ON is the paper's defense (modes `injection` and `full`). OFF (modes `secrets`
 * and `off`; `secrets` is the built-in default since 2026-09-21,
 * docs/design/architecture/protection-modes.md) neutralizes trust classification at
 * its single source — classify() returns TRUSTED for every field — so no
 * untrusted symbol is ever minted and every downstream integrity gate
 * (untrusted-egress approval, AgentShell exec routing, taint decisions)
 * collapses with it, with no per-gate edits. Confidentiality (the second
 * lattice, confidentiality-flag.ts) is independent and keeps running: a
 * TRUSTED-but-secret datum still symbolizes, the watermark and secret-egress
 * gates still fire. Read ONCE at arbiter start and threaded as an explicit
 * option (ArbiterServerOptions.integrity, createEngineBackedPolicy) — decision
 * code never reads ambient env.
 *
 * Resolution: MANDU_INTEGRITY when it says anything (only an explicit
 * "0"/"false"/"off" turns the axis OFF; any other non-empty value fails toward
 * protection, ON), else MANDU_MODE's value for this axis, else the built-in
 * default mode (protection-mode.ts, the single source of truth). The security
 * invariant of CONTRIBUTING.md is unchanged by the default: it constrains what
 * happens when this axis is ON.
 *
 * FROZEN (2026-09-28, docs/design/architecture/protection-modes.md §10): the axis still works,
 * but a PROCESS ENTRY POINT (the arbiter daemon, the launcher) refuses to run
 * it ON unless MANDU_EXPERIMENTAL_INTEGRITY=1 opts in. The gate is at the
 * entry points, not in resolveIntegrityEnabled(): in-process servers and the
 * policy keep resolving the axis exactly as before, so the frozen code and
 * its test lane stay intact. A refusal, never a silent fall back to
 * `secrets`: whoever asked for integrity must learn they did not get it.
 *
 * Mandu-new (no reference origin): designed in docs/design/confidentiality/confidentiality.md
 * §11 (the two-axis switch section).
 */
import { assertAxisStated } from "./axes-strict.js";
import { DEFAULT_MODE, MODE_AXES, modeFromEnv } from "./protection-mode.js";

export function resolveIntegrityEnabled(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  assertAxisStated("MANDU_INTEGRITY", env);
  const v = (env.MANDU_INTEGRITY ?? "").trim().toLowerCase();
  // The axis variable wins for this axis whenever it says anything. Only an
  // explicit "0"/"false"/"off" turns the axis OFF: any other non-empty value
  // (a typo, "yes") fails toward protection, ON.
  if (v === "0" || v === "false" || v === "off") return false;
  if (v !== "") return true;
  // Else MANDU_MODE's value for this axis, else the built-in default mode
  // (protection-mode.ts, the single source of truth for the default pair).
  return MODE_AXES[modeFromEnv(env) ?? DEFAULT_MODE].integrity;
}

/** The opt-in that lets an entry point run the frozen integrity axis ON
 *  (docs/design/architecture/protection-modes.md §10). Mirrored in launcher/src/mode.ts and
 *  dashboard/src/config-axes.ts (the parity test checks the name). */
export const INTEGRITY_OPT_IN_ENV = "MANDU_EXPERIMENTAL_INTEGRITY";

/** True only for an explicit "1"/"true"/"on"/"yes": the opt-in never
 *  defaults on, and a typo keeps the frozen axis refused. */
export function integrityOptedIn(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = (env[INTEGRITY_OPT_IN_ENV] ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "on" || v === "yes";
}

/** Refuse an integrity-ON start that did not opt in. Called by the arbiter
 *  daemon before it registers anything. */
export function assertIntegrityAllowed(
  integrity: boolean,
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (!integrity || integrityOptedIn(env)) return;
  throw new Error(
    "[mandu] the integrity axis (modes `injection` and `full`) is frozen and is not " +
      `started without ${INTEGRITY_OPT_IN_ENV}=1 (docs/design/architecture/protection-modes.md). ` +
      "Run mode `secrets` (the default), or set the opt-in to run the frozen axis as is.",
  );
}
