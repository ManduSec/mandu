/**
 * confidentiality-flag — the ONE switch for the whole confidentiality axis
 * (docs/design/confidentiality/confidentiality.md §11 "the kill switch").
 *
 * ON is the built-in default since 2026-09-21 (mode `secrets`,
 * docs/design/architecture/protection-modes.md; the rootless `gated` posture answered the
 * launch-refusal gate, rootless-confinement-ubuntu-2404.md). OFF (modes
 * `injection` and `off`) must be byte-identical to the integrity-only system:
 * no level derivation, no nomodel_/anymodel_ markers, no new wire fields, no
 * enforcement, no handling-prompt
 * sections. Read ONCE at arbiter start and threaded as an explicit option
 * (ArbiterServerOptions.confidentiality, createEngineBackedPolicy) — decision
 * code never reads ambient env. Every Plan-2+ enforcement branch guards on
 * the same server-held bit. Decision is centralized in the arbiter, so the
 * interceptors carry no flag of their own.
 *
 * Resolution: MANDU_CONFIDENTIALITY when it says anything (only an explicit
 * "0"/"false"/"off" turns the axis OFF; any other non-empty value fails toward
 * protection, ON), else MANDU_MODE's value for this axis, else the built-in
 * default mode (protection-mode.ts, the single source of truth).
 *
 * Mandu-new (no reference origin): designed in docs/design/confidentiality/confidentiality.md.
 */
import { assertAxisStated } from "./axes-strict.js";
import { DEFAULT_MODE, MODE_AXES, modeFromEnv } from "./protection-mode.js";

export function resolveConfidentialityEnabled(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  assertAxisStated("MANDU_CONFIDENTIALITY", env);
  const v = (env.MANDU_CONFIDENTIALITY ?? "").trim().toLowerCase();
  // The axis variable wins for this axis whenever it says anything. Only an
  // explicit "0"/"false"/"off" turns the axis OFF: any other non-empty value
  // (a typo, "yes") fails toward protection, ON.
  if (v === "0" || v === "false" || v === "off") return false;
  if (v !== "") return true;
  // Else MANDU_MODE's value for this axis, else the built-in default mode
  // (protection-mode.ts, the single source of truth for the default pair).
  return MODE_AXES[modeFromEnv(env) ?? DEFAULT_MODE].confidentiality;
}
