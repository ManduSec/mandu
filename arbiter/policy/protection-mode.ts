/**
 * protection-mode — the four named modes over the two axes, and THE built-in
 * default (docs/design/architecture/protection-modes.md §1, §3.1).
 *
 *   mode        confidentiality  integrity
 *   secrets     ON               OFF
 *   injection   OFF              ON
 *   full        ON               ON
 *   off         OFF              OFF
 *
 * This file is the single source of truth for the default pair: the two flag
 * modules (integrity-flag.ts, confidentiality-flag.ts) read DEFAULT_MODE, and
 * the launcher (launcher/src/mode.ts), the dashboard
 * (dashboard/src/config-axes.ts) and the per-package test helpers
 * (test/axes.ts) MIRROR the table. tests/stack/
 * axis-defaults-parity.test.ts fails when any of them drifts.
 *
 * Per axis, the arbiter resolves: the axis variable (MANDU_INTEGRITY /
 * MANDU_CONFIDENTIALITY) if it states anything, else MANDU_MODE's value
 * for that axis, else DEFAULT_MODE's. So `MANDU_MODE=full
 * scripts/dev-arbiter.sh` works without the launcher in between, and an axis
 * variable still beats the mode for that axis only (the launcher's rule). An
 * MANDU_MODE that names no mode THROWS at arbiter start: a typo must never
 * quietly become the default.
 *
 * Mandu-new (no reference origin).
 */
export const PROTECTION_MODES = ["secrets", "injection", "full", "off"] as const;
export type ProtectionMode = (typeof PROTECTION_MODES)[number];

export interface ProtectionAxes {
  integrity: boolean;
  confidentiality: boolean;
}

export const MODE_AXES: Record<ProtectionMode, ProtectionAxes> = {
  secrets: { integrity: false, confidentiality: true },
  injection: { integrity: true, confidentiality: false },
  full: { integrity: true, confidentiality: true },
  off: { integrity: false, confidentiality: false },
};

/** What a cold arbiter runs when nothing states the axes. */
export const DEFAULT_MODE: ProtectionMode = "secrets";

export function modeOf(axes: ProtectionAxes): ProtectionMode {
  if (axes.confidentiality) return axes.integrity ? "full" : "secrets";
  return axes.integrity ? "injection" : "off";
}

/** MANDU_MODE, parsed. Unset/empty ⇒ undefined; an unknown name throws. */
export function modeFromEnv(env: NodeJS.ProcessEnv = process.env): ProtectionMode | undefined {
  const v = (env.MANDU_MODE ?? "").trim().toLowerCase();
  if (v === "") return undefined;
  if ((PROTECTION_MODES as readonly string[]).includes(v)) return v as ProtectionMode;
  throw new Error(
    `[mandu] MANDU_MODE='${env.MANDU_MODE}' is not a protection mode (want ${PROTECTION_MODES.join("|")})`,
  );
}
