/**
 * axes — "every suite states its axes" (docs/design/architecture/protection-modes.md §4).
 *
 * A suite that builds an arbiter (in-process or spawned) calls stateAxes()
 * once at module load. It pins MANDU_INTEGRITY / MANDU_CONFIDENTIALITY in
 * this process's env, which the in-process ArbiterServer / policy read and
 * every spawned daemon inherits. The npm test scripts run with
 * MANDU_AXES_STRICT=1 (arbiter/policy/axes-strict.ts), so a suite that
 * forgets this line fails loudly instead of silently following whatever the
 * built-in default happens to be. An explicit integrity/confidentiality option
 * on one server still wins over this pin.
 *
 * The same small file is mirrored in each TS package's test tree (there is no
 * repo-root workspace to share it from). Mandu-new (no reference origin).
 */
export type ProtectionMode = "secrets" | "injection" | "full" | "off";

/** Mode → axis pair. Mirrors launcher/src/mode.ts (the source of truth). */
export const MODE_AXES: Record<ProtectionMode, { integrity: boolean; confidentiality: boolean }> = {
  secrets: { integrity: false, confidentiality: true },
  injection: { integrity: true, confidentiality: false },
  full: { integrity: true, confidentiality: true },
  off: { integrity: false, confidentiality: false },
};

/** The env for a mode, for a spawn site that builds its own env object. A
 *  mode with the FROZEN integrity axis ON also carries the opt-in the arbiter
 *  daemon and the launcher require (docs/design/architecture/protection-modes.md §10); any
 *  other mode clears it, so a suite never inherits the opt-in by accident. */
export function axesEnv(mode: ProtectionMode): {
  MANDU_INTEGRITY: string;
  MANDU_CONFIDENTIALITY: string;
  MANDU_EXPERIMENTAL_INTEGRITY: string;
} {
  const a = MODE_AXES[mode];
  return {
    MANDU_INTEGRITY: a.integrity ? "1" : "0",
    MANDU_CONFIDENTIALITY: a.confidentiality ? "1" : "0",
    MANDU_EXPERIMENTAL_INTEGRITY: a.integrity ? "1" : "",
  };
}

/** Pin this test process (and everything it spawns) to `mode`. */
export function stateAxes(mode: ProtectionMode): void {
  Object.assign(process.env, axesEnv(mode));
}
