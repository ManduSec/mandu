/**
 * axes-strict — the "every suite states its axes" guard
 * (docs/design/architecture/protection-modes.md §3.1 / §4).
 *
 * The two axis flags (integrity-flag.ts, confidentiality-flag.ts) fall back to
 * a built-in default when nothing states the axis. That fallback is right for
 * a user's launch and WRONG for a test: a security-invariant suite that leans
 * on the implicit default turns into a silent no-op the day the default moves
 * (the axis goes quiet, nothing is symbolized, and "nothing leaked" still
 * passes). With MANDU_AXES_STRICT=1 an unstated axis is a thrown error
 * instead of a default, so the suite fails loudly and names the fix.
 *
 * Every package's `npm test` script and scripts/test-all.sh export the
 * variable; a daemon a test spawns inherits it, so the spawn site has to state
 * the axes too. Production never sets it. Stating an axis means either the
 * explicit option (ArbiterServerOptions / createEngineBackedPolicy) or the
 * MANDU_INTEGRITY / MANDU_CONFIDENTIALITY env var.
 *
 * Mandu-new (no reference origin).
 */
export function axesStrict(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = (env.MANDU_AXES_STRICT ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "on";
}

/** Throw when strict mode is on and `envVar` states nothing. */
export function assertAxisStated(envVar: string, env: NodeJS.ProcessEnv = process.env): void {
  if (!axesStrict(env)) return;
  if ((env[envVar] ?? "").trim() !== "") return;
  if ((env.MANDU_MODE ?? "").trim() !== "") return; // a mode states both axes
  throw new Error(
    `[mandu] MANDU_AXES_STRICT=1: ${envVar} is not stated. A test must state both protection axes ` +
      `(pass integrity/confidentiality options, or set MANDU_INTEGRITY and MANDU_CONFIDENTIALITY) ` +
      `so a change of the built-in default cannot silently turn it into a no-op ` +
      `(docs/design/architecture/protection-modes.md §4).`,
  );
}
