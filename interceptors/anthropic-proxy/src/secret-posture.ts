/**
 * secret-posture — the session's secret posture, a SESSION fact the proxy
 * reports on every handlingPrompt request (docs/design/agents/handling-prompt.md §2).
 *
 * The launcher decides the posture (launcher/src/confinement-posture.ts:
 * `confined` on Linux, `read-blocked` on macOS, `gated` where the host cannot
 * confine) and hands it to the model proxy it starts as MANDU_SECRET_POSTURE.
 * The arbiter maps the fact to a prompt section: under `read-blocked` a read
 * of a credential file FAILS (Seatbelt), so the model must be told not to
 * work around it and where its usable secrets are (the `$MDU:` placeholders).
 *
 * UTILITY, NOT A GATE: the fact only chooses guidance text. A wrong or
 * missing value costs answer quality, never a secret: the read-block, the
 * symbolization and the egress gates hold whatever the prompt says. So an
 * unknown value is dropped (reported as nothing, the byte-identical prompt)
 * rather than refusing the proxy's start.
 *
 * The posture names mirror the launcher's POSTURES (a parity test holds them
 * together; this package does not import the launcher). Mandu-new.
 */

/** Mirrors launcher/src/confinement-posture.ts `POSTURES`. */
export const SECRET_POSTURES = ["confined", "read-blocked", "gated"] as const;
export type SecretPosture = (typeof SECRET_POSTURES)[number];

/** MANDU_SECRET_POSTURE → a known posture, or undefined (unset, empty, or
 *  unknown: an unknown value is logged once and dropped). Pure but for `log`. */
export function secretPostureFromEnv(raw: string | undefined, log?: (msg: string) => void): SecretPosture | undefined {
  if (raw === undefined || raw === "") return undefined;
  if ((SECRET_POSTURES as readonly string[]).includes(raw)) return raw as SecretPosture;
  log?.(`MANDU_SECRET_POSTURE=${JSON.stringify(raw)} is not a posture this proxy knows (${SECRET_POSTURES.join(" | ")}); not reported`);
  return undefined;
}
