/**
 * proxy-secret-posture — the MANDU_SECRET_POSTURE a launch hands the model
 * proxy it starts (docs/design/agents/handling-prompt.md §2; macOS, 2026-09-29).
 *
 * The proxy reports the value on every handling-prompt request, and the
 * arbiter adds the "blocked credential files" section for a `read-blocked`
 * session: on macOS a Seatbelt profile blocks every read of the credential
 * files, so a read FAILS ("Operation not permitted") instead of returning a
 * placeholder, and a model left untold reads that as a bug to route around.
 *
 * WHY A PREDICTION. The context proxy starts before the secret setup (the
 * discovery walk runs while the proxies come up, run.ts), so the setup's own
 * answer is not known yet. The macOS answer is fully decided by the host and
 * the axis: with the confidentiality axis ON and `/usr/bin/sandbox-exec`
 * there the setup wraps the agent in the read-deny profile (secret-setup.ts,
 * the same `sandboxExecAvailable` check of that path, never a PATH lookup);
 * without it the launch is `gated`.
 * Only `read-blocked` changes the prompt, so everything else is unset (an
 * absent value keeps every prompt byte-identical); Linux's placeholder twins
 * explain themselves on the first read and need no prediction.
 *
 * UTILITY, NOT A GATE: a wrong value costs guidance, never a secret (the
 * profile, symbolization and the egress gates hold whatever the prompt says).
 *
 * Mandu-new (no reference origin).
 */
import { sandboxExecAvailable } from "./seatbelt-profile.js";

export interface ProxySecretPostureInput {
  platform: NodeJS.Platform;
  /** The EFFECTIVE confidentiality axis of this launch (plan.effectiveAxes). */
  confidentiality: boolean;
  /** The command check, as the secret setup gets it; asked only for
   *  `/usr/bin/sandbox-exec` by path. Default: that file's executable bit. */
  commandExists?: (cmd: string) => boolean;
}

/** The posture to report, or undefined (leave MANDU_SECRET_POSTURE unset). */
export function proxySecretPosture(input: ProxySecretPostureInput): "read-blocked" | undefined {
  if (!input.confidentiality || input.platform !== "darwin") return undefined;
  return sandboxExecAvailable(input.commandExists) ? "read-blocked" : undefined;
}
