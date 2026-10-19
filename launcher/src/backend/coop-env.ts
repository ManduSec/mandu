/**
 * backend/coop-env — the REQUIRED backend; it IS the wrapper layer.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. Wraps the pure composer (src/env-compose.ts) as a
 *   backend; available on every OS (spec §2.3), never wraps the launch prefix.
 */
import { codexShellNote, codexUploadsNote, composeLaunch, shellTargetNote } from "../env-compose.js";
import type { EnforcementBackend } from "./types.js";

export const coopEnv: EnforcementBackend = {
  id: "coop-env",
  chokepoints: ["context", "net", "fs", "exec"],
  probe: () => ({ available: true }),
  requestedBy: () => true,
  prepare(plan, mut) {
    const { env, argvPrefix } = composeLaunch(plan);
    Object.assign(mut.env, env);
    mut.argvPrefix.push(...argvPrefix);
    // A plain command (target shell) says what its env routing does not
    // reach (agent-e2e-harness.md §9.1). console.error is the launch-note
    // channel: run.ts keeps it in launch.log + the launch_posture event.
    // The same for a shell under --target codex (no Codex routing options).
    // A Codex on a ChatGPT sign-in hears that its apps are off (codexUploadsNote).
    for (const note of [shellTargetNote(plan), codexShellNote(plan), codexUploadsNote(plan)]) {
      if (note !== null) console.error(note);
    }
  },
};
