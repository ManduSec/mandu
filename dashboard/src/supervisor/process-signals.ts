/**
 * process-signals — the supervisor's pid / process-group signalling helpers
 * (moved out of supervisor.ts, agent-legibility split; no logic change).
 *
 * Mandu-new (NO reference origin). Two kinds of target:
 *   - OUR children: spawned `detached: true`, so each leads its own process
 *     group and signalGroup() reaches npm → tsx → node together;
 *   - a FOREIGN pid (an adopted daemon we are REPLACE-ing — not our child, no
 *     process group): signalPidChecked() / waitPidGone(), through the
 *     supervisor's injectable `killPid` seam.
 */

import type { ResolvedSupervisorOptions } from "./supervisor-defs.js";

/** The `process.kill`-shaped seam (SupervisorOptions.killPid). */
export type KillPid = ResolvedSupervisorOptions["killPid"];

/**
 * Signal the child's whole process group (negative pid). Spawned detached, the
 * child leads its own group, so this reaches npm → tsx → node together. Falls
 * back to a direct pid signal if the group is already gone.
 */
export function signalGroup(pid: number, sig: NodeJS.Signals): void {
  try {
    process.kill(-pid, sig);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ESRCH") return; // already gone
    // Group signalling unsupported / failed — try the bare pid.
    try {
      process.kill(pid, sig);
    } catch {
      /* already gone */
    }
  }
}

/** Signal a FOREIGN pid (an adopted daemon — not our child, no process group).
 *  ESRCH means it is already gone (fine); anything else (EPERM) is a real
 *  refusal to surface. */
export function signalPidChecked(killPid: KillPid, pid: number, sig: NodeJS.Signals): void {
  try {
    killPid(pid, sig);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ESRCH") return;
    throw new Error(`cannot signal pid ${pid} (${(err as Error).message}) — stop it yourself, then press Start.`);
  }
}

/** Poll until signal-0 reports the pid gone (ESRCH). EPERM counts as ALIVE. */
export async function waitPidGone(killPid: KillPid, pid: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      killPid(pid, 0);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ESRCH") return true;
    }
    if (Date.now() > deadline) return false;
    await new Promise((r) => setTimeout(r, 50));
  }
}
