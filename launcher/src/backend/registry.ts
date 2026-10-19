/**
 * backend/registry — probe every backend, prepare the available ones, and
 * FAIL CLOSED when an explicitly-requested backend is unavailable.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. Realizes spec §5: a requested gate that cannot be set up
 *   ABORTS the launch (throw); --best-effort downgrades that to a loud warning.
 */
import type { LaunchMutation, LaunchPlan } from "../types.js";
import type { EnforcementBackend } from "./types.js";

export function runBackends(
  backends: EnforcementBackend[],
  plan: LaunchPlan,
  mut: LaunchMutation,
  warn: (msg: string) => void = (m) => console.error(`mandu: ${m}`),
): void {
  for (const b of backends) {
    const avail = b.probe(plan);
    if (avail.available) { b.prepare(plan, mut); continue; }
    if (!b.requestedBy(plan)) continue; // not asked for → silent skip
    const msg = `backend '${b.id}' was requested but is unavailable: ${avail.reason}`;
    if (plan.bestEffort) { warn(`${msg} — proceeding WITHOUT it (--best-effort)`); continue; }
    throw new Error(`mandu: ${msg} (pass --best-effort to launch anyway)`);
  }
}
