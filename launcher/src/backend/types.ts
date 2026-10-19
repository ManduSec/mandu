/**
 * backend/types — the enforcement-backend seam that keeps hardening optional.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. The registry realizes spec §2.3: coop-env required and
 *   identical on every OS; kernel-layer backends (Part 2) probe + degrade.
 */
import type { Availability } from "../platform/types.js";
import type { LaunchMutation, LaunchPlan } from "../types.js";

export interface EnforcementBackend {
  id: "coop-env" | string;
  chokepoints: Array<"context" | "net" | "fs" | "exec">;
  /** Is this backend usable on this host for this plan? */
  probe(plan: LaunchPlan): Availability;
  /** Whether the plan explicitly asked for this backend (drives fail-closed). */
  requestedBy(plan: LaunchPlan): boolean;
  /** Fold this backend's env/argv/launch changes into the mutation. */
  prepare(plan: LaunchPlan, mut: LaunchMutation): void;
  postExit?(): void;
}

export function emptyMutation(): LaunchMutation {
  return { env: {}, argvPrefix: [], launchPrefix: [] };
}
