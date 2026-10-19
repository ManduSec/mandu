/**
 * lineage — best-effort spawn-lineage emission for the exec chokepoint
 * (design §3.2: a child of a tainted process is tainted, so the arbiter needs the
 * parent→child edge at spawn time).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code; mirrors the Rust
 * exec-supervisor `record_spawn_lineage` emitter and the arbiter-client narrow
 * pattern. No reference-source origin — the exec supervisor is Mandu-new.
 *
 * SECURITY-INVARIANT NOTE: this is OFF the security path. Unlike the exec GATE
 * (which fails CLOSED — a arbiter error blocks), lineage emission is
 * observability-grade provenance: a failure is SWALLOWED so it NEVER blocks or
 * alters a real exec. The chain's safety rests on the fail-closed gate
 * (src/gate.ts) + the model-proxy backstop, not on this edge being recorded.
 *
 * PROVISIONAL PROC-KEY FORMAT: `provisionalProcKey` derives an opaque key from a
 * pid. The CROSS-LAYER format — how exec/net/fs proc keys correlate (bare pid vs
 * `pid-starttime` to defeat pid reuse; see design §2 `process_taint.proc_key =
 * pid + start-time`) — is a DEFERRED co-design. Until it lands, this emits a
 * provisional `${pid}-${starttime}` (or bare `${pid}` on fallback) key that is NOT
 * yet correlated against the net/fs layers, so the taint CHAIN is not live
 * end-to-end.
 */

import { readFileSync } from "node:fs";

import type { ExecArbiter } from "./arbiter-client.js";

/**
 * Derive a PROVISIONAL opaque proc key for `pid`. Best-effort: tries to read
 * field 22 (starttime, in clock ticks) of `/proc/<pid>/stat` to form
 * `${pid}-${starttime}` (which defeats pid reuse, matching design §2); on ANY
 * failure (non-Linux, race, permission) it falls back to the bare `${pid}`.
 *
 * NOTE: the bare-pid vs pid-starttime choice + cross-layer correlation is the
 * DEFERRED co-design; callers must treat the returned string as opaque.
 */
export function provisionalProcKey(pid: number): string {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    // The comm field (field 2) is parenthesized and may contain spaces/parens, so
    // split AFTER the last ')'. Fields after that are space-separated; starttime is
    // field 22 overall → index 19 of the post-')' remainder (state is the 1st).
    const afterComm = stat.slice(stat.lastIndexOf(")") + 2);
    const fields = afterComm.split(" ");
    const starttime = fields[19]; // field 22 overall (1-based)
    if (starttime !== undefined && starttime !== "") return `${pid}-${starttime}`;
  } catch {
    // fall through to the bare-pid provisional key
  }
  return `${pid}`;
}

/**
 * Best-effort: record the parent→child spawn lineage edge. NEVER throws — a
 * arbiter error is swallowed so emission can never block or alter the exec.
 */
export async function recordSpawnLineage(
  arbiter: ExecArbiter,
  childKey: string,
  parentKey: string,
): Promise<void> {
  try {
    await arbiter.processLineage({ childKey, parentKey });
  } catch {
    // swallow — observability-grade; off the security path.
  }
}
