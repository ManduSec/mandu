/**
 * services/observe — the launcher's own observability events (dashboard.md
 * §4.21, the session-health stream).
 *
 * Every launch already SAYS what posture it runs at — the rung banners on
 * stderr ("exec-box LIVE …", "service 'net-proxy' is on by default but failed
 * to start …") — but only a human reading that terminal ever saw them, and a
 * session that booted thinner than the product default (a dropped rung on the
 * dev box for weeks, 2026-09-05) was invisible to the dashboard. This module
 * turns the banners into ONE `launch_posture` event per session, plus a
 * `session_exit` event when the agent ends, both emitted best-effort over the
 * arbiter's `emit` op (off the security path — a failure only loses a chip).
 *
 * `postureFindings` classifies the banner lines with the SAME phrases the
 * differential harness's posture oracle uses (its differential-oracles.ts
 * wrappedPostureFindings), so the dashboard and the CI gate agree
 * on what "thinner than the product" means.
 *
 * Mandu-new (no reference origin).
 */
import { randomUUID } from "node:crypto";
import { ndjsonCall } from "../secret-setup.js";
import { printablePath } from "../twin-writes.js";

/** A launch banner line classified. `live` = a rung reported itself LIVE /
 *  ACTIVE; `dropped` = a default-on rung that did not come up, a degraded
 *  confinement, or an explicit OFF-by-default note the user should know. */
export interface PostureFindings {
  live: string[];
  dropped: string[];
}

const LIVE_RE = /\b(LIVE|ACTIVE)\b/;
// NOT here on purpose: "exec-box OFF for codex by default" — a designed
// posture (exec-routing.md §7.7), informational, not a degradation.
const DROPPED_RES = [
  /is on by default but failed to start/,
  /secrets are GATED/,
  /rung DEGRADED/,
  /proceeding WITHOUT it/,
  /could not (write|inherit)/,
];

/** Pure: classify launch banner lines. */
export function postureFindings(notes: readonly string[]): PostureFindings {
  const live: string[] = [];
  const dropped: string[] = [];
  for (const raw of notes) {
    const line = raw.trim();
    if (line === "") continue;
    if (DROPPED_RES.some((re) => re.test(line))) dropped.push(line);
    else if (LIVE_RE.test(line) && /^(mandu:|reply-filter)/.test(line)) live.push(line);
  }
  return { live, dropped };
}

/** Rung names a live banner line names (for the compact chip): the token
 *  before LIVE/ACTIVE, e.g. "exec-box LIVE" → "exec-box", "fs rung ACTIVE" → "fs". */
export function liveRungNames(live: readonly string[]): string[] {
  const out: string[] = [];
  for (const l of live) {
    const m = /^(?:mandu: )?([a-z][a-z0-9-]*)(?: rung)? (?:LIVE|ACTIVE)/.exec(l);
    if (m && !out.includes(m[1]!)) out.push(m[1]!);
  }
  return out;
}

export interface LaunchPostureInput {
  scopeId: string;
  tenant?: string;
  /** The observability batch (MANDU_BATCH_ID) — stamped on the launcher's
   *  own events too, so a session that ends before its first model call (whose
   *  proxy events carry the stamp) still groups with its run on the dashboard. */
  batchId?: string;
  /** What the session is within that batch (MANDU_BATCH_MEMBER): one watch
   *  scenario, or one posture group under --shared-session. */
  batchMember?: { kind: "scenario" | "posture"; key: string };
  target: string;
  argv0: string;
  notes: readonly string[];
  /** The launcher's own version stamp (git rev in a dev checkout, package
   *  version when installed) — the "which Mandu" half of the health row. */
  launcherVersion?: string;
  /** The secret-confinement posture (confinement-posture.ts): first-class on
   *  the event so the dashboard chip never has to parse a banner line. */
  secrets?: { posture: string; gap?: string };
  /** The protection mode this session runs under (mode.ts effectiveAxes):
   *  first-class so the dashboard never infers it from classify reasons.
   *  `reported` = the attached arbiter answered with both axes itself; false
   *  means the pair is the launch's request or the built-in default. */
  protection?: { mode: string; integrity: boolean; confidentiality: boolean; reported: boolean };
  /** The agent's version against Mandu's tested range (agent-versions.ts):
   *  first-class so the dashboard can mark a session whose agent was outside
   *  it even when no proxy reported a client version (Codex). */
  agentVersion?: { agent: string; version: string | null; verdict: string; min: string; max: string };
}

const MAX_NOTES = 40;

function base(sessionId: string, kind: string, tenant: string | undefined, batchId?: string): Record<string, unknown> {
  return {
    id: `ev_${Date.now().toString(36)}${randomUUID().replace(/-/g, "").slice(0, 10)}`,
    sessionId,
    turn: 0,
    ts: new Date().toISOString(),
    seq: 0,
    callId: null,
    parentId: null,
    kind,
    view: "HumanView",
    boundary: "shell",
    emitter: "launcher",
    invariant: { violatedInvariant: false },
    ...(tenant === "live" || tenant === "test" ? { tenant } : {}),
    ...(batchId ? { batchId } : {}),
  };
}

/** Build the `launch_posture` event. Pure. */
export function launchPostureEvent(input: LaunchPostureInput): Record<string, unknown> {
  const { live, dropped } = postureFindings(input.notes);
  const rungs = liveRungNames(live);
  const summary =
    `${input.target} launch: ${rungs.length} rung(s) live [${rungs.join(", ")}]` +
    (dropped.length ? ` · ${dropped.length} DROPPED/degraded` : " · full posture");
  return {
    ...base(input.scopeId, "launch_posture", input.tenant, input.batchId),
    ...(input.batchMember ? { batchMember: { kind: input.batchMember.kind, key: input.batchMember.key } } : {}),
    target: input.target,
    argv0: input.argv0,
    live: rungs,
    dropped,
    ...(input.launcherVersion ? { launcherVersion: input.launcherVersion } : {}),
    ...(input.secrets ? { secrets: input.secrets } : {}),
    ...(input.protection ? { protection: input.protection } : {}),
    ...(input.agentVersion ? { agentVersion: input.agentVersion } : {}),
    notes: input.notes.slice(0, MAX_NOTES),
    input: { symbolized: summary, original: null, differs: false, symbols: [] },
    output: {
      symbolized: dropped.length ? dropped.join("\n") : "every default-on rung engaged",
      original: null, differs: false, symbols: [],
    },
  };
}

/** Build the `session_exit` event. `discardedWrites`: the registered secret
 *  files whose placeholder copy the session changed (twin-writes.ts), by
 *  path only; present only when there is one. The summary text shows each
 *  path with its control and format characters as `?` (twin-writes.ts
 *  `printablePath`); the field keeps the paths as they are. Pure. */
export function sessionExitEvent(input: { scopeId: string; tenant?: string; batchId?: string; code: number; durationMs: number; discardedWrites?: readonly string[] }): Record<string, unknown> {
  const discarded = input.discardedWrites ?? [];
  const summary = `agent exited ${input.code} after ${Math.round(input.durationMs / 1000)}s` +
    (discarded.length > 0
      ? `; the agent changed ${discarded.length} protected file${discarded.length === 1 ? "" : "s"} (${discarded.map(printablePath).join(", ")}): ` +
        "the change stayed in the placeholder copy and never reached the real file"
      : "");
  return {
    ...base(input.scopeId, "session_exit", input.tenant, input.batchId),
    code: input.code,
    durationMs: input.durationMs,
    ...(discarded.length > 0 ? { discardedWrites: [...discarded] } : {}),
    input: { symbolized: summary, original: null, differs: false, symbols: [] },
    output: null,
  };
}

/** Emit one event over the arbiter's `emit` op. Best-effort: resolves false on
 *  any failure (no socket, wedged arbiter, older protocol) — observability is
 *  never on the launch path. `humanSock` first (arbiter-human-plane.md §10.2:
 *  only there is the event believed), else, or on a failure there, `sock`
 *  (the data socket, where the arbiter stores it as a claim). */
export async function emitLauncherEvent(sock: string | undefined, event: Record<string, unknown>, humanSock?: string | null): Promise<boolean> {
  for (const s of [humanSock, sock]) {
    if (!s) continue;
    try {
      await ndjsonCall<unknown>(s, "emit", { event }, 2000);
      return true;
    } catch {
      /* the next socket */
    }
  }
  return false;
}
