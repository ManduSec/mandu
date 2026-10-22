/**
 * view-model/launch-time — how long Mandu took to start a session, in plain
 * words, for the product's session page (dashboard.md §4.25ag;
 * runtime-instances.md §14.11). Mandu-new (no reference origin).
 *
 * The launcher times each step of a launch and records them on its
 * `launch_posture` event (the steps before the AI started) and its
 * `session_exit` event (the AI's own run and the clean-up after it), field
 * `timings` (event-model.ts `LaunchTimingsDetail`). The page says:
 *
 *   "Mandu took 1.7 s to start this session: checking git history for
 *    secrets 0.38 s, starting the session's helpers 0.37 s, starting Mandu
 *    0.26 s."
 *   "After the AI stopped, Mandu took 0.2 s to clean up."
 *
 * The slowest steps first (at most SLOWEST, each at least MIN_SHOWN_MS),
 * the secret setup told by its parts (its git-history step is the one that
 * grows with a home's repositories). OBSERVABILITY ONLY: nothing here is
 * on the security path; a malformed record is no line.
 */
import type { LaunchTimingsDetail, ManduEvent } from "../event-model.js";

/** How many steps the line names. */
export const SLOWEST = 3;
/** A step shorter than this is not named. */
export const MIN_SHOWN_MS = 50;

/** Each step's plain name (the launcher's LAUNCH_STEPS). A step not here
 *  (a newer launcher's) is not named; the total still counts it. */
export const STEP_WORDS: Readonly<Record<string, string>> = {
  node: "starting Mandu",
  plan: "reading your settings",
  arbiter: "reaching Mandu's protection service",
  services: "starting the session's helpers",
  confine: "setting up the network limits",
  "key-grants": "preparing the AI's sign-in keys",
  secrets: "masking your secret files",
  "secrets.discovery": "finding your secret files",
  "secrets.history": "checking git history for secrets",
  "secrets.watch": "watching your repositories for commits",
  "secrets.twin-index": "keeping git quiet about masked files",
  "placeholder-check": "checking earlier sessions",
  "env-secrets": "masking secret settings in the environment",
  compose: "preparing the AI's protections",
  record: "telling the protection service about the session",
  banner: "writing the start line",
  posture: "recording how the session is protected",
  "agent-start": "handing the session to the AI",
};

export interface LaunchTimeVM {
  /** The start, in seconds as the page shows them ("1.7 s"). */
  total: string;
  totalMs: number;
  /** The slowest steps, slowest first. */
  slowest: Array<{ words: string; time: string; ms: number }>;
  /** The whole line: "Mandu took 1.7 s to start this session: …". */
  sentence: string;
  /** "After the AI stopped, Mandu took 0.2 s to clean up.", or null when
   *  the session has not ended (or recorded no clean-up). */
  cleanup: string | null;
}

/** "0.38 s" under a second, "1.7 s" from one, "12 s" from ten. Pure. */
export function seconds(ms: number): string {
  const s = Math.max(0, ms) / 1000;
  if (s < 1) return `${s.toFixed(2)} s`;
  if (s < 10) return `${s.toFixed(1)} s`;
  return `${Math.round(s)} s`;
}

function timingsOf(e: ManduEvent | undefined): LaunchTimingsDetail | null {
  const t = (e as { timings?: unknown } | undefined)?.timings as LaunchTimingsDetail | undefined;
  if (!t || t.v !== 1 || typeof t.totalMs !== "number" || !Number.isFinite(t.totalMs) || !Array.isArray(t.steps)) return null;
  if (t.steps.some((s) => !s || typeof s.step !== "string" || typeof s.ms !== "number" || !Number.isFinite(s.ms))) return null;
  return t;
}

/** The last event of `kind` from the launcher. */
function lastOf(events: readonly ManduEvent[], kind: string): ManduEvent | undefined {
  let at: ManduEvent | undefined;
  for (const e of events) if (e.kind === kind && e.emitter === "launcher" && (at === undefined || e.ts >= at.ts)) at = e;
  return at;
}

/**
 * The session's start time and its slowest steps, or null when its launch
 * recorded none (an older launcher, a session not started by `mandu`). The
 * secret setup counts as its parts plus what is left of it ("masking your
 * secret files"), so its slow part is named. Pure.
 */
export function launchTimeOf(events: readonly ManduEvent[]): LaunchTimeVM | null {
  const start = timingsOf(lastOf(events, "launch_posture"));
  if (start === null) return null;
  const parts = new Map<string, number>();
  for (const s of start.steps) parts.set(s.step, (parts.get(s.step) ?? 0) + s.ms);
  const secretParts = [...parts].filter(([k]) => k.startsWith("secrets."));
  if (parts.has("secrets")) parts.set("secrets", Math.max(0, parts.get("secrets")! - secretParts.reduce((a, [, ms]) => a + ms, 0)));
  const slowest = [...parts]
    .filter(([k, ms]) => STEP_WORDS[k] !== undefined && ms >= MIN_SHOWN_MS)
    .sort((a, b) => b[1] - a[1])
    .slice(0, SLOWEST)
    .map(([k, ms]) => ({ words: STEP_WORDS[k]!, time: seconds(ms), ms }));
  const total = seconds(start.totalMs);
  const sentence = `Mandu took ${total} to start this session` +
    (slowest.length ? `: ${slowest.map((s) => `${s.words} ${s.time}`).join(", ")}.` : ".");
  const end = timingsOf(lastOf(events, "session_exit"));
  const cleanupMs = end ? end.steps.filter((s) => s.step.startsWith("teardown.")).reduce((a, s) => a + s.ms, 0) : 0;
  const cleanup = end && end.steps.some((s) => s.step.startsWith("teardown."))
    ? `After the AI stopped, Mandu took ${seconds(cleanupMs)} to clean up.`
    : null;
  return { total, totalMs: start.totalMs, slowest, sentence, cleanup };
}
