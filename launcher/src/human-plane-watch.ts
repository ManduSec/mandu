/**
 * human-plane-watch — telling a walled launch's user why its file guard is
 * not believed (arbiter-human-plane.md §10.1.1; P0 (E) decision 3,
 * 2026-10-03).
 *
 * While a launch whose agent can reach the arbiter's human-plane socket (an
 * UNWALLED launch: no guard deny entry and no wrap over the human
 * directory, e.g. `--mode off` or `--no-net-guard` without the bind) is
 * live, the arbiter answers every guard and model-proxy report on that
 * socket as a claim (§10.1). A walled launch running beside it therefore
 * loses its guard's attestation: secret opens get the placeholder,
 * protected writes are refused, shell results are masked. That stays (fail
 * closed). This module only makes it visible: the launcher of a walled
 * launch in a protecting mode asks the arbiter (`humanPlaneStatus`, human
 * plane, read-only) once before its agent starts and every
 * {@link WATCH_INTERVAL_MS} while it runs, and prints
 *   - one WARNING block when the exposure begins, naming each launch that
 *     holds it (pid, session, mode) and the fix (stop it, or relaunch it
 *     with its file guard on); told before the agent starts, run.ts holds
 *     it until the banner is out, so it is the last thing on screen when
 *     the agent takes the terminal (launch-banner.ts holdUntilBanner);
 *   - one line when the set of those launches changes, and one when the
 *     guard is believed again;
 *   - after the agent exits, a recap (a full-screen agent may have painted
 *     over the lines above).
 * It decides nothing, and a failed or refused ask prints nothing (an older
 * arbiter answers an unknown op: the watch stops).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */

/** How often the watch asks while the agent runs (ms). */
export const WATCH_INTERVAL_MS = 2000;
/** Per-ask deadline (ms); a slow arbiter costs a skipped tick, never a hang. */
export const WATCH_CALL_TIMEOUT_MS = 3000;

/** One launch that holds the human plane exposed, as the arbiter names it. */
export interface ExposingLaunch {
  pid: number;
  mode: string;
  posture: string;
  session?: string;
  begunAt?: number;
}

/** `humanPlaneStatus`'s answer. */
export interface HumanPlaneStatusWire {
  exposed: boolean;
  since: number | null;
  launches: ExposingLaunch[];
}

/** Read the arbiter's answer, or null when it is not of the shape. Pure. */
export function parseHumanPlaneStatus(v: unknown): HumanPlaneStatusWire | null {
  if (v === null || typeof v !== "object") return null;
  const x = v as Record<string, unknown>;
  if (typeof x.exposed !== "boolean" || !Array.isArray(x.launches)) return null;
  const launches: ExposingLaunch[] = [];
  for (const o of x.launches.slice(0, 64)) {
    if (o === null || typeof o !== "object") continue;
    const l = o as Record<string, unknown>;
    if (typeof l.pid !== "number") continue;
    launches.push({
      pid: l.pid,
      mode: String(l.mode ?? "unknown"),
      posture: String(l.posture ?? "unknown"),
      ...(typeof l.session === "string" && l.session !== "" ? { session: l.session } : {}),
      ...(typeof l.begunAt === "number" ? { begunAt: l.begunAt } : {}),
    });
  }
  // `exposed` with no launch named still counts (the arbiter failed closed).
  return { exposed: x.exposed || launches.length > 0, since: typeof x.since === "number" ? x.since : null, launches };
}

/** One launch in words: `pid 4242 (session s, mode off)`. Pure. */
export function launchWords(l: ExposingLaunch): string {
  const what = [l.session ? `session ${l.session}` : null, `mode ${l.mode}`].filter((p) => p !== null).join(", ");
  return l.pid > 0 ? `pid ${l.pid} (${what})` : "a launch Mandu could not name (its record could not be read)";
}

function list(launches: readonly ExposingLaunch[]): string {
  const shown = launches.slice(0, 3).map(launchWords).join("; ");
  return launches.length > 3 ? `${shown}; and ${launches.length - 3} more` : shown;
}

/** The fix, one line. Pure. */
export const EXPOSURE_FIX =
  "  To fix it: stop that launch, or start it again with its file guard on (not --mode off, not --no-net-guard; " +
  "`mandu doctor` says whether this computer can run the guard). This session is believed again on its own once it ends.";

/** The WARNING block when the exposure begins. Pure. */
export function exposureLostLines(launches: readonly ExposingLaunch[]): string[] {
  const one = launches.length <= 1;
  return [
    `WARNING: mandu: this session's file guard is not believed: ${one ? "another Mandu launch" : `${launches.length} other Mandu launches`} can reach Mandu's own controls: ${list(launches)}.`,
    `  ${one ? "It runs" : "They run"} with no file guard and no mount layer between ${one ? "its" : "their"} agent and Mandu's human-plane socket, so Mandu cannot tell this session's guard reports from forged ones.`,
    `  Until ${one ? "it ends" : "they end"}, here: every secret file opens as its placeholder, every write to a protected file is refused, and shell output is masked once the session has read a secret.`,
    EXPOSURE_FIX,
  ];
}

/** The line when the set changes while still exposed. Pure. */
export function exposureChangedLine(launches: readonly ExposingLaunch[]): string {
  return `WARNING: mandu: this session's file guard is still not believed; the launches that can reach Mandu's own controls are now: ${list(launches)}.`;
}

/** The line when the guard is believed again. Pure. */
export function exposureRestoredLine(ended: readonly ExposingLaunch[]): string {
  return `mandu: this session's file guard is believed again: ${ended.length === 1 ? "the launch" : "the launches"} that could reach Mandu's own controls (${list(ended)}) ended.`;
}

/** One period the guard was not believed. */
export interface ExposurePeriod {
  from: number;
  /** null: still exposed when the recap was taken. */
  to: number | null;
  launches: ExposingLaunch[];
}

function clock(ms: number): string {
  const d = new Date(ms);
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, "0")).join(":");
}

/** After the agent exits: what happened, in one or two lines (a full-screen
 *  agent may have painted over the live lines). Empty when nothing did. Pure. */
export function exposureRecapLines(periods: readonly ExposurePeriod[]): string[] {
  if (periods.length === 0) return [];
  const who = new Map<string, ExposingLaunch>();
  for (const p of periods) for (const l of p.launches) who.set(`${l.pid}/${l.session ?? ""}`, l);
  const spans = periods.slice(0, 5).map((p) => `${clock(p.from)} to ${p.to === null ? "the end" : clock(p.to)}`).join(", ");
  return [
    `WARNING: mandu: during this session its file guard was not believed (${spans}${periods.length > 5 ? ", …" : ""}) while another Mandu launch could reach Mandu's own controls: ${list([...who.values()])}.`,
    "  In that time secret files opened as placeholders, protected writes were refused and shell output was masked; anything that failed then can be run again now.",
    ...(periods.at(-1)!.to === null ? [EXPOSURE_FIX] : []),
  ];
}

const key = (ls: readonly ExposingLaunch[]): string => ls.map((l) => `${l.pid}/${l.session ?? ""}/${l.mode}`).sort().join(",");

/** The watch's state machine: what to print for a new answer. Pure. */
export function exposureStep(
  told: readonly ExposingLaunch[],
  now: HumanPlaneStatusWire,
): { lines: string[]; told: ExposingLaunch[]; change: "lost" | "changed" | "restored" | null } {
  const launches = now.exposed ? (now.launches.length > 0 ? now.launches : [{ pid: 0, mode: "unknown", posture: "unknown" }]) : [];
  if (key(told) === key(launches)) return { lines: [], told: [...told], change: null };
  if (launches.length === 0) return { lines: [exposureRestoredLine(told)], told: [], change: "restored" };
  if (told.length === 0) return { lines: exposureLostLines(launches), told: launches, change: "lost" };
  return { lines: [exposureChangedLine(launches)], told: launches, change: "changed" };
}

export interface HumanPlaneWatchDeps {
  /** One request on a socket (secret-setup.ts `ndjsonCall`). */
  call: (sock: string, op: string, args: Record<string, unknown>) => Promise<unknown>;
  print: (line: string) => void;
  now?: () => number;
  intervalMs?: number;
}

export interface HumanPlaneWatch {
  /** Ask now (and print what changed). Never throws. */
  checkNow(): Promise<void>;
  /** Start asking every interval (unref'd). */
  start(): void;
  /** Stop asking. */
  stop(): void;
  /** The recap lines (`exposureRecapLines` over what was seen). */
  recap(): string[];
}

/** The watch over the arbiter's human socket. */
export function humanPlaneWatch(humanSock: string, deps: HumanPlaneWatchDeps): HumanPlaneWatch {
  const now = deps.now ?? Date.now;
  let told: ExposingLaunch[] = [];
  const periods: ExposurePeriod[] = [];
  let timer: ReturnType<typeof setInterval> | null = null;
  let retired = false;
  let inFlight: Promise<void> | null = null;

  const ask = async (): Promise<void> => {
    if (retired) return;
    let st: HumanPlaneStatusWire | null;
    try {
      st = parseHumanPlaneStatus(await deps.call(humanSock, "humanPlaneStatus", {}));
    } catch (e) {
      // An arbiter that predates the op: nothing to watch. Anything else
      // (unreachable, a timeout): this tick says nothing.
      if (/unknown op/i.test((e as Error)?.message ?? "")) retire();
      return;
    }
    if (st === null) return;
    const step = exposureStep(told, st);
    told = step.told;
    const t = now();
    if (step.change === "lost") periods.push({ from: st.since ?? t, to: null, launches: [...told] });
    else if (step.change === "changed") {
      const open = periods.at(-1);
      if (open && open.to === null) open.launches.push(...told.filter((l) => !open.launches.some((o) => o.pid === l.pid && o.session === l.session)));
    } else if (step.change === "restored") {
      const open = periods.at(-1);
      if (open && open.to === null) open.to = t;
    }
    for (const l of step.lines) {
      try { deps.print(l); } catch { /* display only */ }
    }
  };
  const checkNow = (): Promise<void> => {
    if (inFlight) return inFlight;
    inFlight = ask().finally(() => { inFlight = null; });
    return inFlight;
  };
  const retire = (): void => {
    retired = true;
    if (timer !== null) clearInterval(timer);
    timer = null;
  };
  return {
    checkNow,
    start() {
      if (timer !== null || retired) return;
      timer = setInterval(() => { void checkNow(); }, deps.intervalMs ?? WATCH_INTERVAL_MS);
      timer.unref?.();
    },
    stop() {
      if (timer !== null) clearInterval(timer);
      timer = null;
      retired = true;
    },
    recap: () => exposureRecapLines(periods),
  };
}

/** Does this launch watch? A walled launch in a protecting mode with a human
 *  socket: its guard's reports are the ones an exposure stops believing.
 *  An unwalled launch is itself the exposure, and `off` protects nothing.
 *  Pure. */
export function watchesHumanPlane(claim: { mode: string; humanPlaneWalled?: boolean }, humanSock: string | null | undefined): boolean {
  return !!humanSock && claim.humanPlaneWalled === true && claim.mode !== "off";
}
