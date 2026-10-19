/**
 * view-model/service-summary — the product page's Settings › Protection
 * service block (dashboard.md §4.25, "Settings"), in plain words.
 *
 * Mandu-new (no reference origin). A read-only projection of the supervisor
 * snapshot (`Supervisor.status()`), served at `GET /api/control/summary`.
 * The developer view keeps the full per-service rows (`/api/control/status`,
 * control.js); the product page shows ONE line, under the on/off of the
 * Protection row: whether Mandu itself (the shared per-account service every
 * `mandu` session attaches to) is running, with Start or Restart. The page
 * writes it as "<name>. <sentence>", so the sentence never repeats the name
 * and never says Mandu protects anything: the on/off above it says that, and
 * a service can run with protection off (dashboard.md §4.25 *One Protection
 * row*). The page reads it again on its poll while
 * Settings is open, so the row follows a crash or a start made elsewhere
 * (dashboard.md §4.25, *The service row follows the service*).
 *
 * The model and network helpers the supervisor can also run are NOT shown:
 * they serve only the developer view's own runs, and every agent started
 * with `mandu` brings its own for as long as it runs (runtime-instances.md),
 * so "stopped" is their normal state on a launcher-started stack and read as
 * an outage to a user. A helper that CRASHED gets one note, pointing at the
 * developer view where the build serves it (dashboard.md §4.25ad), since
 * that is not normal.
 *
 * The copy stays inside the product vocabulary (home-view-model.test sweeps
 * it); the service id travels only inside `action.path`, never as words.
 */

import type { ServiceState, ServiceStatus } from "../supervisor/supervisor-defs.js";

/** The service a `mandu` session depends on: the rest are helpers. */
export const MAIN_SERVICE = "arbiter";

export interface ServiceSummary {
  /** False when the supervisor does not run the main service at all. */
  available: boolean;
  state: ServiceState | null;
  /** "Running", "Stopped", …: the line's first word or words. */
  name: string;
  /** One plain sentence after the name, or "" when the name says it all. */
  sentence: string;
  /** For the "Since …" suffix while running; null otherwise, and for an
   *  adopted service (its `since` is when this dashboard found it). */
  since: number | null;
  /** The row's one button: its label, the control route it POSTs to, and,
   *  for Restart, the sentence the page asks the human to confirm first
   *  (a restart drops protection for running agents until it is back).
   *  Null with no main service, for an adopted one (ADOPTED_SENTENCE), and
   *  while it is starting: a Start then only waits for the start under way
   *  (Supervisor.start coalesces), and the page's poll redraws the row once
   *  it is running or has stopped. */
  action: { label: "Start" | "Restart"; path: string; confirm: string | null } | null;
  /** Set only when a helper crashed. */
  helperNote: string | null;
}

const WORDS: Record<ServiceState, { name: string; sentence: string }> = {
  running: { name: "Running", sentence: "" },
  starting: { name: "Starting", sentence: "" },
  stopped: { name: "Stopped", sentence: "It starts again by itself when you next start an agent with mandu." },
  crashed: { name: "Stopped unexpectedly", sentence: "Press Start, or start an agent with mandu." },
};

/** Restart only: Start runs nothing that is protecting anyone yet. While the
 *  service is down, agents' requests are blocked, not let through
 *  (fail-closed), so the sentence says blocked. */
export const RESTART_CONFIRM =
  "Restart Mandu? Agents you are running with mandu right now are blocked until it is back, usually a few seconds.";

/** A main service this dashboard ADOPTED (already running when it started,
 *  supervisor-defs.ts `adopted`) is not its to stop: the supervisor refuses
 *  its restart every time, so the row offers none and says why. */
export const ADOPTED_SENTENCE =
  "It was already running when this dashboard started, so this page cannot restart it.";

export const HELPER_NOTE =
  "A helper the dashboard runs for the developer view stopped unexpectedly. Your agents are not affected. The developer view has the details.";
/** The same, in a build without the developer view (§4.25ad). */
export const HELPER_NOTE_PRODUCT =
  "A helper the dashboard runs stopped unexpectedly. Your agents are not affected.";
const NO_SERVICE = "This dashboard does not run the protection service.";

/** `dev`: the build serves the developer view (absent: true); without it,
 *  no sentence points there. */
export function buildServiceSummary(services: readonly ServiceStatus[], opts: { dev?: boolean } = {}): ServiceSummary {
  const dev = opts.dev !== false;
  const main = services.find((s) => s.id === MAIN_SERVICE);
  const helperNote = services.some((s) => s.id !== MAIN_SERVICE && s.state === "crashed") ? (dev ? HELPER_NOTE : HELPER_NOTE_PRODUCT) : null;
  if (!main) {
    return {
      available: false, state: null, name: "", since: null, action: null, helperNote,
      sentence: dev ? NO_SERVICE + " The developer view lists what it does run." : NO_SERVICE,
    };
  }
  const words = WORDS[main.state] ?? WORDS.stopped;
  const running = main.state === "running";
  const adopted = running && main.adopted === true;
  const starting = main.state === "starting";
  return {
    available: true,
    state: main.state,
    name: words.name,
    sentence: adopted ? ADOPTED_SENTENCE : words.sentence,
    since: running && !adopted ? main.since : null,
    action: adopted || starting ? null : {
      label: running ? "Restart" : "Start",
      path: `control/${encodeURIComponent(main.id)}/${running ? "restart" : "start"}`,
      confirm: running ? RESTART_CONFIRM : null,
    },
    helperNote,
  };
}
