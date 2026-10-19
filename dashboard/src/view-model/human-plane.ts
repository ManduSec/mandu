/**
 * view-model/human-plane — the human plane's exposure, made visible
 * (arbiter-human-plane.md §10.1.1, dashboard.md §4.25x; P0 (E) decision 3).
 *
 * While a launch whose agent can reach the arbiter's human socket is live
 * (an UNWALLED launch: no guard deny entry and no wrap over the human
 * directory, e.g. `--mode off` or `--no-net-guard` without the bind), the
 * arbiter answers every guard and model-proxy report there as a claim, so
 * a confined session beside it gets placeholders, refused protected writes
 * and masked shell output. That stays (fail closed). This module projects
 * the arbiter's `humanPlaneStatus` answer twice, from the same facts:
 *
 *   - for the inspector's Policy panel (`HumanPlaneVM`): a chip
 *     `human plane walled | exposed | unknown` with its ⓘ drawer, in the
 *     inspector's own terms;
 *   - for the product page (`HomeExposure`): one plain notice naming the
 *     agent that causes it (as Home's row names it, with a link to its
 *     page, and its process id) and the fix, in the product's words
 *     (home-view-model.test.ts sweeps them).
 *
 * UNKNOWN IS NOT WALLED: no answer (fixtures, an older arbiter, no human
 * socket) is "unknown" on the chip and no notice on the page (the page
 * says nothing it cannot back). Pure: no I/O, no clock.
 */

import type { HumanPlaneStatus } from "../event-source/contract.js";
import type { DetailSection } from "./detail.js";
import type { HomeTextPart } from "./ask-words.js";

export interface HumanPlaneLaunchVM {
  pid: number;
  mode: string;
  posture: string;
  session: string | null;
  begunAt: number | null;
}

export interface HumanPlaneVM {
  state: "walled" | "exposed" | "unknown";
  /** When the arbiter first saw the current exposure (ms); null otherwise. */
  since: number | null;
  launches: HumanPlaneLaunchVM[];
  /** The chip's ⓘ drawer. */
  detail: DetailSection[];
}

const WHAT_IT_IS: DetailSection = {
  label: "What this is",
  items: [
    { text: "Whether the arbiter believes the reports on its human-plane socket: the session guard's process records (secret opens, protected writes, lineage) and the model proxies' records of a tool call (arbiter-human-plane.md §10.1)." },
    { text: "walled: no live launch's agent can reach that socket, so the reports there are believed. exposed: a launch with no wall (no guard deny entry and no wrap over the human directory: --mode off, or --no-net-guard without the bind) is live, so every report there is a claim, as from the data socket." },
  ],
};

const WHILE_EXPOSED: DetailSection = {
  label: "While exposed",
  items: [
    { text: "Every confined session's guard is not believed: each secret open gets the placeholder, each protected write is refused, and each shell result is masked once the session holds a raw read. Fail closed, by design; nothing is let through." },
    { text: "Each confined launcher prints a warning naming the launch below and the fix, a line when it ends, and a recap after its agent exits. The arbiter-admin stream has one event per change (config_change, humanPlane)." },
    { text: "Fix: stop the launch below, or start it again with its file guard on (not --mode off, not --no-net-guard). Its end is seen within a second, also when its launcher dies." },
  ],
};

/** The inspector's projection. `status` undefined/null: unknown. */
export function toHumanPlaneVM(status: HumanPlaneStatus | null | undefined): HumanPlaneVM {
  if (!status || typeof status !== "object" || typeof status.exposed !== "boolean" || !Array.isArray(status.launches)) {
    return {
      state: "unknown",
      since: null,
      launches: [],
      detail: [WHAT_IT_IS, { label: "Now", items: [{ text: "Unknown: the arbiter did not answer (not running, no human socket for this dashboard, or a build without the humanPlaneStatus op). Unknown is not walled." }] }],
    };
  }
  // Copied field by field (never a spread of the input).
  const launches: HumanPlaneLaunchVM[] = status.launches.slice(0, 20).map((l) => ({
    pid: Number(l.pid),
    mode: String(l.mode ?? "unknown"),
    posture: String(l.posture ?? "unknown"),
    session: typeof l.session === "string" && l.session !== "" ? l.session : null,
    begunAt: typeof l.begunAt === "number" ? l.begunAt : null,
  }));
  const exposed = status.exposed || launches.length > 0;
  if (!exposed) {
    return { state: "walled", since: null, launches: [], detail: [WHAT_IT_IS, { label: "Now", items: [{ text: "Walled: no launch with no wall is live; the guard's and the proxies' reports on the human socket are believed." }] }] };
  }
  const since = typeof status.since === "number" ? status.since : null;
  return {
    state: "exposed",
    since,
    launches,
    detail: [
      WHAT_IT_IS,
      {
        label: "Now",
        items: [
          { text: `Exposed${since !== null ? " since" : ""}`, ...(since !== null ? { ms: since } : {}) },
          ...(launches.length > 0
            ? launches.map((l) => ({ text: `${l.pid > 0 ? `pid ${l.pid}` : "an unreadable launch record (fail closed)"}${l.session ? `, session ${l.session}` : ""}: mode ${l.mode}, posture ${l.posture}, no wall` }))
            : [{ text: "The arbiter could not read its launch records, so it counts the plane as exposed (fail closed)." }]),
        ],
      },
      WHILE_EXPOSED,
    ],
  };
}

/** A cause's part: text, code, or the agent's name as a link to its page
 *  on the product page (`session`). It names the place, never an address:
 *  the page builds the link. */
export type HomeExposurePart = HomeTextPart | { kind: "link"; text: string; to: "agent"; session: string };

export interface HomeExposureCause {
  pid: number;
  session: string | null;
  /** "Claude Code, process 4242, protection off, no file guard", or, for a
   *  session Home has no row for, "process 4242, session claude-…, …":
   *  `parts` joined. */
  words: string;
  /** The same words as parts: the agent's name a link to its page, an
   *  unnamed session's id as code (dashboard.md §4.25x). */
  parts: HomeExposurePart[];
}

/** The product page's notice: one headline, a sentence, the fix, and the
 *  agents that cause it. Product vocabulary only. */
export interface HomeExposure {
  headline: string;
  sentence: string;
  /** The fix in plain words: `fixParts` joined. */
  fix: string;
  /** The same fix as parts, the launch flags as code (dashboard.md §4.25x). */
  fixParts: HomeTextPart[];
  since: number | null;
  /** One per cause, each named as Home's row names its agent. */
  causes: HomeExposureCause[];
}

/** An agent Home draws a row for (home.ts `HomeAgent`): what a cause needs
 *  to name it as that row does. */
export interface HomeExposureAgent {
  id: string;
  agent: string;
}

const MODE_WORDS: Record<string, string> = {
  off: "protection off",
  secrets: "secrets protection",
  injection: "injection protection",
  full: "full protection",
};

/** One cause in the product's words. A launch whose session Home draws a
 *  row for is named as that row names it, the name a link to its page; any
 *  other keeps its session id, as code. The process id stays either way:
 *  the launch record's own (the name is the row's, from the session's
 *  events), and what a terminal user stops. No folder: while the plane is
 *  exposed, that launch's own events are claims, which no folder is read
 *  from (`sessionCwd`), so its row has none. */
function exposureCause(l: HumanPlaneLaunchVM, agents: ReadonlyMap<string, HomeExposureAgent>): HomeExposureCause {
  const t = (text: string): HomeExposurePart => ({ kind: "text", text });
  let parts: HomeExposurePart[];
  if (l.pid <= 0) parts = [t("an agent Mandu could not name")];
  else {
    const rest = `, ${MODE_WORDS[l.mode] ?? `mode ${l.mode}`}, no file guard`;
    const row = l.session ? agents.get(l.session) : undefined;
    if (row && l.session) parts = [{ kind: "link", text: row.agent, to: "agent", session: l.session }, t(`, process ${l.pid}${rest}`)];
    else if (l.session) parts = [t(`process ${l.pid}, session `), { kind: "code", text: l.session }, t(rest)];
    else parts = [t(`process ${l.pid}${rest}`)];
  }
  return { pid: l.pid, session: l.session, words: parts.map((p) => p.text).join(""), parts };
}

/** The product page's projection: null unless exposed (unknown says
 *  nothing: the page claims nothing it cannot back). `agents`: the rows
 *  Home draws, so a cause names its agent as its row does. */
export function homeExposure(vm: HumanPlaneVM | undefined, agents: readonly HomeExposureAgent[] = []): HomeExposure | null {
  if (!vm || vm.state !== "exposed") return null;
  const byId = new Map(agents.map((a) => [a.id, a] as const));
  const causes = vm.launches.slice(0, 5).map((l) => exposureCause(l, byId));
  const one = vm.launches.length <= 1;
  const fixParts: HomeTextPart[] = [
    { kind: "text", text: `Stop ${one ? "that agent" : "those agents"}, or start ${one ? "it" : "them"} again with the file guard on (without ` },
    { kind: "code", text: "--mode off" },
    { kind: "text", text: " or " },
    { kind: "code", text: "--no-net-guard" },
    { kind: "text", text: "). Your other agents work normally again as soon as " + (one ? "it ends" : "they end") + "." },
  ];
  return {
    headline: "Another agent can reach Mandu's own controls.",
    sentence:
      `${one ? "An agent was" : `${vm.launches.length} agents were`} started without the file guard, so ${one ? "its" : "their"} programs can reach Mandu's own controls. ` +
      "Until " + (one ? "it stops" : "they stop") + ", Mandu does not trust the reports of your other agents' file guards: those agents get placeholders instead of secret files, " +
      "their changes to protected files are blocked, and their command output is masked. Your secrets stay protected; some work in those agents may fail.",
    fix: fixParts.map((p) => p.text).join(""),
    fixParts,
    since: vm.since,
    causes,
  };
}
