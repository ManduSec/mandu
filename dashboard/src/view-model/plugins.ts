/**
 * view-model/plugins — the product page's Plugins page (dashboard.md
 * §4.25aj): where Mandu is attached to an agent it does not run, as a
 * plugin inside the agent's own host, beside the resident Mandu service
 * (`mandu serve`; docs/design/agents/openclaw-plugin.md). Mandu-new (no
 * reference origin).
 *
 * One card per attached session, under its host kind: the agent and the
 * session, whether Mandu's model proxy for it answers, whether the
 * protection service holds its registration, the secret files registered
 * for it, since when, the posture name and its sentence from the shared
 * copy (confinement-posture.ts), the cost while it runs (Home's exposure
 * notice in the card's words, with the same fix), and links to its session
 * page and its sessions on History. A known host with nothing attached
 * shows how to attach it; a stopped service says so and how to start it.
 *
 * Built from facts the server gathered (server/plugin-routes.ts: the
 * declared file, the pool's records and port files, each proxy's identity,
 * the arbiter's `humanPlaneStatus`), so this module is pure: no I/O, no
 * clock. Product vocabulary only (plugins.test.ts sweeps it), and never a
 * port, a path or a value: the route is open to a signed-out reader.
 */

import { ATTACHMENT_COVERAGE, postureSentence, resolvePosture, type AttachmentGap, type ConfinementPosture } from "../confinement-posture.js";
import { ROUTE_FIX_PARTS } from "./attachment-route.js";
import type { HomeTextPart } from "./ask-words.js";
import { PLUGIN_EXPOSURE_FIX } from "./human-plane.js";

// ── The host kinds the product knows ────────────────────────────────────────

/** A host Mandu attaches to as a plugin. */
export interface PluginHost {
  /** The attachment kind (confinement-posture.ts AttachmentGap, the
   *  declared file's `kind`). */
  kind: AttachmentGap;
  /** The host's name ("OpenClaw"). */
  name: string;
  /** The card group's title ("Mandu in OpenClaw"). */
  title: string;
  /** What Mandu covers there and what not, and the confined form. */
  covers: readonly HomeTextPart[];
  /** How to attach it once the service runs (the service's own set-up
   *  comes first while it does not). */
  attach: readonly string[];
  /** The History search that finds its sessions (its agent's name). */
  historyQuery: string;
}

/** The command that sets up the resident service, before any host. */
export const SERVICE_INSTALL = "mandu serve install";
/** The command that starts an installed service. */
export const SERVICE_START = "mandu serve start";

/**
 * The hosts the page lists, in order. Today only OpenClaw.
 *
 * OpenShell goes here, after OpenClaw, once it has an attachment kind of its
 * own: its gap in confinement-posture.ts (`AttachmentGap`, with its coverage
 * row and sentence), its kind in the attachment contract's `DECLARED_KINDS`,
 * its session prefix, and its `mandu <host> install`. Until then it is not
 * listed, so the page never offers a set-up that does not exist.
 */
export const PLUGIN_HOSTS: readonly PluginHost[] = [
  {
    kind: "openclaw-plugin",
    name: "OpenClaw",
    title: "Mandu in OpenClaw",
    covers: [
      { kind: "text", text: "Mandu in OpenClaw keeps your secrets out of what the AI sees. Files, programs and their network are not covered here; for that, run " },
      { kind: "code", text: "mandu openclaw gateway" },
      { kind: "text", text: "." },
    ],
    attach: ["mandu openclaw install", "openclaw gateway restart"],
    historyQuery: "OpenClaw",
  },
];

// ── The facts (server/plugin-routes.ts gathers them) ────────────────────────

/** One attachment session as the server found it. */
export interface PluginSessionFacts {
  /** `openclaw:<agent>`. */
  session: string;
  kind: AttachmentGap;
  /** The host's agent id (`main`). */
  agent: string;
  /** In the declared file the pool reads (`mandu openclaw install` adds it). */
  declared: boolean;
  /** A trusted port file names a proxy that answers as this session's. */
  answering: boolean;
  /** The pool's own state for it, when this dashboard runs the pool
   *  (attachment-pool.ts PoolEntry.state); null otherwise. */
  poolState: "registering" | "starting" | "serving" | "backoff" | "stopping" | null;
  /** The service's last secret registration for it (null: none yet). */
  secrets: { found: number; registered: number; at: string } | null;
  /** Whether the host's config still routes the session through Mandu: the
   *  service's route check (openclaw-plugin.md §3.6), as the arbiter's
   *  NEWEST BELIEVED posture record of the attachment says it
   *  (session-health.ts `attachmentRoute`; a claim never counts). `lost`
   *  names each problem the check found. Null: no believed record yet. */
  route?: PluginRoute | null;
  /** The posture that record decided (a lost model route is `gated` with
   *  the gap `model-route-lost`); null: none recorded, and the kind's own
   *  coverage decides. */
  recorded?: { posture: ConfinementPosture; gap: string | null } | null;
}

/** The route check's last word on a session. */
export type PluginRoute = { state: "ok" } | { state: "lost"; problems: string[]; since: number | null };

/** A route problem as the page may show it (the page is open to a
 *  signed-out reader): the check's sentence without the service proxy's
 *  loopback address and with a file named by its name only. A path starts a
 *  word (`/home/…`, `~/…`); a model reference (`openrouter/a/b`, the model
 *  fence's words) does not, and is kept. Pure. */
export function routeProblemWords(detail: string): string {
  return detail
    .replace(/\s*\(https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?[^)]*\)/g, "")
    .replace(/https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?\S*/g, "a local address")
    .replace(/(^|[\s"'(=])(?:~|\/)[^\s,;:()]*\/([^\s,;:()/]+)/g, "$1$2");
}

/** Everything the page is built from. */
export interface PluginFacts {
  /** The service's proxy pool runs (in this dashboard, or a live pid in its
   *  record). */
  serviceRunning: boolean;
  sessions: PluginSessionFacts[];
  /** The sessions the protection service holds an attachment for, with
   *  when it began (ms); null when it did not answer. */
  live: ReadonlyMap<string, number | null> | null;
  /** The sessions that have a record (their session page shows something). */
  known: ReadonlySet<string>;
}

// ── The view model ──────────────────────────────────────────────────────────

export type PluginTone = "ok" | "warn" | "bad";

/** One fact line of a card: a label and its words. */
export interface PluginFactVM {
  label: string;
  parts: HomeTextPart[];
  tone: PluginTone | "plain";
}

/** The card's state. */
export type PluginCardState =
  | "attached" // the proxy answers and the protection service holds it
  | "starting" // the service is starting its proxy
  | "lapsed" // the proxy answers but its registration lapsed
  | "down" // no proxy answers
  | "unknown" // the protection service did not answer
  | "detaching" // no longer declared; its hold runs out
  | "stopped" // the service is not running
  | "route-lost"; // the host stopped sending its model calls through Mandu

export interface PluginCardVM {
  session: string;
  agent: string;
  state: PluginCardState;
  tone: PluginTone;
  /** "Attached", "Not answering", … */
  headline: string;
  /** What that means, with what to do. */
  parts: HomeTextPart[];
  facts: PluginFactVM[];
  /** When the protection service first held this attachment (ms); null. */
  since: number | null;
  /** The posture the protection service decides for it, its name and the
   *  shared sentence. */
  posture: { name: string; sentence: string };
  /** The cost while it runs, with the fix; null while it is not held. */
  notice: { headline: string; parts: HomeTextPart[] } | null;
  /** Its session page (the session id, when it has a record) and the
   *  History search for its host's sessions. */
  links: { session: string | null; historyQuery: string };
}

export interface PluginHostVM {
  kind: AttachmentGap;
  name: string;
  title: string;
  covers: HomeTextPart[];
  cards: PluginCardVM[];
  /** How to attach it, while nothing is attached; null otherwise. */
  setup: { sentence: string; commands: string[] } | null;
}

export interface PluginsVM {
  /** The page's first line. */
  intro: string;
  /** Plain (no colour, no mark) while it is not running and nothing is
   *  attached: nothing of the person's depends on it then. */
  service: { running: boolean; tone: PluginTone | "plain"; headline: string; parts: HomeTextPart[] };
  hosts: PluginHostVM[];
}

// ── The build ───────────────────────────────────────────────────────────────

const t = (text: string): HomeTextPart => ({ kind: "text", text });
const c = (text: string): HomeTextPart => ({ kind: "code", text });
/** A command the line asks you to run: the page gives it a Copy
 *  (dashboard.md §4.25b). */
const run = (text: string): HomeTextPart => ({ kind: "code", text, run: true });

const INTRO = "Where Mandu is attached to an agent it does not start itself: a plugin inside the agent's own app, beside the Mandu service.";

function n(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

/** The service's line. `attached` counts the attached agents, `cards` every
 *  card drawn (a detached one too). */
function serviceVM(running: boolean, attached: number, cards: number): PluginsVM["service"] {
  if (running) {
    return {
      running,
      tone: "ok",
      headline: "The Mandu service is running.",
      parts: [t(attached > 0 ? `It keeps Mandu attached to ${n(attached, "agent", "agents")} below.` : "Nothing is attached to it yet.")],
    };
  }
  if (cards === 0) {
    // Nothing depends on it: a fact, not a warning (§4.25aj, 2026-10-26).
    // The host's set-up below starts with `mandu serve install`.
    return {
      running,
      tone: "plain",
      headline: "The Mandu service is not running.",
      parts: [t("You need it only to attach Mandu to an agent as a plugin; the steps are below.")],
    };
  }
  return {
    running,
    tone: "warn",
    headline: "The Mandu service is not running.",
    parts: [
      t("Plugins need it: it runs Mandu's model proxy for each attached agent. Start it with "),
      run(SERVICE_START),
      t(", or set it up the first time with "),
      run(SERVICE_INSTALL),
      t("."),
    ],
  };
}

/** The card's state and its words. */
function stateOf(f: PluginSessionFacts, running: boolean, registered: boolean | null, host: PluginHost): Pick<PluginCardVM, "state" | "tone" | "headline" | "parts"> {
  if (!running) {
    return {
      state: "stopped", tone: "bad", headline: "Not running",
      parts: [
        t(`${host.name}'s agent ${f.agent} is set up to send its AI requests through Mandu, and they fail until the Mandu service runs again (they never go out unmasked). Start it with `),
        c(SERVICE_START), t("."),
      ],
    };
  }
  if (!f.declared) {
    return {
      state: "detaching", tone: "warn", headline: "Detached",
      parts: [t("It is no longer set up. Mandu lets go of it within a minute.")],
    };
  }
  if (f.route?.state === "lost") {
    // Home's route card says the same (view-model/attachment-route.ts): its
    // fix, word for word.
    const problems = f.route.problems.map(routeProblemWords);
    return {
      state: "route-lost", tone: "bad", headline: "Not going through Mandu",
      parts: [
        t(`${host.name}'s config was changed: ${problems.length > 0 ? problems.join("; ") : "it no longer routes this agent through Mandu"}. ` +
          "A Gateway already running keeps the config it loaded until it restarts; once it runs with this one, the AI can read your secrets as they are. "),
        ...ROUTE_FIX_PARTS,
      ],
    };
  }
  if (f.answering && registered === true) {
    return {
      state: "attached", tone: "ok", headline: "Attached",
      parts: [t(`Every AI request of ${host.name}'s agent ${f.agent} goes through Mandu, which masks your secrets in it.`)],
    };
  }
  if (f.answering && registered === false) {
    return {
      state: "lapsed", tone: "bad", headline: "Not registered",
      parts: [t("Mandu's registration of it lapsed. The service stops its proxy and registers it again within seconds; until then its AI requests fail rather than go out unmasked.")],
    };
  }
  if (f.answering) {
    return {
      state: "unknown", tone: "warn", headline: "Not checked",
      parts: [t("Mandu's proxy answers, but the protection service did not, so whether it holds this agent is not known.")],
    };
  }
  if (f.poolState === "registering" || f.poolState === "starting") {
    return {
      state: "starting", tone: "warn", headline: "Starting",
      parts: [t("The Mandu service is starting its proxy. Until it answers, the agent's AI requests fail rather than go out unmasked.")],
    };
  }
  return {
    state: "down", tone: "bad", headline: "Not answering",
    parts: [
      t("Mandu's proxy for this agent does not answer, so its AI requests fail until it does (they never go out unmasked). The service restarts it; "),
      c("mandu serve status"), t(" says why."),
    ],
  };
}

function cardVM(f: PluginSessionFacts, facts: PluginFacts, host: PluginHost): PluginCardVM {
  const registered = facts.live === null ? null : facts.live.has(f.session);
  const since = facts.live?.get(f.session) ?? null;
  const st = stateOf(f, facts.serviceRunning, registered, host);
  // The arbiter's newest believed record decides (a lost model route is
  // `model-route-lost`); before any, the kind's own coverage.
  const decided = f.recorded ? { posture: f.recorded.posture, ...(f.recorded.gap !== null ? { gap: f.recorded.gap } : {}) } : resolvePosture(ATTACHMENT_COVERAGE[f.kind]);
  const lines: PluginFactVM[] = [
    { label: "Agent", parts: [t(`${host.name}'s agent `), c(f.agent), t(", session "), c(f.session)], tone: "plain" },
    {
      label: "AI requests",
      parts: [t(f.answering ? "Mandu's proxy answers." : "Mandu's proxy does not answer.")],
      tone: f.answering ? "ok" : "bad",
    },
    {
      label: "Registered",
      parts: [t(registered === true ? "Yes, Mandu holds it." : registered === false ? "No." : "Not known: the protection service did not answer.")],
      tone: registered === true ? "ok" : registered === false ? "bad" : "warn",
    },
    {
      label: "Secret files",
      parts: [t(f.secrets === null
        ? "Not registered yet."
        : `${n(f.secrets.registered, "secret file", "secret files")} registered${f.secrets.found > f.secrets.registered ? ` of ${f.secrets.found} found` : ""}.`)],
      tone: f.secrets === null ? "warn" : "plain",
    },
  ];
  return {
    session: f.session,
    agent: f.agent,
    ...st,
    facts: lines,
    since: registered === true ? since : null,
    posture: { name: decided.posture, sentence: postureSentence(decided) },
    // Held: the cost is real for as long as the protection service holds it
    // (a detached one too, until its hold runs out).
    notice: registered === true
      ? {
        headline: "While this runs, your other agents lose a check.",
        parts: [
          t(`${host.name}'s programs run outside any file guard and can reach Mandu's own controls, so Mandu does not trust the file guard of the agents you start with it: their secret files open masked, their changes to protected files are blocked, and their command output is masked. `),
          ...PLUGIN_EXPOSURE_FIX,
        ],
      }
      : null,
    links: { session: facts.known.has(f.session) ? f.session : null, historyQuery: host.historyQuery },
  };
}

/** The Plugins page. Pure. */
export function pluginsPage(facts: PluginFacts): PluginsVM {
  const hosts = PLUGIN_HOSTS.map((host): PluginHostVM => {
    // Declared first (in the file's order), then any the protection service
    // still holds without a declaration (its hold not yet run out).
    const mine = facts.sessions.filter((s) => s.kind === host.kind);
    const cards = mine.map((s) => cardVM(s, facts, host));
    return {
      kind: host.kind,
      name: host.name,
      title: host.title,
      covers: [...host.covers],
      cards,
      setup: cards.length > 0 ? null : {
        sentence: facts.serviceRunning
          ? `Not attached. To attach ${host.name}, run:`
          : `Not attached. To attach ${host.name}, set up the Mandu service, then attach it:`,
        commands: facts.serviceRunning ? [...host.attach] : [SERVICE_INSTALL, ...host.attach],
      },
    };
  });
  const attached = hosts.reduce((k, h) => k + h.cards.filter((x) => x.state !== "detaching").length, 0);
  const cards = hosts.reduce((k, h) => k + h.cards.length, 0);
  return { intro: INTRO, service: serviceVM(facts.serviceRunning, attached, cards), hosts };
}
