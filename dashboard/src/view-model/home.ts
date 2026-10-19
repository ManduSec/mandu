/**
 * view-model/home — the PRODUCT home projection (dashboard.md §4.25).
 *
 * The end-user dashboard served at `/` asks two questions — "is this
 * protecting me?" and "what needs my OK?" — and this module answers both from
 * the SAME facts the developer inspector renders: the session list, each live
 * session's lineage stats + invariant verdict, the policy-panel VM (posture +
 * the approval queue) and the configured protection mode. Pure: no I/O, no
 * clock (the route injects `nowMs`), fully unit-tested.
 *
 * VOCABULARY (the product's eight words — home-copy.test.ts pins it): the copy
 * here says protected / masked / blocked / waiting / allowed / secret / agent /
 * rule and never symbol, egress, invariant, AgentView, HumanView, T-LLM or a
 * `$MDU:` token. Every ask is rendered as a plain sentence built from the
 * queue row's family, never as its raw key.
 */

import { type SessionRef } from "../event-source/contract.js";
import { systemLogKind } from "../event-source/registry.js";
import { type PolicyPanelVM, type QueueRowVM } from "./policy-panel.js";
import { type SessionFlowStats } from "./lineage.js";
import { type Mode } from "../config-axes.js";
import { type SessionHealth } from "../session-health.js";
import { ISSUES_URL, generationOf, rangeWords } from "../agent-versions.js";
import { manduPath } from "../generated/mandu-paths.js";
import { homeExposure, type HomeExposure } from "./human-plane.js";
import { SYM_RE } from "./held-tokens.js";
import { describeAsk, holderLeftParts, holderLeftWords, holderSourceWords, type HolderSourceWords, type HomeAskFamily, type HomeTextPart } from "./ask-words.js";

/** The policy file as the page names it: the path table's `policy` with the
 *  home spelled `~` and no MANDU_HOME override (on-disk-layout.md §5), so the copy
 *  follows the table when the layout moves. */
export const POLICY_FILE_WORDS = manduPath("policy", {}, "~");

/** Per-session facts the route derives from the session's events. */
export interface HomeSessionFacts {
  stats: SessionFlowStats;
  /** The session's secrets as its page's tiles count them, each by its Your
   *  secrets card's first line (agent-page.ts `pageSecrets`): `masked`
   *  before the AI saw it, or read by the AI `early`, before it was marked.
   *  Absent: not computed, so nothing is claimed. */
  secrets?: SecretCounts;
  /** Non-secret items masked before the AI saw them, only where the
   *  session's level masks untrusted text (agent-page.ts `untrustedMasked`,
   *  the page's "untrusted items" tile). Absent: none claimed. */
  untrusted?: number;
  /** The steps Mandu blocked (a command, a file, a send) and the sends that
   *  left with a real value filled in, counted over the story the session's
   *  page tells (agent-page.ts `storyCounts`), so a row and its page agree. */
  blocked: number;
  sent: number;
  holds: boolean;
  violations: number;
  /** The agent's working directory, when the trace names one. */
  cwd: string | null;
  /** The launcher recorded the agent's exit and no agent activity came after
   *  it (agent-page.ts `sessionExited`, the rule the session's page uses):
   *  the row is not running, however recent its last event. */
  exited?: boolean;
  /** When the AI first read each item as it was, before it was masked, by
   *  its token's base (lineage `readFirstByBase` over the trace's
   *  `maskedLater`): what a waiting card about one of them must not call
   *  never read (dashboard.md §4.34). Absent: not computed, none known. */
  readFirst?: ReadonlyMap<string, string>;
  /** The same, by the file the item came from (lineage `readFirstByFile`):
   *  what a waiting card about a program reading that file must not call
   *  unseen by the AI (§4.34). Absent: not computed, none known. */
  readFirstFiles?: ReadonlyMap<string, string>;
}

export type { HomeTextPart, HomeAskFamily, AskWords } from "./ask-words.js";
export { describeAsk, binaryOfSubject, programOfSubject } from "./ask-words.js";

export interface HomeAsk {
  id: string;
  family: HomeAskFamily;
  /** "Claude Code wants to send text from notes.md to evil.example" as parts. */
  sentence: HomeTextPart[];
  /** Why Mandu stopped here — one or two sentences. */
  why: string;
  /** What the AI has now, before an answer; the subject is the AI. */
  aiNow: string;
  /** What happens if the person clicks Allow once or Always allow; the
   *  subject is the AI ("The AI …", "The AI's program …"). */
  ifAllowed: string;
  /** The three cells as parts, each name as code (ask-words.ts `AskWords`,
   *  dashboard.md §4.25u): the same words as the strings. */
  whyParts: HomeTextPart[];
  aiNowParts: HomeTextPart[];
  ifAllowedParts: HomeTextPart[];
  /** A held message under a locked administrator's `ask` row (plan 15 §12,
   *  2026-10-04): why it is answered for this message only; the page then
   *  offers no session answer. Absent otherwise. */
  onlyThisMessage?: string;
  askedAt: number;
  count: number;
  /** A held open or change (`open:`, `trust:`, `write:`, `heldNow`): whether
   *  the program is still waiting for the answer. Present only for those;
   *  their `count` counts the guard's half-second re-asks, so the page
   *  does not show it. */
  held?: boolean;
  /** The session that asked last has ended (a recorded exit, or no event
   *  for the running window): nothing waits on the answer now, and it
   *  counts the next time an agent asks. Absent: running, or not known. */
  askerEnded?: true;
  /** Where the session that asked last works, its facts' `cwd`, so two
   *  agents' questions tell apart ("from Claude Code in ~/projects/shop",
   *  dashboard.md §4.25u *A question says which session asked*). Absent
   *  when not known (the trace names no folder, or the session is not one
   *  Home models); the three are present together. `askerAgent` is that
   *  session's agent, as the sentence names it; `askerSessions` how many
   *  sessions raised it. */
  askerCwd?: string;
  askerAgent?: string;
  askerSessions?: number;
  /** Sessions that raised it (ids), most recent last. */
  sessions: string[];
  /** Which agents raised it, plain names, deduplicated. */
  agents: string[];
  actions: QueueRowVM["actions"];
  mintable: QueueRowVM["mintable"];
  /** A program's send of the secret files it holds (confidentiality plan 13
   *  §5.4): every file, where it may go, whether it is in the way, and one
   *  *Always* per file in the way (`POST …/always-source {path}`). Absent
   *  on any other question. */
  sources?: HolderSourceWords[];
  /** Once some file may go and some may not (after an *Always*): which
   *  are left (`holderLeftWords`). Absent otherwise. */
  sourcesLeft?: string;
  /** `sourcesLeft` as parts, the place and each file as code
   *  (`holderLeftParts`). Absent with it. */
  sourcesLeftParts?: HomeTextPart[];
}

export interface HomeAnswered {
  id: string;
  sentence: HomeTextPart[];
  /** A held message's answer (`prompt:` rows) says what went to the AI:
   *  `sent` (as written, that message), `sent-session`, `masked` (with the
   *  part masked, or the message cancelled: the row does not tell them
   *  apart) or `masked-session` (dashboard.md §4.34 "A held message's
   *  answer"). */
  outcome: "allowed" | "blocked" | "allowed-once" | "allowed-once-used" | "sent" | "sent-session" | "masked" | "masked-session" | "without" | "without-used";
  decidedAt: number | null;
  /** Sessions that raised it (ids), most recent last, as `HomeAsk`'s: the
   *  row links the last, where it was asked (dashboard.md §4.25h). */
  sessions: string[];
  /** The one-click reversal the row offers (the same verdict routes). */
  actions: QueueRowVM["actions"];
  /** The answer applies to nothing any more, and why (dashboard.md §4.34
   *  "Answers that no longer apply"); `actions` is then empty. */
  staleNote?: string;
}

export type HomeAgentState = "running" | "waiting" | "idle";

/** A session's secrets as its page's tiles count them (secret-story.ts
 *  `SecretsStory.counts`). */
export interface SecretCounts {
  masked: number;
  early: number;
}

export interface HomeAgent {
  id: string;
  /** Plain agent name: "Claude Code", "Codex CLI", … */
  agent: string;
  /** The session's label (its first prompt), trimmed for one line. */
  title: string | null;
  cwd: string | null;
  startedAt: string | null;
  lastAt: string | null;
  state: HomeAgentState;
  stats: SessionFlowStats;
  /** Its secrets and untrusted items as its page's tiles count them
   *  ("1 secret masked, 1 secret read before it was marked"). */
  secrets: SecretCounts;
  untrusted: number;
  /** Steps Mandu blocked, the session page's tile ("N actions blocked"). */
  blocked: number;
  /** Sends that left with a real value filled in, the session page's tile
   *  ("N sends with a real value filled in"). */
  sent: number;
  holds: boolean;
  /** Asks waiting that this session raised. */
  waiting: number;
  /** One plain sentence when the agent is outside the versions Mandu was
   *  tested with, or advertised tools Mandu does not know (supported-agents.md);
   *  null otherwise. */
  notice: string | null;
  /** The agent's support status when it is a preview (Goose, OpenCode 1 and 2;
   *  supported-agents.md §2.0): the page's "Preview" tag opens it. null for
   *  a supported agent. */
  preview: AgentPreview | null;
}

/** A preview agent's tag: what it means, and where to report a problem. */
export interface AgentPreview {
  /** The tested line's label: "Goose", "OpenCode 2". */
  label: string;
  /** "Goose support is a preview: Mandu was tested less with it than with
   *  Claude Code and Codex." */
  sentence: string;
  /** Where to report a problem (the launcher's notice names the same). */
  issues: string;
}

export type HomeVerdict =
  | "protected" // masking on, untrusted items masked, nothing waiting
  | "quiet" // masking on, no untrusted data reached any agent yet
  | "secrets-only" // masking off, secrets guarded (the built-in default level)
  | "waiting" // protection holds, but asks or rule changes wait for the person
  | "failed" // an invariant violation in a session in the window
  | "off" // both axes off
  | "unknown"; // no arbiter connection — nothing can be claimed

/** A place the hero's sentence sends the person (dashboard.md §4.25, *The
 *  hero links where it points*): Settings, or the detailed trace of the one
 *  session where protection failed (`session`; null when several did, so
 *  the trace's session list), or, in a build without the developer view
 *  (§4.25ad), that one session's agent page. It names the place, never an
 *  address: the page builds the link. */
export type HomeHeroLink =
  | { kind: "link"; text: string; to: "settings" }
  | { kind: "link"; text: string; to: "trace"; session: string | null }
  | { kind: "link"; text: string; to: "agent"; session: string };

export type HomeHeroPart = HomeTextPart | HomeHeroLink;

export interface HomeVM {
  verdict: HomeVerdict;
  headline: string;
  /** The hero's sentence in plain words: `sentenceParts` joined. */
  sentence: string;
  /** The same sentence as parts, the place it names a link part. */
  sentenceParts: HomeHeroPart[];
  protection: {
    /** The level running now, from the arbiter's posture; "unknown" without one. */
    level: Mode | "unknown";
    /** The level saved in config (applies when the service starts). */
    configured: Mode;
    connected: boolean;
  };
  /** Counts over the live sessions in the window, each the sum of the
   *  sessions' `HomeSessionFacts`, so the hero adds up the rows and the rows
   *  their pages' tiles (§4.25): `secretsMasked` / `secretsEarly`, secrets
   *  masked before the AI saw them / read before they were marked;
   *  `untrusted`, non-secret items masked where the level masks them;
   *  `blocked`, steps Mandu blocked; `sent`, sends with a real value filled
   *  in. `masked` is the lineage's masked items, which only the frozen
   *  levels' verdict sentence reads; it is never drawn as a count.
   *  `sessions`: the live sessions active in the window; `counted`: those
   *  whose facts the counts add up. Fewer when the route's cap left some out
   *  (it models the newest, and every one where protection failed) or one
   *  could not be read: the counts are then a floor, and the page says so. */
  window: {
    hours: number;
    sessions: number;
    counted: number;
    masked: number;
    secretsMasked: number;
    secretsEarly: number;
    untrusted: number;
    blocked: number;
    sent: number;
    waiting: number;
  };
  waitingKnown: boolean;
  waiting: HomeAsk[];
  /** Rule changes waiting for the person's answer (the pending policy
   *  proposals Approvals lists): only their number, which the hero counts
   *  as the Approvals badge does (§4.25, the verdict ladder). */
  ruleChangesWaiting: number;
  /** The newest ANSWERED_PAGE answers (answeredPage); `answeredTotal`:
   *  every answer, so Approvals says how many more Show more reaches
   *  (dashboard.md §4.25 *Past the newest 20*). */
  answered: HomeAnswered[];
  answeredTotal: number;
  agents: HomeAgent[];
  history: { total: number };
  /** The first-run setup card (§4.25, "First-run card"): present only while
   *  no live session has ever been recorded; null once one exists. */
  firstRun: HomeFirstRun | null;
  /** Another agent, started without the file guard, can reach Mandu's own
   *  controls, so the other agents' file guards are not trusted until it
   *  stops (arbiter-human-plane.md §10.1.1, dashboard.md §4.25x); null when
   *  not, or not known. */
  exposure: HomeExposure | null;
  /** The Rules page's "Built-in protections" list, for the level running
   *  now (dashboard.md §4.25z): never a claim the mode does not make. */
  builtIn: HomeBuiltIn;
}

/** The Rules page's built-in protections: what the running mode does without
 *  a rule of the person's. */
export interface HomeBuiltIn {
  /** The muted note beside the heading ("always on in the Secrets mode"). */
  note: string;
  items: string[];
}

/** One step of the first-run card. */
export interface HomeFirstRunStep {
  id: "start" | "secrets" | "check";
  title: string;
  /** The step's sentence in plain words: `parts` joined. */
  text: string;
  /** The same sentence as parts, each command, file, variable pattern and
   *  policy key a code part (dashboard.md §4.25 "First-run card"). */
  parts: HomeTextPart[];
  /** Commands to type in a terminal, each with what it does. */
  commands: Array<{ command: string; does: string }>;
  /** A page of this dashboard the step points at. */
  link: { page: "rules"; text: string } | null;
}

export interface HomeFirstRun {
  /** The mode the card describes: the running one, else the saved one. */
  mode: Mode;
  /** True when Mandu is not running, so `mode` is the saved one. */
  saved: boolean;
  headline: string;
  /** What Mandu does in `mode`, in plain words. */
  protects: string;
  steps: HomeFirstRunStep[];
}

export const AGENT_NAMES: Record<NonNullable<SessionRef["agent"]>, string> = {
  claude: "Claude Code",
  codex: "Codex CLI",
  openclaw: "OpenClaw",
  opencode: "OpenCode",
  goose: "Goose",
};

/**
 * The agent's name as the product page writes it: its kind's name, and the
 * generation when the session's own version check (for that same agent)
 * belongs to a later tested line, so an OpenCode 2.x session reads
 * "OpenCode 2", the name its Preview tag, the launch line and `mandu doctor`
 * use (2026-10-09: Home read "OpenCode" above a tag saying "OpenCode 2
 * support is a preview"). No check, an unreadable version or the first
 * line: the kind's name alone. No kind: "The agent".
 */
export function agentName(kind: SessionRef["agent"], health?: Pick<SessionHealth, "agentVersion"> | null): string {
  if (!kind) return "The agent";
  const v = health?.agentVersion;
  const generation = v && v.agent === kind ? generationOf(kind, v.version) : null;
  return generation === null ? AGENT_NAMES[kind] : `${AGENT_NAMES[kind]} ${generation}`;
}

/** What names a session's agent: its kind and its health's version check. */
export type AgentOf = Pick<SessionRef, "agent" | "health">;

/** The mode's name as the top bar shows it. */
const MODE_WORD: Record<Mode, string> = { secrets: "Secrets", off: "Off", injection: "Injection", full: "Full" };

/** What Mandu does in each mode, for someone who has not run it yet. The
 *  `secrets` sentence must say that untrusted content is NOT masked
 *  (CONTRIBUTING.md, protection modes): it is the default, and the one people get.
 *  A secret leaves "only where a rule or your OK allows", never "unless you
 *  allow it": a rule (an administrator's too) sends with no question. */
const MODE_PROTECTS: Record<Mode, string> = {
  secrets:
    "Mandu keeps your secrets away from the AI: keys, credential files and the files you mark as secret reach it only masked, " +
    "and they leave this computer only where a rule or your OK allows. Untrusted content, such as a web page or a file from outside, " +
    "is not masked in this mode: the AI reads it as-is.",
  off:
    "Protection is off, so Mandu only watches: your secrets are not guarded and untrusted content is not masked. " +
    "Turn it on in Settings › Protection.",
  injection:
    "Mandu masks untrusted content, such as a web page or a file from outside, before the AI reads it. " +
    "Your secrets are not guarded in this mode.",
  full:
    "Mandu keeps your secrets away from the AI (they reach it only masked and leave this computer only where a rule or your OK allows), " +
    "and it masks untrusted content, such as a web page or a file from outside, before the AI reads it.",
};

/**
 * The Rules page's built-in protections for a level. The masking sentence
 * appears only where the integrity axis is on (`injection`, `full`): in the
 * default `secrets` mode untrusted text is NOT masked, and the list says so
 * (CONTRIBUTING.md, protection modes; 2026-10-03 the static list claimed it in
 * every mode). Pure.
 */
export function builtInProtections(level: Mode | "unknown"): HomeBuiltIn {
  const masked = [
    "Untrusted content is masked before the AI reads it.",
    "Masked text used as a command needs your OK.",
    "Masked text sent to a new place needs your OK.",
  ];
  const secretsMasked = "Keys and secret files reach the AI masked, unless a rule lets the AI read them.";
  // Never "not sent anywhere without your OK": a rule sends with no
  // question asked (Home's sentence, below; dashboard.md §4.25d).
  const secretsKept = "Keys and secret files leave this computer only where a rule or your OK allows.";
  switch (level) {
    case "full":
      return { note: "always on in the Full mode", items: [...masked, secretsMasked, secretsKept] };
    case "injection":
      return { note: "always on in the Injection mode", items: [...masked, "Your secrets are not guarded in this mode."] };
    case "secrets":
      return {
        note: "always on in the Secrets mode",
        items: [secretsMasked, secretsKept, "Untrusted content is not masked in this mode: the AI reads it as-is."],
      };
    case "off":
      return { note: "protection is off", items: ["Mandu only watches: nothing is masked, and your secrets are not guarded. Turn it on in Settings."] };
    default:
      return { note: "not connected", items: ["The protection service is not reachable, so Mandu cannot say what is on."] };
  }
}

/** One of the card's own sentences, written with each command, file and
 *  policy key between backticks: its plain words and its parts, the marked
 *  spans as code. Only this module's own literals come through here. */
function ownSentence(marked: string): { text: string; parts: HomeTextPart[] } {
  const parts = marked.split("`")
    .map((text, i): HomeTextPart => ({ kind: i % 2 ? "code" : "text", text }))
    .filter((p) => p.text !== "");
  return { text: parts.map((p) => p.text).join(""), parts };
}

/**
 * The first-run setup card: what Mandu does in the mode it runs (or will
 * start) in, how to start an agent, how to mark a secret, and where
 * `mandu doctor` is. Pure copy over the level; the route decides WHEN (no
 * live session on record yet).
 */
export function buildFirstRun(level: Mode | "unknown", configured: Mode): HomeFirstRun {
  const saved = level === "unknown";
  const mode: Mode = saved ? configured : level;
  const lead = saved
    ? `Mandu starts with your first agent, in the ${MODE_WORD[mode]} mode. `
    : `Mandu is running in the ${MODE_WORD[mode]} mode. `;
  const kinds = Object.keys(AGENT_NAMES) as Array<keyof typeof AGENT_NAMES>;
  return {
    mode,
    saved,
    headline: "Get started with Mandu",
    protects: lead + MODE_PROTECTS[mode],
    steps: [
      {
        id: "start",
        title: "Start your agent through Mandu",
        ...ownSentence("Put `mandu` in front of the command that starts your agent. The first run starts everything Mandu needs, and the agent shows up here."),
        commands: kinds.map((k) => ({ command: `mandu ${k}`, does: AGENT_NAMES[k] })),
        link: null,
      },
      {
        id: "secrets",
        title: "Mark what is secret",
        ...ownSentence(
          "Mandu finds the usual credential files (such as `~/.aws/credentials`, `.env` files and ssh keys) and variables named like " +
          "`*_TOKEN` or `*_API_KEY` by itself. To mark another file or folder, choose \"No AI\" for it under " +
          "Rules › Files and folders, or add it under `paths:` in `" + POLICY_FILE_WORDS + "`.",
        ),
        commands: [
          { command: "mandu doctor --secrets", does: "lists the files and variables a launch would keep secret, and what it would leave as-is" },
          { command: "mandu why ~/.pgpass", does: "says why one file is or is not a secret, and where it may be sent" },
        ],
        link: { page: "rules", text: "Open Files and folders" },
      },
      {
        id: "check",
        title: "Check this computer",
        ...ownSentence("Run `mandu doctor` in a terminal at any time. It says in plain words what Mandu needs, whether it is running, and what it enforces here."),
        commands: [{ command: "mandu doctor", does: "what Mandu needs and what it enforces on this computer" }],
        link: null,
      },
    ],
  };
}

const EMPTY_STATS: SessionFlowStats = { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 };

/**
 * The plain notice under an agent row: its version against the tested range
 * and the tools Mandu does not know (session-health.ts reads both off the
 * session's events). `masking` = untrusted content is masked at this level
 * (injection / full): only then is an unknown tool's output masked in full;
 * at the secrets level it is not masked, like every other untrusted item.
 */
export function agentNotice(health: SessionHealth | undefined, masking: boolean): string | null {
  if (!health) return null;
  const v = health.agentVersion;
  const unknown = health.unknownTools;
  const cost = masking
    ? "Tools it has that Mandu does not know yet have their output masked in full, so it may work less well."
    : "It may not work as expected with Mandu.";
  if (v && v.verdict === "newer") {
    return `${v.name} ${v.version} is newer than the versions Mandu was tested with (${rangeWords(v)}). ${cost}`;
  }
  if (v && v.verdict === "older") {
    return `${v.name} ${v.version} is older than the versions Mandu was tested with (${rangeWords(v)}). Upgrade it if anything misbehaves.`;
  }
  if (unknown.length > 0 && masking) {
    const list = unknown.length <= 3 ? unknown.join(", ") : `${unknown.slice(0, 3).join(", ")} and ${unknown.length - 3} more`;
    return `Mandu does not know ${unknown.length === 1 ? "one of this agent's tools" : `${unknown.length} of this agent's tools`} yet (${list}), so their output is masked in full and the agent may work less well.`;
  }
  return null;
}

/**
 * A preview agent's tag (supported-agents.md §2.0): the session's agent
 * version belongs to a PREVIEW line of the dashboard's own table
 * (session-health.ts `preview`); null for a supported agent or a session
 * with no version check. Every launch says the same in one line before the
 * agent starts; the page keeps it beside the agent's name. It says nothing
 * about what Mandu enforces: the status is about how much testing stands
 * behind the agent, not about its protection.
 */
export function agentPreview(health: SessionHealth | undefined): AgentPreview | null {
  const label = health?.preview;
  if (!label) return null;
  return {
    label,
    sentence: `${label} support is a preview: Mandu was tested less with it than with Claude Code and Codex.`,
    issues: ISSUES_URL,
  };
}

/** A session label a person reads: only the first prompt. A fallback
 *  label (the launcher's posture line "claude launch: 7 rung(s) live […]", a
 *  U-LLM inspection) describes the session to a developer, so the product
 *  pages say there was no prompt instead (dashboard.md §4.25). */
export function promptLabel(s: Pick<SessionRef, "label" | "labelFrom"> | null | undefined): string | null {
  if (!s) return null;
  return s.labelFrom && s.labelFrom !== "prompt" ? null : s.label;
}

/** Trim a session label to one line. */
export function oneLine(s: string | null | undefined, max = 80): string | null {
  if (!s) return null;
  const v = s.replace(/\s+/g, " ").trim();
  if (!v) return null;
  return v.length > max ? v.slice(0, max - 1) + "…" : v;
}

/**
 * Whether a listed session is an agent's: the system logs (the arbiter's
 * admin audit log `arbiter-admin`, the net-guard's and net-proxy's
 * sessionless fallbacks; registry.ts `systemLogKind`) are logs, not agents.
 * Home never lists, counts or opens them; the inspector's Sessions page keeps
 * them in its folded System logs group (dashboard.md §4.25, "Agents, not
 * sessions"; 2026-10-05: a fresh install's Home said "3 agents are running"
 * for one `mandu claude`).
 */
export function isAgentSession(s: Pick<SessionRef, "id">): boolean {
  return systemLogKind(s.id) === undefined;
}

function whoRaised(v: QueueRowVM, byId: Map<string, AgentOf>): string[] {
  const names: string[] = [];
  for (const id of v.sessions ?? []) {
    const s = byId.get(id);
    const n = agentName(s?.agent, s?.health);
    if (!names.includes(n)) names.push(n);
  }
  return names;
}

/**
 * The agent whose request the row holds: the session that raised it LAST
 * (the arbiter keeps `sessions` most-recent-last). One row is one (item,
 * destination) pair, so two sessions sending the same secret to the same
 * host share it: an ask a Codex session raised after a Claude Code one was
 * answered is Codex's (2026-10-05: it read "Claude Code wants to send …",
 * there and under Answered earlier). No session known: "The agent".
 */
export function askedBy(v: Pick<QueueRowVM, "sessions">, byId: Map<string, AgentOf>): string {
  const last = v.sessions?.[v.sessions.length - 1];
  const s = last === undefined ? undefined : byId.get(last);
  return agentName(s?.agent, s?.health);
}

/** An answered row's outcome, as Answered earlier states it; the agent page
 *  says the same under the step that asked (§4.25b). A held message's row
 *  (`prompt:`, keyed to one message `model:<session>#turn:<ref>` or to the
 *  session) records Send as written as approved and Send masked and Cancel
 *  as denied (prompt-filter holds.ts), so it reads as what went to the AI,
 *  never "Blocked" for a message that went masked. */
/** A holder's send question's files on the card (plan 13 §5.4), `~/…`
 *  under the page's home. */
function holderCard(v: QueueRowVM, home: string | undefined): Pick<HomeAsk, "sources" | "sourcesLeft" | "sourcesLeftParts"> {
  if (!v.holderSources || v.holderSources.length === 0) return {};
  const left = holderLeftWords(v.holderSources, v.target, home ?? "");
  const leftParts = holderLeftParts(v.holderSources, v.target, home ?? "");
  return { sources: holderSourceWords(v.holderSources, v.target, home ?? ""), ...(left ? { sourcesLeft: left, sourcesLeftParts: leftParts } : {}) };
}

export function answeredOutcome(v: Pick<QueueRowVM, "status" | "scope" | "consumedAt"> & Partial<Pick<QueueRowVM, "subject" | "target" | "strip">>): HomeAnswered["outcome"] {
  // "Send without it" (dashboard.md §4.34): the request went (or will go)
  // with a marker where the secret was; not "Blocked".
  if (v.strip === true && v.status === "denied") return v.consumedAt ? "without-used" : "without";
  if (String(v.subject ?? "").startsWith("prompt:")) {
    const message = String(v.target ?? "").includes("#turn:");
    if (v.status === "denied") return message ? "masked" : "masked-session";
    return message && v.scope === "once" ? "sent" : "sent-session";
  }
  if (v.status === "denied") return "blocked";
  if (v.scope === "once") return v.consumedAt ? "allowed-once-used" : "allowed-once";
  return "allowed";
}

/**
 * A waiting card's answers on the product page: the panel's, with "Send
 * without it" (dashboard.md §4.34) before Block where the row is marked
 * `stripOffered`. The product's card only: the inspector, whose answer
 * buttons key a once-scoped action to Allow once, keeps the three.
 */
export function sendWithoutActions(v: Pick<QueueRowVM, "actions" | "stripOffered">): QueueRowVM["actions"] {
  if (v.stripOffered !== true || v.actions.some((a) => a.strip)) return v.actions;
  const strip = { approve: false, scope: "once" as const, strip: true as const, label: "Send without it" };
  const block = v.actions.findIndex((a) => !a.approve && a.scope === undefined);
  return block === -1 ? [...v.actions, strip] : [...v.actions.slice(0, block), strip, ...v.actions.slice(block)];
}

export interface HomeInput {
  /** Live (non-test, non-drill) sessions, newest first, `status` stamped. */
  sessions: SessionRef[];
  /** Agent kind and health by session id over EVERY session (an ask raised
   *  from a drill or test session still names its agent, its generation
   *  too; the session itself stays hidden). */
  agentOf?: Map<string, AgentOf>;
  /** Facts for the sessions inside the window (missing ⇒ not computed). */
  facts: Map<string, HomeSessionFacts>;
  panel: PolicyPanelVM;
  configuredMode: Mode;
  nowMs: number;
  /** The window the counts cover, in hours (the route's choice). */
  windowHours: number;
  /** Total live AGENT sessions on record (the history link's number; the
   *  route leaves the system logs out, `isAgentSession`). */
  historyTotal: number;
  /** The folder `~` stands for in an ask that names a secret's file
   *  (describeAsk; the route's HomeDeps `home`). Absent: the path as
   *  recorded. */
  home?: string;
  /** The build serves the developer view (§4.25ac): a sentence may send the
   *  person to the detailed trace. False: none does, and a failed session
   *  is found on its agent page (§4.25ad). Absent = true. */
  dev?: boolean;
  /** Rule changes waiting (pending policy proposals), as the route read
   *  them; absent or unreadable = 0, and the hero counts questions alone. */
  proposalsWaiting?: number;
}

/** The answers one read of Answered earlier brings (Home's first page and
 *  each Show more), and the most one read brings (dashboard.md §4.25
 *  *Past the newest 20*). */
export const ANSWERED_PAGE = 20;
export const ANSWERED_PAGE_MAX = 500;

/**
 * One page of Approvals › Answered earlier (dashboard.md §4.25 *Past the
 * newest 20*): the queue's answered rows, newest decision first (an answer
 * not stamped, by when it was last asked; ties keep the queue's order),
 * the `limit` after the row `after` (none, or one no longer answered: from
 * the top), each in the words its waiting card had. `total`: every answer;
 * `next`: the last row's id while more follow. `/api/home` draws the first
 * page and `/api/home/answered` each next one, both through this, so the
 * two never differ. Pure.
 */
export function answeredPage(queue: readonly QueueRowVM[], byId: Map<string, AgentOf>, home: string | undefined, after: string | null, limit: number): { rows: HomeAnswered[]; total: number; next: string | null } {
  const all = queue
    .filter((r) => r.status !== "pending")
    .sort((a, b) => (b.resolvedAt ?? b.lastSeen) - (a.resolvedAt ?? a.lastSeen));
  const n = Math.max(1, Math.min(ANSWERED_PAGE_MAX, Math.floor(Number.isFinite(limit) ? limit : ANSWERED_PAGE)));
  const at = after === null ? -1 : all.findIndex((r) => r.id === after);
  const page = all.slice(at + 1, at + 1 + n);
  const next = at + 1 + n < all.length && page.length ? page[page.length - 1]!.id : null;
  const rows = page.map((v) => ({
    id: v.id,
    sentence: describeAsk(v, askedBy(v, byId), home).sentence,
    outcome: answeredOutcome(v),
    decidedAt: v.resolvedAt,
    sessions: v.sessions ?? [],
    actions: v.actions,
    ...(v.staleNote ? { staleNote: v.staleNote } : {}),
  }));
  return { rows, total: all.length, next };
}

/** The guard asks again every half second while it holds an open or a
 *  change (net-supervisor guard_kernel.rs), and each ask bumps the row's
 *  `lastSeen`; a row asked within this long is held now. */
export const HELD_FRESH_MS = 5_000;

/** Whether a held open or change still waits for its answer
 *  (dashboard.md §4.34 "After you answer"): undefined for every other
 *  row, whose attempt was refused at once (or, a held message, whose
 *  deadline the page does not see). */
export function heldNow(v: Pick<QueueRowVM, "subject" | "lastSeen">, nowMs: number): boolean | undefined {
  if (!/^(?:open|trust|write):/.test(String(v.subject ?? ""))) return undefined;
  return nowMs - v.lastSeen <= HELD_FRESH_MS;
}

/**
 * One agent's row, as Home lists it under Running now and Earlier and the
 * History page lists every session (dashboard.md §4.25, §4.25ae): its counts
 * are its page's tiles (`f`, the session's facts; absent: not counted, and
 * the listing's `violated` flag alone says whether protection held).
 * `waiting`: the asks it raised that still wait; `masking`: the level
 * running now masks untrusted content (the agent notice's wording).
 */
export function homeAgentRow(s: SessionRef, f: HomeSessionFacts | undefined, waiting: number, masking: boolean): HomeAgent {
  return {
    id: s.id,
    agent: agentName(s.agent, s.health),
    title: oneLine(promptLabel(s)),
    cwd: f?.cwd ?? null,
    startedAt: s.firstTs,
    lastAt: s.lastTs,
    // A recorded exit outranks the listing's recency rule (2026-10-05: a
    // `/exit`ed agent stayed under Running now beside the next one), and
    // an ended agent's question does not bring it back (2026-10-11: one
    // that ended hours ago stayed under Running now, "Waiting for your
    // OK", until the question was answered); its row still counts it.
    state: !(s.status === "running" && !f?.exited) ? "idle" : waiting > 0 ? "waiting" : "running",
    stats: f?.stats ?? EMPTY_STATS,
    secrets: f?.secrets ?? { masked: 0, early: 0 },
    untrusted: f?.untrusted ?? 0,
    blocked: f?.blocked ?? 0,
    sent: f?.sent ?? 0,
    holds: f ? f.holds : !s.violated,
    waiting,
    notice: agentNotice(s.health, masking),
    preview: agentPreview(s.health),
  };
}

/**
 * What a session's row reads from the policy panel beside its own facts
 * (dashboard.md §4.25, §4.25ae *History says what waits for you*), so
 * Home's rows and History's say the same: `waiting`, the asks still waiting
 * by the session that raised each LAST (`askedBy`), as an ask's sentence and
 * Approvals' "See what the agent was doing" link name it (an earlier session
 * that sent the same item to the same host is not waiting); none while the
 * queue is not known. `masking`: the level running now masks untrusted
 * content (the integrity axis on: injection / full), the agent notice's
 * wording. Pure.
 */
export function rowContext(panel: PolicyPanelVM): { waiting: Map<string, number>; masking: boolean } {
  const waiting = new Map<string, number>();
  if (panel.available && panel.verdictsKnown) {
    for (const v of panel.queue) {
      if (v.status !== "pending") continue;
      const id = v.sessions?.[v.sessions.length - 1];
      if (id !== undefined) waiting.set(id, (waiting.get(id) ?? 0) + 1);
    }
  }
  return { waiting, masking: panel.available && panel.posture.integrity.state === "on" };
}

/** The History page's rows past a cursor (dashboard.md §4.25ae). */
export interface HistoryVM {
  /** Every agent session on record (the Home link's number). */
  total: number;
  /** This page of them, newest first, each as Home draws a row. */
  rows: HomeAgent[];
  /** The id the next page starts after (`?after=`); null: no more. */
  next: string | null;
  /** Set when the read named a search (`?q=`, §4.25ae *Finding a session*):
   *  its words as matched, and `all`, every agent session on record; `total`
   *  then counts the matches. */
  query?: { text: string; all: number };
  /** Set when the read named the switch (`?only=stepped-in`, §4.25ae *Only
   *  the sessions where Mandu stepped in*): `rows` are only those
   *  (`steppedIn`), and `through` counts the sessions looked through from
   *  the newest to `next` (all of them when `next` is null). `total` still
   *  counts every session (the search's matches, with `q`). */
  only?: { through: number };
}

/** The most rows one History read returns, and its default. */
export const HISTORY_PAGE_MAX = 100;
export const HISTORY_PAGE = 25;

/**
 * The sessions of one History page: `sessions` every agent session on
 * record, newest first (the route leaves out the test and drill runs and the
 * system logs, as Home does); the page starts after the row `after` (absent,
 * or an id no longer listed: the first page, and the page drops a row it
 * already drew) and holds at most `limit` (1..HISTORY_PAGE_MAX). Pure.
 */
export function historyPage(sessions: readonly SessionRef[], after: string | null, limit: number): { page: SessionRef[]; next: string | null } {
  const list = sessions.filter(isAgentSession);
  const n = Math.max(1, Math.min(HISTORY_PAGE_MAX, Math.floor(Number.isFinite(limit) ? limit : HISTORY_PAGE)));
  const at = after === null ? -1 : list.findIndex((s) => s.id === after);
  const page = list.slice(at + 1, at + 1 + n);
  const next = at + 1 + n < list.length && page.length ? page[page.length - 1]!.id : null;
  return { page, next };
}

/** The `?only=` that keeps the sessions where Mandu stepped in; any other
 *  value reads as off. */
export const HISTORY_ONLY_STEPPED_IN = "stepped-in";
/** The most sessions one filtered History read looks through: a long run
 *  of plain sessions ends the read there, and its `next` goes on from it. */
export const HISTORY_SCAN_BUDGET = 200;

/**
 * Whether Mandu stepped in on a session, as its History row says it
 * (dashboard.md §4.25ae *Only the sessions where Mandu stepped in*): a
 * secret masked before the AI saw it or read before it was marked, an
 * untrusted item masked (counted only where the level masks them), a step
 * blocked, a send with a real value filled in, a question still waiting, or
 * protection failed (the leak check's finding). Read off the row, so the
 * switch keeps exactly the rows whose counts line says something. Pure.
 */
export function steppedIn(row: Pick<HomeAgent, "secrets" | "untrusted" | "blocked" | "sent" | "waiting" | "holds">): boolean {
  return row.secrets.masked > 0 || row.secrets.early > 0 || row.untrusted > 0 || row.blocked > 0 || row.sent > 0 || row.waiting > 0 || !row.holds;
}

/**
 * One History page of the sessions `keep` accepts (the switch, §4.25ae):
 * past the row `after` (absent or no longer listed: from the newest), it
 * looks through `sessions` in order and keeps the accepted ones until
 * `limit` rows (1..HISTORY_PAGE_MAX) or `budget` sessions looked through.
 * `next` is the last session looked through when any is left, so a page
 * that ends on the budget with few matches still pages on; `through`, the
 * sessions looked through from the newest to it. `keep` may read (the
 * route counts each session as it goes); this does no I/O of its own.
 */
export async function historyPageWhere<T extends Pick<SessionRef, "id">>(sessions: readonly T[], after: string | null, limit: number, budget: number, keep: (s: T) => boolean | Promise<boolean>): Promise<{ page: T[]; next: string | null; through: number }> {
  const list = sessions.filter(isAgentSession);
  const n = Math.max(1, Math.min(HISTORY_PAGE_MAX, Math.floor(Number.isFinite(limit) ? limit : HISTORY_PAGE)));
  const most = Math.max(1, Math.floor(Number.isFinite(budget) ? budget : HISTORY_SCAN_BUDGET));
  const at = after === null ? -1 : list.findIndex((s) => s.id === after);
  const page: T[] = [];
  let i = at + 1;
  for (let looked = 0; i < list.length && looked < most && page.length < n; i++, looked++) {
    if (await keep(list[i]!)) page.push(list[i]!);
  }
  return { page, next: i < list.length && i > at + 1 ? list[i - 1]!.id : null, through: i };
}

/** The longest search History reads (`?q=`); the rest is dropped. */
export const HISTORY_QUERY_MAX = 200;

/** A History search's words: `q` cut at HISTORY_QUERY_MAX, lower-cased,
 *  split on spaces; none for an empty or blank one. Pure. */
export function historyWords(q: string | null | undefined): string[] {
  return (q ?? "").slice(0, HISTORY_QUERY_MAX).toLowerCase().split(/\s+/).filter((w) => w !== "");
}

/**
 * The sessions a History search finds (dashboard.md §4.25ae *Finding a
 * session*): each whose agent name or prompt label, as its row reads them,
 * holds every word of `q`, case aside; all of them when `q` has no word.
 * The label is the one the row shows (`promptLabel`), derived from what the
 * AI saw, each masked item spelled "[masked]": never an original, so a
 * search for a secret's value finds nothing (the route is open signed out,
 * and a search over originals would tell a reader whether a value is in a
 * prompt). Order kept. Pure.
 */
export function historyMatches<T extends Pick<SessionRef, "agent" | "health" | "label" | "labelFrom">>(sessions: readonly T[], q: string | null | undefined): T[] {
  const words = historyWords(q);
  if (!words.length) return [...sessions];
  return sessions.filter((s) => {
    const label = (promptLabel(s) ?? "").replace(SYM_RE, "[masked]").replace(/\s+/g, " ");
    const text = `${agentName(s.agent, s.health)} ${label}`.toLowerCase();
    return words.every((w) => text.includes(w));
  });
}

/** The History page's rows (`facts` by id; a session not counted keeps its
 *  listing's verdict; `waiting` and `masking` as Home's rows read them,
 *  `rowContext`). Pure. */
export function buildHistoryViewModel(input: { total: number; page: readonly SessionRef[]; next: string | null; facts: Map<string, HomeSessionFacts>; waiting?: Map<string, number>; masking?: boolean; query?: { text: string; all: number }; only?: { through: number } }): HistoryVM {
  return {
    total: input.total,
    rows: input.page.map((s) => homeAgentRow(s, input.facts.get(s.id), input.waiting?.get(s.id) ?? 0, input.masking === true)),
    next: input.next,
    ...(input.query ? { query: input.query } : {}),
    ...(input.only ? { only: input.only } : {}),
  };
}

export function buildHomeViewModel(input: HomeInput): HomeVM {
  const { panel, nowMs } = input;
  const byId: Map<string, AgentOf> = input.agentOf ?? new Map(input.sessions.map((s) => [s.id, s]));
  const since = nowMs - input.windowHours * 3_600_000;
  const inWindow = input.sessions.filter(isAgentSession).filter((s) => {
    const last = s.lastTs ? Date.parse(s.lastTs) : NaN;
    return Number.isFinite(last) && last >= since;
  });

  // ── The window's counts ────────────────────────────────────────────────────
  const window = { hours: input.windowHours, sessions: inWindow.length, counted: 0, masked: 0, secretsMasked: 0, secretsEarly: 0, untrusted: 0, blocked: 0, sent: 0, waiting: 0 };
  let violations = 0;
  const failedIds: string[] = [];
  for (const s of inWindow) {
    const f = input.facts.get(s.id);
    if (!f) continue;
    if (f.violations > 0) failedIds.push(s.id);
    window.counted += 1;
    window.masked += f.stats.flows;
    window.secretsMasked += f.secrets?.masked ?? 0;
    window.secretsEarly += f.secrets?.early ?? 0;
    window.untrusted += f.untrusted ?? 0;
    window.blocked += f.blocked;
    window.sent += f.sent;
    violations += f.violations;
  }

  // ── Approvals ──────────────────────────────────────────────────────────────
  const waitingKnown = panel.available && panel.verdictsKnown;
  const pendingRows = waitingKnown ? panel.queue.filter((r) => r.status === "pending") : [];
  // A session has ended when it is listed and not running (a recorded exit
  // outranks the listing's recency rule), as its Home row says.
  const ended = (id: string | undefined): boolean => {
    if (id === undefined) return false;
    const s = input.sessions.find((x) => x.id === id);
    return s !== undefined && !(s.status === "running" && !input.facts.get(id)?.exited);
  };
  const waiting: HomeAsk[] = pendingRows.map((v) => {
    const agents = whoRaised(v, byId);
    const who = askedBy(v, byId);
    const held = heldNow(v, nowMs);
    const cwd = input.facts.get(v.sessions?.[v.sessions.length - 1] ?? "")?.cwd;
    return {
      id: v.id,
      ...describeAsk({ ...v, ...(held !== undefined ? { held } : {}) }, who, input.home),
      askedAt: v.lastSeen,
      count: v.count,
      ...(held !== undefined ? { held } : {}),
      ...(ended(v.sessions?.[v.sessions.length - 1]) ? { askerEnded: true as const } : {}),
      ...(cwd ? { askerCwd: cwd, askerAgent: who, askerSessions: new Set(v.sessions).size } : {}),
      sessions: v.sessions ?? [],
      agents,
      actions: sendWithoutActions(v),
      mintable: v.mintable,
      ...holderCard(v, input.home),
    };
  });
  window.waiting = waiting.length;
  // The newest ANSWERED_PAGE; Show more reads on (answeredPage).
  const firstAnswered = waitingKnown ? answeredPage(panel.queue, byId, input.home, null, ANSWERED_PAGE) : { rows: [], total: 0 };
  const answered: HomeAnswered[] = firstAnswered.rows;
  // ── The agents ─────────────────────────────────────────────────────────────
  // Each ask waits on the session that raised it last; untrusted content is
  // masked when the integrity axis is on (rowContext, as History reads it).
  const { waiting: waitingBySession, masking } = rowContext(panel);
  const agents: HomeAgent[] = inWindow.map((s) => homeAgentRow(s, input.facts.get(s.id), waitingBySession.get(s.id) ?? 0, masking));

  // ── The verdict ────────────────────────────────────────────────────────────
  const integrity = panel.available ? panel.posture.integrity.state : "unknown";
  const confidentiality = panel.available ? panel.posture.confidentiality.state : "unknown";
  const level: Mode | "unknown" =
    integrity === "unknown" || confidentiality === "unknown"
      ? "unknown"
      : integrity === "on"
        ? confidentiality === "on"
          ? "full"
          : "injection"
        : confidentiality === "on"
          ? "secrets"
          : "off";
  const protection = { level, configured: input.configuredMode, connected: panel.available };

  const running = agents.filter((a) => a.state !== "idle").length;
  const agentsPhrase =
    running === 0
      ? "No agent is running right now."
      : running === 1
        ? "One agent is running under Mandu."
        : `${running} agents are running under Mandu.`;

  // Rule changes waiting, as the route read them: a count only.
  const changes = Math.max(0, Math.floor(input.proposalsWaiting ?? 0)) || 0;

  let verdict: HomeVerdict;
  let headline: string;
  let sentence = "";
  // The place a sentence sends the person is a link part (§4.25, *The hero
  // links where it points*). Until 2026-10-08 none was a link, and the off
  // sentence said "Turn it back on under Rules": the switch moved to
  // Settings on 2026-10-05.
  let parts: HomeHeroPart[] | null = null;
  if (!panel.available) {
    verdict = "unknown";
    headline = "Not connected.";
    parts = [
      { kind: "text", text: "The protection service is not reachable, so nothing can be checked. Start an agent with Mandu, or " },
      { kind: "link", text: "open Settings", to: "settings" },
      { kind: "text", text: "." },
    ];
  } else if (violations > 0) {
    verdict = "failed";
    headline = "Protection failed.";
    const lead: HomeHeroPart = { kind: "text", text: (violations === 1 ? "One item reached the AI unmasked" : `${violations} items reached the AI unmasked`) + ` in the last ${input.windowHours} hours. ` };
    parts = input.dev !== false
      // One failed session: its own trace; several: the trace's list.
      ? [lead, { kind: "link", text: "Open the detailed trace", to: "trace", session: failedIds.length === 1 ? failedIds[0]! : null }, { kind: "text", text: " to see which." }]
      // No developer view: the agent page of the one session, or each
      // agent's row, which says "protection failed" (§4.25ad).
      : failedIds.length === 1
        ? [lead, { kind: "link", text: "Open that agent's page", to: "agent", session: failedIds[0]! }, { kind: "text", text: " to see which." }]
        : [lead, { kind: "text", text: "Each agent where it happened says \"protection failed\" below, and its page shows which." }];
  } else if (level === "off") {
    verdict = "off";
    headline = "Protection is off.";
    parts = [
      { kind: "text", text: "The AI can read untrusted content as-is, and your secrets are not guarded. " },
      { kind: "link", text: "Turn it back on in Settings", to: "settings" },
      { kind: "text", text: "." },
    ];
  } else if (waiting.length > 0 || changes > 0) {
    verdict = "waiting";
    // The hero counts what the Approvals badge counts: questions and rule
    // changes (dashboard.md §4.25, the verdict ladder).
    const asks = waiting.length;
    headline = changes === 0
      ? asks === 1 ? "One question is waiting for you." : `${asks} questions are waiting for you.`
      : asks === 0
        ? changes === 1 ? "A rule change is waiting for you." : `${changes} rule changes are waiting for you.`
        : asks === 1 && changes === 1
          ? "One question and one rule change are waiting for you."
          : `${asks} ${asks === 1 ? "question" : "questions"} and ${changes} ${changes === 1 ? "rule change" : "rule changes"} are waiting for you.`;
    // Only what holds for every ask (describeAsk's families): never "nothing
    // leaves until you answer", since a rule sends a secret to its own host
    // meanwhile, and most asks are not sends. A rule change waiting is not
    // applied until it is approved (a held hand edit too: the rules in force
    // stay, policy-surface.md §8.4.6). At Secrets the level's own disclosure
    // stays (dashboard.md §4.25, the verdict ladder).
    sentence = (asks > 0
      ? `Protection is holding while you decide: what ${asks === 1 ? "it asks" : "each one asks"} for happens only if you allow it.`
      : "Your rules stay as they are until you answer.")
      + (level === "secrets" ? " Untrusted content is not masked in this mode." : "");
  } else if (level === "secrets") {
    verdict = "secrets-only";
    headline = "Your secrets are guarded.";
    // Never "cannot leave": a binding sends a secret's real value to its own
    // host, and the session pages show those sends (dashboard.md §4.25).
    sentence = `${agentsPhrase} Keys and secret files leave this computer only where a rule or your OK allows. Untrusted content is not masked in this mode.`;
  } else if (window.masked === 0) {
    verdict = "quiet";
    headline = "You are protected.";
    sentence = `${agentsPhrase} No untrusted content has reached the AI in the last ${input.windowHours} hours.`;
  } else {
    verdict = "protected";
    headline = "You are protected.";
    const what = window.masked === 1 ? "the one untrusted item an agent read was masked" : `all ${window.masked} untrusted items agents read were masked`;
    // Frozen levels (copy only): never "nothing left your machine without
    // your OK", for the Secrets sentence's reason; injection guards no secret.
    const sent = level === "full" ? ", and keys and secret files left this computer only where a rule or your OK allowed" : "";
    sentence = `${agentsPhrase} In the last ${input.windowHours} hours, ${what} before the AI saw it${sent}.`;
  }
  const sentenceParts: HomeHeroPart[] = parts ?? [{ kind: "text", text: sentence }];

  return {
    verdict,
    headline,
    sentence: sentenceParts.map((p) => p.text).join(""),
    sentenceParts,
    protection,
    window,
    waitingKnown,
    waiting,
    ruleChangesWaiting: changes,
    answered,
    answeredTotal: firstAnswered.total,
    agents,
    history: { total: input.historyTotal },
    // Never a session on record: the setup card. It goes away with the first
    // live session (a drill or test session is not someone's first run).
    firstRun: input.historyTotal === 0 ? buildFirstRun(level, input.configuredMode) : null,
    // Each cause named as its row here names it, with a link to its page.
    exposure: panel.available ? homeExposure(panel.humanPlane, agents) : null,
    builtIn: builtInProtections(level),
  };
}
