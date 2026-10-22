/**
 * view-model/agent-page-types — the product agent page's story types
 * (§4.25b, §4.25h; moved out of agent-page.ts, which re-exports every one of
 * them — the public API is unchanged). Types only: the story is built in
 * agent-page.ts.
 */

import type { SessionFlowStats } from "./lineage.js";
import type { AgentPreview, HomeAnswered, HomeAsk, HomeTextPart, SecretsPostureNote } from "./home.js";
import type { PromptNote } from "./prompt-notes.js";
import type { SecretsStory } from "./secret-story.js";
import type { BrowserStory } from "./browser-story.js";
import type { LaunchTimeVM } from "./launch-time.js";

export type StoryOutcome =
  | "unmasked" // untrusted content reached the AI without a mask (a violation)
  | "blocked" // a gate refused it
  | "waiting" // a gate is waiting for the person
  | "raw" // the AI got it as it was; it was masked only in LATER requests (labelled after the fact)
  | "sandbox" // read by the sandboxed reader, never by the AI
  | "sent" // a send left this machine with a masked item's real value filled in (allowed)
  | "secret" // a secret was masked (plan 10 rule (i) / secret twin)
  | "masked" // untrusted content was masked before the AI read it
  | "plain"; // nothing to guard: trusted, local, or no result

export interface StoryPart {
  /** "masked" renders as a chip in place of an item the AI did not see
   *  here; its text is the chip's word ("masked" or "secret"). */
  kind: "text" | "code" | "masked" | "time";
  /** For "time": the moment as an ISO timestamp; the page draws it as the
   *  viewer's local clock time, as it draws each turn's time. */
  text: string;
  /** A `secret` chip in a command, path or query: the secret's name as the
   *  send steps say it (`PASTE_KEY`), drawn on the chip. Never a token or
   *  value; absent when no name is known. */
  name?: string;
  /** A `secret` chip of a secret the AI read as it was before it was
   *  marked one: the moment it read it (ISO), as its "Your secrets" card
   *  says (secret-story.ts `earlyReads`). The chip then never says the AI
   *  never got the real value. Absent: no such read recorded. */
  early?: string;
  /** A "text" part that names the Approvals row Mandu filed (the event's
   *  `policy.approvalId`, dual-lanes `askIdOf`), or the rule change a call
   *  to Mandu's rule tool made or asked for (`pc-…`, `pp-…`,
   *  mandu-tool-words.ts): the page draws its text ("Approvals") as a link
   *  to that row. An id, never a value. */
  ask?: string;
  /** A "time" part on a Your secrets card: the id of the step on this page
   *  that shows that moment (a turn step's `id`, its `data-step-id`); the
   *  page draws the time as a link that brings the step into view
   *  (secret-story.ts, *A time opens its step*). An id, never a value.
   *  Absent: no step on the page shows it. */
  step?: string;
  /** A "text" part that names this session's detailed trace ("Open the
   *  detailed trace"): the page draws its text as a link to the developer
   *  view's trace of the session it shows, in a new tab like its *Detailed
   *  trace* button; "secrets" opens the trace's Secrets tab. A tab name,
   *  never an address (dashboard.md §4.25, *The page links the trace it
   *  names*). Only in a build with the developer view: without it, no part
   *  names the trace (§4.25ad). */
  trace?: "trace" | "secrets";
  /** A "text" part the page draws as a link that opens in a new tab: only
   *  a fixed address the server itself names (`ISSUES_URL`, the leak
   *  check's *Report a problem*), never one read from an event. */
  href?: string;
  /** A "text" part the page draws as a link to that card of Rules
   *  (`/rules#built-in`, Built-in protections): a sent step to a company's
   *  own API names where the companies are listed (dashboard.md §4.25b). A
   *  card key, never an address or markup. */
  rules?: "built-in";
}

/** The original behind a masked step, revealed by a click. */
export interface StoryHidden {
  /** null: a secret (never shipped) or an original the session never recorded. */
  text: string | null;
  secret: boolean;
  truncated: boolean;
  /** A secret's: each secret the item held, by its short name and the
   *  opaque ref a signed-in click sends to `POST /api/home/reveal`
   *  (secret-ref.ts); the value itself is never in the page's data. */
  secrets?: Array<{ ref: string; name: string | null }>;
}

/** A step where the AI's view and reality differ, told in two halves. */
export interface StorySplit {
  ai: StoryPart[];
  real: StoryPart[];
  hidden: StoryHidden | null;
}

export type StoryStep =
  | {
      kind: "action"; id: string; ts: string;
      icon: "file" | "edit" | "run" | "web" | "search" | "tool" | "shield";
      sentence: StoryPart[]; outcome: StoryOutcome; note: string | null;
      /** `note` as parts, when a part of it is a link (a step that reached
       *  the AI unmasked: its "Open the detailed trace" opens the trace).
       *  `note` keeps the same words joined. Absent: `note` is all. */
      noteParts?: StoryPart[];
      split: StorySplit | null;
      /** What changed for this item AFTER its step (outcome "raw": "Masked
       *  from 10:42 on, after it was marked a secret."). The step itself
       *  says what the AI received at its own turn. Absent: nothing changed. */
      later?: StoryPart[];
      /** Why Mandu blocked or held it, from the rule its event recorded
       *  ("No rule lets this secret go to `api.stripe.com`. …",
       *  block-why.ts). Absent: not stopped, or no rule the page words. */
      why?: StoryPart[];
      /** The Approvals row Mandu filed when it blocked or held it (the
       *  event's `policy.approvalId`, `egr-<n>`): the page says "Mandu
       *  asked for your OK in Approvals.", linking to that row. An id,
       *  never a value. Absent: it filed none. */
      askId?: string;
      /** That row's answer, as Approvals › Answered earlier states it
       *  (home.ts `answeredOutcome`): the page adds "Your answer: Blocked.".
       *  Absent: still waiting, or the queue was not read. */
      answer?: HomeAnswered["outcome"];
    }
  /** Something the agent said between steps (narration, not the reply). */
  | { kind: "said"; id: string; ts: string; parts: StoryPart[] }
  /** The workspace was prepared before the agent started. */
  | { kind: "setup"; id: string; ts: string; files: string[] }
  /** The agent condensed the conversation (a context compaction). */
  | { kind: "aside"; id: string; ts: string };

export interface StoryReply {
  ts: string;
  /** What you saw (masked items filled in; secrets stay chips). */
  parts: StoryPart[];
  /** What the AI wrote, when it differs from what you saw: this page filled
   *  in at least one masked item. Else null, and the reply is one card. */
  ai: StoryPart[] | null;
  /** The secrets the reply held, which stay chips on both sides: "The reply
   *  held your secret `STRIPE_KEY`. The AI wrote it masked, and this page
   *  keeps it masked." A secret the AI read as it was before its label, at
   *  or before the reply, adds when ("The AI read its real value at 10:41,
   *  before it was marked a secret."). Names and times only, never a token
   *  or value. Absent: none. */
  kept?: StoryPart[];
  /** One card that still shows an ordinary masked item the page could not
   *  fill in (signed out, or the original was not recorded): the page says
   *  which, as a step's hidden box does. Absent: none. */
  unresolved?: true;
}

/** One background step, listed when the page asks for its turn's
 *  (`?background=<turn id>`, dashboard.md §4.25ae): when, and what in plain
 *  words ("Connected to `api.anthropic.com` (4 times)"); a command's masked
 *  items stay chips. Never a value. */
export interface BackgroundItem {
  ts: string;
  parts: StoryPart[];
}

/** A turn's folded background (see `StoryTurn.routine`). */
export interface StoryRoutine {
  count: number;
  hosts: string[];
  parts: StoryPart[];
  /** Each background step, oldest first, when the page asked for them; at
   *  most BACKGROUND_ALL_CAP. Absent: not asked. */
  items?: BackgroundItem[];
  /** Background steps past BACKGROUND_ALL_CAP, with `items`. */
  moreItems?: number;
}

/** One place the leak check found something that reached the AI without a
 *  mask (dashboard.md §4.25ae): when, the step on the page that shows it
 *  (its time opens it), and the sentence. Names and times only: never the
 *  text the check found. */
export interface LeakFindingItem {
  ts: string | null;
  step?: string;
  parts: StoryPart[];
}

/** What the leak check found, for a session where it fired. */
export interface LeakFinding {
  /** Events the check flagged (the tile's number). */
  count: number;
  /** Each place, oldest first, at most FINDING_CAP. */
  items: LeakFindingItem[];
  /** Places past FINDING_CAP. */
  more: number;
  /** What to do now, one line each (`findingTodo`): change each secret the
   *  lines name, the same for a line that names none, and report it.
   *  Secret names only, never a value. */
  todo: StoryPart[][];
}

export interface StoryTurn {
  id: string;
  ts: string | null;
  /** Your question; null for the steps before your first question. Plain
   *  text with each masked item spelled "[masked]" (the page title). */
  prompt: string | null;
  /** The question as the page draws it: each masked item a `secret` or
   *  `masked` chip, never plain text. null with `prompt`, or for a shell escape. */
  promptParts: StoryPart[] | null;
  /** A shell escape (`!cmd` in Claude Code): the command you ran and what it
   *  printed (masked items as chips); the page reads it as "You ran". */
  shell: { command: string; output: StoryPart[] } | null;
  /** One line: what Mandu did in this turn. null when the turn did nothing. */
  summary: string | null;
  /** The same line as the page draws it: each secret it names is code (the
   *  label the steps use), never a token. null with `summary`. */
  summaryParts: StoryPart[] | null;
  /** The most severe outcome in the turn, for the summary's tone. */
  tone: StoryOutcome;
  steps: StoryStep[];
  /** Steps left out past TURN_STEP_CAP, or past TURN_STEP_ALL_CAP with
   *  `allSteps`: the page's *Show them* asks for them (`?steps=<turn id>`,
   *  dashboard.md §4.25ad). */
  moreSteps: number;
  /** The first of them: its step id, which the page focuses once they are
   *  shown, and where its "detailed trace" opens the trace in a build with
   *  the developer view (`?step=`, dashboard.md §4.35). An id, never a
   *  value or an address. Absent: none left out. */
  moreFrom?: string;
  /** The page asked for every step of this turn, or it holds the step an
   *  ask was raised at: a `moreSteps` left is past TURN_STEP_ALL_CAP, which
   *  no *Show them* lifts. Absent: the turn has its first TURN_STEP_CAP. */
  allSteps?: true;
  reply: StoryReply | null;
  /** The folded background: how many steps, which hosts it talked to, and
   *  the line the page draws ("In the background: 4 connections to
   *  `api.anthropic.com`."), each kind in plain words, a host as code. */
  routine: StoryRoutine | null;
  /** Plan 15 §7, §13.7: what the prompt filter changed in your message, in
   *  plain words (never the value); null when it changed nothing. */
  promptNote: PromptNote | null;
}

export interface AgentPageVM {
  found: boolean;
  id: string;
  agent: string;
  /** The "Preview" tag by the agent's name, as on its Home row (home.ts
   *  `agentPreview`); null for a supported agent. */
  preview: AgentPreview | null;
  /** The warning by the agent's name, as on its Home row (home.ts
   *  `agentNotice`): the session could not do its job or some of its
   *  commands could not run (dashboard.md §4.21 *On the product page*), its
   *  version is outside the range Mandu was tested with, or it advertised
   *  tools Mandu does not know where the level masks their output. null
   *  otherwise. */
  notice: string | null;
  /** The same words as parts, each command as code; null with no notice. */
  noticeParts: HomeTextPart[] | null;
  /** The session could not do its job (its health `broken`): the page also
   *  writes the notice out under its header, not only behind the mark. */
  noticeShown: boolean;
  /** The session's launch left the agent's programs able to read the
   *  credential files (its posture `gated`, dashboard.md §4.23 *Product
   *  page*): a line under the header with the fix. null for `confined`,
   *  `read-blocked`, or a session no launcher recorded. */
  secretsPosture: SecretsPostureNote | null;
  title: string | null;
  cwd: string | null;
  startedAt: string | null;
  lastAt: string | null;
  running: boolean;
  holds: boolean;
  violations: number;
  stats: SessionFlowStats;
  /** Steps Mandu blocked, across the whole session (the tile). */
  blocked: number;
  /** Sends that left this machine with a masked item's real value filled
   *  in, across the whole session (the tile; Home's hero counts the same,
   *  `storyCounts`). */
  sent: number;
  waiting: HomeAsk[];
  /** Oldest first. Capped: `earlier` counts the turns left out at the start. */
  story: StoryTurn[];
  earlier: number;
  /** The page asked for every turn (`?turns=all`): an `earlier` left is past
   *  TURN_ALL_CAP, which no *Show them* lifts (dashboard.md §4.25ad). */
  allTurns?: true;
  /** The step an ask was raised at, when the page was opened for one
   *  (`?ask=`): null without `?ask=`. `turnId` null = not found here. */
  focus: StoryFocus | null;
  /** "Main model: your own model (ollama)" when the session's main
   *  conversation is bound to a declared model (dashboard.md §4.25l); null
   *  for the agent's default vendor, an unbound session, or no answer. */
  mainModel: { words: string; local: boolean } | null;
  /** "Mandu took 1.7 s to start this session: …" (dashboard.md §4.25ag),
   *  from the launcher's step timings; null when the launch recorded none. */
  launchTime: LaunchTimeVM | null;
  /** Plan 15 §13.7: notes for messages no turn shows (a message Mandu
   *  blocked never reached the AI), oldest first; the page places each in
   *  the story by its time. */
  unplacedNotes: PromptNote[];
  /** "Your secrets in this session" (§4.25b): each secret the session
   *  recorded, in plain lines backed by its events (secret-story.ts). */
  secrets: SecretsStory;
  /** The page asked for every secret (`?secrets=all`): a `secrets.more`
   *  left is past SECRET_ALL_CAP. */
  allSecrets?: true;
  /** What the leak check found (§4.25ae): null when it never fired. */
  finding: LeakFinding | null;
  /** "On web pages" (§4.25af): a browser agent's run through Mandu's
   *  DevTools relay, from its events; null when the session had none. */
  browser: BrowserStory | null;
  /** The whole original behind one step's mask, up to ORIGINAL_ALL_CAP: only
   *  for the admin route that asked (`AgentPageShow.original`,
   *  `GET /api/home/original`), never on the page's own read. null: that
   *  step has no original to show. */
  original?: StoryHidden | null;
  /** Whether the page carries originals (dashboard.md §6): false for a
   *  viewer without the admin session, whose page is built from what the AI
   *  saw only; the page then says "Sign in to see real values". */
  valuesShown: boolean;
}

/** Where an ask was raised in this session's story (§4.25h). */
export interface StoryFocus {
  ask: string;
  turnId: string | null;
  /** The step itself; null when nothing was found here (its turn is shown
   *  with every step up to TURN_STEP_ALL_CAP; one past that counts as not
   *  found). */
  stepId: string | null;
  /** "exact": a gate event carried the ask's id. "destination": the first
   *  stopped send to the ask's destination (records older than the id). */
  match: "exact" | "destination" | null;
}

/** The queue row an ask came from, as much as locating it needs. */
export interface AskRef {
  id: string;
  /** The key's subject half: a symbol for a network send. */
  subject: string;
  /** Destination host for a network send; path / signature otherwise. */
  target: string;
  family: "network" | "filesystem" | "exec" | "prompt" | "unknown";
}
