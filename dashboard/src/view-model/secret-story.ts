/**
 * view-model/secret-story — "Your secrets in this session" on the product's
 * agent page (dashboard.md §4.25b, *Your secrets*). Mandu-new (no reference
 * origin).
 *
 * One entry per secret the session's lineage recorded (a secret twin, or a
 * symbol carrying a level above `public`, lineage.ts `isSecretFlow`), told in
 * plain lines: what the AI got, where Mandu filled in the real value, what it
 * blocked, what waits for the person, and where the person saw it. Flows
 * that stand for the SAME thing (one file masked to two tokens, say a later
 * re-read) are one entry: the person has one secret, not two rows.
 *
 * READ BEFORE IT WAS LABELLED. A file labelled a secret after the AI read it
 * as it was (dual-lanes `maskedLater`) says so, with both moments, in place
 * of "never the real value": the AI has that value, and only later requests
 * carry the placeholder. They carry it in place of the secret, not "only":
 * the proxies forward the AI's own replies as written (confidentiality.md
 * §7.1, the residual), so when later requests went, the card says that
 * anything the AI wrote from the real value went back to it. The page's
 * turns say it of the same secret by the same answer (`earlyReads`): its
 * chips and a reply that held it.
 *
 * LABELLED AFTER THE SESSION. A file the rule-change log says was labelled
 * after this session read it as it was (later-labels.ts; the page is given
 * the labels in force and their times) is told too, though the session's
 * own record never learned of the label: an entry that already tells of
 * the file takes the earlier read as above, and any other file gets an
 * entry of its own with no placeholder, no "Show the real value" and no
 * send lines, saying when the AI read it and when it was marked
 * (`afterLines`). It counts as "read before it was marked".
 *
 * IN THE ORDER IT HAPPENED. The send line and each block line say when (the
 * first, for more than one), from the events that prove them, and run in
 * time order: a block at 10:38 and a send to the same host at 10:39 read as
 * what happened, not as "allowed" above "blocked". A time the record does
 * not hold is not said, and then the order is not changed.
 *
 * A TIME OPENS ITS STEP. A time on a card (the first send, each host's
 * first block, the read before the label) carries the id of the page's
 * step that shows the same moment, found from the line's own evidence
 * event by the trace's rule (dual-lanes `stepIdOfEvent`; the read's own
 * step): the page draws it as a link to that step. A moment no shown step
 * holds (a model request, a turn past the cap) stays plain.
 *
 * A SEND CLAIMS NO STANDING PERMISSION. A secret leaves this machine only
 * at a destination a rule binds it to, or with the person's OK (the egress
 * gate, confidentiality.md §3.2), and the event of a send records neither
 * which one nor whether an OK was for that one request. So the send line
 * says "where it was allowed to go", in the past, never "where it is
 * allowed to go": the tour's 10:39 send to `api.stripe.com` went out on a
 * one-time OK, and the present told it as a permission that still held
 * (2026-10-06). It names no OK either (A BLOCK SAYS MANDU ASKED YOU).
 *
 * A BLOCK SAYS MANDU ASKED YOU. A block, or a stopped action, whose event
 * names the Approvals row the arbiter filed for the person (dual-lanes
 * `askIdOf`, the session page's step reads the same id) says so: "…, and
 * asked for your OK in Approvals", the word a link to the earliest such
 * row ("for 1 of them" when only some did). It says only that Mandu asked,
 * never that the person answered, or that a later send went out on it.
 *
 * THE TAG AGREES WITH THE CARD. Each card's level tag carries the card's
 * first-line answer (`saw`), so the page never draws a safe-looking level
 * above a line that says the level did not hold: a read before the label
 * (the tag also says since when the AI got a placeholder), Off, a fired
 * leak check.
 *
 * THE TILES COUNT WHAT THE CARDS SAY. The page's secret tiles (`counts`)
 * count the entries by the same answer as each card's first line (`aiSaw`),
 * so "masked before the AI saw it" is never said of a secret its card says
 * the AI read as it was.
 *
 * HONEST CLAIMS ONLY. Every line follows from a recorded event: a lineage
 * edge (each one backed by the event that proves it) or a reply-filter
 * event. A session whose leak check fired makes no claim about what the AI
 * saw; a level that lets a model read the value says so instead of
 * "placeholder only"; "only" is said of a destination list only when no
 * other release was recorded. Mode `off` says nothing was masked.
 *
 * NEVER A VALUE. An entry names the secret by what it stands for, the
 * variable's NAME or the file's path (the same the "Why masked?" answer
 * shows), a command's output masked whole by why (the files and programs
 * its step's `[mandu:secret]` note names, secret-note.ts `maskCause`),
 * never by its token and never by its value: the module reads names, paths,
 * levels, destinations and counts, nothing else. A path under the person's
 * home folder reads `~/…` (the Rules page's file browser's `~`), so a page
 * shown or screenshotted does not spell out the account name.
 *
 * Pure. Built from the BELIEVED events' view-model (a claimed event,
 * arbiter-human-plane.md §10.2, may not make a "blocked" or "never sent"
 * claim), plus the full view-model's leak check, which may only take claims
 * away.
 */

import type { ManduEvent } from "../event-model.js";
import type { SessionViewModel } from "../view-model.js";
import { isSecretFlow, type SymbolLineage } from "./lineage.js";
import type { ProtectionMode } from "./paired-rows.js";
import { TERMS } from "./rule-words.js";
import { tildePath } from "./file-browser.js";
import type { StoryPart } from "./agent-page-types.js";
import { secretRef } from "./secret-ref.js";
import { askIdOf, stepIdOfEvent } from "./dual-lanes.js";
import { maskCause, type MaskCause } from "./secret-note.js";
import { heldTokens, tokensIn } from "./held-tokens.js";
import { toolFamily } from "./tool-family.js";
import { laterLabels, plainReads, readPath, readStepPath, type LabelTime } from "./later-labels.js";

/** Entries past this are counted, not listed, until the page asks for every
 *  one (`StoryOptions.cap`: the agent page's *Show them*, §4.25ad). */
export const SECRET_CAP = 12;
/** The most a page that asked for every secret lists (`?secrets=all`). */
export const SECRET_ALL_CAP = 200;

/** How "Your secrets" is told. `cap`: entries listed (default SECRET_CAP).
 *  `dev`: the build serves the developer view (dashboard.md §4.25ad); without
 *  it, no line points to the detailed trace. Absent: true. */
export interface StoryOptions {
  cap?: number;
  dev?: boolean;
}

export type SecretLineTone = "good" | "warn" | "bad" | "plain";

export interface SecretLine {
  tone: SecretLineTone;
  parts: StoryPart[];
}

export interface StorySecret {
  /** What it stands for: "The environment variable GITHUB_TOKEN". */
  what: StoryPart[];
  /** The level as the Rules page's term ("No AI"). */
  level: string;
  /** What the AI got, the card's first line (`aiSaw`): the page colours
   *  the level's tag by it, so the tag never looks safe above a line that
   *  says the level did not hold. */
  saw: AiSaw;
  /** For `saw` "early": since when the AI got a placeholder in its place
   *  (ISO, the card's "From … on" moment), which the tag says. */
  since?: string;
  lines: SecretLine[];
  /** The opaque ref of the secret's first token (secret-ref.ts): what a
   *  signed-in "Show the real value" sends; never the token, never a value.
   *  Absent for a file labelled after the session read it (*Labelled after
   *  the session*): the session holds no placeholder of it to show. */
  ref?: string;
}

/** What the AI got of one secret, the card's first line (`aiSaw`). */
export type AiSaw = "flagged" | "off" | "readable" | "early" | "own-model" | "masked";

export interface SecretsStory {
  mode: ProtectionMode | null;
  /** The leak check fired somewhere in the session: no claim about the AI. */
  flagged: boolean;
  secrets: StorySecret[];
  /** Secrets past the cap (SECRET_CAP, or SECRET_ALL_CAP for a page that
   *  asked for every one). */
  more: number;
  /** The page's tiles, over EVERY secret (past the cap too), each counted
   *  by its card's first line: `masked`, "The AI got only a placeholder,
   *  never the real value"; `early`, "The AI read its real value …, before
   *  it was marked a secret". A level that lets a model read it, Off and a
   *  fired leak check count in neither: their line says why. */
  counts: { masked: number; early: number };
}

const t = (text: string): StoryPart => ({ kind: "text", text });
const c = (text: string): StoryPart => ({ kind: "code", text });
/** A moment; `step`, the page's step that shows it, when there is one. */
const at = (iso: string, step?: string | null): StoryPart => (step ? { kind: "time", text: iso, step } : { kind: "time", text: iso });
/** Words that name this session's detailed trace, which the page links
 *  (`tab` "secrets": its Secrets tab; dashboard.md §4.25, *The page links
 *  the trace it names*). */
export const traceLink = (text: string, tab: "trace" | "secrets" = "trace"): StoryPart => ({ kind: "text", text, trace: tab });

/** Where a build without the developer view sends the reader of a step or a
 *  card the leak check flagged: the agent page's own finding (agent-page.ts
 *  `leakFinding`, drawn at the top of the page; dashboard.md §4.25ae). */
export const FINDING_POINTER = "What the leak check found, at the top of this page, says what.";

/** A fired leak check, a card's first line: with the developer view, where
 *  to look; without it, the page's own finding (§4.25ae). */
function flaggedLine(dev: boolean): SecretLine {
  const said = "Mandu's leak check flagged this session, so this page cannot say what the AI saw.";
  return { tone: "bad", parts: dev ? [t(said + " "), traceLink("Open the detailed trace"), t(".")] : [t(`${said} ${FINDING_POINTER}`)] };
}

/** `$MDU:tool[hash]` without its field path. */
function baseOf(name: string): string {
  const i = name.indexOf("]");
  return i >= 0 ? name.slice(0, i + 1) : name;
}

const TWIN_RE = /^\$MDU:(nomodel|localmodel|anymodel)_([A-Za-z0-9_]+)\[[0-9a-f]{4,8}\](?:\.(.+))?$/;
const SYM_RE = /\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\](?:\.[A-Za-z_][A-Za-z0-9_[\].]*)*/g;
const LEVEL_OF_PREFIX: Record<string, string> = { nomodel: "no-model", localmodel: "local-model", anymodel: "any-model" };

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

function listParts(items: string[]): StoryPart[] {
  const out: StoryPart[] = [];
  items.forEach((x, i) => {
    if (i > 0) out.push(t(i === items.length - 1 ? " and " : ", "));
    out.push(c(x));
  });
  return out;
}

/** A card line with the moment it tells of (null: not recorded). */
interface TimedLine {
  ts: string | null;
  line: SecretLine;
}

/** ", at 10:38" for one, ", the first at 10:38" for more; nothing when the
 *  time is not known. `step`: the page's step that shows that moment. */
function when(n: number, ts: string | null | undefined, step?: string | null): StoryPart[] {
  return ts ? [t(n === 1 ? ", at " : ", the first at "), at(ts, step)] : [];
}

/** ", and asked for your OK in Approvals" when each of the `n` filed a
 *  row, "… for 1 of them" when only some did, nothing when none did. The
 *  word links the earliest row (`StoryPart.ask`). Only that Mandu asked,
 *  in the past: never that you answered, or how. */
function askedParts(n: number, a: Asked | undefined): StoryPart[] {
  if (!a) return [];
  return [t(", and asked for your OK in "), { kind: "text", text: "Approvals", ask: a.id }, ...(a.n < n ? [t(` for ${a.n} of them`)] : [])];
}

/** The lines in the order they happened (stable for a tie). If any line's
 *  time is not known, the order stays as given: no order is guessed. */
function inTimeOrder(lines: readonly TimedLine[]): SecretLine[] {
  const timed = lines.every((l) => l.ts !== null);
  const ordered = timed ? [...lines].sort((a, b) => Date.parse(a.ts!) - Date.parse(b.ts!)) : lines;
  return ordered.map((l) => l.line);
}

/** The flow's level: the twin prefix, else the first non-public level a
 *  node carries; an unknown level reads as no-model (fail-closed, as
 *  rule-words `levelWords` reads it). */
function levelOf(f: SymbolLineage): string {
  const m = TWIN_RE.exec(f.root);
  if (m) return LEVEL_OF_PREFIX[m[1]!]!;
  for (const n of f.nodes) {
    const l = n.symbol?.confidentiality;
    if (typeof l === "string" && l !== "" && l !== "public") return l;
  }
  return "no-model";
}

function levelTerm(level: string): string {
  return level === "any-model" ? TERMS.readable : level === "local-model" ? TERMS.ownModel : TERMS.hidden;
}

/** "`a`", "`a` and `b`", "`a`, `b`, `c` and 2 more": at most three as code. */
function codeList(items: readonly string[]): StoryPart[] {
  const shown = items.slice(0, 3);
  const more = items.length - shown.length;
  const out: StoryPart[] = [];
  shown.forEach((x, i) => {
    if (i > 0) out.push(t(i === shown.length - 1 && !more ? " and " : ", "));
    out.push(c(x));
  });
  if (more) out.push(t(` and ${more} more`));
  return out;
}

/** The secret files a whole-output mask's note names (secret-note.ts
 *  `maskCause`), a file under `home` as `~/…`: "your secret file
 *  `./.env`", "your secret files `a`, `b` and `c`", "one of your secret
 *  files" when the note names none. The session page's step and *Your
 *  secrets* say them in the same words. */
export function causeFiles(paths: readonly string[], home: string): StoryPart[] {
  const short = [...new Set(paths.map((p) => tildePath(p, home)))];
  return short.length ? [t(short.length === 1 ? "your secret file " : "your secret files "), ...codeList(short)] : [t("one of your secret files")];
}

/** The programs a `read` cause names, by base name, as code; null for none. */
export function causePrograms(apps: readonly string[]): StoryPart[] | null {
  const names = [...new Set(apps.map((a) => a.replace(/\/+$/, "").split("/").pop() || a))];
  return names.length ? codeList(names) : null;
}

/** How a masked command output's name goes on, from its note: "whose
 *  command named your secret file `./.env`", "in which `psql` read your
 *  secret file `~/.pgpass`". In the past, as the card's other lines. */
function causeWhat(cause: MaskCause, home: string): StoryPart[] {
  if (cause.kind === "names") return [t(" whose command named "), ...causeFiles(cause.paths, home)];
  return [t(" in which "), ...(causePrograms(cause.apps) ?? [t("a program")]), t(" read "), ...causeFiles(cause.files, home)];
}

/** What the secret stands for, never its token or value. A file under
 *  `home` reads `~/…`; no `home` leaves the path as recorded. `cause`: why
 *  the step that minted it masked its whole output (`maskCauses`), which
 *  names a tool's output in place of "that held a secret" (a path-derived
 *  mask is not known to hold one); a twin or a variable keeps its name.
 *  `minted`: the file of the read step that minted it (`mintedPaths`), which
 *  names a read token's file when no origin was recorded for it; a recorded
 *  origin always wins. */
export function secretWhat(f: SymbolLineage, home = "", cause: MaskCause | null = null, minted: string | null = null): StoryPart[] {
  const m = TWIN_RE.exec(f.root);
  const recorded = f.summary.originLabel ?? f.nodes.find((n) => n.symbol?.origin)?.symbol?.origin ?? null;
  const tool = m?.[2] ?? null;
  const field = m?.[3] ?? null;
  // Any agent's file read (Claude Code's `Read`, OpenCode's and OpenClaw's
  // `read`, Codex's `read_file`; tool-family.ts) names its file.
  const read = tool !== null && toolFamily(tool) === "read";
  const origin = recorded ?? (read ? minted : null);
  if (tool === "Env" || origin?.startsWith("env:")) {
    const name = field ?? origin?.slice(4) ?? null;
    return name ? [t("The environment variable "), c(name)] : [t("An environment variable")];
  }
  if (read || (!tool && origin)) {
    if (origin && field) return [c(field), t(" in "), c(tildePath(origin, home))];
    if (origin) return [t("The file "), c(tildePath(origin, home))];
    return field ? [c(field), t(" in a file")] : [t("A secret file")];
  }
  if (tool) return [t("Output of a "), c(tool), ...(cause ? [t(" step"), ...causeWhat(cause, home)] : [t(" step that held a secret")])];
  return [t("A secret item")];
}

/** A token's tool tag, with or without its level marker (symbol-format.ts
 *  `shortToolTag`: an exec or web tool's tag is its name). */
const TAG_RE = /^\$MDU:(?:(?:nomodel|localmodel|anymodel)_)?([A-Za-z0-9_]+)\[/;
/** The tools whose recorded origin is not a file (the proxies' `originFor`):
 *  a command (Claude Code's Bash and the tools that read its output, Codex's
 *  exec_command and shell tools, OpenCode's bash, OpenClaw's exec and
 *  process, Goose's shell), or a web address or query. */
const NOT_A_FILE_TOOL_RE = /^(?:Bash|BashOutput|TaskOutput|Monitor|bash|exec|exec_command|shell|shell_command|local_shell|process|WebFetch|WebSearch|webfetch|websearch|web_fetch|web_search|fetch)$/;
const URL_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

/** The short name of a masked item in a sentence: a secret twin's field
 *  (the variable or the file's key, `GITHUB_TOKEN`), an environment
 *  variable's name, else the base name of its recorded origin when that
 *  origin is a file; null otherwise. A command's or a web tool's output is
 *  never named by a piece of its origin: the tour's `set -a && . ./.env && …
 *  /v1/customers -u "$STRIPE_KEY:"` once read "your secret `customers -u
 *  "$STRIPE_KEY:"`" (dashboard.md §4.25b). Never the token. */
export function secretShortName(name: string, origin: string | null): string | null {
  const field = TWIN_RE.exec(name)?.[3] ?? null;
  if (field) return field;
  if (origin?.startsWith("env:")) return origin.slice(4) || null;
  if (!origin || NOT_A_FILE_TOOL_RE.test(TAG_RE.exec(name)?.[1] ?? "") || URL_RE.test(origin)) return null;
  return origin.replace(/\/+$/, "").split("/").pop() || null;
}

/** Tokens an event names, from its structured refs and text surfaces. */
function namesIn(e: ManduEvent): Set<string> {
  const out = new Set<string>();
  for (const r of [e.input, e.output]) {
    if (!r) continue;
    for (const s of r.symbols ?? []) out.add(s.name);
    for (const m of (r.symbolized ?? "").matchAll(SYM_RE)) out.add(m[0].replace(/\.+$/, ""));
  }
  return out;
}

/** The blocks of one line that filed an Approvals row: how many, and the
 *  row of the earliest (by its event's time; the first recorded when no
 *  time can be read). */
interface Asked {
  n: number;
  id: string;
  ts: number;
}

function addAsk(a: Asked | undefined, id: string, iso: string | undefined): Asked {
  const parsed = iso ? Date.parse(iso) : NaN;
  const ts = Number.isFinite(parsed) ? parsed : Infinity;
  return !a ? { n: 1, id, ts } : ts < a.ts ? { n: a.n + 1, id, ts } : { ...a, n: a.n + 1 };
}

interface Tally {
  sent: Map<string, number>;
  blocked: Map<string, number>;
  /** The blocks per host that filed an Approvals row. */
  blockedAsked: Map<string, Asked>;
  /** When the first send went (ISO), over every host; null when a send's
   *  event recorded no readable time (then no line says when). */
  sentFirst?: string | null;
  /** When the first block came, per host; null as for `sentFirst`. */
  blockedFirst: Map<string, string | null>;
  /** The page's step that shows the first send, by the event its time comes
   *  from (dual-lanes `stepIdOfEvent`); absent when no shown step does. */
  sentStep?: string;
  /** The same for each host's first block. */
  blockedStep: Map<string, string>;
  /** Releases or refusals recorded without a destination (the arbiter's
   *  egress queue rows, the OS gates of a call that used the token). */
  approved: number;
  /** Each release after a check (the `approved` edges), in time order:
   *  where it went (`releaseWhere`) and when, with the page's step that
   *  shows it (dashboard.md §4.25ae). */
  releases?: Array<{ ts: string | null; where: StoryPart[]; step?: string }>;
  denied: number;
  waiting: number;
  stoppedActions: number;
  /** The stopped actions that filed an Approvals row. */
  stoppedAsked?: Asked;
  replies: number;
  otherFills: number;
}

/** The earlier of two moments (ISO). `a` undefined: nothing yet. An event
 *  with no readable time makes it null for good, so "the first at" is never
 *  said of a time that may not be the first. */
function earliest(a: string | null | undefined, b: string | undefined): string | null {
  const tb = b ? Date.parse(b) : NaN;
  if (a === null || !Number.isFinite(tb)) return null;
  return a !== undefined && Date.parse(a) <= tb ? a : b!;
}

/** A host as a release's record names it: a structured `destination`, or
 *  the host its masked form sends to ("… to api.example.com"). Never a
 *  value: the masked form is what the AI wrote. */
const HOST_IN_TEXT_RE = /\bto\s+((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d{1,5})?)\b/;

/** Where one release after a check went, in plain words (dashboard.md
 *  §4.25ae): "to `api.example.com`" when its record names the host; else
 *  the kind of place by its boundary ("in a command", "to a file", "off this
 *  machine"); "to a place its record does not name" when neither is known. */
export function releaseWhere(ev: ManduEvent | undefined): StoryPart[] {
  if (!ev) return [t("to a place its record does not name")];
  const loose = ev as unknown as { destination?: unknown; target?: unknown };
  const named = [loose.destination, loose.target].find((d): d is string => typeof d === "string" && d.trim() !== "");
  const inText = typeof ev.input?.symbolized === "string" ? HOST_IN_TEXT_RE.exec(ev.input.symbolized)?.[1] : undefined;
  const host = named ?? inText;
  if (host && !host.includes("$MDU:")) return [t("to "), c(host.replace(/:443$/, ""))];
  switch (ev.boundary) {
    case "network": return [t("off this machine")];
    case "shell": return [t("in a command")];
    case "filesystem": return [t("to a file")];
    default: return [t("to a place its record does not name")];
  }
}

/** Releases a card names one by one before "and N more". */
export const RELEASES_SHOWN = 5;

/** "to `api.example.com` at 10:42; in a command at 10:43; and 2 more": each
 *  release in time order (a time a shown step shows opens it), the first
 *  RELEASES_SHOWN of them. */
function releaseList(releases: NonNullable<Tally["releases"]>, total: number): StoryPart[] {
  const timed = (r: { ts: string | null }): boolean => r.ts !== null && Number.isFinite(Date.parse(r.ts));
  const sorted = [...releases].sort((a, b) => (!timed(a) ? (timed(b) ? 1 : 0) : !timed(b) ? -1 : Date.parse(a.ts!) - Date.parse(b.ts!)));
  // Releases with no recorded time to the same place read once, counted.
  const entries: Array<{ where: StoryPart[]; ts: string | null; step?: string; n: number }> = [];
  for (const r of sorted) {
    const same = !timed(r) ? entries.find((e) => e.ts === null && words(e.where) === words(r.where)) : undefined;
    if (same) same.n++;
    else entries.push({ where: r.where, ts: timed(r) ? r.ts : null, ...(r.step ? { step: r.step } : {}), n: 1 });
  }
  const shown = entries.slice(0, RELEASES_SHOWN);
  const out: StoryPart[] = [];
  shown.forEach((r, i) => {
    if (i > 0) out.push(t("; "));
    out.push(...r.where);
    if (r.ts !== null) out.push(t(" at "), at(r.ts, r.step));
    if (r.n > 1) out.push(t(` (${r.n} times)`));
  });
  const more = total - shown.reduce((a, r) => a + r.n, 0);
  if (more > 0) out.push(t(shown.length ? `; and ${more} more` : `${plural(more, "release", "releases")} its record does not place`));
  return out;
}

const words = (parts: readonly StoryPart[]): string => parts.map((p) => p.text).join("");

/** `steps`: the ids of the steps the page shows (absent: none). */
function tally(flows: readonly SymbolLineage[], members: Set<string>, events: readonly ManduEvent[], steps?: ReadonlySet<string>): Tally {
  const x: Tally = { sent: new Map(), blocked: new Map(), blockedAsked: new Map(), blockedFirst: new Map(), blockedStep: new Map(), approved: 0, denied: 0, waiting: 0, stoppedActions: 0, replies: 0, otherFills: 0 };
  const bump = (m: Map<string, number>, k: string): void => void m.set(k, (m.get(k) ?? 0) + 1);
  // An edge's time, the Approvals row a block filed, and the step that
  // shows it are its evidence event's (lineage's eventId).
  const byId = new Map(events.map((e) => [e.id, e]));
  let sentEv: ManduEvent | undefined;
  const blockedEv = new Map<string, ManduEvent>();
  for (const e of flows.flatMap((f) => f.edges)) {
    const ev = byId.get(e.eventId);
    const ts = ev?.ts;
    if (e.kind === "egress" && e.to.startsWith("snk:net:")) {
      const dest = e.to.slice("snk:net:".length);
      if (e.verdict === "blocked" || e.verdict === "denied") {
        bump(x.blocked, dest);
        const had = x.blockedFirst.get(dest);
        const first = earliest(had, ts);
        x.blockedFirst.set(dest, first);
        if (ev && first !== null && first !== had) blockedEv.set(dest, ev);
        const ask = askIdOf(ev?.policy?.approvalId, true);
        if (ask) x.blockedAsked.set(dest, addAsk(x.blockedAsked.get(dest), ask, ts));
      } else if (e.verdict === "allowed" || e.verdict === "approved") {
        bump(x.sent, dest);
        const had = x.sentFirst;
        x.sentFirst = earliest(had, ts);
        if (ev && x.sentFirst !== null && x.sentFirst !== had) sentEv = ev;
      }
    } else if (e.kind === "egress") {
      if (e.verdict === "pending") x.waiting++;
      else if (e.verdict === "denied" || e.verdict === "blocked") x.denied++;
      else if (e.verdict === "approved" || e.verdict === "allowed") {
        x.approved++;
        const step = ev && steps ? stepIdOfEvent(ev, steps) : null;
        (x.releases ??= []).push({ ts: ts ?? null, where: releaseWhere(ev), ...(step ? { step } : {}) });
      }
    } else if (e.kind === "gated") {
      if (e.verdict === "blocked" || e.verdict === "denied") {
        x.stoppedActions++;
        const ask = askIdOf(ev?.policy?.approvalId, true);
        if (ask) x.stoppedAsked = addAsk(x.stoppedAsked, ask, ts);
      } else if (e.verdict === "pending") x.waiting++;
    }
  }
  if (steps) {
    const sentStep = sentEv ? stepIdOfEvent(sentEv, steps) : null;
    if (sentStep) x.sentStep = sentStep;
    for (const [dest, ev] of blockedEv) {
      const step = stepIdOfEvent(ev, steps);
      if (step) x.blockedStep.set(dest, step);
    }
  }
  // Every reveal, not just the one the lineage draws: the reply-filter's are
  // the person's terminal; any other is a fill on this machine.
  for (const e of events) {
    if (e.kind !== "desymbolize") continue;
    if (e.policy?.usage === "deny" || e.policy?.usage === "needs_approval") continue;
    const names = namesIn(e);
    if (![...members].some((m) => names.has(m))) continue;
    if (e.emitter === "reply-filter") x.replies++;
    else x.otherFills++;
  }
  return x;
}

/** The model requests that carried any of `members` (one entry's flows can
 *  share a request: each is counted once). */
function requestsNaming(members: Set<string>, events: readonly ManduEvent[]): number {
  let n = 0;
  for (const e of events) {
    if (e.kind !== "tllm_call") continue;
    const names = namesIn(e);
    if ([...members].some((m) => names.has(m))) n++;
  }
  return n;
}

/** When the AI read the secret as it was, before it was labelled: the first
 *  such read and the first request that carried it masked, or null. */
export interface ReadBeforeLabel {
  deliveredTs: string;
  maskedTs: string;
  /** The trace step of that first read (its dual-lanes id, which the
   *  page's turn step keeps). */
  deliveredStep: string;
}

function readBeforeLabel(vm: SessionViewModel, members: Set<string>): ReadBeforeLabel | null {
  const bases = new Set([...members].map(baseOf));
  let out: ReadBeforeLabel | null = null;
  for (const s of vm.dualLanes.steps) {
    if (s.step !== "tool" || !s.maskedLater) continue;
    if (!s.maskedLater.symbols.some((n) => bases.has(baseOf(n)))) continue;
    const { deliveredTs, ts } = s.maskedLater;
    if (!out) out = { deliveredTs, maskedTs: ts, deliveredStep: s.id };
    else {
      if (deliveredTs < out.deliveredTs) {
        out.deliveredTs = deliveredTs;
        out.deliveredStep = s.id;
      }
      if (ts < out.maskedTs) out.maskedTs = ts;
    }
  }
  return out;
}

/** What the AI got of a secret, in the order the card's first line weighs
 *  it: a fired leak check makes no claim, Off masked nothing, a level that
 *  lets the AI read it says so, a read before the label outranks the level's
 *  placeholder, and only then "masked" (`no-model`, or an unknown level,
 *  read fail-closed). The tiles count by the same answer, so they never
 *  claim more than the card. */
export function aiSaw(level: string, early: boolean, flagged: boolean, mode: ProtectionMode | null): AiSaw {
  if (flagged) return "flagged";
  if (mode === "off") return "off";
  if (level === "any-model") return "readable";
  if (early) return "early";
  if (level === "local-model") return "own-model";
  return "masked";
}

/** `steps`: the ids of the steps the page shows; a time one of them shows
 *  carries its id (absent: none does, as on Home). */
function linesOf(level: string, requests: number, early: ReadBeforeLabel | null, x: Tally, flagged: boolean, mode: ProtectionMode | null, steps?: ReadonlySet<string>, dev = true): SecretLine[] {
  const lines: SecretLine[] = [];
  const inRequests = requests > 0 ? `, in ${plural(requests, "request", "requests")}` : "";
  // What the AI got.
  const saw = aiSaw(level, early !== null, flagged, mode);
  if (saw === "flagged") {
    lines.push(flaggedLine(dev));
  } else if (saw === "off") {
    lines.push({ tone: "warn", parts: [t("Protection was off, so Mandu did not mask it.")] });
  } else if (saw === "readable") {
    lines.push({ tone: "plain", parts: [t("Its level lets the AI read it.")] });
  } else if (saw === "early" && early) {
    // Read as it was before the label: never "never the real value", and
    // never "only a placeholder" after it: the AI's own replies go back to
    // it as written (confidentiality.md §7.1, the residual).
    lines.push({ tone: "warn", parts: [
      t("The AI read its real value at "), at(early.deliveredTs, steps?.has(early.deliveredStep) ? early.deliveredStep : null), t(", before it was marked a secret. From "),
      at(early.maskedTs), t(` on it got a placeholder in its place${inRequests}.`),
    ] });
    if (requests > 0) lines.push({ tone: "warn", parts: [t("Anything the AI wrote from its real value went back to the AI as written with each later request: Mandu does not mask the AI's own words.")] });
    if (level === "local-model") lines.push({ tone: "plain", parts: [t("Its level lets only your own model read it. An outside AI gets a placeholder.")] });
  } else if (saw === "own-model") {
    lines.push({ tone: "plain", parts: [t("Its level lets only your own model read it. An outside AI gets a placeholder.")] });
  } else {
    lines.push({ tone: "good", parts: [t("The AI got only a placeholder, never the real value." + (requests > 0 ? ` It went to the AI that way in ${plural(requests, "request", "requests")}.` : ""))] });
  }
  // Where Mandu filled in the real value, and where it blocked a send: each
  // line says when, and they run in the order they happened, so a block and
  // a later send to the same place read as a story, not as "allowed" over
  // "blocked".
  const sentTo = [...x.sent.keys()];
  const other = x.approved + x.otherFills;
  const sendLine: TimedLine[] = [];
  if (sentTo.length) {
    const sends = [...x.sent.values()].reduce((a, b) => a + b, 0);
    sendLine.push({ ts: x.sentFirst ?? null, line: { tone: "plain", parts: [
      t(other ? "Mandu sent its real value to " : "Mandu sent its real value only to "), ...listParts(sentTo),
      t(` (${plural(sends, "request", "requests")}`), ...when(sends, x.sentFirst, x.sentStep), t("), where it was allowed to go."),
    ] } });
  }
  const blockLines: TimedLine[] = [...x.blocked].map(([dest, n]) => ({ ts: x.blockedFirst.get(dest) ?? null, line: { tone: "good", parts: [
    t(`Mandu blocked ${plural(n, "attempt", "attempts")} to send it to `), c(dest), ...when(n, x.blockedFirst.get(dest), x.blockedStep.get(dest)),
    ...askedParts(n, x.blockedAsked.get(dest)),
    t(n === 1 ? ". The request never left this machine." : ". None of them left this machine."),
  ] } }));
  if (sentTo.length) lines.push(...inTimeOrder([...sendLine, ...blockLines]));
  if (x.approved) {
    // Where each release went, and when (dashboard.md §4.25ae), in every
    // build: the first RELEASES_SHOWN in time order, then how many more.
    const released = `Mandu released it ${plural(x.approved, "more time", "more times")} after a check: `;
    lines.push({ tone: "plain", parts: [t(released), ...releaseList(x.releases ?? [], x.approved), t(".")] });
  }
  if (x.otherFills) lines.push({ tone: "plain", parts: [t(`Mandu put its real value back ${plural(x.otherFills, "time", "times")} for a step on this machine.`)] });
  if (!sentTo.length && !other && mode !== "off") lines.push({ tone: "good", parts: [t("Mandu did not fill in its real value for any request off this machine.")] });
  // What Mandu stopped (beside the sends above when there were any).
  if (!sentTo.length) lines.push(...inTimeOrder(blockLines));
  if (x.denied) lines.push({ tone: "good", parts: [t(`Mandu refused to release it ${plural(x.denied, "time", "times")}.`)] });
  if (x.stoppedActions) lines.push({ tone: "good", parts: [t(`Mandu stopped ${plural(x.stoppedActions, "action", "actions")} that used it`), ...askedParts(x.stoppedActions, x.stoppedAsked), t(".")] });
  if (x.waiting) lines.push({ tone: "warn", parts: [t(`${plural(x.waiting, "step that uses it is", "steps that use it are")} waiting for your OK.`)] });
  // Where the person saw it.
  if (x.replies) lines.push({ tone: "plain", parts: [t(`You saw its real value in the agent's ${x.replies === 1 ? "reply" : "replies"}. The AI kept the placeholder.`)] });
  return lines;
}

/** The lines of a file labelled after the session read it as it was
 *  (*Labelled after the session*): no placeholder of it was ever in this
 *  session, so nothing is said of sends, fills or blocks (the AI had the
 *  value itself; "Mandu did not fill in its real value" would read as a
 *  safety claim). What the AI got, when, and when the label came. */
function afterLines(level: string, after: NonNullable<SecretEntry["after"]>, saw: AiSaw, steps?: ReadonlySet<string>, dev = true): SecretLine[] {
  if (saw === "flagged") return [flaggedLine(dev)];
  const read = at(after.readTs, steps?.has(after.readStep) ? after.readStep : null);
  if (saw === "off") return [{ tone: "warn", parts: [t("Protection was off, so Mandu did not mask it. The AI read it at "), read, t(". It was marked a secret at "), at(after.at), t(".")] }];
  const lines: SecretLine[] = [
    { tone: "warn", parts: [t("The AI read its real value at "), read, t(", before it was marked a secret at "), at(after.at), t(", so nothing in this session masked it.")] },
    { tone: "warn", parts: [t("If it holds a key or a password, change it: the AI saw it as it was.")] },
  ];
  if (level === "local-model") lines.push({ tone: "plain", parts: [t("Its level lets only your own model read it. An outside AI gets a placeholder.")] });
  return lines;
}

interface SecretEntry {
  what: StoryPart[];
  level: string;
  flows: SymbolLineage[];
  /** Every token the entry's flows recorded. */
  members: Set<string>;
  early: ReadBeforeLabel | null;
  /** A file labelled after the session read it as it was, and never masked
   *  in it (later-labels.ts): the first such read and the label's time. Such
   *  an entry has no flows, so no placeholder. */
  after?: { readTs: string; readStep: string; at: string };
}

/** The labels in force now with their times (later-labels.ts `LabelTime`;
 *  empty: none) and the session's folder, which a relative Read's path is
 *  placed in (a later label's file, and a read token's file, `mintedPaths`). */
export interface LaterLabelInput {
  labels: readonly LabelTime[];
  cwd: string | null;
}

/** Why each token's result was masked whole, by base name: the note of the
 *  first tool step whose result held it (the step that minted it), read by
 *  secret-note.ts `maskCause`, the session page's rule for that step. A
 *  token whose first result's note gives no such reason, or that result
 *  only echoed from the AI's own call (held-tokens.ts), is absent, so its
 *  card keeps its words. Names and paths only, never a value. */
function maskCauses(vm: SessionViewModel): Map<string, MaskCause> {
  const out = new Map<string, MaskCause>();
  const seen = new Set<string>();
  for (const s of vm.dualLanes.steps) {
    if (s.step !== "tool") continue;
    const cause = maskCause(s.secretNote);
    const kept = new Set(cause ? heldTokens(s) : []);
    for (const m of tokensIn(s.resultAgent ?? "")) {
      const base = baseOf(m.name);
      if (seen.has(base)) continue;
      seen.add(base);
      if (cause && kept.has(m.name)) out.set(base, cause);
    }
  }
  return out;
}

/** The file each read token was minted from, by base name, absolute: the
 *  first tool step whose result held it (the rule of `maskCauses`), when that
 *  step is a file read (tool-family.ts), the token is one it kept from the
 *  AI (held-tokens.ts: not one the call echoed back), and its file can be
 *  placed (later-labels.ts `readStepPath`: absolute, `~/…`, or relative to
 *  the session's folder `cwd`). A token first held elsewhere, or a path that
 *  cannot be placed, is absent, so its card keeps "in a file" and never
 *  names the wrong file (dashboard.md §4.25b). Paths only, never a value. */
function mintedPaths(vm: SessionViewModel, cwd: string | null, home: string): Map<string, string> {
  const out = new Map<string, string>();
  const seen = new Set<string>();
  for (const s of vm.dualLanes.steps) {
    if (s.step !== "tool") continue;
    const held = tokensIn(s.resultAgent ?? "");
    if (!held.length) continue;
    const read = toolFamily(s.tool) === "read";
    const kept = new Set(read ? heldTokens(s) : []);
    const path = read ? readStepPath(s, cwd, home) : null;
    for (const m of held) {
      const base = baseOf(m.name);
      if (seen.has(base)) continue;
      seen.add(base);
      if (path && kept.has(m.name)) out.set(base, path);
    }
  }
  return out;
}

/** One entry per thing a secret stands for, at one level: a file masked to
 *  two tokens (a re-read, the history re-send of a result labelled after
 *  the fact) is one secret, in the order it first appears. Command outputs
 *  masked for different reasons are different things; for the same one,
 *  one. */
function secretEntries(believed: SessionViewModel | null, home: string, later?: LaterLabelInput): SecretEntry[] {
  const flows = believed ? believed.lineage.flows.filter((f) => isSecretFlow(f) && !f.summary.modelAuthored) : [];
  const causes = believed ? maskCauses(believed) : new Map<string, MaskCause>();
  const minted = believed ? mintedPaths(believed, later?.cwd ?? null, home) : new Map<string, string>();
  const groups = new Map<string, { what: StoryPart[]; level: string; flows: SymbolLineage[] }>();
  for (const f of flows) {
    const what = secretWhat(f, home, causes.get(baseOf(f.root)) ?? null, minted.get(baseOf(f.root)) ?? null);
    const level = levelOf(f);
    const key = level + "\u0000" + JSON.stringify(what);
    const g = groups.get(key);
    if (g) g.flows.push(f);
    else groups.set(key, { what, level, flows: [f] });
  }
  const entries: SecretEntry[] = [...groups.values()].map((g) => {
    const members = new Set<string>();
    for (const f of g.flows) {
      for (const n of f.nodes) if (n.kind === "symbol" && n.symbol) members.add(n.symbol.name);
      members.add(f.root);
    }
    const early = believed ? readBeforeLabel(believed, members) : null;
    return { ...g, members, early };
  });
  return believed && later?.labels.length ? withLaterLabels(entries, believed, home, later) : entries;
}

/** The files the rule-change log says were labelled after this session read
 *  them as they were (later-labels.ts): an entry that already tells of the
 *  file (a later read of it masked) learns of the earlier read, so it never
 *  says "never the real value"; any other file gets an entry of its own,
 *  with no placeholder. A file is known by its recorded origin, placed as a
 *  Read's path is. */
function withLaterLabels(entries: SecretEntry[], vm: SessionViewModel, home: string, later: LaterLabelInput): SecretEntry[] {
  const out = [...entries];
  const fileOf = (f: SymbolLineage): string | null => {
    const origin = f.summary.originLabel ?? f.nodes.find((n) => n.symbol?.origin)?.symbol?.origin ?? null;
    return origin ? readPath(origin, later.cwd, home) : null;
  };
  for (const l of laterLabels(plainReads(vm, later.cwd, home), later.labels)) {
    const first = l.reads[0]!;
    const known = out.find((e) => e.flows.some((f) => fileOf(f) === l.path));
    if (known) {
      if (!known.early) known.early = { deliveredTs: first.ts, maskedTs: firstMasked(vm, known.members) ?? l.at, deliveredStep: first.stepId };
      else if (first.ts < known.early.deliveredTs) known.early = { ...known.early, deliveredTs: first.ts, deliveredStep: first.stepId };
      continue;
    }
    out.push({
      what: [t("The file "), c(tildePath(l.path, home))], level: l.level, flows: [], members: new Set(), early: null,
      after: { readTs: first.ts, readStep: first.stepId, at: l.at },
    });
  }
  return out;
}

/** When the AI first got one of `members` as a placeholder: the first tool
 *  result that held one. Null: none recorded. */
function firstMasked(vm: SessionViewModel, members: Set<string>): string | null {
  const bases = new Set([...members].map(baseOf));
  for (const s of vm.dualLanes.steps) {
    if (s.step === "tool" && tokensIn(s.resultAgent ?? "").some((m) => bases.has(baseOf(m.name)))) return s.ts;
  }
  return null;
}

/**
 * The tokens of each secret whose card says the AI read it as it was before
 * its label (`aiSaw` "early"), by base name, each with the moment the AI
 * read it (the card's first time). The session page's turns say the same
 * of the secret's chips and of a reply that held it (agent-page.ts), so a
 * turn and the card never disagree: where the card makes no such claim (a
 * fired leak check, Off, a level that lets the AI read it), neither does a
 * turn. Times and token names only, never a value; the page's data carries
 * the times, never the tokens. Arguments as `secretsStory`. Pure.
 */
export function earlyReads(believed: SessionViewModel | null, flagged: boolean, mode: ProtectionMode | null, home = "", later?: LaterLabelInput): Map<string, string> {
  const anyFlag = flagged || (believed ? !believed.invariant.holds : false);
  const out = new Map<string, string>();
  for (const g of secretEntries(believed, home, later)) {
    if (!g.early || aiSaw(g.level, true, anyFlag, mode) !== "early") continue;
    for (const m of g.members) {
      const base = baseOf(m);
      const had = out.get(base);
      if (had === undefined || g.early.deliveredTs < had) out.set(base, g.early.deliveredTs);
    }
  }
  return out;
}

/**
 * "Your secrets in this session". `believed`: the view-model of the believed
 * events only (null: none); `events`: those events; `flagged`: the full
 * view-model's leak check fired; `home`: the folder a file's path is
 * shortened to `~/…` under (absent: paths as recorded); `steps`: the ids of
 * the steps the page shows, so a time one of them shows opens it (absent:
 * no time does, as on Home); `opts`: how many it lists, and whether the
 * build serves the developer view (StoryOptions).
 */
export function secretsStory(believed: SessionViewModel | null, events: readonly ManduEvent[], flagged: boolean, mode: ProtectionMode | null, home = "", steps?: ReadonlySet<string>, later?: LaterLabelInput, opts: StoryOptions = {}): SecretsStory {
  const anyFlag = flagged || (believed ? !believed.invariant.holds : false);
  const entries = secretEntries(believed, home, later);
  const cap = opts.cap ?? SECRET_CAP;
  const dev = opts.dev !== false;
  const secrets = entries.slice(0, cap).map((g): StorySecret => {
    const saw = aiSaw(g.level, g.early !== null || g.after !== undefined, anyFlag, mode);
    if (g.after) {
      return { what: g.what, level: levelTerm(g.level), saw, ...(saw === "early" ? { since: g.after.at } : {}), lines: afterLines(g.level, g.after, saw, steps, dev) };
    }
    // One flow keeps the lineage's own count; merged flows count each request once.
    const requests = g.flows.length === 1 ? g.flows[0]!.summary.contextTurns : requestsNaming(g.members, events);
    return {
      what: g.what, level: levelTerm(g.level), saw, ...(saw === "early" && g.early ? { since: g.early.maskedTs } : {}),
      lines: linesOf(g.level, requests, g.early, tally(g.flows, g.members, events, steps), anyFlag, mode, steps, dev), ref: secretRef(believed?.sessionId ?? "", g.flows[0]!.root),
    };
  });
  const counts = { masked: 0, early: 0 };
  for (const g of entries) {
    const saw = aiSaw(g.level, g.early !== null || g.after !== undefined, anyFlag, mode);
    if (saw === "masked" || saw === "early") counts[saw]++;
  }
  return { mode, flagged: anyFlag, secrets, more: Math.max(0, entries.length - cap), counts };
}
