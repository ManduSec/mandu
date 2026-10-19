/**
 * view-model/ask-words — one waiting question (an approval-queue row) in the
 * product's words: its sentence and the three cells of the Approvals card
 * (why it stopped, what the AI has now, what happens if you click Allow once
 * or Always allow). Mandu-new (no reference origin).
 *
 * Shared by both front-ends (dashboard.md §4.34): the product home
 * (view-model/home.ts, `/api/home`) and the developer view's Approvals page,
 * which reads the same words off `/api/policy/panel` (policy-panel.ts stamps
 * them on each queue row), so the two cards cannot drift. Pure, no I/O.
 *
 * VOCABULARY: the product's words (home-copy.test.ts, the §4.18 sweep):
 * never symbol, egress, invariant, AgentView, HumanView, T-LLM or `$MDU:`.
 */

import type { QueueRowVM } from "./policy-panel-types.js";
import { tildePath } from "./file-browser.js";

/** A sentence fragment: plain text, or a value the page renders as code. */
export interface HomeTextPart {
  kind: "text" | "code";
  text: string;
}

export type HomeAskFamily = "send" | "run" | "read" | "show" | "prompt" | "other";

/** A question in plain words: the family (the card's icon and answers), the
 *  sentence, and the card's three cells. */
export interface AskWords {
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
  /** The three cells as parts, each name in them (a secret, a file, a host,
   *  a program) as code, as the sentence names it (dashboard.md §4.25u,
   *  *The cells name things as the headline does*). Their text is exactly
   *  `why`, `aiNow` and `ifAllowed`, which stay for the developer view and
   *  an older page. */
  whyParts: HomeTextPart[];
  aiNowParts: HomeTextPart[];
  ifAllowedParts: HomeTextPart[];
  /** A held message under a locked administrator's `ask` row (plan 15 §12,
   *  2026-10-04): why the answers cover this message only. Absent otherwise. */
  onlyThisMessage?: string;
}

/** What the person does after answering a stopped action (dashboard.md
 *  §4.34 "After you answer"): the gates refuse the attempt and tell the
 *  agent to wait for the person (the proxies' notes: "tell the user, and do
 *  not retry before they answer"), and the agent cannot see the answer, so
 *  nothing tries again until the person says so. */
export const TELL_AGENT = "After you answer, tell the agent to try again.";

/** Why a held message takes an answer for this message only (plan 15 §12,
 *  2026-10-04), in the product's words; both front ends show it. */
export const ONLY_THIS_MESSAGE =
  "Your administrator set this to ask every time, so your answer covers this message only. Mandu asks again the next time a message holds it.";

function t(text: string): HomeTextPart {
  return { kind: "text", text };
}
function c(text: string): HomeTextPart {
  return { kind: "code", text };
}

/** A cell's words as written: plain text, or parts that name things as code. */
type Cell = string | HomeTextPart[];
/** An ask as the families build it: `AskWords` with each cell a `Cell`. */
type AskCells = Omit<AskWords, "why" | "aiNow" | "ifAllowed" | "whyParts" | "aiNowParts" | "ifAllowedParts"> & {
  why: Cell;
  aiNow: Cell;
  ifAllowed: Cell;
};

/** A cell's sentence as parts: `` w`${c(file)} is a secret file.` ``. A part
 *  or a list of parts is spliced in as it is (a name stays code), any other
 *  value is text; neighbouring text is joined. Parts are copied, never
 *  changed, so a list the sentence also uses is left as it was. */
function w(strings: TemplateStringsArray, ...values: Array<Cell | HomeTextPart>): HomeTextPart[] {
  const out: HomeTextPart[] = [];
  const add = (p: HomeTextPart): void => {
    if (p.text === "") return;
    const last = out[out.length - 1];
    if (p.kind === "text" && last !== undefined && last.kind === "text") out[out.length - 1] = t(last.text + p.text);
    else out.push({ ...p });
  };
  strings.forEach((s, i) => {
    add(t(s));
    if (i >= values.length) return;
    const v = values[i]!;
    if (typeof v === "string") add(t(v));
    else for (const p of Array.isArray(v) ? v : [v]) add(p);
  });
  return out;
}

/** `items` joined by `sep` (text), as one list of parts. */
function joinParts(items: readonly Cell[], sep: string): HomeTextPart[] {
  return items.flatMap((x, i) => [...(i > 0 ? [t(sep)] : []), ...(typeof x === "string" ? [t(x)] : x)]);
}

/** A cell as the card sends it: its text, and its parts. */
function cellOf(x: Cell): { text: string; parts: HomeTextPart[] } {
  const parts = typeof x === "string" ? [t(x)] : x;
  return { text: parts.map((p) => p.text).join(""), parts };
}

/** The families' words as the card sends them: each cell's text (the
 *  string the developer view reads) and its parts. */
function withParts(a: AskCells): AskWords {
  const why = cellOf(a.why);
  const aiNow = cellOf(a.aiNow);
  const ifAllowed = cellOf(a.ifAllowed);
  return {
    ...a,
    why: why.text,
    aiNow: aiNow.text,
    ifAllowed: ifAllowed.text,
    whyParts: why.parts,
    aiNowParts: aiNow.parts,
    ifAllowedParts: ifAllowed.parts,
  };
}
/** The last path segment of a file path, for the sentence; the full path is
 *  kept out of the one-liner (the page shows it on demand). */
function basename(p: string): string {
  const s = p.replace(/\/+$/, "");
  const i = s.lastIndexOf("/");
  return i >= 0 ? s.slice(i + 1) || s : s;
}

/** The program a binary verdict's subject names, without the hash: the
 *  arbiter's `binaryVerdictSubject` (arbiter/policy/flow-taint.ts) writes
 *  `<exe>#<64 hex>`, or `<exe>#` for an unhashed path that ends like one;
 *  for an interpreter (plan 13 §8 decision (c)) it adds
 *  `#script:<path, URI-encoded>#<64 hex>` or `#run:<proc key>`. */
export function binaryOfSubject(rest: string): string {
  return programOfSubject(rest).binary;
}

/** The parts of a binary verdict's subject after its kind: the binary, and
 *  (decision (c)) the script an interpreter runs or whether it names one run
 *  of an interpreter running no pinned script. */
export function programOfSubject(rest: string): { binary: string; script?: string; run?: boolean } {
  const run = /#run:[^#]*$/.exec(rest);
  if (run) return { binary: rest.slice(0, run.index).replace(/#(?:[0-9a-f]{64})?$/, ""), run: true };
  const script = /#script:([^#]*)#[0-9a-f]{64}$/.exec(rest);
  if (script) {
    let path = script[1]!;
    try { path = decodeURIComponent(path); } catch { /* shown as written */ }
    return { binary: rest.slice(0, script.index).replace(/#(?:[0-9a-f]{64})?$/, ""), script: path };
  }
  return { binary: rest.replace(/#(?:[0-9a-f]{64})?$/, "") };
}

/** The program as the Approvals card names it: the binary, and the script
 *  an interpreter runs, or that it runs code no pin names (decision (c)).
 *  Under `home` (the product pages', the dashboard's home folder) each path
 *  reads `~/…`; the inspector passes none and keeps full paths (dashboard.md
 *  §4.34 "`~` is the dashboard's home"). */
function programWords(rest: string, home = ""): string {
  const p = programOfSubject(rest);
  const binary = p.binary ? tildePath(p.binary, home) : "a program";
  return p.script !== undefined ? `${binary} running ${tildePath(p.script, home)}` : p.run ? `${binary} running its own code` : binary;
}

/** "Claude Code's", "The agent's": the agent a program runs for, so a card
 *  about a program still says which agent asked (dashboard.md §4.34 "After
 *  you answer"). */
function possessive(who: string): string {
  return who.endsWith("s") ? `${who}'` : `${who}'s`;
}

/** What Allow does to a held open or change (`open:`, `trust:`, `write:`).
 *  The guard holds the program for a while (the launcher's ask timeout, 60 s
 *  by default) and asks again every half second, then refuses it and leaves
 *  the question waiting. While it holds, Allow lets the same program go on;
 *  after, only the next try. `held` comes from the row's last ask; not
 *  known (the inspector), the words claim neither. */
function heldWords(held: boolean | undefined, program: string, does: string, couldNot: string): HomeTextPart[] {
  if (held === true) return w`The AI's program ${c(program)} is waiting for your answer now, and goes on at once: it ${does}.`;
  if (held === false) return w`The AI's program ${c(program)} stopped waiting and ${couldNot}. If you allow it, it ${does} the next time the AI runs it. ${TELL_AGENT}`;
  return w`The AI's program ${c(program)} ${does}.`;
}

/** What the masked item's subject reads as in plain words. The queue row's
 *  subject is a symbol-table key (`$MDU:Read[9c].content`, `fs:Read:r`,
 *  `open:cat`); the product never shows it raw. */
function itemWords(subject: string): string {
  const m = /^\$MDU:([A-Za-z_][A-Za-z0-9_]*)\[/.exec(subject);
  if (m) {
    const tool = m[1]!;
    if (/^(?:no|any|local)model_/.test(tool)) return "a secret"; // the confidentiality markers (symbol-format.ts)
    if (/^(Read|read_file|fs)/i.test(tool)) return "text from a file";
    if (/^(WebFetch|fetch|web|http|curl)/i.test(tool)) return "text from a web page";
    if (/^(Bash|exec|shell)/i.test(tool)) return "a command's output";
    return "masked text";
  }
  return "masked text";
}

/** A secret's own symbol: the confidentiality marker, the tool, and the field
 *  a registered secret file's value got its own symbol for
 *  (`$MDU:nomodel_Read[9bbd].STRIPE_KEY`, the registry's field rows), as
 *  secret-story.ts reads a twin (`TWIN_RE`). */
const SECRET_SYMBOL_RE = /^\$MDU:(?:no|any|local)model_([A-Za-z0-9_]+)\[[0-9a-f]{4,8}\](?:\.(.+))?$/;

/** Fields that say where in a result a value sat, or number an extraction
 *  (`extract_3`, secret-extract.ts), not which key it is. */
const NOT_A_NAME_RE = /^(?:content|text|body|output|result|stdout|stderr|data|extract_\d+)$/;

/** Which secret a send would carry: its own name when it has one (a key of
 *  a registered file, the symbol's field; an environment variable, the
 *  origin `env:NAME`), and the file it came from (the arbiter's read-time
 *  `source.origin`, a path). Null for what is not known. Provenance only:
 *  never the token, never the value (dashboard.md §4.34 "A send names its
 *  secret").
 *
 *  A field is a key's name only beside the file it came from, and only on a
 *  `Read` row: the registry mints `KEY`, `default.aws_secret_access_key`,
 *  `DATABASE_URL.password` (secret-extract.ts), `.encoded` marking the
 *  decoded value of that same key. fs-sync names a file's symbol by its
 *  path instead (`notes.md`, or an encoded `__mdu_field_…` one with a `/`),
 *  and a human edit's pieces `….__mdu_split[n]`: none of those is a name. */
export function secretOf(subject: string, origin: string | null | undefined): { name: string | null; file: string | null } {
  const m = SECRET_SYMBOL_RE.exec(subject);
  if (!m) return { name: null, file: null };
  const o = typeof origin === "string" ? origin.trim() : "";
  if (o.startsWith("env:")) return { name: o.slice(4) || null, file: null };
  if (!o.startsWith("/")) return { name: null, file: null };
  const field = m[1] === "Read" && m[2] ? m[2].replace(/\.encoded$/, "") : "";
  const isName = field !== "" && !field.includes("__mdu_") && !NOT_A_NAME_RE.test(field)
    && field !== o && !o.endsWith("/" + field);
  return { name: isName ? field : null, file: o };
}

/** What the AI has now when it read the item as it was before it was masked
 *  (the row's `readFirst`, dashboard.md §4.34 "Read before it was marked"):
 *  never "never read", and never "only the masked version" alone, since the
 *  AI's own words go back to it as written (confidentiality.md §7.1). */
function readFirstNow(secret: boolean): string {
  return secret
    ? "The AI read the real value before it was marked a secret. Since then it gets the masked version, but Mandu does not mask what the AI wrote itself."
    : "The AI read the real text before Mandu masked it. Since then it gets the masked version, but Mandu does not mask what the AI wrote itself.";
}

/** What the AI has now when a program asks to read a secret file the AI
 *  read as it was before it was marked (the row's `readFirst`, looked up by
 *  the file, §4.34): never "has not seen the real file". */
function fileReadFirstNow(program: string): HomeTextPart[] {
  return w`The AI read the file as it was before it was marked a secret, and its program ${c(program)} has not read it. Since then the AI gets the masked version, but Mandu does not mask what the AI wrote itself.`;
}

/** The target of a HIGH session's network ask whose call named no place (a
 *  web search): the arbiter's `UNNAMED_DESTINATION` (session-approvals.ts). */
const UNNAMED_DESTINATION = "(no destination named)";

/** What a HIGH session read, by name (confidentiality.md §4, "What the card
 *  says"): a registered key's name, else the file (`~/…` under `home`),
 *  deduplicated, in the arbiter's order. Provenance only, never a value. */
function sessionReadNames(reads: QueueRowVM["sessionReads"], home: string): string[] {
  const out: string[] = [];
  for (const r of reads ?? []) {
    const s = secretOf(r.symbol, r.origin);
    const label = s.name ?? (s.file !== null ? tildePath(s.file, home) : null);
    if (label !== null && !out.includes(label)) out.push(label);
  }
  return out;
}

/** "a, b and c" as sentence parts, each name as code, with "and N more"
 *  for what is not named; "a secret" when nothing is. */
function namesParts(names: readonly string[], more: number): HomeTextPart[] {
  if (names.length === 0) return [t(more > 1 ? `${more} secrets` : "a secret")];
  const parts: HomeTextPart[] = [];
  const items: HomeTextPart[] = names.map((n) => c(n));
  if (more > 0) items.push(t(`${more} more`));
  items.forEach((p, i) => {
    if (i > 0) parts.push(t(i === items.length - 1 ? " and " : ", "));
    parts.push(p);
  });
  return parts;
}

/** The files a holder's send question names (`holder-send:{"session":…,
 *  "files":[…]}`, the arbiter's holder-send-ask.ts), and its session; null
 *  for any other subject. */
export function holderSendOf(subject: string): { session: string | null; files: string[] } | null {
  if (typeof subject !== "string" || !subject.startsWith("holder-send:")) return null;
  try {
    const v = JSON.parse(subject.slice("holder-send:".length)) as { session?: unknown; files?: unknown };
    if (!v || !Array.isArray(v.files) || v.files.length === 0 || !v.files.every((f) => typeof f === "string" && f !== "")) return null;
    return { session: typeof v.session === "string" && v.session !== "" ? v.session : null, files: v.files as string[] };
  } catch {
    return null;
  }
}

/** How many files a holder's sentence names before "and N more". */
const HOLDER_FILES_SHOWN = 4;

/** One file of a holder's send question on the card (confidentiality plan
 *  13 §5.4): its name (`~/…` on the product pages), where it may go now,
 *  whether it is in the way, and its *Always* (the button's words) or why
 *  it has none. */
export interface HolderSourceWords {
  /** The file as the arbiter names it: what the *Always* sends back. */
  path: string;
  /** The file, `~/…` under the page's home; a folder rule: its path. */
  name: string;
  /** `name` as parts: the file as code, a folder rule's "files in " as
   *  text before it, as the card's cells name it (dashboard.md §4.25u,
   *  *Approvals names things whole*). */
  nameParts: HomeTextPart[];
  /** The copy the program read, when this file is one of its sources. */
  via?: string;
  /** "may go to: api.stripe.com, *.amazonaws.com", "may go nowhere". */
  mayGo: string;
  /** `mayGo` as parts, each host as code. */
  mayGoParts: HomeTextPart[];
  blocks: boolean;
  /** The button: "Always: add hooks.slack.com to .env". Absent: none. */
  always?: string;
  /** Why a file in the way takes no *Always* here, in words. */
  noAlways?: string;
}

/** Why a file in the way takes no *Always* (holder-send-ask.ts
 *  `NoAlwaysReason`), in the product's words. */
function noAlwaysWords(reason: string | undefined): string {
  switch (reason) {
    case "folder-rule": return "Its rule covers a whole folder, so Mandu does not change it from here. Change it under Rules.";
    case "page-rule": return "Its rule was made on the Rules page before rules lived in your rules file. Change it under Rules.";
    case "not-secret": return "It is no longer marked secret, so Mandu does not know where the copy may go. Mark it under Rules.";
    case "unknown-origin": return "Mandu does not know which file this copy came from, so it may go nowhere.";
    case "session-value": return "The AI read it in its conversation; it goes where that secret may go.";
    case "pattern-name": return "Its name reads as a pattern, so Mandu does not write a rule for it from here. Change it under Rules.";
    case "per-value": return "Each value in it has its own hosts, and the whole file may go only where every value may. Add the host to the values in your rules file.";
    default: return "Mandu cannot add a place to its rule from here. Change it under Rules.";
  }
}

/** The files of a holder's send question as the card lists them, with one
 *  *Always* per file in the way (plan 13 §5.4, §9 R2). */
export function holderSourceWords(sources: QueueRowVM["holderSources"], target: string, home = ""): HolderSourceWords[] {
  return (sources ?? []).map((s) => {
    const name = cellOf(s.rule ? w`files in ${c(tildePath(s.path, home))}` : [c(tildePath(s.path, home))]);
    const hosts = s.bindings.filter((b) => b !== "");
    const mayGo = cellOf(hosts.length ? w`may go to: ${joinParts(hosts.map((h) => [c(h)]), ", ")}` : "may go nowhere");
    return {
      path: s.path,
      name: name.text,
      nameParts: name.parts,
      ...(s.via ? { via: tildePath(s.via, home) } : {}),
      mayGo: mayGo.text,
      mayGoParts: mayGo.parts,
      blocks: s.blocks,
      ...(s.blocks && s.always ? { always: `Always: add ${target} to ${basename(s.path)}` } : {}),
      ...(s.blocks && !s.always ? { noAlways: noAlwaysWords(s.noAlways) } : {}),
    };
  });
}

/** "Still in the way: customers.csv." once some file of a holder's
 *  question may go and some may not (after an *Always*), else "". */
export function holderLeftWords(sources: QueueRowVM["holderSources"], target: string, home = ""): string {
  return holderLeftParts(sources, target, home).map((p) => p.text).join("");
}

/** `holderLeftWords` as parts: the place and each file left as code, as
 *  the card's cells name them; no line, no parts. */
export function holderLeftParts(sources: QueueRowVM["holderSources"], target: string, home = ""): HomeTextPart[] {
  const all = sources ?? [];
  const left = all.filter((s) => s.blocks);
  if (left.length === 0 || left.length === all.length) return [];
  return w`The send goes once every file may go to ${c(target)}. Still in the way: ${joinParts(left.map((s) => [c(tildePath(s.path, home))]), ", ")}.`;
}

/**
 * A holder's send (confidentiality plan 13 §5.4, §9 R2, 2026-10-11): a
 * program that read several secret files may send only where every one of
 * them may go, and the destination is not such a place. The card names
 * every file it holds and which are in the way; the answers are Allow once,
 * Allow this session (when the row names its session), Block, and one
 * *Always* per file in the way (`holderSourceWords`).
 */
function holderAsk(
  v: Pick<QueueRowVM, "subject" | "target"> & Partial<Pick<QueueRowVM, "holderSources">>,
  held: { session: string | null; files: string[] },
  who: string,
  home: string,
): AskCells {
  const place = v.target || "an unknown place";
  // In the cells a place is code when it is one (the sentence's as before).
  const at: Cell = v.target ? [c(v.target)] : place;
  const names = held.files.slice(0, HOLDER_FILES_SHOWN).map((f) => tildePath(f, home));
  const more = Math.max(0, held.files.length - names.length);
  const these = held.files.length === 1 ? "it" : "every one of them";
  const blockers: Cell[] = (v.holderSources ?? []).filter((s) => s.blocks).map((s) => (s.rule ? w`files in ${c(tildePath(s.path, home))}` : [c(tildePath(s.path, home))]));
  const many = held.files.length > 1;
  return {
    family: "send",
    sentence: [t(`${possessive(who)} program wants to send data from `), ...namesParts(names, more), t(" to "), c(place)],
    why: blockers.length > 0
      ? w`A program that read ${many ? "these files" : "this file"} may send only where ${these} may go, and ${joinParts(blockers, ", ")} may not go to ${at}.`
      : w`A program that read ${many ? "these files" : "this file"} may send only where ${these} may go, and ${at} is not such a place.`,
    aiNow: w`The AI's program has not sent anything: Mandu refused its connection to ${at}.`,
    ifAllowed: w`Allow once lets the program's next connection to ${at} go, with what it read.${held.session !== null ? " Allow this session lets it go for the rest of this session." : ""} Always adds ${at} to where one file may be sent; once every file may go there, the program sends without asking. ${TELL_AGENT}`,
  };
}

/**
 * A HIGH session's ask (confidentiality.md §4, "The human half",
 * 2026-10-11): the session read secret content into the AI's conversation,
 * so a request to a place none of it may go (`session-net:<session>` ×
 * host), or a command Mandu cannot prove stays off the network
 * (`session-exec:<session>` × the command), may carry it in the AI's own
 * words. The card names what the session read, the place or the command,
 * and that the request may carry text derived from it. The answers are
 * Allow once and Block (policy-panel.ts offers no Always), so `ifAllowed`
 * speaks of one request or one run.
 */
function sessionAsk(
  v: Pick<QueueRowVM, "subject" | "target"> & Partial<Pick<QueueRowVM, "reason" | "sessionReads" | "sessionReadsMore" | "sessionConfined" | "sessionBindings" | "sessionHeld">>,
  who: string,
  home: string,
): AskCells {
  const command = String(v.subject).startsWith("session-exec:");
  const target = String(v.target ?? "");
  const names = sessionReadNames(v.sessionReads, home);
  const more = typeof v.sessionReadsMore === "number" && v.sessionReadsMore > 0 ? v.sessionReadsMore : 0;
  const read = namesParts(names, more);
  const many = names.length + more > 1;
  const after: HomeTextPart[] = [t(" after reading "), ...namesParts(names, more)];
  if (command) {
    // What an allowed run may do (confidentiality.md §4): held by the guard
    // (only the hosts what was read may go to; its files marked secret), or,
    // without the guard, not held at all. The card never overstates the hold.
    const hosts = (v.sessionBindings ?? []).filter((h) => h !== "");
    const reach: Cell = hosts.length === 0 ? "no host on the network" : w`only ${joinParts(hosts.map((h) => [c(h)]), ", ")}`;
    return {
      family: "run",
      sentence: [t(`${who} wants to run `), c(target || "a command"), ...after],
      why: w`This session read ${read} into the AI's conversation, and Mandu cannot tell whether a command sends anything over the network. The command could carry what the AI read, in its own words, which Mandu cannot mask.`,
      aiNow: w`The AI read ${read} as ${many ? "they are" : "it is"}. Its command was stopped before it ran.`,
      ifAllowed: v.sessionConfined === true
        ? w`This exact command runs once, held like a program that read ${read}: it may reach ${reach}, Mandu refuses any other connection, and the files it writes are marked secret. Any other command, or this one again, asks again.`
        : w`This exact command runs once, with the network your agent's commands normally have: Mandu cannot hold it on this computer. What it sends may carry text derived from ${read}, and the files it writes are not marked secret. Any other command, or this one again, asks again.`,
    };
  }
  const search = target === UNNAMED_DESTINATION || target === "";
  const place: Cell = search ? "a place the request does not name" : [c(target)];
  if (v.sessionHeld === true && !search) {
    // A HELD command's refused connection (confidentiality.md §4, "A held
    // command's refused connection", 2026-10-12): the command already ran,
    // held by what the session read; its request to this place was stopped.
    // Allow once lets the next try (the same command run again, a new
    // process) connect there once, with what it holds.
    const hosts = (v.sessionBindings ?? []).filter((h) => h !== "");
    const reach: Cell = hosts.length === 0 ? "no host on the network" : w`only ${joinParts(hosts.map((h) => [c(h)]), ", ")}`;
    return {
      family: "send",
      sentence: [t(`${who} ran a command that wants to connect to `), c(target), ...after],
      why: w`This session read ${read} into the AI's conversation, so every command the AI runs holds data from ${many ? "them" : "it"} and may reach ${reach}. ${place} is not such a place, and the command's request there could carry that data.`,
      aiNow: w`The command's request to ${place} was stopped; nothing was sent. The AI was told you were asked.`,
      ifAllowed: w`Allow once lets the next try through: the next connection from this session to ${place} goes, once, and it may carry data from ${read}. The try after that asks again. Block stops this session's requests to ${place} for good.`,
    };
  }
  // The frozen integrity axis's case (§9 rule 1b): the place IS one the data
  // may go to, but the session also read untrusted text that could aim it.
  const steered = /UNTRUSTED-TAINTED/.test(String(v.reason ?? ""));
  return {
    family: "send",
    sentence: search
      ? [t(`${who} wants to send a request that names no place (a web search)`), ...after]
      : [t(`${who} wants to send a request to `), c(target), ...after],
    why: steered
      ? w`This session read ${read} into the AI's conversation, and also text from a source Mandu does not trust. ${place} is a place ${many ? "they" : "it"} may go, but an instruction hidden in that text could aim the AI's request there, so Mandu asks first.`
      : w`This session read ${read} into the AI's conversation, and ${place} is not a place ${many ? "they" : "it"} may go. The request could carry what the AI read, in its own words, which Mandu cannot mask.`,
    aiNow: w`The AI read ${read} as ${many ? "they are" : "it is"}. Its request was stopped before it was sent.`,
    ifAllowed: w`This one request goes to ${place} as the AI wrote it, and it may carry text derived from ${read}. The next request asks again.`,
  };
}

/** The queue row describeAsk words. */
type AskRow = Pick<QueueRowVM, "where" | "subject" | "target" | "reason"> & Partial<Pick<QueueRowVM, "onceOnly" | "origin" | "readFirst" | "sessionReads" | "sessionReadsMore" | "sessionConfined" | "sessionBindings" | "sessionHeld" | "holderSources" | "fileValues">> & {
  /** A held open or change (`open:`, `trust:`, `write:`): whether the
   *  program is still waiting for the answer (the guard asks again every
   *  half second while it holds; home.ts `heldNow`). Absent: not known,
   *  and the words claim neither. */
  held?: boolean;
};

/** Classify a queue row and build its plain sentence + the three cells the
 *  Approvals card shows (dashboard.md §4.25u): why it stopped, what the AI
 *  has now, and what happens if you click Allow once or Always allow. `aiNow` and `ifAllowed`
 *  always have the AI as their subject ("The AI …", "The AI's program …"),
 *  so a card never switches between the AI and a program mid-way, and each
 *  family says what really happens in it: a program allowed to read a secret
 *  file reads it as itself while the AI still gets its output masked, never
 *  the file. Mirrors the inspector's Approvals sentence (dev/js/egress.js
 *  approvalSentence) as data, so the page renders parts and never interprets a
 *  key. A row whose item the AI read as it was before it was masked
 *  (`readFirst`; for a program's read, the file) never says the AI never
 *  read it, nor that it has not seen the file. Each cell also comes as parts,
 *  its names as code (`whyParts`, …; §4.25u). */
export function describeAsk(
  v: AskRow,
  who: string,
  home = "",
): AskWords {
  return withParts(askCells(v, who, home));
}

/** describeAsk's families, each cell as written (`Cell`). */
function askCells(
  v: AskRow,
  who: string,
  home: string,
): AskCells {
  const subject = String(v.subject ?? "");
  const target = String(v.target ?? "");
  const file = basename(target) || target;
  // The AI read the item as it was before it was masked, in a session on the
  // row (dashboard.md §4.34 "Read before it was marked").
  const early = typeof v.readFirst === "string" && v.readFirst !== "";
  const secretItem = itemWords(subject) === "a secret";
  if (subject.startsWith("session-net:") || subject.startsWith("session-exec:")) return sessionAsk(v, who, home);
  const holder = holderSendOf(subject);
  if (holder !== null) return holderAsk(v, holder, who, home);
  if (v.where === "network") {
    const item = itemWords(subject);
    const real = item === "a secret" ? "the real secret" : "the real text";
    const place: Cell = target ? [c(target)] : "that place";
    // A secret is named (dashboard.md §4.34 "A send names its secret"): its
    // own name, else the file it came from, `~/…` on the product pages
    // (`home`, the server's) and the full path in the inspector (no `home`).
    const secret = item === "a secret" ? secretOf(subject, v.origin) : { name: null, file: null };
    const from = secret.file === null ? null : tildePath(secret.file, home);
    // A FILE's card (egress-hold.md "One card per file", 2026-10-19): the
    // request carried several of the file's values; one answer covers them.
    const fileCard = secret.name === null && from !== null && typeof v.fileValues === "number" && v.fileValues > 1 ? v.fileValues : null;
    const sentence: HomeTextPart[] = secret.name !== null
      ? [t(`${who} wants to send your secret `), c(secret.name), t(" to "), c(target || "an unknown place")]
      : fileCard !== null
        ? [t(`${who} wants to send the secrets in `), c(from!), t(" to "), c(target || "an unknown place")]
        : from !== null
          ? [t(`${who} wants to send a secret from `), c(from), t(" to "), c(target || "an unknown place")]
          : [t(`${who} wants to send ${item} to `), c(target || "an unknown place")];
    const where: Cell = fileCard !== null ? `One answer covers all ${fileCard} of them. `
      : secret.name === null ? ""
      : from !== null ? w`${c(secret.name)} comes from ${c(from)}. `
      : v.origin?.startsWith("env:") ? w`${c(secret.name)} is an environment variable. ` : "";
    return {
      family: "send",
      sentence,
      why: fileCard !== null
        ? early
          ? w`${where}Mandu masks them now, but the AI read the file as it was before it was marked a secret. Sending them would show the real secrets to ${place}.`
          : w`${where}Mandu masked them, so the AI never read them. Sending them would show the real secrets to ${place}.`
        : early
          ? w`${where}Mandu masks it now, but the AI read its real ${secretItem ? "value before it was marked a secret" : "text before Mandu masked it"}. Sending it would show ${real} to ${place}.`
          : w`${where}Mandu masked it, so the AI never read it. Sending it would show ${real} to ${place}.`,
      aiNow: early ? readFirstNow(secretItem) : "The AI has only the masked version. It has never read the real one.",
      // The gate refused the request (the proxies answer 403): nothing was
      // sent, and only a new try goes with the value (§4.34 "After you answer").
      ifAllowed: w`The AI's next request goes to ${place} with ${real} filled in. Mandu refused this one, so nothing was sent. ${TELL_AGENT}`,
    };
  }
  if (subject.startsWith("prompt:")) {
    // Plan 15 §7 (phase 3): the person's own message holds something their
    // rules ask about (a code name, a card number, a key); the agent's
    // request waits until they answer. The found text itself is not in the
    // row (the page fetches it on the human plane, prompt-filters/holds).
    const category = /^prompt:([^#]+)#/.exec(subject)?.[1] ?? "something your rules ask about";
    return {
      family: "prompt",
      sentence: [t(`${who} wants to send your message to the AI. It holds `), c(category), t(".")],
      why: "Your rules ask before a message with this goes to the AI. The AI's request waits until you answer, and goes masked if you do not answer in time.",
      // The proxy holds the request until a deadline from the row's first
      // sighting (30 s by default), then sends the default; an answer given
      // later applies to the next request, which carries the message again
      // (prompt-filter/holds.ts). The page does not see the deadline, so
      // the words hold either way.
      aiNow: "The AI has not seen the message as you wrote it. Its request waits for your answer for a short while, then goes with that part masked.",
      ifAllowed: "The AI reads your message as you wrote it (Send as written), with that part masked (Send masked), or not at all (Cancel the message). An answer given after the request went applies from the AI's next request, which carries your message again.",
      ...(v.onceOnly === true ? { onlyThisMessage: ONLY_THIS_MESSAGE } : {}),
    };
  }
  if (v.where === "file" && subject.startsWith("open:")) {
    // `open:<exe>#<sha256>` since 2026-10-02 (Plan 13 D8: the verdict names
    // one binary); the path is shown, so a copy in the workspace is told
    // apart from the system's program. `open:<name>` before. Allowing it
    // makes the PROGRAM a reader of the file (Plan 10 §11.1: "its output
    // will be masked to the AI"); the AI never reads the file, so no line
    // here may say it does. A file the AI read as it was before its label
    // (`readFirst`, by the file) is never "not seen" (§4.34).
    const program = programWords(subject.slice("open:".length), home);
    return {
      family: "read",
      sentence: [t(`${possessive(who)} program `), c(program), t(" wants to read a secret file: "), c(file)],
      why: w`${c(file)} is a secret file, and Mandu keeps secret files from the AI. If you want ${c(program)} to read it, click Allow once or Always allow.`,
      aiNow: early ? fileReadFirstNow(program) : w`The AI has not seen the real file, and its program ${c(program)} has not read it.`,
      ifAllowed: w`${heldWords(v.held, program, "reads the real file", "could not read the file")} What it prints still reaches the AI masked.`,
    };
  }
  if (v.where === "file" && subject.startsWith("trust:")) {
    // Plan 13 D8 (12), the warning question (2026-10-04): a program Mandu
    // has not vetted. Allowing it makes the program a reader as for
    // `open:`, and an Always writes `prints: nothing`, the person's word that
    // it keeps what it reads out of what it prints; the card says plainly
    // what the program may do with the file.
    const program = programWords(subject.slice("trust:".length), home);
    return {
      family: "read",
      sentence: [t(`${possessive(who)} program `), c(program), t(" wants to read a secret file: "), c(file)],
      why: w`Mandu does not know whether ${c(program)} keeps what it reads out of what it prints. If you allow it, the AI's other programs may be able to read the file through it. Allow it only if you know ${c(program)} does not show or pass on what it reads.`,
      aiNow: early ? fileReadFirstNow(program) : w`The AI has not seen the real file, and its program ${c(program)} has not read it.`,
      ifAllowed: w`${heldWords(v.held, program, "reads the real file", "could not read the file")} What it prints still reaches the AI masked, but other programs that read its output may see the real contents.`,
    };
  }
  if (v.where === "file" && subject.startsWith("write:")) {
    // sandbox-security-review-2026-09-28 finding 6: a program in the agent's
    // tree wants to change a file that runs later (a shell startup file, a
    // scheduled service, a git hook). The guard holds the change meanwhile.
    // `write:<exe>#<sha256>` since 2026-10-02 (write-protection.md §2.1, the
    // D8 follow-up): the path is shown, the hash is not. `write:<name>` before.
    const program = programWords(subject.slice("write:".length), home);
    // Plan 13 §8 decision (c): a program that runs code no pin names (a
    // shell running the agent's command) gets an answer for this change only.
    const thisRun = programOfSubject(subject.slice("write:".length)).run === true;
    return {
      family: "other",
      sentence: [t(`${possessive(who)} program `), c(program), t(" wants to change a file that runs later: "), c(file)],
      why: "Files like this run later on this computer, outside Mandu's protection. "
        + (v.held === false ? "Mandu held the change for a while, then refused it." : "Mandu holds the change until you answer.")
        + (thisRun ? " The program runs code the AI gave it, so your answer covers this change only." : ""),
      aiNow: w`The AI's program ${c(program)} has not changed the file.`,
      // A run's answer (`#run:`) is for that process only: once it stopped
      // waiting, a new try is a new process and is asked about again.
      ifAllowed: thisRun && v.held === false
        ? w`The AI's program ${c(program)} stopped waiting and its change was refused. Your answer covers that run only, so a new try asks again.`
        : w`${heldWords(v.held, program, "changes the file", "could not change the file")} What it wrote runs the next time the file is used.`,
    };
  }
  if (v.where === "file" && /^fs:[^:]+:upload$/.test(subject)) {
    // `fs:<tool>:upload` × path (file-upload.ts; supported-agents.md §2): a
    // tool that sends a local file off this computer without the AI reading
    // it (Claude Code's DesignSync to claude.ai). The upload was refused
    // whole; a verdict decides the next identical try.
    return {
      family: "send",
      sentence: [t(`${who} wants to send a file off this computer: `), c(file)],
      why: "The file is a secret file, or holds one of your secrets. The AI's tool would send it as it is, so Mandu asks first.",
      aiNow: "The AI's tool has not sent the file. It got an error instead.",
      ifAllowed: `The AI's tool sends the file as it is when it tries again. ${TELL_AGENT}`,
    };
  }
  if (v.where === "file") {
    // `fs:<tool>:<mode>` × path: the agent's own tool on a path the
    // sensitive-path gate asks about (fs-sync.md §1.4.1): a credential
    // location, or a path outside the workspace. The tool got an error; a
    // verdict decides its next identical try.
    const write = /:write$/.test(subject);
    const verb = write ? "change" : "open";
    const reason = String(v.reason ?? "");
    const sensitive = /^sensitive path/.test(reason);
    const outside = /out-of-workspace/.test(reason);
    const what = sensitive ? "a secret file" : outside ? "a file outside its work folder" : "a protected file";
    return {
      family: "read",
      sentence: [t(`${who} wants to ${verb} ${what}: `), c(file)],
      why: sensitive
        ? `Files like this hold keys and passwords, so Mandu asks before the AI can ${verb} one.`
        : outside
          ? `The file is outside the folders this agent works in, so Mandu asks before the AI can ${verb} it.`
          : `Mandu asks before the AI can ${verb} this file.`,
      aiNow: `The AI has not ${write ? "changed" : "opened"} the file. Its tool got an error instead.`,
      ifAllowed: `The AI's tool can ${verb} the file when it tries again. ${TELL_AGENT}`,
    };
  }
  if (v.where === "exec" && subject.startsWith("exec-program:")) {
    const host = subject.slice("exec-program:".length) || "a download";
    return {
      family: "run",
      sentence:
        target === "(stdin)"
          ? [t(`${who} wants to run code straight from a download from `), c(host)]
          : [t(`${who} wants to run code it downloaded from `), c(host), t(": "), c(file)],
      why: "Code from the internet can do anything the site that served it wants, so Mandu stopped it before it ran.",
      aiNow: "The AI's command was stopped before it ran.",
      ifAllowed: `When the AI runs the command again, the downloaded code runs on this computer. ${TELL_AGENT}`,
    };
  }
  if (v.where === "exec" && subject.startsWith("exec-escalate:")) {
    // exec-routing.md §5: an AgentShell command that needs the real network
    // or the real files; a pending row keeps it in the sandbox.
    const net = subject.slice("exec-escalate:".length) === "network";
    return {
      family: "run",
      sentence: [t(`${who} wants to run a command ${net ? "with network access" : "on your real files"}: `), c(target || "a command")],
      why: net
        ? "The AI's commands run without the network unless you allow it."
        : "The AI's commands run on a masked copy of your files unless you allow it.",
      aiNow: net ? "The AI's command ran without the network." : "The AI's command ran on the masked copy only.",
      ifAllowed: (net
        ? "When the AI runs the command again, it gets the network."
        : "When the AI runs the command again, it runs on your real files.") + ` ${TELL_AGENT}`,
    };
  }
  if (v.where === "exec") {
    return {
      family: "run",
      sentence: [t(`${who} wants to run a command that uses masked text: `), c(target || "a command")],
      why: "The command uses masked text, and Mandu does not put the real text into a command without your OK.",
      aiNow: early ? readFirstNow(secretItem) : "The AI has only the masked text. It has never read the real one.",
      ifAllowed: `When the AI runs the command again, it runs with the real text filled in. ${TELL_AGENT}`,
    };
  }
  if (v.where === "model context") {
    // Named as a send names it (§4.34 "A send names its secret").
    const secret = secretItem ? secretOf(subject, v.origin) : { name: null, file: null };
    return {
      family: "show",
      sentence: secret.name !== null
        ? [t(`${who} wants to show the AI your secret `), c(secret.name), t(" as it is")]
        : secret.file !== null
          ? [t(`${who} wants to show the AI a secret from `), c(tildePath(secret.file, home)), t(" as it is")]
          : [t(`${who} wants to show the AI ${itemWords(subject)} as it is`)],
      why: early
        ? `Mandu masks this now, but the AI read it as it was before ${secretItem ? "it was marked a secret" : "Mandu masked it"}.`
        : "Mandu masked this before the AI read it.",
      aiNow: early ? readFirstNow(secretItem) : "The AI has only the masked version.",
      ifAllowed: `When the AI asks again, it reads the real text. ${TELL_AGENT}`,
    };
  }
  return {
    family: "other",
    sentence: [t(`${who} wants to use ${itemWords(subject)}`), t(target ? " with " : ""), ...(target ? [c(target)] : [])],
    why: "Mandu stops here when no rule covers it.",
    aiNow: "The AI's action has not happened.",
    ifAllowed: "The AI's action goes ahead.",
  };
}
