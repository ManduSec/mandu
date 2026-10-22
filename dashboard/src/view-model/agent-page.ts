/**
 * view-model/agent-page — the PRODUCT's per-agent page (dashboard.md §4.25,
 * "What happened" §4.25b).
 *
 * One session, told as a story an end user can read. It borrows the /dev/
 * trace's paired rows (§4.2f): one card per turn (your question, what the
 * agent did, its reply), a one-line summary of what Mandu did in that turn,
 * and, only on a step where the AI's view and reality differ, two halves side
 * by side: what the AI saw, and what really happened. Bookkeeping (allowed
 * connections, path mappings, command checks) folds into one "In the
 * background" line that names each kind in plain words; a block, a denial or
 * a violation always stays inline.
 *
 * Pure: built from the session's `SessionViewModel` (its `paired` turns, the
 * dual-lanes steps they reference, the symbol rows and the lineage), its
 * listing row and the pending asks the route already described. Same
 * vocabulary rule as home.ts: no `$MDU:` token anywhere in the page's data.
 *
 * ORIGINALS. A masked step ships the original the AI was kept from (the page
 * shows it only on a click). A SECRET is never shipped, at any depth: every
 * token is checked against the session's secret set (twin prefixes, secret
 * lineage flows, any non-public level) before its value is used, and a value
 * is expanded one level at a time so a secret nested inside an ordinary item
 * stays hidden too. A token the session never recorded stays masked (fail
 * toward hidden, never fabricate). `revealValues` fetches missing values one
 * level at a time from the arbiter under the same checks.
 *
 * THE MOMENT OF AN ASK (§4.25h). Opened from an answer on the Rules page or
 * an ask in Approvals (`?ask=<egr-id>`), the page marks the step where
 * Mandu stopped and asked: `locateAsk` finds it by the id the gate event
 * carries, or, for a record older than that stamp, by the ask's destination.
 * Attribution only: nothing here decides anything.
 */

import type { ManduEvent } from "../event-model.js";
import type { SessionRef } from "../event-source/contract.js";
import type { SessionViewModel } from "../view-model.js";
import { netHost, osSubject, stepIdOfEvent, type DualOsStep, type DualResponseStep, type DualStep, type DualToolStep, type FileGuard } from "./dual-lanes.js";
import { isSecretFlow, type SessionFlowStats } from "./lineage.js";
import { sessionExited } from "./session-exit.js";
import { launchTimeOf } from "./launch-time.js";
import type { BackgroundCategory, BackgroundGroup, PairedToolRow, ProtectionMode } from "./paired-rows.js";
import { agentName, agentNotice, agentNoticeParts, agentPreview, oneLine, secretsPostureNote, promptLabel, type HomeAnswered, type HomeAsk } from "./home.js";
import { manduPolicyTool, policyToolAnswerParts, policyToolSentence } from "./mandu-tool-words.js";
import { declassifyAnswer, isManduDeclassify } from "./declassify-words.js";
import { inspectAnswer } from "./inspect-answer.js";
import { promptNotes, type PromptLocks } from "./prompt-notes.js";
import { causeFiles, causePrograms, earlyReads, FINDING_POINTER, SECRET_ALL_CAP, secretsStory, secretShortName, traceLink, type LaterLabelInput, type SecretsStory, type StoryOptions } from "./secret-story.js";
import { laterByStep, laterLabels, plainReads, type LabelTime, type LaterLabel } from "./later-labels.js";
import { secretRef } from "./secret-ref.js";
import { ISSUES_URL } from "../agent-versions.js";
// The kept-or-echoed rule both views share (held-tokens.ts).
import { heldTokens, SYM_RE, tokensIn, trailingDots } from "./held-tokens.js";
import { blockWhy } from "./block-why.js";
import { issuerOfHost, type IssuerReading } from "./issuer-words.js";
import { browserStory } from "./browser-story.js";
import { gateRewrite, noticeWhy, rewriteCheckKind } from "./gate-rewrite.js";
import { pathArg, toolFamily } from "./tool-family.js";
import { isPatchTool, patchFiles, type PatchFile } from "./patch-files.js";
// The refused-read rule both views share (secret-note.ts), and the note's
// reason for a whole-output mask.
import { maskCause, noteMasks, readRefusals, refusedReadWords } from "./secret-note.js";
export { heldTokens, noteMasks };

export type {
  StoryOutcome,
  StoryPart,
  StoryHidden,
  StorySplit,
  StoryStep,
  StoryReply,
  StoryTurn,
  AgentPageVM,
  StoryFocus,
  AskRef,
  BackgroundItem,
  StoryRoutine,
  LeakFinding,
  LeakFindingItem,
} from "./agent-page-types.js";
import type {
  StoryOutcome, StoryPart, StoryHidden, StorySplit, StoryStep, StoryReply, StoryTurn, AgentPageVM, StoryFocus, AskRef,
  BackgroundItem, LeakFinding, LeakFindingItem,
} from "./agent-page-types.js";

/** The session's main model in the product's words, or null when it is not
 *  bound to a declared entry (plan 11 §7.1: null = the agent's default
 *  vendor). The location is the arbiter's, read from the law in force, so an
 *  entry that stopped being `local: true` reads as an outside model. */
export function mainModelOf(u: { endpoint: string | null; location: string } | null | undefined): AgentPageVM["mainModel"] {
  if (!u || typeof u.endpoint !== "string" || u.endpoint === "") return null;
  const local = u.location === "local";
  return { words: `Main model: ${local ? "your own model" : "an outside model"} (${u.endpoint})`, local };
}

/** The story shows the newest TURN_CAP turns, and a turn its first
 *  TURN_STEP_CAP steps, until the page asks for the rest (`AgentPageShow`,
 *  its *Show them*, dashboard.md §4.25ad); then at most the ALL caps, so a
 *  huge session stays a page. */
export const TURN_CAP = 60;
export const TURN_STEP_CAP = 80;
export const TURN_ALL_CAP = 500;
export const TURN_STEP_ALL_CAP = 1000;
/** A revealed original is cut here on the page; a signed-in reader reads
 *  the rest with *Show the whole original* (`GET /api/home/original`, up to
 *  ORIGINAL_ALL_CAP; dashboard.md §4.25ae). */
export const HIDDEN_CAP = 4000;
export const ORIGINAL_ALL_CAP = 1_000_000;
/** The background steps a turn lists once asked (`?background=`). */
export const BACKGROUND_ALL_CAP = 1000;
/** The places What the leak check found lists. */
export const FINDING_CAP = 20;
/** The secrets its *What to do now* names, one line each; the rest counted. */
export const TODO_NAMES_CAP = 5;

/** `$MDU:tool[hash]` without its field path: symbol rows and tokens spell
 *  the same item with and without a field. */
function baseOf(name: string): string {
  const i = name.indexOf("]");
  return i >= 0 ? name.slice(0, i + 1) : name;
}

/** Replace any masked-item token with "[masked]" — a product surface never
 *  shows the token grammar. */
export function maskTokens(s: string): string {
  return s.replace(SYM_RE, (m) => "[masked]" + trailingDots(m));
}

function t(text: string): StoryPart {
  return { kind: "text", text };
}
function c(text: string): StoryPart {
  return { kind: "code", text: maskTokens(text) };
}
/** A moment, drawn by the page as the viewer's local clock time. */
function at(iso: string): StoryPart {
  return { kind: "time", text: iso };
}
/** `early`: a secret the AI read as it was before its label, when (the
 *  chip then never says "never"). */
function chip(secret: boolean, early?: string): StoryPart {
  return { kind: "masked", text: secret ? "secret" : "masked", ...(secret && early ? { early } : {}) };
}

function shorten(s: string, max = 90): string {
  const v = s.replace(/\s+/g, " ").trim();
  return v.length > max ? v.slice(0, max - 1) + "…" : v;
}

function baseName(p: string): string {
  const s = p.replace(/\/+$/, "");
  const i = s.lastIndexOf("/");
  return i >= 0 ? s.slice(i + 1) || s : s;
}

function hostOf(url: string): string {
  const m = /^[a-z]+:\/\/([^/?#]+)/i.exec(url);
  return m ? m[1]! : url;
}

function argsOf(input: string | null): Record<string, unknown> {
  if (!input) return {};
  try {
    const v = JSON.parse(input);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v : null;
}

function isInspect(tool: string): boolean {
  return /inspect_symbol$/.test(tool);
}

type Icon = Extract<StoryStep, { kind: "action" }>["icon"];

/** A masked item's chip in a command, path or query: a secret by the name
 *  the send steps give it, else the `secret` or `masked` word. */
function itemChip(name: string, label: ItemLabel): StoryPart {
  const l = label(name);
  return l.secret && l.name ? { ...chip(true, l.early), name: l.name } : chip(l.secret, l.early);
}

/** How wide a part draws, for a cut: a chip by its word or name. */
function drawnWidth(p: StoryPart): number {
  return p.kind === "masked" ? (p.name ?? p.text).length + 2 : p.text.length;
}

/** A command, path or query as code, each masked item a chip in it, cut at
 *  `max` characters as drawn (whitespace runs read as one space, as
 *  `shorten` does). A chip is drawn whole or not at all: cutting the raw text
 *  first could leave part of a token on the page, past `maskTokens`. */
function codeParts(text: string, label: ItemLabel, max = Infinity): StoryPart[] {
  const v = text.replace(/\s+/g, " ").trim();
  const pieces: StoryPart[] = [];
  let last = 0;
  for (const m of tokensIn(v)) {
    if (m.index > last) pieces.push({ kind: "code", text: v.slice(last, m.index) });
    pieces.push(itemChip(m.name, label));
    last = m.end;
  }
  if (last < v.length) pieces.push({ kind: "code", text: v.slice(last) });
  if (pieces.reduce((n, p) => n + drawnWidth(p), 0) <= max) return pieces;
  const out: StoryPart[] = [];
  let left = max - 1;
  for (const p of pieces) {
    if (p.kind === "masked") {
      if (drawnWidth(p) > left) break;
      out.push(p);
      left -= drawnWidth(p);
    } else {
      out.push({ kind: "code", text: p.text.slice(0, left) });
      left -= p.text.length;
    }
    if (left <= 0) break;
  }
  const end = out[out.length - 1];
  if (end?.kind === "code") end.text += "…";
  else out.push({ kind: "code", text: "…" });
  return out;
}

/** Without the session's scope: a secret by its twin prefix, never named. */
const PREFIX_LABEL: ItemLabel = (name) => ({ secret: isSecretName(name, { values: new Map(), secrets: new Set(), known: new Set(), sessionId: "" }), name: null });

/** A value in a call to Mandu's own rule tools (a path, a host) is cut here. */
export const POLICY_VALUE_CAP = 120;

/** The plain sentence for one tool call, by tool family: every supported
 *  agent's names and path fields (tool-family.ts). Mandu's own rule tools
 *  say what was asked of Mandu (mandu-tool-words.ts), and so does its
 *  in-context read, the secret asked for (declassify-words.ts). Unknown tools read
 *  "Used <tool>" — the name is the agent's, not ours. A masked item in its
 *  command, path or query is a chip, named by `label` when it is a secret.
 *  `home`: the dashboard's home folder, so a file a rule tool's call names
 *  under it reads `~/…`, as on Approvals. */
export function actionSentence(step: Pick<DualToolStep, "tool" | "input" | "patchFiles">, label: ItemLabel = PREFIX_LABEL, home = ""): { icon: Icon; sentence: StoryPart[] } {
  // A patch names its files only in its text (patch-files.ts); the step's
  // `patchFiles` holds every patch it recorded (a code-mode cell may patch
  // more than once).
  const files = step.patchFiles?.length ? step.patchFiles : isPatchTool(step.tool) ? patchFiles(step.input) : [];
  if (files.length && isPatchTool(step.tool)) return { icon: "edit", sentence: patchSentence(files, label) };
  const action = callSentence(step, label, home);
  // A code-mode cell that ran a command and patched files: "Ran `npm test`
  // and edited `a.ts`" (§4.25b "A patch in a code cell").
  if (!files.length) return action;
  const patch = patchSentence(files, label);
  const head = patch[0];
  if (head?.kind === "text") patch[0] = t(head.text.charAt(0).toLowerCase() + head.text.slice(1));
  return { icon: action.icon, sentence: [...action.sentence, t(" and "), ...patch] };
}

/** {@link actionSentence} for every call but a patch's files. */
function callSentence(step: Pick<DualToolStep, "tool" | "input">, label: ItemLabel, home: string): { icon: Icon; sentence: StoryPart[] } {
  const a = argsOf(step.input);
  const path = pathArg(a);
  const tool = step.tool;
  const file = path ? codeParts(baseName(path), label) : [c("a file")];
  switch (toolFamily(tool)) {
    case "read": return { icon: "file", sentence: [t("Read "), ...file] };
    case "write": return { icon: "edit", sentence: [t("Wrote "), ...file] };
    case "edit": return { icon: "edit", sentence: [t("Edited "), ...file] };
    case "exec": {
      const cmd = str(a["command"]) ?? (Array.isArray(a["cmd"]) ? (a["cmd"] as unknown[]).join(" ") : str(a["cmd"])) ?? (Array.isArray(a["command"]) ? (a["command"] as unknown[]).join(" ") : null);
      // Claude Code's Monitor also watches a socket (`ws{url}`), which runs nothing.
      if (!cmd && /^monitor$/i.test(tool)) break;
      return { icon: "run", sentence: [t("Ran "), ...(cmd ? codeParts(cmd, label, 80) : [c("a command")])] };
    }
    case "fetch": {
      const url = str(a["url"]);
      return { icon: "web", sentence: [t("Opened a web page on "), c(url ? hostOf(url) : "the web")] };
    }
    case "web-search": {
      const q = str(a["query"]);
      return { icon: "search", sentence: q ? [t("Searched the web for "), ...codeParts(q, label, 60)] : [t("Searched the web")] };
    }
    case "file-search": {
      const q = str(a["pattern"]) ?? str(a["query"]);
      return { icon: "search", sentence: q ? [t("Searched files for "), ...codeParts(q, label, 60)] : [t("Searched files")] };
    }
    case "list": {
      // A folder by its name; the folder the agent runs in (`.`) by none.
      const dir = path ? baseName(path) : null;
      return { icon: "search", sentence: dir && dir !== "." ? [t("Listed the files in "), ...codeParts(dir, label)] : [t("Listed files")] };
    }
  }
  // Mandu's in-context read: the secret the agent asked Mandu for, as its
  // chip (declassify-words.ts).
  if (isManduDeclassify(tool)) {
    const sym = str(a["symbol"]);
    return { icon: "shield", sentence: [t("Asked Mandu for the real value of "), ...(sym ? codeParts(sym, label, 60) : [t("a masked item")])] };
  }
  if (isInspect(tool)) {
    const q = str(a["instruction"]);
    return { icon: "tool", sentence: q ? [t("Asked the sandboxed reader: "), t(shorten(maskTokens(q), 160))] : [t("Asked the sandboxed reader about a masked item")] };
  }
  // Mandu's own rule tools: what the agent asked Mandu, in the Approvals
  // card's words, each value as code (its masked items chips, cut).
  const policy = manduPolicyTool(tool);
  if (policy) {
    const sentence = policyToolSentence(policy, a, home).flatMap((p): StoryPart[] => (p.kind === "code" ? codeParts(p.text, label, POLICY_VALUE_CAP) : p.kind === "time" ? [{ kind: "time", text: p.text, clock: true }] : [t(maskTokens(p.text))]));
    return { icon: "shield", sentence };
  }
  return { icon: "tool", sentence: [t("Used "), c(tool.replace(/^mcp__/, "").replace(/__/g, " "))] };
}

/** How many files a patch's sentence names before "and N more files". */
export const PATCH_NAMES_SHOWN = 3;

/** A patch's files in words, each group by what the patch does to it:
 *  "Edited `a.ts` and `b.ts`, created `c.ts`, moved `d.ts` to `e.ts`,
 *  deleted `f.ts`", the first {@link PATCH_NAMES_SHOWN} files by name and
 *  the rest counted. A file by its base name, as every step names one. */
export function patchSentence(files: readonly PatchFile[], label: ItemLabel = PREFIX_LABEL): StoryPart[] {
  const order: Array<[string, PatchFile["kind"]]> = [["Edited", "update"], ["Created", "add"], ["Moved", "move"], ["Deleted", "delete"]];
  // The groups drawn, the first files by name in this order.
  const drawn: Array<[string, PatchFile[]]> = [];
  let left = PATCH_NAMES_SHOWN;
  for (const [verb, kind] of order) {
    const shown = files.filter((f) => f.kind === kind).slice(0, Math.max(0, left));
    if (!shown.length) continue;
    left -= shown.length;
    drawn.push([verb, shown]);
  }
  const more = files.length - (PATCH_NAMES_SHOWN - left);
  const out: StoryPart[] = [];
  drawn.forEach(([verb, shown], g) => {
    out.push(t(g === 0 ? `${verb} ` : `, ${verb.toLowerCase()} `));
    // The last "and" is the count's when files are left unnamed.
    const lastAnd = g < drawn.length - 1 || more <= 0;
    shown.forEach((f, i) => {
      if (i > 0) out.push(t(i === shown.length - 1 && lastAnd ? " and " : ", "));
      out.push(...codeParts(baseName(f.path), label));
      if (f.to !== undefined) out.push(t(" to "), ...codeParts(baseName(f.to), label));
    });
  });
  if (more > 0) out.push(t(` and ${more} more file${more === 1 ? "" : "s"}`));
  return out;
}

const BLOCK_RE = /\b(block(ed)?|den(y|ied)|refused|rejected)\b/i;

/** What Mandu did when a note's only news is that it refused programs'
 *  reads of secret files (`denied:`, `held:`; a command's call, so the AI
 *  got the command's own output): the step is a block, and this says so
 *  (secret-note.ts, the inspector's card says the same). Null for a note that
 *  masks or names no refused read. Counts only, never a program or a path. */
export function refusedReadNote(note: string | null | undefined): string | null {
  const reads = readRefusals(note);
  return reads ? refusedReadWords(reads) : null;
}

/** A check refused the call: a usage verdict, or a correlated OS action
 *  that refused it (its gate text is the event title, e.g. "net_action ·
 *  blocked evil.example"). */
function checkBlocked(step: Pick<DualToolStep, "usage" | "gates">): boolean {
  return step.usage === "deny" || step.gates.some((g) => BLOCK_RE.test(g.text));
}

/** A step that reached the AI unmasked: with the developer view, its note
 *  names the detailed trace, which the page links (§4.25, *The page links
 *  the trace it names*); without it, the note points at the leak check's
 *  finding at the top of the same page (§4.25ae, `leakFinding`). */
const UNMASKED_CALL_NOTE: StoryPart[] = [t("This reached the AI without a mask. "), traceLink("Open the detailed trace"), t(".")];
const UNMASKED_OS_NOTE: StoryPart[] = [traceLink("Open the detailed trace"), t(" to see what.")];
const UNMASKED_CALL_WORDS = `This reached the AI without a mask. ${FINDING_POINTER}`;
const said = (parts: StoryPart[]): string => parts.map((p) => p.text).join("");

/** What Mandu did about one tool call, most severe first. `noteParts`: the
 *  note as parts, when one of them is a link. `dev`: the build serves the
 *  developer view (absent: true). */
export function actionOutcome(step: DualToolStep, dev = true): { outcome: StoryOutcome; note: string | null; noteParts?: StoryPart[] } {
  if (step.violated) return dev ? { outcome: "unmasked", note: said(UNMASKED_CALL_NOTE), noteParts: UNMASKED_CALL_NOTE } : { outcome: "unmasked", note: UNMASKED_CALL_WORDS };
  if (checkBlocked(step)) return { outcome: "blocked", note: "Mandu stopped it." };
  if (step.usage === "needs_approval") return { outcome: "waiting", note: "Waiting for your OK." };
  // The AI got the result as it was; only LATER requests carry it masked
  // (its source was labelled after the read). The step says what the AI
  // received at its own turn, never the later state.
  if (step.maskedLater) return { outcome: "raw", note: "The AI got this as it was: nothing marked it for masking when it read it." };
  if (step.quarantine || isInspect(step.tool)) return { outcome: "sandbox", note: "Read by the sandboxed reader. The AI got only its answer." };
  if (noteMasks(step.secretNote)) return { outcome: "secret", note: "A secret was masked before the AI saw it." };
  // A program refused a secret file: no gate event records it, only the
  // proxy's note, and the program's own output reached the AI.
  const refusedRead = refusedReadNote(step.secretNote);
  if (refusedRead) return { outcome: "blocked", note: refusedRead };
  if (step.newSymbols.length > 0 || (step.trust === "UNTRUSTED" && step.upSyms.length > 0)) {
    return { outcome: "masked", note: "The result was masked before the AI read it." };
  }
  return { outcome: "plain", note: null };
}

/** How a masked item is named in a sentence: "your secret `GITHUB_TOKEN`".
 *  `early`: a secret the AI read as it was before its label, when (its
 *  card's moment, `ValueScope.early`); absent: no such read. */
export type ItemLabel = (name: string) => { secret: boolean; name: string | null; early?: string };

/** "your secret `A`", "your secrets `A`, `B` and `C`". */
function namedParts(named: readonly string[]): StoryPart[] {
  const out: StoryPart[] = [t(named.length === 1 ? "your secret " : "your secrets ")];
  named.forEach((n, i) => {
    if (i > 0) out.push(t(i === named.length - 1 ? " and " : ", "));
    out.push(c(n));
  });
  return out;
}

/** "your secret `A`", "your secrets `A` and `B`", "a masked item". */
function itemsParts(names: readonly string[], label: ItemLabel): StoryPart[] {
  const items = names.map(label);
  const secrets = items.filter((i) => i.secret);
  const named = secrets.map((i) => i.name).filter((n): n is string => !!n);
  const out: StoryPart[] = [];
  if (secrets.length) {
    if (named.length === secrets.length) out.push(...namedParts(named));
    else out.push(t(secrets.length === 1 ? "a secret of yours" : `${secrets.length} of your secrets`));
  }
  const others = items.length - secrets.length;
  if (others) {
    if (out.length) out.push(t(" and "));
    out.push(t(others === 1 ? "a masked item" : `${others} masked items`));
  }
  return out;
}

/** An OS decision that stays inline (a block, a denial, a violation, an
 *  uncorrelated file action, a send that carried a masked item), in plain
 *  words. `label` names what a send carried; without it, an item is "a
 *  masked item". A block or a wait also says why, when the event recorded
 *  a rule this page words (block-why.ts); otherwise no `why`. `issuers`:
 *  policy.yaml's `issuer_bindings` as the route read it, so a send to a
 *  company's own API says why it did not ask (§4.25b); absent: no such
 *  sentence. */
export function osSentence(
  s: Pick<DualOsStep, "kind" | "title" | "action" | "usage" | "target" | "violated" | "carried"> & Partial<Pick<DualOsStep, "ruleRef" | "askId" | "fileGuard">>,
  label: ItemLabel = () => ({ secret: false, name: null }),
  dev = true,
  issuers?: IssuerReading,
): { icon: Icon; sentence: StoryPart[]; outcome: StoryOutcome; note: string | null; noteParts?: StoryPart[]; why?: StoryPart[]; askId?: string } {
  const o = osWords(s, label, dev, issuers);
  if (o.outcome !== "blocked" && o.outcome !== "waiting") return o;
  const net = s.kind === "net_action" && !s.fileGuard;
  const why = blockWhy(s.ruleRef, { outcome: o.outcome, host: net ? netHost(s) || null : null, ...(net && s.carried ? { carried: s.carried.length } : {}) });
  return { ...o, ...(why ? { why } : {}), ...(s.askId ? { askId: s.askId } : {}) };
}

/** The last `n` segments of a path, `…/`-prefixed when cut: a repository the
 *  guard names is often deep (OpenCode's snapshot store), and its last
 *  segment alone is a hash. */
function pathTail(p: string, n = 4): string {
  const segs = p.replace(/\/+$/, "").split("/").filter(Boolean);
  return segs.length <= n ? p : `…/${segs.slice(-n).join("/")}`;
}

/** OpenCode's snapshot store under any data home (`…/share/opencode/snapshot/…`;
 *  the launcher's git-lock-backstop.ts `agentGitStoreOf` shape). */
const OPENCODE_SNAPSHOT_RE = /\/share\/opencode\/snapshot(?:\/|$)/;

/** A file decision of the kernel guard (dual-lanes.ts `fileGuardOf`), in
 *  plain words: never "a connection to the network", which is how its
 *  `net_action` record read before (first-session walk, 2026-10-11). */
function fileGuardWords(g: FileGuard): { icon: Icon; sentence: StoryPart[]; outcome: StoryOutcome; note: string | null } {
  switch (g.what) {
    case "git-lock":
      // OpenCode's own snapshot history (its undo), not one of the person's
      // repositories: never registered or prepared, so the work-tree note
      // below would be wrong (confidentiality.md §7.2a "An agent's own git
      // store"; the launcher's exit notice says the same).
      if (OPENCODE_SNAPSHOT_RE.test(g.path)) {
        return {
          icon: "file", sentence: [t("Mandu kept OpenCode from reading its own snapshot history (its undo), which holds a file you marked secret, in "), c(pathTail(g.path))], outcome: "blocked",
          note: "Nothing needs doing. OpenCode's undo of changes from before you marked the file stops working (once OpenCode has packed that history, its undo of new changes too), and this comes back in each session where OpenCode reads that history. To stop it, remove that folder outside Mandu: OpenCode starts a new history.",
        };
      }
      return {
        icon: "file", sentence: [t("Mandu kept git from reading a history that may hold a secret you marked, in "), c(pathTail(g.path))], outcome: "blocked",
        note: "Git does not work in that folder for the rest of this session. The next launch prepares a copy of its history without the secret.",
      };
    case "protected-path":
      return { icon: "file", sentence: [t("Mandu blocked deleting or renaming a protected file: "), c(baseName(g.path))], outcome: "blocked", note: null };
    case "write-protect":
      return { icon: "file", sentence: [t("Mandu blocked a change to a protected file: "), c(baseName(g.path))], outcome: "blocked", note: null };
    case "raw-withheld":
      return {
        icon: "file", sentence: [t("A program got the placeholder copy of "), c(baseName(g.path)), t(", not the real file")], outcome: "secret",
        note: "A network or file-system mount could have seen the read, so Mandu kept the real file back.",
      };
    case "local-socket":
      // A socket is a door on this machine, never "the network" (tmux inside
      // tmux, live 2026-10-11). The program named is the one that tried.
      return {
        icon: "run",
        sentence: [
          t("Mandu kept the AI's command"), ...(g.program ? [t(" "), c(g.program)] : []),
          t(" from reaching a local program's socket"), ...(g.path ? [t(": "), c(pathTail(g.path))] : []),
        ],
        outcome: "blocked",
        note: LOCAL_SOCKET_NOTE,
      };
  }
}

/** Why a local socket is refused, in the page's words (usage.md: a tmux
 *  server, docker or the desktop bus can start a program outside Mandu). */
const LOCAL_SOCKET_NOTE = "A program that runs outside Mandu listens there, so a command sent through it would run outside Mandu's protection.";

const SENT_NOTE = "The real value left this machine, to a destination allowed to receive it.";

/** A send's note, and when `host` is a company's own API while its keys go
 *  there without asking, why nobody asked (dashboard.md §4.25b, *A send to
 *  its company's own API says why it did not ask*). "May": the page knows
 *  the host, not the rule that let the send through (net-proxy records a
 *  rule only on a block), so a rule or an answer of yours may be the reason
 *  instead, and the sentence stays true then too. */
function sentNote(host: string, issuers: IssuerReading | undefined): { note: string; noteParts?: StoryPart[] } {
  const issuer = issuerOfHost(host, issuers);
  if (!issuer) return { note: SENT_NOTE };
  const noteParts = [
    t(`${SENT_NOTE} `), c(host),
    t(` is ${issuer.name}'s own API: a key ${issuer.name} issued may go there without asking you. `),
    { kind: "text" as const, text: "Built-in protections", rules: "built-in" as const },
    t(" in Rules lists these, and says how to have them ask."),
  ];
  return { note: said(noteParts), noteParts };
}

function osWords(
  s: Pick<DualOsStep, "kind" | "title" | "action" | "usage" | "target" | "violated" | "carried"> & Partial<Pick<DualOsStep, "fileGuard">>,
  label: ItemLabel,
  dev: boolean,
  issuers?: IssuerReading,
): { icon: Icon; sentence: StoryPart[]; outcome: StoryOutcome; note: string | null; noteParts?: StoryPart[] } {
  const { act, subject } = osSubject(s);
  const blocked = s.usage === "deny" || BLOCK_RE.test(act);
  const waiting = s.usage === "needs_approval";
  if (s.violated) {
    const sentence = [t("Something reached the AI without a mask")];
    return dev ? { icon: "shield", sentence, outcome: "unmasked", note: said(UNMASKED_OS_NOTE), noteParts: UNMASKED_OS_NOTE } : { icon: "shield", sentence, outcome: "unmasked", note: FINDING_POINTER };
  }
  if (s.fileGuard) return fileGuardWords(s.fileGuard);
  if (s.kind === "net_action") {
    const host = netHost(s) || "the network";
    // A send that carried masked items: the moment data left this machine,
    // or was kept on it (the net-proxy's `resolved` / `withheld`).
    const carried = s.carried ?? [];
    if (carried.length) {
      const items = itemsParts(carried, label);
      if (blocked) return { icon: "web", sentence: [t("Mandu blocked a request to "), c(host), t(" that carried "), ...items], outcome: "blocked", note: "The request never left this machine." };
      if (waiting) return { icon: "web", sentence: [t("Wants to send "), ...items, t(" to "), c(host)], outcome: "waiting", note: "Waiting for your OK." };
      return { icon: "web", sentence: [t("Sent a request to "), c(host), t(" with "), ...items, t(" filled in")], outcome: "sent", ...sentNote(host, issuers) };
    }
    if (blocked) return { icon: "web", sentence: [t("Mandu blocked a connection to "), c(host)], outcome: "blocked", note: "The request never left this machine." };
    if (waiting) return { icon: "web", sentence: [t("Wants to connect to "), c(host)], outcome: "waiting", note: "Waiting for your OK." };
    return { icon: "web", sentence: [t("Connected to "), c(host)], outcome: "plain", note: null };
  }
  if (s.kind === "exec_action") {
    const what = subject ? [t(": "), ...codeParts(subject, label, 60)] : [];
    if (blocked) return { icon: "run", sentence: [t("Mandu stopped a command"), ...what], outcome: "blocked", note: null };
    if (waiting) return { icon: "run", sentence: [t("A command is waiting for your OK"), ...what], outcome: "waiting", note: null };
    return { icon: "run", sentence: [t("Ran a command"), ...what], outcome: "plain", note: null };
  }
  if (s.kind === "fs_action") {
    const file = subject ? [t(" "), ...codeParts(baseName(subject), label)] : [];
    if (blocked) return { icon: "file", sentence: [t("Mandu blocked access to a file"), ...(subject ? [t(": "), ...codeParts(baseName(subject), label)] : [])], outcome: "blocked", note: null };
    return { icon: "file", sentence: [t("Touched a file"), ...file], outcome: waiting ? "waiting" : "plain", note: null };
  }
  if (s.kind === "ullm_call") return { icon: "tool", sentence: [t("The sandboxed reader read a masked item")], outcome: "sandbox", note: null };
  if (blocked) return { icon: "shield", sentence: [t("Mandu blocked an action")], outcome: "blocked", note: null };
  if (waiting) return { icon: "shield", sentence: [t("An action is waiting for your OK")], outcome: "waiting", note: null };
  return { icon: "shield", sentence: [t("Mandu checked an action")], outcome: "plain", note: null };
}

// ── Originals, with secrets held back ────────────────────────────────────────

/** What the page may know about the session's masked items. */
export interface ValueScope {
  /** Recorded values by token and by base name. */
  values: Map<string, string>;
  /** Base names that are secrets (never revealed). */
  secrets: Set<string>;
  /** Base names the session recorded at all (the only ones revealable). */
  known: Set<string>;
  /** The session the scope is of (a secret's ref is per session). */
  sessionId?: string;
  /** Secrets the AI read as they were before their label, by base name:
   *  when it read them, as "Your secrets" says (secret-story.ts
   *  `earlyReads`). Absent: none known. */
  early?: ReadonlyMap<string, string>;
  /** Where a revealed original is cut (absent: HIDDEN_CAP). */
  hiddenCap?: number;
}

/** When the AI read secret `name` as it was, before its label, or undefined. */
function earlyOf(name: string, scope: ValueScope): string | undefined {
  return isSecretName(name, scope) ? scope.early?.get(baseOf(name)) : undefined;
}

/** The first such read among `names`, or undefined. */
function firstEarly(names: readonly string[], scope: ValueScope): string | undefined {
  let first: string | undefined;
  for (const n of names) {
    const e = earlyOf(n, scope);
    if (e !== undefined && (first === undefined || e < first)) first = e;
  }
  return first;
}

function isSecretName(name: string, scope: ValueScope): boolean {
  return name.startsWith("$MDU:nomodel_") || name.startsWith("$MDU:localmodel_") || name.startsWith("$MDU:anymodel_") || scope.secrets.has(baseOf(name));
}

/** The session's value scope: symbol rows, the dual-lanes bands, and the
 *  lineage's secret flows. */
export function valueScope(vm: SessionViewModel, extra?: Map<string, string>): ValueScope {
  const values = new Map<string, string>();
  const secrets = new Set<string>();
  const known = new Set<string>();
  const put = (name: string, value: string | null): void => {
    known.add(baseOf(name));
    if (value === null) return;
    if (!values.has(name)) values.set(name, value);
  };
  for (const r of vm.symbols) put(r.name, r.value);
  for (const s of vm.dualLanes.steps) {
    const bands = s.step === "tool" ? [...s.upSyms, ...s.downSyms] : s.step === "response" ? s.symbols : [];
    for (const b of bands) put(b.name, b.value);
    if (s.step === "tool") for (const n of s.newSymbols) known.add(baseOf(n));
    if (s.step === "os") for (const n of s.newSymbols ?? []) known.add(baseOf(n));
  }
  for (const f of vm.lineage.flows) {
    const secret = isSecretFlow(f);
    if (secret) secrets.add(baseOf(f.root));
    for (const n of f.nodes) {
      const ref = n.symbol;
      if (!ref) continue;
      known.add(baseOf(ref.name));
      const level = ref.confidentiality;
      if (secret || (typeof level === "string" && level !== "" && level !== "public")) secrets.add(baseOf(ref.name));
    }
  }
  if (extra) for (const [k, v] of extra) if (!values.has(k)) values.set(k, v);
  return { values, secrets, known, sessionId: vm.sessionId };
}

function lookup(name: string, scope: ValueScope): string | null {
  if (isSecretName(name, scope)) return null;
  if (!scope.known.has(baseOf(name))) return null;
  return scope.values.get(name) ?? null;
}

/** Expand `text` one level at a time (at most 8): each token becomes its value
 *  when it is known and not secret, else a chip. */
export function revealParts(text: string, scope: ValueScope, depth = 0): StoryPart[] {
  const out: StoryPart[] = [];
  let last = 0;
  const push = (p: StoryPart): void => {
    const prev = out[out.length - 1];
    if (p.kind === "text" && prev?.kind === "text") prev.text += p.text;
    else out.push(p);
  };
  for (const m of tokensIn(text)) {
    if (m.index > last) push(t(text.slice(last, m.index)));
    const secret = isSecretName(m.name, scope);
    const v = secret ? null : lookup(m.name, scope);
    if (v !== null && depth < 8) for (const p of revealParts(v, scope, depth + 1)) push(p);
    else push(chip(secret, earlyOf(m.name, scope)));
    last = m.end;
  }
  if (last < text.length) push(t(text.slice(last)));
  return out;
}

/** The AI's own text: every token a chip (secret or masked), nothing resolved. */
export function aiParts(text: string, scope: ValueScope): StoryPart[] {
  const out: StoryPart[] = [];
  let last = 0;
  for (const m of tokensIn(text)) {
    if (m.index > last) out.push(t(text.slice(last, m.index)));
    out.push(chip(isSecretName(m.name, scope), earlyOf(m.name, scope)));
    last = m.end;
  }
  if (last < text.length) out.push(t(text.slice(last)));
  return out;
}

const partsText = (parts: StoryPart[]): string => parts.map((p) => (p.kind === "masked" ? `[${p.text}]` : p.text)).join("");

/** Harness `<system-reminder>` blocks: not part of what the tool returned. */
const REMINDER_RE = /\n*<system-reminder>[\s\S]*?<\/system-reminder>\s*/g;

/** The original a click reveals: secret anywhere in the item → nothing. */
function hiddenOf(text: string | null, secret: boolean, scope: ValueScope): StoryHidden {
  if (secret || text === null) return { text: null, secret, truncated: false };
  const parts = revealParts(text, scope);
  const whole = partsText(parts).replace(REMINDER_RE, "\n").trim();
  if (parts.every((p) => p.kind === "masked")) return { text: null, secret: parts.some((p) => p.text === "secret"), truncated: false };
  const cap = scope.hiddenCap ?? HIDDEN_CAP;
  return whole.length > cap
    ? { text: whole.slice(0, cap), secret: false, truncated: true }
    : { text: whole, secret: false, truncated: false };
}

/**
 * The secret tokens of a session a signed-in person may see the value of
 * (dashboard.md §4.25b "Showing a real value"): every token the session
 * RECORDED (its symbol rows, the bands, the lineage) that the same rule
 * `revealParts` uses calls a secret. The reveal route resolves a ref only
 * against this set, so it is never a general desymbolize.
 */
export function revealableSecrets(vm: SessionViewModel): Set<string> {
  const scope = valueScope(vm);
  const names = new Set<string>();
  const consider = (n: string | null | undefined): void => {
    if (n && isSecretName(n, scope) && scope.known.has(baseOf(n))) names.add(n);
  };
  for (const f of vm.lineage.flows) {
    consider(f.root);
    for (const n of f.nodes) consider(n.symbol?.name);
  }
  for (const r of vm.symbols) consider(r.name);
  for (const s of vm.dualLanes.steps) {
    if (s.step === "tool") for (const m of tokensIn(s.resultAgent ?? "")) consider(m.name);
  }
  return names;
}

/** Fetch the values the page will need and does not have, ONE LEVEL at a
 *  time (the arbiter's shallow `resolve`), so every nested token passes the
 *  same secret and known checks before it is expanded. Bounded; a failure
 *  leaves the item masked. Returns the fetched values. */
export async function revealValues(
  vm: SessionViewModel,
  resolve: ((name: string) => Promise<string | null>) | undefined,
  max = 200,
): Promise<Map<string, string>> {
  const got = new Map<string, string>();
  if (!resolve) return got;
  const scope = valueScope(vm);
  const frontier: string[] = [];
  for (const s of vm.dualLanes.steps) {
    if (s.step === "tool") frontier.push(...tokensIn(s.resultAgent ?? "").map((m) => m.name));
    if (s.step === "response") frontier.push(...tokensIn(s.text).map((m) => m.name));
  }
  const seen = new Set<string>();
  let budget = max;
  while (frontier.length && budget > 0) {
    const name = frontier.shift()!;
    if (seen.has(name)) continue;
    seen.add(name);
    if (isSecretName(name, scope) || !scope.known.has(baseOf(name))) continue;
    let v = scope.values.get(name) ?? got.get(name) ?? null;
    if (v === null) {
      budget--;
      try {
        v = await resolve(name);
      } catch {
        v = null;
      }
      if (v === null) continue;
      got.set(name, v);
    }
    frontier.push(...tokensIn(v).map((m) => m.name));
  }
  return got;
}

// ── Steps and turns ──────────────────────────────────────────────────────────

const RESULT_SYMBOL_RE = /"result_symbol"\s*:\s*"((?:[^"\\]|\\.)*)"/;
/** The reader's answer: the envelope's `result_symbol` wherever it is, else
 *  the bare answer token the MCP result's text holds (inspect-answer.ts). */
function resultSymbolOf(text: string | null): string | null {
  const m = text ? RESULT_SYMBOL_RE.exec(text) : null;
  if (!m) return inspectAnswer(text)?.answer ?? null;
  try {
    return JSON.parse(`"${m[1]}"`) as string;
  } catch {
    return m[1]!;
  }
}

/** What the AI got for a masked result: one placeholder for the whole of it,
 *  or the result with placeholders inside it (a `.env` whose PASTE_KEY alone
 *  is masked: the rest reached the AI as it was). `held`: the tokens it kept
 *  from the AI (`heldTokens`), the ones counted as real values. `early`:
 *  the AI read a secret it held as it was before its label, when. `note`:
 *  the proxy's `[mandu:secret]` note, which it appends after the result; it
 *  is Mandu's, not part of the result (a command's output masked whole reads
 *  whole). */
function maskedResultParts(text: string | null, secret: boolean, held: readonly string[], early?: string, note?: string | null): StoryPart[] {
  let body = (text ?? "").replace(REMINDER_RE, "\n").trim();
  if (note && body.endsWith(note)) body = body.slice(0, -note.length).trim();
  const toks = tokensIn(body);
  if (toks.length === 0 || (toks.length === 1 && toks[0]!.index === 0 && toks[0]!.end === body.length)) {
    return [t("Got "), chip(secret, early), t(" in place of the result.")];
  }
  const n = new Set(held).size;
  return [t("Got the result with "), chip(secret, early), t(n === 1 ? " in place of the real value." : ` in place of ${n} real values.`)];
}

/** Each item once: a named secret by its name (two `.env` files' `PASTE_KEY`
 *  read as one, as the send steps name them), anything else by its token, so
 *  an unnamed item is never merged with another. */
function distinctItems(names: readonly string[], label: ItemLabel): string[] {
  const seen = new Set<string>();
  return names.filter((n) => {
    const l = label(n);
    const key = l.secret && l.name ? "name:" + l.name : "token:" + n;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Which secrets a masked result held, by the names the send steps use
 *  ("The result held your secret `PASTE_KEY`."), never a token or value. */
function heldParts(names: readonly string[], label: ItemLabel): StoryPart[] {
  const items = distinctItems(names, label);
  // The proxy's secret note alone: a secret, not which.
  if (!items.some((n) => label(n).secret)) return [t("The result held a secret.")];
  return [t("The result held "), ...itemsParts(items, label), t(".")];
}

/** Why a result was masked whole, from the proxy's note (secret-note.ts
 *  `maskCause`): "The command names your secret file `./.env`, so Mandu hid
 *  its whole output from the AI, even whether it worked." or "`psql` read
 *  your secret file `~/.pgpass`, so Mandu hid the whole result from the
 *  AI." (the second form is also an MCP server's or the agent's own
 *  receipt, so it says no "command"). A file under `home` reads `~/…`.
 *  Null when the note gives no such reason, or when the result held a
 *  secret the page can name (its name says more). */
function causeParts(note: string | null | undefined, held: readonly string[], label: ItemLabel, home: string): StoryPart[] | null {
  const cause = maskCause(note);
  if (!cause || held.some((n) => label(n).secret && label(n).name)) return null;
  if (cause.kind === "names") return [t("The command names "), ...causeFiles(cause.paths, home), t(", so Mandu hid its whole output from the AI, even whether it worked.")];
  return [
    ...(causePrograms(cause.apps) ?? [t("A program")]), t(" read "), ...causeFiles(cause.files, home),
    t(", so Mandu hid the whole result from the AI."),
  ];
}

/** The note under a step whose sentence shows a secret's chip: the AI's
 *  call held the masked version (its recorded input holds the token), not
 *  the value. One secret used twice counts once. */
function maskedUseNote(sentence: readonly StoryPart[]): string | null {
  const chips = sentence.filter((p) => p.kind === "masked" && p.text === "secret");
  const n = new Set(chips.map((p, i) => p.name ?? `#${i}`)).size;
  if (!n) return null;
  return n === 1 ? "The AI used the masked version of your secret, not its real value." : "The AI used the masked versions of your secrets, not their real values.";
}

function toolStep(step: DualToolStep, row: PairedToolRow, scope: ValueScope, label: ItemLabel, home = "", labelled?: LaterLabel, dev = true): Extract<StoryStep, { kind: "action" }> {
  const { icon, sentence } = actionSentence(step, label, home);
  let { outcome, note, noteParts } = actionOutcome(step, dev);
  // A Read of a file labelled after it, which this session's own record
  // never learned (later-labels.ts): the AI got it as it was, and the page
  // says when the file was marked.
  if (labelled && outcome === "plain") return {
    kind: "action", id: step.id, ts: step.ts, icon, sentence, outcome: "raw", split: null,
    note: "The AI got this as it was: nothing marked it a secret when it read it.",
    later: [t("Marked a secret at "), at(labelled.at), t(", after this read: the AI saw its real value.")],
  };
  // What the result kept from the AI: a placeholder it only echoed is not
  // one (a blocked curl's refusal names the token the AI sent).
  const resultToks = heldTokens(step);
  const anySecret = (names: (string | null)[]): boolean => names.some((n) => n !== null && isSecretName(n, scope));
  let split: StorySplit | null = null;

  if (isInspect(step.tool)) {
    const answerTok = resultSymbolOf(step.resultAgent);
    const rawAnswer = resultSymbolOf(step.resultHuman);
    const input = row.inspect?.inputSymbol ?? str(argsOf(step.input)["symbol"]);
    const secret = anySecret([answerTok, input]) || !!step.secretNote;
    const answerMasked = answerTok !== null && tokensIn(answerTok).length > 0;
    const original = rawAnswer && rawAnswer !== answerTok && tokensIn(rawAnswer).length === 0 ? rawAnswer : answerTok;
    const error = /"content_kind"\s*:\s*"error_or_refusal"/.test(step.resultAgent ?? "");
    // Plan 11 D6: which model read it, when the event recorded it ("Read by
    // your own model (ollama)." / "Read by the helper."). Absent: as before.
    const readBy = row.inspect?.readByWords;
    const who: StoryPart[] = readBy ? [t(readBy.charAt(0).toUpperCase() + readBy.slice(1) + ". ")] : [];
    split = {
      ai: answerMasked ? [t("Got the answer only as "), chip(secret), t(".")] : [t("Got the reader's answer.")],
      real: error
        ? [...who, t("The reader found an error message, not the data it was asked for. Its answer:")]
        : [...who, t("The reader's answer:")],
      hidden: hiddenOf(original, secret, scope),
    };
    note = null;
    noteParts = undefined;
  } else if (row.masked && resultToks.length) {
    const secret = anySecret(resultToks) || !!step.secretNote;
    // The original a click shows is withheld for an echoed secret too.
    const withhold = secret || anySecret(tokensIn(step.resultAgent ?? "").map((m) => m.name));
    if (outcome === "plain" || outcome === "masked") outcome = secret ? "secret" : "masked";
    const hidden = hiddenOf(step.resultAgent, withhold, scope);
    // Each secret the result held, by name and opaque ref, for a signed-in
    // "Show the real value" (never the token, never the value).
    if (withhold) {
      const toks = tokensIn(step.resultAgent ?? "").map((m) => m.name);
      const held = [...new Set(toks.filter((n) => isSecretName(n, scope) && scope.known.has(baseOf(n))))];
      if (held.length) hidden.secrets = held.slice(0, 8).map((n) => ({ ref: secretRef(scope.sessionId ?? "", n), name: label(n).name }));
    }
    split = {
      ai: maskedResultParts(step.resultAgent, secret, resultToks, firstEarly(resultToks, scope), step.secretNote),
      real: secret ? causeParts(step.secretNote, resultToks, label, home) ?? heldParts(resultToks, label) : [t("The real result:")],
      hidden,
    };
    if (outcome === "masked" || outcome === "secret") note = null;
  }
  // Read as it was, masked only in later requests: say when, and why.
  let later: StoryPart[] | undefined;
  if (outcome === "raw" && step.maskedLater) {
    const secret = anySecret(step.maskedLater.symbols);
    note = secret
      ? "The AI got this as it was: nothing marked it a secret when it read it."
      : "The AI got this as it was: nothing marked it for masking when it read it.";
    later = [t("Masked from "), at(step.maskedLater.ts), t(secret ? " on, after it was marked a secret." : " on.")];
  }
  // A call to Mandu's own rule tools: what Mandu answered, from its recorded
  // envelope only (a masked or other result says nothing). A change it made
  // or a request it filed is linked in Approvals (`ask` on "Approvals").
  const policy = manduPolicyTool(step.tool);
  const answer = policy && outcome === "plain" && note === null ? policyToolAnswerParts(policy, step.resultAgent) : null;
  if (answer) {
    note = answer.map((p) => p.text).join("");
    noteParts = answer.some((p) => p.ask) ? answer : undefined;
  }
  // Mandu's in-context read: what Mandu answered, from the relay's own
  // text only (a masked or other result says nothing).
  const declassify = isManduDeclassify(step.tool);
  if (declassify && outcome === "plain") note ??= declassifyAnswer(step.resultAgent);
  // A call the proxy rewrote so that it could not run: what Mandu stopped,
  // never the rewrite (§4.25b *A call Mandu rewrote reads as what it stopped*).
  const rewritten = outcome === "blocked" ? rewrittenCall(step) : null;
  if (rewritten) {
    const { why: rwhy, askId, ...words } = rewritten;
    return { kind: "action", id: step.id, ts: step.ts, ...words, outcome, split, ...(rwhy ? { why: rwhy } : {}), ...(askId ? { askId } : {}) };
  }
  // A block, a wait or a leak keeps its own note. A request for a secret's
  // real value is not a use of its masked version.
  if (!declassify) note ??= maskedUseNote(sentence);
  // A block or a wait says why, and that Mandu asked you, from its deciding check.
  const stop = outcome === "blocked" || outcome === "waiting" ? outcome : null;
  const gate = stop ? decidingGate(step, stop) : undefined;
  const why = gate && stop ? blockWhy(gate.ruleRef, { outcome: stop }) : null;
  return {
    kind: "action", id: step.id, ts: step.ts, icon, sentence, outcome, note, ...(noteParts && note !== null ? { noteParts } : {}), split,
    ...(later ? { later } : {}), ...(why ? { why } : {}), ...(gate?.askId ? { askId: gate.askId } : {}),
  };
}

/** A check that stopped the call: a recorded denial, or block words in its
 *  recorded text from a check that did not let it through. */
function stopsCall(g: DualToolStep["gates"][number]): boolean {
  return g.usage === "deny" || (g.usage !== "allow" && BLOCK_RE.test(g.text));
}

/** A blocked call whose recorded input is the proxy's rewrite
 *  (gate-rewrite.ts), told as the block it was: what Mandu stopped, the
 *  host its net check recorded, and why: the check's rule when the page
 *  words it, else the reason the exec notice gives. Null unless a check of
 *  the rewrite's own kind stopped the call: a model can write the sentinel
 *  itself, and Codex's checks never join their call (§4.2f). */
function rewrittenCall(step: DualToolStep): { icon: Icon; sentence: StoryPart[]; note: string | null; why: StoryPart[] | null; askId?: string } | null {
  const r = gateRewrite(step.input);
  if (!r) return null;
  const kind = rewriteCheckKind(r);
  const gate = step.gates.find((g) => g.kind === kind && stopsCall(g));
  if (!gate) return null;
  const ask = gate.askId ? { askId: gate.askId } : {};
  if (r.kind === "command") {
    return { icon: "run", sentence: [t("Mandu stopped a command before it ran")], note: null, why: blockWhy(gate.ruleRef, { outcome: "blocked" }) ?? noticeWhy(r.reason), ...ask };
  }
  if (r.kind === "search") {
    return { icon: "search", sentence: [t("Mandu blocked a web search")], note: "The AI's search words were never sent.", why: blockWhy(gate.ruleRef, { outcome: "blocked" }), ...ask };
  }
  // The host the AI asked for, as its net check recorded it (never a token).
  const host = gate.target && tokensIn(gate.target).length === 0 ? gate.target.replace(/:443$/, "") : null;
  return {
    icon: "web", sentence: host ? [t("Mandu blocked opening a web page on "), c(host)] : [t("Mandu blocked opening a web page")],
    note: "The request was never sent.", why: blockWhy(gate.ruleRef, { outcome: "blocked", host }), ...ask,
  };
}

/** The check that stopped a blocked or held tool step: the first gate that
 *  blocked it, or held it for the person. Its rule says why, in the page's
 *  words (block-why.ts), and its Approvals row, when it filed one, that
 *  Mandu asked you. A block with no such gate (a usage verdict alone) has
 *  neither; a rule the page does not word gives no why. The gate's host is
 *  not read: the step's own sentence names it. */
function decidingGate(step: DualToolStep, outcome: "blocked" | "waiting"): DualToolStep["gates"][number] | undefined {
  return step.gates.find((x) => (outcome === "waiting" ? x.usage === "needs_approval" : stopsCall(x)));
}

const SEVERITY: StoryOutcome[] = ["unmasked", "blocked", "waiting", "raw", "secret", "masked", "sandbox", "sent", "plain"];
const worst = (a: StoryOutcome, b: StoryOutcome): StoryOutcome => (SEVERITY.indexOf(a) <= SEVERITY.indexOf(b) ? a : b);

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** The masked items a story step names, for its turn's summary: what a
 *  masked result held, what a send carried or was blocked with (tokens; the
 *  summary names them through the same label as the step). `reads`: the
 *  reads of secret files a blocked step's note says Mandu refused (`denied`
 *  + `held`), when that refusal, not a check, is what blocked it. */
export interface StepItems {
  held?: readonly string[];
  carried?: readonly string[];
  reads?: number;
  /** A Read of a file labelled after it (later-labels.ts): the file's base
   *  name, as the step names it. */
  laterFile?: string;
}

/** What the turn's masked results held, each secret once: "your secret `A`",
 *  "1 secret" (no name known: a result that held only the proxy's note, or
 *  an unnamed secret), "your secret `A` and 1 other secret". */
function hidParts(held: readonly (readonly string[] | undefined)[], label: ItemLabel): StoryPart[] {
  let unnamed = 0;
  const tokens: string[] = [];
  for (const names of held) {
    const secrets = (names ?? []).filter((n) => label(n).secret);
    if (secrets.length) tokens.push(...secrets);
    else unnamed++;
  }
  const items = distinctItems(tokens, label);
  const named = items.map((n) => label(n).name).filter((n): n is string => !!n);
  unnamed += items.length - named.length;
  if (!named.length) return [t(plural(unnamed, "secret", "secrets"))];
  return [...namedParts(named), ...(unnamed ? [t(` and ${plural(unnamed, "other secret", "other secrets")}`)] : [])];
}

/** The turn's one-line summary of what Mandu did, as parts (a secret named
 *  by its label, as code) and as plain text. `items` and `label` name what
 *  the turn's results held and its sends carried; without them (or for a
 *  step they do not cover) the summary counts instead of naming. */
export function turnSummary(
  steps: StoryStep[],
  items: ReadonlyMap<string, StepItems> = new Map(),
  label: ItemLabel = () => ({ secret: false, name: null }),
): { summary: string | null; parts: StoryPart[] | null; tone: StoryOutcome } {
  const n: Record<StoryOutcome, number> = { unmasked: 0, blocked: 0, waiting: 0, raw: 0, secret: 0, masked: 0, sandbox: 0, sent: 0, plain: 0 };
  const of: Partial<Record<StoryOutcome, string[]>> = {};
  let tone: StoryOutcome = "plain";
  let actions = 0;
  let files = 0;
  for (const s of steps) {
    if (s.kind === "setup") { files += s.files.length; tone = worst(tone, "masked"); continue; }
    if (s.kind !== "action") continue;
    actions++;
    n[s.outcome]++;
    (of[s.outcome] ??= []).push(s.id);
    tone = worst(tone, s.outcome);
  }
  if (!actions && !files) return { summary: null, parts: null, tone };
  // What the steps of one outcome carried, only when every one of them is
  // known to have carried something; else null (the summary counts).
  const carriedBy = (outcome: StoryOutcome): string[] | null => {
    const lists = (of[outcome] ?? []).map((id) => items.get(id)?.carried ?? []);
    return lists.length && lists.every((l) => l.length) ? distinctItems(lists.flat(), label) : null;
  };
  const out: StoryPart[][] = [];
  if (files) out.push([t(`Mandu masked ${plural(files, "file", "files")} in the workspace before the agent started.`)]);
  if (n.unmasked) out.push([t(`${plural(n.unmasked, "item", "items")} reached the AI without a mask.`)]);
  if (n.raw) {
    // `held` of a raw step: the tokens later requests masked it to.
    const held = (of.raw ?? []).map((id) => items.get(id)?.held ?? []);
    // A read of a file labelled after it (later-labels.ts) names its file.
    const files = (of.raw ?? []).map((id) => items.get(id)?.laterFile ?? null);
    const secret = files.some((f) => f !== null) || held.some((h) => h.some((x) => label(x).secret));
    // Named when every such read held only secrets the page can name
    // ("your secret `staging.conf`"), or is of a file labelled after it;
    // else counted.
    const nameable = held.every((h, i) => files[i] !== null || (h.length > 0 && h.every((x) => label(x).secret && label(x).name)));
    const named = nameable
      ? [...new Set([...distinctItems(held.filter((_, i) => files[i] === null).flat(), label).map((x) => label(x).name!), ...files.filter((f): f is string => f !== null)])]
      : null;
    const one = named ? named.length === 1 : n.raw === 1;
    out.push([
      t("The AI read "), ...(named ? namedParts(named) : [t(plural(n.raw, "item", "items"))]),
      t(` as ${one ? "it was" : "they were"}: ${one ? "it was" : "they were"} ${secret ? "marked secret" : "masked"} only later.`),
    ]);
  }
  const did: StoryPart[][] = [];
  if (n.blocked) {
    // Each kind of block in its own words, so one kind never hides another's
    // names: the sends whose items are known, named; the rest, counted as
    // actions; the refused reads of secret files, counted as reads, as each
    // step's note counts them.
    const blocked = of.blocked ?? [];
    const sends = blocked.filter((id) => items.get(id)?.carried?.length);
    const reads = blocked.filter((id) => !items.get(id)?.carried?.length && items.get(id)?.reads);
    const rest = blocked.length - sends.length - reads.length;
    if (sends.length) {
      const carried = distinctItems(sends.flatMap((id) => items.get(id)?.carried ?? []), label);
      did.push([t(`blocked ${plural(sends.length, "request", "requests")} that carried `), ...itemsParts(carried, label)]);
    }
    if (rest) did.push([t(`blocked ${sends.length ? plural(rest, "other action", "other actions") : plural(rest, "action", "actions")}`)]);
    if (reads.length) {
      const r = reads.reduce((a, id) => a + (items.get(id)?.reads ?? 0), 0);
      did.push([t(`stopped ${r === 1 ? "1 read of a secret file" : `${r} reads of secret files`}`)]);
    }
  }
  if (n.masked) did.push([t(`masked ${plural(n.masked, "item", "items")}`)]);
  if (n.secret) did.push([t("hid "), ...hidParts((of.secret ?? []).map((id) => items.get(id)?.held), label), t(" from the AI")]);
  if (did.length) out.push([t("Mandu "), ...did.flatMap((d, i) => (i === 0 ? d : [t(i === did.length - 1 ? " and " : ", "), ...d])), t(".")]);
  if (n.waiting) out.push([t(`${plural(n.waiting, "step is", "steps are")} waiting for your OK.`)]);
  if (n.sandbox) out.push([t(`The sandboxed reader answered ${plural(n.sandbox, "question", "questions")} for the AI.`)]);
  if (n.sent) {
    const carried = carriedBy("sent");
    // "each" only of more than one: one request went to one destination.
    out.push([
      t(`${plural(n.sent, "request", "requests")} left this machine with `),
      ...(carried ? itemsParts(carried, label) : [t("a real value")]),
      t(` filled in, ${n.sent === 1 ? "to" : "each to"} a destination allowed to receive it.`),
    ]);
  }
  if (!out.length) out.push([t("Nothing here needed guarding.")]);
  // One run of parts: the sentences joined by a space, adjacent text merged.
  const parts: StoryPart[] = [];
  for (const p of out.flatMap((s, i) => (i === 0 ? s : [t(" "), ...s]))) {
    const prev = parts[parts.length - 1];
    if (p.kind === "text" && prev?.kind === "text") prev.text += p.text;
    else parts.push({ ...p });
  }
  return { summary: parts.map((p) => p.text).join(""), parts, tone };
}

/** Hosts the background line names before "and N more". */
export const ROUTINE_HOST_CAP = 3;

/** Each background kind (paired-rows.ts `backgroundOf`) in plain words, in
 *  the order the line names them. None is a "check" unless Mandu checked
 *  it: a connection is a connection. */
const ROUTINE_WORDS: readonly [BackgroundCategory, (n: number) => string][] = [
  ["connections", (n) => plural(n, "connection", "connections")],
  ["command-checks", (n) => `${plural(n, "command", "commands")} Mandu checked`],
  ["paths", (n) => `${plural(n, "file path", "file paths")} translated between your folder and the AI's masked copy of it`],
  ["reply-checks", (n) => `${plural(n, "update", "updates")} to your screen with the real text in place of masked items`],
  ["sandbox-records", (n) => `${plural(n, "record", "records")} of the sandboxed reader's work, shown above`],
];

/** A turn's background line: "In the background: 4 connections to
 *  `api.anthropic.com`; 1 command Mandu checked." Each kind once, hosts as
 *  code (three, then "and N more"). A kind this list does not know is
 *  counted as "other steps", never dropped. */
export function routineParts(groups: readonly BackgroundGroup[]): StoryPart[] {
  const count = (cat: BackgroundCategory): number => groups.filter((g) => g.category === cat).reduce((a, g) => a + g.count, 0);
  const items: StoryPart[][] = [];
  for (const [cat, words] of ROUTINE_WORDS) {
    const n = count(cat);
    if (!n) continue;
    const item = [t(words(n))];
    if (cat === "connections") {
      const hosts = [...new Set(groups.filter((g) => g.category === cat).flatMap((g) => g.labels))];
      const shown = hosts.slice(0, ROUTINE_HOST_CAP);
      const more = hosts.length - shown.length;
      if (shown.length) item.push(t(" to "));
      shown.forEach((h, i) => {
        if (i > 0) item.push(t(i === shown.length - 1 && !more ? " and " : ", "));
        item.push(c(h));
      });
      if (more) item.push(t(` and ${more} more`));
    }
    items.push(item);
  }
  const known = new Set(ROUTINE_WORDS.map(([cat]) => cat));
  const other = groups.filter((g) => !known.has(g.category)).reduce((a, g) => a + g.count, 0);
  if (other) items.push([t(plural(other, "other step", "other steps"))]);
  const out: StoryPart[] = [];
  for (const p of [t("In the background: "), ...items.flatMap((x, i) => (i === 0 ? x : [t("; "), ...x])), t(".")]) {
    const prev = out[out.length - 1];
    if (p.kind === "text" && prev?.kind === "text") prev.text += p.text;
    else out.push({ ...p });
  }
  return out;
}

/** One background step in plain words, by its kind (the background line's
 *  words, one at a time): a connection names its host, a command its
 *  masked form (chips for masked items, as a step's command). */
function backgroundWords(cat: BackgroundCategory | string, s: DualOsStep, label: ItemLabel): StoryPart[] {
  switch (cat) {
    case "connections": {
      const host = netHost(s);
      return host ? [t("Connected to "), c(host)] : [t("Made a connection")];
    }
    case "command-checks": {
      const { subject } = osSubject(s);
      return [t("Mandu checked a command"), ...(subject ? [t(": "), ...codeParts(subject, label, 60)] : [])];
    }
    case "paths": return [t("Translated a file path between your folder and the AI's masked copy of it")];
    case "reply-checks": return [t("Updated your screen with the real text in place of masked items")];
    case "sandbox-records": return [t("Recorded the sandboxed reader's work, shown above")];
    default: return [t("Another step that needed nothing from you")];
  }
}

/** Each background step of a turn, oldest first, at most BACKGROUND_ALL_CAP
 *  (dashboard.md §4.25ae): what the background line counts, one by one. A
 *  folded repeat says how many times. Pure. */
export function backgroundItems(groups: readonly BackgroundGroup[], byId: ReadonlyMap<string, DualStep>, label: ItemLabel = PREFIX_LABEL): { items: BackgroundItem[]; moreItems: number } {
  const all: BackgroundItem[] = [];
  for (const g of groups) {
    for (const id of g.stepIds) {
      const s = byId.get(id);
      if (!s || s.step !== "os") continue;
      const parts = backgroundWords(g.category, s, label);
      if (s.repeats > 1) parts.push(t(` (${s.repeats} times)`));
      all.push({ ts: s.ts, parts });
    }
  }
  all.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));
  return { items: all.slice(0, BACKGROUND_ALL_CAP), moreItems: Math.max(0, all.length - BACKGROUND_ALL_CAP) };
}

/**
 * What the leak check found (dashboard.md §4.25ae): each place a recorded
 * event says something reached the AI without a mask, in plain words, with
 * when and the step on the page that shows it (`shown`: the action steps the
 * page draws; a time there opens it). A tool call's result names the secrets
 * it held by their names; a request to the AI says so. The check's own detail
 * (the text it found) is never read: a value appears only where the page
 * already shows one, the step's own *Show what was hidden* or *Show the real
 * value*, signed in. null when the check never fired. Pure.
 */
export function leakFinding(vm: SessionViewModel, turns: readonly StoryTurn[], shown: ReadonlySet<string>): LeakFinding | null {
  if (vm.invariant.holds) return null;
  const scope = valueScope(vm);
  const origins = new Map(vm.symbols.map((r) => [r.name, r.origin ?? null]));
  const dual = new Map<string, DualStep>(vm.dualLanes.steps.map((s) => [s.id, s]));
  const ids = new Set(dual.keys());
  const story = new Map<string, Extract<StoryStep, { kind: "action" }>>();
  for (const turn of turns) for (const s of turn.steps) if (s.kind === "action") story.set(s.id, s);
  const seen = new Set<string>();
  const items: LeakFindingItem[] = [];
  const named: string[][] = [];
  for (const row of vm.timeline) {
    if (!row.violated) continue;
    const stepId = stepIdOfEvent({ id: row.id, callId: row.callId }, ids);
    const key = stepId ?? row.id;
    if (seen.has(key)) continue;
    seen.add(key);
    const opens = stepId && shown.has(stepId) ? stepId : undefined;
    const when: StoryPart = opens ? { kind: "time", text: row.ts, step: opens } : at(row.ts);
    const step = stepId ? story.get(stepId) : undefined;
    const tool = stepId ? dual.get(stepId) : undefined;
    let parts: StoryPart[];
    let names: string[] = [];
    if (step && tool?.step === "tool") {
      parts = [t("At "), when, t(", the result of this step reached the AI without a mask: "), ...step.sentence, t(".")];
      names = [...new Set(tool.upSyms.map((b) => b.name).filter((n) => isSecretName(n, scope)).map((n) => secretShortName(n, origins.get(n) ?? origins.get(baseOf(n)) ?? null)).filter((n): n is string => !!n))];
      if (names.length) parts.push(t(" It held "), ...namedParts(names), t("."));
    } else if (row.kind === "tllm_call") {
      parts = [t("At "), when, t(", a request to the AI carried an item as it was, though Mandu had masked it.")];
    } else {
      parts = [t("At "), when, t(", a step reached the AI without a mask.")];
    }
    items.push({ ts: row.ts ?? null, ...(opens ? { step: opens } : {}), parts });
    named.push(names);
  }
  // What to do now names only what the lines drawn above it name.
  const shownNames = named.slice(0, FINDING_CAP);
  const todo = findingTodo([...new Set(shownNames.flat())], items.length === 0 || shownNames.some((n) => n.length === 0));
  return { count: vm.invariant.violationCount, items: items.slice(0, FINDING_CAP), more: Math.max(0, items.length - FINDING_CAP), todo };
}

/**
 * The leak check's *What to do now* (dashboard.md §4.25ae), one line each:
 * change each secret the lines name (`names`, in their order, at most
 * TODO_NAMES_CAP, the rest counted), since the AI's provider received it and
 * nothing Mandu does now takes it back; when a line names none (`unnamed`),
 * the same for whatever it was; and always, that this is a fault in Mandu
 * to report, linked to the issue tracker. Names only, never a value. Pure.
 */
export function findingTodo(names: readonly string[], unnamed: boolean): StoryPart[][] {
  const out: StoryPart[][] = names.slice(0, TODO_NAMES_CAP).map((n) => [
    t("Change "), c(n), t(" where it was issued, and turn the old one off: the AI's provider received it as it was."),
  ]);
  const rest = names.length - TODO_NAMES_CAP;
  if (rest > 0) out.push([t(`And ${rest} more: change each the same way.`)]);
  if (unnamed) {
    out.push([t(names.length
      ? "If what reached the AI held a key or a password, change it the same way. Open the step to see what it was."
      : "If what reached the AI held a key or a password, change it where it was issued, and turn the old one off. Open the step to see what it was.")]);
  }
  out.push([
    t("This is a fault in Mandu, not in your rules. "),
    { kind: "text", text: "Report a problem", href: ISSUES_URL },
    t(", with this session's time. Never paste the key itself."),
  ]);
  return out;
}

export interface AgentPageInput {
  session: SessionRef | null;
  id: string;
  vm: SessionViewModel | null;
  cwd: string | null;
  waiting: HomeAsk[];
  /** Values fetched by `revealValues` (the route); absent in pure use. */
  values?: Map<string, string>;
  /** False when the viewer has no admin session (dashboard.md §6): the
   *  route built `vm` from the signed-out projection. Absent = true. */
  valuesShown?: boolean;
  /** `?ask=`: the ask to mark, and the step `locateAsk` found for it. */
  focus?: { ask: string; stepId: string | null; match: "exact" | "destination" | null };
  /** The arbiter's `sessionUpstream` answer; absent = not asked or no answer. */
  upstream?: { endpoint: string | null; location: string } | null;
  /** The session's BELIEVED events (the prompt filter's notes, plan 15
   *  §13.7); absent in pure use = no notes. */
  events?: readonly ManduEvent[];
  /** The view-model of the BELIEVED events only (null: none), for the claims
   *  "Your secrets" makes; absent in pure use = `vm`. */
  believedVm?: SessionViewModel | null;
  /** The person's home folder: "Your secrets" and a step's words name a
   *  file under it `~/…` (the route's; absent in pure use = paths as
   *  recorded). */
  home?: string;
  /** The administrator's prompt filter locks in force (the arbiter's
   *  `promptFilters` rows): a note offers no let-through the arbiter
   *  refuses. Absent or null = the events alone decide. */
  promptLocks?: PromptLocks | null;
  /** The answered rows of the approval queue, by id (the route's; absent in
   *  pure use, or with no queue): a step that asked says its row's answer. */
  answers?: ReadonlyMap<string, HomeAnswered["outcome"]>;
  /** Untrusted content is masked at the level running now (`injection`,
   *  `full`): the agent's warning is worded as its Home row's
   *  (home.ts `agentNotice`). Absent = not masked, the secrets wording. */
  masking?: boolean;
  /** The labels in force now on the files this session read, each with when
   *  it was made, from the rule-change log (the route's, later-labels.ts):
   *  a Read before its file's label says so, and *Your secrets* tells the
   *  file. Absent in pure use, or with no arbiter: no such claim. */
  labels?: readonly LabelTime[];
  /** What the page asked to see past its caps (`?turns=all`, `?steps=`,
   *  `?secrets=all`, dashboard.md §4.25ad). Absent: the caps. */
  show?: AgentPageShow;
  /** The build serves the developer view (the inspector extension,
   *  §4.25ac): the page's words may point to the detailed trace. False: no
   *  sentence does. Absent = true. */
  dev?: boolean;
  /** policy.yaml's `issuer_bindings` as the route read it, given while the
   *  level running now lists the companies under Rules › Built-in
   *  protections (`secrets`, `full`): a send to a company's own API says
   *  why it did not ask (§4.25b). Absent, or not read: no such sentence. */
  issuerBindings?: IssuerReading;
}

/** What the agent page asked to see past its caps (its *Show them*). */
export interface AgentPageShow {
  /** Every turn, not only the newest TURN_CAP (at most TURN_ALL_CAP). */
  turns?: boolean;
  /** Turns, by id, that show every step, not only the first TURN_STEP_CAP
   *  (at most TURN_STEP_ALL_CAP each). */
  steps?: ReadonlySet<string>;
  /** Every secret in Your secrets, not only the first SECRET_CAP (at most
   *  SECRET_ALL_CAP). */
  secrets?: boolean;
  /** Turns, by id, whose background steps are listed (`routine.items`,
   *  §4.25ae). */
  background?: ReadonlySet<string>;
  /** One step, by id, whose whole original the page carries in `original`
   *  (up to ORIGINAL_ALL_CAP). Only the admin route `GET /api/home/original`
   *  asks it; the page's own query (`agentShowOf`) never sets it. */
  original?: string;
}

/** `https://Host:443/x` → `host`: the form a destination is compared in. */
export function destHost(dest: string | null | undefined): string {
  return String(dest ?? "").trim().toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/[/?#].*$/, "").replace(/:(443|80)$/, "");
}

const STOPPED_RE = /\b(blocked|refused|withheld|denied|needs?[-_ ]approval|approval required)\b/i;

/**
 * The step where Mandu stopped for `ask` in this session (§4.25h), or null.
 *
 *   1. exact: the first gate event whose `policy.approvalId` is the ask's id
 *      (the proxy's fs/exec/model gates, the net-proxy's block): its tool
 *      step when the event has a call id, else its own OS step;
 *   2. destination, a network ask only (a record older than the stamp): the
 *      first stopped send to the ask's host, either a blocked connection card
 *      or a tool step whose gate note or result names the host as stopped.
 *
 * A file or command ask has no destination to match, so without the id it is
 * not located (the page says so rather than guess).
 */
export function locateAsk(
  events: readonly ManduEvent[],
  steps: readonly DualStep[],
  ask: AskRef,
): { stepId: string; match: "exact" | "destination" } | null {
  const ids = new Set(steps.map((s) => s.id));
  for (const e of events) {
    if (e.policy?.approvalId !== ask.id) continue;
    const stepId = stepIdOfEvent(e, ids);
    if (stepId) return { stepId, match: "exact" };
  }
  if (ask.family !== "network") return null;
  const host = destHost(ask.target);
  if (!host) return null;
  // The host as a whole name: `example.com` is not `notexample.com` or `a.example.com`.
  const escaped = host.replace(/[.*+?^$()|[\]\\{}]/g, "\\$&");
  const hostRe = new RegExp("(^|[^a-z0-9.-])" + escaped + "($|[^a-z0-9.-]|\\.(?![a-z0-9]))", "i");
  const names = (text: string | null | undefined): boolean => !!text && hostRe.test(text);
  for (const s of steps) {
    if (s.step === "os") {
      if (s.kind !== "net_action" && s.kind !== "exec_action") continue;
      const stopped = s.usage === "deny" || s.usage === "needs_approval" || STOPPED_RE.test(s.action ?? "");
      if (stopped && (destHost(s.target) === host || names(s.title))) return { stepId: s.id, match: "destination" };
    } else if (s.step === "tool") {
      const gate = s.gates.some((g) => names(g.text) && STOPPED_RE.test(g.text));
      const result = [s.resultHuman, s.resultAgent].some((r) => names(r) && STOPPED_RE.test(r!));
      const decided = (s.usage === "deny" || s.usage === "needs_approval") && names(s.input);
      if (gate || result || decided) return { stepId: s.id, match: "destination" };
    }
  }
  return null;
}

/** The listing label, unless it is a transcript role marker ("▸ system",
 *  a truncated harness header) — then the first question. */
function titleOf(label: string | null | undefined, story: StoryTurn[]): string | null {
  const l = oneLine(label, 120);
  // A shell escape's label is the harness tags: say the command instead.
  const sh = l ? /^<bash-input>([^<]*)/.exec(l) : null;
  if (sh) return sh[1]!.trim() ? `!${maskTokens(sh[1]!).trim()}` : null;
  if (l && !/^▸\s/.test(l)) return l;
  const first = story.find((x) => x.prompt)?.prompt;
  return first ? oneLine(first, 120) : l;
}

/** Claude Code's shell escape (`!cmd`): the harness sends the command and its
 *  output to the model wrapped in these tags. */
const SHELL_RE = /^\s*<bash-input>([\s\S]*?)<\/bash-input>\s*(?:<bash-stdout>([\s\S]*?)<\/bash-stdout>)?\s*(?:<bash-stderr>([\s\S]*?)<\/bash-stderr>)?\s*$/;

/** OpenClaw's time envelope (openclaw `formatEnvelopeTimestamp`, 2026.7.1):
 *  its chat prefixes every message the person types with
 *  `[Sun 2026-10-11 05:20 GMT+9] `, a weekday, a date, a time and a zone.
 *  The person did not write it; the page shows their question without it
 *  (seen walking the first-session tour on OpenClaw, 2026-10-11). */
const OPENCLAW_TIME_ENVELOPE_RE = /^\s*\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) \d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?(?: [A-Za-z][A-Za-z0-9+:/_-]{0,31})?\] /;

/** Your question three ways: the plain title text, the chipped parts, or a
 *  shell escape. A masked item is a chip (`secret` when it is one), never the
 *  token and never its value: this is what the AI got, not a reveal. */
export function promptOf(text: string, scope: ValueScope): Pick<StoryTurn, "prompt" | "promptParts" | "shell"> {
  text = text.replace(OPENCLAW_TIME_ENVELOPE_RE, "");
  const sh = SHELL_RE.exec(text);
  if (sh) {
    const command = maskTokens(sh[1]!).trim();
    const out = [sh[2], sh[3]].map((s) => (s ?? "").trim()).filter(Boolean).join("\n");
    return { prompt: command ? `!${command}` : null, promptParts: null, shell: command ? { command, output: out ? aiParts(out, scope) : [] } : null };
  }
  const v = text.trim();
  return v ? { prompt: maskTokens(v), promptParts: aiParts(v, scope), shell: null } : { prompt: null, promptParts: null, shell: null };
}

/** " The AI read its real value at 10:41, before it was marked a secret.",
 *  for each secret of a reply that the AI read as it was before its label
 *  (`label(..).early`), at or before the reply's moment `ts`. A secret
 *  named in more than one token counts as read when any of them was. One
 *  secret: "its"; more: "the real value of `X`", or "of a secret of
 *  yours" with no name. Empty when none, or when a time cannot be read. */
function readFirstParts(toks: readonly string[], secrets: readonly string[], ts: string, label: ItemLabel): StoryPart[] {
  const key = (n: string): string => { const l = label(n); return l.name ? "name:" + l.name : "token:" + n; };
  const first = new Map<string, string>();
  for (const n of toks) {
    const e = label(n).early;
    if (!e || !label(n).secret) continue;
    const k = key(n);
    const had = first.get(k);
    if (had === undefined || e < had) first.set(k, e);
  }
  const replyMs = Date.parse(ts);
  const out: StoryPart[] = [];
  for (const n of secrets) {
    const e = first.get(key(n));
    const ms = e === undefined ? NaN : Date.parse(e);
    if (!Number.isFinite(ms) || !Number.isFinite(replyMs) || ms > replyMs) continue;
    const name = label(n).name;
    const whose: StoryPart[] = secrets.length === 1 ? [t(" The AI read its real value at ")]
      : name ? [t(" The AI read the real value of "), c(name), t(" at ")]
      : [t(" The AI read the real value of a secret of yours at ")];
    out.push(...whose, at(e!), t(", before it was marked a secret."));
  }
  return out;
}

const sameParts = (a: readonly StoryPart[], b: readonly StoryPart[]): boolean =>
  a.length === b.length && a.every((p, i) => p.kind === b[i]!.kind && p.text === b[i]!.text);

/** A turn's reply (dashboard.md §4.25b). Two halves only where they differ:
 *  this page filled in at least one masked item. A secret is never filled
 *  in, so a reply whose items are all secrets is one card, and a line names
 *  the secrets it held ("The reply held your secret `STRIPE_KEY`. …"). A
 *  secret the AI read as it was before its label, at or before the reply,
 *  adds when ("The AI read its real value at 10:41, before it was marked a
 *  secret."): the AI's own words may say it never saw it. One card that
 *  still shows an ordinary item says why, as a step's hidden box does
 *  (`unresolved`). Names and times only, never a token or value. Null: no
 *  text. */
export function storyReply(ts: string, raw: string, scope: ValueScope, label: ItemLabel): StoryReply | null {
  const text = raw.trim();
  if (!text) return null;
  const toks = tokensIn(text).map((m) => m.name);
  if (!toks.length) return { ts, parts: [t(text)], ai: null };
  const parts = revealParts(text, scope);
  const ai = aiParts(text, scope);
  const split = !sameParts(parts, ai);
  const reply: StoryReply = { ts, parts, ai: split ? ai : null };
  const secrets = distinctItems(toks.filter((n) => label(n).secret), label);
  if (secrets.length) {
    const it = secrets.length === 1 ? "it" : "them";
    reply.kept = [t("The reply held "), ...itemsParts(secrets, label), t(`. The AI wrote ${it} masked, and this page keeps ${it} masked.`)];
    reply.kept.push(...readFirstParts(toks, secrets, ts, label));
  }
  if (!split && parts.some((p) => p.kind === "masked" && p.text !== "secret")) reply.unresolved = true;
  return reply;
}

/** `early`: the secrets the AI read as they were before their label, by
 *  base name (`pageEarlyReads`); absent: none, and no chip or reply says
 *  one was. `home`: the dashboard's home folder, so a file a step's words
 *  name reads `~/…` (absent: as recorded). `after`: the Read steps whose
 *  file was labelled after the AI read it as it was, by step id
 *  (`pageLaterLabels`); absent: none. `opts.stepCap`: the steps a turn
 *  keeps (default TURN_STEP_CAP; `capTurn` cuts a whole story later);
 *  `opts.dev`: the build serves the developer view (absent: true);
 *  `opts.background`: the turns, by id, whose background steps are listed
 *  (`routine.items`); `opts.hiddenCap`: where a revealed original is cut
 *  (absent: HIDDEN_CAP); `opts.issuers`: policy.yaml's `issuer_bindings`
 *  as the route read it, for a send to a company's own API (`osSentence`;
 *  absent: no such sentence). */
export function buildStory(vm: SessionViewModel, values?: Map<string, string>, early?: ReadonlyMap<string, string>, home = "", after?: ReadonlyMap<string, LaterLabel>, opts: { stepCap?: number; dev?: boolean; background?: ReadonlySet<string>; hiddenCap?: number; issuers?: IssuerReading } = {}): StoryTurn[] {
  const dev = opts.dev !== false;
  const scope: ValueScope = { ...valueScope(vm, values), ...(early ? { early } : {}), ...(opts.hiddenCap !== undefined ? { hiddenCap: opts.hiddenCap } : {}) };
  const origins = new Map(vm.symbols.map((r) => [r.name, r.origin ?? null]));
  const label: ItemLabel = (name) => {
    const e = earlyOf(name, scope);
    return { secret: isSecretName(name, scope), name: secretShortName(name, origins.get(name) ?? origins.get(baseOf(name)) ?? null), ...(e ? { early: e } : {}) };
  };
  const byId = new Map<string, DualStep>(vm.dualLanes.steps.map((s) => [s.id, s]));
  const turns: StoryTurn[] = [];
  for (const pt of vm.paired.turns) {
    const input = pt.inputId ? (byId.get(pt.inputId) as Extract<DualStep, { step: "input" }> | undefined) : undefined;
    const steps: StoryStep[] = [];
    const items = new Map<string, StepItems>();
    let reply: StoryReply | null = null;
    for (const r of pt.rows) {
      const s = byId.get(r.stepId);
      if (!s) continue;
      if (r.row === "tool" && s.step === "tool") {
        const labelled = after?.get(s.id);
        const step = toolStep(s, r, scope, label, home, labelled, dev);
        steps.push(step);
        // A result read as it was and masked only later: what it was masked to.
        const held = heldTokens(s);
        // Blocked by its note's refused reads alone (no check refused it),
        // read off the note as actionOutcome reads it.
        const refused = step.outcome === "blocked" && !checkBlocked(s) ? readRefusals(s.secretNote) : null;
        const reads = refused ? refused.denied + refused.held : 0;
        const file = step.outcome === "raw" && labelled && !s.maskedLater ? baseName(labelled.path) : null;
        items.set(s.id, { held: !held.length && s.maskedLater ? s.maskedLater.symbols : held, ...(reads ? { reads } : {}), ...(file ? { laterFile: file } : {}) });
      } else if (r.row === "action" && s.step === "os") {
        const o = osSentence(s, label, dev, opts.issuers);
        steps.push({ kind: "action", id: s.id, ts: s.ts, icon: o.icon, sentence: o.sentence, outcome: o.outcome, note: o.note, ...(o.noteParts ? { noteParts: o.noteParts } : {}), split: null, ...(o.why ? { why: o.why } : {}), ...(o.askId ? { askId: o.askId } : {}) });
        if (s.carried?.length) items.set(s.id, { carried: s.carried });
      } else if (r.row === "setup") steps.push({ kind: "setup", id: s.id, ts: s.ts, files: r.files.map((f) => maskTokens(f)) });
      else if (r.row === "aside") steps.push({ kind: "aside", id: s.id, ts: s.ts });
      else if (r.row === "note" && s.step === "response") {
        const text = shorten((s as DualResponseStep).text, 400);
        if (text) steps.push({ kind: "said", id: s.id, ts: s.ts, parts: aiParts(text, scope) });
      } else if (r.row === "reply" && s.step === "response") {
        reply = storyReply(s.ts, (s as DualResponseStep).text, scope, label) ?? reply;
      }
    }
    const { summary, parts: summaryParts, tone } = turnSummary(steps, items, label);
    const routineCount = pt.background.reduce((a, b) => a + b.count, 0);
    const hosts = pt.background.filter((b) => b.category === "connections").flatMap((b) => b.labels);
    const { prompt, promptParts, shell } = promptOf(input?.text ?? "", scope);
    if (!prompt && !steps.length && !reply) continue;
    turns.push(capTurn({
      id: pt.id,
      ts: input?.ts ?? steps[0]?.ts ?? reply?.ts ?? null,
      prompt,
      promptParts,
      shell,
      summary,
      summaryParts,
      tone,
      steps,
      moreSteps: 0,
      reply,
      routine: routineCount
        ? { count: routineCount, hosts: [...new Set(hosts)], parts: routineParts(pt.background), ...(opts.background?.has(pt.id) ? backgroundItems(pt.background, byId, label) : {}) }
        : null,
      promptNote: null,
    }, opts.stepCap ?? TURN_STEP_CAP));
  }
  return turns;
}

/** A turn with at most `cap` of its steps: the rest counted (`moreSteps`,
 *  added to any already left out) and the first of them named (`moreFrom`). */
export function capTurn(turn: StoryTurn, cap: number): StoryTurn {
  if (turn.steps.length <= cap) return turn;
  return { ...turn, steps: turn.steps.slice(0, cap), moreSteps: turn.moreSteps + turn.steps.length - cap, moreFrom: turn.steps[cap]!.id };
}

/** What a session's story counts, over all its turns: the steps Mandu blocked
 *  (a command, a file, a send: the page's tile) and the sends that left this
 *  machine with a masked item's real value filled in. Home counts a session
 *  by the same story, so a row and the page it opens agree
 *  (dashboard.md §4.25). Pure. */
export function storyCounts(turns: readonly StoryTurn[]): { blocked: number; sent: number } {
  let blocked = 0;
  let sent = 0;
  for (const turn of turns) {
    for (const s of turn.steps) {
      if (s.kind !== "action") continue;
      if (s.outcome === "blocked") blocked++;
      else if (s.outcome === "sent") sent++;
    }
  }
  return { blocked, sent };
}

/** "Your secrets" as the session's page tells it: its claims read the
 *  BELIEVED events (`believed`) and their view-model (`believedVm`; absent =
 *  `vm`: every event believed), the full view-model's leak check may only
 *  take them away, and the mode is the session's recorded one. Home counts a
 *  session's secrets by this same call (home-routes.ts `HomeFacts`), so a
 *  row and the tiles of the page it opens agree (dashboard.md §4.25). A
 *  file under `home` reads `~/…`. `steps`: the ids of the steps the page
 *  shows, so a card's time opens its step (absent: Home, no links). Pure. */
export function pageSecrets(vm: SessionViewModel | null, believed: readonly ManduEvent[], believedVm?: SessionViewModel | null, home = "", steps?: ReadonlySet<string>, later?: LaterLabelInput, opts?: StoryOptions): SecretsStory {
  return secretsStory(believedVm !== undefined ? believedVm : vm, believed, vm ? !vm.invariant.holds : false, vm?.paired.mode ?? null, home, steps, later, opts);
}

/** The secrets "Your secrets" says the AI read as they were before their
 *  label, by base name, with when (secret-story.ts `earlyReads`, the same
 *  arguments as `pageSecrets`): what the turns' chips and replies say of
 *  them, so a turn never claims less than the card. Pure. */
export function pageEarlyReads(vm: SessionViewModel | null, believedVm?: SessionViewModel | null, home = "", later?: LaterLabelInput): Map<string, string> {
  return earlyReads(believedVm !== undefined ? believedVm : vm, vm ? !vm.invariant.holds : false, vm?.paired.mode ?? null, home, later);
}

/** The files of this session labelled after it read them as they were
 *  (later-labels.ts), over the BELIEVED view-model (a claimed event may not
 *  make a claim; absent = `vm`), so a step says so only where *Your
 *  secrets* does. `later` absent: none. Pure. */
export function pageLaterLabels(vm: SessionViewModel | null, believedVm: SessionViewModel | null | undefined, home: string, later: LaterLabelInput | undefined): LaterLabel[] {
  const v = believedVm !== undefined ? believedVm : vm;
  return v && later?.labels.length ? laterLabels(plainReads(v, later.cwd, home), later.labels) : [];
}

/** The non-secret items masked before the AI saw them, the page's
 *  "untrusted items" tile (home.js `renderAgentPage`, the same rule): only a
 *  level that masks untrusted text has any (a frozen one, or a recording
 *  with no mode); Secrets and Off mask none, so a non-secret item there is
 *  not one. Pure. */
export function untrustedMasked(stats: SessionFlowStats, mode: ProtectionMode | null): number {
  return mode === "secrets" || mode === "off" ? 0 : Math.max(0, stats.flows - stats.secret);
}

/** The session's agent exited (session-exit.ts): the recorded exit outranks
 *  the listing's recent-activity "running". */
export { sessionExited };

export function buildAgentPage(input: AgentPageInput): AgentPageVM {
  const { session, vm } = input;
  const stats: SessionFlowStats = vm?.lineage.stats ?? { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 };
  // The labels made after this session read their files (the rule-change
  // log's times, the route's): its Read steps and Your secrets say so. The
  // session's folder goes along even with none: Your secrets places a
  // relative Read's path in it to name a key's file.
  const later: LaterLabelInput = { labels: input.labels ?? [], cwd: input.cwd };
  const after = laterByStep(pageLaterLabels(vm, input.believedVm, input.home ?? "", later));
  const dev = input.dev !== false;
  const show = input.show ?? {};
  // Every step of every turn; the caps are applied below, once the page's
  // asks (`show`) and the marked step are known.
  const all = vm
    ? buildStory(vm, input.values, pageEarlyReads(vm, input.believedVm, input.home, later), input.home, after, {
      stepCap: Infinity, dev,
      ...(show.background ? { background: show.background } : {}),
      ...(show.original !== undefined ? { hiddenCap: ORIGINAL_ALL_CAP } : {}),
      ...(input.issuerBindings ? { issuers: input.issuerBindings } : {}),
    })
    : [];
  // A step that asked says how its question was answered, as Approvals does
  // (§4.25b *A stop says Mandu asked you*); a waiting one only that it asked.
  if (input.answers?.size) {
    for (const t of all) {
      for (const s of t.steps) {
        if (s.kind !== "action" || !s.askId) continue;
        const answer = input.answers.get(s.askId);
        if (answer) s.answer = answer;
      }
    }
  }
  // Plan 15 §13.7: the note under your message, from the prompt filter's events.
  let unplacedNotes: AgentPageVM["unplacedNotes"] = [];
  if (vm && input.events?.length) {
    const byId = new Map<string, DualStep>(vm.dualLanes.steps.map((s) => [s.id, s]));
    const requestOf = new Map(vm.paired.turns.map((pt) => [pt.id, pt.inputId ? byId.get(pt.inputId)?.turn ?? null : null]));
    const notes = promptNotes(input.events, all.map((t) => ({ id: t.id, requestTurn: t.prompt !== null ? requestOf.get(t.id) ?? null : null })), input.promptLocks ?? null);
    for (const t of all) t.promptNote = notes.byTurn.get(t.id) ?? null;
    unplacedNotes = notes.unplaced;
  }
  // The tiles count the story as Home counts it (each turn's first
  // TURN_STEP_CAP steps, home-routes.ts `HomeFacts`), so a row and the page
  // it opens agree whatever the page shows.
  const { blocked, sent } = storyCounts(all.map((x) => capTurn(x, TURN_STEP_CAP)));
  // The focused turn is always shown, even when older than the turns the
  // page shows, and with its every step up to TURN_STEP_ALL_CAP.
  const at = input.focus?.stepId ? all.findIndex((t) => t.steps.some((s) => s.id === input.focus!.stepId)) : -1;
  const focusAt = at === -1 ? -1 : all[at]!.steps.findIndex((s) => s.id === input.focus!.stepId);
  const turnCap = show.turns ? TURN_ALL_CAP : TURN_CAP;
  const earlier = at === -1 ? Math.max(0, all.length - turnCap) : Math.min(at, Math.max(0, all.length - turnCap));
  const found = at !== -1 && focusAt < TURN_STEP_ALL_CAP;
  let focus: StoryFocus | null = null;
  if (input.focus) {
    const turn = found ? all[at]! : null;
    focus = { ask: input.focus.ask, turnId: turn?.id ?? null, stepId: turn ? input.focus.stepId : null, match: turn ? input.focus.match : null };
  }
  const story = all.slice(earlier).map((x) => {
    const lifted = show.steps?.has(x.id) || (found && x === all[at]);
    const turn = capTurn(x, lifted ? TURN_STEP_ALL_CAP : TURN_STEP_CAP);
    return lifted && x.steps.length > TURN_STEP_CAP ? { ...turn, allSteps: true as const } : turn;
  });
  const shown = new Set(story.flatMap((x) => x.steps.filter((s) => s.kind === "action").map((s) => s.id)));
  // The whole original of one step, for the admin route that asked.
  let original: StoryHidden | null | undefined;
  if (show.original !== undefined) {
    const step = all.flatMap((x) => x.steps).find((s) => s.id === show.original);
    const hidden = step?.kind === "action" ? step.split?.hidden ?? null : null;
    original = hidden && hidden.text !== null && !hidden.secret ? hidden : null;
  }
  const notice = agentNotice(session?.health, input.masking === true, input.id);
  return {
    found: !!(session || vm),
    id: input.id,
    agent: agentName(session?.agent, session?.health),
    preview: agentPreview(session?.health),
    notice,
    noticeParts: agentNoticeParts(session?.health, input.masking === true, input.id),
    noticeShown: notice !== null && session?.health?.verdict === "broken",
    secretsPosture: secretsPostureNote(session?.health?.secrets, "session"),
    title: titleOf(promptLabel(session), all),
    cwd: input.cwd,
    startedAt: session?.firstTs ?? null,
    lastAt: session?.lastTs ?? null,
    running: session?.status === "running" && !sessionExited(input.events ?? []),
    holds: vm ? vm.invariant.holds : !(session?.violated ?? false),
    violations: vm?.invariant.violationCount ?? 0,
    stats,
    blocked,
    sent,
    waiting: input.waiting,
    story,
    earlier,
    ...(show.turns ? { allTurns: true as const } : {}),
    focus,
    mainModel: mainModelOf(input.upstream),
    unplacedNotes,
    // A claim of safety reads only believed events; the full record's leak
    // check may still take it away. A card's time opens a step only when
    // the story below draws it (an action step, home.js `data-step-id`).
    secrets: pageSecrets(vm, input.events ?? [], input.believedVm, input.home, shown, later,
      { dev, ...(show.secrets ? { cap: SECRET_ALL_CAP } : {}) }),
    ...(show.secrets ? { allSecrets: true as const } : {}),
    finding: vm ? leakFinding(vm, all, shown) : null,
    browser: browserStory(input.events ?? []),
    launchTime: launchTimeOf(input.events ?? []),
    ...(original !== undefined ? { original } : {}),
    valuesShown: input.valuesShown !== false,
  };
}
