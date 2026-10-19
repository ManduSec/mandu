/**
 * view-model/dual-lanes — §4.2c DualView lane mode (the reference dashboard's
 * three-lane layout; the DEFAULT main-frame view).
 *
 * Extracted verbatim from view-model.ts (agent-legibility split, behavior-preserving).
 * Deduplicates the trace into AgentView/HumanView lane steps + translation bands
 * (symbolize/desymbolize). Depends on eventTitle/eventTool (lanes), extractToolUses
 * (tool-calls), and the transcript parser.
 */

import type { ManduEvent, PathRewriteDetail } from "../event-model.js";
import type { DetailSection } from "./detail.js";
import {
  BIRTH_TITLE, birthDetail, birthItem, execDetail, fsDetail, genericDetail, netDetail, pathRewriteDrawer, replyFilterDetail,
} from "./dual-lanes-detail.js";
import { eventTitle, eventTool } from "./lanes.js";
import { extractToolUses } from "./tool-calls.js";
import { endpointOf, type ModelEndpointRef } from "./model-endpoints.js";
import { parseTranscript, stripHarnessTags, type TranscriptMessage } from "../transcript.js";
import { blockWhy, checkOutcome } from "./block-why.js";
import { readRefusals } from "./secret-note.js";
import { isPatchTool, patchFiles, patchFilesOf } from "./patch-files.js";
import { inspectAnswer, isInspectCall } from "./inspect-answer.js";
import type { StoryPart } from "./agent-page-types.js";

// ── §4.2c — DualView lane mode (the reference dashboard's three-lane layout) ──
// The main trace: LEFT lane = AgentView (what T-LLM sees — symbols only), RIGHT
// lane = HumanView (original data — no symbols), and the symbol↔raw translation
// (+ the P2 path rewrite) rendered ON the trust boundary between them. Built
// tool-call-centrically like the reference's botBuildFlowSteps, and — the
// de-verbosity fix — DEDUPLICATED: the stateless Messages API re-sends the whole
// history every turn, so the proxy re-emits tool_result/symbolize/path_rewrite
// for the SAME callId once per subsequent model call; those repeats collapse
// into the one step (with a `repeats` count) instead of stacking guard rows.

export type {
  DualBandSym,
  DualPathRewrite,
  DualGate,
  DualInputStep,
  DualResponseStep,
  DualToolStep,
  DualOsStep,
  DualStep,
  FileGuard,
  ModelCallClass,
  DualLanesModel,
} from "./dual-lanes-types.js";
import type {
  DualBandSym, DualGate, DualResponseStep, DualToolStep, DualOsStep,
  DualStep, FileGuard, ModelCallClass, DualLanesModel,
} from "./dual-lanes-types.js";

/** The reply-filter's card title (the user-reply egress, uncorrelated). */
const REPLY_FILTER_TITLE = "user reply · reply-filter";

/** The symbol-token surface (mirrors render-helpers' highlight regex). */
const SYM_TOKEN_RE = /\$MDU:\w+\[\w+\](?:\.\w+)*/g;

/** Distinct symbol tokens referenced in `text` (exported for render-lint's
 *  reply-filter cross-check — one token grammar, one implementation). */
export function matchSymbols(text: string | null | undefined): string[] {
  if (!text) return [];
  return [...new Set(text.match(SYM_TOKEN_RE) ?? [])];
}

/** Is the whole text a JSON object/array? (e.g. the title-generation side call —
 *  not a prose reply worth a response card.) */
function isJsonBlob(text: string): boolean {
  const t = text.trim();
  if (!(t.startsWith("{") || t.startsWith("["))) return false;
  try { JSON.parse(t); return true; } catch { return false; }
}

/** The proxy's synthesized stand-in for a model call whose upstream returned an
 *  HTTP error and produced NO output (proxy.ts: "⚠ no model response — upstream
 *  HTTP 429 (rate-limited)…"). Emitted so the dashboard can EXPLAIN a blank
 *  turn — it is not model prose: a quota probe that errors this way must still
 *  read as a side call, and no errored turn was ever DELIVERED, so the
 *  explainer must never take the delivery zone (live: a 429'd quota probe
 *  rendered as the Agent Response, session 1783733223-3201158). */
function isNoModelResponse(outputSymbolized: string): boolean {
  return outputSymbolized.trimStart().startsWith("⚠ no model response");
}

/** A model call Claude Code makes OUTSIDE the agent conversation. Such a call
 *  must neither seed the input endpoint nor produce a response card: the LAST
 *  response card is the delivered reply (delivery zone + §4.2c deep reveal), so
 *  a prose-output side call landing after the real reply would steal `final`
 *  and demote the reply the human actually received to an interim card.
 *   - title generation / topic detection: the whole output is a JSON blob;
 *   - typeahead suggestion: the transcript is the conversation plus a trailing
 *     "[SUGGESTION MODE: …]" user instruction, answered with a predicted prompt;
 *   - the startup quota probe: a lone "quota" user message answered with a
 *     single max_tokens=1 token — or, when the probe itself errors upstream,
 *     with the proxy's no-model-response explainer (a real "quota" prompt
 *     gets a full reply and keeps rendering);
 *   - the away-recap: the harness replays the WHOLE conversation plus a
 *     trailing "The user stepped away and is coming back. Recap …" user
 *     instruction. Because it extends the conversation's prompt list it would
 *     otherwise BOTH mint a bogus input card for the instruction AND steal
 *     `final` from the reply the human actually received (live: session
 *     1783711204-2455055 rendered the recap as the delivered reply);
 *   - the WebFetch summarizer: a stateless call whose ONE user message is the
 *     fetched page ("Web page content:\n---\n…"). Its prompt list never
 *     extends the conversation (no input card), but its prose answer still
 *     rendered as an interim response card — and would steal `final` if it
 *     landed last. */
function isSideCall(msgs: TranscriptMessage[] | null, outputSymbolized: string): boolean {
  if (isJsonBlob(outputSymbolized)) return true;
  const users = (msgs ?? []).filter((m) => /^user$/i.test(m.role));
  const last = users[users.length - 1];
  if (last && last.body.trimStart().startsWith("[SUGGESTION MODE:")) return true;
  if (last && /^The user stepped away and is coming back\./.test(last.body.trimStart())) return true;
  if (users.length === 1 && users[0]!.body.trimStart().startsWith("Web page content:")) return true;
  if (
    users.length === 1 && users[0]!.body.trim() === "quota" &&
    (outputSymbolized.trim().length <= 8 || isNoModelResponse(outputSymbolized))
  ) {
    return true;
  }
  return false;
}

/** The human's prompt as an entry endpoint should show it: the proxy collapses
 *  injected context blocks to literal `[system-reminder]` placeholder lines —
 *  drop EVERY such line (the harness injects them before AND after the typed
 *  text, and re-injects different ones on later turns, so anything kept would
 *  both pollute the card and break the cross-turn prompt prefix match). The
 *  harness ALSO leaves slash-command records inline in the user message
 *  (`<local-command-caveat>…`, `<command-name>/model</command-name>`, the
 *  command's stdout) — those tag spans pass the proxy verbatim and buried the
 *  real prompt under them; strip them the same way (stripHarnessTags). */
/** A place the prompt filter changed in a forwarded message (plan 15 §7): a
 *  symbol, or the `[redacted: …]` / `[blocked: …]` marker. */
const PROMPT_MARK_SRC = /\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]|\[(?:redacted|blocked): [^\]\n]{1,128}\]/.source;
const PROMPT_MARK_RE = new RegExp(PROMPT_MARK_SRC);
/** Literal text a loose match needs, so a message that is all marks never
 *  matches everything. */
const PROMPT_MATCH_MIN_LITERAL = 8;

/** Does `text` read as `pattern` with each prompt-filter mark in `pattern`
 *  standing for some non-empty text? Leftmost matching of the literal parts
 *  (correct for wildcards; linear, no regex backtracking). Pure. */
function matchesWithMarks(pattern: string, text: string): boolean {
  const lits = pattern.split(new RegExp(PROMPT_MARK_SRC, "g"));
  if (lits.length < 2 || lits.join("").length < PROMPT_MATCH_MIN_LITERAL) return false;
  const first = lits[0]!;
  const last = lits[lits.length - 1]!;
  if (!text.startsWith(first) || !text.endsWith(last)) return false;
  let at = first.length;
  const end = text.length - last.length;
  for (let i = 1; i < lits.length - 1; i++) {
    const k = text.indexOf(lits[i]!, at + 1);
    if (k < 0 || k > end) return false;
    at = k + lits[i]!.length;
  }
  return end >= at + 1;
}

/**
 * The same message of the person, resent in another form? The agents resend
 * the whole conversation, and the prompt filter may forward an earlier
 * message differently from one request to the next: masked after a policy
 * change, as written after the person let a span through (plan 15 §7,
 * §13.7). Without this, one such resend stopped the conversation from
 * extending and every later prompt dropped out of the trace and the story.
 * Equal, or equal but for the filter's marks on either side. Pure.
 */
export function samePromptMessage(a: string, b: string): boolean {
  if (a === b) return true;
  if (!PROMPT_MARK_RE.test(a) && !PROMPT_MARK_RE.test(b)) return false;
  return matchesWithMarks(a, b) || matchesWithMarks(b, a);
}

function stripHarnessNoise(body: string): string {
  return stripHarnessTags(body)
    .split("\n")
    .filter((line) => !/^\s*\[system-reminder\]\s*$/.test(line))
    .join("\n");
}

/** The prose part of a tllm_call output: drop `→ tool(args)` decision lines. */
function responseProse(outputSymbolized: string): string {
  const prose = outputSymbolized
    .split("\n")
    .filter((line) => !/^\s*→ /.test(line))
    .join("\n")
    .trim();
  return prose && !isJsonBlob(prose) ? prose : "";
}

function mergeBand(into: DualBandSym[], refs: Iterable<{ name: string; value?: string | null }>): DualBandSym[] {
  for (const s of refs) {
    const existing = into.find((x) => x.name === s.name);
    if (existing) {
      if (existing.value === null && s.value != null) existing.value = s.value;
    } else {
      into.push({ name: s.name, value: s.value ?? null });
    }
  }
  return into;
}

/** An OS step's recorded action and subject: "net_action · blocked
 *  example.com" → `blocked`, `example.com` (the session page reads its
 *  steps by the same split). */
export function osSubject(s: Pick<DualOsStep, "title" | "action">): { act: string; subject: string } {
  const hint = s.title.includes(" · ") ? s.title.slice(s.title.indexOf(" · ") + 3) : "";
  const act = s.action ?? hint.split(" ")[0] ?? "";
  return { act, subject: (hint.startsWith(act) ? hint.slice(act.length) : hint).trim() };
}

/** A send's destination as the event recorded it (`:443` left out). */
export function netHost(s: Pick<DualOsStep, "title" | "action" | "target">): string {
  return (s.target ?? osSubject(s).subject).replace(/:443$/, "");
}

/** The kernel guard's file decisions, by the exact text of their producers
 *  (net-supervisor events.rs: guard_git_lock_refusal_event,
 *  guard_protect_refusal_event, guard_write_refusal_event,
 *  guard_raw_withheld_event). */
const FILE_GUARD_REASONS: ReadonlyArray<[FileGuard["what"], RegExp]> = [
  ["git-lock", /^read of .+ — REFUSED \(git-lock: /s],
  ["protected-path", /^delete or rename of .+ — REFUSED in-kernel \(protected-path: /s],
  ["write-protect", /^change of .+ — REFUSED \(write-protect: /s],
  ["raw-withheld", /^read of .+ — REAL FILE WITHHELD \(/s],
];

/** A `net_action` the kernel guard recorded for a FILE (its binary hosts the
 *  file guard too), or null for any other event. The path is the event's
 *  output, as the producer wrote it (the repository for `git-lock`). Pure. */
export function fileGuardOf(e: ManduEvent): FileGuard | null {
  if (e.kind !== "net_action" || e.emitter !== "net-supervisor") return null;
  const reason = e.policy?.reason ?? "";
  const path = e.output?.symbolized ?? "";
  const socket = localSocketOf(reason, path);
  if (socket) return socket;
  const hit = FILE_GUARD_REASONS.find(([, re]) => re.test(reason));
  return hit && path !== "" ? { what: hit[0], path } : null;
}

/** A Unix-socket connect the guard's allow-list refused (net-supervisor
 *  events.rs `guard_unix_refusal_event`: `connect to <dest>[ by <exe>] —
 *  REFUSED (unix-socket allow-list: <why>; EACCES)`, its output the `dest`),
 *  or null. The socket is the `unix:` destination's path or `@name`; a
 *  destination naming none (a datagram the command box sent) leaves it "".
 *  Live 2026-10-11: Claude Code ran `tmux` inside the tmux session it was
 *  started in, and the page said "Mandu blocked a connection to the
 *  network" for `unix:/tmp/tmux-1007/default`. */
function localSocketOf(reason: string, dest: string): FileGuard | null {
  if (!dest.startsWith("unix:")) return null;
  const head = `connect to ${dest}`;
  if (!reason.startsWith(head)) return null;
  const end = reason.indexOf(" — REFUSED (unix-socket allow-list: ", head.length);
  if (end < 0) return null;
  const by = reason.slice(head.length, end);
  if (by !== "" && !by.startsWith(" by ")) return null;
  const exe = by.slice(" by ".length).trim();
  const program = exe.slice(exe.lastIndexOf("/") + 1);
  const sock = dest.slice("unix:".length);
  const path = sock.startsWith("/") || sock.startsWith("@") ? sock : "";
  return { what: "local-socket", path, ...(program ? { program } : {}) };
}

/** The destination a net check recorded: the net-proxy's `destination`, or
 *  the host in the model proxy's input summary (`WebFetch → evil.example`,
 *  its events.ts `makeNetGate`; "(no destination named)" is none). */
function netTarget(e: ManduEvent): string | null {
  const d = (e as { destination?: unknown }).destination;
  if (typeof d === "string" && d !== "") return d;
  const m = /^\S+ → (\S+)$/.exec(e.input?.symbolized ?? "");
  return m ? m[1]! : null;
}

/** Why a check on a tool card blocked or held the call (block-why.ts), by
 *  the decision its line draws. No host: the line's recorded text names it,
 *  as the session page's tool step does (agent-page.ts `decidingGate`). */
function gateWhy(g: DualGate): StoryPart[] | null {
  const outcome = checkOutcome(g.usage, g.text);
  return outcome ? blockWhy(g.ruleRef, { outcome }) : null;
}

/** Whether an OS step blocked or held something, by the decision the
 *  inspector's line draws; null otherwise. */
function osOutcome(s: DualOsStep): ReturnType<typeof checkOutcome> {
  if (s.violated || s.kind === "ullm_call") return null;
  return checkOutcome(s.usage, osSubject(s).act);
}

/** Why an OS step blocked or held something, with a send's host and how
 *  many items it carried, as the session page words the same step
 *  (agent-page.ts `osSentence`). A flagged step or a sandboxed reader's
 *  record has none: the session page tells neither as a block. */
function osWhy(s: DualOsStep): StoryPart[] | null {
  const outcome = osOutcome(s);
  if (!outcome) return null;
  // A file decision names no host (agent-page.ts words it as a file).
  const net = s.kind === "net_action" && !s.fileGuard;
  return blockWhy(s.ruleRef, { outcome, host: net ? netHost(s) || null : null, ...(net && s.carried ? { carried: s.carried.length } : {}) });
}

/** An approval-queue id in the shape the arbiter files them (`egr-<n>`, the
 *  answer routes' shape); anything else names no row. */
const ASK_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** The Approvals row a check filed for the person (the event's
 *  `policy.approvalId`, §4.2f *A check says it asked*), on a check that
 *  blocked or held the call only: one that let it through names none.
 *  *Your secrets* reads a block's row by the same rule (secret-story.ts). */
export function askIdOf(approvalId: unknown, stopped: boolean): string | null {
  return stopped && typeof approvalId === "string" && ASK_ID_RE.test(approvalId) ? approvalId : null;
}

/** The step of `ids` that shows an event: its tool step (`tool:<callId>`)
 *  when it has a call id, else its own OS step (`os:<event id>`), as the
 *  builder below names them; null when neither is in `ids`. The session
 *  page opens a step by it (an answer's ask, a time on Your secrets). */
export function stepIdOfEvent(e: Pick<ManduEvent, "id" | "callId">, ids: ReadonlySet<string>): string | null {
  if (e.callId && ids.has("tool:" + e.callId)) return "tool:" + e.callId;
  return ids.has("os:" + e.id) ? "os:" + e.id : null;
}

type Usage = DualToolStep["usage"];
const USAGE_RANK: Record<NonNullable<Usage>, number> = { allow: 1, needs_approval: 2, deny: 3 };
/** A call's decision once another of its checks joins it: the severer one
 *  (deny, then a hold, then allow), in whichever order they were recorded.
 *  One call can carry several checks (a net gate, then the exec gate; an exec
 *  gate, then a stdin gate), and a call any check blocked did not run. */
function severerUsage(cur: Usage, next: Usage | undefined): Usage {
  if (!next) return cur;
  return cur === null || USAGE_RANK[next] > USAGE_RANK[cur] ? next : cur;
}

/** A check with its why and the row it filed, when it has them. */
function withGateWhy(g: DualGate, approvalId?: unknown): DualGate {
  const why = gateWhy(g);
  const askId = askIdOf(approvalId, checkOutcome(g.usage, g.text) !== null);
  return { ...g, ...(why ? { why } : {}), ...(askId ? { askId } : {}) };
}

/**
 * THE lane-mode builder: events → the deduplicated step list the dual lanes
 * render. Pure (no DOM); shipped inside the session view-model like everything
 * else, so the browser only turns it into HTML.
 */
/** The symbols a net_action carried: its `resolved` (forwarded) and
 *  `withheld` (blocked) loose fields, in both wire shapes (`string[]` and
 *  `{symbol}[]`, as lineage.ts reads them), deduped, in order. */
function carriedOf(raw: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const k of ["resolved", "withheld"]) {
    const list = raw[k];
    if (!Array.isArray(list)) continue;
    for (const w of list) {
      const name = typeof w === "string" ? w : w && typeof w === "object" && typeof (w as { symbol?: unknown }).symbol === "string" ? (w as { symbol: string }).symbol : null;
      if (name && name.startsWith("$MDU:") && !out.includes(name)) out.push(name);
    }
  }
  return out;
}

export function toDualLanes(events: ManduEvent[]): DualLanesModel {
  const ordered = [...events].sort((a, b) =>
    a.ts !== b.ts ? (a.ts < b.ts ? -1 : 1) : a.seq - b.seq,
  );
  const toolUses = extractToolUses(events);
  // The calls the session recorded a `tool_use` for. A context proxy decides
  // its exec and net gates while it relays the call, so it records each gate
  // BEFORE the call's tool_use: a gate joins its call's card when the
  // session has that call, in whichever order the two were recorded.
  const recordedCalls = new Set(events.flatMap((e) => (e.kind === "tool_use" && e.callId ? [e.callId] : [])));

  // Cumulative symbol → value/origin map (any event may carry the provenance).
  const symValue = new Map<string, string | null>();
  const symOrigin = new Map<string, string | null>();
  for (const e of ordered) {
    for (const r of [e.input, e.output]) {
      if (!r) continue;
      for (const s of r.symbols) {
        if (!symValue.has(s.name) || (symValue.get(s.name) == null && s.value != null)) {
          symValue.set(s.name, s.value);
        }
        if (s.origin != null && !symOrigin.has(s.name)) symOrigin.set(s.name, s.origin);
      }
    }
  }
  const bandFromNames = (names: string[]): DualBandSym[] =>
    names.map((n) => ({ name: n, value: symValue.get(n) ?? null }));

  const steps: DualStep[] = [];
  const toolByCall = new Map<string, DualToolStep>();
  // When each call's result first reached the AI (its first tool_result).
  const resultTs = new Map<string, string>();
  /** §4.25b: the first delivery carried no token and this later event does
   *  (`names`): the AI read the result as it was, and only later requests
   *  carry it masked. The first such event wins; a result that was masked
   *  from the start is never "masked later". */
  const noteMaskedLater = (t: DualToolStep, e: ManduEvent, names: string[]): void => {
    if (t.maskedLater || !names.length || matchSymbols(t.resultAgent).length) return;
    t.maskedLater = { ts: e.ts, deliveredTs: resultTs.get(t.callId) ?? t.ts, symbols: [...new Set(names)] };
  };
  const calls: ModelCallClass[] = [];
  let collapsed = 0;
  // The stripped user-prompt bodies already rendered as input cards, in
  // conversation order. Conversation calls REPLAY the whole history each turn
  // (stateless Messages API), so a genuine conversation call's prompt list
  // EXTENDS this one; a call whose list doesn't is not the agent conversation
  // (e.g. the WebFetch summarizer side call carries the fetched page as its
  // one user message) and must not mint input cards.
  let convoPrompts: string[] = [];
  let lastResponse: DualResponseStep | null = null;
  // The open batch birth card (fs-sync mints): consecutive callId-null symbolize
  // events accumulate into ONE card; any other step in between closes the batch.
  let birthCard: (DualOsStep & { newSymbols: string[]; detail: DetailSection[] }) | null = null;

  // §4.14 — session-wide first-seen tracking for the assignment markers: a name
  // is a BIRTH only on the first minting event (canonical order) that references
  // it; every later reference — same call re-guarded, or another call's result
  // embedding the symbol (a twin read) — is a re-emission, not a new birth.
  const seenSymNames = new Set<string>();
  const mintNames = (t: { newSymbols: string[] }, refs: Iterable<{ name: string }>): string[] => {
    const fresh: string[] = [];
    for (const s of refs) {
      if (seenSymNames.has(s.name)) continue;
      seenSymNames.add(s.name);
      t.newSymbols.push(s.name);
      fresh.push(s.name);
    }
    return fresh;
  };

  const ensureTool = (e: ManduEvent): DualToolStep => {
    let t = toolByCall.get(e.callId!);
    if (!t) {
      t = {
        step: "tool", id: "tool:" + e.callId, ts: e.ts, turn: e.turn,
        violated: false, callId: e.callId!, tool: eventTool(e) ?? "",
        trust: null, crossing: false, readsTwin: false, quarantine: false,
        input: null, resultAgent: null, resultHuman: null, origin: null,
        reason: null,
      secretNote: null, usage: null, downSyms: [], upSyms: [],
        symbolizedBy: null, desymbolizedBy: null, quarantinedBy: null,
        newSymbols: [], pathRewrites: [], gates: [], repeats: 1,
      };
      toolByCall.set(e.callId!, t);
      steps.push(t);
    }
    t.violated = t.violated || e.invariant.violatedInvariant;
    return t;
  };

  // An uncorrelated action card; consecutive identical ones fold together.
  // The fold key stays (kind, title, note); a fold means an identical action,
  // so the FIRST card's detail is kept (matching the card keeping its first ts).
  const ullmEndpointBySymbol = new Map<string, ModelEndpointRef>();
  const pushOs = (
    e: ManduEvent,
    opts: { title?: string; note?: string; quarantine?: boolean; detail?: DetailSection[]; readBy?: ModelEndpointRef | null } = {},
  ): void => {
    const note = opts.note ??
      (typeof (e as unknown as Record<string, unknown>)["note"] === "string"
        ? ((e as unknown as Record<string, unknown>)["note"] as string)
        : null);
    const title = opts.title ?? eventTitle(e);
    const raw = e as unknown as Record<string, unknown>;
    const strField = (k: string): string | null => (typeof raw[k] === "string" ? (raw[k] as string) : null);
    const usage = e.policy?.usage ?? null;
    const carried = e.kind === "net_action" ? carriedOf(raw) : [];
    const fileGuard = fileGuardOf(e);
    const last = steps[steps.length - 1];
    // The fold key includes the DECISION (usage, action) and the violation
    // flag: an exec_action card's title is just "exec_action", so an allowed
    // command followed by a denied one used to fold into ONE card and the
    // denial vanished from the trace.
    if (
      last && last.step === "os" && last.kind === e.kind && last.title === title && last.note === note &&
      last.usage === usage && last.action === strField("action") && last.violated === e.invariant.violatedInvariant &&
      (last.carried ?? []).join(" ") === carried.join(" ")
    ) {
      last.repeats++;
      collapsed++;
      return;
    }
    const step: DualOsStep = {
      step: "os", id: "os:" + e.id, ts: e.ts, turn: e.turn,
      violated: e.invariant.violatedInvariant, kind: e.kind,
      title, note, quarantine: opts.quarantine ?? e.view === "Quarantine", repeats: 1,
      ruleRef: e.policy?.ruleRef ?? null,
      action: strField("action"), usage, target: strField("destination"),
      ...(opts.detail ? { detail: opts.detail } : {}),
      ...(opts.readBy ? { readBy: opts.readBy } : {}),
      ...(carried.length ? { carried } : {}),
      ...(fileGuard ? { fileGuard } : {}),
    };
    const why = osWhy(step);
    const askId = askIdOf(e.policy?.approvalId, osOutcome(step) !== null);
    steps.push({ ...step, ...(why ? { why } : {}), ...(askId ? { askId } : {}) });
  };

  for (const e of ordered) {
    switch (e.kind) {
      case "tllm_call": {
        // A side call (title generation, typeahead suggestion, quota probe) is
        // not part of the agent conversation: it neither seeds the input
        // endpoint nor produces a response card. Two detectors, structural
        // first: a request that carried NO tools cannot be the agent
        // conversation loop (it always sends the agent's tool battery) — the
        // proxy records that as `callShape`; the string shapes (isSideCall)
        // remain for events that predate the field and for side calls that do
        // carry tools.
        const msgs = parseTranscript(e.input?.symbolized ?? "");
        const sideCall =
          (e.callShape !== undefined && e.callShape.toolCount === 0) ||
          isSideCall(msgs, e.output?.symbolized ?? "");
        // Input endpoints: one card per user prompt (a session has MANY — the
        // single-card latch this replaces dropped every prompt after the
        // first). Tool results ride in user-role messages (as role
        // "tool_result", or legacy user bodies starting "[tool_result …]") and
        // are not prompts. New prompts render only when this call's list
        // extends the conversation seen so far — see convoPrompts above.
        let extendsConvo = false;
        if (!sideCall && msgs) {
          const prompts = msgs
            .filter((m) => /^user$/i.test(m.role) && !/^\s*\[tool_result\b/.test(m.body))
            .map((m) => stripHarnessNoise(m.body).trim());
          extendsConvo =
            prompts.length >= convoPrompts.length &&
            convoPrompts.every((p, i) => samePromptMessage(p, prompts[i]!));
          if (extendsConvo) {
            for (let i = convoPrompts.length; i < prompts.length; i++) {
              const text = prompts[i]!;
              if (!text) continue;
              steps.push({
                step: "input", id: `input:${e.id}:${i}`, ts: e.ts, turn: e.turn,
                violated: e.invariant.violatedInvariant, text,
              });
            }
            convoPrompts = prompts;
          }
        }
        const prose = sideCall ? "" : responseProse(e.output?.symbolized ?? "");
        // The self-check seam: how this call was read. "unknown" + prose is the
        // delivered-reply-steal risk render-lint warns about. Classification
        // never gates rendering — a history rewrite (prompt edit, /compact)
        // makes the REAL conversation non-extending, and its replies must keep
        // rendering (and keep the delivery zone).
        calls.push({
          id: e.id, ts: e.ts, turn: e.turn,
          cls: sideCall ? "side" : extendsConvo ? "conversation" : "unknown",
          prose: prose !== "" && !isNoModelResponse(prose),
        });
        if (prose) {
          const resp: DualResponseStep = {
            step: "response", id: "resp:" + e.id, ts: e.ts, turn: e.turn,
            violated: e.invariant.violatedInvariant, text: prose, final: false,
            symbols: bandFromNames(matchSymbols(prose)),
          };
          steps.push(resp);
          // The upstream-error explainer still renders (the blank turn stays
          // explained) but was never delivered to the human — it must not
          // become the delivery-zone reply.
          if (!isNoModelResponse(prose)) lastResponse = resp;
        }
        break;
      }
      case "ullm_call": {
        // Plan 11 D6: which model served the call. Remembered by the call's
        // symbols so an inspect_symbol step (whose ullm_call carries no callId)
        // can name its reader at finalize time.
        const ep = endpointOf(e);
        if (ep) {
          for (const k of [e.output?.symbolized, e.input?.symbolized]) {
            if (k && !ullmEndpointBySymbol.has(k)) ullmEndpointBySymbol.set(k, ep);
          }
        }
        if (e.callId && toolByCall.has(e.callId)) {
          const t = ensureTool(e);
          t.quarantine = true;
          if (t.quarantinedBy === null) t.quarantinedBy = e.emitter ?? null;
          if (ep && !t.readBy) t.readBy = ep;
          if (t.resultHuman === null) {
            t.resultHuman = e.output?.original ?? e.output?.symbolized ?? null;
          }
        } else {
          // Name the technique on the card: which component ran the quarantine.
          pushOs(e, {
            title: `U-LLM (quarantined) · ${e.emitter}${ep ? ` · ${ep.name} (${ep.location === "local" ? "local model" : "external model"})` : ""}`,
            quarantine: true,
            readBy: ep,
          });
        }
        break;
      }
      case "tool_use": {
        if (!e.callId) break;
        const t = ensureTool(e);
        // The call's own record names its card, whatever event opened it: a
        // gate recorded before the call names only its first symbol's tool
        // (`nomodel_Env`), never the call's (`Bash`). A code-mode cell's
        // several records name it as extractToolUses does: a patch never
        // renames a call another tool named.
        const name = toolUses.get(e.callId)?.tool ?? eventTool(e);
        if (name) t.tool = name;
        break;
      }
      case "tool_result": {
        if (!e.callId) break;
        const t = ensureTool(e);
        if (t.resultAgent !== null) {
          // History re-send: the same result re-guarded on a later turn — fold.
          // A re-send that is masked where the first delivery was not is the
          // after-the-fact mask (the file was labelled later): recorded, never
          // written over what the AI got at the step's own turn.
          noteMaskedLater(t, e, matchSymbols(e.output?.symbolized));
          t.repeats++;
          collapsed++;
          break;
        }
        resultTs.set(t.callId, e.ts);
        t.trust = e.policy?.trust ?? t.trust;
        t.reason = e.policy?.reason ?? t.reason;
        t.secretNote = typeof e.secretNote === "string" ? e.secretNote : t.secretNote;
        const refused = readRefusals(t.secretNote);
        if (refused) t.readRefused = refused;
        t.resultAgent = e.output?.symbolized ?? null;
        t.resultHuman = e.output?.original ?? t.resultHuman;
        if (e.output?.originalTokens) t.resultHumanTokens = e.output.originalTokens;
        mergeBand(t.upSyms, e.output?.symbols ?? []);
        mintNames(t, e.output?.symbols ?? []);
        if (t.symbolizedBy === null && (e.output?.symbols?.length ?? 0) > 0) {
          t.symbolizedBy = e.emitter ?? null;
        }
        break;
      }
      case "classify":
      case "symbolize": {
        if (!e.callId) {
          // fs-sync symbol BIRTHS (symbol-lineage.md G1): the workspace seed /
          // eager sync mints symbols on disk with no tool call to correlate to
          // — the only callId-null symbolize emitter. Render a BATCH card (one
          // per consecutive run of births) so the mint is visible in the trace.
          // An uncorrelated classify has no emitter — it stays dropped.
          if (e.kind !== "symbolize") break;
          const refs = (e.output?.symbols ?? []).filter((s) => !seenSymNames.has(s.name));
          if (!refs.length) { collapsed++; break; } // re-emission → fold away
          const last = steps[steps.length - 1];
          if (birthCard && last === birthCard) {
            // Consecutive birth: append to the SAME card. repeats stays 1 —
            // N different files ≠ N identical actions; collapsedCount untouched.
            mintNames(birthCard, refs);
            const did = birthCard.detail.find((s) => s.label === "What it did");
            if (did) did.items.push(...refs.map(birthItem));
            break;
          }
          const card: DualOsStep & { newSymbols: string[]; detail: DetailSection[] } = {
            step: "os", id: "os:" + e.id, ts: e.ts, turn: e.turn,
            violated: e.invariant.violatedInvariant, kind: e.kind,
            title: BIRTH_TITLE, note: null,
            quarantine: e.view === "Quarantine", repeats: 1,
            ruleRef: e.policy?.ruleRef ?? null,
            action: null, usage: null, target: null,
            newSymbols: [],
            // Provenance = the batch's FIRST event.
            detail: birthDetail(e, refs),
          };
          mintNames(card, refs);
          steps.push(card);
          birthCard = card;
          break;
        }
        const t = ensureTool(e);
        const syms = e.output?.symbols ?? [];
        // A history re-send re-symbolizes the SAME result — under today's arbiter
        // that can even mint a fresh NAME for the same value each turn, so a
        // symbol is only "fresh" if its VALUE (or, valueless, its name) is new.
        const fresh = syms.some((s) =>
          !t.upSyms.some((u) => u.name === s.name || (s.value != null && u.value === s.value)),
        );
        if (!fresh && t.upSyms.length) { collapsed++; break; } // re-emission
        // A mint for a result the AI already got unmasked: a later request's
        // history re-send, masked once the source was labelled.
        if (t.resultAgent !== null) noteMaskedLater(t, e, syms.map((s) => s.name));
        mergeBand(t.upSyms, syms);
        mintNames(t, syms);
        if (t.symbolizedBy === null && syms.length > 0) t.symbolizedBy = e.emitter ?? null;
        if (t.resultHuman === null) {
          t.resultHuman = e.output?.original ?? e.input?.original ?? null;
          if (t.resultHuman === null && t.resultHumanTokens === undefined) {
            const toks = e.output?.originalTokens ?? e.input?.originalTokens;
            if (toks) t.resultHumanTokens = toks;
          }
        }
        if (e.policy?.trust && t.trust === null) t.trust = e.policy.trust;
        break;
      }
      case "desymbolize":
      case "egress_request":
      case "egress_decision": {
        if (!e.callId) {
          // An uncorrelated desymbolize from the reply-filter is the user-reply
          // egress: the launcher's PTY relay resolved symbol tokens in the
          // terminal stream the HUMAN sees (one event per repaint that changed
          // something). A bare "desymbolize" card read as a mystery guard step
          // (live: mistaken for inspect_symbol, session 1783733223-3201158) —
          // name the surface and the symbols it resolved. The symbols are mined
          // from the frame text: the emitter sends none (it never learns values).
          if (e.kind === "desymbolize" && e.emitter === "reply-filter") {
            const syms = matchSymbols(e.input?.symbolized ?? e.output?.symbolized ?? "");
            pushOs(e, {
              title: REPLY_FILTER_TITLE,
              note: syms.length
                ? `resolved ${syms.join(", ")} → original in the human's terminal (the agent's context keeps the symbol)`
                : "reply delivered to the human's terminal",
              detail: replyFilterDetail(e, syms),
            });
          } else {
            pushOs(e, { detail: genericDetail(e) });
          }
          break;
        }
        const t = ensureTool(e);
        mergeBand(t.downSyms, [...(e.input?.symbols ?? []), ...(e.output?.symbols ?? [])]);
        if (t.desymbolizedBy === null) t.desymbolizedBy = e.emitter ?? null;
        if (e.policy?.usage) t.usage = e.policy.usage;
        break;
      }
      case "path_rewrite": {
        const d = (e as { rewrite?: PathRewriteDetail }).rewrite;
        if (!d) break; // nothing structured to show
        if (!e.callId) {
          // The uncorrelated card gets the drawer; the CORRELATED path keeps
          // dvPathBand (every field already shown spatially) and gets no ⓘ.
          pushOs(e, { title: `path_rewrite · ${d.direction}`, detail: pathRewriteDrawer(e, d) });
          break;
        }
        const t = ensureTool(e);
        const existing = t.pathRewrites.find(
          (p) => p.direction === d.direction && p.tool === d.tool &&
                 p.field === d.field && p.human === d.human && p.agent === d.agent,
        );
        if (existing) {
          existing.repeats++;
          collapsed++;
        } else {
          t.pathRewrites.push({
            direction: d.direction, tool: d.tool, field: d.field,
            human: d.human, agent: d.agent, repeats: 1,
          });
        }
        break;
      }
      case "fs_action": {
        if (!e.callId) { pushOs(e, { detail: fsDetail(e) }); break; }
        const t = ensureTool(e);
        const txt = [e.input?.symbolized, e.output?.symbolized].filter(Boolean).join(" · ");
        if (txt && !t.gates.some((g) => g.text === txt)) {
          // Dedup keeps the FIRST gate's detail (a repeat is an identical action).
          t.gates.push(withGateWhy({ text: txt, ruleRef: e.policy?.ruleRef ?? null, detail: fsDetail(e), kind: "fs_action", usage: e.policy?.usage ?? null }, e.policy?.approvalId));
        } else if (txt) collapsed++;
        t.usage = severerUsage(t.usage, e.policy?.usage);
        break;
      }
      case "net_action":
      case "exec_action": {
        const detail = e.kind === "net_action" ? netDetail(e) : execDetail(e);
        if (e.callId && (toolByCall.has(e.callId) || recordedCalls.has(e.callId))) {
          // Correlated OS action: surface as a gate-style note on the tool card.
          const t = ensureTool(e);
          const txt = eventTitle(e);
          const usage = e.policy?.usage ?? null;
          // The title is only the kind ("exec_action"), so the DECISION is
          // part of the key, as in pushOs's fold: an allowed check and a
          // blocking one on the same call are two lines, never the first.
          if (!t.gates.some((g) => g.text === txt && (g.usage ?? null) === usage)) {
            // Dedup keeps the FIRST gate's detail (a repeat is an identical action).
            const target = e.kind === "net_action" ? { target: netTarget(e) } : {};
            t.gates.push(withGateWhy({ text: txt, ruleRef: e.policy?.ruleRef ?? null, detail, kind: e.kind, usage, ...target }, e.policy?.approvalId));
          } else collapsed++;
          t.usage = severerUsage(t.usage, e.policy?.usage);
        } else {
          pushOs(e, { detail });
        }
        break;
      }
    }
  }

  // Finalize tool steps: name + args, arg symbols → down band, crossing, origin.
  for (const t of toolByCall.values()) {
    const tu = toolUses.get(t.callId);
    if (tu) {
      if (!t.tool) t.tool = tu.tool;
      t.input = tu.input;
    }
    if (!t.tool) t.tool = "tool";
    // A patch's files: every patch the call recorded (a code-mode cell's
    // `tools.apply_patch`, under a step its exec may name), else its own args.
    {
      const files = tu?.patches ? patchFilesOf(tu.patches) : isPatchTool(t.tool) ? patchFiles(t.input) : [];
      if (files.length) t.patchFiles = files;
    }
    // inspect_symbol may appear under its MCP name (mcp__<server>__inspect_symbol),
    // or another agent's spelling of it (inspect-answer.ts).
    if (isInspectCall(t.tool)) {
      t.quarantine = true;
      if (t.quarantinedBy === null) t.quarantinedBy = "inspect-mcp";
      if (!t.readBy) {
        // The answer token the AI got back, else the symbol it asked about.
        const ep = ullmEndpointBySymbol.get(resultSymbolIn(t.resultAgent) ?? "") ??
          ullmEndpointBySymbol.get(argSymbolIn(t.input) ?? "");
        if (ep) t.readBy = ep;
      }
    }
    mergeBand(t.downSyms, bandFromNames(matchSymbols(t.input)));
    // A read that operated on the AgentView twin did NOT cross the trust wall at
    // read time — the fs chokepoint symbolized the content ON DISK earlier, so the
    // tool's own "original" result is ALREADY a symbol (or its path was ViewMap-
    // translated to the twin). Such reads render as a single AgentView card, not a
    // "HumanView (Original) executes" crossing — the misleading label that put a
    // HumanView pill on an agentview-dir path. (Quarantine keeps its own U-LLM card.)
    t.readsTwin =
      !t.quarantine &&
      (t.pathRewrites.length > 0 || matchSymbols(t.resultHuman).length > 0);
    t.crossing =
      !t.readsTwin && (t.trust === "UNTRUSTED" || t.upSyms.length > 0 || t.quarantine);
    if (t.origin === null) {
      for (const s of t.upSyms) {
        const o = symOrigin.get(s.name);
        if (o != null) { t.origin = o; break; }
      }
    }
  }

  if (lastResponse) lastResponse.final = true;
  // A user prompt OPENS its turn, but its deriving tllm_call is emitted AFTER
  // that turn's tool_use events: the proxy streams tool_use during the response
  // and emits the tllm_call only at stream end (proxy.ts emitTllmCall), so an
  // input step lands after its OWN turn's tool/os cards in emit order. Float
  // each input to the FRONT of its same-turn block — past the contiguous run of
  // same-turn non-input steps immediately preceding it — so every turn reads
  // prompt → tools → reply. The scan stops at the first different-turn step, so
  // cross-turn order is untouched and the session-opening prompt stays on top.
  // (Replaces a single first-input hoist that left every later turn's prompt
  // stranded after its WebFetch/tool cards — dashboard.md §4.2 ordering.)
  // Turn-unaware net noise: net_action events come from the net side (proxy /
  // net-supervisor), which knows no turns — always turn 0 — and they land
  // WHEREVER the race puts them (a curl's `forwarded` card can slot between a
  // tool_use and its deriving tllm_call: claude-e2e-exec-curl-run-blindspot,
  // 2026-07-16). Both floats treat them as TRANSIT — crossed when a same-turn
  // step lies beyond, never a landing spot — else a single net card strands
  // the prompt/prose after the tool cards it caused. Other turn-0 os cards
  // (the U-LLM quarantine card) are deliberate STOPS: the quarantine executed
  // before the reply that uses its result, and must render that way.
  // The reply-filter's terminal repaints are turn-unaware the same way (the
  // launcher's relay knows no turns: always turn 0) and land wherever the PTY
  // flushes: a repaint between a curl's tool_use and the tllm_call that
  // carries the NEXT prompt stranded that prompt behind it, so the curl read
  // as the previous turn's (live tour 2026-10-05, session 1791164083-1418381).
  const turnless = (s: DualStep): boolean =>
    s.step === "os" && s.turn === 0 &&
    (s.kind === "net_action" || (s.kind === "desymbolize" && s.title === REPLY_FILTER_TITLE));
  for (let i = 0; i < steps.length; i++) {
    if (steps[i]!.step !== "input") continue;
    let j = i;
    while (
      j > 0 &&
      ((steps[j - 1]!.turn === steps[i]!.turn && steps[j - 1]!.step !== "input") ||
        turnless(steps[j - 1]!))
    ) j--;
    while (j < i && turnless(steps[j]!)) j++;
    if (j < i) steps.splice(j, 0, steps.splice(i, 1)[0]!);
  }
  // The same emit-order artifact, response side (found live,
  // claude-e2e-chain-fetch-write-read 2026-07-16): a response's PROSE announces
  // the tool calls it issued ("Now saving the output to setup.md:" → Write),
  // but the text rides the tllm_call emitted at stream END while the tool_use
  // (and its exec_action gate) events were emitted mid-stream — so the tool
  // card rendered BEFORE the text introducing it. Float each response ahead of
  // the contiguous run of same-turn tool/os steps immediately preceding it, so
  // a turn reads prompt → announcing prose → tool cards. The scan stops at any
  // other step (an input, a different turn), so a reply never jumps ahead of
  // its prompt and cross-turn order is untouched.
  for (let i = 0; i < steps.length; i++) {
    if (steps[i]!.step !== "response") continue;
    let j = i;
    while (
      j > 0 &&
      ((steps[j - 1]!.turn === steps[i]!.turn &&
        (steps[j - 1]!.step === "tool" || steps[j - 1]!.step === "os")) ||
        turnless(steps[j - 1]!))
    ) j--;
    while (j < i && turnless(steps[j]!)) j++;
    if (j < i) steps.splice(j, 0, steps.splice(i, 1)[0]!);
  }
  return { steps, collapsedCount: collapsed, calls };
}

/** The answer token an inspect_symbol result carries, in any shape, or null. */
function resultSymbolIn(text: string | null): string | null {
  return inspectAnswer(text)?.answer ?? null;
}

/** The `symbol` argument of an inspect_symbol call (JSON text), or null. */
function argSymbolIn(text: string | null): string | null {
  return jsonField(text, "symbol");
}

function jsonField(text: string | null, key: string): string | null {
  if (!text) return null;
  try {
    const v = JSON.parse(text) as unknown;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const f = (v as Record<string, unknown>)[key];
      return typeof f === "string" && f !== "" ? f : null;
    }
  } catch {
    // not JSON: nothing to correlate by
  }
  return null;
}
