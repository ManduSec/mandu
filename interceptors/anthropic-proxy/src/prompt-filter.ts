/**
 * prompt-filter — the proxy half of the prompt filter
 * (docs/design/confidentiality/confidentiality-plan-15-prompt-filter.md §3, phase 1).
 * Mandu-new (no reference origin).
 *
 * The SEGMENTER cuts the user-role text of one Messages request (or the
 * Messages shadow of an OpenAI-family request, openai-wire.ts) into segments
 * tagged by who wrote them, per agent:
 *
 *   - `side-call`: every user text of a request that advertises NO tools: a
 *     call the harness makes on its own (title, quota probe, Claude Code's
 *     WebFetch summarizer, whose one user message is the fetched page). The
 *     !292 scan, now under `filterPrompt`.
 *   - `harness`: text the harness put into a user turn: Claude Code's tag
 *     spans (`<system-reminder>`, the local-command record, `!` bash-mode
 *     output, IDE context, the prompt-submit hook), its whole-message
 *     instructions (the compaction summary, the suggestion and away-recap
 *     calls), any user text that shares a message with a tool_result;
 *     OpenClaw's `Sender (untrusted metadata)` header and image-carrier
 *     lines; OpenCode's pre-read file parts and OpenCode 2's nested
 *     instruction message (`Instructions from: <abs path>/AGENTS.md`).
 *   - `human`: what is left of a user text the rules above PLACED as the
 *     human's. FAIL DIRECTION (§3.1): a text the rules cannot place is not
 *     `human`. An agent this module does not know (the union surface, an
 *     unknown spec) has no `human` segment at all, and an OpenClaw user text
 *     without its wall-clock envelope is harness. Claude Code's, OpenCode's
 *     and Goose's typed text carries no marker, so for them `human` is the
 *     remainder once every known harness shape is cut out: a harness shape
 *     a new agent version adds is `human` until a rule here names it (§3.1,
 *     "Where placed is the remainder").
 *
 * The rules start from the display heuristics (proxy.ts
 * collapseInjectedContext, the dashboard's stripHarnessTags / isSideCall and
 * its OpenClaw envelope); they live here, beside the gate surface the agent is
 * known by (gate-surface.ts `spec`).
 *
 * The arbiter runs the filters and the policy (`filterPrompt`); this module
 * only APPLIES its answer: a `rewrite` replaces the segment's text, a side
 * call's rewritten text keeps the note it always carried; a `block` (phase 2)
 * refuses the request with the arbiter's reason (PromptBlocked → a 400 the
 * agent shows) the first time its spans are seen, and forwards the
 * arbiter's safe text after that (PromptBlockLedger). A `hold` (phase 3,
 * §7: a finding whose action is `ask`) HOLDS the model request: this proxy
 * asks again every half second (`waitOutHolds`) until the human answers in
 * the Inbox or the arbiter's deadline passes, then makes one last ask
 * (`heldMs`), which the arbiter never answers `hold`; the answer it then
 * applies is the human's (as written, masked, or cancelled: a `block` the
 * agent shows) or the default (masked). A token count never waits (it does
 * not say `holds`). Any op failure, a malformed answer, or a hold still
 * standing after the last ask refuses the request (RewriteRefusal → 502):
 * the text is never forwarded unfiltered, and never raw without the human's
 * answer. An agent that disconnects while its prompt is held ends the wait
 * (PromptHoldAbandoned, the proxy's `signal`): no further ask, nothing
 * forwarded, the Inbox row left pending for an answer that applies to the
 * next request carrying the message.
 */

import { createHash } from "node:crypto";

import type { Arbiter, FilterPromptResult, PromptFindingWire, PromptSegmentOrigin } from "./arbiter-client.js";
import type { Message, MessagesRequest } from "./messages-types.js";
import { isToolResultBlock } from "./messages-types.js";

/** The note after a side call's text that held a registered secret. */
export const SIDE_CALL_SECRET_NOTE =
  "[mandu:secret] masked: part of this text holds a registered secret, so the model sees that part as a symbol. The user sees the original.";

/** Whose segmenter rules apply. */
export type SegmentAgent = "claude-code" | "openclaw" | "opencode" | "goose" | "generic";

/** The segmenter for a gate-surface spec (arbiter tool-inbound.ts
 *  InboundSpecId). Anything else (the union fallback, `fail-closed`) has no
 *  rules that place a human segment. */
export function segmentAgentFor(spec: string | undefined): SegmentAgent {
  switch (spec) {
    case "claude-code": return "claude-code";
    case "openclaw":
    case "openclaw-agent": return "openclaw";
    case "opencode": return "opencode";
    case "goose": return "goose";
    default: return "generic";
  }
}

/** One piece of a text: [start, end) and its origin. */
export interface Piece {
  start: number;
  end: number;
  origin: PromptSegmentOrigin;
}

/** Tag spans Claude Code puts into a user message around the human's text.
 *  An unclosed tag runs to the end of the text (it cannot be placed). */
const CLAUDE_TAGS = [
  "system-reminder",
  "local-command-caveat", "local-command-stdout", "local-command-stderr",
  "command-name", "command-message", "command-args", "command-contents",
  "bash-input", "bash-stdout", "bash-stderr",
  "user-prompt-submit-hook",
  "ide_selection", "ide_opened_file", "ide_diagnostics",
];
const CLAUDE_TAG_OPEN_RE = new RegExp(`<(${CLAUDE_TAGS.join("|")})>`, "gi");

/** A user text that is the harness's whole instruction, not the human's. */
const CLAUDE_WHOLE_HARNESS_RE = new RegExp([
  // the compaction summary (it restates tool output)
  "^\\s*This session is being continued from a previous conversation",
  // typeahead suggestion and the away recap (dual-lanes.ts isSideCall)
  "^\\s*\\[SUGGESTION MODE:",
  "^\\s*The user stepped away and is coming back\\.",
  // a slash command's caveat line
  "^\\s*Caveat: The messages below were generated by the user while running local commands",
  // an interrupted turn's marker
  "^\\s*\\[Request interrupted by user",
].join("|"));

/** OpenClaw's wall-clock envelope before the human's text
 *  (dashboard transcript.ts OPENCLAW_ENVELOPE), at a line start. */
const OPENCLAW_ENVELOPE_RE =
  /^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) \d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?(?: [A-Za-z]{1,5}(?:[+-]\d{1,2}(?::?\d{2})?)?)?\][ \t]+/gm;

/** OpenCode's pre-read of an @-mentioned file: a synthetic "Called the …
 *  tool" part, then the tool's output part. */
const OPENCODE_CALLED_RE = /^\s*Called the \S+ tool with the following input:/;
const OPENCODE_FILE_RE = /^\s*<file>/;

/** OpenCode 2's nested instruction file (2.0.23, captured 2026-10-18):
 *  after a `read` under a subdirectory it sends the nearer AGENTS.md /
 *  CLAUDE.md / CONTEXT.md as a user message of its own, one text block
 *  `Instructions from: <absolute path>\n<file contents>` (OpenCode 1 puts the
 *  same text in the read's result, inside a `<system-reminder>`). Only a
 *  block that STARTS with the header and names an absolute path to one of
 *  those three files is this rule; the whole block is harness. A human who
 *  types the header gets harness treatment for that text, the safe
 *  direction: harness findings are redacted (never held, never sent as
 *  written), and the registered-value floor masks harness text always
 *  (confidentiality-plan-15-prompt-filter.md §3.1, §13.6 item 20). */
const OPENCODE_INSTRUCTIONS_RE = /^Instructions from: \/[^\n]*\/(?:AGENTS|CLAUDE|CONTEXT)\.md[ \t]*(?:\r?\n|$)/;

/** Goose's per-turn context (goose 1.53.0, captured 2026-10-05): its own
 *  text part after the human's typed one, `<turn-context>\n<current-time>…
 *  </current-time>\n<working-directory>…</working-directory>\n</turn-context>`.
 *  Every other typed part is the human's (`run -t`, a session line). */
const GOOSE_TAG_OPEN_RE = /<(turn-context)>/gi;

/** Tag spans are the harness's, the rest the human's (Claude Code's
 *  rule, over another agent's tag list). */
function taggedPieces(text: string, openRe: RegExp): Piece[] {
  const out: Piece[] = [];
  let at = 0;
  openRe.lastIndex = 0;
  for (let m = openRe.exec(text); m !== null; m = openRe.exec(text)) {
    const open = m.index;
    const close = `</${m[1]!}>`;
    const closeAt = text.toLowerCase().indexOf(close.toLowerCase(), open + m[0].length);
    const end = closeAt < 0 ? text.length : closeAt + close.length;
    if (open > at) out.push({ start: at, end: open, origin: "human" });
    out.push({ start: open, end, origin: "harness" });
    at = end;
    openRe.lastIndex = end;
  }
  if (at < text.length) out.push({ start: at, end: text.length, origin: "human" });
  return out;
}

function claudePieces(text: string): Piece[] {
  if (CLAUDE_WHOLE_HARNESS_RE.test(text)) return [{ start: 0, end: text.length, origin: "harness" }];
  const out: Piece[] = [];
  let at = 0;
  CLAUDE_TAG_OPEN_RE.lastIndex = 0;
  for (let m = CLAUDE_TAG_OPEN_RE.exec(text); m !== null; m = CLAUDE_TAG_OPEN_RE.exec(text)) {
    const open = m.index;
    const close = `</${m[1]!}>`;
    const closeAt = text.toLowerCase().indexOf(close.toLowerCase(), open + m[0].length);
    const end = closeAt < 0 ? text.length : closeAt + close.length;
    if (open > at) out.push({ start: at, end: open, origin: "human" });
    out.push({ start: open, end, origin: "harness" });
    at = end;
    CLAUDE_TAG_OPEN_RE.lastIndex = end;
  }
  if (at < text.length) out.push({ start: at, end: text.length, origin: "human" });
  return out;
}

function openclawPieces(text: string): Piece[] {
  // The human's text follows the LAST envelope; everything before it
  // (the sender header, earlier context) is the harness's.
  let last = -1;
  let lastEnd = -1;
  OPENCLAW_ENVELOPE_RE.lastIndex = 0;
  for (let m = OPENCLAW_ENVELOPE_RE.exec(text); m !== null; m = OPENCLAW_ENVELOPE_RE.exec(text)) {
    last = m.index;
    lastEnd = m.index + m[0].length;
  }
  if (last < 0) return [{ start: 0, end: text.length, origin: "harness" }];
  const out: Piece[] = [{ start: 0, end: lastEnd, origin: "harness" }];
  if (lastEnd < text.length) out.push({ start: lastEnd, end: text.length, origin: "human" });
  return out;
}

/**
 * Cut one user text into pieces. `ctx.harnessOnly`: the text cannot be the
 * human's whatever it says (a side call is handled by the caller; a text
 * beside a tool_result; a part after OpenCode's pre-read marker).
 */
export function pieceText(agent: SegmentAgent, text: string, ctx: { harnessOnly?: boolean } = {}): Piece[] {
  if (text === "") return [];
  if (ctx.harnessOnly || agent === "generic") return [{ start: 0, end: text.length, origin: "harness" }];
  switch (agent) {
    case "claude-code":
      return claudePieces(text);
    case "openclaw":
      return openclawPieces(text);
    case "opencode":
      if (OPENCODE_CALLED_RE.test(text) || OPENCODE_FILE_RE.test(text) || OPENCODE_INSTRUCTIONS_RE.test(text)) return [{ start: 0, end: text.length, origin: "harness" }];
      // A `<system-reminder>` span inside a typed part is the harness's too.
      return claudePieces(text);
    case "goose":
      return taggedPieces(text, GOOSE_TAG_OPEN_RE);
  }
}

/** Where one user text lives in the request, to write its rewrite back. */
interface TextSlot {
  get(): string;
  set(text: string): void;
}

/** One user text and its pieces. */
interface SlotPieces {
  slot: TextSlot;
  text: string;
  pieces: Array<Piece & { id: string | null }>;
  sideCall: boolean;
}

/** The user texts of one request, in order, with their pieces. */
export function segmentRequest(req: MessagesRequest, agent: SegmentAgent): { slots: SlotPieces[]; segments: Array<{ id: string; origin: PromptSegmentOrigin; text: string }> } {
  const sideCall = !(Array.isArray(req.tools) && req.tools.length > 0);
  const slots: SlotPieces[] = [];
  const segments: Array<{ id: string; origin: PromptSegmentOrigin; text: string }> = [];
  const messages: Message[] = Array.isArray(req.messages) ? req.messages : [];
  messages.forEach((msg, m) => {
    if (!msg || msg.role !== "user") return;
    const add = (slot: TextSlot, where: string, harnessOnly: boolean): void => {
      const text = slot.get();
      const raw: Piece[] = sideCall
        ? (text === "" ? [] : [{ start: 0, end: text.length, origin: "side-call" }])
        : pieceText(agent, text, { harnessOnly });
      const pieces = raw.map((p, k) => {
        // Whitespace-only pieces carry nothing a filter could match.
        const id = text.slice(p.start, p.end).trim() === "" ? null : `${where}.p${k}`;
        if (id !== null) segments.push({ id, origin: p.origin, text: text.slice(p.start, p.end) });
        return { ...p, id };
      });
      slots.push({ slot, text, pieces, sideCall });
    };
    if (typeof msg.content === "string") {
      add({ get: () => msg.content as string, set: (t) => { msg.content = t; } }, `m${m}`, false);
      return;
    }
    if (!Array.isArray(msg.content)) return;
    const withResult = msg.content.some((b) => isToolResultBlock(b));
    let afterPreRead = false;
    msg.content.forEach((block, b) => {
      if (!block || typeof block !== "object" || (block as { type?: unknown }).type !== "text") return;
      const tb = block as { text?: unknown };
      if (typeof tb.text !== "string") return;
      const harnessOnly = withResult || (agent === "opencode" && afterPreRead);
      if (agent === "opencode") afterPreRead = OPENCODE_CALLED_RE.test(tb.text);
      add({ get: () => tb.text as string, set: (t) => { tb.text = t; } }, `m${m}.b${b}`, harnessOnly);
    });
  });
  return { slots, segments };
}

/** What the filter did to one request: the arbiter's per-segment answers,
 *  for the `prompt_filter` events, and the symbols that replaced spans (the
 *  trusted-context haystack cuts them, rewrite-request.ts). */
export interface PromptFilterReport {
  agent: SegmentAgent;
  enforcing: boolean;
  digest: { policy: string; packs: string };
  segments: Array<{
    id: string;
    origin: PromptSegmentOrigin;
    /** `block`: refused this time (the request is not forwarded). A
     *  blocked segment forwarded with its safe text (the human was told
     *  before, or a token count) is `rewrite`. */
    action: "pass" | "rewrite" | "block";
    findings: PromptFindingWire[];
    skipped: number;
    cached: boolean;
    /** A short hash of the segment's text (event dedupe; never the text). */
    hash: string;
    /** Phase 3: the message's opaque reference (a "let it through, once"). */
    turn?: string;
  }>;
  /** Every symbol the filter put into the request. */
  replaced: string[];
}

/** A small, non-cryptographic text hash (FNV-1a, 32 bits): event dedupe only. */
export function textHash(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/** The refusal type the caller maps to its own (RewriteRefusal). */
export class PromptFilterRefusal extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "PromptFilterRefusal";
  }
}

/** A prompt the policy blocks (§7): refused with a reason the agent shows.
 *  Carries what the filter did, for the `prompt_filter` events. */
export class PromptBlocked extends PromptFilterRefusal {
  constructor(message: string, public readonly report: PromptFilterReport) {
    super(message);
    this.name = "PromptBlocked";
  }
}

/**
 * The blocked findings this proxy already refused once, per session (§7,
 * phase 2). The agents keep a refused message in their history and resend
 * it with the next turn; refusing it again would leave the session stuck
 * until the human rewinds. So a blocked span refuses the request the FIRST
 * time it is seen, and later requests forward the arbiter's safe text for
 * it instead (each blocked span replaced by `[blocked: <category>]`): the
 * value never leaves either way. Keyed by session, category and a hash of
 * the span (never the span itself); bounded, oldest out; in memory, so a
 * restarted proxy refuses once more.
 */
export class PromptBlockLedger {
  private readonly seen = new Set<string>();
  constructor(private readonly cap = 4096) {}
  has(key: string): boolean {
    return this.seen.has(key);
  }
  add(key: string): void {
    this.seen.add(key);
    while (this.seen.size > this.cap) {
      const oldest = this.seen.values().next().value as string | undefined;
      if (oldest === undefined) break;
      this.seen.delete(oldest);
    }
  }
}

/**
 * Which `prompt_filter` events this proxy records (plan 15 §8, §13.7). The
 * agents resend the whole conversation with every request, so one message is
 * filtered again and again; an event is recorded only when a segment's
 * outcome differs from the one this proxy last recorded for the same text in
 * the session: the first finding, a changed action, a verdict that let a
 * span through, an ask's answer, an administrator's ask lock that came or
 * went (`onceOnly`, so the note's session button follows it).
 *
 * AND WHEN IT NOW HAS NONE. A message whose earlier finding no longer applies
 * (an exception added, a kind set to pass, a filter turned off) is answered
 * with no finding. Recording nothing would leave the note under it saying
 * what the old outcome was, so the first such resend records an event with no
 * findings and the message's remembered `turn` (the arbiter names a turn on
 * a segment with a finding it can reference): the dashboard's note reads
 * the newest event and clears. A segment never recorded with a finding
 * records nothing, unless the arbiter names its `turn` all the same: it
 * does so on a message it answered with a referenced finding before in the
 * session (holds.ts, noted messages, kept in mandu.db), so a restarted proxy,
 * or one whose entry was evicted, still clears a note it never recorded
 * (plan 15 §13.7 item 10). Categories and counts only, never the value: the
 * entry is the outcome's key and the message's opaque reference. Keyed by
 * session and the segment's text hash; bounded, oldest out; in memory (the
 * arbiter holds what must outlive this proxy).
 */
export class PromptEventLedger {
  private readonly last = new Map<string, { key: string; turn?: string }>();
  constructor(private readonly cap = 4096) {}
  /** Whether to record this segment now, and with which `turn`; null when
   *  its outcome is the one last recorded (or it never had one). */
  next(session: string, s: Pick<PromptFilterReport["segments"][number], "hash" | "action" | "skipped" | "findings" | "turn">): { turn?: string } | null {
    const id = `${session}|${s.hash}`;
    const prev = this.last.get(id);
    const empty = s.findings.length === 0 && s.skipped === 0;
    // A turn on an answer with nothing found is the arbiter's word that the
    // message was answered with a finding before in the session (holds.ts,
    // noted messages): its note stands, so it clears though this proxy never
    // recorded it (a restarted proxy, an entry evicted).
    if (empty && prev === undefined && s.turn === undefined) return null;
    const key = empty ? "" : `${s.action}|${s.skipped}|${s.findings.map((f) => `${f.action}:${f.symbol ?? ""}:${f.let ?? ""}:${f.hold?.state ?? ""}:${f.onceOnly === true ? "1" : ""}`).join(",")}`;
    if (prev !== undefined && prev.key === key) return null;
    const turn = s.turn ?? prev?.turn;
    this.last.delete(id);
    this.last.set(id, { key, ...(turn ? { turn } : {}) });
    while (this.last.size > this.cap) {
      const oldest = this.last.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.last.delete(oldest);
    }
    return turn ? { turn } : {};
  }
}

/** The id of the human's last segment in a request (in request order), or
 *  null when it has none: a blocked span is "told" only once the human has
 *  written after it (plan 15 §7, `block`). */
export function lastHumanSegment(slots: ReadonlyArray<{ pieces: ReadonlyArray<{ id: string | null; origin: string }> }>): string | null {
  let last: string | null = null;
  for (const sp of slots) for (const p of sp.pieces) if (p.id !== null && p.origin === "human") last = p.id;
  return last;
}

/** The ledger keys of a segment's blocked findings. */
export function blockKeys(session: string, original: string, findings: readonly PromptFindingWire[]): string[] {
  return findings
    .filter((f) => f.action === "block" && Number.isInteger(f.start) && Number.isInteger(f.end) && f.end > f.start)
    .map((f) => `${session}|${f.category}|${createHash("sha256").update(original.slice(f.start, f.end)).digest("hex").slice(0, 32)}`);
}


/** How this proxy waits out a `hold` (plan 15 §7). */
export interface HoldWait {
  /** Between two asks (ms; default 500). */
  pollMs?: number;
  /** The longest this proxy holds one request whatever the arbiter says
   *  (ms; default 120 000): past it, one last ask, then a refusal. */
  maxMs?: number;
  /** Seams for tests. `sleep` is handed the client's signal and should
   *  return early when it aborts (the default does, and clears its timer). */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  now?: () => number;
}

/**
 * The agent went away while its prompt was held (plan 15 §13.6 item 13): its
 * connection closed before the human answered, so this proxy stopped asking.
 * A PromptFilterRefusal (anything that catches that still refuses): nothing
 * of the request is forwarded. The hold itself stays pending in the arbiter,
 * as every unanswered ask does (pending asks are not expired): an answer given
 * later applies to the agent's next request that carries the message.
 */
export class PromptHoldAbandoned extends PromptFilterRefusal {
  constructor() {
    super("the agent disconnected while its prompt was held for the human's answer; nothing was sent");
    this.name = "PromptHoldAbandoned";
  }
}

/**
 * A signal that aborts when the agent's connection closes before its answer
 * was written (plan 15 §13.6 item 13): what ends a held prompt's wait. A
 * response that finished also closes; that one does not abort.
 */
export function clientGone(res: { once(event: "close", listener: () => void): unknown; readonly writableFinished: boolean }): AbortSignal {
  const ac = new AbortController();
  res.once("close", () => {
    if (!res.writableFinished) ac.abort();
  });
  return ac.signal;
}

const HOLD_POLL_MS = 500;
const HOLD_MAX_MS = 120_000;
/** Slack past the arbiter's deadline before the last ask. */
const HOLD_SLACK_MS = 1_000;

/** Wait `ms`, or less when `signal` aborts; the timer and the listener are
 *  cleared either way, so an abandoned hold leaves nothing scheduled. */
function pause(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise<void>((resolve) => {
    if (signal?.aborted) return resolve();
    const done = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal?.addEventListener("abort", done, { once: true });
  });
}

/**
 * Ask the arbiter, and while any segment is held, ask again until none is.
 * The deadline is the arbiter's (`hold.timeoutMs`, from the hold's first
 * sighting) plus a little slack, capped by `maxMs`; at it, one last ask with
 * `heldMs`, which the arbiter answers with the default. A hold still standing
 * after that throws (the caller refuses the request). Errors propagate.
 * `signal` is the agent's connection: once it aborts (the client
 * disconnected) no further ask is made and PromptHoldAbandoned is thrown,
 * whatever the last answer was, so nothing is forwarded to a client that is
 * gone and no poll outlives it.
 */
export async function waitOutHolds(
  ask: (extra: { holds?: boolean; heldMs?: number }) => Promise<FilterPromptResult>,
  opts: { canWait: boolean; wait?: HoldWait; log?: (msg: string) => void; signal?: AbortSignal },
): Promise<FilterPromptResult> {
  const now = opts.wait?.now ?? (() => Date.now());
  const sleep = opts.wait?.sleep ?? pause;
  const pollMs = Math.max(10, opts.wait?.pollMs ?? HOLD_POLL_MS);
  const maxMs = opts.wait?.maxMs ?? HOLD_MAX_MS;
  const signal = opts.signal;
  const extra = opts.canWait ? { holds: true } : {};
  const held = (a: FilterPromptResult): Array<FilterPromptResult["segments"][number]> =>
    (Array.isArray(a?.segments) ? a.segments : []).filter((s) => s && s.action === "hold");
  const stillThere = (): void => {
    if (signal?.aborted) {
      opts.log?.("prompt filter: the agent disconnected while its prompt was held; stopped waiting, nothing sent (the hold stays in the Inbox)");
      throw new PromptHoldAbandoned();
    }
  };
  let answer = await ask(extra);
  if (held(answer).length === 0 || !opts.canWait) return answer;
  stillThere();
  const started = now();
  const left = Math.max(0, ...held(answer).map((s) => (typeof s.hold?.timeoutMs === "number" && Number.isFinite(s.hold.timeoutMs) ? s.hold.timeoutMs : 0)));
  const deadline = started + Math.min(maxMs, left + HOLD_SLACK_MS);
  opts.log?.(`prompt filter: HELD for the human's answer in the Inbox (${held(answer).map((s) => s.hold?.approvalId ?? "?").join(", ")}; up to ${Math.round((deadline - started) / 1000)} s)`);
  while (held(answer).length > 0 && now() < deadline) {
    await sleep(Math.min(pollMs, Math.max(0, deadline - now())), signal);
    stillThere();
    answer = await ask(extra);
    stillThere();
  }
  if (held(answer).length > 0) {
    answer = await ask({ ...extra, heldMs: now() - started });
    stillThere();
  }
  if (held(answer).length > 0) throw new Error("the prompt is still held after the deadline");
  return answer;
}

/**
 * Run the prompt filter over `req` (mutated in place): segment, ask the
 * arbiter, apply the answer. Returns null when there is nothing to filter or
 * the arbiter is an in-test mock without the op. Throws PromptFilterRefusal
 * on any failure (fail-closed).
 */
export async function applyPromptFilter(
  req: MessagesRequest,
  arbiter: Arbiter,
  opts: {
    agent: SegmentAgent;
    sessionKey?: string;
    log?: (msg: string) => void;
    /** The blocked spans already refused once (absent: a fresh ledger, so
     *  every block refuses). */
    ledger?: PromptBlockLedger;
    /** A token count (count_tokens): a blocked segment's safe text is
     *  forwarded and nothing is refused or recorded; it is never held. */
    countOnly?: boolean;
    /** How a `hold` is waited out (tests shorten it). */
    holdWait?: HoldWait;
    /** The agent's connection: aborted when it closes, which ends a hold's
     *  wait with PromptHoldAbandoned (nothing forwarded). */
    signal?: AbortSignal;
  },
): Promise<PromptFilterReport | null> {
  if (!arbiter.filterPrompt) return null;
  const { slots, segments } = segmentRequest(req, opts.agent);
  if (segments.length === 0) return null;
  let answer: FilterPromptResult;
  const filterPrompt = arbiter.filterPrompt.bind(arbiter);
  try {
    // Plan 15 §7: a held segment waits for the human (never a token count).
    answer = await waitOutHolds((extra) => filterPrompt({
      ...(opts.sessionKey ? { session: opts.sessionKey } : {}),
      agent: opts.agent,
      segments,
      ...extra,
    }), {
      canWait: opts.countOnly !== true,
      ...(opts.holdWait ? { wait: opts.holdWait } : {}),
      ...(opts.log ? { log: opts.log } : {}),
      ...(opts.signal ? { signal: opts.signal } : {}),
    });
  } catch (err) {
    if (err instanceof PromptHoldAbandoned) throw err;
    throw new PromptFilterRefusal("arbiter filterPrompt failed — refusing to forward the prompt unfiltered", err);
  }
  const byId = new Map<string, FilterPromptResult["segments"][number]>();
  for (const s of Array.isArray(answer?.segments) ? answer.segments : []) {
    if (s && typeof s.id === "string") byId.set(s.id, s);
  }
  const ledger = opts.ledger ?? new PromptBlockLedger();
  const refusals: Array<{ reason: string; keys: string[] }> = [];
  const report: PromptFilterReport = {
    agent: opts.agent,
    enforcing: answer.enforcing === true,
    digest: { policy: String(answer.digest?.policy ?? ""), packs: String(answer.digest?.packs ?? "") },
    segments: [],
    replaced: [],
  };
  // The human's LAST segment in this request: a blocked span there was not
  // followed by anything the human wrote after being told, so a request
  // carrying it is the same message again (the agent's own retry), never
  // the resend the reason asks for. Claude Code 2.1.289 retries a refused
  // request at once with another beta set (live 2026-10-04,
  // conf-prompt-block): the ledger counted that retry as "told" and
  // forwarded it, so the refusal never reached the human's screen.
  const lastHuman = lastHumanSegment(slots);
  for (const sp of slots) {
    let out = "";
    let changed = false;
    let at = 0;
    for (const p of sp.pieces) {
      out += sp.text.slice(at, p.start);
      at = p.end;
      const original = sp.text.slice(p.start, p.end);
      if (p.id === null) { out += original; continue; }
      const r = byId.get(p.id);
      if (!r) throw new PromptFilterRefusal(`arbiter filterPrompt did not answer segment ${p.id} — refusing to forward it unfiltered`);
      if (r.action === "rewrite") {
        if (typeof r.text !== "string") throw new PromptFilterRefusal(`arbiter filterPrompt answered rewrite with no text for ${p.id}`);
        out += r.text;
        changed = true;
        for (const f of r.findings ?? []) if ((f.action === "mask" || f.action === "ask") && typeof f.symbol === "string" && f.let === undefined) report.replaced.push(f.symbol);
      } else if (r.action === "pass") {
        out += original;
      } else if (r.action === "block") {
        // §7, phase 2: the policy blocks this segment. With no safe text (a
        // filter could not run) nothing of it may ever go. With one, the
        // first sighting refuses the request (the agent shows the reason);
        // a token count, or a resend after the human was told, forwards the
        // safe text, where each blocked span is `[blocked: <category>]`.
        const keys = blockKeys(opts.sessionKey ?? "", original, r.findings ?? []);
        const told = opts.countOnly === true || (keys.length > 0 && keys.every((k) => ledger.has(k)) && p.id !== lastHuman);
        if (typeof r.text !== "string" || !told) {
          refusals.push({ reason: r.reason ?? "Mandu's prompt filter blocked this prompt.", keys: typeof r.text === "string" ? keys : [] });
          out += original;
          report.segments.push({
            id: p.id, origin: p.origin, action: "block", findings: r.findings ?? [], skipped: r.skipped ?? 0,
            cached: r.cached === true, hash: textHash(`${p.origin}\u0000${original}`), ...(typeof r.turn === "string" ? { turn: r.turn } : {}),
          });
          continue;
        }
        out += r.text;
        changed = true;
        for (const f of r.findings ?? []) if ((f.action === "mask" || f.action === "ask") && typeof f.symbol === "string" && f.let === undefined) report.replaced.push(f.symbol);
        report.segments.push({
          id: p.id, origin: p.origin, action: "rewrite", findings: r.findings ?? [], skipped: r.skipped ?? 0,
          cached: r.cached === true, hash: textHash(`${p.origin}\u0000${original}`), ...(typeof r.turn === "string" ? { turn: r.turn } : {}),
        });
        continue;
      } else {
        // A `hold` left after the last ask (waitOutHolds throws first), or
        // an action this proxy does not know: refuse rather than forward.
        throw new PromptFilterRefusal(`arbiter filterPrompt answered ${String(r.action)} for a ${p.origin} segment: ${r.reason ?? "refused"}`);
      }
      report.segments.push({
        id: p.id, origin: p.origin, action: r.action, findings: r.findings ?? [], skipped: r.skipped ?? 0,
        cached: r.cached === true, hash: textHash(`${p.origin}\u0000${original}`), ...(typeof r.turn === "string" ? { turn: r.turn } : {}),
      });
    }
    out += sp.text.slice(at);
    if (!changed) continue;
    if (sp.sideCall) out = `${out}\n\n${SIDE_CALL_SECRET_NOTE}`;
    sp.slot.set(out);
  }
  if (refusals.length > 0) {
    // Refused this time; the next request that carries the same spans is
    // forwarded with the safe text once the human has written after them
    // (the human was told; a retry of the same message is refused again).
    for (const r of refusals) for (const k of r.keys) ledger.add(k);
    opts.log?.(`prompt filter: BLOCKED ${refusals.length} segment(s); the request is refused`);
    throw new PromptBlocked([...new Set(refusals.map((r) => r.reason))].join(" "), report);
  }
  const masked = report.segments.filter((s) => s.action === "rewrite");
  if (masked.length > 0) {
    opts.log?.(`prompt filter: ${masked.length} segment(s) masked (${masked.map((s) => s.origin).join(", ")})`);
  }
  return report;
}
