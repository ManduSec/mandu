/**
 * prompt-filter — the openai-proxy half of the prompt filter for Codex
 * (docs/design/confidentiality/confidentiality-plan-15-prompt-filter.md §3, phase 1).
 * Mandu-new (no reference origin); the twin of
 * anthropic-proxy/src/prompt-filter.ts with Codex's rules.
 *
 * Before plan 15 this proxy never read a user `message` item for masking
 * (only tool outputs). The SEGMENTER cuts the user-role text of one Responses
 * request (or the Responses shadow of a Chat Completions request,
 * chat-wire.ts) into segments tagged by who wrote them:
 *
 *   - `side-call`: every user text of a request that advertises no tools
 *     (neither `tools` nor an `additional_tools` item): a call Codex makes
 *     on its own (a compaction or title request).
 *   - `harness`: the runtime context Codex delivers as user-role messages
 *     (transcript.ts CONTEXT_MESSAGE_RE): the workspace's AGENTS.md
 *     ("# AGENTS.md instructions for …"), `<user_instructions>`,
 *     `<environment_context>`, and the records it keeps in user turns: a
 *     `!` shell command's output (`<user_shell_command>`), an aborted turn
 *     (`<turn_aborted>`), a compaction summary. A tag span of these inside
 *     a typed message is harness too.
 *   - `human`: what is left. Fail direction (§3.1): a request whose wire this
 *     module cannot place as Codex's has no `human` segment.
 *
 * The arbiter runs the filters and the policy (`filterPrompt`); this module
 * applies its answer: a `rewrite` replaces the segment's text; a `block`
 * (phase 2) refuses the request with the arbiter's reason the first time its
 * spans are seen and forwards the arbiter's safe text after that
 * (PromptBlockLedger, the anthropic-proxy's twin). A `hold` (phase 3, §7:
 * an `ask` finding) holds the model request until the human answers in the
 * Inbox or the arbiter's deadline passes (`waitOutHolds`, the
 * anthropic-proxy's twin); a token count never waits. Any failure, a
 * malformed answer, or a hold still standing after the last ask refuses the
 * request (fail-closed): never raw without the human's answer. An agent
 * that disconnects while held ends the wait (PromptHoldAbandoned): no
 * further ask, nothing forwarded, the Inbox row left pending.
 */

import { createHash } from "node:crypto";

import type { Arbiter, FilterPromptResult, PromptFindingWire, PromptSegmentOrigin } from "./arbiter-client.js";
import { advertisedTools, isMessageItem, type ResponsesRequest } from "./responses-types.js";

/** Whose segmenter rules apply. */
export type SegmentAgent = "codex" | "generic";

/** One piece of a text: [start, end) and its origin. */
export interface Piece {
  start: number;
  end: number;
  origin: PromptSegmentOrigin;
}

/** A whole user message that is Codex's runtime context or record. */
const CODEX_WHOLE_HARNESS_RE = new RegExp([
  "^\\s*<environment_context>",
  "^\\s*<user_instructions>",
  "^\\s*# AGENTS\\.md instructions for ",
  "^\\s*<user_shell_command>",
  "^\\s*<turn_aborted>",
  // the compaction hand-off (it restates the conversation, tool output included)
  "^\\s*Another language model started to solve this problem",
].join("|"), "i");

/** Codex's runtime context, the evidence a Chat Completions client is Codex. */
const CODEX_CONTEXT_RE = /^\s*(?:<environment_context>|# AGENTS\.md instructions for )/i;

/**
 * Which rules a request gets. The Responses route is Codex's. The Chat
 * Completions route also serves other clients (Kimi Code, Aider, …; whose
 * user messages may carry pasted file content), so a chat request gets
 * Codex's rules only when it carries Codex's runtime context; otherwise no
 * text of it is placed as the human's (the fail direction, §3.1).
 */
export function segmentAgentFor(req: ResponsesRequest, wire: "responses" | "chat"): SegmentAgent {
  if (wire === "responses") return "codex";
  for (const item of Array.isArray(req.input) ? req.input : []) {
    if (!isMessageItem(item) || item.role !== "user") continue;
    const c = item.content;
    const texts = typeof c === "string" ? [c] : Array.isArray(c) ? c.map((p) => (p as { text?: unknown })?.text).filter((t): t is string => typeof t === "string") : [];
    if (texts.some((t) => CODEX_CONTEXT_RE.test(t))) return "codex";
  }
  return "generic";
}

/** Tag spans of that context inside a typed message. */
const CODEX_TAGS = ["environment_context", "user_instructions", "user_shell_command", "turn_aborted"];
const CODEX_TAG_OPEN_RE = new RegExp(`<(${CODEX_TAGS.join("|")})>`, "gi");

/** Cut one user text into pieces. */
export function pieceText(agent: SegmentAgent, text: string, ctx: { harnessOnly?: boolean } = {}): Piece[] {
  if (text === "") return [];
  if (ctx.harnessOnly || agent === "generic" || CODEX_WHOLE_HARNESS_RE.test(text)) return [{ start: 0, end: text.length, origin: "harness" }];
  const out: Piece[] = [];
  let at = 0;
  CODEX_TAG_OPEN_RE.lastIndex = 0;
  for (let m = CODEX_TAG_OPEN_RE.exec(text); m !== null; m = CODEX_TAG_OPEN_RE.exec(text)) {
    const close = `</${m[1]!}>`;
    const closeAt = text.toLowerCase().indexOf(close.toLowerCase(), m.index + m[0].length);
    const end = closeAt < 0 ? text.length : closeAt + close.length;
    if (m.index > at) out.push({ start: at, end: m.index, origin: "human" });
    out.push({ start: m.index, end, origin: "harness" });
    at = end;
    CODEX_TAG_OPEN_RE.lastIndex = end;
  }
  if (at < text.length) out.push({ start: at, end: text.length, origin: "human" });
  return out;
}

interface TextSlot {
  get(): string;
  set(text: string): void;
}

interface SlotPieces {
  slot: TextSlot;
  text: string;
  pieces: Array<Piece & { id: string | null }>;
  sideCall: boolean;
}

/** The user texts of one request, in order, with their pieces. */
export function segmentRequest(req: ResponsesRequest, agent: SegmentAgent): { slots: SlotPieces[]; segments: Array<{ id: string; origin: PromptSegmentOrigin; text: string }> } {
  const sideCall = advertisedTools(req).length === 0;
  const slots: SlotPieces[] = [];
  const segments: Array<{ id: string; origin: PromptSegmentOrigin; text: string }> = [];
  const input = Array.isArray(req.input) ? req.input : [];
  const add = (slot: TextSlot, where: string): void => {
    const text = slot.get();
    const raw: Piece[] = sideCall ? (text === "" ? [] : [{ start: 0, end: text.length, origin: "side-call" }]) : pieceText(agent, text);
    const pieces = raw.map((p, k) => {
      const id = text.slice(p.start, p.end).trim() === "" ? null : `${where}.p${k}`;
      if (id !== null) segments.push({ id, origin: p.origin, text: text.slice(p.start, p.end) });
      return { ...p, id };
    });
    slots.push({ slot, text, pieces, sideCall });
  };
  input.forEach((item, i) => {
    if (!isMessageItem(item) || item.role !== "user") return;
    const c = item.content;
    if (typeof c === "string") {
      add({ get: () => item.content as string, set: (t) => { item.content = t; } }, `i${i}`);
      return;
    }
    if (!Array.isArray(c)) return;
    c.forEach((part, k) => {
      if (!part || typeof part !== "object") return;
      const p = part as { type?: unknown; text?: unknown };
      if ((p.type !== "input_text" && p.type !== "text") || typeof p.text !== "string") return;
      add({ get: () => p.text as string, set: (t) => { p.text = t; } }, `i${i}.c${k}`);
    });
  });
  return { slots, segments };
}

/** What the filter did to one request (the `prompt_filter` events). */
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

/** FNV-1a, 32 bits: event dedupe only. */
export function textHash(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

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

/** Run the prompt filter over `req` (mutated in place). Null when there is
 *  nothing to filter or the arbiter is an in-test mock without the op.
 *  Throws PromptFilterRefusal on any failure (fail-closed). */
export async function applyPromptFilter(
  req: ResponsesRequest,
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
    answer = await waitOutHolds(
      (extra) => filterPrompt({ ...(opts.sessionKey ? { session: opts.sessionKey } : {}), agent: opts.agent, segments, ...extra }),
      {
        canWait: opts.countOnly !== true,
        ...(opts.holdWait ? { wait: opts.holdWait } : {}),
        ...(opts.log ? { log: opts.log } : {}),
        ...(opts.signal ? { signal: opts.signal } : {}),
      },
    );
  } catch (err) {
    if (err instanceof PromptHoldAbandoned) throw err;
    throw new PromptFilterRefusal("arbiter filterPrompt failed — refusing to forward the prompt unfiltered", err);
  }
  const byId = new Map<string, FilterPromptResult["segments"][number]>();
  for (const s of Array.isArray(answer?.segments) ? answer.segments : []) if (s && typeof s.id === "string") byId.set(s.id, s);
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
    if (changed) sp.slot.set(out);
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
  if (masked.length > 0) opts.log?.(`prompt filter: ${masked.length} segment(s) masked (${masked.map((s) => s.origin).join(", ")})`);
  return report;
}
