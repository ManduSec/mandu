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
 * The arbiter runs the filters and the policy (`filterPrompt`); the proxy
 * applies its answer (prompt-filter-core.ts, shared with the Claude proxy): a `rewrite` replaces the segment's text; a `block`
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

import type { Arbiter, PromptSegmentOrigin } from "./arbiter-client.js";
import { filterSegments, type Piece, type PromptFilterOptions, type PromptFilterReport, type Segmentation, type SlotPieces, type TextSlot } from "./prompt-filter-core.js";
import { advertisedTools, isMessageItem, type ResponsesRequest } from "./responses-types.js";

// The protocol-neutral half (the arbiter's answer applied, the ledgers, the
// hold wait) is prompt-filter-core.ts, shared with the Claude proxy.
export {
  blockKeys, clientGone, lastHumanSegment, PromptBlocked, PromptBlockLedger, PromptEventLedger, PromptFilterRefusal,
  PromptHoldAbandoned, textHash, waitOutHolds, type HoldWait, type Piece, type PromptFilterReport,
} from "./prompt-filter-core.js";

/** Whose segmenter rules apply. */
export type SegmentAgent = "codex" | "generic";

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

/** The user texts of one request, in order, with their pieces. */
export function segmentRequest(req: ResponsesRequest, agent: SegmentAgent): Segmentation {
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

/**
 * Run the prompt filter over `req` (mutated in place): segment, ask the
 * arbiter, apply the answer (prompt-filter-core.ts). Null when there is
 * nothing to filter or the arbiter is an in-test mock without the op. Throws
 * PromptFilterRefusal on any failure (fail-closed). A side call's changed
 * text carries no note here (the Claude proxy appends one).
 */
export async function applyPromptFilter(
  req: ResponsesRequest,
  arbiter: Arbiter,
  opts: Omit<PromptFilterOptions, "agent" | "sideCallNote"> & { agent: SegmentAgent },
): Promise<PromptFilterReport | null> {
  if (!arbiter.filterPrompt) return null;
  return filterSegments(segmentRequest(req, opts.agent), arbiter, opts);
}
