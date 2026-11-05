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
 * The arbiter runs the filters and the policy (`filterPrompt`); the proxy
 * only APPLIES its answer (prompt-filter-core.ts, shared with the Codex
 * proxy): a `rewrite` replaces the segment's text, a side call's rewritten text keeps the note it always carried; a `block` (phase 2)
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

import type { Arbiter, PromptSegmentOrigin } from "./arbiter-client.js";
import { filterSegments, type Piece, type PromptFilterOptions, type PromptFilterReport, type Segmentation, type SlotPieces, type TextSlot } from "./prompt-filter-core.js";
import type { Message, MessagesRequest } from "./messages-types.js";
import { isToolResultBlock } from "./messages-types.js";

// The protocol-neutral half (the arbiter's answer applied, the ledgers, the
// hold wait) is prompt-filter-core.ts, shared with the Codex proxy.
export {
  blockKeys, clientGone, lastHumanSegment, PromptBlocked, PromptBlockLedger, PromptEventLedger, PromptFilterRefusal,
  PromptHoldAbandoned, textHash, waitOutHolds, type HoldWait, type Piece, type PromptFilterReport,
} from "./prompt-filter-core.js";

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

/** The user texts of one request, in order, with their pieces. */
export function segmentRequest(req: MessagesRequest, agent: SegmentAgent): Segmentation {
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

/**
 * Run the prompt filter over `req` (mutated in place): segment, ask the
 * arbiter, apply the answer (prompt-filter-core.ts). Returns null when there
 * is nothing to filter or the arbiter is an in-test mock without the op.
 * Throws PromptFilterRefusal on any failure (fail-closed). A side call's
 * changed text keeps the note it always carried.
 */
export async function applyPromptFilter(
  req: MessagesRequest,
  arbiter: Arbiter,
  opts: Omit<PromptFilterOptions, "agent" | "sideCallNote"> & { agent: SegmentAgent },
): Promise<PromptFilterReport | null> {
  if (!arbiter.filterPrompt) return null;
  return filterSegments(segmentRequest(req, opts.agent), arbiter, { ...opts, sideCallNote: SIDE_CALL_SECRET_NOTE });
}
