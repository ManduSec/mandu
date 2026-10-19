/**
 * rewrite-request — the security-critical agent→model request transform.
 *
 * Mandu Track A (interceptors/anthropic-proxy). This is the AgentView context
 * boundary (mandu.md §1, §3, plan §4): every tool_result re-entering T-LLM's
 * context is classified by the arbiter's data-trust policy and, when UNTRUSTED,
 * REPLACED by an opaque $MDU:* token before the request is forwarded
 * upstream. The handling system prompt is injected so T-LLM treats symbols as
 * opaque.
 *
 * Steps (mirror the build spec):
 *   1. Caller has already JSON.parsed the body into a MessagesRequest.
 *   2. Build a correlation map tool_use_id → {name, input} from tool_use blocks
 *      in prior assistant messages of THIS request.
 *   3. For every tool_result block: look up its originating {name, input};
 *      classify(boundary="model_context"); if UNTRUSTED, symbolize and replace
 *      the content with the symbol token. The classify request also carries the
 *      MEASURED exact-match fact (buildTrustedContextHaystack below) so the
 *      arbiter's §4 rung-1 upgrade can fire — decision arbiter-side, always.
 *      One refinement: when the ONLY thing
 *      keeping a result untrusted is a trailing <system-reminder> block the
 *      agent runtime appended to the tool's own output, the reminder tail is
 *      split off and both spans get their OWN arbiter verdict — a TRUSTED body
 *      passes raw; the tail passes raw only as the harness token-budget
 *      reminder shape, else it is symbolized alone under "system_reminder"
 *      (splitTrailingSystemReminders; fixes the inspect-envelope double-wrap
 *      and the decoy-symbol confusion without weakening the gate).
 *   4. Inject the handling system prompt (append a system block — the native
 *      system prefix stays intact, agent-sign-in.md §1.2 F8).
 *
 * FAIL-CLOSED (critical, mandu.md invariant / CONTRIBUTING.md): if the arbiter is
 * unreachable, or classify/symbolize/handlingPrompt throws, we MUST NOT forward
 * un-symbolized untrusted content. The rewrite REJECTS (throws RewriteRefusal),
 * and the server turns that into a 5xx — never a passthrough. We never silently
 * downgrade to "forward as-is".
 */

import { createHash } from "node:crypto";
import { AFTER_THE_FACT_MARKER, AFTER_THE_FACT_SYSTEM_NOTE, afterTheFactLine, type ClearResultLedger } from "./after-the-fact.js";
import { buildTwinNote, findTwinsDetailed, twinNoteSummary, type TwinHint } from "./twin-note.js";
import { CLAUDE_CODE_GATE_SURFACE, type GateSurface } from "./gate-surface.js";
import { unwrapDispatch } from "./dispatch.js";
import { commandLikeText, stricterLevel } from "./unmapped-exec.js";
import { gateNoticeResult } from "./exec-gate.js";
import { applyPromptFilter, PromptBlocked, PromptFilterRefusal, PromptHoldAbandoned, segmentAgentFor, type PromptBlockLedger, type PromptFilterReport } from "./prompt-filter.js";
import { ALL_NOTICE_KINDS, extractBackgroundNotices, movedOutputPath, noticeTexts, restoreBackgroundNotices, type ExtractedNotices, type NoticeKind } from "./opencode-background.js";
import { isOpenclawSurface, type ForwardedResultMemory } from "./openclaw-redaction.js";
// The !292 side-call note moved with its scan into the prompt filter (plan 15 §3.1).
export { SIDE_CALL_SECRET_NOTE } from "./prompt-filter.js";
import type {
  Arbiter,
  ClassifyResult,
  HandlingPromptCapabilities,
  CallTaintWire,
  AgentReceiptTaintWire,
  McpServerTaintWire,
  DocumentTextAnswer,
} from "./arbiter-client.js";
import {
  type MessagesRequest,
  type Message,
  type ContentBlock,
  type ToolResultBlock,
  type ToolResultContentBlock,
  type SystemBlock,
  isToolUseBlock,
  isToolResultBlock,
} from "./messages-types.js";

/** A correlated originating tool call for a tool_result. */
interface ToolCallRef {
  name: string;
  input: Record<string, unknown>;
}

/**
 * Thrown when the rewrite cannot complete safely (arbiter error / unreachable).
 * The server maps this to a 5xx so untrusted bytes never leak upstream.
 */
export class RewriteRefusal extends Error {
  constructor(
    message: string,
    /** The underlying cause, for logging. */
    public readonly cause?: unknown,
  ) {
    super(message);
    this.name = "RewriteRefusal";
  }
}

/**
 * The prompt filter's policy BLOCKS this request (confidentiality-plan-15 §7):
 * a RewriteRefusal (anything that catches that still refuses), which the
 * server answers with a 400 carrying `message`, the arbiter's reason (the
 * categories found, never a value), so the agent shows it and does not
 * retry. `report` feeds the `prompt_filter` events.
 */
export class RewriteBlocked extends RewriteRefusal {
  constructor(message: string, public readonly report: PromptFilterReport) {
    super(message);
    this.name = "RewriteBlocked";
  }
}

/**
 * The agent disconnected while its prompt was held for the human's answer
 * (confidentiality-plan-15 §13.6 item 13): a RewriteRefusal (anything that
 * catches that still refuses), which the server answers with nothing, since
 * nobody is there to read it. Nothing of the request was forwarded.
 */
export class RewriteAbandoned extends RewriteRefusal {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "RewriteAbandoned";
  }
}

export interface RewriteOptions {
  /** Arbiter handle (real adapter or mock). */
  arbiter: Arbiter;
  /** Confidentiality plan 15 §7: the blocked prompt spans this proxy
   *  already refused once (absent: every block refuses). */
  promptBlockLedger?: PromptBlockLedger;
  /** The agent's connection (plan 15 §13.6 item 13): aborted when it closes,
   *  which ends a prompt hold's wait (RewriteAbandoned, nothing forwarded). */
  signal?: AbortSignal;
  /** A token count (count_tokens): a blocked prompt segment is counted
   *  with its safe text and never refused (nothing reaches a model). */
  promptCountOnly?: boolean;
  /**
   * Translate an origin from the AGENT's spelling into HumanView (Plan 9).
   *
   * The agent executes the AgentView twin, so the `tool_use` args it echoes back
   * — which is where `originFor()` reads the origin — carry the AGENTVIEW path.
   * Every path policy the arbiter owns is keyed in HumanView (the catalog says
   * `~/.ssh`; the human labels `~/contracts`; a derived label is minted on the
   * path the MODEL asked to write). Without this the two never meet, and a
   * LABELED file classifies `public` — the label is written and never read.
   *
   * Passed to the arbiter as `originHuman`, which ONLY the confidentiality
   * derivation consumes: trust keeps seeing `origin`/`params` byte-identically,
   * so a spelling translation can never move a datum UNTRUSTED → TRUSTED.
   *
   * Absent (no view map) ⇒ nothing is added to any request — byte-identical.
   */
  toHumanView?: (origin: string) => string;
  /** The AgentView roots of the view map (symbol-twin-shell-blindness.md
   *  §4.1). When present, an UNTRUSTED Bash/BashOutput result whose command
   *  named a path under a root whose twin consists solely of symbol tokens
   *  gets the `[mandu:twin]` note appended OUTSIDE its symbolized span, and
   *  the handling prompt reports `fsView: true`. Absent ⇒ byte-identical. */
  agentViewRoots?: readonly string[];
  /** Per-proxy memory of the exec box's twin hints BY tool_use id
   *  (symbol-twin-shell-blindness.md §4.1 v2). Every later request re-sends
   *  the same tool_result in history and re-runs this rewrite, so the answer
   *  the arbiter gave the FIRST time (right after the command ran) is what
   *  keeps the note byte-stable across turns; without the cache a hint that
   *  aged out of the arbiter's window would make the note vanish from history.
   *  Absent ⇒ hints are asked for on every request (tests) — the note is then
   *  stable only as long as the arbiter still answers. */
  twinHintCache?: Map<string, TwinHint[]>;
  /** The exec gate's block notices this proxy delivered, by tool_use id
   *  (exec-gate.ts ExecGateNotices; confidentiality plan 10 §11.8). A result
   *  that is EXACTLY its call's notice is forwarded as that notice, in clear.
   *  Absent ⇒ every result is classified (byte-identical to before). */
  execGateNotices?: { noticeFor(callId: string): string | undefined };
  /** The notices that replace a call's result, by tool_use id
   *  (path-denial-notice.ts ResultNotices; confidentiality plan 10 §11.8): a
   *  call whose every path Mandu denied, a network call the net gate blocked,
   *  a call Mandu refused whole. Such a result is REPLACED by its notice: no
   *  byte of the tool's output is forwarded.
   *  Absent ⇒ every result is classified (byte-identical to before). */
  resultNotices?: { noticeFor(callId: string): string | undefined };
  /** The tool_use ids whose result body this proxy forwarded in clear
   *  (after-the-fact.ts; confidentiality.md §7.1, "Masked after the fact").
   *  A result masked as a secret now whose id is here gets the `masked after
   *  the fact` note; the ids this rewrite forwards in clear are added once it
   *  completes (and recorded with the arbiter, which `prime` asks first, so
   *  a history resumed under a new launch gets its note too). Absent ⇒ no
   *  note, nothing remembered (byte-identical). */
  clearResults?: Pick<ClearResultLedger, "wasClear" | "remember"> & Partial<Pick<ClearResultLedger, "prime">>;
  /** What this proxy forwarded in clear, by tool_use id, to put back where
   *  OpenClaw's own history redaction rewrote it (openclaw-redaction.ts;
   *  confidentiality.md §6). Used for an OpenClaw session only; texts this
   *  rewrite forwards unchanged are added once it completes (and, with
   *  `flush`, their placeholder records sent to the arbiter, which `prime`
   *  asks first, so a relaunch that resumes the conversation restores them
   *  too). Absent ⇒ nothing restored (byte-identical). */
  forwardedResults?: Pick<ForwardedResultMemory, "restore" | "remember"> & Partial<Pick<ForwardedResultMemory, "prime" | "flush">>;
  /** Optional proxy logger for non-fatal, utility-only notices (hint asks). */
  log?: (msg: string) => void;
  /** The session agent's gate surface (gate-surface.ts): which tools are the
   *  shell (callTaint, the twin note, the exec capability) and where their
   *  command / path / URL fields are. Absent ⇒ Claude Code's. */
  surface?: GateSurface;
  /** The directory the session's agent resolves a relative path in a typed
   *  path field against (proxy.ts relativeBaseFor: the launcher's
   *  MANDU_AGENT_CWD, for a surface with `relativeBase: "launch"`). Sent on
   *  the classify of a result of a tool that surface lists in `paths`, so the
   *  human's label on the file decides a relative read of it
   *  (confidentiality.md §6). Absent ⇒ never sent (byte-identical). */
  relativeBase?: string;
  /** Optional session key threaded into symbolize/recordToolCall — and into
   * classify, where it keys SESSION-KEYED spec resolution on a mixed-agent
   * arbiter (agent-e2e-harness.md §7.1; absent/unbound falls back to the
   * arbiter's process-global boot spec). */
  sessionKey?: string;
  /** Optional handling-prompt mode. */
  handlingMode?: string;
  /** The session's secret posture (src/secret-posture.ts), reported to the
   *  arbiter as `capabilities.secretPosture` so the handling prompt explains
   *  a `read-blocked` session (docs/design/agents/handling-prompt.md §2). Absent ⇒
   *  nothing reported: byte-identical. */
  secretPosture?: string;
  /** If true, skip the handling-prompt injection (e.g. already injected). */
  skipPromptInjection?: boolean;
}

/**
 * Per-tool_result audit record (for logging, the §9 oracle, and event emission).
 * Carries enough to build the observability events WITHOUT re-deriving anything:
 * the raw `value` (original untrusted bytes), the `origin` hint, the policy
 * `reason`, and the minted `symbol`.
 *
 * SECURITY: `value` is the RAW untrusted content. It is consumed ONLY on the
 * privileged side (logging + arbiter event emission); it MUST NOT be written back
 * into the forwarded request. The forwarded request carries the `symbol` only.
 */
export interface RewriteAudit {
  toolUseId: string;
  tool: string;
  trust: "TRUSTED" | "UNTRUSTED";
  symbolized: boolean;
  symbol?: string;
  /** The raw flattened tool_result content (original untrusted bytes). */
  value: string;
  /** Correlated origin hint (file_path / url / command …), if any. */
  origin?: string;
  /** Arbiter classify reason. */
  reason?: string;
  /** Partial symbolization (a trailing <system-reminder> tail split off a
   *  TRUSTED body): the exact original bytes `symbol` replaced. Absent → the
   *  whole `value` was replaced. The §9 oracle and the symbolize event must
   *  use THIS as the must-not-survive span — the body survives BY DESIGN. */
  symbolizedSpan?: string;
  /** The value stored behind `symbol` when it is NOT the wire span — a Read's
   *  un-rendered file bytes (unrenderReadResult). The §9 oracle checks BOTH
   *  this and the wire span; the symbolize event shows this one, because it is
   *  what every later resolve of the symbol yields. */
  symbolValue?: string;
  /** A complete trailing `<system-reminder>` tail the arbiter did not vouch
   *  for, cut off an untrusted body: it is neither forwarded nor part of the
   *  symbol's value (it must not reach a write-back). Audit only. */
  droppedTail?: string;
  /** The TRUSTED piece a split result forwards verbatim beside its symbol
   *  (the vouched body, the kept reminder tail, codex's exec or MCP header).
   *  The §9 own-block check removes it before looking for the raw span: a
   *  short span that also occurs in it (a "9" in "Wall time: 0.9 seconds")
   *  is coincidence, not survival (events.ts survivingResult). */
  keptVerbatim?: string;
  /** What the forwarded request carries for this tool_result after the rewrite
   *  (body + symbol in the split case). Absent → `symbol` (whole-result
   *  symbolization) or `value` (trusted passthrough). */
  forwardedText?: string;
  /** Confidentiality level the classify verdict carried (confidentiality.md
   *  §2). Present only when the datum is secret-labeled — the reason a
   *  TRUSTED result can still be symbolized. */
  confidentiality?: string;
  /** The `[mandu:twin]` note appended after the forwarded body (design
   *  symbol-twin-shell-blindness.md §4.3/§4.4): proxy-authored, never
   *  re-classified, never matched out of the result bytes. Present only when
   *  the command named at least one symbolic AgentView twin. `forwardedText`
   *  already includes it. */
  twinNote?: string;
  /** Plan 10 §4.2: the process-tree taint behind this call, when any. */
  secretTaint?: SecretTaintInfo;
  /** backstop-value-only.md: the result went as the arbiter's value-only
   *  release; each replaced registered value and the symbol that stands for
   *  it. The values are the §9 oracle's must-not-survive spans (the rest of
   *  the result survives by design), and each gets a symbolize event. */
  valueOnly?: Array<{ symbol: string; value: string }>;
  /** The `[mandu:secret]` note appended after the forwarded body (§11.8). */
  secretNote?: string;
  /** The note carries the `masked after the fact` line (confidentiality.md
   *  §7.1): the request then also carries Mandu's system note. */
  afterTheFact?: boolean;
  /** The note's summary for the tool_result event (paths + token count;
   *  `hinted` = how many paths only the exec box's leaf hint surfaced). */
  twinNoteInfo?: { paths: string[]; tokens: number; hinted?: number; more?: number; dirs?: number };
}

export interface RewriteResult {
  /** The rewritten request, safe to forward upstream. */
  request: MessagesRequest;
  /** Per-tool_result audit records (for logging / the oracle / events). */
  rewrites: RewriteAudit[];
  /** What the prompt filter did to the user-role text (confidentiality-plan-15
   *  §3, the `prompt_filter` events); absent when it had nothing to filter. */
  promptFilter?: PromptFilterReport;
}

/**
 * Extract the origin hint for a tool call from its input. Claude Code tools
 * carry the relevant locator in a well-known param; we map the canonical tools.
 * Unknown tools → undefined (the arbiter fails closed → UNTRUSTED → symbolize).
 */
/** The tool names originFor's canonical switch handles (Claude Code's). */
const CLAUDE_ORIGIN_TOOLS: ReadonlySet<string> = new Set([
  "WebFetch", "WebSearch", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep", "Bash",
]);

export function originFor(name: string, input: Record<string, unknown>, surface?: GateSurface): string | undefined {
  const s = (k: string): string | undefined =>
    typeof input[k] === "string" ? (input[k] as string) : undefined;
  // Another agent's names (gate-surface.ts): its shell command, its first
  // path field, its network destination (else the bytes that go there). A
  // Claude Code tool name always takes the canonical switch below, whatever
  // the surface (the union fallback names Claude Code's tools too).
  if (surface && surface.spec !== "claude-code" && !CLAUDE_ORIGIN_TOOLS.has(name)) {
    const own = (o: object): boolean => Object.prototype.hasOwnProperty.call(o, name);
    if (own(surface.exec)) return s(surface.exec[name]!);
    if (own(surface.paths)) {
      for (const f of surface.paths[name]!.fields) if (s(f) !== undefined) return s(f);
      return undefined;
    }
    if (own(surface.net)) {
      const n = surface.net[name]!;
      return (n.destination !== null ? s(n.destination) : undefined) ?? s(n.symbols);
    }
  }
  switch (name) {
    case "WebFetch":
    case "WebSearch":
      return s("url") ?? s("query");
    case "Read":
    case "Write":
    case "Edit":
    case "MultiEdit":
    case "NotebookEdit":
      return s("file_path") ?? s("notebook_path") ?? s("path");
    case "Glob":
    case "Grep":
      return s("path");
    case "Bash":
      return s("command");
    default:
      // MCP tools (mcp__server__tool) and anything else: try common keys.
      return s("url") ?? s("file_path") ?? s("path") ?? undefined;
  }
}

/**
 * Build the correlation map tool_use_id → {name, input} from tool_use blocks
 * in the assistant messages of this request.
 */
export function buildCorrelationMap(messages: Message[]): Map<string, ToolCallRef> {
  const map = new Map<string, ToolCallRef>();
  for (const msg of messages) {
    if (msg.role !== "assistant") continue;
    if (!Array.isArray(msg.content)) continue;
    for (const block of msg.content) {
      if (isToolUseBlock(block)) {
        const input =
          block.input && typeof block.input === "object"
            ? (block.input as Record<string, unknown>)
            : {};
        map.set(block.id, { name: block.name, input });
      }
    }
  }
  return map;
}

/** Flatten a tool_result `content` (string or block array) into one string. */
export function flattenToolResultContent(content: ToolResultBlock["content"]): string {
  if (content == null) return "";
  if (typeof content === "string") return content;
  // Array of nested blocks: concatenate the text blocks. Non-text blocks (images,
  // etc.) carry no text and are NOT represented here — see hasNonTextBlock, which
  // forces such results UNTRUSTED so their bytes are symbolized, never passed raw.
  return content
    .map((b) => (b && typeof b === "object" && typeof b.text === "string" ? b.text : ""))
    .join("");
}

/**
 * Concatenate the text of every tool_result block in `req` — the UNTRUSTED spans.
 * The §9 oracle (`survivingUntrusted`) checks THIS forwarded (post-symbolization)
 * tool_result text, NOT the whole prompt: after symbolization these blocks are
 * `$MDU:*` tokens, so a raw untrusted value that ALSO appears in TRUSTED
 * content (the user prompt, or the agent's own command/argv) does not false-positive,
 * while a tool_result whose raw bytes survived symbolization still does. Untrusted
 * data only ever ENTERS via tool_results, so scoping the check here loses no real
 * leak — it just stops counting coincidental matches in agent/user-authored text.
 */
export function forwardedToolResultText(req: MessagesRequest): string {
  const parts: string[] = [];
  for (const msg of req.messages ?? []) {
    if (!Array.isArray(msg.content)) continue;
    for (const block of msg.content) {
      if (isToolResultBlock(block)) parts.push(flattenToolResultContent((block as ToolResultBlock).content));
    }
  }
  // OpenCode 2's background notices are tool output carried as user text
  // (opencode-background.ts): the oracle reads them as tool results too.
  parts.push(...noticeTexts(req.messages ?? []));
  return parts.join("\n");
}

/** Which program-output texts each session's user messages may hold
 *  (opencode-background.ts): OpenCode 2's background and user-shell notices
 *  in an OpenCode session, Claude Code's bash-mode output in a Claude Code
 *  one, and all of them in a session with no table of its own (the union),
 *  where the agent may be either. */
const BACKGROUND_NOTICE_SPECS: ReadonlyMap<string, ReadonlySet<NoticeKind>> = new Map<string, ReadonlySet<NoticeKind>>([
  ["opencode", new Set<NoticeKind>(["shell", "subagent", "usershell"])],
  ["claude-code", new Set<NoticeKind>(["bashmode"])],
  ["union", ALL_NOTICE_KINDS],
  ["fail-closed", ALL_NOTICE_KINDS],
]);

/**
 * Split complete trailing `<system-reminder>…</system-reminder>` blocks off a
 * flattened tool_result. Claude Code APPENDS such blocks to a tool's own output
 * (plan-mode transitions, contextual reminders), which drags an otherwise
 * TRUSTED-shaped body into whole-result symbolization — the live double-wrap:
 * the inspect tool's pure-symbolic envelope failed the shape gate only because
 * of an appended "Exited Plan Mode" reminder, so T-LLM got an opaque wrapper
 * symbol instead of the result_symbol it was meant to see.
 *
 * Returns `{ body, tail }` with `value === body + tail`, where `tail` is one or
 * more complete reminder blocks (plus surrounding whitespace) and `body` is
 * non-empty. Returns null when there is no trailing reminder, or the value is
 * ONLY reminders (nothing left to vouch for → fail-closed whole-result path).
 *
 * SECURITY: this function grants no trust. The caller re-classifies the body
 * with the arbiter and forwards it raw ONLY on a TRUSTED verdict; the tail is
 * ALWAYS symbolized (a tool could forge `<system-reminder>` text — it stays
 * opaque either way). Loop-based (lastIndexOf), not a single regex: an anchored
 * `(<system-reminder>[\s\S]*?</system-reminder>)+$` backtracks quadratically on
 * adversarial input.
 */
export function splitTrailingSystemReminders(
  value: string,
): { body: string; tail: string } | null {
  const OPEN = "<system-reminder>";
  const CLOSE = "</system-reminder>";
  let end = value.length;
  // Strip one complete trailing block per iteration.
  for (;;) {
    let i = end;
    while (i > 0 && /\s/.test(value[i - 1]!)) i--;
    if (i < CLOSE.length || !value.startsWith(CLOSE, i - CLOSE.length)) break;
    const open = value.lastIndexOf(OPEN, i - CLOSE.length);
    if (open < 0) break;
    end = open;
  }
  if (end === value.length) return null;
  const body = value.slice(0, end);
  if (body.trim() === "") return null;
  return { body, tail: value.slice(end) };
}

/**
 * Undo Claude Code's Read RENDERING: `<line no><sep><line>` per line (sep = tab,
 * `:` under the tab-aware form, `→` on older builds) → the file's own bytes.
 *
 * WHY (docs/design/integrity/read-result-rendering.md; live drills U17/U22): a symbol's
 * value is what a write-back resolves to. Symbolizing the rendering meant a
 * model that copied a file by its symbol wrote `1<TAB>…` gutters and a stray
 * `2` row into the user's file, and renamed source files stopped parsing. The
 * bytes a Read symbol stands for must be the FILE's bytes.
 *
 * SECURITY: this grants no trust and forwards nothing — it only chooses the
 * value stored behind a symbol that is minted either way. It is strict: every
 * line must carry a gutter and the numbers must run consecutively; anything
 * else (a truncation header, a notice, a forged shape) returns null and the
 * caller symbolizes the wire bytes exactly as before. A trailing number-only
 * row is the harness's rendering of the empty line after a final newline (its
 * separator is trimmed when a reminder follows) and restores that newline.
 */
export function unrenderReadResult(text: string): string | null {
  if (text === "") return null;
  const lines = text.split("\n");
  const out: string[] = [];
  let expected: number | null = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const m = /^[ ]{0,8}(\d{1,9})(?:[\t:\u2192]([\s\S]*))?$/.exec(line);
    if (!m) return null;
    const n = Number(m[1]);
    if (expected !== null && n !== expected) return null;
    expected = n + 1;
    // A bare number is only ever the LAST row (the separator-trimmed empty line).
    if (m[2] === undefined && i !== lines.length - 1) return null;
    out.push(m[2] ?? "");
  }
  return out.join("\n");
}

/** The trailer OpenCode's `read` closes its content with. MIRROR of
 *  arbiter/policy/opencode-inbound.ts OPENCODE_READ_TRAILER_RE (this package
 *  never imports the arbiter; tests/stack/opencode-read-value.test.ts pins
 *  the two parsers to one answer): digits and fixed words only. */
const OPENCODE_READ_TRAILER_RE =
  /^\((?:End of file - total \d{1,12} lines|Showing lines \d{1,12}-\d{1,12} of \d{1,12}\. Use offset=\d{1,12} to continue\.)\)$/;

/**
 * Undo OpenCode's `read` RENDERING → the text of the lines it carries
 * (confidentiality-plan-10 §11.16; read-result-rendering.md §3.1). The
 * rendering is EXACTLY
 *
 *   <path>{abs path}</path>
 *   <type>file</type>
 *   <content>
 *   {n}: {line}          (consecutive numbers from the offset)
 *   …
 *
 *   (End of file - total N lines)      or  (Showing lines A-B of C. Use offset=K to continue.)
 *   </content>
 *
 * WHY (live OpenCode drill, 2026-10-05): a secret-labelled read is masked
 * whole and the symbol's value is registered as a secret, line by line
 * (MIN_LINE_FINGERPRINT_LEN). With the rendering stored, OpenCode's own
 * trailer `(End of file - total 1 lines)` became a registered line of a
 * no-model secret, and every later read of ANY one-line file through the same
 * arbiter was masked no-model (the drill's unlabelled control among them).
 * The value is also what an egress or a write-back resolves the symbol to,
 * which must be the file's text, not OpenCode's frame (the Claude Code
 * precedent: unrenderReadResult).
 *
 * SECURITY: this grants no trust and forwards nothing; it only chooses the
 * value stored behind a symbol that is minted either way. Every line of the
 * file stays a registered line (each wire line is `n: ` + that line, so the
 * file's line is a substring of it). It is strict, the arbiter's grammar to
 * the byte: the `<path>` must be absolute and one the call itself named;
 * anything else (a capped read, a trailing `<system-reminder>`, a gap in the
 * numbering, a directory listing) returns null and the caller stores the wire
 * bytes exactly as before (fail-closed: over-masking, never under). The text
 * has no final newline: the rendering does not say whether the file ended
 * with one. Pure; never throws.
 */
export function unrenderOpencodeReadResult(value: string, paths: readonly string[]): string | null {
  if (typeof value !== "string") return null;
  if (value.startsWith("Read file ")) return unrenderOpencode2ReadFrame(value, paths);
  const lines = value.replace(/\s+$/, "").split("\n");
  if (lines.length < 6 || lines.length > 4000) return null;
  const head = /^<path>(.*)<\/path>$/.exec(lines[0]!);
  if (!head || !head[1]!.startsWith("/") || !paths.includes(head[1]!)) return null;
  if (lines[1] !== "<type>file</type>" || lines[2] !== "<content>") return null;
  if (lines[lines.length - 1] !== "</content>") return null;
  if (!OPENCODE_READ_TRAILER_RE.test(lines[lines.length - 2]!)) return null;
  if (lines[lines.length - 3] !== "") return null;
  const body = lines.slice(3, lines.length - 3);
  if (body.length === 0) return null;
  const out: string[] = [];
  let expect: number | null = null;
  for (const line of body) {
    const m = /^(\d{1,9}): ([\s\S]*)$/.exec(line);
    if (!m) return null;
    const n = Number(m[1]);
    if (expect !== null && n !== expect) return null;
    expect = n + 1;
    out.push(m[2]!);
  }
  return out.join("\n");
}

/** OpenCode 2's marker on a line it cut at 2000 characters (2.0.23). MIRROR
 *  of arbiter/policy/opencode-inbound.ts OPENCODE2_LINE_CUT. */
const OPENCODE2_LINE_CUT = "... (line truncated to 2000 chars)";

/**
 * Undo OpenCode 2's `read` FRAME → the text of the lines it carries (2.0.23,
 * captured in arbiter/test/fixtures/opencode2-tool-surface-2026-10-05.json;
 * supported-agents.md §2.3). MIRROR of the arbiter's opencode2ReadFrameText
 * (tests/stack/opencode-read-value.test.ts pins the two to one answer). The
 * frame is EXACTLY
 *
 *   Read file {the path as the call named it}, lines {A}-{B}
 *   {A}: {line}
 *   …
 *   {B}: {line}
 *
 * with no trailer: OpenCode 1's trailer problem (above) becomes the header
 * here, which would otherwise be stored as a registered line of the secret.
 * The header must name a path the call itself named. A cut read (`[Output
 * truncated. …]`), a cut line, an empty file (`…, 0 lines`), a directory
 * (`Read directory …`), an error envelope or any line count other than
 * B-A+1 returns null: the wire bytes are stored, as before (over-masking,
 * never under). Pure; never throws.
 */
export function unrenderOpencode2ReadFrame(value: string, paths: readonly string[]): string | null {
  if (typeof value !== "string") return null;
  const nl = value.indexOf("\n");
  if (nl < 0) return null;
  const head = value.slice(0, nl);
  let range: RegExpExecArray | null = null;
  for (const p of paths) {
    const prefix = `Read file ${p}, lines `;
    if (p !== "" && head.startsWith(prefix)) {
      range = /^(\d{1,9})-(\d{1,9})$/.exec(head.slice(prefix.length));
      if (range) break;
    }
  }
  if (!range) return null;
  const a = Number(range[1]);
  const b = Number(range[2]);
  if (a < 1 || b < a) return null;
  const lines = value.slice(nl + 1).split("\n");
  if (lines.length !== b - a + 1 || lines.length > 4000) return null;
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\d{1,9}): ([\s\S]*)$/.exec(lines[i]!);
    if (!m || Number(m[1]) !== a + i) return null;
    if (m[2]!.endsWith(OPENCODE2_LINE_CUT)) return null;
    out.push(m[2]!);
  }
  return out.join("\n");
}

/** The size OpenClaw prints in a read notice. MIRROR of
 *  arbiter/policy/openclaw-inbound.ts OC_SIZE. */
const OC_SIZE = String.raw`\d{1,12}(?:\.\d)?(?:B|KB|MB)`;

/** The ONE continuation notice OpenClaw's `read` appends after the file text
 *  (2026.7.1 `sessions-*.js` / `openclaw-tools-*.js`, 2026.9.6
 *  `tools-*.mjs`): digits, a size and fixed words only. MIRROR of
 *  arbiter/policy/openclaw-inbound.ts OPENCLAW_READ_NOTICE_RE
 *  (tests/stack/openclaw-read-value.test.ts pins the two to one answer). */
const OPENCLAW_READ_NOTICE_RE = new RegExp(
  String.raw`\n\n\[(?:` +
    String.raw`\d{1,12} more lines? in file\. Use offset=\d{1,12} to continue\.` +
    String.raw`|Showing lines \d{1,12}-\d{1,12} of \d{1,12}(?: \(${OC_SIZE} limit\))?\. Use offset=\d{1,12} to continue\.` +
    String.raw`|Read output capped at ${OC_SIZE} for this call\. Use offset=\d{1,12}(?:, limit=\d{1,12})? to continue\.` +
    String.raw`)\]$`,
);

/**
 * Undo OpenClaw's `read` notice → the file text it carries
 * (confidentiality-plan-10 §11.16; the !730 OpenCode class). OpenClaw prints
 * the selected lines as they are, no gutter, and appends at most one
 * continuation notice (`[2 more lines in file. Use offset=3 to continue.]`).
 *
 * WHY: a secret-labelled read is masked whole and the symbol's value is
 * registered line by line (MIN_LINE_FINGERPRINT_LEN). With the notice
 * stored, `[2 more lines in file. Use offset=3 to continue.]` (49
 * characters) became a registered line of a no-model secret, and every later
 * OpenClaw read that stopped at the same place, of ANY file, was masked
 * no-model. The value is also what the symbol resolves to.
 *
 * SECURITY: grants no trust and forwards nothing; it only chooses the value
 * stored behind a symbol minted either way. Only a notice anchored at the end,
 * after a blank line, of exactly the source's words and digits is removed (no
 * file byte can be in it); anything else returns null and the caller stores
 * the wire bytes as before (fail-closed: over-masking, never under). Pure;
 * never throws. Same answer as the arbiter's openclawReadRenderingText
 * wherever a notice follows some text (a notice alone stores the wire).
 */
export function unrenderOpenclawReadResult(value: string): string | null {
  if (typeof value !== "string") return null;
  const v = value.replace(/\s+$/, "");
  const m = OPENCLAW_READ_NOTICE_RE.exec(v);
  if (!m || m.index === 0) return null;
  return v.slice(0, m.index);
}

/** What a symbol's value is un-rendered against: the session agent's spec
 *  (gate-surface.ts) and the path spellings the call named. */
interface SymbolValueContext {
  spec: string;
  paths: readonly string[];
}

/** The bytes to store behind a symbol minted for `wire` (a tool_result span):
 *  the file's bytes for a Claude Code Read, the text of the lines an OpenCode
 *  `read` carried (only under the opencode spec), an OpenClaw `read` less its
 *  continuation notice (only under an OpenClaw spec), else the wire bytes. */
function symbolValueFor(toolName: string, wire: string, ctx?: SymbolValueContext): string {
  if (toolName === "Read") return unrenderReadResult(wire) ?? wire;
  if (toolName === "read" && ctx?.spec === "opencode") return unrenderOpencodeReadResult(wire, ctx.paths) ?? wire;
  if (toolName === "read" && (ctx?.spec === "openclaw-agent" || ctx?.spec === "openclaw")) return unrenderOpenclawReadResult(wire) ?? wire;
  return wire;
}

/**
 * True iff `content` is a block array containing any non-text block (image, etc.).
 * A text block is `{ type: "text", text: string }`; anything else (an image, an
 * unknown block type, a malformed text block) is "non-text". Such bytes are never
 * vouched for by the text-only flatten, so a result containing one is forced
 * UNTRUSTED and symbolized — never forwarded raw (mandu.md §1 invariant).
 * A PDF `document` block is first replaced by its text when the arbiter can
 * read one (`pdfBlocksAsText`, secret-discovery.md §2.8), so only that text,
 * which the classify judges, ever reaches the model.
 */
export function hasNonTextBlock(content: ToolResultBlock["content"]): boolean {
  if (!Array.isArray(content)) return false;
  return content.some(
    (b) => !(b && typeof b === "object" && b.type === "text" && typeof b.text === "string"),
  );
}

/** A PDF `document` block carried inline (base64), as Claude Code's `Read`
 *  of a `.pdf` sends it. */
export function isPdfDocumentBlock(b: unknown): boolean {
  if (!b || typeof b !== "object" || (b as { type?: unknown }).type !== "document") return false;
  const src = (b as { source?: unknown }).source as { type?: unknown; media_type?: unknown; data?: unknown } | undefined;
  return !!src && src.type === "base64" && typeof src.media_type === "string" && src.media_type.toLowerCase() === "application/pdf" && typeof src.data === "string";
}

/** The arbiter's answers by the block's data and the path, for the requests
 *  that re-send the same history (each one re-reads every result): at most
 *  DOCUMENT_TEXT_CACHE_MAX, the oldest forgotten first. An answer only ever
 *  replaces the block with text the classify then judges, so a stale one
 *  can only cost the twin release (the result masked whole), never a value. */
const documentTextCache = new Map<string, DocumentTextAnswer>();
const DOCUMENT_TEXT_CACHE_MAX = 64;

/**
 * Secret-discovery.md §2.8, "A document block": `content` with each PDF
 * `document` block replaced by the text the arbiter reads in it
 * (`documentText`: a personal document's twin text, or the PDF's text
 * layer). Null, so the content stays as it is (and is masked whole), when
 * the content holds any other block that is not text (an image), or any PDF
 * has no text, or the arbiter cannot answer. A Claude Code `Read` becomes
 * ONE text block in the harness's rendering of a text file (`N\tline`),
 * its `PDF file read:` line dropped, so the read rules judge it as a Read
 * of a text file; another tool keeps its text blocks, each PDF in place.
 */
export async function pdfBlocksAsText(
  content: readonly ToolResultContentBlock[],
  arbiter: Arbiter,
  o: { origin?: string; sessionKey?: string; claudeRead: boolean; log?: (m: string) => void },
): Promise<ToolResultContentBlock[] | null> {
  if (!arbiter.documentText) return null;
  const out: ToolResultContentBlock[] = [];
  const texts: string[] = [];
  for (const b of content) {
    if (b && b.type === "text" && typeof b.text === "string") { out.push(b); continue; }
    if (!isPdfDocumentBlock(b)) return null;
    const src = (b as unknown as { source: { data: string; media_type: string } }).source;
    const key = `${o.origin ?? ""}\u0000${createHash("sha256").update(src.data).digest("hex")}`;
    let a = documentTextCache.get(key);
    if (a === undefined) {
      try {
        a = await arbiter.documentText({ data: src.data, mediaType: src.media_type, ...(o.origin ? { origin: o.origin } : {}), ...(o.sessionKey ? { sessionKey: o.sessionKey } : {}) });
      } catch (err) {
        o.log?.(`document block: the arbiter could not read it (${(err as Error).message}); the result is masked whole`);
        return null;
      }
      if (documentTextCache.size >= DOCUMENT_TEXT_CACHE_MAX) {
        const oldest = documentTextCache.keys().next().value;
        if (oldest !== undefined) documentTextCache.delete(oldest);
      }
      documentTextCache.set(key, a);
    }
    if (typeof a.text !== "string" || a.text === "") {
      o.log?.(`document block: no text (${a.reason}); the result is masked whole`);
      return null;
    }
    texts.push(a.text);
    out.push({ type: "text", text: a.text });
  }
  if (!o.claudeRead) return out;
  const lines = texts.join("\n\n").replace(/\n+$/, "").split("\n");
  return [{ type: "text", text: lines.map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") }];
}

/**
 * Serialize a tool_result content for symbolization/audit when it carries non-text
 * blocks. JSON of the block array preserves the original bytes (image base64, etc.)
 * in the arbiter symbol table so nothing rides through raw and HumanView can restore
 * the original. String content is returned verbatim.
 */
function serializeToolResultContent(content: ToolResultBlock["content"]): string {
  if (content == null) return "";
  if (typeof content === "string") return content;
  return JSON.stringify(content);
}

/**
 * The handling system prompt block injected so T-LLM knows symbols are opaque.
 * The idempotency marker lives INSIDE the block text (a leading sentinel), NOT as
 * an extra JSON key: the Anthropic Messages API validates system blocks strictly
 * and rejects unknown keys ("400 system.N.<key>: Extra inputs are not permitted").
 * Mirrors the openai-proxy, which embeds the same marker in `instructions`.
 */
export const HANDLING_MARKER = "[mandu:handling-prompt]";

/**
 * Shell/exec tool names that mark the exec capability. Exact names (the
 * agent-visible tool set), not substrings — `Bash` is Claude Code's shell;
 * exec/exec_command/shell/local_shell cover the exec-wrap and codex shapes.
 */
const EXEC_TOOL_NAMES = new Set(["Bash", "exec", "exec_command", "shell", "local_shell"]);

/**
 * Any server's inspect_symbol, in every namespacing convention Mandu mounts
 * it under: bare `inspect_symbol` (OpenClaw's plugin tool — no MCP client, so
 * no namespace), `mcp__<server>__inspect_symbol` (Claude Code MCP), and
 * `<server>_inspect_symbol` (OpenCode MCP, a SINGLE underscore — read off the
 * wire, not from docs). Suffix-anchored so `inspect_symbolizer` does not match.
 *
 * This is CAPABILITY DETECTION over the request's own advertised `tools[]`, not
 * a trust decision: a miss silently strips the inspect guidance from the
 * injected handling prompt, so the model is never told the quarantine exists
 * and the whole U-LLM path goes dark. (That was the OpenCode symptom before the
 * single-underscore form was added.) The TRUST-bearing name set is the exact
 * one in arbiter/policy/inspect-tool.ts — deliberately tighter than this.
 */
const INSPECT_TOOL_RE = /(^|__|_)inspect_symbol$/;
/** The mandu-policy MCP server's tools (policy-surface.md §8.5.1): the
 *  Claude Code and OpenCode spellings. Distinct from POLICY_TOOL_RE (the
 *  legacy policy_list/add/del tools). */
const MANDU_POLICY_TOOL_RE = /^(mcp__mandu-policy__|mandu-policy_)/;

/** The Data-Trust-Policy mutation/list tools, bare or MCP-namespaced. */
const POLICY_TOOL_RE = /(^|__)(policy_list|policy_add|policy_del)$/;

/**
 * Does this exec tool's DECLARED input schema carry an `env` property — i.e.
 * is the handling prompt's `env: { RESTRICTED: "1" }` opt-in expressible on
 * this runtime? Absence must be PROVEN from a well-formed declared schema:
 * anything unreadable reports true, which on the arbiter side means "keep
 * today's full exec guidance" (the conservative direction — over-teaching
 * costs prompt tokens; under-detecting here must never change behavior).
 * Claude Code's Bash declares no `env` and its harness REJECTS the whole call
 * (`InputValidationError: An unexpected parameter \`env\` was provided`), so
 * for that shape we report false and the arbiter drops the trap guidance.
 */
function execToolDeclaresEnv(tool: unknown): boolean {
  if (!tool || typeof tool !== "object") return true;
  const schema = (tool as { input_schema?: unknown }).input_schema;
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) return true;
  const props = (schema as { properties?: unknown }).properties;
  if (!props || typeof props !== "object" || Array.isArray(props)) return true;
  return Object.prototype.hasOwnProperty.call(props, "env");
}

/**
 * Derive tool-battery capability FACTS from the request's `tools` array so the
 * arbiter can drop handling-prompt sections about tools this request cannot
 * call (a zero-tool side call gets the core prompt; a battery without
 * inspect_symbol gets no inspect/content_kind guidance).
 *
 * UTILITY HINT, NOT A TRUST GATE: matching is deliberately looser than the
 * arbiter's exact-match inbound-trust constant (MANDU_INSPECT_TOOL in
 * arbiter/policy/claude-code-inbound.ts) — over-matching costs prompt tokens,
 * never security; the arbiter defaults every UNREPORTED capability to present.
 * Never throws: malformed tool entries are skipped, a non-array reports all
 * false (no tools ⇒ the model cannot call any).
 */
export function detectCapabilities(
  tools: unknown,
  facts: {
    /** a ViewMap with an AgentView root is configured (the fs rung) */ fsView?: boolean;
    /** the session's secret posture (src/secret-posture.ts) */ secretPosture?: string;
  } = {},
  /** The session agent's shell tools (gate-surface.ts GateSurface.exec), in
   *  addition to the fixed EXEC_TOOL_NAMES — opencode's `bash` is lowercase. */
  execTools?: Readonly<Record<string, string>>,
): HandlingPromptCapabilities {
  const caps: HandlingPromptCapabilities = {
    inspect: false,
    policyTools: false,
    manduPolicy: false,
    exec: false,
    execEnv: false,
    // Not a tool fact: the proxy knows the file view from its view map. Gates
    // handling-prompt rule R9 (symbol-twin-shell-blindness.md §4.5).
    fsView: facts.fsView === true,
    // Not a tool fact either: the launcher's posture for this session. Only
    // when set, so a session without one reports exactly what it did before.
    ...(facts.secretPosture ? { secretPosture: facts.secretPosture } : {}),
  };
  if (!Array.isArray(tools)) return caps;
  for (const t of tools) {
    const name =
      t && typeof t === "object" && typeof (t as { name?: unknown }).name === "string"
        ? (t as { name: string }).name
        : undefined;
    if (!name) continue;
    if (INSPECT_TOOL_RE.test(name)) caps.inspect = true;
    else if (POLICY_TOOL_RE.test(name)) caps.policyTools = true;
    else if (MANDU_POLICY_TOOL_RE.test(name)) caps.manduPolicy = true;
    else if (EXEC_TOOL_NAMES.has(name) || (execTools !== undefined && Object.prototype.hasOwnProperty.call(execTools, name))) {
      caps.exec = true;
      // ANY exec tool that declares `env` (or whose schema we cannot read)
      // keeps the full guidance; false only when absence is proven for every
      // detected exec tool. With exec=false the arbiter never consults this.
      if (execToolDeclaresEnv(t)) caps.execEnv = true;
    }
  }
  return caps;
}

function makeSystemBlock(prompt: string): SystemBlock {
  return { type: "text", text: `${HANDLING_MARKER}\n${prompt}` } as SystemBlock;
}

function blockText(b: unknown): string {
  return b && typeof b === "object" && typeof (b as { text?: unknown }).text === "string"
    ? (b as { text: string }).text
    : "";
}

function alreadyInjected(system: MessagesRequest["system"]): boolean {
  return systemIncludes(system, HANDLING_MARKER);
}

function systemIncludes(system: MessagesRequest["system"], marker: string): boolean {
  if (typeof system === "string") return system.includes(marker);
  if (Array.isArray(system)) {
    return system.some((b) => blockText(b).includes(marker));
  }
  return false;
}

/**
 * A present, non-"public" confidentiality value means the datum is
 * secret-labeled (confidentiality.md §2). UNKNOWN strings count as secret —
 * fail-closed: a level minted by a newer arbiter must not pass raw here.
 * Absent means the arbiter's confidentiality axis is OFF or the datum is
 * public — either way, integrity alone governs (today's behavior).
 */
function isSecretLevel(level: string | undefined): boolean {
  return level !== undefined && level !== "" && level !== "public";
}

// ─────────────────────────────────────────────────────────────────────────────
// Trusted-context haystack — the MEASUREMENT half of the exec-output
// exact-match upgrade (exec-routing.md §8.4 rung 1; the DECISION half —
// tool gating, length floor, upgrade-only semantics — lives in the arbiter,
// claude-code-inbound.ts classifyExactContextEcho).
//
// SOUNDNESS INVARIANT: the haystack is EXACTLY the bytes of this request that
// are already forwarded raw to the model OUTSIDE tool_result bodies — system
// prompt, user/assistant text, and model-authored tool_use args. An upgrade
// keyed on this haystack can therefore never reveal a NEW byte: whatever
// matches was reaching the model anyway. What it cannot prove is trusted
// INFLUENCE — the selection channel (§4 caveat) is accepted and floored
// arbiter-side.
//
// Two exclusions carry the whole argument:
//   - tool_result bodies, ALWAYS — theirs are exactly the unclassified bytes
//     this walk exists to gate. Including any (even an already-rewritten one)
//     would let one attacker-controlled result vouch for another carrying the
//     same bytes.
//   - non-text blocks (images, documents) — no text channel to match against.
//
// TRIPWIRE (closed by confidentiality-plan-15 phase 1): user text is no longer
// always forwarded raw: the prompt filter replaces registered values in it with
// symbols. So the haystack is built from the request AFTER the prompt filter
// ran, and every symbol the filter put in is cut out (a NUL in its place): the
// spans the filter replaced are in the haystack neither as their original
// bytes (gone from the request) nor as the symbol that stands for them.
// ─────────────────────────────────────────────────────────────────────────────

/** Build the trusted-context haystack for one request. Blocks are joined with
 *  a NUL separator so a candidate span can never match ACROSS two blocks that
 *  are not contiguous on the real model wire. `cut`: the symbols the prompt
 *  filter replaced spans with, each removed (a NUL in its place). */
export function buildTrustedContextHaystack(req: MessagesRequest, cut: readonly string[] = []): string {
  const haystack = trustedContextParts(req).join("\u0000");
  if (cut.length === 0) return haystack;
  let out = haystack;
  for (const sym of [...new Set(cut)].sort((a, b) => b.length - a.length)) out = out.split(sym).join("\u0000");
  return out;
}

function trustedContextParts(req: MessagesRequest): string[] {
  const parts: string[] = [];
  if (typeof req.system === "string") {
    parts.push(req.system);
  } else if (Array.isArray(req.system)) {
    for (const b of req.system) if (typeof b?.text === "string") parts.push(b.text);
  }
  for (const msg of Array.isArray(req.messages) ? req.messages : []) {
    if (typeof msg.content === "string") {
      parts.push(msg.content);
      continue;
    }
    if (!Array.isArray(msg.content)) continue;
    for (const block of msg.content) {
      if (isToolResultBlock(block)) continue; // NEVER — see the invariant above
      if (isToolUseBlock(block)) {
        // Model-authored call args (the command string lives here). JSON
        // escaping means a literal containing quotes/newlines will not match
        // its escaped spelling — a conservative miss, never a false hit.
        try {
          parts.push(`${block.name} ${JSON.stringify(block.input ?? {})}`);
        } catch {
          /* unserializable input contributes nothing */
        }
        continue;
      }
      const text = (block as { text?: unknown }).text;
      if (typeof text === "string") parts.push(text);
    }
  }
  return parts;
}

/** Whole-span contiguous match, on the candidate with AT MOST ONE trailing
 *  newline removed (`echo` appends exactly one; the trusted literal carries
 *  none). KEEP IN SYNC with the arbiter's exactMatchCandidate
 *  (claude-code-inbound.ts) — both sides must measure the same bytes; a small
 *  twin rather than an import because the packages install independently. */
export function spanVerbatimInTrustedContext(haystack: string, value: string): boolean {
  const candidate = value.endsWith("\n") ? value.slice(0, -1) : value;
  return candidate.length > 0 && haystack.includes(candidate);
}

/**
 * Append the `[mandu:twin]` note (symbol-twin-shell-blindness.md §4) to an
 * UNTRUSTED, symbolized Bash/BashOutput result whose command named a symbolic
 * AgentView twin. Mutates `tr.content` (same string/block shape the branch
 * wrote) and the audit record (`forwardedText`, `twinNote`, `twinNoteInfo`).
 * The note is proxy-authored from the model's own command and the twin's
 * already-opaque tokens — never from the result bytes — and is appended
 * AFTER the symbolized span (and after a trusted budget tail, if any). Any
 * failure ⇒ no note; never throws.
 */
/** Bounded per-callId cache insert (oldest-first eviction). */
const TWIN_HINT_CACHE_CAP = 4096;
function rememberHints(cache: Map<string, TwinHint[]>, callId: string, hints: TwinHint[]): void {
  cache.delete(callId);
  cache.set(callId, hints);
  while (cache.size > TWIN_HINT_CACHE_CAP) {
    const oldest = cache.keys().next().value as string | undefined;
    if (oldest === undefined) break;
    cache.delete(oldest);
  }
}

/**
 * The exec box's leaf hints for this call (design §4.1 v2): cached per
 * tool_use id so the note stays byte-stable while the tool_result is re-sent
 * in history; otherwise one best-effort arbiter read, bounded so a slow
 * arbiter can never hold the request (utility-only: a miss is no hint).
 */
/** The cached shape: the hints plus the box's own "left out" count, carried
 *  on the array so the per-callId cache stays a `TwinHint[]`. */
type HintAnswer = TwinHint[] & { more?: number };

async function twinHintsFor(
  arbiter: Arbiter,
  callId: string,
  command: string,
  cache: Map<string, TwinHint[]> | undefined,
  log?: (msg: string) => void,
): Promise<HintAnswer> {
  const cached = cache?.get(callId);
  if (cached) return cached as HintAnswer;
  if (typeof arbiter.execTwinsFor !== "function") return [];
  const hints: HintAnswer = [];
  try {
    const answer = await Promise.race([
      arbiter.execTwinsFor(command),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`no answer within ${TWIN_HINT_DEADLINE_MS} ms`)), TWIN_HINT_DEADLINE_MS).unref?.()),
    ]);
    for (const t of Array.isArray(answer?.twins) ? answer.twins : []) {
      if (t && typeof t.asTyped === "string" && typeof t.abs === "string") hints.push(t);
    }
    if (typeof answer?.more === "number" && answer.more > 0) hints.more = Math.floor(answer.more);
  } catch (err) {
    // A failed or slow ask is NOT an answer: never cache it (the next re-send
    // of this tool_result asks again — a cached miss would silence the note
    // for this call for the proxy's lifetime; watch-20260918T203500 U6 lost
    // its note that way under arbiter contention). Utility-only: log, and
    // the note rests on the command parse this time.
    log?.(`twin hints unavailable for ${callId} (non-fatal, utility only): ${(err as Error).message}`);
    return [];
  }
  if (cache) rememberHints(cache, callId, hints);
  return hints;
}
/** The bound on one hint read. The arbiter answers from memory in µs; the
 *  bound only stops a wedged arbiter from holding the request, so it is
 *  generous — a slow answer under contention must still land (a miss is a
 *  lost note, and the classify/symbolize calls on the same path already
 *  wait on the same arbiter). */
const TWIN_HINT_DEADLINE_MS = 3000;

/** What plan 10's callTaint said about a call, reduced to what the rewrite needs. */
export interface SecretTaintInfo {
  level: string;
  files: string[];
  apps: string[];
  rule: "secret" | "clear" | "mask";
  /** The whole result becomes a secret datum at `level`. */
  maskWhole: boolean;
  /** Opens refused within the tree. */
  denied: Array<{ path: string; app: string; reason: string }>;
  /** The tree read NO secret, at least one open of one was refused, and the
   *  value backstop finds no registered value in the output: the classify
   *  verdict's path-derived mask (the command NAMES a secret file) has
   *  nothing left to protect and is lowered, so the model reads the
   *  program's own failure text plus the denied/held note instead of a
   *  symbol (§11.8; drill S7, 2026-09-24). */
  deniedOnly: boolean;
  /** Plan 10 §11.8: the guard recorded the tree, nothing in it read a
   *  secret, the output is (part of) the structured twin of `twinOf`, and the
   *  value backstop is clean. The caller lowers the path-derived mask: the
   *  model reads the keys, each secret value a symbol. */
  twinOnly?: boolean;
  /** The file(s) whose structured twin the output is. */
  twinOf?: string[];
  /** Plan 10 §11.8, "A document's own twin": the output is exactly the
   *  file's WHOLE-FILE twin (its base symbol); the `twin:` line says so. */
  twinWhole?: boolean;
  /** Plan 10 §11.8, "A key listing": the output holds no token and
   *  is the keys of the file's structured twin, in order (`cut -d= -f1
   *  .env`); the `twin:` line says so. */
  twinKeys?: boolean;
  /** Plan 10 §11.13, "A config with no secret": the output holds no token
   *  and is a piece of the file's OWN-TEXT twin (Mandu found no secret in
   *  it); the `twin:` line says so. */
  twinOwn?: boolean;
  /** Plan 10 §11.8, "A folder's names": the output is exactly a plain `ls`
   *  of the folders in `twinOf` (names only); the `listing:` line says so. */
  dirListing?: boolean;
  /** folder-listing-compound.md: the listing is the FIRST or LAST lines of a
   *  compound's output, the rest the other commands'; `twinOf` then holds
   *  the operands as the model wrote them. */
  dirListingPart?: "first" | "last";
  /** Plan 10 §11.8, "Refused connections": connections the egress proxy
   *  refused from the call's tree (the program, the kind; never a host).
   *  Explains only: never lowers or raises a mask. */
  refusedEgress?: RefusedEgress[];
  /** Plan 10 §11.8, "Blocked commands": commands of the call's tree the
   *  exec-wrap shim refused before they ran (the program, the kind; never
   *  an argument). Explains only: never lowers or raises a mask. */
  blockedExec?: Array<{ app: string; kind: string }>;
  /** Confidentiality §7.1, "the path-derived note" (2026-10-05): the result
   *  is masked whole only because the command NAMES a secret path (the
   *  classify verdict), with no taint answer that masks it. `paths` are the
   *  path tokens as the model wrote them in its own command (never a byte of
   *  the output). Explains only. */
  pathDerived?: { paths: string[]; twins?: PathDerivedTwin[] };
  /** Confidentiality §7.1, "the value-backstop note" (2026-10-17): the
   *  result is masked whole only because the arbiter's value backstop found
   *  a registered secret's value in it (classify `raisedBy:
   *  "value-backstop"`), with no taint answer that masks it. Takes the
   *  path-derived note's place: the call names no secret path. Explains
   *  only. */
  valueBackstop?: true;
  why: string;
}

const SECRET_NOTE_MARKER = "[mandu:secret]";

/** The path-derived note's line (confidentiality.md §7.1): built from the
 *  model's own command tokens only. Byte-identical in both proxies. */
function pathDerivedLine(paths: readonly string[], twins: readonly PathDerivedTwin[] = []): string {
  const named = paths.length === 0
    ? "a secret file"
    : paths.length === 1 ? `a secret file (${paths[0]})` : `secret files (${paths.join(", ")})`;
  const own = twins.map((t) => ` ${pathDerivedTwinSentence(t)}`).join("");
  return `masked: the command names ${named}, so its whole output is hidden from you, including whether it succeeded; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Everything else it printed is hidden with it: to read another file, a listing or a log, run that part again as a command of its own that names no secret file.${own} Do not assume it worked: if you still cannot tell, say you cannot see the result, or ask the user what it printed.`;
}

/** A named secret file's twin kind, as the arbiter answers it
 *  (`namedTwins`, arbiter named-twins.ts). */
export interface PathDerivedTwin {
  path: string;
  twin: "fields" | "lines" | "whole" | "text";
}

const PATH_DERIVED_TWIN_KINDS: ReadonlySet<string> = new Set(["fields", "lines", "whole", "text"]);

/** The arbiter's `namedTwins` the note may use: an entry whose token the
 *  note itself names (`paths`, the model's own spelling) and whose kind is
 *  one this proxy words. Anything else is dropped: no sentence is better
 *  than a wrong one. Pure. Byte-identical in both proxies. */
export function pathDerivedTwins(namedTwins: unknown, paths: readonly string[]): PathDerivedTwin[] {
  if (!Array.isArray(namedTwins)) return [];
  const out: PathDerivedTwin[] = [];
  for (const t of namedTwins as unknown[]) {
    if (t === null || typeof t !== "object") continue;
    const { path, twin } = t as { path?: unknown; twin?: unknown };
    if (typeof path !== "string" || typeof twin !== "string" || !paths.includes(path) || !PATH_DERIVED_TWIN_KINDS.has(twin)) continue;
    if (out.some((o) => o.path === path)) continue;
    out.push({ path, twin: twin as PathDerivedTwin["twin"] });
  }
  return out;
}

/** The path-derived note's sentence on reading a named secret file itself
 *  (confidentiality.md §7.1, 2026-10-19): what a read of it on its own
 *  shows, per its twin kind. Built from the model's own token and the
 *  arbiter's kind only. Byte-identical in both proxies. */
export function pathDerivedTwinSentence(t: PathDerivedTwin): string {
  const glob = /[*?[]/.test(t.path);
  const subject = glob ? `each secret file ${t.path} matches` : t.path;
  const how = glob
    ? "read it on its own (a file read of that one file, or `cat` with that file alone)"
    : `read it on its own (a file read of ${t.path}, or \`cat ${t.path}\` alone)`;
  const send = "(a command that sends it is checked against the file's rules)";
  switch (t.twin) {
    case "lines":
      return `To use ${subject} itself, ${how}: you see each line's label as written and its value as a symbol you can pass to a command ${send}.`;
    case "fields":
      return `To use ${subject} itself, ${how}: you see its keys and layout as written and each secret value as a symbol you can pass to a command ${send}.`;
    case "whole":
      return `To use ${subject} itself, ${how}: you see one symbol that stands for the whole file, which you can pass whole to a command where the file's content belongs ${send}.`;
    case "text":
      return `To read ${subject} itself, ${how}: Mandu read every place in it that can hold a secret and found none, so you see its text.`;
  }
}

/** The `listing:` line of a released folder listing (plan 10 §11.8, "A
 *  folder's names"): built from the arbiter's `twinOf` (the paths `ls`
 *  listed), never from the output. Byte-identical in both proxies. */
function dirListingLine(paths: readonly string[]): string {
  return `listing: these are the names in ${paths.join(", ")} as ls printed them, and nothing else: no file's content, size or date. The files there may still be secret: reading one shows you a symbol where its secret content is.`;
}

/** folder-listing-compound.md: the `listing:` line of a compound's listing
 *  part, naming the operands as the model wrote them (never a resolved
 *  path). Byte-identical in both proxies. */
function dirListingPartLine(operands: readonly string[], part: "first" | "last"): string {
  const where = part === "last" ? "the last lines of this output are" : "the first lines of this output are";
  const rest = part === "last" ? "The lines before them" : "The lines after them";
  return `listing: ${where} the names in ${operands.join(", ")} as ls printed them, no file's content, size or date. ${rest} are the other commands' output, which may describe any folder. The files there may still be secret: reading one shows you a symbol where its secret content is.`;
}

/** The value-backstop note's line (confidentiality.md §7.1, 2026-10-17):
 *  the result is masked whole only because the arbiter's value backstop
 *  found a registered secret's value in it (the classify verdict's
 *  `raisedBy`); the path rules call it public, so no file the call names is
 *  secret. Static text: no byte of the output, no name of the secret.
 *  Byte-identical in both proxies. */
function valueBackstopLine(): string {
  return `masked: this output contains the value of a registered secret, so the whole output is withheld from you, including whether it succeeded; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). It is withheld for that value, not for the file it came from. To read the rest, run a command that prints it with the value left out (for example without the lines that hold it); do not print the value in any other form. Do not assume it worked: if you still cannot tell, say you cannot see the result, or ask the user what it printed.`;
}

/** One whole `$MDU` token (the arbiter's symbol grammar, anchored). */
const WHOLE_SYMBOL_RE = /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*$/;

/**
 * backstop-value-only.md §3, rule P2: the call's own evidence holds no
 * secret read. No taint answer that masks it, no file its tree read (a
 * listed reader's release included), no refused open, no twin served, no
 * connection refused and no command blocked in its tree. A null taint (a
 * call this proxy asked no tree for: a Read) is clean: its path rule already
 * called the result public. Pure. Byte-identical in both proxies.
 */
export function valueOnlyEvidenceClean(t: SecretTaintInfo | null | undefined): boolean {
  if (t == null) return true;
  return !t.maskWhole && !isSecretLevel(t.level) && t.files.length === 0 && t.denied.length === 0 &&
    !t.deniedOnly && !t.twinOnly && (t.twinOf?.length ?? 0) === 0 &&
    (t.refusedEgress?.length ?? 0) === 0 && (t.blockedExec?.length ?? 0) === 0;
}

/**
 * backstop-value-only.md §3, rule P3: the arbiter's value-only offer, checked
 * and rebuilt from this proxy's own copy of the result. The spans must be
 * sorted, disjoint, in bounds and non-empty, each symbol one whole `$MDU`
 * token; the text rebuilt from `value` must equal the offered text, and no
 * replaced value may remain in it. Anything else (or no offer) is null: the
 * result is masked whole. Pure. Byte-identical in both proxies.
 */
export function acceptValueOnlyOffer(
  value: string,
  verdict: { valueOnly?: unknown },
): { text: string; values: Array<{ symbol: string; value: string }> } | null {
  const o = verdict.valueOnly as { text?: unknown; spans?: unknown } | undefined;
  if (!o || typeof o.text !== "string" || !Array.isArray(o.spans) || o.spans.length === 0) return null;
  let out = "";
  let at = 0;
  const values: Array<{ symbol: string; value: string }> = [];
  for (const s of o.spans as Array<{ start?: unknown; end?: unknown; symbol?: unknown }>) {
    if (!s || typeof s.start !== "number" || typeof s.end !== "number" || !Number.isInteger(s.start) || !Number.isInteger(s.end)) return null;
    if (s.start < at || s.end <= s.start || s.end > value.length) return null;
    if (typeof s.symbol !== "string" || !WHOLE_SYMBOL_RE.test(s.symbol)) return null;
    out += value.slice(at, s.start) + s.symbol;
    values.push({ symbol: s.symbol, value: value.slice(s.start, s.end) });
    at = s.end;
  }
  out += value.slice(at);
  if (out !== o.text) return null;
  if (values.some((v) => out.includes(v.value))) return null;
  return { text: out, values };
}

/**
 * clean-tree-release.md §2, rule Q3: the arbiter's clean-tree release offer,
 * checked and rebuilt from this proxy's own copy of the result. With no span
 * the offered text must be the result exactly; with spans, the value-only
 * rebuild (`acceptValueOnlyOffer`). A result holding `$MDU` text in any case
 * is never released. Anything else (or no offer) is null: the result is
 * masked whole. Pure. Byte-identical in both proxies.
 */
export function acceptPathReleaseOffer(
  value: string,
  verdict: { pathRelease?: unknown },
): { text: string; values: Array<{ symbol: string; value: string }>; listing?: { operands: string[]; part: "first" | "last" } } | null {
  const o = verdict.pathRelease as { text?: unknown; spans?: unknown; listing?: unknown } | undefined;
  if (!o || typeof o.text !== "string" || !Array.isArray(o.spans) || /\$MDU/i.test(value)) return null;
  // folder-listing-compound.md: a compound's listing rides only a release
  // with no span, its operands plain lines and its part first or last
  if (o.listing !== undefined) {
    const l = o.listing as { operands?: unknown; part?: unknown } | null;
    if (o.spans.length !== 0 || l === null || typeof l !== "object" || (l.part !== "first" && l.part !== "last")) return null;
    if (!Array.isArray(l.operands) || l.operands.length === 0 || l.operands.length > 32) return null;
    if (!l.operands.every((x) => typeof x === "string" && x !== "" && x.length <= 200 && !/[\r\n]/.test(x))) return null;
    return o.text === value ? { text: value, values: [], listing: { operands: [...l.operands as string[]], part: l.part } } : null;
  }
  if (o.spans.length === 0) return o.text === value ? { text: value, values: [] } : null;
  return acceptValueOnlyOffer(value, { valueOnly: o });
}

/** The path tokens the note may name: the arbiter's `namedPaths` that the
 *  model's own command holds verbatim (a translated spelling never does),
 *  at most 3, each short and on one line. Pure. */
export function pathDerivedPaths(namedPaths: readonly string[] | undefined, command: string): string[] {
  const out: string[] = [];
  for (const p of namedPaths ?? []) {
    if (out.length >= 3) break;
    if (typeof p !== "string" || p === "" || p.length > 200 || /[\r\n]/.test(p) || out.includes(p)) continue;
    if (command.includes(p)) out.push(p);
  }
  return out;
}

/** The `refused:` line's words per refusal kind (arbiter/ipc/protocol.ts
 *  EGRESS_REFUSAL_KINDS), and whether the user can allow it. */
const EGRESS_REFUSAL_WORDS: Readonly<Record<string, { why: string; ask: boolean; next?: string }>> = {
  tainted: { why: "it had read a secret, and the host is not one that secret is bound to", ask: true },
  unattributed: { why: "Mandu could not tell which program opened it, and programs in this session hold a secret", ask: true },
  symbol: { why: "the request carried a masked value ($MDU placeholder) that may not be sent to that host", ask: true },
  // confidentiality.md §4, the tripwire files no Approvals row (2026-10-17):
  // no approval can let a raw secret value through, so none is offered.
  fingerprint: {
    why: "the request carried text Mandu holds as a secret (a registered secret's value, or a line of a result it masked)",
    ask: false,
    next: "Do not retry the same request: there is nothing to approve for it. Tell the user what you were sending and where.",
  },
  "blocked-destination": { why: "the host is a cloud metadata or link-local address, which Mandu always refuses", ask: false },
  "this-machine": { why: "the host is this machine, and Mandu's egress proxy does not relay to this machine's own services", ask: false },
  // confidentiality.md §7, "A placeholder the agent's shell would expand"
  "shell-expanded": {
    why: "the request carried a secret's placeholder after a shell had expanded its $MDU to nothing (the placeholder was in double quotes or unquoted in the command or a script), so it held neither the value nor the placeholder",
    ask: false,
    next: "Put the placeholder in single quotes ('$MDU:…') where the shell reads it, in a script you wrote too, and run it again.",
  },
  "fail-closed": { why: "Mandu could not check the request", ask: false },
  // plan 10 §11.8, "A placeholder as the destination" (2026-10-17): no
  // host and no symbol in the words, only the generic `$MDU:…`.
  "symbol-destination": {
    why: "its destination was a Mandu placeholder ($MDU:…), and Mandu never turns a placeholder into a host to connect to",
    ask: false,
    next: "Do not retry with a placeholder as the host: write the host itself, and use the placeholder only where the secret's value belongs (a header or the body). If the host itself is the secret, tell the user.",
  },
  // confidentiality.md §4, "A held command's refused connection"
  // (2026-10-12): the arbiter filed (or read) the session's own ask.
  "session-asked": {
    why: "it holds what this session read, and the host is not a place that may go, so Mandu asked the user on its Approvals page",
    ask: false,
    next: "Tell the user it is waiting for their OK there; once they allow it, run the same command again: its next connection to that host goes through, once.",
  },
  "session-blocked": {
    why: "it holds what this session read, and the user blocked this session's requests to that host",
    ask: false,
    next: "Do not retry; tell the user.",
  },
};

/** A connection the egress proxy refused, as `callTaint` folds it (plan 10
 *  §11.8): the program and the kind; `unattributed` when the proxy tied it
 *  to no process and the arbiter to this call only by time ("A refusal no
 *  process is tied to"). Never a host. */
export interface RefusedEgress {
  app: string;
  kind: string;
  unattributed?: boolean;
}

/** The `refused:` line for one refusal (plan 10 §11.8), byte-identical in
 *  both proxies. An unattributed one names no program and no host (the host
 *  could be spelled from what was refused): it says the connection was made
 *  while the command ran and that Mandu could not tell which program opened
 *  it. Built from the kind only, never from a request byte. Pure. */
export function refusedEgressLine(r: RefusedEgress): string {
  const w = EGRESS_REFUSAL_WORDS[r.kind] ?? EGRESS_REFUSAL_WORDS["fail-closed"]!;
  const tail = w.ask ? " Tell the user rather than retrying; if it should go, they can allow it on the Mandu dashboard's Approvals page." : ` ${w.next ?? "Do not retry."}`;
  if (r.unattributed === true) {
    const why = r.kind === "unattributed" ? UNATTRIBUTED_SECRET_WHY : w.why;
    return `refused: a connection out was refused while this command ran, and nothing was sent; Mandu could not tell which program opened it, so it may not be this command's: ${why}.${tail}`;
  }
  return `refused: ${r.app} tried to connect out and Mandu refused the connection, nothing was sent: ${w.why}.${tail}`;
}

/** The `unattributed` kind's reason on a line that already says the
 *  program is unknown. */
const UNATTRIBUTED_SECRET_WHY = "programs in this session hold a secret, and while one does Mandu refuses a connection it cannot tie to a program";

/** The `blocked:` line's words per blocked-command kind (arbiter
 *  policy/blocked-exec.ts BLOCKED_EXEC_KINDS, the exec-wrap shim's approval
 *  kinds), and what the model can do instead. Byte-identical in both
 *  proxies. */
const BLOCKED_EXEC_WORDS: Readonly<Record<string, { why: string; next: string }>> = {
  symbol_as_command: {
    why: "a placeholder for text from an untrusted source sat where it would run as a command or as code",
    next: "Tell the user; if they trust that text, they can run the command themselves, outside the agent.",
  },
  unsupported_command: {
    why: "its command line carries a placeholder and uses shell syntax Mandu cannot check safely",
    next: "Write it as one plain command (no pipes, redirects, $( ), { } or wildcards), or tell the user.",
  },
  secret_symbol: {
    why: "its command line would have carried a secret's real value, and a secret leaves only inside a network request to a host it is bound to",
    next: "Tell the user rather than retrying; a request to another host asks for their OK on the Mandu dashboard's Approvals page.",
  },
  // 2026-10-09: the shim ran under Codex's own sandbox with its network
  // off, whose filter refused the shim's connection to Mandu (supported-
  // agents.md §6.4); the shim never asked, so the command was not judged.
  codex_sandbox: {
    why: "Codex's own sandbox, whose network is off, refused its connection to Mandu's command check, and Mandu never runs a command it could not check; the command itself was not the problem, and from that sandbox it could not have reached the network anyway",
    next: "To run it, ask to run it outside the sandbox (sandbox_permissions \"require_escalated\" with a justification, where your approval policy allows it; the user is asked first), or tell the user that sandbox_workspace_write.network_access = true in their Codex config lets these commands reach Mandu.",
  },
  other: {
    why: "Mandu could not check it",
    next: "Tell the user rather than retrying.",
  },
};

/** The `blocked:` line (plan 10 §11.8, "Blocked commands"): the program's
 *  name and the kind's words only. Codex's sandbox kind did not reach
 *  Mandu's check at all, so it is not said to have been refused by it. */
function blockedExecLine(r: { app: string; kind: string }): string {
  const w = BLOCKED_EXEC_WORDS[r.kind] ?? BLOCKED_EXEC_WORDS["other"]!;
  const head = r.kind === "codex_sandbox" ? `${r.app} did not start` : `Mandu's command check refused ${r.app} before it started`;
  return `blocked: ${head}, so it did not run and sent nothing: ${w.why}. ${w.next}`;
}

/** The arbiter's size bound for the structured exec-twin test
 *  (claude-code-inbound.ts EXEC_TWIN_OUTPUT_MAX); no runtime import. */
const EXEC_TWIN_OUTPUT_MAX = 256 * 1024;

/** Worth sending to `callTaint` for the §11.8 twin test: a twin carries at
 *  least one symbol and is a small file's text. Everything else skips the
 *  extra bytes on the socket (the arbiter would answer no `twinOf`). */
function mayBeTwin(value: string): boolean {
  return value.length <= EXEC_TWIN_OUTPUT_MAX && value.includes("$MDU:");
}

/** The arbiter's size bound for the key listing test
 *  (claude-code-inbound.ts KEY_LISTING_OUTPUT_MAX); no runtime import. */
const KEY_LISTING_OUTPUT_MAX = 16 * 1024;
/** A line that could be a key part: one word that starts like a key (a
 *  letter, `_`, a quote, `/`, `@` or `.`: no number) and holds no `=` (so a
 *  `KEY=value` line is not one), after optional indentation and an optional
 *  `export `, then at most a separator (`KEY`, `KEY=`, `  password:`,
 *  `aws_access_key_id =`, `export KEY`). */
const KEY_LIKE_LINE_RE = /^[ \t]*(?:export[ \t]+)?[A-Za-z_"'/@.][^\s=]*(?:[ \t]*[=:])?[ \t\r]*$/m;

/** Worth sending to `callTaint` for the key listing test (plan 10
 *  §11.8, "A key listing"): a command's token-free output of at most
 *  16 KiB with at least one line shaped like a key part (a listing names at
 *  least one secret's key). A traffic screen only, never a security check:
 *  the arbiter decides, and only on the guard's evidence. It is asked for a
 *  call that has a command, BEFORE the classify (the ask binds the call),
 *  so whether the path-derived mask applies is not known yet; the screen
 *  keeps the extra bytes off the socket for most outputs (prose, logs, JSON
 *  with spaces, anything bigger). */
function mayBeKeyListing(value: string): boolean {
  return value.length <= KEY_LISTING_OUTPUT_MAX && !value.includes("$MDU:") && KEY_LIKE_LINE_RE.test(value);
}

/** Worth sending to `callTaint` for the folder-names test (plan 10 §11.8,
 *  "A folder's names", 2026-10-17): the command starts with the word `ls`
 *  and the output is a token-free text of at most 16 KiB (the arbiter's
 *  bound, claude-code-inbound.ts KEY_LISTING_OUTPUT_MAX). A traffic screen
 *  only, like `mayBeKeyListing`: the arbiter parses the command, reads the
 *  folders and decides, on the guard's evidence. Byte-identical in both
 *  proxies. */
function mayBeDirListing(command: string, value: string): boolean {
  return /^\s*ls(?:\s|$)/.test(command) && value !== "" && value.length <= KEY_LISTING_OUTPUT_MAX && !value.includes("$MDU:");
}

/** Worth sending to `callTaint` for the own-text test (plan 10 §11.13, "A
 *  config with no secret", 2026-10-17): a command that may name one of the
 *  exhaustive configs (`.ssh`, `config`, `pip.conf` / `pip.ini`,
 *  `credentials`: `~/.ssh/config` and `config.d/*`, pip's, git's store), and
 *  a token-free output of at most 16 KiB (the arbiter's bound,
 *  claude-code-inbound.ts KEY_LISTING_OUTPUT_MAX). A traffic screen only,
 *  like `mayBeKeyListing`: the arbiter finds the configs the command names
 *  and decides, on the guard's evidence. Byte-identical in both proxies. */
function mayBeOwnTextTwin(command: string, value: string): boolean {
  return /\.ssh\b|(?:^|[\s/'"])config\b|pip\.(?:conf|ini)|credentials/.test(command) && value !== "" && value.length <= KEY_LISTING_OUTPUT_MAX && !value.includes("$MDU:");
}

/** The arbiter's §12.2 ceiling denial (`heldTimeoutReason` in
 *  arbiter/policy/flow-taint.ts; the proxy takes no runtime import from the
 *  arbiter, so the shape is matched here): rendered as the "held:" form. */
function isHeldTimeoutReason(reason: string): boolean {
  return /^held for \d+ s, nobody answered\b/.test(reason);
}

/** Plan 10 §11.18: the mask of a tool the arbiter has no mapping for. The
 *  level is the arbiter's (`no-model`, fail-closed when it sends none); the
 *  note is its product copy, or this one when it sends none. */
function unmappedMask(toolName: string, t: CallTaintWire): SecretTaintInfo {
  const why = typeof t.why === "string" && t.why !== ""
    ? t.why
    : `Mandu has no mapping for the tool ${toolName}, so its whole result is hidden from the AI; to let it through, list it under \`mapped_tools:\` in policy.yaml`;
  return { level: t.level ?? "no-model", files: [], apps: [], rule: "secret", maskWhole: true, denied: [], deniedOnly: false, why };
}

/**
 * Plan 10 §11.13, the per-server rule: the taint of the stdio MCP server
 * behind an `mcp__<server>__<tool>` result, through the arbiter's
 * `mcpServerTaint` (the launcher's registration of the agent's MCP config,
 * the guard's exec records). `{mask}` when the server's own process tree
 * read a secret raw, or when the answer cannot be read (fail-closed); else
 * the verdict (`clean`, `unmapped`, `own`). Null when the arbiter has
 * no such op (every server unmapped).
 */
async function serverTaintFor(
  arbiter: Arbiter,
  tool: string,
  sessionKey: string | undefined,
  log?: (msg: string) => void,
): Promise<{ mask: SecretTaintInfo } | { verdict: McpServerTaintWire["verdict"] } | null> {
  if (!arbiter.mcpServerTaint) return null;
  let r: McpServerTaintWire;
  try {
    r = await arbiter.mcpServerTaint({ tool, ...(sessionKey ? { sessionKey } : {}) });
  } catch (err) {
    log?.(`mcpServerTaint failed for ${tool}: ${(err as Error).message} — masking the result (fail-closed)`);
    return { mask: { level: "no-model", files: [], apps: [], rule: "secret", maskWhole: true, denied: [], deniedOnly: false, why: "the MCP server's process taint could not be read: masked (fail-closed)" } };
  }
  if (r.verdict === "tainted") {
    const files = r.files.map((f) => f.split("/").pop()).join(", ");
    return { mask: { level: r.level ?? "no-model", files: r.files, apps: r.apps, rule: "secret", maskWhole: true, denied: [], deniedOnly: false, why: `plan 10 §11.13: the MCP server ${r.server ?? tool} runs processes that read ${files || "a secret"} raw; the whole output is secret` } };
  }
  return { verdict: r.verdict };
}

/**
 * The command text the exec-output legs read from a call's input: a mapped
 * shell's command field (`surface.execOutput`), else the first command-like
 * field (plan 10 §11.12). Null when the call carries none. The response side
 * records the same text, read from the input it DELIVERED to the agent
 * (`recordCallCommand`, plan 13 D9 follow-up), so the call is bound to the
 * shell that ran it and never by the input the agent echoes back here.
 */
export function callCommandText(toolName: string, input: Record<string, unknown>, surface: GateSurface = CLAUDE_CODE_GATE_SURFACE): string | null {
  if (Object.prototype.hasOwnProperty.call(surface.execOutput, toolName)) {
    const v = input[surface.execOutput[toolName]!];
    return typeof v === "string" && v !== "" ? v : null;
  }
  return commandLikeText(input);
}

/**
 * Plan 10 §4.2 / §11.8: ask the arbiter for the taint of the process tree
 * behind a Bash call, decide whether the whole result is masked, and prepare
 * the note the model will read. Only Bash-shaped tools have a tree. Fail-closed:
 * an arbiter that THROWS on callTaint is treated as "tainted, rule secret"
 * with an unknown level (no-model); an arbiter without the op reports no
 * taint (nothing to mask). A rule (ii)/(iii) result is released only when the
 * verbatim-value backstop finds nothing and no mask regex matches; a backstop
 * that cannot run keeps the result masked.
 */
/** Claude Code's polls of a background task's output (plan 10 §11.12): they
 *  name a task, not a command. */
export const CLAUDE_TASK_POLL_TOOLS: ReadonlySet<string> = new Set(["BashOutput", "TaskOutput"]);
/** The write tools whose whole result leads with the agent's fixed success
 *  notice (plan 15 §13.10; the arbiter's agent-result-head.ts
 *  WRITE_NOTICE_TOOLS, mirrored): Claude Code's `Write`, the `write` of
 *  OpenCode, Goose and OpenClaw. The arbiter matches the notice itself, for
 *  the row's own path, and ignores the name on any other value. */
export const WRITE_NOTICE_RESULT_TOOLS: ReadonlySet<string> = new Set(["Write", "write"]);

/** The whole result of a `Bash` call with `run_in_background: true` (Claude
 *  Code 2.1.x, the call-tree sandbox test's agent): the runtime's own text,
 *  the command's output going to the task's file. */
const CLAUDE_BG_ANNOUNCE_RE = /^Command running in background with ID: ([A-Za-z0-9_-]{1,64})\./;
/** Every spelling of a background id Claude Code announces (started in the
 *  background, moved there by the user, by a timeout, by a queued message).
 *  Read anywhere in any result: each is a claim on that id. */
const CLAUDE_BG_CLAIM_RE = /(?:in background with ID: |backgrounded by user with ID: |moved to the background \(ID: )([A-Za-z0-9_-]{1,64})/g;

/** A poll's answer only raises: the releases that lower a path-derived mask
 *  (denied-only, the structured twin) belong to the call that named the
 *  path, never to a poll of its task. */
function raiseOnly(t: SecretTaintInfo | null): SecretTaintInfo | null {
  return t && (t.deniedOnly || t.twinOnly) ? { ...t, deniedOnly: false, twinOnly: false } : t;
}

/** The `Bash` call a poll continues (plan 13 D7, plan 10 §11.12). */
export interface BackgroundPollRef {
  callId: string;
  name: string;
  input: Record<string, unknown>;
}

/**
 * Plan 13 D7 / plan 10 §11.12, Claude Code's polls (2026-10-09): tie each
 * `BashOutput` / `TaskOutput` call of the request to the ONE `Bash` call that
 * started the task it polls, so the poll is answered by that call's process
 * tree (raise-only) instead of the session's level.
 *
 * A poll is tied only when (1) a `Bash` call with `run_in_background: true`
 * has a result that STARTS with Claude Code's announcement of the id (that
 * result is the runtime's own text: the command's output goes to the task's
 * file), and (2) no other result of the request mentions that id in any
 * announcement spelling (a command or a file could print one; a reused id,
 * or a call moved to the background, makes two claims). Anything else,
 * including a task started outside the request's history (compacted away)
 * or a background subagent, is left unmapped: the poll is asked with no
 * command and the session decides, as before. Read BEFORE the walk rewrites
 * any result. Pure.
 */
export function claudeBackgroundPolls(messages: Message[], correlation: Map<string, ToolCallRef>): Map<string, BackgroundPollRef> {
  const claims = new Map<string, Set<string>>();
  const owners = new Map<string, Set<string>>();
  const add = (m: Map<string, Set<string>>, id: string, callId: string): void => {
    const s = m.get(id) ?? new Set<string>();
    s.add(callId);
    m.set(id, s);
  };
  for (const msg of messages) {
    if (msg.role !== "user" || !Array.isArray(msg.content)) continue;
    for (const block of msg.content) {
      if (!isToolResultBlock(block)) continue;
      const tr = block as ToolResultBlock;
      const text = flattenToolResultContent(tr.content);
      for (const m of text.matchAll(CLAUDE_BG_CLAIM_RE)) add(claims, m[1]!, tr.tool_use_id);
      const ref = correlation.get(tr.tool_use_id);
      if (ref?.name !== "Bash" || ref.input["run_in_background"] !== true) continue;
      const announce = CLAUDE_BG_ANNOUNCE_RE.exec(text);
      if (announce) add(owners, announce[1]!, tr.tool_use_id);
    }
  }
  const out = new Map<string, BackgroundPollRef>();
  for (const [pollId, ref] of correlation) {
    if (!CLAUDE_TASK_POLL_TOOLS.has(ref.name)) continue;
    const id = ["task_id", "bash_id", "shell_id"].map((k) => ref.input[k]).find((v): v is string => typeof v === "string");
    if (id === undefined) continue;
    const own = owners.get(id);
    const claimed = claims.get(id);
    if (!own || own.size !== 1 || !claimed || claimed.size !== 1) continue;
    const callId = [...own][0]!;
    if (!claimed.has(callId)) continue;
    out.set(pollId, { callId, name: "Bash", input: correlation.get(callId)!.input });
  }
  return out;
}

async function secretTaintFor(
  arbiter: Arbiter,
  toolName: string,
  callId: string,
  input: Record<string, unknown>,
  sessionKey: string | undefined,
  value: string,
  log?: (msg: string) => void,
  surface: GateSurface = CLAUDE_CODE_GATE_SURFACE,
  /** Out: the connections the arbiter says were refused from the call's
   *  tree (plan 10 §11.8, "Refused connections"). */
  egress?: { refused?: RefusedEgress[]; blocked?: Array<{ app: string; kind: string }> },
  /** Plan 13 D7: this ask is for the background poll with this tool_use id,
   *  tied to the call `callId` (claudeBackgroundPolls); the arbiter then counts
   *  the poll's masked output as evidence when that call's tree is. */
  forPoll?: string,
): Promise<SecretTaintInfo | null> {
  // A shell-shaped tool has a process tree: the session agent's own
  // (Claude Code Bash/BashOutput/Monitor, opencode bash, openclaw
  // exec/process). Any other tool whose input carries a command-like field
  // is asked about as `unmappedTool` (plan 10 §11.12): the arbiter answers
  // only when the session's spec does not know the tool, and that answer can
  // only mask (the denied-only and twin releases below never apply to it).
  // Plan 10 §11.13, the per-server rule: an MCP result whose server's own
  // process tree read a secret raw is masked whole, command or not. A server
  // proven clean (exactly one process, its tree read no secret raw) falls
  // through to the rule below (a command-like input, §11.12), as before.
  // Rule (c), on Claude Code since 2026-10-03 (maintainer; as on Codex): every
  // other MCP result (an unmapped server: HTTP or remote, not registered,
  // never spawned, two candidates; Mandu's own tools; an arbiter without the
  // op) is asked about the SESSION with no command, so it is masked whole
  // while the session holds a raw read. Such a server is a store a secret
  // can be written into on a channel the proxy never sees, and nothing ties
  // its result to a process tree. The arbiter answers empty for Mandu's own
  // tools. Claude Code's MCP resource tools read a server's resources by a
  // server name the MODEL wrote: never mapped per server, always asked.
  // Plan 10 §11.18 (P0 item 4b, the maintainer's decision 2026-10-07):
  // every result of a tool that is not the agent's shell is asked about as
  // `unmappedTool`. The arbiter answers empty for a tool it has a mapping
  // for (the session's spec, its gate surface, Mandu's own tools,
  // policy.yaml `mapped_tools:`), keeps §11.12/§11.13 for a command-like
  // input and a registered MCP server, and masks WHOLE a tool it has no
  // mapping for (`evidence: "unmapped"`), whatever the session read: an MCP
  // server's tool Mandu cannot tie to a configured server, a plugin's tool,
  // a renamed one, Claude Code's MCP resource tools (no spec entry: they read
  // a server named by the model's own text).
  const mapped = Object.prototype.hasOwnProperty.call(surface.execOutput, toolName);
  let askSession = !mapped;
  if (toolName.startsWith("mcp__")) {
    const server = await serverTaintFor(arbiter, toolName, sessionKey, log);
    if (server && "mask" in server) return server.mask;
    askSession = !(server && server.verdict === "clean");
  }
  const unmappedCommand = mapped ? null : commandLikeText(input);
  if (!mapped && unmappedCommand === null && !askSession) return null;
  if (!arbiter.callTaint) return null;
  // The command as the agent echoed it: since the plan 13 D9 follow-up the
  // arbiter binds the call by the command this proxy recorded when it
  // relayed the call, and reads this one only for its folded guess.
  const command = callCommandText(toolName, input, surface) ?? undefined;
  let t: CallTaintWire;
  try {
    t = await arbiter.callTaint({
      callId, ...(command ? { command } : {}), ...(sessionKey ? { sessionKey } : {}), ...(forPoll ? { forPoll } : {}),
      ...(mapped ? (mayBeTwin(value) || (command !== undefined && (mayBeKeyListing(value) || mayBeDirListing(command, value) || mayBeOwnTextTwin(command, value))) ? { output: value } : {}) : { unmappedTool: toolName }),
    });
  } catch (err) {
    log?.(`callTaint failed for ${callId}: ${(err as Error).message} — masking the result (fail-closed)`);
    return { level: "no-model", files: [], apps: [], rule: "secret", maskWhole: true, denied: [], deniedOnly: false, why: "the process taint could not be read: masked (fail-closed)" };
  }
  const denied = t.denied ?? [];
  if (egress && Array.isArray(t.refusedEgress) && t.refusedEgress.length > 0) {
    egress.refused = t.refusedEgress.filter((r) => r && typeof r.app === "string" && typeof r.kind === "string");
  }
  if (egress && Array.isArray(t.blockedExec) && t.blockedExec.length > 0) {
    egress.blocked = t.blockedExec.filter((r) => r && typeof r.app === "string" && typeof r.kind === "string");
  }
  const twinOf = mapped && t.level === null && Array.isArray(t.twinOf) ? t.twinOf.filter((p) => typeof p === "string" && p !== "") : [];
  if (t.level === null && denied.length === 0 && twinOf.length === 0) return null;
  if (!mapped) {
    // §11.12: raise-only. Denials are only explained; a tainted tree or
    // session masks the whole result (rule `secret` for a session answer).
    // §11.18: a tool Mandu has no mapping for, masked whole; the arbiter's
    // note says why and how to let it through (policy.yaml `mapped_tools:`).
    if (t.evidence === "unmapped") return unmappedMask(toolName, t);
    if (t.level === null) return { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied, deniedOnly: false, why: "an open of a secret in the tree was refused" };
    if (t.evidence === "session") {
      const what = command !== undefined
        ? `plan 10 §11.12: ${toolName} runs a command Mandu could not tie to a process tree`
        : `plan 10 §11.13: ${toolName} is an MCP server whose state Mandu cannot see`;
      return { level: t.level, files: [], apps: t.apps, rule: "secret", maskWhole: true, denied, deniedOnly: false, why: `${what}, and programs in this session read ${t.files.map((f) => f.split("/").pop()).join(", ")} raw; the whole output is secret` };
    }
  } else if (t.evidence === "session" && t.level !== null) {
    // Plan 13 D7, fail-closed: the arbiter could not tie this shell call to
    // the process tree that ran it (no exec of the agent matched it: a tool
    // with no command such as BashOutput, a lost record), and the session
    // holds a raw read. Masked whole at the session's level; no release
    // (the denied-only and twin releases need the tree).
    return { level: t.level, files: [], apps: t.apps, rule: "secret", maskWhole: true, denied, deniedOnly: false, why: `plan 13 D7: Mandu could not tie this ${toolName} call to the processes that ran it, and programs in this session read ${t.files.map((f) => f.split("/").pop()).join(", ")} raw; the whole output is secret` };
  }
  // The value backstop (rule (ii)/(iii), and the denied-only release): a
  // registered value verbatim in the output keeps it masked whatever the
  // tree says; a backstop that cannot run counts as a hit.
  const backstop = async (): Promise<string | null> => {
    if (!arbiter.scanSecretValues) return "the value backstop is unavailable on this arbiter";
    try {
      const scan = await arbiter.scanSecretValues(value);
      return scan.hits.length > 0 ? `a registered secret value appears verbatim (${scan.hits.map((h) => h.symbol).join(", ")})` : null;
    } catch (err) {
      return `the value backstop failed (${(err as Error).message})`;
    }
  };
  if (t.level === null && denied.length === 0) {
    // The structured twin only (§11.8): the arbiter matched the output to
    // one registered file's twin in a tree the guard saw read no secret.
    // Released ⇒ the caller lowers the path-derived mask; a backstop hit ⇒
    // the mask stands.
    // "A document's own twin": the arbiter says the output is exactly a
    // document's whole-file twin (its base symbol), not a structured piece.
    // "A key listing": the output holds no token and is the keys of
    // the file's structured twin, in order (`cut -d= -f1 .env`).
    // "A folder's names": the output is exactly a plain `ls` of the folders
    // in `twinOf`, names only (`ls mail/inbox bank/`).
    // "A config with no secret" (plan 10 §11.13): the output holds no
    // token and is a piece of the own-text twin of a config the command
    // names (`cat ~/.ssh/config`).
    const whole = t.twinWhole === true;
    const keys = !whole && t.twinKeys === true;
    const ownText = !whole && !keys && t.twinOwn === true;
    const listing = !whole && !keys && !ownText && t.dirListing === true;
    const form = whole ? "whole-file twin" : keys ? "key listing of the structured twin" : ownText ? "own text (no secret in it)" : listing ? "names-only listing" : "structured twin";
    const hit = await backstop();
    return { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied, deniedOnly: false, twinOf, ...(whole ? { twinWhole: true } : {}), ...(keys ? { twinKeys: true } : {}), ...(ownText ? { twinOwn: true } : {}), ...(listing ? { dirListing: true } : {}), ...(hit === null ? { twinOnly: true } : {}), why: hit === null ? `the output is the ${form} of ${twinOf.join(", ")}, no process in the tree read a secret, and no registered value appears in it` : `a ${form}, but ${hit}` };
  }
  if (t.level === null) {
    // Denials only: no process in the tree holds a secret. The guard refused
    // every open it saw, so the output cannot carry the file's bytes by that
    // route; the backstop covers the rest. Released ⇒ the caller lowers the
    // path-derived mask; a hit ⇒ the mask stands, and only the note is added.
    const hit = await backstop();
    return { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied, deniedOnly: hit === null, why: hit === null ? "every open of a secret in the tree was refused and no registered value appears in the output" : `a refused tree, but ${hit}` };
  }
  const who = `${t.apps.join(", ") || "a program"} read ${t.files.map((f) => f.split("/").pop()).join(", ")}`;
  if (t.rule === "secret") {
    return { level: t.level, files: t.files, apps: t.apps, rule: t.rule, maskWhole: true, denied, deniedOnly: false, why: `plan 10 rule (i): ${who}; the whole output is secret` };
  }
  // rule (ii)/(iii): the value backstop, then the mask regexes
  let hit = await backstop();
  if (hit === null && t.rule === "mask") {
    for (const re of t.mask) {
      try { if (new RegExp(re, "m").test(value)) { hit = `a mask pattern matched (${re})`; break; } } catch { hit = `an invalid mask pattern (${re})`; break; }
    }
  }
  if (hit !== null) {
    return { level: t.level, files: t.files, apps: t.apps, rule: t.rule, maskWhole: true, denied, deniedOnly: false, why: `plan 10 rule (${t.rule === "clear" ? "ii" : "iii"}) backstop: ${hit}` };
  }
  return { level: t.level, files: t.files, apps: t.apps, rule: t.rule, maskWhole: false, denied, deniedOnly: false, why: `plan 10 rule (${t.rule === "clear" ? "ii" : "iii"}): ${who}; its output is released by the app rule` };
}

/**
 * Confidentiality plan 13 §4.5.1 (decision 2026-10-02: mask, do not refuse):
 * the agent process itself is never made a holder, so a reply it received
 * over its OWN connection to one (an HTTP MCP server that read `.env`, a
 * local dev server it fetched) is masked at the model exit. One
 * `agentReceiptTaint` batch per request, over every tool_result (the tool as
 * the response side gated it: a dispatcher's inner tool); the arbiter
 * answers a level only for a tool whose result the agent itself produced
 * (not a shell's, not a file tool's) during a call whose window overlaps such
 * a connection. Each answer becomes a whole-result mask (raise-only over the
 * other legs). A THROW refuses the request (RewriteRefusal): which results
 * the agent received cannot be told. An arbiter without the op: no mask by
 * this leg.
 */
async function agentReceiptMasks(
  arbiter: Arbiter,
  messages: readonly Message[],
  correlation: ReadonlyMap<string, ToolCallRef>,
  surface: GateSurface,
  sessionKey: string | undefined,
): Promise<Map<string, SecretTaintInfo>> {
  const out = new Map<string, SecretTaintInfo>();
  if (!arbiter.agentReceiptTaint) return out;
  const calls: Array<{ callId: string; tool: string }> = [];
  const seen = new Set<string>();
  for (const msg of messages) {
    if (!Array.isArray(msg.content)) continue;
    for (const block of msg.content) {
      if (!isToolResultBlock(block)) continue;
      const id = (block as ToolResultBlock).tool_use_id;
      if (typeof id !== "string" || id === "" || seen.has(id)) continue;
      seen.add(id);
      const ref = correlation.get(id);
      const name = ref?.name ?? "__unknown__";
      const inner = ref ? unwrapDispatch(name, ref.input, surface) : null;
      calls.push({ callId: id, tool: inner?.kind === "call" ? inner.name : name });
    }
  }
  if (calls.length === 0) return out;
  let r: AgentReceiptTaintWire;
  try {
    r = await arbiter.agentReceiptTaint({ calls, ...(sessionKey ? { sessionKey } : {}) });
  } catch (err) {
    throw new RewriteRefusal("arbiter agentReceiptTaint failed — refusing to forward results the agent may have received from a secret holder (plan 13 §4.5.1)", err);
  }
  for (const c of Array.isArray(r?.calls) ? r.calls : []) {
    if (!c || typeof c.callId !== "string" || typeof c.level !== "string" || c.level === "") continue;
    const files = Array.isArray(c.files) ? c.files : [];
    const apps = Array.isArray(c.apps) ? c.apps : [];
    const names = files.map((f) => f.split("/").pop()).join(", ") || "a secret";
    out.set(c.callId, {
      level: c.level, files, apps, rule: "secret", maskWhole: true, denied: [], deniedOnly: false,
      why: c.unattributed === true
        ? `plan 13 §4.5.1: the agent itself was connected to a program that read ${names} before this result, and the call's start was not recorded; the whole output is secret`
        : `plan 13 §4.5.1: the agent itself was connected, during this call, to a program that read ${names}; the whole output is secret`,
    });
  }
  return out;
}

/** The `[mandu:secret]` note (§11.8): why a result is masked, or which open
 *  was refused and the way out. Proxy-authored; appended after the body. */
export function buildSecretNote(t: SecretTaintInfo): string | null {
  const lines: string[] = [];
  if (t.pathDerived) lines.push(pathDerivedLine(t.pathDerived.paths, t.pathDerived.twins));
  if (t.valueBackstop) lines.push(valueBackstopLine());
  if (t.maskWhole && t.files.length > 0) {
    lines.push(`masked: ${t.apps.join(", ")} read ${t.files.join(", ")}; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Say so rather than retrying.`);
  } else if (t.maskWhole) {
    lines.push(`masked: ${t.why}. The user does not see this output unless your reply quotes the symbol (they then see its real value).`);
  } else if (t.files.length > 0 && !t.pathDerived && !t.valueBackstop) {
    lines.push(`note: ${t.apps.join(", ")} read ${t.files.join(", ")} (a listed reader); the output is released by the program's rule.`);
  }
  if (t.twinOnly && t.twinOf && t.twinOf.length > 0 && t.dirListing) {
    // "A folder's names" (plan 10 §11.8), and beside another command
    // (folder-listing-compound.md). Byte-identical in both proxies.
    lines.push(t.dirListingPart ? dirListingPartLine(t.twinOf, t.dirListingPart) : dirListingLine(t.twinOf));
  } else if (t.twinOnly && t.twinOf && t.twinOf.length > 0) {
    lines.push(t.twinWhole
      ? `twin: this is ${t.twinOf.join(", ")} as you see it: the whole file is one symbol. Use the symbol where the file's content belongs (a command that sends it is checked against the file's rules); the user sees the real content.`
      : t.twinOwn
        // "A config with no secret" (plan 10 §11.13). Byte-identical in
        // both proxies.
        ? `twin: this is ${t.twinOf.join(", ")} as it is: Mandu read every place in it that can hold a secret and found none, so you see its text.`
        : t.twinKeys
        // "A key listing" (plan 10 §11.8). Claude Code has a Read
        // tool; the openai-proxy's line says "cat it" (Codex has none).
        ? `twin: these are the key names in ${t.twinOf.join(", ")}, and the lines of it that hold no masked value, as you see the file; no masked value is in this output. Read the file (or cat it) to see each masked value as a symbol, and use the symbol where the value belongs (a command that sends it is checked against the file's rules); the user sees the real values.`
        : `twin: this is ${t.twinOf.join(", ")} as you see it: the keys as written, each secret value a symbol. Use the symbol where the value belongs (a command that sends it is checked against the file's rules); the user sees the real values.`);
  }
  for (const r of t.refusedEgress ?? []) lines.push(refusedEgressLine(r));
  for (const r of t.blockedExec ?? []) lines.push(blockedExecLine(r));
  for (const d of t.denied) {
    if (isHeldTimeoutReason(d.reason)) {
      // §11.8's third form: the open was held for the user and the hold's
      // ceiling passed. The row is still open, so the way out is the user's
      // answer, not a retry.
      lines.push(`held: ${d.app} waited for the user to allow it to read ${d.path} (${d.reason}). Tell the user the request is waiting on the Mandu dashboard's Approvals page; once they allow it, the same command succeeds without a new prompt. Do not retry before that.`);
    } else {
      lines.push(`denied: ${d.app} is not a reader of ${d.path} (${d.reason}). The user can allow it in policy.yaml (paths[].readers).`);
    }
  }
  if (lines.length === 0) return null;
  return lines.map((l) => `${SECRET_NOTE_MARKER} ${l}`).join("\n");
}

/** Confidentiality §7.1, "Masked after the fact": one more `[mandu:secret]`
 *  line on a result this proxy forwarded in clear in an earlier request and
 *  masks now. Joined to the result's secret note (so the §9 oracle's
 *  own-block scope strips it with that note); static text, no result byte. */
function appendAfterTheFactNote(tr: ToolResultBlock, audit: RewriteAudit, line: string): void {
  const own = `${SECRET_NOTE_MARKER} ${line}`;
  const current = audit.forwardedText ?? (audit.symbolized ? audit.symbol ?? "" : audit.value);
  const forwarded = audit.secretNote ? `${current}\n${own}` : `${current}\n\n${own}`;
  if (typeof tr.content === "string" || tr.content == null) {
    tr.content = forwarded;
  } else {
    tr.content = [{ type: "text", text: forwarded } as ToolResultContentBlock];
  }
  audit.forwardedText = forwarded;
  audit.secretNote = audit.secretNote ? `${audit.secretNote}\n${own}` : own;
  audit.afterTheFact = true;
}

function appendSecretNote(tr: ToolResultBlock, audit: RewriteAudit, t: SecretTaintInfo | null): void {
  if (!t) return;
  audit.secretTaint = t;
  const note = buildSecretNote(t);
  if (!note) return;
  const current = audit.forwardedText ?? (audit.symbolized ? audit.symbol ?? "" : audit.value);
  const forwarded = `${current}\n\n${note}`;
  if (typeof tr.content === "string" || tr.content == null) {
    tr.content = forwarded;
  } else {
    tr.content = [{ type: "text", text: forwarded } as ToolResultContentBlock];
  }
  audit.forwardedText = forwarded;
  audit.secretNote = note;
}

async function appendTwinNote(
  tr: ToolResultBlock,
  audit: RewriteAudit,
  input: Record<string, unknown>,
  agentViewRoots: readonly string[] | undefined,
  toHumanView: ((p: string) => string) | undefined,
  arbiter: Arbiter,
  twinHintCache: Map<string, TwinHint[]> | undefined,
  log?: (msg: string) => void,
  surface: GateSurface = CLAUDE_CODE_GATE_SURFACE,
): Promise<void> {
  try {
    if (!agentViewRoots || agentViewRoots.length === 0) return;
    if (audit.trust !== "UNTRUSTED" || !audit.symbolized || !audit.symbol) return;
    if (!Object.prototype.hasOwnProperty.call(surface.execOutput, audit.tool)) return;
    const commandField = surface.execOutput[audit.tool]!;
    const command = typeof input[commandField] === "string" ? (input[commandField] as string) : "";
    if (command === "") return;
    const hints = await twinHintsFor(arbiter, audit.toolUseId, command, twinHintCache, log);
    const { entries: twins, more } = findTwinsDetailed(command, agentViewRoots, toHumanView ?? ((p) => p), hints, hints.more ?? 0);
    if (twins.length === 0) return;
    const note = buildTwinNote(twins, more);
    const current = audit.forwardedText ?? audit.symbol;
    const forwarded = `${current}\n\n${note}`;
    if (typeof tr.content === "string" || tr.content == null) {
      tr.content = forwarded;
    } else {
      tr.content = [{ type: "text", text: forwarded } as ToolResultContentBlock];
    }
    audit.forwardedText = forwarded;
    audit.twinNote = note;
    audit.twinNoteInfo = twinNoteSummary(twins, more);
  } catch {
    /* utility-only: fail toward silence */
  }
}

/**
 * The WIRE spans of one rewritten tool_result that must not survive in the
 * forwarded request: what its symbol replaced, plus a dropped reminder tail.
 * Deliberately NOT `symbolValue`: a Read's un-rendered bytes are derived from
 * the wire span (each line is a substring of a rendered line), so the span's
 * absence already proves theirs — and being shorter, they would collide with
 * trusted text far more often (a false VIOLATED on `v2`).
 */
export function mustNotSurvive(r: RewriteAudit): string[] {
  if (r.valueOnly) return r.valueOnly.map((v) => v.value);
  const spans = [r.symbolizedSpan ?? r.value];
  if (r.droppedTail) spans.push(r.droppedTail);
  return spans;
}

/** One harness token-budget reminder block. MIRRORS the arbiter's
 *  `TOKEN_BUDGET_BLOCK_SRC` (arbiter/policy/claude-code-inbound.ts, the shape
 *  `isHarnessTokenBudgetReminder` vouches for): anchored, digits-only. */
const TOKEN_BUDGET_BLOCK_SRC =
  "<system-reminder>\\s*<total_tokens>\\d+ tokens left</total_tokens>\\s*</system-reminder>";
const TOKEN_BUDGET_ONLY_RE = new RegExp(`^\\s*(?:${TOKEN_BUDGET_BLOCK_SRC}\\s*)+$`);

/** Is `text` ENTIRELY harness token-budget reminder block(s)? */
export function isTokenBudgetReminder(text: string): boolean {
  return text.trim() !== "" && TOKEN_BUDGET_ONLY_RE.test(text);
}

/**
 * The subset of `mustNotSurvive` the §9 oracle also looks for OUTSIDE the
 * result's own block (events.ts survivingResult, the cross-result scope). It
 * leaves out exactly one span: a dropped tail that is ENTIRELY the harness
 * token-budget reminder. Claude Code appends the SAME reminder (same count)
 * to every tool_result of a turn; on a secret Read the tail inherits the
 * path's level and is dropped, the next public result forwards raw with the
 * identical reminder, and the cross-result check called that recurrence a
 * violation (claude-code.live, 2026-09-29: a false red banner in `secrets`).
 * That shape is a digits-only channel the harness authors, never the secret;
 * its recurrence elsewhere is the harness appending it again. The own-block
 * check still looks for it at any length (it is still cut from THIS result),
 * and every other span (the body, any other tail) stays in both scopes, so a
 * secret's raw bytes reaching the model through another result still flag.
 */
export function crossResultSpans(r: RewriteAudit): string[] {
  if (r.valueOnly) return r.valueOnly.map((v) => v.value);
  const spans = [r.symbolizedSpan ?? r.value];
  if (r.droppedTail && !isTokenBudgetReminder(r.droppedTail)) spans.push(r.droppedTail);
  return spans;
}

/**
 * What the forwarded request carries for THIS result, minus the proxy-authored
 * notes (twin, secret) and the trusted piece a split result keeps verbatim:
 * the own-block scope of the §9 oracle (events.ts survivingResult). What is
 * left is the symbol, so any raw span found here survived the rewrite.
 */
export function ownForwardedText(r: RewriteAudit): string {
  let text = r.forwardedText ?? (r.symbolized ? r.symbol ?? "" : r.value);
  for (const note of [r.twinNote, r.secretNote]) {
    if (note) text = text.replace(`\n\n${note}`, "");
  }
  return r.keptVerbatim ? text.replace(r.keptVerbatim, "") : text;
}

/**
 * The §9 oracle haystack: the forwarded tool_result text MINUS each appended
 * twin note (removed exactly once, as appended). The note is proxy-authored
 * and known byte-exact; a raw span that survived symbolization is still in
 * the haystack after the removal — only the proxy's own suffix is not.
 */
export function oracleHaystack(req: MessagesRequest, rewrites: readonly RewriteAudit[]): string {
  let text = forwardedToolResultText(req);
  for (const r of rewrites) {
    if (r.twinNote) text = text.replace(`\n\n${r.twinNote}`, "");
  }
  return text;
}

/**
 * Rewrite a parsed Messages request: classify + symbolize untrusted tool_result
 * spans, inject the handling prompt. Throws RewriteRefusal on any arbiter error
 * (fail-closed). Mutates a structural clone, never the caller's object.
 */
export async function rewriteRequest(
  original: MessagesRequest,
  opts: RewriteOptions,
): Promise<RewriteResult> {
  const { arbiter, sessionKey, handlingMode, skipPromptInjection, toHumanView, agentViewRoots, twinHintCache } = opts;

  // Deep-clone so the caller's parsed body is untouched and we can safely mutate.
  const req: MessagesRequest = structuredClone(original);
  const messages = Array.isArray(req.messages) ? req.messages : [];

  const correlation = buildCorrelationMap(messages);
  const rewrites: RewriteResult["rewrites"] = [];
  // Plan 13 D7: each background poll's starting Bash call, read off the
  // results BEFORE the walk below rewrites them.
  const bgPolls = claudeBackgroundPolls(messages, correlation);

  // Program output carried as USER text (opencode-background.ts): OpenCode
  // 2's background-completion and user-shell notices (supported-agents.md
  // §2.3 items 6 and 9) and Claude Code's bash-mode output (`!cmd`). Each
  // one becomes, for this rewrite, a stand-in tool_result read as its
  // shell's (or subagent's) result (or masked whole when it cannot be
  // read so), and is put back as text below. FIRST: the prompt filter must
  // not take it for the human's text, and the trusted-context haystack must
  // not contain it.
  const surfaceSpec = (opts.surface ?? CLAUDE_CODE_GATE_SURFACE).spec;
  const noticeKinds = BACKGROUND_NOTICE_SPECS.get(surfaceSpec);
  const bgNotices: ExtractedNotices | null = noticeKinds
    ? extractBackgroundNotices(messages, correlation, (opts.surface ?? CLAUDE_CODE_GATE_SURFACE).exec, noticeKinds)
    : null;
  // The ids whose result body this request forwards in clear: remembered
  // (opts.clearResults) only once the whole rewrite has succeeded.
  const clearIds: string[] = [];
  // The texts this request forwards unchanged, for opts.forwardedResults
  // (OpenClaw only), likewise remembered once the rewrite has succeeded.
  const openclawSession = isOpenclawSurface(opts.surface);
  const clearTexts: Array<[string, string]> = [];

  // The prompt filter (confidentiality-plan-15 §3): the user-role text, cut
  // into human / harness / side-call segments by this agent's rules, goes to
  // the arbiter's `filterPrompt`; a registered value in it becomes its symbol.
  // FIRST, so the haystack below is measured on what is actually forwarded.
  // Any failure refuses the request (fail-closed).
  let promptFilter: PromptFilterReport | null;
  try {
    promptFilter = await applyPromptFilter(req, arbiter, {
      agent: segmentAgentFor((opts.surface ?? CLAUDE_CODE_GATE_SURFACE).spec),
      ...(sessionKey ? { sessionKey } : {}),
      ...(opts.log ? { log: opts.log } : {}),
      ...(opts.promptBlockLedger ? { ledger: opts.promptBlockLedger } : {}),
      ...(opts.promptCountOnly ? { countOnly: true } : {}),
      ...(opts.signal ? { signal: opts.signal } : {}),
    });
  } catch (err) {
    if (err instanceof PromptHoldAbandoned) throw new RewriteAbandoned(err.message, err);
    if (err instanceof PromptBlocked) throw new RewriteBlocked(err.message, err.report);
    if (err instanceof PromptFilterRefusal) throw new RewriteRefusal(err.message, err.cause);
    throw err;
  }

  // Trusted-context haystack for the exec-output exact-match upgrade (§4
  // rung 1) — measured ONCE per request, BEFORE the walk below mutates
  // tool_result blocks (the haystack never sees tool_result bytes anyway),
  // and AFTER the prompt filter, with every span it replaced cut out (see
  // buildTrustedContextHaystack).
  const trustedContext = buildTrustedContextHaystack(req, promptFilter?.replaced ?? []);

  // Plan 13 §4.5.1: the agent's own connections to a holder, one batch for
  // every tool_result of the request (fail-closed: a throw refuses).
  const agentReceipt = await agentReceiptMasks(arbiter, messages, correlation, opts.surface ?? CLAUDE_CODE_GATE_SURFACE, sessionKey);

  // Confidentiality §7.1, "Masked after the fact", across a resume: ask the
  // arbiter which of this history's results an earlier launch forwarded in
  // clear (ids only; a failed ask loses a note, never a mask).
  if (opts.clearResults?.prime) {
    const ids: string[] = [];
    for (const msg of messages) {
      if (!Array.isArray(msg.content)) continue;
      for (const block of msg.content) if (isToolResultBlock(block)) ids.push((block as ToolResultBlock).tool_use_id);
    }
    await opts.clearResults.prime(ids);
  }
  // OpenClaw's history redaction across a relaunch (openclaw-redaction.ts):
  // ask the arbiter for the placeholder records of this history's results
  // that may be redacted and that this launch never forwarded (a failed ask
  // loses a restore, never a mask).
  if (openclawSession && opts.forwardedResults?.prime) {
    const results: Array<[string, string]> = [];
    for (const msg of messages) {
      if (!Array.isArray(msg.content)) continue;
      for (const block of msg.content) {
        if (!isToolResultBlock(block)) continue;
        const tr = block as ToolResultBlock;
        if (!hasNonTextBlock(tr.content)) results.push([tr.tool_use_id, flattenToolResultContent(tr.content)]);
      }
    }
    await opts.forwardedResults.prime(results);
  }

  // Walk every tool_result block in every (user) message.
  for (const msg of messages) {
    if (!Array.isArray(msg.content)) continue;
    for (let i = 0; i < msg.content.length; i++) {
      const block = msg.content[i];
      if (!isToolResultBlock(block)) continue;

      const tr = block as ToolResultBlock;
      const ref = correlation.get(tr.tool_use_id);
      // A background notice's stand-in (above): the arbiter is asked under the
      // id of the call that started the work (its process tree, its relay),
      // the ledgers keep the stand-in's own stable id. A notice that could not
      // be tied to its call is masked whole (`bgUnparsed`).
      const bgNotice = bgNotices?.notices.get(tr.tool_use_id);
      const bgUnparsed = bgNotice !== undefined && "unparsed" in bgNotice ? bgNotice : null;
      const callId = bgNotice !== undefined && !("unparsed" in bgNotice) ? bgNotice.callId : tr.tool_use_id;
      // Unknown originating tool → treat as fully untrusted (fail-closed):
      // an attacker could forge a tool_result with no matching tool_use.
      const toolName = ref?.name ?? "__unknown__";
      // A dispatcher call (OpenClaw's `tool_call{id, args}`, dispatch.ts): the
      // PATH-DERIVED confidentiality (origin + params) and the exec-output legs
      // (callTaint, the value backstop) read the INNER tool, as the response
      // side gated it. Trust is still classified under the dispatcher's own
      // name (`toolName`): its result is a wrapped envelope of whatever tool
      // the id resolved to, which no inner-tool rule vouches for (UNTRUSTED,
      // openclaw-inbound.ts). A refused or unparseable call stays as it is.
      const inner = ref ? unwrapDispatch(toolName, ref.input, opts.surface ?? CLAUDE_CODE_GATE_SURFACE) : null;
      const gateTool = inner?.kind === "call" ? inner.name : toolName;
      const input = inner?.kind === "call" ? inner.input : (ref?.input ?? {});
      const origin = ref ? originFor(gateTool, input, opts.surface) : undefined;
      // The same origin in the arbiter's world. Only present when it actually
      // DIFFERS (a view map translated it) — so with no view map, and for any
      // origin the map does not touch (a URL, a path outside every root), the
      // arbiter's requests are byte-identical to before.
      const humanOrigin = origin && toHumanView ? toHumanView(origin) : undefined;
      const originHuman = humanOrigin && humanOrigin !== origin ? humanOrigin : undefined;
      // …and the PATH-ISH PARAMS, for the same reason and it is not redundant: the
      // arbiter's confidentiality derivation takes the MAX over the origin AND
      // these, so an untranslated param keeps hitting the CATALOG on its BASENAME
      // (`.env` survives any prefix translation) and that hit then OVERRIDES the
      // human's label — silently defeating §6's declassification.
      const paramsHuman = toHumanView ? toHumanViewParams(input, toHumanView) : undefined;
      // What a symbol minted for this result is un-rendered against
      // (symbolValueFor): the session agent's spec and the paths the call named.
      const symCtx: SymbolValueContext = {
        spec: (opts.surface ?? CLAUDE_CODE_GATE_SURFACE).spec,
        paths: [origin, originHuman, input["filePath"], input["path"]].filter((p): p is string => typeof p === "string"),
      };

      // Secret-discovery.md §2.8, "A document block": a PDF the result carries
      // as a `document` block (Claude Code's `Read` of a `.pdf`) is forwarded
      // as the text the arbiter reads in it, so what reaches the model is
      // exactly what the classify below judges; with no text (a scan, a
      // password, an arbiter without the op, a throw) the block stays and
      // the result is masked whole, as before.
      if (Array.isArray(tr.content) && arbiter.documentText && tr.content.some(isPdfDocumentBlock)) {
        const asText = await pdfBlocksAsText(tr.content, arbiter, {
          ...(originHuman ?? origin ? { origin: originHuman ?? origin } : {}),
          ...(sessionKey ? { sessionKey } : {}),
          claudeRead: toolName === "Read" && gateTool === "Read" && (opts.surface ?? CLAUDE_CODE_GATE_SURFACE).spec === "claude-code",
          ...(opts.log ? { log: opts.log } : {}),
        });
        if (asText !== null) tr.content = asText;
      }
      let value = flattenToolResultContent(tr.content);
      const nonText = hasNonTextBlock(tr.content);
      // OpenClaw's history redaction (openclaw-redaction.ts): a result this
      // proxy forwarded in clear comes back with its placeholders cut to
      // `$MDU:n…_KEY`. Put the forwarded text back BEFORE anything judges it,
      // so every check below decides it as it did the first time.
      if (openclawSession && !nonText && opts.forwardedResults) {
        const before = opts.forwardedResults.restore(tr.tool_use_id, value);
        if (before !== undefined) {
          tr.content = typeof tr.content === "string" || tr.content == null ? before : [{ type: "text", text: before } as ToolResultContentBlock];
          value = before;
          opts.log?.(`openclaw-redaction: ${tr.tool_use_id}: OpenClaw's history redaction of a result forwarded in clear is put back before it is judged`);
        }
      }
      // Plan 10 §11.14 (2026-10-09): a background-task poll's result starts
      // with the status tags Claude Code writes (`<status>`, `<exit_code>`,
      // `<retrieval_status>`, …). A symbol minted for the result from its
      // start names them, so the arbiter, matching its own grammar at offset
      // 0, does not register those tag lines as lines of the secret value.
      // Plan 15 §13.10 (2026-10-11): a write tool's result starts with its
      // fixed success notice (OpenCode's diagnostics, a reminder come after
      // it), named the same way, so the notice line never becomes a piece of
      // the row and masks the agent's later notices.
      const pollHead: { resultHead?: "claude-task" | "write-notice" } =
        ref === undefined || nonText || gateTool !== toolName ? {}
          : CLAUDE_TASK_POLL_TOOLS.has(toolName) ? { resultHead: "claude-task" }
            : WRITE_NOTICE_RESULT_TOOLS.has(toolName) ? { resultHead: "write-notice" } : {};

      // Why this result is masked whole whatever any verdict says (null:
      // it is not): an OpenCode 2 notice that could not be tied to its call,
      // or a moved shell's result whose output file could not be labelled.
      let maskWhy: string | null = bgUnparsed
        ? `a background ${bgUnparsed.kind === "usershell" ? "shell the user ran" : bgUnparsed.kind}'s output that Mandu could not read as its tool's output (${bgUnparsed.why}); the whole notice is secret`
        : null;
      // supported-agents.md §2.3 item 7: OpenCode 2's moved shell names the
      // file its output streams to (`$XDG_DATA_HOME/opencode/shell/<hash>/
      // sh_<id>.out`), which nothing labels. Labelled `no-model` for this
      // session BEFORE the model reads the name, so a later `read` of it or
      // a shell command naming it is masked as a labelled file's (both
      // spellings when a view map translates it). Not labelled (no op, a
      // throw, no absolute path): the result is masked whole instead, so the
      // model never learns where the unprotected output is.
      if (bgNotices && !nonText && Object.prototype.hasOwnProperty.call((opts.surface ?? CLAUDE_CODE_GATE_SURFACE).exec, gateTool)) {
        // Read off the FIRST text block: 2.0.23 sends the path at the end of
        // it and its notification advice as a second block, which the
        // flattened value joins on with no separator.
        const first = typeof tr.content === "string"
          ? tr.content
          : (tr.content ?? []).find((b) => b && b.type === "text" && typeof b.text === "string")?.text ?? "";
        const out = movedOutputPath(first);
        if (out && "bad" in out) {
          maskWhy = `${out.bad}; the result is secret`;
        } else if (out) {
          const spellings = [...new Set([out.path, toHumanView ? toHumanView(out.path) : out.path])];
          try {
            if (!arbiter.sessionPathLabel) throw new Error("the arbiter has no sessionPathLabel op");
            for (const sp of spellings) {
              const r = await arbiter.sessionPathLabel({ path: sp, sessionKey: sessionKey ?? "unbound", reason: `OpenCode background output of ${callId}` });
              if (!r.labeled) throw new Error(`not labelled: ${sp}`);
            }
          } catch (err) {
            opts.log?.(`background output ${out.path}: could not label it (${(err as Error).message}); the result naming it is masked whole`);
            maskWhy = "the background output file this result names could not be protected; the result is secret";
          }
        }
      }

      // Mandu's denials that leave the tool nothing real to act on (plan 10
      // §11.8; path-denial-notice.ts ResultNotices): every path rewritten to
      // a sentinel, a network call pointed at the blocked host, a call
      // refused whole. Its result is only its error about that, and is
      // REPLACED by the proxy's notice; nothing the tool said is forwarded,
      // filtered or not. The value backstop must find no
      // registered value in the notice; otherwise the result takes the
      // classify path below, as before.
      const pathNotice = opts.resultNotices?.noticeFor(tr.tool_use_id);
      if (pathNotice !== undefined) {
        let clean = false;
        if (arbiter.scanSecretValues) {
          try {
            clean = (await arbiter.scanSecretValues(pathNotice)).hits.length === 0;
          } catch (err) {
            opts.log?.(`result notice ${tr.tool_use_id}: the value backstop failed (${(err as Error).message}); the result is classified`);
          }
        }
        if (clean) {
          if (typeof tr.content === "string" || tr.content == null) {
            tr.content = pathNotice;
          } else {
            tr.content = [{ type: "text", text: pathNotice } as ToolResultContentBlock];
          }
          rewrites.push({
            toolUseId: tr.tool_use_id,
            tool: toolName,
            trust: "TRUSTED",
            symbolized: false,
            value,
            origin,
            forwardedText: pathNotice,
            reason: "mandu notice: Mandu denied what the call needed (every path, its network request, or the call whole); the result is replaced by Mandu's notice, no byte of the tool's output forwarded (plan 10 §11.8)",
          });
          continue;
        }
      }
      // Genuinely empty AND no non-text payload → nothing to classify/symbolize.
      // (An image-only result has value="" but nonText=true: it must NOT skip.)
      if (value === "" && !nonText) {
        rewrites.push({
          toolUseId: tr.tool_use_id,
          tool: toolName,
          trust: "TRUSTED",
          symbolized: false,
          value,
          origin,
        });
        continue;
      }

      // The exec gate's own notice (plan 10 §11.8; exec-gate.ts
      // ExecGateNotices): a call this proxy rewrote to the block sentinel
      // returns the notice the proxy composed, which the model already reads
      // in its own (rewritten) tool_use. The classify verdict cannot tell: it
      // scans the sentinel command for paths, and a notice saying "secret"
      // matches the catalog. Forwarded in clear ONLY when the body is exactly
      // the sentinel's output and the value backstop finds no registered
      // value in it; the forwarded text is the proxy's own notice, never the
      // received bytes. Any other result takes the classify path below, so a
      // program's output never rides this exit. Trailing reminder blocks are
      // dropped (never raw, never a decoy symbol).
      const gateNotice = nonText ? undefined : opts.execGateNotices?.noticeFor(tr.tool_use_id);
      if (gateNotice !== undefined) {
        const split = splitTrailingSystemReminders(value);
        const notice = gateNoticeResult(split ? split.body : value, gateNotice);
        let clean = false;
        if (notice !== null && arbiter.scanSecretValues) {
          try {
            clean = (await arbiter.scanSecretValues(notice)).hits.length === 0;
          } catch (err) {
            opts.log?.(`exec-gate notice ${tr.tool_use_id}: the value backstop failed (${(err as Error).message}); the result is classified`);
          }
        }
        if (notice !== null && clean) {
          if (typeof tr.content === "string" || tr.content == null) {
            tr.content = notice;
          } else {
            tr.content = [{ type: "text", text: notice } as ToolResultContentBlock];
          }
          rewrites.push({
            toolUseId: tr.tool_use_id,
            tool: toolName,
            trust: "TRUSTED",
            symbolized: false,
            value,
            origin,
            forwardedText: notice,
            ...(split ? { droppedTail: split.tail } : {}),
            reason: "exec gate notice: the result is exactly the block sentinel's output, Mandu's own text, forwarded in clear (plan 10 §11.8)" +
              (split ? "; trailing <system-reminder> block(s) dropped" : ""),
          });
          continue;
        }
      }

      // Plan 10 §4.2: the confidentiality taint of the process tree behind a
      // Bash call (applied below). Asked BEFORE classify (2026-10-04): this
      // ask, on the human socket, is what binds the call to its shell, and
      // classify reads the directory that shell started in off that binding
      // (`callStartDir`, confidentiality.md §6) to read the command's
      // relative paths where the kernel says it ran.
      const egress: { refused?: RefusedEgress[]; blocked?: Array<{ app: string; kind: string }> } = {};
      // A background poll tied to the Bash call that started its task
      // (claudeBackgroundPolls) is answered by that call's process tree,
      // raise-only (no denied-only or twin release); an untied poll is asked
      // with no command, so the session decides (plan 13 D7).
      const poll = bgNotice === undefined && gateTool === toolName ? bgPolls.get(tr.tool_use_id) : undefined;
      let secretTaint = poll
        ? raiseOnly(await secretTaintFor(arbiter, poll.name, poll.callId, poll.input, sessionKey, value, opts.log, opts.surface, egress, tr.tool_use_id))
        : await secretTaintFor(arbiter, gateTool, callId, input, sessionKey, value, opts.log, opts.surface, egress);
      if (maskWhy !== null) {
        secretTaint = { level: "no-model", files: [], apps: [], rule: "secret", maskWhole: true, denied: [], deniedOnly: false, why: maskWhy };
      }

      // A relative typed path is read where the agent reads it (the launch
      // directory; confidentiality.md §6), for a tool whose path fields the
      // surface names; never for a dispatched call (its params are the inner
      // tool's, while `tool` is the dispatcher's). Every classify of this
      // result carries it, so the body / tail re-asks agree with the verdict,
      // and so does every symbolize of its bytes: the arbiter stores the row
      // at the resolved path, whose label then gives it its bindings too
      // (2026-10-10: without it the row kept the relative origin, which no
      // label matches, and a declassify left the session bound nowhere).
      const relBase: { relativeBase?: string } = opts.relativeBase && gateTool === toolName &&
          Object.prototype.hasOwnProperty.call((opts.surface ?? CLAUDE_CODE_GATE_SURFACE).paths, toolName)
        ? { relativeBase: opts.relativeBase }
        : {};

      let verdict;
      try {
        verdict = await arbiter.classify({
          tool: toolName,
          value,
          boundary: "model_context",
          origin,
          ...(originHuman ? { originHuman } : {}),
          ...(paramsHuman ? { paramsHuman } : {}),
          ...(spanVerbatimInTrustedContext(trustedContext, value)
            ? { verbatimInTrustedContext: true }
            : {}),
          ...(sessionKey ? { sessionKey } : {}),
          ...relBase,
          callId,
          params: input,
        });
      } catch (err) {
        throw new RewriteRefusal(
          `arbiter classify failed for tool_use_id=${tr.tool_use_id} (tool=${toolName}) — refusing to forward un-symbolized content`,
          err,
        );
      }
      // Plan 15 §4.1: the verdict as the arbiter answered it, before any raise
      // of this proxy's own (`secretBy` below).
      const classified = verdict;

      // A result carrying any non-text block (image, etc.) is forced UNTRUSTED:
      // the text-only classification cannot vouch for those bytes, so we never
      // forward them raw (mandu.md §1 — completeness of ingress instrumentation).
      const untrusted = verdict.trust === "UNTRUSTED" || nonText;
      // Confidentiality (plan 3, §7 row ①): a secret-labeled datum is
      // symbolized EVEN when integrity-TRUSTED — the model provider must not
      // read it. The arbiter's switch governs this transparently: with the
      // axis OFF the classify result carries no confidentiality field, so
      // `secret` is false and this proxy behaves byte-identically to today.
      // Plan 10 §4.2: the confidentiality taint of the process tree behind a
      // Bash call. A tainted tree under rule (i) makes the WHOLE result a
      // secret datum at the taint's level (the classify verdict is raised,
      // never lowered by a taint); rule (ii)/(iii) release it unless the
      // verbatim-value backstop (or a mask regex) hits. A tree that read NO
      // secret and had an open refused is the one lowering: the classify
      // verdict's path-derived level (the command NAMES the file, e.g.
      // `cat .env` → no-model) guarded against the read the guard has
      // just refused, so with the backstop clean the program's own failure
      // text goes through and the denied/held note explains it (§11.8).
      // (`secretTaint` was asked above, before classify.)
      // Plan 13 §4.5.1: what the agent itself received from a holder during
      // the call. Raise-only: it replaces a release (denied-only, twin) and
      // raises a mask's level.
      const viaAgent = agentReceipt.get(tr.tool_use_id) ?? (callId !== tr.tool_use_id ? agentReceipt.get(callId) : undefined);
      if (viaAgent) {
        secretTaint = secretTaint?.maskWhole
          ? { ...secretTaint, level: stricterLevel(secretTaint.level, viaAgent.level), why: `${secretTaint.why}; ${viaAgent.why}` }
          : viaAgent;
      }
      // Plan 10 §11.8, "Refused connections": the egress proxy refused a
      // connection from this call's tree. Explains only (the note), never a
      // release: maskWhole, deniedOnly and twinOnly are untouched.
      if (egress.refused && egress.refused.length > 0) {
        secretTaint = secretTaint
          ? { ...secretTaint, refusedEgress: egress.refused }
          : { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, refusedEgress: egress.refused, why: "a connection from the command was refused" };
      }
      // Plan 10 §11.8, "Blocked commands": the exec-wrap shim refused a
      // command of this call's tree before it ran. Explains only, like the
      // refused connections above.
      if (egress.blocked && egress.blocked.length > 0) {
        secretTaint = secretTaint
          ? { ...secretTaint, blockedExec: egress.blocked }
          : { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, blockedExec: egress.blocked, why: "a command was blocked before it ran" };
      }
      if (secretTaint?.maskWhole) {
        verdict = { ...verdict, confidentiality: stricterLevel(verdict.confidentiality, secretTaint.level), reason: `${verdict.reason}; ${secretTaint.why}` };
      } else if ((secretTaint?.deniedOnly || secretTaint?.twinOnly) && isSecretLevel(verdict.confidentiality)) {
        const { confidentiality: lowered, ...rest } = verdict;
        verdict = { ...rest, reason: `${verdict.reason}; plan 10: the ${lowered} path-derived mask is lowered (${secretTaint.why})` };
      } else if (secretTaint?.twinOnly && (secretTaint.twinKeys || secretTaint.twinOwn || secretTaint.dirListing)) {
        // "A key listing" (plan 10 §11.8): nothing was masked (the
        // command names no secret path), so there is nothing to lower and
        // no `twin:` line to add to a result that merely reads like keys.
        // "A folder's names": likewise, an `ls` of folders no label covers
        // is forwarded as it is, with no `listing:` line.
        secretTaint = { ...secretTaint, twinOnly: false };
      }
      // clean-tree-release.md §2, rules Q1-Q3: the arbiter's release of a
      // shell result masked only because its command names a registered
      // credential file (`git rm --cached .env`), taken only on this proxy's
      // own evidence (the value-only release's P2). With no span the verdict
      // is lowered and the result is forwarded as received, with no note;
      // with spans it goes as a value-only release (below).
      let pathOffer: ReturnType<typeof acceptPathReleaseOffer> = null;
      // Review round 3: a release is not recorded as forwarded in clear (as the
      // value-only release is not, backstop-value-only.md §4 item 6), or the
      // next request's re-classify of the history would refuse it as masked
      // after the fact and turn it into a symbol.
      let pathReleased = false;
      if (isSecretLevel(verdict.confidentiality) && !untrusted && !nonText && maskWhy === null && !viaAgent &&
          classified.raisedBy === undefined && verdict.confidentiality === classified.confidentiality &&
          valueOnlyEvidenceClean(secretTaint) && opts.clearResults?.wasClear(tr.tool_use_id) !== true) {
        pathOffer = acceptPathReleaseOffer(value, classified);
        if (pathOffer !== null && pathOffer.values.length === 0) {
          pathReleased = true;
          if (pathOffer.listing) {
            // folder-listing-compound.md: the `listing:` line, naming the operands
            // the model's own command holds verbatim
            const command = callCommandText(gateTool, input, opts.surface) ?? "";
            const operands = pathOffer.listing.operands.filter((x) => command.includes(x)).slice(0, 8);
            secretTaint = {
              level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false,
              twinOf: operands.length > 0 ? operands : ["the folders it named"], twinOnly: true, dirListing: true, dirListingPart: pathOffer.listing.part,
              why: "a folder's names beside another command",
            };
          }
          const { confidentiality: lowered, ...rest } = verdict;
          verdict = { ...rest, reason: pathOffer.listing
            ? `${verdict.reason}; a folder's names beside another command: the ${lowered} path-derived mask is lowered (the call's recorded tree read no secret, the ${pathOffer.listing.part} lines are exactly ls's names, and the other commands name no secret path)`
            : `${verdict.reason}; clean-tree release: the ${lowered} path-derived mask is lowered (the call's recorded tree read no secret, and the output holds no secret byte of the credential files the command names)` };
          pathOffer = null;
        }
      }
      const secret = isSecretLevel(verdict.confidentiality);
      // Plan 15 §4.1, "What a raised row registers": the result is secret
      // only by the arbiter's value backstop (its classify says so) and this
      // proxy raised it no further (no taint or agent-receipt mask). Said on
      // the symbolize, so the arbiter may register only the lines a secret
      // was found in; it checks its own record before it does.
      // Plan 15 §13.12, "What a path row registers": secret only by the
      // classify's own path-derived level (no backstop raise) and raised no
      // further here (no taint, agent-receipt or harness mask). The arbiter
      // checks its own records before it registers fewer lines; the mask is
      // unchanged.
      const backstopOnly: { secretBy?: "value-backstop" | "path-rule" } =
        secret && !nonText && classified.raisedBy === "value-backstop" && !secretTaint?.maskWhole &&
        verdict.confidentiality === classified.confidentiality
          ? { secretBy: "value-backstop" }
          : secret && !nonText && classified.raisedBy === undefined && isSecretLevel(classified.confidentiality) &&
              !secretTaint?.maskWhole && verdict.confidentiality === classified.confidentiality
            ? { secretBy: "path-rule" }
            : {};
      // backstop-value-only.md §3: the arbiter's value-only offer, taken only
      // when this proxy's own evidence says the call read no secret (rules
      // P1-P3). Otherwise the result is masked whole below, as before.
      // A clean-tree release with spans (above) takes the same exit.
      const offer = pathOffer ?? (secret && !untrusted && !nonText && maskWhy === null && !viaAgent &&
          classified.raisedBy === "value-backstop" && verdict.confidentiality === classified.confidentiality &&
          valueOnlyEvidenceClean(secretTaint) && opts.clearResults?.wasClear(tr.tool_use_id) !== true
        ? acceptValueOnlyOffer(value, classified)
        : null);
      if (offer !== null) {
        if (typeof tr.content === "string" || tr.content == null) {
          tr.content = offer.text;
        } else {
          tr.content = [{ type: "text", text: offer.text } as ToolResultContentBlock];
        }
        rewrites.push({
          toolUseId: tr.tool_use_id,
          tool: toolName,
          trust: verdict.trust,
          symbolized: true,
          symbol: offer.values[0]!.symbol,
          value,
          forwardedText: offer.text,
          valueOnly: offer.values,
          origin,
          reason: `${verdict.reason}; ${pathOffer !== null ? "clean-tree" : "value-only"} release: ${offer.values.length} registered value(s) replaced by their symbols, the rest released`,
          ...(verdict.confidentiality ? { confidentiality: verdict.confidentiality } : {}),
        });
        continue;
      }
      // Confidentiality §7.1, the path-derived note: a command's result
      // masked whole only because the command NAMES a secret path (no taint
      // answer masked it) used to reach the model as a bare symbol with
      // `is_error` cleared, so the model guessed it had worked. The note says
      // why, naming the paths as the model wrote them; no output byte.
      // The value-backstop note (2026-10-17): a result the arbiter's value
      // backstop raised (a registered secret's value in an old log, a file
      // the path rules call public) names no secret path, and the
      // path-derived advice ("run the part that names no secret file
      // apart") sent the model in circles. It gets its own line, on any
      // tool: a Read is masked whole the same way.
      if (secret && !secretTaint?.maskWhole && classified.raisedBy === "value-backstop") {
        secretTaint = secretTaint
          ? { ...secretTaint, valueBackstop: true }
          : { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, valueBackstop: true, why: "a registered secret's value is in the output" };
      } else if (secret && !secretTaint?.maskWhole) {
        const command = callCommandText(gateTool, input, opts.surface);
        if (command !== null) {
          const paths = pathDerivedPaths(verdict.namedPaths, command);
          const twins = pathDerivedTwins(verdict.namedTwins, paths);
          const pathDerived = twins.length > 0 ? { paths, twins } : { paths };
          secretTaint = secretTaint
            ? { ...secretTaint, pathDerived }
            : { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, pathDerived, why: "the command names a secret path" };
        }
      }
      // Plan 13 §9 R4: a secret result is replaced by its symbol, and the
      // block's `is_error` flag is the one fact about the run left beside it
      // (the exit status, chosen by the code that held the secret: one bit a
      // call). Every secret result carries `is_error: false`; the model learns
      // that a masked command failed only from the user. Fail-closed: cleared
      // before any path below can forward the block.
      if (secret && tr.is_error !== undefined && tr.is_error !== false) tr.is_error = false;
      // Confidentiality §7.1, "Masked after the fact": this result's body went
      // to the model in clear in an earlier request and is masked now (a label
      // or a registration since). The mask stands; a note says the model did
      // read it. The path-derived line ("do not assume it worked") is for a
      // result never seen, so it gives way to this one.
      const afterFact = secret && opts.clearResults?.wasClear(tr.tool_use_id) === true;
      if (afterFact && (secretTaint?.pathDerived || secretTaint?.valueBackstop)) {
        const { pathDerived: _dropped, valueBackstop: _dropped2, ...rest } = secretTaint;
        secretTaint = rest;
      }
      const afterFactLine = afterFact
        ? afterTheFactLine({
            taintCause: secretTaint?.maskWhole === true,
            harnessRead: toolName === "Read" && (opts.surface ?? CLAUDE_CODE_GATE_SURFACE).spec === "claude-code",
          })
        : null;

      if (untrusted || secret) {
        // Companion to the arbiter's fail-closed shape rules (e.g. the inspect
        // pure-symbolic gate): Claude Code APPENDS <system-reminder> blocks to a
        // tool's own output, which would otherwise drag a TRUSTED-shaped body
        // into whole-result symbolization (double-wrap). Split the trailing
        // reminder blocks off, ask the arbiter about the BODY alone, and forward
        // it raw ONLY on a TRUSTED verdict. The tail then gets ITS own arbiter
        // verdict: only the harness token-budget reminder shape classifies
        // TRUSTED (digits-only channel — see claude-code-inbound.ts); every
        // other tail is symbolized. The trusted-forwarding bar is set by the
        // arbiter on both spans; a body the arbiter still distrusts falls
        // through to the whole-result path below. Skipped for non-text results
        // (the flatten cannot vouch for the non-text bytes regardless of shape)
        // AND (this raw-forward half) for secret results: its exits are
        // integrity-only verdicts — a secret body must never forward raw. The
        // untrusted-body dual below still peels a trusted budget tail off a
        // secret body: the body is symbolized (with its label), never raw.
        const split = nonText ? null : splitTrailingSystemReminders(value);
        if (split && !secret) {
          let bodyVerdict: ClassifyResult | null = null;
          try {
            bodyVerdict = await arbiter.classify({
              tool: toolName,
              value: split.body,
              boundary: "model_context",
              origin,
              ...(originHuman ? { originHuman } : {}),
              ...(paramsHuman ? { paramsHuman } : {}),
              ...(spanVerbatimInTrustedContext(trustedContext, split.body)
                ? { verbatimInTrustedContext: true }
                : {}),
              ...(sessionKey ? { sessionKey } : {}),
              ...relBase,
              callId,
              params: input,
            });
          } catch {
            // The whole-result verdict above already succeeded; a failing body
            // re-classify degrades to the STRICTLY SAFER whole-result
            // symbolization below rather than refusing the request.
            bodyVerdict = null;
          }
          if (bodyVerdict?.trust === "TRUSTED") {
            // The tail is classified on ITS own bytes too: the arbiter trusts
            // exactly one tail shape — the harness token-budget reminder
            // (claude-code-inbound.ts isHarnessTokenBudgetReminder; anchored,
            // digits-only). A trusted tail means the WHOLE result passes
            // unchanged: symbolizing it minted a DECOY token next to the real
            // result symbol in every tool_result (the harness appends the
            // budget reminder to all of them), and a weak T-LLM answered with
            // the decoy. A classify failure keeps the strictly safer
            // symbolize-the-tail path.
            let tailVerdict: ClassifyResult | null = null;
            try {
              tailVerdict = await arbiter.classify({
                tool: toolName,
                value: split.tail,
                boundary: "model_context",
                origin,
                ...(originHuman ? { originHuman } : {}),
                ...(paramsHuman ? { paramsHuman } : {}),
                ...(spanVerbatimInTrustedContext(trustedContext, split.tail)
                  ? { verbatimInTrustedContext: true }
                  : {}),
                ...(sessionKey ? { sessionKey } : {}),
                ...relBase,
                callId,
                params: input,
              });
            } catch {
              tailVerdict = null;
            }
            if (tailVerdict?.trust === "TRUSTED") {
              clearIds.push(tr.tool_use_id);
              rewrites.push({
                toolUseId: tr.tool_use_id,
                tool: toolName,
                trust: "TRUSTED",
                symbolized: false,
                value,
                origin,
                reason: `${bodyVerdict.reason}; trailing tail: ${tailVerdict.reason}`,
              });
              continue;
            }
            let tailSymbol: string;
            try {
              // Symbolized under "system_reminder", NOT the tool name: the
              // tail is agent-runtime framing (or a forgery of it), not the
              // tool's output, and a tool-tagged mint ($MDU:inspect[…])
              // masquerades as the tool's result — the exact decoy confusion
              // above. The full provenance keeps the tool_use_id via callId.
              tailSymbol = await arbiter.symbolize({
                tool: "system_reminder",
                value: split.tail,
                origin,
                ...(originHuman ? { originHuman } : {}),
                callId,
                sessionKey,
              });
            } catch (err) {
              throw new RewriteRefusal(
                `arbiter symbolize failed for tool_use_id=${tr.tool_use_id} (tool=${toolName}) — refusing to forward un-symbolized content`,
                err,
              );
            }
            const forwarded = `${split.body}\n\n${tailSymbol}`;
            clearIds.push(tr.tool_use_id);
            if (typeof tr.content === "string" || tr.content == null) {
              tr.content = forwarded;
            } else {
              tr.content = [{ type: "text", text: forwarded } as ToolResultContentBlock];
            }
            rewrites.push({
              toolUseId: tr.tool_use_id,
              tool: toolName,
              trust: "TRUSTED",
              symbolized: true,
              symbol: tailSymbol,
              value,
              symbolizedSpan: split.tail,
              keptVerbatim: split.body,
              forwardedText: forwarded,
              origin,
              reason:
                `${bodyVerdict.reason}; trailing <system-reminder> block(s) appended ` +
                "by the agent runtime symbolized separately (fail-closed)",
            });
            continue;
          }
        }
        if (split) {
          // THE UNTRUSTED-BODY DUAL of the split above (2026-09-05). Claude Code
          // ≥2.1.25x appends the token-budget reminder to EVERY tool_result, and
          // an untrusted body (any workspace Read, any Bash output — the common
          // case) used to fall through to whole-result symbolization with the
          // reminder INSIDE the symbol's value. Three regressions rode on that:
          // T-LLM lost its budget reminder on almost every turn; the resolved
          // value (fs-sync HumanView, the reply-filter's terminal) carried
          // `<system-reminder><total_tokens>…` junk — and became MULTI-LINE, so
          // a one-line file rendered as a clipped frame-safe row; and the same
          // content minted a different symbol every turn (the count varies).
          // So: when the arbiter classifies the TAIL trusted (exactly the
          // digits-only budget shape — claude-code-inbound.ts), symbolize the
          // BODY alone and forward the tail verbatim. The body is never
          // forwarded raw here (it is the symbol); a tail the arbiter does not
          // vouch for is dropped (a forgeable reminder never survives raw —
          // see below). Secret bodies take this path too — the tail is digits
          // or gone, the body is symbolized with its label.
          let tailVerdict: ClassifyResult | null = null;
          try {
            tailVerdict = await arbiter.classify({
              tool: toolName,
              value: split.tail,
              boundary: "model_context",
              origin,
              ...(originHuman ? { originHuman } : {}),
              ...(paramsHuman ? { paramsHuman } : {}),
              ...(sessionKey ? { sessionKey } : {}),
              ...relBase,
              callId,
              params: input,
            });
          } catch {
            tailVerdict = null; // strictly safer: the whole result symbolizes
          }
          {
            // A tail the arbiter vouches for (exactly the digits-only budget
            // shape) stays on the wire verbatim. ANY OTHER complete trailing
            // reminder block (2026-09-21) is DROPPED from the forwarded
            // result and kept out of the body symbol's value. Live (drills
            // U17/U25): Claude Code appends its "MCP Server Instructions"
            // reminder to a session's first tool_result; it rode inside the
            // Read symbol, so a model copying the file by its symbol wrote the
            // whole reminder into the user's file. Why dropped, not symbolized
            // on its own: T-LLM could not read it either way, and a second
            // token beside the result is the DECOY this file already paid for
            // once (a weak T-LLM answers with it — see the trusted-body split
            // above). Nothing is lost to the audit: `value` keeps the wire
            // bytes and `droppedTail` names what was cut. A forged reminder in
            // a tool's own output is cut the same way — attacker bytes removed.
            const tailTrusted =
              tailVerdict?.trust === "TRUSTED" && !isSecretLevel(tailVerdict.confidentiality);
            // The harness's separator whitespace before the reminder is
            // framing, not tool output: it stays on the wire (between the
            // symbol and the tail) and out of the symbol's value, so a
            // one-line output stays a one-line value.
            const bodyText = split.body.replace(/\s+$/, "");
            const sep = split.body.slice(bodyText.length);
            const bodyValue = symbolValueFor(toolName, bodyText, symCtx);
            let bodySymbol: string;
            try {
              bodySymbol = await arbiter.symbolize({
                tool: toolName,
                value: bodyValue,
                origin,
                ...(originHuman ? { originHuman } : {}),
                ...relBase,
                callId,
                sessionKey,
                ...pollHead,
                ...backstopOnly,
                ...(secret
                  ? {
                      confidentiality: verdict.confidentiality,
                      integrity: !untrusted ? "trusted" : "untrusted",
                    }
                  : {}),
              });
            } catch (err) {
              throw new RewriteRefusal(
                `arbiter symbolize failed for tool_use_id=${tr.tool_use_id} (tool=${toolName}) — refusing to forward un-symbolized content`,
                err,
              );
            }
            const forwarded = tailTrusted ? `${bodySymbol}${sep}${split.tail}` : bodySymbol;
            if (typeof tr.content === "string" || tr.content == null) {
              tr.content = forwarded;
            } else {
              tr.content = [{ type: "text", text: forwarded } as ToolResultContentBlock];
            }
            rewrites.push({
              toolUseId: tr.tool_use_id,
              tool: toolName,
              trust: untrusted ? "UNTRUSTED" : "TRUSTED",
              symbolized: true,
              symbol: bodySymbol,
              value,
              symbolizedSpan: bodyText,
              ...(bodyValue !== bodyText ? { symbolValue: bodyValue } : {}),
              ...(tailTrusted ? { keptVerbatim: split.tail } : { droppedTail: split.tail }),
              forwardedText: forwarded,
              origin,
              ...(secret ? { confidentiality: verdict.confidentiality } : {}),
              reason:
                (!untrusted && secret
                  ? `secret content (${verdict.confidentiality}) symbolized by provenance: ${verdict.reason}`
                  : verdict.reason) +
                (tailTrusted
                  ? `; harness token-budget reminder tail kept verbatim (${tailVerdict!.reason})`
                  : "; trailing <system-reminder> block(s) the arbiter does not vouch for dropped from the forwarded result (never raw, never a decoy symbol)") +
                (bodyValue !== bodyText ? "; Read rendering un-numbered: the symbol stands for the file's bytes" : ""),
            });
            await appendTwinNote(tr, rewrites[rewrites.length - 1]!, input, agentViewRoots, toHumanView, arbiter, twinHintCache, opts.log, opts.surface);
            appendSecretNote(tr, rewrites[rewrites.length - 1]!, secretTaint);
            if (afterFactLine) appendAfterTheFactNote(tr, rewrites[rewrites.length - 1]!, afterFactLine);
            continue;
          }
        }
        // Value to symbolize: for a non-text result, serialize the WHOLE content so
        // the original bytes (image base64 etc.) are preserved in the arbiter symbol
        // table for HumanView/audit — never the text-only `value` (possibly "").
        // A Claude Code Read stores the FILE's bytes, not the numbered rendering
        // (unrenderReadResult); `value` stays the wire span for the oracle.
        const symValue = nonText ? serializeToolResultContent(tr.content) : symbolValueFor(toolName, value, symCtx);
        let symbol: string;
        try {
          symbol = await arbiter.symbolize({
            tool: toolName,
            value: symValue,
            origin,
            ...(originHuman ? { originHuman } : {}),
            // The row is placed where the agent read it (a relative typed
            // path in the launch directory, the base the classify above
            // read it in), so its bindings are the human's label's for
            // that file (confidentiality.md §6, 2026-10-10).
            ...relBase,
            callId,
            sessionKey,
            ...pollHead,
            ...backstopOnly,
            // Secret labels ride along (the arbiter re-derives and takes max;
            // this also covers classify-time param sources the symbolize op
            // cannot see). Integrity is "trusted" ONLY when the whole-result
            // verdict vouched for text-only bytes — that is what later lets
            // the egress gate release the datum at its bound destination.
            ...(secret
              ? {
                  confidentiality: verdict.confidentiality,
                  integrity: !untrusted ? "trusted" : "untrusted",
                }
              : {}),
          });
        } catch (err) {
          throw new RewriteRefusal(
            `arbiter symbolize failed for tool_use_id=${tr.tool_use_id} (tool=${toolName}) — refusing to forward un-symbolized content`,
            err,
          );
        }
        // Replace the content with the opaque symbol. Preserve the string-vs-
        // array shape: if the original was an array of blocks, keep a single
        // text block carrying the symbol (drops attacker text AND any non-text
        // block such as an image; keeps the structure valid).
        if (typeof tr.content === "string" || tr.content == null) {
          tr.content = symbol;
        } else {
          const replacement: ToolResultContentBlock = { type: "text", text: symbol };
          tr.content = [replacement];
        }
        rewrites.push({
          toolUseId: tr.tool_use_id,
          tool: toolName,
          // A TRUSTED×secret result keeps its integrity verdict on the audit
          // — it was symbolized by PROVENANCE (confidentiality), not distrust.
          trust: untrusted ? "UNTRUSTED" : "TRUSTED",
          symbolized: true,
          symbol,
          value: nonText ? symValue : value,
          ...(!nonText && symValue !== value ? { symbolValue: symValue } : {}),
          origin,
          ...(secret ? { confidentiality: verdict.confidentiality } : {}),
          reason:
            !untrusted && secret
              ? `secret content (${verdict.confidentiality}) symbolized by provenance: ${verdict.reason}`
              : nonText && verdict.trust !== "UNTRUSTED"
                ? "non-text tool_result content forced UNTRUSTED"
                : verdict.reason,
        });
        await appendTwinNote(tr, rewrites[rewrites.length - 1]!, input, agentViewRoots, toHumanView, arbiter, twinHintCache, opts.log, opts.surface);
        appendSecretNote(tr, rewrites[rewrites.length - 1]!, secretTaint);
        if (afterFactLine) appendAfterTheFactNote(tr, rewrites[rewrites.length - 1]!, afterFactLine);
      } else {
        // TRUSTED → pass through unchanged.
        if (!pathReleased) {
          clearIds.push(tr.tool_use_id);
          if (openclawSession && !nonText) clearTexts.push([tr.tool_use_id, value]);
        }
        rewrites.push({
          toolUseId: tr.tool_use_id,
          tool: toolName,
          trust: "TRUSTED",
          symbolized: false,
          value,
          origin,
          reason: verdict.reason,
        });
        appendSecretNote(tr, rewrites[rewrites.length - 1]!, secretTaint);
      }
    }
  }

  // The background notices go back as OpenCode's text, carrying what the
  // walk above made of their bodies.
  if (bgNotices) restoreBackgroundNotices(bgNotices);

  // Inject the handling system prompt (unless told to skip or already present).
  if (!skipPromptInjection && !alreadyInjected(req.system)) {
    let prompt: string;
    try {
      const r = await arbiter.handlingPrompt({
        ...(handlingMode ? { mode: handlingMode } : {}),
        capabilities: detectCapabilities(req.tools, {
          fsView: (agentViewRoots?.length ?? 0) > 0,
          ...(opts.secretPosture ? { secretPosture: opts.secretPosture } : {}),
        }, opts.surface?.exec),
        // Plan 11 phase 3: the arbiter reads this session's main-model binding
        // to say whether declassify_symbol can open a localmodel_ symbol.
        ...(sessionKey ? { sessionKey } : {}),
      });
      prompt = r.prompt;
    } catch (err) {
      throw new RewriteRefusal(
        "arbiter handlingPrompt failed — refusing to forward (T-LLM would not know symbols are opaque)",
        err,
      );
    }
    const block = makeSystemBlock(prompt);
    // APPEND the handling prompt — never prepend. The caller's own system
    // blocks reach the provider byte-identical and in place (a subscription
    // request whose system prompt no longer starts with them fails;
    // agent-sign-in.md §1.2 F8), which also preserves the prompt-cache
    // prefix; the handling prompt is position-independent.
    if (req.system == null) {
      req.system = [block];
    } else if (typeof req.system === "string") {
      // Promote the string form to the block-array form, prompt appended.
      req.system = [{ type: "text", text: req.system }, block];
    } else {
      req.system = [...req.system, block];
    }
  }
  // Confidentiality §7.1, "Masked after the fact": while any result carries
  // the line, Mandu's own system note says what the model's transcript no
  // longer shows (static text, appended after the handling prompt, once).
  if (!skipPromptInjection && rewrites.some((r) => r.afterTheFact) && !systemIncludes(req.system, AFTER_THE_FACT_MARKER)) {
    const note = { type: "text", text: AFTER_THE_FACT_SYSTEM_NOTE } as SystemBlock;
    if (req.system == null) req.system = [note];
    else if (typeof req.system === "string") req.system = [{ type: "text", text: req.system }, note];
    else req.system = [...req.system, note];
  }

  await opts.clearResults?.remember(clearIds);
  for (const [id, text] of clearTexts) opts.forwardedResults?.remember(id, text);
  await opts.forwardedResults?.flush?.();
  return { request: req, rewrites, ...(promptFilter ? { promptFilter } : {}) };
}

/**
 * The tool input spelled in the arbiter's world (HumanView), for the
 * arbiter's CONFIDENTIALITY derivation only. Every string leaf is translated:
 * for a mapped tool the arbiter reads the path-ish keys of `CLASSIFY_PARAM_KEYS`
 * (arbiter/policy/secret-catalog.ts), for a tool the session's spec does not
 * map it reads every string (labelForUnmappedInput, plan 10 §11.11), and a
 * user label is keyed in HumanView either way.
 *
 * Never forwarded anywhere: `Edit.old_string` / `Write.content` are the
 * agent's DATA, and prefix-substituting inside them on the wire would be the
 * use-vs-mention corruption the view map exists to avoid (fs-sync.md §1
 * §3 rule 2). As classify input they can only add a path hit, which raises.
 *
 * Returns undefined when nothing changed, so a proxy with no view map, or a
 * call whose strings touch no root, sends byte-identical requests.
 */
function toHumanViewParams(
  input: Record<string, unknown>,
  toHumanView: (s: string) => string,
): Record<string, unknown> | undefined {
  let changed = false;
  const map = (v: unknown, depth: number): unknown => {
    if (typeof v === "string") {
      if (v === "") return v;
      const m = toHumanView(v);
      if (m !== v) changed = true;
      return m;
    }
    // The arbiter's own bound (UNMAPPED_INPUT_SCAN_LIMITS.depth): past it the
    // arbiter fails closed anyway, so the copy stops translating there.
    if (v === null || typeof v !== "object" || depth >= 16) return v;
    if (Array.isArray(v)) return v.map((x) => map(x, depth + 1));
    const o: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) o[k] = map(x, depth + 1);
    return o;
  };
  const out = map(input, 0) as Record<string, unknown>;
  return changed ? out : undefined;
}
