/**
 * model-wire — the two model wires' encoders and extractors, shared by the
 * drill scripts' engine (replay-engine.ts) and the legacy scripted fakes
 * (fake-anthropic.ts, fake-responses.ts), which re-export these names
 * (test-reorganization.md §6.4; step 5 WP-A refactored them out of the two
 * fakes, byte for byte, so the legacy suites are untouched).
 *
 *   Anthropic Messages   textTurn, toolUseTurn, readToolUseTurn (SSE events),
 *                        anthropicMessageJson (the non-streamed form),
 *                        extractToolResultText, extractEchoedContent
 *   OpenAI Responses     responsesTextTurn, responsesFnTurn,
 *                        responsesCustomToolTurn (SSE events),
 *                        responsesJson (the non-streamed form),
 *                        extractFunctionCallOutputText, lastUserText
 *   both                 SseEvent, sseChunk, writeSse
 *
 * A change to any encoder here changes what the agents render: the
 * engine's golden test (replay-engine-golden.test.ts) fails until
 * ENGINE_VERSION (replay-model.ts) is bumped, and the bump reruns the
 * differential baselines (baseline-cache.ts keys on it).
 */

import type http from "node:http";

/** One server-sent event: [event name, data]. */
export type SseEvent = [string, unknown];

/** A /v1/messages (or /responses) request, lightly parsed for marker-based
 *  matching. */
export interface ParsedRequest {
  url: string;
  body: string;
  hasToolResult: boolean;
}

export function sseChunk(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

/** Write an SSE event sequence, `paceMs` apart, and end the response. */
export async function writeSse(res: http.ServerResponse, events: SseEvent[], paceMs: number): Promise<void> {
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  for (const [event, data] of events) {
    res.write(sseChunk(event, data));
    if (paceMs > 0) await new Promise((r) => setTimeout(r, paceMs));
  }
  res.end();
}

// ── Anthropic Messages ───────────────────────────────────────────────────────

/** A complete one-shot prose turn. `deltaChunk` splits the text into multiple
 *  content_block_delta events (so `paceMs` paces WITHIN the reply, the shape a
 *  real streamed response has — one big delta would defeat the pacing). */
export function textTurn(text: string, deltaChunk = 0): SseEvent[] {
  const deltas: SseEvent[] = [];
  if (deltaChunk > 0) {
    for (let i = 0; i < text.length; i += deltaChunk) {
      deltas.push(["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: text.slice(i, i + deltaChunk) } }]);
    }
  } else {
    deltas.push(["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text } }]);
  }
  return [
    ["message_start", { type: "message_start", message: { id: "msg_mdu_text", type: "message", role: "assistant", model: "claude-fake-mdu", content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 1 } } }],
    ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }],
    ...deltas,
    ["content_block_stop", { type: "content_block_stop", index: 0 }],
    ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } }],
    ["message_stop", { type: "message_stop" }],
  ];
}

/** A tool_use turn instructing the agent to run `name` with `input`. */
export function toolUseTurn(id: string, name: string, input: Record<string, unknown>): SseEvent[] {
  return [
    ["message_start", { type: "message_start", message: { id: "msg_mdu_tool", type: "message", role: "assistant", model: "claude-fake-mdu", content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 1 } } }],
    ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id, name, input: {} } }],
    ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(input) } }],
    ["content_block_stop", { type: "content_block_stop", index: 0 }],
    ["message_delta", { type: "message_delta", delta: { stop_reason: "tool_use", stop_sequence: null }, usage: { output_tokens: 1 } }],
    ["message_stop", { type: "message_stop" }],
  ];
}

export function readToolUseTurn(id: string, filePath: string): SseEvent[] {
  return toolUseTurn(id, "Read", { file_path: filePath });
}

/** The non-streamed Messages response (a request with `stream` not true):
 *  one text block, or one tool_use block. */
export function anthropicMessageJson(
  block: { text: string } | { id: string; name: string; input: Record<string, unknown> },
): Record<string, unknown> {
  const isTool = "name" in block;
  return {
    id: isTool ? "msg_mdu_tool" : "msg_mdu_text", type: "message", role: "assistant", model: "claude-fake-mdu",
    content: [isTool ? { type: "tool_use", id: block.id, name: block.name, input: block.input } : { type: "text", text: block.text }],
    stop_reason: isTool ? "tool_use" : "end_turn", stop_sequence: null,
    usage: { input_tokens: 10, output_tokens: 1 },
  };
}

/** The proxy's symbol-twin note (anthropic-proxy twin-note.ts TWIN_MARKER,
 *  docs/design/integrity/symbol-twin-shell-blindness.md): a TRUSTED paragraph appended
 *  to a shell tool_result whose command read a whole-file symbol twin —
 *  guidance addressed to the model, never content. A real model does not
 *  parrot it; this scripted fake echoes the tool_result verbatim, so the note
 *  is stripped from the echo or the wrapped side's screen (and every later
 *  scroll position) differs from vanilla by the note's rows. Its presence at
 *  the model ingress is asserted where it belongs — claude-e2e E48. */
const TWIN_NOTE_TAIL_RE = /\n*\[mandu:twin\] [\s\S]*$/;

/** Text of the LAST tool_result block in a request body (its text blocks
 *  joined by newlines; "" when it carries none), minus the twin note, or null
 *  when the body holds no tool_result or is not JSON. On the differential
 *  harness's wrapped side this is the SYMBOLIZED form — echoing it back makes
 *  the reply symbol-bearing, which the reply-filter must resolve for the
 *  human. */
export function extractToolResultText(req: ParsedRequest): string | null {
  const text = extractToolResultTextRaw(req);
  return text === null ? null : text.replace(TWIN_NOTE_TAIL_RE, "");
}

/** Trailing `<system-reminder>` block(s) Claude Code appends to a tool_result.
 *  A block's body never crosses a closing tag (the tempered token): with a
 *  lazy `[\s\S]*?` the match could start at an EARLIER reminder-shaped span
 *  inside the content and stretch over the content after it up to the tail's
 *  closing tag, eating those bytes (fixed 2026-09-29). */
const REMINDER_TAIL_RE = /(?:\s*<system-reminder>(?:(?!<\/system-reminder>)[\s\S])*<\/system-reminder>)+\s*$/;

/** One Read gutter row: `<n><sep><content>`. The content is `[\s\S]*`, not
 *  `.*`: `.` stops at `\r`, U+2028 and U+2029, so a CRLF file's rows never
 *  matched and the echo kept the whole gutter, while the proxy
 *  (unrenderReadResult) unrenders exactly those rows — vanilla then echoed
 *  framing the wrapped side cannot (fixed 2026-09-29). */
const GUTTER_ROW_RE = /^\s*(\d+)(?:\t|→|:)([\s\S]*)$/;

/**
 * What a model that READ the file echoes back: the tool_result's content
 * (extractToolResultText) without Claude Code's harness framing, i.e. the
 * trailing `<system-reminder>` block(s) and the Read tool's `<n><sep>` line
 * gutter (a strict, consecutive-from-1 match; anything else is left as is).
 *
 * WHY (docs/testing/differential-interactive.md §20): a secret Read reaches
 * the wrapped model as ONE symbol standing for the file's bytes, with the
 * gutter unrendered and an unvouched reminder dropped (read-result-rendering.md
 * §3, §4), so the wrapped model CANNOT echo the framing; a verbatim echo
 * would make vanilla's screen differ by harness framing, not by fidelity. On
 * the wrapped side (a bare symbol) this is the identity. Written
 * independently of the proxy's unrenderReadResult on purpose: the oracle must
 * not share the code it checks.
 */
export function extractEchoedContent(req: ParsedRequest): string | null {
  const text = extractToolResultText(req);
  if (text === null) return null;
  return unframeClaudeToolResult(text);
}

/** extractEchoedContent's framing removal on one tool_result text: the
 *  reminder tail, then a strict Read gutter. */
export function unframeClaudeToolResult(text: string): string {
  const body = text.replace(REMINDER_TAIL_RE, "");
  const lines = body.split("\n");
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = GUTTER_ROW_RE.exec(lines[i]!);
    if (m && Number(m[1]) === i + 1) { out.push(m[2]!); continue; }
    // The rendering of the empty line after a final newline: a bare number.
    if (i === lines.length - 1 && i > 0 && new RegExp(`^\\s*${i + 1}\\s*$`).test(lines[i]!)) { out.push(""); continue; }
    return body; // not a Read rendering: keep the bytes
  }
  return out.join("\n");
}

/** One tool_result block's text: a string, or its text blocks joined by
 *  newlines; "" when it carries no text (an image, no content). */
export function toolResultBlockText(block: Record<string, unknown>): string {
  const c = block["content"];
  if (typeof c === "string") return c;
  if (Array.isArray(c)) {
    return (c as unknown[])
      .filter((b): b is Record<string, unknown> =>
        b !== null && typeof b === "object" && (b as Record<string, unknown>)["type"] === "text" &&
        typeof (b as Record<string, unknown>)["text"] === "string")
      .map((b) => b["text"] as string)
      .join("\n");
  }
  return "";
}

function extractToolResultTextRaw(req: ParsedRequest): string | null {
  try {
    const parsed = JSON.parse(req.body) as { messages?: Array<{ content?: unknown } | null> } | null;
    let last: string | null = null;
    const messages = parsed?.messages;
    if (!Array.isArray(messages)) return null;
    for (const m of messages) {
      if (!Array.isArray(m?.content)) continue;
      for (const block of m.content as Array<Record<string, unknown> | null>) {
        if (block === null || typeof block !== "object" || block["type"] !== "tool_result") continue;
        // The LAST tool_result decides, whatever it carries: one with no text
        // (an image, no content) is "", never an EARLIER result's text (before
        // 2026-09-29 it silently fell back to the previous one).
        last = toolResultBlockText(block);
      }
    }
    return last;
  } catch {
    return null;
  }
}

// ── OpenAI Responses ─────────────────────────────────────────────────────────

/** A complete Responses prose turn; `deltaChunk` splits the text into several
 *  output_text.delta events so `paceMs` paces WITHIN the reply. */
export function responsesTextTurn(text: string, deltaChunk = 0): SseEvent[] {
  const m = { type: "message", id: "msg_f", status: "completed", role: "assistant", content: [{ type: "output_text", text, annotations: [] }] };
  const deltas: SseEvent[] = [];
  const step = deltaChunk > 0 ? deltaChunk : text.length || 1;
  for (let i = 0; i < text.length; i += step) {
    deltas.push(["response.output_text.delta", { type: "response.output_text.delta", item_id: "msg_f", output_index: 0, content_index: 0, delta: text.slice(i, i + step) }]);
  }
  return [
    ["response.created", { type: "response.created", response: { id: "r", status: "in_progress", output: [] } }],
    ["response.output_item.added", { type: "response.output_item.added", output_index: 0, item: { type: "message", id: "msg_f", status: "in_progress", role: "assistant", content: [] } }],
    ["response.content_part.added", { type: "response.content_part.added", item_id: "msg_f", output_index: 0, content_index: 0, part: { type: "output_text", text: "" } }],
    ...deltas,
    ["response.output_text.done", { type: "response.output_text.done", item_id: "msg_f", output_index: 0, content_index: 0, text }],
    ["response.content_part.done", { type: "response.content_part.done", item_id: "msg_f", output_index: 0, content_index: 0, part: { type: "output_text", text } }],
    ["response.output_item.done", { type: "response.output_item.done", output_index: 0, item: m }],
    ["response.completed", { type: "response.completed", response: { id: "r", status: "completed", output: [m], usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } } }],
  ];
}

/** A Responses function_call turn (codex's `exec_command` takes `{cmd}`).
 *  `namespace` (Codex ≥ 0.154 MCP tools: `mcp__<server, - → _>`, with `name`
 *  the tool's own name) is set on the item only when given. */
export function responsesFnTurn(callId: string, name: string, args: Record<string, unknown>, namespace?: string): SseEvent[] {
  const argStr = JSON.stringify(args);
  const ns = namespace === undefined ? {} : { namespace };
  const fc = { type: "function_call", id: `fc_${callId}`, call_id: callId, name, ...ns, arguments: argStr, status: "completed" };
  return [
    ["response.created", { type: "response.created", response: { id: "r2", status: "in_progress", output: [] } }],
    ["response.output_item.added", { type: "response.output_item.added", output_index: 0, item: { type: "function_call", id: `fc_${callId}`, call_id: callId, name, ...ns, arguments: "" } }],
    ["response.function_call_arguments.delta", { type: "response.function_call_arguments.delta", item_id: `fc_${callId}`, output_index: 0, delta: argStr }],
    ["response.function_call_arguments.done", { type: "response.function_call_arguments.done", item_id: `fc_${callId}`, output_index: 0, arguments: argStr }],
    ["response.output_item.done", { type: "response.output_item.done", output_index: 0, item: fc }],
    ["response.completed", { type: "response.completed", response: { id: "r2", status: "completed", output: [fc], usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } } }],
  ];
}

/** A Responses custom_tool_call turn: the script-cell wire's `exec` (Codex ≥
 *  0.154, `code_mode_host`), whose `input` is JavaScript
 *  (interceptors/openai-proxy/src/responses-types.ts). */
export function responsesCustomToolTurn(callId: string, name: string, input: string): SseEvent[] {
  const id = `ctc_${callId}`;
  const item = { type: "custom_tool_call", id, call_id: callId, name, input, status: "completed" };
  return [
    ["response.created", { type: "response.created", response: { id: "r3", status: "in_progress", output: [] } }],
    ["response.output_item.added", { type: "response.output_item.added", output_index: 0, item: { type: "custom_tool_call", id, call_id: callId, name, input: "" } }],
    ["response.custom_tool_call_input.delta", { type: "response.custom_tool_call_input.delta", item_id: id, output_index: 0, delta: input }],
    ["response.custom_tool_call_input.done", { type: "response.custom_tool_call_input.done", item_id: id, output_index: 0, input }],
    ["response.output_item.done", { type: "response.output_item.done", output_index: 0, item }],
    ["response.completed", { type: "response.completed", response: { id: "r3", status: "completed", output: [item], usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } } }],
  ];
}

/** The non-streamed Responses object: the completed response of a turn's
 *  events (its `response.completed` payload). */
export function responsesJson(events: SseEvent[]): unknown {
  const done = events.find(([e]) => e === "response.completed");
  return done ? (done[1] as { response: unknown }).response : {};
}

/** The LAST function_call_output's text in a Responses body (symbolized on the
 *  wrapped side), or null. */
export function extractFunctionCallOutputText(req: ParsedRequest): string | null {
  try {
    const j = JSON.parse(req.body) as { input?: Array<{ type?: string; output?: unknown }> };
    let last: string | null = null;
    for (const it of j.input ?? []) {
      if (it.type !== "function_call_output") continue;
      if (typeof it.output === "string") last = it.output;
      else if (it.output && typeof it.output === "object") last = JSON.stringify(it.output);
    }
    return last;
  } catch {
    return null;
  }
}

/** The LAST user message's input_text in a Responses body — a codex request
 *  carries an `<environment_context>` USER message (side-local cwd) BEFORE the
 *  typed prompt, so matchers key on the last user text, never on "any". */
export function lastUserText(req: ParsedRequest): string {
  try {
    const j = JSON.parse(req.body) as { input?: Array<{ type?: string; role?: string; content?: Array<{ type?: string; text?: string }> }> };
    const users = (j.input ?? []).filter((it) => it.type === "message" && it.role === "user");
    const last = users[users.length - 1];
    return (last?.content ?? []).map((c) => c.text ?? "").join("\n");
  } catch {
    return "";
  }
}
