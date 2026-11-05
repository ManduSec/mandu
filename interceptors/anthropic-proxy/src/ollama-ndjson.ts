/**
 * ollama-ndjson — gate the model's tool calls in an Ollama `/api/chat`
 * ANSWER (streamed as NDJSON, one JSON object per line, or one JSON object
 * with `stream: false`) before the agent receives them (model-wires.md, "The
 * Ollama wire"; the request half is ollama-wire.ts).
 *
 * Mandu-new (no reference origin). Every call goes through the same
 * per-exchange gate the Messages, OpenAI and Gemini wires use (proxy.ts
 * toolInputTransform, as `CallGate`; openai-sse.ts `gateCall` releases it).
 *
 * Ollama sends a tool call WHOLE inside one line (`message.tool_calls[]`,
 * `{id?, function: {name, arguments}}`, the arguments an object), so each
 * line is gated in place, with no hold: the call's `arguments` become what
 * the gate released, a call without an `id` is given one (OpenClaw 2026.7
 * and later keep it and echo it back on the tool's result, so the proxy's
 * records correlate exactly), and the gate reads the call under the name the
 * agent runs it as (ollama-wire.ts canonicalToolName: OpenClaw's
 * `openclaw_<name>` aliases and `functions.<tool>` spellings). Arguments that
 * are not an object rename the call to `mandu_refused_unreadable_call`, a
 * tool no agent has.
 *
 * TOOL CALLS WRITTEN AS TEXT. OpenClaw 2026.7.1 and later run a tool call the
 * model writes in its reply text on this wire (its plain-text tool-call
 * compat wrapper, around every Ollama stream: `[tool]` or `[tool:tool]`
 * then a JSON payload, `<function=tool>…`, the Harmony
 * `commentary to=tool code {…}` form, each at the start of a line). No gate
 * sees such a call, so a reply whose text starts one (`textCallStart`) ends
 * the stream here (the grammar is text-calls.ts's, shared with the OpenAI
 * wires), before the line that completes it is relayed and before
 * the final `done` line, without which OpenClaw runs nothing of the turn.
 *
 * Reply text is reported for the `tllm_call` event; `thinking`, usage, timing
 * and the `done` fields pass untouched. An `{"error": …}` line passes as sent
 * (it carries no call; the agent reports it).
 *
 * FAIL-CLOSED: a line that does not parse or is not an object, a `message`
 * that is not the shape the API sends (a field Mandu does not read, content
 * that is not a string, `tool_calls` that is not a list), or a tool call
 * written as text ends the stream with an `{"error": …}` line, and nothing
 * after it is relayed (no `done` line reaches the agent, so the turn fails);
 * a buffered answer that cannot be read throws (the proxy answers 502, never
 * relays it).
 */

import { mintCallId } from "./gemini-sse.js";
import { canonicalToolName } from "./ollama-wire.js";
import { gateCall, type CallGate, type OpenAiRewriterOptions } from "./openai-sse.js";
import { LINE_TEXT_CALL_WHY, TextCallScan as LineScan, textCallStart } from "./text-calls.js";

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

/** An answer this gate cannot read: the stream ends, a buffered answer is a 502. */
class OllamaAnswerError extends Error {}

/** NDJSON framing: split a buffer into complete lines (terminator kept). */
export class NdjsonFramer {
  private buf = "";
  push(chunk: string): string[] {
    this.buf += chunk;
    const out: string[] = [];
    for (;;) {
      const nl = this.buf.indexOf("\n");
      if (nl < 0) break;
      out.push(this.buf.slice(0, nl + 1));
      this.buf = this.buf.slice(nl + 1);
    }
    return out;
  }
  rest(): string {
    const r = this.buf;
    this.buf = "";
    return r;
  }
}

/** The error line an Ollama client reads (the API's own `{"error": …}`). */
export function ollamaStreamError(message: string): string {
  return `${JSON.stringify({ error: message })}\n`;
}

/** Why a reply with a tool call written in its text is ended. */
const TEXT_CALL_WHY = LINE_TEXT_CALL_WHY;

/** The reply-text grammar is text-calls.ts's (shared with the OpenAI
 *  wires); re-exported for this wire's unit tests. */
export { textCallStart };

/** The reply text of one answer (one run), as it grows. */
class TextCallScan {
  private readonly scan: LineScan;
  constructor(names: ReadonlySet<string> | undefined) { this.scan = new LineScan(names); }
  add(delta: string): boolean { return this.scan.add("message", delta); }
}

/** Fields an answer's `message` may carry. */
const ANSWER_MESSAGE_KEYS: ReadonlySet<string> = new Set(["role", "content", "thinking", "tool_calls", "images"]);
const CALL_KEYS: ReadonlySet<string> = new Set(["id", "type", "function"]);
const FUNCTION_KEYS: ReadonlySet<string> = new Set(["name", "arguments", "index", "description"]);

/**
 * Gate every tool call of one answer object (a stream line or a buffered
 * answer) in place. Returns whether anything changed; throws
 * OllamaAnswerError on a shape it cannot read or a call written as text.
 */
async function gateAnswer(obj: Json, gate: CallGate, opts: OpenAiRewriterOptions, scan: TextCallScan): Promise<boolean> {
  const msg = obj["message"];
  if (msg === undefined || msg === null) return false; // an error line, usage only
  if (!isObj(msg)) throw new OllamaAnswerError("`message` is not an object");
  for (const key of Object.keys(msg)) {
    if (!ANSWER_MESSAGE_KEYS.has(key)) throw new OllamaAnswerError(`the answer's message has the field "${key}", which Mandu does not read`);
  }
  const content = msg["content"];
  if (content !== undefined && content !== null && typeof content !== "string") throw new OllamaAnswerError("the answer's content is not a string");
  const thinking = msg["thinking"];
  if (thinking !== undefined && thinking !== null && typeof thinking !== "string") throw new OllamaAnswerError("the answer's thinking is not a string");
  if (typeof content === "string" && content !== "") {
    opts.onText?.(content);
    if (scan.add(content)) throw new OllamaAnswerError(TEXT_CALL_WHY);
  }
  const calls = msg["tool_calls"];
  if (calls === undefined || calls === null) return false;
  if (!Array.isArray(calls)) throw new OllamaAnswerError("the answer's tool_calls is not a list");
  let changed = false;
  for (const [i, c] of calls.entries()) {
    const where = `tool_calls[${i}]`;
    if (!isObj(c)) throw new OllamaAnswerError(`${where} is not an object`);
    for (const key of Object.keys(c)) if (!CALL_KEYS.has(key)) throw new OllamaAnswerError(`${where} has the field "${key}", which Mandu does not read`);
    const fn = c["function"];
    if (!isObj(fn)) throw new OllamaAnswerError(`${where}.function is not an object`);
    for (const key of Object.keys(fn)) if (!FUNCTION_KEYS.has(key)) throw new OllamaAnswerError(`${where}.function has the field "${key}", which Mandu does not read`);
    const wireName = typeof fn["name"] === "string" ? fn["name"] : "";
    const name = canonicalToolName(wireName, opts.toolNames);
    const hadId = typeof c["id"] === "string" && c["id"] !== "";
    const id = hadId ? (c["id"] as string) : mintCallId();
    const args = fn["arguments"];
    // An object as sent; a JSON string as an agent that parses one would read
    // it; anything else reaches gateCall as text that is not an object, so the
    // call is renamed (nothing runs).
    const argsText = args === undefined || args === null ? "" : isObj(args) ? JSON.stringify(args) : typeof args === "string" ? args : "\u0000";
    const g = await gateCall(gate, name, argsText, id, opts.log);
    opts.onCall?.({ id, name: g.name, input: g.input });
    // The wire name stays (the agent maps it as it always does) unless the
    // gate renamed the call.
    const released = g.name === name ? wireName : g.name;
    if (!hadId || released !== wireName || !isObj(args) || JSON.stringify(g.input) !== JSON.stringify(args)) {
      calls[i] = { ...c, id, function: { ...fn, name: released, arguments: g.input } };
      changed = true;
    }
  }
  return changed;
}

/**
 * A buffered answer (`stream: false`): one object. Gated in place; returns
 * whether anything changed; throws on a shape it cannot read (the caller
 * answers 502, never relays).
 */
export async function gateOllamaJson(body: unknown, gate: CallGate, opts: OpenAiRewriterOptions = {}): Promise<boolean> {
  try {
    if (!isObj(body)) throw new OllamaAnswerError("the answer is not a JSON object");
    return await gateAnswer(body, gate, opts, new TextCallScan(opts.toolNames));
  } catch (err) {
    if (err instanceof OllamaAnswerError) throw new Error(err.message);
    throw err;
  }
}

/** The NDJSON stream: one answer object per line. */
export class OllamaStreamRewriter {
  private readonly framer = new NdjsonFramer();
  private readonly scan: TextCallScan;
  private failed = false;

  constructor(private readonly gate: CallGate, private readonly opts: OpenAiRewriterOptions = {}) {
    this.scan = new TextCallScan(opts.toolNames);
  }

  async feed(chunk: string): Promise<string> {
    if (this.failed) return "";
    let out = "";
    for (const line of this.framer.push(chunk)) {
      out += await this.handle(line);
      if (this.failed) break;
    }
    return out;
  }

  async end(): Promise<string> {
    if (this.failed) return "";
    const rest = this.framer.rest();
    return rest.trim() !== "" ? this.handle(rest) : rest;
  }

  private abort(why: string): string {
    this.failed = true;
    this.opts.log?.(`ollama: FAIL-CLOSED ending the stream: ${why}`);
    return ollamaStreamError(`mandu: ${why}; the rest of the response was not relayed`);
  }

  private async handle(raw: string): Promise<string> {
    const text = raw.trim();
    if (text === "") return raw;
    let obj: unknown;
    try { obj = JSON.parse(text); } catch { return this.abort("a response line did not parse"); }
    if (!isObj(obj)) return this.abort("a response line is not an object");
    try {
      if (!(await gateAnswer(obj, this.gate, this.opts, this.scan))) return raw;
    } catch (err) {
      if (err instanceof OllamaAnswerError) return this.abort(err.message);
      throw err;
    }
    return `${JSON.stringify(obj)}\n`;
  }
}
