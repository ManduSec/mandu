/**
 * gemini-sse — gate the model's function calls in a Google Gemini ANSWER
 * (streamed as SSE, streamed as a JSON array, or buffered) before the agent
 * receives them (model-wires.md §4.3; the request half is gemini-wire.ts).
 *
 * Mandu-new (no reference origin). Every call goes through the same
 * per-exchange gate the Messages and OpenAI wires use (proxy.ts
 * toolInputTransform, as `CallGate`; openai-sse.ts `gateCall` releases it).
 *
 * Gemini sends a function call WHOLE inside one part (`functionCall {id?,
 * name, args}`; no argument fragments), so each chunk is gated in place, with
 * no hold: the call's `args` become the canonical serialization of what the
 * gate released (arguments that are not an object rename the call to
 * `mandu_refused_unreadable_call`, a tool no agent has), and a call without
 * an `id` is given one, so the agent echoes it back on its function response
 * and the proxy's records correlate exactly.
 *
 * Text parts are reported for the `tllm_call` event; thought parts,
 * `thoughtSignature`, the model's own media, usage, safety and grounding
 * metadata pass untouched.
 *
 * FAIL-CLOSED: a chunk that does not parse or is not an object, a
 * `candidates` / `content` / `parts` that is not the shape the API sends, a
 * part key gemini-wire.ts does not know, a `functionCall` with streamed
 * arguments (`partialArgs`, `willContinue`), or the provider's own code
 * execution (`executableCode`, `codeExecutionResult`) ends the stream with an
 * error event, and nothing after it is relayed; a buffered answer that cannot
 * be read throws (the proxy answers 502, never relays it).
 */

import { randomBytes } from "node:crypto";

import { canonPart } from "./gemini-wire.js";
import { gateCall, readEvent, SseFramer, type CallGate, type OpenAiRewriterOptions } from "./openai-sse.js";

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

/** An answer this gate cannot read: the stream ends, a buffered answer is a 502. */
class GeminiAnswerError extends Error {}

/** The id given to a call that came without one. */
export function mintCallId(): string {
  return `mandu_${randomBytes(9).toString("hex")}`;
}

/** The error event a Gemini client reads (the API's own error shape). */
export function geminiStreamError(message: string): string {
  return `data: ${JSON.stringify({ error: { code: 502, message, status: "UNAVAILABLE" } })}\n\n`;
}

/**
 * Gate every function call of one answer object (a stream chunk or a whole
 * buffered answer) in place. Returns whether anything changed; throws
 * GeminiAnswerError on a shape it cannot read.
 */
async function gateAnswer(obj: Json, gate: CallGate, opts: OpenAiRewriterOptions): Promise<boolean> {
  const cands = obj["candidates"];
  if (cands === undefined || cands === null) return false; // usage, prompt feedback
  if (!Array.isArray(cands)) throw new GeminiAnswerError("`candidates` is not an array");
  let changed = false;
  for (const [ci, cand] of cands.entries()) {
    if (!isObj(cand)) throw new GeminiAnswerError(`candidates[${ci}] is not an object`);
    const content = cand["content"];
    if (content === undefined || content === null) continue;
    if (!isObj(content)) throw new GeminiAnswerError(`candidates[${ci}].content is not an object`);
    const parts = content["parts"];
    if (parts === undefined || parts === null) continue;
    if (!Array.isArray(parts)) throw new GeminiAnswerError(`candidates[${ci}].content.parts is not an array`);
    for (const [k, part] of parts.entries()) {
      const where = `candidates[${ci}].content.parts[${k}]`;
      const c = canonPart(part, where, GeminiAnswerError);
      for (const bad of ["executableCode", "codeExecutionResult"]) {
        if (c.has(bad)) throw new GeminiAnswerError(`the model produced ${c.get(bad)!.key}, the provider's own code execution, which Mandu does not gate`);
      }
      const t = c.get("text")?.value;
      if (typeof t === "string" && c.get("thought")?.value !== true) opts.onText?.(t);
      const fc = c.get("functionCall");
      if (fc === undefined) continue;
      if (!isObj(fc.value)) throw new GeminiAnswerError(`${where}.${fc.key} is not an object`);
      const v = fc.value;
      for (const key of ["partialArgs", "partial_args", "willContinue", "will_continue"]) {
        if (v[key] !== undefined) throw new GeminiAnswerError("the model streamed a function call's arguments in pieces, which Mandu cannot gate before the agent assembles them");
      }
      const name = typeof v["name"] === "string" ? v["name"] : "";
      const hadId = typeof v["id"] === "string" && v["id"] !== "";
      const id = hadId ? (v["id"] as string) : mintCallId();
      const args = v["args"];
      // Arguments that are not an object reach gateCall as text that is not
      // one, so the call is renamed (nothing runs).
      const argsText = args === undefined || args === null ? "" : isObj(args) ? JSON.stringify(args) : "\u0000";
      const g = await gateCall(gate, name, argsText, id, opts.log);
      opts.onCall?.({ id, name: g.name, input: g.input });
      const released: Json = { ...v, id, name: g.name, args: g.input };
      if (!hadId || g.name !== name || JSON.stringify(g.input) !== JSON.stringify(args ?? {})) {
        (part as Json)[fc.key] = released;
        changed = true;
      }
    }
  }
  return changed;
}

/**
 * A buffered answer: a `generateContent` body (an object), or a
 * `streamGenerateContent` body without `alt=sse` (a JSON array of chunks,
 * read whole). Gated in place; returns whether anything changed; throws on
 * a shape it cannot read (the caller answers 502, never relays).
 */
export async function gateGeminiJson(body: unknown, gate: CallGate, opts: OpenAiRewriterOptions = {}): Promise<boolean> {
  try {
    if (Array.isArray(body)) {
      let changed = false;
      for (const [i, el] of body.entries()) {
        if (!isObj(el)) throw new GeminiAnswerError(`chunk ${i} is not an object`);
        if (await gateAnswer(el, gate, opts)) changed = true;
      }
      return changed;
    }
    if (!isObj(body)) throw new GeminiAnswerError("the answer is not a JSON object");
    return await gateAnswer(body, gate, opts);
  } catch (err) {
    if (err instanceof GeminiAnswerError) throw new Error(err.message);
    throw err;
  }
}

/** The SSE stream (`alt=sse`): one answer object per `data:` event. */
export class GeminiStreamRewriter {
  private readonly framer = new SseFramer();
  private failed = false;

  constructor(private readonly gate: CallGate, private readonly opts: OpenAiRewriterOptions = {}) {}

  async feed(chunk: string): Promise<string> {
    if (this.failed) return "";
    let out = "";
    for (const raw of this.framer.push(chunk)) {
      out += await this.handle(raw);
      if (this.failed) break;
    }
    return out;
  }

  async end(): Promise<string> {
    if (this.failed) return "";
    const rest = this.framer.rest();
    return rest.trim() !== "" ? this.handle(`${rest}\n\n`) : "";
  }

  private abort(why: string): string {
    this.failed = true;
    this.opts.log?.(`gemini: FAIL-CLOSED ending the stream: ${why}`);
    return geminiStreamError(`mandu: ${why}; the rest of the response was not relayed`);
  }

  private async handle(raw: string): Promise<string> {
    const { data } = readEvent(raw);
    if (data === null) {
      // A comment / keepalive carries nothing an agent runs; anything else
      // is not an event stream (it could carry a call), so it ends here.
      const lines = raw.split(/\r?\n/).filter((l) => l !== "");
      if (lines.every((l) => l.startsWith(":") || /^(event|id|retry):/.test(l))) return raw;
      return this.abort("the answer is not an event stream");
    }
    let obj: unknown;
    try { obj = JSON.parse(data); } catch { return this.abort("a response chunk did not parse"); }
    if (!isObj(obj)) return this.abort("a response chunk is not an object");
    try {
      if (!(await gateAnswer(obj, this.gate, this.opts))) return raw;
    } catch (err) {
      if (err instanceof GeminiAnswerError) return this.abort(err.message);
      throw err;
    }
    return `data: ${JSON.stringify(obj)}\n\n`;
  }
}
