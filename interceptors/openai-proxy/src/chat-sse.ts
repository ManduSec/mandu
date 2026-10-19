/**
 * chat-sse — gate the model's tool calls in a Chat Completions RESPONSE
 * (streamed or buffered) before the agent receives them: the Chat twin of
 * sse-rewrite.ts's ResponsesArgsRewriter, with the SAME per-exchange
 * arguments transform (the Phase-0 exec gate, then the P4 forward path map;
 * proxy.ts buildArgsTransform).
 *
 * Mandu Track A (interceptors/openai-proxy). PROVENANCE: adapted from
 * interceptors/anthropic-proxy/src/openai-sse.ts `ChatStreamRewriter` /
 * `gateChatJson` (the routed OpenClaw / OpenCode Chat wire), with that
 * proxy's per-tool gate replaced by this proxy's arguments transform.
 *
 * A call's arguments arrive in pieces (`choices[].delta.tool_calls[]`
 * fragments keyed by `index`; the id and name on the first), and the agent
 * acts on the assembled call, so the fragments are removed from the chunks
 * as they stream and each call is HELD until its choice's `finish_reason`
 * (or `[DONE]`, or the stream's end); then it is gated and released as ONE
 * synthetic chunk carrying the whole call, before the finishing chunk.
 *
 * The released arguments are the canonical serialization of what the gate
 * read (`JSON.stringify(JSON.parse(args))`), never the model's own bytes: an
 * agent whose JSON reader differs from JSON.parse (a duplicate key read
 * first-wins, a lenient repair) could otherwise run arguments the gate never
 * saw. Arguments that are not a JSON object cannot be gated: with the exec
 * gate on (`unparseable: "block"`) the call is renamed
 * `mandu_refused_unreadable_call`, a tool no agent has, so nothing runs.
 *
 * FAIL-CLOSED: a data line that does not parse, a legacy `function_call`, or
 * a call that changes its name mid-stream ends the stream with an error
 * event, and nothing after it is relayed.
 *
 * `onCall` reports each assembled call once, as the model wrote it (the
 * `tool_use` event); `onText` the assistant text (the `tllm_call` answer).
 * Both are observability, never on the security path.
 */

import type { ArgsTransform, ToolCallSeen } from "./sse-rewrite.js";

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

/** The name a call gets when its arguments cannot be read. */
export const UNREADABLE_CALL_NAME = "mandu_refused_unreadable_call";

export interface ChatRewriterOptions {
  /** Arguments that are not a JSON object: `block` (rename the call, the exec
   *  gate is on) or `keep` (relay them). Default `keep`. */
  unparseable?: "block" | "keep";
  onCall?: (call: ToolCallSeen) => void;
  onText?: (text: string) => void;
  log?: (msg: string) => void;
}

/** A tool call's JSON arguments as an object; null when they are not one. */
function parseArguments(args: string): Json | null {
  if (args.trim() === "") return {};
  try {
    const v: unknown = JSON.parse(args);
    return isObj(v) ? v : null;
  } catch {
    return null;
  }
}

/** Gate one assembled call: the name and arguments to release. */
async function gateCall(
  transform: ArgsTransform | null,
  name: string,
  args: string,
  opts: ChatRewriterOptions,
  callId: string | null = null,
): Promise<{ name: string; args: string }> {
  const parsed = parseArguments(args);
  if (parsed === null) {
    if (opts.unparseable === "block") {
      opts.log?.(`chat: a call to ${name} has arguments that are not a JSON object: refused`);
      return { name: UNREADABLE_CALL_NAME, args: "{}" };
    }
    return { name, args };
  }
  const canonical = JSON.stringify(parsed);
  const t = transform ? await transform(canonical, { callId, name }) : null;
  return { name, args: t ?? canonical };
}

interface PendingCall {
  index: number;
  id: string;
  type: string;
  name: string;
  args: string;
  conflict?: boolean;
}

/** SSE framing: split a buffer into complete events (terminator kept). */
class SseFramer {
  private buf = "";
  push(chunk: string): string[] {
    this.buf += chunk;
    const out: string[] = [];
    for (;;) {
      const lf = this.buf.indexOf("\n\n");
      const crlf = this.buf.indexOf("\r\n\r\n");
      const sep = lf < 0 ? crlf : crlf < 0 ? lf : Math.min(lf, crlf);
      if (sep < 0) break;
      const end = this.buf.startsWith("\r\n\r\n", sep) ? sep + 4 : sep + 2;
      out.push(this.buf.slice(0, end));
      this.buf = this.buf.slice(end);
    }
    return out;
  }
  rest(): string {
    const r = this.buf;
    this.buf = "";
    return r;
  }
}

function eventData(raw: string): string | null {
  const data: string[] = [];
  for (const line of raw.split(/\r?\n/)) if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
  return data.length > 0 ? data.join("\n") : null;
}

export class ChatArgsRewriter {
  private readonly framer = new SseFramer();
  /** Pending calls per choice index, by tool-call index. */
  private readonly pending = new Map<number, Map<number, PendingCall>>();
  /** The envelope (id / object / created / model) of the last chunk. */
  private envelope: Json = {};
  private failed = false;

  constructor(private readonly transform: ArgsTransform | null, private readonly opts: ChatRewriterOptions = {}) {}

  async feed(chunk: string): Promise<string> {
    if (this.failed) return "";
    let out = "";
    for (const raw of this.framer.push(chunk)) {
      out += await this.handle(raw);
      if (this.failed) break;
    }
    return out;
  }

  /** A stream cut before the finish: gate what was held, so nothing ungated
   *  is left for the agent to assemble. */
  async end(): Promise<string> {
    if (this.failed) return "";
    let out = "";
    const rest = this.framer.rest();
    if (rest.trim() !== "") out += await this.handle(`${rest}\n\n`);
    if (this.failed) return out;
    for (const ci of [...this.pending.keys()]) out += await this.flush(ci);
    return out;
  }

  private abort(why: string): string {
    this.failed = true;
    this.opts.log?.(`chat: FAIL-CLOSED ending the stream: ${why}`);
    return `data: ${JSON.stringify({ error: { type: "mandu_fail_closed", message: `mandu: ${why}; the rest of the response was not relayed` } })}\n\n`;
  }

  /** Release every pending call of one choice as one synthetic chunk. */
  private async flush(choice: number): Promise<string> {
    const calls = this.pending.get(choice);
    this.pending.delete(choice);
    if (!calls || calls.size === 0) return "";
    const out: Json[] = [];
    for (const c of [...calls.values()].sort((a, b) => a.index - b.index)) {
      this.opts.onCall?.({ itemId: c.id, callId: c.id || null, name: c.name, argumentsJson: c.args });
      const g = await gateCall(this.transform, c.name, c.args, this.opts, c.id || null);
      out.push({ index: c.index, ...(c.id ? { id: c.id } : {}), type: c.type || "function", function: { name: g.name, arguments: g.args } });
    }
    const chunk = { ...this.envelope, choices: [{ index: choice, delta: { tool_calls: out }, finish_reason: null }] };
    return `data: ${JSON.stringify(chunk)}\n\n`;
  }

  private async handle(raw: string): Promise<string> {
    const data = eventData(raw);
    if (data === null) {
      // A comment / keepalive (or a bare event:/id:/retry: line) carries
      // nothing an agent runs. Anything else is not an event stream (a JSON
      // body under a stream request): it could carry a call, so it ends here.
      const lines = raw.split(/\r?\n/).filter((l) => l !== "");
      if (lines.every((l) => l.startsWith(":") || /^(event|id|retry):/.test(l))) return raw;
      return this.abort("the answer is not an event stream");
    }
    if (data.trim() === "[DONE]") {
      let out = "";
      for (const ci of [...this.pending.keys()]) out += await this.flush(ci);
      return out + raw;
    }
    let obj: unknown;
    try { obj = JSON.parse(data); } catch { return this.abort("a response chunk did not parse"); }
    if (!isObj(obj)) return this.abort("a response chunk is not an object");
    const choices = obj["choices"];
    if (choices === undefined) return raw; // a usage-only or error chunk
    if (!Array.isArray(choices)) return this.abort("`choices` is not an array");
    for (const k of ["id", "object", "created", "model", "system_fingerprint"]) if (obj[k] !== undefined) this.envelope[k] = obj[k];

    let changed = false;
    let before = "";
    const kept: unknown[] = [];
    for (const ch of choices) {
      if (!isObj(ch)) return this.abort("a choice is not an object");
      const ci = typeof ch["index"] === "number" ? (ch["index"] as number) : 0;
      const delta = ch["delta"];
      let next: Json = ch;
      if (isObj(delta)) {
        if (typeof delta["content"] === "string") this.opts.onText?.(delta["content"] as string);
        if (delta["function_call"] !== undefined && delta["function_call"] !== null) return this.abort("the model sent a legacy function_call");
        const tcs = delta["tool_calls"];
        if (tcs !== undefined && tcs !== null) {
          if (!Array.isArray(tcs)) return this.abort("`tool_calls` is not an array");
          const calls = this.pending.get(ci) ?? new Map<number, PendingCall>();
          this.pending.set(ci, calls);
          tcs.forEach((tc: unknown, pos: number) => {
            const t = isObj(tc) ? tc : {};
            const idx = typeof t["index"] === "number" ? (t["index"] as number) : pos;
            const fn = isObj(t["function"]) ? (t["function"] as Json) : {};
            const cur = calls.get(idx) ?? { index: idx, id: "", type: "", name: "", args: "" };
            if (typeof t["id"] === "string" && t["id"] !== "" && cur.id === "") cur.id = t["id"] as string;
            if (typeof t["type"] === "string") cur.type = t["type"] as string;
            // Agents differ on a second, different name (some keep the first,
            // some the last): it is refused below.
            if (typeof fn["name"] === "string" && fn["name"] !== "") {
              if (cur.name !== "" && cur.name !== fn["name"]) cur.conflict = true;
              cur.name = fn["name"] as string;
            }
            if (typeof fn["arguments"] === "string") cur.args += fn["arguments"] as string;
            calls.set(idx, cur);
          });
          if ([...calls.values()].some((c) => c.conflict)) return this.abort("a tool call changed its name mid-stream");
          const { tool_calls: _drop, ...rest } = delta;
          next = { ...ch, delta: rest };
          changed = true;
        }
      }
      if (ch["finish_reason"] !== null && ch["finish_reason"] !== undefined && this.pending.has(ci)) {
        before += await this.flush(ci);
      }
      // A choice left with nothing to say (its delta only carried tool-call
      // fragments) is dropped from this chunk.
      const d = next["delta"];
      const empty = isObj(d) && Object.keys(d).length === 0 && (next["finish_reason"] === null || next["finish_reason"] === undefined) && next["logprobs"] == null;
      if (!empty) kept.push(next);
      else changed = true;
    }
    if (!changed) return before + raw;
    if (kept.length === 0 && obj["usage"] == null) return before;
    return `${before}data: ${JSON.stringify({ ...obj, choices: kept })}\n\n`;
  }
}

/**
 * A buffered (non-streamed) Chat Completions response: gate every call in
 * `choices[].message.tool_calls` in place. Returns whether anything changed;
 * throws on a shape it cannot read (the caller answers 502, never relays).
 */
export async function gateChatJson(obj: Json, transform: ArgsTransform | null, opts: ChatRewriterOptions = {}): Promise<boolean> {
  const choices = obj["choices"];
  if (choices === undefined) return false;
  if (!Array.isArray(choices)) throw new Error("`choices` is not an array");
  let changed = false;
  for (const ch of choices) {
    if (!isObj(ch)) throw new Error("a choice is not an object");
    const msg = ch["message"];
    if (!isObj(msg)) continue;
    if (typeof msg["content"] === "string") opts.onText?.(msg["content"] as string);
    if (msg["function_call"] !== undefined && msg["function_call"] !== null) throw new Error("the model sent a legacy function_call");
    const tcs = msg["tool_calls"];
    if (tcs === undefined || tcs === null) continue;
    if (!Array.isArray(tcs)) throw new Error("`tool_calls` is not an array");
    for (const tc of tcs) {
      if (!isObj(tc) || !isObj(tc["function"])) throw new Error("a tool call is not a function call");
      const fn = tc["function"] as Json;
      const id = typeof tc["id"] === "string" ? (tc["id"] as string) : "";
      const name = typeof fn["name"] === "string" ? (fn["name"] as string) : "";
      const args = typeof fn["arguments"] === "string" ? (fn["arguments"] as string) : JSON.stringify(fn["arguments"] ?? {});
      opts.onCall?.({ itemId: id, callId: id || null, name, argumentsJson: args });
      const g = await gateCall(transform, name, args, opts, id || null);
      if (g.name !== name || g.args !== fn["arguments"]) {
        fn["name"] = g.name;
        fn["arguments"] = g.args;
        changed = true;
      }
    }
  }
  return changed;
}
