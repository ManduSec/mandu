/**
 * openai-sse — gate the model's tool calls in an OpenAI-family RESPONSE
 * (Chat Completions and the Responses API, streamed or buffered) before the
 * agent receives them (agent-e2e-harness.md §9; the request side is
 * openai-wire.ts).
 *
 * Every call goes through the same per-exchange transform the Messages wire
 * uses (proxy.ts toolInputTransform: the dispatcher unwrap, the refused-tool
 * tables, the exec / stdin / net / path / derived-label gates, the forward
 * view map). A call's arguments can span many stream chunks, and an agent
 * acts on the assembled call, so the arguments are BUFFERED per call and
 * released only once, gated, as one piece:
 *
 *   Chat Completions: `choices[].delta.tool_calls[]` fragments keyed by
 *   `index` (the id and name arrive on the first fragment, the arguments in
 *   pieces) are removed from the chunks as they stream; when the choice's
 *   `finish_reason` arrives (or `[DONE]`, or the stream ends) each call is
 *   gated and emitted as ONE synthetic chunk carrying the whole call, before
 *   the finishing chunk.
 *
 *   Responses API: `response.function_call_arguments.delta` events are held;
 *   at `.done` the gated arguments go out as one delta plus the `.done`, and
 *   the item snapshots in `response.output_item.done` and the terminal
 *   `response.completed` / `.incomplete` carry the same gated arguments.
 *
 * FAIL-CLOSED, unlike the Messages rewriter's view-consistency fallback: a
 * data line that does not parse, or an output item a routed agent would
 * execute that is not a function call (a custom or local-shell call, which
 * the request never declared), ends the stream with an error event and
 * nothing after it is relayed. Arguments that are not a JSON object are not
 * released: the call is renamed `mandu_refused_unreadable_call`, a tool no
 * agent has, so nothing runs (the agent answers "unknown tool").
 *
 * TOOL CALLS WRITTEN AS TEXT (`refuseTextCalls`, Chat Completions only). An
 * agent may run a call the model writes in its TEXT: Goose's ollama provider
 * (goose-provider-types formats/ollama.rs, for Qwen3-coder and kin) buffers
 * the assistant text once it contains `<function=` and turns every
 * `<function=name><parameter=k>v</parameter></function>` in it into a tool
 * call, which no gate above would see. On a route the launcher marks
 * (MANDU_OPENAI_TEXT_CALLS) a response whose text carries that mark is ENDED
 * with the error event, before the chunk that completes it: the agent never
 * holds the whole mark, so it has nothing to parse (a mark split across
 * chunks is caught on the tail of the text before it).
 *
 * `onCall` reports each released call (as released, after the gate) once,
 * for the arbiter's tool-call record and the `tool_use` event; `onText`
 * reports assistant text for the `tllm_call` event. Both are observability,
 * never on the security path.
 */

import { parseArguments } from "./openai-wire.js";

/** The per-exchange tool-call gate (proxy.ts toolInputTransform). */
export type CallGate = (name: string, input: unknown, callId: string) => Promise<{ input: unknown; changed: boolean } | null>;

export interface ReleasedCall {
  id: string;
  name: string;
  input: unknown;
}

export interface OpenAiRewriterOptions {
  onCall?: (c: ReleasedCall) => void;
  onText?: (t: string) => void;
  log?: (m: string) => void;
  /** End a Chat response whose text carries TEXT_CALL_MARK (see TOOL CALLS
   *  WRITTEN AS TEXT). */
  refuseTextCalls?: boolean;
}

/** What makes Goose's ollama reader parse the assistant text for tool calls
 *  (formats/ollama.rs: `accumulated_text.contains("<function=")`). */
export const TEXT_CALL_MARK = "<function=";

/** Why a response with a tool call written as text is ended. */
const TEXT_CALL_WHY = "the model wrote a tool call in its text (`<function=`), which this agent would run without Mandu's gates";

/** A Chat content value's text (a string, or the text of its parts). */
function chatContentText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((p) => (isObj(p) && typeof p["text"] === "string" ? (p["text"] as string) : "")).join("");
}

/** The name a call gets when its arguments cannot be read. */
export const UNREADABLE_CALL_NAME = "mandu_refused_unreadable_call";

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

/** Gate one assembled call: the name and arguments to release. */
async function gateCall(gate: CallGate, name: string, args: string, id: string, log?: (m: string) => void): Promise<{ name: string; args: string; input: unknown }> {
  const input = parseArguments(args);
  if (input === null) {
    log?.(`openai: call ${id || "(no id)"} to ${name} has arguments that are not a JSON object: refused`);
    return { name: UNREADABLE_CALL_NAME, args: "{}", input: {} };
  }
  const r = await gate(name, input, id);
  const released = r?.changed ? r.input : input;
  // Always the canonical serialization of what the gate read, never the
  // model's own bytes: an agent whose JSON reader differs from JSON.parse
  // (a duplicate key read first-wins, a lenient repair) could otherwise run
  // arguments the gate never saw.
  return { name, args: JSON.stringify(released), input: released };
}

/** SSE framing: split a buffer into complete events (terminator kept). */
export class SseFramer {
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

/** The `event:` name and the joined `data:` payload of one SSE event. */
export function readEvent(raw: string): { event: string; data: string | null } {
  let event = "";
  const data: string[] = [];
  for (const line of raw.split(/\r?\n/)) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
  }
  return { event, data: data.length > 0 ? data.join("\n") : null };
}

// ── Chat Completions ───────────────────────────────────────────────────────

interface PendingChatCall {
  index: number;
  id: string;
  type: string;
  name: string;
  args: string;
  conflict?: boolean;
}

export class ChatStreamRewriter {
  private readonly framer = new SseFramer();
  /** Pending calls per choice index, by tool-call index. */
  private readonly pending = new Map<number, Map<number, PendingChatCall>>();
  /** The envelope (id / object / created / model) of the last chunk. */
  private envelope: Json = {};
  private failed = false;
  /** refuseTextCalls: the end of each choice's text so far, one character
   *  shorter than TEXT_CALL_MARK (a mark split across chunks). */
  private readonly textTail = new Map<number, string>();

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
    let out = "";
    const rest = this.framer.rest();
    if (rest.trim() !== "") out += await this.handle(`${rest}\n\n`);
    if (this.failed) return out;
    for (const ci of [...this.pending.keys()]) out += await this.flush(ci);
    return out;
  }

  private abort(why: string): string {
    this.failed = true;
    this.opts.log?.(`openai: FAIL-CLOSED ending the stream: ${why}`);
    return `data: ${JSON.stringify({ error: { type: "mandu_fail_closed", message: `mandu: ${why}; the rest of the response was not relayed` } })}\n\n`;
  }

  /** Release every pending call of one choice as one synthetic chunk. */
  private async flush(choice: number): Promise<string> {
    const calls = this.pending.get(choice);
    this.pending.delete(choice);
    if (!calls || calls.size === 0) return "";
    const out: Json[] = [];
    for (const c of [...calls.values()].sort((a, b) => a.index - b.index)) {
      const g = await gateCall(this.gate, c.name, c.args, c.id, this.opts.log);
      this.opts.onCall?.({ id: c.id, name: g.name, input: g.input });
      out.push({ index: c.index, ...(c.id ? { id: c.id } : {}), type: c.type || "function", function: { name: g.name, arguments: g.args } });
    }
    const chunk = { ...this.envelope, choices: [{ index: choice, delta: { tool_calls: out }, finish_reason: null }] };
    return `data: ${JSON.stringify(chunk)}\n\n`;
  }

  private async handle(raw: string): Promise<string> {
    const { data } = readEvent(raw);
    if (data === null) return raw; // a comment / keepalive
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
        if (this.opts.refuseTextCalls) {
          const t = chatContentText(delta["content"]);
          if (t !== "") {
            const seen = (this.textTail.get(ci) ?? "") + t;
            if (seen.includes(TEXT_CALL_MARK)) return this.abort(TEXT_CALL_WHY);
            this.textTail.set(ci, seen.slice(-(TEXT_CALL_MARK.length - 1)));
          }
        }
        if (delta["function_call"] !== undefined) return this.abort("the model sent a legacy function_call");
        const tcs = delta["tool_calls"];
        if (tcs !== undefined && tcs !== null) {
          if (!Array.isArray(tcs)) return this.abort("`tool_calls` is not an array");
          const calls = this.pending.get(ci) ?? new Map<number, PendingChatCall>();
          this.pending.set(ci, calls);
          tcs.forEach((tc: unknown, pos: number) => {
            const t = isObj(tc) ? tc : {};
            const idx = typeof t["index"] === "number" ? (t["index"] as number) : pos;
            const fn = isObj(t["function"]) ? (t["function"] as Json) : {};
            const cur = calls.get(idx) ?? { index: idx, id: "", type: "", name: "", args: "" };
            if (typeof t["id"] === "string" && t["id"] !== "" && cur.id === "") cur.id = t["id"] as string;
            if (typeof t["type"] === "string") cur.type = t["type"] as string;
            // The name arrives whole (OpenClaw keeps the last one sent, the AI
            // SDK the first): a second, DIFFERENT name is read differently by
            // the two, so it is refused below.
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

/** A buffered (non-streamed) Chat Completions response: gate every call in
 *  `choices[].message.tool_calls` in place. Returns whether anything changed;
 *  throws on a shape it cannot read (the caller answers 502). */
export async function gateChatJson(obj: Json, gate: CallGate, opts: OpenAiRewriterOptions = {}): Promise<boolean> {
  const choices = obj["choices"];
  if (choices === undefined) return false;
  if (!Array.isArray(choices)) throw new Error("`choices` is not an array");
  let changed = false;
  for (const ch of choices) {
    if (!isObj(ch)) throw new Error("a choice is not an object");
    const msg = ch["message"];
    if (!isObj(msg)) continue;
    if (typeof msg["content"] === "string") opts.onText?.(msg["content"] as string);
    if (opts.refuseTextCalls && chatContentText(msg["content"]).includes(TEXT_CALL_MARK)) throw new Error(TEXT_CALL_WHY);
    if (msg["function_call"] !== undefined) throw new Error("the model sent a legacy function_call");
    const tcs = msg["tool_calls"];
    if (tcs === undefined || tcs === null) continue;
    if (!Array.isArray(tcs)) throw new Error("`tool_calls` is not an array");
    for (const tc of tcs) {
      if (!isObj(tc) || !isObj(tc["function"])) throw new Error("a tool call is not a function call");
      const fn = tc["function"] as Json;
      const id = typeof tc["id"] === "string" ? (tc["id"] as string) : "";
      const name = typeof fn["name"] === "string" ? (fn["name"] as string) : "";
      const args = typeof fn["arguments"] === "string" ? (fn["arguments"] as string) : JSON.stringify(fn["arguments"] ?? {});
      const g = await gateCall(gate, name, args, id, opts.log);
      opts.onCall?.({ id, name: g.name, input: g.input });
      if (g.name !== name || g.args !== fn["arguments"]) {
        fn["name"] = g.name;
        fn["arguments"] = g.args;
        changed = true;
      }
    }
  }
  return changed;
}

// ── Responses API ──────────────────────────────────────────────────────────

/** Output item types a routed agent reads without executing anything. */
const INERT_ITEMS = new Set(["message", "reasoning", "compaction"]);

export class ResponsesStreamRewriter {
  private readonly framer = new SseFramer();
  /** A function_call item from `.output_item.added`, held (with its
   *  argument deltas) until its arguments are complete and gated: the item
   *  goes out announced under the name the gate released. */
  private readonly held = new Map<string, { added: Json; name: string; callId: string; outputIndex: number; args: string; announced: boolean; seqs: number[] }>();
  /** The gated result per item id: every snapshot carries the same one. */
  private readonly gated = new Map<string, Promise<{ name: string; args: string; input: unknown }>>();
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

  /** A stream cut after the deltas but before `.done`: gate what was held and
   *  close the item, so nothing ungated is left for the agent to assemble. */
  async end(): Promise<string> {
    if (this.failed) return "";
    let out = "";
    const rest = this.framer.rest();
    if (rest.trim() !== "") out += await this.handle(`${rest}\n\n`);
    if (this.failed) return out;
    for (const itemId of [...this.held.keys()]) out += await this.release(itemId, null);
    return out;
  }

  private abort(why: string): string {
    this.failed = true;
    this.opts.log?.(`openai: FAIL-CLOSED ending the stream: ${why}`);
    return serialize("error", { type: "error", code: "mandu_fail_closed", message: `mandu: ${why}; the rest of the response was not relayed` });
  }

  private gateItem(itemId: string, name: string, args: string, callId: string): Promise<{ name: string; args: string; input: unknown }> {
    let p = this.gated.get(itemId);
    if (!p) {
      p = gateCall(this.gate, name, args, callId, this.opts.log).then((g) => {
        this.opts.onCall?.({ id: callId, name: g.name, input: g.input });
        return g;
      });
      this.gated.set(itemId, p);
    }
    return p;
  }

  /**
   * Release a held function_call: the `.output_item.added` (under the gated
   * name, no arguments), one delta with the gated arguments and the
   * `.function_call_arguments.done`. `done` is the upstream `.done` event
   * when there is one (its other fields are kept). When the upstream numbers
   * its events, the synthesized ones carry a `sequence_number` too: the
   * first held delta's for the delta, the last one's for a synthesized
   * `.done` (Goose 1.53.0's reader rejects an event without one, captured
   * 2026-10-06; supported-agents.md §5.6).
   */
  private async release(itemId: string, done: Json | null): Promise<string> {
    const h = this.held.get(itemId);
    if (!h) return "";
    this.held.delete(itemId);
    const full = done && typeof done["arguments"] === "string" ? (done["arguments"] as string) : h.args;
    const g = await this.gateItem(itemId, h.name, full, h.callId);
    const seqOf = (o: Json | null): number | undefined => (o && typeof o["sequence_number"] === "number" ? (o["sequence_number"] as number) : undefined);
    const deltaSeq = h.seqs[0] ?? seqOf(done) ?? seqOf(h.added);
    const doneSeq = h.seqs.at(-1) ?? deltaSeq;
    let out = "";
    if (!h.announced) {
      const item = isObj(h.added["item"]) ? (h.added["item"] as Json) : {};
      out += serialize("response.output_item.added", { ...h.added, item: { ...item, name: g.name, arguments: "" } });
    }
    out += serialize("response.function_call_arguments.delta", {
      type: "response.function_call_arguments.delta",
      ...(deltaSeq !== undefined ? { sequence_number: deltaSeq } : {}),
      item_id: itemId, output_index: h.outputIndex, delta: g.args,
    });
    out += serialize("response.function_call_arguments.done", {
      ...(done ?? {
        type: "response.function_call_arguments.done",
        ...(doneSeq !== undefined ? { sequence_number: doneSeq } : {}),
        item_id: itemId, output_index: h.outputIndex,
      }),
      arguments: g.args,
      ...(done?.["name"] !== undefined || g.name !== h.name ? { name: g.name } : {}),
    });
    return out;
  }

  /** An output item as the agent may receive it; null when it may not. */
  private async item(item: Json): Promise<Json | null> {
    const type = String(item["type"] ?? "");
    if (type === "function_call") {
      const itemId = typeof item["id"] === "string" ? (item["id"] as string) : `call:${String(item["call_id"] ?? "")}`;
      const args = typeof item["arguments"] === "string" ? (item["arguments"] as string) : "";
      const g = await this.gateItem(itemId, String(item["name"] ?? ""), args, String(item["call_id"] ?? ""));
      return { ...item, name: g.name, arguments: g.args };
    }
    if (INERT_ITEMS.has(type)) {
      if (type === "message" && Array.isArray(item["content"])) {
        for (const p of item["content"]) if (isObj(p) && p["type"] === "output_text" && typeof p["text"] === "string") this.opts.onText?.(p["text"] as string);
      }
      return item;
    }
    return null;
  }

  private async handle(raw: string): Promise<string> {
    const { event, data } = readEvent(raw);
    if (data === null) return raw;
    let obj: unknown;
    try { obj = JSON.parse(data); } catch { return this.abort("a response event did not parse"); }
    if (!isObj(obj)) return this.abort("a response event is not an object");
    const type = typeof obj["type"] === "string" ? (obj["type"] as string) : event;

    switch (type) {
      case "response.output_item.added": {
        const item = obj["item"];
        if (!isObj(item)) return this.abort("an output item is not an object");
        const t = String(item["type"] ?? "");
        if (t === "function_call") {
          const id = typeof item["id"] === "string" ? (item["id"] as string) : `call:${String(item["call_id"] ?? "")}`;
          this.held.set(id, {
            added: obj,
            name: String(item["name"] ?? ""),
            callId: String(item["call_id"] ?? ""),
            outputIndex: typeof obj["output_index"] === "number" ? (obj["output_index"] as number) : 0,
            args: typeof item["arguments"] === "string" ? (item["arguments"] as string) : "",
            announced: false,
            seqs: [],
          });
          return "";
        }
        if (!INERT_ITEMS.has(t)) return this.abort(`the model produced a "${t}" item, which Mandu does not gate`);
        return raw;
      }
      case "response.function_call_arguments.delta": {
        const id = String(obj["item_id"] ?? "");
        const h = this.held.get(id);
        if (!h) return this.abort("argument deltas for a call that was never announced");
        h.args += typeof obj["delta"] === "string" ? (obj["delta"] as string) : "";
        if (typeof obj["sequence_number"] === "number") h.seqs.push(obj["sequence_number"] as number);
        return "";
      }
      case "response.function_call_arguments.done": {
        const id = String(obj["item_id"] ?? "");
        if (!this.held.has(id)) return this.abort("arguments for a call that was never announced");
        return this.release(id, obj);
      }
      case "response.output_item.done": {
        const item = obj["item"];
        if (!isObj(item)) return this.abort("an output item is not an object");
        let pre = "";
        const itemId = typeof item["id"] === "string" ? (item["id"] as string) : `call:${String(item["call_id"] ?? "")}`;
        if (item["type"] === "function_call" && this.held.has(itemId)) {
          // No `.done` came first: the snapshot's arguments are the call.
          const h = this.held.get(itemId)!;
          if (typeof item["arguments"] === "string") h.args = item["arguments"] as string;
          pre = await this.release(itemId, null);
        }
        const released = await this.item(item);
        if (released === null) return this.abort(`the model produced a "${String(item["type"])}" item, which Mandu does not gate`);
        return pre + (released === item ? raw : serialize(type, { ...obj, item: released }));
      }
      case "response.completed":
      case "response.incomplete":
      case "response.done": {
        let pre = "";
        for (const itemId of [...this.held.keys()]) pre += await this.release(itemId, null);
        const resp = obj["response"];
        if (!isObj(resp) || !Array.isArray(resp["output"])) return pre + raw;
        const out: unknown[] = [];
        for (const it of resp["output"] as unknown[]) {
          if (!isObj(it)) return this.abort("an output item is not an object");
          const released = await this.item(it);
          if (released === null) return this.abort(`the model produced a "${String(it["type"])}" item, which Mandu does not gate`);
          out.push(released);
        }
        return pre + serialize(type, { ...obj, response: { ...resp, output: out } });
      }
      case "response.output_text.delta":
        if (typeof obj["delta"] === "string") this.opts.onText?.(obj["delta"] as string);
        return raw;
      default:
        // Custom-tool / shell / computer call events belong to items refused
        // at `.output_item.added`; anything else (text, reasoning, lifecycle)
        // carries nothing a gate reads.
        if (/^response\.(custom_tool_call|local_shell_call|shell_call|computer_call|apply_patch_call|mcp_call)/.test(type)) {
          return this.abort(`the model produced a ${type} event, which Mandu does not gate`);
        }
        return raw;
    }
  }
}

/** A buffered Responses API response: gate every function_call in `output`
 *  in place. Throws on an item a routed agent would execute that is not a
 *  function call. Returns whether anything changed. */
export async function gateResponsesJson(obj: Json, gate: CallGate, opts: OpenAiRewriterOptions = {}): Promise<boolean> {
  const output = obj["output"];
  if (output === undefined) return false;
  if (!Array.isArray(output)) throw new Error("`output` is not an array");
  let changed = false;
  for (let i = 0; i < output.length; i++) {
    const item = output[i];
    if (!isObj(item)) throw new Error("an output item is not an object");
    const type = String(item["type"] ?? "");
    if (type === "function_call") {
      const id = String(item["call_id"] ?? "");
      const args = typeof item["arguments"] === "string" ? (item["arguments"] as string) : "";
      const g = await gateCall(gate, String(item["name"] ?? ""), args, id, opts.log);
      opts.onCall?.({ id, name: g.name, input: g.input });
      if (g.name !== item["name"] || g.args !== item["arguments"]) {
        output[i] = { ...item, name: g.name, arguments: g.args };
        changed = true;
      }
      continue;
    }
    if (!INERT_ITEMS.has(type)) throw new Error(`the model produced a "${type}" item, which Mandu does not gate`);
    if (type === "message" && Array.isArray(item["content"])) {
      for (const p of item["content"]) if (isObj(p) && p["type"] === "output_text" && typeof p["text"] === "string") opts.onText?.(p["text"] as string);
    }
  }
  return changed;
}

function serialize(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}
