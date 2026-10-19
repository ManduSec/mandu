/**
 * mock-upstream — a fake OpenAI Responses upstream for the openai-proxy unit
 * suite.
 *
 * Mandu Track A (interceptors/openai-proxy) test helper. Provides an
 * `UpstreamFetcher` (src/proxy.ts) that records the forwarded request body and
 * returns a canned response — so the suite exercises the proxy end-to-end with
 * NO real OpenAI key and NO network. The proxy never parses the response (it
 * streams back verbatim), so the canned body is just whatever bytes the test
 * wants to observe round-tripped.
 */

import { Readable } from "node:stream";
import type { UpstreamFetcher, UpstreamResponse } from "../../src/proxy.js";

export interface CapturedUpstreamRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  /** Convenience: the body decoded to a UTF-8 string. */
  bodyText: string;
  /** Convenience: the body JSON-parsed (throws if not JSON). */
  json(): unknown;
}

export interface MockUpstreamOptions {
  /** Response status (default 200). */
  status?: number;
  /** Response headers (default content-type per kind). */
  headers?: Record<string, string>;
  /** SSE event stream body (pre-serialized string). */
  sse?: string;
  /** Split the SSE body into N chunks to test chunk-boundary parsing. */
  chunkInto?: number;
  /** Buffered JSON response body (sets content-type application/json). */
  json?: unknown;
  /** Raw body + content-type for passthrough cases. */
  raw?: { body: Buffer | string; contentType: string };
}

export class MockUpstream {
  /** The request bodies captured, in order. */
  readonly requests: CapturedUpstreamRequest[] = [];

  constructor(private readonly opts: MockUpstreamOptions = {}) {}

  /** The fetcher to hand to OpenAiProxy({ upstream }). */
  fetcher: UpstreamFetcher = async ({ method, path, headers, body }) => {
    const bodyText = body.toString("utf8");
    this.requests.push({
      method,
      path,
      headers,
      body,
      bodyText,
      json: () => JSON.parse(bodyText),
    });
    return this.buildResponse();
  };

  /** The most recent captured request body parsed as JSON. */
  lastJson(): unknown {
    const r = this.requests[this.requests.length - 1];
    if (!r) throw new Error("mock upstream: no request captured");
    return r.json();
  }

  private buildResponse(): UpstreamResponse {
    if (this.opts.sse !== undefined) {
      const headers = { "content-type": "text/event-stream", ...(this.opts.headers ?? {}) };
      const sse = this.opts.sse;
      const n = this.opts.chunkInto ?? 1;
      const body = n <= 1
        ? Readable.from([Buffer.from(sse, "utf8")])
        : Readable.from(chunkString(sse, n).map((s) => Buffer.from(s, "utf8")));
      return { status: this.opts.status ?? 200, headers, body };
    }
    if (this.opts.json !== undefined) {
      const headers = { "content-type": "application/json", ...(this.opts.headers ?? {}) };
      const buf = Buffer.from(JSON.stringify(this.opts.json), "utf8");
      return { status: this.opts.status ?? 200, headers, body: Readable.from([buf]) };
    }
    if (this.opts.raw !== undefined) {
      const headers = { "content-type": this.opts.raw.contentType, ...(this.opts.headers ?? {}) };
      const buf = Buffer.isBuffer(this.opts.raw.body)
        ? this.opts.raw.body
        : Buffer.from(this.opts.raw.body, "utf8");
      return { status: this.opts.status ?? 200, headers, body: Readable.from([buf]) };
    }
    return {
      status: this.opts.status ?? 200,
      headers: { "content-type": "application/json", ...(this.opts.headers ?? {}) },
      body: Readable.from([Buffer.from("{}")]),
    };
  }
}

/** Split `s` into `n` roughly-equal chunks (for chunk-boundary tests). */
function chunkString(s: string, n: number): string[] {
  const size = Math.ceil(s.length / n) || 1;
  const out: string[] = [];
  for (let i = 0; i < s.length; i += size) out.push(s.slice(i, i + size));
  return out.length ? out : [""];
}

/** One SSE event group: `event: <e>\ndata: <json>\n\n`. */
export function sseEvent(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

/**
 * Build a canonical Codex function_call SSE turn invoking `exec_command` with
 * `{cmd}`, split into `argDeltas` argument fragments — mirrors codex 0.136's
 * wire shape (fake-responses.ts): output_item.added → arguments.delta* →
 * arguments.done → output_item.done → response.completed.
 */
export function buildExecCommandSse(args: {
  cmd: string;
  callId?: string;
  itemId?: string;
  argDeltas?: number;
}): string {
  const callId = args.callId ?? "call_1";
  const itemId = args.itemId ?? "fc_1";
  const argsJson = JSON.stringify({ cmd: args.cmd });
  const n = Math.max(1, args.argDeltas ?? 2);
  const size = Math.ceil(argsJson.length / n) || 1;
  const parts: string[] = [];
  for (let i = 0; i < argsJson.length; i += size) parts.push(argsJson.slice(i, i + size));

  const fc = {
    type: "function_call",
    id: itemId,
    call_id: callId,
    name: "exec_command",
    arguments: argsJson,
    status: "completed",
  };
  let out = "";
  out += sseEvent("response.created", { type: "response.created", response: { id: "r", status: "in_progress", output: [] } });
  out += sseEvent("response.output_item.added", {
    type: "response.output_item.added",
    output_index: 0,
    item: { type: "function_call", id: itemId, call_id: callId, name: "exec_command", arguments: "" },
  });
  for (const p of parts) {
    out += sseEvent("response.function_call_arguments.delta", {
      type: "response.function_call_arguments.delta",
      item_id: itemId,
      output_index: 0,
      delta: p,
    });
  }
  out += sseEvent("response.function_call_arguments.done", {
    type: "response.function_call_arguments.done",
    item_id: itemId,
    output_index: 0,
    arguments: argsJson,
  });
  out += sseEvent("response.output_item.done", { type: "response.output_item.done", output_index: 0, item: fc });
  out += sseEvent("response.completed", {
    type: "response.completed",
    response: { id: "r", status: "completed", output: [fc], usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } },
  });
  return out;
}

/** A function_call turn for any tool (a Codex MCP call carries `namespace`). */
export function buildFunctionCallSse(args: { name: string; namespace?: string; arguments: Record<string, unknown>; callId?: string; itemId?: string }): string {
  const callId = args.callId ?? "call_1";
  const itemId = args.itemId ?? "fc_1";
  const argsJson = JSON.stringify(args.arguments);
  const head = { type: "function_call", id: itemId, call_id: callId, name: args.name, ...(args.namespace ? { namespace: args.namespace } : {}) };
  const fc = { ...head, arguments: argsJson, status: "completed" };
  let out = "";
  out += sseEvent("response.created", { type: "response.created", response: { id: "r", status: "in_progress", output: [] } });
  out += sseEvent("response.output_item.added", { type: "response.output_item.added", output_index: 0, item: { ...head, arguments: "" } });
  out += sseEvent("response.function_call_arguments.delta", { type: "response.function_call_arguments.delta", item_id: itemId, output_index: 0, delta: argsJson });
  out += sseEvent("response.function_call_arguments.done", { type: "response.function_call_arguments.done", item_id: itemId, output_index: 0, arguments: argsJson });
  out += sseEvent("response.output_item.done", { type: "response.output_item.done", output_index: 0, item: fc });
  out += sseEvent("response.completed", { type: "response.completed", response: { id: "r", status: "completed", output: [fc], usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } } });
  return out;
}

/** One call of a multi-call turn ({@link buildCallsSse}): a function_call
 *  (`arguments`, an optional `namespace`) or a custom_tool_call (`input`). */
export type TurnCall =
  | { name: string; namespace?: string; arguments: Record<string, unknown>; callId?: string }
  | { name: string; input: string; callId?: string };

/** ONE response (one model turn) carrying several calls, in order, each in
 *  the wire shape of {@link buildFunctionCallSse} / {@link buildCustomToolCallSse}. */
export function buildCallsSse(calls: readonly TurnCall[]): string {
  let out = sseEvent("response.created", { type: "response.created", response: { id: "r", status: "in_progress", output: [] } });
  const items: Array<Record<string, unknown>> = [];
  calls.forEach((c, i) => {
    const callId = c.callId ?? `call_${i}`;
    if ("arguments" in c) {
      const itemId = `fc_${i}`;
      const argsJson = JSON.stringify(c.arguments);
      const head = { type: "function_call", id: itemId, call_id: callId, name: c.name, ...(c.namespace ? { namespace: c.namespace } : {}) };
      const fc = { ...head, arguments: argsJson, status: "completed" };
      out += sseEvent("response.output_item.added", { type: "response.output_item.added", output_index: i, item: { ...head, arguments: "" } });
      out += sseEvent("response.function_call_arguments.delta", { type: "response.function_call_arguments.delta", item_id: itemId, output_index: i, delta: argsJson });
      out += sseEvent("response.function_call_arguments.done", { type: "response.function_call_arguments.done", item_id: itemId, output_index: i, arguments: argsJson });
      out += sseEvent("response.output_item.done", { type: "response.output_item.done", output_index: i, item: fc });
      items.push(fc);
    } else {
      const itemId = `ctc_${i}`;
      const item = { type: "custom_tool_call", id: itemId, call_id: callId, name: c.name, input: c.input, status: "completed" };
      out += sseEvent("response.output_item.added", { type: "response.output_item.added", output_index: i, item: { ...item, input: "" } });
      out += sseEvent("response.custom_tool_call_input.delta", { type: "response.custom_tool_call_input.delta", item_id: itemId, output_index: i, delta: c.input });
      out += sseEvent("response.custom_tool_call_input.done", { type: "response.custom_tool_call_input.done", item_id: itemId, output_index: i, input: c.input });
      out += sseEvent("response.output_item.done", { type: "response.output_item.done", output_index: i, item });
      items.push(item);
    }
  });
  out += sseEvent("response.completed", { type: "response.completed", response: { id: "r", status: "completed", output: items, usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } } });
  return out;
}

/** The call items Codex would act on in a relayed Responses SSE body: each
 *  `response.output_item.done` item, in order. */
export function deliveredItems(sse: string): Array<Record<string, unknown>> {
  return sse.split("\n\n")
    .filter((b) => b.includes("event: response.output_item.done"))
    .map((b) => (JSON.parse(b.slice(b.indexOf("data: ") + 6)) as { item: Record<string, unknown> }).item);
}

/** Build a plain assistant-text SSE turn (no function_call). */
export function buildTextSse(text: string): string {
  const m = { type: "message", id: "msg_f", status: "completed", role: "assistant", content: [{ type: "output_text", text, annotations: [] }] };
  let out = "";
  out += sseEvent("response.created", { type: "response.created", response: { id: "r", status: "in_progress", output: [] } });
  out += sseEvent("response.output_text.delta", { type: "response.output_text.delta", item_id: "msg_f", output_index: 0, content_index: 0, delta: text });
  out += sseEvent("response.output_text.done", { type: "response.output_text.done", item_id: "msg_f", output_index: 0, content_index: 0, text });
  out += sseEvent("response.completed", { type: "response.completed", response: { id: "r", status: "completed", output: [m] } });
  return out;
}

/** The JavaScript a codex ≥ 0.154 `exec` cell carries for one shell command
 *  (the observed shape, responses-types.ts header). */
export function scriptCellFor(args: Record<string, unknown>): string {
  return `const r = await tools.exec_command(${JSON.stringify(args)});\ntext(r.output);\n`;
}

/**
 * Build a canonical codex ≥ 0.154 SCRIPT-CELL SSE turn — a `custom_tool_call`
 * named `exec` whose `input` is JavaScript calling `tools.exec_command({cmd,
 * workdir, …})` — split into `inputDeltas` fragments, mirroring the wire codex
 * accepted live on 2026-09-24: output_item.added → custom_tool_call_input.delta*
 * → custom_tool_call_input.done → output_item.done → response.completed.
 * `input` overrides the cell source outright (a non-literal cell).
 */
export function buildScriptCellSse(args: {
  cmd?: string;
  workdir?: string;
  input?: string;
  callId?: string;
  itemId?: string;
  inputDeltas?: number;
}): string {
  const input = args.input ?? scriptCellFor({ cmd: args.cmd ?? "echo hi", ...(args.workdir ? { workdir: args.workdir } : {}), yield_time_ms: 10000, max_output_tokens: 2000 });
  return buildCustomToolCallSse({ name: "exec", input, callId: args.callId, itemId: args.itemId, inputDeltas: args.inputDeltas });
}

/** Any freeform (`custom_tool_call`) turn on the same wire as
 *  {@link buildScriptCellSse}: Codex's `apply_patch` names its tool and
 *  carries the patch text as `input`. */
export function buildCustomToolCallSse(args: { name: string; input: string; callId?: string; itemId?: string; inputDeltas?: number }): string {
  const callId = args.callId ?? "call_1";
  const itemId = args.itemId ?? "ctc_1";
  const input = args.input;
  const n = Math.max(1, args.inputDeltas ?? 2);
  const size = Math.ceil(input.length / n) || 1;
  const parts: string[] = [];
  for (let i = 0; i < input.length; i += size) parts.push(input.slice(i, i + size));

  const item = { type: "custom_tool_call", id: itemId, call_id: callId, name: args.name, input, status: "completed" };
  let out = "";
  out += sseEvent("response.created", { type: "response.created", response: { id: "r", status: "in_progress", output: [] } });
  out += sseEvent("response.output_item.added", {
    type: "response.output_item.added",
    output_index: 0,
    item: { type: "custom_tool_call", id: itemId, call_id: callId, name: args.name, input: "" },
  });
  for (const p of parts) {
    out += sseEvent("response.custom_tool_call_input.delta", { type: "response.custom_tool_call_input.delta", item_id: itemId, output_index: 0, delta: p });
  }
  out += sseEvent("response.custom_tool_call_input.done", { type: "response.custom_tool_call_input.done", item_id: itemId, output_index: 0, input });
  out += sseEvent("response.output_item.done", { type: "response.output_item.done", output_index: 0, item });
  out += sseEvent("response.completed", {
    type: "response.completed",
    response: { id: "r", status: "completed", output: [item], usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } },
  });
  return out;
}

/** The turn-2 request codex ≥ 0.154 sends after running a cell: the battery
 *  as an `additional_tools` item, the echoed `custom_tool_call`, and the
 *  `custom_tool_call_output` as an ARRAY of text parts (envelope, output). */
export function scriptCellTurn2(opts: { cmd: string; output: string; workdir?: string; callId?: string; envelope?: string; instructions?: string }): Record<string, unknown> {
  const callId = opts.callId ?? "call_1";
  const envelope = opts.envelope ?? "Script completed\nWall time 0.2 seconds\nOutput:\n";
  return {
    model: "gpt-5.6-terra",
    stream: true,
    ...(opts.instructions !== undefined ? { instructions: opts.instructions } : {}),
    input: [
      {
        type: "additional_tools", id: "at_1", role: "developer",
        tools: [
          { type: "namespace", name: "functions", description: "", tools: [
            { type: "custom", name: "exec", description: "Run JavaScript code to orchestrate/compose tool calls\n- Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." },
            { type: "function", name: "wait", description: "Waits on a yielded exec cell", parameters: {} },
          ] },
          { type: "namespace", name: "collaboration", description: "Tools for spawning and managing sub-agents.", tools: [
            { type: "function", name: "spawn_agent", description: "", parameters: {} },
          ] },
        ],
      },
      { type: "message", role: "user", content: [{ type: "input_text", text: "Read notes.md" }] },
      { type: "custom_tool_call", id: "ctc_1", status: "completed", call_id: callId, name: "exec", input: scriptCellFor({ cmd: opts.cmd, ...(opts.workdir ? { workdir: opts.workdir } : {}), yield_time_ms: 10000, max_output_tokens: 2000 }) },
      { type: "custom_tool_call_output", id: "ctco_1", call_id: callId, output: [{ type: "input_text", text: envelope }, { type: "input_text", text: opts.output }] },
    ],
  };
}
