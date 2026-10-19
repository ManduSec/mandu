/**
 * mock-upstream — a fake Anthropic upstream + SSE fixture builders.
 *
 * Mandu Track A (interceptors/anthropic-proxy) test helper. Provides an
 * `UpstreamFetcher` (src/proxy.ts) that records the forwarded request body and
 * returns a canned response — so the suite exercises the proxy end-to-end with
 * NO real Anthropic key and NO network. Also builds canonical SSE event streams
 * so the SSE-sniff path can be tested deterministically.
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
  /** SSE event stream body (array of {event,data} or pre-serialized string). */
  sse?: string;
  /** Buffered JSON response body (sets content-type application/json). */
  json?: unknown;
  /** Raw body + content-type for passthrough cases. */
  raw?: { body: Buffer | string; contentType: string };
  /** Optionally split the SSE body into N chunks to test chunk-boundary parsing. */
  chunkInto?: number;
}

export class MockUpstream {
  /** The request bodies captured, in order. */
  readonly requests: CapturedUpstreamRequest[] = [];

  constructor(private readonly opts: MockUpstreamOptions = {}) {}

  /** The fetcher to hand to AnthropicProxy({ upstream }). */
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
      return { status: this.opts.status ?? 200, headers, body: this.streamOf(this.opts.sse) };
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
    // Default: empty 200.
    return {
      status: this.opts.status ?? 200,
      headers: { "content-type": "application/json", ...(this.opts.headers ?? {}) },
      body: Readable.from([Buffer.from("{}")]),
    };
  }

  private streamOf(sse: string): Readable {
    const n = this.opts.chunkInto ?? 1;
    if (n <= 1) return Readable.from([Buffer.from(sse, "utf8")]);
    const size = Math.ceil(sse.length / n);
    const chunks: Buffer[] = [];
    for (let i = 0; i < sse.length; i += size) {
      chunks.push(Buffer.from(sse.slice(i, i + size), "utf8"));
    }
    return Readable.from(chunks);
  }
}

/** One SSE event line group: `event: <e>\ndata: <json>\n\n`. */
export function sseEvent(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

/**
 * Build a canonical Anthropic tool_use SSE stream for one tool call. The
 * input JSON is delivered as input_json_delta fragments (optionally split) to
 * mirror the real wire shape.
 */
export function buildToolUseSse(args: {
  id: string;
  name: string;
  input: Record<string, unknown>;
  /** Split the input JSON into this many partial_json deltas (default 2). */
  inputDeltas?: number;
  index?: number;
}): string {
  const index = args.index ?? 0;
  const inputStr = JSON.stringify(args.input);
  const n = Math.max(1, args.inputDeltas ?? 2);
  const size = Math.ceil(inputStr.length / n);
  const parts: string[] = [];
  for (let i = 0; i < inputStr.length; i += size) parts.push(inputStr.slice(i, i + size));

  let out = "";
  out += sseEvent("message_start", {
    type: "message_start",
    message: { id: "msg_1", role: "assistant", content: [] },
  });
  out += sseEvent("content_block_start", {
    type: "content_block_start",
    index,
    content_block: { type: "tool_use", id: args.id, name: args.name, input: {} },
  });
  for (const p of parts) {
    out += sseEvent("content_block_delta", {
      type: "content_block_delta",
      index,
      delta: { type: "input_json_delta", partial_json: p },
    });
  }
  out += sseEvent("content_block_stop", { type: "content_block_stop", index });
  out += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } });
  out += sseEvent("message_stop", { type: "message_stop" });
  return out;
}

/**
 * Build a canonical Anthropic TEXT-reply SSE stream (no tool_use): one text
 * content block delivered as text_delta fragments, mirroring the real wire shape
 * Claude Code receives for a plain answer.
 */
export function buildTextSse(text: string, opts: { deltas?: number } = {}): string {
  const n = Math.max(1, opts.deltas ?? 2);
  const size = Math.ceil(text.length / n) || 1;
  const parts: string[] = [];
  for (let i = 0; i < text.length; i += size) parts.push(text.slice(i, i + size));
  if (parts.length === 0) parts.push("");

  let out = "";
  out += sseEvent("message_start", {
    type: "message_start",
    message: { id: "msg_txt", role: "assistant", content: [] },
  });
  out += sseEvent("content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: { type: "text", text: "" },
  });
  for (const p of parts) {
    out += sseEvent("content_block_delta", {
      type: "content_block_delta",
      index: 0,
      delta: { type: "text_delta", text: p },
    });
  }
  out += sseEvent("content_block_stop", { type: "content_block_stop", index: 0 });
  out += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn" } });
  out += sseEvent("message_stop", { type: "message_stop" });
  return out;
}
