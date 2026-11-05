/**
 * wire-adapter — the contract one model wire implements, and the three
 * adapters this proxy serves beside its native Messages wire
 * (model-wires.md §2): Chat Completions and the Responses API under
 * `/_mandu/openai/<id>`, Google Gemini under `/_mandu/google/<id>`, Ollama's
 * native chat API under `/_mandu/ollama/<id>`.
 *
 * Mandu-new (no reference origin). The core is everything that decides,
 * written once over the Messages shadow: the request rewrite, the tool-call
 * gate, the relay loop (proxy.ts onWireRequest / forwardWire). An adapter
 * only READS its wire: what must not go at all, the shadow and its
 * write-back, the answer's tool calls, the runs of reply text the token
 * repacker and the `MEDIA:` reply gate cut, the answer's id, the error shape
 * its clients print. A new wire is a new adapter here, never a new copy of
 * the relay loop or of a gate.
 */

import { OpenAiWireError, providerSideRefusal, shadowFor, type CallMemory, type Shadow } from "./openai-wire.js";
import { ChatStreamRewriter, ResponsesStreamRewriter, gateChatJson, gateResponsesJson, type CallGate, type OpenAiRewriterOptions } from "./openai-sse.js";
import { GeminiWireError, geminiRequestRefusal, geminiShadow } from "./gemini-wire.js";
import { GeminiStreamRewriter, gateGeminiJson } from "./gemini-sse.js";
import { OllamaWireError, ollamaRequestRefusal, ollamaShadow, ollamaToolNames } from "./ollama-wire.js";
import { OllamaStreamRewriter, gateOllamaJson } from "./ollama-ndjson.js";
import { ChatTextRepacker, GeminiTextRepacker, OllamaTextRepacker, ResponsesTextRepacker } from "./text-repack.js";
import {
  CHAT_WIRE, GEMINI_WIRE, OLLAMA_WIRE, RESPONSES_WIRE,
  gateChatJsonReply, gateGeminiJsonReply, gateOllamaJsonReply, gateResponsesJsonReply,
  type ReplyMediaStreamOptions, type ReplyMediaWire,
} from "./reply-media-stream.js";
import type { ResponseIdWire } from "./response-id.js";

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

/** The wires an adapter reads. */
export type WireId = "chat" | "responses" | "gemini" | "ollama";

/** Which provider prefix (and error shape) a wire is served under. */
export type WireFamily = "openai" | "google" | "ollama";

/** What the shadow needs that is not in the body. */
export interface ShadowContext {
  memory: CallMemory;
  /** The model the request path names (Gemini: the body has none). */
  model?: string;
  /** The request asks for a stream (Gemini: by its path). */
  stream: boolean;
}

/** A streamed answer's tool-call gate. */
export interface StreamRewriter {
  feed(chunk: string): Promise<string>;
  end(): Promise<string>;
}

/** A streamed answer's text-delta token repacker (pure string work). */
export interface StreamRepacker {
  feed(chunk: string): string;
  end(): string;
}

export interface WireAdapter {
  id: WireId;
  family: WireFamily;
  /** For messages: "Chat Completions", "Responses", "Gemini". */
  label: string;
  /** A request that must not go at all, or null (checked before the shadow). */
  refusal(body: Json): string | null;
  /** The Messages shadow and its write-back; throws a read error (400). */
  shadow(body: Json, ctx: ShadowContext): Shadow;
  /** Whether `err` is this wire's "cannot read this request" (400, nothing sent). */
  isReadError(err: unknown): boolean;
  /** Whether the request asks for a streamed answer. */
  wantsStream(body: Json, ctx: { stream: boolean }): boolean;
  /** A buffered answer gated in place; throws on a shape it cannot read. */
  gateJson(body: unknown, gate: CallGate, opts: OpenAiRewriterOptions): Promise<boolean>;
  streamRewriter(gate: CallGate, opts: OpenAiRewriterOptions): StreamRewriter;
  textRepacker(): StreamRepacker;
  replyWire: ReplyMediaWire;
  gateJsonReply(body: unknown, opts: ReplyMediaStreamOptions): Promise<boolean>;
  /** Where the answer's id is; null when the wire's answers carry none (Ollama). */
  responseIdWire: ResponseIdWire | null;
  /** The model a request names, for the events. */
  modelOf(body: Json, ctx: { model?: string }): string;
  /** The tool names the request declares, as sent, when the answer gate
   *  reads a call's name the way the agent maps it (Ollama). */
  toolNames?(body: Json): string[];
}

/** The body an OpenAI-family client prints (`{"error":{"message","type"}}`). */
export function openAiErrorBody(status: number, message: string): string {
  return JSON.stringify({ error: { type: status === 400 ? "invalid_request_error" : "mandu_fail_closed", message } });
}

/** The Google API's own error shape (`{"error":{"code","message","status"}}`). */
export function googleErrorBody(status: number, message: string): string {
  const s = status === 400 ? "INVALID_ARGUMENT" : status === 403 ? "PERMISSION_DENIED" : status === 413 ? "INVALID_ARGUMENT" : "UNAVAILABLE";
  return JSON.stringify({ error: { code: status, message, status: s } });
}

/** Ollama's own error shape (`{"error": "…"}`), which its clients print. */
export function ollamaErrorBody(_status: number, message: string): string {
  return JSON.stringify({ error: message });
}

/** The error body for a wire family. */
export function wireErrorBody(family: WireFamily, status: number, message: string): string {
  return family === "google" ? googleErrorBody(status, message)
    : family === "ollama" ? ollamaErrorBody(status, message)
      : openAiErrorBody(status, message);
}

const objectOnly = (body: unknown): Json => {
  if (!isObj(body)) throw new Error("not a JSON object");
  return body;
};

export const CHAT_ADAPTER: WireAdapter = {
  id: "chat",
  family: "openai",
  label: "Chat Completions",
  refusal: (body) => providerSideRefusal("chat", body),
  shadow: (body, ctx) => shadowFor("chat", body, ctx.memory),
  isReadError: (err) => err instanceof OpenAiWireError,
  wantsStream: (body) => body["stream"] === true,
  gateJson: (body, gate, opts) => gateChatJson(objectOnly(body), gate, opts),
  streamRewriter: (gate, opts) => new ChatStreamRewriter(gate, opts),
  textRepacker: () => new ChatTextRepacker(),
  replyWire: CHAT_WIRE,
  gateJsonReply: (body, opts) => (isObj(body) ? gateChatJsonReply(body, opts) : Promise.resolve(false)),
  responseIdWire: "chat",
  modelOf: (body) => (typeof body["model"] === "string" ? body["model"] : ""),
};

export const RESPONSES_ADAPTER: WireAdapter = {
  id: "responses",
  family: "openai",
  label: "Responses",
  refusal: (body) => providerSideRefusal("responses", body),
  shadow: (body, ctx) => shadowFor("responses", body, ctx.memory),
  isReadError: (err) => err instanceof OpenAiWireError,
  wantsStream: (body) => body["stream"] === true,
  gateJson: (body, gate, opts) => gateResponsesJson(objectOnly(body), gate, opts),
  streamRewriter: (gate, opts) => new ResponsesStreamRewriter(gate, opts),
  textRepacker: () => new ResponsesTextRepacker(),
  replyWire: RESPONSES_WIRE,
  gateJsonReply: (body, opts) => (isObj(body) ? gateResponsesJsonReply(body, opts) : Promise.resolve(false)),
  responseIdWire: "responses",
  modelOf: (body) => (typeof body["model"] === "string" ? body["model"] : ""),
};

export const GEMINI_ADAPTER: WireAdapter = {
  id: "gemini",
  family: "google",
  label: "Gemini",
  refusal: (body) => geminiRequestRefusal(body),
  shadow: (body, ctx) => geminiShadow(body, { model: ctx.model ?? "", stream: ctx.stream, memory: ctx.memory }),
  isReadError: (err) => err instanceof GeminiWireError,
  // `:streamGenerateContent?alt=sse` streams SSE; without `alt=sse` the
  // stream is a JSON array, read whole and gated as one body.
  wantsStream: (_body, ctx) => ctx.stream,
  gateJson: (body, gate, opts) => gateGeminiJson(body, gate, opts),
  streamRewriter: (gate, opts) => new GeminiStreamRewriter(gate, opts),
  textRepacker: () => new GeminiTextRepacker(),
  replyWire: GEMINI_WIRE,
  gateJsonReply: (body, opts) => gateGeminiJsonReply(body, opts),
  responseIdWire: "gemini",
  modelOf: (_body, ctx) => ctx.model ?? "",
};

export const OLLAMA_ADAPTER: WireAdapter = {
  id: "ollama",
  family: "ollama",
  label: "Ollama",
  refusal: (body) => ollamaRequestRefusal(body),
  shadow: (body, ctx) => ollamaShadow(body, { memory: ctx.memory }),
  isReadError: (err) => err instanceof OllamaWireError,
  // Ollama streams unless the request says `stream: false`.
  wantsStream: (body) => body["stream"] !== false,
  gateJson: (body, gate, opts) => gateOllamaJson(body, gate, opts),
  streamRewriter: (gate, opts) => new OllamaStreamRewriter(gate, opts),
  textRepacker: () => new OllamaTextRepacker(),
  replyWire: OLLAMA_WIRE,
  gateJsonReply: (body, opts) => gateOllamaJsonReply(body, opts),
  responseIdWire: null,
  modelOf: (body) => (typeof body["model"] === "string" ? body["model"] : ""),
  toolNames: (body) => ollamaToolNames(body),
};
