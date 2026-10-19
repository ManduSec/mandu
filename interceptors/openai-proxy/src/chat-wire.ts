/**
 * chat-wire — read a Chat Completions request as the Responses request this
 * proxy already masks, and write the masked result back onto the ORIGINAL
 * body (mandu.md §4.1 "Which requests go upstream"; supported-agents.md §5.5).
 *
 * Mandu Track A (interceptors/openai-proxy). The Chat Completions wire is the
 * one Kimi Code, Aider, the OpenHands CLI, nanobot and most local-model
 * setups speak. Its ingress of untrusted data is the same as the Responses
 * wire's: a tool's output re-entering the context, here a `role:"tool"`
 * message answering an assistant `tool_calls[]` entry.
 *
 * THE SHADOW (the approach of anthropic-proxy/src/openai-wire.ts, which reads
 * the same wire as a Messages request for OpenClaw / OpenCode). `chatShadow`
 * builds a ResponsesRequest carrying exactly what `rewriteRequest` reads:
 * every assistant tool call as a `function_call` item (the correlation that
 * names the tool and its origin), every tool message as a
 * `function_call_output` item, the user / assistant text as `message` items
 * (the transcript and the call shape), the tools as Responses function tools
 * (the handling prompt's capabilities). The rewrite, the view map's reverse
 * pass and the ingress events then run on the shadow unchanged, and `apply`
 * copies what they changed back onto a clone of the original body, by
 * position: a tool message's content, a tool call's arguments, and the
 * handling prompt (into the first system message, or a new one). Every other
 * byte of the original (fields this module does not read, `reasoning_content`,
 * provider options, the user's own images) goes upstream as the agent sent it.
 *
 * FAIL-CLOSED. A shape this module does not read is a `ChatWireError` (the
 * proxy answers 400 and sends nothing): an unknown role, the legacy
 * `function` role / `function_call` / `functions`, a tool message whose
 * content carries a non-text part (a tool's image would reach the model
 * past the mask), a system message with a non-text part. A tool that runs at
 * the provider (a non-function tool, `web_search_options`, OpenRouter's
 * `plugins`, an `:online` model) is refused the same way
 * (`chatProviderRefusal`): its results enter the model's context at the
 * provider, where no gate sees them.
 *
 * Pure (no I/O); never mutates its inputs.
 */

import { HANDLING_MARKER } from "./rewrite-request.js";
import type { InputItem, ResponsesRequest, ToolOutputItem } from "./responses-types.js";

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

/** A request this module cannot read safely: answered 400, never sent. */
export class ChatWireError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChatWireError";
  }
}

/** Request keys that make the PROVIDER fetch content into the model's
 *  context (Chat Completions `web_search_options`, OpenRouter `plugins`). */
const PROVIDER_FETCH_KEYS = ["web_search_options", "plugins"] as const;

/**
 * Why the request as a whole cannot go (a tool the provider runs, a
 * provider-side web fetch, the legacy function-calling fields), or null.
 * Copied from anthropic-proxy/src/openai-wire.ts `providerSideRefusal` (the
 * Chat half).
 */
export function chatProviderRefusal(body: Json): string | null {
  for (const k of PROVIDER_FETCH_KEYS) {
    if (body[k] !== undefined && body[k] !== null) {
      return `the request sets \`${k}\`, which makes the model provider fetch content into the model's context where Mandu cannot mask it`;
    }
  }
  const model = body["model"];
  if (typeof model === "string" && /:online$/i.test(model.trim())) {
    return `model ${model} searches the web at the provider (the :online suffix), where Mandu cannot mask what it reads`;
  }
  if (body["functions"] !== undefined || body["function_call"] !== undefined) {
    return "the request uses the legacy `functions` field; Mandu reads tools only from `tools`";
  }
  const tools = body["tools"];
  if (tools !== undefined && tools !== null) {
    if (!Array.isArray(tools)) return "`tools` is not an array";
    for (const t of tools) {
      if (!isObj(t) || t["type"] !== "function") {
        const type = isObj(t) ? String(t["type"] ?? "?") : typeof t;
        return `tool type "${type}" runs at the model provider (or is not a function tool), where Mandu cannot mask its results; only function tools are routed`;
      }
    }
  }
  return null;
}

/** A Chat content value as text: a string, or parts of the given types.
 *  Null when a part is not text. */
function chatText(content: unknown, textTypes: readonly string[]): string | null {
  if (content === null || content === undefined) return "";
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return null;
  const out: string[] = [];
  for (const p of content) {
    if (!isObj(p) || !textTypes.includes(String(p["type"]))) return null;
    const t = p["type"] === "refusal" && typeof p["refusal"] === "string" ? p["refusal"] : p["text"];
    if (typeof t !== "string") return null;
    out.push(t);
  }
  return out.join("");
}

export interface ChatShadow {
  /** What the rewrite reads. */
  shadow: ResponsesRequest;
  /** The agent's own system text (the transcript shows it beside the
   *  handling-prompt placeholder). */
  agentInstructions: string;
  /** The original body with the masked shadow's changes written back. */
  apply(masked: ResponsesRequest): Json;
}

/** Where one shadow item came from, and how to write its change back. */
type Link =
  | { kind: "output"; item: number; original: string; write: (body: Json, text: string) => void }
  | { kind: "call"; item: number; original: string; write: (body: Json, args: string) => void }
  // A user text part (confidentiality-plan-15 §3): the prompt filter may
  // replace a registered value in it with its symbol, written back here.
  | { kind: "user"; item: number; part: number; original: string; write: (body: Json, text: string) => void };

/**
 * Build the Responses shadow of a Chat Completions body. Throws
 * `ChatWireError` on a shape it cannot read.
 */
export function chatShadow(original: Json): ChatShadow {
  const messages = original["messages"];
  if (!Array.isArray(messages)) throw new ChatWireError("the Chat Completions request has no `messages` array");
  const input: InputItem[] = [];
  const links: Link[] = [];
  const systemTexts: string[] = [];

  messages.forEach((msg: unknown, j: number) => {
    if (!isObj(msg)) throw new ChatWireError(`messages[${j}] is not an object`);
    const role = msg["role"];
    if (role === "system" || role === "developer") {
      const text = chatText(msg["content"], ["text"]);
      if (text === null) throw new ChatWireError(`messages[${j}] (${String(role)}) carries a non-text part`);
      systemTexts.push(text);
      return;
    }
    if (role === "user") {
      // The user's own turn: one input_text part per text part (the
      // transcript joins them), each linked back so the prompt filter's
      // rewrite reaches the body (plan 15 §3). Non-text parts (the user's
      // images) go upstream as sent, as on the Responses wire.
      const c = msg["content"];
      const at = typeof c === "string" ? [null]
        : Array.isArray(c) ? c.flatMap((p, i) => (isObj(p) && p["type"] === "text" && typeof p["text"] === "string" ? [i] : []))
          : [];
      const parts = at.map((i) => ({ type: "input_text", text: i === null ? (c as string) : ((c as Json[])[i]!["text"] as string) }));
      input.push({ type: "message", role: "user", content: parts.length > 0 ? parts : [{ type: "input_text", text: "" }] });
      const item = input.length - 1;
      at.forEach((i, k) => links.push({
        kind: "user", item, part: k, original: parts[k]!.text,
        write: (body, t) => {
          const m = (body["messages"] as Json[])[j]!;
          if (i === null) m["content"] = t;
          else ((m["content"] as Json[])[i]!)["text"] = t;
        },
      }));
      return;
    }
    if (role === "assistant") {
      if (msg["function_call"] !== undefined && msg["function_call"] !== null) {
        throw new ChatWireError(`messages[${j}] uses the legacy function_call`);
      }
      const text = chatText(msg["content"], ["text", "refusal"]);
      if (text === null) throw new ChatWireError(`messages[${j}] (assistant) carries a non-text part`);
      if (text !== "") input.push({ type: "message", role: "assistant", content: [{ type: "output_text", text }] });
      const calls = msg["tool_calls"];
      if (calls === undefined || calls === null) return;
      if (!Array.isArray(calls)) throw new ChatWireError(`messages[${j}].tool_calls is not an array`);
      calls.forEach((tc: unknown, k: number) => {
        if (!isObj(tc) || !isObj(tc["function"])) throw new ChatWireError(`messages[${j}].tool_calls[${k}] is not a function call`);
        const fn = tc["function"] as Json;
        const args = typeof fn["arguments"] === "string" ? (fn["arguments"] as string) : JSON.stringify(fn["arguments"] ?? {});
        input.push({
          type: "function_call",
          call_id: typeof tc["id"] === "string" ? (tc["id"] as string) : "",
          name: typeof fn["name"] === "string" ? (fn["name"] as string) : "",
          arguments: args,
        });
        links.push({
          kind: "call", item: input.length - 1, original: args,
          write: (body, a) => { ((((body["messages"] as Json[])[j]!)["tool_calls"] as Json[])[k]!["function"] as Json)["arguments"] = a; },
        });
      });
      return;
    }
    if (role === "tool") {
      const text = chatText(msg["content"], ["text"]);
      if (text === null) {
        throw new ChatWireError(`messages[${j}] (tool) carries a non-text part, which Mandu cannot mask`);
      }
      input.push({ type: "function_call_output", call_id: typeof msg["tool_call_id"] === "string" ? (msg["tool_call_id"] as string) : "", output: text });
      links.push({
        kind: "output", item: input.length - 1, original: text,
        write: (body, t) => { ((body["messages"] as Json[])[j]!)["content"] = t; },
      });
      return;
    }
    throw new ChatWireError(`messages[${j}] has role "${String(role)}", which Mandu does not read`);
  });

  const tools = Array.isArray(original["tools"])
    ? (original["tools"] as unknown[]).map((t) => {
        const fn = isObj(t) && isObj(t["function"]) ? (t["function"] as Json) : {};
        return { type: "function", name: typeof fn["name"] === "string" ? fn["name"] : "", ...(typeof fn["description"] === "string" ? { description: fn["description"] } : {}) };
      })
    : [];
  const agentInstructions = systemTexts.join("\n\n");
  // A body that already carries the handling prompt is not given a second one
  // (the rewrite skips the injection when `instructions` has the marker).
  const marked = agentInstructions.includes(HANDLING_MARKER);
  const maxTokens = original["max_completion_tokens"] ?? original["max_tokens"];
  const shadow: ResponsesRequest = {
    model: typeof original["model"] === "string" ? (original["model"] as string) : "",
    input,
    ...(tools.length > 0 ? { tools } : {}),
    ...(marked ? { instructions: agentInstructions } : {}),
    ...(typeof maxTokens === "number" ? { max_output_tokens: maxTokens } : {}),
  } as ResponsesRequest;
  const shadowInstructions = shadow.instructions;

  return {
    shadow,
    agentInstructions,
    apply(masked: ResponsesRequest): Json {
      const body = structuredClone(original);
      const items = Array.isArray(masked.input) ? masked.input : [];
      for (const link of links) {
        const item = items[link.item];
        if (!item) continue;
        if (link.kind === "user") {
          const parts = (item as { content?: unknown }).content;
          const part = Array.isArray(parts) ? (parts[link.part] as { text?: unknown } | undefined) : undefined;
          if (typeof part?.text === "string" && part.text !== link.original) link.write(body, part.text);
        } else if (link.kind === "output") {
          const out = (item as ToolOutputItem).output;
          const text = typeof out === "string" ? out : JSON.stringify(out);
          if (text !== link.original) link.write(body, text);
        } else {
          const a = (item as { arguments?: unknown }).arguments;
          if (typeof a === "string" && a !== link.original) link.write(body, a);
        }
      }
      // The handling prompt LAST: a new system message moves every index the
      // writes above use.
      const prompt = masked.instructions;
      if (typeof prompt === "string" && prompt !== shadowInstructions && prompt.includes(HANDLING_MARKER)) {
        injectSystem(body, prompt);
      }
      return body;
    },
  };
}

/** Put the handling prompt in front of the agent's system text: prefixed to
 *  the first message when it is a system / developer message, else as a new
 *  system message at the start (the Responses wire prefixes `instructions`
 *  the same way). */
function injectSystem(body: Json, prompt: string): void {
  const msgs = body["messages"] as Json[];
  const first = msgs[0];
  if (first && (first["role"] === "system" || first["role"] === "developer")) {
    const c = first["content"];
    if (typeof c === "string") {
      first["content"] = c.length > 0 ? `${prompt}\n\n${c}` : prompt;
      return;
    }
    if (Array.isArray(c)) {
      first["content"] = [{ type: "text", text: prompt }, ...c];
      return;
    }
  }
  msgs.unshift({ role: "system", content: prompt });
}
