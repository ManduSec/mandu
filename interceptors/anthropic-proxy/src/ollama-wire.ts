/**
 * ollama-wire — read an Ollama native `/api/chat` request as the Messages
 * request the rest of this proxy gates, and write the gated result back onto
 * the ORIGINAL body (model-wires.md §8). The request half of the Ollama
 * adapter; the answer half is ollama-ndjson.ts.
 *
 * Mandu-new (no reference origin). The wire facts were read from the
 * published OpenClaw releases the real-OpenClaw lane runs (its `ollama`
 * provider, `api: "ollama"`: 2026.3.12, 2026.7.1-2, 2026.9.9, 2026.10.7,
 * `convertToOllamaMessages` / `buildOllamaChatRequest`) and Ollama's API
 * reference (`POST /api/chat`). Same pattern as gemini-wire.ts, with the same
 * builder (wire-shadow.ts), so every gate the Messages wire runs runs here
 * unchanged.
 *
 * THE SHADOW. A `system` message is system text; a `user` message's
 * `content` user text (the prompt filter may rewrite a registered value into
 * its symbol); an `assistant` message's `content` assistant text and each
 * `tool_calls[]` entry a `tool_use` (its `function.arguments` object); a
 * `tool` message a `tool_result`. An assistant `thinking` text is never read
 * nor written. `apply` writes back, by position, a tool result's masked
 * `content`, a call's changed `arguments`, a user text the prompt filter
 * rewrote, and the handling prompt (appended to the last leading system
 * message, or a system message of its own at the head: a model's chat
 * template may read only one).
 *
 * A TOOL'S IMAGES (`images` on a `tool` message, OpenClaw 2026.9 and later)
 * join that tool result, which the rewrite then masks whole, and leave the
 * body; so do the `images` of a `user` message right after a run of tool
 * messages (a client that moves a tool's images into the next user turn; a
 * user's own images in that exact spot are masked too, the fail-closed
 * direction). A user's own `images` anywhere else go upstream as sent, as
 * on the other wires.
 *
 * CORRELATION. Ollama's tool calls often carry no id: OpenClaw 2026.3.12
 * sends none anywhere, 2026.7.1 an id on the call but none on the result
 * (only `tool_name`), 2026.9.9 and later `tool_call_id` too. A call without
 * an `id` gets a positional one in the shadow; a result with a
 * `tool_call_id` is that call's; one without is matched to the first
 * unanswered call of its `tool_name` (any name when it has none) in the
 * assistant message before it, which is the order OpenClaw writes results
 * in; one that matches nothing is an unknown tool's (UNTRUSTED). The answer
 * side gives every call an id (ollama-ndjson.ts), which OpenClaw 2026.7 and
 * later keep and echo back.
 *
 * TOOL NAMES. OpenClaw 2026.10.7 renames a tool whose name is part of a
 * tool-call envelope (`tool_call`, the Tool Search dispatcher, is one) to
 * `openclaw_<name>` on this wire and maps it back before it runs, and runs
 * a call named `functions.<tool>` / `tools/<tool>` as `<tool>`. The gates
 * key on the agent's own names, so the shadow and the answer gate read
 * every name through `canonicalToolName`: a dispatcher call is unwrapped
 * and gated as on every other wire, never passed as an unknown tool.
 *
 * FAIL-CLOSED: a shape this module does not read is an `OllamaWireError` (the
 * proxy answers 400 and sends nothing): a top-level field the chat API does
 * not take (`prompt`, `system`, `template`, `context`, `raw`, `suffix`,
 * `images`: `/api/generate`'s, whose content Mandu would not read), a
 * message role other than system / user / assistant / tool, a message field
 * Mandu does not know, a field on a role that does not carry it (tool calls
 * on a user message, images on an assistant message), `content` that is not
 * a string, call arguments that are not an object, a `tools` entry that is
 * not a function.
 *
 * Pure (no I/O); never mutates its inputs.
 */

import type { ContentBlock, MessagesRequest, ToolResultBlock, ToolResultContentBlock, ToolUseBlock } from "./messages-types.js";
import {
  applyShadow, attachToRun, finishShadow, newBuilder, nonTextBlock, push, synthesizeCall,
  type Builder, type CallMemory, type Link, type Shadow,
} from "./wire-shadow.js";

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

/** A request this module cannot read safely: answered 400, never sent. */
export class OllamaWireError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OllamaWireError";
  }
}

// ── tool names ─────────────────────────────────────────────────────────────

/** The tool-call envelopes OpenClaw 2026.10.7 renames a tool name inside
 *  of (extensions/ollama tool-name-aliases.ts TOOL_CALL_ENVELOPES). */
const TOOL_CALL_ENVELOPES = [
  "<tool_call>",
  "<tool_calls>",
  "[TOOL_CALLS]",
  "<|tool▁calls▁begin|><|tool▁call▁begin|>function<|tool▁sep|>",
  "{\"name\":\"\",\"arguments\":",
];

const ALIAS_PREFIX = "openclaw_";

/**
 * The name the agent runs a call of `wire` under, as the gates know it, read
 * the way OpenClaw reads it (extensions/ollama `normalizeOllamaToolCallName`,
 * 2026.7.1 and later, then 2026.10.7's alias map):
 *   - the name is trimmed; one the request's tools name (`known`, the names
 *     on the wire) is kept; else a `functions.` / `function_` / `tools/` / …
 *     prefix is dropped when what is left is one of them (with no tool list,
 *     only a `.` or `/` separated one);
 *   - a tool whose name is part of a tool-call envelope is sent as
 *     `openclaw_<name>` (`openclaw_openclaw_<name>` when that is taken) and
 *     mapped back before it runs.
 * Over-reading is the fail-closed direction (a tool literally named
 * `openclaw_tool_call` would be gated as the dispatcher). Exported for the
 * answer gate and the tests.
 */
export function canonicalToolName(wire: string, known?: ReadonlySet<string>): string {
  let name = wire.trim();
  if (known === undefined || !known.has(name)) {
    if (known !== undefined && known.size > 0) {
      const stripped = name.replace(/^(?:functions?|tools?)[./_-]+/i, "").trim();
      if (stripped !== name && known.has(stripped)) name = stripped;
    } else {
      const stripped = name.replace(/^(?:functions?|tools?)[./]+/i, "").trim();
      if (stripped !== "") name = stripped;
    }
  }
  let base = name;
  while (base.startsWith(ALIAS_PREFIX) && base.length > ALIAS_PREFIX.length) base = base.slice(ALIAS_PREFIX.length);
  if (base !== name && TOOL_CALL_ENVELOPES.some((e) => e.includes(base))) name = base;
  return name;
}

/** The tool names a chat request declares, as sent (for canonicalToolName
 *  and the answer's text-call check). */
export function ollamaToolNames(body: Json): string[] {
  const tools = body["tools"];
  if (!Array.isArray(tools)) return [];
  return tools.flatMap((t) => (isObj(t) && isObj(t["function"]) && typeof t["function"]["name"] === "string" ? [t["function"]["name"] as string] : []));
}

// ── request-level refusals ─────────────────────────────────────────────────

/** The top-level fields of a chat request (Ollama's API reference; what
 *  OpenClaw sends). Anything else is refused: `/api/generate`'s `prompt`,
 *  `system`, `template`, `context`, `suffix`, `images` and `raw` carry
 *  content the shadow would not read. */
const TOP_KEYS: ReadonlySet<string> = new Set([
  "model", "messages", "tools", "format", "options", "stream", "keep_alive", "think",
  "truncate", "shift", "logprobs", "top_logprobs",
]);

/**
 * Why the request as a whole cannot go, or null. Checked before any shadow
 * is built: a field the chat API does not take (its content would pass
 * unread), a tool that is not a function declaration.
 */
export function ollamaRequestRefusal(body: Json): string | null {
  for (const key of Object.keys(body)) {
    if (!TOP_KEYS.has(key)) {
      return `the request carries "${key}", which Ollama's chat API does not take and Mandu does not read`;
    }
  }
  const tools = body["tools"];
  if (tools !== undefined && tools !== null) {
    if (!Array.isArray(tools)) return "`tools` is not a list";
    for (const t of tools) {
      if (!isObj(t) || (t["type"] !== undefined && t["type"] !== "function") || !isObj(t["function"])) {
        return "a `tools` entry is not a function declaration; only function tools are routed";
      }
    }
  }
  return null;
}

// ── the shadow ─────────────────────────────────────────────────────────────

/** Fields a chat message may carry, and the roles that carry each. */
const MESSAGE_FIELDS: Readonly<Record<string, ReadonlySet<string>>> = {
  role: new Set(["system", "user", "assistant", "tool"]),
  content: new Set(["system", "user", "assistant", "tool"]),
  images: new Set(["user", "tool"]),
  tool_calls: new Set(["assistant"]),
  thinking: new Set(["assistant"]),
  tool_name: new Set(["tool"]),
  tool_call_id: new Set(["tool"]),
};

/** Keys of a `tool_calls[]` entry and of its `function`. */
const CALL_KEYS: ReadonlySet<string> = new Set(["id", "type", "function"]);
const FUNCTION_KEYS: ReadonlySet<string> = new Set(["name", "arguments", "index", "description"]);

export interface OllamaShadowOptions {
  memory?: CallMemory;
}

interface TurnCall { id: string; name: string; answered: boolean }

export function ollamaShadow(original: Json, opts: OllamaShadowOptions = {}): Shadow {
  const b: Builder = newBuilder();
  const raw = original["messages"];
  if (raw !== undefined && raw !== null && !Array.isArray(raw)) throw new OllamaWireError("`messages` is not a list");
  const messages = (raw ?? []) as unknown[];

  const sysAt: number[] = [];
  const sysOrig: string[] = [];
  /** How many system messages open the conversation (the handling prompt joins the last). */
  let leadingSystem = 0;
  let turnCalls: TurnCall[] = [];
  /** The message before this one was a tool message (a run of results). */
  let lastWasResult = false;
  const known = new Set(ollamaToolNames(original));
  const canon = (n: string): string => canonicalToolName(n, known);
  const msgAt = (body: Json, j: number): Json => (body["messages"] as Json[])[j]!;

  messages.forEach((m: unknown, j: number) => {
    const where = `messages[${j}]`;
    if (!isObj(m)) throw new OllamaWireError(`${where} is not an object`);
    const role = m["role"];
    if (typeof role !== "string" || !MESSAGE_FIELDS["role"]!.has(role)) {
      throw new OllamaWireError(`${where} has role ${JSON.stringify(role)}, which Mandu does not read`);
    }
    for (const [key, value] of Object.entries(m)) {
      const roles = MESSAGE_FIELDS[key];
      if (roles === undefined) throw new OllamaWireError(`${where} has the field "${key}", which Mandu does not read`);
      if (!roles.has(role) && value !== undefined && value !== null) {
        throw new OllamaWireError(`${where} carries "${key}" on a "${role}" message, which Mandu does not read`);
      }
    }
    const content = m["content"];
    if (content !== undefined && content !== null && typeof content !== "string") {
      throw new OllamaWireError(`${where}.content is not a string`);
    }
    const text = typeof content === "string" ? content : "";
    const images = m["images"];
    if (images !== undefined && images !== null && !Array.isArray(images)) throw new OllamaWireError(`${where}.images is not a list`);
    if (role === "system") {
      lastWasResult = false;
      if (leadingSystem === j) leadingSystem = j + 1;
      sysAt.push(j);
      sysOrig.push(text);
      b.system.push({ type: "text", text });
      return;
    }

    if (role === "user") {
      // Images on a user message right after a run of tool messages are read
      // as the tools' (a client that moves a tool's images into the next
      // user turn, as OpenClaw does on the Gemini wire): they join the last
      // result, masked with it, and leave the body. A user's own images
      // anywhere else go upstream as sent (not read).
      if (lastWasResult && Array.isArray(images) && images.length > 0) {
        attachToRun(b, b.run.length - 1, images.map((img) => nonTextBlock({ images: [img] })));
        b.drops.push((body) => { delete msgAt(body, j)["images"]; });
      }
      lastWasResult = false;
      push(b, "user", [{ type: "text", text }], [{
        kind: "user", original: text,
        write: (body, t) => { msgAt(body, j)["content"] = t; },
      }]);
      return;
    }

    if (role === "assistant") {
      const blocks: ContentBlock[] = [];
      const links: Array<Link | null> = [];
      if (text !== "") { blocks.push({ type: "text", text }); links.push(null); }
      const calls = m["tool_calls"];
      if (calls !== undefined && calls !== null && !Array.isArray(calls)) throw new OllamaWireError(`${where}.tool_calls is not a list`);
      const turn: TurnCall[] = [];
      ((calls ?? []) as unknown[]).forEach((c, i) => {
        const cw = `${where}.tool_calls[${i}]`;
        if (!isObj(c)) throw new OllamaWireError(`${cw} is not an object`);
        for (const key of Object.keys(c)) if (!CALL_KEYS.has(key)) throw new OllamaWireError(`${cw} has the field "${key}", which Mandu does not read`);
        const fn = c["function"];
        if (!isObj(fn)) throw new OllamaWireError(`${cw}.function is not an object`);
        for (const key of Object.keys(fn)) if (!FUNCTION_KEYS.has(key)) throw new OllamaWireError(`${cw}.function has the field "${key}", which Mandu does not read`);
        const wireName = typeof fn["name"] === "string" ? fn["name"] : "";
        const args = fn["arguments"];
        if (args !== undefined && args !== null && !isObj(args)) {
          throw new OllamaWireError(`${cw}.function.arguments is not an object`);
        }
        const input = isObj(args) ? args : {};
        const id = typeof c["id"] === "string" && c["id"] !== "" ? c["id"] : `ollama-call:${j}:${i}`;
        blocks.push({ type: "tool_use", id, name: canon(wireName), input } as ToolUseBlock);
        b.callIds.add(id);
        turn.push({ id, name: wireName, answered: false });
        links.push({
          kind: "call", input, writable: true,
          write: (body, a) => {
            const f = ((msgAt(body, j)["tool_calls"] as Json[])[i]!)["function"] as Json;
            f["arguments"] = JSON.parse(a) as unknown;
          },
        });
      });
      push(b, "assistant", blocks, links);
      turnCalls = turn;
      lastWasResult = false;
      return;
    }

    // role === "tool"
    const name = typeof m["tool_name"] === "string" ? m["tool_name"] : "";
    const given = typeof m["tool_call_id"] === "string" && m["tool_call_id"] !== "" ? m["tool_call_id"] : "";
    let id = given;
    if (id === "") {
      const call = turnCalls.find((c) => !c.answered && (name === "" || c.name === name || canon(c.name) === canon(name)));
      id = call ? call.id : `ollama-result:${j}`;
    }
    const answered = turnCalls.find((c) => c.id === id && !c.answered);
    if (answered) answered.answered = true;
    if (!b.callIds.has(id)) synthesizeCall(b, id, opts.memory);
    const media: ToolResultContentBlock[] = ((images ?? []) as unknown[]).map((img) => nonTextBlock({ images: [img] }));
    const hadNonText = media.length > 0;
    const blockContent: ToolResultBlock["content"] = hadNonText ? [{ type: "text", text }, ...media] : text;
    const at = push(b, "user", [{ type: "tool_result", tool_use_id: id, content: blockContent } as ToolResultBlock], [{
      kind: "result", original: text, hadNonText,
      write: (body, t) => {
        const target = msgAt(body, j);
        target["content"] = t;
        // A tool's images were masked with its result: they leave the body.
        delete target["images"];
      },
    }]);
    if (!lastWasResult) b.run = [];
    b.run.push({ msg: at, block: 0 });
    lastWasResult = true;
  });

  const tools: unknown[] = [];
  const rawTools = original["tools"];
  for (const t of Array.isArray(rawTools) ? rawTools : []) {
    if (!isObj(t) || !isObj(t["function"])) continue;
    const fn = t["function"];
    tools.push({
      name: canon(String(fn["name"] ?? "")),
      description: fn["description"],
      input_schema: fn["parameters"],
    });
  }

  const shadow: MessagesRequest = finishShadow(b, original["model"], original["stream"] !== false, tools);
  return {
    shadow,
    apply: (gated) => applyShadow(original, b, gated, {
      count: sysAt.length,
      originals: sysOrig,
      set: (body, i, t) => { msgAt(body, sysAt[i]!)["content"] = t; },
      add: (body, texts) => {
        const extra = texts.join("\n\n");
        const list = (Array.isArray(body["messages"]) ? body["messages"] : (body["messages"] = [])) as Json[];
        if (leadingSystem > 0) {
          const last = list[leadingSystem - 1]!;
          const cur = typeof last["content"] === "string" ? last["content"] : "";
          last["content"] = cur === "" ? extra : `${cur}\n\n${extra}`;
        } else {
          list.unshift({ role: "system", content: extra });
        }
      },
    }),
  };
}

// ── POST /api/show ─────────────────────────────────────────────────────────

/**
 * Whether a `POST /api/show` body is a model lookup and nothing more:
 * `{model}` (or the older `{name}`) naming one model, and an optional
 * `verbose` flag. OpenClaw's model discovery sends `{model}`; the answer is
 * the model's metadata (its template, parameters, capabilities), which
 * carries no conversation. Null when it is; else why not.
 */
export function ollamaShowRefusal(body: Buffer): string | null {
  let v: unknown;
  try { v = JSON.parse(body.toString("utf8")); } catch { return "its body is not JSON"; }
  if (!isObj(v)) return "its body is not a JSON object";
  const keys = Object.keys(v);
  const named = keys.filter((k) => k === "model" || k === "name");
  if (named.length !== 1 || typeof v[named[0]!] !== "string") return "it does not name exactly one model";
  for (const k of keys) {
    if (k === "model" || k === "name") continue;
    if (k === "verbose" && typeof v[k] === "boolean") continue;
    return `it carries "${k}", which a model lookup does not`;
  }
  return null;
}

// ── MANDU_OLLAMA_UPSTREAMS ─────────────────────────────────────────────────

/** A routed provider id: what the launcher writes into the agent's config. */
const PROVIDER_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * MANDU_OLLAMA_UPSTREAMS: a JSON object of provider id → base URL, the
 * Ollama providers routed under /_mandu/ollama/<id> (model-wires.md §8.5).
 * Unset or empty ⇒ {}. Anything malformed THROWS, as MANDU_GOOGLE_UPSTREAMS
 * does: a proxy started without the routes the launcher asked for would
 * refuse every turn, one started with a garbled URL would send them
 * somewhere else.
 */
export function parseOllamaUpstreamsEnv(raw: string | undefined): Record<string, string> {
  if (raw === undefined || raw.trim() === "") return {};
  let v: unknown;
  try { v = JSON.parse(raw); } catch (e) { throw new Error(`MANDU_OLLAMA_UPSTREAMS is not JSON: ${(e as Error).message}`); }
  if (!isObj(v)) throw new Error("MANDU_OLLAMA_UPSTREAMS is not a JSON object");
  const out: Record<string, string> = {};
  for (const [id, url] of Object.entries(v)) {
    if (!PROVIDER_ID_RE.test(id)) throw new Error(`MANDU_OLLAMA_UPSTREAMS: provider id ${JSON.stringify(id)} is not a plain name`);
    if (typeof url !== "string") throw new Error(`MANDU_OLLAMA_UPSTREAMS: the URL for ${id} is not a string`);
    let u: URL;
    try { u = new URL(url); } catch { throw new Error(`MANDU_OLLAMA_UPSTREAMS: the URL for ${id} does not parse`); }
    if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error(`MANDU_OLLAMA_UPSTREAMS: the URL for ${id} is not http(s)`);
    if (u.search !== "" || u.hash !== "" || u.username !== "" || u.password !== "") {
      throw new Error(`MANDU_OLLAMA_UPSTREAMS: the URL for ${id} carries a query, fragment or credentials`);
    }
    out[id] = url;
  }
  return out;
}
