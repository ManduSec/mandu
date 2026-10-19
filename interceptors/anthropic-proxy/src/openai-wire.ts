/**
 * openai-wire — read an OpenAI-family request (Chat Completions or the
 * Responses API) as the Messages request the rest of this proxy gates, and
 * write the gated result back onto the ORIGINAL request (agent-e2e-harness.md
 * §9, "Other providers through the model proxy"; supported-agents.md §4).
 *
 * WHY HERE, not in the openai-proxy: OpenClaw and OpenCode speak an OpenAI
 * wire to a non-Anthropic model with THEIR tools (`exec`, `read`, `bash`,
 * OpenClaw's `tool_call` dispatcher, …), and every gate for those tools (the
 * per-session gate surface, the dispatcher unwrap, the refused-tool tables,
 * the exec / stdin / net / path / derived-label gates, the exec-output legs,
 * the unmapped-command backstop) lives in this proxy. The openai-proxy's gates
 * are Codex's. Reading the other wire here means ONE gate implementation for
 * those agents whatever model they talk to: a table added for OpenClaw is
 * enforced on both wires by construction, with no copy to drift.
 *
 * THE SHADOW. `chatShadow` / `responsesShadow` build a MessagesRequest that
 * carries exactly what the gates read: every tool result as a `tool_result`
 * block (content kept text vs non-text), every tool call as a `tool_use`
 * block (arguments parsed), the system text as `system` blocks, and the
 * user / assistant text (for the trusted-context haystack). `rewriteRequest`,
 * the view map's reverse pass and the net-gate history then run on the shadow
 * unchanged, and `apply` copies what they changed back onto a clone of the
 * original body, by position: a tool result's content, a tool call's
 * arguments, and the handling prompt. Every other byte of the original body
 * (fields this module does not know, reasoning items, provider options) goes
 * upstream as the agent sent it.
 *
 * FAIL-CLOSED. A shape this module does not read is a `OpenAiWireError`
 * (the proxy answers 400 and sends nothing): a message role, an input item
 * type or a content part that could carry a tool's output past the shadow.
 * A tool that runs at the provider (a hosted `web_search`, `file_search`,
 * `code_interpreter`, an MCP tool, OpenRouter's `web` plugin, an `:online`
 * model) is refused the same way: its results enter the model's context at
 * the provider, where no gate sees them.
 *
 * IMAGES A TOOL RETURNED. OpenClaw's Chat Completions transport cannot put an
 * image inside a `tool` message, so it sends the tool's images in the NEXT
 * user message ("Image(s) from tool result #N (read):" + image parts; read
 * from @openclaw/ai 2026.9.6 `convertMessages`). On the Messages wire those
 * bytes sit inside the tool_result and are masked with it. So a user message
 * that directly follows tool results and carries a non-text part is read as
 * that tool result's continuation: its non-text parts join the tool result in
 * the shadow (which masks the result whole), and `apply` drops them from the
 * user message. A user's own image in that exact position is masked too, the
 * fail-closed direction.
 *
 * CONTINUATIONS (Responses API). With `previous_response_id` the agent sends
 * only the new items, so a `function_call_output` may answer a call this
 * request does not carry. The proxy remembers every call it gated on the way
 * out (`CallMemory`, keyed by call id); the shadow then carries the
 * remembered call so the result is classified as that tool's. A call the
 * proxy never saw (it restarted) is classified as an unknown tool: UNTRUSTED.
 *
 * Pure (no I/O); never mutates its inputs.
 */

import type { ContentBlock, Message, MessagesRequest, SystemBlock, ToolResultBlock, ToolResultContentBlock, ToolUseBlock } from "./messages-types.js";
import { flattenToolResultContent } from "./rewrite-request.js";

/** Which OpenAI wire a request is on. */
export type OpenAiApi = "chat" | "responses";

/** A request this module cannot read safely: answered 400, never sent. */
export class OpenAiWireError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OpenAiWireError";
  }
}

/** Calls the proxy gated on the way out, by call id (see CONTINUATIONS). */
export interface CallMemory {
  get(callId: string): { name: string; input: Record<string, unknown> } | undefined;
}

export interface Shadow {
  /** What the gates read. */
  shadow: MessagesRequest;
  /** The original body with the gated shadow's changes written back. */
  apply(gated: MessagesRequest): Record<string, unknown>;
}

type Json = Record<string, unknown>;

const isObj = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

/** The filler OpenClaw inserts between tool results and a user message for
 *  providers that require an assistant turn there
 *  (`compat.requiresAssistantAfterToolResult`). */
const FILLER_ASSISTANT = "I have processed the tool results.";

/** "Image(s) from tool result #N (name):" — which tool result of the run the
 *  image parts after it belong to (1-based). */
const CARRIER_MARK_RE = /^Image\(s\) from tool result #(\d+)\b/;

/** Request keys that make the PROVIDER fetch content into the model's
 *  context (Chat Completions `web_search_options`, OpenRouter `plugins`). */
const PROVIDER_FETCH_KEYS = ["web_search_options", "plugins"] as const;

// ── request-level refusals ─────────────────────────────────────────────────

/**
 * Why the request as a whole cannot go (a tool the provider runs, a
 * provider-side web fetch), or null. Checked before any shadow is built.
 */
export function providerSideRefusal(api: OpenAiApi, body: Json): string | null {
  for (const k of PROVIDER_FETCH_KEYS) {
    if (body[k] !== undefined && body[k] !== null) {
      return `the request sets \`${k}\`, which makes the model provider fetch content into the model's context where Mandu cannot mask it`;
    }
  }
  const model = body["model"];
  if (typeof model === "string" && /:online$/i.test(model.trim())) {
    return `model ${model} searches the web at the provider (the :online suffix), where Mandu cannot mask what it reads`;
  }
  if (api === "chat" && (body["functions"] !== undefined || body["function_call"] !== undefined)) {
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

// ── shared helpers ─────────────────────────────────────────────────────────

/** Parse a tool call's JSON arguments; null when they are not a JSON object. */
export function parseArguments(args: unknown): Json | null {
  if (isObj(args)) return args;
  if (typeof args !== "string") return null;
  if (args.trim() === "") return {};
  try {
    const v: unknown = JSON.parse(args);
    return isObj(v) ? v : null;
  } catch {
    return null;
  }
}

function sameJson(a: unknown, b: unknown): boolean {
  try { return JSON.stringify(a) === JSON.stringify(b); } catch { return false; }
}

/** Where one shadow block came from, and how to write its change back. */
type Link =
  | { kind: "result"; write: (body: Json, text: string) => void; original: string; hadNonText: boolean }
  | { kind: "call"; write: (body: Json, args: string) => void; input: Json; writable: boolean }
  // A user text (confidentiality-plan-15 §3): the prompt filter may replace a
  // registered value in it with its symbol, and the change must reach the
  // body the provider receives. Before plan 15 user text was pushed with a
  // null link and nothing in it could change.
  | { kind: "user"; write: (body: Json, text: string) => void; original: string };

interface Builder {
  messages: Message[];
  system: SystemBlock[];
  /** links[msgIdx][blockIdx] */
  links: Array<Array<Link | null>>;
  /** Tool results of the current run (for image carriers), with their shadow position. */
  run: Array<{ msg: number; block: number }>;
  /** Carrier parts to drop on apply: (body) => void. */
  drops: Array<(body: Json) => void>;
  /** Call ids present as a tool_use in the shadow. */
  callIds: Set<string>;
}

function newBuilder(): Builder {
  return { messages: [], system: [], links: [], run: [], drops: [], callIds: new Set() };
}

function push(b: Builder, role: "user" | "assistant", blocks: ContentBlock[], links: Array<Link | null>): number {
  b.messages.push({ role, content: blocks });
  b.links.push(links);
  return b.messages.length - 1;
}

/** Attach a carrier's non-text parts to a tool result of the preceding run. */
function attachToRun(b: Builder, runIdx: number, blocks: ToolResultContentBlock[]): void {
  const at = b.run[Math.min(Math.max(runIdx, 0), b.run.length - 1)];
  if (!at) return;
  const tr = (b.messages[at.msg]!.content as ContentBlock[])[at.block] as ToolResultBlock;
  const cur = tr.content;
  const base: ToolResultContentBlock[] = typeof cur === "string" ? (cur === "" ? [] : [{ type: "text", text: cur }]) : [...(cur ?? [])];
  tr.content = [...base, ...blocks];
  const link = b.links[at.msg]![at.block];
  if (link && link.kind === "result") link.hadNonText = true;
}

/** A non-text content part as a shadow block. Its `type` is not "text", so
 *  the rewrite forces the whole tool result UNTRUSTED and masks it; the part
 *  itself is kept whole so the symbol's value is the original bytes. */
function nonTextBlock(part: unknown): ToolResultContentBlock {
  return { type: "image", source: { type: "openai-part", part } } as ToolResultContentBlock;
}

function carrierTargets(parts: unknown[], runLength: number): Array<{ runIdx: number; part: unknown; index: number }> {
  const out: Array<{ runIdx: number; part: unknown; index: number }> = [];
  let cur = runLength - 1;
  parts.forEach((p, index) => {
    if (isObj(p) && (p["type"] === "text" || p["type"] === "input_text") && typeof p["text"] === "string") {
      const m = CARRIER_MARK_RE.exec(p["text"] as string);
      if (m) cur = Math.min(Number(m[1]) - 1, runLength - 1);
      return;
    }
    out.push({ runIdx: cur, part: p, index });
  });
  return out;
}

function finishShadow(b: Builder, model: unknown, stream: unknown, tools: unknown[]): MessagesRequest {
  return {
    model: typeof model === "string" ? model : "",
    ...(b.system.length > 0 ? { system: b.system } : {}),
    messages: b.messages,
    ...(tools.length > 0 ? { tools } : {}),
    ...(stream === true ? { stream: true } : {}),
  };
}

/**
 * Write the gated shadow back. `setSystem(body, i, text)` rewrites the i-th
 * original system text; `addSystem(body, texts)` places texts the rewrite
 * appended (the handling prompt).
 */
function applyShadow(
  original: Json,
  b: Builder,
  gated: MessagesRequest,
  sys: { count: number; originals: string[]; set: (body: Json, i: number, text: string) => void; add: (body: Json, texts: string[]) => void },
): Json {
  const body = structuredClone(original);
  const msgs = Array.isArray(gated.messages) ? gated.messages : [];
  for (let m = 0; m < b.links.length; m++) {
    const content = msgs[m]?.content;
    if (!Array.isArray(content)) continue;
    const links = b.links[m]!;
    for (let k = 0; k < links.length; k++) {
      const link = links[k];
      const block = content[k];
      if (!link || !block) continue;
      if (link.kind === "user") {
        const text = (block as { text?: unknown }).text;
        if (typeof text === "string" && text !== link.original) link.write(body, text);
      } else if (link.kind === "result") {
        const tr = block as ToolResultBlock;
        const text = flattenToolResultContent(tr.content);
        // A result that carried a non-text part is always rewritten (the
        // rewrite masks it); a text result only when its text changed.
        if (link.hadNonText || text !== link.original) link.write(body, text);
      } else {
        const tu = block as ToolUseBlock;
        if (link.writable && isObj(tu.input) && !sameJson(tu.input, link.input)) link.write(body, JSON.stringify(tu.input));
      }
    }
  }
  for (const d of b.drops) d(body);
  // The system text LAST: adding a system message moves every index the
  // writes above use.
  const gs = gated.system;
  const gatedSys: string[] = typeof gs === "string" ? [gs] : Array.isArray(gs) ? gs.map((s) => String((s as SystemBlock).text ?? "")) : [];
  for (let i = 0; i < Math.min(sys.count, gatedSys.length); i++) {
    if (gatedSys[i] !== sys.originals[i]) sys.set(body, i, gatedSys[i]!);
  }
  if (gatedSys.length > sys.count) sys.add(body, gatedSys.slice(sys.count));
  return body;
}

// ── Chat Completions ───────────────────────────────────────────────────────

/** A Chat Completions content value as text: a string, or text parts. Null
 *  when a part is not text. */
function chatText(content: unknown, textTypes: readonly string[]): string | null {
  if (content === null || content === undefined) return "";
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return null;
  const out: string[] = [];
  for (const p of content) {
    if (!isObj(p) || !textTypes.includes(String(p["type"]))) return null;
    // A refusal part carries its text under `refusal`.
    const t = p["type"] === "refusal" && typeof p["refusal"] === "string" ? p["refusal"] : p["text"];
    if (typeof t !== "string") return null;
    out.push(t);
  }
  return out.join("");
}

export function chatShadow(original: Json, memory?: CallMemory): Shadow {
  const messages = original["messages"];
  if (!Array.isArray(messages)) throw new OpenAiWireError("Chat Completions request has no `messages` array");
  const b = newBuilder();
  const sysIdx: number[] = [];
  const sysOrig: string[] = [];
  let lastWasTool = false;
  let fillerAfterTool = false;

  messages.forEach((msg: unknown, j: number) => {
    if (!isObj(msg)) throw new OpenAiWireError(`messages[${j}] is not an object`);
    const role = msg["role"];
    if (role === "system" || role === "developer") {
      const text = chatText(msg["content"], ["text"]);
      if (text === null) throw new OpenAiWireError(`messages[${j}] (${String(role)}) carries a non-text part`);
      sysIdx.push(j);
      sysOrig.push(text);
      b.system.push({ type: "text", text });
      lastWasTool = false;
      return;
    }
    if (role === "tool") {
      if (!lastWasTool) b.run = [];
      const id = typeof msg["tool_call_id"] === "string" ? (msg["tool_call_id"] as string) : "";
      const c = msg["content"];
      let content: ToolResultBlock["content"];
      let hadNonText = false;
      if (typeof c === "string" || c === null || c === undefined) {
        content = typeof c === "string" ? c : "";
      } else if (Array.isArray(c)) {
        content = c.map((p) => {
          if (isObj(p) && p["type"] === "text" && typeof p["text"] === "string") return { type: "text", text: p["text"] as string };
          hadNonText = true;
          return nonTextBlock(p);
        });
      } else {
        throw new OpenAiWireError(`messages[${j}] (tool) content is neither text nor parts`);
      }
      const original = flattenToolResultContent(content);
      if (id && !b.callIds.has(id)) synthesizeCall(b, id, memory);
      const tr: ToolResultBlock = { type: "tool_result", tool_use_id: id, content };
      const m = push(b, "user", [tr], [{
        kind: "result", original, hadNonText,
        write: (body, text) => { ((body["messages"] as Json[])[j]!)["content"] = text; },
      }]);
      b.run.push({ msg: m, block: 0 });
      lastWasTool = true;
      fillerAfterTool = false;
      return;
    }
    if (role === "assistant") {
      if (msg["function_call"] !== undefined) throw new OpenAiWireError(`messages[${j}] uses the legacy function_call`);
      const text = chatText(msg["content"], ["text", "refusal"]);
      if (text === null) throw new OpenAiWireError(`messages[${j}] (assistant) carries a non-text part`);
      // OpenClaw's filler between tool results and the image carrier.
      if (lastWasTool && text.trim() === FILLER_ASSISTANT && msg["tool_calls"] === undefined) {
        fillerAfterTool = true;
        lastWasTool = false;
        return;
      }
      const blocks: ContentBlock[] = [];
      const links: Array<Link | null> = [];
      if (text !== "") { blocks.push({ type: "text", text }); links.push(null); }
      const calls = msg["tool_calls"];
      if (calls !== undefined && calls !== null) {
        if (!Array.isArray(calls)) throw new OpenAiWireError(`messages[${j}].tool_calls is not an array`);
        calls.forEach((tc: unknown, k: number) => {
          if (!isObj(tc) || !isObj(tc["function"])) throw new OpenAiWireError(`messages[${j}].tool_calls[${k}] is not a function call`);
          const fn = tc["function"] as Json;
          const id = typeof tc["id"] === "string" ? (tc["id"] as string) : "";
          const name = typeof fn["name"] === "string" ? (fn["name"] as string) : "";
          const parsed = parseArguments(fn["arguments"]);
          blocks.push({ type: "tool_use", id, name, input: parsed ?? {} } as ToolUseBlock);
          if (id) b.callIds.add(id);
          links.push({
            kind: "call", input: parsed ?? {}, writable: parsed !== null,
            write: (body, args) => {
              const t = ((((body["messages"] as Json[])[j]!)["tool_calls"] as Json[])[k]!)["function"] as Json;
              t["arguments"] = args;
            },
          });
        });
      }
      push(b, "assistant", blocks, links);
      lastWasTool = false;
      fillerAfterTool = false;
      return;
    }
    if (role === "user") {
      const c = msg["content"];
      const afterTool = (lastWasTool || fillerAfterTool) && b.run.length > 0;
      const userText = (i: number | null, original: string): Link => ({
        kind: "user", original,
        write: (body, text) => {
          const m = (body["messages"] as Json[])[j]!;
          if (i === null) m["content"] = text;
          else ((m["content"] as Json[])[i]!)["text"] = text;
        },
      });
      if (typeof c === "string" || c === null || c === undefined) {
        if (typeof c === "string" && c !== "") push(b, "user", [{ type: "text", text: c }], [userText(null, c)]);
        else push(b, "user", [], []);
      } else if (Array.isArray(c)) {
        const nonText = c.some((p) => !(isObj(p) && p["type"] === "text"));
        if (afterTool && nonText) {
          // The tool results' image carrier (see IMAGES A TOOL RETURNED).
          const targets = carrierTargets(c, b.run.length);
          const byRun = new Map<number, ToolResultContentBlock[]>();
          for (const t of targets) byRun.set(t.runIdx, [...(byRun.get(t.runIdx) ?? []), nonTextBlock(t.part)]);
          for (const [runIdx, blocks] of byRun) attachToRun(b, runIdx, blocks);
          const dropIdx = new Set(targets.map((t) => t.index));
          b.drops.push((body) => {
            const m = (body["messages"] as Json[])[j]!;
            const kept = (m["content"] as unknown[]).filter((_, i) => !dropIdx.has(i));
            m["content"] = kept.length > 0 ? kept : [{ type: "text", text: "(a tool result's images: masked by Mandu)" }];
          });
          const at = c.flatMap((p, i) => (isObj(p) && p["type"] === "text" ? [i] : []));
          const texts = at.map((i) => ({ type: "text", text: String((c[i] as Json)["text"] ?? "") }));
          push(b, "user", texts, at.map((i, k) => (typeof (c[i] as Json)["text"] === "string" ? userText(i, texts[k]!.text) : null)));
        } else {
          const at = c.flatMap((p, i) => (isObj(p) && p["type"] === "text" && typeof p["text"] === "string" ? [i] : []));
          const texts = at.map((i) => ({ type: "text", text: (c[i] as Json)["text"] as string }));
          push(b, "user", texts, at.map((i, k) => userText(i, texts[k]!.text)));
        }
      } else {
        throw new OpenAiWireError(`messages[${j}] (user) content is neither text nor parts`);
      }
      lastWasTool = false;
      fillerAfterTool = false;
      return;
    }
    throw new OpenAiWireError(`messages[${j}] has role "${String(role)}", which Mandu does not read`);
  });

  const tools = (Array.isArray(original["tools"]) ? original["tools"] : []).map((t) => {
    const fn = isObj(t) && isObj(t["function"]) ? (t["function"] as Json) : {};
    return { name: String(fn["name"] ?? ""), description: fn["description"], input_schema: fn["parameters"] };
  });

  return {
    shadow: finishShadow(b, original["model"], original["stream"], tools),
    apply: (gated) => applyShadow(original, b, gated, {
      count: sysIdx.length,
      originals: sysOrig,
      set: (body, i, text) => { ((body["messages"] as Json[])[sysIdx[i]!]!)["content"] = text; },
      add: (body, texts) => {
        const msgs = body["messages"] as Json[];
        const extra = texts.join("\n\n");
        if (sysIdx.length > 0) {
          // Appended to the FIRST system message: some chat templates accept
          // exactly one system message, and only first.
          const first = msgs[sysIdx[0]!]!;
          const cur = first["content"];
          if (Array.isArray(cur)) first["content"] = [...cur, { type: "text", text: `\n\n${extra}` }];
          else first["content"] = `${typeof cur === "string" ? cur : ""}\n\n${extra}`;
        } else {
          msgs.unshift({ role: "system", content: extra });
        }
      },
    }),
  };
}

/** A remembered call as a shadow tool_use, just before its result (the
 *  call's own turn is not in this request; nothing is written back). */
function synthesizeCall(b: Builder, callId: string, memory?: CallMemory): void {
  const r = memory?.get(callId);
  if (!r) return;
  b.callIds.add(callId);
  push(b, "assistant", [{ type: "tool_use", id: callId, name: r.name, input: r.input } as ToolUseBlock], [null]);
}

// ── Responses API ──────────────────────────────────────────────────────────

/** Input item types that carry nothing a gate reads (passed through). */
const PASS_ITEMS = new Set(["reasoning", "compaction", "item_reference"]);

export function responsesShadow(original: Json, memory?: CallMemory): Shadow {
  const b = newBuilder();
  const sysRefs: Array<"instructions" | number> = [];
  const sysOrig: string[] = [];
  const instructions = original["instructions"];
  if (instructions !== undefined && instructions !== null) {
    if (typeof instructions !== "string") throw new OpenAiWireError("`instructions` is not a string");
    sysRefs.push("instructions");
    sysOrig.push(instructions);
    b.system.push({ type: "text", text: instructions });
  }
  const rawInput = original["input"];
  const items: unknown[] = typeof rawInput === "string" ? [{ type: "message", role: "user", content: rawInput }]
    : Array.isArray(rawInput) ? rawInput
    : rawInput === undefined || rawInput === null ? []
    : (() => { throw new OpenAiWireError("`input` is neither a string nor an array"); })();
  const inputIsString = typeof rawInput === "string";
  /** A string `input` the prompt filter rewrote (written by its user link). */
  let inputWritten = false;
  let lastWasResult = false;

  const itemAt = (body: Json, j: number): Json => (body["input"] as Json[])[j]!;

  items.forEach((item: unknown, j: number) => {
    if (!isObj(item)) throw new OpenAiWireError(`input[${j}] is not an object`);
    const type = item["type"] ?? (item["role"] !== undefined ? "message" : undefined);
    if (type === "message") {
      const role = item["role"];
      const c = item["content"];
      if (role === "system" || role === "developer") {
        const text = chatText(c, ["input_text", "text"]);
        if (text === null) throw new OpenAiWireError(`input[${j}] (${String(role)}) carries a non-text part`);
        sysRefs.push(j);
        sysOrig.push(text);
        b.system.push({ type: "text", text });
        lastWasResult = false;
        return;
      }
      if (role === "assistant") {
        const text = chatText(c, ["output_text", "input_text", "text", "refusal"]);
        if (text === null) throw new OpenAiWireError(`input[${j}] (assistant) carries a part Mandu does not read`);
        push(b, "assistant", text !== "" ? [{ type: "text", text }] : [], text !== "" ? [null] : []);
        lastWasResult = false;
        return;
      }
      if (role === "user") {
        const userText = (i: number | null, original: string): Link => ({
          kind: "user", original,
          write: (body, text) => {
            if (i === null && inputIsString) { body["input"] = text; inputWritten = true; return; }
            const it = itemAt(body, j);
            if (i === null) it["content"] = text;
            else ((it["content"] as Json[])[i]!)["text"] = text;
          },
        });
        if (typeof c === "string" || c === undefined || c === null) {
          if (typeof c === "string" && c !== "") push(b, "user", [{ type: "text", text: c }], [userText(null, c)]);
          else push(b, "user", [], []);
        } else if (Array.isArray(c)) {
          const isText = (p: unknown): boolean => isObj(p) && (p["type"] === "input_text" || p["type"] === "text");
          const at = c.flatMap((p, i) => (isText(p) ? [i] : []));
          const texts = at.map((i) => ({ type: "text", text: String((c[i] as Json)["text"] ?? "") }));
          const textLinks = at.map((i, k) => (typeof (c[i] as Json)["text"] === "string" ? userText(i, texts[k]!.text) : null));
          if (lastWasResult && b.run.length > 0 && c.some((p) => !isText(p))) {
            const targets = carrierTargets(c, b.run.length);
            const byRun = new Map<number, ToolResultContentBlock[]>();
            for (const t of targets) byRun.set(t.runIdx, [...(byRun.get(t.runIdx) ?? []), nonTextBlock(t.part)]);
            for (const [runIdx, blocks] of byRun) attachToRun(b, runIdx, blocks);
            const dropIdx = new Set(targets.map((t) => t.index));
            b.drops.push((body) => {
              const it = itemAt(body, j);
              const kept = (it["content"] as unknown[]).filter((_, i) => !dropIdx.has(i));
              it["content"] = kept.length > 0 ? kept : [{ type: "input_text", text: "(a tool result's images: masked by Mandu)" }];
            });
          }
          push(b, "user", texts, textLinks);
        } else {
          throw new OpenAiWireError(`input[${j}] (user) content is neither text nor parts`);
        }
        lastWasResult = false;
        return;
      }
      throw new OpenAiWireError(`input[${j}] has role "${String(role)}", which Mandu does not read`);
    }
    if (type === "function_call") {
      const id = typeof item["call_id"] === "string" ? (item["call_id"] as string) : "";
      const name = typeof item["name"] === "string" ? (item["name"] as string) : "";
      const parsed = parseArguments(item["arguments"]);
      if (id) b.callIds.add(id);
      push(b, "assistant", [{ type: "tool_use", id, name, input: parsed ?? {} } as ToolUseBlock], [{
        kind: "call", input: parsed ?? {}, writable: parsed !== null,
        write: (body, args) => { itemAt(body, j)["arguments"] = args; },
      }]);
      lastWasResult = false;
      return;
    }
    if (type === "function_call_output") {
      if (!lastWasResult) b.run = [];
      const id = typeof item["call_id"] === "string" ? (item["call_id"] as string) : "";
      const out = item["output"];
      let content: ToolResultBlock["content"];
      let hadNonText = false;
      if (typeof out === "string") content = out;
      else if (Array.isArray(out)) {
        content = out.map((p) => {
          if (isObj(p) && (p["type"] === "input_text" || p["type"] === "text" || p["type"] === "output_text") && typeof p["text"] === "string") {
            return { type: "text", text: p["text"] as string };
          }
          hadNonText = true;
          return nonTextBlock(p);
        });
      } else if (out === undefined || out === null) content = "";
      else throw new OpenAiWireError(`input[${j}] (function_call_output) output is neither text nor parts`);
      if (id && !b.callIds.has(id)) synthesizeCall(b, id, memory);
      const original = flattenToolResultContent(content);
      const m = push(b, "user", [{ type: "tool_result", tool_use_id: id, content } as ToolResultBlock], [{
        kind: "result", original, hadNonText,
        write: (body, text) => { itemAt(body, j)["output"] = text; },
      }]);
      b.run.push({ msg: m, block: 0 });
      lastWasResult = true;
      return;
    }
    if (typeof type === "string" && PASS_ITEMS.has(type)) {
      return;
    }
    throw new OpenAiWireError(`input[${j}] has type "${String(type)}", which Mandu does not read (only function tools are routed)`);
  });

  const tools = (Array.isArray(original["tools"]) ? original["tools"] : []).map((t) => {
    const fn = isObj(t) ? t : {};
    return { name: String(fn["name"] ?? ""), description: fn["description"], input_schema: fn["parameters"] };
  });

  return {
    shadow: finishShadow(b, original["model"], original["stream"], tools),
    apply: (gated) => {
      const body = applyShadow(original, b, gated, {
        count: sysRefs.length,
        originals: sysOrig,
        set: (bd, i, text) => {
          const ref = sysRefs[i]!;
          if (ref === "instructions") bd["instructions"] = text;
          else itemAt(bd, ref)["content"] = text;
        },
        add: (bd, texts) => {
          // Appended to `instructions`: a continuation (`previous_response_id`)
          // does not carry the previous request's instructions, so the
          // prompt must ride every request, and `instructions` is the one
          // place that never becomes history.
          const extra = texts.join("\n\n");
          const cur = bd["instructions"];
          bd["instructions"] = typeof cur === "string" && cur !== "" ? `${cur}\n\n${extra}` : extra;
        },
      });
      // A string `input` was read as one user message; it changes only when
      // the prompt filter rewrote it (its user link wrote it above).
      if (inputIsString && !inputWritten) body["input"] = rawInput;
      return body;
    },
  };
}

/** Build the shadow for either wire. */
export function shadowFor(api: OpenAiApi, body: Json, memory?: CallMemory): Shadow {
  return api === "chat" ? chatShadow(body, memory) : responsesShadow(body, memory);
}

/** A routed provider id: what the launcher writes into the agent's config. */
const PROVIDER_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * MANDU_OPENAI_UPSTREAMS: a JSON object of provider id → base URL (http or
 * https; plain http reaches only a loopback address, enforced per request by
 * the proxy's fetcher). Unset or empty ⇒ {}. Anything malformed THROWS: a
 * proxy started without the routes the launcher asked for would refuse the
 * agent's every turn, and one started with a garbled URL would send them
 * somewhere else.
 */
export function parseOpenAiUpstreamsEnv(raw: string | undefined): Record<string, string> {
  if (raw === undefined || raw.trim() === "") return {};
  let v: unknown;
  try { v = JSON.parse(raw); } catch (e) { throw new Error(`MANDU_OPENAI_UPSTREAMS is not JSON: ${(e as Error).message}`); }
  if (!isObj(v)) throw new Error("MANDU_OPENAI_UPSTREAMS is not a JSON object");
  const out: Record<string, string> = {};
  for (const [id, url] of Object.entries(v)) {
    if (!PROVIDER_ID_RE.test(id)) throw new Error(`MANDU_OPENAI_UPSTREAMS: provider id ${JSON.stringify(id)} is not a plain name`);
    if (typeof url !== "string") throw new Error(`MANDU_OPENAI_UPSTREAMS: the URL for ${id} is not a string`);
    let u: URL;
    try { u = new URL(url); } catch { throw new Error(`MANDU_OPENAI_UPSTREAMS: the URL for ${id} does not parse`); }
    if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error(`MANDU_OPENAI_UPSTREAMS: the URL for ${id} is not http(s)`);
    if (u.search !== "" || u.hash !== "" || u.username !== "" || u.password !== "") {
      throw new Error(`MANDU_OPENAI_UPSTREAMS: the URL for ${id} carries a query, fragment or credentials`);
    }
    out[id] = url;
  }
  return out;
}

/**
 * MANDU_OPENAI_TEXT_CALLS: a JSON array of routed provider ids whose agent
 * runs a tool call the model WRITES in its text (Goose's ollama provider
 * parses `<function=name><parameter=k>v</parameter></function>` out of the
 * assistant text, goose-provider-types formats/ollama.rs). On those routes a
 * response whose text carries that markup is ended (openai-sse.ts
 * TEXT_CALL_MARK). Unset or empty ⇒ []. Malformed THROWS, as above: a proxy
 * started without the check the launcher asked for would let such a call
 * past every gate.
 */
export function parseOpenAiTextCallsEnv(raw: string | undefined): string[] {
  if (raw === undefined || raw.trim() === "") return [];
  let v: unknown;
  try { v = JSON.parse(raw); } catch (e) { throw new Error(`MANDU_OPENAI_TEXT_CALLS is not JSON: ${(e as Error).message}`); }
  if (!Array.isArray(v)) throw new Error("MANDU_OPENAI_TEXT_CALLS is not a JSON array");
  for (const id of v) {
    if (typeof id !== "string" || !PROVIDER_ID_RE.test(id)) throw new Error(`MANDU_OPENAI_TEXT_CALLS: provider id ${JSON.stringify(id)} is not a plain name`);
  }
  return v as string[];
}
