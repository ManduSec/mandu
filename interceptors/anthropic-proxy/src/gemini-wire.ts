/**
 * gemini-wire — read a Google Gemini `generateContent` request as the
 * Messages request the rest of this proxy gates, and write the gated result
 * back onto the ORIGINAL body (model-wires.md §4.2). The request half of the
 * Gemini adapter; the answer half is gemini-sse.ts.
 *
 * Mandu-new (no reference origin). The wire facts were read from the
 * published clients: `@openclaw/ai` 2026.10.7 (`projectGoogleMessages`,
 * over `@google/genai`), `@ai-sdk/google` 2.0.106
 * (`convertToGoogleGenerativeAIMessages`, OpenCode's provider) and Goose's
 * `formats/google.rs`. Same pattern as openai-wire.ts, with the same builder
 * (wire-shadow.ts), so every gate the Messages wire runs runs here unchanged.
 *
 * THE SHADOW. Every `functionResponse` part becomes a `tool_result` block,
 * every `functionCall` part a `tool_use` block (its `args` object), the
 * `systemInstruction` text parts `system` blocks, a `user` content's text
 * parts user text (the prompt filter may rewrite a registered value into its
 * symbol), a `model` content's text parts assistant text. Thought parts
 * (`thought: true`) and every `thoughtSignature` are never read nor written,
 * so they round-trip byte-identical. `apply` writes back, by position, a
 * result's masked text, a call's changed args, a user text the prompt filter
 * rewrote, and the handling prompt (one more `systemInstruction` part).
 *
 * A FUNCTION RESPONSE'S TEXT. The clients wrap the tool's text: OpenClaw
 * `{output: t}` / `{error: t}`, the AI SDK `{name, content: t}`, Goose
 * `{content: {text: t}}`. When the response's only scalar leaf is one string
 * (a top-level `name` equal to the call's name not counted) that string is
 * the result, and the masked text goes back into the same leaf. Any other
 * response is read as its JSON text (as the Chat wire reads a JSON tool
 * result) and written back as the masked JSON when it still parses to an
 * object, else as `{output: masked}`.
 *
 * A TOOL'S MEDIA joins its result, which the rewrite then masks whole, and
 * is dropped from the body: a function response's own `parts` (Gemini 3), an
 * `inlineData` part in a content that carries function responses (the AI
 * SDK's legacy form), and the `inlineData` parts of a `user` content right
 * after a run of function responses (OpenClaw's "Tool result image:" turn).
 * A text part in a content that carries function responses is the tools'
 * too (the AI SDK's legacy form writes a tool part it cannot map as text
 * there): it joins the result before it and moves into that response.
 * A user's own media anywhere else goes upstream as sent, as on the OpenAI
 * wires.
 *
 * CORRELATION. A call without an `id` gets a positional one in the shadow; a
 * response without one is matched to the first unanswered call of the same
 * name in the model turn before it; a response that matches nothing is an
 * unknown tool's (UNTRUSTED). The answer side gives every call an id
 * (gemini-sse.ts), so the agents echo it back.
 *
 * SPELLINGS. The API reads protobuf JSON, which accepts a field's camelCase
 * and snake_case names alike (Goose sends `inline_data` / `mime_type`), so
 * both are read; a part or a request that spells one field both ways is
 * refused (which one the API reads is not ours to guess). It also takes a
 * single value for a repeated field as a list of one: Goose 1.53.0 sends
 * `tools` as one Tool object (captured from the binary,
 * test/fixtures/goose-1.53.0-gemini-request.json), so the read-only fields
 * `tools` and `functionDeclarations` are read either way (repeatedField).
 *
 * FAIL-CLOSED: a shape this module does not read is a `GeminiWireError` (the
 * proxy answers 400 and sends nothing): a content role other than `user`,
 * `model` and the old `function`; a part key it does not know; `fileData`
 * (the provider fetches the file into the context); `executableCode` /
 * `codeExecutionResult`; a non-text system part. `geminiRequestRefusal`
 * refuses a request whose tools run at the provider, cached content, and
 * streamed function-call arguments.
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
export class GeminiWireError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GeminiWireError";
  }
}

// ── spellings ──────────────────────────────────────────────────────────────

/** A part's keys, by their canonical (camelCase) name. */
const PART_KEYS: Readonly<Record<string, string>> = {
  text: "text",
  thought: "thought",
  thoughtSignature: "thoughtSignature", thought_signature: "thoughtSignature",
  inlineData: "inlineData", inline_data: "inlineData",
  fileData: "fileData", file_data: "fileData",
  functionCall: "functionCall", function_call: "functionCall",
  functionResponse: "functionResponse", function_response: "functionResponse",
  executableCode: "executableCode", executable_code: "executableCode",
  codeExecutionResult: "codeExecutionResult", code_execution_result: "codeExecutionResult",
  videoMetadata: "videoMetadata", video_metadata: "videoMetadata",
  mediaResolution: "mediaResolution", media_resolution: "mediaResolution",
  partMetadata: "partMetadata", part_metadata: "partMetadata",
};

/** One part, its keys canonical: the value and the key the body spells it with. */
export type CanonPart = Map<string, { key: string; value: unknown }>;

/**
 * A part's keys read canonically. Throws on a key this module does not know
 * or a field spelled both ways. Exported for gemini-sse.ts, which reads the
 * answer's parts with the same table.
 */
export function canonPart(part: unknown, where: string, Err: new (m: string) => Error = GeminiWireError): CanonPart {
  if (!isObj(part)) throw new Err(`${where} is not an object`);
  const out: CanonPart = new Map();
  for (const [key, value] of Object.entries(part)) {
    const canon = PART_KEYS[key];
    if (canon === undefined) throw new Err(`${where} has the field "${key}", which Mandu does not read`);
    if (out.has(canon)) throw new Err(`${where} spells "${canon}" twice (${out.get(canon)!.key} and ${key})`);
    out.set(canon, { key, value });
  }
  return out;
}

/** A field of an object read under either spelling; throws when both are present. */
function field(obj: Json, camel: string, snake: string, where: string): { key: string; value: unknown } | undefined {
  const a = Object.prototype.hasOwnProperty.call(obj, camel);
  const b = snake !== camel && Object.prototype.hasOwnProperty.call(obj, snake);
  if (a && b) throw new GeminiWireError(`${where} spells "${camel}" twice (${camel} and ${snake})`);
  if (a) return { key: camel, value: obj[camel] };
  if (b) return { key: snake, value: obj[snake] };
  return undefined;
}

// ── request-level refusals ─────────────────────────────────────────────────

/** `tools[]` keys whose tool runs at the provider (named in the refusal). */
const TOOL_FUNCTIONS = new Set(["functionDeclarations", "function_declarations"]);

/**
 * A repeated field as the API reads it: Google's JSON reader takes a single
 * value for a repeated field as a list of one. Goose 1.53.0 sends `tools` so,
 * one Tool object (`{"functionDeclarations": [...]}`, captured from the real
 * binary 2026-10-25), and Gemini answers it. Used for the fields this module
 * only READS (`tools`, `functionDeclarations`); a field it writes back by
 * position (`contents`, `parts`) must be a list, else the request is refused.
 * Null for a value that is neither (refused by the caller).
 */
export function repeatedField(v: unknown): unknown[] | null {
  if (v === undefined || v === null) return [];
  if (Array.isArray(v)) return v;
  if (isObj(v)) return [v];
  return null;
}

/**
 * Why the request as a whole cannot go, or null. Checked before any shadow is
 * built: a tool the provider runs (its results enter the model's context
 * where no gate sees them), cached content (context Mandu never saw), and
 * streamed function-call arguments (a call the agent would assemble from
 * pieces this proxy cannot hold).
 */
export function geminiRequestRefusal(body: Json): string | null {
  for (const k of ["cachedContent", "cached_content"]) {
    if (body[k] !== undefined && body[k] !== null) {
      return `the request names cached content (\`${k}\`), which reaches the model at the provider where Mandu never saw it`;
    }
  }
  for (const k of ["tools"]) {
    const tools = repeatedField(body[k]);
    if (tools === null) return "`tools` is neither a list nor a tool";
    for (const t of tools) {
      if (!isObj(t)) return "a `tools` entry is not an object";
      for (const key of Object.keys(t)) {
        if (!TOOL_FUNCTIONS.has(key)) {
          return `the tool "${key}" runs at the model provider, where Mandu cannot mask its results; only function declarations are routed`;
        }
      }
    }
  }
  for (const k of ["toolConfig", "tool_config"]) {
    const tc = body[k];
    if (!isObj(tc)) continue;
    for (const fk of ["functionCallingConfig", "function_calling_config"]) {
      const fc = tc[fk];
      if (isObj(fc) && (fc["streamFunctionCallArguments"] === true || fc["stream_function_call_arguments"] === true)) {
        return "the request asks for streamed function-call arguments, which Mandu cannot gate before the agent assembles them";
      }
    }
  }
  return null;
}

// ── a function response's text ─────────────────────────────────────────────

type Path = Array<string | number>;

/** Every scalar leaf of `v` (strings, numbers, booleans, null), with its path. */
function leaves(v: unknown, path: Path, out: Array<{ path: Path; value: unknown }>): void {
  if (Array.isArray(v)) { v.forEach((x, i) => leaves(x, [...path, i], out)); return; }
  if (isObj(v)) { for (const [k, x] of Object.entries(v)) leaves(x, [...path, k], out); return; }
  out.push({ path, value: v });
}

/**
 * The path of a response's one text leaf, or null when the response is not
 * that shape: its only scalar leaf (a top-level `name` equal to the call's
 * name not counted) is a string. Exported for the unit tests.
 */
export function responseTextPath(response: unknown, callName: string): Path | null {
  if (!isObj(response)) return null;
  const all: Array<{ path: Path; value: unknown }> = [];
  leaves(response, [], all);
  const counted = all.filter((l) => !(l.path.length === 1 && l.path[0] === "name" && l.value === callName));
  if (counted.length !== 1 || typeof counted[0]!.value !== "string") return null;
  return counted[0]!.path;
}

function getAt(v: unknown, path: Path): unknown {
  let cur = v;
  for (const p of path) cur = (cur as Record<string | number, unknown>)[p];
  return cur;
}

function setAt(v: unknown, path: Path, value: unknown): void {
  let cur = v as Record<string | number, unknown>;
  for (const p of path.slice(0, -1)) cur = cur[p] as Record<string | number, unknown>;
  cur[path[path.length - 1]!] = value;
}

/** The response written back from the masked text (see the module header). */
export function responseFromText(text: string): Json {
  try {
    const v: unknown = JSON.parse(text);
    if (isObj(v)) return v;
  } catch {
    // not JSON: the masked text (a symbol) as the output
  }
  return { output: text };
}

// ── the shadow ─────────────────────────────────────────────────────────────

export interface GeminiShadowOptions {
  /** The model named in the request path (`models/{model}:…`): the body has none. */
  model: string;
  /** `:streamGenerateContent` */
  stream: boolean;
  memory?: CallMemory;
}

/** A Gemma model takes no system instruction on the Gemini API: the
 *  handling prompt goes into the first user turn instead (as the AI SDK puts
 *  the system text there for Gemma). */
const GEMMA_RE = /(^|\/)gemma/i;

export function geminiShadow(original: Json, opts: GeminiShadowOptions): Shadow {
  const b: Builder = newBuilder();
  const contentsField = field(original, "contents", "contents", "the request");
  const contents = contentsField?.value;
  if (contents !== undefined && !Array.isArray(contents)) throw new GeminiWireError("`contents` is not an array");
  const items = (contents ?? []) as unknown[];

  // ── systemInstruction ──
  const sysField = field(original, "systemInstruction", "system_instruction", "the request");
  const sysParts: number[] = [];
  const sysOrig: string[] = [];
  if (sysField !== undefined && sysField.value !== null) {
    const si = sysField.value;
    if (!isObj(si)) throw new GeminiWireError("`systemInstruction` is not a content object");
    const parts = si["parts"];
    if (parts !== undefined && !Array.isArray(parts)) throw new GeminiWireError("`systemInstruction.parts` is not an array");
    ((parts ?? []) as unknown[]).forEach((p, i) => {
      const c = canonPart(p, `systemInstruction.parts[${i}]`);
      for (const k of c.keys()) {
        if (k !== "text" && k !== "thoughtSignature" && k !== "partMetadata") {
          throw new GeminiWireError(`systemInstruction.parts[${i}] carries a non-text part (${c.get(k)!.key})`);
        }
      }
      const t = c.get("text")?.value;
      if (t === undefined) return;
      if (typeof t !== "string") throw new GeminiWireError(`systemInstruction.parts[${i}].text is not a string`);
      sysParts.push(i);
      sysOrig.push(t);
      b.system.push({ type: "text", text: t });
    });
  }

  const partsAt = (body: Json, j: number): Json[] => ((body[contentsField!.key] as Json[])[j]!)["parts"] as Json[];

  /** The previous model turn's calls, for responses that carry no id. */
  let turnCalls: Array<{ id: string; name: string; answered: boolean }> = [];
  let lastWasResult = false;

  items.forEach((content: unknown, j: number) => {
    if (!isObj(content)) throw new GeminiWireError(`contents[${j}] is not an object`);
    const role = content["role"] === undefined || content["role"] === null || content["role"] === "" ? "user" : content["role"];
    const rawParts = content["parts"];
    if (rawParts !== undefined && rawParts !== null && !Array.isArray(rawParts)) throw new GeminiWireError(`contents[${j}].parts is not an array`);
    const parts = ((rawParts ?? []) as unknown[]).map((p, k) => canonPart(p, `contents[${j}].parts[${k}]`));
    for (const [k, c] of parts.entries()) {
      for (const bad of ["fileData", "executableCode", "codeExecutionResult"]) {
        if (c.has(bad)) {
          throw new GeminiWireError(bad === "fileData"
            ? `contents[${j}].parts[${k}] names a file by URI (${c.get(bad)!.key}), which the provider fetches into the model's context where Mandu cannot mask it`
            : `contents[${j}].parts[${k}] carries ${c.get(bad)!.key}, the provider's own code execution, which Mandu does not route`);
        }
      }
    }

    // A function response belongs to a user turn (the shadow masks it there)
    // and a function call to a model turn: anywhere else a response would
    // pass unread, so either is refused.
    for (const [k, c] of parts.entries()) {
      const misplaced = role === "model" ? c.get("functionResponse") : c.get("functionCall");
      if (misplaced !== undefined) {
        throw new GeminiWireError(`contents[${j}].parts[${k}] carries ${misplaced.key} in a "${String(role)}" turn, which Mandu does not read`);
      }
    }

    if (role === "model") {
      const blocks: ContentBlock[] = [];
      const links: Array<Link | null> = [];
      const calls: typeof turnCalls = [];
      parts.forEach((c, k) => {
        const fc = c.get("functionCall");
        if (fc !== undefined) {
          if (!isObj(fc.value)) throw new GeminiWireError(`contents[${j}].parts[${k}].${fc.key} is not an object`);
          const v = fc.value;
          const name = typeof v["name"] === "string" ? v["name"] : "";
          const id = typeof v["id"] === "string" && v["id"] !== "" ? v["id"] : `gemini-call:${j}:${k}`;
          const args = v["args"];
          const input = isObj(args) ? args : {};
          blocks.push({ type: "tool_use", id, name, input } as ToolUseBlock);
          b.callIds.add(id);
          calls.push({ id, name, answered: false });
          links.push({
            kind: "call", input, writable: args === undefined || isObj(args),
            write: (body, a) => { (partsAt(body, j)[k]![fc.key] as Json)["args"] = JSON.parse(a) as unknown; },
          });
          return;
        }
        const t = c.get("text")?.value;
        if (typeof t === "string" && c.get("thought")?.value !== true && t !== "") {
          blocks.push({ type: "text", text: t });
          links.push(null);
        }
        // thought parts, signature-only parts and the model's own media: not read
      });
      push(b, "assistant", blocks, links);
      turnCalls = calls;
      lastWasResult = false;
      return;
    }

    if (role !== "user" && role !== "function") {
      throw new GeminiWireError(`contents[${j}] has role "${String(role)}", which Mandu does not read`);
    }

    const hasResults = parts.some((c) => c.has("functionResponse"));
    if (role === "function" && parts.some((c) => !c.has("functionResponse"))) {
      throw new GeminiWireError(`contents[${j}] (function) carries a part that is not a function response`);
    }
    const userText = (k: number, key: string, original: string): Link => ({
      kind: "user", original,
      write: (body, text) => { partsAt(body, j)[k]![key] = text; },
    });
    const dropIdx = new Set<number>();
    if (hasResults && !lastWasResult) b.run = [];
    // A tool's media sitting beside its function response in one content
    // attaches to the response before it (the AI SDK's legacy form), or to
    // this content's first one when it comes first.
    const mediaFor = new Map<number, ToolResultContentBlock[]>();
    const runStart = b.run.length;
    let runIdxOfLast = -1;
    const carrier = !hasResults && lastWasResult && b.run.length > 0 && parts.some((c) => c.has("inlineData"));

    parts.forEach((c, k) => {
      const fr = c.get("functionResponse");
      if (fr !== undefined) {
        b.run.push(resultInto(b, fr, j, k, partsAt, turnCalls, opts.memory));
        runIdxOfLast = b.run.length - 1;
        return;
      }
      const media = c.get("inlineData");
      if (media !== undefined && (hasResults || carrier)) {
        const at = hasResults ? (runIdxOfLast >= 0 ? runIdxOfLast : runStart) : b.run.length - 1;
        mediaFor.set(at, [...(mediaFor.get(at) ?? []), nonTextBlock({ [media.key]: media.value })]);
        dropIdx.add(k);
        return;
      }
      const t = c.get("text");
      if (t !== undefined && typeof t.value === "string" && hasResults) {
        // Text beside function responses is the tools' (the AI SDK's legacy
        // form writes a tool part it cannot map as a text part there): it
        // joins the result before it, judged and masked with it, and moves
        // into that response.
        const at = runIdxOfLast >= 0 ? runIdxOfLast : runStart;
        mediaFor.set(at, [...(mediaFor.get(at) ?? []), { type: "text", text: `\n${t.value}` }]);
        dropIdx.add(k);
        return;
      }
      if (t !== undefined && typeof t.value === "string" && c.get("thought")?.value !== true) {
        push(b, "user", [{ type: "text", text: t.value }], [userText(k, t.key, t.value)]);
      }
      // a user's own media, and signature-only parts: sent as is
    });
    for (const [runIdx, blocks] of mediaFor) attachToRun(b, runIdx, blocks);
    if (dropIdx.size > 0) {
      b.drops.push((body) => {
        const arr = partsAt(body, j);
        const kept = arr.filter((_, i) => !dropIdx.has(i));
        const cont = (body[contentsField!.key] as Json[])[j]!;
        cont["parts"] = kept.length > 0 ? kept : [{ text: "(a tool result's images: masked by Mandu)" }];
      });
    }
    if (role === "user" && !hasResults && parts.length === 0) push(b, "user", [], []);
    lastWasResult = hasResults || (carrier && lastWasResult);
  });

  const tools: unknown[] = [];
  // `tools` may be one Tool object (Goose), read as a list of one.
  for (const t of repeatedField(original["tools"]) ?? []) {
    if (!isObj(t)) continue;
    const decls = repeatedField(t["functionDeclarations"] ?? t["function_declarations"]) ?? [];
    for (const d of decls) {
      if (!isObj(d)) continue;
      tools.push({
        name: String(d["name"] ?? ""),
        description: d["description"],
        input_schema: d["parametersJsonSchema"] ?? d["parameters_json_schema"] ?? d["parameters"],
      });
    }
  }

  const gemma = GEMMA_RE.test(opts.model);
  const shadow: MessagesRequest = finishShadow(b, opts.model, opts.stream, tools);
  return {
    shadow,
    apply: (gated) => applyShadow(original, b, gated, {
      count: sysParts.length,
      originals: sysOrig,
      set: (body, i, text) => {
        const si = body[sysField!.key] as Json;
        ((si["parts"] as Json[])[sysParts[i]!]!)["text"] = text;
      },
      add: (body, texts) => {
        const extra = texts.join("\n\n");
        if (gemma && sysField === undefined) {
          // No system instruction on a Gemma model: the first user turn.
          const list = (contentsField ? body[contentsField.key] : (body["contents"] = [])) as Json[];
          const first = list.find((c) => isObj(c) && (c["role"] === undefined || c["role"] === "user"));
          if (first) first["parts"] = [{ text: extra }, ...(Array.isArray(first["parts"]) ? (first["parts"] as Json[]) : [])];
          else list.unshift({ role: "user", parts: [{ text: extra }] });
          return;
        }
        if (sysField !== undefined && isObj(body[sysField.key])) {
          const si = body[sysField.key] as Json;
          si["parts"] = [...(Array.isArray(si["parts"]) ? (si["parts"] as Json[]) : []), { text: extra }];
        } else {
          body["systemInstruction"] = { parts: [{ text: extra }] };
        }
      },
    }),
  };
}

/** Keys a function response may carry. */
const RESPONSE_KEYS = new Set(["id", "name", "response", "parts", "willContinue", "will_continue", "scheduling"]);

/** One function response as a shadow tool_result; returns its run entry. */
function resultInto(
  b: Builder,
  fr: { key: string; value: unknown },
  j: number,
  k: number,
  partsAt: (body: Json, j: number) => Json[],
  turnCalls: Array<{ id: string; name: string; answered: boolean }>,
  memory?: CallMemory,
): { msg: number; block: number } {
  const where = `contents[${j}].parts[${k}].${fr.key}`;
  if (!isObj(fr.value)) throw new GeminiWireError(`${where} is not an object`);
  const v = fr.value;
  for (const key of Object.keys(v)) {
    if (!RESPONSE_KEYS.has(key)) throw new GeminiWireError(`${where} has the field "${key}", which Mandu does not read`);
  }
  const name = typeof v["name"] === "string" ? v["name"] : "";
  let id = typeof v["id"] === "string" && v["id"] !== "" ? v["id"] : "";
  if (id === "") {
    const call = turnCalls.find((c) => !c.answered && c.name === name);
    id = call ? call.id : `gemini-result:${j}:${k}`;
  }
  const answered = turnCalls.find((c) => c.id === id && !c.answered);
  if (answered) answered.answered = true;
  if (!b.callIds.has(id)) synthesizeCall(b, id, memory);

  const response = v["response"];
  const textPath = responseTextPath(response, name);
  const original = textPath !== null ? (getAt(response, textPath) as string) : response === undefined ? "" : JSON.stringify(response);
  // A function response's own media (Gemini 3's multimodal responses).
  const media: ToolResultContentBlock[] = [];
  const partsKey = v["parts"] !== undefined ? "parts" : null;
  if (partsKey !== null) {
    if (!Array.isArray(v["parts"])) throw new GeminiWireError(`${where}.parts is not an array`);
    (v["parts"] as unknown[]).forEach((p, i) => {
      const c = canonPart(p, `${where}.parts[${i}]`);
      if (c.has("fileData")) throw new GeminiWireError(`${where}.parts[${i}] names a file by URI, which the provider fetches into the model's context where Mandu cannot mask it`);
      media.push(nonTextBlock(p));
    });
  }
  const content: ToolResultBlock["content"] = media.length > 0 ? [{ type: "text", text: original }, ...media] : original;
  const hadNonText = media.length > 0;
  const m = push(b, "user", [{ type: "tool_result", tool_use_id: id, content } as ToolResultBlock], [{
    kind: "result", original, hadNonText,
    write: (body, text) => {
      const target = partsAt(body, j)[k]![fr.key] as Json;
      if (textPath !== null && isObj(target["response"])) setAt(target["response"], textPath, text);
      else target["response"] = responseFromText(text);
      if (partsKey !== null) delete target[partsKey];
    },
  }]);
  return { msg: m, block: 0 };
}

// ── MANDU_GOOGLE_UPSTREAMS ─────────────────────────────────────────────────

/** A routed provider id: what the launcher writes into the agent's config. */
const PROVIDER_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * MANDU_GOOGLE_UPSTREAMS: a JSON object of provider id → base URL, the Gemini
 * providers routed under /_mandu/google/<id> (model-wires.md §5). Unset or
 * empty ⇒ {}. Anything malformed THROWS, as MANDU_OPENAI_UPSTREAMS does: a
 * proxy started without the routes the launcher asked for would refuse every
 * turn, one started with a garbled URL would send them somewhere else.
 */
export function parseGoogleUpstreamsEnv(raw: string | undefined): Record<string, string> {
  if (raw === undefined || raw.trim() === "") return {};
  let v: unknown;
  try { v = JSON.parse(raw); } catch (e) { throw new Error(`MANDU_GOOGLE_UPSTREAMS is not JSON: ${(e as Error).message}`); }
  if (!isObj(v)) throw new Error("MANDU_GOOGLE_UPSTREAMS is not a JSON object");
  const out: Record<string, string> = {};
  for (const [id, url] of Object.entries(v)) {
    if (!PROVIDER_ID_RE.test(id)) throw new Error(`MANDU_GOOGLE_UPSTREAMS: provider id ${JSON.stringify(id)} is not a plain name`);
    if (typeof url !== "string") throw new Error(`MANDU_GOOGLE_UPSTREAMS: the URL for ${id} is not a string`);
    let u: URL;
    try { u = new URL(url); } catch { throw new Error(`MANDU_GOOGLE_UPSTREAMS: the URL for ${id} does not parse`); }
    if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error(`MANDU_GOOGLE_UPSTREAMS: the URL for ${id} is not http(s)`);
    if (u.search !== "" || u.hash !== "" || u.username !== "" || u.password !== "") {
      throw new Error(`MANDU_GOOGLE_UPSTREAMS: the URL for ${id} carries a query, fragment or credentials`);
    }
    out[id] = url;
  }
  return out;
}

/**
 * MANDU_VERTEX_UPSTREAMS: the session's one Vertex AI provider, served at the
 * proxy's root (route.ts classifyVertexRoute; model-wires.md §4.1): a JSON
 * object of at most one entry, provider id → its own address (an http(s)
 * URL, of which only the origin is kept: OpenClaw's Vertex transport drops
 * the path) or null for Google's own Vertex host per location. Unset or
 * empty ⇒ null. Anything malformed THROWS, as MANDU_GOOGLE_UPSTREAMS does.
 */
export function parseVertexUpstreamsEnv(raw: string | undefined): { provider: string; upstream: string | null } | null {
  if (raw === undefined || raw.trim() === "") return null;
  let v: unknown;
  try { v = JSON.parse(raw); } catch (e) { throw new Error(`MANDU_VERTEX_UPSTREAMS is not JSON: ${(e as Error).message}`); }
  if (!isObj(v)) throw new Error("MANDU_VERTEX_UPSTREAMS is not a JSON object");
  const entries = Object.entries(v);
  if (entries.length === 0) return null;
  if (entries.length > 1) throw new Error("MANDU_VERTEX_UPSTREAMS names more than one provider: Vertex AI requests carry no provider id, so a session routes one");
  const [id, url] = entries[0]!;
  if (!PROVIDER_ID_RE.test(id)) throw new Error(`MANDU_VERTEX_UPSTREAMS: provider id ${JSON.stringify(id)} is not a plain name`);
  if (url === null) return { provider: id, upstream: null };
  if (typeof url !== "string") throw new Error(`MANDU_VERTEX_UPSTREAMS: the URL for ${id} is not a string or null`);
  let u: URL;
  try { u = new URL(url); } catch { throw new Error(`MANDU_VERTEX_UPSTREAMS: the URL for ${id} does not parse`); }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error(`MANDU_VERTEX_UPSTREAMS: the URL for ${id} is not http(s)`);
  if (u.search !== "" || u.hash !== "" || u.username !== "" || u.password !== "") {
    throw new Error(`MANDU_VERTEX_UPSTREAMS: the URL for ${id} carries a query, fragment or credentials`);
  }
  return { provider: id, upstream: u.origin };
}
