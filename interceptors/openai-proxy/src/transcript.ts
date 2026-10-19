/**
 * transcript — the readable `▸ role` summaries the `tllm_call` event carries
 * for one Codex exchange: the request's conversation (input DualRepr) and the
 * model's answer (output DualRepr).
 *
 * Mandu-new. Mirrors the Anthropic proxy's `summarizeRequest` /
 * `fitBlocks` (interceptors/anthropic-proxy/src/proxy.ts; the packages ship
 * standalone) over the Responses API. WHY (2026-09-26): this proxy recorded
 * the raw request JSON, capped at 4 KB, as the call's input, and codex ≥ 0.154
 * puts its tool battery FIRST in `input[]`, so the cap kept only tool
 * descriptions; and it never read the response. The dashboard's trace
 * (dashboard.md §4.2f) found no `▸ user` prompt and no reply, so a Codex
 * session showed tool rows only. Both summaries are built from what the
 * proxy already has on the privileged side: the SYMBOLIZED forwarded request
 * and the model's own output, so any `$MDU:*` token stays a token.
 */

import { StringDecoder } from "node:string_decoder";

import {
  flattenOutput,
} from "./rewrite-request.js";
import {
  isCustomToolCallItem,
  isFunctionCallItem,
  isMessageItem,
  isToolOutputItem,
  type ResponsesRequest,
  type ToolOutputItem,
} from "./responses-types.js";

/** Cap on the input summary (same as the Anthropic proxy's). */
export const PROMPT_SUMMARY_CAP = 4096;
/** Per-system-block cap, so the agent's own instructions cannot push the
 *  user's prompt off the end of the summary. */
export const SYSTEM_SUMMARY_CAP = 512;
/** The marker the rewrite prefixes to the injected handling prompt. */
const HANDLING_MARKER = "[mandu:handling-prompt]";
const ROLE_MARK = "▸";
const BLOCK_SEP = "\n\n";

/**
 * Runtime context Codex delivers as USER-role messages ahead of the typed
 * prompt: the workspace's AGENTS.md, the older `<user_instructions>`
 * wrapper, and the `<environment_context>` block (cwd, shell, sandbox). None
 * is what the human typed; they render as collapsed `▸ system` blocks so the
 * dashboard neither cards them as prompts nor labels the session with them.
 */
const CONTEXT_MESSAGE_RE = /^\s*(?:<environment_context>|<user_instructions>|# AGENTS\.md instructions for )/;

function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max)}…[+${s.length - max} chars]`;
}

/** A message item's text: a string, or its text parts joined in order. */
function messageText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((p) => {
      const part = (p ?? {}) as { type?: unknown; text?: unknown };
      if (typeof part.text === "string") return part.text;
      return `[${String(part.type ?? "part")}]`;
    })
    .join("\n");
}

/** A tool call as ONE line, `→ name(args)`: the dashboard drops these lines
 *  from the reply prose, so a multi-line argument must not leak past them. */
function callLine(name: string, args: string): string {
  let oneLine: string;
  try {
    oneLine = JSON.stringify(JSON.parse(args));
  } catch {
    oneLine = JSON.stringify(args);
  }
  return `→ ${name}(${oneLine})`;
}

/**
 * The `▸ role` transcript of a forwarded Responses request. `agentInstructions`
 * is the agent's OWN instructions (before the handling prompt was prefixed);
 * the handling prompt itself collapses to a placeholder.
 */
export function summarizeResponsesRequest(req: ResponsesRequest, agentInstructions?: string): string {
  const blocks: string[] = [];
  const sys: string[] = [];
  if (typeof req.instructions === "string" && req.instructions.includes(HANDLING_MARKER)) {
    sys.push("[Mandu IPI handling prompt]");
  }
  if (agentInstructions?.trim()) sys.push(agentInstructions.trim());
  if (sys.length) blocks.push(`${ROLE_MARK} system\n${truncate(sys.join("\n"), SYSTEM_SUMMARY_CAP)}`);

  if (typeof req.input === "string") blocks.push(`${ROLE_MARK} user\n${req.input}`);
  for (const item of Array.isArray(req.input) ? req.input : []) {
    if (isMessageItem(item)) {
      const text = messageText(item.content);
      const context = (item.role !== "user" && item.role !== "assistant") || (item.role === "user" && CONTEXT_MESSAGE_RE.test(text));
      blocks.push(context
        ? `${ROLE_MARK} system\n${truncate(text.trim(), SYSTEM_SUMMARY_CAP)}`
        : `${ROLE_MARK} ${item.role}\n${text}`);
    } else if (isFunctionCallItem(item)) {
      blocks.push(`${ROLE_MARK} assistant\n${callLine(item.name, item.arguments ?? "")}`);
    } else if (isCustomToolCallItem(item)) {
      blocks.push(`${ROLE_MARK} assistant\n${callLine(item.name, JSON.stringify(item.input ?? ""))}`);
    } else if (isToolOutputItem(item)) {
      const out = item as ToolOutputItem;
      blocks.push(`${ROLE_MARK} user\n[tool_result ${out.call_id}]\n${flattenOutput(out.output)}`);
    }
    // reasoning (encrypted), additional_tools (the battery) and other items
    // carry nothing a reader of the conversation needs.
  }
  return fitBlocks(blocks, PROMPT_SUMMARY_CAP).join(BLOCK_SEP);
}

/**
 * Fit the transcript's blocks into `cap` chars so that EVERY block survives:
 * the longest blocks are cut first (water-filling). The dashboard keys on
 * each block's head (prompt cards, side-call shapes), so heads survive.
 * Copied from the Anthropic proxy's `fitBlocks`.
 */
export function fitBlocks(blocks: string[], cap: number): string[] {
  const sep = BLOCK_SEP.length * Math.max(0, blocks.length - 1);
  const total = blocks.reduce((n, b) => n + b.length, 0) + sep;
  if (total <= cap) return blocks;
  const MARK = 24;
  const fits = (L: number): boolean =>
    blocks.reduce((n, b) => n + (b.length > L ? L + MARK : b.length), 0) + sep <= cap;
  let lo = 0;
  let hi = Math.max(...blocks.map((b) => b.length));
  if (!fits(lo)) return [truncate(blocks.join(BLOCK_SEP), cap)];
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (fits(mid)) lo = mid;
    else hi = mid - 1;
  }
  return blocks.map((b) => (b.length > lo ? truncate(b, lo) : b));
}

/**
 * The model's answer as the `tllm_call` output: the assistant text, then one
 * `→ name(args)` line per tool call (the Anthropic proxy's shape).
 */
export function summarizeOutputItems(items: readonly unknown[]): string {
  const text: string[] = [];
  const calls: string[] = [];
  for (const item of items) {
    if (isMessageItem(item) && item.role === "assistant") {
      const t = messageText(item.content).trim();
      if (t) text.push(t);
    } else if (isFunctionCallItem(item)) {
      calls.push(callLine(item.name, item.arguments ?? ""));
    } else if (isCustomToolCallItem(item)) {
      calls.push(callLine(item.name, JSON.stringify(item.input ?? "")));
    }
  }
  return [...text, ...calls].join("\n");
}

/** Past this much buffered body the reader stops (the reply summary is an
 *  observability nicety; the relay itself is untouched). */
const MAX_SNIFF_BYTES = 16 * 1024 * 1024;

/**
 * A passive reader of the response body as it is relayed: never changes a
 * byte, only remembers the finished output items. SSE: every
 * `response.output_item.done` item, with `response.completed`'s `output` as
 * the fallback (Codex backends may send it empty); a `response.failed` or
 * `error` event's message. JSON (stream:false): the body's `output` / `error`.
 */
export class ResponseSniffer {
  private readonly decoder = new StringDecoder("utf8");
  private buf = "";
  private size = 0;
  private readonly items: unknown[] = [];
  private completed: unknown[] | null = null;
  private error: string | null = null;

  constructor(private readonly kind: "sse" | "json") {}

  feed(chunk: Buffer | string): void {
    if (this.size > MAX_SNIFF_BYTES) return;
    const text = typeof chunk === "string" ? chunk : this.decoder.write(chunk);
    this.size += text.length;
    this.buf += text;
    if (this.kind === "sse") this.drainEvents(false);
  }

  private drainEvents(final: boolean): void {
    const blocks = this.buf.split(/\r?\n\r?\n/);
    this.buf = final ? "" : blocks.pop() ?? "";
    for (const block of blocks) {
      const data = block.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");
      if (!data || data === "[DONE]") continue;
      let ev: Record<string, unknown>;
      try { ev = JSON.parse(data) as Record<string, unknown>; } catch { continue; }
      if (ev["type"] === "response.output_item.done" && ev["item"]) this.items.push(ev["item"]);
      else if (ev["type"] === "response.completed") {
        const out = (ev["response"] as { output?: unknown } | undefined)?.output;
        if (Array.isArray(out)) this.completed = out;
      } else if (ev["type"] === "response.failed" || ev["type"] === "error") {
        this.error = errorMessage(ev["response"] ?? ev) ?? this.error;
      }
    }
  }

  /** The summary once the body ended. */
  finish(): { text: string; error: string | null } {
    if (this.kind === "sse") {
      this.buf += this.decoder.end();
      this.drainEvents(true);
      return { text: summarizeOutputItems(this.items.length ? this.items : this.completed ?? []), error: this.error };
    }
    this.buf += this.decoder.end();
    try {
      const obj = JSON.parse(this.buf) as Record<string, unknown>;
      return { text: Array.isArray(obj["output"]) ? summarizeOutputItems(obj["output"]) : "", error: errorMessage(obj) };
    } catch {
      return { text: "", error: null };
    }
  }
}

function errorMessage(v: unknown): string | null {
  const err = (v as { error?: unknown } | null)?.error ?? v;
  const e = err as { message?: unknown; code?: unknown; type?: unknown } | null;
  if (!e || typeof e !== "object") return null;
  if (typeof e.message === "string" && e.message) return e.message;
  if (typeof e.code === "string") return e.code;
  return null;
}
