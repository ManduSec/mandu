/**
 * wire-shadow — the shadow builder every non-Messages wire adapter shares
 * (model-wires.md §2): a Messages request the core (rewriteRequest, the view
 * map's reverse pass, the net-gate history) reads, built from another wire's
 * body, with a link per block that writes what the core changed back onto a
 * clone of the agent's own body, by position.
 *
 * Mandu-new (no reference origin). Moved out of openai-wire.ts (2026-10-25)
 * unchanged, so the Chat Completions, Responses and Gemini adapters
 * (openai-wire.ts, gemini-wire.ts) build their shadows with ONE builder and
 * ONE write-back. Pure (no I/O); never mutates its inputs.
 */

import type { ContentBlock, Message, MessagesRequest, SystemBlock, ToolResultBlock, ToolResultContentBlock, ToolUseBlock } from "./messages-types.js";
import { flattenToolResultContent } from "./rewrite-request.js";

type Json = Record<string, unknown>;

const isObj = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

/** Calls the proxy gated on the way out, by call id (openai-wire.ts
 *  CONTINUATIONS). */
export interface CallMemory {
  get(callId: string): { name: string; input: Record<string, unknown> } | undefined;
}

export interface Shadow {
  /** What the gates read. */
  shadow: MessagesRequest;
  /** The original body with the gated shadow's changes written back. */
  apply(gated: MessagesRequest): Record<string, unknown>;
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

export function sameJson(a: unknown, b: unknown): boolean {
  try { return JSON.stringify(a) === JSON.stringify(b); } catch { return false; }
}

/** Where one shadow block came from, and how to write its change back. */
export type Link =
  | { kind: "result"; write: (body: Json, text: string) => void; original: string; hadNonText: boolean }
  | { kind: "call"; write: (body: Json, args: string) => void; input: Json; writable: boolean }
  // A user text (confidentiality-plan-15 §3): the prompt filter may replace a
  // registered value in it with its symbol, and the change must reach the
  // body the provider receives. Before plan 15 user text was pushed with a
  // null link and nothing in it could change.
  | { kind: "user"; write: (body: Json, text: string) => void; original: string };

export interface Builder {
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

export function newBuilder(): Builder {
  return { messages: [], system: [], links: [], run: [], drops: [], callIds: new Set() };
}

export function push(b: Builder, role: "user" | "assistant", blocks: ContentBlock[], links: Array<Link | null>): number {
  b.messages.push({ role, content: blocks });
  b.links.push(links);
  return b.messages.length - 1;
}

/** Attach a carrier's non-text parts to a tool result of the preceding run. */
export function attachToRun(b: Builder, runIdx: number, blocks: ToolResultContentBlock[]): void {
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
export function nonTextBlock(part: unknown): ToolResultContentBlock {
  return { type: "image", source: { type: "openai-part", part } } as ToolResultContentBlock;
}

export function finishShadow(b: Builder, model: unknown, stream: unknown, tools: unknown[]): MessagesRequest {
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
export function applyShadow(
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

/** A remembered call as a shadow tool_use, just before its result (the
 *  call's own turn is not in this request; nothing is written back). */
export function synthesizeCall(b: Builder, callId: string, memory?: CallMemory): void {
  const r = memory?.get(callId);
  if (!r) return;
  b.callIds.add(callId);
  push(b, "assistant", [{ type: "tool_use", id: callId, name: r.name, input: r.input } as ToolUseBlock], [null]);
}
