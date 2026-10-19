/**
 * reserve-request — the request-side half of reply row reservation on the
 * Responses wire (Codex): collapse every reserve block in the assistant's
 * own text back to its token, then strip every leftover fragment from every
 * text the model will read.
 *
 * Mandu Track A (interceptors/openai-proxy). Design:
 * docs/design/ui/reply-row-reservation.md §3.4, §5.2, §11.7. PROVENANCE: NEW
 * Mandu code (2026-09-30), the Responses twin of
 * interceptors/anthropic-proxy/src/reserve-request.ts; the grammar is
 * src/reserve-block.ts (a verbatim copy of the Claude proxy's).
 *
 * WHY: the proxy expands a multi-line token into N rows on its way to Codex
 * (src/sse-reserve-expand.ts). Codex re-sends its history on every request
 * (with or without `previous_response_id`), so the block comes back. The
 * model must get its own token back byte for byte (the prompt cache keys on
 * the assistant prefix it produced), and must never read N, the line count
 * of a secret. So, over `input[]`:
 *   1. collapse, in the assistant's own text only: a `message` item with
 *      role `assistant` (string content, or its text parts), and any
 *      message's `output_text` part: a well-formed block becomes its token
 *      again;
 *   2. strip, over every text the model reads: `instructions`, every other
 *      message's string content and text parts (`input_text`, `text`), and
 *      every tool output (`function_call_output`, `custom_tool_call_output`,
 *      any `*_output` item: its string `output`, or the text parts of an
 *      array `output`).
 * Never touched: `reasoning` items (their `encrypted_content` and summary
 * must survive as the model produced them), `function_call` arguments and
 * `custom_tool_call` input (model-authored arguments), images, files, and
 * every item type not listed above. The strip matches only the literal
 * marker grammar, so a text without markers is untouched byte for byte.
 *
 * ORDER: this runs on the parsed body BEFORE rewriteRequest, so the
 * symbolization, the handling prompt (prepended to the stripped
 * `instructions`) and the §9 oracle read the bytes actually forwarded.
 *
 * FAIL-SAFE: pure, never throws on a malformed shape (what it cannot read it
 * leaves alone); a malformed block falls through to the strip. Mutates the
 * request in place.
 */

import type { ResponsesRequest } from "./responses-types.js";
import { collapseTextCounted, stripResiduals } from "./reserve-block.js";

/** What one pass did. */
export interface ReserveRequestPass {
  /** Well-formed blocks collapsed back to their token. */
  collapsed: number;
  /** Residual fragments stripped. */
  removed: number;
  /** Where fragments were stripped (`instructions`,
   *  `input[i].content[j]:<kind>`), capped at WHERE_CAP entries. */
  where: string[];
}

export const WHERE_CAP = 16;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);

/** Text part types the model reads as text. */
const TEXT_PARTS = new Set(["input_text", "output_text", "text"]);

/** Collapse then strip (assistant text), or strip only. */
function pass(text: string, assistant: boolean, r: ReserveRequestPass, where: string): string {
  if (!text.includes("$MDU")) return text;
  let t = text;
  if (assistant) {
    const c = collapseTextCounted(t);
    t = c.text;
    r.collapsed += c.collapsed;
  }
  const s = stripResiduals(t);
  if (s.removed > 0) {
    r.removed += s.removed;
    if (r.where.length < WHERE_CAP) r.where.push(where);
  }
  return s.text;
}

/** Walk an array of content parts: text parts only. `message`: a message's
 *  content, where an `output_text` part is the model's own text whatever the
 *  role; a tool output's parts are never the model's. */
function passParts(parts: unknown[], assistant: boolean, message: boolean, r: ReserveRequestPass, at: string, kind: string): void {
  parts.forEach((p, j) => {
    if (!isObj(p) || typeof p["type"] !== "string" || !TEXT_PARTS.has(p["type"] as string)) return;
    if (typeof p["text"] !== "string") return;
    const own = assistant || (message && p["type"] === "output_text");
    p["text"] = pass(p["text"] as string, own, r, `${at}[${j}]:${own ? "assistant_text" : kind}`);
  });
}

/** Run the collapse + strip pass over a parsed Responses request, in place. */
export function reserveRequestPass(req: ResponsesRequest): ReserveRequestPass {
  const r: ReserveRequestPass = { collapsed: 0, removed: 0, where: [] };
  if (!isObj(req)) return r;

  if (typeof req.instructions === "string") {
    req.instructions = pass(req.instructions, false, r, "instructions");
  }

  const input = (req as Obj)["input"];
  if (typeof input === "string") {
    (req as Obj)["input"] = pass(input, false, r, "input:user_text");
    return r;
  }
  if (!Array.isArray(input)) return r;
  input.forEach((item, i) => {
    if (!isObj(item)) return;
    const type = item["type"];
    const at = `input[${i}]`;
    // A message item (`type` is optional on the wire for an easy message).
    if (type === "message" || (type === undefined && typeof item["role"] === "string")) {
      const assistant = item["role"] === "assistant";
      const kind = assistant ? "assistant_text" : "user_text";
      const content = item["content"];
      if (typeof content === "string") {
        item["content"] = pass(content, assistant, r, `${at}.content:${kind}`);
      } else if (Array.isArray(content)) {
        passParts(content, assistant, true, r, `${at}.content`, kind);
      }
      return;
    }
    // A tool's output re-entering the context, whichever tool.
    if (typeof type === "string" && type.endsWith("_output")) {
      const out = item["output"];
      if (typeof out === "string") {
        item["output"] = pass(out, false, r, `${at}.output:${type}`);
      } else if (Array.isArray(out)) {
        passParts(out, false, false, r, `${at}.output`, type);
      }
    }
    // Everything else (reasoning, function_call, custom_tool_call, …): never.
  });
  return r;
}
