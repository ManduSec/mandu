/**
 * reserve-request — the request-side half of reply row reservation: collapse
 * every reserve block in the assistant's own text back to its token, then
 * strip every leftover fragment from every text the model will read.
 *
 * Mandu Track A (interceptors/anthropic-proxy). Design:
 * docs/design/ui/reply-row-reservation.md §3.4 and §5.2. PROVENANCE: NEW Mandu
 * code (2026-09-30); the grammar is src/reserve-block.ts.
 *
 * WHY: the proxy expands a multi-line token into N rows on its way to the
 * agent (src/sse-reserve-expand.ts). The agent re-sends its history on every
 * request, so the block comes back. The model must get its own token back
 * byte for byte (the prompt cache keys on the assistant prefix it produced),
 * and must never read N, the line count of a secret. So:
 *   1. collapse, in assistant `text` blocks (and a string assistant content)
 *      only: a well-formed block becomes its token again;
 *   2. strip, over every text the model reads: user text, tool_result
 *      content (a string or its text blocks), assistant text, and the system
 *      prompt. The system prompt is included because it is a model-bound
 *      text channel like the others (Claude Code puts CLAUDE.md and memory
 *      files there, which a tool can write), and the strip matches only the
 *      literal marker grammar, so a prompt without markers is untouched byte
 *      for byte. It runs before the proxy's handling prompt is appended.
 * Never touched: `thinking` / `redacted_thinking` (their signatures must
 * survive), `tool_use` input (model-authored arguments), images, documents.
 *
 * ORDER: this runs on the parsed body BEFORE rewriteRequest, so every later
 * step, the trusted-context haystack (rewrite-request.ts
 * buildTrustedContextHaystack, whose TRIPWIRE wants any change to a
 * non-tool_result block reflected there) included, reads the bytes that are
 * actually forwarded.
 *
 * FAIL-SAFE: pure, never throws on a malformed shape (what it cannot read it
 * leaves alone); a malformed block falls through to the strip. Mutates the
 * request in place.
 */

import type { MessagesRequest } from "./messages-types.js";
import { collapseTextCounted, stripResiduals } from "./reserve-block.js";

/** What one pass did. */
export interface ReserveRequestPass {
  /** Well-formed blocks collapsed back to their token. */
  collapsed: number;
  /** Residual fragments stripped. */
  removed: number;
  /** Where fragments were stripped (`system`, `messages[i].content[j]:<kind>`),
   *  capped at WHERE_CAP entries. */
  where: string[];
}

export const WHERE_CAP = 16;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);

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

/** Run the collapse + strip pass over a parsed Messages request, in place. */
export function reserveRequestPass(req: MessagesRequest): ReserveRequestPass {
  const r: ReserveRequestPass = { collapsed: 0, removed: 0, where: [] };
  if (!isObj(req)) return r;

  const sys = (req as Obj)["system"];
  if (typeof sys === "string") {
    (req as Obj)["system"] = pass(sys, false, r, "system");
  } else if (Array.isArray(sys)) {
    sys.forEach((b, i) => {
      if (isObj(b) && b["type"] === "text" && typeof b["text"] === "string") {
        b["text"] = pass(b["text"] as string, false, r, `system[${i}]`);
      }
    });
  }

  const msgs = (req as Obj)["messages"];
  if (!Array.isArray(msgs)) return r;
  msgs.forEach((msg, mi) => {
    if (!isObj(msg)) return;
    const assistant = msg["role"] === "assistant";
    const kind = assistant ? "assistant_text" : "user_text";
    const content = msg["content"];
    if (typeof content === "string") {
      msg["content"] = pass(content, assistant, r, `messages[${mi}].content:${kind}`);
      return;
    }
    if (!Array.isArray(content)) return;
    content.forEach((block, bi) => {
      if (!isObj(block)) return;
      const at = `messages[${mi}].content[${bi}]`;
      if (block["type"] === "text" && typeof block["text"] === "string") {
        block["text"] = pass(block["text"] as string, assistant, r, `${at}:${kind}`);
        return;
      }
      if (block["type"] !== "tool_result") return;
      const tc = block["content"];
      if (typeof tc === "string") {
        block["content"] = pass(tc, false, r, `${at}:tool_result`);
      } else if (Array.isArray(tc)) {
        tc.forEach((nb, ni) => {
          if (isObj(nb) && nb["type"] === "text" && typeof nb["text"] === "string") {
            nb["text"] = pass(nb["text"] as string, false, r, `${at}.content[${ni}]:tool_result`);
          }
        });
      }
    });
  });
  return r;
}
