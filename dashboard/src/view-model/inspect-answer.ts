/**
 * view-model/inspect-answer — which calls are the sandboxed reader's
 * (`inspect_symbol` of the mandu-inspect server), and the answer placeholder
 * each one got back, in every shape an agent forwards it (dashboard.md §4.2f,
 * "The sandboxed reader's card").
 *
 * Mandu-new (no reference origin). WHY: the inspector drew the reader's card
 * only when the AI's result was, whole, the JSON envelope
 * `{"result_symbol": …}`. But the arbiter's rule keeps three success shapes
 * (arbiter/policy/claude-code-inbound.ts `isPureSymbolicInspectResult`): the
 * bare token (the MCP content text), the envelope (the structuredContent
 * Claude Code forwards), and the token followed by the envelope. And Claude
 * Code appends its own `<system-reminder>` blocks after the envelope, which
 * the proxy forwards kept or masked on their own (rewrite-request.ts
 * `splitTrailingSystemReminders`). Two of the four reader calls in the
 * recorded live sessions carried such a tail and drew as a plain card.
 * Pure; it reads only the text it is given, never a value of its own.
 *
 *   - NAME: Mandu's own spellings, the list the arbiter keeps
 *     (arbiter/policy/inspect-tool.ts `isManduInspectTool`;
 *     tests/stack/inspector-inspect-answer.test.ts pins the two equal),
 *     plus any server's `…__inspect_symbol` as the inspector drew before.
 *   - ANSWER: read from the head of the result only. What follows it is the
 *     tail, drawn as it is: the AI got it too.
 */
import { tokensIn } from "./held-tokens.js";

const SERVER = "mandu-inspect";
const BASENAME = "inspect_symbol";

/** Every spelling of Mandu's inspect tool, as the arbiter keeps them:
 *  Claude Code, OpenCode (one underscore), Codex (the server's "-" read as
 *  "_"), Goose, and OpenClaw's plugin tool (bare, it has no namespace). */
export const MANDU_INSPECT_TOOL_SPELLINGS: readonly string[] = [
  `mcp__${SERVER}__${BASENAME}`,
  `${SERVER}_${BASENAME}`,
  `mcp__${SERVER.replace(/-/g, "_")}__${BASENAME}`,
  `${SERVER}__${BASENAME}`,
  BASENAME,
];

/** Is `tool` a call the inspector draws as the sandboxed reader's card? */
export function isInspectCall(tool: string): boolean {
  return MANDU_INSPECT_TOOL_SPELLINGS.includes(tool) || tool.endsWith(`__${BASENAME}`);
}

export interface InspectAnswer {
  /** The envelope's `result_symbol` (the AI's side: the answer placeholder;
   *  the original side: the answer itself), or the bare answer token. */
  answer: string;
  /** What the result held after the answer (an agent's appended note, kept
   *  or masked), trimmed; null when there is none. */
  tail: string | null;
}

/** The JSON object at the very start of `text` and where it ends, or null.
 *  Strings are skipped whole, so a brace inside one does not count. */
function leadingObject(text: string): { value: Record<string, unknown>; end: number } | null {
  if (!text.startsWith("{")) return null;
  let depth = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (ch === "\\") i++;
      else if (ch === '"') inString = false;
    } else if (ch === '"') inString = true;
    else if (ch === "{" || ch === "[") depth++;
    else if (ch === "}" || ch === "]") {
      if (--depth > 0) continue;
      try {
        const v = JSON.parse(text.slice(0, i + 1)) as unknown;
        return v && typeof v === "object" && !Array.isArray(v) ? { value: v as Record<string, unknown>, end: i + 1 } : null;
      } catch {
        return null;
      }
    }
  }
  return null;
}

const resultSymbolOf = (o: Record<string, unknown>): string | null => {
  const v = o["result_symbol"];
  return typeof v === "string" && v !== "" ? v : null;
};

/** The answer a reader's result carries, from its head: the envelope, or the
 *  reader's answer token (its field is `result`, inspect-symbol.ts), alone or
 *  followed by the envelope that names it. Null for anything else (an error,
 *  prose, a result masked whole), so the caller draws what it drew before. */
export function inspectAnswer(text: string | null): InspectAnswer | null {
  if (!text) return null;
  const body = text.trimStart();
  let answer: string;
  let rest: string;
  const env = leadingObject(body);
  if (env) {
    const a = resultSymbolOf(env.value);
    if (a === null) return null;
    answer = a;
    rest = body.slice(env.end);
  } else {
    const tok = tokensIn(body)[0];
    if (!tok || tok.index !== 0 || !tok.name.endsWith(".result")) return null;
    answer = tok.name;
    rest = body.slice(tok.end);
    // Both of the MCP result's blocks, joined: the envelope repeats the token.
    const next = leadingObject(rest.trimStart());
    if (next && resultSymbolOf(next.value) === answer) rest = rest.trimStart().slice(next.end);
  }
  const tail = rest.trim();
  return { answer, tail: tail === "" ? null : tail };
}
