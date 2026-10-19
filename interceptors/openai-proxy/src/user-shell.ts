/**
 * user-shell — Codex's user-run shell command (`!cmd` in the TUI) read as the
 * PROGRAM OUTPUT it is (supported-agents.md §2.4).
 *
 * Mandu-new. Codex runs the command itself and puts the record in the next
 * request as a user message item of its own (captured on codex-cli 0.160.0
 * against a scripted Responses upstream, tests/fixtures/
 * codex-user-shell-2026-10-05.json):
 *
 *   {type:"message", role:"user", content:[{type:"input_text", text:
 *     "<user_shell_command>\n<command>\n{command}\n</command>\n<result>\n
 *      Exit code: {n}\nDuration: {s} seconds\nOutput:\n{output}\n</result>\n
 *      </user_shell_command>"}]}
 *
 * Nothing is escaped (a `</user_shell_command>` in the output appears as it
 * is), and every later request re-sends the item unchanged. Until this, the
 * prompt filter tagged it harness (prompt-filter.ts) and only the
 * registered-value filter read it: no path label from the command, no
 * callTaint, so a `!cat` of a labelled file Mandu never registered reached
 * the model raw.
 *
 * Now each such part becomes, for the rewrite, a stand-in (inserted before its message)
 * `function_call_output` of an `exec_command{cmd}` call (the command off the
 * record, up to the FIRST `\n</command>\n<result>\n`, which the strict head
 * after it must follow; a command holding that sequence is cut early and the
 * rest is read as output, never forwarded raw as "the command"), so the
 * output gets the classify verdict's path label, callTaint by the command's
 * exec signature, the value backstop and the inbound spec. It goes back into
 * the record between the original head and tail: byte for byte when nothing
 * changed, the symbol and note when masked, the same in every later request.
 * A part in that shape that does not parse is masked whole. Pure helpers;
 * rewrite-request.ts applies them.
 */
import { createHash } from "node:crypto";
import type { FunctionCallOutputItem, InputItem } from "./responses-types.js";

const OPEN = "<user_shell_command>";
const CMD_HEAD = "<user_shell_command>\n<command>\n";
const CMD_END = "\n</command>\n<result>\n";
const RESULT_HEAD_RE = /^Exit code: -?\d{1,5}\nDuration: \d{1,9}(?:\.\d{1,9})? seconds\nOutput:\n/;
const TAIL = "\n</result>\n</user_shell_command>";

/** A record the rewrite reads as `exec_command{cmd: command}`'s output. */
export interface ParsedUserShell {
  command: string;
  /** The record up to the output, and after it. */
  head: string;
  output: string;
  tail: string;
}

/** Does this user text start like a user-shell record? */
export function isUserShellText(text: unknown): text is string {
  return typeof text === "string" && text.startsWith(OPEN);
}

/** Read one record. Null: in that shape but not this grammar (mask whole). Pure. */
export function parseUserShell(text: string): ParsedUserShell | null {
  if (!text.startsWith(CMD_HEAD) || !text.endsWith(TAIL)) return null;
  const end = text.indexOf(CMD_END, CMD_HEAD.length);
  if (end < 0) return null;
  const command = text.slice(CMD_HEAD.length, end);
  const afterCmd = end + CMD_END.length;
  const m = RESULT_HEAD_RE.exec(text.slice(afterCmd));
  if (!m) return null;
  const outStart = afterCmd + m[0].length;
  const outEnd = text.length - TAIL.length;
  if (outEnd < outStart) return null;
  return { command, head: text.slice(0, outStart), output: text.slice(outStart, outEnd), tail: text.slice(outEnd) };
}

/** One extracted part: where it was and how to put it back. */
export interface ExtractedUserShell {
  /** The stand-in's call id (stable: the record's own hash; a repeat gets #n). */
  callId: string;
  parsed: ParsedUserShell | null;
  original: string;
  item: Record<string, unknown>;
  partIndex: number;
  /** The stand-in output item put in the input array in the message's place. */
  stand: FunctionCallOutputItem;
}

/**
 * Pull every user-shell record out of the user messages for the walk
 * (mutates `input`; the caller holds a clone): a stand-in
 * function_call_output goes in right before its message, and the record's
 * own text part is emptied meanwhile, so the prompt filter reads only the
 * message's other parts (the human's own text, if any) and never the
 * record. `restoreUserShells` puts the text back and drops the stand-ins.
 */
export function extractUserShells(input: InputItem[]): ExtractedUserShell[] {
  const out: ExtractedUserShell[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < input.length; i++) {
    const item = input[i] as unknown as Record<string, unknown>;
    if (!item || typeof item !== "object" || item["role"] !== "user" || (item["type"] !== undefined && item["type"] !== "message")) continue;
    const content = item["content"];
    if (!Array.isArray(content)) continue;
    const stands: FunctionCallOutputItem[] = [];
    content.forEach((part: unknown, partIndex: number) => {
      const p = part as { type?: unknown; text?: unknown };
      if (!p || p.type !== "input_text" || !isUserShellText(p.text)) return;
      const base = `mandu-user-shell:${createHash("sha256").update(p.text).digest("hex").slice(0, 16)}`;
      let callId = base;
      for (let k = 2; seen.has(callId); k++) callId = `${base}#${k}`;
      seen.add(callId);
      const parsed = parseUserShell(p.text);
      const stand: FunctionCallOutputItem = { type: "function_call_output", call_id: callId, output: parsed ? parsed.output : p.text };
      out.push({ callId, parsed, original: p.text, item, partIndex, stand });
      stands.push(stand);
      (part as { text: string }).text = "";
    });
    if (stands.length === 0) continue;
    input.splice(i, 0, ...(stands as unknown as InputItem[]));
    i += stands.length;
  }
  return out;
}

/** The output a stand-in carries after the walk, as text. */
function standText(stand: FunctionCallOutputItem): string {
  const o = stand.output;
  if (typeof o === "string") return o;
  if (Array.isArray(o)) return o.map((x) => (x && typeof x === "object" && typeof (x as { text?: unknown }).text === "string" ? (x as { text: string }).text : "")).join("");
  return JSON.stringify(o);
}

/** Put every record back, carrying what the walk made of its output (byte
 *  for byte when nothing changed; a masked-whole record is the rewritten
 *  text alone), and drop the stand-ins. */
export function restoreUserShells(input: InputItem[], extracted: readonly ExtractedUserShell[]): void {
  if (extracted.length === 0) return;
  const stands = new Set<unknown>(extracted.map((e) => e.stand));
  for (const e of extracted) {
    const rewritten = standText(e.stand);
    const text = e.parsed
      ? (rewritten === e.parsed.output ? e.original : `${e.parsed.head}${rewritten}${e.parsed.tail}`)
      : rewritten;
    ((e.item["content"] as Array<Record<string, unknown>>)[e.partIndex]!)["text"] = text;
  }
  for (let i = input.length - 1; i >= 0; i--) if (stands.has(input[i])) input.splice(i, 1);
}

/** The user-shell texts of a forwarded request (the §9 oracle reads them as
 *  tool output too). */
export function userShellTexts(input: readonly unknown[]): string[] {
  const out: string[] = [];
  for (const item of input) {
    const it = item as Record<string, unknown>;
    if (!it || it["role"] !== "user" || !Array.isArray(it["content"])) continue;
    for (const p of it["content"] as Array<{ type?: unknown; text?: unknown }>) {
      if (p && p.type === "input_text" && isUserShellText(p.text)) out.push(p.text);
    }
  }
  return out;
}
