/**
 * agent-result-head — the result head an agent's OWN runtime writes in front
 * of a command's output, so a value registered from that whole result does
 * not fingerprint the head's lines (confidentiality-plan-10-flow-taint.md
 * §11.14). Mandu-new (no reference origin).
 *
 * Codex wraps every exec result in a head its runtime writes before the
 * command's bytes (codex-rs unified exec `format_response`, and the script
 * cell's runtime):
 *
 *   Chunk ID: 9a\nWall time: 0.0123 seconds\nProcess exited with code 0\n
 *   Original token count: 11\nOutput:\n<the command's output>
 *
 * A result masked whole is registered as a secret value, and a multi-line
 * value also registers every line of 24+ characters (egress-fingerprint.ts
 * MIN_LINE_FINGERPRINT_LEN). Before this module that included the head's own
 * lines (`Process exited with code 0`, `Original token count: 11`, `Process
 * running with session ID 7`, `Script running with cell ID 1`), so every
 * later result that repeated them was masked too: fail-closed, but most of
 * a Codex session's later results became one opaque handle.
 *
 * Only the head the runtime itself writes is excluded, and only by exact
 * structure: the whole grammar below must match at offset 0 of the value,
 * and the caller must say the value is the agent's whole result (the
 * symbolize request's `resultHead`, set by the openai-proxy on the whole
 * function_call_output it masked). A line that merely looks like a head line
 * anywhere else (the command printed it, or a body-only value starts with
 * it) stays registered. Every payload the grammar admits is digits, a short
 * hex chunk id, a cell id or a status word from a closed set.
 *
 * Two more heads of the same kind (2026-10-09): Codex's MCP call head
 * (`Wall time: N seconds\nOutput:`, `codex-mcp`) and the status tags Claude
 * Code writes in front of a background task's polled output (`BashOutput` /
 * `TaskOutput`, `claude-task`). Each is matched only under its own name.
 *
 * And the write notice (2026-10-11, `write-notice`; plan 15 §13.10, "A
 * Write's own result"): the fixed success sentence a write tool answers with
 * (own-write-notice.ts), on the first line of a write tool's result, before
 * any diagnostics or reminder the agent adds after it. Its free spans are the
 * ROW'S OWN origin (the path the call named, as the model wrote it) and
 * digits; OpenCode 1's has none. Unlike the other kinds it needs the row's
 * origin to match. Masked whole (OpenCode's LSP diagnostics after it), the
 * notice line had become a piece of the row, and OpenCode 1's sentence (24
 * characters, no path) then masked every later OpenCode 1 write notice on
 * the arbiter. A row whose WHOLE value is a notice (`isWholeWriteNotice`)
 * holds nothing but the sentence and needs no request to say so.
 *
 * The marks are durable (`result-heads.ts`): the arbiter stores the kind
 * with the row, bound to the row's value, so a restart keeps them.
 */

import { CC_STATE_CURRENT, CC_USER_MODIFIED } from "./own-write-notice.js";

/** Codex's unified-exec head (codex-rs `format_response`): a chunk id, an
 *  optional wall time, then EITHER the exit line OR the running-session
 *  line, an optional token count, then `Output:`. The three-line form
 *  (chunk id / exit / `Output:`) of older codex is the same grammar with
 *  the optional lines absent. */
const CODEX_EXEC_HEAD_SRC =
  "Chunk ID: [0-9a-f]{1,32}\\n" +
  "(?:Wall time: \\d+(?:\\.\\d+)? seconds\\n)?" +
  "(?:Process exited with code \\d+\\n|Process running with session ID \\d{1,20}\\n)" +
  "(?:Original token count: \\d+\\n)?";

/** The script-cell runtime's head (codex ≥ 0.154): a status word from a
 *  closed set (or the yielded cell's `running with cell ID <id>`), then the
 *  same digits-only lines. */
const CODEX_SCRIPT_HEAD_SRC =
  "Script (?:(?:completed|failed|running|yielded|timed out|interrupted|killed)(?: \\(exit code \\d+\\))?|running with cell ID [A-Za-z0-9_-]{1,64})\\n" +
  "(?:Wall time \\d+(?:\\.\\d+)? seconds\\n)?" +
  "(?:Process exited with code \\d+\\n)?" +
  "(?:Original token count: \\d+\\n)?";

const CODEX_RESULT_HEAD_RE = new RegExp(`^(?:${CODEX_EXEC_HEAD_SRC}|${CODEX_SCRIPT_HEAD_SRC})Output:\\n`);

/** Codex's MCP call head (codex ≥ 0.154, read off the wire 2026-09-25; the
 *  openai-proxy's `splitCodexMcpOutput`): the runtime's wall time, then
 *  `Output:`. In the parts form the head is its own `input_text` part and the
 *  flattened value runs straight on into the server's text; in the string
 *  form (a `structuredContent` result) one `\n` follows. Digits only. */
const CODEX_MCP_HEAD_RE = /^Wall time: \d+(?:\.\d+)? seconds\nOutput:\n?/;

/** One status tag line of Claude Code's background-task poll result
 *  (`TaskOutput`: `<retrieval_status>`, `<task_id>`, `<task_type>`,
 *  `<status>`, `<exit_code>`; the older `BashOutput`: `<status>`,
 *  `<exit_code>`). Each payload is a word from a closed set, digits, a task
 *  id the model itself named in its call, or a lower-case type word. */
const CLAUDE_TASK_TAG_SRC =
  "(?:<retrieval_status>(?:success|timeout|not_ready)</retrieval_status>" +
  "|<task_id>[A-Za-z0-9_-]{1,64}</task_id>" +
  "|<task_type>[a-z_]{1,32}</task_type>" +
  "|<status>(?:running|pending|completed|failed|killed|stopped)</status>" +
  "|<exit_code>-?\\d{1,10}</exit_code>)";

/** Claude Code's poll head: one or more status tag lines (blank lines between
 *  them), then the output's open tag (`<output>` / `<stdout>`) on its own
 *  line, or the end of the value (a poll with no output yet). The task's own
 *  bytes come after the open tag, so they cannot claim a head line. */
const CLAUDE_TASK_HEAD_RE = new RegExp(`^(?:${CLAUDE_TASK_TAG_SRC}(?:\\n+|$))+(?:<(?:output|stdout)>\\n)?`);

/** The kinds of result head a symbolize request may name:
 *  - `codex`: Codex's unified-exec or script-cell head (above);
 *  - `codex-mcp`: Codex's MCP call head;
 *  - `claude-task`: Claude Code's `BashOutput` / `TaskOutput` status tags;
 *  - `write-notice`: a write tool's fixed success sentence (below). */
export type ResultHeadKind = "codex" | "codex-mcp" | "claude-task" | "write-notice";

const RESULT_HEAD_KINDS: ReadonlySet<string> = new Set<ResultHeadKind>(["codex", "codex-mcp", "claude-task", "write-notice"]);

/** Parse the wire field: only an exact known name counts. */
export function parseResultHead(v: unknown): ResultHeadKind | null {
  return typeof v === "string" && RESULT_HEAD_KINDS.has(v) ? (v as ResultHeadKind) : null;
}

/**
 * The length of the head of kind `kind` at the START of `value`, or 0 when
 * the value does not start with exactly that kind's grammar. A head of
 * another kind is no head: the request names one. `origin` is the row's
 * stored origin, read by `write-notice` only (its path span). Pure.
 */
export function resultHeadLength(kind: ResultHeadKind, value: string, origin?: string | null): number {
  if (kind === "codex") return codexResultHeadLength(value);
  if (kind === "write-notice") return writeNoticeHeadLength(value, origin ?? null);
  const m = (kind === "codex-mcp" ? CODEX_MCP_HEAD_RE : CLAUDE_TASK_HEAD_RE).exec(value);
  return m ? m[0].length : 0;
}

/** The tool names whose results a `write-notice` head may lead: Claude
 *  Code's `Write` and the `write` of OpenCode (1 and 2), Goose and OpenClaw. */
export const WRITE_NOTICE_TOOLS: ReadonlySet<string> = new Set(["Write", "write"]);

/** May a row carry a `write-notice` head: a write tool's whole result, not
 *  a field of one. */
export function writeNoticeRow(e: { tool: string; field: string | null }): boolean {
  return WRITE_NOTICE_TOOLS.has(e.tool) && e.field === null;
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const CC_TAILS = `(?:${escapeRe(CC_USER_MODIFIED)})?(?:${escapeRe(CC_STATE_CURRENT)})?`;

/** The pinned sentences (own-write-notice.ts), one line each; group 1 is
 *  the path span where there is one. The counts are digits only. */
const WRITE_NOTICE_LINES: readonly RegExp[] = [
  new RegExp(`^File created successfully at: (.+?)${CC_TAILS}$`), // Claude Code, created
  new RegExp(`^The file (.+) has been updated successfully\\.${CC_TAILS}$`), // Claude Code, updated
  /^Created file successfully: (.+)$/, // OpenCode 2
  /^Wrote file successfully\.$/, // OpenCode 1: no free span
  /^Created (.+) \(\d{1,12} lines\)$/, // Goose
  /^Successfully wrote \d{1,15} bytes to (.+)$/, // OpenClaw
];

/** Is `span` the row's own path: its origin as stored, or (a relative path
 *  the arbiter placed at the launch directory) the end of it after a `/`. */
function isOwnPath(span: string, origin: string | null): boolean {
  if (origin === null || span === "") return false;
  return span === origin || (!span.startsWith("/") && origin.endsWith(`/${span}`));
}

/**
 * The length of a write tool's success notice at the START of `value` (its
 * first line, and the line break after it), or 0: the line must be exactly
 * one of the pinned sentences, its path span the row's own `origin`. Pure.
 */
export function writeNoticeHeadLength(value: string, origin: string | null): number {
  const nl = value.indexOf("\n");
  const line = nl === -1 ? value : value.slice(0, nl);
  for (const re of WRITE_NOTICE_LINES) {
    const m = re.exec(line);
    if (!m) continue;
    if (m[1] !== undefined && !isOwnPath(m[1], origin)) continue;
    return nl === -1 ? line.length : nl + 1;
  }
  return 0;
}

/**
 * Is the WHOLE `value` (a final line break aside) a write tool's success
 * notice for its own `origin`? Such a row holds the fixed sentence, its own
 * path and digits, nothing else, so it has no piece to fingerprint whoever
 * minted it: a row from before the `write-notice` mark existed, or the
 * notice body of a result whose reminder tail the proxy split off. Pure.
 */
export function isWholeWriteNotice(tool: string, field: string | null, value: string, origin: string | null): boolean {
  if (!writeNoticeRow({ tool, field })) return false;
  const v = value.replace(/\r?\n$/, "");
  return v !== "" && !v.includes("\n") && writeNoticeHeadLength(v, origin) === v.length;
}

/**
 * The length of the Codex result head at the START of `value` (it ends right
 * after `Output:\n`), or 0 when the value does not start with exactly that
 * grammar. Pure.
 */
export function codexResultHeadLength(value: string): number {
  const m = CODEX_RESULT_HEAD_RE.exec(value);
  return m ? m[0].length : 0;
}
