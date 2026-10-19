/**
 * unmapped-upload — the local files a Codex tool Mandu does not map may send
 * off this computer: the openai-proxy's unmapped upload leg (guarantees.md
 * §3, "A tool that uploads a local file by its path"; supported-agents.md
 * §2, "The upload residuals", item 4).
 *
 * Mandu-new (no reference origin). The anthropic-proxy's leg
 * (interceptors/anthropic-proxy/src/unmapped-upload.ts, 2026-10-17) for the
 * Responses wire. Until 2026-10-17 Codex's MCP tools had no such check: an
 * MCP server's `upload_file{path: "/ws/app/.env"}` reached Codex unchanged,
 * its result masked whole while unmapped, but the file it sent kept home
 * only by the confinement. The pure core (the path finder, the arbiter
 * asks, the withheld spelling, the notices) is unmapped-upload-core.ts, one
 * text with the anthropic-proxy's; this module adds what is Codex's:
 *
 *   - WHICH TOOLS. Every tool but codex's own (`isCodexBuiltinTool`: its
 *     shells and CODEX_MAPPED_TOOLS: `apply_patch`, `view_image`, the file
 *     and sub-agent tools, …), each judged by its own legs and never asked
 *     about here. A namespaced call goes by `<namespace>__<name>`
 *     (`mcp__drive__upload_file`), the spelling the arbiter's MCP
 *     registration and its rule 0 read. The arbiter answers the rest
 *     (file-upload.ts rules 0, 4a, 5a): a tool the session maps keeps its
 *     legs, a registered local MCP server's tool in a session the file guard
 *     confines is let be, a secret, a registered value, a sensitive path, a
 *     file of a process or unreadable bytes are held for the person's OK,
 *     nothing at the path or a plain folder pass.
 *   - THE CODE CELLS. On codex's code-mode wire every MCP call rides inside
 *     an `exec` JavaScript cell (supported-agents.md §6). A cell the
 *     allow-list grammar identifies call by call (mcp-cell.ts parseCell, in
 *     a fresh isolate) has each non-codex call judged on its literal
 *     arguments, in order, an earlier call of the cell that may write
 *     counting as a writer before a later one. Any other cell has every
 *     string literal of its text that names a local path judged under each
 *     tool the text names that is not codex's (cell-guard.ts
 *     writtenToolNames: a tool it does not name is switched off by the cell
 *     guard). A held path in a cell replaces the WHOLE cell by the exec
 *     gate's sentinel cell (script-cell.ts blockSentinelCell): a cell's
 *     literal is code, and a cell half run is not one the model wrote.
 *   - THE WINDOW. Codex runs a tool that does not support parallel calls
 *     (an MCP server's, unless its config sets `supports_parallel_tool_calls
 *     = true`) under an exclusive lock, so every call the response named
 *     before it has finished when it runs. So, as in the anthropic-proxy, a
 *     path judged by its bytes in a call that follows, in the same response,
 *     a call that may write files (`codexPossibleWriter`: anything but
 *     codex's bookkeeping) is withheld (`proxy:upload-after-write`).
 *     Left: a server configured for parallel calls runs its tool beside the
 *     parallel-capable calls of the turn, so a writer LATER in the same
 *     response can race it; a cell's path computed at run time.
 *
 * A function_call's withheld path becomes `/mandu/denied/upload/<path>`
 * (names no file), every other argument as the model wrote it, and the
 * call's output is replaced by the notice in the next request (UploadNotices,
 * read by rewrite-request.ts); the model reads its own call back
 * (exec-history.ts). Fail-closed as the core: no answer, too many paths, a
 * value nested too deep withholds.
 *
 * Pure but for the arbiter call; never throws.
 */

import { writtenToolNames } from "./cell-guard.js";
import { parseCell } from "./mcp-cell.js";
import { isCodexBuiltinTool } from "./rewrite-request.js";
import {
  gateUnmappedUploadToolUse,
  UNMAPPED_UPLOAD_MAX_PATHS,
  type UnmappedUploadOptions,
  type WithheldPath,
} from "./unmapped-upload-core.js";

export * from "./unmapped-upload-core.js";

/** Is `name` a tool the leg judges? Every tool but codex's own (a shell or
 *  a CODEX_MAPPED_TOOLS built-in), each of which keeps its own legs. Pure. */
export function uploadLegApplies(name: string): boolean {
  return name !== "" && !isCodexBuiltinTool(name);
}

/** Codex's tools that write no file of the person's: its plan, its questions,
 *  its goal, its timer, the file readers and the image viewer, the tool
 *  search, and the sub-agent tools that only look (a running sub-agent's own
 *  writes are a background writer's, the confinement's). Names off codex's
 *  wire (rewrite-request.ts CODEX_MAPPED_TOOLS). */
export const CODEX_NON_WRITING_TOOLS: ReadonlySet<string> = new Set([
  "update_plan", "view_image", "read_file", "list_dir", "grep_files", "tool_search",
  "request_user_input", "request_user_input_async", "get_goal", "create_goal", "update_goal",
  "clock__sleep", "wait_agent", "collaboration__list_agents", "collaboration__wait_agent",
]);

/** May a call of `tool`, earlier in the same response, change a local file
 *  before a later call of that response reads it? THE WINDOW (module
 *  header): true but for CODEX_NON_WRITING_TOOLS. A shell, a patch, a cell,
 *  `write_stdin`, `wait` (a yielded cell runs on), a sub-agent it starts and
 *  every tool Mandu does not map may. Pure. */
export function codexPossibleWriter(tool: string): boolean {
  return !CODEX_NON_WRITING_TOOLS.has(tool);
}

/**
 * The calls of ONE response (one model turn), in the order the stream
 * carried them, for the window rule. A call is recorded once by its id (the
 * same call arrives in several snapshots); a call with no id each time.
 */
export class UploadTurn {
  private readonly calls: Array<{ id: string | null; name: string }> = [];

  /** The first call recorded before `callId`'s own (or before now, when it
   *  is not recorded yet) that may write files. */
  priorWriter(callId: string | null): string | undefined {
    const at = callId !== null ? this.calls.findIndex((c) => c.id === callId) : -1;
    const before = at >= 0 ? this.calls.slice(0, at) : this.calls;
    return before.find((c) => codexPossibleWriter(c.name))?.name;
  }

  record(callId: string | null, name: string): void {
    if (callId !== null && this.calls.some((c) => c.id === callId)) return;
    this.calls.push({ id: callId, name });
  }
}

/** How many notices UploadNotices keeps (oldest out): a forgotten one only
 *  costs utility (the output is classified as before). */
export const UPLOAD_NOTICES_MAX = 1024;

/**
 * The leg's notices by call id: a function_call whose path(s) the leg
 * withheld reached nothing the model asked for, so its output (the tool's
 * error about a path that names no file) is REPLACED by the notice in the
 * next request (rewrite-request.ts), the anthropic-proxy's ResultNotices.
 * In memory only: a restarted proxy classifies the output as before.
 */
export class UploadNotices {
  private readonly notices = new Map<string, string>();

  remember(callId: string | null | undefined, notice: string | undefined): void {
    if (!callId || !notice) return;
    this.notices.delete(callId);
    this.notices.set(callId, notice);
    while (this.notices.size > UPLOAD_NOTICES_MAX) {
      const oldest = this.notices.keys().next().value;
      if (oldest === undefined) break;
      this.notices.delete(oldest);
    }
  }

  noticeFor(callId: string): string | undefined {
    return this.notices.get(callId);
  }
}

/** Bound on the string literals one cell's text is read for. Past it the
 *  cell is held whole (fail-closed). */
export const CELL_LITERALS_MAX = 1024;

const SIMPLE_ESCAPES: Readonly<Record<string, string>> = { n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", v: "\v", "0": "\0" };

/** A JavaScript string literal's body, its escapes decoded (an unknown
 *  escape is the character itself, as JavaScript reads it). Pure. */
function decodeJsString(body: string): string {
  return body.replace(/\\(?:x([0-9A-Fa-f]{2})|u\{([0-9A-Fa-f]{1,6})\}|u([0-9A-Fa-f]{4})|\r?\n|([\s\S]))/g, (_m, x, ub, u, c) => {
    const hex = (x ?? ub ?? u) as string | undefined;
    if (hex !== undefined) {
      const cp = Number.parseInt(hex, 16);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : "";
    }
    if (c === undefined) return ""; // a line continuation
    return SIMPLE_ESCAPES[c as string] ?? (c as string);
  });
}

/**
 * Every string a cell's text spells: each quoted literal (`'…'`, `"…"`, and
 * the text pieces of a template literal around its `${…}` holes), escapes
 * decoded, read twice (a scanner that skips comments, then a plain pattern
 * over the whole text, so a regex literal that confuses the scanner cannot
 * hide a string from both). Over-reading is safe: each string is only asked
 * about if it names a local path. A path the cell COMPUTES at run time is
 * not read (module header, Left). Pure.
 */
export function cellStringLiterals(src: string): string[] {
  const out = new Set<string>();
  const add = (s: string): void => { if (s !== "") out.add(s); };
  // 1. the scanner
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    if (c === "/" && src[i + 1] === "/") { const e = src.indexOf("\n", i); i = e < 0 ? src.length : e + 1; continue; }
    if (c === "/" && src[i + 1] === "*") { const e = src.indexOf("*/", i + 2); i = e < 0 ? src.length : e + 2; continue; }
    if (c === "'" || c === "\"") {
      let j = i + 1;
      while (j < src.length && src[j] !== c && src[j] !== "\n") j += src[j] === "\\" ? 2 : 1;
      if (src[j] === c) add(decodeJsString(src.slice(i + 1, j)));
      i = j + 1;
      continue;
    }
    if (c === "`") {
      let j = i + 1;
      let piece = "";
      while (j < src.length && src[j] !== "`") {
        if (src[j] === "\\") { piece += src.slice(j, j + 2); j += 2; continue; }
        if (src[j] === "$" && src[j + 1] === "{") {
          add(decodeJsString(piece));
          piece = "";
          let depth = 1;
          j += 2;
          while (j < src.length && depth > 0) {
            if (src[j] === "{") depth++;
            else if (src[j] === "}") depth--;
            j++;
          }
          continue;
        }
        piece += src[j];
        j++;
      }
      add(decodeJsString(piece));
      i = j + 1;
      continue;
    }
    i++;
  }
  // 2. the plain pattern
  for (const m of src.matchAll(/(["'])((?:\\.|(?!\1)[^\\\n])*)\1/g)) add(decodeJsString(m[2]!));
  for (const m of src.matchAll(/`((?:\\[\s\S]|[^\\`])*)`/g)) for (const piece of m[1]!.split(/\$\{[^}]*\}/)) add(decodeJsString(piece));
  return [...out];
}

/** What the cell leg held: the notice the model reads (printed by the
 *  sentinel cell), the reason, and every withheld path. */
export interface CellUploadHold {
  tool: string;
  reason: string;
  notice: string;
  withheld: WithheldPath[];
}

export interface CellUploadOptions extends Omit<UnmappedUploadOptions, "priorWriter"> {
  /** The request's `exec` tool says each cell runs in a fresh isolate
   *  (mcp-cell.ts cellsAreIsolated): only then is a parsed cell's call list
   *  the cell's whole story. */
  cellsIsolated: boolean;
  /** An earlier call of the same response that may write files. */
  priorWriter?: string;
}

/** A hold with no arbiter verdict behind it (a bound, the parse). */
function heldWhole(tool: string, why: string): CellUploadHold {
  const notice = `mandu-upload-gate: the cell was not run: ${why}, so Mandu could not check which local files ${tool} would send. Call ${tool} as its own tool call, with each file path written out. (rule: proxy:upload-unreadable)`;
  return { tool, reason: `${why} — fail closed`, notice, withheld: [] };
}

/**
 * The unmapped upload leg for one code cell (module header, THE CODE
 * CELLS): null when nothing is held, else the hold (the caller replaces the
 * whole cell by the sentinel cell). NEVER THROWS: the core withholds on any
 * arbiter failure.
 */
export async function gateUnmappedUploadCell(src: string, opts: CellUploadOptions): Promise<CellUploadHold | null> {
  if (typeof src !== "string" || src === "") return null;
  const parsed = opts.cellsIsolated ? parseCell(src) : null;
  if (parsed !== null && "calls" in parsed) {
    // Identified call by call: each non-codex call on its own literal, in order.
    let prior = opts.priorWriter;
    for (const call of parsed.calls) {
      if (uploadLegApplies(call.name)) {
        const r = await gateUnmappedUploadToolUse(call.name, call.args, { ...opts, ...(prior !== undefined ? { priorWriter: prior } : {}) });
        if (r.outcome?.decision === "block") {
          return { tool: call.name, reason: r.outcome.reason, notice: r.outcome.notice ?? "mandu-upload-gate: a file this cell names was held", withheld: r.outcome.withheld };
        }
      }
      if (prior === undefined && codexPossibleWriter(call.name)) prior = call.name;
    }
    return null;
  }
  // Not identified: every local path the text spells, under every tool the
  // text names that is not codex's (the cell guard switches off the rest).
  const tools = writtenToolNames(src).filter(uploadLegApplies);
  if (tools.length === 0) return null;
  const literals = cellStringLiterals(src);
  if (literals.length > CELL_LITERALS_MAX) return heldWhole(tools[0]!, `the cell spells more than ${CELL_LITERALS_MAX} strings`);
  if (literals.length === 0) return null;
  // The cell may run a writer of its own (a shell, a patch, another tool)
  // before the upload: an unidentified cell's order is not known.
  if (tools.length * literals.length > UNMAPPED_UPLOAD_MAX_PATHS * 4) return heldWhole(tools[0]!, "the cell names too many tools and strings to check");
  const written = writtenToolNames(src);
  for (const tool of tools) {
    const own = written.find((n) => n !== tool && codexPossibleWriter(n));
    const prior = opts.priorWriter ?? own;
    const r = await gateUnmappedUploadToolUse(tool, { literals }, { ...opts, ...(prior !== undefined ? { priorWriter: prior } : {}) });
    if (r.outcome?.decision === "block") {
      return { tool, reason: r.outcome.reason, notice: r.outcome.notice ?? "mandu-upload-gate: a file this cell names was held", withheld: r.outcome.withheld };
    }
  }
  return null;
}
