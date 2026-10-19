/**
 * script-cell — the Codex ≥ 0.154 `exec` CUSTOM tool: a JavaScript cell the
 * model writes, which the Codex runtime evaluates in a host whose `tools.*`
 * functions run the real shell (`tools.exec_command({cmd, workdir, …})`).
 *
 * Mandu Track A (interceptors/openai-proxy). On this wire the shell command
 * is no longer a `function_call.arguments` JSON string but a JSON object
 * LITERAL embedded in JavaScript source (responses-types.ts header). This
 * module is the one place that finds those literals, so the rest of the proxy
 * keeps working on argument JSON exactly as it does for `function_call`:
 *
 *   findScriptCalls(js)   every `tools.<name>({…})` call: name + the literal's
 *                         byte span + its JSON text
 *   scriptCellArgs(js)    the FIRST exec_command call's parsed arguments (the
 *                         correlation / origin seam for the request rewrite)
 *   transformScriptCell   run an ArgsTransform (the exec gate → the forward
 *                         path-map, sse-rewrite.ts composeArgsTransform) over
 *                         every exec_command literal and splice the results
 *                         back — the response-side seam
 *
 * FAIL-CLOSED where it is a gate: a cell whose exec_command arguments are not
 * ONE object literal (a variable, a concatenation, a call — parseLiteral
 * accepts JSON and the hand-written JavaScript literal subset) is exactly
 * the shape that would carry a symbol past a literal-only gate, so
 * with `unparseable: "block"` the WHOLE cell is replaced by a sentinel cell
 * that runs the exec-gate block sentinel (`exit 77`, exec-gate.ts) through
 * the same tool — the model reads the block reason, nothing runs. The
 * observed cells (codex 0.154, gpt-5.6) are always `JSON.stringify`-shaped
 * literals, so the honest cell costs nothing. `"keep"` (no gate active) never
 * rewrites what it cannot parse (the path-map's rule 3).
 */

import { blockNoticeText, blockSentinelCommand } from "./exec-gate.js";
import { cellCallsIdentified, parseCell } from "./mcp-cell.js";
import { commandLikeFields } from "./unmapped-exec.js";

/** The `tools.*` functions whose argument object carries the shell command. */
export const SCRIPT_EXEC_FUNCTIONS: ReadonlySet<string> = new Set(["exec_command"]);

export interface ScriptCall {
  /** The `tools.<name>` function called. */
  name: string;
  /** Byte span of the argument OBJECT LITERAL inside the cell source. */
  start: number;
  end: number;
  /** The literal's text (JSON when the model wrote it the observed way). */
  argsJson: string;
}

const CALL_HEAD_RE = /\btools\s*\.\s*([A-Za-z_$][\w$]*)\s*\(\s*/g;

/**
 * Scan a balanced `{…}` starting at `text[at]` (which must be `{`), honoring
 * JS/JSON string literals (double, single, template) and their escapes.
 * Returns the index just past the closing brace, or -1 when unbalanced.
 */
function scanObjectLiteral(text: string, at: number): number {
  if (text[at] !== "{") return -1;
  let depth = 0;
  let quote: string | null = null;
  for (let i = at; i < text.length; i++) {
    const c = text[i]!;
    if (quote !== null) {
      if (c === "\\") { i++; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") { quote = c; continue; }
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return i + 1; }
  }
  return -1;
}

/** Every `tools.<name>({…})` call in a cell, in source order. Never throws. */
export function findScriptCalls(js: string): ScriptCall[] {
  const out: ScriptCall[] = [];
  if (typeof js !== "string" || js === "") return out;
  CALL_HEAD_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = CALL_HEAD_RE.exec(js)) !== null) {
    const name = m[1]!;
    const start = m.index + m[0].length;
    if (js[start] !== "{") continue; // not a literal argument (a variable, a call, …): recorded by exec-shaped callers as unparseable
    const end = scanObjectLiteral(js, start);
    if (end < 0) continue;
    out.push({ name, start, end, argsJson: js.slice(start, end) });
    CALL_HEAD_RE.lastIndex = end;
  }
  return out;
}

/** Does the cell call an exec function at all (with ANY argument shape)? */
export function callsExec(js: string): boolean {
  if (typeof js !== "string") return false;
  for (const fn of SCRIPT_EXEC_FUNCTIONS) {
    if (new RegExp(`\\btools\\s*\\.\\s*${fn}\\s*\\(`).test(js)) return true;
  }
  return false;
}

/**
 * Parse one argument literal: JSON first, else the LITERAL subset of a
 * JavaScript object literal the model writes by hand — unquoted or quoted
 * keys, single/double/template-quoted strings (no `${…}`), numbers, booleans,
 * null/undefined, nested objects and arrays, trailing commas. Nothing
 * computed: an identifier value, a call, an operator, a template hole or a
 * comment makes the literal unparseable (null), which the gate treats as
 * "cannot inspect" (block). Live 2026-09-24 (gpt-6-astra): the model's first
 * cell of every session was not strict JSON, so a JSON-only gate blocked an
 * honest `cat notes.md` until the model retried in JSON.
 */
export function parseLiteral(argsJson: string): Record<string, unknown> | null {
  try {
    const o = JSON.parse(argsJson) as unknown;
    if (o && typeof o === "object" && !Array.isArray(o)) return o as Record<string, unknown>;
  } catch { /* not JSON: try the JS literal subset */ }
  const parsed = parseJsObjectLiteral(argsJson);
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
}

/** The literal-subset parser behind parseLiteral. Exported for its tests. */
export function parseJsObjectLiteral(text: string): unknown {
  let i = 0;
  const ws = (): void => { while (i < text.length && /\s/.test(text[i]!)) i++; };
  const fail = (): never => { throw new Error("not a literal"); };
  const str = (): string => {
    const q = text[i]!;
    i++;
    let out = "";
    while (i < text.length) {
      const c = text[i]!;
      if (c === "\\") {
        const n = text[i + 1];
        if (n === undefined) fail();
        const esc: Record<string, string> = { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", v: "\v", "0": "\0", "\\": "\\", "'": "'", '"': '"', "`": "`", "/": "/", "\n": "" };
        if (n === "u") {
          const hex = text.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail();
          out += String.fromCharCode(parseInt(hex, 16));
          i += 6;
          continue;
        }
        if (n === "x") {
          const hex = text.slice(i + 2, i + 4);
          if (!/^[0-9a-fA-F]{2}$/.test(hex)) fail();
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
          continue;
        }
        if (!(n! in esc)) fail();
        out += esc[n!];
        i += 2;
        continue;
      }
      if (c === q) { i++; return out; }
      if (q === "`" && c === "$" && text[i + 1] === "{") fail(); // a template hole is computed
      if (q !== "`" && c === "\n") fail();
      out += c;
      i++;
    }
    return fail();
  };
  const value = (): unknown => {
    ws();
    const c = text[i];
    if (c === undefined) fail();
    if (c === "{") return obj();
    if (c === "[") return arr();
    if (c === '"' || c === "'" || c === "`") return str();
    const m = /^(?:-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?|true|false|null|undefined)(?![\w$])/.exec(text.slice(i));
    if (!m) return fail();
    i += m[0].length;
    const t = m[0];
    if (t === "true") return true;
    if (t === "false") return false;
    if (t === "null" || t === "undefined") return null;
    return Number(t);
  };
  const arr = (): unknown[] => {
    i++; // [
    const out: unknown[] = [];
    for (;;) {
      ws();
      if (text[i] === "]") { i++; return out; }
      out.push(value());
      ws();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "]") { i++; return out; }
      fail();
    }
  };
  const obj = (): Record<string, unknown> => {
    i++; // {
    const out: Record<string, unknown> = {};
    for (;;) {
      ws();
      if (text[i] === "}") { i++; return out; }
      let key: string;
      if (text[i] === '"' || text[i] === "'") key = str();
      else {
        const m = /^[A-Za-z_$][\w$]*/.exec(text.slice(i));
        if (!m) fail();
        key = m![0];
        i += key.length;
      }
      ws();
      if (text[i] !== ":") fail();
      i++;
      out[key] = value();
      ws();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "}") { i++; return out; }
      fail();
    }
  };
  try {
    ws();
    if (text[i] !== "{") return null;
    const v = obj();
    ws();
    return i === text.length ? v : null;
  } catch {
    return null;
  }
}

/**
 * The FIRST exec_command call's arguments (the shell command the cell runs),
 * parsed; null when the cell holds no parseable exec literal. Used by the
 * request rewrite to recover the origin (`cmd`) and the params of a
 * custom_tool_call_output's originating call.
 */
export function scriptCellArgs(js: string): { name: string; args: Record<string, unknown> } | null {
  for (const call of findScriptCalls(js)) {
    if (!SCRIPT_EXEC_FUNCTIONS.has(call.name)) continue;
    const args = parseLiteral(call.argsJson);
    if (args) return { name: call.name, args };
  }
  return null;
}

/** Every exec_command call's arguments, in order, as JSON text (a hand-written
 *  JavaScript literal is normalized) — the tool_use events. */
export function scriptCellExecCalls(js: string): Array<{ name: string; argsJson: string }> {
  const out: Array<{ name: string; argsJson: string }> = [];
  for (const c of findScriptCalls(js)) {
    if (!SCRIPT_EXEC_FUNCTIONS.has(c.name)) continue;
    const args = parseLiteral(c.argsJson);
    if (args) out.push({ name: c.name, argsJson: JSON.stringify(args) });
  }
  return out;
}

export type ArgsTransformFn = (argumentsJson: string) => Promise<string | null>;

export interface TransformScriptCellOptions {
  /** What to do with an exec call whose arguments are not one JSON object
   *  literal: `block` replaces the whole cell by the sentinel cell (the exec
   *  gate is active — fail closed); `keep` leaves the cell untouched (no gate,
   *  path-map only — its rule 3). */
  unparseable: "block" | "keep";
  log?: (msg: string) => void;
  /**
   * The whole-cell gate (plan 10 §11.13, path (a)): asked, while the exec gate
   * is active (`unparseable: "block"`), about every cell whose calls the
   * allow-list grammar cannot ALL identify (mcp-cell.ts cellCallsIdentified)
   * — such a cell may run an exec the literal scanner never sees
   * (`tools["exec_command"]`, an alias, an escape). Answers a block reason, or
   * null to let the cell through to the per-literal gate. Never throws (the
   * caller fails closed inside).
   */
  cellGate?: (src: string) => Promise<string | null>;
  /** The request's `exec` tool says each cell is a fresh isolate (mcp-cell.ts
   *  cellsAreIsolated). Without it no cell counts as identified: an earlier
   *  cell could have redefined what a call runs. */
  cellsIsolated?: boolean;
  /** Told the notice the sentinel cell prints whenever the WHOLE cell is
   *  replaced by it (plan 10 §11.8, the !545 leftover): the caller keeps it
   *  by the cell's call id, so the cell's output reaches the model as the
   *  notice instead of one masked symbol. Never throws into the gate. */
  onCellBlocked?: (notice: string) => void;
}

/** The sentinel cell: runs the block sentinel through the same tool so the
 *  model reads the reason as the command's own failure. */
export function blockSentinelCell(reason: string): string {
  const args = JSON.stringify({ cmd: blockSentinelCommand(reason), yield_time_ms: 10000, max_output_tokens: 2000 });
  return `const r = await tools.exec_command(${args});\ntext(r.output);\n`;
}

/** Replace the whole cell by the sentinel cell, and tell the caller the
 *  notice it prints (`onCellBlocked`). */
function blockWhole(reason: string, opts: TransformScriptCellOptions): string {
  try {
    opts.onCellBlocked?.(blockNoticeText(reason));
  } catch { /* a record only: the cell is blocked either way */ }
  return blockSentinelCell(reason);
}

/**
 * Apply `transform` to every exec_command literal of a cell and splice the
 * rewritten literals back into the source. Returns the new source, or null
 * when nothing changed (the caller re-emits the original bytes). Never
 * throws: a transform that throws counts as "unchanged" for that literal (the
 * exec gate itself never throws — it fails closed inside).
 */
export async function transformScriptCell(
  js: string,
  transform: ArgsTransformFn,
  opts: TransformScriptCellOptions,
): Promise<string | null> {
  if (typeof js !== "string" || js === "") return null;
  // A cell whose calls are not all identified is gated as a whole first: the
  // regex count below cannot under-count an exec it was never shown.
  if (opts.unparseable === "block" && opts.cellGate && !(opts.cellsIsolated === true && cellCallsIdentified(js))) {
    let reason: string | null;
    try {
      reason = await opts.cellGate(js);
    } catch (err) {
      reason = `the cell could not be checked (${(err as Error).message}) — fail closed`;
    }
    if (reason !== null) {
      opts.log?.(`script-cell: BLOCKED a cell whose calls are not all identified (${reason}); cell: ${JSON.stringify(js.slice(0, 400))}`);
      return blockWhole(reason, opts);
    }
  } else if (opts.unparseable === "block" && opts.cellGate) {
    // An identified cell's MCP calls whose arguments carry a command (an MCP
    // `run_command` in a cell) go through the same gate as a shell command,
    // field by field; a block, or a field the gate cannot read, replaces the
    // whole cell (plan 10 §11.13, MCP command tools).
    const parsed = parseCell(js);
    const mcpCommands = "calls" in parsed ? parsed.calls.filter((c) => c.name.startsWith("mcp__")).flatMap((c) => commandLikeFields(c.args)) : [];
    for (const f of mcpCommands) {
      let reason: string | null;
      try {
        reason = f.text === null ? `the ${f.key} field is not a command the gate can read — fail closed` : await opts.cellGate(f.text);
      } catch (err) {
        reason = `the command could not be checked (${(err as Error).message}) — fail closed`;
      }
      if (reason !== null) {
        opts.log?.(`script-cell: BLOCKED a cell whose MCP call carries a blocked command (${reason})`);
        return blockWhole(reason, opts);
      }
    }
  }
  const calls = findScriptCalls(js).filter((c) => SCRIPT_EXEC_FUNCTIONS.has(c.name));
  // Fail closed on an exec call the literal scanner could not pin down: an
  // exec function called with a non-literal argument, or a literal that is
  // not JSON. Counted BEFORE any splice so the decision covers the whole cell.
  const execCallCount = (js.match(/\btools\s*\.\s*(?:exec_command)\s*\(/g) ?? []).length;
  const unparseable = execCallCount > calls.length || calls.some((c) => parseLiteral(c.argsJson) === null);
  if (unparseable) {
    if (opts.unparseable === "keep") return null;
    const reason = "the exec cell passes its command as something other than one object literal, which the gate cannot inspect";
    // the cell is the model's own decision (never untrusted data): its head
    // goes to the privileged log so an over-strict grammar can be seen
    opts.log?.(`script-cell: BLOCKED a cell with non-literal exec arguments (${reason}); cell: ${JSON.stringify(js.slice(0, 400))}`);
    return blockWhole(reason, opts);
  }
  let out = "";
  let cursor = 0;
  let changed = false;
  for (const c of calls) {
    // the transform (exec gate, view map) reads JSON: a hand-written
    // JavaScript literal is normalized first; an unchanged literal keeps the
    // model's own spelling on the wire
    const json = JSON.stringify(parseLiteral(c.argsJson));
    let rewritten: string | null = null;
    try {
      rewritten = await transform(json);
    } catch {
      rewritten = null;
    }
    out += js.slice(cursor, c.start) + (rewritten ?? c.argsJson);
    cursor = c.end;
    if (rewritten !== null) changed = true;
  }
  out += js.slice(cursor);
  return changed ? out : null;
}
