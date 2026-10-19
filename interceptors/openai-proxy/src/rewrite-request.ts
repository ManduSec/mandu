/**
 * rewrite-request — the security-critical agent→model request transform for the
 * OpenAI Responses API (the Codex CLI's wire format).
 *
 * Mandu Track A (interceptors/openai-proxy). This is the AgentView context
 * boundary (mandu.md §1, §3): every tool output re-entering T-LLM's context is
 * classified by the arbiter's data-trust policy and, when UNTRUSTED, REPLACED by
 * an opaque $MDU:* token before the request is forwarded upstream. The
 * handling system prompt is prepended to `instructions` so T-LLM treats symbols
 * as opaque.
 *
 * Responses-API specifics (mirrors anthropic-proxy/src/rewrite-request.ts, adapted to
 * the OpenAI wire format):
 *   1. Caller has JSON.parsed the body into a ResponsesRequest.
 *   2. Build a correlation map call_id → {name, arguments} from `function_call`
 *      items in `input[]`.
 *   3. For every `function_call_output` item: look up its originating
 *      {name, arguments}; classify(boundary="model_context", tool=name); if
 *      UNTRUSTED, symbolize and replace the item's `output` with the symbol token.
 *      The `origin` hint is the shell command recovered from the function_call's
 *      `arguments.cmd` (Codex exec_command), if present.
 *   4. Prepend the handling system prompt to `instructions`.
 *
 * FAIL-CLOSED (critical, mandu.md invariant / CONTRIBUTING.md): if the arbiter is
 * unreachable, or classify/symbolize/handlingPrompt throws, we MUST NOT forward
 * un-symbolized untrusted content. The rewrite REJECTS (throws RewriteRefusal),
 * and the server turns that into a 502 — never a passthrough.
 *
 * Note: Codex's shell tool is `exec_command`. Unknown / unmapped tool names
 * classify UNTRUSTED under the arbiter's fail-closed default, so the command
 * output is symbolized regardless.
 *
 * The SCRIPT-CELL wire (codex ≥ 0.154, responses-types.ts header): the
 * originating call is a `custom_tool_call` whose JavaScript `input` carries
 * the command as a `tools.exec_command({…})` literal (script-cell.ts), and
 * the result is a `custom_tool_call_output` whose `output` is an ARRAY of
 * text parts. Both are walked exactly like their function_call twins: the
 * correlation map reads the literal, the parts are joined into ONE value,
 * classified and symbolized as one datum, and written back as ONE text part.
 * Found 2026-09-24: until then every 0.154 shell result rode into the model
 * raw — the walk only knew `function_call_output`.
 */

import type { Arbiter, CallTaintWire, HandlingPromptCapabilities, McpServerTaintWire } from "./arbiter-client.js";
import {
  type ResponsesRequest,
  type InputItem,
  type ToolOutputItem,
  advertisedTools,
  isCustomToolCallItem,
  isCustomToolCallOutputItem,
  isFunctionCallItem,
  isFunctionCallOutputItem,
  isToolOutputItem,
} from "./responses-types.js";
import { scriptCellArgs } from "./script-cell.js";
import { CODE_MODE_TOOL, cellCallsIdentified, cellsAreIsolated, exactExecCall, qualifyMcpCell } from "./mcp-cell.js";
import { cellResourceTools, type CellResourceTools } from "./cell-resource-tools.js";
import { splitGuardedCell, writtenToolNames } from "./cell-guard.js";
import { commandLikeText, stricterLevel } from "./unmapped-exec.js";
import { AFTER_THE_FACT_MARKER, AFTER_THE_FACT_SYSTEM_NOTE, afterTheFactLine, type ClearResultLedger } from "./after-the-fact.js";
import { applyPromptFilter, PromptBlocked, PromptFilterRefusal, PromptHoldAbandoned, type PromptBlockLedger, type PromptFilterReport, type SegmentAgent } from "./prompt-filter.js";
import { extractUserShells, restoreUserShells, userShellTexts, type ExtractedUserShell } from "./user-shell.js";

/** A correlated originating function_call for a function_call_output. */
interface ToolCallRef {
  name: string;
  /** Parsed arguments object (best-effort), e.g. { cmd: "cat notes.md" }. */
  args: Record<string, unknown>;
  /** How the process leg asks about the call when not by its name (plan 10
   *  §11.12, §11.13): `unmapped` = a script cell the proxy could not read,
   *  asked as `unmappedTool` whatever its name; `none` = a cell that runs no
   *  process (a bare `ALL_TOOLS` listing). Absent = by the name, as before. */
  taint?: "unmapped" | "none";
  /** Also ask the session (`unmappedTool: "exec"`, no command) and fold the
   *  answer in, raise-only: a cell whose exec calls the grammar could not all
   *  identify, so the first literal's tree is not the whole story (§11.13,
   *  path (a)). */
  foldSession?: boolean;
  /** The Codex MCP resource tools a cell the grammar does not identify may
   *  call (cell-resource-tools.ts; plan 10 §11.18): each is asked about as its
   *  direct call is, raise-only. */
  resourceTools?: CellResourceTools;
  /** The call whose process leg this output belongs to, when not its own: a
   *  `wait` continues a yielded cell (§11.13, path (b)). */
  taintVia?: { name: string; args: Record<string, unknown>; callId: string; taint?: "unmapped" | "none"; foldSession?: boolean; resourceTools?: CellResourceTools };
  /** Never apply the denied-only or twin releases to this output. */
  raiseOnly?: boolean;
}

/**
 * Thrown when the rewrite cannot complete safely (arbiter error / unreachable).
 * The server maps this to a 502 so untrusted bytes never leak upstream.
 */
export class RewriteRefusal extends Error {
  constructor(
    message: string,
    /** The underlying cause, for logging. */
    public readonly cause?: unknown,
  ) {
    super(message);
    this.name = "RewriteRefusal";
  }
}

/**
 * The prompt filter's policy BLOCKS this request (confidentiality-plan-15 §7):
 * a RewriteRefusal (anything that catches that still refuses), which the
 * server answers with a 400 carrying `message`, the arbiter's reason (the
 * categories found, never a value), so the agent shows it and does not
 * retry. `report` feeds the `prompt_filter` events.
 */
export class RewriteBlocked extends RewriteRefusal {
  constructor(message: string, public readonly report: PromptFilterReport) {
    super(message);
    this.name = "RewriteBlocked";
  }
}

/**
 * The agent disconnected while its prompt was held for the human's answer
 * (confidentiality-plan-15 §13.6 item 13): a RewriteRefusal (anything that
 * catches that still refuses), which the server answers with nothing, since
 * nobody is there to read it. Nothing of the request was forwarded.
 */
export class RewriteAbandoned extends RewriteRefusal {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "RewriteAbandoned";
  }
}

export interface RewriteOptions {
  /** Arbiter handle (real adapter or mock). */
  arbiter: Arbiter;
  /** Confidentiality plan 15 §7: the blocked prompt spans this proxy
   *  already refused once (absent: every block refuses). */
  promptBlockLedger?: PromptBlockLedger;
  /** The agent's connection (plan 15 §13.6 item 13): aborted when it closes,
   *  which ends a prompt hold's wait (RewriteAbandoned, nothing forwarded). */
  signal?: AbortSignal;
  /** The exec gate's block notices this proxy delivered, by call id
   *  (exec-gate.ts ExecGateNotices; confidentiality plan 10 §11.8). An output
   *  that is EXACTLY its call's sentinel output is forwarded as the notice,
   *  in clear (gateNoticeOutput). Absent ⇒ every output is classified.
   *  `wholeCell` says the call's whole code-mode cell was replaced by the
   *  sentinel cell (its output then carries the script runtime's head). */
  execGateNotices?: { noticeFor(callId: string): string | undefined; wholeCell?(callId: string): boolean };
  /** The unmapped upload leg's notices by call id (unmapped-upload.ts
   *  UploadNotices): a function_call whose local path(s) the leg withheld
   *  reached nothing the model asked for, so its output is REPLACED by the
   *  notice (the anthropic-proxy's ResultNotices), when the value backstop
   *  finds no registered value in it. Absent ⇒ every output is classified. */
  uploadNotices?: { noticeFor(callId: string): string | undefined };

  /**
   * Translate an origin from the AGENT's spelling into HumanView (Plan 9).
   *
   * Codex's origin is the recovered SHELL COMMAND, and under a view map that
   * command names AgentView paths (the agent runs in the twin). Every path policy
   * the arbiter owns — the catalog, the user labels, the derived labels — is keyed
   * in HumanView, so without this a LABELED file classifies `public` and the label
   * is written but never read. Sent as `originHuman`, which ONLY the
   * confidentiality derivation consumes: trust keeps seeing `origin`/`params`
   * byte-identically, so a spelling translation can never move a datum from
   * UNTRUSTED to TRUSTED. Absent (no view map) ⇒ the requests are unchanged.
   */
  toHumanView?: (origin: string) => string;
  /** Optional session key threaded into symbolize. */
  sessionKey?: string;
  /** Optional handling-prompt mode. */
  handlingMode?: string;
  /** The session's secret posture (src/secret-posture.ts), reported as
   *  `capabilities.secretPosture` on the handling-prompt request. Absent ⇒
   *  nothing reported: byte-identical. */
  secretPosture?: string;
  /** If true, skip the handling-prompt injection. */
  skipPromptInjection?: boolean;
  /** The call ids whose output body this proxy forwarded in clear
   *  (after-the-fact.ts; confidentiality.md §7.1, "Masked after the fact").
   *  An output masked as a secret now whose id is here gets the `masked after
   *  the fact` note; the ids this rewrite forwards in clear are added once it
   *  completes (and recorded with the arbiter, which `prime` asks first, so
   *  a history resumed under a new launch gets its note too). Absent ⇒ no
   *  note, nothing remembered (byte-identical). */
  clearResults?: Pick<ClearResultLedger, "wasClear" | "remember"> & Partial<Pick<ClearResultLedger, "prime">>;
  /** Logger for the fail-closed branches (a failed callTaint), off the wire. */
  log?: (msg: string) => void;
  /** Whose segmenter rules cut the user text for the prompt filter
   *  (prompt-filter.ts segmentAgentFor; default Codex, the Responses route's). */
  promptAgent?: SegmentAgent;
}

/**
 * Per-function_call_output audit record (for logging + the §9 oracle).
 *
 * SECURITY: `value` is the RAW untrusted content. It is consumed ONLY on the
 * privileged side (logging); it MUST NOT be written back into the forwarded
 * request. The forwarded request carries the `symbol` only.
 */
export interface RewriteAudit {
  callId: string;
  tool: string;
  trust: "TRUSTED" | "UNTRUSTED";
  symbolized: boolean;
  symbol?: string;
  /** The raw function_call_output content (original untrusted bytes). */
  value: string;
  /** Correlated origin hint (the shell command), if recoverable. */
  origin?: string;
  /** Arbiter classify reason. */
  reason?: string;
  /** Confidentiality level the classify verdict carried (confidentiality.md
   *  §2). Present only when the datum is secret-labeled — the reason a
   *  TRUSTED result can still be symbolized. */
  confidentiality?: string;
  /** Partial symbolization (the codex exec envelope split, 2026-09-05): the
   *  span that became the symbol — the command's output AFTER codex's
   *  `Output:` header — and what was actually forwarded (header + symbol). */
  symbolizedSpan?: string;
  forwardedText?: string;
  /** The TRUSTED piece a split result forwards verbatim beside its symbol
   *  (the vouched body, the kept reminder tail, codex's exec or MCP header).
   *  The §9 own-block check removes it before looking for the raw span: a
   *  short span that also occurs in it (a "9" in "Wall time: 0.9 seconds")
   *  is coincidence, not survival (events.ts survivingResult). */
  keptVerbatim?: string;
  /** Plan 10 §4.2: the process-tree taint behind a shell result (the files,
   *  the programs, the rule, whether the whole result was masked). */
  secretTaint?: SecretTaintInfo;
  /** backstop-value-only.md: the output went as the arbiter's value-only
   *  release; each replaced registered value and its symbol (the §9
   *  oracle's must-not-survive spans; a symbolize event each). */
  valueOnly?: Array<{ symbol: string; value: string }>;
  /** The `[mandu:secret]` note appended after the forwarded text (§11.8). */
  secretNote?: string;
  /** The note carries the `masked after the fact` line (confidentiality.md
   *  §7.1): the request's instructions then also carry Mandu's note. */
  afterTheFact?: boolean;
}

/**
 * Split codex's LEADING exec_command output header off the command's bytes.
 * Codex's runtime writes `Chunk ID: … / Wall time: … / Process exited with
 * code N / Original token count: N / Output:` BEFORE the output; the
 * arbiter trusts exactly that header (claude-code-inbound.ts
 * isCodexExecEnvelope — digits/hex-only), and the bytes after `Output:` are
 * still symbolized whole. The script-cell wire (codex ≥ 0.154) writes
 * `Script completed / Wall time N seconds / Output:` instead — a fixed word
 * from a closed set plus digits, the same channel width. Returns null when the value does not start with
 * the header or carries nothing after it (then the whole value IS the
 * header and the ordinary classify already passes it). A forged header
 * inside the output lands after the real one and stays in the body. The
 * grammar is duplicated here (not imported: the proxy never imports the
 * arbiter package — CONTRIBUTING.md arbiter-client pattern) and the ARBITER's
 * verdict on the split-off header is what forwards it, never this regex.
 */
/**
 * Codex's MCP call result (codex 0.154, read off the wire 2026-09-25): a
 * function_call_output whose `output` is `[{input_text "Wall time: N
 * seconds\nOutput:"}, {input_text <the tool's own text>}, …]`. The first part
 * is the runtime's digits-only header; the rest is what the MCP server
 * returned. Split them so the tool's text is classified ON ITS OWN BYTES under
 * the tool's name (the header glued in front would fail any shape rule, e.g.
 * the Mandu policy tools' envelope). The ARBITER vouches for the header
 * (claude-code-inbound.ts, the MCP header alternative of the codex envelope
 * rule), never this regex.
 *
 * A result that carries `structuredContent` (inspect-mcp's success result)
 * comes as ONE STRING instead: `Wall time: N seconds\nOutput:\n<the
 * structuredContent JSON>` (raw wire of a live codex exec, 2026-09-26). The
 * same split applies; `form` says how to write the item back, and the byte
 * between header and body is the fixed "\n". Before this, every inspect
 * answer on Codex fell through to whole-value symbolization: fail-closed,
 * but the model got an opaque token hiding its own result_symbol.
 */
const CODEX_MCP_HEADER_RE = /^Wall time: \d+(?:\.\d+)? seconds\nOutput:$/;
const CODEX_MCP_STRING_RE = /^(Wall time: \d+(?:\.\d+)? seconds\nOutput:)\n([\s\S]*)$/;

export function splitCodexMcpOutput(output: unknown): { header: string; body: string; form: "parts" | "string" } | null {
  if (typeof output === "string") {
    const m = CODEX_MCP_STRING_RE.exec(output);
    return m ? { header: m[1]!, body: m[2]!, form: "string" } : null;
  }
  if (!Array.isArray(output) || output.length < 2 || !output.every(isInputTextPart)) return null;
  const [first, ...rest] = output as Array<{ type: "input_text"; text: string }>;
  if (!CODEX_MCP_HEADER_RE.test(first!.text)) return null;
  return { header: first!.text, body: rest.map((p) => p.text).join(""), form: "parts" };
}

const CODEX_EXEC_ENVELOPE_LEADING_RE =
  /^((?:Chunk ID: [0-9a-f]{1,32}\n(?:Wall time: \d+(?:\.\d+)? seconds\n)?Process exited with code \d+\n(?:Original token count: \d+\n)?|Script (?:completed|failed|running|yielded|timed out|interrupted|killed)(?: \(exit code \d+\))?\n(?:Wall time \d+(?:\.\d+)? seconds\n)?(?:Process exited with code \d+\n)?(?:Original token count: \d+\n)?)Output:\n)([\s\S]*)$/;

/**
 * Plan 10 §11.14: is the flattened `fco.output` Codex's own whole output for
 * a call Codex made, so that any head at its start is the one Codex's
 * runtime wrote? True for a known call that is not an MCP tool (an MCP
 * result is the server's text behind the MCP header) whose output is Codex's
 * text (a string, or the script-cell wire's `input_text` parts; a structured
 * output is JSON-inlined and starts with no head). The arbiter, not this
 * predicate, decides whether the value starts with a head: it matches its
 * own exact grammar at offset 0.
 */
/** The write tools whose whole result leads with the agent's fixed success
 *  notice (plan 15 §13.10; the arbiter's agent-result-head.ts
 *  WRITE_NOTICE_TOOLS, mirrored). */
export const WRITE_NOTICE_RESULT_TOOLS: ReadonlySet<string> = new Set(["Write", "write"]);

export function codexWholeOutput(fco: ToolOutputItem, knownCall: boolean, toolName: string): boolean {
  if (!knownCall || toolName.startsWith("mcp__")) return false;
  if (typeof fco.output === "string") return true;
  return Array.isArray(fco.output) && fco.output.length > 0 && fco.output.every(isInputTextPart);
}

/**
 * Plan 10 §11.14 (2026-10-09): which runtime head the WHOLE flattened
 * `fco.output` starts with, as the `symbolize` request names it, or null.
 * `codex` for Codex's own output of a call it made (`codexWholeOutput`);
 * `codex-mcp` for a known MCP call whose output has Codex's MCP shape
 * (`splitCodexMcpOutput`: the runtime's `Wall time: N seconds\nOutput:`
 * part or line first, the server's text after it). The arbiter matches the
 * named kind's own grammar at offset 0 either way. `write-notice` (plan 15
 * §13.10, 2026-10-11) for the whole text output of an agent's `write` tool
 * (OpenCode's or Goose's on this wire; Codex has none): it leads with the
 * agent's fixed success notice, which the arbiter matches for the row's own
 * path.
 */
export function codexResultHeadKind(fco: ToolOutputItem, knownCall: boolean, toolName: string): "codex" | "codex-mcp" | "write-notice" | null {
  if (WRITE_NOTICE_RESULT_TOOLS.has(toolName)) return codexWholeOutput(fco, knownCall, toolName) ? "write-notice" : null;
  if (codexWholeOutput(fco, knownCall, toolName)) return "codex";
  if (knownCall && toolName.startsWith("mcp__") && fco.type === "function_call_output" && splitCodexMcpOutput(fco.output) !== null) return "codex-mcp";
  return null;
}

export function splitCodexExecEnvelope(value: string): { envelope: string; body: string } | null {
  const m = CODEX_EXEC_ENVELOPE_LEADING_RE.exec(value);
  if (!m) return null;
  const body = m[2]!;
  if (body.trim() === "") return null;
  return { envelope: m[1]!, body };
}

/**
 * Plan 13 §9 R4: the runtime header kept beside a SECRET result's symbol
 * says nothing about how the run went. The code that held the secret chose
 * its exit code, its output's length and its running time, and the header
 * carries each verbatim (`Process exited with code N`, `Script failed (exit
 * code N)`, `Original token count: N`, `Wall time: N seconds`): a few bits a
 * call. The masked form reads exit code 0, status `completed`, wall time 0
 * and no token count, the twin of the Claude proxy's `is_error: false`. A
 * script cell still `running` or `yielded` keeps that word (whether the run
 * is still going is the timing bit plan 13 §4.9 leaves; without it the model
 * would never collect the rest). The chunk id (a random handle) is kept. The
 * result still matches the header grammar the arbiter vouches for.
 */
export function blankRunFacts(header: string): string {
  return header
    .replace(/^Wall time: \d+(?:\.\d+)? seconds$/m, "Wall time: 0 seconds")
    .replace(/^Wall time \d+(?:\.\d+)? seconds$/m, "Wall time 0 seconds")
    .replace(/^Process exited with code \d+$/m, "Process exited with code 0")
    .replace(/^Original token count: \d+\n/m, "")
    .replace(/^Script (completed|failed|timed out|interrupted|killed)(?: \(exit code \d+\))?$/m, "Script completed")
    .replace(/^Script (running|yielded) \(exit code \d+\)$/m, "Script $1");
}

/**
 * The exec gate's own notice (confidentiality plan 10 §11.8; exec-gate.ts
 * ExecGateNotices): what to forward for a gated call's output, or null when
 * the output is not exactly the sentinel's. Two shapes match, each whole:
 *   - Codex's exec envelope (`splitCodexExecEnvelope`'s grammar) saying exit
 *     77, followed by exactly the notice (trailing whitespace ignored);
 *   - an MCP result (`splitCodexMcpOutput`) whose body is exactly the notice.
 * The header is forwarded as plan 13 §9 R4 forwards a masked result's header
 * (`blankRunFacts`: exit code 0, wall time 0, no token count, the chunk id
 * kept), and the text after it is the proxy's own `notice`, never the
 * received bytes. Anything else (a program's byte before, after or inside the
 * notice, another exit status) returns null: the output takes the classify
 * path whole.
 *
 * A third (the !545 leftover, 2026-10-09): a code-mode cell the proxy
 * replaced WHOLE by the sentinel cell (`wholeCell`, ExecGateNotices) runs
 * nothing but the sentinel and prints its output (`text(r.output)`), so the
 * script runtime's head says the script itself `completed`, with no exit 77.
 * For such a cell only, a `custom_tool_call_output` whose script head is
 * followed by exactly the notice (or by the sentinel's own exec head saying
 * 77 and then exactly the notice) matches; the forwarded text is still the
 * R4-blanked script head and the proxy's own notice.
 */
export function gateNoticeOutput(
  fco: ToolOutputItem,
  toolName: string,
  notice: string,
  wholeCell = false,
): { output: ToolOutputItem["output"]; text: string } | null {
  if (toolName.startsWith("mcp__") && fco.type === "function_call_output") {
    const mcp = splitCodexMcpOutput(fco.output);
    if (!mcp || mcp.body.replace(/\s+$/, "") !== notice) return null;
    const header = blankRunFacts(mcp.header);
    return mcp.form === "string"
      ? { output: `${header}\n${notice}` as never, text: `${header}\n${notice}` }
      : { output: [{ type: "input_text", text: header }, { type: "input_text", text: notice }] as never, text: `${header}${notice}` };
  }
  if (typeof fco.output !== "string" && !(Array.isArray(fco.output) && fco.output.every(isInputTextPart))) return null;
  const split = splitCodexExecEnvelope(flattenOutput(fco.output));
  if (!split) return null;
  const exit77 = (head: string): boolean => /^Process exited with code 77$/m.test(head) || /\(exit code 77\)$/m.test(head);
  let body = split.body;
  let ok = exit77(split.envelope);
  if (!ok && wholeCell && fco.type === "custom_tool_call_output" && split.envelope.startsWith("Script ")) {
    const inner = splitCodexExecEnvelope(body);
    if (inner && !inner.envelope.startsWith("Script ") && exit77(inner.envelope)) body = inner.body;
    ok = true;
  }
  if (!ok || body.replace(/\s+$/, "") !== notice) return null;
  const text = `${blankRunFacts(split.envelope)}${notice}`;
  const shaped: ToolOutputItem = { ...fco };
  setOutput(shaped, text);
  return { output: shaped.output, text };
}

export interface RewriteResult {
  /** The rewritten request, safe to forward upstream. */
  request: ResponsesRequest;
  /** Per-function_call_output audit records (for logging / the oracle). */
  rewrites: RewriteAudit[];
  /** What the prompt filter did to the user-role text (confidentiality-plan-15
   *  §3, the `prompt_filter` events); absent when it had nothing to filter. */
  promptFilter?: PromptFilterReport;
}

/** Codex's shell tool name; used when a function_call_output has no matching
 * function_call (an attacker could forge one with no originating call). */
const DEFAULT_TOOL = "exec_command";

/**
 * Recover the origin hint (the shell command) from a function_call's parsed
 * arguments. Codex `exec_command` carries `{cmd: string}`; we also try common
 * alternates so the proxy is robust to tool-name / param drift. Unknown shape →
 * undefined (the arbiter fails closed → UNTRUSTED → symbolize regardless).
 */
export function originFor(args: Record<string, unknown>): string | undefined {
  const s = (k: string): string | undefined =>
    typeof args[k] === "string" ? (args[k] as string) : undefined;
  return s("cmd") ?? s("command") ?? s("path") ?? s("file_path") ?? s("url") ?? undefined;
}

/** Best-effort parse of a function_call's JSON-encoded `arguments` string. */
function parseArgs(arguments_: unknown): Record<string, unknown> {
  if (arguments_ == null) return {};
  if (typeof arguments_ === "object") return arguments_ as Record<string, unknown>;
  if (typeof arguments_ !== "string") return {};
  try {
    const o = JSON.parse(arguments_);
    return o && typeof o === "object" ? (o as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/**
 * Build the correlation map call_id → {name, args} from `function_call` items in
 * `input[]` (and the script cells, `custom_tool_call`).
 *
 * `isolatedCells`: the request's own `exec` tool says each cell runs in a fresh
 * isolate (mcp-cell.ts cellsAreIsolated). Only then may a cell that is nothing
 * but one literal MCP call be named as that tool (plan 10 §11.13). Default
 * false: every such cell keeps the fail-closed handling.
 */
/** Codex's own default namespace (codex-cli ≥ 0.154 code mode: `exec`,
 *  `wait`, the user questions): a call in it is the tool by its own name. */
export const CODEX_DEFAULT_NAMESPACE = "functions";

/** A function_call in a namespace other than codex's default one (an MCP
 *  server's `mcp__<server>`, codex 0.160's `clock`, `collaboration`): named
 *  `<namespace>__<name>`. */
function isNamespaced(item: { namespace?: unknown }): boolean {
  return typeof item.namespace === "string" && item.namespace !== "" && item.namespace !== CODEX_DEFAULT_NAMESPACE;
}

/** The name a function_call goes by for the arbiter and Mandu's tables:
 *  `<namespace>__<name>` in a namespace other than codex's default one,
 *  else its own name (the request side's correlation and the response
 *  side's upload leg read a call alike). Pure. */
export function codexToolName(name: string, namespace: unknown): string {
  return isNamespaced({ namespace }) ? `${namespace as string}__${name}` : name;
}

export function buildCorrelationMap(input: InputItem[], opts: { isolatedCells?: boolean } = {}): Map<string, ToolCallRef> {
  const map = new Map<string, ToolCallRef>();
  for (const item of input) {
    if (isFunctionCallItem(item)) {
      // A Codex MCP tool call carries its server as `namespace`
      // (`mcp__mandu_policy`) and the tool's own name as `name`; the
      // arbiter's exact-name trust rules key on the two joined with "__"
      // (policy-tool.ts / inspect-tool.ts, the Codex spelling). A bare `name`
      // would read as an unrelated tool (and the policy rule refuses bare names).
      // Codex's own default namespace (`functions`: `exec`'s `wait`, the
      // user questions) names the tool itself, as codex runs it (codex-cli
      // 0.160 runs `{namespace: "functions", name: "wait"}` as `wait`).
      const name = codexToolName(item.name, item.namespace);
      map.set(item.call_id, { name, args: parseArgs(item.arguments) });
    } else if (isCustomToolCallItem(item)) {
      // Plan 10 §11.18 (2026-10-11): a code cell the allow-list grammar does
      // not identify call by call may call codex's MCP resource tools (codex
      // 0.162 declares them in every cell), whose direct call is masked
      // whole. Each one its source may call is asked about as the direct
      // call is (cell-resource-tools.ts), raise-only.
      // The cell guard (cell-guard.ts): a cell that starts with exactly the
      // proxy's guard, in an isolated cell, had every nested tool its keep
      // list leaves out switched off before its code ran; the text rule is
      // kept beside it for when the keep list no longer holds. A cell whose
      // code names `import` keeps the text rule only (an import would run
      // before the guard; codex 0.162 refuses every import).
      const guarded = opts.isolatedCells === true && item.name === CODE_MODE_TOOL ? splitGuardedCell(item.input) : null;
      const cellSrc = guarded ? guarded.body : item.input;
      const textRule = item.name !== "apply_patch" && typeof cellSrc === "string"
        && !(opts.isolatedCells === true && item.name === CODE_MODE_TOOL && cellCallsIdentified(cellSrc))
        ? cellResourceTools(cellSrc)
        : null;
      const guardKeep = guarded && !/(?<![A-Za-z0-9_$])import(?![A-Za-z0-9_$])/.test(guarded.body) ? guarded.keep : undefined;
      const resourceTools = guardKeep
        ? { ...(textRule ?? { tools: [], why: "" }), guardKeep }
        : textRule ?? undefined;
      const withResources = resourceTools ? { resourceTools } : {};
      // The script cell: the shell command is the `tools.exec_command({…})`
      // literal inside the JavaScript. Named by the function the cell CALLS
      // (exec_command), so every arbiter rule keyed on Codex's shell tool —
      // the exec-output trust rungs, the process taint, the symbol tag — applies
      // unchanged. A cell with no parseable exec literal keeps the custom
      // tool's own name and empty args (origin unknown ⇒ UNTRUSTED).
      const cell = typeof item.input === "string" ? scriptCellArgs(item.input) : null;
      if (cell) {
        // §11.13 path (a): named by its first literal, but that literal's tree
        // is the whole story only when the grammar identifies EVERY call of
        // the cell and finds just this one (in an isolated cell). Otherwise a
        // second exec (another literal, `tools["exec_command"]`, an alias) may
        // have run a reader: the session is folded in, raise-only.
        const exact = opts.isolatedCells === true && item.name === CODE_MODE_TOOL ? exactExecCall(item.input) : null;
        const identified = exact !== null && JSON.stringify(exact) === JSON.stringify(cell.args);
        map.set(item.call_id, { name: cell.name, args: cell.args, ...(identified ? {} : { foldSession: true }), ...withResources });
        continue;
      }
      // Plan 10 §11.13: a code-mode cell that is nothing but ONE literal call
      // to an MCP tool is that tool, named and argued exactly as the
      // namespaced function_call to it (`mcp__<server>__<tool>`, the literal
      // object), so it gets that call's verdict. A bare `ALL_TOOLS` listing
      // runs no process and names nothing: `exec` with no input and no taint
      // ask. Only under a fresh isolate per cell; anything else falls through.
      const qualified = opts.isolatedCells === true && item.name === CODE_MODE_TOOL ? qualifyMcpCell(item.input) : null;
      if (qualified?.kind === "mcp") {
        map.set(item.call_id, { name: qualified.name, args: qualified.args });
        continue;
      }
      if (qualified?.kind === "listing") {
        map.set(item.call_id, { name: item.name, args: {}, taint: "none" });
        continue;
      }
      // Any other freeform tool that is not a patch (codex `js_repl`, a
      // later one) carries CODE: kept as `code`, so the unmapped-command
      // backstop asks for its taint and the classify scan reads its strings
      // (plan 10 §11.11, §11.12). `apply_patch` keeps empty args.
      // A guarded cell's code is the model's own (the guard is the proxy's text).
      const code = typeof cellSrc === "string" && cellSrc.trim() !== "" && item.name !== "apply_patch" ? { code: cellSrc } : {};
      // A cell under an exec-shaped name (`exec`) with no exec literal is not
      // a shell the guard can tie to a tree by its text (the taint would be
      // looked up by the JavaScript's signature, which matches nothing): it is
      // asked as an unmapped tool, so the session backstop applies (§11.12;
      // the gap closed with §11.13). Raise-only.
      const unmapped = "code" in code && isExecShaped(item.name);
      map.set(item.call_id, { name: item.name, args: code, ...(unmapped ? { taint: "unmapped" as const } : {}), ...withResources });
    }
  }
  // §11.13 path (b): a yielded cell answers `Script running with cell ID <id>`
  // and its later output arrives through Codex's `wait({cell_id})`, which
  // carries no command. Each wait continues the cell that yielded that id:
  // the cell's process leg (its tree, its session fold) decides, and the
  // cell's arguments are read beside the wait's own by the classify scan. A
  // wait no cell in the request accounts for is asked as an unmapped tool
  // (the session decides). Raise-only: a wait never takes a release.
  const yielded = new Map<string, string>();
  for (const item of input) {
    if (!isCustomToolCallOutputItem(item)) continue;
    const m = YIELDED_CELL_RE.exec(flattenOutput(item.output));
    if (m) yielded.set(m[1]!, item.call_id);
  }
  for (const item of input) {
    if (!isFunctionCallItem(item) || item.name !== WAIT_TOOL || isNamespaced(item)) continue;
    const waitArgs = parseArgs(item.arguments);
    const cellCallId = typeof waitArgs["cell_id"] === "string" ? yielded.get(waitArgs["cell_id"] as string) : undefined;
    const cellRef = cellCallId !== undefined ? map.get(cellCallId) : undefined;
    if (cellRef && cellCallId !== undefined) {
      map.set(item.call_id, {
        name: WAIT_TOOL, args: { ...cellRef.args, ...waitArgs }, raiseOnly: true,
        taintVia: { name: cellRef.name, args: cellRef.args, callId: cellCallId, ...(cellRef.taint ? { taint: cellRef.taint } : {}), ...(cellRef.foldSession ? { foldSession: true } : {}), ...(cellRef.resourceTools ? { resourceTools: cellRef.resourceTools } : {}) },
      });
    } else {
      map.set(item.call_id, { name: WAIT_TOOL, args: waitArgs, taint: "unmapped", raiseOnly: true });
    }
  }
  // Plan 10 §11.12's poll (closed 2026-10-02): an `exec_command` still
  // running when it yields answers `Process running with session ID <n>` in
  // codex's result head (before `Output:`, so a command's own output cannot
  // claim one), and the process's later output arrives through
  // `write_stdin({session_id: n})`, which carries no command. Each poll
  // continues the ONE exec call that started session n: that call's process
  // leg decides (its tree also holds whatever `chars` typed into it). A poll
  // no exec call accounts for, or one two calls claim (a reused id), is asked
  // as an unmapped tool (the session decides). Raise-only, as a `wait`.
  const execSessions = new Map<string, string[]>();
  for (const item of input) {
    if (!isFunctionCallOutputItem(item)) continue;
    const ref = map.get(item.call_id);
    if (!ref || ref.name === WRITE_STDIN_TOOL || !isExecShaped(ref.name) || ref.taint !== undefined) continue;
    const sid = runningSessionId(flattenOutput(item.output));
    if (sid === null) continue;
    const owners = execSessions.get(sid) ?? [];
    if (!owners.includes(item.call_id)) owners.push(item.call_id);
    execSessions.set(sid, owners);
  }
  for (const item of input) {
    if (!isFunctionCallItem(item) || item.name !== WRITE_STDIN_TOOL || isNamespaced(item)) continue;
    const pollArgs = parseArgs(item.arguments);
    const sid = typeof pollArgs["session_id"] === "number" || typeof pollArgs["session_id"] === "string" ? String(pollArgs["session_id"]) : null;
    const owners = sid !== null ? execSessions.get(sid) ?? [] : [];
    const execCallId = owners.length === 1 ? owners[0]! : undefined;
    const execRef = execCallId !== undefined ? map.get(execCallId) : undefined;
    if (execRef && execCallId !== undefined) {
      map.set(item.call_id, {
        name: WRITE_STDIN_TOOL, args: { ...execRef.args, ...pollArgs }, raiseOnly: true,
        taintVia: { name: execRef.name, args: execRef.args, callId: execCallId, ...(execRef.foldSession ? { foldSession: true } : {}) },
      });
    } else {
      map.set(item.call_id, { name: WRITE_STDIN_TOOL, args: pollArgs, taint: "unmapped", raiseOnly: true });
    }
  }
  return map;
}

/** Codex's poll of (and input to) a process an `exec_command` left running
 *  (codex-cli 0.159.1 unified exec). */
const WRITE_STDIN_TOOL = "write_stdin";
/** The session line of codex's unified-exec result head (codex-rs
 *  `format_response`: `Chunk ID`, `Wall time`, then `Process exited with code
 *  <c>` or `Process running with session ID <n>`, `Original token count`,
 *  `Output:`). */
const RUNNING_SESSION_RE = /^Process running with session ID ([0-9]{1,20})$/m;

/** The session id an exec result's HEAD says is still running (only the text
 *  before the first `Output:` line is read), or null. */
export function runningSessionId(output: string): string | null {
  const at = output.search(/^Output:$/m);
  if (at < 0) return null;
  const m = RUNNING_SESSION_RE.exec(output.slice(0, at));
  return m ? m[1]! : null;
}

/** Codex's continuation of a yielded `exec` cell (codex-cli 0.159.1). */
const WAIT_TOOL = "wait";
/** The head a yielded cell's output starts with (read off the wire against a
 *  recording server, 2026-10-02: `Script running with cell ID 1\nWall time
 *  0.2 seconds\nOutput:\n`). */
const YIELDED_CELL_RE = /^Script running with cell ID ([A-Za-z0-9_-]{1,64})\n/;

/**
 * Flatten a function_call_output `output` into one string. It is normally a
 * string (the raw command stdout); defensively handle the structured-output
 * array/object variant by JSON-stringifying it (so we never silently forward
 * un-classified untrusted bytes hidden in a structured field).
 */
export function flattenOutput(output: ToolOutputItem["output"]): string {
  if (output == null) return "";
  if (typeof output === "string") return output;
  if (Array.isArray(output) && output.length > 0 && output.every(isInputTextPart)) {
    // The script-cell wire: an array of `input_text` parts, joined in order
    // (the envelope part, then the output — one datum). Any other array
    // shape takes the structured path below (JSON-inlined whole, so no byte
    // hides in a structured field).
    return output.map((part) => part.text).join("");
  }
  try {
    return JSON.stringify(output);
  } catch {
    return String(output);
  }
}

/**
 * Write the forwarded text back into a tool-output item in ITS wire's shape:
 * a function_call_output is always a string (a structured payload collapses
 * to the string, as before); a custom_tool_call_output ARRAY becomes exactly
 * one `input_text` part holding the forwarded text (the envelope + symbol,
 * the symbol alone, or the released value) — any attacker-structured parts
 * are dropped with it.
 */
export function setOutput(item: ToolOutputItem, text: string): void {
  if (item.type === "custom_tool_call_output" && Array.isArray(item.output)) item.output = [{ type: "input_text", text }];
  else item.output = text;
}

function isInputTextPart(part: unknown): part is { type: "input_text"; text: string } {
  const p = part as { type?: unknown; text?: unknown } | null;
  return !!p && typeof p === "object" && p.type === "input_text" && typeof p.text === "string";
}

/**
 * The handling system prompt prefix injected into `instructions` so T-LLM knows
 * symbols are opaque. Marked with a sentinel so we never double-inject across
 * multi-turn requests (Codex resends the full `instructions` each turn).
 */
export const HANDLING_MARKER = "[mandu:handling-prompt]";

/**
 * Shell/exec tool identifiers that mark the exec capability. Responses-API
 * function tools carry a flat `name` ({type:"function", name:"exec_command"});
 * built-in tools are identified by `type` alone ({type:"local_shell"}).
 */
const EXEC_TOOL_NAMES = new Set(["Bash", "exec", "exec_command", "shell", "shell_command", "local_shell"]);

/** Any server's inspect_symbol: bare or MCP-namespaced; suffix-anchored so
 * lookalikes (inspect_symbolizer) do not match. */
const INSPECT_TOOL_RE = /(^|__)inspect_symbol$/;
/** The mandu-policy MCP server's tools (policy-surface.md §8.5.1).
 *  Distinct from POLICY_TOOL_RE (the legacy policy_list/add/del tools). */
const MANDU_POLICY_TOOL_RE = /^(mcp__mandu-policy__|mandu-policy_|mcp__mandu_policy__)/;
/** Codex 0.154 defers MCP tools behind a client-executed `tool_search` tool,
 *  whose description lists the mounted servers ("- mandu-policy"); the
 *  tools themselves appear only after a search. That list is the one signal
 *  present on the FIRST request, so it is what reports the capability. */
const TOOL_SEARCH_SOURCE_RE = (server: string) => new RegExp(`^- ${server.replace(/-/g, "\\-")}\\s*$`, "m");

/** The Data-Trust-Policy mutation/list tools, bare or MCP-namespaced. */
const POLICY_TOOL_RE = /(^|__)(policy_list|policy_add|policy_del)$/;

/**
 * Derive tool-battery capability FACTS from the request's advertised tools
 * (`tools`, or the `additional_tools` item's namespaces on the script-cell
 * wire — responses-types.ts advertisedTools) so the arbiter can drop
 * handling-prompt sections about tools this request cannot call. A `custom`
 * tool named `exec` (the script cell) is the exec capability. Codex 0.154
 * defers MCP tools behind `tool_search`, so the Mandu servers are read off
 * its source list (TOOL_SEARCH_SOURCE_RE) until a search exposes them.
 *
 * UTILITY HINT, NOT A TRUST GATE (mirrors anthropic-proxy detectCapabilities):
 * over-matching costs prompt tokens, never security; the arbiter defaults
 * every UNREPORTED capability to present. Never throws: malformed entries are
 * skipped, a non-array reports all false (no tools => no tool calls).
 */
export function detectCapabilities(
  tools: unknown,
  facts: { /** the session's secret posture (src/secret-posture.ts) */ secretPosture?: string } = {},
): HandlingPromptCapabilities {
  const caps: HandlingPromptCapabilities = {
    inspect: false, policyTools: false, manduPolicy: false, exec: false,
    // Not a tool fact: the launcher's posture for this session, only when set.
    ...(facts.secretPosture ? { secretPosture: facts.secretPosture } : {}),
  };
  if (!Array.isArray(tools)) return caps;
  for (const t of tools) {
    if (!t || typeof t !== "object") continue;
    const rec = t as { name?: unknown; type?: unknown };
    // Function tools carry the identity in `name`; built-ins in `type`.
    const name =
      typeof rec.name === "string"
        ? rec.name
        : typeof rec.type === "string"
          ? rec.type
          : undefined;
    if (!name) continue;
    if (name === "tool_search" && typeof (rec as { description?: unknown }).description === "string") {
      const d = (rec as { description: string }).description;
      if (TOOL_SEARCH_SOURCE_RE("mandu-policy").test(d)) caps.manduPolicy = true;
      if (TOOL_SEARCH_SOURCE_RE("mandu-inspect").test(d)) caps.inspect = true;
      continue;
    }
    if (INSPECT_TOOL_RE.test(name)) caps.inspect = true;
    else if (POLICY_TOOL_RE.test(name)) caps.policyTools = true;
    else if (MANDU_POLICY_TOOL_RE.test(name)) caps.manduPolicy = true;
    else if (EXEC_TOOL_NAMES.has(name)) caps.exec = true;
  }
  return caps;
}

/**
 * A present, non-"public" confidentiality value means the datum is
 * secret-labeled (confidentiality.md §2). UNKNOWN strings count as secret —
 * fail-closed: a level minted by a newer arbiter must not pass raw here.
 * Absent means the arbiter's confidentiality axis is OFF or the datum is
 * public — either way, integrity alone governs (today's behavior).
 */
function isSecretLevel(level: string | undefined): boolean {
  return level !== undefined && level !== "" && level !== "public";
}

/** What plan 10's callTaint said about a call, reduced to what the rewrite needs. */
export interface SecretTaintInfo {
  level: string;
  files: string[];
  apps: string[];
  rule: "secret" | "clear" | "mask";
  /** The whole result becomes a secret datum at `level`. */
  maskWhole: boolean;
  /** Opens refused within the tree. */
  denied: Array<{ path: string; app: string; reason: string }>;
  /** The tree read NO secret, at least one open of one was refused, and the
   *  value backstop finds no registered value in the output: the classify
   *  verdict's path-derived mask (the command NAMES a secret file) is
   *  lowered, so the model reads the program's own failure text plus the
   *  denied/held note instead of a symbol (§11.8; drill S7, 2026-09-24). */
  deniedOnly: boolean;
  /** Plan 10 §11.8: the guard recorded the tree, nothing in it read a
   *  secret, the output is (part of) the structured twin of `twinOf`, and the
   *  value backstop is clean. The caller lowers the path-derived mask: the
   *  model reads the keys, each secret value a symbol. */
  twinOnly?: boolean;
  /** The file(s) whose structured twin the output is. */
  twinOf?: string[];
  /** Plan 10 §11.8, "A document's own twin": the output is exactly the
   *  file's WHOLE-FILE twin (its base symbol); the `twin:` line says so. */
  twinWhole?: boolean;
  /** Plan 10 §11.8, "A key listing": the output holds no token and
   *  is the keys of the file's structured twin, in order (`cut -d= -f1
   *  .env`); the `twin:` line says so. */
  twinKeys?: boolean;
  /** Plan 10 §11.13, "A config with no secret": the output holds no token
   *  and is a piece of the file's OWN-TEXT twin (Mandu found no secret in
   *  it); the `twin:` line says so. */
  twinOwn?: boolean;
  /** Plan 10 §11.8, "A folder's names": the output is exactly a plain `ls`
   *  of the folders in `twinOf` (names only); the `listing:` line says so. */
  dirListing?: boolean;
  /** folder-listing-compound.md: the listing is the FIRST or LAST lines of a
   *  compound's output, the rest the other commands'; `twinOf` then holds
   *  the operands as the model wrote them. */
  dirListingPart?: "first" | "last";
  /** Plan 10 §11.8, "Refused connections": connections the egress proxy
   *  refused from the call's tree (the program, the kind; never a host).
   *  Explains only: never lowers or raises a mask. */
  refusedEgress?: RefusedEgress[];
  /** Plan 10 §11.8, "Blocked commands": commands of the call's tree the
   *  exec-wrap shim refused before they ran (the program, the kind; never
   *  an argument). Explains only: never lowers or raises a mask. */
  blockedExec?: Array<{ app: string; kind: string }>;
  /** Confidentiality §7.1, "the path-derived note" (2026-10-05): the result
   *  is masked whole only because the command NAMES a secret path (the
   *  classify verdict), with no taint answer that masks it. `paths` are the
   *  path tokens as the model wrote them in its own command (never a byte of
   *  the output). Explains only. */
  pathDerived?: { paths: string[]; twins?: PathDerivedTwin[] };
  /** Confidentiality §7.1, "the value-backstop note" (2026-10-17): the
   *  result is masked whole only because the arbiter's value backstop found
   *  a registered secret's value in it (classify `raisedBy:
   *  "value-backstop"`), with no taint answer that masks it. Takes the
   *  path-derived note's place: the call names no secret path. Explains
   *  only. */
  valueBackstop?: true;
  why: string;
}

const SECRET_NOTE_MARKER = "[mandu:secret]";

/** The `listing:` line of a released folder listing (plan 10 §11.8, "A
 *  folder's names"): built from the arbiter's `twinOf` (the paths `ls`
 *  listed), never from the output. Byte-identical in both proxies. */
function dirListingLine(paths: readonly string[]): string {
  return `listing: these are the names in ${paths.join(", ")} as ls printed them, and nothing else: no file's content, size or date. The files there may still be secret: reading one shows you a symbol where its secret content is.`;
}

/** folder-listing-compound.md: the `listing:` line of a compound's listing
 *  part, naming the operands as the model wrote them (never a resolved
 *  path). Byte-identical in both proxies. */
function dirListingPartLine(operands: readonly string[], part: "first" | "last"): string {
  const where = part === "last" ? "the last lines of this output are" : "the first lines of this output are";
  const rest = part === "last" ? "The lines before them" : "The lines after them";
  return `listing: ${where} the names in ${operands.join(", ")} as ls printed them, no file's content, size or date. ${rest} are the other commands' output, which may describe any folder. The files there may still be secret: reading one shows you a symbol where its secret content is.`;
}

/** The path-derived note's line (confidentiality.md §7.1): built from the
 *  model's own command tokens only. Byte-identical in both proxies. */
function pathDerivedLine(paths: readonly string[], twins: readonly PathDerivedTwin[] = []): string {
  const named = paths.length === 0
    ? "a secret file"
    : paths.length === 1 ? `a secret file (${paths[0]})` : `secret files (${paths.join(", ")})`;
  const own = twins.map((t) => ` ${pathDerivedTwinSentence(t)}`).join("");
  return `masked: the command names ${named}, so its whole output is hidden from you, including whether it succeeded; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Everything else it printed is hidden with it: to read another file, a listing or a log, run that part again as a command of its own that names no secret file.${own} Do not assume it worked: if you still cannot tell, say you cannot see the result, or ask the user what it printed.`;
}

/** A named secret file's twin kind, as the arbiter answers it
 *  (`namedTwins`, arbiter named-twins.ts). */
export interface PathDerivedTwin {
  path: string;
  twin: "fields" | "lines" | "whole" | "text";
}

const PATH_DERIVED_TWIN_KINDS: ReadonlySet<string> = new Set(["fields", "lines", "whole", "text"]);

/** The arbiter's `namedTwins` the note may use: an entry whose token the
 *  note itself names (`paths`, the model's own spelling) and whose kind is
 *  one this proxy words. Anything else is dropped: no sentence is better
 *  than a wrong one. Pure. Byte-identical in both proxies. */
export function pathDerivedTwins(namedTwins: unknown, paths: readonly string[]): PathDerivedTwin[] {
  if (!Array.isArray(namedTwins)) return [];
  const out: PathDerivedTwin[] = [];
  for (const t of namedTwins as unknown[]) {
    if (t === null || typeof t !== "object") continue;
    const { path, twin } = t as { path?: unknown; twin?: unknown };
    if (typeof path !== "string" || typeof twin !== "string" || !paths.includes(path) || !PATH_DERIVED_TWIN_KINDS.has(twin)) continue;
    if (out.some((o) => o.path === path)) continue;
    out.push({ path, twin: twin as PathDerivedTwin["twin"] });
  }
  return out;
}

/** The path-derived note's sentence on reading a named secret file itself
 *  (confidentiality.md §7.1, 2026-10-19): what a read of it on its own
 *  shows, per its twin kind. Built from the model's own token and the
 *  arbiter's kind only. Byte-identical in both proxies. */
export function pathDerivedTwinSentence(t: PathDerivedTwin): string {
  const glob = /[*?[]/.test(t.path);
  const subject = glob ? `each secret file ${t.path} matches` : t.path;
  const how = glob
    ? "read it on its own (a file read of that one file, or `cat` with that file alone)"
    : `read it on its own (a file read of ${t.path}, or \`cat ${t.path}\` alone)`;
  const send = "(a command that sends it is checked against the file's rules)";
  switch (t.twin) {
    case "lines":
      return `To use ${subject} itself, ${how}: you see each line's label as written and its value as a symbol you can pass to a command ${send}.`;
    case "fields":
      return `To use ${subject} itself, ${how}: you see its keys and layout as written and each secret value as a symbol you can pass to a command ${send}.`;
    case "whole":
      return `To use ${subject} itself, ${how}: you see one symbol that stands for the whole file, which you can pass whole to a command where the file's content belongs ${send}.`;
    case "text":
      return `To read ${subject} itself, ${how}: Mandu read every place in it that can hold a secret and found none, so you see its text.`;
  }
}

/** The value-backstop note's line (confidentiality.md §7.1, 2026-10-17):
 *  the result is masked whole only because the arbiter's value backstop
 *  found a registered secret's value in it (the classify verdict's
 *  `raisedBy`); the path rules call it public, so no file the call names is
 *  secret. Static text: no byte of the output, no name of the secret.
 *  Byte-identical in both proxies. */
function valueBackstopLine(): string {
  return `masked: this output contains the value of a registered secret, so the whole output is withheld from you, including whether it succeeded; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). It is withheld for that value, not for the file it came from. To read the rest, run a command that prints it with the value left out (for example without the lines that hold it); do not print the value in any other form. Do not assume it worked: if you still cannot tell, say you cannot see the result, or ask the user what it printed.`;
}

/** One whole `$MDU` token (the arbiter's symbol grammar, anchored). */
const WHOLE_SYMBOL_RE = /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*$/;

/**
 * backstop-value-only.md §3, rule P2: the call's own evidence holds no
 * secret read. No taint answer that masks it, no file its tree read (a
 * listed reader's release included), no refused open, no twin served, no
 * connection refused and no command blocked in its tree. A null taint (a
 * call this proxy asked no tree for: a Read) is clean: its path rule already
 * called the result public. Pure. Byte-identical in both proxies.
 */
export function valueOnlyEvidenceClean(t: SecretTaintInfo | null | undefined): boolean {
  if (t == null) return true;
  return !t.maskWhole && !isSecretLevel(t.level) && t.files.length === 0 && t.denied.length === 0 &&
    !t.deniedOnly && !t.twinOnly && (t.twinOf?.length ?? 0) === 0 &&
    (t.refusedEgress?.length ?? 0) === 0 && (t.blockedExec?.length ?? 0) === 0;
}

/**
 * backstop-value-only.md §3, rule P3: the arbiter's value-only offer, checked
 * and rebuilt from this proxy's own copy of the result. The spans must be
 * sorted, disjoint, in bounds and non-empty, each symbol one whole `$MDU`
 * token; the text rebuilt from `value` must equal the offered text, and no
 * replaced value may remain in it. Anything else (or no offer) is null: the
 * result is masked whole. Pure. Byte-identical in both proxies.
 */
export function acceptValueOnlyOffer(
  value: string,
  verdict: { valueOnly?: unknown },
): { text: string; values: Array<{ symbol: string; value: string }> } | null {
  const o = verdict.valueOnly as { text?: unknown; spans?: unknown } | undefined;
  if (!o || typeof o.text !== "string" || !Array.isArray(o.spans) || o.spans.length === 0) return null;
  let out = "";
  let at = 0;
  const values: Array<{ symbol: string; value: string }> = [];
  for (const s of o.spans as Array<{ start?: unknown; end?: unknown; symbol?: unknown }>) {
    if (!s || typeof s.start !== "number" || typeof s.end !== "number" || !Number.isInteger(s.start) || !Number.isInteger(s.end)) return null;
    if (s.start < at || s.end <= s.start || s.end > value.length) return null;
    if (typeof s.symbol !== "string" || !WHOLE_SYMBOL_RE.test(s.symbol)) return null;
    out += value.slice(at, s.start) + s.symbol;
    values.push({ symbol: s.symbol, value: value.slice(s.start, s.end) });
    at = s.end;
  }
  out += value.slice(at);
  if (out !== o.text) return null;
  if (values.some((v) => out.includes(v.value))) return null;
  return { text: out, values };
}

/**
 * clean-tree-release.md §2, rule Q3: the arbiter's clean-tree release offer,
 * checked and rebuilt from this proxy's own copy of the result. With no span
 * the offered text must be the result exactly; with spans, the value-only
 * rebuild (`acceptValueOnlyOffer`). A result holding `$MDU` text in any case
 * is never released. Anything else (or no offer) is null: the result is
 * masked whole. Pure. Byte-identical in both proxies.
 */
export function acceptPathReleaseOffer(
  value: string,
  verdict: { pathRelease?: unknown },
): { text: string; values: Array<{ symbol: string; value: string }>; listing?: { operands: string[]; part: "first" | "last" } } | null {
  const o = verdict.pathRelease as { text?: unknown; spans?: unknown; listing?: unknown } | undefined;
  if (!o || typeof o.text !== "string" || !Array.isArray(o.spans) || /\$MDU/i.test(value)) return null;
  // folder-listing-compound.md: a compound's listing rides only a release
  // with no span, its operands plain lines and its part first or last
  if (o.listing !== undefined) {
    const l = o.listing as { operands?: unknown; part?: unknown } | null;
    if (o.spans.length !== 0 || l === null || typeof l !== "object" || (l.part !== "first" && l.part !== "last")) return null;
    if (!Array.isArray(l.operands) || l.operands.length === 0 || l.operands.length > 32) return null;
    if (!l.operands.every((x) => typeof x === "string" && x !== "" && x.length <= 200 && !/[\r\n]/.test(x))) return null;
    return o.text === value ? { text: value, values: [], listing: { operands: [...l.operands as string[]], part: l.part } } : null;
  }
  if (o.spans.length === 0) return o.text === value ? { text: value, values: [] } : null;
  return acceptValueOnlyOffer(value, { valueOnly: o });
}

/** The path tokens the note may name: the arbiter's `namedPaths` that the
 *  model's own command holds verbatim (a translated spelling never does),
 *  at most 3, each short and on one line. Pure. */
export function pathDerivedPaths(namedPaths: readonly string[] | undefined, command: string): string[] {
  const out: string[] = [];
  for (const p of namedPaths ?? []) {
    if (out.length >= 3) break;
    if (typeof p !== "string" || p === "" || p.length > 200 || /[\r\n]/.test(p) || out.includes(p)) continue;
    if (command.includes(p)) out.push(p);
  }
  return out;
}

/** The `refused:` line's words per refusal kind (arbiter/ipc/protocol.ts
 *  EGRESS_REFUSAL_KINDS), and whether the user can allow it. */
const EGRESS_REFUSAL_WORDS: Readonly<Record<string, { why: string; ask: boolean; next?: string }>> = {
  tainted: { why: "it had read a secret, and the host is not one that secret is bound to", ask: true },
  unattributed: { why: "Mandu could not tell which program opened it, and programs in this session hold a secret", ask: true },
  symbol: { why: "the request carried a masked value ($MDU placeholder) that may not be sent to that host", ask: true },
  // confidentiality.md §4, the tripwire files no Approvals row (2026-10-17):
  // no approval can let a raw secret value through, so none is offered.
  fingerprint: {
    why: "the request carried text Mandu holds as a secret (a registered secret's value, or a line of a result it masked)",
    ask: false,
    next: "Do not retry the same request: there is nothing to approve for it. Tell the user what you were sending and where.",
  },
  "blocked-destination": { why: "the host is a cloud metadata or link-local address, which Mandu always refuses", ask: false },
  "this-machine": { why: "the host is this machine, and Mandu's egress proxy does not relay to this machine's own services", ask: false },
  // confidentiality.md §7, "A placeholder the agent's shell would expand"
  "shell-expanded": {
    why: "the request carried a secret's placeholder after a shell had expanded its $MDU to nothing (the placeholder was in double quotes or unquoted in the command or a script), so it held neither the value nor the placeholder",
    ask: false,
    next: "Put the placeholder in single quotes ('$MDU:…') where the shell reads it, in a script you wrote too, and run it again.",
  },
  "fail-closed": { why: "Mandu could not check the request", ask: false },
  // plan 10 §11.8, "A placeholder as the destination" (2026-10-17): no
  // host and no symbol in the words, only the generic `$MDU:…`.
  "symbol-destination": {
    why: "its destination was a Mandu placeholder ($MDU:…), and Mandu never turns a placeholder into a host to connect to",
    ask: false,
    next: "Do not retry with a placeholder as the host: write the host itself, and use the placeholder only where the secret's value belongs (a header or the body). If the host itself is the secret, tell the user.",
  },
  // confidentiality.md §4, "A held command's refused connection"
  // (2026-10-12): the arbiter filed (or read) the session's own ask.
  "session-asked": {
    why: "it holds what this session read, and the host is not a place that may go, so Mandu asked the user on its Approvals page",
    ask: false,
    next: "Tell the user it is waiting for their OK there; once they allow it, run the same command again: its next connection to that host goes through, once.",
  },
  "session-blocked": {
    why: "it holds what this session read, and the user blocked this session's requests to that host",
    ask: false,
    next: "Do not retry; tell the user.",
  },
};

/** A connection the egress proxy refused, as `callTaint` folds it (plan 10
 *  §11.8): the program and the kind; `unattributed` when the proxy tied it
 *  to no process and the arbiter to this call only by time ("A refusal no
 *  process is tied to"). Never a host. */
export interface RefusedEgress {
  app: string;
  kind: string;
  unattributed?: boolean;
}

/** The `refused:` line for one refusal (plan 10 §11.8), byte-identical in
 *  both proxies. An unattributed one names no program and no host (the host
 *  could be spelled from what was refused): it says the connection was made
 *  while the command ran and that Mandu could not tell which program opened
 *  it. Built from the kind only, never from a request byte. Pure. */
export function refusedEgressLine(r: RefusedEgress): string {
  const w = EGRESS_REFUSAL_WORDS[r.kind] ?? EGRESS_REFUSAL_WORDS["fail-closed"]!;
  const tail = w.ask ? " Tell the user rather than retrying; if it should go, they can allow it on the Mandu dashboard's Approvals page." : ` ${w.next ?? "Do not retry."}`;
  if (r.unattributed === true) {
    const why = r.kind === "unattributed" ? UNATTRIBUTED_SECRET_WHY : w.why;
    return `refused: a connection out was refused while this command ran, and nothing was sent; Mandu could not tell which program opened it, so it may not be this command's: ${why}.${tail}`;
  }
  return `refused: ${r.app} tried to connect out and Mandu refused the connection, nothing was sent: ${w.why}.${tail}`;
}

/** The `unattributed` kind's reason on a line that already says the
 *  program is unknown. */
const UNATTRIBUTED_SECRET_WHY = "programs in this session hold a secret, and while one does Mandu refuses a connection it cannot tie to a program";

/** The `blocked:` line's words per blocked-command kind (arbiter
 *  policy/blocked-exec.ts BLOCKED_EXEC_KINDS, the exec-wrap shim's approval
 *  kinds), and what the model can do instead. Byte-identical in both
 *  proxies. */
const BLOCKED_EXEC_WORDS: Readonly<Record<string, { why: string; next: string }>> = {
  symbol_as_command: {
    why: "a placeholder for text from an untrusted source sat where it would run as a command or as code",
    next: "Tell the user; if they trust that text, they can run the command themselves, outside the agent.",
  },
  unsupported_command: {
    why: "its command line carries a placeholder and uses shell syntax Mandu cannot check safely",
    next: "Write it as one plain command (no pipes, redirects, $( ), { } or wildcards), or tell the user.",
  },
  secret_symbol: {
    why: "its command line would have carried a secret's real value, and a secret leaves only inside a network request to a host it is bound to",
    next: "Tell the user rather than retrying; a request to another host asks for their OK on the Mandu dashboard's Approvals page.",
  },
  // 2026-10-09: the shim ran under Codex's own sandbox with its network
  // off, whose filter refused the shim's connection to Mandu (supported-
  // agents.md §6.4); the shim never asked, so the command was not judged.
  codex_sandbox: {
    why: "Codex's own sandbox, whose network is off, refused its connection to Mandu's command check, and Mandu never runs a command it could not check; the command itself was not the problem, and from that sandbox it could not have reached the network anyway",
    next: "To run it, ask to run it outside the sandbox (sandbox_permissions \"require_escalated\" with a justification, where your approval policy allows it; the user is asked first), or tell the user that sandbox_workspace_write.network_access = true in their Codex config lets these commands reach Mandu.",
  },
  other: {
    why: "Mandu could not check it",
    next: "Tell the user rather than retrying.",
  },
};

/** The `blocked:` line (plan 10 §11.8, "Blocked commands"): the program's
 *  name and the kind's words only. Codex's sandbox kind did not reach
 *  Mandu's check at all, so it is not said to have been refused by it. */
function blockedExecLine(r: { app: string; kind: string }): string {
  const w = BLOCKED_EXEC_WORDS[r.kind] ?? BLOCKED_EXEC_WORDS["other"]!;
  const head = r.kind === "codex_sandbox" ? `${r.app} did not start` : `Mandu's command check refused ${r.app} before it started`;
  return `blocked: ${head}, so it did not run and sent nothing: ${w.why}. ${w.next}`;
}

/** The arbiter's size bound for the structured exec-twin test
 *  (claude-code-inbound.ts EXEC_TWIN_OUTPUT_MAX); no runtime import. */
const EXEC_TWIN_OUTPUT_MAX = 256 * 1024;

/** Worth sending to `callTaint` for the §11.8 twin test: a twin carries at
 *  least one symbol and is a small file's text. Everything else skips the
 *  extra bytes on the socket (the arbiter would answer no `twinOf`). */
function mayBeTwin(value: string): boolean {
  return value.length <= EXEC_TWIN_OUTPUT_MAX && value.includes("$MDU:");
}

/** The arbiter's size bound for the key listing test
 *  (claude-code-inbound.ts KEY_LISTING_OUTPUT_MAX); no runtime import. */
const KEY_LISTING_OUTPUT_MAX = 16 * 1024;
/** A line that could be a key part: one word that starts like a key (a
 *  letter, `_`, a quote, `/`, `@` or `.`: no number) and holds no `=` (so a
 *  `KEY=value` line is not one), after optional indentation and an optional
 *  `export `, then at most a separator (`KEY`, `KEY=`, `  password:`,
 *  `aws_access_key_id =`, `export KEY`). */
const KEY_LIKE_LINE_RE = /^[ \t]*(?:export[ \t]+)?[A-Za-z_"'/@.][^\s=]*(?:[ \t]*[=:])?[ \t\r]*$/m;

/** Worth sending to `callTaint` for the key listing test (plan 10
 *  §11.8, "A key listing"): a command's token-free output of at most
 *  16 KiB with at least one line shaped like a key part (a listing names at
 *  least one secret's key), looked for after Codex's exec envelope (whose
 *  `Output:` line would pass any output); a script cell's printed result
 *  object (`{…}`) is sent as it is. A traffic screen only, never a security
 *  check: the arbiter decides, and only on the guard's evidence. It is asked
 *  BEFORE the classify (the ask binds the call), so whether the path-derived
 *  mask applies is not known yet; the screen keeps the extra bytes off the
 *  socket for most outputs. Byte-identical to the anthropic-proxy's but for
 *  the envelope. */
function mayBeKeyListing(value: string): boolean {
  if (value.length > KEY_LISTING_OUTPUT_MAX || value.includes("$MDU:")) return false;
  const body = splitCodexExecEnvelope(value)?.body ?? value;
  return body.trimStart().startsWith("{") || KEY_LIKE_LINE_RE.test(body);
}

/** Worth sending to `callTaint` for the folder-names test (plan 10 §11.8,
 *  "A folder's names", 2026-10-17): the command starts with the word `ls`
 *  and the output is a token-free text of at most 16 KiB (the arbiter's
 *  bound, claude-code-inbound.ts KEY_LISTING_OUTPUT_MAX). A traffic screen
 *  only, like `mayBeKeyListing`: the arbiter parses the command, reads the
 *  folders and decides, on the guard's evidence. Byte-identical in both
 *  proxies. */
function mayBeDirListing(command: string, value: string): boolean {
  return /^\s*ls(?:\s|$)/.test(command) && value !== "" && value.length <= KEY_LISTING_OUTPUT_MAX && !value.includes("$MDU:");
}

/** Worth sending to `callTaint` for the own-text test (plan 10 §11.13, "A
 *  config with no secret", 2026-10-17): a command that may name one of the
 *  exhaustive configs (`.ssh`, `config`, `pip.conf` / `pip.ini`,
 *  `credentials`: `~/.ssh/config` and `config.d/*`, pip's, git's store), and
 *  a token-free output of at most 16 KiB (the arbiter's bound,
 *  claude-code-inbound.ts KEY_LISTING_OUTPUT_MAX). A traffic screen only,
 *  like `mayBeKeyListing`: the arbiter finds the configs the command names
 *  and decides, on the guard's evidence. Byte-identical in both proxies. */
function mayBeOwnTextTwin(command: string, value: string): boolean {
  return /\.ssh\b|(?:^|[\s/'"])config\b|pip\.(?:conf|ini)|credentials/.test(command) && value !== "" && value.length <= KEY_LISTING_OUTPUT_MAX && !value.includes("$MDU:");
}

/** The arbiter's §12.2 ceiling denial (`heldTimeoutReason` in
 *  arbiter/policy/flow-taint.ts; no runtime import from the arbiter here, so
 *  the shape is matched): rendered as the "held:" form. */
function isHeldTimeoutReason(reason: string): boolean {
  return /^held for \d+ s, nobody answered\b/.test(reason);
}

/** The Codex tools that run a process tree: the shell/exec names the
 *  capability detector knows, plus the default a forged (uncorrelated)
 *  function_call_output falls back to. Only those have a taint to ask for. */
function isExecShaped(toolName: string): boolean {
  return EXEC_TOOL_NAMES.has(toolName) || toolName === DEFAULT_TOOL;
}

/**
 * The command text the exec-output legs read from a call's arguments: an
 * exec-shaped tool's `cmd` / `command` (originFor), else the first
 * command-like field (plan 10 §11.12). Null when the call carries none. The
 * response side records the same text, read from the arguments it DELIVERED
 * to Codex (`recordCallCommand`, plan 13 D9 follow-up), so the call is bound
 * to the shell that ran it and never by the arguments Codex echoes back.
 */
export function callCommandText(toolName: string, args: Record<string, unknown>): string | null {
  return (isExecShaped(toolName) ? originFor(args) ?? commandLikeText(args) : commandLikeText(args)) ?? null;
}

/**
 * Plan 10 §11.18: Codex's own tools that are not a shell (the shell names
 * are EXEC_TOOL_NAMES), each read off codex-cli's wire (0.136 to 0.162.0;
 * 0.161 and 0.162 add none, supported-agents.md §6.4):
 * the patch, the plan, the image viewer, the polls of a running process or
 * cell, the code-mode and REPL cells, the deferred-tool search, the user
 * question, the experimental file tools and the sub-agent tools. They have
 * no inbound spec, so the arbiter cannot name them: listed here, they keep
 * their rules and are never masked for being unmapped. A tool a codex
 * release adds or renames is not here, and is masked whole until it is
 * mapped (or listed under policy.yaml `mapped_tools:`). The MCP resource
 * tools (`list_mcp_resources`, `list_mcp_resource_templates`,
 * `read_mcp_resource`) are deliberately NOT here: they return a server's
 * resources by a server name the model wrote, so no mapping can vouch for
 * them.
 */
export const CODEX_MAPPED_TOOLS: ReadonlySet<string> = new Set([
  "apply_patch", "update_plan", "view_image", "wait", "write_stdin", "exec", "js_repl", "js_repl_reset",
  "tool_search", "request_user_input", "read_file", "list_dir", "grep_files",
  "spawn_agent", "send_input", "wait_agent", "close_agent", "resume_agent",
  // codex-cli 0.160 (read off its wire 2026-10-07): the thread goal (its
  // objective and token usage), the question that returns at once (the
  // answer arrives as a user message), and the namespaced timer and
  // sub-agent tools, named `<namespace>__<name>` (buildCorrelationMap). None
  // returns data from outside codex: an ack, a status, an agent list, the
  // goal the user or the model wrote.
  "get_goal", "create_goal", "update_goal", "request_user_input_async",
  "clock__sleep",
  "collaboration__spawn_agent", "collaboration__send_message", "collaboration__followup_task",
  "collaboration__interrupt_agent", "collaboration__list_agents", "collaboration__wait_agent",
]);

/** One of codex's own tools (a shell or a mapped built-in): the cell guard
 *  keeps it without asking (plan 10 §11.18, "The cell guard"). */
export function isCodexBuiltinTool(name: string): boolean {
  return CODEX_MAPPED_TOOLS.has(name) || EXEC_TOOL_NAMES.has(name);
}

/** A name no tool has: the cell guard's ask whether the arbiter masks a
 *  tool with no mapping (the confidentiality axis on, §11.18 built). */
const GUARD_PROBE_TOOL = "mandu.cell-guard.probe";

/**
 * Plan 10 §11.18, the cell guard: the nested tools an unidentified code cell
 * keeps, or null when the guard does not apply (the arbiter does not mask a
 * tool with no mapping: the axis off, an older arbiter, an ask that fails).
 * Kept: codex's own tools, and each tool the cell's text names that the
 * arbiter has a mapping for (an `mcp__` tool of a registered server, Mandu's
 * own, a tool under policy.yaml `mapped_tools:`). Everything else the cell's
 * `tools` holds is switched off before its code runs (cell-guard.ts).
 */
export async function cellGuardKeep(arbiter: Arbiter, src: string, sessionKey: string | undefined, log?: (msg: string) => void): Promise<string[] | null> {
  if (!arbiter.callTaint) return null;
  const mapped = async (name: string): Promise<boolean | null> => {
    try {
      const r = await arbiter.callTaint!({ callId: `mandu-guard#${name}`, unmappedTool: name, ...(sessionKey ? { sessionKey } : {}) });
      return r.evidence !== "unmapped";
    } catch (err) {
      log?.(`cell guard: callTaint failed for ${name}: ${(err as Error).message}`);
      return null;
    }
  };
  if ((await mapped(GUARD_PROBE_TOOL)) !== false) return null;
  const keep = [...CODEX_MAPPED_TOOLS, ...EXEC_TOOL_NAMES].filter((n) => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(n));
  for (const name of writtenToolNames(src)) {
    if (isCodexBuiltinTool(name)) continue;
    if ((await mapped(name)) === true) keep.push(name);
  }
  return keep;
}

/** Is every tool a guarded cell kept one the arbiter still maps (or one of
 *  codex's own)? An ask that fails counts as no. */
async function guardKeepHolds(arbiter: Arbiter, keep: readonly string[], sessionKey: string | undefined, log?: (msg: string) => void): Promise<boolean> {
  for (const name of keep) {
    if (isCodexBuiltinTool(name)) continue;
    if (!arbiter.callTaint) return false;
    try {
      const r = await arbiter.callTaint({ callId: `mandu-guard#${name}`, unmappedTool: name, ...(sessionKey ? { sessionKey } : {}) });
      if (r.evidence === "unmapped") return false;
    } catch (err) {
      log?.(`cell guard: callTaint failed for ${name}: ${(err as Error).message} — the cell keeps the text rules`);
      return false;
    }
  }
  return true;
}

/**
 * Plan 10 §11.13, the per-server rule: the taint of the stdio MCP server
 * behind an `mcp__<server>__<tool>` result, through the arbiter's
 * `mcpServerTaint` (the launcher's registration of the agent's MCP config,
 * the guard's exec records). `{mask}` when the server's own process tree
 * read a secret raw, or when the answer cannot be read (fail-closed); else
 * the verdict (`clean`, `unmapped`, `own`). Null when the arbiter has
 * no such op (every server unmapped).
 */
async function serverTaintFor(
  arbiter: Arbiter,
  tool: string,
  sessionKey: string | undefined,
  log?: (msg: string) => void,
): Promise<{ mask: SecretTaintInfo } | { verdict: McpServerTaintWire["verdict"] } | null> {
  if (!arbiter.mcpServerTaint) return null;
  let r: McpServerTaintWire;
  try {
    r = await arbiter.mcpServerTaint({ tool, ...(sessionKey ? { sessionKey } : {}) });
  } catch (err) {
    log?.(`mcpServerTaint failed for ${tool}: ${(err as Error).message} — masking the result (fail-closed)`);
    return { mask: { level: "no-model", files: [], apps: [], rule: "secret", maskWhole: true, denied: [], deniedOnly: false, why: "the MCP server's process taint could not be read: masked (fail-closed)" } };
  }
  if (r.verdict === "tainted") {
    const files = r.files.map((f) => f.split("/").pop()).join(", ");
    return { mask: { level: r.level ?? "no-model", files: r.files, apps: r.apps, rule: "secret", maskWhole: true, denied: [], deniedOnly: false, why: `plan 10 §11.13: the MCP server ${r.server ?? tool} runs processes that read ${files || "a secret"} raw; the whole output is secret` } };
  }
  return { verdict: r.verdict };
}

/**
 * Plan 10 §4.2 / §11.8: ask the arbiter for the taint of the process tree
 * behind an exec_command call, decide whether the whole result is masked, and
 * prepare the note the model will read. Ported from
 * anthropic-proxy/src/rewrite-request.ts `secretTaintFor`: only exec-shaped
 * tools have a tree, and the command is Codex's `cmd` (originFor). Fail-closed:
 * an arbiter that THROWS on callTaint is treated as "tainted, rule secret"
 * with an unknown level (no-model); an arbiter without the op reports no
 * taint (nothing to mask). A rule (ii)/(iii) result is released only when the
 * verbatim-value backstop finds nothing and no mask regex matches; a backstop
 * that cannot run keeps the result masked.
 */
async function secretTaintFor(
  arbiter: Arbiter,
  toolName: string,
  callId: string,
  args: Record<string, unknown>,
  origin: string | undefined,
  sessionKey: string | undefined,
  value: string,
  log?: (msg: string) => void,
  how?: ToolCallRef["taint"],
  /** Out: the connections the arbiter says were refused from the call's
   *  tree (plan 10 §11.8, "Refused connections"). */
  egress?: { refused?: RefusedEgress[]; blocked?: Array<{ app: string; kind: string }> },
): Promise<SecretTaintInfo | null> {
  // A cell that runs no process (a bare tool listing, §11.13) has no tree.
  if (how === "none") return null;
  // Any other tool whose input carries a command-like field is asked about as
  // `unmappedTool` (plan 10 §11.12): the arbiter answers only when the
  // session's spec does not know the tool, and that answer can only mask (the
  // denied-only and twin releases below never apply to it). A script cell the
  // proxy could not read is asked that way whatever its name.
  const mapped = how !== "unmapped" && isExecShaped(toolName);
  const unmappedCommand = mapped ? null : commandLikeText(args);
  // The MCP server's own process tree (§11.13, the per-server rule): a server
  // the launcher registered and the guard saw spawned answers for itself. A
  // tainted server masks its result whole; a clean one (exactly one process,
  // its tree read no secret raw) is not asked about the session below.
  const server = toolName.startsWith("mcp__") ? await serverTaintFor(arbiter, toolName, sessionKey, log) : null;
  if (server && "mask" in server) return server.mask;
  // Asked with no command (the session answers, §11.13): a cell or `wait` the
  // proxy could not tie to a command, and every MCP tool whose server is not
  // proven clean — an MCP server is a store a script cell can write a
  // reader's raw output into without the proxy seeing the write (§11.13
  // path (c)). The arbiter answers empty for Mandu's own tools. Codex's own
  // MCP resource tools return a server's resources by a `server` field the
  // model wrote: never mapped per server, always asked (2026-10-03).
  // Plan 10 §11.18 (P0 item 4b, the maintainer's decision 2026-10-07):
  // every other tool is asked too, and the arbiter masks WHOLE one it has no
  // mapping for (`evidence: "unmapped"`): an MCP tool of a server the
  // launcher did not register, a codex release's new or renamed tool (the
  // resource tools included). Codex's own built-ins have no inbound spec:
  // CODEX_MAPPED_TOOLS names them, and they keep their rules (not asked
  // unless the proxy could not tie them, `how: "unmapped"`, or their input
  // carries a command; then asked as `builtin`).
  const builtin = how === "unmapped" || CODEX_MAPPED_TOOLS.has(toolName);
  const cleanServer = toolName.startsWith("mcp__") && !!server && "verdict" in server && server.verdict === "clean";
  const askBare = how === "unmapped" || (!builtin && !cleanServer);
  if (!mapped && unmappedCommand === null && !askBare) return null;
  if (!arbiter.callTaint) return null;
  // `shell{command: [argv]}` names its command as an array: joined so the
  // arbiter's signature tokenizer splits it back (originFor reads strings only).
  const command = mapped ? (origin ?? commandLikeText(args) ?? undefined) : (unmappedCommand ?? undefined);
  let t: CallTaintWire;
  try {
    t = await arbiter.callTaint({
      callId, ...(command ? { command } : {}), ...(sessionKey ? { sessionKey } : {}),
      // `codexHead` (review of !1604): the output is Codex's exec result, so its
      // first head is Codex's own, and the arbiter's twin tests may look
      // through that one head; the anthropic-proxy never says so.
      ...(mapped ? (mayBeTwin(value) || (command !== undefined && (mayBeKeyListing(value) || mayBeDirListing(command, value) || mayBeOwnTextTwin(command, value))) ? { output: value, codexHead: true } : {}) : { unmappedTool: toolName, ...(builtin ? { builtin: true } : {}) }),
    });
  } catch (err) {
    log?.(`callTaint failed for ${callId}: ${(err as Error).message} — masking the result (fail-closed)`);
    return { level: "no-model", files: [], apps: [], rule: "secret", maskWhole: true, denied: [], deniedOnly: false, why: "the process taint could not be read: masked (fail-closed)" };
  }
  const denied = t.denied ?? [];
  if (egress && Array.isArray(t.refusedEgress) && t.refusedEgress.length > 0) {
    egress.refused = t.refusedEgress.filter((r) => r && typeof r.app === "string" && typeof r.kind === "string");
  }
  if (egress && Array.isArray(t.blockedExec) && t.blockedExec.length > 0) {
    egress.blocked = t.blockedExec.filter((r) => r && typeof r.app === "string" && typeof r.kind === "string");
  }
  // §11.18: a tool Mandu has no mapping for, masked whole; the arbiter's
  // note says why and how to let it through (policy.yaml `mapped_tools:`).
  if (!mapped && t.evidence === "unmapped") {
    const why = typeof t.why === "string" && t.why !== ""
      ? t.why
      : `Mandu has no mapping for the tool ${toolName}, so its whole result is hidden from the AI; to let it through, list it under \`mapped_tools:\` in policy.yaml`;
    return { level: t.level ?? "no-model", files: [], apps: [], rule: "secret", maskWhole: true, denied: [], deniedOnly: false, why };
  }
  const twinOf = mapped && t.level === null && Array.isArray(t.twinOf) ? t.twinOf.filter((p) => typeof p === "string" && p !== "") : [];
  if (t.level === null && denied.length === 0 && twinOf.length === 0) return null;
  if (!mapped) {
    // §11.12: raise-only. Denials are only explained; a tainted tree or
    // session masks the whole result (rule `secret` for a session answer).
    if (t.level === null) return { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied, deniedOnly: false, why: "an open of a secret in the tree was refused" };
    if (t.evidence === "session") {
      const what = command !== undefined
        ? `plan 10 §11.12: ${toolName} runs a command Mandu could not tie to a process tree`
        : toolName.startsWith("mcp__")
          ? `plan 10 §11.13: ${toolName} is an MCP server whose state Mandu cannot see`
          : `plan 10 §11.13: ${toolName} is output Mandu could not tie to a command`;
      return { level: t.level, files: [], apps: t.apps, rule: "secret", maskWhole: true, denied, deniedOnly: false, why: `${what}, and programs in this session read ${t.files.map((f) => f.split("/").pop()).join(", ")} raw; the whole output is secret` };
    }
  } else if (t.evidence === "session" && t.level !== null) {
    // Plan 13 D7, fail-closed: the arbiter could not tie this exec call to
    // the process tree that ran it (no exec of the agent matched it), and
    // the session holds a raw read. Masked whole at the session's level; no
    // release (the denied-only and twin releases need the tree).
    return { level: t.level, files: [], apps: t.apps, rule: "secret", maskWhole: true, denied, deniedOnly: false, why: `plan 13 D7: Mandu could not tie this ${toolName} call to the processes that ran it, and programs in this session read ${t.files.map((f) => f.split("/").pop()).join(", ")} raw; the whole output is secret` };
  }
  // The value backstop (rule (ii)/(iii), and the denied-only release): a
  // registered value verbatim in the output keeps it masked whatever the
  // tree says; a backstop that cannot run counts as a hit.
  const backstop = async (): Promise<string | null> => {
    if (!arbiter.scanSecretValues) return "the value backstop is unavailable on this arbiter";
    try {
      const scan = await arbiter.scanSecretValues(value);
      return scan.hits.length > 0 ? `a registered secret value appears verbatim (${scan.hits.map((h) => h.symbol).join(", ")})` : null;
    } catch (err) {
      return `the value backstop failed (${(err as Error).message})`;
    }
  };
  if (t.level === null && denied.length === 0) {
    // The structured twin only (§11.8): the arbiter matched the output to
    // one registered file's twin in a tree the guard saw read no secret.
    // Released ⇒ the caller lowers the path-derived mask; a backstop hit ⇒
    // the mask stands.
    // "A document's own twin": the arbiter says the output is exactly a
    // document's whole-file twin (its base symbol), not a structured piece.
    // "A key listing": the output holds no token and is the keys of
    // the file's structured twin, in order (`cut -d= -f1 .env`).
    // "A folder's names": the output is exactly a plain `ls` of the folders
    // in `twinOf`, names only (`ls mail/inbox bank/`).
    // "A config with no secret" (plan 10 §11.13): the output holds no
    // token and is a piece of the own-text twin of a config the command
    // names (`cat ~/.ssh/config`).
    const whole = t.twinWhole === true;
    const keys = !whole && t.twinKeys === true;
    const ownText = !whole && !keys && t.twinOwn === true;
    const listing = !whole && !keys && !ownText && t.dirListing === true;
    const form = whole ? "whole-file twin" : keys ? "key listing of the structured twin" : ownText ? "own text (no secret in it)" : listing ? "names-only listing" : "structured twin";
    const hit = await backstop();
    return { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied, deniedOnly: false, twinOf, ...(whole ? { twinWhole: true } : {}), ...(keys ? { twinKeys: true } : {}), ...(ownText ? { twinOwn: true } : {}), ...(listing ? { dirListing: true } : {}), ...(hit === null ? { twinOnly: true } : {}), why: hit === null ? `the output is the ${form} of ${twinOf.join(", ")}, no process in the tree read a secret, and no registered value appears in it` : `a ${form}, but ${hit}` };
  }
  if (t.level === null) {
    // Denials only: no process in the tree holds a secret. Released ⇒ the
    // caller lowers the path-derived mask; a hit ⇒ the mask stands.
    const hit = await backstop();
    return { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied, deniedOnly: hit === null, why: hit === null ? "every open of a secret in the tree was refused and no registered value appears in the output" : `a refused tree, but ${hit}` };
  }
  const who = `${t.apps.join(", ") || "a program"} read ${t.files.map((f) => f.split("/").pop()).join(", ")}`;
  if (t.rule === "secret") {
    return { level: t.level, files: t.files, apps: t.apps, rule: t.rule, maskWhole: true, denied, deniedOnly: false, why: `plan 10 rule (i): ${who}; the whole output is secret` };
  }
  // rule (ii)/(iii): the value backstop, then the mask regexes
  let hit = await backstop();
  if (hit === null && t.rule === "mask") {
    for (const re of t.mask) {
      try { if (new RegExp(re, "m").test(value)) { hit = `a mask pattern matched (${re})`; break; } } catch { hit = `an invalid mask pattern (${re})`; break; }
    }
  }
  if (hit !== null) {
    return { level: t.level, files: t.files, apps: t.apps, rule: t.rule, maskWhole: true, denied, deniedOnly: false, why: `plan 10 rule (${t.rule === "clear" ? "ii" : "iii"}) backstop: ${hit}` };
  }
  return { level: t.level, files: t.files, apps: t.apps, rule: t.rule, maskWhole: false, denied, deniedOnly: false, why: `plan 10 rule (${t.rule === "clear" ? "ii" : "iii"}): ${who}; its output is released by the app rule` };
}

/**
 * The process leg for one output, as its correlation says (§11.12, §11.13):
 * through the call it continues (`taintVia`, a `wait`), with the session
 * folded in for a cell whose exec calls are not all identified, and with the
 * releases dropped where the output may not lower a verdict. Raise-only over
 * secretTaintFor.
 */
async function processTaintFor(
  arbiter: Arbiter,
  ref: ToolCallRef | undefined,
  toolName: string,
  callId: string,
  args: Record<string, unknown>,
  origin: string | undefined,
  sessionKey: string | undefined,
  value: string,
  log?: (msg: string) => void,
): Promise<SecretTaintInfo | null> {
  const egress: { refused?: RefusedEgress[]; blocked?: Array<{ app: string; kind: string }> } = {};
  const t = await processTaintCore(arbiter, ref, toolName, callId, args, origin, sessionKey, value, log, egress);
  // Plan 10 §11.8, "Refused connections": the egress proxy refused a
  // connection from this call's tree. Explains only (the note), never a
  // release: maskWhole, deniedOnly and twinOnly are untouched.
  let out = t;
  if (egress.refused && egress.refused.length > 0) {
    out = out
      ? { ...out, refusedEgress: egress.refused }
      : { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, refusedEgress: egress.refused, why: "a connection from the command was refused" };
  }
  // Plan 10 §11.8, "Blocked commands": the exec-wrap shim refused a command
  // of this call's tree before it ran. Explains only, like the above.
  if (egress.blocked && egress.blocked.length > 0) {
    out = out
      ? { ...out, blockedExec: egress.blocked }
      : { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, blockedExec: egress.blocked, why: "a command was blocked before it ran" };
  }
  return out;
}

/**
 * Plan 10 §11.18, a cell's resource tools (2026-10-11): each Codex MCP
 * resource tool a cell may call (cell-resource-tools.ts) is asked about exactly
 * as its direct call is (`callTaint{unmappedTool: <tool>}` under
 * `<callId>#<tool>`, no command, not a built-in), and the strictest answer is
 * folded into the cell's, raise-only. The arbiter answers `unmapped` (masked
 * whole) unless policy.yaml `mapped_tools:` lists the tool; an ask that
 * throws masks (secretTaintFor fails closed).
 */
async function withResourceTools(
  arbiter: Arbiter,
  resourceTools: CellResourceTools | undefined,
  callId: string,
  sessionKey: string | undefined,
  value: string,
  log: ((msg: string) => void) | undefined,
  t: SecretTaintInfo | null,
): Promise<SecretTaintInfo | null> {
  if (!resourceTools || t?.maskWhole) return t;
  // The cell guard switched off every tool it did not keep, at run time:
  // nothing the cell's text may reach is asked, while every kept tool is
  // still mapped (§11.18, "The cell guard").
  if (resourceTools.guardKeep && await guardKeepHolds(arbiter, resourceTools.guardKeep, sessionKey, log)) return t;
  // No trusted guard: the text rule, and every tool a guard kept that is not
  // codex's own (one may no longer be mapped).
  const ask = [...new Set([...resourceTools.tools, ...(resourceTools.guardKeep ?? []).filter((n) => !isCodexBuiltinTool(n))])];
  for (const tool of ask) {
    const r = await secretTaintFor(arbiter, tool, `${callId}#${tool}`, {}, undefined, sessionKey, value, log);
    if (!r?.maskWhole) continue;
    return {
      level: stricterLevel(t?.level, r.level), files: [...(t?.files ?? []), ...r.files], apps: [...new Set([...(t?.apps ?? []), ...r.apps])],
      rule: "secret", maskWhole: true, denied: t?.denied ?? [], deniedOnly: false,
      why: `plan 10 §11.18: this cell ${resourceTools.tools.includes(tool) ? resourceTools.why : `kept ${tool} in its guard`}; ${r.why}`,
    };
  }
  return t;
}

async function processTaintCore(
  arbiter: Arbiter,
  ref: ToolCallRef | undefined,
  toolName: string,
  callId: string,
  args: Record<string, unknown>,
  origin: string | undefined,
  sessionKey: string | undefined,
  value: string,
  log: ((msg: string) => void) | undefined,
  egress: { refused?: RefusedEgress[]; blocked?: Array<{ app: string; kind: string }> },
): Promise<SecretTaintInfo | null> {
  const via = ref?.taintVia;
  let t = via
    ? await secretTaintFor(arbiter, via.name, via.callId, via.args, originFor(via.args), sessionKey, value, log, via.taint, egress)
    : await secretTaintFor(arbiter, toolName, callId, args, origin, sessionKey, value, log, ref?.taint, egress);
  if (ref?.raiseOnly && t && (t.deniedOnly || t.twinOnly)) t = { ...t, deniedOnly: false, twinOnly: false };
  t = await withResourceTools(arbiter, via?.resourceTools ?? ref?.resourceTools, via?.callId ?? callId, sessionKey, value, log, t);
  const fold = via ? via.foldSession === true || ref?.foldSession === true : ref?.foldSession === true;
  if (!fold || !arbiter.callTaint) return t;
  // The session, asked under a call id of its own: the cell's id may already
  // be tied to its first literal's tree, which would answer instead.
  const id = `${via?.callId ?? callId}#cell`;
  let s: CallTaintWire;
  try {
    s = await arbiter.callTaint({ callId: id, unmappedTool: "exec", builtin: true, ...(sessionKey ? { sessionKey } : {}) });
  } catch (err) {
    log?.(`callTaint failed for ${id}: ${(err as Error).message} — masking the result (fail-closed)`);
    return { level: "no-model", files: t?.files ?? [], apps: t?.apps ?? [], rule: "secret", maskWhole: true, denied: t?.denied ?? [], deniedOnly: false, why: "the process taint could not be read: masked (fail-closed)" };
  }
  if (s.level === null) return t;
  return {
    level: stricterLevel(t?.maskWhole ? t.level : undefined, s.level),
    files: t?.files ?? [], apps: [...new Set([...(t?.apps ?? []), ...s.apps])],
    rule: "secret", maskWhole: true, denied: t?.denied ?? [], deniedOnly: false,
    why: `plan 10 §11.13: the cell's exec calls are not all ones Mandu can identify, and programs in this session read ${s.files.map((f) => f.split("/").pop()).join(", ")} raw; the whole output is secret`,
  };
}

/** The `[mandu:secret]` note (§11.8): why a result is masked, or which open
 *  was refused and the way out. Proxy-authored; appended after the body.
 *  Byte-identical to the anthropic proxy's so the two agents read one note. */
export function buildSecretNote(t: SecretTaintInfo): string | null {
  const lines: string[] = [];
  if (t.pathDerived) lines.push(pathDerivedLine(t.pathDerived.paths, t.pathDerived.twins));
  if (t.valueBackstop) lines.push(valueBackstopLine());
  if (t.maskWhole && t.files.length > 0) {
    lines.push(`masked: ${t.apps.join(", ")} read ${t.files.join(", ")}; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Say so rather than retrying.`);
  } else if (t.maskWhole) {
    lines.push(`masked: ${t.why}. The user does not see this output unless your reply quotes the symbol (they then see its real value).`);
  } else if (t.files.length > 0 && !t.pathDerived && !t.valueBackstop) {
    lines.push(`note: ${t.apps.join(", ")} read ${t.files.join(", ")} (a listed reader); the output is released by the program's rule.`);
  }
  if (t.twinOnly && t.twinOf && t.twinOf.length > 0 && t.dirListing) {
    // "A folder's names" (plan 10 §11.8), and beside another command
    // (folder-listing-compound.md). Byte-identical in both proxies.
    lines.push(t.dirListingPart ? dirListingPartLine(t.twinOf, t.dirListingPart) : dirListingLine(t.twinOf));
  } else if (t.twinOnly && t.twinOf && t.twinOf.length > 0) {
    lines.push(t.twinWhole
      ? `twin: this is ${t.twinOf.join(", ")} as you see it: the whole file is one symbol. Use the symbol where the file's content belongs (a command that sends it is checked against the file's rules); the user sees the real content.`
      : t.twinOwn
        // "A config with no secret" (plan 10 §11.13). Byte-identical in
        // both proxies.
        ? `twin: this is ${t.twinOf.join(", ")} as it is: Mandu read every place in it that can hold a secret and found none, so you see its text.`
        : t.twinKeys
        // "A key listing" (plan 10 §11.8). Codex has no Read tool,
        // so this line says "cat it" where the anthropic-proxy's says "Read".
        ? `twin: these are the key names in ${t.twinOf.join(", ")}, and the lines of it that hold no masked value, as you see the file; no masked value is in this output. Print the file (cat it) to see each masked value as a symbol, and use the symbol where the value belongs (a command that sends it is checked against the file's rules); the user sees the real values.`
        : `twin: this is ${t.twinOf.join(", ")} as you see it: the keys as written, each secret value a symbol. Use the symbol where the value belongs (a command that sends it is checked against the file's rules); the user sees the real values.`);
  }
  for (const r of t.refusedEgress ?? []) lines.push(refusedEgressLine(r));
  for (const r of t.blockedExec ?? []) lines.push(blockedExecLine(r));
  for (const d of t.denied) {
    if (isHeldTimeoutReason(d.reason)) {
      // §11.8's third form: held for the user, the ceiling passed; the way
      // out is the user's answer, not a retry.
      lines.push(`held: ${d.app} waited for the user to allow it to read ${d.path} (${d.reason}). Tell the user the request is waiting on the Mandu dashboard's Approvals page; once they allow it, the same command succeeds without a new prompt. Do not retry before that.`);
    } else {
      lines.push(`denied: ${d.app} is not a reader of ${d.path} (${d.reason}). The user can allow it in policy.yaml (paths[].readers).`);
    }
  }
  if (lines.length === 0) return null;
  return lines.map((l) => `${SECRET_NOTE_MARKER} ${l}`).join("\n");
}

/** Append the note to a function_call_output. Its `output` is a string on
 *  the wire, so the forwarded text (symbol, envelope+symbol, or the released
 *  value) simply grows a trailing note; the audit records what went out. */
function appendSecretNote(fco: ToolOutputItem, audit: RewriteAudit, t: SecretTaintInfo | null): void {
  if (!t) return;
  audit.secretTaint = t;
  const note = buildSecretNote(t);
  if (!note) return;
  const current = audit.forwardedText ?? (audit.symbolized ? audit.symbol ?? "" : audit.value);
  const forwarded = `${current}\n\n${note}`;
  setOutput(fco, forwarded);
  audit.forwardedText = forwarded;
  audit.secretNote = note;
}

/** The same note on a Codex MCP result (a function_call_output split into the
 *  runtime header and the tool's text): appended to the string, or as one more
 *  `input_text` part, so the header and the body stay where they were. */
function appendMcpSecretNote(fco: ToolOutputItem, audit: RewriteAudit, t: SecretTaintInfo | null, form: "parts" | "string"): void {
  if (!t) return;
  audit.secretTaint = t;
  const note = buildSecretNote(t);
  if (!note) return;
  if (form === "string" || !Array.isArray(fco.output)) fco.output = `${flattenOutput(fco.output)}\n\n${note}`;
  else fco.output = [...(fco.output as unknown[]), { type: "input_text", text: `\n\n${note}` }];
  audit.forwardedText = flattenOutput(fco.output);
  audit.secretNote = note;
}

/** Confidentiality §7.1, "Masked after the fact": one more `[mandu:secret]`
 *  line on an output this proxy forwarded in clear in an earlier request and
 *  masks now. Joined to the output's secret note (so the §9 oracle's
 *  own-block scope strips it with that note); static text, no output byte.
 *  `form`: a Codex MCP result's shape (one more `input_text` part). */
function appendAfterTheFactNote(fco: ToolOutputItem, audit: RewriteAudit, line: string, form?: "parts" | "string"): void {
  const own = `${SECRET_NOTE_MARKER} ${line}`;
  const sep = audit.secretNote ? "\n" : "\n\n";
  if (form === "parts" && Array.isArray(fco.output)) {
    fco.output = [...(fco.output as unknown[]), { type: "input_text", text: `${sep}${own}` }] as never;
    audit.forwardedText = flattenOutput(fco.output);
  } else if (form === "string") {
    fco.output = `${flattenOutput(fco.output)}${sep}${own}` as never;
    audit.forwardedText = flattenOutput(fco.output);
  } else {
    const current = audit.forwardedText ?? (audit.symbolized ? audit.symbol ?? "" : audit.value);
    const forwarded = `${current}${sep}${own}`;
    setOutput(fco, forwarded);
    audit.forwardedText = forwarded;
  }
  audit.secretNote = audit.secretNote ? `${audit.secretNote}\n${own}` : own;
  audit.afterTheFact = true;
}

/**
 * What the forwarded request carries for THIS output, minus the proxy-authored
 * secret note and the trusted piece a split result keeps verbatim: the
 * own-block scope of the §9 oracle (events.ts survivingResult). What is left
 * is the symbol, so any raw span found here survived the rewrite.
 */
export function ownForwardedText(r: RewriteAudit): string {
  let text = r.forwardedText ?? (r.symbolized ? r.symbol ?? "" : r.value);
  if (r.secretNote) text = text.replace(`\n\n${r.secretNote}`, "");
  return r.keptVerbatim ? text.replace(r.keptVerbatim, "") : text;
}

/** A message Codex itself writes: its `<environment_context>` block, the
 *  whole text of its message (an CONTRIBUTING.md block or the human's prompt that
 *  merely quotes one starts otherwise). */
const ENV_CONTEXT_MESSAGE_RE = /^\s*<environment_context>[\s\S]*<\/environment_context>\s*$/;
const ENV_CONTEXT_CWD_RE = /<cwd>([^<]*)<\/cwd>/g;

/**
 * The directory Codex runs a shell call in when the call names no `workdir`
 * (2026-10-04, confidentiality.md §6): the session's cwd, as Codex's own
 * `<environment_context>` messages state it. Known for certain only when
 * every such message of the request names one and the same absolute path;
 * none, two different ones, or a message naming two: null (the call's
 * relative tokens then keep the catalog's verdict). Only a user- or
 * developer-role message whose whole text is the block counts, so neither a
 * tool output nor an CONTRIBUTING.md block can name it. Pure.
 */
export function codexSessionCwd(input: readonly unknown[]): string | null {
  const seen = new Set<string>();
  for (const item of input) {
    if (!item || typeof item !== "object") continue;
    const m = item as { type?: unknown; role?: unknown; content?: unknown };
    if (m.type !== undefined && m.type !== "message") continue;
    if (m.role !== "user" && m.role !== "developer") continue;
    const parts = typeof m.content === "string" ? [m.content] : Array.isArray(m.content)
      ? m.content.map((c) => (c && typeof c === "object" && typeof (c as { text?: unknown }).text === "string" ? (c as { text: string }).text : null)).filter((t): t is string => t !== null)
      : [];
    for (const text of parts) {
      if (!ENV_CONTEXT_MESSAGE_RE.test(text)) continue;
      const cwds = [...text.matchAll(ENV_CONTEXT_CWD_RE)].map((x) => x[1]!.trim());
      if (cwds.length !== 1) return null;
      seen.add(cwds[0]!);
    }
  }
  if (seen.size !== 1) return null;
  const [cwd] = [...seen];
  return cwd!.startsWith("/") && !cwd!.split("/").includes("..") ? cwd! : null;
}

/**
 * The §9 oracle haystack: the forwarded tool-output text only, the same scope
 * as the Anthropic proxy's forwardedToolResultText. Untrusted data enters only
 * through tool outputs, so a raw value that ALSO occurs in the user's prompt,
 * the instructions or the agent's own call arguments is not a leak.
 */
export function forwardedToolOutputText(req: ResponsesRequest): string {
  const parts: string[] = [];
  for (const item of Array.isArray(req.input) ? req.input : []) {
    if (isToolOutputItem(item)) parts.push(flattenOutput((item as ToolOutputItem).output));
  }
  // Codex's user-run shell records are tool output carried as user text
  // (user-shell.ts): the oracle reads them as tool output too.
  parts.push(...userShellTexts(Array.isArray(req.input) ? req.input : []));
  return parts.join("\n");
}

function alreadyInjected(instructions: string | undefined): boolean {
  return typeof instructions === "string" && instructions.includes(HANDLING_MARKER);
}

/**
 * The call's input spelled in HumanView, for the arbiter's confidentiality
 * derivation only (never forwarded): every string leaf through the view
 * map, bounded at the arbiter's scan depth. Undefined when nothing changed,
 * so a proxy with no view map sends byte-identical requests. Same helper as
 * the anthropic-proxy's (rewrite-request.ts toHumanViewParams).
 */
function toHumanViewParams(
  input: Record<string, unknown>,
  toHumanView: (s: string) => string,
): Record<string, unknown> | undefined {
  let changed = false;
  const map = (v: unknown, depth: number): unknown => {
    if (typeof v === "string") {
      if (v === "") return v;
      const m = toHumanView(v);
      if (m !== v) changed = true;
      return m;
    }
    if (v === null || typeof v !== "object" || depth >= 16) return v;
    if (Array.isArray(v)) return v.map((x) => map(x, depth + 1));
    const o: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) o[k] = map(x, depth + 1);
    return o;
  };
  const out = map(input, 0) as Record<string, unknown>;
  return changed ? out : undefined;
}

/**
 * Rewrite a parsed Responses request: classify + symbolize untrusted
 * function_call_output spans, prepend the handling prompt to `instructions`.
 * Throws RewriteRefusal on any arbiter error (fail-closed). Mutates a structural
 * clone, never the caller's object.
 */
export async function rewriteRequest(
  original: ResponsesRequest,
  opts: RewriteOptions,
): Promise<RewriteResult> {
  const { arbiter, sessionKey, handlingMode, skipPromptInjection } = opts;

  // Deep-clone so the caller's parsed body is untouched and we can safely mutate.
  const req: ResponsesRequest = structuredClone(original);
  const input = Array.isArray(req.input) ? req.input : [];

  // Codex's user-run shell (`!cmd`, supported-agents.md §2.4; user-shell.ts):
  // its `<user_shell_command>` record is PROGRAM OUTPUT carried as a user
  // message. Each one becomes, for this rewrite, a stand-in
  // function_call_output of `exec_command{cmd}` (masked whole when it does not
  // parse), and goes back into its message below. FIRST: the prompt filter
  // must not read it as the human's (or harness) text.
  const userShells: ExtractedUserShell[] = (opts.promptAgent ?? "codex") === "codex" ? extractUserShells(input) : [];
  const userShellUnparsed = new Set(userShells.filter((e) => e.parsed === null).map((e) => e.callId));

  // The prompt filter (confidentiality-plan-15 §3): before plan 15 this proxy
  // never read a user message for masking. The user-role text, cut into
  // human / harness / side-call segments by Codex's rules, goes to the
  // arbiter's `filterPrompt`; a registered value in it becomes its symbol.
  // Any failure refuses the request (fail-closed). This proxy has no
  // trusted-context haystack (the Claude proxy's exact-match upgrade), so
  // there is no span to exclude from one here.
  let promptFilter: PromptFilterReport | null;
  try {
    promptFilter = await applyPromptFilter(req, arbiter, {
      agent: opts.promptAgent ?? "codex",
      ...(sessionKey ? { sessionKey } : {}),
      ...(opts.log ? { log: opts.log } : {}),
      ...(opts.promptBlockLedger ? { ledger: opts.promptBlockLedger } : {}),
      ...(opts.signal ? { signal: opts.signal } : {}),
    });
  } catch (err) {
    if (err instanceof PromptHoldAbandoned) throw new RewriteAbandoned(err.message, err);
    if (err instanceof PromptBlocked) throw new RewriteBlocked(err.message, err.report);
    if (err instanceof PromptFilterRefusal) throw new RewriteRefusal(err.message, err.cause);
    throw err;
  }

  const correlation = buildCorrelationMap(input, { isolatedCells: cellsAreIsolated(advertisedTools(req)) });
  // the user shell's stand-in calls: no model call started them; callTaint
  // asks by the command (its exec signature)
  for (const e of userShells) if (e.parsed) correlation.set(e.callId, { name: DEFAULT_TOOL, args: { cmd: e.parsed.command } });
  const rewrites: RewriteResult["rewrites"] = [];
  // The ids whose output body this request forwards in clear: remembered
  // (opts.clearResults) only once the whole rewrite has succeeded.
  const clearIds: string[] = [];
  // Confidentiality §7.1, "Masked after the fact": a secret output whose
  // body went to the model in clear in an earlier request.
  const afterFact = (id: string): boolean => opts.clearResults?.wasClear(id) === true;
  // Where a shell call that names no `workdir` runs: the session's directory,
  // when Codex's own context names exactly one (codexSessionCwd), HumanView.
  const sessionCwd = codexSessionCwd(input);
  const workdirDefault = sessionCwd !== null ? (opts.toHumanView ? opts.toHumanView(sessionCwd) : sessionCwd) : undefined;

  // Confidentiality §7.1, "Masked after the fact", across a resume: ask the
  // arbiter which of this history's outputs an earlier launch forwarded in
  // clear (ids only; a failed ask loses a note, never a mask).
  if (opts.clearResults?.prime) {
    await opts.clearResults.prime(input.filter(isToolOutputItem).map((item) => (item as ToolOutputItem).call_id));
  }

  // Walk every tool-output item in input[] (function_call_output on the
  // classic wire, custom_tool_call_output on the script-cell wire).
  for (const item of input) {
    if (!isToolOutputItem(item)) continue;
    const fco = item as ToolOutputItem;
    const ref = correlation.get(fco.call_id);
    // Unknown originating call → still symbolize (fail-closed): an attacker could
    // forge a tool output with no matching call.
    const toolName = ref?.name ?? DEFAULT_TOOL;
    const args = ref?.args ?? {};
    const origin = originFor(args);
    // The same origin in the arbiter's world. Present only when the map actually
    // TRANSLATED it, so a proxy with no view map sends byte-identical requests.
    const mapped = origin && opts.toHumanView ? opts.toHumanView(origin) : undefined;
    const originHuman = mapped && mapped !== origin ? mapped : undefined;
    // …and every string of the call's input (plan 10 §11.11: an unmapped
    // tool's paths may sit under any key; a user label is keyed in HumanView).
    const paramsHuman = opts.toHumanView ? toHumanViewParams(args, opts.toHumanView) : undefined;

    // The exec gate's own notice (plan 10 §11.8): a call this proxy rewrote
    // to the block sentinel returns the notice the proxy composed, which the
    // model already reads in its own (rewritten) call. The classify verdict
    // cannot tell (its path scan reads the sentinel command, and a notice
    // saying "secret" matches the catalog). Forwarded in clear ONLY when the
    // output is exactly the runtime header and the notice, and the value
    // backstop finds no registered value in the notice; the header is
    // R4-blanked and the notice is the proxy's own string. Anything else
    // takes the classify path below, whole.
    // The unmapped upload leg's notice (unmapped-upload.ts): the call reached
    // the agent with a path that names no file, so its output is only the
    // tool's error about that. REPLACED by the proxy's own notice, no byte of
    // the tool's output forwarded, once the value backstop finds no
    // registered value in the notice; otherwise the classify path below.
    const uploadNotice = fco.type === "function_call_output" ? opts.uploadNotices?.noticeFor(fco.call_id) : undefined;
    if (uploadNotice !== undefined) {
      let clean = false;
      if (arbiter.scanSecretValues) {
        try {
          clean = (await arbiter.scanSecretValues(uploadNotice)).hits.length === 0;
        } catch (err) {
          opts.log?.(`upload notice ${fco.call_id}: the value backstop failed (${(err as Error).message}); the output is classified`);
        }
      }
      if (clean) {
        const value = flattenOutput(fco.output);
        fco.output = uploadNotice as never;
        rewrites.push({
          callId: fco.call_id,
          tool: toolName,
          trust: "TRUSTED",
          symbolized: false,
          value,
          origin,
          forwardedText: uploadNotice,
          reason: "mandu notice: the unmapped upload leg withheld a local path of this call; the output is replaced by Mandu's notice, no byte of the tool's output forwarded (guarantees.md §3)",
        });
        continue;
      }
    }

    const gateNotice = opts.execGateNotices?.noticeFor(fco.call_id);
    if (gateNotice !== undefined) {
      const out = gateNoticeOutput(fco, toolName, gateNotice, opts.execGateNotices?.wholeCell?.(fco.call_id) === true);
      let clean = false;
      if (out !== null && arbiter.scanSecretValues) {
        try {
          clean = (await arbiter.scanSecretValues(gateNotice)).hits.length === 0;
        } catch (err) {
          opts.log?.(`exec-gate notice ${fco.call_id}: the value backstop failed (${(err as Error).message}); the output is classified`);
        }
      }
      if (out !== null && clean) {
        const value = flattenOutput(fco.output);
        fco.output = out.output as never;
        rewrites.push({
          callId: fco.call_id,
          tool: toolName,
          trust: "TRUSTED",
          symbolized: false,
          value,
          origin,
          forwardedText: out.text,
          reason: "exec gate notice: the output is exactly the block sentinel's, Mandu's own text, forwarded in clear under the R4-blanked header (plan 10 §11.8)",
        });
        continue;
      }
    }

    // A Codex MCP result (a namespaced call): classify the tool's own text
    // alone under the tool's name; the runtime header rides only if the
    // arbiter vouches for it on ITS own bytes. Anything else about it (the
    // body UNTRUSTED or secret, the header refused, a classify failure) takes
    // the symbolize path below, whole or body-only.
    const mcp = toolName.startsWith("mcp__") && fco.type === "function_call_output" ? splitCodexMcpOutput(fco.output) : null;
    // The process leg's answer, when the MCP branch below already asked.
    let precomputedTaint: SecretTaintInfo | null | undefined;
    if (mcp && mcp.body !== "") {
      const ask = (v: string) => arbiter.classify({ tool: toolName, value: v, boundary: "model_context", ...(sessionKey ? { sessionKey } : {}), params: args, ...(paramsHuman ? { paramsHuman } : {}), ...(workdirDefault ? { workdirDefault } : {}) });
      let bodyVerdict: Awaited<ReturnType<typeof arbiter.classify>>;
      let headerVerdict: Awaited<ReturnType<typeof arbiter.classify>> | null = null;
      try {
        bodyVerdict = await ask(mcp.body);
        headerVerdict = await ask(mcp.header).catch(() => null);
      } catch (err) {
        throw new RewriteRefusal(`arbiter classify failed for call_id=${fco.call_id} (tool=${toolName}) — refusing to forward un-symbolized content`, err);
      }
      // Plan 10 §11.12 on this path too (found with §11.13, 2026-10-02): an
      // MCP tool whose input carries a command is asked about as
      // `unmappedTool` BEFORE the trusted shortcut below. Until then a
      // namespaced call whose header and body both classified TRUSTED (every
      // call in `secrets`, integrity off) returned here without the ask, so a
      // listed reader's output behind an MCP `run_command` reached the model
      // raw. Raise-only: a mask makes the body secret; the note explains.
      const mcpTaint = await processTaintFor(arbiter, ref, toolName, fco.call_id, args, origin, sessionKey, mcp.body, opts.log);
      precomputedTaint = mcpTaint;
      if (mcpTaint?.maskWhole) {
        bodyVerdict = { ...bodyVerdict, confidentiality: stricterLevel(bodyVerdict.confidentiality, mcpTaint.level), reason: `${bodyVerdict.reason}; ${mcpTaint.why}` };
      }
      const headerOk = headerVerdict?.trust === "TRUSTED" && !isSecretLevel(headerVerdict.confidentiality);
      const bodyOk = bodyVerdict.trust === "TRUSTED" && !isSecretLevel(bodyVerdict.confidentiality);
      if (headerOk && bodyOk) {
        clearIds.push(fco.call_id);
        rewrites.push({ callId: fco.call_id, tool: toolName, trust: "TRUSTED", symbolized: false, value: mcp.body, origin, reason: `${bodyVerdict.reason}; codex MCP header kept verbatim` });
        appendMcpSecretNote(fco, rewrites[rewrites.length - 1]!, mcpTaint, mcp.form);
        continue;
      }
      if (headerOk) {
        let symbol: string;
        try {
          symbol = await arbiter.symbolize({
            tool: toolName, value: mcp.body, origin, callId: fco.call_id, sessionKey,
            ...(isSecretLevel(bodyVerdict.confidentiality)
              ? { confidentiality: bodyVerdict.confidentiality, integrity: bodyVerdict.trust === "TRUSTED" ? "trusted" : "untrusted" }
              : {}),
          });
        } catch (err) {
          throw new RewriteRefusal(`arbiter symbolize failed for call_id=${fco.call_id} (tool=${toolName}) — refusing to forward un-symbolized content`, err);
        }
        // Plan 13 §9 R4: a secret body's header carries no fact about the run.
        const header = isSecretLevel(bodyVerdict.confidentiality) ? blankRunFacts(mcp.header) : mcp.header;
        fco.output = (mcp.form === "string"
          ? `${header}\n${symbol}`
          : [{ type: "input_text", text: header }, { type: "input_text", text: symbol }]) as never;
        rewrites.push({
          callId: fco.call_id, tool: toolName, trust: bodyVerdict.trust, symbolized: true, symbol, value: mcp.body, origin,
          symbolizedSpan: mcp.body,
          keptVerbatim: header,
          ...(isSecretLevel(bodyVerdict.confidentiality) ? { confidentiality: bodyVerdict.confidentiality } : {}),
          reason: `${bodyVerdict.reason}; codex MCP header kept verbatim`,
        });
        appendMcpSecretNote(fco, rewrites[rewrites.length - 1]!, mcpTaint, mcp.form);
        if (isSecretLevel(bodyVerdict.confidentiality) && afterFact(fco.call_id)) {
          appendAfterTheFactNote(fco, rewrites[rewrites.length - 1]!, afterTheFactLine({ taintCause: mcpTaint?.maskWhole === true, harnessRead: false }), mcp.form);
        }
        continue;
      }
      // The header is not vouched for: fall through, the whole value
      // symbolizes (with the taint already read: asked once per output).
    }

    const value = flattenOutput(fco.output);
    // Empty output → nothing to classify.
    if (value === "") {
      rewrites.push({
        callId: fco.call_id,
        tool: toolName,
        trust: "TRUSTED",
        symbolized: false,
        value,
        origin,
      });
      continue;
    }

    // Plan 10 §4.2: the call's process taint, asked BEFORE classify
    // (2026-10-18, clean-tree-release.md R3; the Claude proxy has since
    // 2026-10-04): this ask, on the human socket, binds the call to its
    // shell, and the classify's clean-tree release reads that binding.
    let secretTaint = precomputedTaint !== undefined
      ? precomputedTaint
      : await processTaintFor(arbiter, ref, toolName, fco.call_id, args, origin, sessionKey, value, opts.log);
    let verdict;
    try {
      verdict = await arbiter.classify({
        tool: toolName,
        value,
        boundary: "model_context",
        origin,
        ...(originHuman ? { originHuman } : {}),
        ...(paramsHuman ? { paramsHuman } : {}),
        ...(workdirDefault ? { workdirDefault } : {}),
        ...(sessionKey ? { sessionKey } : {}),
        // clean-tree-release.md R3: the call whose recorded tree the
        // arbiter's release reads (not `callId`, which would move this
        // classify's relative paths to the guard's start directory)
        treeCallId: fco.call_id,
        params: args,
      });
    } catch (err) {
      throw new RewriteRefusal(
        `arbiter classify failed for call_id=${fco.call_id} (tool=${toolName}) — refusing to forward un-symbolized content`,
        err,
      );
    }
    // Plan 15 §4.1: the verdict as the arbiter answered it, before any raise
    // of this proxy's own (`backstopOnly` below).
    const classified = verdict;

    // Confidentiality (plan 3, §7 row ①): a secret-labeled datum is
    // symbolized EVEN when integrity-TRUSTED. With the arbiter axis OFF the
    // classify result carries no level field, so this seam is inert.
    // Plan 10 §4.2: the confidentiality taint of the process tree behind an
    // exec_command call. A tainted tree under rule (i) makes the WHOLE result
    // a secret datum at the taint's level (the classify verdict is raised,
    // never lowered by a taint); rule (ii)/(iii) release it unless the
    // verbatim-value backstop (or a mask regex) hits. A tree that read NO
    // secret and had an open refused lowers the classify verdict's
    // path-derived level (the command NAMES the file), with the backstop
    // clean: the program's own failure text goes through and the
    // denied/held note explains it (§11.8; same seam as the Claude proxy).
    // (`secretTaint` was asked above, before classify.)
    if (userShellUnparsed.has(fco.call_id)) {
      secretTaint = {
        level: "no-model", files: [], apps: [], rule: "secret", maskWhole: true, denied: [], deniedOnly: false,
        why: "a shell command the user ran whose record Mandu could not read as a command and its output; the whole record is secret",
      };
    }
    if (secretTaint?.maskWhole) {
      verdict = { ...verdict, confidentiality: stricterLevel(verdict.confidentiality, secretTaint.level), reason: `${verdict.reason}; ${secretTaint.why}` };
    } else if ((secretTaint?.deniedOnly || secretTaint?.twinOnly) && isSecretLevel(verdict.confidentiality)) {
      const { confidentiality: lowered, ...rest } = verdict;
      verdict = { ...rest, reason: `${verdict.reason}; plan 10: the ${lowered} path-derived mask is lowered (${secretTaint.why})` };
    } else if (secretTaint?.twinOnly && (secretTaint.twinKeys || secretTaint.twinOwn || secretTaint.dirListing)) {
      // "A key listing" (plan 10 §11.8): nothing was masked (the
      // command names no secret path), so there is nothing to lower and no
      // `twin:` line to add to a result that merely reads like keys.
      // "A folder's names": likewise, an `ls` of folders no label covers
      // is forwarded as it is, with no `listing:` line.
      secretTaint = { ...secretTaint, twinOnly: false };
    }
    const untrusted = verdict.trust === "UNTRUSTED";
    // A non-text output (an image part, a structured object) is never
    // released in part: flattenOutput renders it as JSON text, bytes and all.
    const textOnly = typeof fco.output === "string" || (Array.isArray(fco.output) && fco.output.every(isInputTextPart));
    // clean-tree-release.md §2, rules Q1-Q3 (same seam as the Claude proxy):
    // the arbiter's release of a shell result masked only because its
    // command names a registered credential file, taken only on this proxy's
    // own evidence. With no span the verdict is lowered (forwarded as
    // received, no note); with spans it goes as a value-only release below.
    let pathOffer: ReturnType<typeof acceptPathReleaseOffer> = null;
    // Review round 3: a release is not recorded as forwarded in clear (as the
    // value-only release is not, backstop-value-only.md §4 item 6), or the
    // next request's re-classify of the history would refuse it as masked
    // after the fact and turn it into a symbol.
    let pathReleased = false;
    // A plain call only: never a script cell, a `wait` continuing one, or a
    // call asked another way (review round 3: a cell's other literals are
    // covered only by the session fold).
    const plainCall = ref === undefined || (ref.foldSession !== true && ref.taintVia === undefined && ref.taint === undefined && ref.raiseOnly !== true);
    if (isSecretLevel(verdict.confidentiality) && !untrusted && textOnly && plainCall && classified.raisedBy === undefined &&
        verdict.confidentiality === classified.confidentiality && valueOnlyEvidenceClean(secretTaint) &&
        !userShellUnparsed.has(fco.call_id) && !afterFact(fco.call_id)) {
      pathOffer = acceptPathReleaseOffer(value, classified);
      if (pathOffer !== null && pathOffer.values.length === 0) {
        pathReleased = true;
        if (pathOffer.listing) {
          // folder-listing-compound.md: the `listing:` line, naming the operands
          // the model's own command holds verbatim
          const command = callCommandText(toolName, args) ?? "";
          const operands = pathOffer.listing.operands.filter((x) => command.includes(x)).slice(0, 8);
          secretTaint = {
            level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false,
            twinOf: operands.length > 0 ? operands : ["the folders it named"], twinOnly: true, dirListing: true, dirListingPart: pathOffer.listing.part,
            why: "a folder's names beside another command",
          };
        }
        const { confidentiality: lowered, ...rest } = verdict;
        verdict = { ...rest, reason: pathOffer.listing
          ? `${verdict.reason}; a folder's names beside another command: the ${lowered} path-derived mask is lowered (the call's recorded tree read no secret, the ${pathOffer.listing.part} lines are exactly ls's names, and the other commands name no secret path)`
          : `${verdict.reason}; clean-tree release: the ${lowered} path-derived mask is lowered (the call's recorded tree read no secret, and the output holds no secret byte of the credential files the command names)` };
        pathOffer = null;
      }
    }
    const secret = isSecretLevel(verdict.confidentiality);
    // backstop-value-only.md §3: the arbiter's value-only offer, taken only
    // when this proxy's own evidence says the call read no secret (rules
    // P1-P3; same seam as the Claude proxy). Otherwise masked whole below.
    // A clean-tree release with spans (above) takes the same exit.
    const offer = pathOffer ?? (secret && !untrusted && textOnly && classified.raisedBy === "value-backstop" &&
        verdict.confidentiality === classified.confidentiality && valueOnlyEvidenceClean(secretTaint) &&
        !userShellUnparsed.has(fco.call_id) && !afterFact(fco.call_id)
      ? acceptValueOnlyOffer(value, classified)
      : null);
    if (offer !== null) {
      setOutput(fco, offer.text);
      rewrites.push({
        callId: fco.call_id,
        tool: toolName,
        trust: "TRUSTED",
        symbolized: true,
        symbol: offer.values[0]!.symbol,
        value,
        forwardedText: offer.text,
        valueOnly: offer.values,
        origin,
        ...(verdict.confidentiality ? { confidentiality: verdict.confidentiality } : {}),
        reason: `${verdict.reason}; ${pathOffer !== null ? "clean-tree" : "value-only"} release: ${offer.values.length} registered value(s) replaced by their symbols, the rest released`,
      });
      continue;
    }
    // Plan 15 §4.1, "What a raised row registers" (same seam as the Claude
    // proxy): secret only by the arbiter's value backstop, raised no further
    // here. Said on the whole-output symbolize; the arbiter checks its own
    // record of the classify before it registers less.
    // Plan 15 §13.12, "What a path row registers": secret only by the
    // classify's own path-derived level (no backstop raise) and raised no
    // further here (no taint mask, no unparsed user shell). Said on the
    // whole-output symbolize; the arbiter checks its own records (the path
    // rule alone, the call's tree, the files registered as they are)
    // before it registers fewer lines. The mask is unchanged.
    const backstopOnly: { secretBy?: "value-backstop" | "path-rule" } =
      secret && classified.raisedBy === "value-backstop" && !secretTaint?.maskWhole &&
      verdict.confidentiality === classified.confidentiality
        ? { secretBy: "value-backstop" }
        : secret && classified.raisedBy === undefined && isSecretLevel(classified.confidentiality) && !secretTaint?.maskWhole &&
            verdict.confidentiality === classified.confidentiality
          ? { secretBy: "path-rule" }
          : {};
    // Confidentiality §7.1, the path-derived note (same seam as the Claude
    // proxy): a result masked whole only because the command NAMES a secret
    // path says so, naming the paths as the model wrote them; no output byte.
    // The value-backstop note (same seam as the Claude proxy): a result the
    // arbiter's value backstop raised names no secret path, so it gets its
    // own line instead of the path-derived advice.
    if (secret && !secretTaint?.maskWhole && classified.raisedBy === "value-backstop") {
      secretTaint = secretTaint
        ? { ...secretTaint, valueBackstop: true }
        : { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, valueBackstop: true, why: "a registered secret's value is in the output" };
    } else if (secret && !secretTaint?.maskWhole) {
      const command = callCommandText(toolName, args);
      if (command !== null) {
        const paths = pathDerivedPaths(verdict.namedPaths, command);
        const twins = pathDerivedTwins(verdict.namedTwins, paths);
        const pathDerived = twins.length > 0 ? { paths, twins } : { paths };
        secretTaint = secretTaint
          ? { ...secretTaint, pathDerived }
          : { level: "public", files: [], apps: [], rule: "secret", maskWhole: false, denied: [], deniedOnly: false, pathDerived, why: "the command names a secret path" };
      }
    }
    // The path-derived line ("do not assume it worked") is for an output
    // never seen: an output masked after the fact gets that note instead.
    const afterFactLine = secret && afterFact(fco.call_id)
      ? afterTheFactLine({ taintCause: secretTaint?.maskWhole === true, harnessRead: false })
      : null;
    if (afterFactLine && (secretTaint?.pathDerived || secretTaint?.valueBackstop)) {
      const { pathDerived: _dropped, valueBackstop: _dropped2, ...rest } = secretTaint;
      secretTaint = rest;
    }
    if (untrusted || secret) {
      // The codex exec envelope dual (2026-09-05): when the arbiter trusts the
      // split-off header on its own bytes, only the command's output is
      // symbolized and the header rides verbatim. The output is never
      // forwarded raw here; a header the arbiter does not vouch for keeps the
      // whole-value path below.
      const split = typeof fco.output === "string" || Array.isArray(fco.output) ? splitCodexExecEnvelope(value) : null;
      if (split) {
        let envVerdict: Awaited<ReturnType<typeof arbiter.classify>> | null = null;
        try {
          envVerdict = await arbiter.classify({
            tool: toolName,
            value: split.envelope,
            boundary: "model_context",
            origin,
            ...(originHuman ? { originHuman } : {}),
            ...(paramsHuman ? { paramsHuman } : {}),
            ...(workdirDefault ? { workdirDefault } : {}),
            ...(sessionKey ? { sessionKey } : {}),
            params: args,
          });
        } catch {
          envVerdict = null; // strictly safer: the whole value symbolizes
        }
        if (envVerdict?.trust === "TRUSTED" && !isSecretLevel(envVerdict.confidentiality)) {
          // Trailing whitespace is framing (codex ends the output with the
          // command's own newline): on the wire, not in the value, so a
          // one-line output stays a one-line value.
          const bodyText = split.body.replace(/\s+$/, "");
          const sep = split.body.slice(bodyText.length);
          let bodySymbol: string;
          try {
            bodySymbol = await arbiter.symbolize({
              tool: toolName,
              value: bodyText,
              origin,
              ...(originHuman ? { originHuman } : {}),
              callId: fco.call_id,
              sessionKey,
              ...(secret
                ? { confidentiality: verdict.confidentiality, integrity: !untrusted ? "trusted" : "untrusted" }
                : {}),
            });
          } catch (err) {
            throw new RewriteRefusal(
              `arbiter symbolize failed for call_id=${fco.call_id} (tool=${toolName}) — refusing to forward un-symbolized content`,
              err,
            );
          }
          // Plan 13 §9 R4: a secret body's header carries no fact about the run.
          const envelope = secret ? blankRunFacts(split.envelope) : split.envelope;
          const forwarded = `${envelope}${bodySymbol}${sep}`;
          setOutput(fco, forwarded);
          rewrites.push({
            callId: fco.call_id,
            tool: toolName,
            trust: untrusted ? "UNTRUSTED" : "TRUSTED",
            symbolized: true,
            symbol: bodySymbol,
            value,
            origin,
            symbolizedSpan: bodyText,
            keptVerbatim: envelope,
            forwardedText: forwarded,
            ...(secret ? { confidentiality: verdict.confidentiality } : {}),
            reason:
              (!untrusted && secret
                ? `secret content (${verdict.confidentiality}) symbolized by provenance: ${verdict.reason}`
                : verdict.reason) +
              `; codex exec envelope kept verbatim (${envVerdict.reason})`,
          });
          appendSecretNote(fco, rewrites[rewrites.length - 1]!, secretTaint);
          if (afterFactLine) appendAfterTheFactNote(fco, rewrites[rewrites.length - 1]!, afterFactLine);
          continue;
        }
      }
      let symbol: string;
      try {
        symbol = await arbiter.symbolize({
          tool: toolName,
          value,
          origin,
          ...(originHuman ? { originHuman } : {}),
          callId: fco.call_id,
          sessionKey,
          // Plan 10 §11.14: `value` is Codex's whole output for a call it
          // made, so whatever head starts it is the one Codex's runtime
          // wrote (a command's bytes come after `Output:`). The arbiter
          // matches that head by its own grammar at offset 0 and does not
          // fingerprint its lines; the split path above (body only) never
          // says so, so a body that starts like a head keeps every line. An
          // MCP result masked whole (its header not vouched for) names
          // Codex's MCP head the same way (2026-10-09).
          ...((): { resultHead?: "codex" | "codex-mcp" | "write-notice" } => {
            const kind = codexResultHeadKind(fco, ref !== undefined, toolName);
            return kind ? { resultHead: kind } : {};
          })(),
          ...backstopOnly,
          ...(secret
            ? {
                confidentiality: verdict.confidentiality,
                integrity: !untrusted ? "trusted" : "untrusted",
              }
            : {}),
        });
      } catch (err) {
        throw new RewriteRefusal(
          `arbiter symbolize failed for call_id=${fco.call_id} (tool=${toolName}) — refusing to forward un-symbolized content`,
          err,
        );
      }
      // Replace the output with the opaque symbol, in the item's own wire
      // shape (setOutput): a string, or one text part — either way any
      // structured attacker payload is dropped with the original.
      setOutput(fco, symbol);
      rewrites.push({
        callId: fco.call_id,
        tool: toolName,
        // A TRUSTED×secret result keeps its integrity verdict on the audit —
        // it was symbolized by PROVENANCE (confidentiality), not distrust.
        trust: untrusted ? "UNTRUSTED" : "TRUSTED",
        symbolized: true,
        symbol,
        value,
        origin,
        ...(secret ? { confidentiality: verdict.confidentiality } : {}),
        reason:
          !untrusted && secret
            ? `secret content (${verdict.confidentiality}) symbolized by provenance: ${verdict.reason}`
            : verdict.reason,
      });
      appendSecretNote(fco, rewrites[rewrites.length - 1]!, secretTaint);
      if (afterFactLine) appendAfterTheFactNote(fco, rewrites[rewrites.length - 1]!, afterFactLine);
    } else {
      // TRUSTED → pass through unchanged (plus the plan 10 note, if any).
      if (!pathReleased) clearIds.push(fco.call_id);
      rewrites.push({
        callId: fco.call_id,
        tool: toolName,
        trust: "TRUSTED",
        symbolized: false,
        value,
        origin,
        reason: verdict.reason,
      });
      appendSecretNote(fco, rewrites[rewrites.length - 1]!, secretTaint);
    }
  }

  // The user shell records go back into their messages, carrying what the
  // walk made of their outputs.
  restoreUserShells(input, userShells);

  // Prepend the handling system prompt to `instructions` (unless told to skip or
  // already present). The Responses API carries the system prompt as the
  // `instructions` STRING, so we concatenate rather than push a system block.
  if (!skipPromptInjection && !alreadyInjected(req.instructions)) {
    let prompt: string;
    try {
      const r = await arbiter.handlingPrompt({
        ...(handlingMode ? { mode: handlingMode } : {}),
        capabilities: detectCapabilities(advertisedTools(req), opts.secretPosture ? { secretPosture: opts.secretPosture } : {}),
        // Plan 11 phase 3 (§7.2 for Codex): the arbiter reads this session's
        // main-model binding to say whether declassify_symbol can open a
        // localmodel_ symbol.
        ...(sessionKey ? { sessionKey } : {}),
      });
      prompt = r.prompt;
    } catch (err) {
      throw new RewriteRefusal(
        "arbiter handlingPrompt failed — refusing to forward (T-LLM would not know symbols are opaque)",
        err,
      );
    }
    const marked = `${HANDLING_MARKER}\n${prompt}`;
    req.instructions =
      typeof req.instructions === "string" && req.instructions.length > 0
        ? `${marked}\n\n${req.instructions}`
        : marked;
  }

  // Confidentiality §7.1, "Masked after the fact": while any output carries
  // the line, Mandu's own note in the instructions says what the model's
  // transcript no longer shows (static text, appended once).
  if (!skipPromptInjection && rewrites.some((r) => r.afterTheFact)
      && !(typeof req.instructions === "string" && req.instructions.includes(AFTER_THE_FACT_MARKER))) {
    req.instructions = typeof req.instructions === "string" && req.instructions.length > 0
      ? `${req.instructions}\n\n${AFTER_THE_FACT_SYSTEM_NOTE}`
      : AFTER_THE_FACT_SYSTEM_NOTE;
  }

  await opts.clearResults?.remember(clearIds);
  return { request: req, rewrites, ...(promptFilter ? { promptFilter } : {}) };
}
