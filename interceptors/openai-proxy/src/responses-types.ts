/**
 * responses-types — the subset of the OpenAI Responses API the proxy parses.
 *
 * Mandu Track A (interceptors/openai-proxy). These mirror the public
 * `POST /v1/responses` request shape as the Codex CLI (codex 0.136) emits it. We
 * model only the fields the proxy must read or rewrite (instructions, input, and
 * the function_call / function_call_output items); everything else is preserved
 * verbatim via index signatures so we never drop unknown fields when we
 * re-serialize the rewritten request.
 *
 * Ground truth (verified against codex 0.136, wire_api="responses"):
 *   Request body keys: model, instructions, input, tools, tool_choice,
 *   parallel_tool_calls, reasoning, store, stream, include, prompt_cache_key,
 *   client_metadata.
 *   - `instructions` is the system-prompt STRING.
 *   - `input[]` holds the conversation as items:
 *       {type:"message", role, content:[{type:"input_text", text}]}
 *     and, on the follow-up turn:
 *       {type:"function_call", call_id, name, arguments}
 *       {type:"function_call_output", call_id, output}
 *   - THE UNTRUSTED INGRESS (turn 2): the `output` field of every
 *     function_call_output item — the raw stdout of the agent's shell tool.
 *
 * The SCRIPT-CELL wire (verified against codex 0.154, 2026-09-24; the
 * `code_mode_host` / `unified_exec` features, stable and ON by default, and
 * the only wire the shell runs on — disabling them leaves the model emitting
 * the same cell into a host that answers "code-mode host is disabled"):
 *   - the tool battery no longer rides `tools`; it is an `input[]` item
 *       {type:"additional_tools", id, role, tools:[{type:"namespace", name,
 *        tools:[{type:"custom", name:"exec", …}, {type:"function", name:"wait", …}]}]}
 *   - the shell is a CUSTOM tool, `exec`, whose payload is JavaScript:
 *       {type:"custom_tool_call", call_id, name:"exec",
 *        input:'const r = await tools.exec_command({"cmd":"cat notes.md","workdir":"/…",
 *               "yield_time_ms":10000,"max_output_tokens":2000});\ntext(r.output);\n'}
 *     streamed as response.custom_tool_call_input.delta / .done;
 *   - its result is {type:"custom_tool_call_output", call_id,
 *       output:[{type:"input_text", text:"Script completed\nWall time 0.2 seconds\nOutput:\n"},
 *               {type:"input_text", text:"<the command's bytes>"}]}
 *     — THE UNTRUSTED INGRESS of this wire, an ARRAY of text parts whose
 *     first part is the runtime's envelope and whose rest is the output.
 *   Both wires are handled (an older codex still speaks the first).
 */

/** A message item in `input[]` (system/user/assistant turn text). */
export interface MessageItem {
  type: "message";
  role: string;
  content: unknown;
  [k: string]: unknown;
}

/** A function_call item: the model's tool-call decision (Codex: exec_command). */
export interface FunctionCallItem {
  type: "function_call";
  call_id: string;
  name: string;
  /** Codex 0.154 MCP tools: the tool's server namespace (`mcp__<server, - → _>`),
   *  with `name` the tool's own name. Absent for Codex's built-in tools. */
  namespace?: string;
  /** JSON-encoded arguments string, e.g. '{"cmd":"cat notes.md"}'. */
  arguments?: string;
  id?: string;
  status?: string;
  [k: string]: unknown;
}

/**
 * A function_call_output item: a tool's output re-entering the model context.
 * `output` is the RAW command stdout (the untrusted ingress this proxy must
 * symbolize). It is normally a string; we tolerate the structured-output variant
 * defensively.
 */
export interface FunctionCallOutputItem {
  type: "function_call_output";
  call_id: string;
  output: string | unknown;
  id?: string;
  [k: string]: unknown;
}

/**
 * A custom_tool_call item (codex ≥ 0.154): the model's `exec` script cell. The
 * shell command lives INSIDE `input` as the JSON argument object of a
 * `tools.exec_command({…})` call (script-cell.ts).
 */
export interface CustomToolCallItem {
  type: "custom_tool_call";
  call_id: string;
  name: string;
  /** The JavaScript source of the cell. */
  input?: string;
  id?: string;
  status?: string;
  [k: string]: unknown;
}

/** One text part of a custom_tool_call_output array. */
export interface InputTextPart {
  type: "input_text";
  text: string;
  [k: string]: unknown;
}

/**
 * A custom_tool_call_output item: the script cell's result re-entering the
 * model context — the untrusted ingress of the 0.154 wire. `output` is an
 * ARRAY of parts on that wire (envelope part, then the output); a string is
 * tolerated (the API accepts both).
 */
export interface CustomToolCallOutputItem {
  type: "custom_tool_call_output";
  call_id: string;
  output: string | InputTextPart[] | unknown;
  id?: string;
  [k: string]: unknown;
}

/** The inlined tool battery (codex ≥ 0.154): namespaces of tools in `input[]`. */
export interface AdditionalToolsItem {
  type: "additional_tools";
  tools?: unknown[];
  id?: string;
  [k: string]: unknown;
}

/** Any `input[]` item. The proxy preserves unknown item types verbatim. */
export type InputItem =
  | MessageItem
  | FunctionCallItem
  | FunctionCallOutputItem
  | CustomToolCallItem
  | CustomToolCallOutputItem
  | AdditionalToolsItem
  | ({ type: string } & Record<string, unknown>);

/** Either wire's tool-output item: the untrusted ingress the rewrite walks. */
export type ToolOutputItem = FunctionCallOutputItem | CustomToolCallOutputItem;

/** The subset of the Responses request the proxy reads/rewrites. */
export interface ResponsesRequest {
  model?: string;
  /** The system-prompt string. The proxy prepends the handling prompt to it. */
  instructions?: string;
  /** The conversation items. function_call_output items are symbolized. */
  input?: InputItem[];
  tools?: unknown[];
  stream?: boolean;
  [k: string]: unknown;
}

// ── Type guards ───────────────────────────────────────────────────────────────

export function isMessageItem(b: unknown): b is MessageItem {
  return !!b && typeof b === "object" && (b as { type?: string }).type === "message";
}

export function isFunctionCallItem(b: unknown): b is FunctionCallItem {
  return !!b && typeof b === "object" && (b as { type?: string }).type === "function_call";
}

export function isFunctionCallOutputItem(b: unknown): b is FunctionCallOutputItem {
  return (
    !!b && typeof b === "object" && (b as { type?: string }).type === "function_call_output"
  );
}

export function isCustomToolCallItem(b: unknown): b is CustomToolCallItem {
  return !!b && typeof b === "object" && (b as { type?: string }).type === "custom_tool_call";
}

export function isCustomToolCallOutputItem(b: unknown): b is CustomToolCallOutputItem {
  return (
    !!b && typeof b === "object" && (b as { type?: string }).type === "custom_tool_call_output"
  );
}

export function isAdditionalToolsItem(b: unknown): b is AdditionalToolsItem {
  return !!b && typeof b === "object" && (b as { type?: string }).type === "additional_tools";
}

/** A tool output of either wire (function_call_output | custom_tool_call_output). */
export function isToolOutputItem(b: unknown): b is ToolOutputItem {
  return isFunctionCallOutputItem(b) || isCustomToolCallOutputItem(b);
}

/**
 * Every tool definition a request advertises, whichever wire: the top-level
 * `tools` array (codex ≤ 0.136) plus the `additional_tools` input item's
 * namespaces flattened (codex ≥ 0.154: `{type:"namespace", tools:[…]}` —
 * a namespace's own entry is not a tool). Never throws; malformed entries are
 * skipped.
 */
export function advertisedTools(req: ResponsesRequest): unknown[] {
  const out: unknown[] = [];
  if (Array.isArray(req.tools)) out.push(...req.tools);
  if (Array.isArray(req.input)) {
    for (const item of req.input) {
      if (!isAdditionalToolsItem(item) || !Array.isArray(item.tools)) continue;
      for (const t of item.tools) {
        if (!t || typeof t !== "object") continue;
        const rec = t as { type?: unknown; tools?: unknown };
        if (rec.type === "namespace" && Array.isArray(rec.tools)) out.push(...rec.tools);
        else out.push(t);
      }
    }
  }
  return out;
}
