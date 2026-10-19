/**
 * mcp-server — a thin, hand-rolled MCP stdio JSON-RPC server exposing
 * `inspect_symbol` (rung 2) and `declassify_symbol` (rung 3, relayed through
 * declassify-symbol.ts).
 *
 * Mandu M4 cooperative U-LLM path (interceptors/inspect-mcp). Per
 * docs/design/architecture/implementation-plan.md §7, the cooperative path for Claude Code is
 * to expose `inspect_symbol` as an MCP tool and steer the agent toward it via
 * the injected handling system prompt (Track A). Claude Code launches this as an
 * stdio MCP server and speaks JSON-RPC 2.0 over newline-delimited frames.
 *
 * Zero deps by design: the MCP surface we need is tiny — `initialize`,
 * `tools/list`, `tools/call` — so we implement the JSON-RPC handling directly
 * rather than pulling in @modelcontextprotocol/sdk. The protocol logic
 * (handleRpc) is pure and unit-testable; the stdio loop (runStdioServer) is the
 * only I/O.
 *
 * SECURITY: the server is a SHELL around inspect-symbol.ts. All the security
 * (resolve → quarantined U-LLM → re-symbolize → fail-closed) lives in the core;
 * `tools/call` returns ONLY the re-symbolized result symbol (or a T-LLM-safe
 * error), never raw untrusted text.
 */

import { createInterface } from "node:readline";
import {
  inspectSymbol,
  NEXT_STEP_BY_KIND,
  type InspectSymbolDeps,
  type InspectSymbolParams,
} from "./inspect-symbol.js";
import { declassifySymbol } from "./declassify-symbol.js";

// MCP / JSON-RPC version constants.
const JSONRPC_VERSION = "2.0";
const MCP_PROTOCOL_VERSION = "2024-11-05";
const SERVER_NAME = "mandu-inspect-symbol";
const SERVER_VERSION = "0.2.0-beta.7"; // one product version: scripts/set-version.sh rewrites this line

// JSON-RPC error codes (subset).
const ERR_PARSE = -32700;
const ERR_INVALID_REQUEST = -32600;
const ERR_METHOD_NOT_FOUND = -32601;
const ERR_INVALID_PARAMS = -32602;
const ERR_INTERNAL = -32603;

export interface JsonRpcRequest {
  jsonrpc: string;
  id?: string | number | null;
  method: string;
  params?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: string;
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

/** The single tool definition advertised by tools/list. */
export const INSPECT_SYMBOL_TOOL = {
  name: "inspect_symbol",
  description:
    "Process the untrusted data behind an opaque $MDU:* symbol WITHOUT " +
    "revealing it. Use this whenever you need to summarize, extract from, " +
    "translate, or transform content for delivery. It cannot reveal content to you. The " +
    "data is processed by a quarantined model in isolation and the result is " +
    "returned as a NEW opaque symbol (the raw text never enters this " +
    "conversation). Provide exactly one of 'symbol' for one input or 'symbols' " +
    "for ALL inputs to a merge, join, comparison, or validation. Include every " +
    "original needed; mentioning another file in the instruction does not supply it. " +
    "For a JSON artifact, set output_format to json; the quarantine validates JSON before sealing it. " +
    "Ask for the final artifact, then pass result_symbol directly to Write.content. " +
    "Provide an 'instruction' " +
    "describing what you need (e.g. 'summarize in 2-3 sentences', 'extract the " +
    "author and title', 'translate to English'). State WHAT information you " +
    "need, not what format you assume the data has — you have not seen it, " +
    "and a wrong format guess degrades the answer. The result also carries " +
    "'content_kind' — the system's own verdict on what the inspected content " +
    "IS: 'as_requested' (matches what the source tool call asked for), " +
    "'wrong_content' (real content but NOT what was asked), 'substantive' " +
    "(real content; request-match not assessed), 'error_or_refusal', " +
    "'auth_wall', 'empty', or 'unknown' (no signal). On 'error_or_refusal', " +
    "'empty', or 'wrong_content', the SOURCE tool call likely failed or " +
    "fetched the wrong thing — re-run that source call ONCE (with corrected " +
    "parameters if apparent) and inspect the NEW symbol it returns. Do NOT " +
    "re-inspect the same symbol: its content is frozen, so every " +
    "inspect_symbol call on it sees the same failed data. On 'auth_wall' do " +
    "not retry (report it to the user); on 'unknown' proceed normally. " +
    "Levels in the symbol name: a $MDU:localmodel_* symbol is readable only by " +
    "the user's own model; inspect_symbol routes it there by itself (pass it " +
    "like any other symbol), and declassify_symbol is refused for it. A " +
    "$MDU:nomodel_* symbol is readable by no model and is refused here; route it " +
    "instead. A $MDU:anymodel_* symbol is processed normally.",
  inputSchema: {
    type: "object" as const,
    required: ["instruction"],
    additionalProperties: false,
    properties: {
      output_format: {
        type: "string", enum: ["text", "json"],
        description: "Output artifact format. Use json for JSON files; validated inside quarantine. Default text preserves bytes.",
      },
      symbols: {
        type: "array", minItems: 1, maxItems: 16, uniqueItems: true,
        items: { type: "string" },
        description: "All original input symbols needed for one transformation. For completeness checks include originals and candidate; ask for a complete corrected artifact.",
      },
      symbol: {
        type: "string",
        description:
          "The opaque symbol to inspect, e.g. '$MDU:web_fetch[a1b2]'.",
      },
      instruction: {
        type: "string",
        description:
          "What to extract or how to transform the data behind the symbol.",
      },
    },
  },
} as const;

/**
 * §3.3 RUNG 3 — the IN-CONTEXT READ (Plan 8). The SECOND tool, and the split
 * from `inspect_symbol` is the design, not an accident:
 *
 *   inspect_symbol    → rung 2. Processed in the QUARANTINE. Result comes back
 *                       as a symbol. No watermark. PREFERRED, always.
 *   declassify_symbol → rung 3. Raw content enters THIS conversation. A logged
 *                       declassification that HIGH-WATERMARKS the session, after
 *                       which every egress is gated.
 *
 * Two tools rather than one flag, so the escalation is a deliberate, named,
 * logged act the human can see and refuse — and so a refactor that forgot a flag
 * could not silently pick the dangerous path.
 *
 * The arbiter is the authority and refuses far more than it allows: an
 * UNTRUSTED datum is refused outright (raw untrusted content must never reach
 * the privileged model — the one invariant, and no approval opens it), and a
 * `no-model` one is refused outright (no model reads it, ever). What is
 * left is trusted × model-ok, which is narrow on purpose.
 */
export const DECLASSIFY_SYMBOL_TOOL = {
  name: "declassify_symbol",
  description:
    "Read an any-model symbol's REAL CONTENT into this conversation. Use " +
    "this ONLY when you must act on the content directly — branch on it, weave " +
    "it through multi-step work. If you only need to summarize, extract from, " +
    "or answer a question about it, use inspect_symbol instead: that keeps the " +
    "content out of this conversation entirely and is always preferred. This " +
    "call is a logged DECLASSIFICATION: it marks the whole session as holding " +
    "secret data, after which requests to the content's bound hosts still go " +
    "through and any other network request or shell command that could carry " +
    "the content out is stopped while Mandu asks the user on its Approvals page " +
    "(keep making calls as usual: Mandu decides each one; if it stops one, tell " +
    "the user and make the call again after they answer). It is REFUSED for $MDU:nomodel_* (no-model) symbols, for " +
    "$MDU:localmodel_* symbols (readable only by the user's own model: " +
    "inspect_symbol routes them there by itself), and for untrusted data; in " +
    "those cases use inspect_symbol (a no-model symbol is only routed). A refusal " +
    "is the system working as designed: do not retry it.",
  inputSchema: {
    type: "object" as const,
    required: ["symbol", "reason"],
    additionalProperties: false,
    properties: {
      symbol: {
        type: "string",
        description: "The any-model symbol to read, e.g. '$MDU:anymodel_Read[7b21]'.",
      },
      reason: {
        type: "string",
        description:
          "Why the content must be in this conversation rather than processed " +
          "via inspect_symbol. Shown to the user on the approval.",
      },
    },
  },
} as const;

/**
 * Pure JSON-RPC method dispatch. Returns a response for requests, or null for
 * notifications (no `id`). All errors are mapped to JSON-RPC errors; the handler
 * never throws.
 */
export async function handleRpc(
  req: JsonRpcRequest,
  deps: InspectSymbolDeps,
): Promise<JsonRpcResponse | null> {
  const id = req.id ?? null;
  const isNotification = req.id === undefined || req.id === null;

  if (req.jsonrpc !== JSONRPC_VERSION || typeof req.method !== "string") {
    if (isNotification) return null;
    return rpcError(id, ERR_INVALID_REQUEST, "invalid JSON-RPC request");
  }

  switch (req.method) {
    case "initialize":
      return ok(id, {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      });

    // Lifecycle notifications we simply acknowledge / ignore.
    case "notifications/initialized":
    case "initialized":
      return null;

    case "ping":
      return ok(id, {});

    case "tools/list":
      // Both tools are always advertised; the ARBITER is the authority on
      // whether rung 3 is available at all (it refuses when the confidentiality
      // axis is OFF, where no secret symbols exist to declassify). Gating the
      // list on a locally-held flag would put a security-relevant claim in the
      // wrong process.
      return ok(id, { tools: [INSPECT_SYMBOL_TOOL, DECLASSIFY_SYMBOL_TOOL] });

    case "tools/call":
      return handleToolsCall(id, req.params, deps);

    default:
      if (isNotification) return null;
      return rpcError(id, ERR_METHOD_NOT_FOUND, `method not found: ${req.method}`);
  }
}

async function handleToolsCall(
  id: string | number | null,
  params: unknown,
  deps: InspectSymbolDeps,
): Promise<JsonRpcResponse> {
  if (!isRecord(params) || typeof params.name !== "string") {
    return rpcError(id, ERR_INVALID_PARAMS, "tools/call requires { name, arguments }");
  }
  if (params.name === DECLASSIFY_SYMBOL_TOOL.name) {
    return handleDeclassify(id, params.arguments, deps);
  }
  if (params.name !== INSPECT_SYMBOL_TOOL.name) {
    return rpcError(id, ERR_METHOD_NOT_FOUND, `unknown tool: ${params.name}`);
  }

  const args = isRecord(params.arguments) ? params.arguments : {};
  const symbol = args.symbol as string | undefined;
  const symbols = args.symbols as string[] | undefined;
  const instruction = typeof args.instruction === "string" ? args.instruction : "";
  const callParams: InspectSymbolParams = { symbol, symbols, instruction, output_format: args.output_format as InspectSymbolParams["output_format"] };

  let result;
  try {
    result = await inspectSymbol(deps, callParams);
  } catch (err) {
    // Defensive: inspectSymbol is itself fail-closed, but never let an
    // unexpected throw escape as a leak. Report a tool error with no raw text.
    return ok(id, toolError(`inspect_symbol: internal error: ${msgOf(err)}`));
  }

  if (!result.ok) {
    // A tool-level error (unknown symbol / fail-closed). Surface it as an MCP
    // tool error so the agent sees it WITHOUT any raw untrusted text.
    return ok(id, toolError(result.error));
  }

  // Success: return ONLY the re-symbolized symbol (never raw text) plus the
  // validated content_kind triage token.
  //
  // SHAPE CONTRACT (do not drift): the arbiter's inbound data-trust policy
  // trusts this tool's result ONLY when it is pure-symbolic — exactly this
  // shape: a $MDU:* token as the content text, plus the
  // { result_symbol, model, content_kind, next_step? } envelope as
  // structuredContent (arbiter/policy/claude-code-inbound.ts,
  // classifyManduInspectResult; that's what stops the proxy from
  // re-symbolizing the already-opaque token into a double-wrapped symbol).
  // `content_kind` is a token from the closed CONTENT_KINDS vocabulary,
  // validated by inspect-symbol.ts BEFORE it gets here — raw triage model
  // text never reaches this envelope — and the policy re-constrains it
  // (INSPECT_CONTENT_KIND_RE) as defense in depth. `next_step` has a fixed directive per validated kind and its value is a FIXED TCB string from
  // NEXT_STEP_BY_KIND — the policy accepts the key only on an EXACT match
  // keyed off content_kind, so the pair adds zero attacker-controllable
  // bytes. Adding any OTHER new key or free-text value here re-enables the
  // (harmless, fail-closed) double-wrap until that rule is updated in the
  // same change. Error results (toolError) are intentionally NOT covered:
  // their strings can embed upstream error bodies that may echo the raw
  // untrusted value, so they must stay symbolized.
  const nextStep = NEXT_STEP_BY_KIND[result.contentKind];
  return ok(id, {
    content: [
      {
        type: "text",
        text: result.resultSymbol,
      },
    ],
    structuredContent: {
      result_symbol: result.resultSymbol,
      model: result.model,
      content_kind: result.contentKind,
      ...(nextStep !== undefined ? { next_step: nextStep } : {}),
    },
    isError: false,
  });
}

/**
 * Run the stdio JSON-RPC loop: read newline-delimited JSON requests on stdin,
 * write newline-delimited JSON responses on stdout. (MCP's stdio transport is
 * line-delimited JSON, not LSP-style Content-Length framing.)
 */
export function runStdioServer(
  deps: InspectSymbolDeps,
  io: { input?: NodeJS.ReadableStream; output?: NodeJS.WritableStream } = {},
): { close: () => void } {
  const input = io.input ?? process.stdin;
  const output = io.output ?? process.stdout;
  const rl = createInterface({ input, crlfDelay: Infinity });

  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    void dispatchLine(trimmed, deps, output);
  });

  return { close: () => rl.close() };
}

async function dispatchLine(
  line: string,
  deps: InspectSymbolDeps,
  output: NodeJS.WritableStream,
): Promise<void> {
  let req: JsonRpcRequest;
  try {
    req = JSON.parse(line) as JsonRpcRequest;
  } catch {
    writeResponse(output, rpcError(null, ERR_PARSE, "parse error"));
    return;
  }
  let resp: JsonRpcResponse | null;
  try {
    resp = await handleRpc(req, deps);
  } catch (err) {
    resp = rpcError(req.id ?? null, ERR_INTERNAL, msgOf(err));
  }
  if (resp) writeResponse(output, resp);
}

function writeResponse(output: NodeJS.WritableStream, resp: JsonRpcResponse): void {
  output.write(JSON.stringify(resp) + "\n");
}

/**
 * §3.3 rung 3. The arbiter decides; this only relays, through the shared
 * relay in declassify-symbol.ts (the OpenClaw plugin runs the same one).
 *
 * Note what is NOT here: any fallback. If the arbiter refuses, or lacks the op,
 * or throws, we return a tool error with NO content. There is deliberately no
 * "well, try resolve() instead" path — that would hand raw content to T-LLM with
 * no gate and no watermark, which is precisely the leak the whole plan exists to
 * close, and it is the kind of helpful-looking fallback that quietly guts a
 * confidentiality design.
 */
async function handleDeclassify(
  id: string | number | null,
  rawArgs: unknown,
  deps: InspectSymbolDeps,
): Promise<JsonRpcResponse> {
  const out = await declassifySymbol({ arbiter: deps.arbiter, sessionId: deps.sessionId }, rawArgs);
  if (!out.ok) return ok(id, toolError(out.error));
  return ok(id, { content: [{ type: "text", text: out.text }] });
}

// ── Small builders ────────────────────────────────────────────────────────────

function ok(id: string | number | null, result: unknown): JsonRpcResponse {
  return { jsonrpc: JSONRPC_VERSION, id, result };
}

function rpcError(
  id: string | number | null,
  code: number,
  message: string,
): JsonRpcResponse {
  return { jsonrpc: JSONRPC_VERSION, id, error: { code, message } };
}

/** An MCP tool-level error result (isError:true) — distinct from a protocol error. */
function toolError(text: string): {
  content: { type: "text"; text: string }[];
  isError: true;
} {
  return { content: [{ type: "text", text }], isError: true };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function msgOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
