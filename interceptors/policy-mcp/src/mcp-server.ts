/**
 * mcp-server — a thin, hand-rolled MCP stdio JSON-RPC server exposing the
 * three mandu-policy tools (docs/design/ui/policy-surface.md §8.5.1).
 *
 * PROVENANCE: copied from interceptors/inspect-mcp/src/mcp-server.ts (the
 * JSON-RPC framing, `handleRpc` dispatch, the stdio loop and the builders),
 * with the tool surface replaced. Zero deps: the MCP surface we need is
 * `initialize`, `tools/list`, `tools/call`.
 *
 * SECURITY: the tools are data-plane clients of the arbiter; approving or
 * undoing a change is not reachable from here (ADMIN_ONLY_OPS). A successful
 * result is exactly one token-only text item (envelope.ts); errors are
 * isError results whose prose the proxy masks (fail-closed).
 */
import { createInterface } from "node:readline";

import { proposeTool, READ_TOOL, runPropose, runRead, runTest, TEST_TOOL, type PolicyToolDeps } from "./tools.js";

const JSONRPC_VERSION = "2.0";
const MCP_PROTOCOL_VERSION = "2024-11-05";
const SERVER_NAME = "mandu-policy";
const SERVER_VERSION = "0.2.0-beta.8"; // one product version: scripts/set-version.sh rewrites this line

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

export interface ServerDeps extends PolicyToolDeps {
  /** Cache for the edit schema, fetched once at the first tools/list. */
  schemaCache?: { edits?: unknown; tried?: boolean };
}

async function editsSchema(deps: ServerDeps): Promise<unknown | undefined> {
  const cache = (deps.schemaCache ??= {});
  if (!cache.tried) {
    cache.tried = true;
    try {
      cache.edits = (await deps.arbiter.policySchema()).edits;
    } catch {
      // Unreachable arbiter: list the tool with the short description; the
      // call itself then fails (and a later list does not retry forever).
      cache.edits = undefined;
    }
  }
  return cache.edits;
}

export async function handleRpc(req: JsonRpcRequest, deps: ServerDeps): Promise<JsonRpcResponse | null> {
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
    case "notifications/initialized":
    case "initialized":
      return null;
    case "ping":
      return ok(id, {});
    case "tools/list":
      return ok(id, { tools: [READ_TOOL, TEST_TOOL, proposeTool(await editsSchema(deps))] });
    case "tools/call":
      return handleToolsCall(id, req.params, deps);
    default:
      if (isNotification) return null;
      return rpcError(id, ERR_METHOD_NOT_FOUND, `method not found: ${req.method}`);
  }
}

async function handleToolsCall(id: string | number | null, params: unknown, deps: ServerDeps): Promise<JsonRpcResponse> {
  if (!isRecord(params) || typeof params.name !== "string") {
    return rpcError(id, ERR_INVALID_PARAMS, "tools/call requires { name, arguments }");
  }
  const args = isRecord(params.arguments) ? params.arguments : {};
  try {
    switch (params.name) {
      case READ_TOOL.name:
        return ok(id, await runRead(deps));
      case TEST_TOOL.name:
        return ok(id, await runTest(deps, args));
      case "mandu_policy_propose":
        if (args.edits === undefined) return ok(id, toolError("mandu_policy_propose: 'edits' is required"));
        return ok(id, await runPropose(deps, args));
      default:
        return rpcError(id, ERR_METHOD_NOT_FOUND, `unknown tool: ${params.name}`);
    }
  } catch (err) {
    // Arbiter unreachable or refused the op: a tool error (masked by the proxy).
    return ok(id, toolError(`${params.name}: arbiter error: ${msgOf(err)}`));
  }
}

export function runStdioServer(
  deps: ServerDeps,
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

async function dispatchLine(line: string, deps: ServerDeps, output: NodeJS.WritableStream): Promise<void> {
  let req: JsonRpcRequest;
  try {
    req = JSON.parse(line) as JsonRpcRequest;
  } catch {
    output.write(JSON.stringify(rpcError(null, ERR_PARSE, "parse error")) + "\n");
    return;
  }
  let resp: JsonRpcResponse | null;
  try {
    resp = await handleRpc(req, deps);
  } catch (err) {
    resp = rpcError(req.id ?? null, ERR_INTERNAL, msgOf(err));
  }
  if (resp) output.write(JSON.stringify(resp) + "\n");
}

function ok(id: string | number | null, result: unknown): JsonRpcResponse {
  return { jsonrpc: JSONRPC_VERSION, id, result };
}

function rpcError(id: string | number | null, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: JSONRPC_VERSION, id, error: { code, message } };
}

function toolError(text: string): { content: { type: "text"; text: string }[]; isError: true } {
  return { content: [{ type: "text", text }], isError: true };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function msgOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
