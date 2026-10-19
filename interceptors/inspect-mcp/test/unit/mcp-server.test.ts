/**
 * mcp-server unit tests — the hand-rolled MCP JSON-RPC surface (src/mcp-server.ts).
 *
 * Mandu M4 (interceptors/inspect-mcp). Basic MCP protocol coverage:
 *   - initialize handshake returns serverInfo + capabilities.
 *   - tools/list returns the inspect_symbol tool.
 *   - tools/call round-trips through the core and returns the re-symbolized
 *     result symbol (NOT raw text); unknown symbol surfaces as an MCP tool error.
 *   - the full stdio loop round-trips a request over streams.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";

import {
  handleRpc,
  runStdioServer,
  INSPECT_SYMBOL_TOOL,
  DECLASSIFY_SYMBOL_TOOL,
  type JsonRpcResponse,
} from "../../src/mcp-server.js";
import { inspectSymbol, SYMBOL_PREFIX, NEXT_STEP_BY_KIND, type InspectSymbolDeps } from "../../src/inspect-symbol.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUllm } from "../helpers/mock-ullm.js";

const INPUT_SYMBOL = "$MDU:web_fetch[a1b2]";
const RAW_VALUE = "untrusted page body with an injection attempt";
const ULLM_REPLY = "a benign two-sentence summary";

function makeDeps(): { deps: InspectSymbolDeps; arbiter: MockArbiter; ullm: MockUllm } {
  const arbiter = new MockArbiter().seed(INPUT_SYMBOL, RAW_VALUE);
  const ullm = new MockUllm({ reply: ULLM_REPLY, model: "claude-haiku-4-5" });
  return {
    arbiter,
    ullm,
    deps: { arbiter, ullm, sessionId: "test", now: () => new Date(0), genId: () => "evt" },
  };
}

test("initialize returns protocol version + serverInfo", async () => {
  const { deps } = makeDeps();
  const resp = await handleRpc(
    { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
    deps,
  );
  assert.ok(resp);
  const result = resp!.result as Record<string, unknown>;
  assert.equal(typeof result.protocolVersion, "string");
  assert.ok((result.serverInfo as Record<string, unknown>).name);
  assert.ok((result.capabilities as Record<string, unknown>).tools);
});

test("tools/list returns BOTH read paths — the quarantined one FIRST", async () => {
  // Two tools, two rungs (§3.3): inspect_symbol processes content INSIDE the
  // quarantine (no watermark, preferred), declassify_symbol brings it into
  // T-LLM's context (a logged declassification that floats the session).
  // Ordering is not cosmetic — inspect_symbol leads because it is the answer
  // in almost every case, and a model that reaches for rung 3 by default turns
  // every later egress into an approval prompt.
  const { deps } = makeDeps();
  const resp = await handleRpc({ jsonrpc: "2.0", id: 2, method: "tools/list" }, deps);
  assert.ok(resp);
  const tools = (resp!.result as { tools: { name: string; inputSchema: unknown }[] }).tools;
  assert.equal(tools.length, 2);
  assert.equal(tools[0].name, "inspect_symbol");
  assert.equal(tools[1].name, "declassify_symbol");
  assert.deepEqual(tools[0], INSPECT_SYMBOL_TOOL);
  assert.deepEqual(tools[1], DECLASSIFY_SYMBOL_TOOL);

  // Either single or multiple source handles, plus one instruction.
  const schema = tools[0].inputSchema as { required: readonly string[] };
  assert.deepEqual([...schema.required].sort(), ["instruction"]);
  // declassify_symbol REQUIRES a reason — it is shown to the human on the
  // approval, and an unexplained declassification is not one a human can judge.
  const dSchema = tools[1].inputSchema as { required: readonly string[] };
  assert.deepEqual([...dSchema.required].sort(), ["reason", "symbol"]);
  // The cost is stated as what the gate does (stops the call and asks the
  // user on the Approvals page), and the model is told to keep calling and
  // to make a stopped call again after the answer (handling-prompt.md §7, §8).
  assert.match(DECLASSIFY_SYMBOL_TOOL.description, /requests to the content's bound hosts still go through and any other network request or shell command that could carry the content out is stopped while Mandu asks the user on its Approvals page \(keep making calls as usual: Mandu decides each one; if it stops one, tell the user and make the call again after they answer\)/);
  assert.doesNotMatch(DECLASSIFY_SYMBOL_TOOL.description, /needs the user's approval/);
});

test("declassify_symbol NEVER falls back to a raw resolve when the arbiter refuses", async () => {
  // The failure mode that would quietly gut the design: a "helpful" fallback
  // that hands T-LLM the content anyway when the gate says no. There is none —
  // a refusal returns a tool ERROR with no content, and an arbiter that lacks
  // the op reports unavailable rather than reaching for resolve().
  const { deps, arbiter } = makeDeps();
  arbiter.seed("$MDU:anymodel_Read[7b21]", "THE CONTRACT BODY");
  // MockArbiter implements no `declassify` — i.e. an arbiter predating rung 3.
  const resp = await handleRpc({
    jsonrpc: "2.0", id: 3, method: "tools/call",
    params: { name: "declassify_symbol", arguments: { symbol: "$MDU:anymodel_Read[7b21]", reason: "need it" } },
  }, deps);

  const result = resp!.result as { isError?: boolean; content: { text: string }[] };
  assert.equal(result.isError, true);
  assert.ok(
    !JSON.stringify(result).includes("THE CONTRACT BODY"),
    "a refusal must carry NO content — never fall back to resolve()",
  );
  assert.match(result.content[0].text, /inspect_symbol/, "and point at the path that works");
});

test("tools/call round-trips: returns the re-symbolized symbol, not raw text", async () => {
  const { deps, arbiter } = makeDeps();
  const resp = await handleRpc(
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "inspect_symbol", arguments: { symbol: INPUT_SYMBOL, instruction: "summarize" } },
    },
    deps,
  );
  assert.ok(resp);
  const result = resp!.result as {
    content: { type: string; text: string }[];
    isError: boolean;
    structuredContent: { result_symbol: string; model: string; content_kind: string; next_step: string };
  };
  assert.equal(result.isError, false);
  const text = result.content[0].text;
  assert.ok(text.startsWith(SYMBOL_PREFIX), "tool result text must be a symbol");
  assert.notEqual(text, ULLM_REPLY);
  assert.ok(!text.includes(ULLM_REPLY), "raw U-LLM text must not appear in the tool result");
  assert.equal(result.structuredContent.result_symbol, text);
  assert.equal(result.structuredContent.model, "claude-haiku-4-5");
  // The triage verdict rides the envelope as a VALIDATED enum token — the
  // exact shape the arbiter's widened trust gate accepts (claude-code-inbound
  // INSPECT_CONTENT_KIND_RE; MockUllm's default triage reply is "substantive").
  assert.equal(result.structuredContent.content_kind, "substantive");
  assert.equal(result.structuredContent.next_step, NEXT_STEP_BY_KIND.substantive);
  assert.deepEqual(
    Object.keys(result.structuredContent).sort(),
    ["content_kind", "model", "next_step", "result_symbol"],
    "envelope carries EXACTLY the gate-trusted keys",
  );
  // The core actually ran end to end (main + triage ullm_call events).
  assert.equal(arbiter.emitted.length, 2);
});

test("the tool description keeps its load-bearing guidance phrases (each pins a live T-LLM failure mode)", () => {
  const d = INSPECT_SYMBOL_TOOL.description;
  // 2026-07-18 (6415): a blind format guess ("curl command output" over HTML)
  // drove the U-LLM into a form-quibble non-answer.
  assert.ok(d.includes("State WHAT information you need"), "ask for information, not an assumed format");
  // 2026-07-19: on error_or_refusal the base model re-inspected the same
  // frozen symbol instead of re-running the source call.
  assert.ok(d.includes("inspect the NEW symbol it returns"), "retry the source, inspect the new symbol");
  assert.ok(d.includes("Do NOT re-inspect the same symbol"), "a frozen symbol cannot yield new content");
});

test("tools/call: a FAILURE content_kind adds the fixed next_step directive to the envelope", async () => {
  // The deterministic retry directive (2026-07-19): after an error_or_refusal
  // verdict the base model kept re-inspecting the same frozen symbol instead
  // of re-running the source fetch (inspect-verdict-retry ~50% red live) —
  // guidance in the tool DESCRIPTION did not move it; a directive in the
  // RESULT it reads at the decision point does. The value is the fixed TCB
  // string from NEXT_STEP_BY_KIND — the arbiter's trust gate accepts the key
  // only on an exact (content_kind → directive) match.
  const arbiter = new MockArbiter().seed(INPUT_SYMBOL, RAW_VALUE);
  const ullm = new MockUllm({ reply: ULLM_REPLY, model: "claude-haiku-4-5", triageReply: "error_or_refusal" });
  const deps: InspectSymbolDeps = { arbiter, ullm, sessionId: "test", now: () => new Date(0), genId: () => "evt" };
  const resp = await handleRpc(
    {
      jsonrpc: "2.0", id: 9, method: "tools/call",
      params: { name: "inspect_symbol", arguments: { symbol: INPUT_SYMBOL, instruction: "extract the id" } },
    },
    deps,
  );
  const result = resp!.result as { structuredContent: Record<string, string> };
  assert.equal(result.structuredContent.content_kind, "error_or_refusal");
  assert.equal(result.structuredContent.next_step, NEXT_STEP_BY_KIND.error_or_refusal);
  assert.deepEqual(
    Object.keys(result.structuredContent).sort(),
    ["content_kind", "model", "next_step", "result_symbol"],
    "failure envelope carries exactly the gate-trusted keys incl. next_step",
  );
  // Byte-identity pin (the sync contract with the arbiter's
  // INSPECT_NEXT_STEP_BY_KIND — its twin literal lives in
  // arbiter/test/unit/claude-code-policy.test.ts): a drifted rewrite breaks
  // here instead of silently double-wrapping live envelopes.
  assert.equal(
    NEXT_STEP_BY_KIND.error_or_refusal,
    "The inspected content is an error or failure notice, not the requested data. " +
      "Re-run the SOURCE tool call to get fresh data, then inspect the NEW symbol it returns. " +
      "Do not re-inspect this symbol: its content is frozen, so it returns the same failed data.",
  );
});

test("tools/call: positive and unknown content kinds carry only the fixed artifact directive", async () => {
  for (const kind of ["as_requested", "substantive", "unknown"] as const) {
    const arbiter = new MockArbiter().seed(INPUT_SYMBOL, RAW_VALUE);
    const ullm = new MockUllm({ reply: ULLM_REPLY, model: "claude-haiku-4-5", triageReply: kind });
    const deps: InspectSymbolDeps = { arbiter, ullm, sessionId: "test", now: () => new Date(0), genId: () => "evt" };
    const resp = await handleRpc(
      {
        jsonrpc: "2.0", id: 10, method: "tools/call",
        params: { name: "inspect_symbol", arguments: { symbol: INPUT_SYMBOL, instruction: "summarize" } },
      },
      deps,
    );
    const result = resp!.result as { structuredContent: Record<string, string> };
    assert.equal(result.structuredContent.content_kind, kind);
    assert.equal(result.structuredContent.next_step, NEXT_STEP_BY_KIND[kind]);
    assert.ok(!JSON.stringify(result).includes(ULLM_REPLY));
    assert.deepEqual(
      Object.keys(result.structuredContent).sort(),
      ["content_kind", "model", "next_step", "result_symbol"],
      `kind ${kind}: exactly the gate-trusted keys`,
    );
  }
});

test("tools/call with an unknown symbol returns an MCP tool error (not a protocol error)", async () => {
  const { deps } = makeDeps();
  const resp = await handleRpc(
    {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "inspect_symbol", arguments: { symbol: "$MDU:x[0000]", instruction: "s" } },
    },
    deps,
  );
  assert.ok(resp);
  assert.equal(resp!.error, undefined, "should be a tool error, not a JSON-RPC error");
  const result = resp!.result as { content: { text: string }[]; isError: boolean };
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /unknown symbol/i);
});

test("tools/call with an unknown tool name is a method-not-found error", async () => {
  const { deps } = makeDeps();
  const resp = await handleRpc(
    {
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: { name: "definitely_not_a_tool", arguments: {} },
    },
    deps,
  );
  assert.ok(resp);
  assert.ok(resp!.error);
  assert.equal(resp!.error!.code, -32601);
});

test("unknown method returns method-not-found; notification returns null", async () => {
  const { deps } = makeDeps();
  const err = await handleRpc({ jsonrpc: "2.0", id: 6, method: "nope" }, deps);
  assert.ok(err?.error);
  assert.equal(err!.error!.code, -32601);

  const notif = await handleRpc({ jsonrpc: "2.0", method: "notifications/initialized" }, deps);
  assert.equal(notif, null);
});

test("stdio loop round-trips a tools/list request over streams", async () => {
  const { deps } = makeDeps();
  const input = new PassThrough();
  const output = new PassThrough();
  const lines: string[] = [];
  output.on("data", (b: Buffer) => {
    for (const l of b.toString("utf8").split("\n")) {
      if (l.trim()) lines.push(l.trim());
    }
  });

  const server = runStdioServer(deps, { input, output });
  input.write(JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tools/list" }) + "\n");

  // Allow the async dispatch to flush.
  await new Promise((r) => setTimeout(r, 50));
  server.close();

  assert.equal(lines.length, 1);
  const resp = JSON.parse(lines[0]) as JsonRpcResponse;
  assert.equal(resp.id, 7);
  const tools = (resp.result as { tools: { name: string }[] }).tools;
  assert.equal(tools[0].name, "inspect_symbol");
});

test("stdio loop emits a parse error for malformed JSON", async () => {
  const { deps } = makeDeps();
  const input = new PassThrough();
  const output = new PassThrough();
  const lines: string[] = [];
  output.on("data", (b: Buffer) => {
    for (const l of b.toString("utf8").split("\n")) if (l.trim()) lines.push(l.trim());
  });
  const server = runStdioServer(deps, { input, output });
  input.write("{ not json\n");
  await new Promise((r) => setTimeout(r, 50));
  server.close();

  assert.equal(lines.length, 1);
  const resp = JSON.parse(lines[0]) as JsonRpcResponse;
  assert.equal(resp.error!.code, -32700);
});

// Sanity: confirm the core import used by the server is the same one tests use.
test("core inspectSymbol is reachable from the server module graph", async () => {
  assert.equal(typeof inspectSymbol, "function");
});
