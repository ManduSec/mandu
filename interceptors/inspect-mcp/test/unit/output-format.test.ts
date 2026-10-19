import { test } from "node:test";
import assert from "node:assert/strict";
import {
  inspectSymbol,
  normalizeInspectionOutput,
  type InspectSymbolDeps,
  type InspectSymbolParams,
} from "../../src/inspect-symbol.js";
import { handleRpc, INSPECT_SYMBOL_TOOL } from "../../src/mcp-server.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUllm } from "../helpers/mock-ullm.js";

const INPUT = "$MDU:Read[a123]";
const RAW = "PRIVATE_SOURCE_MARKER";
const JSON_BYTES = '{"id":9007199254740993,"name":"PRIVATE_OUTPUT_MARKER"}';
const FENCED = "```json\n" + JSON_BYTES + "\n```";
const INVALID_ERROR = "inspect_symbol: output is not valid JSON; no artifact returned";

function makeDeps(reply: string): { deps: InspectSymbolDeps; arbiter: MockArbiter; ullm: MockUllm } {
  const arbiter = new MockArbiter().seed(INPUT, RAW);
  const ullm = new MockUllm({ reply });
  return { deps: { arbiter, ullm, sessionId: "format-test" }, arbiter, ullm };
}

test("explicit JSON accepts one complete fence and preserves large integer bytes", () => {
  for (const wrapped of [FENCED, "```\n" + JSON_BYTES + "\n```", " \r\n```json\r\n" + JSON_BYTES + "\r\n```\r\n"]) {
    assert.equal(normalizeInspectionOutput(wrapped, "json"), JSON_BYTES);
  }
  assert.equal(normalizeInspectionOutput("  " + JSON_BYTES + "\n", "json"), JSON_BYTES);
  for (const value of ["null", "true", '"a string"', "9007199254740993", "[1,2]"]) {
    assert.equal(normalizeInspectionOutput(value, "json"), value);
  }
});

test("text mode preserves legitimate Markdown and whitespace byte for byte", () => {
  for (const value of [FENCED, " \n" + FENCED + "\n ", "not JSON", ""]) {
    assert.equal(normalizeInspectionOutput(value, "text"), value);
  }
});

const malformed = [
  '{"PRIVATE_OUTPUT_MARKER":',
  "Here is PRIVATE_OUTPUT_MARKER:\n" + FENCED,
  FENCED + "\n" + FENCED,
  FENCED + "\nPRIVATE_OUTPUT_MARKER",
  "```javascript\n" + JSON_BYTES + "\n```",
  "",
];

test("JSON rejects malformed output, prose and multiple blocks with a fixed generic error", () => {
  for (const output of malformed) {
    assert.throws(() => normalizeInspectionOutput(output, "json"), { message: "Invalid inspection JSON output" });
  }
});

test("core normalizes only explicit JSON before sealing; every returned result stays opaque", async () => {
  for (const format of [undefined, "text", "json"] as const) {
    const { deps, arbiter, ullm } = makeDeps(FENCED);
    const result = await inspectSymbol(deps, { symbol: INPUT, instruction: "derive the record", output_format: format });
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(arbiter.table.get(result.resultSymbol), format === "json" ? JSON_BYTES : FENCED);
    assert.equal(arbiter.symbolizeCalls.length, 1);
    if (format === "json") assert.match(ullm.mainCalls[0].system, /exactly one valid JSON value/);
    assert.ok(!JSON.stringify(result).includes("PRIVATE_OUTPUT_MARKER"));
    assert.ok(!JSON.stringify(result).includes(RAW));
  }
});

test("core rejects invalid JSON without sealing or disclosing parser output", async () => {
  for (const output of malformed) {
    const { deps, arbiter } = makeDeps(output);
    const result = await inspectSymbol(deps, { symbol: INPUT, instruction: "derive JSON", output_format: "json" });
    assert.deepEqual(result, { ok: false, error: INVALID_ERROR });
    assert.equal(arbiter.symbolizeCalls.length, 0);
    assert.ok(!JSON.stringify(result).includes("PRIVATE_OUTPUT_MARKER"));
    assert.ok(!JSON.stringify(result).includes(RAW));
  }
});

test("invalid output_format is refused before source resolution or model calls", async () => {
  for (const format of ["yaml", null, {}, 3]) {
    const { deps, arbiter, ullm } = makeDeps(FENCED);
    const result = await inspectSymbol(deps, {
      symbol: INPUT, instruction: "derive JSON", output_format: format,
    } as unknown as InspectSymbolParams);
    assert.deepEqual(result, { ok: false, error: "inspect_symbol: output_format must be text or json" });
    assert.equal(arbiter.resolveCalls.length, 0);
    assert.equal(ullm.calls.length, 0);
    assert.equal(arbiter.symbolizeCalls.length, 0);
  }
});

test("MCP advertises JSON mode and threads it through core normalization and fail-closed errors", async () => {
  assert.deepEqual(INSPECT_SYMBOL_TOOL.inputSchema.properties.output_format.enum, ["text", "json"]);
  for (const output of [FENCED, ...malformed]) {
    const { deps, arbiter } = makeDeps(output);
    const rpc = await handleRpc({
      jsonrpc: "2.0", id: 1, method: "tools/call",
      params: { name: "inspect_symbol", arguments: { symbol: INPUT, instruction: "derive JSON", output_format: "json" } },
    }, deps);
    const result = rpc!.result as { isError: boolean; content: { text: string }[]; structuredContent?: { result_symbol: string } };
    assert.equal(result.isError, output !== FENCED);
    if (output === FENCED) assert.equal(arbiter.table.get(result.structuredContent!.result_symbol), JSON_BYTES);
    else {
      assert.equal(result.content[0].text, INVALID_ERROR);
      assert.equal(result.structuredContent, undefined);
      assert.equal(arbiter.symbolizeCalls.length, 0);
    }
    assert.ok(!JSON.stringify(rpc).includes("PRIVATE_OUTPUT_MARKER"));
    assert.ok(!JSON.stringify(rpc).includes(RAW));
  }
});
