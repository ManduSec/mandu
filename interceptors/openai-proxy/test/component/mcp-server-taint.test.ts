/**
 * mcp-server-taint (proxy e2e, Codex) — plan 10 §11.13's per-server rule
 * through the REAL OpenAiProxy, in a session where a listed reader read a
 * secret raw: a tainted server's result is masked on both wires; a server
 * proven clean (mapped, exactly one process, its tree read nothing) is
 * forwarded raw instead of being masked by the session rule; an unmapped
 * server keeps the session rule.
 *
 * Axes: `secrets`, stated through the mock (classify TRUSTED with no level;
 * mcpServerTaint and callTaint as the arbiter answers them with the
 * confidentiality axis on).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { OpenAiProxy } from "../../src/proxy.js";
import type { CallTaintWire, McpServerTaintWire } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream } from "../helpers/mock-upstream.js";

const ROWS = "card | 4411-5522-6633-7744";
const SESSION: CallTaintWire = { level: "no-model", files: ["/h/.pgpass"], apps: ["psql"], rule: "secret", mask: [], root: null, denied: [], evidence: "session" };
const BATTERY = { type: "additional_tools", role: "developer", tools: [{ type: "namespace", name: "functions", tools: [{ type: "custom", name: "exec", description: "- Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." }] }] };

function call(port: number, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/responses", headers: { "content-type": "application/json" } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    req.on("error", reject);
    req.end(body);
  });
}

async function outputs(verdict: McpServerTaintWire["verdict"]): Promise<{ cell: string; fn: string }> {
  const arbiter = new MockArbiter({
    classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "mock: integrity off" }),
    callTaintFn: () => SESSION,
    mcpServerTaintFn: () => ({ verdict, server: "store", candidates: verdict === "unmapped" ? 0 : 1, level: verdict === "tainted" ? "no-model" : null, files: verdict === "tainted" ? ["/h/.npmrc"] : [], apps: verdict === "tainted" ? ["node"] : [] }),
  });
  const up = new MockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter, upstream: up.fetcher, sessionKey: "codex-srv", log: () => {} });
  const port = await proxy.listen(0);
  try {
    const body = JSON.stringify({ model: "gpt-6.1-sol", stream: true, input: [
      BATTERY,
      { type: "custom_tool_call", call_id: "c1", name: "exec", input: "text(await tools.mcp__store__get({key: \"rows\"}));" },
      { type: "custom_tool_call_output", call_id: "c1", output: [{ type: "input_text", text: "Script completed\nWall time 0.1 seconds\nOutput:\n" }, { type: "input_text", text: ROWS }] },
      { type: "function_call", call_id: "f1", namespace: "mcp__store", name: "get", arguments: "{\"key\":\"rows\"}" },
      { type: "function_call_output", call_id: "f1", output: [{ type: "input_text", text: "Wall time: 0.1 seconds\nOutput:" }, { type: "input_text", text: ROWS }] },
    ] });
    assert.equal(await call(port, body), 200);
    const input = JSON.parse(up.requests[0]!.bodyText).input as Array<Record<string, unknown>>;
    const out = (id: string) => JSON.stringify(input.find((i) => String(i["type"]).endsWith("_output") && i["call_id"] === id)!["output"]);
    return { cell: out("c1"), fn: out("f1") };
  } finally { await proxy.close(); }
}

test("in a tainted session: a tainted server is masked, a clean one is raw, an unmapped one keeps the session rule", async () => {
  const t = await outputs("tainted");
  assert.ok(!t.cell.includes("4411-5522") && !t.fn.includes("4411-5522"), "CONFIDENTIALITY VIOLATION: a tainted server's result reached the model");
  const c = await outputs("clean");
  assert.ok(c.cell.includes("4411-5522") && c.fn.includes("4411-5522"), "a server proven clean is forwarded raw");
  const u = await outputs("unmapped");
  assert.ok(!u.cell.includes("4411-5522") && !u.fn.includes("4411-5522"), "unmapped: the session rule masks");
});

// Plan 10 §11.18 (P0 item 4b, 2026-10-07), through the real proxy with a mock
// upstream, in a session that read NOTHING: a tool Mandu has no mapping for
// (Codex's MCP resource tools, a renamed one, an MCP tool of no registered
// server) reaches the model only as a symbol with the note saying how to let
// it through; a Codex built-in (update_plan) is forwarded. MASTER: all raw.
test("a session that read nothing: every unmapped tool's result reaches the model only as a symbol; a Codex built-in is forwarded", async () => {
  const EMPTY: CallTaintWire = { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] };
  const arbiter = new MockArbiter({
    classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "mock: integrity off" }),
    // the arbiter: empty for a built-in, `unmapped` for a tool it has no mapping for
    callTaintFn: (r) => (r.builtin === true ? EMPTY : { ...EMPTY, level: "no-model", evidence: "unmapped", why: `Mandu has no mapping for the tool ${r.unmappedTool}; list it under \`mapped_tools:\` in policy.yaml` }),
    mcpServerTaintFn: () => ({ verdict: "unmapped", candidates: 0, level: null, files: [], apps: [] }),
  });
  const up = new MockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter, upstream: up.fetcher, sessionKey: "codex-res", log: () => {} });
  const port = await proxy.listen(0);
  try {
    const body = JSON.stringify({ model: "gpt-6.1-sol", stream: true, input: [
      BATTERY,
      { type: "function_call", call_id: "r1", name: "read_mcp_resource", arguments: "{\"server\":\"res\",\"uri\":\"res://rows\"}" },
      { type: "function_call_output", call_id: "r1", output: JSON.stringify({ server: "res", uri: "res://rows", contents: [{ uri: "res://rows", mimeType: "text/plain", text: ROWS }] }) },
      { type: "function_call", call_id: "r2", name: "mcp_resource_read", arguments: "{\"id\":\"rows\"}" },
      { type: "function_call_output", call_id: "r2", output: ROWS },
      { type: "function_call", call_id: "r3", namespace: "mcp__remote", name: "search", arguments: "{\"q\":\"rows\"}" },
      { type: "function_call_output", call_id: "r3", output: [{ type: "input_text", text: "Wall time: 0.1 seconds\nOutput:" }, { type: "input_text", text: ROWS }] },
      { type: "function_call", call_id: "p1", name: "update_plan", arguments: "{\"plan\":[]}" },
      { type: "function_call_output", call_id: "p1", output: "Plan updated 7c1e" },
    ] });
    assert.equal(await call(port, body), 200);
    const wire = up.requests[0]!.bodyText;
    assert.ok(!wire.includes("4411-5522"), "CONFIDENTIALITY VIOLATION: an unmapped tool's result reached the model raw");
    const outs = (JSON.parse(wire).input as Array<Record<string, unknown>>).filter((i) => i["type"] === "function_call_output" && i["call_id"] !== "p1");
    assert.equal(outs.length, 3);
    for (const o of outs) assert.match(JSON.stringify(o["output"]), /\$MDU:/, String(o["call_id"]));
    assert.match(wire, /mapped_tools/);
    assert.ok(wire.includes("Plan updated 7c1e"), "a Codex built-in is forwarded");
  } finally { await proxy.close(); }
});
