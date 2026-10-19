/**
 * unmapped-tool-mask — confidentiality plan 10 §11.18 (P0 item 4b, the
 * maintainer's decision of 2026-10-07) over the REAL components: a real
 * ArbiterServer in `secrets` reading a real policy.yaml (`policyPath`), both
 * proxies over their PRODUCTION adapters (the real AnthropicProxy for the
 * agents it serves, the gate surface from the arbiter's op).
 *
 * The leak oracle, in a session that read NOTHING raw: the result of a tool
 * Mandu has no mapping for reaches the model only as a symbol, with the note
 * on why and how to let it through, for Claude Code (a new tool, a resource
 * tool, an MCP tool of no registered server), Codex (a resource tool, a
 * renamed one, an unregistered MCP tool), OpenCode (an MCP tool) and Goose (an
 * extension's tool). MASTER: each raw. Controls: each agent's own tools and
 * Mandu's own tool are forwarded; a tool policy.yaml lists under
 * `mapped_tools:` (by name, and by `mcp:<server>`) is forwarded.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { rewriteRequest as rewriteResponses } from "../../interceptors/openai-proxy/src/rewrite-request.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import type { ResponsesRequest } from "../../interceptors/openai-proxy/src/responses-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const ROW = (tag: string): string => `card | 4411-5522-6633-${tag}`;

async function withArbiter(policyYaml: string, fn: (h: { data: ArbiterClient; human: ArbiterClient }) => Promise<void>): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-unmapped-e2e-"));
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, policyYaml);
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const data = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  try {
    await fn({ data, human });
  } finally {
    data.close(); human.close();
    await server.close();
    resetCurrentPolicyForTests("claude-code");
    rmSync(tmp, { recursive: true, force: true });
  }
}

function post(port: number, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    req.on("error", reject);
    req.end(body);
  });
}

/** Each tool's result, tagged, through the real AnthropicProxy; the bytes the upstream got. */
async function viaAnthropicProxy(data: ArbiterClient, human: ArbiterClient, session: string, tools: Array<[string, string]>): Promise<string> {
  const up = new MockUpstream({ sse: buildTextSse("ok") });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream: up.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const messages: unknown[] = [{ role: "user", content: "go" }];
    tools.forEach(([name, tag], i) => {
      messages.push({ role: "assistant", content: [{ type: "tool_use", id: `tu_${i}`, name, input: { q: "rows" } }] });
      messages.push({ role: "user", content: [{ type: "tool_result", tool_use_id: `tu_${i}`, content: ROW(tag) }] });
    });
    assert.equal(await post(port, JSON.stringify({ model: "claude-sonnet-5", stream: true, messages })), 200);
    return up.requests[0]!.bodyText;
  } finally { await proxy.close(); }
}

const NO_POLICY = "version: 1\n";

test("Claude Code, OpenCode, Goose (real AnthropicProxy): an unmapped tool's result reaches the model only as a symbol in a session that read nothing; the agent's own tools and Mandu's are forwarded", async () => {
  await withArbiter(NO_POLICY, async ({ data, human }) => {
    const cases: Array<{ spec?: string; unmapped: Array<[string, string]>; mapped: Array<[string, string]> }> = [
      { unmapped: [["NewTool", "1001"], ["ListMcpResourcesTool", "1002"], ["mcp__remote__search", "1003"]], mapped: [["Grep", "2001"], ["ToolSearch", "2002"], ["mcp__mandu-policy__mandu_policy_read", "2003"]] },
      { spec: "opencode", unmapped: [["notes_get", "1101"]], mapped: [["read", "2101"], ["mandu-inspect_inspect_symbol", "2102"]] },
      { spec: "goose", unmapped: [["crm__lookup", "1201"], ["memory__retrieve_memories", "1202"]], mapped: [["tree", "2201"], ["analyze", "2202"]] },
    ];
    for (const c of cases) {
      const session = `unmapped-${c.spec ?? "claude"}-${process.pid}`;
      if (c.spec) assert.equal((await data.setSessionSpec({ sessionKey: session, spec: c.spec, requestedBy: "unmapped-tool-mask e2e" })).bound, c.spec);
      const wire = await viaAnthropicProxy(data, human, session, [...c.unmapped, ...c.mapped]);
      for (const [name, tag] of c.unmapped) {
        // MASTER: raw (no command, nothing read raw in the session)
        assert.ok(!wire.includes(ROW(tag)), `CONFIDENTIALITY (${c.spec ?? "claude-code"}): ${name}'s result reached the model raw`);
        assert.match(wire, new RegExp(`no mapping for the tool ${name}`), name);
      }
      assert.match(wire, /\$MDU:nomodel_/);
      assert.match(wire, /mapped_tools/);
      for (const [name, tag] of c.mapped) assert.ok(wire.includes(ROW(tag)), `${c.spec ?? "claude-code"} ${name}: forwarded`);
    }
  });
});

const BATTERY = { type: "additional_tools", role: "developer", tools: [{ type: "namespace", name: "functions", tools: [{ type: "custom", name: "exec", description: "- Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." }] }] };

async function codexTurn(data: ArbiterClient, human: ArbiterClient, session: string, calls: Array<{ id: string; name: string; namespace?: string; tag: string }>): Promise<(id: string) => string> {
  const input: unknown[] = [BATTERY];
  for (const c of calls) {
    input.push({ type: "function_call", call_id: c.id, name: c.name, ...(c.namespace ? { namespace: c.namespace } : {}), arguments: "{\"q\":\"rows\"}" });
    input.push({ type: "function_call_output", call_id: c.id, output: ROW(c.tag) });
  }
  const { request } = await rewriteResponses({ model: "m", input } as unknown as ResponsesRequest, { arbiter: new OpenAiProxyArbiterAdapter(data, human), sessionKey: session, skipPromptInjection: true });
  return (id) => JSON.stringify((request.input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" && i["call_id"] === id)!["output"]);
}

test("Codex (production adapter): a resource tool, a renamed one and an unregistered MCP tool reach the model only as symbols; its built-ins and Mandu's tool are forwarded", async () => {
  await withArbiter(NO_POLICY, async ({ data, human }) => {
    const out = await codexTurn(data, human, `unmapped-codex-${process.pid}`, [
      { id: "r1", name: "read_mcp_resource", tag: "3001" },
      { id: "r2", name: "mcp_resource_read", tag: "3002" },
      { id: "r3", name: "search", namespace: "mcp__remote", tag: "3003" },
      { id: "b1", name: "update_plan", tag: "4001" },
      { id: "b2", name: "view_image", tag: "4002" },
      { id: "m1", name: "mandu_policy_read", namespace: "mcp__mandu_policy", tag: "4003" },
    ]);
    for (const [id, tag] of [["r1", "3001"], ["r2", "3002"], ["r3", "3003"]] as const) {
      assert.ok(!out(id).includes(ROW(tag)), `CONFIDENTIALITY (codex): ${id} reached the model raw`);
      assert.match(out(id), /no mapping for the tool .*mapped_tools/, id);
    }
    for (const [id, tag] of [["b1", "4001"], ["b2", "4002"], ["m1", "4003"]] as const) assert.ok(out(id).includes(ROW(tag)), `${id}: forwarded`);
  });
});

test("policy.yaml `mapped_tools:` (by name and by mcp:<server>) lets the listed tools through, on both wires; an unlisted one stays masked", async () => {
  await withArbiter("version: 1\nmapped_tools:\n  - NewTool\n  - mcp:remote\n", async ({ data, human }) => {
    const wire = await viaAnthropicProxy(data, human, `mapped-claude-${process.pid}`, [["NewTool", "5001"], ["mcp__remote__search", "5002"], ["OtherTool", "5003"]]);
    assert.ok(wire.includes(ROW("5001")) && wire.includes(ROW("5002")), "listed: forwarded");
    assert.ok(!wire.includes(ROW("5003")), "unlisted: masked");
    const out = await codexTurn(data, human, `mapped-codex-${process.pid}`, [
      { id: "l1", name: "search", namespace: "mcp__remote", tag: "6001" },
      { id: "l2", name: "read_mcp_resource", tag: "6002" },
    ]);
    assert.ok(out("l1").includes(ROW("6001")), "codex: mcp:remote lists the tool");
    assert.ok(!out("l2").includes(ROW("6002")), "codex: an unlisted resource tool stays masked");
  });
});
