/**
 * declassify-tool tests — the OpenClaw `declassify_symbol` plugin tool
 * (src/declassify-tool.ts), driven through the real registrar against a fake
 * OpenClaw api and a mock arbiter. No OpenClaw, no daemon.
 *
 * The load-bearing assertions:
 *   - the tool is the MCP tool, verbatim (name, description, schema);
 *   - a release is ONE text block that the proxy flattens to the exact form
 *     the arbiter's declassify result rule accepts, with no `details` copy;
 *   - the arbiter is asked with the Mandu SCOPE as the session, never
 *     OpenClaw's session key, and the call refuses when no scope is set;
 *   - every refusal (pending approval, hard refusal, unreachable arbiter)
 *     carries no content, and a failed connect is retried on the next call.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { registerInspectPlugin, type RegisterOptions } from "../../src/register.js";
import { createDeclassifySymbolPluginTool, DECLASSIFY_TOOL_NAME } from "../../src/declassify-tool.js";
import type { OpenClawPluginApiLike, PluginAgentTool, PluginToolFactory } from "../../src/openclaw-api.js";
import { DECLASSIFY_SYMBOL_TOOL } from "../../../inspect-mcp/src/mcp-server.js";
import { declassifiedNotice } from "../../../inspect-mcp/src/declassify-symbol.js";
import type { Arbiter, DeclassifyResult } from "../../../inspect-mcp/src/arbiter-client.js";
import { MockArbiter } from "../../../inspect-mcp/test/helpers/mock-arbiter.js";
import { MockUllm } from "../../../inspect-mcp/test/helpers/mock-ullm.js";
import { flattenLikeProxy } from "../helpers/trusted-shape.js";

const SOCK = "/tmp/mandu-test/arbiter.sock";
const SYM = "$MDU:anymodel_read[7b21]";
const BODY = "Reference code R-2718. OC_DECLASSIFY_CANARY";

/** A mock arbiter whose rung-3 op answers the current `verdict`. */
function rung3Arbiter(verdict: () => DeclassifyResult): { arbiter: Arbiter; calls: Array<Record<string, unknown>> } {
  const calls: Array<Record<string, unknown>> = [];
  const arbiter = new MockArbiter() as unknown as Arbiter;
  arbiter.declassify = async (args) => { calls.push({ ...args }); return verdict(); };
  return { arbiter, calls };
}

function declassifyTool(
  pluginConfig: Record<string, unknown>,
  over: Partial<RegisterOptions>,
  ctx: Record<string, unknown> = { sessionKey: "openclaw-main" },
): PluginAgentTool {
  const registered: Array<PluginAgentTool | PluginToolFactory> = [];
  const api: OpenClawPluginApiLike = {
    id: "mandu-inspect",
    pluginConfig,
    logger: { info() {}, warn() {}, error() {} },
    registerTool: (tool) => registered.push(tool),
  };
  registerInspectPlugin(api, { env: {}, cliAvailable: () => true, buildUllm: () => new MockUllm(), ...over });
  const tools = registered.map((f) => (f as PluginToolFactory)(ctx) as PluginAgentTool);
  const tool = tools.find((t) => t.name === "declassify_symbol");
  assert.ok(tool, "the registrar mounts declassify_symbol");
  return tool!;
}

const CFG = { arbiterSock: SOCK, scopeId: "mandu-scope-1", ullmMode: "cli", ullmBinary: "claude" };
const ALLOWED: DeclassifyResult = { value: BODY, allowed: true, requiresApproval: false, reason: "ok", watermark: "any-model" };

test("the plugin tool IS the MCP tool: name, description and schema verbatim", () => {
  const tool = createDeclassifySymbolPluginTool(async () => { throw new Error("unused"); });
  assert.equal(tool.name, "declassify_symbol");
  assert.equal(DECLASSIFY_TOOL_NAME, "declassify_symbol");
  assert.equal(tool.description, DECLASSIFY_SYMBOL_TOOL.description);
  assert.deepEqual(tool.parameters, DECLASSIFY_SYMBOL_TOOL.inputSchema);
  assert.deepEqual([...(tool.parameters.required ?? [])].sort(), ["reason", "symbol"]);
});

test("allowed: one text block, flattened to the notice + value, keyed to the Mandu scope (not OpenClaw's session)", async () => {
  const { arbiter, calls } = rung3Arbiter(() => ALLOWED);
  const tool = declassifyTool(CFG, { connectArbiter: async () => arbiter });
  const res = await tool.execute("c1", { symbol: SYM, reason: "the user asked" });
  assert.equal(res.content.length, 1);
  assert.equal(flattenLikeProxy(res), `${declassifiedNotice("any-model")}\n\n${BODY}`);
  assert.equal(res.details, undefined, "the value is not copied into UI metadata");
  assert.deepEqual(calls, [{ symbol: SYM, sessionKey: "mandu-scope-1", reason: "the user asked" }]);
});

test("the scope may come from env MANDU_SCOPE_ID, like every other key", async () => {
  const { arbiter, calls } = rung3Arbiter(() => ALLOWED);
  const { scopeId: _drop, ...noScope } = CFG;
  const tool = declassifyTool(noScope, { connectArbiter: async () => arbiter, env: { MANDU_SCOPE_ID: "env-scope" } });
  await tool.execute("c1", { symbol: SYM, reason: "r" });
  assert.equal(calls[0]!.sessionKey, "env-scope");
});

test("FAIL CLOSED: no Mandu scope → refused before the arbiter is dialed (no fallback to OpenClaw's session key)", async () => {
  let dials = 0;
  const { arbiter, calls } = rung3Arbiter(() => ALLOWED);
  const { scopeId: _drop, ...noScope } = CFG;
  const tool = declassifyTool(noScope, { connectArbiter: async () => { dials++; return arbiter; } });
  const res = await tool.execute("c1", { symbol: SYM, reason: "r" });
  assert.match(res.content[0]!.text, /refusing \(fail closed\).*no Mandu scope/);
  assert.ok(!JSON.stringify(res).includes("OC_DECLASSIFY_CANARY"));
  assert.equal(dials, 0);
  assert.equal(calls.length, 0);
});

test("approval pending and hard refusal: an error block, no content", async () => {
  let verdict: DeclassifyResult = { value: null, allowed: false, requiresApproval: true, reason: "the session ingested untrusted data" };
  const { arbiter } = rung3Arbiter(() => verdict);
  const tool = declassifyTool(CFG, { connectArbiter: async () => arbiter });
  const pending = await tool.execute("c1", { symbol: SYM, reason: "r" });
  assert.match(pending.content[0]!.text, /asked to approve/);
  verdict = { value: null, allowed: false, requiresApproval: false, reason: "the user declined to show this to the model" };
  const denied = await tool.execute("c2", { symbol: SYM, reason: "r" });
  assert.match(denied.content[0]!.text, /declined.*do not retry/);
  for (const r of [pending, denied]) assert.ok(!JSON.stringify(r).includes("OC_DECLASSIFY_CANARY"));
});

test("FAIL CLOSED: an unreachable arbiter refuses, and the next call dials again", async () => {
  let dials = 0;
  const { arbiter } = rung3Arbiter(() => ALLOWED);
  const tool = declassifyTool(CFG, {
    connectArbiter: async () => {
      dials++;
      if (dials === 1) throw new Error("connect ENOENT " + SOCK);
      return arbiter;
    },
  });
  const first = await tool.execute("c1", { symbol: SYM, reason: "r" });
  assert.match(first.content[0]!.text, /arbiter unavailable, refusing \(fail closed\): connect ENOENT/);
  assert.ok(!JSON.stringify(first).includes("OC_DECLASSIFY_CANARY"));
  const second = await tool.execute("c2", { symbol: SYM, reason: "r" });
  assert.match(flattenLikeProxy(second), /OC_DECLASSIFY_CANARY/);
  assert.equal(dials, 2);
});

test("an arbiter that answers with an error mid-call refuses with no content", async () => {
  const arbiter = new MockArbiter() as unknown as Arbiter;
  arbiter.declassify = async () => { throw new Error("arbiter socket closed"); };
  const tool = declassifyTool(CFG, { connectArbiter: async () => arbiter });
  const res = await tool.execute("c1", { symbol: SYM, reason: "r" });
  assert.match(res.content[0]!.text, /arbiter error: arbiter socket closed/);
});
