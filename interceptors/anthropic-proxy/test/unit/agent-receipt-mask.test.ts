/**
 * agent-receipt-mask (unit, Claude Code) — confidentiality plan 13 §4.5.1,
 * the decision of 2026-10-02: a result the AGENT process itself received
 * over its own connection to a secret holder (an HTTP MCP server that read
 * `.env`, a local dev server fetched with WebFetch) reaches the model
 * masked at the holder's level. The proxy asks the arbiter once per request
 * (`agentReceiptTaint`, every tool_result with the tool the response side
 * gated) and masks each result the arbiter answers a level for, raise-only
 * over the other legs; a throw refuses the request.
 *
 * Axes: `secrets`, stated through the mock (classify TRUSTED with no level,
 * integrity off; agentReceiptTaint as the arbiter answers it with the
 * confidentiality axis on).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { rewriteRequest, RewriteRefusal } from "../../src/rewrite-request.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import type { AgentReceiptTaintWire } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const PAGE = "DATABASE_URL=postgres://app:hunter2-AGENT-RECEIPT@db/app";

function turn(calls: Array<{ id: string; name: string; input: Record<string, unknown>; content: string }>): MessagesRequest {
  return {
    model: "claude-sonnet-5",
    messages: [
      { role: "user", content: "go" },
      { role: "assistant", content: calls.map((c) => ({ type: "tool_use" as const, id: c.id, name: c.name, input: c.input })) },
      { role: "user", content: calls.map((c) => ({ type: "tool_result" as const, tool_use_id: c.id, content: c.content })) },
    ],
  };
}
const forwarded = (r: MessagesRequest, i: number): string => JSON.stringify((r.messages[2]!.content as Array<{ content: unknown }>)[i]!.content);
const trusted = () => ({ trust: "TRUSTED" as const, category: null, reason: "mock: integrity off" });
const held = (ids: readonly string[], extra: Partial<AgentReceiptTaintWire["calls"][number]> = {}) =>
  (req: { calls: Array<{ callId: string; tool: string }> }): AgentReceiptTaintWire => ({
    calls: req.calls.map((c) => ids.includes(c.callId)
      ? { callId: c.callId, level: "no-model", files: ["/w/.env"], apps: ["python3"], ...extra }
      : { callId: c.callId, level: null, files: [], apps: [] }),
  });

test("a WebFetch and an MCP result the agent received from a holder are masked whole at its level; the batch names every tool_result once", async () => {
  const arbiter = new MockArbiter({ classifyFn: trusted, agentReceiptTaintFn: held(["tu_fetch", "tu_mcp"]) });
  const { request, rewrites } = await rewriteRequest(turn([
    { id: "tu_fetch", name: "WebFetch", input: { url: "http://localhost:3000/", prompt: "show" }, content: PAGE },
    { id: "tu_mcp", name: "mcp__dev__query", input: { q: "env" }, content: PAGE },
    { id: "tu_read", name: "Read", input: { file_path: "/w/README.md" }, content: "# readme" },
  ]), { arbiter, sessionKey: "s" });
  for (const i of [0, 1]) {
    assert.ok(!forwarded(request, i).includes("hunter2"), `CONFIDENTIALITY VIOLATION: result ${i} the agent received from a holder reached the model raw`);
    assert.equal(rewrites[i]!.symbolized, true);
    assert.equal(rewrites[i]!.confidentiality, "no-model");
    assert.match(forwarded(request, i), /\[mandu:secret\] masked: python3 read \/w\/\.env/);
  }
  assert.ok(forwarded(request, 2).includes("# readme"), "utility: a result the arbiter does not name stays raw");
  assert.deepEqual(arbiter.agentReceiptTaintCalls, [{
    calls: [{ callId: "tu_fetch", tool: "WebFetch" }, { callId: "tu_mcp", tool: "mcp__dev__query" }, { callId: "tu_read", tool: "Read" }],
    sessionKey: "s",
  }]);
});

test("an unattributed call (its relay never recorded) is masked with its own reason", async () => {
  const arbiter = new MockArbiter({ classifyFn: trusted, agentReceiptTaintFn: held(["tu_fetch"], { unattributed: true }) });
  const { request } = await rewriteRequest(turn([{ id: "tu_fetch", name: "WebFetch", input: { url: "http://localhost:3000/" }, content: PAGE }]), { arbiter, sessionKey: "s" });
  assert.ok(!forwarded(request, 0).includes("hunter2"));
});

test("raise-only: the agent-receipt level raises a shell mask's level, and nothing is lowered when the arbiter answers null", async () => {
  const arbiter = new MockArbiter({
    classifyFn: trusted,
    agentReceiptTaintFn: held(["tu_sh"]),
    callTaintFn: () => ({ level: "local-model", files: ["/w/notes"], apps: ["cat"], rule: "secret", mask: [], root: "1-1", denied: [], evidence: "tree" }),
  });
  const { rewrites } = await rewriteRequest(turn([{ id: "tu_sh", name: "Bash", input: { command: "cat notes" }, content: PAGE }]), { arbiter, sessionKey: "s" });
  assert.equal(rewrites[0]!.symbolized, true);
  assert.equal(rewrites[0]!.confidentiality, "no-model", "the stricter of the two levels");
});

test("fail-closed: an arbiter that throws refuses the request; one without the op masks nothing by this leg", async () => {
  const broken = new MockArbiter({ classifyFn: trusted, agentReceiptTaintFn: () => { throw new Error("socket closed"); } });
  await assert.rejects(
    rewriteRequest(turn([{ id: "tu_fetch", name: "WebFetch", input: { url: "http://localhost:3000/" }, content: PAGE }]), { arbiter: broken, sessionKey: "s" }),
    (e: unknown) => e instanceof RewriteRefusal && /agentReceiptTaint failed/.test((e as Error).message),
  );
  const old = new MockArbiter({ classifyFn: trusted });
  const { request } = await rewriteRequest(turn([{ id: "tu_fetch", name: "WebFetch", input: { url: "http://localhost:3000/" }, content: PAGE }]), { arbiter: old, sessionKey: "s" });
  assert.ok(forwarded(request, 0).includes("hunter2"), "an arbiter predating the op: today's behaviour");
});
