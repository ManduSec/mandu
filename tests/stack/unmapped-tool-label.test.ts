/**
 * unmapped-tool-label — plan 10 §11.11 over the REAL components: a tool the
 * session's inbound spec does not map has EVERY string of its input read for
 * labeled paths, so its result is masked when it names one, for OpenClaw
 * through the anthropic-proxy and for a Codex MCP tool through the
 * openai-proxy, via the production adapters
 * (`new XAdapter(new ArbiterClient(sock))`).
 *
 * Before: the path-derived level read only the origin and four named params
 * (`file_path`, `path`, `notebook_path`, `command`), so an unmapped tool that
 * named its path `target` returned a labeled file's text to the model raw in
 * `secrets` mode. The paths ride the AgentView spelling on the wire (a view
 * map), so this also pins the HumanView copy of every string. A mapped tool
 * is unchanged: a secret path under a key its spec does not read stays unread.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { rewriteRequest } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import { ViewMap } from "../../interceptors/anthropic-proxy/src/view-map.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import {
  ArbiterClientAdapter as OpenAiProxyArbiterAdapter,
  type RealArbiterClient as OpenAiProxyRealArbiterClient,
} from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { rewriteRequest as rewriteResponsesRequest } from "../../interceptors/openai-proxy/src/rewrite-request.js";
import type { ResponsesRequest } from "../../interceptors/openai-proxy/src/responses-types.js";
import { compilePolicy, resetCurrentPolicyForTests, swapCurrentPolicy } from "../../arbiter/policy/compiled-policy.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const CONTRACT = "ACME master services agreement: fee schedule 4.2M, termination 90 days";

function toolResult(id: string, name: string, input: Record<string, unknown>, content: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "summarize it" },
      { role: "assistant", content: [{ type: "tool_use", id, name, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  };
}
const forwarded = (r: MessagesRequest): string => JSON.stringify((r.messages[2]!.content as any[])[0].content);

function codexCall(id: string, name: string, args: Record<string, unknown>, output: string): ResponsesRequest {
  return {
    model: "gpt-5.5",
    instructions: "You are Codex.",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "summarize it" }] },
      { type: "function_call", call_id: id, name, arguments: JSON.stringify(args) },
      { type: "function_call_output", call_id: id, output },
    ],
  } as ResponsesRequest;
}
const codexForwarded = (r: ResponsesRequest, id: string): string =>
  String((r.input as any[]).find((i) => i.type === "function_call_output" && i.call_id === id).output);

test("an unmapped tool naming a labeled file under any key is masked (OpenClaw via anthropic-proxy, Codex MCP via openai-proxy); a mapped tool is unchanged (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-unmapped-label-e2e-"));
  const human = join(tmp, "human");
  const agent = join(tmp, "agent");
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` mode axes, stated
  });
  await server.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect(); // labeling acts are admin-only
  const realA: RealArbiterClient = new ArbiterClient(socketPath); await realA.connect();
  const realO: OpenAiProxyRealArbiterClient = new ArbiterClient(socketPath); await realO.connect();
  const claude = new ArbiterClientAdapter(realA);
  const codex = new OpenAiProxyArbiterAdapter(realO);
  const vm = new ViewMap([{ human, agent }], { dialect: "posix" });
  const toHumanView = (s: string): string => vm.mapText(s, "reverse");
  const oc = `unmapped-oc-${process.pid}`;
  const cx = `unmapped-cx-${process.pid}`;
  try {
    await admin.setPathLabel({ path: join(human, "contracts"), confidentiality: "any-model" });
    const bound = await admin.setSessionSpec({ sessionKey: oc, spec: "openclaw-agent", requestedBy: "unmapped-tool-label e2e" });
    assert.equal(bound.bound, "openclaw-agent");
    const contractAgentPath = join(agent, "contracts", "q3.md");

    // 1. OpenClaw, an unmapped tool naming the file `target` (AgentView spelling)
    const a = await rewriteRequest(toolResult("tu_u1", "acme_blob_reader", { target: contractAgentPath }, CONTRACT), { arbiter: claude, sessionKey: oc, toHumanView });
    assert.equal(a.rewrites[0]!.symbolized, true, a.rewrites[0]!.reason);
    assert.ok(!forwarded(a.request).includes("fee schedule"), "CONFIDENTIALITY VIOLATION: a labeled file reached the model raw through an unmapped tool");
    assert.match(a.rewrites[0]!.reason ?? "", /unmapped tool/);

    // 2. the same tool reached through the dispatcher (tool_call, unmapped on purpose)
    const d = await rewriteRequest(
      toolResult("tu_u2", "tool_call", { id: "acme_blob_reader", args: { src: { files: [contractAgentPath] } } }, CONTRACT),
      { arbiter: claude, sessionKey: oc, toHumanView },
    );
    assert.equal(d.rewrites[0]!.symbolized, true, d.rewrites[0]!.reason);
    assert.ok(!forwarded(d.request).includes("fee schedule"));

    // 3. plan 10 §11.18 (2026-10-07): a tool Mandu has no mapping for is
    //    masked whole even when its input names nothing labeled…
    const p0 = await rewriteRequest(toolResult("tu_u3", "acme_blob_reader", { target: join(agent, "notes.md") }, "plain public notes"), { arbiter: claude, sessionKey: oc, toHumanView });
    assert.equal(p0.rewrites[0]!.symbolized, true, p0.rewrites[0]!.reason);
    assert.match(p0.rewrites[0]!.reason ?? "", /no mapping for the tool acme_blob_reader/);
    //    …until policy.yaml lists it under `mapped_tools:`: then a file it
    //    names that is labeled still masks it (the input scan), and one that
    //    is not does not over-mask
    swapCurrentPolicy(compilePolicy({ specId: "claude-code", document: { mapped_tools: ["acme_blob_reader"] } }));
    const listed = await rewriteRequest(toolResult("tu_u5", "acme_blob_reader", { target: contractAgentPath }, CONTRACT), { arbiter: claude, sessionKey: oc, toHumanView });
    assert.equal(listed.rewrites[0]!.symbolized, true, listed.rewrites[0]!.reason);
    assert.ok(!forwarded(listed.request).includes("fee schedule"), "CONFIDENTIALITY VIOLATION: a listed tool naming a labeled file reached the model raw");
    // (another text: the masked result above is now a registered value, the §11.18 cost)
    const p = await rewriteRequest(toolResult("tu_u6", "acme_blob_reader", { target: join(agent, "notes.md") }, "other public notes"), { arbiter: claude, sessionKey: oc, toHumanView });
    assert.equal(p.rewrites[0]!.symbolized, false, p.rewrites[0]!.reason);
    assert.ok(forwarded(p.request).includes("other public notes"));

    // 4. a MAPPED tool is unchanged: `read` reads `path`, not an unrelated key
    const m = await rewriteRequest(
      toolResult("tu_m1", "read", { path: join(agent, "notes.md"), note: contractAgentPath }, "read notes, never masked"),
      { arbiter: claude, sessionKey: oc, toHumanView },
    );
    assert.equal(m.rewrites[0]!.symbolized, false, m.rewrites[0]!.reason);

    // 5. Codex: an MCP tool (no exact entry in the spec) naming the file `target`
    const c = await rewriteResponsesRequest(
      codexCall("call_u1", "mcp__files__fetch", { target: contractAgentPath }, CONTRACT),
      { arbiter: codex, sessionKey: cx, toHumanView },
    );
    assert.equal(c.rewrites[0]!.symbolized, true, c.rewrites[0]!.reason);
    assert.ok(!codexForwarded(c.request, "call_u1").includes("fee schedule"), "CONFIDENTIALITY VIOLATION: a labeled file reached the model raw through a Codex MCP tool");
  } finally {
    admin.close(); realA.close(); realO.close();
    await server.close();
    resetCurrentPolicyForTests("claude-code");
    rmSync(tmp, { recursive: true, force: true });
  }
});
