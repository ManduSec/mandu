/**
 * backstop-secret-by — confidentiality-plan-15-prompt-filter.md §4.1, "What
 * a raised row registers": the proxy tells the arbiter (`secretBy:
 * "value-backstop"`) that a result it symbolizes is secret by the arbiter's
 * value backstop alone, only when the classify said so (`raisedBy`) and the
 * proxy raised the level no further, and (`secretBy: "path-rule"`, plan 15
 * §13.12) that it is secret by the classify's own path rule alone. Any
 * raise of its own (a tainted call tree) names nothing, so the arbiter
 * keeps every line of the row (fail-closed). The real-arbiter e2e is
 * tests/stack/backstop-raised-row.test.ts.
 *
 * Axes: the mock answers levels as the confidentiality axis ON does.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { rewriteRequest } from "../../src/rewrite-request.js";
import { CLAUDE_CODE_GATE_SURFACE } from "../../src/gate-surface.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import type { MessagesRequest, Message } from "../../src/messages-types.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const EMPTY: CallTaintWire = { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] };
const RAISED: ClassifyResult = { trust: "TRUSTED", category: null, reason: "mock: a registered secret appears verbatim", confidentiality: "no-model", raisedBy: "value-backstop" };
const POLICY: ClassifyResult = { trust: "TRUSTED", category: null, reason: "mock: a labelled path", confidentiality: "no-model" };

function req(name: string, input: Record<string, unknown>, result: string): MessagesRequest {
  const messages: Message[] = [
    { role: "user", content: "go" },
    { role: "assistant", content: [{ type: "tool_use", id: "toolu_1", name, input }] } as Message,
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_1", content: result }] } as Message,
  ];
  return { model: "claude-sonnet-5", max_tokens: 64, messages } as MessagesRequest;
}

test("secretBy: a Read raised by the value backstop alone says so on its symbolize", async () => {
  const a = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: () => RAISED, callTaintFn: () => ({ ...EMPTY }) });
  await rewriteRequest(req("Read", { file_path: "/w/notes.md" }, "     1\t## heading\n     2\tKEY=x\n"), { arbiter: a, sessionKey: "s" });
  assert.equal(a.symbolizeCalls.length, 1);
  assert.equal(a.symbolizeCalls[0]!.secretBy, "value-backstop");
});

test("secretBy: a verdict secret by the path rule alone says path-rule (plan 15 §13.12); one the proxy raised by a tainted tree names nothing", async () => {
  const policy = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: () => POLICY, callTaintFn: () => ({ ...EMPTY }) });
  await rewriteRequest(req("Read", { file_path: "/w/vault/a.env" }, "KEY=x\n"), { arbiter: policy, sessionKey: "s" });
  assert.equal(policy.symbolizeCalls[0]!.secretBy, "path-rule", "secret by the path rule alone (the arbiter decides what it means)");

  const pathTainted = new MockArbiter({
    gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: () => POLICY,
    callTaintFn: () => ({ ...EMPTY, level: "no-model", files: ["/w/vault/a.env"], apps: ["cat"], root: "p1", evidence: "tree" }),
  });
  await rewriteRequest(req("Bash", { command: "cat vault/a.env notes.md" }, "KEY=x\n"), { arbiter: pathTainted, sessionKey: "s" });
  assert.ok(pathTainted.symbolizeCalls.length > 0);
  assert.ok(pathTainted.symbolizeCalls.every((c) => c.secretBy === undefined), "a path verdict the proxy raised by a tainted tree");

  const tainted = new MockArbiter({
    gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: () => RAISED,
    callTaintFn: () => ({ ...EMPTY, level: "no-model", files: ["/w/vault/a.env"], apps: ["cat"], root: "p1", evidence: "tree" }),
  });
  await rewriteRequest(req("Bash", { command: "cat notes.md" }, "KEY=x\n"), { arbiter: tainted, sessionKey: "s" });
  assert.ok(tainted.symbolizeCalls.length > 0);
  assert.ok(tainted.symbolizeCalls.every((c) => c.secretBy === undefined), "the proxy's own taint raise");

  const plain = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: () => ({ trust: "UNTRUSTED", category: null, reason: "mock" }), callTaintFn: () => ({ ...EMPTY }) });
  await rewriteRequest(req("Read", { file_path: "/w/n.md" }, "hello\n"), { arbiter: plain, sessionKey: "s" });
  assert.ok(plain.symbolizeCalls.every((c) => c.secretBy === undefined), "not secret at all");
});
