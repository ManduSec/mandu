/**
 * mcp-server-taint (unit, Claude Code) — plan 10 §11.13, the per-server rule
 * in the anthropic-proxy's request rewrite: an MCP result is masked whole
 * when the arbiter says its SERVER's own process tree read a secret raw (or
 * the answer cannot be read); a clean server keeps its behaviour (raw unless
 * the input carries a command, §11.12). Since 2026-10-03 (maintainer) rule
 * (c) holds on Claude Code too: an unmapped server's result, and an MCP
 * resource read, is asked about the session with no command and masked whole
 * while the session holds a raw read. Only adds masking.
 *
 * Axes: `secrets`, stated through the mock (classify TRUSTED with no level,
 * integrity off; mcpServerTaint and callTaint as the arbiter answers them
 * with the confidentiality axis on).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { rewriteRequest } from "../../src/rewrite-request.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import type { CallTaintWire, McpServerTaintWire } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const ROWS = "card | 4411-5522-6633-7744";
const answer = (verdict: McpServerTaintWire["verdict"], extra: Partial<McpServerTaintWire> = {}): McpServerTaintWire =>
  ({ verdict, candidates: verdict === "clean" ? 1 : 0, level: null, files: [], apps: [], ...extra });
const TAINTED = answer("tainted", { server: "store", candidates: 1, level: "no-model", files: ["/h/.npmrc"], apps: ["node"] });

function turn(name: string, input: Record<string, unknown>, content: string): MessagesRequest {
  return {
    model: "claude-sonnet-5",
    messages: [
      { role: "user", content: "go" },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_1", name, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_1", content }] },
    ],
  };
}
const forwarded = (r: MessagesRequest): string => JSON.stringify((r.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);
const SESSION: CallTaintWire = { level: "no-model", files: ["/h/.pgpass"], apps: ["psql"], rule: "secret", mask: [], root: null, denied: [], evidence: "session" };
const EMPTY: CallTaintWire = { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] };
const trusted = () => ({ trust: "TRUSTED" as const, category: null, reason: "mock: integrity off" });

test("a tainted server's result is masked whole, even with no command in the input", async () => {
  const asked: Array<{ tool: string; sessionKey?: string }> = [];
  const arbiter = new MockArbiter({ classifyFn: trusted, mcpServerTaintFn: (r) => { asked.push(r); return TAINTED; } });
  const { request, rewrites } = await rewriteRequest(turn("mcp__store__get", { key: "rows" }, ROWS), { arbiter, sessionKey: "s" });
  assert.ok(!forwarded(request).includes("4411-5522"), "CONFIDENTIALITY VIOLATION: a tainted MCP server's result reached the model");
  assert.equal(rewrites[0]!.symbolized, true);
  assert.equal(rewrites[0]!.confidentiality, "no-model");
  assert.match(forwarded(request), /\[mandu:secret\] masked: node read \/h\/\.npmrc/);
  assert.deepEqual(asked, [{ tool: "mcp__store__get", sessionKey: "s" }]);
});

test("a clean server keeps its behaviour: raw with no command, and the session is not asked", async () => {
  const asked: unknown[] = [];
  const arbiter = new MockArbiter({ classifyFn: trusted, mcpServerTaintFn: () => answer("clean"), callTaintFn: (r) => { asked.push(r); return SESSION; } });
  const { request } = await rewriteRequest(turn("mcp__store__get", { key: "rows" }, ROWS), { arbiter, sessionKey: "s" });
  assert.ok(forwarded(request).includes("4411-5522"), "clean: unchanged (raw)");
  assert.deepEqual(asked, [], "a server proven clean is never asked about the session");
});

// 2026-10-03 (maintainer): rule (c) on Claude Code. An MCP server Mandu cannot
// map (HTTP, remote, not registered, two candidates, never spawned) or an
// arbiter without the per-server op: the session decides, as on Codex.
test("an unmapped server (or an arbiter without the op) is asked about the session with no command; a session holding a raw read masks it whole", async () => {
  for (const v of ["unmapped", null] as const) {
    const asked: Array<{ callId: string; command?: string; unmappedTool?: string; sessionKey?: string }> = [];
    const arbiter = new MockArbiter({ classifyFn: trusted, ...(v ? { mcpServerTaintFn: () => answer(v) } : {}), callTaintFn: (r) => { asked.push(r); return SESSION; } });
    const { request, rewrites } = await rewriteRequest(turn("mcp__store__get", { key: "rows" }, ROWS), { arbiter, sessionKey: "s" });
    assert.ok(!forwarded(request).includes("4411-5522"), `${v}: CONFIDENTIALITY VIOLATION: an unmapped MCP server's result reached the model in a session holding a raw read`);
    assert.equal(rewrites[0]!.confidentiality, "no-model");
    assert.match(forwarded(request), /MCP server whose state Mandu cannot see/);
    assert.deepEqual(asked, [{ callId: "tu_1", sessionKey: "s", unmappedTool: "mcp__store__get" }], `${v}: asked bare`);
  }
});

test("an unmapped server in a session with no raw read, and Mandu's own tools, stay raw", async () => {
  for (const v of ["unmapped", "own"] as const) {
    const arbiter = new MockArbiter({ classifyFn: trusted, mcpServerTaintFn: () => answer(v), callTaintFn: () => EMPTY });
    const { request } = await rewriteRequest(turn("mcp__store__get", { key: "rows" }, ROWS), { arbiter, sessionKey: "s" });
    assert.ok(forwarded(request).includes("4411-5522"), `${v}: raw when the arbiter answers empty`);
  }
});

test("a session ask that throws masks the unmapped server's result (fail-closed)", async () => {
  const arbiter = new MockArbiter({ classifyFn: trusted, mcpServerTaintFn: () => answer("unmapped"), callTaintFn: () => { throw new Error("socket closed"); } });
  const { request } = await rewriteRequest(turn("mcp__store__get", {}, ROWS), { arbiter, sessionKey: "s" });
  assert.ok(!forwarded(request).includes("4411-5522"));
  assert.match(forwarded(request), /could not be read: masked \(fail-closed\)/);
});

test("Claude Code's MCP resource tools are an MCP server's output: asked about the session, never mapped per server", async () => {
  for (const [name, input] of [["ReadMcpResourceTool", { server: "store", uri: "store://rows" }], ["ListMcpResourcesTool", { server: "store" }]] as const) {
    const servers: string[] = [];
    const asked: Array<{ unmappedTool?: string; command?: string }> = [];
    const arbiter = new MockArbiter({ classifyFn: trusted, mcpServerTaintFn: (r) => { servers.push(r.tool); return answer("clean"); }, callTaintFn: (r) => { asked.push(r); return SESSION; } });
    const { request } = await rewriteRequest(turn(name, input, ROWS), { arbiter, sessionKey: "s" });
    assert.ok(!forwarded(request).includes("4411-5522"), `${name}: CONFIDENTIALITY VIOLATION: an MCP resource reached the model in a session holding a raw read`);
    assert.match(forwarded(request), /MCP server whose state Mandu cannot see/);
    assert.deepEqual(servers, [], `${name}: no per-server verdict (the server field is the model's)`);
    assert.deepEqual(asked.map((a) => [a.unmappedTool, a.command]), [[name, undefined]]);
    const quiet = new MockArbiter({ classifyFn: trusted, callTaintFn: () => EMPTY });
    assert.ok(forwarded((await rewriteRequest(turn(name, input, ROWS), { arbiter: quiet, sessionKey: "s" })).request).includes("4411-5522"), `${name}: raw with no raw read`);
  }
});

test("an answer that cannot be read masks (fail-closed); non-MCP tools are never asked", async () => {
  const asked: string[] = [];
  const broken = new MockArbiter({ classifyFn: trusted, mcpServerTaintFn: (r) => { asked.push(r.tool); throw new Error("socket closed"); } });
  const { request } = await rewriteRequest(turn("mcp__store__get", {}, ROWS), { arbiter: broken, sessionKey: "s" });
  assert.ok(!forwarded(request).includes("4411-5522"));
  assert.match(forwarded(request), /could not be read: masked \(fail-closed\)/);
  await rewriteRequest(turn("Read", { file_path: "/w/notes.md" }, "notes"), { arbiter: broken, sessionKey: "s" });
  assert.deepEqual(asked, ["mcp__store__get"]);
});

test("plan 13 §9 R4 with rule (c): an MCP result masked by the session, by a tainted server or fail-closed carries is_error: false; a raw one keeps is_error: true", async () => {
  const failing = (name: string, input: Record<string, unknown>): MessagesRequest => {
    const r = turn(name, input, ROWS);
    ((r.messages[2]!.content as Array<{ is_error?: boolean }>)[0]!).is_error = true;
    return r;
  };
  const block = (r: MessagesRequest): { is_error?: boolean } => (r.messages[2]!.content as Array<{ is_error?: boolean }>)[0]!;
  const cases: Array<[string, MockArbiter, string, Record<string, unknown>]> = [
    ["unmapped, session holds a raw read", new MockArbiter({ classifyFn: trusted, mcpServerTaintFn: () => answer("unmapped"), callTaintFn: () => SESSION }), "mcp__store__get", { key: "rows" }],
    ["resource tool, session holds a raw read", new MockArbiter({ classifyFn: trusted, callTaintFn: () => SESSION }), "ReadMcpResourceTool", { server: "store", uri: "store://rows" }],
    ["tainted server", new MockArbiter({ classifyFn: trusted, mcpServerTaintFn: () => TAINTED }), "mcp__store__get", { key: "rows" }],
    ["session ask throws", new MockArbiter({ classifyFn: trusted, mcpServerTaintFn: () => answer("unmapped"), callTaintFn: () => { throw new Error("socket closed"); } }), "mcp__store__get", {}],
  ];
  for (const [what, arbiter, name, input] of cases) {
    const { request } = await rewriteRequest(failing(name, input), { arbiter, sessionKey: "s" });
    assert.ok(!forwarded(request).includes("4411-5522"), `${what}: masked`);
    assert.equal(block(request).is_error, false, `${what}: THE SIDE CHANNEL: a masked MCP result said the call failed`);
  }
  // control: an unmapped server in a session with no raw read stays raw, flag kept
  const quiet = new MockArbiter({ classifyFn: trusted, mcpServerTaintFn: () => answer("unmapped"), callTaintFn: () => EMPTY });
  const { request } = await rewriteRequest(failing("mcp__store__get", { key: "rows" }), { arbiter: quiet, sessionKey: "s" });
  assert.ok(forwarded(request).includes("4411-5522"));
  assert.equal(block(request).is_error, true);
});
