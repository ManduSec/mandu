/**
 * mcp-server-taint (e2e, Claude Code) — plan 10 §11.13's per-server rule
 * through the REAL AnthropicProxy: an MCP result whose server's own process
 * tree read a secret raw is masked whole before it is forwarded; a clean
 * server's result is forwarded as before (raw, no command in the input).
 * Rule (c), on Claude Code since 2026-10-03: an unmapped server's result is
 * masked whole while the session holds a raw read, raw otherwise. Only adds
 * masking.
 *
 * Axes: `secrets`, stated through the mock (classify TRUSTED with no level;
 * mcpServerTaint as the arbiter answers with the confidentiality axis on).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { AnthropicProxy } from "../../src/proxy.js";
import type { CallTaintWire, McpServerTaintWire } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildTextSse } from "../helpers/mock-upstream.js";

const ROWS = "card | 4411-5522-6633-7744";

function call(port: number, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    req.on("error", reject);
    req.end(body);
  });
}

async function forwardedFor(verdict: McpServerTaintWire["verdict"], session?: CallTaintWire): Promise<string> {
  const arbiter = new MockArbiter({
    ...(session ? { callTaintFn: () => session } : {}),
    classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "mock: integrity off" }),
    mcpServerTaintFn: (r) => ({ verdict, server: "store", candidates: 1, level: verdict === "tainted" ? "no-model" : null, files: verdict === "tainted" ? ["/h/.npmrc"] : [], apps: verdict === "tainted" ? ["node"] : [], ...(r.tool.startsWith("mcp__store__") ? {} : { verdict: "unmapped" as const }) }),
  });
  const up = new MockUpstream({ sse: buildTextSse("ok") });
  const proxy = new AnthropicProxy({ arbiter, upstream: up.fetcher, sessionKey: "mcp-srv", log: () => {} });
  const port = await proxy.listen(0);
  try {
    const body = JSON.stringify({
      model: "claude-sonnet-5", stream: true,
      messages: [
        { role: "user", content: "read the rows from the store" },
        { role: "assistant", content: [{ type: "tool_use", id: "tu_get", name: "mcp__store__get", input: { key: "rows" } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_get", content: ROWS }] },
      ],
    });
    assert.equal(await call(port, body), 200);
    return up.requests[0]!.bodyText;
  } finally { await proxy.close(); }
}

test("a tainted MCP server's result never reaches the model; a clean one, or an unmapped one in a session with no raw read, is forwarded", async () => {
  const tainted = await forwardedFor("tainted");
  assert.ok(!tainted.includes("4411-5522"), "CONFIDENTIALITY VIOLATION: a tainted MCP server's result reached the model");
  assert.match(tainted, /masked: node read \/h\/\.npmrc/);
  for (const v of ["clean", "unmapped"] as const) assert.ok((await forwardedFor(v)).includes("4411-5522"), `${v}: unchanged`);
});

test("rule (c) on Claude Code: an unmapped server's result never reaches the model while the session holds a raw read; a clean one does", async () => {
  const held: CallTaintWire = { level: "no-model", files: ["/h/.pgpass"], apps: ["psql"], rule: "secret", mask: [], root: null, denied: [], evidence: "session" };
  const unmapped = await forwardedFor("unmapped", held);
  assert.ok(!unmapped.includes("4411-5522"), "CONFIDENTIALITY VIOLATION: an unmapped MCP server's result reached the model in a session holding a raw read");
  assert.match(unmapped, /MCP server whose state Mandu cannot see, and programs in this session read \.pgpass raw/);
  assert.ok((await forwardedFor("clean", held)).includes("4411-5522"), "a server proven clean is not asked about the session");
});
