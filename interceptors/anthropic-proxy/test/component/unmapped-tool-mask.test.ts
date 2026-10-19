/**
 * unmapped-tool-mask (proxy e2e) — confidentiality plan 10 §11.18 (P0 item
 * 4b, the maintainer's decision of 2026-10-07) through the REAL
 * AnthropicProxy with a mock upstream, in a session that read NOTHING: for
 * each agent the proxy serves (Claude Code, OpenCode, Goose, OpenClaw; the
 * gate surface from the arbiter's op, as in production) a tool Mandu has no
 * mapping for reaches the model only as a symbol, with the note on why and
 * how to let it through (policy.yaml `mapped_tools:`); a tool the agent's
 * spec names is forwarded. MASTER: every one raw.
 *
 * Axes: `secrets`, stated through the mock (classify TRUSTED with no level;
 * callTaint as the arbiter answers it with the confidentiality axis on: the
 * real form is tests/stack/unmapped-tool-mask.test.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { AnthropicProxy } from "../../src/proxy.js";
import { CLAUDE_CODE_GATE_SURFACE, type GateSurface } from "../../src/gate-surface.js";
import type { CallTaintWire } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildTextSse } from "../helpers/mock-upstream.js";

const ROWS = "card | 4411-5522-6633-7744";
const EMPTY: CallTaintWire = { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] };

const surface = (spec: string, shell: string): GateSurface => ({ ...CLAUDE_CODE_GATE_SURFACE, spec, exec: { [shell]: "command" }, execOutput: { [shell]: "command" }, net: {}, paths: {} });

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

async function upstreamBody(gs: GateSurface, known: readonly string[], tools: string[]): Promise<string> {
  const arbiter = new MockArbiter({
    classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "mock: integrity off" }),
    gateSurfaceFn: () => gs,
    callTaintFn: (r) => (r.unmappedTool === undefined || known.includes(r.unmappedTool)
      ? EMPTY
      : { ...EMPTY, level: "no-model", evidence: "unmapped", why: `Mandu has no mapping for the tool ${r.unmappedTool}, so its whole result is hidden from the AI. To let it through, list \`${r.unmappedTool}\` under \`mapped_tools:\` in policy.yaml` }),
  });
  const up = new MockUpstream({ sse: buildTextSse("ok") });
  const proxy = new AnthropicProxy({ arbiter, upstream: up.fetcher, sessionKey: "unmapped-e2e", log: () => {} });
  const port = await proxy.listen(0);
  try {
    const messages: unknown[] = [{ role: "user", content: "go" }];
    tools.forEach((name, i) => {
      messages.push({ role: "assistant", content: [{ type: "tool_use", id: `tu_${i}`, name, input: { q: "rows" } }] });
      messages.push({ role: "user", content: [{ type: "tool_result", tool_use_id: `tu_${i}`, content: `${ROWS} (${name})` }] });
    });
    assert.equal(await call(port, JSON.stringify({ model: "claude-sonnet-5", stream: true, messages })), 200);
    return up.requests[0]!.bodyText;
  } finally { await proxy.close(); }
}

const CASES: Array<{ agent: string; gs: GateSurface; known: string; unmapped: string[] }> = [
  { agent: "Claude Code", gs: CLAUDE_CODE_GATE_SURFACE, known: "Read", unmapped: ["NewTool", "mcp__remote__search", "ListMcpResourcesTool"] },
  { agent: "OpenCode", gs: surface("opencode", "bash"), known: "read", unmapped: ["notes_get", "leaktool"] },
  { agent: "Goose", gs: surface("goose", "shell"), known: "tree", unmapped: ["crm__lookup", "memory__retrieve_memories"] },
  { agent: "OpenClaw", gs: surface("openclaw-agent", "exec"), known: "read", unmapped: ["plugin_lookup"] },
];

for (const c of CASES) {
  test(`${c.agent}: a tool Mandu has no mapping for reaches the model only as a symbol in a session that read nothing; ${c.known} is forwarded`, async () => {
    const wire = await upstreamBody(c.gs, [c.known], [...c.unmapped, c.known]);
    for (const name of c.unmapped) {
      assert.ok(!wire.includes(`${ROWS} (${name})`), `${c.agent} ${name}: CONFIDENTIALITY: an unmapped tool's result reached the model raw`);
      assert.match(wire, new RegExp(`no mapping for the tool ${name}`));
    }
    assert.match(wire, /\$MDU:/);
    assert.match(wire, /mapped_tools/);
    assert.ok(wire.includes(`${ROWS} (${c.known})`), `${c.known}: forwarded`);
  });
}
