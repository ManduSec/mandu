/**
 * agent-gate-surface (proxy e2e) — through the REAL AnthropicProxy with a mock
 * arbiter that answers the `gateSurface` op for an OpenCode session: the gates
 * that read the agent's SHELL tool fire on `bash`, not only on Claude Code's
 * `Bash` (agent-e2e-harness.md §7.7).
 *
 *   exec      a `bash` tool_use with a symbol in command position reaches the
 *             agent as the exit-77 sentinel;
 *   callTaint the process-tree taint is asked for a `bash` RESULT, so a tree
 *             that read a secret masks the whole output. This is the
 *             confidentiality leg of the DEFAULT `secrets` mode, where a shell
 *             result is otherwise forwarded raw (integrity OFF): before the
 *             table, an OpenCode `bash` result that `cat`s a secret reached the
 *             model verbatim;
 *   twin note the symbol-twin note rides an OpenCode `bash` result too.
 *
 * Each has a CONTROL with the arbiter answering Claude Code's surface: the
 * pre-2026-09-27 behavior every session got, shown so the fix is visible in
 * the suite. And the arbiter-misbehaves case: an OpenCode session whose
 * `gateSurface` fails still gets the exec gate (the proxy falls back to the
 * union of every agent's table).
 * The real-arbiter version (exec/net/fs over real IPC, both agents) is
 * tests/stack/agent-gate-surface.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AnthropicProxy } from "../../src/proxy.js";
import { ViewMap } from "../../src/view-map.js";
import { EXEC_BLOCK_EXIT_CODE } from "../../src/exec-gate.js";
import { CLAUDE_CODE_GATE_SURFACE, type GateSurface } from "../../src/gate-surface.js";
import type { ClassifyResult } from "../../src/arbiter-client.js";
import { SseToolUseParser, type ReconstructedToolUse } from "../../src/sse-parser.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildToolUseSse } from "../helpers/mock-upstream.js";

const OPENCODE: GateSurface = {
  spec: "opencode",
  exec: { bash: "command" },
  execOutput: { bash: "command" },
  net: { webfetch: { destination: "url", symbols: "url" } },
  paths: { read: { fields: ["filePath"], mode: "read" }, write: { fields: ["filePath"], mode: "write" } },
  dispatch: {},
  refuse: {},
  refuseArgs: {},
  stdin: {},
};

function post(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": "oc-1" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function toolUsesOf(sse: string): ReconstructedToolUse[] {
  const seen: ReconstructedToolUse[] = [];
  const p = new SseToolUseParser((tu) => seen.push(tu));
  p.feed(sse);
  p.end();
  return seen;
}

function bashTurn(command: string, output: string, id = "toolu_oc"): string {
  return JSON.stringify({
    model: "claude-sonnet-5",
    stream: false,
    tools: [{ name: "bash", input_schema: { type: "object", properties: { command: { type: "string" } } } }],
    messages: [
      { role: "user", content: "go" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "bash", input: { command } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
    ],
  });
}

async function withProxy(
  arbiter: MockArbiter,
  upstream: MockUpstream,
  fn: (port: number) => Promise<void>,
  viewMap?: ViewMap,
): Promise<void> {
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, sessionKey: "oc-1", log: () => {}, ...(viewMap ? { viewMap } : {}) });
  const port = await proxy.listen(0);
  try { await fn(port); } finally { await proxy.close(); }
}

test("exec gate: an OpenCode `bash` tool_use with a symbol in command position reaches the agent as the exit-77 sentinel (control: ungated on Claude Code's surface)", async () => {
  const sse = buildToolUseSse({ id: "tu_x", name: "bash", input: { command: 'bash -c "$MDU:bash[a1b2]"' } });
  const gated = new MockArbiter({ gateSurfaceFn: () => OPENCODE });
  await withProxy(gated, new MockUpstream({ sse }), async (port) => {
    const r = await post(port, JSON.stringify({ model: "m", stream: true, messages: [{ role: "user", content: "go" }] }));
    const cmd = String((toolUsesOf(r.body)[0]!.input as Record<string, unknown>)["command"]);
    assert.match(cmd, new RegExp(`exit ${EXEC_BLOCK_EXIT_CODE}$`));
    assert.deepEqual(gated.gateSurfaceCalls[0], { sessionKey: "oc-1" }, "asked for THIS session's surface");
  });
  const control = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE });
  await withProxy(control, new MockUpstream({ sse }), async (port) => {
    const r = await post(port, JSON.stringify({ model: "m", stream: true, messages: [{ role: "user", content: "go" }] }));
    assert.equal((toolUsesOf(r.body)[0]!.input as Record<string, unknown>)["command"], 'bash -c "$MDU:bash[a1b2]"');
    assert.equal(control.execGateCalls.length, 0);
  });
});

test("arbiter misbehaves: an OpenCode session whose gateSurface THROWS, answers MALFORMED, or is ABSENT still has `bash -c \"$MDU:…\"` rewritten to the exit-77 sentinel (union fallback)", async () => {
  const sse = buildToolUseSse({ id: "tu_x", name: "bash", input: { command: 'bash -c "$MDU:bash[a1b2]"' } });
  const cases: Array<[string, MockArbiter]> = [
    ["throws", new MockArbiter({ gateSurfaceFn: () => { throw new Error("arbiter down"); } })],
    ["malformed", new MockArbiter({ gateSurfaceFn: () => ({ spec: "opencode", exec: "bash" }) })],
    ["absent op", new MockArbiter()],
  ];
  for (const [label, arbiter] of cases) {
    await withProxy(arbiter, new MockUpstream({ sse }), async (port) => {
      const r = await post(port, JSON.stringify({ model: "m", stream: true, messages: [{ role: "user", content: "go" }] }));
      const cmd = String((toolUsesOf(r.body)[0]!.input as Record<string, unknown>)["command"]);
      assert.match(cmd, new RegExp(`exit ${EXEC_BLOCK_EXIT_CODE}$`), `${label}: gated (got ${cmd})`);
      assert.equal(arbiter.execGateCalls.length, 1, `${label}: the arbiter's exec gate decided`);
    });
  }
});

test("callTaint (secrets mode's shell leg): an OpenCode `bash` result whose tree read a secret is masked whole, with the note (control: forwarded raw)", async () => {
  // integrity OFF: classify says TRUSTED, so only the taint leg protects the output
  const trusted = (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock: integrity off" });
  const taintCalls: Array<{ callId: string; command?: string }> = [];
  const arbiter = new MockArbiter({
    gateSurfaceFn: () => OPENCODE,
    classifyFn: trusted,
    callTaintFn: (req) => {
      taintCalls.push(req);
      return { level: "no-model", rule: "secret", files: ["/h/.env"], apps: ["cat"], mask: [], root: "bash-1", denied: [] };
    },
  });
  const up = new MockUpstream({ json: { type: "message", role: "assistant", content: [] } });
  await withProxy(arbiter, up, async (port) => {
    assert.equal((await post(port, bashTurn("cat .env", "API_KEY=sk-live-9f8e7d"))).status, 200);
    const fwd = up.requests[0]!.bodyText;
    assert.ok(!fwd.includes("sk-live-9f8e7d"), "the secret never reaches the model");
    assert.match(fwd, /\[mandu:secret\] masked: cat read \/h\/\.env/);
    assert.deepEqual(taintCalls, [{ callId: "toolu_oc", command: "cat .env", sessionKey: "oc-1" }]);
  });
  // Control: under Claude Code's table `bash` is no shell, so the mapped leg
  // never asks; the unmapped-command backstop (plan 10 §11.12) asks instead,
  // as `unmappedTool`, and an arbiter with no taint to report forwards it raw.
  const controlCalls: Array<Record<string, unknown>> = [];
  const control = new MockArbiter({
    gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: trusted,
    callTaintFn: (req) => { controlCalls.push({ ...req }); return { level: null, rule: "secret", files: [], apps: [], mask: [], root: null, denied: [] }; },
  });
  const up2 = new MockUpstream({ json: { type: "message", role: "assistant", content: [] } });
  await withProxy(control, up2, async (port) => {
    await post(port, bashTurn("cat .env", "API_KEY=sk-live-9f8e7d"));
    assert.ok(up2.requests[0]!.bodyText.includes("sk-live-9f8e7d"), "control: without the agent's table and no taint, the bash result is forwarded raw");
    assert.deepEqual(controlCalls, [{ callId: "toolu_oc", command: "cat .env", sessionKey: "oc-1", unmappedTool: "bash" }]);
  });
});

test("twin note: an OpenCode `bash` result over an untrusted AgentView twin carries the [mandu:twin] note", async () => {
  const base = mkdtempSync(join(tmpdir(), "oc-twin-"));
  const human = join(base, "ws");
  const agent = join(base, "view-state", "agentview");
  mkdirSync(human, { recursive: true });
  mkdirSync(agent, { recursive: true });
  writeFileSync(join(human, "notes.md"), "line1\nline2\nMDUINJECT\n");
  writeFileSync(join(agent, "notes.md"), "$MDU:read[2d3e].notes.md\n");
  try {
    const arbiter = new MockArbiter({ gateSurfaceFn: () => OPENCODE });
    const up = new MockUpstream({ json: { type: "message", role: "assistant", content: [] } });
    const viewMap = new ViewMap([{ human, agent }], { dialect: "posix", home: base });
    await withProxy(arbiter, up, async (port) => {
      await post(port, bashTurn(`sed -n '3p' ${join(agent, "notes.md")}`, "(no output)"));
      const fwd = up.requests[0]!.bodyText;
      assert.match(fwd, /\[mandu:twin\] [^"\\]*notes\.md is an untrusted file/);
      assert.ok(!fwd.includes("(no output)"), "the raw body never reaches upstream");
    }, viewMap);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
