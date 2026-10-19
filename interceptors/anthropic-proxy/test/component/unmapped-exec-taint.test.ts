/**
 * unmapped-exec-taint (proxy e2e) — plan 10 §11.12 through the REAL
 * AnthropicProxy with a mock arbiter: a tool no gate surface knows as a shell
 * (here an MCP `run_command`) but whose input carries a command is asked
 * about with `unmappedTool`, and the answer only ever masks.
 *
 * Axes: the mock's classify answers TRUSTED with no level (integrity OFF, the
 * `secrets` default), so only the taint leg can protect the output. Each case
 * has its control. The real-arbiter version (both proxies, production
 * adapters) is tests/stack/unmapped-exec-taint.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { AnthropicProxy } from "../../src/proxy.js";
import { CLAUDE_CODE_GATE_SURFACE, UNION_GATE_SURFACE } from "../../src/gate-surface.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream } from "../helpers/mock-upstream.js";

const SECRET = "id | 4411-5522-6633-7744";
const TOOL = "mcp__box__run_command";

function post(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": "un-1" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

function turn(name: string, input: Record<string, unknown>, output: string, id = "toolu_un"): string {
  return JSON.stringify({
    model: "claude-sonnet-5",
    stream: false,
    messages: [
      { role: "user", content: "go" },
      { role: "assistant", content: [{ type: "tool_use", id, name, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
    ],
  });
}

const trusted = (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock: integrity off" });
const EMPTY: CallTaintWire = { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] };

async function forward(arbiter: MockArbiter, body: string): Promise<string> {
  const up = new MockUpstream({ json: { type: "message", role: "assistant", content: [] } });
  const proxy = new AnthropicProxy({ arbiter, upstream: up.fetcher, sessionKey: "un-1", log: () => {} });
  const port = await proxy.listen(0);
  try {
    assert.equal((await post(port, body)).status, 200);
    return up.requests[0]!.bodyText;
  } finally { await proxy.close(); }
}

test("session evidence: an unmapped command tool in a session where a reader read a secret raw is masked whole, with the note", async () => {
  const asked: Array<Record<string, unknown>> = [];
  const arbiter = new MockArbiter({
    gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE,
    classifyFn: trusted,
    callTaintFn: (req) => { asked.push({ ...req }); return { ...EMPTY, level: "no-model", files: ["/h/.pgpass"], apps: ["psql"], evidence: "session" }; },
  });
  const fwd = await forward(arbiter, turn(TOOL, { command: "psql -c 'select * from cards'" }, SECRET));
  assert.ok(!fwd.includes("4411-5522-6633-7744"), "the reader's output never reaches the model");
  assert.match(fwd, /\[mandu:secret\] masked: plan 10 §11\.12: mcp__box__run_command runs a command Mandu could not tie to a process tree, and programs in this session read \.pgpass raw/);
  assert.deepEqual(asked, [{ callId: "toolu_un", command: "psql -c 'select * from cards'", sessionKey: "un-1", unmappedTool: TOOL }], "asked as unmappedTool, no twin test");
  // control: the arbiter reports no taint ⇒ forwarded raw
  const control = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: trusted, callTaintFn: () => ({ ...EMPTY, evidence: "session" }) });
  assert.ok((await forward(control, turn(TOOL, { command: "psql -c 'select * from cards'" }, SECRET))).includes("4411-5522-6633-7744"));
});

test("tree evidence under rule (i) masks; an argv array is joined for the signature; a throwing callTaint masks (fail-closed)", async () => {
  const asked: Array<Record<string, unknown>> = [];
  const tree = new MockArbiter({
    gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: trusted,
    callTaintFn: (req) => { asked.push({ ...req }); return { ...EMPTY, level: "no-model", files: ["/h/.pgpass"], apps: ["psql"], root: "sh-1", evidence: "tree" }; },
  });
  const fwd = await forward(tree, turn(TOOL, { argv: ["bash", "-lc", "psql -c 'select 1'"] }, SECRET));
  assert.ok(!fwd.includes("4411-5522-6633-7744"));
  assert.match(fwd, /\[mandu:secret\] masked: psql read \/h\/\.pgpass/);
  assert.equal(asked[0]!["command"], `bash -lc 'psql -c '"'"'select 1'"'"''`);
  const broken = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: trusted, callTaintFn: () => { throw new Error("socket gone"); } });
  const b = await forward(broken, turn(TOOL, { command: "cat x" }, SECRET));
  assert.ok(!b.includes("4411-5522-6633-7744"), "fail-closed");
  assert.match(b, /masked: the process taint could not be read/);
});

test("raise-only: a denied-only tree never lowers the path-derived mask of an unmapped tool (control: a mapped Bash is lowered)", async () => {
  const denied: CallTaintWire = { ...EMPTY, root: "sh-1", denied: [{ path: "/w/.env", app: "cat", reason: "not a listed reader" }], evidence: "tree" };
  const labeled = (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock: .env named", confidentiality: "no-model" } as ClassifyResult);
  const unm = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: labeled, callTaintFn: () => denied, scanSecretValuesFn: () => ({ hits: [] }) });
  const fwd = await forward(unm, turn(TOOL, { command: "cat /w/.env" }, "cat: /w/.env: Permission denied"));
  assert.ok(!fwd.includes("Permission denied"), "the path-derived mask stands for an unmapped tool");
  assert.match(fwd, /\[mandu:secret\] denied: cat is not a reader of \/w\/\.env/);
  const bash = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: labeled, callTaintFn: () => { const { evidence: _e, ...t } = denied; return t; }, scanSecretValuesFn: () => ({ hits: [] }) });
  assert.ok((await forward(bash, turn("Bash", { command: "cat /w/.env" }, "cat: /w/.env: Permission denied"))).includes("Permission denied"), "control: the mapped shell's §11.8 release");
});

// A non-MCP tool only: since 2026-10-03 every MCP result whose server is not
// proven clean is asked about the session (plan 10 §11.13 rule (c);
// test/unit/mcp-server-taint.test.ts).
test("a tool with no command-like field is asked as unmapped with no command (plan 10 §11.18), forwarded on an empty answer; the arbiter's op absent asks nothing", async () => {
  const asked: Array<{ unmappedTool?: string; command?: string }> = [];
  const mapped = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: trusted, callTaintFn: (r) => { asked.push({ unmappedTool: r.unmappedTool, command: r.command }); return EMPTY; } });
  assert.ok((await forward(mapped, turn("ToolSearch", { query: "cards" }, SECRET))).includes("4411-5522-6633-7744"));
  assert.deepEqual(asked, [{ unmappedTool: "ToolSearch", command: undefined }]);
  const old = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: trusted });
  assert.ok((await forward(old, turn(TOOL, { command: "ls" }, "a b"))).includes("a b"));
});

test("Monitor is Claude Code's mapped shell: its result takes the mapped leg (no unmappedTool)", async () => {
  const asked: Array<Record<string, unknown>> = [];
  const arbiter = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: trusted, callTaintFn: (req) => { asked.push({ ...req }); return { ...EMPTY, level: "no-model", files: ["/h/.pgpass"], apps: ["psql"], root: "sh-1" }; } });
  const fwd = await forward(arbiter, turn("Monitor", { command: "psql -c 'select 1'", description: "rows", timeout_ms: 1000 }, SECRET));
  assert.ok(!fwd.includes("4411-5522-6633-7744"));
  assert.equal(asked[0]!["unmappedTool"], undefined);
  assert.equal(asked[0]!["command"], "psql -c 'select 1'");
});

// Plan 10 §11.12's polls (2026-10-02): a poll names a background task, not a
// command, so the arbiter can bind it to no shell and answers it at the
// session's level (plan 13 D7) while the session holds a raw read. BashOutput
// and OpenClaw's `process` were already mapped; `TaskOutput` (Claude Code's
// poll of a background shell or agent) was not: the leg never asked, raw.
test("poll tools: BashOutput, TaskOutput and OpenClaw's process are mapped shells asked with no command; a session answer masks them whole", async () => {
  const asked: Array<Record<string, unknown>> = [];
  const session = (): MockArbiter => new MockArbiter({
    gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: trusted,
    callTaintFn: (req) => { asked.push({ ...req }); return { ...EMPTY, level: "no-model", files: ["/w/x.txt"], apps: ["cat"], evidence: "session" }; },
  });
  for (const [name, input] of [
    ["BashOutput", { bash_id: "b1" }],
    ["TaskOutput", { task_id: "b1", block: true, timeout: 30000 }],
  ] as const) {
    asked.length = 0;
    const fwd = await forward(session(), turn(name, input, SECRET));
    // MASTER (TaskOutput): never asked, forwarded raw
    assert.ok(!fwd.includes("4411-5522-6633-7744"), `CONFIDENTIALITY: ${name}'s output is masked: ${fwd}`);
    assert.match(fwd, new RegExp(`plan 13 D7: Mandu could not tie this ${name} call to the processes that ran it`));
    assert.deepEqual(asked, [{ callId: "toolu_un", sessionKey: "un-1" }], `${name}: a mapped ask, no command, no unmappedTool`);
  }
  const openclaw = new MockArbiter({
    gateSurfaceFn: () => UNION_GATE_SURFACE, classifyFn: trusted,
    callTaintFn: () => ({ ...EMPTY, level: "no-model", files: ["/w/x.txt"], apps: ["cat"], evidence: "session" }),
  });
  const p = await forward(openclaw, turn("process", { action: "poll", sessionId: "s1" }, SECRET));
  assert.ok(!p.includes("4411-5522-6633-7744"), `OpenClaw's process poll is masked: ${p}`);
  // control: a session with no raw read leaves a poll raw
  const clean = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: trusted, callTaintFn: () => ({ ...EMPTY }) });
  assert.ok((await forward(clean, turn("TaskOutput", { task_id: "b1" }, SECRET))).includes("4411-5522-6633-7744"));
});
