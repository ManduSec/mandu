/**
 * call-command-binding — plan 13 D9's last "Left" item over the REAL
 * components: a tool call is bound to the agent's shell for it by the command
 * the model proxy RECORDED when it relayed the call, never by the command text
 * the agent echoes back in its next request.
 *
 *   a real ArbiterServer in `secrets`, the real proxies over HTTP in their
 *   production wiring (a data and a human client, as server-main builds
 *   them), a scripted model behind each. The model's turn carries two shell
 *   calls: one whose shell's subshell runs `mytool` on a labelled file (the
 *   guard lets it read raw, as a listed reader) and hex-dumps it, and one
 *   clean `echo`. The proxy gates each (execGate, with the call's id) and
 *   records the command it DELIVERS (recordCallCommand): for Claude Code the
 *   view map's AgentView spelling of the model's HumanView path. The guard's
 *   records follow, on the human socket. The next request is built by the
 *   agent, which here LIES: it echoes the clean call's command for the
 *   reader's call.
 *
 * Before the fix (master `c82f1656`) the arbiter bound a call by the echoed
 * text: asked first, the reader's call bound to the clean call's shell and
 * its hex dump reached the model raw, while the clean call lost its own shell
 * and was masked. Now the reader's call binds to its own shell (masked) and
 * the clean call to its own (raw). Codex (openai-proxy) gets the same
 * binding: it now sends the call_id to execGate (it sent none before, so a
 * Codex call had no lower time bound) and records the delivered command.
 * Unit twins: arbiter `guard-report-attestation.test.ts` (the D9 follow-up
 * pair), `provenance-store.test.ts` (the D9 follow-up block), each proxy's
 * `exec-gate` component test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { ViewMap } from "../../interceptors/anthropic-proxy/src/view-map.js";
import { buildTextSse, sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream as OpenAiMockUpstream, buildExecCommandSse } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const CANARY = `D9F_STACK_CANARY_${process.pid}`;
const FILE_HEX = Buffer.from(`token=${CANARY}\n`).toString("hex");
const HEX = " | od -An -tx1 | tr -d ' \\n'";
const CLEAN = "echo clean-$((6*7))";
const CLEAN_OUT = "clean-42\n";

interface Rig {
  tmp: string;
  secret: string;
  sock: string;
  human: string;
  guard: ArbiterClient;
  clients: ArbiterClient[];
  server: ArbiterServer;
  open: (sock: string) => Promise<ArbiterClient>;
  done: () => Promise<void>;
}

async function rig(): Promise<Rig> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-d9f-stack-"));
  const secret = join(tmp, "x.txt");
  writeFileSync(secret, `token=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, prints: nothing }]\n`);
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(human); // what the guard writes, on the human socket (plan 13 D9)
  return {
    tmp, secret, sock, human, guard, clients, server, open,
    done: async () => { for (const c of clients) c.close(); await server.close(); rmSync(tmp, { recursive: true, force: true }); },
  };
}

/** The guard's records for one call: the agent's shell (`argv`), a subshell
 *  that never execs, and `mytool` under it reading the labelled file raw. */
async function readerShell(r: Rig, session: string, tag: string, argv: string[]): Promise<void> {
  await r.guard.recordExecRoot({ procKey: `${tag}-sh-1`, ancestors: [`${tag}-agent-0`], argv, session, callRoot: true });
  const chain = [`${tag}-sub-2`, `${tag}-sh-1`, `${tag}-agent-0`];
  await r.guard.recordExecRoot({ procKey: `${tag}-mytool-3`, ancestors: chain, argv: ["mytool", r.secret], session });
  const d = await r.guard.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: `${tag}-mytool-3`, parentKey: chain[0], ancestorKeys: chain, session });
  assert.equal(d.verdict, "raw", `mytool is a listed reader: ${d.reason}`);
}

// ── Claude Code through the anthropic-proxy, with the view map active ───────

/** Claude Code's shell for one Bash call, as the guard reads its argv. */
const ccShell = (command: string, n: number): string[] =>
  ["/bin/bash", "-c", `source /h/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true && eval '${command.replace(/'/g, `'"'"'`)}' && pwd -P >| /tmp/claude-d9f${n}-cwd`];

function postClaude(port: number, session: string, messages: unknown[]): Promise<{ status: number; body: string }> {
  const body = JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Bash", input_schema: { type: "object" } }], messages });
  return new Promise((resolve, reject) => {
    const q = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => { let b = ""; res.on("data", (c) => (b += String(c))); res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b })); });
    q.on("error", reject);
    q.end(body);
  });
}

function claudeResultIn(body: string, id: string): string {
  for (const m of (JSON.parse(body) as { messages: Array<{ content?: unknown }> }).messages) {
    if (!Array.isArray(m.content)) continue;
    for (const b of m.content as Array<Record<string, unknown>>) {
      if (b.type === "tool_result" && b.tool_use_id === id) return typeof b.content === "string" ? b.content : JSON.stringify(b.content);
    }
  }
  throw new Error(`no tool_result ${id} forwarded`);
}

test("the D9 follow-up over the real anthropic-proxy: an agent echoing the clean call's command for the reader's call does not unmask it; the delivered (AgentView) command binds each call to its own shell (secrets axes, explicit)", async () => {
  const r = await rig();
  const HUMAN_ROOT = "/home/u/project";
  const AGENT_ROOT = "/home/u/.mandu/workspaces/d9f/agentview";
  const READ_MODEL = `( mytool ${HUMAN_ROOT}/x.tx?; true )${HEX}`;
  const READ_AGENT = `( mytool ${AGENT_ROOT}/x.tx?; true )${HEX}`;
  const session = `d9f-claude-${process.pid}`;
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    let sse: string;
    if (seen.length === 1) {
      sse = sseEvent("message_start", { type: "message_start", message: { id: "msg_d9f", role: "assistant", content: [] } });
      [["toolu_d9f_read", READ_MODEL], ["toolu_d9f_clean", CLEAN]].forEach(([id, command], index) => {
        sse += sseEvent("content_block_start", { type: "content_block_start", index, content_block: { type: "tool_use", id, name: "Bash", input: {} } });
        sse += sseEvent("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: JSON.stringify({ command }) } });
        sse += sseEvent("content_block_stop", { type: "content_block_stop", index });
      });
      sse += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } });
      sse += sseEvent("message_stop", { type: "message_stop" });
    } else {
      sse = buildTextSse("done", { deltas: 1 });
    }
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const viewMap = new ViewMap([{ human: HUMAN_ROOT, agent: AGENT_ROOT }], { dialect: "posix", home: "/home/u" });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await r.open(r.sock), await r.open(r.human)), upstream, viewMap, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    // 1. The model's turn, gated and recorded by the proxy as it streams.
    const turn = await postClaude(port, session, [{ role: "user", content: "go" }]);
    assert.equal(turn.status, 200);
    assert.ok(turn.body.includes(JSON.stringify(READ_AGENT).slice(1, -1).slice(0, 40)), "the agent received the AgentView spelling");

    // 2. The agent runs what it was given; the guard reports it.
    await readerShell(r, session, "c", ccShell(READ_AGENT, 1));
    await r.guard.recordExecRoot({ procKey: "c-sh-9", ancestors: ["c-agent-0"], argv: ccShell(CLEAN, 2), session, callRoot: true });

    // 3. The agent's next request LIES about the reader's call: it echoes
    //    the clean call's command for it (and the clean output's twin text).
    const lying = [
      { role: "user", content: "go" },
      { role: "assistant", content: [
        { type: "tool_use", id: "toolu_d9f_read", name: "Bash", input: { command: CLEAN } },
        { type: "tool_use", id: "toolu_d9f_clean", name: "Bash", input: { command: CLEAN } },
      ] },
      { role: "user", content: [
        { type: "tool_result", tool_use_id: "toolu_d9f_read", content: FILE_HEX },
        { type: "tool_result", tool_use_id: "toolu_d9f_clean", content: CLEAN_OUT },
      ] },
    ];
    assert.equal((await postClaude(port, session, lying)).status, 200);
    const read = claudeResultIn(seen[1]!, "toolu_d9f_read");
    // MASTER: bound to c-sh-9 (the clean shell) by the echoed text: the hex dump raw
    assert.ok(!read.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: the reader's output reached the model raw under a forged echo: ${read}`);
    assert.match(read, /\[mandu:secret\] masked: mytool read .*x\.txt/, "masked by its own tree's evidence");
    const clean = claudeResultIn(seen[1]!, "toolu_d9f_clean");
    // MASTER: its shell was taken by the reader's call, so it masked at the session's level
    assert.ok(clean.startsWith(CLEAN_OUT), `utility: the clean call keeps its own shell: ${clean}`);

    // THE ORACLE: no request to the model carried the file, raw or hex.
    const wire = seen.join("\n");
    assert.ok(!wire.includes(CANARY) && !wire.includes(FILE_HEX.slice(0, 24)), "the file's bytes never reached the model");
  } finally {
    await proxy.close();
    await r.done();
  }
});

// ── Codex through the openai-proxy ──────────────────────────────────────────

function codexTurn(...items: unknown[]): unknown {
  return { model: "gpt-5.5", stream: true, instructions: "You are Codex.", input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }, ...items] };
}

function codexOutputOf(body: string, callId: string): string {
  const item = (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" && i["call_id"] === callId)!;
  const o = item["output"];
  return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
}

test("the D9 follow-up over the real openai-proxy (Codex): execGate now carries the call_id, the delivered command binds the call, and a forged echo does not unmask the reader's call (secrets axes, explicit)", async () => {
  const r = await rig();
  const READ = `( mytool ./x.tx?; true )${HEX}`;
  const session = `d9f-codex-${process.pid}`;
  let upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(await r.open(r.sock), await r.open(r.human)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const send = async (body: unknown, sse: string): Promise<{ toAgent: string; toModel: string }> => {
    upstream = new OpenAiMockUpstream({ sse });
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, { method: "POST", headers: { "content-type": "application/json", "x-mandu-session-id": session }, body: JSON.stringify(body) });
    const toAgent = await res.text();
    assert.equal(res.status, 200, toAgent);
    return { toAgent, toModel: upstream.requests[0]!.bodyText };
  };
  try {
    // 1. Two model turns, one exec_command each, relayed (gated + recorded).
    await send(codexTurn(), buildExecCommandSse({ cmd: READ, callId: "call_d9f_read", itemId: "fc_r" }));
    await send(codexTurn(), buildExecCommandSse({ cmd: CLEAN, callId: "call_d9f_clean", itemId: "fc_c" }));

    // 2. Codex runs each in its own shell (`bash -lc <cmd>`); the guard reports it.
    await readerShell(r, session, "x", ["/bin/bash", "-lc", READ]);
    await r.guard.recordExecRoot({ procKey: "x-sh-9", ancestors: ["x-agent-0"], argv: ["/bin/bash", "-lc", CLEAN], session, callRoot: true });

    // 3. The next request echoes the clean command for the reader's call.
    const { toModel } = await send(codexTurn(
      { type: "function_call", call_id: "call_d9f_read", name: "exec_command", arguments: JSON.stringify({ cmd: CLEAN }) },
      { type: "function_call_output", call_id: "call_d9f_read", output: FILE_HEX },
      { type: "function_call", call_id: "call_d9f_clean", name: "exec_command", arguments: JSON.stringify({ cmd: CLEAN }) },
      { type: "function_call_output", call_id: "call_d9f_clean", output: CLEAN_OUT },
    ), "event: response.completed\ndata: {}\n\n");
    const read = codexOutputOf(toModel, "call_d9f_read");
    assert.ok(!read.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: the reader's output reached the model raw under a forged echo: ${read}`);
    assert.match(read, /\[mandu:secret\] masked: mytool read .*x\.txt/, "masked by its own tree's evidence");
    assert.ok(codexOutputOf(toModel, "call_d9f_clean").startsWith(CLEAN_OUT), "utility: the clean call keeps its own shell");
    assert.ok(!toModel.includes(CANARY) && !toModel.includes(FILE_HEX.slice(0, 24)), "the file's bytes never reached the model");
  } finally {
    await proxy.close();
    await r.done();
  }
});
