/**
 * codex-developer-prompt — codex-cli 0.162's classic wire over the REAL
 * components. From 0.162 the classic wire (a model without code mode) sends
 * no `instructions`: codex's own prompt is the first developer message, as on
 * the code-mode wire since 0.154 (supported-agents.md §6.4, read off the
 * wire 2026-10-09). The proxy must still prefix its handling prompt, leave
 * codex's prompt alone, and keep a secret out of the model.
 *
 *   a real ArbiterServer in `secrets` (a policy file labels the secret,
 *   `mytool` its listed reader), the real openai-proxy over HTTP in its
 *   production wiring, a scripted model behind it. The model asks for
 *   `mytool <secret>`; the guard's records say `mytool` read the file raw
 *   under the call's shell; the result comes back in the 0.162 request shape.
 *
 * Asserts: the secret reaches the model only as a symbol (the oracle, over
 * every forwarded request); the forwarded request's `instructions` is the
 * handling prompt alone; codex's developer messages are forwarded byte for
 * byte. Unit twin: openai-proxy `codex-mcp.test.ts` (the 0.162 tests).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { HANDLING_MARKER } from "../../interceptors/openai-proxy/src/rewrite-request.js";
import { MockUpstream as OpenAiMockUpstream, buildExecCommandSse } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const CANARY = `DEV_PROMPT_CANARY_${process.pid}_4c1e`;
const FILE = `token=${CANARY}\n`;
/** codex-rs `format_response`: the head Codex writes before every exec output. */
const HEAD = "Chunk ID: 9a3f\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 9\nOutput:\n";

/** codex-cli 0.162's classic request: no `instructions`; its prompt and skills are developer messages. */
const DEVELOPER = [
  { type: "message", role: "developer", content: [{ type: "input_text", text: "You are Codex, a coding agent based on GPT-5. You and the user share one workspace." }] },
  { type: "message", role: "developer", content: [{ type: "input_text", text: "<skills_instructions>\n## Skills\n</skills_instructions>" }] },
];
const TOOLS = [
  ...["exec_command", "write_stdin", "request_user_input"].map((name) => ({ type: "function", name, parameters: { type: "object", properties: {} } })),
  { type: "custom", name: "apply_patch", format: { type: "grammar", syntax: "lark", definition: "start: /.+/" } },
  ...["view_image", "get_goal", "create_goal", "update_goal"].map((name) => ({ type: "function", name, parameters: { type: "object", properties: {} } })),
  { type: "tool_search", execution: "client" },
  { type: "web_search", external_web_access: false },
];
function codexTurn(...items: unknown[]): unknown {
  return {
    model: "gpt-5.5", stream: true,
    input: [...DEVELOPER,
      { type: "message", role: "user", content: [{ type: "input_text", text: "<environment_context>\n  <cwd>/w</cwd>\n</environment_context>" }] },
      { type: "message", role: "user", content: [{ type: "input_text", text: "show me the token" }] },
      ...items],
    tools: TOOLS, tool_choice: "auto", parallel_tool_calls: true, store: false,
  };
}

function outputOf(body: string, callId: string): string {
  const item = (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" && i["call_id"] === callId)!;
  const o = item["output"];
  return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
}

test("codex 0.162's classic wire (no instructions, its prompt a developer message): a secret a reader printed reaches the model only as a symbol, the handling prompt is the instructions, codex's prompt is untouched (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-dev-prompt-stack-"));
  const secret = join(tmp, "creds.txt");
  writeFileSync(secret, FILE);
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
  const session = `dev-prompt-${process.pid}`;
  let upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const seen: string[] = [];
  // the production wiring: the data client and the human plane's
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(await open(sock), await open(human)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const send = async (body: unknown, sse = "event: response.completed\ndata: {}\n\n"): Promise<string> => {
    upstream = new OpenAiMockUpstream({ sse });
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, { method: "POST", headers: { "content-type": "application/json", "x-mandu-session-id": session }, body: JSON.stringify(body) });
    assert.equal(res.status, 200, await res.text());
    const toModel = upstream.requests[0]!.bodyText;
    seen.push(toModel);
    return toModel;
  };
  try {
    // the model asks for `mytool <secret>` (relayed: gated and recorded)
    const cmd = `mytool ${secret}`;
    const callId = "call_dp_1";
    const first = await send(codexTurn(), buildExecCommandSse({ cmd, callId, itemId: "fc_1" }));
    const firstJson = JSON.parse(first) as { instructions?: string; input: unknown[] };
    assert.ok((firstJson.instructions ?? "").startsWith(HANDLING_MARKER), "the handling prompt is the request's instructions on the first turn");
    // the guard's records: codex's shell for the call, mytool under it, its raw read
    await guard.recordExecRoot({ procKey: "dp-sh-1", ancestors: ["dp-agent-0"], argv: ["/bin/bash", "-lc", cmd], session, callRoot: true });
    await guard.recordExecRoot({ procKey: "dp-mytool-2", ancestors: ["dp-sh-1", "dp-agent-0"], argv: ["mytool", secret], session });
    const d = await guard.decideSecretOpen({ path: secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "dp-mytool-2", parentKey: "dp-sh-1", ancestorKeys: ["dp-sh-1", "dp-agent-0"], session });
    assert.equal(d.verdict, "raw", `mytool is a listed reader: ${d.reason}`);

    const call = { type: "function_call", call_id: callId, name: "exec_command", arguments: JSON.stringify({ cmd }) };
    const second = await send(codexTurn(call, { type: "function_call_output", call_id: callId, output: `${HEAD}${FILE}` }));
    const masked = outputOf(second, callId);
    assert.ok(!masked.includes(CANARY), `CONFIDENTIALITY VIOLATION: the reader's output reached the model raw: ${masked}`);
    assert.match(masked, /\$MDU:nomodel_exec_command\[[0-9a-f]{4}\]/, "the output reached the model as a symbol");
    const json = JSON.parse(second) as { instructions?: string; input: unknown[] };
    assert.ok((json.instructions ?? "").startsWith(HANDLING_MARKER), "the handling prompt is the request's instructions");
    assert.equal((json.instructions ?? "").split(HANDLING_MARKER).length - 1, 1, "injected once");
    assert.ok(!(json.instructions ?? "").includes("You are Codex"), "codex's prompt is not moved into the instructions");
    assert.deepEqual(json.input.slice(0, 2), DEVELOPER, "codex's developer messages are forwarded byte for byte");

    // THE ORACLE: no request to the model carried the secret.
    assert.ok(!seen.join("\n").includes(CANARY), "the secret never reached the model");
  } finally {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
