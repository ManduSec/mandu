/**
 * dir-change-label-raise (stack) — a directory change in a shell command
 * never lets a labelled file's text reach the model in clear (2026-10-17,
 * confidentiality.md §6, "A directory change only raises"), over the REAL
 * components: a real ArbiterServer in `secrets` whose policy file labels
 * the workspace's `secrets/`, `vault/` and `notes/*.md` no-model (human labels; no file is a
 * registered secret, so no twin, process taint or value backstop stands
 * behind the path-derived verdict), the real anthropic-proxy and the real
 * openai-proxy over HTTP in their production wiring, mock models behind them.
 *
 * Before the fix the text scan dropped the call's start directory whenever
 * the command could change directory, so `cd . && cat secrets/plan.md` read
 * `secrets/plan.md` only as written, matched no label (the store is keyed
 * by absolute path), and the plan went to the model in clear.
 *
 *   - Claude Code's Bash (the guard's start directory, the proxy's callTaint
 *     binding) and Codex's exec_command (its workdir): every `cd` spelling,
 *     a resolvable change, a flag form, an unreadable target, no start
 *     directory: masked;
 *   - a benign command after a `cd` stays in clear;
 *   - THE ORACLE: the plan's text is in no request to either model.
 *
 * Unit and component twins: arbiter `dir-change-label-raise.test.ts` (both).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream as OpenAiMockUpstream } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const PLAN_VALUE = "PLAN-DIRCHANGE-LABELLED-3b7e";
const README_VALUE = "readme-in-clear-77a0";

/** The commands that read the labelled plan, by a relative path, after or
 *  around a change of directory: each must reach the model as a symbol. */
const MASKED = [
  "cd . && cat secrets/plan.md",
  "cd .; cat secrets/plan.md",
  "cd ./ && cat secrets/plan.md",
  "cd -- . && cat secrets/plan.md",
  "pushd . >/dev/null && cat secrets/plan.md",
  'cd "$PWD" && cat secrets/plan.md',
  "(cd . && cat secrets/plan.md)",
  "\\cd . && cat secrets/plan.md",
  "builtin cd . && cat secrets/plan.md",
  "cd vault && cat plan.md",
  "cd sub && cat ../vault/plan.md",
  "env -C sub cat ../vault/plan.md",
  "tar -Cvault -cf - plan.md",
  `python3 -c "import os; os.chdir('sub'); print(open('../vault/plan.md').read())"`,
  'cd "$TARGET" && cat plan.md',
  "cd - && cat plan.md",
  "cd notes && cat plan.md",
  'cat va""ult/plan.md',
  'cd "$D" && echo "$(cat plan.md)"',
  "cd vau*;head<plan.md",
];

function makeWorkspace(prefix: string): { tmp: string; ws: string; policy: string } {
  const tmp = mkdtempSync(join(tmpdir(), prefix));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "secrets"), { recursive: true });
  mkdirSync(join(ws, "vault"), { recursive: true });
  mkdirSync(join(ws, "notes"), { recursive: true });
  mkdirSync(join(ws, "sub"), { recursive: true });
  for (const d of ["secrets", "vault", "notes"]) writeFileSync(join(ws, d, "plan.md"), `${PLAN_VALUE}\n`);
  writeFileSync(join(ws, "README.md"), `${README_VALUE}\n`);
  const policy = join(tmp, "policy.yaml");
  // `vault`: a name no catalog shape matches (`*secret*` masks a bare `secrets` token unlabelled)
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(ws, "secrets")}\n    level: no-model\n  - path: ${join(ws, "vault")}\n    level: no-model\n  - path: ${join(ws, "notes")}/*.md\n    level: no-model\n`);
  return { tmp, ws, policy };
}

test("Claude Code Bash: a labelled file read after a directory change reaches the model only as a symbol (secrets axes, explicit)", async () => {
  const { tmp, ws, policy } = makeWorkspace("mandu-dirchange-bash-");
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(humanSock);
  const human = await open(humanSock);
  const session = `dirchange-bash-${process.pid}`;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), human), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);

  let n = 0;
  /** One Bash call as it runs under Mandu (see claude-bash-public-label):
   *  what the model got for its result. */
  const bashCall = async (command: string, output: string, cwd: string | null): Promise<string> => {
    const id = `toolu_dcr_${n++}`;
    await human.recordCallCommand({ callId: id, command, sessionKey: session });
    await guard.recordExecRoot({
      procKey: `sh-${id}`, ancestors: ["agent-dcr-0"], session, callRoot: true,
      argv: ["/bin/bash", "-c", `source /dev/null 2>/dev/null || true && eval '${command.replace(/'/g, `'"'"'`)}' && pwd -P >| /tmp/claude-x-cwd`],
      ...(cwd !== null ? { cwd } : {}),
    });
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
        tools: [{ name: "Bash", input_schema: { type: "object" } }],
        messages: [
          { role: "user", content: "go" },
          { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
          { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: output }] },
        ],
      }),
    });
    assert.equal(res.status, 200, await res.text());
    const body = upstream.requests.at(-1)!.json() as { messages: Array<{ content: Array<{ content?: unknown }> }> };
    return JSON.stringify(body.messages[2]!.content[0]!.content);
  };

  try {
    for (const [command, cwd] of [...MASKED.map((c) => [c, ws] as const), ["cd . && cat secrets/plan.md", null] as const, ["cd sub && cat ../vault/plan.md", null] as const]) {
      const seen = await bashCall(command, `${PLAN_VALUE}\n`, cwd);
      assert.ok(!seen.includes(PLAN_VALUE), `CONFIDENTIALITY VIOLATION: ${command} (start ${cwd ?? "unknown"}) put the labelled plan in clear: ${seen}`);
      assert.ok(seen.includes("$MDU:"), `${command}: masked: ${seen}`);
    }
    // utility: a benign read after a cd stays in clear
    const readme = await bashCall("cd sub && cat ../README.md", `${README_VALUE}\n`, ws);
    assert.ok(readme.includes(README_VALUE) && !readme.includes("$MDU:"), `a benign read after a cd is not masked: ${readme}`);

    // THE ORACLE
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(PLAN_VALUE), "CONFIDENTIALITY VIOLATION: the labelled plan's text is in a request to the model");
  } finally {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

const head = (chunk: string): string => `Chunk ID: ${chunk}\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 9\nOutput:\n`;

test("Codex exec_command: a labelled file read after a directory change reaches the model only as a symbol (secrets axes, explicit)", async () => {
  const { tmp, ws, policy } = makeWorkspace("mandu-dirchange-codex-");
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const session = `dirchange-codex-${process.pid}`;
  const upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(await open(sock), await open(human)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const items: unknown[] = [{ type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }];
    const commands = [...MASKED, "cd sub && cat ../README.md"];
    commands.forEach((cmd, i) => {
      const out = cmd.endsWith("README.md") ? README_VALUE : PLAN_VALUE;
      items.push({ type: "function_call", call_id: `c_${i}`, name: "exec_command", arguments: JSON.stringify({ cmd, workdir: ws }) });
      items.push({ type: "function_call_output", call_id: `c_${i}`, output: `${head(`a${i}`)}${out}\n` });
    });
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session },
      body: JSON.stringify({ model: "gpt-5.5", stream: true, instructions: "You are Codex.", input: items }),
    });
    assert.equal(res.status, 200, await res.text());
    const toModel = upstream.requests[0]!.bodyText;
    const outputOf = (id: string): string => {
      const item = (JSON.parse(toModel).input as Array<Record<string, unknown>>).find((x) => x["type"] === "function_call_output" && x["call_id"] === id)!;
      const o = item["output"];
      return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
    };
    MASKED.forEach((cmd, i) => {
      const o = outputOf(`c_${i}`);
      assert.ok(!o.includes(PLAN_VALUE) && o.includes("$MDU:"), `CONFIDENTIALITY VIOLATION: exec_command ${cmd} put the labelled plan in clear: ${o}`);
    });
    const readme = outputOf(`c_${MASKED.length}`);
    assert.ok(readme.includes(README_VALUE), `a benign read after a cd is not masked: ${readme}`);
    assert.ok(!toModel.includes(PLAN_VALUE), "CONFIDENTIALITY VIOLATION: the labelled plan's text is in the request to the model");
  } finally {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
