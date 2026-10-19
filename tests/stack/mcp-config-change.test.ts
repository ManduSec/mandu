/**
 * mcp-config-change — plan 10 §11.17 (P0 item 11 (a)) over the REAL
 * components: the launcher's read and watch of the agent's MCP config
 * (`mapLaunchMcpServers`, the real `ndjsonCall` on the human socket), the
 * guard's exec and taint records (written as the guard writes them), the
 * real ArbiterServer in `secrets`, and the proxies over their PRODUCTION
 * adapters (the real AnthropicProxy for OpenCode, which fetches its gate
 * surface from the arbiter).
 *
 * The session read a secret raw. The leak oracle, per agent:
 *   - Claude Code / Codex: a server whose config the agent edits mid-session
 *     to a command line whose tree reads a secret raw. Before the launcher's
 *     re-read lands, the arbiter's stamp check keeps it from `clean`, so its
 *     result is masked by the session rule; after it, both command lines are
 *     registered and the server is tainted. MASTER: the old command line's
 *     one clean process vouched for it (`clean`), and its result reached the
 *     model raw on both wires.
 *   - OpenCode: an MCP server no config named (its `<server>_<tool>`) is
 *     masked whole; the spec's own `read` is not. MASTER: raw.
 * Plus the stamp parity: the launcher's mcpSourceStamp and the arbiter's
 * give one answer for a file, a missing path and a directory.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer, mcpSourceStamp as arbiterStamp } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { mapLaunchMcpServers, mcpSourceStamp as launcherStamp, type McpLaunchPlan } from "../../launcher/src/mcp-server-config.js";
import { ndjsonCall } from "../../launcher/src/secret-setup.js";
import { rewriteRequest as rewriteMessages } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import { rewriteRequest as rewriteResponses } from "../../interceptors/openai-proxy/src/rewrite-request.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import type { ResponsesRequest } from "../../interceptors/openai-proxy/src/responses-types.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const BATTERY = { type: "additional_tools", role: "developer", tools: [{ type: "namespace", name: "functions", tools: [{ type: "custom", name: "exec", description: "- Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." }] }] };

async function withArbiter(fn: (h: { tmp: string; human: string; data: ArbiterClient; humanClient: ArbiterClient }) => Promise<void>): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-mcp-cfg-e2e-"));
  const human = join(tmp, "human", "h.sock");
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const data = new ArbiterClient(socketPath); await data.connect();
  const humanClient = new ArbiterClient(human); await humanClient.connect();
  try {
    await fn({ tmp, human, data, humanClient });
  } finally {
    data.close(); humanClient.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
}

test("stamp parity: the launcher's and the arbiter's mcpSourceStamp give one answer", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-mcp-stamp-"));
  try {
    const f = join(dir, ".mcp.json");
    writeFileSync(f, "{}");
    for (const p of [f, join(dir, "missing.json"), dir, join(f, "under-a-file")]) assert.equal(launcherStamp(p), arbiterStamp(p), p);
    assert.equal(launcherStamp(join(dir, "missing.json")), "absent");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

for (const target of ["claude", "codex"] as const) {
  test(`${target}: a server whose config changes mid-session is never vouched for by its old process (real launcher watch, real arbiter, production adapter)`, async () => {
    await withArbiter(async ({ tmp, human, data, humanClient }) => {
      const home = join(tmp, "home");
      const work = join(tmp, "work");
      mkdirSync(join(home, ".codex"), { recursive: true });
      mkdirSync(work, { recursive: true });
      const OLD = ["node", "/opt/notes/server.js"];
      const NEW = ["sh", "-c", "psql -c 'select * from cards' >/tmp/rows; node /opt/notes/server.js"];
      const cfgFile = target === "claude" ? join(work, ".mcp.json") : join(home, ".codex", "config.toml");
      const writeCfg = (argv: string[]): void => writeFileSync(cfgFile, target === "claude"
        ? JSON.stringify({ mcpServers: { notes: { command: argv[0], args: argv.slice(1) } } })
        : `[mcp_servers.notes]\ncommand = ${JSON.stringify(argv[0])}\nargs = ${JSON.stringify(argv.slice(1))}\n`);
      writeCfg(OLD);
      const session = `mcp-cfg-${target}-${process.pid}`;
      const plan = { target, scopeId: session, humanCwd: work, cwd: work, arbiterHumanSock: human, effectiveAxes: { integrity: false, confidentiality: true }, confidentiality: true } as McpLaunchPlan;
      const { registration, watch } = await mapLaunchMcpServers(plan, { HOME: home }, {
        home, call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000), log: () => {},
      });
      assert.deepEqual(registration, { status: "registered", registered: 1 });
      assert.ok(watch, "a watch for this agent");
      try {
        // the guard: the agent spawned the server; a listed reader elsewhere read a secret raw
        await humanClient.recordExecRoot({ procKey: `${target}-agent`, argv: [target], session });
        await humanClient.recordExecRoot({ procKey: `${target}-notes-1`, parentKey: `${target}-agent`, argv: OLD, session });
        await humanClient.taintProcessSecret({ procKey: `${target}-psql`, path: join(home, ".pgpass"), level: "no-model", app: "psql", session });

        const tool = target === "claude" ? "mcp__notes__list" : "list";
        let turn = 0;
        const forward = async (row: string): Promise<string> => {
          turn++;
          if (target === "claude") {
            const req: MessagesRequest = { model: "claude-sonnet-5", messages: [
              { role: "user", content: "go" },
              { role: "assistant", content: [{ type: "tool_use", id: `tu_${turn}`, name: tool, input: { key: "x" } }] },
              { role: "user", content: [{ type: "tool_result", tool_use_id: `tu_${turn}`, content: row }] },
            ] };
            const adapter = new ArbiterClientAdapter(data, humanClient);
            return JSON.stringify((await rewriteMessages(req, { arbiter: adapter, sessionKey: session })).request.messages[2]!.content);
          }
          const adapter = new OpenAiProxyArbiterAdapter(data, humanClient);
          const input = [BATTERY,
            { type: "function_call", call_id: `f_${turn}`, namespace: "mcp__notes", name: tool, arguments: "{\"key\":\"x\"}" },
            { type: "function_call_output", call_id: `f_${turn}`, output: [{ type: "input_text", text: "Wall time: 0.1 seconds\nOutput:" }, { type: "input_text", text: row }] },
          ];
          const { request } = await rewriteResponses({ model: "m", input } as unknown as ResponsesRequest, { arbiter: adapter, sessionKey: session, skipPromptInjection: true });
          return JSON.stringify((request.input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output")!["output"]);
        };

        const before = `clean-row-${target}-1a2b`;
        assert.ok((await forward(before)).includes(before), "an unchanged config: the one clean process vouches (raw in a tainted session)");

        // the agent edits its config; its reload spawns the new command line,
        // whose tree reads the card table raw; the watch has not run yet
        writeCfg(NEW);
        await humanClient.recordExecRoot({ procKey: `${target}-notes-2`, parentKey: `${target}-agent`, argv: NEW, session });
        await humanClient.taintProcessSecret({ procKey: `${target}-notes-2`, path: join(home, ".pgpass"), level: "no-model", app: "psql", session });
        const stale = `card-row-${target}-4411-5522`;
        const out1 = await forward(stale);
        // MASTER: raw (the old process answered `clean`)
        assert.ok(!out1.includes(stale), `CONFIDENTIALITY VIOLATION (${target}): a changed config's old process vouched for the server and its new tree's rows reached the model`);
        assert.match(out1, /\$MDU:/);

        // the watch's re-read lands: both command lines, the server tainted
        assert.equal(await watch!.checkNow(), true);
        assert.equal((await data.mcpServerTaint("mcp__notes__list", session)).verdict, "tainted");
        const after = `card-row-${target}-6633-7744`;
        assert.ok(!(await forward(after)).includes(after), `CONFIDENTIALITY VIOLATION (${target}): after the re-read`);
      } finally { watch?.stop(); }
    });
  });
}

function post(port: number, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    req.on("error", reject);
    req.end(body);
  });
}

test("opencode: an MCP server no config named reaches the model only as a symbol; the spec's read is forwarded (real AnthropicProxy, gate surface from the real arbiter)", async () => {
  await withArbiter(async ({ data, humanClient }) => {
    const session = `mcp-cfg-opencode-${process.pid}`;
    assert.equal((await data.setSessionSpec({ sessionKey: session, spec: "opencode", requestedBy: "mcp-config-change e2e" })).bound, "opencode");
    await humanClient.taintProcessSecret({ procKey: "oc-psql", path: "/h/.pgpass", level: "no-model", app: "psql", session });
    const up = new MockUpstream({ sse: buildTextSse("ok") });
    const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, humanClient), upstream: up.fetcher, sessionKey: session, log: () => {} });
    const port = await proxy.listen(0);
    try {
      const body = JSON.stringify({ model: "claude-sonnet-5", stream: true, messages: [
        { role: "user", content: "read the rows" },
        { role: "assistant", content: [{ type: "tool_use", id: "tu_mcp", name: "notes_get", input: { key: "rows" } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_mcp", content: "card | 4411-5522-6633-7744" }] },
        { role: "assistant", content: [{ type: "tool_use", id: "tu_read", name: "read", input: { filePath: "/w/notes.md" } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_read", content: "plain notes 9f8e" }] },
      ] });
      assert.equal(await post(port, body), 200);
      const wire = up.requests[0]!.bodyText;
      // MASTER: raw (an OpenCode MCP tool is not `mcp__`, and was never asked)
      assert.ok(!wire.includes("4411-5522"), "CONFIDENTIALITY VIOLATION: an OpenCode MCP tool's result reached the model raw in a session holding a raw read");
      assert.match(wire, /\$MDU:/);
      assert.ok(wire.includes("plain notes 9f8e"), "the spec's own read is forwarded");
    } finally { await proxy.close(); }
  });
});
