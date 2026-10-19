/**
 * guard-provenance — the taint records come from the REAL guard, and the
 * model proxies act on them (test-reorganization.md §11.1: `exec/provenance`
 * in the arbiter's suite hands the arbiter its taint records, and
 * `model-ingress/mcp` was proven only by the unmapped-tool backstop, the
 * per-server rule of !284 only over records written by hand).
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around an
 *   "agent" process tree, in `secrets`, against a real ArbiterServer loaded
 *   with a policy.yaml (~/.pgpass: no-model, reader `mdu-holder`, a reader
 *   the test builds and pins by path and hash, tests/lib/holder-reader.c;
 *   until 2026-10-03 the reader was `cat` itself, which admits nothing since
 *   plan 13 D8's "printers admit nothing"; it named node too before plan 13
 *   §8 decision (b), 2026-10-02, when the dirty server opened the file
 *   itself, which node running an agent-writable script no longer may):
 *     - the agent's Bash calls: `bash -c "mdu-holder ~/.pgpass | od -An -tx1 | tr -d …"`
 *       (the pinned reader gets the real bytes; the output is a transform no
 *       value scan can see) and `bash -c "echo …"` (reads nothing);
 *     - the agent's stdio MCP servers, configured in its own ~/.claude.json
 *       and ~/.codex/config.toml and registered by the LAUNCHER's reader on
 *       the arbiter's human socket: `dirty-store` (node, reads ~/.pgpass raw
 *       through the pipe from the reader, so a holder by plan 13 D2, and answers
 *       with its hex dump) and `clean-notes` (reads nothing).
 *   The guard writes every exec record (argv, parent) and every raw read's
 *   taint itself. Then each result goes to the model through the model
 *   proxies in their production wiring: the AnthropicProxy over HTTP (Claude
 *   Code's Bash and mcp__ tools) and the openai-proxy's rewrite (Codex's
 *   exec_command and namespaced MCP calls).
 *
 * The oracle: the tainted Bash result and the dirty server's result never
 * reach the model (masked whole, with the note naming the reader and the
 * file); the clean ones reach it raw. Red with the guard's records missing
 * (the hex dump is no registered value), with the per-server rule removed from
 * either proxy, or with callTaint ignored. SKIPs only where the guard is not
 * built or the kernel lacks seccomp user notification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { registerLaunchMcpServers } from "../../../launcher/src/mcp-server-config.js";
import { ndjsonCall } from "../../../launcher/src/secret-setup.js";
import { AnthropicProxy } from "../../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { rewriteRequest as rewriteResponses } from "../../../interceptors/openai-proxy/src/rewrite-request.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../../interceptors/openai-proxy/src/arbiter-client.js";
import type { ResponsesRequest } from "../../../interceptors/openai-proxy/src/responses-types.js";
import { agentNodeCopy, pickGuard } from "../../lib/native-guard.js";
import { holderReader, holderSkip } from "../../lib/holder-reader.js";
import { stateAxes } from "../../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const skip = process.platform !== "linux" ? "Linux only" : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : holderSkip() !== false ? holderSkip() : false;

const PG_CANARY = `PGPASS_GUARD_PROV_CANARY_${process.pid}`;
const hex = (s: string): string => Buffer.from(s).toString("hex");

/** A minimal stdio MCP server: one tool, whose answer `answer()` computes. */
function mcpServerSource(tool: string, answer: string): string {
  return `import { execFileSync } from "node:child_process";
import { createInterface } from "node:readline";
const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
createInterface({ input: process.stdin }).on("line", (line) => {
  const msg = JSON.parse(line);
  if (msg.method === "initialize") return send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1" } } });
  if (msg.method === "tools/list") return send({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: ${JSON.stringify(tool)}, inputSchema: { type: "object" } }] } });
  if (msg.method === "tools/call") {
    let text;
    try { text = ${answer}; } catch (e) { text = "error: " + e.message; }
    return send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text }] } });
  }
  if (msg.id !== undefined) send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "no such method" } });
});
`;
}

/** The "agent": runs its Bash calls and its MCP servers, prints what each returned. */
const AGENT_SOURCE = `import { spawn, spawnSync } from "node:child_process";
import { createInterface } from "node:readline";
const cfg = JSON.parse(process.argv[2]);
const out = { bash: {}, mcp: {} };
for (const [k, cmd] of Object.entries(cfg.bash)) {
  const r = spawnSync("bash", ["-c", cmd], { encoding: "utf8" });
  out.bash[k] = (r.stdout ?? "") + (r.stderr ?? "");
}
async function callServer(argv, tool) {
  const child = spawn(argv[0], argv.slice(1), { stdio: ["pipe", "pipe", "inherit"] });
  const pending = new Map();
  createInterface({ input: child.stdout }).on("line", (l) => { const m = JSON.parse(l); pending.get(m.id)?.(m); });
  let id = 0;
  const rpc = (method, params) => new Promise((ok) => { const i = ++id; pending.set(i, ok); child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: i, method, params }) + "\\n"); });
  await rpc("initialize", {});
  const r = await rpc("tools/call", { name: tool, arguments: {} });
  child.stdin.end(); child.kill();
  return r.result.content.map((c) => c.text).join("");
}
for (const [k, s] of Object.entries(cfg.mcp)) out.mcp[k] = await callServer(s.argv, s.tool);
process.stdout.write("AGENT_OUT " + JSON.stringify(out) + "\\n");
`;

/** The agent under the real guard; its stdout, stderr and exit status. */
function runGuarded(argv: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; status: number | null }> {
  return new Promise((ok) => {
    const child = spawn(GUARD.path!, ["--allow", "127.0.0.0/8:*", "--", ...argv], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += String(c)));
    child.stderr.on("data", (c) => (stderr += String(c)));
    const timer = setTimeout(() => child.kill("SIGKILL"), 120_000);
    child.on("close", (status) => { clearTimeout(timer); ok({ stdout, stderr, status }); });
  });
}

function post(port: number, body: unknown, session: string): Promise<number> {
  return new Promise((ok, fail) => {
    const req = http.request({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => { res.resume(); res.on("end", () => ok(res.statusCode ?? 0)); });
    req.on("error", fail);
    req.end(JSON.stringify(body));
  });
}

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("exec/provenance + model-ingress/mcp: the REAL guard's taint records mask a reader's transformed output and a dirty MCP server's result on both wires; clean ones stay raw (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-guard-prov-"));
  const home = join(tmp, "home");
  const work = join(tmp, "work");
  mkdirSync(join(home, ".codex"), { recursive: true });
  mkdirSync(work, { recursive: true });
  const pgpass = join(home, ".pgpass");
  writeFileSync(pgpass, `db:5432:prod:app:${PG_CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  const holder = holderReader(tmp)!;
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${pgpass}\n    level: no-model\n    readers: [${holder.yaml}]\n`);
  const dirtyJs = join(tmp, "dirty-store.mjs");
  const cleanJs = join(tmp, "clean-notes.mjs");
  writeFileSync(dirtyJs, mcpServerSource("get", `Buffer.from(execFileSync(${JSON.stringify(holder.path)}, [${JSON.stringify(pgpass)}], { encoding: "utf8" })).toString("hex")`));
  writeFileSync(cleanJs, mcpServerSource("list", `"clean-row-8d2f"`));
  const agentJs = join(tmp, "agent.mjs");
  writeFileSync(agentJs, AGENT_SOURCE);
  const agentNode = agentNodeCopy(tmp);
  // The agents' own MCP config, as the user wrote it.
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: {
    "dirty-store": { command: "node", args: [dirtyJs] },
    "clean-notes": { command: "node", args: [cleanJs] },
  } }));
  writeFileSync(join(home, ".codex", "config.toml"), [
    "[mcp_servers.dirty-store]", 'command = "node"', `args = [${JSON.stringify(dirtyJs)}]`,
    "[mcp_servers.clean-notes]", 'command = "node"', `args = [${JSON.stringify(cleanJs)}]`, "",
  ].join("\n"));

  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  // The proxies' second client (server-main): execGate and callTaint ride
  // the human socket, the only one the arbiter binds a call from (plan 13 D9).
  const humanClient = new ArbiterClient(human);
  await humanClient.connect();
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  // The Claude Code session's model proxy, started for it (MANDU_SESSION_KEY).
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client, humanClient), upstream: upstream.fetcher, sessionKey: `guard-prov-claude-${process.pid}`, log: () => {} });
  const port = await proxy.listen(0);
  try {
    // The launcher registers the secret and writes the guard's policy file.
    const reg = await client.registerSecret({ path: pgpass, home });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    const twin = join(tmp, "pgpass.twin");
    writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);

    const leaks: string[] = [];
    for (const target of ["claude", "codex"] as const) {
      const session = `guard-prov-${target}-${process.pid}`;
      const registered = await registerLaunchMcpServers(
        { target, scopeId: session, humanCwd: work, cwd: work, arbiterHumanSock: human, effectiveAxes: { integrity: false, confidentiality: true }, confidentiality: true } as never,
        { HOME: home },
        { home, call: (s, op, args) => ndjsonCall<unknown>(s, op, args, 5_000), log: () => {} },
      );
      assert.deepEqual(registered, { status: "registered", registered: 2 });
      const secretPolicy = join(tmp, `secret-policy-${target}.json`);
      // agentExe: the agent's own binary, so the guard reports its Bash shells as
      // call roots (plan 13 D7's recorder; a call it cannot bind is masked
      // while the session holds a raw read)
      writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: pgpass, twin, level: "no-model" }] }));

      const cmds = { dirty: `${holder.path} ${pgpass} | od -An -tx1 | tr -d " \\n"`, clean: `echo clean-bash-out-${target}` };
      const cfg = { bash: cmds, mcp: { dirty: { argv: ["node", dirtyJs], tool: "get" }, clean: { argv: ["node", cleanJs], tool: "list" } } };
      // The proxy's record of each shell call's command, made when it relayed
      // the call (its response side; plan 13 D9 follow-up: a call binds by
      // that record, never by the command echoed back).
      const ids = target === "claude" ? { dirty: "toolu_bash_dirty", clean: "toolu_bash_clean" } : { dirty: "c_bash_dirty", clean: "c_bash_clean" };
      for (const k of ["dirty", "clean"] as const) await humanClient.recordCallCommand({ callId: ids[k], command: cmds[k], sessionKey: session });
      // Async: the arbiter answers the guard from THIS process's event loop.
      const run = await runGuarded([agentNode, agentJs, JSON.stringify(cfg)], { ...process.env, HOME: home, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy });
      const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
      if (!line && /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(run.stderr ?? "")) {
        t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
        return;
      }
      assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
      const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as { bash: Record<string, string>; mcp: Record<string, string> };
      // Preconditions: the readers got the real bytes (so a leak is possible).
      assert.equal(got.bash["dirty"]!.trim(), hex(`db:5432:prod:app:${PG_CANARY}\n`), `the pinned reader read the real file: ${got.bash["dirty"]}`);
      assert.equal(got.mcp["dirty"], hex(`db:5432:prod:app:${PG_CANARY}\n`), `the dirty server (node, a listed reader) read the real file: ${got.mcp["dirty"]}`);
      const secretHex = got.mcp["dirty"]!;
      // The guard's own records reached the arbiter.
      // (asked under the call's own id: the recorder binds the call to the
      // agent's shell for it, and a shell is one call's root; asked as the
      // proxy asks, on the human socket: plan 13 D9)
      const tree = await humanClient.callTaint(target === "claude" ? "toolu_bash_dirty" : "c_bash_dirty", { command: cmds.dirty, session });
      assert.equal((tree as { evidence?: string }).evidence, "tree", `the call-root recorder bound the call to the agent's shell: ${JSON.stringify(tree)}`);
      assert.equal(tree.level, "no-model", `the guard recorded the Bash tree's exec and the reader's raw read: ${JSON.stringify(tree)}`);
      const srv = await client.mcpServerTaint("mcp__dirty-store__get", session);
      assert.equal(srv.verdict, "tainted", `the guard's records map the dirty server: ${JSON.stringify(srv)}`);
      assert.equal((await client.mcpServerTaint("mcp__clean-notes__list", session)).verdict, "clean", "and the clean one");

      if (target === "claude") {
        const tools = [{ name: "Bash", input_schema: { type: "object" } }, { name: "mcp__dirty-store__get", input_schema: { type: "object" } }, { name: "mcp__clean-notes__list", input_schema: { type: "object" } }];
        const send = async (name: string, input: Record<string, unknown>, result: string, id: string): Promise<string> => {
          const n = upstream.requests.length;
          assert.equal(await post(port, { model: "claude-sonnet-4-5", stream: true, max_tokens: 512, tools, messages: [
            { role: "user", content: "go" },
            { role: "assistant", content: [{ type: "tool_use", id, name, input }] },
            { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: result }] },
          ] }, session), 200);
          assert.equal(upstream.requests.length, n + 1);
          const b = upstream.requests[n]!.json() as { messages: Array<{ content: Array<{ content: unknown }> }> };
          return JSON.stringify(b.messages[2]!.content[0]!.content);
        };
        const bashDirty = await send("Bash", { command: cmds.dirty }, got.bash["dirty"]!, "toolu_bash_dirty");
        if (bashDirty.includes(secretHex.slice(0, 24))) leaks.push("claude: the reader's Bash output");
        assert.match(bashDirty, /\[mandu:secret\] masked: mdu-holder read .*\.pgpass/, bashDirty);
        const bashClean = await send("Bash", { command: cmds.clean }, got.bash["clean"]!, "toolu_bash_clean");
        assert.ok(bashClean.includes(`clean-bash-out-${target}`), `an untainted Bash call is raw: ${bashClean}`);
        const mcpDirty = await send("mcp__dirty-store__get", {}, got.mcp["dirty"]!, "toolu_mcp_dirty");
        if (mcpDirty.includes(secretHex.slice(0, 24))) leaks.push("claude: the dirty MCP server's result");
        // the note names the reader the server got the bytes through (the holder; node
        // opened the file itself before plan 13 §8 decision (b))
        assert.match(mcpDirty, /\[mandu:secret\] masked: mdu-holder read .*\.pgpass/, mcpDirty);
        const mcpClean = await send("mcp__clean-notes__list", {}, got.mcp["clean"]!, "toolu_mcp_clean");
        assert.ok(mcpClean.includes("clean-row-8d2f"), `a clean server's result is raw: ${mcpClean}`);
      } else {
        const adapter = new OpenAiProxyArbiterAdapter(client, humanClient);
        const input: unknown[] = [
          { type: "function_call", call_id: "c_bash_dirty", name: "exec_command", arguments: JSON.stringify({ cmd: cmds.dirty }) },
          { type: "function_call_output", call_id: "c_bash_dirty", output: got.bash["dirty"] },
          { type: "function_call", call_id: "c_bash_clean", name: "exec_command", arguments: JSON.stringify({ cmd: cmds.clean }) },
          { type: "function_call_output", call_id: "c_bash_clean", output: got.bash["clean"] },
          { type: "function_call", call_id: "c_mcp_dirty", namespace: "mcp__dirty_store", name: "get", arguments: "{}" },
          { type: "function_call_output", call_id: "c_mcp_dirty", output: got.mcp["dirty"] },
          { type: "function_call", call_id: "c_mcp_clean", namespace: "mcp__clean_notes", name: "list", arguments: "{}" },
          { type: "function_call_output", call_id: "c_mcp_clean", output: got.mcp["clean"] },
        ];
        const { request } = await rewriteResponses({ model: "m", input } as unknown as ResponsesRequest, { arbiter: adapter, sessionKey: session, skipPromptInjection: true });
        const out = (id: string): string => JSON.stringify((request.input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" && i["call_id"] === id)!["output"]);
        if (out("c_bash_dirty").includes(secretHex.slice(0, 24))) leaks.push("codex: the reader's exec_command output");
        if (out("c_mcp_dirty").includes(secretHex.slice(0, 24))) leaks.push("codex: the dirty MCP server's result");
        assert.ok(out("c_bash_clean").includes(`clean-bash-out-${target}`), `an untainted exec_command is raw: ${out("c_bash_clean")}`);
        assert.ok(out("c_mcp_clean").includes("clean-row-8d2f"), `a server proven clean is raw in a tainted session: ${out("c_mcp_clean")}`);
      }
    }
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(PG_CANARY), "the file's bytes never reached the model");
    assert.deepEqual(leaks, [], "CONFIDENTIALITY VIOLATION: a secret read by a guarded process reached the model");
  } finally {
    await proxy.close();
    client.close();
    humanClient.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
