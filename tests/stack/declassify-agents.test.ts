/**
 * e2e — `declassify_symbol` (rung 3, the in-context read) on OpenCode and
 * OpenClaw, through each agent's PRODUCTION mount over a real ArbiterServer
 * (agent-e2e-harness.md §8.5, supported-agents.md §5.5 item 3, 2026-09-29):
 *
 *   OpenCode: the real inspect-mcp stdio server (src/server-main.ts, the
 *     process OpenCode's `mcp.mandu-inspect` entry launches), spoken to over
 *     stdio JSON-RPC; its tool reaches the model as
 *     `mandu-inspect_declassify_symbol`.
 *   OpenClaw: the real plugin registrar (registerInspectPlugin with its default
 *     arbiter factory, `new ArbiterClientAdapter(new ArbiterClient(sock))`);
 *     the tool reaches the model as bare `declassify_symbol`.
 *
 * Each tool result then goes through the anthropic-proxy's rewrite, under the
 * production adapter and a session bound to that agent's inbound spec, which
 * is what the model is sent.
 *
 * The semantics are Claude Code's, unchanged, because the arbiter decides:
 * in a session that has ingested untrusted data the read waits for the human;
 * a human "no" is a refusal with no content and no watermark; a human "yes"
 * releases the value, raises the session to the datum's level, and the value
 * reaches the model unmasked. An unreachable arbiter releases nothing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { request as httpRequest } from "node:http";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as ProxyAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { registerInspectPlugin } from "../../interceptors/openclaw-inspect-plugin/src/register.js";
import type { PluginAgentTool, PluginToolFactory } from "../../interceptors/openclaw-inspect-plugin/src/openclaw-api.js";
import type { UllmClient } from "../../interceptors/inspect-mcp/src/ullm-client.js";
import { axesEnv, stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

const HERE = dirname(fileURLToPath(import.meta.url));
const TSX = join(HERE, "..", "node_modules", ".bin", "tsx");
const SERVER_MAIN = join(HERE, "..", "..", "interceptors", "inspect-mcp", "src", "server-main.ts");

const DENIED_BODY = "Deal memo A: margin 31 percent. DECL_DENIED_CANARY_4410";
const APPROVED_BODY = "Deal memo B: reference R-2718. DECL_APPROVED_CANARY_2718";
const IN_CONTEXT_READ = "model_context:in-context-read";

/** One agent's production mount of declassify_symbol. */
interface Mount {
  /** the name the model's tool_use carries */
  toolName: string;
  /** the agent's file-read tool and the param naming the path */
  read: { tool: string; param: string };
  spec: "opencode" | "openclaw-agent";
  /** call the tool; the text the agent hands back as the tool_result */
  call(args: { symbol: string; reason: string }): Promise<{ text: string; isError: boolean }>;
  close(): Promise<void>;
}

// ── OpenCode: the real MCP stdio server ─────────────────────────────────────

/** `scope` null = the launcher named no Mandu scope (no MANDU_SCOPE_ID at all,
 *  not even one inherited from the shell running the tests). */
function serverEnv(sock: string, scope: string | null): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...axesEnv("secrets"),
    MANDU_ARBITER_SOCK: sock,
    // api mode with a dummy key: the U-LLM is never called by declassify
    MANDU_ULLM_MODE: "api",
    ANTHROPIC_API_KEY: "sk-ant-test-dummy",
    ANTHROPIC_BASE_URL: "https://api.anthropic.com",
  };
  if (scope === null) delete env.MANDU_SCOPE_ID;
  else env.MANDU_SCOPE_ID = scope;
  return env;
}

async function opencodeMount(sock: string, scope: string | null): Promise<Mount & { child: ChildProcess }> {
  const child = spawn(TSX, [SERVER_MAIN], { env: serverEnv(sock, scope), stdio: ["pipe", "pipe", "pipe"] });
  const pending = new Map<number, (r: { result?: unknown; error?: unknown }) => void>();
  createInterface({ input: child.stdout! }).on("line", (line) => {
    const msg = JSON.parse(line) as { id: number; result?: unknown; error?: unknown };
    pending.get(msg.id)?.(msg);
    pending.delete(msg.id);
  });
  let seq = 0;
  const rpc = (method: string, params: unknown): Promise<{ result?: unknown; error?: unknown }> =>
    new Promise((resolve, reject) => {
      const id = ++seq;
      pending.set(id, resolve);
      child.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      setTimeout(() => reject(new Error(`no answer to ${method} within 20 s`)), 20_000).unref();
    });
  const init = await rpc("initialize", {});
  assert.ok(init.result, "the stdio server answers initialize");
  const listed = (await rpc("tools/list", {})).result as { tools: { name: string }[] };
  assert.deepEqual(listed.tools.map((t) => t.name), ["inspect_symbol", "declassify_symbol"]);
  return {
    child,
    toolName: "mandu-inspect_declassify_symbol",
    read: { tool: "read", param: "filePath" },
    spec: "opencode",
    async call(args) {
      const r = (await rpc("tools/call", { name: "declassify_symbol", arguments: args })).result as {
        content: { text: string }[]; isError?: boolean;
      };
      return { text: r.content.map((c) => c.text).join(""), isError: r.isError === true };
    },
    async close() {
      child.stdin!.end();
      if (child.exitCode === null) await new Promise((r) => { child.once("exit", r); setTimeout(() => { child.kill("SIGKILL"); r(null); }, 3000).unref(); });
    },
  };
}

// ── OpenClaw: the real plugin registrar ─────────────────────────────────────

const NO_ULLM = { async complete() { throw new Error("the U-LLM is not part of rung 3"); } } as unknown as UllmClient;

function openclawTool(sock: string, scope: string): PluginAgentTool {
  const registered: Array<PluginAgentTool | PluginToolFactory> = [];
  registerInspectPlugin(
    {
      id: "mandu-inspect",
      pluginConfig: { arbiterSock: sock, scopeId: scope, ullmMode: "cli", ullmBinary: "claude" },
      logger: { info() {}, warn() {}, error() {} },
      registerTool: (t) => registered.push(t),
    },
    // Production arbiter wiring (no connectArbiter override); only the
    // quarantine transport is stubbed, and declassify never touches it.
    { env: {}, cliAvailable: () => true, buildUllm: () => NO_ULLM },
  );
  const tools = registered.map((f) => (f as PluginToolFactory)({ sessionKey: "agent:main:main" }) as PluginAgentTool);
  const tool = tools.find((t) => t.name === "declassify_symbol");
  assert.ok(tool, "the plugin registers declassify_symbol");
  return tool!;
}

function openclawMount(sock: string, scope: string): Mount {
  const tool = openclawTool(sock, scope);
  return {
    toolName: "declassify_symbol",
    read: { tool: "read", param: "path" },
    spec: "openclaw-agent",
    async call(args) {
      const r = await tool.execute("call-1", args);
      const text = r.content.map((c) => c.text).join("");
      return { text, isError: !text.startsWith("[DECLASSIFIED") };
    },
    async close() {},
  };
}

// ── The shared scenario ─────────────────────────────────────────────────────

function turn(toolName: string, input: Record<string, unknown>, result: string): string {
  return JSON.stringify({
    model: "claude-test",
    stream: true,
    messages: [
      { role: "user", content: "Read the memo into context." },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_1", name: toolName, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_1", content: result }] },
    ],
  });
}

function post(port: number, body: string, session: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); },
    );
    req.on("error", reject);
    req.end(body);
  });
}

/** The model proxy for one Mandu session, in its production wiring (it
 *  fetches the session's gate surface itself). `send` returns the tool_result
 *  content the model was actually sent. */
async function modelProxy(client: ArbiterClient, scope: string): Promise<{ send(body: string): Promise<string>; close(): Promise<void> }> {
  const up = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ProxyAdapter(client), upstream: up.fetcher, sessionKey: scope, log: () => {} });
  const port = await proxy.listen(0);
  return {
    async send(body) {
      assert.equal(await post(port, body, scope), 200);
      const sent = up.requests[up.requests.length - 1]!.json() as { messages: Array<{ content: unknown }> };
      return JSON.stringify((sent.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);
    },
    close: () => proxy.close(),
  };
}

const ANYMODEL_SYMBOL_RE = /\$MDU:anymodel_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\]/;

interface Stack {
  tmp: string;
  sock: string;
  server: ArbiterServer;
  admin: ArbiterClient;
  data: ArbiterClient;
  proxyClient: ArbiterClient;
  memoA: string;
  memoB: string;
}

async function stack(): Promise<Stack> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-decl-agents-"));
  mkdirSync(join(tmp, "ws", "memo"), { recursive: true });
  const memoA = join(tmp, "ws", "memo", "a.md");
  const memoB = join(tmp, "ws", "memo", "b.md");
  writeFileSync(memoA, DENIED_BODY + "\n");
  writeFileSync(memoB, APPROVED_BODY + "\n");
  const sock = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"),
    eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await server.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock")); await admin.connect();
  const data = new ArbiterClient(sock); await data.connect();
  const proxyClient = new ArbiterClient(sock); await proxyClient.connect();
  await admin.setPathLabel({ path: join(tmp, "ws", "memo"), confidentiality: "any-model", recursive: true });
  return { tmp, sock, server, admin, data, proxyClient, memoA, memoB };
}

async function teardown(s: Stack): Promise<void> {
  s.admin.close(); s.data.close(); s.proxyClient.close();
  await s.server.close().catch(() => {});
  rmSync(s.tmp, { recursive: true, force: true });
}

/** The human answers the queued in-context read of `symbol` on the dashboard. */
async function humanAnswers(s: Stack, symbol: string, approve: boolean): Promise<void> {
  const pending = await s.admin.egressApprovals("pending");
  const entry = pending.find((a) => a.symbol === symbol && a.destination === IN_CONTEXT_READ);
  assert.ok(entry, "the read is queued for the human, keyed to the act");
  await s.admin.resolveEgressApproval(entry!.id, approve, "once");
}

async function scenario(s: Stack, scope: string, mount: Mount): Promise<void> {
  const bound = await s.admin.setSessionSpec({ sessionKey: scope, spec: mount.spec, requestedBy: "declassify-agents e2e" });
  assert.equal(bound.bound, mount.spec);
  const proxy = await modelProxy(s.proxyClient, scope);
  try {
    // The agent reads both labeled files: the proxy mints any-model symbols.
    const symbolFor = async (path: string, body: string): Promise<string> => {
      const sent = await proxy.send(turn(mount.read.tool, { [mount.read.param]: path }, body));
      assert.ok(!sent.includes(body.slice(-20)), `the labeled file reaches the model only as a symbol: ${sent}`);
      const m = ANYMODEL_SYMBOL_RE.exec(sent);
      assert.ok(m, `an any-model symbol: ${sent}`);
      return m![0];
    };
    const symA = await symbolFor(s.memoA, DENIED_BODY);
    const symB = await symbolFor(s.memoB, APPROVED_BODY);
    assert.notEqual(symA, symB);

    // The session has ingested untrusted data (§9 rule 2's session half), so
    // an in-context read now waits for the human, as it does for Claude Code.
    await s.data.symbolizeFull({ tool: "webfetch", value: "a web page", field: "content", origin: "https://example.com", integrity: "untrusted", sessionKey: scope });
    assert.equal((await s.data.sessionState(scope)).untrustedTainted, true);

    // ── DENIED: queued, the human says no, the retry is refused ──
    const asked = await mount.call({ symbol: symA, reason: "the user asked" });
    assert.equal(asked.isError, true);
    assert.match(asked.text, /asked to approve/);
    await humanAnswers(s, symA, false);
    const denied = await mount.call({ symbol: symA, reason: "the user asked" });
    assert.equal(denied.isError, true);
    assert.match(denied.text, /declined/);
    for (const t of [asked.text, denied.text]) assert.ok(!t.includes("DECL_DENIED_CANARY"), "CONFIDENTIALITY VIOLATION: a refused read carried content");
    assert.equal((await s.data.sessionState(scope)).high, false, "a refused read floats nothing");
    assert.ok(!(await proxy.send(turn(mount.toolName, { symbol: symA, reason: "the user asked" }, denied.text))).includes("DECL_DENIED_CANARY"));

    // ── APPROVED: queued, the human says yes, the value reaches the model ──
    const askedB = await mount.call({ symbol: symB, reason: "the user asked" });
    assert.equal(askedB.isError, true);
    assert.ok(!askedB.text.includes("DECL_APPROVED_CANARY"));
    assert.equal((await s.data.sessionState(scope)).high, false);
    await humanAnswers(s, symB, true);
    const approved = await mount.call({ symbol: symB, reason: "the user asked" });
    assert.equal(approved.isError, false, approved.text);
    assert.match(approved.text, /^\[DECLASSIFIED — this session is now HIGH \(any-model\)\./);
    // The live banner keeps the model making its calls and promises no
    // approval the session gate does not file (handling-prompt.md §7).
    assert.match(approved.text, /Requests to the hosts this content is bound to still go through/);
    assert.match(approved.text, /Keep making the calls the user asks for and let Mandu decide each one/);
    assert.doesNotMatch(approved.text, /requires the user's approval/);
    assert.ok(approved.text.endsWith(`\n\n${APPROVED_BODY}`), `the released value, byte for byte: ${approved.text}`);
    const st = await s.data.sessionState(scope);
    assert.equal(st.high, true, "the release raised the gated session's watermark");
    assert.equal(st.confidentiality, "any-model");
    const sent = await proxy.send(turn(mount.toolName, { symbol: symB, reason: "the user asked" }, approved.text));
    assert.match(sent, /DECL_APPROVED_CANARY_2718/, `the model receives what it was allowed to read, not a fresh token: ${sent}`);
    assert.ok(!ANYMODEL_SYMBOL_RE.test(sent), "no re-mask");

    // Nightly 11551 (2026-10-17): the model's `reason` names the file it
    // declassifies, relative or absolute. The tool's every input string is
    // read for a labelled path (plan 10 §11.11), and that raise masked the
    // granted read again. The exact grant still reaches the model...
    for (const reason of ["the user authorized loading memo/b.md here", `load ${s.memoB} into context`]) {
      const named = await proxy.send(turn(mount.toolName, { symbol: symB, reason }, approved.text));
      assert.match(named, /DECL_APPROVED_CANARY_2718/, `a reason naming the file (${reason}) does not re-mask the grant: ${named}`);
      assert.ok(!ANYMODEL_SYMBOL_RE.test(named), `no re-mask (${reason})`);
      // ...and a result that is not exactly the grant keeps the raise.
      const padded = await proxy.send(turn(mount.toolName, { symbol: symB, reason }, `${approved.text}\nand more text after it`));
      assert.ok(!padded.includes("DECL_APPROVED_CANARY"), `CONFIDENTIALITY VIOLATION: a result that is not the grant reached the model raw (${reason}): ${padded}`);
      assert.match(padded, ANYMODEL_SYMBOL_RE, `masked at the file's level (${reason})`);
    }
  } finally {
    await proxy.close();
  }
}

// ── The tests ───────────────────────────────────────────────────────────────

test("OpenCode (MCP stdio server): a read the human denies stays out; one the human approves reaches the model and raises the session (secrets axes)", async () => {
  const s = await stack();
  const scope = `decl-opencode-${process.pid}`;
  const mount = await opencodeMount(s.sock, scope);
  try {
    await scenario(s, scope, mount);
  } finally {
    await mount.close();
    await teardown(s);
  }
});

test("OpenClaw (plugin tool): a read the human denies stays out; one the human approves reaches the model and raises the session (secrets axes)", async () => {
  const s = await stack();
  const scope = `decl-openclaw-${process.pid}`;
  const mount = openclawMount(s.sock, scope);
  try {
    await scenario(s, scope, mount);
  } finally {
    await mount.close();
    await teardown(s);
  }
});

test("FAIL CLOSED: an unreachable arbiter releases nothing, on either agent (secrets axes)", async () => {
  const s = await stack();
  const scopeOc = `decl-dead-oc-${process.pid}`;
  const scopeOw = `decl-dead-ow-${process.pid}`;
  const sym = (await s.data.symbolizeFull({
    tool: "read", value: APPROVED_BODY, field: "content", origin: s.memoB, integrity: "trusted", sessionKey: scopeOc,
  })).symbol;
  // Both mounts connected while the arbiter was up...
  const oc = await opencodeMount(s.sock, scopeOc);
  const ow = openclawMount(s.sock, scopeOw);
  try {
    // ...and it dies.
    await s.server.close();
    const a = await oc.call({ symbol: sym, reason: "r" });
    assert.equal(a.isError, true);
    assert.match(a.text, /arbiter error/);
    const b = await ow.call({ symbol: sym, reason: "r" });
    assert.equal(b.isError, true);
    assert.match(b.text, /arbiter unavailable, refusing \(fail closed\)/);
    for (const t of [a.text, b.text]) assert.ok(!t.includes("DECL_APPROVED_CANARY"), "CONFIDENTIALITY VIOLATION: content without an arbiter");

    // No arbiter at all from the start: OpenCode's server refuses to start
    // (the tool never exists), OpenClaw's tool refuses every call.
    const dead = join(s.tmp, "no-such.sock");
    const child = spawn(TSX, [SERVER_MAIN], { env: serverEnv(dead, "x"), stdio: ["pipe", "ignore", "pipe"] });
    let stderr = "";
    child.stderr!.on("data", (d) => { stderr += String(d); });
    const code = await new Promise<number | null>((r) => child.once("exit", r));
    assert.notEqual(code, 0, "the MCP server exits rather than serve without an arbiter");
    assert.match(stderr, /ENOENT|ECONNREFUSED|fatal/);
    const never = await openclawMount(dead, "x").call({ symbol: sym, reason: "r" });
    assert.match(never.text, /arbiter unavailable, refusing \(fail closed\)/);
  } finally {
    await oc.close();
    await teardown(s);
  }
});

test("FAIL CLOSED: the MCP server with no Mandu scope refuses declassify_symbol and releases nothing; with the scope the same read is released (secrets axes)", async () => {
  const s = await stack();
  const scope = `decl-scope-${process.pid}`;
  const minted = await s.data.symbolizeFull({
    tool: "read", value: APPROVED_BODY, field: "content", origin: s.memoB, integrity: "trusted", sessionKey: scope,
  });
  assert.equal(minted.confidentiality, "any-model", "a secret symbol, so a refusal is about the scope and nothing else");
  const mounts: Mount[] = [];
  try {
    for (const missing of [null, "", "   "] as const) {
      const noScope = await opencodeMount(s.sock, missing);
      mounts.push(noScope);
      const r = await noScope.call({ symbol: minted.symbol, reason: "the user asked" });
      assert.equal(r.isError, true, `MANDU_SCOPE_ID=${JSON.stringify(missing)}`);
      assert.match(r.text, /no Mandu scope is configured \(MANDU_SCOPE_ID\)/);
      assert.ok(!r.text.includes("DECL_APPROVED_CANARY"), "CONFIDENTIALITY VIOLATION: a release with no gated session");
    }
    // Nothing happened at the arbiter: no session went HIGH (neither the
    // run's nor the server's inspect fallback), nothing was queued.
    for (const sk of [scope, "inspect-mcp"]) assert.equal((await s.data.sessionState(sk)).high, false, sk);
    assert.deepEqual(await s.admin.egressApprovals("pending"), []);

    // Control: the same server, given the scope, releases the same read.
    const scoped = await opencodeMount(s.sock, scope);
    mounts.push(scoped);
    const ok = await scoped.call({ symbol: minted.symbol, reason: "the user asked" });
    assert.equal(ok.isError, false, ok.text);
    assert.ok(ok.text.endsWith(`\n\n${APPROVED_BODY}`));
    assert.equal((await s.data.sessionState(scope)).high, true);
  } finally {
    for (const m of mounts) await m.close();
    await teardown(s);
  }
});
