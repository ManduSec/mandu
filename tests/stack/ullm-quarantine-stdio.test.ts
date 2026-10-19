/**
 * ullm-quarantine-stdio — `ullm/quarantine` on the real path, with no login
 * and no network beyond loopback (test-reorganization.md §11.1: the replay
 * drills' inspect-extract scenarios need a Claude login and may skip, so no
 * per-push suite ran the quarantine end to end).
 *
 *   the agent's Read ──► the REAL AnthropicProxy over HTTP (production
 *     adapter) ──► the fake model: the model-ok contract arrives as an
 *     `anymodel_` symbol;
 *   the agent's inspect_symbol ──► the REAL inspect-mcp stdio server
 *     (src/server-main.ts, the process an agent's MCP config launches), over
 *     JSON-RPC, in `api` mode against a STUB U-LLM on 127.0.0.1 named as the
 *     launcher names its relay (ANTHROPIC_BASE_URL = MANDU_ULLM_FORWARDER),
 *     with MANDU_MODEL_PROXY_URL naming the model proxy;
 *   the inspect result ──► the proxy again, as the next tool_result.
 *
 * The oracle (secrets axes): the stub U-LLM read the contract (the quarantine
 * really ran, it can never skip); the result the agent gets is a NEW
 * `anymodel_` symbol, never the summary; the privileged model's wire carries
 * neither the contract nor the summary; no quarantined call went through the
 * model proxy (its upstream saw only the agent's turns), and the server
 * refuses to start when its U-LLM base URL IS the model proxy. A strict
 * (`no-model`) secret is refused into the quarantine before any U-LLM call.
 *
 * Both forms the product starts the server in run the whole oracle: from
 * source (tsx, a checkout's source form) and from the bundle
 * (`node dist/inspect-mcp.mjs` with the bundled arbiter client: installed,
 * and a checkout's fresh build, packaging.md §5.1), built privately from the
 * current source.
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { QUARANTINE_SYSTEM_PROMPT, TRIAGE_SYSTEM_PROMPT, TRIAGE_SYSTEM_PROMPT_REQUEST } from "../../interceptors/inspect-mcp/src/inspect-symbol.js";
import { axesEnv, stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

const HERE = dirname(fileURLToPath(import.meta.url));
const TSX = join(HERE, "..", "node_modules", ".bin", "tsx");
const SERVER_MAIN = join(HERE, "..", "..", "interceptors", "inspect-mcp", "src", "server-main.ts");
const BUILD = join(HERE, "..", "..", "launcher", "scripts", "build-bundle.mjs");

/** How the inspect-mcp stdio server is started: `cmd args…` plus env. */
interface Launch { form: string; cmd: string; args: string[]; env: NodeJS.ProcessEnv }
const FROM_SOURCE: Launch = { form: "source", cmd: TSX, args: [SERVER_MAIN], env: {} };

/** The bundled form (packaging.md §5, the launcher's Layout.inspectMcp when
 *  bundled): `node dist/inspect-mcp.mjs`, the arbiter client from
 *  dist/arbiter-client.mjs. Built once into a private dir (never the shared
 *  launcher/dist) from the current source. */
let bundleDir: string | null = null;
function fromBundle(): Launch {
  if (bundleDir === null) {
    const dir = mkdtempSync(join(tmpdir(), "mandu-ullm-stdio-dist-"));
    const b = spawnSync(process.execPath, [BUILD, `--outdir=${join(dir, "dist")}`, "--no-native", "--quiet"], { cwd: dirname(dirname(BUILD)), encoding: "utf8", timeout: 300_000 });
    assert.equal(b.status, 0, `the private build: ${b.stdout}\n${b.stderr}`);
    bundleDir = join(dir, "dist");
  }
  return {
    form: "bundle", cmd: process.execPath,
    args: ["--no-warnings=ExperimentalWarning", join(bundleDir, "inspect-mcp.mjs")],
    env: { MANDU_ARBITER_CLIENT_MODULE: join(bundleDir, "arbiter-client.mjs") },
  };
}
after(() => { if (bundleDir !== null) rmSync(dirname(bundleDir), { recursive: true, force: true }); });

const CONTRACT_CANARY = "ULLM_STDIO_CONTRACT_CANARY_6631";
const CONTRACT_BODY = `Acme agrees to pay $4,200,000 on 2026-09-30. ${CONTRACT_CANARY}`;
const SUMMARY_CANARY = "ULLM_STDIO_SUMMARY_CANARY_2290";
const SUMMARY = `Acme pays 4.2M on 2026-09-30. ${SUMMARY_CANARY}`;
const NPM_TOKEN = "npm_UllmStdioStrictCanary5d1e2f3a4b5c6d7e8f";
const ANYMODEL_RE = /\$MDU:anymodel_[A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;
const NOMODEL_RE = /\$MDU:nomodel_[A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;
const TRIAGE = new Set([TRIAGE_SYSTEM_PROMPT, TRIAGE_SYSTEM_PROMPT_REQUEST]);

/** A stub of the Anthropic Messages API: the quarantined model. */
async function stubUllm(): Promise<{ origin: string; requests: Array<{ system: string; user: string; raw: string }>; close(): Promise<void> }> {
  const requests: Array<{ system: string; user: string; raw: string }> = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const body = JSON.parse(raw) as { system?: unknown; messages?: Array<{ content: unknown }> };
      const system = typeof body.system === "string" ? body.system : JSON.stringify(body.system ?? "");
      const m = body.messages?.[0]?.content;
      const user = typeof m === "string" ? m : JSON.stringify(m ?? "");
      requests.push({ system, user, raw });
      const text = TRIAGE.has(system) ? "substantive" : SUMMARY;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ id: "msg_stub", type: "message", role: "assistant", model: "claude-stub-ullm", content: [{ type: "text", text }], stop_reason: "end_turn", usage: { input_tokens: 1, output_tokens: 1 } }));
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  return {
    origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    requests,
    close: () => new Promise<void>((ok) => server.close(() => ok())),
  };
}

/** The real inspect-mcp stdio server, spoken to as an agent's MCP client. */
async function inspectServer(launch: Launch, env: NodeJS.ProcessEnv): Promise<{ call(args: Record<string, unknown>): Promise<{ text: string; isError: boolean }>; close(): Promise<void> }> {
  const child: ChildProcess = spawn(launch.cmd, launch.args, { env: { ...env, ...launch.env }, stdio: ["pipe", "pipe", "pipe"] });
  let stderr = "";
  child.stderr!.on("data", (c) => (stderr += String(c)));
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
      setTimeout(() => reject(new Error(`no answer to ${method} within 30 s; stderr: ${stderr}`)), 30_000).unref();
    });
  assert.ok((await rpc("initialize", {})).result, "the stdio server answers initialize");
  return {
    async call(args) {
      const r = (await rpc("tools/call", { name: "inspect_symbol", arguments: args })).result as { content: { text: string }[]; isError?: boolean };
      return { text: r.content.map((c) => c.text).join(""), isError: r.isError === true };
    },
    async close() {
      child.stdin!.end();
      if (child.exitCode === null) await new Promise((r) => { child.once("exit", r); setTimeout(() => { child.kill("SIGKILL"); r(null); }, 3000).unref(); });
    },
  };
}

function post(port: number, body: unknown, session: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); },
    );
    req.on("error", reject);
    req.end(JSON.stringify(body));
  });
}

const TOOLS = [{ name: "Read", input_schema: { type: "object" } }, { name: "mcp__mandu-inspect__inspect_symbol", input_schema: { type: "object" } }];
function turn(tool: string, input: Record<string, unknown>, result: string, id: string): unknown {
  return {
    model: "claude-sonnet-4-5", stream: true, max_tokens: 1024, tools: TOOLS,
    messages: [
      { role: "user", content: "Summarize the Acme contract." },
      { role: "assistant", content: [{ type: "tool_use", id, name: tool, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: result }] },
    ],
  };
}

function toolResultOf(bodyText: string): string {
  const b = JSON.parse(bodyText) as { messages: Array<{ content: unknown }> };
  return JSON.stringify((b.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);
}

for (const [form, launchOf] of [["source", () => FROM_SOURCE], ["bundle", fromBundle]] as const) {
test(`ullm/quarantine on the real path (inspect-mcp from ${form}): the real inspect-mcp server summarizes a model-ok contract through a stub U-LLM, re-symbolized; the privileged model never reads it and no quarantined call crosses the model proxy (secrets axes)`, { timeout: 360_000 }, async () => {
  const launch = launchOf();
  const tmp = mkdtempSync(join(tmpdir(), "mandu-ullm-stdio-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  writeFileSync(join(home, ".npmrc"), `//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n`);
  const sock = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath: sock, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const admin = new ArbiterClient(join(tmp, "admin.sock"));
  await admin.connect();
  const client = new ArbiterClient(sock);
  await client.connect();
  const ullm = await stubUllm();
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client), upstream: upstream.fetcher, log: () => {} });
  const port = await proxy.listen(0);
  const proxyUrl = `http://127.0.0.1:${port}`;
  const session = `ullm-stdio-${process.pid}`;
  const baseEnv: NodeJS.ProcessEnv = {
    ...process.env, ...axesEnv("secrets"),
    MANDU_ARBITER_SOCK: sock, MANDU_SCOPE_ID: session,
    MANDU_ULLM_MODE: "api", ANTHROPIC_API_KEY: "sk-ant-test-dummy",
    MANDU_MODEL_PROXY_URL: proxyUrl,
  };
  delete baseEnv.MANDU_ULLM_MODEL;
  let mcp: Awaited<ReturnType<typeof inspectServer>> | null = null;
  try {
    // The human's label: the contract may be read by any model (rung 2).
    await admin.setPathLabel({ path: "/workspace/contracts", confidentiality: "any-model" });
    // ── The agent's Read, through the proxy: the model sees a symbol.
    assert.equal(await post(port, turn("Read", { file_path: "/workspace/contracts/acme.txt" }, CONTRACT_BODY, "toolu_read"), session), 200);
    const readSpan = toolResultOf(upstream.requests[0]!.bodyText);
    assert.ok(!readSpan.includes(CONTRACT_CANARY), "CONFIDENTIALITY VIOLATION: the contract reached the privileged model");
    const symbol = ANYMODEL_RE.exec(readSpan)?.[0];
    assert.ok(symbol, `the model sees an anymodel_ symbol: ${readSpan}`);

    // ── The agent calls inspect_symbol on the real stdio server.
    mcp = await inspectServer(launch, { ...baseEnv, ANTHROPIC_BASE_URL: ullm.origin, MANDU_ULLM_FORWARDER: ullm.origin });
    const out = await mcp.call({ symbol, instruction: "Summarize this contract in one sentence." });
    assert.equal(out.isError, false, out.text);
    const main = ullm.requests.filter((r) => !TRIAGE.has(r.system));
    assert.ok(main.length >= 1, "the quarantined model ran (it cannot skip: the stub is always there)");
    assert.ok(main.some((r) => r.system === QUARANTINE_SYSTEM_PROMPT && r.user.includes(CONTRACT_CANARY)), "the U-LLM read the contract, under the quarantine prompt");
    assert.ok(!out.text.includes(SUMMARY_CANARY), "the summary never comes back raw");
    const resultSymbol = ANYMODEL_RE.exec(out.text)?.[0];
    assert.ok(resultSymbol && resultSymbol !== symbol, `a NEW anymodel_ symbol (a model-ok datum's summary is model-ok): ${out.text}`);
    const derived = await admin.resolveFull(resultSymbol!, { deep: true });
    assert.equal(derived.value, SUMMARY, "the symbol holds the U-LLM's summary");
    assert.equal(derived.confidentiality, "any-model");

    // ── The inspect result goes back to the model as the next tool_result.
    assert.equal(await post(port, turn("mcp__mandu-inspect__inspect_symbol", { symbol, instruction: "Summarize" }, out.text, "toolu_inspect"), session), 200);
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(CONTRACT_CANARY), "CONFIDENTIALITY VIOLATION: the contract reached the privileged model");
    assert.ok(!wire.includes(SUMMARY_CANARY), "nor did the summary");
    assert.ok(toolResultOf(upstream.requests[1]!.bodyText).includes(resultSymbol!), "the model gets the result symbol");

    // ── The U-LLM channel never crosses the model proxy.
    assert.equal(upstream.requests.length, 2, "the model proxy's upstream saw only the agent's two turns");
    assert.ok(!upstream.requests.some((r) => r.bodyText.includes(QUARANTINE_SYSTEM_PROMPT.slice(0, 60))), "no quarantine prompt on the privileged wire");
    assert.ok(!ullm.requests.some((r) => r.raw.includes("Summarize the Acme contract.")), "and no privileged-model context in the quarantine");

    // ── A strict secret is refused into the quarantine before any model call.
    const reg = await client.registerSecret({ path: join(home, ".npmrc"), home });
    assert.match(String(reg.symbol), NOMODEL_RE);
    const before = ullm.requests.length;
    const strict = await mcp.call({ symbol: String(reg.symbol), instruction: "What is the token?" });
    assert.ok(!strict.text.includes(NPM_TOKEN), "the strict secret never comes back");
    assert.equal(ullm.requests.length, before, "THE RESIDENCY CLAIM: no model read the strict secret, not even the quarantined one");
    assert.ok(!ullm.requests.some((r) => r.raw.includes(NPM_TOKEN)));
  } finally {
    await mcp?.close();
    await proxy.close();
    await ullm.close();
    client.close();
    admin.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test(`ullm/quarantine FAIL CLOSED (inspect-mcp from ${form}): the inspect server refuses to start with its U-LLM base URL at the model proxy, or with no U-LLM at all (secrets axes)`, { timeout: 360_000 }, () => {
  const launch = launchOf();
  const env = (extra: Record<string, string>): NodeJS.ProcessEnv => {
    const e: NodeJS.ProcessEnv = { ...process.env, ...axesEnv("secrets"), MANDU_ARBITER_SOCK: "/nonexistent/mandu-ullm-stdio.sock", MANDU_ULLM_MODE: "api", ANTHROPIC_API_KEY: "sk-ant-test-dummy", ...launch.env, ...extra };
    delete e.MANDU_ULLM_FORWARDER;
    return e;
  };
  // The model proxy is a loopback address that is not the pinned relay.
  const atProxy = spawnSync(launch.cmd, launch.args, { env: env({ ANTHROPIC_BASE_URL: "http://127.0.0.1:8788" }), input: "", encoding: "utf8", timeout: 30_000 });
  assert.notEqual(atProxy.status, 0, "the server does not start");
  assert.match(atProxy.stderr, /loopback host .*refusing/, atProxy.stderr);
  // api mode with no key: no U-LLM, no start.
  const noKey = env({});
  delete noKey.ANTHROPIC_API_KEY;
  const r = spawnSync(launch.cmd, launch.args, { env: noKey, input: "", encoding: "utf8", timeout: 30_000 });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /ANTHROPIC_API_KEY is not set/);
});
}
