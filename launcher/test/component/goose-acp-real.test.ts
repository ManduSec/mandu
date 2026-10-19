/**
 * goose-acp-real.test — `mandu goose acp` (supported-agents.md §5.6 "ACP"):
 * the REAL launcher as its own process (`node --import tsx src/run.ts`), the
 * REAL goose 1.53.0 serving ACP on stdio behind it, the REAL arbiter daemon
 * in `secrets` mode with a file labelled `no-model`, the autostarted
 * anthropic-proxy and a scripted model upstream. A scripted ACP client plays
 * the editor, offering Goose its file system and terminal as an editor
 * does. Needs a goose binary (MANDU_GOOSE_BIN, else `goose` on PATH);
 * without one the suite SKIPS with that reason, never a green.
 *
 *   stream    every line the editor reads parses as JSON-RPC (the launcher's
 *             notices go to stderr; the reply filter is off for this shape);
 *   tools     Goose is offered neither the editor's file system nor its
 *             terminal: its `shell` runs in Goose (no `terminal/*` or `fs/*`
 *             request reaches the editor), the model sees the captured
 *             17-tool surface (no ACP `read`) plus Mandu's own
 *             (`mandu-inspect__inspect_symbol`, mounted per session);
 *   routing   the turn's model calls go through the proxy, and the labelled
 *             file the model makes Goose `cat` reaches the model only as a
 *             symbol (THE INVARIANT);
 *   refusals  a provider switch to `openai` and a desktop `_goose/*` method
 *             are answered with an error and change nothing; `acp
 *             --enable-scheduler` starts nothing;
 *   display   the model's reply quotes the symbol it was given, and the
 *             editor reads the ORIGINAL in its place (the relay's JSON-aware
 *             pass over the human plane, goose-acp-display.ts) while every
 *             request the model saw holds only the symbol; the editor
 *             echoing what it was shown into its next prompt still reaches
 *             the model only as the symbol (the prompt filter's
 *             registered-value floor); `--no-reply-filter` keeps the symbol
 *             in the editor's view.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../axes.js";
import { stopGroup } from "../lib/tmp-dir.js";

stateAxes("secrets"); // the shipped default: the labelled file must reach the model only as a symbol

const HERE = dirname(fileURLToPath(import.meta.url));
const LAUNCHER_ROOT = resolve(HERE, "..", "..");
const REPO_ROOT = resolve(LAUNCHER_ROOT, "..");
const ARBITER_DIR = join(REPO_ROOT, "arbiter");
const ARBITER_TSX = join(ARBITER_DIR, "node_modules", ".bin", "tsx");
const ARBITER_MAIN = join(ARBITER_DIR, "ipc", "server-main.ts");

function findGoose(): string | null {
  const pinned = process.env["MANDU_GOOSE_BIN"];
  if (pinned) return existsSync(pinned) ? pinned : null;
  for (const d of (process.env["PATH"] ?? "").split(delimiter)) {
    const p = join(d, "goose");
    if (d && existsSync(p)) return p;
  }
  return null;
}
const GOOSE = findGoose();
const SKIP = GOOSE === null
  ? "no goose binary: set MANDU_GOOSE_BIN or put goose on PATH (the CI guest image pins it; scripts/ci/pins.env)"
  : (spawnSync(GOOSE, ["--version"], { encoding: "utf8", timeout: 20_000 }).status !== 0 ? `${GOOSE} --version failed` : false);

const MODEL = "claude-sonnet-4-5";
const CANARY = "GOOSE-ACP-CANARY-4417";

let tmp: string;
let work: string;
let secretFile: string;
let arbiter: ChildProcess | undefined;
let upstream: Server;
let upstreamOrigin = "";
const reqs: Array<{ method: string; path: string; raw: string; body: Record<string, unknown> | null }> = [];
let passed = 0;

function sse(events: Array<[string, unknown]>): string {
  return events.map(([e, d]) => `event: ${e}\ndata: ${JSON.stringify(d)}\n\n`).join("");
}
const start = (id: string): [string, unknown] => ["message_start", { type: "message_start", message: { id, type: "message", role: "assistant", model: MODEL, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 5, output_tokens: 1 } } }];
const textTurn = (t: string): string => sse([
  start("msg_t"),
  ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }],
  ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: t } }],
  ["content_block_stop", { type: "content_block_stop", index: 0 }],
  ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } }],
  ["message_stop", { type: "message_stop" }],
]);
const shellTurn = (command: string): string => sse([
  start("msg_u"),
  ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_goose_acp_1", name: "shell", input: {} } }],
  ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ command }) } }],
  ["content_block_stop", { type: "content_block_stop", index: 0 }],
  ["message_delta", { type: "message_delta", delta: { stop_reason: "tool_use", stop_sequence: null }, usage: { output_tokens: 1 } }],
  ["message_stop", { type: "message_stop" }],
]);

/** The scripted model: a tools-bearing request without a tool result gets a
 *  shell call that cats the labelled file, the one carrying its result the
 *  closing text, a tool-less one (a title) a title. Goose's ACP server also
 *  lists models (`GET /v1/models`) once. */
function scripted(req: IncomingMessage, res: ServerResponse): void {
  let buf = "";
  req.setEncoding("utf8");
  req.on("data", (c) => (buf += c));
  req.on("end", () => {
    let body: Record<string, unknown> | null = null;
    try { body = JSON.parse(buf) as Record<string, unknown>; } catch { /* not JSON */ }
    reqs.push({ method: req.method ?? "", path: req.url ?? "", raw: buf, body });
    if (req.method === "GET") {
      res.writeHead(200, { "content-type": "application/json" });
      return void res.end(JSON.stringify({ data: [{ type: "model", id: MODEL, display_name: "Sonnet", created_at: "2026-01-01T00:00:00Z" }], has_more: false, first_id: MODEL, last_id: MODEL }));
    }
    const tools = Array.isArray(body?.["tools"]) ? (body!["tools"] as unknown[]) : [];
    const msgs = Array.isArray(body?.["messages"]) ? (body!["messages"] as Array<{ content?: unknown }>) : [];
    const hasResult = msgs.some((m) => Array.isArray(m.content) && (m.content as Array<{ type?: string }>).some((b) => b.type === "tool_result"));
    res.writeHead(200, { "content-type": "text/event-stream" });
    if (tools.length === 0) return void res.end(textTurn("Title"));
    // The closing text repeats the symbol the tool result carried (a model
    // quoting what it read), so the editor has one to see resolved.
    const seen = /\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/.exec(buf)?.[0];
    res.end(hasResult ? textTurn(`MANDU_GOOSE_ACP_DONE${seen ? ` ${seen}` : ""}`) : shellTurn(`cat ${secretFile}`));
  });
}

async function waitFor(path: string, ms: number): Promise<void> {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (existsSync(path)) return; await new Promise((r) => setTimeout(r, 50)); }
  throw new Error(`never appeared: ${path}`);
}

before(async () => {
  if (SKIP) return;
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-goose-acp-")));
  work = join(tmp, "work");
  mkdirSync(join(work, "vault"), { recursive: true });
  secretFile = join(work, "vault", "api.env");
  writeFileSync(secretFile, `ACME_API_KEY=sk-live-${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(work, "vault")}\n    level: no-model\n`);
  const logFd = openSync(join(tmp, "arbiter.log"), "a");
  arbiter = spawn(ARBITER_TSX, [ARBITER_MAIN, join(tmp, "arbiter.sock")], {
    cwd: ARBITER_DIR,
    env: { ...process.env, HOME: tmp, MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_HOME: join(tmp, "mandu-home"), MANDU_RUNTIME_DIR: join(tmp, "mandu"), MANDU_POLICY_FILE: policy },
    stdio: ["ignore", logFd, logFd], detached: true,
  });
  closeSync(logFd);
  await waitFor(join(tmp, "arbiter.sock"), 20_000);
  upstream = createHttpServer(scripted);
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
  upstreamOrigin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(async () => {
  upstream?.close();
  if (arbiter) await stopGroup(arbiter);
  if (!tmp) return;
  if (passed < 4) {
    try { console.error(`goose-acp-real: arbiter log tail:\n${readFileSync(join(tmp, "arbiter.log"), "utf8").split("\n").slice(-30).join("\n")}`); } catch { /* none */ }
  }
  rmSync(tmp, { recursive: true, force: true });
});

/** The launch env: a throwaway Goose home and a key; no kernel layer (the
 *  model-context chokepoint and the relay are what is under test). The reply
 *  filter is left at its default: the launch must turn it off itself. */
function launchEnv(home: string): Record<string, string> {
  const env: Record<string, string> = {
    HOME: tmp, PATH: process.env["PATH"]!, PWD: work,
    MANDU_HOME: PRIVATE_MANDU_HOME, XDG_RUNTIME_DIR: tmp,
    MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_PROXY_PORT: "0", MANDU_MODE: "secrets",
    MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0",
    MANDU_UPSTREAM: upstreamOrigin, MANDU_AXES_STRICT: "1", MANDU_POLICY_FILE: "/dev/null/mandu-test-no-policy.yaml",
    GOOSE_PATH_ROOT: home, GOOSE_DISABLE_KEYRING: "1", GOOSE_MODE: "auto", GOOSE_MODEL: MODEL,
    ANTHROPIC_API_KEY: "sk-ant-mandu-test",
  };
  if (process.env["MANDU_RUNTIME_DIR"]) env["MANDU_RUNTIME_DIR"] = process.env["MANDU_RUNTIME_DIR"];
  return env;
}

interface Rpc { jsonrpc?: string; id?: unknown; method?: string; params?: Record<string, unknown>; result?: Record<string, unknown>; error?: { code: number; message: string } }

/** A scripted ACP client over the launcher's stdio. */
class Editor {
  readonly lines: string[] = [];
  readonly fromAgent: Rpc[] = [];
  readonly stderr: string[] = [];
  private buf = "";
  private nextId = 0;
  private waiting = new Map<number, (m: Rpc) => void>();
  readonly exited: Promise<number | null>;
  constructor(readonly child: ChildProcess) {
    child.stdout!.setEncoding("utf8");
    child.stdout!.on("data", (c: string) => {
      this.buf += c;
      let nl: number;
      while ((nl = this.buf.indexOf("\n")) >= 0) {
        const line = this.buf.slice(0, nl);
        this.buf = this.buf.slice(nl + 1);
        this.onLine(line);
      }
    });
    child.stderr!.setEncoding("utf8");
    child.stderr!.on("data", (c: string) => this.stderr.push(c));
    this.exited = new Promise((r) => child.on("exit", (code) => r(code)));
  }
  private onLine(line: string): void {
    this.lines.push(line);
    let m: Rpc;
    try { m = JSON.parse(line) as Rpc; } catch { return; } // asserted below: every line parses
    this.fromAgent.push(m);
    if (m.method === undefined && typeof m.id === "number" && this.waiting.has(m.id)) {
      this.waiting.get(m.id)!(m);
      this.waiting.delete(m.id);
    } else if (m.method !== undefined && m.id !== undefined) {
      // A request from the agent: grant a permission; anything else, an
      // editor that offers its fs / terminal would serve (this one records it).
      const result = m.method === "session/request_permission"
        ? { outcome: { outcome: "selected", optionId: (m.params?.["options"] as Array<{ optionId: string }> | undefined)?.[0]?.optionId } }
        : {};
      this.child.stdin!.write(`${JSON.stringify({ jsonrpc: "2.0", id: m.id, result })}\n`);
    }
  }
  request(method: string, params: Record<string, unknown>, ms = 120_000): Promise<Rpc> {
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`no answer to ${method} in ${ms} ms; stderr: ${this.stderr.join("").slice(-2000)}`)), ms);
      this.waiting.set(id, (m) => { clearTimeout(t); resolve(m); });
      this.child.stdin!.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  }
}

test("CONTROL (no Mandu): bare `goose acp` runs `shell` through the editor's terminal when the editor offers one, so the relay's refusal of it is what keeps tools in the wrap", { skip: SKIP, timeout: 120_000 }, async () => {
  reqs.length = 0;
  const child = spawn(GOOSE!, ["acp"], {
    cwd: work, stdio: ["pipe", "pipe", "pipe"],
    env: { PATH: process.env["PATH"]!, HOME: tmp, GOOSE_PATH_ROOT: join(tmp, "goose-control"), GOOSE_DISABLE_KEYRING: "1", GOOSE_MODE: "auto", GOOSE_MODEL: MODEL, GOOSE_PROVIDER: "anthropic", ANTHROPIC_HOST: upstreamOrigin, ANTHROPIC_API_KEY: "sk-ant-mandu-test", GOOSE_TELEMETRY_OFF: "1" },
  });
  const ed = new Editor(child);
  try {
    await ed.request("initialize", { protocolVersion: 1, clientCapabilities: { fs: { readTextFile: true, writeTextFile: true }, terminal: true } });
    const created = await ed.request("session/new", { cwd: work, mcpServers: [] });
    await ed.request("session/prompt", { sessionId: created.result?.["sessionId"], prompt: [{ type: "text", text: "Read vault/api.env." }] });
    const asked = ed.fromAgent.filter((m) => m.method !== undefined && /^terminal\//.test(m.method)).map((m) => m.method);
    assert.ok(asked.includes("terminal/create"), `without the relay Goose asked the editor's terminal: ${asked.join(",")}`);
    const tools = (reqs.find((q) => Array.isArray(q.body?.["tools"]) && (q.body!["tools"] as unknown[]).length > 0)?.body?.["tools"] as Array<{ name: string }>).map((t) => t.name);
    assert.ok(tools.includes("read"), `and advertised the editor-backed read tool: ${tools.join(",")}`);
  } finally {
    child.stdin!.end();
    const t = setTimeout(() => child.kill("SIGKILL"), 20_000);
    await ed.exited;
    clearTimeout(t);
  }
});

test("`mandu goose acp`: a clean JSON-RPC stream, every tool run in Goose, the turn through the proxy, the labelled file only as a symbol, a provider switch and `_goose/*` refused", { skip: SKIP, timeout: 240_000 }, async () => {
  reqs.length = 0;
  // run from the workspace, as an editor starts it there (the launch's
  // secret discovery walks the working directory); tsx by its path, since
  // `--import tsx` resolves from the working directory
  const tsxLoader = pathToFileURL(join(LAUNCHER_ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;
  const child = spawn(process.execPath, ["--import", tsxLoader, join(LAUNCHER_ROOT, "src", "run.ts"), "--no-scope", "--", GOOSE!, "acp"], {
    cwd: work, env: launchEnv(join(tmp, "goose-acp")), stdio: ["pipe", "pipe", "pipe"],
  });
  const ed = new Editor(child);
  try {
    // An editor offers its file system and terminal.
    const init = await ed.request("initialize", { protocolVersion: 1, clientCapabilities: { fs: { readTextFile: true, writeTextFile: true }, terminal: true }, clientInfo: { name: "mandu-test-editor", version: "0" } });
    assert.equal((init.result?.["agentInfo"] as { name?: string } | undefined)?.name, "goose", JSON.stringify(init));
    const created = await ed.request("session/new", { cwd: work, mcpServers: [] });
    const sessionId = created.result?.["sessionId"] as string;
    assert.ok(sessionId, JSON.stringify(created));
    const provider = (created.result?.["configOptions"] as Array<{ id: string; currentValue: string }>).find((o) => o.id === "provider");
    assert.equal(provider?.currentValue, "anthropic", "the session runs the routed provider");

    // A provider switch (the editor's picker) is refused; so is the desktop's surface.
    const sw = await ed.request("session/set_config_option", { sessionId, configId: "provider", value: "openai" });
    assert.ok(sw.error, `refused: ${JSON.stringify(sw)}`);
    assert.match(sw.error!.message, /routes only Goose's anthropic provider through Mandu's model proxy/);
    const desk = await ed.request("_goose/config/read", { key: "GOOSE_PROVIDER" });
    assert.equal(desk.error?.code, -32601, JSON.stringify(desk));

    const before = reqs.length;
    const turn = await ed.request("session/prompt", { sessionId, prompt: [{ type: "text", text: "Read vault/api.env and summarize it." }] });
    assert.equal(turn.result?.["stopReason"], "end_turn", JSON.stringify(turn));

    // the stream: every line parses
    for (const l of ed.lines) assert.doesNotThrow(() => JSON.parse(l), `a line the editor read is not JSON: ${l.slice(0, 200)}`);
    assert.ok(ed.lines.length > 5, "the editor read Goose's updates");
    // tools ran in Goose: the editor was never asked for its terminal or file system
    const asked = ed.fromAgent.filter((m) => m.method !== undefined && /^(fs|terminal)\//.test(m.method));
    assert.deepEqual(asked.map((m) => m.method), [], "no fs/* or terminal/* request reached the editor");
    const text = ed.fromAgent.filter((m) => m.method === "session/update" && (m.params?.["update"] as { sessionUpdate?: string })?.sessionUpdate === "agent_message_chunk");
    assert.ok(JSON.stringify(text).includes("MANDU_GOOSE_ACP_DONE"), "the reply reached the editor");

    // routing: through the proxy, with the captured surface and Mandu's tools
    const turnReqs = reqs.slice(before).filter((q) => q.method === "POST");
    for (const q of reqs) assert.match(q.path, /\/v1\/(messages|models)/);
    const tooled = turnReqs.filter((q) => Array.isArray(q.body?.["tools"]) && (q.body!["tools"] as unknown[]).length > 0);
    assert.ok(tooled.length >= 2, `the turn's model calls went through the proxy (${turnReqs.length})`);
    const names = (tooled[0]!.body!["tools"] as Array<{ name: string }>).map((t) => t.name);
    assert.ok(names.includes("shell") && !names.includes("read"), `Goose's own surface, no editor-backed read: ${names.join(",")}`);
    assert.ok(names.includes("mandu-inspect__inspect_symbol"), `the U-LLM is mounted per session: ${names.join(",")}`);
    const last = JSON.stringify(tooled.at(-1)!.body);
    assert.ok(last.includes("tool_result"), "the shell result came back through the proxy");
    assert.match(last, /\$MDU:/, "the labelled file reached the model as a symbol");
    for (const q of reqs) assert.ok(!q.raw.includes(CANARY), `INVARIANT: the labelled value never reaches the model raw (${q.method} ${q.path})`);
    assert.ok(ed.stderr.join("").includes("Mandu's ACP relay"), "the launcher says so on stderr");

    // A loaded session: its provider comes from Goose's answer, then it prompts.
    const loaded = await ed.request("session/load", { sessionId, cwd: work, mcpServers: [] });
    assert.ok(loaded.result, JSON.stringify(loaded));
    const again = await ed.request("session/prompt", { sessionId, prompt: [{ type: "text", text: "Thanks." }] });
    assert.equal(again.result?.["stopReason"], "end_turn", `a loaded session on the routed provider prompts: ${JSON.stringify(again)}`);
    for (const l of ed.lines) assert.doesNotThrow(() => JSON.parse(l), `a line the editor read is not JSON: ${l.slice(0, 200)}`);
    for (const q of reqs) assert.ok(!q.raw.includes(CANARY), "INVARIANT: still never raw after the load");
  } finally {
    child.stdin!.end();
    const t = setTimeout(() => child.kill("SIGKILL"), 30_000);
    await ed.exited;
    clearTimeout(t);
  }
  passed++;
});

/** The text of the editor's `agent_message_chunk`s, joined. */
function replyText(ed: Editor, from = 0): string {
  return ed.fromAgent.slice(from)
    .filter((m) => m.method === "session/update" && (m.params?.["update"] as { sessionUpdate?: string })?.sessionUpdate === "agent_message_chunk")
    .map((m) => ((m.params!["update"] as { content?: { text?: string } }).content?.text ?? ""))
    .join("");
}

async function acpSession(extra: string[], home: string): Promise<{ ed: Editor; sessionId: string; stop: () => Promise<void> }> {
  const tsxLoader = pathToFileURL(join(LAUNCHER_ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;
  const child = spawn(process.execPath, ["--import", tsxLoader, join(LAUNCHER_ROOT, "src", "run.ts"), "--no-scope", ...extra, "--", GOOSE!, "acp"], {
    cwd: work, env: launchEnv(join(tmp, home)), stdio: ["pipe", "pipe", "pipe"],
  });
  const ed = new Editor(child);
  await ed.request("initialize", { protocolVersion: 1, clientCapabilities: { fs: { readTextFile: true, writeTextFile: true }, terminal: true } });
  const created = await ed.request("session/new", { cwd: work, mcpServers: [] });
  const sessionId = created.result?.["sessionId"] as string;
  assert.ok(sessionId, JSON.stringify(created));
  return {
    ed, sessionId,
    stop: async () => {
      child.stdin!.end();
      const t = setTimeout(() => child.kill("SIGKILL"), 30_000);
      await ed.exited;
      clearTimeout(t);
    },
  };
}

test("`mandu goose acp` display: the model's reply carries the symbol, the editor reads the original; echoing it back reaches the model only as the symbol", { skip: SKIP, timeout: 240_000 }, async () => {
  reqs.length = 0;
  const { ed, sessionId, stop } = await acpSession([], "goose-acp-display");
  try {
    const turn = await ed.request("session/prompt", { sessionId, prompt: [{ type: "text", text: "Read vault/api.env and summarize it." }] });
    assert.equal(turn.result?.["stopReason"], "end_turn", JSON.stringify(turn));
    // the model's side: the reply it wrote quotes a symbol, never the value
    const closing = reqs.filter((q) => q.method === "POST" && q.raw.includes("tool_result"));
    assert.ok(closing.length >= 1, "the shell result came back through the proxy");
    assert.match(closing.at(-1)!.raw, /\$MDU:/, "the model read the labelled file as a symbol");
    for (const q of reqs) assert.ok(!q.raw.includes(CANARY), `INVARIANT: never raw toward the model (${q.method} ${q.path})`);
    // the editor's side: the reply resolved, the framing intact
    const shown = replyText(ed);
    assert.ok(shown.includes("MANDU_GOOSE_ACP_DONE"), `the reply reached the editor: ${shown}`);
    assert.ok(shown.includes(CANARY), `the editor reads the ORIGINAL where the model wrote the symbol: ${shown}`);
    assert.ok(!shown.includes("$MDU:"), `no symbol left in the editor's reply text: ${shown}`);
    for (const l of ed.lines) assert.doesNotThrow(() => JSON.parse(l), `a line the editor read is not JSON: ${l.slice(0, 200)}`);

    // FLOW-BACK: the editor quotes what it was shown into the next prompt
    // (a human's paste, an editor's "add to thread"). The relay passes the
    // editor's lines as they are; the proxy's prompt filter masks the
    // registered value, so the model still reads only the symbol.
    const before = reqs.length;
    const echo = await ed.request("session/prompt", { sessionId, prompt: [{ type: "text", text: `You said: ${shown}. Again?` }] });
    assert.equal(echo.result?.["stopReason"], "end_turn", JSON.stringify(echo));
    const echoed = reqs.slice(before).filter((q) => q.method === "POST");
    assert.ok(echoed.length >= 1, "the echo turn reached the model through the proxy");
    for (const q of reqs) assert.ok(!q.raw.includes(CANARY), `INVARIANT: the editor's echo of an original reaches the model only as a symbol (${q.method} ${q.path})`);
    assert.ok(echoed.some((q) => q.raw.includes("You said: MANDU_GOOSE_ACP_DONE")), "the echo is the turn the model read");

    // A load replays the history: the editor reads originals again, the
    // human's own turns as Goose holds them.
    const from = ed.fromAgent.length;
    const loaded = await ed.request("session/load", { sessionId, cwd: work, mcpServers: [] });
    assert.ok(loaded.result, JSON.stringify(loaded));
    assert.ok(replyText(ed, from).includes(CANARY), "the replay shows the original");
  } finally {
    await stop();
  }
  passed++;
});

test("`mandu --no-reply-filter goose acp`: the display pass is off with the filter, the editor reads the symbol", { skip: SKIP, timeout: 240_000 }, async () => {
  reqs.length = 0;
  const { ed, sessionId, stop } = await acpSession(["--no-reply-filter"], "goose-acp-nofilter");
  try {
    const turn = await ed.request("session/prompt", { sessionId, prompt: [{ type: "text", text: "Read vault/api.env and summarize it." }] });
    assert.equal(turn.result?.["stopReason"], "end_turn", JSON.stringify(turn));
    const shown = replyText(ed);
    assert.match(shown, /MANDU_GOOSE_ACP_DONE \$MDU:/, `the symbol as the model wrote it: ${shown}`);
    assert.ok(!shown.includes(CANARY));
    assert.ok(ed.stderr.join("").includes("the editor sees Goose's symbols"), ed.stderr.join(""));
    for (const q of reqs) assert.ok(!q.raw.includes(CANARY), "INVARIANT: never raw toward the model");
  } finally {
    await stop();
  }
  passed++;
});

test("`mandu goose acp --enable-scheduler`: refused before anything starts", { skip: SKIP, timeout: 60_000 }, async () => {
  reqs.length = 0;
  const env = launchEnv(join(tmp, "goose-acp-refused"));
  await assert.rejects(() => main(["--no-scope", "--", GOOSE!, "acp", "--enable-scheduler"], env), /--enable-scheduler runs scheduled recipes/);
  assert.equal(reqs.length, 0, "nothing reached the upstream");
  passed++;
});
