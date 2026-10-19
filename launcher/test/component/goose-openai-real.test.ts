/**
 * goose-openai-real.test — the REAL goose binary on its built-in `openai`
 * provider under the REAL launcher (`main()`), the REAL arbiter daemon and the
 * autostarted model proxy, against a scripted OpenAI-wire upstream on
 * loopback (supported-agents.md §5.6, "The openai provider"). No key is spent:
 * the upstream is this process. Needs a goose binary: MANDU_GOOSE_BIN, else
 * `goose` on PATH (the CI guest pins 1.53.0, scripts/ci/pins.env); without one
 * the suite SKIPS with that reason, never a green.
 *
 *   routing   `mandu goose run` with GOOSE_PROVIDER=openai and the user's own
 *             OPENAI_HOST: every model request reaches the upstream THROUGH
 *             the proxy (the launcher pins OPENAI_HOST at the proxy's
 *             /_mandu/openai/openai route and hands the proxy the user's
 *             host), on the wire Goose picks per model: Chat Completions for
 *             gpt-4o, the Responses API for gpt-5;
 *   invariant (SECURITY) the scripted model asks for `cat` of a labelled
 *             (no-model) file: the shell runs, and its output reaches the
 *             upstream ONLY as a `$MDU:` symbol; no request carries the value;
 *   refused   GOOSE_PROVIDER naming a provider Mandu does not route (google),
 *             openai at an endpoint the proxy cannot reach (plain http off
 *             this machine), or openai beside anthropic subagents at the
 *             user's own undeclared ANTHROPIC_HOST (which skips the proxy):
 *             the launch is refused, goose never starts and the upstream
 *             sees nothing.
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
import { fileURLToPath } from "node:url";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../axes.js";
import { stopGroup } from "../lib/tmp-dir.js";

stateAxes("secrets"); // the shipped default mode: the labelled file must reach the model only as a symbol

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
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

const CANARY = "GOOSE-OAI-REAL-CANARY-4417";
const SECRET_BODY = `ACME_API_KEY=sk-live-${CANARY}\n`;
const SYMBOL_RE = /\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]+\]/;

let tmp: string;
let vault: string;
let arbiter: ChildProcess | undefined;
let upstream: Server;
let origin = "";
const seen: Array<{ method: string; path: string; auth: string; body: string }> = [];
let passed = 0;

// ── the scripted OpenAI-wire model (Goose 1.53.0's stream readers) ─────────

const chatChunk = (model: string, delta: unknown, finish: string | null = null): string =>
  `data: ${JSON.stringify({ id: "chatcmpl-1", object: "chat.completion.chunk", created: 1, model, choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
const chatText = (model: string, t: string): string =>
  chatChunk(model, { role: "assistant", content: "" }) + chatChunk(model, { content: t }) + chatChunk(model, {}, "stop") + "data: [DONE]\n\n";
const chatShell = (model: string, command: string): string => {
  const args = JSON.stringify({ command });
  return chatChunk(model, { role: "assistant", content: null, tool_calls: [{ index: 0, id: "call_cat", type: "function", function: { name: "shell", arguments: args.slice(0, 8) } }] }) +
    chatChunk(model, { tool_calls: [{ index: 0, function: { arguments: args.slice(8) } }] }) + chatChunk(model, {}, "tool_calls") + "data: [DONE]\n\n";
};
let seq = 0;
const ev = (type: string, o: Record<string, unknown>): string => `event: ${type}\ndata: ${JSON.stringify({ type, sequence_number: ++seq, ...o })}\n\n`;
const meta = (model: string, status: string, output: unknown[]): Record<string, unknown> => ({ id: "resp_1", object: "response", created_at: 1, status, model, output });
const respText = (model: string, t: string): string => {
  const item = { id: "msg_1", type: "message", status: "completed", role: "assistant", content: [{ type: "output_text", text: t, annotations: [] }] };
  return ev("response.created", { response: meta(model, "in_progress", []) }) +
    ev("response.output_item.added", { output_index: 0, item: { ...item, status: "in_progress", content: [] } }) +
    ev("response.content_part.added", { item_id: "msg_1", output_index: 0, content_index: 0, part: { type: "output_text", text: "", annotations: [] } }) +
    ev("response.output_text.delta", { item_id: "msg_1", output_index: 0, content_index: 0, delta: t }) +
    ev("response.output_text.done", { item_id: "msg_1", output_index: 0, content_index: 0, text: t }) +
    ev("response.content_part.done", { item_id: "msg_1", output_index: 0, content_index: 0, part: { type: "output_text", text: t, annotations: [] } }) +
    ev("response.output_item.done", { output_index: 0, item }) +
    ev("response.completed", { response: meta(model, "completed", [item]) });
};
const respShell = (model: string, command: string): string => {
  const args = JSON.stringify({ command });
  const item = { id: "fc_1", type: "function_call", status: "completed", call_id: "call_cat", name: "shell", arguments: args };
  return ev("response.created", { response: meta(model, "in_progress", []) }) +
    ev("response.output_item.added", { output_index: 0, item: { ...item, status: "in_progress", arguments: "" } }) +
    ev("response.function_call_arguments.delta", { item_id: "fc_1", output_index: 0, delta: args.slice(0, 8) }) +
    ev("response.function_call_arguments.delta", { item_id: "fc_1", output_index: 0, delta: args.slice(8) }) +
    ev("response.function_call_arguments.done", { item_id: "fc_1", output_index: 0, arguments: args }) +
    ev("response.output_item.done", { output_index: 0, item }) +
    ev("response.completed", { response: meta(model, "completed", [item]) });
};

/** One agentic turn on either wire: the first tool-bearing request gets a
 *  `cat` of the labelled file, the request carrying its result the closing
 *  text; a tool-less request (Goose's title call) a title. */
function scripted(req: IncomingMessage, res: ServerResponse): void {
  let buf = "";
  req.setEncoding("utf8");
  req.on("data", (c) => (buf += c));
  req.on("end", () => {
    const path = req.url ?? "";
    seen.push({ method: req.method ?? "", path, auth: String(req.headers["authorization"] ?? ""), body: buf });
    let body: Record<string, unknown> = {};
    try { body = JSON.parse(buf) as Record<string, unknown>; } catch { /* a GET */ }
    const model = typeof body["model"] === "string" ? body["model"] : "m";
    const tools = Array.isArray(body["tools"]) ? body["tools"] : [];
    const cat = `cat ${join(vault, "api.env")}`;
    if (req.method === "GET" && /\/models$/.test(path)) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ object: "list", data: [{ id: model, object: "model" }] }));
    } else if (/\/chat\/completions$/.test(path)) {
      const hasResult = ((body["messages"] as Array<{ role?: string }> | undefined) ?? []).some((m) => m.role === "tool");
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(tools.length === 0 ? chatText(model, "Title") : hasResult ? chatText(model, "MANDU_OAI_DONE") : chatShell(model, cat));
    } else if (/\/responses$/.test(path)) {
      const hasResult = ((body["input"] as Array<{ type?: string }> | undefined) ?? []).some((i) => i.type === "function_call_output");
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(tools.length === 0 ? respText(model, "Title") : hasResult ? respText(model, "MANDU_OAI_DONE") : respShell(model, cat));
    } else {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "not scripted" } }));
    }
  });
}

async function waitFor(path: string, ms: number): Promise<void> {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (existsSync(path)) return; await new Promise((r) => setTimeout(r, 50)); }
  throw new Error(`never appeared: ${path}`);
}

before(async () => {
  if (SKIP) return;
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-goose-oai-")));
  mkdirSync(join(tmp, "work"));
  vault = join(tmp, "vault");
  mkdirSync(vault);
  writeFileSync(join(vault, "api.env"), SECRET_BODY);
  // The arbiter labels the vault no-model: what the shell reads there must
  // reach any model only as a symbol.
  writeFileSync(join(tmp, "policy.yaml"), `version: 1\npaths:\n  - path: ${vault}\n    level: no-model\n`);
  const logFd = openSync(join(tmp, "arbiter.log"), "a");
  arbiter = spawn(ARBITER_TSX, [ARBITER_MAIN, join(tmp, "arbiter.sock")], {
    cwd: ARBITER_DIR,
    env: { ...process.env, MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_HOME: join(tmp, "mandu-home"), MANDU_RUNTIME_DIR: join(tmp, "mandu"), MANDU_POLICY_FILE: join(tmp, "policy.yaml") },
    stdio: ["ignore", logFd, logFd], detached: true,
  });
  closeSync(logFd);
  await waitFor(join(tmp, "arbiter.sock"), 20_000);
  upstream = createHttpServer(scripted);
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
  origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(async () => {
  upstream?.close();
  if (arbiter) await stopGroup(arbiter);
  if (!tmp) return;
  if (passed < 3) {
    try { console.error(`goose-openai-real: arbiter log tail:\n${readFileSync(join(tmp, "arbiter.log"), "utf8").split("\n").slice(-30).join("\n")}`); } catch { /* none */ }
  }
  rmSync(tmp, { recursive: true, force: true });
});

/** The user's env: a throwaway Goose home on its openai provider at the
 *  user's own OpenAI-compatible host (the scripted upstream). */
function userEnv(name: string, extra: Record<string, string>): Record<string, string | undefined> {
  return {
    HOME: tmp, PATH: process.env["PATH"], PWD: join(tmp, "work"),
    MANDU_HOME: PRIVATE_MANDU_HOME, XDG_RUNTIME_DIR: tmp, MANDU_RUNTIME_DIR: join(tmp, "mandu-launch"),
    MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_PROXY_PORT: "0", MANDU_MODE: "secrets",
    MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0",
    GOOSE_PATH_ROOT: join(tmp, `goose-${name}`), GOOSE_DISABLE_KEYRING: "1", GOOSE_MODE: "auto",
    GOOSE_PROVIDER: "openai", OPENAI_API_KEY: "sk-mandu-test-not-a-key", OPENAI_HOST: origin,
    ...extra,
  };
}

for (const [model, wire] of [["gpt-4o", "/v1/chat/completions"], ["gpt-5", "/v1/responses"]] as const) {
  test(`\`mandu goose run\` on openai ${model}: every request through the proxy on ${wire}, the labelled file's content reaches the model ONLY as a symbol`, { skip: SKIP, timeout: 180_000 }, async () => {
    seen.length = 0;
    mkdirSync(join(tmp, "mandu-launch"), { recursive: true, mode: 0o700 });
    const code = await main(["--no-scope", "--", GOOSE!, "run", "--no-session", "-t", "check the api key file"], userEnv(model, { GOOSE_MODEL: model }));
    assert.equal(code, 0, "goose under Mandu exited 0");
    const posts = seen.filter((q) => q.method === "POST");
    assert.ok(posts.length >= 2, `the proxy forwarded Goose's turns (${seen.map((q) => `${q.method} ${q.path}`).join(", ")})`);
    for (const q of posts) assert.equal(q.path, wire, `Goose's own wire choice kept for ${model}`);
    for (const q of seen) assert.equal(q.auth, "Bearer sk-mandu-test-not-a-key", "the user's own key is relayed");
    const withResult = posts.filter((q) => q.body.includes("call_cat") && (q.body.includes('"role":"tool"') || q.body.includes("function_call_output")));
    assert.ok(withResult.length >= 1, "the shell ran and its result came back through the proxy");
    assert.match(withResult.at(-1)!.body, SYMBOL_RE, "the result reached the model as a symbol");
    for (const q of seen) assert.ok(!q.body.includes(CANARY), `INVARIANT: no request carries the labelled secret (${q.path})`);
    passed++;
  });
}

test("refused before goose starts: a provider Mandu does not route, openai at an endpoint the proxy cannot reach, openai where the proxy would be skipped", { skip: SKIP, timeout: 60_000 }, async () => {
  seen.length = 0;
  for (const [extra, re] of [
    [{ GOOSE_PROVIDER: "google", GOOSE_MODEL: "gemini-2.5-pro" }, /GOOSE_PROVIDER names the provider `google`/],
    [{ OPENAI_HOST: "http://llm.corp.example:8000", GOOSE_MODEL: "gpt-4o" }, /OPENAI_HOST \(`http:\/\/llm\.corp\.example:8000`\) is not an endpoint/],
    // the subagents on anthropic at the user's own undeclared host: that
    // override skips the proxy the openai route needs
    [{ GOOSE_MODEL: "gpt-4o", GOOSE_SUBAGENT_PROVIDER: "anthropic", ANTHROPIC_HOST: "https://gw.corp.example" }, /your ANTHROPIC_HOST \(https:\/\/gw\.corp\.example\).*skips that proxy/],
  ] as Array<[Record<string, string>, RegExp]>) {
    let err: unknown;
    try { await main(["--no-scope", "--", GOOSE!, "run", "--no-session", "-t", "hi"], userEnv("refused", extra)); } catch (e) { err = e; }
    assert.match(String(err), re);
    assert.match(String(err), /^Error: mandu: refusing to launch goose: /);
  }
  assert.equal(existsSync(join(tmp, "goose-refused")), false, "goose never started (it would have created its home)");
  assert.equal(seen.length, 0, "nothing reached the upstream");
  passed++;
});
