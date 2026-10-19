/**
 * goose-compat-real.test — the REAL goose binary on each of its built-in
 * Chat Completions providers with an env host (litellm, openrouter, ollama,
 * xai, tetrate) under the REAL launcher (`main()`), the REAL arbiter daemon
 * and the autostarted model proxy, against a scripted Chat Completions
 * upstream on loopback (supported-agents.md §5.6.4). No key is spent and no
 * provider is dialed: every provider's host key in the user's env points at
 * the upstream, which is this process. Needs a goose binary: MANDU_GOOSE_BIN,
 * else `goose` on PATH (the CI guest pins 1.53.0, scripts/ci/pins.env);
 * without one the suite SKIPS with that reason, never a green.
 *
 *   routing   `mandu goose run` with GOOSE_PROVIDER=<provider> and the
 *             user's own host: every model request reaches the upstream
 *             THROUGH the proxy (the launcher pins the provider's host key at
 *             the proxy's /_mandu/openai/<provider> route and hands the proxy
 *             the user's host), on Goose's own path for that provider;
 *   invariant (SECURITY) the scripted model asks for `cat` of a labelled
 *             (no-model) file: the shell runs, and its output reaches the
 *             upstream ONLY as a `$MDU:` symbol; no request carries the value;
 *   text call (SECURITY) on ollama, the scripted model WRITES a shell call in
 *             its text (`<function=shell><parameter=command>…`), which
 *             Goose's ollama reader runs as a tool call: under Mandu the
 *             command never runs (the proxy ends that response); the control,
 *             the same goose without Mandu against the same upstream, does
 *             run it, so the probe is real;
 *   refused   ollama at a host the proxy cannot reach (plain http to another
 *             machine) and litellm on a base path that is not Chat
 *             Completions: the launch is refused, goose never starts and the
 *             upstream sees nothing.
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
import { GOOSE_COMPAT_PROVIDERS } from "../../src/goose-route.js";
import { stateAxes } from "../axes.js";
import { stopGroup } from "../lib/tmp-dir.js";
import { sourceArbiterArgs, waitForPaths } from "../lib/arbiter-ready.js";

stateAxes("secrets"); // the shipped default mode: the labelled file must reach the model only as a symbol

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const ARBITER_DIR = join(REPO_ROOT, "arbiter");

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

const CANARY = "GOOSE-COMPAT-REAL-CANARY-6620";
const SECRET_BODY = `ACME_API_KEY=sk-live-${CANARY}\n`;
const SYMBOL_RE = /\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]+\]/;
const TEXT_CALL_PROMPT = "MDU-TEXT-CALL-PROMPT-2291";

let tmp: string;
let vault: string;
let arbiter: ChildProcess | undefined;
let upstream: Server;
let origin = "";
const seen: Array<{ method: string; path: string; auth: string; body: string }> = [];
let passed = 0;

// ── the scripted Chat Completions model (Goose 1.53.0's stream reader) ─────

const chatChunk = (model: string, delta: unknown, finish: string | null = null): string =>
  `data: ${JSON.stringify({ id: "chatcmpl-1", object: "chat.completion.chunk", created: 1, model, choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
const chatText = (model: string, t: string): string =>
  chatChunk(model, { role: "assistant", content: "" }) + chatChunk(model, { content: t }) + chatChunk(model, {}, "stop") + "data: [DONE]\n\n";
const chatShell = (model: string, command: string): string => {
  const args = JSON.stringify({ command });
  return chatChunk(model, { role: "assistant", content: null, tool_calls: [{ index: 0, id: "call_cat", type: "function", function: { name: "shell", arguments: args.slice(0, 8) } }] }) +
    chatChunk(model, { tool_calls: [{ index: 0, function: { arguments: args.slice(8) } }] }) + chatChunk(model, {}, "tool_calls") + "data: [DONE]\n\n";
};

/** One agentic turn: the first tool-bearing request gets a `cat` of the
 *  labelled file, the request carrying its result the closing text; a
 *  tool-less request (Goose's title call) a title. A GET (a model listing:
 *  `models`, `api/v1/models`, LiteLLM's `model/info`, Ollama's `api/tags`)
 *  gets an empty list. */
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
    const textCall = buf.includes(TEXT_CALL_PROMPT) && !((body["messages"] as Array<{ role?: string }> | undefined) ?? []).some((m) => m.role === "tool");
    if (req.method === "GET") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ object: "list", data: [], models: [] }));
    } else if (/\/chat\/completions$/.test(path) && textCall && tools.length > 0) {
      // the call as TEXT, split across deltas the way a model streams it
      const xml = `<function=shell><parameter=command>touch ${join(tmp, "text-call-ran")}</parameter></function>`;
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(chatChunk(model, { role: "assistant", content: "" }) + chatChunk(model, { content: "Running it. <func" }) +
        chatChunk(model, { content: xml.slice(5) }) + chatChunk(model, {}, "stop") + "data: [DONE]\n\n");
    } else if (/\/chat\/completions$/.test(path)) {
      const hasResult = ((body["messages"] as Array<{ role?: string }> | undefined) ?? []).some((m) => m.role === "tool");
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(tools.length === 0 ? chatText(model, "Title") : hasResult ? chatText(model, "MANDU_COMPAT_DONE") : chatShell(model, `cat ${join(vault, "api.env")}`));
    } else {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "not scripted" } }));
    }
  });
}

before(async () => {
  if (SKIP) return;
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-goose-compat-")));
  mkdirSync(join(tmp, "work"));
  vault = join(tmp, "vault");
  mkdirSync(vault);
  writeFileSync(join(vault, "api.env"), SECRET_BODY);
  writeFileSync(join(tmp, "policy.yaml"), `version: 1\npaths:\n  - path: ${vault}\n    level: no-model\n`);
  const logFd = openSync(join(tmp, "arbiter.log"), "a");
  arbiter = spawn(process.execPath, sourceArbiterArgs(join(tmp, "arbiter.sock")), {
    cwd: ARBITER_DIR,
    env: { ...process.env, MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_HOME: join(tmp, "mandu-home"), MANDU_RUNTIME_DIR: join(tmp, "mandu"), MANDU_POLICY_FILE: join(tmp, "policy.yaml") },
    stdio: ["ignore", logFd, logFd], detached: true,
  });
  closeSync(logFd);
  await waitForPaths(join(tmp, "arbiter.sock"), { what: "the arbiter", child: arbiter, logPath: join(tmp, "arbiter.log") });
  upstream = createHttpServer(scripted);
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
  origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(async () => {
  upstream?.close();
  if (arbiter) await stopGroup(arbiter);
  if (!tmp) return;
  if (passed < GOOSE_COMPAT_PROVIDERS.length + 2) {
    try { console.error(`goose-compat-real: arbiter log tail:\n${readFileSync(join(tmp, "arbiter.log"), "utf8").split("\n").slice(-30).join("\n")}`); } catch { /* none */ }
  }
  rmSync(tmp, { recursive: true, force: true });
});

/** The user's env: a throwaway Goose home on `provider`, with EVERY
 *  provider's host key at the scripted upstream (xAI's default host carries
 *  `/v1`, so the user's does too), so nothing could reach a real provider
 *  even if a key went unpinned. */
function userEnv(name: string, provider: string, extra: Record<string, string> = {}): Record<string, string | undefined> {
  return {
    HOME: tmp, PATH: process.env["PATH"], PWD: join(tmp, "work"),
    MANDU_HOME: PRIVATE_MANDU_HOME, XDG_RUNTIME_DIR: tmp, MANDU_RUNTIME_DIR: join(tmp, "mandu-launch"),
    MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_PROXY_PORT: "0", MANDU_MODE: "secrets",
    MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0",
    GOOSE_PATH_ROOT: join(tmp, `goose-${name}`), GOOSE_DISABLE_KEYRING: "1", GOOSE_MODE: "auto",
    GOOSE_PROVIDER: provider, GOOSE_MODEL: "mandu-test-model",
    LITELLM_HOST: origin, OPENROUTER_HOST: origin, OLLAMA_HOST: origin, XAI_HOST: `${origin}/v1`, TETRATE_HOST: origin,
    OPENAI_HOST: origin,
    LITELLM_API_KEY: "sk-mandu-test-not-a-key", OPENROUTER_API_KEY: "sk-mandu-test-not-a-key",
    XAI_API_KEY: "sk-mandu-test-not-a-key", TETRATE_API_KEY: "sk-mandu-test-not-a-key",
    ...extra,
  };
}

/** Goose's chat path under the user's host, per provider. */
const WIRE: Record<string, string> = {
  litellm: "/v1/chat/completions", openrouter: "/api/v1/chat/completions", ollama: "/v1/chat/completions",
  xai: "/v1/chat/completions", tetrate: "/v1/chat/completions",
};

for (const { provider } of GOOSE_COMPAT_PROVIDERS) {
  test(`\`mandu goose run\` on ${provider}: every request through the proxy on ${WIRE[provider]}, the labelled file's content reaches the model ONLY as a symbol`, { skip: SKIP, timeout: 180_000 }, async () => {
    seen.length = 0;
    mkdirSync(join(tmp, "mandu-launch"), { recursive: true, mode: 0o700 });
    const code = await main(["--no-scope", "--", GOOSE!, "run", "--no-session", "-t", "check the api key file"], userEnv(provider, provider));
    assert.equal(code, 0, "goose under Mandu exited 0");
    const posts = seen.filter((q) => q.method === "POST");
    assert.ok(posts.length >= 2, `the proxy forwarded Goose's turns (${seen.map((q) => `${q.method} ${q.path}`).join(", ")})`);
    for (const q of posts) assert.equal(q.path, WIRE[provider], `Goose's own path for ${provider}`);
    for (const q of seen) {
      assert.equal(q.auth, provider === "ollama" ? "" : "Bearer sk-mandu-test-not-a-key", "the user's own key is relayed (ollama sends none)");
    }
    const withResult = posts.filter((q) => q.body.includes("call_cat") && q.body.includes('"role":"tool"'));
    assert.ok(withResult.length >= 1, "the shell ran and its result came back through the proxy");
    assert.match(withResult.at(-1)!.body, SYMBOL_RE, "the result reached the model as a symbol (only the proxy mints one)");
    for (const q of seen) assert.ok(!q.body.includes(CANARY), `INVARIANT: no request carries the labelled secret (${q.path})`);
    passed++;
  });
}

test("text call, ollama: a shell call the model writes in its text never runs under Mandu; the same goose without Mandu runs it (the probe is real)", { skip: SKIP, timeout: 240_000 }, async () => {
  const marker = join(tmp, "text-call-ran");
  rmSync(marker, { force: true });
  seen.length = 0;
  mkdirSync(join(tmp, "mandu-launch"), { recursive: true, mode: 0o700 });
  await main(["--no-scope", "--", GOOSE!, "run", "--no-session", "-t", TEXT_CALL_PROMPT], userEnv("textcall", "ollama")).catch(() => 1);
  assert.ok(seen.some((q) => q.method === "POST" && q.body.includes(TEXT_CALL_PROMPT)), "the turn reached the upstream through the proxy");
  assert.equal(existsSync(marker), false, "INVARIANT: the call written as text did not run under Mandu");
  // the control: goose alone, on the same upstream (every host key at it)
  const env = { ...userEnv("textcall-control", "ollama"), GOOSE_TELEMETRY_OFF: "1" } as Record<string, string>;
  for (const k of Object.keys(env)) if (k.startsWith("MANDU_") || env[k] === undefined) delete env[k];
  // async: the scripted upstream runs in this process
  const r = await new Promise<{ code: number | null; out: string }>((done) => {
    const c = spawn(GOOSE!, ["run", "--no-session", "-t", TEXT_CALL_PROMPT], { cwd: join(tmp, "work"), env, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    c.stdout!.on("data", (d) => (out += d));
    c.stderr!.on("data", (d) => (out += d));
    const timer = setTimeout(() => c.kill("SIGKILL"), 120_000);
    c.on("close", (code) => { clearTimeout(timer); done({ code, out }); });
  });
  assert.ok(existsSync(marker), `goose alone runs the call written as text, so the probe is real (status ${r.code}: ${r.out.slice(-300)})`);
  passed++;
});

test("refused before goose starts: ollama at a host the proxy cannot reach, litellm on a base path that is not Chat Completions", { skip: SKIP, timeout: 60_000 }, async () => {
  seen.length = 0;
  for (const [provider, extra, re] of [
    ["ollama", { OLLAMA_HOST: "http://gpu-box.corp.example:11434" }, /GOOSE_PROVIDER names the provider `ollama`, but the environment's OLLAMA_HOST \(`http:\/\/gpu-box\.corp\.example:11434`\) is not an endpoint/],
    ["litellm", { LITELLM_BASE_PATH: "v1/embeddings" }, /LITELLM_BASE_PATH \(`v1\/embeddings`\) does not end in `chat\/completions`/],
  ] as Array<[string, Record<string, string>, RegExp]>) {
    let err: unknown;
    try { await main(["--no-scope", "--", GOOSE!, "run", "--no-session", "-t", "hi"], userEnv("refused", provider, extra)); } catch (e) { err = e; }
    assert.match(String(err), re);
    assert.match(String(err), /^Error: mandu: refusing to launch goose: /);
  }
  assert.equal(existsSync(join(tmp, "goose-refused")), false, "goose never started (it would have created its home)");
  assert.equal(seen.length, 0, "nothing reached the upstream");
  passed++;
});
