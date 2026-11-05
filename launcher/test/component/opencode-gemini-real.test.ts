/**
 * opencode-gemini-real.test — the REAL `opencode run` on its `google`
 * provider (`@ai-sdk/google`, the Gemini wire) under the REAL launcher
 * (`src/run.ts`, its own process), the REAL arbiter daemon and the autostarted model proxy,
 * against a scripted Gemini upstream on loopback (model-wires.md §4, §5;
 * supported-agents.md "Non-Anthropic models"). No key is spent and no
 * provider is dialed: the user's config points the provider's
 * `options.baseURL` at the upstream, which is this process. Needs an opencode
 * binary: MANDU_OPENCODE_BIN, else `opencode` on PATH (the CI guest pins
 * 1.18.13, scripts/ci/pins.env); without one the suite SKIPS with that
 * reason, never a green.
 *
 *   routing   the launcher re-points `provider.google.options.baseURL` at the
 *             proxy's /_mandu/google/google route and hands the proxy the
 *             user's address (MANDU_GOOGLE_UPSTREAMS): every model request
 *             reaches the upstream THROUGH the proxy, on the AI SDK's own
 *             Gemini path (`/v1beta/models/{model}:streamGenerateContent`);
 *   invariant (SECURITY) the scripted model asks for a `read` of a labelled
 *             (no-model) file: the read runs, and its output reaches the
 *             upstream ONLY as a `$MDU:` symbol, in the AI SDK's own
 *             `{name, content}` function response; no request carries the
 *             value.
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
import { once } from "node:events";
import { pathToFileURL } from "node:url";
import { stateAxes } from "../axes.js";
import { stopGroup } from "../lib/tmp-dir.js";
import { sourceArbiterArgs, waitForPaths } from "../lib/arbiter-ready.js";

stateAxes("secrets"); // the shipped default mode: the labelled file must reach the model only as a symbol

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const ARBITER_DIR = join(REPO_ROOT, "arbiter");
const LAUNCHER_ROOT = join(REPO_ROOT, "launcher");
// The launch runs in its folder (cwd = PWD), as a shell starts it, so tsx is imported by path.
const TSX_LOADER = pathToFileURL(join(LAUNCHER_ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;

function findOpencode(): string | null {
  const pinned = process.env["MANDU_OPENCODE_BIN"];
  if (pinned) return existsSync(pinned) ? pinned : null;
  for (const d of (process.env["PATH"] ?? "").split(delimiter)) {
    const p = join(d, "opencode");
    if (d && existsSync(p)) return p;
  }
  return null;
}
const OPENCODE = findOpencode();
const VERSION = OPENCODE === null ? null : spawnSync(OPENCODE, ["--version"], { encoding: "utf8", timeout: 20_000 });
const SKIP = OPENCODE === null
  ? "no opencode binary: set MANDU_OPENCODE_BIN or put opencode on PATH (the CI guest image pins it; scripts/ci/pins.env)"
  : VERSION?.status !== 0 ? `${OPENCODE} --version failed`
    // OpenCode 2 speaks another config spelling and tool set; this leg is the 1.x one.
    : /^2\./.test(VERSION.stdout.trim()) ? `opencode ${VERSION.stdout.trim()} is OpenCode 2; this leg pins 1.x` : false;

const CANARY = "OPENCODE-GEMINI-REAL-CANARY-4471";
const SECRET_BODY = `ACME_API_KEY=sk-live-${CANARY}\n`;
const SYMBOL_RE = /\$MDU:nomodel_[A-Za-z0-9_]*\[[0-9a-f]+\]/;
const MODEL = "gemini-2.5-flash";
const WIRE = `/v1beta/models/${MODEL}:streamGenerateContent`;

let tmp: string;
let vault: string;
let arbiter: ChildProcess | undefined;
let upstream: Server;
let origin = "";
const seen: Array<{ method: string; path: string; googKey: string; body: string }> = [];

// ── the scripted Gemini model (@ai-sdk/google's stream reader) ─────────────

const chunk = (parts: unknown[], finish?: string): string =>
  `data: ${JSON.stringify({ candidates: [{ content: { role: "model", parts }, index: 0, ...(finish ? { finishReason: finish } : {}) }], modelVersion: MODEL, responseId: "resp-oc-1", usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1, totalTokenCount: 2 } })}\r\n\r\n`;
const text = (t: string): string => chunk([{ text: t }]) + chunk([{ text: "" }], "STOP");

/** One agentic turn: a tool-bearing request without a function response
 *  gets a `read` of the labelled file; the one carrying its result the
 *  closing text; a tool-less request (the title call) a title. */
function scripted(req: IncomingMessage, res: ServerResponse): void {
  let buf = "";
  req.setEncoding("utf8");
  req.on("data", (c) => (buf += c));
  req.on("end", () => {
    const path = req.url ?? "";
    seen.push({ method: req.method ?? "", path, googKey: String(req.headers["x-goog-api-key"] ?? ""), body: buf });
    let body: Record<string, unknown> = {};
    try { body = JSON.parse(buf) as Record<string, unknown>; } catch { /* a GET */ }
    if (req.method !== "POST") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ models: [] }));
      return;
    }
    const tools = body["tools"] === undefined ? [] : [body["tools"]].flat();
    const hasResult = buf.includes('"functionResponse"');
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.end(tools.length === 0 ? text("Title") : hasResult ? text("MANDU_OC_GEMINI_DONE")
      : chunk([{ functionCall: { name: "read", args: { filePath: join(vault, "api-notes.txt") } } }], "STOP"));
  });
}

before(async () => {
  if (SKIP) return;
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-oc-gemini-")));
  mkdirSync(join(tmp, "work"));
  // Inside the project folder: a read outside it is an `external_directory`
  // ask, which `opencode run` answers no.
  vault = join(tmp, "work", "vault");
  mkdirSync(vault);
  writeFileSync(join(vault, "api-notes.txt"), SECRET_BODY);
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
  rmSync(tmp, { recursive: true, force: true });
});

test("`mandu opencode run` on google (@ai-sdk/google): every request through the proxy on the Gemini path, the labelled file's content reaches the model ONLY as a symbol", { skip: SKIP, timeout: 240_000 }, async () => {
  seen.length = 0;
  mkdirSync(join(tmp, "mandu-launch"), { recursive: true, mode: 0o700 });
  // The user's own config: the built-in google provider at their own Gemini endpoint.
  const config = join(tmp, "opencode.json");
  writeFileSync(config, JSON.stringify({
    $schema: "https://opencode.ai/config.json",
    model: `google/${MODEL}`,
    provider: { google: { options: { baseURL: `${origin}/v1beta` }, models: { [MODEL]: { name: "Stand-in", tool_call: true } } } },
  }));
  const env: Record<string, string | undefined> = {
    HOME: tmp, PATH: process.env["PATH"], PWD: join(tmp, "work"),
    XDG_CONFIG_HOME: join(tmp, "xdg-config"), XDG_DATA_HOME: join(tmp, "xdg-data"), XDG_CACHE_HOME: join(tmp, "xdg-cache"), XDG_STATE_HOME: join(tmp, "xdg-state"),
    MANDU_HOME: PRIVATE_MANDU_HOME, XDG_RUNTIME_DIR: tmp, MANDU_RUNTIME_DIR: join(tmp, "mandu-launch"),
    MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_PROXY_PORT: "0", MANDU_MODE: "secrets",
    MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0", MANDU_NO_MCP: "1",
    OPENCODE_CONFIG: config,
    OPENCODE_DISABLE_AUTOUPDATE: "1", OPENCODE_DISABLE_MODELS_FETCH: "1", OPENCODE_DISABLE_CLAUDE_CODE: "1", OPENCODE_DISABLE_EXTERNAL_SKILLS: "1", OPENCODE_DISABLE_LSP_DOWNLOAD: "1", OPENCODE_DISABLE_DEFAULT_PLUGINS: "1",
    GOOGLE_GENERATIVE_AI_API_KEY: "AIza-mandu-test-not-a-key",
  };
  // The real CLI as its own process, as a shell starts it: its environment is
  // the one it reads the agent's config from (run.ts agentModelPlan), and
  // stdin is closed (`opencode run` off a TTY waits for its stdin to end).
  const child = spawn(process.execPath, [
    "--import", TSX_LOADER, join(LAUNCHER_ROOT, "src", "run.ts"),
    "--no-scope", "--no-mcp", "--", OPENCODE!, "run", "check the api key file",
  ], { cwd: join(tmp, "work"), env: env as NodeJS.ProcessEnv, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  child.stdout!.on("data", (d) => { out += String(d); });
  child.stderr!.on("data", (d) => { out += String(d); });
  const timer = setTimeout(() => child.kill("SIGKILL"), 200_000);
  const [code] = await once(child, "exit") as [number | null];
  clearTimeout(timer);
  if (code !== 0) console.error(`opencode-gemini-real: launch output:\n${out.slice(-3000)}`);
  const posts = seen.filter((q) => q.method === "POST");
  assert.equal(code, 0, `opencode under Mandu exited 0 (requests: ${seen.map((q) => `${q.method} ${q.path}`).join(", ")})`);
  assert.ok(posts.length >= 2, `the proxy forwarded OpenCode's turns (${seen.map((q) => `${q.method} ${q.path}`).join(", ")})`);
  // The turns on the configured model; the title call on OpenCode's small model of the provider.
  for (const q of posts) assert.match(q.path.split("?")[0]!, /^\/v1beta\/models\/[A-Za-z0-9.-]+:streamGenerateContent$/, "the AI SDK's own Gemini path under the user's base URL");
  assert.ok(posts.some((q) => q.path.split("?")[0] === WIRE), "the turns ran on the configured model");
  // The agent's own key, left unmasked for its routed Gemini provider
  // (agent-model-route.ts googleRoutedKeyVars), reaches the provider as set.
  for (const q of posts) assert.equal(q.googKey, "AIza-mandu-test-not-a-key", "the user's own key is relayed in x-goog-api-key");
  const withResult = posts.filter((q) => q.body.includes('"functionResponse"'));
  assert.ok(withResult.length >= 1, `the read ran and its result came back through the proxy (launch output: ${out.slice(-1500)})`);
  assert.match(withResult.at(-1)!.body, SYMBOL_RE, "the result reached the model as a nomodel symbol (only the proxy mints one)");
  for (const q of seen) assert.ok(!q.body.includes(CANARY), `INVARIANT: no request carries the labelled secret (${q.path})`);
});
