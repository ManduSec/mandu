/**
 * goose-resume-real.test — a RESUMED Goose session under `mandu goose`
 * (supported-agents.md §5.6, "Resumed sessions"): the REAL goose binary, the
 * REAL launcher (`main()`), the REAL arbiter daemon and the autostarted model
 * proxy, against scripted upstreams on loopback (no key, no real provider
 * host).
 *
 * WHY (goose 1.53.0 goose-cli session/builder.rs resolve_provider_and_model):
 * a resumed session's provider is `--provider`, then the provider SAVED with
 * the session, then a recipe's, then env GOOSE_PROVIDER / the config. The
 * saved provider outranks the env routing Mandu sets, so a session started
 * outside Mandu on a provider Mandu does not route would, resumed under
 * `mandu goose`, send its history (the raw tool output in it) to that
 * provider around the proxy.
 *
 *   CONTROL  the session is created outside Mandu on a declarative provider
 *            (`custom_providers/custom_leak.json`, its base URL a COUNTING
 *            upstream standing in for a provider Mandu does not route), and
 *            resumed with env GOOSE_PROVIDER=anthropic: Goose dials the
 *            counting upstream anyway, so the probe is real;
 *   resume   `mandu goose run --resume --name …` and `-r -n …`: the counting
 *            upstream sees NOTHING; every model request goes through the
 *            proxy on the routed provider, and the saved history's tool
 *            output (a `cat` of a labelled file) reaches the model only as a
 *            `$MDU:` symbol.
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
import { sourceArbiterArgs, waitForPaths } from "../lib/arbiter-ready.js";

stateAxes("secrets"); // the shipped default: the labelled file must reach the model only as a symbol

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

const MODEL = "claude-sonnet-4-5";
const CANARY = "GOOSE-RESUME-CANARY-6203";
const SECRET_BODY = `ACME_API_KEY=sk-live-${CANARY}\n`;
const SYMBOL_RE = /\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]+\]/;

let tmp: string;
let work: string;
let gooseHome: string;
let secretFile: string;
let arbiter: ChildProcess | undefined;
let leak: Server; // the provider Mandu does not route (counting)
let anth: Server; // the routed provider's scripted upstream (MANDU_UPSTREAM)
let leakOrigin = "";
const leakReqs: Array<{ method: string; path: string; raw: string }> = [];
const anthReqs: Array<{ path: string; raw: string }> = [];
let passed = 0;

// ── the provider Mandu does not route: Chat Completions, counting ─────────
const chatChunk = (delta: unknown, finish: string | null = null): string =>
  `data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", created: 1, model: "leak-model", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
const chatText = (t: string): string => chatChunk({ role: "assistant", content: "" }) + chatChunk({ content: t }) + chatChunk({}, "stop") + "data: [DONE]\n\n";
const chatShell = (command: string): string =>
  chatChunk({ role: "assistant", content: null, tool_calls: [{ index: 0, id: "call_cat", type: "function", function: { name: "shell", arguments: JSON.stringify({ command }) } }] }) +
  chatChunk({}, "tool_calls") + "data: [DONE]\n\n";

function leakScripted(req: IncomingMessage, res: ServerResponse): void {
  let buf = "";
  req.setEncoding("utf8");
  req.on("data", (c) => (buf += c));
  req.on("end", () => {
    leakReqs.push({ method: req.method ?? "", path: req.url ?? "", raw: buf });
    let body: Record<string, unknown> = {};
    try { body = JSON.parse(buf) as Record<string, unknown>; } catch { /* a GET */ }
    if (req.method === "GET") {
      res.writeHead(200, { "content-type": "application/json" });
      return void res.end(JSON.stringify({ object: "list", data: [{ id: "leak-model", object: "model" }] }));
    }
    const tools = Array.isArray(body["tools"]) ? body["tools"] : [];
    const msgs = (body["messages"] as Array<{ role?: string; content?: unknown }> | undefined) ?? [];
    const lastIsResult = msgs.at(-1)?.role === "tool";
    res.writeHead(200, { "content-type": "text/event-stream" });
    // the first turn reads the labelled file, so its raw output is in the saved history
    res.end(tools.length === 0 ? chatText("Title") : lastIsResult || msgs.some((m) => m.role === "tool") ? chatText("LEAK_DONE") : chatShell(`cat ${secretFile}`));
  });
}

// ── the routed provider (anthropic, through the proxy) ─────────────────────
function sse(events: Array<[string, unknown]>): string {
  return events.map(([e, d]) => `event: ${e}\ndata: ${JSON.stringify(d)}\n\n`).join("");
}
const textTurn = (t: string): string => sse([
  ["message_start", { type: "message_start", message: { id: "msg_t", type: "message", role: "assistant", model: MODEL, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 5, output_tokens: 1 } } }],
  ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }],
  ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: t } }],
  ["content_block_stop", { type: "content_block_stop", index: 0 }],
  ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } }],
  ["message_stop", { type: "message_stop" }],
]);
function anthScripted(req: IncomingMessage, res: ServerResponse): void {
  let buf = "";
  req.setEncoding("utf8");
  req.on("data", (c) => (buf += c));
  req.on("end", () => {
    anthReqs.push({ path: req.url ?? "", raw: buf });
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.end(textTurn("RESUMED_DONE"));
  });
}

/** goose itself, outside Mandu. Asynchronous: the upstreams answer from
 *  this process. */
async function gooseDirect(args: string[], env: Record<string, string>): Promise<{ status: number | null; stderr: string }> {
  const child = spawn(GOOSE!, args, {
    cwd: work, stdio: ["ignore", "ignore", "pipe"],
    env: { PATH: process.env["PATH"]!, HOME: tmp, GOOSE_PATH_ROOT: gooseHome, GOOSE_DISABLE_KEYRING: "1", GOOSE_MODE: "auto", GOOSE_TELEMETRY_OFF: "1", OTEL_SDK_DISABLED: "true", ...env },
  });
  let stderr = "";
  child.stderr!.on("data", (c) => (stderr += String(c)));
  const status = await new Promise<number | null>((r) => {
    const t = setTimeout(() => { child.kill("SIGKILL"); r(null); }, 90_000);
    child.on("exit", (c) => { clearTimeout(t); r(c); });
  });
  return { status, stderr };
}

before(async () => {
  if (SKIP) return;
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-goose-resume-")));
  work = join(tmp, "work");
  gooseHome = join(tmp, "goose-home");
  mkdirSync(join(work, "vault"), { recursive: true });
  secretFile = join(work, "vault", "api.env");
  writeFileSync(secretFile, SECRET_BODY);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(work, "vault")}\n    level: no-model\n`);
  const logFd = openSync(join(tmp, "arbiter.log"), "a");
  arbiter = spawn(process.execPath, sourceArbiterArgs(join(tmp, "arbiter.sock")), {
    cwd: ARBITER_DIR,
    env: { ...process.env, HOME: tmp, MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_HOME: join(tmp, "mandu-home"), MANDU_RUNTIME_DIR: join(tmp, "mandu"), MANDU_POLICY_FILE: policy },
    stdio: ["ignore", logFd, logFd], detached: true,
  });
  closeSync(logFd);
  await waitForPaths(join(tmp, "arbiter.sock"), { what: "the arbiter", child: arbiter, logPath: join(tmp, "arbiter.log") });
  leak = createHttpServer(leakScripted);
  await new Promise<void>((r) => leak.listen(0, "127.0.0.1", () => r()));
  leakOrigin = `http://127.0.0.1:${(leak.address() as AddressInfo).port}`;
  anth = createHttpServer(anthScripted);
  await new Promise<void>((r) => anth.listen(0, "127.0.0.1", () => r()));
  process.env["MANDU_UPSTREAM"] = `http://127.0.0.1:${(anth.address() as AddressInfo).port}`;
  // A provider Mandu does not route: a declarative provider whose base URL
  // is the counting upstream (as a user's own custom provider would be).
  mkdirSync(join(gooseHome, "config", "custom_providers"), { recursive: true });
  writeFileSync(join(gooseHome, "config", "custom_providers", "custom_leak.json"), JSON.stringify({
    name: "custom_leak", engine: "openai", display_name: "Leak", api_key_env: "CUSTOM_LEAK_API_KEY",
    base_url: `${leakOrigin}/v1`, models: [{ name: "leak-model", context_limit: 128000 }], dynamic_models: false,
  }));
});

after(async () => {
  delete process.env["MANDU_UPSTREAM"];
  leak?.close(); anth?.close();
  if (arbiter) await stopGroup(arbiter);
  if (!tmp) return;
  if (passed < 2) {
    try { console.error(`goose-resume-real: arbiter log tail:\n${readFileSync(join(tmp, "arbiter.log"), "utf8").split("\n").slice(-30).join("\n")}`); } catch { /* none */ }
  }
  rmSync(tmp, { recursive: true, force: true });
});

/** The launch env: the same Goose home, its config naming anthropic. */
function launchEnv(): Record<string, string | undefined> {
  return {
    HOME: tmp, PATH: process.env["PATH"], PWD: work,
    MANDU_HOME: PRIVATE_MANDU_HOME, XDG_RUNTIME_DIR: tmp, MANDU_RUNTIME_DIR: join(tmp, "mandu-launch"),
    MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_PROXY_PORT: "0", MANDU_MODE: "secrets",
    MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0",
    GOOSE_PATH_ROOT: gooseHome, GOOSE_DISABLE_KEYRING: "1", GOOSE_MODE: "auto", GOOSE_MODEL: MODEL,
    ANTHROPIC_API_KEY: "sk-ant-mandu-test", CUSTOM_LEAK_API_KEY: "sk-leak-test",
  };
}

async function launchIn(argv: string[]): Promise<number> {
  const was = process.cwd();
  process.chdir(work);
  mkdirSync(join(tmp, "mandu-launch"), { recursive: true, mode: 0o700 });
  try { return await main(argv, launchEnv()); } finally { process.chdir(was); }
}

test("CONTROL (no Mandu): a session saved on a provider Mandu does not route is resumed on THAT provider, whatever env GOOSE_PROVIDER says", { skip: SKIP, timeout: 240_000 }, async () => {
  // Created outside Mandu on the declarative provider; its turn cats the labelled file.
  const created = await gooseDirect(["run", "--name", "saved-leak", "-t", "check the api key file"], {
    GOOSE_PROVIDER: "custom_leak", GOOSE_MODEL: "leak-model", CUSTOM_LEAK_API_KEY: "sk-leak-test",
  });
  assert.equal(created.status, 0, `goose created the session (stderr: ${created.stderr})`);
  assert.ok(leakReqs.some((q) => q.raw.includes(CANARY)), "outside Mandu the file's raw content went to that provider: the saved history holds it");
  for (const name of ["saved-leak-2", "saved-leak-3"]) {
    const again = await gooseDirect(["run", "--name", name, "-t", "check the api key file"], {
      GOOSE_PROVIDER: "custom_leak", GOOSE_MODEL: "leak-model", CUSTOM_LEAK_API_KEY: "sk-leak-test",
    });
    assert.equal(again.status, 0, again.stderr);
  }
  // Resumed with the env naming anthropic at the routed upstream: the saved provider wins.
  const before = leakReqs.length;
  const resumed = await gooseDirect(["run", "--resume", "--name", "saved-leak-3", "-t", "and again"], {
    GOOSE_PROVIDER: "anthropic", ANTHROPIC_HOST: process.env["MANDU_UPSTREAM"]!, ANTHROPIC_API_KEY: "sk-ant-mandu-test", CUSTOM_LEAK_API_KEY: "sk-leak-test",
  });
  assert.equal(resumed.status, 0, resumed.stderr);
  assert.ok(leakReqs.length > before, "the resumed session dialed its SAVED provider, not the env's");
  passed++;
});

for (const [label, args] of [
  ["`--resume --name`", ["run", "--resume", "--name", "saved-leak", "-t", "continue"]],
  ["`-r -n`", ["run", "-r", "-n", "saved-leak-2", "-t", "continue"]],
] as const) {
  test(`\`mandu goose run\` ${label} on that session: the saved provider is never dialed; the turn goes through the proxy and the saved history's file content reaches the model only as a symbol`, { skip: SKIP, timeout: 180_000 }, async () => {
    const leakBefore = leakReqs.length;
    anthReqs.length = 0;
    const code = await launchIn(["--no-scope", "--", GOOSE!, ...args]);
    assert.equal(code, 0, "goose under Mandu exited 0");
    assert.equal(leakReqs.length, leakBefore, `INVARIANT: the provider Mandu does not route saw nothing (${leakReqs.slice(leakBefore).map((q) => `${q.method} ${q.path}`).join(", ")})`);
    const posts = anthReqs.filter((q) => q.raw !== "");
    assert.ok(posts.length >= 1, "the resumed turn went through the proxy to the routed provider");
    for (const q of posts) assert.match(q.path, /\/v1\/messages$/);
    const withHistory = posts.filter((q) => q.raw.includes("check the api key file"));
    assert.ok(withHistory.length >= 1, "the saved history rode the resumed turn");
    assert.match(withHistory.at(-1)!.raw, SYMBOL_RE, "the saved tool output reached the model as a symbol");
    for (const q of anthReqs) assert.ok(!q.raw.includes(CANARY), "INVARIANT: the labelled value never reaches the model raw");
    passed++;
  });
}
