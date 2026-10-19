/**
 * goose-real.test — the REAL goose binary under the REAL launcher
 * (`main()`), the REAL arbiter daemon and the autostarted anthropic-proxy,
 * against a scripted model upstream (supported-agents.md §5.6). Needs a goose
 * binary: MANDU_GOOSE_BIN, else `goose` on PATH (the CI guest pins 1.53.0,
 * scripts/ci/pins.env); without one the suite SKIPS with that reason, never a
 * green.
 *
 *   routing   `mandu goose run …` reaches the model only through the proxy:
 *             the scripted upstream sees Goose's requests (its tools[], the
 *             shell's result) and the run exits 0;
 *   U-LLM     the tools[] Goose advertises carry Mandu's own MCP tools in
 *             Goose's spelling (`mandu-inspect__inspect_symbol`): the real
 *             inspect-mcp started from the `--with-extension` splice;
 *   uploads   (supported-agents.md §5.3.4 rule 1, SECURITY) the user's env
 *             turns on Goose's OTLP export, its Langfuse tracing and its
 *             telemetry, pointed at a counting collector on loopback: under
 *             `mandu goose` the collector receives NOTHING. The CONTROL runs
 *             the same goose with the same env, less the Langfuse keys
 *             (`controlEnv`: Goose's own crash, test-organization.md §8.8),
 *             without Mandu and the collector DOES receive the traces, so
 *             the probe is real.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../axes.js";
import { stopGroup } from "../lib/tmp-dir.js";
import { sourceArbiterArgs, waitForPaths } from "../lib/arbiter-ready.js";

stateAxes("secrets"); // the shipped default mode; the routing and the forced-off uploads are what is under test

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const ARBITER_DIR = join(REPO_ROOT, "arbiter");

/** The goose binary, or null. */
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

let tmp: string;
let arbiter: ChildProcess | undefined;
let upstream: HttpsServer;
let plainUpstream: Server;
let collector: Server;
let upstreamOrigin = "";
let plainOrigin = "";
let collectorOrigin = "";
const upstreamReqs: Array<{ path: string; body: Record<string, unknown> | null }> = [];
const collected: string[] = [];
let passed = false;

const MODEL = "claude-sonnet-4-5";
const SHELL_MARK = "MANDU_GOOSE_SHELL_OK";

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
const shellTurn = (): string => sse([
  start("msg_u"),
  ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_goose_1", name: "shell", input: {} } }],
  ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ command: `echo ${SHELL_MARK}` }) } }],
  ["content_block_stop", { type: "content_block_stop", index: 0 }],
  ["message_delta", { type: "message_delta", delta: { stop_reason: "tool_use", stop_sequence: null }, usage: { output_tokens: 1 } }],
  ["message_stop", { type: "message_stop" }],
]);

/** One agentic turn: the first tools-bearing request of a session gets a
 *  shell call, the request carrying its result gets the closing text; a
 *  tool-less request (Goose's title call) gets a title. */
function scripted(req: IncomingMessage, res: ServerResponse): void {
  let buf = "";
  req.setEncoding("utf8");
  req.on("data", (c) => (buf += c));
  req.on("end", () => {
    let body: Record<string, unknown> | null = null;
    try { body = JSON.parse(buf) as Record<string, unknown>; } catch { /* not JSON */ }
    upstreamReqs.push({ path: req.url ?? "", body });
    const tools = Array.isArray(body?.["tools"]) ? (body!["tools"] as unknown[]) : [];
    const msgs = Array.isArray(body?.["messages"]) ? (body!["messages"] as Array<{ content?: unknown }>) : [];
    const hasResult = msgs.some((m) => Array.isArray(m.content) && (m.content as Array<{ type?: string }>).some((b) => b.type === "tool_result"));
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.end(tools.length === 0 ? textTurn("Title") : hasResult ? textTurn("MANDU_GOOSE_DONE") : shellTurn());
  });
}

function mintSelfSignedCert(dir: string): { cert: Buffer; key: Buffer } {
  const r = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"), "-days", "1", "-nodes", "-subj", "/CN=mandu-goose-real"], { encoding: "utf8", timeout: 20_000 });
  if (r.status !== 0) throw new Error(`openssl: ${r.stderr ?? r.stdout}`);
  return { cert: readFileSync(join(dir, "c.pem")), key: readFileSync(join(dir, "k.pem")) };
}

before(async () => {
  if (SKIP) return;
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-goose-")));
  mkdirSync(join(tmp, "work"));
  const logFd = openSync(join(tmp, "arbiter.log"), "a");
  arbiter = spawn(process.execPath, sourceArbiterArgs(join(tmp, "arbiter.sock")), {
    cwd: ARBITER_DIR,
    env: { ...process.env, MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_HOME: join(tmp, "mandu-home"), MANDU_RUNTIME_DIR: join(tmp, "mandu") },
    stdio: ["ignore", logFd, logFd], detached: true,
  });
  closeSync(logFd);
  await waitForPaths(join(tmp, "arbiter.sock"), { what: "the arbiter", child: arbiter, logPath: join(tmp, "arbiter.log") });
  const { cert, key } = mintSelfSignedCert(tmp);
  upstream = createHttpsServer({ cert, key }, scripted);
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
  upstreamOrigin = `https://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  plainUpstream = createHttpServer(scripted);
  await new Promise<void>((r) => plainUpstream.listen(0, "127.0.0.1", () => r()));
  plainOrigin = `http://127.0.0.1:${(plainUpstream.address() as AddressInfo).port}`;
  // The counting collector: OTLP (/v1/traces, /v1/metrics, /v1/logs) and
  // Langfuse (/api/public/ingestion) land here when an upload is on.
  collector = createHttpServer((req, res) => { collected.push(`${req.method} ${req.url}`); req.resume(); res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); });
  await new Promise<void>((r) => collector.listen(0, "127.0.0.1", () => r()));
  collectorOrigin = `http://127.0.0.1:${(collector.address() as AddressInfo).port}`;
  process.env["MANDU_UPSTREAM"] = upstreamOrigin;
  process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";
});

after(async () => {
  delete process.env["MANDU_UPSTREAM"];
  delete process.env["NODE_TLS_REJECT_UNAUTHORIZED"];
  upstream?.close(); plainUpstream?.close(); collector?.close();
  if (arbiter) await stopGroup(arbiter);
  if (!tmp) return;
  if (!passed) {
    try { console.error(`goose-real: arbiter log tail:\n${readFileSync(join(tmp, "arbiter.log"), "utf8").split("\n").slice(-30).join("\n")}`); } catch { /* none */ }
  }
  rmSync(tmp, { recursive: true, force: true });
});

/** The user's env: a throwaway Goose home, a key, and every upload ON,
 *  pointed at the counting collector. */
function userEnv(home: string): Record<string, string> {
  return {
    GOOSE_PATH_ROOT: home, GOOSE_DISABLE_KEYRING: "1", GOOSE_MODE: "auto", GOOSE_MODEL: MODEL,
    ANTHROPIC_API_KEY: "sk-ant-mandu-test",
    GOOSE_TELEMETRY_ENABLED: "true",
    OTEL_EXPORTER_OTLP_ENDPOINT: collectorOrigin, OTEL_EXPORTER_OTLP_PROTOCOL: "http/protobuf",
    LANGFUSE_PUBLIC_KEY: "pk-lf-test", LANGFUSE_SECRET_KEY: "sk-lf-test", LANGFUSE_URL: collectorOrigin,
  };
}

/** The keys that switch on Goose's Langfuse layer (it is built only when a
 *  public and a secret key are both set; the INIT_PROJECT spellings are the
 *  fallbacks). */
const LANGFUSE_KEYS = ["LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_INIT_PROJECT_PUBLIC_KEY", "LANGFUSE_INIT_PROJECT_SECRET_KEY"];

/** The CONTROL's env: the user's, less the Langfuse keys (test-organization.md
 *  §8.8). Goose 1.53.0's Langfuse layer calls `tokio::spawn` from its
 *  `on_close` (crates/goose/src/tracing/observation_layer.rs:312), so when the
 *  last handle on a `goose::` span drops on a sqlx-sqlite worker thread, which
 *  has no Tokio runtime, Goose panics ("there is no reactor running") inside
 *  the span's destructor and aborts with no exit status: 19 of 139 CI runs
 *  (2026-10-09 and 10-10), never with Mandu in the path. Without the keys the
 *  layer is never built, so the crash cannot happen. Nothing the control
 *  proves goes with them: it asserts the OTLP traces, and Langfuse sends its
 *  batch every 5 s with no flush at exit, so a short run often sends none and
 *  the control never checked it. The Mandu leg keeps every key on: there the
 *  launcher empties them (goose-delivery.test.ts pins that), and a Langfuse
 *  upload or this crash under Mandu would fail it. */
function controlEnv(home: string): Record<string, string> {
  const env = userEnv(home);
  for (const k of LANGFUSE_KEYS) delete env[k];
  return env;
}

test("CONTROL (no Mandu): the same goose with the same OTLP env uploads its traces to the collector, so the probe below is real", { skip: SKIP, timeout: 120_000 }, async () => {
  const home = join(tmp, "goose-control");
  // Asynchronous: the scripted upstream answers from this process.
  const child = spawn(GOOSE!, ["run", "--no-session", "-t", "say hi"], {
    cwd: join(tmp, "work"), stdio: ["ignore", "ignore", "pipe"],
    env: { PATH: process.env["PATH"]!, HOME: tmp, ...controlEnv(home), GOOSE_PROVIDER: "anthropic", ANTHROPIC_HOST: plainOrigin },
  });
  let stderr = "";
  child.stderr!.on("data", (c) => (stderr += String(c)));
  const status = await new Promise<number | null>((res) => {
    const t = setTimeout(() => { child.kill("SIGKILL"); res(null); }, 90_000);
    child.on("exit", (c) => { clearTimeout(t); res(c); });
  });
  assert.equal(status, 0, `goose ran (stderr: ${stderr})`);
  await new Promise((res) => setTimeout(res, 1500));
  assert.ok(collected.length > 0, "without Mandu the collector received Goose's uploads");
  assert.ok(collected.some((c) => /\/v1\/traces/.test(c)), `OTLP traces uploaded: ${collected.join(", ")}`);
});

test("`mandu goose run`: model traffic only through the proxy, Mandu's MCP tools advertised, and NOTHING uploaded to the collector", { skip: SKIP, timeout: 180_000 }, async () => {
  collected.length = 0;
  upstreamReqs.length = 0;
  const home = join(tmp, "goose-mandu");
  const code = await main(
    ["--no-scope", "--", GOOSE!, "run", "--no-session", "-t", "say hi"],
    {
      HOME: tmp, PATH: process.env["PATH"], PWD: join(tmp, "work"),
      MANDU_HOME: PRIVATE_MANDU_HOME, XDG_RUNTIME_DIR: tmp,
      MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_PROXY_PORT: "0", MANDU_MODE: "secrets",
      MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0",
      ...userEnv(home),
    },
  );
  assert.equal(code, 0, "goose under Mandu exited 0");
  const tooled = upstreamReqs.filter((q) => Array.isArray(q.body?.["tools"]) && (q.body!["tools"] as unknown[]).length > 0);
  assert.ok(tooled.length >= 2, `the proxy forwarded Goose's turns (${upstreamReqs.length} requests)`);
  for (const q of upstreamReqs) assert.match(q.path, /\/v1\/messages$/);
  const names = (tooled[0]!.body!["tools"] as Array<{ name: string }>).map((t) => t.name);
  assert.ok(names.includes("shell"), names.join(","));
  assert.ok(names.includes("mandu-inspect__inspect_symbol"), `the U-LLM is mounted in Goose's spelling: ${names.join(",")}`);
  assert.ok(JSON.stringify(tooled.at(-1)!.body).includes(SHELL_MARK), "the shell ran and its result came back through the proxy");
  await new Promise((res) => setTimeout(res, 1500));
  assert.deepEqual(collected, [], "INVARIANT (rule 1): no trace, telemetry or log upload left Goose under Mandu");
  passed = true;
});
