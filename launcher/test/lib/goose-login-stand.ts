/**
 * goose-login-stand — the stand the Goose login tests share
 * (test/component/goose-login.test.ts, test/kernel/goose-keyring.test.ts;
 * supported-agents.md §5.6.1): a real arbiter daemon, a scripted Anthropic
 * upstream that records the `x-api-key` each request carries (TLS for the
 * proxy, plain HTTP for a goose run without Mandu), a goose home, an
 * in-process `main()` launch with the launch's lines captured, and, for the
 * keyring, a private D-Bus session bus with the Secret Service mock
 * (test/fixtures/secret-service-mock.py) or a bare listener that only counts
 * connections. Never a real key: the keys are made up here.
 */
import "./private-home.js";
import { PRIVATE_MANDU_HOME } from "./private-home.js";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createNetServer, type Server as NetServer, type AddressInfo } from "node:net";
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { main } from "./launch-in-dir.js";
import { stopGroup } from "./tmp-dir.js";
import { sourceArbiterArgs, waitForPaths } from "./arbiter-ready.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const ARBITER_DIR = join(REPO_ROOT, "arbiter");
const MOCK = join(HERE, "..", "fixtures", "secret-service-mock.py");

export const MODEL = "claude-sonnet-4-5";
/** A made-up key in Anthropic's shape: never a real one. */
export const FAKE_KEY = "sk-ant-api03-MANDUFAKEgooseLOGINkey0123456789abcdefABCDEFghijklmnopQRSTUV-xyzAA";

/** The goose binary (MANDU_GOOSE_BIN, else PATH), or null. */
export function findGoose(): string | null {
  const pinned = process.env["MANDU_GOOSE_BIN"];
  if (pinned) return existsSync(pinned) ? pinned : null;
  for (const d of (process.env["PATH"] ?? "").split(delimiter)) {
    const p = join(d, "goose");
    if (d && existsSync(p)) return p;
  }
  return null;
}

/** Why a goose test cannot run here, or false. */
export function gooseSkip(goose: string | null): string | false {
  if (goose === null) return "no goose binary: set MANDU_GOOSE_BIN or put goose on PATH (the CI guest image pins it; scripts/ci/pins.env)";
  if (spawnSync(goose, ["--version"], { encoding: "utf8", timeout: 20_000 }).status !== 0) return `${goose} --version failed`;
  if (spawnSync("openssl", ["version"], { encoding: "utf8" }).status !== 0) return "no openssl (the scripted upstream's certificate)";
  return false;
}

/** Why the Secret Service mock cannot run here, or false. */
export function secretServiceSkip(): string | false {
  if (spawnSync("dbus-daemon", ["--version"], { encoding: "utf8" }).status !== 0) return "no dbus-daemon (the private session bus)";
  const py = spawnSync("python3", ["-c", "import dbus, dbus.service, dbus.mainloop.glib; from gi.repository import GLib"], { encoding: "utf8" });
  if (py.status !== 0) return "no python3 with dbus-python and PyGObject (python3-dbus, python3-gi) for the Secret Service mock";
  return false;
}

export interface UpstreamRequest { path: string; key: string | undefined; auth: string | undefined; body: string }

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
const toolTurn = (name: string, input: Record<string, unknown>): string => sse([
  start("msg_u"),
  ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_goose_login_1", name, input: {} } }],
  ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(input) } }],
  ["content_block_stop", { type: "content_block_stop", index: 0 }],
  ["message_delta", { type: "message_delta", delta: { stop_reason: "tool_use", stop_sequence: null }, usage: { output_tokens: 1 } }],
  ["message_stop", { type: "message_stop" }],
]);

/** One Chat Completions text answer, streamed. */
const chatText = (t: string): string => {
  const env = { id: "chatcmpl-goose-login", object: "chat.completion.chunk", created: 1, model: "gpt-4o" };
  return [
    { ...env, choices: [{ index: 0, delta: { role: "assistant", content: t }, finish_reason: null }] },
    { ...env, choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 5, completion_tokens: 1, total_tokens: 6 } },
  ].map((c) => `data: ${JSON.stringify(c)}\n\n`).join("") + "data: [DONE]\n\n";
};

export interface Stand {
  tmp: string;
  sock: string;
  /** The scripted upstream over TLS (the proxy's MANDU_UPSTREAM). */
  upstreamOrigin: string;
  /** The same script over plain HTTP (goose without Mandu). */
  plainOrigin: string;
  /** Every request the upstream received, in order. */
  seen: UpstreamRequest[];
  /** The shell command the first tools-bearing turn asks for; null: none. */
  command: string | null;
  /** Any other tool call the first tools-bearing turn asks for instead
   *  (`load_skill{name}`, …); null: the shell `command`, if any. */
  call: { name: string; input: Record<string, unknown> } | null;
  close(): Promise<void>;
}

/** The arbiter, the two upstreams, and the env the in-process launch reads. */
export async function startStand(prefix: string): Promise<Stand> {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  const sock = join(tmp, "arbiter.sock");
  const logFd = openSync(join(tmp, "arbiter.log"), "a");
  const arbiter: ChildProcess = spawn(process.execPath, sourceArbiterArgs(sock), {
    cwd: ARBITER_DIR,
    env: { ...process.env, MANDU_ARBITER_SOCK: sock, MANDU_HOME: join(tmp, "mandu-home"), MANDU_RUNTIME_DIR: join(tmp, "mandu") },
    stdio: ["ignore", logFd, logFd], detached: true,
  });
  closeSync(logFd);
  await waitForPaths(sock, { what: "the arbiter", child: arbiter, logPath: join(tmp, "arbiter.log") });
  const ssl = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-keyout", join(tmp, "k.pem"), "-out", join(tmp, "c.pem"), "-days", "1", "-nodes", "-subj", "/CN=mandu-goose-login"], { encoding: "utf8", timeout: 20_000 });
  if (ssl.status !== 0) throw new Error(`openssl: ${ssl.stderr}`);
  const stand = { tmp, sock, upstreamOrigin: "", plainOrigin: "", seen: [] as UpstreamRequest[], command: null as string | null, call: null } as Stand;
  const scripted = (req: IncomingMessage, res: ServerResponse): void => {
    let buf = "";
    req.setEncoding("utf8");
    req.on("data", (c) => (buf += c));
    req.on("end", () => {
      const one = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v[0] : v);
      stand.seen.push({ path: req.url ?? "", key: one(req.headers["x-api-key"]), auth: one(req.headers["authorization"]), body: buf });
      let body: { tools?: unknown[]; messages?: Array<{ content?: unknown }> } = {};
      try { body = JSON.parse(buf) as typeof body; } catch { /* not JSON */ }
      // Goose's openai provider (Chat Completions): one text turn, streamed
      // as Goose asked (agent-sign-in.md §3's openai leg records the bearer).
      if (/chat\/completions$/.test((req.url ?? "").split("?")[0]!)) {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.end(chatText("MANDU_GOOSE_DONE"));
        return;
      }
      const tools = Array.isArray(body.tools) ? body.tools : [];
      const hasResult = (body.messages ?? []).some((m) => Array.isArray(m.content) && (m.content as Array<{ type?: string }>).some((b) => b.type === "tool_result"));
      res.writeHead(200, { "content-type": "text/event-stream" });
      const call = stand.call ?? (stand.command === null ? null : { name: "shell", input: { command: stand.command } });
      res.end(tools.length === 0 ? textTurn("Title") : hasResult || call === null ? textTurn("MANDU_GOOSE_DONE") : toolTurn(call.name, call.input));
    });
  };
  const upstream: HttpsServer = createHttpsServer({ cert: readFileSync(join(tmp, "c.pem")), key: readFileSync(join(tmp, "k.pem")) }, scripted);
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
  stand.upstreamOrigin = `https://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  const plain: Server = createHttpServer(scripted);
  await new Promise<void>((r) => plain.listen(0, "127.0.0.1", () => r()));
  stand.plainOrigin = `http://127.0.0.1:${(plain.address() as AddressInfo).port}`;
  process.env["MANDU_UPSTREAM"] = stand.upstreamOrigin;
  process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";
  stand.close = async () => {
    delete process.env["MANDU_UPSTREAM"];
    delete process.env["NODE_TLS_REJECT_UNAUTHORIZED"];
    upstream.close(); plain.close();
    await stopGroup(arbiter);
    rmSync(tmp, { recursive: true, force: true });
  };
  return stand;
}

/** A goose home under the stand: `<tmp>/<name>` with its `.config/goose`,
 *  and, when `secretsYaml` is given, Goose's secrets.yaml holding it. */
export function gooseHome(stand: Stand, name: string, secretsYaml?: string): { home: string; secrets: string } {
  const home = join(stand.tmp, name);
  const dir = join(home, ".config", "goose");
  mkdirSync(dir, { recursive: true });
  mkdirSync(join(home, "work"), { recursive: true });
  const secrets = join(dir, "secrets.yaml");
  if (secretsYaml !== undefined) writeFileSync(secrets, secretsYaml, { mode: 0o600 });
  return { home, secrets };
}

/**
 * `mandu goose run …` in process, in `secrets` mode, with `home` as HOME for
 * the launch AND for this process while it runs (the secret discovery walks
 * this process's home). Returns the exit code and every line the launch
 * printed. `kernel`: false adds MANDU_NO_KERNEL=1 (no guard). `args`:
 * goose's own arguments (default `run --no-session -t "say hi"`).
 */
export async function launchGoose(
  goose: string,
  stand: Stand,
  home: string,
  extraEnv: Record<string, string>,
  opts: { kernel: boolean; netGuardBin?: string; args?: readonly string[] },
): Promise<{ code: number; lines: string[] }> {
  const lines: string[] = [];
  const orig = console.error;
  const savedHome = process.env["HOME"];
  const savedGuard = process.env["MANDU_NET_GUARD_BIN"];
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  process.env["HOME"] = home;
  if (opts.netGuardBin) process.env["MANDU_NET_GUARD_BIN"] = opts.netGuardBin;
  try {
    const code = await main(
      ["--no-scope", "--", goose, ...(opts.args ?? ["run", "--no-session", "-t", "say hi"])],
      {
        HOME: home, PATH: process.env["PATH"], PWD: join(home, "work"),
        MANDU_HOME: PRIVATE_MANDU_HOME, XDG_RUNTIME_DIR: stand.tmp,
        MANDU_ARBITER_SOCK: stand.sock, MANDU_PROXY_PORT: "0", MANDU_MODE: "secrets", MANDU_VERBOSE: "1",
        MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_FS_SYNC: "0",
        ...(opts.kernel ? {} : { MANDU_NO_KERNEL: "1" }),
        GOOSE_MODE: "auto", GOOSE_MODEL: MODEL,
        ...extraEnv,
      },
    );
    return { code, lines };
  } finally {
    console.error = orig;
    if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
    if (savedGuard === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = savedGuard;
  }
}

/** The same goose WITHOUT Mandu (a control), against the plain upstream.
 *  Asynchronous: the upstream answers from this process. */
export async function runGooseBare(goose: string, stand: Stand, home: string, extraEnv: Record<string, string>): Promise<{ code: number | null; stderr: string }> {
  const child = spawn(goose, ["run", "--no-session", "-t", "say hi"], {
    cwd: join(home, "work"), stdio: ["ignore", "ignore", "pipe"],
    env: { PATH: process.env["PATH"]!, HOME: home, GOOSE_PROVIDER: "anthropic", ANTHROPIC_HOST: stand.plainOrigin, GOOSE_MODE: "auto", GOOSE_MODEL: MODEL, ...extraEnv },
  });
  let stderr = "";
  child.stderr!.on("data", (c) => (stderr += String(c)));
  const code = await new Promise<number | null>((res) => {
    const t = setTimeout(() => { child.kill("SIGKILL"); res(null); }, 90_000);
    child.on("exit", (c) => { clearTimeout(t); res(c); });
  });
  return { code, stderr };
}

/** A private session bus with the Secret Service mock holding Goose's item
 *  (`{"ANTHROPIC_API_KEY": key}` under service `goose`, account `secrets`).
 *  Its socket sits in a short temp dir (a Unix socket path is at most 108
 *  bytes). `calls()` lists the mock's method calls so far. */
export async function startSecretService(key: string): Promise<{ address: string; calls(): string[]; close(): Promise<void> }> {
  const dir = mkdtempSync(join("/tmp", "mdu-ss-"));
  const address = `unix:path=${join(dir, "bus")}`;
  const daemon = spawn("dbus-daemon", ["--session", `--address=${address}`, "--nofork", "--nopidfile"], { stdio: "ignore", detached: true });
  const t0 = Date.now();
  while (!existsSync(join(dir, "bus"))) {
    if (Date.now() - t0 > 10_000) throw new Error("dbus-daemon never came up");
    await new Promise((r) => setTimeout(r, 50));
  }
  const log = join(dir, "calls.log");
  const mock = spawn("python3", [MOCK, address, log, JSON.stringify({ service: "goose", username: "secrets" }), JSON.stringify({ ANTHROPIC_API_KEY: key })], { stdio: "ignore", detached: true });
  const read = (): string[] => { try { return readFileSync(log, "utf8").split("\n").filter(Boolean); } catch { return []; } };
  while (!read().some((l) => l.startsWith("ready"))) {
    if (Date.now() - t0 > 15_000) throw new Error("the Secret Service mock never came up");
    await new Promise((r) => setTimeout(r, 50));
  }
  return {
    address,
    calls: () => read().filter((l) => !l.startsWith("ready")),
    close: async () => {
      await stopGroup(mock);
      await stopGroup(daemon);
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** A bare Unix listener standing in for a session bus: it counts the
 *  CLIENTS that dialed it, a connection that sends bytes (a D-Bus client
 *  opens with a NUL byte and `AUTH`), and closes each then (the client sees
 *  the bus fail, which goose's keyring code treats as no keyring). A
 *  connection that sends nothing is not counted: the guard's own probe of
 *  who listens (SO_PEERCRED, unix-policy.ts) is one. */
export async function startCountingBus(): Promise<{ address: string; connections(): number; close(): Promise<void> }> {
  const dir = mkdtempSync(join("/tmp", "mdu-bus-"));
  const path = join(dir, "bus");
  let n = 0;
  const srv: NetServer = createNetServer((c) => {
    c.once("data", () => { n++; c.destroy(); });
    c.on("error", () => { /* the peer went away */ });
  });
  await new Promise<void>((r) => srv.listen(path, () => r()));
  return {
    address: `unix:path=${path}`,
    connections: () => n,
    close: async () => {
      await new Promise<void>((r) => srv.close(() => r()));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
