/**
 * OpenCode 2 under the default kernel layer (supported-agents.md §2.3.1,
 * net-supervisor own_server.rs), across the REAL components: the launcher's
 * main(), the REAL mandu-net-guard and landlock-net wrap, a REAL
 * ArbiterServer, and the REAL OpenCode 2 binary (MANDU_OPENCODE_V2_BIN, else
 * `opencode2` on PATH; a SKIP with the reason otherwise). Keyless and
 * offline: a dummy key and a scripted local Anthropic upstream, which asks
 * for one `shell` tool call. That call runs a probe as an agent's command
 * would, inside the session:
 *
 *   - the client (`opencode run --standalone`) works: its private server
 *     binds an ephemeral loopback port (performed by the guard; the launch's
 *     port wrap grants no bind) and the client reaches it, so the model turn
 *     and the tool call happen;
 *   - the agent's command cannot reach the private server's port (its API
 *     would put a program's output into the conversation as the user's own
 *     message), nor a listener outside the tree standing in for the user's
 *     background service;
 *   - a nested `opencode run --standalone` and a nested `opencode run
 *     --server <the service>` fail without any model request.
 *
 * Two launches: `mandu opencode` in mode `off` (the product path; OpenCode 2
 * is supported by default), and a mode `secrets` session (`--target shell`,
 * the agent a shell script that runs OpenCode 2) where the test names the
 * guard's allowance itself (MANDU_NET_GUARD_OWN_SERVER), so it pins the
 * guard alone; the product path in `secrets` (the allowance, write-protect
 * and the config lockdown, opencode2-confidentiality.ts) is the replay
 * suite integration.replay-opencode2. A control launch without the
 * allowance shows the private server cannot start under the kernel layer
 * at all.
 *
 * Self-SKIPs without the guard bin (scripts/build-native.sh), the OpenCode 2
 * binary, or Landlock (manifest entry integration.opencode2-own-server).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer, type AddressInfo, type Server } from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";
import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { stateAxes } from "../../lib/axes.js";
import { pickGuard } from "../../lib/native-guard.js";

stateAxes("secrets"); // the second launch's; the first pins `off` on its own arbiter

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = resolve(HERE, "..", "..", "..", "interceptors", "target");
const PICK = pickGuard(TARGET);
const LAUNCHER = resolve(HERE, "..", "..", "..", "launcher");
const TSX = join(LAUNCHER, "node_modules", ".bin", "tsx");
const RUN = join(LAUNCHER, "src", "run.ts");
const GUARD = PICK.path;

function v2Bin(): string | null {
  const fromEnv = process.env["MANDU_OPENCODE_V2_BIN"];
  const cands = fromEnv ? [fromEnv] : (process.env["PATH"] ?? "").split(delimiter).filter(Boolean).map((d) => join(d, "opencode2"));
  const bin = cands.find((c) => existsSync(c));
  if (!bin) return null;
  const v = spawnSync(bin, ["--version"], { encoding: "utf8", timeout: 10_000 });
  return /\bv?2\.\d+\.\d+/.test(`${v.stdout}`) ? realpathSync(bin) : null;
}
const OC2 = process.platform === "linux" ? v2Bin() : null;
const LANDLOCK_NET = (() => {
  try { return Number(readFileSync("/sys/kernel/security/lsm", "utf8").includes("landlock")) === 1; } catch { return false; }
})();
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !OC2 ? "no OpenCode 2 binary: set MANDU_OPENCODE_V2_BIN (npm i --prefix <dir> @opencode/cli) or put `opencode2` on PATH"
  : !LANDLOCK_NET ? "Landlock is not active on this kernel"
  : false;

/** The agent's command: run by OpenCode 2's `shell` tool inside the session.
 *  argv: <results file> <service port>. Finds the private server (its
 *  parent's loopback listener), tries it and the service, then nests. */
const PROBE = `
const fs = require("fs"), net = require("net"), cp = require("child_process");
const [out, servicePort] = process.argv.slice(2);
const res = {};
const ppid = process.ppid;
const inodes = new Set(fs.readdirSync("/proc/" + ppid + "/fd").map((f) => { try { return fs.readlinkSync("/proc/" + ppid + "/fd/" + f); } catch { return ""; } })
  .map((l) => (/^socket:\\[(\\d+)\\]$/.exec(l) || [])[1]).filter(Boolean));
let port = 0;
for (const line of fs.readFileSync("/proc/net/tcp", "utf8").split("\\n").slice(1)) {
  const c = line.trim().split(/\\s+/);
  if (c[3] === "0A" && inodes.has(c[9])) port = parseInt(c[1].split(":")[1], 16);
}
res.serverPort = port;
const tryConnect = (p) => new Promise((done) => {
  const s = net.connect({ host: "127.0.0.1", port: p });
  s.setTimeout(5000, () => { s.destroy(); done("timeout"); });
  s.once("connect", () => { s.destroy(); done("connected"); });
  s.once("error", (e) => done(e.code || String(e)));
});
(async () => {
  res.server = port ? await tryConnect(port) : "no-port";
  res.service = await tryConnect(Number(servicePort));
  const nest = (args) => { const r = cp.spawnSync("opencode", args, { encoding: "utf8", timeout: 40000, stdio: ["ignore", "pipe", "pipe"] }); return r.status; };
  res.nestedStandalone = nest(["run", "--standalone", "-m", "anthropic/claude-sonnet-4-5", "nested"]);
  res.nestedServer = nest(["run", "--server", "http://127.0.0.1:" + servicePort, "-m", "anthropic/claude-sonnet-4-5", "nested"]);
  fs.writeFileSync(out, JSON.stringify(res));
})();
`;

interface Hit { session: string | undefined; tools: number; toolResult: string | null }

/** A scripted Anthropic upstream: the first request that offers `shell` gets a
 *  tool call running `command`; every other one gets a text turn. */
async function upstream(command: string): Promise<{ port: number; hits: Hit[]; close: () => void }> {
  const hits: Hit[] = [];
  let asked = false;
  const srv = createHttpServer((req: IncomingMessage, res: ServerResponse) => {
    let body = "";
    req.on("data", (c: Buffer) => { body += c.toString("utf8"); });
    req.on("end", () => {
      if (!(req.url ?? "").includes("/messages")) { res.writeHead(404); res.end("{}"); return; }
      let j: { tools?: Array<{ name: string }>; messages?: Array<{ content: unknown }> } = {};
      try { j = JSON.parse(body); } catch { /* not JSON */ }
      const tools = (j.tools ?? []).map((t) => t.name);
      const last = j.messages?.[j.messages.length - 1]?.content;
      const tr = Array.isArray(last) ? (last as Array<{ type: string; content?: unknown }>).find((b) => b.type === "tool_result") : undefined;
      const h = req.headers["x-mandu-session-id"];
      hits.push({ session: typeof h === "string" ? h : undefined, tools: tools.length, toolResult: tr ? JSON.stringify(tr.content) : null });
      const want = !asked && tools.includes("shell");
      if (want) asked = true;
      const message = { id: "msg_1", type: "message", role: "assistant", model: "claude-sonnet-4-5", stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } };
      res.writeHead(200, { "content-type": "text/event-stream" });
      const ev = (t: string, d: unknown): void => { res.write(`event: ${t}\ndata: ${JSON.stringify(d)}\n\n`); };
      ev("message_start", { type: "message_start", message: { ...message, content: [], stop_reason: null } });
      if (want) {
        const input = { command, description: "probe" };
        ev("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_1", name: "shell", input: {} } });
        ev("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(input) } });
      } else {
        ev("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });
        ev("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "done" } });
      }
      ev("content_block_stop", { type: "content_block_stop", index: 0 });
      ev("message_delta", { type: "message_delta", delta: { stop_reason: want ? "tool_use" : "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } });
      ev("message_stop", { type: "message_stop" });
      res.end();
    });
  });
  srv.listen(0, "127.0.0.1");
  await once(srv, "listening");
  return { port: (srv.address() as AddressInfo).port, hits, close: () => { srv.closeAllConnections(); srv.close(); } };
}

/** Linux: the pids whose environment carries `marker`. */
function pidsWithMarker(marker: string): number[] {
  const out: number[] = [];
  for (const d of readdirSync("/proc")) {
    if (!/^\d+$/.test(d) || Number(d) === process.pid) continue;
    try { if (readFileSync(`/proc/${d}/environ`, "latin1").includes(marker)) out.push(Number(d)); } catch { /* gone */ }
  }
  return out;
}

interface Outcome { code: number | null; error: string; hits: Hit[]; probe: Record<string, unknown> | null; lines: string[] }

/** One launch: `how` builds main()'s argv and the extra env from the rig. */
async function launch(mode: "off" | "secrets", how: (r: { dir: string; bin: string; probe: string; out: string }) => { argv: string[]; env: Record<string, string> }): Promise<Outcome> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-oc2-own-"));
  const home = join(dir, "home");
  const proj = join(dir, "proj");
  const bin = join(dir, "bin");
  mkdirSync(home, { recursive: true });
  mkdirSync(proj, { recursive: true });
  mkdirSync(bin, { recursive: true });
  // `opencode` as npm installs it: a link to the binary.
  symlinkSync(OC2!, join(bin, "opencode"));
  const probe = join(dir, "probe.js");
  writeFileSync(probe, PROBE);
  const out = join(proj, "probe-result.json");
  // The user's background service, standing in: a listener outside the tree.
  const service: Server = createServer((c) => c.end("service"));
  service.listen(0, "127.0.0.1");
  await once(service, "listening");
  const servicePort = (service.address() as AddressInfo).port;
  const up = await upstream(`node ${probe} ${out} ${servicePort}`);
  const sock = join(dir, "arbiter.sock");
  const off = mode === "off";
  const arbiter = new ArbiterServer({ socketPath: sock, dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {}, confidentiality: !off, integrity: false });
  await arbiter.listen();
  const marker = `MANDU_TEST_OC2_OWN=${randomUUID()}`;
  try {
    const { argv, env } = how({ dir, bin: join(bin, "opencode"), probe, out });
    // The real CLI entry (run.ts → main()) in a child with stdin closed:
    // `opencode run` waits for a piped stdin to end, and the runner's never
    // does. The child gets exactly this environment.
    const childEnv: Record<string, string> = {
      HOME: home, PWD: proj, MANDU_ARBITER_SOCK: sock, PATH: `${bin}${delimiter}${process.env["PATH"] ?? ""}`,
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_PROXY_PORT: String(up.port), MANDU_HOME: join(home, ".mandu"),
      MANDU_MODE: mode, XDG_RUNTIME_DIR: dir, MANDU_TENANT: "test", MANDU_NET_GUARD_BIN: GUARD!, MANDU_VERBOSE: "1",
      XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local", "share"),
      XDG_STATE_HOME: join(home, ".local", "state"), XDG_CACHE_HOME: join(home, ".cache"),
      ANTHROPIC_API_KEY: "sk-ant-test-dummy", OPENCODE_DISABLE_MODELS_FETCH: "1", OPENCODE_DISABLE_AUTOUPDATE: "1",
      npm_config_cache: join(dir, "npm-cache"),
      [marker.split("=")[0]!]: marker.split("=")[1]!,
      ...env,
    };
    const child = spawn(TSX, [RUN, "--no-scope", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", ...argv], {
      cwd: proj, env: childEnv, stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stdout.resume();
    child.stderr.on("data", (c: Buffer) => { stderr += c.toString("utf8"); });
    const timer = setTimeout(() => child.kill("SIGKILL"), 240_000);
    const [code] = await once(child, "close") as [number | null];
    clearTimeout(timer);
    const lines = stderr.split("\n");
    // Nothing the launch started outlives it (the private server stops with its client).
    let left = pidsWithMarker(marker);
    for (let i = 0; i < 50 && left.length > 0; i++) { await sleep(100); left = pidsWithMarker(marker); }
    for (const p of left) { try { process.kill(p, "SIGKILL"); } catch { /* gone */ } }
    assert.deepEqual(left, [], "no process of the launch is left");
    const probeOut = existsSync(out) ? JSON.parse(readFileSync(out, "utf8")) as Record<string, unknown> : null;
    return { code, error: "", hits: [...up.hits], probe: probeOut, lines };
  } finally {
    up.close();
    service.close();
    await arbiter.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** What every working launch must show: the turn and the tool call went
 *  through Mandu's routing, and the agent's command reached nothing. */
function assertConfined(o: Outcome, label: string, routedByMandu: boolean): void {
  const ctx = `${label}\n${o.error}\n${o.lines.slice(-40).join("\n")}`;
  assert.equal(o.error, "", ctx);
  assert.equal(o.code, 0, ctx);
  const turns = o.hits.filter((h) => h.tools > 0);
  assert.ok(turns.length >= 2, `the turn, its tool call and the follow-up reached the routing (${o.hits.length} requests)\n${ctx}`);
  // Mandu's routing config carries the session header; the shell-target
  // launch's agent writes its own config (the routing is not under test there).
  if (routedByMandu) assert.ok(o.hits.every((h) => h.session), "every request carries the session header");
  assert.ok(turns.some((h) => h.toolResult !== null), "the tool's result came back");
  assert.ok(o.probe, `the agent's command ran\n${ctx}`);
  assert.ok(Number(o.probe!["serverPort"]) > 0, `the command found the private server's port: ${JSON.stringify(o.probe)}`);
  assert.equal(o.probe!["server"], "EACCES", `the agent's command cannot reach the private server: ${JSON.stringify(o.probe)}`);
  assert.equal(o.probe!["service"], "EACCES", `nor the user's service: ${JSON.stringify(o.probe)}`);
  assert.notEqual(o.probe!["nestedStandalone"], 0, "a nested `opencode run --standalone` fails");
  assert.notEqual(o.probe!["nestedServer"], 0, "a nested `opencode run --server <the service>` fails");
  // The nested runs made no model request: one turn of the launch's own
  // (tool call, then its follow-up) plus OpenCode's title request at most.
  assert.ok(o.hits.length <= 3, `no model request from a nested run (${o.hits.length})`);
}

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});

test("mode off, the product path: `mandu opencode` runs OpenCode 2 under the kernel layer; the agent's command reaches neither its private server nor the user's service", { skip, timeout: 300_000 }, async () => {
  const o = await launch("off", (r) => ({
    argv: ["--no-mcp", "--", r.bin, "run", "-m", "anthropic/claude-sonnet-4-5", "--auto", "probe"],
    env: {},
  }));
  assertConfined(o, "mode off", true);
  assert.ok(o.lines.some((l) => /net-guard LIVE/.test(l)), "the guard ran");
  assert.ok(o.lines.some((l) => /landlock-net LIVE/.test(l)), "the port wrap ran");
  assert.ok(o.lines.some((l) => /the agent's private server/.test(l)), "the launch named the private server");
});

const SHELL_AGENT = (bin: string): string => `#!/bin/sh
export OPENCODE_CONFIG_CONTENT="{\\"enabled_providers\\":[\\"anthropic\\"],\\"provider\\":{\\"anthropic\\":{\\"options\\":{\\"baseURL\\":\\"$ANTHROPIC_BASE_URL/v1\\"}}}}"
exec ${bin} run --standalone --auto -m anthropic/claude-sonnet-4-5 probe </dev/null
`;

test("mode secrets (the allowance named by the test): the client works under the kernel layer, and only the client reaches its server", { skip, timeout: 300_000 }, async () => {
  const o = await launch("secrets", (r) => {
    const agent = join(r.dir, "agent.sh");
    writeFileSync(agent, SHELL_AGENT(r.bin), { mode: 0o755 });
    return { argv: ["--target", "shell", "--", agent], env: { MANDU_NET_GUARD_OWN_SERVER: realpathSync(OC2!) } };
  });
  assertConfined(o, "mode secrets", false);
});

test("control: without the allowance the private server cannot start under the kernel layer (fail-closed: no model request)", { skip, timeout: 300_000 }, async () => {
  const o = await launch("secrets", (r) => {
    const agent = join(r.dir, "agent.sh");
    writeFileSync(agent, SHELL_AGENT(r.bin), { mode: 0o755 });
    return { argv: ["--target", "shell", "--", agent], env: {} };
  });
  assert.equal(o.hits.length, 0, "nothing reached the routing");
  assert.equal(o.probe, null, "no tool ran");
});
