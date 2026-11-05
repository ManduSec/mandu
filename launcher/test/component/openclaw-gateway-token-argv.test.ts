/**
 * openclaw-gateway-token-argv — a Gateway token given on the command line
 * (`mandu openclaw gateway run --token <v>` / `--token=<v>`) under the REAL
 * launcher (`src/run.ts`, its own process), the REAL arbiter daemon and the
 * autostarted model proxy, with a stand-in `openclaw` that reports what it
 * was handed (confidentiality-plan-10 §11.4, "OpenClaw's Gateway
 * credentials: one stable placeholder"; openclaw-gateway-credentials.ts).
 *
 * The stand-in reads its own /proc/self/cmdline (what the agent's programs
 * could read), its environment and the run config, writes them to a file,
 * and sends them to the model as a tool result through the proxy the run
 * config names. Asserted, for both spellings: the raw token is in none of
 * them and in no model request; the command line carries the token's
 * placeholder, the same one for both spellings (stable per value); the run
 * config and the environment carry the same placeholder.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js";
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer as createHttpServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { chmodSync, closeSync, existsSync, lstatSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { once } from "node:events";
import { stateAxes } from "../axes.js";
import { stopGroup } from "../lib/tmp-dir.js";
import { sourceArbiterArgs, waitForPaths } from "../lib/arbiter-ready.js";

stateAxes("secrets"); // the shipped default mode: the token must reach no model and no agent program raw

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const ARBITER_DIR = join(REPO_ROOT, "arbiter");
const LAUNCHER_ROOT = join(REPO_ROOT, "launcher");
const TSX_LOADER = pathToFileURL(join(LAUNCHER_ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;
const TOKEN = "ocgw-argv-5e1f2a9c7d3b8e4f6a0c1d2e3f4a5b6c";
const linux = process.platform === "linux";

/** The stand-in `openclaw`: reports, then one model call carrying it all. */
const FAKE = `#!${process.execPath}
const fs = require("node:fs");
const args = process.argv.slice(2);
if (args.includes("--version")) { console.log("OpenClaw 2026.9.9 (stand-in)"); process.exit(0); }
let cmdline = "";
try { cmdline = fs.readFileSync("/proc/self/cmdline", "utf8").split("\\0").join(" "); } catch { cmdline = process.argv.join(" "); }
const configPath = process.env.OPENCLAW_CONFIG_PATH || "";
let config = "";
try { config = fs.readFileSync(configPath, "utf8"); } catch {}
const report = { cmdline, env: process.env, config };
fs.writeFileSync(process.env.MDU_FAKE_REPORT, JSON.stringify(report));
let base = "";
try { base = JSON.parse(config).models.providers.anthropic.baseUrl; } catch {}
if (!base) { console.error("stand-in: no anthropic route in the run config"); process.exit(3); }
const body = JSON.stringify({ model: "claude-haiku-4-5", stream: true, max_tokens: 32, messages: [
  { role: "user", content: "report" },
  { role: "assistant", content: [{ type: "tool_use", id: "toolu_rep", name: "exec", input: { command: "cat /proc/self/cmdline; env" } }] },
  { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_rep", content: JSON.stringify(report) }] },
] });
fetch(base.replace(/\\/$/, "") + "/v1/messages", { method: "POST", headers: { "content-type": "application/json", "x-api-key": "sk-ant-x" }, body })
  .then((r) => r.text()).then(() => process.exit(0), (e) => { console.error("stand-in:", e.message); process.exit(4); });
`;

let tmp: string;
let arbiter: ChildProcess | undefined;
let upstream: Server;
let origin = "";
const seen: string[] = [];

before(async () => {
  if (!linux) return;
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-ocgw-argv-")));
  const logFd = openSync(join(tmp, "arbiter.log"), "a");
  arbiter = spawn(process.execPath, sourceArbiterArgs(join(tmp, "arbiter.sock")), {
    cwd: ARBITER_DIR,
    env: { ...process.env, MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_HOME: join(tmp, "mandu-home"), MANDU_RUNTIME_DIR: join(tmp, "mandu") },
    stdio: ["ignore", logFd, logFd], detached: true,
  });
  closeSync(logFd);
  await waitForPaths(join(tmp, "arbiter.sock"), { what: "the arbiter", child: arbiter, logPath: join(tmp, "arbiter.log") });
  upstream = createHttpServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      seen.push(b);
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end([
        ["message_start", { type: "message_start", message: { id: "m", type: "message", role: "assistant", model: "claude-haiku-4-5", content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } } }],
        ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } }],
        ["message_stop", { type: "message_stop" }],
      ].map(([e, d]) => `event: ${e}\ndata: ${JSON.stringify(d)}\n\n`).join(""));
    });
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
  origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(async () => {
  upstream?.close();
  if (arbiter) await stopGroup(arbiter);
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

async function launch(spelling: "split" | "eq"): Promise<{ code: number | null; out: string; report: { cmdline: string; env: Record<string, string>; config: string } | null }> {
  const run = join(tmp, `run-${spelling}`);
  mkdirSync(join(run, "bin"), { recursive: true });
  mkdirSync(join(run, "state"), { recursive: true });
  mkdirSync(join(run, "mandu-launch"), { recursive: true, mode: 0o700 });
  writeFileSync(join(run, "bin", "openclaw"), FAKE);
  chmodSync(join(run, "bin", "openclaw"), 0o755);
  const config = join(run, "openclaw.json");
  writeFileSync(config, JSON.stringify({ gateway: { mode: "local", port: 18789 }, agents: { defaults: { model: { primary: "anthropic/claude-haiku-4-5" }, workspace: run } } }));
  const report = join(run, "report.json");
  const tokenArgs = spelling === "split" ? ["--token", TOKEN] : [`--token=${TOKEN}`];
  const env: Record<string, string | undefined> = {
    HOME: run, PATH: `${join(run, "bin")}${delimiter}${process.env["PATH"] ?? ""}`, PWD: run,
    MANDU_HOME: PRIVATE_MANDU_HOME, XDG_RUNTIME_DIR: run, MANDU_RUNTIME_DIR: join(run, "mandu-launch"),
    MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_PROXY_PORT: "0", MANDU_MODE: "secrets", MANDU_UPSTREAM: origin,
    MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0", MANDU_NO_MCP: "1",
    OPENCLAW_CONFIG_PATH: config, OPENCLAW_STATE_DIR: join(run, "state"), OPENCLAW_HOME: run, MDU_FAKE_REPORT: report,
    NO_COLOR: "1", TERM: "dumb",
  };
  const child = spawn(process.execPath, [
    "--import", TSX_LOADER, join(LAUNCHER_ROOT, "src", "run.ts"), "--no-scope", "--no-mcp", "--",
    "openclaw", "gateway", "run", "--port", "18789", ...tokenArgs, "--bind", "loopback",
  ], { cwd: run, env: env as NodeJS.ProcessEnv, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  child.stdout!.on("data", (d) => { out += String(d); });
  child.stderr!.on("data", (d) => { out += String(d); });
  const timer = setTimeout(() => child.kill("SIGKILL"), 180_000);
  const [code] = await once(child, "exit") as [number | null];
  clearTimeout(timer);
  return { code, out, report: existsSync(report) ? JSON.parse(readFileSync(report, "utf8")) : null };
}

test("`mandu openclaw gateway run --token <v>` and `--token=<v>`: the agent's command line, environment and run config carry the token's one placeholder; the raw token reaches no agent program and no model request (secrets axes, explicit)",
  { skip: linux ? false : "reads /proc/self/cmdline (Linux)", timeout: 400_000 }, async () => {
    const placeholders: string[] = [];
    for (const spelling of ["split", "eq"] as const) {
      seen.length = 0;
      const r = await launch(spelling);
      assert.equal(r.code, 0, `the launch ran (${spelling}): ${r.out.slice(-2500)}`);
      assert.ok(r.report, `the stand-in reported: ${r.out.slice(-1500)}`);
      const { cmdline, config } = r.report!;
      assert.ok(!cmdline.includes(TOKEN), `CONFIDENTIALITY VIOLATION: the raw token is in the agent's /proc/self/cmdline (${spelling}): ${cmdline}`);
      assert.ok(!JSON.stringify(r.report!.env).includes(TOKEN), "nor in its environment");
      assert.ok(!config.includes(TOKEN), "nor in its run config");
      const m = /\$MDU:nomodel_Env\[[0-9a-f]+\]\.OPENCLAW_GATEWAY_TOKEN/.exec(cmdline);
      assert.ok(m, `the command line carries the token's placeholder (${spelling}): ${cmdline}`);
      assert.ok(spelling === "split" ? cmdline.includes(` --token ${m![0]}`) : cmdline.includes(` --token=${m![0]}`), `in the same spelling: ${cmdline}`);
      placeholders.push(m![0]);
      assert.ok(seen.length >= 1, "the model call reached the upstream through the proxy");
      for (const b of seen) assert.ok(!b.includes(TOKEN), "CONFIDENTIALITY VIOLATION: the raw token reached the model");
    }
    assert.equal(placeholders[0], placeholders[1], "one placeholder per value: both spellings, both launches");

    // THE GUARD: no record of either launch holds the raw token. Every file
    // under the runs' directories (the run config, the runtime dir, the
    // stand-in's report), the arbiter's home (the session events NDJSON, the
    // admin events, its log) and the launcher's Mandu home (the launch
    // logs) is read; only the symbol store (`mandu.db*`), which keeps every
    // registered value by design and is hidden from the agent, may hold it.
    // A change that logs or records the launch's original argv fails here.
    const hits: string[] = [];
    const read: string[] = [];
    const walk = (d: string): void => {
      let names: string[] = [];
      try { names = readdirSync(d); } catch { return; }
      for (const n of names) {
        const p = join(d, n);
        let st;
        try { st = lstatSync(p); } catch { continue; }
        if (st.isDirectory()) { walk(p); continue; }
        if (!st.isFile() || /^mandu\.db(-wal|-shm|-journal)?$/.test(n)) continue;
        try {
          read.push(p);
          if (readFileSync(p).includes(TOKEN)) hits.push(p);
        } catch { /* unreadable: not a record */ }
      }
    };
    walk(tmp);
    walk(dirname(PRIVATE_MANDU_HOME));
    // The scan is not blind: it read the records it guards.
    assert.ok(read.some((p) => /\/events\/[^/]+\.ndjson$/.test(p)), `the session events were read: ${read.join(", ")}`);
    assert.ok(read.some((p) => /\/launch-logs\/[^/]+\.log$/.test(p)), `the launch logs were read: ${read.join(", ")}`);
    assert.deepEqual(hits, [], "CONFIDENTIALITY VIOLATION: a record of the launch holds the raw Gateway token");
  });
