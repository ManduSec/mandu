/**
 * OpenCode 2's kept shell output files under the REAL launcher stack
 * (supported-agents.md §2.3 item 10): the launcher's main(), its autostarted
 * anthropic-proxy, the REAL mandu-net-guard and landlock-net wrap, a REAL
 * ArbiterServer in `secrets`, and the REAL OpenCode 2 binary
 * (MANDU_OPENCODE_V2_BIN, else `opencode2` on PATH; a SKIP otherwise).
 * Keyless and offline: a dummy key and a scripted local Anthropic upstream
 * behind the proxy, so what the upstream receives is what a model would.
 *
 * OpenCode 2 writes EVERY shell command's output to
 * `$XDG_DATA_HOME/opencode/shell/<40 hex>/sh_<id>.out` and keeps it after the
 * run. Two launches on one HOME, each with a FRESH arbiter (nothing
 * registered, no session label):
 *
 *   run 1   the model asks `shell` to print a canary: OpenCode runs it and
 *           writes the .out file (Mandu's catalog location, never twinned:
 *           the agent still writes its own files);
 *   run 2   the model asks `read{path}` of run 1's file, then `shell cat`
 *           of it: the canary reaches the upstream in neither result (the
 *           read is denied by the path gate, the cat's output is masked as
 *           a `no-model` file's), and `shell` still works (its result came
 *           back, OpenCode wrote run 2's own .out).
 *
 * The launch is a mode `secrets` session with `--target shell` (the agent a
 * shell script that runs OpenCode 2) and the guard's allowance for OpenCode's
 * private server named by the test (MANDU_NET_GUARD_OWN_SERVER), as
 * opencode2-own-server.test.ts does: the product still refuses `mandu
 * opencode` for OpenCode 2 in `secrets`. Self-SKIPs without the guard bin
 * (scripts/build-native.sh), the OpenCode 2 binary, or Landlock.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { stateAxes } from "../../lib/axes.js";
import { pickGuard } from "../../lib/native-guard.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode

const HERE = dirname(fileURLToPath(import.meta.url));
const PICK = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
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
const LANDLOCK = (() => {
  try { return readFileSync("/sys/kernel/security/lsm", "utf8").includes("landlock"); } catch { return false; }
})();
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !OC2 ? "no OpenCode 2 binary: set MANDU_OPENCODE_V2_BIN (npm i --prefix <dir> @opencode/cli) or put `opencode2` on PATH"
  : !LANDLOCK ? "Landlock is not active on this kernel"
  : false;

const CANARY = `OC2-OUTFILE-CANARY-${process.pid}-5731`;

interface Hit { tools: number; results: string[] }
type Step = { name: string; input: Record<string, unknown> };

/** A scripted Anthropic upstream: a request that offers tools gets the next
 *  step's tool call (by the number of tool results so far), then text. */
async function upstream(steps: Step[]): Promise<{ url: string; hits: Hit[]; close: () => void }> {
  const hits: Hit[] = [];
  const srv = createHttpServer((req: IncomingMessage, res: ServerResponse) => {
    let body = "";
    req.on("data", (c: Buffer) => { body += c.toString("utf8"); });
    req.on("end", () => {
      if (!(req.url ?? "").includes("/messages")) { res.writeHead(404); res.end("{}"); return; }
      let j: { tools?: unknown[]; messages?: Array<{ content: unknown }> } = {};
      try { j = JSON.parse(body); } catch { /* not JSON */ }
      const results: string[] = [];
      for (const m of j.messages ?? []) {
        if (!Array.isArray(m.content)) continue;
        for (const b of m.content as Array<{ type: string; content?: unknown }>) if (b.type === "tool_result") results.push(JSON.stringify(b.content));
      }
      const tools = (j.tools ?? []).length;
      hits.push({ tools, results });
      const step = tools > 0 ? steps[results.length] : undefined;
      res.writeHead(200, { "content-type": "text/event-stream" });
      const ev = (t: string, d: unknown): void => { res.write(`event: ${t}\ndata: ${JSON.stringify(d)}\n\n`); };
      ev("message_start", { type: "message_start", message: { id: `msg_${hits.length}`, type: "message", role: "assistant", model: "claude-sonnet-4-5", content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } } });
      if (step) {
        ev("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: `toolu_${results.length}`, name: step.name, input: {} } });
        ev("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(step.input) } });
      } else {
        ev("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });
        ev("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "done" } });
      }
      ev("content_block_stop", { type: "content_block_stop", index: 0 });
      ev("message_delta", { type: "message_delta", delta: { stop_reason: step ? "tool_use" : "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } });
      ev("message_stop", { type: "message_stop" });
      res.end();
    });
  });
  srv.listen(0, "127.0.0.1");
  await once(srv, "listening");
  return { url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, hits, close: () => { srv.closeAllConnections(); srv.close(); } };
}

const SHELL_AGENT = (bin: string): string => `#!/bin/sh
export OPENCODE_CONFIG_CONTENT="{\\"enabled_providers\\":[\\"anthropic\\"],\\"provider\\":{\\"anthropic\\":{\\"options\\":{\\"baseURL\\":\\"$ANTHROPIC_BASE_URL/v1\\"}}}}"
exec ${bin} run --standalone --auto -m anthropic/claude-sonnet-4-5 go </dev/null
`;

/** Every .out file under `dir`, recursively. */
function outFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    let es: string[] = [];
    try { es = readdirSync(d); } catch { return; }
    for (const e of es) {
      const p = join(d, e);
      try {
        if (statSync(p).isDirectory()) walk(p);
        else if (p.endsWith(".out")) out.push(p);
      } catch { /* gone */ }
    }
  };
  walk(dir);
  return out;
}

/** One `secrets` launch on `home` with a fresh arbiter, the upstream
 *  scripted with `steps`. */
async function launch(rig: { dir: string; home: string; proj: string; bin: string }, steps: Step[], tag: string): Promise<{ code: number | null; hits: Hit[]; tail: string }> {
  const up = await upstream(steps);
  const adir = mkdtempSync(join(rig.dir, `arb-${tag}-`));
  const sock = join(adir, "arbiter.sock");
  const arbiter = new ArbiterServer({ socketPath: sock, dbPath: join(adir, "sym.db"), eventDir: join(adir, "events"), log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  try {
    const agent = join(rig.dir, "agent.sh");
    writeFileSync(agent, SHELL_AGENT(rig.bin), { mode: 0o755 });
    const env: Record<string, string> = {
      HOME: rig.home, PWD: rig.proj, MANDU_ARBITER_SOCK: sock, PATH: `${dirname(rig.bin)}${delimiter}${process.env["PATH"] ?? ""}`,
      MANDU_UPSTREAM: up.url, MANDU_HOME: join(rig.home, ".mandu"),
      MANDU_MODE: "secrets", XDG_RUNTIME_DIR: rig.dir, MANDU_TENANT: "test", MANDU_NET_GUARD_BIN: GUARD!, MANDU_VERBOSE: "1",
      XDG_CONFIG_HOME: join(rig.home, ".config"), XDG_DATA_HOME: join(rig.home, ".local", "share"),
      XDG_STATE_HOME: join(rig.home, ".local", "state"), XDG_CACHE_HOME: join(rig.home, ".cache"),
      ANTHROPIC_API_KEY: "sk-ant-test-dummy", OPENCODE_DISABLE_MODELS_FETCH: "1", OPENCODE_DISABLE_AUTOUPDATE: "1",
      npm_config_cache: join(rig.dir, "npm-cache"),
      MANDU_NET_GUARD_OWN_SERVER: realpathSync(OC2!),
    };
    const child = spawn(TSX, [RUN, "--no-scope", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--target", "shell", "--", agent], {
      cwd: rig.proj, env, stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stdout.resume();
    child.stderr.on("data", (c: Buffer) => { stderr += c.toString("utf8"); });
    const timer = setTimeout(() => child.kill("SIGKILL"), 240_000);
    const [code] = await once(child, "close") as [number | null];
    clearTimeout(timer);
    return { code, hits: [...up.hits], tail: stderr.split("\n").slice(-40).join("\n") };
  } finally {
    up.close();
    await arbiter.close();
  }
}

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});

test("an old shell output file (an earlier run, a fresh arbiter) reaches the model only masked, via read{path} and via shell cat; OpenCode still writes and runs its shell", { skip, timeout: 600_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-oc2-outfile-"));
  const home = join(dir, "home");
  const proj = join(dir, "proj");
  const binDir = join(dir, "bin");
  for (const d of [home, proj, binDir]) mkdirSync(d, { recursive: true });
  symlinkSync(OC2!, join(binDir, "opencode"));
  const rig = { dir, home, proj, bin: join(binDir, "opencode") };
  const shellDir = join(home, ".local", "share", "opencode", "shell");
  try {
    // run 1: a command prints the canary; OpenCode writes and keeps its .out
    const r1 = await launch(rig, [{ name: "shell", input: { command: `echo ${CANARY}` } }], "run1");
    assert.equal(r1.code, 0, r1.tail);
    assert.ok(r1.hits.some((h) => h.results.length > 0), `run 1's shell result came back\n${r1.tail}`);
    const kept = outFiles(shellDir).filter((f) => readFileSync(f, "utf8").includes(CANARY));
    assert.equal(kept.length, 1, `OpenCode wrote and kept the output file under Mandu: ${outFiles(shellDir).join(", ")}\n${r1.tail}`);
    const old = kept[0]!;

    // run 2: a fresh arbiter (nothing registered); the model reads the old file both ways
    const before = new Set(outFiles(shellDir));
    const r2 = await launch(rig, [
      { name: "read", input: { path: old } },
      { name: "shell", input: { command: `cat ${old}` } },
    ], "run2");
    assert.equal(r2.code, 0, r2.tail);
    const last = r2.hits.filter((h) => h.tools > 0).at(-1)!;
    assert.equal(last.results.length, 2, `both tool results came back\n${r2.tail}`);
    for (const h of r2.hits) for (const res of h.results) assert.ok(!res.includes(CANARY), `INVARIANT: the old output reached the model raw: ${res}\n${r2.tail}`);
    assert.match(last.results[1]!, /\$MDU:/, `the cat's output reached the model as a symbol: ${last.results[1]}`);
    assert.ok(outFiles(shellDir).some((f) => !before.has(f)), "OpenCode wrote run 2's own output file: its shell works under the catalog label");
    assert.ok(readFileSync(old, "utf8").includes(CANARY), "the old file is untouched (classified, never twinned)");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
