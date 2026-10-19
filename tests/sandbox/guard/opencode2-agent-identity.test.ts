/**
 * OpenCode 2's agent identity under the guard (supported-agents.md §2.3.1,
 * "The agent is the server"; confidentiality-plan-13 D2 / D7), across the
 * REAL components in mode `secrets`: the launcher (child process, `--target
 * opencode` on a link to the binary under another name, so the product's
 * OpenCode 2 refusal in `secrets` is not met: the wrapper contract, the
 * guard's private-server allowance named by the test), the REAL
 * mandu-net-guard and landlock-net wrap, the launcher-started model proxy
 * (production wiring), a REAL ArbiterServer with its human plane and a
 * policy.yaml on disk, and the REAL OpenCode 2 binary (MANDU_OPENCODE_V2_BIN,
 * else `opencode2` on PATH; SKIP with the reason otherwise). Keyless and
 * offline: a scripted local upstream behind the proxy.
 *
 * Under OpenCode 2 the process that makes the model calls and runs the
 * tools is the private SERVER (`opencode serve --stdio`, the client's
 * child), not the first-started client. The scripted model asks for one
 * `shell` call that runs a pinned reader of a labelled file (no output
 * rule: its output is secret). Asserted:
 *
 *   - the call is bound by the call-root recorder (the shell the server
 *     spawned is a call root: the server is the agent), so callTaint answers
 *     from the call's own tree (`evidence: "tree"`, a root);
 *   - the result reaches the scripted model only as a symbol: no request
 *     body carries the canary;
 *   - the server is not made a secret holder by reading the reader's output
 *     (D2): its next model request goes through, so the turn completes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { type AddressInfo } from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { stateAxes } from "../../lib/axes.js";
import { pickGuard } from "../../lib/native-guard.js";
import { holderReader, holderSkip } from "../../lib/holder-reader.js";

stateAxes("secrets"); // confidentiality ON: the axis under test

const HERE = dirname(fileURLToPath(import.meta.url));
const PICK = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const GUARD = PICK.path;
const LAUNCHER = resolve(HERE, "..", "..", "..", "launcher");
const TSX = join(LAUNCHER, "node_modules", ".bin", "tsx");
const RUN = join(LAUNCHER, "src", "run.ts");
const CANARY = "OC2-IDENTITY-CANARY-7319";

function v2Bin(): string | null {
  const fromEnv = process.env["MANDU_OPENCODE_V2_BIN"];
  const cands = fromEnv ? [fromEnv] : (process.env["PATH"] ?? "").split(delimiter).filter(Boolean).map((d) => join(d, "opencode2"));
  const bin = cands.find((c) => existsSync(c));
  if (!bin) return null;
  const v = spawnSync(bin, ["--version"], { encoding: "utf8", timeout: 10_000 });
  return /\bv?2\.\d+\.\d+/.test(`${v.stdout}`) ? realpathSync(bin) : null;
}
const OC2 = process.platform === "linux" ? v2Bin() : null;
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !OC2 ? "no OpenCode 2 binary: set MANDU_OPENCODE_V2_BIN (npm i --prefix <dir> @opencode/cli) or put `opencode2` on PATH"
  : holderSkip();

interface Req { body: string; tools: number; toolResult: string | null }

/** A scripted Anthropic upstream: the first request offering `shell` gets one
 *  tool call (`toolu_oc2raw`) running `command`; every other a text turn. */
async function upstream(command: string): Promise<{ url: string; reqs: Req[]; close: () => void }> {
  const reqs: Req[] = [];
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
      reqs.push({ body, tools: tools.length, toolResult: tr ? JSON.stringify(tr.content) : null });
      const want = !asked && tools.includes("shell");
      if (want) asked = true;
      const message = { id: "msg_1", type: "message", role: "assistant", model: "claude-sonnet-4-5", stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } };
      res.writeHead(200, { "content-type": "text/event-stream" });
      const ev = (t: string, d: unknown): void => { res.write(`event: ${t}\ndata: ${JSON.stringify(d)}\n\n`); };
      ev("message_start", { type: "message_start", message: { ...message, content: [], stop_reason: null } });
      if (want) {
        const input = { command, description: "read the file" };
        ev("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_oc2raw", name: "shell", input: {} } });
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
  return { url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, reqs, close: () => { srv.closeAllConnections(); srv.close(); } };
}

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});

test("OpenCode 2 in `secrets`: the server is the agent — its shell call is bound by the call-root recorder, the reader's secret output reaches the model only as a symbol, and the server keeps its model connection", { skip, timeout: 300_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-oc2-id-"));
  const home = join(dir, "home");
  const proj = join(dir, "proj");
  const bin = join(dir, "bin");
  for (const d of [home, proj, bin]) mkdirSync(d, { recursive: true });
  // A link under another name: `--target opencode` takes it as a wrapper
  // (not probed, argv untouched), and the agent executable resolves to
  // the binary itself.
  const wrap = join(bin, "oc-wrap");
  symlinkSync(OC2!, wrap);
  const secret = join(proj, "secret.txt");
  writeFileSync(secret, `token=${CANARY}\n`);
  const holder = holderReader(dir)!;
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${secret}`, "    level: no-model", `    readers: [${holder.yaml}]`, ""].join("\n"));
  // The pause outlasts the model proxy's keep-alive (5 s), so the follow-up
  // request needs a NEW connection from the server: one a secret holder is
  // refused. Before the server was the agent, the reader's output made it a
  // holder, and the turn stopped there.
  const up = await upstream(`${holder.path} secret.txt; sleep 7`);
  const sock = join(dir, "arbiter.sock");
  const human = join(dir, "human", "h.sock");
  const arbiter = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  try {
    const env: Record<string, string> = {
      HOME: home, PWD: proj, PATH: `${bin}${delimiter}${process.env["PATH"] ?? ""}`, MANDU_ARBITER_SOCK: sock,
      MANDU_UPSTREAM: up.url, MANDU_HOME: join(home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: dir, MANDU_TENANT: "test",
      MANDU_NET_GUARD_BIN: GUARD!, MANDU_NET_GUARD_OWN_SERVER: OC2!, MANDU_VERBOSE: "1",
      XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local", "share"),
      XDG_STATE_HOME: join(home, ".local", "state"), XDG_CACHE_HOME: join(home, ".cache"),
      ANTHROPIC_API_KEY: "sk-ant-test-dummy", OPENCODE_DISABLE_MODELS_FETCH: "1", OPENCODE_DISABLE_AUTOUPDATE: "1",
      npm_config_cache: join(dir, "npm-cache"),
    };
    const child = spawn(TSX, [RUN, "--no-scope", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--no-mcp", "--target", "opencode", "--",
      wrap, "run", "--standalone", "--auto", "-m", "anthropic/claude-sonnet-4-5", "read secret.txt"], { cwd: proj, env, stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    child.stdout.resume();
    child.stderr.on("data", (c: Buffer) => { stderr += c.toString("utf8"); });
    const timer = setTimeout(() => child.kill("SIGKILL"), 240_000);
    const [code] = await once(child, "close") as [number | null];
    clearTimeout(timer);
    const ctx = `exit ${code}; ${up.reqs.length} model requests\n${stderr.split("\n").slice(-60).join("\n")}`;
    // The model never saw the canary, in any request.
    for (const r of up.reqs) assert.ok(!r.body.includes(CANARY), `the canary reached the model\n${ctx}`);
    const results = up.reqs.filter((r) => r.toolResult !== null);
    assert.ok(results.length >= 1, `the tool call's result reached the model (the server kept its model connection)\n${ctx}`);
    assert.match(results[0]!.toolResult!, /\$MDU:/, `the result reached the model as a symbol\n${ctx}`);
    // Masked from the call's own tree (the reader named), not the session's
    // fallback ("could not tie this shell call to the processes that ran it").
    assert.match(results[0]!.toolResult!, /mdu-holder read /, `masked from the call's tree\n${ctx}`);
    assert.doesNotMatch(results[0]!.toolResult!, /could not tie this shell call/, ctx);
    assert.equal(code, 0, ctx);
    // The call is bound by the recorder: its tree is the evidence.
    const client = new ArbiterClient(human);
    await client.connect();
    try {
      const t = await client.callTaint("toolu_oc2raw");
      assert.equal(t.evidence, "tree", `callTaint bound the call to its shell: ${JSON.stringify(t)}`);
      assert.ok(t.root, "a root");
      assert.ok(t.files.includes(secret), `the reader's raw read is in the call's tree: ${JSON.stringify(t)}`);
    } finally {
      client.close();
    }
  } finally {
    up.close();
    await arbiter.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
