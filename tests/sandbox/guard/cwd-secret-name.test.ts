/**
 * cwd-secret-name — the residual of plan 13 D4's "a holder's working-directory
 * file" (!554), checked, not inferred: a holder that names a directory AFTER
 * the secret and `cd`s into it.
 *
 *   the real mandu-net-guard around an "agent" (a node copy, the launch's
 *   `agentExe`) running Bash calls the Claude Code 2.1.288 way (`<command> &&
 *   pwd -P >| /tmp/claude-<n>-cwd`, the cwd file read back after the call),
 *   in `secrets`, a real ArbiterServer (`.env`: no-model, reader `mdu-holder`,
 *   built and pinned by the test), and both model proxies in their
 *   production wiring: the AnthropicProxy over HTTP (Claude Code) and the
 *   openai-proxy's rewrite (Codex's `exec_command`).
 *
 *   - call 0 (tainted): `d=$(mdu-holder .env | head -1 | cut -d= -f2)`, then
 *     `mkdir` and `cd` into `<names>/$d`: the RAW registered value as a
 *     directory name. Its shell writes that path into the cwd file, whose
 *     twin is its own text since !554, so the agent's next call runs there;
 *   - call 1 (clean): `pwd`, whose output holds the raw value;
 *   - call 2 (tainted): the same with the value base64-encoded;
 *   - call 3 (clean): `pwd` again;
 *   - calls 4 and 5 (clean): `ls` of the base64 and the raw names'
 *     directories, the names residual of plan 13 §4.9 that needs no cwd
 *     file at all (the controls).
 *
 * The oracle: the raw value never reaches either model's wire (the proxies'
 * registered-value scan masks a clean call's output that carries it
 * verbatim). The base64 name is NOT caught, exactly as the `ls` control is
 * not: the names channel §4.9 leaves uncovered, which the cwd file only
 * delivers without an `ls`. Pinned so a change in either shows.
 *
 * SKIPs only where the guard is not built, the C compiler is missing, or the
 * kernel lacks seccomp user notification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { rewriteRequest as rewriteResponses } from "../../../interceptors/openai-proxy/src/rewrite-request.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../../interceptors/openai-proxy/src/arbiter-client.js";
import type { ResponsesRequest } from "../../../interceptors/openai-proxy/src/responses-types.js";
import { agentNodeCopy, pickGuard } from "../../lib/native-guard.js";
import { holderReader, holderSkip } from "../../lib/holder-reader.js";
import { stateAxes } from "../../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : holderSkip() !== false ? holderSkip()
  : false;

/** The secret value: a credential's shape, long enough for the value scan. */
const CANARY = `sk_live_CWDNAME${process.pid}x7Qz`;
const B64 = Buffer.from(CANARY).toString("base64").replaceAll("/", "_").replaceAll("+", "-");

/** The agent: its Bash calls the Claude Code 2.1.288 way, each in the
 *  directory the previous call's cwd file named. */
const AGENT = `import { spawnSync } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import { isAbsolute } from "node:path";
const cfg = JSON.parse(process.argv[2]);
fs.mkdirSync(cfg.tasks, { recursive: true });
let cwd = cfg.cwd;
const calls = [];
for (const [i, command] of cfg.commands.entries()) {
  const out = cfg.tasks + "/b" + i + ".output";
  const fd = fs.openSync(out, "w");
  const r = spawnSync("bash", ["-c", command], { cwd, stdio: ["ignore", fd, fd], timeout: 60000 });
  fs.closeSync(fd);
  const call = { status: r.status, ranIn: cwd };
  try { call.output = await fsp.readFile(out, "utf8"); } catch (e) { call.output = "ERR " + e.message; }
  try {
    const back = (await fsp.readFile(cfg.cwdFiles[i], "utf8")).trim();
    if (isAbsolute(back) && (await fsp.stat(back)).isDirectory()) cwd = back;
  } catch {}
  calls.push(call);
}
process.stdout.write("AGENT_OUT " + JSON.stringify({ calls }) + "\\n");
`;

function post(port: number, body: unknown, session: string): Promise<number> {
  return new Promise((ok, fail) => {
    const req = http.request({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => { res.resume(); res.on("end", () => ok(res.statusCode ?? 0)); });
    req.on("error", fail);
    req.end(JSON.stringify(body));
  });
}

function runGuarded(argv: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; status: number | null }> {
  return new Promise((ok) => {
    const child = spawn(GUARD.path!, ["--allow", "127.0.0.0/8:*", "--", ...argv], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += String(c)));
    child.stderr.on("data", (c) => (stderr += String(c)));
    const timer = setTimeout(() => child.kill("SIGKILL"), 120_000);
    child.on("close", (status) => { clearTimeout(timer); ok({ stdout, stderr, status }); });
  });
}

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("plan 13 D4 residual LIVE: a directory named with the RAW secret and cd'd into reaches neither model through the next call's pwd; a base64 name passes exactly as the ls control does (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-cwdn-")));
  const work = join(tmp, "work");
  const names = join(tmp, "names");
  const names64 = join(tmp, "names64");
  mkdirSync(work, { recursive: true });
  mkdirSync(names, { recursive: true });
  mkdirSync(names64, { recursive: true });
  const secret = join(work, ".env");
  writeFileSync(secret, `STRIPE_KEY=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  const holder = holderReader(tmp)!;
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [${holder.yaml}]\n`);
  const sock = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  const human = new ArbiterClient(join(tmp, "human", "h.sock"));
  await human.connect();
  const session = `cwdn-${process.pid}`;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client, human), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const reg = await client.registerSecret({ path: secret, home: tmp });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    const twin = join(tmp, "env.twin");
    writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
    const agentNode = agentNodeCopy(tmp);
    const guardDir = join(tmp, "guard");
    mkdirSync(guardDir, { recursive: true });
    const secretPolicy = join(guardDir, "secret-policy.json");
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: secret, twin, level: "no-model" }] }));

    const value = `mdu-holder ${secret} | head -1 | cut -d= -f2`;
    const commands = [
      `d="${names}/$(${value})"; mkdir -p "$d" && cd "$d"`,
      `pwd`,
      `d="${names64}/$(${value} | tr -d '\\n' | /usr/bin/base64 -w0 | tr '/+' '_-')"; mkdir -p "$d" && cd "$d"`,
      `pwd`,
      `ls ${names64}`,
      `ls ${names}`,
    ];
    const cwdFiles = commands.map((_, i) => join(tmp, `claude-n${i}-cwd`));
    const full = commands.map((c, i) => `${c} && pwd -P >| ${cwdFiles[i]}`);
    const ids = full.map((_, i) => `toolu_cwdn_${i}`);
    for (const [i, id] of ids.entries()) await human.recordCallCommand({ callId: id, command: full[i]!, sessionKey: session });
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT);
    const run = await runGuarded([agentNode, agentJs, JSON.stringify({ commands: full, cwdFiles, cwd: work, tasks: join(tmp, "claude-uid", "proj", "sess", "tasks") })],
      { ...process.env, HOME: tmp, PATH: `${join(tmp, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy });
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as { calls: Array<{ status: number | null; ranIn: string; output: string }> };
    const calls = got.calls;
    const dump = JSON.stringify(got).replaceAll(CANARY, "<CANARY>").replaceAll(B64, "<B64>");

    // Preconditions (the human's side): the holder made both directories,
    // and the agent's next calls ran in them, so their `pwd` carries the name.
    assert.equal(calls[0]!.status, 0, dump);
    assert.equal(calls[1]!.ranIn, join(names, CANARY), `the cwd file delivered the raw-named directory (!554): ${dump}`);
    assert.ok(calls[1]!.output.includes(CANARY), "the clean call's pwd holds the raw value (so a leak is possible)");
    assert.equal(calls[3]!.ranIn, join(names64, B64), dump);
    assert.ok(calls[4]!.output.includes(B64) && calls[5]!.output.includes(CANARY), "the ls controls list each name");

    // Claude Code: the AnthropicProxy over HTTP.
    const tools = [{ name: "Bash", input_schema: { type: "object" } }];
    const n = upstream.requests.length;
    assert.equal(await post(port, { model: "claude-haiku-4-5", stream: true, max_tokens: 512, tools, messages: [
      { role: "user", content: "go" },
      { role: "assistant", content: ids.map((id, i) => ({ type: "tool_use", id, name: "Bash", input: { command: full[i] } })) },
      { role: "user", content: ids.map((id, i) => ({ type: "tool_result", tool_use_id: id, content: calls[i]!.output })) },
    ] }, session), 200);
    const claude = (upstream.requests[n]!.json() as { messages: Array<{ content: Array<{ content: unknown }> }> }).messages[2]!.content.map((x) => JSON.stringify(x.content));
    // Codex: the openai-proxy's rewrite of exec_command outputs.
    const adapter = new OpenAiProxyArbiterAdapter(client, human);
    const input: unknown[] = ids.flatMap((id, i) => [
      { type: "function_call", call_id: id, name: "exec_command", arguments: JSON.stringify({ cmd: full[i] }) },
      { type: "function_call_output", call_id: id, output: calls[i]!.output },
    ]);
    const { request } = await rewriteResponses({ model: "m", input } as unknown as ResponsesRequest, { arbiter: adapter, sessionKey: session, skipPromptInjection: true });
    const codex = ids.map((id) => JSON.stringify((request.input as Array<Record<string, unknown>>).find((x) => x["type"] === "function_call_output" && x["call_id"] === id)!["output"]));
    const seen = (side: string[]): string => side.map((s, i) => `${i}: ${s.replaceAll(CANARY, "<CANARY>").replaceAll(B64, "<B64>")}`).join("\n");

    for (const [name, side] of [["claude", claude], ["codex", codex]] as const) {
      // THE ORACLE: the raw value reaches neither model, the cwd's `pwd` included.
      assert.ok(!side[1]!.includes(CANARY), `CONFIDENTIALITY VIOLATION (${name}): the clean pwd in a raw-named directory reached the model:\n${seen(side)}`);
      assert.ok(!side.some((s) => s.includes(CANARY)), `CONFIDENTIALITY VIOLATION (${name}): the raw value reached the model:\n${seen(side)}`);
      assert.ok(!side[5]!.includes(CANARY), `${name}: the raw name is caught in the ls control too:\n${seen(side)}`);
      // The residual, pinned: a transformed name passes, through the cwd
      // file and through ls alike (plan 13 §4.9's names channel).
      assert.ok(side[3]!.includes(B64) && side[4]!.includes(B64), `${name}: the base64 name is the uncovered names channel, the same through the cwd file as through ls (pinned, §4.9):\n${seen(side)}`);
    }
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(CANARY), "no raw value on the Claude wire");
  } finally {
    await proxy.close();
    client.close();
    human.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
