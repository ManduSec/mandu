/**
 * call-tree — plan 13 D7 under the REAL guard: the model exit's fold over a
 * tool call's process tree (plan 10 §3.2, `callTaint`) finds the right tree,
 * and the whole of it, or masks.
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around an
 *   "agent" process (a copy of node, the launch's `agentExe`), in `secrets`,
 *   against a real ArbiterServer loaded with a policy.yaml (`x.txt`:
 *   no-model, reader `mdu-holder`: a reader the test builds and pins by path and
 *   hash, tests/lib/holder-reader.ts, on the agent's PATH; until 2026-10-03
 *   the reader was `cat` itself, which admits nothing since plan 13 D8's
 *   "printers admit nothing"). Every reader's output is hex-encoded so no value
 *   scan can see it, and every command names the file by a glob, so the
 *   path-derived precaution (the command NAMES a secret file) cannot be what
 *   masks it. Two runs:
 *
 *   1. Fork without exec. The agent runs its Bash calls as Codex does
 *      (`bash -c <command>`), each a reader inside a subshell that never
 *      execs: `( mdu-holder ./x.tx?; true ) | od …`, `echo "$(mdu-holder ./x.tx?; true)" |
 *      od …`, `{ mdu-holder ./x.tx?; true; } | od …`; `( mdu-holder ./x.tx? ) | od …` (bash
 *      execs a lone command in place: linked before the fix too) and
 *      `echo clean-d7` are the controls. Each result goes through the
 *      AnthropicProxy over HTTP in its production wiring. Before the fix the
 *      guard reported only `mdu-holder → subshell`, nothing linked the subshell to
 *      the root, and the three hex dumps reached the model raw.
 *
 *   2. The call-root recorder, end to end. The agent behaves as Claude Code:
 *      it talks to the real AnthropicProxy (a scripted model behind it), runs
 *      each tool_use in a shell of its own exactly as Claude Code spawns it
 *      (`bash -c 'source … && eval '<command>' && pwd -P >| …'`), the turn's
 *      calls concurrently, and sends the results back. Turn 1: a subshell
 *      reader, a command-substitution reader, two calls with the SAME text
 *      (`if { set -C; : > lock; } …; then mdu-holder …; else echo no-lock; fi`:
 *      whichever runs first reads) and a clean call. Turn 2: a reader the agent runs through
 *      a wrapper shell, so no exec of the agent carries its command (an
 *      unknown tree). Before the fix every reader's output reached the model
 *      raw (Claude Code's eval-wrapped shell never matched a command; the
 *      lookup fell to "the most recent exec of this command", which a
 *      pipeline's leaf never is).
 *
 * The oracle: no form of the file's bytes reaches the model; every reader's
 * result, both same-text results, and the unknown tree's are masked whole;
 * the clean calls stay raw. SKIPs only where the guard is not built or the
 * kernel lacks seccomp user notification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, sseEvent } from "../../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { agentNodeCopy, pickGuard } from "../../lib/native-guard.js";
import { holderReader, holderSkip } from "../../lib/holder-reader.js";
import { stateAxes } from "../../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const skip = process.platform !== "linux" ? "Linux only" : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : holderSkip() !== false ? holderSkip() : false;

const CANARY = `X_TXT_D7_CANARY_${process.pid}`;
const hex = (s: string): string => Buffer.from(s).toString("hex");
const HEX = " | od -An -tx1 | tr -d ' \\n'";
const FILE_HEX = hex(`token=${CANARY}\n`);

/** Run 1's agent: each Bash call as Codex runs it, what each returned. */
const AGENT_CODEX = `import { spawnSync } from "node:child_process";
const cfg = JSON.parse(process.argv[2]);
const out = {};
for (const [k, cmd] of Object.entries(cfg.bash)) {
  const r = spawnSync("bash", ["-c", cmd], { encoding: "utf8", cwd: cfg.cwd });
  out[k] = (r.stdout ?? "") + (r.stderr ?? "");
}
process.stdout.write("AGENT_OUT " + JSON.stringify(out) + "\\n");
`;

/** Run 2's agent: Claude Code's loop against the model proxy, each tool_use
 *  in a shell of its own spawned as Claude Code spawns it, a turn's calls
 *  together. A call whose input says "via-wrapper" runs under a wrapper
 *  shell (the agent's child is \`sh\`, its command is not on that argv). */
const AGENT_CLAUDE = `import { spawn } from "node:child_process";
const cfg = JSON.parse(process.argv[2]);
const base = process.env.ANTHROPIC_BASE_URL;
const tools = [{ name: "Bash", input_schema: { type: "object" } }];
const messages = [{ role: "user", content: "go" }];
const outputs = {};
let n = 0;
function toolUses(text) {
  const blocks = new Map();
  for (const chunk of text.split("\\n\\n")) {
    const line = chunk.split("\\n").find((l) => l.startsWith("data: "));
    if (!line) continue;
    let ev; try { ev = JSON.parse(line.slice(6)); } catch { continue; }
    if (ev.type === "content_block_start" && ev.content_block && ev.content_block.type === "tool_use") blocks.set(ev.index, { id: ev.content_block.id, name: ev.content_block.name, json: "" });
    if (ev.type === "content_block_delta" && ev.delta && ev.delta.type === "input_json_delta" && blocks.has(ev.index)) blocks.get(ev.index).json += ev.delta.partial_json;
  }
  return [...blocks.values()].map((b) => ({ type: "tool_use", id: b.id, name: b.name, input: JSON.parse(b.json || "{}") }));
}
function run(input) {
  const k = n++;
  const quoted = "'" + String(input.command).replace(/'/g, "'\\"'\\"'") + "'";
  const payload = "source /dev/null 2>/dev/null || true && eval " + quoted + " && pwd -P >| " + cfg.tmp + "/cwd-" + k;
  const [prog, args] = input.description === "via-wrapper" ? ["sh", ["-c", 'bash -c "$0"; true', payload]] : ["bash", ["-c", payload]];
  return new Promise((ok) => {
    const c = spawn(prog, args, { cwd: cfg.cwd, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (out += d));
    c.on("close", () => ok(out));
  });
}
for (let turn = 0; turn < 6; turn++) {
  const res = await fetch(base + "/v1/messages", {
    method: "POST",
    headers: { "content-type": "application/json", "x-mandu-session-id": cfg.session, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 512, tools, messages }),
  });
  const uses = toolUses(await res.text());
  if (uses.length === 0) break;
  messages.push({ role: "assistant", content: uses });
  const outs = await Promise.all(uses.map((u) => run(u.input)));
  uses.forEach((u, i) => { outputs[u.id] = outs[i]; });
  messages.push({ role: "user", content: uses.map((u, i) => ({ type: "tool_result", tool_use_id: u.id, content: outs[i] })) });
}
process.stdout.write("AGENT_OUT " + JSON.stringify(outputs) + "\\n");
`;

/** Run 3's agent: Claude Code's loop, but each model request after the first
 *  is sent from a worker thread the agent started WHILE the turn's tool call
 *  ran (Claude Code 2.1.299, a Bun binary, starts threads all session long).
 *  `worker` records how that request went: "ok", or the error it met. */
const AGENT_THREAD = `import { spawn } from "node:child_process";
import { Worker } from "node:worker_threads";
const cfg = JSON.parse(process.argv[2]);
const base = process.env.ANTHROPIC_BASE_URL;
const tools = [{ name: "Bash", input_schema: { type: "object" } }];
const messages = [{ role: "user", content: "go" }];
const outputs = {};
const WORKER = 'const { parentPort } = require("node:worker_threads");'
  + 'parentPort.on("message", async (m) => { try { const r = await fetch(m.url, m.init); parentPort.postMessage({ ok: true, text: await r.text() }); }'
  + ' catch (e) { parentPort.postMessage({ ok: false, error: String((e && e.cause && (e.cause.code || e.cause.message)) || e) }); } });';
function toolUses(text) {
  const blocks = new Map();
  for (const chunk of text.split("\\n\\n")) {
    const line = chunk.split("\\n").find((l) => l.startsWith("data: "));
    if (!line) continue;
    let ev; try { ev = JSON.parse(line.slice(6)); } catch { continue; }
    if (ev.type === "content_block_start" && ev.content_block && ev.content_block.type === "tool_use") blocks.set(ev.index, { id: ev.content_block.id, json: "" });
    if (ev.type === "content_block_delta" && ev.delta && ev.delta.type === "input_json_delta" && blocks.has(ev.index)) blocks.get(ev.index).json += ev.delta.partial_json;
  }
  return [...blocks.values()].map((b) => ({ type: "tool_use", id: b.id, name: "Bash", input: JSON.parse(b.json || "{}") }));
}
function run(input) {
  return new Promise((ok) => {
    const c = spawn("bash", ["-c", input.command], { cwd: cfg.cwd, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (out += d));
    c.on("close", () => ok(out));
  });
}
const request = () => ({ method: "POST", headers: { "content-type": "application/json", "x-mandu-session-id": cfg.session, "anthropic-version": "2023-06-01" },
  body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 512, tools, messages }) });
let text = await (await fetch(base + "/v1/messages", request())).text();
let worker = "not reached";
for (let turn = 0; turn < 4; turn++) {
  const uses = toolUses(text);
  if (uses.length === 0) break;
  messages.push({ role: "assistant", content: uses });
  const calls = Promise.all(uses.map((u) => run(u.input)));
  await new Promise((r) => setTimeout(r, 300));
  const w = new Worker(WORKER, { eval: true });
  await new Promise((r) => w.once("online", r));
  const outs = await calls;
  uses.forEach((u, i) => { outputs[u.id] = outs[i]; });
  messages.push({ role: "user", content: uses.map((u, i) => ({ type: "tool_result", tool_use_id: u.id, content: outs[i] })) });
  await new Promise((r) => setTimeout(r, 300));
  const got = await new Promise((r) => { w.once("message", r); w.postMessage({ url: base + "/v1/messages", init: request() }); });
  await w.terminate();
  worker = got.ok ? "ok" : got.error;
  if (!got.ok) break;
  text = got.text;
}
process.stdout.write("AGENT_OUT " + JSON.stringify({ ...outputs, worker }) + "\\n");
`;

/** The agent under the real guard; its stdout, stderr and exit status. */
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

function post(port: number, body: unknown, session: string): Promise<number> {
  return new Promise((ok, fail) => {
    const req = http.request({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => { res.resume(); res.on("end", () => ok(res.statusCode ?? 0)); });
    req.on("error", fail);
    req.end(JSON.stringify(body));
  });
}

/** The arbiter and the registered secret both runs share. */
async function stack(name: string): Promise<{
  tmp: string; work: string; sock: string; secretPolicy: string; session: string; agentNode: string; pathEnv: string;
  client: ArbiterClient; human: ArbiterClient; logs: string[]; done: () => Promise<void>;
}> {
  const logs: string[] = [];
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), `mandu-d7-${name}-`)));
  const work = join(tmp, "work");
  mkdirSync(work, { recursive: true });
  const secret = join(work, "x.txt");
  writeFileSync(secret, `token=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  const holder = holderReader(tmp)!;
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [${holder.yaml}]\n`);
  const pathEnv = `${join(tmp, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`;
  const sock = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: (m: string) => { logs.push(m); }, confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  // The proxy's second client (server-main): execGate and callTaint ride the
  // human socket, the only one the arbiter binds a call from (plan 13 D9).
  const human = new ArbiterClient(join(tmp, "human", "h.sock"));
  await human.connect();
  const session = `d7-${name}-${process.pid}`;
  // The launcher registers the secret and writes the guard's policy file;
  // `agentExe` names the agent's binary, as the launcher's resolveAgentExe.
  const reg = await client.registerSecret({ path: secret, home: tmp });
  assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
  const twin = join(tmp, "x.twin");
  writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
  const agentNode = agentNodeCopy(tmp);
  const secretPolicy = join(tmp, "secret-policy.json");
  writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: secret, twin, level: "no-model" }] }));
  return {
    tmp, work, sock, secretPolicy, session, agentNode, pathEnv, client, human, logs,
    done: async () => { client.close(); human.close(); await server.close(); rmSync(tmp, { recursive: true, force: true }); },
  };
}

const cannotAttach = (stderr: string): boolean => /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(stderr);

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("D7 LIVE, fork without exec: a reader inside a subshell, a command substitution or a brace group is in its call's tree; its output reaches the model masked (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const s = await stack("fork");
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(s.client, s.human), upstream: upstream.fetcher, sessionKey: s.session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const agentJs = join(s.tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT_CODEX);
    const readers: Record<string, string> = {
      subshell: `( mdu-holder ./x.tx?; true )${HEX}`,
      substitution: `echo "$(mdu-holder ./x.tx?; true)"${HEX}`,
      brace: `{ mdu-holder ./x.tx?; true; }${HEX}`,
      lone: `( mdu-holder ./x.tx? )${HEX}`,
    };
    const cmds = { ...readers, clean: "echo clean-d7" };
    // The proxy's record of each call's command, made when it relayed the
    // call (its response side; plan 13 D9 follow-up: a call binds by that
    // record, never by the command echoed back).
    for (const [k, cmd] of Object.entries(cmds)) await s.human.recordCallCommand({ callId: `toolu_d7_${k}`, command: cmd, sessionKey: s.session });
    const run = await runGuarded([s.agentNode, agentJs, JSON.stringify({ bash: cmds, cwd: s.work })], { ...process.env, HOME: s.tmp, PATH: s.pathEnv, MANDU_ARBITER_SOCK: s.sock, MANDU_NET_GUARD_SECRETS: s.secretPolicy });
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && cannotAttach(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;
    // Preconditions: each reader got the real bytes (so a leak is possible).
    for (const k of Object.keys(readers)) assert.equal(got[k]!.trim(), FILE_HEX, `${k}: mdu-holder, the pinned reader, read the real file: ${got[k]}`);

    const tools = [{ name: "Bash", input_schema: { type: "object" } }];
    const send = async (command: string, result: string, id: string): Promise<string> => {
      const n = upstream.requests.length;
      assert.equal(await post(port, { model: "claude-sonnet-4-5", stream: true, max_tokens: 512, tools, messages: [
        { role: "user", content: "go" },
        { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: result }] },
      ] }, s.session), 200);
      assert.equal(upstream.requests.length, n + 1);
      const b = upstream.requests[n]!.json() as { messages: Array<{ content: Array<{ content: unknown }> }> };
      return JSON.stringify(b.messages[2]!.content[0]!.content);
    };
    const leaks: string[] = [];
    for (const [k, cmd] of Object.entries(readers)) {
      const seen = await send(cmd, got[k]!, `toolu_d7_${k}`);
      if (seen.includes(FILE_HEX.slice(0, 24))) leaks.push(k);
      else assert.match(seen, /\[mandu:secret\] masked: mdu-holder read .*x\.txt/, `${k}: ${seen}`);
    }
    const clean = await send(cmds.clean, got["clean"]!, "toolu_d7_clean");
    assert.ok(clean.includes("clean-d7"), `a call that read nothing, bound to its own shell, stays raw: ${clean}`);
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(CANARY), "the file's bytes never reached the model");
    assert.deepEqual(leaks, [], "CONFIDENTIALITY VIOLATION: a reader's output reached the model raw (its subshell was not in the call's tree)");
  } finally {
    await proxy.close();
    await s.done();
  }
});

/** One model turn of tool_use blocks, as the API streams them. */
function toolUseTurn(uses: Array<{ id: string; input: Record<string, unknown> }>): string {
  let out = sseEvent("message_start", { type: "message_start", message: { id: `msg_${uses[0]!.id}`, role: "assistant", content: [] } });
  uses.forEach((u, index) => {
    out += sseEvent("content_block_start", { type: "content_block_start", index, content_block: { type: "tool_use", id: u.id, name: "Bash", input: {} } });
    out += sseEvent("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: JSON.stringify(u.input) } });
    out += sseEvent("content_block_stop", { type: "content_block_stop", index });
  });
  out += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } });
  out += sseEvent("message_stop", { type: "message_stop" });
  return out;
}

test("D7 LIVE, the call-root recorder: Claude Code's shells bind their calls by command text; two same-text calls run together are both masked; an unknown tree in a session holding a secret is masked; clean calls stay raw (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const s = await stack("recorder");
  // The lock is bash's own O_EXCL create (noclobber), never `mkdir`: uutils
  // coreutils' mkdir (Ubuntu 26.04) answers success to BOTH of two racing
  // calls, so both read (a CI flake, 2026-10-10).
  const SAME = `if { set -C; : > ./lock.f; } 2>/dev/null; then mdu-holder ./x.tx?${HEX}; else echo no-lock; fi`;
  const turns = [
    [
      { id: "toolu_cc_sub", input: { command: `( mdu-holder ./x.tx?; true )${HEX}` } },
      { id: "toolu_cc_subst", input: { command: `echo "$(mdu-holder ./x.tx?; true)"${HEX}` } },
      { id: "toolu_cc_same_a", input: { command: SAME } },
      { id: "toolu_cc_same_b", input: { command: SAME } },
      { id: "toolu_cc_clean", input: { command: "echo clean-cc-$((6*7))" } },
    ],
    [
      { id: "toolu_cc_wrapped", input: { command: `mdu-holder ./x.tx?${HEX} # run through a wrapper`, description: "via-wrapper" } },
      { id: "toolu_cc_clean2", input: { command: "echo still-clean-$((7*6))" } },
    ],
  ];
  const seen: string[] = [];
  const fetcher: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const turn = turns[seen.length - 1];
    const sse = turn ? toolUseTurn(turn) : buildTextSse("done", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(s.client, s.human), upstream: fetcher, sessionKey: s.session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const agentJs = join(s.tmp, "agent-cc.mjs");
    writeFileSync(agentJs, AGENT_CLAUDE);
    const cfg = { cwd: s.work, tmp: s.tmp, session: s.session };
    const run = await runGuarded([s.agentNode, agentJs, JSON.stringify(cfg)], {
      ...process.env, HOME: s.tmp, PATH: s.pathEnv, MANDU_ARBITER_SOCK: s.sock, MANDU_NET_GUARD_SECRETS: s.secretPolicy,
      ANTHROPIC_BASE_URL: `http://127.0.0.1:${port}`,
    });
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && cannotAttach(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;
    assert.equal(seen.length, 3, `two tool turns and the closing turn reached the model: ${seen.length}`);
    // Preconditions: the readers got the real bytes; exactly one same-text call read.
    const opens = (): string => s.logs.filter((l) => l.startsWith("decideSecretOpen")).join("\n");
    for (const id of ["toolu_cc_sub", "toolu_cc_subst", "toolu_cc_wrapped"]) assert.equal(got[id]?.trim(), FILE_HEX, `${id} read the real file: ${JSON.stringify(got)}\n${opens()}`);
    const same = [got["toolu_cc_same_a"]!.trim(), got["toolu_cc_same_b"]!.trim()].sort();
    assert.deepEqual(same, [FILE_HEX, "no-lock"].sort(), `one same-text call read, the other did not: ${JSON.stringify(same)}`);
    assert.equal(got["toolu_cc_clean"]?.trim(), "clean-cc-42");

    // What the model received for each result, in the request that carried it.
    const resultIn = (body: string, id: string): string => {
      const msgs = (JSON.parse(body) as { messages: Array<{ content: unknown }> }).messages;
      for (const m of msgs) {
        if (!Array.isArray(m.content)) continue;
        for (const b of m.content as Array<{ type?: string; tool_use_id?: string; content?: unknown }>) {
          if (b.type === "tool_result" && b.tool_use_id === id) return JSON.stringify(b.content);
        }
      }
      throw new Error(`no tool_result ${id} in the request`);
    };
    const leaks: string[] = [];
    const unmasked: string[] = [];
    for (const [id, body] of [
      ["toolu_cc_sub", seen[1]!], ["toolu_cc_subst", seen[1]!], ["toolu_cc_same_a", seen[1]!], ["toolu_cc_same_b", seen[1]!], ["toolu_cc_wrapped", seen[2]!],
    ] as const) {
      const r = resultIn(body, id);
      if (r.includes(FILE_HEX.slice(0, 24))) leaks.push(id);
      else if (!/\[mandu:secret\] masked/.test(r)) unmasked.push(`${id}: ${r}`);
    }
    assert.deepEqual(leaks, [], "CONFIDENTIALITY VIOLATION: a reader's output reached the model raw");
    assert.deepEqual(unmasked, [], "every reader's result, and both same-text results, are masked");
    // Both same-text results are masked, the one that read nothing too:
    // nothing tells the two runs apart, so each call is folded over both.
    assert.ok(!resultIn(seen[1]!, "toolu_cc_same_a").includes("no-lock") && !resultIn(seen[1]!, "toolu_cc_same_b").includes("no-lock"));
    // The unknown tree is masked at the session's level (no exec of the agent
    // carried its command), with the reason said.
    assert.match(resultIn(seen[2]!, "toolu_cc_wrapped"), /plan 13 D7: Mandu could not tie this Bash call/);
    // Utility: the clean calls, each bound to its own shell, are raw in a
    // session that holds a secret.
    assert.ok(resultIn(seen[1]!, "toolu_cc_clean").includes("clean-cc-42"), resultIn(seen[1]!, "toolu_cc_clean"));
    assert.ok(resultIn(seen[2]!, "toolu_cc_clean2").includes("still-clean-42"), resultIn(seen[2]!, "toolu_cc_clean2"));
    // The arbiter's account of each call.
    const tree = async (id: string, command: string) => s.client.callTaint(id, { command, session: s.session });
    assert.equal((await tree("toolu_cc_sub", turns[0]![0]!.input.command)).evidence, "tree");
    assert.equal((await tree("toolu_cc_same_a", SAME)).level, "no-model");
    assert.equal((await tree("toolu_cc_same_b", SAME)).level, "no-model");
    assert.equal((await tree("toolu_cc_wrapped", turns[1]![0]!.input.command as string)).evidence, "session");

    // THE ORACLE: no request to the model carried the file, raw or hex.
    const wire = seen.join("\n");
    assert.ok(!wire.includes(CANARY), "the file's bytes never reached the model");
    assert.ok(!wire.includes(FILE_HEX.slice(0, 24)), "the file's hex never reached the model");
    assert.deepEqual(leaks, [], "CONFIDENTIALITY VIOLATION: a reader's output reached the model raw");
  } finally {
    await proxy.close();
    await s.done();
  }
});

/** The background agent: Claude Code 2.1.287's `run_in_background`, as read
 *  off its process table (2026-10-02): the agent opens
 *  `<tasks>/<id>.output` and hands it to the shell as its stdout and stderr,
 *  answers at once ("Command running in background with ID: <id>. Output is
 *  being written to: <path>."), and the model reads the file later with
 *  `Read`, or polls it with `TaskOutput`. */
const AGENT_BG = `import { spawn } from "node:child_process";
import { openSync, closeSync, readFileSync, mkdirSync } from "node:fs";
const cfg = JSON.parse(process.argv[2]);
const base = process.env.ANTHROPIC_BASE_URL;
const tools = ["Bash", "TaskOutput", "Read"].map((name) => ({ name, input_schema: { type: "object" } }));
const messages = [{ role: "user", content: "go" }];
const outputs = {};
const bg = new Map();
function toolUses(text) {
  const blocks = new Map();
  for (const chunk of text.split("\\n\\n")) {
    const line = chunk.split("\\n").find((l) => l.startsWith("data: "));
    if (!line) continue;
    let ev; try { ev = JSON.parse(line.slice(6)); } catch { continue; }
    if (ev.type === "content_block_start" && ev.content_block && ev.content_block.type === "tool_use") blocks.set(ev.index, { id: ev.content_block.id, name: ev.content_block.name, json: "" });
    if (ev.type === "content_block_delta" && ev.delta && ev.delta.type === "input_json_delta" && blocks.has(ev.index)) blocks.get(ev.index).json += ev.delta.partial_json;
  }
  return [...blocks.values()].map((b) => ({ type: "tool_use", id: b.id, name: b.name, input: JSON.parse(b.json || "{}") }));
}
const readOut = (path) => { try { return readFileSync(path, "utf8"); } catch (e) { return "<error>" + e.code + "</error>"; } };
async function run(u) {
  if (u.name === "Bash" && u.input.run_in_background) {
    const id = "b" + bg.size;
    mkdirSync(cfg.tasks, { recursive: true });
    const path = cfg.tasks + "/" + id + ".output";
    const fd = openSync(path, "a");
    const quoted = "'" + String(u.input.command).replace(/'/g, "'\\"'\\"'") + "'";
    const c = spawn("bash", ["-c", "source /dev/null 2>/dev/null || true && eval " + quoted + " && pwd -P >| " + cfg.tasks + "/cwd-" + id], { cwd: cfg.cwd, stdio: ["ignore", fd, fd], detached: true });
    closeSync(fd);
    bg.set(id, { path, done: new Promise((ok) => c.on("exit", ok)) });
    return "Command running in background with ID: " + id + ". Output is being written to: " + path + ". You will be notified when it completes.";
  }
  if (u.name === "TaskOutput") {
    const t = bg.get(u.input.task_id);
    if (!t) return "<error>no such task</error>";
    await t.done;
    return "<retrieval_status>success</retrieval_status>\\n<task_id>" + u.input.task_id + "</task_id>\\n<status>completed</status>\\n<output>\\n" + readOut(t.path) + "</output>";
  }
  if (u.name === "Read") {
    for (const t of bg.values()) await t.done;
    return readOut(u.input.file_path).split("\\n").map((l, i) => String(i + 1).padStart(6) + "\\t" + l).join("\\n");
  }
  return "<error>unknown tool</error>";
}
for (let turn = 0; turn < 4; turn++) {
  const res = await fetch(base + "/v1/messages", {
    method: "POST",
    headers: { "content-type": "application/json", "x-mandu-session-id": cfg.session, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 512, tools, messages }),
  });
  const uses = toolUses(await res.text());
  if (uses.length === 0) break;
  messages.push({ role: "assistant", content: uses });
  const outs = [];
  for (const u of uses) outs.push(await run(u));
  uses.forEach((u, i) => { outputs[u.id] = outs[i]; });
  messages.push({ role: "user", content: uses.map((u, i) => ({ type: "tool_result", tool_use_id: u.id, content: outs[i] })) });
}
for (const t of bg.values()) await t.done;
process.stdout.write("AGENT_OUT " + JSON.stringify(outputs) + "\\n");
`;

/** One model turn of tool_use blocks of any tool. */
function anyToolTurn(uses: Array<{ id: string; name: string; input: Record<string, unknown> }>): string {
  let out = sseEvent("message_start", { type: "message_start", message: { id: `msg_${uses[0]!.id}`, role: "assistant", content: [] } });
  uses.forEach((u, index) => {
    out += sseEvent("content_block_start", { type: "content_block_start", index, content_block: { type: "tool_use", id: u.id, name: u.name, input: {} } });
    out += sseEvent("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: JSON.stringify(u.input) } });
    out += sseEvent("content_block_stop", { type: "content_block_stop", index });
  });
  out += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } });
  out += sseEvent("message_stop", { type: "message_stop" });
  return out;
}

// Plan 10 §11.12's polls (2026-10-02). Claude Code 2.1.287 runs a background
// Bash with the task's output file as the shell's stdout and stderr; the
// model reads it with `Read` (or `TaskOutput`). A reader in that shell writes
// the secret into a file the AGENT opened, which no shell call's result
// carries: only the file's label (plan 13 D5's sweep: a file a reader holds
// open for writing takes the label at the taint) and the poll's own mask keep
// it from the model.
test("background output LIVE: a reader in a run_in_background shell labels the task's output file; neither Read nor TaskOutput of it reaches the model raw (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const s = await stack("bg");
  const tasks = join(s.tmp, "tasks");
  const outPath = join(tasks, "b0.output");
  const turns = [
    [{ id: "toolu_bg_run", name: "Bash", input: { command: `sleep 0.3; mdu-holder ./x.tx? | od -An -tx1 | tr -d ' \\n'`, run_in_background: true, description: "bg" } }],
    [{ id: "toolu_bg_poll", name: "TaskOutput", input: { task_id: "b0", block: true, timeout: 30000 } }],
    [{ id: "toolu_bg_read", name: "Read", input: { file_path: outPath } }],
  ];
  const seen: string[] = [];
  const fetcher: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const turn = turns[seen.length - 1];
    const sse = turn ? anyToolTurn(turn) : buildTextSse("done", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(s.client, s.human), upstream: fetcher, sessionKey: s.session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const agentJs = join(s.tmp, "agent-bg.mjs");
    writeFileSync(agentJs, AGENT_BG);
    const run = await runGuarded([s.agentNode, agentJs, JSON.stringify({ cwd: s.work, tasks, session: s.session })], {
      ...process.env, HOME: s.tmp, PATH: s.pathEnv, MANDU_ARBITER_SOCK: s.sock, MANDU_NET_GUARD_SECRETS: s.secretPolicy,
      ANTHROPIC_BASE_URL: `http://127.0.0.1:${port}`,
    });
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && cannotAttach(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;
    assert.equal(seen.length, 4, `three tool turns and the closing turn reached the model: ${seen.length}`);
    // Precondition: the background reader read the real file into the
    // task's output file (the test reads it from outside the guard).
    assert.equal(readFileSync(outPath, "utf8").trim(), FILE_HEX, "mdu-holder, the pinned reader, read the real file into the output file");
    // The file took the reader's label (D5's sweep: the reader's pipeline
    // held it open for writing when it read the secret).
    const lvl = await s.client.pathLevel(outPath);
    assert.equal(lvl.level, "no-model", `the task's output file is labeled: ${JSON.stringify(lvl)}`);
    // THE ORACLE: no request to the model carried the file, raw or hex, by
    // the poll or by Read (whatever the agent's own reads were served).
    const wire = seen.join("\n");
    assert.ok(!wire.includes(CANARY), "the file's bytes never reached the model");
    assert.ok(!wire.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: the background reader's output reached the model (agent saw: ${JSON.stringify(got)})`);
  } finally {
    await proxy.close();
    await s.done();
  }
});

// Plan 13 D7's lineage residual (closed 2026-10-02): a subshell whose first
// exec or open below it comes after its parent (the call's shell) exited.
// `( read -t 1 -u 9; mdu-holder … ) & echo started`: the shell returns at once, its
// subshell waits on a FIFO the shell opened (a builtin: no trapped call), is
// re-parented to the guard, and only then runs the reader. The agent still
// reads the reader's output on the call's stdout pipe (Claude Code waits for
// it to close). On master mdu-holder's chain stopped at the orphaned subshell, no
// edge linked it to the call's shell, and the hex dump reached the model raw.
test("D7 LIVE, the orphan subshell: a reader under a subshell orphaned before it acted is folded into its call; the result is masked; a later clean call stays raw (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const s = await stack("orphan");
  const ORPHAN = `rm -f ./p; mkfifo ./p; exec 9<>./p; ( read -t 1 -u 9; mdu-holder ./x.tx?${HEX} ) & echo started`;
  const turns = [
    [{ id: "toolu_or_bg", input: { command: ORPHAN } }],
    [{ id: "toolu_or_clean", input: { command: "echo after-$((6*7))" } }],
  ];
  const seen: string[] = [];
  const fetcher: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const turn = turns[seen.length - 1];
    const sse = turn ? toolUseTurn(turn) : buildTextSse("done", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(s.client, s.human), upstream: fetcher, sessionKey: s.session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const agentJs = join(s.tmp, "agent-orphan.mjs");
    writeFileSync(agentJs, AGENT_CLAUDE);
    const run = await runGuarded([s.agentNode, agentJs, JSON.stringify({ cwd: s.work, tmp: s.tmp, session: s.session })], {
      ...process.env, HOME: s.tmp, PATH: s.pathEnv, MANDU_ARBITER_SOCK: s.sock, MANDU_NET_GUARD_SECRETS: s.secretPolicy,
      ANTHROPIC_BASE_URL: `http://127.0.0.1:${port}`,
    });
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && cannotAttach(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;
    assert.equal(seen.length, 3, `two tool turns and the closing turn reached the model: ${seen.length}`);
    // Precondition: the orphaned subshell's reader read the real file, and its
    // output reached the agent on the call's stdout.
    assert.ok(got["toolu_or_bg"]?.includes(FILE_HEX), `the orphan's mdu-holder read the real file: ${JSON.stringify(got)}`);
    const resultIn = (body: string, id: string): string => {
      const msgs = (JSON.parse(body) as { messages: Array<{ content: unknown }> }).messages;
      for (const m of msgs) {
        if (!Array.isArray(m.content)) continue;
        for (const b of m.content as Array<{ type?: string; tool_use_id?: string; content?: unknown }>) {
          if (b.type === "tool_result" && b.tool_use_id === id) return JSON.stringify(b.content);
        }
      }
      throw new Error(`no tool_result ${id} in the request`);
    };
    const bg = resultIn(seen[1]!, "toolu_or_bg");
    assert.ok(!bg.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: the orphaned subshell's reader reached the model raw: ${bg}`);
    assert.match(bg, /\[mandu:secret\] masked/, bg);
    // Utility: a call relayed after the orphan acted is not folded with it.
    assert.ok(resultIn(seen[2]!, "toolu_or_clean").includes("after-42"), resultIn(seen[2]!, "toolu_or_clean"));
    const wire = seen.join("\n");
    assert.ok(!wire.includes(CANARY), "the file's bytes never reached the model");
    assert.ok(!wire.includes(FILE_HEX.slice(0, 24)), "the file's hex never reached the model");
  } finally {
    await proxy.close();
    await s.done();
  }
});

// 2026-10-15 (drill conf-tainted-bound-blocked, Claude Code 2.1.299): a
// notification names the calling THREAD, and the orphan check walked up from
// it, reading the thread's own start time. A worker thread the agent started
// while a holder lived was judged a root born in that holder's window, so
// once the holder exited the agent became its orphan: its next model request
// was refused (EACCES) and every file it wrote was labelled. The holder here
// is `od`, which receives the reader's pipe and lives while the subshell
// sleeps; the agent starts its worker meanwhile and sends the next request
// from it after the call has ended.
test("D7 LIVE, a thread the agent starts during a call: the agent is no orphan of the call's holder; its model request from that thread goes through; the read is still masked (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const s = await stack("thread");
  const turns = [[{ id: "toolu_th_read", input: { command: `( mdu-holder ./x.tx?; sleep 1 )${HEX}` } }]];
  const seen: string[] = [];
  const fetcher: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const turn = turns[seen.length - 1];
    const sse = turn ? toolUseTurn(turn) : buildTextSse("done", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(s.client, s.human), upstream: fetcher, sessionKey: s.session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const agentJs = join(s.tmp, "agent-thread.mjs");
    writeFileSync(agentJs, AGENT_THREAD);
    const run = await runGuarded([s.agentNode, agentJs, JSON.stringify({ cwd: s.work, session: s.session })], {
      ...process.env, HOME: s.tmp, PATH: s.pathEnv, MANDU_ARBITER_SOCK: s.sock, MANDU_NET_GUARD_SECRETS: s.secretPolicy,
      ANTHROPIC_BASE_URL: `http://127.0.0.1:${port}`,
    });
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && cannotAttach(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;
    // Precondition: the reader read the real file and its output reached the agent.
    assert.ok(got["toolu_th_read"]?.includes(FILE_HEX), `mdu-holder read the real file: ${JSON.stringify(got)}`);
    // UTILITY, the regression: the agent's request from its new thread went through.
    assert.equal(got["worker"], "ok", `the agent's model request from a thread started during the call was refused: ${got["worker"]}\n${run.stderr}`);
    assert.equal(seen.length, 2, `the tool turn and the closing turn reached the model: ${seen.length}`);
    // CONFIDENTIALITY: the read is masked all the same.
    const wire = seen.join("\n");
    assert.match(seen[1]!, /\[mandu:secret\] masked/, seen[1]);
    assert.ok(!wire.includes(CANARY), "the file's bytes never reached the model");
    assert.ok(!wire.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: the reader's output reached the model raw: ${seen[1]}`);
  } finally {
    await proxy.close();
    await s.done();
  }
});
