/**
 * forged-reports — plan 13 §3 D9 under the REAL guard: a program the agent
 * runs cannot forge the guard's process records over the arbiter's data
 * socket, the one its tree reaches.
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around an
 *   "agent" (a copy of node, the launch's `agentExe`) that behaves as Claude
 *   Code: it talks to the real AnthropicProxy in its production wiring (a
 *   data and a human-plane client, as server-main builds it; a scripted
 *   model behind it), runs each tool_use in a shell of its own spawned as
 *   Claude Code spawns it, and sends the results back. A real ArbiterServer
 *   with both sockets, in `secrets`, loaded with a policy.yaml (`x.txt`:
 *   no-model, readers `mdu-holder` by name and pinned by path and hash: a
 *   reader the test builds, tests/lib/holder-reader.c, on the agent's
 *   PATH; until 2026-10-03 the reader was `cat` itself, which admits nothing
 *   since plan 13 D8's "printers admit nothing"). The guard's policy file walls the agent world
 *   off from the human socket (`unixDeny`, as the launcher writes it), so
 *   the agent's programs have the data socket only, as in a real launch.
 *
 *   1. A forged parent. One Bash call forks a subshell that waits, then a
 *      program of the agent's records a false parent for every sibling of
 *      its own (`processLineage` and `recordExecRoot` over
 *      $MANDU_ARBITER_SOCK) BEFORE the guard reports any exec or open below
 *      it; the subshell then `exec`s the reader on the file, hex-encoded. Before
 *      the fix the guard's chain lost to the forged edge (first edge wins),
 *      the reader was out of its call's tree, and the hex dump reached the
 *      model raw. A clean call in the same turn stays raw (utility).
 *   2. A forged reader. A program of the agent's copies the reader into the
 *      workspace and reports a raw open of that copy as a system binary
 *      (`decideSecretOpen`, `exeSystem: true`) before any real reader ran.
 *      Before the fix the arbiter pinned the bare-name reader to the copy,
 *      and in the next turn the copy, under the real guard, read the file
 *      raw. Now the forged report is answered with the twin and pins
 *      nothing; the copy gets no raw byte; the pinned reader still reads.
 *
 * The oracle: no form of the file's bytes reaches the model, and the
 * agent's own copy of a reader never holds them. SKIPs only where the guard
 * is not built or the kernel lacks seccomp user notification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, sseEvent } from "../../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { agentNodeCopy, pickGuard } from "../../lib/native-guard.js";
import { holderReader, holderSkip } from "../../lib/holder-reader.js";
import { stateAxes } from "../../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const skip = process.platform !== "linux" ? "Linux only" : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : holderSkip() !== false ? holderSkip() : false;

const CANARY = `X_TXT_D9_CANARY_${process.pid}`;
const FILE_HEX = Buffer.from(`token=${CANARY}\n`).toString("hex");
const HEX = " | od -An -tx1 | tr -d ' \\n'";
const NODE = realpathSync(process.execPath);

/** The agent: Claude Code's loop against the model proxy, each tool_use in a
 *  shell of its own spawned as Claude Code spawns it, a turn's calls together. */
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
  return new Promise((ok) => {
    const c = spawn("bash", ["-c", payload], { cwd: cfg.cwd, stdio: ["ignore", "pipe", "pipe"] });
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

/** A data-socket NDJSON exchange, as any program of the agent's can make. */
const DATA_SOCKET_CALL = `import net from "node:net";
export function call(reqs) {
  return new Promise((ok, fail) => {
    const s = net.createConnection(process.env.MANDU_ARBITER_SOCK);
    const answers = []; let buf = "";
    s.on("data", (d) => {
      buf += d;
      let nl;
      while ((nl = buf.indexOf("\\n")) >= 0) { answers.push(JSON.parse(buf.slice(0, nl))); buf = buf.slice(nl + 1); }
      if (answers.length === reqs.length) { s.end(); ok(answers); }
    });
    s.on("error", fail);
    for (const r of reqs) s.write(JSON.stringify(r) + "\\n");
  });
}
`;

/** Run 1's forger: a false parent for every sibling of its own (the shell's
 *  other children: the waiting subshell among them), over the data socket. */
const FORGE_LINEAGE = `import { readdirSync, readFileSync } from "node:fs";
import { call } from "./data-socket.mjs";
const stat = (pid) => { try { const s = readFileSync("/proc/" + pid + "/stat", "utf8"); const r = s.slice(s.lastIndexOf(")") + 2).split(" "); return { ppid: Number(r[1]), start: r[19] }; } catch { return null; } };
const shell = process.ppid;
const sibs = readdirSync("/proc").filter((d) => /^\\d+$/.test(d) && Number(d) !== process.pid)
  .map((d) => [d, stat(d)]).filter(([, s]) => s && s.ppid === shell).map(([d, s]) => d + "-" + s.start);
let id = 0;
const reqs = [];
for (const k of sibs) {
  reqs.push({ id: ++id, op: "processLineage", childKey: k, parentKey: "1-1" });
  reqs.push({ id: ++id, op: "recordExecRoot", procKey: k, ancestors: ["1-1"], argv: ["true"] });
}
const answers = reqs.length ? await call(reqs) : [];
process.stdout.write("FORGED " + answers.filter((a) => a.ok).length / 2 + "\\n");
`;

/** Run 2's forger: a raw open of the agent's own copy of the reader, reported as a
 *  system binary, before any real reader ran. */
const FORGE_PIN = `import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { call } from "./data-socket.mjs";
const [copy, file] = process.argv.slice(2);
const exe = realpathSync(copy);
const sha256 = createHash("sha256").update(readFileSync(exe)).digest("hex");
const [a] = await call([{ id: 1, op: "decideSecretOpen", path: file, exe, sha256, isAgent: false, exeSystem: true, openerEnv: [], procKey: process.pid + "-1" }]);
process.stdout.write("FORGED-PIN " + (a.ok ? a.result.verdict : a.error) + "\\n");
`;

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

function toolUseTurn(uses: Array<{ id: string; command: string }>): string {
  let out = sseEvent("message_start", { type: "message_start", message: { id: `msg_${uses[0]!.id}`, role: "assistant", content: [] } });
  uses.forEach((u, index) => {
    out += sseEvent("content_block_start", { type: "content_block_start", index, content_block: { type: "tool_use", id: u.id, name: "Bash", input: {} } });
    out += sseEvent("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: JSON.stringify({ command: u.command }) } });
    out += sseEvent("content_block_stop", { type: "content_block_stop", index });
  });
  out += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } });
  out += sseEvent("message_stop", { type: "message_stop" });
  return out;
}

function resultIn(body: string, id: string): string {
  const msgs = (JSON.parse(body) as { messages: Array<{ content: unknown }> }).messages;
  for (const m of msgs) {
    if (!Array.isArray(m.content)) continue;
    for (const b of m.content as Array<{ type?: string; tool_use_id?: string; content?: unknown }>) {
      if (b.type === "tool_result" && b.tool_use_id === id) return JSON.stringify(b.content);
    }
  }
  throw new Error(`no tool_result ${id} in the request`);
}

const cannotAttach = (stderr: string): boolean => /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(stderr);

/** A session: the arbiter with both sockets, the policy, the guard's policy
 *  file as the launcher writes it, the proxy in its production wiring, and
 *  the agent run under the real guard through `turns`. */
async function session(name: string, turns: Array<Array<{ id: string; command: string }>>): Promise<{
  got: Record<string, string> | null; seen: string[]; stderr: string; policy: string; work: string; logs: string[];
  skipped: string | null; done: () => Promise<void>;
}> {
  const logs: string[] = [];
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), `mandu-d9-${name}-`)));
  const work = join(tmp, "work");
  mkdirSync(work, { recursive: true });
  const secret = join(work, "x.txt");
  writeFileSync(secret, `token=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  // The reader by name (what a forged first-use pin would bind) and pinned
  // by path and hash (the binary the human vouched for).
  const holder = holderReader(tmp)!;
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [${holder.app}, ${holder.yaml}]\n`);
  const sock = join(tmp, "arbiter.sock");
  const humanDir = join(tmp, "human");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: join(humanDir, "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: (m: string) => { logs.push(m); }, confidentiality: true, integrity: false });
  await server.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(join(humanDir, "h.sock")); await human.connect();
  const sessionKey = `d9-${name}-${process.pid}`;
  const reg = await data.registerSecret({ path: secret, home: tmp });
  assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
  const twin = join(tmp, "x.twin");
  writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
  const agentNode = agentNodeCopy(tmp);
  const secretPolicy = join(tmp, "secret-policy.json");
  // As the launcher writes it: the secrets, the agent, the human plane walled off.
  writeFileSync(secretPolicy, JSON.stringify({ agentExe: agentNode, ask: "never", session: sessionKey, secrets: [{ path: secret, twin, level: "no-model" }], unixDeny: [humanDir] }));
  writeFileSync(join(work, "data-socket.mjs"), DATA_SOCKET_CALL);
  writeFileSync(join(work, "forge-lineage.mjs"), FORGE_LINEAGE);
  writeFileSync(join(work, "forge-pin.mjs"), FORGE_PIN);
  const seen: string[] = [];
  const fetcher: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const turn = turns[seen.length - 1];
    const sse = turn ? toolUseTurn(turn) : buildTextSse("done", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  // The production wiring: server-main's data client and its human-plane one.
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream: fetcher, sessionKey, log: () => {} });
  const port = await proxy.listen(0);
  const done = async (): Promise<void> => { await proxy.close(); data.close(); human.close(); await server.close(); rmSync(tmp, { recursive: true, force: true }); };
  const agentJs = join(tmp, "agent.mjs");
  writeFileSync(agentJs, AGENT_CLAUDE);
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: tmp, PATH: `${join(tmp, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy, ANTHROPIC_BASE_URL: `http://127.0.0.1:${port}` };
  delete env["MANDU_ARBITER_HUMAN_SOCK"]; // the agent's env never carries it (env-compose)
  const run = await runGuarded([agentNode, agentJs, JSON.stringify({ cwd: work, tmp, session: sessionKey })], env);
  const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
  if (!line && cannotAttach(run.stderr ?? "")) return { got: null, seen, stderr: run.stderr, policy, work, logs, skipped: run.stderr.slice(0, 300), done };
  assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
  return { got: JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>, seen, stderr: run.stderr, policy, work, logs, skipped: null, done };
}

/** What a refused open leaves to read in a CI log (2026-10-18: pipeline
 *  11800's one refusal of the pinned reader said only "Permission denied",
 *  in a run where the guard suites ran 4-5 times slower than the same
 *  commit an hour later, and could not be reproduced): the arbiter's
 *  verdicts and the guard's own lines. */
function diagnosis(s: { logs: string[]; stderr: string }): string {
  const verdicts = s.logs.filter((l) => l.startsWith("decideSecretOpen") || l.startsWith("sessionExecRoot"));
  return `the arbiter's verdicts:\n${verdicts.join("\n") || "(none)"}\nthe guard's stderr (tail):\n${s.stderr.slice(-4000) || "(none)"}`;
}

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("D9 LIVE, a forged parent: a program of the agent records a false parent for a reader before the guard does; the reader stays in its call's tree and its hex dump reaches the model masked (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const FORGED = `( until [ -e ./go ]; do :; done; exec mdu-holder ./x.tx? )${HEX} & ${NODE} ./forge-lineage.mjs; : > ./go; wait`;
  const CLEAN = "echo clean-d9-$((6*7))";
  const s = await session("lineage", [[{ id: "toolu_d9_forged", command: FORGED }, { id: "toolu_d9_clean", command: CLEAN }]]);
  try {
    if (s.skipped !== null) { t.skip(`the guard cannot attach here: ${s.skipped}`); return; }
    const got = s.got!;
    assert.ok(!/reporting on the data socket/.test(s.stderr), `the guard reports on the human socket: ${s.stderr}`);
    // Preconditions: the forger forged for its siblings before the subshell
    // exec'd the reader, and it (the pinned reader) read the real file.
    const forged = /FORGED (\d+)/.exec(got["toolu_d9_forged"] ?? "");
    assert.ok(forged && Number(forged[1]) >= 1, `the forger reached the data socket and forged: ${got["toolu_d9_forged"]}`);
    assert.ok(got["toolu_d9_forged"]!.includes(FILE_HEX), `the reader read the real file: ${JSON.stringify(got)}\n${s.logs.filter((l) => l.startsWith("decideSecretOpen")).join("\n")}`);
    assert.equal(s.seen.length, 2, `one tool turn and the closing turn reached the model: ${s.seen.length}`);
    const r = resultIn(s.seen[1]!, "toolu_d9_forged");
    // MASTER (6f27c2cc): the hex dump reached the model raw
    assert.ok(!r.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: a forged parent took the reader out of its call's tree: ${r}`);
    assert.match(r, /\[mandu:secret\] masked/, r);
    // Utility: the clean call, bound to its own shell, is raw.
    assert.ok(resultIn(s.seen[1]!, "toolu_d9_clean").includes("clean-d9-42"), resultIn(s.seen[1]!, "toolu_d9_clean"));
    // THE ORACLE
    const wire = s.seen.join("\n");
    assert.ok(!wire.includes(CANARY) && !wire.includes(FILE_HEX.slice(0, 24)), "no form of the file reached the model");
  } finally {
    await s.done();
  }
});

test("D9 LIVE, a forged reader: a program of the agent reports a raw open of its own copy of the reader as a system binary; nothing is pinned, the copy gets no raw byte, the pinned reader still reads, and the model sees no byte (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const s = await session("pin", [
    [{ id: "toolu_d9_plant", command: `mkdir -p ./bin && cp "$(command -v mdu-holder)" ./bin/mdu-holder && ${NODE} ./forge-pin.mjs ./bin/mdu-holder "$PWD/x.txt"` }],
    [{ id: "toolu_d9_copy", command: `./bin/mdu-holder ./x.tx?${HEX}` }],
    [{ id: "toolu_d9_system", command: `mdu-holder ./x.tx?${HEX}` }],
  ]);
  try {
    if (s.skipped !== null) { t.skip(`the guard cannot attach here: ${s.skipped}`); return; }
    const got = s.got!;
    assert.ok(!/reporting on the data socket/.test(s.stderr), `the guard reports on the human socket: ${s.stderr}`);
    // MASTER (6f27c2cc): FORGED-PIN raw, and the copy was pinned into policy.yaml
    assert.match(got["toolu_d9_plant"] ?? "", /FORGED-PIN twin/, `the forged report is answered with the twin: ${got["toolu_d9_plant"]}`);
    const law = readFileSync(s.policy, "utf8");
    assert.ok(!law.includes(join(s.work, "bin", "mdu-holder")), `no pin of the agent's copy was written:\n${law}`);
    // MASTER: the copy read the file raw under the real guard
    assert.ok(!(got["toolu_d9_copy"] ?? "").includes(FILE_HEX.slice(0, 24)), `the agent's own copy of the reader held the file raw: ${got["toolu_d9_copy"]}`);
    // Utility: the pinned binary is still the reader.
    assert.ok((got["toolu_d9_system"] ?? "").includes(FILE_HEX), `the pinned reader read the real file: ${JSON.stringify(got)}\n${diagnosis(s)}`);
    // THE ORACLE
    const wire = s.seen.join("\n");
    assert.ok(!wire.includes(CANARY) && !wire.includes(FILE_HEX.slice(0, 24)), "no form of the file reached the model");
  } finally {
    await s.done();
  }
});
