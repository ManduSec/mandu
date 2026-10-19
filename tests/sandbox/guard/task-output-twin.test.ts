/**
 * task-output-twin — confidentiality plan 13 D4 under the REAL guard: a tool
 * call's output that reaches the agent through a FILE the agent reads back
 * (Claude Code 2.1.288's Bash task file), written by a secret holder.
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around an
 *   "agent" process (a copy of node, the launch's `agentExe`), in `secrets`,
 *   against a real ArbiterServer loaded with a policy.yaml (`.env`: no-model,
 *   reader `mdu-holder`, a reader the test builds and pins by path and hash,
 *   tests/lib/holder-reader.c), and the AnthropicProxy in its production
 *   wiring (a data and a human client). The agent does what Claude Code does
 *   for a Bash call: it creates `tasks/<id>.output`, runs `bash -c <command>`
 *   with that file as the call's stdout and stderr, and once the call exits
 *   reads the file back with Claude Code's check (`lstat` the path, open it
 *   `O_NOFOLLOW`, `fstat` the descriptor, refuse it unless `st_dev` and
 *   `st_ino` agree: "output file identity changed").
 *
 * The command is `mdu-holder .env | od | tr`: the reader holds the file's
 * bytes, so the guard labels the task file it writes (plan 13 D5) and the
 * agent's own open of it is served the twin (`$MDU:nomodel_Read[…]`, the
 * derived twin, whose symbol stands for the real output). The bug (drill
 * conf-hold-once, runs watch-20261003T203557 and watch-20261003T204036): the
 * twin is another inode, Claude Code's check refused it and reported the
 * output unreadable, so the model saw a symbol of an ERROR and the human,
 * through the reply filter, never saw the program's output. Now the twin's
 * descriptor reports the identity of the file it stands for
 * (`stat_twin::fd_stat_call`), the check passes, and:
 *
 *   - the agent holds the twin's text, never a byte of the real output;
 *   - the proxy masks the Bash result whole (the call's tree held the
 *     secret): no form of the file on the model's wire;
 *   - the human plane's deep `desymbolize` of the symbol the model saw (what
 *     the reply filter does to a reply that quotes it) is the REAL output.
 *
 * SKIPs only where the guard is not built, the C compiler is missing, or the
 * kernel lacks seccomp user notification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
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

const CANARY = `ENV_TASK_OUTPUT_CANARY_${process.pid}`;
const FILE_HEX = Buffer.from(`API_KEY=${CANARY}\n`).toString("hex");
/** The twin base (`stat_twin::TWIN_FD_BASE`). */
const TWIN_FD_BASE = 768;

/** The agent: one Bash call the Claude Code 2.1.288 way (the output through a
 *  task file it reads back with an identity check), then it reports. */
const AGENT = `import { spawnSync } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
const cfg = JSON.parse(process.argv[2]);
fs.mkdirSync(cfg.tasks, { recursive: true });
const path = cfg.tasks + "/b1.output";
const out = fs.openSync(path, "w");
const r = spawnSync("bash", ["-c", cfg.command], { cwd: cfg.cwd, stdio: ["ignore", out, out], timeout: 60000 });
fs.closeSync(out);
const report = { status: r.status };
try {
  const l = await fsp.lstat(path);
  const h = await fsp.open(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const s = await h.stat();
    report.fd = h.fd;
    report.same = s.ino === l.ino && s.dev === l.dev;
    if (!report.same) {
      report.text = "<bash output unavailable: output file " + path + " could not be read (unknown). This usually means another Claude Code process in the same project deleted it during startup cleanup.>";
    } else {
      const chunks = [];
      for (let pos = 0; ; ) {
        const b = Buffer.alloc(65536);
        const { bytesRead } = await h.read(b, 0, b.length, pos);
        if (bytesRead === 0) break;
        chunks.push(b.subarray(0, bytesRead));
        pos += bytesRead;
      }
      report.text = Buffer.concat(chunks).toString("utf8");
      report.size = s.size;
    }
  } finally { await h.close(); }
} catch (e) { report.text = "ERR " + e.message; }
process.stdout.write("AGENT_OUT " + JSON.stringify(report) + "\\n");
`;

function post(port: number, body: unknown, session: string): Promise<number> {
  return new Promise((ok, fail) => {
    const req = http.request({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => { res.resume(); res.on("end", () => ok(res.statusCode ?? 0)); });
    req.on("error", fail);
    req.end(JSON.stringify(body));
  });
}

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

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("plan 13 D4 LIVE: a holder's call output read back from the agent's task file is the twin (identity check passes), masked to the model, and the real output once desymbolized (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-tot-")));
  const work = join(tmp, "work");
  mkdirSync(work, { recursive: true });
  const secret = join(work, ".env");
  writeFileSync(secret, `API_KEY=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  const holder = holderReader(tmp)!;
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [${holder.yaml}]\n`);
  const logs: string[] = [];
  const sock = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: (m: string) => { logs.push(m); }, confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  const human = new ArbiterClient(join(tmp, "human", "h.sock"));
  await human.connect();
  const session = `tot-${process.pid}`;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client, human), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const reg = await client.registerSecret({ path: secret, home: tmp });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    const twin = join(tmp, "env.twin");
    writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
    const agentNode = agentNodeCopy(tmp);
    // The guard's policy file sits in its own directory: the derived twins
    // are made beside it (`derived-twins/`), outside the agent's reach here.
    const guardDir = join(tmp, "guard");
    mkdirSync(guardDir, { recursive: true });
    const secretPolicy = join(guardDir, "secret-policy.json");
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: secret, twin, level: "no-model" }] }));

    const command = `mdu-holder ./.env | od -An -tx1 | tr -d " \\n"`;
    const callId = "toolu_tot_bash";
    // The proxy's record of the call's command, made when it relayed the call.
    await human.recordCallCommand({ callId, command, sessionKey: session });
    const tasks = join(tmp, "claude-uid", "proj", "sess", "tasks");
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT);
    const run = await runGuarded([agentNode, agentJs, JSON.stringify({ command, cwd: work, tasks })],
      { ...process.env, HOME: tmp, PATH: `${join(tmp, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy });
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as { status: number | null; fd?: number; same?: boolean; text: string; size?: number };
    const taskFile = join(tasks, "b1.output");

    // Preconditions: the reader got the real bytes and the call's output is
    // on disk (the human's side of the file), so a leak is possible.
    assert.equal(got.status, 0, `the call ran: ${JSON.stringify(got)}\n${run.stderr}`);
    assert.equal(readFileSync(taskFile, "utf8"), FILE_HEX, "the task file holds the real output (HumanView)");
    assert.ok(logs.some((l) => l.includes("labelWrittenPathTainted: ") && l.includes(taskFile) && l.endsWith("no-model")),
      `the holder's write labelled the task file (plan 13 D5): ${logs.filter((l) => /labelWritten|decideSecretOpen/.test(l)).join("\n")}`);

    // The fix: Claude Code's identity check accepts the twin's descriptor.
    // Before: `same` false, and the text the "could not be read (unknown)"
    // error the live drill saw.
    assert.equal(got.same, true, `fstat of the agent's descriptor names the task file (Claude Code: "output file identity changed"): ${JSON.stringify(got)}\n${run.stderr}`);
    assert.ok((got.fd ?? -1) >= TWIN_FD_BASE, `the twin's descriptor sits at the twin base: ${JSON.stringify(got)}`);
    assert.ok(!got.text.includes(FILE_HEX.slice(0, 24)) && !got.text.includes(CANARY), `CONFIDENTIALITY VIOLATION: the agent's own read of a holder's output file was raw: ${got.text}`);
    assert.match(got.text, /^\$MDU:nomodel_Read\[[0-9a-f]+\]\n?$/, `the agent reads the derived twin, one symbol: ${JSON.stringify(got)}`);
    assert.equal(got.size, Buffer.byteLength(got.text), "the size fstat reports is the twin's, what a read returns");

    // The model exit: the Bash result (the twin's text) reaches the model masked.
    const tools = [{ name: "Bash", input_schema: { type: "object" } }];
    const n = upstream.requests.length;
    assert.equal(await post(port, { model: "claude-haiku-4-5", stream: true, max_tokens: 512, tools, messages: [
      { role: "user", content: "Run it and tell me what it printed." },
      { role: "assistant", content: [{ type: "tool_use", id: callId, name: "Bash", input: { command } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: callId, content: got.text }] },
    ] }, session), 200);
    const seen = JSON.stringify((upstream.requests[n]!.json() as { messages: Array<{ content: Array<{ content: unknown }> }> }).messages[2]!.content[0]!.content);
    assert.match(seen, /\$MDU:[a-z]+_[A-Za-z]+\[[0-9a-f]+\]/, `the model sees a symbol: ${seen}`);
    assert.ok(!seen.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: the task file's output reached the model: ${seen}`);

    // The human: the reply filter's deep desymbolize of a reply that quotes
    // the symbol the model saw is the program's REAL output.
    const sym = seen.match(/\$MDU:[a-z]+_[A-Za-z]+\[[0-9a-f]+\]/)![0];
    const reply = await human.desymbolize(`It printed ${sym}`);
    assert.ok(reply.includes(FILE_HEX), `the human sees the program's real output after desymbolize (before: the "could not be read" error): ${reply.slice(0, 300)}`);

    // THE ORACLE.
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(CANARY) && !wire.includes(FILE_HEX.slice(0, 24)), "the file's bytes never reached the model");
  } finally {
    await proxy.close();
    client.close();
    human.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
