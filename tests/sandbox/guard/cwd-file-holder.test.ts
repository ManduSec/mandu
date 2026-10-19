/**
 * cwd-file-holder — confidentiality plan 13 D4 under the REAL guard: Claude
 * Code's working-directory file after a call whose tree held a secret.
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around an
 *   "agent" process (a copy of node, the launch's `agentExe`), in `secrets`,
 *   against a real ArbiterServer loaded with a policy.yaml (`.env`: no-model,
 *   reader `mdu-holder`, built and pinned by the test, tests/lib/holder-reader.c),
 *   and the AnthropicProxy in its production wiring. The agent runs its Bash
 *   calls the way Claude Code 2.1.288 does: `bash -c "<command> && pwd -P >|
 *   /tmp/claude-<n>-cwd"`, the output through a task file; after the call it
 *   reads the cwd file back and, when it holds an absolute path of a
 *   directory, runs its next call there (else it keeps its directory).
 *
 * The call's shell reaps the reader's pipeline, so it is a holder (plan 13
 * §4.9) and the cwd file it writes is labelled; the agent is served its twin.
 * Before 2026-10-04 that twin was a symbol, Claude Code ignored it ("not an
 * absolute path") and silently kept its previous directory. Now a derived
 * file whose whole text is the canonical path of an existing directory twins
 * as its own text (a NAME in the filesystem, §4.9's uncovered channel, which
 * any later `ls` would show): the next call runs in the directory the
 * tainted call moved to. Fail-closed for anything else: a holder that writes
 * the secret into the cwd file gets a symbol back, and the agent keeps its
 * directory. The oracle: no form of the secret on the model's wire.
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

const CANARY = `ENV_CWD_FILE_CANARY_${process.pid}`;
const FILE_HEX = Buffer.from(`API_KEY=${CANARY}\n`).toString("hex");

/** The agent: its Bash calls the Claude Code 2.1.288 way, one after another,
 *  each in the directory the previous call's cwd file named. */
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
  const cwdFile = cfg.tmp + "/claude-c" + i + "-cwd";
  const fd = fs.openSync(out, "w");
  const r = spawnSync("bash", ["-c", command], { cwd, stdio: ["ignore", fd, fd], timeout: 60000 });
  fs.closeSync(fd);
  const call = { status: r.status, ranIn: cwd };
  try { call.output = await fsp.readFile(out, "utf8"); } catch (e) { call.output = "ERR " + e.message; }
  // Claude Code's read-back: an absolute path of a directory, else ignored.
  try {
    const back = (await fsp.readFile(cwdFile, "utf8")).trim();
    call.cwdRead = back;
    if (isAbsolute(back) && (await fsp.stat(back)).isDirectory()) cwd = back;
  } catch (e) { call.cwdRead = "ERR " + e.message; }
  calls.push(call);
}
process.stdout.write("AGENT_OUT " + JSON.stringify({ calls, finalCwd: cwd }) + "\\n");
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

test("plan 13 D4 LIVE: after a tainted call that cds, the agent's next call runs in the new directory; a cwd file carrying the secret is a symbol and the directory stays; nothing on the model's wire (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-cwd-")));
  const work = join(tmp, "work");
  const sub = join(work, "sub");
  mkdirSync(sub, { recursive: true });
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
  const session = `cwd-${process.pid}`;
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

    // 0: tainted, moves to sub before the reader; 1: clean, where is it?
    // 2: tainted, the wrapper's `pwd -P` is a function that prints the
    //    secret into the cwd file (a holder trying the cwd file as an exit);
    //    3: clean, where now?
    const commands = [
      `cd sub && mdu-holder ../.env | od -An -tx1 | tr -d " \\n"`,
      `pwd`,
      `pwd() { mdu-holder ../.env; }; true`,
      `pwd`,
    ];
    // Claude Code's wrapper: the command, then `pwd -P` into the call's cwd file.
    const full = commands.map((c, i) => `${c} && pwd -P >| ${join(tmp, `claude-c${i}-cwd`)}`);
    const ids = ["toolu_cwd_0", "toolu_cwd_1", "toolu_cwd_2", "toolu_cwd_3"];
    for (const [i, id] of ids.entries()) await human.recordCallCommand({ callId: id, command: full[i]!, sessionKey: session });
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT);
    const run = await runGuarded([agentNode, agentJs, JSON.stringify({ commands: full, cwd: work, tmp, tasks: join(tmp, "claude-uid", "proj", "sess", "tasks") })],
      { ...process.env, HOME: tmp, PATH: `${join(tmp, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy });
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as { calls: Array<{ status: number | null; ranIn: string; output: string; cwdRead: string }>; finalCwd: string };
    const [c0, c1, c2, c3] = got.calls;
    const dump = JSON.stringify(got).replaceAll(CANARY, "<CANARY>");

    // Preconditions: the tainted call ran, its shell is a holder, and the cwd
    // file it wrote took the label (so before the fix the agent read a symbol).
    assert.equal(c0!.status, 0, dump);
    assert.equal(readFileSync(join(tmp, "claude-c0-cwd"), "utf8"), `${sub}\n`, "on disk the cwd file names sub (HumanView)");
    assert.ok(logs.some((l) => l.includes("labelWrittenPathTainted: ") && l.includes(join(tmp, "claude-c0-cwd")) && l.endsWith("no-model")),
      `the shell's write labelled the cwd file: ${logs.filter((l) => /labelWritten/.test(l)).join("\n")}`);
    assert.match(c0!.output, /^\$MDU:nomodel_Read\[[0-9a-f]+\]\n?$/, `the call's output is the twin: ${dump}`);

    // The fix: the twin of a file holding only a directory's name is that
    // name, so the next call runs in sub.
    assert.equal(c0!.cwdRead, sub, `the agent read the directory back (before: a $MDU:nomodel_Read symbol, ignored): ${dump}`);
    assert.equal(c1!.ranIn, sub, dump);
    assert.equal(c1!.output.trim(), sub, `the next call runs in the directory the tainted call moved to: ${dump}`);

    // Fail-closed: a cwd file a holder filled with the secret is a symbol;
    // the agent ignores it and keeps its directory.
    assert.ok(!c2!.cwdRead.includes(CANARY) && !c2!.cwdRead.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: the agent read a holder's cwd file raw: ${dump}`);
    assert.match(c2!.cwdRead, /^\$MDU:nomodel_Read\[[0-9a-f]+\]$/, `a cwd file holding the secret is served a symbol: ${dump}`);
    assert.equal(c3!.ranIn, sub, `the directory stays: ${dump}`);

    // The model exit: the tainted results are masked, the clean ones raw.
    const tools = [{ name: "Bash", input_schema: { type: "object" } }];
    const n = upstream.requests.length;
    assert.equal(await post(port, { model: "claude-haiku-4-5", stream: true, max_tokens: 512, tools, messages: [
      { role: "user", content: "go" },
      { role: "assistant", content: ids.map((id, i) => ({ type: "tool_use", id, name: "Bash", input: { command: full[i] } })) },
      { role: "user", content: ids.map((id, i) => ({ type: "tool_result", tool_use_id: id, content: got.calls[i]!.output })) },
    ] }, session), 200);
    const results = (upstream.requests[n]!.json() as { messages: Array<{ content: Array<{ content: unknown }> }> }).messages[2]!.content.map((x) => JSON.stringify(x.content));
    assert.ok(results[1]!.includes(sub), `utility: the clean call's pwd reaches the model raw: ${results[1]}`);

    // THE ORACLE.
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(CANARY) && !wire.includes(FILE_HEX.slice(0, 24)), "the secret never reached the model");
  } finally {
    await proxy.close();
    client.close();
    human.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
