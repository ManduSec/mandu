/**
 * agent-flow — confidentiality plan 13 §4.5.1, the decision of 2026-10-02
 * (mask, do not refuse), under the REAL guard: the AGENT process itself
 * connects to a secret holder, and what it receives reaches the model masked.
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around an
 *   "agent" process (a copy of node, the launch's `agentExe`), in `secrets`,
 *   against a real ArbiterServer loaded with a policy.yaml (`x.txt`:
 *   no-model, reader `mdu-holder` (a reader the test builds, tests/lib/holder-reader.c, pinned by path and hash; `cat` itself admits nothing since plan 13 D8, 2026-10-03), bound nowhere), and the AnthropicProxy in
 *   its production wiring (a data and a human client). The agent's Bash call
 *   starts three local servers (python3, outliving the call): H reads x.txt
 *   at once (a holder, fed by the reader's pipe) and answers with the file's hex; K
 *   reads it only when asked over a connection the agent already holds (a
 *   keep-alive, as an HTTP MCP client keeps one), by running the reader and reading
 *   its output; L holds nothing. (Before plan 13 §8 decision (b),
 *   2026-10-02, the reader was `python3` and H and K opened the file
 *   themselves; python3 running an agent-writable script is no reader now,
 *   so they hold it through the reader's pipe, plan 13 D2.) Then the agent ITSELF, as
 *   WebFetch and an HTTP MCP client do (never a holder, D2):
 *
 *   - fetches H (call `toolu_af_fetch`, a WebFetch): the guard records the
 *     agent flow at H's accept; the summarizer's side call (a request with
 *     no tools, the fetched page as its text) and the WebFetch result both
 *     reach the model masked. Before: both raw (only the exact registered
 *     value was matched, and the hex is not it);
 *   - fetches L once the H connection is gone (`toolu_af_live`): raw (the
 *     control, and the utility);
 *   - asks K to LOAD over its keep-alive (`toolu_af_mcp`, an MCP tool): the
 *     raw open of K's reader is admitted (on master it was REFUSED: the guard
 *     judged the agent's end of the keep-alive as an exit; K is swept as the
 *     pipe's receiver), the flow is recorded at the
 *     taint-time sweep, the result is masked; a PING on the same connection
 *     (`toolu_af_ping`) is masked too while it stays open (conservative: the
 *     utility cost), and a Read result relayed with it stays raw.
 *
 * The oracle: no form of the file reaches the model. Each call's relay is
 * recorded the way the proxy records it before relaying (`recordCallCommand`
 * with no command, on the human socket). SKIPs only where the guard is not
 * built, python3 is missing, or the kernel lacks seccomp user notification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import net from "node:net";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
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
  : !has("python3") ? "python3 not installed"
  : holderSkip() !== false ? holderSkip()
  : false;

const CANARY = `X_TXT_AGENT_FLOW_${process.pid}`;
const FILE_HEX = Buffer.from(`token=${CANARY}\n`).toString("hex");

/** H and L: read the file at start from standard input (H, `@stdin`: the reader's
 *  pipe) or hold nothing (L, path `-`), mark `ready`, answer one request
 *  with the file's hex (or LIVE-AF). */
const SERVER = `import socket, sys
path, port, ready = sys.argv[1], int(sys.argv[2]), sys.argv[3]
body = "LIVE-AF" if path == "-" else (sys.stdin.read() if path == "@stdin" else open(path).read()).encode().hex()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(8); s.settimeout(90)
open(ready, "w").write("r")
c, _ = s.accept()
c.recv(4096)
c.sendall(("HTTP/1.1 200 OK\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n%s" % (len(body), body)).encode())
c.close()
`;

/** K: one keep-alive connection; LOAD reads the file through the reader (the first
 *  raw open, with the agent's connection already held by K, the reader's pipe's
 *  receiver), PING answers PONG. */
const KEEPALIVE = `import socket, subprocess, sys
path, port, ready = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(8); s.settimeout(90)
open(ready, "w").write("r")
c, _ = s.accept()
f = c.makefile("rb")
for line in f:
    cmd = line.strip()
    if cmd == b"LOAD":
        r = subprocess.run(["mdu-holder", path], capture_output=True)
        out = r.stdout.hex() if r.returncode == 0 else "DENIED:" + r.stderr.decode(errors="replace").strip()
    elif cmd == b"PING":
        out = "PONG"
    else:
        break
    c.sendall((out + "\\n").encode())
c.close()
`;

/** The agent: one Bash call (start the servers), then its OWN connections,
 *  phase by phase as the test lets it go (go-<phase> files). */
const AGENT = `import { spawnSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import net from "node:net";
const cfg = JSON.parse(process.argv[2]);
const gate = async (name) => { for (let i = 0; i < 1200 && !existsSync(cfg.dir + "/go-" + name); i++) await new Promise((r) => setTimeout(r, 50)); };
const done = (name, text) => writeFileSync(cfg.dir + "/out-" + name, text);
const fetchOnce = (port) => new Promise((ok) => {
  let got = "";
  const s = net.connect(port, "127.0.0.1", () => s.write("GET / HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n"));
  s.on("data", (d) => (got += d));
  s.on("end", () => { s.destroy(); ok(got.split("\\r\\n\\r\\n")[1] ?? got); });
  s.on("error", (e) => ok("ERR " + e.message));
});
const r = spawnSync("bash", ["-c", cfg.start], { encoding: "utf8", cwd: cfg.cwd, timeout: 60000 });
done("start", (r.stdout ?? "") + (r.stderr ?? ""));
await gate("fetch");
done("fetch", await fetchOnce(cfg.held));
await gate("live");
done("live", await fetchOnce(cfg.live));
await gate("load");
const k = net.connect(cfg.ka, "127.0.0.1");
let buf = "";
const next = () => new Promise((ok) => { const t = () => { const i = buf.indexOf("\\n"); if (i >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 1); ok(l); } else setTimeout(t, 20); }; t(); });
k.on("data", (d) => (buf += d));
k.on("error", (e) => (buf += "ERR " + e.message + "\\n"));
await new Promise((ok) => k.once("connect", ok));
k.write("LOAD\\n");
done("load", await next());
await gate("ping");
k.write("PING\\n");
done("ping", await next());
await gate("end");
k.end("BYE\\n");
k.destroy();
process.stdout.write("AGENT_DONE\\n");
`;

function freePort(host: string): Promise<number> {
  return new Promise((ok, fail) => {
    const s = net.createServer();
    s.on("error", fail);
    s.listen(0, host, () => { const p = (s.address() as net.AddressInfo).port; s.close(() => ok(p)); });
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

const sleep = (ms: number): Promise<void> => new Promise((ok) => setTimeout(ok, ms));
async function waitFile(p: string, ms = 60_000): Promise<string | null> {
  for (let t = 0; t < ms; t += 50) {
    if (existsSync(p)) { await sleep(20); return readFileSync(p, "utf8"); }
    await sleep(50);
  }
  return null;
}

const cannotAttach = (stderr: string): boolean => /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(stderr);

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("§4.5.1 LIVE: what the agent itself receives from a holder (a fetch, a keep-alive MCP connection) reaches the model masked; a later fetch of a clean server is raw (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-af-")));
  const work = join(tmp, "work");
  mkdirSync(work, { recursive: true });
  const secret = join(work, "x.txt");
  writeFileSync(secret, `token=${CANARY}\n`);
  writeFileSync(join(tmp, "srv.py"), SERVER);
  writeFileSync(join(tmp, "ka.py"), KEEPALIVE);
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
  const session = `af-${process.pid}`;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client, human), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  let guard: ReturnType<typeof spawn> | null = null;
  try {
    const reg = await client.registerSecret({ path: secret, home: tmp });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    const twin = join(tmp, "x.twin");
    writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
    const agentNode = agentNodeCopy(tmp);
    const secretPolicy = join(tmp, "secret-policy.json");
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: secret, twin, level: "no-model" }] }));
    const [held, live, ka] = [await freePort("127.0.0.1"), await freePort("127.0.0.1"), await freePort("127.0.0.1")];
    const wait = (f: string): string => `for i in $(seq 1 100); do [ -e ${f} ] && break; sleep 0.1; done`;
    // L and K detached (their subshell exits at once) and ready BEFORE H's
    // the reader reads: since 2026-10-03 the shell that starts a holder is one
    // itself (it learns the holder's exit status, plan 13 §4.9), and a
    // server it still parented would be swept with it.
    const start = [
      `( nohup python3 ${tmp}/srv.py - ${live} ${tmp}/ready-l >/dev/null 2>&1 & );`,
      `( nohup python3 ${tmp}/ka.py ./x.txt ${ka} ${tmp}/ready-k >/dev/null 2>&1 & );`,
      `${wait(`${tmp}/ready-l`)}; ${wait(`${tmp}/ready-k`)};`,
      `mdu-holder ./x.txt | nohup python3 ${tmp}/srv.py @stdin ${held} ${tmp}/ready-h >/dev/null 2>&1 &`,
      `${wait(`${tmp}/ready-h`)}; echo started`,
    ].join(" ");
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT);
    let stderr = "";
    let stdout = "";
    guard = spawn(GUARD.path!, ["--allow", "127.0.0.0/8:*", "--", agentNode, agentJs, JSON.stringify({ start, cwd: work, dir: tmp, held, live, ka })],
      { env: { ...process.env, HOME: tmp, PATH: `${join(tmp, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`, MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_NET_GUARD_SECRETS: secretPolicy }, stdio: ["ignore", "pipe", "pipe"] });
    guard.stdout!.on("data", (c) => (stdout += String(c)));
    guard.stderr!.on("data", (c) => (stderr += String(c)));
    const exited = new Promise<number | null>((ok) => guard!.on("close", (code) => ok(code)));
    const started = await Promise.race([waitFile(join(tmp, "out-start")), exited.then(() => null)]);
    if (started === null && cannotAttach(stderr)) {
      t.skip(`the guard cannot attach here: ${stderr.slice(0, 300)}`);
      return;
    }
    assert.equal(started?.trim(), "started", `the agent's Bash call started the servers: ${started}\n${stdout}\n${stderr}`);

    const tools = [{ name: "WebFetch", input_schema: { type: "object" } }, { name: "Read", input_schema: { type: "object" } }];
    const relay = async (id: string): Promise<void> => { assert.equal((await human.recordCallCommand({ callId: id, sessionKey: session })).recorded, true); };
    const go = (phase: string): void => writeFileSync(join(tmp, `go-${phase}`), "go");
    const send = async (calls: Array<{ id: string; name: string; input: Record<string, unknown>; result: string }>): Promise<string[]> => {
      const n = upstream.requests.length;
      assert.equal(await post(port, { model: "claude-sonnet-4-5", stream: true, max_tokens: 512, tools, messages: [
        { role: "user", content: "go" },
        { role: "assistant", content: calls.map((c) => ({ type: "tool_use", id: c.id, name: c.name, input: c.input })) },
        { role: "user", content: calls.map((c) => ({ type: "tool_result", tool_use_id: c.id, content: c.result })) },
      ] }, session), 200);
      const b = upstream.requests[n]!.json() as { messages: Array<{ content: Array<{ content: unknown }> }> };
      return b.messages[2]!.content.map((x) => JSON.stringify(x.content));
    };

    // 1. The agent's own fetch of H (WebFetch).
    await relay("toolu_af_fetch");
    await sleep(20);
    go("fetch");
    const fetched = await waitFile(join(tmp, "out-fetch"));
    assert.equal(fetched?.trim(), FILE_HEX, `precondition: the agent received the holder's bytes (so a leak is possible): ${fetched}\n${stderr}`);
    //    The WebFetch summarizer's side call: no tools, the page as its text.
    const nSide = upstream.requests.length;
    assert.equal(await post(port, { model: "claude-haiku-4-5", max_tokens: 256, messages: [{ role: "user", content: `Web page content:\n---\n${fetched}\n---\nSummarize it.` }] }, session), 200);
    const sideSeen = upstream.requests[nSide]!.bodyText;
    assert.ok(!sideSeen.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: the summarizer's side call carried the holder's bytes raw: ${sideSeen.slice(0, 400)}`);
    const [webfetch] = await send([{ id: "toolu_af_fetch", name: "WebFetch", input: { url: `http://127.0.0.1:${held}/`, prompt: "show" }, result: fetched! }]);
    assert.ok(!webfetch!.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: the agent's own fetch of a holder reached the model raw: ${webfetch}`);
    assert.match(webfetch!, /\[mandu:secret\] masked/, webfetch);

    // 2. The control: a fetch of L after the H connection is gone (the
    //    guard reports the close within its 200 ms look).
    await sleep(700);
    await relay("toolu_af_live");
    await sleep(20);
    go("live");
    const liveOut = await waitFile(join(tmp, "out-live"));
    assert.equal(liveOut?.trim(), "LIVE-AF");
    const [liveSeen] = await send([{ id: "toolu_af_live", name: "WebFetch", input: { url: `http://127.0.0.1:${live}/`, prompt: "show" }, result: liveOut! }]);
    assert.ok(liveSeen!.includes("LIVE-AF"), `utility: a fetch of a clean server once the holder's connection closed stays raw: ${liveSeen}`);

    // 3. The keep-alive: K reads its file only now, with the agent connected.
    await relay("toolu_af_mcp");
    await sleep(20);
    go("load");
    const loaded = await waitFile(join(tmp, "out-load"));
    assert.equal(loaded?.trim(), FILE_HEX, `K's reader's raw open is admitted while the agent holds a connection to K (refused before): ${loaded}\n${logs.filter((l) => /decideSecretOpen|AgentFlow|agent/.test(l)).join("\n")}`);
    await relay("toolu_af_ping");
    await relay("toolu_af_read");
    await sleep(20);
    go("ping");
    const pong = await waitFile(join(tmp, "out-ping"));
    assert.equal(pong?.trim(), "PONG");
    const [mcp, ping, readSeen] = await send([
      { id: "toolu_af_mcp", name: "mcp__dev__load", input: {}, result: loaded! },
      { id: "toolu_af_ping", name: "mcp__dev__ping", input: {}, result: pong! },
      { id: "toolu_af_read", name: "Read", input: { file_path: join(work, "README") }, result: "plain readme text" },
    ]);
    assert.ok(!mcp!.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: an MCP reply over the agent's keep-alive to a holder reached the model raw: ${mcp}`);
    assert.match(mcp!, /\[mandu:secret\] masked/);
    assert.ok(!ping!.includes("PONG"), `conservative (the utility cost): a reply on a connection to a holder still open is masked: ${ping}`);
    assert.ok(readSeen!.includes("plain readme text"), `utility: a file tool's result in the same window stays raw: ${readSeen}`);
    go("end");
    assert.equal(await exited, 0, `the agent ran to the end under the guard: ${stdout}\n${stderr}`);

    // THE ORACLE.
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(CANARY) && !wire.includes(FILE_HEX.slice(0, 24)), "the file's bytes never reached the model");
  } finally {
    if (guard && guard.exitCode === null) guard.kill("SIGKILL");
    await proxy.close();
    client.close();
    human.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

/** The agent of the FIFO case: one Bash call that leaves a writer of a
 *  named pipe waiting for its reader (the pipe opened BEFORE the secret is
 *  read: no label can attach to it) and appends the file's hex to a log;
 *  then the agent ITSELF reads the pipe and the log, as its Read tool does. */
const AGENT_FIFO = `import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
const cfg = JSON.parse(process.argv[2]);
const gate = async (name) => { for (let i = 0; i < 1200 && !existsSync(cfg.dir + "/go-" + name); i++) await new Promise((r) => setTimeout(r, 50)); };
const done = (name, text) => writeFileSync(cfg.dir + "/out-" + name, text);
const r = spawnSync("bash", ["-c", cfg.start], { encoding: "utf8", cwd: cfg.cwd, timeout: 60000 });
done("start", (r.stdout ?? "") + (r.stderr ?? ""));
await gate("fifo");
let fifo;
try { fifo = readFileSync(cfg.fifo, "utf8"); } catch (e) { fifo = "ERR " + e.message; }
done("fifo", fifo);
await gate("log");
let log;
try { log = readFileSync(cfg.log, "utf8"); } catch (e) { log = "ERR " + e.message; }
done("log", log);
await gate("end");
process.stdout.write("AGENT_DONE\\n");
`;

test("§4.5.1 LIVE: a named pipe a holder writes, read by the agent ITSELF (its file tool), reaches the model masked; a log a holder appends to is masked by its label (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-aff-")));
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
  const session = `aff-${process.pid}`;
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client, human), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  let guard: ReturnType<typeof spawn> | null = null;
  try {
    const reg = await client.registerSecret({ path: secret, home: tmp });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    const twin = join(tmp, "x.twin");
    writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
    const agentNode = agentNodeCopy(tmp);
    const secretPolicy = join(tmp, "secret-policy.json");
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: secret, twin, level: "no-model" }] }));
    const fifo = join(tmp, "out.fifo");
    assert.equal(spawnSync("mkfifo", [fifo]).status, 0, "mkfifo");
    const log = join(work, "build.log");
    const hex = `python3 -c 'import sys; sys.stdout.write(sys.stdin.read().encode().hex())'`;
    // The writer opens the pipe (fd 3) before the reader reads the file: the pipe
    // takes no label; the reader and python3 hold its write end at the reader's raw open.
    const start = [
      `( exec 3>${fifo}; mdu-holder ./x.txt | ${hex} >&3 ) >/dev/null 2>&1 &`,
      `mdu-holder ./x.txt | ${hex} >> ${log}; echo started`,
    ].join(" ");
    const agentJs = join(tmp, "agent-fifo.mjs");
    writeFileSync(agentJs, AGENT_FIFO);
    let stderr = "";
    let stdout = "";
    guard = spawn(GUARD.path!, ["--allow", "127.0.0.0/8:*", "--", agentNode, agentJs, JSON.stringify({ start, cwd: work, dir: tmp, fifo, log })],
      { env: { ...process.env, HOME: tmp, PATH: `${join(tmp, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`, MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"), MANDU_NET_GUARD_SECRETS: secretPolicy }, stdio: ["ignore", "pipe", "pipe"] });
    guard.stdout!.on("data", (c) => (stdout += String(c)));
    guard.stderr!.on("data", (c) => (stderr += String(c)));
    const exited = new Promise<number | null>((ok) => guard!.on("close", (code) => ok(code)));
    const started = await Promise.race([waitFile(join(tmp, "out-start")), exited.then(() => null)]);
    if (started === null && cannotAttach(stderr)) {
      t.skip(`the guard cannot attach here: ${stderr.slice(0, 300)}`);
      return;
    }
    assert.equal(started?.trim(), "started", `the agent's Bash call ran: ${started}\n${stdout}\n${stderr}`);

    const tools = [{ name: "Read", input_schema: { type: "object" } }];
    const relay = async (id: string): Promise<void> => { assert.equal((await human.recordCallCommand({ callId: id, sessionKey: session })).recorded, true); };
    const go = (phase: string): void => writeFileSync(join(tmp, `go-${phase}`), "go");
    const send = async (calls: Array<{ id: string; input: Record<string, unknown>; result: string }>): Promise<string[]> => {
      const n = upstream.requests.length;
      assert.equal(await post(port, { model: "claude-sonnet-4-5", stream: true, max_tokens: 512, tools, messages: [
        { role: "user", content: "go" },
        { role: "assistant", content: calls.map((c) => ({ type: "tool_use", id: c.id, name: "Read", input: c.input })) },
        { role: "user", content: calls.map((c) => ({ type: "tool_result", tool_use_id: c.id, content: c.result })) },
      ] }, session), 200);
      const b = upstream.requests[n]!.json() as { messages: Array<{ content: Array<{ content: unknown }> }> };
      return b.messages[2]!.content.map((x) => JSON.stringify(x.content));
    };

    // 1. The agent's own Read of the named pipe.
    await relay("toolu_aff_fifo");
    await sleep(20);
    go("fifo");
    const piped = await waitFile(join(tmp, "out-fifo"));
    assert.equal(piped?.trim(), FILE_HEX, `precondition: the agent read the holder's bytes from the pipe (so a leak is possible): ${piped}\n${stderr}`);
    const [fifoSeen] = await send([{ id: "toolu_aff_fifo", input: { file_path: fifo }, result: piped! }]);
    assert.ok(!fifoSeen!.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: the agent's own Read of a named pipe a holder writes reached the model raw: ${fifoSeen}`);
    assert.match(fifoSeen!, /\[mandu:secret\] masked/, fifoSeen);

    // 2. Already closed before this change (proved here so it stays so): a
    //    file a holder appends to takes a label (D5 / the write-open), so the
    //    agent's Read of it is served the twin or masked.
    await relay("toolu_aff_log");
    await sleep(20);
    go("log");
    const logged = await waitFile(join(tmp, "out-log"));
    assert.ok(logged !== null, "the agent read the log");
    const [logSeen] = await send([{ id: "toolu_aff_log", input: { file_path: log }, result: logged! }]);
    assert.ok(!logSeen!.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: the agent's Read of a file a holder appended to reached the model raw: ${logSeen}`);
    go("end");
    assert.equal(await exited, 0, `the agent ran to the end under the guard: ${stdout}\n${stderr}`);

    // THE ORACLE.
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(CANARY) && !wire.includes(FILE_HEX.slice(0, 24)), "the file's bytes never reached the model");
  } finally {
    if (guard && guard.exitCode === null) guard.kill("SIGKILL");
    await proxy.close();
    client.close();
    human.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
