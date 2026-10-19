/**
 * script-reader-pin (sandbox) — confidentiality plan 13 §9 R5 with the REAL
 * guard reading the script an interpreter runs: the `(interpreter, script)`
 * reader pin.
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around an
 *   "agent" that runs Bash calls, in `secrets`, against a real ArbiterServer
 *   loaded from a policy.yaml on disk:
 *     ~/.pgpass   readers: [bash, python3, { app: python3, script: <stdlib base64.py>, output: clear, prints: nothing }]
 *   (the bare `bash` and `python3` entries admit nothing since plan 13 §8
 *   decision (b), 2026-10-02: before it each of the calls below but `pinned`
 *   read the file through them)
 *   base64.py run as a program (`python3 -I …/base64.py <file>`) opens its
 *   file operand: a script out of the agent's reach that stands in for
 *   `/opt/tools/report.py`.
 *
 * The calls, each naming the file through the environment (a command that
 * names a secret path is masked by the proxy's path rule whatever the
 * output rule says):
 *   pinned       `python3 -I $B64 "$PGPASSFILE" | wc -c`   (the pair)
 *   inline       `python3 -I -c '…open(argv[1])…' "$PGPASSFILE"`
 *   copy         `python3 -I $WS/base64.py "$PGPASSFILE"`  (a workspace copy)
 *   relative     `cd $(dirname $B64); python3 -I base64.py "$PGPASSFILE"`
 *   pythonpath   `PYTHONPATH=$WS python3 -I $B64 "$PGPASSFILE"`
 *   unisolated   `python3 $B64 "$PGPASSFILE"`             (user site-packages on)
 *   bashInline   `bash -c 'x=$(< "$PGPASSFILE"); … od'`   (decision (b): bash listed)
 *
 * The oracle: only the pinned pair reads the real bytes; no other call's
 * output carries the file (raw, or as the base64 that script prints); the
 * pinned call's output reaches the model through the AnthropicProxy in its
 * production wiring as printed (`output: clear`), and no byte of the file
 * reaches the model; the first-use pin written into policy.yaml names the
 * interpreter, the script and its hash, and no workspace path is pinned.
 * Red before R5: the loader refused `script:` on a reader entry, and a
 * python3 reader could not carry `output: clear`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { agentNodeCopy, pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));

/** The stdlib's base64.py, canonical, when python3 has one. */
function stdlibBase64(): string | null {
  const r = spawnSync("python3", ["-I", "-c", "import base64, os; print(os.path.realpath(base64.__file__))"], { encoding: "utf8" });
  const p = (r.stdout ?? "").trim();
  return r.status === 0 && p.endsWith("base64.py") ? p : null;
}
const B64 = process.platform === "linux" ? stdlibBase64() : null;
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !B64 ? "python3 with a stdlib base64.py is not installed"
  : false;

const CANARY = `PGPASS_R5_CANARY_${process.pid}`;
const RAW = `db:5432:prod:app:${CANARY}\n`;

/** The "agent": runs its Bash calls, prints what each returned. */
const AGENT_SOURCE = `import { spawnSync } from "node:child_process";
const cmds = JSON.parse(process.argv[2]);
const out = {};
for (const [k, cmd] of Object.entries(cmds)) {
  const r = spawnSync("bash", ["-c", cmd], { encoding: "utf8" });
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

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("R5: the (python3, script) pin under the REAL guard: only the pinned pair reads raw and its output reaches the model as printed; inline code, a copy, a relative path, PYTHONPATH and no isolation get no byte (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-r5-guard-"));
  const home = join(tmp, "home");
  const ws = join(tmp, "ws");
  mkdirSync(home, { recursive: true });
  mkdirSync(ws, { recursive: true });
  const pgpass = join(home, ".pgpass");
  writeFileSync(pgpass, RAW);
  copyFileSync(B64!, join(ws, "base64.py"));
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, [
    "version: 1",
    "paths:",
    `  - path: ${pgpass}`,
    "    level: no-model",
    "    readers:",
    "      - bash",
    "      - python3",
    `      - { app: python3, script: ${B64}, output: clear, prints: nothing }`,
    "",
  ].join("\n"));

  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  const humanClient = new ArbiterClient(human);
  await humanClient.connect();
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const session = `r5-guard-${process.pid}`;
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client, humanClient), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const reg = await client.registerSecret({ path: pgpass, home });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    const twin = join(tmp, "twin");
    writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
    const secretPolicy = join(tmp, "secret-policy.json");
    const agentNode = agentNodeCopy(tmp);
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: pgpass, twin, level: "no-model" }] }));

    const cmds = {
      pinned: `python3 -I "$B64" "$PGPASSFILE" | wc -c`,
      inline: `python3 -I -c 'import sys; sys.stdout.write(open(sys.argv[1]).read().encode().hex())' "$PGPASSFILE"`,
      copy: `python3 -I "$WS/base64.py" "$PGPASSFILE"`,
      relative: `cd "$(dirname "$B64")" && python3 -I base64.py "$PGPASSFILE"`,
      pythonpath: `PYTHONPATH="$WS" python3 -I "$B64" "$PGPASSFILE"`,
      unisolated: `python3 "$B64" "$PGPASSFILE"`,
      bashInline: `bash -c 'x=$(< "$PGPASSFILE"); printf %s "$x" | od -An -tx1 | tr -d " \\n"'`,
    };
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT_SOURCE);
    // The proxy's record of each call's command, made when it relayed the
    // call (its response side; plan 13 D9 follow-up: a call binds by it).
    for (const [k, cmd] of Object.entries(cmds)) await humanClient.recordCallCommand({ callId: `toolu_r5_${k}`, command: cmd, sessionKey: session });
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, PGPASSFILE: pgpass, B64: B64!, WS: ws, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy };
    delete env.PYTHONPATH; delete env.PYTHONNOUSERSITE; delete env.PYTHONHOME;
    const run = await runGuarded([agentNode, agentJs, JSON.stringify(cmds)], env);
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;

    // The pinned pair read the real file: base64.py printed its encoding.
    const encoded = spawnSync("python3", ["-I", B64!, "-"], { input: RAW, encoding: "utf8" }).stdout;
    assert.equal(got["pinned"]!.trim(), String(Buffer.byteLength(encoded)), `the pinned script read the real .pgpass: ${got["pinned"]}`);

    // No other call got a byte of it, raw or encoded.
    const marks = [CANARY, Buffer.from(RAW).toString("hex").slice(0, 32), encoded.trim().slice(0, 24)];
    const leaks: string[] = [];
    for (const k of ["inline", "copy", "relative", "pythonpath", "unisolated", "bashInline"]) {
      const out = got[k] ?? "";
      if (marks.some((m) => out.includes(m))) leaks.push(`${k}: ${out.slice(0, 200)}`);
    }
    assert.deepEqual(leaks, [], "CONFIDENTIALITY VIOLATION: an opener that is not the pinned (interpreter, script) pair read the raw file");

    // The pinned pair's output reaches the model as printed.
    const send = async (command: string, result: string, id: string): Promise<string> => {
      const n = upstream.requests.length;
      assert.equal(await post(port, { model: "claude-sonnet-4-5", stream: true, max_tokens: 512, tools: [{ name: "Bash", input_schema: { type: "object" } }], messages: [
        { role: "user", content: "go" },
        { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: result }] },
      ] }, session), 200);
      assert.equal(upstream.requests.length, n + 1);
      const b = upstream.requests[n]!.json() as { messages: Array<{ content: Array<{ content: unknown }> }> };
      return JSON.stringify(b.messages[2]!.content[0]!.content);
    };
    const cleared = await send(cmds.pinned, got["pinned"]!, "toolu_r5_pinned");
    assert.ok(cleared.includes(got["pinned"]!.trim()) && !cleared.includes("$MDU:"), `the pinned script's output reaches the model as printed: ${cleared}`);
    for (const k of ["inline", "copy", "relative", "pythonpath", "unisolated", "bashInline"] as const) await send(cmds[k], got[k]!, `toolu_r5_${k}`);
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!marks.some((m) => wire.includes(m)), "no byte of the file reached the model");

    // The first-use pin: the interpreter, the script and its hash; no workspace path.
    const law = readFileSync(policy, "utf8");
    assert.match(law, /scriptSha256: [0-9a-f]{64}/, `the script's hash was pinned:\n${law}`);
    assert.ok(law.includes(`script: ${B64}`), law);
    assert.match(law, /output: clear/, "the pin keeps the entry's output (a system interpreter and script)");
    assert.ok(!law.includes(ws), `no workspace path was pinned:\n${law}`);
    // plan 13 §8 decision (b): the bare entries pinned nothing (no
    // interpreter was let in through them)
    assert.ok(!/- \{?\s*app: bash,/.test(law) && !/path: \/usr\/bin\/bash/.test(law), `nothing was pinned for bash:\n${law}`);
    assert.equal(realpathSync(B64!), B64);
  } finally {
    await proxy.close();
    client.close();
    humanClient.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
