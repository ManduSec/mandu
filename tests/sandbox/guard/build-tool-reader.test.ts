/**
 * build-tool-reader (sandbox) — confidentiality plan 13 §3 D8 (10),
 * 2026-10-04: a build tool runs the code of its build file, so as a reader it
 * admits nothing, like a shell or an interpreter (§8 decision (b)).
 *
 * `cmake` stands for the build tools and runtimes that joined the
 * code-running list that day (ctest, ninja, go, cargo, run-parts, the TeX
 * engines, …): `cmake -P script.cmake` runs whatever the script says, so a
 * `.env` naming `cmake` among its readers handed the agent's script the raw
 * bytes (`file(READ …)`), which it could pass on to any metadata exit (§4.9).
 * With the REAL guard, the arbiter and the AnthropicProxy in its production
 * wiring:
 *
 *   ~/.env   level no-model, readers: [cmake], others: twin
 *
 *   read      `cmake -P read.cmake` (file(READ) then hex)  → the twin's hex: no byte
 *             of the secret. Red before: the raw bytes' hex, kept from the
 *             model only by the call's taint (the proxy masked the result)
 *   pass      `cmake -P pass.cmake` (file(READ) then python3 with the value in argv)
 *             → python3 sees the twin, no byte
 *
 * The oracle: neither output carries the canary or its hex, and no form of
 * it reaches the model. Self-skips (said) where cmake is not installed; the
 * CI kernel guest installs it (scripts/ci/guest/provision.sh).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
const has = (p: string): boolean => spawnSync("sh", ["-c", `command -v ${p}`]).status === 0;
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !has("cmake") ? "cmake is not installed (the representative build tool)"
  : !has("python3") ? "python3 is needed"
  : false;

const CANARY = `BUILD_TOOL_READER_${process.pid}_m4Rt8`;
const CANARY_HEX = Buffer.from(CANARY).toString("hex");

/** The "agent": runs its Bash calls in order, prints what each returned. */
const AGENT_SOURCE = `import { spawnSync } from "node:child_process";
const cmds = JSON.parse(process.argv[2]);
const out = {};
for (const [k, cmd] of Object.entries(cmds)) {
  const r = spawnSync("bash", ["-c", cmd], { encoding: "utf8", timeout: 60000 });
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

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("a listed build tool (cmake -P) reads the twin: its script, and the program it hands the value, see no byte; nothing reaches the model (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-build-tool-"));
  const home = join(tmp, "home");
  const ws = join(tmp, "ws");
  mkdirSync(home, { recursive: true });
  mkdirSync(ws, { recursive: true });
  const secret = join(home, ".env");
  writeFileSync(secret, `API_TOKEN=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${secret}`, "    level: no-model", "    readers: [cmake]", "    others: twin", ""].join("\n"));

  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  const humanClient = new ArbiterClient(human);
  await humanClient.connect();
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const session = `build-tool-${process.pid}`;
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client, humanClient), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const reg = await client.registerSecret({ path: secret, home });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    const twin = join(tmp, "twin");
    writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
    const secretPolicy = join(tmp, "secret-policy.json");
    const agentNode = agentNodeCopy(tmp);
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: secret, twin, level: "no-model" }] }));

    // The agent's build scripts: read the file, print its hex; hand it on.
    writeFileSync(join(ws, "read.cmake"), 'file(READ "$ENV{F}" x)\nstring(HEX "${x}" h)\nmessage("HEX=${h}")\n');
    writeFileSync(join(ws, "pass.cmake"), 'file(READ "$ENV{F}" x)\nexecute_process(COMMAND python3 -c "import sys; print(\'PASSED=\' + sys.argv[1].encode().hex())" "${x}")\n');
    const cmds: Record<string, string> = {
      read: `cmake -P "$WS/read.cmake"`,
      pass: `cmake -P "$WS/pass.cmake"`,
    };
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT_SOURCE);
    for (const [k, cmd] of Object.entries(cmds)) await humanClient.recordCallCommand({ callId: `toolu_bt_${k}`, command: cmd, sessionKey: session });
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, F: secret, WS: ws, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy };
    delete env.PYTHONPATH; delete env.PYTHONHOME;
    const run = await runGuarded([agentNode, agentJs, JSON.stringify(cmds)], env);
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;
    const show = JSON.stringify(got, null, 1);

    // The script ran and read something (the twin), not nothing.
    assert.match(got["read"]!, /HEX=[0-9a-f]{8,}/, `cmake read the file: ${show}`);
    assert.match(got["pass"]!, /PASSED=[0-9a-f]{8,}/, `cmake handed the value on: ${show}`);
    assert.ok(!got["read"]!.includes(CANARY_HEX), `CONFIDENTIALITY VIOLATION: a listed cmake read the secret raw: ${show}`);
    assert.ok(!got["pass"]!.includes(CANARY_HEX), `CONFIDENTIALITY VIOLATION: the program a listed cmake ran got the secret: ${show}`);

    // No form of the secret reaches the model.
    for (const [k, cmd] of Object.entries(cmds)) {
      const id = `toolu_bt_${k}`;
      assert.equal(await post(port, { model: "claude-sonnet-4-5", stream: true, max_tokens: 256, tools: [{ name: "Bash", input_schema: { type: "object" } }], messages: [
        { role: "user", content: "go" },
        { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command: cmd } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: got[k] ?? "" }] },
      ] }, session), 200);
    }
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    assert.ok(!wire.includes(CANARY) && !wire.includes(CANARY_HEX), "no form of the secret reached the model");
  } finally {
    await proxy.close();
    client.close();
    humanClient.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
