/**
 * reader-allow-list (sandbox) — confidentiality plan 13 §3 D8 (12), the
 * maintainer's decision of 2026-10-04: raw bytes go only to a vetted reader
 * (ssh, ssh-add) or to a program its reader entry
 * vouches for (`prints: nothing`); every other program gets the twin.
 *
 * With the REAL guard, the arbiter and the AnthropicProxy in its production
 * wiring, one program the test builds (`mdu-holder`, tests/lib/holder-reader.c:
 * it prints the files it is given) pinned by path and hash:
 *
 *   ~/plain.env    readers: [{ app: mdu-holder, path, sha256 }]                   (no word)
 *   ~/vouched.env  readers: [{ app: mdu-holder, path, sha256, prints: nothing }]  (the human's word)
 *   ~/.ssh/id_test readers: [ssh-add]                                              (a vetted reader)
 *
 *   unvetted   `mdu-holder plain.env`    → the twin: no byte of it (red before: the raw file)
 *   vouched    `mdu-holder vouched.env`  → the raw bytes (the human's word), its call masked
 *   vetted     `ssh-add ~/.ssh/id_test` (to an ssh-agent the test starts) → ssh-add opens
 *              the key raw (the arbiter says so); it prints nothing of it
 *
 * The oracle: the twin case prints no byte of its canary, the vouched case
 * prints its canary (the control that the word admits), ssh's open is raw,
 * and no canary of any file reaches the model's wire. Self-skips (said)
 * without a C compiler or ssh-agent / ssh-add.
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
import { holderReader, holderSkip } from "../../lib/holder-reader.js";
import { stateAxes } from "../../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const has = (p: string): boolean => spawnSync("sh", ["-c", `command -v ${p}`]).status === 0;
const skip = process.platform !== "linux" ? "Linux only"
  : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
  : !has("ssh-add") || !has("ssh-agent") ? "ssh-add and ssh-agent (openssh-client) are needed: the vetted reader"
  : holderSkip() !== false ? holderSkip()
  : false;

const PLAIN = `ALLOW_LIST_PLAIN_${process.pid}_t2Ks`;
const VOUCHED = `ALLOW_LIST_VOUCHED_${process.pid}_w8Pq`;
const KEY = `ALLOW_LIST_KEY_${process.pid}_z5Mn`;

/** The "agent": runs its Bash calls in order, prints what each returned. */
const AGENT_SOURCE = `import { spawnSync } from "node:child_process";
const cmds = JSON.parse(process.argv[2]);
const out = {};
for (const [k, cmd] of Object.entries(cmds)) {
  const r = spawnSync("bash", ["-c", cmd], { encoding: "utf8", timeout: 30000 });
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

test("the allow-list: an unvetted program named without the word reads the twin, with `prints: nothing` reads raw, a vetted reader (ssh-add) reads raw; nothing reaches the model (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-allow-list-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, ".ssh"), { recursive: true, mode: 0o700 });
  const plain = join(home, "plain.env");
  const vouched = join(home, "vouched.env");
  const key = join(home, ".ssh", "id_test");
  writeFileSync(plain, `API_TOKEN=${PLAIN}\n`);
  writeFileSync(vouched, `API_TOKEN=${VOUCHED}\n`);
  writeFileSync(key, `-----BEGIN OPENSSH PRIVATE KEY-----\n${KEY}\n-----END OPENSSH PRIVATE KEY-----\n`, { mode: 0o600 });
  const holder = holderReader(tmp)!;
  const pin = `{ app: ${holder.app}, path: ${holder.path}, sha256: ${holder.sha256} }`;
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, [
    "version: 1", "paths:",
    `  - path: ${plain}`, "    level: no-model", `    readers: [${pin}]`,
    `  - path: ${vouched}`, "    level: no-model", `    readers: [${holder.yaml}]`,
    `  - path: ${key}`, "    level: no-model", "    readers: [ssh-add]", "",
  ].join("\n"));

  const logs: string[] = [];
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: (m) => logs.push(m), confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  const humanClient = new ArbiterClient(human);
  await humanClient.connect();
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const session = `allow-list-${process.pid}`;
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client, humanClient), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  let sshAgentPid = 0;
  try {
    const secrets: Array<{ path: string; twin: string; level: string }> = [];
    for (const [i, p] of [plain, vouched, key].entries()) {
      const reg = await client.registerSecret({ path: p, home });
      assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
      const twin = join(tmp, `twin-${i}`);
      writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
      secrets.push({ path: p, twin, level: "no-model" });
    }
    const secretPolicy = join(tmp, "secret-policy.json");
    const agentNode = agentNodeCopy(tmp);
    writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets }));

    // The files are named through the environment, so no command names a
    // secret path (the proxy's path rule would mask the call whatever it read).
    const cmds: Record<string, string> = {
      unvetted: `mdu-holder "$PLAIN_F"`,
      vouched: `mdu-holder "$VOUCHED_F"`,
      vetted: `ssh-add "$KEY_F" 2>&1; echo rc=$?`,
    };
    // An ssh-agent started outside the guard (its own start-up sweep of
    // ~/.ssh/agent is no part of what is tested); ssh-add talks to it.
    const agentSock = join(tmp, "ssh-agent.sock");
    const ag = spawnSync("ssh-agent", ["-s", "-a", agentSock], { encoding: "utf8", env: { ...process.env, HOME: home } });
    sshAgentPid = Number(/SSH_AGENT_PID=(\d+)/.exec(ag.stdout ?? "")?.[1] ?? 0);
    assert.ok(sshAgentPid > 0, `ssh-agent started: ${ag.stdout}${ag.stderr}`);
    const agentJs = join(tmp, "agent.mjs");
    writeFileSync(agentJs, AGENT_SOURCE);
    for (const [k, cmd] of Object.entries(cmds)) await humanClient.recordCallCommand({ callId: `toolu_al_${k}`, command: cmd, sessionKey: session });
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, PLAIN_F: plain, VOUCHED_F: vouched, KEY_F: key, PATH: `${join(tmp, "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`, SSH_AUTH_SOCK: agentSock, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy };
    const run = await runGuarded([agentNode, agentJs, JSON.stringify(cmds)], env);
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;
    const show = JSON.stringify(got, null, 1);

    // 1. unvetted, no word: the twin (it printed the placeholder copy)
    assert.ok(!got["unvetted"]!.includes(PLAIN), `CONFIDENTIALITY VIOLATION: an unvetted program named without prints: nothing read the raw file: ${show}`);
    assert.match(got["unvetted"]!, /API_TOKEN=/, `it read the twin, not nothing: ${show}`);
    assert.ok(logs.some((l) => l.includes(`${plain} by ${holder.path}`) && / → twin \(.*not a program Mandu knows/.test(l)), logs.filter((l) => l.includes("decideSecretOpen")).join("\n"));
    // 2. the human's word: raw (the control that the word admits)
    assert.ok(got["vouched"]!.includes(VOUCHED), `the vouched program read the raw file: ${show}`);
    // 3. the vetted reader: ssh opened the key raw, and printed nothing of it
    assert.ok(logs.some((l) => l.includes(`${key} by `) && /\/ssh-add\b/.test(l) && / → raw /.test(l)), `ssh-add read the key raw: ${show}\n${logs.filter((l) => l.includes("decideSecretOpen")).join("\n")}`);
    assert.ok(!got["vetted"]!.includes(KEY), `ssh-add printed nothing of the key: ${show}`);

    // 4. the model's wire stays clean in every case
    for (const [k, cmd] of Object.entries(cmds)) {
      const id = `toolu_al_${k}`;
      assert.equal(await post(port, { model: "claude-sonnet-4-5", stream: true, max_tokens: 256, tools: [{ name: "Bash", input_schema: { type: "object" } }], messages: [
        { role: "user", content: "go" },
        { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command: cmd } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: got[k] ?? "" }] },
      ] }, session), 200);
    }
    const wire = upstream.requests.map((r) => r.bodyText).join("\n");
    for (const c of [PLAIN, VOUCHED, KEY]) assert.ok(!wire.includes(c), `CONFIDENTIALITY VIOLATION: ${c} reached the model`);
  } finally {
    if (sshAgentPid > 0) try { process.kill(sshAgentPid); } catch { /* gone */ }
    await proxy.close();
    client.close();
    humanClient.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
