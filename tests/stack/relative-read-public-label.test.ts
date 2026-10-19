/**
 * relative-read-public-label — a human `public` label decides a RELATIVE read
 * on Goose and OpenClaw as it does a Read of the absolute path (2026-10-09,
 * live drill conf-public-label-wins at 1250328fa5: the fixture the human made
 * public reached the model as `$MDU:nomodel_shell[…]` on Goose and as
 * `$MDU:nomodel_read[…]` on OpenClaw), over the REAL components: a real
 * ArbiterServer in `secrets` whose policy labels the workspace's
 * `test/fixtures/.env` public, the session bound to the agent's spec, the real
 * AnthropicProxy over HTTP in its production wiring (`new
 * ArbiterClientAdapter(new ArbiterClient(sock), new ArbiterClient(human))`,
 * as server-main builds it, with the launcher's MANDU_AGENT_CWD), a scripted
 * model behind it.
 *
 * Goose: `shell {command: "cat test/fixtures/.env"}` names no directory; the
 *   guard reports its `bash -c` (with the directory the kernel says it started
 *   in) on the human socket, the proxy's callTaint binds the call to it, and
 *   classify reads the relative token there (callWorkdir's start directory,
 *   which the `shell` name used to skip: Codex's tool has that name too).
 *     - the public fixture: in clear;
 *     - the same command also reading the workspace's `.env`: masked whole;
 *     - a call whose shell nobody reported: masked (the catalog's verdict).
 *   A FORGED `workdir` (2026-10-11): Goose's `shell` has no such field, so a
 *   `workdir` the model writes is a claim nothing acts on. It used to be
 *   believed (the tool shares Codex's name): `cat .env` with `workdir` set
 *   to the public fixture's directory reached the model raw. Now only the
 *   session's own agent table decides (GateSurface `workdir`, none for
 *   Goose): bound, the kernel's directory is read; unbound, the catalog's.
 * OpenClaw: `read {path: "test/fixtures/.env"}` resolves against its
 *   workspace, the launch directory; classify now reads the typed path there.
 *     - the public fixture: in clear;
 *     - a relative read of `.env`: masked;
 *     - a relative read of a file under a `no-model` label: masked;
 *     - a public-labelled file holding a REGISTERED secret value: the value
 *       backstop still masks it;
 *     - a proxy with no MANDU_AGENT_CWD: the catalog's verdict (masked).
 * THE ORACLE, both: the secret values are in no request to the model.
 *
 * Unit twins: arbiter `relative-path-base.test.ts`, `call-start-dir.test.ts`,
 * `workdir-per-agent.test.ts`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const FIXTURE_VALUE = `fixture-not-a-key-PUBLIC-${process.pid}`;
const SECRET_VALUE = `sk-live-REL-READ-SECRET-${process.pid}-9d2e`;
const VAULT_VALUE = `vault-REL-READ-${process.pid}`;

interface Stack {
  tmp: string;
  ws: string;
  session: string;
  guard: ArbiterClient;
  real: ArbiterClient;
  seen: string[];
  /** A proxy over the production wiring; `agentCwd` as the launcher names it. */
  proxy(opts: { agentCwd?: string; firstTurn?: string }): Promise<number>;
}

async function withStack(spec: "goose" | "openclaw-agent", fn: (s: Stack) => Promise<void>): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rel-read-"));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "test", "fixtures"), { recursive: true });
  mkdirSync(join(ws, "vault"), { recursive: true });
  const fixture = join(ws, "test", "fixtures", ".env");
  writeFileSync(fixture, `API_KEY=${FIXTURE_VALUE}\n`);
  writeFileSync(join(ws, ".env"), `API_KEY=${SECRET_VALUE}\n`);
  writeFileSync(join(ws, "vault", "k.txt"), `${VAULT_VALUE}\n`);
  writeFileSync(join(ws, "notes.txt"), `copied: ${SECRET_VALUE}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, [
    "version: 1",
    "paths:",
    `  - path: ${fixture}`,
    "    level: public",
    "    recursive: false",
    `  - path: ${join(ws, "notes.txt")}`,
    "    level: public",
    "    recursive: false",
    `  - path: ${join(ws, "vault")}`,
    "    level: no-model",
    "",
  ].join("\n"));
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(human); // what the guard writes, on the human socket
  const real = await open(sock);
  const session = `rel-read-${spec}-${process.pid}`;
  const bound = await real.setSessionSpec({ sessionKey: session, spec, requestedBy: "relative-read-public-label e2e" });
  assert.equal(bound.bound, spec);
  const proxies: AnthropicProxy[] = [];
  const seen: string[] = [];
  try {
    await fn({
      tmp, ws, session, guard, real, seen,
      proxy: async ({ agentCwd, firstTurn }) => {
        const upstream: UpstreamFetcher = async ({ body }) => {
          seen.push(body.toString("utf8"));
          const sse = seen.length === 1 && firstTurn !== undefined ? firstTurn : buildTextSse("done", { deltas: 1 });
          return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
        };
        const p = new AnthropicProxy({
          arbiter: new ArbiterClientAdapter(await open(sock), await open(human)), // PRODUCTION wiring
          upstream,
          sessionKey: session,
          ...(agentCwd !== undefined ? { agentCwd } : {}), // the launcher's MANDU_AGENT_CWD
          log: () => {},
        });
        proxies.push(p);
        return p.listen(0);
      },
    });
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
}

function post(port: number, session: string, tools: string[], messages: unknown[]): Promise<{ status: number; body: string }> {
  const body = JSON.stringify({ model: "claude-haiku-4-5", stream: true, max_tokens: 512, tools: tools.map((name) => ({ name, input_schema: { type: "object" } })), messages });
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => { let b = ""; res.on("data", (c) => (b += String(c))); res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b })); });
    r.on("error", reject);
    r.end(body);
  });
}

/** What the model received for one tool_result in one upstream request. */
function resultIn(body: string, id: string): string {
  const msgs = (JSON.parse(body) as { messages: Array<{ content?: unknown }> }).messages;
  for (const m of msgs) {
    if (!Array.isArray(m.content)) continue;
    for (const b of m.content as Array<Record<string, unknown>>) {
      if (b.type !== "tool_result" || b.tool_use_id !== id) continue;
      return typeof b.content === "string" ? b.content : JSON.stringify(b.content);
    }
  }
  throw new Error(`no tool_result ${id} forwarded`);
}

function toolUseTurn(name: string, calls: ReadonlyArray<{ id: string; input: Record<string, unknown> }>): string {
  let out = sseEvent("message_start", { type: "message_start", message: { id: "msg_rel_1", role: "assistant", content: [] } });
  calls.forEach((c, index) => {
    out += sseEvent("content_block_start", { type: "content_block_start", index, content_block: { type: "tool_use", id: c.id, name, input: {} } });
    out += sseEvent("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: JSON.stringify(c.input) } });
    out += sseEvent("content_block_stop", { type: "content_block_stop", index });
  });
  out += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } });
  out += sseEvent("message_stop", { type: "message_stop" });
  return out;
}

test("Goose: a bound `shell` read of the public fixture reaches the model in clear; the same command also reading .env, and an unbound call, stay masked (secrets axes, explicit)", async () => {
  await withStack("goose", async (s) => {
    const CALLS = [
      { id: "toolu_g_public", command: "cat test/fixtures/.env", out: `API_KEY=${FIXTURE_VALUE}\n`, reported: true },
      { id: "toolu_g_both", command: "cat test/fixtures/.env .env", out: `API_KEY=${FIXTURE_VALUE}\nAPI_KEY=${SECRET_VALUE}\n`, reported: true },
      { id: "toolu_g_unbound", command: "cat ./test/fixtures/.env", out: `API_KEY=${FIXTURE_VALUE}\n`, reported: false },
    ];
    const port = await s.proxy({ agentCwd: s.ws, firstTurn: toolUseTurn("shell", CALLS.map((c) => ({ id: c.id, input: { command: c.command } }))) });
    // 1. The model's turn: the proxy gates each shell call as it streams.
    const turn = await post(port, s.session, ["shell"], [{ role: "user", content: "go" }]);
    assert.equal(turn.status, 200);
    // 2. Goose runs each as `bash -c <command>` in its launch directory; the
    //    guard reports the shell (and the directory the kernel says it
    //    started in) on the human socket. The unbound call's never arrives.
    let n = 0;
    for (const c of CALLS.filter((x) => x.reported)) {
      await s.guard.recordExecRoot({ procKey: `g-sh-${n++}`, ancestors: ["g-agent-0"], argv: ["bash", "-c", c.command], session: s.session, callRoot: true, cwd: s.ws });
    }
    // 3. The results go back to the model.
    const history = [
      { role: "user", content: "go" },
      { role: "assistant", content: CALLS.map((c) => ({ type: "tool_use", id: c.id, name: "shell", input: { command: c.command } })) },
      { role: "user", content: CALLS.map((c) => ({ type: "tool_result", tool_use_id: c.id, content: c.out })) },
    ];
    assert.equal((await post(port, s.session, ["shell"], history)).status, 200);
    const sent = s.seen[1]!;

    const pub = resultIn(sent, "toolu_g_public");
    assert.ok(pub.includes(`API_KEY=${FIXTURE_VALUE}`), `utility: the human's public label must decide Goose's shell read (over-block): ${pub}`);
    assert.ok(!pub.includes("$MDU:"), `no symbol minted for the public fixture: ${pub}`);

    const both = resultIn(sent, "toolu_g_both");
    assert.ok(!both.includes(SECRET_VALUE), `CONFIDENTIALITY VIOLATION: the .env read alongside the public fixture reached the model raw: ${both}`);
    assert.ok(both.includes("$MDU:"), `the mixed read is a symbol: ${both}`);

    const unbound = resultIn(sent, "toolu_g_unbound");
    assert.ok(!unbound.includes(FIXTURE_VALUE) && unbound.includes("$MDU:"), `a call the recorder could not bind keeps the catalog's verdict (fail-closed): ${unbound}`);

    // THE ORACLE
    assert.ok(!s.seen.join("\n").includes(SECRET_VALUE), "CONFIDENTIALITY VIOLATION: the .env value is in a request to the model");
  });
});

test("Goose: a model-forged `workdir` on `shell` (a field Goose's tool does not have) is not believed: the bound call is read where the kernel says it ran, the unbound one keeps the catalog's verdict (secrets axes, explicit)", async () => {
  await withStack("goose", async (s) => {
    // Goose's `shell{command, timeout_secs}` runs `bash -c` in the launch
    // directory and ignores any other key: each `workdir` below is a claim
    // the model wrote and nothing acted on. Each points the arbiter at a
    // directory where the token would read differently than where it ran.
    const fixtures = join(s.ws, "test", "fixtures");
    const CALLS = [
      // `.env` read at the forged dir is the human's PUBLIC fixture; where it
      // ran, it is the workspace's secret .env.
      { id: "toolu_f_env_bound", command: "cat .env", workdir: fixtures, out: `API_KEY=${SECRET_VALUE}\n`, reported: true },
      { id: "toolu_f_env_unbound", command: "cat ./.env", workdir: fixtures, out: `API_KEY=${SECRET_VALUE}\n`, reported: false },
      // `vault/k.txt` read at `/` names nothing labelled; where it ran, the
      // human's no-model label (a name the catalog knows nothing about).
      { id: "toolu_f_vault_bound", command: "cat vault/k.txt", workdir: "/", out: `${VAULT_VALUE}\n`, reported: true },
      // utility: the forged dir changes nothing for a read the kernel's own
      // directory already decides (the public fixture, in clear).
      { id: "toolu_f_public_bound", command: "cat test/fixtures/.env", workdir: "/", out: `API_KEY=${FIXTURE_VALUE}\n`, reported: true },
    ];
    const input = (c: (typeof CALLS)[number]) => ({ command: c.command, workdir: c.workdir });
    const port = await s.proxy({ agentCwd: s.ws, firstTurn: toolUseTurn("shell", CALLS.map((c) => ({ id: c.id, input: input(c) }))) });
    assert.equal((await post(port, s.session, ["shell"], [{ role: "user", content: "go" }])).status, 200);
    // Goose ran each in its launch directory: that is what the kernel saw.
    let n = 0;
    for (const c of CALLS.filter((x) => x.reported)) {
      await s.guard.recordExecRoot({ procKey: `f-sh-${n++}`, ancestors: ["f-agent-0"], argv: ["bash", "-c", c.command], session: s.session, callRoot: true, cwd: s.ws });
    }
    const history = [
      { role: "user", content: "go" },
      { role: "assistant", content: CALLS.map((c) => ({ type: "tool_use", id: c.id, name: "shell", input: input(c) })) },
      { role: "user", content: CALLS.map((c) => ({ type: "tool_result", tool_use_id: c.id, content: c.out })) },
    ];
    assert.equal((await post(port, s.session, ["shell"], history)).status, 200);
    const sent = s.seen[1]!;

    for (const id of ["toolu_f_env_bound", "toolu_f_env_unbound"]) {
      const r = resultIn(sent, id);
      assert.ok(!r.includes(SECRET_VALUE) && r.includes("$MDU:"), `CONFIDENTIALITY VIOLATION: a forged workdir on the public fixture's directory let the workspace's .env reach the model raw (${id}): ${r}`);
    }
    const vault = resultIn(sent, "toolu_f_vault_bound");
    assert.ok(!vault.includes(VAULT_VALUE) && vault.includes("$MDU:"), `CONFIDENTIALITY VIOLATION: a forged workdir dropped the human's no-model label on a bound read: ${vault}`);
    const pub = resultIn(sent, "toolu_f_public_bound");
    assert.ok(pub.includes(`API_KEY=${FIXTURE_VALUE}`), `utility: the kernel's directory still decides the public fixture (over-block): ${pub}`);

    // THE ORACLE
    const wire = s.seen.join("\n");
    assert.ok(!wire.includes(SECRET_VALUE), "CONFIDENTIALITY VIOLATION: the .env value is in a request to the model");
    assert.ok(!wire.includes(VAULT_VALUE), "CONFIDENTIALITY VIOLATION: the vault value is in a request to the model");
  });
});

test("OpenClaw: a relative `read` of the public fixture reaches the model in clear; .env, a no-model label and a registered value stay masked; no launch directory keeps the mask (secrets axes, explicit)", async () => {
  await withStack("openclaw-agent", async (s) => {
    // The workspace's .env is a registered credential: its value is known.
    const reg = await s.real.registerSecret({ path: join(s.ws, ".env"), sessionKey: s.session });
    assert.ok(reg, "the .env registered");
    const READS = [
      { id: "toolu_o_public", path: "test/fixtures/.env", out: `API_KEY=${FIXTURE_VALUE}\n` },
      { id: "toolu_o_env", path: ".env", out: `API_KEY=${SECRET_VALUE}\n` },
      { id: "toolu_o_vault", path: "vault/k.txt", out: `${VAULT_VALUE}\n` },
      { id: "toolu_o_copied", path: "notes.txt", out: `copied: ${SECRET_VALUE}\n` },
    ];
    const history = [
      { role: "user", content: "Read test/fixtures/.env and tell me the value of API_KEY in one sentence." },
      { role: "assistant", content: READS.map((r) => ({ type: "tool_use", id: r.id, name: "read", input: { path: r.path } })) },
      { role: "user", content: READS.map((r) => ({ type: "tool_result", tool_use_id: r.id, content: r.out })) },
    ];
    const port = await s.proxy({ agentCwd: s.ws });
    assert.equal((await post(port, s.session, ["read"], history)).status, 200);
    const sent = s.seen[0]!;

    const pub = resultIn(sent, "toolu_o_public");
    assert.ok(pub.includes(`API_KEY=${FIXTURE_VALUE}`), `utility: the human's public label must decide OpenClaw's relative read (over-block): ${pub}`);
    assert.ok(!pub.includes("$MDU:"), `no symbol minted for the public fixture: ${pub}`);

    const env = resultIn(sent, "toolu_o_env");
    assert.ok(!env.includes(SECRET_VALUE) && env.includes("$MDU:"), `CONFIDENTIALITY VIOLATION: a relative read of .env reached the model raw: ${env}`);
    const vault = resultIn(sent, "toolu_o_vault");
    assert.ok(!vault.includes(VAULT_VALUE) && vault.includes("$MDU:"), `CONFIDENTIALITY VIOLATION: a relative read under the no-model label reached the model raw: ${vault}`);
    const copied = resultIn(sent, "toolu_o_copied");
    assert.ok(!copied.includes(SECRET_VALUE), `CONFIDENTIALITY VIOLATION: a registered value inside a public-labelled file reached the model raw: ${copied}`);

    // A proxy the launcher named no directory: the relative fixture keeps the catalog's verdict.
    const bare = await s.proxy({});
    assert.equal((await post(bare, s.session, ["read"], history)).status, 200);
    const noBase = resultIn(s.seen[1]!, "toolu_o_public");
    assert.ok(!noBase.includes(FIXTURE_VALUE) && noBase.includes("$MDU:"), `no launch directory: the catalog's .env shape (fail-closed): ${noBase}`);

    // THE ORACLE
    const wire = s.seen.join("\n");
    assert.ok(!wire.includes(SECRET_VALUE), "CONFIDENTIALITY VIOLATION: the .env value is in a request to the model");
    assert.ok(!wire.includes(VAULT_VALUE), "CONFIDENTIALITY VIOLATION: the vault value is in a request to the model");
  });
});
