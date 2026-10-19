/**
 * relative-path-label — under the REAL guard, a Claude Code Bash read by a
 * RELATIVE path is read in the directory the kernel says the call's shell
 * started in (2026-10-04, confidentiality.md §6).
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around an
 *   "agent" process (a copy of node, the launch's `agentExe`) that behaves
 *   as Claude Code: it talks to the real AnthropicProxy (a scripted model
 *   behind it), runs each tool_use in a shell of its own exactly as Claude
 *   Code spawns it (`bash -c 'source … && eval '<command>' && pwd -P >| …'`,
 *   in the directory Claude Code tracks for the session), and sends the
 *   results back; a real ArbiterServer in `secrets` whose policy.yaml labels
 *   the workspace's `test/fixtures/.env` public.
 *
 * Claude Code's Bash names no directory. The guard reads the call root's
 * `/proc/<pid>/cwd` while its exec is suspended and reports it with the
 * root (`recordExecRoot.cwd`); the proxy's callTaint binds the call to that
 * shell; classify reads the call's relative tokens there. So:
 *
 *   - `cat test/fixtures/.env` from the workspace: the public fixture, in clear;
 *   - `cat fixtures/.env` from `test/` (Claude Code's tracked directory after
 *     a `cd test`): the same file, in clear;
 *   - `head fixtures/.env` from the workspace: names `<ws>/fixtures/.env`, a
 *     file no label covers: the catalog's `.env` shape, masked (the guard
 *     serves its shell the placeholder since 2026-10-17, and the model's
 *     copy is masked by path too);
 *   - `cat .env` (the workspace's own `.env`, a catalog secret) and
 *     `cd test && cat fixtures/.env`: masked;
 *   - THE ORACLE: the workspace `.env`'s value is in no request to the model.
 *
 * SKIPs only where the guard is not built or the kernel lacks seccomp user
 * notification. Stack twin (the guard's reports sent by hand):
 * tests/stack/claude-bash-public-label.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, sseEvent } from "../../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { agentNodeCopy, pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const skip = process.platform !== "linux" ? "Linux only" : !GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)" : false;

const FIXTURE_VALUE = `fixture-not-a-key-PUBLIC-${process.pid}`;
const SECRET_VALUE = `sk-live-REL-GUARD-SECRET-${process.pid}`;
const OTHER_VALUE = `other-fixture-UNLABELLED-${process.pid}`;

/** Claude Code's loop against the model proxy: each tool_use in a shell of
 *  its own spawned as Claude Code spawns it, in the directory it tracks for
 *  the session (here: the input's `description` names a subdirectory, as a
 *  previous `cd` would have left it). */
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
  const cwd = input.description ? cfg.cwd + "/" + input.description : cfg.cwd;
  return new Promise((ok) => {
    const c = spawn("bash", ["-c", payload], { cwd, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (out += d));
    c.on("close", () => ok(out));
  });
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
  for (const u of uses) outs.push(await run(u.input));
  uses.forEach((u, i) => { outputs[u.id] = outs[i]; });
  messages.push({ role: "user", content: uses.map((u, i) => ({ type: "tool_result", tool_use_id: u.id, content: outs[i] })) });
}
process.stdout.write("AGENT_OUT " + JSON.stringify(outputs) + "\\n");
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

/** One model turn of Bash tool_use blocks, as the API streams them. */
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

const cannotAttach = (stderr: string): boolean => /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(stderr);

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("LIVE: a Claude Code Bash read by a relative path is read where the kernel says its shell started: the public fixture in clear, a file no label covers and the workspace .env masked (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-relpath-")));
  const work = join(tmp, "work");
  mkdirSync(join(work, "test", "fixtures"), { recursive: true });
  mkdirSync(join(work, "fixtures"), { recursive: true });
  const fixture = join(work, "test", "fixtures", ".env");
  writeFileSync(fixture, `API_KEY=${FIXTURE_VALUE}\n`);
  writeFileSync(join(work, "fixtures", ".env"), `API_KEY=${OTHER_VALUE}\n`);
  writeFileSync(join(work, ".env"), `API_KEY=${SECRET_VALUE}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${fixture}\n    level: public\n    recursive: false\n`);
  const sock = join(tmp, "arbiter.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const logs: string[] = [];
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: (m: string) => { logs.push(m); }, confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(sock); await client.connect();
  // The proxy's second client (server-main): execGate and callTaint ride the
  // human socket, the only one the arbiter binds a call from (plan 13 D9).
  const human = new ArbiterClient(join(tmp, "human", "h.sock")); await human.connect();
  const session = `relpath-${process.pid}`;
  // The launcher registers the workspace .env and writes the guard's policy
  // file; `agentExe` names the agent's binary (resolveAgentExe).
  const secret = join(work, ".env");
  const reg = await client.registerSecret({ path: secret, home: tmp });
  assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
  const twin = join(tmp, "env.twin");
  writeFileSync(twin, typeof (reg as { twin?: unknown }).twin === "string" ? String((reg as { twin?: string }).twin) : `${reg.symbol}\n`);
  const agentNode = agentNodeCopy(tmp);
  const secretPolicy = join(tmp, "secret-policy.json");
  writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [{ path: secret, twin, level: "no-model" }] }));

  const turns = [[
    { id: "toolu_rp_pub", input: { command: "cat test/fixtures/.env" } },
    { id: "toolu_rp_sub", input: { command: "cat fixtures/.env", description: "test" } },
    // (not the same text as toolu_rp_sub: two same-text calls of one turn
    // are folded over both shells, and their directories differ)
    { id: "toolu_rp_other", input: { command: "head fixtures/.env" } },
    { id: "toolu_rp_env", input: { command: "cat .env" } },
    { id: "toolu_rp_cd", input: { command: "cd test && cat fixtures/.env" } },
  ]];
  const seen: string[] = [];
  const fetcher: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const turn = turns[seen.length - 1];
    const sse = turn ? toolUseTurn(turn) : buildTextSse("done", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(client, human), upstream: fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const agentJs = join(tmp, "agent-cc.mjs");
    writeFileSync(agentJs, AGENT_CLAUDE);
    const run = await runGuarded([agentNode, agentJs, JSON.stringify({ cwd: work, tmp, session })], {
      ...process.env, HOME: tmp, MANDU_ARBITER_SOCK: sock, MANDU_NET_GUARD_SECRETS: secretPolicy,
      ANTHROPIC_BASE_URL: `http://127.0.0.1:${port}`,
    });
    const line = (run.stdout ?? "").split("\n").find((l) => l.startsWith("AGENT_OUT "));
    if (!line && cannotAttach(run.stderr ?? "")) {
      t.skip(`the guard cannot attach here: ${run.stderr.slice(0, 300)}`);
      return;
    }
    assert.ok(line, `the agent ran under the guard (status ${run.status}): ${run.stdout}\n${run.stderr}`);
    const got = JSON.parse(line!.slice("AGENT_OUT ".length)) as Record<string, string>;
    assert.equal(seen.length, 2, `one tool turn and the closing turn reached the model: ${seen.length}`);
    // Preconditions: each call read what its directory holds.
    assert.ok(got["toolu_rp_pub"]?.includes(FIXTURE_VALUE), JSON.stringify(got));
    assert.ok(got["toolu_rp_sub"]?.includes(FIXTURE_VALUE), JSON.stringify(got));
    // `fixtures/.env` is a catalog file the launch did not register: since
    // 2026-10-17 the guard serves the shell its placeholder (confidentiality.md
    // §6, "A catalog file the launch did not register"); never its value.
    assert.ok(got["toolu_rp_other"]?.includes("$MDU:") && !got["toolu_rp_other"]!.includes(OTHER_VALUE), JSON.stringify(got));

    const resultIn = (body: string, id: string): string => {
      for (const m of (JSON.parse(body) as { messages: Array<{ content: unknown }> }).messages) {
        if (!Array.isArray(m.content)) continue;
        for (const b of m.content as Array<{ type?: string; tool_use_id?: string; content?: unknown }>) {
          if (b.type === "tool_result" && b.tool_use_id === id) return JSON.stringify(b.content);
        }
      }
      throw new Error(`no tool_result ${id} in the request`);
    };
    const pub = resultIn(seen[1]!, "toolu_rp_pub");
    assert.ok(pub.includes(FIXTURE_VALUE), `utility: the public fixture by a relative path, read where the kernel says the shell started: ${pub}`);
    const sub = resultIn(seen[1]!, "toolu_rp_sub");
    assert.ok(sub.includes(FIXTURE_VALUE), `the same file from the subdirectory the shell started in: ${sub}`);
    for (const id of ["toolu_rp_other", "toolu_rp_env", "toolu_rp_cd"]) {
      const r = resultIn(seen[1]!, id);
      assert.ok(r.includes("$MDU:"), `${id}: masked: ${r}\n${logs.filter((l) => /callTaint|classify/.test(l)).join("\n")}`);
    }
    assert.ok(!resultIn(seen[1]!, "toolu_rp_other").includes(OTHER_VALUE), "a file no label covers keeps the catalog's .env verdict: the kernel's directory decided, not a guess");

    // THE ORACLE: the workspace .env never reached the model.
    assert.ok(!seen.join("\n").includes(SECRET_VALUE), "CONFIDENTIALITY VIOLATION: the workspace .env's value is in a request to the model");
  } finally {
    await proxy.close();
    client.close(); human.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
