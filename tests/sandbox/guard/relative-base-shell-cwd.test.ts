/**
 * relative-base-shell-cwd — under the REAL guard, a Claude Code tool call's
 * RELATIVE path is read where the agent really is, as the kernel sees it,
 * ACROSS calls: after a `cd` in an earlier `Bash` call and after
 * EnterWorktree (2026-10-17, confidentiality.md §6, "The base follows the
 * shell"; fs-sync.md §1.4.1).
 *
 *   the real mandu-net-guard (seccomp user notification, no root) around an
 *   "agent" process (a copy of node, the launch's `agentExe`) that keeps a
 *   session directory exactly as Claude Code does: each `Bash` call is a
 *   fresh `bash -c 'source … && eval '<command>' && pwd -P >| <cwd file>'`
 *   spawned IN that directory, and the directory the shell ended in (the cwd
 *   file) becomes the session's directory for the next call; its `Read`
 *   opens `<session directory>/<file_path>` in the agent process itself; its
 *   `EnterWorktree` moves the session's directory with no shell at all. A
 *   real ArbiterServer in `secrets` whose policy.yaml labels the
 *   workspace's `vault/` and the worktree `.claude/worktrees/release/`
 *   no-model and the fixture `test/fixtures/.env` public (human labels; no
 *   file is a registered secret, so no launch twin stands behind a
 *   verdict), and the real AnthropicProxy in its production wiring.
 *
 * The model's calls, one per turn, as a session runs them:
 *
 *   1. Bash `cd vault`
 *   2. Read `plan.md`            → `<ws>/vault/plan.md`: MASKED at its FIRST
 *      exposure. The agent opened the file itself (no shell, no gate on its
 *      read); the guard reported that open (`labelledLevel` with
 *      `agentOpen`) and classify read the relative value at the file the
 *      kernel opened. RED before: the value named no label (no base), the
 *      plan reached the model in clear and was masked only after the fact,
 *      once a shell had read the file;
 *   3. Bash `cat plan.md`        → MASKED (the guard serves the shell the
 *      label's placeholder, and classify reads the token where the kernel
 *      says the call's shell started: `<ws>/vault`);
 *   4. Bash `cd ..`, 5. Bash `cat plan.md`, 6. Read `plan.md` → the
 *      workspace's open plan: in clear (utility: the base followed back, and
 *      the vault open of call 2 is outside these calls' windows);
 *   7. Bash `cd test`, 8. Bash `cat fixtures/.env` → the public fixture in
 *      clear: only read in `<ws>/test`, where the kernel says this call's
 *      shell started, is the `.env`-shaped token the human's public file
 *      (red with `ProvenanceStore.callStartDir` disabled: masked);
 *   9. Bash `cd ..`, 10. EnterWorktree `release`
 *  11. Read `plan.md`            → the worktree's plan: MASKED (red before,
 *      as 2);
 *  12. Bash `cat plan.md`        → MASKED;
 *   - THE ORACLE: neither labelled plan's text is in any request to the model.
 *
 * SKIPs only where the guard is not built or the kernel lacks seccomp user
 * notification. Component twin (the guard's reports sent by hand): arbiter
 * `test/component/agent-open-base`.
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

const VAULT_PLAN = `vault-plan-LABELLED-${process.pid}`;
const WT_PLAN = `worktree-plan-LABELLED-${process.pid}`;
const OPEN_PLAN = `workspace-plan-in-clear-${process.pid}`;
const FIXTURE_VALUE = `fixture-not-a-key-PUBLIC-${process.pid}`;

/** Claude Code's loop against the model proxy, with its session directory:
 *  a `Bash` call runs in a shell of its own spawned in that directory, and
 *  the directory the shell ended in (`pwd -P`, read back from the cwd file)
 *  is the next call's; `EnterWorktree` sets it to the named worktree. */
const AGENT_CLAUDE = `import { spawn } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
const cfg = JSON.parse(process.argv[2]);
const base = process.env.ANTHROPIC_BASE_URL;
const tools = [{ name: "Bash", input_schema: { type: "object" } }, { name: "EnterWorktree", input_schema: { type: "object" } }, { name: "Read", input_schema: { type: "object" } }];
const messages = [{ role: "user", content: "go" }];
const outputs = {};
const dirs = {};
let cwd = cfg.cwd;
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
function bash(input) {
  const k = n++;
  const quoted = "'" + String(input.command).replace(/'/g, "'\\"'\\"'") + "'";
  const cwdFile = cfg.tmp + "/cwd-" + k;
  const payload = "source /dev/null 2>/dev/null || true && eval " + quoted + " && pwd -P >| " + cwdFile;
  return new Promise((ok) => {
    const c = spawn("bash", ["-c", payload], { cwd, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (out += d));
    c.on("close", () => {
      try {
        const next = readFileSync(cwdFile, "utf8").trim();
        if (next.startsWith("/") && statSync(next).isDirectory()) cwd = next;
      } catch {}
      ok(out);
    });
  });
}
async function run(u) {
  dirs[u.id] = cwd;
  if (u.name === "Read") {
    try { return readFileSync(cwd + "/" + u.input.file_path, "utf8"); } catch (e) { return "error: " + e.code; }
  }
  if (u.name === "EnterWorktree") {
    cwd = cfg.cwd + "/.claude/worktrees/" + u.input.name;
    return "Created worktree at " + cwd + ". The session is now working in the worktree.";
  }
  return bash(u.input);
}
for (let turn = 0; turn < 20; turn++) {
  const res = await fetch(base + "/v1/messages", {
    method: "POST",
    headers: { "content-type": "application/json", "x-mandu-session-id": cfg.session, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 512, tools, messages }),
  });
  const uses = toolUses(await res.text());
  if (uses.length === 0) break;
  messages.push({ role: "assistant", content: uses });
  const outs = [];
  for (const u of uses) outs.push(await run(u));
  uses.forEach((u, i) => { outputs[u.id] = outs[i]; });
  messages.push({ role: "user", content: uses.map((u, i) => ({ type: "tool_result", tool_use_id: u.id, content: outs[i] })) });
}
process.stdout.write("AGENT_OUT " + JSON.stringify({ outputs, dirs }) + "\\n");
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

/** One model turn of one tool_use, as the API streams it. */
function toolUseTurn(u: { id: string; name: string; input: Record<string, unknown> }): string {
  let out = sseEvent("message_start", { type: "message_start", message: { id: `msg_${u.id}`, role: "assistant", content: [] } });
  out += sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: u.id, name: u.name, input: {} } });
  out += sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(u.input) } });
  out += sseEvent("content_block_stop", { type: "content_block_stop", index: 0 });
  out += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } });
  out += sseEvent("message_stop", { type: "message_stop" });
  return out;
}

const cannotAttach = (stderr: string): boolean => /seccomp|SECCOMP|user notification|ENOSYS|not supported/i.test(stderr);

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("LIVE: after `cd vault` in one Bash call (and after EnterWorktree) a Read or a `cat` of `plan.md` is read where the agent really is, as the kernel saw it, and reaches the model masked at its first exposure; after `cd ..` the same name is the open plan, in clear (secrets axes)", { skip, timeout: 300_000 }, async (t) => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mandu-relbase-")));
  const work = join(tmp, "work");
  const vault = join(work, "vault");
  const wt = join(work, ".claude", "worktrees", "release");
  mkdirSync(vault, { recursive: true });
  mkdirSync(wt, { recursive: true });
  writeFileSync(join(vault, "plan.md"), `# plan\n${VAULT_PLAN}\n`);
  writeFileSync(join(wt, "plan.md"), `# plan\n${WT_PLAN}\n`);
  writeFileSync(join(work, "plan.md"), `# plan\n${OPEN_PLAN}\n`);
  mkdirSync(join(work, "test", "fixtures"), { recursive: true });
  const fixture = join(work, "test", "fixtures", ".env");
  writeFileSync(fixture, `API_KEY=${FIXTURE_VALUE}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${vault}\n    level: no-model\n    recursive: true\n  - path: ${wt}\n    level: no-model\n    recursive: true\n  - path: ${fixture}\n    level: public\n    recursive: false\n`);
  const sock = join(tmp, "arbiter.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const logs: string[] = [];
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: (m: string) => { logs.push(m); }, confidentiality: true, integrity: false });
  await server.listen();
  const client = new ArbiterClient(sock); await client.connect();
  // The proxy's second client (server-main): execGate and callTaint ride the
  // human socket, the only one the arbiter binds a call from (plan 13 D9).
  const human = new ArbiterClient(join(tmp, "human", "h.sock")); await human.connect();
  const session = `relbase-${process.pid}`;
  // No registered secret: the guard's policy names only the agent's binary.
  const agentNode = agentNodeCopy(tmp);
  const secretPolicy = join(tmp, "secret-policy.json");
  writeFileSync(secretPolicy, JSON.stringify({ unixDeny: [join(tmp, "human")], agentExe: agentNode, ask: "never", session, secrets: [] }));

  const calls = [
    { id: "toolu_rb_cd", name: "Bash", input: { command: "cd vault" } },
    { id: "toolu_rb_read", name: "Read", input: { file_path: "plan.md" } },
    { id: "toolu_rb_vault", name: "Bash", input: { command: "cat plan.md" } },
    { id: "toolu_rb_up", name: "Bash", input: { command: "cd .." } },
    { id: "toolu_rb_open", name: "Bash", input: { command: "cat plan.md " } },
    { id: "toolu_rb_readopen", name: "Read", input: { file_path: "plan.md" } },
    { id: "toolu_rb_cdtest", name: "Bash", input: { command: "cd test" } },
    { id: "toolu_rb_fixture", name: "Bash", input: { command: "cat fixtures/.env" } },
    { id: "toolu_rb_back", name: "Bash", input: { command: "cd .." } },
    { id: "toolu_rb_wt", name: "EnterWorktree", input: { name: "release" } },
    { id: "toolu_rb_wtread", name: "Read", input: { file_path: "plan.md" } },
    { id: "toolu_rb_wtplan", name: "Bash", input: { command: "cat  plan.md" } },
  ];
  const seen: string[] = [];
  const fetcher: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const call = calls[seen.length - 1];
    const sse = call ? toolUseTurn(call) : buildTextSse("done", { deltas: 1 });
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
    const { outputs: got, dirs } = JSON.parse(line!.slice("AGENT_OUT ".length)) as { outputs: Record<string, string>; dirs: Record<string, string> };
    assert.equal(seen.length, calls.length + 1, `every call's turn and the closing turn reached the model: ${seen.length}`);
    // Preconditions: the session's directory moved as Claude Code's does, and
    // each call read what its directory holds. The guard resolves the
    // shell's own `open("plan.md")` against the shell's real directory too,
    // so a labelled plan reaches the shell as the label's placeholder (the
    // kernel layer); the open plan and the public fixture are read raw.
    assert.equal(dirs["toolu_rb_read"], vault, JSON.stringify(dirs));
    assert.equal(dirs["toolu_rb_vault"], vault, JSON.stringify(dirs));
    assert.equal(dirs["toolu_rb_readopen"], work, JSON.stringify(dirs));
    assert.equal(dirs["toolu_rb_wtread"], wt, JSON.stringify(dirs));
    assert.equal(dirs["toolu_rb_open"], work, JSON.stringify(dirs));
    assert.equal(dirs["toolu_rb_fixture"], join(work, "test"), JSON.stringify(dirs));
    assert.equal(dirs["toolu_rb_wtplan"], wt, JSON.stringify(dirs));
    for (const [id, plan] of [["toolu_rb_vault", VAULT_PLAN], ["toolu_rb_wtplan", WT_PLAN]] as const) {
      assert.ok(got[id]?.includes("$MDU:") && !got[id]!.includes(plan), `${id}: the guard served the shell the placeholder: ${JSON.stringify(got)}`);
    }
    assert.ok(got["toolu_rb_open"]?.includes(OPEN_PLAN), JSON.stringify(got));
    // The agent's own reads are not gated: it read every file raw.
    assert.ok(got["toolu_rb_read"]?.includes(VAULT_PLAN), JSON.stringify(got));
    assert.ok(got["toolu_rb_readopen"]?.includes(OPEN_PLAN), JSON.stringify(got));
    assert.ok(got["toolu_rb_wtread"]?.includes(WT_PLAN), JSON.stringify(got));
    assert.ok(got["toolu_rb_fixture"]?.includes(FIXTURE_VALUE), JSON.stringify(got));

    const resultIn = (id: string): string => {
      const last = seen[seen.length - 1]!;
      for (const m of (JSON.parse(last) as { messages: Array<{ content: unknown }> }).messages) {
        if (!Array.isArray(m.content)) continue;
        for (const b of m.content as Array<{ type?: string; tool_use_id?: string; content?: unknown }>) {
          if (b.type === "tool_result" && b.tool_use_id === id) return JSON.stringify(b.content);
        }
      }
      throw new Error(`no tool_result ${id} in the request`);
    };
    const why = (): string => logs.filter((l) => /callTaint|classify/.test(l)).join("\n");
    // The FIRST request that carries each result: masking after the fact
    // (on a later request) is no protection, the model already read it.
    const firstResultIn = (id: string): string => {
      for (const body of seen) {
        for (const m of (JSON.parse(body) as { messages: Array<{ content: unknown }> }).messages) {
          if (!Array.isArray(m.content)) continue;
          for (const b of m.content as Array<{ type?: string; tool_use_id?: string; content?: unknown }>) {
            if (b.type === "tool_result" && b.tool_use_id === id) return JSON.stringify(b.content);
          }
        }
      }
      throw new Error(`no tool_result ${id} in any request`);
    };
    const masked = (id: string, plan: string, what: string): void => {
      for (const r of [firstResultIn(id), resultIn(id)]) {
        assert.ok(r.includes("$MDU:") && !r.includes(plan), `${what}: masked: ${r}\n${why()}`);
      }
    };
    masked("toolu_rb_read", VAULT_PLAN, "Read `plan.md` after `cd vault` in the call before (the agent's own open, as the kernel saw it)");
    masked("toolu_rb_vault", VAULT_PLAN, "Bash `cat plan.md` after `cd vault` in the call before (the kernel's start directory)");
    masked("toolu_rb_wtread", WT_PLAN, "Read `plan.md` after EnterWorktree (no shell moved: the agent's own open)");
    masked("toolu_rb_wtplan", WT_PLAN, "Bash `cat plan.md` after EnterWorktree");
    for (const id of ["toolu_rb_open", "toolu_rb_readopen"]) {
      const r = firstResultIn(id);
      assert.ok(r.includes(OPEN_PLAN) && !r.includes("$MDU:"), `utility: ${id}, the workspace's open plan after \`cd ..\`: in clear: ${r}`);
    }
    // THE BASE FOLLOWED THE SHELL: `fixtures/.env` has the catalog's `.env`
    // shape and names no label as written; only read in `<ws>/test`, where
    // the kernel says this call's shell started (call `cd test` left it
    // there), is it the file the human labelled public.
    const fixtureSeen = firstResultIn("toolu_rb_fixture");
    assert.ok(fixtureSeen.includes(FIXTURE_VALUE), `utility: the public fixture by a relative name, after a \`cd test\` in the call before: in clear: ${fixtureSeen}\n${why()}`);

    // THE ORACLE: neither labelled plan reached the model.
    const all = seen.join("\n");
    assert.ok(!all.includes(VAULT_PLAN), "CONFIDENTIALITY VIOLATION: the no-model vault's plan is in a request to the model");
    assert.ok(!all.includes(WT_PLAN), "CONFIDENTIALITY VIOLATION: the no-model worktree's plan is in a request to the model");
  } finally {
    await proxy.close();
    client.close(); human.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
