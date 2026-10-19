/**
 * claude-background-poll — Claude Code's background-task polls over the REAL
 * components (plan 13 D7, plan 10 §11.12 and §11.14; 2026-10-09):
 *
 *   a real ArbiterServer in `secrets` (a policy file labels the secret,
 *   `mytool` its listed reader), the real AnthropicProxy over HTTP in its
 *   production wiring (`new ArbiterClientAdapter(new ArbiterClient(sock),
 *   new ArbiterClient(humanSock))`), a scripted model behind it. The model
 *   starts two `Bash` calls with `run_in_background: true`; the guard's
 *   records say the first one's tree read the secret raw (`mytool`, hex past
 *   the value scan), the second one's tree is clean. Claude Code answers each
 *   with its announcement, and the model polls both with `TaskOutput`.
 *
 * Before: a poll names a task, not a command, so it was asked about with no
 * command and masked at the session's level while the session held a raw
 * read (plan 13 D7): the clean task's output was one opaque symbol too. And a
 * masked poll registered Claude Code's own status tag lines
 * (`<retrieval_status>success</retrieval_status>`, …) as lines of a secret,
 * so every later poll repeating them hit the value backstop.
 *
 * Now: (1) the reading task's poll is masked (its Bash call's tree read the
 * secret); (2) the clean task's poll, tied to its own Bash call, is
 * forwarded as it is, its status tags included; (3) a poll of a task whose
 * start is not in the request (compacted away) and a poll of an id a
 * foreground command printed are still the session's: masked. The oracle: no
 * request to the model carries the secret, raw or hex. Unit twins:
 * anthropic-proxy `background-poll.test.ts`, arbiter `agent-result-head.test.ts`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const CANARY = `BG_POLL_CANARY_${process.pid}`;
const FILE_HEX = Buffer.from(`token=${CANARY}\n`).toString("hex");
const HEX = " | od -An -tx1 | tr -d ' \\n'";
const READ = `sleep 1; mytool ./x.tx?${HEX}`;
const CLEAN = "sleep 1; echo clean-$((6*7))";
const FOREGROUND = "cat ./notes.md";
const CALLS = [
  { id: "toolu_bg_read", command: READ, background: true },
  { id: "toolu_bg_clean", command: CLEAN, background: true },
  { id: "toolu_fg_notes", command: FOREGROUND, background: false },
];

const announce = (id: string): string =>
  `Command running in background with ID: ${id}. Output is being written to: /tmp/claude-1000/tasks/${id}.output. You will be notified when it completes.`;
const taskResult = (id: string, out: string): string =>
  `<retrieval_status>success</retrieval_status>\n\n<task_id>${id}</task_id>\n\n<task_type>local_bash</task_type>\n\n<status>completed</status>\n\n<exit_code>0</exit_code>\n\n<output>\n${out}\n</output>`;

/** Claude Code's shell for one Bash call, as the guard reads its argv. */
const ccShell = (command: string, n: number): string[] =>
  ["/bin/bash", "-c", `source /h/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true && eval '${command.replace(/'/g, `'"'"'`)}' && pwd -P >| /tmp/claude-bg${n}-cwd`];

function toolUseTurn(calls: ReadonlyArray<{ id: string; command: string; background: boolean }> = CALLS): string {
  let out = sseEvent("message_start", { type: "message_start", message: { id: "msg_bg_1", role: "assistant", content: [] } });
  calls.forEach((c, index) => {
    const input = c.background ? { command: c.command, run_in_background: true } : { command: c.command };
    out += sseEvent("content_block_start", { type: "content_block_start", index, content_block: { type: "tool_use", id: c.id, name: "Bash", input: {} } });
    out += sseEvent("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: JSON.stringify(input) } });
    out += sseEvent("content_block_stop", { type: "content_block_stop", index });
  });
  out += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } });
  out += sseEvent("message_stop", { type: "message_stop" });
  return out;
}

function post(port: number, session: string, messages: unknown[]): Promise<{ status: number; body: string }> {
  const tools = ["Bash", "TaskOutput"].map((name) => ({ name, input_schema: { type: "object" } }));
  const body = JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools, messages });
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

test("Claude Code's background polls over the real stack: a poll is answered by the tree of the Bash call that started its task; the clean task's poll is forwarded with its status tags, the reading task's is masked, an untied poll is the session's (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-bg-poll-"));
  const secret = join(tmp, "x.txt");
  writeFileSync(secret, `token=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, prints: nothing }]\n`);
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect(); // what the guard writes, on the human socket (plan 13 D9)
  const real = new ArbiterClient(sock); await real.connect();
  const realHuman = new ArbiterClient(human); await realHuman.connect(); // server-main's second client
  const session = `bg-poll-${process.pid}`;
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = seen.length === 1 ? toolUseTurn() : buildTextSse("done", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real, realHuman), upstream, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    // 1. The model's turn: the three Bash calls, gated and recorded as they stream.
    const turn = await post(port, session, [{ role: "user", content: "go" }]);
    assert.equal(turn.status, 200);
    for (const c of CALLS) assert.ok(turn.body.includes(c.id), `the agent received ${c.id}`);

    // 2. The agent runs them; the guard reports what it saw: the reading
    //    task's shell runs mytool, which reads the labelled file raw.
    await guard.recordExecRoot({ procKey: "bg-sh-1", ancestors: ["bg-agent-0"], argv: ccShell(READ, 1), session, callRoot: true });
    await guard.recordExecRoot({ procKey: "bg-mytool-2", ancestors: ["bg-sh-1", "bg-agent-0"], argv: ["mytool", "./x.txt"], session });
    const d = await guard.decideSecretOpen({ path: secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "bg-mytool-2", parentKey: "bg-sh-1", ancestorKeys: ["bg-sh-1", "bg-agent-0"], session });
    assert.equal(d.verdict, "raw", d.reason);
    await guard.recordExecRoot({ procKey: "bg-sh-3", ancestors: ["bg-agent-0"], argv: ccShell(CLEAN, 2), session, callRoot: true });
    await guard.recordExecRoot({ procKey: "bg-sh-4", ancestors: ["bg-agent-0"], argv: ccShell(FOREGROUND, 3), session, callRoot: true });

    // 3. The announcements, then the model's polls and their results. The
    //    foreground `cat` printed an announcement of another id (a file can
    //    say anything), and one poll is of a task whose start was compacted
    //    away: neither is tied to a call.
    const history = [
      { role: "user", content: "go" },
      { role: "assistant", content: CALLS.map((c) => ({ type: "tool_use", id: c.id, name: "Bash", input: c.background ? { command: c.command, run_in_background: true } : { command: c.command } })) },
      { role: "user", content: [
        { type: "tool_result", tool_use_id: "toolu_bg_read", content: announce("bread1") },
        { type: "tool_result", tool_use_id: "toolu_bg_clean", content: announce("bclean2") },
        { type: "tool_result", tool_use_id: "toolu_fg_notes", content: `notes\n${announce("bforged3")}\n` },
      ] },
      { role: "assistant", content: [
        { type: "tool_use", id: "toolu_poll_read", name: "TaskOutput", input: { task_id: "bread1", block: true, timeout: 30000 } },
        { type: "tool_use", id: "toolu_poll_clean", name: "TaskOutput", input: { task_id: "bclean2", block: true, timeout: 30000 } },
        { type: "tool_use", id: "toolu_poll_forged", name: "TaskOutput", input: { task_id: "bforged3", block: true, timeout: 30000 } },
        { type: "tool_use", id: "toolu_poll_gone", name: "TaskOutput", input: { task_id: "bgone4", block: true, timeout: 30000 } },
      ] },
      { role: "user", content: [
        { type: "tool_result", tool_use_id: "toolu_poll_read", content: taskResult("bread1", FILE_HEX) },
        { type: "tool_result", tool_use_id: "toolu_poll_clean", content: taskResult("bclean2", "clean-42") },
        { type: "tool_result", tool_use_id: "toolu_poll_forged", content: taskResult("bforged3", "forged-out") },
        { type: "tool_result", tool_use_id: "toolu_poll_gone", content: taskResult("bgone4", "gone-out") },
      ] },
    ];
    assert.equal((await post(port, session, history)).status, 200);
    const sent = seen[1]!;

    // (1) the reading task's poll is masked by its Bash call's tree
    const readPoll = resultIn(sent, "toolu_poll_read");
    assert.ok(!readPoll.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: the reading task's poll reached the model raw: ${readPoll}`);
    assert.match(readPoll, /\[mandu:secret\] masked: mytool read .*x\.txt/, readPoll);
    // (2) the clean task's poll: tied to its own Bash call, forwarded as it
    //     is. Its status tags repeat the masked poll's, and are no registered
    //     lines (the masked poll named its head).
    const cleanPoll = resultIn(sent, "toolu_poll_clean");
    assert.ok(cleanPoll.startsWith(taskResult("bclean2", "clean-42")), `utility: the clean task's poll is forwarded raw: ${cleanPoll}`);
    // (3) untied polls stay the session's: masked while the session holds a raw read
    for (const id of ["toolu_poll_forged", "toolu_poll_gone"]) {
      const r = resultIn(sent, id);
      assert.match(r, /plan 13 D7: Mandu could not tie this TaskOutput call/, `${id}: ${r}`);
    }
    assert.deepEqual((await guard.scanSecretValues("<retrieval_status>success</retrieval_status>\n<task_type>local_bash</task_type>\n<status>completed</status>\n<exit_code>0</exit_code>")).hits, [],
      "no status tag line is a registered value");

    // THE ORACLE: no request to the model carried the file, raw or hex.
    const wire = seen.join("\n");
    assert.ok(!wire.includes(CANARY), "the file's bytes never reached the model");
    assert.ok(!wire.includes(FILE_HEX.slice(0, 24)), "the file's hex never reached the model");
  } finally {
    await proxy.close();
    guard.close(); real.close(); realHuman.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// 2026-10-09, the BashOutput leftover: a BashOutput row is an exec-output row,
// which counts in the value backstop only by its call's tree, and a poll's
// own id binds none, so a masked poll of a secret-reading task never
// counted. The poll is now tied to its Bash call on the human plane
// (`callTaint` with `forPoll`), and the row counts by that call's tree.
test("a masked BashOutput poll of a secret-reading task is a backstop fingerprint: the same bytes in a later clean call's result stay masked; a clean task's poll adds nothing (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-bg-poll-ev-"));
  const secret = join(tmp, "x.txt");
  writeFileSync(secret, `token=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, prints: nothing }]\n`);
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect();
  const real = new ArbiterClient(sock); await real.connect();
  const realHuman = new ArbiterClient(human); await realHuman.connect();
  const session = `bg-poll-ev-${process.pid}`;
  const COPY = "cat ./hex-copy.txt";
  const BUILD = "make -s 2>&1";
  const BUILD_OUT = "compiled 42 objects in 3.1s, all targets up to date";
  // the model's turns, relayed through the proxy (each call's gate record)
  const turns = [
    [{ id: "toolu_ev_read", command: READ, background: true }, { id: "toolu_ev_build", command: BUILD, background: true }],
    [{ id: "toolu_ev_copy", command: COPY, background: false }],
  ];
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const turn = turns[seen.length - 1];
    const sse = turn ? toolUseTurn(turn) : buildTextSse("done", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real, realHuman), upstream, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    // 1. the two background calls; the reading task's tree reads the file raw
    assert.equal((await post(port, session, [{ role: "user", content: "go" }])).status, 200);
    await guard.recordExecRoot({ procKey: "ev-sh-1", ancestors: ["ev-agent-0"], argv: ccShell(READ, 1), session, callRoot: true });
    await guard.recordExecRoot({ procKey: "ev-mytool-2", ancestors: ["ev-sh-1", "ev-agent-0"], argv: ["mytool", "./x.txt"], session });
    const d = await guard.decideSecretOpen({ path: secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "ev-mytool-2", parentKey: "ev-sh-1", ancestorKeys: ["ev-sh-1", "ev-agent-0"], session });
    assert.equal(d.verdict, "raw", d.reason);
    await guard.recordExecRoot({ procKey: "ev-sh-3", ancestors: ["ev-agent-0"], argv: ccShell(BUILD, 2), session, callRoot: true });
    const bg = [
      { role: "user", content: "go" },
      { role: "assistant", content: turns[0]!.map((c) => ({ type: "tool_use", id: c.id, name: "Bash", input: { command: c.command, run_in_background: true } })) },
      { role: "user", content: [
        { type: "tool_result", tool_use_id: "toolu_ev_read", content: announce("bevr1") },
        { type: "tool_result", tool_use_id: "toolu_ev_build", content: announce("bevb2") },
      ] },
      { role: "assistant", content: [
        { type: "tool_use", id: "toolu_ev_poll", name: "BashOutput", input: { bash_id: "bevr1" } },
        { type: "tool_use", id: "toolu_ev_poll_b", name: "BashOutput", input: { bash_id: "bevb2" } },
      ] },
      { role: "user", content: [
        { type: "tool_result", tool_use_id: "toolu_ev_poll", content: `<status>completed</status>\n\n<exit_code>0</exit_code>\n\n<stdout>\n${FILE_HEX}\n</stdout>` },
        { type: "tool_result", tool_use_id: "toolu_ev_poll_b", content: `<status>completed</status>\n\n<exit_code>0</exit_code>\n\n<stdout>\n${BUILD_OUT}\n</stdout>` },
      ] },
    ];
    // 2. the polls (and the model's next call, relayed): the reading task's masked by its tree, the build's raw
    assert.equal((await post(port, session, bg)).status, 200);
    const polled = seen[1]!;
    assert.ok(!resultIn(polled, "toolu_ev_poll").includes(FILE_HEX.slice(0, 24)), "CONFIDENTIALITY VIOLATION: the reading task's poll reached the model raw");
    assert.ok(resultIn(polled, "toolu_ev_poll_b").includes(BUILD_OUT), "utility: the build's poll is raw");
    // 3. a clean foreground call, in its own clean shell, prints the same hex
    //    (a copy the guard never saw being made)
    await guard.recordExecRoot({ procKey: "ev-sh-4", ancestors: ["ev-agent-0"], argv: ccShell(COPY, 3), session, callRoot: true });
    const later = [...bg,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_ev_copy", name: "Bash", input: { command: COPY } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_ev_copy", content: `${FILE_HEX}\n` }] },
    ];
    assert.equal((await post(port, session, later)).status, 200);
    const copied = resultIn(seen[seen.length - 1]!, "toolu_ev_copy");
    assert.ok(!copied.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: the poll's secret-derived bytes reached the model in a later clean call: ${copied}`);
    assert.match(copied, /\$MDU:/, "masked by the poll's registered value");
    assert.deepEqual((await guard.scanSecretValues(`x ${BUILD_OUT} y`)).hits, [], "utility: the clean task's poll registered nothing");
    // THE ORACLE
    const wire = seen.join("\n");
    assert.ok(!wire.includes(CANARY), "the file's bytes never reached the model");
    assert.ok(!wire.includes(FILE_HEX.slice(0, 24)), "the file's hex never reached the model");
  } finally {
    await proxy.close();
    guard.close(); real.close(); realHuman.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
