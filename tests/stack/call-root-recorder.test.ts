/**
 * call-root-recorder — plan 13 D7 over the REAL components: the model exit
 * binds a tool call to the agent's own shell for it, folds the whole tree
 * under that shell, and masks when it cannot tell which tree ran the call.
 *
 *   a real ArbiterServer in `secrets`, the real AnthropicProxy over HTTP in
 *   its production wiring (`new ArbiterClientAdapter(new ArbiterClient(sock),
 *   new ArbiterClient(humanSock))`, as server-main builds it),
 *   a scripted model behind it. One turn: the model emits five Bash calls
 *   (streamed, so the proxy's response-side exec gate sees each tool_use and
 *   its id before the agent does). The guard's records are then written as
 *   the guard writes them over a second production client, on the human
 *   socket where they are believed (plan 13 D9): each call's shell
 *   is the agent's own child (`recordExecRoot` with `callRoot`, Claude Code's
 *   `bash -c 'source … && eval '<command>' && pwd -P >| …'`), every exec and
 *   raw open below it with its live ancestor chain. The next request carries
 *   the five results.
 *     - a reader inside a subshell that never execs: masked (its chain links
 *       it to the call's shell);
 *     - two calls with the same text, run together, one of whose trees read
 *       the file: both masked (nothing tells the runs apart);
 *     - a call no exec of the agent carried (an unknown tree), in a session
 *       holding a raw read: masked, with the reason;
 *     - a clean call bound to its own shell: raw (utility).
 *   A third request re-sends the history after a shell for the unknown call
 *   is forged over the agent-reachable socket: it stays masked.
 *
 * Before the fix the arbiter took "the most recent exec of this command's
 * signature" as a call's root: Claude Code's eval-wrapped shell never matched
 * a command, so every reader's output (hex-encoded past the value scan)
 * reached the model raw. Unit twins: arbiter `provenance-ipc.test.ts` (the
 * D7 recorder block); live: `tests/sandbox/guard/call-tree.test.ts`.
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

const CANARY = `D7_STACK_CANARY_${process.pid}`;
const FILE_HEX = Buffer.from(`token=${CANARY}\n`).toString("hex");
const HEX = " | od -An -tx1 | tr -d ' \\n'";
const SUB = `( mytool ./x.tx?; true )${HEX}`;
const SAME = `if mkdir ./lock.d 2>/dev/null; then mytool ./x.tx?${HEX}; else echo no-lock; fi`;
const LOST = `head -c 64 ./x.tx?${HEX}`;
const CLEAN = "echo clean-$((6*7))";
const CALLS = [
  { id: "toolu_st_sub", command: SUB },
  { id: "toolu_st_same_a", command: SAME },
  { id: "toolu_st_same_b", command: SAME },
  { id: "toolu_st_lost", command: LOST },
  { id: "toolu_st_clean", command: CLEAN },
];
const OUTPUT: Record<string, string> = {
  toolu_st_sub: FILE_HEX,
  toolu_st_same_a: FILE_HEX,
  toolu_st_same_b: "no-lock\n",
  toolu_st_lost: FILE_HEX,
  toolu_st_clean: "clean-42\n",
};

/** Claude Code's shell for one Bash call, as the guard reads its argv. */
const ccShell = (command: string, n: number): string[] =>
  ["/bin/bash", "-c", `source /h/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true && eval '${command.replace(/'/g, `'"'"'`)}' && pwd -P >| /tmp/claude-st${n}-cwd`];

function toolUseTurn(calls: ReadonlyArray<{ id: string; command: string }> = CALLS): string {
  let out = sseEvent("message_start", { type: "message_start", message: { id: "msg_st_1", role: "assistant", content: [] } });
  calls.forEach((c, index) => {
    out += sseEvent("content_block_start", { type: "content_block_start", index, content_block: { type: "tool_use", id: c.id, name: "Bash", input: {} } });
    out += sseEvent("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: JSON.stringify({ command: c.command }) } });
    out += sseEvent("content_block_stop", { type: "content_block_stop", index });
  });
  out += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } });
  out += sseEvent("message_stop", { type: "message_stop" });
  return out;
}

function post(port: number, session: string, messages: unknown[]): Promise<{ status: number; body: string }> {
  const body = JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Bash", input_schema: { type: "object" } }], messages });
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

test("D7 over the real stack: the call-root recorder binds each Bash call to its shell; a subshell's reader, two same-text calls and an unknown tree are masked, a clean call is raw, a forged shell never unmasks (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-d7-stack-"));
  const secret = join(tmp, "x.txt");
  writeFileSync(secret, `token=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, prints: nothing }]\n`);
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const guard = new ArbiterClient(human); await guard.connect(); // what the guard writes, on the human socket (plan 13 D9)
  const agent = new ArbiterClient(sock); await agent.connect(); // what a program the agent runs reaches
  const real = new ArbiterClient(sock); await real.connect();
  const realHuman = new ArbiterClient(human); await realHuman.connect(); // server-main's second client
  const session = `d7-stack-${process.pid}`;
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = seen.length === 1 ? toolUseTurn() : buildTextSse("done", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real, realHuman), upstream, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    // 1. The model's turn: five Bash calls, gated by the proxy as they stream.
    const turn = await post(port, session, [{ role: "user", content: "go" }]);
    assert.equal(turn.status, 200);
    for (const c of CALLS) assert.ok(turn.body.includes(c.id), `the agent received ${c.id}`);

    // 2. The agent runs them; the guard reports what it saw.
    const reads = async (proc: string, chain: string[]): Promise<void> => {
      const d = await guard.decideSecretOpen({ path: secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: proc, parentKey: chain[0], ancestorKeys: chain, session });
      assert.equal(d.verdict, "raw", d.reason);
    };
    // the subshell reader: shell → subshell (fork only) → mytool
    await guard.recordExecRoot({ procKey: "st-sh-1", ancestors: ["st-agent-0"], argv: ccShell(SUB, 1), session, callRoot: true });
    await guard.recordExecRoot({ procKey: "st-mytool-3", ancestors: ["st-sub-2", "st-sh-1", "st-agent-0"], argv: ["mytool", "./x.txt"], session });
    await reads("st-mytool-3", ["st-sub-2", "st-sh-1", "st-agent-0"]);
    // the same text twice: the first shell takes the lock and reads
    await guard.recordExecRoot({ procKey: "st-sh-4", ancestors: ["st-agent-0"], argv: ccShell(SAME, 2), session, callRoot: true });
    await guard.recordExecRoot({ procKey: "st-sh-5", ancestors: ["st-agent-0"], argv: ccShell(SAME, 3), session, callRoot: true });
    await guard.recordExecRoot({ procKey: "st-mytool-6", ancestors: ["st-sh-4", "st-agent-0"], argv: ["mytool", "./x.txt"], session });
    await reads("st-mytool-6", ["st-sh-4", "st-agent-0"]);
    // the lost call: its reader ran, but no exec of the agent carried its
    // command (here: its shell's record never arrived)
    await guard.recordExecRoot({ procKey: "st-head-8", ancestors: ["st-wrap-7", "st-agent-0"], argv: ["head", "-c", "64", "./x.txt"], session });
    // the clean call
    await guard.recordExecRoot({ procKey: "st-sh-9", ancestors: ["st-agent-0"], argv: ccShell(CLEAN, 4), session, callRoot: true });

    // 3. The results go back to the model.
    const history = [
      { role: "user", content: "go" },
      { role: "assistant", content: CALLS.map((c) => ({ type: "tool_use", id: c.id, name: "Bash", input: { command: c.command } })) },
      { role: "user", content: CALLS.map((c) => ({ type: "tool_result", tool_use_id: c.id, content: OUTPUT[c.id] })) },
    ];
    assert.equal((await post(port, session, history)).status, 200);
    const sent = seen[1]!;
    for (const id of ["toolu_st_sub", "toolu_st_same_a", "toolu_st_same_b", "toolu_st_lost"]) {
      const r = resultIn(sent, id);
      assert.ok(!r.includes(FILE_HEX.slice(0, 24)) && !r.includes("no-lock"), `CONFIDENTIALITY VIOLATION: ${id} reached the model raw: ${r}`);
      assert.match(r, /\[mandu:secret\] masked/, `${id}: ${r}`);
    }
    assert.match(resultIn(sent, "toolu_st_sub"), /masked: mytool read .*x\.txt/);
    assert.match(resultIn(sent, "toolu_st_lost"), /plan 13 D7: Mandu could not tie this Bash call/);
    assert.ok(resultIn(sent, "toolu_st_clean").startsWith("clean-42"), `a clean call bound to its own shell is raw: ${resultIn(sent, "toolu_st_clean")}`);

    // 4. A shell for the lost call, forged over the socket the agent's tree
    //    reaches, after the call was answered: the next request (the history
    //    re-sent) still masks it.
    await agent.recordExecRoot({ procKey: "st-forged-10", ancestors: ["st-agent-0"], argv: ccShell(LOST, 5), session, callRoot: true });
    assert.equal((await post(port, session, history)).status, 200);
    const again = resultIn(seen[2]!, "toolu_st_lost");
    assert.ok(!again.includes(FILE_HEX.slice(0, 24)), `CONFIDENTIALITY VIOLATION: a forged shell unmasked the lost call: ${again}`);

    // THE ORACLE: no request to the model carried the file, raw or hex.
    const wire = seen.join("\n");
    assert.ok(!wire.includes(CANARY), "the file's bytes never reached the model");
    assert.ok(!wire.includes(FILE_HEX.slice(0, 24)), "the file's hex never reached the model");
  } finally {
    await proxy.close();
    guard.close(); agent.close(); real.close(); realHuman.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// Plan 13 D7's last residual (closed 2026-10-02): two Bash calls with the
// same text; X's shell ran a reader but X's own exec report was lost, Y's
// clean shell was recorded. On master X bound `exact` to Y's shell and its
// hex dump reached the model raw (and Y, its shell taken, was masked).
test("D7 lost record over the real stack: a call whose shell report was lost is not bound to a live same-text call's clean shell; both are masked (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-d7-lost-"));
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
  const session = `d7-lost-${process.pid}`;
  // whichever run takes the lock reads the file (hex past the value scan)
  const RUN = `if mkdir ./lock.d 2>/dev/null; then mytool ./x.tx?${HEX}; else echo no-lock; fi`;
  const calls = [{ id: "toolu_lr_x", command: RUN }, { id: "toolu_lr_y", command: RUN }];
  const output: Record<string, string> = { toolu_lr_x: FILE_HEX, toolu_lr_y: "no-lock\n" };
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = seen.length === 1 ? toolUseTurn(calls) : buildTextSse("done", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real, realHuman), upstream, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    assert.equal((await post(port, session, [{ role: "user", content: "go" }])).status, 200);
    await new Promise((ok) => setTimeout(ok, 5));
    // X's shell (lost report) → mytool, which read the file raw
    const chain = ["lr-sh-x", "lr-agent-0"];
    await guard.recordExecRoot({ procKey: "lr-mytool-3", ancestors: chain, argv: ["mytool", "./x.txt"], session });
    const d = await guard.decideSecretOpen({ path: secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "lr-mytool-3", parentKey: chain[0], ancestorKeys: chain, session });
    assert.equal(d.verdict, "raw", d.reason);
    // Y's shell, clean, recorded
    await guard.recordExecRoot({ procKey: "lr-sh-y", ancestors: ["lr-agent-0"], argv: ccShell(RUN, 7), session, callRoot: true });
    await new Promise((ok) => setTimeout(ok, 5));
    const history = [
      { role: "user", content: "go" },
      { role: "assistant", content: calls.map((c) => ({ type: "tool_use", id: c.id, name: "Bash", input: { command: c.command } })) },
      { role: "user", content: calls.map((c) => ({ type: "tool_result", tool_use_id: c.id, content: output[c.id] })) },
    ];
    assert.equal((await post(port, session, history)).status, 200);
    for (const id of ["toolu_lr_x", "toolu_lr_y"]) {
      const r = resultIn(seen[1]!, id);
      // MASTER: toolu_lr_x bound exact to lr-sh-y and its hex reached the model raw
      assert.ok(!r.includes(FILE_HEX.slice(0, 24)) && !r.includes("no-lock"), `CONFIDENTIALITY VIOLATION: ${id} reached the model raw: ${r}`);
      assert.match(r, /plan 13 D7: Mandu could not tie this Bash call/, `${id}: ${r}`);
    }
    assert.ok(!seen.join("\n").includes(FILE_HEX.slice(0, 24)), "the file's hex never reached the model");
  } finally {
    await proxy.close();
    guard.close(); real.close(); realHuman.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
