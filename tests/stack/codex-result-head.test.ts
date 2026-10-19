/**
 * codex-result-head — plan 10 §11.14 over the REAL components: a Codex exec
 * result masked whole is registered as a secret value (its whole value and
 * its long lines), but the head Codex's runtime writes in front of every
 * exec output (`Process exited with code 0`, `Original token count: 9`, …)
 * is not registered line by line.
 *
 *   a real ArbiterServer in `secrets` (a policy file labels the secret,
 *   `mytool` its listed reader), the real openai-proxy over HTTP in its
 *   production wiring, a scripted model behind it. The model asks for `mytool
 *   <secret>`; the command names the labelled path, so the whole output,
 *   head included, is masked (the head is not vouched for apart). The
 *   guard's records say `mytool` read the file raw under the call's shell.
 *
 * Before the fix every later Codex result was masked too, because its head
 * repeats the registered `Process exited with code 0` line. Now: (1) the
 * secret, read raw, still never reaches the model, in that result or in a
 * later one that prints it again; (2) a later clean result carrying only
 * Codex's head lines is forwarded raw; (3) a line the COMMAND printed that
 * reads like a head line stays registered (exact structure, in position,
 * never a content regex). Unit twins: arbiter `agent-result-head.test.ts`,
 * openai-proxy `rewrite-request.test.ts` (the §11.14 test).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream as OpenAiMockUpstream, buildExecCommandSse } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const CANARY = `RESULT_HEAD_CANARY_${process.pid}_7f3a9c`;
/** A line of the secret file that reads exactly like a Codex head line. */
const LOOKALIKE = "Process running with session ID 4242";
const FILE = `token=${CANARY}\n${LOOKALIKE}\n`;
/** codex-rs `format_response`: the head Codex writes before every exec output. */
const head = (status: string, chunk = "9a3f"): string =>
  `Chunk ID: ${chunk}\nWall time: 0.0123 seconds\n${status}\nOriginal token count: 9\nOutput:\n`;
const EXITED = "Process exited with code 0";

function codexTurn(...items: unknown[]): unknown {
  return { model: "gpt-5.5", stream: true, instructions: "You are Codex.", input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }, ...items] };
}

function codexOutputOf(body: string, callId: string): string {
  const item = (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" && i["call_id"] === callId)!;
  const o = item["output"];
  return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
}

test("a Codex result masked whole registers its secret and the lines its command printed, never Codex's own head lines; a later clean result with only head lines is forwarded raw (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-result-head-stack-"));
  const secret = join(tmp, "creds.txt");
  writeFileSync(secret, FILE);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, prints: nothing }]\n`);
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const guard = await open(human); // what the guard writes, on the human socket (plan 13 D9)
  const session = `result-head-${process.pid}`;
  let upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const seen: string[] = [];
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(await open(sock), await open(human)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const send = async (body: unknown, sse = "event: response.completed\ndata: {}\n\n"): Promise<string> => {
    upstream = new OpenAiMockUpstream({ sse });
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, { method: "POST", headers: { "content-type": "application/json", "x-mandu-session-id": session }, body: JSON.stringify(body) });
    assert.equal(res.status, 200, await res.text());
    const toModel = upstream.requests[0]!.bodyText;
    seen.push(toModel);
    return toModel;
  };
  /** One model turn asking for `cmd`, relayed (gated + recorded), and the guard's record of Codex's shell for it. */
  const relay = async (n: number, cmd: string): Promise<{ callId: string; call: unknown }> => {
    const callId = `call_rh_${n}`;
    await send(codexTurn(), buildExecCommandSse({ cmd, callId, itemId: `fc_${n}` }));
    await guard.recordExecRoot({ procKey: `rh-sh-${n}`, ancestors: ["rh-agent-0"], argv: ["/bin/bash", "-lc", cmd], session, callRoot: true });
    return { callId, call: { type: "function_call", call_id: callId, name: "exec_command", arguments: JSON.stringify({ cmd }) } };
  };
  const output = (callId: string, text: string) => ({ type: "function_call_output", call_id: callId, output: text });
  try {
    // 1. `mytool <secret>`: mytool, a listed reader, reads the labelled file raw.
    const read = await relay(1, `mytool ${secret}`);
    await guard.recordExecRoot({ procKey: "rh-mytool-2", ancestors: ["rh-sh-1", "rh-agent-0"], argv: ["mytool", secret], session });
    const d = await guard.decideSecretOpen({ path: secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "rh-mytool-2", parentKey: "rh-sh-1", ancestorKeys: ["rh-sh-1", "rh-agent-0"], session });
    assert.equal(d.verdict, "raw", `mytool is a listed reader: ${d.reason}`);
    const first = await send(codexTurn(read.call, output(read.callId, `${head(EXITED)}${FILE}`)));
    const masked = codexOutputOf(first, read.callId);
    assert.ok(!masked.includes(CANARY), `CONFIDENTIALITY VIOLATION: the reader's output reached the model raw: ${masked}`);
    assert.ok(!masked.includes(EXITED), "the whole result, head included, is the masked block (plan 13 R4)");
    assert.match(masked, /^\$MDU:nomodel_exec_command\[[0-9a-f]{4}\]/);

    // 2. Later calls in clean shells, the read call still in the history.
    const clean = await relay(3, "echo clean-$((6*7))");
    const leak = await relay(4, "mytool ./copy-the-guard-never-saw.txt");
    const running = await relay(5, "sleep 30; echo slow");
    const later = await send(codexTurn(
      read.call, output(read.callId, `${head(EXITED)}${FILE}`),
      clean.call, output(clean.callId, `${head(EXITED, "b7c1")}clean-42\n`),
      leak.call, output(leak.callId, `${head(EXITED, "c0d2")}token=${CANARY}\n`),
      running.call, output(running.callId, `${head(LOOKALIKE, "d4e5")}partial\n`),
    ));
    // (2) the clean result's head is Codex's own: no longer a registered value
    const cleanOut = codexOutputOf(later, clean.callId);
    assert.ok(cleanOut.startsWith(`${head(EXITED, "b7c1")}clean-42\n`), `utility: a clean result with only Codex's head lines is forwarded raw: ${cleanOut}`);
    // (1) the secret printed again by a route the guard never saw: the registered value masks it
    const leakOut = codexOutputOf(later, leak.callId);
    assert.ok(!leakOut.includes(CANARY), `CONFIDENTIALITY VIOLATION: a registered secret reached the model in a later result: ${leakOut}`);
    assert.match(leakOut, /Output:\n\$MDU:nomodel_exec_command\[[0-9a-f]{4}\]/, "masked by the registered value");
    // (3) the file's own line that reads like a head line is still registered:
    //     a later head carrying that exact text is masked (fail-closed)
    const runningOut = codexOutputOf(later, running.callId);
    assert.ok(!runningOut.includes("partial"), `a line the command printed stays registered even though it reads like a head line: ${runningOut}`);

    // THE ORACLE: no request to the model carried the secret.
    assert.ok(!seen.join("\n").includes(CANARY), "the secret never reached the model");
  } finally {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// 2026-10-09: the marks survive an arbiter restart (they lived in memory: the
// head lines counted again until the result was re-sent), and an MCP result
// masked whole names Codex's MCP head (`Wall time: N seconds\nOutput:`).
test("after an arbiter restart a later clean Codex result with only head lines is still forwarded raw, with no re-send; an MCP result masked whole registers its body, never Codex's MCP head line; the secret never reaches the model (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-result-head-restart-"));
  const secret = join(tmp, "creds.txt");
  writeFileSync(secret, FILE);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, prints: nothing }]\n`);
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const session = `result-head-restart-${process.pid}`;
  const MCP_HEAD = "Wall time: 0.0055 seconds\nOutput:";
  const MCP_ROWS = `rows for ${CANARY}: 4411-5522-6633-7744`;
  const seen: string[] = [];
  const boot = async () => {
    const server = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {}, confidentiality: true, integrity: false });
    await server.listen();
    const clients: ArbiterClient[] = [];
    const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
    const guard = await open(human);
    let upstream = new OpenAiMockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
    const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(await open(sock), await open(human)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
    const port = await proxy.listen(0);
    const send = async (body: unknown, sse = "event: response.completed\ndata: {}\n\n"): Promise<string> => {
      upstream = new OpenAiMockUpstream({ sse });
      const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, { method: "POST", headers: { "content-type": "application/json", "x-mandu-session-id": session }, body: JSON.stringify(body) });
      assert.equal(res.status, 200, await res.text());
      const toModel = upstream.requests[0]!.bodyText;
      seen.push(toModel);
      return toModel;
    };
    const relay = async (n: number, cmd: string): Promise<{ callId: string; call: unknown }> => {
      const callId = `call_rr_${n}`;
      await send(codexTurn(), buildExecCommandSse({ cmd, callId, itemId: `fc_${n}` }));
      await guard.recordExecRoot({ procKey: `rr-sh-${n}`, ancestors: ["rr-agent-0"], argv: ["/bin/bash", "-lc", cmd], session, callRoot: true });
      return { callId, call: { type: "function_call", call_id: callId, name: "exec_command", arguments: JSON.stringify({ cmd }) } };
    };
    const stop = async (): Promise<void> => { await proxy.close(); for (const c of clients) c.close(); await server.close(); };
    return { guard, send, relay, stop };
  };
  const output = (callId: string, text: string) => ({ type: "function_call_output", call_id: callId, output: text });
  let live = await boot();
  try {
    // 1. A listed reader's output, masked whole (head and all).
    const read = await live.relay(1, `mytool ${secret}`);
    await live.guard.recordExecRoot({ procKey: "rr-mytool-2", ancestors: ["rr-sh-1", "rr-agent-0"], argv: ["mytool", secret], session });
    const d = await live.guard.decideSecretOpen({ path: secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "rr-mytool-2", parentKey: "rr-sh-1", ancestorKeys: ["rr-sh-1", "rr-agent-0"], session });
    assert.equal(d.verdict, "raw", d.reason);
    // 2. An MCP call naming the labelled file: its header is not vouched for
    //    apart (the call names a secret path), so the whole output is masked.
    const mcpCall = { type: "function_call", call_id: "call_rr_mcp", name: "run", namespace: "mcp__box", arguments: JSON.stringify({ path: secret }) };
    const mcpOut = { type: "function_call_output", call_id: "call_rr_mcp", output: [{ type: "input_text", text: MCP_HEAD }, { type: "input_text", text: MCP_ROWS }] };
    const first = await live.send(codexTurn(read.call, output(read.callId, `${head(EXITED)}${FILE}`), mcpCall, mcpOut));
    assert.ok(!codexOutputOf(first, read.callId).includes(CANARY), "CONFIDENTIALITY VIOLATION: the reader's output reached the model raw");
    assert.ok(!codexOutputOf(first, "call_rr_mcp").includes("4411-5522"), "CONFIDENTIALITY VIOLATION: the MCP body reached the model raw");
    const headHits = async (): Promise<number> => (await live.guard.scanSecretValues(`${MCP_HEAD}\nProcess exited with code 0\nOriginal token count: 9\nWall time: 0.0123 seconds`)).hits.length;
    assert.equal(await headHits(), 0, "no head line (exec or MCP) is a registered value");
    assert.ok((await live.guard.scanSecretValues(`x ${MCP_ROWS} y`)).hits.length > 0, "the MCP body stays registered");

    // 3. The arbiter restarts (same mandu.db); the proxy too.
    await live.stop();
    live = await boot();
    assert.equal(await headHits(), 0, "after the restart, with no re-send: still no head line is a registered value");

    // 4. A clean call, and the secret printed by a route the guard never saw;
    //    the masked result is NOT in this request's history (no re-send).
    const clean = await live.relay(3, "echo clean-$((6*7))");
    const leak = await live.relay(4, "mytool ./copy-the-guard-never-saw.txt");
    const later = await live.send(codexTurn(
      clean.call, output(clean.callId, `${head(EXITED, "b7c1")}clean-42\n`),
      leak.call, output(leak.callId, `${head(EXITED, "c0d2")}token=${CANARY}\n`),
    ));
    const cleanOut = codexOutputOf(later, clean.callId);
    assert.ok(cleanOut.startsWith(`${head(EXITED, "b7c1")}clean-42\n`), `utility after a restart: a clean result with only Codex's head lines is forwarded raw: ${cleanOut}`);
    const leakOut = codexOutputOf(later, leak.callId);
    assert.ok(!leakOut.includes(CANARY), `CONFIDENTIALITY VIOLATION: a registered secret reached the model after the restart: ${leakOut}`);

    // THE ORACLE: no request to the model carried the secret or the MCP rows.
    const wire = seen.join("\n");
    assert.ok(!wire.includes(CANARY), "the secret never reached the model");
    assert.ok(!wire.includes("4411-5522-6633-7744"), "the MCP rows never reached the model");
  } finally {
    await live.stop();
    rmSync(tmp, { recursive: true, force: true });
  }
});
