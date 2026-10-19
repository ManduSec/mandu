/**
 * masked-result-run-facts — confidentiality plan 13 §9 R4, the second half,
 * over the REAL components: a tool result masked because a program in its
 * tree read a secret raw says nothing about how the run went. The code that
 * held the secret chose its exit status, and before this change it reached
 * the model beside the symbol: Claude Code's `is_error: true` on the
 * tool_result block, and Codex's runtime header (`Process exited with code
 * N`, `Original token count: N`, `Wall time: N seconds`). Both proxies run in
 * their production wiring (`new XAdapter(new ArbiterClient(sock))`) over a
 * real `ArbiterServer`; the guard's reports go on the human socket.
 *
 * Oracle: the masked result carries `is_error: false` and a header with exit
 * code 0, wall time 0 and no token count; a result the model may read (no
 * raw read in its tree) keeps both as written.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { rewriteRequest } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import {
  ArbiterClientAdapter as OpenAiProxyArbiterAdapter,
  type RealArbiterClient as OpenAiProxyRealArbiterClient,
} from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { rewriteRequest as rewriteResponsesRequest } from "../../interceptors/openai-proxy/src/rewrite-request.js";
import type { ResponsesRequest } from "../../interceptors/openai-proxy/src/responses-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const KEY = "sk_live_runfacts_0123456789abcdef";
const FAILED = "Chunk ID: 7c1e\nWall time: 4.2500 seconds\nProcess exited with code 37\nOriginal token count: 30\nOutput:\n";

function bashResult(command: string, content: string, id: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "check the key" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content, is_error: true }] },
    ],
  };
}
function execResult(cmd: string, output: string, id: string): ResponsesRequest {
  return {
    model: "gpt-5.5",
    instructions: "You are Codex.",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "check the key" }] },
      { type: "function_call", call_id: id, name: "exec_command", arguments: JSON.stringify({ cmd }) },
      { type: "function_call_output", call_id: id, output },
    ],
  } as ResponsesRequest;
}
const bashBlock = (r: MessagesRequest): { content: string; is_error?: boolean } => (r.messages[2]!.content as any[])[0];
const execOut = (r: ResponsesRequest, id: string): string =>
  String((r.input as any[]).find((i) => i.type === "function_call_output" && i.call_id === id).output);

test("plan 13 §9 R4: a masked result carries is_error: false (Claude) and a header with no exit code, token count or wall time (Codex); an unmasked one keeps both (secrets axes)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-run-facts-"));
  const ws = join(tmp, "ws"); mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, `API_KEY=${KEY}\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect(); // the guard reports on the human socket (plan 13 D9)
  const realHuman = new ArbiterClient(join(tmp, "human", "h.sock")); await realHuman.connect();
  const realA: RealArbiterClient = new ArbiterClient(socketPath); await realA.connect();
  const realO: OpenAiProxyRealArbiterClient = new ArbiterClient(socketPath); await realO.connect();
  const claude = new ArbiterClientAdapter(realA, realHuman);
  const codex = new OpenAiProxyArbiterAdapter(realO, realHuman);
  const session = "s-run-facts";
  try {
    const reg = await guard.registerSecret({ path: env, sessionKey: session });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    // The agent's code downstream of a reader: it held the key and chose to fail.
    // (the command does not name the file: a path-derived verdict would mask the header too)
    const held = `keytool print | python3 -c 'import sys; sys.exit(37 if "sk_live" in sys.stdin.read() else 0)'`;
    const bind = async (callId: string, command: string, root: string, taint: boolean): Promise<void> => {
      await claude.recordCallCommand!({ callId, command, sessionKey: session });
      await guard.recordExecRoot({ procKey: root, ancestors: ["agent-rf-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true });
      if (taint) {
        await guard.processLineage({ childKey: `${root}-reader`, parentKey: root });
        await guard.taintProcessSecret({ procKey: `${root}-reader`, path: env, level: "no-model", app: "keytool", session });
      }
    };

    // Claude Code's Bash: masked, and the failure bit is gone.
    await bind("toolu_rf_1", held, "bash-rf-1", true);
    const a = await rewriteRequest(bashResult(held, "exit status 37\n", "toolu_rf_1"), { arbiter: claude, sessionKey: session });
    assert.equal(a.rewrites[0]!.symbolized, true, a.rewrites[0]!.reason);
    assert.match(a.rewrites[0]!.reason ?? "", /rule \(i\)/);
    assert.equal(bashBlock(a.request).is_error, false, "THE SIDE CHANNEL: a masked result said the command failed");
    assert.ok(!String(bashBlock(a.request).content).includes("exit status"), String(bashBlock(a.request).content));

    // Codex's exec_command: masked body, header blanked.
    await realHuman.recordCallCommand({ callId: "call_rf_1", command: held, sessionKey: session });
    await guard.recordExecRoot({ procKey: "bash-rf-2", ancestors: ["agent-rf-0"], argv: ["/bin/bash", "-c", held], session, callRoot: true });
    await guard.processLineage({ childKey: "bash-rf-2-reader", parentKey: "bash-rf-2" });
    await guard.taintProcessSecret({ procKey: "bash-rf-2-reader", path: env, level: "no-model", app: "keytool", session });
    const o = await rewriteResponsesRequest(execResult(held, `${FAILED}exit status 37\n`, "call_rf_1"), { arbiter: codex, sessionKey: session });
    const fo = execOut(o.request, "call_rf_1");
    assert.equal(o.rewrites[0]!.symbolized, true, o.rewrites[0]!.reason);
    assert.ok(fo.startsWith("Chunk ID: 7c1e\nWall time: 0 seconds\nProcess exited with code 0\nOutput:\n$MDU:"), fo);
    assert.ok(!/code 37|4\.2500|token count|status 37/.test(fo), `THE SIDE CHANNEL: a fact about the run beside the symbol: ${fo}`);

    // Controls: a clean tree's failing result keeps its flag and its header.
    const clean = "ls /nonexistent";
    await bind("toolu_rf_c", clean, "bash-rf-c", false);
    const c = await rewriteRequest(bashResult(clean, "ls: cannot access '/nonexistent'\n", "toolu_rf_c"), { arbiter: claude, sessionKey: session });
    assert.equal(c.rewrites[0]!.symbolized, false, c.rewrites[0]!.reason);
    assert.equal(bashBlock(c.request).is_error, true);
    await realHuman.recordCallCommand({ callId: "call_rf_c", command: clean, sessionKey: session });
    await guard.recordExecRoot({ procKey: "bash-rf-c2", ancestors: ["agent-rf-0"], argv: ["/bin/bash", "-c", clean], session, callRoot: true });
    const oc = await rewriteResponsesRequest(execResult(clean, `${FAILED}ls: cannot access '/nonexistent'\n`, "call_rf_c"), { arbiter: codex, sessionKey: session });
    assert.equal(oc.rewrites[0]!.symbolized, false, oc.rewrites[0]!.reason);
    assert.ok(execOut(oc.request, "call_rf_c").startsWith(FAILED));
  } finally {
    guard.close(); realHuman.close(); realA.close(); realO.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
