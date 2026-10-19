/**
 * unmapped-exec-taint — plan 10 §11.12 over the REAL components: a tool no
 * gate surface knows as a shell, whose input carries a command, has its
 * result checked against the guard's process-taint records, for Claude Code
 * through the anthropic-proxy and Codex through the openai-proxy, via the
 * production adapters (`new XAdapter(new ArbiterClient(sock))`) and the real
 * `callTaint` op with `unmappedTool`.
 *
 * Before: only a mapped shell's result (Bash, bash, exec, exec_command) was
 * checked, so an MCP `run_command` whose tree held a secret's raw bytes (a
 * listed reader) returned that output to the model unmasked in `secrets`
 * mode. The guard's records are written here as the guard writes them
 * (`recordExecRoot`, `processLineage`, `taintProcessSecret`).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
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

const ROWS = "card | 4411-5522-6633-7744";

function toolResult(id: string, name: string, input: Record<string, unknown>, content: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "list the cards" },
      { role: "assistant", content: [{ type: "tool_use", id, name, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  };
}
const forwarded = (r: MessagesRequest): string => JSON.stringify((r.messages[2]!.content as any[])[0].content);

function codexCall(id: string, name: string, args: Record<string, unknown>, output: string): ResponsesRequest {
  return {
    model: "gpt-5.5",
    instructions: "You are Codex.",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "list the cards" }] },
      { type: "function_call", call_id: id, name, arguments: JSON.stringify(args) },
      { type: "function_call_output", call_id: id, output },
    ],
  } as ResponsesRequest;
}
const codexForwarded = (r: ResponsesRequest, id: string): string =>
  String((r.input as any[]).find((i) => i.type === "function_call_output" && i.call_id === id).output);

test("an unmapped command tool whose tree or session read a secret raw is masked (Claude Code and Codex, production adapters); controls forward raw (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-unmapped-exec-e2e-"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` mode axes, stated
  });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect(); // what the guard writes, on the human socket (plan 13 D9)
  const realHuman = new ArbiterClient(join(tmp, "human", "h.sock")); await realHuman.connect(); // the proxies' second client (server-main)
  const realA: RealArbiterClient = new ArbiterClient(socketPath); await realA.connect();
  const realO: OpenAiProxyRealArbiterClient = new ArbiterClient(socketPath); await realO.connect();
  const claude = new ArbiterClientAdapter(realA, realHuman);
  const codex = new OpenAiProxyArbiterAdapter(realO, realHuman);
  const s1 = `unmapped-exec-a-${process.pid}`;
  const s2 = `unmapped-exec-b-${process.pid}`;
  const cx = `unmapped-exec-cx-${process.pid}`;
  const pgpass = join(tmp, ".pgpass");
  try {
    // the launcher registered both stdio servers from the agent's config (an
    // MCP server Mandu has no mapping for is masked whole before any of the
    // rules below, plan 10 §11.18; case 7)
    for (const s of [s1, s2, cx]) await guard.registerMcpServers(s, [{ name: "box", command: "box-mcp", args: [] }, { name: "py", command: "py-mcp", args: [] }]);
    // 1. the guard saw the MCP tool's command run in a tree whose child read
    //    a secret raw (the server's shell, not the agent's: only a guess ties
    //    it to the call, so the session's raw reads decide, plan 13 D7)
    await guard.recordExecRoot({ procKey: "t-sh-1", argv: ["/bin/sh", "-c", "dbdump cards"], session: s1 });
    await guard.processLineage({ childKey: "t-dbdump-2", parentKey: "t-sh-1", session: s1 });
    await guard.taintProcessSecret({ procKey: "t-dbdump-2", path: pgpass, level: "no-model", app: "dbdump", session: s1 });
    const a = await rewriteRequest(toolResult("tu_t1", "mcp__box__run_command", { command: "dbdump cards" }, ROWS), { arbiter: claude, sessionKey: s1 });
    assert.equal(a.rewrites[0]!.symbolized, true, a.rewrites[0]!.reason);
    assert.ok(!forwarded(a.request).includes("4411-5522"), "CONFIDENTIALITY VIOLATION: a reader's output reached the model through an unmapped command tool");
    assert.match(forwarded(a.request), /\[mandu:secret\] masked: plan 10 §11\.12: mcp__box__run_command runs a command Mandu could not tie to a process tree, and programs in this session read \.pgpass raw/);

    // 2. a tool that runs its command in-process (no tree): the session's raw reads decide
    const b = await rewriteRequest(toolResult("tu_t2", "mcp__py__exec", { code: "print(rows())" }, ROWS), { arbiter: claude, sessionKey: s1 });
    assert.equal(b.rewrites[0]!.symbolized, true, b.rewrites[0]!.reason);
    assert.match(b.rewrites[0]!.reason ?? "", /§11\.12/);

    // 3. control: a session where nothing read a secret raw forwards the same
    //    call raw (other rows: the masked ones above are now registered values)
    const c = await rewriteRequest(toolResult("tu_t3", "mcp__py__exec", { code: "print(rows())" }, "card | 9900-8800-7700-6600"), { arbiter: claude, sessionKey: s2 });
    assert.equal(c.rewrites[0]!.symbolized, false, c.rewrites[0]!.reason);
    assert.ok(forwarded(c.request).includes("9900-8800"));

    // 4. control: a MAPPED tool with a command-like key is not the backstop's
    //    (Workflow is in Claude Code's spec): the arbiter answers empty
    const d = await rewriteRequest(toolResult("tu_t4", "Workflow", { script: "export const meta = {name: 'x'}" }, "done"), { arbiter: claude, sessionKey: s1 });
    assert.equal(d.rewrites[0]!.secretTaint, undefined);

    // 5. Codex: an MCP tool, no tree, in a session with a raw read ⇒ masked
    await guard.taintProcessSecret({ procKey: "cx-psql-1", path: pgpass, level: "no-model", app: "psql", session: cx });
    const e = await rewriteResponsesRequest(codexCall("call_u1", "mcp__box__run_command", { command: "cat rows.txt" }, "card | 3141-5926-5358-9793"), { arbiter: codex, sessionKey: cx });
    assert.equal(e.rewrites[0]!.symbolized, true, e.rewrites[0]!.reason);
    assert.match(e.rewrites[0]!.reason ?? "", /§11\.12/, "masked by the session's taint, not by a value scan");
    assert.ok(!codexForwarded(e.request, "call_u1").includes("3141-5926"));

    // 7. §11.18: a server no config registered: masked whole, even in the
    //    session that read nothing (the note says how to let it through)
    const g = await rewriteRequest(toolResult("tu_t7", "mcp__other__exec", { code: "print(rows())" }, "card | 1212-3434-5656-7878"), { arbiter: claude, sessionKey: s2 });
    assert.equal(g.rewrites[0]!.symbolized, true, g.rewrites[0]!.reason);
    assert.ok(!forwarded(g.request).includes("1212-3434"));
    assert.match(forwarded(g.request), /no mapping for the tool mcp__other__exec.*mapped_tools/);

    // 6. Codex's string shell `shell_command` is a mapped shell: the tree decides
    // the proxy's record of the command it relayed (plan 13 D9 follow-up: the call binds by it)
    await codex.recordCallCommand({ callId: "call_s1", command: "dbdump cards", sessionKey: cx });
    await guard.recordExecRoot({ procKey: "cx-sh-2", argv: ["/bin/bash", "-lc", "dbdump cards"], session: cx, callRoot: true }); // Codex's own shell for the call
    await guard.processLineage({ childKey: "cx-dbdump-3", parentKey: "cx-sh-2", session: cx });
    await guard.taintProcessSecret({ procKey: "cx-dbdump-3", path: pgpass, level: "no-model", app: "dbdump", session: cx });
    const f = await rewriteResponsesRequest(codexCall("call_s1", "shell_command", { command: "dbdump cards", workdir: tmp }, "card | 2718-2818-2845-9045"), { arbiter: codex, sessionKey: cx });
    assert.equal(f.rewrites[0]!.symbolized, true, f.rewrites[0]!.reason);
    assert.match(codexForwarded(f.request, "call_s1"), /\[mandu:secret\] masked: dbdump read /);
  } finally {
    guard.close(); realHuman.close(); realA.close(); realO.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

// Plan 10 §11.12's background polls (closed 2026-10-02). A poll's output is
// a process an earlier call left running, and the poll carries no command:
// before, Claude Code's `TaskOutput` and Codex's `write_stdin` were never
// asked about, so a reader's output read back that way reached the model raw.
// Now TaskOutput is a mapped shell no shell binds (the session's raw reads
// decide, as BashOutput), and write_stdin is tied to the exec_command whose
// result head says it started that session (that call's tree decides).
test("background polls over the real arbiter: Claude Code's BashOutput and TaskOutput mask at the session's level; Codex's write_stdin takes the tree of the exec_command it polls; controls raw (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-poll-e2e-"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect();
  const realHuman = new ArbiterClient(join(tmp, "human", "h.sock")); await realHuman.connect();
  const realA: RealArbiterClient = new ArbiterClient(socketPath); await realA.connect();
  const realO: OpenAiProxyRealArbiterClient = new ArbiterClient(socketPath); await realO.connect();
  const claude = new ArbiterClientAdapter(realA, realHuman);
  const codex = new OpenAiProxyArbiterAdapter(realO, realHuman);
  const cc = `poll-cc-${process.pid}`;
  const cx = `poll-cx-${process.pid}`;
  const clean = `poll-clean-${process.pid}`;
  const secret = join(tmp, "x.txt");
  try {
    // Claude Code: a background Bash's reader read the file raw.
    await guard.recordExecRoot({ procKey: "cc-sh-1", ancestors: ["cc-agent-0"], argv: ["/bin/bash", "-c", "eval 'sleep 1; cat ./x.txt | od -An -tx1'"], session: cc, callRoot: true });
    await guard.recordExecRoot({ procKey: "cc-cat-2", ancestors: ["cc-sh-1", "cc-agent-0"], argv: ["cat", "./x.txt"], session: cc });
    await guard.taintProcessSecret({ procKey: "cc-cat-2", path: secret, level: "no-model", app: "cat", session: cc });
    const HEXROWS = " 74 6f 6b 65 6e 3d 50 4f 4c 4c";
    for (const [id, name, input] of [
      ["tu_bo", "BashOutput", { bash_id: "b7" }],
      ["tu_to", "TaskOutput", { task_id: "b7", block: true, timeout: 30000 }],
    ] as const) {
      const r = await rewriteRequest(toolResult(id, name, input, HEXROWS), { arbiter: claude, sessionKey: cc });
      // MASTER (TaskOutput): not asked, forwarded raw
      assert.ok(!forwarded(r.request).includes("74 6f 6b"), `CONFIDENTIALITY VIOLATION: ${name}'s poll of a reader's output reached the model raw: ${forwarded(r.request)}`);
      assert.match(forwarded(r.request), new RegExp(`plan 13 D7: Mandu could not tie this ${name} call`));
    }
    // control: a session with no raw read forwards a poll raw
    const ok = await rewriteRequest(toolResult("tu_to2", "TaskOutput", { task_id: "b8" }, "build ok"), { arbiter: claude, sessionKey: clean });
    assert.ok(forwarded(ok.request).includes("build ok"), forwarded(ok.request));

    // Codex: exec_command started `sleep 1; dbdump` and yielded session 4; its
    // tree read the file raw. A clean exec_command yielded session 5.
    // Every head line differs between calls: a result masked whole registers
    // each of its lines of 24 characters or more as a value (its head's too),
    // so a later result repeating one verbatim would be masked by the value
    // scan whatever its tree.
    const head = (sid: number | null, exit: number | null, wall: string): string =>
      `Chunk ID: 9a\nWall time: ${wall} seconds\n${exit !== null ? `Process exited with code ${exit}\n` : ""}${sid !== null ? `Process running with session ID ${sid}\n` : ""}Original token count: 4\nOutput:\n`;
    await codex.recordCallCommand({ callId: "call_x", command: "sleep 1; dbdump cards", sessionKey: cx });
    await codex.recordCallCommand({ callId: "call_c", command: "sleep 1; echo built", sessionKey: cx });
    await guard.recordExecRoot({ procKey: "cx-sh-1", ancestors: ["cx-agent-0"], argv: ["/bin/bash", "-lc", "sleep 1; dbdump cards"], session: cx, callRoot: true });
    await guard.recordExecRoot({ procKey: "cx-sh-2", ancestors: ["cx-agent-0"], argv: ["/bin/bash", "-lc", "sleep 1; echo built"], session: cx, callRoot: true });
    const turn = (polls: Array<[string, number, string]>): ResponsesRequest => ({
      model: "gpt-5.5", instructions: "You are Codex.",
      input: [
        { type: "message", role: "user", content: [{ type: "input_text", text: "dump the cards" }] },
        { type: "function_call", call_id: "call_x", name: "exec_command", arguments: JSON.stringify({ cmd: "sleep 1; dbdump cards", yield_time_ms: 300 }) },
        { type: "function_call_output", call_id: "call_x", output: head(4, null, "0.5004") },
        { type: "function_call", call_id: "call_c", name: "exec_command", arguments: JSON.stringify({ cmd: "sleep 1; echo built", yield_time_ms: 300 }) },
        { type: "function_call_output", call_id: "call_c", output: head(5, null, "0.5005") },
        ...polls.flatMap(([id, sid, out]) => [
          { type: "function_call", call_id: id, name: "write_stdin", arguments: JSON.stringify({ session_id: sid, chars: "" }) },
          { type: "function_call_output", call_id: id, output: `${head(null, sid, `1.20${sid}`)}${out}` },
        ]),
      ],
    } as ResponsesRequest);
    // the first turn: both exec results asked (each binds to its own shell);
    // only then does the reader read
    await rewriteResponsesRequest(turn([]), { arbiter: codex, sessionKey: cx });
    await guard.recordExecRoot({ procKey: "cx-dbdump-3", ancestors: ["cx-sh-1", "cx-agent-0"], argv: ["dbdump", "cards"], session: cx });
    await guard.taintProcessSecret({ procKey: "cx-dbdump-3", path: secret, level: "no-model", app: "dbdump", session: cx });
    const polled = await rewriteResponsesRequest(turn([["call_p4", 4, "card | 1618-0339-8874-9894\n"], ["call_p5", 5, "built\n"]]), { arbiter: codex, sessionKey: cx });
    // MASTER: write_stdin was never asked; the reader's rows reached the model raw
    assert.ok(!codexForwarded(polled.request, "call_p4").includes("1618-0339"), `CONFIDENTIALITY VIOLATION: write_stdin read a reader's output back raw: ${codexForwarded(polled.request, "call_p4")}`);
    assert.match(codexForwarded(polled.request, "call_p4"), /\[mandu:secret\] masked: dbdump read /);
    assert.ok(codexForwarded(polled.request, "call_p5").includes("built"), `utility: the clean session's poll stays raw: ${codexForwarded(polled.request, "call_p5")}`);
  } finally {
    guard.close(); realHuman.close(); realA.close(); realO.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
