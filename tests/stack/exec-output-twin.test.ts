/**
 * exec-output-twin — plan 10 §11.8 over the REAL components: a shell command
 * that prints a secret file the guard served as its structured twin reaches
 * the model with the keys visible and each value a symbol, for Claude Code's
 * Bash (anthropic-proxy) and Codex's exec_command (openai-proxy), through the
 * production adapters (`new XAdapter(new ArbiterClient(sock))`).
 *
 * Before (os-test-matrix.md §10.14.1 item 7): the command NAMES `.env`,
 * so the path-derived precaution masked the whole result and Codex answered
 * "a protected opaque result". The release rests on the arbiter's record
 * (a guard-recorded tree, no raw open) plus the text being a piece of the
 * twin; the negatives pin both halves: raw bytes, no record, a reader's
 * taint, and output from two files all stay one symbol.
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

const STRIPE = "sk_live_twin_e2e_0123456789";
const DB_PW = "pg_twin_e2e_pw_987654";
const RAW = `PORT=3000\nSTRIPE_KEY=${STRIPE}\nDATABASE_URL=postgres://app:${DB_PW}@db:5432/prod\nLOG_LEVEL=info\n`;
const ENVELOPE = "Chunk ID: 7c1e\nWall time: 0.0100 seconds\nProcess exited with code 0\nOriginal token count: 30\nOutput:\n";

function bashResult(command: string, content: string, id: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "which keys are in the env file?" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  };
}
function execResult(cmd: string, output: string, id: string): ResponsesRequest {
  return {
    model: "gpt-5.5",
    instructions: "You are Codex.",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "which keys are in the env file?" }] },
      { type: "function_call", call_id: id, name: "exec_command", arguments: JSON.stringify({ cmd }) },
      { type: "function_call_output", call_id: id, output },
    ],
  } as ResponsesRequest;
}
const bashForwarded = (r: MessagesRequest): string => ((r.messages[2]!.content as any[])[0].content as string);

/** One symbol, and at most the path-derived note the proxy writes from the
 *  command (confidentiality.md §7.1, 2026-10-05): never an output byte. */
const ONE_SYMBOL = /^\$MDU:nomodel_Bash\[[0-9a-f]{4,8}\](?:\n\n\[mandu:secret\] masked: (?:the command names|this output contains the value of a registered secret)[^\n]*)?$/;
const execForwarded = (r: ResponsesRequest, id: string): string =>
  String((r.input as any[]).find((i) => i.type === "function_call_output" && i.call_id === id).output);

test("`cat .env` served as the structured twin: keys visible, values as symbols, for Claude Bash and Codex exec_command; raw bytes, no record, a taint or two files stay one symbol (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-exec-twin-e2e-"));
  const ws = join(tmp, "ws"); mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, RAW);
  const aws = join(tmp, "credentials");
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` mode axes, stated
  });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect(); // the guard reports on the human socket (plan 13 D9)
  const realHuman = new ArbiterClient(join(tmp, "human", "h.sock")); await realHuman.connect(); // the proxies' second client (server-main)
  const realA: RealArbiterClient = new ArbiterClient(socketPath); await realA.connect();
  const realO: OpenAiProxyRealArbiterClient = new ArbiterClient(socketPath); await realO.connect();
  const claude = new ArbiterClientAdapter(realA, realHuman);
  const codex = new OpenAiProxyArbiterAdapter(realO, realHuman);
  const session = "s-exec-twin";
  const command = `cat ${env}`;
  try {
    const reg = await guard.registerSecret({ path: env, sessionKey: session });
    assert.ok(typeof reg.twin === "string", JSON.stringify(reg));
    const twin = reg.twin as string;
    assert.ok(!twin.includes(STRIPE) && !twin.includes(DB_PW), "the twin holds no secret byte");

    // The guard at `cat`'s open: no reader list, so `cat` gets the twin (no taint).
    const open = await guard.decideSecretOpen({ path: env, exe: "/usr/bin/cat", isAgent: false, exeSystem: true, openerEnv: [], procKey: "cat-tw-1", session });
    assert.equal(open.verdict, "twin");
    await guard.recordCallRoot({ callId: "toolu_tw_1", procKey: "cat-tw-1", session });
    await guard.recordCallRoot({ callId: "call_tw_1", procKey: "cat-tw-1", session });

    // Claude Code's Bash
    const a = await rewriteRequest(bashResult(command, twin, "toolu_tw_1"), { arbiter: claude, sessionKey: session });
    const fa = bashForwarded(a.request);
    assert.equal(a.rewrites[0]!.symbolized, false, a.rewrites[0]!.reason);
    assert.match(fa, /^PORT=3000\nSTRIPE_KEY='\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.STRIPE_KEY'\n/, fa);
    assert.match(fa, /DATABASE_URL='postgres:\/\/app:\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.DATABASE_URL\.password@db:5432\/prod'/);
    assert.match(fa, /\[mandu:secret\] twin: this is .*\.env as you see it/);
    assert.ok(!fa.includes(STRIPE) && !fa.includes(DB_PW));

    // Codex's exec_command, envelope first
    const o = await rewriteResponsesRequest(execResult(command, `${ENVELOPE}${twin}`, "call_tw_1"), { arbiter: codex, sessionKey: session });
    const fo = execForwarded(o.request, "call_tw_1");
    assert.equal(o.rewrites[0]!.symbolized, false, o.rewrites[0]!.reason);
    assert.ok(fo.startsWith(`${ENVELOPE}PORT=3000\nSTRIPE_KEY='$MDU:nomodel_Read[`), fo);
    assert.match(fo, /\.STRIPE_KEY'/);
    assert.ok(!fo.includes(STRIPE) && !fo.includes(DB_PW));

    // Codex's script cell that printed the WHOLE exec result object (the live
    // GPT-5 wire, VM run 2026-09-28): the twin arrives JSON-escaped inside
    // `output`, and is released the same way.
    await guard.recordCallRoot({ callId: "call_tw_cell", procKey: "cat-tw-1", session });
    const cellJson = JSON.stringify({ chunk_id: "3ec25a", wall_time_seconds: 0.01, exit_code: 0, original_token_count: 52, output: twin });
    const cellReq = {
      model: "gpt-5.5",
      instructions: "You are Codex.",
      input: [
        { type: "message", role: "user", content: [{ type: "input_text", text: "which keys are in the env file?" }] },
        { type: "custom_tool_call", id: "ctc_tw", status: "completed", call_id: "call_tw_cell", name: "exec", input: `const r = await tools.exec_command(${JSON.stringify({ cmd: command })});\ntext(JSON.stringify(r));\n` },
        { type: "custom_tool_call_output", id: "ctco_tw", call_id: "call_tw_cell", output: [{ type: "input_text", text: "Script completed\nWall time 0.2 seconds\nOutput:\n" }, { type: "input_text", text: cellJson }] },
      ],
    } as unknown as ResponsesRequest;
    const c = await rewriteResponsesRequest(cellReq, { arbiter: codex, sessionKey: session });
    const fc = ((c.request.input as any[]).find((i) => i.type === "custom_tool_call_output").output as Array<{ text: string }>).map((p) => p.text).join("");
    assert.equal(c.rewrites[0]!.symbolized, false, c.rewrites[0]!.reason);
    assert.ok(fc.includes('"output":"PORT=3000\\nSTRIPE_KEY=\'$MDU:nomodel_Read['), fc);
    assert.match(fc, /\[mandu:secret\] twin: this is .*\.env as you see it/);
    assert.ok(!fc.includes(STRIPE) && !fc.includes(DB_PW));
    // the same object with an extra field is not unwrapped: one symbol
    await guard.recordCallRoot({ callId: "call_tw_cell_x", procKey: "cat-tw-1", session });
    const xReq = JSON.parse(JSON.stringify(cellReq).split("call_tw_cell").join("call_tw_cell_x"));
    xReq.input[2].output[1].text = JSON.stringify({ chunk_id: "3ec25a", note: "x", output: twin });
    const x = await rewriteResponsesRequest(xReq, { arbiter: codex, sessionKey: session });
    assert.equal(x.rewrites[0]!.symbolized, true);

    // NEGATIVE 1: the raw file (no twin layer served it) under the same record: one symbol
    await guard.recordCallRoot({ callId: "toolu_tw_raw", procKey: "cat-tw-1", session });
    const r = await rewriteRequest(bashResult(command, RAW, "toolu_tw_raw"), { arbiter: claude, sessionKey: session });
    assert.equal(r.rewrites[0]!.symbolized, true);
    assert.match(bashForwarded(r.request), ONE_SYMBOL);

    // NEGATIVE 2: the twin text but no guard record of the call: one symbol
    const n = await rewriteResponsesRequest(execResult("cat ./.env", twin, "call_tw_norecord"), { arbiter: codex, sessionKey: session });
    assert.equal(n.rewrites[0]!.symbolized, true);
    assert.doesNotMatch(execForwarded(n.request, "call_tw_norecord"), /STRIPE_KEY/);

    // NEGATIVE 3: a listed reader read it raw in the tree (rule (i)): one symbol, even for twin-shaped text
    // (the call's shell, the agent's own child, as the guard reports it: the
    // call-root recorder of plan 13 D7 binds the call to it by command text)
    const tainted = `sh -c 'reader; ${command}'`;
    // the proxy's record of the command it relayed (plan 13 D9 follow-up: the call binds by it)
    await claude.recordCallCommand!({ callId: "toolu_tw_taint", command: tainted, sessionKey: session });
    await guard.recordExecRoot({ procKey: "cat-tw-3", ancestors: ["agent-tw-0"], argv: ["/bin/bash", "-c", tainted], session, callRoot: true });
    await guard.processLineage({ childKey: "reader-tw-2", parentKey: "cat-tw-3" });
    await guard.taintProcessSecret({ procKey: "reader-tw-2", path: env, level: "no-model", app: "reader", session });
    const t = await rewriteRequest(bashResult(tainted, twin, "toolu_tw_taint"), { arbiter: claude, sessionKey: session });
    assert.equal(t.rewrites[0]!.symbolized, true);
    assert.match(t.rewrites[0]!.reason ?? "", /rule \(i\)/);

    // NEGATIVE 4: two files in one output: one symbol (the unknown shape is masked whole)
    writeFileSync(aws, "[default]\naws_access_key_id = AKIAEXAMPLE0000\naws_secret_access_key = abcdEFGH1234ijklMNOP5678qrstUVWX9012yzAB\n");
    const reg2 = await guard.registerSecret({ path: aws, sessionKey: session });
    assert.ok(typeof reg2.twin === "string", JSON.stringify(reg2));
    // (its own clean shell, bound by the recorder: the session holds the
    // reader's raw read above, and a call not bound would be masked for that)
    await claude.recordCallCommand!({ callId: "toolu_tw_two", command: `cat ${env} ${aws}`, sessionKey: session });
    await guard.recordExecRoot({ procKey: "cat-tw-4", ancestors: ["agent-tw-0"], argv: ["/bin/bash", "-c", `cat ${env} ${aws}`], session, callRoot: true });
    const both = `${twin}${reg2.twin as string}`;
    const w = await rewriteRequest(bashResult(`cat ${env} ${aws}`, both, "toolu_tw_two"), { arbiter: claude, sessionKey: session });
    assert.equal(w.rewrites[0]!.symbolized, true);
    assert.match(bashForwarded(w.request), ONE_SYMBOL);
  } finally {
    guard.close(); realHuman.close(); realA.close(); realO.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
