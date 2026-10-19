/**
 * codex-cell-hidden-paths — plan 10 §11.13's three closed paths over the REAL
 * components: the real ArbiterServer in `secrets`, the real OpenAiProxy, the
 * PRODUCTION adapter (`new ArbiterClientAdapter(new ArbiterClient(sock))`),
 * only the model upstream canned. The guard's records are written as the
 * guard writes them (`recordExecRoot`, `processLineage`, `taintProcessSecret`).
 *
 * The security-invariant oracle, one case per path: a listed reader's raw
 * output never reaches the model —
 *   (a) through a cell whose first `exec_command` literal ran a clean `ls`
 *       while a second exec the literal scanner cannot see ran the reader;
 *   (b) through Codex's `wait`, which returns a yielded cell's later output
 *       and carries no command (correlated to its cell, and uncorrelated);
 *   (c) through an MCP server a cell wrote the reader's output into, read
 *       back by a later qualifying cell and by a namespaced call.
 * Controls: an identified cell with a clean tree, and Mandu's own policy tool,
 * are forwarded raw in the same tainted session. Red with any one of the three
 * fixes removed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

// one value per case: a value masked once is a registered secret, and the
// value backstop would then mask a later case by value, not by its rule
const C_A = "psql-row-a1f0c3", C_B = "dbdump-row-b2e1d4", C_B2 = "dbdump-row-b3f2e5", C_C = "store-row-c4a3f6", C_C2 = "store-row-c5b4a7";
const ENVELOPE = "Script completed\nWall time 0.1 seconds\nOutput:\n";
const BATTERY = {
  type: "additional_tools", role: "developer",
  tools: [{ type: "namespace", name: "functions", tools: [
    { type: "custom", name: "exec", description: "Run JavaScript code to orchestrate/compose tool calls\n- Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." },
    { type: "function", name: "wait" },
  ] }],
};

function turn(...items: unknown[]): unknown {
  return { model: "gpt-6.1-sol", stream: true, instructions: "You are Codex.", input: [BATTERY, { type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }, ...items] };
}
const cell = (id: string, input: string) => ({ type: "custom_tool_call", call_id: id, name: "exec", input });
const cellOut = (id: string, text: string) => ({ type: "custom_tool_call_output", call_id: id, output: [{ type: "input_text", text: ENVELOPE }, { type: "input_text", text }] });

function outputOf(body: string, callId: string): string {
  const item = (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => String(i["type"]).endsWith("_output") && i["call_id"] === callId)!;
  const o = item["output"];
  return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
}

test("no reader output reaches the model through a hidden exec, a wait, or an MCP store (secrets axes, real arbiter, production adapter)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-cell-hidden-"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` mode axes, stated
  });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect(); // the guard reports on the human socket (plan 13 D9)
  const realHuman = new ArbiterClient(join(tmp, "human", "h.sock")); await realHuman.connect(); // the proxies' second client (server-main)
  const real: RealArbiterClient = new ArbiterClient(socketPath); await real.connect();
  const session = `codex-cell-hidden-${process.pid}`;
  let upstream = new MockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter: new ArbiterClientAdapter(real, realHuman), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const send = async (body: unknown): Promise<string> => {
    upstream = new MockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    assert.equal(res.status, 200, await res.text());
    return upstream.requests[0]!.bodyText;
  };
  const pgpass = join(tmp, ".pgpass");
  try {
    // what the guard saw: a clean `ls` tree; a listed reader that read a secret raw
    // each the agent's own shell for one call (callRoot: the call-root recorder, plan 13 D7)
    await guard.recordExecRoot({ procKey: "g-ls-1", argv: ["/bin/bash", "-lc", "ls"], session, callRoot: true });
    await guard.recordExecRoot({ procKey: "g-psql-1", argv: ["/bin/bash", "-lc", "psql -c 'select key from creds'"], session, callRoot: true });
    await guard.taintProcessSecret({ procKey: "g-psql-1", path: pgpass, level: "no-model", app: "psql", session });
    // a yielded dbdump: its tree read the secret after the cell yielded
    await guard.recordExecRoot({ procKey: "g-sh-db", argv: ["/bin/bash", "-lc", "dbdump cards"], session, callRoot: true });
    await guard.processLineage({ childKey: "g-dbdump", parentKey: "g-sh-db", session });
    await guard.taintProcessSecret({ procKey: "g-dbdump", path: pgpass, level: "no-model", app: "dbdump", session });

    const leaks: string[] = [];
    const check = (label: string, out: string, canary: string): void => { if (out.includes(canary)) leaks.push(label); };

    // (a) the first literal ran `ls` (clean tree); a second exec, unseen, ran the reader
    const hidden = 'const r = await tools.exec_command({"cmd":"ls"});\nconst p = await tools["exec_command"]({"cmd":"psql -c \'select key from creds\'"});\ntext(r.output + p.output);\n';
    check("(a) hidden exec", outputOf(await send(turn(cell("c_a", hidden), cellOut("c_a", `notes.md\n${C_A}`))), "c_a"), C_A);
    // control: the identified `ls` cell, same session, its clean tree decides
    // (its own run of `ls`: the first cell's shell is bound to that cell)
    // (the proxy recorded the cell's literal when it relayed the cell: plan 13
    // D9 follow-up, the call binds by that record, never by the echoed cell)
    await realHuman.recordCallCommand({ callId: "c_ok", command: "ls", sessionKey: session });
    await guard.recordExecRoot({ procKey: "g-ls-2", argv: ["/bin/bash", "-lc", "ls"], session, callRoot: true });
    const exact = 'const r = await tools.exec_command({"cmd":"ls"});\ntext(r.output);\n';
    assert.equal(outputOf(await send(turn(cell("c_ok", exact), cellOut("c_ok", "notes.md"))), "c_ok"), `${ENVELOPE}notes.md`, "control: an identified clean cell is raw");

    // (b) a yielded cell's later output through wait, correlated and not
    const yielded = 'const r = await tools.exec_command({"cmd":"dbdump cards"});\ntext(r.output);\n';
    const b = await send(turn(
      cell("c_b", yielded),
      { type: "custom_tool_call_output", call_id: "c_b", output: "Script running with cell ID 4\nWall time 0.2 seconds\nOutput:\n" },
      { type: "function_call", call_id: "w_b", name: "wait", arguments: JSON.stringify({ cell_id: "4", yield_time_ms: 3000 }) },
      { type: "function_call_output", call_id: "w_b", output: [{ type: "input_text", text: "Script completed\nWall time 1.3 seconds\nOutput:\n" }, { type: "input_text", text: C_B }] },
      { type: "function_call", call_id: "w_lost", name: "wait", arguments: JSON.stringify({ cell_id: "77" }) },
      { type: "function_call_output", call_id: "w_lost", output: [{ type: "input_text", text: "Script completed\nWall time 1.0 seconds\nOutput:\n" }, { type: "input_text", text: C_B2 }] },
    ));
    check("(b) wait, correlated", outputOf(b, "w_b"), C_B);
    check("(b) wait, uncorrelated", outputOf(b, "w_lost"), C_B2);

    // (c) cell A wrote the reader's output into an MCP store (its own output
    // says only "ok"); the read-back, by a cell and by a namespaced call
    const c = await send(turn(
      cell("c_put", 'const r = await tools.exec_command({"cmd":"psql -c \'select key from creds\'"});\nawait tools.mcp__store__put({value: "x"});\ntext("ok");\n'),
      cellOut("c_put", "ok"),
      cell("c_get", 'text(await tools.mcp__store__get({key: "rows"}));'),
      cellOut("c_get", C_C),
      { type: "function_call", call_id: "f_get", namespace: "mcp__store", name: "get", arguments: JSON.stringify({ key: "rows" }) },
      { type: "function_call_output", call_id: "f_get", output: [{ type: "input_text", text: "Wall time: 0.1 seconds\nOutput:" }, { type: "input_text", text: C_C2 }] },
    ));
    check("(c) store read-back, cell", outputOf(c, "c_get"), C_C);
    check("(c) store read-back, namespaced", outputOf(c, "f_get"), C_C2);
    // control: Mandu's own policy tool in the same tainted session is raw
    const policy = JSON.stringify({ tool: "mandu_policy_read", law: { pendingAskCount: 0 } });
    assert.equal(outputOf(await send(turn(cell("c_pol", "text(await tools.mcp__mandu_policy__mandu_policy_read({}));"), cellOut("c_pol", policy))), "c_pol"), ENVELOPE + policy);

    assert.deepEqual(leaks, [], "CONFIDENTIALITY VIOLATION: a reader's raw output reached the model through these");
  } finally {
    await proxy.close();
    guard.close(); realHuman.close(); real.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
