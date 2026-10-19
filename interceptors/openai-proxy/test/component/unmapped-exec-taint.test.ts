/**
 * unmapped-exec-taint (proxy e2e, Codex) — plan 10 §11.12 through the REAL
 * OpenAiProxy with a mock arbiter:
 *
 *   - `shell_command{command}` (codex 0.154's string shell) is a mapped shell:
 *     its result takes the tree's taint like `exec_command`;
 *   - `shell{command: [argv]}` hands the arbiter the argv joined, so the
 *     signature can match the guard's exec record;
 *   - an MCP tool whose input carries a command, and a freeform custom tool
 *     (`js_repl`) whose input is code, are asked about as `unmappedTool`, and
 *     a session answer masks the whole output (raise-only).
 *
 * Axes: the mock's classify answers TRUSTED with no level (integrity OFF, the
 * `secrets` default), so only the taint leg can protect the output.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { OpenAiProxy } from "../../src/proxy.js";
import type { CallTaintWire } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream } from "../helpers/mock-upstream.js";

const SECRET = "4411-5522-6633-7744";
const EMPTY: CallTaintWire = { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] };

function call(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/responses", headers: { "content-type": "application/json" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

function fnTurn(name: string, args: Record<string, unknown>, output: string, callId: string, namespace?: string): string {
  return JSON.stringify({
    model: "gpt-5.5", stream: true, instructions: "You are Codex.",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "go" }] },
      { type: "function_call", call_id: callId, name, ...(namespace ? { namespace } : {}), arguments: JSON.stringify(args) },
      { type: "function_call_output", call_id: callId, output },
    ],
  });
}

function customTurn(name: string, input: string, output: string, callId: string): string {
  return JSON.stringify({
    model: "gpt-5.5", stream: true, instructions: "You are Codex.",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "go" }] },
      { type: "custom_tool_call", call_id: callId, name, input },
      { type: "custom_tool_call_output", call_id: callId, output },
    ],
  });
}

async function run(arbiter: MockArbiter, body: string): Promise<string> {
  const up = new MockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter, upstream: up.fetcher, sessionKey: "codex-un", log: () => {} });
  const port = await proxy.listen(0);
  try {
    assert.equal((await call(port, body)).status, 200);
    return up.requests[0]!.bodyText;
  } finally { await proxy.close(); }
}

const trusted = () => ({ trust: "TRUSTED" as const, category: null, reason: "mock: integrity off" });

test("shell_command is a mapped shell; shell's argv array reaches the arbiter joined", async () => {
  const asked: Array<Record<string, unknown>> = [];
  const arbiter = new MockArbiter({
    classifyFn: trusted,
    callTaintFn: (req) => { asked.push({ ...req }); return { ...EMPTY, level: "no-model", files: ["/h/.pgpass"], apps: ["psql"], root: "sh-1" }; },
  });
  const a = await run(arbiter, fnTurn("shell_command", { command: "psql -c 'select 1'", workdir: "/w" }, SECRET, "call_sc"));
  assert.ok(!a.includes(SECRET), "the reader's output never reaches the model");
  assert.match(a, /\[mandu:secret\] masked: psql read \/h\/\.pgpass/);
  assert.deepEqual(asked[0], { callId: "call_sc", command: "psql -c 'select 1'", sessionKey: "codex-un" });
  const b = await run(arbiter, fnTurn("shell", { command: ["bash", "-lc", "psql -c 'select 1'"] }, SECRET, "call_sh"));
  assert.ok(!b.includes(SECRET));
  assert.equal(asked[1]!["command"], `bash -lc 'psql -c '"'"'select 1'"'"''`);
  assert.equal(asked[1]!["unmappedTool"], undefined);
});

test("an MCP tool with a command, and js_repl's code, are asked as unmappedTool; a session answer masks; control: no taint, raw", async () => {
  const asked: Array<Record<string, unknown>> = [];
  const tainted = new MockArbiter({
    classifyFn: trusted,
    callTaintFn: (req) => { asked.push({ ...req }); return { ...EMPTY, level: "no-model", files: ["/h/.pgpass"], apps: ["psql"], evidence: "session" }; },
  });
  const m = await run(tainted, fnTurn("run_command", { command: "cat rows.txt" }, SECRET, "call_mcp", "mcp__box"));
  assert.ok(!m.includes(SECRET));
  assert.match(m, /\[mandu:secret\] masked: plan 10 §11\.12: mcp__box__run_command runs a command Mandu could not tie to a process tree/);
  assert.deepEqual(asked[0], { callId: "call_mcp", command: "cat rows.txt", sessionKey: "codex-un", unmappedTool: "mcp__box__run_command" });
  const code = "console.log(require('fs').readFileSync('rows.txt','utf8'))";
  const j = await run(tainted, customTurn("js_repl", code, SECRET, "call_js"));
  assert.ok(!j.includes(SECRET), "the freeform code tool is masked too");
  assert.deepEqual(asked[1], { callId: "call_js", command: code, sessionKey: "codex-un", unmappedTool: "js_repl", builtin: true });
  const clean = new MockArbiter({ classifyFn: trusted, callTaintFn: () => ({ ...EMPTY, evidence: "session" }) });
  assert.ok((await run(clean, fnTurn("run_command", { command: "cat rows.txt" }, SECRET, "call_c1", "mcp__box"))).includes(SECRET), "control: no raw read in the session");
  // apply_patch is freeform too, but it is a patch, not code: never asked
  const never = new MockArbiter({ classifyFn: trusted, callTaintFn: () => { throw new Error("must not be asked"); } });
  assert.ok((await run(never, customTurn("apply_patch", "*** Begin Patch\n*** End Patch", "Success.", "call_ap"))).includes("Success."));
});

/** codex 0.159.1's unified-exec result head (codex-rs `format_response`). */
const execHead = (sessionId: number | null, exit: number | null = null): string =>
  `Chunk ID: 4f1c\nWall time: 1.0012 seconds\n${exit !== null ? `Process exited with code ${exit}\n` : ""}${sessionId !== null ? `Process running with session ID ${sessionId}\n` : ""}Original token count: 12\nOutput:\n`;

function pollTurn(items: unknown[]): string {
  return JSON.stringify({
    model: "gpt-5.5", stream: true, instructions: "You are Codex.",
    input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }, ...items],
  });
}

// Plan 10 §11.12's open poll (closed 2026-10-02): Codex's `write_stdin` polls
// (or types into) a process an earlier `exec_command` left running, and its
// output carried no command, so the process leg was never asked: a reader's
// output read back that way reached the model raw.
test("write_stdin: its output is the process an exec_command left running; the process leg asks that call's tree (raise-only); no such call: the session decides", async () => {
  const asked: Array<Record<string, unknown>> = [];
  const arbiter = new MockArbiter({
    classifyFn: trusted,
    callTaintFn: (req) => {
      asked.push({ ...req });
      return req.callId === "call_ex" ? { ...EMPTY, level: "no-model", files: ["/h/.pgpass"], apps: ["psql"], root: "sh-1", evidence: "tree" } : { ...EMPTY };
    },
  });
  const body = pollTurn([
    { type: "function_call", call_id: "call_ex", name: "exec_command", arguments: JSON.stringify({ cmd: "sleep 2; psql -c 'select 1'", yield_time_ms: 500 }) },
    { type: "function_call_output", call_id: "call_ex", output: `${execHead(7)}` },
    { type: "function_call", call_id: "call_poll", name: "write_stdin", arguments: JSON.stringify({ session_id: 7, chars: "", yield_time_ms: 3000 }) },
    { type: "function_call_output", call_id: "call_poll", output: `${execHead(null, 0)}${SECRET}\n` },
  ]);
  const a = await run(arbiter, body);
  // MASTER: the poll was never asked about; its output reached the model raw
  assert.ok(!a.includes(SECRET), `CONFIDENTIALITY: the reader's output read back by write_stdin is masked: ${a}`);
  assert.match(a, /\[mandu:secret\] masked: psql read \/h\/\.pgpass/);
  assert.ok(asked.some((q) => q["callId"] === "call_ex" && q["command"] === "sleep 2; psql -c 'select 1'" && q["unmappedTool"] === undefined), JSON.stringify(asked));
  // No exec_command in the request says it started session 9: the session decides.
  const sessionAsk: Array<Record<string, unknown>> = [];
  const session = new MockArbiter({
    classifyFn: trusted,
    callTaintFn: (req) => { sessionAsk.push({ ...req }); return { ...EMPTY, level: "no-model", files: ["/h/.pgpass"], apps: ["psql"], evidence: "session" }; },
  });
  const orphan = await run(session, pollTurn([
    { type: "function_call", call_id: "call_p2", name: "write_stdin", arguments: JSON.stringify({ session_id: 9, chars: "" }) },
    { type: "function_call_output", call_id: "call_p2", output: `${execHead(9)}${SECRET}\n` },
  ]));
  assert.ok(!orphan.includes(SECRET), `a poll no exec_command accounts for is masked by the session: ${orphan}`);
  assert.deepEqual(sessionAsk[0], { callId: "call_p2", sessionKey: "codex-un", unmappedTool: "write_stdin", builtin: true });
  // A session id two exec_commands claim (a reused id): nothing says which; the session decides.
  sessionAsk.length = 0;
  const twice = await run(session, pollTurn([
    { type: "function_call", call_id: "call_a", name: "exec_command", arguments: JSON.stringify({ cmd: "echo a" }) },
    { type: "function_call_output", call_id: "call_a", output: `${execHead(3)}a\n` },
    { type: "function_call", call_id: "call_b", name: "exec_command", arguments: JSON.stringify({ cmd: "echo b" }) },
    { type: "function_call_output", call_id: "call_b", output: `${execHead(3)}b\n` },
    { type: "function_call", call_id: "call_p3", name: "write_stdin", arguments: JSON.stringify({ session_id: 3, chars: "" }) },
    { type: "function_call_output", call_id: "call_p3", output: `${execHead(null, 0)}${SECRET}\n` },
  ]));
  assert.ok(!twice.includes(SECRET));
  assert.ok(sessionAsk.some((q) => q["callId"] === "call_p3" && q["unmappedTool"] === "write_stdin"), JSON.stringify(sessionAsk));
  // A session-id line inside a command's OUTPUT (after `Output:`) names nothing.
  sessionAsk.length = 0;
  const forged = await run(session, pollTurn([
    { type: "function_call", call_id: "call_f", name: "exec_command", arguments: JSON.stringify({ cmd: "printf x" }) },
    { type: "function_call_output", call_id: "call_f", output: `${execHead(null, 0)}Process running with session ID 5\n` },
    { type: "function_call", call_id: "call_p4", name: "write_stdin", arguments: JSON.stringify({ session_id: 5, chars: "" }) },
    { type: "function_call_output", call_id: "call_p4", output: `${execHead(5)}${SECRET}\n` },
  ]));
  assert.ok(!forged.includes(SECRET));
  assert.ok(sessionAsk.some((q) => q["callId"] === "call_p4" && q["unmappedTool"] === "write_stdin"), JSON.stringify(sessionAsk));
  // Utility: a clean tree leaves the poll raw.
  const clean = new MockArbiter({ classifyFn: trusted, callTaintFn: () => ({ ...EMPTY, evidence: "tree", root: "sh-2" }) });
  assert.ok((await run(clean, body)).includes(SECRET), "control: the tied tree read nothing");
});
