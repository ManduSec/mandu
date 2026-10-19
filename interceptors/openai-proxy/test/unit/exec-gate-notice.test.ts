/**
 * exec-gate-notice.test.ts — the exec gate's own block notice reaches Codex's
 * model in clear, under the plan 13 §9 R4-blanked runtime header, and nothing
 * else rides with it (confidentiality plan 10 §11.8, "The exec gate's own
 * notice"; the anthropic-proxy twin is its test/unit/exec-gate-notice.test.ts).
 * The mock classify answers `no-model` for every output, as the real path
 * scan does on a sentinel that says "secret".
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { gateNoticeOutput, rewriteRequest } from "../../src/rewrite-request.js";
import {
  blockNoticeText,
  blockSentinelCommand,
  ExecGateNotices,
  EXEC_GATE_NOTICES_MAX,
  gateFunctionCallArguments,
} from "../../src/exec-gate.js";
import type { ResponsesRequest, ToolOutputItem } from "../../src/responses-types.js";
import type { ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const REASON =
  "HIGH SESSION (any-model): this session has read secret content into context, so anything it emits may be derived from it. Egress to an unspecified destination is not a bound destination of the data it read → human approval required (§4).";
const NOTICE = blockNoticeText(REASON);
const HEADER = "Chunk ID: 4f1c2a\nWall time: 0.0123 seconds\nProcess exited with code 77\nOriginal token count: 57\nOutput:\n";
const BLANKED = "Chunk ID: 4f1c2a\nWall time: 0 seconds\nProcess exited with code 0\nOutput:\n";
/** A test-only stand-in for a program's output (not a real credential). */
const PROGRAM_BYTES = "FIXTURE-PROGRAM-OUTPUT-7f3a";
const SYM_RE = /\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;

const secretEverything = (): ClassifyResult => ({
  trust: "TRUSTED",
  category: null,
  reason: "integrity axis OFF — trust classification disabled",
  confidentiality: "no-model",
});

function request(output: unknown, opts: { id?: string; name?: string } = {}): ResponsesRequest {
  const id = opts.id ?? "call_gate";
  return {
    model: "gpt-test",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "send it" }] },
      { type: "function_call", call_id: id, name: opts.name ?? "exec_command", arguments: JSON.stringify({ cmd: blockSentinelCommand(REASON) }) },
      { type: "function_call_output", call_id: id, output },
    ],
  } as unknown as ResponsesRequest;
}

function notices(id = "call_gate"): ExecGateNotices {
  const n = new ExecGateNotices();
  n.remember(id, NOTICE);
  return n;
}

function forwarded(out: Awaited<ReturnType<typeof rewriteRequest>>): string {
  const fco = (out.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!;
  return typeof fco.output === "string" ? fco.output : (fco.output as Array<{ text: string }>).map((p) => p.text).join("");
}

test("a blocked outcome carries the notice its sentinel prints", async () => {
  const arbiter = new MockArbiter();
  const r = await gateFunctionCallArguments(JSON.stringify({ cmd: "$MDU:web_fetch[a1b2].text" }), { arbiter });
  assert.equal(r.outcome!.decision, "block");
  assert.equal(r.outcome!.notice, blockNoticeText(r.outcome!.reason));
  assert.equal(r.outcome!.sentinel, blockSentinelCommand(r.outcome!.reason));
  assert.ok(!blockNoticeText("it's 'quoted'").includes("'"));
});

test("ExecGateNotices: by call id, empty id or notice ignored, bounded", () => {
  const n = new ExecGateNotices();
  n.remember(undefined, "x");
  n.remember("c", undefined);
  assert.equal(n.noticeFor("c"), undefined);
  n.remember("c", "notice");
  assert.equal(n.noticeFor("c"), "notice");
  for (let i = 0; i < EXEC_GATE_NOTICES_MAX; i++) n.remember(`c${i}`, `n${i}`);
  assert.equal(n.noticeFor("c"), undefined, "the oldest record is dropped");
});

test("gateNoticeOutput: Codex's exec header saying 77 plus exactly the notice; the header R4-blanked, the text the proxy's own", () => {
  const fco = (output: unknown, type = "function_call_output") => ({ type, call_id: "c", output }) as unknown as ToolOutputItem;
  assert.deepEqual(gateNoticeOutput(fco(`${HEADER}${NOTICE}\n`), "exec_command", NOTICE), { output: `${BLANKED}${NOTICE}`, text: `${BLANKED}${NOTICE}` });
  const parts = gateNoticeOutput(fco([{ type: "input_text", text: `${HEADER}${NOTICE}` }], "custom_tool_call_output"), "exec", NOTICE);
  assert.deepEqual(parts?.output, [{ type: "input_text", text: `${BLANKED}${NOTICE}` }]);
  // misses
  assert.equal(gateNoticeOutput(fco(`${HEADER}${NOTICE}\n${PROGRAM_BYTES}`), "exec_command", NOTICE), null);
  assert.equal(gateNoticeOutput(fco(`${HEADER}${PROGRAM_BYTES}\n${NOTICE}`), "exec_command", NOTICE), null);
  assert.equal(gateNoticeOutput(fco(`${HEADER.replace("code 77", "code 1")}${NOTICE}`), "exec_command", NOTICE), null, "another exit status");
  assert.equal(gateNoticeOutput(fco(NOTICE), "exec_command", NOTICE), null, "no runtime header");
  assert.equal(gateNoticeOutput(fco(`junk\n${HEADER}${NOTICE}`), "exec_command", NOTICE), null);
  // an MCP result: the header blanked, the body exactly the notice
  const mcp = gateNoticeOutput(fco([{ type: "input_text", text: "Wall time: 1.5 seconds\nOutput:" }, { type: "input_text", text: NOTICE }]), "mcp__box__run", NOTICE);
  assert.deepEqual(mcp?.output, [{ type: "input_text", text: "Wall time: 0 seconds\nOutput:" }, { type: "input_text", text: NOTICE }]);
  assert.equal(gateNoticeOutput(fco(`Wall time: 1.5 seconds\nOutput:\n${NOTICE}\n${PROGRAM_BYTES}`), "mcp__box__run", NOTICE), null);
});

// The !545 leftover (2026-10-09): a code-mode cell the proxy replaced WHOLE by
// the sentinel cell runs nothing but the sentinel; the script runtime's head
// then says the script `completed` (no exit 77).
const SCRIPT_HEAD = "Script completed\nWall time 0.2 seconds\nOutput:\n";
const SCRIPT_BLANKED = "Script completed\nWall time 0 seconds\nOutput:\n";

test("gateNoticeOutput, a whole-cell sentinel: the script head plus exactly the notice (or the sentinel's own exec head saying 77, then the notice); only for a cell the proxy replaced whole", () => {
  const cell = (output: unknown) => ({ type: "custom_tool_call_output", call_id: "c", output }) as unknown as ToolOutputItem;
  assert.deepEqual(gateNoticeOutput(cell(`${SCRIPT_HEAD}${NOTICE}\n`), "exec", NOTICE, true), { output: `${SCRIPT_BLANKED}${NOTICE}`, text: `${SCRIPT_BLANKED}${NOTICE}` });
  assert.deepEqual(gateNoticeOutput(cell([{ type: "input_text", text: SCRIPT_HEAD }, { type: "input_text", text: `${NOTICE}\n` }]), "exec", NOTICE, true)?.text, `${SCRIPT_BLANKED}${NOTICE}`);
  assert.deepEqual(gateNoticeOutput(cell(`${SCRIPT_HEAD}${HEADER}${NOTICE}\n`), "exec", NOTICE, true)?.text, `${SCRIPT_BLANKED}${NOTICE}`, "the sentinel's exec head inside the cell output is dropped");
  // misses
  assert.equal(gateNoticeOutput(cell(`${SCRIPT_HEAD}${NOTICE}\n`), "exec", NOTICE), null, "not a whole-cell replacement: the exit-77 rule stands");
  assert.equal(gateNoticeOutput(cell(`${SCRIPT_HEAD}${NOTICE}\n${PROGRAM_BYTES}`), "exec", NOTICE, true), null);
  assert.equal(gateNoticeOutput(cell(`${SCRIPT_HEAD}${PROGRAM_BYTES}\n${NOTICE}`), "exec", NOTICE, true), null);
  assert.equal(gateNoticeOutput(cell(`${SCRIPT_HEAD}${HEADER.replace("code 77", "code 0")}${NOTICE}`), "exec", NOTICE, true), null, "an inner exec head that is not the sentinel's");
  assert.equal(gateNoticeOutput(cell(NOTICE), "exec", NOTICE, true), null, "no runtime head");
  assert.equal(gateNoticeOutput({ type: "function_call_output", call_id: "c", output: `${SCRIPT_HEAD}${NOTICE}` } as unknown as ToolOutputItem, "exec_command", NOTICE, true), null, "a function call is not a cell");
});

test("rewriteRequest: a whole-cell sentinel's output reaches the model as the notice; program bytes beside it never do", async () => {
  const cellReq = (output: string): ResponsesRequest => ({
    model: "gpt-test",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "send it" }] },
      { type: "custom_tool_call", call_id: "call_cell", name: "exec", input: 'const r = await tools.exec_command({"cmd":"x"});\ntext(r.output);\n' },
      { type: "custom_tool_call_output", call_id: "call_cell", output },
    ],
  }) as unknown as ResponsesRequest;
  const whole = new ExecGateNotices();
  whole.remember("call_cell", NOTICE, { wholeCell: true });
  assert.equal(whole.wholeCell("call_cell"), true);
  const arbiter = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => ({ hits: [] }) });
  const out = await rewriteRequest(cellReq(`${SCRIPT_HEAD}${NOTICE}\n`), { arbiter, execGateNotices: whole });
  const fwd = (o: typeof out): string => {
    const item = (o.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "custom_tool_call_output")!;
    return typeof item.output === "string" ? item.output : (item.output as Array<{ text: string }>).map((p) => p.text).join("");
  };
  assert.equal(fwd(out), `${SCRIPT_BLANKED}${NOTICE}`, "over-masking gone: the model reads why its cell was blocked");
  assert.equal(arbiter.symbolizeCalls.length, 0);
  // a per-literal notice (not whole-cell) under the same script head stays masked as before
  const literal = new ExecGateNotices();
  literal.remember("call_cell", NOTICE);
  assert.equal(literal.wholeCell("call_cell"), false);
  assert.match(fwd(await rewriteRequest(cellReq(`${SCRIPT_HEAD}${NOTICE}\n`), { arbiter, execGateNotices: literal })), SYM_RE);
  // program bytes beside the notice: masked whole, nothing of it forwarded (CONFIDENTIALITY)
  const mixed = fwd(await rewriteRequest(cellReq(`${SCRIPT_HEAD}${NOTICE}\n${PROGRAM_BYTES}\n`), { arbiter, execGateNotices: whole }));
  assert.match(mixed, SYM_RE);
  assert.ok(!mixed.includes(PROGRAM_BYTES) && !mixed.includes("mandu-exec-gate"));
  // a backstop hit keeps it masked
  const hit = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => ({ hits: [{ symbol: "$MDU:nomodel_Read[ab12]", level: "no-model" }] }) });
  assert.match(fwd(await rewriteRequest(cellReq(`${SCRIPT_HEAD}${NOTICE}\n`), { arbiter: hit, execGateNotices: whole })), SYM_RE);
});

test("rewriteRequest: the sentinel's output reaches the model as the notice under the blanked header; nothing is minted", async () => {
  const arbiter = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => ({ hits: [] }) });
  const out = await rewriteRequest(request(`${HEADER}${NOTICE}\n`), { arbiter, execGateNotices: notices() });
  assert.equal(forwarded(out), `${BLANKED}${NOTICE}`);
  assert.equal(arbiter.symbolizeCalls.length, 0);
  assert.equal(out.rewrites[0]!.symbolized, false);
  assert.match(out.rewrites[0]!.reason ?? "", /exec gate notice/);
});

test("rewriteRequest: program output beside the notice is never forwarded, and the notice is not split out", async () => {
  const arbiter = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => ({ hits: [] }) });
  for (const body of [`${HEADER}${NOTICE}\n${PROGRAM_BYTES}\n`, `${HEADER}${PROGRAM_BYTES}\n${NOTICE}\n`]) {
    const text = forwarded(await rewriteRequest(request(body), { arbiter, execGateNotices: notices() }));
    assert.match(text, SYM_RE);
    assert.ok(!text.includes(PROGRAM_BYTES), "the program's bytes never reach the model");
    assert.ok(!text.includes("mandu-exec-gate"), "the notice is not split out of a mixed output");
  }
});

test("rewriteRequest: no record, a backstop hit, a failing or missing backstop → classified as before", async () => {
  const body = `${HEADER}${NOTICE}\n`;
  const clean = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => ({ hits: [] }) });
  assert.match(forwarded(await rewriteRequest(request(body), { arbiter: clean, execGateNotices: notices("call_other") })), SYM_RE);
  assert.match(forwarded(await rewriteRequest(request(body), { arbiter: clean })), SYM_RE);
  const hit = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => ({ hits: [{ symbol: "$MDU:nomodel_Read[ab12]", level: "no-model" }] }) });
  assert.match(forwarded(await rewriteRequest(request(body), { arbiter: hit, execGateNotices: notices() })), SYM_RE);
  const failing = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => { throw new Error("down"); } });
  assert.match(forwarded(await rewriteRequest(request(body), { arbiter: failing, execGateNotices: notices() })), SYM_RE);
  const missing = new MockArbiter({ classifyFn: secretEverything });
  assert.match(forwarded(await rewriteRequest(request(body), { arbiter: missing, execGateNotices: notices() })), SYM_RE);
});
