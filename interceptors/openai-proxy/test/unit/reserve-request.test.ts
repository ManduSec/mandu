/**
 * reserve-request.test — the request-side collapse and residual strip on the
 * Responses wire (src/reserve-request.ts; docs/design/ui/reply-row-reservation.md
 * §3.4, §5.2, §11.7): Codex re-sends the reserve block in its assistant
 * history, and the model must get its own token back byte for byte; a
 * fragment anywhere else (a tool output that read Codex's session file, the
 * user's text, `instructions`) is stripped; reasoning items and the model's
 * own call arguments are never touched. Pure: no arbiter, no axes.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { reserveRequestPass, WHERE_CAP } from "../../src/reserve-request.js";
import { reserveBlock } from "../../src/reserve-block.js";
import type { ResponsesRequest } from "../../src/responses-types.js";

const T = "$MDU:nomodel_exec_command[464e]";
const BLOCK = reserveBlock(T, 4);
const BLOCK2 = reserveBlock(T, 3, { width: 78, first: 65 });
const MARKER_RE = /\$MDU\/[0-9a-f]{4,8}\/[0-9]+|\$MDU:[^\s]*?\/1:[0-9]/;

type Json = Record<string, unknown>;
const clone = <X>(x: X): X => JSON.parse(JSON.stringify(x)) as X;

test("collapse: the assistant's output_text gets the model's text back byte for byte (v1 and v2, mid-line)", () => {
  const said = `Your config:\n\n${T}\n\nand inline: The value is ${T} and that is all.`;
  const sent = `Your config:\n\n${BLOCK}\n\nand inline: The value is ${BLOCK2} and that is all.`;
  const req: ResponsesRequest = {
    model: "gpt-5",
    instructions: "You are Codex.",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "show me the config" }] },
      { type: "message", role: "assistant", id: "msg_1", content: [{ type: "output_text", text: sent, annotations: [] }] },
      { type: "message", role: "user", content: [{ type: "input_text", text: "thanks" }] },
    ],
  };
  const before = clone(req);
  const r = reserveRequestPass(req);
  assert.deepEqual(r, { collapsed: 2, removed: 0, where: [] });
  const item = (req.input as Json[])[1]!;
  assert.equal(((item["content"] as Json[])[0]!)["text"], said);
  // Everything else is byte-identical.
  (((before.input as Json[])[1]!["content"]) as Json[])[0]!["text"] = said;
  assert.deepEqual(req, before);
});

test("collapse: a string assistant content, and an output_text part in any message", () => {
  const req = {
    input: [
      { type: "message", role: "assistant", content: `x\n${BLOCK}\ny` },
      { role: "assistant", content: BLOCK }, // an easy message: `type` omitted
      { type: "message", role: "developer", content: [{ type: "output_text", text: BLOCK }] },
    ],
  } as ResponsesRequest;
  const r = reserveRequestPass(req);
  assert.equal(r.collapsed, 3);
  assert.equal(r.removed, 0);
  const input = req.input as Json[];
  assert.equal(input[0]!["content"], `x\n${T}\ny`);
  assert.equal(input[1]!["content"], T);
  assert.equal(((input[2]!["content"] as Json[])[0]!)["text"], T);
});

test("strip: a residual in a function_call_output / custom_tool_call_output, the user's text and instructions; counted and located", () => {
  const transcript = `{"text":"${BLOCK.replace(/\n/g, "\\n")}"}\n${BLOCK}\n`;
  const req: ResponsesRequest = {
    instructions: `rules\n${BLOCK}`,
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: `paste: ${BLOCK}` }] },
      { type: "function_call", call_id: "c1", name: "exec_command", arguments: JSON.stringify({ cmd: "cat ~/.codex/sessions/x.jsonl" }) },
      { type: "function_call_output", call_id: "c1", output: transcript },
      { type: "custom_tool_call", call_id: "c2", name: "exec", input: "text(1)" },
      { type: "custom_tool_call_output", call_id: "c2", output: [
        { type: "input_text", text: "Script completed\nOutput:\n" },
        { type: "input_text", text: BLOCK },
        { type: "output_text", text: BLOCK }, // a tool's part is never the model's: stripped, not collapsed
      ] },
    ],
  };
  const r = reserveRequestPass(req);
  assert.equal(r.collapsed, 0, "nothing outside the assistant's own text collapses");
  assert.ok(r.removed > 0);
  assert.deepEqual(r.where, [
    "instructions",
    "input[0].content[0]:user_text",
    "input[2].output:function_call_output",
    "input[4].output[1]:custom_tool_call_output",
    "input[4].output[2]:custom_tool_call_output",
  ]);
  const body = JSON.stringify(req);
  assert.doesNotMatch(body, MARKER_RE, "no marker and no head suffix reaches the model");
  assert.ok(body.includes(T), "the token itself stays");
  assert.equal(req.instructions, `rules\n${T}`);
  const input = req.input as Json[];
  assert.equal(input[2]!["output"], `{"text":"${T}\\n$MDU/464e/2\\n$MDU/464e/3\\n$MDU/464e/4"}\n${T}\n`.replace(/\\n\$MDU\/464e\/[0-9]/g, "\\n"));
});

test("never touched: reasoning items, function_call arguments, custom_tool_call input, unknown items, images", () => {
  const req = {
    input: [
      { type: "reasoning", id: "rs_1", summary: [{ type: "summary_text", text: BLOCK }], encrypted_content: `enc${BLOCK}` },
      { type: "function_call", call_id: "c1", name: "exec_command", arguments: JSON.stringify({ cmd: `echo '${BLOCK}'` }) },
      { type: "custom_tool_call", call_id: "c2", name: "exec", input: `text("${BLOCK}")` },
      { type: "additional_tools", tools: [{ type: "namespace", name: "x", description: BLOCK }] },
      { type: "message", role: "user", content: [{ type: "input_image", image_url: `data:${BLOCK}` }] },
    ],
  } as ResponsesRequest;
  const before = clone(req);
  const r = reserveRequestPass(req);
  assert.deepEqual(r, { collapsed: 0, removed: 0, where: [] });
  assert.deepEqual(req, before);
});

test("a request without markers is untouched byte for byte; malformed shapes never throw", () => {
  const req: ResponsesRequest = {
    instructions: `about ${T}`,
    input: [
      { type: "message", role: "assistant", content: [{ type: "output_text", text: `The value is ${T}.` }] },
      { type: "function_call_output", call_id: "c", output: `$MDU/xyz/2 is not hex, $MDU:x[zz] no hash` },
    ],
  };
  const before = JSON.stringify(req);
  assert.deepEqual(reserveRequestPass(req), { collapsed: 0, removed: 0, where: [] });
  assert.equal(JSON.stringify(req), before);
  for (const odd of [null, 7, "x", [], { input: "plain" }, { input: [null, 1, "s", { type: "message" }, { type: "x_output", output: 5 }] }]) {
    assert.doesNotThrow(() => reserveRequestPass(odd as never));
  }
  const s = { input: `a ${BLOCK}` } as unknown as ResponsesRequest;
  reserveRequestPass(s);
  assert.equal(s.input as unknown, `a ${T}`, "a string `input` (a single user text) is stripped");
});

test("a malformed block in assistant text falls through to the strip; `where` is capped", () => {
  const broken = `${T}/1:4\n$MDU/464e/2\n$MDU/464e/3`; // one row missing
  const req = { input: [{ type: "message", role: "assistant", content: [{ type: "output_text", text: `a\n${broken}\nb` }] }] } as ResponsesRequest;
  const r = reserveRequestPass(req);
  assert.equal(r.collapsed, 0);
  assert.equal(((req.input as Json[])[0]!["content"] as Json[])[0]!["text"], `a\n${T}\nb`);
  const many = { input: Array.from({ length: WHERE_CAP + 5 }, () => ({ type: "function_call_output", call_id: "c", output: BLOCK })) } as ResponsesRequest;
  const rm = reserveRequestPass(many);
  assert.equal(rm.where.length, WHERE_CAP);
  assert.equal(rm.removed, (WHERE_CAP + 5) * 4);
});
