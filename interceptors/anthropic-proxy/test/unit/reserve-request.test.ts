/**
 * reserve-request.test — the request-side pass of reply row reservation
 * (src/reserve-request.ts; docs/design/ui/reply-row-reservation.md §3.4): exact
 * collapse in assistant text only, the residual strip over every text block
 * type the model reads, and the blocks it must never touch.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { reserveRequestPass, WHERE_CAP } from "../../src/reserve-request.js";
import { reserveBlock } from "../../src/reserve-block.js";
import { buildTrustedContextHaystack } from "../../src/rewrite-request.js";
import type { MessagesRequest } from "../../src/messages-types.js";

const T = "$MDU:nomodel_Bash[464e]";
const BLOCK = reserveBlock(T, 3);
const MARK = /\$MDU\/[0-9a-f]{4,8}\/\d+|\/1:\d/;

function req(messages: MessagesRequest["messages"], system?: MessagesRequest["system"]): MessagesRequest {
  return { model: "claude-x", messages, ...(system !== undefined ? { system } : {}) };
}

test("assistant text: a well-formed block collapses to the exact token", () => {
  const text = `The file:\n\n${BLOCK}\n\nDone.`;
  const r = req([
    { role: "user", content: "show me" },
    { role: "assistant", content: [{ type: "text", text }] },
  ]);
  const p = reserveRequestPass(r);
  assert.deepEqual(p, { collapsed: 1, removed: 0, where: [] });
  assert.equal((r.messages[1]!.content as Array<{ text: string }>)[0]!.text, `The file:\n\n${T}\n\nDone.`);
});

test("assistant string content collapses too", () => {
  const r = req([{ role: "assistant", content: BLOCK }]);
  assert.equal(reserveRequestPass(r).collapsed, 1);
  assert.equal(r.messages[0]!.content, T);
});

test("a mangled assistant block is stripped (fail to strip, never pass on)", () => {
  const r = req([{ role: "assistant", content: [{ type: "text", text: `${T}/1:3\n$MDU/464e/3` }] }]);
  const p = reserveRequestPass(r);
  assert.equal(p.collapsed, 0);
  assert.equal(p.removed, 2);
  assert.deepEqual(p.where, ["messages[0].content[0]:assistant_text"]);
  assert.equal((r.messages[0]!.content as Array<{ text: string }>)[0]!.text, T);
});

test("strip everywhere the model reads: user text, tool_result (string and text blocks), system", () => {
  const r = req(
    [
      { role: "user", content: [{ type: "text", text: `pasted:\n${BLOCK}` }] },
      { role: "assistant", content: [{ type: "tool_use", id: "tu1", name: "Bash", input: { command: "cat t.jsonl" } }] },
      {
        role: "user",
        content: [
          { type: "tool_result", tool_use_id: "tu1", content: `{"text":"x"}\n$MDU/464e/2\n${T}/1:9` },
          { type: "tool_result", tool_use_id: "tu2", content: [{ type: "text", text: "row $MDU/464e/5 here" }, { type: "image", source: { type: "base64", data: "$MDU/464e/5" } }] },
        ],
      },
      { role: "user", content: `string user content ${T}/1:2` },
    ],
    [{ type: "text", text: "memory: $MDU/abcd/2" }],
  );
  const p = reserveRequestPass(r);
  // User text is never COLLAPSED (only the assistant's own blocks are
  // exact); its fragments are stripped.
  assert.equal(p.collapsed, 0);
  const json = JSON.stringify(r);
  const imageData = "$MDU/464e/5";
  assert.ok(json.includes(imageData), "a non-text block is untouched");
  const withoutImage = json.replace(`"data":"${imageData}"`, "");
  assert.doesNotMatch(withoutImage, MARK, withoutImage);
  assert.equal((r.messages[0]!.content as Array<{ text: string }>)[0]!.text, `pasted:\n${T}`);
  const tr = (r.messages[2]!.content as Array<{ content: unknown }>);
  assert.equal(tr[0]!.content, `{"text":"x"}\n${T}`);
  assert.equal((tr[1]!.content as Array<{ text?: string }>)[0]!.text, "row  here");
  assert.equal(r.messages[3]!.content, `string user content ${T}`);
  assert.equal((r.system as Array<{ text: string }>)[0]!.text, "memory: ");
  assert.deepEqual(p.where, [
    "system[0]",
    "messages[0].content[0]:user_text",
    "messages[2].content[0]:tool_result",
    "messages[2].content[1].content[0]:tool_result",
    "messages[3].content:user_text",
  ]);
  assert.equal(p.removed, 3 + 1 + 2 + 1 + 1);
});

test("never touched: thinking, redacted_thinking, tool_use input", () => {
  const thinking = { type: "thinking", thinking: `plan ${BLOCK}`, signature: "sig" };
  const redacted = { type: "redacted_thinking", data: "$MDU/464e/2" };
  const tu = { type: "tool_use", id: "t", name: "Bash", input: { command: `echo ${T}/1:3 $MDU/464e/2` } };
  const r = req([{ role: "assistant", content: [thinking, redacted, tu] }]);
  const before = JSON.stringify(r);
  assert.deepEqual(reserveRequestPass(r), { collapsed: 0, removed: 0, where: [] });
  assert.equal(JSON.stringify(r), before);
});

test("a system prompt string is stripped; one with no fragment is byte-identical", () => {
  const r1 = req([], "sys $MDU/464e/2");
  reserveRequestPass(r1);
  assert.equal(r1.system, "sys ");
  const clean = req([{ role: "user", content: "hi" }], [{ type: "text", text: "You are Claude Code. $MDU:x[ab12] cost $5/1:2" }]);
  const before = JSON.stringify(clean);
  reserveRequestPass(clean);
  assert.equal(JSON.stringify(clean), before);
});

test("malformed shapes never throw", () => {
  for (const bad of [null, {}, { messages: "x" }, { messages: [null, 3, { role: "user" }, { role: "user", content: [null, 5, { type: "text" }, { type: "tool_result", content: [null, { type: "text", text: 7 }] }] }] }, { system: [null, { type: "text" }] }]) {
    assert.doesNotThrow(() => reserveRequestPass(bad as unknown as MessagesRequest));
  }
});

test("where is capped", () => {
  const msgs = Array.from({ length: WHERE_CAP + 5 }, () => ({ role: "user", content: "$MDU/464e/2" }));
  const p = reserveRequestPass(req(msgs));
  assert.equal(p.removed, WHERE_CAP + 5);
  assert.equal(p.where.length, WHERE_CAP);
});

test("the trusted-context haystack built after the pass holds the token, never a marker (TRIPWIRE)", () => {
  const r = req([
    { role: "assistant", content: [{ type: "text", text: `x\n${BLOCK}` }] },
    { role: "user", content: [{ type: "text", text: `${T}/1:4` }] },
  ]);
  reserveRequestPass(r);
  const hay = buildTrustedContextHaystack(r);
  assert.ok(hay.includes(T));
  assert.doesNotMatch(hay, MARK);
});
