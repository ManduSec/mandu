/**
 * inspect-answer.test.ts — view-model/inspect-answer.ts: which calls are the
 * sandboxed reader's, and the answer each one got back in every shape the
 * arbiter keeps (dashboard.md §4.2f, "The sandboxed reader's card"). Pure.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { inspectAnswer, isInspectCall, MANDU_INSPECT_TOOL_SPELLINGS } from "../../../src/view-model/inspect-answer.js";

const ANS = "$MDU:inspect[1e26].result";
const ENV = JSON.stringify({ result_symbol: ANS, model: "claude-haiku-4-5", content_kind: "as_requested" });
const BUDGET = "<system-reminder>\n<total_tokens>91234 tokens left</total_tokens>\n</system-reminder>";

test("isInspectCall: each of Mandu's spellings, and any server's `__inspect_symbol` as before; nothing else", () => {
  assert.deepEqual([...MANDU_INSPECT_TOOL_SPELLINGS], [
    "mcp__mandu-inspect__inspect_symbol",
    "mandu-inspect_inspect_symbol",
    "mcp__mandu_inspect__inspect_symbol",
    "mandu-inspect__inspect_symbol",
    "inspect_symbol",
  ]);
  for (const tool of MANDU_INSPECT_TOOL_SPELLINGS) assert.equal(isInspectCall(tool), true, tool);
  assert.equal(isInspectCall("mcp__other__inspect_symbol"), true, "the card's words name no server: kept as before");
  for (const tool of ["other_inspect_symbol", "inspect_symbols", "mcp__mandu-inspect__declassify_symbol", "xinspect_symbol", "mandu-inspect_inspect_symbol2", "Read", ""]) {
    assert.equal(isInspectCall(tool), false, tool);
  }
});

test("inspectAnswer: the envelope (Claude Code's structuredContent), alone or with what an agent appended after it", () => {
  assert.deepEqual(inspectAnswer(ENV), { answer: ANS, tail: null });
  assert.deepEqual(inspectAnswer(`  ${JSON.stringify(JSON.parse(ENV), null, 2)}\n`), { answer: ANS, tail: null }, "pretty-printed, padded");
  assert.deepEqual(inspectAnswer(`${ENV}\n\n${BUDGET}`), { answer: ANS, tail: BUDGET }, "a kept reminder");
  assert.deepEqual(inspectAnswer(`${ENV}\n\n\n\n$MDU:inspect[5a3a]`), { answer: ANS, tail: "$MDU:inspect[5a3a]" }, "a masked reminder (a live session's shape)");
  // The original side: the envelope holds the answer itself.
  assert.deepEqual(inspectAnswer(JSON.stringify({ result_symbol: "A short summary.", model: "m" })), { answer: "A short summary.", tail: null });
  // A brace or an escaped quote inside a string does not end the envelope.
  const tricky = JSON.stringify({ result_symbol: 'a "quoted" } answer {', model: "m}" });
  assert.deepEqual(inspectAnswer(`${tricky}\nafter`), { answer: 'a "quoted" } answer {', tail: "after" });
  assert.deepEqual(inspectAnswer(JSON.stringify({ result_symbol: ANS, extra: { nested: [1, { b: "}" }] } })), { answer: ANS, tail: null });
  // One escaped quote before a brace: the string goes on past it.
  assert.deepEqual(inspectAnswer(`${JSON.stringify({ result_symbol: 'one " quote } here' })}\n${BUDGET}`), { answer: 'one " quote } here', tail: BUDGET });
});

test("inspectAnswer: the bare answer token (the MCP content text), alone, padded, level-named, or followed by the envelope or a note", () => {
  assert.deepEqual(inspectAnswer(ANS), { answer: ANS, tail: null });
  assert.deepEqual(inspectAnswer(`\n ${ANS} \n`), { answer: ANS, tail: null });
  assert.deepEqual(inspectAnswer("$MDU:localmodel_inspect[1e26].result"), { answer: "$MDU:localmodel_inspect[1e26].result", tail: null });
  assert.deepEqual(inspectAnswer(`${ANS}${ENV}`), { answer: ANS, tail: null }, "both blocks joined: the envelope repeats the token");
  assert.deepEqual(inspectAnswer(`${ANS}\n${ENV}\n\n${BUDGET}`), { answer: ANS, tail: BUDGET });
  const other = JSON.stringify({ result_symbol: "$MDU:inspect[9999].result" });
  assert.deepEqual(inspectAnswer(`${ANS}${other}`), { answer: ANS, tail: other }, "an envelope naming another token is not dropped");
  assert.deepEqual(inspectAnswer(`${ANS}\n\n${BUDGET}`), { answer: ANS, tail: BUDGET });
});

test("inspectAnswer: anything else is no answer, so the caller draws what it drew before", () => {
  for (const text of [
    null,
    "",
    "   ",
    `Here it is: ${ENV}`, // prose before the envelope
    JSON.stringify({ model: "m" }), // no result_symbol
    JSON.stringify({ result_symbol: 5 }),
    JSON.stringify({ result_symbol: "" }),
    `{"result_symbol":"${ANS}"`, // never closed
    `{"result_symbol":"${ANS}",}`, // not JSON
    JSON.stringify([{ result_symbol: ANS }]), // an array
    "$MDU:inspect[5a3a]", // a result masked whole: its token has no `result` field
    "$MDU:mcp__mandu-inspect__inspect_symbol[0bad]",
    `see ${ANS}`, // a token in prose
    "inspect_symbol: unknown symbol $MDU:Read[3df9]", // the server's refusal
  ]) {
    assert.equal(inspectAnswer(text), null, String(text));
  }
});
