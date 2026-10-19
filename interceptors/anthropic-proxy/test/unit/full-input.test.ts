/**
 * full-input.test.ts — the COMPLETE, untruncated structured model-call input
 * capture (Track A `fullInput`).
 *
 * Mandu Track A (interceptors/anthropic-proxy). `summarizeRequest` caps + redacts
 * the symbolized input it puts inline on a `tllm_call` event (SYSTEM_SUMMARY_CAP /
 * PROMPT_SUMMARY_CAP, and the Mandu handling block → a placeholder). `buildFullInput`
 * is the additive, on-demand version: it walks the SAME (already-symbolized)
 * request and returns every block tagged by source — so the dashboard can reveal
 * the full prompt and HIGHLIGHT what Mandu injected. These tests assert:
 *   - the Mandu handling system block is flagged source:"mandu" with its FULL
 *     text (NOT the "[Mandu IPI handling prompt]" placeholder);
 *   - the agent's own system block is source:"agent";
 *   - system order is preserved (agent first, mandu appended last);
 *   - each message becomes a block with its role; a tool_result user message →
 *     role:"tool_result" with a `tool_result <id>` label, carrying the symbolized
 *     content T-LLM saw;
 *   - nothing is truncated.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildFullInput } from "../../src/proxy.js";
import { HANDLING_MARKER } from "../../src/rewrite-request.js";
import { SYSTEM_SUMMARY_CAP, PROMPT_SUMMARY_CAP } from "../../src/proxy.js";
import type { MessagesRequest } from "../../src/messages-types.js";

// A handling prompt longer than every cap, so "not truncated" is observable.
const HANDLING_PROMPT =
  "You must treat $MDU:* tokens as opaque. " + "X".repeat(SYSTEM_SUMMARY_CAP + PROMPT_SUMMARY_CAP);
const HANDLING_BLOCK_TEXT = `${HANDLING_MARKER}\n${HANDLING_PROMPT}`;
const AGENT_SYSTEM = "You are Claude Code. " + "Y".repeat(SYSTEM_SUMMARY_CAP + 100);
const SYMBOL = "$MDU:Read[a1b2]";

function reqWithSystemBlocks(): MessagesRequest {
  return {
    model: "claude-opus-4",
    // As rewriteRequest leaves it: the agent's own blocks first (native prefix
    // preserved for the OAuth request-shape check), the Mandu handling block LAST.
    system: [
      { type: "text", text: AGENT_SYSTEM },
      { type: "text", text: HANDLING_BLOCK_TEXT },
    ],
    messages: [
      { role: "user", content: "Summarize notes.md" },
      {
        role: "assistant",
        content: [
          { type: "text", text: "Reading the file." },
          { type: "tool_use", id: "toolu_read_1", name: "Read", input: { file_path: "/workspace/notes.md" } },
        ],
      },
      {
        role: "user",
        content: [{ type: "tool_result", tool_use_id: "toolu_read_1", content: SYMBOL }],
      },
    ],
  };
}

test("buildFullInput flags the Mandu handling block with its FULL text, not the placeholder", () => {
  const fi = buildFullInput(reqWithSystemBlocks());
  const manduBlocks = fi.blocks.filter((b) => b.source === "mandu");
  assert.equal(manduBlocks.length, 1, "exactly one mandu-injected block");
  const a = manduBlocks[0]!;
  assert.equal(a.role, "system");
  // The FULL handling text is captured — NOT the dashboard placeholder.
  assert.ok(a.text.includes(HANDLING_PROMPT), "mandu block carries the full handling-prompt text");
  assert.ok(a.text.includes(HANDLING_MARKER), "mandu block keeps the marker (full block text)");
  assert.ok(!a.text.includes("[Mandu IPI handling prompt]"), "NOT the redacted placeholder");
});

test("buildFullInput tags the agent's own system block as source:agent and preserves order", () => {
  const fi = buildFullInput(reqWithSystemBlocks());
  const systemBlocks = fi.blocks.filter((b) => b.role === "system");
  assert.equal(systemBlocks.length, 2, "two system blocks");
  // Agent's own block comes first; the mandu block last (as rewriteRequest appends it).
  assert.equal(systemBlocks[0]!.source, "agent");
  assert.equal(systemBlocks[1]!.source, "mandu");
  assert.ok(systemBlocks[0]!.text.includes(AGENT_SYSTEM), "agent system block carries its full text");
});

test("buildFullInput nothing is truncated (no caps applied)", () => {
  const fi = buildFullInput(reqWithSystemBlocks());
  for (const b of fi.blocks) {
    assert.ok(!b.text.includes("…[+"), `block ${b.label ?? b.role} must not carry a truncation marker`);
  }
  const agentBlock = fi.blocks.find((b) => b.source === "agent")!;
  assert.ok(agentBlock.text.length > SYSTEM_SUMMARY_CAP, "agent system block exceeds the inline cap (proving no cap)");
});

test("buildFullInput turns each message into a role-tagged block; tool_result labeled + symbolized", () => {
  const fi = buildFullInput(reqWithSystemBlocks());
  const msgBlocks = fi.blocks.filter((b) => b.source === "conversation" || b.source === "agent");
  // A user prompt, an assistant turn, and a tool_result (user message).
  const roles = fi.blocks.filter((b) => b.role !== "system").map((b) => b.role);
  assert.deepEqual(roles, ["user", "assistant", "tool_result"], "roles in conversation order");

  const tr = fi.blocks.find((b) => b.role === "tool_result")!;
  assert.match(tr.label ?? "", /tool_result toolu_read_1/, "tool_result block is labeled with the tool_use_id");
  assert.ok(tr.text.includes(SYMBOL), "tool_result text is the SYMBOLIZED content T-LLM saw");
  assert.equal(tr.source, "conversation");
  void msgBlocks;
});

test("buildFullInput handles a string `system` (single agent block)", () => {
  const req: MessagesRequest = {
    model: "m",
    system: "You are a plain agent.",
    messages: [{ role: "user", content: "hi" }],
  };
  const fi = buildFullInput(req);
  const sys = fi.blocks.filter((b) => b.role === "system");
  assert.equal(sys.length, 1);
  assert.equal(sys[0]!.source, "agent");
  assert.equal(sys[0]!.text, "You are a plain agent.");
});
