/**
 * claude-mcp-background.test.ts — the window the launcher gives Claude Code's
 * MCP auto-background when the session declares the user's own model
 * (launcher/src/claude-mcp-background.ts, model-endpoints.md §1.9).
 *
 * The second live demo battery (2026-10-17): inspect_symbol at a local
 * qwen2.5:32b took over 120 s, Claude Code moved it to the background, and
 * the model ended its turn with "the summary is still being generated".
 * The e2e (the real launcher and claude -p with a slow MCP tool) is the
 * drill suite's claude-mcp-auto-background.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { CLAUDE_MCP_AUTO_BACKGROUND_ENV, autoBackgroundNote, claudeMcpAutoBackgroundMs } from "../../src/claude-mcp-background.js";
import { INSPECT_CALL_MARGIN_MS, LOCAL_ULLM_ENDPOINT_TIMEOUT_MS } from "../../src/ullm-timeout.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // a launch-env rule; no axis turns it on or off

const LOCAL = [{ local: true }];
const OUTSIDE = [{ local: false }];

test("the variable is Claude Code's own name", () => {
  assert.equal(CLAUDE_MCP_AUTO_BACKGROUND_ENV, "CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS");
});

test("a Claude Code launch with a local model: two endpoint timeouts plus the margin, above Claude Code's 120 s default", () => {
  // no user timeout: the local default the inspect entry carries (ullm-timeout.ts)
  const def = claudeMcpAutoBackgroundMs({ target: "claude", endpoints: LOCAL, env: {} });
  assert.equal(def, 2 * LOCAL_ULLM_ENDPOINT_TIMEOUT_MS + INSPECT_CALL_MARGIN_MS);
  assert.ok(def! > 120_000, "above the default window");
  // the demo's 6 min endpoint timeout: 13 min
  assert.equal(claudeMcpAutoBackgroundMs({ target: "claude", endpoints: LOCAL, env: { MANDU_ULLM_ENDPOINT_TIMEOUT_MS: "360000" } }), 780_000);
  // every value exceeds the longest wait it covers
  for (const t of [1, 5_000, 60_000, 600_000]) {
    const ms = claudeMcpAutoBackgroundMs({ target: "claude", endpoints: LOCAL, env: { MANDU_ULLM_ENDPOINT_TIMEOUT_MS: String(t) } })!;
    assert.ok(ms > 2 * t, `${ms} > 2 × ${t}`);
  }
});

test("a mix of a local and an outside model still sets it", () => {
  assert.notEqual(claudeMcpAutoBackgroundMs({ target: "claude", endpoints: [...OUTSIDE, ...LOCAL], env: {} }), null);
});

test("none without a local model, for another agent, or with no models read", () => {
  assert.equal(claudeMcpAutoBackgroundMs({ target: "claude", endpoints: OUTSIDE, env: {} }), null);
  assert.equal(claudeMcpAutoBackgroundMs({ target: "claude", endpoints: [], env: {} }), null);
  assert.equal(claudeMcpAutoBackgroundMs({ target: "claude", endpoints: undefined, env: {} }), null);
  for (const target of ["codex", "goose", "opencode", "openclaw", "shell"]) {
    assert.equal(claudeMcpAutoBackgroundMs({ target, endpoints: LOCAL, env: {} }), null, target);
  }
});

test("a value the user set stands, whether larger, smaller or 0 (off): the launcher never replaces it", () => {
  for (const own of ["900000", "30000", "0"]) {
    assert.equal(claudeMcpAutoBackgroundMs({ target: "claude", endpoints: LOCAL, env: { [CLAUDE_MCP_AUTO_BACKGROUND_ENV]: own } }), null, own);
  }
  // an empty value is unset (Claude Code reads it so)
  assert.notEqual(claudeMcpAutoBackgroundMs({ target: "claude", endpoints: LOCAL, env: { [CLAUDE_MCP_AUTO_BACKGROUND_ENV]: " " } }), null);
});

test("the launch note names the variable and the value", () => {
  assert.match(autoBackgroundNote(180_000), /^mandu: Claude Code waits up to 180 s for inspect_symbol .*CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS=180000/);
});
