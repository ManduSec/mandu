/**
 * ullm-timeout.test.ts — how long inspect_symbol may wait for a declared
 * model, and the agents' MCP timeouts derived from it
 * (launcher/src/ullm-timeout.ts, model-endpoints.md §1.9).
 *
 * The live demo runs of 2026-10-17 lost a local model's summary three ways:
 * Codex handed inspect-mcp no MANDU_ULLM_ENDPOINT_TIMEOUT_MS ("U-LLM request
 * timed out after 60000ms"), OpenCode's 30 s MCP timeout cut the call ("MCP
 * error -32001: Request timed out"), and Claude Code moved it to the
 * background (claude-mcp-background.test.ts). The e2e is the drill suite's
 * codex-mcp-tool-timeout (the real `codex exec`, the production overrides,
 * a slow stand-in tool).
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  INSPECT_CALL_MARGIN_MS, LOCAL_ULLM_ENDPOINT_TIMEOUT_MS, ULLM_ENDPOINT_DEFAULT_TIMEOUT_MS, ULLM_ENDPOINT_TIMEOUT_ENV,
  declaresLocalModel, effectiveUllmEndpointTimeoutMs, entryUllmEndpointTimeoutMs, inspectCallBoundMs, userUllmEndpointTimeoutMs,
} from "../../src/ullm-timeout.js";
import { inspectMcpConfigDoc } from "../../src/services/mcp.js";
import { buildOpencodeWrapDoc, OPENCODE_MCP_TIMEOUT_MS, opencodeInspectTimeoutMs, opencodeV2McpServer } from "../../src/services/agent-config.js";
import { codexMcpOverrides, codexMcpTimeouts } from "../../src/env-compose.js";
import { Layout } from "../../src/services/layout.js";
import type { Ullm } from "../../src/types.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // launch configuration; no axis turns it on or off

const LOCAL = [{ local: true }];
const OUTSIDE = [{ local: false }];
const ULLM: Ullm = { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" };
const SLICE = { arbiterSock: "/run/mandu/arbiter.sock", scopeId: "sid-1", tenant: "live" as const, ullm: ULLM };

test("the user's value is read with inspect-mcp's rule: a positive integer of ms up to 10 min, else none", () => {
  assert.equal(ULLM_ENDPOINT_TIMEOUT_ENV, "MANDU_ULLM_ENDPOINT_TIMEOUT_MS");
  assert.equal(userUllmEndpointTimeoutMs({}), undefined);
  assert.equal(userUllmEndpointTimeoutMs({ MANDU_ULLM_ENDPOINT_TIMEOUT_MS: "360000" }), 360_000);
  assert.equal(userUllmEndpointTimeoutMs({ MANDU_ULLM_ENDPOINT_TIMEOUT_MS: " 5000 " }), 5_000);
  assert.equal(userUllmEndpointTimeoutMs({ MANDU_ULLM_ENDPOINT_TIMEOUT_MS: "600000" }), 600_000);
  for (const bad of ["600001", "0", "-5", "1e5", "abc", "", "12000000"]) {
    assert.equal(userUllmEndpointTimeoutMs({ MANDU_ULLM_ENDPOINT_TIMEOUT_MS: bad }), undefined, bad);
  }
});

test("the entry's value: the user's (larger or smaller), else the local default with a local model, else none", () => {
  assert.equal(entryUllmEndpointTimeoutMs({}, LOCAL), LOCAL_ULLM_ENDPOINT_TIMEOUT_MS);
  assert.ok(LOCAL_ULLM_ENDPOINT_TIMEOUT_MS > ULLM_ENDPOINT_DEFAULT_TIMEOUT_MS, "a declared local model raises the default");
  assert.equal(entryUllmEndpointTimeoutMs({ MANDU_ULLM_ENDPOINT_TIMEOUT_MS: "30000" }, LOCAL), 30_000, "never over the user's value");
  assert.equal(entryUllmEndpointTimeoutMs({ MANDU_ULLM_ENDPOINT_TIMEOUT_MS: "500000" }, LOCAL), 500_000);
  assert.equal(entryUllmEndpointTimeoutMs({ MANDU_ULLM_ENDPOINT_TIMEOUT_MS: "90000" }, OUTSIDE), 90_000, "the user's value without a local model too");
  assert.equal(entryUllmEndpointTimeoutMs({}, OUTSIDE), undefined);
  assert.equal(entryUllmEndpointTimeoutMs({}, undefined), undefined);
  assert.equal(declaresLocalModel([...OUTSIDE, ...LOCAL]), true);
  assert.equal(effectiveUllmEndpointTimeoutMs(undefined), ULLM_ENDPOINT_DEFAULT_TIMEOUT_MS);
  assert.equal(effectiveUllmEndpointTimeoutMs(1234), 1234);
});

test("the call bound exceeds two model waits", () => {
  for (const t of [1, 60_000, LOCAL_ULLM_ENDPOINT_TIMEOUT_MS, 600_000]) {
    assert.equal(inspectCallBoundMs(t), 2 * t + INSPECT_CALL_MARGIN_MS);
  }
});

test("the inspect-mcp entry carries the value every agent hands the server (Codex hands only the entry's env); none when undefined", () => {
  const layout = Layout.dev("/repo");
  const withIt = inspectMcpConfigDoc({ ...SLICE, ullmEndpointTimeoutMs: 240_000 }, layout).mcpServers["mandu-inspect"]!.env;
  assert.equal(withIt["MANDU_ULLM_ENDPOINT_TIMEOUT_MS"], "240000");
  const without = inspectMcpConfigDoc(SLICE, layout).mcpServers["mandu-inspect"]!.env;
  assert.equal("MANDU_ULLM_ENDPOINT_TIMEOUT_MS" in without, false, "the entry as before");
});

test("Codex: mandu-inspect's tool_timeout_sec is the call bound in whole seconds; none without a U-LLM timeout; other servers untouched", () => {
  assert.deepEqual(codexMcpTimeouts(undefined), {});
  assert.deepEqual(codexMcpTimeouts(240_000), { toolTimeoutSec: { "mandu-inspect": 540 } });
  assert.deepEqual(codexMcpTimeouts(1_500), { toolTimeoutSec: { "mandu-inspect": 63 } }, "rounded up");
  const servers = {
    "mandu-inspect": { command: "node", args: ["inspect.mjs"], env: { A: "1" } },
    "mandu-policy": { command: "node", args: ["policy.mjs"], env: {} },
  };
  const argv = codexMcpOverrides(servers, codexMcpTimeouts(240_000));
  assert.ok(argv.includes("mcp_servers.mandu-inspect.tool_timeout_sec=540"), argv.join(" "));
  assert.ok(!argv.some((a) => a.startsWith("mcp_servers.mandu-policy.tool_timeout_sec")));
  assert.ok(!codexMcpOverrides(servers).some((a) => a.includes("tool_timeout_sec")), "the overrides as before");
  for (const bad of [0, -1, 1.5, Number.NaN]) {
    assert.ok(!codexMcpOverrides(servers, { toolTimeoutSec: { "mandu-inspect": bad } }).some((a) => a.includes("tool_timeout_sec")), String(bad));
  }
});

test("OpenCode: mandu-inspect's timeout is the call bound (never under 30 s); the policy server keeps 30 s; V1 and V2 spellings", () => {
  assert.equal(opencodeInspectTimeoutMs(undefined), OPENCODE_MCP_TIMEOUT_MS);
  assert.equal(opencodeInspectTimeoutMs(240_000), 540_000);
  assert.equal(opencodeInspectTimeoutMs(1), 60_002);
  const layout = Layout.dev("/repo");
  const input = { target: "opencode" as const, scopeId: "sid-1", tenant: "live" as const, proxyUrl: "http://127.0.0.1:8788", inspect: true };
  type Doc = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  const v1 = buildOpencodeWrapDoc(input, { ...SLICE, ullmEndpointTimeoutMs: 240_000 }, layout) as Doc;
  assert.equal(v1["mcp"]["mandu-inspect"].timeout, 540_000);
  assert.equal(v1["mcp"]["mandu-inspect"].environment.MANDU_ULLM_ENDPOINT_TIMEOUT_MS, "240000");
  assert.equal(v1["mcp"]["mandu-policy"].timeout, OPENCODE_MCP_TIMEOUT_MS);
  const v1plain = buildOpencodeWrapDoc(input, SLICE, layout) as Doc;
  assert.equal(v1plain["mcp"]["mandu-inspect"].timeout, OPENCODE_MCP_TIMEOUT_MS, "as before without a U-LLM timeout");
  const v2 = buildOpencodeWrapDoc({ ...input, opencodeGeneration: 2 }, { ...SLICE, ullmEndpointTimeoutMs: 240_000 }, layout) as Doc;
  assert.deepEqual(v2["mcp"]["servers"]["mandu-inspect"].timeout, { startup: 30_000, catalog: 30_000, execution: 540_000 });
  assert.deepEqual(v2["mcp"]["servers"]["mandu-policy"].timeout, { startup: 30_000, catalog: 30_000, execution: 30_000 });
  assert.deepEqual((opencodeV2McpServer({ command: "x", args: [], env: {} }) as Doc)["timeout"], { startup: 30_000, catalog: 30_000, execution: 30_000 });
});
