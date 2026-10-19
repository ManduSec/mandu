import { test } from "node:test";
import assert from "node:assert/strict";
import { checkEvidence, renderPairedReport, type PairedReport } from "./paired-report.js";
import { SMOKE_TASKS } from "./paired-tasks.js";
import type { CapturedModelRequest } from "./paired-observer.js";
import { SubscriptionBudget } from "./paired-subscription.js";
import { BatchBudget, approvalProposal, PAID_MODEL } from "./paired-budget.js";

const task = SMOKE_TASKS[0];
const marker = task.markers[0];
const request = (content: string): CapturedModelRequest => ({ channel: "model", path: "/v1/messages", body: {
  tools: [{ name: "mcp__mandu-inspect__inspect_symbol" }], messages: [
    { role: "assistant", content: [{ type: "tool_use", id: "reread", name: "Read", input: { file_path: "result.json" } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "reread", content }] },
  ],
} });
const events = [{ kind: "ullm_call", output: { symbolized: "$MDU:inspect[aaaa]" } }, { kind: "launch_posture", dropped: [] }];
const inspection: CapturedModelRequest = { channel: "inspection", path: "/v1/messages", body: { messages: [{ role: "user", content: marker }] } };

test("empty capture and symbols without successful inspection cannot pass", () => {
  assert.equal(checkEvidence(task, "wrapped-default", [], []).status, "incomplete");
  assert.equal(checkEvidence(task, "unwrapped", [], []).status, "incomplete");
  assert.equal(checkEvidence(task, "wrapped-default", [request("$MDU:Read[aaaa]")], []).status, "incomplete");
});

test("boundary and liveness checks distinguish original data from symbols", () => {
  assert.equal(checkEvidence(task, "unwrapped", [request(marker)], []).status, "pass");
  assert.equal(checkEvidence(task, "unwrapped", [request("$MDU:Read[aaaa]")], []).status, "incomplete");
  assert.equal(checkEvidence(task, "wrapped-default", [request(marker), inspection], events).status, "fail");
  assert.equal(checkEvidence(task, "wrapped-default", [request("$MDU:Read[aaaa]"), inspection], events).status, "pass");
  assert.equal(checkEvidence(task, "wrapped-default", [request("$MDU:Read[aaaa]"), inspection], [{ ...events[1], dropped: ["fs dropped"] }, events[0]]).status, "incomplete");
});

test("a marker only in assistant prose is not evidence the baseline consumed input", () => {
  const r = request("no data");
  (r.body.messages as any[]).push({ role: "assistant", content: marker });
  assert.equal(checkEvidence(task, "unwrapped", [r], []).status, "incomplete");
  assert.equal(checkEvidence(task, "wrapped-default", [r, inspection], events).status, "fail");
});

test("report retains incomplete pairs and unknown costs without claiming model utility", () => {
  const report: PairedReport = {
    schemaVersion: 1, mode: "scripted", createdAt: "test", suiteDigest: "test", agentVersion: "test", revision: "test", sourceDigest: "test", workingTreeDirty: false,
    config: { model: "mock", inspectionModel: "mock", agentBinary: "claude", repoRoot: "/repo", timeoutMs: 1 },
    results: ["unwrapped", "wrapped-default"].map((side) => ({ taskId: "BP-01", side: side as "unwrapped" | "wrapped-default", status: side === "unwrapped" ? "pass" : "not-run", durationMs: null, exitCode: null, reason: null, checks: [], evidence: { status: "incomplete", checks: [] }, modelRequests: 0, inspectionRequests: 0, costUsd: null, artifactDir: "/tmp/x" })),
  };
  const text = renderPairedReport(report);
  assert.match(text, /not real-model task utility/);
  assert.match(text, /incomplete: 1/);
  assert.match(text, /wrapped-default: 0\/1 planned legs passed/);
  assert.match(text, /unknown/);
  const now = Date.parse("2026-09-11T09:00:00Z");
  const budget = new BatchBudget({ ...approvalProposal(now), approved: true }, () => now);
  const id = budget.reserve("BP-01-unwrapped", "model", 100);
  budget.settle(id, { input_tokens: 17, output_tokens: 0 });
  budget.reserve("BP-01-unwrapped", "model", 100);
  report.mode = "real";
  report.budget = budget.snapshot();
  const real = renderPairedReport(report);
  assert.match(real, /BP-01 \| unwrapped \| model \| partial \| 1 \/ 2 \| 0 \| 17 \| 0 \| 0 \| 0/);
  assert.match(real, /BP-01 \| wrapped-default \| inspection \| not-observed \| 0 \/ 0 \| 0 \| unknown/);
  assert.match(real, /not whole-run totals/);
  const subscription = new SubscriptionBudget();
  const subscriptionId = subscription.reserve("BP-01-unwrapped", "model", { model: PAID_MODEL, max_tokens: 4096 }, false);
  subscription.settle(subscriptionId, { input_tokens: 19, output_tokens: 5 }, 200);
  report.mode = "subscription";
  delete report.budget;
  report.subscription = subscription.snapshot();
  const sub = renderPairedReport(report);
  assert.match(sub, /BP-01 \| unwrapped \| model \| complete \| 1 \/ 1 \| 0 \| 19 \| 0 \| 0 \| 5/);
  assert.match(sub, /1\/120 requests/);
  assert.match(sub, /Dollar charges and remaining account quota are unknown/);
  assert.doesNotMatch(sub, /Batch token-cost upper bound/);
});
