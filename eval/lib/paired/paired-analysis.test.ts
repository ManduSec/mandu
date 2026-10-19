import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeReport, renderAnalysis, toolObservations } from "./paired-analysis.js";
import type { PairResult, PairedReport } from "./paired-report.js";
import type { CapturedModelRequest } from "./paired-observer.js";

function row(id: string, side: PairResult["side"]): PairResult {
  return { taskId: id, side, status: "pass", evidence: { status: "pass", checks: [] }, checks: [], durationMs: side === "unwrapped" ? 100 : 300,
    exitCode: 0, reason: null, modelRequests: 1, inspectionRequests: 0, costUsd: 0, artifactDir: `/private/${id}-${side}` };
}
function report(): PairedReport {
  return { schemaVersion: 1, mode: "scripted", createdAt: "fixed", suiteDigest: "suite", sourceDigest: "source", revision: "revision", workingTreeDirty: false, agentVersion: "test",
    config: { model: "scripted", inspectionModel: "scripted", agentBinary: "unused", repoRoot: "/unused", timeoutMs: 1 },
    results: ["A", "B", "C"].flatMap((id) => [row(id, "unwrapped"), row(id, "wrapped-default")]) };
}

test("review prioritizes every observed failure and retains pending legs without changing verdicts", () => {
  const r = report();
  r.results[0].status = "not-run";
  r.results[1].status = "incomplete";
  r.results[1].evidence = { status: "fail", checks: [{ name: "model-boundary:marker", passed: false, detail: "private-detail" }] };
  r.results[2].status = "fail";
  r.results[2].checks = [{ name: "input-preserved:source.json", passed: false, detail: "private-detail" }];
  r.results[3].status = "fail";
  r.results[3].checks = [{ name: "exact-output", passed: false, detail: "private-detail" }];
  r.results[4].status = "incomplete";
  const original = structuredClone(r);
  const a = analyzeReport(r);
  assert.deepEqual(a.queue.map((e) => e.kind), ["boundary-violation", "input-integrity", "task-failure", "incomplete", "not-run", "sampled-pass"]);
  assert.equal(a.queue[0].checkPointers[0], "/results/1/evidence/checks/0");
  assert.equal(a.latencyPairs.length, 0);
  assert.deepEqual(a.excludedLatencyTasks, ["A", "B", "C"]);
  assert.deepEqual(r, original);
  r.results[5].durationMs = 999;
  assert.notEqual(analyzeReport(r).reportDigest, a.reportDigest);
  assert.doesNotMatch(JSON.stringify(a) + renderAnalysis(a), /private-detail/);
});

test("pass sample is reproducible and paired overhead excludes unsuccessful or zero-duration attempts", () => {
  const r = report();
  const a = analyzeReport(r);
  assert.deepEqual(a, analyzeReport(structuredClone(r)));
  assert.equal(a.queue.length, 2);
  assert.deepEqual(new Set(a.queue.map((q) => q.side)), new Set(["unwrapped", "wrapped-default"]));
  assert.equal(a.latencyPairs[0].ratio, 3);
  assert.equal(a.latencyPairs[0].deltaMs, 200);
  r.results[0].durationMs = 0;
  r.results[2].status = "fail";
  assert.deepEqual(analyzeReport(r).excludedLatencyTasks, ["A", "B"]);
  assert.match(renderAnalysis(a), /No real-model performance evidence/);
});

test("trajectory deduplicates history and locates recovered errors without copying tool content", () => {
  const messages = [
    { role: "assistant", content: [{ type: "tool_use", id: "one", name: "Read", input: { file_path: "private-name" } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "one", is_error: true, content: "private-error" }] },
  ];
  const request = (m: unknown[]): CapturedModelRequest => ({ channel: "model", path: "/v1/messages", body: { messages: m } });
  const requests = [request(messages), request([...messages, { role: "assistant", content: [{ type: "tool_use", id: "two", name: "Write", input: { content: "private-output" } }] }])];
  const t = toolObservations(requests);
  assert.equal(t.length, 2);
  assert.equal(t[0].status, "error");
  assert.equal(t[0].firstError, "/0/body/messages/1/content/0");
  assert.equal(t[1].status, "missing");
  assert.doesNotMatch(JSON.stringify(t), /private-name|private-error|private-output/);
  assert.equal(JSON.parse(JSON.stringify(requests))[0].body.messages[1].content[0].is_error, true);
});

test("conflicting tool IDs or results remain explicitly ambiguous", () => {
  const requests: CapturedModelRequest[] = [{ channel: "model", path: "/v1/messages", body: { messages: [{ content: [
    { type: "tool_use", id: "x", name: "Read", input: { path: "a" } },
    { type: "tool_use", id: "x", name: "Read", input: { path: "b" } },
    { type: "tool_result", tool_use_id: "x", content: "done" },
  ] }] } }];
  assert.deepEqual(toolObservations(requests).map((t) => t.status), ["conflicting", "conflicting"]);
});


test("subscription observations are labeled real and link to subscription accounting", () => {
  const r = report();
  r.mode = "subscription";
  const text = renderAnalysis(analyzeReport(r));
  assert.doesNotMatch(text, /No real-model performance evidence/);
  assert.match(text, /observations for review/);
  assert.match(text, /subscription.json for subscription usage/);
});
