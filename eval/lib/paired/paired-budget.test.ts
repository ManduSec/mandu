import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { approvalProposal, validateApproval, consumeApproval, BatchBudget, PAID_MODEL, summarizeUsage } from "./paired-budget.js";
import { approvedBody, replyUsage } from "./paired-provider.js";

const now = Date.parse("2026-09-11T09:00:00Z");
const config = { model: PAID_MODEL, inspectionModel: PAID_MODEL, timeoutMs: 120000, repoRoot: "/unused", agentBinary: "/unused" };
const approved = () => ({ ...approvalProposal(now), approved: true });

test("approval binds task digest, fixed models, expiry, and positive limits", () => {
  assert.throws(() => validateApproval(approvalProposal(now), config, now), /separate budget/);
  assert.deepEqual(validateApproval(approved(), config, now).model, PAID_MODEL);
  assert.throws(() => validateApproval({ ...approved(), apiKey: "must-not-persist" }, config, now), /Unexpected approval fields/);
  for (const change of [{ suiteDigest: "different" }, { rollouts: 7 }, { expiresAt: "invalid" }, { expiresAt: new Date(now).toISOString() }, { maxRequests: NaN }, { maxOutputTokens: -1 }, { maxUsd: Infinity }, { maxLegMs: 1 }, { rateRevision: "unknown" }, { model: "haiku" }]) {
    assert.throws(() => validateApproval({ ...approved(), ...change }, config, now));
  }
  assert.throws(() => validateApproval(approved(), config, Date.parse("2026-09-19")), /Pricing review expired/);
});

test("approval IDs are consumed atomically and cannot be reused", () => {
  const dir = mkdtempSync(join(tmpdir(), "paired-approval-"));
  try {
    const a = approved(); consumeApproval(a, dir, "/first");
    assert.throws(() => consumeApproval(structuredClone(a), dir, "/second"), /EEXIST/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("the approval registry is the path table's paired-approvals, under MANDU_HOME", async () => {
  const { pairedApprovalsDir } = await import("./paired-runner.js");
  assert.equal(pairedApprovalsDir({}, "/home/u"), "/home/u/.mandu/state/paired-approvals");
  assert.equal(pairedApprovalsDir({ MANDU_HOME: "" }, "/home/u"), "/home/u/.mandu/state/paired-approvals");
  assert.equal(pairedApprovalsDir({ MANDU_HOME: "/m" }, "/home/u"), "/m/state/paired-approvals");
  assert.equal(pairedApprovalsDir({ XDG_STATE_HOME: "/xdg/state" }, "/home/u"), "/home/u/.mandu/state/paired-approvals", "XDG roots no longer move it");
});

test("main and inspection reserve against one budget before settling", () => {
  const a = { ...approved(), maxUsd: 0.85 };
  const budget = new BatchBudget(a, () => now);
  const first = budget.reserve("one", "model", 4096);
  const second = budget.reserve("one", "inspection", 4096);
  assert.equal(budget.snapshot().upperBoundUsd, 0.84096);
  assert.throws(() => budget.reserve("one", "inspection", 4096), /Insufficient budget/);
  budget.settle(first, { input_tokens: 100, output_tokens: 10, cache_creation_input_tokens: 1000, cache_read_input_tokens: 10000 });
  budget.settle(second, { input_tokens: 100, output_tokens: 10 });
  assert.equal(budget.snapshot().upperBoundUsd, 0.0225);
  assert.throws(() => budget.reserve("next", "model", 100), /Insufficient budget/);
});

test("unknown usage retains reservation; expired time and request caps stop both channels", () => {
  const budget = new BatchBudget(approved(), () => now);
  const id = budget.reserve("one", "model", 4096);
  budget.settle(id, { output_tokens: 1 });
  assert.equal(budget.snapshot().upperBoundUsd, 0.42048);
  assert.equal(budget.snapshot().requests[0].state, "uncertain");
  assert.throws(() => budget.reserve("one", "inspection", 1), /usage uncertain/);
  let clock = now;
  const expired = new BatchBudget(approved(), () => clock);
  clock += approved().maxBatchMs;
  assert.throws(() => expired.reserve("x", "model", 1), /deadline/);
  const capped = new BatchBudget({ ...approved(), maxRequests: 1 }, () => now);
  capped.reserve("x", "model", 1, true);
  assert.throws(() => capped.reserve("x", "inspection", 1), /request limit/);
});

test("forwarded profile caps output and refuses models or paid feature extensions", () => {
  const body = { model: PAID_MODEL, messages: [], max_tokens: 32000 };
  assert.equal(approvedBody(body, 4096, false).max_tokens, 4096);
  assert.equal(body.max_tokens, 32000);
  for (const change of [{ model: "latest" }, { service_tier: "auto" }, { speed: "fast" }, { mcp_servers: [] }, { tools: [{ type: "web_search_20250305" }] }, { thinking: { type: "enabled", budget_tokens: 8192 } }]) {
    assert.throws(() => approvedBody({ ...body, ...change }, 4096, false));
  }
  assert.throws(() => approvedBody({ ...body, context_management: { edits: [{ type: "compact_20260112" }] } }, 4096, false), /no server compaction/);
  assert.doesNotThrow(() => approvedBody({ ...body, context_management: { edits: [{ type: "clear_thinking_20251015", keep: "all" }] } }, 4096, false));
});

test("streaming usage requires a completed stream and terminal usage", () => {
  const frames = [
    { type: "message_start", message: { model: PAID_MODEL, usage: { input_tokens: 20, output_tokens: 1, cache_read_input_tokens: 100 } } },
    { type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 30 } },
    { type: "message_stop" },
  ];
  const reply = (f: unknown[]) => ({ status: 200, contentType: "text/event-stream", text: f.map((e) => `data: ${JSON.stringify(e)}\r\n\r\n`).join("") });
  assert.deepEqual(replyUsage(reply(frames), false), { input_tokens: 20, output_tokens: 30, cache_read_input_tokens: 100 });
  assert.throws(() => replyUsage(reply(frames.slice(0, -1)), false), /Incomplete/);
  assert.throws(() => replyUsage(reply([...frames, { type: "error" }]), false), /stream error/);
});

test("token summaries isolate legs/channels and exclude count estimates and unresolved requests", () => {
  const b = new BatchBudget(approved(), () => now);
  const count = b.reserve("one", "model", 1, true);
  b.settle(count, { input_tokens: 100000 });
  const first = b.reserve("one", "model", 4096);
  b.settle(first, { input_tokens: 12, cache_creation_input_tokens: 30, cache_read_input_tokens: 100, output_tokens: 9 });
  const inspection = b.reserve("one", "inspection", 4096);
  b.settle(inspection, { input_tokens: 800, output_tokens: 50 });
  const otherLeg = b.reserve("two", "model", 4096);
  b.settle(otherLeg, { input_tokens: 3000, output_tokens: 80 });
  const complete = summarizeUsage(b.snapshot(), "one", "model");
  assert.deepEqual(complete, { status: "complete", completionRequests: 1, observedResponses: 1, countRequests: 1, observedTokens: { uncachedInput: 12, cacheWrite: 30, cacheRead: 100, output: 9 } });
  assert.equal(b.snapshot().requests[count].usage, undefined);
  const unresolved = b.reserve("one", "model", 4096);
  assert.equal(summarizeUsage(b.snapshot(), "one", "model").status, "partial");
  b.uncertain(unresolved);
  const partial = summarizeUsage(b.snapshot(), "one", "model");
  assert.equal(partial.completionRequests, 2);
  assert.deepEqual(partial.observedTokens, complete.observedTokens);
  assert.deepEqual(summarizeUsage(b.snapshot(), "not-run", "model"), { status: "not-observed", completionRequests: 0, observedResponses: 0, countRequests: 0, observedTokens: null });
  assert.equal(summarizeUsage(undefined, "one", "model").observedTokens, null);
  const legacy = b.snapshot();
  legacy.requests.forEach((r) => { delete r.usage; });
  assert.equal(summarizeUsage(legacy, "one", "model").status, "partial");
  assert.equal(summarizeUsage(legacy, "one", "model").observedTokens, null);
});
