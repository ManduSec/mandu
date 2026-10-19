/** Shared, synchronous reservation ledger for the benign six-rollout batch.
 * PROVENANCE: NEW Mandu code; contract in evaluation.md §3.
 * Rates/capacity verified against Anthropic's Haiku 4.5 docs on 2026-09-11.
 */
import { randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { PairConfig } from "./paired-config.js";
import { TASK_SUITE_DIGEST } from "./paired-tasks.js";

export const PAID_MODEL = "claude-haiku-4-5-20251001";
export const RATE_REVISION = "haiku-4.5-global-standard-2026-09-11";
const RATE_EXPIRY = Date.parse("2026-09-18T00:00:00Z");
const CONTEXT = 200_000;
// Integer microdollars: maximum input rate includes one-hour cache writes.
const INPUT_MICRO = 2;
const OUTPUT_MICRO = 5;

export interface BatchApproval {
  schemaVersion: 1;
  approved: boolean;
  id: string;
  suiteDigest: string;
  model: string;
  inspectionModel: string;
  rateRevision: string;
  expiresAt: string;
  maxUsd: number;
  maxRequests: number;
  maxOutputTokens: number;
  maxBatchMs: number;
  maxLegMs: number;
  rollouts: 6;
}

/** A proposal is never an authorization. Only the maintainer may approve it. */
export function approvalProposal(now = Date.now()): BatchApproval {
  return { schemaVersion: 1, approved: false, id: randomUUID(), suiteDigest: TASK_SUITE_DIGEST,
    model: PAID_MODEL, inspectionModel: PAID_MODEL, rateRevision: RATE_REVISION,
    expiresAt: new Date(Math.min(now + 24 * 3600_000, RATE_EXPIRY)).toISOString(),
    maxUsd: 5, maxRequests: 120, maxOutputTokens: 4096, maxBatchMs: 20 * 60_000, maxLegMs: 180_000, rollouts: 6 };
}

export function validateApproval(value: unknown, config: PairConfig, now = Date.now()): BatchApproval {
  const a = value as BatchApproval | undefined;
  if (!a || a.approved !== true) throw new Error("Approve the task digest and a separate budget before real execution");
  const fields = new Set(["schemaVersion", "approved", "id", "suiteDigest", "model", "inspectionModel", "rateRevision", "expiresAt", "maxUsd", "maxRequests", "maxOutputTokens", "maxBatchMs", "maxLegMs", "rollouts"]);
  if (Object.keys(a).some((k) => !fields.has(k))) throw new Error("Unexpected approval fields; credentials do not belong in approval files");
  if (a.schemaVersion !== 1 || !/^[a-f0-9-]{36}$/.test(a.id) || a.suiteDigest !== TASK_SUITE_DIGEST || a.rollouts !== 6) throw new Error("Approval does not match the six-task-leg manifest");
  if (a.model !== PAID_MODEL || a.inspectionModel !== PAID_MODEL || config.model !== a.model || config.inspectionModel !== a.inspectionModel) throw new Error("Approval requires the supported fixed model on both channels");
  if (a.rateRevision !== RATE_REVISION || now >= RATE_EXPIRY) throw new Error("Pricing review expired; refresh the reviewed rate table before execution");
  const expiry = Date.parse(a.expiresAt);
  if (!Number.isFinite(expiry) || expiry <= now || expiry > RATE_EXPIRY) throw new Error("Invalid or expired approval deadline");
  if (!Number.isFinite(a.maxUsd) || a.maxUsd <= 0 || a.maxUsd > 100 || !Number.isSafeInteger(Math.round(a.maxUsd * 1e6))) throw new Error("Invalid batch dollar limit");
  for (const [value, cap] of [[a.maxRequests, 1000], [a.maxOutputTokens, 64000], [a.maxBatchMs, 3600_000], [a.maxLegMs, 600_000]]) {
    if (!Number.isSafeInteger(value) || value < 1 || value > cap) throw new Error("Invalid approval request/token/time limits");
  }
  if (config.timeoutMs > a.maxLegMs || a.maxLegMs > a.maxBatchMs) throw new Error("Run timeout exceeds approval");
  return structuredClone(a);
}

/** Stable per-maintainer registry makes accidental reuse/copies of an ID fail. */
export function consumeApproval(a: BatchApproval, registry: string, out: string): void {
  mkdirSync(registry, { recursive: true, mode: 0o700 });
  writeFileSync(join(registry, `${a.id}.json`), JSON.stringify({ approval: a, out, consumedAt: new Date().toISOString() }) + "\n", { flag: "wx", mode: 0o600 });
}

export interface TokenUsage {
  uncachedInput: number;
  cacheWrite: number;
  cacheRead: number;
  output: number;
}

export interface Reservation {
  id: number;
  leg: string;
  channel: "model" | "inspection";
  countOnly: boolean;
  maxOutputTokens: number;
  upperMicroUsd: number;
  state: "reserved" | "settled" | "uncertain";
  usage?: TokenUsage;
}
export interface BudgetSnapshot {
  approval: BatchApproval;
  stopped: string | null;
  upperBoundUsd: number;
  requests: Reservation[];
}

export interface UsageSummary {
  status: "not-observed" | "complete" | "partial";
  completionRequests: number;
  observedResponses: number;
  countRequests: number;
  observedTokens: TokenUsage | null;
}

/** Count-token estimates are never added to billed completion usage. Partial
 * sums describe only observed responses and cannot stand for the whole run.
 */
export function summarizeUsage(snapshot: { requests: Pick<Reservation, "leg" | "channel" | "countOnly" | "state" | "usage">[] } | undefined, leg: string, channel: Reservation["channel"]): UsageSummary {
  const entries = snapshot?.requests.filter((r) => r.leg === leg && r.channel === channel) ?? [];
  const completions = entries.filter((r) => !r.countOnly);
  const measured = completions.filter((r) => r.state === "settled" && r.usage !== undefined);
  return {
    status: completions.length === 0 ? "not-observed" : measured.length === completions.length ? "complete" : "partial",
    completionRequests: completions.length, observedResponses: measured.length,
    countRequests: entries.filter((r) => r.countOnly).length,
    observedTokens: measured.length === 0 ? null : measured.reduce((sum, r) => ({
      uncachedInput: sum.uncachedInput + r.usage!.uncachedInput,
      cacheWrite: sum.cacheWrite + r.usage!.cacheWrite,
      cacheRead: sum.cacheRead + r.usage!.cacheRead,
      output: sum.output + r.usage!.output,
    }), { uncachedInput: 0, cacheWrite: 0, cacheRead: 0, output: 0 }),
  };
}

export class BatchBudget {
  private entries: Reservation[] = [];
  private reason: string | null = null;
  readonly deadline: number;
  readonly approval: BatchApproval;
  constructor(a: BatchApproval, private now = () => Date.now(), private persist: (s: BudgetSnapshot) => void = () => {}) {
    this.approval = structuredClone(a);
    this.deadline = Math.min(Date.parse(a.expiresAt), now() + a.maxBatchMs);
  }
  remainingMs(): number { return Math.max(0, this.deadline - this.now()); }
  snapshot(): BudgetSnapshot {
    return { approval: structuredClone(this.approval), stopped: this.reason, upperBoundUsd: this.entries.reduce((s, r) => s + r.upperMicroUsd, 0) / 1e6, requests: structuredClone(this.entries) };
  }
  stop(reason: string): void { this.reason ??= reason; this.persist(this.snapshot()); }
  private deny(reason: string): never { this.stop(reason); throw new Error(reason); }
  reserve(leg: string, channel: Reservation["channel"], output: number, countOnly = false): number {
    if (this.reason) throw new Error(this.reason);
    if (!this.remainingMs()) this.deny("Batch deadline reached");
    if (this.entries.length >= this.approval.maxRequests) this.deny("Batch request limit reached");
    if (!Number.isSafeInteger(output) || output < 1 || output > this.approval.maxOutputTokens) this.deny("Output limit exceeded");
    const micro = countOnly ? 0 : CONTEXT * INPUT_MICRO + output * OUTPUT_MICRO;
    if (this.entries.reduce((s, r) => s + r.upperMicroUsd, 0) + micro > Math.floor(this.approval.maxUsd * 1e6)) this.deny("Insufficient budget for conservative request reservation");
    const id = this.entries.length;
    this.entries.push({ id, leg, channel, countOnly, maxOutputTokens: output, upperMicroUsd: micro, state: "reserved" });
    // Persist BEFORE any remote request. A crash leaves the full reservation.
    this.persist(this.snapshot());
    return id;
  }
  settle(id: number, usage: unknown): void {
    const r = this.entries[id];
    if (!r || r.state !== "reserved") this.deny("Invalid budget settlement");
    const u = usage as Record<string, unknown> | undefined;
    const valid = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
    const input = u?.input_tokens;
    const output = r.countOnly ? 0 : u?.output_tokens;
    const created = u?.cache_creation_input_tokens ?? 0;
    const read = u?.cache_read_input_tokens ?? 0;
    if (!valid(input) || !valid(output) || !valid(created) || !valid(read) || input + created + read > CONTEXT || output > r.maxOutputTokens) {
      this.uncertain(id); return;
    }
    r.upperMicroUsd = r.countOnly ? 0 : (input + created + read) * INPUT_MICRO + output * OUTPUT_MICRO;
    if (!r.countOnly) r.usage = { uncachedInput: input, cacheWrite: created, cacheRead: read, output };
    r.state = "settled";
    this.persist(this.snapshot());
  }
  uncertain(id: number): void {
    const r = this.entries[id];
    if (r?.state === "reserved") r.state = "uncertain";
    this.stop("Provider usage uncertain; retained full reservation and stopped batch");
  }
}
