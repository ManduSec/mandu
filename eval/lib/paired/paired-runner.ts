/** Three-task paired product evaluation with private per-leg state.
 * PROVENANCE: arbiter lifecycle adapted from tests/lib/launcher-live.ts;
 * invokes the existing launcher, fs-sync, proxies, and inspection server unchanged.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, readdirSync, readlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { homedir } from "node:os";
import { manduPath } from "../generated/mandu-paths.js";
import { SMOKE_TASKS, TASK_SUITE_DIGEST, checkTask, digest, type SmokeTask } from "./paired-tasks.js";
import { launchSpec, pairOrder, wrappedAxes, type PairConfig, type PairMode, type PairSide } from "./paired-config.js";
import { legWorkBase, openLegWork } from "./leg-work.js";
import { startScriptedObserver } from "./paired-observer.js";
import { checkEvidence, renderPairedReport, type PairedReport, type PairResult } from "./paired-report.js";
import { runCaptured } from "./paired-process.js";
import type { TlsMaterial } from "../tls.js";
import { approvalProposal, validateApproval, consumeApproval, BatchBudget } from "./paired-budget.js";
import { startBudgetObserver, providerTransport, type ProviderTransport } from "./paired-provider.js";
import { SubscriptionBudget, SUBSCRIPTION_LIMITS, isolatedSubscriptionLogin, checkSubscriptionLogin, startSubscriptionObserver } from "./paired-subscription.js";
import { PAID_MODEL } from "./paired-budget.js";
import { analyzeReport, renderAnalysis, toolObservations } from "./paired-analysis.js";

/** The single-use approval registry: the path table's `paired-approvals`
 *  (docs/design/architecture/on-disk-layout.md §5). */
export function pairedApprovalsDir(env: NodeJS.ProcessEnv = process.env, home = homedir()): string {
  return manduPath("paired-approvals", env, home);
}

export function save(path: string, value: unknown): void { writeFileSync(path, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 }); }

/** Hash source bytes without persisting file contents; ignored credentials/artifacts excluded. */
export function sourceIdentity(repoRoot: string): { sourceDigest: string; workingTreeDirty: boolean } {
  const files = execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { cwd: repoRoot }).toString().split("\0").filter(Boolean);
  const hash = createHash("sha256");
  for (const name of [...new Set(files)].sort()) {
    hash.update(name + "\0");
    try {
      const path = join(repoRoot, name);
      const st = lstatSync(path);
      hash.update(String(st.mode) + "\0");
      if (st.isSymbolicLink()) hash.update(readlinkSync(path));
      else if (st.isFile()) hash.update(readFileSync(path));
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
      hash.update("deleted");
    }
    hash.update("\0");
  }
  return { sourceDigest: hash.digest("hex"), workingTreeDirty: execFileSync("git", ["status", "--porcelain"], { cwd: repoRoot }).length > 0 };
}

export function stage(task: Pick<SmokeTask, "inputs">, workspace: string): void {
  for (const [name, text] of Object.entries(task.inputs)) {
    if (!name || name.startsWith("/") || name.split("/").some((part) => !part || part === "." || part === "..")) throw new Error("Invalid fixture path");
    const file = join(workspace, name);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, text);
  }
  const env = { PATH: process.env.PATH, HOME: workspace, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_AUTHOR_NAME: "Mandu evaluation", GIT_AUTHOR_EMAIL: "eval@example.invalid", GIT_COMMITTER_NAME: "Mandu evaluation", GIT_COMMITTER_EMAIL: "eval@example.invalid" };
  for (const args of [["init", "-q"], ["add", "--", ...Object.keys(task.inputs)], ["-c", "commit.gpgsign=false", "commit", "-qm", "benign input snapshot"]]) {
    execFileSync("git", args, { cwd: workspace, env, stdio: "pipe", timeout: 10_000 });
  }
}

export function readEvents(dir: string): Record<string, any>[] {
  const all: Record<string, any>[] = [];
  try {
    for (const name of readdirSync(dir)) {
      if (!name.endsWith(".ndjson")) continue;
      for (const line of readFileSync(join(dir, name), "utf8").split("\n").filter(Boolean)) all.push(JSON.parse(line));
    }
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
  return all;
}

export function tlsMaterial(root: string): TlsMaterial {
  const cert = join(root, "observer-cert.pem");
  const key = join(root, "observer-key.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=mandu-benign-eval", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", key, "-out", cert], { stdio: "pipe", timeout: 20_000 });
  return { cert: readFileSync(cert), key: readFileSync(key) };
}

function pending(task: SmokeTask, side: PairSide, artifactDir: string): PairResult {
  return { taskId: task.id, side, status: "not-run", durationMs: null, exitCode: null, reason: "Not executed", checks: [], evidence: { status: "incomplete", checks: [] }, modelRequests: 0, inspectionRequests: 0, costUsd: null, artifactDir };
}

/** Missing boundary evidence must stop real calls even when objective checks
 * also failed. Utility failure alone, with complete boundary evidence, does not. */
export function realModelStopReason(result: Pick<PairResult, 'status' | 'evidence'>): string | null {
  if (result.evidence.status === 'fail') return 'Model boundary violation; no additional real-model legs started';
  if (result.status === 'incomplete' || result.evidence.status === 'incomplete') return 'Incomplete rollout; no additional real-model legs started';
  return null;
}

async function executeLeg(config: PairConfig, task: SmokeTask, side: PairSide, root: string, tls: TlsMaterial, certPath: string, paid?: { budget: BatchBudget; send: ProviderTransport }, subscription?: SubscriptionBudget): Promise<PairResult> {
  const result = pending(task, side, root);
  const start = (channel: "model" | "inspection") => subscription ? startSubscriptionObserver(tls, subscription, `${task.id}-${side}`, channel) : paid ? startBudgetObserver(tls, paid.budget, `${task.id}-${side}`, channel, paid.send) : startScriptedObserver(tls, task, side, channel);
  // Only results go under `root`; the agent works in a short dir outside
  // every Mandu home (leg-work.ts), copied back by close() below.
  const work = openLegWork(root);
  const paths = work.paths;
  let model: Awaited<ReturnType<typeof start>>;
  try {
    stage(task, paths.workspace);
    model = await start("model");
  } catch (e) { work.close(); throw e; }
  let login: ReturnType<typeof isolatedSubscriptionLogin> | undefined;
  let inspection: Awaited<ReturnType<typeof start>> | undefined;
  let arbiter: { listen(): Promise<void>; close(): Promise<void> } | undefined;
  try {
    inspection = await start("inspection");
    const sock = paths.sock;
    if (side === "wrapped-default") {
      // Runtime cross-package adapter follows eval's standalone typecheck convention.
      const { ArbiterServer } = await import(pathToFileURL(join(config.repoRoot, "arbiter/ipc/server.ts")).href);
      arbiter = new ArbiterServer({ socketPath: sock, dbPath: join(paths.root, "symbols.sqlite"), eventDir: join(paths.root, "events"), tenant: "test", ...wrappedAxes(config.wrappedMode), policyDocument: null, log: () => {} });
      await arbiter!.listen();
    }
    const spec = launchSpec(config, side, paths, task.prompt, { model: model.origin, inspection: inspection.origin, arbiterSock: sock });
    spec.env.NODE_EXTRA_CA_CERTS = certPath;
    if (subscription) {
      login = isolatedSubscriptionLogin();
      spec.env.CLAUDE_CONFIG_DIR = login.configDir;
      checkSubscriptionLogin(config.agentBinary, spec.env, paths.workspace);
    }
    save(join(paths.root, "launch.json"), spec);
    const processResult = await runCaptured(spec, paths.workspace, (subscription || paid) ? Math.max(1, Math.min(config.timeoutMs, (subscription ?? paid!.budget).remainingMs())) : config.timeoutMs);
    save(join(paths.root, "process.json"), processResult);
    // close flushes event coalescers; child services have already stopped on normal exit.
    if (arbiter) { await arbiter.close(); arbiter = undefined; }
    await model.close();
    await inspection.close();
    const requests = [...model.requests, ...inspection.requests];
    const events = readEvents(join(paths.root, "events"));
    save(join(paths.root, "requests.json"), requests);
    save(join(paths.root, "events.json"), events);
    result.checks = checkTask(task, paths.workspace);
    result.evidence = checkEvidence(task, side, requests, events);
    result.durationMs = processResult.durationMs;
    result.exitCode = processResult.code;
    result.modelRequests = model.requests.length;
    result.inspectionRequests = inspection.requests.length;
    result.costUsd = (paid || subscription) ? null : 0;
    if (paid) result.costUpperBoundUsd = paid.budget.snapshot().requests.filter((r) => r.leg === `${task.id}-${side}`).reduce((s, r) => s + r.upperMicroUsd, 0) / 1e6;
    const errors = [...model.errors, ...inspection.errors];
    if (processResult.timedOut || processResult.truncated || processResult.error || errors.length) {
      result.status = "incomplete";
      result.reason = JSON.stringify({ timedOut: processResult.timedOut, truncated: processResult.truncated, error: processResult.error, observerErrors: errors });
    } else if (result.evidence.status === "fail") {
      result.status = "fail"; result.reason = "Model boundary violation";
    } else if (processResult.code !== 0 || !result.checks.every((c) => c.passed)) {
      result.status = "fail"; result.reason = "Process or objective acceptance checks failed";
    } else if (result.evidence.status !== "pass") {
      result.status = "incomplete"; result.reason = "Required path/posture evidence missing";
    } else { result.status = "pass"; result.reason = null; }
  } finally {
    login?.close();
    if (arbiter) await arbiter.close();
    await model.close();
    if (inspection) await inspection.close();
    // Retain partial capture even when setup, process collection, or checks fail.
    const captured = [...model.requests, ...(inspection?.requests ?? [])];
    save(join(paths.root, "requests.json"), captured);
    save(join(paths.root, "trajectory.json"), toolObservations(captured));
    save(join(paths.root, "observer-errors.json"), [...model.errors, ...(inspection?.errors ?? [])]);
    if (paid) save(join(paths.root, "receipts.json"), [...("receipts" in model ? model.receipts as unknown[] : []), ...(inspection && "receipts" in inspection ? inspection.receipts as unknown[] : [])]);
    const skipped = work.close();
    if (skipped.length) save(join(paths.root, "work-retain-errors.json"), skipped);
  }
  return result;
}

export function reviewPacket(config: PairConfig): string {
  const lines = ["# Manual review packet", "", `Suite digest: \`${TASK_SUITE_DIGEST}\``, "", "These tasks are candidates. Review the prompts, inputs, and exact acceptance values before approving a real-model batch. Scripted results are harness checks only.", "", `Requested models: ${config.model} (agent), ${config.inspectionModel} (inspection).`, "", "The sibling approval.json is an UNAPPROVED proposal: six rollouts, pinned Haiku 4.5 for both channels, $5 conservative token-cost ceiling, 120 total provider requests, 4096 output tokens per call, up to 180 seconds per leg and 20 minutes overall. Review its exact expiry. Both channels share reservations; missing usage stops execution. Rates expire 2026-09-18. Only explicit maintainer authorization permits changing approved to true. Never put a credential in this file. The API budget is separate from the coding assistant's subscription usage.", ""];
  for (const task of SMOKE_TASKS) {
    lines.push(`## ${task.id}: ${task.title}`, "", task.prompt, "", `Task/check digest: \`${digest(task)}\``, "");
    for (const [name, text] of Object.entries(task.inputs)) lines.push(`Input: ${name}`, "", "```json", text.trimEnd(), "```", "");
    lines.push(`Expected ${task.outputPath}:`, "", "```json", JSON.stringify(task.expected, null, 2), "```", "");
  }
  lines.push("## Before paid execution", "", "- Approve or amend the task/check digest.", "- Select fixed agent and inspection model ids and authorize a separate batch budget covering both channels.", "- Review per-run limits and the first six-rollout batch; no retries are implicit.", "", "## After execution", "", "- Read report.md; investigate every failure and incomplete leg.", "- Inspect each workspace/result.json and confirm source files are unchanged.", "- Compare launch.json between paired legs: same agent arguments, default protections and MCP only on the wrapped leg.", "- Inspect requests.json: raw benign markers in baseline tool results; only opaque symbols in wrapped model requests; original data confined to inspection requests.", "- Inspect events.json for successful inspection and launch posture, including dropped rungs.", "- Review process.json for tool failures, denials, timeouts, and the final human-visible response.", "- Record accept/reject and reasons in a separate manual-notes.md. No automated score substitutes for this decision.", "", "Artifacts contain synthetic HumanView originals and local paths. Keep the run directory private; do not upload raw diagnostics from real work.");
  if (config.subscription) {
    const start = lines.findIndex((l) => l.startsWith("The sibling approval.json"));
    lines[start] = "Subscription execution explicitly requested by the operator: six rollouts, pinned Haiku 4.5 on both first-party CLI channels, 120 requests, 4096 output tokens per call, 180 seconds per leg, 20 minutes overall. Consumes subscription allowance; dollar cost and remaining account quota are unknown. No API-key fallback. See authorization.json and subscription.json.";
    const before = lines.indexOf("## Before paid execution");
    lines.splice(before, 6, "## Subscription authorization", "", "The operator selected subscription mode for this batch. The original API-key proposal does not apply. Task definitions and objective checks remain unchanged.", "");
  }
  return lines.join("\n") + "\n";
}

export async function runPaired(config: PairConfig, mode: PairMode, outDir: string, approvalValue?: unknown): Promise<PairedReport> {
  if (!config.model || !config.inspectionModel || !Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 1) throw new Error("Explicit models and a positive timeout are required");
  if (mode === "subscription") {
    if (config.model !== PAID_MODEL || config.inspectionModel !== PAID_MODEL || config.timeoutMs > SUBSCRIPTION_LIMITS.maxLegMs) throw new Error("Subscription smoke requires pinned Haiku 4.5 and at most 180 seconds per leg");
    config = { ...config, subscription: true };
  } else if (config.subscription) throw new Error("Subscription configuration requires subscription mode");
  const approval = mode === "real" ? validateApproval(approvalValue, config) : undefined;
  if (approval && !process.env.ANTHROPIC_API_KEY) throw new Error("ANTHROPIC_API_KEY is required in the runner environment; do not put a key in approval.json");
  const out = resolve(outDir);
  // Each leg's agent works in a short dir outside every Mandu home
  // (leg-work.ts); refuse before any artifact when there is none.
  if (mode !== "prepare") legWorkBase();
  // No overwrite: each run is its own evidence record.
  mkdirSync(out, { mode: 0o700 });
  // Single use includes failed/interrupted batches; resumption needs fresh approval.
  if (approval) consumeApproval(approval, pairedApprovalsDir(), out);
  const budget = approval ? new BatchBudget(approval, () => Date.now(), (s) => save(join(out, "budget.json"), s)) : undefined;
  const paid = budget ? { budget, send: providerTransport(process.env.ANTHROPIC_API_KEY!) } : undefined;
  const subscription = mode === "subscription" ? new SubscriptionBudget((s) => save(join(out, "subscription.json"), s)) : undefined;
  const gate = subscription ?? budget;
  let version = "unavailable";
  try { version = execFileSync(config.agentBinary, ["--version"], { encoding: "utf8", timeout: 10_000 }).trim(); } catch { /* recorded; attempts remain visible */ }
  const revision = execFileSync("git", ["rev-parse", "HEAD"], { cwd: config.repoRoot, encoding: "utf8" }).trim();
  const report: PairedReport = { schemaVersion: 1, mode, createdAt: new Date().toISOString(), suiteDigest: TASK_SUITE_DIGEST, agentVersion: version, revision, ...sourceIdentity(config.repoRoot), config, results: [] };
  const flush = () => {
    if (subscription) { report.subscription = subscription.snapshot(); save(join(out, "subscription.json"), report.subscription); }
    if (budget) { report.budget = budget.snapshot(); save(join(out, "budget.json"), report.budget); }
    save(join(out, "report.json"), report);
    writeFileSync(join(out, "report.md"), renderPairedReport(report), { mode: 0o600 });
    const analysis = analyzeReport(report);
    save(join(out, "analysis.json"), analysis);
    writeFileSync(join(out, "ANALYSIS.md"), renderAnalysis(analysis), { mode: 0o600 });
  };
  writeFileSync(join(out, "REVIEW.md"), reviewPacket(config), { mode: 0o600 });
  save(join(out, "tasks.json"), SMOKE_TASKS);
  if (subscription) save(join(out, "authorization.json"), { mode, suiteDigest: TASK_SUITE_DIGEST, models: [config.model, config.inspectionModel], limits: SUBSCRIPTION_LIMITS, basis: "Explicit subscription-mode invocation; uses existing Claude login, no API-key budget" });
  else save(join(out, "approval.json"), approval ?? approvalProposal());
  for (const [i, task] of SMOKE_TASKS.entries()) for (const side of pairOrder(i)) report.results.push(pending(task, side, join(out, `${task.id}-${side}`)));
  flush();
  const tls = mode !== "prepare" ? tlsMaterial(out) : undefined;
  for (let i = 0; i < report.results.length; i++) {
    const row = report.results[i];
    const task = SMOKE_TASKS.find((t) => t.id === row.taskId)!;
    if (gate && (!gate.remainingMs() || gate.snapshot().stopped)) {
      report.results[i].reason = gate.snapshot().stopped ?? "Batch deadline reached"; flush(); continue;
    }
    if (mode === "prepare") {
      // No agent runs: the staged inputs are a preview for review, in the results dir.
      mkdirSync(join(row.artifactDir, "workspace"), { recursive: true, mode: 0o700 });
      stage(task, join(row.artifactDir, "workspace"));
      continue;
    }
    report.results[i] = { ...row, status: "incomplete", reason: "Started; no completed result recorded" };
    flush();
    try {
      report.results[i] = await executeLeg(config, task, row.side, row.artifactDir, tls!, join(out, "observer-cert.pem"), paid, subscription);
    } catch (e) {
      report.results[i] = { ...row, status: "incomplete", reason: String(e) };
    }
    const stop = realModelStopReason(report.results[i]);
    if (gate && stop) gate.stop(stop);
    flush();
  }
  flush();
  return report;
}
