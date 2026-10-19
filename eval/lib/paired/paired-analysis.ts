/** Evidence index for human/AI failure review; never changes outcome verdicts.
 * PROVENANCE: NEW Mandu code; release-review manual packet requirements.
 */
import type { PairedReport, PairResult } from "./paired-report.js";
import type { CapturedModelRequest } from "./paired-observer.js";
import { digest } from "./paired-tasks.js";

export interface ToolObservation {
  id: string;
  name: string;
  argumentDigest: string;
  callPointer: string;
  firstSuccess: string | null;
  firstError: string | null;
  status: "missing" | "success" | "error" | "conflicting";
}

/** Histories repeat previous calls. Index unique calls, retaining conflicting IDs.
 * Pointers address requests.json; bodies and result text are never copied here.
 */
export function toolObservations(requests: CapturedModelRequest[]): ToolObservation[] {
  const observations: ToolObservation[] = [];
  const results: { id: string; error: boolean; pointer: string }[] = [];
  requests.forEach((r, ri) => {
    if (r.channel !== "model" || r.path.includes("count_tokens") || !Array.isArray(r.body.messages)) return;
    r.body.messages.forEach((m: any, mi: number) => {
      if (!Array.isArray(m?.content)) return;
      m.content.forEach((block: any, bi: number) => {
        const pointer = `/${ri}/body/messages/${mi}/content/${bi}`;
        if (block?.type === "tool_use" && typeof block.id === "string" && typeof block.name === "string") {
          const argumentDigest = digest(block.input ?? null);
          if (!observations.some((o) => o.id === block.id && o.name === block.name && o.argumentDigest === argumentDigest)) {
            observations.push({ id: block.id, name: block.name, argumentDigest, callPointer: pointer, firstSuccess: null, firstError: null, status: "missing" });
          }
        } else if (block?.type === "tool_result" && typeof block.tool_use_id === "string") {
          results.push({ id: block.tool_use_id, error: block.is_error === true, pointer });
        }
      });
    });
  });
  for (const o of observations) {
    o.firstError = results.find((r) => r.id === o.id && r.error)?.pointer ?? null;
    o.firstSuccess = results.find((r) => r.id === o.id && !r.error)?.pointer ?? null;
    o.status = (o.firstError && o.firstSuccess) || observations.some((other) => other !== o && other.id === o.id)
      ? "conflicting" : o.firstError ? "error" : o.firstSuccess ? "success" : "missing";
  }
  return observations;
}

type ReviewKind = "boundary-violation" | "input-integrity" | "task-failure" | "incomplete" | "not-run" | "sampled-pass";
export interface ReviewEntry {
  taskId: string;
  side: PairResult["side"];
  kind: ReviewKind;
  reportPointer: string;
  checkPointers: string[];
  artifactDir: string;
}
export interface PairOverhead {
  taskId: string;
  unwrappedMs: number;
  wrappedMs: number;
  deltaMs: number;
  ratio: number;
  unwrappedPointer: string;
  wrappedPointer: string;
}
export interface ReviewAnalysis {
  schemaVersion: 1;
  mode: PairedReport["mode"];
  reportDigest: string;
  sampleSeed: string;
  plannedLegs: number;
  queue: ReviewEntry[];
  latencyPairs: PairOverhead[];
  excludedLatencyTasks: string[];
}

function kind(row: PairResult): ReviewKind | null {
  if (row.evidence.status === "fail") return "boundary-violation";
  if (row.checks.some((c) => !c.passed && /^(?:input-preserved|missing-input-preserved):/.test(c.name))) return "input-integrity";
  if (row.status === "not-run") return "not-run";
  if (row.status === "incomplete" || row.evidence.status !== "pass") return "incomplete";
  if (row.status === "fail" || row.checks.some((c) => !c.passed)) return "task-failure";
  return null;
}

export function analyzeReport(report: PairedReport): ReviewAnalysis {
  const sampleSeed = digest([report.suiteDigest, report.sourceDigest, report.createdAt]);
  const analysis: ReviewAnalysis = { schemaVersion: 1, mode: report.mode, reportDigest: digest(report), sampleSeed, plannedLegs: report.results.length, queue: [], latencyPairs: [], excludedLatencyTasks: [] };
  const add = (r: PairResult, i: number, kind: ReviewKind) => analysis.queue.push({ taskId: r.taskId, side: r.side, kind, reportPointer: `/results/${i}`,
    checkPointers: [...r.checks.flatMap((c, ci) => c.passed ? [] : [`/results/${i}/checks/${ci}`]), ...r.evidence.checks.flatMap((c, ci) => c.passed ? [] : [`/results/${i}/evidence/checks/${ci}`])], artifactDir: r.artifactDir });
  report.results.forEach((r, i) => { const k = kind(r); if (k) add(r, i, k); });
  // Reproducible pseudorandom pass sample, one per configuration. No cherry-picking.
  for (const side of ["unwrapped", "wrapped-default"] as const) {
    const candidates = report.results.map((r, i) => ({ r, i, key: digest([sampleSeed, r.taskId, side]) }))
      .filter(({ r }) => r.side === side && kind(r) === null).sort((a, b) => a.key.localeCompare(b.key));
    if (candidates[0]) add(candidates[0].r, candidates[0].i, "sampled-pass");
  }
  const priority: ReviewKind[] = ["boundary-violation", "input-integrity", "task-failure", "incomplete", "not-run", "sampled-pass"];
  analysis.queue.sort((a, b) => priority.indexOf(a.kind) - priority.indexOf(b.kind));
  for (const id of new Set(report.results.map((r) => r.taskId))) {
    const ui = report.results.findIndex((r) => r.taskId === id && r.side === "unwrapped");
    const wi = report.results.findIndex((r) => r.taskId === id && r.side === "wrapped-default");
    const u = report.results[ui]; const w = report.results[wi];
    // Failed/partial attempts cannot establish successful-completion overhead.
    if (!u || !w || kind(u) || kind(w) || !Number.isFinite(u.durationMs) || !Number.isFinite(w.durationMs) || u.durationMs! <= 0 || w.durationMs! <= 0) {
      analysis.excludedLatencyTasks.push(id); continue;
    }
    analysis.latencyPairs.push({ taskId: id, unwrappedMs: u.durationMs!, wrappedMs: w.durationMs!, deltaMs: w.durationMs! - u.durationMs!, ratio: w.durationMs! / u.durationMs!, unwrappedPointer: `/results/${ui}`, wrappedPointer: `/results/${wi}` });
  }
  analysis.latencyPairs.sort((a, b) => b.deltaMs - a.deltaMs);
  return analysis;
}

export function renderAnalysis(a: ReviewAnalysis): string {
  const lines = ["# Batch review queue", "", `Mode: **${a.mode}**. Planned legs: ${a.plannedLegs}.`, "", `Source report digest: \`${a.reportDigest}\` (SHA-256 of JSON.stringify(parsed report.json)); check this if report generation was interrupted.`, "",
    (a.mode === "real" || a.mode === "subscription") ? "These are observations for review, not root-cause diagnoses or release acceptance." : "No real-model performance evidence: prepared/scripted observations only.", "",
    "Review every failure or incomplete/not-run leg below, plus the sampled passes. Categories prioritize observed impact without changing the report's verdicts. A tool error may be expected recovery; compare it to REVIEW.md before proposing a repair.", "",
    `Pass sampling seed: \`${a.sampleSeed}\` (one reproducible pseudorandom pass per configuration).`, "", "## Queue", ""];
  for (const r of a.queue) {
    lines.push(`- ${r.taskId} / ${r.side}: **${r.kind}**. report.json pointer \`${r.reportPointer}\`; artifacts: \`${r.artifactDir}\`.`);
    if (r.checkPointers.length) lines.push(`  Failed-check pointers: ${r.checkPointers.map((p) => `\`${p}\``).join(", ")}.`);
  }
  lines.push("", "## Completion latency", "", "Pairs with both successful outcomes only, sorted by added wall time. Scripted timing is component overhead, not model utility. Observer buffering affects streaming latency. No population estimate or success target is inferred.", "",
    "| Task | Unwrapped seconds | Wrapped seconds | Added seconds | Ratio |", "| --- | --- | --- | --- | --- |");
  for (const p of a.latencyPairs) lines.push(`| ${p.taskId} | ${(p.unwrappedMs / 1000).toFixed(3)} | ${(p.wrappedMs / 1000).toFixed(3)} | ${(p.deltaMs / 1000).toFixed(3)} | ${p.ratio.toFixed(2)} |`);
  lines.push("", `Excluded tasks (missing/failed pair or unusable timing): ${a.excludedLatencyTasks.join(", ") || "none"}.`, "",
    "## Manual disposition", "",
    "For each queued leg, inspect the exact output and preserved inputs in workspace/, checker results in report.json, and process.json. Use trajectory.json pointers into requests.json to locate observed calls and the first tool error; use events.json for posture/inspection and receipts.json/budget.json for API usage or subscription.json for subscription usage. Empty or absent artifacts mean missing evidence.", "",
    "Record accept/reject/unresolved, evidence pointers, first observed deviation from the task contract, any manual intervention and time spent, proposed cause (as a hypothesis), and next check in your own manual-notes.md. Do not equate differences in the two agents' tool sequences with a defect. No notes are overwritten by the runner.", "",
    "Judge disagreements and automated root-cause judgments are not available in this exact-answer smoke suite. No judge was run. Failures must not trigger a policy relaxation or an unapproved retry.");
  return lines.join("\n") + "\n";
}
