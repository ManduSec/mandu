/** Benign-only paired evaluation CLI. Preparation is the zero-call default. */
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { runPaired } from "./lib/paired/paired-runner.js";
import type { PairMode } from "./lib/paired/paired-config.js";
import { outputBanner, resolveEvalOut } from "./lib/eval-out.js";

const usage = `Usage: npm run eval:paired -- --model FIXED_ID --inspection-model FIXED_ID [--out /tmp/new-run] [--mode prepare|scripted|real|subscription] [--agent /path/to/claude] [--timeout-ms 120000]
Output: a new run dir under ~/.mandu/runs/eval (MANDU_HOME moves it) unless --out names one; either way it must not exist yet.
Default: prepare (no model calls). Scripted: real CLI with local prescribed replies.
Subscription mode uses the existing Claude Pro/Max CLI login on both channels (no API key).
Real-model API mode requires --approval /path/to/approved.json and ANTHROPIC_API_KEY.
Preparation writes an unapproved proposal. Never approve it without the maintainer's authorization.`;

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("--help")) { console.log(usage); return; }
  const values: Record<string, string> = {};
  const allowed = new Set(["--out", "--model", "--inspection-model", "--mode", "--agent", "--timeout-ms", "--approval"]);
  for (let i = 0; i < args.length; i += 2) {
    if (!allowed.has(args[i]) || !args[i + 1] || args[i + 1].startsWith("--") || args[i] in values) throw new Error(`Invalid or duplicate argument: ${args[i]}`);
    values[args[i]] = args[i + 1];
  }
  if (!values["--model"] || !values["--inspection-model"]) throw new Error(usage);
  const mode = values["--mode"] ?? "prepare";
  if (!["prepare", "scripted", "real", "subscription"].includes(mode)) throw new Error("Invalid mode");
  const out = resolveEvalOut(values["--out"], "paired");
  console.log(outputBanner(out));
  const report = await runPaired({
    agentBinary: values["--agent"] ?? "claude", model: values["--model"], inspectionModel: values["--inspection-model"],
    repoRoot: resolve(dirname(fileURLToPath(import.meta.url)), ".."), timeoutMs: Number(values["--timeout-ms"] ?? 120000),
    // The paired eval measures the INTEGRITY invariant (its markers must never
    // reach the privileged model), so its wrapped leg runs the paper's defense.
    wrappedMode: "injection",
  }, mode as PairMode, out.dir, values["--approval"] ? JSON.parse(readFileSync(values["--approval"], "utf8")) : undefined);
  console.log(`Report: ${join(out.dir, "report.md")}`);
  if (mode !== "prepare" && report.results.some((r) => r.status !== "pass")) process.exitCode = 1;
}
main().catch((e) => { console.error(String(e)); process.exitCode = 2; });
