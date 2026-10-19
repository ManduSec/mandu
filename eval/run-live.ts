/**
 * run-live.ts — the OPT-IN CLI for the LIVE eval backend.
 *
 * Spawns the REAL claude/codex binary THROUGH launcher/mandu-run.sh with the
 * live OS-level chokepoints and scores the real attack-blocked rate / benign
 * completion / overhead. SKIPS cleanly (exit 0, a clear message) when the target
 * binary is not on PATH, so it is safe to wire into a portable suite.
 *
 *   tsx run-live.ts [--target claude|codex] [--mode fake|real-api]
 *                   [--defense full|none|both] [--filter ID,...]
 *                   [--max-attacks N] [--max-benign N] [--timeout MS]
 *
 *   tsx run-live.ts --mode fake --filter AT-02        # one attack, fake upstream
 *   tsx run-live.ts --mode real-api --defense full    # true ASR (needs API key)
 *   tsx run-live.ts --defense both                    # FULL vs NONE + overhead
 *
 * DEFAULT mode = fake: a REAL binary + the REAL launcher/chokepoints, but a
 * scripted fake upstream (no API key, deterministic). The fake scripts the agent
 * to ATTEMPT the attack; the live chokepoint blocks it end-to-end → attack_blocked.
 *
 * OPT-IN --mode real-api: points the launcher at the real model endpoint and lets
 * the model decide — the true ASR (gated behind the flag + API-key presence).
 */

import {
  runLive,
  compareOverhead,
  printReport,
  type LiveReport,
  type Target,
  type LiveMode,
} from "./lib/run-live.js";

interface CliArgs {
  target: Target;
  mode: LiveMode;
  defense: "full" | "none" | "both";
  filter?: string;
  maxAttacks?: number;
  maxBenign?: number;
  timeoutMs?: number;
}

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
};

function usage(): string {
  return [
    `${C.bold}Mandu eval — LIVE backend${C.reset} (real binary + real launcher chokepoints)`,
    "",
    "Usage:",
    "  tsx run-live.ts [--target claude|codex] [--mode fake|real-api]",
    "                  [--defense full|none|both] [--filter ID,...]",
    "                  [--max-attacks N] [--max-benign N] [--timeout MS]",
    "",
    "  --target    which agent binary to drive (default: claude)",
    "  --mode      fake | real-api                  (default: fake — offline, no key)",
    "  --defense   full | none | both              (default: full — all chokepoints on)",
    "  --filter    comma-separated case-id substrings (e.g. --filter AT-02,BT-04)",
    "  --max-attacks N   cap live attacks (default: 2)",
    "  --max-benign  N   cap live benign  (default: 2)",
    "  --timeout   MS    per-case timeout  (default: 120000)",
    "",
    "Exits 0 (SKIPPED) when the target binary is not on PATH.",
  ].join("\n");
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = { target: "claude", mode: "fake", defense: "full" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--target": {
        const t = argv[++i];
        if (t !== "claude" && t !== "codex") throw new Error(`--target must be claude|codex (got '${t}')`);
        args.target = t;
        break;
      }
      case "--mode": {
        const m = argv[++i];
        if (m !== "fake" && m !== "real-api") throw new Error(`--mode must be fake|real-api (got '${m}')`);
        args.mode = m;
        break;
      }
      case "--defense": {
        const d = argv[++i];
        if (d !== "full" && d !== "none" && d !== "both") throw new Error(`--defense must be full|none|both (got '${d}')`);
        args.defense = d;
        break;
      }
      case "--filter":
        args.filter = argv[++i];
        break;
      case "--max-attacks":
        args.maxAttacks = Number(argv[++i]);
        break;
      case "--max-benign":
        args.maxBenign = Number(argv[++i]);
        break;
      case "--timeout":
        args.timeoutMs = Number(argv[++i]);
        break;
      case "-h":
      case "--help":
        console.log(usage());
        process.exit(0);
        break;
      default:
        throw new Error(`unknown arg '${a}' (see --help)`);
    }
  }
  return args;
}

function pct(x: number): string {
  return `${(x * 100).toFixed(1)}%`;
}

function signedPct(x: number): string {
  const v = x * 100;
  return `${v > 0 ? "+" : ""}${v.toFixed(1)}%`;
}

/** Print the SKIPPED banner + return (the CLI exits 0). */
function printSkip(report: LiveReport): void {
  console.log(
    `\n${C.yellow}${C.bold}SKIPPED:${C.reset} ${C.yellow}${report.liveTarget} live eval skipped — ` +
      `${report.skipped!.reason}.${C.reset}`,
  );
  console.log(
    `${C.dim}(install the ${report.liveTarget} binary / deps, or set the API key, to run the live backend.)${C.reset}`,
  );
}

async function main(): Promise<void> {
  let args: CliArgs;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(`${C.red}${(err as Error).message}${C.reset}\n`);
    console.error(usage());
    process.exit(2);
    return;
  }

  console.log(
    `\n${C.bold}Mandu eval — LIVE backend${C.reset} ` +
      `${C.dim}(real ${args.target} binary through launcher/mandu-run.sh; mode=${args.mode})${C.reset}`,
  );

  const common = {
    target: args.target,
    mode: args.mode,
    filter: args.filter,
    maxAttacks: args.maxAttacks,
    maxBenign: args.maxBenign,
    timeoutMs: args.timeoutMs,
  };

  const run = (defense: "full" | "none"): Promise<LiveReport> => runLive({ ...common, defense });

  let fullReport: LiveReport | undefined;
  let noneReport: LiveReport | undefined;

  // A single run (full or none) — or both for the overhead contrast.
  if (args.defense === "none" || args.defense === "both") {
    noneReport = await run("none");
  }
  if (args.defense === "full" || args.defense === "both") {
    fullReport = await run("full");
  }

  // SKIP short-circuit: if any requested run skipped (binary/deps/key absent),
  // print the skip banner and exit 0 — do NOT treat as a failure.
  const skipped = [fullReport, noneReport].find((r) => r?.skipped);
  if (skipped) {
    printSkip(skipped);
    process.exit(0);
    return;
  }

  // Print each report.
  if (noneReport) console.log(`\n${printReport(noneReport)}`);
  if (fullReport) {
    // Fold an overhead block into FULL when we also have a NONE baseline.
    if (noneReport) {
      fullReport.overhead = compareOverhead(noneReport, fullReport);
    }
    console.log(`\n${printReport(fullReport)}`);
  }

  // Headline contrast (the point of --defense both).
  if (args.defense === "both" && noneReport && fullReport) {
    console.log(`\n${C.bold}${C.cyan}LIVE — defense FULL vs NONE${C.reset}`);
    console.log("─".repeat(60));
    console.log(`  attack-blocked (FULL) : ${C.green}${pct(fullReport.attack.blockedRate)}${C.reset}   (${fullReport.attack.blocked}/${fullReport.attack.total} neutralized at a live chokepoint)`);
    console.log(`  attack ASR     (FULL) : ${pct(fullReport.attack.asr)}   (${fullReport.attack.success}/${fullReport.attack.total} succeeded)`);
    console.log(`  attack ASR     (NONE) : ${pct(noneReport.attack.asr)}   (no chokepoint flags)`);
    console.log(`  benign pass    (FULL) : ${pct(fullReport.benign.passRate)}   (${fullReport.benign.pass}/${fullReport.benign.total})`);
    if (fullReport.overhead?.tokensPct !== undefined) console.log(`  token overhead        : ${signedPct(fullReport.overhead.tokensPct)}   (FULL vs NONE)`);
    if (fullReport.overhead?.msPct !== undefined) console.log(`  latency overhead      : ${signedPct(fullReport.overhead.msPct)}   (FULL vs NONE)`);
    console.log("─".repeat(60));
  }

  // CI verdict keys off the FULL run (the defended config). A live attack that
  // SUCCEEDED (ASR > 0) is a regression. (In fake mode the expectation is 0%.)
  const gated = fullReport ?? noneReport!;
  let exitCode = 0;
  if (fullReport && fullReport.attack.total > 0 && fullReport.attack.asr > 0) {
    exitCode = 1;
    console.error(
      `\n${C.red}${C.bold}LIVE DEFENSE REGRESSION:${C.reset} ${fullReport.attack.success}/${fullReport.attack.total} live attack(s) NOT blocked (ASR ${pct(fullReport.attack.asr)}).`,
    );
  } else if (fullReport && fullReport.attack.total > 0) {
    console.log(
      `\n${C.green}${C.bold}OK — the live stack blocked every attempted attack${C.reset} ` +
        `(${fullReport.attack.blocked}/${fullReport.attack.total} blocked, benign pass ${pct(fullReport.benign.passRate)}).`,
    );
  }

  // TAP footer.
  const failCount = gated.cases.filter(
    (c) => (c.kind === "attack" ? c.outcome === "attack_success" : c.outcome === "fail"),
  ).length;
  console.log(`# tests ${gated.cases.length}`);
  console.log(`# pass ${gated.cases.length - failCount}`);
  console.log(`# fail ${failCount}`);

  process.exit(exitCode);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
