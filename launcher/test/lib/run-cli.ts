/**
 * run-cli — run the real `mandu` CLI entry (src/run.ts through tsx) in a child
 * process and collect its output.
 *
 * Why a child and not `main()` with process.stdout.write patched: node's test
 * runner reports through the same stdout. A patch held across an await (the
 * doctor's host probes, the arbiter round trips) swallows whatever the runner
 * flushes meanwhile, typically the previous test's result: the run then counts
 * one test fewer, and a failure's diagnostics vanish. A child owns its own
 * stdout. Tests that call a command function directly pass its `out` sink
 * instead (runStatus, runStop, runRevert, runWhy).
 *
 * Async on purpose: a test may serve a stand-in arbiter socket from this
 * process, which a spawnSync would starve.
 */
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PKG = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

export interface CliResult { code: number; stdout: string; stderr: string }

/** `mandu <argv>` with exactly `env` (plus this process's PATH when `env` has none). */
export function runCli(argv: string[], env: Record<string, string | undefined>): Promise<CliResult> {
  const childEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries({ PATH: process.env["PATH"], ...env })) if (v !== undefined) childEnv[k] = v;
  return new Promise((resolve, reject) => {
    const child = spawn(join(PKG, "node_modules", ".bin", "tsx"), [join(PKG, "src", "run.ts"), ...argv], {
      env: childEnv,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "", stderr = "";
    child.stdout.setEncoding("utf8").on("data", (c: string) => { stdout += c; });
    child.stderr.setEncoding("utf8").on("data", (c: string) => { stderr += c; });
    child.on("error", reject);
    child.on("close", (code, signal) => resolve({ code: code ?? (signal ? 128 : 127), stdout, stderr }));
  });
}
