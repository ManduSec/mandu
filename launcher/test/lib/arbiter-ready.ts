/**
 * arbiter-ready.ts — how long a test waits for a daemon it started (an
 * arbiter's socket) and how that wait ends (docs/design/architecture/runtime-instances.md
 * §14.6, "Tests and the dev arbiter").
 *
 * The suites each had a fixed wait of their own (10 s, 20 s), sized on an idle
 * workstation. On a CI runner the first start of a job is the slow one: the
 * tsx cache is cold, and the job's other test files compile their own imports
 * on the same few vCPUs at the same moment. GitHub's runners showed it: the
 * first arbiter start of the launcher job took most of a 20 s wait in a green
 * run, and a few starts missed theirs now and then. The 1-minute load average
 * the product's deadline scales by lags behind a burst at a job's start, so
 * the test budget doubles on CI.
 *
 * The budget: MANDU_SERVICE_READY_TIMEOUT_MS when set (exactly, as for the
 * launcher), else the launcher's load-aware deadline (`serviceReadyDeadlineMs`:
 * 30 s idle, stretched by load per CPU, capped at 120 s), doubled when CI is
 * set. scripts/lib/ready-deadline.sh is the same rule for the shell suites
 * and scripts/dev-arbiter.sh. A long budget costs a passing run nothing (the
 * wait ends when the socket appears) and a broken start nothing (it ends when
 * the started process exits); only a hung start waits it out.
 */
import type { ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { availableParallelism, loadavg } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SERVICE_READY_ENV, serviceReadyDeadlineMs } from "../../src/services/primitives.js";

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "arbiter");

/**
 * The arbiter from source as ONE node process, the form scripts/dev-arbiter.sh
 * and the launcher use (packaging.md §5.1): `node --import <arbiter's tsx>
 * ipc/server-main.ts <sock>`, run from the arbiter package. The tsx binary
 * (node_modules/.bin/tsx) starts a node that starts another node: a second
 * cold start at the job's busiest moment. Node's argv, for
 * `spawn(process.execPath, sourceArbiterArgs(sock), { cwd: <arbiter package>, ... })`.
 */
export function sourceArbiterArgs(sock: string): string[] {
  return ["--import", join(ARBITER_DIR, "node_modules", "tsx", "dist", "esm", "index.mjs"), join(ARBITER_DIR, "ipc", "server-main.ts"), sock];
}

/** CI is set the way GitHub Actions and GitLab CI set it (`true`), and not
 *  switched off (`false`, `0`, `no`, empty). */
export function onCi(env: Record<string, string | undefined> = process.env): boolean {
  const v = (env.CI ?? "").trim().toLowerCase();
  return v !== "" && v !== "0" && v !== "false" && v !== "no";
}

/** MANDU_SERVICE_READY_TIMEOUT_MS holds a usable override (a positive
 *  integer; a garbled value is ignored, as the launcher ignores it). */
export function readyOverridden(env: Record<string, string | undefined> = process.env): boolean {
  const raw = env[SERVICE_READY_ENV]?.trim();
  return Boolean(raw && /^\d+$/.test(raw) && Number(raw) > 0);
}

/** The test readiness budget in milliseconds (the header's rule). Pure over
 *  its inputs. */
export function testReadyBudgetMs(
  env: Record<string, string | undefined> = process.env,
  host: { load1: number; ncpu: number } = { load1: loadavg()[0] ?? 0, ncpu: availableParallelism() },
): number {
  const product = serviceReadyDeadlineMs(env, host); // the override exactly, when set
  return !readyOverridden(env) && onCi(env) ? product * 2 : product;
}

export interface WaitReadyOptions {
  /** What is waited for, for the error ("the arbiter"). */
  what?: string;
  /** The started process: its exit ends the wait at once. */
  child?: ChildProcess;
  /** Its log file: the error carries the last lines. */
  logPath?: string;
  /** Or its captured output so far. */
  output?: () => string;
  /** Default: testReadyBudgetMs(). */
  budgetMs?: number;
  /** Between probes (default 100 ms). */
  pollMs?: number;
}

function tail(text: string, n = 30): string {
  return text.trimEnd().split("\n").slice(-n).join("\n");
}

function exitNote(child: ChildProcess | undefined): string | null {
  if (!child) return null;
  if (child.signalCode !== null) return `it was killed by ${child.signalCode}`;
  if (child.exitCode !== null) return `it exited with code ${child.exitCode}`;
  return null;
}

/**
 * Wait until every path in `paths` exists (a daemon's sockets). Rejects at the
 * budget, or at once when `child` has exited, with what was waited for, why
 * it ended, the time spent against the budget and the log's last lines.
 */
export async function waitForPaths(paths: string | readonly string[], o: WaitReadyOptions = {}): Promise<void> {
  const want = typeof paths === "string" ? [paths] : paths;
  const budget = o.budgetMs ?? testReadyBudgetMs();
  const poll = o.pollMs ?? 100;
  const t0 = Date.now();
  let why: string;
  for (;;) {
    const missing = want.filter((p) => !existsSync(p));
    if (missing.length === 0) return;
    const gone = exitNote(o.child);
    if (gone) { why = `${gone} before ${missing.join(", ")} appeared`; break; }
    if (Date.now() - t0 >= budget) { why = `${missing.join(", ")} not there`; break; }
    await new Promise((r) => setTimeout(r, poll));
  }
  const spent = ((Date.now() - t0) / 1000).toFixed(1);
  let log = "";
  if (o.logPath) {
    try { log = tail(readFileSync(o.logPath, "utf8")); } catch { log = ""; }
    log = log ? `\n--- ${o.logPath} (last lines) ---\n${log}` : `\n(${o.logPath} is empty or missing)`;
  } else if (o.output) {
    const out = tail(o.output());
    log = out ? `\n--- its output (last lines) ---\n${out}` : "\n(it printed nothing)";
  }
  throw new Error(
    `${o.what ?? "the daemon"} did not come up: ${why} after ${spent} s ` +
      `(budget ${(budget / 1000).toFixed(1)} s${o.budgetMs === undefined && !readyOverridden() && onCi() ? ", doubled on CI" : ""}; ${SERVICE_READY_ENV} sets it)${log}`,
  );
}
