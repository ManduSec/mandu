/**
 * launch-budget — the launch-time budget check's arithmetic
 * (runtime-instances.md §14.11): a cell's median wall time and per-step
 * medians over its runs, the recorded baseline file, and the verdict.
 *
 * A cell is one agent's `<agent> --version` launched through Mandu from one
 * place (an empty directory, a repository). The check fails a cell only on
 * its WALL time (what the person waits for), when the median is more than
 * `slack` over the baseline's AND more than `floorMs` over it: shared CI
 * runners are noisy (one build's medians differed by 18% on the developer
 * host, §14.10), and the regression this exists for was +74%
 * (1.17 s to 2.04 s, §14.7 to §14.11). Each step is compared too and
 * marked when it is over the same slack and `stepFloorMs`, but a step alone
 * never fails the check: single steps are noisier than the whole, and the
 * marks say where to look. A cell more than `warnSlack` (20%) AND
 * `warnFloorMs` (150 ms) over, but within the budget, gets a WARN line
 * naming the steps that grew most: the slow creep the 50% lets through.
 *
 * Pure: no clock, no process. tests/env/launch-budget.test.ts runs the
 * launches; tests/stack/launch-budget-verdict.test.ts tests this.
 *
 * Mandu-new (no reference origin).
 */
import { median, stepOrder, type LaunchTimings } from "../../launcher/src/launch-timings.js";

/** A cell's medians. `steps` by name (the launch's step names). */
export interface CellMeasure {
  wallMs: number;
  totalMs: number;
  steps: Record<string, number>;
}

/** The recorded baseline (tests/env/launch-budget-baseline.json). */
export interface LaunchBudgetBaseline {
  v: 1;
  /** When and where it was measured, and from which commit. */
  recorded: string;
  where: string;
  commit: string;
  /** Measured runs per cell. */
  runs: number;
  cells: Record<string, CellMeasure>;
}

/** Over the baseline by more than this fraction AND by `floorMs`: a failure. */
export const DEFAULT_SLACK = 0.5;
export const FLOOR_MS = 300;
/** A step over by the slack and by this many ms is marked (never a failure). */
export const STEP_FLOOR_MS = 50;
/** A cell over by more than this fraction AND this many ms, but not over
 *  the budget, gets a WARN line: the creep the 50% lets through, said each
 *  night it is there (never a failure). */
export const WARN_SLACK = 0.2;
export const WARN_FLOOR_MS = 150;

/** One run of a cell: the wall time the test measured and the launch's own record. */
export interface CellRun {
  wallMs: number;
  timings: LaunchTimings;
}

/** A cell's medians over its runs (each step over the runs that have it). Pure. */
export function measureCell(runs: readonly CellRun[]): CellMeasure {
  const steps: Record<string, number> = {};
  for (const name of stepOrder(runs.map((r) => r.timings))) {
    const xs: number[] = [];
    for (const r of runs) {
      let sum: number | null = null;
      for (const s of r.timings.steps) if (s.step === name) sum = (sum ?? 0) + s.ms;
      if (sum !== null) xs.push(sum);
    }
    if (xs.length > 0) steps[name] = Math.round(median(xs));
  }
  return {
    wallMs: Math.round(median(runs.map((r) => r.wallMs))),
    totalMs: Math.round(median(runs.map((r) => r.timings.totalMs))),
    steps,
  };
}

/** A baseline file's content, or the reason it is not one. Pure. */
export function parseBaseline(text: string): LaunchBudgetBaseline | string {
  let o: unknown;
  try { o = JSON.parse(text); } catch (e) { return `not JSON: ${(e as Error).message}`; }
  const b = o as Partial<LaunchBudgetBaseline>;
  if (b === null || typeof b !== "object" || b.v !== 1 || typeof b.cells !== "object" || b.cells === null) return "not a v1 baseline (v, cells)";
  for (const [name, c] of Object.entries(b.cells)) {
    if (typeof c?.wallMs !== "number" || typeof c?.totalMs !== "number" || typeof c?.steps !== "object") return `cell ${name}: wallMs, totalMs, steps`;
  }
  return b as LaunchBudgetBaseline;
}

function pct(now: number, base: number): string {
  if (base <= 0) return "";
  const d = Math.round(((now - base) / base) * 100);
  return `${d >= 0 ? "+" : ""}${d}%`;
}

function over(now: number, base: number, slack: number, floor: number): boolean {
  return now > base * (1 + slack) && now - base > floor;
}

export interface BudgetVerdict {
  /** One line per failing cell; empty: the check passes. */
  failures: string[];
  /** One WARN line per cell over WARN_SLACK and WARN_FLOOR_MS but within
   *  the budget (also in `report`): creep, never a failure. */
  warnings: string[];
  /** The breakdown, printed either way. */
  report: string[];
}

/**
 * Compare the measured cells with the baseline. A cell the baseline does
 * not have is reported, never failed (a new cell's first numbers); a
 * baseline cell not measured (its agent absent) is said. Pure.
 */
export function budgetVerdict(
  measured: Record<string, CellMeasure>,
  baseline: LaunchBudgetBaseline | null,
  opts: { slack?: number; floorMs?: number; stepFloorMs?: number; warnSlack?: number; warnFloorMs?: number } = {},
): BudgetVerdict {
  const slack = opts.slack ?? DEFAULT_SLACK;
  const floor = opts.floorMs ?? FLOOR_MS;
  const stepFloor = opts.stepFloorMs ?? STEP_FLOOR_MS;
  const warnSlack = opts.warnSlack ?? WARN_SLACK;
  const warnFloor = opts.warnFloorMs ?? WARN_FLOOR_MS;
  const failures: string[] = [];
  const warnings: string[] = [];
  const report: string[] = [];
  report.push(baseline === null
    ? "launch budget: no baseline recorded; the numbers below are this run's"
    : `launch budget: against the baseline of ${baseline.recorded} (${baseline.where}, ${baseline.commit}); a cell fails over +${Math.round(slack * 100)}% and +${floor} ms of wall time`);
  for (const [name, m] of Object.entries(measured)) {
    const b = baseline?.cells[name];
    if (b === undefined) {
      report.push(`${name}: wall ${m.wallMs} ms, launch ${m.totalMs} ms (no baseline for this cell)`);
    } else {
      const bad = over(m.wallMs, b.wallMs, slack, floor);
      report.push(`${name}: wall ${m.wallMs} ms against ${b.wallMs} ms (${pct(m.wallMs, b.wallMs)}), launch ${m.totalMs} ms against ${b.totalMs} ms (${pct(m.totalMs, b.totalMs)})${bad ? "  OVER BUDGET" : ""}`);
      if (bad) failures.push(`${name}: ${m.wallMs} ms against a baseline of ${b.wallMs} ms (${pct(m.wallMs, b.wallMs)}, over +${Math.round(slack * 100)}% and +${floor} ms)`);
      else if (over(m.wallMs, b.wallMs, warnSlack, warnFloor)) {
        // Where the time went: the top-level steps that grew the most.
        const grew = Object.entries(m.steps)
          .filter(([s]) => !s.includes(".") && b.steps[s] !== undefined)
          .map(([s, ms]) => [s, ms - b.steps[s]!] as const)
          .filter(([, d]) => d > 0)
          .sort((x, y) => y[1] - x[1])
          .slice(0, 2)
          .map(([s, d]) => `${s} +${d} ms`);
        const line = `WARN ${name}: ${m.wallMs} ms against a baseline of ${b.wallMs} ms (${pct(m.wallMs, b.wallMs)}, over +${Math.round(warnSlack * 100)}% and +${warnFloor} ms; not a failure)` +
          (grew.length ? `; grew most: ${grew.join(", ")}` : "");
        warnings.push(line);
        report.push(line);
      }
    }
    const names = [...new Set([...Object.keys(m.steps), ...Object.keys(b?.steps ?? {})])];
    for (const step of names) {
      const now = m.steps[step];
      const base = b?.steps[step];
      const shown = step.startsWith("secrets.") ? `    ${step.slice("secrets.".length)}` : `  ${step}`;
      const cols = `${shown.padEnd(24)} ${(now === undefined ? "-" : String(now)).padStart(6)} ms`;
      if (base === undefined) { report.push(cols); continue; }
      const mark = now !== undefined && over(now, base, slack, stepFloor) ? "  over" : "";
      report.push(`${cols}  (baseline ${String(base).padStart(5)} ms${now !== undefined ? `, ${pct(now, base)}` : ""})${mark}`);
    }
  }
  for (const name of Object.keys(baseline?.cells ?? {})) {
    if (!(name in measured)) report.push(`${name}: not measured this run (its agent is not on PATH?)`);
  }
  return { failures, warnings, report };
}

/** The file a re-baseline writes: this run's cells, with where they came from. Pure. */
export function baselineOf(measured: Record<string, CellMeasure>, meta: { recorded: string; where: string; commit: string; runs: number }): LaunchBudgetBaseline {
  return { v: 1, ...meta, cells: measured };
}
