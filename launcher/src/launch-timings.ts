/**
 * launch-timings — how long each step of a launch took
 * (runtime-instances.md §14.11, 2026-10-21).
 *
 * A warm `mandu claude --version` went from 1.17 s (2026-10-16) to about
 * 2 s (2026-10-21) and nobody saw it until the launch felt slow; each
 * investigation re-instrumented `launch()` by hand. Every launch now times
 * its named steps (LAUNCH_STEPS, a fixed set) with this timer, always on.
 * The record goes to the `launch_posture` event (the steps before the
 * agent), the `session_exit` event (the agent and the teardown), the
 * session's `launch.log` and the launch's own log (launch-log.ts), where
 * `mandu log --timings` reads it back. A `--verbose` launch prints it on
 * stderr at its end; a normal launch never prints it.
 *
 * The timer is best effort and cheap: a step is one `performance.now()`,
 * one `process.cpuUsage()` and one array slot, no call throws, a misuse (an
 * end with nothing running, a span after the record is full) is ignored. It
 * never decides anything: it only reads the clocks and the counters.
 *
 * The costs (runtime-instances.md §14.11, "What a step costs, counted",
 * 2026-10-22): each top-level step also records the launcher's own CPU time
 * in it (`cpuMs`), the git processes the launcher started in it (`git`) and
 * the sandboxes it made for them (`sandboxes`): numbers a loaded host
 * cannot move, where it moves the wall time. The git runners call
 * `countGitCall` / `countGitSandbox` (git-session.ts, and the launch's
 * single git probes); the timer reads the counters at each step's start
 * and end, as it reads the clock. A per-push check
 * (tests/sandbox/launch-git-budget.test.ts) holds the counts under a budget.
 *
 * Mandu-new (no reference origin).
 */

/** The steps a launch times, in launch order, each with what it covers.
 *  A dotted name is a part of the step before the dot (its wait inside it):
 *  the parent's time includes its parts'. The doc (runtime-instances.md
 *  §14.11) lists the same set; a new step goes in both. */
export const LAUNCH_STEPS = [
  ["node", "the node process start and the launcher's module load, to main() (the `mandu` command only)"],
  ["plan", "the parse, the plan, the agent's version probe and the refusals before anything starts"],
  ["arbiter", "attach to (or start) the arbiter: its release, tenant and mode checks, the policy reads, the session's model binding"],
  ["services", "the session's services: the model proxy, the network proxy, the shims (the secret walk starts inside it)"],
  ["confine", "the command box, the agent's environment, the network layers"],
  ["key-grants", "the agents' API keys bound to their model hosts"],
  ["secrets", "the secret setup: the placeholder copies, the git history step, the twins' index stat"],
  ["secrets.discovery", "the wait for the secret walk"],
  ["secrets.history", "the git history step"],
  ["secrets.watch", "the wait for the placeholder watch"],
  ["secrets.twin-index", "the twins' index stat"],
  ["placeholder-check", "earlier sessions' placeholder records"],
  ["env-secrets", "the environment's secrets as placeholders"],
  ["compose", "the guard settings, the write protection, the composed command and environment"],
  ["record", "the TLS word, the MCP servers, the launch on the arbiter's record, the human-plane watch"],
  ["banner", "the mode and dashboard lines, the sign-in link, the key-suggestion notice"],
  ["posture", "the session's launch.log and the launch_posture event"],
  ["agent-start", "the early reply filter handed the agent"],
  ["agent", "the agent's own run, from its start to its exit, under Mandu's wrappers"],
  ["teardown.index", "the twins' index stat put back"],
  ["teardown.services", "the session's services stopped"],
  ["teardown.notices", "the guard's refused repositories and moved files"],
  ["teardown.placeholder", "the placeholder-commit checks"],
  ["teardown.exit", "the written-copies notice, the session_exit event, the scope folder"],
  ["teardown.summary", "the session's last line (what Mandu kept from the AI), asked of the dashboard"],
  ["teardown.records", "the TLS word withdrawn, the launch's record ended"],
] as const;

/** A step's name. */
export type LaunchStepName = (typeof LAUNCH_STEPS)[number][0];
/** A top-level step (what `step()` takes). */
export type LaunchTopStep = Exclude<LaunchStepName, `secrets.${string}`>;
/** A part of the `secrets` step (what secret-setup.ts times). */
export type SecretSpanName = "discovery" | "history" | "watch" | "twin-index";

/** What a top-level step cost besides its wall time (absent on a part,
 *  whose window overlaps its siblings', and on an older launcher's record). */
export interface StepCost {
  /** The launcher process's CPU time (user + system) in the step, ms. */
  cpuMs?: number;
  /** git processes the launcher started in the step (countGitCall). */
  git?: number;
  /** Sandboxes made for them (one per call, or a session's one). */
  sandboxes?: number;
}

/** One timed step. */
export interface StepTiming extends StepCost {
  step: string;
  ms: number;
}

/** A launch's timings: on the events (`timings`), in the logs. */
export interface LaunchTimings {
  v: 1;
  /** From the process start (the `mandu` command) or main()'s start (in-process). */
  totalMs: number;
  /** Each finished step, in the order the steps started. */
  steps: StepTiming[];
  /** The same costs over the whole record, from the timer's origin to the
   *  snapshot (what started outside every step included). */
  cost?: StepCost;
}

// ── The counters ──────────────────────────────────────────────────────────────

/** The git processes and sandboxes this process has started (never reset:
 *  the timer takes differences). */
const COUNTS = { git: 0, sandboxes: 0 };

/** A git process the launcher starts; `sandboxed`: in a sandbox of its own
 *  (a per-call bubblewrap or Seatbelt). */
export function countGitCall(sandboxed: boolean): void {
  COUNTS.git++;
  if (sandboxed) COUNTS.sandboxes++;
}

/** A sandbox made for many git calls (a git session's runner). */
export function countGitSandbox(): void {
  COUNTS.sandboxes++;
}

/** The counters now (a copy). */
export function gitCounts(): { git: number; sandboxes: number } {
  return { ...COUNTS };
}

/** The narrow face the secret setup gets: a part of the running step. */
export interface StepSpans {
  /** Start a part of the running step; the function returned ends it. */
  span(name: SecretSpanName): () => void;
}

/** More records than any launch makes: a loop that spans cannot grow it. */
const MAX_RECORDS = 128;

/** The CPU clock and the counters, read at a step's start and end. */
interface Reading { cpuUs: number; git: number; sandboxes: number }

interface Rec { step: string; start: number; ms: number | null; at?: Reading; cost?: StepCost }

function roundMs(ms: number): number {
  return Math.max(0, Math.round(ms));
}

function processCpuUs(): number {
  const c = process.cpuUsage();
  return c.user + c.system;
}

/** The cost between two readings. Pure. */
function costBetween(a: Reading, b: Reading): StepCost {
  return {
    cpuMs: roundMs((b.cpuUs - a.cpuUs) / 1000),
    git: Math.max(0, b.git - a.git),
    sandboxes: Math.max(0, b.sandboxes - a.sandboxes),
  };
}

export class LaunchTimer implements StepSpans {
  private readonly recs: Rec[] = [];
  private current: Rec | null = null;
  private readonly now: () => number;
  private readonly cpuUs: () => number;
  private readonly counts: () => { git: number; sandboxes: number };
  private readonly origin: number;
  private readonly originReading: Reading | null;

  /**
   * `cli`: the `mandu` command, whose process started for this launch: the
   * total counts from the process start and the `node` step is the time to
   * here. Otherwise (main() called in-process) both count from now.
   * `cpuUs`, `counts` (tests): the process's CPU time in microseconds and
   * the git counters (default: process.cpuUsage, gitCounts).
   */
  constructor(opts: { cli?: boolean; now?: () => number; cpuUs?: () => number; counts?: () => { git: number; sandboxes: number } } = {}) {
    this.now = opts.now ?? (() => performance.now());
    this.cpuUs = opts.cpuUs ?? processCpuUs;
    this.counts = opts.counts ?? gitCounts;
    const at = this.read();
    const reading = this.reading();
    this.origin = opts.cli === true ? 0 : at;
    // The `mandu` command's process started for this launch: its CPU time
    // and its counters count from zero, as its clock does.
    const zero: Reading = { cpuUs: 0, git: 0, sandboxes: 0 };
    this.originReading = opts.cli === true ? zero : reading;
    if (opts.cli === true) {
      this.recs.push({ step: "node", start: 0, ms: roundMs(at), ...(reading !== null ? { cost: costBetween(zero, reading) } : {}) });
    }
  }

  private read(): number {
    try { return this.now(); } catch { return 0; }
  }

  /** The CPU clock and the counters now, or null when one cannot be read. */
  private reading(): Reading | null {
    try {
      const c = this.counts();
      return { cpuUs: this.cpuUs(), git: c.git, sandboxes: c.sandboxes };
    } catch {
      return null;
    }
  }

  /** End the running step (and its open parts) and start `name`. */
  step(name: LaunchTopStep): void {
    try {
      this.end();
      if (this.recs.length >= MAX_RECORDS) return;
      const at = this.reading();
      const r: Rec = { step: name, start: this.read(), ms: null, ...(at !== null ? { at } : {}) };
      this.recs.push(r);
      this.current = r;
    } catch { /* best-effort */ }
  }

  /** End the running step; nothing when none runs. */
  end(): void {
    try {
      const c = this.current;
      if (c === null) return;
      this.current = null;
      const at = this.read();
      for (const r of this.recs) if (r.ms === null && r.step.startsWith(`${c.step}.`)) r.ms = roundMs(at - r.start);
      c.ms = roundMs(at - c.start);
      const done = c.at !== undefined ? this.reading() : null;
      if (c.at !== undefined && done !== null) c.cost = costBetween(c.at, done);
    } catch { /* best-effort */ }
  }

  /** A part of the running step, named `<step>.<name>`; the function
   *  returned ends it (a second call does nothing). Outside a step, a no-op. */
  span(name: string): () => void {
    try {
      const c = this.current;
      if (c === null || this.recs.length >= MAX_RECORDS) return () => {};
      const r: Rec = { step: `${c.step}.${name}`, start: this.read(), ms: null };
      this.recs.push(r);
      return () => {
        try { if (r.ms === null) r.ms = roundMs(this.read() - r.start); } catch { /* best-effort */ }
      };
    } catch {
      return () => {};
    }
  }

  /** Whether any step was started (a launch, not `--help` or a subcommand). */
  get started(): boolean {
    return this.recs.some((r) => r.step !== "node");
  }

  /** The finished steps so far; `from`: only that step and the ones after
   *  it (and no whole-record `cost`, which counts from the origin). */
  snapshot(opts: { from?: LaunchStepName } = {}): LaunchTimings {
    try {
      let recs = this.recs;
      if (opts.from !== undefined) {
        const i = recs.findIndex((r) => r.step === opts.from);
        recs = i < 0 ? [] : recs.slice(i);
      }
      const now = opts.from === undefined && this.originReading !== null ? this.reading() : null;
      return {
        v: 1,
        totalMs: roundMs(this.read() - this.origin),
        steps: recs.filter((r) => r.ms !== null).map((r) => ({ step: r.step, ms: r.ms!, ...(r.cost ?? {}) })),
        ...(opts.from === undefined && this.originReading !== null && now !== null ? { cost: costBetween(this.originReading, now) } : {}),
      };
    } catch {
      return { v: 1, totalMs: 0, steps: [] };
    }
  }
}


// ── the log line ───────────────────────────────────────────────────────────────

/** What starts the timings line in a launch's log. */
export const TIMINGS_LINE_PREFIX = "mandu: launch timings ";

/** The line a launch's log keeps. Pure. */
export function timingsLogLine(t: LaunchTimings): string {
  return TIMINGS_LINE_PREFIX + JSON.stringify(t);
}

/** The cost fields, in the order they are printed. */
const COST_KEYS = ["cpuMs", "git", "sandboxes"] as const;

/** The costs a record holds: each a finite number >= 0 (any other value is
 *  left out, never a reason to drop the record). Pure. */
function asStepCost(o: Record<string, unknown>): StepCost {
  const out: StepCost = {};
  for (const k of COST_KEYS) {
    const x = o[k];
    if (typeof x === "number" && Number.isFinite(x) && x >= 0) out[k] = x;
  }
  return out;
}

/** A record read back (a log line, an event's field), or null. Pure. */
export function asLaunchTimings(v: unknown): LaunchTimings | null {
  if (v === null || typeof v !== "object") return null;
  const o = v as Record<string, unknown>;
  if (o["v"] !== 1 || typeof o["totalMs"] !== "number" || !Array.isArray(o["steps"])) return null;
  const steps: StepTiming[] = [];
  for (const s of o["steps"] as unknown[]) {
    if (s === null || typeof s !== "object") return null;
    const step = (s as Record<string, unknown>)["step"];
    const ms = (s as Record<string, unknown>)["ms"];
    if (typeof step !== "string" || typeof ms !== "number" || !Number.isFinite(ms)) return null;
    steps.push({ step, ms, ...asStepCost(s as Record<string, unknown>) });
  }
  const cost = o["cost"] !== null && typeof o["cost"] === "object" ? asStepCost(o["cost"] as Record<string, unknown>) : {};
  return { v: 1, totalMs: o["totalMs"] as number, steps, ...(Object.keys(cost).length > 0 ? { cost } : {}) };
}

/** The last timings line of a launch's log text (the one written at its
 *  end; a launch that never ended has only the one written before its
 *  agent started), or null. Pure. */
export function timingsFromLog(text: string): LaunchTimings | null {
  const lines = text.split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    const l = lines[i]!;
    if (!l.startsWith(TIMINGS_LINE_PREFIX)) continue;
    try {
      const t = asLaunchTimings(JSON.parse(l.slice(TIMINGS_LINE_PREFIX.length)));
      if (t !== null) return t;
    } catch { /* not ours */ }
  }
  return null;
}

// ── reading them ──────────────────────────────────────────────────────────────

/** The steps' names in order: the documented ones first, in their order,
 *  then any other a record holds (an older or newer launcher's). Pure. */
export function stepOrder(records: readonly LaunchTimings[]): string[] {
  const known: string[] = LAUNCH_STEPS.map(([n]) => n);
  const seen = new Set<string>();
  for (const t of records) for (const s of t.steps) seen.add(s.step);
  return [...known.filter((n) => seen.has(n)), ...[...seen].filter((n) => !known.includes(n))];
}

/** A step's time in one record: the sum when it was timed more than once. */
export function stepMs(t: LaunchTimings, step: string): number | null {
  let sum: number | null = null;
  for (const s of t.steps) if (s.step === step) sum = (sum ?? 0) + s.ms;
  return sum;
}

/** The median of some numbers (the mean of the middle two for an even count). Pure. */
export function median(xs: readonly number[]): number {
  if (xs.length === 0) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 === 1 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
}

/** Each step's median over the records that have it, and the total's. Pure. */
export function medianTimings(records: readonly LaunchTimings[]): LaunchTimings {
  const steps: StepTiming[] = [];
  for (const step of stepOrder(records)) {
    const xs = records.map((t) => stepMs(t, step)).filter((x): x is number => x !== null);
    if (xs.length > 0) steps.push({ step, ms: Math.round(median(xs)) });
  }
  // The whole launch's costs, each over the records that hold it.
  const cost: StepCost = {};
  for (const k of COST_KEYS) {
    const xs = records.map((t) => t.cost?.[k]).filter((x): x is number => x !== undefined);
    if (xs.length > 0) cost[k] = Math.round(median(xs));
  }
  return { v: 1, totalMs: Math.round(median(records.map((t) => t.totalMs))), steps, ...(Object.keys(cost).length > 0 ? { cost } : {}) };
}

/** A step's name, indented under its parent. */
function shownName(step: string): string {
  const dot = step.indexOf(".");
  return dot > 0 && step.startsWith("secrets.") ? `  ${step.slice(dot + 1)}` : step;
}

/** A cost as the breakdown prints it (`cpu 40 ms, 12 git, 1 sandbox`), or
 *  "" when the record holds none. Pure. */
export function formatCost(c: StepCost | undefined): string {
  if (c === undefined) return "";
  const parts: string[] = [];
  if (c.cpuMs !== undefined) parts.push(`cpu ${c.cpuMs} ms`);
  if (c.git !== undefined) parts.push(`${c.git} git`);
  if (c.sandboxes !== undefined) parts.push(`${c.sandboxes} sandbox${c.sandboxes === 1 ? "" : "es"}`);
  return parts.join(", ");
}

/** The breakdown a `--verbose` launch prints at its end: each step's time,
 *  and a top-level step's cost beside it. Pure. */
export function formatTimings(t: LaunchTimings): string[] {
  const total = formatCost(t.cost);
  const out = [`mandu: launch timings: ${t.totalMs} ms in all${total !== "" ? ` (${total})` : ""}`];
  for (const s of t.steps) {
    const cost = formatCost({
      ...(s.cpuMs !== undefined ? { cpuMs: s.cpuMs } : {}),
      ...(s.git !== undefined ? { git: s.git } : {}),
      ...(s.sandboxes !== undefined ? { sandboxes: s.sandboxes } : {}),
    });
    out.push(`  ${shownName(s.step).padEnd(22)} ${String(s.ms).padStart(6)} ms${cost !== "" ? `   ${cost}` : ""}`);
  }
  return out;
}

/** `mandu log --timings`: one column per launch (newest first) and, for
 *  more than one, the median first. Pure. */
export function formatTimingsTable(launches: ReadonlyArray<{ label: string; timings: LaunchTimings }>): string[] {
  if (launches.length === 0) return [];
  const records = launches.map((l) => l.timings);
  const cols: Array<{ label: string; t: LaunchTimings }> = [
    ...(launches.length > 1 ? [{ label: "median", t: medianTimings(records) }] : []),
    ...launches.map((l) => ({ label: l.label, t: l.timings })),
  ];
  const w = Math.max(8, ...cols.map((c) => c.label.length));
  const cell = (v: number | null): string => (v === null ? "-" : String(v)).padStart(w);
  const row = (name: string, vals: Array<number | null>): string => `${name.padEnd(22)} ${vals.map(cell).join("  ")}`.trimEnd();
  const out = [`${"step (ms)".padEnd(22)} ${cols.map((c) => c.label.padStart(w)).join("  ")}`];
  out.push(row("total", cols.map((c) => c.t.totalMs)));
  // The whole launch's costs, when a record holds them (an older launcher's
  // does not): the launcher's CPU time, its git calls and their sandboxes.
  for (const [k, name] of [["cpuMs", "  cpu"], ["git", "  git calls"], ["sandboxes", "  sandboxes"]] as const) {
    if (cols.some((c) => c.t.cost?.[k] !== undefined)) out.push(row(name, cols.map((c) => c.t.cost?.[k] ?? null)));
  }
  for (const step of stepOrder(records)) out.push(row(shownName(step), cols.map((c) => stepMs(c.t, step))));
  return out;
}
