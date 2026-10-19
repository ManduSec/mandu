/**
 * server/cache-warmup — the boot warm-up of the dashboard's slow read caches
 * (dashboard.md §4.30). Mandu-new (no reference origin). OBSERVABILITY / DEV
 * TOOLING ONLY: it only calls readers that already exist, earlier.
 *
 * The server calls runWarmup once it listens, in the background (never
 * awaited by a request). The in-process steps run one at a time, each after a
 * turn of the event loop, so a request that arrived meanwhile is answered
 * first; the long ones yield inside themselves too (warmReplayRuns, the
 * recorded source's listing, warmCiRuns). A `concurrent` step is one whose
 * work is in a child process (the drill catalog, the manifest CLI): it is
 * started in its turn but not waited for, so the steps after it run beside
 * it (it costs the event loop nothing). A step that fails is logged and
 * skipped: the cache it would have filled fills on its first request, as
 * before.
 */

export interface WarmStep {
  name: string;
  run: () => unknown;
  /** the work is out of process: start it with the first step, not in turn */
  concurrent?: boolean;
}

export interface WarmResult {
  name: string;
  ms: number;
  ok: boolean;
  error?: string;
}

const turn = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

async function runStep(step: WarmStep): Promise<WarmResult> {
  const t0 = performance.now();
  try {
    await step.run();
    return { name: step.name, ms: Math.round(performance.now() - t0), ok: true };
  } catch (err) {
    return { name: step.name, ms: Math.round(performance.now() - t0), ok: false, error: String((err as Error)?.message ?? err).slice(0, 200) };
  }
}

/** Run the steps (results in step order); `stopped` true (a server closing)
 *  starts no further step. */
export async function runWarmup(steps: WarmStep[], stopped: () => boolean = () => false): Promise<WarmResult[]> {
  const results = new Map<WarmStep, Promise<WarmResult>>();
  for (const step of steps) {
    await turn();
    if (stopped()) break;
    const r = runStep(step);
    results.set(step, r);
    if (!step.concurrent) await r;
  }
  const out: WarmResult[] = [];
  for (const step of steps) {
    const r = results.get(step);
    if (r) out.push(await r);
  }
  return out;
}

/** One log line: `caches warm in 4.1 s (replay heads 2.3 s, …; coverage failed: …)`. */
export function describeWarmup(results: WarmResult[], totalMs: number): string {
  const s = (ms: number): string => (ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${ms} ms`);
  const parts = results.map((r) => (r.ok ? `${r.name} ${s(r.ms)}` : `${r.name} failed: ${r.error}`));
  return `caches warm in ${s(Math.round(totalMs))} (${parts.join(", ")})`;
}
