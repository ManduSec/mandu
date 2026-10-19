/**
 * exit-guard — the hung-runner BACKSTOP for the integration e2e/live suites.
 *
 * Mandu (tests/). NEW code, no reference origin.
 *
 * WHY: the suites run under `tsx --test` (node:test spawns one child runner
 * per file), and a runner only exits when its event loop drains. If ANY ref'd
 * handle leaks — a unix socket to the arbiter, a pipe fd inherited by an
 * orphaned grandchild — the runner stays alive FOREVER after every test
 * finished (observed 2026-07-11: one runner held ~7 leaked unix sockets for
 * 7.5h; the TAP epilogue never printed). The leak SOURCES are fixed
 * individually (child-run.ts, interactive-driver killTree, …); this module is
 * the backstop that turns any FUTURE leak into a loud per-handle diagnostic
 * plus a clean exit instead of a zombie.
 *
 * HOW: `installExitGuard` registers a root `after()` hook. Once every test
 * has run — and any background work registered via `guardTrackPending` has
 * settled (bounded by `pendingCeilingMs`) — the hook arms an UNREF'd grace
 * timer and returns. On a healthy runner the loop then drains and the process
 * exits naturally BEFORE the timer can fire, so the guard is a silent no-op.
 * Only when leaked handles are still holding the loop does the timer fire: it
 * prints one line per leaked non-stdio handle (type, fd, peer, pid, …) and
 * force-exits PRESERVING the run's exit code (node:test has already set
 * `process.exitCode = 1` on a red run), so green stays green and red stays red.
 *
 * This is a diagnostic backstop, NOT a teardown: if the guard ever fires, the
 * real fix is closing whatever leaked. Note that root `after()` hooks run in
 * REGISTRATION order — call `installExitGuard` before a suite registers slow
 * `after()` teardowns of its own only if `graceMs` comfortably exceeds them
 * (the grace timer is armed when THIS hook runs, ahead of later hooks).
 */

import { after } from "node:test";

/** Background work the runner must not exit under (shared by both exports). */
const tracked: Array<Promise<unknown>> = [];
/** How many tracked promises have settled (for the ceiling warning). */
let settledCount = 0;
/** Idempotency: a second installExitGuard call is a no-op. */
let installed = false;

/**
 * Register background work the runner must not exit under (e.g. the
 * eager-start scenario pool's settled-result promises — after a test timeout
 * the test body stops awaiting them but the WORK, including a live claude
 * child, keeps running; force-exiting under it would orphan the child
 * mid-run).
 */
export function guardTrackPending(work: Iterable<Promise<unknown>>): void {
  for (const p of work) {
    tracked.push(p);
    // Count settlements so the ceiling warning can name how many are still
    // pending. Both callbacks resolve the derived promise, so a rejecting
    // tracked promise can never surface as an unhandled rejection from here.
    void Promise.resolve(p).then(
      () => { settledCount += 1; },
      () => { settledCount += 1; },
    );
  }
}

/** The fd a handle sits on, checking both the JS wrapper and the libuv wrap. */
function handleFd(h: unknown): number | undefined {
  try {
    const o = h as { fd?: unknown; _handle?: { fd?: unknown } | null };
    if (typeof o.fd === "number") return o.fd;
    const inner = o._handle?.fd;
    if (typeof inner === "number") return inner;
  } catch {
    /* a hostile getter threw — treat as fd-less */
  }
  return undefined;
}

/** stdio handles (fd 0/1/2) are the runner's own plumbing, never a leak. */
function isStdioHandle(h: unknown): boolean {
  const fd = handleFd(h);
  return fd === 0 || fd === 1 || fd === 2;
}

/** One diagnostic line for a leaked handle. Small and DEFENSIVE — every
 *  property access is best-effort; a weird handle degrades to its name. */
function describeHandle(h: unknown): string {
  const parts: string[] = [];
  try {
    const o = h as {
      constructor?: { name?: string };
      _handle?: { constructor?: { name?: string } } | null;
      remoteAddress?: unknown;
      _peername?: { address?: unknown } | null;
      pid?: unknown;
      spawnargs?: unknown;
      address?: () => unknown;
    };
    const name = o.constructor?.name ?? typeof h;
    parts.push(name);
    const fd = handleFd(h);
    if (fd !== undefined) parts.push(`fd=${fd}`);
    // Sockets: the wrap class distinguishes unix (Pipe) from TCP, and the
    // peer names WHO the leaked connection points at.
    const wrap = o._handle?.constructor?.name;
    if (wrap && wrap !== name) parts.push(`wrap=${wrap}`);
    const peer =
      (typeof o.remoteAddress === "string" && o.remoteAddress !== "" && o.remoteAddress) ||
      (typeof o._peername?.address === "string" && o._peername.address) ||
      undefined;
    if (peer !== undefined) parts.push(`peer=${String(peer)}`);
    if (name === "ChildProcess") {
      if (typeof o.pid === "number") parts.push(`pid=${o.pid}`);
      if (Array.isArray(o.spawnargs)) parts.push(`argv=${JSON.stringify(o.spawnargs.slice(0, 4))}`);
    }
    if (name === "Server" && typeof o.address === "function") {
      try {
        parts.push(`address=${JSON.stringify(o.address())}`);
      } catch {
        /* not listening */
      }
    }
  } catch (err) {
    parts.push(`(describe failed: ${String(err)})`);
  }
  return parts.join(" ");
}

/**
 * Install the backstop: a root `after()` hook that (1) waits for tracked
 * background work (up to `pendingCeilingMs`, default 300s), then (2) arms an
 * unref'd `graceMs` timer (default 15s). A healthy runner exits naturally
 * before the timer fires; a leak-held runner gets the per-handle diagnostic
 * and a forced exit that preserves `process.exitCode`.
 */
export function installExitGuard(
  label: string,
  opts?: { graceMs?: number; pendingCeilingMs?: number },
): void {
  if (installed) return;
  installed = true;
  const graceMs = opts?.graceMs ?? 15_000;
  const pendingCeilingMs = opts?.pendingCeilingMs ?? 300_000;

  const fire = (): void => {
    const proc = process as unknown as { _getActiveHandles?: () => unknown[] };
    let handles: unknown[];
    try {
      handles = proc._getActiveHandles?.() ?? [];
    } catch {
      handles = [];
    }
    const leaked = handles.filter((h) => !isStdioHandle(h));
    const code = process.exitCode ?? 0;
    console.error(
      `[exit-guard:${label}] runner still alive ${graceMs}ms after tests + tracked work settled — ${leaked.length} leaked handle(s):`,
    );
    for (const h of leaked) {
      console.error(`[exit-guard:${label}]   ${describeHandle(h)}`);
    }
    console.error(
      `[exit-guard:${label}] forcing exit code=${code} — fix the leak; this guard is a backstop, not a teardown`,
    );
    process.exit(code);
  };

  after(async () => {
    // (1) Never force-exit under still-running tracked work (a live claude
    // child would be orphaned mid-run). Tracked pool results are pre-settled
    // objects and never reject; allSettled absorbs anything else. The ceiling
    // timer is UNREF'd so this wait can itself never hold a drained loop open.
    if (tracked.length > 0) {
      let ceilingTimer: NodeJS.Timeout | undefined;
      const ceiling = new Promise<"ceiling">((resolve) => {
        ceilingTimer = setTimeout(() => resolve("ceiling"), pendingCeilingMs);
        ceilingTimer.unref();
      });
      const outcome = await Promise.race([
        Promise.allSettled(tracked).then(() => "settled" as const),
        ceiling,
      ]);
      if (ceilingTimer !== undefined) clearTimeout(ceilingTimer);
      if (outcome === "ceiling") {
        console.error(
          `[exit-guard:${label}] pending-work ceiling (${pendingCeilingMs}ms) tripped — ${tracked.length - settledCount}/${tracked.length} tracked promise(s) still pending; proceeding to the leak check`,
        );
      }
    }
    // (2) UNREF'd, so a healthy runner exits naturally before this fires and
    // the guard is a no-op. It fires only if leaked handles still hold the loop.
    const t = setTimeout(fire, graceMs);
    t.unref();
  });
}
