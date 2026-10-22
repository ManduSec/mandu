/**
 * services/fs-view — seed the AgentView worktree and rewrite the agent CWD
 * (the Part-3 filesystem chokepoint, cooperative tier: portable-wrapper.md
 * §2.1 "CWD → the AgentView worktree").
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. All view logic lives in fs-sync (lifted from
 *   adfi-openclaw); this service only DRIVES fs-sync/src/fs-sync-cli.ts as
 *   one-shot subprocesses (init pre-spawn, sync post-exit) — the CLI was built
 *   as the launcher's entry point and fails closed (non-zero) on any error.
 *   Uses the package-local tsx, NOT npx (npx's wrapper does not forward
 *   signals; see fs-sync/test/integrity/fs-sync-cli.test.ts:46).
 *
 * Default-on for git workspaces (user decision 2026-07-05): auto mode skips
 * non-git workspaces (raw CWD — the context chokepoint backstops, see
 * architecture-map.md §9 §② honest bound); an EXPLICIT --fs-sync on a
 * non-git workspace fails the launch closed.
 */
import { readFileSync, realpathSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import type { LaunchPlan } from "../types.js";
import type { Layout } from "./layout.js";
import type { ServiceDeps } from "./primitives.js";
import { humanSockEnv } from "../human-plane.js";
import { hardenedGitArgs, hardenedGitEnv } from "../hardened-git.js";
import { countGitCall } from "../launch-timings.js";

/** Bound the one-shot subprocesses so a wedged CLI can't hang the launch/exit. */
const GIT_PROBE_TIMEOUT_MS = 10_000;
const FS_SYNC_CLI_TIMEOUT_MS = 600_000; // init may symbolize a large worktree
/** Soft readiness bound for the eager watcher's ready line (fail-safe: a slow
 * watcher only warns — it is never allowed to abort or delay-fail the launch). */
const WATCH_READY = { tries: 50, delayMs: 100 };
/** Bound on waiting for the SIGTERM'd watcher's process group to empty before
 * the sweep runs (the watcher drains its in-flight sync first; the sweep must
 * not race it on the layout lock or on the worktree's index.lock). Generous:
 * covers a large in-flight desymbolization. */
const WATCH_EXIT = { tries: 300, delayMs: 100 };
/** After the bound above, the whole group is SIGTERMed; this short wait lets
 * it go before the sweep runs anyway. */
const WATCH_KILL = { tries: 20, delayMs: 100 };

export interface FsViewResult {
  /** The rewritten agent CWD (AgentView worktree + preserved subdir). */
  agentCwd: string;
  gitRoot: string;
  /**
   * The AgentView worktree ROOT (no subdir) — with gitRoot, the HumanView↔
   * AgentView pair the context proxy's prefix map needs (P2, plan.viewMap).
   */
  agentView: string;
  /** True when the eager watcher was spawned (--fs-sync-eager and the spawn
   * did not immediately fail) — truth-in-labeling for the manager's rung line. */
  eager: boolean;
  /** Watcher teardown (if any) + post-exit write-back (AgentView → HumanView).
   * Warns on failure, never throws. */
  stop: () => Promise<void>;
  /** Settles when the eager watcher confirmed its subscription, or its wait
   * timed out (warned). Soft, so the launch does not wait on it here: the
   * manager awaits it once the other services are up (never rejects). */
  ready?: Promise<void>;
}

/** Is any process of group `pgid` still alive (or a not-yet-reaped zombie)?
 * kill(-pgid, 0) probes; EPERM means a member exists. The watcher leads its
 * own group, so this covers a git it started that outlives it. */
export function groupAlive(pgid: number): boolean {
  try {
    process.kill(-pgid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * The launch line for the ignored files left out of the AgentView, from
 * `fs-sync-cli init`'s `ignored` field, or null when nothing was left out
 * (or the field is absent or malformed: an older fs-sync). Pure.
 */
export function ignoredSkipNote(ignored: unknown): string | null {
  if (ignored === null || typeof ignored !== "object") return null;
  const r = ignored as { skippedCounts?: unknown; manifest?: unknown };
  if (r.skippedCounts === null || typeof r.skippedCounts !== "object") return null;
  const parts: string[] = [];
  let total = 0;
  for (const [reason, n] of Object.entries(r.skippedCounts as Record<string, unknown>)) {
    if (typeof n !== "number" || !Number.isInteger(n) || n <= 0) continue;
    total += n;
    parts.push(`${n} ${reason}`);
  }
  if (total === 0) return null;
  const where = typeof r.manifest === "string" ? `; the list is in ${r.manifest}` : "";
  return (
    `fs-view: ${total} git-ignored path(s) are NOT in the AI's working copy (${parts.join(", ")}): ` +
    `heavy folders such as node_modules, files over the size caps, and binaries stay out${where}`
  );
}

export async function startFsView(
  plan: LaunchPlan,
  layout: Layout,
  deps: ServiceDeps,
  warn: (msg: string) => void = (m) => console.error(`mandu: ${m}`),
): Promise<FsViewResult | null> {
  // Hardened (hardened-git.ts): the workspace is the agent's to configure.
  countGitCall(false); // the launch's costs (launch-timings.ts)
  const probe = deps.runOnce("git", hardenedGitArgs(["-C", plan.humanCwd, "rev-parse", "--show-toplevel"]), {
    cwd: plan.humanCwd, env: hardenedGitEnv(), timeoutMs: GIT_PROBE_TIMEOUT_MS,
  });
  if (probe.status !== 0) {
    if (plan.fsSync === true) {
      // Append the probe detail: a status-null failure (git missing / probe
      // timeout) is NOT "not a repo" — don't let the message mislead.
      throw new Error(`mandu: --fs-sync requested but ${plan.humanCwd} is not inside a git repository (${probe.stderr.trim() || "git probe failed"})`);
    }
    // Truth-in-labeling (fs-sync.md §1.5, §1.6 P5): say exactly which
    // protections are absent in this degraded mode, not just "raw CWD".
    warn(
      `fs-view: ${plan.humanCwd} is not a git workspace — running with the RAW CWD ` +
      `(DEGRADED fs rung: no AgentView worktree, no HumanView↔AgentView prefix map, ` +
      `no sensitive-path gate; the context chokepoint backstop still applies)`,
    );
    return null; // auto mode: raw CWD for non-git workspaces
  }
  const gitRoot = probe.stdout.trim();

  // The layout resolves the fs-sync CLI invocation: dev = the package-local tsx
  // over fs-sync-cli.ts; installed = `node dist/fs-sync-cli.mjs` (+ the arbiter
  // client module). The one-shot base (init/sync) and the eager-watch base
  // differ only in dev (watch uses `node --import tsx` for signal delivery).
  const oneShot = layout.fsSyncCli();
  // fs-sync resolves and desymbolizes over the arbiter's HUMAN plane
  // (arbiter-human-plane.md); an unset one (none reported) is explicit, so a
  // stale ambient value never points it at another arbiter.
  const env = { ...process.env, MANDU_ARBITER_SOCK: plan.arbiterSock, ...humanSockEnv(plan.arbiterHumanSock), ...oneShot.env };

  // --session: seed-time mints file their birth events under this scope
  // (symbol-lineage.md G1) — without it the seeded twins' symbols have no
  // recorded birth in the session's event log.
  const init = deps.runOnce(oneShot.cmd, [...oneShot.baseArgs, "init", gitRoot, "--session", plan.scopeId], { cwd: oneShot.cwd, env, timeoutMs: FS_SYNC_CLI_TIMEOUT_MS });
  if (init.status !== 0) {
    throw new Error(`mandu: fs-view init failed (fail-closed): ${(init.stderr || init.stdout).trim()}`);
  }
  // Validate the CLI's output fail-closed: an exit-0 with drifted/absent JSON
  // must NOT silently yield agentCwd:undefined (the manager would then spawn
  // the agent in a raw CWD — a silent fail-open).
  const lastLine = init.stdout.trim().split("\n").pop() ?? "";
  let agentView: string;
  let ignored: unknown;
  try {
    const parsed = JSON.parse(lastLine) as { agentView?: unknown; ignored?: unknown };
    agentView = parsed.agentView as string;
    ignored = parsed.ignored;
  } catch {
    throw new Error(`mandu: fs-view init returned unparseable JSON (fail-closed): ${lastLine}`);
  }
  if (typeof agentView !== "string" || agentView === "") {
    throw new Error(`mandu: fs-view init returned no agentView path (fail-closed): ${lastLine}`);
  }
  // The `.gitignore`d files the AI's copy does NOT carry (a heavy directory,
  // a cap, a binary; fs-sync.md §3.4.1): said at every launch, so a
  // missing file is never a silent surprise. Absent on an older fs-sync.
  const note = ignoredSkipNote(ignored);
  if (note !== null) warn(note);

  // Preserve the launch dir's position below the git root. realpath both sides:
  // git prints a resolved root while the env-derived humanCwd may ride a symlink.
  const rel = relative(realpathSync(gitRoot), realpathSync(plan.humanCwd));
  const agentCwd = rel ? join(agentView, rel) : agentView;

  // ── Eager tool-call-boundary sync (fs-sync.md §2.3–§4, Phase 1,
  // default OFF): keep a resident `fs-sync-cli watch` subscribed to this
  // session's tool_result events so AgentView writes reach the HumanView
  // mid-run, not just post-exit. UTILITY-CLASS / FAIL-SAFE: a watcher that
  // fails to start (or dies later) only warns and degrades to today's
  // behavior — the post-exit sweep below stays UNCONDITIONAL either way.
  //
  // Spawned as single-process `node --import tsx` (resolved from the fs-sync
  // cwd), NOT the tsx binary: the tsx wrapper turns SIGTERM into its own exit
  // 143 while its node child may outlive it — stop() below waits on THIS pid
  // to keep the graceful drain and the sweep off each other's layout lock.
  let watcher: { pid: number | undefined; stop: () => void; stopLeader?: () => void } | undefined;
  let ready: Promise<void> | undefined;
  if (plan.fsSyncEager) {
    const watchLog = join(resolve(plan.eventDir, ".."), "fs-sync-watch.log");
    try {
      const watchBase = layout.fsSyncWatch();
      watcher = deps.startDetachedCmd(
        watchBase.cmd,
        [...watchBase.baseArgs, "watch", gitRoot, "--session", plan.scopeId],
        { cwd: watchBase.cwd, env: { ...env, ...watchBase.env } },
        watchLog,
      );
      // Soft readiness: the watcher prints {"ok":true,...} (into its log) once
      // its subscription is live. Not fail-closed — on timeout warn and keep
      // it running; it may still come up, and the sweep remains the catch-all.
      // Not awaited here (the manager awaits `ready` after the proxies are
      // up): the watcher's node startup overlaps theirs.
      ready = deps.waitFor(() => {
        try { return readFileSync(watchLog, "utf8").includes('"ok":true'); } catch { return false; }
      }, WATCH_READY).then((ok) => {
        if (!ok) warn(`fs-view eager watcher not confirmed ready (log: ${watchLog}) — eager sync may be inactive; the post-exit sweep remains the catch-all`);
      }, () => {
        warn(`fs-view eager watcher not confirmed ready (log: ${watchLog}) — eager sync may be inactive; the post-exit sweep remains the catch-all`);
      });
    } catch (e) {
      watcher = undefined;
      warn(`fs-view eager watcher failed to start — degrading to the post-exit sweep only: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  return {
    agentCwd,
    gitRoot,
    agentView,
    eager: watcher !== undefined,
    ...(ready ? { ready } : {}),
    stop: async () => {
      // Tear the watcher down BEFORE the sweep (fs-sync.md §2.4a): SIGTERM
      // lets it drain an in-flight sync (its commit pair finishes), and
      // waiting keeps the sweep from contending on the fs-sync layout lock.
      // The SIGTERM goes to the watcher ONLY, not its group: a git it is
      // running that is SIGTERMed can leave the AgentView's index.lock behind,
      // and the sweep's commit then fails on it (the golden-path canary,
      // 2026-10-04). The wait is for the whole GROUP, so a git that outlives
      // the watcher (one that died before its SIGTERM handler was installed)
      // finishes first. A group that won't go is SIGTERMed whole, warned
      // about, and the sweep still runs (catch-all).
      if (watcher) {
        try { (watcher.stopLeader ?? watcher.stop)(); } catch { /* already gone */ }
        const pid = watcher.pid;
        if (pid !== undefined) {
          const gone = await deps.waitFor(() => !groupAlive(pid), WATCH_EXIT);
          if (!gone) {
            try { watcher.stop(); } catch { /* already gone */ }
            await deps.waitFor(() => !groupAlive(pid), WATCH_KILL);
            warn(`fs-view eager watcher did not exit after SIGTERM — running the sweep anyway`);
          }
        }
      }
      // In a session of its own (teardown-signals.ts): the terminal is back in
      // cooked mode once the agent has quit, and a ^C there is a SIGINT for the
      // whole foreground group, which a same-group sweep would die of
      // part-way. The launcher ignores SIGINT during teardown; this keeps the
      // sweep out of the signal's reach, and lets it finish on its own if the
      // launcher itself is ended (SIGTERM, a closed terminal) meanwhile.
      const sync = deps.runOnce(oneShot.cmd, [...oneShot.baseArgs, "sync", gitRoot, "--tool", "launcher"], { cwd: oneShot.cwd, env, timeoutMs: FS_SYNC_CLI_TIMEOUT_MS, ownSession: true });
      if (sync.status !== 0) {
        warn(`fs-view sync-back FAILED — agent changes remain in the AgentView worktree: ${(sync.stderr || sync.stdout).trim()}`);
      }
    },
  };
}
