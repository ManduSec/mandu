/**
 * git-shared-answers — one launch-time git question, asked once
 * (confidentiality.md §7.2a "Cost on a relaunch", "The same question
 * once"; runtime-instances.md §14.10).
 *
 * The history step (git-object-twins.ts prepareGitObjectTwins) and the
 * placeholder watch (placeholder-commits.ts preparePlaceholderWatch) run at
 * the same point of the launch, concurrently, after the twins are planned
 * and before the agent starts, and each asked the same repository the same
 * two questions: `rev-list --all --no-walk` (each work tree's tips) and
 * `ls-files -s -z -- <its protected files>` (their index entries). This
 * runner, scoped to those two callers and closed when both are done, starts
 * an identical call (the same arguments, work tree, stdin and environment)
 * once and hands its answer to both. Nothing is cached across launches nor
 * across a step that could change a repository: the prefetch's reads at
 * launch start keep their own runner (the step re-reads its facts fresh to
 * check them), and the placeholder check after the agent exits runs its own
 * calls on what git holds then.
 *
 * Each caller keeps its own failure handling and its own deadline:
 *
 *   - the answer is the call's (`{code, stdout, stderr}`, a failure
 *     included), so the step still refuses on a failed call (mustGit) and
 *     the watch still drops the tips or the repository;
 *   - a caller that joins a call whose deadline is as long as its own or
 *     longer waits at most its OWN deadline from when it asked, and gets
 *     the runner's cut-off answer (exit 1, the deadline named on stderr)
 *     past it, as its own call would have;
 *   - a caller that joins a call with a SHORTER deadline (the step, 120 s,
 *     joining the watch's 5 s call) takes its answer only when it
 *     succeeded; a failure (possibly a cut-off the caller would have
 *     outlived) is asked again under the caller's own deadline.
 *
 * A call that writes (`writable`: the pack build) is never shared.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import type { GitRun, GitRunner } from "./git-object-twins.js";
import { GIT_RUNNER_DEFAULT_TIMEOUT_MS, markProductionLike } from "./git-session.js";

interface Entry {
  run: Promise<GitRun>;
  deadlineMs: number;
}

export interface SharedGitAnswers {
  /** The runner both callers use. */
  readonly runner: GitRunner;
  /** Stop sharing: every later call is the base runner's own. Idempotent. */
  close(): void;
  /** Calls started on the base runner, and answers handed to a second
   *  caller (a test and log aid). */
  readonly stats: { started: number; shared: number };
}

/** The key of a call: everything that decides its answer but the
 *  deadline. Pure. */
export function sharedCallKey(args: readonly string[], opts: Parameters<GitRunner>[1]): string {
  const env = opts.env === undefined ? null : Object.entries(opts.env).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return JSON.stringify([args, opts.cwd, opts.input ?? null, env, opts.binary === true]);
}

/** `run`, or the runner's cut-off answer once `ms` pass. */
function within(run: Promise<GitRun>, ms: number): Promise<GitRun> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => resolve({ code: 1, stdout: "", stderr: `killed at its ${ms} ms deadline (an answer shared with another caller)` }), Math.max(1, ms));
    run.then((r) => { clearTimeout(t); resolve(r); }, (e: unknown) => { clearTimeout(t); reject(e); });
  });
}

/** A runner over `base` that asks each identical call once while open (the
 *  module comment). A production `base` makes it production too, so the
 *  step takes `git version` from the sandbox probe as before. */
export function shareGitAnswers(base: GitRunner): SharedGitAnswers {
  const calls = new Map<string, Entry>();
  const stats = { started: 0, shared: 0 };
  let closed = false;
  const start = (key: string, args: string[], opts: Parameters<GitRunner>[1], deadlineMs: number): Promise<GitRun> => {
    const run = base(args, opts);
    run.catch(() => undefined);
    calls.set(key, { run, deadlineMs });
    stats.started++;
    return run;
  };
  const runner: GitRunner = async (args, opts) => {
    if (closed || (opts.writable !== undefined && opts.writable.length > 0)) return base(args, opts);
    const key = sharedCallKey(args, opts);
    const deadlineMs = opts.timeoutMs ?? GIT_RUNNER_DEFAULT_TIMEOUT_MS;
    const e = calls.get(key);
    if (e === undefined) return start(key, args, opts, deadlineMs);
    if (e.deadlineMs >= deadlineMs) {
      stats.shared++;
      return within(e.run, deadlineMs);
    }
    const r = await e.run.catch(() => null);
    if (r !== null && r.code === 0) { stats.shared++; return r; }
    if (closed) return base(args, opts);
    const again = calls.get(key);
    if (again !== undefined && again !== e) {
      // Another caller asked again meanwhile: join it under the same rule.
      return runner(args, opts);
    }
    return start(key, args, opts, deadlineMs);
  };
  markProductionLike(runner, base);
  return {
    runner,
    stats,
    close(): void {
      closed = true;
      calls.clear();
    },
  };
}
