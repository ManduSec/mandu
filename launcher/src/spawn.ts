/**
 * spawn — compose the final argv, spawn the agent with stdio passthrough,
 * forward signals, propagate the exit code, and run post-exit hooks.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Adapted from launcher/mandu-run.sh: env-prefix order (L1191-1199),
 *   run-and-wait for post-exit (L1223-1228), exit-code propagation as a hard
 *   rule (L1287-1293), stdio passthrough (L1232). Post-exit ALWAYS runs (spec
 *   §5: agent crash → write-back + teardown still run). The agent-tree
 *   teardown hook (`tree`, portable-wrapper-cross-platform.md §3.5) is new.
 */
import { spawn, type ChildProcess } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import type { AgentTree, KillTreeResult, ScopePlan } from "./platform/types.js";
import { codexSpliceOverrides } from "./codex-argv.js";
import { gooseSpliceExtensions, isGooseBinary } from "./goose-argv.js";

/** Outer→inner: scope prefix, launch prefix, then agent argv[0] + splice + rest.
 *  For the codex binary the splice ALSO follows every subcommand
 *  (codex-argv.ts: a user's `exec -c …` would otherwise drop the routing).
 *  For the goose binary the splice (its `--with-extension` flags) goes after
 *  the `session` / `run` subcommand, whose flags they are (goose-argv.ts). */
export function buildFinalArgv(
  agentArgv: string[],
  argvPrefix: string[],
  scope: ScopePlan,
  launchPrefix: string[],
): string[] {
  const agent = isGooseBinary(agentArgv[0]) ? gooseSpliceExtensions(agentArgv, argvPrefix) : codexSpliceOverrides(agentArgv, argvPrefix);
  return [...scope.prefix, ...launchPrefix, ...agent];
}

/** A chain whose first process is already running: the early-started reply
 *  filter, handed the agent (reply-filter.ts). `exit` was taken from the
 *  moment it was spawned (childExit), so an exit before the adoption is not
 *  missed. */
export interface AdoptedChain {
  child: ChildProcess;
  exit: Promise<number>;
  /** When it was spawned (Date.now() ms): the tree's age floor (`tree.track`). */
  spawnedAtMs?: number;
}

export interface RunAgentOpts {
  argv: string[];
  /** Adopt this running chain instead of spawning `argv`. */
  adopted?: AdoptedChain;
  /** Relay the chain's stdin and stdout instead of passing the terminal
   *  through (`goose acp`, goose-acp-relay.ts): the chain is spawned with
   *  piped stdin / stdout (stderr stays the launcher's) and this is called
   *  once with them. Ignored for an adopted chain. */
  stdioRelay?: (chain: { stdin: Writable; stdout: Readable }) => void;
  env: Record<string, string | undefined>;
  cwd: string;
  detached: boolean;
  postExit?: () => Promise<void>;
  /** Called once the chain is done, with its first process's pid, before
   *  `postExit` (guard-death.ts ends what a dead guard left behind). */
  onChainExit?: (pid: number | undefined) => void;
  /** Armed once the chain has exited, BEFORE the forwarding handlers come
   *  off, so from there to the launcher's return a ^C never has SIGINT's
   *  default action (teardown-signals.ts). The caller disarms it. */
  teardown?: { arm(): void };
  /**
   * The agent-tree teardown (Platform.trackTree / killTree,
   * portable-wrapper-cross-platform.md §3.5). `track` gets the chain's first
   * pid right after the spawn; once the chain has exited, `end` ends what it
   * left running, BEFORE `onChainExit` and `postExit`, so nothing the agent
   * started outlives the services it was pointed at, and runAgent prints
   * `treeTeardownNote` when it stopped anything. Best-effort: a throw in
   * either never changes the exit code or skips `postExit`.
   */
  tree?: {
    /** `sinceMs`: when the chain was spawned (an adopted chain's own spawn
     *  time, else just now): the tree's age floor. */
    track(rootPid: number, sinceMs: number): AgentTree;
    end(tree: AgentTree): Promise<KillTreeResult>;
  };
}

/** The exit status of `child` as a shell reports it: the code, 128+n for a
 *  death by signal, 127 when it could not be spawned. Attach it as soon as
 *  the child is spawned. */
export function childExit(child: ChildProcess): Promise<number> {
  return new Promise((resolve) => {
    child.on("exit", (c, sig) => resolve(sig ? 128 + signo(sig) : (c ?? 0)));
    child.on("error", () => resolve(127));
  });
}

export async function runAgent(opts: RunAgentOpts): Promise<number> {
  const [cmd, ...args] = opts.argv;
  const relay = opts.adopted ? undefined : opts.stdioRelay;
  const spawnedAtMs = opts.adopted?.spawnedAtMs ?? Date.now();
  const child = opts.adopted?.child ?? spawn(cmd!, args, {
    cwd: opts.cwd,
    env: opts.env,
    // TUI-safe passthrough of the real terminal fds, or the relay's pipes
    stdio: relay ? ["pipe", "pipe", "inherit"] : "inherit",
    detached: opts.detached,
  });
  if (relay && child.stdin && child.stdout) relay({ stdin: child.stdin, stdout: child.stdout });
  let tree: AgentTree | undefined;
  if (opts.tree && child.pid !== undefined) {
    try { tree = opts.tree.track(child.pid, spawnedAtMs); } catch { /* untracked: nothing to end later */ }
  }
  const exited = opts.adopted?.exit ?? childExit(child);

  // SIGWINCH (spec §2.1): on the detached/pgid path the kernel delivers
  // terminal-resize to the wrapper's group, not the agent's — forward it so
  // the agent's TUI learns the terminal resized. Forward it to the child's
  // whole PROCESS GROUP when detached (setsid made the child a group leader):
  // the direct child is a `tsx` wrapper that relays SIGINT/SIGTERM only, so a
  // per-pid SIGWINCH died there and the reply-filter's inner script(1) — and
  // the TUI behind it — never learned the terminal resized (found by the
  // differential harness's resize-reflow scenario, 2026-09-05: vanilla
  // reflowed to 120 columns, the wrapped claude stayed at 80). A group
  // signal reaches every hop at once: the wrapper (ignores it), the real
  // reply-filter (forwards), the inner script(1) itself (re-copies the
  // winsize onto its pty, which raises SIGWINCH for the TUI) — on macOS BSD
  // script ignores SIGWINCH and the reply-filter's companion re-sizes the pty
  // instead (docs/design/agents/pty-relay.md §3).
  const forward = (sig: NodeJS.Signals) => {
    try {
      if (sig === "SIGWINCH" && opts.detached && child.pid) process.kill(-child.pid, sig);
      else child.kill(sig);
    } catch { /* child already gone */ }
  };
  const signals: NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP", "SIGWINCH"];
  for (const s of signals) process.on(s, forward);

  try {
    const code = await exited;
    if (tree) {
      try {
        const note = treeTeardownNote(await opts.tree!.end(tree));
        if (note) console.error(note);
      } catch { /* best-effort: never costs the exit code */ }
    }
    opts.onChainExit?.(child.pid);
    return code;
  } finally {
    // The teardown guard goes on BEFORE the forwarders come off: removing the
    // last SIGINT listener restores the default action at once.
    opts.teardown?.arm();
    for (const s of signals) process.off(s, forward);
    if (tree) await tree.stop().catch(() => { /* already stopped */ });
    if (opts.postExit) await opts.postExit();
  }
}

/** The one line the launcher prints when the session's end stopped processes
 *  the agent had left running (null when there were none). */
export function treeTeardownNote(r: KillTreeResult): string | null {
  if (r.terminated.length === 0 && r.survivors.length === 0) return null;
  const pids = (list: number[]) => list.slice(0, 5).join(", ") + (list.length > 5 ? ", …" : "");
  const n = r.terminated.length;
  let note = `mandu: the session ended, so ${n} process${n === 1 ? "" : "es"} the agent left running ` +
    `${n === 1 ? "was" : "were"} stopped (pid ${pids(r.terminated)})`;
  if (r.survivors.length) note += `; ${r.survivors.length} could not be stopped (pid ${pids(r.survivors)})`;
  return note;
}

function signo(sig: NodeJS.Signals): number {
  const map: Record<string, number> = { SIGINT: 2, SIGTERM: 15, SIGHUP: 1, SIGKILL: 9, SIGWINCH: 28 };
  return map[sig] ?? 15;
}
