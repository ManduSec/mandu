/**
 * platform/types — the narrow OS-abstraction the orchestrator branches on.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. Replaces the Linux-only systemd/proc idioms scattered
 *   through launcher/mandu-run.sh with one interface; the ONLY place
 *   process.platform is read is platform/index.ts (spec §2 "one rule").
 */

/** A probe verdict for an optional facility. */
export type Availability = { available: true } | { available: false; reason: string };

/** How the agent process tree is scoped for attribution + reaping. */
export interface ScopePlan {
  /** argv prefix that performs scoping (e.g. systemd-run … --), or [] for pgid. */
  prefix: string[];
  /** Spawn the child detached into its own process group (the pgid path). */
  detached: boolean;
}

export interface Platform {
  id: "linux" | "darwin" | "win32";
  /**
   * The DEFAULT runtime base (the runtime-base.ts rule, rules 2–4:
   * `$XDG_RUNTIME_DIR/mandu`, else `$TMPDIR/mandu` when an instance socket
   * fits, else the private `/tmp/mandu-<uid>`; runtime-instances.md §3b).
   * `MANDU_RUNTIME_DIR` is NOT applied, so this is the scope-dir root (the
   * same base parse.ts roots scope dirs in), not necessarily where the
   * arbiter socket lives.
   */
  runtimeDir(env: Record<string, string | undefined>): string;
  /**
   * Decide the scope mechanism. `commandExists` is injected so this is unit
   * testable without probing the host. env is marshalled into the systemd
   * scope via --setenv when the systemd prefix is used.
   */
  planScope(args: {
    scopeId: string;
    env: Record<string, string>;
    noScope: boolean;
    commandExists: (cmd: string) => boolean;
    systemdUserOk: () => boolean;
  }): ScopePlan;
  /** Enumerate descendant pids of the agent for observation/teardown. */
  agentTree(pid: number): Promise<number[]>;
  /**
   * Start tracking the agent's process tree, rooted at the launch chain's
   * first process, so `killTree` can end what it leaves behind
   * (portable-wrapper-cross-platform.md §3.5). Called right after the spawn.
   */
  trackTree(rootPid: number, opts?: TrackTreeOpts): AgentTree;
  /**
   * After the chain exited: end every surviving process of `tree` (SIGTERM,
   * a grace, then SIGKILL). Never Mandu's own services, the launcher, the
   * user's shell or anything the agent did not start. Where the platform
   * already contains the tree by other means (Linux: the systemd scope, the
   * twin wrap's PID namespace) it does nothing and says why in `skipped`.
   */
  killTree(tree: AgentTree, opts?: KillTreeOpts): Promise<KillTreeResult>;
}

/** The handle `trackTree` returns; `killTree` reads what it recorded. */
export interface AgentTree {
  readonly rootPid: number;
  /** Record the tree now (the platform also samples on its own timer). */
  sample(): Promise<void>;
  /** Stop sampling; resolves once an in-flight sample has landed. */
  stop(): Promise<void>;
}

export interface TrackTreeOpts {
  /** How often the tree is sampled while the chain runs (ms). */
  intervalMs?: number;
  /**
   * When the chain's first process was spawned (Date.now() ms): the age
   * floor, nothing older is the agent's. Default: now, right after the spawn.
   * A chain started earlier and adopted (the reply filter started with the
   * services, reply-filter.ts) passes its own spawn time, or the root and the
   * filter's processes read as older than the launch and the whole tree is
   * missed (the macOS wrapper suite, 2026-10-09).
   */
  sinceMs?: number;
}

export interface KillTreeOpts {
  /** How long the survivors get between SIGTERM and SIGKILL (ms). */
  graceMs?: number;
  /** A first look waits this long for what is exiting on its own (ms). */
  settleMs?: number;
}

export interface KillTreeResult {
  /** Pids sent SIGTERM. */
  terminated: number[];
  /** Pids still alive after the grace, sent SIGKILL. */
  killed: number[];
  /** Pids still alive after the SIGKILL rounds (should stay empty). */
  survivors: number[];
  /** Set when this platform does not tear the tree down itself, and why. */
  skipped?: string;
}
