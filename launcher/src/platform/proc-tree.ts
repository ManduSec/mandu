/**
 * platform/proc-tree — the agent's process tree where the only scope is a
 * process group (darwin): sampled while the launch chain runs, ended after it
 * exits (portable-wrapper-cross-platform.md §3.5).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. The spec (§5) named `tree-kill` (a `pgrep -P` walk from the
 *   root at kill time); that walk finds nothing here, see below, so the
 *   tracking is Mandu's own. The pure planning (`parsePsTable`, `observe`) is
 *   unit-tested on injected `ps` tables; only `readPsTable` touches the host.
 *
 * Why a walk from the root at exit time is not enough on macOS:
 *   - When the chain's first process exits, everything it left running is
 *     reparented to launchd (ppid 1): no parent walk reaches it any more.
 *   - The chain's process group is not the tree either: BSD script(1) (the
 *     reply-filter's PTY relay) runs the agent in a session of its own, and
 *     Claude Code starts every Bash command, hook and background task in a new
 *     session (it spawns them detached).
 *   - macOS has no session id to ask for: `ps -o sess` prints a zeroed kernel
 *     pointer, pgrep has no -s, and `ps -E` shows no other process's
 *     environment (measured on macOS 26.5.1).
 *
 * So the tracker keeps two sets, both read from ONE `ps` table per sample:
 *   - members: every process ever seen in the tree, by pid AND start time
 *     (`lstart`), so a recycled pid is a different process;
 *   - groups: every process group a member was seen in. Such a group belongs
 *     to a session an agent process created (setsid only ever makes a NEW
 *     session; setpgid only joins a group of the caller's own session), so
 *     every process in it was started by the agent, including a child forked
 *     after the last sample whose parent has since exited. A group is trusted
 *     only while it lives: once a table shows no process in it (it emptied),
 *     or shows its id as a different process's pid (recycled), it is dropped.
 * At teardown a fresh table names the targets: live members, live processes
 * of a recorded group, and every live descendant of either. Never a target:
 * anything older than the launch (the age floor), the launcher, its
 * ancestors (the user's shell), its process group, pid 0/1, zombies.
 *
 * The residual (§3.5): a process that moves to a new session AND loses its
 * parent within one sampling interval is never seen (a double-fork daemon, or
 * `cmd &` in a Bash tool call that returns at once), so it outlives the
 * session. The kernel-backed answer is Linux's PID namespace / cgroup; macOS
 * has no unprivileged equivalent.
 */
import { execFile } from "node:child_process";
import type { AgentTree, KillTreeOpts, KillTreeResult } from "./types.js";

/** One process as `ps` reports it (under PS_ENV). */
export interface ProcRow {
  pid: number;
  ppid: number;
  pgid: number;
  /** `ps` state letters; a leading Z is a zombie. */
  stat: string;
  /** Seconds since the process started (`etime`), for the age floor. */
  ageSec: number;
  /** `lstart` (in UTC: PS_ENV), whitespace-collapsed: the identity token beside the pid. */
  start: string;
}

/** What the tracker learned about the tree while the chain ran. */
export interface TreeRecord {
  rootPid: number;
  /** Date.now() when tracking began: the chain had just been spawned. */
  sinceMs: number;
  /** pid -> start token of every process seen in the tree. */
  members: Map<number, string>;
  /** Process groups a member was seen in. */
  groups: Set<number>;
}

/** The launcher side of a teardown: who is asking, and when. */
export interface Observer {
  selfPid: number;
  nowMs: number;
}

/** `etime` and `lstart` have one-second resolution, and the root was spawned
 *  just before tracking began: a process up to this much older than the
 *  launch still counts as started by it. */
export const AGE_SLACK_MS = 2000;

/** The `ps` argv the darwin reader runs (under PS_ENV: a fixed lstart shape). */
export const PS_ARGV = ["-x", "-o", "pid=,ppid=,pgid=,stat=,etime=,lstart="];

/**
 * The environment every `ps` read of a start time runs under: the C locale (a
 * fixed `lstart` shape) and UTC. `lstart` is rendered in the local time zone,
 * so without TZ a zone change mid-session (automatic time zone on a laptop)
 * rewrote every member's start token: the member check failed, each member's
 * own group read as recycled, and the teardown found nothing. `reap.ts` reads
 * an arbiter's start time under the same env.
 */
export const PS_ENV: Readonly<Record<string, string>> = { LC_ALL: "C", TZ: "UTC0", PATH: "/usr/bin:/bin" };

/** `[[dd-]hh:]mm:ss` → seconds; NaN when it is not that shape. */
export function parseEtime(s: string): number {
  const m = /^(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)$/.exec(s.trim());
  if (!m) return NaN;
  return Number(m[1] ?? 0) * 86400 + Number(m[2] ?? 0) * 3600 + Number(m[3]) * 60 + Number(m[4]);
}

/** Parse `ps -o pid=,ppid=,pgid=,stat=,etime=,lstart=` output. Lines that do
 *  not have that shape are dropped (a dropped row is never a target). */
export function parsePsTable(text: string): ProcRow[] {
  const rows: ProcRow[] = [];
  for (const line of text.split("\n")) {
    const m = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S.*?)\s*$/.exec(line);
    if (!m) continue;
    const ageSec = parseEtime(m[5]!);
    if (!Number.isFinite(ageSec)) continue;
    rows.push({
      pid: Number(m[1]), ppid: Number(m[2]), pgid: Number(m[3]),
      stat: m[4]!, ageSec, start: m[6]!.replace(/\s+/g, " "),
    });
  }
  return rows;
}

export function newTreeRecord(rootPid: number, sinceMs: number): TreeRecord {
  return { rootPid, sinceMs, members: new Map(), groups: new Set() };
}

/** Pids descended (by ppid) from `rootPid` in `rows`, the root excluded. */
export function descendantPids(rows: ProcRow[], rootPid: number): number[] {
  const kids = childrenIndex(rows);
  const out: number[] = [];
  const seen = new Set<number>([rootPid]);
  const queue = [rootPid];
  while (queue.length) {
    for (const c of kids.get(queue.shift()!) ?? []) {
      if (seen.has(c.pid)) continue;
      seen.add(c.pid); out.push(c.pid); queue.push(c.pid);
    }
  }
  return out;
}

function childrenIndex(rows: ProcRow[]): Map<number, ProcRow[]> {
  const kids = new Map<number, ProcRow[]>();
  for (const r of rows) {
    const list = kids.get(r.ppid);
    if (list) list.push(r); else kids.set(r.ppid, [r]);
  }
  return kids;
}

/**
 * The tree's live processes in `rows`, recorded into `rec` (members and their
 * groups) so a later table still knows them after they are reparented. The
 * one planner for sampling and teardown alike.
 */
export function observe(rec: TreeRecord, rows: ProcRow[], who: Observer): ProcRow[] {
  const byPid = new Map(rows.map((r) => [r.pid, r]));
  const self = byPid.get(who.selfPid);
  // The launcher and every ancestor (the user's shell, its terminal, launchd).
  const excluded = new Set<number>([0, 1, who.selfPid]);
  for (let p = self?.ppid; p !== undefined && !excluded.has(p); p = byPid.get(p)?.ppid) excluded.add(p);
  const selfPgid = self?.pgid;
  const sinceLaunchMs = who.nowMs - rec.sinceMs + AGE_SLACK_MS;
  const young = (r: ProcRow): boolean => r.ageSec * 1000 <= sinceLaunchMs;
  const eligible = (r: ProcRow): boolean =>
    !excluded.has(r.pid) && !r.stat.startsWith("Z") && r.pgid !== selfPgid && young(r);
  // A recorded group whose id is now a DIFFERENT process's pid was recycled
  // (it emptied and the pid came back): its current members are not ours. A
  // leader that is merely a zombie still names the same group.
  const recycled = (g: number): boolean => {
    const leader = byPid.get(g);
    if (!leader) return false;
    const known = rec.members.get(g);
    return (known !== undefined && known !== leader.start) || !young(leader) || excluded.has(g);
  };
  // Expire groups BEFORE seeding: a group id is trusted only while the group
  // lives. One that no row carries any more has emptied, and the kernel frees
  // its id with it, so the id can only come back as the pid of a NEW leader:
  // someone else's group, even after that leader exits and leaves its members
  // behind (the case `recycled` cannot see, having no leader to compare). One
  // that `recycled` flags is someone else's already. A sample comes every
  // second, far too soon for a group to empty, its id to lead a new group and
  // that leader to exit again in between.
  const carried = new Set(rows.map((r) => r.pgid));
  for (const g of rec.groups) if (!carried.has(g) || recycled(g)) rec.groups.delete(g);
  const isSeed = (r: ProcRow): boolean => {
    if (!eligible(r)) return false;
    const known = rec.members.get(r.pid);
    if (known !== undefined) return known === r.start || rec.groups.has(r.pgid);
    if (r.pid === rec.rootPid) return true;
    return rec.groups.has(r.pgid);
  };
  const kids = childrenIndex(rows);
  const found = new Map<number, ProcRow>();
  const queue = rows.filter(isSeed);
  for (const r of queue) found.set(r.pid, r);
  while (queue.length) {
    for (const c of kids.get(queue.shift()!.pid) ?? []) {
      if (found.has(c.pid) || !eligible(c)) continue;
      found.set(c.pid, c); queue.push(c);
    }
  }
  const out = [...found.values()];
  for (const r of out) {
    rec.members.set(r.pid, r.start);
    if (r.pgid > 1) rec.groups.add(r.pgid);
  }
  return out;
}

/** The host side of a teardown, injectable for tests. */
export interface TreeDeps {
  /** The process table, or null when it could not be read (then nothing is signalled). */
  table(): Promise<ProcRow[] | null>;
  kill(pid: number, sig: NodeJS.Signals): void;
  sleep(ms: number): Promise<void>;
  now(): number;
  selfPid: number;
}

/**
 * End every live process of the recorded tree: SIGTERM (with SIGCONT, so a
 * stopped process handles it), re-looking every `pollMs` for what is left
 * or newly forked, then SIGKILL after `graceMs`. Each signal goes to a pid
 * the table just listed as a target (no group signals: a group id is never
 * trusted past the table that confirmed it).
 */
export async function endTree(rec: TreeRecord, deps: TreeDeps, opts: KillTreeOpts & { pollMs?: number } = {}): Promise<KillTreeResult> {
  const graceMs = opts.graceMs ?? 2000;
  const settleMs = opts.settleMs ?? 250;
  const pollMs = opts.pollMs ?? 100;
  const look = async (): Promise<ProcRow[]> => {
    const rows = await deps.table();
    return rows ? observe(rec, rows, { selfPid: deps.selfPid, nowMs: deps.now() }) : [];
  };
  const signal = (pid: number, sig: NodeJS.Signals): void => {
    try { deps.kill(pid, sig); } catch { /* gone, or not ours to signal */ }
  };

  let targets = await look();
  // What is exiting on its own (an MCP server on its stdin EOF) is not "left running".
  if (targets.length && settleMs > 0) { await deps.sleep(settleMs); targets = await look(); }

  const terminated: number[] = [];
  const termed = new Set<string>();
  const term = (rows: ProcRow[]): void => {
    for (const r of rows) {
      const key = `${r.pid}@${r.start}`;
      if (termed.has(key)) continue;
      termed.add(key); terminated.push(r.pid);
      signal(r.pid, "SIGTERM");
      signal(r.pid, "SIGCONT");
    }
  };
  term(targets);
  const deadline = deps.now() + graceMs;
  while (targets.length && deps.now() < deadline) {
    await deps.sleep(pollMs);
    targets = await look();
    term(targets); // forked during the grace: it gets its SIGTERM too
  }
  const killed: number[] = [];
  for (let round = 0; round < 3 && targets.length; round++) {
    for (const r of targets) {
      if (!killed.includes(r.pid)) killed.push(r.pid);
      signal(r.pid, "SIGKILL");
    }
    await deps.sleep(pollMs);
    targets = await look();
  }
  return { terminated, killed, survivors: targets.map((r) => r.pid) };
}

/**
 * The live tracker `trackTree` returns: one sample at once, then every
 * `intervalMs` (unref'd: it never keeps the launcher alive).
 */
export class ProcTreeTracker implements AgentTree {
  readonly record: TreeRecord;
  private readonly timer: NodeJS.Timeout;
  private inflight: Promise<void> | null = null;
  private stopped = false;

  constructor(
    readonly rootPid: number,
    private readonly deps: Pick<TreeDeps, "table" | "now" | "selfPid">,
    intervalMs: number,
    /** The chain's spawn time (TrackTreeOpts.sinceMs); default now. */
    sinceMs?: number,
  ) {
    this.record = newTreeRecord(rootPid, Math.min(sinceMs ?? deps.now(), deps.now()));
    this.timer = setInterval(() => { void this.sample(); }, intervalMs);
    this.timer.unref();
    void this.sample();
  }

  sample(): Promise<void> {
    if (this.stopped) return Promise.resolve();
    if (this.inflight) return this.inflight;
    this.inflight = (async () => {
      const rows = await this.deps.table();
      if (rows) observe(this.record, rows, { selfPid: this.deps.selfPid, nowMs: this.deps.now() });
    })().catch(() => { /* a failed sample is a gap, not an error */ }).finally(() => { this.inflight = null; });
    return this.inflight;
  }

  async stop(): Promise<void> {
    this.stopped = true;
    clearInterval(this.timer);
    await this.inflight;
  }
}

/** A tree nobody samples (a platform whose kernel scope holds the tree). */
export function inertTree(rootPid: number): AgentTree {
  return { rootPid, sample: async () => {}, stop: async () => {} };
}

/** How `readPsTable` runs `ps` (node's execFile shape), injectable for tests. */
export type PsRunner = (
  file: string,
  args: readonly string[],
  opts: { env: Record<string, string>; timeout: number; maxBuffer: number },
  done: (err: Error | null, stdout: string) => void,
) => void;

const execPs: PsRunner = (file, args, opts, done) => {
  execFile(file, args, { ...opts, encoding: "utf8" }, (err, stdout) => done(err, stdout));
};

/** The darwin process table: this user's processes (`ps -x`), under PS_ENV. */
export function readPsTable(run: PsRunner = execPs): Promise<ProcRow[] | null> {
  return new Promise((resolve) => {
    run(
      "/bin/ps", PS_ARGV,
      { env: { ...PS_ENV }, timeout: 5000, maxBuffer: 16 * 1024 * 1024 },
      (err, stdout) => resolve(err ? null : parsePsTable(String(stdout))),
    );
  });
}

export const realTreeDeps: TreeDeps = {
  table: () => readPsTable(),
  kill: (pid, sig) => { process.kill(pid, sig); },
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  now: () => Date.now(),
  selfPid: process.pid,
};
