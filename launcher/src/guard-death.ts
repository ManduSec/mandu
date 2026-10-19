/**
 * guard-death — a session whose guard died before its agent ends, and says so
 * (rootless-confinement-ubuntu-2404.md §12.2).
 *
 * The whole-agent guard (`mandu-net-guard`) records itself in a status file
 * the launcher names (`MANDU_NET_GUARD_STATUS`): `supervising <guard pid>
 * <child pid>` once it serves the agent tree, `exited <code>` when the tree
 * is done. A file still at `supervising` after the launch returned means the
 * guard stopped first: killed from outside (the agent itself cannot, see
 * guard_signals.rs) or crashed. A dead guard fails closed (every trapped
 * open, connect and exec returns ENOSYS) and its child dies with it
 * (PR_SET_PDEATHSIG), but processes the agent started live on, broken. The
 * launcher kills what is left of the session (its systemd scope, or the
 * processes of its session on the no-scope path) and prints why.
 *
 * `Mandu-new`.
 */
import { readFileSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";

/** Read by mandu-net-guard (src/bin/mandu-net-guard.rs STATUS_ENV). */
export const NET_GUARD_STATUS_ENV = "MANDU_NET_GUARD_STATUS";

export type GuardStatus =
  | { state: "supervising"; guard: number; child: number }
  | { state: "exited"; code: number }
  | null;

/** The status file's one line; null when absent or unreadable (the guard
 *  never supervised: not wrapped, degraded, or it failed to start). */
export function parseGuardStatus(text: string | null): GuardStatus {
  const line = (text ?? "").trim();
  let m = /^supervising (\d+) (\d+)$/.exec(line);
  if (m) return { state: "supervising", guard: Number(m[1]), child: Number(m[2]) };
  m = /^exited (-?\d+)$/.exec(line);
  if (m) return { state: "exited", code: Number(m[1]) };
  return null;
}

/** The line to print when the guard died before its tree; null otherwise. */
export function guardDeathNote(s: GuardStatus): string | null {
  if (s?.state !== "supervising") return null;
  return (
    `mandu: WARNING — the guard (mandu-net-guard, pid ${s.guard}) stopped before the agent did ` +
    "(killed from outside the session, or crashed); the session is ended: every file open, connect " +
    "and exec in the agent's processes would now fail (ENOSYS, fail-closed: nothing was exposed), so " +
    "the agent and what it started were stopped. Check `journalctl --user` or `dmesg` for an OOM kill, " +
    "then start the agent again."
  );
}

export interface EndSessionDeps {
  /** `systemctl --user <args>`; true on success. */
  systemctl(args: string[]): boolean;
  /** Pids whose session id is `sid`. */
  sessionPids(sid: number): number[];
  kill(pid: number, sig: NodeJS.Signals): void;
}

/** Kill what is left of a session: its systemd scope unit, or (the no-scope
 *  path, where the launch's first process leads a session of its own) every
 *  process of that session. The launcher itself is in neither. */
export function endSession(
  where: { scopeUnit: string } | { sessionLeader: number },
  deps: EndSessionDeps = realEndSessionDeps,
): void {
  if ("scopeUnit" in where) {
    deps.systemctl(["kill", "--signal=SIGKILL", where.scopeUnit]);
    return;
  }
  for (const pid of deps.sessionPids(where.sessionLeader)) {
    if (pid === process.pid) continue;
    try { deps.kill(pid, "SIGKILL"); } catch { /* already gone */ }
  }
}

/** Field 6 of /proc/<pid>/stat (the session id), after the parenthesized name. */
export function sessionOfStat(stat: string): number | null {
  const rest = stat.slice(stat.lastIndexOf(")") + 1).trim().split(/\s+/);
  const sid = Number(rest[3]);
  return Number.isInteger(sid) ? sid : null;
}

export const realEndSessionDeps: EndSessionDeps = {
  systemctl: (args) => spawnSync("systemctl", ["--user", ...args], { stdio: "ignore" }).status === 0,
  sessionPids: (sid) => {
    const out: number[] = [];
    let names: string[] = [];
    try { names = readdirSync("/proc"); } catch { return out; }
    for (const n of names) {
      if (!/^\d+$/.test(n)) continue;
      try {
        if (sessionOfStat(readFileSync(`/proc/${n}/stat`, "utf8")) === sid) out.push(Number(n));
      } catch { /* gone */ }
    }
    return out;
  },
  kill: (pid, sig) => process.kill(pid, sig),
};

/** After the launch returned: read the guard's status file and, when the
 *  guard died first, end the session and return the note to print. */
export function afterGuardedLaunch(
  statusFile: string,
  where: { scopeUnit: string } | { sessionLeader: number } | null,
  deps: EndSessionDeps = realEndSessionDeps,
  read: (p: string) => string | null = (p) => { try { return readFileSync(p, "utf8"); } catch { return null; } },
): string | null {
  const note = guardDeathNote(parseGuardStatus(read(statusFile)));
  if (note && where) endSession(where, deps);
  return note;
}
