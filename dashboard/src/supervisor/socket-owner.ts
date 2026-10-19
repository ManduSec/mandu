/**
 * socket-owner — unprivileged discovery of WHICH process listens on a unix
 * socket path (Mandu-new, no reference origin).
 *
 * Why it exists: an ADOPTED daemon that never answers the arbiter `hello`
 * handshake used to leave the control panel's Replace action with no verified
 * target — the row dead-ended in "kill whatever listens on <sock> yourself".
 * But the kernel hands an unprivileged same-uid user exactly this information:
 * `/proc/net/unix` maps the bound path to the socket inode, and a
 * `/proc/<pid>/fd` scan maps the inode to its owner pid. The non-root-privilege
 * principle (docs/design/architecture/privilege-model.md §0) makes leaving that unused a gap
 * to close, not a design choice.
 *
 * Hosts without /proc (darwin) take a second rung: `lsof -U` lists this
 * user's unix sockets by the path they were bound to (a listener and its
 * accepted connections; a connecting client shows `->0x…`, never the path),
 * and `ps -o args=` supplies the command line. Unprivileged for the same user,
 * like the /proc walk. A path held by more than one process (an unlinked
 * socket still open in an old daemon, the same path bound again by a new one)
 * is ambiguous and answers null rather than guess.
 *
 * Scope-honest limits: same pid namespace and same uid only (other users'
 * `/proc/<pid>/fd` are unreadable; a container's daemon is invisible) — the
 * caller must treat null as "not findable from here", never "nothing listens".
 * discoverUnixSocketOwner never throws: a missing /proc, a missing or hung
 * lsof, any probe error is that same null. Unix sockets only; the TCP proxies
 * never carry the adopted-identity problem this solves today.
 */

import { execFileSync, spawnSync } from "node:child_process";
import { readdirSync, readFileSync, readlinkSync, realpathSync } from "node:fs";

export interface SocketOwner {
  pid: number;
  /** The owner's command line (procCmdlineOf), null when unreadable. */
  cmdline: string | null;
}

/** Injectable /proc access for unit tests (the shape discoverUnixSocketOwner
 *  fills with the real filesystem by default). */
export interface ProcDeps {
  procNetUnix(): string;
  realpath(p: string): string;
  listPids(): number[];
  listFdLinks(pid: number): string[];
  cmdlineOf(pid: number): string | null;
}

/** Where a command line is read from — injectable for tests. */
export interface CmdlineSource {
  platform: NodeJS.Platform;
  /** Raw `/proc/<pid>/cmdline` (NUL-separated); throws when unreadable. */
  readProcCmdline(pid: number): string;
  /** `ps -ww -o args= -p <pid>`; throws when ps fails (no such pid) or hangs. */
  psArgs(pid: number): string;
}

export const realCmdlineSource: CmdlineSource = {
  platform: process.platform,
  readProcCmdline: (pid) => readFileSync(`/proc/${pid}/cmdline`, "utf8"),
  psArgs: (pid) =>
    execFileSync("/bin/ps", ["-ww", "-o", "args=", "-p", String(pid)], {
      encoding: "utf8",
      timeout: 2_000,
      stdio: ["ignore", "pipe", "ignore"],
    }),
};

/** A pid's command line with NULs as spaces, trimmed, or null when unreadable
 *  (dead pid, another user, a container's pid namespace, a failed probe).
 *  Linux reads /proc/<pid>/cmdline; a host without /proc (darwin) asks
 *  `ps -ww -o args=` — the same argv area, so the canonical `mandu-arbiter`
 *  title reads the same on both. The same probe as launcher/src/reap.ts and
 *  arbiter/symbol-table/db-owner.ts processCmdline (each package stays
 *  standalone). */
export function procCmdlineOf(pid: number, src: CmdlineSource = realCmdlineSource): string | null {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    const raw = src.platform === "linux" ? src.readProcCmdline(pid).replaceAll("\0", " ") : src.psArgs(pid);
    return raw.trim() || null;
  } catch {
    return null;
  }
}

const realDeps: ProcDeps = {
  // No /proc (darwin, a masked /proc): nothing listed, so nothing is found —
  // the documented null, never a thrown ENOENT.
  procNetUnix: () => {
    try {
      return readFileSync("/proc/net/unix", "utf8");
    } catch {
      return "";
    }
  },
  realpath: (p) => realpathSync(p),
  listPids: () => {
    try {
      return readdirSync("/proc").filter((d) => /^\d+$/.test(d)).map(Number);
    } catch {
      return [];
    }
  },
  listFdLinks: (pid) => {
    // EACCES (another user) / ESRCH (gone) → no links; the scan just moves on.
    try {
      return readdirSync(`/proc/${pid}/fd`).map((fd) => {
        try {
          return readlinkSync(`/proc/${pid}/fd/${fd}`);
        } catch {
          return "";
        }
      });
    } catch {
      return [];
    }
  },
  cmdlineOf: procCmdlineOf,
};

/**
 * The LISTENER inode for a bound unix-socket path, from /proc/net/unix.
 * Format: `Num RefCount Protocol Flags Type St Inode Path` — accepted peer
 * sockets list the same path with St=03, so the listener is selected by St=01.
 * Paths are compared through realpath so a promotion symlink spelling
 * (`current/arbiter.sock`) matches the instance-dir path the daemon bound.
 */
export function inodeForUnixSocket(sockPath: string, deps: ProcDeps = realDeps): string | null {
  let target: string;
  try {
    target = deps.realpath(sockPath);
  } catch {
    return null; // the socket file itself is gone — nothing to own
  }
  for (const line of deps.procNetUnix().split("\n")) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 8) continue; // header or pathless (unbound) socket row
    const [, , , , , st, inode] = parts;
    const path = parts.slice(7).join(" ");
    if (st !== "01") continue; // not the listener (01 = unconnected+listening)
    if (path !== sockPath && path !== target) {
      let real: string;
      try {
        real = deps.realpath(path);
      } catch {
        continue;
      }
      if (real !== target) continue;
    }
    return inode ?? null;
  }
  return null;
}

/** The pid holding `socket:[inode]` open, via a same-uid /proc fd sweep. */
export function pidOwningSocketInode(inode: string, deps: ProcDeps = realDeps): number | null {
  const needle = `socket:[${inode}]`;
  for (const pid of deps.listPids()) {
    if (pid === process.pid) continue; // never report ourselves (an in-process probe socket)
    if (deps.listFdLinks(pid).includes(needle)) return pid;
  }
  return null;
}

/** Injectable lsof access for the darwin rung. */
export interface LsofDeps {
  /** `lsof -F pn` field output over this user's unix sockets: `p<pid>`
   *  starts a process, `n<name>` names one of its sockets ("" when lsof is
   *  missing, fails or hangs). */
  lsofUnix(): string;
  realpath(p: string): string;
  cmdlineOf(pid: number): string | null;
  /** This process (never reported: an in-process probe socket is not a target). */
  selfPid: number;
}

const LSOF_TIMEOUT_MS = 3_000;

const realLsofDeps: LsofDeps = {
  lsofUnix: () => {
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    const args = ["-w", "-n", "-P", "-a", "-U", ...(uid === null ? [] : ["-u", String(uid)]), "-F", "pn"];
    // lsof exits 1 when a selection matched nothing; the output is still the answer.
    const r = spawnSync("/usr/sbin/lsof", args, {
      encoding: "utf8",
      timeout: LSOF_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "ignore"],
      maxBuffer: 16 * 1024 * 1024,
    });
    return r.error ? "" : (r.stdout ?? "");
  },
  realpath: (p) => realpathSync(p),
  cmdlineOf: (pid) => procCmdlineOf(pid),
  selfPid: process.pid,
};

/** The darwin rung: the one pid (other than this process) holding a unix
 *  socket bound to `sockPath`, from `lsof -F pn` output. Names are compared
 *  literally and through realpath (the daemon bound `instances/<id>/…` under
 *  a `/tmp` or `/var` spelling; the caller probes `current/…`). Null when the
 *  socket file is gone, nothing matches, or more than one process holds the
 *  path (ambiguous: never guess a kill target). */
export function lsofUnixSocketOwner(sockPath: string, deps: LsofDeps = realLsofDeps): SocketOwner | null {
  let target: string;
  try {
    target = deps.realpath(sockPath);
  } catch {
    return null; // the socket file itself is gone — nothing to own
  }
  const pids = new Set<number>();
  let pid = 0;
  for (const line of deps.lsofUnix().split("\n")) {
    if (line.startsWith("p")) {
      pid = Number(line.slice(1));
      continue;
    }
    if (!line.startsWith("n/") || !(Number.isSafeInteger(pid) && pid > 0) || pid === deps.selfPid) continue;
    const name = line.slice(1);
    if (name !== sockPath && name !== target) {
      let real: string;
      try {
        real = deps.realpath(name);
      } catch {
        continue;
      }
      if (real !== target) continue;
    }
    pids.add(pid);
  }
  if (pids.size !== 1) return null;
  const [owner] = [...pids];
  return { pid: owner!, cmdline: deps.cmdlineOf(owner!) };
}

/** One-shot: the verified owner of a listening unix socket, or null when not
 *  findable from this process (see the scope-honest limits above). Linux (or
 *  injected ProcDeps) walks /proc; a host without /proc asks lsof. Never
 *  throws. */
export function discoverUnixSocketOwner(sockPath: string, deps?: ProcDeps): SocketOwner | null {
  try {
    if (deps === undefined && process.platform !== "linux") return lsofUnixSocketOwner(sockPath);
    const d = deps ?? realDeps;
    const inode = inodeForUnixSocket(sockPath, d);
    if (!inode) return null;
    const pid = pidOwningSocketInode(inode, d);
    if (pid === null) return null;
    return { pid, cmdline: d.cmdlineOf(pid) };
  } catch {
    return null;
  }
}
