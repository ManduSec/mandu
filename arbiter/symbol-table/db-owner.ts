/**
 * db-owner — LOUD single-writer ownership of the symbol DB file.
 *
 * The arbiter is the single writer of the symbol table (README architecture;
 * every interceptor is an IPC client). Until 2026-07-15 that was enforced by
 * convention only: a second arbiter opening the same DB — the
 * launcher/dashboard split-brain, a stray hand-started daemon — interleaved
 * writes SILENTLY, and the failure surfaced later as inexplicable symbol-table
 * state. This module turns the broken invariant into an immediate, diagnosable
 * refusal at startup (the fail-closed direction).
 *
 * Mechanism: an `<db>.owner` JSON lockfile created with O_EXCL, recording
 * `{pid, cmdline, startedAt}`. A conflicting acquire probes the recorded owner:
 *   - pid dead → stale (crashed/SIGKILLed owner) → steal;
 *   - pid alive but its CURRENT cmdline differs from the recorded one →
 *     pid reuse → stale → steal (the cmdline is /proc/<pid>/cmdline on Linux
 *     and `ps -o args=` where there is no /proc, e.g. darwin: processCmdline);
 *   - pid alive and cmdline matches (or cannot be read — fail closed) → refuse
 *     with SymbolDbOwnedError naming the owner.
 * Release unlinks only while the file still records OUR pid (a successor that
 * stole a stale lock must never lose it to the crasher's late cleanup).
 *
 * This is an app-level advisory lock on WRITER IDENTITY, not an SQLite lock:
 * read-only openers (none today by design) are unaffected, and the arbiter's
 * own per-operation connections never contend with it.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/** What the lockfile records about its owner. */
interface OwnerRecord {
  pid: number;
  cmdline: string | null;
  startedAt: string;
}

/** Probing the recorded owner — injectable for tests. */
export interface OwnerProbe {
  /** kill(pid, 0) semantics: true when the pid exists (EPERM counts as alive). */
  pidAlive(pid: number): boolean;
  /** The pid's command line (processCmdline), or null when unreadable. */
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

/** ps answers in a few ms; a hung one must not stall the arbiter's start. */
const PS_TIMEOUT_MS = 2_000;

export const realCmdlineSource: CmdlineSource = {
  platform: process.platform,
  readProcCmdline: (pid) => readFileSync(`/proc/${pid}/cmdline`, "utf8"),
  psArgs: (pid) =>
    execFileSync("/bin/ps", ["-ww", "-o", "args=", "-p", String(pid)], {
      encoding: "utf8",
      timeout: PS_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "ignore"],
    }),
};

/**
 * The command line of `pid` with NULs as spaces, trimmed, or null when it
 * cannot be read (dead pid, another user's process, a hung or failed probe).
 *
 * Linux reads /proc/<pid>/cmdline. A host without /proc (darwin) asks
 * `ps -ww -o args=` (unprivileged for the same user): the same argv area, so
 * the canonical `process.title` (`mandu-arbiter`, runtime-instances.md §7)
 * reads the same on both. Without this rung darwin recorded a null cmdline,
 * the pid-reuse test disappeared, and a stale lock whose pid had been
 * recycled refused every later arbiter start. Mirrors launcher/src/reap.ts
 * and dashboard/src/supervisor/socket-owner.ts (each package stays standalone).
 */
export function processCmdline(pid: number, src: CmdlineSource = realCmdlineSource): string | null {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    const raw = src.platform === "linux" ? src.readProcCmdline(pid).replaceAll("\0", " ") : src.psArgs(pid);
    return raw.trim() || null;
  } catch {
    return null;
  }
}

export const realOwnerProbe: OwnerProbe = {
  pidAlive(pid: number): boolean {
    try {
      process.kill(pid, 0);
      return true;
    } catch (e) {
      return (e as NodeJS.ErrnoException).code === "EPERM";
    }
  },
  cmdlineOf: (pid: number): string | null => processCmdline(pid),
};

export class SymbolDbOwnedError extends Error {
  constructor(
    readonly lockPath: string,
    readonly owner: OwnerRecord,
  ) {
    super(
      `symbol DB is already owned by a live arbiter (pid ${owner.pid}, started ${owner.startedAt}` +
        `${owner.cmdline ? `, cmdline: ${owner.cmdline}` : ""}) — refusing to start a second writer. ` +
        `The symbol table is single-writer; stop the other arbiter (mandu stop) or point this one ` +
        `at its own DB with --symbol-db <path>. Lock: ${lockPath}`,
    );
    this.name = "SymbolDbOwnedError";
  }
}

export interface SymbolDbOwner {
  lockPath: string;
  release(): void;
}

/**
 * Acquire single-writer ownership of `dbPath`, or throw SymbolDbOwnedError.
 * `self` defaults to this process; tests inject fake identities/probes.
 */
export function acquireSymbolDbOwner(
  dbPath: string,
  probe: OwnerProbe = realOwnerProbe,
  self: { pid: number } = { pid: process.pid },
): SymbolDbOwner {
  const lockPath = `${dbPath}.owner`;
  // Owner-only like the DB beside it (on-disk-layout.md §4): the record is no
  // secret, but nothing in the Mandu home is the agent's to read.
  mkdirSync(dirname(lockPath), { recursive: true, mode: 0o700 });
  const record: OwnerRecord = {
    pid: self.pid,
    cmdline: probe.cmdlineOf(self.pid),
    startedAt: new Date().toISOString(),
  };
  // Bounded retries cover the unlink-then-recreate races between two stealers:
  // exactly one wins the O_EXCL create; the loser re-reads a LIVE record and
  // refuses on the next pass.
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      writeFileSync(lockPath, JSON.stringify(record), { flag: "wx", mode: 0o600 });
      return makeOwner(lockPath, record.pid);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
    const existing = readRecord(lockPath);
    if (existing && isOwnerLive(existing, probe)) {
      throw new SymbolDbOwnedError(lockPath, existing);
    }
    // Corrupt record, dead pid, or reused pid → stale: remove and retry.
    try { unlinkSync(lockPath); } catch { /* raced with another stealer */ }
  }
  // Three straight EEXIST losses without a live owner: something is churning
  // the lock faster than we can claim it — refuse rather than write blind.
  const last = readRecord(lockPath);
  throw new SymbolDbOwnedError(lockPath, last ?? { pid: -1, cmdline: null, startedAt: "unknown" });
}

function readRecord(lockPath: string): OwnerRecord | null {
  try {
    const parsed = JSON.parse(readFileSync(lockPath, "utf8")) as Partial<OwnerRecord>;
    if (typeof parsed.pid !== "number") return null;
    return {
      pid: parsed.pid,
      cmdline: typeof parsed.cmdline === "string" ? parsed.cmdline : null,
      startedAt: typeof parsed.startedAt === "string" ? parsed.startedAt : "unknown",
    };
  } catch {
    return null; // unreadable/corrupt → stale
  }
}

/** Live = pid exists AND (recorded cmdline unknown, or it still matches —
 *  a mismatch means the pid was recycled by an unrelated process). When the
 *  CURRENT cmdline is unreadable while the pid exists, stay fail-closed:
 *  treat the owner as live and refuse. */
function isOwnerLive(record: OwnerRecord, probe: OwnerProbe): boolean {
  if (!probe.pidAlive(record.pid)) return false;
  if (record.cmdline === null) return true;
  const now = probe.cmdlineOf(record.pid);
  if (now === null) return true;
  return now === record.cmdline;
}

function makeOwner(lockPath: string, pid: number): SymbolDbOwner {
  return {
    lockPath,
    release(): void {
      // Unlink only while the file still records OUR pid — never delete a
      // successor's lock (mirror of the socket boundInode guard in server.ts).
      const current = readRecord(lockPath);
      if (current?.pid !== pid) return;
      try { unlinkSync(lockPath); } catch { /* already gone */ }
    },
  };
}
