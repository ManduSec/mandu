/**
 * wire-release-sessions — the sessions whose egress proxy terminates TLS, as
 * the launch that started the proxy said it (`registerWireRelease`, plan 10
 * §11.13.1).
 *
 * Mandu-new (no reference origin).
 *
 * The session's word decides whether npm is served the `.npmrc` twin (the
 * proxy puts each registry token back at its own registry) or reads the file
 * raw as a confined reader. It is a HUMAN-PLANE op: only the launcher, which
 * started the proxy, may say the proxy inspects TLS.
 *
 * Until 2026-10-17 the word lived in the arbiter's memory only, so an
 * arbiter restarted under a live session forgot it and npm read `.npmrc`
 * raw again until the next launch. That direction is fail-closed (npm and
 * the `npx` MCP servers it starts hold the token, their output is masked,
 * their sends are held to the token's own registry; no byte leaks), but the
 * session loses what the twin was for. The word is now also written to
 * mandu.db with the launcher's pid and that pid's start time, as the auth
 * grants are (auth-grants.ts): a restarted arbiter takes back the sessions
 * whose launcher still runs (same pid, same start time), never one whose
 * launch ended. A row holds a session key, the session's `NO_PROXY` hosts
 * and the launcher's pid: no value. The session's end drops it (the
 * launcher's `inspecting: false`, or the launcher being gone at the next
 * write or start). A word sent without a pid (an older launcher), or whose
 * pid this process cannot see, stays in memory only: the old behaviour.
 */
import Database from "../db/sqlite.js";
import { pidExists, procStartTime } from "../policy/cache-seals.js";

/** One session's word: the hosts npm reaches around the proxy. */
export interface WireReleaseSession {
  direct: string[];
}

/** At most this many `NO_PROXY` entries are kept per session. */
export const MAX_DIRECT_HOSTS = 256;

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS wire_release_sessions (
  session_key   TEXT PRIMARY KEY,
  direct        TEXT NOT NULL,
  pid           INTEGER NOT NULL,
  pid_start     TEXT,
  registered_at INTEGER NOT NULL
);
`;

export interface WireReleaseStoreOptions {
  /** mandu.db: a word with a launcher pid is kept there across a restart.
   *  Absent: memory only (a unit test's store). */
  dbPath?: string;
  /** Liveness seams (tests). */
  pidExists?: (pid: number) => boolean;
  procStartTime?: (pid: number) => string | null;
  now?: () => number;
}

/** Read a stored or sent `direct` list: strings only, at most
 *  {@link MAX_DIRECT_HOSTS}; anything else is none. Pure. */
export function parseDirectHosts(raw: unknown): string[] {
  return Array.isArray(raw) ? raw.filter((d): d is string => typeof d === "string").slice(0, MAX_DIRECT_HOSTS) : [];
}

/** The sessions of this arbiter's life whose proxy inspects TLS (and, with a
 *  DB, those of the launchers still alive across a restart). */
export class WireReleaseStore {
  private readonly sessions = new Map<string, WireReleaseSession & { pid?: number }>();
  private readonly db: InstanceType<typeof Database> | null;
  private readonly exists: (pid: number) => boolean;
  private readonly startOf: (pid: number) => string | null;
  private readonly now: () => number;
  /** How many persisted sessions the start took back (a log line, a test). */
  readonly restored: number;

  constructor(opts: WireReleaseStoreOptions = {}) {
    this.exists = opts.pidExists ?? pidExists;
    this.startOf = opts.procStartTime ?? ((pid) => procStartTime(pid));
    this.now = opts.now ?? Date.now;
    this.db = opts.dbPath !== undefined ? new Database(opts.dbPath) : null;
    let restored = 0;
    if (this.db) {
      this.db.pragma("journal_mode = WAL");
      this.db.exec(SCHEMA_SQL);
      // Read only here (an arbiter whose start is then refused writes
      // nothing); the rows of gone launchers are pruned at the next write.
      const rows = this.db.prepare("SELECT session_key, direct, pid, pid_start FROM wire_release_sessions ORDER BY registered_at, rowid")
        .all() as Array<{ session_key: string; direct: string; pid: number; pid_start: string | null }>;
      for (const r of rows) {
        if (typeof r.session_key !== "string" || r.session_key === "") continue;
        if (!this.launcherAlive(Number(r.pid), r.pid_start)) continue;
        // A row is data, never trusted shape: re-read as the op reads it.
        let direct: string[];
        try {
          direct = parseDirectHosts(JSON.parse(r.direct));
        } catch {
          continue;
        }
        this.sessions.set(r.session_key, { direct, pid: Number(r.pid) });
        restored++;
      }
    }
    this.restored = restored;
  }

  /** Is the launcher `pid` that started at `start` still running? A start
   *  time that could not be read when the word was given: the pid alone. */
  private launcherAlive(pid: number, start: string | null): boolean {
    if (!Number.isSafeInteger(pid) || pid <= 0 || !this.exists(pid)) return false;
    if (start === null) return true;
    return this.startOf(pid) === start;
  }

  /** The session's word, or undefined (npm then reads `.npmrc` raw). */
  get(sessionKey: string): WireReleaseSession | undefined {
    const s = this.sessions.get(sessionKey);
    return s ? { direct: [...s.direct] } : undefined;
  }

  /** Record that `sessionKey`'s proxy inspects TLS. With `pid` and a DB,
   *  also persisted for a restart while that launcher lives (a pid this
   *  process cannot see is not persisted, and any earlier row of the session
   *  goes: the newer word is memory only). */
  set(sessionKey: string, direct: readonly string[], pid?: number): void {
    const hosts = parseDirectHosts([...direct]);
    const live = pid !== undefined && Number.isSafeInteger(pid) && pid > 0 && this.exists(pid);
    this.sessions.set(sessionKey, { direct: hosts, ...(live ? { pid } : {}) });
    if (!this.db) return;
    if (live) {
      this.db.prepare(
        "INSERT INTO wire_release_sessions (session_key, direct, pid, pid_start, registered_at) VALUES (?, ?, ?, ?, ?) " +
        "ON CONFLICT(session_key) DO UPDATE SET direct = excluded.direct, pid = excluded.pid, pid_start = excluded.pid_start, registered_at = excluded.registered_at",
      ).run(sessionKey, JSON.stringify(hosts), pid, this.startOf(pid), this.now());
    } else {
      this.db.prepare("DELETE FROM wire_release_sessions WHERE session_key = ?").run(sessionKey);
    }
    this.prune();
  }

  /** The session ended, or its proxy no longer inspects TLS: forget it, in
   *  memory and on disk. With `pid`, only a word that launcher gave (a later
   *  launch of the same session key keeps its own). Returns whether one was
   *  dropped. */
  clear(sessionKey: string, pid?: number): boolean {
    const s = this.sessions.get(sessionKey);
    if (!s) {
      if (this.db && pid === undefined) this.db.prepare("DELETE FROM wire_release_sessions WHERE session_key = ?").run(sessionKey);
      return false;
    }
    if (pid !== undefined && s.pid !== undefined && s.pid !== pid) return false;
    this.sessions.delete(sessionKey);
    this.db?.prepare("DELETE FROM wire_release_sessions WHERE session_key = ?").run(sessionKey);
    this.prune();
    return true;
  }

  /** Drop the persisted rows of launchers that are gone (their words stay
   *  in this run's memory, as before; a restart no longer takes them back). */
  private prune(): void {
    if (!this.db) return;
    const rows = this.db.prepare("SELECT session_key, pid, pid_start FROM wire_release_sessions").all() as Array<{ session_key: string; pid: number; pid_start: string | null }>;
    const del = this.db.prepare("DELETE FROM wire_release_sessions WHERE session_key = ?");
    for (const r of rows) if (!this.launcherAlive(Number(r.pid), r.pid_start)) del.run(r.session_key);
  }

  /** The persisted rows (a test aid): a session key, its hosts, a pid. */
  persisted(): Array<{ sessionKey: string; direct: string[]; pid: number }> {
    if (!this.db) return [];
    return (this.db.prepare("SELECT session_key, direct, pid FROM wire_release_sessions ORDER BY registered_at, rowid").all() as Array<{ session_key: string; direct: string; pid: number }>)
      .map((r) => ({ sessionKey: r.session_key, direct: parseDirectHosts(JSON.parse(r.direct)), pid: Number(r.pid) }));
  }

  close(): void {
    try { this.db?.close(); } catch { /* double-close must not throw */ }
  }
}
