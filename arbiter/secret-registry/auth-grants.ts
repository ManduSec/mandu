/**
 * auth-grants — which field of an agent's own key file authenticates to which
 * host, as the launch that routes the agent said it (agent-sign-in.md §3).
 *
 * Mandu-new (no reference origin).
 *
 * The agent's key file (Goose's `secrets.yaml`) is twinned: the agent sends
 * the field's placeholder as its key, and the model proxy puts the real key
 * back in the auth header of the request it forwards to the provider. The
 * release is the egress gate's bound-destination release
 * (`egress:secret-bound-trusted`), so the field needs a binding to that
 * provider's host. The launcher, which routes the provider, says which host
 * (`registerAuthGrant`, a HUMAN-PLANE op: from the data socket the agent
 * could bind its key to a host of its own). This store keeps the grants in
 * memory; the bindings law keeps each granted field bound to its hosts
 * (current-bindings.ts rule 1), and the wire scheme rule reads whether a
 * grant was made for https (registry.ts `wireReleaseScheme`).
 *
 * Across a restart (2026-10-11): a grant whose launch named its launcher
 * (`pid`) is also written to mandu.db, beside the symbol rows it binds, and a
 * restarted arbiter takes back the grants of the launchers still alive (the
 * same pid with the same start time, cache-seals.ts `procStartTime`), so a
 * live session keeps its key working. A grant of a launcher that is gone is
 * not taken back (and its row is pruned at the next write), so a restart
 * still ends the grants of ended launches, as before. A row holds a path, a
 * field name, a host, the scheme and the launcher's pid, never a value: the
 * key itself stays where it was (the user's file, and the symbol row the
 * registration already persisted in the same DB file). A grant without a
 * pid (an older launcher) stays in memory only: the old fail-closed 401
 * after a restart.
 */
import { realpathSync } from "fs";
import Database from "../db/sqlite.js";
import { pidExists, procStartTime } from "../policy/cache-seals.js";

/** One grant as the op carries it. */
export interface AuthGrant {
  /** The field (a key of the file's structured twin: `ANTHROPIC_API_KEY`). */
  field: string;
  /** The host the field's value authenticates to, without a port. */
  host: string;
  /** The upstream is https: the value is never put back over plain HTTP. */
  https: boolean;
}

/** At most this many grants per request (a launch sends one per provider). */
export const MAX_GRANTS_PER_REQUEST = 16;

const FIELD_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/** Is `host` this machine's loopback (`localhost`, 127.0.0.0/8, `::1`)? Pure. */
export function isLoopbackGrantHost(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "localhost" || h === "::1") return true;
  return IPV4_RE.test(h) && h.startsWith("127.");
}

/**
 * Read a request's grants: each a valid field name, a plain host name, an
 * IPv4 address or `::1` (no port, no scheme, no wildcard), and a boolean
 * `https`. A plain-HTTP grant (`https: false`) is accepted only for a
 * loopback host: a key never goes over plain HTTP off this machine. Throws
 * on anything else (the op answers an error and records nothing). Pure.
 */
export function parseAuthGrants(raw: unknown): AuthGrant[] {
  if (!Array.isArray(raw) || raw.length === 0) throw new Error("grants must be a non-empty array");
  if (raw.length > MAX_GRANTS_PER_REQUEST) throw new Error(`at most ${MAX_GRANTS_PER_REQUEST} grants per request`);
  return raw.map((g, i) => {
    if (g === null || typeof g !== "object") throw new Error(`grants[${i}] is not an object`);
    const { field, host, https } = g as Record<string, unknown>;
    if (typeof field !== "string" || !FIELD_RE.test(field)) throw new Error(`grants[${i}].field is not a field name`);
    if (typeof host !== "string") throw new Error(`grants[${i}].host is not a string`);
    const h = host.trim().toLowerCase();
    if (!(h === "::1" || HOST_RE.test(h))) throw new Error(`grants[${i}].host is not a host name or address (no port, scheme or wildcard)`);
    if (IPV4_RE.test(h) && h.split(".").some((n) => Number(n) > 255)) throw new Error(`grants[${i}].host is not an IPv4 address`);
    if (typeof https !== "boolean") throw new Error(`grants[${i}].https must be a boolean`);
    if (!https && !isLoopbackGrantHost(h)) throw new Error(`grants[${i}]: plain HTTP is granted only to this machine's loopback, not '${h}'`);
    return { field, host: h, https };
  });
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS auth_grants (
  origin     TEXT NOT NULL,
  field      TEXT NOT NULL,
  host       TEXT NOT NULL,
  https      INTEGER NOT NULL,
  pid        INTEGER NOT NULL,
  pid_start  TEXT,
  granted_at INTEGER NOT NULL,
  PRIMARY KEY (origin, field, host, pid)
);
`;

export interface AuthGrantStoreOptions {
  /** mandu.db: grants with a launcher pid are kept there across a restart.
   *  Absent: memory only (a unit test's store). */
  dbPath?: string;
  /** Liveness seams (tests). */
  pidExists?: (pid: number) => boolean;
  procStartTime?: (pid: number) => string | null;
  now?: () => number;
}

/** The launcher that made a grant: its pid (the grant is taken back after a
 *  restart only while that process lives). */
export interface GrantLauncher { pid: number }

/** Is `origin` a key the store keeps: an absolute path (a key file) or
 *  `env:NAME` (an environment variable's row, registry.ts
 *  `registerEnvSecret`)? Pure. */
export function isGrantOrigin(origin: unknown): origin is string {
  return typeof origin === "string" && (origin.startsWith("/") || /^env:[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(origin));
}

/** The grants of this arbiter's life, by key file and field (and, with a
 *  DB, those of the launchers still alive across a restart). */
export class AuthGrantStore {
  /** path (as given and its real path) → field → host → https */
  private readonly byPath = new Map<string, Map<string, Map<string, boolean>>>();
  private readonly db: InstanceType<typeof Database> | null;
  private readonly exists: (pid: number) => boolean;
  private readonly startOf: (pid: number) => string | null;
  private readonly now: () => number;
  /** How many persisted grants the start took back (a log line, a test). */
  readonly restored: number;

  constructor(opts: AuthGrantStoreOptions = {}) {
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
      const rows = this.db.prepare("SELECT origin, field, host, https, pid, pid_start FROM auth_grants ORDER BY granted_at, rowid")
        .all() as Array<{ origin: string; field: string; host: string; https: number; pid: number; pid_start: string | null }>;
      const alive = new Map<string, boolean>();
      for (const r of rows) {
        const k = `${r.pid}\u0000${r.pid_start ?? ""}`;
        let live = alive.get(k);
        if (live === undefined) alive.set(k, (live = this.launcherAlive(Number(r.pid), r.pid_start)));
        if (!live || !isGrantOrigin(r.origin)) continue;
        // Re-checked as the op checks it: a row is data, never trusted shape.
        let parsed: AuthGrant[];
        try {
          parsed = parseAuthGrants([{ field: r.field, host: r.host, https: r.https === 1 }]);
        } catch {
          continue;
        }
        this.remember(r.origin, parsed);
        restored++;
      }
    }
    this.restored = restored;
  }

  /** Is the launcher `pid` that started at `start` still running? A start
   *  time that could not be read when the grant was made: the pid alone. */
  private launcherAlive(pid: number, start: string | null): boolean {
    if (!Number.isSafeInteger(pid) || pid <= 0 || !this.exists(pid)) return false;
    if (start === null) return true;
    return this.startOf(pid) === start;
  }

  /** Record `grants` for the key file at `path` (accumulating: a host
   *  granted once stays granted; https only narrows to plain HTTP when a
   *  launch grants a loopback host over it). With `launcher` and a DB, also
   *  persisted for a restart while that launcher lives (a pid this process
   *  cannot see is not persisted). Returns the paths it is keyed by. */
  grant(path: string, grants: readonly AuthGrant[], launcher?: GrantLauncher): string[] {
    const keys = this.remember(path, grants);
    if (this.db && launcher && Number.isSafeInteger(launcher.pid) && launcher.pid > 0 && this.exists(launcher.pid)) {
      const start = this.startOf(launcher.pid);
      const now = this.now();
      const ins = this.db.prepare(
        "INSERT INTO auth_grants (origin, field, host, https, pid, pid_start, granted_at) VALUES (?, ?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(origin, field, host, pid) DO UPDATE SET https = excluded.https, pid_start = excluded.pid_start, granted_at = excluded.granted_at",
      );
      for (const g of grants) ins.run(path, g.field, g.host, g.https ? 1 : 0, launcher.pid, start, now);
      this.prune();
    }
    return keys;
  }

  /** Drop the persisted rows of launchers that are gone (their grants stay
   *  in this run's memory, as before; a restart no longer takes them back). */
  private prune(): void {
    if (!this.db) return;
    const launchers = this.db.prepare("SELECT DISTINCT pid, pid_start FROM auth_grants").all() as Array<{ pid: number; pid_start: string | null }>;
    const del = this.db.prepare("DELETE FROM auth_grants WHERE pid = ? AND pid_start IS ?");
    for (const l of launchers) {
      if (!this.launcherAlive(Number(l.pid), l.pid_start)) del.run(l.pid, l.pid_start);
    }
  }

  /** The persisted rows (a test aid): never a value, only what a grant names. */
  persisted(): Array<{ origin: string; field: string; host: string; https: boolean; pid: number }> {
    if (!this.db) return [];
    return (this.db.prepare("SELECT origin, field, host, https, pid FROM auth_grants ORDER BY granted_at, rowid").all() as Array<{ origin: string; field: string; host: string; https: number; pid: number }>)
      .map((r) => ({ origin: r.origin, field: r.field, host: r.host, https: r.https === 1, pid: Number(r.pid) }));
  }

  close(): void {
    try { this.db?.close(); } catch { /* double-close must not throw */ }
  }

  private remember(path: string, grants: readonly AuthGrant[]): string[] {
    const keys = [path];
    // A key file's real path too; an `env:NAME` origin is no path.
    if (path.startsWith("/")) {
      try {
        const real = realpathSync(path);
        if (real !== path) keys.push(real);
      } catch { /* not there (yet): the given path only */ }
    }
    for (const key of keys) {
      let fields = this.byPath.get(key);
      if (!fields) this.byPath.set(key, (fields = new Map()));
      for (const g of grants) {
        let hosts = fields.get(g.field);
        if (!hosts) fields.set(g.field, (hosts = new Map()));
        hosts.set(g.host, g.https);
      }
    }
    return keys;
  }

  /** The hosts `field` of the key file at `origin` is granted to (empty: none). */
  hosts(origin: string, field: string): string[] {
    return [...(this.byPath.get(origin)?.get(field)?.keys() ?? [])];
  }

  /** The wire scheme rule for a granted field at `destination` (registry.ts
   *  `wireReleaseScheme`): `any` when that host's grant is a plain-HTTP
   *  loopback one, else `https` (a host the field is not granted to included:
   *  fail closed, and the binding check refuses it anyway); undefined when
   *  the field has no grant at all. */
  scheme(origin: string, field: string, destination?: string): "https" | "any" | undefined {
    const hosts = this.byPath.get(origin)?.get(field);
    if (!hosts || hosts.size === 0) return undefined;
    const host = destination === undefined ? undefined : destinationHost(destination);
    return host !== undefined && hosts.get(host) === false ? "any" : "https";
  }
}

/** A destination's host: lowercased, without a port or IPv6 brackets. Pure. */
export function destinationHost(destination: string): string {
  const d = destination.trim().toLowerCase();
  const v6 = /^\[([^\]]+)\](?::\d+)?$/.exec(d);
  if (v6) return v6[1]!;
  return d.replace(/:\d+$/, "");
}
