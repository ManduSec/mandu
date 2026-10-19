/**
 * session-upstreams — which declared model each session's MAIN conversation is
 * sent to (model-endpoints.md §1.7.1, phase 3).
 *
 * Mandu-new (no reference origin).
 *
 * Rung 3 (`declassify_symbol`) puts a secret's bytes into the T-LLM's
 * context, and so onto whatever wire carries that context. For a
 * `local-model` datum that is allowed only when the wire ends at the user's
 * own model. The arbiter cannot see where a proxy sends bytes, so it learns
 * it once per session from the launcher, the one component that chooses the
 * proxy's upstream, and records the NAME of the `models:` entry. The location
 * is never stored: it is looked up in the law in force at each decision, so
 * a policy edit that drops `local: true` (or the entry) closes the door for
 * running sessions too.
 *
 * ── Why bind-once, refuse-after-traffic, and persisted ─────────────────────
 *
 * The op is data-plane, so a process inside the agent can call it. A forged
 * "my main model is the local one" would let a trusted `local-model` datum
 * into an outside vendor's context with no approval (a clean session's rung 3
 * is a logged read, not a question). So:
 *   - the first binding wins and a different one is refused (re-binding to
 *     the same entry is an idempotent no-op);
 *   - a session that has already carried traffic cannot be bound: the
 *     launcher binds before it starts any service, so a late first binding is
 *     not the launcher's;
 *   - the row is persisted in the same mandu.db as the session watermark, so
 *     an arbiter restart does not hand an unbound session to whoever asks
 *     first.
 * An unbound session reads as `external` everywhere: the strict reading.
 */

import Database from "../db/sqlite.js";
import { getSymbolDbPath } from "../symbol-table/symbol-table.js";

/** One session's binding. `endpoint === null` = the agent's default vendor. */
export interface SessionUpstream {
  sessionKey: string;
  endpoint: string | null;
  requestedBy: string;
  boundAt: number;
}

export type BindResult =
  | { ok: true; binding: SessionUpstream; changed: boolean }
  | { ok: false; error: string };

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS session_upstreams (
  session_key  TEXT PRIMARY KEY,
  endpoint     TEXT,
  requested_by TEXT NOT NULL DEFAULT '',
  bound_at     INTEGER NOT NULL
);
`;

export interface SessionUpstreamStoreOptions {
  dbPath?: string;
}

export class SessionUpstreamStore {
  private readonly db: InstanceType<typeof Database>;
  private readonly rows = new Map<string, SessionUpstream>();

  constructor(opts: SessionUpstreamStoreOptions = {}) {
    this.db = new Database(opts.dbPath ?? getSymbolDbPath());
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA_SQL);
    const all = this.db
      .prepare("SELECT session_key, endpoint, requested_by, bound_at FROM session_upstreams")
      .all() as Array<{ session_key: string; endpoint: string | null; requested_by: string; bound_at: number }>;
    for (const r of all) {
      this.rows.set(r.session_key, {
        sessionKey: r.session_key,
        endpoint: typeof r.endpoint === "string" && r.endpoint !== "" ? r.endpoint : null,
        requestedBy: r.requested_by,
        boundAt: r.bound_at,
      });
    }
  }

  /** The session's binding, or undefined when it has none. */
  get(sessionKey: string | undefined): SessionUpstream | undefined {
    return sessionKey ? this.rows.get(sessionKey) : undefined;
  }

  /**
   * Bind a session's main model. `hasTraffic` says whether the session has
   * already carried traffic (the caller knows; the store does not).
   */
  bind(sessionKey: string, endpoint: string | null, requestedBy: string, hasTraffic: boolean): BindResult {
    const prior = this.rows.get(sessionKey);
    if (prior !== undefined) {
      if (prior.endpoint === endpoint) return { ok: true, binding: prior, changed: false };
      return {
        ok: false,
        error:
          `setSessionUpstream: session already bound to ${describe(prior.endpoint)} ` +
          `(asked ${describe(endpoint)}); the main model is bind-once`,
      };
    }
    if (hasTraffic) {
      return {
        ok: false,
        error:
          "setSessionUpstream: session has already carried traffic; the main model is recorded " +
          "only before the session starts",
      };
    }
    const row: SessionUpstream = { sessionKey, endpoint, requestedBy, boundAt: Date.now() };
    this.db
      .prepare("INSERT INTO session_upstreams (session_key, endpoint, requested_by, bound_at) VALUES (?, ?, ?, ?)")
      .run(row.sessionKey, row.endpoint, row.requestedBy, row.boundAt);
    this.rows.set(sessionKey, row);
    return { ok: true, binding: row, changed: true };
  }

  close(): void {
    try { this.db.close(); } catch { /* double-close must not throw */ }
  }
}

function describe(endpoint: string | null): string {
  return endpoint === null ? "the default vendor" : `'${endpoint}'`;
}
