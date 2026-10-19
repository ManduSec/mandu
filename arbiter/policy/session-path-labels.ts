/**
 * session-path-labels — a SESSION's machine labels: exact paths labelled
 * `no-model` for as long as the session lives, in memory only.
 *
 * Mandu-new. The first producer is OpenCode 2's background output file
 * (supported-agents.md §2.3 item 7): a shell the user moves to the background
 * keeps streaming its output to `$XDG_DATA_HOME/opencode/shell/<40 hex>/
 * sh_<id>.out`, and the call's own result names that file and invites the
 * model to read it. That file holds the program's output (a secret, when the
 * program read one) but carries no label: the agent itself wrote it, so no
 * human label names it, the derived-label machinery (a file a process holding
 * a secret wrote) does not see the agent's writes, and a `read` of it or a
 * `cat` in a shell passed raw. The proxy registers the exact path here when
 * it forwards the result that names it, BEFORE the model can ask for it.
 *
 * Why not `setPathLabel`: a path label is the human's persistent act, shown
 * on the Rules page and kept across restarts; this is a machine's taint on a
 * scratch file of one agent run. Why not a derived label: those persist too,
 * and are a written-by-a-holder record. So a third store with three rules:
 *
 *   - RAISE-ONLY. A session label makes the exact path `no-model`, bound
 *     nowhere, whatever any other store says (label-lookup.ts composes it
 *     last). Registering one can only make Mandu stricter, so the data plane
 *     (the proxy) may do it; nothing here ever lowers a level.
 *   - NOT PERSISTENT. Memory only: an arbiter restart forgets every row (the
 *     proxy registers the path again on the next request that carries the
 *     result, since OpenCode re-sends its history every turn).
 *   - DROPPED ONLY ON PURPOSE. `clearSession` drops a session's rows (the
 *     human-plane op `clearSessionPathLabels`). The launcher does not call
 *     it at the session's end: the file outlives the session, and clearing
 *     the label would lower its protection.
 *
 * Every lookup funnels through the arbiter's `labelLookup`, so the proxy's
 * path-derived classification (a `read` of the file, a shell command naming
 * it), callTaint's file levels and `decideSecretOpen` see a session label.
 * The kernel guard's index (`derivedLabelsSince`) does NOT list the rows: it
 * would gate the agent's own reads of the file and hand OpenCode a twin.
 *
 * BELT AND BRACES since 2026-10-05: OpenCode's data directory, where these
 * files live, is a PERSISTENT catalog location (secret-catalog.ts, §2.3 item
 * 10), which also covers files from earlier runs and outlives an arbiter
 * restart. A session label still catches an output file the catalog does not
 * know (a future layout, a spelling no shape matches), since the proxy
 * registers whatever path the result names.
 */
import { normalizeLabelPath } from "./path-labels.js";

export interface SessionPathLabel {
  /** Absolute, normalized (HumanView spelling). */
  path: string;
  /** The session that registered it. */
  sessionKey: string;
  /** Why (shown with the label): e.g. "OpenCode background output sh_…". */
  reason: string;
  /** The derived index's change number it was listed under. */
  gen: number;
  createdAt: number;
}

/** A bound on the rows one arbiter keeps: past it, registering fails, and the
 *  proxy refuses to forward what would have named the path (fail-closed). */
export const SESSION_PATH_LABELS_MAX = 100_000;

export class SessionPathLabelStore {
  private readonly rows = new Map<string, SessionPathLabel>();

  /**
   * Label `rawPath` for `sessionKey`. `nextGen` hands out a change number in
   * the derived index's sequence (one cursor for the guard). Null: not an
   * absolute path, or the store is full. Idempotent for a path already
   * labelled (its first row stands, under its first session).
   */
  set(rawPath: string, sessionKey: string, reason: string, nextGen: () => number): SessionPathLabel | null {
    const p = normalizeLabelPath(rawPath);
    if (p === null || typeof sessionKey !== "string" || sessionKey === "") return null;
    const prev = this.rows.get(p);
    if (prev) return prev;
    if (this.rows.size >= SESSION_PATH_LABELS_MAX) return null;
    const row: SessionPathLabel = { path: p, sessionKey, reason: String(reason ?? "").slice(0, 200), gen: nextGen(), createdAt: Date.now() };
    this.rows.set(p, row);
    return row;
  }

  /** Drop a session's rows; the number dropped. */
  clearSession(sessionKey: string): number {
    let n = 0;
    for (const [p, r] of this.rows) {
      if (r.sessionKey === sessionKey) {
        this.rows.delete(p);
        n++;
      }
    }
    return n;
  }

  /** The rows listed after change number `gen` (every row for 0). */
  since(gen: number): SessionPathLabel[] {
    return [...this.rows.values()].filter((r) => r.gen > gen).sort((a, b) => a.gen - b.gen);
  }

  /** path → row, for the pure resolver (label-lookup.ts). */
  map(): ReadonlyMap<string, SessionPathLabel> {
    return this.rows;
  }

  list(sessionKey?: string): SessionPathLabel[] {
    return [...this.rows.values()].filter((r) => sessionKey === undefined || r.sessionKey === sessionKey);
  }
}
