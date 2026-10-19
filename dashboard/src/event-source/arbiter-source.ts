/**
 * event-source/arbiter-source — the live arbiter-backed EventSource (NDJSON
 * over the arbiter Unix socket). Extracted VERBATIM from src/event-source.ts in
 * the event-source decomposition; see the barrel for the module map.
 */

import { connect, type Socket } from "node:net";

import { type ManduEvent, coerceEvent } from "../event-model.js";
import type { PolicySnapshot } from "../policy-model.js";
import {
  sortCanonical,
  type EventListener,
  type EventSource,
  type HumanPlaneStatus,
  type SessionRef,
  type SessionUpstream,
  type Unsubscribe,
} from "./contract.js";
import {
  assertionVerdicts,
  deriveAgentKind,
  deriveBrowserAgent,
  deriveRuntime,
  deriveBatchMember,
  deriveOrigin,
  sessionLabelFields,
  deriveTenant,
  tenantedTags,
  testNumber,
} from "./registry.js";
import { deriveHealth } from "../session-health.js";
import { withCounts } from "../view-model/session-counts.js";
import { withExited } from "../view-model/session-exit.js";
import { NdjsonLineSplitter } from "./ndjson-lines.js";

// ── Arbiter-backed source (live event stream over the arbiter IPC socket) ───────

/**
 * Deadline for the `sessions` op only. Warm it answers from the arbiter's stat
 * cache in milliseconds, but the first call after an arbiter restart re-parses
 * every session file; at the 2026-07-18 shared stack (~1000 sessions / 220MB)
 * that cold scan took ~7s and the 5s default deadline blanked the sidebar.
 */
const COLD_SESSIONS_SCAN_TIMEOUT_MS = 30_000;

export interface ArbiterEventSourceOptions {
  /** Arbiter DATA Unix-socket path (the same socket the M0 arbiter listens on):
   *  the data-plane reads (policySnapshot, handlingPrompt, sessionUpstream) and
   *  the `hello` that discovers the human socket. */
  socketPath: string;
  /**
   * The arbiter's HUMAN-PLANE socket (docs/design/architecture/arbiter-human-plane.md):
   * `sessions` / `events` / `subscribe` / `desymbolize` / shallow `resolve`
   * return originals and the arbiter serves them only there. Explicit (from
   * $MANDU_ARBITER_HUMAN_SOCK) or, when absent, discovered per arbiter
   * instance from the data socket's `hello().humanSock` — re-discovered after a
   * connection failure, since a restarted arbiter binds a new one. NEVER
   * replaced by the data socket: with no human socket those reads fail, and
   * the dashboard degrades the way it does for an unreachable arbiter.
   */
  humanSocketPath?: string;
  /** Connect timeout (ms) for request/response ops. Default 5000. */
  connectTimeoutMs?: number;
  /**
   * How to enact `deleteSession` — an ADMIN-ONLY op (policy-surface.md
   * §2.6): the arbiter refuses it on the data socket this source dials, so the
   * deletion must travel the admin channel server-main holds. Absent (or set
   * later via {@link ArbiterEventSource.setAdminDeleter}) → deleteSession
   * throws the admin-unavailable error the route maps to 503.
   */
  adminDelete?: (sessionId: string) => Promise<void>;
}

/** Arbiter `sessions` op row — the count-only summary the arbiter reports. */
interface ArbiterSessionSummary {
  sessionId: string;
  count: number;
  firstTs: string | null;
  lastTs: string | null;
  /** Tenant from the first stamped event (policy-surface.md §2.7);
   *  absent on pre-tenancy arbiters and unstamped sessions. */
  tenant?: string;
}

/**
 * Live arbiter-backed EventSource. Speaks the arbiter's event protocol over its
 * Unix socket (dashboard.md §3.1):
 *
 *   - `sessions`  req {op:"sessions"} → {sessions:[{sessionId,count,firstTs,lastTs}]}
 *   - `events`    req {op:"events", sessionId, sinceSeq?} → {events: ManduEvent[]}
 *                 (seq-ordered, seq > sinceSeq)
 *   - `subscribe` req {op:"subscribe", sessionId, sinceSeq?} on a DEDICATED
 *                 connection → backlog then live frames, each
 *                 {ok:true, result:{type:"event", event}}, until the client closes.
 *
 * Wire framing matches arbiter/ipc/protocol.ts (NDJSON: one JSON object per line,
 * "\n"-terminated). Request/response ops correlate by `id`; the subscribe stream
 * is a long-lived push connection with no correlation id on its frames.
 *
 * The dashboard package stays free of any dependency on the arbiter package — it
 * does NOT import arbiter/ipc/client.ts (that client is bound to the arbiter's
 * typed ops and lives in another package). Instead this source carries a small
 * self-contained NDJSON socket helper: a one-shot request/response for the
 * `sessions`/`events` ops, and a dedicated line-reading socket for `subscribe`.
 *
 * Because it implements the same EventSource interface as FileEventSource,
 * server.ts and the frontend need no change beyond which source is constructed.
 */
export class ArbiterEventSource implements EventSource {
  private readonly socketPath: string;
  private readonly explicitHumanSock?: string;
  /** The human socket `hello` named for the instance we last reached. */
  private discoveredHumanSock: string | null = null;
  private readonly connectTimeoutMs: number;
  /** Live subscribe sockets, closed on close(). */
  private readonly streams = new Set<Socket>();
  /**
   * sessionId → the SessionRef derived at (count, lastTs). The event log is
   * append-only, so an unchanged (count, lastTs) means the SAME event list and
   * therefore the same pure derivations (label/violated/agent/verdicts/…) —
   * only sessions the summary shows as changed re-fetch their events. Without
   * this, every listSessions() poll re-fetched the FULL event list of EVERY
   * session (~1000 `events` ops / ~220MB at the 2026-07-18 shared stack) and
   * the sidebar 500'd on the per-op deadline.
   */
  private readonly refCache = new Map<
    string,
    { count: number; lastTs: string | null; ref: SessionRef }
  >();

  /** Sessions whose last events replay failed (logged once per streak). */
  private readonly degraded = new Set<string>();

  private adminDelete?: (sessionId: string) => Promise<void>;

  constructor(opts: ArbiterEventSourceOptions) {
    this.socketPath = opts.socketPath;
    this.explicitHumanSock = opts.humanSocketPath || undefined;
    this.connectTimeoutMs = opts.connectTimeoutMs ?? 5000;
    this.adminDelete = opts.adminDelete;
  }

  /** Late-bind the admin-channel deleter (server-main gets its admin channel
   *  only after autostart spawns the arbiter). */
  setAdminDeleter(fn: ((sessionId: string) => Promise<void>) | undefined): void {
    this.adminDelete = fn;
  }

  /** The arbiter socket this source attaches to. */
  get target(): string {
    return this.socketPath;
  }

  /**
   * The human-plane socket to dial (explicit, else `hello().humanSock` over the
   * data socket, cached per instance). Rejects when there is none — the
   * human-plane reads then fail like any unreachable-arbiter read; they are
   * never retried on the data socket, which refuses them anyway.
   */
  private async humanSock(): Promise<string> {
    if (this.explicitHumanSock) return this.explicitHumanSock;
    if (this.discoveredHumanSock) return this.discoveredHumanSock;
    const hello = await this.requestOnce<{ humanSock?: unknown }>({ op: "hello" }, undefined, this.socketPath);
    const path = typeof hello?.humanSock === "string" && hello.humanSock !== "" ? hello.humanSock : null;
    if (path === null) {
      throw new Error(
        `human plane unavailable: the arbiter at ${this.socketPath} names no human socket ` +
          `(an arbiter older than the human plane, or one started without it) — sessions, events and reveals need it`,
      );
    }
    this.discoveredHumanSock = path;
    return path;
  }

  /** A human-plane request: resolve the human socket, then ask it. A failed
   *  connection drops the discovered path so the next call re-asks `hello`. */
  private async requestHuman<T>(req: Record<string, unknown>, timeoutMs?: number): Promise<T> {
    const path = await this.humanSock();
    try {
      return await this.requestOnce<T>(req, timeoutMs, path);
    } catch (err) {
      if (/connection failed/.test((err as Error).message) && this.discoveredHumanSock === path) {
        this.discoveredHumanSock = null;
      }
      throw err;
    }
  }

  async listSessions(): Promise<SessionRef[]> {
    // The summaries op is stat-cheap warm, but the FIRST call after an arbiter
    // restart re-scans every session file server-side — give that one cold scan
    // real headroom instead of the per-op default (5s died at ~220MB).
    const { sessions } = await this.requestHuman<{ sessions: ArbiterSessionSummary[] }>(
      { op: "sessions" },
      COLD_SESSIONS_SCAN_TIMEOUT_MS,
    );
    const refs: SessionRef[] = [];
    const seen = new Set<string>();
    for (const s of sessions ?? []) {
      seen.add(s.sessionId);
      // Append-only log ⇒ an unchanged (count, lastTs) is the same event list,
      // so the cached derivation is exact — skip the full event fetch.
      const cached = this.refCache.get(s.sessionId);
      if (cached && cached.count === (s.count ?? cached.count) && cached.lastTs === (s.lastTs ?? null)) {
        refs.push(cached.ref);
        continue;
      }
      // The arbiter `sessions` op is count-only and carries no invariant flag, so
      // compute `violated` the same way FileEventSource does: by inspecting the
      // session's events. This keeps SessionRef identical across both sources
      // (the sidebar pre-flags violated sessions without per-event client work).
      //
      // ONE session's replay failing (deadline, hangup) must not blank the
      // whole rail (dashboard.md §3.3, 2026-09-17): fall back to the last
      // derived ref if there is one (stale label/verdicts, current counts),
      // else a summary-only stub — and leave the cache alone so the next poll
      // retries. Logged once per failure streak, not per poll.
      let events: ManduEvent[];
      try {
        events = await this.readEvents(s.sessionId);
      } catch (err) {
        if (!this.degraded.has(s.sessionId)) {
          this.degraded.add(s.sessionId);
          console.error(
            `[dashboard] sidebar: session ${s.sessionId} listed from its summary only — ` +
              `events replay failed (${(err as Error).message}); retrying next poll`,
          );
        }
        refs.push(cached ? staleRef(cached.ref, s.count ?? cached.count, s.lastTs ?? cached.lastTs) : summaryOnlyRef(s));
        continue;
      }
      this.degraded.delete(s.sessionId);
      // The arbiter's summary carries the tenant it saw first (server-side,
      // one stat per file); the events are the fallback for older arbiters.
      const tenant = deriveTenant(events, s.tenant);
      const ref: SessionRef = {
        id: s.sessionId,
        ...sessionLabelFields(events, s.sessionId),
        eventCount: s.count ?? events.length,
        firstTs: s.firstTs ?? (events.length ? events[0]!.ts : null),
        lastTs: s.lastTs ?? (events.length ? events[events.length - 1]!.ts : null),
        ...withExited(events),
        violated: events.some((e) => e.invariant.violatedInvariant),
        ...withCounts(events),
        tags: tenantedTags(s.sessionId, tenant, events),
        ...(tenant ? { tenant } : {}),
        testNumber: testNumber(s.sessionId),
        batchId: events.find((e) => e.batchId)?.batchId,
        ...(deriveBatchMember(events) ? { batchMember: deriveBatchMember(events)! } : {}),
        agent: deriveAgentKind(events, s.sessionId),
        ...(deriveBrowserAgent(events, s.sessionId) ? { browserAgent: deriveBrowserAgent(events, s.sessionId)! } : {}),
        runtime: deriveRuntime(events),
        origin: deriveOrigin(events),
        ...assertionVerdicts(events),
        ...(deriveHealth(events) ? { health: deriveHealth(events)! } : {}),
      };
      this.refCache.set(s.sessionId, {
        count: s.count ?? events.length,
        lastTs: s.lastTs ?? null,
        ref,
      });
      refs.push(ref);
    }
    // Evict refs whose session vanished (deleted or rotated away).
    for (const id of this.refCache.keys()) {
      if (!seen.has(id)) this.refCache.delete(id);
    }
    // Most-recent session first (matches FileEventSource ordering).
    refs.sort((a, b) => ((a.lastTs ?? "") < (b.lastTs ?? "") ? 1 : -1));
    return refs;
  }

  async readEvents(sessionId: string, sinceSeq?: number): Promise<ManduEvent[]> {
    const args: Record<string, unknown> = { op: "events", sessionId };
    if (sinceSeq !== undefined) args.sinceSeq = sinceSeq;
    const { events } = await this.requestHuman<{ events: unknown[] }>(args);
    const valid: ManduEvent[] = [];
    for (const e of events ?? []) {
      // Tolerant: coerce (repairing emitter variances) and skip only the
      // unrecoverable, so one bad row can't blank the whole session.
      const ev = coerceEvent(e);
      if (ev) valid.push(ev);
    }
    return sortCanonical(valid);
  }

  /**
   * Open a DEDICATED `subscribe` connection for `sessionId` and call `listener`
   * for each delivered event. Per the arbiter contract the stream replays the
   * backlog (events with seq > sinceSeq) and then the live tail on one socket;
   * `sinceSeq` (optional) skips a backlog the caller already has. The returned
   * close handle tears the connection down (the arbiter drops the subscriber when
   * the socket closes). Events are de-duped by seq so a backlog/live overlap can
   * never double-emit on a single stream.
   */
  subscribe(sessionId: string, listener: EventListener, sinceSeq?: number): Unsubscribe {
    // The stream carries originals: human plane only. Its socket is resolved
    // first (possibly a `hello` round trip), so the connection opens async;
    // an unsubscribe before then simply never opens it.
    let closed = false;
    let sock: Socket | null = null;
    const teardown = (): void => {
      if (closed) return;
      closed = true;
      if (!sock) return;
      this.streams.delete(sock);
      sock.removeAllListeners("data");
      sock.end();
      sock.destroy();
    };
    void this.humanSock().then(
      (path) => {
        if (closed) return;
        sock = connect(path);
        this.openStream(sock, sessionId, listener, sinceSeq, () => {
          closed = true;
          if (this.discoveredHumanSock === path) this.discoveredHumanSock = null;
        }, teardown);
      },
      (err: Error) => {
        // No human plane → no live tail (the same as an unreachable arbiter).
        console.error(`[dashboard] live stream for ${sessionId} unavailable: ${err.message}`);
        closed = true;
      },
    );
    return teardown;
  }

  private openStream(
    sock: Socket,
    sessionId: string,
    listener: EventListener,
    sinceSeq: number | undefined,
    markClosed: () => void,
    teardown: () => void,
  ): void {
    this.streams.add(sock);
    sock.setEncoding("utf8");
    const lines = new NdjsonLineSplitter();
    let lastSeq = -1;

    const deliver = (event: ManduEvent): void => {
      if (event.seq <= lastSeq) return; // de-dupe a backlog/live overlap
      lastSeq = event.seq;
      listener(event);
    };

    sock.once("connect", () => {
      const req: Record<string, unknown> = { op: "subscribe", sessionId };
      if (sinceSeq !== undefined) req.sinceSeq = sinceSeq;
      sock.write(JSON.stringify(req) + "\n");
    });

    sock.on("data", (chunk: string) => {
      for (const line of lines.push(chunk)) {
        if (line.trim() === "") continue;
        let frame: unknown;
        try {
          frame = JSON.parse(line);
        } catch {
          continue; // tolerant: skip an unparseable frame
        }
        const raw = extractEventFrame(frame);
        const event = raw === null ? null : coerceEvent(raw);
        if (event) deliver(event);
      }
    });

    // A closed/errored subscribe socket is not fatal — the dashboard simply
    // stops receiving live updates for that session (the SSE relay's req.close
    // also drives teardown via the returned unsubscribe).
    sock.on("error", () => teardown());
    sock.on("close", () => {
      markClosed();
      this.streams.delete(sock);
    });
  }

  /** Fetch the arbiter's active policy rule table (the `policySnapshot` op).
   * Reuses the one-shot request/response path; the caller (the /api/policy
   * route) fails soft to null on any error, so this never blocks the trace. */
  async policySnapshot(): Promise<PolicySnapshot | null> {
    return this.requestOnce<PolicySnapshot>({ op: "policySnapshot" });
  }

  /** Whether the human plane is exposed, and by which launches (the
   * arbiter's `humanPlaneStatus` op, arbiter-human-plane.md §10.1.1): a
   * HUMAN-plane read (it names sessions). The caller (loadPolicyPanel) fails
   * soft to "unknown" on any error. */
  async humanPlaneStatus(): Promise<HumanPlaneStatus> {
    return this.requestHuman<HumanPlaneStatus>({ op: "humanPlaneStatus" });
  }

  /** Deep-resolve symbol references in `text` via the arbiter's `desymbolize`
   * op — the same fixpoint egress the reply-filter applies, so the dashboard's
   * delivered-reply reveal shows exactly what that chokepoint would hand the
   * human. The caller (view-model/delivery.ts via /api/events) fails soft to
   * the event-carried values on any error, so this never blocks the trace. */
  async desymbolize(text: string): Promise<string> {
    const r = await this.requestHuman<{ text: string }>({ op: "desymbolize", text });
    return r.text;
  }

  /** One level of one symbol via the arbiter's SHALLOW `resolve` op (no
   * `deep`): nested tokens come back as tokens, so the product page can check
   * each one for a secret before it asks for that one too (§4.25b). */
  async resolveSymbol(name: string): Promise<string | null> {
    const r = await this.requestHuman<{ value: string | null }>({ op: "resolve", symbol: name });
    return typeof r.value === "string" ? r.value : null;
  }

  /** The session's main model via the arbiter's `sessionUpstream` op (plan 11
   * §7.1): the bound entry name and where it runs in the law in force. A
   * read on the data socket; the caller fails soft to no line. */
  async sessionUpstream(sessionKey: string): Promise<SessionUpstream | null> {
    const r = await this.requestOnce<Partial<SessionUpstream>>({ op: "sessionUpstream", sessionKey });
    if (!r || typeof r !== "object") return null;
    return {
      sessionKey,
      endpoint: typeof r.endpoint === "string" && r.endpoint !== "" ? r.endpoint : null,
      location: r.location === "local" ? "local" : "external",
      bound: r.bound === true,
    };
  }

  /** The ACTIVE handling system prompt via the arbiter's `handlingPrompt` op
   * (§8.8 drawer). Default mode/capabilities — the full prompt, as the
   * anthropic-proxy's default injection would render it against the arbiter's
   * live posture. Fetched per call (the content varies with posture). */
  async handlingPrompt(): Promise<string> {
    const r = await this.requestOnce<{ prompt: string }>({ op: "handlingPrompt" });
    return r.prompt;
  }

  /** Delete ONE session (live or test) via the arbiter's `deleteSession` op —
   * the arbiter (the single owner of the event store) unlinks the log, drops
   * its in-memory state and ends live streams. It rejects unknown sessions;
   * the error propagates for the route to map (404/503). */
  async deleteSession(sessionId: string): Promise<void> {
    if (!this.adminDelete) {
      // Never try the data socket: the arbiter would refuse ("admin-only") and
      // the message here is the one with the remedy in it.
      throw new Error(
        "admin channel unavailable: this dashboard did not start the arbiter (adopted instance), " +
          "so it cannot delete sessions — restart the services from Settings to regain control",
      );
    }
    await this.adminDelete(sessionId);
    this.refCache.delete(sessionId);
  }

  close(): void {
    for (const sock of this.streams) {
      sock.removeAllListeners("data");
      sock.end();
      sock.destroy();
    }
    this.streams.clear();
  }

  /**
   * One-shot NDJSON request/response over a fresh connection: connect, write a
   * single `{id, ...req}` line, resolve with the first `result` whose `id`
   * matches (or reject on an `ok:false` frame / connection failure), then close.
   * A fresh connection per call keeps the request/response path independent of
   * the long-lived subscribe sockets and needs no multiplexing.
   */
  private requestOnce<T>(req: Record<string, unknown>, timeoutMs?: number, path: string = this.socketPath): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const id = 1;
      const sock = connect(path);
      sock.setEncoding("utf8");
      // Linear framing (ndjson-lines.ts): the `events` reply for one long
      // interactive session is a single multi-MB line; re-scanning the whole
      // buffer per chunk made a 0.8 s reply take 6–7 s and trip the deadline.
      const lines = new NdjsonLineSplitter();
      let settled = false;

      const timer = setTimeout(() => {
        finish(() => reject(new Error(`arbiter request '${String(req.op)}' timed out`)));
      }, timeoutMs ?? this.connectTimeoutMs);

      const finish = (fn: () => void): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        sock.removeAllListeners();
        sock.end();
        sock.destroy();
        fn();
      };

      sock.once("connect", () => {
        sock.write(JSON.stringify({ id, ...req }) + "\n");
      });
      sock.on("data", (chunk: string) => {
        for (const line of lines.push(chunk)) {
          if (line.trim() === "") continue;
          let resp: { id?: unknown; ok?: boolean; result?: unknown; error?: unknown };
          try {
            resp = JSON.parse(line) as typeof resp;
          } catch {
            continue;
          }
          if (resp.id !== id) continue; // not our reply
          if (resp.ok === false) {
            finish(() => reject(new Error(String(resp.error ?? "arbiter error"))));
            return;
          }
          finish(() => resolve(resp.result as T));
          return;
        }
      });
      sock.on("error", (err: Error) => {
        finish(() => reject(new Error(`arbiter connection failed (${path}): ${err.message}`)));
      });
      sock.on("close", () => {
        finish(() => reject(new Error(`arbiter connection closed before reply to '${String(req.op)}'`)));
      });
    });
  }
}

/** A SessionRef from the arbiter summary alone (no events replayed): counts,
 *  ts bounds, tenant + tags; no label / verdicts / health. Used when a
 *  session's replay failed and nothing better is cached (listSessions). */
function summaryOnlyRef(s: ArbiterSessionSummary): SessionRef {
  const tenant = deriveTenant([], s.tenant);
  return {
    id: s.sessionId,
    label: null,
    eventCount: s.count ?? 0,
    firstTs: s.firstTs ?? null,
    lastTs: s.lastTs ?? null,
    violated: false,
    tags: tenantedTags(s.sessionId, tenant),
    ...(tenant ? { tenant } : {}),
    testNumber: testNumber(s.sessionId),
    agent: deriveAgentKind([], s.sessionId),
    ...(deriveBrowserAgent([], s.sessionId) ? { browserAgent: deriveBrowserAgent([], s.sessionId)! } : {}),
  };
}

/** The last derived ref of a session whose replay failed, with the summary's
 *  current count and lastTs (listSessions). Its derivations are stale: the
 *  log grew since, or the cache would have answered. So it keeps its label
 *  and verdicts but never `exited`: an event after the exit may be the agent
 *  resuming, and the list falls back to the recent-activity rule. */
function staleRef(ref: SessionRef, eventCount: number, lastTs: string | null): SessionRef {
  const { exited: _exited, ...rest } = ref;
  return { ...rest, eventCount, lastTs };
}

/**
 * Pull the event payload out of a subscribe frame. The contract frames each as
 * `{ok:true, result:{type:"event", event}}`; we also accept a bare
 * `{result:{event}}` and a top-level `{event}` defensively so a small framing
 * variant at real integration does not silently drop live events.
 */
function extractEventFrame(frame: unknown): unknown {
  if (frame === null || typeof frame !== "object") return null;
  const f = frame as Record<string, unknown>;
  const result = f.result;
  if (result !== null && typeof result === "object") {
    const r = result as Record<string, unknown>;
    if ("event" in r) return r.event;
  }
  if ("event" in f) return f.event;
  return null;
}
