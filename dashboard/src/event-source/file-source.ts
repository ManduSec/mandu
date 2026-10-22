/**
 * event-source/file-source — the file-backed EventSource (tests + local demo).
 * Extracted VERBATIM from src/event-source.ts in the event-source
 * decomposition; see the barrel for the module map.
 */

import { readFileSync, existsSync, readdirSync, statSync, unlinkSync, watch, type FSWatcher } from "node:fs";
import { join } from "node:path";

import { type ManduEvent, coerceEvent } from "../event-model.js";
import type { PolicySnapshot } from "../policy-model.js";
import {
  sortCanonical,
  type EventListener,
  type EventSource,
  type SessionRef,
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
  withCwd,
} from "./registry.js";
import { deriveHealth } from "../session-health.js";
import { withCounts } from "../view-model/session-counts.js";
import { withExited } from "../view-model/session-exit.js";

// ── File-backed source (tests + local demo) ───────────────────────────────────

/**
 * Reads append-only NDJSON files named `<sessionId>.ndjson` in a directory.
 * Tolerant line parsing (skips blank/garbage lines) mirrors the arbiter IPC
 * server's NDJSON framing. `subscribe` tails the file via fs.watch.
 */
export class FileEventSource implements EventSource {
  private readonly dir: string;
  /** Live fs.watch tails, keyed by the sessionId each one tails — so
   *  deleteSession can stop just that session's watchers. */
  private readonly watchers = new Map<FSWatcher, string>();
  /**
   * sessionId → SessionRef derived at a file identity (ino, size, mtimeMs).
   * The log is append-only, so an unchanged identity means the same events and
   * the same pure derivations — listSessions re-reads only changed files
   * (mirrors ArbiterEventSource's (count, lastTs) memo; big local demo dirs
   * otherwise re-parse everything on every sidebar poll).
   */
  private readonly refCache = new Map<
    string,
    { ino: number; size: number; mtimeMs: number; ref: SessionRef }
  >();

  constructor(dir: string) {
    this.dir = dir;
  }

  async listSessions(): Promise<SessionRef[]> {
    if (!existsSync(this.dir)) return [];
    const refs: SessionRef[] = [];
    const seen = new Set<string>();
    for (const name of readdirSync(this.dir)) {
      if (!name.endsWith(".ndjson")) continue;
      const id = name.slice(0, -".ndjson".length);
      seen.add(id);
      let st: ReturnType<typeof statSync> | null = null;
      try {
        st = statSync(join(this.dir, name));
      } catch {
        st = null; // raced delete — derive from whatever readEvents sees
      }
      const cached = this.refCache.get(id);
      if (st && cached && cached.ino === st.ino && cached.size === st.size && cached.mtimeMs === st.mtimeMs) {
        refs.push(cached.ref);
        continue;
      }
      const events = await this.readEvents(id);
      const tenant = deriveTenant(events);
      const ref: SessionRef = {
        id,
        ...sessionLabelFields(events, id),
        ...withCwd(events),
        eventCount: events.length,
        firstTs: events.length ? events[0]!.ts : null,
        lastTs: events.length ? events[events.length - 1]!.ts : null,
        ...withExited(events),
        violated: events.some((e) => e.invariant.violatedInvariant),
        ...withCounts(events),
        tags: tenantedTags(id, tenant, events),
        ...(tenant ? { tenant } : {}),
        testNumber: testNumber(id),
        batchId: events.find((e) => e.batchId)?.batchId,
        ...(deriveBatchMember(events) ? { batchMember: deriveBatchMember(events)! } : {}),
        agent: deriveAgentKind(events, id),
        ...(deriveBrowserAgent(events, id) ? { browserAgent: deriveBrowserAgent(events, id)! } : {}),
        runtime: deriveRuntime(events),
        origin: deriveOrigin(events),
        ...assertionVerdicts(events),
        ...(deriveHealth(events) ? { health: deriveHealth(events)! } : {}),
      };
      if (st) this.refCache.set(id, { ino: st.ino, size: st.size, mtimeMs: st.mtimeMs, ref });
      refs.push(ref);
    }
    for (const id of this.refCache.keys()) {
      if (!seen.has(id)) this.refCache.delete(id);
    }
    // Most-recent session first.
    refs.sort((a, b) => (a.lastTs ?? "") < (b.lastTs ?? "") ? 1 : -1);
    return refs;
  }

  async readEvents(sessionId: string, sinceSeq?: number): Promise<ManduEvent[]> {
    const path = this.pathFor(sessionId);
    if (!existsSync(path)) return [];
    const raw = readFileSync(path, "utf-8");
    const events: ManduEvent[] = [];
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        continue; // tolerant: skip an unparseable line (matches arbiter IPC)
      }
      // coerceEvent repairs emitter variances (e.g. a net_action's epoch-ms ts /
      // missing invariant) so OS-interceptor traces render instead of vanishing.
      const ev = coerceEvent(parsed);
      if (!ev) continue;
      if (sinceSeq !== undefined && ev.seq <= sinceSeq) continue;
      events.push(ev);
    }
    return sortCanonical(events);
  }

  subscribe(sessionId: string, listener: EventListener, sinceSeq?: number): Unsubscribe {
    const path = this.pathFor(sessionId);
    // With sinceSeq set, replay the backlog (seq > sinceSeq) then tail from
    // there; with it omitted, prime from the current tail so only *new* lines
    // are emitted (the live-tail behavior the SSE relay relies on).
    let lastSeq = sinceSeq ?? -1;
    if (sinceSeq !== undefined) {
      void this.readEvents(sessionId, sinceSeq).then((backlog) => {
        for (const ev of backlog) {
          lastSeq = Math.max(lastSeq, ev.seq);
          listener(ev);
        }
      });
    } else {
      void this.readEvents(sessionId).then((evs) => {
        if (evs.length) lastSeq = evs[evs.length - 1]!.seq;
      });
    }
    if (!existsSync(path)) {
      // Nothing to tail yet; return a no-op unsubscribe.
      return () => {};
    }
    const watcher = watch(path, () => {
      void this.readEvents(sessionId, lastSeq).then((fresh) => {
        for (const ev of fresh) {
          lastSeq = Math.max(lastSeq, ev.seq);
          listener(ev);
        }
      });
    });
    this.watchers.set(watcher, sessionId);
    return () => {
      watcher.close();
      this.watchers.delete(watcher);
    };
  }

  /** No arbiter behind a file source → no policy rules to surface. */
  async policySnapshot(): Promise<PolicySnapshot | null> {
    return null;
  }

  /**
   * Delete `<dir>/<sessionId>.ndjson` and stop any live tails on it. Like the
   * arbiter's event store, this is a policy-free storage primitive (any
   * session, live or test — the route's mutating gates are the protection).
   * An unknown session rejects (→ the route's 404) rather than silently
   * succeeding.
   */
  async deleteSession(sessionId: string): Promise<void> {
    const path = this.pathFor(sessionId);
    if (!existsSync(path)) throw new Error(`unknown session: ${sessionId}`);
    // Close this session's watchers FIRST so the unlink can't fire a final
    // change callback into a listener for a file that no longer exists.
    for (const [w, sid] of this.watchers) {
      if (sid !== sessionId) continue;
      w.close();
      this.watchers.delete(w);
    }
    unlinkSync(path);
    this.refCache.delete(sessionId);
  }

  close(): void {
    for (const w of this.watchers.keys()) w.close();
    this.watchers.clear();
  }

  private pathFor(sessionId: string): string {
    return join(this.dir, `${sessionId}.ndjson`);
  }
}

