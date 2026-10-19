/**
 * event-source — the EventSource seam between the dashboard and the event log.
 *
 * Mandu-new (NO reference origin). docs/design/ui/dashboard.md §3 specifies the
 * canonical append-only event log produced by the arbiter over IPC (the `events`
 * paged-read op + a `subscribe` push stream the dashboard relays over SSE). This
 * module defines a small `EventSource` interface and TWO implementations behind
 * it:
 *
 *   - FileEventSource  — reads append-only NDJSON at `<dir>/<sessionId>.ndjson`
 *                        for tests and local demo. This is the proven path today.
 *   - ArbiterEventSource — connects to the arbiter Unix socket and serves live
 *                        sessions/events from the arbiter's `sessions`/`events`
 *                        request/response ops plus a dedicated `subscribe` push
 *                        connection (backlog then live frames).
 *
 * The API server depends only on `EventSource`, so flipping local→arbiter is a
 * one-line construction change in server-main (env-driven); server.ts and the
 * frontend are unchanged.
 *
 * This file is the BARREL of the src/event-source/ decomposition (agent-
 * legibility split, behavior-preserving): the public API is re-exported
 * unchanged from four cohesive modules —
 *   contract.ts        the EventSource interface, SessionRef, listener types,
 *                      canonical ordering (sortCanonical)
 *   registry.ts        the canonical e2e test registry + per-class badges and
 *                      the per-session sidebar derivations (label/agent/verdicts)
 *   file-source.ts     FileEventSource (NDJSON dir; tests + local demo)
 *   arbiter-source.ts  ArbiterEventSource (live NDJSON IPC over the arbiter socket)
 * The developer view's recorded sources are not re-exported here: its
 * extension imports them where it uses them (dashboard.md §4.25ac) —
 *   recorded-source.ts RecordedEventSource (replay runs on disk, read-only),
 *                      RecordedSources and the CompositeEventSource
 *   ci-live-source.ts  CiLiveEventSource (a CI live run's carried event logs)
 *   own-arbiter-source.ts OwnArbiterEventSource (a local `--own-arbiter` live
 *                      run's private arbiter's event logs, read-only, tailed)
 */

export * from "./event-source/contract.js";
export * from "./event-source/registry.js";
export * from "./event-source/file-source.js";
export * from "./event-source/arbiter-source.js";
