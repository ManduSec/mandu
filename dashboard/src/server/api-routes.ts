/**
 * server/api-routes — the read-mostly observability REST + SSE routes
 * (`/api/sessions`, `/api/events`, `/api/stream`, `/api/policy/panel`),
 * extracted VERBATIM from src/server.ts in the server.ts decomposition; see
 * server.ts for the route map and security posture. handle() in server.ts
 * still owns the matching + the source-IP/auth gating; these are the
 * per-route bodies. The developer view's own reads are in
 * the developer view's own module (dashboard.md §4.25ac).
 */

import { type IncomingMessage, type ServerResponse } from "node:http";

import { json, jsonConditional, requireCsrf } from "./http-util.js";
import { type EventSource, type SessionRef } from "../event-source.js";
import { toSessionViewModel, revealDeliveredReply, revealPairedOriginals } from "../view-model.js";
import { buildSidebarSections, type SessionBatch, type SidebarSections, type SidebarTestRun, type SidebarWatchRun } from "../session-batches.js";
import { type ManduEvent } from "../event-model.js";
import { type DrillShortIndex } from "../drill-shorts.js";
import { sessionCwd, sessionViewRoots } from "../session-paths.js";
import { toPolicyPanelViewModel, type PolicyPanelVM } from "../view-model/policy-panel.js";
import { toHumanPlaneVM } from "../view-model/human-plane.js";
import { filePaths } from "./path-kinds.js";
import { type HumanPlaneStatus } from "../event-source/contract.js";
import { type PolicySnapshot, type VerdictEntry } from "../policy-model.js";
import { type ApprovalsArbiter } from "./approval-routes.js";
import { countsOfView, sessionCounts, type SessionCounts } from "../view-model/session-counts.js";
import { redactEvent, redactEvents } from "../view-model/redact.js";

/**
 * Default cap on the events `/api/events` ships (and models + the client renders)
 * up front. A session over this returns its first window plus a `truncated` flag +
 * `total`, so the page paints fast and the client offers an explicit "load all"
 * (`limit=0`). Sized well above a normal session so only pathological ones are
 * capped; the arbiter's coalescer already bounds the common runaway case.
 */
export const DEFAULT_EVENT_LIMIT = 2000;

// ── REST: /api/sessions ──────────────────────────────────────────────────────

/** The wire form of a recorded row's `replay` annotation: what the sidebar
 *  row draws (dev/js/app.js replayRow). Its run id is the batch id, its key is
 *  in the session id, the run's commit/ref/source/start ride the batch
 *  (SessionBatch.replayRun), and the session panel reads the rest from
 *  /api/replay/runs/<runId> (dashboard.md §4.30). */
export type WireReplay = Omit<NonNullable<SessionRef["replay"]>, "runId" | "key" | "run">;
export type WireSessionRef = Omit<SessionRef, "replay"> & { replay?: WireReplay };
/** A flat label-map row: no replay annotation and no chip counts (both are
 *  drawn from the row in `sections`). */
export type WireFlatSessionRef = Omit<SessionRef, "replay" | "counts">;
export type WireBatch = Omit<SessionBatch, "sessions"> & { sessions: WireSessionRef[] };
/** What this dashboard can start, by the runners it was built with (`server-main.ts`
 *  builds none under `DASHBOARD_CONTROL=0`): an agent run (`/api/run`), a test suite
 *  (`/api/test`), a drill (`POST /api/drills`). The sidebar's empty lines read it, so
 *  they never point at a button whose surface says it is off (dashboard.md §4.8). */
export interface StartCapabilities { agent: boolean; suite: boolean; drill: boolean }

export function wireReplay(r: NonNullable<SessionRef["replay"]>): WireReplay {
  const { runId: _runId, key: _key, run: _run, ...row } = r;
  return row;
}

/**
 * The /api/sessions body (pure; dashboard.md §4.30). The list goes out ONCE
 * per role: `sessions` is the flat label/selection map, without the replay
 * annotation (a recorded row is drawn from its section); `sections` carries
 * the rows the sidebar draws, a replay row's annotation trimmed to what the
 * row shows. The old `batches` copy (the pre-sections single list) is gone:
 * the client reads it only from a server that sends no `sections`. A row's
 * chip counts (`counts`, §4.33) ride the section rows only, like `replay`.
 */
export function sessionsPayload(
  sessions: SessionRef[],
  sections: SidebarSections,
  canDelete: boolean,
  canStart: StartCapabilities,
): { sessions: WireFlatSessionRef[]; sections: Record<keyof SidebarSections, WireBatch[]>; canDelete: boolean; canStart: StartCapabilities } {
  const flat = sessions.map((s): WireFlatSessionRef => {
    if (!s.replay && !s.counts) return s;
    const { replay: _replay, counts: _counts, ...rest } = s;
    return rest;
  });
  const rows = (batches: SessionBatch[]): WireBatch[] =>
    batches.map((b) => ({ ...b, sessions: b.sessions.map((s): WireSessionRef => (s.replay ? { ...s, replay: wireReplay(s.replay) } : s)) }));
  return {
    sessions: flat,
    sections: { live: rows(sections.live), drills: rows(sections.drills), replay: rows(sections.replay), testing: rows(sections.testing) },
    canDelete,
    canStart,
  };
}

/** What the developer view adds to the session list (its extension passes
 *  them; the product's server, none). */
export interface SessionListExtras {
  /** The test runs, which the testing batches join (per-scenario ✓/✗). */
  testRuns?: SidebarTestRun[];
  /** The recorded drill runs, which the DRILLS batches join. */
  watchRuns?: SidebarWatchRun[];
  /** `watchRuns` came from a store the server read: a drill session with no
   *  run there is RECORD LOST (session-batches.ts SidebarOptions). */
  watchStoreRead?: boolean;
  /** The catalog's short indexes, which badge the drill rows (drill-shorts.ts). */
  drills?: DrillShortIndex;
  /** What this server can start (its runners); none by default. */
  canStart?: StartCapabilities;
}

export async function apiSessions(
  source: EventSource,
  url: string,
  req: IncomingMessage,
  res: ServerResponse,
  extras: SessionListExtras = {},
): Promise<void> {
  const { watchRuns = [], watchStoreRead = false, drills, canStart = { agent: false, suite: false, drill: false } } = extras;
  const sessions = await source.listSessions();
  // `sessions` stays for the flat label map. `sections` splits the sidebar
  // into its groups and joins testing batches with their test-run records
  // (per-scenario ✓/✗ results). See session-batches.ts and sessionsPayload.
  const runs = extras.testRuns ?? [];
  // The day a session is filed under is a PRESENTATION call, so it belongs to
  // the viewer's clock — and this process's zone is not it (the docker rig runs
  // the dashboard in a UTC container that a KST browser watches on :4500). The
  // client sends its resolved IANA zone (app.js loadSessions); we key days in
  // THAT zone and never guess. Absent/garbage → localDayKey falls back to ours,
  // which is right for the common case where server and browser share a host.
  const tz = new URLSearchParams(url.split("?")[1] ?? "").get("tz") || undefined;
  // An ETag over the exact body answers an unchanged list with 304 (the
  // inspector's poll sends If-None-Match), and a changed one goes out gzipped.
  await jsonConditional(req, res, sessionsPayload(
    sessions,
    // Date.now() feeds the recent-activity RUNNING rule (SessionRef.status) —
    // the one non-deterministic input, injected so session-batches stays pure.
    buildSidebarSections(sessions, runs, Date.now(), tz, watchRuns, { watchStoreRead, ...(drills ? { drills } : {}) }),
    // Capability advertisement: sessions are deletable iff the source
    // implements deleteSession (an older arbiter without the op → false, and
    // the sidebar renders no 🗑 affordance at all).
    typeof source.deleteSession === "function",
    canStart,
  ));
}

// ── REST: /api/policy/panel ───────────────────────────────────────────────────
// The Policy panel's projected view-model (policy-surface.md §9.4): posture,
// human decisions (standing verdicts), the usage-rule catalog — the server
// projects, the browser paints (view-model/policy-panel.ts is the unit-tested
// logic; egress.js the shell). Same fail-soft posture as /api/policy: no
// arbiter / old arbiter → the VM says unavailable/not-known, never a 500.

/** The policy-panel projection the Policy panel AND the product home share:
 *  the live snapshot, back-filled with the approvals op on an arbiter that
 *  predates the snapshot's `verdicts` extension. */
/** When the AI first read each pending row's item as it was, before it was
 *  masked, by verdict id (home-routes.ts `readFirstLookup`, over each row's
 *  sessions; dashboard.md §4.34 "Read before it was marked"). */
export type ReadFirstLookup = (verdicts: readonly VerdictEntry[]) => Promise<ReadonlyMap<string, string>>;

/** `readFirst`: so a waiting card never says the AI never read an item it
 *  read before it was masked. Absent, or failing: none known, the words as
 *  before (display only). `home`: the folder an answer's words call `~`. */
export async function loadPolicyPanel(
  source: EventSource,
  approvals: ApprovalsArbiter | undefined,
  readFirst?: ReadFirstLookup,
  home = "",
): Promise<PolicyPanelVM> {
  const snapshot = await loadPolicySnapshot(source, approvals);
  let early: ReadonlyMap<string, string> | undefined;
  if (readFirst && snapshot?.verdicts?.length) {
    try {
      early = await readFirst(snapshot.verdicts);
    } catch {
      early = undefined;
    }
  }
  // The human plane's exposure (arbiter-human-plane.md §10.1.1), a human-plane
  // read beside the snapshot. Display only; any failure is "unknown".
  let humanPlane: HumanPlaneStatus | null = null;
  try {
    humanPlane = (await source.humanPlaneStatus?.()) ?? null;
  } catch {
    humanPlane = null;
  }
  // Which rules reaching everything inside name a file (path-kinds.ts):
  // display only, so they read as that file.
  const files = await filePaths((snapshot?.document?.paths ?? []).filter((p) => p.recursive).map((p) => p.path));
  return { ...toPolicyPanelViewModel(snapshot, early, home, files), humanPlane: toHumanPlaneVM(humanPlane) };
}

/** The live policy snapshot (null when there is none), its `verdicts`
 *  back-filled from the approvals op on an older arbiter. */
export async function loadPolicySnapshot(
  source: EventSource,
  approvals: ApprovalsArbiter | undefined,
): Promise<PolicySnapshot | null> {
  let snapshot: PolicySnapshot | null = null;
  try {
    snapshot = ((await source.policySnapshot?.()) ?? null) as PolicySnapshot | null;
  } catch {
    snapshot = null;
  }
  // VERSION-SKEW FALLBACK (§4): an arbiter older than the snapshot extension
  // reports no `verdicts`, but the approvals op PREDATES the extension and
  // serves the queue (every status) on any arbiter — back-fill it so the
  // Human-decisions tab keeps working across skew. Only posture and the rule
  // catalog genuinely need a new arbiter (the catalog must come from the code
  // that ENFORCES it — a dashboard-bundled copy could drift), and the VM keeps
  // reporting those honestly as unknown.
  if (snapshot && snapshot.verdicts === undefined && approvals) {
    try {
      snapshot = { ...snapshot, verdicts: await approvals.egressApprovals() };
    } catch {
      // Arbiter went away mid-request — verdicts stay honestly not-known.
    }
  }
  return snapshot;
}

/** Sent uncompressed (json, never jsonConditional): the queue carries symbol
 *  names and secret paths beside destinations an agent chose, the mix a
 *  compression side channel works on (dashboard.md §4.30). */
export async function apiPolicyPanel(
  source: EventSource,
  approvals: ApprovalsArbiter | undefined,
  res: ServerResponse,
  readFirst?: ReadFirstLookup,
  home = "",
): Promise<void> {
  json(res, 200, { panel: await loadPolicyPanel(source, approvals, readFirst, home) });
}

// ── REST: /api/events?session=ID[&sinceSeq=N] ─────────────────────────────────
// Returns the raw events AND the derived per-session view-model so a thin
// browser client can render without reimplementing the model (the same
// toSessionViewModel the unit/e2e tests assert).
//
// VALUES (dashboard.md §6, server/read-gate.ts): with `values` false (no
// admin session) the events are the signed-out projection (view-model/
// redact.ts: what the AI saw, no original, no symbol value, no HumanView
// file), the view-model is derived from THOSE, and the deep reveal does not
// run. `valuesShown` tells the page which one it got.

/** What a front-end adds to one session's `/api/events` body (the
 *  developer view's test setup panel); null adds nothing. */
export type EventsExtra = (sessionId: string, events: ManduEvent[]) => Record<string, unknown> | null;

export async function apiEvents(
  source: EventSource,
  log: (msg: string) => void,
  url: string,
  res: ServerResponse,
  values = false,
  extra?: EventsExtra,
): Promise<void> {
  const params = new URLSearchParams(url.split("?")[1] ?? "");
  const sessionId = params.get("session");
  if (!sessionId) {
    json(res, 400, { error: "missing ?session=" });
    return;
  }
  const sinceSeqRaw = params.get("sinceSeq");
  const sinceSeq = sinceSeqRaw !== null ? Number(sinceSeqRaw) : undefined;
  // Incremental loading: cap the events shipped/modeled/rendered up front so a
  // huge session can't stall the page. `limit` overrides the default; limit<=0
  // means "all" (the client's explicit load-all). The cap keeps the FIRST window
  // in canonical order — the trace reads from the start, the rest load on demand.
  // The viewModel is derived over exactly the returned slice.
  const limitRaw = params.get("limit");
  const limit =
    limitRaw !== null && Number.isFinite(Number(limitRaw)) ? Number(limitRaw) : DEFAULT_EVENT_LIMIT;
  const read = await source.readEvents(sessionId, sinceSeq);
  const all = values ? read : redactEvents(read);
  const total = all.length;
  const events = limit > 0 && total > limit ? all.slice(0, limit) : all;
  const truncated = events.length < total;
  const viewModel = toSessionViewModel(sessionId, events);
  // The header's "N masked · N steps blocked · N approvals asked" are the
  // session list's counts (dashboard.md §4.33, session-counts.ts), over the
  // WHOLE log even when the events above are capped, so a long session's
  // header and its row agree. Read off the view-model when it covers the
  // whole log; recomputed over every event only when capped. A `sinceSeq`
  // read is a tail, so it carries none. Fail-soft: a projection that throws
  // costs the header its counts (the client then counts the loaded steps).
  let counts: SessionCounts | undefined;
  if (sinceSeq === undefined) {
    try {
      counts = (truncated ? sessionCounts(all) : countsOfView(viewModel)) ?? {};
    } catch (err) {
      log(`session counts skipped: ${(err as Error).message}`);
    }
  }
  // §4.2c delivery-zone deep reveal: resolve the DELIVERED reply's symbols to
  // full-fidelity originals via the arbiter (nested fs-sync chains collapse —
  // view-model/delivery.ts). Fails soft: without an arbiter-backed source (or
  // with one that errors, or one that never minted the symbols — a docker/CI
  // e2e run's arbiter dies with its container) the reveal still collapses
  // nested chains from the session's own event-carried band values.
  // Signed out: no reveal at all (not even the local collapse, whose band
  // values the projection already left out).
  if (values) try {
    await revealDeliveredReply(
      viewModel.dualLanes,
      source.desymbolize ? (t) => source.desymbolize!(t) : undefined,
    );
  } catch (err) {
    log(`delivery deep reveal skipped: ${(err as Error).message}`);
  }
  // §4.2f the paired rows' right-hand originals: a masked result (a twin read
  // above all) is a NESTED chain whose inner original often lives only in the
  // arbiter's table — deepen what the local collapse left tokened. Same
  // utility-only posture as the delivered-reply reveal.
  if (values) try {
    await revealPairedOriginals(
      viewModel.paired,
      source.desymbolize ? (t) => source.desymbolize!(t) : undefined,
    );
  } catch (err) {
    log(`paired-rows deep reveal skipped: ${(err as Error).message}`);
  }
  // What the caller adds (the developer view: an e2e TEST session's setup
  // panel, dashboard.md §4.11); null adds nothing.
  const added = extra?.(sessionId, events) ?? null;
  // For EVERY session, ship the recorded run paths (session-paths.ts — the same
  // event-sourced facts testSetup embeds for test sessions) so the client's
  // session-wide short↔full path display works on live sessions too. Absent
  // when the session recorded none — the client then has nothing to fold.
  const sessionPaths = { cwd: sessionCwd(events), ...sessionViewRoots(events) };
  const anyPath = sessionPaths.cwd || sessionPaths.agentViewRoot || sessionPaths.humanViewRoot;
  json(res, 200, {
    sessionId, events, viewModel, total, returned: events.length, truncated, valuesShown: values,
    ...(counts ? { counts } : {}),
    ...(anyPath ? { sessionPaths } : {}),
    ...(added ?? {}),
  });
}

// ── SSE: /api/stream?session=ID (NEW, §3.1) ───────────────────────────────────

export function apiStream(
  source: EventSource,
  url: string,
  req: IncomingMessage,
  res: ServerResponse,
  /** The viewer holds the admin session (read-gate.ts): otherwise each event
   *  goes out as the signed-out projection (view-model/redact.ts). */
  values = false,
): void {
  const params = new URLSearchParams(url.split("?")[1] ?? "");
  const sessionId = params.get("session");
  if (!sessionId) {
    json(res, 400, { error: "missing ?session=" });
    return;
  }
  // The client fetches the session's events via /api/events BEFORE opening the
  // stream, then passes the highest seq it already holds as ?sinceSeq=. We
  // forward it to subscribe so the backlog (seq > sinceSeq) is empty and ONLY
  // genuinely new (live) events stream as `append`s. Without this the source
  // replays the WHOLE backlog as appends and the client's per-append re-render
  // storms the page (header/tool-call sidebar/main flicker). Same parse as
  // /api/events: omit when absent/NaN so a direct (backlog-wanting) client still
  // gets the full replay.
  const sinceSeqRaw = params.get("sinceSeq");
  const sinceSeq =
    sinceSeqRaw !== null && Number.isFinite(Number(sinceSeqRaw)) ? Number(sinceSeqRaw) : undefined;
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  res.write(`event: hello\ndata: ${JSON.stringify({ sessionId, valuesShown: values })}\n\n`);
  const unsubscribe = source.subscribe(
    sessionId,
    (event) => {
      res.write(`event: append\ndata: ${JSON.stringify(values ? event : redactEvent(event))}\n\n`);
    },
    sinceSeq,
  );
  // Heartbeat so proxies don't drop the idle connection.
  const heartbeat = setInterval(() => res.write(`: ping\n\n`), 15_000);
  req.on("close", () => {
    clearInterval(heartbeat);
    unsubscribe();
  });
}
