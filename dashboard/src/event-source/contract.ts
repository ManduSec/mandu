/**
 * event-source/contract — the EventSource interface, the SessionRef sidebar
 * row, and canonical event ordering (extracted VERBATIM from src/event-source.ts
 * in the event-source decomposition; see the barrel for the module map).
 */

import { type ManduEvent } from "../event-model.js";
import type { PolicySnapshot } from "../policy-model.js";
import type { SessionHealth } from "../session-health.js";
import type { SessionCounts } from "../view-model/session-counts.js";
import type { Agent } from "../generated/agents.js";

/** A live subscriber callback. Receives each newly-appended event. */
export type EventListener = (event: ManduEvent) => void;

/** Unsubscribe handle returned by subscribe(). */
export type Unsubscribe = () => void;

/** Where a session label came from: the person's first prompt, or a fallback
 *  that describes the session to a developer (the launcher's posture line, a
 *  U-LLM inspection, a system log's name). The product pages show only a
 *  prompt (dashboard.md §4.25). */
export type SessionLabelFrom = "prompt" | "posture" | "inspection" | "system";

export interface SessionRef {
  /** Mandu scope id (the NDJSON basename / arbiter session key). */
  id: string;
  /** A human-readable label derived from the session's first user prompt, so the
   *  sidebar differentiates sessions by what they DO, not by an opaque scope id
   *  (which is `<unix-ts>-<pid>`). null when no prompt is recoverable. */
  label: string | null;
  /** Where `label` came from (registry.ts `sessionLabel`). A fallback
   *  (`posture`, `inspection`, `system`) names the session for a developer,
   *  so the product pages give it no title. Absent with no label. */
  labelFrom?: SessionLabelFrom;
  /** The folder the agent worked in (session-paths.ts `sessionCwd`, the one
   *  the session's row names), read from the agent's own prompt blocks, never
   *  a tool result. History's search matches it (dashboard.md §4.25ae);
   *  absent when the agent records none (Codex, an offline replay). */
  cwd?: string;
  /** Event count currently known for the session. */
  eventCount: number;
  /** ISO ts of the FIRST event (the session's start), if any. With `lastTs`
   *  this gives the sidebar the session's start clock + elapsed duration. */
  firstTs: string | null;
  /** ISO ts of the most recent event, if any. */
  lastTs: string | null;
  /** The agent exited: its launcher recorded `session_exit` and no agent
   *  activity came after it (view-model/session-exit.ts, the rule the
   *  product pages use). Set by the sources that read the session's events;
   *  absent when no exit is recorded or the events could not be read. The
   *  list then never calls the session "running" by recency
   *  (session-batches.ts `sessionStatus`, dashboard.md §4.10.4). */
  exited?: true;
  /** Session HEALTH (session-health.ts, dashboard.md §4.21): the posture the
   *  session actually runs at — ok / degraded / broken — derived from the
   *  launcher's, the reply-filter's and the proxy's health events. Absent
   *  for a session no launcher started (proxy-only / test-harness traces). */
  health?: SessionHealth;
  /** True if any known event has violatedInvariant — lets the session list
   *  flag a violated session without loading every event client-side. */
  violated: boolean;
  /** The row's "N masked · N asks · N blocked" chips (dashboard.md §4.33,
   *  view-model/session-counts.ts): derived from the events where the row is,
   *  and cached with it. A zero count is absent; absent altogether when all
   *  are zero or the events could not be read. Sent on the list's rows only
   *  (api-routes sessionsPayload strips it from the flat label map). */
  counts?: SessionCounts;
  /** Coarse annotations derived from the session id, e.g. `["test"]` for an e2e
   *  test run (id starting `e2e-`). Lets the sidebar badge non-production runs so
   *  test traffic isn't mistaken for a real session. Omitted when there's none. */
  tags?: string[];
  /** The session's TENANT (policy-surface.md §2.7): from the events'
   *  `tenant` stamp (the arbiter's `sessions` summary carries it, or the first
   *  stamped event). A stamped `test` session ALSO carries the `"test"` tag so
   *  every existing consumer of tags keeps working; a stamped `live` session
   *  never does, even when its id happens to look like a test prefix. Omitted
   *  for unstamped, pre-tenancy sessions (id-prefix heuristics apply). */
  tenant?: "live" | "test";
  /** Stable `T<n>` number for a registered e2e test scenario (see TEST_REGISTRY),
   *  so a test is referenceable as "T8" in the sidebar. Omitted for non-tests. */
  testNumber?: string;
  /** Batch id shared by sessions run together (from the events' `batchId`), so the
   *  sidebar can group them. Omitted when no event carried one (→ "Ungrouped"). */
  batchId?: string;
  /** What this session IS within its batch, from the launcher's
   *  `launch_posture.batchMember` (MANDU_BATCH_MEMBER, the watch runner's):
   *  one watch scenario variant (`{kind: "scenario", key: "S3@haiku"}`) or,
   *  under --shared-session, one posture group (`{kind: "posture", key:
   *  "S1"}`). The sidebar's scenario-id badge prefers it to reading the
   *  session id, where posture group `S1` and scenario `S1` look the same
   *  (dashboard.md §4.22). Omitted when the launch named none. */
  batchMember?: { kind: "scenario" | "posture"; key: string };
  /** Per-scenario test outcome for a TEST session, joined from the test-runner's
   *  parsed run results (session-batches.ts buildSidebarSections — NOT set by an
   *  EventSource). Drives the ✓/✗/− mark on the Testing-section session row. */
  testResult?: "pass" | "fail" | "skip";
  /** Which agent CLI drove the session (deriveAgentKind). For a registered e2e
   *  test session the SESSION-ID CLASS decides; otherwise the Track A emitter
   *  does (`openai-proxy` → Codex, `anthropic-proxy` → Claude Code). The id must
   *  win because OpenClaw and OpenCode also speak Anthropic Messages, so the
   *  emitter cannot tell the three anthropic-proxy agents apart. Omitted when
   *  neither signal is present (an OS-interceptor-only trace), so the sidebar
   *  badges only what it knows. */
  agent?: Agent;
  /** Which browser agent drove the session (deriveBrowserAgent): `jev` /
   *  `browser-use` when a drill names it, `browser` for any launch behind the
   *  DevTools relay. Omitted otherwise. The sidebar's badge beside `agent`. */
  browserAgent?: string;
  /** Execution runtime the e2e harness ran the session under: `"docker"` (the
   *  containerized rig) or `"host"` (dev box directly), derived from the events'
   *  `runtime` tag. Omitted when no event carries it (non-e2e traffic). Drives
   *  the sidebar's docker/host badge — see docs/design/testing/docker-e2e.md §2. */
  runtime?: "docker" | "host";
  /** WHO started the session: `"ci"` (a GitLab pipeline job) or `"local"` (a human
   *  on the dev box), derived from the events' `origin` tag. Orthogonal to
   *  `runtime` — that is WHERE it ran, this is WHO ran it, and a CI run is also a
   *  docker run. Omitted when no event carries it (non-e2e traffic, or sessions
   *  predating the field). Drives the sidebar's CI badge — see docs/design/testing/docker-e2e.md §1.6. */
  origin?: "ci" | "local";
  /** The recorded WATCH run this session belongs to (dashboard.md §4.22),
   *  joined by session-batches.ts from the run store — NOT set by an
   *  EventSource. `recorded` says whether a terminal recording (asciicast)
   *  exists for it: sessions the watch runner drove have one (unless
   *  --no-record or the run predates the recorder); a session you launched
   *  yourself in a terminal never does. Drives the sidebar's 🎬 chip. */
  watch?: {
    runId: string;
    recorded: boolean;
    /** RECORD LOST (2026-10-02, dashboard.md §4.22): this session's recording
     *  is gone from disk — its run is not in the watch store at all (then
     *  `runId` is the run the session names: its batch stamp or id prefix,
     *  and nothing else is joined), or the run's record names this session's
     *  cast and the file is not there. The row says "record lost" and offers
     *  no player. Present only when true. */
    recordLost?: true;
    /** …and the reason is that the store holds no run `runId` at all (no
     *  record, no chapters, no verdicts: only the session's events). Absent
     *  when the run is stored and only its recording is gone. */
    runMissing?: true;
    /** RECORD NOT IN THE STORE YET (2026-10-03, dashboard.md §4.22): the run
     *  is still in progress (its runner's pid is alive) and writes its record
     *  outside the watch store, where it cannot be read yet. The row says
     *  "running, record not in the store yet", never "record lost". */
    recordPending?: true;
    /** the run's own directory outside the store its record is read from (or
     *  will be), while the run is alive */
    recordAt?: string;
    /** the session's own scenario verdict when `scenario` is set (`running`
     *  until graded), else the run's rollup */
    verdict?: "PASS" | "WARN" | "FAIL" | "TIMEOUT" | "PAUSED" | "running";
    /** the ONE catalog scenario this session ran (one `mandu claude` per
     *  scenario since 2026-09-19): the sidebar row is named by it and marked
     *  P/F/− by its verdict. Absent on a shared-session / older run's row. */
    scenario?: { id: string; title: string; setting: string };
  };
  /** The catalog drill a LIVE drill row ran, with its short index (`U7`;
   *  test-reorganization.md §6.1.1, dashboard.md §4.35): joined by
   *  session-batches.ts buildSidebarSections from the catalog index
   *  (drill-shorts.ts), never set by an EventSource. `via` is where the
   *  scenario key came from: the run's record (`run`), the launch's word
   *  (`launch`, batchMember), or the session id alone (`id`: inferred, which
   *  the badge says). `key` is the key as recorded when it is an old watch id
   *  the index maps (`S6`); `variant` the model / repetition tail
   *  (`@sonnet#2`, `-sonnet-2`). */
  drillShort?: { short: string; drill: string; title: string; via: "run" | "launch" | "id"; key?: string; variant?: string };
  /** A RECORDED replay-drill session (dashboard.md §4.28, test-reorganization.md
   *  §7.3): set ONLY by the recorded event source from a validated session
   *  record, never derived from events, so no arbiter session can claim it.
   *  Its id is `<runId>/<key>`; the sidebar files it under Replay drills. */
  replay?: {
    runId: string;
    key: string;
    drill: string;
    /** the drill's short index (`C27`), joined from the catalog index by
     *  session-batches.ts (drill-shorts.ts), so an old record is badged
     *  too; absent when the catalog does not list the drill */
    short?: string;
    title: string;
    agent: Agent;
    lane?: string;
    /** `<cols>x<rows>` */
    size: string;
    mode: "interactive" | "headless";
    verdict: "PASS" | "WARN" | "FAIL" | "TIMEOUT";
    /** `warned` (the human was told) only on a session that has such a
     *  check (2026-10-17) */
    tally: Record<"security" | "utility" | "fidelity", { pass: number; total: number }> & { warned?: { pass: number; total: number } };
    script: { version: string; origin: "hand" | "recorded" };
    engine: number;
    /** the Mandu side's recording exists */
    recorded: boolean;
    /** the plain agent's recording exists */
    plainRecorded: boolean;
    /** RECORD LOST (2026-10-02): the record names the Mandu side's cast and
     *  the file is not on disk (replay-run-store.ts `available`). Present
     *  only when true. */
    recordLost?: true;
    /** the run this session belongs to (the batch header names it) */
    run: { commit: string; ref?: string; source: "ci" | "local"; startedAt: string };
  };
  /** Overall verdict of the session's `assertion` event (the e2e harness writes
   *  one per session; latest wins): "fail" iff any check is a BLOCKING fail —
   *  warn/skip don't fail, matching the §4.13 panel. Omitted when the session
   *  carries no assertion event. Unlike `testResult` (joined only for runs the
   *  dashboard launched), this marks ✓/✗ on ANY e2e session, e.g. a standalone
   *  `npm test` run (event-source.ts assertionVerdicts). */
  checksVerdict?: "pass" | "fail";
  /** WHICH groups carry a blocking fail behind a "fail" checksVerdict — ordered
   *  security-integrity, security-confidentiality, security (a legacy
   *  aspect-less check), utility, fidelity (event-source.ts assertionVerdicts).
   *  Drives the sidebar F badge's which-property-broke tooltip. Omitted when
   *  nothing failed. */
  checksFailed?: string[];
  /** Simplified sidebar state for the row's P/R/F badge, computed by
   *  session-batches.ts buildSidebarSections (NOT set by an EventSource):
   *  pass/fail from `testResult ?? checksVerdict`; "running" while the joined
   *  test run is still executing this scenario, or — for verdict-less (live)
   *  sessions — while the last event is within the recent-activity window;
   *  "skip" mirrors a skipped scenario. Omitted when none of those apply
   *  (e.g. an ended live session, which has no pass/fail concept). */
  status?: "pass" | "running" | "fail" | "skip";
  /** Verdict of just the HISTORY-FIDELITY oracle checks (the live claude-e2e
   *  "dashboard render ≡ Claude Code's own transcript" block; filtered from the
   *  assertion event by HISTORY_FIDELITY_ASSERTS). Omitted when the oracle
   *  didn't run (replay/codex suites, non-test sessions). */
  historyFidelity?: "pass" | "fail";
}

/**
 * The single dependency the API server has on its data feed. Both the local
 * file source and the future arbiter source satisfy it identically, so §3's
 * REST + SSE endpoints are written once.
 */
/** The arbiter's `humanPlaneStatus` answer (arbiter/ipc/protocol.ts
 *  HumanPlaneStatusResult), structurally. */
export interface HumanPlaneStatus {
  exposed: boolean;
  /** When the arbiter first saw the current exposure (ms); null while walled. */
  since: number | null;
  /** The launches with no wall, oldest first: the launcher's pid, its mode
   *  and posture, the session it named (display only). */
  launches: Array<{ pid: number; mode: string; posture: string; session?: string; begunAt?: number }>;
}

/** The arbiter's `sessionUpstream` answer (arbiter/ipc/protocol.ts
 *  SessionUpstreamResult), structurally. */
export interface SessionUpstream {
  sessionKey: string;
  endpoint: string | null;
  location: "local" | "external";
  bound: boolean;
}

export interface EventSource {
  /** List known sessions (for the sidebar picker). */
  listSessions(): Promise<SessionRef[]>;
  /**
   * Read a session's events, optionally only those with `seq > sinceSeq`
   * (the §3.1 `events` paging contract). Always returned in canonical order
   * (ts primary, seq tiebreak — §3.2).
   */
  readEvents(sessionId: string, sinceSeq?: number): Promise<ManduEvent[]>;
  /**
   * Subscribe to a session's event stream (backs the SSE `/stream` endpoint).
   * With `sinceSeq` omitted the source streams newly-appended events only
   * (the live tail); with `sinceSeq` set it MAY first replay the backlog of
   * events whose seq > sinceSeq, then the live tail. The returned function
   * unsubscribes. Sources that cannot stream (a static fixture) may return a
   * no-op unsubscribe and never call back.
   */
  subscribe(sessionId: string, listener: EventListener, sinceSeq?: number): Unsubscribe;
  /**
   * The active arbiter policy snapshot (inbound/outbound/origin rules), for the
   * per-tool-call policy modal. OPTIONAL: a arbiter-backed source returns it; a
   * file/fixtures source (no arbiter) omits it or returns null. OBSERVABILITY
   * ONLY and off the security path — the route fails soft to null, never an
   * error, when this is absent/unreachable.
   */
  policySnapshot?(): Promise<PolicySnapshot | null>;
  /**
   * Whether the arbiter's human plane is exposed now: a launch whose agent
   * can reach the human socket is live, so every guard and model-proxy report
   * there is a claim and a confined session beside it gets placeholders,
   * refused protected writes and masked shell output (arbiter-human-plane.md
   * §10.1, §10.1.1; the arbiter's `humanPlaneStatus` op, human plane only).
   * OPTIONAL and OBSERVABILITY ONLY: absent or failing, the Policy panel's
   * chip and the product page show it as unknown, never as walled.
   */
  humanPlaneStatus?(): Promise<HumanPlaneStatus>;
  /**
   * Deep-resolve every `$MDU:*` reference in `text` to its original value
   * (fixpoint — nested chains like the fs-sync twin-Read double-symbolization
   * collapse; unknown symbols stay literal). Backs the §4.2c delivery-zone deep
   * reveal. OPTIONAL and OBSERVABILITY ONLY, same posture as policySnapshot: an
   * arbiter-backed source implements it via the `desymbolize` op; a
   * file/fixtures source (no arbiter) omits it, and the caller degrades to the
   * event-carried one-level values — display fidelity only, never an error.
   */
  desymbolize?(text: string): Promise<string>;
  /**
   * ONE level of one symbol: its raw value with any nested `$MDU:*` tokens
   * left as tokens (the arbiter's shallow `resolve`), or null when unknown.
   * Backs the product page's "show what was hidden" (§4.25b), which must
   * check each nested token for a secret before expanding it, so it cannot
   * use the deep `desymbolize`. OPTIONAL and OBSERVABILITY ONLY, same posture
   * as desymbolize: absent → the page keeps the event-carried values.
   */
  resolveSymbol?(name: string): Promise<string | null>;
  /**
   * Which declared model a session's MAIN conversation is sent to (the
   * arbiter's `sessionUpstream` op, confidentiality plan 11 §7.1): the entry
   * name the launcher bound (null = the agent's default vendor, or unbound)
   * and its location in the law in force. Backs the product agent page's
   * "Main model" line (dashboard.md §4.25l). OPTIONAL and OBSERVABILITY ONLY:
   * absent or failing, the page just leaves the line out.
   */
  sessionUpstream?(sessionKey: string): Promise<SessionUpstream | null>;
  /**
   * The ACTIVE T-LLM handling system prompt (the arbiter's `handlingPrompt`
   * op — the exact text the model-API proxy injects, rendered against the
   * arbiter's LIVE posture, so it must be fetched per view, never cached at
   * boot). Backs the §8.8 "view the active handling prompt" drawer. OPTIONAL
   * and OBSERVABILITY ONLY, same posture as policySnapshot: a file/fixtures
   * source (no arbiter) omits it and the route answers 404, never a crash.
   */
  handlingPrompt?(): Promise<string>;
  /**
   * Delete ONE session's event log plus any per-session in-memory state the
   * source holds (file watchers / the arbiter's seq counters + live streams).
   * OPTIONAL capability: `GET /api/sessions` advertises `canDelete` iff the
   * source implements it, so a dashboard in front of an OLDER arbiter (no
   * `deleteSession` op) simply renders no delete affordance. OBSERVABILITY
   * ONLY — it removes the trace, never anything on the security path (symbol
   * table / policy). Available for ANY session, live or test (2026-07-11: the
   * original test-only rule was dropped at the user's request; what protects
   * live traces is the route's mutating gates — IP allowlist → auth → CSRF —
   * plus the client confirm). Rejects on an unknown session so the route can
   * answer 404 instead of pretending success.
   */
  deleteSession?(sessionId: string): Promise<void>;
  /** Release any held resources (watchers, sockets). */
  close(): void;
}

/** Canonical ordering (§3.2): ts primary, seq tiebreak. */
export function sortCanonical(events: ManduEvent[]): ManduEvent[] {
  return [...events].sort((a, b) => {
    if (a.ts !== b.ts) return a.ts < b.ts ? -1 : 1;
    return a.seq - b.seq;
  });
}
