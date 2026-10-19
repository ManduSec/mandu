/**
 * session-batches — the pure rules that shape the sidebar's session list:
 *   1. groupSessionsIntoBatches — sessions sharing a `batchId` were "run
 *      together" (e.g. one "Run e2e" click) and fold into a collapsible batch;
 *      sessions with no `batchId` group into per-DAY batches (their `lastTs`'s
 *      day in the VIEWER's zone — the caller passes `tz`; see dayKey) that
 *      interleave chronologically with the real ones — no giant "Ungrouped"
 *      catch-all pinned at the bottom.
 *   2. Every batch carries a server-computed, human-meaningful `title`: the
 *      test run's label, a "<suite> e2e run" derivation, the first member's
 *      task label (a live batch is one launcher/Run invocation — name it by
 *      what it did), or the day (ISO date; the client prettifies to
 *      Today/Yesterday/"Jun 21").
 *   3. buildSidebarSections — splits the list into the LIVE section (real agent
 *      sessions) and the TESTING section (e2e TEST sessions), and joins each
 *      testing batch with its test-runner run record (batch id === runId) so
 *      the sidebar shows the run's pass/fail outcome and each TEST session its
 *      per-scenario result.
 *
 * Pure + deterministic (no Date.now — the caller injects `nowMs` for the
 * recent-activity RUNNING rule, which a recorded exit turns off; no
 * formatting) so it is fully unit-tested and app.js / the server only RENDER
 * its output (dashboard.md §4: logic lives here).
 * The shapes it reads and returns live in session-batch-types.ts.
 * See docs/design/ui/dashboard.md §4.10.1.
 */
import { parseTestSessionId, systemLogKind, type SessionRef } from "./event-source.js";
import type {
  BatchMarks, BatchRunSummary, BatchStatus, SessionBatch, SidebarSections, SidebarTestRun, SidebarWatchRun,
} from "./session-batch-types.js";
import { liveDrillShort, type DrillShortIndex } from "./drill-shorts.js";
import { localDayKey } from "./transcript.js";

// The shapes (SessionBatch and the run views it joins) live in
// session-batch-types.ts; re-exported so every importer keeps one path.
export type {
  BatchMarks, BatchRunSummary, BatchStatus, SessionBatch, SidebarSections, SidebarTestRun, SidebarWatchRun,
} from "./session-batch-types.js";

/** Prefix of the synthetic per-day batch ids (`day:<YYYY-MM-DD>` / `day:undated`). */
export const DAY_BATCH_PREFIX = "day:";
/** The TESTING section re-keys its day batches (`day-testing:<YYYY-MM-DD>`) so
 *  the two sections never render duplicate batch ids (fold state + DOM keys
 *  stay distinct between Live's and Testing's day groups). */
export const DAY_TESTING_BATCH_PREFIX = "day-testing:";
/** …and the DRILLS section re-keys its day groups the same way (a drill whose
 *  run predates the batch stamp sits in a day group). */
export const DAY_DRILLS_BATCH_PREFIX = "day-drills:";
/** The Live section's one group of event logs that are not agent sessions
 *  (registry.ts systemLogKind: the admin audit log, net events with no
 *  session). Pinned LAST in Live, after the day groups. */
export const SYSTEM_LOGS_BATCH_ID = "system-logs";
/** Every id the watch runner mints (run ids and the sessions it drives). */
const WATCH_ID_PREFIX = "watch-";

/** How recently a verdict-less session must have emitted an event to still count
 *  as RUNNING (SessionRef.status). A live agent session just stops emitting, so
 *  recency is the signal when nothing else says; sized to survive a long tool
 *  call between model turns. A recorded exit (SessionRef.exited, the launcher's
 *  `session_exit`) outranks it: an ended session is never RUNNING by recency. */
export const RUNNING_WINDOW_MS = 5 * 60_000;

/** The per-session 🎬 annotation (SessionRef.watch) for a session a watch run
 *  drove: which run, whether it has a recording, and the verdict — the
 *  session's OWN scenario verdict when the run gave each scenario its own
 *  session (`running` until graded), else the run's rollup. */
function watchAnnotation(run: SidebarWatchRun, sessionId: string): NonNullable<SessionRef["watch"]> {
  const own = run.scenarios?.find((x) => x.sessionId === sessionId);
  const rollup: NonNullable<SessionRef["watch"]>["verdict"] =
    run.state === "running" ? "running" : run.counts.fail > 0 ? "FAIL" : run.counts.skip > 0 ? "WARN" : "PASS";
  const outside = { ...(run.recordPending ? { recordPending: true as const } : {}), ...(run.recordAt ? { recordAt: run.recordAt } : {}) };
  if (!own) return { runId: run.runId, recorded: run.recorded === true, ...(run.recordLost ? { recordLost: true as const } : {}), ...outside, verdict: rollup };
  const verdict: NonNullable<SessionRef["watch"]>["verdict"] = own.verdict ?? (run.state === "running" ? "running" : undefined);
  // its OWN recording when the run made one per scenario, else the run's
  const lost = own.recordLost ?? (own.recorded === undefined ? run.recordLost : undefined);
  return {
    runId: run.runId, recorded: (own.recorded ?? run.recorded) === true, ...(lost ? { recordLost: true as const } : {}), ...outside, ...(verdict ? { verdict } : {}),
    scenario: { id: own.id, title: own.title, setting: own.setting },
  };
}

/** The run a drill session names when the store has no record of it
 *  (RECORD LOST, dashboard.md §4.22): its `watch-…` batch stamp, else the
 *  runner's default run id read off its own id (`watch-<YYYYMMDDTHHMMSS>-<key>`),
 *  else any batch stamp it carries. Undefined: it names none. */
export function claimedWatchRunId(s: Pick<SessionRef, "id" | "batchId">): string | undefined {
  if (s.batchId?.startsWith(WATCH_ID_PREFIX)) return s.batchId;
  const m = /^(watch-\d{8}T\d{6})-/.exec(s.id);
  if (m) return m[1];
  return s.batchId ?? undefined;
}

/** Options of buildSidebarSections beyond its positional inputs. */
export interface SidebarOptions {
  /** The caller read a watch store into `watchRuns` (the server always does
   *  when it has one): a drill session whose run is not among them is then
   *  RECORD LOST — its record and recording are gone from that store — and
   *  carries `watch.recordLost`. Off (no store consulted), such a session is
   *  left unannotated: absence from a list nobody read proves nothing. */
  watchStoreRead?: boolean;
  /** The catalog's short indexes (drill-shorts.ts, from drills.json): each
   *  replay row gets its drill's (`replay.short`) and each live drill row
   *  the drill it ran (`drillShort`), so the two lists line up (dashboard.md
   *  §4.35). Absent (no source checkout): no row is badged from it. */
  drills?: DrillShortIndex;
}

/** Testing-style order for a watch batch's rows: the run's scenario order
 *  (chapters.json order) for sessions that ARE a scenario, then the rest in
 *  input order (Array.sort is stable). */
function compareWatchRows(run: SidebarWatchRun): (a: SessionRef, b: SessionRef) => number {
  const at = new Map((run.scenarios ?? []).map((x, i) => [x.sessionId, i]));
  return (a, b) => {
    const ia = at.get(a.id);
    const ib = at.get(b.id);
    if (ia !== undefined && ib !== undefined) return ia - ib;
    if (ia !== undefined || ib !== undefined) return ia !== undefined ? -1 : 1;
    return 0;
  };
}

/** Latest ISO ts among a set of sessions (ISO strings compare lexicographically). */
function maxTs(sessions: SessionRef[]): string | null {
  return sessions.reduce<string | null>(
    (m, s) => (s.lastTs && (m === null || s.lastTs > m) ? s.lastTs : m),
    null,
  );
}

/** Earliest member `firstTs` — when the batch's work started. */
function minFirstTs(sessions: SessionRef[]): string | null {
  return sessions.reduce<string | null>(
    (m, s) => (s.firstTs && (m === null || s.firstTs < m) ? s.firstTs : m),
    null,
  );
}

/** Cap a batch title derived from a session label (headers are one line). */
function truncateTitle(s: string, max = 60): string {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, max - 1) + "…" : t;
}

/**
 * The human-meaningful header for a REAL (batchId) batch, from its members:
 *   - test members → "<suite> e2e run" (tags[1] is the e2e class; mixed or
 *     class-less → "e2e run"). The run label overrides this when the run record
 *     is joined (buildSidebarSections).
 *   - live members → the first member's task label (a batch is one launcher /
 *     ▶ Run invocation — name it by what it did), else "run".
 */
export function batchTitle(sessions: SessionRef[]): string {
  if (sessions.some((s) => s.tags?.includes("test"))) {
    const classes = new Set(sessions.map((s) => s.tags?.[1]).filter(Boolean));
    if (classes.size === 1) {
      const cls = [...classes][0]!; // "claude-e2e" | "replay-e2e"
      return `${cls.replace(/-?e2e$/, "").replace(/-/g, " ") || "e2e"} e2e run`.replace(/^ /, "");
    }
    return "e2e run";
  }
  const labeled = sessions.find((s) => s.label);
  return labeled?.label ? truncateTitle(labeled.label) : "run";
}

/**
 * The calendar day a batch-less session groups under, in the VIEWER's zone `tz`
 * (ts-less → "undated"). Not the ISO/UTC date prefix: the sidebar prints each
 * row's time as the viewer's wall-clock, so a UTC bucket files a KST-morning
 * session under the previous day's header. And not this process's zone either —
 * the server may be a UTC container serving a KST browser — hence `tz`, which
 * the client sends. See transcript.ts localDayKey.
 */
function dayKey(s: SessionRef, tz?: string): string {
  return localDayKey(s.lastTs, tz);
}

/**
 * Group sessions into batches. Sessions sharing a `batchId` form a real batch,
 * titled by `batchTitle`. Batch-less sessions group into per-DAY batches (the
 * day of `lastTs` in the viewer's zone `tz` — see dayKey; id `day:<YYYY-MM-DD>`,
 * title = that day, which the client prettifies). ALL batches — real and day —
 * order by their most-recent
 * session (newest first; ties keep first-seen order — Array.sort is stable), so
 * day groups interleave chronologically instead of one giant catch-all pinned
 * last. Within a batch, input order is preserved.
 */
export function groupSessionsIntoBatches(sessions: SessionRef[], tz?: string): SessionBatch[] {
  const byId = new Map<string, SessionRef[]>();
  const firstSeen: string[] = [];
  const byDay = new Map<string, SessionRef[]>();
  const daysSeen: string[] = [];

  for (const s of sessions) {
    if (!s.batchId) {
      const day = dayKey(s, tz);
      let arr = byDay.get(day);
      if (!arr) {
        arr = [];
        byDay.set(day, arr);
        daysSeen.push(day);
      }
      arr.push(s);
      continue;
    }
    let arr = byId.get(s.batchId);
    if (!arr) {
      arr = [];
      byId.set(s.batchId, arr);
      firstSeen.push(s.batchId);
    }
    arr.push(s);
  }

  const batches: SessionBatch[] = firstSeen.map((id) => {
    const ss = byId.get(id)!;
    return {
      id, ungrouped: false, title: batchTitle(ss), sessions: ss,
      firstTs: minFirstTs(ss), lastTs: maxTs(ss), violated: ss.some((s) => s.violated),
    };
  });
  for (const day of daysSeen) {
    const ss = byDay.get(day)!;
    batches.push({
      id: DAY_BATCH_PREFIX + day, ungrouped: true, title: day, sessions: ss,
      firstTs: minFirstTs(ss), lastTs: maxTs(ss), violated: ss.some((s) => s.violated),
    });
  }

  // Newest batch first; equal/absent timestamps keep insertion order (stable
  // sort; a ts-less "undated" day group sinks to the end).
  batches.sort((a, b) => {
    const at = a.lastTs ?? "";
    const bt = b.lastTs ?? "";
    return at < bt ? 1 : at > bt ? -1 : 0;
  });

  return batches;
}

/**
 * Order Testing-section rows by their stable badge number (E2 before E10 —
 * numeric, not lexicographic; mixed-class batches group by badge prefix:
 * C < E < Re). Numbered rows come first; unnumbered ones (a scenario not yet in
 * TEST_REGISTRY) trail, ordered by id so re-runs stay adjacent. Ties keep the
 * input (newest-first) order — Array.sort is stable.
 */
function compareTestRows(a: SessionRef, b: SessionRef): number {
  const parse = (s: SessionRef): { pre: string; n: number } | null => {
    const m = /^([A-Za-z]+)(\d+)$/.exec(s.testNumber ?? "");
    return m ? { pre: m[1]!, n: Number(m[2]) } : null;
  };
  const ka = parse(a);
  const kb = parse(b);
  if (ka && kb) return ka.pre === kb.pre ? ka.n - kb.n : ka.pre < kb.pre ? -1 : 1;
  if (ka || kb) return ka ? -1 : 1;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/**
 * The row's simplified P/R/F state (SessionRef.status): the effective verdict
 * (`testResult ?? checksVerdict`) when there is one; else RUNNING while the
 * joined test run is still executing (the scenario has no result yet), or —
 * for verdict-less sessions, live ones included — while the last event is
 * within RUNNING_WINDOW_MS of `nowMs`, unless the session's agent exited
 * (`exited`: the launcher recorded `session_exit` and no activity came after
 * it, the rule the product pages use; dashboard.md §4.10.4). Without a
 * recorded exit, recent activity is the "still going" signal. `nowMs`
 * omitted (an older caller / deterministic contexts) skips the recency rule.
 */
function sessionStatus(
  s: SessionRef,
  runState: string | undefined,
  nowMs: number | undefined,
): SessionRef["status"] {
  const v = s.testResult ?? s.checksVerdict;
  if (v === "pass" || v === "fail" || v === "skip") return v;
  // a watch session that IS one scenario reads its scenario's verdict (WARN =
  // the badge's third bucket, like a skipped test); the run's rollup on a
  // shared session is NOT a per-row verdict and marks nothing
  if (s.watch?.scenario) {
    const w = s.watch.verdict;
    if (w === "PASS") return "pass";
    // PAUSED: the model's safeguards stopped the drill — never a pass
    if (w === "FAIL" || w === "TIMEOUT" || w === "PAUSED") return "fail";
    if (w === "WARN") return "skip";
    if (w === "running") return "running";
  }
  if (runState === "running") return "running";
  if (nowMs !== undefined && s.lastTs && !s.exited) {
    const t = Date.parse(s.lastTs);
    if (!Number.isNaN(t) && nowMs - t < RUNNING_WINDOW_MS) return "running";
  }
  return undefined;
}

/** The batch header's simplified P/R/F state (SessionBatch.status): the joined
 *  run's state when there is one, else rolled up from the members' statuses
 *  (running dominates — the batch is still going — then fail, then pass). */
function batchStatus(sessions: SessionRef[], run?: SidebarTestRun): BatchStatus | undefined {
  if (run) {
    if (run.state === "running") return "running";
    if (run.state === "passed") return "pass";
    if (run.state === "failed" || run.state === "error") return "fail";
    return undefined; // canceled etc. — the header's run badge spells those out
  }
  if (sessions.some((s) => s.status === "running")) return "running";
  if (sessions.some((s) => s.status === "fail")) return "fail";
  if (sessions.some((s) => s.status === "pass")) return "pass";
  return undefined;
}

/** The batch's execution runtime (SessionBatch.runtime): the joined run's
 *  runtime when there is one, else the members' UNIFORM SessionRef.runtime —
 *  undefined when no member carries one or they disagree (badging a mixed
 *  day group either way would lie about half its rows). */
function batchRuntime(
  sessions: SessionRef[],
  run?: SidebarTestRun,
): "docker" | "host" | undefined {
  if (run?.runtime) return run.runtime;
  const seen = new Set(sessions.map((s) => s.runtime).filter((r): r is "docker" | "host" => r !== undefined));
  return seen.size === 1 ? [...seen][0] : undefined;
}

/** The batch's ORIGIN (SessionBatch.origin): the members' UNIFORM SessionRef.origin
 *  — undefined when no member carries one or they disagree.
 *
 *  No run-record shortcut, unlike batchRuntime: a CI batch is created by a GitLab
 *  job, which never goes through the dashboard's TestRunner, so there is no run
 *  record to read — the members' stamped events are the only source. (Which is the
 *  whole point: one host can run CI and a dev box, both writing the same arbiter event
 *  dir, so a CI batch is otherwise indistinguishable from a hand-run one.) */
function batchOrigin(sessions: SessionRef[]): "ci" | "local" | undefined {
  const seen = new Set(sessions.map((s) => s.origin).filter((o): o is "ci" | "local" => o !== undefined));
  return seen.size === 1 ? [...seen][0] : undefined;
}

/** Tally the members' effective outcomes (`testResult ?? checksVerdict` — the
 *  row-mark fallback chain) into SessionBatch.marks; undefined when no member
 *  carries a verdict (so the header shows nothing rather than "0 pass"). */
function tallyMarks(sessions: SessionRef[]): BatchMarks | undefined {
  const marks: BatchMarks = { pass: 0, fail: 0, skip: 0 };
  for (const s of sessions) {
    const v = s.testResult ?? s.checksVerdict;
    if (v === "pass" || v === "fail" || v === "skip") marks[v]++;
  }
  return marks.pass + marks.fail + marks.skip > 0 ? marks : undefined;
}

/**
 * Split the flat session list into the sidebar's four sections (shown as
 * Sessions, Live drills, Replay drills and Tests; test-reorganization.md §7.1)
 * and join test runs onto testing batches:
 *   - a session is a REPLAY drill iff the recorded source made it (`replay`
 *     set from a validated record) — decided before anything else
 *     (buildReplayBatches);
 *   - a session is a DRILL iff a 🎬 watch run drove it (the run names it, or
 *     its batch id is the run id) — decided first, whatever its tenant;
 *   - a session is TESTING iff its tags include "test" (event-source sessionTags);
 *   - each side is batched independently, so each gets its own Ungrouped
 *     catch-all (a loose test session never lands between live batches);
 *   - a testing batch whose id matches a run's runId (the test-runner stamps
 *     MANDU_BATCH_ID=runId) gains that run's summary, and each member session
 *     gains its per-scenario `testResult` (matched by the `<class>[<scenario>]`
 *     key parsed from the run's TAP titles vs the session id) — copies, never
 *     mutations of the input refs;
 *   - every testing batch's rows are re-ordered by badge number
 *     (compareTestRows) and tallied into `marks` (tallyMarks) — the Live side
 *     keeps its newest-first order and carries no marks;
 *   - every session (both sides) gains the simplified P/R/F `status`
 *     (sessionStatus) and every batch its rollup (batchStatus). `nowMs` — the
 *     caller's Date.now(), injected so this module stays pure — feeds the
 *     recent-activity RUNNING rule; omitted, that rule is off.
 */
export function buildSidebarSections(
  sessions: SessionRef[],
  runs: SidebarTestRun[] = [],
  nowMs?: number,
  tz?: string,
  watchRuns: SidebarWatchRun[] = [],
  opts: SidebarOptions = {},
): SidebarSections {
  // The tenant stamp decides when present (policy-surface.md §2.7);
  // the id-derived "test" tag is the fallback for unstamped sessions. The
  // sources already reconcile the two (registry.ts tenantedTags: a live stamp
  // strips the tag), so a live-stamped row carrying "test" is the one case
  // tenantedTags keeps on purpose: a harness FRAGMENT.
  const isTest = (s: SessionRef): boolean =>
    s.tenant === "test" || (s.tags?.includes("test") ?? false);
  const watchById = new Map(watchRuns.map((r) => [r.runId, r]));
  // session id → the watch run that drove it (also for runs that predate the
  // batch stamp, whose sessions sit in a day group)
  const watchBySession = new Map<string, SidebarWatchRun>();
  for (const r of watchRuns) for (const id of r.sessions ?? []) watchBySession.set(id, r);
  // A DRILL is a session a watch run drove: named by the run (meta.sessions /
  // chapters) or stamped with the run's batch id. Decided BEFORE live/test: a
  // drill run under MANDU_TENANT=test is still a drill.
  // …or, for a run that died before it recorded its sessions, named after it:
  // the runner's scope ids are always `<runId>-<scenario|setting>`.
  // …or minted by the watch runner at all (2026-09-28): its run ids are
  // always `watch-<stamp>`, and a run whose record is gone (runs from before
  // the per-run record, a deleted watch dir) left its sessions in Live.
  const isDrill = (s: SessionRef): boolean =>
    watchBySession.has(s.id) || (s.batchId !== undefined && s.batchId !== null && watchById.has(s.batchId)) ||
    watchRuns.some((r) => s.id.startsWith(r.runId + "-")) ||
    s.id.startsWith(WATCH_ID_PREFIX) || (s.batchId?.startsWith(WATCH_ID_PREFIX) ?? false);
  // A REPLAY drill is a recorded session (recorded-source.ts): only that
  // source sets `replay`, from a validated record, so nothing else can claim
  // the section. Decided before everything else.
  const isReplay = (s: SessionRef): boolean => s.replay !== undefined;
  const replay = buildReplayBatches(sessions.filter(isReplay), tz, opts.drills);
  sessions = sessions.filter((s) => !isReplay(s));
  const withLiveStatus = (s: SessionRef): SessionRef => ({ ...s, status: sessionStatus(s, undefined, nowMs) });
  const liveRefs = sessions.filter((s) => !isDrill(s) && !isTest(s));
  const live = groupSessionsIntoBatches(liveRefs.filter((s) => !systemLogKind(s.id)), tz)
    .map((batch) => ({ ...batch, sessions: batch.sessions.map(withLiveStatus) }))
    .map((batch) => ({ ...batch, status: batchStatus(batch.sessions) }));
  const systemLogs = liveRefs.filter((s) => systemLogKind(s.id)).map(withLiveStatus);
  if (systemLogs.length) {
    live.push({
      id: SYSTEM_LOGS_BATCH_ID, ungrouped: false, title: "System logs", sessions: systemLogs,
      firstTs: minFirstTs(systemLogs), lastTs: maxTs(systemLogs), violated: systemLogs.some((s) => s.violated),
      status: batchStatus(systemLogs),
    });
  }
  // A drill session with no batch stamp still joins the run that drove it: the
  // stamp rides the model-proxy's events, so a scenario that ended before its
  // first model call (a TIMEOUT at launch) carries none and would otherwise
  // fall into a day group, away from its run's siblings.
  // The id-prefix fallback takes the LONGEST matching run id: run
  // `…-p10-drills` must not claim `…-p10-drills-all2-s4-haiku`.
  const runOf = (s: SessionRef): SidebarWatchRun | undefined =>
    watchBySession.get(s.id) ??
    watchRuns.filter((r) => s.id.startsWith(r.runId + "-")).sort((a, b) => b.runId.length - a.runId.length)[0];
  const drillRefs = sessions.filter(isDrill).map((s) => {
    if (s.batchId) return s;
    const run = runOf(s);
    return run ? { ...s, batchId: run.runId } : s;
  });
  const drills = groupSessionsIntoBatches(drillRefs, tz).map((batch) => {
    // A drill batch that IS a watch run (batch id === runId) carries the run's
    // label + verdict tally, exactly as a testing batch carries its test run.
    const watch = batch.ungrouped ? undefined : watchById.get(batch.id);
    const members = watch ? [...batch.sessions].sort(compareWatchRows(watch)) : batch.sessions;
    const annotated = members.map((s) => {
      const own = watchBySession.get(s.id);
      let withWatch: SessionRef = s;
      if (own) withWatch = { ...s, watch: watchAnnotation(own, s.id) };
      else if (watch?.recordPending) {
        // RUNNING, RECORD NOT IN THE STORE YET: the run is in progress and its
        // record (outside the store) lists no session yet; every member is its
        withWatch = { ...s, watch: { runId: watch.runId, recorded: false, recordPending: true, ...(watch.recordAt ? { recordAt: watch.recordAt } : {}), verdict: "running" } };
      } else if (opts.watchStoreRead && !watch && !runOf(s) && !(s.batchId && watchById.has(s.batchId))) {
        // RECORD LOST: the store was read and holds no run for this session
        // (a deleted run, or one written to a temp home / another --out):
        // say so, naming the run it claims, so no row offers a recording
        const runId = claimedWatchRunId(s);
        if (runId) withWatch = { ...s, watch: { runId, recorded: false, recordLost: true, runMissing: true } };
      }
      const short = opts.drills ? liveDrillShort(opts.drills, withWatch) : undefined;
      return { ...withWatch, ...(short ? { drillShort: short } : {}), status: sessionStatus(withWatch, watch?.state, nowMs) };
    });
    // the whole batch's recording is gone: its run says so, or (no run in the
    // store) every member is record-lost
    const lostBatch = watch
      ? watch.recordLost === true
      : !batch.ungrouped && annotated.length > 0 && annotated.every((s) => s.watch?.recordLost === true);
    const lostMark = lostBatch ? { recordLost: true as const } : watch?.recordPending ? { recordPending: true as const } : {};
    // re-key the drill side's day groups so they never collide with Live's
    if (!watch) return { ...batch, ...(batch.ungrouped ? { id: DAY_DRILLS_BATCH_PREFIX + batch.id.slice(DAY_BATCH_PREFIX.length) } : {}), sessions: annotated, status: batchStatus(annotated), ...lostMark };
    const run: BatchRunSummary = { runId: watch.runId, suite: "watch", label: watch.label, state: watch.state, since: watch.since, finishedAt: watch.finishedAt, counts: watch.counts };
    return { ...batch, title: watch.label, sessions: annotated, status: batchStatus(annotated), run, ...lostMark };
  });
  const runById = new Map(runs.map((r) => [r.runId, r]));

  const testing = groupSessionsIntoBatches(sessions.filter((s) => !isDrill(s) && isTest(s)), tz).map((batch) => {
    // Badge-number order within every testing batch (a fresh array — the
    // grouper's arrays are per-batch copies, but sort defensively anyway).
    const ordered = [...batch.sessions].sort(compareTestRows);
    const run = batch.ungrouped ? undefined : runById.get(batch.id);
    const annotated = ordered.map((s) => {
      const key = run ? parseTestSessionId(s.id) : null;
      const result = key
        ? run!.results?.find((r) => r.cls === key.cls && r.scenario === key.scenario)
        : undefined;
      const joined = result ? { ...s, testResult: result.status } : { ...s };
      return { ...joined, status: sessionStatus(joined, run?.state, nowMs) };
    });
    // Re-key the testing side's day groups so they never collide with Live's.
    const runtime = batchRuntime(annotated, run);
    const origin = batchOrigin(annotated);
    if (batch.ungrouped) {
      return {
        ...batch,
        id: DAY_TESTING_BATCH_PREFIX + batch.id.slice(DAY_BATCH_PREFIX.length),
        sessions: annotated,
        status: batchStatus(annotated),
        marks: tallyMarks(annotated),
        ...(runtime ? { runtime } : {}),
        ...(origin ? { origin } : {}),
      };
    }
    if (!run) {
      return {
        ...batch,
        sessions: annotated,
        status: batchStatus(annotated),
        marks: tallyMarks(annotated),
        ...(runtime ? { runtime } : {}),
        ...(origin ? { origin } : {}),
      };
    }
    return {
      ...batch,
      // The run's label is the most specific name for the batch (the batch IS
      // that run) — it overrides the member-derived title.
      title: run.label || batch.title,
      sessions: annotated,
      status: batchStatus(annotated, run),
      marks: tallyMarks(annotated),
      ...(runtime ? { runtime } : {}),
      ...(origin ? { origin } : {}),
      run: {
        runId: run.runId,
        suite: run.suite,
        label: run.label,
        state: run.state,
        since: run.since,
        finishedAt: run.finishedAt ?? null,
        counts: run.counts ?? { pass: 0, fail: 0, skip: 0 },
        ...(run.runtime ? { runtime: run.runtime } : {}),
      },
    };
  });

  return { live, drills, replay, testing };
}

/** PASS → pass, WARN → the third bucket (like a skipped test, as a live
 *  drill's WARN is), FAIL / TIMEOUT → fail. */
function replayStatus(v: NonNullable<SessionRef["replay"]>["verdict"]): SessionRef["status"] {
  return v === "PASS" ? "pass" : v === "WARN" ? "skip" : "fail";
}

/** Rows of a replay batch: by drill, then agent, then lane, then size. */
function compareReplayRows(a: SessionRef, b: SessionRef): number {
  const ka = [a.replay!.drill, a.replay!.agent, a.replay!.lane ?? "", a.replay!.size].join("\u0000");
  const kb = [b.replay!.drill, b.replay!.agent, b.replay!.lane ?? "", b.replay!.size].join("\u0000");
  return ka < kb ? -1 : ka > kb ? 1 : 0;
}

/**
 * The REPLAY DRILLS section (dashboard.md §4.28): one batch per replay run
 * (the recorded source stamps `batchId` = runId), titled by the run's ref (or
 * source) and short commit, with the run's verdict counts as its run tally
 * (PASS = pass, WARN = the third bucket, FAIL / TIMEOUT = fail) and each row's
 * P/F badge from its own verdict. With the catalog's short indexes
 * (`drills`), each row carries its drill's (`replay.short`).
 */
export function buildReplayBatches(sessions: SessionRef[], tz?: string, drills?: DrillShortIndex): SessionBatch[] {
  const withShort = (s: SessionRef): SessionRef => {
    const short = drills?.byId.get(s.replay!.drill)?.short;
    return short ? { ...s, replay: { ...s.replay!, short } } : s;
  };
  return groupSessionsIntoBatches(sessions, tz).map((batch) => {
    const rows = [...batch.sessions].sort(compareReplayRows).map((s) => ({ ...withShort(s), status: replayStatus(s.replay!.verdict) }));
    const counts = { pass: 0, fail: 0, skip: 0 };
    for (const s of rows) counts[s.status === "pass" ? "pass" : s.status === "skip" ? "skip" : "fail"]++;
    const first = rows[0]?.replay?.run;
    const since = first ? Date.parse(first.startedAt) : NaN;
    const end = batch.lastTs ? Date.parse(batch.lastTs) : NaN;
    const title = first
      ? `replay · ${first.ref || first.source} · ${first.commit.slice(0, 8)}`
      : batch.title;
    const run: BatchRunSummary | undefined = first && Number.isFinite(since)
      ? {
          runId: batch.id, suite: "replay", label: title, state: counts.fail > 0 ? "failed" : "passed",
          since, finishedAt: Number.isFinite(end) ? end : null, counts,
        }
      : undefined;
    return {
      ...batch,
      title,
      sessions: rows,
      status: counts.fail > 0 ? "fail" : rows.length ? "pass" : undefined,
      ...(run ? { run } : {}),
      ...(first ? { replayRun: { commit: first.commit, ...(first.ref !== undefined ? { ref: first.ref } : {}), source: first.source, startedAt: first.startedAt } } : {}),
    };
  });
}
