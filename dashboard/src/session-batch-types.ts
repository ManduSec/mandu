/**
 * session-batch-types — the shapes session-batches.ts reads and returns: the
 * sidebar's SessionBatch (with its BatchMarks / BatchStatus rollups and the
 * joined BatchRunSummary), the narrow structural views of the test-runner and
 * watch-runner runs it joins (SidebarTestRun / SidebarWatchRun), and the
 * three-section result (SidebarSections).
 *
 * Types only. Moved out of session-batches.ts, which keeps the rules and
 * re-exports every name here. See docs/design/ui/dashboard.md §4.10.1.
 */
import type { SessionRef } from "./event-source.js";

export interface SessionBatch {
  /** The shared `batchId`, or `day:<YYYY-MM-DD>` for a per-day group. */
  id: string;
  /** True for a synthetic per-day group of batch-less sessions. */
  ungrouped: boolean;
  /** Human-meaningful header: the run label / "<suite> e2e run" / the first
   *  member's task label / the ISO day (client prettifies day titles). */
  title: string;
  /** Member sessions in input order (the server already sorts newest-first). */
  sessions: SessionRef[];
  /** The earliest member `firstTs` — when the batch's work STARTED. With
   *  `lastTs` this gives the header its elapsed duration. */
  firstTs: string | null;
  /** The most-recent member `lastTs` (orders batches + drives the header age). */
  lastTs: string | null;
  /** True if ANY member violated the invariant, so a FOLDED batch still flags it. */
  violated: boolean;
  /** The test run that produced this batch (Testing section only; joined by
   *  batch id === runId). Absent for live batches and for test batches whose
   *  run the dashboard didn't launch (e.g. a standalone `npm test`). */
  run?: BatchRunSummary;
  /** Simplified batch state for the header's P/R/F badge (buildSidebarSections):
   *  from the joined run's state when there is one (running → "running",
   *  passed → "pass", failed/error → "fail"), else rolled up from the members
   *  (any running member → "running", else any fail → "fail", else any pass →
   *  "pass"). Omitted when nothing is known (e.g. an ended live batch). */
  status?: BatchStatus;
  /** Per-member outcome tallies (Testing section only): each session counts by
   *  `testResult ?? checksVerdict` (the same fallback chain as the row's ✓/✗
   *  mark); sessions with neither are uncounted. Omitted when no member has a
   *  verdict. Lets the batch header show "✓ x pass / ✗ y fail" even for a
   *  launcher / standalone `npm test` batch that has no run record. */
  marks?: BatchMarks;
  /** Execution runtime the batch ran under (Testing section only): the joined
   *  run's runtime when there is one (known at run start), else the members'
   *  uniform SessionRef.runtime — so a standalone `npm test` batch still badges
   *  host-vs-docker once its sessions emit their runtime tag. Omitted when
   *  unknown or when members disagree (a day group mixing both). */
  runtime?: "docker" | "host";
  /** WHO ran the batch (Testing section only): the members' uniform SessionRef.origin
   *  — `"ci"` = a GitLab pipeline job, `"local"` = a human on the dev box. Drives the
   *  group row's CI badge. Omitted when unknown or when members disagree. */
  origin?: "ci" | "local";
  /** The replay run a REPLAY DRILLS batch is (dashboard.md §4.28): its commit,
   *  ref, source and start, from the members' validated records. Replay
   *  batches only. */
  replayRun?: { commit: string; ref?: string; source: "ci" | "local"; startedAt: string };
  /** RECORD LOST (Live drills only, 2026-10-02, dashboard.md §4.22): the watch
   *  run this batch is has no recording on disk any more — its run is not in
   *  the store at all, or its record names recordings none of which is there.
   *  The header says "record lost". Present only when true. */
  recordLost?: true;
  /** RECORD NOT IN THE STORE YET (Live drills only, 2026-10-03): the watch run
   *  this batch is, is still in progress and writes its record outside the
   *  store, where it cannot be read yet (SidebarWatchRun.recordPending). The
   *  header says so; never "record lost". Present only when true. */
  recordPending?: true;
}

/** The batch header's member-derived pass/fail tallies (see SessionBatch.marks). */
export interface BatchMarks {
  pass: number;
  fail: number;
  skip: number;
}

/** Simplified batch state for the header's P/R/F badge (see SessionBatch.status). */
export type BatchStatus = "pass" | "running" | "fail";

/** The slice of a test-runner run the sidebar needs (state + tallies; the full
 *  per-case list stays in the 🧪 Tests drawer via GET /api/test). */
export interface BatchRunSummary {
  runId: string;
  suite: string;
  label: string;
  /** running | passed | failed | error | canceled (test-runner TestState). */
  state: string;
  since: number;
  finishedAt: number | null;
  counts: { pass: number; fail: number; skip: number };
  /** Execution runtime this run used: "docker" (containerized rig) or "host".
   *  Sourced from the run record, so the batch header can badge docker-vs-host
   *  IMMEDIATELY at run start (before any session emits its runtime-tagged event). */
  runtime?: "docker" | "host";
}

/** A recorded WATCH run (drill-runs.ts) joined onto the DRILLS batch whose id is
 *  its runId — the runner stamps MANDU_BATCH_ID=runId on the `mandu claude`
 *  it drives, so the run's real session(s) group as one drill batch. Shape is
 *  the BatchRunSummary subset the sidebar badge reads. */
export interface SidebarWatchRun {
  runId: string;
  label: string;
  /** running | passed | failed | canceled (mapped from the run's status + verdicts) */
  state: string;
  since: number;
  finishedAt: number | null;
  counts: { pass: number; fail: number; skip: number };
  /** the Mandu session ids this run drove (meta.sessions values) */
  sessions?: string[];
  /** a terminal recording exists for the run */
  recorded?: boolean;
  /** the run is over and every recording its record names is gone from disk
   *  (drill-run-store.ts WatchRunSummary.recordLost) */
  recordLost?: true;
  /** the run is in progress and writes its record outside the store, where
   *  it cannot be read yet (drill-run-store.ts WatchRunSummary.recordPending):
   *  "running, record not in the store yet", never "record lost" */
  recordPending?: true;
  /** the run's own directory outside the store its record is read from (or,
   *  pending, will be), while it runs (WatchRunSummary.recordAt) */
  recordAt?: string;
  /** the scenario each session ran (one `mandu claude` per scenario since
   *  2026-09-19), in run order: the sidebar names the row by its scenario,
   *  marks it P/F/− by the scenario's own verdict and keeps the run's order.
   *  Absent/empty for a shared-session or older run (one row per setting). */
  scenarios?: Array<{ sessionId: string; id: string; title: string; setting: string; verdict?: "PASS" | "WARN" | "FAIL" | "TIMEOUT" | "PAUSED"; recorded?: boolean; recordLost?: true }>;
}

/** Structural view of a test-runner TestRunHandle (kept narrow so this module
 *  needs no import from test-runner.ts and stays trivially unit-testable). */
export interface SidebarTestRun {
  runId: string;
  suite: string;
  label: string;
  state: string;
  since: number;
  finishedAt?: number | null;
  counts?: { pass: number; fail: number; skip: number };
  runtime?: "docker" | "host";
  results?: Array<{
    name: string;
    cls: string | null;
    scenario: string | null;
    status: "pass" | "fail" | "skip";
  }>;
}

/** The four sidebar sections (dashboard.md §4.10, test-reorganization.md
 *  §7.1). The keys predate the labels: `live` is shown as **Sessions**,
 *  `drills` as **Live drills**, `replay` as **Replay drills** and `testing`
 *  as **Tests**. */
export interface SidebarSections {
  /** Sessions: real agent sessions (launcher / ▶ Run / anything not TEST-tagged). */
  live: SessionBatch[];
  /** Live drills: sessions a 🎬 watch run drove (dashboard.md §4.22) — a REAL
   *  agent in a real TUI, but the prompts are scripted, graded and recorded, so
   *  they are neither someone's work (Sessions) nor the headless e2e harness (Tests). */
  drills: SessionBatch[];
  /** Replay drills: the replay runner's RECORDED sessions (dashboard.md §4.28),
   *  one batch per run, a row per drill × agent × size. */
  replay: SessionBatch[];
  /** Tests: e2e TEST sessions, batches joined with their test-runner run records. */
  testing: SessionBatch[];
}
