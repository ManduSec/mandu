#!/usr/bin/env node
// scripts/run-suites.mjs — run entries of the suite manifest (tests/suites.mjs) and
// write the results (docs/design/testing/test-organization.md §5, docs/design/
// continuous-integration.md §5–§6). Node builtins only (and, on Linux, the host's
// `cc` for the entries' subreaper, lib/subreaper.c, when it is there).
//
//   node scripts/run-suites.mjs --kind <k,k> [--frozen] [--only <id,id>] [--jobs N]
//       [--kernel-jobs N] [--sandbox <path-to-wrapper>] [--costs FILE]
//       [--out DIR | --keep-results N|all [--keep-results-hours H]] [--run-id ID]
//       [--source local|gitlab] [--commit SHA] [--ref REF] [--image NAME]
//       [--stages-json FILE] [--strict-skips] [--include-flaky]
//       [--flaky-kinds <k,k>] [--include-internet] [--lane subscription|api-key] [--need <n>]
//       [--agents <a,a>] [--drills <id,id>] [--replay-store DIR] [--replay-baselines DIR]
//       [--replay-baselines-seed DIR] [--replay-baseline-mode record|use|off] [--replay-blocking]
//       [--watch-store DIR] [--tmp-leftovers fail|warn] [--failures-only] [--fail-tail N]
//       [--fail-fast] [--deadline EPOCH_S] [--heartbeat S] [--dry-run]
//
// --kind picks the entries of those kinds (test-reorganization.md §3); a frozen
// entry never runs with its kind, --frozen adds every frozen entry (the
// integrity lane, protection-modes.md §10).
// --flaky-kinds adds the flaky entries (only those) of more kinds to the
// --kind selection: the nightly's "every flaky entry" (continuous-integration.md §9).
// --lane subscription|api-key keeps only the selected entries of that nightly
// lane (the entry's `credential`, continuous-integration.md §9.8; an entry that
// needs no login holds none and is in the subscription lane).
// --need n keeps only the selected entries whose needs include n (the kernel
// guest's job: --kind sandbox,replay-drill --need kernel).
// --agents a,b (claude, codex, openclaw, opencode, goose) keeps only the entries
// whose agents (their `agent` and `ullm`, else their agent CLI or login needs)
// are all in the list.
// An entry that names its `agent` (every live-drill) shows the agent and the
// version its CLI reports (`--version`, asked once per run) beside its result,
// and summary.json carries them (agent, agentVersion, ullm).
// --drills id,id narrows the drill entries to those watch-catalog scenarios
// (an unknown id is a usage error); alone it selects the live-drill kind.
// --replay-store DIR gives every replay-drill entry a place for its replay
// record (test-reorganization.md §7.3): MANDU_REPLAY_STORE, MANDU_REPLAY_RUN_ID
// (this run's id) and MANDU_REPLAY_BASELINES (--replay-baselines DIR; without
// it, unsandboxed, the CALLER's `drill-baselines` from the path table
// (runs/drills/baselines), as for the watch store below). With --sandbox each entry gets its own
// <DIR>/<id> (and <baselines>/<id>), bound read-write into its box by ns-run's
// --bind-rw: the box's only writable host path, never shared with another
// entry; without --sandbox they share DIR. Without --replay-store the three
// are unset for every entry, whatever the caller's environment holds: no
// record (continuous-integration.md §6). --replay-baselines-seed DIR (with
// --replay-store) is a READ-ONLY store of promoted baselines the entries'
// `use` falls back to (MANDU_REPLAY_BASELINES_SEED; a per-push CI run's,
// master's promoted ones: test-reorganization.md §6.9, step 5 decision 8),
// and --replay-baseline-mode record|use|off sets MANDU_REPLAY_BASELINE for
// them (without it the caller's stands). --replay-blocking (with
// --replay-store) sets MANDU_REPLAY_BLOCKING=1 for them: a FAIL or TIMEOUT
// replay verdict fails the entry's test. The per-push CI run passes it
// (test-reorganization.md §6.9); without it the caller's stands.
// --watch-store DIR is where every drill entry (drill.*, drill-run.ts) puts its
// run record: it gets `--store DIR` (withWatchStore). Without it, the CALLER's
// `live-drill-runs` from the path table (runs/drills/live), resolved from this process's
// environment, which is the right one only when MANDU_HOME is still the
// caller's: test-all.sh pins MANDU_HOME before it calls this runner, so it
// resolves the caller's store first and passes it here (a store under the
// pinned /dev/null home is said on stderr: the records would go nowhere).
// --failures-only prints only what a reader must act on (test-organization.md
// §5): no row for an entry that passed or skipped; each failed entry's header,
// verdict and the last --fail-tail N lines of its log (default 40 under
// --failures-only, 25 otherwise; 0 prints only the log's path); then the summary's failed
// rows and one counts line (the verdict, failed / passed / skipped) and the
// results directory. What the run writes (summary.json, junit.xml, logs/) and
// its exit code are the same either way.
//
// Order: the entries outside the kernel lane that are safe side by side run
// concurrently (up to --jobs, default 1), then the non-parallel ones one at a
// time, then the kernel lane (the entries that need `kernel`): those marked
// `parallel: true` up to --kernel-jobs at a time (default 1), then the others
// one at a time. With --sandbox every entry outside the kernel lane runs as
//   <wrapper> --chdir <abs cwd> [--setenv K V]... -- <cmd...>
// (scripts/ci/ns-run.sh's interface); kernel entries never go through it, and
// the kernel entries share the parallel stage's slots instead of running after
// it: the sandbox gives each non-kernel entry its own network, PID and IPC
// namespaces, $HOME, /tmp and tree, so a kernel entry cannot meet one on a
// port or a path (continuous-integration.md §5.2). Then one queue, longest first by
// the cost tables (tests/suite-costs.json + private/suite-costs.json, under --costs FILE's
// seconds where it names the entry), fills --jobs plus
// --kernel-jobs slots; at most --kernel-jobs of them run kernel entries, and a
// kernel entry that is not `parallel: true` starts only when no other kernel
// entry is running or waiting (§5.4). Without --sandbox the order stays
// sequential (each pool longest first). The shared queue weights a kernel
// entry's cost by its slots ÷ kernel jobs (suites.mjs sharedQueueOrder, §5.7).
// Every entry gets a fresh, empty TMPDIR of its own, <run tmp>/<n> under one
// per-run directory (`mdu-run-*` in the runner's own tmpdir; sandboxed, it is
// bound read-write into the box and set over ns-run's TMPDIR=/tmp). When the
// entry is done and its process group is gone, whatever it left there (but
// the tools' caches, `tsx-<uid>` and `node-compile-cache`) FAILS the entry
// with the leftover names, as does a process it left running outside its
// process group (a `setsid` daemon still naming its TMPDIR, or any orphan of
// its tree its subreaper adopted; killed)
// (--tmp-leftovers warn, or MANDU_TEST_TMP_LEFTOVERS=warn, only reports them);
// the directory is then removed, and the per-run directory at the end of the
// run. New files of an unsandboxed entry in /tmp, $HOME or the caller's
// runtime dir are a warning (test-organization.md §8.5).
//
// --deadline EPOCH_S (seconds since the epoch) is when the run must be over
// (the CI guest's, continuous-integration.md §3): no entry starts after it,
// and an entry still running then is stopped as at its own timeout (the
// timeout report in its log, then SIGTERM, then SIGKILL) with the result
// `timeout` and a reason that names the deadline; the run is an `error`
// ("deadline: …") with the entries it never started listed as not run, and
// summary.json and the logs are still written. --heartbeat S prints, every S
// seconds while entries run, one line naming each with its age and timeout
// (an entry's ▶ line comes only when it is done, so without it a hung
// entry is silent).
// Writes <out>/summary.json (schema 1, kind "mandu-ci-run"), <out>/junit.xml and
// <out>/logs/<id>.log (capped at 5 MiB, the tail kept); when an entry named its
// agent, the agent matrix too: printed after the summary and written to
// <out>/summary.md (a suite per row, an agent per column). Without --out, <out>
// is a fresh `mandu-suites-XXXXXX` in the runner's tmpdir (TMPDIR), named on
// the summary's last line; at the start of such a run the older ones of this
// user are pruned to the newest --keep-results N (MANDU_TEST_KEEP_RESULTS;
// default 5, `all` keeps them), never one that changed within
// --keep-results-hours H (MANDU_TEST_KEEP_RESULTS_HOURS, default 6) nor one
// whose run is still live (pruneResultsDirs). With --out nothing is pruned. Exit 0 when every
// selected entry passed (or skipped, where a skip is allowed), 1 otherwise,
// 2 on a usage error.

import { spawn, spawnSync, execFileSync } from "node:child_process";
import {
  chmodSync, closeSync, existsSync, lstatSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, readSync,
  readlinkSync, realpathSync, rmSync, statSync, writeFileSync,
} from "node:fs";
import { homedir, tmpdir, userInfo } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

import { resolvePath } from "./paths/mandu-paths.mjs";
import { parseProcStat, readProcTable, timeoutReason as sharedTimeoutReason, timeoutReport as sharedTimeoutReport } from "./lib/timeout-report.mjs";
import { CACHED_LINES } from "./agents/agent-registry.mjs";
import { REPO_ROOT, KINDS, CREDENTIALS, AGENTS, LIVE_AGENTS, isDrill, recordsLive, loadAllCosts, loadCosts, loadManifest, namedAgents, needsKernel, nonBlocking, orderByCost, planPhases, selectEntries, sharedQueueOrder } from "./suites.mjs";

/** Set for every entry, as test-all.sh always did (protection-modes.md §4; no
 *  host policy.yaml). MANDU_HOME is a home that cannot exist: no suite inherits
 *  the caller's real one (a CI runner's unit sets MANDU_HOME for its own
 *  results), and a test that forgets to isolate fails loudly instead of
 *  touching real data (on-disk-layout.md §9). Its reads of optional files
 *  there see ENOTDIR, i.e. absent. */
export const FIXED_ENV = Object.freeze({
  MANDU_AXES_STRICT: "1",
  MANDU_HOME: "/dev/null/mandu-test-home",
  MANDU_POLICY_FILE: "/dev/null/mandu-test-no-policy.yaml",
});
export const LOG_CAP = 5 * 1024 * 1024;
const PARSE_WINDOW = 64 * 1024 * 1024;
const KILL_GRACE_MS = 10_000;

// ── counts ─────────────────────────────────────────────────────────────────────

const stripAnsi = (s) => s.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "");

/**
 * Parse a suite's pass / fail / skip counts from its output. Formats, in order:
 * node:test footers (TAP `# pass N` or spec `ℹ pass N`, summed over every run in
 * the log), cargo `test result:` lines (summed; `SKIP:` lines a kernel test
 * prints are passes that are really skips; ignored tests are skips), then a
 * shell footer (`N passed, M failed`, `(skipped)`, `N skipped, M failed`, and
 * kernel-tests.sh's `N suite(s) SKIPPED`), the last one in the log.
 */
export function parseCounts(raw) {
  const lines = stripAnsi(raw).split(/\r?\n/);
  const node = { tests: 0, pass: 0, fail: 0, cancelled: 0, skipped: 0, todo: 0, seen: false };
  for (const l of lines) {
    const m = /^(?:#|ℹ) (tests|pass|fail|cancelled|skipped|todo) (\d+)\s*$/.exec(l);
    if (m) { node[m[1]] += Number(m[2]); node.seen = true; }
  }
  if (node.seen) {
    const skip = node.skipped + node.todo;
    return finish("node", node.pass, node.fail + node.cancelled, skip);
  }
  let cargo = null;
  let selfSkips = 0;
  let suitesSkipped = 0;
  for (const l of lines) {
    const m = /^test result: \S+ (\d+) passed; (\d+) failed; (\d+) ignored;/.exec(l);
    if (m) {
      cargo ??= { passed: 0, failed: 0, ignored: 0 };
      cargo.passed += Number(m[1]); cargo.failed += Number(m[2]); cargo.ignored += Number(m[3]);
    }
    if (/^SKIP:/.test(l)) selfSkips++;
    const s = /(\d+) suite\(s\) SKIPPED/.exec(l);
    if (s) suitesSkipped += Number(s[1]);
  }
  if (cargo) {
    const skips = Math.min(selfSkips, cargo.passed);
    return finish("cargo", cargo.passed - skips, cargo.failed, cargo.ignored + skips + suitesSkipped);
  }
  for (let i = lines.length - 1; i >= 0; i--) {
    const l = lines[i];
    const sk = /(?:^|\s)(\d+) skipped, (\d+) failed\s*$/.exec(l);
    if (sk) return finish("shell", 0, Number(sk[2]), Number(sk[1]) + suitesSkipped);
    const m = /(\d+) passed, (\d+) failed(\s*\(skipped\))?/.exec(l);
    if (m) {
      const skipped = m[3] ? 1 : 0;
      return finish("shell", Number(m[1]), Number(m[2]), skipped + suitesSkipped);
    }
  }
  return { format: null, pass: 0, fail: 0, skip: 0, summary: "(no test counts in the output; see log)" };
}

function finish(format, pass, fail, skip) {
  return { format, pass, fail, skip, summary: `${pass} passed; ${fail} failed; ${skip} skipped` };
}

/**
 * An entry's result: error (could not start), timeout, fail (non-zero exit, a
 * failed count, or --strict-skips counts outside the entry's `ci`), skip (ran
 * nothing but skips) or pass. Returns { result, reason }.
 */
export function classify(entry, { code, timedOut = false, hung = [], spawnError = null, counts, strictSkips = false, deadlineAfterS = null }) {
  if (spawnError) return { result: "error", reason: `could not start: ${spawnError}` };
  if (timedOut) return { result: "timeout", reason: timeoutReason(entry, hung, { deadlineAfterS }) };
  if (code !== 0) return { result: "fail", reason: `exit ${code}` };
  if (counts.fail > 0) return { result: "fail", reason: `${counts.fail} failed` };
  if (strictSkips && entry.ci) {
    const { maxSkip = null, minPass = null } = entry.ci;
    if (maxSkip != null && counts.skip > maxSkip) return { result: "fail", reason: `--strict-skips: ${counts.skip} skipped, ci.maxSkip is ${maxSkip}` };
    if (minPass != null && counts.pass < minPass) return { result: "fail", reason: `--strict-skips: ${counts.pass} passed, ci.minPass is ${minPass}` };
  }
  if (counts.pass === 0 && counts.skip > 0) return { result: "skip", reason: null };
  return { result: "pass", reason: null };
}

// ── running one entry ──────────────────────────────────────────────────────────

/** The replay record's variables (test-reorganization.md §7.3): set only by
 *  run-suites. MANDU_REPLAY_BASELINE (the mode) and MANDU_REPLAY_BLOCKING are
 *  not: a caller's stands unless --replay-baseline-mode / --replay-blocking
 *  sets it. */
export const REPLAY_VARS = Object.freeze(["MANDU_REPLAY_STORE", "MANDU_REPLAY_RUN_ID", "MANDU_REPLAY_BASELINES", "MANDU_REPLAY_BASELINES_SEED"]);
/** The baseline modes --replay-baseline-mode takes (baseline-cache.ts). */
export const BASELINE_MODES = Object.freeze(["record", "use", "off"]);

/** The host store (test-reorganization.md §7.3): the path table's
 *  `replay-drill-runs` and `drill-baselines` rows. */
export function replayHostPaths(env, home) {
  return { store: resolvePath("replay-drill-runs", env, home), baselines: resolvePath("drill-baselines", env, home) };
}

/**
 * Where a replay-drill entry writes its record, or null (not a replay-drill
 * entry, or no --replay-store). `replay` is { store, baselines, runId,
 * perEntry, seed?, baselineMode?, blocking? }: perEntry (a --sandbox run)
 * gives the entry its own <store>/<id> and <baselines>/<id>; `seed` (shared,
 * read-only, never bound writable) and `baselineMode` are passed as they are;
 * `blocking` sets MANDU_REPLAY_BLOCKING=1, so a FAIL or TIMEOUT replay
 * verdict fails the entry's test (test-reorganization.md §6.9). Returns
 * { env, dirs }: the variables, and the directories to create (and,
 * sandboxed, to bind read-write).
 */
export function replayPlan(entry, replay) {
  if (!replay?.store || entry.kind !== "replay-drill") return null;
  const at = (d) => (replay.perEntry ? join(d, entry.id) : d);
  const store = at(replay.store);
  const baselines = replay.baselines ? at(replay.baselines) : null;
  return {
    env: {
      MANDU_REPLAY_STORE: store, MANDU_REPLAY_RUN_ID: replay.runId, ...(baselines ? { MANDU_REPLAY_BASELINES: baselines } : {}),
      ...(replay.seed ? { MANDU_REPLAY_BASELINES_SEED: replay.seed } : {}),
      ...(replay.baselineMode ? { MANDU_REPLAY_BASELINE: replay.baselineMode } : {}),
      ...(replay.blocking ? { MANDU_REPLAY_BLOCKING: "1" } : {}),
    },
    dirs: baselines ? [store, baselines] : [store],
  };
}

/** The environment an entry adds: its own `env`, the replay record's
 *  variables (replayPlan), under the fixed pins, which always win, and its
 *  own TMPDIR (`tmp`, below) over all of them, with the same path in
 *  ENTRY_MARK, which a child that moves its TMPDIR still carries (the
 *  stray-process check, entryStrays). */
export function entryEnv(entry, replay = null, tmp = null) {
  return { ...(entry.env ?? {}), ...(replayPlan(entry, replay)?.env ?? {}), ...FIXED_ENV, ...(tmp ? { [ENTRY_MARK]: tmp, TMPDIR: tmp } : {}) };
}

// ── each entry's own TMPDIR (test-organization.md §8.5) ───────────────────────
//
// Test suites that left their temp dirs behind filled a shared host's /tmp (a
// tmpfs, ~1M inodes) on 2026-10-03 and stopped every session and CI. So each
// entry runs with a fresh, empty TMPDIR of its own under one per-run
// directory, and what it leaves there is a failure that names it.

/** What the leftover check does: `fail` (the default) fails an entry that
 *  leaves anything in its TMPDIR, `warn` only says so. */
export const TMP_MODES = Object.freeze(["fail", "warn"]);
/** tsx's compile cache, `${os.tmpdir()}/tsx-${euid}`: tsx has no variable that
 *  moves it but TMPDIR, so every tsx suite makes one in its own TMPDIR. */
export const TSX_CACHE = `tsx-${typeof process.geteuid === "function" ? process.geteuid() : userInfo().username}`;
/** The tools' dirs a suite's TMPDIR gets without the suite asking: tsx's
 *  compile cache (`tsx-<euid>`, also `tsx-0` from a tsx run as root in a user
 *  namespace), node's module compile cache (`node-compile-cache`, which tsc
 *  turns on) and the opencode CLI's temp root (`opencode`, made by the agent
 *  CLI a replay drill drives), and Bun's runtime library
 *  (`.bun-<uid>-<hash>.so`, which a Bun-compiled CLI such as OpenCode 2 unpacks
 *  into TMPDIR at every start, `--version` included; BUN_RUNTIME_LIB), and
 *  Claude Code's temp root (`claude-<uid>`, `$CLAUDE_CODE_TMPDIR || os.tmpdir()`
 *  + `/claude-<uid>`, holding `<cwd-slug>/<session>/tasks/*.output`, which the
 *  claude CLI makes at every start, `--version` included; CLAUDE_CODE_TMP).
 *  They are the tools', not the suite's leak: not counted, removed with the
 *  rest (removeTree takes the whole entry TMPDIR unconditionally, so a CLI's
 *  raw task output never survives the entry). Each suite starts with them cold
 *  (test-organization.md §8.5). */
export const TOOL_CACHES = Object.freeze([TSX_CACHE, "node-compile-cache", "opencode"]);
/** Bun's unpacked runtime library (OpenCode 2.0.23, measured 2026-10-05). */
export const BUN_RUNTIME_LIB = /^\.bun-\d+-[0-9a-f]+\.so$/;
/** Claude Code's temp root, `claude-<uid>` (2.1.273 and 2.1.295, measured
 *  2026-10-09: a drill or corpus suite that runs the claude CLI made one). */
export const CLAUDE_CODE_TMP = /^claude-\d+$/;
const isToolCache = (name) => TOOL_CACHES.includes(name) || /^tsx-\d+$/.test(name) || BUN_RUNTIME_LIB.test(name) || CLAUDE_CODE_TMP.test(name);
/** How long a finished entry's process group gets to exit (its daemons to
 *  remove their sockets and dirs) after the SIGTERM, before the SIGKILL and
 *  the count. */
export const TMP_SETTLE_MS = 5_000;
/** How many leftover names a report lists. */
const TMP_NAMES_SHOWN = 10;

/** The run's directory of per-entry TMPDIRs: short (a socket path under it
 *  must stay within the 107-byte sun_path), canonical (ns-run's --bind-rw
 *  refuses a path through a symlink), private (0700, mkdtemp's). */
export function makeRunTmp(base = tmpdir(), { platform = process.platform } = {}) {
  // Keep per-entry socket paths short on macOS while preserving private,
  // canonical per-run and per-entry directories on both platforms.
  // Resolve the caller's short spelling too: /tmp is /private/tmp on
  // macOS, and a nested short TMPDIR can exceed the budget after realpath.
  const parent = platform === "darwin" &&
    (needsShortTmpdir(platform, base) || Buffer.byteLength(realpathSync(base)) > 12) ? "/tmp" : base;
  // macOS needs the six random characters alone: instance-mode tests add
  // their own temp root and the 63-byte arbiter-instance suffix below it.
  const prefix = platform === "darwin" ? `${parent.replace(/\/+$/, "")}/` : join(parent, "mdu-run-");
  return realpathSync(mkdtempSync(prefix));
}

/** Entry number `n`'s fresh, empty TMPDIR under the run's directory. Its name
 *  is two base-36 digits, so every entry's TMPDIR has the same length: a
 *  replay drill's plain screen prints a path under it, and its cached
 *  baseline is keyed by that length (baseline-cache.ts). */
export function entryTmpDir(runTmp, n) {
  const d = join(runTmp, n.toString(36).padStart(2, "0"));
  mkdirSync(d, { mode: 0o700 });
  return d;
}

// ── The default results dir (no --out): the newest N kept ────────────────────
// A run without --out (test-all.sh's, an agent's --failures-only run) writes
// its summary.json, junit.xml and logs/ to a fresh `mandu-suites-XXXXXX` in
// the runner's tmpdir, which the summary's last line names. Nothing reads one
// later but the person or session that ran it, so at the start of each such
// run the older ones of this user are pruned to the newest N (--keep-results,
// MANDU_TEST_KEEP_RESULTS, default 5; `all` keeps every one), but never one
// that changed within the grace period (--keep-results-hours,
// MANDU_TEST_KEEP_RESULTS_HOURS, default 6: parallel agent sessions each run
// test-all and then read their logs, and another session's run must not
// prune a just-finished dir first), nor one a live run is writing: each
// holds an owner file naming its runner's pid and start time. A run with --out (CI, the dashboard's Tests tab) is never touched
// (test-organization.md §5).

export const RESULTS_PREFIX = "mandu-suites-";
/** The owner file in a default results dir: `{ pid, startTicks, started }`. */
export const RESULTS_OWNER = ".run-suites-owner.json";
export const RESULTS_KEEP = 5;
/** mkdtemp's six characters after the prefix. */
const RESULTS_NAME_RE = /^mandu-suites-[A-Za-z0-9]{6}$/;
/** A dir with no owner file (made by a runner from before 2026-10-18) is
 *  pruned only when nothing in it changed for this long: an older runner's
 *  live run writes its logs as it goes. */
export const RESULTS_LEGACY_IDLE_MS = 60 * 60 * 1000;
/** The grace period: a dir whose newest file changed within it stays,
 *  whatever N says. */
export const RESULTS_GRACE_HOURS = 6;

/** --keep-results-hours / MANDU_TEST_KEEP_RESULTS_HOURS: hours, 0 or more
 *  (fractions allowed). Null when the value is not one. */
export function parseGraceHours(v) {
  if (v == null || v === "") return RESULTS_GRACE_HOURS;
  const n = Number(v);
  return String(v).trim() !== "" && Number.isFinite(n) && n >= 0 ? n : null;
}

/** --keep-results / MANDU_TEST_KEEP_RESULTS: a count of 1 or more, or `all`
 *  (Infinity: no pruning). Null when the value is not one. */
export function parseKeep(v) {
  if (v == null || v === "") return RESULTS_KEEP;
  if (String(v).trim() === "all") return Infinity;
  const n = Number(v);
  return Number.isInteger(n) && n >= 1 ? n : null;
}

/** A fresh default results dir under `base`, with its owner file. */
export function makeResultsDir(base = tmpdir(), { pid = process.pid, startTicks = procStartTicks(pid), now = Date.now() } = {}) {
  const dir = mkdtempSync(join(base, RESULTS_PREFIX));
  writeFileSync(join(dir, RESULTS_OWNER), `${JSON.stringify({ pid, startTicks, started: new Date(now).toISOString() })}\n`);
  return dir;
}

/** Whether the run that made `dir` still runs: true, false, or null (no
 *  readable owner file). A pid that is alive with another start time (reused)
 *  is not the owner; where the start time cannot be read (no /proc) a live
 *  pid counts as the owner. */
export function resultsOwnerLive(dir, { alive = pidAlive, ticksOf = procStartTicks } = {}) {
  let o;
  try { o = JSON.parse(readFileSync(join(dir, RESULTS_OWNER), "utf8")); } catch { return null; }
  if (!o || !Number.isSafeInteger(o.pid) || o.pid <= 0) return null;
  if (!alive(o.pid)) return false;
  const now = o.startTicks == null ? null : ticksOf(o.pid);
  return now == null || now === o.startTicks;
}

/** The newest mtime in a results dir's tree (it is two levels deep: logs/). */
function newestMtime(dir, depth = 2) {
  let t = 0;
  try { t = lstatSync(dir).mtimeMs; } catch { return Infinity; }
  if (depth === 0) return t;
  let names;
  try { names = readdirSync(dir, { withFileTypes: true }); } catch { return Infinity; }
  for (const d of names) {
    const p = join(dir, d.name);
    if (d.isDirectory()) t = Math.max(t, newestMtime(p, depth - 1));
    else { try { t = Math.max(t, lstatSync(p).mtimeMs); } catch { /* gone */ } }
  }
  return t;
}

/**
 * Prune the default results dirs in `base` to the newest `keep` (by mtime):
 * only real directories named `mandu-suites-XXXXXX` and owned by `uid`, and
 * only those outside the newest `keep` AND idle past the grace (nothing in
 * the tree changed within `graceMs`); never `self`, nor one whose owner run
 * is live, nor one with no owner file that changed within the longer of the
 * grace and RESULTS_LEGACY_IDLE_MS. Returns { removed, recent, live } (paths;
 * `recent`: kept by the grace).
 */
export function pruneResultsDirs(base, { keep = RESULTS_KEEP, graceMs = RESULTS_GRACE_HOURS * 3600_000, self = null, uid = process.getuid?.() ?? null, now = Date.now(), legacyIdleMs = RESULTS_LEGACY_IDLE_MS, alive, ticksOf } = {}) {
  const removed = [];
  const recent = [];
  const live = [];
  if (!(keep >= 1) || keep === Infinity) return { removed, recent, live };
  let names;
  try { names = readdirSync(base); } catch { return { removed, recent, live }; }
  const dirs = [];
  for (const name of names) {
    if (!RESULTS_NAME_RE.test(name)) continue;
    const p = join(base, name);
    let st;
    try { st = lstatSync(p); } catch { continue; }
    if (!st.isDirectory() || (uid != null && st.uid !== uid)) continue;
    dirs.push({ p, mtime: st.mtimeMs });
  }
  dirs.sort((a, b) => b.mtime - a.mtime || (a.p < b.p ? -1 : 1));
  for (const { p } of dirs.slice(keep)) {
    if (self && p === self) continue;
    const idle = now - newestMtime(p);
    if (idle < graceMs) { recent.push(p); continue; }
    const owner = resultsOwnerLive(p, { alive, ticksOf });
    if (owner === true || (owner === null && idle < legacyIdleMs)) { live.push(p); continue; }
    try { rmSync(p, { recursive: true, force: true }); removed.push(p); } catch { /* left for tmp-gc */ }
  }
  return { removed, recent, live };
}

/** What an entry left in its TMPDIR: the top-level names (sorted, the tools'
 *  caches left out) and how many inodes they hold (symlinks not followed). */
export function tmpLeftovers(dir, { ignore = isToolCache } = {}) {
  let names;
  try { names = readdirSync(dir).filter((n) => !ignore(n)).sort(); } catch { return { names: [], inodes: 0 }; }
  let inodes = 0;
  const stack = names.map((n) => join(dir, n));
  while (stack.length) {
    const p = stack.pop();
    inodes++;
    let st;
    try { st = lstatSync(p); } catch { continue; }
    if (!st.isDirectory()) continue;
    try { for (const x of readdirSync(p)) stack.push(join(p, x)); } catch { /* unreadable: counted as one */ }
  }
  return { names, inodes };
}

/** One line for a leftover report: the count, the inodes, the first names. */
export function leftoverText({ names, inodes }) {
  const shown = names.slice(0, TMP_NAMES_SHOWN).join(", ");
  const more = names.length > TMP_NAMES_SHOWN ? `, … (+${names.length - TMP_NAMES_SHOWN} more)` : "";
  return `left ${names.length} entr${names.length === 1 ? "y" : "ies"} (${inodes} inodes) in its TMPDIR: ${shown}${more}`;
}

/** Remove a tree a suite left, also one it made read-only (each directory gets
 *  its owner's rwx back first). True when it is gone. */
export function removeTree(dir) {
  try { rmSync(dir, { recursive: true, force: true }); return true; } catch { /* below */ }
  const stack = [dir];
  while (stack.length) {
    const p = stack.pop();
    try {
      if (!lstatSync(p).isDirectory()) continue;
      chmodSync(p, 0o700);
      for (const x of readdirSync(p)) stack.push(join(p, x));
    } catch { /* not ours, or gone */ }
  }
  try { rmSync(dir, { recursive: true, force: true }); return true; } catch { return !existsSync(dir); }
}

const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });

/** Wait (up to `ms`) until no process of group `pid` is left. */
export async function groupGone(pid, ms) {
  const end = Date.now() + ms;
  for (;;) {
    try { process.kill(-pid, 0); } catch (e) { if (e.code === "ESRCH") return true; }
    if (Date.now() >= end) return false;
    await sleep(50);
  }
}

// ── what escapes the process group and the TMPDIR (test-organization.md §8.5) ──
//
// A daemon started with `setsid` (or `detached: true`) leaves the entry's
// process group, so the group's SIGTERM/SIGKILL misses it and it outlives the
// entry, holding sockets, ports and files. Every process the entry starts
// inherits its TMPDIR and ENTRY_MARK, which name a directory no other process
// has reason to know, so after the group is gone the runner looks for its
// own uid's processes, born since the entry started, that still name that
// directory: in ENTRY_MARK, TMPDIR or XDG_RUNTIME_DIR, as their cwd, or in an
// open file. Each is a stray: killed (SIGTERM, then SIGKILL) and reported,
// and it FAILS the entry like a leftover file. The match is exact (the
// directory is unique to this entry of this run), so nothing else is killed.
//
// A daemon that also dropped its environment, moved its cwd and holds
// nothing open there names nothing of the entry; its ancestry is the trace it
// cannot drop. On Linux the entry runs under a child subreaper of its own,
// lib/subreaper.c, compiled once per run with the host's `cc`: every orphan
// of the entry's tree is reparented to it, not to init, so once the group is
// gone any live child of the subreaper is a stray too, whatever it names
// (`adoptedBy`). It reaps every child that ends, as init would, and is no
// interpreter (a guard that trusts a `from: python3` parent counts every
// ancestor). The subreaper itself names the entry's TMPDIR too and is never
// a stray (`exclude`).

/** The variable every entry's processes carry: the entry's own TMPDIR. */
export const ENTRY_MARK = "MANDU_TEST_ENTRY";
/** How long the strays get after their SIGTERM, before the SIGKILL. */
export const STRAY_GRACE_MS = 2_000;

/** A process's start, in clock ticks since boot, or null when /proc does not show it. */
export function procStartTicks(pid, procRoot = "/proc") {
  try { return parseProcStat(readFileSync(join(procRoot, String(pid), "stat"), "utf8"))?.startTicks ?? null; } catch { return null; }
}

/** The entry's subreaper's source (C, libc only). */
export const SUBREAPER_SRC = fileURLToPath(new URL("./lib/subreaper.c", import.meta.url));
const subreapers = new Map();
/**
 * The subreaper binary for the run whose directory is `runDir` (an entry's
 * TMPDIR is `<runDir>/<n>`): `<runDir>/mdu-subreaper`, compiled from
 * SUBREAPER_SRC with `cc` on the first ask and removed with the run's
 * directory. Null: not Linux, no `cc` (or it failed), or
 * MANDU_TEST_SUBREAPER=0; the entry then runs directly and a stray is found
 * by what it names alone.
 */
export function subreaperBinary(runDir, { env = process.env, platform = process.platform } = {}) {
  if (platform !== "linux" || env.MANDU_TEST_SUBREAPER === "0" || !runDir) return null;
  if (!subreapers.has(runDir)) {
    const out = join(runDir, "mdu-subreaper");
    const r = spawnSync("cc", ["-O2", "-o", out, SUBREAPER_SRC], { stdio: "ignore", timeout: 60_000 });
    subreapers.set(runDir, r.status === 0 && existsSync(out) ? out : null);
  }
  return subreapers.get(runDir);
}

/**
 * The processes still naming one of `dirs` (the entry's TMPDIR and runtime
 * dir): { pid, argv, why } for each process of `uid` but this one, started at
 * or after `sinceTicks` (procStartTicks of the entry's first process; null:
 * any), whose environment names a dir (ENTRY_MARK equal to one, TMPDIR or
 * XDG_RUNTIME_DIR under one), whose cwd is under one, or that holds a file
 * open under one; and, with `adoptedBy` (the entry's subreaper), each live
 * child of it, which names nothing at all ("orphan"). A process /proc will
 * not show is left out.
 */
export function entryStrays(dirs, { procRoot = "/proc", uid = process.getuid?.() ?? null, self = process.pid, sinceTicks = null, adoptedBy = null, exclude = [] } = {}) {
  const roots = dirs.filter(Boolean);
  if (!roots.length && adoptedBy == null) return [];
  const under = (p) => typeof p === "string" && roots.some((d) => p === d || p.startsWith(`${d}/`));
  const skip = new Set([self, ...exclude].filter((x) => x != null).map(Number));
  let names;
  try { names = readdirSync(procRoot).filter((n) => /^\d+$/.test(n) && !skip.has(Number(n))); } catch { return []; }
  const out = [];
  for (const n of names) {
    const base = join(procRoot, n);
    let why = null;
    try {
      if (uid != null && statSync(base).uid !== uid) continue;
      const text = readFileSync(join(base, "stat"), "utf8");
      const st = parseProcStat(text);
      if (!st || (sinceTicks != null && st.startTicks < sinceTicks)) continue;
      // A zombie (state Z, the field after the comm) is gone already: its
      // subreaper reaps it.
      if (adoptedBy != null && st.ppid === adoptedBy) {
        if (text.slice(text.lastIndexOf(")") + 2, text.lastIndexOf(")") + 3) === "Z") continue;
        why = "orphan";
      }
    } catch { continue; }
    if (!why) {
      try {
        for (const kv of readFileSync(join(base, "environ"), "latin1").split("\0")) {
          const i = kv.indexOf("=");
          if (i <= 0) continue;
          const k = kv.slice(0, i);
          const v = kv.slice(i + 1);
          if (k === ENTRY_MARK ? roots.includes(v) : (k === "TMPDIR" || k === "XDG_RUNTIME_DIR") && under(v)) { why = `env ${k}`; break; }
        }
      } catch { /* not readable */ }
    }
    if (!why) { try { if (under(readlinkSync(join(base, "cwd")))) why = "cwd"; } catch { /* gone */ } }
    if (!why) {
      try {
        for (const fd of readdirSync(join(base, "fd"))) {
          let target;
          try { target = readlinkSync(join(base, "fd", fd)); } catch { continue; }
          if (under(target)) { why = `open ${target}`; break; }
        }
      } catch { /* not readable */ }
    }
    if (!why) continue;
    let argv = [];
    try { argv = readFileSync(join(base, "cmdline"), "utf8").split("\0").filter(Boolean); } catch { /* gone */ }
    out.push({ pid: Number(n), argv, why });
  }
  return out;
}

/** Alive: signalable and not a zombie (an orphan the subreaper adopted
 *  stays a zombie until it ends; it is gone all the same). */
const pidAlive = (pid) => {
  try { process.kill(pid, 0); } catch (e) { if (e.code !== "EPERM") return false; }
  try { const st = readFileSync(`/proc/${pid}/stat`, "utf8"); return st.slice(st.lastIndexOf(")") + 2, st.lastIndexOf(")") + 3) !== "Z"; } catch { return true; }
};

/** Find the entry's strays and kill them: SIGTERM, `graceMs`, SIGKILL; a few
 *  rounds, for one that started another. A process found already on its way
 *  out (one the suite stopped just before it exited) gets `graceMs` to go by
 *  itself first and is no stray if it does. Returns every stray killed. */
export async function reapStrays(dirs, { graceMs = STRAY_GRACE_MS, rounds = 3, ...scan } = {}) {
  const found = new Map();
  let first = entryStrays(dirs, scan);
  if (first.length) {
    const end = Date.now() + graceMs;
    while (first.some((s) => pidAlive(s.pid)) && Date.now() < end) await sleep(50);
    first = null;
  }
  for (let i = 0; i < rounds; i++) {
    const strays = (first ?? entryStrays(dirs, scan)).filter((s) => !found.has(s.pid));
    first = null;
    if (!strays.length) break;
    for (const s of strays) { found.set(s.pid, s); try { process.kill(s.pid, "SIGTERM"); } catch { /* gone */ } }
    const end = Date.now() + graceMs;
    while (strays.some((s) => pidAlive(s.pid)) && Date.now() < end) await sleep(50);
    for (const s of strays) if (pidAlive(s.pid)) { try { process.kill(s.pid, "SIGKILL"); } catch { /* gone */ } }
  }
  return [...found.values()];
}

/** One line for a stray report: the count and the first processes. */
export function strayText(strays) {
  const one = (s) => `${s.pid} (${(s.argv.join(" ") || "?").slice(0, 120)})`;
  const shown = strays.slice(0, TMP_NAMES_SHOWN).map(one).join(", ");
  const more = strays.length > TMP_NAMES_SHOWN ? `, … (+${strays.length - TMP_NAMES_SHOWN} more)` : "";
  return `left ${strays.length} process${strays.length === 1 ? "" : "es"} running outside its process group (killed): ${shown}${more}`;
}

// ── new entries outside the TMPDIR (warn only) ─────────────────────────────────
//
// A test that writes to a hard-coded /tmp/..., to $HOME or to the caller's
// XDG_RUNTIME_DIR is outside its TMPDIR, so the leftover count cannot see it.
// For an unsandboxed entry (a box has its own /tmp, home and runtime dir) the
// runner lists those directories before and after, and names what is new,
// owned by this uid and still there at the end. Another process of the same
// user (a concurrent entry, another session) writes there too, so this is a
// warning, never a failure.

/** The directories the outside check lists for an entry with environment
 *  `env`: /tmp, the runtime dir and its `mandu`, `mandu/instances` and
 *  `mandu/human` (unless it is the entry's own, `ownRt`), and $HOME. */
export function outsideRoots(env, { ownRt = null, hostTmp = "/tmp" } = {}) {
  const rt = env.XDG_RUNTIME_DIR && env.XDG_RUNTIME_DIR !== ownRt ? env.XDG_RUNTIME_DIR : null;
  const roots = [hostTmp, ...(rt ? [rt, join(rt, "mandu"), join(rt, "mandu", "instances"), join(rt, "mandu", "human")] : []), env.HOME || null];
  return [...new Set(roots.filter((d) => d && isAbsolute(d) && d !== "/"))];
}

/** The names in each root now: { root: Set<name> } (an unreadable root: empty). */
export function snapshotRoots(roots) {
  const snap = {};
  for (const r of roots) { try { snap[r] = new Set(readdirSync(r)); } catch { snap[r] = new Set(); } }
  return snap;
}

/** What is new since `before` (snapshotRoots), owned by `uid` and still
 *  there: the full paths, sorted, without the paths in `except` (the run's
 *  own dirs). */
export function newOutside(before, { uid = process.getuid?.() ?? null, except = [] } = {}) {
  const found = [];
  for (const [r, was] of Object.entries(before)) {
    let now;
    try { now = readdirSync(r); } catch { continue; }
    for (const n of now) {
      if (was.has(n)) continue;
      const p = join(r, n);
      if (except.some((e) => p === e || e.startsWith(`${p}/`))) continue;
      try { if (uid != null && lstatSync(p).uid !== uid) continue; } catch { continue; }
      found.push(p);
    }
  }
  return found.sort();
}

/** One line for the outside report. */
export function outsideText(paths) {
  const shown = paths.slice(0, TMP_NAMES_SHOWN).join(", ");
  const more = paths.length > TMP_NAMES_SHOWN ? `, … (+${paths.length - TMP_NAMES_SHOWN} more)` : "";
  return `${paths.length} new outside its TMPDIR while it ran (not counted: another process may have made them): ${shown}${more}`;
}

/** A drill runs `drill-run.ts` (and a `watchStore` entry, the demo battery,
 *  runs it per side: suites.mjs recordsLive), whose record (meta, chapters, the terminal
 *  recordings, the report) the dashboard reads from the account's watch store.
 *  The MANDU_HOME pinned above is not the caller's, so the store is resolved
 *  from the CALLER's environment and handed over as a flag (a store placed
 *  elsewhere is told by a flag, on-disk-layout.md §9). Without it every drill
 *  run's record went to a temp home under /tmp and the dashboard showed the
 *  sessions with no record and no recording (2026-09-30; test-organization.md
 *  §7.2). An entry that names its own --store or --out keeps it. `store`
 *  (--watch-store) wins over the environment: test-all.sh resolves the
 *  caller's before it pins MANDU_HOME, so a drill run through it records
 *  where the dashboard looks, not under /dev/null (2026-10-01). */
export function withWatchStore(entry, env, home, store = null) {
  if (!recordsLive(entry) || entry.cmd.includes("--store") || entry.cmd.includes("--out")) return entry;
  return { ...entry, cmd: [...entry.cmd, "--store", store ?? resolvePath("live-drill-runs", env, home)] };
}

/** A watch store that cannot hold a record: one below /dev/null, as every
 *  path under the pinned test home (FIXED_ENV.MANDU_HOME) is. */
export function unusableWatchStore(store) {
  return store === "/dev/null" || store.startsWith("/dev/null/");
}

/** The argv an entry runs as: sandboxed (non-kernel, --sandbox given) or
 *  direct. A sandboxed replay-drill entry's record directories are its
 *  --bind-rw paths (ns-run.sh: the box's only writable host paths), and so is
 *  its own TMPDIR (`tmp`), set over ns-run's TMPDIR=/tmp (its --setenv pairs
 *  come last), so the leftover check sees what the box left there. */
export function buildArgv(entry, { root = REPO_ROOT, sandbox = null, replay = null, tmp = null } = {}) {
  const cwd = resolve(root, entry.cwd ?? ".");
  if (sandbox && !needsKernel(entry)) {
    const setenv = Object.entries(entryEnv(entry, replay, tmp)).flatMap(([k, v]) => ["--setenv", k, String(v)]);
    const binds = [...(replayPlan(entry, replay)?.dirs ?? []), ...(tmp ? [tmp] : [])].flatMap((d) => ["--bind-rw", d]);
    return { argv: [sandbox, "--chdir", cwd, ...binds, ...setenv, "--", ...entry.cmd], cwd: root, sandboxed: true };
  }
  return { argv: [...entry.cmd], cwd, sandboxed: false };
}

function killGroup(pid, signal) {
  try { process.kill(-pid, signal); } catch { /* gone */ }
}

const running = new Set();

/** Keep the tail of a log over `cap` bytes, with a marker line. */
export function capLog(path, cap = LOG_CAP) {
  const size = statSync(path).size;
  if (size <= cap) return false;
  const buf = Buffer.alloc(cap);
  const fd = openSync(path, "r");
  try { readSync(fd, buf, 0, cap, size - cap); } finally { closeSync(fd); }
  const nl = buf.indexOf(0x0a);
  const tail = nl >= 0 && nl < 4096 ? buf.subarray(nl + 1) : buf;
  writeFileSync(path, Buffer.concat([Buffer.from(`[run-suites] log truncated: kept the last ${tail.length} of ${size} bytes\n`), tail]));
  return true;
}

function readForParse(path) {
  const size = statSync(path).size;
  if (size <= PARSE_WINDOW) return readFileSync(path, "utf8");
  const buf = Buffer.alloc(PARSE_WINDOW);
  const fd = openSync(path, "r");
  try { readSync(fd, buf, 0, PARSE_WINDOW, size - PARSE_WINDOW); } finally { closeSync(fd); }
  return buf.toString("utf8");
}

/** Last `n` lines of a file (at most 64 KiB), for a failure's report. */
export function tailOf(path, n = 25) {
  if (!existsSync(path)) return "";
  const size = statSync(path).size;
  const len = Math.min(size, 64 * 1024);
  const buf = Buffer.alloc(len);
  const fd = openSync(path, "r");
  try { readSync(fd, buf, 0, len, size - len); } finally { closeSync(fd); }
  return stripAnsi(buf.toString("utf8")).split("\n").slice(-n - 1).join("\n").trimEnd();
}

// ── a timeout's report ─────────────────────────────────────────────────────────
//
// At the deadline, before the SIGTERM, the entry's processes are read off /proc
// and the test files still running are named (lib/timeout-report.mjs, shared
// verbatim with the dashboard's test runner). These wrappers take the entry.

export { openTestsInLog, parseProcStat, readProcTable, runningTestFiles, suiteProcesses } from "./lib/timeout-report.mjs";

/** The report a timeout writes into the entry's log before the SIGTERM (lib/timeout-report.mjs). */
export function timeoutReport({ entry, rootPid, table, logText = "", root = REPO_ROOT }) {
  return sharedTimeoutReport({ timeoutS: entry.timeout, rootPid, table, logText, root, tag: "run-suites" });
}

/** The `reason` of a timed-out entry: the limit, then what was still running.
 *  `deadlineAfterS` (a number): the run's --deadline stopped it after that many
 *  seconds, before its own timeout. */
export function timeoutReason(entry, hung = [], { deadlineAfterS = null } = {}) {
  if (deadlineAfterS == null) return sharedTimeoutReason(entry.timeout, hung);
  const still = sharedTimeoutReason(deadlineAfterS, hung).replace(/^timed out after \d+s/, "");
  return `stopped by the run's deadline (--deadline) after ${deadlineAfterS}s, before its own timeout of ${entry.timeout}s${still}`;
}

/**
 * When an entry's timer fires: its own timeout, or the run's deadline when that
 * comes first. Pure: { ms, byDeadline }; `deadline` is epoch ms or null.
 */
export function entryLimit(entry, { now = Date.now(), deadline = null } = {}) {
  const own = entry.timeout * 1000;
  if (deadline == null) return { ms: own, byDeadline: false };
  const left = Math.max(0, deadline - now);
  return left < own ? { ms: left, byDeadline: true } : { ms: own, byDeadline: false };
}

/** --heartbeat's line: the entries still running, longest first, each with its
 *  age and its timeout. `active` maps id → { started (epoch ms), timeout (s) }. */
export function heartbeatLine(active, { now = Date.now(), runStarted = now } = {}) {
  const rows = [...active].map(([id, a]) => ({ id, age: Math.round((now - a.started) / 1000), timeout: a.timeout }))
    .sort((a, b) => b.age - a.age || (a.id < b.id ? -1 : 1));
  return `… ${Math.round((now - runStarted) / 1000)}s into the run, still running: ${rows.map((r) => `${r.id} (${r.age}s of ${r.timeout}s)`).join(", ")}`;
}

/**
 * Run one entry to completion. Output goes straight to logs/<id>.log (a file,
 * not a pipe, so a background child a suite leaves behind cannot hold the run
 * open). The entry is its own process group: a timeout first writes the
 * timeout report (above) into the log, then sends SIGTERM to the group, then
 * SIGKILL after a grace period; a normal exit sweeps the group too.
 * With `tmp` (the entry's own empty TMPDIR, entryTmpDir) the entry runs with
 * TMPDIR set to it; once it is done, its group gets `tmpSettleMs` to exit
 * (then SIGKILL), what is left there is counted (tmpLeftovers) and the dir
 * removed. A leftover fails a passing (or skipping) entry under `tmpMode`
 * "fail" and is reported in every case (the result's `tmpLeft`); so does a
 * stray, a process outside the group that still names the TMPDIR or that
 * the entry's subreaper adopted (killed;
 * the result's `strays`, reapStrays). An unsandboxed entry's new files in
 * `watchRoots` (default outsideRoots) are reported, never a failure (the
 * result's `outside`).
 */
/** macOS gives each user a 49-byte TMPDIR (/var/folders/…/T/), and the
 *  suites bind Unix sockets under tmpdir(): an arbiter instance socket in a
 *  mkdtemp dir there overshoots the 104-byte sun_path (runtime-instances.md
 *  §3a/§3b). A darwin run whose TMPDIR is longer than this gets a short
 *  private one instead (development.md, "Developing and testing on macOS"). */
export const DARWIN_TMPDIR_MAX = 20;

/** Does this run need a short TMPDIR? Pure: the platform and the TMPDIR the
 *  suites would otherwise inherit. */
export function needsShortTmpdir(platform, tmp) {
  return platform === "darwin" && Buffer.byteLength(String(tmp).replace(/\/+$/, ""), "utf8") > DARWIN_TMPDIR_MAX;
}

export function runEntry(entry, {
  root = REPO_ROOT, outDir, sandbox = null, replay = null, strictSkips = false, logCap = LOG_CAP, killGraceMs = KILL_GRACE_MS,
  baseEnv = process.env, tmp = null, tmpMode = "fail", tmpSettleMs = TMP_SETTLE_MS, watchRoots = null, procRoot = "/proc",
  deadline = null,
} = {}) {
  const logRel = `logs/${entry.id}.log`;
  const logPath = join(outDir, logRel);
  const { argv, cwd, sandboxed } = buildArgv(entry, { root, sandbox, replay, tmp });
  // The replay variables come from --replay-store alone, never from the caller.
  const inherited = { ...baseEnv };
  for (const k of REPLAY_VARS) delete inherited[k];
  const env = sandboxed ? inherited : { ...inherited, ...entryEnv(entry, replay, tmp) };
  // An unsandboxed entry with no runtime dir (the CI guest's kernel lane)
  // gets a fresh one beside its TMPDIR, as ns-run gives a box one: without
  // it the arbiter's runtime root falls back to $TMPDIR/mandu, which a
  // session keeps by design (arbiter/ipc/instance.ts). Removed afterwards,
  // never counted.
  const rt = tmp && !sandboxed && !env.XDG_RUNTIME_DIR ? `${tmp}.rt` : null;
  if (rt) { mkdirSync(rt, { mode: 0o700 }); env.XDG_RUNTIME_DIR = rt; }
  for (const d of replayPlan(entry, replay)?.dirs ?? []) mkdirSync(d, { recursive: true });
  // The outside check (above outsideRoots): an unsandboxed entry only.
  const watch = tmp && !sandboxed ? (watchRoots ?? outsideRoots(env, { ownRt: rt })) : [];
  const before = watch.length ? snapshotRoots(watch) : null;
  let since = null;
  // With the guard on, the entry runs under its own subreaper (lib/
  // subreaper.c, "Strays" above): its orphans stay its descendants.
  const reaper = tmp ? subreaperBinary(dirname(tmp), { env: baseEnv }) : null;
  const started = Date.now();
  const fd = openSync(logPath, "w");
  writeFileSync(fd, `[run-suites] ${entry.id} kind=${entry.kind}${entry.frozen ? " frozen" : ""} axis=${entry.axis} cwd=${entry.cwd}${sandboxed ? " sandbox" : ""}\n[run-suites] cmd: ${JSON.stringify(argv)}\n`);

  return new Promise((done) => {
    let child;
    // The entry's first process, which leads its session and process group:
    // the spawned child itself, or the one the subreaper reports.
    let pid = null;
    let timedOut = false;
    let deadlineAfterS = null;
    let hung = [];
    let settled = false;
    let timer = null;
    let killer = null;
    // `ticks`: its start as the subreaper read it (before anything could reap
    // it); else read here, which an entry that is already gone defeats.
    const begin = (p, ticks = null) => { pid = p; running.add(p); since = ticks ?? procStartTicks(p, procRoot); };
    // The subreaper stops when its stdin closes; by then its strays are gone.
    const release = () => { if (reaper) { try { child?.stdin?.end(); } catch { /* gone */ } } };
    const settle = (code, signal, spawnError) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (killer) clearTimeout(killer);
      if (pid) killGroup(pid, "SIGTERM");
      const duration = (Date.now() - started) / 1000;
      try { writeFileSync(fd, `\n[run-suites] exit=${code ?? "-"} signal=${signal ?? "-"} duration=${duration.toFixed(1)}s\n`); } catch { /* closed */ }
      (async () => {
        // The leftover check waits for the whole group (a daemon the suite
        // started removes its socket on the SIGTERM above), then counts.
        let left = null;
        let strays = [];
        let outside = [];
        if (tmp) {
          if (pid && !(await groupGone(pid, tmpSettleMs))) {
            killGroup(pid, "SIGKILL");
            await groupGone(pid, 1000);
          }
          // A daemon that left the group (setsid) is found by the directory it
          // still names, or as the subreaper's child, killed, and counted
          // before the files it holds.
          if (pid) strays = await reapStrays([tmp, rt], { procRoot, sinceTicks: since, adoptedBy: reaper ? child?.pid ?? null : null, exclude: reaper && child?.pid ? [child.pid] : [] });
          release();
          left = tmpLeftovers(tmp);
          if (before) outside = newOutside(before, { except: [tmp, rt, outDir].filter(Boolean) });
          if (!removeTree(tmp)) {
            try { writeFileSync(fd, `[run-suites] could not remove its TMPDIR ${tmp}; the run's directory is removed at the end\n`); } catch { /* closed */ }
          }
          if (rt) removeTree(rt);
        }
        release();
        if (pid) running.delete(pid);
        try { closeSync(fd); } catch { /* closed */ }
        const counts = parseCounts(readForParse(logPath));
        let { result, reason } = classify(entry, { code, timedOut, hung, spawnError, counts, strictSkips, deadlineAfterS });
        const tmpLeft = left?.names.length ? left : null;
        const leaks = [...(strays.length ? [strayText(strays)] : []), ...(tmpLeft ? [leftoverText(tmpLeft)] : [])];
        for (const text of leaks) {
          try { writeFileSync(logPath, `[run-suites] TMPDIR: ${text}\n`, { flag: "a" }); } catch { /* ignore */ }
          if (tmpMode === "fail") {
            if (result === "pass" || result === "skip") { result = "fail"; reason = text; }
            else reason = reason ? `${reason}; ${text}` : text;
          }
        }
        if (outside.length) {
          try { writeFileSync(logPath, `[run-suites] outside: ${outsideText(outside)}\n`, { flag: "a" }); } catch { /* ignore */ }
        }
        if (reason && result !== "pass") {
          try { writeFileSync(logPath, `[run-suites] ${result}: ${reason}\n`, { flag: "a" }); } catch { /* ignore */ }
        }
        capLog(logPath, logCap);
        done({
          id: entry.id, kind: entry.kind, result, pass: counts.pass, fail: counts.fail, skip: counts.skip,
          duration_s: Math.round(duration * 10) / 10, log: logRel,
          summary: counts.summary, reason, format: counts.format, argv, ...(tmpLeft ? { tmpLeft } : {}),
          ...(strays.length ? { strays } : {}), ...(outside.length ? { outside } : {}),
        });
      })();
    };
    const [file, ...args] = reaper ? [reaper, ...argv] : argv;
    try {
      child = spawn(file, args, { cwd, env, detached: true, stdio: reaper ? ["pipe", fd, fd, "pipe"] : ["ignore", fd, fd] });
    } catch (e) {
      settle(null, null, e.message);
      return;
    }
    child.on("error", (e) => settle(null, null, e.message));
    if (!reaper) {
      if (child.pid) begin(child.pid);
      child.on("exit", (code, signal) => settle(code, signal, null));
    } else {
      // Its report on fd 3 (lib/subreaper.c): "pid N TICKS", then "exit CODE
      // SIGNAL" or "error MESSAGE". Its own end before that is an error.
      child.stdin.on("error", () => { /* it is gone */ });
      let buf = "";
      child.stdio[3].setEncoding("utf8");
      child.stdio[3].on("data", (chunk) => {
        buf += chunk;
        for (let nl = buf.indexOf("\n"); nl >= 0; nl = buf.indexOf("\n")) {
          const [word, ...rest] = buf.slice(0, nl).split(" ");
          buf = buf.slice(nl + 1);
          if (word === "pid" && !pid) begin(Number(rest[0]), /^\d+$/.test(rest[1] ?? "") ? Number(rest[1]) : null);
          else if (word === "exit") settle(rest[0] === "-" ? null : Number(rest[0]), rest[1] === "-" ? null : rest[1], null);
          else if (word === "error") settle(null, null, rest.join(" "));
        }
      });
      child.on("close", (code, signal) => settle(null, null, `its subreaper ended first (exit ${code ?? "-"}, signal ${signal ?? "-"})`));
    }
    // The entry's own timeout, or the run's --deadline when that comes first:
    // either way the timeout report, then SIGTERM, then SIGKILL.
    const limit = entryLimit(entry, { deadline });
    timer = setTimeout(() => {
      timedOut = true;
      const lead = pid ?? child.pid;
      const afterS = Math.round((Date.now() - started) / 1000);
      if (limit.byDeadline) deadlineAfterS = afterS;
      try {
        const report = timeoutReport({ entry: limit.byDeadline ? { ...entry, timeout: afterS } : entry, rootPid: lead, table: readProcTable(), logText: readForParse(logPath), root });
        hung = report.hung;
        const head = limit.byDeadline ? [`[run-suites] the run's deadline (--deadline) came after ${afterS}s, before this entry's own timeout of ${entry.timeout}s`] : [];
        writeFileSync(fd, `\n${[...head, ...report.lines].join("\n")}\n`);
      } catch (e) {
        try { writeFileSync(fd, `\n[run-suites] timeout report failed: ${e.message}\n`); } catch { /* closed */ }
      }
      killGroup(lead, "SIGTERM");
      killer = setTimeout(() => killGroup(lead, "SIGKILL"), killGraceMs);
      killer.unref?.();
    }, limit.ms);
  });
}

// ── results ────────────────────────────────────────────────────────────────────

const xmlEscape = (s) => String(s)
  // eslint-disable-next-line no-control-regex
  .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]/g, "")
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** junit.xml: one <testsuite> per entry, so a merge request names the failing entry. */
export function junitXml(results, outDir, { name = "mandu" } = {}) {
  const sum = (k) => results.reduce((a, r) => a + r[k], 0);
  const failures = results.filter((r) => r.result === "fail").length;
  const errors = results.filter((r) => r.result === "timeout" || r.result === "error").length;
  const skipped = results.filter((r) => r.result === "skip").length;
  const time = results.reduce((a, r) => a + r.duration_s, 0).toFixed(1);
  const out = ['<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites name="${xmlEscape(name)}" tests="${results.length}" failures="${failures}" errors="${errors}" skipped="${skipped}" time="${time}">`];
  for (const r of results) {
    const f = r.result === "fail" ? 1 : 0;
    const er = r.result === "timeout" || r.result === "error" ? 1 : 0;
    const sk = r.result === "skip" ? 1 : 0;
    out.push(`  <testsuite name="${xmlEscape(r.id)}" tests="1" failures="${f}" errors="${er}" skipped="${sk}" time="${r.duration_s}">`);
    out.push(`    <properties><property name="kind" value="${xmlEscape(r.kind)}"/><property name="pass" value="${r.pass}"/><property name="fail" value="${r.fail}"/><property name="skip" value="${r.skip}"/><property name="log" value="${xmlEscape(r.log)}"/></properties>`);
    out.push(`    <testcase classname="${xmlEscape(r.kind)}" name="${xmlEscape(r.id)}" time="${r.duration_s}">`);
    const tail = () => xmlEscape(tailOf(join(outDir, r.log), 80));
    if (f) out.push(`      <failure type="fail" message="${xmlEscape(r.reason ?? r.summary)}">${tail()}</failure>`);
    else if (er) out.push(`      <error type="${r.result}" message="${xmlEscape(r.reason ?? r.result)}">${tail()}</error>`);
    else if (sk) out.push(`      <skipped message="${xmlEscape(r.summary)}"/>`);
    out.push(`      <system-out>${xmlEscape(r.summary)}</system-out>`);
    out.push("    </testcase>", "  </testsuite>");
  }
  out.push("</testsuites>", "");
  return out.join("\n");
}

const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

/** Text the dashboard's validator accepts: no C0/C1 controls or bidi overrides, bounded. */
const safeText = (s, max) => String(s).replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, " ").slice(0, max);

// ── the agent an entry drives ────────────────────────────────────────────────

/** The agents whose CLIs the hand-run drill script pins in its own cache
 *  (scripts/drills-live.sh --install: MANDU_DRILL_AGENTS, else
 *  ~/.cache/mandu/drill-agents; the agent node in node/bin, the CLIs in
 *  prefix/bin; the agent registry's `cache` lines). Claude Code and Codex
 *  come from PATH. */
export const CACHED_AGENTS = CACHED_LINES;
/** The cache's bin directories to put ahead of PATH, or none when it has no prefix/bin. */
export function agentCacheBins(env, home, exists = existsSync) {
  const dir = env.MANDU_DRILL_AGENTS || join(home, ".cache", "mandu", "drill-agents");
  if (!exists(join(dir, "prefix", "bin"))) return [];
  return [join(dir, "node", "bin"), join(dir, "prefix", "bin")].filter((d) => exists(d));
}
/** The environment an entry runs (and its agent is asked its version) in: an
 *  entry whose agent is one of CACHED_AGENTS finds the cache's CLIs first, so
 *  a dev host runs the pinned agents the hand-run script installed. */
export function withAgentPath(agents, env, home, exists = existsSync) {
  if (!agents.some((a) => CACHED_AGENTS.includes(a))) return env;
  const bins = agentCacheBins(env, home, exists);
  return bins.length ? { ...env, PATH: [...bins, env.PATH ?? ""].filter(Boolean).join(":") } : env;
}

/** The CLI each named agent runs as (OpenCode 2's may be named by its variable). */
export const agentBin = (agent, env = process.env) => (agent === "opencode2" ? env.MANDU_OPENCODE_V2_BIN || "opencode2" : agent);
/** The version in a CLI's `--version` output ("2.1.299 (Claude Code)", "codex-cli 0.162.0"), or null. */
export function parseVersion(text) {
  const m = /(?:^|[^0-9A-Za-z.])v?(\d+\.\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.]+)?)/.exec(stripAnsi(String(text ?? "")));
  return m ? m[1].slice(0, 64) : null;
}
/** Ask an agent's CLI for its version (null when it is absent, fails or hangs). */
export function probeAgentVersion(agent, { env = process.env, timeoutMs = 20_000, run = spawnSync } = {}) {
  let r;
  try { r = run(agentBin(agent, env), ["--version"], { env, encoding: "utf8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] }); } catch { return null; }
  if (!r || r.error || r.status !== 0) return null;
  return parseVersion(`${r.stdout ?? ""}\n${r.stderr ?? ""}`);
}
/** The version an entry's own run reported (`# agent-version X`, the drill
 *  runner's footer; the last one wins), or null: it wins over the probe, so
 *  an entry that installed another release (the drift check) is reported at
 *  the version it ran. */
export function loggedAgentVersion(text) {
  let v = null;
  for (const m of String(text ?? "").matchAll(/^# agent-version ([0-9][0-9A-Za-z.+-]{0,63})\s*$/gm)) v = m[1];
  return v;
}

/** "codex 0.162.0 (U-LLM claude 2.1.299)", the agent column of a result row. */
export function agentLabel(r) {
  if (!r.agent) return "";
  const one = (a, v) => (v ? `${a} ${v}` : a);
  const main = Array.isArray(r.agent) ? r.agent.join("+") : one(r.agent, r.agentVersion);
  return r.ullm ? `${main} (U-LLM ${one(r.ullm, r.ullmVersion)})` : main;
}

// ── the agent matrix (test-organization.md §5) ────────────────────────────────

/** A result's matrix row: a generic suite's id without its agent part
 *  (`drill.conf.codex` → `drill.conf`), an agent-only suite's own id
 *  (`integration.codex-headless`, `drill.claude-fidelity`). */
export const matrixRow = (r) => (typeof r.agent === "string" && r.id.endsWith(`.${r.agent}`) ? r.id.slice(0, -(r.agent.length + 1)) : r.id);

/** A result's cell: its counts (`29✓`, `27✓ 1✗`, `3∅`), else its result. */
export function matrixCell(r) {
  if (r.result === "timeout" || r.result === "error") return r.result;
  const parts = [r.pass ? `${r.pass}✓` : "", r.fail ? `${r.fail}✗` : "", r.skip ? `${r.skip}∅` : ""].filter(Boolean);
  if (r.result === "skip") return parts.length ? `skip (${parts.join(" ")})` : "skip";
  return parts.length ? parts.join(" ") : r.result;
}

/** The results that drove one named agent, as { agents, rows: [{ row, cells }] }:
 *  agents in LIVE_AGENTS order, rows in run order; null when none named one. */
export function agentMatrix(results) {
  const named = results.filter((r) => typeof r.agent === "string");
  if (!named.length) return null;
  const agents = LIVE_AGENTS.filter((a) => named.some((r) => r.agent === a));
  const rows = new Map();
  for (const r of named) {
    const row = matrixRow(r);
    if (!rows.has(row)) rows.set(row, {});
    rows.get(row)[r.agent] = matrixCell(r);
  }
  return { agents, rows: [...rows].map(([row, cells]) => ({ row, cells })) };
}

/** The matrix as plain-text lines (the console) or a Markdown table (summary.md). */
export function matrixText(m) {
  const head = ["suite", ...m.agents];
  const body = m.rows.map(({ row, cells }) => [row, ...m.agents.map((a) => cells[a] ?? "—")]);
  const w = head.map((h, i) => Math.max(h.length, ...body.map((r) => r[i].length)));
  return [head, ...body].map((r) => r.map((c, i) => c.padEnd(w[i])).join("  ").trimEnd());
}
export function matrixMarkdown(m, { run = null } = {}) {
  const esc = (s) => String(s).replace(/\|/g, "\\|");
  return [
    ...(run ? [`# ${esc(run)}`, ""] : []),
    `| suite | ${m.agents.join(" | ")} |`,
    `|---|${m.agents.map(() => "---").join("|")}|`,
    ...m.rows.map(({ row, cells }) => `| \`${esc(row)}\` | ${m.agents.map((a) => esc(cells[a] ?? "—")).join(" | ")} |`),
    "",
    "✓ passed · ✗ failed · ∅ skipped (a count of drills or tests) · — not run on that agent",
    "",
  ].join("\n");
}

/**
 * summary.json, schema 1 (continuous-integration.md §6). Only the schema's fields:
 * `image` and `reason` appear when they have a value; `stages` gains a `suites`
 * stage for this run. An entry that drives one named agent carries `agent`,
 * `agentVersion` (when its CLI reported one) and `ullm`. The dashboard (the
 * developer view's ci-runs.ts) refuses any other field, so nothing else is added here.
 */
export function buildSummary({ run, source, commit, ref, image = null, started, finished, stages = {}, results, runError = null }) {
  const green = (r) => r.result === "pass" || r.result === "skip";
  const suitesOk = results.every((r) => r.nonBlocking || green(r));
  const suitesDuration = Math.round((finished - started) / 100) / 10;
  const allStages = {};
  for (const [name, st] of Object.entries(stages ?? {})) allStages[name] = { result: st.result, duration_s: st.duration_s };
  allStages.suites = { result: runError ? "error" : suitesOk ? "pass" : "fail", duration_s: suitesDuration };
  const erroredStage = Object.entries(allStages).find(([, st]) => st.result === "error" || st.result === "timeout");
  const failedStage = Object.entries(allStages).find(([, st]) => st.result === "fail");
  const result = runError || erroredStage ? "error" : failedStage ? "fail" : "pass";
  const bad = results.filter((r) => !r.nonBlocking && !green(r)).map((r) => `${r.id} (${r.result})`);
  const soft = results.filter((r) => r.nonBlocking && !green(r)).map((r) => `${r.id} (${r.result})`);
  const reason = runError ? runError
    : erroredStage ? `stage ${erroredStage[0]}: ${erroredStage[1].result}`
    : bad.length ? `${bad.length} entr${bad.length === 1 ? "y" : "ies"} not green: ${bad.join(", ")}`
    : failedStage ? `stage ${failedStage[0]}: fail`
    : soft.length ? `non-blocking (flaky, reported or nightly) entries not green: ${soft.join(", ")}` : null;
  return {
    schema: 1, kind: "mandu-ci-run", run, source, commit, ref: safeText(ref ?? "", 255),
    ...(image ? { image: safeText(image, 200) } : {}),
    started: iso(started), finished: iso(finished), result,
    ...(reason ? { reason: safeText(reason, 2000) } : {}),
    stages: allStages,
    entries: results.map(({ id, kind, result: r, pass, fail, skip, duration_s, log, agent, agentVersion, ullm }) => ({
      id, kind, result: r, pass, fail, skip, duration_s, log,
      ...(typeof agent === "string" ? { agent, ...(agentVersion ? { agentVersion } : {}), ...(ullm ? { ullm } : {}) } : {}),
    })),
  };
}

/** The commit id: --commit as given, else HEAD, with +dirty when the tree has changes. */
export function resolveCommit(root, given) {
  if (given) return given;
  const head = git(root, ["rev-parse", "HEAD"]);
  if (!head) return null;
  let dirty = false;
  try {
    dirty = execFileSync("git", ["status", "--porcelain", "--untracked-files=normal"], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() !== "";
  } catch { /* treat as clean */ }
  return dirty ? `${head}+dirty` : head;
}

export const COMMIT_RE = /^[0-9a-f]{7,64}(\+dirty)?$/;
export const ID_RE = /^[A-Za-z0-9._:-]{1,120}$/;

/** The default run id: local-<UTC yyyymmddThhmmssZ>-<short sha>. */
export function defaultRunId(commit, now = Date.now()) {
  return `local-${iso(now).replace(/[-:]/g, "")}-${commit.replace(/\+dirty$/, "").slice(0, 12)}`;
}

// ── CLI ────────────────────────────────────────────────────────────────────────

const OPTIONS = {
  kind: { type: "string" }, frozen: { type: "boolean" }, only: { type: "string" }, jobs: { type: "string" }, "kernel-jobs": { type: "string" }, costs: { type: "string" },
  sandbox: { type: "string" },
  out: { type: "string" }, "keep-results": { type: "string" }, "keep-results-hours": { type: "string" }, "run-id": { type: "string" }, source: { type: "string" }, commit: { type: "string" },
  ref: { type: "string" }, image: { type: "string" }, "stages-json": { type: "string" },
  "strict-skips": { type: "boolean" }, "include-flaky": { type: "boolean" }, "include-internet": { type: "boolean" },
  "flaky-kinds": { type: "string" }, need: { type: "string" }, lane: { type: "string" }, agents: { type: "string" }, drills: { type: "string" },
  "replay-store": { type: "string" }, "replay-baselines": { type: "string" }, "watch-store": { type: "string" },
  "replay-baselines-seed": { type: "string" }, "replay-baseline-mode": { type: "string" }, "replay-blocking": { type: "boolean" },
  "tmp-leftovers": { type: "string" }, "failures-only": { type: "boolean" }, "fail-tail": { type: "string" },
  "fail-fast": { type: "boolean" }, "dry-run": { type: "boolean" }, help: { type: "boolean", short: "h" },
  deadline: { type: "string" }, heartbeat: { type: "string" },
};

const USAGE = `usage: node scripts/run-suites.mjs --kind <k,k> [--frozen] [--only <id,id>] [--jobs N] [--kernel-jobs N] [--sandbox <wrapper>]
         [--costs FILE] [--out DIR | --keep-results N|all [--keep-results-hours H]] [--run-id ID] [--source local|gitlab]
         [--commit SHA] [--ref REF] [--image NAME] [--stages-json FILE] [--strict-skips] [--include-flaky]
         [--flaky-kinds <k,k>] [--include-internet]
         [--lane ${CREDENTIALS.join("|")}] [--need <n>] [--agents <${AGENTS.join(",")}>] [--drills <id,id>]
         [--replay-store DIR] [--replay-baselines DIR] [--replay-baselines-seed DIR] [--replay-baseline-mode MODE]
         [--replay-blocking] [--watch-store DIR] [--tmp-leftovers fail|warn] [--failures-only] [--fail-tail N]
         [--fail-fast] [--deadline EPOCH_S] [--heartbeat S] [--dry-run]
kinds:${KINDS.join(", ")}  (--frozen adds the frozen lane; --only selects ids, '*' allowed, whatever their kind;
       --drills alone = the drill catalog's live-drill entries)`;

/**
 * --failures-only's one counts line: the run's verdict and its counts, e.g.
 * `FAILURES PRESENT: 1 failed, 12 passed, 3 skipped of 16 entries (2 excluded)`.
 * A failure is any result but pass and skip (fail, timeout, error); the
 * non-blocking ones (flaky, reported, nightly) among them are said.
 */
export function countsLine(summary, results, { notRun = 0, excluded = 0, runError = null, C = { g: "", r: "", b: "", x: "" } } = {}) {
  const n = (k) => results.filter((r) => r.result === k).length;
  const pass = n("pass");
  const skip = n("skip");
  const failed = results.length - pass - skip;
  const nonBlocking = results.filter((r) => r.nonBlocking && r.result !== "pass" && r.result !== "skip").length;
  const verdict = summary.result === "pass" ? `${C.g}${C.b}ALL SUITES GREEN${C.x}`
    : `${C.r}${C.b}${summary.result === "error" ? `RUN ERROR (${runError ?? "a stage errored"})` : "FAILURES PRESENT"}${C.x}`;
  const parts = [`${failed} failed${nonBlocking ? ` (${nonBlocking} non-blocking)` : ""}`, `${pass} passed`, `${skip} skipped`];
  if (notRun) parts.push(`${notRun} not run`);
  const total = results.length + notRun;
  return `${verdict}: ${parts.join(", ")} of ${total} entr${total === 1 ? "y" : "ies"}${excluded ? ` (${excluded} excluded)` : ""}`;
}

function git(root, args) {
  try { return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null; } catch { return null; }
}

// `platform` (default the host's) is the one the plan is selected for; a
// test pins it so a dry run reads the same on every host.
export async function main(argv = process.argv.slice(2), { root = REPO_ROOT, stdout = process.stdout, stderr = process.stderr, env = process.env, platform = process.platform } = {}) {
  const say = (s = "") => stdout.write(`${s}\n`);
  let opts;
  try { opts = parseArgs({ args: argv, options: OPTIONS, allowPositionals: false }).values; } catch (e) {
    stderr.write(`run-suites: ${e.message}\n${USAGE}\n`); return 2;
  }
  if (opts.help) { say(USAGE); return 0; }
  const list = (v) => (v ? v.split(",").map((s) => s.trim()).filter(Boolean) : []);
  const drills = opts.drills != null ? list(opts.drills) : null;
  if (drills && !drills.length) { stderr.write("run-suites: --drills needs scenario ids (e.g. U7,C9)\n"); return 2; }
  const kinds = list(opts.kind);
  const frozen = !!opts.frozen;
  const only = list(opts.only);
  // --drills alone selects the drill catalog's entries (selectEntries).
  if (!kinds.length && !frozen && !only.length && !drills) { stderr.write(`run-suites: --kind (or --frozen, --only or --drills) is required\n${USAGE}\n`); return 2; }
  for (const k of kinds) if (!KINDS.includes(k)) { stderr.write(`run-suites: unknown kind '${k}'\n`); return 2; }
  const flakyKinds = list(opts["flaky-kinds"]);
  for (const k of flakyKinds) if (!KINDS.includes(k)) { stderr.write(`run-suites: unknown kind '${k}' in --flaky-kinds\n`); return 2; }
  const lane = opts.lane ?? null;
  if (lane !== null && !CREDENTIALS.includes(lane)) { stderr.write(`run-suites: --lane is ${CREDENTIALS.join(" or ")}\n`); return 2; }
  const agents = opts.agents != null ? list(opts.agents) : null;
  if (agents && !agents.length) { stderr.write(`run-suites: --agents needs one or more of ${AGENTS.join(", ")}\n`); return 2; }
  for (const a of agents ?? []) if (!AGENTS.includes(a)) { stderr.write(`run-suites: unknown agent '${a}' in --agents (${AGENTS.join(", ")})\n`); return 2; }
  const jobs = opts.jobs ? Number(opts.jobs) : 1;
  if (!Number.isInteger(jobs) || jobs < 1) { stderr.write("run-suites: --jobs must be a positive integer\n"); return 2; }
  const failuresOnly = !!opts["failures-only"];
  const failTail = opts["fail-tail"] != null ? Number(opts["fail-tail"]) : failuresOnly ? 40 : 25;
  if (opts["fail-tail"] === "" || !Number.isInteger(failTail) || failTail < 0) { stderr.write("run-suites: --fail-tail must be a number of lines (0 or more)\n"); return 2; }
  const kernelJobs = opts["kernel-jobs"] ? Number(opts["kernel-jobs"]) : 1;
  if (!Number.isInteger(kernelJobs) || kernelJobs < 1) { stderr.write("run-suites: --kernel-jobs must be a positive integer\n"); return 2; }
  const deadline = opts.deadline != null ? Number(opts.deadline) * 1000 : null;
  if (opts.deadline != null && (opts.deadline.trim() === "" || !Number.isFinite(deadline) || deadline <= 0)) { stderr.write("run-suites: --deadline must be a time in seconds since the epoch\n"); return 2; }
  const heartbeat = opts.heartbeat != null ? Number(opts.heartbeat) : 0;
  if (opts.heartbeat != null && (opts.heartbeat.trim() === "" || !Number.isInteger(heartbeat) || heartbeat < 0)) { stderr.write("run-suites: --heartbeat must be seconds (0: none)\n"); return 2; }
  // Read only without --out: a run with --out (CI's) never prunes.
  const keepRaw = opts["keep-results"] ?? env.MANDU_TEST_KEEP_RESULTS;
  const keep = opts.out ? Infinity : parseKeep(keepRaw);
  if (keep == null) { stderr.write(`run-suites: --keep-results (MANDU_TEST_KEEP_RESULTS) is a count of 1 or more, or all; not '${keepRaw}'\n`); return 2; }
  const graceRaw = opts["keep-results-hours"] ?? env.MANDU_TEST_KEEP_RESULTS_HOURS;
  const graceHours = opts.out ? 0 : parseGraceHours(graceRaw);
  if (graceHours == null) { stderr.write(`run-suites: --keep-results-hours (MANDU_TEST_KEEP_RESULTS_HOURS) is hours, 0 or more; not '${graceRaw}'\n`); return 2; }
  const source = opts.source ?? "local";
  if (!["local", "gitlab"].includes(source)) { stderr.write("run-suites: --source is local or gitlab\n"); return 2; }
  const sandbox = opts.sandbox ? resolve(opts.sandbox) : null;
  if (sandbox && !existsSync(sandbox)) { stderr.write(`run-suites: sandbox wrapper '${sandbox}' not found\n`); return 2; }
  if (opts["replay-baselines"] && !opts["replay-store"]) { stderr.write("run-suites: --replay-baselines needs --replay-store\n"); return 2; }
  if (opts["replay-baselines-seed"] && !opts["replay-store"]) { stderr.write("run-suites: --replay-baselines-seed needs --replay-store\n"); return 2; }
  if (opts["replay-baseline-mode"] && !opts["replay-store"]) { stderr.write("run-suites: --replay-baseline-mode needs --replay-store\n"); return 2; }
  if (opts["replay-blocking"] && !opts["replay-store"]) { stderr.write("run-suites: --replay-blocking needs --replay-store\n"); return 2; }
  if (opts["replay-baseline-mode"] && !BASELINE_MODES.includes(opts["replay-baseline-mode"])) {
    stderr.write(`run-suites: --replay-baseline-mode is one of ${BASELINE_MODES.join(", ")}\n`); return 2;
  }
  // The replay store (above); its run id is filled in once the run's is known.
  const replayOf = (runId) => {
    if (!opts["replay-store"]) return null;
    const host = replayHostPaths(env, env.HOME || homedir());
    const baselines = opts["replay-baselines"] ? resolve(opts["replay-baselines"]) : sandbox ? null : host.baselines;
    return {
      store: resolve(opts["replay-store"]), baselines, runId, perEntry: !!sandbox,
      ...(opts["replay-baselines-seed"] ? { seed: resolve(opts["replay-baselines-seed"]) } : {}),
      ...(opts["replay-baseline-mode"] ? { baselineMode: opts["replay-baseline-mode"] } : {}),
      ...(opts["replay-blocking"] ? { blocking: true } : {}),
    };
  };
  let stages = {};
  if (opts["stages-json"]) {
    try {
      const s = JSON.parse(readFileSync(opts["stages-json"], "utf8"));
      stages = s && typeof s.stages === "object" ? s.stages : s;
      if (!stages || typeof stages !== "object" || Array.isArray(stages)) throw new Error("not an object of stages");
      for (const [name, st] of Object.entries(stages)) {
        if (!ID_RE.test(name) || name === "suites") throw new Error(`stage name '${name}' (must match ${ID_RE}; 'suites' is this run's own)`);
        if (!st || !["pass", "fail", "skip", "timeout", "error"].includes(st.result)) throw new Error(`stage '${name}': result must be pass|fail|skip|timeout|error`);
        if (!(typeof st.duration_s === "number" && Number.isFinite(st.duration_s) && st.duration_s >= 0)) throw new Error(`stage '${name}': duration_s must be seconds`);
      }
    } catch (e) { stderr.write(`run-suites: --stages-json: ${e.message}\n`); return 2; }
  }

  const { entries } = await loadManifest({ root });
  const { selected: picked, excluded, unknown, unknownDrills } = selectEntries(entries, {
    kinds, frozen, only, platform,
    includeFlaky: !!opts["include-flaky"], includeInternet: !!opts["include-internet"],
    flakyKinds, lane, need: opts.need ?? null, agents, drills,
  });
  if (unknown.length) { stderr.write(`run-suites: no manifest entry matches: ${unknown.join(", ")}\n`); return 2; }
  if (unknownDrills.length) {
    const known = [...new Set(entries.filter(isDrill).flatMap((x) => x.select?.values ?? []))].sort();
    stderr.write(`run-suites: no drill runs ${unknownDrills.join(", ")}; the drill scenarios are: ${known.join(", ")}\n`);
    return 2;
  }
  const tmpMode = opts["tmp-leftovers"] ?? env.MANDU_TEST_TMP_LEFTOVERS ?? "fail";
  if (!TMP_MODES.includes(tmpMode)) { stderr.write(`run-suites: --tmp-leftovers (MANDU_TEST_TMP_LEFTOVERS) is ${TMP_MODES.join(" or ")}\n`); return 2; }
  if (opts["watch-store"] === "") { stderr.write("run-suites: --watch-store needs a directory\n"); return 2; }
  const watchStore = opts["watch-store"] ? resolve(opts["watch-store"]) : null;
  const selected = picked.map((x) => withWatchStore(x, env, env.HOME || homedir(), watchStore));
  if (selected.some(recordsLive)) {
    const store = watchStore ?? resolvePath("live-drill-runs", env, env.HOME || homedir());
    if (unusableWatchStore(store)) {
      stderr.write(`run-suites: the drill entries' watch store ${store} is under the pinned test home: their records would go nowhere; pass --watch-store <the caller's runs/drills/live>\n`);
    }
  }
  let costs;
  try {
    // --costs (the CI host's measured medians, continuous-integration.md §5.4)
    // over the checked-in tables: an entry it does not name keeps its table cost.
    costs = { ...loadAllCosts(root), ...(opts.costs ? loadCosts(resolve(opts.costs), { required: true }) : {}) };
  } catch (e) { stderr.write(`run-suites: ${e.message}\n`); return 2; }
  const phases = Object.fromEntries(Object.entries(planPhases(selected, { sandboxed: !!sandbox })).map(([k, xs]) => [k, orderByCost(xs, costs)]));

  const tty = stdout.isTTY && !env.NO_COLOR;
  const C = tty ? { g: "\x1b[32m", r: "\x1b[31m", y: "\x1b[33m", d: "\x1b[2m", b: "\x1b[1m", x: "\x1b[0m" } : { g: "", r: "", y: "", d: "", b: "", x: "" };

  // A temp dir short of inodes fails every entry's writes, each with its own
  // ENOSPC: say it once, first, with who fills it (test-organization.md §8.5.1;
  // MANDU_TMP_WARN_PERCENT, default 80).
  // Loaded lazily: a tree copied without tmp-gc.mjs (the CI and test-all
  // tests' throwaway repos) still runs, without the warning.
  const tmpGc = await import("./tmp-gc.mjs").catch(() => null);
  const tmpWarning = tmpGc?.inodeWarning(env.TMPDIR || tmpdir(), { percent: Number(env.MANDU_TMP_WARN_PERCENT || 80) });
  if (tmpWarning) stderr.write(`run-suites: ${tmpWarning}\n`);

  if (opts["dry-run"]) {
    const replay = replayOf(opts["run-id"] ?? "<run-id>");
    for (const [name, xs] of Object.entries(phases)) {
      say(`${name}:`);
      for (const x of xs) {
        say(`  ${x.id}  ${JSON.stringify(buildArgv(x, { root, sandbox, replay }).argv)}`);
        const plan = replayPlan(x, replay);
        if (plan && !(sandbox && !needsKernel(x))) say(`    env: ${Object.entries(plan.env).map(([k, v]) => `${k}=${v}`).join(" ")}`);
      }
    }
    for (const x of excluded) say(`excluded: ${x.id} (${x.reason})`);
    return 0;
  }

  const commit = resolveCommit(root, opts.commit);
  if (!commit || !COMMIT_RE.test(commit)) {
    stderr.write(`run-suites: ${commit ? `--commit '${commit}' is not a commit id (hex, 7-64, optional +dirty)` : "cannot resolve the commit (not a git checkout?): pass --commit"}\n`);
    return 2;
  }
  const runId = opts["run-id"] ?? defaultRunId(commit);
  if (!ID_RE.test(runId) || runId === "." || runId === "..") { stderr.write(`run-suites: --run-id '${runId}' must match ${ID_RE}\n`); return 2; }
  const replay = replayOf(runId);
  // Without --out, a fresh dir in the runner's tmpdir; the older ones of this
  // user pruned to the newest `keep` (above makeResultsDir). Never fatal.
  const outDir = opts.out ? resolve(opts.out) : makeResultsDir(env.TMPDIR || tmpdir());
  if (!opts.out) {
    try { pruneResultsDirs(dirname(outDir), { keep, graceMs: graceHours * 3600_000, self: outDir }); } catch (e) { stderr.write(`run-suites: could not prune the older results dirs: ${e.message}\n`); }
  }
  mkdirSync(join(outDir, "logs"), { recursive: true });
  const baseEnv = env;
  const ref = opts.ref ?? git(root, ["rev-parse", "--abbrev-ref", "HEAD"]) ?? "";
  const image = opts.image ?? null;
  // Each entry's own TMPDIR, under this run's directory (above runEntry): in
  // the runner's tmpdir, removed when the run ends (below), or by the exit
  // hook on an exit that does not get there.
  const runTmp = makeRunTmp(env.TMPDIR || tmpdir());
  let tmpSeq = 0;
  const dropRunTmp = () => { removeTree(runTmp); };
  process.once("exit", dropRunTmp);
  // The version of every agent a selected entry names, asked once (a CLI's
  // --version may write to TMPDIR: it gets one under this run's).
  const versions = new Map();
  const probeEnv = { ...baseEnv, TMPDIR: entryTmpDir(runTmp, tmpSeq++) };
  const home = env.HOME || homedir();
  for (const a of new Set(selected.flatMap((x) => [...namedAgents(x), ...(x.ullm ? [x.ullm] : [])]))) versions.set(a, probeAgentVersion(a, { env: withAgentPath([a], probeEnv, home) }));
  const withAgent = (x, r) => {
    if (x.agent == null) return r;
    r.agent = x.agent;
    if (typeof x.agent === "string" && versions.get(x.agent)) r.agentVersion = versions.get(x.agent);
    if (x.ullm) { r.ullm = x.ullm; if (versions.get(x.ullm)) r.ullmVersion = versions.get(x.ullm); }
    return r;
  };

  const started = Date.now();
  const results = [];
  let stop = false;
  let runError = null;
  const onSignal = (sig) => {
    stop = true;
    runError = `interrupted by ${sig}`;
    for (const pid of running) killGroup(pid, "SIGTERM");
  };
  const sigHandlers = { SIGINT: () => onSignal("SIGINT"), SIGTERM: () => onSignal("SIGTERM") };
  for (const [s, h] of Object.entries(sigHandlers)) process.on(s, h);

  const report = (r) => {
    // --failures-only: an entry that passed or skipped prints nothing here
    // (its warnings are counted in the summary's lines below).
    if (failuresOnly && (r.result === "pass" || r.result === "skip")) return;
    const label = r.id;
    const who = agentLabel(r);
    say(`${C.b}▶ ${label}${C.x}${who ? ` ${C.b}[${who}]${C.x}` : ""} ${C.d}(${r.argv.join(" ")})${C.x}`);
    const text = r.reason && r.result !== "pass" && r.result !== "skip" ? `${r.reason}; ${r.summary}` : r.summary;
    if (r.result === "pass") say(`  ${C.g}✓ PASS${C.x}  ${C.d}${text} (${r.duration_s}s)${C.x}`);
    else if (r.result === "skip") say(`  ${C.y}∅ SKIP${C.x}  ${C.d}${text} (${r.duration_s}s)${C.x}`);
    else {
      say(`  ${C.r}✗ FAIL${C.x}  ${C.d}${r.result === "fail" ? "" : `${r.result}: `}${text} (${r.duration_s}s)${C.x}`);
      if (failTail === 0) say(`  ${C.d}log: ${join(outDir, r.log)}${C.x}`);
      else {
        say(`  ${C.d}--- tail of ${join(outDir, r.log)} ---${C.x}`);
        for (const l of tailOf(join(outDir, r.log), failTail).split("\n")) say(`  ${l}`);
      }
    }
    if (r.strays && tmpMode === "warn") say(`  ${C.y}⚠ STRAYS${C.x}  ${C.d}${strayText(r.strays)}${C.x}`);
    if (r.tmpLeft && tmpMode === "warn") say(`  ${C.y}⚠ TMPDIR${C.x}  ${C.d}${leftoverText(r.tmpLeft)}${C.x}`);
    if (r.outside) say(`  ${C.y}⚠ OUTSIDE${C.x}  ${C.d}${outsideText(r.outside)}${C.x}`);
  };
  // The entries running now, for --heartbeat and the deadline's line.
  const active = new Map();
  const one = async (x) => {
    if (stop || (deadline != null && Date.now() >= deadline)) return null;
    const tmp = entryTmpDir(runTmp, tmpSeq++);
    const entryBase = withAgentPath(namedAgents(x), baseEnv, home);
    active.set(x.id, { started: Date.now(), timeout: x.timeout });
    let ran;
    try { ran = await runEntry(x, { root, outDir, sandbox, replay, strictSkips: !!opts["strict-skips"], tmp, tmpMode, baseEnv: entryBase, deadline }); }
    finally { active.delete(x.id); }
    const r = withAgent(x, ran);
    if (typeof x.agent === "string" && r.log) {
      let logged = null;
      try { logged = loggedAgentVersion(readForParse(join(outDir, r.log))); } catch { /* no log */ }
      if (logged) r.agentVersion = logged;
    }
    // A `flaky` entry runs but never blocks (test-organization.md §4), nor does
    // a `reported` or `nightly` one (test-reorganization.md §6.9): its red is
    // reported (the entry's own result) and left out of the run's result.
    if (nonBlocking(x)) r.nonBlocking = true;
    results.push(r);
    report(r);
    if (opts["fail-fast"] && !r.nonBlocking && r.result !== "pass" && r.result !== "skip") stop = true;
    return r;
  };
  const pool = async (xs, n) => {
    let i = 0;
    const worker = async () => { while (!stop && i < xs.length) await one(xs[i++]); };
    await Promise.all(Array.from({ length: Math.min(n, xs.length) }, worker));
  };

  say(`${C.b}run-suites${C.x} ${C.d}run ${runId}: ${selected.length} entries (kinds ${kinds.join(",") || "-"}${frozen ? " + frozen" : ""}${only.length ? `; only ${only.join(",")}` : ""}), jobs ${jobs}, kernel jobs ${kernelJobs}${sandbox ? `, sandbox ${sandbox}, kernel entries in the shared queue` : ""}${opts["strict-skips"] ? ", strict skips" : ""}${replay ? `, replay records in ${replay.store}${replay.perEntry ? "/<entry>" : ""}` : ""}${deadline != null ? `, deadline ${new Date(deadline).toISOString()} (in ${Math.round((deadline - Date.now()) / 1000)}s)` : ""}${heartbeat ? `, heartbeat every ${heartbeat}s` : ""}${C.x}`);
  // --deadline: from then on nothing starts; the running entries' own timers
  // (runEntry's entryLimit) stop them at the same moment.
  let deadlineTimer = null;
  if (deadline != null) {
    const reached = () => {
      if (stop) return;
      stop = true;
      runError = `deadline: the run's time was up at ${new Date(deadline).toISOString()} (--deadline); the entries still running were stopped as timeouts, the rest not run`;
      say(`${C.r}${C.b}⏰ deadline reached${C.x} ${C.d}(--deadline): stopping ${active.size ? [...active.keys()].join(", ") : "nothing running"}; no other entry starts${C.x}`);
    };
    if (deadline <= Date.now()) reached();
    else deadlineTimer = setTimeout(reached, deadline - Date.now());
  }
  const beat = heartbeat ? setInterval(() => { if (active.size) say(`${C.d}${heartbeatLine(active, { runStarted: started })}${C.x}`); }, heartbeat * 1000) : null;
  beat?.unref?.();
  // The sandboxed schedule (continuous-integration.md §5.4): one queue, longest
  // first, over jobs + kernelJobs slots. An entry starts in the first free
  // slot unless it is a kernel entry over the kernel cap; a non-parallel kernel
  // entry waits until no other kernel entry runs or waits.
  const shared = (xs, slots) => new Promise((done, fail) => {
    const queue = [...xs];
    let busy = 0;
    let kernelBusy = 0;
    const isKernel = needsKernel;
    const admit = (x) => {
      if (!isKernel(x)) return true;
      if (x.parallel === true) return kernelBusy < kernelJobs;
      return kernelBusy === 0 && !queue.some((y) => isKernel(y) && y.parallel === true);
    };
    const pump = () => {
      if (stop) queue.length = 0;
      while (busy < slots) {
        const i = queue.findIndex(admit);
        if (i < 0) break;
        const [x] = queue.splice(i, 1);
        busy++;
        if (isKernel(x)) kernelBusy++;
        one(x).then(() => { busy--; if (isKernel(x)) kernelBusy--; pump(); }, (e) => { stop = true; fail(e); });
      }
      if (busy === 0) done();
    };
    pump();
  });
  const kernelLane = async () => { await pool(phases.kernel, kernelJobs); await pool(phases.kernelSerial, 1); };
  if (sandbox) {
    await shared(sharedQueueOrder([...phases.parallel, ...phases.kernel, ...phases.kernelSerial], costs, { slots: jobs + kernelJobs, kernelJobs, isKernel: needsKernel }), jobs + kernelJobs);
    await pool(phases.serial, 1);
  } else {
    await pool(phases.parallel, jobs);
    await pool(phases.serial, 1);
    await kernelLane();
  }
  if (deadlineTimer) clearTimeout(deadlineTimer);
  if (beat) clearInterval(beat);
  for (const [s, h] of Object.entries(sigHandlers)) process.off(s, h);

  // Manifest order in the results, whatever order the pool finished in.
  const order = new Map(selected.map((x, i) => [x.id, i]));
  results.sort((a, b) => order.get(a.id) - order.get(b.id));
  const notRun = selected.filter((x) => !results.some((r) => r.id === x.id)).map((x) => x.id);
  const finished = Date.now();
  if (!selected.length) runError = "no entries selected";
  const summary = buildSummary({ run: runId, source, commit, ref, image, started, finished, stages, results, runError });
  writeFileSync(join(outDir, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
  writeFileSync(join(outDir, "junit.xml"), junitXml(results, outDir));

  say();
  say(`${C.b}══════════════════════ run-suites summary ══════════════════════${C.x}`);
  if (!failuresOnly) say(`  ${C.d}kinds: ${kinds.join(", ") || "(by id)"}${frozen ? " + frozen" : ""}${only.length ? `; only: ${only.join(", ")}` : ""}${C.x}`);
  if (!frozen && !failuresOnly) say(`  ${C.d}integrity lane: the FROZEN entries did not run (--frozen)${C.x}`);
  const entryOf = new Map(entries.map((y) => [y.id, y]));
  for (const x of failuresOnly ? [] : excluded) {
    const y = entryOf.get(x.id);
    const who = y?.agent != null ? ` [${agentLabel({ agent: y.agent, ullm: y.ullm })}]` : "";
    say(`  ${C.d}excluded: ${x.id}${who} — ${x.reason}${C.x}`);
  }
  const w = Math.max(26, ...results.map((r) => r.id.length));
  const aw = Math.max(0, ...results.map((r) => agentLabel(r).length));
  for (const r of results) {
    if (failuresOnly && (r.result === "pass" || r.result === "skip")) continue;
    const mark = r.result === "pass" ? `${C.g}✓${C.x}` : r.result === "skip" ? `${C.y}∅${C.x}` : `${C.r}✗${C.x}`;
    const who = aw ? `${agentLabel(r).padEnd(aw)} ` : "";
    say(`  ${mark}  ${r.id.padEnd(w)} ${who}${C.d}${r.result === "pass" ? "" : `${r.result}: `}${r.summary}${C.x}`);
  }
  for (const id of notRun) say(`  ${C.r}-${C.x}  ${id.padEnd(w)} ${C.d}not run (${runError ?? "--fail-fast"})${C.x}`);
  const matrix = agentMatrix(results);
  if (matrix) {
    say(`${C.b}─────────────────────────── by agent ──────────────────────────${C.x}`);
    for (const l of matrixText(matrix)) say(`  ${l}`);
    try { writeFileSync(join(outDir, "summary.md"), matrixMarkdown(matrix, { run: runId })); } catch (e) { stderr.write(`run-suites: could not write summary.md: ${e.message}\n`); }
  }
  say(`${C.b}───────────────────────────────────────────────────────────────${C.x}`);
  if (failuresOnly) say(`  ${countsLine(summary, results, { notRun: notRun.length, excluded: excluded.length, runError, C })}`);
  else if (summary.result === "pass") say(`  ${C.g}${C.b}ALL SUITES GREEN${C.x}`);
  else say(`  ${C.r}${C.b}${summary.result === "error" ? `RUN ERROR (${runError ?? "a stage errored"})` : "FAILURES PRESENT"}${C.x} — see the ✗ rows above`);
  const leaked = results.filter((r) => r.tmpLeft);
  if (leaked.length) {
    const what = leaked.map((r) => `${r.id} (${r.tmpLeft.names.length})`).join(", ");
    say(`  ${tmpMode === "fail" ? C.r : C.y}${leaked.length} entr${leaked.length === 1 ? "y" : "ies"} left files in their TMPDIR${tmpMode === "fail" ? "" : " (--tmp-leftovers warn: not a failure)"}: ${what}${C.x}`);
  }
  const strayed = results.filter((r) => r.strays);
  if (strayed.length) {
    const what = strayed.map((r) => `${r.id} (${r.strays.length})`).join(", ");
    say(`  ${tmpMode === "fail" ? C.r : C.y}${strayed.length} entr${strayed.length === 1 ? "y" : "ies"} left processes running outside their process group${tmpMode === "fail" ? "" : " (--tmp-leftovers warn: not a failure)"}: ${what}${C.x}`);
  }
  const outsiders = results.filter((r) => r.outside);
  if (outsiders.length) {
    const what = outsiders.map((r) => `${r.id} (${r.outside.length})`).join(", ");
    say(`  ${C.y}${outsiders.length} entr${outsiders.length === 1 ? "y" : "ies"} saw new files outside their TMPDIR (/tmp, $HOME, the runtime dir; a warning, see each log's [run-suites] outside line): ${what}${C.x}`);
  }
  const kept = opts.out ? "" : keep === Infinity ? "; every such dir kept" : `; the newest ${keep} such dirs and those of the last ${graceHours}h kept, --keep-results`;
  say(`  ${C.d}results: ${outDir} (summary.json${matrix ? ", summary.md" : ""}, junit.xml, logs/${kept})${C.x}`);
  process.off("exit", dropRunTmp);
  if (!removeTree(runTmp)) stderr.write(`run-suites: could not remove the run's TMPDIRs ${runTmp}\n`);
  return summary.result === "pass" ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(isAbsolute(process.argv[1]) ? process.argv[1] : resolve(process.argv[1])).href) {
  main().then((rc) => { process.exitCode = rc; }, (e) => { process.stderr.write(`run-suites: ${e?.stack ?? e}\n`); process.exitCode = 2; });
}
