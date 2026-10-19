// timeout-report.mjs — what a timed-out test suite was still running, read off
// /proc before the kill (docs/design/testing/test-organization.md §5). Node builtins
// only, no repository imports.
//
// COPIED VERBATIM: scripts/lib/timeout-report.mjs is the source, used by
// scripts/run-suites.mjs; the developer view's timeout-report.mjs is a
// byte-identical copy for the dashboard's test runner (dashboard.md §4.10),
// which ships standalone. scripts/test/run-suites.test.mjs fails on a drift:
// edit this file, then copy it over the dashboard's.
//
// node's test runner prints each file's results in argument order, so a log that
// stops at file N says nothing about which later file hung (pipeline 7777: the
// hung arbiter file had to be inferred from where the TAP stopped). At the
// deadline, before the SIGTERM, the runner therefore snapshots the suite's
// processes from /proc: node's runner spawns one child per test file whose argv
// names that file, so the files still running are read off the live tree, with
// every process under them (pid, age, argv). The log adds what it can (a TAP
// subtest opened and never closed, libtest's "has been running for over"). A
// suite that is neither node nor cargo still gets the process list.

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, readlinkSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";

const TEST_FILE_RE = /(?:^|\/)[^/\s]+[._-](?:test|spec)\.[cm]?[jt]sx?$/;
const CARGO_TEST_BIN_RE = /\/target\/[^/]+\/deps\/([^/]+)-[0-9a-f]{16}$/;
const REPORT_MAX_PROCS = 200;
const REPORT_ARGV_MAX = 400;

const stripAnsi = (s) => s.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "");

/** One /proc/<pid>/stat line → { pid, ppid, pgid, startTicks } (comm may hold spaces and parens). */
export function parseProcStat(text) {
  const close = text.lastIndexOf(")");
  if (close < 0) return null;
  const pid = Number(text.slice(0, text.indexOf(" ")));
  const f = text.slice(close + 2).trim().split(/\s+/);
  const ppid = Number(f[1]);
  const pgid = Number(f[2]);
  const startTicks = Number(f[19]);
  if (![pid, ppid, pgid, startTicks].every(Number.isFinite)) return null;
  return { pid, ppid, pgid, startTicks };
}

let clkTck = null;
function clockTicks() {
  if (clkTck == null) {
    try { clkTck = Number(execFileSync("getconf", ["CLK_TCK"], { encoding: "utf8" }).trim()) || 100; } catch { clkTck = 100; }
  }
  return clkTck;
}

/**
 * Every process /proc shows: { pid, ppid, pgid, age_s, argv, cwd }. A process
 * that exits mid-walk, or one /proc will not show (hidepid, another user), is
 * left out; with no /proc at all the table is empty.
 */
export function readProcTable(procRoot = "/proc") {
  let names;
  let uptime;
  try {
    names = readdirSync(procRoot).filter((n) => /^\d+$/.test(n));
    uptime = Number(readFileSync(join(procRoot, "uptime"), "utf8").split(" ")[0]);
  } catch { return []; }
  const hz = clockTicks();
  const table = [];
  for (const n of names) {
    try {
      const st = parseProcStat(readFileSync(join(procRoot, n, "stat"), "utf8"));
      if (!st) continue;
      const argv = readFileSync(join(procRoot, n, "cmdline"), "utf8").split("\0");
      if (argv.at(-1) === "") argv.pop();
      let cwd = null;
      try { cwd = readlinkSync(join(procRoot, n, "cwd")); } catch { /* not ours to read */ }
      table.push({ pid: st.pid, ppid: st.ppid, pgid: st.pgid, age_s: Math.max(0, Math.round(uptime - st.startTicks / hz)), argv, cwd });
    } catch { /* gone */ }
  }
  return table;
}

/**
 * The suite's processes, as a tree in pre-order: the root and its descendants
 * (by ppid; a sandbox's new session is still a descendant), then any process
 * left in the suite's process group that no longer descends from it (an
 * orphan reparented to init). Each gets its `depth`.
 */
export function suiteProcesses(table, rootPid) {
  const kids = new Map();
  for (const p of table) {
    if (!kids.has(p.ppid)) kids.set(p.ppid, []);
    kids.get(p.ppid).push(p);
  }
  for (const list of kids.values()) list.sort((a, b) => a.pid - b.pid);
  const out = [];
  const seen = new Set();
  const walk = (p, depth) => {
    if (seen.has(p.pid)) return;
    seen.add(p.pid);
    out.push({ ...p, depth });
    for (const c of kids.get(p.pid) ?? []) walk(c, depth + 1);
  };
  const root = table.find((p) => p.pid === rootPid);
  if (root) walk(root, 0);
  for (const p of table.filter((q) => q.pgid === rootPid && !seen.has(q.pid)).sort((a, b) => a.pid - b.pid)) walk(p, 0);
  return out;
}

/** A path for the report: repo-relative when it lies under `root`, resolved against the process's cwd. */
function displayPath(file, cwd, root) {
  const abs = isAbsolute(file) ? file : cwd ? resolve(cwd, file) : null;
  if (abs && root && (abs === root || abs.startsWith(root + "/"))) return relative(root, abs);
  return abs ?? file;
}

/**
 * The test files (or cargo test binaries) the processes are still running. A
 * node test runner's per-file child names exactly one test file and no
 * `--test`; the runner itself (`node --test a b c`, tsx's re-exec) names them
 * all and is skipped unless it names one (a one-file suite, or --test-isolation=none).
 */
export function runningTestFiles(procs, { root = null } = {}) {
  const files = [];
  const add = (f) => { if (!files.includes(f)) files.push(f); };
  const runners = [];
  for (const p of procs) {
    const cargo = CARGO_TEST_BIN_RE.exec(p.argv[0] ?? "");
    if (cargo) { add(`cargo test binary ${cargo[1]}`); continue; }
    // An argument with whitespace is a command line (`bash -c "… x.test.ts"`,
    // a docker-mode container's init), not a file: never named.
    const named = p.argv.slice(1).filter((a) => !/\s/.test(a) && TEST_FILE_RE.test(a));
    if (named.length === 0) continue;
    if (p.argv.includes("--test")) { runners.push({ p, named }); continue; }
    if (named.length === 1) add(displayPath(named[0], p.cwd, root));
  }
  if (files.length === 0) {
    for (const { p, named } of runners) if (named.length === 1) add(displayPath(named[0], p.cwd, root));
  }
  return files;
}

/**
 * What the log says is unfinished: TAP subtests opened (`# Subtest: x`) and
 * never closed by an `ok`/`not ok` at their indentation (as a path, outer >
 * inner), and libtest tests reported "has been running for over 60 seconds"
 * with no result line after.
 */
export function openTestsInLog(raw) {
  const lines = stripAnsi(raw).split(/\r?\n/);
  const stack = [];
  const slow = new Set();
  for (const l of lines) {
    const s = /^( *)# Subtest: (.*)$/.exec(l);
    if (s) {
      const ind = s[1].length;
      while (stack.length && stack[stack.length - 1].ind >= ind) stack.pop();
      stack.push({ ind, name: s[2] });
      continue;
    }
    const r = /^( *)(?:not )?ok \d+ - (.*?)(?: # (?:SKIP|TODO).*)?$/.exec(l);
    if (r) {
      const ind = r[1].length;
      while (stack.length && stack[stack.length - 1].ind > ind) stack.pop();
      if (stack.length && stack[stack.length - 1].ind === ind) stack.pop();
      continue;
    }
    const over = /^test (\S+) has been running for over \d+ seconds/.exec(l);
    if (over) { slow.add(over[1]); continue; }
    const done = /^test (\S+) \.\.\. /.exec(l);
    if (done) slow.delete(done[1]);
  }
  const out = [];
  if (stack.length) out.push(stack.map((x) => x.name).join(" > "));
  for (const t of slow) out.push(t);
  return out;
}

/**
 * The report a timeout writes into the suite's log before the SIGTERM (pure:
 * the process snapshot and the log text are inputs). Every line starts with
 * `[<tag>]`. Returns { lines, hung }, `hung` being the test files still
 * running, or failing that the log's open tests, for the run's reason.
 */
export function timeoutReport({ timeoutS, rootPid, table, logText = "", root = null, tag = "run-suites" }) {
  const procs = suiteProcesses(table, rootPid);
  const files = runningTestFiles(procs, { root });
  const open = openTestsInLog(logText);
  const L = [`[${tag}] timeout after ${timeoutS}s: the suite's processes at the deadline, before the SIGTERM`];
  if (procs.length === 0) L.push(`[${tag}]   (none visible: /proc unreadable, or the suite already gone)`);
  else {
    L.push(`[${tag}]   pid       age  argv`);
    for (const p of procs.slice(0, REPORT_MAX_PROCS)) {
      const argv = p.argv.join(" ");
      const cut = argv.length > REPORT_ARGV_MAX ? `${argv.slice(0, REPORT_ARGV_MAX)}…` : argv;
      L.push(`[${tag}]   ${String(p.pid).padEnd(8)} ${`${p.age_s}s`.padStart(5)}  ${"  ".repeat(p.depth)}${cut || "(no argv)"}`);
    }
    if (procs.length > REPORT_MAX_PROCS) L.push(`[${tag}]   … ${procs.length - REPORT_MAX_PROCS} more`);
  }
  L.push(`[${tag}] still running: ${files.length ? files.join(", ") : "(no test file named by a process)"}`);
  if (open.length) L.push(`[${tag}] unfinished in the log: ${open.join("; ")}`);
  return { lines: L, hung: files.length ? files : open };
}

/** A timed-out run's reason: the limit, then what was still running (three names at most). */
export function timeoutReason(timeoutS, hung = []) {
  const base = `timed out after ${timeoutS}s`;
  if (!hung.length) return base;
  const shown = hung.slice(0, 3).join(", ");
  return `${base}; still running: ${shown}${hung.length > 3 ? ` (+${hung.length - 3} more)` : ""}`;
}
