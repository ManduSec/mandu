// run-suites.test.mjs — the manifest runner (scripts/run-suites.mjs,
// docs/design/testing/test-organization.md §5, continuous-integration.md §5–§6): count
// parsing on real output shapes, selection and ordering, the sandbox argv, the
// timeout's process-group kill, the results files (validated against the rules
// the dashboard's CI reader enforces, the developer view's ci-runs.ts), strict skips
// and the log cap. Pure node, no network, no privilege.

import { spawn } from "node:child_process";
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  FIXED_ENV, buildArgv, buildSummary, capLog, classify, defaultRunId, junitXml, main, openTestsInLog, parseCounts, parseProcStat,
  readProcTable, resolveCommit, runningTestFiles, suiteProcesses, timeoutReason, timeoutReport, unusableWatchStore, withWatchStore,
  entryEnv, replayPlan, replayHostPaths, REPLAY_VARS, TSX_CACHE, entryTmpDir, leftoverText, makeRunTmp, removeTree, runEntry, tmpLeftovers,
  ENTRY_MARK, entryStrays, newOutside, outsideRoots, outsideText, procStartTicks, snapshotRoots, strayText, subreaperBinary,
  needsShortTmpdir, DARWIN_TMPDIR_MAX, agentBin, agentLabel, parseVersion, probeAgentVersion, countsLine,
  agentMatrix, matrixCell, matrixMarkdown, matrixRow, matrixText, CACHED_AGENTS, agentCacheBins, withAgentPath, loggedAgentVersion,
  entryLimit, heartbeatLine, parseKeep, parseGraceHours, RESULTS_GRACE_HOURS, RESULTS_KEEP, RESULTS_OWNER, RESULTS_PREFIX, makeResultsDir, pruneResultsDirs, resultsOwnerLive,
} from "../run-suites.mjs";
import { entryAgents, narrowSelect, planPhases, selectEntries } from "../suites.mjs";
import { devViewFile } from "../dev-view.mjs";

// ── the dashboard's summary.json rules (the developer view's ci-runs.ts validateSummary) ──
const ID_RE = /^[A-Za-z0-9._:-]{1,120}$/;
const COMMIT_RE = /^[0-9a-f]{7,64}(\+dirty)?$/;
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const UNSAFE = /[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/;
const TOP = ["schema", "kind", "run", "source", "commit", "ref", "image", "started", "finished", "result", "reason", "stages", "entries"];
const TOP_REQ = ["schema", "kind", "run", "source", "commit", "ref", "started", "finished", "result", "entries"];
const ENTRY = ["id", "kind", "result", "pass", "fail", "skip", "duration_s", "log", "agent", "agentVersion", "ullm"];
const ENTRY_OPTIONAL = ["log", "agent", "agentVersion", "ullm"];
const ENTRY_RESULTS = ["pass", "fail", "skip", "timeout", "error"];

function validateSummary(o, dirName) {
  const bad = (why) => { throw new Error(`summary invalid: ${why}`); };
  const keys = (x, allowed, req, where) => {
    for (const k of Object.keys(x)) if (!allowed.includes(k)) bad(`${where}: unknown field ${k}`);
    for (const k of req) if (!(k in x)) bad(`${where}: missing ${k}`);
  };
  const id = (v, w) => { if (typeof v !== "string" || !ID_RE.test(v) || v === "." || v === "..") bad(`${w}: not an id`); };
  const count = (v, w) => { if (!Number.isSafeInteger(v) || v < 0) bad(`${w}: not a count`); };
  const secs = (v, w) => { if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 1e7) bad(`${w}: not a duration`); };
  const text = (v, max, w) => { if (typeof v !== "string" || v.length > max || UNSAFE.test(v)) bad(`${w}: bad text`); };
  keys(o, TOP, TOP_REQ, "summary");
  if (o.schema !== 1) bad("schema");
  if (o.kind !== "mandu-ci-run") bad("kind");
  id(o.run, "run");
  if (dirName !== undefined && o.run !== dirName) bad("run != dir");
  if (!["gitlab", "local"].includes(o.source)) bad("source");
  if (!COMMIT_RE.test(o.commit)) bad("commit");
  text(o.ref, 255, "ref");
  for (const t of ["started", "finished"]) if (!TIME_RE.test(o[t]) || !Number.isFinite(Date.parse(o[t]))) bad(t);
  if (!["pass", "fail", "error"].includes(o.result)) bad("result");
  if ("image" in o) text(o.image, 200, "image");
  if ("reason" in o) text(o.reason, 2000, "reason");
  if ("stages" in o) {
    for (const [n, st] of Object.entries(o.stages)) {
      id(n, "stage");
      keys(st, ["result", "duration_s"], ["result", "duration_s"], `stages.${n}`);
      if (!ENTRY_RESULTS.includes(st.result)) bad(`stages.${n}.result`);
      secs(st.duration_s, `stages.${n}.duration_s`);
    }
  }
  const seen = new Set();
  for (const [i, e] of o.entries.entries()) {
    keys(e, ENTRY, ENTRY.filter((k) => !ENTRY_OPTIONAL.includes(k)), `entries[${i}]`);
    for (const k of ["agent", "ullm"]) if (k in e && !/^[a-z][a-z0-9-]{0,39}$/.test(e[k])) bad(`entry ${k}`);
    if ("agentVersion" in e && !/^[0-9][0-9A-Za-z.+-]{0,63}$/.test(e.agentVersion)) bad("entry agentVersion");
    if (("agentVersion" in e || "ullm" in e) && !("agent" in e)) bad("agentVersion / ullm without agent");
    id(e.id, "entry id"); id(e.kind, "entry kind");
    if (!ENTRY_RESULTS.includes(e.result)) bad("entry result");
    count(e.pass, "pass"); count(e.fail, "fail"); count(e.skip, "skip"); secs(e.duration_s, "duration_s");
    if ("log" in e && e.log !== `logs/${e.id}.log`) bad("entry log");
    if (seen.has(e.id)) bad("duplicate entry");
    seen.add(e.id);
  }
  return true;
}

// ── count parsing, on the output shapes the suites really print ────────────────

test("parseCounts: node:test TAP footer (tsx --test, non-TTY)", () => {
  const out = "ok 12 - x\n  ---\n  duration_ms: 2.7\n  ...\n1..12\n# tests 12\n# suites 0\n# pass 12\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 523.6\n";
  assert.deepEqual(pick(parseCounts(out)), { format: "node", pass: 12, fail: 0, skip: 0 });
});

test("parseCounts: TAP footers of several runs sum; cancelled counts as failed, todo as skipped", () => {
  const run = (p, f, c, s, t) => `# tests ${p + f}\n# pass ${p}\n# fail ${f}\n# cancelled ${c}\n# skipped ${s}\n# todo ${t}\n`;
  const out = `${run(3, 0, 0, 1, 0)}noise\n${run(2, 1, 1, 0, 2)}`;
  assert.deepEqual(pick(parseCounts(out)), { format: "node", pass: 5, fail: 2, skip: 3 });
});

test("parseCounts: node:test spec reporter footer", () => {
  const out = "✔ a (1ms)\nℹ tests 4\nℹ suites 0\nℹ pass 3\nℹ fail 0\nℹ cancelled 0\nℹ skipped 1\nℹ todo 0\nℹ duration_ms 40\n";
  assert.deepEqual(pick(parseCounts(out)), { format: "node", pass: 3, fail: 0, skip: 1 });
});

test("parseCounts: an indented subtest line is not a footer", () => {
  const out = "    # pass 99\n# pass 1\n# fail 0\n";
  assert.equal(parseCounts(out).pass, 1);
});

test("parseCounts: the eval's deterministic CLI footer", () => {
  assert.deepEqual(pick(parseCounts("…\n# tests 40\n# pass 40\n# fail 0\n")), { format: "node", pass: 40, fail: 0, skip: 0 });
});

test("parseCounts: cargo test result lines sum across crates; ignored counts as skipped", () => {
  const out = [
    "running 12 tests", "test result: ok. 12 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; finished in 0.02s",
    "", "running 0 tests", "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
    "test result: FAILED. 4 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.10s",
  ].join("\n");
  assert.deepEqual(pick(parseCounts(out)), { format: "cargo", pass: 16, fail: 1, skip: 3 });
});

test("parseCounts: kernel-tests.sh echoes cargo counts; a test's SKIP: line is a skip, not a pass", () => {
  const out = [
    "▶ fs-supervisor (unshare --user … -- cargo test -p fs-supervisor --features kernel -- --include-ignored)",
    "test result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.2s",
    "SKIP: seccomp ADDFD redirect needs kernel >= 5.9; this kernel is 5.4",
    "  ✓ PASS  29 passed; 1 kernel-version SKIP (seccomp ADDFD redirect needs kernel >= 5.9)",
    "kernel-tests.sh: 3 passed, 0 failed",
  ].join("\n");
  assert.deepEqual(pick(parseCounts(out)), { format: "cargo", pass: 29, fail: 0, skip: 1 });
});

test("parseCounts: kernel-tests.sh on a host without unprivileged userns: every crate SKIPPED", () => {
  const out = [
    "unprivileged user namespaces are unavailable on this host",
    "  ∅ SKIP  no unprivileged userns (Tier 1 unavailable)",
    "  ∅ SKIP  no unprivileged userns (Tier 1 unavailable)",
    "  ∅ SKIP  no unprivileged userns (Tier 1 unavailable)",
    "kernel-tests.sh: 3 suite(s) SKIPPED (userns/prereq unavailable — counts green)",
    "kernel-tests.sh: 0 passed, 0 failed",
  ].join("\n");
  assert.deepEqual(pick(parseCounts(out)), { format: "shell", pass: 0, fail: 0, skip: 3 });
});

test("parseCounts: shell footers — counted, skipped whole, 'N skipped', ANSI-coloured", () => {
  assert.deepEqual(pick(parseCounts("  ok — a\nnet-proxy-live.test.sh: 5 passed, 0 failed\n")), { format: "shell", pass: 5, fail: 0, skip: 0 });
  assert.deepEqual(pick(parseCounts("SKIP: curl not on PATH\nnet-proxy-live.test.sh: 0 passed, 0 failed (skipped)\n")), { format: "shell", pass: 0, fail: 0, skip: 1 });
  assert.deepEqual(pick(parseCounts("secret-readers-live.test.sh: SKIP (no bwrap)\n1 skipped, 0 failed\n")), { format: "shell", pass: 0, fail: 0, skip: 1 });
  assert.deepEqual(pick(parseCounts("\n  \x1b[32m7 passed, 0 failed\x1b[0m\n")), { format: "shell", pass: 7, fail: 0, skip: 0 });
  // the LAST footer wins (a script that prints a partial tally first)
  assert.deepEqual(pick(parseCounts("x: 1 passed, 0 failed\nx: 4 passed, 2 failed\n")), { format: "shell", pass: 4, fail: 2, skip: 0 });
});

test("parseCounts: nothing recognizable", () => {
  const c = parseCounts("hello\nworld\n");
  assert.equal(c.format, null);
  assert.match(c.summary, /no test counts/);
});

// ── classification and strict skips ────────────────────────────────────────────

test("classify: exit code, counts, timeout, spawn error", () => {
  const e = { id: "x", timeout: 5 };
  const c = (pass, fail, skip) => ({ pass, fail, skip });
  assert.equal(classify(e, { code: 0, counts: c(3, 0, 0) }).result, "pass");
  assert.equal(classify(e, { code: 1, counts: c(3, 0, 0) }).result, "fail");
  assert.equal(classify(e, { code: 0, counts: c(3, 1, 0) }).result, "fail");
  assert.equal(classify(e, { code: 0, counts: c(0, 0, 2) }).result, "skip");
  assert.equal(classify(e, { code: 0, counts: c(0, 0, 0) }).result, "pass");
  assert.equal(classify(e, { code: null, timedOut: true, counts: c(0, 0, 0) }).result, "timeout");
  assert.equal(classify(e, { code: null, spawnError: "ENOENT", counts: c(0, 0, 0) }).result, "error");
});

test("classify: --strict-skips fails an entry whose skips exceed ci.maxSkip, or passes under ci.minPass", () => {
  const k = { id: "k", timeout: 5, ci: { maxSkip: 0, minPass: 1 } };
  const skipped = { code: 0, counts: { pass: 0, fail: 0, skip: 3 } };
  assert.equal(classify(k, skipped).result, "skip", "without --strict-skips a skip is allowed");
  const r = classify(k, { ...skipped, strictSkips: true });
  assert.equal(r.result, "fail");
  assert.match(r.reason, /3 skipped, ci\.maxSkip is 0/);
  assert.match(classify(k, { code: 0, counts: { pass: 0, fail: 0, skip: 0 }, strictSkips: true }).reason, /ci\.minPass is 1/);
  assert.equal(classify(k, { code: 0, counts: { pass: 4, fail: 0, skip: 0 }, strictSkips: true }).result, "pass");
  assert.equal(classify({ id: "o", timeout: 5 }, { ...skipped, strictSkips: true }).result, "skip", "no ci: no count check");
});

// ── a timeout's report (test-organization.md §5) ───────────────────────────────

test("parseProcStat: a comm with spaces and parens; the fields after it", () => {
  const line = "4242 (node (x) y) S 4200 4100 4100 0 -1 4194560 1 0 0 0 5 1 0 0 20 0 11 0 987654 1000 99";
  assert.deepEqual(parseProcStat(line), { pid: 4242, ppid: 4200, pgid: 4100, startTicks: 987654 });
  assert.equal(parseProcStat("garbage"), null);
});

// The table is read from /proc: Linux only. macOS has no /proc, so there a
// suite timeout's report names no processes (the empty table below).
test("readProcTable: this process is in the table with its argv, cwd and an age", { skip: process.platform !== "linux" && "reads /proc (Linux only)" }, () => {
  const me = readProcTable().find((p) => p.pid === process.pid);
  assert.ok(me, "the test process reads itself from /proc");
  assert.equal(me.ppid, process.ppid);
  assert.ok(me.argv.some((a) => a.endsWith("run-suites.test.mjs")), JSON.stringify(me.argv));
  assert.equal(me.cwd, process.cwd());
  assert.ok(me.age_s >= 0);
});

test("readProcTable: no /proc is an empty table, no throw (macOS)", () => {
  assert.deepEqual(readProcTable("/nonexistent-proc"), [], "no /proc: an empty table, no throw");
});

// The process tree `tsx --test a b` left at a hang (its shape captured from node
// 22 on 2026-09-30), plus an orphan still in the entry's group and a process of
// another suite.
const P = (pid, ppid, pgid, argv, o = {}) => ({ pid, ppid, pgid, age_s: 5, argv, cwd: "/repo/arbiter", ...o });
const TSX = "/repo/arbiter/node_modules/.bin/tsx";
const LOADER = ["--require", "/repo/arbiter/node_modules/tsx/dist/preflight.cjs", "--import", "file:///repo/arbiter/node_modules/tsx/dist/loader.mjs"];
const HANG_TABLE = [
  P(1, 0, 1, ["/sbin/init"], { cwd: "/" }),
  P(100, 1, 100, ["npm", "test"]),
  P(110, 100, 100, ["node", TSX, "--test", "test/unit/a.test.ts", "test/component/b.test.ts"]),
  P(120, 110, 100, ["/usr/bin/node", ...LOADER, "--test", "test/unit/a.test.ts", "test/component/b.test.ts"]),
  P(130, 120, 100, ["/usr/bin/node", ...LOADER, "test/component/b.test.ts"]),
  P(140, 130, 100, ["/repo/arbiter/node_modules/@esbuild/linux-x64/bin/esbuild", "--service=0.28.1", "--ping"]),
  P(141, 130, 100, ["git", "index-pack", "--stdin"]),
  P(150, 1, 100, ["bwrap", "--unshare-net", "--", "git", "status"]),
  P(200, 1, 200, ["node", "--test", "other.test.mjs"]),
];

test("suiteProcesses: the root's descendants in pre-order with depth, then an orphan still in the group", () => {
  const got = suiteProcesses(HANG_TABLE, 100).map((p) => [p.pid, p.depth]);
  assert.deepEqual(got, [[100, 0], [110, 1], [120, 2], [130, 3], [140, 4], [141, 4], [150, 0]]);
  assert.deepEqual(suiteProcesses(HANG_TABLE, 999), [], "the entry already gone");
});

test("runningTestFiles: the per-file child names the hung file (repo-relative); the runners that name every file do not", () => {
  const procs = suiteProcesses(HANG_TABLE, 100);
  assert.deepEqual(runningTestFiles(procs, { root: "/repo" }), ["arbiter/test/component/b.test.ts"]);
  assert.deepEqual(runningTestFiles(procs, { root: "/elsewhere" }), ["/repo/arbiter/test/component/b.test.ts"], "outside the root: absolute");
  // A one-file suite (or --test-isolation=none): the runner itself is the only name.
  const one = [P(1, 0, 1, ["node", "--test", "x.spec.mjs"], { cwd: "/repo/pkg" })];
  assert.deepEqual(runningTestFiles(one, { root: "/repo" }), ["pkg/x.spec.mjs"]);
  // A cargo test binary names its crate; a shell suite names nothing.
  const cargo = [P(1, 0, 1, ["/repo/interceptors/target/debug/deps/fs_supervisor-0123456789abcdef", "--nocapture"])];
  assert.deepEqual(runningTestFiles(cargo, { root: "/repo" }), ["cargo test binary fs_supervisor"]);
  assert.deepEqual(runningTestFiles([P(1, 0, 1, ["bash", "scripts/test/x.sh"]), P(2, 1, 1, ["sleep", "60"])]), []);
  // A command line is not a file (a docker-mode container's init keeps its
  // `bash -c "… tsx --test x.test.ts"` for the whole run): never named.
  assert.deepEqual(runningTestFiles([P(1, 0, 1, ["/sbin/docker-init", "--", "bash", "-c", "cd tests && exec tsx --test stack/a.test.ts"], { cwd: "/repo" })], { root: "/repo" }), []);
});

test("openTestsInLog: a TAP subtest never closed, nested as a path; libtest's slow test with no result", () => {
  const tap = [
    "TAP version 13",
    "# Subtest: done",
    "ok 1 - done",
    "# Subtest: outer",
    "    # Subtest: inner ok",
    "    ok 1 - inner ok",
    "    # Subtest: inner hangs",
    "",
  ].join("\n");
  assert.deepEqual(openTestsInLog(tap), ["outer > inner hangs"]);
  assert.deepEqual(openTestsInLog("# Subtest: a\nnot ok 1 - a\n# Subtest: b\nok 2 - b # SKIP no userns\n"), []);
  const cargo = [
    "test guard::a ... ok",
    "test guard::slow has been running for over 60 seconds",
    "test guard::b has been running for over 60 seconds",
    "test guard::b ... ok",
  ].join("\n");
  assert.deepEqual(openTestsInLog(cargo), ["guard::slow"]);
});

test("timeoutReport: the process tree, the file still running, the log's open test; the reason names the file", () => {
  const entry = { id: "arbiter", timeout: 900 };
  const { lines, hung } = timeoutReport({ entry, rootPid: 100, table: HANG_TABLE, root: "/repo", logText: "# Subtest: outer\n" });
  const text = lines.join("\n");
  assert.match(lines[0], /timeout after 900s: the suite's processes at the deadline, before the SIGTERM/);
  assert.match(text, /^\[run-suites\] {3}130 +5s {8}\/usr\/bin\/node .* test\/component\/b\.test\.ts$/m, "indented by depth");
  assert.match(text, /^\[run-suites\] {3}141 +5s {10}git index-pack --stdin$/m, "the hung file's children are listed");
  assert.doesNotMatch(text, /other\.test\.mjs/, "another suite's process is not the entry's");
  assert.match(text, /^\[run-suites\] still running: arbiter\/test\/component\/b\.test\.ts$/m);
  assert.match(text, /^\[run-suites\] unfinished in the log: outer$/m);
  assert.deepEqual(hung, ["arbiter/test/component/b.test.ts"]);
  assert.equal(classify(entry, { code: null, timedOut: true, hung, counts: { pass: 0, fail: 0, skip: 0 } }).reason,
    "timed out after 900s; still running: arbiter/test/component/b.test.ts");
  // Nothing visible: said so, and the reason is the bare limit.
  const none = timeoutReport({ entry, rootPid: 100, table: [] });
  assert.match(none.lines.join("\n"), /none visible/);
  assert.deepEqual(none.hung, []);
  // No file named, but the log has an open test: that is what the reason carries.
  const shell = timeoutReport({ entry, rootPid: 1, table: [P(1, 0, 1, ["bash", "x.sh"])], logText: "# Subtest: stuck\n" });
  assert.match(shell.lines.join("\n"), /still running: \(no test file named by a process\)/);
  assert.deepEqual(shell.hung, ["stuck"]);
});

const TIMEOUT_REPORT_COPY = devViewFile("src/test-runs/timeout-report.mjs");
test("the developer view's copy of lib/timeout-report.mjs is byte-identical (dashboard.md §4.10)", { skip: TIMEOUT_REPORT_COPY === null && "no developer view in this checkout" }, () => {
  // The developer view's test runner ships standalone, so it carries a
  // verbatim copy; a drift would leave its timeout report reading /proc
  // differently.
  const here = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
  const master = readFileSync(join(here, "scripts", "lib", "timeout-report.mjs"), "utf8");
  assert.equal(readFileSync(TIMEOUT_REPORT_COPY, "utf8"), master,
    "the developer view's test-runs/timeout-report.mjs drifted from scripts/lib/timeout-report.mjs; copy the scripts/ file over it again");
});

test("timeoutReason: at most three names, then a count", () => {
  const e = { timeout: 5 };
  assert.equal(timeoutReason(e), "timed out after 5s");
  assert.equal(timeoutReason(e, ["a", "b", "c", "d", "e"]), "timed out after 5s; still running: a, b, c (+2 more)");
  assert.equal(timeoutReason({ timeout: 3600 }, ["cargo test binary guard_integration"], { deadlineAfterS: 2300 }),
    "stopped by the run's deadline (--deadline) after 2300s, before its own timeout of 3600s; still running: cargo test binary guard_integration");
  assert.equal(timeoutReason({ timeout: 3600 }, [], { deadlineAfterS: 12 }), "stopped by the run's deadline (--deadline) after 12s, before its own timeout of 3600s");
});

test("entryLimit: the entry's own timeout, or the run's deadline when that comes first", () => {
  const e = { timeout: 60 };
  assert.deepEqual(entryLimit(e, { now: 1000 }), { ms: 60_000, byDeadline: false });
  assert.deepEqual(entryLimit(e, { now: 1000, deadline: 1000 + 120_000 }), { ms: 60_000, byDeadline: false });
  assert.deepEqual(entryLimit(e, { now: 1000, deadline: 1000 + 5_000 }), { ms: 5_000, byDeadline: true });
  assert.deepEqual(entryLimit(e, { now: 9000, deadline: 1000 }), { ms: 0, byDeadline: true }, "a deadline already past fires at once");
});

test("heartbeatLine: every running entry, longest first, with its age and timeout", () => {
  const active = new Map([["a.quick", { started: 90_000, timeout: 600 }], ["rust.kernel", { started: 10_000, timeout: 1200 }]]);
  assert.equal(heartbeatLine(active, { now: 100_000, runStarted: 0 }),
    "… 100s into the run, still running: rust.kernel (90s of 1200s), a.quick (10s of 600s)");
});

// ── selection and order ────────────────────────────────────────────────────────

const E = (id, o = {}) => ({ id, kind: "unit", axis: "secrets", cwd: ".", cmd: ["true"], needs: [], timeout: 5, parallel: true, flaky: null, internet: false, platforms: ["linux"], env: {}, ...o });
const SAMPLE = [
  E("a"), E("b", { parallel: false }), E("c", { parallel: "sandbox" }),
  E("k1", { kind: "sandbox", needs: ["kernel"], parallel: false }), E("f", { flaky: { reason: "pty", since: "2026-09-28" } }),
  E("net", { internet: true }), E("mac", { platforms: ["darwin"] }), E("both", { platforms: ["linux", "darwin"] }),
  E("fr", { kind: "unit", frozen: true, axis: "full" }), E("af", { kind: "replay-drill" }),
];

test("selectEntries: by kind; flaky and internet stay out unless included; platforms filter; frozen never with its kind", () => {
  const { selected, excluded } = selectEntries(SAMPLE, { kinds: ["unit", "sandbox"], platform: "linux" });
  assert.deepEqual(selected.map((x) => x.id), ["a", "b", "c", "k1", "both"]);
  assert.deepEqual(excluded.map((x) => x.id).sort(), ["f", "mac", "net"]);
  const all = selectEntries(SAMPLE, { kinds: ["unit"], platform: "linux", includeFlaky: true, includeInternet: true });
  assert.deepEqual(all.selected.map((x) => x.id), ["a", "b", "c", "f", "net", "both"]);
  const mac = selectEntries(SAMPLE, { kinds: ["unit"], platform: "darwin" });
  assert.deepEqual(mac.selected.map((x) => x.id), ["mac", "both"]);
});

test("selectEntries: `frozen` adds every frozen entry, whatever its kind; alone it selects only them", () => {
  const S = [...SAMPLE, E("frd", { kind: "live-drill", frozen: true, axis: "full" })];
  assert.deepEqual(selectEntries(S, { frozen: true, platform: "linux" }).selected.map((x) => x.id), ["fr", "frd"]);
  assert.deepEqual(selectEntries(S, { kinds: ["replay-drill"], frozen: true, platform: "linux" }).selected.map((x) => x.id), ["fr", "af", "frd"]);
  assert.ok(!selectEntries(S, { kinds: ["unit", "live-drill"], platform: "linux" }).selected.some((x) => x.frozen), "a kinds run leaves the frozen lane out");
});

test("selectEntries `need`: keeps only the entries that need it, the rest excluded with the reason (the kernel lane)", () => {
  const r = selectEntries(SAMPLE, { kinds: ["unit", "sandbox", "replay-drill"], need: "kernel", platform: "linux" });
  assert.deepEqual(r.selected.map((x) => x.id), ["k1"]);
  assert.deepEqual(r.excluded.find((x) => x.id === "a"), { id: "a", reason: "does not need kernel (this run: --need kernel)" });
});

test("run-suites --need kernel: the kernel-linux-7 selection is every kernel-lane entry", async () => {
  const out = sink();
  // Planned for Linux on every host: the kernel lane is Linux's.
  assert.equal(await main(["--kind", "sandbox,component", "--need", "kernel", "--dry-run"], { stdout: out, stderr: sink(), platform: "linux" }), 0);
  assert.match(out.text, /^\s+rust\.kernel /m);
  assert.doesNotMatch(out.text, /^\s+launcher\.net-proxy-live /m, "an entry without the kernel need stays out");
  assert.match(out.text, /excluded: launcher\.net-proxy-live \(does not need kernel \(this run: --need kernel\)\)/);
});

test("run-suites says first when its temp dir is short of inodes, naming who fills it (MANDU_TMP_WARN_PERCENT)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "run-suites-inodes-"));
  try {
    mkdirSync(join(tmp, "mandu-filler", "a"), { recursive: true });
    const run = async (percent) => {
      const err = sink();
      const env = { ...process.env, TMPDIR: tmp, MANDU_TMP_WARN_PERCENT: percent };
      assert.equal(await main(["--kind", "unit", "--dry-run"], { stdout: sink(), stderr: err, env, platform: "linux" }), 0);
      return err.text;
    };
    assert.match(await run("0"), /^run-suites: WARNING: .* has used \d+% of its inodes .*mandu-filler 2/m);
    assert.doesNotMatch(await run("101"), /WARNING/);
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});

test("selectEntries: flakyKinds adds only the flaky entries of more kinds (the nightly's every flaky entry)", () => {
  const S = [...SAMPLE, E("aff", { kind: "replay-drill", flaky: { reason: "pty", since: "2026-09-28" } }),
    E("frf", { kind: "live-drill", frozen: true, axis: "full", flaky: { reason: "E25", since: "2026-09-29" } }),
    E("rm", { kind: "live-drill" }), E("rmf", { kind: "live-drill", internet: true, flaky: { reason: "latest", since: "2026-09-28" } })];
  const n = selectEntries(S, { kinds: ["live-drill"], platform: "linux", flakyKinds: ["unit", "replay-drill", "live-drill"] });
  assert.deepEqual(n.selected.map((x) => x.id), ["f", "aff", "rm"], "flaky entries of the named kinds join; none of their other entries; the frozen flaky one stays out");
  const withNet = selectEntries(S, { kinds: ["live-drill"], platform: "linux", includeInternet: true, flakyKinds: ["unit", "replay-drill", "live-drill"] });
  assert.deepEqual(withNet.selected.map((x) => x.id), ["f", "aff", "rm", "rmf"], "an internet flaky entry still needs includeInternet");
  assert.deepEqual(selectEntries(S, { kinds: ["live-drill"], platform: "linux" }).selected.map((x) => x.id), ["rm"]);
});

test("run-suites --flaky-kinds: an unknown kind is a usage error; the retired --tier / --flaky-tiers are refused", async () => {
  const err = sink();
  assert.equal(await main(["--kind", "unit", "--flaky-kinds", "unit,nope", "--dry-run"], { stdout: sink(), stderr: err }), 2);
  assert.match(err.text, /unknown kind .nope. in --flaky-kinds/);
  assert.equal(await main(["--tier", "offline", "--dry-run"], { stdout: sink(), stderr: sink() }), 2);
  assert.equal(await main(["--kind", "unit", "--flaky-tiers", "unit", "--dry-run"], { stdout: sink(), stderr: sink() }), 2);
});

test("run-suites --lane: subscription or api-key, anything else is a usage error; the dry run lists only that credential (continuous-integration.md §9.8)", async () => {
  for (const bad of ["nightly", "api"]) {
    const err = sink();
    assert.equal(await main(["--kind", "live-drill", "--lane", bad, "--dry-run"], { stdout: sink(), stderr: err }), 2, bad);
    assert.match(err.text, /--lane is subscription or api-key/);
  }
  const out = sink();
  assert.equal(await main(["--kind", "live-drill,env,eval", "--lane", "api-key", "--dry-run"], { stdout: out, stderr: sink() }), 0);
  assert.doesNotMatch(out.text, /^\s+integration\.local-model /m);
  assert.match(out.text, /excluded: integration\.local-model \(credential subscription \(this run: api-key\)\)/);
});

// ── --agents and --drills (test-organization.md §5) ────────────────────────────

const AGENT_SAMPLE = [
  E("plain", { kind: "live-drill" }),
  E("cc", { kind: "live-drill", needs: ["node", "claude", "claude-login"] }),
  E("cx", { kind: "live-drill", needs: ["node", "codex", "openai-api-key"] }),
  E("cxg", { kind: "live-drill", needs: ["node", "codex", "chatgpt-login"] }),
  E("cxu", { kind: "live-drill", needs: ["node", "codex", "chatgpt-login", "claude-login"] }),
  E("oc", { kind: "live-drill", needs: ["node", "openclaw", "opencode", "anthropic-api-key"] }),
];

test("entryAgents: an agent's CLI or its login names it; a key or a tool does not", () => {
  assert.deepEqual(AGENT_SAMPLE.map((x) => [x.id, entryAgents(x)]), [
    ["plain", []], ["cc", ["claude"]], ["cx", ["codex"]], ["cxg", ["codex"]], ["cxu", ["claude", "codex"]], ["oc", ["openclaw", "opencode"]],
  ]);
});

test("entryAgents: a named agent (and its ullm) wins over the needs; opencode2 counts as opencode", () => {
  // The needs would say claude + codex + openclaw; the entry says what it drives.
  const named = E("n", { kind: "live-drill", agent: "codex", ullm: "claude", needs: ["codex", "claude", "openclaw"] });
  assert.deepEqual(entryAgents(named), ["claude", "codex"]);
  assert.deepEqual(entryAgents(E("o2", { kind: "live-drill", agent: "opencode2", needs: ["opencode2"] })), ["opencode"]);
  assert.deepEqual(entryAgents(E("fz", { kind: "live-drill", frozen: true, agent: ["openclaw", "opencode"], needs: [] })), ["openclaw", "opencode"]);
  const sel = selectEntries([named], { kinds: ["live-drill"], platform: "linux", agents: ["codex", "claude"] });
  assert.deepEqual(sel.selected.map((x) => x.id), ["n"], "openclaw in its needs does not exclude it");
});

test("parseCounts: the drill runner's footer (node:test's form, drill-report.ts countsFooter) gives its pass, fail and skip", () => {
  const log = "[watch] skipped conf-x: not runnable on codex\nconf-a  secrets  PASS\n# tests 31\n# pass 27\n# fail 1\n# skipped 3\n";
  const c = parseCounts(log);
  assert.deepEqual([c.pass, c.fail, c.skip], [27, 1, 3]);
  const skipped = parseCounts("[watch] SKIP: the goose CLI (`goose`) is not on PATH (--skip-unavailable)\n# tests 2\n# pass 0\n# fail 0\n# skipped 2\n");
  assert.equal(classify({ id: "drill.conf.goose" }, { code: 0, counts: skipped }).result, "skip", "a host without the agent: SKIP, not a pass");
});

test("parseVersion: the version in each agent CLI's --version output; null when there is none", () => {
  for (const [out, v] of [
    ["2.1.299 (Claude Code)\n", "2.1.299"], ["codex-cli 0.162.0", "0.162.0"], ["goose 1.9.3", "1.9.3"],
    ["OpenClaw 2026.9.3 (1a2b3c)", "2026.9.3"], ["1.18.35", "1.18.35"], ["opencode v2.0.26", "2.0.26"],
    ["\x1b[1m2.0.0-beta.1\x1b[0m", "2.0.0-beta.1"], ["no version here", null], ["", null], [null, null],
  ]) assert.equal(parseVersion(out), v, JSON.stringify(out));
});

test("probeAgentVersion: asks the agent's CLI once with --version; absent, failing or hanging is null", () => {
  const calls = [];
  const run = (bin, args, o) => { calls.push([bin, args, o.timeout]); return { status: 0, stdout: "2.1.299 (Claude Code)\n", stderr: "" }; };
  assert.equal(probeAgentVersion("claude", { run, timeoutMs: 1000 }), "2.1.299");
  assert.deepEqual(calls, [["claude", ["--version"], 1000]]);
  assert.equal(probeAgentVersion("codex", { run: () => ({ status: 1, stdout: "0.1.0", stderr: "" }) }), null, "a failing CLI");
  assert.equal(probeAgentVersion("codex", { run: () => ({ error: new Error("ENOENT"), status: null }) }), null, "an absent CLI");
  assert.equal(probeAgentVersion("codex", { run: () => { throw new Error("boom"); } }), null);
  assert.equal(probeAgentVersion("nonexistent-agent-cli-xyz"), null, "the real spawn of an absent CLI");
  assert.equal(agentBin("opencode2", {}), "opencode2");
  assert.equal(agentBin("opencode2", { MANDU_OPENCODE_V2_BIN: "/opt/oc2" }), "/opt/oc2");
  assert.equal(agentBin("goose", { MANDU_OPENCODE_V2_BIN: "/opt/oc2" }), "goose");
});

test("agentLabel: the agent and its version, the U-LLM beside it; nothing for an entry that names none", () => {
  assert.equal(agentLabel({}), "");
  assert.equal(agentLabel({ agent: "claude", agentVersion: "2.1.299" }), "claude 2.1.299");
  assert.equal(agentLabel({ agent: "opencode" }), "opencode", "no version reported");
  assert.equal(agentLabel({ agent: "codex", agentVersion: "0.162.0", ullm: "claude", ullmVersion: "2.1.299" }), "codex 0.162.0 (U-LLM claude 2.1.299)");
  assert.equal(agentLabel({ agent: ["openclaw", "opencode"] }), "openclaw+opencode");
});

test("buildSummary: an entry that drove one named agent carries agent, agentVersion and ullm; a list of agents carries none", () => {
  const row = (id, extra = {}) => ({ id, kind: "live-drill", result: "pass", pass: 1, fail: 0, skip: 0, duration_s: 1, log: `logs/${id}.log`, ...extra });
  const s = buildSummary({
    run: "local-a", source: "local", commit: "abcdef0", ref: "master", started: 0, finished: 1000,
    results: [
      row("cc", { agent: "claude", agentVersion: "2.1.299" }),
      row("cx", { agent: "codex", agentVersion: "0.162.0", ullm: "claude", ullmVersion: "2.1.299" }),
      row("oc", { agent: "opencode" }),
      row("fz", { agent: ["openclaw", "opencode"] }),
      row("plain"),
    ],
  });
  validateSummary(s);
  const by = Object.fromEntries(s.entries.map((x) => [x.id, x]));
  assert.equal(by.cc.agent, "claude");
  assert.equal(by.cc.agentVersion, "2.1.299");
  assert.deepEqual([by.cx.agent, by.cx.agentVersion, by.cx.ullm], ["codex", "0.162.0", "claude"]);
  assert.ok(!("ullmVersion" in by.cx), "the U-LLM's version is console-only (the schema has no field for it)");
  assert.equal(by.oc.agent, "opencode");
  assert.ok(!("agentVersion" in by.oc), "no version reported: the field is left out, not null");
  for (const k of ["agent", "agentVersion", "ullm"]) {
    assert.ok(!(k in by.fz), `a frozen entry's list of agents: no ${k}`);
    assert.ok(!(k in by.plain), `an entry that names no agent: no ${k}`);
  }
});

test("loggedAgentVersion: the drill runner's `# agent-version` line, the last one; nothing else is a version", () => {
  assert.equal(loggedAgentVersion("x\n# agent-version 2.1.300\n# pass 1\n"), "2.1.300");
  assert.equal(loggedAgentVersion("# agent-version 1.0\n# agent-version 1.1-beta.2\n"), "1.1-beta.2");
  assert.equal(loggedAgentVersion("# agent-version <b>x</b>\n"), null);
  assert.equal(loggedAgentVersion("  # agent-version 1.0\nagent-version 2.0"), null, "only a line of its own");
  assert.equal(loggedAgentVersion(null), null);
});

test("withAgentPath: an entry of a cached agent finds the hand-run script's pinned CLIs first; others, or no cache, keep PATH", () => {
  assert.deepEqual(CACHED_AGENTS, ["openclaw", "opencode", "opencode2", "goose"]);
  const have = new Set(["/h/.cache/mandu/drill-agents/prefix/bin", "/h/.cache/mandu/drill-agents/node/bin", "/c/prefix/bin"]);
  const exists = (p) => have.has(p);
  assert.deepEqual(agentCacheBins({}, "/h", exists), ["/h/.cache/mandu/drill-agents/node/bin", "/h/.cache/mandu/drill-agents/prefix/bin"]);
  assert.deepEqual(agentCacheBins({ MANDU_DRILL_AGENTS: "/c" }, "/h", exists), ["/c/prefix/bin"], "MANDU_DRILL_AGENTS; no node/bin there");
  assert.deepEqual(agentCacheBins({}, "/nohome", exists), [], "no cache");
  const env = { PATH: "/usr/bin", X: "1" };
  assert.equal(withAgentPath(["opencode"], env, "/h", exists).PATH, "/h/.cache/mandu/drill-agents/node/bin:/h/.cache/mandu/drill-agents/prefix/bin:/usr/bin");
  assert.equal(withAgentPath(["opencode"], env, "/h", exists).X, "1");
  assert.equal(withAgentPath(["claude"], env, "/h", exists), env, "Claude Code comes from PATH");
  assert.equal(withAgentPath([], env, "/h", exists), env);
  assert.equal(withAgentPath(["goose"], env, "/nohome", exists), env, "no cache: unchanged");
});

test("agentMatrix: a generic suite's agents side by side in one row, an agent-only suite its own row; counts per cell, — where it did not run", () => {
  const r = (id, agent, result, pass = 0, fail = 0, skip = 0) => ({ id, agent, result, pass, fail, skip });
  assert.equal(matrixRow(r("drill.conf.codex", "codex")), "drill.conf");
  assert.equal(matrixRow(r("drill.claude-fidelity", "claude")), "drill.claude-fidelity");
  assert.equal(matrixRow(r("integration.codex-headless", "codex")), "integration.codex-headless");
  assert.equal(matrixRow({ id: "x.claude", agent: ["claude", "codex"] }), "x.claude", "a list of agents: its own row");
  assert.equal(matrixCell(r("a", "claude", "pass", 29)), "29✓");
  assert.equal(matrixCell(r("a", "claude", "fail", 27, 1, 1)), "27✓ 1✗ 1∅");
  assert.equal(matrixCell(r("a", "claude", "skip", 0, 0, 3)), "skip (3∅)");
  assert.equal(matrixCell(r("a", "claude", "skip")), "skip");
  assert.equal(matrixCell(r("a", "claude", "pass")), "pass", "no counts: the result");
  assert.equal(matrixCell(r("a", "claude", "timeout", 3)), "timeout");
  assert.equal(agentMatrix([{ id: "plain", result: "pass" }]), null, "no entry named an agent: no matrix");
  const m = agentMatrix([
    r("drill.conf.codex", "codex", "pass", 25), r("drill.conf.claude", "claude", "fail", 28, 1),
    r("integration.codex-headless", "codex", "pass", 3), { id: "plain", result: "pass", pass: 1, fail: 0, skip: 0 },
    r("drill.util.opencode2", "opencode2", "skip", 0, 0, 16),
  ]);
  assert.deepEqual(m.agents, ["claude", "codex", "opencode2"], "LIVE_AGENTS order, only those that ran");
  assert.deepEqual(m.rows, [
    { row: "drill.conf", cells: { codex: "25✓", claude: "28✓ 1✗" } },
    { row: "integration.codex-headless", cells: { codex: "3✓" } },
    { row: "drill.util", cells: { opencode2: "skip (16∅)" } },
  ]);
  assert.deepEqual(matrixText(m), [
    "suite                       claude  codex  opencode2",
    "drill.conf                  28✓ 1✗  25✓    —",
    "integration.codex-headless  —       3✓     —",
    "drill.util                  —       —      skip (16∅)",
  ]);
  const md = matrixMarkdown(m, { run: "local-x" });
  assert.match(md, /^# local-x\n\n\| suite \| claude \| codex \| opencode2 \|\n\|---\|---\|---\|---\|\n\| `drill\.conf` \| 28✓ 1✗ \| 25✓ \| — \|/);
  assert.match(matrixMarkdown({ agents: ["claude"], rows: [{ row: "a|b", cells: { claude: "x|y" } }] }), /\| `a\\\|b` \| x\\\|y \|/, "a pipe cannot break the table");
});

test("main: a live entry's row names its agent and the version its CLI reported; summary.json carries them", async () => {
  const live = (id, o) => E(id, { kind: "live-drill", cmd: ["bash", "-c", "echo '# pass 1'"], ...o });
  const { root } = fixtureRoot([
    live("drill.x", { agent: "claude", needs: ["claude"] }),
    live("cx.mcp", { agent: "codex", ullm: "claude", needs: ["codex", "claude"] }),
    E("plain", { cmd: ["bash", "-c", "echo '# pass 1'"] }),
    // an entry that ran another release (the drift check): the version its run reported wins
    live("drift.claude", { agent: "claude", needs: ["claude"], cmd: ["bash", "-c", "echo '# pass 1'; echo '# agent-version 3.0.0'"] }),
  ]);
  const bin = join(root, "bin");
  try {
    mkdirSync(bin);
    // A fake claude that counts its calls: the version is asked once per run.
    writeFileSync(join(bin, "claude"), `#!/usr/bin/env bash\necho x >> '${join(root, "claude-calls")}'\necho '9.8.7 (Claude Code)'\n`);
    writeFileSync(join(bin, "codex"), "#!/usr/bin/env bash\nexit 3\n");
    chmodSync(join(bin, "claude"), 0o755);
    chmodSync(join(bin, "codex"), 0o755);
    const out = join(root, "o");
    const stdout = sink();
    const env = { ...process.env, PATH: `${bin}:${process.env.PATH}` };
    assert.equal(await main(["--only", "drill.x,cx.mcp,plain,drift.claude", "--out", out, "--commit", "abcdef0"], { root, stdout, stderr: sink(), env }), 0);
    assert.equal(readFileSync(join(root, "claude-calls"), "utf8"), "x\n", "one --version call for two entries");
    assert.match(stdout.text, /^▶ drill\.x \[claude 9\.8\.7\] /m);
    assert.match(stdout.text, /^▶ cx\.mcp \[codex \(U-LLM claude 9\.8\.7\)\] /m, "codex reported no version");
    assert.match(stdout.text, /^ {2}✓ {2}drill\.x +claude 9\.8\.7 +/m);
    assert.match(stdout.text, /^ {2}✓ {2}plain {2,}/m);
    const s = JSON.parse(readFileSync(join(out, "summary.json"), "utf8"));
    validateSummary(s);
    const by = Object.fromEntries(s.entries.map((x) => [x.id, x]));
    assert.deepEqual([by["drill.x"].agent, by["drill.x"].agentVersion], ["claude", "9.8.7"]);
    assert.deepEqual([by["cx.mcp"].agent, by["cx.mcp"].ullm, "agentVersion" in by["cx.mcp"]], ["codex", "claude", false]);
    assert.ok(!("agent" in by.plain));
    assert.equal(by["drift.claude"].agentVersion, "3.0.0", "the run's own version over the PATH's pin");
    // the agent matrix: after the summary, and in summary.md
    assert.match(stdout.text, /─ by agent ─[\s\S]*^ {2}suite +claude +codex$/m);
    assert.match(stdout.text, /^ {2}drill\.x +1✓ +—$/m);
    assert.match(stdout.text, /^ {2}cx\.mcp +— +1✓$/m);
    assert.match(readFileSync(join(out, "summary.md"), "utf8"), /^\| `drill\.x` \| 1✓ \| — \|$/m);
    assert.match(stdout.text, /results: .*\(summary\.json, summary\.md, junit\.xml, logs\/\)/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("selectEntries --agents: keeps an entry whose agents are all listed; one driving none stays; the rest excluded with the agents outside", () => {
  const codex = selectEntries(AGENT_SAMPLE, { kinds: ["live-drill"], platform: "linux", agents: ["codex"] });
  assert.deepEqual(codex.selected.map((x) => x.id), ["plain", "cx", "cxg"]);
  assert.deepEqual(codex.excluded, [
    { id: "cc", reason: "drives claude (this run: --agents codex)" },
    { id: "cxu", reason: "drives claude (this run: --agents codex)" },
    { id: "oc", reason: "drives openclaw,opencode (this run: --agents codex)" },
  ]);
  const both = selectEntries(AGENT_SAMPLE, { kinds: ["live-drill"], platform: "linux", agents: ["claude", "codex"] });
  assert.deepEqual(both.selected.map((x) => x.id), ["plain", "cc", "cx", "cxg", "cxu"]);
  assert.equal(selectEntries(AGENT_SAMPLE, { kinds: ["live-drill"], platform: "linux" }).selected.length, AGENT_SAMPLE.length, "no --agents: every agent");
  // --only names an entry; --agents still applies to it.
  assert.deepEqual(selectEntries(AGENT_SAMPLE, { only: ["cc", "cx"], platform: "linux", agents: ["codex"] }).selected.map((x) => x.id), ["cx"]);
});

const DRILL = (id, ids, o = {}) => E(id, {
  kind: "live-drill", cwd: "tests", needs: ["node", "claude", "claude-login", "tmux"],
  cmd: ["npx", "tsx", "drill-tree/live/drill-run.ts", "--ids", ids.join(","), "--skip-permissions", "--own-arbiter"],
  select: { arg: "--ids", values: ids }, ...o,
});
const DRILL_SAMPLE = [DRILL("drill.secrets", ["util-reasoning", "conf-callback-unbound", "conf-three-levels"]), DRILL("drill.secrets-mock-sites", ["util-web-answers"]), DRILL("drill.frozen-full-mock-sites", ["integ-web-page", "util-trusted-grep"], { frozen: true }),
  E("cut", { kind: "live-drill", env: { MANDU_E2E_ONLY: "a,b" }, select: { env: "MANDU_E2E_ONLY", values: ["a", "b"] } })];

test("narrowSelect: the list in the argument after select.arg, or in select.env, keeps the entry's order; none wanted → null", () => {
  const d = narrowSelect(DRILL_SAMPLE[0], ["conf-three-levels", "util-reasoning"]);
  assert.deepEqual(d.cmd, ["npx", "tsx", "drill-tree/live/drill-run.ts", "--ids", "util-reasoning,conf-three-levels", "--skip-permissions", "--own-arbiter"]);
  assert.deepEqual(d.select.values, ["util-reasoning", "conf-three-levels"]);
  assert.deepEqual(DRILL_SAMPLE[0].select.values, ["util-reasoning", "conf-callback-unbound", "conf-three-levels"], "the manifest's entry is not mutated");
  const c = narrowSelect(DRILL_SAMPLE[3], ["b"]);
  assert.deepEqual(c.env, { MANDU_E2E_ONLY: "b" });
  assert.equal(narrowSelect(DRILL_SAMPLE[1], ["conf-callback-unbound"]), null);
  assert.equal(narrowSelect(E("x"), ["conf-callback-unbound"]).id, "x", "an entry with no select is unchanged");
});

test("selectEntries --drills: narrows each drill entry, excludes one left with none, leaves other entries alone; unknown ids reported", () => {
  const r = selectEntries(DRILL_SAMPLE, { kinds: ["live-drill"], platform: "linux", drills: ["conf-callback-unbound", "util-web-answers", "integ-web-page"] });
  assert.deepEqual(r.selected.map((x) => [x.id, x.cmd[4] ?? null]), [["drill.secrets", "conf-callback-unbound"], ["drill.secrets-mock-sites", "util-web-answers"], ["cut", null]]);
  assert.deepEqual(r.selected[2].env, { MANDU_E2E_ONLY: "a,b" }, "--drills narrows drill entries only");
  assert.deepEqual(r.unknownDrills, [], "an id only a frozen drill runs is still a known drill id");
  const none = selectEntries(DRILL_SAMPLE.filter((x) => x.id !== "cut"), { kinds: ["live-drill"], platform: "linux", drills: ["conf-callback-unbound"] });
  assert.deepEqual(none.excluded, [{ id: "drill.secrets-mock-sites", reason: "none of its scenarios in --drills conf-callback-unbound" }]);
  assert.deepEqual(selectEntries(DRILL_SAMPLE, { kinds: ["live-drill"], platform: "linux", drills: ["conf-callback-unbound", "Z99"] }).unknownDrills, ["Z99"]);
});

test("run-suites --agents: an unknown agent is a usage error", async () => {
  // The plan is selected for Linux on every host (the drills and the Codex
  // real-model lane are Linux-only entries).
  let err = sink();
  assert.equal(await main(["--kind", "live-drill", "--agents", "claude,gemini", "--dry-run"], { stdout: sink(), stderr: err }), 2);
  assert.match(err.text, /unknown agent 'gemini' in --agents/);
});

test("withWatchStore: a drill gets --store <the CALLER's watch store>, never the pinned MANDU_HOME's; other entries and a drill with its own --store/--out are left alone", async () => {
  // 2026-09-30: under FIXED_ENV's /dev/null home, drill-run.ts fell back to a
  // temp home and every drill run's record (casts, chapters) went to /tmp,
  // out of the dashboard's sight
  const drill = { id: "drill.secrets", kind: "live-drill", cmd: ["npx", "tsx", "drill-tree/live/drill-run.ts", "--ids", "conf-env-catalog"] };
  assert.deepEqual(withWatchStore(drill, { MANDU_HOME: "/srv/mh" }, "/home/u").cmd, [...drill.cmd, "--store", "/srv/mh/runs/drills/live"]);
  assert.deepEqual(withWatchStore(drill, {}, "/home/u").cmd, [...drill.cmd, "--store", "/home/u/.mandu/runs/drills/live"]);
  assert.equal(withWatchStore({ ...drill, cmd: [...drill.cmd, "--store", "/x"] }, {}, "/home/u").cmd.filter((a) => a === "--store").length, 1);
  assert.equal(withWatchStore({ ...drill, cmd: [...drill.cmd, "--out", "/x/r"] }, {}, "/home/u").cmd.includes("--store"), false);
  const plain = { id: "integration.e2e", kind: "stack", cmd: ["npm", "test"] };
  assert.equal(withWatchStore(plain, {}, "/home/u"), plain);
  assert.equal(FIXED_ENV.MANDU_HOME, "/dev/null/mandu-test-home", "the suites' own pin is unchanged");
  // an entry that runs the live runner per side (the demo battery) says so,
  // and records where a drill entry does (the CI guest collects it from there)
  const battery = { id: "live.battery", kind: "live-drill", watchStore: true, cmd: ["npx", "tsx", "drill-tree/live/demo-battery.ts"] };
  assert.deepEqual(withWatchStore(battery, {}, "/home/u", "/srv/caller/runs/drills/live").cmd, [...battery.cmd, "--store", "/srv/caller/runs/drills/live"]);
  assert.equal(withWatchStore({ ...battery, watchStore: undefined }, {}, "/home/u").cmd.includes("--store"), false, "without the flag a non-drill entry is left alone");
});

test("--watch-store: wins over the environment (test-all.sh passes the caller's, resolved before its MANDU_HOME pin); a store under /dev/null is warned about", async () => {
  // 2026-10-01 (test-reorganization.md §8.1): test-all.sh exports the pinned
  // MANDU_HOME before calling the runner, so the environment's live-drill-runs was
  // /dev/null/mandu-test-home/runs/drills/live and a drill run recorded nowhere.
  const drill = { id: "drill.secrets", kind: "live-drill", cmd: ["npx", "tsx", "drill-tree/live/drill-run.ts"] };
  assert.deepEqual(withWatchStore(drill, { MANDU_HOME: FIXED_ENV.MANDU_HOME }, "/home/u", "/srv/caller/runs/drills/live").cmd, [...drill.cmd, "--store", "/srv/caller/runs/drills/live"]);
  assert.equal(unusableWatchStore("/dev/null/mandu-test-home/runs/drills/live"), true);
  assert.equal(unusableWatchStore("/dev/null"), true);
  assert.equal(unusableWatchStore("/home/u/.mandu/runs/drills/live"), false);
  assert.equal(unusableWatchStore("/dev/nullx/runs/drills/live"), false);
  const pinned = { ...process.env, MANDU_HOME: FIXED_ENV.MANDU_HOME };
  // no drill selected: no warning; an empty --watch-store is a usage error
  const err3 = sink();
  assert.equal(await main(["--kind", "unit", "--dry-run"], { stdout: sink(), stderr: err3, env: pinned }), 0);
  assert.equal(err3.text, "");
  assert.equal(await main(["--kind", "unit", "--watch-store", "", "--dry-run"], { stdout: sink(), stderr: sink(), env: pinned }), 2);
});

test("selectEntries: --only names entries whatever their kind or flags, frozen ones too; '*' globs; unknown ids reported", () => {
  const r = selectEntries(SAMPLE, { kinds: ["unit"], only: ["fr", "net", "k*", "nope"], platform: "linux" });
  assert.deepEqual(r.selected.map((x) => x.id), ["k1", "net", "fr"]);
  assert.deepEqual(r.unknown, ["nope"]);
});

test("planPhases: 'sandbox' is parallel only when sandboxed; the entries that need `kernel` split by `parallel: true`, never by 'sandbox'", () => {
  const sel = [
    ...SAMPLE.filter((x) => ["a", "b", "c", "k1", "both"].includes(x.id)),
    E("k2", { kind: "sandbox", needs: ["kernel"], parallel: true }), E("k3", { kind: "replay-drill", needs: ["kernel"], parallel: "sandbox" }),
    E("rd", { kind: "replay-drill", parallel: true }),
  ];
  const ids = (ph) => [ph.parallel, ph.serial, ph.kernel, ph.kernelSerial].map((p) => p.map((x) => x.id));
  assert.deepEqual(ids(planPhases(sel, { sandboxed: false })), [["a", "both", "rd"], ["b", "c"], ["k2"], ["k1", "k3"]], "a replay-drill without the need is not in the kernel lane");
  assert.deepEqual(ids(planPhases(sel, { sandboxed: true })), [["a", "c", "both", "rd"], ["b"], ["k2"], ["k1", "k3"]]);
});

// ── the sandbox argv ───────────────────────────────────────────────────────────

test("buildArgv: a non-kernel entry goes through the wrapper with --chdir and --setenv; the fixed pins win", () => {
  const x = E("s", { cwd: "pkg", cmd: ["npm", "test"], env: { FOO: "1", MANDU_AXES_STRICT: "0", MANDU_HOME: "/home/u/.mandu" } });
  const { argv, cwd, sandboxed } = buildArgv(x, { root: "/r", sandbox: "/w/ns-run.sh" });
  assert.equal(sandboxed, true);
  assert.equal(cwd, "/r");
  assert.deepEqual(argv, [
    "/w/ns-run.sh", "--chdir", "/r/pkg",
    "--setenv", "FOO", "1",
    "--setenv", "MANDU_AXES_STRICT", "1",
    "--setenv", "MANDU_HOME", "/dev/null/mandu-test-home",
    "--setenv", "MANDU_POLICY_FILE", FIXED_ENV.MANDU_POLICY_FILE,
    "--", "npm", "test",
  ]);
});

test("buildArgv: kernel-lane entries never go through the sandbox; without one, cmd runs in its cwd", () => {
  const k = E("k", { kind: "sandbox", needs: ["kernel"], cwd: "x", cmd: ["bash", "k.sh"] });
  assert.deepEqual(buildArgv(k, { root: "/r", sandbox: "/w/ns-run.sh" }), { argv: ["bash", "k.sh"], cwd: "/r/x", sandboxed: false });
  assert.deepEqual(buildArgv(E("d", { cwd: "y" }), { root: "/r" }), { argv: ["true"], cwd: "/r/y", sandboxed: false });
});

// ── end to end over a throwaway manifest ───────────────────────────────────────

function sink() {
  const s = { text: "", isTTY: false, write(c) { s.text += c; return true; } };
  return s;
}

/** A root with its own tests/suites.mjs, and a fake ns-run.sh that records its argv then runs the command. */
/** The fake wrapper's calls, one line each (one file per call). */
function wrapperCalls(root) {
  return readdirSync(root).filter((f) => f.startsWith("wrapper-calls.")).map((f) => readFileSync(join(root, f), "utf8").trim());
}

function fixtureRoot(entries) {
  // main() selects for the running host (selectEntries platform:
  // process.platform), so the fixture entries run here whatever E()'s default.
  entries = entries.map((x) => ({ ...x, platforms: [...new Set([...(x.platforms ?? []), process.platform])] }));
  const root = mkdtempSync(join(tmpdir(), "run-suites-test-"));
  mkdirSync(join(root, "tests"), { recursive: true });
  mkdirSync(join(root, "pkg"), { recursive: true });
  writeFileSync(join(root, "tests", "suites.mjs"), `export const entries = ${JSON.stringify(entries, null, 2)};\nexport default entries;\n`);
  const wrapper = join(root, "fake-ns-run.sh");
  writeFileSync(wrapper, [
    "#!/usr/bin/env bash",
    // One file per call: concurrent appends of a line over 1 KiB to one file
    // interleave under macOS's bash 3.2, whose printf writes it in pieces.
    `printf '%s\\n' "$*" > "${join(root, "wrapper-calls.")}$$.$RANDOM"`,
    "dir=.",
    "while [[ $# -gt 0 ]]; do",
    "  case \"$1\" in",
    "    --chdir) dir=\"$2\"; shift 2 ;;",
    "    --setenv) export \"$2=$3\"; shift 3 ;;",
    // ns-run's --bind-rw refuses a directory that is missing or not empty.
    "    --bind-rw) [[ -d \"$2\" && -z \"$(ls -A \"$2\")\" ]] || { echo \"fake-ns-run: bad --bind-rw $2\" >&2; exit 98; }; shift 2 ;;",
    "    --) shift; break ;;",
    "    *) echo \"fake-ns-run: bad arg $1\" >&2; exit 97 ;;",
    "  esac",
    "done",
    "cd \"$dir\" && exec \"$@\"",
    "",
  ].join("\n"));
  chmodSync(wrapper, 0o755);
  return { root, wrapper };
}

const RUN_ENTRIES = (pidFile) => [
  E("ok.node", { cwd: "pkg", cmd: ["bash", "-c", "echo \"$MANDU_AXES_STRICT|$MANDU_HOME|$MANDU_POLICY_FILE|$FOO|$(pwd)\"; printf '# pass 2\\n# fail 0\\n# skipped 1\\n'"], env: { FOO: "bar" } }),
  E("bad.shell", { cmd: ["bash", "-c", "echo 'x.test.sh: 1 passed, 1 failed'; echo 'boom <&>' >&2; exit 1"], parallel: "sandbox" }),
  E("slow", { cmd: ["bash", "-c", `sleep 60 & echo $! > '${pidFile}'; wait`], timeout: 1 }),
  E("kern", { kind: "sandbox", needs: ["kernel"], parallel: false, ci: { maxSkip: 0, minPass: 1 }, cmd: ["bash", "-c", "echo 'SKIP: no userns'; echo 'k.test.sh: 0 passed, 0 failed (skipped)'"] }),
];

function alive(pid) {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

test("main: runs the selection sandboxed, writes a valid summary.json, junit.xml and logs; exit 1 on failures", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "run-suites-pid-"));
  const pidFile = join(scratch, "slow.pid");
  const { root, wrapper } = fixtureRoot(RUN_ENTRIES(pidFile));
  const stagesFile = join(root, "stages.json");
  writeFileSync(stagesFile, JSON.stringify({ build: { result: "pass", duration_s: 3 } }));
  const out = join(root, "out", "gl-12-34");
  const stdout = sink();
  try {
    const rc = await main([
      "--kind", "unit,sandbox", "--jobs", "3", "--sandbox", wrapper, "--out", out, "--run-id", "gl-12-34",
      "--source", "gitlab", "--commit", "b814495e", "--ref", "master", "--image", "mandu-ci-3f2a", "--stages-json", stagesFile,
    ], { root, stdout, stderr: sink() });
    assert.equal(rc, 1, stdout.text);

    const summary = JSON.parse(readFileSync(join(out, "summary.json"), "utf8"));
    validateSummary(summary, "gl-12-34");
    assert.equal(summary.result, "fail");
    assert.equal(summary.commit, "b814495e");
    assert.equal(summary.image, "mandu-ci-3f2a");
    assert.deepEqual(summary.stages.build, { result: "pass", duration_s: 3 });
    assert.equal(summary.stages.suites.result, "fail");
    assert.match(summary.reason, /bad\.shell \(fail\)/);
    assert.deepEqual(summary.entries.map((x) => x.id), ["ok.node", "bad.shell", "slow", "kern"], "manifest order");
    const by = Object.fromEntries(summary.entries.map((x) => [x.id, x]));
    assert.deepEqual([by["ok.node"].result, by["ok.node"].pass, by["ok.node"].skip], ["pass", 2, 1]);
    assert.deepEqual([by["bad.shell"].result, by["bad.shell"].pass, by["bad.shell"].fail], ["fail", 1, 1]);
    assert.equal(by.slow.result, "timeout");
    assert.equal(by.kern.result, "skip", "a skip is allowed without --strict-skips");
    assert.deepEqual(summary.entries.map((x) => x.kind), ["unit", "unit", "unit", "sandbox"], "each entry carries its kind");
    assert.ok(summary.entries.every((x) => !("tier" in x)), "no tier key");

    // The sandbox: every non-kernel entry went through the wrapper, the kernel one did not.
    const calls = wrapperCalls(root);
    assert.equal(calls.length, 3);
    assert.ok(calls.every((c) => c.includes(`--setenv MANDU_AXES_STRICT 1 --setenv MANDU_HOME /dev/null/mandu-test-home --setenv MANDU_POLICY_FILE ${FIXED_ENV.MANDU_POLICY_FILE} --setenv MANDU_TEST_ENTRY /`)));
    // Each boxed entry's own TMPDIR is bound into its box and set last.
    for (const c of calls) {
      const tmp = /--setenv TMPDIR (\S+) --/.exec(c)?.[1];
      assert.ok(tmp && c.includes(`--bind-rw ${tmp} `), `bound and set: ${c}`);
    }
    assert.ok(!calls.some((c) => c.includes("no userns")), "kernel entries never enter the sandbox");
    const okLog = readFileSync(join(out, "logs", "ok.node.log"), "utf8");
    assert.match(okLog, new RegExp(`^1\\|/dev/null/mandu-test-home\\|/dev/null/mandu-test-no-policy\\.yaml\\|bar\\|${join(root, "pkg")}$`, "m"));

    // The timeout killed the whole process group, the backgrounded sleep included.
    const pid = Number(readFileSync(pidFile, "utf8"));
    for (let i = 0; i < 50 && alive(pid); i++) await new Promise((r) => setTimeout(r, 100));
    assert.equal(alive(pid), false, "the timed-out entry's grandchild is gone");

    const junit = readFileSync(join(out, "junit.xml"), "utf8");
    assert.equal((junit.match(/<testsuite name=/g) ?? []).length, 4);
    assert.match(junit, /<testsuites name="mandu" tests="4" failures="1" errors="1" skipped="1"/);
    assert.match(junit, /<testsuite name="bad\.shell"[\s\S]*?<failure type="fail" message="exit 1"[^>]*>[\s\S]*boom &lt;&amp;&gt;[\s\S]*?<\/failure>/);
    assert.match(junit, /<testsuite name="slow"[\s\S]*?<error type="timeout"/);
    assert.match(junit, /<testsuite name="kern"[\s\S]*?<skipped /);
    assert.match(junit, /<property name="kind" value="sandbox"\/>[\s\S]*?<testcase classname="sandbox" name="kern"/);
    assert.doesNotMatch(junit, /name="tier"/);

    assert.match(stdout.text, /^▶ bad\.shell /m);
    assert.match(stdout.text, /^ {2}✗ FAIL {2}/m, "the test-all.sh verdict shape the dashboard parses");
    assert.match(stdout.text, /^ {2}✓ PASS {2}2 passed; 0 failed; 1 skipped/m);
    assert.match(stdout.text, /^ {2}∅ SKIP {2}/m);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("main: --strict-skips fails a kernel entry that skipped; --only selects by id; a green run exits 0", async () => {
  const { root } = fixtureRoot(RUN_ENTRIES("/dev/null"));
  try {
    const out1 = join(root, "o1");
    assert.equal(await main(["--kind", "sandbox", "--strict-skips", "--out", out1, "--commit", "abcdef0"], { root, stdout: sink(), stderr: sink() }), 1);
    const s1 = JSON.parse(readFileSync(join(out1, "summary.json"), "utf8"));
    validateSummary(s1);
    assert.equal(s1.entries[0].result, "fail");
    assert.match(readFileSync(join(out1, "logs", "kern.log"), "utf8"), /--strict-skips: 1 skipped, ci\.maxSkip is 0/);

    const out2 = join(root, "o2");
    assert.equal(await main(["--only", "ok.node", "--out", out2, "--commit", "abcdef0"], { root, stdout: sink(), stderr: sink() }), 0);
    const s2 = JSON.parse(readFileSync(join(out2, "summary.json"), "utf8"));
    validateSummary(s2);
    assert.equal(s2.result, "pass");
    assert.equal("reason" in s2, false);
    assert.equal("image" in s2, false, "no image given: the optional field is left out, not null");
    assert.match(s2.run, /^local-\d{8}T\d{6}Z-abcdef0$/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

/** Entries that append `start <id> <ns>` / `end <id> <ns>` to one timeline file around a short sleep. */
const TIMED = (tl) => {
  const t = (id, o = {}) => E(id, {
    // Nanoseconds through perl: BSD date (macOS) has no %N.
    platforms: [...new Set(["linux", process.platform])], // main() selects for this host
    cmd: ["bash", "-c", `ns() { perl -MTime::HiRes=time -e 'printf "%d", time()*1e9'; }; echo "start ${id} $(ns)" >> '${tl}'; sleep 0.5; echo "end ${id} $(ns)" >> '${tl}'; echo '# pass 1'`],
    ...o,
  });
  return [
    t("par1"), t("par2", { parallel: "sandbox" }), t("ser", { parallel: false }),
    t("kA", { kind: "sandbox", needs: ["kernel"], parallel: true }), t("kB", { kind: "sandbox", needs: ["kernel"], parallel: true }),
    t("kS", { kind: "sandbox", needs: ["kernel"], parallel: false }),
  ];
};

/** The timeline as { id: [startNs, endNs] }. */
function spans(tl) {
  const out = {};
  for (const l of readFileSync(tl, "utf8").trim().split("\n")) {
    const [what, id, ns] = l.split(" ");
    (out[id] ??= [0n, 0n])[what === "start" ? 0 : 1] = BigInt(ns);
  }
  return out;
}
const overlap = (a, b) => a[0] < b[1] && b[0] < a[1];
const after = (a, ...bs) => bs.every((b) => a[0] >= b[1]);

test("main --sandbox: the kernel lane runs beside the parallel stage, its `parallel: true` entries --kernel-jobs at a time, then the lane's serial ones alone; the serial phase waits for both", async () => {
  const { root, wrapper } = fixtureRoot(TIMED("/dev/null"));
  const tl = join(root, "timeline.txt");
  writeFileSync(join(root, "tests", "suites.mjs"), `export const entries = ${JSON.stringify(TIMED(tl), null, 2)};\nexport default entries;\n`);
  try {
    const rc = await main(["--kind", "unit,sandbox", "--jobs", "2", "--kernel-jobs", "2", "--sandbox", wrapper,
      "--out", join(root, "o"), "--commit", "abcdef0"], { root, stdout: sink(), stderr: sink() });
    assert.equal(rc, 0);
    const s = spans(tl);
    assert.ok(overlap(s.kA, s.par1) && overlap(s.kB, s.par1), "kernel entries run beside the parallel stage");
    assert.ok(overlap(s.kA, s.kB), "--kernel-jobs 2 runs the kernel lane's parallel entries side by side");
    assert.ok(after(s.kS, s.kA, s.kB), "a `parallel: false` kernel entry runs alone in the lane, after the others");
    assert.ok(after(s.ser, s.par1, s.par2, s.kA, s.kB, s.kS), "the serial phase runs alone, after both lanes");
    const summary = JSON.parse(readFileSync(join(root, "o", "summary.json"), "utf8"));
    validateSummary(summary);
    assert.deepEqual(summary.entries.map((x) => x.id), ["par1", "par2", "ser", "kA", "kB", "kS"], "manifest order, whatever the schedule");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

/** The most entries running at once in a timeline. */
function peak(s) {
  const ev = Object.values(s).flatMap(([a, b]) => [[a, 1], [b, -1]]).sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : x[1] - y[1]));
  let n = 0;
  let max = 0;
  for (const [, d] of ev) { n += d; max = Math.max(max, n); }
  return max;
}

test("main --sandbox: one queue, longest first by the cost table, over --jobs + --kernel-jobs slots; the kernel cap and the lone kernel entry hold", async () => {
  const { root, wrapper } = fixtureRoot(TIMED("/dev/null"));
  const tl = join(root, "timeline.txt");
  writeFileSync(join(root, "tests", "suites.mjs"), `export const entries = ${JSON.stringify(TIMED(tl), null, 2)};\nexport default entries;\n`);
  // Manifest order is par1, par2, ser, kA, kB, kS; the costs put par2 and kA first.
  const costs = join(root, "costs.json");
  writeFileSync(costs, JSON.stringify({ par2: 9, kA: 5, kB: 4, par1: 1, kS: 0 }));
  try {
    const rc = await main(["--kind", "unit,sandbox", "--jobs", "1", "--kernel-jobs", "1", "--sandbox", wrapper, "--costs", costs,
      "--out", join(root, "o"), "--commit", "abcdef0"], { root, stdout: sink(), stderr: sink() });
    assert.equal(rc, 0);
    const s = spans(tl);
    const { ser, ...queued } = s;
    assert.ok(peak(queued) <= 2, "never more than --jobs + --kernel-jobs entries at once");
    for (const later of [s.par1, s.kB]) {
      assert.ok(later[0] >= s.par2[0] && later[0] >= s.kA[0], "the costliest entries start first, whatever the manifest order");
    }
    assert.ok(!overlap(s.kA, s.kB), "--kernel-jobs 1: one kernel entry at a time");
    assert.ok(after(s.kS, s.kA, s.kB), "a `parallel: false` kernel entry waits for the other kernel entries");
    assert.ok(after(ser, s.par1, s.par2, s.kA, s.kB, s.kS), "the serial phase runs alone, after the queue");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("main --costs: the measured costs order the queue over the checked-in table; an entry they do not name keeps its table cost", async () => {
  const one = (tl, id) => ({ ...TIMED(tl).find((x) => x.id === "par1"), id,
    cmd: ["bash", "-c", `ns() { perl -MTime::HiRes=time -e 'printf "%d", time()*1e9'; }; echo "start ${id} $(ns)" >> '${tl}'; echo "end ${id} $(ns)" >> '${tl}'; echo '# pass 1'`] });
  const { root } = fixtureRoot([one("/dev/null", "a")]);
  const tl = join(root, "timeline.txt");
  writeFileSync(join(root, "tests", "suites.mjs"), `export const entries = ${JSON.stringify(["a", "b", "c", "d"].map((id) => one(tl, id)), null, 2)};\nexport default entries;\n`);
  // The checked-in table says a is the longest and knows c; the measured file
  // (what vm-run.sh brings) says b is the longest now and a short, and says
  // nothing of c, which keeps its table cost (50: ahead of a's measured 40;
  // a table the file replaced would cost c the default 30, behind a); d is in
  // neither (the default 30).
  writeFileSync(join(root, "tests", "suite-costs.json"), JSON.stringify({ a: 100, b: 1, c: 50 }));
  const costs = join(root, "measured.json");
  writeFileSync(costs, JSON.stringify({ b: 200, a: 40 }));
  try {
    const rc = await main(["--kind", "unit", "--jobs", "1", "--costs", costs, "--out", join(root, "o"), "--commit", "abcdef0"],
      { root, stdout: sink(), stderr: sink() });
    assert.equal(rc, 0);
    const s = spans(tl);
    const order = Object.entries(s).sort((x, y) => (x[1][0] < y[1][0] ? -1 : 1)).map(([id]) => id);
    assert.deepEqual(order, ["b", "c", "a", "d"]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("main --sandbox: a slot no kernel entry needs runs non-kernel work", async () => {
  const { root, wrapper } = fixtureRoot(TIMED("/dev/null"));
  const tl = join(root, "timeline.txt");
  writeFileSync(join(root, "tests", "suites.mjs"), `export const entries = ${JSON.stringify(TIMED(tl), null, 2)};\nexport default entries;\n`);
  try {
    const rc = await main(["--kind", "unit", "--jobs", "1", "--kernel-jobs", "1", "--sandbox", wrapper,
      "--out", join(root, "o"), "--commit", "abcdef0"], { root, stdout: sink(), stderr: sink() });
    assert.equal(rc, 0);
    const s = spans(tl);
    assert.ok(overlap(s.par1, s.par2), "--jobs 1 plus the idle kernel slot: two non-kernel entries side by side");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("main without --sandbox: the order stays sequential (parallel, serial, then the kernel lane), --kernel-jobs 1 by default", async () => {
  const { root } = fixtureRoot(TIMED("/dev/null"));
  const tl = join(root, "timeline.txt");
  writeFileSync(join(root, "tests", "suites.mjs"), `export const entries = ${JSON.stringify(TIMED(tl), null, 2)};\nexport default entries;\n`);
  try {
    const rc = await main(["--kind", "unit,sandbox", "--jobs", "2", "--out", join(root, "o"), "--commit", "abcdef0"],
      { root, stdout: sink(), stderr: sink() });
    assert.equal(rc, 0);
    const s = spans(tl);
    assert.ok(after(s.par2, s.par1) && after(s.ser, s.par2), "'sandbox' is serial unsandboxed: par2, then ser, after the parallel stage");
    for (const k of [s.kA, s.kB, s.kS]) assert.ok(after(k, s.par1, s.par2, s.ser), "the kernel lane waits for every other entry");
    assert.ok(!overlap(s.kA, s.kB), "one kernel entry at a time by default");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("main: usage errors exit 2 (unknown kind, the retired --tier, unknown id, a commit that is no commit id, a bad stage)", async () => {
  const { root } = fixtureRoot(RUN_ENTRIES("/dev/null"));
  try {
    const run = (args) => main(args, { root, stdout: sink(), stderr: sink() });
    assert.equal(await run(["--kind", "nightly"]), 2);
    assert.equal(await run(["--kind", "frozen"]), 2, "frozen is a marker, not a kind");
    assert.equal(await run(["--tier", "unit"]), 2);
    assert.equal(await run(["--only", "nope", "--commit", "abcdef0"]), 2);
    assert.equal(await run(["--kind", "unit", "--commit", "unknown"]), 2);
    assert.equal(await run([]), 2);
    assert.equal(await run(["--kind", "unit", "--kernel-jobs", "0"]), 2);
    assert.equal(await run(["--kind", "unit", "--commit", "abcdef0", "--costs", join(root, "no-such-costs.json")]), 2);
    const badCosts = join(root, "bad-costs.json");
    writeFileSync(badCosts, JSON.stringify({ x: "slow" }));
    assert.equal(await run(["--kind", "unit", "--commit", "abcdef0", "--costs", badCosts]), 2);
    const bad = join(root, "bad-stages.json");
    writeFileSync(bad, JSON.stringify({ "bad stage": { result: "pass", duration_s: 1 } }));
    assert.equal(await run(["--kind", "unit", "--commit", "abcdef0", "--stages-json", bad]), 2);
    for (const t of ["-1", "abc", "2.5", ""]) assert.equal(await run(["--kind", "unit", "--commit", "abcdef0", "--fail-tail", t]), 2, `--fail-tail ${t}`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ── --failures-only (test-organization.md §5) ──────────────────────────────────

test("countsLine: the verdict, then failed (any result but pass and skip), passed, skipped, of the entries; not run and excluded when there are", () => {
  const rs = (...xs) => xs.map((result, i) => ({ id: `e${i}`, result }));
  assert.equal(countsLine({ result: "pass" }, rs("pass", "pass", "skip")), "ALL SUITES GREEN: 0 failed, 2 passed, 1 skipped of 3 entries");
  assert.equal(countsLine({ result: "fail" }, rs("pass", "fail", "timeout", "error", "skip"), { excluded: 2 }),
    "FAILURES PRESENT: 3 failed, 1 passed, 1 skipped of 5 entries (2 excluded)");
  assert.equal(countsLine({ result: "fail" }, rs("fail"), { notRun: 2 }), "FAILURES PRESENT: 1 failed, 0 passed, 0 skipped, 2 not run of 3 entries");
  assert.equal(countsLine({ result: "error" }, [], { runError: "no entries selected" }), "RUN ERROR (no entries selected): 0 failed, 0 passed, 0 skipped of 0 entries");
  assert.equal(countsLine({ result: "pass" }, [{ id: "x", result: "fail", nonBlocking: true }]), "ALL SUITES GREEN: 1 failed (1 non-blocking), 0 passed, 0 skipped of 1 entry");
});

// A pass, a skip and a failure whose log has 60 numbered lines.
const FAILURES_ONLY_ENTRIES = [
  E("fo.pass", { cmd: ["bash", "-c", "printf '# pass 3\\n# fail 0\\n'"] }),
  E("fo.skip", { cmd: ["bash", "-c", "echo 'k.test.sh: 0 passed, 0 failed (skipped)'"] }),
  E("fo.bad", { cmd: ["bash", "-c", "for i in $(seq 1 60); do echo \"line-$i\"; done; echo 'x.test.sh: 1 passed, 1 failed'; exit 1"] }),
];

test("main --failures-only: no PASS or SKIP row; the FAIL row with the last 40 log lines; the failed rows and one counts line; summary.json, junit.xml, logs/ and the exit code as without it", async () => {
  const { root } = fixtureRoot(FAILURES_ONLY_ENTRIES);
  try {
    const runOnce = async (extra, out) => {
      const stdout = sink();
      const rc = await main(["--kind", "unit", "--out", out, "--commit", "abcdef0", "--run-id", "fo-1", ...extra], { root, stdout, stderr: sink() });
      return { rc, text: stdout.text, summary: JSON.parse(readFileSync(join(out, "summary.json"), "utf8")) };
    };
    const full = await runOnce([], join(root, "full"));
    const fo = await runOnce(["--failures-only"], join(root, "fo"));
    assert.equal(fo.rc, 1, fo.text);
    assert.equal(full.rc, 1, "the same exit code");
    validateSummary(fo.summary, "fo-1");
    const strip = (s) => ({ ...s, started: 0, finished: 0, stages: { suites: { ...s.stages.suites, duration_s: 0 } }, entries: s.entries.map((e) => ({ ...e, duration_s: 0 })) });
    assert.deepEqual(strip(fo.summary), strip(full.summary), "the same summary.json");
    // The same log but the trailer's duration (0.0s in one run, 0.1s in the
    // other on a loaded CI host, 2026-10-18).
    const logOf = (dir) => readFileSync(join(root, dir, "logs", "fo.bad.log"), "utf8").replace(/ duration=\d+(?:\.\d+)?s/g, " duration=Ns");
    assert.match(readFileSync(join(root, "fo", "logs", "fo.bad.log"), "utf8"), / duration=\d+\.\ds/, "the trailer still says how long");
    assert.equal(logOf("fo"), logOf("full"), "the same full log on disk");
    assert.ok(existsSync(join(root, "fo", "junit.xml")));

    // The default output is unchanged: every row, a 25-line tail, the green/red line.
    assert.match(full.text, /^ {2}✓ PASS {2}/m);
    assert.match(full.text, /^ {2}∅ SKIP {2}/m);
    assert.match(full.text, /^ {2}line-40$/m);
    assert.doesNotMatch(full.text, /^ {2}line-39$/m, "25 lines by default (the last four: the footer, a blank, the runner's two)");
    assert.match(full.text, /^ {2}kinds: unit$/m);
    assert.match(full.text, /^ {2}FAILURES PRESENT — see the ✗ rows above$/m);

    // --failures-only: only the failure, a 40-line tail, the counts line, where the rest is.
    assert.doesNotMatch(fo.text, /PASS|SKIP|fo\.pass|fo\.skip/, "no row of a pass or a skip");
    assert.match(fo.text, /^▶ fo\.bad /m);
    assert.match(fo.text, /^ {2}✗ FAIL {2}/m, "the verdict shape the dashboard parses");
    assert.match(fo.text, new RegExp(`^ {2}--- tail of ${join(root, "fo", "logs", "fo.bad.log").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} ---$`, "m"));
    assert.match(fo.text, /^ {2}line-25$/m);
    assert.match(fo.text, /^ {2}line-60$/m);
    assert.doesNotMatch(fo.text, /^ {2}line-24$/m, "40 lines under --failures-only");
    assert.match(fo.text, /^ {2}✗ {2}fo\.bad +fail: /m, "the failed row in the summary");
    assert.doesNotMatch(fo.text, /kinds: |integrity lane: |excluded: /);
    assert.match(fo.text, /^ {2}FAILURES PRESENT: 1 failed, 1 passed, 1 skipped of 3 entries$/m);
    assert.match(fo.text, new RegExp(`^ {2}results: ${join(root, "fo").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} \\(summary\\.json, junit\\.xml, logs/\\)$`, "m"));

    // --fail-tail sets the tail's length, with or without --failures-only; 0 prints none.
    const three = await runOnce(["--failures-only", "--fail-tail", "8"], join(root, "t3"));
    assert.match(three.text, /^ {2}line-57$/m);
    assert.doesNotMatch(three.text, /^ {2}line-56$/m);
    const none = await runOnce(["--fail-tail", "0"], join(root, "t0"));
    assert.doesNotMatch(none.text, /line-60|--- tail of/);
    assert.match(none.text, /^ {2}log: \S+\/t0\/logs\/fo\.bad\.log$/m, "0 lines still names the log");
    assert.match(none.text, /^ {2}✓ PASS {2}/m, "--fail-tail alone keeps every row");

    // A green run under --failures-only is the summary banner, its counts line and the results line.
    const green = sink();
    assert.equal(await main(["--only", "fo.pass,fo.skip", "--out", join(root, "g"), "--commit", "abcdef0", "--failures-only"], { root, stdout: green, stderr: sink() }), 0);
    assert.match(green.text, /^ {2}ALL SUITES GREEN: 0 failed, 1 passed, 1 skipped of 2 entries$/m);
    assert.doesNotMatch(green.text, /▶ |✓|∅/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ── the default results dir (no --out): the newest N kept ──────────────────────

test("parseKeep: a count of 1 or more, `all` (Infinity), the default 5 when unset; anything else null", () => {
  assert.equal(parseKeep(undefined), RESULTS_KEEP);
  assert.equal(parseKeep(""), RESULTS_KEEP);
  assert.equal(RESULTS_KEEP, 5);
  assert.equal(parseKeep("1"), 1);
  assert.equal(parseKeep("12"), 12);
  assert.equal(parseKeep("all"), Infinity);
  for (const bad of ["0", "-1", "2.5", "x", "5x"]) assert.equal(parseKeep(bad), null, bad);
});

/** A results dir `name` in `base`, its tree's mtimes `ageH` hours ago, with
 *  an owner file naming `owner` (a { pid, startTicks }) unless null. */
function resultsDir(base, name, ageH, owner = { pid: 999_999_999, startTicks: 1 }) {
  const d = join(base, name);
  mkdirSync(join(d, "logs"), { recursive: true });
  writeFileSync(join(d, "logs", "a.log"), "x\n");
  writeFileSync(join(d, "summary.json"), "{}\n");
  if (owner) writeFileSync(join(d, RESULTS_OWNER), JSON.stringify(owner));
  const t = (Date.now() - ageH * 3600_000) / 1000;
  for (const p of [join(d, "logs", "a.log"), join(d, "summary.json"), ...(owner ? [join(d, RESULTS_OWNER)] : []), join(d, "logs"), d]) utimesSync(p, t, t);
  return d;
}

test("pruneResultsDirs: keeps the newest N, removes the older finished ones; never a live run's, `self`, a recent dir with no owner file, another name or a symlink", () => {
  const base = mkdtempSync(join(tmpdir(), "run-suites-keep-"));
  try {
    const alive = (pid) => pid === 4242 || pid === 4343;
    const ticksOf = (pid) => (pid === 4242 ? 77 : pid === 4343 ? 99 : null);
    const kept = ["mandu-suites-aaaaa1", "mandu-suites-aaaaa2", "mandu-suites-aaaaa3"].map((n, i) => resultsDir(base, n, i + 1));
    const old = ["mandu-suites-bbbbb1", "mandu-suites-bbbbb2"].map((n, i) => resultsDir(base, n, 10 + i));
    const liveRun = resultsDir(base, "mandu-suites-live01", 20, { pid: 4242, startTicks: 77 });
    const reused = resultsDir(base, "mandu-suites-reuse1", 21, { pid: 4343, startTicks: 5 });
    const legacyRecent = resultsDir(base, "mandu-suites-legcy1", 0.2, null);
    const legacyOld = resultsDir(base, "mandu-suites-legcy2", 30, null);
    const self = resultsDir(base, "mandu-suites-self01", 40);
    // The legacy recent one is the newest by mtime: push it out of the top N.
    utimesSync(legacyRecent, (Date.now() - 50 * 3600_000) / 1000, (Date.now() - 50 * 3600_000) / 1000);
    const other = resultsDir(base, "mandu-suites-toolongname", 99);
    const notOurs = resultsDir(base, "mdu-run-abc123", 99);
    symlinkSync(old[0], join(base, "mandu-suites-link01"));

    const { removed, live } = pruneResultsDirs(base, { keep: 3, graceMs: 0, self, alive, ticksOf });
    assert.deepEqual(removed.sort(), [...old, reused, legacyOld].sort(), "the older finished ones, a reused pid's and an idle legacy dir");
    assert.deepEqual(live.sort(), [liveRun, legacyRecent].sort());
    for (const d of [...kept, liveRun, legacyRecent, self, other, notOurs]) assert.ok(existsSync(d), d);
    for (const d of removed) assert.ok(!existsSync(d), d);
    assert.ok(lstatSync(join(base, "mandu-suites-link01")).isSymbolicLink(), "a symlink is never followed nor removed");

    // N = 1 keeps only the newest; `all` (Infinity) removes nothing.
    assert.deepEqual(pruneResultsDirs(base, { keep: Infinity, alive, ticksOf }).removed, []);
    assert.deepEqual(pruneResultsDirs(base, { keep: 1, graceMs: 0, self, alive, ticksOf }).removed.sort(), kept.slice(1).sort());
    assert.ok(existsSync(kept[0]) && existsSync(self) && existsSync(liveRun));
    // Another uid's dirs are never touched.
    assert.deepEqual(pruneResultsDirs(base, { keep: 1, graceMs: 0, uid: (process.getuid?.() ?? 0) + 1, alive, ticksOf }).removed, []);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("pruneResultsDirs: the grace period keeps a just-finished dir beyond N (a parallel session has yet to read its logs); one past the grace goes; the grace counts the tree's newest file", () => {
  const base = mkdtempSync(join(tmpdir(), "run-suites-keep-"));
  try {
    const dead = () => false;
    assert.equal(RESULTS_GRACE_HOURS, 6);
    const newest = resultsDir(base, "mandu-suites-new001", 0);
    const justDone = resultsDir(base, "mandu-suites-done01", 0.01);
    const inGrace = resultsDir(base, "mandu-suites-grace1", 5.5);
    const past = resultsDir(base, "mandu-suites-past01", 6.5);
    // An old dir whose log changed an hour ago: the newest file counts.
    const touched = resultsDir(base, "mandu-suites-touch1", 30);
    const t = (Date.now() - 3600_000) / 1000;
    utimesSync(join(touched, "logs", "a.log"), t, t);

    const r = pruneResultsDirs(base, { keep: 1, alive: dead });
    assert.deepEqual(r.removed, [past], "only the dir outside N and past the grace");
    assert.deepEqual(r.recent.sort(), [justDone, inGrace, touched].sort());
    for (const d of [newest, justDone, inGrace, touched]) assert.ok(existsSync(d), d);
    // A shorter grace (hours, as the option gives it) lets the 5.5 h one go too.
    assert.deepEqual(pruneResultsDirs(base, { keep: 1, graceMs: 2 * 3600_000, alive: dead }).removed, [inGrace]);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("parseGraceHours: hours, 0 or more, fractions allowed; the default 6 when unset; anything else null", () => {
  assert.equal(parseGraceHours(undefined), 6);
  assert.equal(parseGraceHours(""), 6);
  assert.equal(parseGraceHours("0"), 0);
  assert.equal(parseGraceHours("1.5"), 1.5);
  assert.equal(parseGraceHours("48"), 48);
  for (const bad of ["-1", "x", " ", "Infinity", "2h"]) assert.equal(parseGraceHours(bad), null, bad);
});

test("makeResultsDir / resultsOwnerLive: the owner file names this process, live while it runs; a dead pid, a reused one or no owner file is not live", () => {
  const base = mkdtempSync(join(tmpdir(), "run-suites-keep-"));
  try {
    const d = makeResultsDir(base);
    assert.match(d.slice(base.length + 1), /^mandu-suites-[A-Za-z0-9]{6}$/);
    const o = JSON.parse(readFileSync(join(d, RESULTS_OWNER), "utf8"));
    assert.equal(o.pid, process.pid);
    assert.equal(resultsOwnerLive(d), true, "this process is live");
    assert.equal(resultsOwnerLive(d, { alive: () => false }), false);
    assert.equal(resultsOwnerLive(d, { ticksOf: () => (o.startTicks ?? 0) + 1 }), o.startTicks == null, "another start time: a reused pid");
    assert.equal(resultsOwnerLive(d, { ticksOf: () => null }), true, "no start time to compare: a live pid counts");
    rmSync(join(d, RESULTS_OWNER));
    assert.equal(resultsOwnerLive(d), null);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("main without --out: the results dir is made in TMPDIR and named on the last line; the older ones pruned to --keep-results past --keep-results-hours (MANDU_TEST_KEEP_RESULTS, _HOURS); --out prunes nothing; a bad N or grace is a usage error", async () => {
  const { root } = fixtureRoot([E("keep.pass", { cmd: ["bash", "-c", "printf '# pass 1\\n# fail 0\\n'"] })]);
  const tmp = join(root, "tmp");
  mkdirSync(tmp);
  const env = { ...process.env, TMPDIR: tmp };
  delete env.MANDU_TEST_KEEP_RESULTS;
  delete env.MANDU_TEST_KEEP_RESULTS_HOURS;
  const ours = () => readdirSync(tmp).filter((n) => n.startsWith(RESULTS_PREFIX)).sort();
  try {
    // Finished runs (dead owners) 1 h, 2 h, 8 h and 9 h ago.
    const olds = ["mandu-suites-old001", "mandu-suites-old002", "mandu-suites-old003", "mandu-suites-old004"].map((n, i) => resultsDir(tmp, n, [1, 2, 8, 9][i]));
    const stdout = sink();
    assert.equal(await main(["--only", "keep.pass", "--commit", "abcdef0", "--keep-results", "1"], { root, stdout, stderr: sink(), env }), 0, stdout.text);
    const m = stdout.text.match(/results: (\S+) \(summary\.json, junit\.xml, logs\/; the newest 1 such dirs and those of the last 6h kept, --keep-results\)/);
    assert.ok(m, stdout.text);
    assert.equal(dirname(m[1]), tmp);
    assert.ok(existsSync(join(m[1], "summary.json")));
    assert.deepEqual(ours(), [basename(m[1]), "mandu-suites-old001", "mandu-suites-old002"].sort(), "this run's (N = 1) and the two within the 6 h grace");
    assert.ok(!existsSync(olds[2]) && !existsSync(olds[3]), "outside N and past the grace");

    // The variables, when no option: N = 1 and no grace prune the 1 h and
    // 2 h ones, but not the first run's, whose owner (this test's process)
    // still runs: the live guard.
    const second = sink();
    const noGrace = { ...env, MANDU_TEST_KEEP_RESULTS: "1", MANDU_TEST_KEEP_RESULTS_HOURS: "0" };
    assert.equal(await main(["--only", "keep.pass", "--commit", "abcdef0"], { root, stdout: second, stderr: sink(), env: noGrace }), 0);
    const m2 = second.text.match(/results: (\S+) \(/);
    assert.match(second.text, /the newest 1 such dirs and those of the last 0h kept/);
    assert.deepEqual(ours(), [basename(m[1]), basename(m2[1])].sort(), "old001 and old002 pruned; the live owner's dir kept");

    // --out: nothing pruned, whatever N and the grace say.
    resultsDir(tmp, "mandu-suites-old005", 5);
    assert.equal(await main(["--only", "keep.pass", "--commit", "abcdef0", "--out", join(root, "o")], { root, stdout: sink(), stderr: sink(), env: noGrace }), 0);
    assert.equal(ours().length, 3);
    assert.ok(!existsSync(join(root, "o", RESULTS_OWNER)), "--out gets no owner file");

    const err = sink();
    assert.equal(await main(["--only", "keep.pass", "--commit", "abcdef0", "--keep-results", "0"], { root, stdout: sink(), stderr: err, env }), 2);
    assert.match(err.text, /--keep-results \(MANDU_TEST_KEEP_RESULTS\) is a count of 1 or more, or all/);
    const err2 = sink();
    assert.equal(await main(["--only", "keep.pass", "--commit", "abcdef0", "--keep-results-hours", "x"], { root, stdout: sink(), stderr: err2, env }), 2);
    assert.match(err2.text, /--keep-results-hours \(MANDU_TEST_KEEP_RESULTS_HOURS\) is hours, 0 or more/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ── the replay records (--replay-store; test-reorganization.md §7.3) ───────────

test("replayPlan / entryEnv / buildArgv: a replay-drill entry gets the store, the run id and the baselines; sandboxed, its own <dir>/<id> as --bind-rw; other kinds nothing", () => {
  const rd = E("integration.differential.fidelity-write-file", { kind: "replay-drill", cwd: "pkg", cmd: ["npm", "test"], env: { MANDU_DIFF_ONLY: "fidelity-write-file", MANDU_REPLAY_STORE: "/from/the/manifest" } });
  const sandboxed = { store: "/o/drills/replay", baselines: "/o/drills/baselines", runId: "gl-1-2", perEntry: true };
  assert.deepEqual(replayPlan(rd, sandboxed), {
    env: { MANDU_REPLAY_STORE: `/o/drills/replay/${rd.id}`, MANDU_REPLAY_RUN_ID: "gl-1-2", MANDU_REPLAY_BASELINES: `/o/drills/baselines/${rd.id}` },
    dirs: [`/o/drills/replay/${rd.id}`, `/o/drills/baselines/${rd.id}`],
  });
  const { argv } = buildArgv(rd, { root: "/r", sandbox: "/w/ns-run.sh", replay: sandboxed });
  assert.deepEqual(argv.slice(0, 7), ["/w/ns-run.sh", "--chdir", "/r/pkg", "--bind-rw", `/o/drills/replay/${rd.id}`, "--bind-rw", `/o/drills/baselines/${rd.id}`]);
  const setenv = Object.fromEntries(argv.flatMap((a, i) => (a === "--setenv" ? [[argv[i + 1], argv[i + 2]]] : [])));
  assert.equal(setenv.MANDU_REPLAY_STORE, `/o/drills/replay/${rd.id}`, "run-suites' store wins over an entry's own");
  assert.equal(setenv.MANDU_REPLAY_RUN_ID, "gl-1-2");
  assert.equal(setenv.MANDU_HOME, FIXED_ENV.MANDU_HOME, "the fixed pins still win");
  // unsandboxed: one shared store (WP0's run.json is O_EXCL: the first shard wins)
  const shared = { ...sandboxed, perEntry: false };
  assert.equal(entryEnv(rd, shared).MANDU_REPLAY_STORE, "/o/drills/replay");
  assert.equal(entryEnv(rd, { ...shared, baselines: null }).MANDU_REPLAY_BASELINES, undefined, "no baselines dir: unset");
  // a kernel-lane replay entry: no wrapper, the same per-entry dirs in its env
  const k = E("integration.launcher-kernel-tier", { kind: "replay-drill", needs: ["kernel"] });
  assert.deepEqual(buildArgv(k, { root: "/r", sandbox: "/w/ns-run.sh", replay: sandboxed }).argv, ["true"]);
  assert.equal(entryEnv(k, sandboxed).MANDU_REPLAY_STORE, `/o/drills/replay/${k.id}`);
  // not a replay-drill, or no store: nothing
  for (const [x, r] of [[E("u"), sandboxed], [rd, null], [rd, { ...sandboxed, store: null }]]) {
    assert.equal(replayPlan(x, r), null);
    assert.ok(!buildArgv(x, { root: "/r", sandbox: "/w/ns-run.sh", replay: r }).argv.includes("--bind-rw"));
  }
  assert.deepEqual(replayHostPaths({ MANDU_HOME: "/m" }, "/h"), { store: "/m/runs/drills/replay", baselines: "/m/runs/drills/baselines" });
  assert.deepEqual(REPLAY_VARS, ["MANDU_REPLAY_STORE", "MANDU_REPLAY_RUN_ID", "MANDU_REPLAY_BASELINES", "MANDU_REPLAY_BASELINES_SEED"]);
});

test("replayPlan: the read-only seed store and the baseline mode (step 5 decision 8) pass as they are, shared, never bound writable", () => {
  const rd = E("integration.replay-push.claude", { kind: "replay-drill" });
  const r = { store: "/o/drills/replay", baselines: "/o/drills/baselines", runId: "gl-1-2", perEntry: true, seed: "/t/.mandu-ci/baselines", baselineMode: "use" };
  const plan = replayPlan(rd, r);
  assert.equal(plan.env.MANDU_REPLAY_BASELINES_SEED, "/t/.mandu-ci/baselines", "one shared seed, not per entry");
  assert.equal(plan.env.MANDU_REPLAY_BASELINE, "use");
  assert.deepEqual(plan.dirs, [`/o/drills/replay/${rd.id}`, `/o/drills/baselines/${rd.id}`], "the seed is not a dir to create or bind");
  const { argv } = buildArgv(rd, { root: "/r", sandbox: "/w/ns-run.sh", replay: r });
  assert.ok(!argv.join(" ").includes("--bind-rw /t/.mandu-ci/baselines"), "the seed is never writable in the box");
  const setenv = Object.fromEntries(argv.flatMap((a, i) => (a === "--setenv" ? [[argv[i + 1], argv[i + 2]]] : [])));
  assert.equal(setenv.MANDU_REPLAY_BASELINES_SEED, "/t/.mandu-ci/baselines");
  assert.equal(setenv.MANDU_REPLAY_BASELINE, "use");
  const without = replayPlan(rd, { ...r, seed: undefined, baselineMode: undefined });
  assert.equal("MANDU_REPLAY_BASELINES_SEED" in without.env, false);
  assert.equal("MANDU_REPLAY_BASELINE" in without.env, false, "without the flag the caller's mode stands");
  assert.equal("MANDU_REPLAY_BLOCKING" in without.env, false, "without --replay-blocking the caller's stands");
});

test("replayPlan: `blocking` (--replay-blocking, the per-push switch of test-reorganization.md §6.9) sets MANDU_REPLAY_BLOCKING=1 into the box; only for a replay-drill entry", () => {
  const rd = E("integration.replay-push.claude", { kind: "replay-drill" });
  const r = { store: "/o/drills/replay", baselines: "/o/drills/baselines", runId: "gl-1-2", perEntry: true, baselineMode: "use", blocking: true };
  assert.equal(replayPlan(rd, r).env.MANDU_REPLAY_BLOCKING, "1");
  const { argv } = buildArgv(rd, { root: "/r", sandbox: "/w/ns-run.sh", replay: r });
  const setenv = Object.fromEntries(argv.flatMap((a, i) => (a === "--setenv" ? [[argv[i + 1], argv[i + 2]]] : [])));
  assert.equal(setenv.MANDU_REPLAY_BLOCKING, "1", "a sandboxed entry is given it with --setenv");
  assert.equal(replayPlan(E("u"), r), null, "a unit entry is never given it");
});

test("main --replay-baselines-seed / --replay-baseline-mode / --replay-blocking: need --replay-store; the mode is record, use or off; all reach a replay-drill entry", async () => {
  const { root } = fixtureRoot([E("rd", { kind: "replay-drill", cmd: ["bash", "-c", 'echo "seed=${MANDU_REPLAY_BASELINES_SEED:-unset} mode=${MANDU_REPLAY_BASELINE:-unset} blocking=${MANDU_REPLAY_BLOCKING:-unset}"; echo "# pass 1"'] })]);
  try {
    for (const [args, re] of [
      [["--replay-baselines-seed", "/s"], /--replay-baselines-seed needs --replay-store/],
      [["--replay-baseline-mode", "use"], /--replay-baseline-mode needs --replay-store/],
      [["--replay-blocking"], /--replay-blocking needs --replay-store/],
      [["--replay-store", "/x", "--replay-baseline-mode", "always"], /--replay-baseline-mode is one of record, use, off/],
    ]) {
      const err = sink();
      assert.equal(await main(["--kind", "replay-drill", ...args, "--dry-run"], { root, stdout: sink(), stderr: err }), 2, args.join(" "));
      assert.match(err.text, re);
    }
    const out = join(root, "out");
    const env = { ...process.env, MANDU_REPLAY_BASELINES_SEED: "/leaked/seed" };
    delete env.MANDU_REPLAY_BLOCKING;
    // --replay-baselines given: unsandboxed, the default is the caller's store (a /dev/null home in CI)
    assert.equal(await main(["--kind", "replay-drill", "--out", out, "--commit", "b814495e", "--replay-store", join(out, "drills", "replay"),
      "--replay-baselines", join(out, "drills", "baselines"), "--replay-baselines-seed", join(root, "seed"), "--replay-baseline-mode", "use", "--replay-blocking"], { root, stdout: sink(), stderr: sink(), env }), 0);
    assert.match(readFileSync(join(out, "logs", "rd.log"), "utf8"), new RegExp(`^seed=${join(root, "seed").replace(/[.]/g, "\\.")} mode=use blocking=1$`, "m"));
    // no seed flag: the caller's leaked seed is stripped
    const out2 = join(root, "out2");
    assert.equal(await main(["--kind", "replay-drill", "--out", out2, "--commit", "b814495e", "--replay-store", join(out2, "drills", "replay"),
      "--replay-baselines", join(out2, "drills", "baselines")], { root, stdout: sink(), stderr: sink(), env }), 0);
    assert.match(readFileSync(join(out2, "logs", "rd.log"), "utf8"), /^seed=unset mode=unset blocking=unset$/m);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("main --replay-store: sandboxed, each replay-drill entry writes its record into its own bound dir; nothing else sees the variables, not even the caller's", async () => {
  const write = 'echo "store=${MANDU_REPLAY_STORE:-unset} run=${MANDU_REPLAY_RUN_ID:-unset} base=${MANDU_REPLAY_BASELINES:-unset}"; ' +
    '[[ -n "${MANDU_REPLAY_STORE:-}" ]] && mkdir -p "$MANDU_REPLAY_STORE/$MANDU_REPLAY_RUN_ID/sessions" && echo "{}" > "$MANDU_REPLAY_STORE/$MANDU_REPLAY_RUN_ID/run.json"; echo "# pass 1"';
  const { root, wrapper } = fixtureRoot([
    E("rd.one", { kind: "replay-drill", cmd: ["bash", "-c", write] }),
    E("rd.two", { kind: "replay-drill", cmd: ["bash", "-c", write] }),
    E("plain.unit", { kind: "unit", cmd: ["bash", "-c", write] }),
  ]);
  const out = join(root, "out");
  const caller = { ...process.env, MANDU_REPLAY_STORE: "/leaked/from/the/caller", MANDU_REPLAY_RUN_ID: "leak", MANDU_REPLAY_BASELINES: "/leak" };
  try {
    const rc = await main(["--kind", "replay-drill,unit", "--jobs", "2", "--sandbox", wrapper, "--out", out, "--run-id", "gl-7-8", "--commit", "b814495e",
      "--replay-store", join(out, "drills", "replay"), "--replay-baselines", join(out, "drills", "baselines")], { root, stdout: sink(), stderr: sink(), env: caller });
    assert.equal(rc, 0, readFileSync(join(out, "logs", "rd.one.log"), "utf8"));
    for (const id of ["rd.one", "rd.two"]) {
      const log = readFileSync(join(out, "logs", `${id}.log`), "utf8");
      assert.match(log, new RegExp(`^store=${join(out, "drills", "replay", id).replace(/[.]/g, "\\.")} run=gl-7-8 base=${join(out, "drills", "baselines", id).replace(/[.]/g, "\\.")}$`, "m"));
      assert.ok(existsSync(join(out, "drills", "replay", id, "gl-7-8", "run.json")), `${id}'s record is in its own dir`);
      assert.ok(existsSync(join(out, "drills", "baselines", id)), "its baselines dir exists (empty: the box could not have been given one with files)");
    }
    assert.match(readFileSync(join(out, "logs", "plain.unit.log"), "utf8"), /^store=unset run=unset base=unset$/m, "a unit entry: none, the caller's leak stripped");
    const calls = wrapperCalls(root);
    const recordBinds = (c) => (c.match(/--bind-rw \S+/g) ?? []).filter((b) => b.includes(join(out, "drills")));
    assert.equal(calls.filter((c) => recordBinds(c).length).length, 2, "only the replay-drill entries get a record bind (every entry gets its TMPDIR)");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("main without --replay-store: no entry gets a store, whatever the caller's environment holds; --replay-baselines alone is a usage error", async () => {
  const { root } = fixtureRoot([E("rd", { kind: "replay-drill", cmd: ["bash", "-c", 'echo "store=${MANDU_REPLAY_STORE:-unset}"; echo "# pass 1"'] })]);
  const out = join(root, "out");
  try {
    assert.equal(await main(["--kind", "replay-drill", "--out", out, "--commit", "b814495e"], { root, stdout: sink(), stderr: sink(), env: { ...process.env, MANDU_REPLAY_STORE: "/leak" } }), 0);
    assert.match(readFileSync(join(out, "logs", "rd.log"), "utf8"), /^store=unset$/m);
    const err = sink();
    assert.equal(await main(["--kind", "replay-drill", "--replay-baselines", "/x", "--dry-run"], { root, stdout: sink(), stderr: err }), 2);
    assert.match(err.text, /--replay-baselines needs --replay-store/);
    // unsandboxed, the baselines default to the CALLER's store (as the watch store does)
    const dry = sink();
    assert.equal(await main(["--kind", "replay-drill", "--replay-store", "/s", "--run-id", "r1", "--dry-run"], { root, stdout: dry, stderr: sink(), env: { ...process.env, MANDU_HOME: "/caller" } }), 0);
    assert.match(dry.text, /env: MANDU_REPLAY_STORE=\/s MANDU_REPLAY_RUN_ID=r1 MANDU_REPLAY_BASELINES=\/caller\/runs\/drills\/baselines/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("main --frozen: frozen entries run only with it (any kind); without it the summary says they did not run", async () => {
  const pass = ["bash", "-c", "echo '# pass 1'"];
  const { root } = fixtureRoot([E("u1", { cmd: pass }), E("fz", { kind: "replay-drill", frozen: true, axis: "full", cmd: pass })]);
  try {
    const go = async (args, out) => {
      const stdout = sink();
      assert.equal(await main([...args, "--out", join(root, out), "--commit", "abcdef0"], { root, stdout, stderr: sink() }), 0, stdout.text);
      const sm = JSON.parse(readFileSync(join(root, out, "summary.json"), "utf8"));
      validateSummary(sm);
      return { ids: sm.entries.map((x) => x.id), text: stdout.text, sm };
    };
    const k = await go(["--kind", "unit,replay-drill"], "k");
    assert.deepEqual(k.ids, ["u1"], "a kinds run leaves the frozen entry out, even of a selected kind");
    assert.match(k.text, /integrity lane: the FROZEN entries did not run \(--frozen\)/);
    const f = await go(["--frozen"], "f");
    assert.deepEqual(f.ids, ["fz"], "--frozen alone: the frozen lane");
    assert.equal(f.sm.entries[0].kind, "replay-drill", "a frozen entry keeps its kind");
    assert.doesNotMatch(f.text, /FROZEN entries did not run/);
    assert.deepEqual((await go(["--kind", "unit", "--frozen"], "kf")).ids, ["u1", "fz"]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ── results helpers ────────────────────────────────────────────────────────────

test("buildSummary: a stage error makes the run an error; control characters never reach a text field", () => {
  const s = buildSummary({
    run: "local-x", source: "local", commit: "abcdef0+dirty", ref: "feat/‮evil\nref", started: 0, finished: 1500,
    stages: { build: { result: "error", duration_s: 2 } }, results: [],
  });
  validateSummary(s);
  assert.equal(s.result, "error");
  assert.match(s.reason, /stage build: error/);
  assert.equal(s.stages.suites.duration_s, 1.5);
});

test("buildSummary: a flaky (non-blocking) entry's red is reported but does not fail the run", () => {
  const row = (id, result, extra = {}) => ({ id, kind: "replay-drill", result, pass: 1, fail: result === "fail" ? 1 : 0, skip: 0, duration_s: 1, log: `logs/${id}.log`, ...extra });
  const soft = buildSummary({
    run: "local-y", source: "local", commit: "abcdef0", ref: "master", started: 0, finished: 1000,
    results: [row("a", "pass"), row("b.flaky", "fail", { nonBlocking: true })],
  });
  validateSummary(soft);
  assert.equal(soft.result, "pass");
  assert.equal(soft.stages.suites.result, "pass");
  assert.equal(soft.entries.find((x) => x.id === "b.flaky").result, "fail", "the entry keeps its own red");
  assert.match(soft.reason, /non-blocking \(flaky, reported or nightly\) entries not green: b\.flaky \(fail\)/);
  assert.ok(!("nonBlocking" in soft.entries[1]), "the schema carries no extra field");
  const hard = buildSummary({
    run: "local-z", source: "local", commit: "abcdef0", ref: "master", started: 0, finished: 1000,
    results: [row("a", "fail"), row("b.flaky", "fail", { nonBlocking: true })],
  });
  assert.equal(hard.result, "fail");
  assert.match(hard.reason, /1 entry not green: a \(fail\)/);
});

test("resolveCommit / defaultRunId: HEAD with +dirty; the run id carries the short sha", () => {
  assert.equal(resolveCommit("/", "0123456789abcdef"), "0123456789abcdef");
  const c = resolveCommit(process.cwd());
  if (c) assert.match(c, COMMIT_RE);
  assert.equal(defaultRunId("0123456789abcdef0123+dirty", Date.UTC(2026, 8, 28, 10, 0, 0)), "local-20260928T100000Z-0123456789ab");
});

test("capLog keeps the tail of an oversized log behind a marker line", () => {
  const dir = mkdtempSync(join(tmpdir(), "run-suites-cap-"));
  try {
    const p = join(dir, "x.log");
    const lines = Array.from({ length: 5000 }, (_, i) => `line ${i}`).join("\n");
    writeFileSync(p, `${lines}\n# pass 1\n`);
    assert.equal(capLog(p, 4096), true);
    const kept = readFileSync(p, "utf8");
    assert.ok(statSync(p).size <= 4096 + 120);
    assert.match(kept, /^\[run-suites\] log truncated: kept the last \d+ of \d+ bytes\n/);
    assert.match(kept, /line 4999\n# pass 1\n$/);
    assert.ok(!kept.includes("line 10\n"));
    assert.equal(capLog(p, 1 << 20), false, "under the cap: untouched");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("junitXml escapes and strips what XML cannot carry", () => {
  const dir = mkdtempSync(join(tmpdir(), "run-suites-junit-"));
  try {
    mkdirSync(join(dir, "logs"));
    writeFileSync(join(dir, "logs", "a.log"), "bad \u0001byte & <tag>\n");
    const xml = junitXml([{ id: "a", kind: "unit", result: "fail", pass: 0, fail: 1, skip: 0, duration_s: 1, log: "logs/a.log", summary: "s", reason: 'exit "1"' }], dir);
    assert.match(xml, /message="exit &quot;1&quot;"/);
    assert.match(xml, /<property name="kind" value="unit"\/>/);
    assert.match(xml, /<testcase classname="unit" name="a"/);
    assert.match(xml, /bad byte &amp; &lt;tag&gt;/);
    assert.ok(!xml.includes("\u0001"));
    assert.ok(existsSync(join(dir, "logs", "a.log")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function pick(c) {
  return { format: c.format, pass: c.pass, fail: c.fail, skip: c.skip };
}

test("needsShortTmpdir: only a darwin run whose TMPDIR is too long for a Unix socket in a mkdtemp dir", () => {
  // macOS gives every user a 49-byte TMPDIR; a suite's arbiter instance socket under it overshoots sun_path.
  assert.equal(needsShortTmpdir("darwin", "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/"), true);
  assert.equal(needsShortTmpdir("darwin", "/tmp"), false);
  assert.equal(needsShortTmpdir("darwin", "/tmp/"), false, "a trailing slash is not counted");
  assert.equal(needsShortTmpdir("darwin", "x".repeat(DARWIN_TMPDIR_MAX)), false);
  assert.equal(needsShortTmpdir("darwin", "x".repeat(DARWIN_TMPDIR_MAX + 1)), true);
  assert.equal(needsShortTmpdir("linux", "/var/folders/gc/bm49jf5s3dn6xym2llklvsqc0000gp/T/"), false, "Linux keeps its TMPDIR");
});

// ── each entry's own TMPDIR and the leftover check (test-organization.md §8.5) ──

// The template names $TMPDIR: macOS's mktemp with none makes its dir in the
// per-user confstr temp dir, not in $TMPDIR (the macOS wrapper suite, 2026-10-09).
const TMP_ENTRIES = [
  E("clean", { cmd: ["bash", "-c", "echo \"tmp=$TMPDIR\"; d=\"$(mktemp -d \"$TMPDIR/tmp.XXXXXX\")\"; touch \"$d/x\"; rm -rf \"$d\"; mkdir -p \"$TMPDIR/tsx-$(id -u)/c\"; echo '# pass 1'"] }),
  E("leaky", { cmd: ["bash", "-c", "echo \"tmp=$TMPDIR\"; d=\"$(mktemp -d \"$TMPDIR/tmp.XXXXXX\")\"; mkdir -p \"$d/a/b\"; touch \"$d/a/b/f\" \"$TMPDIR/stray.sock\"; chmod 0500 \"$d/a\"; echo '# pass 1'"] }),
  E("red.leaky", { cmd: ["bash", "-c", "echo \"tmp=$TMPDIR\"; touch \"$TMPDIR/left\"; echo '# pass 0'; echo '# fail 1'; exit 1"] }),
  // A daemon in the entry's group that removes its socket dir on the SIGTERM
  // the runner sends the group when the entry exits: no leftover.
  E("daemon", { cmd: ["bash", "-c", "echo \"tmp=$TMPDIR\"; d=\"$TMPDIR/daemon\"; ( trap 'rm -rf \"$d\"; exit 0' TERM; mkdir \"$d\"; touch \"$d/sock\"; while :; do sleep 0.1; done ) & while [[ ! -e \"$d/sock\" ]]; do sleep 0.01; done; echo '# pass 1'"] }),
];
const tmpsOf = (out, ids) => Object.fromEntries(ids.map((id) => [id, /^tmp=(\S+)$/m.exec(readFileSync(join(out, "logs", `${id}.log`), "utf8"))?.[1]]));

test("main: each entry runs with a fresh TMPDIR of its own under one per-run dir; a leftover fails the entry with its names; the dirs are gone after the run", async () => {
  const { root, wrapper } = fixtureRoot(TMP_ENTRIES);
  try {
    for (const sandboxed of [false, true]) {
      const out = join(root, sandboxed ? "boxed" : "direct");
      const stdout = sink();
      const rc = await main(["--kind", "unit", "--jobs", "4", "--out", out, "--commit", "abcdef0", ...(sandboxed ? ["--sandbox", wrapper] : [])], { root, stdout, stderr: sink() });
      assert.equal(rc, 1, stdout.text);
      const s = JSON.parse(readFileSync(join(out, "summary.json"), "utf8"));
      validateSummary(s);
      const by = Object.fromEntries(s.entries.map((x) => [x.id, x.result]));
      assert.deepEqual(by, { clean: "pass", leaky: "fail", "red.leaky": "fail", daemon: "pass" }, stdout.text);
      assert.match(s.reason, /leaky \(fail\)/);
      const tmps = tmpsOf(out, ["clean", "leaky", "red.leaky", "daemon"]);
      const dirs = Object.values(tmps);
      assert.equal(new Set(dirs).size, 4, "one TMPDIR per entry");
      assert.equal(new Set(dirs.map((d) => dirname(d))).size, 1, "all under one per-run dir");
      assert.equal(new Set(dirs.map((d) => d.length)).size, 1, "every entry's TMPDIR has the same length");
      assert.match(dirname(dirs[0]), process.platform === "darwin" ? /\/[A-Za-z0-9]{6}$/ : /\/mdu-run-[^/]+$/);
      assert.ok(dirs.every((d) => d.length - tmpdir().length < 30), "short enough for a socket under it");
      assert.ok(!existsSync(dirname(dirs[0])), "the per-run dir is removed at the end, the read-only leftover too");
      const leakyLog = readFileSync(join(out, "logs", "leaky.log"), "utf8");
      assert.match(leakyLog, /\[run-suites\] fail: left 2 entries \(5 inodes\) in its TMPDIR: stray\.sock, tmp\.\w+/);
      assert.match(readFileSync(join(out, "logs", "red.leaky.log"), "utf8"), /\[run-suites\] fail: exit 1; left 1 entry \(1 inodes\) in its TMPDIR: left/);
      assert.doesNotMatch(readFileSync(join(out, "logs", "clean.log"), "utf8"), /TMPDIR:/, "tsx's compile cache is not a leftover");
      assert.doesNotMatch(readFileSync(join(out, "logs", "daemon.log"), "utf8"), /TMPDIR:/, "the group's daemon cleaned up before the count");
      assert.match(stdout.text, /^ {2}✗ FAIL {2}left 2 entries \(5 inodes\) in its TMPDIR: stray\.sock/m);
      assert.match(stdout.text, /2 entries left files in their TMPDIR: leaky \(2\), red\.leaky \(1\)/);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("main --tmp-leftovers warn (or MANDU_TEST_TMP_LEFTOVERS=warn): a leftover is reported, not a failure; anything else is a usage error", async () => {
  const { root } = fixtureRoot([TMP_ENTRIES[1]]);
  try {
    const out = join(root, "o");
    const stdout = sink();
    assert.equal(await main(["--kind", "unit", "--tmp-leftovers", "warn", "--out", out, "--commit", "abcdef0"], { root, stdout, stderr: sink() }), 0, stdout.text);
    assert.match(stdout.text, /^ {2}⚠ TMPDIR {2}left 2 entries/m);
    assert.match(stdout.text, /\(--tmp-leftovers warn: not a failure\): leaky \(2\)/);
    assert.match(readFileSync(join(out, "logs", "leaky.log"), "utf8"), /\[run-suites\] TMPDIR: left 2 entries/);
    assert.ok(!existsSync(dirname(tmpsOf(out, ["leaky"]).leaky)), "removed in warn mode too");
    const out2 = join(root, "o2");
    assert.equal(await main(["--kind", "unit", "--out", out2, "--commit", "abcdef0"], { root, stdout: sink(), stderr: sink(), env: { ...process.env, MANDU_TEST_TMP_LEFTOVERS: "warn" } }), 0);
    const err = sink();
    assert.equal(await main(["--kind", "unit", "--tmp-leftovers", "off", "--commit", "abcdef0"], { root, stdout: sink(), stderr: err }), 2);
    assert.match(err.text, /--tmp-leftovers \(MANDU_TEST_TMP_LEFTOVERS\) is fail or warn/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("tmpLeftovers / leftoverText / removeTree: names sorted without the tools' caches, inodes counted without following symlinks; a read-only tree is removed", () => {
  const dir = mkdtempSync(join(tmpdir(), "run-suites-left-"));
  try {
    assert.deepEqual(tmpLeftovers(dir), { names: [], inodes: 0 });
    mkdirSync(join(dir, TSX_CACHE, "x"), { recursive: true });
    mkdirSync(join(dir, "node-compile-cache", "v22"), { recursive: true });
    mkdirSync(join(dir, "tsx-0"));
    mkdirSync(join(dir, "opencode"));
    writeFileSync(join(dir, ".bun-1000-f9ff78253ed86245.so"), "");
    mkdirSync(join(dir, "claude-1000", "-tmp-x", "0f1e2d3c", "tasks"), { recursive: true });
    writeFileSync(join(dir, "claude-1000", "-tmp-x", "0f1e2d3c", "tasks", "t.output"), "");
    mkdirSync(join(dir, "claude-0"));
    assert.deepEqual(tmpLeftovers(dir), { names: [], inodes: 0 }, "the tools' caches alone are no leftover");
    for (const n of ["claude-x", "claude-1000x", "claude-"]) {
      mkdirSync(join(dir, n));
      assert.deepEqual(tmpLeftovers(dir).names, [n], `only claude-<uid> is Claude Code's, not ${n}`);
      rmSync(join(dir, n), { recursive: true });
    }
    writeFileSync(join(dir, ".bun-fixture.so"), "");
    assert.deepEqual(tmpLeftovers(dir).names, [".bun-fixture.so"], "only .bun-<uid>-<hex>.so is Bun's");
    rmSync(join(dir, ".bun-fixture.so"));
    mkdirSync(join(dir, "tsx-fixture-x"));
    assert.deepEqual(tmpLeftovers(dir).names, ["tsx-fixture-x"], "only tsx-<uid> is tsx's");
    rmSync(join(dir, "tsx-fixture-x"), { recursive: true });
    mkdirSync(join(dir, "b", "c"), { recursive: true });
    writeFileSync(join(dir, "b", "c", "f"), "");
    writeFileSync(join(dir, "a"), "");
    symlinkSync("/", join(dir, "b", "root-link"));
    assert.deepEqual(tmpLeftovers(dir), { names: ["a", "b"], inodes: 5 });
    assert.equal(leftoverText({ names: ["a"], inodes: 1 }), "left 1 entry (1 inodes) in its TMPDIR: a");
    const many = Array.from({ length: 12 }, (_, i) => `n${i}`);
    assert.match(leftoverText({ names: many, inodes: 12 }), /: n0, .*, n9, … \(\+2 more\)$/);
    chmodSync(join(dir, "b", "c"), 0o500);
    chmodSync(join(dir, "b"), 0o500);
    assert.equal(removeTree(dir), true);
    assert.equal(existsSync(dir), false);
    assert.equal(removeTree(dir), true, "a missing tree is removed");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runEntry: an unsandboxed entry with no XDG_RUNTIME_DIR gets a fresh one beside its TMPDIR (not counted, removed); a caller's stands", async () => {
  const out = mkdtempSync(join(tmpdir(), "run-suites-xdg-"));
  const runTmp = makeRunTmp(out);
  try {
    mkdirSync(join(out, "logs"));
    const x = E("rt", { cmd: ["bash", "-c", "echo \"rt=${XDG_RUNTIME_DIR:-none}\"; mkdir -p \"$XDG_RUNTIME_DIR/mandu/instances\"; echo '# pass 1'"] });
    const { XDG_RUNTIME_DIR: _drop, ...noRt } = process.env;
    const tmp = entryTmpDir(runTmp, 0);
    const r = await runEntry(x, { root: out, outDir: out, baseEnv: noRt, tmp });
    assert.equal(r.result, "pass", readFileSync(join(out, r.log), "utf8"));
    assert.match(readFileSync(join(out, r.log), "utf8"), new RegExp(`^rt=${tmp.replace(/[.]/g, "\\.")}\\.rt$`, "m"));
    assert.ok(!existsSync(`${tmp}.rt`) && !existsSync(tmp), "both removed");
    const own = join(out, "own-rt");
    mkdirSync(own);
    const tmp2 = entryTmpDir(runTmp, 1);
    const r2 = await runEntry({ ...x, id: "rt2" }, { root: out, outDir: out, baseEnv: { ...noRt, XDG_RUNTIME_DIR: own }, tmp: tmp2 });
    assert.match(readFileSync(join(out, r2.log), "utf8"), new RegExp(`^rt=${own.replace(/[.]/g, "\\.")}$`, "m"));
    assert.ok(existsSync(join(own, "mandu", "instances")), "the caller's runtime dir is the caller's");
  } finally {
    removeTree(runTmp);
    rmSync(out, { recursive: true, force: true });
  }
});

// ── what escapes the group and the TMPDIR: strays and the outside check (§8.5) ──

const waitDead = async (pids) => {
  for (let i = 0; i < 50 && pids.some(alive); i++) await new Promise((r) => setTimeout(r, 100));
  return pids.filter(alive);
};
/** Shell: start `cmd` in the background, append its pid to `pids`, and wait
 *  until it leads its own session (setsid done), so the entry's exit (and its
 *  group's SIGTERM) cannot beat it. */
const detached = (cmd, pids) => `${cmd} & p=$!; echo $p >> '${pids}'; until [ "$(ps -o sid= -p $p | tr -d ' ')" = "$p" ]; do sleep 0.01; done`;
const killAll = (file) => {
  const text = existsSync(file) ? readFileSync(file, "utf8") : "";
  for (const p of text.split("\n").map(Number).filter(Boolean)) { try { process.kill(p, "SIGKILL"); } catch { /* gone */ } }
};

test("main: a daemon that left the entry's process group (setsid) is found by the TMPDIR it names (env, cwd or an open file), killed, and fails the entry", { skip: process.platform !== "linux" && "stray detection reads Linux /proc" }, async () => {
  const scratch = mkdtempSync(join(tmpdir(), "run-suites-stray-"));
  const pids = join(scratch, "pids");
  // Three setsid daemons: one keeps the environment; one drops it (env -i)
  // but runs in the TMPDIR; one drops it, runs in / and holds a log there.
  const daemons = [
    `(${detached("setsid sleep 300 </dev/null >/dev/null 2>&1", pids)})`,
    `(cd "$TMPDIR"; ${detached("setsid env -i sleep 301 </dev/null >/dev/null 2>&1", pids)})`,
    `(cd /; ${detached("setsid env -i sleep 302 </dev/null >\"$TMPDIR/d.log\" 2>&1", pids)})`,
  ].join("; ");
  const { root, wrapper } = fixtureRoot([
    E("strays", { cmd: ["bash", "-c", `${daemons}; echo '# pass 1'`] }),
    E("clean", { cmd: ["bash", "-c", "sleep 0.2 & wait; echo '# pass 1'"] }),
    // One the suite stopped just before it exited, still shutting down: no stray.
    E("stopping", { cmd: ["bash", "-c", `${detached(`setsid bash -c 'trap "sleep 0.5; exit 0" TERM; while :; do sleep 0.1; done' </dev/null >/dev/null 2>&1`, join(scratch, "stopping.pid"))}; kill -TERM $p; echo '# pass 1'`] }),
  ]);
  try {
    for (const sandboxed of [false, true]) {
      writeFileSync(pids, "");
      const out = join(root, sandboxed ? "boxed" : "direct");
      const stdout = sink();
      const rc = await main(["--kind", "unit", "--jobs", "2", "--out", out, "--commit", "abcdef0", ...(sandboxed ? ["--sandbox", wrapper] : [])], { root, stdout, stderr: sink() });
      assert.equal(rc, 1, stdout.text);
      const s = JSON.parse(readFileSync(join(out, "summary.json"), "utf8"));
      validateSummary(s);
      assert.deepEqual(Object.fromEntries(s.entries.map((x) => [x.id, x.result])), { strays: "fail", clean: "pass", stopping: "pass" }, stdout.text);
      const started = readFileSync(pids, "utf8").trim().split("\n").map(Number);
      assert.equal(started.length, 3);
      assert.deepEqual(await waitDead(started), [], "every stray was killed");
      const log = readFileSync(join(out, "logs", "strays.log"), "utf8");
      assert.match(log, /\[run-suites\] fail: left 3 processes running outside its process group \(killed\): /);
      for (const p of started) assert.match(log, new RegExp(`\\b${p} \\(sleep 30[0-2]\\)`), `pid ${p} named`);
      assert.match(log, /left 1 entry \(1 inodes\) in its TMPDIR: d\.log/, "the file the stray held is a leftover too");
      assert.match(stdout.text, /1 entry left processes running outside their process group: strays \(3\)/);
      assert.doesNotMatch(readFileSync(join(out, "logs", "clean.log"), "utf8"), /outside its process group/);
      assert.doesNotMatch(readFileSync(join(out, "logs", "stopping.log"), "utf8"), /outside its process group/, "it went by itself within the grace");
    }
  } finally {
    killAll(pids);
    killAll(join(scratch, "stopping.pid"));
    rmSync(root, { recursive: true, force: true });
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("main --tmp-leftovers warn: a stray is still killed and reported, not a failure", { skip: process.platform !== "linux" && "stray detection reads Linux /proc" }, async () => {
  const scratch = mkdtempSync(join(tmpdir(), "run-suites-stray-"));
  const pids = join(scratch, "pids");
  const { root } = fixtureRoot([E("strays", { cmd: ["bash", "-c", `${detached("setsid sleep 300 </dev/null >/dev/null 2>&1", pids)}; echo '# pass 1'`] })]);
  try {
    const stdout = sink();
    assert.equal(await main(["--kind", "unit", "--tmp-leftovers", "warn", "--out", join(root, "o"), "--commit", "abcdef0"], { root, stdout, stderr: sink() }), 0, stdout.text);
    assert.match(stdout.text, /^ {2}⚠ STRAYS {2}left 1 process running outside its process group \(killed\)/m);
    assert.deepEqual(await waitDead([Number(readFileSync(pids, "utf8"))]), []);
  } finally {
    killAll(pids);
    rmSync(root, { recursive: true, force: true });
    rmSync(scratch, { recursive: true, force: true });
  }
});

// A daemon that names nothing of its entry: setsid, an empty environment, cwd
// /, every descriptor /dev/null. Only its ancestry is left: the entry's
// subreaper (lib/subreaper.py) adopts it when its parent exits.
const anonymous = (n, pids) => `(cd /; ${detached(`setsid env -i /bin/sh -c 'exec sleep ${n}' </dev/null >/dev/null 2>&1`, pids)})`;
const reaperProbe = mkdtempSync(join(tmpdir(), "run-suites-reaper-"));
process.on("exit", () => rmSync(reaperProbe, { recursive: true, force: true }));
const reaperSkip = process.platform !== "linux" ? "the subreaper is Linux's" : !subreaperBinary(reaperProbe) && "no cc to build the subreaper here";

test("main: a daemon that names nothing of its entry (no environment, cwd /, nothing open there) is the subreaper's orphan: killed, and it fails the entry", { skip: reaperSkip }, async () => {
  const scratch = mkdtempSync(join(tmpdir(), "run-suites-stray-"));
  const pids = join(scratch, "pids");
  const { root, wrapper } = fixtureRoot([
    E("anon", { cmd: ["bash", "-c", `${anonymous(303, pids)}; echo '# pass 1'`] }),
    // Its exit code and signal still come through the subreaper.
    E("three", { cmd: ["bash", "-c", "echo '# pass 1'; exit 3"] }),
    E("signalled", { cmd: ["bash", "-c", "echo '# pass 1'; kill -USR1 $$"] }),
    E("absent", { cmd: ["run-suites-no-such-command-xyz"] }),
  ]);
  try {
    for (const sandboxed of [false, true]) {
      writeFileSync(pids, "");
      const out = join(root, sandboxed ? "boxed" : "direct");
      const stdout = sink();
      const rc = await main(["--kind", "unit", "--jobs", "2", "--out", out, "--commit", "abcdef0", ...(sandboxed ? ["--sandbox", wrapper] : [])], { root, stdout, stderr: sink() });
      assert.equal(rc, 1, stdout.text);
      const s = JSON.parse(readFileSync(join(out, "summary.json"), "utf8"));
      validateSummary(s);
      const by = Object.fromEntries(s.entries.map((x) => [x.id, x]));
      const logOf = (id) => readFileSync(join(out, "logs", `${id}.log`), "utf8");
      assert.equal(by.anon.result, "fail", stdout.text);
      assert.equal(by.three.result, "fail");
      assert.match(logOf("three"), /^\[run-suites\] exit=3 signal=- /m);
      assert.match(logOf("three"), /^\[run-suites\] fail: exit 3$/m);
      assert.match(logOf("signalled"), /\[run-suites\] exit=- signal=SIGUSR1 /);
      if (!sandboxed) {
        assert.equal(by.absent.result, "error", "an entry that cannot start is an error, as without the subreaper");
        assert.match(logOf("absent"), /\[run-suites\] error: could not start: spawn run-suites-no-such-command-xyz /);
      }
      const [p] = readFileSync(pids, "utf8").trim().split("\n").map(Number);
      assert.deepEqual(await waitDead([p]), [], "the stray was killed");
      const log = readFileSync(join(out, "logs", "anon.log"), "utf8");
      assert.match(log, new RegExp(`\\[run-suites\\] fail: left 1 process running outside its process group \\(killed\\): ${p} \\(sleep 303\\)`));
    }
  } finally {
    killAll(pids);
    rmSync(root, { recursive: true, force: true });
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("main with MANDU_TEST_SUBREAPER=0: the entry runs directly, and a daemon that names nothing of it is not seen (the gap the subreaper closes)", { skip: reaperSkip }, async () => {
  const scratch = mkdtempSync(join(tmpdir(), "run-suites-stray-"));
  const pids = join(scratch, "pids");
  const { root } = fixtureRoot([E("anon", { cmd: ["bash", "-c", `${anonymous(304, pids)}; echo '# pass 1'`] })]);
  try {
    const stdout = sink();
    const out = join(root, "o");
    assert.equal(await main(["--kind", "unit", "--out", out, "--commit", "abcdef0"], { root, stdout, stderr: sink(), env: { ...process.env, MANDU_TEST_SUBREAPER: "0" } }), 0, stdout.text);
    const p = Number(readFileSync(pids, "utf8"));
    assert.ok(alive(p), "nothing named it, so nothing killed it");
    assert.doesNotMatch(readFileSync(join(out, "logs", "anon.log"), "utf8"), /outside its process group/);
  } finally {
    killAll(pids);
    rmSync(root, { recursive: true, force: true });
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("runEntry under the subreaper: no interpreter among the entry's ancestors, an orphan that ends is reaped (no zombie), and an entry that ends at once is never a stray of its own", { skip: reaperSkip }, async () => {
  // A guard that trusts a `from: python3` parent counts every ancestor
  // (secret-readers-live, MR !1667's first pipeline), and a test that waits
  // for a killed process with `kill -0` sees a zombie alive (guard-death-live,
  // twin-git-clean, its second): the subreaper is C and reaps what it adopts.
  const out = mkdtempSync(join(tmpdir(), "run-suites-anc-"));
  const runTmp = makeRunTmp(out);
  try {
    mkdirSync(join(out, "logs"));
    const walk = 'p=$$; while [ "$p" -gt 1 ]; do echo "anc=$(basename "$(readlink /proc/$p/exe)")"; p=$(awk \'{print $4}\' /proc/$p/stat); done; echo "opts=${NODE_OPTIONS-unset}"; ' +
      // An orphan (its parent subshell exits at once) that ends after 0.3 s.
      '( sleep 0.3 & echo $! > "$TMPDIR/o.pid" ); o=$(cat "$TMPDIR/o.pid"); rm -f "$TMPDIR/o.pid"; sleep 1.5; ' +
      'if [ -e /proc/$o ]; then echo "orphan=$(awk \'{print $3}\' /proc/$o/stat)"; else echo orphan=reaped; fi; echo "# pass 1"';
    const x = E("anc", { cmd: ["bash", "-c", walk] });
    const r = await runEntry(x, { root: out, outDir: out, tmp: entryTmpDir(runTmp, 0), baseEnv: { ...process.env, NODE_OPTIONS: "--no-warnings" } });
    const log = readFileSync(join(out, r.log), "utf8");
    assert.equal(r.result, "pass", log);
    const anc = [...log.matchAll(/^anc=(.*)$/gm)].map((m) => m[1]);
    assert.ok(anc.length >= 2, log);
    assert.ok(!anc.some((a) => /python|perl/.test(a)), `an ancestor is an interpreter: ${anc.join(" ")}`);
    assert.ok(anc.includes("mdu-subreaper"), `the subreaper is an ancestor: ${anc.join(" ")}`);
    assert.match(log, /^opts=--no-warnings$/m, "the entry's NODE_OPTIONS reaches it");
    assert.match(log, /^orphan=reaped$/m, "an orphan that ended was reaped, as init would");
    // Many entries that end at once, side by side: none is failed for a
    // stray (the subreaper names the entry's TMPDIR and is no stray, and
    // the entry's start comes from the subreaper, not from a /proc it left).
    const quick = await Promise.all(Array.from({ length: 12 }, (_, i) => runEntry({ ...E(`q${i}`), cmd: ["true"] }, { root: out, outDir: out, tmp: entryTmpDir(runTmp, i + 1) })));
    assert.deepEqual(quick.map((q) => [q.id, q.result, q.reason ?? null]).filter((q) => q[1] !== "pass"), [], "every quick entry passes");
  } finally {
    removeTree(runTmp);
    rmSync(out, { recursive: true, force: true });
  }
});

test("subreaperBinary: built once per run directory, none off Linux or with MANDU_TEST_SUBREAPER=0; entryStrays with adoptedBy names its live children as orphans, whatever they name", { skip: reaperSkip }, async () => {
  const bin = subreaperBinary(reaperProbe);
  assert.equal(bin, join(reaperProbe, "mdu-subreaper"));
  assert.ok(isAbsolute(bin) && existsSync(bin));
  assert.equal(subreaperBinary(reaperProbe), bin, "asked again: the same one");
  assert.equal(subreaperBinary(join(reaperProbe, "elsewhere"), { platform: "darwin" }), null);
  assert.equal(subreaperBinary(join(reaperProbe, "elsewhere"), { env: { MANDU_TEST_SUBREAPER: "0" } }), null);
  assert.equal(subreaperBinary(null), null);
  // A plain child of this process stands in for an adopted orphan: its ppid is ours.
  const child = spawn("sleep", ["30"], { cwd: "/", env: {}, stdio: "ignore" });
  try {
    await new Promise((r) => child.once("spawn", r));
    const found = entryStrays([], { adoptedBy: process.pid, self: -1 }).find((s) => s.pid === child.pid);
    assert.deepEqual(found, { pid: child.pid, argv: ["sleep", "30"], why: "orphan" });
    assert.equal(entryStrays([], {}).length, 0, "no dirs and no subreaper: nothing to look for");
  } finally {
    child.kill("SIGKILL");
  }
});

test("entryStrays: only this uid's processes born since the entry started that name the dir; ENTRY_MARK must equal it, TMPDIR may be under it", { skip: process.platform !== "linux" && "stray detection reads Linux /proc" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "run-suites-strays-"));
  const kids = [];
  const start = (env, o = {}) => {
    const c = spawn("sleep", ["30"], { env: { PATH: process.env.PATH, ...env }, detached: true, stdio: "ignore", ...o });
    kids.push(c.pid);
    return c.pid;
  };
  try {
    const old = start({ [ENTRY_MARK]: dir });
    // A clock tick is 10 ms: the later processes start at least a tick after `old`.
    await new Promise((r) => setTimeout(r, 50));
    const since = procStartTicks(old) + 1;
    const marked = start({ [ENTRY_MARK]: dir });
    const nested = start({ TMPDIR: join(dir, "sub") });
    const prefixOnly = start({ [ENTRY_MARK]: join(dir, "sub"), TMPDIR: `${dir}x` });
    const inCwd = start({}, { cwd: dir });
    const unrelated = start({ TMPDIR: tmpdir() });
    await new Promise((r) => setTimeout(r, 100));
    const found = new Map(entryStrays([dir], { sinceTicks: since }).map((s) => [s.pid, s]));
    assert.equal(found.get(marked)?.why, `env ${ENTRY_MARK}`);
    assert.equal(found.get(nested)?.why, "env TMPDIR");
    assert.equal(found.get(inCwd)?.why, "cwd");
    assert.deepEqual(found.get(marked).argv, ["sleep", "30"]);
    assert.ok(!found.has(prefixOnly), "a sibling path is not the dir; the mark must be the dir itself");
    assert.ok(!found.has(unrelated));
    assert.ok(!found.has(old), "born before the entry: not its");
    assert.ok(entryStrays([dir]).some((s) => s.pid === old), "without a start, any age");
    assert.ok(!found.has(process.pid), "never the runner");
    assert.deepEqual(entryStrays([], {}), []);
    assert.deepEqual(entryStrays([dir], { uid: -5 }), [], "another uid's processes are never looked at");
  } finally {
    for (const p of kids) { try { process.kill(p, "SIGKILL"); } catch { /* gone */ } }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runEntry: new files an unsandboxed entry leaves outside its TMPDIR (a hard-coded /tmp, $HOME, the runtime dir) are reported, never a failure", async () => {
  const out = mkdtempSync(join(tmpdir(), "run-suites-outside-"));
  const runTmp = makeRunTmp(out);
  try {
    mkdirSync(join(out, "logs"));
    const host = join(out, "host-tmp");
    mkdirSync(host);
    writeFileSync(join(host, "old"), "");
    const x = E("out", { cmd: ["bash", "-c", `mkdir '${host}/leak-dir'; touch '${host}/leak-file' '${host}/gone'; rm '${host}/gone'; touch '${host}/old'; echo '# pass 1'`] });
    const r = await runEntry(x, { root: out, outDir: out, tmp: entryTmpDir(runTmp, 0), watchRoots: [host] });
    assert.equal(r.result, "pass", "a warning, not a failure");
    assert.deepEqual(r.outside, [join(host, "leak-dir"), join(host, "leak-file")], "new and still there; an old name and one removed are not");
    assert.match(readFileSync(join(out, r.log), "utf8"), /\[run-suites\] outside: 2 new outside its TMPDIR while it ran \(not counted: another process may have made them\): .*leak-dir, .*leak-file/);
    const clean = await runEntry({ ...x, id: "clean", cmd: ["true"] }, { root: out, outDir: out, tmp: entryTmpDir(runTmp, 1), watchRoots: [host] });
    assert.equal(clean.outside, undefined);
  } finally {
    removeTree(runTmp);
    rmSync(out, { recursive: true, force: true });
  }
});

test("outsideRoots / newOutside: /tmp, the caller's runtime dir with its mandu, instances and human dirs, and $HOME; the entry's own runtime dir and the run's dirs are not looked at", () => {
  assert.deepEqual(outsideRoots({ XDG_RUNTIME_DIR: "/run/user/7", HOME: "/home/u" }),
    ["/tmp", "/run/user/7", "/run/user/7/mandu", "/run/user/7/mandu/instances", "/run/user/7/mandu/human", "/home/u"]);
  assert.deepEqual(outsideRoots({ XDG_RUNTIME_DIR: "/r/00.rt", HOME: "/" }, { ownRt: "/r/00.rt" }), ["/tmp"], "its own runtime dir and a home of / are not watched");
  const dir = mkdtempSync(join(tmpdir(), "run-suites-newout-"));
  try {
    const before = snapshotRoots([dir, join(dir, "missing")]);
    mkdirSync(join(dir, "run", "00"), { recursive: true });
    writeFileSync(join(dir, "x"), "");
    assert.deepEqual(newOutside(before, { except: [join(dir, "run", "00")] }), [join(dir, "x")], "a parent of the run's own dir is the run's");
    assert.deepEqual(newOutside(before, { uid: -5 }), [], "another uid's are not reported");
    assert.match(outsideText(Array.from({ length: 12 }, (_, i) => `/tmp/n${i}`)), /^12 new outside .*\/tmp\/n9, … \(\+2 more\)$/);
    assert.match(strayText([{ pid: 9, argv: ["node", "x.js"], why: "cwd" }]), /^left 1 process running outside its process group \(killed\): 9 \(node x\.js\)$/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("makeRunTmp: macOS long TMPDIR falls back to a private canonical short root while each entry stays isolated", () => {
  const parent = mkdtempSync(join(tmpdir(), "run-suites-long-parent-"));
  mkdirSync(join(parent, "long"));
  const long = join(parent, "long");
  const darwin = makeRunTmp(long, { platform: "darwin" });
  const linux = makeRunTmp(long, { platform: "linux" });
  try {
    assert.equal(dirname(darwin), realpathSync("/tmp"));
    assert.equal(statSync(darwin).mode & 0o777, 0o700);
    assert.equal(dirname(linux), realpathSync(long), "Linux preserves the caller's temp parent");
    const first = entryTmpDir(darwin, 0);
    const second = entryTmpDir(darwin, 1);
    assert.notEqual(first, second);
    assert.equal(dirname(first), darwin);
    assert.equal(statSync(first).mode & 0o777, 0o700);
    assert.ok(Buffer.byteLength(first) <= 22, "room remains for a suite's socket directory");
    const macEntry = first.startsWith("/private/") ? first : `/private${first}`;
    assert.ok(Buffer.byteLength(join(macEntry, "mdu-XXXXXX", "mandu")) + 63 < 104,
      "the instance-mode fixture and maximum arbiter instance suffix fit macOS sun_path");
  } finally {
    removeTree(darwin);
    removeTree(linux);
    rmSync(parent, { recursive: true, force: true });
  }
});


test("makeRunTmp: a short TMPDIR alias whose canonical parent is long falls back on macOS", () => {
  const target = mkdtempSync(join(tmpdir(), "run-suites-canonical-parent-"));
  const aliases = mkdtempSync("/tmp/m-");
  const alias = join(aliases, "x");
  symlinkSync(target, alias);
  assert.equal(needsShortTmpdir("darwin", alias), false, "the caller's spelling is short");
  const run = makeRunTmp(alias, { platform: "darwin" });
  try {
    assert.equal(dirname(run), realpathSync("/tmp"), "the canonical spelling decides the socket budget");
  } finally {
    removeTree(run);
    rmSync(aliases, { recursive: true, force: true });
    rmSync(target, { recursive: true, force: true });
  }
});
