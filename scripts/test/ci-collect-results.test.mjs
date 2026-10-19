// ci-collect-results.test.mjs — scripts/ci/collect-results.mjs, the host side
// of a CI run's results (docs/design/testing/continuous-integration.md §6). The archive is
// untrusted: these tests hand it crafted tars (symlink, hard link, `..`,
// absolute path, device, fifo, too many members, too many bytes, a member
// outside the layout, a bad summary) and check it refuses each one as an
// `error` run without writing anything outside its directories, and that the
// summaries it writes (pass, fail, error) pass the DASHBOARD's validator too
// (the developer view's ci-runs.ts, through tsx, when the dashboard's node_modules
// are installed; otherwise that one assertion is skipped).
//
// Run: node --test scripts/test/ci-collect-results.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  collect, listTar, validateSummary, errorSummary, pruneRuns, checkMemberPath, MAX_MEMBERS, MAX_BYTES, defaultRunsDir,
  collectReplay, promoteBaselines, isDefaultBranchRun, defaultReplayDirs, MAX_REPLAY_RUNS, BASELINE_FILES,
  staleStatusline, statusRows, parseAllowStale, describeStale, ALLOW_STALE_ENV, WAITED_CHECKPOINT_KINDS,
  drillsReport, DRILLS_MAX_MEMBERS, DRILLS_MAX_BYTES, DRILLS_WARN_RATIO,
  collectLive, pruneLive, liveRunName, liveReport, defaultLiveDir, LIVE_MAX_MEMBERS, LIVE_MAX_BYTES, LIVE_RUN_ID_RE,
  LIVE_RUN_FILE_RE, LIVE_DATA_FILE_RE, LIVE_MARKER, MAX_RECORD_FILE_BYTES, LIVE_EVENTS_FILE_RE, LIVE_SESSION_ID_RE, liveSessionName,
  PINNED_JOBS, pinnedJob, isPinned, pinRun, unpinRun, listPinned, liveRunsOf,
} from "../ci/collect-results.mjs";
import { resolvePath } from "../paths/mandu-paths.mjs";
import { drillTree } from "../drill-tree.mjs";
import { EVENTS_MAX_BYTES, EVENTS_FILE_MAX_BYTES } from "../ci/live-events.mjs";
import { PIN_FILE } from "../ci/replay-retention.mjs";
import { devView } from "../dev-view.mjs";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const COLLECTOR = path.join(REPO, "scripts/ci/collect-results.mjs");

// ── a minimal tar writer (ustar), so the tests can say anything a tar can ──
function header(name, { type = "0", size = 0, linkname = "", mode = 0o644, prefix = "" } = {}) {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, "utf8");
  h.write(mode.toString(8).padStart(7, "0") + "\0", 100, "ascii");
  h.write("0000000\0", 108, "ascii");
  h.write("0000000\0", 116, "ascii");
  h.write(size.toString(8).padStart(11, "0") + "\0", 124, "ascii");
  h.write("00000000000\0", 136, "ascii");
  h.write("        ", 148, "ascii");
  h.write(type, 156, "ascii");
  h.write(linkname, 157, 100, "utf8");
  h.write("ustar\0", 257, "ascii");
  h.write("00", 263, "ascii");
  h.write(prefix, 345, 155, "utf8");
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "ascii");
  return h;
}
function member(name, data = "", opts = {}) {
  const body = Buffer.from(data);
  const pad = Buffer.alloc((512 - (body.length % 512)) % 512);
  return Buffer.concat([header(name, { size: body.length, ...opts }), body, pad]);
}
const END = Buffer.alloc(1024);

let tmpRoot;
function tmp() {
  tmpRoot ??= fs.mkdtempSync(path.join(os.tmpdir(), "ci-collect-test-"));
  return fs.mkdtempSync(path.join(tmpRoot, "t-"));
}
process.on("exit", () => { if (tmpRoot) fs.rmSync(tmpRoot, { recursive: true, force: true }); });

const RUN = "gl-1234-5678";
const COMMIT = "b814495e347ecae33129d059617e749616c21fca";
function goodSummary(over = {}) {
  return {
    schema: 1, kind: "mandu-ci-run", run: RUN, source: "gitlab", commit: COMMIT, ref: "master",
    image: "mandu-ci-3f2a0000aaaa1111", started: "2026-09-28T10:00:00Z", finished: "2026-09-28T10:07:12Z",
    result: "pass", stages: { build: { result: "pass", duration_s: 131 }, suites: { result: "pass", duration_s: 300 } },
    entries: [{ id: "arbiter", kind: "component", result: "pass", pass: 431, fail: 0, skip: 2, duration_s: 48.2, log: "logs/arbiter.log" }],
    ...over,
  };
}
function archive(parts) {
  const d = tmp();
  const f = path.join(d, "out.raw");
  fs.writeFileSync(f, Buffer.concat([...parts, END]));
  // A disk is bigger than its tar: trailing zeros, as the guest's 2 GiB disk.
  fs.appendFileSync(f, Buffer.alloc(64 * 1024));
  return f;
}
function goodParts(summary = goodSummary()) {
  return [
    member("summary.json", JSON.stringify(summary)),
    member("junit.xml", "<testsuites/>"),
    header("logs/", { type: "5", mode: 0o755 }),
    member("logs/arbiter.log", "ok\n"),
  ];
}
function run(archivePath, extra = {}) {
  const d = tmp();
  const runsDir = path.join(d, "runs");
  const r = collect({ archive: archivePath, runId: RUN, source: "gitlab", commit: COMMIT, ref: "master",
    image: "mandu-ci-3f2a0000aaaa1111", runsDir, ...extra });
  return { ...r, runsDir, d };
}

// ── the dashboard's validator, through tsx ──────────────────────────────────
const TSX = path.join(REPO, "dashboard/node_modules/.bin/tsx");
/** The developer view's CI reader, where this checkout has it (scripts/dev-view.mjs). */
const DEV = devView();
const DASH = DEV === null ? "" : path.join(DEV, "src/ci-runs.ts");
function dashboardValidate(summaries) {
  const d = tmp();
  const file = path.join(d, "check.ts");
  fs.writeFileSync(path.join(d, "in.json"), JSON.stringify(summaries));
  fs.writeFileSync(file, `import { validateSummary } from ${JSON.stringify(DASH)};
import { readFileSync } from "node:fs";
const xs = JSON.parse(readFileSync(${JSON.stringify(path.join(d, "in.json"))}, "utf8"));
console.log(JSON.stringify(xs.map(([s, dir]) => validateSummary(s, dir))));\n`);
  const r = spawnSync(TSX, [file], { encoding: "utf8", cwd: path.join(REPO, "dashboard") });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout.trim().split("\n").pop());
}
const haveDashboard = DEV !== null && fs.existsSync(TSX) && fs.existsSync(DASH);

// ── member paths ────────────────────────────────────────────────────────────
test("member paths: relative, no .., no absolute, narrow charset", () => {
  assert.equal(checkMemberPath("./logs/a.log"), "logs/a.log");
  assert.equal(checkMemberPath("logs/"), "logs");
  assert.equal(checkMemberPath("./"), "");
  for (const bad of ["/etc/passwd", "../x", "logs/../../x", "logs//x", "logs/./x", "logs/a b", "logs/‮b", "a\0b"]) {
    assert.throws(() => checkMemberPath(bad), undefined, bad);
  }
});

// ── the good path ───────────────────────────────────────────────────────────
test("a valid archive is collected: pass → exit status pass, files in the runs dir, --out copy", () => {
  const out = path.join(tmp(), "ci-out");
  const r = run(archive(goodParts()), { out });
  assert.equal(r.result, "pass");
  assert.equal(r.error, undefined);
  assert.equal(r.dir, path.join(r.runsDir, RUN));
  assert.equal(fs.readFileSync(path.join(r.dir, "logs/arbiter.log"), "utf8"), "ok\n");
  assert.ok(fs.existsSync(path.join(r.dir, "junit.xml")));
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(out, "summary.json"), "utf8")), goodSummary());
  assert.equal(fs.statSync(r.dir).mode & 0o777, 0o755);
  assert.equal(fs.statSync(path.join(r.dir, "logs/arbiter.log")).mode & 0o777, 0o644);
  // no staging leftovers (hidden names)
  assert.deepEqual(fs.readdirSync(r.runsDir), [RUN]);
});

test("a fail run keeps its result; artifacts/release/ is allowed and copied", () => {
  const s = goodSummary({ result: "fail", entries: [{ id: "exec", kind: "exec", result: "fail", pass: 0, fail: 1, skip: 0, duration_s: 3, log: "logs/exec.log" }] });
  const parts = [
    member("./summary.json", JSON.stringify(s)),
    header("./logs/", { type: "5", mode: 0o755 }),
    member("./logs/exec.log", "boom\n"),
    header("./artifacts/", { type: "5", mode: 0o755 }),
    header("./artifacts/release/", { type: "5", mode: 0o755 }),
    member("./artifacts/release/mandusec-mandu-0.1.0.tgz", "TGZ"),
    member("./artifacts/release/SHA256SUMS", "abc  mandusec-mandu-0.1.0.tgz\n"),
  ];
  const out = path.join(tmp(), "ci-out");
  const r = run(archive(parts), { out });
  assert.equal(r.result, "fail");
  assert.equal(fs.readFileSync(path.join(out, "artifacts/release/mandusec-mandu-0.1.0.tgz"), "utf8"), "TGZ");
});

test("an archive written by GNU tar (the guest's own command) is accepted, long names included", (t) => {
  const d = tmp();
  const src = path.join(d, "out");
  const longId = `entry.${"x".repeat(100)}`;
  fs.mkdirSync(path.join(src, "logs"), { recursive: true });
  const s = goodSummary({ entries: [{ id: longId, kind: "unit", result: "pass", pass: 1, fail: 0, skip: 0, duration_s: 1, log: `logs/${longId}.log` }] });
  fs.writeFileSync(path.join(src, "summary.json"), JSON.stringify(s));
  fs.writeFileSync(path.join(src, `logs/${longId}.log`), "x\n");
  for (const format of ["gnu", "pax", "posix"]) {
    const f = path.join(d, `out.${format}.tar`);
    const r = spawnSync("tar", ["-c", "-f", f, "-C", src, `--format=${format}`, "--owner=0", "--group=0", "--numeric-owner", "."]);
    if (r.status !== 0) { t.diagnostic(`tar --format=${format} unavailable`); continue; }
    const got = run(f);
    assert.equal(got.result, "pass", `${format}: ${got.error}`);
  }
});

// ── refusals ────────────────────────────────────────────────────────────────
const refusals = [
  ["a symlink", [member("logs/evil.log", "", { type: "2", linkname: "/etc/passwd" })], /symlink/],
  ["a hard link", [member("logs/evil.log", "", { type: "1", linkname: "summary.json" })], /hard link/],
  ["a character device", [member("logs/dev", "", { type: "3" })], /character device/],
  ["a block device", [member("logs/dev", "", { type: "4" })], /block device/],
  ["a fifo", [member("logs/fifo", "", { type: "6" })], /fifo/],
  ["a `..` path", [member("logs/../../../evil", "x")], /'\.\.'/],
  ["an absolute path", [member("/tmp/evil", "x")], /absolute/],
  ["a path outside the layout", [member("bin/evil.sh", "x")], /outside the results layout/],
  ["summary.json as a directory", [header("summary.json/", { type: "5" })], /outside the results layout/],
  ["a duplicate member", [member("logs/arbiter.log", "again")], /duplicate/],
  ["a member under a file", [member("logs/arbiter.log/x", "x")], /under a file/],
];
for (const [what, extra, why] of refusals) {
  test(`refuses an archive with ${what} (error run, nothing outside)`, () => {
    const r = run(archive([...goodParts(), ...extra]));
    assert.equal(r.result, "error");
    assert.match(r.error, /^unreadable results: /);
    assert.match(r.error, why);
    assert.deepEqual(fs.readdirSync(r.dir).sort(), ["summary.json"]);
    assert.ok(!fs.existsSync("/tmp/evil"));
    assert.deepEqual(validateSummary(r.summary, { dirName: RUN }), []);
  });
}

test("refuses more than MAX_MEMBERS members", () => {
  const parts = goodParts();
  for (let i = 0; i < MAX_MEMBERS; i++) parts.push(member(`logs/m${i}.log`, ""));
  const r = run(archive(parts));
  assert.equal(r.result, "error");
  assert.match(r.error, new RegExp(`more than ${MAX_MEMBERS} members`));
});

test("refuses more than MAX_BYTES unpacked (read from the headers, before any data)", () => {
  const big = header("logs/big.log", { size: MAX_BYTES + 1 });
  const r = run(archive([...goodParts(), big]));
  assert.equal(r.result, "error");
  assert.match(r.error, /bytes unpacked/);
});

test("refuses an empty disk, a truncated archive and a bad checksum", () => {
  const empty = path.join(tmp(), "empty.raw");
  fs.writeFileSync(empty, Buffer.alloc(4096));
  assert.match(run(empty).error, /no summary\.json/);
  const trunc = path.join(tmp(), "trunc.raw");
  fs.writeFileSync(trunc, Buffer.concat(goodParts()).subarray(0, 1500));
  assert.equal(run(trunc).result, "error");
  const bad = Buffer.concat([...goodParts(), END]);
  bad[0] ^= 1;
  const badf = path.join(tmp(), "bad.raw");
  fs.writeFileSync(badf, bad);
  assert.match(run(badf).error, /checksum/);
});

test("refuses an invalid summary.json (schema, unknown field, log path, commit, an entry with tier instead of kind)", () => {
  const cases = [
    [goodSummary({ schema: 2 }), /schema/],
    [goodSummary({ extra: 1 }), /unknown field/],
    [goodSummary({ commit: "HEAD" }), /commit/],
    [goodSummary({ commit: null }), /commit/],
    [goodSummary({ image: null }), /image/],
    [goodSummary({ started: "yesterday" }), /started/],
    [goodSummary({ result: "green" }), /result/],
    [goodSummary({ entries: [{ id: "arbiter", kind: "component", result: "pass", pass: 1, fail: 0, skip: 0, duration_s: 1, log: "logs/other.log" }] }), /logs\/<id>\.log/],
    [goodSummary({ entries: [{ id: "a b", kind: "unit", result: "pass", pass: 1, fail: 0, skip: 0, duration_s: 1 }] }), /\.id/],
    [goodSummary({ stages: { build: { result: "pass", duration_s: 1, log: "logs/build.log" } } }), /unknown field/],
    // The retired `tier` key (test-reorganization.md §4): an entry carrying it instead of `kind` is refused.
    [goodSummary({ entries: [{ id: "arbiter", tier: "offline", result: "pass", pass: 1, fail: 0, skip: 0, duration_s: 1, log: "logs/arbiter.log" }] }), /entries\[0\]: unknown field tier/],
    [goodSummary({ entries: [{ id: "arbiter", result: "pass", pass: 1, fail: 0, skip: 0, duration_s: 1, log: "logs/arbiter.log" }] }), /entries\[0\]\.kind/],
    [goodSummary({ entries: [{ id: "arbiter", kind: "a b", result: "pass", pass: 1, fail: 0, skip: 0, duration_s: 1, log: "logs/arbiter.log" }] }), /entries\[0\]\.kind/],
    [goodSummary({ ref: "x‮y" }), /ref/],
    // The agent a live entry drove (test-organization.md §5): a name, a version, and both only with agent.
    [goodSummary({ entries: [{ id: "arbiter", kind: "live-drill", result: "pass", pass: 1, fail: 0, skip: 0, duration_s: 1, agent: "Claude Code" }] }), /entries\[0\]\.agent/],
    [goodSummary({ entries: [{ id: "arbiter", kind: "live-drill", result: "pass", pass: 1, fail: 0, skip: 0, duration_s: 1, agent: "claude", agentVersion: "v2;rm" }] }), /entries\[0\]\.agentVersion/],
    [goodSummary({ entries: [{ id: "arbiter", kind: "live-drill", result: "pass", pass: 1, fail: 0, skip: 0, duration_s: 1, agentVersion: "2.1.299" }] }), /need agent/],
    [goodSummary({ entries: [{ id: "arbiter", kind: "live-drill", result: "pass", pass: 1, fail: 0, skip: 0, duration_s: 1, agent: "codex", ullm: 7 }] }), /entries\[0\]\.ullm/],
  ];
  for (const [s, why] of cases) {
    const r = run(archive(goodParts(s)));
    assert.equal(r.result, "error", JSON.stringify(s).slice(0, 80));
    assert.match(r.error, why);
  }
  const notJson = run(archive([member("summary.json", "{nope")]));
  assert.match(notJson.error, /not JSON/);
});

test("refuses a summary for another run, commit or image", () => {
  assert.match(run(archive(goodParts(goodSummary({ run: "gl-9-9" })))).error, /does not match|not gl-1234-5678/);
  assert.match(run(archive(goodParts(goodSummary({ commit: "0123456789abcdef" })))).error, /commit/);
  assert.match(run(archive(goodParts(goodSummary({ image: "mandu-ci-other" })))).error, /image/);
});

test("the agent matrix (summary.md, run-suites.mjs) is a file the layout allows; a directory of that name is not", () => {
  const ok = run(archive([...goodParts(), member("summary.md", "| suite | claude |\n")]));
  assert.equal(ok.result, "pass", ok.error);
  const bad = run(archive([...goodParts(), header("summary.md/", { type: "5", mode: 0o755 })]));
  assert.equal(bad.result, "error");
});

test("a log the summary names must be in the archive", () => {
  const parts = [member("summary.json", JSON.stringify(goodSummary()))];
  assert.match(run(archive(parts)).error, /not in the archive/);
});

test("--error (a timeout) writes an error run without reading the archive; the console log is kept, capped", () => {
  const con = path.join(tmp(), "console.log");
  fs.writeFileSync(con, "x".repeat(6 * 1024 * 1024) + "TAIL");
  const r = run(archive(goodParts()), { error: "timeout: the guest ran longer than 2700s", console: con });
  assert.equal(r.result, "error");
  assert.equal(r.summary.reason, "timeout: the guest ran longer than 2700s");
  const kept = fs.readFileSync(path.join(r.dir, "console.log"), "utf8");
  assert.equal(kept.length, 5 * 1024 * 1024);
  assert.ok(kept.endsWith("TAIL"));
});

test("a re-run with the same id replaces the old run; prune keeps the newest 200", () => {
  const d = tmp();
  const runsDir = path.join(d, "runs");
  const a = archive(goodParts());
  collect({ archive: a, runId: RUN, runsDir, commit: COMMIT, image: "mandu-ci-3f2a0000aaaa1111" });
  fs.writeFileSync(path.join(runsDir, RUN, "stale-file"), "x");
  collect({ archive: a, runId: RUN, runsDir, commit: COMMIT, image: "mandu-ci-3f2a0000aaaa1111" });
  assert.ok(!fs.existsSync(path.join(runsDir, RUN, "stale-file")));
  for (let i = 0; i < 205; i++) {
    const dir = path.join(runsDir, `old-${String(i).padStart(3, "0")}`);
    fs.mkdirSync(dir);
    fs.writeFileSync(path.join(dir, "summary.json"), "{}");
    const t = new Date(Date.UTC(2020, 0, 1) + i * 1000);
    fs.utimesSync(path.join(dir, "summary.json"), t, t);
  }
  const removed = pruneRuns(runsDir, 200);
  assert.equal(removed.length, 6);
  assert.equal(fs.readdirSync(runsDir).filter((n) => !n.startsWith(".")).length, 200);
  assert.ok(fs.existsSync(path.join(runsDir, RUN)), "the newest run survives");
  assert.ok(!fs.existsSync(path.join(runsDir, "old-000")), "the oldest go");
});

test("the CLI's exit status is the run's result: 0 pass, 1 fail, 2 error", () => {
  const d = tmp();
  const env = { ...process.env, MANDU_HOME: path.join(d, "home") };
  const cli = (a, extra = []) => spawnSync(process.execPath, [COLLECTOR, "--archive", a, "--run-id", RUN, ...extra], { env, encoding: "utf8" }).status;
  assert.equal(cli(archive(goodParts())), 0);
  assert.equal(cli(archive(goodParts(goodSummary({ result: "fail" })))), 1);
  assert.equal(cli(archive([member("bin/x", "x")])), 2);
  assert.equal(cli(archive(goodParts()), ["--error", "qemu exited 1"]), 2);
  assert.equal(spawnSync(process.execPath, [COLLECTOR, "--archive", "x"], { env }).status, 2, "no --run-id");
  assert.equal(spawnSync(process.execPath, [COLLECTOR, "--archive", "x", "--run-id", "../evil"], { env }).status, 2, "bad run id");
});

// ── the dashboard reads what the collector writes ───────────────────────────
test("the collector's summaries (pass, fail, error) pass the dashboard's validator", { skip: !haveDashboard && "no developer view here, or dashboard/node_modules not installed" }, () => {
  const pass = run(archive(goodParts()));
  const fail = run(archive(goodParts(goodSummary({ result: "fail" }))));
  const err = run(archive([member("bin/x", "x")]));
  const minimal = errorSummary({ runId: "local-x", error: "image stale: \u0007 bell", commit: "nonsense" });
  const verdicts = dashboardValidate([[pass.summary, RUN], [fail.summary, RUN], [err.summary, RUN], [minimal, "local-x"]]);
  for (const v of verdicts) assert.equal(v.ok, true, JSON.stringify(v));
  // an entry naming its agent passes both
  const liveRow = { id: "drill.conf.claude", kind: "live-drill", result: "pass", pass: 29, fail: 0, skip: 0, duration_s: 900, agent: "claude", agentVersion: "2.1.299" };
  const withAgent = goodSummary({ entries: [liveRow, { ...liveRow, id: "codex-mcp", agent: "codex", agentVersion: "0.162.0", ullm: "claude" }] });
  assert.deepEqual(validateSummary(withAgent, { dirName: RUN }), []);
  const [agentOk] = dashboardValidate([[withAgent, RUN]]);
  assert.equal(agentOk.ok, true, JSON.stringify(agentOk));
  // and the two validators agree on what they refuse
  const bads = [goodSummary({ extra: 1 }), goodSummary({ commit: "HEAD" }), goodSummary({ image: null }),
    goodSummary({ stages: { build: { result: "ok", duration_s: 1 } } }),
    goodSummary({ entries: [{ ...liveRow, agent: "Claude Code" }] }), goodSummary({ entries: [{ ...liveRow, agentVersion: "x" }] }),
    goodSummary({ entries: [{ ...liveRow, agent: undefined, ullm: "claude" }] })];
  const dv = dashboardValidate(bads.map((s) => [s, RUN]));
  bads.forEach((s, i) => {
    assert.equal(dv[i].ok, false);
    assert.notDeepEqual(validateSummary(s, { dirName: RUN }), []);
  });
});

// ── where runs land: the path table's `ci-runs` (on-disk-layout.md §5) ─────
test("the default runs dir is the path table's ci-runs entry", () => {
  const cases = [
    [{ MANDU_CI_RUNS_DIR: "/srv/runs", MANDU_HOME: "/m", HOME: "/h" }, "/m/runs/ci"], // the retired override moves nothing
    [{ MANDU_HOME: "/var/mandu", HOME: "/h" }, "/var/mandu/runs/ci"],
    [{ XDG_STATE_HOME: "/var/state", HOME: "/h" }, "/h/.mandu/runs/ci"],
    [{ HOME: "/home/u" }, "/home/u/.mandu/runs/ci"],
    [{ MANDU_HOME: "", HOME: "/home/u" }, "/home/u/.mandu/runs/ci"],
  ];
  for (const [env, want] of cases) {
    assert.equal(defaultRunsDir(env), want, JSON.stringify(env));
    assert.equal(defaultRunsDir(env), resolvePath("ci-runs", env, env.HOME), JSON.stringify(env));
  }
  assert.equal(defaultRunsDir({}), resolvePath("ci-runs", {}, os.homedir()), "no HOME: the account's home");
});

// ── drills/: the replay records and the baselines (continuous-integration.md §6) ──
// Synthetic record trees in the run-directory layout of test-reorganization.md
// §7.3 (WP0's replay-model.ts): what the replay-drill entries leave under
// $OUT/drills/ (run-suites --replay-store / --replay-baselines).
const runMeta = (over = {}) => ({ schema: 1, kind: "mandu-replay-run", runId: "guest-chose-this", commit: "deadbeef", source: "ci", startedAt: "2026-10-01T10:00:00Z", engine: 1, ...over });
const sessionRec = (key, over = {}) => ({ schema: 1, kind: "mandu-replay-session", key, sessionId: `guest-chose-this/${key}`, drill: "fidelity-echo", agent: "claude", verdict: "PASS", checks: [], ...over });
function writeTree(root, files) {
  for (const [rel, data] of Object.entries(files)) {
    const f = path.join(root, ...rel.split("/"));
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, typeof data === "string" ? data : JSON.stringify(data));
  }
}
/** A GNU tar of a results dir: summary, one log, and `drills` files. */
function drillsArchive(drills, summary = goodSummary()) {
  const d = tmp();
  const src = path.join(d, "out");
  writeTree(src, { "summary.json": summary, "junit.xml": "<testsuites/>", "logs/arbiter.log": "ok\n" });
  writeTree(path.join(src, "drills"), drills);
  const f = path.join(d, "out.tar");
  const r = spawnSync("tar", ["-c", "-f", f, "-C", src, "--format=gnu", "--owner=0", "--group=0", "--numeric-owner", "."]);
  assert.equal(r.status, 0, String(r.stderr));
  return f;
}
const E1 = "replay/integration.differential.fidelity-echo/gl-1234-5678";
const E2 = "replay/integration.differential.fidelity-write-file/gl-1234-5678";
const K1 = "fidelity-echo-claude-inline-80x24";
const K2 = "fidelity-write-file-claude-80x24";
const SAMPLE_DRILLS = {
  [`${E1}/run.json`]: runMeta(),
  [`${E1}/sessions/${K1}.json`]: sessionRec(K1),
  [`${E1}/events-${K1}.ndjson`]: '{"type":"assertion"}\n',
  [`${E1}/casts/${K1}.mandu.cast`]: '{"version":2}\n',
  [`${E1}/casts/${K1}.plain.cast`]: '{"version":2}\n',
  [`${E1}/panes/${K1}/turn-1.txt`]: "pane\n",
  [`${E2}/run.json`]: runMeta({ runId: "another" }),
  [`${E2}/sessions/${K2}.json`]: sessionRec(K2),
  [`${E2}/casts/${K2}.mandu.cast`]: '{"version":2}\n',
  [`${E2}/sessions/mismatch.json`]: sessionRec("not-mismatch"),
  [`${E2}/events-mismatch.ndjson`]: "{}\n",
  [`${E2}/notes.txt`]: "not a record file\n",
  [`${E2}/sessions/broken.json`]: "{nope",
  "baselines/integration.differential.fidelity-echo/bk-echo-1/baseline.json": { schema: 2, kind: "mandu-replay-baseline", key: "bk-echo-1" },
};
function runDrills(archivePath, extra = {}) {
  const d = tmp();
  const runsDir = path.join(d, "runs", "ci");
  const r = collect({ archive: archivePath, runId: RUN, source: "gitlab", commit: COMMIT, ref: "master",
    image: "mandu-ci-3f2a0000aaaa1111", runsDir, ...extra });
  return { ...r, runsDir, replayDir: path.join(d, "runs", "drills", "replay"), baselinesDir: path.join(d, "runs", "drills", "baselines") };
}
const readJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));

test("drills/: the replay records merge into ONE host run, runId and sessionIds forced to the CI run's; the CI run dir holds no drills/; --out keeps them raw", () => {
  const out = path.join(tmp(), "ci-out");
  const r = runDrills(drillsArchive(SAMPLE_DRILLS), { out });
  assert.equal(r.result, "pass");
  assert.equal(r.replay.dir, path.join(r.replayDir, RUN), "beside runs/ci, under the same runs root");
  const meta = readJson(path.join(r.replay.dir, "run.json"));
  assert.equal(meta.runId, RUN, "run.json's runId is the CI run's, whatever the guest wrote");
  assert.equal(meta.commit, COMMIT, "and the commit the host tested");
  assert.deepEqual(r.replay.sessions.sort(), [K1, K2].sort());
  for (const k of [K1, K2]) assert.equal(readJson(path.join(r.replay.dir, "sessions", `${k}.json`)).sessionId, `${RUN}/${k}`, "§7.3: namespaced by the run");
  for (const f of [`events-${K1}.ndjson`, `casts/${K1}.mandu.cast`, `casts/${K1}.plain.cast`, `panes/${K1}/turn-1.txt`, `casts/${K2}.mandu.cast`]) {
    assert.ok(fs.statSync(path.join(r.replay.dir, f)).isFile(), f);
    assert.equal(fs.statSync(path.join(r.replay.dir, f)).mode & 0o777, 0o644, f);
  }
  for (const f of ["notes.txt", "sessions/mismatch.json", "events-mismatch.ndjson", "sessions/broken.json"]) assert.ok(!fs.existsSync(path.join(r.replay.dir, f)), `${f} left behind`);
  assert.ok(r.replay.notes.some((n) => /notes\.txt: skipped \(not a replay record file\)/.test(n)));
  assert.ok(r.replay.notes.some((n) => /mismatch\.json: skipped \(its key is not its file's name\)/.test(n)));
  assert.ok(r.replay.notes.some((n) => /broken\.json: skipped/.test(n)));
  assert.ok(!fs.existsSync(path.join(r.dir, "drills")), "runs/ci/<run> holds no drills/");
  assert.deepEqual(readJson(path.join(out, "drills", E1, "run.json")), runMeta(), "--out (the GitLab artifact) keeps the guest's files as they were");
  assert.deepEqual(fs.readdirSync(r.replayDir), [RUN], "no staging leftovers");
});

test("drills/: an unsandboxed run's shared store (drills/replay/<run>/) is collected the same way", () => {
  const r = runDrills(drillsArchive({ "replay/local-x/run.json": runMeta(), [`replay/local-x/sessions/${K1}.json`]: sessionRec(K1) }));
  assert.deepEqual(r.replay.sessions, [K1]);
  assert.equal(readJson(path.join(r.replay.dir, "run.json")).runId, RUN);
});

test("drills/: a session key two entries both wrote keeps the first; with no readable run.json nothing is copied", () => {
  const dup = runDrills(drillsArchive({
    "replay/a/r/run.json": runMeta(), [`replay/a/r/sessions/${K1}.json`]: sessionRec(K1, { title: "first" }),
    "replay/b/r/run.json": runMeta(), [`replay/b/r/sessions/${K1}.json`]: sessionRec(K1, { title: "second" }), [`replay/b/r/casts/${K1}.plain.cast`]: "x",
  }));
  assert.equal(readJson(path.join(dup.replay.dir, "sessions", `${K1}.json`)).title, "first");
  assert.ok(!fs.existsSync(path.join(dup.replay.dir, "casts", `${K1}.plain.cast`)), "the second entry's files of that key stay behind");
  const none = runDrills(drillsArchive({ "replay/a/r/run.json": { kind: "something-else" }, [`replay/a/r/sessions/${K1}.json`]: sessionRec(K1) }));
  assert.equal(none.replay.dir, null);
  assert.ok(!fs.existsSync(none.replayDir));
  assert.ok(none.replay.notes.some((n) => /no readable run\.json/.test(n)));
});

test("drills/: the archive's own rules hold under drills/ (a symlink, a path beside replay/ and baselines/, drills as a file refuse the archive)", () => {
  const cases = [
    [member("drills/replay/a/run.json", "", { type: "2", linkname: "/etc/passwd" }), /symlink/],
    [member("drills/other/x", "x"), /outside the results layout/],
    [member("drills", "x"), /outside the results layout/],
    [member("drills/replay/a/../../../evil", "x"), /'\.\.'/],
  ];
  for (const [m, why] of cases) {
    const r = runDrills(archive([...goodParts(), m]));
    assert.equal(r.result, "error");
    assert.match(r.error, why);
    assert.equal(r.replay, undefined, "an error run copies nothing of drills/");
    assert.ok(!fs.existsSync(r.replayDir));
  }
});

test("drills/: re-collecting a run replaces its replay record; the store keeps the newest MAX_REPLAY_RUNS (replay-retention.mjs)", () => {
  const d = tmp();
  const replayDir = path.join(d, "replay");
  const tree = path.join(d, "tree");
  writeTree(path.join(tree, "drills"), { "replay/r/run.json": runMeta(), [`replay/r/sessions/${K1}.json`]: sessionRec(K1) });
  collectReplay(tree, { runId: RUN, replayDir });
  fs.writeFileSync(path.join(replayDir, RUN, "stale"), "x");
  collectReplay(tree, { runId: RUN, replayDir });
  assert.ok(!fs.existsSync(path.join(replayDir, RUN, "stale")));
  const old = new Date(Date.UTC(2020, 0, 1));
  for (let i = 0; i < 5; i++) {
    const dir = path.join(replayDir, `old-${i}`);
    fs.mkdirSync(dir);
    fs.writeFileSync(path.join(dir, "run.json"), JSON.stringify(runMeta({ runId: `old-${i}`, startedAt: new Date(Date.UTC(2020, 0, 1) + i * 1000).toISOString() })));
    fs.utimesSync(path.join(dir, "run.json"), old, old);
    fs.utimesSync(dir, old, old);
  }
  // not a replay run (run.json not one): never pruned, only reported
  fs.mkdirSync(path.join(replayDir, "not-a-run"));
  fs.writeFileSync(path.join(replayDir, "not-a-run", "run.json"), "{}");
  const r = collectReplay(tree, { runId: RUN, replayDir, maxRuns: 3 });
  assert.deepEqual(fs.readdirSync(replayDir).sort(), [RUN, "not-a-run", "old-3", "old-4"]);
  assert.deepEqual(r.pruned.deleted.map((x) => x.name), ["old-2", "old-1", "old-0"], "oldest by startedAt go first");
  assert.deepEqual(r.pruned.ignored.map((x) => x.name), ["not-a-run"]);
  assert.equal(MAX_REPLAY_RUNS, 300, "the store keeps the newest 300 (the replay page lists them all)");
});

test("drills/: the collector's retention honours MANDU_REPLAY_KEEP_RUNS, keeps a run still being written, and a malformed value keeps the default with a note", () => {
  const d = tmp();
  const replayDir = path.join(d, "replay");
  const tree = path.join(d, "tree");
  writeTree(path.join(tree, "drills"), { "replay/r/run.json": runMeta(), [`replay/r/sessions/${K1}.json`]: sessionRec(K1) });
  const old = new Date(Date.UTC(2020, 0, 1));
  const put = (name, startedAt, aged = true) => {
    const dir = path.join(replayDir, name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "run.json"), JSON.stringify(runMeta({ runId: name, startedAt })));
    if (aged) { fs.utimesSync(path.join(dir, "run.json"), old, old); fs.utimesSync(dir, old, old); }
  };
  put("a-1", "2020-01-01T00:00:01Z");
  put("a-2", "2020-01-01T00:00:02Z");
  put("writing", "2020-01-01T00:00:00Z", false); // fresh mtimes: a writer may still be at it
  const r = collectReplay(tree, { runId: RUN, replayDir, maxRuns: 2 });
  assert.deepEqual(fs.readdirSync(replayDir).sort(), ["a-2", RUN, "writing"]);
  assert.deepEqual(r.pruned.kept.map((k) => [k.name, k.reason]), [[RUN, "newest"], ["a-2", "newest"], ["writing", "recent"]]);

  // collect() reads MANDU_REPLAY_KEEP_RUNS from opts.env
  const a = drillsArchive(SAMPLE_DRILLS);
  const bad = collect({ archive: a, runId: RUN, source: "gitlab", commit: COMMIT, ref: "master", image: "mandu-ci-3f2a0000aaaa1111", runsDir: path.join(d, "ci"), replayDir, env: { MANDU_REPLAY_KEEP_RUNS: "zero" } });
  assert.ok(bad.replay.notes.some((n) => /MANDU_REPLAY_KEEP_RUNS=zero: not a whole number/.test(n)), bad.replay.notes.join("\n"));
  assert.equal(bad.replay.pruned.keep, MAX_REPLAY_RUNS);
  const one = collect({ archive: a, runId: RUN, source: "gitlab", commit: COMMIT, ref: "master", image: "mandu-ci-3f2a0000aaaa1111", runsDir: path.join(d, "ci"), replayDir, env: { MANDU_REPLAY_KEEP_RUNS: "1" } });
  assert.equal(one.replay.pruned.keep, 1);
  assert.deepEqual(fs.readdirSync(replayDir).sort(), [RUN, "writing"], "keep 1: the newest, plus the run still being written");
});

test("drills/: baselines are promoted only from a passing default-branch GitLab run", () => {
  const a = drillsArchive(SAMPLE_DRILLS);
  const mr = runDrills(a);
  assert.deepEqual(mr.baselines.promoted, []);
  assert.match(mr.baselines.notes[0], /not a default-branch GitLab run/);
  assert.ok(!fs.existsSync(mr.baselinesDir), "an MR's baselines never reach the host's cache");
  const master = runDrills(a, { promote: true });
  assert.deepEqual(master.baselines.promoted, ["bk-echo-1"]);
  assert.deepEqual(fs.readdirSync(path.join(master.baselinesDir, "bk-echo-1")), ["baseline.json"]);
  const red = runDrills(drillsArchive(SAMPLE_DRILLS, goodSummary({ result: "fail" })), { promote: true });
  assert.deepEqual(red.baselines.promoted, []);
  assert.match(red.baselines.notes[0], /the run is fail/);
});

test("drills/: a baseline with a file outside BASELINE_FILES (a schema 1 entry of nine files), a subdirectory, another kind or key, or a bad name is not promoted; the rest are", () => {
  const d = tmp();
  const tree = path.join(d, "tree");
  const baselinesDir = path.join(d, "baselines");
  const b = (key, over = {}) => ({ schema: 2, kind: "mandu-replay-baseline", key, ...over });
  writeTree(path.join(tree, "drills", "baselines"), {
    "e/good/baseline.json": b("good", { k: 1 }),
    "e/extra/baseline.json": b("extra"), "e/extra/evil.sh": "x",
    "e/old/baseline.json": b("old", { schema: 1 }), "e/old/requests.json": [], "e/old/stdout.bin": "",
    "e/sub/baseline.json": b("sub"), "e/sub/dir/x": "x",
    "e/notjson/baseline.json": "[1,2]",
    "e/nokind/baseline.json": { key: "nokind" },
    "e/moved/baseline.json": b("good"),
    "e/-dash/baseline.json": b("-dash"),
    "f/good/baseline.json": b("good", { k: 2 }),
  });
  const r = promoteBaselines(tree, { baselinesDir });
  assert.deepEqual(r.promoted, ["good"]);
  assert.equal(readJson(path.join(baselinesDir, "good", "baseline.json")).k, 1, "a key two entries both hold keeps the first");
  assert.deepEqual(fs.readdirSync(baselinesDir), ["good"]);
  for (const why of [/extra: not promoted \(holds evil\.sh/, /old: not promoted \(holds requests\.json/, /sub: not promoted \(holds dir/,
    /notjson: not promoted \(not a JSON object\)/, /nokind: not promoted \(baseline\.json's kind/, /moved: not promoted \(baseline\.json's key is not its directory's name/,
    /-dash: not promoted \(not a baseline key\)/, /f\/good: not promoted/]) {
    assert.ok(r.notes.some((n) => why.test(n)), `${why}: ${r.notes.join(" | ")}`);
  }
  assert.deepEqual([...BASELINE_FILES], ["baseline.json"], "baseline-cache.ts schema 2: one file per baseline");
});

// ── the stale-statusline guard (continuous-integration.md §6) ─────────────────
// The differential fixture's status line row, as its statusline.sh prints it,
// and a screen in the shape of a real-config checkpoint (claude 2.1.295).
const slRow = (p, d, m = 1) => `  sl p${p}/d${d} m${m} | Haiku 4.5 | workspace | git | +0 -0`;
const slScreen = (row) => ["❯ DIFF_T1 read notes.md and echo its content back", "", "● DIFF_S1_DONE", "",
  "────────────────────────────────────────", "❯", "────────────────────────────────────────", row,
  "  ⏵⏵ bypass permissions on (shift+tab to cycle)"];
/** A schema 2 baseline's judged fields: one screen per checkpoint mark. */
const slBaseline = (key, cps) => ({
  schema: 2, kind: "mandu-replay-baseline", key,
  side: { checkpointMarks: cps.map(([turn, kind], i) => ({ t: i + 1, turn, kind })) },
  checkpoints: cps.map(([, , screen]) => screen),
});
const FRESH_TWO_TURNS = [[0, "turn", slScreen(slRow(1, 1))], [1, "turn", slScreen(slRow(2, 2))], [1, "resize", slScreen(slRow(2, 2))], [1, "quit", slScreen(slRow(2, 2))]];
const STALE_TURN_2 = [[0, "turn", slScreen(slRow(1, 1))], [1, "turn", slScreen(slRow(2, 1))], [1, "quit", slScreen(slRow(2, 1))]];

test("statusRows: the fixture row (sl p<P>/d<D> m<M>), whole-word, every one on the screen", () => {
  assert.deepEqual(statusRows(slScreen(slRow(3, 2)).join("\n")), [{ prompts: 3, done: 2 }]);
  assert.deepEqual(statusRows(`${slRow(1, 0)}\n${slRow(1, 1, 0)}`), [{ prompts: 1, done: 0 }, { prompts: 1, done: 1 }]);
  for (const t of ["sl p1/d1 | no m segment", "xsl p1/d1 m1 |", "sl p1/d1 m1x", "  Ctx: 12k | Model: Haiku", ""]) assert.deepEqual(statusRows(t), [], t);
  assert.deepEqual(statusRows("sl p1/d1 m1"), [{ prompts: 1, done: 1 }], "at the end of the screen too");
});

test("staleStatusline: a waited checkpoint (turn, resize) whose fixture row is not sl p<k>/d<k> after turn k", () => {
  assert.deepEqual([...WAITED_CHECKPOINT_KINDS], ["turn", "resize"]);
  assert.deepEqual(staleStatusline(slBaseline("k", FRESH_TWO_TURNS)), [], "every waited row reads its turn");
  assert.deepEqual(staleStatusline(slBaseline("k", STALE_TURN_2)), [{ checkpoint: 1, turn: 1, kind: "turn", shown: ["sl p2/d1"], expected: "sl p2/d2" }]);
  // a resize checkpoint after turn 1; a turn whose prompt the hook never logged
  assert.deepEqual(staleStatusline(slBaseline("k", [[0, "turn", slScreen(slRow(1, 1))], [0, "resize", slScreen(slRow(1, 0))]])).map((s) => s.kind), ["resize"]);
  assert.deepEqual(staleStatusline(slBaseline("k", [[0, "turn", slScreen(slRow(0, 1))]]))[0].shown, ["sl p0/d1"]);
  // the m segment is not the guard's (the lane asserts m1 on each side)
  assert.deepEqual(staleStatusline(slBaseline("k", [[0, "turn", slScreen(slRow(1, 1, 0))]])), []);
  // a stale fragment beside the fresh row: the driver's wait accepted the screen
  assert.deepEqual(staleStatusline(slBaseline("k", [[0, "turn", [...slScreen(slRow(1, 1)), slRow(1, 0)]]])), []);
});

test("staleStatusline: a screen with no fixture row, a dialog, the quit capture and a malformed baseline are not judged", () => {
  const dev = ["❯ DIFF_T1", "  28d77e44 | Model: Haiku 4.5 | Ctx: 12k | ⎇ main (+0,-0)"];
  assert.deepEqual(staleStatusline(slBaseline("k", [[0, "turn", dev], [0, "dialog", slScreen(slRow(0, 0))], [0, "quit", slScreen(slRow(1, 0))]])), []);
  assert.deepEqual(staleStatusline(slBaseline("k", [[0, "turn", ["> DIFF_S1_DONE"]]])), [], "a drill replay's screen");
  for (const b of [null, [], "x", { checkpoints: [slScreen(slRow(1, 0))] }, { side: {}, checkpoints: [slScreen(slRow(1, 0))] },
    { side: { checkpointMarks: [{ turn: -1, kind: "turn" }] }, checkpoints: [slScreen(slRow(1, 0))] },
    { side: { checkpointMarks: [{ turn: 0, kind: "turn" }] }, checkpoints: ["not lines"] },
    { side: { checkpointMarks: [] }, checkpoints: [slScreen(slRow(1, 0))] }]) {
    assert.deepEqual(staleStatusline(b), [], String(JSON.stringify(b)).slice(0, 80));
  }
});

test("describeStale / parseAllowStale: one line for a note; the override is all or a list of baseline keys, and a typo allows nothing", () => {
  const stale = staleStatusline(slBaseline("k", [[0, "turn", slScreen(slRow(1, 0))], [1, "turn", slScreen(slRow(2, 1))]]));
  assert.equal(describeStale(stale), "a stale statusline: checkpoint 0 (turn 1, turn) shows sl p1/d0, not sl p1/d1, and 1 more checkpoint(s)");
  assert.equal(describeStale([]), "");
  assert.deepEqual(parseAllowStale(undefined), { allow: null });
  assert.deepEqual(parseAllowStale("  "), { allow: null });
  assert.deepEqual(parseAllowStale("all"), { allow: "all" });
  assert.deepEqual([...parseAllowStale(" a-1 , b.2,").allow], ["a-1", "b.2"]);
  for (const bad of ["../x", "-dash", ",", "a b"]) {
    const r = parseAllowStale(bad);
    assert.equal(r.allow, null, bad);
    assert.match(r.error, /not a baseline key or "all"; no stale baseline is promoted/, bad);
  }
  assert.equal(ALLOW_STALE_ENV, "MANDU_CI_ALLOW_STALE_STATUSLINE");
});

test("drills/: a baseline whose plain side shows a stale statusline is not promoted and the host's entry for its key is kept; the override promotes it with a note", () => {
  const d = tmp();
  const tree = path.join(d, "tree");
  const baselinesDir = path.join(d, "baselines");
  writeTree(path.join(tree, "drills", "baselines"), {
    "e/fresh/baseline.json": slBaseline("fresh", FRESH_TWO_TURNS),
    "e/stale/baseline.json": slBaseline("stale", STALE_TURN_2),
    "e/stale2/baseline.json": slBaseline("stale2", [[0, "turn", slScreen(slRow(1, 0))]]),
  });
  writeTree(baselinesDir, { "stale/baseline.json": { ...slBaseline("stale", FRESH_TWO_TURNS), recordedAt: "the old one" } });
  const r = promoteBaselines(tree, { baselinesDir });
  assert.deepEqual(r.promoted, ["fresh"]);
  assert.deepEqual(r.stale, ["stale", "stale2"]);
  assert.ok(r.notes.includes("e/stale: not promoted (a stale statusline: checkpoint 1 (turn 2, turn) shows sl p2/d1, not sl p2/d2)"), r.notes.join(" | "));
  assert.equal(readJson(path.join(baselinesDir, "stale", "baseline.json")).recordedAt, "the old one", "the refused baseline replaces nothing");
  assert.ok(!fs.existsSync(path.join(baselinesDir, "stale2")));
  // the override: by key, then all
  const one = promoteBaselines(tree, { baselinesDir: path.join(d, "b1"), allowStale: parseAllowStale("stale2").allow });
  assert.deepEqual(one.promoted, ["fresh", "stale2"]);
  assert.deepEqual(one.stale, ["stale"]);
  assert.ok(one.notes.includes("e/stale2: promoted with a stale statusline: checkpoint 0 (turn 1, turn) shows sl p1/d0, not sl p1/d1, as --allow-stale-statusline asked"), one.notes.join(" | "));
  const all = promoteBaselines(tree, { baselinesDir: path.join(d, "b2"), allowStale: "all" });
  assert.deepEqual(all.promoted, ["fresh", "stale", "stale2"]);
  assert.deepEqual(all.stale, []);
});

test("collect: the guard on the promote path; allowStaleStatusline (the CLI's --allow-stale-statusline) or the job's env overrides; a malformed value overrides nothing", () => {
  const drills = {
    ...SAMPLE_DRILLS,
    "baselines/integration.differential.fidelity-echo/bk-stale/baseline.json": slBaseline("bk-stale", STALE_TURN_2),
  };
  const a = drillsArchive(drills);
  const refused = runDrills(a, { promote: true, env: {} });
  assert.equal(refused.result, "pass", "the guard never changes the run's result");
  assert.deepEqual(refused.baselines.promoted, ["bk-echo-1"]);
  assert.deepEqual(refused.baselines.stale, ["bk-stale"]);
  assert.ok(!fs.existsSync(path.join(refused.baselinesDir, "bk-stale")));
  const byOpt = runDrills(a, { promote: true, env: {}, allowStaleStatusline: "bk-stale" });
  assert.deepEqual(byOpt.baselines.promoted, ["bk-echo-1", "bk-stale"]);
  assert.ok(fs.existsSync(path.join(byOpt.baselinesDir, "bk-stale", "baseline.json")));
  const byEnv = runDrills(a, { promote: true, env: { [ALLOW_STALE_ENV]: "all" } });
  assert.deepEqual(byEnv.baselines.promoted, ["bk-echo-1", "bk-stale"]);
  const typo = runDrills(a, { promote: true, env: { [ALLOW_STALE_ENV]: "bk stale" } });
  assert.deepEqual(typo.baselines.stale, ["bk-stale"]);
  assert.match(typo.baselines.notes[0], /MANDU_CI_ALLOW_STALE_STATUSLINE: bk stale is not a baseline key/);
  const mr = runDrills(a, { env: { [ALLOW_STALE_ENV]: "all" } });
  assert.deepEqual(mr.baselines.promoted, [], "the override never makes an MR's baselines promotable");
});

test("the CLI WARNS of a stale baseline it did not promote and names the override; --allow-stale-statusline promotes it; the exit status stays the run's", () => {
  const d = tmp();
  const env = { PATH: process.env.PATH, HOME: path.join(d, "h"), MANDU_HOME: path.join(d, "m"),
    GITLAB_CI: "true", CI_DEFAULT_BRANCH: "master", CI_COMMIT_BRANCH: "master", CI_PIPELINE_SOURCE: "push" };
  const a = drillsArchive({ ...SAMPLE_DRILLS, "baselines/e/bk-stale/baseline.json": slBaseline("bk-stale", STALE_TURN_2) });
  const cli = (extra = []) => spawnSync(process.execPath, [COLLECTOR, "--archive", a, "--run-id", RUN, "--source", "gitlab", "--commit", COMMIT, "--ref", "master", ...extra], { env, encoding: "utf8" });
  const store = path.join(d, "m", "runs", "drills", "baselines");
  const r = cli();
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /baselines promoted: bk-echo-1\n/);
  assert.match(r.stdout, /WARNING: 1 baseline\(s\) not promoted: the plain side shows a stale statusline, .*: bk-stale\n/);
  assert.match(r.stdout, /--allow-stale-statusline KEY\[,KEY\.\.\.\] \(or all\), or MANDU_CI_ALLOW_STALE_STATUSLINE/);
  assert.match(r.stdout, /drills: e\/bk-stale: not promoted \(a stale statusline: checkpoint 1 \(turn 2, turn\) shows sl p2\/d1, not sl p2\/d2\)/);
  assert.ok(!fs.existsSync(path.join(store, "bk-stale")));
  const o = cli(["--allow-stale-statusline", "bk-stale"]);
  assert.equal(o.status, 0, o.stderr);
  assert.match(o.stdout, /baselines promoted: bk-stale, bk-echo-1\n/);
  assert.doesNotMatch(o.stdout, /WARNING: .*stale statusline/);
  assert.ok(fs.existsSync(path.join(store, "bk-stale", "baseline.json")));
});

// ── drills/'s caps (continuous-integration.md §6) ───────────────────────────────

test("drills/ caps: pipeline.sh's tidy_drills drops at the collector's DRILLS_MAX_*, and the archive's caps leave room beside them", () => {
  const sh = fs.readFileSync(path.join(REPO, "scripts/ci/pipeline.sh"), "utf8");
  const files = /DRILLS_MAX_FILES="\$\{MANDU_CI_DRILLS_MAX_FILES:-(\d+)\}"/.exec(sh);
  const bytes = /DRILLS_MAX_BYTES="\$\{MANDU_CI_DRILLS_MAX_BYTES:-\$\(\((\d+) \* 1024 \* 1024\)\)\}"/.exec(sh);
  assert.ok(files && bytes, "pipeline.sh states its drills/ caps");
  assert.equal(Number(files[1]), DRILLS_MAX_MEMBERS);
  assert.equal(Number(bytes[1]) * 1024 * 1024, DRILLS_MAX_BYTES);
  // the rest of an archive beside a full drills/: summary, junit, the logs
  // (one per entry, ~118 on the per-push run of 2026-10-01; each at most 5 MiB)
  assert.ok(MAX_MEMBERS - DRILLS_MAX_MEMBERS >= 1000, "room for 1,000 more members than drills/ holds");
  assert.ok(MAX_BYTES - DRILLS_MAX_BYTES >= 256 * 1024 * 1024, "room for 256 MiB more than drills/ holds");
  // the measured per-push drills/ (2026-10-01, after one-file baselines): 686 members, ~41 MB
  assert.ok(686 * 4 <= DRILLS_MAX_MEMBERS && 41e6 * 6 <= DRILLS_MAX_BYTES, "4x headroom in members and 6x in bytes over today's per-push run");
});

test("drillsReport: members and bytes from the listing; a WARNING near the cap and when the guest dropped drills/", () => {
  const m = (p, size = 0) => ({ path: p, type: size || p.includes(".") ? "file" : "dir", size });
  const some = [m("drills"), m("drills/replay"), m("drills/replay/run.json", 100), m("logs/a.log", 50), m("summary.json", 10)];
  const ok = drillsReport(some, goodSummary());
  assert.deepEqual(ok, { members: 3, bytes: 100, dropped: false, warnings: [] });
  const near = Array.from({ length: Math.floor(DRILLS_MAX_MEMBERS * DRILLS_WARN_RATIO) + 1 }, (_, i) => m(`drills/replay/f${i}.json`, 1));
  assert.match(drillsReport(near, goodSummary()).warnings[0], /drills\/ is near its cap: \d+ of 3000 members/);
  const heavy = [m("drills/replay/big.cast", Math.ceil(DRILLS_MAX_BYTES * DRILLS_WARN_RATIO) + 1)];
  assert.match(drillsReport(heavy, goodSummary()).warnings[0], /near its cap/);
  const dropped = drillsReport([m("logs/drills.log", 80)], goodSummary({ stages: { suites: { result: "pass", duration_s: 1 }, drills: { result: "skip", duration_s: 0 } } }));
  assert.equal(dropped.dropped, true);
  assert.equal(dropped.members, 0);
  assert.match(dropped.warnings[0], /the guest DROPPED drills\//);
});

test("the CLI says how full drills/ came, and WARNS in the job log when the guest dropped it; the run's result is unchanged", () => {
  const d = tmp();
  const env = { PATH: process.env.PATH, HOME: path.join(d, "h"), MANDU_HOME: path.join(d, "m") };
  const cli = (a) => spawnSync(process.execPath, [COLLECTOR, "--archive", a, "--run-id", RUN, "--source", "gitlab", "--commit", COMMIT, "--ref", "master"], { env, encoding: "utf8" });
  const full = cli(drillsArchive(SAMPLE_DRILLS));
  assert.equal(full.status, 0, full.stderr);
  assert.match(full.stdout, /collect-results: drills\/: \d+ members, \d+ bytes \(the guest's cap: 3000 members, 268435456 bytes\)/);
  assert.doesNotMatch(full.stdout, /WARNING/);
  const s = goodSummary({ stages: { suites: { result: "pass", duration_s: 1 }, drills: { result: "skip", duration_s: 0 } } });
  const dropped = cli(drillsArchive({}, s));
  assert.equal(dropped.status, 0, "a dropped drills/ is a warning, not a red");
  assert.match(dropped.stdout, /collect-results: WARNING: the guest DROPPED drills\/ .*no replay record or baseline of this run is kept/);
});

test("isDefaultBranchRun: a push or schedule on the default branch, from GitLab, recorded with that ref; never an MR, a tag or another branch", () => {
  const env = { GITLAB_CI: "true", CI_DEFAULT_BRANCH: "master", CI_COMMIT_BRANCH: "master", CI_PIPELINE_SOURCE: "push" };
  const o = { source: "gitlab", ref: "master" };
  assert.equal(isDefaultBranchRun(env, o), true);
  assert.equal(isDefaultBranchRun({ ...env, CI_PIPELINE_SOURCE: "schedule" }, o), true);
  for (const [what, e, oo] of [
    ["an MR pipeline", { ...env, CI_PIPELINE_SOURCE: "merge_request_event", CI_MERGE_REQUEST_IID: "7" }, o],
    ["an MR iid at all", { ...env, CI_MERGE_REQUEST_IID: "7" }, o],
    ["another branch", { ...env, CI_COMMIT_BRANCH: "feat/x" }, o],
    ["a tag", { ...env, CI_COMMIT_BRANCH: undefined, CI_COMMIT_TAG: "v1" }, o],
    ["a web-started pipeline", { ...env, CI_PIPELINE_SOURCE: "web" }, o],
    ["not GitLab", { ...env, GITLAB_CI: undefined }, o],
    ["no default branch", { ...env, CI_DEFAULT_BRANCH: "", CI_COMMIT_BRANCH: "" }, { source: "gitlab", ref: "" }],
    ["a local run", env, { source: "local", ref: "master" }],
    ["a run recorded under another ref", env, { source: "gitlab", ref: "feat/x" }],
  ]) assert.equal(isDefaultBranchRun(e, oo), false, what);
});

test("the CLI promotes from the GitLab job's environment, and the exit status stays the run's", () => {
  const d = tmp();
  const env = { PATH: process.env.PATH, HOME: path.join(d, "h"), MANDU_HOME: path.join(d, "m") };
  const a = drillsArchive(SAMPLE_DRILLS);
  const cli = (e) => spawnSync(process.execPath, [COLLECTOR, "--archive", a, "--run-id", RUN, "--source", "gitlab", "--commit", COMMIT, "--ref", "master"], { env: e, encoding: "utf8" });
  const mr = cli({ ...env, GITLAB_CI: "true", CI_DEFAULT_BRANCH: "master", CI_COMMIT_BRANCH: "feat/x", CI_PIPELINE_SOURCE: "merge_request_event", CI_MERGE_REQUEST_IID: "3" });
  assert.equal(mr.status, 0, mr.stderr);
  assert.match(mr.stdout, /replay records \(2 sessions\) in .*\/runs\/drills\/replay\/gl-1234-5678/);
  assert.match(mr.stdout, /baselines not promoted: not a default-branch GitLab run/);
  assert.ok(!fs.existsSync(path.join(d, "m", "runs", "drills", "baselines")));
  const master = cli({ ...env, GITLAB_CI: "true", CI_DEFAULT_BRANCH: "master", CI_COMMIT_BRANCH: "master", CI_PIPELINE_SOURCE: "push" });
  assert.equal(master.status, 0, master.stderr);
  assert.match(master.stdout, /baselines promoted: bk-echo-1/);
  assert.ok(fs.existsSync(path.join(d, "m", "runs", "drills", "baselines", "bk-echo-1", "baseline.json")));
});

test("the default replay dirs are the path table's replay-drill-runs and drill-baselines, beside ci-runs", () => {
  for (const env of [{ MANDU_HOME: "/m", HOME: "/h" }, { HOME: "/home/u" }]) {
    assert.deepEqual(defaultReplayDirs(env), { replayDir: resolvePath("replay-drill-runs", env, env.HOME), baselinesDir: resolvePath("drill-baselines", env, env.HOME) });
    // collect() with --runs-dir puts them under that runs root, the same rows
    assert.equal(path.dirname(defaultReplayDirs(env).replayDir), path.join(path.dirname(defaultRunsDir(env)), "drills"));
  }
  assert.deepEqual(defaultReplayDirs({ MANDU_HOME: "/m", HOME: "/h" }), { replayDir: "/m/runs/drills/replay", baselinesDir: "/m/runs/drills/baselines" });
});

test("drills/: WP0's golden fixture run (the dashboard's copy, dashboard/test/fixtures/replay-run) is collected whole, under the CI run's id", () => {
  const fixture = path.join(REPO, "dashboard/test/fixtures/replay-run");
  const files = {};
  const walk = (rel) => {
    for (const ent of fs.readdirSync(path.join(fixture, rel), { withFileTypes: true })) {
      const r = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) walk(r);
      else files[`replay/integration.differential.fidelity-echo-short/gl-1234-5678/${r}`] = fs.readFileSync(path.join(fixture, r), "utf8");
    }
  };
  walk("");
  const r = runDrills(drillsArchive(files));
  assert.deepEqual(r.replay.notes, [], "every fixture file is a record file the collector keeps");
  const want = Object.keys(files).map((f) => f.split("/").slice(3).join("/")).sort();
  const got = [];
  const walkOut = (rel) => {
    for (const ent of fs.readdirSync(path.join(r.replay.dir, rel), { withFileTypes: true })) {
      const x = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) walkOut(x); else got.push(x);
    }
  };
  walkOut("");
  assert.deepEqual(got.sort(), want);
  const [key] = r.replay.sessions;
  const sess = readJson(path.join(r.replay.dir, "sessions", `${key}.json`));
  assert.equal(sess.sessionId, `${RUN}/${key}`);
  for (const f of sess.files) assert.ok(fs.existsSync(path.join(r.replay.dir, f)), `the session's file ${f} is there`);
  assert.equal(readJson(path.join(r.replay.dir, "run.json")).runId, RUN);
  // byte-identical apart from the forced ids
  assert.equal(fs.readFileSync(path.join(r.replay.dir, sess.casts.mandu), "utf8"), fs.readFileSync(path.join(fixture, sess.casts.mandu), "utf8"));
  // and what the collector wrote passes WP0's own validators, the forced ids
  // included (the replay runner's, where the checkout has the drill tree:
  // the public snapshot does not)
  const tsx = path.join(REPO, "tests/node_modules/.bin/tsx");
  const tree = drillTree(REPO);
  const replayModel = tree && path.join(tree.root, "lib", "replay-model.ts");
  if (!fs.existsSync(tsx) || !replayModel || !fs.existsSync(replayModel)) return;
  const d = tmp();
  const check = path.join(d, "check.ts");
  fs.writeFileSync(check, `import { validateRunMeta, validateSessionRecord } from ${JSON.stringify(replayModel)};
import { readFileSync } from "node:fs";
const meta = validateRunMeta(JSON.parse(readFileSync(${JSON.stringify(path.join(r.replay.dir, "run.json"))}, "utf8")), ${JSON.stringify(RUN)});
const sess = validateSessionRecord(JSON.parse(readFileSync(${JSON.stringify(path.join(r.replay.dir, "sessions", `${key}.json`))}, "utf8")), { runId: ${JSON.stringify(RUN)}, key: ${JSON.stringify(key)} });
console.log(JSON.stringify([typeof meta === "string" ? meta : "ok", typeof sess === "string" ? sess : "ok"]));\n`);
  const v = spawnSync(tsx, [check], { encoding: "utf8", cwd: path.join(REPO, "tests") });
  assert.equal(v.status, 0, v.stderr);
  assert.deepEqual(JSON.parse(v.stdout.trim().split("\n").pop()), ["ok", "ok"]);
});

// ── drills/live: the live-drill records (test-reorganization.md §8.1) ───────
// What pipeline.sh's collect_live leaves under $OUT/drills/live/<drill run>/:
// the live runner's record files (drill-run.ts), the shapes
// the dashboard's watch store reads (the developer view's drill-run-store.ts).
const liveMeta = (over = {}) => ({ runId: "watch-20261002T010203", startedAt: "2026-10-02T01:02:03Z", finishedAt: "2026-10-02T01:30:00Z", status: "done", pid: 777, ws: "/work/x", ids: ["util-shell-echo"], settings: ["secrets"], model: "claude-haiku-4-5", attach: {}, sessions: { "util-shell-echo": "watch-20261002T010203-util-shell-echo" }, casts: { "util-shell-echo": "terminal-util-shell-echo.cast" }, ...over });
const liveChapter = (over = {}) => ({ id: "util-shell-echo", scenarioId: "util-shell-echo", title: "echo", setting: "secrets", scopeId: "watch-20261002T010203-util-shell-echo", cast: "terminal-util-shell-echo.cast", t: 0, verdict: "PASS", turns: [], ...over });
const LR = "watch-20261002T010203";
const GS = `${LR}-util-shell-echo`;
// one event as the guest's own arbiter logged it (the guest's ids; an original the drill's synthetic data)
const LIVE_EVENT = (sid) => `${JSON.stringify({ id: "ev_1", seq: 1, ts: "2026-10-02T01:02:04.000Z", sessionId: sid, batchId: LR, turn: 0, callId: null, parentId: null, kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy", tenant: "test", input: { symbolized: "$MDU:abc", original: "synthetic-canary-value", differs: true, symbols: [] }, output: null, invariant: { violatedInvariant: false } })}\n`;
const SAMPLE_LIVE = {
  [`live/${LR}/meta.json`]: liveMeta(),
  [`live/${LR}/chapters.json`]: [liveChapter()],
  [`live/${LR}/report.json`]: [],
  [`live/${LR}/report.md`]: "# report\n",
  [`live/${LR}/run.log`]: "log\n",
  [`live/${LR}/terminal-util-shell-echo.cast`]: '{"version":2}\n',
  [`live/${LR}/utilshellecho-1.pane.txt`]: "pane\n",
  [`live/${LR}/seed-utilshellecho.json`]: {},
  [`live/${LR}/events-${GS}.ndjson`]: LIVE_EVENT(GS),
  [`live/${LR}/events-${LR}-not-named.ndjson`]: LIVE_EVENT(`${LR}-not-named`),
  [`live/${LR}/notes.txt`]: "not a record file\n",
  [`live/${LR}/ws-util-shell-echo/.env`]: "SECRET-WS\n",
  [`live/${LR}/arbiter/symbols.db`]: "SECRET-DB\n",
};
const liveFiles = (dir) => fs.readdirSync(dir).sort();

test("drills/live: the record files land in the host's live store as <CI run>.<drill run>, meta's runId that name; nothing else is copied", () => {
  const r = runDrills(drillsArchive(SAMPLE_LIVE));
  const liveDir = path.join(path.dirname(r.replayDir), "live");
  const name = `${RUN}.${LR}`;
  assert.deepEqual(r.live.runs, [name]);
  assert.equal(r.live.dir, liveDir, "beside runs/ci, under the same runs root");
  const dir = path.join(liveDir, name);
  assert.deepEqual(liveFiles(dir), [LIVE_MARKER, "chapters.json", `events-${name}-util-shell-echo.ndjson`, "meta.json", "report.json", "report.md", "run.log", "seed-utilshellecho.json", "terminal-util-shell-echo.cast", "utilshellecho-1.pane.txt"].sort());
  const meta = readJson(path.join(dir, "meta.json"));
  assert.equal(meta.runId, name);
  assert.equal(meta.status, "done");
  assert.equal(meta.pid, 0, "a guest's pid means nothing on the host");
  assert.equal(meta.startedAt, "2026-10-02T01:02:03Z");
  assert.deepEqual(readJson(path.join(dir, LIVE_MARKER)), { kind: "mandu-ci-live-run", ciRun: RUN, commit: COMMIT, guestRun: LR, sessions: { [GS]: `${name}-util-shell-echo` } });
  assert.ok(r.live.notes.some((n) => /notes\.txt: skipped \(not a live record file\)/.test(n)));
  assert.ok(r.live.notes.some((n) => /ws-util-shell-echo: skipped \(not a live record file\)/.test(n)));
  assert.ok(r.live.notes.some((n) => /arbiter: skipped \(not a live record file\)/.test(n)));
  assert.ok(!fs.existsSync(path.join(r.runsDir, RUN, "drills")), "runs/ci/<run> holds no drills/");
});

test("drills/live: a baseline's wire.ndjson and the demo battery's compare.md come back too (the numbers lane, continuous-integration.md §9.9); look-alikes do not", () => {
  const r = runDrills(drillsArchive({
    ...SAMPLE_LIVE,
    [`live/${LR}/wire.ndjson`]: '{"seq":1,"reqHeaders":{"authorization":"[redacted]"}}\n',
    [`live/${LR}/compare.md`]: "| setting | model |\n",
    [`live/${LR}/wire.ndjson.bak`]: "x\n",
    [`live/${LR}/model-capture.ndjson`]: "x\n",
  }));
  const dir = path.join(path.dirname(r.replayDir), "live", `${RUN}.${LR}`);
  const files = liveFiles(dir);
  assert.ok(files.includes("wire.ndjson") && files.includes("compare.md"), files.join(" "));
  assert.equal(fs.readFileSync(path.join(dir, "compare.md"), "utf8"), "| setting | model |\n");
  assert.ok(!files.includes("wire.ndjson.bak") && !files.includes("model-capture.ndjson"));
  for (const f of ["wire.ndjson", "compare.md"]) assert.ok(LIVE_DATA_FILE_RE.test(f) && !LIVE_RUN_FILE_RE.test(f), `${f}: a data file, not served by the dashboard's file route`);
  const sh = fs.readFileSync(path.join(REPO, "scripts/ci/pipeline.sh"), "utf8");
  const shFile = new RegExp(/^LIVE_FILE_RE='(.+)'$/m.exec(sh)[1]);
  for (const f of ["wire.ndjson", "compare.md"]) assert.ok(shFile.test(f), `pipeline.sh's collect_live carries ${f}`);
  for (const f of ["wire.ndjson.bak", "model-capture.ndjson", "compare.txt"]) assert.ok(!shFile.test(f) && !LIVE_DATA_FILE_RE.test(f), f);
  assert.match(sh, /-name 'wire\.ndjson' -printf/, "a wire log is trimmed before the record files are dropped");
});

test("drills/live: owner-only in the store and in --out (0700 directories, 0600 files): an event log holds originals", () => {
  const out = path.join(tmp(), "ci-out");
  const r = runDrills(drillsArchive(SAMPLE_LIVE), { out });
  const liveDir = path.join(path.dirname(r.replayDir), "live");
  const dir = path.join(liveDir, `${RUN}.${LR}`);
  assert.equal(fs.statSync(liveDir).mode & 0o777, 0o700, "the store, created by the collector");
  assert.equal(fs.statSync(dir).mode & 0o777, 0o700, "the run");
  for (const f of liveFiles(dir)) assert.equal(fs.statSync(path.join(dir, f)).mode & 0o777, 0o600, f);
  const outRun = path.join(out, "drills", "live", LR);
  assert.equal(fs.statSync(path.join(out, "drills", "live")).mode & 0o777, 0o700);
  assert.equal(fs.statSync(outRun).mode & 0o777, 0o700);
  for (const f of liveFiles(outRun)) {
    const st = fs.statSync(path.join(outRun, f));
    assert.equal(st.mode & 0o777, st.isFile() ? 0o600 : 0o700, f);
  }
});

test("drills/live: each session id the record names, and its event log, becomes the host's (<CI part>.<guest session>); a log of a session the run does not name is skipped", () => {
  const r = runDrills(drillsArchive({
    ...SAMPLE_LIVE,
    [`live/${LR}/meta.json`]: liveMeta({ sessions: { "util-shell-echo": GS, secrets: `${LR}-secrets` } }),
    [`live/${LR}/report.json`]: [{ id: "util-shell-echo", setting: "secrets", scopeId: GS, verdict: "PASS", turns: [] }],
    [`live/${LR}/chapters.json`]: [liveChapter(), liveChapter({ id: "x", scopeId: "x".repeat(199) })],
  }));
  const name = `${RUN}.${LR}`;
  const dir = path.join(path.dirname(r.replayDir), "live", name);
  assert.deepEqual(readJson(path.join(dir, "meta.json")).sessions, { "util-shell-echo": `${name}-util-shell-echo`, secrets: `${name}-secrets` });
  const ch = readJson(path.join(dir, "chapters.json"));
  assert.equal(ch[0].scopeId, `${name}-util-shell-echo`);
  assert.equal(ch[1].scopeId, "x".repeat(199), "an id too long once namespaced keeps the guest's (and carries no events)");
  assert.equal(readJson(path.join(dir, "report.json"))[0].scopeId, `${name}-util-shell-echo`);
  assert.equal(fs.readFileSync(path.join(dir, `events-${name}-util-shell-echo.ndjson`), "utf8"), LIVE_EVENT(GS), "the bytes as they came; the dashboard stamps the host id");
  assert.ok(!fs.readdirSync(dir).some((f) => f.includes("not-named")));
  assert.ok(r.live.notes.some((n) => new RegExp(`events-${LR}-not-named\\.ndjson: skipped \\(not a session the run names\\)`).test(n)));
});

test("liveSessionName: <CI part>.<guest session>, so <drill run>-<key> reads <host run>-<key>; null when not a session id or too long", () => {
  assert.equal(liveSessionName(`${RUN}.${LR}`, LR, GS), `${RUN}.${GS}`);
  assert.equal(liveSessionName(`${RUN}.${LR}`, LR, GS), `${RUN}.${LR}-util-shell-echo`);
  assert.equal(liveSessionName(`ci-0123456789ab.${LR}`, LR, "mandu-x"), "ci-0123456789ab.mandu-x");
  assert.equal(liveSessionName(`${RUN}.${LR}`, LR, "../x"), null);
  assert.equal(liveSessionName(`${RUN}.${LR}`, LR, "a/b"), null);
  assert.equal(liveSessionName(`${RUN}.${LR}`, LR, "x".repeat(195)), null);
  assert.equal(liveSessionName(`${RUN}.other`, LR, GS), null, "the host run must be that guest run's");
  assert.ok(LIVE_EVENTS_FILE_RE.test(`events-${RUN}.${GS}.ndjson`));
  for (const f of ["events-.ndjson", "events-a/b.ndjson", "events-.x.ndjson", "events-x.json", "x.ndjson"]) assert.ok(!LIVE_EVENTS_FILE_RE.test(f), f);
  assert.ok(LIVE_SESSION_ID_RE.test(`${RUN}.${GS}`));
});

test("drills/live: an event log over MAX_RECORD_FILE_BYTES is skipped, the run kept", () => {
  const d = tmp();
  const tree = path.join(d, "tree");
  writeTree(path.join(tree, "drills"), { [`live/${LR}/meta.json`]: liveMeta(), [`live/${LR}/chapters.json`]: [liveChapter()] });
  const big = path.join(tree, "drills", "live", LR, `events-${GS}.ndjson`);
  fs.writeFileSync(big, "");
  fs.truncateSync(big, MAX_RECORD_FILE_BYTES + 1);
  const r = collectLive(tree, { runId: RUN, liveDir: path.join(d, "live") });
  assert.deepEqual(r.runs, [`${RUN}.${LR}`]);
  assert.ok(!fs.readdirSync(path.join(d, "live", `${RUN}.${LR}`)).some((f) => f.startsWith("events-")));
  assert.ok(r.notes.some((n) => /events-.*\.ndjson: skipped \(over \d+ bytes\)/.test(n)));
});

test("drills/live: a `running` meta (the guest's runner is gone) reads aborted; a bad chapters.json is skipped, a bad meta.json skips the run", () => {
  const r = runDrills(drillsArchive({
    [`live/${LR}/meta.json`]: liveMeta({ status: "running" }),
    [`live/${LR}/chapters.json`]: { not: "an array" },
    "live/watch-nostart/meta.json": liveMeta({ startedAt: undefined }),
    "live/watch-notjson/meta.json": "{nope",
    "live/watch-array/meta.json": [],
  }));
  assert.deepEqual(r.live.runs, [`${RUN}.${LR}`]);
  const dir = path.join(path.dirname(r.replayDir), "live", `${RUN}.${LR}`);
  assert.equal(readJson(path.join(dir, "meta.json")).status, "aborted");
  assert.ok(!fs.existsSync(path.join(dir, "chapters.json")));
  assert.ok(r.live.notes.some((n) => /chapters\.json: skipped \(not a JSON array\)/.test(n)));
  assert.ok(r.live.notes.some((n) => /watch-nostart: not copied \(meta\.json has no startedAt\)/.test(n)));
  assert.ok(r.live.notes.some((n) => /watch-notjson: not copied \(meta\.json: /.test(n)));
  assert.ok(r.live.notes.some((n) => /watch-array: not copied \(meta\.json: not a JSON object\)/.test(n)));
});

test("drills/live: one level deeper (a sandboxed entry's own store) is read too; a name two directories hold keeps the first", () => {
  const r = runDrills(drillsArchive({
    [`live/drill.secrets.util/${LR}/meta.json`]: liveMeta({ model: "second" }),
    [`live/drill.secrets.conf/${LR}/meta.json`]: liveMeta({ model: "first" }),
  }));
  assert.deepEqual(r.live.runs, [`${RUN}.${LR}`]);
  assert.equal(readJson(path.join(path.dirname(r.replayDir), "live", `${RUN}.${LR}`, "meta.json")).model, "first", "sorted: drill.secrets.conf comes first");
  assert.ok(r.live.notes.some((n) => /drill\.secrets\.util\/watch-20261002T010203: not copied \(a run of that name came from an earlier directory\)/.test(n)));
});

test("drills/live: a record file over MAX_RECORD_FILE_BYTES is skipped", () => {
  const d = tmp();
  const tree = path.join(d, "tree");
  writeTree(path.join(tree, "drills"), { [`live/${LR}/meta.json`]: liveMeta() });
  const big = path.join(tree, "drills", "live", LR, "terminal-big.cast");
  fs.writeFileSync(big, "");
  fs.truncateSync(big, MAX_RECORD_FILE_BYTES + 1);
  const r = collectLive(tree, { runId: RUN, liveDir: path.join(d, "live") });
  assert.deepEqual(r.runs, [`${RUN}.${LR}`]);
  assert.ok(!fs.existsSync(path.join(d, "live", `${RUN}.${LR}`, "terminal-big.cast")));
  assert.ok(r.notes.some((n) => /terminal-big\.cast: skipped \(over \d+ bytes\)/.test(n)));
});

test("liveRunName: <CI run>.<drill run>, a colon a dash; a hash of the CI run when too long; null for a bad drill run", () => {
  assert.equal(liveRunName("gl-1-2", "watch-20261002T010203"), "gl-1-2.watch-20261002T010203");
  assert.equal(liveRunName("local:x", "watch-1"), "local-x.watch-1");
  const long = liveRunName(`nightly-subscription-${"9".repeat(80)}`, "watch-20261002T010203");
  assert.match(long, /^ci-[0-9a-f]{12}\.watch-20261002T010203$/);
  assert.equal(liveRunName("gl-1", "../x"), null);
  assert.equal(liveRunName("gl-1", ".hidden"), null);
  assert.equal(liveRunName("gl-1", "w".repeat(81)), null, "no host name fits");
  for (const n of ["gl-1-2.watch-1", long]) assert.ok(LIVE_RUN_ID_RE.test(n));
});

test("pruneLive: keeps the newest CI-brought runs (ci-run.json) and never touches the host's own", () => {
  const d = tmp();
  const t0 = Date.now() / 1000;
  for (let i = 0; i < 5; i++) {
    const dir = path.join(d, `gl-${i}.watch-1`);
    writeTree(dir, { "meta.json": liveMeta(), [LIVE_MARKER]: {} });
    fs.utimesSync(path.join(dir, LIVE_MARKER), t0 - 100 + i, t0 - 100 + i);
  }
  writeTree(path.join(d, "watch-host-own"), { "meta.json": liveMeta() });
  fs.utimesSync(path.join(d, "watch-host-own"), t0 - 1000, t0 - 1000);
  const removed = pruneLive(d, 2);
  assert.equal(removed.length, 3);
  assert.deepEqual(fs.readdirSync(d).sort(), ["gl-3.watch-1", "gl-4.watch-1", "watch-host-own"]);
});

// ── pins: the records a prune never removes (continuous-integration.md §6) ──
const pinIn = (dir) => fs.writeFileSync(path.join(dir, PIN_FILE), `${JSON.stringify({ kind: "mandu-keep", reason: "test" })}\n`);

test("pruneRuns: a pinned run (.keep) survives past the cap and does not count toward it; unpinned ones still rotate", () => {
  const d = tmp();
  for (let i = 0; i < 6; i++) {
    const dir = path.join(d, `old-${i}`);
    writeTree(dir, { "summary.json": {} });
    const t = new Date(Date.UTC(2020, 0, 1) + i * 1000);
    fs.utimesSync(path.join(dir, "summary.json"), t, t);
  }
  pinIn(path.join(d, "old-0")); // the oldest
  pinIn(path.join(d, "old-4"));
  const removed = pruneRuns(d, 3);
  // unpinned: 1, 2, 3, 5; the newest 3 of them stay. Had the pins counted, 2 and 3 would go too.
  assert.deepEqual(removed.map((p) => path.basename(p)), ["old-1"]);
  assert.deepEqual(fs.readdirSync(d).sort(), ["old-0", "old-2", "old-3", "old-4", "old-5"]);
  assert.deepEqual(pruneRuns(d, 1).map((p) => path.basename(p)).sort(), ["old-2", "old-3"], "rotating on: the pins stay put");
  assert.deepEqual(fs.readdirSync(d).sort(), ["old-0", "old-4", "old-5"]);
});

test("pruneLive: a pinned CI-brought run survives past the cap and does not count; the host's own and the unpinned behave as before", () => {
  const d = tmp();
  const t0 = Date.now() / 1000;
  for (let i = 0; i < 5; i++) {
    const dir = path.join(d, `gl-${i}.watch-1`);
    writeTree(dir, { "meta.json": liveMeta(), [LIVE_MARKER]: { ciRun: `gl-${i}` } });
    fs.utimesSync(path.join(dir, LIVE_MARKER), t0 - 100 + i, t0 - 100 + i);
  }
  writeTree(path.join(d, "watch-host-own"), { "meta.json": liveMeta() });
  pinIn(path.join(d, "gl-0.watch-1"));
  pinIn(path.join(d, "gl-1.watch-1"));
  assert.ok(isPinned(path.join(d, "gl-0.watch-1")) && !isPinned(path.join(d, "gl-2.watch-1")));
  const removed = pruneLive(d, 2);
  assert.deepEqual(removed.map((p) => path.basename(p)), ["gl-2.watch-1"], "the cap of 2 counts gl-2..4 only");
  assert.deepEqual(fs.readdirSync(d).sort(), ["gl-0.watch-1", "gl-1.watch-1", "gl-3.watch-1", "gl-4.watch-1", "watch-host-own"]);
});

test("pinnedJob: the demo battery's jobs pin (the subscription's and the API key's, alone or in a list); its scripted rehearsal and any other selection do not", () => {
  assert.deepEqual(PINNED_JOBS, ["live.demo-battery", "live.demo-battery.api"]);
  assert.equal(pinnedJob("live.demo-battery"), "live.demo-battery");
  assert.equal(pinnedJob("deps.audit-npm, live.demo-battery"), "live.demo-battery");
  assert.equal(pinnedJob("live.demo-battery.api"), "live.demo-battery.api");
  assert.equal(pinnedJob("deps.audit-npm,live.demo-battery.api"), "live.demo-battery.api");
  for (const no of ["live.demo-battery.rehearsal", "live.demo-battery-x", "live.demo-battery.api-x", "live.demo-battery.ap", "", undefined, null, "unit"]) assert.equal(pinnedJob(no), null, String(no));
});

test("a collected demo battery on the API key comes out pinned too, naming its job", () => {
  const r = runDrills(drillsArchive(batteryLive()), { only: "live.demo-battery.api" });
  assert.equal(r.pinned, "live.demo-battery.api");
  assert.ok(isPinned(r.dir));
  const pin = readJson(path.join(r.live.dir, r.live.runs[0], PIN_FILE));
  assert.match(pin.reason, /live\.demo-battery\.api/);
});

const BATTERY_RUN = "demo-20261017T120740-demo-c2-mandu";
const batteryLive = (lr = BATTERY_RUN) => ({
  [`live/${lr}/meta.json`]: liveMeta({ runId: lr, sessions: {} }),
  [`live/${lr}/report.json`]: [],
  [`live/${lr}/compare.md`]: "# compare\n",
  [`live/${lr}/${PIN_FILE}`]: "the guest's own pin\n",
});
const collectAs = (runId, lr, runsDir, extra = {}) => collect({ archive: drillsArchive(batteryLive(lr), goodSummary({ run: runId })), runId, commit: COMMIT,
  image: "mandu-ci-3f2a0000aaaa1111", runsDir, ...extra });

test("a collected demo battery comes out PINNED (its run directory and every live run), survives the prunes, and keeps its pin when collected again", () => {
  const r = runDrills(drillsArchive({ ...batteryLive(), ...batteryLive(`${BATTERY_RUN}-2`) }), { only: "live.demo-battery", maxRuns: 1, maxLiveRuns: 1 });
  assert.equal(r.result, "pass");
  assert.equal(r.pinned, "live.demo-battery");
  assert.ok(isPinned(r.dir), "the run directory (the summary) is pinned");
  assert.equal(r.live.runs.length, 2);
  for (const name of r.live.runs) {
    const dir = path.join(r.live.dir, name);
    const pin = readJson(path.join(dir, PIN_FILE));
    assert.equal(pin.kind, "mandu-keep");
    assert.match(pin.reason, /live\.demo-battery/);
    assert.equal(fs.statSync(path.join(dir, PIN_FILE)).mode & 0o777, 0o600, "owner-only, as the store");
  }
  assert.ok(r.live.notes.some((n) => n.includes(`${PIN_FILE}: skipped (not a live record file)`)), "the guest's own .keep is never carried: the host pins");
  // the stores rotate past it: two later, unpinned CI runs at a cap of 1
  const later = collectAs("gl-later", "watch-later", r.runsDir, { maxRuns: 1, maxLiveRuns: 1 });
  assert.equal(later.pinned, null);
  const laterLive = path.join(later.live.dir, "gl-later.watch-later");
  assert.ok(!isPinned(later.dir) && !isPinned(laterLive));
  const third = collectAs("gl-third", "watch-third", r.runsDir, { maxRuns: 1, maxLiveRuns: 1 });
  assert.ok(!fs.existsSync(later.dir) && !fs.existsSync(laterLive), "the unpinned rotate");
  assert.ok(fs.existsSync(r.dir) && fs.existsSync(third.dir));
  for (const name of r.live.runs) assert.ok(fs.existsSync(path.join(r.live.dir, name, "compare.md")), `${name} is kept`);
  // the same run id collected again WITHOUT --only: the pins carry over
  const re = collectAs(RUN, BATTERY_RUN, r.runsDir);
  assert.equal(re.pinned, null);
  assert.ok(isPinned(re.dir), "a replaced run directory keeps its pin");
  assert.ok(isPinned(path.join(re.live.dir, re.live.runs[0])), "a replaced live run keeps its pin");
});

test("only the host pins: no --only, the rehearsal, or a .keep in the guest's archive pin nothing (a top-level .keep refuses the archive)", () => {
  for (const extra of [{}, { only: "live.demo-battery.rehearsal" }]) {
    const r = runDrills(drillsArchive(batteryLive()), extra);
    assert.equal(r.pinned, null);
    assert.ok(!isPinned(r.dir));
    assert.ok(!isPinned(path.join(r.live.dir, r.live.runs[0])));
  }
  const bad = run(archive([...goodParts(), member(PIN_FILE, "")]));
  assert.equal(bad.result, "error");
  assert.ok(!isPinned(bad.dir));
});

/** A host store: runs/ci/<run>/ and runs/drills/live/<name>/ with markers. */
function pinStore() {
  const d = tmp();
  const runsDir = path.join(d, "runs", "ci");
  const liveDir = path.join(d, "runs", "drills", "live");
  const battery = "local-20261017-041123-b26ba674";
  writeTree(path.join(runsDir, battery), { "summary.json": {} });
  writeTree(path.join(runsDir, "gl-other"), { "summary.json": {} });
  const hashed = liveRunName(battery, `demo-20261017T041200-demo-c1-baseline-cc-mask-${"x".repeat(10)}`);
  assert.match(hashed, /^ci-[0-9a-f]{12}\./, "a long name holds a hash of the run id, not the id");
  for (const [name, ciRun] of [[`${battery}.demo-c1-mandu`, battery], [hashed, battery], ["gl-other.watch-1", "gl-other"]]) {
    writeTree(path.join(liveDir, name), { "meta.json": liveMeta(), [LIVE_MARKER]: { kind: "mandu-ci-live-run", ciRun } });
  }
  writeTree(path.join(liveDir, "watch-host-own"), { "meta.json": liveMeta() });
  return { d, runsDir, liveDir, battery, hashed };
}

test("pinRun / unpinRun / listPinned: a CI run's summary and every live run it brought (by its marker, hashed names too); nothing else", () => {
  const { runsDir, liveDir, battery, hashed } = pinStore();
  assert.deepEqual(liveRunsOf(liveDir, battery).map((p) => path.basename(p)), [`${battery}.demo-c1-mandu`, hashed].sort());
  const p = pinRun(battery, { runsDir, liveDir, reason: "comparisons.md §5, battery 3" });
  assert.equal(p.ci, path.join(runsDir, battery));
  assert.equal(p.live.length, 2);
  assert.ok(!isPinned(path.join(runsDir, "gl-other")) && !isPinned(path.join(liveDir, "gl-other.watch-1")) && !isPinned(path.join(liveDir, "watch-host-own")));
  const rows = listPinned({ runsDir, liveDir });
  assert.equal(rows.length, 1);
  assert.deepEqual({ ...rows[0], pinnedAt: undefined }, { ciRun: battery, ci: true, live: 2, reason: "comparisons.md §5, battery 3", pinnedAt: undefined });
  assert.match(rows[0].pinnedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  // the pins hold through the prunes, at a cap of 0
  pruneRuns(runsDir, 0);
  pruneLive(liveDir, 0);
  assert.deepEqual(fs.readdirSync(runsDir), [battery]);
  assert.deepEqual(fs.readdirSync(liveDir).sort(), [`${battery}.demo-c1-mandu`, hashed, "watch-host-own"].sort());
  // a run whose records are gone: nothing to pin
  assert.deepEqual(pinRun("gl-other", { runsDir, liveDir }), { ci: null, live: [] });
  assert.throws(() => pinRun("../x", { runsDir, liveDir }), /bad CI run id/);
  const u = unpinRun(battery, { runsDir, liveDir });
  assert.equal(u.ci, path.join(runsDir, battery));
  assert.equal(u.live.length, 2);
  assert.deepEqual(listPinned({ runsDir, liveDir }), []);
  assert.deepEqual(unpinRun(battery, { runsDir, liveDir }), { ci: null, live: [] }, "nothing left to unpin");
});

test("pin store: a .keep that is a symlink is replaced, never followed", () => {
  const { d, runsDir, liveDir, battery } = pinStore();
  const target = path.join(d, "elsewhere");
  fs.writeFileSync(target, "untouched\n");
  fs.symlinkSync(target, path.join(runsDir, battery, PIN_FILE));
  pinRun(battery, { runsDir, liveDir });
  assert.equal(fs.readFileSync(target, "utf8"), "untouched\n");
  assert.ok(fs.lstatSync(path.join(runsDir, battery, PIN_FILE)).isFile());
});

test("the CLI: --pin <CI run>, --pinned, --unpin; exit 1 when nothing of the run is left; the modes go alone", () => {
  const { runsDir, liveDir, battery } = pinStore();
  const cli = (args) => spawnSync(process.execPath, [COLLECTOR, ...args, "--runs-dir", runsDir], { encoding: "utf8", env: { PATH: process.env.PATH, HOME: "/nonexistent" } });
  const p = cli(["--pin", battery, "--reason", "published"]);
  assert.equal(p.status, 0, p.stderr);
  assert.ok(p.stdout.includes(`pinned ${battery}: summary ${path.join(runsDir, battery)}; 2 live run(s) in ${liveDir}`), `--runs-dir moves the live store with it: ${p.stdout}`);
  const l = cli(["--pinned"]);
  assert.equal(l.status, 0, l.stderr);
  assert.match(l.stdout, new RegExp(`${battery}  summary pinned  live 2  \\S+  published`));
  assert.match(l.stdout, /1 pinned CI run\(s\)/);
  const gone = cli(["--pin", "local-20200101-000000-deadbeef"]);
  assert.equal(gone.status, 1);
  assert.match(gone.stdout, /is left to pin \(its records are gone\)/);
  const u = cli(["--unpin", battery]);
  assert.equal(u.status, 0, u.stderr);
  assert.match(cli(["--pinned"]).stdout, /0 pinned CI run\(s\)/);
  assert.equal(cli(["--pin", battery, "--unpin", battery]).status, 2);
  assert.equal(cli(["--pin", "../etc"]).status, 2);
});

test("drills/live: the collector's and pipeline.sh's record names are the developer view's (drill-run-store.ts RUN_ID_RE, RUN_FILE_RE, WATCH_JSON_MAX_BYTES)", { skip: DEV === null && "no developer view in this checkout" }, () => {
  const src = fs.readFileSync(path.join(DEV, "src/drill-run-store.ts"), "utf8");
  const re = (name) => { const m = new RegExp(`export const ${name} = (/.+/);`).exec(src); assert.ok(m, name); return m[1]; };
  assert.equal(re("RUN_ID_RE"), String(LIVE_RUN_ID_RE));
  assert.equal(re("RUN_FILE_RE"), String(LIVE_RUN_FILE_RE));
  assert.match(src, /export const WATCH_JSON_MAX_BYTES = 16 \* 1024 \* 1024;/);
  const sh = fs.readFileSync(path.join(REPO, "scripts/ci/pipeline.sh"), "utf8");
  const run = /^LIVE_RUN_RE='(.+)'$/m.exec(sh);
  const file = /^LIVE_FILE_RE='(.+)'$/m.exec(sh);
  assert.ok(run && file, "pipeline.sh states its live record names");
  assert.equal(`/${run[1]}/`, String(LIVE_RUN_ID_RE));
  const shFile = new RegExp(file[1]);
  const records = ["meta.json", "chapters.json", "report.json", "matrix.json", "terminal-util-x-1.cast", "run.log", "report.md", "utilx-12.pane.txt", "seed-utilx.json"];
  for (const f of records) assert.ok(shFile.test(f), f);
  for (const f of records.slice(4)) assert.ok(LIVE_RUN_FILE_RE.test(f), f);
  for (const f of ["ci-run.json", "model-util-x.ndjson", "boot-x.pane.txt", "arbiter", "terminal-X.cast", "seed-a-b.json", "meta.json.bak", "policy.yaml"]) {
    assert.ok(!shFile.test(f), f);
    assert.ok(!LIVE_RUN_FILE_RE.test(f), f);
  }
});

test("drills/live caps: pipeline.sh's collect_live caps are the collector's LIVE_MAX_*, and the archive has room for both trees and the logs", () => {
  const sh = fs.readFileSync(path.join(REPO, "scripts/ci/pipeline.sh"), "utf8");
  const files = /LIVE_MAX_FILES="\$\{MANDU_CI_LIVE_MAX_FILES:-(\d+)\}"/.exec(sh);
  const bytes = /LIVE_MAX_BYTES="\$\{MANDU_CI_LIVE_MAX_BYTES:-\$\(\((\d+) \* 1024 \* 1024\)\)\}"/.exec(sh);
  assert.ok(files && bytes, "pipeline.sh states its drills/live caps");
  assert.equal(Number(files[1]), LIVE_MAX_MEMBERS);
  assert.equal(Number(bytes[1]) * 1024 * 1024, LIVE_MAX_BYTES);
  assert.ok(MAX_MEMBERS - DRILLS_MAX_MEMBERS - LIVE_MAX_MEMBERS >= 1000, "room for 1,000 more members than drills/ and drills/live hold");
  assert.ok(MAX_BYTES - DRILLS_MAX_BYTES - LIVE_MAX_BYTES >= 256 * 1024 * 1024, "room for 256 MiB more than both hold");
  // a nightly: 41 live drills in 5 entries, ~7 members a drill (with its
  // event log) and 5 a run
  assert.ok((41 * 7 + 5 * 5) * 3 <= LIVE_MAX_MEMBERS, "3x headroom in members over a nightly's live drills");
  // the demo battery: 6 demos x (Mandu + 5 baselines) x 3 rounds, one drill a
  // run, ~12 members a run (meta, chapters, report.json/.md, run.log, seed,
  // wire, compare.md, cast, two panes, the directory): it fits with every
  // pane capture kept (2026-10-17: past 1,000 the trim took the panes)
  assert.ok(6 * 6 * 3 * 12 * 1.5 <= LIVE_MAX_MEMBERS, "1.5x headroom in members over a demo battery");
  // the two-model battery (2026-10-18): 9 demos x (Mandu + 9 sides) x 2
  // models x 3 takes = 540 runs, ~13 members a run (the above and an event
  // log), ~1.1 MB a run measured (the wire log ~0.8 MB): kept whole, and its
  // record files alone (7 a run) far from the drop
  assert.ok(540 * 13 * 1.4 <= LIVE_MAX_MEMBERS, "1.4x headroom in members over a two-model battery");
  assert.ok(540 * 1.1e6 * 1.3 <= LIVE_MAX_BYTES, "1.3x headroom in bytes over a two-model battery");
  assert.ok(540 * 7 * 2 <= LIVE_MAX_MEMBERS, "its record files alone are under half the cap");
  // the archive fits the results disk vm-run.sh gives the guest
  const vm = fs.readFileSync(path.join(REPO, "scripts/ci/vm-run.sh"), "utf8");
  const disk = /truncate -s (\d+)G "\$OUTPUT"/.exec(vm);
  assert.ok(disk, "vm-run.sh sizes the results disk");
  assert.ok(MAX_BYTES + MAX_MEMBERS * 1024 + 64 * 1024 * 1024 <= Number(disk[1]) * 1024 ** 3, "the archive at its caps (and a tar header a member) fits the results disk");
  // the event logs' own budget (live-events.mjs) sits inside drills/live's bytes
  const ev = /LIVE_EVENTS_MAX_BYTES="\$\{MANDU_CI_LIVE_EVENTS_MAX_BYTES:-\$\(\((\d+) \* 1024 \* 1024\)\)\}"/.exec(sh);
  assert.ok(ev, "pipeline.sh states its events budget");
  assert.equal(Number(ev[1]) * 1024 * 1024, EVENTS_MAX_BYTES);
  assert.ok(EVENTS_MAX_BYTES <= LIVE_MAX_BYTES / 2, "the event logs take at most half of drills/live");
  assert.equal(EVENTS_FILE_MAX_BYTES, MAX_RECORD_FILE_BYTES, "one event log: the collector's per-file cap");
  assert.match(sh, /--max-file-bytes "\$LIVE_FILE_MAX"/);
  assert.match(sh, /^LIVE_FILE_MAX=\$\(\(32 \* 1024 \* 1024\)\)$/m);
});

test("liveReport / drillsReport: each counts its own tree (drills/live out of drills/'s count); WARNINGs near a cap and on the stage drills-live: skip", () => {
  const m = (p, size = 0) => ({ path: p, type: size || p.includes(".") ? "file" : "dir", size });
  const both = [m("drills"), m("drills/replay"), m("drills/replay/run.json", 100), m("drills/live"), m(`drills/live/${LR}`), m(`drills/live/${LR}/meta.json`, 40)];
  assert.deepEqual(drillsReport(both, goodSummary()), { members: 3, bytes: 100, dropped: false, warnings: [] });
  assert.deepEqual(liveReport(both, goodSummary()), { members: 3, bytes: 40, dropped: false, warnings: [] });
  const near = Array.from({ length: Math.floor(LIVE_MAX_MEMBERS * DRILLS_WARN_RATIO) + 1 }, (_, i) => m(`drills/live/r/f${i}.json`, 1));
  assert.match(liveReport(near, goodSummary()).warnings[0], new RegExp(`drills/live is near its cap: \\d+ of ${LIVE_MAX_MEMBERS} members`));
  assert.deepEqual(drillsReport(near, goodSummary()).warnings, [], "drills/live's members are not drills/'s");
  const dropped = liveReport([], goodSummary({ stages: { suites: { result: "pass", duration_s: 1 }, "drills-live": { result: "skip", duration_s: 0 } } }));
  assert.equal(dropped.dropped, true);
  assert.match(dropped.warnings[0], /the guest DROPPED drills\/live/);
});

test("the CLI copies the live records into the path table's live-drill-runs (runs/drills/live) and says so; --live-dir moves them", () => {
  const d = tmp();
  const env = { PATH: process.env.PATH, HOME: path.join(d, "h"), MANDU_HOME: path.join(d, "m") };
  const a = drillsArchive(SAMPLE_LIVE);
  const cli = (extra = []) => spawnSync(process.execPath, [COLLECTOR, "--archive", a, "--run-id", RUN, "--source", "gitlab", "--commit", COMMIT, "--ref", "master", ...extra], { env, encoding: "utf8" });
  const r = cli();
  assert.equal(r.status, 0, r.stderr);
  assert.equal(defaultLiveDir(env), path.join(d, "m", "runs", "drills", "live"));
  assert.equal(defaultLiveDir(env), resolvePath("live-drill-runs", env, env.HOME));
  assert.match(r.stdout, new RegExp(`collect-results: live-drill records \\(1 runs: ${RUN}\\.${LR}\\) in .*/m/runs/drills/live`));
  assert.match(r.stdout, new RegExp(`collect-results: drills/live: \\d+ members, \\d+ bytes \\(the guest's cap: ${LIVE_MAX_MEMBERS} members, ${LIVE_MAX_BYTES} bytes\\)`));
  assert.ok(fs.existsSync(path.join(d, "m", "runs", "drills", "live", `${RUN}.${LR}`, "chapters.json")));
  const moved = cli(["--live-dir", path.join(d, "elsewhere")]);
  assert.equal(moved.status, 0, moved.stderr);
  assert.ok(fs.existsSync(path.join(d, "elsewhere", `${RUN}.${LR}`, "meta.json")));
});

test("drills/live: an error run (a refused archive) copies no live record", () => {
  const r = runDrills(archive([...goodParts(), member("drills/live/x/meta.json", "", { type: "2", linkname: "/etc/passwd" })]));
  assert.equal(r.result, "error");
  assert.equal(r.live, undefined);
});

test("drills/live: the dashboard's watch store and drill matrix read what the collector wrote", { skip: !haveDashboard && "no developer view here, or dashboard/node_modules not installed" }, () => {
  const r = runDrills(drillsArchive(SAMPLE_LIVE));
  const liveDir = path.join(path.dirname(r.replayDir), "live");
  const d = tmp();
  const file = path.join(d, "check.mts");
  fs.writeFileSync(file, `import { listWatchRuns, readRun } from ${JSON.stringify(path.join(DEV, "src/drill-run-store.ts"))};
import { liveObservations } from ${JSON.stringify(path.join(DEV, "src/drill-matrix.ts"))};
import { CiLiveEventSource } from ${JSON.stringify(path.join(DEV, "src/event-source/ci-live-source.ts"))};
const runs = listWatchRuns(${JSON.stringify(liveDir)});
const detail = readRun(${JSON.stringify(liveDir)}, runs[0]!.runId)!;
const o = liveObservations([detail]);
const ci = new CiLiveEventSource(${JSON.stringify(liveDir)});
const sessions = (await ci.listSessions()).map((x) => [x.id, x.batchId, x.eventCount]);
const evs = (await ci.readEvents(o.obs[0]!.sessionId!)).map((e) => [e.kind, e.sessionId, e.batchId, e.input?.original]);
console.log(JSON.stringify({ ids: runs.map((x) => x.runId), status: runs[0]!.status, recorded: runs[0]!.recorded, files: detail.files, obs: o.obs.map((x) => [x.mode, x.drill, x.agent, x.model, x.runId, x.verdict, x.sessionId]), rejected: o.rejected, sessions, evs }));\n`);
  const v = spawnSync(TSX, [file], { encoding: "utf8", cwd: path.join(REPO, "dashboard") });
  assert.equal(v.status, 0, v.stderr);
  const out = JSON.parse(v.stdout.trim().split("\n").pop());
  const name = `${RUN}.${LR}`;
  assert.deepEqual(out.ids, [name]);
  assert.equal(out.status, "done");
  assert.equal(out.recorded, true, "the cast meta names is there");
  assert.ok(!out.files.includes(LIVE_MARKER), "the marker is not a file the route serves");
  assert.deepEqual(out.obs, [["live", "util-shell-echo", "claude", "claude-haiku-4-5", name, "PASS", `${name}-util-shell-echo`]]);
  assert.equal(out.rejected, 0);
  // the event lanes: the matrix cell's session opens with the carried log, host ids stamped
  assert.ok(!out.files.some((f) => f.startsWith("events-")), "an event log is not a file the route serves");
  assert.deepEqual(out.sessions, [[`${name}-util-shell-echo`, name, 1]]);
  assert.deepEqual(out.evs, [["tllm_call", `${name}-util-shell-echo`, name, "synthetic-canary-value"]]);
});
