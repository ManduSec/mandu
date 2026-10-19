// replay-retention.test.mjs — the replay store's retention policy
// (scripts/ci/replay-retention.mjs; continuous-integration.md §6 "Retention of the
// replay store"): the pure selection (newest N in the dashboard's order, ties,
// pins, the grace), the scan's refusals (malformed and hostile entries are
// ignored, never deleted; nothing is followed), the prune itself over a temp
// store (dry run lists, real run deletes exactly that, stale staging goes),
// and the CLI. The dashboard side (a pruned run vanishes from a live
// server's listings) is dashboard/test/component/replay-retention.test.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { tmpDir } from "./lib/tmp-dir.mjs";
import { devView } from "../dev-view.mjs";

import {
  DEFAULT_GRACE_MS, DEFAULT_KEEP_RUNS, KEEP_RUNS_ENV, PIN_FILE, compareRuns, diskBytes, formatReport, keepRunsFromEnv,
  pruneReplayStore, readRunMeta, scanReplayStore, selectReplayPrune,
} from "../ci/replay-retention.mjs";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const CLI = path.join(REPO, "scripts/ci/replay-retention.mjs");
const OLD = new Date(Date.UTC(2020, 0, 1));
const NOW = Date.UTC(2026, 9, 2, 12);

function tmp() {
  return fs.realpathSync(tmpDir("replay-retention-"));
}
const meta = (runId, startedAt, over = {}) => ({ schema: 1, kind: "mandu-replay-run", runId, commit: "deadbeef", source: "ci", startedAt, engine: 3, ...over });

/** A run dir as the collector writes it, its mtimes aged unless `fresh`. */
function putRun(root, name, startedAt, { fresh = false, metaOver = {}, rawMeta } = {}) {
  const d = path.join(root, name);
  fs.mkdirSync(path.join(d, "sessions"), { recursive: true });
  fs.mkdirSync(path.join(d, "casts"), { recursive: true });
  fs.writeFileSync(path.join(d, "run.json"), rawMeta ?? JSON.stringify(meta(name, startedAt, metaOver)));
  fs.writeFileSync(path.join(d, "sessions", "k-claude-80x24.json"), "{}");
  fs.writeFileSync(path.join(d, "events-k-claude-80x24.ndjson"), "x".repeat(10_000));
  fs.writeFileSync(path.join(d, "casts", "k-claude-80x24.mandu.cast"), "{\"version\":2}\n");
  if (!fresh) age(d);
  return d;
}
function age(p) {
  const st = fs.lstatSync(p);
  if (st.isDirectory()) for (const c of fs.readdirSync(p)) age(path.join(p, c));
  if (!st.isSymbolicLink()) fs.utimesSync(p, OLD, OLD);
}
const run = (name, startedAt, o = {}) => ({ name, path: `/s/${name}`, runId: name, startedAt, startedMs: Date.parse(startedAt), latestMtimeMs: OLD.getTime(), pinned: false, ...o });

// ── the pure selection ─────────────────────────────────────────────────────

test("selectReplayPrune keeps the newest N by startedAt (the dashboard's order) and dooms the rest, oldest last", () => {
  const runs = [run("r-1", "2026-10-01T01:00:00Z"), run("r-3", "2026-10-01T03:00:00Z"), run("r-2", "2026-10-01T02:00:00Z"), run("r-4", "2026-10-01T04:00:00Z")];
  const s = selectReplayPrune(runs, { keep: 2, now: NOW });
  assert.deepEqual(s.kept.map((r) => [r.name, r.reason]), [["r-4", "newest"], ["r-3", "newest"]]);
  assert.deepEqual(s.doomed.map((r) => r.name), ["r-2", "r-1"]);
  const all = selectReplayPrune(runs, { keep: 10, now: NOW });
  assert.equal(all.doomed.length, 0, "fewer runs than N: nothing goes");
});

test("selectReplayPrune breaks a startedAt tie by run id, descending, as replay-run-store.ts scanRunMetas does", () => {
  const t = "2026-10-01T01:00:00Z";
  const runs = [run("gl-10-1", t), run("gl-10-3", t), run("gl-10-2", t)];
  assert.deepEqual([...runs].sort(compareRuns).map((r) => r.name), ["gl-10-3", "gl-10-2", "gl-10-1"]);
  const s = selectReplayPrune(runs, { keep: 1, now: NOW });
  assert.deepEqual(s.kept.map((r) => r.name), ["gl-10-3"]);
  assert.deepEqual(s.doomed.map((r) => r.name), ["gl-10-2", "gl-10-1"]);
  // the same input in any order selects the same
  assert.deepEqual(selectReplayPrune([...runs].reverse(), { keep: 1, now: NOW }).doomed.map((r) => r.name), ["gl-10-2", "gl-10-1"]);
  // a startedAt in another zone compares by the instant, not the text
  const z = [run("a", "2026-10-01T10:00:00+09:00"), run("b", "2026-10-01T02:00:00Z")];
  assert.deepEqual(selectReplayPrune(z, { keep: 1, now: NOW }).kept.map((r) => r.name), ["b"]);
});

test("selectReplayPrune keeps a pinned run and a run written within the grace beyond N", () => {
  const runs = [
    run("new", "2026-10-01T05:00:00Z"),
    run("pinned", "2026-01-01T00:00:00Z", { pinned: true }),
    run("writing", "2026-01-01T00:00:01Z", { latestMtimeMs: NOW - 5 * 60_000 }),
    run("future-mtime", "2026-01-01T00:00:02Z", { latestMtimeMs: NOW + 60_000 }),
    run("aged", "2026-01-01T00:00:03Z", { latestMtimeMs: NOW - DEFAULT_GRACE_MS - 1 }),
  ];
  const s = selectReplayPrune(runs, { keep: 1, now: NOW });
  assert.deepEqual(s.kept.map((r) => [r.name, r.reason]), [["new", "newest"], ["future-mtime", "recent"], ["writing", "recent"], ["pinned", "pinned"]]);
  assert.deepEqual(s.doomed.map((r) => r.name), ["aged"]);
  assert.deepEqual(selectReplayPrune(runs, { keep: 1, now: NOW, graceMs: 0 }).doomed.map((r) => r.name), ["aged", "writing"], "grace 0: only a future mtime still reads as recent");
});

test("selectReplayPrune refuses a keep that is not a whole number ≥ 1 (a typo never empties the store)", () => {
  for (const keep of [0, -1, 1.5, NaN, "3"]) assert.throws(() => selectReplayPrune([], { keep }), /keep must be a whole number/);
});

test("keepRunsFromEnv: MANDU_REPLAY_KEEP_RUNS, a whole number ≥ 1, else the default with an error", () => {
  assert.equal(DEFAULT_KEEP_RUNS, 300, "the store keeps 300 runs (~4.5 GiB at ~15.5 MiB a run)");
  assert.deepEqual(keepRunsFromEnv({}), { keep: 300, error: null });
  assert.deepEqual(keepRunsFromEnv({ [KEEP_RUNS_ENV]: " 120 " }), { keep: 120, error: null });
  for (const v of ["0", "-3", "1e3", "ten", "1.5"]) {
    const r = keepRunsFromEnv({ [KEEP_RUNS_ENV]: v });
    assert.equal(r.keep, DEFAULT_KEEP_RUNS);
    assert.match(r.error, /not a whole number/);
  }
});

test("disk retention is at least every dashboard listing window (a prune never removes a run a view shows)", { skip: devView() === null && "no developer view in this checkout" }, () => {
  // the windows, by reader (dashboard.md §4.28/§4.30): the replay page lists
  // REPLAY_LIST_LIMIT runs, the recorded sessions read REPLAY_SESSIONS_RUN_LIMIT,
  // the drill matrix REPLAY_RUN_LIMIT
  const windows = [
    ["src/replay-run-store.ts", "REPLAY_LIST_LIMIT"],
    ["src/replay-run-store.ts", "REPLAY_SESSIONS_RUN_LIMIT"],
    ["src/drill-matrix.ts", "REPLAY_RUN_LIMIT"],
  ].map(([file, name]) => {
    const m = new RegExp(`export const ${name} = (\\d+);`).exec(fs.readFileSync(path.join(devView(), file), "utf8"));
    assert.ok(m, `${file} declares ${name}`);
    return [name, Number(m[1])];
  });
  for (const [name, n] of windows) assert.ok(DEFAULT_KEEP_RUNS >= n, `DEFAULT_KEEP_RUNS ${DEFAULT_KEEP_RUNS} < ${name} ${n}`);
  // the replay page browses every kept run
  assert.equal(Object.fromEntries(windows).REPLAY_LIST_LIMIT, DEFAULT_KEEP_RUNS);
});

// ── the scan: what counts as a replay run ──────────────────────────────────

test("scanReplayStore ignores every entry that is not verifiably a replay run, and follows no symlink", () => {
  const root = tmp();
  const outside = tmp();
  putRun(outside, "victim", "2020-01-01T00:00:00Z");
  putRun(root, "good-1", "2026-10-01T00:00:00Z");
  putRun(root, "no-meta", "x"); fs.rmSync(path.join(root, "no-meta", "run.json"));
  putRun(root, "not-json", "x", { rawMeta: "{" });
  putRun(root, "wrong-kind", "2026-10-01T00:00:00Z", { metaOver: { kind: "mandu-ci-run" } });
  putRun(root, "wrong-schema", "2026-10-01T00:00:00Z", { metaOver: { schema: 2 } });
  putRun(root, "poser", "2026-10-01T00:00:00Z", { metaOver: { runId: "good-1" } });
  putRun(root, "bad-time", "yesterday");
  putRun(root, "huge", "2026-10-01T00:00:00Z", { rawMeta: JSON.stringify({ ...meta("huge", "2026-10-01T00:00:00Z"), pad: "x".repeat(70_000) }) });
  putRun(root, "array", "x", { rawMeta: "[]" });
  fs.mkdirSync(path.join(root, "meta-dir", "run.json"), { recursive: true });
  fs.mkdirSync(path.join(root, "meta-link"));
  fs.symlinkSync(path.join(outside, "victim", "run.json"), path.join(root, "meta-link", "run.json"));
  fs.symlinkSync(path.join(outside, "victim"), path.join(root, "linked-run"));
  fs.writeFileSync(path.join(root, "a-file"), "x");
  fs.mkdirSync(path.join(root, "bad name!"));
  fs.mkdirSync(path.join(root, ".hidden"));
  fs.mkdirSync(path.join(root, "-dash"));

  const s = scanReplayStore(root);
  assert.equal(s.exists, true);
  assert.deepEqual(s.runs.map((r) => r.name), ["good-1"]);
  const why = Object.fromEntries(s.ignored.map((i) => [i.name, i.reason]));
  assert.deepEqual(Object.keys(why).sort(), [".hidden", "-dash", "a-file", "array", "bad name!", "bad-time", "huge", "linked-run", "meta-dir", "meta-link", "no-meta", "not-json", "poser", "wrong-kind", "wrong-schema"].sort());
  assert.equal(why["linked-run"], "a symlink");
  assert.equal(why["meta-link"], "run.json is a symlink");
  assert.equal(why["meta-dir"], "run.json is not a regular file");
  assert.match(why.huge, /over 65536 bytes/);
  assert.match(why.poser, /runId is not its directory's name/);
  assert.equal(why["-dash"], "not a run id");

  // a prune with keep 1 and no grace deletes nothing of all that, nor the target of a link
  const r = pruneReplayStore(root, { keep: 1, graceMs: 0, now: NOW });
  assert.deepEqual(r.deleted, []);
  assert.equal(fs.readdirSync(root).length, 16);
  assert.ok(fs.existsSync(path.join(outside, "victim", "run.json")));
});

test("readRunMeta reads a FIFO without hanging and refuses it", () => {
  const root = tmp();
  fs.mkdirSync(path.join(root, "fifo"));
  const mk = spawnSync("mkfifo", [path.join(root, "fifo", "run.json")]);
  if (mk.status !== 0) return; // no mkfifo: nothing to prove
  assert.deepEqual(readRunMeta(path.join(root, "fifo"), "fifo"), { ok: false, reason: "run.json is not a regular file" });
});

test("scanReplayStore: a missing store is nothing to do; a store that is a symlink or a file is refused", () => {
  const d = tmp();
  assert.deepEqual(scanReplayStore(path.join(d, "none")), { root: path.join(d, "none"), exists: false, runs: [], stale: [], ignored: [] });
  assert.deepEqual(pruneReplayStore(path.join(d, "none")).deleted, []);
  fs.mkdirSync(path.join(d, "real"));
  fs.symlinkSync(path.join(d, "real"), path.join(d, "link"));
  assert.throws(() => scanReplayStore(path.join(d, "link")), /is a symlink; refusing/);
  fs.writeFileSync(path.join(d, "file"), "x");
  assert.throws(() => scanReplayStore(path.join(d, "file")), /not a directory/);
});

test("scanReplayStore: a pin is any entry named .keep; the latest write is the newest of the run dir, run.json, sessions/, casts/, panes/", () => {
  const root = tmp();
  putRun(root, "pinned", "2020-01-01T00:00:00Z");
  fs.writeFileSync(path.join(root, "pinned", PIN_FILE), "");
  // The pin touched the run directory's mtime: age it again, or its latest
  // write is the wall clock, which passed NOW at 2026-10-02 12:00 UTC.
  age(path.join(root, "pinned"));
  putRun(root, "plain", "2020-01-01T00:00:00Z");
  const fresh = new Date(NOW);
  fs.utimesSync(path.join(root, "plain", "sessions"), fresh, fresh);
  const s = Object.fromEntries(scanReplayStore(root).runs.map((r) => [r.name, r]));
  assert.equal(s.pinned.pinned, true);
  assert.equal(s.plain.pinned, false);
  assert.equal(s.plain.latestMtimeMs, NOW);
  assert.equal(s.pinned.latestMtimeMs < NOW, true);
});

// ── the prune ──────────────────────────────────────────────────────────────

test("pruneReplayStore: a dry run lists exactly what a real run then deletes, with sizes, and deletes nothing", () => {
  const root = tmp();
  for (let i = 0; i < 6; i++) putRun(root, `gl-${100 + i}-1`, `2026-10-01T0${i}:00:00Z`);
  const outside = tmp();
  fs.writeFileSync(path.join(outside, "keep-me"), "precious");
  fs.symlinkSync(outside, path.join(root, "gl-100-1", "link-out"));
  fs.symlinkSync(path.join(outside, "keep-me"), path.join(root, "gl-100-1", "file-link"));
  // The links touched the run dir's mtime (the wall clock): aged again, or
  // from an hour before NOW on the run counts as recent and is kept.
  fs.utimesSync(path.join(root, "gl-100-1"), OLD, OLD);
  const before = fs.readdirSync(root).sort();

  const dry = pruneReplayStore(root, { keep: 4, now: NOW, dryRun: true });
  assert.deepEqual(fs.readdirSync(root).sort(), before, "a dry run deletes nothing");
  assert.deepEqual(dry.deleted.map((d) => d.name), ["gl-101-1", "gl-100-1"]);
  assert.ok(dry.deleted.every((d) => d.bytes >= 10_000), "each with its size on disk");
  assert.equal(dry.bytesFreed, dry.deleted.reduce((a, d) => a + d.bytes, 0));
  const lines = formatReport(dry);
  assert.match(lines[0], /6 runs; keeping 4 \(newest 4, pinned 0, recent 0\); would delete 2 runs .*\(dry run: nothing deleted\)/);
  assert.match(lines[1], /^ {2}would delete {2}gl-101-1 {2}2026-10-01T01:00:00Z {2}\d/);

  const real = pruneReplayStore(root, { keep: 4, now: NOW });
  assert.deepEqual(real.deleted.map((d) => d.name), dry.deleted.map((d) => d.name));
  assert.deepEqual(real.errors, []);
  assert.deepEqual(fs.readdirSync(root).sort(), ["gl-102-1", "gl-103-1", "gl-104-1", "gl-105-1"], "exactly those, and no trash left behind");
  assert.equal(fs.readFileSync(path.join(outside, "keep-me"), "utf8"), "precious", "a symlink inside a pruned run is removed, never followed");
  assert.match(formatReport(real)[0], /deleted 2 runs/);
  // idempotent
  assert.deepEqual(pruneReplayStore(root, { keep: 4, now: NOW }).deleted, []);
});

test("pruneReplayStore removes a hidden staging directory (.prune-*, .tmp-*) older than the grace, and no other hidden entry", () => {
  const root = tmp();
  putRun(root, "gl-1-1", "2026-10-01T00:00:00Z");
  for (const n of [".prune-gl-0-1-abcd1234", ".tmp-gl-2-2-XyZ123", ".tmp-gl-2-2-XyZ123.old", ".tmp-fresh-1", ".other"]) {
    fs.mkdirSync(path.join(root, n, "sub"), { recursive: true });
    fs.writeFileSync(path.join(root, n, "sub", "f"), "x");
    if (n !== ".tmp-fresh-1") age(path.join(root, n));
  }
  const outside = tmp();
  fs.symlinkSync(outside, path.join(root, ".prune-linked"));
  const dry = pruneReplayStore(root, { keep: 5, now: Date.now(), dryRun: true });
  assert.deepEqual(dry.stale.map((s) => s.name).sort(), [".prune-gl-0-1-abcd1234", ".tmp-gl-2-2-XyZ123", ".tmp-gl-2-2-XyZ123.old"]);
  assert.equal(fs.readdirSync(root).length, 7);
  pruneReplayStore(root, { keep: 5, now: Date.now() });
  assert.deepEqual(fs.readdirSync(root).sort(), [".other", ".prune-linked", ".tmp-fresh-1", "gl-1-1"]);
  assert.ok(fs.existsSync(outside));
});

test("pruneReplayStore: a run that vanishes between the scan and the delete is skipped, not an error", () => {
  const root = tmp();
  putRun(root, "gl-1-1", "2026-10-01T00:00:00Z");
  putRun(root, "gl-2-1", "2026-10-01T01:00:00Z");
  // a concurrent prune got there first: simulate by removing it after a dry run's scan
  const dry = pruneReplayStore(root, { keep: 1, now: NOW, dryRun: true });
  assert.deepEqual(dry.deleted.map((d) => d.name), ["gl-1-1"]);
  fs.rmSync(path.join(root, "gl-1-1"), { recursive: true });
  const r = pruneReplayStore(root, { keep: 1, now: NOW });
  assert.deepEqual(r.deleted, []);
  assert.deepEqual(r.errors, []);
});

test("diskBytes counts a symlink as itself and a missing path as 0", () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, "big"), "x".repeat(200_000));
  const e = tmp();
  fs.symlinkSync(path.join(d, "big"), path.join(e, "l"));
  assert.ok(diskBytes(d) >= 200_000);
  assert.ok(diskBytes(e) < 200_000);
  assert.equal(diskBytes(path.join(d, "none")), 0);
});

// ── the CLI ────────────────────────────────────────────────────────────────

const cli = (args, env = {}) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", env: { PATH: process.env.PATH, HOME: env.HOME ?? os.tmpdir(), ...env } });

test("the CLI: --dry-run lists, a real run deletes, --json reports; the default store is the path table's replay-drill-runs", () => {
  const root = tmp();
  for (let i = 0; i < 3; i++) putRun(root, `gl-${i}-1`, `2026-10-01T0${i}:00:00Z`);
  const dry = cli(["--dir", root, "--keep", "1", "--dry-run"]);
  assert.equal(dry.status, 0, dry.stderr);
  assert.match(dry.stdout, /3 runs; keeping 1 .*would delete 2 runs/);
  assert.match(dry.stdout, /would delete {2}gl-1-1/);
  assert.match(dry.stdout, /would delete {2}gl-0-1/);
  assert.equal(fs.readdirSync(root).length, 3);

  const env = cli(["--dir", root, "--json"], { [KEEP_RUNS_ENV]: "2" });
  assert.equal(env.status, 0, env.stderr);
  const j = JSON.parse(env.stdout);
  assert.equal(j.keep, 2);
  assert.deepEqual(j.deleted.map((d) => d.name), ["gl-0-1"]);
  assert.deepEqual(j.kept.map((k) => k.name), ["gl-2-1", "gl-1-1"]);
  assert.deepEqual(fs.readdirSync(root).sort(), ["gl-1-1", "gl-2-1"]);

  const home = tmp();
  const store = path.join(home, ".mandu", "runs", "drills", "replay");
  fs.mkdirSync(store, { recursive: true });
  putRun(store, "gl-9-1", "2026-10-01T00:00:00Z");
  const def = cli(["--dry-run"], { HOME: home });
  assert.equal(def.status, 0, def.stderr);
  assert.ok(def.stdout.startsWith(`replay-retention: ${store}: 1 runs; keeping 1`), def.stdout);
  const mh = cli(["--dry-run"], { HOME: tmp(), MANDU_HOME: path.join(home, ".mandu") });
  assert.ok(mh.stdout.startsWith(`replay-retention: ${store}:`), mh.stdout);
});

test("the CLI refuses a bad --keep, a bad MANDU_REPLAY_KEEP_RUNS, an unknown option (exit 2) and a symlinked store (exit 1)", () => {
  const root = tmp();
  for (const [args, env, re] of [
    [["--keep", "0"], {}, /--keep 0: not a whole number/],
    [["--keep"], {}, /--keep needs a value/],
    [["--grace-minutes", "-1"], {}, /--grace-minutes -1/],
    [[], { [KEEP_RUNS_ENV]: "all" }, /MANDU_REPLAY_KEEP_RUNS=all: not a whole number/],
    [["--force"], {}, /unknown option: --force/],
  ]) {
    const r = cli(["--dir", root, ...args], env);
    assert.equal(r.status, 2, `${args.join(" ")}: ${r.stdout}${r.stderr}`);
    assert.match(r.stderr, re);
  }
  const link = path.join(tmp(), "link");
  fs.symlinkSync(root, link);
  const r = cli(["--dir", link]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /is a symlink; refusing/);
});
