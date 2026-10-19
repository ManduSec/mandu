#!/usr/bin/env node
// replay-retention.mjs — the retention policy of the host's replay-drill store
// (`${MANDU_HOME:-~/.mandu}/runs/drills/replay`, the path table's
// `replay-drill-runs` row; continuous-integration.md §6 "Retention of the replay
// store"). Mandu-new (no reference origin).
//
// The CI collector (collect-results.mjs collectReplay) applies it after every
// run it copies in; a developer applies it by hand:
//
//   node scripts/ci/replay-retention.mjs [--dir DIR] [--keep N]
//        [--grace-minutes M] [--dry-run] [--json]
//
// The rule. A store entry is a REPLAY RUN only when it is a real directory
// (lstat: never a symlink) whose name is a run id (RUN_ID_RE, no `..`) and
// whose run.json is a regular file (opened O_NOFOLLOW) of at most 64 KiB
// holding a `mandu-replay-run` object of schema 1, its `runId` the
// directory's name and its `startedAt` a time. Anything else is IGNORED:
// never deleted, only reported. The runs are ordered as the dashboard orders
// them (replay-run-store.ts scanRunMetas: `startedAt` newest first, then the
// run id, descending), and a run is KEPT when it is
//   - one of the newest `keep` (default 300, MANDU_REPLAY_KEEP_RUNS or --keep;
//     about 15.5 MiB a run, so ~4.5 GiB at 300). This is DISK retention, and
//     it is at least every dashboard LISTING WINDOW (replay-run-store.ts
//     REPLAY_LIST_LIMIT: the replay page lists the newest 300, so every kept
//     run is browsable; REPLAY_SESSIONS_RUN_LIMIT and drill-matrix.ts
//     REPLAY_RUN_LIMIT: the recorded sessions and the drill matrix read the
//     newest 50), so a prune never removes a run a view shows,
//   - pinned: it holds an entry named `.keep` (the host's operator touches
//     it; the collector copies only record files, so a CI run cannot pin
//     itself),
//   - or recent: its directory, run.json, sessions/, casts/ or panes/ changed
//     within the grace (default 60 minutes, --grace-minutes): a writer may
//     still be filling it.
// Every other run is deleted: renamed to a hidden `.prune-<run>-<hex>` in the
// same directory (one rename, so a reader sees the run whole or not at all:
// the dashboard skips dot names), then removed. A hidden `.prune-*` or
// `.tmp-*` directory (an interrupted prune, a crashed collector's staging
// directory) older than the grace is removed too. Nothing is followed:
// fs.rmSync removes a symlink inside a run, never its target.
//
// Exported for the collector and the tests: RUN_ID_RE, DEFAULT_KEEP_RUNS,
// KEEP_RUNS_ENV, DEFAULT_GRACE_MS, PIN_FILE, keepRunsFromEnv, compareRuns,
// readRunMeta, scanReplayStore, selectReplayPrune, pruneReplayStore,
// formatBytes, formatReport.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { resolvePath } from "../paths/mandu-paths.mjs";

/** A run id as the collector and the replay runner make them (no leading dot). */
export const RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/;
/** Disk retention: the runs a prune keeps by default (≥ every dashboard
 *  listing window; scripts/test/replay-retention.test.mjs pins the relation). */
export const DEFAULT_KEEP_RUNS = 300;
export const KEEP_RUNS_ENV = "MANDU_REPLAY_KEEP_RUNS";
export const DEFAULT_GRACE_MS = 60 * 60 * 1000;
/** A run holding an entry of this name is never pruned. */
export const PIN_FILE = ".keep";
const TRASH_PREFIX = ".prune-";
/** Hidden staging names this store may hold: an interrupted prune's trash,
 *  the collector's replaceDir staging (`.tmp-<run>-XXXXXX`, `….old`). */
const STALE_RE = /^\.(?:prune|tmp)-/;
const RUN_META_MAX_BYTES = 64 * 1024;
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
/** The subdirectories a writer adds to (their mtimes say it is still writing). */
const WRITE_DIRS = ["sessions", "casts", "panes"];

const isRunId = (s) => typeof s === "string" && RUN_ID_RE.test(s) && !s.includes("..");

/** `keep` from the environment: a whole number ≥ 1, else the default.
 *  Returns { keep, error } (error set when the variable was malformed). */
export function keepRunsFromEnv(env = process.env) {
  const v = (env[KEEP_RUNS_ENV] ?? "").trim();
  if (v === "") return { keep: DEFAULT_KEEP_RUNS, error: null };
  if (!/^\d{1,6}$/.test(v) || Number(v) < 1) return { keep: DEFAULT_KEEP_RUNS, error: `${KEEP_RUNS_ENV}=${v}: not a whole number ≥ 1 (kept the default ${DEFAULT_KEEP_RUNS})` };
  return { keep: Number(v), error: null };
}

/** The dashboard's order: startedAt newest first, then the run id descending. */
export function compareRuns(a, b) {
  return b.startedMs - a.startedMs || (a.runId < b.runId ? 1 : a.runId > b.runId ? -1 : 0);
}

/** Read `<runDir>/run.json` without following anything. Returns
 *  { ok: true, runId, startedAt, startedMs } or { ok: false, reason }. */
export function readRunMeta(runDir, name) {
  let fd;
  try {
    fd = fs.openSync(path.join(runDir, "run.json"), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  } catch (e) {
    return { ok: false, reason: e.code === "ENOENT" ? "no run.json" : e.code === "ELOOP" ? "run.json is a symlink" : `run.json: ${e.code || e.message}` };
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) return { ok: false, reason: "run.json is not a regular file" };
    if (st.size > RUN_META_MAX_BYTES) return { ok: false, reason: `run.json is over ${RUN_META_MAX_BYTES} bytes` };
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < buf.length) {
      const n = fs.readSync(fd, buf, off, buf.length - off, off);
      if (n === 0) break;
      off += n;
    }
    let m;
    try { m = JSON.parse(buf.subarray(0, off).toString("utf8")); } catch { return { ok: false, reason: "run.json is not JSON" }; }
    if (!m || typeof m !== "object" || Array.isArray(m)) return { ok: false, reason: "run.json is not an object" };
    if (m.kind !== "mandu-replay-run" || m.schema !== 1) return { ok: false, reason: "run.json is not a mandu-replay-run of schema 1" };
    if (m.runId !== name) return { ok: false, reason: "run.json's runId is not its directory's name" };
    const startedMs = typeof m.startedAt === "string" && TIME_RE.test(m.startedAt) ? Date.parse(m.startedAt) : NaN;
    if (!Number.isFinite(startedMs)) return { ok: false, reason: "run.json's startedAt is not a time" };
    return { ok: true, runId: name, startedAt: m.startedAt, startedMs };
  } finally {
    fs.closeSync(fd);
  }
}

function lstatOrNull(p) {
  try { return fs.lstatSync(p); } catch { return null; }
}

/** Bytes on disk under `p` (st.blocks; the apparent size where blocks are
 *  unknown), walking with lstat: a symlink counts as itself. A path that
 *  vanishes while walked counts as 0. */
export function diskBytes(p) {
  const st = lstatOrNull(p);
  if (!st) return 0;
  let n = typeof st.blocks === "number" ? st.blocks * 512 : st.size;
  if (st.isDirectory()) {
    let names = [];
    try { names = fs.readdirSync(p); } catch { /* vanished */ }
    for (const c of names) n += diskBytes(path.join(p, c));
  }
  return n;
}

/**
 * scanReplayStore(root, {now}) → { root, exists, runs, stale, ignored }.
 * runs: [{ name, path, runId, startedAt, startedMs, latestMtimeMs, pinned }];
 * stale: hidden staging directories [{ name, path, mtimeMs }];
 * ignored: [{ name, reason }]. Throws when `root` is a symlink or not a directory.
 */
export function scanReplayStore(root) {
  const out = { root, exists: false, runs: [], stale: [], ignored: [] };
  const rst = lstatOrNull(root);
  if (!rst) return out;
  if (rst.isSymbolicLink()) throw new Error(`${root}: the store is a symlink; refusing to prune through it`);
  if (!rst.isDirectory()) throw new Error(`${root}: not a directory`);
  out.exists = true;
  for (const name of fs.readdirSync(root).sort()) {
    const p = path.join(root, name);
    const st = lstatOrNull(p);
    if (!st) continue; // vanished between readdir and lstat
    if (name.startsWith(".")) {
      if (STALE_RE.test(name) && st.isDirectory() && !st.isSymbolicLink()) out.stale.push({ name, path: p, mtimeMs: st.mtimeMs });
      else out.ignored.push({ name, reason: "a hidden entry" });
      continue;
    }
    if (st.isSymbolicLink()) { out.ignored.push({ name, reason: "a symlink" }); continue; }
    if (!st.isDirectory()) { out.ignored.push({ name, reason: "not a directory" }); continue; }
    if (!isRunId(name)) { out.ignored.push({ name, reason: "not a run id" }); continue; }
    const meta = readRunMeta(p, name);
    if (!meta.ok) { out.ignored.push({ name, reason: meta.reason }); continue; }
    let latest = st.mtimeMs;
    for (const sub of ["run.json", ...WRITE_DIRS]) {
      const s = lstatOrNull(path.join(p, sub));
      if (s && s.mtimeMs > latest) latest = s.mtimeMs;
    }
    out.runs.push({ name, path: p, runId: meta.runId, startedAt: meta.startedAt, startedMs: meta.startedMs, latestMtimeMs: latest, pinned: lstatOrNull(path.join(p, PIN_FILE)) !== null });
  }
  return out;
}

/**
 * selectReplayPrune(runs, {keep, now, graceMs}) → { kept, doomed }, both in
 * the dashboard's order; each kept run carries `reason`: "newest", "pinned"
 * or "recent" (the first that applies). Pure.
 */
export function selectReplayPrune(runs, { keep = DEFAULT_KEEP_RUNS, now = Date.now(), graceMs = DEFAULT_GRACE_MS } = {}) {
  if (!Number.isInteger(keep) || keep < 1) throw new Error(`keep must be a whole number ≥ 1, not ${keep}`);
  const sorted = [...runs].sort(compareRuns);
  const kept = [], doomed = [];
  sorted.forEach((r, i) => {
    const reason = i < keep ? "newest" : r.pinned ? "pinned" : now - r.latestMtimeMs < graceMs ? "recent" : null;
    if (reason) kept.push({ ...r, reason });
    else doomed.push(r);
  });
  return { kept, doomed };
}

/** Remove one directory of `root` named `name`: re-checked (a real directory,
 *  directly under root), renamed to a hidden trash name, then removed.
 *  Returns false when it was already gone. */
function removeEntry(root, name, { hidden = false } = {}) {
  if (name.includes("/") || name === "." || name === ".." || name.includes("\0")) throw new Error(`${name}: not an entry name`);
  const p = path.join(root, name);
  if (path.dirname(p) !== root) throw new Error(`${name}: escapes the store`);
  const st = lstatOrNull(p);
  if (!st) return false;
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error(`${name}: no longer a real directory; left alone`);
  let target = p;
  if (!hidden) {
    target = path.join(root, `${TRASH_PREFIX}${name}-${crypto.randomBytes(4).toString("hex")}`);
    try { fs.renameSync(p, target); } catch (e) { if (e.code === "ENOENT") return false; throw e; }
  }
  fs.rmSync(target, { recursive: true, force: true });
  return true;
}

/**
 * pruneReplayStore(root, {keep, graceMs, now, dryRun}) → { root, exists,
 * keep, graceMs, dryRun, kept, deleted, stale, ignored, errors, bytesFreed }.
 * deleted and stale entries carry `bytes`; a dry run deletes nothing and
 * reports what a real run would.
 */
export function pruneReplayStore(root, { keep = DEFAULT_KEEP_RUNS, graceMs = DEFAULT_GRACE_MS, now = Date.now(), dryRun = false } = {}) {
  const scan = scanReplayStore(root);
  const { kept, doomed } = selectReplayPrune(scan.runs, { keep, now, graceMs });
  const report = { root, exists: scan.exists, keep, graceMs, dryRun, kept, deleted: [], stale: [], ignored: scan.ignored, errors: [], bytesFreed: 0 };
  for (const r of doomed) {
    const bytes = diskBytes(r.path);
    if (!dryRun) {
      try { if (!removeEntry(root, r.name)) continue; }
      catch (e) { report.errors.push(`${r.name}: ${e.message}`); continue; }
    }
    report.deleted.push({ name: r.name, startedAt: r.startedAt, bytes });
    report.bytesFreed += bytes;
  }
  for (const s of scan.stale) {
    if (now - s.mtimeMs < graceMs) continue;
    const bytes = diskBytes(s.path);
    if (!dryRun) {
      try { if (!removeEntry(root, s.name, { hidden: true })) continue; }
      catch (e) { report.errors.push(`${s.name}: ${e.message}`); continue; }
    }
    report.stale.push({ name: s.name, bytes });
    report.bytesFreed += bytes;
  }
  return report;
}

export function formatBytes(n) {
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(2)} GiB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MiB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${n} B`;
}

/** The report as lines (the CLI's output). */
export function formatReport(r, { verbose = true } = {}) {
  const tag = r.dryRun ? " (dry run: nothing deleted)" : "";
  if (!r.exists) return [`replay-retention: ${r.root}: no store; nothing to do`];
  const by = (why) => r.kept.filter((k) => k.reason === why).length;
  const lines = [
    `replay-retention: ${r.root}: ${r.kept.length + r.deleted.length} runs; keeping ${r.kept.length} ` +
      `(newest ${by("newest")}, pinned ${by("pinned")}, recent ${by("recent")}); ` +
      `${r.dryRun ? "would delete" : "deleted"} ${r.deleted.length} runs and ${r.stale.length} stale staging directories, ` +
      `${formatBytes(r.bytesFreed)}${tag}`,
  ];
  if (verbose) {
    for (const d of r.deleted) lines.push(`  ${r.dryRun ? "would delete" : "deleted"}  ${d.name}  ${d.startedAt}  ${formatBytes(d.bytes)}`);
    for (const s of r.stale) lines.push(`  ${r.dryRun ? "would delete" : "deleted"}  ${s.name}  (stale staging)  ${formatBytes(s.bytes)}`);
    for (const k of r.kept.filter((x) => x.reason !== "newest")) lines.push(`  kept  ${k.name}  (${k.reason})`);
    for (const i of r.ignored) lines.push(`  ignored  ${i.name.replace(/[^\x20-\x7e]/g, "?").slice(0, 120)}  (${i.reason})`);
  }
  for (const e of r.errors) lines.push(`  ERROR  ${e}`);
  return lines;
}

// ── CLI ────────────────────────────────────────────────────────────────────

const USAGE = "usage: replay-retention.mjs [--dir DIR] [--keep N] [--grace-minutes M] [--dry-run] [--json]";

function parseArgs(argv, env) {
  const fromEnv = keepRunsFromEnv(env);
  if (fromEnv.error) throw new Error(fromEnv.error.replace(/ \(kept the default \d+\)$/, ""));
  const o = { dir: null, keep: fromEnv.keep, graceMs: DEFAULT_GRACE_MS, dryRun: false, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--dir") o.dir = val();
    else if (a === "--keep") { const v = val(); if (!/^\d{1,6}$/.test(v) || Number(v) < 1) throw new Error(`--keep ${v}: not a whole number ≥ 1`); o.keep = Number(v); }
    else if (a === "--grace-minutes") { const v = val(); if (!/^\d{1,7}$/.test(v)) throw new Error(`--grace-minutes ${v}: not a whole number`); o.graceMs = Number(v) * 60_000; }
    else if (a === "--dry-run") o.dryRun = true;
    else if (a === "--json") o.json = true;
    else if (a === "-h" || a === "--help") { o.help = true; }
    else throw new Error(`unknown option: ${a}`);
  }
  return o;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let o;
  try { o = parseArgs(process.argv.slice(2), process.env); }
  catch (e) { console.error(`replay-retention: ${e.message}\n${USAGE}`); process.exit(2); }
  if (o.help) { console.log(USAGE); process.exit(0); }
  const root = path.resolve(o.dir ?? resolvePath("replay-drill-runs", process.env, process.env.HOME || os.homedir()));
  try {
    const r = pruneReplayStore(root, { keep: o.keep, graceMs: o.graceMs, dryRun: o.dryRun });
    if (o.json) console.log(JSON.stringify({ ...r, kept: r.kept.map(({ name, startedAt, reason }) => ({ name, startedAt, reason })) }, null, 2));
    else for (const l of formatReport(r)) console.log(l);
    process.exit(r.errors.length ? 1 : 0);
  } catch (e) {
    console.error(`replay-retention: ${e.message}`);
    process.exit(1);
  }
}
