// live-events.mjs — the guest side of a live drill session's EVENT LANES
// (docs/design/testing/continuous-integration.md §6, "The live-drill
// records"). Mandu-new (no reference origin).
//
// A `drill.*` entry of the nightly runs drill-run.ts --own-arbiter: the run's
// own arbiter (drill-arbiter.ts) writes every session's
// events to <its work dir>/events/<session>.ndjson, and its work dir is
// <run dir>/arbiter (or, when that socket path would be too long, a
// <tmp>/mdu-a-XXXXXX that meta.json's `arbiter.eventDir` names). Nothing
// else on the host has those events: the guest is discarded with them, so a
// CI live session had its recording and verdicts and no trace.
//
// pipeline.sh's collect_live first copies a run's record files to
// $OUT/drills/live/<drill run>/; this then copies, for each such run, the
// event log of each session the RUN NAMES (meta.json's `sessions`, the
// chapters' and report rows' `scopeId`) and nothing else of the arbiter's
// work dir (never its symbol DB, its log, its policy copy or another
// session's log), as <drill run>/events-<session>.ndjson:
//   - a regular file, opened without following a symlink, at most
//     --max-file-bytes (the dashboard's EVENTS_MAX_BYTES, 32 MiB);
//   - all of drills/live's logs together at most --max-bytes (an explicit
//     events budget inside drills/live's own caps): past it the LARGEST logs
//     are left behind first, so as many sessions as fit keep their lanes;
//   - written owner-only (0600), like the rest of the record (collect_live
//     makes drills/live 0700 / 0600), because an event log holds originals
//     (DualRepr.original): the drill's data is synthetic, but the record is
//     treated as ~/.mandu treats every event log.
// Every log left behind is named, with why, in the output (logs/drills.log).
// The collector (collect-results.mjs collectLive) checks every one again.
//
//   node scripts/ci/live-events.mjs --store DIR --dest DIR [--max-file-bytes N] [--max-bytes N]
//
// Exit: 0 (what was or was not copied is said on stdout), 2 on a bad call.
// Exported for scripts/test/ci-live-events.test.mjs.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** A session id the record may name: the event store's file name, and the
 *  dashboard's drill-matrix SESSION_RE (no `/`, no leading dot). */
export const SESSION_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;
/** An event log in a live run directory: `events-<session>.ndjson`. */
export const EVENTS_FILE_RE = /^events-([A-Za-z0-9][A-Za-z0-9._-]{0,199})\.ndjson$/;
/** the developer view's replay-run-store.ts EVENTS_MAX_BYTES. */
export const EVENTS_FILE_MAX_BYTES = 32 * 1024 * 1024;
/** All of drills/live's event logs together (continuous-integration.md §6). */
export const EVENTS_MAX_BYTES = 96 * 1024 * 1024;
/** The run directory names (the developer view's drill-run-store.ts RUN_ID_RE). */
const RUN_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$/;
/** The fallback work dir ownArbiterWorkDir makes: mkdtemp(<tmp>/mdu-a-). */
const TMP_WORK_RE = /^mdu-a-[A-Za-z0-9]{6}$/;
const JSON_MAX_BYTES = 16 * 1024 * 1024;

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** A real directory (lstat: never through a symlink). */
function realDir(p) {
  try { return fs.lstatSync(p).isDirectory(); } catch { return false; }
}

/** A JSON record file of the copied run, or undefined. */
function readJson(p) {
  try {
    const st = fs.lstatSync(p);
    if (!st.isFile() || st.size > JSON_MAX_BYTES) return undefined;
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch { return undefined; }
}

/** The sessions a run names, sorted: meta.json's `sessions` values and every
 *  chapter's and report row's `scopeId` that is a session id. */
export function namedSessions(meta, chapters, report) {
  const out = new Set();
  if (isObj(meta) && isObj(meta.sessions)) for (const v of Object.values(meta.sessions)) if (typeof v === "string" && SESSION_ID_RE.test(v)) out.add(v);
  for (const rows of [chapters, report]) {
    if (!Array.isArray(rows)) continue;
    for (const r of rows) if (isObj(r) && typeof r.scopeId === "string" && SESSION_ID_RE.test(r.scopeId)) out.add(r.scopeId);
  }
  return [...out].sort();
}

/** Where a run's own arbiter wrote its events, or null: `<run dir>/arbiter/events`
 *  when it is a real directory, else meta.json's `arbiter.eventDir` when it
 *  is the `events` of a mkdtemp'd `mdu-a-XXXXXX` work dir (and a real
 *  directory). Any other path is not read. */
export function ownArbiterEventDir(runDir, meta) {
  const inRun = path.join(runDir, "arbiter", "events");
  if (realDir(path.join(runDir, "arbiter")) && realDir(inRun)) return inRun;
  const named = isObj(meta) && isObj(meta.arbiter) ? meta.arbiter.eventDir : undefined;
  if (typeof named !== "string" || !path.isAbsolute(named) || path.normalize(named) !== named) return null;
  if (path.basename(named) !== "events" || !TMP_WORK_RE.test(path.basename(path.dirname(named)))) return null;
  return realDir(path.dirname(named)) && realDir(named) ? named : null;
}

/** Read one regular file without following a final symlink; null when it is
 *  not one or is over `cap` (checked on the open descriptor). */
function readRegularNoFollow(p, cap) {
  let fd;
  try { fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); } catch { return null; }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > cap) return null;
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < st.size) {
      const n = fs.readSync(fd, buf, off, st.size - off, off);
      if (n === 0) break;
      off += n;
    }
    return buf.subarray(0, off);
  } finally { fs.closeSync(fd); }
}

/**
 * copyLiveEvents({store, dest, maxFileBytes, maxBytes}) → { copied, notes }.
 * For each run directory under `dest` (what collect_live copied) whose
 * source `store/<run>` names an own arbiter's event dir, the event log of
 * every session the run names, as dest/<run>/events-<session>.ndjson (0600).
 * `copied` lists {run, session, bytes}; `notes` says what was left behind.
 */
export function copyLiveEvents({ store, dest, maxFileBytes = EVENTS_FILE_MAX_BYTES, maxBytes = EVENTS_MAX_BYTES }) {
  const notes = [];
  const candidates = [];
  let runs = [];
  try { runs = fs.readdirSync(dest).sort(); } catch { return { copied: [], notes }; }
  for (const run of runs) {
    const out = path.join(dest, run);
    if (!RUN_RE.test(run) || !realDir(out)) continue;
    const src = path.join(store, run);
    if (!realDir(src)) continue;
    const meta = readJson(path.join(out, "meta.json"));
    const sessions = namedSessions(meta, readJson(path.join(out, "chapters.json")), readJson(path.join(out, "report.json")));
    if (!sessions.length) continue;
    const dir = ownArbiterEventDir(src, meta);
    if (!dir) { notes.push(`live: ${run}: no event logs (no own arbiter's event dir: the run did not start one, or names one this does not read)`); continue; }
    for (const session of sessions) {
      const f = path.join(dir, `${session}.ndjson`);
      let st;
      try { st = fs.lstatSync(f); } catch { notes.push(`live: ${run}: no event log for ${session}`); continue; }
      if (!st.isFile()) { notes.push(`live: ${run}: the event log of ${session} left behind (not a regular file)`); continue; }
      if (st.size > maxFileBytes) { notes.push(`live: ${run}: the event log of ${session} left behind (over ${maxFileBytes} bytes)`); continue; }
      candidates.push({ run, session, from: f, size: st.size });
    }
  }
  // The events budget: the largest go first, so the most sessions keep lanes.
  let total = candidates.reduce((a, c) => a + c.size, 0);
  const keep = new Set(candidates);
  for (const c of [...candidates].sort((a, b) => b.size - a.size || (a.session < b.session ? -1 : 1))) {
    if (total <= maxBytes) break;
    keep.delete(c);
    total -= c.size;
    notes.push(`live: ${c.run}: the event log of ${c.session} left behind (over the events cap: ${c.size} bytes; cap ${maxBytes} bytes for all of drills/live's logs)`);
  }
  const copied = [];
  for (const c of candidates) {
    if (!keep.has(c)) continue;
    const buf = readRegularNoFollow(c.from, maxFileBytes);
    if (!buf) { notes.push(`live: ${c.run}: the event log of ${c.session} left behind (not a regular file of at most ${maxFileBytes} bytes when read)`); continue; }
    const to = path.join(dest, c.run, `events-${c.session}.ndjson`);
    try {
      fs.writeFileSync(to, buf, { mode: 0o600, flag: "wx" });
      fs.chmodSync(to, 0o600);
    } catch (e) { notes.push(`live: ${c.run}: the event log of ${c.session} not written (${e.code ?? e.message})`); continue; }
    copied.push({ run: c.run, session: c.session, bytes: buf.length });
  }
  return { copied, notes };
}

function parseArgs(argv) {
  const o = {};
  const map = { "--store": "store", "--dest": "dest", "--max-file-bytes": "maxFileBytes", "--max-bytes": "maxBytes" };
  for (let i = 0; i < argv.length; i++) {
    const k = map[argv[i]];
    if (!k || i + 1 >= argv.length) throw new Error(`unknown or incomplete option: ${argv[i]}`);
    o[k] = argv[++i];
  }
  if (!o.store || !o.dest) throw new Error("--store and --dest are required");
  for (const k of ["maxFileBytes", "maxBytes"]) {
    if (o[k] === undefined) continue;
    if (!/^\d+$/.test(o[k])) throw new Error(`--${k === "maxBytes" ? "max-bytes" : "max-file-bytes"} needs a number of bytes`);
    o[k] = Number(o[k]);
  }
  return o;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`live-events: ${e.message}`); process.exit(2); }
  const r = copyLiveEvents(o);
  for (const n of r.notes) console.log(n);
  const bytes = r.copied.reduce((a, c) => a + c.bytes, 0);
  console.log(`live: event logs: ${r.copied.length} copied, ${bytes} bytes (cap ${o.maxBytes ?? EVENTS_MAX_BYTES} bytes)`);
}
