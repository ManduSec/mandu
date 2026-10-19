#!/usr/bin/env node
// collect-results.mjs — the host side of a CI run's results
// (docs/design/testing/continuous-integration.md §6). The guest writes a tar onto its
// output disk; code from the commit under test produced it, so it is
// UNTRUSTED. This reads it without tar(1) and without following anything:
//
//   1. list first: every member must be a regular file or a directory, under
//      a relative path with no `..`, in the results layout (below), at most
//      MAX_MEMBERS members and MAX_BYTES unpacked; no duplicates, no member
//      under a file. Anything else refuses the whole archive.
//   2. extract into a fresh directory, creating each file with O_EXCL, mode
//      0644/0755 (never the archive's owner or permissions).
//   3. validate summary.json against schema 1 (validateSummary below), and
//      check it is THIS run (run id, commit, image as the host set them).
//   4. copy it, without drills/, to the path table's `ci-runs` dir
//      (${MANDU_HOME:-~/.mandu}/runs/ci)/<run>/ and prune that
//      directory to the newest MAX_RUNS runs; with --out, copy it there too,
//      drills/ included (the GitLab job's artifact).
//   5. the replay records under drills/replay/ (collectReplay below): every
//      record directory's allowed files, merged into ONE run of the host's
//      store, runs/drills/replay/<run>/, with run.json's runId (and each
//      session's sessionId) forced to this run's id; then the store's
//      retention policy (replay-retention.mjs: the newest MAX_REPLAY_RUNS by
//      startedAt, MANDU_REPLAY_KEEP_RUNS overriding, plus pinned and
//      recently written runs). And, only from a passing default-branch GitLab run
//      (isDefaultBranchRun), the plain-run baselines under drills/baselines/
//      into the host's baseline cache, runs/drills/baselines/<key>/: an MR's
//      baseline is never promoted, since the plain run is the control a
//      replay is graded against (test-reorganization.md §6.3). Nor is one
//      whose plain screens show a stale statusline (staleStatusline below),
//      unless --allow-stale-statusline names it.
//   6. the live-drill records under drills/live/ (collectLive below): each
//      run directory of the nightly's drill entries (drill-run.ts, its
//      --store the guest's), the record files the dashboard reads and the
//      event log of each session the run names (events-<session>.ndjson),
//      nothing else, into the host's live store, runs/drills/live/<run>.<drill run>/
//      (the path table's `live-drill-runs`), owner-only, its meta's runId
//      forced to that name, its session ids namespaced by the CI run, and a
//      run the guest left `running` marked `aborted`; a marker
//      file, ci-run.json, says which CI run brought it, and only the marked
//      directories are pruned (to the newest MAX_LIVE_RUNS: the store also
//      holds the host's own live runs, which this never touches). From any
//      run, like the replay records: an observation, not a control.
//   6a. PINS: a run directory (step 4's or step 6's) holding `.keep` is never
//      pruned and does not count toward the cap. With --only naming a
//      PINNED_JOBS job (the demo battery, whose numbers are published), the
//      collector pins that run's directory and live records as it writes
//      them; --pin / --unpin / --pinned do it by hand (below).
//   7. say how full drills/ came (members and bytes against the guest's own
//      caps, DRILLS_MAX_MEMBERS / DRILLS_MAX_BYTES for the replay records and
//      baselines, LIVE_MAX_MEMBERS / LIVE_MAX_BYTES for drills/live, which
//      pipeline.sh's tidy_drills and collect_live enforce) and WARN when
//      either is near its caps, or when the guest dropped it (its summary's
//      stage `drills` or `drills-live` is `skip`).
//
// On any refusal, and when the host already knows the run broke (--error,
// e.g. a timeout), it writes a minimal `result: "error"` summary instead, so
// the run still shows up (and nothing of drills/ is copied). Exit: 0 pass,
// 1 fail, 2 error; the replay copy and the promotion never change it.
//
//   node scripts/ci/collect-results.mjs --archive <out.raw|tar> --run-id <id>
//        [--source local|gitlab] [--commit SHA] [--ref REF] [--image NAME]
//        [--started ISO] [--error MSG] [--console FILE] [--out DIR]
//        [--runs-dir DIR] [--replay-dir DIR] [--baselines-dir DIR] [--live-dir DIR]
//        [--only IDS]   the job's suite selection (MANDU_CI_ONLY, the host's)
//        [--allow-stale-statusline KEYS|all]   promote these baselines although
//                       their plain side shows a stale statusline (step 5;
//                       MANDU_CI_ALLOW_STALE_STATUSLINE is the same, from the job)
//   node scripts/ci/collect-results.mjs --pin <CI run> [--reason TEXT]   pin its records
//   node scripts/ci/collect-results.mjs --unpin <CI run>                 release them
//   node scripts/ci/collect-results.mjs --pinned                         list the pinned runs
//        (each with [--runs-dir DIR] [--live-dir DIR]; --pin / --unpin exit 1
//        when nothing of that run is left)
//
// The results layout the archive may hold (and nothing else):
//   summary.json            required
//   junit.xml               optional
//   summary.md              optional: the agent matrix (run-suites.mjs), text
//   logs/**                 one log per entry and stage
//   artifacts/release/**    what `vm-run.sh --exec` left in release/
//   drills/replay/**        the replay-drill entries' records (run-suites
//                           --replay-store: <entry>/<run>/… sandboxed, <run>/… not)
//   drills/baselines/**     their plain-run baselines (--replay-baselines)
//   drills/live/**          the live-drill entries' run records (run-suites
//                           --watch-store, then pipeline.sh's collect_live:
//                           <drill run>/<record file>, and live-events.mjs:
//                           <drill run>/events-<session>.ndjson)
//
// Exported for tests and for other readers: listTar, extractTar,
// validateSummary, collect, collectReplay, promoteBaselines, staleStatusline,
// statusRows, parseAllowStale, isDefaultBranchRun,
// collectLive, drillsReport, liveReport, pinRun, unpinRun, listPinned,
// liveRunsOf, pinnedJob, isPinned.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { resolvePath } from "../paths/mandu-paths.mjs";
import { DEFAULT_GRACE_MS, DEFAULT_KEEP_RUNS, PIN_FILE, formatBytes, keepRunsFromEnv, pruneReplayStore } from "./replay-retention.mjs";
import { EVENTS_FILE_RE, SESSION_ID_RE } from "./live-events.mjs";

// The whole archive. Sized for drills/ and drills/live at their own caps
// (below) plus the logs: one per entry (a summary holds at most 2,000
// entries; the per-push run has ~115) and each at most 5 MiB, and the kernel
// lane's per-crate logs (continuous-integration.md §6). It must fit the
// results disk vm-run.sh gives the guest (2 GiB; a test reads it).
export const MAX_MEMBERS = 14000;
export const MAX_BYTES = 1280 * 1024 * 1024;
// drills/ in the guest, drills/live left out: pipeline.sh's tidy_drills drops
// the replay records and baselines whole past these (DRILLS_MAX_FILES /
// DRILLS_MAX_BYTES there; ci-collect-results.test.mjs checks the two agree).
// The per-push run of 2026-10-01 left 686 members and ~41 MB: 65 replay
// sessions at 7 members each, a baseline at 2.
export const DRILLS_MAX_MEMBERS = 3000;
export const DRILLS_MAX_BYTES = 256 * 1024 * 1024;
// drills/live in the guest: pipeline.sh's collect_live trims the recordings
// (the casts, then the pane captures, largest first) past these and drops the
// tree only when the record files alone are over (LIVE_MAX_FILES /
// LIVE_MAX_BYTES there). A nightly runs 41 live drills in 5 entries: about
// 6 members each (a cast, the pane captures, a seed) and 5 per run, so ~270
// members; a cast is a few MB. The demo battery (6 demos, Mandu and 5
// baselines, 3 rounds: 108 runs of one drill each) comes to about 12 a run,
// ~1,300: past the old 1,000 its trim took every cast and then the pane
// captures (local-20261017-041123-b26ba674: every demo-c3 turn-2 pane), the
// only record of what the user saw, so a grade could not be checked again.
// 2026-10-18: the battery runs Sonnet and Opus, and the planned one (9
// demos, Mandu and 9 sides, 2 models, 3 takes) is 540 runs, ~13 members
// and ~1.1 MB a run (the wire log most of it): ~7,000 members and ~600 MB.
// Past the old 2,500 its record files alone (7 a run, ~3,800) were over, so
// the guest would have DROPPED drills/live whole: no record of the battery.
export const LIVE_MAX_MEMBERS = 10000;
export const LIVE_MAX_BYTES = 768 * 1024 * 1024;
/** drillsReport warns from this share of a drills/ cap on. */
export const DRILLS_WARN_RATIO = 0.8;
export const MAX_RUNS = 200;
const MAX_SUMMARY_BYTES = 1024 * 1024; // the dashboard reads at most 1 MiB
const MAX_CONSOLE_BYTES = 5 * 1024 * 1024;
const BLOCK = 512;
/** The host store keeps this many replay runs (replay-retention.mjs's default,
 *  300, at least every dashboard listing window; MANDU_REPLAY_KEEP_RUNS
 *  overrides it), this many
 *  baselines, and this many live runs a CI run brought (the host's own are
 *  never pruned). */
export const MAX_REPLAY_RUNS = DEFAULT_KEEP_RUNS;
export const MAX_BASELINES = 500;
export const MAX_LIVE_RUNS = 200;
/** One replay record file (a cast, an event log) at most. */
export const MAX_RECORD_FILE_BYTES = 32 * 1024 * 1024;

// ── summary.json, schema 1 ────────────────────────────────────────────────
// The canonical description (continuous-integration.md §6). The dashboard
// re-validates every run it reads with its own copy of these rules
// (the developer view's ci-runs.ts validateSummary), and a run it refuses is not
// shown, so this validator is AT LEAST as strict as that one; the test
// scripts/test/ci-collect-results.test.mjs feeds the collector's outputs to
// both. Keep the three in sync.
//
// {
//   schema:   1,                                          required
//   kind:     "mandu-ci-run",                             required
//   run:      ID, not starting with "."; == its directory required
//   source:   "gitlab" | "local"                          required
//   commit:   /^[0-9a-f]{7,64}(\+dirty)?$/                required
//             (`<sha>+dirty`: a --worktree run with local changes)
//   ref:      text ≤ 255 (may be "")                      required
//   image:    text ≤ 200                                  optional
//   started:  ISO-8601, Z or ±hh:mm                       required
//   finished: ISO-8601, Z or ±hh:mm                       required
//   result:   "pass" | "fail" | "error"                   required
//   reason:   text ≤ 2000: why an `error` run broke       optional
//             ("image stale", "unreadable results: …", "timeout …")
//   stages:   { ID: { result: ENTRY_RESULT, duration_s } } ≤ 64   optional
//   entries:  [ ENTRY ] ≤ 2000, ids unique                required
// }
// ENTRY = { id: ID, kind: ID, result: ENTRY_RESULT,
//           pass, fail, skip: integer 0..1e9, duration_s: number 0..1e7,
//           log?: exactly "logs/<id>.log" (and in the archive),
//           agent?: AGENT, agentVersion?: VERSION, ullm?: AGENT (with agent) }
// AGENT = /^[a-z][a-z0-9-]{0,39}$/ (the agent the entry drove, or its U-LLM)
// VERSION = /^[0-9][0-9A-Za-z.+-]{0,63}$/ (what the agent's CLI reported)
// ID = /^[A-Za-z0-9._:-]{1,120}$/, not "." or ".."
// ENTRY_RESULT = "pass" | "fail" | "skip" | "timeout" | "error"
// text = a string without C0/C1 controls, DEL or bidi overrides.
// No other field, at any level.

export const ID_RE = /^[A-Za-z0-9._:-]{1,120}$/;
export const AGENT_RE = /^[a-z][a-z0-9-]{0,39}$/;
export const AGENT_VERSION_RE = /^[0-9][0-9A-Za-z.+-]{0,63}$/;
const isId = (v) => typeof v === "string" && ID_RE.test(v) && v !== "." && v !== "..";
const RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/;
export const COMMIT_RE = /^[0-9a-f]{7,64}(\+dirty)?$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const COMPONENT_RE = /^[A-Za-z0-9._@+=,:-]{1,255}$/;
// eslint-disable-next-line no-control-regex
const UNSAFE_TEXT_RE = /[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/;
const RUN_RESULTS = ["pass", "fail", "error"];
const ENTRY_RESULTS = ["pass", "fail", "skip", "timeout", "error"];

const isText = (v, max) => typeof v === "string" && v.length <= max && !UNSAFE_TEXT_RE.test(v);
const isCount = (v) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0 && v <= 1e9;
const isSeconds = (v) => typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1e7;
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
export const cleanText = (v, max) => String(v).replace(new RegExp(UNSAFE_TEXT_RE.source, "g"), "?").slice(0, max);

/** checkMemberPath(p) → normalized relative path, or throws. */
export function checkMemberPath(raw) {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 1024) throw new Error(`bad member path length`);
  if (raw.includes("\0")) throw new Error("NUL in member path");
  if (raw.startsWith("/")) throw new Error(`absolute member path: ${JSON.stringify(raw)}`);
  let p = raw;
  while (p.startsWith("./")) p = p.slice(2);
  if (p.endsWith("/")) p = p.replace(/\/+$/, "");
  if (p === "" || p === ".") return "";
  for (const c of p.split("/")) {
    if (c === "..") throw new Error(`'..' in member path: ${JSON.stringify(raw)}`);
    if (c === "." || c === "") throw new Error(`empty or '.' component in member path: ${JSON.stringify(raw)}`);
    if (!COMPONENT_RE.test(c)) throw new Error(`member path has a character outside [A-Za-z0-9._@+=,:-]: ${JSON.stringify(raw)}`);
  }
  return p;
}

/** Is `p` (normalized) a place the results layout allows, for this type? */
const LAYOUT_DIRS = ["logs", "artifacts", "artifacts/release", "drills", "drills/replay", "drills/baselines", "drills/live"];
const LAYOUT_TREES = ["logs/", "artifacts/release/", "drills/replay/", "drills/baselines/", "drills/live/"];
function allowedInLayout(p, type) {
  if (p === "summary.json" || p === "junit.xml" || p === "summary.md") return type === "file";
  if (LAYOUT_DIRS.includes(p)) return type === "dir";
  return LAYOUT_TREES.some((t) => p.startsWith(t));
}

/**
 * validateSummary(obj, {files, dirName}) → array of error strings (empty =
 * valid). `files`, when given, is the set of file paths the archive held;
 * every log the summary names must be among them. `dirName`, when given, is
 * the run's directory name, which `run` must equal.
 */
export function validateSummary(s, { files, dirName } = {}) {
  const errs = [];
  const bad = (m) => errs.push(m);
  if (!isObj(s)) return ["summary is not an object"];
  const TOP = ["schema", "kind", "run", "source", "commit", "ref", "image", "started", "finished", "result", "reason", "stages", "entries"];
  const REQ = ["schema", "kind", "run", "source", "commit", "ref", "started", "finished", "result", "entries"];
  for (const k of Object.keys(s)) if (!TOP.includes(k)) bad(`unknown field: ${k.slice(0, 40)}`);
  for (const k of REQ) if (!(k in s)) bad(`missing field: ${k}`);
  if (s.schema !== 1) bad("schema must be 1");
  if (s.kind !== "mandu-ci-run") bad('kind must be "mandu-ci-run"');
  if (!isId(s.run) || !RUN_ID_RE.test(s.run)) bad("run: not a run id");
  else if (dirName !== undefined && s.run !== dirName) bad("run: does not match its directory");
  if (!["gitlab", "local"].includes(s.source)) bad('source must be "gitlab" or "local"');
  if (typeof s.commit !== "string" || !COMMIT_RE.test(s.commit)) bad("commit: not a commit id (<sha> or <sha>+dirty)");
  if (!isText(s.ref, 255)) bad("ref: text ≤ 255");
  if ("image" in s && !isText(s.image, 200)) bad("image: text ≤ 200");
  for (const k of ["started", "finished"]) {
    if (typeof s[k] !== "string" || !ISO_RE.test(s[k]) || Number.isNaN(Date.parse(s[k]))) bad(`${k}: an ISO-8601 time`);
  }
  if (!RUN_RESULTS.includes(s.result)) bad('result must be "pass", "fail" or "error"');
  if ("reason" in s && !isText(s.reason, 2000)) bad("reason: text ≤ 2000");

  if ("stages" in s) {
    if (!isObj(s.stages)) bad("stages: an object");
    else {
      const names = Object.keys(s.stages);
      if (names.length > 64) bad("stages: at most 64");
      for (const n of names) {
        const st = s.stages[n];
        if (!isId(n)) { bad(`stages: bad stage name ${JSON.stringify(n.slice(0, 40))}`); continue; }
        if (!isObj(st)) { bad(`stages.${n}: an object`); continue; }
        for (const k of Object.keys(st)) if (!["result", "duration_s"].includes(k)) bad(`stages.${n}: unknown field ${k.slice(0, 40)}`);
        if (!ENTRY_RESULTS.includes(st.result)) bad(`stages.${n}.result`);
        if (!isSeconds(st.duration_s)) bad(`stages.${n}.duration_s`);
      }
    }
  }

  if (!Array.isArray(s.entries)) bad("entries: an array");
  else {
    if (s.entries.length > 2000) bad("entries: at most 2000");
    const ids = new Set();
    const KEYS = ["id", "kind", "result", "pass", "fail", "skip", "duration_s", "log", "agent", "agentVersion", "ullm"];
    s.entries.slice(0, 2000).forEach((e, i) => {
      const w = `entries[${i}]`;
      if (!isObj(e)) { bad(`${w}: an object`); return; }
      for (const k of Object.keys(e)) if (!KEYS.includes(k)) bad(`${w}: unknown field ${k.slice(0, 40)}`);
      if (!isId(e.id)) bad(`${w}.id`);
      else if (ids.has(e.id)) bad(`${w}.id: duplicate ${e.id}`);
      else ids.add(e.id);
      if (!isId(e.kind)) bad(`${w}.kind`);
      if (!ENTRY_RESULTS.includes(e.result)) bad(`${w}.result`);
      for (const k of ["pass", "fail", "skip"]) if (!isCount(e[k])) bad(`${w}.${k}`);
      if (!isSeconds(e.duration_s)) bad(`${w}.duration_s`);
      if ("agent" in e && !(typeof e.agent === "string" && AGENT_RE.test(e.agent))) bad(`${w}.agent`);
      if ("agentVersion" in e && !(typeof e.agentVersion === "string" && AGENT_VERSION_RE.test(e.agentVersion))) bad(`${w}.agentVersion`);
      if ("ullm" in e && !(typeof e.ullm === "string" && AGENT_RE.test(e.ullm))) bad(`${w}.ullm`);
      if (("agentVersion" in e || "ullm" in e) && !("agent" in e)) bad(`${w}: agentVersion and ullm need agent`);
      if ("log" in e) {
        if (!isId(e.id) || e.log !== `logs/${e.id}.log`) bad(`${w}.log: must be exactly logs/<id>.log`);
        else if (files && !files.has(e.log)) bad(`${w}.log: ${e.log} is not in the archive`);
      }
    });
  }
  return errs;
}

// ── the tar reader ─────────────────────────────────────────────────────────

function readAt(fd, pos, len) {
  const buf = Buffer.alloc(len);
  let off = 0;
  while (off < len) {
    const n = fs.readSync(fd, buf, off, len - off, pos + off);
    if (n === 0) break;
    off += n;
  }
  return off === len ? buf : buf.subarray(0, off);
}
function cstr(buf, start, len) {
  const b = buf.subarray(start, start + len);
  const z = b.indexOf(0);
  return b.subarray(0, z === -1 ? b.length : z).toString("utf8");
}
function octal(buf, start, len) {
  if (buf[start] & 0x80) return Infinity; // GNU base-256: only for huge values; refuse
  const s = cstr(buf, start, len).trim();
  if (s === "") return 0;
  if (!/^[0-7]+$/.test(s)) throw new Error(`bad numeric field ${JSON.stringify(s)}`);
  return parseInt(s, 8);
}
function checksumOk(h) {
  const want = octal(h, 148, 8);
  let u = 0;
  for (let i = 0; i < BLOCK; i++) u += i >= 148 && i < 156 ? 32 : h[i];
  return u === want;
}
function parsePax(buf) {
  const out = {};
  let i = 0;
  while (i < buf.length) {
    const sp = buf.indexOf(0x20, i);
    if (sp === -1) break;
    const len = parseInt(buf.subarray(i, sp).toString("ascii"), 10);
    if (!Number.isInteger(len) || len <= 0 || i + len > buf.length) throw new Error("bad pax record");
    const rec = buf.subarray(sp + 1, i + len - 1).toString("utf8");
    const eq = rec.indexOf("=");
    if (eq === -1) throw new Error("bad pax record");
    out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}

/**
 * listTar(file) → { members: [{path, type: "file"|"dir", size, offset}] }.
 * Throws on anything outside the rules. Reads headers only.
 */
export function listTar(file, { maxMembers = MAX_MEMBERS, maxBytes = MAX_BYTES } = {}) {
  const fd = fs.openSync(file, "r");
  try {
    const members = [];
    const seen = new Map(); // path → type
    let pos = 0, total = 0, headers = 0, ended = false;
    let longName = null, pax = null;
    for (;;) {
      if (++headers > maxMembers * 4 + 16) throw new Error("too many headers");
      const h = readAt(fd, pos, BLOCK);
      if (h.length < BLOCK) throw new Error("truncated archive (no end-of-archive marker)");
      if (h.every((b) => b === 0)) { ended = true; break; }
      if (!checksumOk(h)) throw new Error(`bad header checksum at offset ${pos}`);
      const type = String.fromCharCode(h[156] || 0x30);
      const size = octal(h, 124, 12);
      if (!Number.isFinite(size) || size < 0) throw new Error("bad member size");
      const dataPos = pos + BLOCK;
      const next = dataPos + Math.ceil(size / BLOCK) * BLOCK;
      if (type === "L") {
        if (size > 4096) throw new Error("long name too long");
        longName = cstr(readAt(fd, dataPos, size), 0, size);
        pos = next; continue;
      }
      if (type === "x") {
        if (size > 65536) throw new Error("pax header too long");
        pax = parsePax(readAt(fd, dataPos, size));
        for (const k of Object.keys(pax)) {
          if (!["path", "size", "mtime", "atime", "ctime", "uid", "gid", "uname", "gname"].includes(k) && !k.startsWith("LIBARCHIVE.") && !k.startsWith("SCHILY.")) {
            throw new Error(`pax key not allowed: ${k}`);
          }
        }
        pos = next; continue;
      }
      if (type === "g") { pos = next; continue; } // global pax: ignored, sets nothing
      let name;
      if (pax && pax.path !== undefined) name = pax.path;
      else if (longName !== null) name = longName;
      else {
        // POSIX ustar ("ustar\0") has a prefix field; GNU ("ustar ") reuses
        // those bytes for other data, so only the former reads it.
        const base = cstr(h, 0, 100);
        const prefix = cstr(h, 257, 6) === "ustar" ? cstr(h, 345, 155) : "";
        name = prefix ? `${prefix}/${base}` : base;
      }
      let msize = size;
      if (pax && pax.size !== undefined) {
        if (!/^\d+$/.test(pax.size)) throw new Error("bad pax size");
        msize = Number(pax.size);
        if (msize !== size) throw new Error("pax size differs from header size");
      }
      longName = null; pax = null;
      let mtype;
      if (type === "0" || type === "\0" || type === "7") mtype = "file";
      else if (type === "5") mtype = "dir";
      else {
        const what = { 1: "hard link", 2: "symlink", 3: "character device", 4: "block device", 6: "fifo", K: "long link name", S: "sparse file", V: "volume header", M: "multi-volume" }[type] || `type ${JSON.stringify(type)}`;
        throw new Error(`refused member ${JSON.stringify(name)}: ${what}`);
      }
      const p = checkMemberPath(name);
      if (p === "") { if (mtype !== "dir") throw new Error("root member is not a directory"); pos = next; continue; }
      if (!allowedInLayout(p, mtype)) throw new Error(`member outside the results layout: ${p}`);
      if (seen.has(p)) throw new Error(`duplicate member: ${p}`);
      if (mtype === "dir" && msize !== 0) throw new Error(`directory with data: ${p}`);
      seen.set(p, mtype);
      members.push({ path: p, type: mtype, size: msize, offset: dataPos });
      if (members.length > maxMembers) throw new Error(`more than ${maxMembers} members`);
      total += msize;
      if (total > maxBytes) throw new Error(`more than ${maxBytes} bytes unpacked`);
      pos = next;
    }
    if (!ended) throw new Error("no end-of-archive marker");
    if (longName !== null || pax !== null) throw new Error("dangling long-name/pax header");
    // No member under a file ("logs" a file and "logs/x" a member).
    for (const m of members) {
      const parts = m.path.split("/");
      for (let i = 1; i < parts.length; i++) {
        const anc = parts.slice(0, i).join("/");
        if (seen.get(anc) === "file") throw new Error(`member under a file: ${m.path}`);
      }
    }
    return { members };
  } finally {
    fs.closeSync(fd);
  }
}

/** extractTar(file, members, dest): dest must be a fresh empty directory. */
export function extractTar(file, members, dest) {
  const fd = fs.openSync(file, "r");
  try {
    for (const m of members) {
      const target = path.join(dest, ...m.path.split("/"));
      if (!target.startsWith(dest + path.sep)) throw new Error(`escapes: ${m.path}`);
      if (m.type === "dir") { fs.mkdirSync(target, { recursive: true, mode: 0o755 }); continue; }
      fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
      const out = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o644);
      try {
        let left = m.size, pos = m.offset;
        while (left > 0) {
          const chunk = readAt(fd, pos, Math.min(left, 1 << 20));
          if (chunk.length === 0) throw new Error(`truncated data: ${m.path}`);
          fs.writeSync(out, chunk);
          left -= chunk.length; pos += chunk.length;
        }
      } finally { fs.closeSync(out); }
    }
  } finally { fs.closeSync(fd); }
}

// ── collect ────────────────────────────────────────────────────────────────

/** The path table's `ci-runs` entry (docs/design/architecture/on-disk-layout.md §5). */
export function defaultRunsDir(env = process.env) {
  return resolvePath("ci-runs", env, env.HOME || os.homedir());
}

function nowIso() { return new Date().toISOString().replace(/\.\d{3}Z$/, "Z"); }

export function errorSummary({ runId, source, commit, ref, image, started, error }) {
  const s = {
    schema: 1, kind: "mandu-ci-run", run: runId,
    source: source === "gitlab" ? "gitlab" : "local",
    // The host always knows the commit it tested; "0000000" only when a caller
    // gave none (the dashboard needs a commit id to list the run at all).
    commit: commit && COMMIT_RE.test(commit) ? commit : "0000000",
    ref: ref && isText(ref, 255) ? ref : "",
    started: started && ISO_RE.test(started) ? started : nowIso(),
    finished: nowIso(),
    result: "error",
    reason: cleanText(error, 2000),
    entries: [],
  };
  if (image && isText(image, 200)) s.image = image;
  return s;
}

function copyTree(src, dst, { skip = [] } = {}) {
  fs.mkdirSync(dst, { recursive: true, mode: 0o755 });
  for (const ent of fs.readdirSync(src, { withFileTypes: true })) {
    if (skip.includes(ent.name)) continue;
    const a = path.join(src, ent.name), b = path.join(dst, ent.name);
    if (ent.isDirectory()) copyTree(a, b);
    else if (ent.isFile()) fs.copyFileSync(a, b);
  }
}

function copyCapped(src, dst, cap) {
  const st = fs.statSync(src);
  const fd = fs.openSync(src, "r");
  try {
    const start = Math.max(0, st.size - cap);
    fs.writeFileSync(dst, readAt(fd, start, st.size - start), { mode: 0o644 });
  } finally { fs.closeSync(fd); }
}

/** Put the tree at `from` (or what `fill(tmp)` writes) at dir/<name>,
 *  replacing an older one: staged as a hidden sibling, then renamed.
 *  `dirMode` is the mode of dir/<name> (and of dir, when this creates it).
 *  A pin (PIN_FILE, below) survives the replacement: the older directory's
 *  is carried over, and `pin` (a reason) writes one. Only the host writes a
 *  pin: the fills copy record files alone, and PIN_FILE is never one. */
function replaceDir(dir, name, fill, { dirMode = 0o755, pin = null } = {}) {
  fs.mkdirSync(dir, { recursive: true, mode: dirMode });
  const final = path.join(dir, name);
  const tmp = fs.mkdtempSync(path.join(dir, `.tmp-${name}-`));
  try {
    fill(tmp);
    const fileMode = dirMode === 0o700 ? 0o600 : 0o644;
    if (pin !== null) writePin(tmp, pin, fileMode);
    else if (isPinned(final)) fs.writeFileSync(path.join(tmp, PIN_FILE), readPinText(final), { mode: fileMode, flag: "wx" });
    let old = null;
    if (fs.existsSync(final)) { old = `${tmp}.old`; fs.renameSync(final, old); }
    fs.renameSync(tmp, final);
    fs.chmodSync(final, dirMode); // 0755: the dashboard (maybe another user) reads it
    if (old) fs.rmSync(old, { recursive: true, force: true });
  } catch (e) {
    fs.rmSync(tmp, { recursive: true, force: true });
    throw e;
  }
  return final;
}

/** Replace runsDir/<run> atomically with the tree at `from` (drills/ left out:
 *  its records go to their own store), pinned when `pin` is a reason; prune. */
function publishRun(from, runsDir, runId, maxRuns, pin = null) {
  const final = replaceDir(runsDir, runId, (tmp) => copyTree(from, tmp, { skip: ["drills"] }), { pin });
  pruneRuns(runsDir, maxRuns);
  return final;
}

// ── pins: the records a prune never removes ───────────────────────────────
// A run directory of the ci store (runs/ci/<run>/) or a CI-brought one of the
// live store (runs/drills/live/<name>/) holding an entry named PIN_FILE
// (`.keep`, the replay store's pin too, replay-retention.mjs) is PINNED: the
// prunes below skip it, and it does not count toward their cap. The records
// behind a published number (the demo battery's, comparisons.md §5) must be
// there when someone asks for them, whatever ran since. The collector pins
// the records of a PINNED_JOBS job as it collects them (by the host's --only,
// never the guest's word); `--pin <CI run>`, `--unpin <CI run>` and
// `--pinned` do it by hand (continuous-integration.md §6). A pin is a small
// JSON note ({kind: "mandu-keep", reason, pinnedAt}); any entry of that name
// pins, as in the replay store.

/** The jobs (manifest ids, as MANDU_CI_ONLY names them) whose records are
 *  pinned as collected: the demo battery, on the subscription and on an API
 *  key (continuous-integration.md §9.9), whose numbers are published. Its
 *  stand-in rehearsal is not: a scripted model's numbers are no one's
 *  evidence. */
export const PINNED_JOBS = Object.freeze(["live.demo-battery", "live.demo-battery.api"]);

/** The PINNED_JOBS job a run's --only selection (comma-separated ids) names,
 *  else null. */
export function pinnedJob(only) {
  if (typeof only !== "string") return null;
  const ids = only.split(",").map((x) => x.trim());
  return PINNED_JOBS.find((j) => ids.includes(j)) ?? null;
}

/** Does dir hold a pin (any entry named PIN_FILE, not followed)? */
export function isPinned(dir) {
  try { fs.lstatSync(path.join(dir, PIN_FILE)); return true; } catch { return false; }
}

function writePin(dir, reason, mode) {
  const note = { kind: "mandu-keep", reason: cleanText(reason, 300), pinnedAt: nowIso() };
  const f = path.join(dir, PIN_FILE);
  fs.rmSync(f, { force: true }); // a pin that is a symlink is replaced, never followed
  fs.writeFileSync(f, `${JSON.stringify(note)}\n`, { mode, flag: "wx" });
}
/** A pin's text (a regular file's, at most 4 KiB), else "". */
function readPinText(dir) {
  const f = path.join(dir, PIN_FILE);
  try {
    const st = fs.lstatSync(f);
    return st.isFile() && st.size <= 4096 ? fs.readFileSync(f, "utf8") : "";
  } catch { return ""; }
}
/** A pin's note ({reason, pinnedAt}), {} when it is not one. */
function readPin(dir) {
  try {
    const v = JSON.parse(readPinText(dir));
    if (!isObj(v)) return {};
    return { reason: typeof v.reason === "string" ? v.reason : undefined, pinnedAt: typeof v.pinnedAt === "string" ? v.pinnedAt : undefined };
  } catch { return {}; }
}

/** A live directory's LIVE_MARKER (this collector wrote it), or null. */
function readMarker(dir) {
  try {
    const f = path.join(dir, LIVE_MARKER);
    const st = fs.lstatSync(f);
    if (!st.isFile() || st.size > 64 * 1024) return null;
    const v = JSON.parse(fs.readFileSync(f, "utf8"));
    return isObj(v) && typeof v.ciRun === "string" ? v : null;
  } catch { return null; }
}

function isRealDir(d) {
  try { return fs.lstatSync(d).isDirectory(); } catch { return false; }
}

/** The live store's directories a CI run brought: those whose LIVE_MARKER
 *  names it (a directory's name may hold a hash of the run id instead,
 *  liveRunName), sorted. */
export function liveRunsOf(liveDir, ciRun) {
  let ents;
  try { ents = fs.readdirSync(liveDir, { withFileTypes: true }); } catch { return []; }
  return ents
    .filter((e) => e.isDirectory() && LIVE_RUN_ID_RE.test(e.name) && readMarker(path.join(liveDir, e.name))?.ciRun === ciRun)
    .map((e) => path.join(liveDir, e.name))
    .sort();
}

function checkCiRun(ciRun) {
  if (typeof ciRun !== "string" || !RUN_ID_RE.test(ciRun)) throw new Error(`bad CI run id: ${ciRun}`);
}

/**
 * pinRun(ciRun, {runsDir, liveDir, reason}) → { ci, live }: pin a CI run's
 * records: its summary directory runsDir/<run>/ (ci: that path, or null when
 * it is gone) and each live directory it brought (live: their paths, [] when
 * none is left). An existing pin is rewritten with this reason.
 */
export function pinRun(ciRun, { runsDir, liveDir, reason = "pinned by hand" }) {
  checkCiRun(ciRun);
  const ciDir = path.join(runsDir, ciRun);
  const ci = isRealDir(ciDir) ? ciDir : null;
  if (ci) writePin(ci, reason, 0o644);
  const live = liveRunsOf(liveDir, ciRun);
  for (const d of live) writePin(d, reason, 0o600);
  return { ci, live };
}

/** unpinRun(ciRun, {runsDir, liveDir}) → { ci, live }: the directories whose
 *  pin it removed (only a pin that is a regular file); the next prune may
 *  then take them. */
export function unpinRun(ciRun, { runsDir, liveDir }) {
  checkCiRun(ciRun);
  const drop = (d) => {
    const f = path.join(d, PIN_FILE);
    try { if (fs.lstatSync(f).isFile()) { fs.unlinkSync(f); return true; } } catch { /* no pin */ }
    return false;
  };
  const ciDir = path.join(runsDir, ciRun);
  const ci = isRealDir(ciDir) && drop(ciDir) ? ciDir : null;
  return { ci, live: liveRunsOf(liveDir, ciRun).filter(drop) };
}

/** listPinned({runsDir, liveDir}) → [{ ciRun, ci, live, reason, pinnedAt }]:
 *  one row per CI run with a pinned summary (ci: true) or pinned live
 *  directories (live: how many), by run id; reason and pinnedAt from the
 *  first pin read. A live directory without LIVE_MARKER (the host's own,
 *  never pruned) is not listed. */
export function listPinned({ runsDir, liveDir }) {
  const rows = new Map();
  const row = (ciRun, dir) => {
    if (!rows.has(ciRun)) rows.set(ciRun, { ciRun, ci: false, live: 0, ...readPin(dir) });
    return rows.get(ciRun);
  };
  const pinned = (root, nameRe) => {
    let ents;
    try { ents = fs.readdirSync(root, { withFileTypes: true }); } catch { return []; }
    return ents.filter((e) => e.isDirectory() && nameRe.test(e.name) && isPinned(path.join(root, e.name))).map((e) => e.name);
  };
  for (const name of pinned(runsDir, RUN_ID_RE)) row(name, path.join(runsDir, name)).ci = true;
  for (const name of pinned(liveDir, LIVE_RUN_ID_RE)) {
    const d = path.join(liveDir, name);
    const m = readMarker(d);
    if (m) row(m.ciRun, d).live++;
  }
  return [...rows.values()].sort((a, b) => (a.ciRun < b.ciRun ? -1 : a.ciRun > b.ciRun ? 1 : 0));
}

/** Keep the newest `maxRuns` directories of `runsDir` whose names match
 *  `nameRe`, by the mtime of their `marker` file (else the directory's); a
 *  pinned one (isPinned) is never removed and does not count. */
export function pruneRuns(runsDir, maxRuns = MAX_RUNS, { marker = "summary.json", nameRe = RUN_ID_RE } = {}) {
  const runs = [];
  for (const ent of fs.readdirSync(runsDir, { withFileTypes: true })) {
    if (!ent.isDirectory() || !nameRe.test(ent.name)) continue;
    const d = path.join(runsDir, ent.name);
    if (isPinned(d)) continue;
    let t;
    try { t = fs.statSync(path.join(d, marker)).mtimeMs; } catch { t = fs.statSync(d).mtimeMs; }
    runs.push({ d, t });
  }
  runs.sort((a, b) => b.t - a.t);
  for (const r of runs.slice(maxRuns)) fs.rmSync(r.d, { recursive: true, force: true });
  return runs.slice(maxRuns).map((r) => r.d);
}

// ── the replay records and the baselines (drills/) ─────────────────────────
// The record layout (test-reorganization.md §7.3; WP0's replay-model.ts), one
// run directory:
//   run.json                       the run's meta (kind "mandu-replay-run")
//   sessions/<key>.json            one per session (kind "mandu-replay-session")
//   events-<key>.ndjson            its Mandu arbiter's events
//   casts/<key>.mandu.cast, casts/<key>.plain.cast
//   panes/<key>/<file> (or one directory deeper)
// A baseline (the plain run, cached by its key, §6.3): <key>/ holding only
// BASELINE_FILES, the ONE file of baseline-cache.ts's schema 2 (a schema 1
// entry of nine files is not promoted). Anything else is left behind, and
// said so. The dashboard
// re-validates every record it reads, as strictly as a CI summary (step 3's
// inspector); this copies only the shapes it can read, with the run's
// identity the host's.

/** The host store: the path table's `replay-drill-runs` and `drill-baselines`
 *  rows (on-disk-layout.md §5), both under the runs root beside `ci-runs`. */
export function defaultReplayDirs(env = process.env) {
  const home = env.HOME || os.homedir();
  return { replayDir: resolvePath("replay-drill-runs", env, home), baselinesDir: resolvePath("drill-baselines", env, home) };
}

/** The host's live store: the path table's `live-drill-runs` row
 *  (runs/drills/live), the dashboard's watch store. */
export function defaultLiveDir(env = process.env) {
  return resolvePath("live-drill-runs", env, env.HOME || os.homedir());
}

// The record's names, as WP0's replay-model.ts has them (SESSION_KEY_RE,
// BASELINE_KEY_RE, sessionFileAllowed's FILE_SEG_RE); its validators and this
// collector must agree, which ci-collect-results.test.mjs checks against the
// golden fixture.
export const SESSION_KEY_RE = /^[a-z0-9][a-z0-9.-]{0,119}$/;
export const BASELINE_KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$/;
export const BASELINE_FILES = Object.freeze(["baseline.json"]);
const KEY = "([a-z0-9][a-z0-9.-]{0,119})";
const SEG = "[A-Za-z0-9][A-Za-z0-9._-]{0,119}";
const RECORD_FILES = [
  [new RegExp(`^sessions/${KEY}\\.json$`), "session"],
  [new RegExp(`^events-${KEY}\\.ndjson$`), "events"],
  [new RegExp(`^casts/${KEY}\\.(?:mandu|plain)\\.cast$`), "cast"],
  [new RegExp(`^panes/${KEY}/(?:${SEG}/)?${SEG}$`), "pane"],
];

/** Every regular file under `dir`, as relative paths (sorted); the tree was
 *  extracted by extractTar, so it holds only files and directories. */
function filesUnder(dir, rel = "") {
  const out = [];
  for (const ent of fs.readdirSync(path.join(dir, rel), { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    const r = rel ? `${rel}/${ent.name}` : ent.name;
    if (ent.isDirectory()) out.push(...filesUnder(dir, r));
    else if (ent.isFile()) out.push(r);
  }
  return out;
}

/** The directories under `base` that hold `marker` as a file: base/<x>/ (an
 *  unsandboxed run's shared store) or base/<entry>/<x>/ (a sandboxed entry's own). */
function recordDirs(base, marker) {
  if (!fs.existsSync(base)) return [];
  const out = [];
  const dirsOf = (d) => fs.readdirSync(d, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort();
  const holds = (d) => { try { return fs.lstatSync(path.join(d, marker)).isFile(); } catch { return false; } };
  for (const a of dirsOf(base)) {
    const da = path.join(base, a);
    if (holds(da)) { out.push({ dir: da, rel: a, name: a }); continue; }
    for (const b of dirsOf(da)) {
      const db = path.join(da, b);
      if (holds(db)) out.push({ dir: db, rel: `${a}/${b}`, name: b });
    }
  }
  return out;
}

function readJsonCapped(file, cap) {
  const st = fs.lstatSync(file);
  if (!st.isFile()) throw new Error("not a file");
  if (st.size > cap) throw new Error(`over ${cap} bytes`);
  const v = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!isObj(v)) throw new Error("not a JSON object");
  return v;
}

function writeNew(file, data, mode = 0o644) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: mode === 0o600 ? 0o700 : 0o755 });
  fs.writeFileSync(file, data, { mode, flag: "wx" });
  if (mode === 0o600) fs.chmodSync(file, mode); // whatever the umask
}

/** Make a tree owner-only: 0700 directories, 0600 files (no symlink is
 *  followed; the trees this is given hold only files and directories). */
export function ownerOnly(root) {
  let st;
  try { st = fs.lstatSync(root); } catch { return; }
  if (st.isFile()) { fs.chmodSync(root, 0o600); return; }
  if (!st.isDirectory()) return;
  fs.chmodSync(root, 0o700);
  for (const ent of fs.readdirSync(root)) ownerOnly(path.join(root, ent));
}

/**
 * collectReplay(tree, {runId, commit, replayDir, maxRuns, graceMs}) → { dir,
 * sessions, notes, pruned }. Merges every record directory of tree/drills/replay into
 * replayDir/<runId>/: run.json from the first directory whose run.json is a
 * replay run (its runId forced to runId, its commit to the host's), each
 * session whose file parses as that key's session (its sessionId forced to
 * `<runId>/<key>`), and the events, casts and panes of the sessions kept; a
 * key two directories both hold keeps the first. Nothing when no run.json
 * reads. Returns dir null then. Then the store's retention policy
 * (replay-retention.mjs pruneReplayStore; `pruned` is its report, null when
 * it failed, which a note says and which never undoes the copy).
 */
export function collectReplay(tree, { runId, commit = null, replayDir, maxRuns = MAX_REPLAY_RUNS, graceMs = DEFAULT_GRACE_MS }) {
  const notes = [];
  const sources = recordDirs(path.join(tree, "drills", "replay"), "run.json");
  if (!sources.length) return { dir: null, sessions: [], notes };
  let meta = null;
  for (const src of sources) {
    try {
      const m = readJsonCapped(path.join(src.dir, "run.json"), 64 * 1024);
      if (m.kind !== "mandu-replay-run") throw new Error('kind is not "mandu-replay-run"');
      meta = m;
      break;
    } catch (e) { notes.push(`${src.rel}/run.json: skipped (${e.message})`); }
  }
  if (!meta) { notes.push("no readable run.json: no replay run copied"); return { dir: null, sessions: [], notes }; }
  meta.runId = runId;
  if (commit && COMMIT_RE.test(commit)) meta.commit = commit;

  const plan = new Map(); // destination rel → source file, or JSON text
  const sessions = [];
  for (const src of sources) {
    const files = filesUnder(src.dir).filter((f) => f !== "run.json");
    const kept = new Set();
    for (const f of files) {
      const m = /^sessions\/([a-z0-9][a-z0-9.-]{0,119})\.json$/.exec(f);
      if (!m) continue;
      const key = m[1];
      if (key.includes("..")) { notes.push(`${src.rel}/${f}: skipped (not a session key)`); continue; }
      if (plan.has(f)) { notes.push(`${src.rel}/${f}: skipped (session ${key} came from an earlier directory)`); continue; }
      try {
        const sess = readJsonCapped(path.join(src.dir, f), 4 * 1024 * 1024);
        if (sess.kind !== "mandu-replay-session") throw new Error('kind is not "mandu-replay-session"');
        if (sess.key !== key) throw new Error("its key is not its file's name");
        sess.sessionId = `${runId}/${key}`;
        plan.set(f, `${JSON.stringify(sess, null, 2)}\n`);
        kept.add(key);
        sessions.push(key);
      } catch (e) { notes.push(`${src.rel}/${f}: skipped (${e.message})`); }
    }
    for (const f of files) {
      if (/^sessions\//.test(f) && plan.has(f)) continue;
      const hit = RECORD_FILES.find(([re]) => re.test(f));
      if (!hit || hit[1] === "session") { if (!hit) notes.push(`${src.rel}/${f}: skipped (not a replay record file)`); continue; }
      const key = hit[0].exec(f)[1];
      if (!kept.has(key)) { notes.push(`${src.rel}/${f}: skipped (no session ${key} from this directory)`); continue; }
      if (plan.has(f)) { notes.push(`${src.rel}/${f}: skipped (a duplicate)`); continue; }
      const size = fs.lstatSync(path.join(src.dir, f)).size;
      if (size > MAX_RECORD_FILE_BYTES) { notes.push(`${src.rel}/${f}: skipped (over ${MAX_RECORD_FILE_BYTES} bytes)`); continue; }
      plan.set(f, { from: path.join(src.dir, f) });
    }
  }
  const dir = replaceDir(replayDir, runId, (tmp) => {
    writeNew(path.join(tmp, "run.json"), `${JSON.stringify(meta, null, 2)}\n`);
    for (const [rel, what] of plan) {
      const dst = path.join(tmp, ...rel.split("/"));
      if (typeof what === "string") writeNew(dst, what);
      else writeNew(dst, fs.readFileSync(what.from));
    }
  });
  let pruned = null;
  try {
    pruned = pruneReplayStore(replayDir, { keep: maxRuns, graceMs });
    for (const e of pruned.errors) notes.push(`retention: ${e}`);
  } catch (e) { notes.push(`retention: the replay store was not pruned (${e.message})`); }
  return { dir, sessions, notes, pruned };
}

/**
 * Is this a default-branch GitLab run, the only one whose baselines the host's
 * cache takes (test-reorganization.md §6.3; decision 1 of step 3)? Read from
 * the GitLab job's environment on the runner host (the host's, never the
 * guest's): a push or a schedule on the default branch, not a merge request
 * or a tag, and the run recorded with that ref and source gitlab.
 */
export function isDefaultBranchRun(env, { source, ref } = {}) {
  const branch = env.CI_DEFAULT_BRANCH;
  return source === "gitlab" && env.GITLAB_CI === "true" && !!branch &&
    ["push", "schedule"].includes(env.CI_PIPELINE_SOURCE) &&
    env.CI_COMMIT_BRANCH === branch && ref === branch &&
    !env.CI_MERGE_REQUEST_IID && !env.CI_COMMIT_TAG;
}

// ── the stale-statusline guard (continuous-integration.md §6) ──────────────
// The differential harness's fixture config prints a status line row
//   sl p<P>/d<D> m<M> | <model> | <cwd> | <git|nogit> | +<added> -<removed>
// (its statusline.sh: P prompts submitted, D turns finished, M the MCP
// handshake), and before each turn checkpoint (and the resize checkpoint
// after it) the driver waits for the row to read `sl p<k>/d<k>` after turn k
// (differential-profiles.ts fixtureStatuslineReady). A wait that runs out
// captures the screen as it is. When both sides run out with the same stale
// row, screen parity agrees and the run passes, and promoting its plain side
// would freeze a stale screen into the control every later replay is graded
// against. A passing run's Mandu side matched its plain side, so the plain
// side alone, which is what a baseline holds, says it: a promoted baseline's
// waited checkpoints that show a fixture row must show the expected one.
// A screen with no fixture row (a developer's config, a drill replay, a
// screen a dialog covers) is not judged; the differential lane's own
// assertion fails a side whose row never shows `m1`.

/** The env twin of --allow-stale-statusline (read on the host, the GitLab
 *  job's, never the guest's). */
export const ALLOW_STALE_ENV = "MANDU_CI_ALLOW_STALE_STATUSLINE";
/** The checkpoint kinds the driver's wait covers (a `dialog` screen has no
 *  status line; the `quit` capture is not waited for). */
export const WAITED_CHECKPOINT_KINDS = Object.freeze(["turn", "resize"]);
const STATUS_ROW_RE = /(?:^|\s)sl p(\d{1,6})\/d(\d{1,6}) m\d+(?=\s|$)/gm;

/** The fixture status line rows a screen shows: [{prompts, done}], in order. */
export function statusRows(text) {
  return [...String(text).matchAll(STATUS_ROW_RE)].map((m) => ({ prompts: Number(m[1]), done: Number(m[2]) }));
}

/**
 * staleStatusline(baseline) → [{checkpoint, turn, kind, shown, expected}]:
 * each waited checkpoint (WAITED_CHECKPOINT_KINDS, by `side.checkpointMarks`;
 * `turn` 0-based) whose screen shows a fixture status line row and none
 * reading `sl p<turn+1>/d<turn+1>`, the marker the driver waited for.
 * `shown` lists the rows it shows. Empty for a fresh baseline, one without
 * fixture rows, and one whose checkpoints or marks are not arrays.
 */
export function staleStatusline(baseline) {
  const screens = isObj(baseline) ? baseline.checkpoints : null;
  const marks = isObj(baseline) && isObj(baseline.side) ? baseline.side.checkpointMarks : null;
  if (!Array.isArray(screens) || !Array.isArray(marks)) return [];
  const out = [];
  screens.forEach((screen, i) => {
    const m = marks[i];
    if (!isObj(m) || !WAITED_CHECKPOINT_KINDS.includes(m.kind) || !Number.isSafeInteger(m.turn) || m.turn < 0) return;
    if (!Array.isArray(screen) || !screen.every((l) => typeof l === "string")) return;
    const rows = statusRows(screen.join("\n"));
    const n = m.turn + 1;
    if (!rows.length || rows.some((r) => r.prompts === n && r.done === n)) return;
    out.push({ checkpoint: i, turn: m.turn, kind: m.kind, shown: rows.map((r) => `sl p${r.prompts}/d${r.done}`), expected: `sl p${n}/d${n}` });
  });
  return out;
}

/** One line for a note: the first stale checkpoint, and how many more. */
export function describeStale(stale) {
  if (!stale.length) return "";
  const s = stale[0];
  const more = stale.length > 1 ? `, and ${stale.length - 1} more checkpoint(s)` : "";
  return `a stale statusline: checkpoint ${s.checkpoint} (turn ${s.turn + 1}, ${s.kind}) shows ${s.shown.join(", ")}, not ${s.expected}${more}`;
}

/**
 * parseAllowStale(value) → { allow, error? }: --allow-stale-statusline's (or
 * ALLOW_STALE_ENV's) value. Unset or empty: allow null (refuse every stale
 * baseline). `all`: every one. Else a comma list of baseline keys, each a
 * BASELINE_KEY_RE. A malformed value allows nothing and says why: a typo
 * must never promote what the guard refused.
 */
export function parseAllowStale(value) {
  if (value === undefined || value === null) return { allow: null };
  const v = String(value).trim();
  if (v === "") return { allow: null };
  if (v === "all") return { allow: "all" };
  const keys = v.split(",").map((k) => k.trim()).filter((k) => k !== "");
  const bad = keys.find((k) => !BASELINE_KEY_RE.test(k));
  if (bad !== undefined || !keys.length) {
    return { allow: null, error: `--allow-stale-statusline / ${ALLOW_STALE_ENV}: ${cleanText(bad ?? v, 200)} is not a baseline key or "all"; no stale baseline is promoted` };
  }
  return { allow: new Set(keys) };
}

/**
 * promoteBaselines(tree, {baselinesDir, maxBaselines, allowStale}) →
 * { promoted, notes, stale }.
 * Each baseline directory of tree/drills/baselines (holding baseline.json,
 * BASELINE_FILES only, each a file under MAX_RECORD_FILE_BYTES, baseline.json
 * a JSON object of kind "mandu-replay-baseline" whose key is the directory's
 * name, a BASELINE_KEY_RE) replaces baselinesDir/<key>/; a key two
 * directories both hold keeps the first. A baseline that shows a stale
 * statusline (staleStatusline) is refused, its key listed in `stale`, unless
 * `allowStale` (parseAllowStale's `allow`: "all" or a Set of keys) names it,
 * which a note records. The cache's loader re-checks every
 * field before it uses an entry (baseline-cache.ts loadBaseline). The caller decides whether
 * this run may promote (isDefaultBranchRun and a passing run).
 */
export function promoteBaselines(tree, { baselinesDir, maxBaselines = MAX_BASELINES, allowStale = null }) {
  const notes = [];
  const promoted = [];
  const staleKeys = [];
  for (const src of recordDirs(path.join(tree, "drills", "baselines"), "baseline.json")) {
    const key = src.name;
    try {
      if (!BASELINE_KEY_RE.test(key)) throw new Error("not a baseline key");
      if (promoted.includes(key)) throw new Error("its key came from an earlier directory");
      const ents = fs.readdirSync(src.dir, { withFileTypes: true });
      for (const e of ents) {
        if (!e.isFile() || !BASELINE_FILES.includes(e.name)) throw new Error(`holds ${e.name}, which a baseline does not`);
        if (fs.lstatSync(path.join(src.dir, e.name)).size > MAX_RECORD_FILE_BYTES) throw new Error(`${e.name} is over ${MAX_RECORD_FILE_BYTES} bytes`);
      }
      const b = readJsonCapped(path.join(src.dir, "baseline.json"), MAX_RECORD_FILE_BYTES);
      if (b.kind !== "mandu-replay-baseline") throw new Error('baseline.json\'s kind is not "mandu-replay-baseline"');
      if (b.key !== key) throw new Error("baseline.json's key is not its directory's name");
      const stale = staleStatusline(b);
      if (stale.length) {
        if (!(allowStale === "all" || (allowStale instanceof Set && allowStale.has(key)))) {
          staleKeys.push(key);
          throw new Error(describeStale(stale));
        }
        notes.push(`${src.rel}: promoted with ${describeStale(stale)}, as --allow-stale-statusline asked`);
      }
      replaceDir(baselinesDir, key, (tmp) => {
        for (const e of ents) writeNew(path.join(tmp, e.name), fs.readFileSync(path.join(src.dir, e.name)));
      });
      promoted.push(key);
    } catch (e) { notes.push(`${src.rel}: not promoted (${e.message})`); }
  }
  if (promoted.length) pruneRuns(baselinesDir, maxBaselines, { marker: "baseline.json", nameRe: BASELINE_KEY_RE });
  return { promoted, notes, stale: staleKeys };
}


// ── the live-drill records (drills/live) ───────────────────────────────────
// One run directory of the live runner (drill-run.ts, the
// single writer), as the dashboard's watch store reads it
// (the developer view's drill-run-store.ts readRun): meta.json (an object with a
// startedAt), chapters.json and report.json (arrays), matrix.json (an
// object), and the files its file route serves (LIVE_RUN_FILE_RE, that
// file's RUN_FILE_RE; ci-collect-results.test.mjs checks the two agree);
// plus the EVENT LANES: `events-<session>.ndjson`, the event log of a session
// the run names, which pipeline.sh's collect_live took from the run's own
// arbiter (live-events.mjs) and the dashboard's CI live source reads
// (the developer view's ci-live-source.ts), never its file route.
// Everything else a run directory holds (the workspaces, the rest of the
// owned arbiter's work dir with its symbol DB, a private CODEX_HOME, the
// model captures) is never carried: pipeline.sh's collect_live copies the
// record files alone, and this copies them alone again.

/** the developer view's drill-run-store.ts RUN_ID_RE and RUN_FILE_RE. */
export const LIVE_RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$/;
export const LIVE_RUN_FILE_RE = /^(terminal-[a-z0-9-]+\.cast|browser-[a-z0-9-]+\.mp4|run\.log|report\.md|matrix\.json|[A-Za-z0-9]+-\d+\.pane\.txt|seed-[a-z0-9]+\.json)$/;
/** A live run's data files the dashboard's file route does not serve but a
 *  CI run brings back: a baseline's wire log (the neutral recorder's,
 *  credentials redacted, drill-runner.md §7.2) and the demo battery's
 *  comparison (§3.9), for the numbers lane (continuous-integration.md §9.9). */
export const LIVE_DATA_FILE_RE = /^(wire\.ndjson|compare\.md)$/;
/** An event log of a live run (live-events.mjs EVENTS_FILE_RE, the
 *  dashboard's ci-live-source.ts CI_EVENTS_FILE_RE) and a session id. */
export const LIVE_EVENTS_FILE_RE = EVENTS_FILE_RE;
export const LIVE_SESSION_ID_RE = SESSION_ID_RE;
/** The JSON record files and the shape each must parse to. */
const LIVE_JSON = { "meta.json": "object", "chapters.json": "array", "report.json": "array", "matrix.json": "object" };
/** drill-run-store.ts WATCH_JSON_MAX_BYTES: a larger JSON file is never read. */
export const LIVE_JSON_MAX_BYTES = 16 * 1024 * 1024;
/** The marker of a live run a CI run brought (the only ones pruned). */
export const LIVE_MARKER = "ci-run.json";

/** The host directory a guest's drill run lands in: `<CI run>.<drill run>`
 *  (a colon of the CI run id a dash), else a hash of the CI run id in its
 *  place when that is too long; null when neither is a run id. */
export function liveRunName(ciRun, name) {
  if (!LIVE_RUN_ID_RE.test(name)) return null;
  const plain = `${ciRun.replace(/:/g, "-")}.${name}`;
  if (LIVE_RUN_ID_RE.test(plain)) return plain;
  const hashed = `ci-${crypto.createHash("sha256").update(ciRun).digest("hex").slice(0, 12)}.${name}`;
  return LIVE_RUN_ID_RE.test(hashed) ? hashed : null;
}

/** A guest session's id on the host: namespaced by the CI run, as the run's
 *  name is (`<CI part>.<guest session>`). The guest's runner names a session
 *  `<drill run>-<key>`, so it becomes `<host run>-<key>`, the shape the
 *  dashboard reads a run's sessions by. Every private arbiter mints its own
 *  ids: two CI runs' sessions (or a CI run's and the host's) would otherwise
 *  share one, and one run's trace would show under another's verdict
 *  (test-reorganization.md §7.3). Null when the result is not a session id. */
export function liveSessionName(hostRun, guestRun, session) {
  if (!SESSION_ID_RE.test(session) || !hostRun.endsWith(`.${guestRun}`)) return null;
  const ns = `${hostRun.slice(0, hostRun.length - guestRun.length - 1)}.${session}`;
  return SESSION_ID_RE.test(ns) ? ns : null;
}

/**
 * collectLive(tree, {runId, commit, liveDir, maxRuns}) → { runs, notes }.
 * Each run directory of tree/drills/live (one holding meta.json, at
 * drills/live/<run>/ or one level deeper) whose meta.json is an object with a
 * startedAt replaces liveDir/<liveRunName>/ with its record files: the JSON
 * ones that parse to their shape, under LIVE_JSON_MAX_BYTES, the others
 * LIVE_RUN_FILE_RE's and LIVE_DATA_FILE_RE's, under MAX_RECORD_FILE_BYTES, and the event log of each
 * session the run names (LIVE_EVENTS_FILE_RE, under MAX_RECORD_FILE_BYTES).
 * meta's runId becomes the host name, a status other than `done` or
 * `aborted` (a `running` one: the guest and its runner are gone) `aborted`,
 * and its pid 0; every session id the record names (meta.sessions, the
 * chapters' and report rows' scopeId) and each event log's name become the
 * host's (liveSessionName); ci-run.json records the CI run, its commit, the
 * guest's name and the guest's session ids. Written owner-only (0700 / 0600:
 * an event log holds originals). A name two directories both hold keeps the
 * first. With `pin` (a reason: a PINNED_JOBS job) each is pinned; one it
 * replaces keeps its pin either way. Prunes the marked directories to the
 * newest `maxRuns` unpinned ones.
 */
export function collectLive(tree, { runId, commit = null, liveDir, maxRuns = MAX_LIVE_RUNS, pin = null }) {
  const notes = [];
  const runs = [];
  for (const src of recordDirs(path.join(tree, "drills", "live"), "meta.json")) {
    try {
      const name = liveRunName(runId, src.name);
      if (!name) throw new Error("not a live run id");
      if (runs.includes(name)) throw new Error("a run of that name came from an earlier directory");
      const plan = new Map();
      const json = {};
      const events = [];
      for (const ent of fs.readdirSync(src.dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
        const f = path.join(src.dir, ent.name);
        const shape = LIVE_JSON[ent.name];
        const ev = ent.isFile() ? LIVE_EVENTS_FILE_RE.exec(ent.name) : null;
        if (!ent.isFile() || (!shape && !ev && !LIVE_RUN_FILE_RE.test(ent.name) && !LIVE_DATA_FILE_RE.test(ent.name))) { notes.push(`${src.rel}/${ent.name}: skipped (not a live record file)`); continue; }
        if (!shape) {
          if (fs.lstatSync(f).size > MAX_RECORD_FILE_BYTES) { notes.push(`${src.rel}/${ent.name}: skipped (over ${MAX_RECORD_FILE_BYTES} bytes)`); continue; }
          if (ev) events.push({ session: ev[1], from: f, rel: `${src.rel}/${ent.name}` });
          else plan.set(ent.name, { from: f });
          continue;
        }
        let v;
        try {
          if (fs.lstatSync(f).size > LIVE_JSON_MAX_BYTES) throw new Error(`over ${LIVE_JSON_MAX_BYTES} bytes`);
          v = JSON.parse(fs.readFileSync(f, "utf8"));
          if (shape === "array" ? !Array.isArray(v) : !isObj(v)) throw new Error(`not a JSON ${shape}`);
        } catch (e) {
          if (ent.name === "meta.json") throw new Error(`meta.json: ${e.message}`);
          notes.push(`${src.rel}/${ent.name}: skipped (${e.message})`);
          continue;
        }
        if (ent.name === "meta.json" && typeof v.startedAt !== "string") throw new Error("meta.json has no startedAt");
        json[ent.name] = v;
      }
      const meta = json["meta.json"];
      if (!meta) throw new Error("no meta.json file");
      meta.runId = name;
      if (!["done", "aborted"].includes(meta.status)) meta.status = "aborted";
      meta.pid = 0;
      // The sessions the record names, each by its host id.
      const sessions = {};
      const rename = (id) => {
        if (typeof id !== "string") return id;
        if (!(id in sessions)) sessions[id] = liveSessionName(name, src.name, id);
        return sessions[id] ?? id;
      };
      if (isObj(meta.sessions)) for (const k of Object.keys(meta.sessions)) meta.sessions[k] = rename(meta.sessions[k]);
      for (const f of ["chapters.json", "report.json"]) {
        for (const row of json[f] ?? []) if (isObj(row) && "scopeId" in row) row.scopeId = rename(row.scopeId);
      }
      for (const [f, v] of Object.entries(json)) plan.set(f, `${JSON.stringify(v, null, 2)}\n`);
      for (const e of events) {
        const host = sessions[e.session];
        if (!host) { notes.push(`${e.rel}: skipped (${e.session in sessions ? "its session has no host id" : "not a session the run names"})`); continue; }
        plan.set(`events-${host}.ndjson`, { from: e.from });
      }
      const named = Object.fromEntries(Object.entries(sessions).filter(([, v]) => v !== null));
      const marker = { kind: "mandu-ci-live-run", ciRun: runId, ...(commit && COMMIT_RE.test(commit) ? { commit } : {}), guestRun: src.name, sessions: named };
      replaceDir(liveDir, name, (tmp) => {
        for (const [rel, what] of plan) writeNew(path.join(tmp, rel), typeof what === "string" ? what : fs.readFileSync(what.from), 0o600);
        writeNew(path.join(tmp, LIVE_MARKER), `${JSON.stringify(marker, null, 2)}\n`, 0o600);
      }, { dirMode: 0o700, pin });
      runs.push(name);
    } catch (e) { notes.push(`${src.rel}: not copied (${e.message})`); }
  }
  if (runs.length) pruneLive(liveDir, maxRuns);
  return { runs, notes };
}

/** Keep the newest `maxRuns` of liveDir's directories that carry LIVE_MARKER
 *  (by its mtime); a directory without one is the host's own and stays, and
 *  a pinned one (isPinned) stays and does not count. */
export function pruneLive(liveDir, maxRuns = MAX_LIVE_RUNS) {
  const marked = [];
  for (const ent of fs.readdirSync(liveDir, { withFileTypes: true })) {
    if (!ent.isDirectory() || !LIVE_RUN_ID_RE.test(ent.name)) continue;
    const d = path.join(liveDir, ent.name);
    if (isPinned(d)) continue;
    try {
      const st = fs.lstatSync(path.join(d, LIVE_MARKER));
      if (st.isFile()) marked.push({ d, t: st.mtimeMs });
    } catch { /* the host's own run */ }
  }
  marked.sort((a, b) => b.t - a.t);
  for (const r of marked.slice(maxRuns)) fs.rmSync(r.d, { recursive: true, force: true });
  return marked.slice(maxRuns).map((r) => r.d);
}

/**
 * drillsReport(members, summary) → { members, bytes, dropped, warnings }: how
 * full drills/ came, from the archive's listing (members under drills/, the
 * directory itself included and drills/live left out, as tidy_drills counts
 * them), against the guest's caps; and whether the guest dropped it (the
 * stage `drills` is `skip`, which tidy_drills records). The archive's own
 * text is not read: the numbers are the host's, the flag a validated
 * summary's.
 */
export function drillsReport(members, summary) {
  const inLive = (p) => p === "drills/live" || p.startsWith("drills/live/");
  const ms = members.filter((m) => (m.path === "drills" || m.path.startsWith("drills/")) && !inLive(m.path));
  const bytes = ms.reduce((a, m) => a + m.size, 0);
  const dropped = summary?.stages?.drills?.result === "skip";
  const mib = (n) => `${Math.round(n / 1024 / 1024)} MiB`;
  const warnings = [];
  if (dropped) {
    warnings.push(`the guest DROPPED drills/ (the replay records and baselines): it was over its cap of ${DRILLS_MAX_MEMBERS} members or ${mib(DRILLS_MAX_BYTES)}; no replay record or baseline of this run is kept (logs/drills.log says how much it held)`);
  } else if (ms.length > DRILLS_MAX_MEMBERS * DRILLS_WARN_RATIO || bytes > DRILLS_MAX_BYTES * DRILLS_WARN_RATIO) {
    warnings.push(`drills/ is near its cap: ${ms.length} of ${DRILLS_MAX_MEMBERS} members, ${mib(bytes)} of ${mib(DRILLS_MAX_BYTES)}; past either the guest drops it whole (continuous-integration.md §6)`);
  }
  return { members: ms.length, bytes, dropped, warnings };
}

/**
 * liveReport(members, summary) → { members, bytes, dropped, warnings }: the
 * same for drills/live (the directory itself included, as collect_live counts
 * it) against LIVE_MAX_*, and the stage `drills-live: skip` collect_live
 * records when the record files alone were over them.
 */
export function liveReport(members, summary) {
  const ms = members.filter((m) => m.path === "drills/live" || m.path.startsWith("drills/live/"));
  const bytes = ms.reduce((a, m) => a + m.size, 0);
  const dropped = summary?.stages?.["drills-live"]?.result === "skip";
  const mib = (n) => `${Math.round(n / 1024 / 1024)} MiB`;
  const warnings = [];
  if (dropped) {
    warnings.push(`the guest DROPPED drills/live (the live-drill records): their record files alone were over its cap of ${LIVE_MAX_MEMBERS} members or ${mib(LIVE_MAX_BYTES)}; no live record of this run is kept (logs/drills.log says how much it held)`);
  } else if (ms.length > LIVE_MAX_MEMBERS * DRILLS_WARN_RATIO || bytes > LIVE_MAX_BYTES * DRILLS_WARN_RATIO) {
    warnings.push(`drills/live is near its cap: ${ms.length} of ${LIVE_MAX_MEMBERS} members, ${mib(bytes)} of ${mib(LIVE_MAX_BYTES)}; past either the guest trims the recordings, largest first (continuous-integration.md §6)`);
  }
  return { members: ms.length, bytes, dropped, warnings };
}

/** The drills/ stores collect() writes: the path table's rows, or with
 *  --runs-dir the same rows under that runs root (`ci-runs` is <root>/ci). */
function liveDirs(runsDir, given) {
  if (!given) return { ...defaultReplayDirs(), liveDir: defaultLiveDir() };
  const root = path.dirname(runsDir);
  return { replayDir: path.join(root, "drills", "replay"), baselinesDir: path.join(root, "drills", "baselines"), liveDir: path.join(root, "drills", "live") };
}

/**
 * collect(opts) → { result, dir, summary, error?, replay?, baselines?, drills?, live?, liveReport? }.
 * opts: archive, runId, source, commit, ref, image, started, error, console,
 * out, runsDir, maxRuns, replayDir, baselinesDir (default defaultReplayDirs),
 * maxReplayRuns (default: MANDU_REPLAY_KEEP_RUNS of opts.env, else MAX_REPLAY_RUNS), liveDir (default defaultLiveDir), maxLiveRuns, promote (may this run promote baselines: the CLI passes
 * isDefaultBranchRun of the job's environment; only a `pass` run does), only
 * (the job's suite selection, MANDU_CI_ONLY as the HOST set it: a PINNED_JOBS
 * job's run directory and live records are pinned as collected; `pinned` in
 * the result says so), allowStaleStatusline (--allow-stale-statusline's value,
 * else ALLOW_STALE_ENV of opts.env: the stale baselines a human promotes
 * anyway, parseAllowStale).
 */
export function collect(opts) {
  const runId = opts.runId;
  if (typeof runId !== "string" || !RUN_ID_RE.test(runId)) throw new Error(`bad --run-id: ${runId}`);
  const runsDir = opts.runsDir || defaultRunsDir();
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "mandu-ci-collect-"));
  const tree = path.join(work, "tree");
  fs.mkdirSync(tree, { mode: 0o755 });
  let summary, why = opts.error || null, listed = [];
  try {
    if (!why) {
      try {
        if (!opts.archive || !fs.existsSync(opts.archive)) throw new Error("no results archive");
        const { members } = listTar(opts.archive);
        listed = members;
        const sm = members.find((m) => m.path === "summary.json");
        if (!sm) throw new Error("no summary.json in the archive");
        if (sm.size > MAX_SUMMARY_BYTES) throw new Error("summary.json too large");
        extractTar(opts.archive, members, tree);
        let parsed;
        try { parsed = JSON.parse(fs.readFileSync(path.join(tree, "summary.json"), "utf8")); }
        catch (e) { throw new Error(`summary.json is not JSON: ${e.message}`); }
        const files = new Set(members.filter((m) => m.type === "file").map((m) => m.path));
        const errs = validateSummary(parsed, { files, dirName: runId });
        if (errs.length) throw new Error(`summary.json invalid: ${errs.slice(0, 10).join("; ")}`);
        if (parsed.run !== runId) throw new Error(`summary.json is for run ${parsed.run}, not ${runId}`);
        if (opts.commit && parsed.commit !== opts.commit) throw new Error(`summary.json names commit ${parsed.commit}, the job tested ${opts.commit}`);
        if (opts.image && parsed.image !== opts.image) throw new Error(`summary.json names image ${parsed.image}, the job booted ${opts.image}`);
        summary = parsed;
      } catch (e) {
        why = `unreadable results: ${e.message}`;
      }
    }
    if (why) {
      fs.rmSync(tree, { recursive: true, force: true });
      fs.mkdirSync(tree, { mode: 0o755 });
      summary = errorSummary({ ...opts, runId, error: why });
      fs.writeFileSync(path.join(tree, "summary.json"), JSON.stringify(summary, null, 2) + "\n", { mode: 0o644 });
    }
    if (opts.console && fs.existsSync(opts.console)) copyCapped(opts.console, path.join(tree, "console.log"), MAX_CONSOLE_BYTES);
    const job = pinnedJob(opts.only);
    const pin = job ? `the ${job} job's records: published evidence, kept until unpinned by hand` : null;
    const dir = publishRun(tree, runsDir, runId, opts.maxRuns ?? MAX_RUNS, pin);
    if (opts.out) {
      copyTree(tree, opts.out);
      // the live sessions' event logs hold originals: owner-only, as in the store
      ownerOnly(path.join(opts.out, "drills", "live"));
    }
    // The replay records and the baselines: never the run's result.
    let replay, baselines, drills, live, liveRep;
    if (!why) {
      drills = drillsReport(listed, summary);
      liveRep = liveReport(listed, summary);
      // The path table's rows; with --runs-dir (`ci-runs` is <runs root>/ci),
      // the same rows under that runs root, so --runs-dir moves all four.
      const def = liveDirs(runsDir, opts.runsDir);
      try {
        const fromEnv = keepRunsFromEnv(opts.env ?? process.env);
        replay = collectReplay(tree, { runId, commit: opts.commit, replayDir: opts.replayDir || def.replayDir, maxRuns: opts.maxReplayRuns ?? fromEnv.keep });
        if (fromEnv.error) replay.notes.push(`retention: ${fromEnv.error}`);
      } catch (e) { replay = { dir: null, sessions: [], notes: [`replay records not copied: ${e.message}`] }; }
      if (fs.existsSync(path.join(tree, "drills", "baselines"))) {
        const may = !opts.promote ? "not a default-branch GitLab run" : summary.result !== "pass" ? `the run is ${summary.result}` : null;
        if (may) baselines = { promoted: [], notes: [`baselines not promoted: ${may}`] };
        else {
          const allow = parseAllowStale(opts.allowStaleStatusline ?? (opts.env ?? process.env)[ALLOW_STALE_ENV]);
          try { baselines = promoteBaselines(tree, { baselinesDir: opts.baselinesDir || def.baselinesDir, allowStale: allow.allow }); }
          catch (e) { baselines = { promoted: [], notes: [`baselines not promoted: ${e.message}`], stale: [] }; }
          if (allow.error) baselines.notes.unshift(allow.error);
        }
      }
      if (fs.existsSync(path.join(tree, "drills", "live"))) {
        const liveDir = opts.liveDir || def.liveDir;
        try { live = { dir: liveDir, ...collectLive(tree, { runId, commit: opts.commit, liveDir, maxRuns: opts.maxLiveRuns ?? MAX_LIVE_RUNS, pin }) }; }
        catch (e) { live = { dir: liveDir, runs: [], notes: [`live records not copied: ${e.message}`] }; }
      }
    }
    return { result: summary.result, dir, summary, error: why || undefined, replay, baselines, drills, live, liveReport: liveRep, pinned: job };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

// ── CLI ────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const o = {};
  const map = { "--archive": "archive", "--run-id": "runId", "--source": "source", "--commit": "commit",
    "--ref": "ref", "--image": "image", "--started": "started", "--error": "error", "--console": "console",
    "--out": "out", "--runs-dir": "runsDir", "--replay-dir": "replayDir", "--baselines-dir": "baselinesDir", "--live-dir": "liveDir",
    "--only": "only", "--pin": "pin", "--unpin": "unpin", "--reason": "reason", "--allow-stale-statusline": "allowStaleStatusline" };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--pinned") { o.pinned = true; continue; }
    const k = map[argv[i]];
    if (!k || i + 1 >= argv.length) throw new Error(`unknown or incomplete option: ${argv[i]}`);
    o[k] = argv[++i];
  }
  const modes = ["pin", "unpin", "pinned"].filter((m) => o[m] !== undefined);
  if (modes.length > 1) throw new Error("--pin, --unpin and --pinned go alone");
  if (modes.length) o.mode = modes[0];
  else if (!o.runId) throw new Error("--run-id is required");
  return o;
}

/** --pin <CI run> [--reason TEXT], --unpin <CI run>, --pinned: by hand, on
 *  the path table's stores (or --runs-dir's, --live-dir). Exit 0, or 1 when
 *  --pin / --unpin found nothing of that run (its records are gone, or
 *  were never pinned). */
function pinCli(opts) {
  const runsDir = opts.runsDir || defaultRunsDir();
  const liveDir = opts.liveDir || liveDirs(runsDir, opts.runsDir).liveDir;
  if (opts.mode === "pinned") {
    const rows = listPinned({ runsDir, liveDir });
    for (const r of rows) console.log(`${r.ciRun}  summary ${r.ci ? "pinned" : "-"}  live ${r.live}  ${r.pinnedAt ?? "?"}  ${cleanText(r.reason ?? "", 200)}`);
    console.log(`collect-results: ${rows.length} pinned CI run(s) in ${runsDir} and ${liveDir}`);
    return 0;
  }
  const id = opts[opts.mode];
  const r = opts.mode === "pin" ? pinRun(id, { runsDir, liveDir, ...(opts.reason ? { reason: opts.reason } : {}) }) : unpinRun(id, { runsDir, liveDir });
  const verb = opts.mode === "pin" ? "pinned" : "unpinned";
  console.log(`collect-results: ${verb} ${id}: summary ${r.ci ? r.ci : "none"}; ${r.live.length} live run(s) in ${liveDir}`);
  for (const d of r.live) console.log(`  ${path.basename(d)}`);
  if (!r.ci && !r.live.length) {
    console.log(`collect-results: nothing of ${id} ${opts.mode === "pin" ? "is left to pin (its records are gone)" : "was pinned"}`);
    return 1;
  }
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); }
  catch (e) { console.error(`collect-results: ${e.message}`); process.exit(2); }
  if (opts.mode) {
    try { process.exit(pinCli(opts)); }
    catch (e) { console.error(`collect-results: ${e.message}`); process.exit(2); }
  }
  try {
    const r = collect({ ...opts, promote: isDefaultBranchRun(process.env, opts) });
    const s = r.summary;
    const counts = s.entries.reduce((a, e) => ({ pass: a.pass + e.pass, fail: a.fail + e.fail, skip: a.skip + e.skip }), { pass: 0, fail: 0, skip: 0 });
    console.log(`collect-results: run ${s.run}: ${s.result}${r.error ? ` (${r.error})` : ""}; ${s.entries.length} entries, ${counts.pass} passed, ${counts.fail} failed, ${counts.skip} skipped`);
    for (const e of s.entries) if (e.result !== "pass" && e.result !== "skip") console.log(`  ${e.result.toUpperCase()}  ${e.id} (${e.kind})${e.log ? `  ${path.join(r.dir, e.log)}` : ""}`);
    console.log(`collect-results: results in ${r.dir}${opts.out ? ` and ${opts.out}` : ""}`);
    if (r.drills && (r.drills.members || r.drills.dropped)) console.log(`collect-results: drills/: ${r.drills.members} members, ${r.drills.bytes} bytes (the guest's cap: ${DRILLS_MAX_MEMBERS} members, ${DRILLS_MAX_BYTES} bytes)`);
    for (const w of r.drills?.warnings ?? []) console.log(`collect-results: WARNING: ${w}`);
    if (r.liveReport && (r.liveReport.members || r.liveReport.dropped)) console.log(`collect-results: drills/live: ${r.liveReport.members} members, ${r.liveReport.bytes} bytes (the guest's cap: ${LIVE_MAX_MEMBERS} members, ${LIVE_MAX_BYTES} bytes)`);
    for (const w of r.liveReport?.warnings ?? []) console.log(`collect-results: WARNING: ${w}`);
    if (r.replay?.dir) console.log(`collect-results: replay records (${r.replay.sessions.length} sessions) in ${r.replay.dir}`);
    const pr = r.replay?.pruned;
    if (pr && (pr.deleted.length || pr.stale.length)) console.log(`collect-results: replay store retention: kept ${pr.kept.length} runs (keep ${pr.keep}), deleted ${pr.deleted.length} runs and ${pr.stale.length} stale staging directories, ${formatBytes(pr.bytesFreed)}`);
    if (r.baselines?.promoted.length) console.log(`collect-results: baselines promoted: ${r.baselines.promoted.join(", ")}`);
    if (r.baselines?.stale?.length) {
      console.log(`collect-results: WARNING: ${r.baselines.stale.length} baseline(s) not promoted: the plain side shows a stale statusline, which screen parity cannot see when the Mandu side shows the same (their notes below): ${r.baselines.stale.join(", ")}`);
      console.log(`collect-results: to promote one anyway: --allow-stale-statusline KEY[,KEY...] (or all), or ${ALLOW_STALE_ENV} in the job's environment`);
    }
    if (r.live?.runs.length) console.log(`collect-results: live-drill records (${r.live.runs.length} runs: ${r.live.runs.join(", ")}) in ${r.live.dir}`);
    if (r.pinned) console.log(`collect-results: PINNED (${r.pinned} job: never pruned): the run directory${r.live?.runs.length ? ` and its ${r.live.runs.length} live runs` : ""}; \`--unpin ${s.run}\` releases them`);
    for (const n of [...(r.replay?.notes ?? []), ...(r.baselines?.notes ?? []), ...(r.live?.notes ?? [])].slice(0, 50)) console.log(`  drills: ${cleanText(n, 300)}`);
    process.exit(s.result === "pass" ? 0 : s.result === "fail" ? 1 : 2);
  } catch (e) {
    console.error(`collect-results: ${e.stack || e.message}`);
    process.exit(2);
  }
}
