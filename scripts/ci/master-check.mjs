#!/usr/bin/env node
// scripts/ci/master-check.mjs — the hourly master check's two steps on the
// runner host (docs/design/testing/continuous-integration.md §7.1). The `test`
// job in .gitlab-ci.yml calls it before and after vm-run.sh; it runs nothing
// from the commit's tests and reads no credential but the job's own token.
//
//   node scripts/ci/master-check.mjs skip
//       In the master check's scheduled pipeline (MANDU_SCHEDULE=master-check):
//       exit 0 when this host already holds a finished test (pass or fail) of
//       the commit under test, after renaming the pipeline
//       "master-check: skipped, …" (PUT pipelines/:id/metadata, which the job
//       token may call); the job then ends. Any other exit, or a crash, means
//       "run the test": a commit not tested here, no state, a rename GitLab
//       refused. Fail-safe: it never skips a commit it cannot show was tested.
//
//   node scripts/ci/master-check.mjs record --rc N --summary FILE
//       After vm-run.sh in a master pipeline (a push to the default branch, or
//       the master check): remember that the commit's full test finished, when
//       vm-run.sh exited 0 (pass) or 1 (fail) and the run's summary agrees
//       (same commit, same result). An error (the guest broke, a timeout) or a
//       cancel records nothing, so the next check tests the commit again.
//       Always exits 0: recording never changes the job's verdict.
//
// Why: master pushes are interruptible, so a run of fast merges cancels each
// master pipeline before its `test` finishes (on 2026-10-17, twenty in a row);
// the hourly check is the run nothing cancels, and it costs a guest only when
// master has moved since the last finished test.
//
// The state is one JSON file per runner host, MANDU_CI_MASTER_STATE or the
// path table's `ci-cache` dir + master-tested.json (regenerable: losing it
// costs one redundant run). Another host's tests are not in it, so with
// several runner hosts a check can test a commit another host already tested;
// it never skips one no host tested.

import fs from "node:fs";
import os from "node:os";
import path, { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { resolvePath } from "../paths/mandu-paths.mjs";

/** The schedule variable that marks the master check's pipeline schedule. */
export const SCHEDULE = "master-check";
/** The name a skipped check's pipeline gets; a reader of master's pipelines passes over it (§7.1). */
export const SKIPPED_PREFIX = "master-check: skipped";
/** How many tested commits the state keeps. */
export const KEEP = 50;
const SHA_RE = /^[0-9a-f]{40}$/;

export function statePath(env = process.env) {
  if (env.MANDU_CI_MASTER_STATE) return env.MANDU_CI_MASTER_STATE;
  return path.join(resolvePath("ci-cache", env, env.HOME || os.homedir()), "master-tested.json");
}

/** The state's tested commits, newest first; an absent or broken file is none. */
export function readState(file) {
  try {
    const s = JSON.parse(fs.readFileSync(file, "utf8"));
    const tested = Array.isArray(s?.tested) ? s.tested : [];
    return { schema: 1, tested: tested.filter((e) => e && SHA_RE.test(e.sha) && ["pass", "fail"].includes(e.result)) };
  } catch { return { schema: 1, tested: [] }; }
}

/** Write atomically (temp file + rename), so a reader never sees half a file. */
export function writeState(file, state) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o644 });
  fs.renameSync(tmp, file);
}

/** The state with `entry` first (an older entry for the same commit dropped), at most `keep`. Pure. */
export function addTested(state, entry, keep = KEEP) {
  return { schema: 1, tested: [entry, ...state.tested.filter((e) => e.sha !== entry.sha)].slice(0, keep) };
}

/** Is this the master check's scheduled pipeline, on the default branch? */
export function isMasterCheck(env) {
  return env.GITLAB_CI === "true" && env.CI_PIPELINE_SOURCE === "schedule" && env.MANDU_SCHEDULE === SCHEDULE &&
    !!env.CI_DEFAULT_BRANCH && env.CI_COMMIT_BRANCH === env.CI_DEFAULT_BRANCH && !env.CI_COMMIT_TAG;
}

/** Is this a master pipeline whose `test` runs the full per-push selection (a push to the default branch, or the check)? */
export function isMasterRun(env) {
  if (isMasterCheck(env)) return true;
  return env.GITLAB_CI === "true" && env.CI_PIPELINE_SOURCE === "push" && !!env.CI_DEFAULT_BRANCH &&
    env.CI_COMMIT_BRANCH === env.CI_DEFAULT_BRANCH && !env.CI_COMMIT_TAG && !env.CI_MERGE_REQUEST_IID;
}

/** The finished test of `sha` this host holds, or null. Pure. */
export function testedEntry(state, sha) {
  return state.tested.find((e) => e.sha === sha) ?? null;
}

/** "12 min ago" / "3 h ago" / "2 d ago"; "" without a time. Pure. */
export function ago(iso, now = Date.now()) {
  const t = Date.parse(iso ?? "");
  if (!Number.isFinite(t)) return "";
  const min = Math.max(0, Math.round((now - t) / 60000));
  if (min < 90) return `${min} min ago`;
  const h = Math.round(min / 60);
  return h < 48 ? `${h} h ago` : `${Math.round(h / 24)} d ago`;
}

/** The skipped pipeline's name. Pure. */
export function skippedName(sha, entry) {
  return `${SKIPPED_PREFIX}, ${sha.slice(0, 8)} already tested in #${entry.pipeline} (${entry.result})`;
}

/** Rename this pipeline through the job token; true on a 2xx. */
async function renamePipeline(env, name, fetchImpl) {
  const { CI_API_V4_URL: api, CI_PROJECT_ID: project, CI_PIPELINE_ID: pipeline, CI_JOB_TOKEN: token } = env;
  if (!api || !project || !pipeline || !token) return { ok: false, why: "no CI_API_V4_URL / CI_PROJECT_ID / CI_PIPELINE_ID / CI_JOB_TOKEN" };
  try {
    const r = await fetchImpl(`${api}/projects/${encodeURIComponent(project)}/pipelines/${encodeURIComponent(pipeline)}/metadata`, {
      method: "PUT",
      headers: { "JOB-TOKEN": token, "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
      signal: AbortSignal.timeout(20000),
    });
    return r.ok ? { ok: true } : { ok: false, why: `GitLab answered HTTP ${r.status}` };
  } catch (e) { return { ok: false, why: `the request failed (${e?.name ?? "error"})` }; }
}

/** `skip`: 0 = skipped (the job ends), 1 = test. */
export async function skip(env = process.env, { fetchImpl = fetch, now = Date.now(), log = (s) => process.stdout.write(`master-check: ${s}\n`) } = {}) {
  if (!isMasterCheck(env)) { log("not the master check's scheduled pipeline: testing"); return 1; }
  const sha = env.CI_COMMIT_SHA ?? "";
  if (!SHA_RE.test(sha)) { log(`no commit id in CI_COMMIT_SHA: testing`); return 1; }
  const state = readState(statePath(env));
  const hit = testedEntry(state, sha);
  if (!hit) {
    const last = state.tested[0];
    log(`${sha.slice(0, 8)} has no finished test on this host${last ? ` (the newest: ${last.sha.slice(0, 8)} in #${last.pipeline}, ${last.result}, ${ago(last.at, now)})` : ""}: testing it`);
    return 1;
  }
  const r = await renamePipeline(env, skippedName(sha, hit), fetchImpl);
  if (!r.ok) { log(`master has not moved since #${hit.pipeline}, but the pipeline could not be marked skipped (${r.why}): testing anyway`); return 1; }
  log(`master has not moved since #${hit.pipeline} tested ${sha.slice(0, 8)} (${hit.result}, ${ago(hit.at, now)}): skipped`);
  return 0;
}

/** `record`: always 0. */
export function record(env = process.env, { rc, summary, now = Date.now(), log = (s) => process.stdout.write(`master-check: ${s}\n`) } = {}) {
  if (!isMasterRun(env)) return 0; // an MR or a tag: nothing to remember
  const sha = env.CI_COMMIT_SHA ?? "";
  const result = rc === 0 ? "pass" : rc === 1 ? "fail" : null;
  if (!SHA_RE.test(sha) || !result) { log(`vm-run.sh exited ${rc}: no finished test to record`); return 0; }
  let s = null;
  try { s = JSON.parse(fs.readFileSync(summary, "utf8")); } catch { /* checked below */ }
  const commit = typeof s?.commit === "string" ? s.commit : "";
  if (!s || s.result !== result || commit.length < 7 || !sha.startsWith(commit)) {
    log(`the run's summary does not show a ${result} of ${sha.slice(0, 8)}: nothing recorded`);
    return 0;
  }
  const file = statePath(env);
  try {
    writeState(file, addTested(readState(file), {
      sha, result, pipeline: Number(env.CI_PIPELINE_ID) || null, job: Number(env.CI_JOB_ID) || null,
      source: env.CI_PIPELINE_SOURCE, at: new Date(now).toISOString(),
    }));
    log(`recorded ${sha.slice(0, 8)} (${result}) as tested`);
  } catch (e) { log(`could not write ${file}: ${e.message}`); }
  return 0;
}

export async function main(argv = process.argv.slice(2), env = process.env) {
  const [cmd, ...rest] = argv;
  if (cmd === "skip" && rest.length === 0) return skip(env);
  if (cmd === "record") {
    const opt = {};
    for (let i = 0; i < rest.length; i += 2) {
      if (rest[i] === "--rc" && /^\d+$/.test(rest[i + 1] ?? "")) opt.rc = Number(rest[i + 1]);
      else if (rest[i] === "--summary" && rest[i + 1]) opt.summary = rest[i + 1];
      else { process.stderr.write(`master-check: record: unknown or bad argument ${rest[i]}\n`); return 2; }
    }
    if (opt.rc === undefined || !opt.summary) { process.stderr.write("master-check: record needs --rc N --summary FILE\n"); return 2; }
    return record(env, opt);
  }
  process.stderr.write("usage: master-check.mjs skip | record --rc N --summary FILE\n");
  return 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(isAbsolute(process.argv[1]) ? process.argv[1] : resolve(process.argv[1])).href) {
  process.exitCode = await main();
}
