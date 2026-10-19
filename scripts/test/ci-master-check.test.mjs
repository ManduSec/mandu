// ci-master-check.test.mjs — the hourly master check's host-side steps
// (scripts/ci/master-check.mjs, docs/design/testing/continuous-integration.md
// §7.1): `record` remembers only a master pipeline's finished full test (pass
// or fail, the summary agreeing), `skip` ends the check only for a commit this
// host holds a finished test of AND only once GitLab took the pipeline's
// "skipped" name; every doubt is "test". The CLI runs against a stand-in
// GitLab on 127.0.0.1 (the PUT the job token makes). No network, no privilege.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { KEEP, SKIPPED_PREFIX, addTested, ago, isMasterCheck, isMasterRun, readState, record, skip, skippedName, statePath, testedEntry } from "../ci/master-check.mjs";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "..", "ci", "master-check.mjs");
const SHA = "b3a6b3fe1e50368f458cda3a4fda19a4b3f2b246";
const OTHER = "1d7b4a98620eb377d638cfc4116942ebeb34e9b3";
const BASE = { GITLAB_CI: "true", CI_DEFAULT_BRANCH: "master", CI_COMMIT_BRANCH: "master", CI_COMMIT_SHA: SHA, CI_PIPELINE_ID: "11800", CI_JOB_ID: "13001" };
const CHECK = { ...BASE, CI_PIPELINE_SOURCE: "schedule", MANDU_SCHEDULE: "master-check" };
const PUSH = { ...BASE, CI_PIPELINE_SOURCE: "push" };
const quiet = () => {};

function tmp() {
  const d = mkdtempSync(join(tmpdir(), "master-check-"));
  return { d, state: join(d, "state", "master-tested.json"), done: () => rmSync(d, { recursive: true, force: true }) };
}
function summary(dir, o) { const f = join(dir, "summary.json"); writeFileSync(f, JSON.stringify({ schema: 1, kind: "mandu-ci-run", ...o })); return f; }

test("which pipelines are the check, and which record a finished test", () => {
  assert.equal(isMasterCheck(CHECK), true);
  assert.equal(isMasterCheck({ ...CHECK, MANDU_SCHEDULE: undefined }), false, "the nightly's schedule");
  assert.equal(isMasterCheck({ ...CHECK, CI_COMMIT_BRANCH: "feat/x" }), false, "a schedule on another branch");
  assert.equal(isMasterCheck({ ...CHECK, GITLAB_CI: undefined }), false, "not in GitLab");
  assert.equal(isMasterRun(CHECK), true);
  assert.equal(isMasterRun(PUSH), true);
  assert.equal(isMasterRun({ ...PUSH, CI_PIPELINE_SOURCE: "merge_request_event", CI_MERGE_REQUEST_IID: "7" }), false, "an MR");
  assert.equal(isMasterRun({ ...PUSH, CI_COMMIT_BRANCH: undefined, CI_COMMIT_TAG: "v1.0.0" }), false, "a tag");
  assert.equal(isMasterRun({ ...PUSH, CI_COMMIT_BRANCH: "feat/x" }), false, "a branch push");
  assert.equal(isMasterRun({ ...CHECK, MANDU_SCHEDULE: undefined }), false, "the nightly");
});

test("the state: newest first, one entry per commit, capped; a broken file is empty", () => {
  let s = { schema: 1, tested: [] };
  s = addTested(s, { sha: OTHER, result: "fail", pipeline: 1 });
  s = addTested(s, { sha: SHA, result: "pass", pipeline: 2 });
  s = addTested(s, { sha: OTHER, result: "pass", pipeline: 3 });
  assert.deepEqual(s.tested.map((e) => [e.sha, e.pipeline]), [[OTHER, 3], [SHA, 2]]);
  assert.equal(testedEntry(s, SHA).pipeline, 2);
  assert.equal(testedEntry(s, "f".repeat(40)), null);
  let big = { schema: 1, tested: [] };
  for (let i = 0; i < KEEP + 5; i++) big = addTested(big, { sha: i.toString(16).padStart(40, "0"), result: "pass", pipeline: i });
  assert.equal(big.tested.length, KEEP);
  const t = tmp();
  try {
    assert.deepEqual(readState(t.state), { schema: 1, tested: [] }, "no file");
    writeFileSync(join(t.d, "bad.json"), "{not json");
    assert.deepEqual(readState(join(t.d, "bad.json")).tested, []);
    writeFileSync(join(t.d, "junk.json"), JSON.stringify({ tested: [{ sha: "x", result: "pass" }, { sha: SHA, result: "error" }, { sha: SHA, result: "fail" }] }));
    assert.deepEqual(readState(join(t.d, "junk.json")).tested.map((e) => e.result), ["fail"], "only well-formed pass/fail entries");
  } finally { t.done(); }
  assert.match(statePath({ HOME: "/h" }), /^\/h\/.+\/master-tested\.json$/);
  assert.equal(statePath({ MANDU_CI_MASTER_STATE: "/x/s.json" }), "/x/s.json");
});

test("record: a master pipeline's pass or fail, the summary agreeing; never an error, an MR, or a mismatch", () => {
  const t = tmp();
  try {
    const env = { ...PUSH, MANDU_CI_MASTER_STATE: t.state };
    const now = Date.parse("2026-10-18T01:00:00Z");
    assert.equal(record(env, { rc: 1, summary: summary(t.d, { commit: SHA, result: "fail" }), now, log: quiet }), 0);
    assert.deepEqual(readState(t.state).tested, [{ sha: SHA, result: "fail", pipeline: 11800, job: 13001, source: "push", at: "2026-10-18T01:00:00.000Z" }]);
    // the check's own run, a pass, replaces the entry
    record({ ...CHECK, MANDU_CI_MASTER_STATE: t.state, CI_PIPELINE_ID: "11810" }, { rc: 0, summary: summary(t.d, { commit: SHA, result: "pass" }), now, log: quiet });
    assert.deepEqual(readState(t.state).tested.map((e) => [e.result, e.pipeline, e.source]), [["pass", 11810, "schedule"]]);
    const before = readFileSync(t.state, "utf8");
    const none = [
      [env, 2, { commit: OTHER, result: "error" }, "vm-run's error (the guest broke, a timeout)"],
      [env, 0, { commit: OTHER, result: "fail" }, "the summary disagrees with the exit code"],
      [{ ...env, CI_COMMIT_SHA: OTHER }, 0, { commit: SHA, result: "pass" }, "the summary is another commit's"],
      [{ ...env, CI_COMMIT_SHA: OTHER }, 0, { commit: "", result: "pass" }, "no commit in the summary"],
      [{ ...env, CI_PIPELINE_SOURCE: "merge_request_event", CI_MERGE_REQUEST_IID: "9", CI_COMMIT_SHA: OTHER }, 0, { commit: OTHER, result: "pass" }, "an MR"],
      [{ ...env, CI_PIPELINE_SOURCE: "schedule", CI_COMMIT_SHA: OTHER }, 0, { commit: OTHER, result: "pass" }, "the nightly"],
    ];
    for (const [e, rc, s, why] of none) {
      assert.equal(record(e, { rc, summary: summary(t.d, s), now, log: quiet }), 0, why);
      assert.equal(readFileSync(t.state, "utf8"), before, why);
    }
    assert.equal(record({ ...env, CI_COMMIT_SHA: OTHER }, { rc: 0, summary: join(t.d, "missing.json"), log: quiet }), 0, "no summary");
    assert.equal(readFileSync(t.state, "utf8"), before);
    // an abbreviated commit id in the summary still matches
    record({ ...env, CI_COMMIT_SHA: OTHER }, { rc: 0, summary: summary(t.d, { commit: OTHER.slice(0, 12), result: "pass" }), now, log: quiet });
    assert.deepEqual(readState(t.state).tested.map((e) => e.sha), [OTHER, SHA]);
  } finally { t.done(); }
});

test("skip: only for a commit this host tested, and only once GitLab took the skipped name", async () => {
  const t = tmp();
  try {
    const env = { ...CHECK, MANDU_CI_MASTER_STATE: t.state, CI_API_V4_URL: "https://gitlab.test/api/v4", CI_PROJECT_ID: "411", CI_JOB_TOKEN: "tok" };
    const calls = [];
    const ok = async (url, init) => { calls.push({ url, init }); return { ok: true, status: 200 }; };
    const lines = [];
    const log = (s) => lines.push(s);
    // no state: test
    assert.equal(await skip(env, { fetchImpl: ok, log }), 1);
    assert.equal(calls.length, 0);
    assert.match(lines.pop(), /b3a6b3fe has no finished test on this host: testing it/);
    // another commit tested: test, naming the newest
    record({ ...PUSH, MANDU_CI_MASTER_STATE: t.state, CI_COMMIT_SHA: OTHER, CI_PIPELINE_ID: "11769" }, { rc: 0, summary: summary(t.d, { commit: OTHER, result: "pass" }), log: quiet });
    assert.equal(await skip(env, { fetchImpl: ok, log }), 1);
    assert.match(lines.pop(), /has no finished test on this host \(the newest: 1d7b4a98 in #11769, pass, \d+ min ago\): testing it/);
    // this commit tested (failed): skip, renaming the pipeline through the job token
    record({ ...PUSH, MANDU_CI_MASTER_STATE: t.state, CI_PIPELINE_ID: "11771" }, { rc: 1, summary: summary(t.d, { commit: SHA, result: "fail" }), log: quiet });
    assert.equal(await skip(env, { fetchImpl: ok, log }), 0);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://gitlab.test/api/v4/projects/411/pipelines/11800/metadata");
    assert.equal(calls[0].init.method, "PUT");
    assert.equal(calls[0].init.headers["JOB-TOKEN"], "tok");
    assert.deepEqual(JSON.parse(calls[0].init.body), { name: "master-check: skipped, b3a6b3fe already tested in #11771 (fail)" });
    assert.match(lines.pop(), /master has not moved since #11771 tested b3a6b3fe \(fail, \d+ min ago\): skipped/);
    // GitLab refusing the name, or not answering, or no token: test anyway
    assert.equal(await skip(env, { fetchImpl: async () => ({ ok: false, status: 403 }), log }), 1);
    assert.match(lines.pop(), /could not be marked skipped \(GitLab answered HTTP 403\): testing anyway/);
    assert.equal(await skip(env, { fetchImpl: async () => { throw new TypeError("fetch failed"); }, log }), 1);
    assert.equal(await skip({ ...env, CI_JOB_TOKEN: "" }, { fetchImpl: ok, log }), 1);
    // not the check's pipeline, or no commit id: test
    assert.equal(await skip({ ...env, MANDU_SCHEDULE: "" }, { fetchImpl: ok, log }), 1);
    assert.equal(await skip({ ...env, CI_COMMIT_SHA: "HEAD" }, { fetchImpl: ok, log }), 1);
    assert.equal(calls.length, 1, "only the one skip renamed the pipeline");
    assert.doesNotMatch(lines.join("\n"), /tok/, "the token is never printed");
  } finally { t.done(); }
});

test("the skipped name starts with the prefix a reader of the pipeline list passes over; ages read in min, h, d", () => {
  assert.ok(skippedName(SHA, { pipeline: 5, result: "pass" }).startsWith(`${SKIPPED_PREFIX}, `));
  const now = Date.parse("2026-10-18T12:00:00Z");
  assert.equal(ago("2026-10-18T11:48:00Z", now), "12 min ago");
  assert.equal(ago("2026-10-18T09:00:00Z", now), "3 h ago");
  assert.equal(ago("2026-10-15T12:00:00Z", now), "3 d ago");
  assert.equal(ago(undefined, now), "");
});

// ── the CLI, against a stand-in GitLab on 127.0.0.1 ─────────────────────────
function cli(args, env) {
  return new Promise((res) => {
    const c = spawn(process.execPath, [SCRIPT, ...args], { env: { PATH: process.env.PATH, ...env } });
    let out = "", err = "";
    c.stdout.on("data", (b) => { out += b; });
    c.stderr.on("data", (b) => { err += b; });
    c.on("close", (code) => res({ code, out, err }));
  });
}

test("cli: record then skip, the PUT reaching GitLab with the job token; usage errors exit 2", async () => {
  const t = tmp();
  const seen = [];
  const srv = createServer((req, res) => {
    let body = "";
    req.on("data", (b) => { body += b; });
    req.on("end", () => { seen.push({ method: req.method, url: req.url, token: req.headers["job-token"], body }); res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  try {
    const api = `http://127.0.0.1:${srv.address().port}/api/v4`;
    const env = { ...CHECK, MANDU_CI_MASTER_STATE: t.state, CI_API_V4_URL: api, CI_PROJECT_ID: "411", CI_JOB_TOKEN: "job-tok" };
    let r = await cli(["skip"], env);
    assert.equal(r.code, 1, r.err);
    r = await cli(["record", "--rc", "0", "--summary", summary(t.d, { commit: SHA, result: "pass" })], env);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /recorded b3a6b3fe \(pass\)/);
    r = await cli(["skip"], env);
    assert.equal(r.code, 0, r.err + r.out);
    assert.deepEqual(seen.map((s) => [s.method, s.url, s.token]), [["PUT", "/api/v4/projects/411/pipelines/11800/metadata", "job-tok"]]);
    assert.match(JSON.parse(seen[0].body).name, /^master-check: skipped, b3a6b3fe already tested in #11800 \(pass\)$/);
    assert.equal((await cli(["record", "--rc", "x", "--summary", "s"], env)).code, 2);
    assert.equal((await cli(["record"], env)).code, 2);
    assert.equal((await cli(["nope"], env)).code, 2);
  } finally { srv.close(); t.done(); }
});
