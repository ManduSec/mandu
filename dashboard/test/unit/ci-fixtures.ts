/**
 * ci-fixtures — schema-1 summary.json builders and a runs-dir writer for the
 * CI tab's tests (src/ci-runs.ts unit tests, the ci-area e2e). Includes the
 * hostile shapes a merge request could leave behind.
 */
import { mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpDir } from "./tmp-dir.js";

export type Json = Record<string, unknown>;

export function entry(id: string, kind: string, result: string, extra: Json = {}): Json {
  return { id, kind, result, pass: result === "pass" ? 10 : 3, fail: result === "fail" ? 1 : 0, skip: 1, duration_s: 12.5, log: `logs/${id}.log`, ...extra };
}

export function summary(run: string, extra: Json = {}): Json {
  return {
    schema: 1,
    kind: "mandu-ci-run",
    run,
    source: "gitlab",
    commit: "b814495e0123456789abcdef0123456789abcdef",
    ref: "master",
    image: "mandu-ci-3f2a",
    started: "2026-09-28T10:00:00Z",
    finished: "2026-09-28T10:07:12Z",
    result: "pass",
    stages: { build: { result: "pass", duration_s: 131 } },
    entries: [entry("arbiter", "component", "pass"), entry("launcher-kernel", "sandbox", "pass")],
    ...extra,
  };
}

/** Write one run dir: `summary` (object → JSON, string → verbatim, undefined → none) and logs. */
export function putRun(dir: string, name: string, s: Json | string | undefined, logs: Record<string, string> = {}): string {
  const rd = join(dir, name);
  mkdirSync(join(rd, "logs"), { recursive: true });
  if (s !== undefined) writeFileSync(join(rd, "summary.json"), typeof s === "string" ? s : JSON.stringify(s));
  for (const [id, text] of Object.entries(logs)) writeFileSync(join(rd, "logs", `${id}.log`), text);
  return rd;
}

export function tmpRunsDir(prefix = "ci-runs-"): string {
  return tmpDir(prefix);
}

/**
 * A runs dir with three valid runs (one red) and a set of hostile ones:
 * each hostile run must be skipped and counted, never listed or served.
 * Returns the dir and a secret file outside it that no route may reveal.
 */
export function hostileRunsDir(): { dir: string; secret: string; validIds: string[]; invalidCount: number } {
  const dir = tmpRunsDir();
  const outside = tmpDir("ci-outside-");
  const secret = join(outside, "secret.txt");
  writeFileSync(secret, "TOP-SECRET-OUTSIDE-THE-RUNS-DIR\n");

  // valid: newest is the red one
  putRun(dir, "gl-100-1", summary("gl-100-1", { finished: "2026-09-27T09:00:00Z", started: "2026-09-27T08:50:00Z" }), { arbiter: "ok\n", "launcher-kernel": "ok\n" });
  putRun(dir, "gl-101-1", summary("gl-101-1", {
    ref: "mr-7",
    result: "fail",
    finished: "2026-09-28T10:07:12Z",
    entries: [entry("arbiter", "component", "pass"), entry("fs-sync", "component", "fail"), entry("exec-box", "sandbox", "skip", { log: undefined })],
  }), { arbiter: "ok\n", "fs-sync": "\u001b[31mnot ok 3\u001b[0m <script>alert(1)</script>\n" });
  putRun(dir, "local-20260926-1", summary("local-20260926-1", { source: "local", ref: "feat/x", finished: "2026-09-26T09:00:00Z", started: "2026-09-26T08:59:00Z" }));

  let invalid = 0;
  const bad = (name: string, s: Json | string | undefined, logs: Record<string, string> = {}) => { putRun(dir, name, s, logs); invalid++; };
  bad("extra-field", summary("extra-field", { html: "<b>x</b>" }));
  bad("bad-enum", summary("bad-enum", { result: "passed" }));
  bad("bad-entry-enum", summary("bad-entry-enum", { entries: [entry("a", "component", "ok")] }));
  bad("bad-entry-id", summary("bad-entry-id", { entries: [entry("../../etc/passwd", "component", "pass", { log: "logs/../../etc/passwd.log" })] }));
  bad("bad-log-path", summary("bad-log-path", { entries: [entry("a", "component", "pass", { log: "../../secret.txt" })] }));
  bad("run-mismatch", summary("gl-100-1"));
  bad("not-json", "{ nope");
  bad("no-summary", undefined);
  bad("huge", JSON.stringify(summary("huge", { reason: "x".repeat(1024) })) + " ".repeat(1024 * 1024));
  bad("bad name with spaces", summary("bad name with spaces"));
  // a run dir that is a symlink to a valid run elsewhere
  const elsewhere = tmpRunsDir("ci-elsewhere-");
  putRun(elsewhere, "linked", summary("linked"));
  symlinkSync(join(elsewhere, "linked"), join(dir, "linked"));
  invalid++;
  // a summary.json that is a symlink
  mkdirSync(join(dir, "sym-summary", "logs"), { recursive: true });
  writeFileSync(join(outside, "summary.json"), JSON.stringify(summary("sym-summary")));
  symlinkSync(join(outside, "summary.json"), join(dir, "sym-summary", "summary.json"));
  invalid++;
  // a valid run whose log is a symlink to the secret, and one whose logs dir is
  putRun(dir, "gl-90-1", summary("gl-90-1", { finished: "2026-09-20T00:00:00Z", started: "2026-09-19T23:00:00Z" }));
  symlinkSync(secret, join(dir, "gl-90-1", "logs", "arbiter.log"));
  mkdirSync(join(dir, "gl-91-1"));
  writeFileSync(join(dir, "gl-91-1", "summary.json"), JSON.stringify(summary("gl-91-1", { finished: "2026-09-21T00:00:00Z", started: "2026-09-20T23:00:00Z" })));
  mkdirSync(join(outside, "logs"));
  writeFileSync(join(outside, "logs", "arbiter.log"), "TOP-SECRET-OUTSIDE-THE-RUNS-DIR\n");
  symlinkSync(join(outside, "logs"), join(dir, "gl-91-1", "logs"));
  // a stray file and the collector's hidden staging dir (ignored, not counted)
  writeFileSync(join(dir, "README"), "not a run");
  invalid++;
  mkdirSync(join(dir, ".staging-gl-102-1"));
  return { dir, secret, validIds: ["gl-101-1", "gl-100-1", "local-20260926-1", "gl-91-1", "gl-90-1"], invalidCount: invalid };
}
