// ci-macos-run.test.mjs — scripts/ci/macos-run.sh, the macOS check
// (docs/design/testing/continuous-integration.md §12.6): its options, the host
// it refuses, and the labels its run gets in a GitLab job, a GitHub job and by
// hand (--dry-run: nothing installed, nothing run).
//
// Run: node --test scripts/test/ci-macos-run.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SCRIPT = join(REPO, "scripts", "ci", "macos-run.sh");
const DARWIN = process.platform === "darwin";
const SHA = "b3a6b3fe1e50368f458cda3a4fda19a4b3f2b246";

/** The script with only PATH and HOME from here, plus `env`. */
function run(args, env = {}) {
  return spawnSync("bash", [SCRIPT, ...args], { cwd: REPO, encoding: "utf8", env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env } });
}

/** Can this Mac run the check at all? (an unnested sandbox-exec and an OpenSSL 3) */
const MAC_READY = (() => {
  if (!DARWIN) return "macOS only";
  const sb = spawnSync("/usr/bin/sandbox-exec", ["-p", "(version 1)(allow default)", "/usr/bin/true"]);
  if (sb.status !== 0) return "sandbox-exec cannot apply a profile here (this run is inside another sandbox)";
  const r = run(["--dry-run"]);
  if (r.status === 2 && /OpenSSL 3/.test(r.stderr)) return "no OpenSSL 3 on this Mac";
  return false;
})();

test("options: an unknown one or --out without a directory exits 2; --help prints the header", () => {
  assert.equal(run(["--nope"]).status, 2);
  assert.equal(run(["--out"]).status, 2);
  const h = run(["--help"]);
  assert.equal(h.status, 0);
  assert.match(h.stdout, /the macOS check: the manifest's darwin entries/);
});

test("a host that is not macOS cannot run the check: exit 2, before anything is installed", { skip: DARWIN && "this is a Mac" }, () => {
  const r = run(["--dry-run"]);
  assert.equal(r.status, 2, r.stdout + r.stderr);
  assert.match(r.stderr, /not macOS/);
});

test("the run's labels: a GitLab job's ids, a GitHub job's run and CPU, a run by hand; always the darwin kinds", { skip: MAC_READY }, () => {
  const arch = spawnSync("uname", ["-m"], { encoding: "utf8" }).stdout.trim();
  const gl = run(["--dry-run", "--out", "o"], { GITLAB_CI: "true", CI_PIPELINE_ID: "5", CI_JOB_ID: "6", CI_COMMIT_SHA: SHA, CI_COMMIT_REF_NAME: "master" });
  assert.equal(gl.status, 0, gl.stderr);
  assert.match(gl.stdout, new RegExp(`would run: node scripts/run-suites\\.mjs --kind unit,component,stack,sandbox --run-id gl-5-6 --source gitlab --commit ${SHA} --ref master --image darwin-[0-9.]+-${arch} --out o\\n`));
  const gh = run(["--dry-run"], { GITHUB_RUN_ID: "7", GITHUB_RUN_ATTEMPT: "2", GITHUB_REF_NAME: "v0.2.0" });
  assert.equal(gh.status, 0, gh.stderr);
  assert.match(gh.stdout, new RegExp(`--run-id gh-7-2-${arch} --source local --commit [0-9a-f]{40} --ref v0\\.2\\.0 .* --out ci-out\\n`));
  const local = run(["--dry-run"]);
  assert.equal(local.status, 0, local.stderr);
  assert.match(local.stdout, /--run-id local-\d{8}T\d{6}Z-[0-9a-f]{12} --source local --commit [0-9a-f]{40}(\+dirty)? /);
  // The toolchain line names what the run will use.
  assert.match(gl.stdout, /^macOS \S+ \S+; node v\d+\.\d+\.\d+; OpenSSL 3/m);
});

test("the script keeps CI secrets out of the suites, checks both Seatbelt entries, and stays bash 3.2", () => {
  const src = readFileSync(SCRIPT, "utf8");
  const unset = /^unset (.+?) 2>\/dev\/null/m.exec(src)?.[1].split(/\s+/) ?? [];
  for (const v of ["CI_JOB_TOKEN", "NPM_TOKEN", "NODE_AUTH_TOKEN", "GITHUB_TOKEN", "CI_REPOSITORY_URL"]) assert.ok(unset.includes(v), `unsets ${v}`);
  assert.match(src, /"launcher\.darwin-seatbelt": 0, "launcher\.darwin-git-sandbox": 1/, "never green by absence");
  const code = src.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
  assert.doesNotMatch(code, /\bmapfile\b|\breadarray\b|declare -A|\$\{[A-Za-z_]+,,\}|\$\{[A-Za-z_]+\^\^\}/, "no bash 4 features (macOS /bin/bash is 3.2)");
  assert.match(src, /npm ci --no-audit --no-fund/, "the packages install as the Linux guest's do");
});
