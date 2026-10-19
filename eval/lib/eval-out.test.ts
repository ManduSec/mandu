/** Unit tests for eval-out.ts: an evaluation run's default output dir
 * (on-disk-layout.md §9 decision 3), and its parity with the AgentDojo
 * runner's Python copy (agentdojo/eval_out.py). Every case uses a temp
 * MANDU_HOME; none touches a real ~/.mandu.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { evalRunsDir, mintRunId, outputBanner, resolveEvalOut } from "./eval-out.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const mode = (p: string): number => statSync(p).mode & 0o777;

test("eval-runs is <MANDU_HOME>/runs/eval, else ~/.mandu/runs/eval", () => {
  assert.equal(evalRunsDir({ MANDU_HOME: "/m" }, "/home/u"), "/m/runs/eval");
  assert.equal(evalRunsDir({}, "/home/u"), "/home/u/.mandu/runs/eval");
  assert.equal(evalRunsDir({ MANDU_HOME: "" }, "/home/u"), "/home/u/.mandu/runs/eval");
});

test("a run id sorts by UTC start time, names the suite, and ends in random hex", () => {
  const now = new Date(Date.UTC(2026, 8, 29, 12, 3, 1, 456));
  assert.equal(mintRunId("paired", now, "a1b2c3"), "20260929T120301Z-paired-a1b2c3");
  assert.match(mintRunId("utility"), /^\d{8}T\d{6}Z-utility-[0-9a-f]{6}$/);
  assert.notEqual(mintRunId("paired", now), mintRunId("paired", now), "two runs in one second stay apart");
  const earlier = mintRunId("paired", new Date(Date.UTC(2026, 8, 29, 12, 3, 0)), "ffffff");
  assert.ok(earlier < mintRunId("paired", now, "000000"));
  for (const bad of ["", "../x", "Paired", "a b", "a/b"]) assert.throws(() => mintRunId(bad), /Invalid run suite/);
  assert.throws(() => mintRunId("paired", now, "xyz"), /random tail/);
});

test("no --out: a new run dir under <MANDU_HOME>/runs/eval, parents made 0700; the run dir itself is left to the runner", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-eval-out-"));
  try {
    const home = join(tmp, "fresh", "mandu"); // none of it exists yet
    const now = new Date(Date.UTC(2026, 8, 29, 12, 3, 1));
    const out = resolveEvalOut(undefined, "paired", { env: { MANDU_HOME: home }, home: "/nowhere", now, random: "a1b2c3" });
    assert.deepEqual(out, { dir: join(home, "runs", "eval", "20260929T120301Z-paired-a1b2c3"), defaulted: true });
    for (const d of [home, join(home, "runs"), join(home, "runs", "eval")]) assert.equal(mode(d), 0o700, d);
    assert.equal(existsSync(out.dir), false, "the runner creates the run dir, refusing an existing one");
    assert.match(outputBanner(out), /^Output: .*20260929T120301Z-paired-a1b2c3 \(default; pass --out <dir> to choose\)$/);
    assert.equal(existsSync("/nowhere"), false);
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});

test("--out wins verbatim (resolved against the cwd) and creates nothing", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-eval-out-"));
  try {
    const home = join(tmp, "mandu");
    assert.deepEqual(resolveEvalOut("/tmp/mine", "paired", { env: { MANDU_HOME: home } }), { dir: "/tmp/mine", defaulted: false });
    assert.deepEqual(resolveEvalOut("rel/run", "utility", { env: { MANDU_HOME: home } }), { dir: resolve("rel/run"), defaulted: false });
    assert.equal(existsSync(home), false);
    assert.equal(outputBanner({ dir: "/tmp/mine", defaulted: false }), "Output: /tmp/mine");
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});

const python = spawnSync("python3", ["--version"]).status === 0;

test("the AgentDojo runner's Python copy resolves the same eval-runs dir", { skip: python ? false : "python3 unavailable" }, () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-eval-out-py-"));
  try {
    for (const env of [{ MANDU_HOME: join(tmp, "m") }, {}]) {
      const r = spawnSync("python3", ["-c", "import eval_out, sys; print(eval_out.eval_runs_dir(home=sys.argv[1]))", "/home/u"], {
        cwd: join(HERE, "..", "agentdojo"), env: { PATH: process.env.PATH, ...env }, encoding: "utf8",
      });
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.stdout.trim(), evalRunsDir(env, "/home/u"));
    }
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});

test("the AgentDojo runner's eval_out unit tests pass", { skip: python ? false : "python3 unavailable" }, () => {
  const r = spawnSync("python3", ["-m", "unittest", "-q", "test_eval_out"], {
    cwd: join(HERE, "..", "agentdojo"), env: { PATH: process.env.PATH, PYTHONDONTWRITEBYTECODE: "1" }, encoding: "utf8",
  });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});
