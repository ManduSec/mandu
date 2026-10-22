/**
 * launch-budget — the launch-time budget check (runtime-instances.md
 * §14.11). A warm `mandu claude --version` went from 1.17 s to about 2 s
 * between 2026-10-16 and 2026-10-21 and nothing said so; this check says so
 * within a night.
 *
 * What it does: starts its own arbiter (scripts/dev-arbiter.sh, `secrets`,
 * the test tenant) and a small made-up home (a few credential files, a
 * project whose history holds a `.env`), then for each agent on PATH (claude and codex by
 * default, MANDU_LAUNCH_BUDGET_AGENTS) and each place (an empty directory,
 * and a two-commit repository whose history holds a `.env`, so the git
 * history step runs, both under the small home; and `devhome`: a project
 * with 24 linked worktrees in a developer-sized home of 15 repositories
 * and a deep folder tree, the costs that grow with a real home) launches
 * `<agent> --version` through the real `mandu`
 * (MANDU_BIN, else the checkout's launcher/mandu-run.sh): one warm-up
 * launch per cell, then MANDU_LAUNCH_BUDGET_RUNS (7) measured launches per
 * cell, interleaved. Each run's wall time is measured here and its steps
 * are read from its own launch log (launch-timings.ts). It prints every
 * cell's medians, step by step, against the recorded baseline
 * (launch-budget-baseline.json beside this file) and fails a cell whose
 * median wall time is more than 50% AND more than 300 ms over its baseline
 * (tests/lib/launch-budget.ts says why those numbers); a cell more than
 * 20% and 150 ms over gets a WARN line instead (creep, not a failure).
 *
 * It runs in the nightly, never per push (env kind, the subscription lane's
 * guest, alone: `parallel: false`), and only with MANDU_LAUNCH_BUDGET=1,
 * which its manifest entry sets. Re-baseline (§14.11): run it in the CI
 * guest and keep the `LAUNCH_BUDGET_MEASURED` line of its log, or set
 * MANDU_LAUNCH_BUDGET_WRITE=<file> to write that file directly.
 *
 * Mode `secrets` (stated): the product default, whose secret setup is most
 * of the launch's own work.
 *
 * Mandu-new (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { cpus, hostname, release, tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { stateAxes } from "../lib/axes.js";
import { baselineOf, budgetVerdict, measureCell, parseBaseline, type CellMeasure, type CellRun } from "../lib/launch-budget.js";
import { launchLogDir } from "../../launcher/src/launch-log.js";
import { timingsFromLog } from "../../launcher/src/launch-timings.js";

stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..");
const BASELINE_FILE = join(HERE, "launch-budget-baseline.json");
const ON = process.env["MANDU_LAUNCH_BUDGET"] === "1";
const RUNS = Math.max(1, Number(process.env["MANDU_LAUNCH_BUDGET_RUNS"] ?? "7") || 7);
const AGENTS = (process.env["MANDU_LAUNCH_BUDGET_AGENTS"] ?? "claude,codex").split(",").map((a) => a.trim()).filter(Boolean);
const PLACES = ["empty", "repo", "devhome"] as const;

function onPath(cmd: string): boolean {
  return spawnSync("sh", ["-c", 'command -v "$1" >/dev/null', "sh", cmd], { stdio: "ignore" }).status === 0;
}

function manduCommand(): string[] {
  const bin = process.env["MANDU_BIN"] || "launcher/mandu-run.sh";
  const path = isAbsolute(bin) ? bin : join(REPO, bin);
  return path.endsWith(".sh") ? ["bash", path] : [path];
}

function commitOf(): string {
  try { return execFileSync("git", ["-C", REPO, "rev-parse", "--short=12", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch { /* not a checkout */ }
  return process.env["CI_COMMIT_SHA"]?.slice(0, 12) ?? "unknown";
}

const GIT_ENV = { GIT_AUTHOR_NAME: "budget", GIT_AUTHOR_EMAIL: "b@test.local", GIT_COMMITTER_NAME: "budget", GIT_COMMITTER_EMAIL: "b@test.local" };

function gitIn(dir: string, ...args: string[]): void {
  execFileSync("git", args, { cwd: dir, stdio: "ignore", env: { ...process.env, ...GIT_ENV } });
}

/** A repository whose history holds a protected file, so the launch's git
 *  history step runs; `commits` (2 or more) of history. */
function makeRepo(dir: string, commits = 2): void {
  mkdirSync(dir, { recursive: true });
  gitIn(dir, "init", "-q");
  writeFileSync(join(dir, ".env"), "OPENAI_API_KEY=not-a-real-key\n");
  writeFileSync(join(dir, "README.md"), "a repository for the launch budget\n");
  gitIn(dir, "add", "-A");
  gitIn(dir, "commit", "-qm", "one");
  for (let i = 2; i <= commits; i++) {
    writeFileSync(join(dir, "README.md"), `a repository for the launch budget, change ${i}\n`);
    gitIn(dir, "commit", "-qam", `change ${i}`);
  }
}

/** The credential files both made-up homes hold (made-up values). */
function putCredentials(home: string): void {
  const put = (rel: string, text: string): void => {
    mkdirSync(dirname(join(home, rel)), { recursive: true, mode: 0o700 });
    writeFileSync(join(home, rel), text, { mode: 0o600 });
  };
  put(".aws/credentials", "[default]\naws_access_key_id = not-a-real-key\naws_secret_access_key = not-a-real-secret\n");
  put(".netrc", "machine example.invalid login budget password not-a-real-password\n");
  put(".ssh/id_ed25519", "not a real key\n");
  put(".config/gh/hosts.yml", "github.com:\n    oauth_token: not-a-real-token\n");
}

/** How big the developer home is (runtime-instances.md §14.11). */
const DEV_HOME ={ repos: 14, worktrees: 24, bigCommits: 30, tree: [12, 8, 6, 4] } as const;

/**
 * A developer home at the scale the launch's per-home costs show (§14.10:
 * the history step read seven repositories, several with linked worktrees,
 * on the developer host): DEV_HOME.repos projects each with a `.env` in
 * history, one more (`src/big`, the launch's directory) with a longer
 * history and DEV_HOME.worktrees linked worktrees in the home, and a deep
 * folder tree for the secret walk (12 x 8 x 6 x 4 leaves, about 2,900
 * folders). Returns the launch directory.
 */
function makeDevHome(home: string): string {
  putCredentials(home);
  for (let i = 1; i <= DEV_HOME.repos; i++) makeRepo(join(home, "src", `proj${String(i).padStart(2, "0")}`), 2 + (i % 4));
  const big = join(home, "src", "big");
  makeRepo(big, DEV_HOME.bigCommits);
  for (let i = 1; i <= DEV_HOME.worktrees; i++) {
    const n = String(i).padStart(2, "0");
    gitIn(big, "worktree", "add", "-q", "-b", `wt${n}`, join(home, "src", "big-worktrees", `wt${n}`));
  }
  const [a, b, c, d] = DEV_HOME.tree;
  for (let i = 0; i < a; i++) for (let j = 0; j < b; j++) for (let k = 0; k < c; k++) for (let l = 0; l < d; l++) {
    const leaf = join(home, "notes", `n${i}`, `m${j}`, `k${k}`, `l${l}`);
    mkdirSync(leaf, { recursive: true });
    writeFileSync(join(leaf, "notes.md"), "notes\n");
  }
  return big;
}

/** A small developer home: a few credential files the walk finds and a
 *  project whose history holds a protected file, so every launch (from any
 *  directory) walks it and runs the history step for it, as on a real home
 *  (runtime-instances.md §14.10). No real secret: made-up values. */
function makeHome(home: string): void {
  putCredentials(home);
  makeRepo(join(home, "projects", "app"));
}

function logNames(dir: string): string[] {
  try { return readdirSync(dir).filter((n) => n.endsWith(".log")); } catch { return []; }
}

test("launch budget: warm `mandu <agent> --version` from an empty directory and a repository, against the recorded baseline", {
  skip: ON ? false : "set MANDU_LAUNCH_BUDGET=1 (its manifest entry does; runtime-instances.md §14.11)",
  timeout: 30 * 60_000,
}, async (t) => {
  const agents = AGENTS.filter(onPath);
  for (const a of AGENTS.filter((x) => !agents.includes(x))) t.diagnostic(`${a} is not on PATH: its cells are not measured`);
  if (agents.length === 0) { t.skip(`none of ${AGENTS.join(", ")} is on PATH`); return; }

  // Short: the arbiter's sockets live under it (107-byte sun_path).
  const base = Buffer.byteLength(tmpdir()) > 60 ? "/tmp" : tmpdir();
  const work = mkdtempSync(join(base, "mlb-"));
  const arbDir = join(work, "arb");
  try {
    const out = execFileSync("bash", [join(REPO, "scripts", "dev-arbiter.sh"), arbDir], {
      encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 120_000,
      env: { ...process.env, MANDU_MODE: "secrets", MANDU_TENANT: "test" },
    });
    const sock = /MANDU_ARBITER_SOCK="([^"]+)"/.exec(out)?.[1];
    assert.ok(sock && existsSync(sock), `the dev arbiter came up: ${out}`);

    const home = join(work, "home");
    const devHome = join(work, "devhome");
    const manduHome = join(work, "mandu-home");
    mkdirSync(home, { recursive: true, mode: 0o700 });
    mkdirSync(devHome, { recursive: true, mode: 0o700 });
    makeHome(home);
    const setup0 = performance.now();
    const devCwd = makeDevHome(devHome);
    t.diagnostic(`the developer home took ${Math.round(performance.now() - setup0)} ms to make`);
    const places: Record<(typeof PLACES)[number], { cwd: string; home: string }> = {
      empty: { cwd: join(work, "empty"), home },
      repo: { cwd: join(work, "repo"), home },
      devhome: { cwd: devCwd, home: devHome },
    };
    mkdirSync(places.empty.cwd, { recursive: true });
    makeRepo(places.repo.cwd);
    const baseEnv: NodeJS.ProcessEnv = {
      ...process.env,
      MANDU_HOME: manduHome, MANDU_ARBITER_SOCK: sock, MANDU_TENANT: "test", MANDU_MODE: "secrets",
      MANDU_UPDATE_CHECK: "0",
    };
    delete baseEnv["MANDU_VERBOSE"];
    delete baseEnv["MANDU_ADMIN_SOCK"];
    // One Mandu home for every cell, so one log folder; HOME is the cell's.
    const logDir = launchLogDir(baseEnv, home);
    const [cmd, ...pre] = manduCommand();

    const launchOnce = (agent: string, place: (typeof PLACES)[number]): CellRun => {
      const before = new Set(logNames(logDir));
      const env = { ...baseEnv, HOME: places[place].home };
      const t0 = performance.now();
      const r = spawnSync(cmd!, [...pre, agent, "--version"], { cwd: places[place].cwd, env, encoding: "utf8", timeout: 120_000, stdio: ["ignore", "pipe", "pipe"] });
      const wallMs = performance.now() - t0;
      assert.equal(r.status, 0, `mandu ${agent} --version in the ${place} directory exited ${r.status}:\n${r.stdout}\n${r.stderr}`);
      const added = logNames(logDir).filter((n) => !before.has(n));
      assert.equal(added.length, 1, `one new launch log in ${logDir}: ${added.join(", ")}`);
      const timings = timingsFromLog(readFileSync(join(logDir, added[0]!), "utf8"));
      assert.ok(timings, `the launch's log holds its timings (${added[0]})`);
      assert.ok(timings!.steps.some((s) => s.step === "agent"), "the agent's run is timed");
      return { wallMs, timings: timings! };
    };

    const cells = agents.flatMap((a) => PLACES.map((p) => ({ name: `${a} ${p}`, agent: a, place: p })));
    // Warm: the bundle's build, the per-boot caches, a workspace's first scan.
    for (const c of cells) launchOnce(c.agent, c.place);
    const runs = new Map<string, CellRun[]>(cells.map((c) => [c.name, []]));
    for (let i = 0; i < RUNS; i++) for (const c of cells) runs.get(c.name)!.push(launchOnce(c.agent, c.place));

    const measured: Record<string, CellMeasure> = {};
    for (const c of cells) measured[c.name] = measureCell(runs.get(c.name)!);
    let baseline = null;
    if (existsSync(BASELINE_FILE)) {
      const parsed = parseBaseline(readFileSync(BASELINE_FILE, "utf8"));
      assert.ok(typeof parsed !== "string", `${BASELINE_FILE}: ${String(parsed)}`);
      baseline = parsed;
    }
    const verdict = budgetVerdict(measured, baseline);
    for (const l of verdict.report) console.log(l);
    for (const w of verdict.warnings) t.diagnostic(w);
    const record = baselineOf(measured, {
      recorded: new Date().toISOString().slice(0, 10),
      where: `${hostname()}: ${cpus().length} CPUs, Linux ${release()}, node ${process.version}`,
      commit: commitOf(),
      runs: RUNS,
    });
    // The re-baseline line (§14.11): this run's numbers, as the baseline file holds them.
    console.log(`LAUNCH_BUDGET_MEASURED ${JSON.stringify(record)}`);
    const write = process.env["MANDU_LAUNCH_BUDGET_WRITE"];
    if (write) writeFileSync(write, JSON.stringify(record, null, 2) + "\n");
    assert.deepEqual(verdict.failures, [], `launch time over budget:\n${verdict.failures.join("\n")}\n(the breakdown is above; a deliberate change re-baselines, runtime-instances.md §14.11)`);
  } finally {
    spawnSync("bash", [join(REPO, "scripts", "dev-arbiter.sh"), "stop", arbDir], { stdio: "ignore", timeout: 60_000 });
    rmSync(work, { recursive: true, force: true });
  }
});
