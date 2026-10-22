/**
 * launch-git-budget — the launch's git work, COUNTED, held under a budget
 * on every push (runtime-instances.md §14.11, "What a step costs, counted").
 *
 * The nightly budget (tests/env/launch-budget.test.ts) times launches
 * against a baseline recorded in the CI guest, and only a 50% slower launch
 * fails it: a loaded host moves the wall time more than one step's
 * regression does. What the warm-launch regression of 2026-10-21 was made
 * of is WORK: git calls asked of every repository of the home holding a
 * protected file, each check after the agent in a sandbox of its own. Work
 * a loaded host cannot move. Every launch's record now counts it per step
 * (launch-timings.ts: `git`, `sandboxes`, `cpuMs`), and this check holds
 * the counts, so a change that asks every work tree one more git call, makes
 * a sandbox per call before the agent, or asks git in a step that asked
 * none, fails per push, whatever the host's load.
 *
 * The REAL components: the launcher's main() in `secrets` mode against a
 * REAL ArbiterServer, the host's bwrap (the git sandbox and the twins), real
 * git. A made-up home with three repositories holding a tracked `.env`, one
 * of them with two linked worktrees, and the workspace, a fourth: six work
 * trees in four object stores, each in the history step and the placeholder
 * watch. Two warm-up launches (the first scans each store and leaves the
 * prefetch its first record; the second's prefetch still reads less than a
 * steady one), then two MEASURED launches, each held to the budget:
 *
 *   - before the agent (every step from `plan` to `agent-start`): at most
 *     BUDGET.perWorkTree git calls per work tree, BUDGET.perStore per object
 *     store, plus BUDGET.base, in at most BUDGET.prepSandboxes sandboxes (the
 *     launch's one git session; not held where the host's Yama scope forbids
 *     the session, which then runs one sandbox per call);
 *   - no git call in any step after `secrets` until the agent has exited,
 *     nor in a teardown step but `teardown.placeholder` (no earlier session
 *     left a record: each launch here ends cleanly);
 *   - `teardown.placeholder`: at most two calls per watched work tree when
 *     the session changed nothing (its index entries and its tips), each in
 *     a sandbox of its own (runtime-instances.md §14.12 says why they are
 *     not shared).
 *
 * The CPU time is printed beside the counts, never held: a loaded guest's
 * CPU time varies by a third, and a budget loose enough for that would
 * catch nothing the counts do not.
 *
 * Self-SKIPs where bwrap cannot create a user namespace (no twins, no git
 * sandbox: nothing to count).
 *
 * Mandu-new (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { launchLogs } from "../../launcher/test/lib/launch-log-read.js";
import { resolveWrapBwrap } from "../../launcher/src/bwrap-grant.js";
import { hostPtraceScope, sessionAllowed } from "../../launcher/src/git-session.js";
import { formatTimings, LAUNCH_STEPS, timingsFromLog, type LaunchTimings } from "../../launcher/src/launch-timings.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // the history step and the placeholder watch run with the confidentiality axis on

const BWRAP = (process.platform === "linux" ? resolveWrapBwrap() : null) ?? "bwrap";
const BWRAP_RUNS = process.platform === "linux" && spawnSync(BWRAP, ["--ro-bind", "/", "/", "--", "true"], { stdio: "ignore", timeout: 10_000 }).status === 0;
const GIT = spawnSync("git", ["--version"], { stdio: "ignore" }).status === 0;
const skip = !BWRAP_RUNS ? "bwrap cannot create a user namespace on this host (no twins, no git sandbox)"
  : !GIT ? "git is not installed" : false;

/**
 * The budget (runtime-instances.md §14.11, where the calls are listed).
 * Measured 2026-10-22 on this fixture: 57 git calls before the agent (eight
 * per work tree, two per store, the session's `git version`) in one sandbox,
 * then 12 calls in 12 sandboxes. `slack` absorbs a rare call asked again
 * (a shared answer that failed under load), never a call per work tree. A
 * change that costs work on purpose raises these here and in the doc,
 * saying why.
 */
const BUDGET = { perWorkTree: 8, perStore: 2, base: 1, slack: 3, prepSandboxes: 1, teardownPerWorkTree: 2 };

const GIT_ENV = {
  ...process.env, GIT_AUTHOR_NAME: "u", GIT_AUTHOR_EMAIL: "u@x", GIT_COMMITTER_NAME: "u", GIT_COMMITTER_EMAIL: "u@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...args: string[]): void => { execFileSync("git", args, { cwd, stdio: "ignore", env: GIT_ENV }); };

/** A repository whose history holds a tracked `.env` (made-up values). */
function makeRepo(dir: string, commits: number): void {
  mkdirSync(dir, { recursive: true });
  git(dir, "init", "-q", "-b", "main");
  writeFileSync(join(dir, ".env"), "API_TOKEN=not-a-real-token-0\n");
  writeFileSync(join(dir, "README.md"), "a project\n");
  git(dir, "add", "-A");
  git(dir, "commit", "-qm", "one");
  for (let i = 1; i < commits; i++) {
    writeFileSync(join(dir, ".env"), `API_TOKEN=not-a-real-token-${i}\n`);
    git(dir, "commit", "-qam", `change ${i}`);
  }
}

interface Rig { dir: string; home: string; ws: string; manduHome: string; sock: string; server: ArbiterServer; workTrees: number; stores: number }

async function rig(): Promise<Rig> {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-git-budget-")));
  const home = join(dir, "home");
  const ws = join(dir, "ws");
  mkdirSync(home, { recursive: true, mode: 0o700 });
  makeRepo(join(home, "src", "a"), 2);
  makeRepo(join(home, "src", "b"), 3);
  for (const n of ["w1", "w2"]) git(join(home, "src", "b"), "worktree", "add", "-q", "-b", n, join(home, "src", "b-worktrees", n));
  makeRepo(join(home, "src", "c"), 2);
  makeRepo(ws, 2);
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {},
    // The human plane: the launch is recorded with the arbiter (the
    // history caches' seals, the placeholder records' folder).
    humanSocketPath: humanSockIn(dir), confidentiality: true, integrity: false,
  });
  await server.listen();
  // Work trees: a, b and its two worktrees, c, the workspace. Stores: a, b, c, the workspace.
  return { dir, home, ws, manduHome: join(dir, "mandu-home"), sock, server, workTrees: 6, stores: 4 };
}

const FLAGS = ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box"];

function launchEnv(r: Rig): Record<string, string> {
  return {
    HOME: r.home, PWD: r.ws, MANDU_ARBITER_SOCK: r.sock, PATH: process.env["PATH"] ?? "",
    MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: r.manduHome, MANDU_MODE: "secrets", XDG_RUNTIME_DIR: r.dir,
    // The launch-time scan for unprotected keys is not under test here.
    MANDU_SUGGEST_AT_LAUNCH: "0", MANDU_UPDATE_CHECK: "0",
  };
}

/** One in-process launch of `/bin/sh -c true` (the agent does nothing):
 *  the whole launch's record, from its own log. */
async function launch(r: Rig): Promise<LaunchTimings> {
  const lines: string[] = [];
  const orig = console.error;
  const saved = { HOME: process.env["HOME"], MANDU_HOME: process.env["MANDU_HOME"] };
  const env = launchEnv(r);
  const logs = launchLogs(env);
  let code: number | null = null;
  try {
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["HOME"] = r.home;
    process.env["MANDU_HOME"] = r.manduHome;
    code = await main([...FLAGS, "--", "/bin/sh", "-c", "true"], env);
  } finally {
    console.error = orig;
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
  assert.equal(code, 0, lines.join("\n"));
  const t = timingsFromLog(logs.newLines().join("\n"));
  assert.ok(t, `the launch's log holds its timings\n${lines.join("\n")}`);
  return t!;
}

type Counts = { git: number; sandboxes: number };
const TOP: string[] = LAUNCH_STEPS.map(([n]) => n).filter((n) => !n.startsWith("secrets."));

/** Each top-level step's git calls and sandboxes; every one carries them. */
function countsOf(t: LaunchTimings): Map<string, Counts> {
  const out = new Map<string, Counts>();
  for (const s of t.steps) {
    if (!TOP.includes(s.step)) continue;
    assert.ok(s.git !== undefined && s.sandboxes !== undefined && s.cpuMs !== undefined, `${s.step} carries its cost: ${JSON.stringify(s)}`);
    const c = out.get(s.step) ?? { git: 0, sandboxes: 0 };
    out.set(s.step, { git: c.git + s.git!, sandboxes: c.sandboxes + s.sandboxes! });
  }
  return out;
}

const sum = (m: Map<string, Counts>, steps: readonly string[]): Counts =>
  steps.reduce((acc, s) => ({ git: acc.git + (m.get(s)?.git ?? 0), sandboxes: acc.sandboxes + (m.get(s)?.sandboxes ?? 0) }), { git: 0, sandboxes: 0 });

test("the launch's git work: a budget per work tree before the agent in one sandbox, none until the agent exits, two per work tree after it", { skip, timeout: 600_000 }, async (t) => {
  const r = await rig();
  try {
    await launch(r);
    await launch(r);
    const runs = [await launch(r), await launch(r)];
    const prepSteps = TOP.slice(0, TOP.indexOf("agent"));
    const prepMax = BUDGET.perWorkTree * r.workTrees + BUDGET.perStore * r.stores + BUDGET.base + BUDGET.slack;
    const sessions = sessionAllowed(hostPtraceScope());
    if (!sessions) t.diagnostic("Yama's ptrace scope forbids the git session here: one sandbox per call, the sandbox budget not held");
    for (const [i, run] of runs.entries()) {
      for (const l of formatTimings(run)) t.diagnostic(l);
      const m = countsOf(run);
      const prep = sum(m, prepSteps);
      t.diagnostic(`launch ${i + 1}: before the agent ${prep.git} git calls in ${prep.sandboxes} sandboxes (budget ${prepMax}); ${r.workTrees} work trees, ${r.stores} stores`);
      // The history step ran in every work tree (else the count proves nothing).
      assert.ok(prep.git >= 2 * r.workTrees, `before the agent: only ${prep.git} git calls for ${r.workTrees} work trees: did the history step run?`);
      assert.ok(prep.git <= prepMax, `before the agent: ${prep.git} git calls, over the budget of ${prepMax} (runtime-instances.md §14.11)`);
      if (sessions) {
        assert.ok(prep.sandboxes <= BUDGET.prepSandboxes,
          `before the agent: ${prep.sandboxes} sandboxes, over the budget of ${BUDGET.prepSandboxes}: a git call outside the launch's one git session`);
      }
      for (const s of TOP.slice(TOP.indexOf("secrets") + 1)) {
        if (s === "teardown.placeholder") continue;
        assert.equal(m.get(s)?.git ?? 0, 0, `${s}: no git call (it asked ${m.get(s)?.git})`);
      }
      const td = m.get("teardown.placeholder");
      assert.ok(td, "the check after the agent ran");
      assert.ok(td!.git <= BUDGET.teardownPerWorkTree * r.workTrees, `teardown.placeholder: ${td!.git} git calls for ${r.workTrees} work trees`);
      assert.ok(td!.sandboxes <= td!.git, "at most one sandbox per call");
    }
  } finally {
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});
